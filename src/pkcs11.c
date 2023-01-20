/*
 * Copyright (C) IBM Corp. 2022
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dlfcn.h>
#include <string.h>
#include <openssl/crypto.h>

#include "debug.h"
#include "pkcs11.h"

#define OBJ_PER_SEARCH			8

static const CK_OBJECT_CLASS oc_private = CKO_PRIVATE_KEY;
static const CK_OBJECT_CLASS oc_public = CKO_PUBLIC_KEY;
static const CK_OBJECT_CLASS oc_certificate = CKO_CERTIFICATE;

const char *str_priv = "private";
const char *str_pub = "public";
const char *str_cert = "certificate";

static void module_info(struct pkcs11_module *pkcs, struct dbg *dbg)
{
	CK_INFO ck_info = { 0 };
	CK_RV ck_rv;

	ck_rv = pkcs->fns->C_GetInfo(&ck_info);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_GetInfo() failed: %d",
			     pkcs->soname, (int)ck_rv);
		return;
	}

	ps_dbg_info(dbg, "%s: cryptokiVersion: %d.%d",
		    pkcs->soname,
		    (int)ck_info.cryptokiVersion.major,
		    (int)ck_info.cryptokiVersion.minor);
	ps_dbg_info(dbg, "%s: libraryDescription: %.*s",
		    pkcs->soname,
		    sizeof(ck_info.libraryDescription),
		    ck_info.libraryDescription);
	ps_dbg_info(dbg, "%s: manufacturerID: %.*s",
		    pkcs->soname,
		    sizeof(ck_info.manufacturerID),
		    ck_info.manufacturerID);
	ps_dbg_info(dbg, "%s: libraryVersion: %d.%d",
		    pkcs->soname,
		    (int)ck_info.libraryVersion.major,
		    (int)ck_info.libraryVersion.minor);
}

static inline void attr_string(CK_ATTRIBUTE_PTR attr, CK_ATTRIBUTE_TYPE type,
			       const char *s)
{
	if (!attr || !s)
		return;
	attr->type = type;
	attr->pValue = (CK_VOID_PTR)s;
	attr->ulValueLen = strlen(s);
}

void pkcs11_attr_type(CK_ATTRIBUTE_PTR attr, const char *type)
{
	if (!attr)
		return;
	if (strncmp(type, str_priv, strlen(str_priv)) == 0)
		attr->pValue = (CK_VOID_PTR)&oc_private;
	else if (strncmp(type, str_pub, strlen(str_pub)) == 0)
		attr->pValue = (CK_VOID_PTR)&oc_public;
	else if (strncmp(type, str_pub, strlen(str_pub)) == 0)
		attr->pValue = (CK_VOID_PTR)&oc_certificate;
	else
		return;		/* not supported:  data, secret-key */

	attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
}

void pkcs11_attr_id(CK_ATTRIBUTE_PTR attr, const char *id)
{
	attr_string(attr, CKA_ID, id);
}

void pkcs11_attr_label(CK_ATTRIBUTE_PTR attr, const char *label)
{
	attr_string(attr, CKA_LABEL, label);
}

size_t pkcs11_strlen(const CK_CHAR_PTR c, CK_ULONG csize)
{
	size_t idx = csize;

	while ((idx > 0) && (c[idx - 1] == ' ')) {
		idx--;
	}
	return idx;
}

int pkcs11_strcmp(const char *s, const CK_CHAR_PTR c, CK_ULONG csize)
{
	if (!s)
		return -1;
	if (!c || !csize)
		return 1;
	if (strlen(s) > csize)
		return 1;

	return strncmp(s, (const char *)c, pkcs11_strlen(c, csize));
}

CK_RV pkcs11_find_objects(struct pkcs11_module *pkcs11,
			  CK_SESSION_HANDLE session,
			  const char *label, const char *id, const char *type,
			  CK_OBJECT_HANDLE_PTR *objects, CK_ULONG_PTR nobjects,
			  struct dbg *dbg)
{
	CK_RV rv;
	CK_ATTRIBUTE template[3];
	CK_ULONG tidx = 0;
	CK_OBJECT_HANDLE tmp[OBJ_PER_SEARCH];
	CK_ULONG ntmp;
	CK_OBJECT_HANDLE_PTR objs = NULL;
	CK_ULONG nobjs = 0;

	if (!pkcs11 || !objects || !nobjects || !dbg ||
	    (session == CK_INVALID_HANDLE))
		return CKR_ARGUMENTS_BAD;

	memset(template, 0, sizeof(template));
	tidx = 0;
	if (label)
		pkcs11_attr_label(&template[tidx++], label);
	if (id)
		pkcs11_attr_id(&template[tidx++], id);
	if (type)
		pkcs11_attr_type(&template[tidx++], type);

	rv = pkcs11->fns->C_FindObjectsInit(session, template, tidx);
	if (rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: unable to initialize search: %d",
			     pkcs11->soname, rv);
		return rv;
	}

	while (1) {
		rv = pkcs11->fns->C_FindObjects(session, tmp, OBJ_PER_SEARCH,
						&ntmp);
		if (rv != CKR_OK) {
			OPENSSL_free(objs);
			nobjs = 0;
			goto out;
		}

		if (!ntmp)
			break;

		objs = OPENSSL_realloc(objs, ntmp * sizeof(CK_OBJECT_HANDLE));
		if (!objs) {
			nobjs = 0;
			rv = CKR_HOST_MEMORY;
			goto out;
		}
		/* append found objects */
		memcpy(&objs[nobjs], tmp, ntmp * sizeof(CK_OBJECT_HANDLE));
		nobjs += ntmp;
	}

out:
	*objects = objs;
	*nobjects = nobjs;

	pkcs11->fns->C_FindObjectsFinal(session);
	return rv;
}

void pkcs11_session_close(struct pkcs11_module *pkcs11,
			   CK_SESSION_HANDLE_PTR session,
			   struct dbg *dbg)
{
	CK_RV ck_rv;

	if (!session || (*session == CK_INVALID_HANDLE))
		return;

	ck_rv = pkcs11->fns->C_CloseSession(*session);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_CloseSession() failed: %lu",
			     pkcs11->soname, ck_rv);
	}
	*session = CK_INVALID_HANDLE;
}

CK_RV pkcs11_session_open_login(struct pkcs11_module *pkcs11,
				CK_SLOT_ID slot_id,
				CK_SESSION_HANDLE_PTR session, const char *pin,
				struct dbg *dbg)
{
	CK_RV ck_rv;

	if (!pkcs11 || !session || !pin || !dbg ||
	    (slot_id == CK_UNAVAILABLE_INFORMATION) ||
	    (*session != CK_INVALID_HANDLE))
		return CKR_ARGUMENTS_BAD;

	ck_rv = pkcs11->fns->C_OpenSession(slot_id, CKF_SERIAL_SESSION,
					   NULL, NULL, session);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_OpenSession(%lu) failed: %lu",
			     pkcs11->soname, slot_id, ck_rv);
		return ck_rv;
	}

	ck_rv = pkcs11->fns->C_Login(*session, CKU_USER,
				     (CK_UTF8CHAR_PTR)pin, strlen(pin));
	if ((ck_rv != CKR_OK) &&
	    (ck_rv != CKR_USER_ALREADY_LOGGED_IN)) {
		ps_dbg_error(dbg, "%s: C_Login(%lu) failed: %lu",
			     pkcs11->soname, slot_id, ck_rv);
		goto err;
	}

	return CKR_OK;
err:
	pkcs11_session_close(pkcs11, session, dbg);
	return ck_rv;
}

CK_RV pkcs11_get_slots(struct pkcs11_module *pkcs11,
		       CK_SLOT_ID_PTR *slots, CK_ULONG *nslots,
		       struct dbg *dbg)
{
	CK_RV ck_rv;
	CK_SLOT_ID_PTR sl;
	CK_ULONG nsl;

	if (!pkcs11 | !slots | !nslots | !dbg)
		return CKR_ARGUMENTS_BAD;

	ck_rv = pkcs11->fns->C_GetSlotList(CK_TRUE, NULL_PTR, &nsl);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_GetSlotList(NULL) failed: %d",
			     pkcs11->soname, ck_rv);
		return ck_rv;
	}

	sl = malloc(nsl);
	if (!sl) {
		ps_dbg_error(dbg, "%s: slot-list allocation failed: nsl = %lu",
			     pkcs11->soname, nsl);
		return CKR_HOST_MEMORY;
	}

	ck_rv = pkcs11->fns->C_GetSlotList(CK_TRUE, sl, &nsl);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_GetSlotList(NULL) failed: %d",
			     pkcs11->soname, ck_rv);
		free(sl);
		return ck_rv;
	}

	*slots = sl;
	*nslots = nsl;

	return CKR_OK;
}

void pkcs11_module_teardown(struct pkcs11_module *pkcs)
{
	if (!pkcs)
		return;

	if (pkcs->state != PKCS11_INITIALIZED)
		return;

	if (pkcs->fns) {
		pkcs->fns->C_Finalize(NULL);
		pkcs->fns = NULL;
	}

	if (pkcs->dlhandle) {
		dlclose(pkcs->dlhandle);
		pkcs->dlhandle = NULL;
	}

	OPENSSL_free(pkcs->soname);
	pkcs->soname = NULL;

	pkcs->state = PKCS11_UNINITIALIZED;
}

#if !defined(RTLD_DEEPBIND)
#define RTLD_DEEPBIND 0
#endif

CK_RV pkcs11_module_init(struct pkcs11_module *pkcs,
			 const char *module,
			 const char *module_initargs,
			 struct dbg *dbg)
{
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	CK_C_INITIALIZE_ARGS args = {
		.flags = CKF_OS_LOCKING_OK,
		.pReserved = (void *)module_initargs,
	};
	CK_RV ck_rv = CKR_GENERAL_ERROR;

	if (!pkcs)
		return CKR_ARGUMENTS_BAD;

	/* TODO handle empty module */
	if (!module)
		return CKR_ARGUMENTS_BAD;
	pkcs->soname = OPENSSL_strdup(module);

	dlerror();
	pkcs->dlhandle = dlopen(module,
				RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
	if (!pkcs->dlhandle) {
		char *err = dlerror();
		ps_dbg_error(dbg, "%s: dlopen() failed: %s",
			     pkcs->soname, err);
		goto err;
	}

	c_get_function_list = dlsym(pkcs->dlhandle, "C_GetFunctionList");
	if (!c_get_function_list) {
		char *err = dlerror();
		ps_dbg_error(dbg, "%s: dlsym() failed: %s",
			     pkcs->soname, err);
		goto close_err;
	}

	ck_rv = c_get_function_list(&pkcs->fns);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_GetFunctionList() failed: %d",
			     pkcs->soname, ck_rv);
		goto close_err;
	}

	ck_rv = pkcs->fns->C_Initialize(&args);
	if (ck_rv != CKR_OK) {
		ps_dbg_error(dbg, "%s: C_Initialize(%s) failed: %d",
			     pkcs->soname, module_initargs, ck_rv);
		goto close_err;
	}

	pkcs->state = PKCS11_INITIALIZED;
	module_info(pkcs, dbg);

	return CKR_OK;

close_err:
	dlclose(pkcs->dlhandle);
err:
	OPENSSL_free(pkcs->soname);

	pkcs->soname = NULL;
	pkcs->dlhandle = NULL;
	pkcs->fns = NULL;

	return ck_rv;
}
