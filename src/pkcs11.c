/*
 * Copyright (C) IBM Corp. 2022
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dlfcn.h>
#include <openssl/crypto.h>

#include "debug.h"
#include "pkcs11.h"

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
