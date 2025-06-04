/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>

#include "common.h"
#include "provider.h"
#include "debug.h"
#include "pkcs11.h"
#include "uri.h"
#include "object.h"

#define KEY_PARAMS	4

static const int key_obj_type = OSSL_OBJECT_PKEY;

struct store_ctx {
	struct provider_ctx *pctx;
	struct parsed_uri *puri;
	CK_SLOT_ID slot_id;
	char *slot_login_info;
	bool objects_loaded;
	struct obj **objects;
	CK_ULONG nobjects;
	CK_ULONG load_idx;
	int expect;
};

#define MAX_PIN		64
static char *pin_from_cb(OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
			 const char *msg)
{
	OSSL_PARAM params[2] = {
		OSSL_PARAM_DEFN(OSSL_PASSPHRASE_PARAM_INFO,
				OSSL_PARAM_UTF8_STRING, (void *)msg,
				strlen(msg)),
		OSSL_PARAM_END,
	};
	char cbpin[MAX_PIN + 1] = { 0 };
	size_t cbpin_len;
	char *rv = NULL;

	if (pw_cb(cbpin, MAX_PIN, &cbpin_len, params, pw_cbarg) != OSSL_RV_OK)
		goto out;

	rv = OPENSSL_strndup(cbpin, cbpin_len);
out:
	OPENSSL_cleanse(cbpin, sizeof(cbpin));
	return rv;
}

static int key2params(struct obj *obj, OSSL_PARAM *params, unsigned int nparams)
{
	char *data_type;

	CK_KEY_TYPE tmp;

	if (nparams < KEY_PARAMS)
		return OSSL_RV_ERR;

	tmp = obj_get_key_type(obj);
	switch (tmp) {
	case CKK_RSA:
		data_type = "RSA";
		break;
	case CKK_ECDSA:
		data_type = "EC";
		break;
	default:
		return OSSL_RV_ERR;
	}

	params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, (int *)&key_obj_type);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
						     data_type, 0);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
						      obj, sizeof(struct obj));
	params[3] = OSSL_PARAM_construct_end();

	return OSSL_RV_OK;
}

static int object2params(struct obj *obj, OSSL_PARAM *params, unsigned int nparams)
{
	if (!obj || !params)
		return OSSL_RV_ERR;

	switch (obj_get_class(obj)) {
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		return key2params(obj, params, nparams);
	default:
		return OSSL_RV_ERR;
	}
}

static int get_object_params(struct obj *obj)
{
	CK_KEY_TYPE type;

	type = obj_get_key_type(obj);

	switch (type) {
	case CKK_RSA:
		obj->type = EVP_PKEY_RSA;
		break;
	case CKK_EC:
		obj->type = EVP_PKEY_EC;
		break;
	default:
		/* other types are not supported */
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static struct obj *get_next_loadable_object(struct store_ctx *sctx)
{
	if (!sctx)
		return NULL;

	while (sctx->load_idx < sctx->nobjects) {
		struct obj *o = sctx->objects[sctx->load_idx++];

		/* TODO add certificate support */
		switch (obj_get_class(o)) {
		case CKO_PUBLIC_KEY:
		case CKO_PRIVATE_KEY:
			return o;
		default:
			continue;
		}
	}

	return NULL;
}

static int handle_pkcs11_module(struct store_ctx *sctx)
{
	struct dbg *dbg = &sctx->pctx->dbg;
	struct parsed_uri *puri = sctx->puri;

	if (puri->mod_path) {
		/* TODO handle module-path correctly */
		ps_dbg_warn(dbg, "sctx: %p, ignore URI parameter module-path: %s",
			    sctx, puri->mod_path);
	}

	if (puri->mod_name) {
		/* TODO handle module-name correctly */
		ps_dbg_warn(dbg, "sctx: %p, ignore URI parameter module-name: %s",
			    sctx, puri->mod_name);
	}

	ps_dbg_info(dbg, "sctx: %p, use pkcs11-module %s",
		    sctx, sctx->pctx->pkcs11.soname);
	return 0;
}

static bool match_token_uri(struct pkcs11_module *pkcs11, CK_SLOT_ID slot_id,
			    struct parsed_uri *puri, struct dbg *dbg)
{
	CK_TOKEN_INFO ti;

	if(!puri->tok_token && !puri->tok_manuf &&
	   !puri->tok_serial && !puri->tok_model)
		return true;

	if (pkcs11_get_token_info(pkcs11, slot_id, &ti, dbg) != CKR_OK)
		return false;

	if (puri->tok_token &&
	    (pkcs11_strcmp(puri->tok_token, (const CK_CHAR_PTR)&ti.label,
			   sizeof(ti.label)) != 0))
		return false;

	if (puri->tok_manuf &&
	    (pkcs11_strcmp(puri->tok_manuf, (const CK_CHAR_PTR)&ti.manufacturerID,
			   sizeof(ti.manufacturerID)) != 0))
		return false;

	if (puri->tok_serial &&
	    (pkcs11_strcmp(puri->tok_serial, (const CK_CHAR_PTR)&ti.serialNumber,
			   sizeof(ti.serialNumber)) != 0))
		return false;

	if (puri->tok_model &&
	    (pkcs11_strcmp(puri->tok_model, (const CK_CHAR_PTR)&ti.model,
			   sizeof(ti.model)) != 0))
		return false;

	return true;
}

static bool match_slot_uri(struct pkcs11_module *pkcs11, CK_SLOT_ID slot_id,
			   struct parsed_uri *puri, struct dbg *dbg)
{
	CK_SLOT_INFO si;

	if (puri->slt_id &&
	    (slot_id != strtoul(puri->slt_id, NULL, 10)))
		return false;

	if (!puri->slt_manuf && !puri->slt_desc)
		return true;

	if (pkcs11_get_slot_info(pkcs11, slot_id, &si, dbg) != CKR_OK)
		return false;

	if (puri->slt_manuf &&
	    (pkcs11_strcmp(puri->slt_manuf, (const CK_CHAR_PTR)&si.manufacturerID,
			   sizeof(si.manufacturerID)) != 0))
		return false;

	if (puri->slt_desc &&
	    (pkcs11_strcmp(puri->slt_desc, (const CK_CHAR_PTR)&si.slotDescription,
			   sizeof(si.slotDescription)) != 0))
		return false;

	return true;
}

static bool match_library_uri(struct pkcs11_module *pkcs11, struct parsed_uri *puri,
			      struct dbg *dbg)
{
	CK_INFO ci;

	if (!puri->lib_manuf && !puri->lib_desc && !puri->lib_ver)
		return true;

	if (pkcs11_get_info(pkcs11, &ci, dbg) != CKR_OK)
		return false;

	if (puri->lib_manuf &&
	    (pkcs11_strcmp(puri->lib_manuf, (const CK_CHAR_PTR)&ci.manufacturerID,
			   sizeof(ci.manufacturerID)) != 0))
		return false;

	if (puri->lib_desc &&
	    (pkcs11_strcmp(puri->lib_desc, (const CK_CHAR_PTR)&ci.libraryDescription,
			   sizeof(ci.libraryDescription)) != 0))
		return false;

	if (puri->lib_ver &&
	    (puri->lib_ver_major != ci.libraryVersion.major ||
	     puri->lib_ver_minor != ci.libraryVersion.minor))
		return false;

	return true;
}

#define LOGIN_INFO_FMT	"PKCS#11 token \'%s\' in slot %lu (user pin)"
static void prepare_login_info(struct store_ctx *sctx, struct dbg *dbg)
{
	char *tlabel = NULL;
	CK_TOKEN_INFO ti;

	if (pkcs11_get_token_info(&sctx->pctx->pkcs11, sctx->slot_id,
				  &ti, dbg) == CKR_OK)
		tlabel = OPENSSL_strndup((char *)ti.label, pkcs11_strlen(ti.label, sizeof(ti.label)));

	asprintf(&sctx->slot_login_info, LOGIN_INFO_FMT,
		 tlabel ?: "", sctx->slot_id);
	OPENSSL_free(tlabel);
}

static int load_object_handles(struct store_ctx *sctx, CK_SESSION_HANDLE sh,
			       CK_OBJECT_HANDLE_PTR handles, CK_ULONG nhandles)
{
	struct provider_ctx *pctx = sctx->pctx;
	struct dbg *dbg = &pctx->dbg;
	struct obj **objs;
	CK_ULONG nobjs, i;

	objs = OPENSSL_zalloc((sizeof(struct obj *) * nhandles));
	if (!objs)
		return OSSL_RV_ERR;
	nobjs = nhandles;

	for (i = 0; i < nhandles; i++) {
		objs[i] = obj_new_init(pctx, sctx->slot_id, sctx->puri->pin);
		if (!objs[i]) {
			goto err;
		}

		if (pkcs11_fetch_attributes(&sctx->pctx->pkcs11, sh,
					    handles[i], &objs[i]->attrs,
					    &objs[i]->nattrs, dbg) != CKR_OK) {
			ps_dbg_error(dbg, "sctx: %p, attribute lookup failed (handle: %lu)",
				     sctx, handles[i]);
			goto err;
		}

		if (get_object_params(objs[i]) != OSSL_RV_OK) {
			ps_dbg_error(dbg, "sctx: %p, params lookup failed (handle: %lu)",
				     sctx, handles[i]);
			goto err;
		}
	}

	sctx->objects = objs;
	sctx->nobjects = nobjs;

	ps_dbg_debug(dbg, "sctx: %p, %d objects found", sctx, sctx->nobjects);

	return OSSL_RV_OK;
err:
	for (i = 0; i < nobjs; i++) {
		obj_free(objs[i]);
	}
	OPENSSL_free(objs);
	return OSSL_RV_ERR;
}

static CK_SLOT_ID lookup_slot_id(struct pkcs11_module *pkcs11, struct parsed_uri *puri, struct dbg *dbg)
{
	CK_SLOT_ID_PTR slots;
	CK_ULONG nslots, i;
	CK_SLOT_ID found = CK_UNAVAILABLE_INFORMATION;
	CK_SLOT_ID rv = CK_UNAVAILABLE_INFORMATION;

	if (pkcs11_get_slots(pkcs11, &slots, &nslots, dbg) != CKR_OK) {
		ps_dbg_debug(dbg, "%s: slot lookup failed",
			     pkcs11->soname);
		return rv;
	}

	for (i = 0; i < nslots; i++) {
		CK_SLOT_ID sid = slots[i];

		if (!match_slot_uri(pkcs11, sid, puri, dbg)) {
			ps_dbg_debug(dbg, "%s: slot %lu: slot mismatch",
				     pkcs11->soname, sid);
			continue;
		}

		if (!match_token_uri(pkcs11, sid, puri, dbg)) {
			ps_dbg_debug(dbg, "%s: slot %lu: token mismatch",
				     pkcs11->soname, sid);
			continue;
		}

		if (found != CK_UNAVAILABLE_INFORMATION) {
			ps_dbg_debug(dbg, "%s: too many matching slots/tokens (%lu, %lu)",
				     pkcs11->soname, found, sid);
			goto out;
		}

		found = sid;
	}

	rv = found;
out:
	OPENSSL_free(slots);
	return rv;
}

static int lookup_objects(struct store_ctx *sctx,
			  OSSL_PASSPHRASE_CALLBACK *pw_cb,
			  void *pw_cbarg)
{
	struct pkcs11_module *pkcs11 = &sctx->pctx->pkcs11;
	CK_SESSION_HANDLE sh = CK_INVALID_HANDLE;
	struct parsed_uri *puri = sctx->puri;
	CK_OBJECT_HANDLE_PTR handles = NULL;
	struct dbg *dbg = &sctx->pctx->dbg;
	int rv = OSSL_RV_ERR;
	CK_ULONG nhandles;

	if (!puri->pin)
		puri->pin = pin_from_cb(pw_cb, pw_cbarg, sctx->slot_login_info);

	if (pkcs11_session_open_login(pkcs11, sctx->slot_id, &sh,
				      puri->pin, dbg) != CKR_OK)
		return OSSL_RV_ERR;

	if (pkcs11_find_objects(pkcs11, sh,
				puri->obj_object, puri->obj_id.p,
				puri->obj_id.plen, puri->obj_type,
				&handles, &nhandles, dbg) != CKR_OK)
		goto err;

	if (nhandles== 0) {
		ps_dbg_error(dbg, "sctx: %p, no objects found in slot %d",
			     sctx, sctx->slot_id);
		goto err;
	}

	sctx->load_idx = 0;
	if (load_object_handles(sctx, sh, handles, nhandles) != OSSL_RV_OK) {
		ps_dbg_error(dbg, "sctx: %p, slot %d failed to load object handles",
			     sctx, sctx->slot_id);
		goto err;
	}

	sctx->objects_loaded = true;
	rv = OSSL_RV_OK;
err:
	pkcs11_session_close(&sctx->pctx->pkcs11, &sh, dbg);
	OPENSSL_free(handles);
	return rv;
}

static int store_ctx_open(struct store_ctx *sctx, const char *uri)
{
	struct pkcs11_module *pkcs11 = &sctx->pctx->pkcs11;
	struct dbg *dbg = &sctx->pctx->dbg;

	sctx->puri = parsed_uri_new(uri);
	if (!sctx->puri) {
		ps_dbg_error(dbg, "sctx: %p, parsed_uri_new() failed. uri: %s",
			     sctx, uri);
		return OSSL_RV_ERR;
	}

	if (handle_pkcs11_module(sctx)) {
		ps_dbg_error(dbg, "sctx: %p, pkcs11 module handling failed. uri: %s",
			     sctx, uri);
		return OSSL_RV_ERR;
	}

	if (!match_library_uri(pkcs11, sctx->puri, dbg)) {
		ps_dbg_debug(dbg, "sctx: %p, library mismatch",
			     sctx);
		return OSSL_RV_ERR;
	}

	sctx->slot_id = lookup_slot_id(pkcs11, sctx->puri, dbg);
	if (sctx->slot_id == CK_UNAVAILABLE_INFORMATION) {
		ps_dbg_debug(dbg, "sctx: %p, no matching slot/token found",
			     sctx);
		return OSSL_RV_ERR;
	}

	prepare_login_info(sctx, dbg);

	ps_dbg_debug(dbg, "sctx: %p, token in slot %lu selected",
		     sctx, sctx->slot_id);

	return OSSL_RV_OK;
}

static void store_ctx_free(struct store_ctx *sctx)
{
	CK_ULONG i;

	if (!sctx)
		return;

	parsed_uri_free(sctx->puri);
	for (i = 0; i < sctx->nobjects; i++) {
		obj_free(sctx->objects[i]);
	}
	free(sctx->slot_login_info);
	OPENSSL_free(sctx->objects);
	OPENSSL_free(sctx);
}

static struct store_ctx *store_ctx_init(struct provider_ctx *pctx)
{
	struct store_ctx *sctx;

	sctx = OPENSSL_zalloc(sizeof(struct store_ctx));
	if (!sctx)
		return NULL;

	sctx->pctx = pctx;
	sctx->slot_id = CK_UNAVAILABLE_INFORMATION;
	sctx->objects_loaded = false;

	return sctx;
}

#define DISP_STORE_FN(tname, name) DECL_DISPATCH_FUNC(store, tname, name)
DISP_STORE_FN(open, ps_store_open);
#ifdef OSSL_FUNC_STORE_OPEN_EX
DISP_STORE_FN(open_ex, ps_store_open_ex);
#endif
DISP_STORE_FN(load, ps_store_load);
DISP_STORE_FN(eof, ps_store_eof);
DISP_STORE_FN(close, ps_store_close);
DISP_STORE_FN(export_object, ps_store_export_object);
DISP_STORE_FN(set_ctx_params, ps_store_set_ctx_params);
DISP_STORE_FN(settable_ctx_params, ps_store_settable_ctx_params);

static void *ps_store_open(void *vpctx, const char *uri)
{
	struct provider_ctx *pctx = (struct provider_ctx *)vpctx;
	struct dbg *dbg;
	struct store_ctx *sctx;

	if (!pctx || !uri)
		return NULL;
	dbg = &pctx->dbg;

	ps_dbg_debug(dbg, "entry: pctx: %pi, uri: %s",
		     pctx, uri);

	sctx = store_ctx_init(pctx);
	if (!sctx)
		return NULL;

	if (store_ctx_open(sctx, uri) != OSSL_RV_OK) {
		store_ctx_free(sctx);
		return NULL;
	}

	ps_dbg_debug(dbg, "exit: sctx: %p, pctx: %p",
		     sctx, pctx);

	return sctx;
}

#ifdef OSSL_FUNC_STORE_OPEN_EX
static void *ps_store_open_ex(void *vpctx, const char *uri,
			      const OSSL_PARAM params[],
			      OSSL_PASSPHRASE_CALLBACK *pw_cb __unused,
			      void *pw_cbarg __unused)
{
	struct provider_ctx *pctx = (struct provider_ctx *)vpctx;
	struct store_ctx *sctx;
	struct dbg *dbg;

	if (!pctx || !uri)
		return NULL;
	dbg = &pctx->dbg;

	ps_dbg_debug(dbg, "entry: pctx: %pi, uri: %s",
		     pctx, uri);

	sctx = ps_store_open(pctx, uri);
	if (!sctx)
		return NULL;

	if ((ps_store_set_ctx_params(sctx, params) != OSSL_RV_OK) ||
	    (lookup_objects(sctx, pw_cb, pw_cbarg) != OSSL_RV_OK)) {
		store_ctx_free(sctx);
		return NULL;
	}

	ps_dbg_debug(dbg, "exit: sctx: %p, pctx: %p",
		     sctx, pctx);

	return sctx;
}
#endif

static int ps_store_load(void *vctx,
			 OSSL_CALLBACK *object_cb,
			 void *object_cbarg,
			 OSSL_PASSPHRASE_CALLBACK *pw_cb,
			 void *pw_cbarg)
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg;
	struct obj *obj;
	OSSL_PARAM params[KEY_PARAMS];

	if (!sctx)
		return OSSL_RV_ERR;
	dbg = &sctx->pctx->dbg;

	ps_dbg_debug(dbg, "sctx: %p, pctx: %p, entry",
		     sctx, sctx->pctx);

	if (!sctx->objects_loaded &&
	    (lookup_objects(sctx, pw_cb, pw_cbarg) != OSSL_RV_OK))
		return OSSL_RV_ERR;

	obj = get_next_loadable_object(sctx);
	if (!obj)
		return OSSL_RV_ERR;

	if (object2params(obj, params, KEY_PARAMS) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	ps_dbg_debug(dbg, "sctx: %p, pctx: %p, --> obj: %p",
		     sctx, sctx->pctx, obj);

	return object_cb(params, object_cbarg);
}

static int ps_store_eof(void *vctx)
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg;
	int rv;

	if (!sctx)
		return OSSL_RV_TRUE;
	dbg = &sctx->pctx->dbg;

	ps_dbg_debug(dbg, "sctx: %p, pctx: %p, entry",
		     sctx, sctx->pctx);

	rv = (!sctx->objects_loaded || (sctx->load_idx < sctx->nobjects)) ?
		OSSL_RV_FALSE : OSSL_RV_TRUE;

	ps_dbg_debug(dbg, "sctx: %p, pctx: %p, exit: %d",
		     sctx, sctx->pctx, rv);

	return rv;
}

static int ps_store_close(void *vctx)
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg;

	if (!sctx)
		return OSSL_RV_ERR;
	dbg = &sctx->pctx->dbg;

	ps_dbg_debug(dbg, "sctx: %p, pctx: %p, entry",
		     sctx, sctx->pctx);

	store_ctx_free(sctx);

	return OSSL_RV_OK;
}

static int ps_store_export_object(void *vctx ,
				  const void *reference, size_t reference_sz,
				  OSSL_CALLBACK *cb_fn __unused,
				  void *cb_arg __unused)
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg;

	if (!sctx)
		return OSSL_RV_ERR;
	dbg = &sctx->pctx->dbg;

	ps_dbg_debug(dbg, "sctx: %p, pctx: %p, reference %p, reference_sz: %lu",
		     sctx, sctx->pctx, reference, reference_sz);

	/* TODO export public keys and certificates */
	return OSSL_RV_ERR;
}

static const OSSL_PARAM *ps_store_settable_ctx_params(void *pctx __unused)
{
	static const OSSL_PARAM known_settable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
		OSSL_PARAM_END,
	};
	return known_settable_ctx_params;
}

static int ps_store_set_ctx_params(void *vctx,
				   const OSSL_PARAM params[])
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	const OSSL_PARAM *p;
	struct dbg *dbg;

	if (!sctx)
		return OSSL_RV_ERR;
	dbg = &sctx->pctx->dbg;

	ps_dbg_debug(dbg, "sctx: %p", sctx);
	for (p = params; (p && p->key); p++)
		ps_dbg_debug(dbg, "param: %s (type: 0x%x)",
			     p->key, p->data_type);

	p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
	if (p) {
		int val;

		if (OSSL_PARAM_get_int(p, &val) != OSSL_RV_OK)
			return OSSL_RV_ERR;
		ps_dbg_debug(dbg, "expect: %d", val);
		switch (val) {
		case OSSL_STORE_INFO_PKEY:
			break;
		default:
			ps_dbg_debug(dbg, "expect: %d not supported", val);
			return OSSL_RV_ERR;
		}
		sctx->expect = val;
	}

	return OSSL_RV_OK;
}

#define DISP_STORE_ELEM(NAME, name) \
	{ OSSL_FUNC_STORE_##NAME, (void (*)(void))name }
static const OSSL_DISPATCH ps_store_funcs[] = {
	DISP_STORE_ELEM(OPEN, ps_store_open),
#ifdef OSSL_FUNC_STORE_OPEN_EX
	DISP_STORE_ELEM(OPEN, ps_store_open_ex),
#endif
	DISP_STORE_ELEM(LOAD, ps_store_load),
	DISP_STORE_ELEM(EOF, ps_store_eof),
	DISP_STORE_ELEM(CLOSE, ps_store_close),
	DISP_STORE_ELEM(SET_CTX_PARAMS, ps_store_set_ctx_params),
	DISP_STORE_ELEM(SETTABLE_CTX_PARAMS, ps_store_settable_ctx_params),
	DISP_STORE_ELEM(EXPORT_OBJECT, ps_store_export_object),
	{ 0, NULL },
};

const OSSL_ALGORITHM ps_store[] = {
	{ "pkcs11", "provider=" PS_PROV_NAME, ps_store_funcs, "PKCS11 URI Store" },
	{ NULL, NULL, NULL, NULL },
};
