/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <openssl/store.h>
#include <openssl/core_names.h>

#include "common.h"
#include "provider.h"
#include "debug.h"
#include "pkcs11.h"
#include "uri.h"

struct store_ctx {
	struct provider_ctx *provctx;
	struct parsed_uri *puri;
	struct pkcs11_module *pkcs11;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE_PTR objects;
	CK_ULONG nobjects;
};

static int handle_pkcs11_module(struct store_ctx *sctx)
{
	struct dbg *dbg = &sctx->provctx->dbg;
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

	if (!sctx->pkcs11) {
		sctx->pkcs11 = &sctx->provctx->pkcs11;
	}

	ps_dbg_info(dbg, "sctx: %p, use pkcs11-module %s",
		    sctx, sctx->pkcs11->soname);
	return 0;
}

static bool match_token_uri(struct pkcs11_module *pkcs11, CK_SLOT_ID slot_id,
			    struct parsed_uri *puri)
{
	CK_TOKEN_INFO ti;

	if(!puri->tok_token && !puri->tok_manuf &&
	   !puri->tok_serial && !puri->tok_model)
		return true;

	if (pkcs11->fns->C_GetTokenInfo(slot_id, &ti) != CKR_OK)
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
			   struct parsed_uri *puri)
{
	CK_SLOT_INFO si;

	if (puri->slt_id &&
	    (slot_id != strtoul(puri->slt_id, NULL, 10)))
		return false;

	if (!puri->slt_manuf && !puri->slt_desc)
		return true;

	if (pkcs11->fns->C_GetSlotInfo(slot_id, &si) != CKR_OK)
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

static bool match_library_uri(struct pkcs11_module *pkcs11, struct parsed_uri *puri)
{
	CK_INFO ci;

	if (!puri->lib_manuf && !puri->lib_desc && !puri->lib_ver)
		return true;

	if (pkcs11->fns->C_GetInfo(&ci) != CKR_OK)
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

static int lookup_objects(struct store_ctx *sctx)
{
	struct dbg *dbg = &sctx->provctx->dbg;
	struct pkcs11_module *pkcs11 = sctx->pkcs11;
	struct parsed_uri *puri = sctx->puri;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG nslots = 0, i;
	CK_RV rv;

	if (!match_library_uri(pkcs11, puri)) {
		ps_dbg_debug(dbg, "sctx: %p, library mismatch",
			     sctx);
		return 1;
	}

	rv = pkcs11_get_slots(pkcs11, &slots, &nslots, dbg);
	if (rv != CKR_OK) {
		ps_dbg_debug(dbg, "sctx: %p, no slots found",
			     sctx);
		return 1;
	}

	for (i = 0; i < nslots; i++) {
		CK_SLOT_ID sid = slots[i];

		if (!match_slot_uri(pkcs11, sid, puri)) {
			ps_dbg_debug(dbg, "sctx: %p, slot %lu: slot mismatch",
				     sctx, sid);
			continue;
		}

		if (!match_token_uri(pkcs11, sid, puri)) {
			ps_dbg_debug(dbg, "sctx: %p, slot %lu: token mismatch",
				     sctx, sid);
			continue;
		}

		if (sctx->slot_id != CK_UNAVAILABLE_INFORMATION) {
			ps_dbg_debug(dbg, "sctx: %p, too many matching slots/tokens",
				     sctx);
			return 1;
		}

		sctx->slot_id = sid;
	}

	if (sctx->slot_id == CK_UNAVAILABLE_INFORMATION) {
		ps_dbg_debug(dbg, "sctx: %p, no matching slot/token found",
			     sctx);
		return 1;
	}

	ps_dbg_debug(dbg, "sctx: %p, token in slot %lu selected",
		     sctx, sctx->slot_id);

	rv = pkcs11_session_open_login(pkcs11, sctx->slot_id, &sctx->session,
				  puri->pin, dbg);
	if (rv != CKR_OK) {
		return 1;
	}

	rv = pkcs11_find_objects(pkcs11, sctx->session,
				 puri->obj_object, puri->obj_id, puri->obj_type,
				 &sctx->objects, &sctx->nobjects,
				 dbg);
	if (rv != CKR_OK) {
		return 1;
	}

	if (sctx->nobjects == 0) {
		ps_dbg_error(dbg, "%s: no objects found in slot %d",
			     sctx, sctx->slot_id);
		return 1;
	}

	/* TODO tolerate up to 3 objects (max 1 of priv, pub and cert) */
	if (sctx->nobjects > 1) {
		ps_dbg_error(dbg, "%s: too many (%d) objects found in slot %d",
			     sctx, sctx->nobjects, sctx->slot_id);
		OPENSSL_free(sctx->objects);
		sctx->objects = NULL_PTR;
		sctx->nobjects = 0;
		return 1;
	}

	return 0;
}

static void ps_store_ctx_free(struct store_ctx *sctx)
{
	if (!sctx)
		return;

	sctx->provctx = NULL;

	parsed_uri_free(sctx->puri);
	OPENSSL_free(sctx);
}

static struct store_ctx *store_ctx_init(struct provider_ctx *provctx,
					   const char *uri)
{
	struct dbg *dbg = &provctx->dbg;
	struct store_ctx *sctx;

	sctx = OPENSSL_zalloc(sizeof(struct store_ctx));
	if (!sctx)
		return NULL;

	sctx->puri = parsed_uri_new(uri);
	if (!sctx->puri) {
		ps_dbg_error(dbg, "provctx: %p, parsed_uri_new() failed. uri: %s",
			     provctx, uri);
		ps_store_ctx_free(sctx);
		return NULL;
	}

	sctx->provctx = provctx;

	if (handle_pkcs11_module(sctx)) {
		ps_dbg_error(dbg, "provctx: %p, pkcs11 module handling failed. uri: %s",
			     provctx, uri);
		ps_store_ctx_free(sctx);
		return NULL;
	}

	sctx->slot_id = CK_UNAVAILABLE_INFORMATION;

	return sctx;
}

#define DISPATCH_STORE_FN(tname, name) DECL_DISPATCH_FUNC(store, tname, name)
#define DISPATCH_STORE_ELEM(NAME, name) \
	{ OSSL_FUNC_STORE_##NAME, (void (*)(void))name }

DISPATCH_STORE_FN(open, ps_store_open);
DISPATCH_STORE_FN(attach, ps_store_attach);
DISPATCH_STORE_FN(load, ps_store_load);
DISPATCH_STORE_FN(eof, ps_store_eof);
DISPATCH_STORE_FN(close, ps_store_close);
DISPATCH_STORE_FN(export_object, ps_store_export_object);
DISPATCH_STORE_FN(set_ctx_params, ps_store_set_ctx_params);
DISPATCH_STORE_FN(settable_ctx_params, ps_store_settable_ctx_params);

static void *ps_store_open(void *vpctx, const char *uri)
{
	struct provider_ctx *provctx = (struct provider_ctx *)vpctx;
	struct dbg *dbg = &provctx->dbg;
	struct store_ctx *sctx;

	if (!provctx || !uri)
		return NULL;

	ps_dbg_debug(dbg, "entry: provctx: %p",
		     provctx);

	sctx = store_ctx_init(provctx, uri);
	if (!sctx)
		return NULL;

	if (lookup_objects(sctx)) {
		ps_store_ctx_free(sctx);
		return NULL;
	}

	ps_dbg_debug(dbg, "exit: sctx: %p, provctx: %p",
		     sctx, provctx);

	return sctx;
}

static void *ps_store_attach(void *vctx,
			     OSSL_CORE_BIO *in __attribute__((unused)))
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg = &sctx->provctx->dbg;

	if (!sctx)
		return OSSL_RV_ERR;

	ps_dbg_debug(dbg, "sctx: %p, provctx: %p",
		     sctx, sctx->provctx);
	return NULL;
}

static int ps_store_load(void *vctx,
			 OSSL_CALLBACK *object_cb __attribute__((unused)),
			 void *object_cbarg __attribute__((unused)),
			 OSSL_PASSPHRASE_CALLBACK *pw_cb __attribute__((unused)),
			 void *pw_cbarg __attribute__((unused)))
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg = &sctx->provctx->dbg;

	if (!sctx)
		return OSSL_RV_ERR;

	ps_dbg_debug(dbg, "sctx: %p, provctx: %p",
		     sctx, sctx->provctx);

	return OSSL_RV_ERR;
}

static int ps_store_eof(void *vctx)
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg = &sctx->provctx->dbg;

	if (!sctx)
		return OSSL_RV_ERR;

	ps_dbg_debug(dbg, "sctx: %p, provctx: %p",
		     sctx, sctx->provctx);

	return OSSL_RV_ERR;
}

static int ps_store_close(void *vctx)
{
	struct store_ctx *sctx = (struct store_ctx *)vctx;
	struct dbg *dbg;

	if (!sctx)
		return OSSL_RV_ERR;
	dbg = &sctx->provctx->dbg;

	ps_dbg_debug(dbg, "sctx: %p, provctx: %p",
		     sctx, sctx->provctx);

	pkcs11_session_close(&sctx->provctx->pkcs11, &sctx->session, dbg);

	ps_store_ctx_free(sctx);

	return OSSL_RV_OK;
}

static int ps_store_export_object(void *loaderctx, const void *reference,
				  size_t reference_sz,
				  OSSL_CALLBACK *cb_fn, void *cb_arg)
{
	return OSSL_RV_ERR;
}

static const OSSL_PARAM *ps_store_settable_ctx_params(void *provctx)
{
	static const OSSL_PARAM known_settable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
		OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
		OSSL_PARAM_BN(OSSL_STORE_PARAM_SERIAL, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_DIGEST, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_STORE_PARAM_FINGERPRINT, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, NULL, 0),
		OSSL_PARAM_END,
	};
	return known_settable_ctx_params;
}

static int ps_store_set_ctx_params(void *pctx, const OSSL_PARAM params[])
{
	return OSSL_RV_ERR;
}

static const OSSL_DISPATCH ps_store_funcs[] = {
	DISPATCH_STORE_ELEM(OPEN, ps_store_open),
	DISPATCH_STORE_ELEM(ATTACH, ps_store_attach),
	DISPATCH_STORE_ELEM(LOAD, ps_store_load),
	DISPATCH_STORE_ELEM(EOF, ps_store_eof),
	DISPATCH_STORE_ELEM(CLOSE, ps_store_close),
	DISPATCH_STORE_ELEM(SET_CTX_PARAMS, ps_store_set_ctx_params),
	DISPATCH_STORE_ELEM(SETTABLE_CTX_PARAMS, ps_store_settable_ctx_params),
	DISPATCH_STORE_ELEM(EXPORT_OBJECT, ps_store_export_object),
	{ 0, NULL },
};

const OSSL_ALGORITHM ps_store[] = {
	{ "pkcs11", "provider=" PS_PROV_NAME, ps_store_funcs, "PKCS11 URI Store" },
	{ NULL, NULL, NULL, NULL },
};
