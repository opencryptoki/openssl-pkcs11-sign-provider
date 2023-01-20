/*
 * Copyright (C) IBM Corp. 2022
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
};

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
	struct store_ctx *sctx;

	sctx = OPENSSL_zalloc(sizeof(struct store_ctx));
	if (!sctx)
		return NULL;


	sctx->puri = parsed_uri_new(uri);
	if (!sctx->puri) {
		ps_dbg_error(&provctx->dbg, "parsed_uri_new() failed. uri: %s",
			     uri);
		ps_store_ctx_free(sctx);
		return NULL;
	}

	sctx->provctx = provctx;

	/* TODO load pkcs11-module from uri */
	if (!sctx->pkcs11)
		sctx->pkcs11 = &provctx->pkcs11;

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
