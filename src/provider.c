/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 * Authors: Holger Dengler <dengler@linux.ibm.com>
 *          Ingo Franzki <ifranzki@linux.ibm.com>
 */

#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include "asym.h"
#include "common.h"
#include "debug.h"
#include "keyexch.h"
#include "keymgmt.h"
#include "object.h"
#include "ossl.h"
#include "pkcs11.h"
#include "provider.h"
#include "signature.h"
#include "store.h"

#define PS_PROV_DESCRIPTION	"PKCS11 signing key provider"
#ifdef HAVE_CONFIG_H
#include "config.h"
#define PS_PROV_VERSION		PACKAGE_VERSION
#else
#define PS_PROV_VERSION		"n/a"
#endif

#define PS_PKCS11_MODULE_PATH			"pkcs11sign-module-path"
#define PS_PKCS11_MODULE_INIT_ARGS		"pkcs11sign-module-init-args"
#define PS_PKCS11_FWD				"pkcs11sign-forward"

#define DISPATCH_PROVIDER_FN(tname, name) DECL_DISPATCH_FUNC(provider, tname, name)
DISPATCH_PROVIDER_FN(teardown, 			ps_prov_teardown);
DISPATCH_PROVIDER_FN(gettable_params, 		ps_prov_gettable_params);
DISPATCH_PROVIDER_FN(get_params, 		ps_prov_get_params);
DISPATCH_PROVIDER_FN(query_operation, 		ps_prov_query_operation);
DISPATCH_PROVIDER_FN(get_reason_strings, 	ps_prov_get_reason_strings);
DISPATCH_PROVIDER_FN(get_capabilities, 		ps_prov_get_capabilities);

struct dbg *hack_dbg = NULL;

static void provider_ctx_teardown(struct provider_ctx *pctx)
{
	if (!pctx)
		return;

	ps_dbg_exit(&pctx->dbg);

	return;
}

static int provider_ctx_init(struct provider_ctx *pctx)
{
	if (!pctx)
		return OSSL_RV_ERR;

	ps_dbg_init(&pctx->dbg);

	return OSSL_RV_OK;
}

static void provider_ctx_free(struct provider_ctx *pctx)
{
	if (!pctx)
		return;

	OPENSSL_free(pctx);
}

static inline struct provider_ctx *provider_ctx_new(void)
{
	return OPENSSL_zalloc(sizeof(struct provider_ctx));
}

static const OSSL_PARAM ps_prov_param_types[] = {
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL,
									0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *ps_prov_gettable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (pctx == NULL)
		return NULL;

	ps_pctx_debug(pctx, "pctx: %p", pctx);
	return ps_prov_param_types;
}

static int ps_prov_get_params(void *vpctx, OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;
	OSSL_PARAM *p;

	if (pctx == NULL)
		return 0;

	ps_pctx_debug(pctx, "pctx: %p", pctx);

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PS_PROV_DESCRIPTION)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "OSSL_PARAM_set_utf8_ptr failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PS_PROV_VERSION)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "OSSL_PARAM_set_utf8_ptr failed");
	return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PS_PROV_VERSION)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "OSSL_PARAM_set_utf8_ptr failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "OSSL_PARAM_set_int failed");
		return 0;
	}

	return 1;
}

static const OSSL_ALGORITHM *ps_prov_query_operation(void *vpctx,
						     int operation_id,
						     int *no_cache)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	*no_cache = 0;

	ps_pctx_debug(pctx, "pctx: %p operation_id: %d", pctx, operation_id);

	switch (operation_id) {
	case OSSL_OP_KEYMGMT:
		return ps_keymgmt;
	case OSSL_OP_KEYEXCH:
		return ps_keyexch;
	case OSSL_OP_SIGNATURE:
		return ps_signature;
	case OSSL_OP_ASYM_CIPHER:
		return ps_asym_cipher;
	case OSSL_OP_STORE:
		return ps_store;
	}

	return NULL;
}

static void ps_prov_teardown(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return;

	pkcs11_module_free(pctx->pkcs11);
	pctx->pkcs11 = NULL;

	fwd_teardown(&pctx->fwd);
	core_teardown(&pctx->core);

	provider_ctx_teardown(pctx);
	provider_ctx_free(pctx);
}

static const OSSL_ITEM *ps_prov_get_reason_strings(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	ps_pctx_debug(pctx, "pctx: %p", pctx);
	return ps_prov_reason_strings;
}

static int ps_prov_get_capabilities(void *vpctx,
				    const char *capability, OSSL_CALLBACK *cb, void *arg)
{
	struct provider_ctx *pctx = vpctx;

	ps_pctx_debug(pctx, "pctx: %p capability: %s", pctx,
		     capability);

	if (pctx->fwd.provider == NULL)
		return 0;

	return OSSL_PROVIDER_get_capabilities(pctx->fwd.provider,
					      capability, cb, arg);
}

static const OSSL_DISPATCH ps_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN,
		(void (*)(void))ps_prov_teardown },
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
		(void (*)(void))ps_prov_gettable_params },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS,
		(void (*)(void))ps_prov_get_params },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION,
		(void (*)(void))ps_prov_query_operation },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
		(void (*)(void))ps_prov_get_reason_strings },
	{ OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
		(void (*)(void))ps_prov_get_capabilities },
	{ 0, NULL }
};

static int ps_prov_init(const OSSL_CORE_HANDLE *handle,
			const OSSL_DISPATCH *in,
			const OSSL_DISPATCH **out,
			void **vctx)
{
	struct provider_ctx *pctx = NULL;
	OSSL_PARAM core_params[4] = { 0 };
	const char *module = NULL;
	const char *module_args = NULL;
	const char *fwd = NULL;

	if (!handle || !in || !out || !vctx)
		return OSSL_RV_ERR;

	pctx = provider_ctx_new();
	if (!pctx)
		return OSSL_RV_ERR;

	if (provider_ctx_init(pctx) != OSSL_RV_OK)
		goto err;
	ps_dbg_info(&pctx->dbg, "provider: %s", PS_PROV_NAME);
#ifdef HAVE_CONFIG_H
	ps_dbg_info(&pctx->dbg, "version: %s", PACKAGE_VERSION);
#endif

	if (core_init(&pctx->core, handle, in, &pctx->dbg) != OSSL_RV_OK) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "Failed to initialize provider core");
		goto err;
	}

	core_params[0] = OSSL_PARAM_construct_utf8_ptr(
				PS_PKCS11_MODULE_PATH,
				(char **)&module, sizeof(module));
	core_params[1] = OSSL_PARAM_construct_utf8_ptr(
				PS_PKCS11_MODULE_INIT_ARGS,
				(char **)&module_args, sizeof(module_args));
	core_params[2] = OSSL_PARAM_construct_utf8_ptr(
				PS_PKCS11_FWD,
				(char **)&fwd, sizeof(fwd));
	core_params[3] = OSSL_PARAM_construct_end();

	if (pctx->core.fns.get_params(handle, core_params) != OSSL_RV_OK) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "Failed to get configured parameters");
		goto err;
	}

	ps_pctx_debug(pctx, "pctx: %p, %s: %s, modified: %d", pctx,
		     PS_PKCS11_MODULE_PATH, module,
		     OSSL_PARAM_modified(&core_params[0]));
	ps_pctx_debug(pctx, "pctx: %p, %s: %s, modified: %d", pctx,
		     PS_PKCS11_MODULE_INIT_ARGS, module_args,
		     OSSL_PARAM_modified(&core_params[1]));
	ps_pctx_debug(pctx, "pctx: %p, %s: %s, modified: %d", pctx,
		     PS_PKCS11_FWD, fwd,
		     OSSL_PARAM_modified(&core_params[2]));

	if (!OSSL_PARAM_modified(&core_params[2]))
		fwd = "default";

	/* REVISIT skip provider prefix if present */
	if (strncmp(fwd, "provider=", strlen("provider=")) == 0)
		fwd += strlen("provider=");

	if (fwd_init(&pctx->fwd, fwd, pctx->core.libctx,
		     &pctx->dbg) != OSSL_RV_OK) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "Failed to initialize forward %s", fwd);
		goto err;
	}
	ps_pctx_debug(pctx, "pctx: %p, forward: %s", pctx, pctx->fwd.name);

	pctx->pkcs11 = pkcs11_module_new(module, module_args, &pctx->dbg);
	if (!pctx->pkcs11) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "Failed to initialize pkcs11 module %s", module);
		goto err;
	}
	ps_pctx_debug(pctx, "pctx: %p, pkcs11: %s", pctx, pctx->pkcs11->soname);

	*vctx = pctx;
	*out = ps_dispatch_table;
	hack_dbg = &pctx->dbg;
	return OSSL_RV_OK;

err:
	ps_prov_teardown(pctx);
	return OSSL_RV_ERR;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out,
		       void **vctx)
{
	return ps_prov_init(handle, in, out, vctx);
}
