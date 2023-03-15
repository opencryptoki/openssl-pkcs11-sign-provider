/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 * Authors: Holger Dengler <dengler@linux.ibm.com>
 *          Ingo Franzki <ifranzki@linux.ibm.com>
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "common.h"
#include "debug.h"
#include "ossl.h"

#define ps_opctx_debug(opctx, fmt...)	ps_dbg_debug(&(opctx->pctx->dbg), fmt)

struct ps_op_ctx {
	struct provider_ctx *pctx;
	struct obj *key;

	CK_OBJECT_HANDLE ohandle;
	CK_SESSION_HANDLE shandle;

	int type;

	/* legacy */
	const char *propq;
	void *fwd_op_ctx; /* shadow context of default provider */
	void (*fwd_op_ctx_free)(void *fwd_op_ctx);
	int operation;
	OSSL_FUNC_signature_sign_fn *sign_fn;
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
};

static void ps_op_freectx(void *vopctx __unused)
{
}

static struct ps_op_ctx *ps_op_dupctx(struct ps_op_ctx *opctx __unused)
{
	return NULL;
}

static struct ps_op_ctx *ps_op_newctx(struct provider_ctx *pctx __unused, const char *propq __unused, int type __unused)
{
	return NULL;
}

static struct ps_op_ctx *ps_op_init(struct ps_op_ctx *opctx __unused, struct obj *key __unused, int operation __unused)
{
	return NULL;
}

#define DISP_KEYEXCH_FN(tname, name) DECL_DISPATCH_FUNC(keyexch, tname, name)
DISP_KEYEXCH_FN(newctx, ps_keyexch_ec_newctx);
DISP_KEYEXCH_FN(dupctx, ps_keyexch_ec_dupctx);
DISP_KEYEXCH_FN(init, ps_keyexch_ec_init);
DISP_KEYEXCH_FN(set_peer, ps_keyexch_ec_set_peer);
DISP_KEYEXCH_FN(derive, ps_keyexch_ec_derive);
DISP_KEYEXCH_FN(set_ctx_params, ps_keyexch_ec_set_ctx_params);
DISP_KEYEXCH_FN(get_ctx_params, ps_keyexch_ec_get_ctx_params);
DISP_KEYEXCH_FN(settable_ctx_params, ps_keyexch_ec_settable_ctx_params);
DISP_KEYEXCH_FN(gettable_ctx_params, ps_keyexch_ec_gettable_ctx_params);

// keep
static void *ps_keyexch_ec_newctx(void *vpctx)
{
	OSSL_FUNC_keyexch_freectx_fn *default_freectx_fn;
	OSSL_FUNC_keyexch_newctx_fn *default_newctx_fn;
	struct provider_ctx *pctx = vpctx;
	struct ps_op_ctx *opctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

	default_newctx_fn = (OSSL_FUNC_keyexch_newctx_fn *)
		fwd_keyexch_get_func(&pctx->fwd,
				     OSSL_FUNC_KEYEXCH_NEWCTX,
				     &pctx->dbg);
	if (default_newctx_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default newctx_fn");
		return NULL;
	}

	default_freectx_fn = (OSSL_FUNC_keyexch_freectx_fn *)
		fwd_keyexch_get_func(&pctx->fwd,
				     OSSL_FUNC_KEYEXCH_FREECTX,
				     &pctx->dbg);
	if (default_freectx_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default freectx_fn");
		return NULL;
	}

	opctx = ps_op_newctx(pctx, NULL, EVP_PKEY_EC);
	if (opctx == NULL) {
		ps_dbg_debug(&pctx->dbg, "ERROR: ps_op_newctx failed");
		return NULL;
	}

	opctx->fwd_op_ctx = default_newctx_fn(pctx->fwd.ctx);
	if (opctx->fwd_op_ctx == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "default_newctx_fn failed");
		ps_op_freectx(opctx);
		return NULL;
	}
	opctx->fwd_op_ctx_free = default_freectx_fn;

	ps_dbg_debug(&pctx->dbg, "opctx: %p", opctx);

	return opctx;
}

// keep
static void *ps_keyexch_ec_dupctx(void *vctx)
{
	OSSL_FUNC_keyexch_dupctx_fn *default_dupctx_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	default_dupctx_fn = (OSSL_FUNC_keyexch_dupctx_fn *)
			fwd_keyexch_get_func(&ctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_DUPCTX,
					&ctx->pctx->dbg);
	if (default_dupctx_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	new_ctx = ps_op_dupctx(ctx);
	if (new_ctx == NULL) {
		ps_opctx_debug(ctx, "ERROR: ps_op_dupctx failed");
		return NULL;
	}

	new_ctx->fwd_op_ctx = default_dupctx_fn(ctx->fwd_op_ctx);
	if (new_ctx->fwd_op_ctx == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_dupctx_fn failed");
		ps_op_freectx(new_ctx);
		return NULL;
	}

	ps_opctx_debug(ctx, "new_ctx: %p", new_ctx);
	return new_ctx;
}

// keep
static int ps_keyexch_ec_init(void *vctx, void *vkey,
				   const OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_init_fn *default_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	default_init_fn = (OSSL_FUNC_keyexch_init_fn *)
			fwd_keyexch_get_func(&ctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_INIT,
					&ctx->pctx->dbg);
	if (default_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_DERIVE)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!default_init_fn(ctx->fwd_op_ctx, key->fwd_key, params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_init_fn failed");
		return 0;
	}

	return 1;
}

// keep
static int ps_keyexch_ec_set_peer(void *vctx, void *vpeerkey)

{
	OSSL_FUNC_keyexch_set_peer_fn *default_set_peer_fn;
	struct obj *peerkey = vpeerkey;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL || peerkey == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p peerkey: %p", ctx, ctx->key,
			peerkey);

	default_set_peer_fn = (OSSL_FUNC_keyexch_set_peer_fn *)
			fwd_keyexch_get_func(&ctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_SET_PEER,
					&ctx->pctx->dbg);
	if (default_set_peer_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default set_peer_fn");
		return 0;
	}

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_DERIVE) {
		put_error_op_ctx(ctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "derive operation not initialized");
		return 0;
	}

	if (!default_set_peer_fn(ctx->fwd_op_ctx, peerkey->fwd_key)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_set_peer_fn failed");
		return 0;
	}

	return 1;
}

// keep
static int ps_keyexch_ec_derive(void *vctx,
				     unsigned char *secret, size_t *secretlen,
				     size_t outlen)
{
	OSSL_FUNC_keyexch_derive_fn *default_derive_fn;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL || secretlen == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p outlen: %lu", ctx, ctx->key,
			outlen);

	default_derive_fn = (OSSL_FUNC_keyexch_derive_fn *)
			fwd_keyexch_get_func(&ctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_DERIVE,
					&ctx->pctx->dbg);
	if (default_derive_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default derive_fn");
		return 0;
	}

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_DERIVE) {
		put_error_op_ctx(ctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "derive operation not initialized");
		return 0;
	}

	if (!default_derive_fn(ctx->fwd_op_ctx, secret, secretlen,
			       outlen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_derive_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "secretlen: %lu", *secretlen);

	return 1;
}

// keep
static int ps_keyexch_ec_set_ctx_params(void *vctx,
					     const OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_set_ctx_params_fn *default_set_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	default_set_params_fn = (OSSL_FUNC_keyexch_set_ctx_params_fn *)
			fwd_keyexch_get_func(&ctx->pctx->fwd,
				OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
				&ctx->pctx->dbg);

	/* default_set_params_fn is optional */
	if (default_set_params_fn != NULL) {
		if (!default_set_params_fn(ctx->fwd_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_set_params_fn failed");
			return 0;
		}
	}

	return 1;

}

// keep
static const OSSL_PARAM *ps_keyexch_ec_settable_ctx_params(void *vctx,
								void *vprovctx)
{
	OSSL_FUNC_keyexch_settable_ctx_params_fn
						*default_settable_params_fn;
	struct provider_ctx *pctx = vprovctx;
	const OSSL_PARAM *params = NULL, *p;
	struct ps_op_ctx *opctx = vctx;

	if (opctx == NULL || pctx == NULL)
		return NULL;

	default_settable_params_fn =
		(OSSL_FUNC_keyexch_settable_ctx_params_fn *)
			fwd_keyexch_get_func(&pctx->fwd,
				OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* default_settable_params_fn is optional */
	if (default_settable_params_fn != NULL)
		params = default_settable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

// keep
static int ps_keyexch_ec_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_get_ctx_params_fn *default_get_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	default_get_params_fn = (OSSL_FUNC_keyexch_get_ctx_params_fn *)
			fwd_keyexch_get_func(&ctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
					&ctx->pctx->dbg);

	/* default_get_params_fn is optional */
	if (default_get_params_fn != NULL) {
		if (!default_get_params_fn(ctx->fwd_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_get_params_fn failed");
			return 0;
		}
	}

	return 1;
}

// keep
static const OSSL_PARAM *ps_keyexch_ec_gettable_ctx_params(void *vctx,
								void *vprovctx)
{
	OSSL_FUNC_keyexch_gettable_ctx_params_fn
						*fwd_gettable_params_fn;
	struct provider_ctx *pctx = vprovctx;
	const OSSL_PARAM *params = NULL, *p;
	struct ps_op_ctx *opctx = vctx;

	if (opctx == NULL || pctx == NULL)
		return NULL;

	fwd_gettable_params_fn =
		(OSSL_FUNC_keyexch_gettable_ctx_params_fn *)
			fwd_keyexch_get_func(&pctx->fwd,
				OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* default_settable_params_fn is optional */
	if (fwd_gettable_params_fn != NULL)
		params = fwd_gettable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}


static const OSSL_DISPATCH ps_ec_keyexch_functions[] = {
	/* Context management */
	{ OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))ps_keyexch_ec_newctx },
	{ OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))ps_op_freectx },
	{ OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))ps_keyexch_ec_dupctx },

	/* Shared secret derivation */
	{ OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ps_keyexch_ec_init },
	{ OSSL_FUNC_KEYEXCH_SET_PEER,
		(void (*)(void))ps_keyexch_ec_set_peer },
	{ OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))ps_keyexch_ec_derive },

	/* Key Exchange parameters */
	{ OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
		(void (*)(void))ps_keyexch_ec_set_ctx_params },
	{ OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
		(void (*)(void))ps_keyexch_ec_settable_ctx_params },
	{ OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
			(void (*)(void))ps_keyexch_ec_get_ctx_params },
	{ OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
		(void (*)(void))ps_keyexch_ec_gettable_ctx_params },

	{ 0, NULL }
};

/*
 * Although ECDH key derivation is not supported for secure keys (would result
 * in a secure symmetric key, which OpenSSL can't handle), the provider still
 * must implement the ECDH key exchange functions and proxy them all to the
 * default provider. OpenSSL common code requires that the key management
 * provider and the key exchange provider for a derive operation is the same.
 * So for clear EC keys created with this provider, we do support the ECDH
 * operation by forwarding it to the configured provider.
 */
const OSSL_ALGORITHM ps_keyexch[] = {
	{ "ECDH", "provider="PS_PROV_NAME, ps_ec_keyexch_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};
