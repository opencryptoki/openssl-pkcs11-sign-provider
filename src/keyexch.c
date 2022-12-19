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

static int kex_newctx_fwd(struct op_ctx *opctx)
{
	OSSL_FUNC_keyexch_freectx_fn *fwd_freectx_fn;
	OSSL_FUNC_keyexch_newctx_fn *fwd_newctx_fn;

	fwd_newctx_fn = (OSSL_FUNC_keyexch_newctx_fn *)
		fwd_keyexch_get_func(&opctx->pctx->fwd,
				     OSSL_FUNC_KEYEXCH_NEWCTX,
				     &opctx->pctx->dbg);
	if (!fwd_newctx_fn) {
		put_error_pctx(opctx->pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no fwd newctx_fn");
		return OSSL_RV_ERR;
	}

	fwd_freectx_fn = (OSSL_FUNC_keyexch_freectx_fn *)
		fwd_keyexch_get_func(&opctx->pctx->fwd,
				     OSSL_FUNC_KEYEXCH_FREECTX,
				     &opctx->pctx->dbg);
	if (!fwd_freectx_fn) {
		put_error_pctx(opctx->pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no fwd freectx_fn");
		return OSSL_RV_ERR;
	}

	opctx->fwd_op_ctx = fwd_newctx_fn(opctx->pctx->fwd.ctx);
	if (!opctx->fwd_op_ctx) {
		put_error_pctx(opctx->pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_newctx_fn failed");
		return OSSL_RV_ERR;
	}
	opctx->fwd_op_ctx_free = fwd_freectx_fn;

	return OSSL_RV_OK;
}

#define DISP_KEX_FN(tname, name) DECL_DISPATCH_FUNC(keyexch, tname, name)
DISP_KEX_FN(newctx, ps_kex_ec_newctx);
DISP_KEX_FN(dupctx, ps_kex_ec_dupctx);
DISP_KEX_FN(init, ps_kex_ec_init);
DISP_KEX_FN(set_peer, ps_kex_ec_set_peer);
DISP_KEX_FN(derive, ps_kex_ec_derive);
DISP_KEX_FN(set_ctx_params, ps_kex_ec_set_ctx_params);
DISP_KEX_FN(get_ctx_params, ps_kex_ec_get_ctx_params);
DISP_KEX_FN(settable_ctx_params, ps_kex_ec_settable_ctx_params);
DISP_KEX_FN(gettable_ctx_params, ps_kex_ec_gettable_ctx_params);

static void *ps_kex_ec_newctx(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;
	struct op_ctx *opctx;

	if (!pctx)
		return NULL;

	ps_pctx_debug(pctx, "pctx: %p", pctx);

	opctx = op_ctx_new(pctx, NULL, EVP_PKEY_EC);
	if (!opctx) {
		ps_pctx_debug(pctx, "ERROR: op_ctx_new() failed");
		return NULL;
	}

	if (kex_newctx_fwd(opctx) != OSSL_RV_OK) {
		ps_pctx_debug(pctx, "ERROR: kex_newctx_fwd() failed");
		op_ctx_free(opctx);
		return NULL;
	}

	ps_pctx_debug(pctx, "opctx: %p", opctx);
	return opctx;
}

static void *ps_kex_ec_dupctx(void *vctx)
{
	OSSL_FUNC_keyexch_dupctx_fn *fwd_dupctx_fn;
	struct op_ctx *opctx = vctx;
	struct op_ctx *opctx_new;

	if (!opctx)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	fwd_dupctx_fn = (OSSL_FUNC_keyexch_dupctx_fn *)
			fwd_keyexch_get_func(&opctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_DUPCTX,
					&opctx->pctx->dbg);
	if (!fwd_dupctx_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd dupctx_fn");
		return NULL;
	}

	opctx_new = op_ctx_dup(opctx);
	if (!opctx_new) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_dup() failed");
		return NULL;
	}

	opctx_new->fwd_op_ctx = fwd_dupctx_fn(opctx->fwd_op_ctx);
	if (!opctx_new->fwd_op_ctx) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_dupctx_fn failed");
		op_ctx_free(opctx_new);
		return NULL;
	}

	ps_opctx_debug(opctx, "opctx_new: %p", opctx_new);
	return opctx_new;
}

static int ps_kex_ec_init(void *vctx, void *vkey,
			  const OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_init_fn *fwd_init_fn;
	struct op_ctx *opctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!opctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p", opctx, key);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (op_ctx_init(opctx, key, EVP_PKEY_OP_DERIVE) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_init() failed");
		return OSSL_RV_ERR;
	}

	if (key->use_pkcs11) {
		ps_opctx_debug(opctx, "opctx: %p, not supported for key %p (pkcs11)",
			       opctx, key);
		return OSSL_RV_ERR;
	}

	fwd_init_fn = (OSSL_FUNC_keyexch_init_fn *)
			fwd_keyexch_get_func(&opctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_INIT,
					&opctx->pctx->dbg);
	if (!fwd_init_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_init_fn(opctx->fwd_op_ctx, key->fwd_key, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_kex_ec_set_peer(void *vctx, void *vpeerkey)

{
	OSSL_FUNC_keyexch_set_peer_fn *fwd_set_peer_fn;
	struct obj *peerkey = vpeerkey;
	struct op_ctx *opctx = vctx;

	if (!opctx || !peerkey)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p peerkey: %p", opctx, opctx->key,
			peerkey);

	if (!opctx->key || (opctx->operation != EVP_PKEY_OP_DERIVE)) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "derive operation not initialized");
		return OSSL_RV_ERR;
	}

	fwd_set_peer_fn = (OSSL_FUNC_keyexch_set_peer_fn *)
			fwd_keyexch_get_func(&opctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_SET_PEER,
					&opctx->pctx->dbg);
	if (!fwd_set_peer_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd set_peer_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_set_peer_fn(opctx->fwd_op_ctx, peerkey->fwd_key) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_set_peer_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_kex_ec_derive(void *vctx,
			    unsigned char *secret, size_t *secretlen,
			    size_t outlen)
{
	OSSL_FUNC_keyexch_derive_fn *fwd_derive_fn;
	struct op_ctx *opctx = vctx;

	if (!opctx || !secretlen)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p outlen: %lu", opctx, opctx->key,
			outlen);

	fwd_derive_fn = (OSSL_FUNC_keyexch_derive_fn *)
			fwd_keyexch_get_func(&opctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_DERIVE,
					&opctx->pctx->dbg);
	if (!fwd_derive_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd derive_fn");
		return OSSL_RV_ERR;
	}

	if (!opctx->key || (opctx->operation != EVP_PKEY_OP_DERIVE)) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "derive operation not initialized");
		return OSSL_RV_ERR;
	}

	if (fwd_derive_fn(opctx->fwd_op_ctx,
			  secret, secretlen, outlen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_derive_fn failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "secretlen: %lu", *secretlen);

	return OSSL_RV_OK;
}

static int ps_kex_ec_set_ctx_params(void *vctx,
				    const OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_set_ctx_params_fn *fwd_set_params_fn;
	struct op_ctx *opctx = vctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_set_params_fn = (OSSL_FUNC_keyexch_set_ctx_params_fn *)
		fwd_keyexch_get_func(&opctx->pctx->fwd,
				     OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
				     &opctx->pctx->dbg);

	/* fwd_set_params_fn is optional */
	if ((fwd_set_params_fn) &&
	    (fwd_set_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK)) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_set_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;

}

static const OSSL_PARAM *ps_kex_ec_settable_ctx_params(void *vctx,
								void *vprovctx)
{
	OSSL_FUNC_keyexch_settable_ctx_params_fn
						*fwd_settable_params_fn;
	struct provider_ctx *pctx = vprovctx;
	const OSSL_PARAM *params = NULL, *p;
	struct op_ctx *opctx = vctx;

	if (!opctx || !pctx)
		return NULL;

	fwd_settable_params_fn = (OSSL_FUNC_keyexch_settable_ctx_params_fn *)
		fwd_keyexch_get_func(&pctx->fwd,
				     OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
				     &pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (fwd_settable_params_fn)
		params = fwd_settable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p && p->key; p++)
		ps_pctx_debug(pctx, "param: %s", p->key);

	return params;
}

static int ps_kex_ec_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_keyexch_get_ctx_params_fn *fwd_get_params_fn;
	struct op_ctx *opctx = vctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_get_params_fn = (OSSL_FUNC_keyexch_get_ctx_params_fn *)
			fwd_keyexch_get_func(&opctx->pctx->fwd,
					OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
					&opctx->pctx->dbg);

	/* fwd_get_params_fn is optional */
	if ((fwd_get_params_fn) &&
	    (fwd_get_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK)) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_get_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_kex_ec_gettable_ctx_params(void *vctx,
						       void *vprovctx)
{
	OSSL_FUNC_keyexch_gettable_ctx_params_fn *fwd_gettable_params_fn;
	struct provider_ctx *pctx = vprovctx;
	const OSSL_PARAM *params = NULL, *p;
	struct op_ctx *opctx = vctx;

	if (!opctx || !pctx)
		return NULL;

	fwd_gettable_params_fn = (OSSL_FUNC_keyexch_gettable_ctx_params_fn *)
		fwd_keyexch_get_func(&pctx->fwd,
				     OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
				     &pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (fwd_gettable_params_fn)
		params = fwd_gettable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p && p->key; p++)
		ps_pctx_debug(pctx, "param: %s", p->key);

	return params;
}


static const OSSL_DISPATCH ps_kex_ec_functions[] = {
	/* Context management */
	{ OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))ps_kex_ec_newctx },
	{ OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))op_ctx_free },
	{ OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))ps_kex_ec_dupctx },

	/* Shared secret derivation */
	{ OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ps_kex_ec_init },
	{ OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))ps_kex_ec_set_peer },
	{ OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))ps_kex_ec_derive },

	/* Key Exchange parameters */
	{ OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))ps_kex_ec_set_ctx_params },
	{ OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))ps_kex_ec_settable_ctx_params },
	{ OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))ps_kex_ec_get_ctx_params },
	{ OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))ps_kex_ec_gettable_ctx_params },

	{ 0, NULL }
};

const OSSL_ALGORITHM ps_keyexch[] = {
	{ "ECDH", "provider="PS_PROV_NAME, ps_kex_ec_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};
