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
#include "pkcs11.h"
#include "keymgmt.h"

#define DISPATCH_ASYMCIPHER(tname, name) \
  DECL_DISPATCH_FUNC(asym_cipher, tname, name)
DISPATCH_ASYMCIPHER(newctx, ps_asym_rsa_newctx);
DISPATCH_ASYMCIPHER(dupctx, ps_asym_op_dupctx);
DISPATCH_ASYMCIPHER(get_ctx_params, ps_asym_op_get_ctx_params);
DISPATCH_ASYMCIPHER(set_ctx_params, ps_asym_op_set_ctx_params);
DISPATCH_ASYMCIPHER(encrypt_init, ps_asym_op_encrypt_init);
DISPATCH_ASYMCIPHER(encrypt, ps_asym_op_encrypt);
DISPATCH_ASYMCIPHER(decrypt_init, ps_asym_op_decrypt_init);
DISPATCH_ASYMCIPHER(decrypt, ps_asym_rsa_decrypt);
DISPATCH_ASYMCIPHER(gettable_ctx_params, ps_asym_rsa_gettable_ctx_params);
DISPATCH_ASYMCIPHER(settable_ctx_params, ps_asym_rsa_settable_ctx_params);

static int ps_asym_op_newctx_fwd(struct op_ctx *opctx,
					    int pkey_type)
{
	OSSL_FUNC_asym_cipher_freectx_fn *fwd_freectx_fn;
	OSSL_FUNC_asym_cipher_newctx_fn *fwd_newctx_fn;
	struct provider_ctx *pctx = opctx->pctx;

	fwd_newctx_fn = (OSSL_FUNC_asym_cipher_newctx_fn *)
		fwd_asym_get_func(&pctx->fwd, pkey_type,
				  OSSL_FUNC_ASYM_CIPHER_NEWCTX, &pctx->dbg);
	if (!fwd_newctx_fn) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default newctx_fn");
		return OSSL_RV_ERR;
	}

	fwd_freectx_fn = (OSSL_FUNC_asym_cipher_freectx_fn *)
		fwd_asym_get_func(&pctx->fwd, pkey_type,
				  OSSL_FUNC_ASYM_CIPHER_FREECTX,
				  &pctx->dbg);
	if (!fwd_freectx_fn) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default freectx_fn");
		return OSSL_RV_ERR;
	}

	opctx->fwd_op_ctx = fwd_newctx_fn(pctx->fwd.ctx);
	if (!opctx->fwd_op_ctx) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_newctx_fn failed");
		return OSSL_RV_ERR;
	}
	opctx->fwd_op_ctx_free = fwd_freectx_fn;

	return OSSL_RV_OK;
}

static struct op_ctx *ps_asym_op_newctx(struct provider_ctx *pctx,
					int pkey_type)
{
	struct op_ctx *opctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	opctx = op_ctx_new(pctx, NULL, pkey_type);
	if (!opctx) {
		ps_dbg_error(&pctx->dbg, "ERROR: ps_op_newctx failed");
		return NULL;
	}

	if (ps_asym_op_newctx_fwd(opctx, pkey_type) != OSSL_RV_OK) {
		op_ctx_free(opctx);
		return NULL;
	}

	ps_dbg_debug(&pctx->dbg, "opctx: %p", opctx);
	return opctx;
}

static void *ps_asym_op_dupctx(void *vopctx)
{
	OSSL_FUNC_asym_cipher_dupctx_fn *fwd_dupctx_fn;
	struct op_ctx *opctx = vopctx;
	struct op_ctx *opctx_new;

	if (!opctx)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	fwd_dupctx_fn = (OSSL_FUNC_asym_cipher_dupctx_fn *)
		fwd_asym_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_ASYM_CIPHER_DUPCTX,
				  &opctx->pctx->dbg);

	if (!fwd_dupctx_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	opctx_new = op_ctx_dup(opctx);
	if (!opctx_new) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_dup failed");
		return NULL;
	}

	opctx_new->fwd_op_ctx = fwd_dupctx_fn(opctx->fwd_op_ctx);
	if (!opctx_new->fwd_op_ctx) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_dupctx_fn failed");
		op_ctx_free(opctx_new);
		return NULL;
	}
	opctx_new->fwd_op_ctx_free = opctx->fwd_op_ctx_free;

	ps_opctx_debug(opctx, "opctx_new: %p", opctx_new);
	return opctx_new;
}

static int ps_asym_op_get_ctx_params(void *vopctx, OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_get_ctx_params_fn *fwd_get_params_fn;
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_get_params_fn = (OSSL_FUNC_asym_cipher_get_ctx_params_fn *)
		fwd_asym_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
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

static int ps_asym_op_set_ctx_params(void *vopctx, const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_set_ctx_params_fn *fwd_set_params_fn;
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_set_params_fn = (OSSL_FUNC_asym_cipher_set_ctx_params_fn *)
		fwd_asym_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
				  &opctx->pctx->dbg);

	/* fwd_set_params_fn is optional */
	if ((fwd_set_params_fn) &&
	    (fwd_set_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK)) {
		put_error_op_ctx(opctx,
				 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_set_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int asym_mechanism_prepare(struct op_ctx *opctx, CK_MECHANISM_PTR mech,
				  CK_RSA_PKCS_OAEP_PARAMS_PTR oaep_params)
{
	char digest[32], mgf[32];
	int padmode;

	OSSL_PARAM s_params[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
				       &digest, sizeof(digest)),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
				       &mgf, sizeof(mgf)),
		OSSL_PARAM_END
	};
	OSSL_PARAM i_params[] = {
		OSSL_PARAM_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &padmode),
		OSSL_PARAM_END
	};
	OSSL_PARAM p_params[] = {
		OSSL_PARAM_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
				     &oaep_params->pSourceData,
				     sizeof(oaep_params->pSourceData)),
		OSSL_PARAM_END
	};

	if (ps_asym_op_get_ctx_params(opctx, s_params) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: ps_asym_op_get_ctx_params(string) failed");
		return OSSL_RV_ERR;
	}

	if (ps_asym_op_get_ctx_params(opctx, i_params) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: ps_asym_op_get_ctx_params(int) failed");
		return OSSL_RV_ERR;
	}

	if (ps_asym_op_get_ctx_params(opctx, p_params) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: ps_asym_op_get_ctx_params(ptr) failed");
		return OSSL_RV_ERR;
	}

	if (mechtype_by_id(padmode, &mech->mechanism) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: mechtype_by_id() failed");
		return OSSL_RV_ERR;
	}

	switch(mech->mechanism) {
	case CKM_RSA_PKCS_OAEP:
		if (!OSSL_PARAM_modified(&s_params[0]) ||
		    !OSSL_PARAM_modified(&s_params[1])) {
			ps_opctx_debug(opctx, "ERROR: oaep parameters missing");
			return OSSL_RV_ERR;
		}

		if (mechtype_by_name(digest, &oaep_params->hashAlg) != OSSL_RV_OK) {
			ps_opctx_debug(opctx,
				       "ERROR: digest mechtype_by_name failed");
			return OSSL_RV_ERR;
		}

		if (mgftype_by_name(mgf, &oaep_params->mgf) != OSSL_RV_OK) {
			ps_opctx_debug(opctx,
				       "ERROR: mgf mechtype_by_name() failed");
			return OSSL_RV_ERR;
		}

		if (OSSL_PARAM_modified(&p_params[0])) {
			oaep_params->source = CKZ_DATA_SPECIFIED;
			oaep_params->ulSourceDataLen = p_params[0].return_size;
		} else {
			oaep_params->source = 0;
			oaep_params->pSourceData = NULL;
			oaep_params->ulSourceDataLen = 0;
		}

		mech->pParameter = oaep_params;
		mech->ulParameterLen = sizeof(*oaep_params);
		break;
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
		/* no mechanism parameter */
		mech->pParameter = NULL;
		mech->ulParameterLen = 0;
		break;
	default:
		ps_opctx_debug(opctx, "ERROR: mechanism type %lu not supported");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_asym_op_gettable_ctx_params(struct op_ctx *opctx,
							struct provider_ctx *pctx,
							int pkey_type)
{
	OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *fwd_gettable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	ps_pctx_debug(pctx, "pctx: %p, opctx: %p, pkey_type: %d",
		      pctx, opctx, pkey_type);

	fwd_gettable_params_fn =
		(OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *)
		fwd_asym_get_func(&pctx->fwd, pkey_type,
				  OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
				  &pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (fwd_gettable_params_fn)
		params = fwd_gettable_params_fn(opctx->fwd_op_ctx,
						pctx->fwd.ctx);

	for (p = params; p && p->key; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *ps_asym_op_settable_ctx_params(
				struct op_ctx *opctx,
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_asym_cipher_settable_ctx_params_fn *fwd_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	ps_pctx_debug(pctx, "pctx: %p, opctx: %p, pkey_type: %d",
		      pctx, opctx, pkey_type);

	fwd_settable_params_fn =
		(OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)
		fwd_asym_get_func(&pctx->fwd, pkey_type,
				  OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
				  &pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (fwd_settable_params_fn)
		params = fwd_settable_params_fn(opctx->fwd_op_ctx,
						pctx->fwd.ctx);

	for (p = params; p && p->key; p++)
		ps_pctx_debug(pctx, "param: %s", p->key);

	return params;
}

static int ps_asym_op_encrypt_init_fwd(struct op_ctx *ctx,
				       struct obj *key,
				       const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_encrypt_init_fn *fwd_encrypt_init_fn;

	fwd_encrypt_init_fn = (OSSL_FUNC_asym_cipher_encrypt_init_fn *)
				fwd_asym_get_func(&ctx->pctx->fwd,
					ctx->type,
					OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
					&ctx->pctx->dbg);
	if (!fwd_encrypt_init_fn) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_encrypt_init_fn(ctx->fwd_op_ctx, key->fwd_key,
				params) != OSSL_RV_OK) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_encrypt_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_asym_op_encrypt_init(void *vctx, void *vkey,
				   const OSSL_PARAM params[])
{
	struct op_ctx *ctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!ctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	if (!op_ctx_init(ctx, key, EVP_PKEY_OP_ENCRYPT)) {
		ps_opctx_debug(ctx, "ERROR: op_ctx_init failed");
		return OSSL_RV_ERR;
	}

	return ps_asym_op_encrypt_init_fwd(ctx, key, params);
}

static int ps_asym_op_decrypt_init_fwd(struct op_ctx *opctx, struct obj *key,
				       const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_decrypt_init_fn *fwd_decrypt_init_fn;

	fwd_decrypt_init_fn = (OSSL_FUNC_asym_cipher_decrypt_init_fn *)
				fwd_asym_get_func(&opctx->pctx->fwd, opctx->type,
					OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
					&opctx->pctx->dbg);
	if (!fwd_decrypt_init_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_decrypt_init_fn(opctx->fwd_op_ctx, key->fwd_key,
				params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_decrypt_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_asym_op_decrypt_init(void *vctx, void *vkey,
				   const OSSL_PARAM params[])
{
	struct op_ctx *opctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!opctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p", opctx, key);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (op_ctx_init(opctx, key, EVP_PKEY_OP_DECRYPT) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_init() failed");
		return OSSL_RV_ERR;
	}

	if (!key->use_pkcs11)
		return ps_asym_op_decrypt_init_fwd(opctx, key, params);

	return OSSL_RV_OK;
}

static int ps_asym_op_encrypt_fwd(struct op_ctx *opctx,
				  unsigned char *out, size_t *outlen,
				  size_t outsize, const unsigned char *in,
				  size_t inlen)
{
	OSSL_FUNC_asym_cipher_encrypt_fn *fwd_encrypt_fn;

	fwd_encrypt_fn = (OSSL_FUNC_asym_cipher_encrypt_fn *)
			fwd_asym_get_func(&opctx->pctx->fwd,
				opctx->type, OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
				&opctx->pctx->dbg);
	if (!fwd_encrypt_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_encrypt_fn(opctx->fwd_op_ctx, out, outlen, outsize,
			   in, inlen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_encrypt_fn failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "outlen: %lu", *outlen);

	return OSSL_RV_OK;
}

static int ps_asym_op_encrypt(void *vctx,
				   unsigned char *out, size_t *outlen,
				   size_t outsize, const unsigned char *in,
				   size_t inlen)
{
	struct op_ctx *opctx = vctx;

	if (!opctx || !in || !outlen)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p inlen: %lu outsize: %lu",
			opctx, opctx->key, inlen, outsize);

	return  ps_asym_op_encrypt_fwd(opctx, out, outlen, outsize,
				       in, inlen);
}

static int ps_asym_op_decrypt_fwd(struct op_ctx *opctx,
				  unsigned char *out, size_t *outlen,
				  size_t outsize, const unsigned char *in,
				  size_t inlen)
{
	OSSL_FUNC_asym_cipher_decrypt_fn *fwd_decrypt_fn;

	fwd_decrypt_fn = (OSSL_FUNC_asym_cipher_decrypt_fn *)
			fwd_asym_get_func(&opctx->pctx->fwd,
				opctx->type, OSSL_FUNC_ASYM_CIPHER_DECRYPT,
				&opctx->pctx->dbg);
	if (!fwd_decrypt_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_decrypt_fn(opctx->fwd_op_ctx, out, outlen, outsize,
			   in, inlen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_decrypt_fn failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "outlen: %lu", *outlen);
	return OSSL_RV_OK;
}

static int ps_asym_op_decrypt(struct op_ctx *opctx,
			      unsigned char *out, size_t *outlen,
			      size_t outsize, const unsigned char *in,
			      size_t inlen)
{
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_MECHANISM mech;
	size_t len;
	int s;

	ps_opctx_debug(opctx, "opctx: %p key: %p inlen: %lu outsize: %lu",
			opctx, opctx->key, inlen, outsize);

	if (!opctx->key->use_pkcs11)
		return ps_asym_op_decrypt_fwd(opctx, out, outlen, outsize,
					      in, inlen);

	if (asym_mechanism_prepare(opctx, &mech, &oaep_params) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: asym_mechanism_prepare failed");
		return OSSL_RV_ERR;
	}

	if (op_ctx_object_ensure(opctx) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_object_ensure() failed");
		return OSSL_RV_ERR;
	}

	s = keymgmt_get_size(opctx->key);
	if (s < 0) {
		ps_opctx_debug(opctx, "ERROR: keymgmt_get_size failed");
		return OSSL_RV_ERR;
	}

	len = s;

	if (pkcs11_decrypt_init(opctx->pctx->pkcs11, opctx->hsession,
				&mech, opctx->hobject,
				&opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_decrypt_init() failed");
		return OSSL_RV_ERR;
	}

	if (pkcs11_decrypt(opctx->pctx->pkcs11, opctx->hsession,
			   in, inlen, out, &len,
			   &opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_decrypt() failed");
		return OSSL_RV_ERR;
	}
	*outlen = len;

	ps_opctx_debug(opctx, "outlen: %lu", *outlen);
	return OSSL_RV_OK;
}

static void *ps_asym_rsa_newctx(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_asym_op_newctx(pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_asym_rsa_gettable_ctx_params(void *vctx,
							 void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct op_ctx *opctx = vctx;

	if (!pctx || !opctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p, opctx: %p", pctx, opctx);
	return ps_asym_op_gettable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_asym_rsa_settable_ctx_params(void *vctx,
							 void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct op_ctx *opctx = vctx;

	if (!pctx || !opctx)
		return NULL;

	ps_pctx_debug(pctx, "pctx: %p, opctx: %p", pctx, opctx);
	return ps_asym_op_settable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static int ps_asym_rsa_decrypt(void *vopctx,
			       unsigned char *out, size_t *outlen,
			       size_t outsize, const unsigned char *in,
			       size_t inlen)
{
	struct op_ctx *opctx = vopctx;

	if (!opctx || !in || !outlen)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p in: %p, inlen: %lu out: %p, outsize: %lu",
		       opctx, opctx->key, in, inlen, out, outsize);

	if (!opctx->key || opctx->operation != EVP_PKEY_OP_DECRYPT) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "decrypt operation not initialized");
		return OSSL_RV_ERR;
	}

	return ps_asym_op_decrypt(opctx, out, outlen, outsize,
				  in, inlen);
}

static const OSSL_DISPATCH ps_rsa_asym_cipher_functions[] = {
	/* RSA context constructor, descructor */
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))ps_asym_rsa_newctx },
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))op_ctx_free },
	{ OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))ps_asym_op_dupctx },
	/* RSA context set/get parameters */
	{ OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))ps_asym_op_get_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ps_asym_rsa_gettable_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))ps_asym_op_set_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ps_asym_rsa_settable_ctx_params },
	/* RSA encrypt */
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))ps_asym_op_encrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))ps_asym_op_encrypt },
	/* RSA decrypt */
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))ps_asym_op_decrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))ps_asym_rsa_decrypt },
	{ 0, NULL }
};

const OSSL_ALGORITHM ps_asym_cipher[] = {
	{ "RSA:rsaEncryption", "provider="PS_PROV_NAME,
				ps_rsa_asym_cipher_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};
