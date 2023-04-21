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

static int asym_set_mech_type(CK_MECHANISM_PTR mech, const OSSL_PARAM *p)
{
	int pad_mode;

	switch (p->data_type) {
	case OSSL_PARAM_INTEGER:
		if (OSSL_PARAM_get_int(p, &pad_mode) != OSSL_RV_OK)
			return OSSL_RV_ERR;

		switch (pad_mode) {
		case RSA_NO_PADDING:
			mech->mechanism = CKM_RSA_X_509;
			break;
		case RSA_PKCS1_PADDING:
			mech->mechanism = CKM_RSA_PKCS;
			break;
		case RSA_PKCS1_OAEP_PADDING:
			mech->mechanism = CKM_RSA_PKCS_OAEP;
			break;
		case RSA_X931_PADDING:
			mech->mechanism = CKM_RSA_X9_31;
			break;
		default:
			return OSSL_RV_ERR;
		}
		break;
	case OSSL_PARAM_UTF8_STRING:
		if (!p->data)
			return OSSL_RV_ERR;

		if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0)
			mech->mechanism = CKM_RSA_X_509;
		else if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
			mech->mechanism = CKM_RSA_PKCS;
		else if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0)
			mech->mechanism = CKM_RSA_PKCS_OAEP;
		else if (strcmp(p->data, OSSL_PKEY_RSA_PAD_MODE_X931) == 0)
			mech->mechanism = CKM_RSA_X9_31;
		else
			return OSSL_RV_ERR;
		break;
	default:
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

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

static struct op_ctx *ps_asym_op_newctx(struct provider_ctx *pctx,
					int pkey_type)
{
	OSSL_FUNC_asym_cipher_freectx_fn *fwd_freectx_fn;
	OSSL_FUNC_asym_cipher_newctx_fn *fwd_newctx_fn;
	struct op_ctx *opctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	fwd_newctx_fn = (OSSL_FUNC_asym_cipher_newctx_fn *)
		fwd_asym_get_func(&pctx->fwd, pkey_type,
				  OSSL_FUNC_ASYM_CIPHER_NEWCTX, &pctx->dbg);
	if (fwd_newctx_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default newctx_fn");
		return NULL;
	}

	fwd_freectx_fn = (OSSL_FUNC_asym_cipher_freectx_fn *)
		fwd_asym_get_func(&pctx->fwd, pkey_type,
				  OSSL_FUNC_ASYM_CIPHER_FREECTX,
				  &pctx->dbg);
	if (fwd_freectx_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default freectx_fn");
		return NULL;
	}

	opctx = op_ctx_new(pctx, NULL, pkey_type);
	if (opctx == NULL) {
		ps_dbg_error(&pctx->dbg, "ERROR: ps_op_newctx failed");
		return NULL;
	}

	opctx->fwd_op_ctx = fwd_newctx_fn(pctx->fwd.ctx);
	if (opctx->fwd_op_ctx == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_newctx_fn failed");
		op_ctx_free(opctx);
		return NULL;
	}
	opctx->fwd_op_ctx_free = fwd_freectx_fn;

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
			fwd_asym_get_func(&opctx->pctx->fwd,
				opctx->type, OSSL_FUNC_ASYM_CIPHER_DUPCTX,
				&opctx->pctx->dbg);
	if (fwd_dupctx_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	opctx_new = op_ctx_dup(opctx);
	if (opctx_new == NULL) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_dup failed");
		return NULL;
	}

	opctx_new->fwd_op_ctx = fwd_dupctx_fn(opctx->fwd_op_ctx);
	if (opctx_new->fwd_op_ctx == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_dupctx_fn failed");
		op_ctx_free(opctx_new);
		return NULL;
	}

	ps_opctx_debug(opctx, "opctx_new: %p", opctx_new);
	return opctx_new;
}

static int ps_asym_op_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_get_ctx_params_fn *fwd_get_params_fn;
	struct op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_get_params_fn = (OSSL_FUNC_asym_cipher_get_ctx_params_fn *)
			fwd_asym_get_func(&ctx->pctx->fwd,
				ctx->type,
				OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
				&ctx->pctx->dbg);

	/* fwd_get_params_fn is optional */
	if (fwd_get_params_fn != NULL) {
		if (!fwd_get_params_fn(ctx->fwd_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "fwd_get_params_fn failed");
			return OSSL_RV_ERR;
		}
	}

	return OSSL_RV_OK;
}

static int ps_asym_op_set_ctx_params_fwd(struct op_ctx *opctx,
					 const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_set_ctx_params_fn *fwd_set_params_fn;

	fwd_set_params_fn = (OSSL_FUNC_asym_cipher_set_ctx_params_fn *)
			fwd_asym_get_func(&opctx->pctx->fwd,
				opctx->type,
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

static int ps_asym_op_set_ctx_params(void *vopctx, const OSSL_PARAM params[])
{
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (opctx == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (!opctx->key->use_pkcs11)
		return ps_asym_op_set_ctx_params_fwd(opctx, params);

	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
	if ((p) && (asym_set_mech_type(&opctx->mech, p) != OSSL_RV_OK)) {
		ps_opctx_debug(opctx, "asym_set_mech_type() failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_asym_op_gettable_ctx_params(
				struct op_ctx *opctx,
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
						*fwd_gettable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (opctx == NULL || pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	fwd_gettable_params_fn =
		(OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *)
			fwd_asym_get_func(&pctx->fwd, pkey_type,
				OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (fwd_gettable_params_fn)
		params = fwd_gettable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM asym_params[] = {
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM *ps_asym_op_settable_ctx_params_fwd(
				struct op_ctx *opctx,
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_asym_cipher_settable_ctx_params_fn
						*fwd_settable_params_fn;

	fwd_settable_params_fn =
		(OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)
			fwd_asym_get_func(&pctx->fwd, pkey_type,
				OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (!fwd_settable_params_fn)
		return NULL;

	return fwd_settable_params_fn(opctx->fwd_op_ctx, pctx->fwd.ctx);
}

static const OSSL_PARAM *ps_asym_op_settable_ctx_params(
				struct op_ctx *opctx,
				struct provider_ctx *pctx, int pkey_type)
{
	const OSSL_PARAM *params = NULL, *p;

	if (opctx == NULL || pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	params = (opctx->key && opctx->key->use_pkcs11) ?
		asym_params :
		ps_asym_op_settable_ctx_params_fwd(opctx, pctx, pkey_type);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static EVP_MD *ps_asym_op_get_oaep_md(struct op_ctx *opctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	if (!ps_asym_op_get_ctx_params(opctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		ps_opctx_debug(opctx, "ps_asym_op_get_ctx_params failed");
		if (opctx->md != NULL) {
			ps_opctx_debug(opctx, "use digest from context: %s",
					EVP_MD_name(opctx->md));
			EVP_MD_up_ref(opctx->md);
			return opctx->md;
		}

		ps_opctx_debug(opctx, "use default");
		strcpy(mdname, PS_PROV_RSA_DEFAULT_MD);
		strcpy(mdprops, "");
	}
	md = EVP_MD_fetch(opctx->pctx->core.libctx,
			  mdname, mdprops[0] != '\0' ? mdprops : opctx->prop);
	if (md == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					opctx->prop != NULL ? opctx->prop : "");
		return NULL;
	}

	ps_opctx_debug(opctx, "md: %s", EVP_MD_name(md));
	return md;
}

static EVP_MD *ps_asym_op_get_mgf_md(struct op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		ps_opctx_debug(ctx, "ps_asym_op_get_ctx_params failed, "
				"using oaep digest");
		return ps_asym_op_get_oaep_md(ctx);
	}

	md = EVP_MD_fetch(ctx->pctx->core.libctx,
			  mdname, mdprops[0] != '\0' ? mdprops : ctx->prop);
	if (md == NULL) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 (mdprops[0]) ?
					mdprops :
					(ctx->prop) ? ctx->prop : "");
		return NULL;
	}

	ps_opctx_debug(ctx, "md: %s", EVP_MD_name(md));
	return md;
}

static int ps_asym_op_get_oaep_label(struct op_ctx *ctx,
					  unsigned char **label)
{
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
				label, 0),
		OSSL_PARAM_END
	};
	int oaep_label_len;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "ps_asym_op_get_ctx_params failed to "
				 "get OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL");
		return -1;
	}

	oaep_label_len = ctx_params[0].return_size;
	ps_opctx_debug(ctx, "oaep_label: %p oaep_label_len: %d", *label,
			oaep_label_len);

	return oaep_label_len;
}

static int ps_asym_op_get_padding(struct op_ctx *ctx)
{
	char padding[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PAD_MODE,
				&padding, sizeof(padding)),
		OSSL_PARAM_END
	};

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_asym_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "ps_asym_op_get_ctx_params failed to "
				 "get OSSL_PKEY_PARAM_PAD_MODE");
		return -1;
	}

	ps_opctx_debug(ctx, "padding: %s", padding);

	return ossl_parse_padding(padding);
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
	if (fwd_encrypt_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_init_fn");
		return OSSL_RV_ERR;
	}

	if (!fwd_encrypt_init_fn(ctx->fwd_op_ctx, key->fwd_key,
				     params)) {
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

	if (ctx == NULL || key == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	if (!op_ctx_init(ctx, key, EVP_PKEY_OP_ENCRYPT)) {
		ps_opctx_debug(ctx, "ERROR: op_ctx_init failed");
		return OSSL_RV_ERR;
	}

	if (!key->use_pkcs11)
		return ps_asym_op_encrypt_init_fwd(ctx, key, params);

	/* TODO pkcs11 implementation */
	return OSSL_RV_ERR;
}

static int ps_asym_op_decrypt_init_fwd(struct op_ctx *opctx, struct obj *key,
				       const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_decrypt_init_fn *fwd_decrypt_init_fn;

	fwd_decrypt_init_fn = (OSSL_FUNC_asym_cipher_decrypt_init_fn *)
				fwd_asym_get_func(&opctx->pctx->fwd, opctx->type,
					OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
					&opctx->pctx->dbg);
	if (fwd_decrypt_init_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_init_fn");
		return OSSL_RV_ERR;
	}

	if (!fwd_decrypt_init_fn(opctx->fwd_op_ctx, key->fwd_key,
				     params)) {
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
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (op_ctx_init(opctx, key, EVP_PKEY_OP_DECRYPT) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_init() failed");
		return OSSL_RV_ERR;
	}

	if (!key->use_pkcs11)
		return ps_asym_op_decrypt_init_fwd(opctx, key, params);

	if (op_ctx_object_ensure(opctx) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_object_ensure() failed");
		return OSSL_RV_ERR;
	}

	if (ps_asym_op_set_ctx_params(opctx, params) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: ps_asym_op_set_ctx_params() failed");
		return OSSL_RV_ERR;
	}

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
	if (fwd_encrypt_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_fn");
		return OSSL_RV_ERR;
	}

	if (!fwd_encrypt_fn(opctx->fwd_op_ctx, out, outlen, outsize,
				in, inlen)) {
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

	if (opctx == NULL || in == NULL || outlen == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p inlen: %lu outsize: %lu",
			opctx, opctx->key, inlen, outsize);

	if (!opctx->key->use_pkcs11)
		return  ps_asym_op_encrypt_fwd(opctx, out, outlen, outsize,
					       in, inlen);

	/* not supported */
	return OSSL_RV_ERR;
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
	if (fwd_decrypt_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_fn");
		return OSSL_RV_ERR;
	}

	if (!fwd_decrypt_fn(opctx->fwd_op_ctx, out, outlen, outsize,
				in, inlen)) {
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
	size_t len;

	if (!opctx || !in || !outlen)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p inlen: %lu outsize: %lu",
			opctx, opctx->key, inlen, outsize);

	if (!opctx->key->use_pkcs11)
		return ps_asym_op_decrypt_fwd(opctx, out, outlen, outsize,
					      in, inlen);

	if (pkcs11_decrypt_init(opctx->pctx->pkcs11, opctx->hsession,
				&opctx->mech, opctx->hobject,
				&opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_decrypt_init() failed");
		return OSSL_RV_ERR;
	}

	len = outsize;
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

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_asym_op_newctx(pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_asym_rsa_gettable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_asym_op_gettable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_asym_rsa_settable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
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

	if (opctx->key == NULL || opctx->operation != EVP_PKEY_OP_DECRYPT) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "decrypt operation not initialized");
		return OSSL_RV_ERR;
	}

	if (opctx->key->use_pkcs11)
		return ps_asym_op_decrypt(opctx, out, outlen, outsize,
					  in, inlen);

	/* TODO pkcs11 implementation */
	return OSSL_RV_ERR;
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
