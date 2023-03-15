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

typedef int (*ps_rsa_decrypt_t)(const unsigned char *key_blob,
				size_t key_blob_length,
				unsigned char *to, size_t *tolen,
				const unsigned char *from, size_t fromlen,
				int padding_type, void *private, bool debug);
typedef int (*ps_rsa_decrypt_oaep_t)(const unsigned char *key_blob,
				     size_t key_blob_length,
				     unsigned char *to, size_t *tolen,
				     const unsigned char *from, size_t fromlen,
				     int oaep_md_nid, int mgfmd_nid,
				     unsigned char *label, int label_len,
				     void *private, bool debug);

struct ps_funcs {
	ps_rsa_decrypt_t	rsa_decrypt;
	ps_rsa_decrypt_oaep_t	rsa_decrypt_oaep;
};

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

#define DISPATCH_ASYMCIPHER(tname, name) DECL_DISPATCH_FUNC(asym_cipher, tname, name)
DISPATCH_ASYMCIPHER(newctx, ps_asym_newctx);
DISPATCH_ASYMCIPHER(dupctx, ps_asym_dupctx);
DISPATCH_ASYMCIPHER(get_ctx_params, ps_asym_get_ctx_params);
DISPATCH_ASYMCIPHER(set_ctx_params, ps_asym_set_ctx_params);
DISPATCH_ASYMCIPHER(encrypt_init, ps_asym_encrypt_init);
DISPATCH_ASYMCIPHER(encrypt, ps_asym_encrypt);
DISPATCH_ASYMCIPHER(decrypt_init, ps_asym_decrypt_init);
DISPATCH_ASYMCIPHER(decrypt, ps_asym_decrypt);
DISPATCH_ASYMCIPHER(gettable_ctx_params, ps_asym_gettable_ctx_params);
DISPATCH_ASYMCIPHER(settable_ctx_params, ps_asym_settable_ctx_params);
DISPATCH_ASYMCIPHER(freectx, ps_op_freectx);

static struct ps_op_ctx *ps_asym_op_newctx(
					struct provider_ctx *pctx,
					int pkey_type)
{
	OSSL_FUNC_asym_cipher_freectx_fn *fwd_freectx_fn;
	OSSL_FUNC_asym_cipher_newctx_fn *fwd_newctx_fn;
	struct ps_op_ctx *opctx;

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

	opctx = ps_op_newctx(pctx, NULL, pkey_type);
	if (opctx == NULL) {
		ps_dbg_error(&pctx->dbg, "ERROR: ps_op_newctx failed");
		return NULL;
	}

	opctx->fwd_op_ctx = fwd_newctx_fn(pctx->fwd.ctx);
	if (opctx->fwd_op_ctx == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_newctx_fn failed");
		ps_op_freectx(opctx);
		return NULL;
	}
	opctx->fwd_op_ctx_free = fwd_freectx_fn;

	ps_dbg_debug(&pctx->dbg, "opctx: %p", opctx);
	return opctx;
}

static void *ps_asym_op_dupctx(void *vctx)
{
	OSSL_FUNC_asym_cipher_dupctx_fn *fwd_dupctx_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	fwd_dupctx_fn = (OSSL_FUNC_asym_cipher_dupctx_fn *)
			fwd_asym_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_ASYM_CIPHER_DUPCTX,
				&ctx->pctx->dbg);
	if (fwd_dupctx_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		return NULL;
	}

	new_ctx = ps_op_dupctx(ctx);
	if (new_ctx == NULL) {
		ps_opctx_debug(ctx, "ERROR: ps_op_dupctx failed");
		return NULL;
	}

	new_ctx->fwd_op_ctx = fwd_dupctx_fn(ctx->fwd_op_ctx);
	if (new_ctx->fwd_op_ctx == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_dupctx_fn failed");
		ps_op_freectx(new_ctx);
		return NULL;
	}

	ps_opctx_debug(ctx, "new_ctx: %p", new_ctx);
	return new_ctx;
}

static int ps_asym_op_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_get_ctx_params_fn *fwd_get_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

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
			return 0;
		}
	}

	return 1;
}

static int ps_asym_op_set_ctx_params(void *vopctx, const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_set_ctx_params_fn *fwd_set_params_fn;
	struct ps_op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (opctx == NULL)
		return 0;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_set_params_fn = (OSSL_FUNC_asym_cipher_set_ctx_params_fn *)
			fwd_asym_get_func(&opctx->pctx->fwd,
				opctx->type,
				OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
				&opctx->pctx->dbg);

	/* fwd_set_params_fn is optional */
	if (fwd_set_params_fn != NULL) {
		if (!fwd_set_params_fn(opctx->fwd_op_ctx, params)) {
			put_error_op_ctx(opctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "fwd_set_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *ps_asym_op_gettable_ctx_params(
				struct ps_op_ctx *opctx,
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
	if (fwd_gettable_params_fn != NULL)
		params = fwd_gettable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *ps_asym_op_settable_ctx_params(
				struct ps_op_ctx *opctx,
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_asym_cipher_settable_ctx_params_fn
						*fwd_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (opctx == NULL || pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	fwd_settable_params_fn =
		(OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)
			fwd_asym_get_func(&pctx->fwd, pkey_type,
				OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (fwd_settable_params_fn != NULL)
		params = fwd_settable_params_fn(opctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static EVP_MD *ps_asym_op_get_oaep_md(struct ps_op_ctx *opctx)
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
			  mdname, mdprops[0] != '\0' ? mdprops : opctx->propq);
	if (md == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					opctx->propq != NULL ? opctx->propq : "");
		return NULL;
	}

	ps_opctx_debug(opctx, "md: %s", EVP_MD_name(md));
	return md;
}

static EVP_MD *ps_asym_op_get_mgf_md(struct ps_op_ctx *ctx)
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
			  mdname, mdprops[0] != '\0' ? mdprops : ctx->propq);
	if (md == NULL) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 mdprops[0] != '\0' ? mdprops :
					ctx->propq != NULL ? ctx->propq : "");
		return NULL;
	}

	ps_opctx_debug(ctx, "md: %s", EVP_MD_name(md));
	return md;
}

static int ps_asym_op_get_oaep_label(struct ps_op_ctx *ctx,
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

static int ps_asym_op_get_padding(struct ps_op_ctx *ctx)
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

static int ps_asym_op_encrypt_init(void *vctx, void *vkey,
					const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_encrypt_init_fn *fwd_encrypt_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_encrypt_init_fn = (OSSL_FUNC_asym_cipher_encrypt_init_fn *)
				fwd_asym_get_func(&ctx->pctx->fwd,
					ctx->type,
					OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
					&ctx->pctx->dbg);
	if (fwd_encrypt_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_ENCRYPT)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!fwd_encrypt_init_fn(ctx->fwd_op_ctx, key->fwd_key,
				     params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_encrypt_init_fn failed");
		return 0;
	}

	return 1;
}

static int ps_asym_op_decrypt_init(void *vctx, void *vkey,
					const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_decrypt_init_fn *fwd_decrypt_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_decrypt_init_fn = (OSSL_FUNC_asym_cipher_decrypt_init_fn *)
				fwd_asym_get_func(&ctx->pctx->fwd, ctx->type,
					OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
					&ctx->pctx->dbg);
	if (fwd_decrypt_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_DECRYPT)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!fwd_decrypt_init_fn(ctx->fwd_op_ctx, key->fwd_key,
				     params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_decrypt_init_fn failed");
		return 0;
	}

	return 1;
}

static int ps_asym_op_encrypt(void *vctx,
				   unsigned char *out, size_t *outlen,
				   size_t outsize, const unsigned char *in,
				   size_t inlen)
{
	OSSL_FUNC_asym_cipher_encrypt_fn *fwd_encrypt_fn;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL || in == NULL || outlen == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p inlen: %lu outsize: %lu",
			ctx, ctx->key, inlen, outsize);

	fwd_encrypt_fn = (OSSL_FUNC_asym_cipher_encrypt_fn *)
			fwd_asym_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
				&ctx->pctx->dbg);
	if (fwd_encrypt_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default encrypt_fn");
		return 0;
	}

	if (!fwd_encrypt_fn(ctx->fwd_op_ctx, out, outlen, outsize,
				in, inlen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_encrypt_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "outlen: %lu", *outlen);

	return 1;
}

static int ps_asym_op_decrypt(struct ps_op_ctx *ctx,
				   unsigned char *out, size_t *outlen,
				   size_t outsize, const unsigned char *in,
				   size_t inlen)
{
	OSSL_FUNC_asym_cipher_decrypt_fn *fwd_decrypt_fn;

	if (ctx == NULL || in == NULL || outlen == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p inlen: %lu outsize: %lu",
			ctx, ctx->key, inlen, outsize);

	fwd_decrypt_fn = (OSSL_FUNC_asym_cipher_decrypt_fn *)
			fwd_asym_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_ASYM_CIPHER_DECRYPT,
				&ctx->pctx->dbg);
	if (fwd_decrypt_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default decrypt_fn");
		return 0;
	}

	if (!fwd_decrypt_fn(ctx->fwd_op_ctx, out, outlen, outsize,
				in, inlen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_decrypt_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "outlen: %lu", *outlen);

	return 1;
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
	struct ps_op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_asym_op_gettable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_asym_rsa_settable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct ps_op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_asym_op_settable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static int ps_asym_rsa_decrypt(void *vctx,
				    unsigned char *out, size_t *outlen,
				    size_t outsize, const unsigned char *in,
				    size_t inlen)
{
	int rsa_size, pad_mode, oaep_label_len = 0, rc;
	EVP_MD *oaep_md = NULL, *mgf_md = NULL;
	struct ps_op_ctx *ctx = vctx;
	unsigned char *oaep_label = NULL;
	unsigned char *tmp = NULL;
	struct ps_key *key;
	struct ps_funcs *funcs;

	if (ctx == NULL || in == NULL || outlen == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p inlen: %lu outsize: %lu",
			ctx, ctx->key, inlen, outsize);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_DECRYPT) {
		put_error_op_ctx(ctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "decrypt operation not initialized");
		return 0;
	}

	/* For clear key, let the default provider handle it */
	if (ctx->key->secure_key == NULL)
		return ps_asym_op_decrypt(ctx, out, outlen, outsize,
					    in, inlen);

#if 0
	funcs = ctx->key->funcs;
	if (funcs == NULL) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "no secure key funcs");
		return 0;
	}

	key = ctx->key;

	rsa_size = ps_keymgmt_get_size(key);
	if (rsa_size <= 0) {
		ps_opctx_debug(ctx, "ps_keymgmt_get_size failed");
		return 0;
	}
#endif

	if (out == NULL) {
		tmp = OPENSSL_zalloc(rsa_size);
		if (tmp == NULL) {
			put_error_op_ctx(ctx, PS_ERR_MALLOC_FAILED,
					 "OPENSSL_zalloc failed");
			return 0;
		}
		out = tmp;
		outsize = rsa_size;
	}

	if (outsize < (size_t)rsa_size) {
		put_error_op_ctx(ctx, PS_ERR_INVALID_PARAM,
				 "output buffer length invalid");
		return 0;
	}

	pad_mode = ps_asym_op_get_padding(ctx);
	switch (pad_mode) {
	case RSA_NO_PADDING:
	case RSA_PKCS1_PADDING:
	case RSA_X931_PADDING:
		break;

	case RSA_PKCS1_OAEP_PADDING:
		oaep_label_len = ps_asym_op_get_oaep_label(ctx,
								&oaep_label);
		if (oaep_label_len < 0) {
			ps_opctx_debug(ctx,
				"ERROR: ps_rsa_asym_get_oaep_label failed");
			rc = 0;
			goto out;
		}

		oaep_md = ps_asym_op_get_oaep_md(ctx);
		if (oaep_md == NULL) {
			ps_opctx_debug(ctx,
				"ERROR: ps_asym_op_get_oaep_md failed");
			rc = 0;
			goto out;
		}

		mgf_md = ps_asym_op_get_mgf_md(ctx);
		if (mgf_md == NULL) {
			ps_opctx_debug(ctx,
				"ERROR: ps_asym_op_get_mgf_md failed");
			rc = 0;
			goto out;
		}
		break;
	default:
		put_error_op_ctx(ctx, PS_ERR_INVALID_PADDING,
				 "unknown/unsupported padding: %d", pad_mode);
		return 0;
	}

	*outlen = outsize;

	switch (pad_mode) {
	case RSA_PKCS1_OAEP_PADDING:
		if (funcs->rsa_decrypt_oaep == NULL) {
			put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
					 "no secure key decrypt function");
			rc = 0;
			goto out;
		}

#if 0
		rc = funcs->rsa_decrypt_oaep(key->secure_key,
					     key->secure_key_size,
					     out, outlen, in, inlen,
					     EVP_MD_type(oaep_md),
					     EVP_MD_type(mgf_md),
					     oaep_label, oaep_label_len,
					     key->private,
					     ps_dbg_enabled(&ctx->pctx->dbg));
#endif
		break;

	default:
		if (funcs->rsa_decrypt == NULL) {
			put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
					 "no secure key decrypt function");
			rc = 0;
			goto out;
		}

#if 0
		rc = funcs->rsa_decrypt(key->secure_key, key->secure_key_size,
					out, outlen, in, inlen, pad_mode,
					key->private,
					ps_dbg_enabled(&ctx->pctx->dbg));
#endif
		break;
	}

	if (tmp != NULL) {
		OPENSSL_cleanse(tmp, outsize);
		OPENSSL_free(tmp);
	}

	if (rc != 0) {
		put_error_op_ctx(ctx, PS_ERR_SECURE_KEY_FUNC_FAILED,
				 "Secure key encrypt operation failed: rc: %d",
				 rc);
		rc = 0;
		goto out;
	}

	rc = 1;

	ps_opctx_debug(ctx, "outlen: %lu", *outlen);

out:
	if (oaep_md != NULL)
		EVP_MD_free(oaep_md);
	if (mgf_md != NULL)
		EVP_MD_free(mgf_md);

	return rc;
}

static const OSSL_DISPATCH ps_rsa_asym_cipher_functions[] = {
	/* RSA context constructor, descructor */
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))ps_asym_rsa_newctx },
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))ps_op_freectx },
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
