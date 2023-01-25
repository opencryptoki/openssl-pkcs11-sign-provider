/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 * Authors: Holger Dengler <dengler@linux.ibm.com>
 *          Ingo Franzki <ifranzki@linux.ibm.com>
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "common.h"
#include "provider.h"
#include "ossl.h"
#include "pkcs11.h"
#include "store.h"
#include "debug.h"

/*
 * This source file is only used with OpenSSL >= 3.0
 */
#if OPENSSL_VERSION_PREREQ(3, 0)

#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "openssl/param_build.h"
#include <openssl/decoder.h>

static OSSL_PROVIDER *pkcs11sign_provider;

#define PS_PROV_RSA_DEFAULT_MD			"SHA-1"
#define PS_PROV_PKEY_PARAM_SK_BLOB		"ps-blob"
#define PS_PROV_PKEY_PARAM_SK_FUNCS		"ps-funcs"
#define PS_PROV_PKEY_PARAM_SK_PRIVATE		"ps-private"

#define PS_PKCS11_MODULE_PATH			"pkcs11sign-module-path"
#define PS_PKCS11_MODULE_INIT_ARGS		"pkcs11sign-module-init-args"
#define PS_PKCS11_FWD				"pkcs11sign-forward"

struct ps_key {
	struct provider_ctx *pctx;
	int type; /* EVP_PKEY_xxx types */
	void *fwd_key; /* shadow key of default provider */
	unsigned char *secure_key;
	size_t secure_key_size;
	struct ps_funcs *funcs;
	void *private;
	unsigned int ref_count;
};

struct ps_op_ctx {
	struct provider_ctx *pctx;
	int type; /* EVP_PKEY_xxx types */
	const char *propq;
	void *fwd_op_ctx; /* shadow context of default provider */
	void (*fwd_op_ctx_free)(void *fwd_op_ctx);
	struct ps_key *key;
	int operation;
	OSSL_FUNC_signature_sign_fn *sign_fn;
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
};

typedef int (*ps_rsa_sign_t)(const unsigned char *key_blob,
			     size_t key_blob_length,
			     unsigned char *sig, size_t *siglen,
			     const unsigned char *tbs, size_t tbslen,
			     int padding_type, int md_nid,
			     void *private, bool debug);
typedef int (*ps_rsa_pss_sign_t)(const unsigned char *key_blob,
				 size_t key_blob_length, unsigned char *sig,
				 size_t *siglen, const unsigned char *tbs,
				 size_t tbslen, int md_nid, int mfgmd_nid,
				 int saltlen, void *private, bool debug);
typedef int (*ps_ecdsa_sign_t)(const unsigned char *key_blob,
			       size_t key_blob_length, unsigned char *sig,
			       size_t *siglen, const unsigned char *tbs,
			       size_t tbslen, int md_nid, void *private,
			       bool debug);
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
	ps_rsa_sign_t		rsa_sign;
	ps_rsa_pss_sign_t	rsa_pss_sign;
	ps_ecdsa_sign_t		ecdsa_sign;
	ps_rsa_decrypt_t	rsa_decrypt;
	ps_rsa_decrypt_oaep_t	rsa_decrypt_oaep;
};

#define ps_key_debug(key, fmt...)	ps_dbg_debug(&(key->pctx->dbg), fmt)
#define ps_opctx_debug(opctx, fmt...)	ps_dbg_debug(&(opctx->pctx->dbg), fmt)

#define DISPATCH_PROVIDER_FN(tname, name) DECL_DISPATCH_FUNC(provider, tname, name)
DISPATCH_PROVIDER_FN(teardown, 			ps_prov_teardown);
DISPATCH_PROVIDER_FN(gettable_params, 		ps_prov_gettable_params);
DISPATCH_PROVIDER_FN(get_params, 		ps_prov_get_params);
DISPATCH_PROVIDER_FN(query_operation, 		ps_prov_query_operation);
DISPATCH_PROVIDER_FN(get_reason_strings, 	ps_prov_get_reason_strings);
DISPATCH_PROVIDER_FN(get_capabilities, 		ps_prov_get_capabilities);

#define DISPATCH_KEYMGMT_FN(tname, name) DECL_DISPATCH_FUNC(keymgmt, tname, name)
DISPATCH_KEYMGMT_FN(free, 			ps_keymgmt_free);
DISPATCH_KEYMGMT_FN(gen_cleanup, 		ps_keymgmt_gen_cleanup);
DISPATCH_KEYMGMT_FN(load, 			ps_keymgmt_load);
DISPATCH_KEYMGMT_FN(gen_set_template, 		ps_keymgmt_gen_set_template);
DISPATCH_KEYMGMT_FN(gen_set_params, 		ps_keymgmt_gen_set_params);
DISPATCH_KEYMGMT_FN(gen, 			ps_keymgmt_gen);
DISPATCH_KEYMGMT_FN(get_params, 		ps_keymgmt_get_params);
DISPATCH_KEYMGMT_FN(set_params, 		ps_keymgmt_set_params);
DISPATCH_KEYMGMT_FN(has, 			ps_keymgmt_has);
DISPATCH_KEYMGMT_FN(match, 			ps_keymgmt_match);
DISPATCH_KEYMGMT_FN(validate, 			ps_keymgmt_validate);
DISPATCH_KEYMGMT_FN(export, 			ps_keymgmt_export);
DISPATCH_KEYMGMT_FN(import, 			ps_keymgmt_import);
DISPATCH_KEYMGMT_FN(new, 			ps_keymgmt_rsa_new);
DISPATCH_KEYMGMT_FN(new, 			ps_keymgmt_rsa_pss_new);
DISPATCH_KEYMGMT_FN(new, 			ps_keymgmt_ec_new);
DISPATCH_KEYMGMT_FN(gen_init, 			ps_keymgmt_rsa_gen_init);
DISPATCH_KEYMGMT_FN(gen_init, 			ps_keymgmt_rsa_pss_gen_init);
DISPATCH_KEYMGMT_FN(gen_init, 			ps_keymgmt_ec_gen_init);
DISPATCH_KEYMGMT_FN(gen_settable_params, 	ps_keymgmt_rsa_gen_settable_params);
DISPATCH_KEYMGMT_FN(gen_settable_params, 	ps_keymgmt_rsa_pss_gen_settable_params);
DISPATCH_KEYMGMT_FN(gen_settable_params, 	ps_keymgmt_ec_gen_settable_params);
DISPATCH_KEYMGMT_FN(gettable_params, 		ps_keymgmt_rsa_gettable_params);
DISPATCH_KEYMGMT_FN(gettable_params, 		ps_keymgmt_rsa_pss_gettable_params);
DISPATCH_KEYMGMT_FN(gettable_params, 		ps_keymgmt_ec_gettable_params);
DISPATCH_KEYMGMT_FN(settable_params, 		ps_keymgmt_rsa_settable_params);
DISPATCH_KEYMGMT_FN(settable_params, 		ps_keymgmt_rsa_pss_settable_params);
DISPATCH_KEYMGMT_FN(settable_params, 		ps_keymgmt_ec_settable_params);
DISPATCH_KEYMGMT_FN(export_types, 		ps_keymgmt_rsa_export_types);
DISPATCH_KEYMGMT_FN(export_types, 		ps_keymgmt_rsa_pss_export_types);
DISPATCH_KEYMGMT_FN(export_types, 		ps_keymgmt_ec_export_types);
DISPATCH_KEYMGMT_FN(import_types, 		ps_keymgmt_rsa_import_types);
DISPATCH_KEYMGMT_FN(import_types, 		ps_keymgmt_rsa_pss_import_types);
DISPATCH_KEYMGMT_FN(import_types, 		ps_keymgmt_ec_import_types);
DISPATCH_KEYMGMT_FN(query_operation_name, 	ps_keymgmt_rsa_query_operation_name);
DISPATCH_KEYMGMT_FN(query_operation_name, 	ps_keymgmt_ec_query_operation_name);

#define DISPATCH_KEYEXCH_FN(tname, name) DECL_DISPATCH_FUNC(keyexch, tname, name)
DISPATCH_KEYEXCH_FN(newctx, ps_keyexch_ec_newctx);
DISPATCH_KEYEXCH_FN(dupctx, ps_keyexch_ec_dupctx);
DISPATCH_KEYEXCH_FN(init, ps_keyexch_ec_init);
DISPATCH_KEYEXCH_FN(set_peer, ps_keyexch_ec_set_peer);
DISPATCH_KEYEXCH_FN(derive, ps_keyexch_ec_derive);
DISPATCH_KEYEXCH_FN(set_ctx_params, ps_keyexch_ec_set_ctx_params);
DISPATCH_KEYEXCH_FN(get_ctx_params, ps_keyexch_ec_get_ctx_params);
DISPATCH_KEYEXCH_FN(settable_ctx_params, ps_keyexch_ec_settable_ctx_params);
DISPATCH_KEYEXCH_FN(gettable_ctx_params, ps_keyexch_ec_gettable_ctx_params);

#define DISPATCH_SIGNATURE(tname, name) DECL_DISPATCH_FUNC(signature, tname, name)
DISPATCH_SIGNATURE(newctx, ps_signature_rsa_newctx);
DISPATCH_SIGNATURE(newctx, ps_signature_ec_newctx);
DISPATCH_SIGNATURE(dupctx, ps_signature_op_dupctx);
DISPATCH_SIGNATURE(sign_init, ps_signature_op_sign_init);
DISPATCH_SIGNATURE(sign, ps_signature_rsa_sign);
DISPATCH_SIGNATURE(sign, ps_signature_ec_sign);
DISPATCH_SIGNATURE(verify_init, ps_signature_op_verify_init);
DISPATCH_SIGNATURE(verify, ps_signature_op_verify);
DISPATCH_SIGNATURE(verify_recover_init, ps_signature_op_verify_recover_init);
DISPATCH_SIGNATURE(verify_recover, ps_signature_op_verify_recover);
DISPATCH_SIGNATURE(digest_sign_init, ps_signature_rsa_digest_sign_init);
DISPATCH_SIGNATURE(digest_sign_init, ps_signature_ec_digest_sign_init);
DISPATCH_SIGNATURE(digest_sign_update, ps_signature_op_digest_sign_update);
DISPATCH_SIGNATURE(digest_sign_final, ps_signature_op_digest_sign_final);
DISPATCH_SIGNATURE(digest_verify_init, ps_signature_op_digest_verify_init);
DISPATCH_SIGNATURE(digest_verify_update, ps_signature_op_digest_verify_update);
DISPATCH_SIGNATURE(digest_verify_final, ps_signature_op_digest_verify_final);
DISPATCH_SIGNATURE(get_ctx_params, ps_signature_op_get_ctx_params);
DISPATCH_SIGNATURE(gettable_ctx_params, ps_signature_rsa_gettable_ctx_params);
DISPATCH_SIGNATURE(gettable_ctx_params, ps_signature_ec_gettable_ctx_params);
DISPATCH_SIGNATURE(set_ctx_params, ps_signature_op_set_ctx_params);
DISPATCH_SIGNATURE(settable_ctx_params, ps_signature_rsa_settable_ctx_params);
DISPATCH_SIGNATURE(settable_ctx_params, ps_signature_ec_settable_ctx_params);
DISPATCH_SIGNATURE(get_ctx_md_params, ps_signature_op_get_ctx_md_params);
DISPATCH_SIGNATURE(gettable_ctx_md_params, ps_signature_rsa_gettable_ctx_md_params);
DISPATCH_SIGNATURE(gettable_ctx_md_params, ps_signature_ec_gettable_ctx_md_params);
DISPATCH_SIGNATURE(set_ctx_md_params, ps_signature_op_set_ctx_md_params);
DISPATCH_SIGNATURE(settable_ctx_md_params, ps_signature_rsa_settable_ctx_md_params);
DISPATCH_SIGNATURE(settable_ctx_md_params, ps_signature_ec_settable_ctx_md_params);

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

#define PS_ERR_INTERNAL_ERROR		1
#define PS_ERR_MALLOC_FAILED		2
#define PS_ERR_INVALID_PARAM		3
#define PS_ERR_DEFAULT_PROV_FUNC_MISSING	4
#define PS_ERR_DEFAULT_PROV_FUNC_FAILED	5
#define PS_ERR_OPRATION_NOT_INITIALIZED	6
#define PS_ERR_MISSING_PARAMETER		7
#define PS_ERR_INVALID_PADDING		8
#define PS_ERR_INVALID_MD			9
#define PS_ERR_INVALID_SALTLEN		10
#define PS_ERR_SECURE_KEY_FUNC_FAILED	11

static const OSSL_ITEM ps_prov_reason_strings[] = {
	{ PS_ERR_INTERNAL_ERROR,	"Internal error" },
	{ PS_ERR_MALLOC_FAILED,	"Memory allocation failed" },
	{ PS_ERR_INVALID_PARAM,	"Invalid parameter encountered" },
	{ PS_ERR_DEFAULT_PROV_FUNC_MISSING,
		"A function inherited from default provider is missing" },
	{ PS_ERR_DEFAULT_PROV_FUNC_FAILED,
		"A function inherited from default provider has failed" },
	{ PS_ERR_OPRATION_NOT_INITIALIZED,
		"An operation context has not been initialized" },
	{ PS_ERR_MISSING_PARAMETER,
		"A parameter of a key or a context is missing" },
	{ PS_ERR_INVALID_PADDING,
		"An invalid or unknown padding is used" },
	{ PS_ERR_INVALID_MD, "An invalid or unknown digest is used" },
	{ PS_ERR_INVALID_SALTLEN, "An invalid salt length is used" },
	{ PS_ERR_SECURE_KEY_FUNC_FAILED,
		"A secure key function has failed" },
	{0, NULL }
};

static void ps_keymgmt_upref(struct ps_key *key);
static struct ps_key *ps_keymgmt_new(struct provider_ctx *pctx,
					       int type);
static int ps_keymgmt_get_bits(struct ps_key *key);

/* --- provider START --- */
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
/* --- provider END --- */

static struct ps_op_ctx *ps_op_newctx(struct provider_ctx *pctx,
						const char *propq,
						int type)
{
	struct ps_op_ctx *opctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "propq: %s type: %d",
		     propq != NULL ? propq : "", type);

	opctx = OPENSSL_zalloc(sizeof(struct ps_op_ctx));
	if (opctx == NULL) {
		put_error_pctx(pctx, PS_ERR_MALLOC_FAILED,
			       "OPENSSL_zalloc failed");
		return NULL;
	}

	opctx->pctx = pctx;
	opctx->type = type;

	if (propq != NULL)
		opctx->propq = OPENSSL_strdup(propq);

	if (opctx->propq == NULL) {
		put_error_pctx(pctx, PS_ERR_MALLOC_FAILED,
			       "OPENSSL_strdup failed");
		OPENSSL_free(opctx);
		return NULL;
	}

	ps_dbg_debug(&pctx->dbg, "opctx: %p", opctx);
	return opctx;
}

// keep
static void ps_op_freectx(void *vopctx)
{
	struct ps_op_ctx *opctx = vopctx;

	if (opctx == NULL)
		return;

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	if (opctx->fwd_op_ctx != NULL && opctx->fwd_op_ctx_free != NULL)
		opctx->fwd_op_ctx_free(opctx->fwd_op_ctx);

	if (opctx->key)
		ps_keymgmt_free(opctx->key);

	if (opctx->propq)
		OPENSSL_free((void *)opctx->propq);

	if (opctx->mdctx)
		EVP_MD_CTX_free(opctx->mdctx);
	if (opctx->md)
		EVP_MD_free(opctx->md);

	OPENSSL_free(opctx);
}

static struct ps_op_ctx *ps_op_dupctx(struct ps_op_ctx *opctx)
{
	struct ps_op_ctx *new_opctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	new_opctx = ps_op_newctx(opctx->pctx, opctx->propq, opctx->type);
	if (new_opctx == NULL) {
		ps_opctx_debug(opctx, "ERROR: ps_op_newctx failed");
		return NULL;
	}

	new_opctx->operation = opctx->operation;
	new_opctx->fwd_op_ctx_free = opctx->fwd_op_ctx_free;
	new_opctx->sign_fn = opctx->sign_fn;

	if (opctx->mdctx) {
		new_opctx->mdctx = EVP_MD_CTX_new();
		if (!new_opctx->mdctx) {
			put_error_op_ctx(opctx, PS_ERR_MALLOC_FAILED,
					 "EVP_MD_CTX_new failed");
			ps_op_freectx(new_opctx);
			return NULL;
		}

		if (!EVP_MD_CTX_copy_ex(new_opctx->mdctx, opctx->mdctx)) {
			ps_opctx_debug(opctx,
					"ERROR: EVP_MD_CTX_copy_ex failed");
			ps_op_freectx(new_opctx);
			return NULL;
		}
	};

	if (opctx->md) {
		new_opctx->md = opctx->md;
		EVP_MD_up_ref(opctx->md);
	}

	if (opctx->key) {
		new_opctx->key = opctx->key;
		ps_keymgmt_upref(opctx->key);
	}

	ps_opctx_debug(opctx, "new_opctx: %p", new_opctx);
	return new_opctx;
}

static int ps_op_init(struct ps_op_ctx *ctx, struct ps_key *key,
			   int operation)
{
	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p operation: %d", ctx, key,
			operation);

	if (key != NULL) {
		switch (ctx->type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA_PSS:
			if (key->type != EVP_PKEY_RSA &&
			    key->type != EVP_PKEY_RSA_PSS) {
				put_error_op_ctx(ctx,
						 PS_ERR_INTERNAL_ERROR,
						 "key type mismatch: ctx type: "
						 "%d key type: %d",
						 ctx->type, key->type);
				return 0;
			}
			break;
		case EVP_PKEY_EC:
			if (key->type != EVP_PKEY_EC) {
				put_error_op_ctx(ctx,
						 PS_ERR_INTERNAL_ERROR,
						 "key type mismatch: ctx type: "
						 "%d key type: %d",
						 ctx->type, key->type);
				return 0;
			}
			break;
		default:
			put_error_op_ctx(ctx, PS_ERR_INTERNAL_ERROR,
					 "key type unknown: ctx type: "
					 "%d key type: %d",
					 ctx->type, key->type);
			return 0;
		}
	}

	if (key != NULL)
		ps_keymgmt_upref(key);

	if (ctx->key != NULL)
		ps_keymgmt_free(ctx->key);

	ctx->key = key;
	ctx->operation = operation;

	return 1;
}

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

static int ps_parse_padding(const char *padding)
{
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0)
		return RSA_NO_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
		return RSA_PKCS1_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0)
		return RSA_PKCS1_OAEP_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_X931) == 0)
		return RSA_X931_PADDING;
	if (strcmp(padding, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
		return RSA_PKCS1_PSS_PADDING;

	return -1;
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

	return ps_parse_padding(padding);
}

static int ps_asym_op_encrypt_init(void *vctx, void *vkey,
					const OSSL_PARAM params[])
{
	OSSL_FUNC_asym_cipher_encrypt_init_fn *fwd_encrypt_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_key *key = vkey;
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
	struct ps_key *key = vkey;
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

static struct ps_op_ctx *ps_signature_op_newctx(
					struct provider_ctx *pctx,
					const char *propq,
					int pkey_type)
{
	OSSL_FUNC_signature_freectx_fn *fwd_freectx_fn;
	OSSL_FUNC_signature_newctx_fn *fwd_newctx_fn;
	struct ps_op_ctx *ctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "propq: %s pkey_type: %d",
		     propq != NULL ? propq : "", pkey_type);

	fwd_newctx_fn = (OSSL_FUNC_signature_newctx_fn *)
			fwd_sign_get_func(&pctx->fwd, pkey_type,
					OSSL_FUNC_SIGNATURE_NEWCTX,
					&pctx->dbg);
	if (fwd_newctx_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default newctx_fn");
		return NULL;
	}

	fwd_freectx_fn = (OSSL_FUNC_signature_freectx_fn *)
			fwd_sign_get_func(&pctx->fwd, pkey_type,
					OSSL_FUNC_SIGNATURE_FREECTX,
					&pctx->dbg);
	if (fwd_freectx_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default freectx_fn");
		return NULL;
	}

	ctx = ps_op_newctx(pctx, propq, pkey_type);
	if (ctx == NULL) {
		ps_dbg_error(&pctx->dbg, "ERROR: ps_op_newctx failed");
		return NULL;
	}

	ctx->fwd_op_ctx = fwd_newctx_fn(pctx->fwd.ctx,
						propq);
	if (ctx->fwd_op_ctx == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_newctx_fn failed");
		ps_op_freectx(ctx);
		return NULL;
	}
	ctx->fwd_op_ctx_free = fwd_freectx_fn;

	ps_dbg_debug(&pctx->dbg, "ctx: %p", ctx);
	return ctx;
}

static void *ps_signature_op_dupctx(void *vctx)
{
	OSSL_FUNC_signature_dupctx_fn *fwd_dupctx_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_op_ctx *new_ctx;

	if (ctx == NULL)
		return NULL;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	fwd_dupctx_fn = (OSSL_FUNC_signature_dupctx_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_DUPCTX,
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

static int ps_signature_op_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_signature_get_ctx_params_fn *fwd_get_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_get_params_fn = (OSSL_FUNC_signature_get_ctx_params_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
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

static int ps_signature_op_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_set_ctx_params_fn *fwd_set_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_set_params_fn = (OSSL_FUNC_signature_set_ctx_params_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
				&ctx->pctx->dbg);

	/* fwd_set_params_fn is optional */
	if (fwd_set_params_fn != NULL) {
		if (!fwd_set_params_fn(ctx->fwd_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "fwd_set_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *ps_signature_op_gettable_ctx_params(
				struct ps_op_ctx *ctx,
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_signature_gettable_ctx_params_fn *fwd_gettable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL || pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	fwd_gettable_params_fn =
		(OSSL_FUNC_signature_gettable_ctx_params_fn *)
			fwd_sign_get_func(&pctx->fwd, pkey_type,
				OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (fwd_gettable_params_fn != NULL)
		params = fwd_gettable_params_fn(ctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *ps_signature_op_settable_ctx_params(
				struct ps_op_ctx *ctx,
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_signature_settable_ctx_params_fn *fwd_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL || pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	fwd_settable_params_fn =
		(OSSL_FUNC_signature_settable_ctx_params_fn *)
			fwd_sign_get_func(&pctx->fwd, pkey_type,
				OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
				&pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (fwd_settable_params_fn != NULL)
		params = fwd_settable_params_fn(ctx->fwd_op_ctx,
						    pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static int ps_signature_op_get_ctx_md_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_FUNC_signature_get_ctx_md_params_fn *fwd_get_md_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_get_md_params_fn = (OSSL_FUNC_signature_get_ctx_md_params_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type,
				OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
				&ctx->pctx->dbg);

	/* fwd_get_md_params_fn is optional */
	if (fwd_get_md_params_fn != NULL) {
		if (!fwd_get_md_params_fn(ctx->fwd_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "fwd_get_md_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static int ps_signature_op_set_ctx_md_params(void *vctx,
					     const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_set_ctx_md_params_fn *fwd_set_md_params_fn;
	struct ps_op_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p", ctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_set_md_params_fn = (OSSL_FUNC_signature_set_ctx_md_params_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type,
				OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
				&ctx->pctx->dbg);

	/* fwd_set_md_params_fn is optional */
	if (fwd_set_md_params_fn != NULL) {
		if (!fwd_set_md_params_fn(ctx->fwd_op_ctx, params)) {
			put_error_op_ctx(ctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "fwd_set_md_params_fn failed");
			return 0;
		}
	}

	/* Also set parameters in own MD context */
	if (ctx->mdctx)
		return EVP_MD_CTX_set_params(ctx->mdctx, params);

	return 1;
}

static const OSSL_PARAM *ps_signature_op_gettable_ctx_md_params(
				struct ps_op_ctx *ctx, int pkey_type)
{
	OSSL_FUNC_signature_gettable_ctx_md_params_fn
						*fwd_gettable_md_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL)
		return NULL;

	ps_opctx_debug(ctx, "pkey_type: %d", pkey_type);

	fwd_gettable_md_params_fn =
		(OSSL_FUNC_signature_gettable_ctx_md_params_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd, pkey_type,
				OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
				&ctx->pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (fwd_gettable_md_params_fn != NULL)
		params = fwd_gettable_md_params_fn(ctx->fwd_op_ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *ps_signature_op_settable_ctx_md_params(
				struct ps_op_ctx *ctx, int pkey_type)
{
	OSSL_FUNC_signature_settable_ctx_md_params_fn
						*fwd_settable_md_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (ctx == NULL)
		return NULL;

	ps_opctx_debug(ctx, "pkey_type: %d", pkey_type);

	fwd_settable_md_params_fn =
		(OSSL_FUNC_signature_settable_ctx_md_params_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd, pkey_type,
				OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
				&ctx->pctx->dbg);

	/* fwd_settable_md_params_fn is optional */
	if (fwd_settable_md_params_fn != NULL)
		params = fwd_settable_md_params_fn(ctx->fwd_op_ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	return params;
}

static EVP_MD *ps_signature_op_get_md(struct ps_op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_signature_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		ps_opctx_debug(ctx, "ps_signature_op_get_ctx_params failed");
		if (ctx->md != NULL) {
			ps_opctx_debug(ctx, "use digest from context: %s",
					EVP_MD_name(ctx->md));
			EVP_MD_up_ref(ctx->md);
			return ctx->md;
		}

		ps_opctx_debug(ctx, "use default");
		strcpy(mdname, PS_PROV_RSA_DEFAULT_MD);
		strcpy(mdprops, "");
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

static EVP_MD *ps_signature_op_get_mgf_md(struct ps_op_ctx *ctx)
{
	char mdprops[256], mdname[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST,
				&mdname, sizeof(mdname)),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES,
				&mdprops, sizeof(mdprops)),
		OSSL_PARAM_END
	};
	EVP_MD *md;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_signature_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		ps_opctx_debug(ctx, "ps_signature_op_get_ctx_params failed, "
				"using signature digest");
		return ps_signature_op_get_md(ctx);
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

static int ps_signature_op_get_padding(struct ps_op_ctx *ctx)
{
	char padding[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PAD_MODE,
				&padding, sizeof(padding)),
		OSSL_PARAM_END
	};

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_signature_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "ps_signature_op_get_ctx_params failed to "
				 "get OSSL_PKEY_PARAM_PAD_MODE");
		return -1;
	}

	ps_opctx_debug(ctx, "padding: %s", padding);
	return ps_parse_padding(padding);
}

static int ps_signature_op_get_pss_saltlen(struct ps_op_ctx *ctx,
					   struct ps_key *key,
					   EVP_MD *mgf_md)
{
	char saltlen[50];
	OSSL_PARAM ctx_params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
				&saltlen, sizeof(saltlen)),
		OSSL_PARAM_END
	};
	int salt_len, rsa_bits, max_saltlen;

	ps_opctx_debug(ctx, "ctx: %p", ctx);

	if (!ps_signature_op_get_ctx_params(ctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0])) {
		put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
				 "ps_signature_op_get_ctx_params failed to "
				 "get OSSL_SIGNATURE_PARAM_PSS_SALTLEN");
		return -1;
	}

	ps_opctx_debug(ctx, "saltlen: %s", saltlen);

	rsa_bits = ps_keymgmt_get_bits(key);
	if (rsa_bits <= 0) {
		ps_opctx_debug(ctx,
			"ERROR: ps_keymgmt_get_bits failed");
		return -1;
	}

	max_saltlen = rsa_bits / 8 - EVP_MD_size(mgf_md) - 2;

	if (strcmp(saltlen, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
		salt_len = EVP_MD_size(mgf_md);
	else if (strcmp(saltlen, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
		salt_len = max_saltlen;
	else if (strcmp(saltlen, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
		salt_len = max_saltlen;
	else
		salt_len = atoi(saltlen);

	if (salt_len > max_saltlen || salt_len < 0) {
		put_error_op_ctx(ctx, PS_ERR_INVALID_SALTLEN,
				 "invalid salt len: %d", saltlen);
		return -1;
	}

	ps_opctx_debug(ctx, "salt_len: %d", salt_len);
	return salt_len;
}

static int ps_signature_op_sign_init(void *vctx, void *vkey,
				     const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_sign_init_fn *fwd_sign_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_sign_init_fn = (OSSL_FUNC_signature_sign_init_fn *)
				fwd_sign_get_func(&ctx->pctx->fwd,
					ctx->type,
					OSSL_FUNC_SIGNATURE_SIGN_INIT,
					&ctx->pctx->dbg);
	if (fwd_sign_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default sign_init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_SIGN)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!fwd_sign_init_fn(ctx->fwd_op_ctx, key->fwd_key,
				  params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_sign_init_fn failed");
		return 0;
	}

	return 1;
}

static int ps_signature_op_verify_init(void *vctx, void *vkey,
				       const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_verify_init_fn *fwd_verify_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_verify_init_fn = (OSSL_FUNC_signature_verify_init_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_VERIFY_INIT,
				&ctx->pctx->dbg);
	if (fwd_verify_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_VERIFY)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!fwd_verify_init_fn(ctx->fwd_op_ctx, key->fwd_key,
				    params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_init_fn failed");
		return 0;
	}

	return 1;
}

static int ps_signature_op_verify_recover_init(void *vctx, void *vkey,
					       const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_verify_recover_init_fn
					*fwd_verify_recover_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p", ctx, key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	fwd_verify_recover_init_fn =
		(OSSL_FUNC_signature_verify_recover_init_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type,
				OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
				&ctx->pctx->dbg);
	if (fwd_verify_recover_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_recover_init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_VERIFYRECOVER)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!fwd_verify_recover_init_fn(ctx->fwd_op_ctx,
					    key->fwd_key,
					    params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_recover_init_fn failed");
		return 0;
	}

	return 1;
}

static int ps_signature_op_sign(struct ps_op_ctx *ctx,
				unsigned char *sig, size_t *siglen,
				size_t sigsize,
				const unsigned char *tbs, size_t tbslen)
{
	OSSL_FUNC_signature_sign_fn *fwd_sign_fn;

	if (ctx == NULL || tbs == NULL || siglen == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p tbslen: %lu sigsize: %lu",
			ctx, ctx->key, tbslen, sigsize);

	fwd_sign_fn = (OSSL_FUNC_signature_sign_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_SIGN,
				&ctx->pctx->dbg);
	if (fwd_sign_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default sign_fn");
		return 0;
	}

	if (!fwd_sign_fn(ctx->fwd_op_ctx, sig, siglen, sigsize,
			     tbs, tbslen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_sign_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "siglen: %lu", *siglen);

	return 1;
}

static int ps_signature_op_verify(void *vctx,
				  const unsigned char *sig, size_t siglen,
				  const unsigned char *tbs, size_t tbslen)
{
	OSSL_FUNC_signature_verify_fn *fwd_verify_fn;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL || tbs == NULL || sig == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p tbslen: %lu siglen: %lu",
			ctx, ctx->key, tbslen, siglen);

	fwd_verify_fn = (OSSL_FUNC_signature_verify_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_VERIFY,
				&ctx->pctx->dbg);
	if (fwd_verify_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_fn");
		return 0;
	}

	if (!fwd_verify_fn(ctx->fwd_op_ctx, sig, siglen, tbs, tbslen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_fn failed");
		return 0;
	}

	return 1;
}

static int ps_signature_op_verify_recover(void *vctx,
					  unsigned char *rout, size_t *routlen,
					  size_t routsize,
					  const unsigned char *sig,
					  size_t siglen)
{
	OSSL_FUNC_signature_verify_recover_fn *fwd_verify_recover_fn;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL || routlen == NULL || sig == NULL)
		return 0;

	ps_opctx_debug(ctx,
			"ctx: %p key: %p routsize: %lu siglen: %lu",
			ctx, ctx->key, routsize, siglen);

	fwd_verify_recover_fn = (OSSL_FUNC_signature_verify_recover_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd,
				ctx->type, OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
				&ctx->pctx->dbg);
	if (fwd_verify_recover_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_recover_fn");
		return 0;
	}

	if (!fwd_verify_recover_fn(ctx->fwd_op_ctx, rout, routlen,
				       routsize, sig, siglen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_recover_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "routlen: %lu", *routlen);

	return 1;
}

static int ps_signature_op_digest_sign_init(struct ps_op_ctx *opctx,
					    const char *mdname,
					    struct ps_key *key,
					    const OSSL_PARAM params[],
					  OSSL_FUNC_signature_sign_fn *sign_fn)
{
	OSSL_FUNC_signature_digest_sign_init_fn *fwd_digest_sign_init_fn;
	const OSSL_PARAM *p;

	if (!opctx || !key || !sign_fn)
		return 0;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p", opctx,
		       mdname != NULL ? mdname : "", key);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_digest_sign_init_fn = (OSSL_FUNC_signature_digest_sign_init_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
				  &opctx->pctx->dbg);
	if (fwd_digest_sign_init_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_init_fn");
		return 0;
	}

	if (!ps_op_init(opctx, key, EVP_PKEY_OP_SIGN)) {
		ps_opctx_debug(opctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!fwd_digest_sign_init_fn(opctx->fwd_op_ctx, mdname,
					 key->fwd_key, params)) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_sign_init_fn failed");
		return 0;
	}

	/* For clear key, the default provider has already handled it */
	if (opctx->key->secure_key == NULL)
		return 1;

	opctx->sign_fn = sign_fn;

	if (opctx->mdctx != NULL)
		EVP_MD_CTX_free(opctx->mdctx);
	opctx->mdctx = EVP_MD_CTX_new();
	if (opctx->mdctx == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MALLOC_FAILED,
		"EVP_MD_CTX_new failed");
		return 0;
	}

	if (opctx->md)
		EVP_MD_free(opctx->md);

	opctx->md = (mdname) ?
		EVP_MD_fetch(opctx->pctx->core.libctx, mdname, opctx->propq) :
		ps_signature_op_get_md(opctx);
	if (!opctx->md) {
		ps_opctx_debug(opctx, "ERROR: Failed to get digest sign digest");
		EVP_MD_CTX_free(opctx->mdctx);
		opctx->mdctx = NULL;
		return 0;
	}

	return EVP_DigestInit_ex2(opctx->mdctx, opctx->md, params);
}

static int ps_signature_op_digest_sign_update(void *vctx,
					      const unsigned char *data,
					      size_t datalen)
{
	OSSL_FUNC_signature_digest_sign_update_fn *fwd_digest_sign_update_fn;
	struct ps_op_ctx *opctx = vctx;

	if (opctx == NULL)
		return 0;

	ps_opctx_debug(opctx, "opctx: %p key: %p datalen: %lu", opctx,
		       opctx->key, datalen);

	if (opctx->key == NULL || opctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	/* For secure key, don't pass it to the default provider */
	if (opctx->key->secure_key != NULL)
		goto secure_key;

	fwd_digest_sign_update_fn = (OSSL_FUNC_signature_digest_sign_update_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd,
				  opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
				  &opctx->pctx->dbg);

	if (fwd_digest_sign_update_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_update_fn");
		return 0;
	}

	if (!fwd_digest_sign_update_fn(opctx->fwd_op_ctx, data,
					   datalen)) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_sign_update_fn failed");
		return 0;
	}

	return 1;

secure_key:
	if (!opctx->mdctx) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	return EVP_DigestUpdate(opctx->mdctx, data, datalen);
}

static int ps_signature_op_digest_sign_final(void *vctx,
					     unsigned char *sig,
					     size_t *siglen, size_t sigsize)
{
	OSSL_FUNC_signature_digest_sign_final_fn *default_digest_sign_final_fn;
	unsigned char digest[EVP_MAX_MD_SIZE];
	struct ps_op_ctx *ctx = vctx;
	unsigned int dlen = 0;

	if (ctx == NULL || siglen == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p sigsize: %lu", ctx, ctx->key,
			sigsize);

	if (ctx->key == NULL || ctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(ctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	/* For secure key, don't pass it to the default provider */
	if (ctx->key->secure_key != NULL)
		goto secure_key;

	default_digest_sign_final_fn =
			(OSSL_FUNC_signature_digest_sign_final_fn *)
				fwd_sign_get_func(&ctx->pctx->fwd,
					ctx->type,
					OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
					&ctx->pctx->dbg);
	if (default_digest_sign_final_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_final_fn");
		return 0;
	}

	if (!default_digest_sign_final_fn(ctx->fwd_op_ctx, sig, siglen,
					  sigsize)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_sign_final_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "siglen: %lu", *siglen);
	return 1;

secure_key:
	if (ctx->mdctx == NULL || ctx->sign_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return 0;
	}

	if (sig != NULL) {
		if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen)) {
			ps_opctx_debug(ctx,
					"ERROR: EVP_DigestFinal_ex failed");
			return 0;
		}
	}

	if (!ctx->sign_fn(ctx, sig, siglen, sigsize, digest, (size_t)dlen)) {
		ps_opctx_debug(ctx, "ERROR: sign_fn failed");
		return 0;
	}

	ps_opctx_debug(ctx, "siglen: %lu", *siglen);
	return 1;
}

static int ps_signature_op_digest_verify_init(void *vctx,
					      const char *mdname,
					      void *vkey,
					      const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_digest_verify_init_fn
					*default_digest_verify_init_fn;
	struct ps_op_ctx *ctx = vctx;
	struct ps_key *key = vkey;
	const OSSL_PARAM *p;

	if (ctx == NULL || key == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p mdname: %s key: %p", ctx,
			mdname != NULL ? mdname : "", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(ctx, "param: %s", p->key);

	default_digest_verify_init_fn =
			(OSSL_FUNC_signature_digest_verify_init_fn *)
				fwd_sign_get_func(&ctx->pctx->fwd,
					ctx->type,
					OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
					&ctx->pctx->dbg);
	if (default_digest_verify_init_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_init_fn");
		return 0;
	}

	if (!ps_op_init(ctx, key, EVP_PKEY_OP_VERIFY)) {
		ps_opctx_debug(ctx, "ERROR: ps_op_init failed");
		return 0;
	}

	if (!default_digest_verify_init_fn(ctx->fwd_op_ctx, mdname,
					 key->fwd_key, params)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_init_fn failed");
		return 0;
	}

	return 1;
}

static int ps_signature_op_digest_verify_update(void *vctx,
						const unsigned char *data,
						size_t datalen)
{
	OSSL_FUNC_signature_digest_verify_update_fn
					*default_digest_verify_update_fn;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p datalen: %lu", ctx, ctx->key,
			datalen);

	default_digest_verify_update_fn =
		(OSSL_FUNC_signature_digest_verify_update_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd, ctx->type,
				OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
				&ctx->pctx->dbg);
	if (default_digest_verify_update_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_update_fn");
		return 0;
	}

	if (!default_digest_verify_update_fn(ctx->fwd_op_ctx,
					     data, datalen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_update_fn failed");
		return 0;
	}

	return 1;
}

static int ps_signature_op_digest_verify_final(void *vctx,
					       const unsigned char *sig,
					       size_t siglen)
{
	OSSL_FUNC_signature_digest_verify_final_fn
					*default_digest_verify_final_fn;
	struct ps_op_ctx *ctx = vctx;

	if (ctx == NULL || sig == NULL)
		return 0;

	ps_opctx_debug(ctx, "ctx: %p key: %p siglen: %lu", ctx, ctx->key,
			siglen);

	default_digest_verify_final_fn =
		(OSSL_FUNC_signature_digest_verify_final_fn *)
			fwd_sign_get_func(&ctx->pctx->fwd, ctx->type,
				OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
				&ctx->pctx->dbg);
	if (default_digest_verify_final_fn == NULL) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_final_fn");
		return 0;
	}

	if (!default_digest_verify_final_fn(ctx->fwd_op_ctx, sig, siglen)) {
		put_error_op_ctx(ctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_final_fn failed");
		return 0;
	}

	return 1;
}


static void ps_keymgmt_upref(struct ps_key *key)
{
	ps_key_debug(key, "key: %p", key);

	key->ref_count++;

	ps_key_debug(key, "ref_count: %u", key->ref_count);
}

static unsigned int ps_keymgmt_downref(struct ps_key *key)
{
	ps_key_debug(key, "key: %p ", key);

	if (key->ref_count > 0)
		key->ref_count--;

	ps_key_debug(key, "ref_count: %u", key->ref_count);

	return key->ref_count;
}

static struct ps_key *ps_keymgmt_new(struct provider_ctx *pctx,
					       int type)
{
	OSSL_FUNC_keymgmt_new_fn *default_new_fn;
	struct ps_key *key;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p type: %d", pctx,
		     type);

	default_new_fn = (OSSL_FUNC_keymgmt_new_fn *)
			fwd_keymgmt_get_func(&pctx->fwd, type,
					     OSSL_FUNC_KEYMGMT_NEW,
					     &pctx->dbg);
	if (default_new_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default new_fn");
		return NULL;
	}

	key = OPENSSL_zalloc(sizeof(struct ps_key));
	if (key == NULL) {
		put_error_pctx(pctx, PS_ERR_MALLOC_FAILED,
			       "OPENSSL_zalloc failed");
		return NULL;
	}

	key->pctx = pctx;
	key->type = type;

	key->fwd_key = default_new_fn(pctx->fwd.ctx);
	if (key->fwd_key == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "default_new_fn failed");
		OPENSSL_free(key);
		return NULL;
	}

	ps_keymgmt_upref(key);

	ps_dbg_debug(&pctx->dbg, "key: %p", key);

	return key;
}

static void ps_keymgmt_free(void *vkey)
{
	OSSL_FUNC_keymgmt_free_fn *default_free_fn;
	struct ps_key *key = vkey;

	if (key == NULL)
		return;

	ps_key_debug(key, "key: %p", key);

	if (ps_keymgmt_downref(key) > 0)
		return;

	ps_key_debug(key, "free key: %p", key);

	default_free_fn = (OSSL_FUNC_keymgmt_free_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
					key->type, OSSL_FUNC_KEYMGMT_FREE,
					&key->pctx->dbg);
	if (default_free_fn == NULL)
		ps_key_debug(key, "no default free_fn");
	else
		default_free_fn(key->fwd_key);

	if (key->secure_key != NULL)
		OPENSSL_free(key->secure_key);
	OPENSSL_free(key);
}

static int ps_keymgmt_match(const void *vkey1, const void *vkey2,
				 int selection)
{
	OSSL_FUNC_keymgmt_match_fn *default_match_fn;
	const struct ps_key *key1 = vkey1;
	const struct ps_key *key2 = vkey2;

	if (key1 == NULL || key2 == NULL)
		return 0;

	ps_key_debug(key1, "key1: %p key2: %p", key1, key2);

	default_match_fn = (OSSL_FUNC_keymgmt_match_fn *)
			fwd_keymgmt_get_func(&key1->pctx->fwd,
					key1->type, OSSL_FUNC_KEYMGMT_MATCH,
					&key1->pctx->dbg);
	if (default_match_fn == NULL) {
		put_error_key(key1, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default match_fn");
		return 0;
	}

	if (key1->type != key2->type)
		return 0;

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		/* match everything except private key */
		return default_match_fn(key1->fwd_key, key2->fwd_key,
					selection &
					    (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY));
	}

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (key1->secure_key_size != key2->secure_key_size)
			return 0;
		if (key1->secure_key_size > 0) {
			if (memcmp(key1->secure_key, key2->secure_key,
				   key1->secure_key_size) != 0)
				return 0;
			selection &= (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
		}
	}

	return default_match_fn(key1->fwd_key, key2->fwd_key,
				selection);
}

static int ps_keymgmt_validate(const void *vkey,
				    int selection, int checktype)
{
	OSSL_FUNC_keymgmt_validate_fn *default_validate_fn;
	const struct ps_key *key = vkey;
	int default_selection = selection;

	if (key == NULL)
		return 0;

	ps_key_debug(key, "key: %p selection: %x checktype: %x", key,
		     selection, checktype);

	default_validate_fn = (OSSL_FUNC_keymgmt_validate_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
					key->type, OSSL_FUNC_KEYMGMT_VALIDATE,
					&key->pctx->dbg);
	if (default_validate_fn == NULL) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default validate_fn");
		return 0;
	}

	/* A secure key doesn't have the private parts in the default key */
	if (key->secure_key != NULL)
		default_selection &= (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY);

	return default_validate_fn(key->fwd_key, default_selection,
				   checktype);
}

static int ps_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_get_params_fn *default_get_params_fn;
	struct ps_key *key = vkey;
	OSSL_PARAM *p;

	if (key == NULL)
		return 0;

	ps_key_debug(key, "key: %p", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_key_debug(key, "param: %s", p->key);

	default_get_params_fn = (OSSL_FUNC_keymgmt_get_params_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
				key->type, OSSL_FUNC_KEYMGMT_GET_PARAMS,
				&key->pctx->dbg);

	/* default_get_params_fn is optional */
	if (default_get_params_fn != NULL) {
		if (!default_get_params_fn(key->fwd_key, params)) {
			put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				      "default_get_params_fn failed");
			return 0;
		}
	}

	if (key->secure_key == NULL)
		return 1;

	p = OSSL_PARAM_locate(params, PS_PROV_PKEY_PARAM_SK_BLOB);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, key->secure_key,
						      key->secure_key_size)) {
		put_error_key(key, PS_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_octet_string failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, PS_PROV_PKEY_PARAM_SK_FUNCS);
	if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, key->funcs,
						   sizeof(struct ps_funcs))) {
		put_error_key(key, PS_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_octet_ptr failed");
		return 0;
	}
	p = OSSL_PARAM_locate(params, PS_PROV_PKEY_PARAM_SK_PRIVATE);
	if (p != NULL && !OSSL_PARAM_set_octet_ptr(p, key->private, 0)) {
		put_error_key(key, PS_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_set_octet_ptr failed");
		return 0;
	}

	return 1;
}


static int ps_keymgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_set_params_fn *default_set_params_fn;
	struct ps_key *key = vkey;
	const OSSL_PARAM *p;
	size_t len;

	if (key == NULL)
		return 0;

	ps_key_debug(key, "key: %p", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_key_debug(key, "param: %s",  p->key);

	default_set_params_fn = (OSSL_FUNC_keymgmt_set_params_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
				key->type, OSSL_FUNC_KEYMGMT_SET_PARAMS,
				&key->pctx->dbg);

	/* default_set_params_fn is optional */
	if (default_set_params_fn != NULL) {
		if (!default_set_params_fn(key->fwd_key, params)) {
			put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				      "default_set_params_fn failed");
			return 0;
		}
	}

	if (key->secure_key == NULL)
		return 1;

	p = OSSL_PARAM_locate_const(params, PS_PROV_PKEY_PARAM_SK_FUNCS);
	if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p,
				(const void **)&key->funcs, &len)) {
		put_error_key(key, PS_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_get_octet_string_ptr failed");
		return 0;
	}

	p = OSSL_PARAM_locate_const(params, PS_PROV_PKEY_PARAM_SK_PRIVATE);
	if (p != NULL && !OSSL_PARAM_get_octet_string_ptr(p,
				(const void **)&key->private, &len)) {
		put_error_key(key, PS_ERR_INTERNAL_ERROR,
			      "OSSL_PARAM_get_octet_string_ptr failed");
		return 0;
	}

	return 1;
}

#define PS_SECURE_KEY_FUNC_PARMS					\
	OSSL_PARAM_octet_ptr(PS_PROV_PKEY_PARAM_SK_FUNCS, NULL, 0),	\
	OSSL_PARAM_octet_ptr(PS_PROV_PKEY_PARAM_SK_PRIVATE, NULL, 0)

#define PS_SECURE_KEY_PARMS					\
	OSSL_PARAM_octet_string(PS_PROV_PKEY_PARAM_SK_BLOB, NULL, 0),	\
	PS_SECURE_KEY_FUNC_PARMS

static const OSSL_PARAM *ps_keymgmt_gettable_params(
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_keymgmt_gettable_params_fn *fwd_gettable_params_fn;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	fwd_gettable_params_fn = (OSSL_FUNC_keymgmt_gettable_params_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, pkey_type,
				     OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
				     &pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (fwd_gettable_params_fn != NULL)
		return fwd_gettable_params_fn(pctx->fwd.ctx);
}

static const OSSL_PARAM *ps_keymgmt_settable_params(
				struct provider_ctx *pctx, int pkey_type)
{
	OSSL_FUNC_keymgmt_settable_params_fn *default_settable_params_fn;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	default_settable_params_fn = (OSSL_FUNC_keymgmt_settable_params_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, pkey_type,
				     OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
				     &pctx->dbg);

	/* default_settable_params_fn is optional */
	if (default_settable_params_fn != NULL)
		return default_settable_params_fn(pctx->fwd.ctx);
}

static int ps_keymgmt_has(const void *vkey, int selection)
{
	OSSL_FUNC_keymgmt_has_fn *fwd_has_fn;
	const struct ps_key *key = vkey;
	int default_selection = selection;

	if (key == NULL)
		return 0;

	ps_key_debug(key, "key: %p selection: %x", key,
		     selection);

	fwd_has_fn = (OSSL_FUNC_keymgmt_has_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd, key->type,
				     OSSL_FUNC_KEYMGMT_HAS, &key->pctx->dbg);

	if (!fwd_has_fn) {
		put_error_key(key,
			      PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no fwd_has_fn");
		return 0;
	}

	/* A secure key doesn't have the private parts in the default key */
	if (key->secure_key != NULL)
		default_selection &= (~OSSL_KEYMGMT_SELECT_PRIVATE_KEY);

	return fwd_has_fn(key->fwd_key, default_selection);
}

struct ps_export_cb {
	struct ps_key *key;
	OSSL_CALLBACK *param_callback;
	void *cbarg;
};

static int ps_keymgmt_export_cb(const OSSL_PARAM params[], void *arg)
{
	return 0;
}

static int ps_keymgmt_export(void *vkey, int selection,
				  OSSL_CALLBACK *param_callback, void *cbarg)
{
	OSSL_FUNC_keymgmt_export_fn *default_export_fn;
	struct ps_export_cb cb_data;
	struct ps_key *key = vkey;

	if (key == NULL || param_callback == NULL)
		return 0;

	ps_key_debug(key, "key: %p selection: %x", key, selection);

	default_export_fn = (OSSL_FUNC_keymgmt_export_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
					key->type, OSSL_FUNC_KEYMGMT_EXPORT,
					&key->pctx->dbg);
	if (default_export_fn == NULL) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default export_fn");
		return 0;
	}

	if (key->secure_key == NULL ||
	    (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
		/*
		 * Clear key, or no private key selected, call default_export_fn
		 *  with original callback
		 */
		if (!default_export_fn(key->fwd_key, selection,
				       param_callback, cbarg)) {
			put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				      "default_export_fn failed");
			return 0;
		}
		return 1;
	}

	/* Let the callback add our 3 addl. params */
	cb_data.key = key;
	cb_data.param_callback = param_callback;
	cb_data.cbarg = cbarg;
	if (!default_export_fn(key->fwd_key, selection,
			       ps_keymgmt_export_cb, &cb_data)) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_export_fn failed");
		return 0;
	}

	return 1;
}

static int ps_keymgmt_import(void *vkey, int selection,
				  const OSSL_PARAM params[])
{
	const OSSL_PARAM *p_blob, *p_funcs, *p_private, *p;
	OSSL_FUNC_keymgmt_import_fn *default_import_fn;
	struct ps_key *key = vkey;
	size_t len;

	if (key == NULL)
		return 0;

	ps_key_debug(key, "key: %p selection: %x", key,
		     selection);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_key_debug(key, "param: %s", p->key);

	default_import_fn = (OSSL_FUNC_keymgmt_import_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
					key->type, OSSL_FUNC_KEYMGMT_IMPORT,
					&key->pctx->dbg);
	if (default_import_fn == NULL) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default import_fn");
		return 0;
	}

	if (!default_import_fn(key->fwd_key, selection, params)) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "default_import_fn failed");
		return 0;
	}

	if (key->secure_key != NULL)
		OPENSSL_free(key->secure_key);
	key->secure_key = NULL;
	key->secure_key_size = 0;
	key->funcs = NULL;
	key->private = NULL;

	p_blob = OSSL_PARAM_locate_const(params, PS_PROV_PKEY_PARAM_SK_BLOB);
	p_funcs = OSSL_PARAM_locate_const(params, PS_PROV_PKEY_PARAM_SK_FUNCS);
	p_private = OSSL_PARAM_locate_const(params,
					    PS_PROV_PKEY_PARAM_SK_PRIVATE);

	if (p_blob != NULL && p_funcs != NULL && p_private != NULL) {
		if (!OSSL_PARAM_get_octet_string(p_blob,
						 (void **)&key->secure_key, 0,
						 &key->secure_key_size)) {
			put_error_key(key, PS_ERR_INTERNAL_ERROR,
				      "OSSL_PARAM_get_octet_string failed");
			return 0;
		}

		if (!OSSL_PARAM_get_octet_string_ptr(p_funcs,
					(const void **)&key->funcs, &len)) {
			put_error_key(key, PS_ERR_INTERNAL_ERROR,
				      "OSSL_PARAM_get_octet_string_ptr failed");
			return 0;
		}

		if (!OSSL_PARAM_get_octet_string_ptr(p_private,
				(const void **)&key->private, &len)) {
			put_error_key(key, PS_ERR_INTERNAL_ERROR,
				      "OSSL_PARAM_get_octet_string_ptr failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *ps_keymgmt_export_types(int selection,
						      int pkey_type)
{
	OSSL_FUNC_keymgmt_export_types_fn *fwd_export_types_fn;
	struct provider_ctx *pctx;

	pctx = OSSL_PROVIDER_get0_provider_ctx(pkcs11sign_provider);
	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "selection: %d pkey_type: %d", selection,
		     pkey_type);

	fwd_export_types_fn =
		(OSSL_FUNC_keymgmt_export_types_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, pkey_type,
				     OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
				     &pctx->dbg);

	/* fwd_export_types_fn is optional */
	if (!fwd_export_types_fn)
		return NULL;

	return fwd_export_types_fn(selection);
}

static const OSSL_PARAM *ps_keymgmt_import_types(int selection,
						      int pkey_type)
{
	OSSL_FUNC_keymgmt_import_types_fn *fwd_import_types_fn;
	struct provider_ctx *pctx;

	pctx = OSSL_PROVIDER_get0_provider_ctx(pkcs11sign_provider);
	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "selection: %d pkey_type: %d", selection,
		     pkey_type);

	fwd_import_types_fn = (OSSL_FUNC_keymgmt_import_types_fn *)
			fwd_keymgmt_get_func(&pctx->fwd, pkey_type,
					     OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
					     &pctx->dbg);

	/* fwd_import_types_fn is optional */
	if (!fwd_import_types_fn)
		return NULL;

	return fwd_import_types_fn(selection);
}

static struct ps_op_ctx *ps_keymgmt_gen_init(
				struct provider_ctx *pctx, int selection,
				const OSSL_PARAM params[], int pkey_type)
{
	OSSL_FUNC_keymgmt_gen_cleanup_fn *fwd_gen_cleanup_fn;
	OSSL_FUNC_keymgmt_gen_init_fn *fwd_gen_init_fn;
	struct ps_op_ctx *genctx;
	const OSSL_PARAM *p;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "selection: %x type: %d", selection, pkey_type);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	fwd_gen_init_fn = (OSSL_FUNC_keymgmt_gen_init_fn *)
			fwd_keymgmt_get_func(&pctx->fwd, pkey_type,
					     OSSL_FUNC_KEYMGMT_GEN_INIT,
					     &pctx->dbg);
	if (!fwd_gen_init_fn) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default gen_init_fn");
		return NULL;
	}

	fwd_gen_cleanup_fn = (OSSL_FUNC_keymgmt_gen_cleanup_fn *)
			fwd_keymgmt_get_func(&pctx->fwd, pkey_type,
					     OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
					     &pctx->dbg);
	if (fwd_gen_cleanup_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default gen_cleanup_fn");
		return NULL;
	}

	genctx = ps_op_newctx(pctx, NULL, pkey_type);
	if (!genctx) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "ps_op_newctx failed");
		return NULL;
	}

	if (!ps_op_init(genctx, NULL, EVP_PKEY_OP_KEYGEN)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "ps_op_init failed");
		ps_op_freectx(genctx);
		return NULL;
	}

	genctx->fwd_op_ctx = fwd_gen_init_fn(pctx->fwd.ctx,
						     selection, params);
	if (genctx->fwd_op_ctx == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_gen_init_fn failed");
		ps_op_freectx(genctx);
		return NULL;
	}
	genctx->fwd_op_ctx_free = fwd_gen_cleanup_fn;

	ps_dbg_debug(&pctx->dbg, "genctx: %p", genctx);
	return genctx;
}

static void ps_keymgmt_gen_cleanup(void *vgenctx)
{
	struct ps_op_ctx *genctx = vgenctx;

	if (!genctx)
		return;

	ps_opctx_debug(genctx, "genctx: %p", genctx);
	ps_op_freectx(genctx);
}

static int ps_keymgmt_gen_set_params(void *vgenctx,
					  const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_gen_set_params_fn *default_gen_set_params_fn;
	struct ps_op_ctx *genctx = vgenctx;
	const OSSL_PARAM *p;

	if (!genctx)
		return 0;

	ps_opctx_debug(genctx, "genctx: %p", genctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(genctx, "param: %s", p->key);

	default_gen_set_params_fn = (OSSL_FUNC_keymgmt_gen_set_params_fn *)
			fwd_keymgmt_get_func(&genctx->pctx->fwd,
				genctx->type, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
				&genctx->pctx->dbg);

	/* default_gen_set_params_fn is optional */
	if (default_gen_set_params_fn != NULL) {
		if (!default_gen_set_params_fn(genctx->fwd_op_ctx,
					       params)) {
			put_error_op_ctx(genctx,
					 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "default_gen_set_params_fn failed");
			return 0;
		}
	}

	return 1;
}

static const OSSL_PARAM *ps_keymgmt_gen_settable_params(
					struct ps_op_ctx *genctx,
					struct provider_ctx *pctx,
					int pkey_type)
{
	OSSL_FUNC_keymgmt_gen_settable_params_fn
						*default_gen_settable_params_fn;
	const OSSL_PARAM *params = NULL, *p;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pkey_type: %d", pkey_type);

	default_gen_settable_params_fn =
		(OSSL_FUNC_keymgmt_gen_settable_params_fn *)
			fwd_keymgmt_get_func(&pctx->fwd,
				pkey_type,
				OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
				&pctx->dbg);

	/* default_gen_settable_params_fn is optional */
	if (default_gen_settable_params_fn != NULL)
		params = default_gen_settable_params_fn(genctx->fwd_op_ctx,
						   pctx->fwd.ctx);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_dbg_debug(&pctx->dbg, "param: %s", p->key);

	return params;
}

static int ps_keymgmt_gen_set_template(void *vgenctx, void *vtempl)
{
	OSSL_FUNC_keymgmt_gen_set_template_fn *default_gen_set_template_fn;
	struct ps_op_ctx *genctx = vgenctx;
	struct ps_key *templ = vtempl;

	if (!genctx || !templ)
		return 0;

	ps_opctx_debug(genctx, "genctx: %p templ: %p", genctx, templ);

	default_gen_set_template_fn = (OSSL_FUNC_keymgmt_gen_set_template_fn *)
			fwd_keymgmt_get_func(&genctx->pctx->fwd,
					genctx->type,
					OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
					&genctx->pctx->dbg);

	if (!default_gen_set_template_fn) {
		put_error_op_ctx(genctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default get_set_template_fn");
		return 0;
	}

	return default_gen_set_template_fn(genctx->fwd_op_ctx,
					   templ->fwd_key);
}

static void *ps_keymgmt_gen(void *vgenctx,
				 OSSL_CALLBACK *osslcb, void *cbarg)
{
	OSSL_FUNC_keymgmt_gen_fn *default_gen_fn;
	struct ps_op_ctx *genctx = vgenctx;
	struct ps_key *key;

	if (!genctx)
		return NULL;

	ps_opctx_debug(genctx, "genctx: %p", genctx);

	default_gen_fn = (OSSL_FUNC_keymgmt_gen_fn *)
			fwd_keymgmt_get_func(&genctx->pctx->fwd,
					genctx->type, OSSL_FUNC_KEYMGMT_GEN,
					&genctx->pctx->dbg);

	if (!default_gen_fn) {
		put_error_op_ctx(genctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default gen_fn");
		return NULL;
	}

	key = OPENSSL_zalloc(sizeof(struct ps_key));
	if (!key) {
		put_error_op_ctx(genctx, PS_ERR_MALLOC_FAILED,
				 "OPENSSL_zalloc failed");
		return NULL;
	}

	key->pctx = genctx->pctx;
	key->type = genctx->type;

	key->fwd_key = default_gen_fn(genctx->fwd_op_ctx,
					  osslcb, cbarg);
	if (!key->fwd_key) {
		put_error_op_ctx(genctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_gen_fn failed");
		OPENSSL_free(key);
		return NULL;
	}

	ps_keymgmt_upref(key);

	ps_opctx_debug(genctx, "key: %p", key);

	return key;
}

static void *ps_keymgmt_load(const void *reference, size_t reference_sz)
{
	struct ps_key *key;

	if (!reference)
		return NULL;

	if (reference_sz == sizeof(struct ps_key)) {
		/* The contents of the reference is the address to our object */
		key = *(struct ps_key **)reference;

		/* We grabbed, so we detach it */
		*(struct ps_key **)reference = NULL;
		return key;
	}

	return NULL;
}

static int ps_keymgmt_get_size(struct ps_key *key)
{
	int size = 0;
	OSSL_PARAM key_params[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, &size),
		OSSL_PARAM_END
	};

	ps_key_debug(key, "key: %p", key);

	if (!ps_keymgmt_get_params(key, key_params) ||
	    !OSSL_PARAM_modified(&key_params[0]) ||
	    size <= 0) {
		put_error_key(key, PS_ERR_MISSING_PARAMETER,
				 "ps_keymgmt_get_params failed to "
				 "get OSSL_PKEY_PARAM_MAX_SIZE");
		return -1;
	}

	ps_key_debug(key, "size: %d", size);
	return size;
}

static int ps_keymgmt_get_bits(struct ps_key *key)
{
	int bits = 0;
	OSSL_PARAM key_params[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, &bits),
		OSSL_PARAM_END
	};

	ps_key_debug(key, "key: %p", key);

	if (!ps_keymgmt_get_params(key, key_params) ||
	    !OSSL_PARAM_modified(&key_params[0]) ||
	    bits <= 0) {
		put_error_key(key, PS_ERR_MISSING_PARAMETER,
				 "ps_keymgmt_get_params failed to "
				 "get OSSL_PKEY_PARAM_BITS");
		return -1;
	}

	ps_key_debug(key, "bits: %d", bits);
	return bits;
}

static void *ps_keymgmt_rsa_new(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

	return ps_keymgmt_new(pctx, EVP_PKEY_RSA);
}

static const char *ps_keymgmt_rsa_query_operation_name(int operation_id)
{
	switch (operation_id) {
	case OSSL_OP_SIGNATURE:
	case OSSL_OP_ASYM_CIPHER:
		return "RSA";
	}

	return NULL;
}

static const OSSL_PARAM *ps_keymgmt_rsa_gettable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gettable_params(pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_settable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_settable_params(pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_export_types(int selection)
{
	return ps_keymgmt_export_types(selection, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_import_types(int selection)
{
	return ps_keymgmt_import_types(selection, EVP_PKEY_RSA);
}

static void *ps_keymgmt_rsa_gen_init(void *vprovctx, int selection,
					  const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_init(pctx, selection, params,
					EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_gen_settable_params(void *vgenctx,
								 void *vprovctx)
{
	struct ps_op_ctx *genctx = vgenctx;
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_settable_params(genctx, pctx,
						   EVP_PKEY_RSA);
}

static void *ps_keymgmt_rsa_pss_new(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_new(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsa_pss_gettable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gettable_params(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsa_pss_settable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_settable_params(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsa_pss_export_types(int selection)
{
	return ps_keymgmt_export_types(selection, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsa_pss_import_types(int selection)
{
	return ps_keymgmt_import_types(selection, EVP_PKEY_RSA_PSS);
}

static void *ps_keymgmt_rsa_pss_gen_init(void *vpctx, int selection,
					      const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_init(pctx, selection, params,
					EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsa_pss_gen_settable_params(
								void *vgenctx,
								void *vpctx)
{
	struct ps_op_ctx *genctx = vgenctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_settable_params(genctx, pctx,
						   EVP_PKEY_RSA_PSS);
}

static void *ps_keymgmt_ec_new(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_new(pctx, EVP_PKEY_EC);
}

static const char *ps_keymgmt_ec_query_operation_name(int operation_id)
{
	switch (operation_id) {
	case OSSL_OP_KEYEXCH:
		return "ECDH";
	case OSSL_OP_SIGNATURE:
		return "ECDSA";
	}

	return NULL;
}

static const OSSL_PARAM *ps_keymgmt_ec_gettable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gettable_params(pctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_settable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_settable_params(pctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_export_types(int selection)
{
	return ps_keymgmt_export_types(selection, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_import_types(int selection)
{
	return ps_keymgmt_import_types(selection, EVP_PKEY_EC);
}

static void *ps_keymgmt_ec_gen_init(void *vpctx, int selection,
					 const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_init(pctx, selection, params,
					EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_gen_settable_params(void *vopctx,
								void *vpctx)
{
	struct ps_op_ctx *genctx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_settable_params(genctx, pctx,
						   EVP_PKEY_EC);
}

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
	struct ps_key *key = vkey;
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
	struct ps_key *peerkey = vpeerkey;
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

		rc = funcs->rsa_decrypt_oaep(key->secure_key,
					     key->secure_key_size,
					     out, outlen, in, inlen,
					     EVP_MD_type(oaep_md),
					     EVP_MD_type(mgf_md),
					     oaep_label, oaep_label_len,
					     key->private,
					     ps_dbg_enabled(&ctx->pctx->dbg));
		break;

	default:
		if (funcs->rsa_decrypt == NULL) {
			put_error_op_ctx(ctx, PS_ERR_MISSING_PARAMETER,
					 "no secure key decrypt function");
			rc = 0;
			goto out;
		}

		rc = funcs->rsa_decrypt(key->secure_key, key->secure_key_size,
					out, outlen, in, inlen, pad_mode,
					key->private,
					ps_dbg_enabled(&ctx->pctx->dbg));
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

static void *ps_signature_rsa_newctx(void *vprovctx, const char *propq)
{
	struct provider_ctx *pctx = vprovctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p propq: %s", pctx,
		     propq != NULL ? propq : "");
	return ps_signature_op_newctx(pctx, propq, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_gettable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct ps_op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_signature_op_gettable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_settable_ctx_params(void *vctx,
							      void *vpctx)
{
	struct provider_ctx *pctx = vpctx;
	struct ps_op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_signature_op_settable_ctx_params(opctx, pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_gettable_ctx_md_params(void *vctx)
{
	struct ps_op_ctx *opctx = vctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_gettable_ctx_md_params(opctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_settable_ctx_md_params(void *vctx)
{
	struct ps_op_ctx *opctx = vctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_settable_ctx_md_params(opctx, EVP_PKEY_RSA);
}

static int ps_signature_rsa_sign(void *vopctx,
				 unsigned char *sig, size_t *siglen,
				 size_t sigsize,
				 const unsigned char *tbs, size_t tbslen)
{
	EVP_MD *sign_md = NULL, *mgf_md = NULL;
	int rsa_size, pad_mode, salt_len, rc;
	struct ps_op_ctx *opctx = vopctx;
	struct ps_key *key;
	struct ps_funcs *funcs;

	if (opctx == NULL || siglen == NULL || tbs == NULL)
		return 0;

	ps_opctx_debug(opctx, "opctx: %p key: %p tbslen: %lu sigsize: %lu",
			opctx, opctx->key, tbslen, sigsize);

	if (opctx->key == NULL || opctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "sign operation not initialized");
		return 0;
	}

	/* For clear key, let the default provider handle it */
	if (opctx->key->secure_key == NULL)
		return ps_signature_op_sign(opctx, sig, siglen, sigsize,
					    tbs, tbslen);

	key = opctx->key;

	rsa_size = ps_keymgmt_get_size(key);
	if (rsa_size <= 0) {
		ps_opctx_debug(opctx, "ERROR: ps_keymgmt_get_size failed");
		return 0;
	}

	if (sig == NULL) {
		*siglen = rsa_size;
		ps_opctx_debug(opctx, "siglen: %lu", *siglen);
		return 1;
	}

	if (sigsize < (size_t)rsa_size) {
		put_error_op_ctx(opctx, PS_ERR_INVALID_PARAM,
				 "signature length invalid");
		return 0;
	}

	funcs = opctx->key->funcs;
	if (funcs == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
				 "no secure key funcs");
		return 0;
	}

	sign_md = ps_signature_op_get_md(opctx);
	pad_mode = ps_signature_op_get_padding(opctx);

	if (sign_md == NULL) {
		/* Sign without a signature digest, fall back to no padding */
		pad_mode = RSA_NO_PADDING;
	} else {
		if (tbslen != (size_t)EVP_MD_size(sign_md)) {
			put_error_op_ctx(opctx, PS_ERR_INVALID_PARAM,
					 "tbslen must be size of digest");
			rc = 0;
			goto out;
		}
	}

	*siglen = rsa_size;

	switch (pad_mode) {
	case RSA_PKCS1_PADDING:
	case RSA_X931_PADDING:
		if (sign_md == NULL) {
			put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
					 "padding needs a signature digest");
			rc = 0;
			goto out;
		}
		/* fall through */

	case RSA_NO_PADDING:
		if (funcs->rsa_sign == NULL) {
			put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
					 "no secure key sign function");
			rc = 0;
			goto out;

		}

		rc = funcs->rsa_sign(key->secure_key, key->secure_key_size,
				     sig, siglen, tbs, tbslen, pad_mode,
				     sign_md != NULL ?
					EVP_MD_type(sign_md) : NID_undef,
				     key->private,
				     ps_dbg_enabled(&opctx->pctx->dbg));
		break;

	case RSA_PKCS1_PSS_PADDING:
		if (sign_md == NULL) {
			put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
					 "PSS padding needs a signature digest");
			rc = 0;
			goto out;
		}

		mgf_md = ps_signature_op_get_mgf_md(opctx);
		if (mgf_md == NULL) {
			ps_opctx_debug(opctx,
				"ERROR ps_signature_op_get_mgf_md failed");
			rc = 0;
			goto out;
		}

		salt_len = ps_signature_op_get_pss_saltlen(opctx, key, mgf_md);
		if (salt_len < 0) {
			ps_opctx_debug(opctx,
				"ERROR: ps_signature_op_get_pss_saltlen failed");
			rc = 0;
			goto out;
		}

		if (funcs->rsa_pss_sign == NULL) {
			put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
					 "no secure key sign function");
			rc = 0;
			goto out;
		}

		rc = funcs->rsa_pss_sign(key->secure_key, key->secure_key_size,
					 sig, siglen, tbs, tbslen,
					 EVP_MD_type(sign_md),
					 EVP_MD_type(mgf_md),
					 salt_len, key->private,
					 ps_dbg_enabled(&opctx->pctx->dbg));
		break;
	default:
		put_error_op_ctx(opctx, PS_ERR_INVALID_PADDING,
				 "unknown/unsupported padding: %d", pad_mode);
		rc = 0;
		goto out;
	}

	if (rc != 0) {
		put_error_op_ctx(opctx, PS_ERR_SECURE_KEY_FUNC_FAILED,
				 "Secure key sign operation failed: rc: %d",
				 rc);
		rc = 0;
		goto out;
	}

	rc = 1;

	ps_opctx_debug(opctx, "siglen: %lu", *siglen);

out:
	if (sign_md != NULL)
		EVP_MD_free(sign_md);
	if (mgf_md != NULL)
		EVP_MD_free(mgf_md);

	return rc;
}

static int ps_signature_rsa_digest_sign_init(void *vopctx,
					     const char *mdname,
					     void *vkey,
					     const OSSL_PARAM params[])
{
	struct ps_op_ctx *opctx = vopctx;
	struct ps_key *key = vkey;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p", opctx,
			mdname != NULL ? mdname : "", key);
	return ps_signature_op_digest_sign_init(opctx, mdname, key, params,
						ps_signature_rsa_sign);
}

static void *ps_signature_ec_newctx(void *vpctx, const char *propq)
{
	struct provider_ctx *pctx = vpctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p propq: %s", pctx,
		     propq != NULL ? propq : "");
	return ps_signature_op_newctx(pctx, propq, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_gettable_ctx_params(void *vopctx,
							     void *vpctx)
{
	struct ps_op_ctx *opctx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_signature_op_gettable_ctx_params(opctx, pctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_settable_ctx_params(void *vopctx,
							     void *vpctx)
{
	struct ps_op_ctx *opctx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_signature_op_settable_ctx_params(opctx, pctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_gettable_ctx_md_params(void *vopctx)
{
	struct ps_op_ctx *opctx = vopctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_gettable_ctx_md_params(opctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_settable_ctx_md_params(void *vopctx)
{
	struct ps_op_ctx *opctx = vopctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_settable_ctx_md_params(opctx, EVP_PKEY_EC);
}

static int ps_signature_ec_sign(void *vopctx,
				unsigned char *sig, size_t *siglen,
				size_t sigsize,
				const unsigned char *tbs, size_t tbslen)
{
	struct ps_op_ctx *opctx = vopctx;
	struct ps_key *key;
	EVP_MD *sign_md = NULL;
	struct ps_funcs *funcs;
	int ec_size, rc;

	if (opctx == NULL || siglen == NULL || tbs == NULL)
		return 0;

	ps_opctx_debug(opctx, "opctx: %p key: %p tbslen: %lu sigsize: %lu",
			opctx, opctx->key, tbslen, sigsize);

	if (opctx->key == NULL || opctx->operation != EVP_PKEY_OP_SIGN) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "sign operation not initialized");
		return 0;
	}

	/* For clear key, let the default provider handle it */
	if (opctx->key->secure_key == NULL)
		return ps_signature_op_sign(opctx, sig, siglen, sigsize,
					    tbs, tbslen);

	key = opctx->key;

	ec_size = ps_keymgmt_get_size(key);
	if (ec_size <= 0) {
		ps_opctx_debug(opctx, "ERROR: ps_keymgmt_get_size failed");
		return 0;
	}

	if (sig == NULL) {
		*siglen = ec_size;
		ps_opctx_debug(opctx, "siglen: %lu", *siglen);
		return 1;
	}

	if (sigsize < (size_t)ec_size) {
		put_error_op_ctx(opctx, PS_ERR_INVALID_PARAM,
				 "signature length invalid");
		return 0;
	}

	funcs = opctx->key->funcs;
	if (funcs == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
				 "no secure key funcs");
		return 0;
	}

	sign_md = ps_signature_op_get_md(opctx);
	if (sign_md == NULL) {
		ps_opctx_debug(opctx, "ERROR: ps_signature_op_get_md failed");
		return 0;
	}

	if (tbslen != (size_t)EVP_MD_size(sign_md)) {
		put_error_op_ctx(opctx, PS_ERR_INVALID_PARAM,
				 "tbslen must be size of digest");
		rc = 0;
		goto out;
	}

	*siglen = ec_size;

	if (funcs->ecdsa_sign == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
				 "no secure key sign function");
		rc = 0;
		goto out;
	}

	rc = funcs->ecdsa_sign(key->secure_key, key->secure_key_size,
				 sig, siglen, tbs, tbslen,
				 EVP_MD_type(sign_md), key->private,
				 ps_dbg_enabled(&opctx->pctx->dbg));
	if (rc != 0) {
		put_error_op_ctx(opctx, PS_ERR_SECURE_KEY_FUNC_FAILED,
				 "Secure key sign operation failed: rc: %d",
				 rc);
		rc = 0;
		goto out;
	}

	rc = 1;

	ps_opctx_debug(opctx, "siglen: %lu", *siglen);

out:
	if (sign_md != NULL)
		EVP_MD_free(sign_md);

	return rc;
}

static int ps_signature_ec_digest_sign_init(void *vopctx,
					    const char *mdname,
					    void *vkey,
					    const OSSL_PARAM params[])
{
	struct ps_op_ctx *opctx = vopctx;
	struct ps_key *key = vkey;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p", opctx,
			mdname != NULL ? mdname : "", key);
	return ps_signature_op_digest_sign_init(opctx, mdname, key, params,
						ps_signature_ec_sign);
}

static const OSSL_DISPATCH ps_rsa_signature_functions[] = {
	/* Signature context constructor, descructor */
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ps_signature_rsa_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ps_op_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ps_signature_op_dupctx },
	/* Signing */
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT,
			(void (*)(void))ps_signature_op_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ps_signature_rsa_sign },
	/* Verifying */
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT,
			(void (*)(void))ps_signature_op_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ps_signature_op_verify },
	/* Verify recover */
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
			(void (*)(void))ps_signature_op_verify_recover_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
			(void (*)(void))ps_signature_op_verify_recover },
	/* Digest Sign */
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
			(void (*)(void))ps_signature_rsa_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
			(void (*)(void))ps_signature_op_digest_sign_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
			(void (*)(void))ps_signature_op_digest_sign_final },
	/* Digest Verify */
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
			(void (*)(void))ps_signature_op_digest_verify_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
			(void (*)(void))ps_signature_op_digest_verify_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
			(void (*)(void))ps_signature_op_digest_verify_final },
	/* Signature parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
			(void (*)(void))ps_signature_op_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
			(void (*)(void))ps_signature_rsa_gettable_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void
			(*)(void))ps_signature_op_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
			(void (*)(void))ps_signature_rsa_settable_ctx_params },
	/* MD parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
			(void (*)(void))ps_signature_op_get_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
		(void (*)(void))ps_signature_rsa_gettable_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
			(void (*)(void))ps_signature_op_set_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
		(void (*)(void))ps_signature_rsa_settable_ctx_md_params },
	{ 0, NULL }
};

static const OSSL_DISPATCH ps_ecdsa_signature_functions[] = {
	/* Signature context constructor, descructor */
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ps_signature_ec_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ps_op_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ps_signature_op_dupctx },
	/* Signing */
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT,
			(void (*)(void))ps_signature_op_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ps_signature_ec_sign },
	/* Verifying */
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT,
			(void (*)(void))ps_signature_op_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ps_signature_op_verify },
	/* Verify recover */
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
			(void (*)(void))ps_signature_op_verify_recover_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
			(void (*)(void))ps_signature_op_verify_recover },
	/* Digest Sign */
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
			(void (*)(void))ps_signature_ec_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
			(void (*)(void))ps_signature_op_digest_sign_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
			(void (*)(void))ps_signature_op_digest_sign_final },
	/* Digest Verify */
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
			(void (*)(void))ps_signature_op_digest_verify_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
			(void (*)(void))ps_signature_op_digest_verify_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
			(void (*)(void))ps_signature_op_digest_verify_final },
	/* Signature parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
			(void (*)(void))ps_signature_op_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
			(void (*)(void))ps_signature_ec_gettable_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void
			(*)(void))ps_signature_op_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
			(void (*)(void))ps_signature_ec_settable_ctx_params },
	/* MD parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
			(void (*)(void))ps_signature_op_get_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
		(void (*)(void))ps_signature_ec_gettable_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
			(void (*)(void))ps_signature_op_set_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
		(void (*)(void))ps_signature_ec_settable_ctx_md_params },
	{ 0, NULL }
};

static const OSSL_ALGORITHM ps_signature[] = {
	{ "RSA:rsaEncryption", "provider="PS_PROV_NAME,
				ps_rsa_signature_functions, NULL },
	{ "ECDSA", "provider="PS_PROV_NAME,
				ps_ecdsa_signature_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_DISPATCH ps_rsa_asym_cipher_functions[] = {
	/* RSA context constructor, descructor */
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX,
			(void (*)(void))ps_asym_rsa_newctx },
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))ps_op_freectx },
	{ OSSL_FUNC_ASYM_CIPHER_DUPCTX,
			(void (*)(void))ps_asym_op_dupctx },
	/* RSA context set/get parameters */
	{ OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
			(void (*)(void))ps_asym_op_get_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
			(void (*)(void))ps_asym_rsa_gettable_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
			(void (*)(void))ps_asym_op_set_ctx_params },
	{ OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
			(void (*)(void))ps_asym_rsa_settable_ctx_params },
	/* RSA encrypt */
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
			(void (*)(void))ps_asym_op_encrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
			(void (*)(void))ps_asym_op_encrypt },
	/* RSA decrypt */
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
			(void (*)(void))ps_asym_op_decrypt_init },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT,
			(void (*)(void))ps_asym_rsa_decrypt },
	{ 0, NULL }
};

static const OSSL_ALGORITHM ps_asym_cipher[] = {
	{ "RSA:rsaEncryption", "provider="PS_PROV_NAME,
				ps_rsa_asym_cipher_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};


#define DISPATCH_KEYMGMT_ELEM(NAME, name) \
	{ OSSL_FUNC_KEYMGMT_##NAME, (void (*)(void))name }

static const OSSL_DISPATCH ps_rsa_keymgmt_functions[] = {
	/* Constructor, destructor */
	DISPATCH_KEYMGMT_ELEM(NEW, ps_keymgmt_rsa_new),
	DISPATCH_KEYMGMT_ELEM(FREE, ps_keymgmt_free),

	/* Key generation and loading */
	DISPATCH_KEYMGMT_ELEM(GEN_INIT, ps_keymgmt_rsa_gen_init),
	DISPATCH_KEYMGMT_ELEM(GEN_SET_TEMPLATE, ps_keymgmt_gen_set_template),
	DISPATCH_KEYMGMT_ELEM(GEN_SET_PARAMS, ps_keymgmt_gen_set_params),
	DISPATCH_KEYMGMT_ELEM(GEN_SETTABLE_PARAMS,
			      ps_keymgmt_rsa_gen_settable_params),
	DISPATCH_KEYMGMT_ELEM(GEN, ps_keymgmt_gen),
	DISPATCH_KEYMGMT_ELEM(GEN_CLEANUP, ps_keymgmt_gen_cleanup),
	DISPATCH_KEYMGMT_ELEM(LOAD, ps_keymgmt_load),

	/* Key object checking */
	DISPATCH_KEYMGMT_ELEM(HAS, ps_keymgmt_has),
	DISPATCH_KEYMGMT_ELEM(MATCH, ps_keymgmt_match),
	DISPATCH_KEYMGMT_ELEM(VALIDATE, ps_keymgmt_validate),
	DISPATCH_KEYMGMT_ELEM(QUERY_OPERATION_NAME,
			      ps_keymgmt_rsa_query_operation_name),

	/* Key object information */
	DISPATCH_KEYMGMT_ELEM(GET_PARAMS, ps_keymgmt_get_params),
	DISPATCH_KEYMGMT_ELEM(GETTABLE_PARAMS, ps_keymgmt_rsa_gettable_params),
	DISPATCH_KEYMGMT_ELEM(SET_PARAMS, ps_keymgmt_set_params),
	DISPATCH_KEYMGMT_ELEM(SETTABLE_PARAMS, ps_keymgmt_rsa_settable_params),

	/* Import and export routines */
	DISPATCH_KEYMGMT_ELEM(EXPORT, ps_keymgmt_export),
	DISPATCH_KEYMGMT_ELEM(EXPORT_TYPES, ps_keymgmt_rsa_export_types),
	DISPATCH_KEYMGMT_ELEM(IMPORT, ps_keymgmt_import),
	DISPATCH_KEYMGMT_ELEM(IMPORT_TYPES, ps_keymgmt_rsa_import_types),
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

static const OSSL_DISPATCH ps_rsapss_keymgmt_functions[] = {
	/* Constructor, destructor */
	DISPATCH_KEYMGMT_ELEM(NEW, ps_keymgmt_rsa_pss_new),
	DISPATCH_KEYMGMT_ELEM(FREE, ps_keymgmt_free),

	/* Key generation and loading */
	DISPATCH_KEYMGMT_ELEM(GEN_INIT, ps_keymgmt_rsa_pss_gen_init),
	DISPATCH_KEYMGMT_ELEM(GEN_SET_TEMPLATE, ps_keymgmt_gen_set_template),
	DISPATCH_KEYMGMT_ELEM(GEN_SET_PARAMS, ps_keymgmt_gen_set_params),
	DISPATCH_KEYMGMT_ELEM(GEN_SETTABLE_PARAMS,
			      ps_keymgmt_rsa_pss_gen_settable_params),
	DISPATCH_KEYMGMT_ELEM(GEN, ps_keymgmt_gen),
	DISPATCH_KEYMGMT_ELEM(GEN_CLEANUP, ps_keymgmt_gen_cleanup),
	DISPATCH_KEYMGMT_ELEM(LOAD, ps_keymgmt_load),

	/* Key object checking */
	DISPATCH_KEYMGMT_ELEM(HAS, ps_keymgmt_has),
	DISPATCH_KEYMGMT_ELEM(MATCH, ps_keymgmt_match),
	DISPATCH_KEYMGMT_ELEM(VALIDATE, ps_keymgmt_validate),
	DISPATCH_KEYMGMT_ELEM(QUERY_OPERATION_NAME,
			      ps_keymgmt_rsa_query_operation_name),

	/* Key object information */
	DISPATCH_KEYMGMT_ELEM(GET_PARAMS, ps_keymgmt_get_params),
	DISPATCH_KEYMGMT_ELEM(GETTABLE_PARAMS,
			      ps_keymgmt_rsa_pss_gettable_params),
	DISPATCH_KEYMGMT_ELEM(SET_PARAMS, ps_keymgmt_set_params),
	DISPATCH_KEYMGMT_ELEM(SETTABLE_PARAMS,
			      ps_keymgmt_rsa_pss_settable_params),

	/* Import and export routines */
	DISPATCH_KEYMGMT_ELEM(EXPORT, ps_keymgmt_export),
	DISPATCH_KEYMGMT_ELEM(EXPORT_TYPES, ps_keymgmt_rsa_pss_export_types),
	DISPATCH_KEYMGMT_ELEM(IMPORT, ps_keymgmt_import),
	DISPATCH_KEYMGMT_ELEM(IMPORT_TYPES, ps_keymgmt_rsa_pss_import_types),
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

static const OSSL_DISPATCH ps_ec_keymgmt_functions[] = {
	/* Constructor, destructor */
	DISPATCH_KEYMGMT_ELEM(NEW, ps_keymgmt_ec_new),
	DISPATCH_KEYMGMT_ELEM(FREE, ps_keymgmt_free),

	/* Key generation and loading */
	DISPATCH_KEYMGMT_ELEM(GEN_INIT, ps_keymgmt_ec_gen_init),
	DISPATCH_KEYMGMT_ELEM(GEN_SET_TEMPLATE, ps_keymgmt_gen_set_template),
	DISPATCH_KEYMGMT_ELEM(GEN_SET_PARAMS, ps_keymgmt_gen_set_params),
	DISPATCH_KEYMGMT_ELEM(GEN_SETTABLE_PARAMS,
			      ps_keymgmt_ec_gen_settable_params),
	DISPATCH_KEYMGMT_ELEM(GEN, ps_keymgmt_gen),
	DISPATCH_KEYMGMT_ELEM(GEN_CLEANUP, ps_keymgmt_gen_cleanup),
	DISPATCH_KEYMGMT_ELEM(LOAD, ps_keymgmt_load),

	/* Key object checking */
	DISPATCH_KEYMGMT_ELEM(HAS, ps_keymgmt_has),
	DISPATCH_KEYMGMT_ELEM(MATCH, ps_keymgmt_match),
	DISPATCH_KEYMGMT_ELEM(VALIDATE, ps_keymgmt_validate),
	DISPATCH_KEYMGMT_ELEM(QUERY_OPERATION_NAME,
			      ps_keymgmt_ec_query_operation_name),

	/* Key object information */
	DISPATCH_KEYMGMT_ELEM(GET_PARAMS, ps_keymgmt_get_params),
	DISPATCH_KEYMGMT_ELEM(GETTABLE_PARAMS, ps_keymgmt_ec_gettable_params),
	DISPATCH_KEYMGMT_ELEM(SET_PARAMS, ps_keymgmt_set_params),
	DISPATCH_KEYMGMT_ELEM(SETTABLE_PARAMS, ps_keymgmt_ec_settable_params),

	/* Import and export routines */
	DISPATCH_KEYMGMT_ELEM(EXPORT, ps_keymgmt_export),
	DISPATCH_KEYMGMT_ELEM(EXPORT_TYPES, ps_keymgmt_ec_export_types),
	DISPATCH_KEYMGMT_ELEM(IMPORT, ps_keymgmt_import),
	DISPATCH_KEYMGMT_ELEM(IMPORT_TYPES, ps_keymgmt_ec_import_types),
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

static const OSSL_ALGORITHM ps_keymgmt[] = {
	{ "RSA:rsaEncryption", "provider="PS_PROV_NAME,
				ps_rsa_keymgmt_functions, NULL },
	{ "RSA-PSS:RSASSA-PSS", "provider="PS_PROV_NAME,
				ps_rsapss_keymgmt_functions, NULL },
	{ "EC:id-ecPublicKey", "provider="PS_PROV_NAME,
				ps_ec_keymgmt_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

// keep (deep)
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

// keep (deep)
/*
 * Although ECDH key derivation is not supported for secure keys (would result
 * in a secure symmetric key, which OpenSSL can't handle), the provider still
 * must implement the ECDH key exchange functions and proxy them all to the
 * default provider. OpenSSL common code requires that the key management
 * provider and the key exchange provider for a derive operation is the same.
 * So for clear EC keys created with this provider, we do support the ECDH
 * operation by forwarding it to the configured provider.
 */
static const OSSL_ALGORITHM ps_keyexch[] = {
	{ "ECDH", "provider="PS_PROV_NAME, ps_ec_keyexch_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

// keep
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

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_prov_param_types;
}

static int ps_prov_get_params(void *vpctx, OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;
	OSSL_PARAM *p;

	if (pctx == NULL)
		return 0;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

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

	ps_dbg_debug(&pctx->dbg, "pctx: %p operation_id: %d", pctx, operation_id);

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

	provider_ctx_free(pctx);
}

static const OSSL_ITEM *ps_prov_get_reason_strings(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_prov_reason_strings;
}

static int ps_prov_get_capabilities(void *vpctx,
				    const char *capability, OSSL_CALLBACK *cb, void *arg)
{
	struct provider_ctx *pctx = vpctx;

	ps_dbg_debug(&pctx->dbg, "pctx: %p capability: %s", pctx,
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

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out,
		       void **vctx)
{
	const OSSL_DISPATCH **pout;
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

	ps_dbg_debug(&pctx->dbg, "pctx: %p, %s: %s", pctx,
		     PS_PKCS11_MODULE_PATH, module);
	ps_dbg_debug(&pctx->dbg, "pctx: %p, %s: %s", pctx,
		     PS_PKCS11_MODULE_INIT_ARGS, module_args);
	ps_dbg_debug(&pctx->dbg, "pctx: %p, %s: %s", pctx,
		     PS_PKCS11_FWD, fwd);

	if (fwd_init(&pctx->fwd, fwd, handle, in, pctx->core.libctx,
		     &pctx->dbg) != OSSL_RV_OK) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "Failed to initialize forward %s", fwd);
		goto err;
	}
	ps_dbg_debug(&pctx->dbg, "pctx: %p, forward: %s", pctx, pctx->fwd.name);

	pctx->pkcs11 = pkcs11_module_new(module, module_args, &pctx->dbg);
	if (!pctx->pkcs11) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "Failed to initialize pkcs11 module %s", module);
		goto err;
	}
	ps_dbg_debug(&pctx->dbg, "pctx: %p, pkcs11: %s", pctx, pctx->pkcs11->soname);

	*vctx = pctx;
	*out = ps_dispatch_table;
	return OSSL_RV_OK;

err:
	ps_prov_teardown(pctx);
	return OSSL_RV_ERR;
}

#endif
