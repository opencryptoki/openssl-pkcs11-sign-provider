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
#include "object.h"
#include "keymgmt.h"
#include "signature.h"
#include "asym.h"
#include "keyexch.h"

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

#define PS_PROV_DESCRIPTION	"PKCS11 signing key provider"
#define PS_PROV_VERSION		"0.1"

#define PS_PROV_RSA_DEFAULT_MD			"SHA-1"
#define PS_PROV_PKEY_PARAM_SK_BLOB		"ps-blob"
#define PS_PROV_PKEY_PARAM_SK_FUNCS		"ps-funcs"
#define PS_PROV_PKEY_PARAM_SK_PRIVATE		"ps-private"

#define PS_PKCS11_MODULE_PATH			"pkcs11sign-module-path"
#define PS_PKCS11_MODULE_INIT_ARGS		"pkcs11sign-module-init-args"
#define PS_PKCS11_FWD				"pkcs11sign-forward"

struct ps_op_ctx {
	struct provider_ctx *pctx;
	int type; /* EVP_PKEY_xxx types */
	const char *propq;
	void *fwd_op_ctx; /* shadow context of default provider */
	void (*fwd_op_ctx_free)(void *fwd_op_ctx);
	struct obj *key;
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

struct dbg *hack_dbg = NULL;

static int ps_get_bits(struct obj *key)
{
	/* dummy */
	return 0;
}

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
		obj_free(opctx->key);

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
		obj_get(opctx->key);
	}

	ps_opctx_debug(opctx, "new_opctx: %p", new_opctx);
	return new_opctx;
}

static int ps_op_init(struct ps_op_ctx *ctx, struct obj *key,
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
		obj_get(key);

	if (ctx->key != NULL)
		obj_free(ctx->key);

	ctx->key = key;
	ctx->operation = operation;

	return 1;
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

	provider_ctx_teardown(pctx);
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

	/* REVISIT skip provider prefix if present */
	if (strncmp(fwd, "provider=", strlen("provider=")) == 0)
		fwd += strlen("provider=");

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
	hack_dbg = &pctx->dbg;
	return OSSL_RV_OK;

err:
	ps_prov_teardown(pctx);
	return OSSL_RV_ERR;
}

#endif
