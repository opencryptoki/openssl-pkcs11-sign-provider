/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "common.h"
#include "ossl.h"
#include "object.h"

static int op_ctx_init_key(struct op_ctx *octx, struct obj *key)
{
	if (!key)
		return OSSL_RV_OK;

	switch (octx->type) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
		break;
	default:
		put_error_op_ctx(octx, PS_ERR_INTERNAL_ERROR,
				 "key type unknown: ctx type: "
				 "%d key type: %d",
				 octx->type, key->type);
		return OSSL_RV_ERR;
	}

	if (octx->type != key->type) {
		put_error_op_ctx(octx,
				 PS_ERR_INTERNAL_ERROR,
				 "key type mismatch: ctx type: "
				 "%d key type: %d",
				 octx->type, key->type);
		return OSSL_RV_ERR;
	}

	/* update/replace key (implicit NULL check) */
	obj_free(octx->key);
	octx->key = obj_get(key);

	return OSSL_RV_OK;
}

int op_ctx_init(struct op_ctx *octx, struct obj *key, int operation)
{
	struct dbg *dbg = &octx->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p, operation: %d",
		     key, operation);

	if (op_ctx_init_key(octx, key) != OSSL_RV_OK)
	    return OSSL_RV_ERR;

	octx->operation = operation;

	return OSSL_RV_OK;
}

struct op_ctx *op_ctx_new(struct provider_ctx *pctx, const char *prop, int type)
{
	struct op_ctx *opctx;

	if (!pctx)
		return NULL;

	opctx = OPENSSL_zalloc(sizeof(struct op_ctx));
	if (!opctx)
		return NULL;

	opctx->pctx = pctx;
	opctx->type = type;
	if (prop)
		opctx->prop = OPENSSL_strdup(prop);

	opctx->hsession = CK_INVALID_HANDLE;
	opctx->hobject = CK_INVALID_HANDLE;

	return opctx;
}

struct op_ctx *op_ctx_dup(struct op_ctx * opctx)
{
	struct op_ctx *opctx_new;

	if (!opctx)
		return NULL;

	opctx_new = op_ctx_new(opctx->pctx, (const char *)opctx->prop, opctx->type);
	if (!opctx_new)
		return NULL;

	if (op_ctx_init_key(opctx_new, opctx->key) != OSSL_RV_OK)
		goto err;

	opctx_new->operation = opctx->operation;

	return opctx_new;

err:
	op_ctx_free(opctx_new);
	return NULL;
}

void op_ctx_free(struct op_ctx *octx)
{
	obj_free(octx->key);
	OPENSSL_free(octx->prop);
	OPENSSL_free(octx);
}
