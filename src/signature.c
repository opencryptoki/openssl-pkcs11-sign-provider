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
#include "object.h"

static int op_ctx_signature_size(struct op_ctx *opctx, size_t *siglen)
{
	unsigned char *rawsig, dummy;
	size_t rawsiglen, len;

	if (pkcs11_sign_init(opctx->pctx->pkcs11, opctx->hsession,
			     &opctx->mech, opctx->hobject,
			     &opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_sign() failed");
		return OSSL_RV_ERR;
	}

	if (pkcs11_sign(opctx->pctx->pkcs11, opctx->hsession,
			      &dummy, sizeof(dummy), NULL, &rawsiglen,
			      &opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_sign() failed");
		return OSSL_RV_ERR;
	}

	switch (opctx->type) {
	case EVP_PKEY_EC:
		rawsig = OPENSSL_malloc(rawsiglen);
		if (!rawsig) {
			ps_opctx_debug(opctx, "ERROR: cannot alloc dummy buffer");
			return OSSL_RV_ERR;
		}

		/*
		 * HACK: the length of OPENSSL ecdsa signatures depends on its content.
		 * Filling the dummy buffer with 0xff cause the convertion to return
		 * the maximum length.
		 */
		memset(rawsig, 0xff, rawsiglen);

		if (ossl_ecdsa_signature(rawsig, rawsiglen, NULL, &len) != OSSL_RV_OK) {
			ps_opctx_debug(opctx, "ERROR: ossl_build_ecdsa_signature() failed");
			OPENSSL_free(rawsig);
			return OSSL_RV_ERR;
		}
		OPENSSL_free(rawsig);
		break;
	case EVP_PKEY_RSA:
		len = rawsiglen;
		break;
	default:
		return OSSL_RV_ERR;
	}

	*siglen = len;
	return OSSL_RV_OK;
}

static int signature_op_ctx_new_fwd(struct op_ctx *opctx)
{
	OSSL_FUNC_signature_freectx_fn *fwd_freectx_fn;
	OSSL_FUNC_signature_newctx_fn *fwd_newctx_fn;

	fwd_newctx_fn = (OSSL_FUNC_signature_newctx_fn *)
			fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
					OSSL_FUNC_SIGNATURE_NEWCTX,
					&opctx->pctx->dbg);
	if (fwd_newctx_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default newctx_fn");
		return OSSL_RV_ERR;
	}

	fwd_freectx_fn = (OSSL_FUNC_signature_freectx_fn *)
			fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
					OSSL_FUNC_SIGNATURE_FREECTX,
					&opctx->pctx->dbg);
	if (!fwd_freectx_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default freectx_fn");
		return OSSL_RV_ERR;
	}

	opctx->fwd_op_ctx = fwd_newctx_fn(opctx->pctx->fwd.ctx, opctx->prop);
	if (!opctx->fwd_op_ctx) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_newctx_fn failed");
		op_ctx_free(opctx);
		return OSSL_RV_ERR;
	}
	opctx->fwd_op_ctx_free = fwd_freectx_fn;

	return OSSL_RV_OK;
}

static struct op_ctx *signature_op_ctx_new(
					struct provider_ctx *pctx,
					const char *propq,
					int pkey_type)
{
	struct op_ctx *opctx;

	ps_dbg_debug(&pctx->dbg, "propq: %s pkey_type: %d",
		     propq != NULL ? propq : "", pkey_type);

	opctx = op_ctx_new(pctx, propq, pkey_type);
	if (!opctx) {
		ps_dbg_error(&pctx->dbg, "ERROR: op_ctx_new() failed");
		return NULL;
	}

	if (signature_op_ctx_new_fwd(opctx) != OSSL_RV_OK) {
		ps_dbg_error(&pctx->dbg, "ERROR: signature_op_ctx_new_fwd() failed");
		goto err;
	}

	ps_dbg_debug(&pctx->dbg, "opctx: %p", opctx);
	return opctx;

err:
	op_ctx_free(opctx);
	return NULL;
}

static void *ps_signature_op_dupctx_fwd(struct op_ctx *opctx)
{
	OSSL_FUNC_signature_dupctx_fn *fwd_dupctx_fn;
	void *fwd_op_ctx_new = NULL;

	fwd_dupctx_fn = (OSSL_FUNC_signature_dupctx_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd,
				  opctx->type, OSSL_FUNC_SIGNATURE_DUPCTX,
				  &opctx->pctx->dbg);

	if (!fwd_dupctx_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default dupctx_fn");
		goto out;
	}

	fwd_op_ctx_new = fwd_dupctx_fn(opctx->fwd_op_ctx);
	if (!fwd_op_ctx_new) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_dupctx_fn failed");
	}

out:
	return fwd_op_ctx_new;
}

static void *ps_signature_op_dupctx(void *vopctx)
{
	struct op_ctx *opctx = vopctx;
	struct op_ctx *opctx_new;

	if (!opctx)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	opctx_new = op_ctx_dup(opctx);
	if (!opctx_new) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_dup() failed");
		return NULL;
	}
	opctx_new->mech = opctx->mech;

	opctx_new->fwd_op_ctx = ps_signature_op_dupctx_fwd(opctx);
	if (!opctx_new->fwd_op_ctx) {
		ps_opctx_debug(opctx, "ERROR: unable to dup fwd_op_ctx");
		goto err;
	}
	opctx_new->fwd_op_ctx_free = opctx->fwd_op_ctx_free;

	if (opctx->mdctx) {
		opctx_new->mdctx = EVP_MD_CTX_new();
		if (!opctx_new->mdctx) {
			put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "EVP_MD_CTX_new failed");
			goto err;
		}
		if (EVP_MD_CTX_copy(opctx_new->mdctx, opctx->mdctx) != OSSL_RV_OK) {
			put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
					 "EVP_MD_CTX_copy failed");
			goto err;
		}
	}

	if ((opctx->md) &&
	    (EVP_MD_up_ref(opctx->md) != OSSL_RV_OK)) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "EVP_MD_up_ref failed");
		goto err;
	}

	if ((opctx->hobject != CK_INVALID_HANDLE) &&
	    (op_ctx_object_ensure(opctx_new) != OSSL_RV_OK)) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "EVP_MD_up_ref failed");
		goto err;
	}

	ps_opctx_debug(opctx, "opctx_new: %p", opctx_new);
	return opctx_new;

err:
	op_ctx_free(opctx_new);
	return NULL;
}

static int ps_signature_op_get_ctx_params(void *vopctx, OSSL_PARAM params[])
{
	OSSL_FUNC_signature_get_ctx_params_fn *fwd_get_params_fn;
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (opctx == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_get_params_fn = (OSSL_FUNC_signature_get_ctx_params_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
				  &opctx->pctx->dbg);

	/* fwd_get_params_fn is optional */
	if (!fwd_get_params_fn)
		return OSSL_RV_OK;

	if (fwd_get_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx,
				 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_get_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_set_ctx_params(void *vopctx,
					  const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_set_ctx_params_fn *fwd_set_params_fn;
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_set_params_fn = (OSSL_FUNC_signature_set_ctx_params_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
				  &opctx->pctx->dbg);

	/* fwd_set_params_fn is optional */
	if (!fwd_set_params_fn)
		return OSSL_RV_OK;

	if (fwd_set_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx,
				 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_set_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_signature_op_gettable_ctx_params(
				struct op_ctx *opctx, int pkey_type)
{
	OSSL_FUNC_signature_gettable_ctx_params_fn *fwd_gettable_params_fn;
	const OSSL_PARAM *params, *p;

	ps_opctx_debug(opctx, "opctx: %p, pkey_type: %d",
		       opctx, pkey_type);

	fwd_gettable_params_fn =
		(OSSL_FUNC_signature_gettable_ctx_params_fn *)
			fwd_sign_get_func(&opctx->pctx->fwd, pkey_type,
				OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
				&opctx->pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (!fwd_gettable_params_fn)
		return NULL;

	params = fwd_gettable_params_fn(opctx->fwd_op_ctx,
					opctx->pctx->fwd.ctx);

	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "opctx: %p, param: %s",
			       opctx, p->key);

	return params;
}

static const OSSL_PARAM *ps_signature_op_settable_ctx_params(
				struct op_ctx *opctx, int pkey_type)
{
	OSSL_FUNC_signature_settable_ctx_params_fn *fwd_settable_params_fn;
	const OSSL_PARAM *params, *p;

	ps_opctx_debug(opctx, "opctx: %p, pkey_type: %d",
		       opctx, pkey_type);

	fwd_settable_params_fn = (OSSL_FUNC_signature_settable_ctx_params_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, pkey_type,
				  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
				  &opctx->pctx->dbg);

	/* fwd_settable_params_fn is optional */
	if (!fwd_settable_params_fn)
		return NULL;

	params = fwd_settable_params_fn(opctx->fwd_op_ctx,
					opctx->pctx->fwd.ctx);

	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	return params;
}

static int ps_signature_op_get_ctx_md_params(void *vopctx, OSSL_PARAM params[])
{
	OSSL_FUNC_signature_get_ctx_md_params_fn *fwd_get_md_params_fn;
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_get_md_params_fn = (OSSL_FUNC_signature_get_ctx_md_params_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
				&opctx->pctx->dbg);

	/* fwd_get_md_params_fn is optional */
	if (!fwd_get_md_params_fn)
		return OSSL_RV_OK;

	if (fwd_get_md_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx,
				 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_get_md_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_set_ctx_md_params(void *vopctx,
					     const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_set_ctx_md_params_fn *fwd_set_md_params_fn;
	struct op_ctx *opctx = vopctx;
	const OSSL_PARAM *p;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	fwd_set_md_params_fn = (OSSL_FUNC_signature_set_ctx_md_params_fn *)
			fwd_sign_get_func(&opctx->pctx->fwd,
				opctx->type,
				OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
				&opctx->pctx->dbg);

	/* fwd_set_md_params_fn is optional */
	if (!fwd_set_md_params_fn)
		return OSSL_RV_OK;

	if (fwd_set_md_params_fn(opctx->fwd_op_ctx, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx,
				 PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_set_md_params_fn failed");
		return OSSL_RV_ERR;
	}

	/* Also set parameters in own MD context */
	if (opctx->mdctx)
		return EVP_MD_CTX_set_params(opctx->mdctx, params);

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_signature_op_gettable_ctx_md_params(
				struct op_ctx *opctx, int pkey_type)
{
	OSSL_FUNC_signature_gettable_ctx_md_params_fn
						*fwd_gettable_md_params_fn;
	const OSSL_PARAM *params, *p;

	ps_opctx_debug(opctx, "opctx: %p, pkey_type: %d",
		       opctx, pkey_type);

	fwd_gettable_md_params_fn =
		(OSSL_FUNC_signature_gettable_ctx_md_params_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, pkey_type,
				  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
				  &opctx->pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	if (!fwd_gettable_md_params_fn)
		return NULL;

	params = fwd_gettable_md_params_fn(opctx->fwd_op_ctx);

	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	return params;
}

static const OSSL_PARAM *ps_signature_op_settable_ctx_md_params(
				struct op_ctx *opctx, int pkey_type)
{
	OSSL_FUNC_signature_settable_ctx_md_params_fn
						*fwd_settable_md_params_fn;
	const OSSL_PARAM *params, *p;

	ps_opctx_debug(opctx, "opctx: %p, pkey_type: %d",
		       opctx, pkey_type);

	fwd_settable_md_params_fn =
		(OSSL_FUNC_signature_settable_ctx_md_params_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, pkey_type,
				  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
				  &opctx->pctx->dbg);

	/* fwd_settable_md_params_fn is optional */
	if (!fwd_settable_md_params_fn)
		return NULL;

	params = fwd_settable_md_params_fn(opctx->fwd_op_ctx);

	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	return params;
}

static EVP_MD *ps_signature_op_get_md(struct op_ctx *opctx)
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

	ps_opctx_debug(opctx, "opctx: %p", opctx);

	if (!ps_signature_op_get_ctx_params(opctx, ctx_params) ||
	    !OSSL_PARAM_modified(&ctx_params[0]) ||
	    !OSSL_PARAM_modified(&ctx_params[1])) {
		ps_opctx_debug(opctx, "ps_signature_op_get_ctx_params failed");
		if (opctx->md) {
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
	if (!md) {
		put_error_op_ctx(opctx, PS_ERR_MISSING_PARAMETER,
				 "EVP_MD_fetch failed to fetch '%s' using "
				 "property query '%s'", mdname,
				 (mdprops[0] != '\0') ?
					mdprops :
					(opctx->prop) ?
						opctx->prop :
						"");
		return NULL;
	}

	ps_opctx_debug(opctx, "md: %s", EVP_MD_name(md));
	return md;
}

static int ps_signature_op_sign_init_fwd(struct op_ctx *opctx,
					 struct obj *key,
					 const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_sign_init_fn *fwd_sign_init_fn;

	fwd_sign_init_fn = (OSSL_FUNC_signature_sign_init_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_SIGN_INIT,
				  &opctx->pctx->dbg);
	if (!fwd_sign_init_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default sign_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_sign_init_fn(opctx->fwd_op_ctx, key->fwd_key,
			     params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_sign_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_sign_init(void *vopctx, void *vkey,
				     const OSSL_PARAM params[],
				     const CK_MECHANISM_PTR mech)
{
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!opctx || !key )
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p, mech: %p",
		       opctx, key, mech);

	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (op_ctx_init(opctx, key, EVP_PKEY_OP_SIGN) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_init() failed");
		return OSSL_RV_ERR;
	}

	if (ps_signature_op_sign_init_fwd(opctx, key, params) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_init() failed");
		return OSSL_RV_ERR;
	}

	if (!key->use_pkcs11)
		return OSSL_RV_OK;

	opctx->mech = *mech;

	if (op_ctx_object_ensure(opctx) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_object_ensure() failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_sign_fwd(struct op_ctx *opctx,
				    unsigned char *sig, size_t *siglen,
				    size_t sigsize,
				    const unsigned char *tbs, size_t tbslen)
{
	OSSL_FUNC_signature_sign_fn *fwd_sign_fn;

	fwd_sign_fn =
		(OSSL_FUNC_signature_sign_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_SIGN,
				  &opctx->pctx->dbg);
	if (!fwd_sign_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd sign_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_sign_fn(opctx->fwd_op_ctx, sig, siglen, sigsize,
			tbs, tbslen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_sign_fn failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "siglen: %lu", *siglen);
	return OSSL_RV_OK;
}

static int ps_signature_op_sign(void *vopctx,
				unsigned char *sig, size_t *siglen,
				size_t sigsize,
				const unsigned char *tbs, size_t tbslen)
{
	struct op_ctx *opctx = vopctx;
	size_t raw_siglen;

	if (opctx == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p sig: %p siglen: %p, sigsize: %lu, tbs: %p, tbslen: %lu",
		       opctx, sig, siglen, sigsize, tbs, tbslen);

	if (!opctx->key || (opctx->operation != EVP_PKEY_OP_SIGN)) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "sign operation not initialized");
		return OSSL_RV_ERR;
	}

	if (!opctx->key->use_pkcs11)
		return ps_signature_op_sign_fwd(opctx, sig, siglen, sigsize, tbs, tbslen);

	if (!sig)
		return op_ctx_signature_size(opctx, siglen);

	if (pkcs11_sign_init(opctx->pctx->pkcs11, opctx->hsession,
			     &opctx->mech, opctx->hobject,
			     &opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_sign() failed");
		return OSSL_RV_ERR;
	}

	if (pkcs11_sign(opctx->pctx->pkcs11, opctx->hsession,
			tbs, tbslen, sig, &raw_siglen,
			&opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_sign() failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "raw signature: [%p, %lu]",
		       sig, raw_siglen);
	ps_dbg_debug_dump(&opctx->pctx->dbg,
			  sig, raw_siglen);

	if (ossl_ecdsa_signature(sig, raw_siglen, sig, siglen) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: ossl_build_ecdsa_signature() failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "signature: [%p, %lu]",
		       sig, *siglen);
	ps_dbg_debug_dump(&opctx->pctx->dbg,
			  sig, *siglen);

	return OSSL_RV_OK;
}

static int ps_signature_op_verify_init_fwd(struct op_ctx *opctx,
					   struct obj *key,
					   const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_verify_init_fn *fwd_verify_init_fn;

	fwd_verify_init_fn = (OSSL_FUNC_signature_verify_init_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_VERIFY_INIT,
				  &opctx->pctx->dbg);

	if (!fwd_verify_init_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_verify_init_fn(opctx->fwd_op_ctx, key->fwd_key,
			       params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_verify_init(void *vopctx, void *vkey,
				       const OSSL_PARAM params[])
{
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!opctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p",
		       opctx, key);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (!op_ctx_init(opctx, key, EVP_PKEY_OP_VERIFY)) {
		ps_opctx_debug(opctx, "ERROR: ps_op_init failed");
		return OSSL_RV_ERR;
	}

	if (ps_signature_op_verify_init_fwd(opctx, key, params) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	if (!key->use_pkcs11)
		return OSSL_RV_OK;

	/* TODO implementation for pkcs11 */
	return OSSL_RV_ERR;

}

static int ps_signature_op_verify_recover_init_fwd(struct op_ctx *opctx,
						   struct obj *key,
						   const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_verify_recover_init_fn
					*fwd_verify_recover_init_fn;

	fwd_verify_recover_init_fn =
		(OSSL_FUNC_signature_verify_recover_init_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
				  &opctx->pctx->dbg);

	if (fwd_verify_recover_init_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_recover_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_verify_recover_init_fn(opctx->fwd_op_ctx, key->fwd_key,
					params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_recover_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_verify_recover_init(void *vopctx, void *vkey,
					       const OSSL_PARAM params[])
{
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!opctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p", opctx, key);
	for (p = params; p && p->key; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (!op_ctx_init(opctx, key, EVP_PKEY_OP_VERIFYRECOVER)) {
		ps_opctx_debug(opctx, "ERROR: ps_op_init failed");
		return OSSL_RV_ERR;
	}

	if (ps_signature_op_verify_recover_init_fwd(opctx, key,
						    params) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	if (!opctx->key->use_pkcs11)
		return OSSL_RV_OK;

	/* TODO implementation for pkcs11 */
	return OSSL_RV_ERR;
}

static int ps_signature_op_verify_fwd(struct op_ctx *opctx,
				      const unsigned char *sig, size_t siglen,
				      const unsigned char *tbs, size_t tbslen)
{
	OSSL_FUNC_signature_verify_fn *fwd_verify_fn;

	fwd_verify_fn = (OSSL_FUNC_signature_verify_fn *)
			fwd_sign_get_func(&opctx->pctx->fwd,
				opctx->type, OSSL_FUNC_SIGNATURE_VERIFY,
				&opctx->pctx->dbg);
	if (fwd_verify_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_verify_fn(opctx->fwd_op_ctx, sig, siglen, tbs, tbslen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_verify(void *vopctx,
				  const unsigned char *sig, size_t siglen,
				  const unsigned char *tbs, size_t tbslen)
{
	struct op_ctx *opctx = vopctx;

	if (!opctx || !tbs || !sig)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p tbslen: %lu siglen: %lu",
			opctx, opctx->key, tbslen, siglen);

	if (!opctx->key->use_pkcs11)
		return ps_signature_op_verify_fwd(opctx, sig, siglen, tbs, tbslen);

	/* TODO implementation for pkcs11 */
	return OSSL_RV_ERR;
}

static int ps_signature_op_verify_recover_fwd(struct op_ctx *opctx,
					      unsigned char *rout, size_t *routlen,
					      size_t routsize,
					      const unsigned char *sig,
					      size_t siglen)
{
	OSSL_FUNC_signature_verify_recover_fn *fwd_verify_recover_fn;

	fwd_verify_recover_fn =
		(OSSL_FUNC_signature_verify_recover_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
				  &opctx->pctx->dbg);
	if (fwd_verify_recover_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default verify_recover_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_verify_recover_fn(opctx->fwd_op_ctx, rout, routlen,
				  routsize, sig, siglen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_verify_recover_fn failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "routlen: %lu", *routlen);

	return OSSL_RV_OK;
}

static int ps_signature_op_verify_recover(void *vopctx,
					  unsigned char *rout, size_t *routlen,
					  size_t routsize,
					  const unsigned char *sig,
					  size_t siglen)
{
	struct op_ctx *opctx = vopctx;

	if (!opctx || !routlen || !sig)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p routsize: %lu siglen: %lu",
		       opctx, opctx->key, routsize, siglen);

	if (!opctx->key->use_pkcs11)
		return ps_signature_op_verify_recover_fwd(opctx, rout, routlen,
							  routsize, sig, siglen);

	/* TODO implementation for pkcs11 */
	return OSSL_RV_ERR;
}

static int ps_signature_op_digest_sign_init_fwd(struct op_ctx *opctx,
						const char *mdname,
						struct obj *key,
						const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_digest_sign_init_fn *fwd_digest_sign_init_fn;

	fwd_digest_sign_init_fn = (OSSL_FUNC_signature_digest_sign_init_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
				  &opctx->pctx->dbg);
	if (fwd_digest_sign_init_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_digest_sign_init_fn(opctx->fwd_op_ctx, mdname,
				    key->fwd_key, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_sign_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;

}

static int ps_signature_op_digest_sign_init(struct op_ctx *opctx,
					    const char *mdname,
					    struct obj *key,
					    const OSSL_PARAM params[],
					    const CK_MECHANISM_PTR mech)
{
	const OSSL_PARAM *p;

	if (!opctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p, mech: %p",
		       opctx, (mdname) ? mdname : "",
		       key, mech);

	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (!op_ctx_init(opctx, key, EVP_PKEY_OP_SIGN)) {
		ps_opctx_debug(opctx, "ERROR: ps_op_init failed");
		return OSSL_RV_ERR;
	}

	if (ps_signature_op_digest_sign_init_fwd(opctx, mdname,
						 key, params) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	if (!opctx->key->use_pkcs11)
		return OSSL_RV_OK;

	opctx->mech = *mech;

	if (op_ctx_object_ensure(opctx) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_object_ensure() failed");
		return OSSL_RV_ERR;
	}

	/* mdctx */
	if (opctx->mdctx != NULL)
		EVP_MD_CTX_free(opctx->mdctx);

	opctx->mdctx = EVP_MD_CTX_new();
	if (opctx->mdctx == NULL) {
		put_error_op_ctx(opctx, PS_ERR_MALLOC_FAILED,
			 "EVP_MD_CTX_new failed");
		return OSSL_RV_ERR;
	}

	/* md */
	if (opctx->md)
		EVP_MD_free(opctx->md);

	opctx->md = (mdname) ?
		EVP_MD_fetch(opctx->pctx->core.libctx, mdname, opctx->prop) :
		ps_signature_op_get_md(opctx);
	if (!opctx->md) {
		ps_opctx_debug(opctx, "ERROR: Failed to get digest sign digest");
		EVP_MD_CTX_free(opctx->mdctx);
		opctx->mdctx = NULL;
		return OSSL_RV_ERR;
	}

	if (EVP_DigestInit_ex2(opctx->mdctx, opctx->md, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_MALLOC_FAILED,
				 "EVP_DigestInit_ex2 failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_sign_update_fwd(struct op_ctx *opctx,
						  const unsigned char *data,
						  size_t datalen)
{
	OSSL_FUNC_signature_digest_sign_update_fn *fwd_digest_sign_update_fn;

	fwd_digest_sign_update_fn = (OSSL_FUNC_signature_digest_sign_update_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd,
				  opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
				  &opctx->pctx->dbg);

	if (fwd_digest_sign_update_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_update_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_digest_sign_update_fn(opctx->fwd_op_ctx,
				      data, datalen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_sign_update_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_sign_update(void *vctx,
					      const unsigned char *data,
					      size_t datalen)
{
	struct op_ctx *opctx = vctx;

	if (opctx == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p datalen: %lu", opctx,
		       opctx->key, datalen);

	if (!opctx->key->use_pkcs11)
		return ps_signature_op_digest_sign_update_fwd(opctx, data, datalen);

	if (!opctx->mdctx) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return OSSL_RV_ERR;
	}

	if (EVP_DigestUpdate(opctx->mdctx, data, datalen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "ERROR: EVP_DigestUpdate() failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_sign_final_fwd(struct op_ctx *opctx,
						 unsigned char *sig, size_t *siglen,
						 size_t sigsize)
{
	OSSL_FUNC_signature_digest_sign_final_fn *fwd_digest_sign_final_fn;

	fwd_digest_sign_final_fn =
		(OSSL_FUNC_signature_digest_sign_final_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
				  &opctx->pctx->dbg);
	if (!fwd_digest_sign_final_fn) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_sign_final_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_digest_sign_final_fn(opctx->fwd_op_ctx, sig, siglen,
					 sigsize) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_sign_final_fn failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "siglen: %lu", *siglen);
	return OSSL_RV_OK;
}

static int ps_signature_op_digest_sign_final(void *vopctx,
					     unsigned char *sig, size_t *siglen,
					     size_t sigsize)
{
	unsigned char tbs[DER_DIGESTINFO_MAX + EVP_MAX_MD_SIZE], *digest;
	struct op_ctx *opctx = vopctx;
	size_t raw_siglen;
	unsigned int tbslen = 0, dlen = 0;

	if (!opctx || !siglen)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p sigsize: %lu",
		       opctx, opctx->key, sigsize);

	if (!opctx->key || (opctx->operation != EVP_PKEY_OP_SIGN)) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return OSSL_RV_ERR;
	}

	if (!opctx->key->use_pkcs11)
		return ps_signature_op_digest_sign_final_fwd(opctx, sig,
							     siglen, sigsize);

	if (!opctx->mdctx) {
		put_error_op_ctx(opctx, PS_ERR_OPRATION_NOT_INITIALIZED,
				 "digest sign operation not initialized");
		return OSSL_RV_ERR;
	}

	if (!sig)
		return op_ctx_signature_size(opctx, siglen);

	switch (opctx->type) {
	case EVP_PKEY_RSA:
		/* prefix hash with DER-encoded algo */
		if ((opctx->mech.mechanism == CKM_RSA_PKCS) &&
		    (ossl_hash_prefix(opctx->mdctx, tbs, &tbslen) != OSSL_RV_OK))
			return OSSL_RV_ERR;
		digest = tbs + tbslen;
		break;
	default:
		/* no extra padding */
		digest = tbs;
		break;
	}

	if (EVP_DigestFinal_ex(opctx->mdctx, digest, &dlen) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: EVP_DigestFinal_ex failed");
		return OSSL_RV_ERR;
	}

	ps_opctx_debug(opctx, "digest: [%p, %lu]",
		       digest, dlen);
	ps_dbg_debug_dump(&opctx->pctx->dbg,
			  digest, dlen);

	if (pkcs11_sign_init(opctx->pctx->pkcs11, opctx->hsession,
			     &opctx->mech, opctx->hobject,
			     &opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_sign() failed");
		return OSSL_RV_ERR;
	}

	tbslen += dlen;
	raw_siglen = sigsize;
	if (pkcs11_sign(opctx->pctx->pkcs11, opctx->hsession,
			tbs, tbslen, sig, &raw_siglen,
			&opctx->pctx->dbg) != CKR_OK) {
		ps_opctx_debug(opctx, "ERROR: pkcs11_sign() failed");
		return OSSL_RV_ERR;
	}

	switch (opctx->type) {
	case EVP_PKEY_EC:
		ps_opctx_debug(opctx, "raw signature: [%p, %lu]",
			       sig, raw_siglen);
		ps_dbg_debug_dump(&opctx->pctx->dbg,
				  sig, raw_siglen);

		if (ossl_ecdsa_signature(sig, raw_siglen, sig, siglen) != OSSL_RV_OK) {
			ps_opctx_debug(opctx, "ERROR: ossl_build_ecdsa_signature() failed");
			return OSSL_RV_ERR;
		}
		break;
	default:
		*siglen = raw_siglen;
	}

	ps_opctx_debug(opctx, "signature: [%p, %lu]",
		       sig, *siglen);
	ps_dbg_debug_dump(&opctx->pctx->dbg,
			  sig, *siglen);

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_verify_init_fwd(struct op_ctx *opctx,
						  const char *mdname,
						  struct obj *key,
						  const OSSL_PARAM params[])
{
	OSSL_FUNC_signature_digest_verify_init_fn *fwd_digest_verify_init_fn;

	fwd_digest_verify_init_fn = (OSSL_FUNC_signature_digest_verify_init_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
				  &opctx->pctx->dbg);
	if (fwd_digest_verify_init_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd digest_verify_init_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_digest_verify_init_fn(opctx->fwd_op_ctx, mdname,
				      key->fwd_key, params) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_verify_init_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_verify_init(void *vctx,
					      const char *mdname,
					      void *vkey,
					      const OSSL_PARAM params[])
{
	struct op_ctx *opctx = vctx;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!opctx || !key)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p", opctx,
			mdname != NULL ? mdname : "", key);
	for (p = params; p != NULL && p->key != NULL; p++)
		ps_opctx_debug(opctx, "param: %s", p->key);

	if (op_ctx_init(opctx, key, EVP_PKEY_OP_VERIFY) != OSSL_RV_OK) {
		ps_opctx_debug(opctx, "ERROR: op_ctx_init() failed");
		return OSSL_RV_ERR;
	}

	if (ps_signature_op_digest_verify_init_fwd(opctx, mdname,
						   opctx->key,
						   params) != OSSL_RV_OK)
		return OSSL_RV_ERR;

	if (!opctx->key->use_pkcs11)
		return OSSL_RV_OK;

	/* not supported for pkcs11 */
	return OSSL_RV_ERR;
}

static int ps_signature_op_digest_verify_update_fwd(struct op_ctx *opctx,
						    const unsigned char *data,
						    size_t datalen)
{
	OSSL_FUNC_signature_digest_verify_update_fn *fwd_digest_verify_update_fn;

	fwd_digest_verify_update_fn =
		(OSSL_FUNC_signature_digest_verify_update_fn *)
			fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
				&opctx->pctx->dbg);
	if (fwd_digest_verify_update_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default digest_verify_update_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_digest_verify_update_fn(opctx->fwd_op_ctx,
					data, datalen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "default_digest_verify_update_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_verify_update(void *vctx,
						const unsigned char *data,
						size_t datalen)
{
	struct op_ctx *opctx = vctx;

	if (!opctx)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p datalen: %lu", opctx, opctx->key,
			datalen);

	if (!opctx->key->use_pkcs11)
		return  ps_signature_op_digest_verify_update_fwd(opctx, data, datalen);

	/* not supported for pkcs11 */
	return OSSL_RV_ERR;
}

static int ps_signature_op_digest_verify_final_fwd(struct op_ctx *opctx,
						   const unsigned char *sig,
						   size_t siglen)
{
	OSSL_FUNC_signature_digest_verify_final_fn *fwd_digest_verify_final_fn;

	fwd_digest_verify_final_fn = (OSSL_FUNC_signature_digest_verify_final_fn *)
		fwd_sign_get_func(&opctx->pctx->fwd, opctx->type,
				  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
				  &opctx->pctx->dbg);
	if (fwd_digest_verify_final_fn == NULL) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no fwd digest_verify_final_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_digest_verify_final_fn(opctx->fwd_op_ctx, sig, siglen) != OSSL_RV_OK) {
		put_error_op_ctx(opctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_digest_verify_final_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_signature_op_digest_verify_final(void *vctx,
					       const unsigned char *sig,
					       size_t siglen)
{
	struct op_ctx *opctx = vctx;

	if (!opctx || sig == NULL)
		return OSSL_RV_ERR;

	ps_opctx_debug(opctx, "opctx: %p key: %p siglen: %lu", opctx, opctx->key,
			siglen);

	if (!opctx->key->use_pkcs11)
		return ps_signature_op_digest_verify_final_fwd(opctx, sig, siglen);

	/* not supported for pkcs11 */
	return OSSL_RV_ERR;
}

#define DISP_SIG(tname, name) DECL_DISPATCH_FUNC(signature, tname, name)
DISP_SIG(newctx, ps_signature_rsa_newctx);
DISP_SIG(newctx, ps_signature_ec_newctx);
DISP_SIG(dupctx, ps_signature_op_dupctx);
DISP_SIG(sign_init, ps_signature_ec_sign_init);
DISP_SIG(sign_init, ps_signature_rsa_sign_init);
DISP_SIG(sign, ps_signature_op_sign);
DISP_SIG(verify_init, ps_signature_op_verify_init);
DISP_SIG(verify, ps_signature_op_verify);
DISP_SIG(verify_recover_init, ps_signature_op_verify_recover_init);
DISP_SIG(verify_recover, ps_signature_op_verify_recover);
DISP_SIG(digest_sign_init, ps_signature_rsa_digest_sign_init);
DISP_SIG(digest_sign_init, ps_signature_ec_digest_sign_init);
DISP_SIG(digest_sign_update, ps_signature_op_digest_sign_update);
DISP_SIG(digest_sign_final, ps_signature_op_digest_sign_final);
DISP_SIG(digest_verify_init, ps_signature_op_digest_verify_init);
DISP_SIG(digest_verify_update, ps_signature_op_digest_verify_update);
DISP_SIG(digest_verify_final, ps_signature_op_digest_verify_final);
DISP_SIG(get_ctx_params, ps_signature_op_get_ctx_params);
DISP_SIG(gettable_ctx_params, ps_signature_rsa_gettable_ctx_params);
DISP_SIG(gettable_ctx_params, ps_signature_ec_gettable_ctx_params);
DISP_SIG(set_ctx_params, ps_signature_op_set_ctx_params);
DISP_SIG(settable_ctx_params, ps_signature_rsa_settable_ctx_params);
DISP_SIG(settable_ctx_params, ps_signature_ec_settable_ctx_params);
DISP_SIG(get_ctx_md_params, ps_signature_op_get_ctx_md_params);
DISP_SIG(gettable_ctx_md_params, ps_signature_rsa_gettable_ctx_md_params);
DISP_SIG(gettable_ctx_md_params, ps_signature_ec_gettable_ctx_md_params);
DISP_SIG(set_ctx_md_params, ps_signature_op_set_ctx_md_params);
DISP_SIG(settable_ctx_md_params, ps_signature_rsa_settable_ctx_md_params);
DISP_SIG(settable_ctx_md_params, ps_signature_ec_settable_ctx_md_params);

static void *ps_signature_rsa_newctx(void *vprovctx, const char *propq)
{
	struct provider_ctx *pctx = vprovctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p propq: %s", pctx,
		     propq != NULL ? propq : "");
	return signature_op_ctx_new(pctx, propq, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_gettable_ctx_params(void *vctx,
							      void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;
	struct op_ctx *opctx = vctx;

	if (!opctx || !pctx)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p, pctx: %p",
		       opctx, pctx);

	if (pctx != opctx->pctx)
		return NULL;

	return ps_signature_op_gettable_ctx_params(opctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_settable_ctx_params(void *vctx,
							      void *vpctx)
{
	struct provider_ctx *pctx = vpctx;
	struct op_ctx *opctx = vctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_signature_op_settable_ctx_params(opctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_gettable_ctx_md_params(void *vctx)
{
	struct op_ctx *opctx = vctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_gettable_ctx_md_params(opctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_signature_rsa_settable_ctx_md_params(void *vctx)
{
	struct op_ctx *opctx = vctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_settable_ctx_md_params(opctx, EVP_PKEY_RSA);
}

static int ps_signature_rsa_sign_init(void *vopctx,
				      void *vkey,
				      const OSSL_PARAM params[])
{
	CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;

	ps_opctx_debug(opctx, "opctx: %p key: %p",
		       opctx, key);

	return ps_signature_op_sign_init(opctx, key, params, &mech);
}

static int ps_signature_rsa_digest_sign_init(void *vopctx,
					     const char *mdname,
					     void *vkey,
					     const OSSL_PARAM params[])
{
	CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p", opctx,
			mdname != NULL ? mdname : "", key);
	return ps_signature_op_digest_sign_init(opctx, mdname, key, params, &mech);
}

static void *ps_signature_ec_newctx(void *vpctx, const char *propq)
{
	struct provider_ctx *pctx = vpctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p propq: %s", pctx,
		     propq != NULL ? propq : "");
	return signature_op_ctx_new(pctx, propq, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_gettable_ctx_params(void *vopctx,
							     void *vpctx)
{
	struct op_ctx *opctx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (!opctx || !pctx)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p, pctx: %p",
		       opctx, pctx);

	if (pctx != opctx->pctx)
		return NULL;

	return ps_signature_op_gettable_ctx_params(opctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_settable_ctx_params(void *vopctx,
							     void *vpctx)
{
	struct op_ctx *opctx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (pctx == NULL)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_signature_op_settable_ctx_params(opctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_gettable_ctx_md_params(void *vopctx)
{
	struct op_ctx *opctx = vopctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_gettable_ctx_md_params(opctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_signature_ec_settable_ctx_md_params(void *vopctx)
{
	struct op_ctx *opctx = vopctx;

	if (opctx == NULL)
		return NULL;

	ps_opctx_debug(opctx, "opctx: %p", opctx);
	return ps_signature_op_settable_ctx_md_params(opctx, EVP_PKEY_EC);
}

static int ps_signature_ec_sign_init(void *vopctx,
				     void *vkey,
				     const OSSL_PARAM params[])
{
	CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;

	ps_opctx_debug(opctx, "opctx: %p key: %p",
		       opctx, key);

	return ps_signature_op_sign_init(opctx, key, params, &mech);
}

static int ps_signature_ec_digest_sign_init(void *vopctx,
					    const char *mdname,
					    void *vkey,
					    const OSSL_PARAM params[])
{
	CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
	struct op_ctx *opctx = vopctx;
	struct obj *key = vkey;

	ps_opctx_debug(opctx, "opctx: %p mdname: %s key: %p", opctx,
			mdname != NULL ? mdname : "", key);
	return ps_signature_op_digest_sign_init(opctx, mdname, key, params, &mech);
}

static const OSSL_DISPATCH ps_rsa_signature_functions[] = {
	/* Signature context constructor, descructor */
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ps_signature_rsa_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))op_ctx_free},
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ps_signature_op_dupctx },
	/* Signing */
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ps_signature_rsa_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ps_signature_op_sign },
	/* Verifying */
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))ps_signature_op_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ps_signature_op_verify },
	/* Verify recover */
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void))ps_signature_op_verify_recover_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, (void (*)(void))ps_signature_op_verify_recover },
	/* Digest Sign */
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))ps_signature_rsa_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))ps_signature_op_digest_sign_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))ps_signature_op_digest_sign_final },
	/* Digest Verify */
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))ps_signature_op_digest_verify_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))ps_signature_op_digest_verify_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))ps_signature_op_digest_verify_final },
	/* Signature parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))ps_signature_op_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))ps_signature_rsa_gettable_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))ps_signature_op_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))ps_signature_rsa_settable_ctx_params },
	/* MD parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))ps_signature_op_get_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))ps_signature_rsa_gettable_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))ps_signature_op_set_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))ps_signature_rsa_settable_ctx_md_params },
	{ 0, NULL }
};

static const OSSL_DISPATCH ps_ecdsa_signature_functions[] = {
	/* Signature context constructor, descructor */
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ps_signature_ec_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))op_ctx_free },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ps_signature_op_dupctx },
	/* Signing */
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ps_signature_ec_sign_init },
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ps_signature_op_sign },
	/* Verifying */
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))ps_signature_op_verify_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ps_signature_op_verify },
	/* Verify recover */
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, (void (*)(void))ps_signature_op_verify_recover_init },
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, (void (*)(void))ps_signature_op_verify_recover },
	/* Digest Sign */
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))ps_signature_ec_digest_sign_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))ps_signature_op_digest_sign_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
			(void (*)(void))ps_signature_op_digest_sign_final },
	/* Digest Verify */
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))ps_signature_op_digest_verify_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))ps_signature_op_digest_verify_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))ps_signature_op_digest_verify_final },
	/* Signature parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))ps_signature_op_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))ps_signature_ec_gettable_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))ps_signature_op_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))ps_signature_ec_settable_ctx_params },
	/* MD parameters */
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))ps_signature_op_get_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))ps_signature_ec_gettable_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))ps_signature_op_set_ctx_md_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))ps_signature_ec_settable_ctx_md_params },
	{ 0, NULL }
};

const OSSL_ALGORITHM ps_signature[] = {
	{ "RSA:rsaEncryption", "provider="PS_PROV_NAME,
				ps_rsa_signature_functions, NULL },
	{ "ECDSA", "provider="PS_PROV_NAME,
				ps_ecdsa_signature_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};
