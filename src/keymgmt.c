/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 * Authors: Holger Dengler <dengler@linux.ibm.com>
 *          Ingo Franzki <ifranzki@linux.ibm.com>
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>

#include "common.h"
#include "pkcs11.h"
#include "ossl.h"
#include "debug.h"
#include "object.h"

static int op_ctx_init_fwd(struct op_ctx *octx, int selection, const OSSL_PARAM params[], int type)
{
	OSSL_FUNC_keymgmt_gen_cleanup_fn *fwd_gen_cleanup_fn;
	OSSL_FUNC_keymgmt_gen_init_fn *fwd_gen_init_fn;
	struct ossl_provider *fwd = &octx->pctx->fwd;

	if (!octx)
		return OSSL_RV_ERR;

	fwd_gen_init_fn = (OSSL_FUNC_keymgmt_gen_init_fn *)
		fwd_keymgmt_get_func(fwd, type,
				     OSSL_FUNC_KEYMGMT_GEN_INIT,
				     &octx->pctx->dbg);
	if (!fwd_gen_init_fn) {
		put_error_pctx(octx->pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no fwd gen_init_fn");
		return OSSL_RV_ERR;
	}

	fwd_gen_cleanup_fn = (OSSL_FUNC_keymgmt_gen_cleanup_fn *)
		fwd_keymgmt_get_func(fwd, type,
				     OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
				     &octx->pctx->dbg);
	if (!fwd_gen_cleanup_fn) {
		put_error_pctx(octx->pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no fwd gen_cleanup_fn");
		return OSSL_RV_ERR;
	}

	octx->fwd_op_ctx = fwd_gen_init_fn(fwd->ctx,
					   selection, params);
	if (!octx->fwd_op_ctx) {
		put_error_pctx(octx->pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_gen_init_fn failed");
		return OSSL_RV_ERR;
	}
	octx->fwd_op_ctx_free = fwd_gen_cleanup_fn;

	return OSSL_RV_OK;
}

static void *keymgmt_fwd_new(struct provider_ctx *pctx, int type)
{
	OSSL_FUNC_keymgmt_new_fn *fwd_new_fn;
	struct dbg *dbg = &pctx->dbg;

	fwd_new_fn = (OSSL_FUNC_keymgmt_new_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, type,
				     OSSL_FUNC_KEYMGMT_NEW,
				     dbg);
	if (!fwd_new_fn)
		return NULL;

	return fwd_new_fn(&pctx->fwd.ctx);
}

static int keymgmt_fetch_pki(struct obj *key)
{
	OSSL_FUNC_keymgmt_import_fn *fwd_import_fn;
	int selection, rv = OSSL_RV_OK;
	OSSL_PARAM *params = NULL;
	EVP_PKEY *pkey = NULL;
	CK_BYTE_PTR pki;
	CK_ULONG pkilen;

	if (obj_get_pub_key_info(key, &pki, &pkilen) != OSSL_RV_OK) {
		ps_obj_debug(key, "key: %p, no public_key_info available",
			     key);
		return OSSL_RV_ERR;
	}

	pkey = d2i_PUBKEY(NULL, (const unsigned char **)&pki, pkilen);
	if (!pkey) {
		ps_obj_debug(key, "key: %p, unable to parse public_key_info",
			     key);
		return OSSL_RV_ERR;
	}

	selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
		    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS |
		    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
	if (EVP_PKEY_todata(pkey, selection, &params) != OSSL_RV_OK) {
		ps_obj_debug(key, "key: %p, unable to get params",
			     key);
		rv = OSSL_RV_ERR;
		goto out;
	}

	fwd_import_fn = (OSSL_FUNC_keymgmt_import_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_IMPORT,
				     &key->pctx->dbg);
	if (fwd_import_fn == NULL) {
		ps_obj_debug(key, "key: %p, no fwd_import_fn",
			     key);
		rv = OSSL_RV_ERR;
		goto out;
	}

	if (fwd_import_fn(key->fwd_key, selection, params) != OSSL_RV_OK) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_import_fn failed");
		rv = OSSL_RV_ERR;
		goto out;
	}

out:
	EVP_PKEY_free(pkey);
	OSSL_PARAM_free(params);
	return rv;
}

static struct obj *keymgmt_new(struct provider_ctx *pctx,
			       int type)
{
	struct obj *key;

	ps_pctx_debug(pctx, "pctx: %p, type: %d",
		      pctx, type);

	key = obj_new_init(pctx, CK_UNAVAILABLE_INFORMATION, NULL);
	if (!key) {
		put_error_pctx(pctx, PS_ERR_MALLOC_FAILED,
			       "OPENSSL_zalloc failed");
		return NULL;
	}

	key->fwd_key = keymgmt_fwd_new(pctx, type);
	if (!key->fwd_key)
		goto err;

	key->type = type;
	key->use_pkcs11 = false;

	ps_pctx_debug(pctx, "pctx: %p, type: %d, --> key: %p, fwd_key: %p",
		      pctx, type, key, key->fwd_key);
	return key;
err:
	obj_free(key);
	return NULL;
}

static const OSSL_PARAM *keymgmt_gettable_params(struct provider_ctx *pctx,
						 int type)
{
	OSSL_FUNC_keymgmt_gettable_params_fn *fwd_gettable_params_fn;

	ps_pctx_debug(pctx, "pctx: %p, type: %d",
		      pctx, type);

	fwd_gettable_params_fn = (OSSL_FUNC_keymgmt_gettable_params_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, type,
				     OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
				     &pctx->dbg);

	/* fwd_gettable_params_fn is optional */
	return (fwd_gettable_params_fn) ?
		fwd_gettable_params_fn(pctx->fwd.ctx) :
		NULL;
}

static const OSSL_PARAM *keymgmt_settable_params(struct provider_ctx *pctx,
						 int type)
{
	OSSL_FUNC_keymgmt_settable_params_fn *fwd_settable_params_fn;

	ps_pctx_debug(pctx, "pctx: %p, type: %d",
		      pctx, type);

	fwd_settable_params_fn = (OSSL_FUNC_keymgmt_settable_params_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, type,
				     OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
				     &pctx->dbg);

	/* fwd_settable_params_fn is optional */
	return (fwd_settable_params_fn) ?
		fwd_settable_params_fn(fwd_settable_params_fn) :
		NULL;
}

static const OSSL_PARAM *keymgmt_export_types(int selection,
					      int type)
{
	if (hack_dbg)
		ps_dbg_debug(hack_dbg, "selection: %d type: %d",
			     selection, type);

	/* not supported */
	return NULL;
}

static const OSSL_PARAM *keymgmt_import_types(int selection,
					      int type)
{
	if (hack_dbg)
		ps_dbg_debug(hack_dbg, "selection: %d type: %d",
			     selection, type);

	/* not supported */
	return NULL;
}

static struct op_ctx *keymgmt_gen_init(struct provider_ctx *pctx, int selection,
				       const OSSL_PARAM params[], int type)
{
	struct op_ctx *octx;
	const OSSL_PARAM *p;

	ps_pctx_debug(pctx, "pctx: %p, selection: %d, type: %d",
		      pctx, selection, type);

	for (p = params; (p && p->key); p++)
		ps_pctx_debug(pctx, "param: %s (0x%x)", p->key, p->data_type);

	octx = op_ctx_new(pctx, NULL, type);
	if (!octx) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "ps_op_newctx failed");
		return NULL;
	}

	if (!op_ctx_init(octx, NULL, EVP_PKEY_OP_KEYGEN)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "ps_op_init failed");
		goto err;
	}

	if (op_ctx_init_fwd(octx, selection, params, type) != OSSL_RV_OK)
		goto err;

	ps_pctx_debug(pctx, "octx: %p", octx);
	return octx;

err:
	op_ctx_free(octx);
	return NULL;
}

static const OSSL_PARAM *keymgmt_gen_settable_params(struct op_ctx *octx,
						     int type)
{
	OSSL_FUNC_keymgmt_gen_settable_params_fn *fwd_gen_settable_params_fn;

	if (octx)
		return NULL;

	ps_opctx_debug(octx, "pctx: %p, octx: %p, type: %d",
		       octx->pctx, octx, type);

	if (octx->fwd_op_ctx)
		goto fwd;

	/* not supported */
	return NULL;

fwd:
	fwd_gen_settable_params_fn = (OSSL_FUNC_keymgmt_gen_settable_params_fn *)
		fwd_keymgmt_get_func(&octx->pctx->fwd,
				     type, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
				     &octx->pctx->dbg);

	return (fwd_gen_settable_params_fn) ?
		fwd_gen_settable_params_fn(octx->fwd_op_ctx, octx->pctx->fwd.ctx) :
		NULL;
}

#define DISP_KMGMT_FN(tname, name) DECL_DISPATCH_FUNC(keymgmt, tname, name)
DISP_KMGMT_FN(free,		ps_keymgmt_free);
DISP_KMGMT_FN(gen_cleanup,	ps_keymgmt_gen_cleanup);
DISP_KMGMT_FN(load,		ps_keymgmt_load);
DISP_KMGMT_FN(gen_set_template,	ps_keymgmt_gen_set_template);
DISP_KMGMT_FN(gen_set_params,	ps_keymgmt_gen_set_params);
DISP_KMGMT_FN(gen,		ps_keymgmt_gen);
DISP_KMGMT_FN(get_params,	ps_keymgmt_get_params);
DISP_KMGMT_FN(set_params,	ps_keymgmt_set_params);
DISP_KMGMT_FN(has,		ps_keymgmt_has);
DISP_KMGMT_FN(match,		ps_keymgmt_match);
DISP_KMGMT_FN(validate,		ps_keymgmt_validate);
DISP_KMGMT_FN(export,		ps_keymgmt_export);
DISP_KMGMT_FN(import,		ps_keymgmt_import);

static void ps_keymgmt_free(void *vkey)
{
	OSSL_FUNC_keymgmt_free_fn *fwd_free_fn;
	struct obj *key = vkey;

	if (!key)
		return;

	ps_obj_debug(key, "key: %p", key);

	fwd_free_fn = (OSSL_FUNC_keymgmt_free_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_FREE,
				     &key->pctx->dbg);

	if (key->fwd_key && fwd_free_fn) {
		ps_obj_debug(key, "free fwd_key: %p", key->fwd_key);
		fwd_free_fn(key->fwd_key);
	}

	obj_free(key);
}

static int keymgmt_match_fwd(const struct obj *key1, const struct obj *key2,
			     int selection)
{
	OSSL_FUNC_keymgmt_match_fn *fwd_match_fn;
	int rv;

	ps_obj_debug(key1, "key1: %p key2: %p, selection: %d",
		     key1, key2, selection);

	fwd_match_fn = (OSSL_FUNC_keymgmt_match_fn *)
			fwd_keymgmt_get_func(&key1->pctx->fwd,
					key1->type, OSSL_FUNC_KEYMGMT_MATCH,
					&key1->pctx->dbg);
	if (!fwd_match_fn) {
		put_error_key(key1, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no fwd match_fn");
		rv = OSSL_RV_FALSE;
		goto out;
	}

	rv = fwd_match_fn(key1->fwd_key, key2->fwd_key, selection);
out:
	ps_obj_debug(key1, "key1: %p key2: %p, selection: %d --> %s",
		     key1, key2, selection,
		     (rv == OSSL_RV_TRUE) ? "match" : "mismatch");
	return rv;
}

static int ps_keymgmt_match(const void *vkey1, const void *vkey2,
			    int selection)
{
	const struct obj *key1 = vkey1, *key2 = vkey2;

	if (!key1 || !key2)
		return OSSL_RV_FALSE;

	ps_obj_debug(key1, "key1: %p key2: %p, selection: %d",
		     key1, key2, selection);

	return keymgmt_match_fwd(key1, key2, selection);
}

static int ps_keymgmt_validate_fwd(const struct obj *key,
				   int selection, int checktype)
{
	OSSL_FUNC_keymgmt_validate_fn *fwd_validate_fn;

	fwd_validate_fn = (OSSL_FUNC_keymgmt_validate_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_VALIDATE,
				     &key->pctx->dbg);
	if (!fwd_validate_fn) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default validate_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_validate_fn(key->fwd_key, selection,
			       checktype) != OSSL_RV_OK) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_validate_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_keymgmt_validate(const void *vkey,
			       int selection, int checktype)
{
	const struct obj *key = vkey;

	if (!key)
		return OSSL_RV_ERR;

	ps_obj_debug(key, "key: %p selection: %d checktype: %d",
		     key, selection, checktype);

	if (!key->use_pkcs11)
		return ps_keymgmt_validate_fwd(key, selection, checktype);

	if (key->type != checktype)
		return OSSL_RV_ERR;

	if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return OSSL_RV_ERR;

	return OSSL_RV_OK;
}

static int ps_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_get_params_fn *fwd_get_params_fn;
	struct obj *key = vkey;
	OSSL_PARAM *p;

	if (!key)
		return OSSL_RV_ERR;

	ps_obj_debug(key, "key: %p", key);
	for (p = params; (p && p->key); p++)
		ps_obj_debug(key, "param: %s (0x%x)", p->key, p->data_type);

	/* get params of fwd key first */
	fwd_get_params_fn = (OSSL_FUNC_keymgmt_get_params_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_GET_PARAMS,
				     &key->pctx->dbg);
	if (!fwd_get_params_fn)
		return OSSL_RV_OK;

	if (fwd_get_params_fn(key->fwd_key, params) != OSSL_RV_OK) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_get_params_fn failed");
		return OSSL_RV_ERR;
	}

	/* no parameters supported for pkcs11 keys */
	return OSSL_RV_OK;
}

static int ps_keymgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_set_params_fn *fwd_set_params_fn;
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (!key)
		return OSSL_RV_ERR;

	ps_obj_debug(key, "key: %p", key);
	for (p = params; (p && p->key); p++)
		ps_obj_debug(key, "param: %s (0x%x)", p->key, p->data_type);

	fwd_set_params_fn = (OSSL_FUNC_keymgmt_set_params_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_SET_PARAMS,
				     &key->pctx->dbg);
	if (!fwd_set_params_fn)
		return OSSL_RV_OK;

	if (fwd_set_params_fn(key->fwd_key, params) != OSSL_RV_OK) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_set_params_fn failed");
		return OSSL_RV_ERR;
	}

	if (!key->use_pkcs11)
		return OSSL_RV_OK;

	/* no parameters supported for pkcs11 keys */
	return OSSL_RV_OK;
}

static int ps_keymgmt_has_fwd(const struct obj *key, int selection)
{
	OSSL_FUNC_keymgmt_has_fn *fwd_has_fn;

	fwd_has_fn = (OSSL_FUNC_keymgmt_has_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd, key->type,
				     OSSL_FUNC_KEYMGMT_HAS, &key->pctx->dbg);
	if (!fwd_has_fn) {
		put_error_key(key,
			      PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no fwd_has_fn");
		return OSSL_RV_FALSE;
	}

	if (fwd_has_fn(key->fwd_key, selection) != OSSL_RV_OK) {
		put_error_key(key,
			      PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_has_fn failed");
		return OSSL_RV_FALSE;
	}

	return OSSL_RV_OK;
}

static int ps_keymgmt_has(const void *vkey, int selection)
{
	const struct obj *key = vkey;
	int rv = OSSL_RV_FALSE;

	if (key == NULL)
		return rv;

	ps_obj_debug(key, "key: %p, selection: %d",
		     key, selection);

	if (!key->use_pkcs11)
		return ps_keymgmt_has_fwd(key, selection);

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		switch (obj_get_class(key)) {
		case CKO_PRIVATE_KEY:
			rv = OSSL_RV_TRUE;
			break;
		default:
			break;
		}
	}

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		switch (obj_get_class(key)) {
		case CKO_PRIVATE_KEY:
		case CKO_PUBLIC_KEY:
		case CKO_CERTIFICATE:
			rv = OSSL_RV_TRUE;
			break;
		default:
			break;
		}
	}

	return rv;
}

static int ps_keymgmt_export_fwd(struct obj *key, int selection,
				 OSSL_CALLBACK *param_callback, void *cbarg)
{
	OSSL_FUNC_keymgmt_export_fn *fwd_export_fn;

	fwd_export_fn = (OSSL_FUNC_keymgmt_export_fn *)
			fwd_keymgmt_get_func(&key->pctx->fwd,
					key->type, OSSL_FUNC_KEYMGMT_EXPORT,
					&key->pctx->dbg);
	if (fwd_export_fn == NULL) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default export_fn");
		return OSSL_RV_ERR;
	}

	if (!fwd_export_fn(key->fwd_key, selection, param_callback, cbarg)) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_export_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_keymgmt_export(void *vkey, int selection,
			     OSSL_CALLBACK *param_callback, void *cbarg)
{
	struct obj *key = vkey;

	if (!key || !param_callback)
		return OSSL_RV_ERR;

	ps_obj_debug(key, "key: %p selection: %d",
		     key, selection);

	if (key->use_pkcs11 &&
	    (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return OSSL_RV_ERR;

	if (ps_keymgmt_export_fwd(key, selection,
				  param_callback, cbarg) != OSSL_RV_OK) {
		ps_obj_debug(key, "ps_keymgmt_export_fwd() failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_keymgmt_import_fwd(struct obj *key, int selection,
				 const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_import_fn *fwd_import_fn;

	fwd_import_fn = (OSSL_FUNC_keymgmt_import_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_IMPORT,
				     &key->pctx->dbg);
	if (fwd_import_fn == NULL) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default import_fn");
		return OSSL_RV_ERR;
	}

	if (fwd_import_fn(key->fwd_key, selection, params) != OSSL_RV_OK) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_import_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_keymgmt_import(void *vkey, int selection,
			     const OSSL_PARAM params[])
{
	struct obj *key = vkey;
	const OSSL_PARAM *p;

	if (key == NULL)
		return OSSL_RV_ERR;

	ps_obj_debug(key, "key: %p selection: %d",
		     key, selection);
	for (p = params; (p && p->key); p++)
		ps_obj_debug(key, "param: %s (0x%x)", p->key, p->data_type);

	if (!key->use_pkcs11)
		return  ps_keymgmt_import_fwd(vkey, selection, params);

	/* not supported */
	return OSSL_RV_ERR;
}

static void ps_keymgmt_gen_cleanup(void *vgenctx)
{
	struct op_ctx *octx = vgenctx;

	if (!octx)
		return;

	ps_opctx_debug(octx, "octx: %p", octx);
	op_ctx_free(octx);
}

static int ps_keymgmt_gen_set_params(void *vgenctx,
				     const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_gen_set_params_fn *fwd_gen_set_params_fn;
	struct op_ctx *octx = vgenctx;
	const OSSL_PARAM *p;

	if (!octx)
		return OSSL_RV_ERR;

	ps_opctx_debug(octx, "octx: %p", octx);
	for (p = params; (p && p->key); p++)
		ps_opctx_debug(octx, "param: %s (0x%x)", p->key, p->data_type);

	fwd_gen_set_params_fn = (OSSL_FUNC_keymgmt_gen_set_params_fn *)
		fwd_keymgmt_get_func(&octx->pctx->fwd, octx->type,
				     OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
				     &octx->pctx->dbg);
	if (!fwd_gen_set_params_fn)
		return OSSL_RV_OK;

	if (fwd_gen_set_params_fn(octx->fwd_op_ctx, params) != OSSL_RV_OK) {
		put_error_op_ctx(octx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_gen_set_params_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static int ps_keymgmt_gen_set_template(void *vgenctx, void *vtempl)
{
	OSSL_FUNC_keymgmt_gen_set_template_fn *fwd_gen_set_template_fn;
	struct op_ctx *octx = vgenctx;
	struct obj *templ = vtempl;

	if (!octx || !templ)
		return OSSL_RV_ERR;

	ps_opctx_debug(octx, "octx: %p, templ: %p",
		     octx, templ);

	fwd_gen_set_template_fn = (OSSL_FUNC_keymgmt_gen_set_template_fn *)
		fwd_keymgmt_get_func(&octx->pctx->fwd, octx->type,
				     OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
				     &octx->pctx->dbg);

	if (octx->fwd_op_ctx)
		goto fwd;

	return OSSL_RV_ERR;

fwd:
	if (!fwd_gen_set_template_fn) {
		put_error_op_ctx(octx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default get_set_template_fn");
		return 0;
	}

	return fwd_gen_set_template_fn(octx->fwd_op_ctx, templ->fwd_key);
}

static void *ps_keymgmt_gen(void *vgenctx,
			    OSSL_CALLBACK *osslcb, void *cbarg)
{
	OSSL_FUNC_keymgmt_gen_fn *fwd_gen_fn;
	struct op_ctx *octx = vgenctx;
	struct obj *key;
	void *pkey;

	if (!octx)
		return NULL;

	ps_opctx_debug(octx, "octx: %p", octx);

	fwd_gen_fn = (OSSL_FUNC_keymgmt_gen_fn *)
		fwd_keymgmt_get_func(&octx->pctx->fwd, octx->type,
				     OSSL_FUNC_KEYMGMT_GEN, &octx->pctx->dbg);
	if (!fwd_gen_fn) {
		put_error_op_ctx(octx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default gen_fn");
		return NULL;
	}

	key = obj_new_init(octx->pctx, CK_UNAVAILABLE_INFORMATION, NULL);
	if (!key) {
		put_error_op_ctx(octx, PS_ERR_MALLOC_FAILED,
				 "OPENSSL_zalloc failed");
		return NULL;
	}

	pkey = fwd_gen_fn(octx->fwd_op_ctx, osslcb, cbarg);
	if (!pkey) {
		put_error_op_ctx(octx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
				 "fwd_gen_fn failed");
		obj_free(key);
		return NULL;
	}

	key->type = octx->type;
	key->use_pkcs11 = false;
	key->fwd_key = pkey;

	ps_opctx_debug(octx, "key: %p", key);

	return key;
}

static void *ps_keymgmt_load(const void *reference, size_t reference_sz)
{
	struct obj *key;

	if (!reference || (reference_sz != sizeof(struct obj)))
		return NULL;

	key = obj_get((struct obj *)reference);
	key->use_pkcs11 = (obj_get_class(key) == CKO_PRIVATE_KEY);

	key->fwd_key = keymgmt_fwd_new(key->pctx, key->type);
	if (!key->fwd_key)
		goto err;

	if (keymgmt_fetch_pki(key) != OSSL_RV_OK)
		goto err;

	ps_obj_debug(key, "key: %p", key);
	return key;

err:
	obj_free(key);
	return NULL;
}

DISP_KMGMT_FN(new,			ps_keymgmt_rsa_new);
DISP_KMGMT_FN(gen_init,			ps_keymgmt_rsa_gen_init);
DISP_KMGMT_FN(gen_settable_params,	ps_keymgmt_rsa_gen_settable_params);
DISP_KMGMT_FN(gettable_params,		ps_keymgmt_rsa_gettable_params);
DISP_KMGMT_FN(settable_params,		ps_keymgmt_rsa_settable_params);
DISP_KMGMT_FN(export_types,		ps_keymgmt_rsa_export_types);
DISP_KMGMT_FN(import_types,		ps_keymgmt_rsa_import_types);
DISP_KMGMT_FN(query_operation_name,	ps_keymgmt_rsa_query_operation_name);

static void *ps_keymgmt_rsa_new(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_new(pctx, EVP_PKEY_RSA);
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

static const OSSL_PARAM *ps_keymgmt_rsa_gettable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_gettable_params(pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_settable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_settable_params(pctx, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_export_types(int selection)
{
	return keymgmt_export_types(selection, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_import_types(int selection)
{
	return keymgmt_import_types(selection, EVP_PKEY_RSA);
}

static void *ps_keymgmt_rsa_gen_init(void *vpctx, int selection,
				     const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_gen_init(pctx, selection, params, EVP_PKEY_RSA);
}

static const OSSL_PARAM *ps_keymgmt_rsa_gen_settable_params(void *vopctx,
							    void *vpctx)
{
	struct op_ctx *octx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx || !octx || octx->pctx != pctx)
		return NULL;

	return keymgmt_gen_settable_params(octx, EVP_PKEY_RSA);
}

#define DISP_KMGMT_ELEM(NAME, name) \
	{ OSSL_FUNC_KEYMGMT_##NAME, (void (*)(void))name }

static const OSSL_DISPATCH ps_keymgmt_functions_rsa[] = {
	/* Constructor, destructor */
	DISP_KMGMT_ELEM(NEW,		ps_keymgmt_rsa_new),
	DISP_KMGMT_ELEM(FREE,		ps_keymgmt_free),

	/* Key generation and loading */
	DISP_KMGMT_ELEM(GEN_INIT,		ps_keymgmt_rsa_gen_init),
	DISP_KMGMT_ELEM(GEN_SET_TEMPLATE,	ps_keymgmt_gen_set_template),
	DISP_KMGMT_ELEM(GEN_SET_PARAMS,		ps_keymgmt_gen_set_params),
	DISP_KMGMT_ELEM(GEN_SETTABLE_PARAMS,	ps_keymgmt_rsa_gen_settable_params),
	DISP_KMGMT_ELEM(GEN,			ps_keymgmt_gen),
	DISP_KMGMT_ELEM(GEN_CLEANUP,		ps_keymgmt_gen_cleanup),
	DISP_KMGMT_ELEM(LOAD,			ps_keymgmt_load),

	/* Key object checking */
	DISP_KMGMT_ELEM(HAS,			ps_keymgmt_has),
	DISP_KMGMT_ELEM(MATCH,			ps_keymgmt_match),
	DISP_KMGMT_ELEM(VALIDATE,		ps_keymgmt_validate),
	DISP_KMGMT_ELEM(QUERY_OPERATION_NAME,	ps_keymgmt_rsa_query_operation_name),

	/* Key object information */
	DISP_KMGMT_ELEM(GET_PARAMS,		ps_keymgmt_get_params),
	DISP_KMGMT_ELEM(GETTABLE_PARAMS,	ps_keymgmt_rsa_gettable_params),
	DISP_KMGMT_ELEM(SET_PARAMS,		ps_keymgmt_set_params),
	DISP_KMGMT_ELEM(SETTABLE_PARAMS,	ps_keymgmt_rsa_settable_params),

	/* Import and export routines */
	DISP_KMGMT_ELEM(EXPORT,			ps_keymgmt_export),
	DISP_KMGMT_ELEM(EXPORT_TYPES,		ps_keymgmt_rsa_export_types),
	DISP_KMGMT_ELEM(IMPORT,			ps_keymgmt_import),
	DISP_KMGMT_ELEM(IMPORT_TYPES,		ps_keymgmt_rsa_import_types),
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

DISP_KMGMT_FN(new,			ps_keymgmt_rsapss_new);
DISP_KMGMT_FN(gen_init,			ps_keymgmt_rsapss_gen_init);
DISP_KMGMT_FN(gen_settable_params,	ps_keymgmt_rsapss_gen_settable_params);
DISP_KMGMT_FN(gettable_params,		ps_keymgmt_rsapss_gettable_params);
DISP_KMGMT_FN(settable_params,		ps_keymgmt_rsapss_settable_params);
DISP_KMGMT_FN(export_types,		ps_keymgmt_rsapss_export_types);
DISP_KMGMT_FN(import_types,		ps_keymgmt_rsapss_import_types);

static void *ps_keymgmt_rsapss_new(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	return keymgmt_new(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_gettable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_gettable_params(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_settable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	return keymgmt_settable_params(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_export_types(int selection)
{
	return keymgmt_export_types(selection, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_import_types(int selection)
{
	return keymgmt_import_types(selection, EVP_PKEY_RSA_PSS);
}

static void *ps_keymgmt_rsapss_gen_init(void *vpctx, int selection,
					 const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_gen_init(pctx, selection, params, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_gen_settable_params(void *vopctx,
							       void *vpctx)
{
	struct op_ctx *octx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx || !octx || octx->pctx != pctx)
		return NULL;

	ps_pctx_debug(pctx, "pctx: %p, octx: %p",
		      pctx, octx);
	return keymgmt_gen_settable_params(octx, EVP_PKEY_RSA_PSS);
}

static const OSSL_DISPATCH ps_keymgmt_functions_rsapss[] = {
	/* Constructor, destructor */
	DISP_KMGMT_ELEM(NEW,			ps_keymgmt_rsapss_new),
	DISP_KMGMT_ELEM(FREE,			ps_keymgmt_free),

	/* Key generation and loading */
	DISP_KMGMT_ELEM(GEN_INIT,		ps_keymgmt_rsapss_gen_init),
	DISP_KMGMT_ELEM(GEN_SET_TEMPLATE,	ps_keymgmt_gen_set_template),
	DISP_KMGMT_ELEM(GEN_SET_PARAMS,		ps_keymgmt_gen_set_params),
	DISP_KMGMT_ELEM(GEN_SETTABLE_PARAMS,	ps_keymgmt_rsapss_gen_settable_params),
	DISP_KMGMT_ELEM(GEN,			ps_keymgmt_gen),
	DISP_KMGMT_ELEM(GEN_CLEANUP,		ps_keymgmt_gen_cleanup),
	DISP_KMGMT_ELEM(LOAD,			ps_keymgmt_load),

	/* Key object checking */
	DISP_KMGMT_ELEM(HAS,			ps_keymgmt_has),
	DISP_KMGMT_ELEM(MATCH,			ps_keymgmt_match),
	DISP_KMGMT_ELEM(VALIDATE,		ps_keymgmt_validate),
	DISP_KMGMT_ELEM(QUERY_OPERATION_NAME,	ps_keymgmt_rsa_query_operation_name),

	/* Key object information */
	DISP_KMGMT_ELEM(GET_PARAMS,		ps_keymgmt_get_params),
	DISP_KMGMT_ELEM(GETTABLE_PARAMS,	ps_keymgmt_rsapss_gettable_params),
	DISP_KMGMT_ELEM(SET_PARAMS,		ps_keymgmt_set_params),
	DISP_KMGMT_ELEM(SETTABLE_PARAMS,	ps_keymgmt_rsapss_settable_params),

	/* Import and export routines */
	DISP_KMGMT_ELEM(EXPORT,			ps_keymgmt_export),
	DISP_KMGMT_ELEM(EXPORT_TYPES,		ps_keymgmt_rsapss_export_types),
	DISP_KMGMT_ELEM(IMPORT,			ps_keymgmt_import),
	DISP_KMGMT_ELEM(IMPORT_TYPES,		ps_keymgmt_rsapss_import_types),
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

DISP_KMGMT_FN(new,			ps_keymgmt_ec_new);
DISP_KMGMT_FN(gen_init,			ps_keymgmt_ec_gen_init);
DISP_KMGMT_FN(gen_settable_params,	ps_keymgmt_ec_gen_settable_params);
DISP_KMGMT_FN(gettable_params,		ps_keymgmt_ec_gettable_params);
DISP_KMGMT_FN(settable_params,		ps_keymgmt_ec_settable_params);
DISP_KMGMT_FN(export_types,		ps_keymgmt_ec_export_types);
DISP_KMGMT_FN(import_types,		ps_keymgmt_ec_import_types);
DISP_KMGMT_FN(query_operation_name,	ps_keymgmt_ec_query_operation_name);

static void *ps_keymgmt_ec_new(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_new(pctx, EVP_PKEY_EC);
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

	return keymgmt_gettable_params(pctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_settable_params(void *vpctx)
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_settable_params(pctx, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_export_types(int selection)
{
	return keymgmt_export_types(selection, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_import_types(int selection)
{
	return keymgmt_import_types(selection, EVP_PKEY_EC);
}

static void *ps_keymgmt_ec_gen_init(void *vpctx, int selection,
				    const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	return keymgmt_gen_init(pctx, selection, params, EVP_PKEY_EC);
}

static const OSSL_PARAM *ps_keymgmt_ec_gen_settable_params(void *vopctx,
							   void *vpctx)
{
	struct op_ctx *octx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx || !octx || octx->pctx != pctx)
		return NULL;

	ps_pctx_debug(pctx, "pctx: %p, octx: %p",
		      pctx, octx);
	return keymgmt_gen_settable_params(octx, EVP_PKEY_EC);
}

static const OSSL_DISPATCH ps_keymgmt_functions_ec[] = {
	/* Constructor, destructor */
	DISP_KMGMT_ELEM(NEW,			ps_keymgmt_ec_new),
	DISP_KMGMT_ELEM(FREE,			ps_keymgmt_free),

	/* Key generation and loading */
	DISP_KMGMT_ELEM(GEN_INIT,		ps_keymgmt_ec_gen_init),
	DISP_KMGMT_ELEM(GEN_SET_TEMPLATE,	ps_keymgmt_gen_set_template),
	DISP_KMGMT_ELEM(GEN_SET_PARAMS,		ps_keymgmt_gen_set_params),
	DISP_KMGMT_ELEM(GEN_SETTABLE_PARAMS,	ps_keymgmt_ec_gen_settable_params),
	DISP_KMGMT_ELEM(GEN,			ps_keymgmt_gen),
	DISP_KMGMT_ELEM(GEN_CLEANUP,		ps_keymgmt_gen_cleanup),
	DISP_KMGMT_ELEM(LOAD,			ps_keymgmt_load),

	/* Key object checking */
	DISP_KMGMT_ELEM(HAS,			ps_keymgmt_has),
	DISP_KMGMT_ELEM(MATCH,			ps_keymgmt_match),
	DISP_KMGMT_ELEM(VALIDATE,		ps_keymgmt_validate),
	DISP_KMGMT_ELEM(QUERY_OPERATION_NAME,	ps_keymgmt_ec_query_operation_name),

	/* Key object information */
	DISP_KMGMT_ELEM(GET_PARAMS,		ps_keymgmt_get_params),
	DISP_KMGMT_ELEM(GETTABLE_PARAMS,	ps_keymgmt_ec_gettable_params),
	DISP_KMGMT_ELEM(SET_PARAMS,		ps_keymgmt_set_params),
	DISP_KMGMT_ELEM(SETTABLE_PARAMS,	ps_keymgmt_ec_settable_params),

	/* Import and export routines */
	DISP_KMGMT_ELEM(EXPORT,			ps_keymgmt_export),
	DISP_KMGMT_ELEM(EXPORT_TYPES,		ps_keymgmt_ec_export_types),
	DISP_KMGMT_ELEM(IMPORT,			ps_keymgmt_import),
	DISP_KMGMT_ELEM(IMPORT_TYPES,		ps_keymgmt_ec_import_types),
	/* No copy function, OpenSSL will use export/import to copy instead */

	{ 0, NULL }
};

const OSSL_ALGORITHM ps_keymgmt[] = {
	{ "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider="PS_PROV_NAME,
				ps_keymgmt_functions_rsa, NULL },
	{ "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10", "provider="PS_PROV_NAME,
				ps_keymgmt_functions_rsapss, NULL },
	{ "EC:id-ecPublicKey:1.2.840.10045.2.1", "provider="PS_PROV_NAME,
				ps_keymgmt_functions_ec, NULL },
	{ NULL, NULL, NULL, NULL }
};

int keymgmt_get_size(struct obj *key)
{
	int size = 0;

	OSSL_PARAM key_params[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, &size),
		OSSL_PARAM_END
	};

	ps_obj_debug(key, "key: %p", key);

	if (ps_keymgmt_get_params(key, key_params) != OSSL_RV_OK ||
	    !OSSL_PARAM_modified(&key_params[0]) ||
	    size <= 0) {
		put_error_key(key, PS_ERR_MISSING_PARAMETER,
			      "failed to get key size");
		return -1;
	}

	ps_obj_debug(key, "key: %p, size: %d", key, size);
	return size;
}
