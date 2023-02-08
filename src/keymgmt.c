/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 * Authors: Holger Dengler <dengler@linux.ibm.com>
 *          Ingo Franzki <ifranzki@linux.ibm.com>
 */

#include <openssl/evp.h>

#include "common.h"
#include "pkcs11.h"
#include "ossl.h"
#include "debug.h"
#include "object.h"

struct op_ctx {
	struct provider_ctx *pctx;
	int type;
	int operation;
	char *prop;
	struct obj *key;

	void *fwd_op_ctx;
	void (*fwd_op_ctx_free)(void *fwd_op_ctx);
};

static void op_ctx_free(struct op_ctx *octx)
{
	obj_free(octx->key);
	OPENSSL_free(octx->prop);
	OPENSSL_free(octx);
}

static struct op_ctx *op_ctx_new(struct provider_ctx *pctx, const char *prop,
				 int type)
{
	struct op_ctx *octx;

	octx = OPENSSL_zalloc(sizeof(struct op_ctx));
	if (!octx)
		return NULL;

	octx->pctx = pctx;
	octx->prop = OPENSSL_strdup(prop);
	octx->type = type;

	return octx;
}

static int op_ctx_init(struct op_ctx *octx, struct obj *key, int operation)
{
	struct dbg *dbg = &octx->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p, operation: %d",
		     key, operation);

	if (!key)
		goto out;

	switch (octx->type) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		if (key->type != EVP_PKEY_RSA &&
		    key->type != EVP_PKEY_RSA_PSS) {
			put_error_op_ctx(octx,
					 PS_ERR_INTERNAL_ERROR,
					 "key type mismatch: ctx type: "
					 "%d key type: %d",
					 octx->type, key->type);
			return 0;
		}
		break;
	case EVP_PKEY_EC:
		if (key->type != EVP_PKEY_EC) {
			put_error_op_ctx(octx,
					 PS_ERR_INTERNAL_ERROR,
					 "key type mismatch: ctx type: "
					 "%d key type: %d",
					 octx->type, key->type);
			return 0;
		}
		break;
	default:
		put_error_op_ctx(octx, PS_ERR_INTERNAL_ERROR,
				 "key type unknown: ctx type: "
				 "%d key type: %d",
				 octx->type, key->type);
		return 0;
	}
out:
	octx->operation = operation;

	/* update/replace key */
	obj_free(octx->key);
	octx->key = obj_get(key);

	return 1;
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

static struct obj *keymgmt_new(struct provider_ctx *pctx,
			       int type)
{
	OSSL_FUNC_keymgmt_new_fn *fwd_new_fn;
	struct dbg *dbg;
	struct obj *key;

	if (!pctx)
		return NULL;
	dbg = &pctx->dbg;

	ps_dbg_debug(dbg, "pctx: %p, type: %d",
		     pctx, type);

	fwd_new_fn = (OSSL_FUNC_keymgmt_new_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, type,
				     OSSL_FUNC_KEYMGMT_NEW,
				     &pctx->dbg);

	if (!fwd_new_fn) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default new_fn");
		return NULL;
	}

	key = obj_new_init(pctx, NULL, CK_UNAVAILABLE_INFORMATION, NULL);
	if (!key) {
		put_error_pctx(pctx, PS_ERR_MALLOC_FAILED,
			       "OPENSSL_zalloc failed");
		return NULL;
	}

	key->fwd_key = fwd_new_fn(pctx->fwd.ctx);
	if (!key->fwd_key) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_new_fn failed");
		goto err;
	}
	key->type = type;

	ps_dbg_debug(dbg, "pctx: %p, key: %p, fwd_key: %p, type: %d",
		     pctx, key, key->fwd_key, type);
	return key;
err:
	obj_free(key);
	return NULL;
}

static void ps_keymgmt_free(void *vkey)
{
	OSSL_FUNC_keymgmt_free_fn *fwd_free_fn;
	struct dbg *dbg;
	struct obj *key = vkey;

	if (!key)
		return;
	dbg = &key->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p", key);

	if (!key->fwd_key)
		goto out;

	fwd_free_fn = (OSSL_FUNC_keymgmt_free_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_FREE,
				     &key->pctx->dbg);

	if (!fwd_free_fn) {
		ps_dbg_debug(dbg, "free fwd_key: %p", key->fwd_key);
		fwd_free_fn(key->fwd_key);
	}
out:
	obj_free(key);
}

static int ps_keymgmt_match(const void *vkey1, const void *vkey2,
				 int selection)
{
	OSSL_FUNC_keymgmt_match_fn *fwd_match_fn;
	const struct obj *key1 = vkey1;
	const struct obj *key2 = vkey2;
	struct dbg *dbg;

	if (!key1 || !key2)
		return OSSL_RV_ERR;
	dbg = &key1->pctx->dbg;

	ps_dbg_debug(dbg, "key1: %p key2: %p", key1, key2);

	fwd_match_fn = (OSSL_FUNC_keymgmt_match_fn *)
			fwd_keymgmt_get_func(&key1->pctx->fwd,
					key1->type, OSSL_FUNC_KEYMGMT_MATCH,
					&key1->pctx->dbg);
	if (!fwd_match_fn) {
		put_error_key(key1, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default match_fn");
		return OSSL_RV_ERR;
	}

	if (key1->type != key2->type)
		return OSSL_RV_ERR;

	return fwd_match_fn(key1->fwd_key, key2->fwd_key,
				selection);
}

static int ps_keymgmt_validate(const void *vkey,
				    int selection, int checktype)
{
	OSSL_FUNC_keymgmt_validate_fn *fwd_validate_fn;
	const struct obj *key = vkey;
	int fwd_selection = selection;
	struct dbg *dbg;

	if (!key)
		return OSSL_RV_ERR;
	dbg = &key->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p selection: %d checktype: %d",
		     key, selection, checktype);

	if (key->fwd_key)
		goto fwd;

	/* not supported */
	return OSSL_RV_ERR;

fwd:
	fwd_validate_fn = (OSSL_FUNC_keymgmt_validate_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_VALIDATE,
				     &key->pctx->dbg);
	if (!fwd_validate_fn) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default validate_fn");
		return OSSL_RV_ERR;
	}

	return fwd_validate_fn(key->fwd_key, fwd_selection,
			       checktype);
}

static int ps_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_get_params_fn *fwd_get_params_fn;
	struct obj *key = vkey;
	struct dbg *dbg;
	OSSL_PARAM *p;

	if (!key)
		return OSSL_RV_ERR;
	dbg = &key->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p", key);
	for (p = params; (p && p->key); p++)
		ps_dbg_debug(dbg, "param: %s", p->key);

	if (key->fwd_key)
		goto fwd;

	/* TODO add get parameter */
	return OSSL_RV_OK;

fwd:
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

	return OSSL_RV_OK;
}


static int ps_keymgmt_set_params(void *vkey, const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_set_params_fn *fwd_set_params_fn;
	struct obj *key = vkey;
	const OSSL_PARAM *p;
	struct dbg *dbg;
	size_t len;

	if (!key)
		return OSSL_RV_ERR;
	dbg = &key->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p", key);
	for (p = params; (p && p->key); p++)
		ps_dbg_debug(dbg, "param: %s", p->key);

	if (key->fwd_key)
		goto fwd;

	/* TODO add set parameter */
	return OSSL_RV_OK;

fwd:
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

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_keymgmt_gettable_params(
				struct provider_ctx *pctx, int type)
{
	OSSL_FUNC_keymgmt_gettable_params_fn *fwd_gettable_params_fn;
	struct dbg *dbg;

	if (pctx == NULL)
		return NULL;
	dbg = &pctx->dbg;

	ps_dbg_debug(dbg, "pctx: %p, type: %d",
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

static const OSSL_PARAM *ps_keymgmt_settable_params(
				struct provider_ctx *pctx, int type)
{
	OSSL_FUNC_keymgmt_settable_params_fn *fwd_settable_params_fn;
	struct dbg *dbg;

	if (pctx == NULL)
		return NULL;
	dbg = &pctx->dbg;

	ps_dbg_debug(dbg, "pctx: %p, type: %d",
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

static int ps_keymgmt_has(const void *vkey, int selection)
{
	OSSL_FUNC_keymgmt_has_fn *fwd_has_fn;
	const struct obj *key = vkey;
	struct dbg *dbg;

	if (key == NULL)
		return OSSL_RV_ERR;
	dbg = &key->pctx->dbg;

	ps_dbg_debug(dbg, "key: %p selection: %x", key,
		     selection);

	if (key->fwd_key)
		goto fwd;

	return OSSL_RV_OK;

fwd:
	fwd_has_fn = (OSSL_FUNC_keymgmt_has_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd, key->type,
				     OSSL_FUNC_KEYMGMT_HAS, &key->pctx->dbg);
	if (!fwd_has_fn) {
		put_error_key(key,
			      PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no fwd_has_fn");
		return OSSL_RV_ERR;
	}

	return fwd_has_fn(key->fwd_key, selection);
}

static int ps_keymgmt_export(void *vkey, int selection,
				  OSSL_CALLBACK *param_callback, void *cbarg)
{
	OSSL_FUNC_keymgmt_export_fn *fwd_export_fn;
	struct obj *key = vkey;

	if (!key || !param_callback)
		return OSSL_RV_ERR;

	ps_dbg_debug(&key->pctx->dbg, "key: %p selection: %x", key, selection);

	if (key->fwd_key)
		goto fwd;

	return OSSL_RV_ERR;

fwd:
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

static int ps_keymgmt_import(void *vkey, int selection,
			     const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_import_fn *fwd_import_fn;
	struct obj *key = vkey;
	const OSSL_PARAM *p;
	struct dbg *dbg;
	size_t len;

	if (key == NULL)
		return OSSL_RV_ERR;

	ps_dbg_debug(&key->pctx->dbg, "key: %p selection: %x", key,
		     selection);
	for (p = params; (p && p->key); p++)
		ps_dbg_debug(dbg, "param: %s", p->key);

	if (key->fwd_key)
		goto fwd;

	/* not supported */
	return OSSL_RV_ERR;

fwd:
	fwd_import_fn = (OSSL_FUNC_keymgmt_import_fn *)
		fwd_keymgmt_get_func(&key->pctx->fwd,
				     key->type, OSSL_FUNC_KEYMGMT_IMPORT,
				     &key->pctx->dbg);
	if (fwd_import_fn == NULL) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			      "no default import_fn");
		return OSSL_RV_ERR;
	}

	if (!fwd_import_fn(key->fwd_key, selection, params)) {
		put_error_key(key, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			      "fwd_import_fn failed");
		return OSSL_RV_ERR;
	}

	return OSSL_RV_OK;
}

static const OSSL_PARAM *ps_keymgmt_export_types(int selection,
						 int type)
{
	/* not supported */
	return NULL;
}

static const OSSL_PARAM *ps_keymgmt_import_types(int selection,
						 int type)
{
	/* not supported */
	return NULL;
}

static struct op_ctx *ps_keymgmt_gen_init(
				struct provider_ctx *pctx, int selection,
				const OSSL_PARAM params[], int type)
{
	OSSL_FUNC_keymgmt_gen_cleanup_fn *fwd_gen_cleanup_fn;
	OSSL_FUNC_keymgmt_gen_init_fn *fwd_gen_init_fn;
	struct dbg *dbg = &pctx->dbg;
	struct op_ctx *octx;
	const OSSL_PARAM *p;

	ps_dbg_debug(dbg, "pctx: %p, selection: %d, type: %d",
		     pctx, selection, type);

	for (p = params; (p && p->key); p++)
		ps_dbg_debug(dbg, "param: %s", p->key);

	fwd_gen_init_fn = (OSSL_FUNC_keymgmt_gen_init_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, type,
				     OSSL_FUNC_KEYMGMT_GEN_INIT,
				     &pctx->dbg);
	if (!fwd_gen_init_fn) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default gen_init_fn");
		return NULL;
	}

	fwd_gen_cleanup_fn = (OSSL_FUNC_keymgmt_gen_cleanup_fn *)
		fwd_keymgmt_get_func(&pctx->fwd, type,
				     OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
				     &pctx->dbg);
	if (fwd_gen_cleanup_fn == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
			       "no default gen_cleanup_fn");
		return NULL;
	}

	octx = op_ctx_new(pctx, NULL, type);
	if (!octx) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "ps_op_newctx failed");
		return NULL;
	}

	if (!op_ctx_init(octx, NULL, EVP_PKEY_OP_KEYGEN)) {
		put_error_pctx(pctx, PS_ERR_INTERNAL_ERROR,
			       "ps_op_init failed");
		op_ctx_free(octx);
		return NULL;
	}

	octx->fwd_op_ctx = fwd_gen_init_fn(pctx->fwd.ctx,
					   selection, params);
	if (octx->fwd_op_ctx == NULL) {
		put_error_pctx(pctx, PS_ERR_DEFAULT_PROV_FUNC_FAILED,
			       "fwd_gen_init_fn failed");
		op_ctx_free(octx);
		return NULL;
	}
	octx->fwd_op_ctx_free = fwd_gen_cleanup_fn;

	ps_dbg_debug(&pctx->dbg, "octx: %p", octx);
	return octx;
}

static void ps_keymgmt_gen_cleanup(void *vgenctx)
{
	struct op_ctx *octx = vgenctx;

	if (!octx)
		return;

	ps_dbg_debug(&octx->pctx->dbg, "octx: %p", octx);
	op_ctx_free(octx);
}

static int ps_keymgmt_gen_set_params(void *vgenctx,
				     const OSSL_PARAM params[])
{
	OSSL_FUNC_keymgmt_gen_set_params_fn *fwd_gen_set_params_fn;
	struct op_ctx *octx = vgenctx;
	const OSSL_PARAM *p;
	struct dbg *dbg;

	if (!octx)
		return OSSL_RV_ERR;
	dbg = &octx->pctx->dbg;

	ps_dbg_debug(dbg, "octx: %p", octx);
	for (p = params; (p && p->key); p++)
		ps_dbg_debug(dbg, "param: %s", p->key);

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

static const OSSL_PARAM *ps_keymgmt_gen_settable_params(
					struct op_ctx *octx,
					int type)
{
	OSSL_FUNC_keymgmt_gen_settable_params_fn *fwd_gen_settable_params_fn;

	if (octx)
		return NULL;

	ps_dbg_debug(&octx->pctx->dbg, "pctx: %p, octx: %p, type: %d",
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

static int ps_keymgmt_gen_set_template(void *vgenctx, void *vtempl)
{
	OSSL_FUNC_keymgmt_gen_set_template_fn *fwd_gen_set_template_fn;
	struct op_ctx *octx = vgenctx;
	struct obj *templ = vtempl;

	if (!octx || !templ)
		return OSSL_RV_ERR;

	ps_dbg_debug(&octx->pctx->dbg, "octx: %p, templ: %p",
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
	EVP_PKEY *pkey;

	if (!octx)
		return NULL;

	ps_dbg_debug(&octx->pctx->dbg, "octx: %p", octx);

	fwd_gen_fn = (OSSL_FUNC_keymgmt_gen_fn *)
		fwd_keymgmt_get_func(&octx->pctx->fwd, octx->type,
				     OSSL_FUNC_KEYMGMT_GEN, &octx->pctx->dbg);
	if (!fwd_gen_fn) {
		put_error_op_ctx(octx, PS_ERR_DEFAULT_PROV_FUNC_MISSING,
				 "no default gen_fn");
		return NULL;
	}

	key = obj_new_init(octx->pctx, NULL, CK_UNAVAILABLE_INFORMATION, NULL);
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
	key->fwd_key = pkey;

	ps_dbg_debug(&octx->pctx->dbg, "key: %p", key);

	return key;
}

static void *ps_keymgmt_load(const void *reference, size_t reference_sz)
{
	struct obj *key;

	if (!reference || (reference_sz != sizeof(struct obj)))
		return NULL;

	key = obj_get((struct obj *)reference);
	ps_dbg_debug(&key->pctx->dbg, "key: %p", key);

	/* take and detach reference */
	return key;
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

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

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
	struct op_ctx *octx = vgenctx;
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

	return ps_keymgmt_gen_settable_params(octx, EVP_PKEY_RSA);
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

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return keymgmt_new(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_gettable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gettable_params(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_settable_params(void *vprovctx)
{
	struct provider_ctx *pctx = vprovctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_settable_params(pctx, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_export_types(int selection)
{
	return ps_keymgmt_export_types(selection, EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_import_types(int selection)
{
	return ps_keymgmt_import_types(selection, EVP_PKEY_RSA_PSS);
}

static void *ps_keymgmt_rsapss_gen_init(void *vpctx, int selection,
					 const OSSL_PARAM params[])
{
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
	return ps_keymgmt_gen_init(pctx, selection, params,
				   EVP_PKEY_RSA_PSS);
}

static const OSSL_PARAM *ps_keymgmt_rsapss_gen_settable_params(void *vgenctx,
							       void *vpctx)
{
	struct op_ctx *octx = vgenctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

	return ps_keymgmt_gen_settable_params(octx, EVP_PKEY_RSA_PSS);
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

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);
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
	struct op_ctx *octx = vopctx;
	struct provider_ctx *pctx = vpctx;

	if (!pctx)
		return NULL;

	ps_dbg_debug(&pctx->dbg, "pctx: %p", pctx);

	return ps_keymgmt_gen_settable_params(octx, EVP_PKEY_EC);
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
	{ "RSA:rsaEncryption", "provider="PS_PROV_NAME,
				ps_keymgmt_functions_rsa, NULL },
	{ "RSA-PSS:RSASSA-PSS", "provider="PS_PROV_NAME,
				ps_keymgmt_functions_rsapss, NULL },
	{ "EC:id-ecPublicKey", "provider="PS_PROV_NAME,
				ps_keymgmt_functions_ec, NULL },
	{ NULL, NULL, NULL, NULL }
};
