/*
 * Copyright (C) IBM Corp. 2022
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_OSSL_H
#define _PKCS11SIGN_OSSL_H

#include <stdbool.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>

#include "common.h"
#include "debug.h"

#define put_error_pctx(pctx, err, fmt...)			\
	do {							\
		ps_dbg_error(&pctx->dbg, fmt);			\
		ossl_put_error(&pctx->core, err,		\
			       __FILE__, __LINE__, __func__,	\
			       fmt);				\
	} while (0)
#define put_error_key(key, err, fmt...)				\
	put_error_pctx(key->pctx, err, fmt)
#define put_error_op_ctx(opctx, err, fmt...)			\
	put_error_pctx(opctx->pctx, err, fmt)

struct ossl_provider {
	const char *name;
	OSSL_PROVIDER *provider;
	void *ctx;
	const OSSL_ALGORITHM *alg_cache[OSSL_OP__HIGHEST];
};

struct ossl_core {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;
	struct {
		OSSL_FUNC_core_get_params_fn *get_params;
		OSSL_FUNC_core_set_error_debug_fn *set_error_debug;
		OSSL_FUNC_core_vset_error_fn *vset_error;
		OSSL_FUNC_core_new_error_fn *new_error;
	} fns;
};

void ossl_put_error(struct ossl_core *core, int err,
		    const char *file, int line, const char *func,
		    char *fmt, ...);

func_t fwd_keymgmt_get_func(struct ossl_provider *fwd, int pkey_type,
			    int function_id, struct dbg *dbg);
func_t fwd_keyexch_get_func(struct ossl_provider *fwd,
			    int function_id, struct dbg *dbg);
func_t fwd_asym_get_func(struct ossl_provider *fwd, int pkey_type,
			 int function_id, struct dbg *dbg);
func_t fwd_sign_get_func(struct ossl_provider *fwd, int pkey_type,
			 int function_id, struct dbg *dbg);

void fwd_teardown(struct ossl_provider *fwd);
int fwd_init(struct ossl_provider *fwd, const char *fwd_name,
	     const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
	     OSSL_LIB_CTX *libctx, struct dbg *dbg);

void core_teardown(struct ossl_core *core);
int core_init(struct ossl_core *core, const OSSL_CORE_HANDLE *handle,
	      const OSSL_DISPATCH *in, struct dbg *dbg);

#endif /* _PKCS11SIGN_OSSL_H */
