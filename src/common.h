/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_COMMON_H
#define _PKCS11SIGN_COMMON_H

#include <bits/types/FILE.h>
#include <openssl/types.h>
#include <openssl/core_dispatch.h>
#include <opencryptoki/pkcs11types.h>

#define __unused		__attribute__((unused))
#define min(a,b)		(((a) < (b)) ? (a) : (b))

#define OSSL_RV_TRUE	(1)
#define OSSL_RV_FALSE	(0)
#define OSSL_RV_OK	(1)
#define OSSL_RV_ERR	(0)

#define PS_PROV_NAME		"pkcs11sign"
#define PS_PROV_RSA_DEFAULT_MD	"SHA-1"

#define DECL_DISPATCH_FUNC(type, tname, name) \
	static OSSL_FUNC_##type##_##tname##_fn name

typedef void (*func_t)(void);

struct pkcs11_module {
	char *soname;
	void *dlhandle;
	CK_FUNCTION_LIST *fns;
	enum PKCS11_STATE {
		PKCS11_UNINITIALIZED = 0,
		PKCS11_INITIALIZED,
	} state;
	unsigned int refcnt;
};

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

struct dbg {
	FILE *stream;
	unsigned int level;
};

struct provider_ctx {
	struct dbg dbg;
	struct ossl_core core;
	struct ossl_provider fwd;
	struct pkcs11_module *pkcs11;
};

struct obj {
	struct provider_ctx *pctx;
	struct pkcs11_module *pkcs11;
	CK_SLOT_ID slot_id;
	char *pin;

	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG nattrs;

	OSSL_PARAM *params;	/* NULL-terminated */

	unsigned int refcnt;

	int type;
	void *fwd_key;

	/* REVISIT */
	unsigned char *secure_key;
};
#define ps_obj_debug(obj, fmt...)	ps_dbg_debug(&(obj->pctx->dbg), fmt)

struct op_ctx {
	struct provider_ctx *pctx;
	int type;
	int operation;
	char *prop;

	struct obj *key;
	CK_OBJECT_HANDLE hobject;
	CK_SESSION_HANDLE hsession;

	void *fwd_op_ctx;
	void (*fwd_op_ctx_free)(void *);

	EVP_MD *md;
	EVP_MD_CTX *mdctx;
	CK_MECHANISM mech;
};
#define ps_opctx_debug(opctx, fmt...)	ps_dbg_debug(&(opctx->pctx->dbg), fmt)

int op_ctx_init(struct op_ctx *octx, struct obj *key, int operation);
struct op_ctx *op_ctx_new(struct provider_ctx *pctx, const char *prop, int type);
struct op_ctx *op_ctx_dup(struct op_ctx * opctx);
void op_ctx_teardown_pkcs11(struct op_ctx *opctx);
void op_ctx_free(struct op_ctx *octx);

extern struct dbg *hack_dbg;

#endif /* _PKCS11SIGN_COMMON_H */
