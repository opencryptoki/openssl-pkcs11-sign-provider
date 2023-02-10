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

#define OSSL_RV_TRUE	(1)
#define OSSL_RV_FALSE	(0)
#define OSSL_RV_OK	(1)
#define OSSL_RV_ERR	(0)

#define PS_PROV_NAME		"pkcs11sign"

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

	unsigned int refcnt;

	int type;
	EVP_PKEY *fwd_key;

	/* REVISIT */
	unsigned char *secure_key;
};

#endif /* _PKCS11SIGN_COMMON_H */
