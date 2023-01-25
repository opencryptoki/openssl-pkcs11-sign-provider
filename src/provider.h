/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_PROVIDER_H
#define _PKCS11SIGN_PROVIDER_H

#include "ossl.h"
#include "pkcs11.h"
#include "debug.h"

#define PS_PROV_NAME		"pkcs11sign"
#define PS_PROV_DESCRIPTION	"PKCS11 signing key provider"
#define PS_PROV_VERSION		"0.1"

#define DECL_DISPATCH_FUNC(type, tname, name) \
	static OSSL_FUNC_##type##_##tname##_fn name

struct provider_ctx {
	struct dbg dbg;
	struct ossl_core core;
	struct ossl_provider fwd;
	struct pkcs11_module *pkcs11;
};

#endif /* _PKCS11SIGN_PROVIDER_H */
