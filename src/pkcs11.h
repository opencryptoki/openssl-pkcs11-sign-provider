/*
 * Copyright (C) IBM Corp. 2022
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_PKCS11_H
#define _PKCS11SIGN_PKCS11_H

#include <opencryptoki/pkcs11.h>

struct pkcs11_module {
	char *soname;
	void *dlhandle;
	CK_FUNCTION_LIST *fns;
	enum PKCS11_STATE {
		PKCS11_UNINITIALIZED = 0,
		PKCS11_INITIALIZED,
	} state;
};

void pkcs11_module_teardown(struct pkcs11_module *pkcs);
CK_RV pkcs11_module_init(struct pkcs11_module *pkcs,
			 const char *module,
			 const char *module_initargs,
			 struct dbg *dbg);

#endif /* _PKCS11SIGN_PKCS11_H */
