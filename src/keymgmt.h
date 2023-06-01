/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_KEYMGMT_H
#define _PKCS11SIGN_KEYMGMT_H

extern const OSSL_ALGORITHM ps_keymgmt[];

int keymgmt_get_size(struct obj *key);

#endif /* _PKCS11SIGN_KEYMGMT_H */
