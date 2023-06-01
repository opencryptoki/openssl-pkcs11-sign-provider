/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_CT_H
#define _PKCS11SIGN_CT_H

static inline unsigned int ct_equals(unsigned int a, unsigned int b)
{
	return !(a ^ b);
}

#endif /* _PKCS11SIGN_CT_H */
