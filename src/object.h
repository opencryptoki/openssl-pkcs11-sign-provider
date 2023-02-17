/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_OBJECT_H
#define _PKCS11SIGN_OBJECT_H

#include "common.h"
#include "debug.h"
#include "pkcs11.h"

int obj_get_pub_key_info(const struct obj *obj, CK_BYTE_PTR *info, CK_ULONG_PTR infolen);
int obj_get_id(const struct obj *obj, CK_BYTE_PTR *id, CK_ULONG_PTR idlen);
CK_KEY_TYPE obj_get_key_type(const struct obj *obj);
CK_OBJECT_CLASS obj_get_class(const struct obj *obj);

void obj_free(struct obj *obj);
struct obj *obj_get(struct obj *obj);
struct obj *obj_new_init(struct provider_ctx *pctx, struct pkcs11_module *pkcs11, CK_SLOT_ID slot_id, const char *pin);

#endif /* _PKCS11SIGN_OBJECT_H */
