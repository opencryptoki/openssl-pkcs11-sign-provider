/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_OBJECT_H
#define _PKCS11SIGN_OBJECT_H

#include "common.h"
#include "debug.h"
#include "pkcs11.h"

CK_KEY_TYPE obj_get_key_type(struct obj *obj);
CK_OBJECT_CLASS obj_get_class(struct obj *obj);

void obj_free(struct obj *obj);
struct obj *obj_get(struct obj *obj);
struct obj *obj_new_init(struct provider_ctx *pctx, struct pkcs11_module *pkcs11, CK_SLOT_ID slot_id, const char *pin);

#endif /* _PKCS11SIGN_OBJECT_H */
