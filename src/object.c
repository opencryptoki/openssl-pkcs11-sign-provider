/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/crypto.h>

#include "common.h"
#include "debug.h"
#include "pkcs11.h"

static CK_ATTRIBUTE *get_attribute(const struct obj *obj,
				   CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	if (!obj)
		return NULL;

	for (i = 0; i < obj->nattrs; i++) {
		if (obj->attrs[i].type == type)
			return &obj->attrs[i];
	}

	return NULL;
}

CK_KEY_TYPE obj_get_key_type(const struct obj *obj)
{
	CK_ATTRIBUTE_PTR attr;

	if (!obj)
		return CK_UNAVAILABLE_INFORMATION;

	attr = get_attribute(obj, CKA_KEY_TYPE);
	if (!attr)
		return CK_UNAVAILABLE_INFORMATION;

	return *(CK_KEY_TYPE *)attr->pValue;
}

CK_OBJECT_CLASS obj_get_class(const struct obj *obj)
{
	CK_ATTRIBUTE_PTR attr;

	if (!obj)
		return CK_UNAVAILABLE_INFORMATION;

	attr = get_attribute(obj, CKA_CLASS);
	if (!attr)
		return CK_UNAVAILABLE_INFORMATION;

	return *(CK_OBJECT_CLASS_PTR)attr->pValue;
}

static void _obj_free(struct obj *obj)
{
	if (obj->pin)
		OPENSSL_cleanse(obj->pin, sizeof(obj->pin));

	pkcs11_module_free(obj->pkcs11);

	OPENSSL_free(obj->pin);
	pkcs11_attrs_deepfree(obj->attrs, obj->nattrs);
	OPENSSL_free(obj->attrs);
	OPENSSL_free(obj);
}

void obj_free(struct obj *obj)
{
	if (!obj)
		return;

	if (__atomic_sub_fetch(&obj->refcnt, 1, __ATOMIC_SEQ_CST))
		return;

	_obj_free(obj);
}

struct obj *obj_get(struct obj *obj)
{
	if (!obj)
		return NULL;

	__atomic_fetch_add(&obj->refcnt, 1, __ATOMIC_SEQ_CST);
	return obj;
}

struct obj *obj_new_init(struct provider_ctx *pctx, struct pkcs11_module *pkcs11, CK_SLOT_ID slot_id, const char *pin)
{
	struct obj *obj;

	obj = OPENSSL_zalloc(sizeof(struct obj));
	if (!obj)
		return NULL;

	obj->pctx = pctx;
	obj->pkcs11 = pkcs11_module_get(pkcs11);
	obj->slot_id = slot_id;
	if (pin)
		obj->pin = OPENSSL_strdup(pin);

	return obj_get(obj);
}
