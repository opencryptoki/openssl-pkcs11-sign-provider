/*
 * Copyright (C) IBM Corp. 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
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

int obj_get_pub_key_info(const struct obj *obj, CK_BYTE_PTR *info, CK_ULONG_PTR infolen)
{
	CK_ATTRIBUTE_PTR attr;

	if (!obj)
		return OSSL_RV_ERR;

	attr = get_attribute(obj, CKA_PUBLIC_KEY_INFO);
	if (!attr)
		return OSSL_RV_ERR;

	*info = (CK_BYTE_PTR)attr->pValue;
	*infolen = attr->ulValueLen;

	return OSSL_RV_OK;
}

int obj_get_id(const struct obj *obj, CK_BYTE_PTR *id, CK_ULONG_PTR idlen)
{
	CK_ATTRIBUTE_PTR attr;

	if (!obj)
		return OSSL_RV_ERR;

	attr = get_attribute(obj, CKA_ID);
	if (!attr)
		return OSSL_RV_ERR;

	*id = (CK_BYTE_PTR)attr->pValue;
	*idlen = attr->ulValueLen;

	return OSSL_RV_OK;
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
		OPENSSL_clear_free(obj->pin, strlen(obj->pin));
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

struct obj *obj_new_init(struct provider_ctx *pctx, CK_SLOT_ID slot_id, const char *pin)
{
	struct obj *obj;

	obj = OPENSSL_zalloc(sizeof(struct obj));
	if (!obj)
		return NULL;

	obj->pctx = pctx;
	obj->slot_id = slot_id;
	if (pin)
		obj->pin = OPENSSL_strdup(pin);

	return obj_get(obj);
}
