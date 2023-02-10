/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_PKCS11_H
#define _PKCS11SIGN_PKCS11_H

#include <opencryptoki/pkcs11.h>

#include "common.h"

size_t pkcs11_strlen(const CK_CHAR_PTR c, CK_ULONG csize);
int pkcs11_strcmp(const char *s, const CK_CHAR_PTR c, CK_ULONG csize);

void pkcs11_attr_deepfree(CK_ATTRIBUTE_PTR attribute);
void pkcs11_attrs_deepfree(CK_ATTRIBUTE_PTR attributes, CK_ULONG nattributes);
CK_RV pkcs11_attr_dup(const CK_ATTRIBUTE_PTR src, CK_ATTRIBUTE_PTR dst);
CK_ATTRIBUTE_PTR pkcs11_attrs_dup(CK_ATTRIBUTE_PTR src, CK_ULONG n);

CK_RV pkcs11_fetch_attributes(struct pkcs11_module *pkcs11,
			      CK_SESSION_HANDLE session, CK_OBJECT_HANDLE ohandle,
			      CK_ATTRIBUTE_PTR *attributes, CK_ULONG *nattributes,
			      struct dbg *dbg);
CK_RV pkcs11_find_objects(struct pkcs11_module *pkcs11,
			  CK_SESSION_HANDLE session,
			  const char *label, const char *id, const char *type,
			  CK_OBJECT_HANDLE_PTR *objects, CK_ULONG_PTR nobjects,
			  struct dbg *dbg);
void pkcs11_session_close(struct pkcs11_module *pkcs11,
			   CK_SESSION_HANDLE_PTR session, struct dbg *dbg);
CK_RV pkcs11_session_open_login(struct pkcs11_module *pkcs11,
				CK_SLOT_ID slot_id,
				CK_SESSION_HANDLE_PTR session, const char *pin,
				struct dbg *dbg);
CK_RV pkcs11_get_slots(struct pkcs11_module *pkcs,
		       CK_SLOT_ID_PTR *slots, CK_ULONG *nslots,
		       struct dbg *dbg);

void pkcs11_module_free(struct pkcs11_module *pkcs);
struct pkcs11_module *pkcs11_module_get(struct pkcs11_module *pkcs);
struct pkcs11_module *pkcs11_module_new(const char *module,
					const char *module_initargs,
					struct dbg *dbg);

#endif /* _PKCS11SIGN_PKCS11_H */
