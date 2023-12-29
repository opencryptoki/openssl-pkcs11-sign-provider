/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_PKCS11_H
#define _PKCS11SIGN_PKCS11_H

#include <opencryptoki/pkcs11.h>

#include "common.h"

int mechtype_by_id(int id, CK_MECHANISM_TYPE_PTR mech);
int mechtype_by_name(const char *name, CK_MECHANISM_TYPE_PTR mech);
int mgftype_by_name(const char *name, CK_RSA_PKCS_MGF_TYPE_PTR mgf);

size_t pkcs11_strlen(const CK_CHAR_PTR c, CK_ULONG csize);
int pkcs11_strcmp(const char *s, const CK_CHAR_PTR c, CK_ULONG csize);

void pkcs11_attr_deepfree(CK_ATTRIBUTE_PTR attribute);
void pkcs11_attrs_deepfree(CK_ATTRIBUTE_PTR attributes, CK_ULONG nattributes);
CK_RV pkcs11_attr_dup(const CK_ATTRIBUTE_PTR src, CK_ATTRIBUTE_PTR dst);
CK_ATTRIBUTE_PTR pkcs11_attrs_dup(CK_ATTRIBUTE_PTR src, CK_ULONG n);

CK_RV pkcs11_sign_init(struct pkcs11_module *pkcs11,
		       CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
		       CK_OBJECT_HANDLE hkey, struct dbg *dbg);
CK_RV pkcs11_sign(struct pkcs11_module *pkcs11,
		  CK_SESSION_HANDLE hsession,
		  const unsigned char *data, size_t datalen,
		  unsigned char *sig, size_t *siglen,
		  struct dbg *dbg);
CK_RV pkcs11_decrypt_init(struct pkcs11_module *pkcs11,
			  CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			  CK_OBJECT_HANDLE hkey, struct dbg *dbg);
CK_RV pkcs11_decrypt(struct pkcs11_module *pkcs11,
		     CK_SESSION_HANDLE hsession,
		     const unsigned char *cdata, size_t cdatalen,
		     unsigned char *data, size_t *datalen,
		     struct dbg *dbg);
CK_RV pkcs11_fetch_attributes(struct pkcs11_module *pkcs11,
			      CK_SESSION_HANDLE session,
			      CK_OBJECT_HANDLE ohandle,
			      CK_ATTRIBUTE_PTR *attributes,
			      CK_ULONG *nattributes,
			      struct dbg *dbg);
CK_RV pkcs11_object_handle(struct pkcs11_module *pkcs11,
			   CK_SESSION_HANDLE hsession,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG nattrs,
			   CK_OBJECT_HANDLE_PTR phobject,
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

void pkcs11_module_teardown(struct pkcs11_module *pkcs);
int pkcs11_module_init(struct pkcs11_module *pkcs,
		       const char *module, const char *module_initargs,
		       struct dbg *dbg);

#endif /* _PKCS11SIGN_PKCS11_H */
