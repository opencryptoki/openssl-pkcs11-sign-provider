/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_URI_H
#define _PKCS11SIGN_URI_H

#include <stdlib.h>

struct key_value {
	const char *key;
	const char *value;
};

struct parsed_uri {
	char *priv;
	char *pin;

	/* only valid if lib_ver != 0 */
	unsigned long lib_ver_major;
	unsigned long lib_ver_minor;

	/* path parameter */
	const char *lib_manuf;
	const char *lib_desc;
	const char *lib_ver;

	const char *slt_manuf;
	const char *slt_desc;
	const char *slt_id;

	const char *tok_token;
	const char *tok_manuf;
	const char *tok_serial;
	const char *tok_model;

	const char *obj_object;
	const char *obj_type;
	const char *obj_id;

	struct key_value *vendor_pattr;
	size_t vendor_pattr_len;

	/* query parameter */
	const char *mod_name;
	const char *mod_path;

	const char *pin_value;
	const char *pin_source;

	struct key_value *vendor_qattr;
	size_t vendor_qattr_len;
};

struct parsed_uri *parsed_uri_new(const char *uri);
void parsed_uri_free(struct parsed_uri *puri);

#endif /*  _PKCS11SIGN_URI_H */
