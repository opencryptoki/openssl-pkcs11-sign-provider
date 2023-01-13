/*
 * Copyright (C) IBM Corp. 2022
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

	/* query parameter */
	const char *mod_name;
	const char *mod_path;

	const char *pin_value;
	const char *pin_source;

	struct key_value *vendor_qattr;
};

struct parsed_uri *parsed_uri_new(const char *uri);
void parsed_uri_free(struct parsed_uri *puri);

#endif /*  _PKCS11SIGN_URI_H */
