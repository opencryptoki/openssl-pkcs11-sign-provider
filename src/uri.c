/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

#include "uri.h"

#define SEP_PROTOCOL		":"
#define SEP_PATHQUERY		"?"
#define SEP_KEYVALUE		"="
#define SEP_PATHATTRS		";"
#define SEP_QUERYATTRS		"&"

#define URI_PROTOCOL_PREFIX	"pkcs11"
#define URI_PROTOCOL		URI_PROTOCOL_PREFIX SEP_PROTOCOL

#define URI_P_LIBMANUF		"library-manufacturer="
#define URI_P_LIBDESC		"library-description="
#define URI_P_LIBVER		"library-version="
#define URI_P_SLOTMANUF		"slot-manufacturer="
#define URI_P_SLOTDESC		"slot_description="
#define URI_P_SLOTID		"slot-id="
#define URI_P_TOKTOKEN		"token="
#define URI_P_TOKMANUF		"manufacturer="
#define URI_P_TOKSERIAL		"serial="
#define URI_P_TOKMODEL		"model="
#define URI_P_OBJOBJECT		"object="
#define URI_P_OBJTYPE		"type="
#define URI_P_OBJID		"id="

#define URI_Q_PINSOURCE		"pin-source="
#define URI_Q_PINVALUE		"pin-value="
#define URI_Q_MODNAME		"module-name="
#define URI_Q_MODPATH		"module-path="

#define FILE_PROTOCOL_PREFIX	"file"
#define FILE_PROTOCOL		FILE_PROTOCOL_PREFIX SEP_PROTOCOL

#define HEX_CHARS		"0123456789abcdefABCDEF"

static void decode(char *s)
{
	char *rp, *wp, *endptr;
	unsigned long tmp;

	if (!s || !strchr(s, '%'))
		return;

	rp = wp = s;
	while(*rp) {
		switch(*rp) {
		case '%':
			/* abort on invalid format and chars */
			if ((strlen(rp) < 3) ||
			    !strchr(HEX_CHARS, rp[1]) ||
			    !strchr(HEX_CHARS, rp[2])) {
				*wp = '\0';
				return;
			}

			rp++;				/* skip % */
			endptr = rp + 2;		/* 2 chars only */

			tmp = strtoul(rp, &endptr, 16);	/* convert */
			*wp = (char)(tmp & 0xff);

			rp++;
			break;
		default:
			*wp = *rp;
		}

		rp++;
		wp++;
	}
	*wp = '\0';
}

#define MAX_PIN_LEN		64
static char *retrieve_pin_from_file(const char *source)
{
	char *rv = NULL, pin[MAX_PIN_LEN];
	const char *path;
	int rc;
	BIO *fp;

	path = source;

	/* drop file protocol prefix */
	if (strncmp(source, FILE_PROTOCOL, strlen(FILE_PROTOCOL)) == 0)
		path += strlen(FILE_PROTOCOL);

	fp = BIO_new_file(path, "r");
	if (!fp)
		return NULL;

	rc = BIO_gets(fp, pin, MAX_PIN_LEN);
	if (rc <= 0)
		goto err;

	rv = OPENSSL_strndup(pin, MAX_PIN_LEN);
err:
	BIO_free(fp);
	return rv;
}

static void retrieve_pin(struct parsed_uri *puri)
{
	if (puri->pin_source)
		puri->pin = retrieve_pin_from_file(puri->pin_source);

	/* use to pin-value only if pin-source is absent */
	if ((puri->pin_value) && !puri->pin)
		puri->pin = OPENSSL_strdup(puri->pin_value);

	return;
}

static void parse_key_attr(char *attr, const char **parsed_key, const char **parsed_attr)
{
	char *key, **val;

	if (!attr || !parsed_attr)
		return;

	/* skip already parsed attribute */
	if (*parsed_attr)
		return;

	val = &attr;

	key = strsep(val, SEP_KEYVALUE);
	if (val) {
		decode(*val);
		*parsed_attr = *val;

		if (parsed_key)
			*parsed_key = key;
	}
}

static inline int match_elem_attrkey(const char *elem, const char *attrkey)
{
	return (strncmp(elem, attrkey, strlen(attrkey)) == 0);
}

static int parse_query(char *qattr, struct parsed_uri *puri)
{
	char **next;

	/* query attributes are optional */
	if (!qattr || !strlen(qattr))
		return 0;

	next = &qattr;
	do {
		char *e = strsep(next, SEP_QUERYATTRS);

		if (match_elem_attrkey(e, URI_Q_PINVALUE))
			parse_key_attr(e, NULL, &puri->pin_value);
		else if (match_elem_attrkey(e, URI_Q_PINSOURCE))
			parse_key_attr(e, NULL, &puri->pin_source);
		else if (match_elem_attrkey(e, URI_Q_MODNAME))
			parse_key_attr(e, NULL, &puri->mod_name);
		else if (match_elem_attrkey(e, URI_Q_MODPATH))
			parse_key_attr(e, NULL, &puri->mod_path);
		else {}	/* TODO: vendor specific query attributes */

	} while (*next);

	return 0;
}

static int parse_path(char *pattr, struct parsed_uri *puri)
{
	char **next;

	/* path attributes are mandatory */
	if (!pattr || !strlen(pattr))
		return 1;

	next = &pattr;
	do {
		char *e = strsep(next, SEP_PATHATTRS);

		if (match_elem_attrkey(e, URI_P_LIBMANUF))
			parse_key_attr(e, NULL, &puri->lib_manuf);
		else if (match_elem_attrkey(e, URI_P_LIBDESC))
			parse_key_attr(e, NULL, &puri->lib_desc);
		else if (match_elem_attrkey(e, URI_P_LIBVER))
			parse_key_attr(e, NULL, &puri->lib_ver);
		else if (match_elem_attrkey(e, URI_P_SLOTMANUF))
			parse_key_attr(e, NULL, &puri->slt_manuf);
		else if (match_elem_attrkey(e, URI_P_SLOTDESC))
			parse_key_attr(e, NULL, &puri->slt_desc);
		else if (match_elem_attrkey(e, URI_P_SLOTID))
			parse_key_attr(e, NULL, &puri->slt_id);
		else if (match_elem_attrkey(e, URI_P_TOKTOKEN))
			parse_key_attr(e, NULL, &puri->tok_token);
		else if (match_elem_attrkey(e, URI_P_TOKMANUF))
			parse_key_attr(e, NULL, &puri->tok_manuf);
		else if (match_elem_attrkey(e, URI_P_TOKSERIAL))
			parse_key_attr(e, NULL, &puri->tok_serial);
		else if (match_elem_attrkey(e, URI_P_TOKMODEL))
			parse_key_attr(e, NULL, &puri->tok_model);
		else if (match_elem_attrkey(e, URI_P_OBJOBJECT))
			parse_key_attr(e, NULL, &puri->obj_object);
		else if (match_elem_attrkey(e, URI_P_OBJTYPE))
			parse_key_attr(e, NULL, &puri->obj_type);
		else if (match_elem_attrkey(e, URI_P_OBJID))
			parse_key_attr(e, NULL, &puri->obj_id);
		else {}	/* TODO: vendor specific path attributes */

	} while (*next);

	return 0;
}

static int parse(char *uri, struct parsed_uri *puri)
{
	char *pattr, *qattr;
	char **next;
	int rv;

	if (!uri || !puri)
		return 1;

	if (strncmp(uri, URI_PROTOCOL, strlen(URI_PROTOCOL)) != 0)
		return 1;

	next = &uri;

	// drop pkcs11 protocol
	strsep(next, SEP_PROTOCOL);

	pattr = strsep(next, SEP_PATHQUERY);
	qattr = *next;

	rv = parse_path(pattr, puri);
	if (rv) {
		return rv;
	}

	rv = parse_query(qattr, puri);
	if (rv) {
		return rv;
	}

	if (puri->lib_ver)
		sscanf(puri->lib_ver, "%lu.%lu",
		       &puri->lib_ver_major, &puri->lib_ver_minor);

	retrieve_pin(puri);

	return 0;
}

void parsed_uri_free(struct parsed_uri *puri)
{
	if (!puri)
		return;

	if (puri->priv)
		OPENSSL_clear_free(puri->priv, strlen(puri->priv));

	if (puri->pin)
		OPENSSL_clear_free(puri->pin, strlen(puri->pin));

	OPENSSL_free(puri);
}

struct parsed_uri *parsed_uri_new(const char *uri)
{
	struct parsed_uri *puri;

	puri = OPENSSL_zalloc(sizeof(struct parsed_uri));
	if (!puri)
		return NULL;

	puri->priv = OPENSSL_strdup(uri);
	if (!puri->priv)
		goto err;

	if(parse(puri->priv, puri))
		goto err;

	return puri;

err:
	parsed_uri_free(puri);
	return NULL;
}
