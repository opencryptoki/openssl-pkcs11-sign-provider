/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include "utils.h"

#ifdef HAVE_CONFIG_H
#include "config.h"

void info(void)
{
	fprintf(stderr, "Package Version %s, Author: %s\n",
		PACKAGE_VERSION, PACKAGE_AUTHOR);
}
#else
void info(void) {}
#endif

EVP_PKEY *uri_pkey_get1(const char *uri)
{
	OSSL_STORE_CTX *sctx;
	EVP_PKEY *pkey = NULL;

	sctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!sctx) {
		fprintf(stderr, "fail: OSSL_STORE_open() [uri=%s]\n", uri);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	while (!OSSL_STORE_eof(sctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
		if (!info) {
			fprintf(stderr, "fail: OSSL_STORE_load() [uri=%s]\n", uri);
			ERR_print_errors_fp(stderr);
			OSSL_STORE_close(sctx);
			exit(EXIT_FAILURE);
		}

		switch (OSSL_STORE_INFO_get_type(info)) {
		case OSSL_STORE_INFO_PUBKEY:
			pkey = OSSL_STORE_INFO_get1_PUBKEY(info);
			break;
		case OSSL_STORE_INFO_CERT:
			pkey = X509_get_pubkey(OSSL_STORE_INFO_get0_CERT(info));
			break;
		case OSSL_STORE_INFO_PKEY:
			pkey = OSSL_STORE_INFO_get1_PKEY(info);
			break;
		default:
			OSSL_STORE_INFO_free(info);
			continue;
		}

		OSSL_STORE_INFO_free(info);
		break;
	}

	if (!pkey) {
		fprintf(stderr, "fail: OSSL_STORE_INFO_PKEY lookup [uri=%s\n]", uri);
		ERR_print_errors_fp(stderr);
		OSSL_STORE_close(sctx);
		exit(EXIT_FAILURE);
	}

	OSSL_STORE_close(sctx);
	return pkey;
}

void fdump(FILE *restrict stream, const unsigned char *p, size_t len)
{
	size_t i;

	if (!stream || !p || !len)
		return;

	for (i = 0; i < len; i++) {
		if (!(i % 8)) {
			if (i)
				fprintf(stream, "\n");
			fprintf(stream, "  %p:", &p[i]);
		}
		fprintf(stream, " 0x%02x", p[i]);
	}
	if (len)
		fprintf(stream, "\n");
}
