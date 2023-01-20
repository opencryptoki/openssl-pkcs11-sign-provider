/*
 * Copyright (C) IBM Corp. 2022
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/store.h>

#include "config.h"

static void info(void)
{
	fprintf(stderr, "Package Version %s, Author: %s\n",
		PACKAGE_VERSION, PACKAGE_AUTHOR);
}

int main(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx = NULL;
	OSSL_STORE_CTX *sctx;
	const char *uri;

	info();

	method = TLS_server_method();
	if (!method) {
		fprintf(stderr, "Failed to get server method\n");
		exit(EXIT_FAILURE);
	}

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		fprintf(stderr, "Failed to create SSL context\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "SSL Context works!\n");

	uri = getenv("URI_KEY_ECDSA_PRV");
	sctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!sctx) {
		fprintf(stderr, "Failed to open store (uri: %s)\n", uri);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	OSSL_STORE_close(sctx);
	fprintf(stderr, "Store open/close works! (uri: %s)\n", uri);

	return 0;
}

