/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/store.h>

#ifdef HAVE_CONFIG_H
#include "config.h"

static void info(void)
{
	fprintf(stderr, "Package Version %s, Author: %s\n",
		PACKAGE_VERSION, PACKAGE_AUTHOR);
}
#else
static void info(void) {}
#endif

#define EXIT_SKIP	(77)

static EVP_PKEY *uri_pkey_get1(const char *uri)
{
	OSSL_STORE_CTX *sctx;
	EVP_PKEY *pkey = NULL;

	sctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!sctx) {
		fprintf(stderr, "OSSL_STORE_open() failed: uri=%s\n", uri);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	while (!OSSL_STORE_eof(sctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
		if (!info) {
			fprintf(stderr, "OSSL_STORE_load() failed: uri=%s\n", uri);
			ERR_print_errors_fp(stderr);
			OSSL_STORE_close(sctx);
			exit(EXIT_FAILURE);
		}

		if (OSSL_STORE_INFO_get_type(info) != OSSL_STORE_INFO_PKEY) {
			OSSL_STORE_INFO_free(info);
			continue;
		}

		pkey = OSSL_STORE_INFO_get1_PKEY(info);
		OSSL_STORE_INFO_free(info);
	}

	if (!pkey) {
		fprintf(stderr, "OSSL_STORE_INFO_PKEY not found: uri=%s\n", uri);
		ERR_print_errors_fp(stderr);
		OSSL_STORE_close(sctx);
		exit(EXIT_FAILURE);
	}

	OSSL_STORE_close(sctx);
	return pkey;
}

static SSL_CTX *create_context(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method();
	if (!method) {
		fprintf(stderr, "TLS_server_method() failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		fprintf(stderr, "SSL_CTX_new() failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static void configure_context(SSL_CTX *ctx, EVP_PKEY *pkey,
			      const char *cert_file)
{
	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "SSL_CTX_use_certificate_file() failed: ctx=%p, file=%s\n",
			ctx, cert_file);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
		fprintf(stderr, "SSL_CTX_use_PrivateKey() failed: ctx=%p, pkey=%p\n",
			ctx, pkey);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	SSL_CTX *ctx = NULL;
	EVP_PKEY *pkey;
	const char *uri, *cert;

	info();

	/* get all required env valiables */
	uri = getenv("URI_KEY_ECDSA_PRV");
	cert = getenv("FILE_PEM_ECDSA_CRT");

	if (!uri || !cert)
		exit(EXIT_SKIP);

	ctx = create_context();
	fprintf(stderr, "SSL Context works!\n");

	pkey = uri_pkey_get1(uri);
	fprintf(stderr, "Pkey load works: uri: %s, pkey: %p\n",
		uri, pkey);

	configure_context(ctx, pkey, cert);
	fprintf(stderr, "Context configuration works: uri: %s, cert: %s\n",
		uri, cert);

	/*
	 * TODO:
	 * - create socket
	 * - handle connections (in a loop)
	 */

	EVP_PKEY_free(pkey);
	SSL_CTX_free(ctx);

	return 0;
}
