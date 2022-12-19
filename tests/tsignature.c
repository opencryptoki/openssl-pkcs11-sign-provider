/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/store.h>

#include "utils.h"

#define EXIT_SKIP	(77)

static EVP_MD_CTX *create_context(void)
{
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();
	if (!ctx) {
		fprintf(stderr, "fail: EVP_MD_CTX_create()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static void configure_sign_context(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const char *key_info)
{
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		fprintf(stderr, "fail: EVP_DigestSignInit() [ctx=%p, key_info=%s]\n",
			ctx, key_info);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

static void configure_verify_context(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const char *key_info)
{
	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		fprintf(stderr, "fail: EVP_DigestVerifyInit() [ctx=%p, key_info=%s]\n",
			ctx, key_info);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

static size_t sign_get_length(EVP_MD_CTX *ctx)
{
	size_t len;

	if (EVP_DigestSignFinal(ctx, NULL, &len) != 1) {
		fprintf(stderr, "fail: EVP_DigestSignFinal() [ctx=%p]\n",
			ctx);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return len;
}

static void sign_msg(EVP_MD_CTX *ctx, const char *msg, size_t msglen,
		     unsigned char *s, size_t slen, size_t *len)
{
	size_t _len = slen;

	if (EVP_DigestSignUpdate(ctx, msg, msglen) != 1) {
		fprintf(stderr, "fail: EVP_DigestSignUpdate() [ctx=%p]\n",
			ctx);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (EVP_DigestSignFinal(ctx, s, &_len) != 1) {
		fprintf(stderr, "fail: EVP_DigestSignFinal() [ctx=%p]\n",
			ctx);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	*len = _len;
}

static void verify_msg(EVP_MD_CTX *ctx, const char *msg, size_t msglen,
		       const unsigned char *sig, size_t siglen)
{
	if (EVP_DigestVerifyUpdate(ctx, msg, msglen) != 1) {
		fprintf(stderr, "fail: EVP_DigestVerifyUpdate() [ctx=%p]\n",
			ctx);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (EVP_DigestVerifyFinal(ctx, sig, siglen) != 1) {
		fprintf(stderr, "fail: EVP_DigestVerifyFinal() [ctx=%p]\n",
			ctx);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	const char *priv, *cert, *msg = "test message for sign/verify";
	EVP_MD_CTX *sctx = NULL, *vctx = NULL;
	unsigned char *sig;
	EVP_PKEY *spkey, *vpkey;
	size_t len, siglen;

	info();

	/* get all required env valiables */
	priv = getenv("URI_KEY_ECDSA_PRV");
	// priv = getenv("FILE_PEM_ECDSA_PRV");
	cert = getenv("FILE_PEM_ECDSA_CRT");

	if (!priv || !cert)
		exit(EXIT_SKIP);

	/* sign */
	sctx = create_context();
	fprintf(stderr, "pass: signature context creation\n");

	spkey = uri_pkey_get1(priv);
	fprintf(stderr, "pass: pkey load for signing [uri: %s, spkey: %p]\n",
		priv, spkey);

	configure_sign_context(sctx, spkey, priv);
	fprintf(stderr, "pass: signature context configuration [uri: %s]\n",
		priv);

	siglen = sign_get_length(sctx);
	sig = OPENSSL_zalloc(siglen);
	if (!sig)
		exit(EXIT_FAILURE);

	sign_msg(sctx, msg, strlen(msg), sig, siglen, &len);
	fprintf(stderr, "pass: message signing [uri: %s, len: %lu]\n",
		priv, len);

	fdump(stderr, sig, len);

	/* verify */
	vctx = create_context();
	fprintf(stderr, "pass: verify context creation\n");

	vpkey = uri_pkey_get1(cert);
	fprintf(stderr, "pass: pkey load for verify [uri: %s, vpkey: %p]\n",
		cert, vpkey);

	configure_verify_context(vctx, vpkey, cert);
	fprintf(stderr, "pass: verify context configuration [uri: %s]\n",
		cert);

	verify_msg(vctx, msg, strlen(msg), sig, len);
	fprintf(stderr, "pass: message verification [uri: %s]\n",
		cert);

	EVP_PKEY_free(spkey);
	EVP_PKEY_free(vpkey);
	EVP_MD_CTX_free(sctx);
	EVP_MD_CTX_free(vctx);
	OPENSSL_free(sig);

	return 0;
}
