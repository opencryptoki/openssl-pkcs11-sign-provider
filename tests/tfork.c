/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
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

void sign_verify(const char *priv, const char *cert, bool debug)
{
	const char *msg = "test message for sign/verify";
	EVP_MD_CTX *sctx = NULL, *vctx = NULL;
	unsigned char *sig;
	EVP_PKEY *spkey, *vpkey;
	size_t len, siglen;

	/* sign */
	sctx = create_context();
	if (debug) fprintf(stderr, "pass: [%d] signature context creation\n", getpid());

	child_propagate();

	spkey = uri_pkey_get1(priv);
	if (debug) fprintf(stderr, "pass: [%d] pkey load for signing [uri: %s, spkey: %p]\n",
			   getpid(), priv, spkey);

	child_propagate();

	configure_sign_context(sctx, spkey, priv);
	if (debug) fprintf(stderr, "pass: [%d] signature context configuration [uri: %s]\n",
			   getpid(), priv);

	child_propagate();

	siglen = sign_get_length(sctx);
	sig = OPENSSL_zalloc(siglen);
	if (!sig)
		exit(EXIT_FAILURE);

	child_propagate();

	sign_msg(sctx, msg, strlen(msg), sig, siglen, &len);
	if (debug) fprintf(stderr, "pass: [%d] message signing [uri: %s, len: %lu]\n",
			   getpid(), priv, len);

	if (debug) fdump(stderr, sig, len);

	/* verify */
	vctx = create_context();
	if (debug) fprintf(stderr, "pass: [%d] verify context creation\n", getpid());

	child_propagate();

	vpkey = uri_pkey_get1(cert);
	if (debug) fprintf(stderr, "pass: [%d] pkey load for verify [uri: %s, vpkey: %p]\n",
			   getpid(), cert, vpkey);

	child_propagate();

	configure_verify_context(vctx, vpkey, cert);
	if (debug) fprintf(stderr, "pass: [%d] verify context configuration [uri: %s]\n",
			   getpid(), cert);

	child_propagate();

	verify_msg(vctx, msg, strlen(msg), sig, len);
	if (debug) fprintf(stderr, "pass: [%d] message verification [uri: %s]\n",
			   getpid(), cert);

	EVP_PKEY_free(spkey);
	EVP_PKEY_free(vpkey);
	EVP_MD_CTX_free(sctx);
	EVP_MD_CTX_free(vctx);
	OPENSSL_free(sig);
}

static char *test_keys[][2] = {
	/* ecdsa */
	{ "FILE_PEM_ECDSA_PRV", "FILE_PEM_ECDSA_CRT"},
	{ "URI_KEY_ECDSA_PRV", "FILE_PEM_ECDSA_CRT"},
	/* rsa */
	{ "FILE_PEM_RSA4K_PRV", "FILE_PEM_RSA4K_CRT"},
	{ "URI_KEY_RSA4K_PRV", "FILE_PEM_RSA4K_CRT"},
};

int main(void)
{
	size_t i, nelem;
	bool debug;

	debug = (getenv("PKCS11SIGN_DEBUG")) ? true : false;
	if (debug) info();

	nelem = sizeof(test_keys) / sizeof(test_keys[0]);
	for (i = 0; i < nelem; i++) {
		char *env_p, *env_c, *priv, *cert;

		env_p = test_keys[i][0];
		env_c = test_keys[i][1];

		if (!env_p || !env_c) {
			fprintf(stderr, "skip: [%ld] forked sign/verify with %s/%s\n",
				i, env_p, env_c);
			continue;
		}

		priv = getenv(env_p);
		cert = getenv(env_c);

		if (!priv || !cert) {
			fprintf(stderr, "skip: [%ld] forked sign/verify with %s/%s\n",
				i, env_p, env_c);
			continue;
		}

		sign_verify(priv, cert, debug);
		fprintf(stderr, "pass: [%ld] forked sign/verify with %s/%s\n",
			i, env_p, env_c);
	}

	return 0;
}
