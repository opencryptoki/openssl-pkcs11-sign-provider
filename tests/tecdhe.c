#define _POSIX_C_SOURCE 1
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "utils.h"

static unsigned char *ecdh(EVP_PKEY *kp, EVP_PKEY *kp_peer, size_t *slen)
{
	EVP_PKEY_CTX *ctx;
	unsigned char *secret = NULL;
	size_t secret_len;

	/* Create the context for the shared secret derivation */
	ctx = EVP_PKEY_CTX_new(kp, NULL);
	if (!ctx) {
		fprintf(stderr, "fail: EVP_PKEY_CTX_new()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Initialise */
	if (EVP_PKEY_derive_init(ctx) != OSSL_RV_OK) {
		fprintf(stderr, "fail: EVP_PKEY_derive_init()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Provide the peer public key */
	if (EVP_PKEY_derive_set_peer(ctx, kp_peer) != OSSL_RV_OK) {
		fprintf(stderr, "fail: EVP_PKEY_derive_set_peer()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Determine buffer length for shared secret */
	if (EVP_PKEY_derive(ctx, NULL, &secret_len) != OSSL_RV_OK) {
		fprintf(stderr, "fail: EVP_PKEY_derive(NULL)\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Create the buffer */
	secret = OPENSSL_malloc(secret_len);
	if (!secret) {
		fprintf(stderr, "fail: OPENSSL_malloc()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Derive the shared secret */
	if (EVP_PKEY_derive(ctx, secret, &secret_len) != OSSL_RV_OK) {
		fprintf(stderr, "fail: EVP_PKEY_derive()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	EVP_PKEY_CTX_free(ctx);

	/* Never use a derived secret directly. Typically it is passed
	 * through some hash function to produce a key */
	*slen = secret_len;
	return secret;
}

static void *generate_key_pair(const char *curveName)
{
	OSSL_PARAM_BLD *param_build = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *kp = NULL;

	param_build = OSSL_PARAM_BLD_new();
	if (!param_build) {
		fprintf(stderr, "fail: \n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Push the curve name to the OSSL_PARAM_BLD. */
	if (OSSL_PARAM_BLD_push_utf8_string(param_build,
					    OSSL_PKEY_PARAM_GROUP_NAME,
					    curveName, 0) != OSSL_RV_OK) {
		fprintf(stderr, "fail: OSSL_PARAM_BLD_push_utf8_string()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Convert OSSL_PARAM_BLD to OSSL_PARAM. */
	params = OSSL_PARAM_BLD_to_param(param_build);
	if (!params) {
		fprintf(stderr, "fail: OSSL_PARAM_BLD_to_param()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Create the EC key generation context. */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!ctx) {
		fprintf(stderr, "fail: EVP_PKEY_CTX_new_from_name()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Initialize the key generation context. */
	if (EVP_PKEY_keygen_init(ctx) != OSSL_RV_OK) {
		fprintf(stderr, "fail: EVP_PKEY_keygen_init()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Set the parameters which include the curve name. */
	if (EVP_PKEY_CTX_set_params(ctx, params) != OSSL_RV_OK) {
		fprintf(stderr, "fail: EVP_PKEY_CTX_set_params()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* Generate a key pair. */
	EVP_PKEY_generate(ctx, &kp);
	if (!kp) {
		fprintf(stderr, "fail: EVP_PKEY_generate()\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(param_build);

	return kp;
}

int main(void)
{

	const char curve_name[] = "secp384r1";
	EVP_PKEY *kp, *kp_peer;
	unsigned char *s;
	size_t slen;
	BIO *berr;

	info();
	berr = BIO_new_fd(fileno(stderr), BIO_NOCLOSE);

	kp = generate_key_pair(curve_name);
	fprintf(stderr, "pass: keypair generate\n");
	EVP_PKEY_print_private(berr, kp, 2, NULL);

	kp_peer = generate_key_pair(curve_name);
	fprintf(stderr, "pass: keypair generate (peer)\n");
	EVP_PKEY_print_public(berr, kp_peer, 2, NULL);

	s = ecdh(kp, kp_peer, &slen);

	fprintf(stderr, "pass: shared secret\n");
	fdump(stderr, s, slen);

	OPENSSL_free(s);
	EVP_PKEY_free(kp);
	EVP_PKEY_free(kp_peer);
	BIO_free(berr);

	return 0;
}
