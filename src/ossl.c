/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "ossl.h"
#include "debug.h"

const OSSL_ITEM ps_prov_reason_strings[] = {
	{ PS_ERR_INTERNAL_ERROR,
		"Internal error" },
	{ PS_ERR_MALLOC_FAILED,
		"Memory allocation failed" },
	{ PS_ERR_INVALID_PARAM,
		"Invalid parameter encountered" },
	{ PS_ERR_DEFAULT_PROV_FUNC_MISSING,
		"A function inherited from forward provider is missing" },
	{ PS_ERR_DEFAULT_PROV_FUNC_FAILED,
		"A function inherited from forward provider has failed" },
	{ PS_ERR_OPRATION_NOT_INITIALIZED,
		"An operation context has not been initialized" },
	{ PS_ERR_MISSING_PARAMETER,
		"A parameter of a key or a context is missing" },
	{ PS_ERR_INVALID_PADDING,
		"An invalid or unknown padding is used" },
	{ PS_ERR_INVALID_MD,
		"An invalid or unknown digest is used" },
	{ PS_ERR_INVALID_SALTLEN,
		"An invalid salt length is used" },
	{ PS_ERR_SECURE_KEY_FUNC_FAILED,
		"A secure key function has failed" },
	{0, NULL }
};

static const unsigned char der_DigestInfo_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, };
static const unsigned char der_DigestInfo_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	0x00, 0x04, 0x1C, };
static const unsigned char der_DigestInfo_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20, };
static const unsigned char der_DigestInfo_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	0x00, 0x04, 0x30, };
static const unsigned char der_DigestInfo_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
	0x00, 0x04, 0x40, };
static const unsigned char der_DigestInfo_SHA3_224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
	0x00, 0x04, 0x1C, };
static const unsigned char der_DigestInfo_SHA3_256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
	0x00, 0x04, 0x20, };
static const unsigned char der_DigestInfo_SHA3_384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
	0x00, 0x04, 0x30, };
static const unsigned char der_DigestInfo_SHA3_512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
	0x00, 0x04, 0x40, };

int ossl_hash_prefix(EVP_MD_CTX *mdctx, unsigned char *p, unsigned int *size)
{
	const unsigned char *der;
	size_t len;

	switch (EVP_MD_CTX_type(mdctx)) {
	case NID_sha1:
		len = sizeof(der_DigestInfo_SHA1);
		der = der_DigestInfo_SHA1;
		break;
	case NID_sha224:
		len = sizeof(der_DigestInfo_SHA224);
		der = der_DigestInfo_SHA224;
		break;
	case NID_sha256:
		len = sizeof(der_DigestInfo_SHA256);
		der = der_DigestInfo_SHA256;
		break;
	case NID_sha384:
		len = sizeof(der_DigestInfo_SHA384);
		der = der_DigestInfo_SHA384;
		break;
	case NID_sha512:
		len = sizeof(der_DigestInfo_SHA512);
		der = der_DigestInfo_SHA512;
		break;
	case NID_sha3_224:
		len = sizeof(der_DigestInfo_SHA3_224);
		der = der_DigestInfo_SHA3_224;
		break;
	case NID_sha3_256:
		len = sizeof(der_DigestInfo_SHA3_256);
		der = der_DigestInfo_SHA3_256;
		break;
	case NID_sha3_384:
		len = sizeof(der_DigestInfo_SHA3_384);
		der = der_DigestInfo_SHA3_384;
		break;
	case NID_sha3_512:
		len = sizeof(der_DigestInfo_SHA3_512);
		der = der_DigestInfo_SHA3_512;
		break;
	default:
		return OSSL_RV_ERR;
	}

	memcpy(p, der, len);
	*size = len;

	return OSSL_RV_OK;
}

/**
 * Builds an DER encoded signature from a raw signature.
 *
 * @param raw_sig            the raw signature to encode
 * @param raw_sig_len        the size of the raw signature (2 times prime len)
 * @param sig                a buffer for storing the encoded signature. If
 *                           NULL, then required size is returend in sig_len.
 * @param sig_len            On entry: the size of the buffer in sig.
 *                           On exit: the size of the encoded sigature.
 *
 * @returns 1 for success, otherwise 0.
 */
int ossl_ecdsa_signature(const unsigned char *raw_sig, size_t raw_siglen,
			 unsigned char *sig, size_t *siglen)
{
	int rc = OSSL_RV_OK;
	unsigned char *der;
	ECDSA_SIG *ec_sig;
	int derlen;

	if (!raw_sig || !raw_siglen)
		return OSSL_RV_ERR;

	ec_sig = ECDSA_SIG_new();
	if (!ec_sig) {
		return OSSL_RV_ERR;
	}

	rc = ECDSA_SIG_set0(ec_sig,
			    BN_bin2bn(raw_sig, raw_siglen / 2, NULL),
			    BN_bin2bn(raw_sig + raw_siglen / 2, raw_siglen / 2, NULL));
	if (rc != OSSL_RV_OK)
		goto out;

	derlen = i2d_ECDSA_SIG(ec_sig, NULL);
	if (derlen <= 0) {
		rc = OSSL_RV_ERR;
		goto out;
	}

	if (!sig) {
		*siglen = derlen;
		goto out;
	}

	if (*siglen < (size_t)derlen) {
		rc = OSSL_RV_ERR;
		goto out;
	}

	der = sig;
	derlen = i2d_ECDSA_SIG(ec_sig, &der);
	if (derlen <= 0) {
		rc = OSSL_RV_ERR;
		goto out;
	}

	*siglen = derlen;
out:
	ECDSA_SIG_free(ec_sig);
	return rc;
}

void ossl_put_error(struct ossl_core *core, int err,
		      const char *file, int line, const char *func,
		      char *fmt, ...)
{
	va_list ap;

	if (!core)
		return;

	va_start(ap, fmt);

	if (core->fns.new_error)
		core->fns.new_error(core->handle);
	if (core->fns.set_error_debug)
		core->fns.set_error_debug(core->handle, file, line, func);
	if (core->fns.vset_error)
		core->fns.vset_error(core->handle, err, fmt, ap);

	va_end(ap);
}

static func_t fwd_get_func(struct ossl_provider *fwd, int operation_id,
		    const char *algorithm, int function_id,
		    struct dbg *dbg)
{
	const OSSL_ALGORITHM *fwd_algos, *algs;
	const OSSL_DISPATCH *fwd_impl, *impl;
	int algolen = strlen(algorithm);
	int no_cache = 0, query = 0;
	func_t func = NULL;
	const char *found;

	if (fwd == NULL || fwd->provider == NULL ||
	    operation_id <= 0 || operation_id > OSSL_OP__HIGHEST)
		return NULL;

	ps_dbg_debug(dbg, "operation_id: %d, algo: %s, func: %d",
		     operation_id, algorithm, function_id);

	fwd_algos = fwd->alg_cache[operation_id];
	if (fwd_algos == NULL) {
		fwd_algos = OSSL_PROVIDER_query_operation(
				fwd->provider,
				operation_id, &no_cache);
		query = 1;
	}

	for (algs = fwd_algos; algs != NULL &&
				   algs->algorithm_names != NULL; algs++) {
		found = strcasestr(algs->algorithm_names, algorithm);
		if (found == NULL)
			continue;
		if (found[algolen] != '\0' && found[algolen] != ':')
			continue;
		if (found != algs->algorithm_names && found[-1] != ':')
			continue;

		fwd_impl = algs->implementation;
		for (impl = fwd_impl; impl->function_id != 0; impl++) {
			if (impl->function_id == function_id) {
				func = impl->function;
				break;
			}
		}
		break;
	}

	if (query == 1 && fwd_algos != NULL)
		OSSL_PROVIDER_unquery_operation(fwd->provider,
						operation_id,
						fwd_algos);

	if (no_cache == 0 &&
	    fwd->alg_cache[operation_id] == NULL)
		fwd->alg_cache[operation_id] = fwd_algos;

	ps_dbg_debug(dbg, "func: %p", func);
	return func;
}

static const char *fwd_get_algo(int pkey_type, bool sign)
{
	switch (pkey_type) {
	case EVP_PKEY_RSA:
		return "RSA";
	case EVP_PKEY_RSA_PSS:
		return "RSA-PSS";
	case EVP_PKEY_EC:
		if (sign)
			return "ECDSA";
		else
			return "EC";
	default:
		return NULL;
	}
}

func_t fwd_keymgmt_get_func(struct ossl_provider *fwd, int pkey_type,
			    int function_id, struct dbg *dbg)
{
	return fwd_get_func(fwd, OSSL_OP_KEYMGMT,
			    fwd_get_algo(pkey_type, false),
			    function_id, dbg);
}

func_t fwd_keyexch_get_func(struct ossl_provider *fwd,
			    int function_id, struct dbg *dbg)
{
	return fwd_get_func(fwd, OSSL_OP_KEYEXCH, "ECDH",
			    function_id, dbg);
}

func_t fwd_asym_get_func(struct ossl_provider *fwd, int pkey_type,
			 int function_id, struct dbg *dbg)
{
	return fwd_get_func(fwd, OSSL_OP_ASYM_CIPHER,
			    fwd_get_algo(pkey_type, false),
			    function_id, dbg);
}

func_t fwd_sign_get_func(struct ossl_provider *fwd, int pkey_type,
			 int function_id, struct dbg *dbg)
{
	return fwd_get_func(fwd, OSSL_OP_SIGNATURE,
			    fwd_get_algo(pkey_type, true),
			    function_id, dbg);
}

void fwd_teardown(struct ossl_provider *fwd)
{
	if (!fwd)
		return;

	if (fwd->provider)
		OSSL_PROVIDER_unload(fwd->provider);
	fwd->provider = NULL;

	fwd->ctx = NULL;
}

int fwd_init(struct ossl_provider *fwd, const char *fwd_name,
	     OSSL_LIB_CTX *libctx, struct dbg *dbg)
{
	if (!fwd || !fwd_name || !libctx || !dbg)
		return OSSL_RV_ERR;

	fwd->provider = OSSL_PROVIDER_load(libctx, fwd_name);
	if (!fwd->provider) {
		ps_dbg_error(dbg, "fwd %s: Failed to load provider", fwd_name);
		goto err;
	}

	fwd->ctx = OSSL_PROVIDER_get0_provider_ctx(fwd->provider);
	if (!fwd->ctx)
		goto err;
	fwd->name = fwd_name;

	return OSSL_RV_OK;

err:
	fwd_teardown(fwd);
	return OSSL_RV_ERR;
}

void core_teardown(struct ossl_core *core)
{
	if (!core)
		return;

	if (core->libctx)
		OSSL_LIB_CTX_free(core->libctx);

	core->libctx = NULL;
	core->handle = NULL;

	core->fns.get_params = NULL;
	core->fns.set_error_debug = NULL;
	core->fns.vset_error = NULL;
	core->fns.new_error = NULL;
}

int core_init(struct ossl_core *core, const OSSL_CORE_HANDLE *handle,
		  const OSSL_DISPATCH *in, struct dbg *dbg)
{
	const OSSL_DISPATCH *iter_in;

	core->libctx = OSSL_LIB_CTX_new_child(handle, in);
	if (!core->libctx) {
		ps_dbg_error(dbg, "Failed to create new libctx (child)");
		return OSSL_RV_ERR;
	}

	core->handle = handle;

	for (iter_in = in; iter_in->function_id != 0; iter_in++) {
		switch (iter_in->function_id) {
		case OSSL_FUNC_CORE_GET_PARAMS:
			core->fns.get_params =
				OSSL_FUNC_core_get_params(iter_in);
			break;
		case OSSL_FUNC_CORE_NEW_ERROR:
			core->fns.new_error =
				OSSL_FUNC_core_new_error(iter_in);
			break;
		case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
			core->fns.set_error_debug =
				OSSL_FUNC_core_set_error_debug(iter_in);
			break;
		case OSSL_FUNC_CORE_VSET_ERROR:
			core->fns.vset_error =
				OSSL_FUNC_core_vset_error(iter_in);
			break;
		default:
			continue;
		}
	}

	/* other members of fns are optional and must be checked before use */
	if (!core->fns.get_params)
		return OSSL_RV_ERR;

	return OSSL_RV_OK;
}
