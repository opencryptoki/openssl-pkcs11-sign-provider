#!/bin/bash
# Copyright (C) IBM Corp. 2022, 2023
# SPDX-License-Identifier: Apache-2.0

gen_unsetenv() {
    grep "^export" "${TMPPDIR}/setenv" \
    | sed -e 's/export/unset/' -e 's/=.*$//' \
    >> "${TMPPDIR}/unsetenv"
}

ensure_ca_key_cert() {
	local ca_prv="$1"
	local ca_crt="$2"

	# skip, if key/cert already exists
	test -r "${ca_prv}" -a -r "${ca_crt}" && return

	# create ca key/certificate (selfsigned)
	openssl req						\
		-newkey ec -pkeyopt ec_paramgen_curve:secp384r1	\
		-nodes -keyout "${ca_prv}"			\
		-x509 -sha256					\
		-days 3650					\
		-subj '/CN=test-ca'				\
		-outform PEM -out "${ca_crt}"
}

generate_rsa_tls_certificates() {
	local ca_prv="$1"
	local ca_crt="$2"
	local server_prv="$3"
	local server_pub="$4"
	local server_crt="$5"

	local tmppdir=$(dirname "${server_crt}")

	cat > "${tmppdir}/server.v3.ext" << EOF
basicConstraints=critical,CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
EOF

	# create ca key/certificate (selfsigned)
	ensure_ca_key_cert "${ca_prv}" "${ca_crt}"

	# create server key/csr (self-signed)
	openssl req						\
		-newkey rsa:4096				\
		-nodes -keyout ${server_prv}			\
		-new -subj '/CN=localhost'			\
		-outform PEM -out "${tmppdir}/tmp.csr"

	# sign server certificate (ca-signed)
	openssl x509						\
		-req -sha256 -in "${tmppdir}/tmp.csr"		\
		-CAkey "${ca_prv}" -CA "${ca_crt}"		\
		-CAcreateserial					\
		-days 365					\
		-extfile "${tmppdir}/server.v3.ext"		\
		-outform PEM -out "${server_crt}"

	# export public server key
	openssl pkey 						\
		-pubout						\
		-in ${server_prv}				\
		-outform PEM -out ${server_pub}

	# cleanup
	rm -f "${tmppdir}/tmp.csr" "${tmppdir}/server.v3.ext"
}

generate_ec_tls_certificates() {
	local ca_prv="$1"
	local ca_crt="$2"
	local server_prv="$3"
	local server_pub="$4"
	local server_crt="$5"

	local tmppdir=$(dirname "${server_crt}")

	cat > "${tmppdir}/server.v3.ext" << EOF
basicConstraints=critical,CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
EOF

	# create ca key/certificate (selfsigned)
	ensure_ca_key_cert "${ca_prv}" "${ca_crt}"

	# create server key/csr (self-signed)
	openssl req						\
		-newkey ec -pkeyopt ec_paramgen_curve:secp384r1	\
		-nodes -keyout ${server_prv}			\
		-new -subj '/CN=localhost'			\
		-outform PEM -out "${tmppdir}/tmp.csr"

	# sign server certificate (ca-signed)
	openssl x509						\
		-req -sha256 -in "${tmppdir}/tmp.csr"		\
		-CAkey "${ca_prv}" -CA "${ca_crt}"		\
		-CAcreateserial					\
		-days 365					\
		-extfile "${tmppdir}/server.v3.ext"		\
		-outform PEM -out "${server_crt}"

	# export public server key
	openssl pkey 						\
		-pubout						\
		-in ${server_prv}				\
		-outform PEM -out ${server_pub}

	# cleanup
	rm -f "${tmppdir}/tmp.csr" "${tmppdir}/server.v3.ext"
}

generate_payload() {
	for length in 256 512; do
		DATA="${TMPPDIR}/random-${length}.bin"

		dd if=/dev/random				\
		   of="${DATA}"					\
		   bs=1 count=${length}

		openssl sha256					\
			-binary					\
			-out "${DATA}.sha256"			\
			"${DATA}"
	done

	for length in 1 64; do
		DATA="${TMPPDIR}/random-${length}k.bin"

		dd if=/dev/random				\
		   of="${DATA}"					\
		   bs=1K count=${length}

		openssl sha256					\
			-binary					\
			-out "${DATA}.sha256"			\
			"${DATA}"
	done
}

ossl() {
	echo "r "$* >> ${TMPPDIR}/ossl.gdb
	echo openssl $*
	eval openssl $1
}
