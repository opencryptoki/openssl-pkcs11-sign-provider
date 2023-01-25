#!/bin/bash
# Copyright (C) IBM Corp. 2022, 2023
# SPDX-License-Identifier: Apache-2.0

gen_unsetvars() {
    grep "^export" "${TMPPDIR}/testvars" \
    | sed -e 's/export/unset/' -e 's/=.*$//' \
    >> "${TMPPDIR}/unsetvars"
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
	openssl req						\
		-newkey ec -pkeyopt ec_paramgen_curve:secp384r1	\
		-nodes -keyout "${ca_prv}"			\
		-x509 -sha256					\
		-days 3650					\
		-subj '/CN=test-ca'				\
		-outform PEM -out "${ca_crt}"

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
