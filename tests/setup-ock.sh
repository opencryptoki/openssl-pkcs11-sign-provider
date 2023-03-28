#!/bin/bash
# Copyright (C) IBM Corp. 2022, 2023
# SPDX-License-Identifier: Apache-2.0

# Interface
OCK_USER_PIN=${OCK_USER_PIN:-"12345678"}
OCK_SLOT=${OCK_SLOT:-"3"}
OCK_TOKEN=${OCK_TOKEN:-"softtok"}
# Interface (end)

# Point to the local openssl configuration later to prevent
# chicken-egg-problems.
unset OPENSSL_CONF

[ ! -r "${TESTSDIR}/helpers.sh" ] && exit 77
source "${TESTSDIR}/helpers.sh"

command -v p11tool > /dev/null || exit 77
P11TOOL="p11tool --batch --login"

echo "##################################################"
echo "## Check test environment requirements (module: ock)"
echo "##"

#######################################
echo "## Check pkcsslotd"
pidof -q pkcsslotd
if [ $? -eq 1 ]; then
	echo "!!! pkcsslotd not running !!!"
	exit 77
fi

echo "##################################################"
echo "## Setup test environment (module: ock)"
echo "##"

BASEDIR=$(pwd)

TMPPDIR=tmp.ock
mkdir -p ${TMPPDIR} \
|| exit 99

#######################################
echo "## Generate test data"
generate_payload

#######################################
echo "## Generate PKCS#11 pin file"
PIN_SOURCE=${TMPPDIR}/pinfile.txt
touch "${PIN_SOURCE}"
chmod 600 "${PIN_SOURCE}"
printf "%s" "${OCK_USER_PIN}" > ${PIN_SOURCE} \
|| exit 99

#######################################
echo "## Generate CA key/cert and server key/cert"
LABEL="test_ec_secp384r1"
FILE_PEM_CA_PRV="${TMPPDIR}/ca_key.prv"
FILE_PEM_CA_CRT="${TMPPDIR}/ca_cert.crt"
FILE_PEM_ECDSA_PRV="${TMPPDIR}/${LABEL}_key.prv"
FILE_PEM_ECDSA_PUB="${TMPPDIR}/${LABEL}_key.pub"
FILE_PEM_ECDSA_CRT="${TMPPDIR}/${LABEL}_cert.crt"
generate_ec_tls_certificates \
	${FILE_PEM_CA_PRV} ${FILE_PEM_CA_CRT} \
	${FILE_PEM_ECDSA_PRV} ${FILE_PEM_ECDSA_PUB} ${FILE_PEM_ECDSA_CRT}

#######################################
echo "## Re-import server keys"
URI_TOKEN="pkcs11:token=${OCK_TOKEN}"
URI_KEY_ECDSA="${URI_TOKEN};object=${LABEL}"
URI_KEY_ECDSA_PRV="${URI_KEY_ECDSA};type=private"
URI_KEY_ECDSA_PUB="${URI_KEY_ECDSA};type=public"

GNUTLS_PIN=${OCK_USER_PIN}			\
${P11TOOL} --delete				\
	   "${URI_KEY_ECDSA}" 2> /dev/null

GNUTLS_PIN=${OCK_USER_PIN}			\
${P11TOOL} --write --label ${LABEL}		\
	   --mark-private			\
	   --load-privkey=${FILE_PEM_ECDSA_PRV}	\
	   "${URI_TOKEN}" 2> /dev/null		\
|| exit 99

GNUTLS_PIN=${OCK_USER_PIN}			\
${P11TOOL} --write --label ${LABEL}		\
	   --load-pubkey=${FILE_PEM_ECDSA_PUB}	\
	   "${URI_TOKEN}" 2> /dev/null		\
|| exit 99

#######################################
echo "## Generate openssl config file"
OPENSSL_CONF=${TMPPDIR}/pkcs11sign.cnf
sed -e "s|@libtoollibs[@]|${LIBSPATH}|g" \
    -e "s|@pkcs11modulepath[@]|libopencryptoki.so|g" \
    -e "/pkcs11sign-module-init-args.*$/d" \
        "${TESTSDIR}/pkcs11sign.cnf.in" > ${OPENSSL_CONF} \
|| exit 99

#######################################
echo "## Export tests variables to ${TMPPDIR}/testvars"
tee > ${TMPPDIR}/testvars << DBGSCRIPT
export TESTSDIR="${TESTSDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
export OPENSSL_CONF="${BASEDIR}/${OPENSSL_CONF}"
export PIN_SOURCE=${BASEDIR}/${PIN_SOURCE}
export FILE_PEM_CA_PRV="${BASEDIR}/${FILE_PEM_CA_PRV}"
export FILE_PEM_CA_CRT="${BASEDIR}/${FILE_PEM_CA_CRT}"
export FILE_PEM_ECDSA_PRV="${BASEDIR}/${FILE_PEM_ECDSA_PRV}"
export FILE_PEM_ECDSA_PUB="${BASEDIR}/${FILE_PEM_ECDSA_PUB}"
export FILE_PEM_ECDSA_CRT="${BASEDIR}/${FILE_PEM_ECDSA_CRT}"
export URI_KEY_ECDSA="${URI_KEY_ECDSA}?pin-source=${BASEDIR}/${PIN_SOURCE}"
export URI_KEY_ECDSA_PRV="${URI_KEY_ECDSA_PRV}?pin-source=${BASEDIR}/${PIN_SOURCE}"
export URI_KEY_ECDSA_PUB="${URI_KEY_ECDSA_PUB}?pin-source=${BASEDIR}/${PIN_SOURCE}"
DBGSCRIPT
test $? -eq 0 \
|| exit 99
gen_unsetvars

echo "##"
echo "##################################################"
exit 0
