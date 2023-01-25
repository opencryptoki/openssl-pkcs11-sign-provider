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
echo "## Generate PKCS#11 pin file"
PIN_SOURCE=${TMPPDIR}/pinfile.txt
printf "%s" "${OCK_USER_PIN}" > ${PIN_SOURCE} \
|| exit 99

echo "## Generate EC Key (if required)"
URI_KEY_ECDSA="pkcs11:token=${OCK_TOKEN};object=test_ec_secp256r1"
URI_KEY_ECDSA_PRV="${URI_KEY_ECDSA};type=private"
URI_KEY_ECDSA_PUB="${URI_KEY_ECDSA};type=public"
GNUTLS_PIN=${OCK_USER_PIN} \
${P11TOOL} --list-all \
	   "${URI_KEY_ECDSA}" 2> /dev/null || \
GNUTLS_PIN=${OCK_USER_PIN} \
${P11TOOL} --generate-privkey ecc \
	   --curve "secp256r1" \
	   --label "test_ec_secp256r1" \
	   "pkcs11:token=${OCK_TOKEN}" || \
exit 99

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
