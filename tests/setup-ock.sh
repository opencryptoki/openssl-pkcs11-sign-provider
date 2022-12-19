#!/bin/bash
# Copyright (C) IBM Corp. 2022
# SPDX-License-Identifier: Apache-2.0

[ ! -r "${TESTSDIR}/helpers.sh" ] && exit 77
source "${TESTSDIR}/helpers.sh"

echo "##################################################"
echo "## Setup test environment (module: ock)"
echo "##"

BASEDIR=$(pwd)

TMPPDIR=tmp.ock
mkdir -p ${TMPPDIR}

echo "## Generate openssl config file"
OPENSSL_CONF=${TMPPDIR}/pkcs11sign.cnf
sed -e "s|@libtoollibs[@]|${LIBSPATH}|g" \
    -e "s|@pkcs11modulepath[@]|libopencryptoki.so|g" \
    -e "/pkcs11sign-module-init-args.*$/d" \
        "${TESTSDIR}/pkcs11sign.cnf.in" > ${OPENSSL_CONF}

echo "## Export tests variables to ${TMPPDIR}/testvars"
tee > ${TMPPDIR}/testvars << DBGSCRIPT
export TESTSDIR="${TESTSDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
export OPENSSL_CONF="${BASEDIR}/${OPENSSL_CONF}"
DBGSCRIPT
gen_unsetvars

echo "##"
echo "##################################################"
exit 0
