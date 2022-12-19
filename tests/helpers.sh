#!/bin/bash
# Copyright (C) IBM Corp. 2022
# SPDX-License-Identifier: Apache-2.0

gen_unsetvars() {
    grep "^export" "${TMPPDIR}/testvars" \
    | sed -e 's/export/unset/' -e 's/=.*$//' \
    >> "${TMPPDIR}/unsetvars"
}
