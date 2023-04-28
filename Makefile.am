# Copyright (C) 2022 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

SUBDIRS = src man tests

CONF_TEMPLATE = openssl.cnf.in
CONF_SAMPLES = openssl-ock.cnf.sample

openssl-ock.cnf.sample: $(CONF_TEMPLATE)
	@sed -e "s|@libtoollibs[@]|${libdir}|g" \
	     -e "s|@pkcs11modulepath[@]|libopencryptoki.so|g" \
	     -e "/pkcs11sign-module-init-args.*$$/d" \
	     $< > $@

all-local: $(CONF_SAMPLES)

EXTRA_DIST = $(CONF_TEMPLATE)

CLEANFILES = $(CONF_SAMPLES)
DISTCLEANFILES = *~
MAINTAINERCLEANFILES = Makefile.in test-driver ar-lib \
	aclocal.m4 autom4te.cache/* compile config.guess config.h.in \
	config.sub configure depcomp install-sh ltmain.sh missing m4/*
