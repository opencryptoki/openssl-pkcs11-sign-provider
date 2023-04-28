# Copyright (C) 2022 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

libspath=@abs_top_builddir@/src/.libs
testsdir=@abs_srcdir@

check_PROGRAMS = ttls tsignature tecdhe

ttls_SOURCES = ttls.c utils.c utils.h
ttls_CFLAGS = $(AM_CFLAGS) $(STD_CFLAGS) $(OPENSSL_CFLAGS)
ttls_LDADD = $(OPENSSL_LIBS)

tsignature_SOURCES = tsignature.c utils.c utils.h
tsignature_CFLAGS = $(AM_CFLAGS) $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tsignature_LDADD = $(OPENSSL_LIBS)

tecdhe_SOURCES = tecdhe.c utils.c utils.h
tecdhe_CFLAGS = $(AM_CFLAGS) $(STD_CFLAGS) $(OPENSSL_CFLAGS)
tecdhe_LDADD = $(OPENSSL_LIBS)

setup_scripts =
setup_scripts += setup-ock.sh

tmp.ock:
	LIBSPATH=$(libspath) \
	TESTSDIR=$(testsdir) \
	$(testsdir)/setup-ock.sh > setup-ock.log 2>&1

TESTS = openssl-ock tls-ock signature-ock ecdhe-ock

$(TESTS): tmp.ock

dist_check_SCRIPTS = module-test-wrapper \
	$(setup_scripts) \
	topenssl

LOG_COMPILER = $(testsdir)/module-test-wrapper

CLEANFILES = setup-*.log

clean-local:
	rm -rf tmp.ock

DISTCLEANFILES = *~
MAINTAINERCLEANFILES = Makefile.in
