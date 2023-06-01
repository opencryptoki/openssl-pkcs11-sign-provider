# Copyright (C) IBM Corp. 2022, 2023
# SPDX-License-Identifier: Apache-2.0

EXTRA_DIST = provider.exports

AM_CFLAGS = $(STD_CFLAGS) -I$(top_srcdir)/include

SHARED_EXT=@SHARED_EXT@

lib_LTLIBRARIES = pkcs11sign.la

pkcs11sign_la_SOURCES = \
	provider.c provider.h \
	debug.c debug.h \
	ossl.c ossl.h \
	pkcs11.c pkcs11.h \
	store.c store.h \
	uri.c uri.h \
	object.c object.h \
	keymgmt.c keymgmt.h \
	signature.c signature.h \
	asym.c asym.h \
	keyexch.c keyexch.h \
	common.c common.h \
	consttime.h

pkcs11sign_la_CFLAGS = $(AM_CFLAGS) $(STD_FLAGS) $(OPENSSL_CFLAGS) -D_GNU_SOURCE
pkcs11sign_la_LIBADD = $(OPENSSL_LIBS)
pkcs11sign_la_LDFLAGS = \
	$(AM_LDFLAGS) -module \
	-shared -shrext $(SHARED_EXT) \
	-avoid-version \
	-export-symbols "$(srcdir)/provider.exports"

DISTCLEANFILES = *~
MAINTAINERCLEANFILES = Makefile.in
