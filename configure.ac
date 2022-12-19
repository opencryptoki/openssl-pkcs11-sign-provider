# Copyright (C) 2022 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([openssl-pkcs11-sign-provider],
	[0.0.1],
	[https://github.com/opencryptoki/openssl-pkcs11-sign-provider/issues],
	,
	[https://github.com/opencryptoki/openssl-pkcs11-sign-provider]
)

AC_CONFIG_SRCDIR([src/provider.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT([shared disable-static])
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES(
	[OPENSSL],[libcrypto >= 3.0.8, libssl],
	,
	[AC_MSG_ERROR([libcrypto >= 3.0.8 is required])]
)

# Compile flags
AX_CHECK_COMPILE_FLAG(
	[-std=c99],
	[CFLAGS="$CFLAGS -std=c99"],
	AC_MSG_ERROR([C compiler must support C99 standard])
)
STD_CFLAGS="-Wall -Wextra"

AC_SUBST([STD_CFLAGS])
AC_SUBST([SHARED_EXT], $(eval echo "${shrext_cmds}"))

AC_CONFIG_FILES([Makefile
                 man/Makefile
                 src/Makefile
                 tests/Makefile])
AC_OUTPUT
