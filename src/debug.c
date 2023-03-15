/*
 * Copyright (C) IBM Corp. 2022
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"

#define PKCS11SIGN_ENV_DBG	"PKCS11SIGN_DEBUG"
#define PKCS11SIGN_ENV_DBG_LVL	"PKCS11SIGN_DEBUG_LEVEL"

static int get_level(void)
{
	const char *env;

	env = getenv(PKCS11SIGN_ENV_DBG_LVL);
	if (!env)
		return DBG_ERROR;

	return atoi(env);
}

static FILE *get_stream(void)
{
	const char *env;
	FILE *s;

	env = getenv(PKCS11SIGN_ENV_DBG);
	if (!env)
		return NULL;

	s = fopen(env, "w");
	if (s)
		return s;

	fprintf(stderr, "Unable to open debug file %s. Use stderr instead.\n",
		env);
	return stderr;
}

void ps_dbg_println(unsigned int level, struct dbg *dbg,
		    const char *file, int line, const char *func,
		    const char *fmt, ...)
{
	va_list args;

	if ((!ps_dbg_enabled(dbg)) || (dbg->level < level))
		return;

	fprintf(dbg->stream, "[%d] ", level);
	if (file)
		fprintf(dbg->stream, "file: %s, line: %d, ", file, line);
	if (func)
		fprintf(dbg->stream, "func: %s, ", func);

	va_start(args, fmt);
	vfprintf(dbg->stream, fmt, args);
	va_end(args);

	fwrite("\n", 1, 1, dbg->stream);
	fflush(dbg->stream);
}

void ps_dbg_exit(struct dbg *dbg)
{
	FILE *stream;

	if (!dbg)
		return;

	stream = dbg->stream;

	dbg->stream = NULL;
	dbg->level = DBG_ERROR;

	if (stream)
		fclose(stream);
}

void ps_dbg_init(struct dbg *dbg)
{
	if ((!dbg) || (dbg->stream))
		return;

	dbg->level = get_level();
	dbg->stream = get_stream();
}
