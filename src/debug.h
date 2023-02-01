/*
 * Copyright (C) IBM Corp. 2022, 2023
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PKCS11SIGN_DEBUG_H
#define _PKCS11SIGN_DEBUG_H

#include <stdarg.h>
#include <stdbool.h>

#include "common.h"

#define DBG_ERROR	(0)
#define DBG_WARN	(1)
#define DBG_INFO	(2)
#define DBG_DEBUG	(3)

inline bool ps_dbg_enabled(struct dbg *dbg)
{
	return (dbg) && (dbg->stream);
}

void ps_dbg_println(unsigned int level, struct dbg *dbg,
		    const char *file, int line, const char *func,
		    const char *fmt, ...);
#define ps_dbg_error(dbg, fmt...) \
	ps_dbg_println(DBG_ERROR, dbg, NULL, 0, NULL, fmt)
#define ps_dbg_warn(dbg, fmt...) \
	ps_dbg_println(DBG_WARN, dbg, NULL, 0, NULL, fmt)
#define ps_dbg_info(dbg, fmt...) \
	ps_dbg_println(DBG_INFO, dbg, NULL, 0, NULL, fmt)
#define ps_dbg_debug(dbg, fmt...) \
	ps_dbg_println(DBG_DEBUG, dbg, __FILE__, __LINE__, __func__, fmt)

void ps_dbg_init(struct dbg *dbg);
void ps_dbg_exit(struct dbg *dbg);

#endif /* _PKCS11SIGN_DEBUG_H */
