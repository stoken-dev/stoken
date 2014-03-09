/*
 * stoken-internal.h - internal functions called within the stoken package
 *
 * Copyright 2012 Kevin Cernekee <cernekee@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __STOKEN_INTERNAL_H__
#define __STOKEN_INTERNAL_H__

#include "securid.h"
#include "stoken.h"

struct stoken_cfg {
	char			*rc_ver;
	char			*rc_token;
	char			*rc_pin;
};

typedef void (warn_fn_t)(const char *, ...);
static inline void __stoken_warn_empty(const char *fmt, ...) { }

int __stoken_parse_and_decode_token(const char *str, struct securid_token *t,
				    int interactive);
int __stoken_read_rcfile(const char *override, struct stoken_cfg *cfg,
	warn_fn_t warn_fn);
int __stoken_write_rcfile(const char *override, const struct stoken_cfg *cfg,
	warn_fn_t warn_fn);
void __stoken_zap_rcfile_data(struct stoken_cfg *cfg);

#endif /* !__STOKEN_INTERNAL_H__ */
