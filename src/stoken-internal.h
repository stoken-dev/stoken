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

#include "stoken.h"

#define BUFLEN			2048
#define RC_NAME			".stokenrc"
#define RC_VER			1

struct stoken_cfg {
	char			*rc_ver;
	char			*rc_token;
	char			*rc_pin;
};

struct securid_token;

/* keep this in sync with stoken_errstr */
enum {
	ERR_NONE = 0,
	ERR_GENERAL,
	ERR_BAD_LEN,
	ERR_TOKEN_VERSION,
	ERR_CHECKSUM_FAILED,
	ERR_BAD_PASSWORD,
	ERR_MISSING_PASSWORD,
	ERR_DECRYPT_FAILED,
	ERR_BAD_DEVID,
	ERR_NO_MEMORY,
	ERR_FILE_READ,
	ERR_MULTIPLE_TOKENS,
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

#ifdef __ANDROID__
/* Sigh.  This exists but it isn't in the Bionic headers. */
int mkstemps(char *path, int slen);
#endif

/* crypto wrappers */
int stc_standalone_init(void);

#endif /* !__STOKEN_INTERNAL_H__ */
