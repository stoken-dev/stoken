/*
 * common.h - Common definitions for stoken and stoken-gui
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

#ifndef __STOKEN_COMMON_H__
#define __STOKEN_COMMON_H__

#include "config.h"

#include <stdarg.h>
#include <sys/types.h>

#define BUFLEN			256
#define RC_NAME			".stokenrc"
#define RC_VER			1

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
};

static const char stoken_errstr[][32] = {
	"Success",
	"General failure",
	"Invalid length",
	"Unsupported token version",
	"Checksum failed",
	"Invalid password format",
	"Missing required password",
	"Seed decryption failed",
	"Device ID mismatch",
};

#define NOT_GUI			0
#define IS_GUI			1

void prompt(const char *fmt, ...);
void warn(const char *fmt, ...);
void dbg(const char *fmt, ...);
void die(const char *fmt, ...);

char *xstrdup(const char *s);
char *xconcat(const char *s1, const char *s2);
void *xmalloc(size_t size);
void *xzalloc(size_t size);

char *parse_cmdline(int argc, char **argv, int is_gui);
int common_init(char *cmd);
int write_token_and_pin(char *token_str, char *pin_str, char *password);
char *format_token(const char *raw_token_str);

/* binary flags, long options */
extern int opt_random, opt_keep_password, opt_blocks, opt_iphone, opt_android,
	opt_seed;

/* binary flags, short/long options */
extern int opt_debug, opt_version, opt_help, opt_batch, opt_force, opt_stdin;

/* string arguments */
extern char *opt_rcfile, *opt_file, *opt_token, *opt_devid, *opt_password,
	    *opt_pin, *opt_use_time, *opt_new_password, *opt_new_devid,
	    *opt_new_pin;

/* token read from .stokenrc, if available */
struct securid_token;
extern struct securid_token *current_token;

#endif /* !__STOKEN_COMMON_H__ */
