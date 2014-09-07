/*
 * common.c - Common functions for stoken and stoken-gui
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

#include "config.h"

#include <ctype.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tomcrypt.h>

#include "common.h"
#include "securid.h"
#include "stoken.h"
#include "stoken-internal.h"

/* globals - shared with cli.c or gui.c */

int opt_random, opt_keep_password, opt_blocks, opt_iphone, opt_android,
	opt_v3, opt_show_qr, opt_seed, opt_sdtid, opt_small, opt_next;
int opt_debug, opt_version, opt_help, opt_batch, opt_force, opt_stdin;
char *opt_rcfile, *opt_file, *opt_token, *opt_devid, *opt_password,
     *opt_pin, *opt_use_time, *opt_new_password, *opt_new_devid,
     *opt_new_pin, *opt_template, *opt_qr;
struct securid_token *current_token;

static int debug_level;
static struct stoken_cfg *cfg;

void prompt(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (!opt_stdin)
		vfprintf(stdout, fmt, ap);
	va_end(ap);
}

void warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fflush(stdout);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void dbg(const char *fmt, ...)
{
	va_list ap;

	if (!debug_level)
		return;
	va_start(ap, fmt);
	fflush(stdout);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fflush(stdout);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

char *xstrdup(const char *s)
{
	char *ret = strdup(s);
	if (!ret)
		die("out of memory\n");
	return ret;
}

char *xconcat(const char *s1, const char *s2)
{
	char *ret = xmalloc(strlen(s1) + strlen(s2) + 1);
	strcpy(ret, s1);
	strcat(ret, s2);
	return ret;
}

void xstrncpy(char *dest, const char *src, size_t n)
{
	strncpy(dest, src, n);
	dest[n - 1] = 0;
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret)
		die("out of memory\n");
	return ret;
}

void *xzalloc(size_t size)
{
	void *ret = xmalloc(size);
	memset(ret, 0, size);
	return ret;
}

enum {
	OPT_DEVID		= 1,
	OPT_USE_TIME,
	OPT_NEW_PASSWORD,
	OPT_NEW_DEVID,
	OPT_NEW_PIN,
	OPT_TEMPLATE,
	OPT_QR,
};

static const struct option long_opts[] = {
	/* global: token sources */
	{ "rcfile",         1, NULL,                    'r'               },
	{ "file",           1, NULL,                    'i'               },
	{ "token",          1, NULL,                    't'               },
	{ "random",         0, &opt_random,             1,                },

	/* global: secrets used to decrypt/use a seed */
	{ "devid",          1, NULL,                    OPT_DEVID         },
	{ "password",       1, NULL,                    'p'               },
	{ "pin",            1, NULL,                    'n'               },

	/* GUI: use smaller window */
	{ "small",          0, &opt_small,              1                 },

	/* global: misc/debug */
	{ "debug",          0, NULL,                    'd'               },
	{ "version",        0, NULL,                    'v'               },
	{ "force",          0, NULL,                    'f'               },
	{ "use-time",       1, NULL,                    OPT_USE_TIME      },
	{ "help",           0, NULL,                    'h'               },

	/* all remaining options are for CLI only */
#define FINAL_GUI_OPTION	"help"

	{ "batch",          0, NULL,                    'b'               },

	/* used for tokencode generation */
	{ "next",           0, &opt_next,               1                 },

	/* these are mostly for exporting/issuing tokens */
	{ "new-password",   1, NULL,                    OPT_NEW_PASSWORD  },
	{ "new-devid",      1, NULL,                    OPT_NEW_DEVID     },
	{ "new-pin",        1, NULL,                    OPT_NEW_PIN       },
	{ "template",       1, NULL,                    OPT_TEMPLATE      },
	{ "keep-password",  0, &opt_keep_password,      1                 },
	{ "blocks",         0, &opt_blocks,             1                 },
	{ "iphone",         0, &opt_iphone,             1                 },
	{ "android",        0, &opt_android,            1                 },
	{ "v3",             0, &opt_v3,                 1                 },
	{ "sdtid",          0, &opt_sdtid,              1                 },
	{ "xml",            0, &opt_sdtid,              1                 },
	{ "qr",             1, NULL,                    OPT_QR            },
	{ "show-qr",        0, &opt_show_qr,            1                 },
	{ "seed",           0, &opt_seed,               1                 },
	{ "stdin",          0, NULL,                    's'               },
	{ NULL,             0, NULL,                    0                 },
};

static void usage_common(void)
{
	puts("Alternate seed sources:");
	puts("");
	puts("  --rcfile=<alt_rcfile>");
	puts("  --token=<token_string>");
	puts("  --file=<token_file>");
	puts("  --random");
	puts("");
	puts("See the stoken(1) man page for additional information.");
}

static void usage_gui(void)
{
	puts("usage: stoken-gui [ <options> ]");
	puts("");
	usage_common();
	exit(1);
}

static void usage_cli(void)
{
	puts("usage: stoken <cmd> [ <options> ]");
	puts("");
	puts("Common operations:");
	puts("");
	puts("  stoken [ tokencode ] [ --stdin ]");
	puts("  stoken import { --token=<token_string> | --file=<token_file> } [ --force ]");
	puts("  stoken setpass");
	puts("  stoken setpin");
	puts("");
	puts("Other commands:");
	puts("");
	puts("  stoken show [ --seed ]");
	puts("  stoken export [ { --blocks | --iphone | --android | --v3 | --sdtid |");
	puts("                    --qr=<file> | --show-qr } ]");
	puts("  stoken issue [ --template=<sdtid_skeleton> ]");
	puts("");
	usage_common();
	exit(1);
}

static void show_version(void)
{
	puts(PACKAGE_STRING " - software token for Linux/UNIX systems");
	puts("Copyright (C) 2014 Kevin Cernekee <cernekee@gmail.com>");
	puts("");
	puts("This is free software with ABSOLUTELY NO WARRANTY.");
	puts("For details see the COPYING.LIB file in the source distribution.");
	exit(0);
}

char *parse_cmdline(int argc, char **argv, int is_gui)
{
	int ret, longindex = 0, last_gui_opt = 0;
	const struct option *opt = long_opts;
	char *cmd = NULL;

	for (; strcmp(opt->name, FINAL_GUI_OPTION); last_gui_opt++, opt++)
		;

	while (1) {
		ret = getopt_long(argc, argv, "r:i:t:p:n:dvhbfs",
				  long_opts, &longindex);
		if (ret == -1)
			break;

		if (is_gui && longindex > last_gui_opt)
			die("error: --%s is not valid in GUI mode\n",
				long_opts[longindex].name);

		switch (ret) {
		case 'r': opt_rcfile = optarg; break;
		case 'i': opt_file = optarg; break;
		case 't': opt_token = optarg; break;
		case 'p': opt_password = optarg; break;
		case 'n': opt_pin = optarg; break;
		case 'd': opt_debug = 1; break;
		case 'v': opt_version = 1; break;
		case 'h': opt_help = 1; break;
		case 'b': opt_batch = 1; break;
		case 'f': opt_force = 1; break;
		case 's': opt_stdin = 1; break;
		case OPT_DEVID: opt_devid = optarg; break;
		case OPT_USE_TIME: opt_use_time = optarg; break;
		case OPT_NEW_PASSWORD: opt_new_password = optarg; break;
		case OPT_NEW_DEVID: opt_new_devid = optarg; break;
		case OPT_NEW_PIN: opt_new_pin = optarg; break;
		case OPT_TEMPLATE: opt_template = optarg; break;
		case OPT_QR: opt_qr = optarg; break;
		case 0: break;
		default: opt_help = 1;
		}
	}

	if (!is_gui && optind == argc - 1)
		cmd = argv[optind];
	else if (optind == argc)
		cmd = xstrdup("tokencode");	/* default command */
	else
		warn("error: too many command-line arguments\n");

	if (!cmd || !strcmp(cmd, "help") || opt_help) {
		if (is_gui)
			usage_gui();
		else
			usage_cli();
	}

	if (!strcmp(cmd, "version") || opt_version)
		show_version();

	return cmd;
}

static int read_token_from_file(char *filename, struct securid_token *t)
{
	char buf[65536], *p;
	int rc = ERR_BAD_LEN;
	FILE *f;
	size_t len;

	f = fopen(filename, "r");
	if (f == NULL)
		return ERR_FILE_READ;

	len = fread(buf, 1, sizeof(buf) - 1, f);
	if (ferror(f))
		len = 0;
	fclose(f);

	if (len == 0)
		return ERR_FILE_READ;
	buf[len] = 0;

	for (p = buf; *p; ) {
		rc = __stoken_parse_and_decode_token(p, t, 1);

		/*
		 * keep checking more lines until we find something that
		 * looks like a token
		 */
		if (rc != ERR_GENERAL)
			break;

		p = strchr(p, '\n');
		if (!p)
			break;
		p++;
	}

	return rc;
}

static int decode_rc_token(struct stoken_cfg *cfg, struct securid_token *t)
{
	int rc = securid_decode_token(cfg->rc_token, t);

	if (rc != ERR_NONE) {
		warn("rcfile: token data is garbled, ignoring\n");
		return rc;
	}

	if (cfg->rc_pin) {
		if (t->flags & FL_PASSPROT)
			t->enc_pin_str = xstrdup(cfg->rc_pin);
		else {
			if (securid_pin_format_ok(cfg->rc_pin) == ERR_NONE)
				xstrncpy(t->pin, cfg->rc_pin, MAX_PIN + 1);
			else
				warn("rcfile: invalid PIN format\n");
		}
	}
	return ERR_NONE;
}

int common_init(char *cmd)
{
	int rc;
	struct securid_token *t;
	int is_import = !strcmp(cmd, "import");

	/*
	 * we don't actually scrub memory, but at least try to keep the seeds
	 * from being swapped out to disk
	 */
#ifdef HAVE_MLOCKALL
	mlockall(MCL_CURRENT | MCL_FUTURE);
#endif

	/* libtomcrypt init for sdtid BatchSignature generation */
	ltc_mp = ltm_desc;
	if (register_hash(&sha1_desc) == -1)
		return ERR_GENERAL;

	cfg = xzalloc(sizeof(*cfg));
	if (__stoken_read_rcfile(opt_rcfile, cfg,
				 is_import ? &dbg : &warn) != ERR_NONE)
		__stoken_zap_rcfile_data(cfg);

	if (cfg->rc_ver && atoi(cfg->rc_ver) != RC_VER) {
		warn("rcfile: version mismatch, ignoring contents\n");
		__stoken_zap_rcfile_data(cfg);
	}

	/* accept a token from the command line, or fall back to the rcfile */
	do {
		t = xzalloc(sizeof(struct securid_token));

		if (opt_token) {
			rc = __stoken_parse_and_decode_token(opt_token, t, 1);
			if (rc != ERR_NONE)
				die("error: --token string is garbled: %s\n",
				    stoken_errstr[rc]);
			current_token = t;
			break;
		}
		if (opt_file) {
			rc = read_token_from_file(opt_file, t);
			if (rc == ERR_MULTIPLE_TOKENS)
				die("error: multiple tokens found; use 'stoken split' to create separate files\n");
			else if (rc != ERR_NONE)
				die("error: no valid token in file '%s': %s\n",
				    opt_file, stoken_errstr[rc]);
			current_token = t;
			break;
		}
		if (opt_random) {
			rc = securid_random_token(t);
			if (rc != ERR_NONE)
				die("error: can't generate random token\n");
			current_token = t;
			break;
		}
		if (cfg->rc_token) {
			if (is_import)
				die("error: please specify --file, --token, or --random\n");
			if (decode_rc_token(cfg, t) == ERR_NONE) {
				current_token = t;
				break;
			}
		}
		free(t);
	} while (0);

	if (is_import && cfg->rc_token && !opt_force)
		die("error: token already exists; use --force to overwrite it\n");

	return ERR_NONE;
}

int write_token_and_pin(char *token_str, char *pin_str, char *password)
{
	free(cfg->rc_ver);
	free(cfg->rc_token);
	free(cfg->rc_pin);

	cfg->rc_token = xstrdup(token_str);

	if (pin_str && !password)
		cfg->rc_pin = xstrdup(pin_str);
	else if (pin_str && password) {
		cfg->rc_pin = securid_encrypt_pin(pin_str, password);
		if (!cfg->rc_pin)
			return ERR_GENERAL;
	} else
		cfg->rc_pin = NULL;

	cfg->rc_ver = xstrdup("1");

	return __stoken_write_rcfile(opt_rcfile, cfg, &warn);
}

char *format_token(const char *token_str)
{
	int i;
	char *out, *p;

	if (opt_iphone)
		return xconcat("com.rsa.securid.iphone://ctf?ctfData=",
			token_str);
	else if (opt_android || opt_v3)
		return xconcat("http://127.0.0.1/securid/ctf?ctfData=",
			token_str);
	else if (!opt_blocks)
		return xstrdup(token_str);

	/* user requested blocks of 5 digits (--blocks) */
	i = strlen(token_str);
	out = xzalloc(i + (i / 5) + 2);

	for (i = 0, p = out; token_str[i]; i++) {
		if (i % 5 == 0 && i)
			*(p++) = '-';
		*(p++) = token_str[i];
	}

	return out;
}
