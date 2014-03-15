/*
 * library.c - libstoken library implementation
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "securid.h"
#include "sdtid.h"
#include "stoken-internal.h"

struct stoken_ctx {
	struct securid_token	*t;
	struct stoken_cfg	cfg;
};

/***********************************************************************
 * Internal functions (only called from within the stoken package)
 ***********************************************************************/

static int strstarts(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

int __stoken_parse_and_decode_token(const char *str, struct securid_token *t,
				    int interactive)
{
	char buf[BUFLEN];
	const char *p;
	int i, ret;

	memset(t, 0, sizeof(*t));
	t->interactive = interactive;

	do {
		/* try to handle broken quoted-printable input */
		p = strcasestr(str, "ctfData=3D");
		if (p) {
			p += 10;
			break;
		}

		/* normal iPhone/Android soft token URLs */
		p = strcasestr(str, "ctfData=");
		if (p) {
			p += 8;
			break;
		}

		/* sdtid (XML) token format */
		p = strcasestr(str, "<?xml ");
		if (p)
			return sdtid_decode(p, t);

		p = str;
		if (isdigit(*p))
			break;

		/* bogus token string */
		return ERR_GENERAL;
	} while (0);

	for (i = 0; *p; p++) {
		if (i >= BUFLEN - 1)
			return ERR_BAD_LEN;
		if (isdigit(*p))
			buf[i++] = *p;
		else if (*p != '-')
			break;
	}
	buf[i] = 0;

	ret = securid_decode_token(buf, t);

	if (strstarts(str, "com.rsa.securid.iphone://ctf") ||
	    strstarts(str, "com.rsa.securid://ctf") ||
	    strstarts(str, "http://127.0.0.1/securid/ctf"))
		t->is_smartphone = 1;
	return ret;
}

static int next_token(char **in, char *tok, int maxlen)
{
	int len;

	for (len = 0; len < BUFLEN - 1; (*in)++) {
		if (**in == 0 || **in == '\r' || **in == '\n') {
			if (len == 0)
				return -1;
			goto done;
		}
		if (**in == ' ' || **in == '\t') {
			if (len != 0)
				goto done;
			continue;
		}
		*(tok++) = **in;
		len++;
	}

	/* if the loop terminates here, truncate the line and return success */

done:
	*tok = 0;
	return 0;
}

static int parse_rcline(struct stoken_cfg *cfg, int linenum, char *line,
	warn_fn_t warn_fn)
{
	char *p = line, key[BUFLEN], val[BUFLEN], **dst;

	if (next_token(&p, key, BUFLEN) < 0)
		return ERR_NONE;	/* empty line */

	if (key[0] == '#')
		return ERR_NONE;	/* comment */

	if (next_token(&p, val, BUFLEN) < 0) {
		warn_fn("rcfile:%d: missing argument for '%s'\n", linenum, key);
		return ERR_GENERAL;
	}

	dst = NULL;
	if (strcasecmp(key, "version") == 0)
		dst = &cfg->rc_ver;
	else if (strcasecmp(key, "token") == 0)
		dst = &cfg->rc_token;
	else if (strcasecmp(key, "pin") == 0)
		dst = &cfg->rc_pin;

	if (!dst) {
		/* this isn't treated as a fatal error */
		warn_fn("rcfile:%d: unrecognized option '%s'\n", linenum, key);
		return ERR_NONE;
	}

	free(*dst);
	*dst = strdup(val);
	if (!*dst) {
		warn_fn("rcfile:%d: out of memory\n", linenum);
		return ERR_GENERAL;
	}

	return ERR_NONE;
}

static int fopen_rcfile(const char *override, const char *mode,
	warn_fn_t warn_fn, FILE **f)
{
	char *homedir;
	const char *file = override;
	char filename[BUFLEN];
	mode_t old_umask;

	if (!override) {
		homedir = getenv("HOME");
		if (!homedir) {
			warn_fn("rcfile: HOME is not set so I can't read '%s'\n",
				RC_NAME);
			return ERR_GENERAL;
		}

		snprintf(filename, BUFLEN, "%s/%s", homedir, RC_NAME);
		file = filename;
	}

	/* force mode 0600 on creation */
	old_umask = umask(0177);
	*f = fopen(file, mode);
	umask(old_umask);

	if (!*f && override)
		warn_fn("rcfile: can't open '%s'\n", override);

	return *f ? ERR_NONE : ERR_GENERAL;
}

void __stoken_zap_rcfile_data(struct stoken_cfg *cfg)
{
	free(cfg->rc_ver);
	free(cfg->rc_token);
	free(cfg->rc_pin);
	memset(cfg, 0, sizeof(*cfg));
}

int __stoken_read_rcfile(const char *override, struct stoken_cfg *cfg,
	warn_fn_t warn_fn)
{
	FILE *f;
	char buf[BUFLEN];
	int linenum = 1, ret;

	__stoken_zap_rcfile_data(cfg);

	/* XXX: kind of dumb return code here, but it gets the job done */
	ret = fopen_rcfile(override, "r", warn_fn, &f);
	if (ret != ERR_NONE)
		return ERR_MISSING_PASSWORD;

	while (fgets(buf, BUFLEN, f) != NULL) {
		int ret2 = parse_rcline(cfg, linenum++, buf, warn_fn);
		if (ret2 != ERR_NONE)
			ret = ret2;
	}

	if (ferror(f)) {
		ret = ERR_GENERAL;
		warn_fn("rcfile: read error(s) were detected\n");
	}
	fclose(f);

	return ret;
}

int __stoken_write_rcfile(const char *override, const struct stoken_cfg *cfg,
	warn_fn_t warn_fn)
{
	FILE *f;
	int ret;

	ret = fopen_rcfile(override, "w", warn_fn, &f);
	if (ret != ERR_NONE)
		return ret;

	if (cfg->rc_ver)
		fprintf(f, "version %s\n", cfg->rc_ver);
	if (cfg->rc_token)
		fprintf(f, "token %s\n", cfg->rc_token);
	if (cfg->rc_pin)
		fprintf(f, "pin %s\n", cfg->rc_pin);

	if (ferror(f))
		ret = ERR_GENERAL;
	fclose(f);

	return ret;
}

static void zap_current_token(struct stoken_ctx *ctx)
{
	if (ctx->t) {
		sdtid_free(ctx->t->sdtid);
		free(ctx->t);
	}
	ctx->t = NULL;
}

static int clone_token(struct stoken_ctx *ctx, struct securid_token *tmp)
{
	ctx->t = malloc(sizeof(*tmp));
	if (!ctx->t)
		return -EIO;
	memcpy(ctx->t, tmp, sizeof(*tmp));
	return 0;
}

/***********************************************************************
 * Exported functions
 ***********************************************************************/

struct stoken_ctx *stoken_new(void)
{
	struct stoken_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	return ctx;
}

void stoken_destroy(struct stoken_ctx *ctx)
{
	zap_current_token(ctx);
	__stoken_zap_rcfile_data(&ctx->cfg);
	free(ctx);
}

int stoken_import_rcfile(struct stoken_ctx *ctx, const char *path)
{
	struct securid_token tmp;
	int rc;

	zap_current_token(ctx);

	rc = __stoken_read_rcfile(path, &ctx->cfg, &__stoken_warn_empty);
	if (rc == ERR_MISSING_PASSWORD)
		return -ENOENT;
	else if (rc != ERR_NONE)
		goto bad;

	if (__stoken_parse_and_decode_token(ctx->cfg.rc_token, &tmp, 0) !=
	    ERR_NONE)
		goto bad;

	if (ctx->cfg.rc_pin) {
		if (tmp.flags & FL_PASSPROT)
			tmp.enc_pin_str = ctx->cfg.rc_pin;
		else {
			if (securid_pin_format_ok(ctx->cfg.rc_pin) == ERR_NONE)
				strncpy(tmp.pin, ctx->cfg.rc_pin,
					MAX_PIN + 1);
			else
				goto bad;
		}
	}
	return clone_token(ctx, &tmp);

bad:
	__stoken_zap_rcfile_data(&ctx->cfg);
	return -EINVAL;
}

int stoken_import_string(struct stoken_ctx *ctx, const char *token_string)
{
	struct securid_token tmp;

	zap_current_token(ctx);

	if (__stoken_parse_and_decode_token(token_string, &tmp, 0) != ERR_NONE)
		return -EINVAL;
	return clone_token(ctx, &tmp);
}

void stoken_pin_range(struct stoken_ctx *ctx, int *min_pin, int *max_pin)
{
	*min_pin = MIN_PIN;
	*max_pin = MAX_PIN;
}

int stoken_pin_required(struct stoken_ctx *ctx)
{
	/* don't prompt for a PIN if it was saved in the rcfile */
	if (ctx->t->enc_pin_str || strlen(ctx->t->pin))
		return 0;
	return securid_pin_required(ctx->t);
}

int stoken_pass_required(struct stoken_ctx *ctx)
{
	return securid_pass_required(ctx->t);
}

int stoken_devid_required(struct stoken_ctx *ctx)
{
	return securid_devid_required(ctx->t);
}

int stoken_check_pin(struct stoken_ctx *ctx, const char *pin)
{
	return securid_pin_format_ok(pin) == ERR_NONE ? 0 : -EINVAL;
}

int stoken_check_devid(struct stoken_ctx *ctx, const char *devid)
{
	if (securid_decrypt_seed(ctx->t, "", devid) == ERR_BAD_DEVID)
		return -EINVAL;
	return 0;
}

int stoken_decrypt_seed(struct stoken_ctx *ctx, const char *pass,
	const char *devid)
{
	if (securid_decrypt_seed(ctx->t, pass, devid) != ERR_NONE)
		return -EINVAL;
	if (ctx->t->enc_pin_str) {
		if (securid_decrypt_pin(ctx->t->enc_pin_str, pass,
		    ctx->t->pin) != ERR_NONE)
			return -EINVAL;
	}

	return 0;
}

char *stoken_encrypt_seed(struct stoken_ctx *ctx, const char *pass,
	const char *devid)
{
	char *ret;

	if (!ctx->t || !ctx->t->has_dec_seed)
		return NULL;
	ret = calloc(1, MAX_TOKEN_CHARS + 1);
	if (!ret)
		return NULL;
	if (securid_encode_token(ctx->t, pass, devid, ret) != ERR_NONE) {
		free(ret);
		return NULL;
	}
	return ret;
}

int stoken_compute_tokencode(struct stoken_ctx *ctx, time_t when,
	const char *pin, char *out)
{
	if (stoken_pin_required(ctx) && pin) {
		if (securid_pin_format_ok(pin) != ERR_NONE)
			return -EINVAL;
		strncpy(ctx->t->pin, pin, MAX_PIN + 1);
	}
	securid_compute_tokencode(ctx->t, when, out);
	return 0;
}
