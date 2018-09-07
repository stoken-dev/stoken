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

#include <stdarg.h>
#include <stdint.h>
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

STOKEN_EXPORT int __stoken_parse_and_decode_token(const char *str,
						  struct securid_token *t,
						  int interactive);

STOKEN_EXPORT int __stoken_read_rcfile(const char *override,
				       struct stoken_cfg *cfg,
				       warn_fn_t warn_fn);

STOKEN_EXPORT int __stoken_write_rcfile(const char *override,
					const struct stoken_cfg *cfg,
					warn_fn_t warn_fn);

STOKEN_EXPORT void __stoken_zap_rcfile_data(struct stoken_cfg *cfg);

#ifdef __ANDROID__
/* Sigh.  This exists but it isn't in the Bionic headers. */
int mkstemps(char *path, int slen);
#elif !defined(HAVE_MKSTEMPS)
#define mkstemps stoken__mkstemps
STOKEN_EXPORT int stoken__mkstemps(char *path, int slen);
#endif

#ifndef HAVE_STRCASESTR
#define strcasestr stoken__strcasestr
STOKEN_EXPORT char *stoken__strcasestr(const char *haystack,
				       const char *needle);
#endif

#ifndef HAVE_GMTIME_R
#define gmtime_r stoken__gmtime_r
struct tm *stoken__gmtime_r(const time_t *timep, struct tm *result);
#endif

#ifndef HAVE_TIMEGM
#define timegm stoken__timegm
time_t stoken__timegm(struct tm *tm);
#endif

/* crypto wrappers */
STOKEN_EXPORT int stc_standalone_init(void);
void stc_aes128_ecb_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);
void stc_aes128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);
void stc_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out);
void stc_aes256_cbc_encrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out);
void stc_omac1_aes(const void *key, size_t klen, void *result, size_t reslen,
		   ...);
void stc_sha1_hash(uint8_t *out, ...);
void stc_sha256_hash(uint8_t *out, ...);
int stc_b64_encode(const uint8_t *in,  unsigned long len,
		   uint8_t *out, unsigned long *outlen);
int stc_b64_decode(const uint8_t *in,  unsigned long len,
		   uint8_t *out, unsigned long *outlen);
int stc_rsa_sha1_sign_digest(const uint8_t *privkey_der, size_t privkey_len,
			     const uint8_t *digest,
			     uint8_t *out, unsigned long *outlen);

#endif /* !__STOKEN_INTERNAL_H__ */
