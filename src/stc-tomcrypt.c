/*
 * stc-tomcrypt.c - stoken crypto wrappers for libtomcrypt
 *
 * Copyright 2014 Nikos Mavrogiannopoulos <nmav@redhat.com>
 * Copyright 2014 Kevin Cernekee <cernekee@gmail.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>
#include <unistd.h>

#include "stoken-internal.h"

/* These are redundant, but stc-* files shouldn't include securid.h */
#define AES_BLOCK_SIZE		16
#define AES_KEY_SIZE		16
#define AES256_KEY_SIZE		32

int stc_standalone_init(void)
{
	/* libtomcrypt init for sdtid BatchSignature generation */
	ltc_mp = ltm_desc;
	if (register_hash(&sha1_desc) == -1)
		return ERR_GENERAL;
	return ERR_NONE;
}

void stc_aes128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
	symmetric_key skey;
	uint8_t tmp[AES_BLOCK_SIZE];

	/* these shouldn't allocate memory or fail */
	if (rijndael_setup(key, AES_KEY_SIZE, 0, &skey) != CRYPT_OK ||
	    rijndael_ecb_encrypt(in, tmp, &skey) != CRYPT_OK)
		abort();
	rijndael_done(&skey);

	/* in case "in" and "out" point to the same buffer */
	memcpy(out, tmp, AES_BLOCK_SIZE);
}

void stc_aes128_ecb_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
	symmetric_key skey;
	uint8_t tmp[AES_BLOCK_SIZE];

	if (rijndael_setup(key, AES_KEY_SIZE, 0, &skey) != CRYPT_OK ||
	    rijndael_ecb_decrypt(in, tmp, &skey) != CRYPT_OK)
		abort();
	rijndael_done(&skey);

	memcpy(out, tmp, AES_BLOCK_SIZE);
}

void stc_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out)
{
	symmetric_key skey;
	int i, j;
	uint8_t local_iv[AES_BLOCK_SIZE];

	rijndael_setup(key, AES256_KEY_SIZE, 0, &skey);

	memcpy(local_iv, iv, AES_BLOCK_SIZE);
	for (i = 0; i < in_len; i += AES_BLOCK_SIZE) {
		rijndael_ecb_decrypt(in, out, &skey);
		for (j = 0; j < AES_BLOCK_SIZE; j++)
			out[j] ^= local_iv[j];
		memcpy(local_iv, in, AES_BLOCK_SIZE);
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}
	rijndael_done(&skey);
}

void stc_aes256_cbc_encrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out)
{
	symmetric_key skey;
	int i, j;
	uint8_t xored_in[AES_BLOCK_SIZE];

	rijndael_setup(key, AES256_KEY_SIZE, 0, &skey);

	for (i = 0; i < in_len; i += AES_BLOCK_SIZE) {
		for (j = 0; j < AES_BLOCK_SIZE; j++) {
			xored_in[j] = in[j] ^
				      (i ? out[j - AES_BLOCK_SIZE] : iv[j]);
		}
		rijndael_ecb_encrypt(xored_in, out, &skey);
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}
	rijndael_done(&skey);
}

void stc_sha1_hash(uint8_t *out, ...)
{
	va_list ap;
	hash_state md;

	sha1_init(&md);
	va_start(ap, out);
	while (1) {
		const uint8_t *in = va_arg(ap, const uint8_t *);
		int in_len;

		if (!in)
			break;
		in_len = va_arg(ap, int);
		sha1_process(&md, in, in_len);
	}
	va_end(ap);
	sha1_done(&md, out);
}

void stc_sha256_hash(uint8_t *out, ...)
{
	va_list ap;
	hash_state md;

	sha256_init(&md);
	va_start(ap, out);
	while (1) {
		const uint8_t *in = va_arg(ap, const uint8_t *);
		int in_len;

		if (!in)
			break;
		in_len = va_arg(ap, int);
		sha256_process(&md, in, in_len);
	}
	va_end(ap);
	sha256_done(&md, out);
}

int stc_b64_encode(const uint8_t *in,  unsigned long len,
		   uint8_t *out, unsigned long *outlen)
{
	return base64_encode(in, len, out, outlen) == CRYPT_OK ?
		ERR_NONE : ERR_GENERAL;
}

int stc_b64_decode(const uint8_t *in,  unsigned long len,
		   uint8_t *out, unsigned long *outlen)
{
	return base64_decode(in, len, out, outlen) == CRYPT_OK ?
		ERR_NONE : ERR_GENERAL;
}
