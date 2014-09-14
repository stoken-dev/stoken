/*
 * stc-nettle.c - stoken crypto wrappers for nettle
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
#include <unistd.h>

#include <nettle/aes.h>
#include <nettle/base64.h>
#include <nettle/bignum.h>
#include <nettle/cbc.h>
#include <nettle/hmac.h>
#include <nettle/rsa.h>
#include <nettle/sha.h>

#include "stoken-internal.h"

int stc_standalone_init(void)
{
	return ERR_NONE;
}

void stc_aes128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
	struct aes_ctx ctx;
	aes_set_encrypt_key(&ctx, 128/8, key);
	aes_encrypt(&ctx, AES_BLOCK_SIZE, out, in);
}

void stc_aes128_ecb_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
	struct aes_ctx ctx;
	aes_set_decrypt_key(&ctx, 128/8, key);
	aes_decrypt(&ctx, AES_BLOCK_SIZE, out, in);
}

void stc_aes256_cbc_decrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out)
{
	struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) ctx;
	aes_set_decrypt_key(&ctx.ctx, 256/8, key);
	CBC_SET_IV(&ctx, iv);
	CBC_DECRYPT(&ctx, aes_decrypt, in_len, out, in);
}

void stc_aes256_cbc_encrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out)
{
	struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) ctx;
	aes_set_encrypt_key(&ctx.ctx, 256/8, key);
	CBC_SET_IV(&ctx, iv);
	CBC_ENCRYPT(&ctx, aes_encrypt, in_len, out, in);
}

void stc_sha1_hash(uint8_t *out, ...)
{
	va_list ap;
	struct sha1_ctx md;

	sha1_init(&md);
	va_start(ap, out);
	while (1) {
		const uint8_t *in = va_arg(ap, const uint8_t *);
		int in_len;

		if (!in)
			break;
		in_len = va_arg(ap, int);
		sha1_update(&md, in_len, in);
	}
	va_end(ap);
	sha1_digest(&md, SHA1_DIGEST_SIZE, out);
}

void stc_sha256_hash(uint8_t *out, ...)
{
	va_list ap;
	struct sha256_ctx md;

	sha256_init(&md);
	va_start(ap, out);
	while (1) {
		const uint8_t *in = va_arg(ap, const uint8_t *);
		int in_len;

		if (!in)
			break;
		in_len = va_arg(ap, int);
		sha256_update(&md, in_len, in);
	}
	va_end(ap);
	sha256_digest(&md, SHA256_DIGEST_SIZE, out);
}

int stc_b64_encode(const uint8_t *in,  unsigned long len,
		   uint8_t *out, unsigned long *outlen)
{
	struct base64_encode_ctx ctx;
	unsigned size = 0;
	base64_encode_init(&ctx);

	size = base64_encode_update(&ctx, out, len, in);
	size += base64_encode_final(&ctx, out+size);
	out[size] = 0;
	*outlen = size;

	return ERR_NONE;
}

int stc_b64_decode(const uint8_t *in,  unsigned long len,
		   uint8_t *out, unsigned long *outlen)
{
	struct base64_decode_ctx ctx;
	char tmp[BASE64_DECODE_LENGTH(len)];
	unsigned dst_length;
	int ret;

	dst_length = BASE64_DECODE_LENGTH(len);
	base64_decode_init(&ctx);
	ret = base64_decode_update(&ctx, &dst_length, tmp, len, in);
	if (ret == 0) {
		return ERR_GENERAL;
	}

	if (*outlen >= dst_length) {
		memcpy(out, tmp, dst_length);
	} else {
		return ERR_GENERAL;
	}
	*outlen = dst_length;

	return ERR_NONE;
}

int stc_rsa_sha1_sign_digest(const uint8_t *privkey_der, size_t privkey_len,
			     const uint8_t *digest,
			     uint8_t *out, unsigned long *outlen)
{
	struct rsa_private_key key;
	struct rsa_public_key pub;
	mpz_t msig;
	int ret;

	rsa_private_key_init(&key);
	rsa_public_key_init(&pub);
	mpz_init(msig);

	ret = rsa_keypair_from_der(&pub, &key, 1025,
				   privkey_len - 1, privkey_der);
	if (ret == 0) {
		ret = ERR_GENERAL;
		goto cleanup;
	}

	ret = rsa_sha1_sign_digest(&key, digest, msig);
	if (ret == 0) {
		ret = ERR_GENERAL;
		goto cleanup;
	}

	nettle_mpz_get_str_256(nettle_mpz_sizeinbase_256_u(msig), out, msig);
	ret = ERR_NONE;

cleanup:
	rsa_private_key_clear(&key);
	rsa_public_key_clear(&pub);
	mpz_clear(msig);
	return ret;
}
