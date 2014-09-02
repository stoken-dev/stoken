/*
 * securid.c - SecurID token handling
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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef HAVE_NETTLE
#include <tomcrypt.h>
#else
#include <nettle/cbc.h>
#include <nettle/aes.h>
#include <nettle/sha2.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include "common.h"
#endif

#include "securid.h"
#include "sdtid.h"

struct v3_token {
	uint8_t			version;
	uint8_t			password_locked;
	uint8_t			devid_locked;
	uint8_t			nonce_devid_hash[SHA256_HASH_SIZE];
	uint8_t			nonce_devid_pass_hash[SHA256_HASH_SIZE];
	uint8_t			nonce[V3_NONCE_BYTES];
	uint8_t			enc_payload[0xb0];
	uint8_t			mac[SHA256_HASH_SIZE];
};

#define V3_ADDPIN_OFF		0x1f
#define V3_ADDPIN_ON		0x21

struct v3_payload {
	char			serial[16];
	uint8_t			dec_seed[SID_AES_KEY_SIZE];
	uint8_t			unk0[2];
	uint8_t			mode;
	uint8_t			digits;
	uint8_t			addpin;
	uint8_t			interval;
	uint8_t			res0[2];
	uint8_t			birth_date[5];
	uint8_t			res1[3];
	uint8_t			exp_date[5];
	uint8_t			res2[0x6b];
	uint8_t			padding[0x10];
};

/********************************************************************
 * Utility and crypto functions
 ********************************************************************/

static uint8_t hex2nibble(char in)
{
	uint8_t ret = in - '0';
	return (ret <= 9) ? ret : (10 + toupper(in) - 'A');
}

static uint8_t hex2byte(const char *in)
{
	return (hex2nibble(in[0]) << 4) | hex2nibble(in[1]);
}

void aes128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
#ifndef HAVE_NETTLE
	uint8_t tmp[AES_BLOCK_SIZE];
	symmetric_key skey;
	/* these shouldn't allocate memory or fail */
	if (rijndael_setup(key, SID_AES_KEY_SIZE, 0, &skey) != CRYPT_OK ||
	    rijndael_ecb_encrypt(in, tmp, &skey) != CRYPT_OK)
		abort();
	rijndael_done(&skey);

	/* in case "in" and "out" point to the same buffer */
	memcpy(out, tmp, AES_BLOCK_SIZE);
#else
	struct aes_ctx ctx;
	aes_set_encrypt_key(&ctx, SID_AES_KEY_SIZE, key);
	aes_encrypt(&ctx, AES_BLOCK_SIZE, out, in);
#endif
}

void aes128_ecb_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
#ifndef HAVE_NETTLE
	symmetric_key skey;
	uint8_t tmp[AES_BLOCK_SIZE];

	if (rijndael_setup(key, SID_AES_KEY_SIZE, 0, &skey) != CRYPT_OK ||
	    rijndael_ecb_decrypt(in, tmp, &skey) != CRYPT_OK)
		abort();
	rijndael_done(&skey);

	memcpy(out, tmp, AES_BLOCK_SIZE);
#else
	struct aes_ctx ctx;
	aes_set_decrypt_key(&ctx, SID_AES_KEY_SIZE, key);
	aes_decrypt(&ctx, AES_BLOCK_SIZE, out, in);
#endif
}

static void aes256_cbc_decrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out)
{
#ifndef HAVE_NETTLE
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
#else
	struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) ctx;
	aes_set_decrypt_key(&ctx.ctx, AES256_KEY_SIZE, key);
	CBC_SET_IV(&ctx, iv);
	CBC_DECRYPT(&ctx, aes_decrypt, in_len, out, in);
#endif
}

static void aes256_cbc_encrypt(const uint8_t *key, const uint8_t *in, int in_len,
			       const uint8_t *iv, uint8_t *out)
{
#ifndef HAVE_NETTLE
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
#else
	struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) ctx;
	aes_set_encrypt_key(&ctx.ctx, AES256_KEY_SIZE, key);
	CBC_SET_IV(&ctx, iv);
	CBC_ENCRYPT(&ctx, aes_encrypt, in_len, out, in);
#endif
}

int securid_rand(void *out, int len, int paranoid)
{
	if (paranoid) {
		/*
		 * Use /dev/random for long lived key material but not for
		 * test purposes.  This can block for a long time if entropy
		 * is limited.
		 */
		int fd;
		char *p = out;

		fd = open("/dev/random", O_RDONLY);
		if (fd < 0)
			return ERR_GENERAL;

		while (len) {
			ssize_t ret = read(fd, p, len);
			if (ret < 0) {
				close(fd);
				return ERR_GENERAL;
			}
			p += ret;
			len -= ret;
		}
		close(fd);
	} else {
#ifndef HAVE_NETTLE
		if (rng_get_bytes(out, len, NULL) != len)
			return ERR_GENERAL;
#else
		int fd;
		char *p = out;

		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0)
			return ERR_GENERAL;

		while (len) {
			ssize_t ret = read(fd, p, len);
			if (ret < 0) {
				close(fd);
				return ERR_GENERAL;
			}
			p += ret;
			len -= ret;
		}
		close(fd);
#endif
	}
	return ERR_NONE;
}

static void encrypt_then_xor(const uint8_t *key, uint8_t *work, uint8_t *enc)
{
	int i;

	aes128_ecb_encrypt(key, work, enc);
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		work[i] ^= enc[i];
}

static void securid_mac(const uint8_t *in, int in_len, uint8_t *out)
{
	int i, odd = 0;
	const int incr = SID_AES_KEY_SIZE;
	uint8_t work[incr], enc[incr], pad[incr], zero[incr], lastblk[incr], *p;

	memset(zero, 0, incr);
	memset(pad, 0, incr);
	memset(lastblk, 0, incr);
	memset(work, 0xff, incr);

	/* padding */
	p = &pad[incr - 1];
	for (i = in_len * 8; i > 0; i >>= 8)
		*(p--) = (uint8_t)i;

	/* handle the bulk of the input data here */
	for (; in_len > incr; in_len -= incr, in += incr, odd = !odd)
		encrypt_then_xor(in, work, enc);

	/* final 0-16 bytes of input data */
	memcpy(lastblk, in, in_len);
	encrypt_then_xor(lastblk, work, enc);

	/* hash an extra block of zeroes, for certain input lengths */
	if (odd)
		encrypt_then_xor(zero, work, enc);

	/* always hash the padding */
	encrypt_then_xor(pad, work, enc);

	/* run hash over current hash value, then return */
	memcpy(out, work, incr);
	encrypt_then_xor(work, out, enc);
}

static uint16_t securid_shortmac(const uint8_t *in, int in_len)
{
	uint8_t hash[AES_BLOCK_SIZE];

	securid_mac(in, in_len, hash);
	return (hash[0] << 7) | (hash[1] >> 1);
}

static void sha256_hash(const uint8_t *in, int in_len, uint8_t *out)
{
#ifndef HAVE_NETTLE
	hash_state md;
	sha256_init(&md);
	sha256_process(&md, in, in_len);
	sha256_done(&md, out);
#else
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, in_len, in);
	sha256_digest(&ctx, SHA256_HASH_SIZE, out);
#endif
}

static void sha256_hmac(const uint8_t *key, int key_len,
			const uint8_t *msg, int msg_len, uint8_t *out)
{
#ifndef HAVE_NETTLE
	hash_state md;
	uint8_t tmp_key[SHA256_HASH_SIZE], o_key_pad[SHA256_BLOCK_SIZE],
		i_key_pad[SHA256_BLOCK_SIZE], inner_hash[SHA256_BLOCK_SIZE];
	int i;

	if (key_len > SHA256_BLOCK_SIZE) {
		sha256_hash(key, key_len, tmp_key);
		key = tmp_key;
		key_len = SHA256_HASH_SIZE;
	}

	memset(o_key_pad, 0x5c, SHA256_BLOCK_SIZE);
	memset(i_key_pad, 0x36, SHA256_BLOCK_SIZE);
	for (i = 0; i < key_len; i++) {
		o_key_pad[i] ^= key[i];
		i_key_pad[i] ^= key[i];
	}

	sha256_init(&md);
	sha256_process(&md, i_key_pad, SHA256_BLOCK_SIZE);
	sha256_process(&md, msg, msg_len);
	sha256_done(&md, inner_hash);

	sha256_init(&md);
	sha256_process(&md, o_key_pad, SHA256_BLOCK_SIZE);
	sha256_process(&md, inner_hash, SHA256_HASH_SIZE);
	sha256_done(&md, out);
#else
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, key_len, key);
	hmac_sha256_update(&ctx, msg_len, msg);
	hmac_sha256_digest(&ctx, SHA256_HASH_SIZE, out);
#endif
}

static void sha256_pbkdf2(const uint8_t *pass, int pass_len,
			  const uint8_t *salt, int salt_len,
			  int n_rounds, uint8_t *key_out)
{
#ifndef HAVE_NETTLE
	uint8_t *ext_salt;
	uint8_t hash[SHA256_HASH_SIZE];
	int i, round;

	ext_salt = alloca(salt_len + 4);
	memcpy(ext_salt, salt, salt_len);

	/* always 0x00000001, as the output size is fixed at SHA256_HASH_SIZE */
	ext_salt[salt_len + 0] = 0;
	ext_salt[salt_len + 1] = 0;
	ext_salt[salt_len + 2] = 0;
	ext_salt[salt_len + 3] = 1;

	sha256_hmac(pass, pass_len, ext_salt, salt_len + 4, key_out);
	memcpy(hash, key_out, SHA256_HASH_SIZE);

	for (round = 2; round <= n_rounds; round++) {
		sha256_hmac(pass, pass_len, hash, SHA256_HASH_SIZE, hash);

		for (i = 0; i < SHA256_HASH_SIZE; i++)
			key_out[i] ^= hash[i];
	}
#else
	pbkdf2_hmac_sha256(pass_len, pass, n_rounds, salt_len, salt, SHA256_HASH_SIZE, key_out);
#endif
}

/********************************************************************
 * V1/V2 token handling
 ********************************************************************/

static void numinput_to_bits(const char *in, uint8_t *out, unsigned int n_bits)
{
	int bitpos = 13;

	memset(out, 0, (n_bits + 7) / 8);
	for (; n_bits; n_bits -= TOKEN_BITS_PER_CHAR, in++) {
		uint16_t decoded = (*in - '0') & 0x07;
		decoded <<= bitpos;
		out[0] |= decoded >> 8;
		out[1] |= decoded & 0xff;

		bitpos -= TOKEN_BITS_PER_CHAR;
		if (bitpos < 0) {
			bitpos += 8;
			out++;
		}
	}
}

static void bits_to_numoutput(const uint8_t *in, char *out, unsigned int n_bits)
{
	int bitpos = 13;

	for (; n_bits; n_bits -= TOKEN_BITS_PER_CHAR, out++) {
		uint16_t binary = (in[0] << 8) | in[1];
		*out = ((binary >> bitpos) & 0x07) + '0';

		bitpos -= TOKEN_BITS_PER_CHAR;
		if (bitpos < 0) {
			bitpos += 8;
			in++;
		}
	}
	*out = 0;
}

static uint32_t get_bits(const uint8_t *in, unsigned int start, int n_bits)
{
	uint32_t out = 0;

	in += start / 8;
	start %= 8;

	for (; n_bits > 0; n_bits--) {
		out <<= 1;
		if ((*in << start) & 0x80)
			out |= 0x01;
		start++;
		if (start == 8) {
			start = 0;
			in++;
		}
	}
	return out;
}

static void set_bits(uint8_t *out, unsigned int start, int n_bits, uint32_t val)
{
	out += start / 8;
	start %= 8;
	val <<= (32 - n_bits);

	for (; n_bits > 0; n_bits--) {
		if (val & BIT(31))
			*out |= BIT(7 - start);
		else
			*out &= ~BIT(7 - start);
		val <<= 1;
		start++;
		if (start == 8) {
			start = 0;
			out++;
		}
	}
}

static int v2_decode_token(const char *in, struct securid_token *t)
{
	uint8_t d[MAX_TOKEN_BITS / 8 + 2];
	int len = strlen(in);
	uint16_t token_mac, computed_mac;

	if (len < MIN_TOKEN_CHARS || len > MAX_TOKEN_CHARS)
		return ERR_BAD_LEN;

	/* the last 5 digits provide a checksum for the rest of the string */
	numinput_to_bits(&in[len - CHECKSUM_CHARS], d, 15);
	token_mac = get_bits(d, 0, 15);
	computed_mac = securid_shortmac(in, len - CHECKSUM_CHARS);

	if (token_mac != computed_mac)
		return ERR_CHECKSUM_FAILED;

	t->version = in[0] - '0';
	memcpy(&t->serial, &in[VER_CHARS], SERIAL_CHARS);
	t->serial[SERIAL_CHARS] = 0;

	numinput_to_bits(&in[BINENC_OFS], d, BINENC_BITS);
	memcpy(t->enc_seed, d, SID_AES_KEY_SIZE);
	t->has_enc_seed = 1;

	t->flags = get_bits(d, 128, 16);
	t->exp_date = get_bits(d, 144, 14);
	t->dec_seed_hash = get_bits(d, 159, 15);
	t->device_id_hash = get_bits(d, 174, 15);

	return ERR_NONE;
}

static int generate_key_hash(uint8_t *key_hash, const char *pass,
	const char *devid, uint16_t *device_id_hash, struct securid_token *t)
{
	uint8_t key[MAX_PASS + DEVID_CHARS + MAGIC_LEN + 1], *devid_buf;
	int pos = 0, devid_len = t->is_smartphone ? 40 : 32;
	const uint8_t magic[] = { 0xd8, 0xf5, 0x32, 0x53, 0x82, 0x89, 0x00 };

	memset(key, 0, sizeof(key));

	if (pass) {
		pos = strlen(pass);
		if (pos > MAX_PASS)
			return ERR_BAD_PASSWORD;
		memcpy(key, pass, pos);
	}

	devid_buf = &key[pos];
	if (devid) {
		int len = 0;

		/*
		 * For iPhone/Android ctf strings, the device ID takes up
		 * 40 bytes and consists of hex digits + zero padding.
		 *
		 * For other ctf strings (e.g. --blocks), the device ID takes
		 * up 32 bytes and consists of decimal digits + zero padding.
		 *
		 * If this seed isn't locked to a device, we'll just hash
		 * 40 (or 32) zero bytes, below.
		 */
		for (; *devid; devid++) {
			if (++len > devid_len)
				break;
			if ((t->version == 1 && isdigit(*devid)) ||
			    (t->version >= 2 && !isxdigit(*devid)))
				continue;
			key[pos++] = toupper(*devid);
		}
	}
	if (device_id_hash)
		*device_id_hash = securid_shortmac(devid_buf, devid_len);

	memcpy(&key[pos], magic, MAGIC_LEN);
	securid_mac(key, pos + MAGIC_LEN, key_hash);

	return ERR_NONE;
}

static int v2_decrypt_seed(struct securid_token *t, const char *pass,
			   const char *devid)
{
	uint8_t key_hash[AES_BLOCK_SIZE], dec_seed_hash[AES_BLOCK_SIZE];
	uint16_t computed_mac;
	uint16_t device_id_hash;
	int rc;

	rc = generate_key_hash(key_hash, pass, devid, &device_id_hash, t);
	if (rc)
		return rc;

	if (t->flags & FL_SNPROT && device_id_hash != t->device_id_hash)
		return ERR_BAD_DEVID;

	aes128_ecb_decrypt(key_hash, t->enc_seed, t->dec_seed);
	securid_mac(t->dec_seed, SID_AES_KEY_SIZE, dec_seed_hash);
	computed_mac = (dec_seed_hash[0] << 7) | (dec_seed_hash[1] >> 1);

	if (computed_mac != t->dec_seed_hash)
		return ERR_DECRYPT_FAILED;
	t->has_dec_seed = 1;

	return ERR_NONE;
}

static void key_from_time(const uint8_t *bcd_time, int bcd_time_bytes,
	const uint8_t *serial, uint8_t *key)
{
	int i;

	memset(key, 0xaa, 8);
	memcpy(key, bcd_time, bcd_time_bytes);
	memset(key + 12, 0xbb, 4);

	/* write BCD-encoded partial serial number */
	key += 8;
	for (i = 4; i < 12; i += 2)
		*(key++) = ((serial[i] - '0') << 4) |
			    (serial[i + 1] - '0');
}

static void bcd_write(uint8_t *out, int val, unsigned int bytes)
{
	out += bytes - 1;
	for (; bytes; bytes--) {
		*out = val % 10;
		val /= 10;
		*(out--) |= (val % 10) << 4;
		val /= 10;
	}
}

static int v2_encode_token(struct securid_token *t, const char *pass,
			   const char *devid, char *out)
{
	uint8_t d[MAX_TOKEN_BITS / 8 + 2];
	uint8_t key_hash[AES_BLOCK_SIZE];
	int rc;

	rc = generate_key_hash(key_hash, pass, devid, &t->device_id_hash, t);
	if (rc)
		return rc;

	memset(d, 0, sizeof(d));
	aes128_ecb_encrypt(key_hash, t->dec_seed, t->enc_seed);
	memcpy(d, t->enc_seed, SID_AES_KEY_SIZE);

	set_bits(d, 128, 16, t->flags);
	set_bits(d, 144, 14, t->exp_date);
	set_bits(d, 159, 15, securid_shortmac(t->dec_seed, SID_AES_KEY_SIZE));
	set_bits(d, 174, 15, t->device_id_hash);

	sprintf(out, "2%s", t->serial);
	bits_to_numoutput(d, &out[BINENC_OFS], BINENC_BITS);

	set_bits(d, 0, 15, securid_shortmac(out, CHECKSUM_OFS));
	bits_to_numoutput(d, &out[CHECKSUM_OFS], CHECKSUM_BITS);

	return ERR_NONE;
}

/********************************************************************
 * V3 token handling
 ********************************************************************/

static void v3_derive_key(const char *pass, const char *devid, const uint8_t *salt,
			  int key_id, uint8_t *out)
{
	uint8_t *buf0, *buf1;
	int pass_len = pass ? strlen(pass) : 0;
	int buf_len = V3_DEVID_CHARS + 16 + V3_NONCE_BYTES + pass_len;
	unsigned int i;
	const uint8_t key0[] = { 0xd0, 0x14, 0x43, 0x3c, 0x6d, 0x17, 0x9f, 0xeb,
				 0xda, 0x09, 0xab, 0xfc, 0x32, 0x49, 0x63, 0x4c };
	const uint8_t key1[] = { 0x3b, 0xaf, 0xff, 0x4d, 0x91, 0x8d, 0x89, 0xb6,
				 0x81, 0x60, 0xde, 0x44, 0x4e, 0x05, 0xc0, 0xdd };

	buf0 = alloca(buf_len);
	buf1 = alloca(buf_len >> 1);

	memset(buf0, 0, buf_len);

	if (pass)
		strncpy(buf0, pass, pass_len);
	if (devid)
		strncpy(&buf0[pass_len], devid, V3_DEVID_CHARS);
	memcpy(&buf0[pass_len + V3_DEVID_CHARS], key_id ? key1 : key0, 16);
	memcpy(&buf0[pass_len + V3_DEVID_CHARS + 16], salt, V3_NONCE_BYTES);

	/* yup, the PBKDF2 password is really "every 2nd byte of the input" */
	for (i = 1; i < buf_len; i += 2)
		buf1[i >> 1] = buf0[i];

	sha256_pbkdf2(buf1, buf_len >> 1, salt, V3_NONCE_BYTES, 1000, out);
}

static int v3_decode_token(const char *in, struct securid_token *t)
{
	char decoded[V3_BASE64_SIZE];
	int i, j;
	unsigned long actual;
	/* remove URL-encoding */
	for (i = 0, j = 0; in[i]; ) {
		if (j == V3_BASE64_SIZE - 1)
			return ERR_BAD_LEN;
		if (in[i] == '%') {
			if (!isxdigit(in[i + 1]) || !isxdigit(in[i + 2]))
				return ERR_BAD_LEN;
			decoded[j++] = hex2byte(&in[i + 1]);
			i += 3;
		} else {
			decoded[j++] = in[i++];
		}
	}
	decoded[j] = 0;

	actual = V3_SIZE(strlen(decoded));
	t->v3 = malloc(actual);
	if (!t->v3)
		return ERR_NO_MEMORY;

	if (base64_decode(decoded, strlen(decoded),
			  (void *)t->v3, &actual) != CRYPT_OK ||
	    actual != sizeof(struct v3_token) ||
	    t->v3->version != 0x03) {
		free(t->v3);
		t->v3 = NULL;
		return ERR_GENERAL;
	}

	t->version = 3;

	/* more flags will get populated later when we decrypt the payload */
	t->flags = t->v3->password_locked ? FL_PASSPROT : 0;
	t->flags |= t->v3->devid_locked ? FL_SNPROT : 0;

	return ERR_NONE;
}

static uint16_t v3_parse_date(uint8_t *in)
{
	uint64_t longdate;

	longdate = ((uint64_t)in[0] << 32) |
		   ((uint64_t)in[1] << 24) |
		   ((uint64_t)in[2] << 16) |
		   ((uint64_t)in[3] <<  8) |
		   ((uint64_t)in[4] <<  0);
	longdate /= SECURID_V3_DAY;
	return longdate - SECURID_EPOCH_DAYS;
}

static void v3_encode_date(uint8_t *out, uint16_t in)
{
	uint64_t longdate;

	longdate = ((uint64_t)in + SECURID_EPOCH_DAYS) * SECURID_V3_DAY;
	out[0] = longdate >> 32;
	out[1] = longdate >> 24;
	out[2] = longdate >> 16;
	out[3] = longdate >>  8;
	out[4] = longdate >>  0;
}

static void v3_compute_hash(const char *pass, const char *devid,
			    const uint8_t *salt, uint8_t *hash)
{
	uint8_t hash_buf[V3_NONCE_BYTES + V3_DEVID_CHARS + MAX_PASS];
	int pass_len = 0;

	memset(hash_buf, 0, sizeof(hash_buf));
	memcpy(&hash_buf[0], salt, V3_NONCE_BYTES);

	if (devid)
		strncpy(&hash_buf[V3_NONCE_BYTES], devid, V3_DEVID_CHARS);

	if (pass) {
		pass_len = strlen(pass);
		strncpy(&hash_buf[V3_NONCE_BYTES + V3_DEVID_CHARS], pass, MAX_PASS);
	}
	sha256_hash(hash_buf, V3_NONCE_BYTES + V3_DEVID_CHARS + pass_len, hash);
}

static void v3_compute_hmac(struct v3_token *v3, const char *pass,
			    const char *devid, uint8_t *out)
{
	uint8_t hash[SHA256_HASH_SIZE];

	v3_derive_key(pass, devid, v3->nonce, 0, hash);
	sha256_hmac(hash, SHA256_HASH_SIZE,
		    (void *)v3, sizeof(*v3) - SHA256_HASH_SIZE, out);
}

static void v3_scrub_devid(const char *in, char *out)
{
	int j;
	for (j = 0; in && *in && j < V3_DEVID_CHARS; in++) {
		if (isalnum(*in))
			out[j++] = toupper(*in);
	}
	out[j] = 0;
}

static int v3_decrypt_seed(struct securid_token *t,
			   const char *pass, const char *raw_devid)
{
	struct v3_payload payload;
	uint8_t hash[SHA256_HASH_SIZE];
	char devid[V3_DEVID_CHARS + 1];

	v3_scrub_devid(raw_devid, devid);

	v3_compute_hash(NULL, devid, t->v3->nonce, hash);
	if (memcmp(hash, t->v3->nonce_devid_hash, SHA256_HASH_SIZE) != 0)
		return ERR_BAD_DEVID;

	v3_compute_hash(pass, devid, t->v3->nonce, hash);
	if (memcmp(hash, t->v3->nonce_devid_pass_hash, SHA256_HASH_SIZE) != 0)
		return ERR_DECRYPT_FAILED;

	v3_compute_hmac(t->v3, pass, devid, hash);
	if (memcmp(hash, t->v3->mac, SHA256_HASH_SIZE) != 0)
		return ERR_CHECKSUM_FAILED;

	v3_derive_key(pass, devid, t->v3->nonce, 1, hash);
	aes256_cbc_decrypt(hash,
			   t->v3->enc_payload, sizeof(struct v3_payload),
			   t->v3->nonce, (void *)&payload);

	strncpy(t->serial, payload.serial, SERIAL_CHARS);
	t->serial[SERIAL_CHARS] = 0;

	memcpy(t->dec_seed, &payload.dec_seed, SID_AES_KEY_SIZE);
	t->has_dec_seed = 1;

	t->flags |= FL_TIMESEEDS | FL_128BIT;
	t->flags |= payload.mode ? FL_FEAT4 : 0;
	t->flags |= ((payload.digits-1) << FLD_DIGIT_SHIFT) & FLD_DIGIT_MASK;
	t->flags |= (payload.addpin != V3_ADDPIN_OFF) ?
		    (0x2 << FLD_PINMODE_SHIFT) : 0;
	t->flags |= payload.interval == 60 ? (1 << FLD_NUMSECONDS_SHIFT) : 0;

	t->exp_date = v3_parse_date(payload.exp_date);

	return ERR_NONE;
}

static int v3_encode_token(struct securid_token *t, const char *pass,
			   const char *raw_devid, char *out)
{
	struct v3_payload payload;
	struct v3_token v3;
	uint8_t key[SHA256_HASH_SIZE];
	unsigned long enclen = V3_BASE64_SIZE;
	char raw_b64[V3_BASE64_SIZE];
	char devid[V3_DEVID_CHARS + 1];
	int i;

	memset(&payload, 0, sizeof(payload));
	strncpy(payload.serial, t->serial, sizeof(payload.serial));
	memcpy(payload.dec_seed, t->dec_seed, SID_AES_KEY_SIZE);
	payload.unk0[0] = payload.unk0[1] = 1;
	payload.mode = !!(t->flags & FL_FEAT4);
	payload.digits = ((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1;
	payload.addpin = (t->flags & (0x2 << FLD_PINMODE_SHIFT)) ?
			 V3_ADDPIN_ON : V3_ADDPIN_OFF;
	payload.interval = (t->flags & FLD_NUMSECONDS_MASK) ? 60 : 30;

	v3_encode_date(payload.exp_date, t->exp_date);

	memset(payload.padding, 0x10, 0x10);

	memset(&v3, 0, sizeof(v3));
	if (securid_rand(v3.nonce, sizeof(v3.nonce), 0))
		return ERR_GENERAL;

	v3.version = 3;
	v3.password_locked = !!pass;
	v3.devid_locked = !!raw_devid;

	v3_scrub_devid(raw_devid, devid);
	v3_derive_key(pass, devid, v3.nonce, 1, key);
	aes256_cbc_encrypt(key, (void *)&payload, sizeof(struct v3_payload),
			   v3.nonce, v3.enc_payload);

	v3_compute_hash(NULL, devid, v3.nonce, v3.nonce_devid_hash);
	v3_compute_hash(pass, devid, v3.nonce, v3.nonce_devid_pass_hash);
	v3_compute_hmac(&v3, pass, devid, v3.mac);

	base64_encode((void *)&v3, sizeof(v3), raw_b64, &enclen);

	for (i = 0; i < enclen; i++) {
		char c = raw_b64[i];
		if (!isalnum(c)) {
			sprintf(out, "%%%02X", c);
			out += 3;
		} else
			*(out++) = c;
	}
	*out = 0;

	return ERR_NONE;
}


/********************************************************************
 * Public functions
 ********************************************************************/

int securid_decode_token(const char *in, struct securid_token *t)
{
	/*
	 * V1/V2 tokens start with the ASCII version digit
	 * V3 tokens always start with a base64-encoded 0x03 byte, which
	 *   is guaranteed to encode to 'A'
	 */
	if (in[0] == '1' || in[0] == '2')
		return v2_decode_token(in, t);
	else if (strlen(in) >= V3_BASE64_MIN_CHARS && (in[0] == 'A'))
		return v3_decode_token(in, t);
	else
		return ERR_TOKEN_VERSION;
}

int securid_decrypt_seed(struct securid_token *t, const char *pass,
			 const char *devid)
{
	if (t->flags & FL_PASSPROT) {
		if (!pass || !strlen(pass))
			return ERR_MISSING_PASSWORD;
		if (strlen(pass) > MAX_PASS)
			return ERR_BAD_PASSWORD;
	} else
		pass = NULL;

	if (t->flags & FL_SNPROT) {
		if (!devid || !strlen(devid))
			return ERR_MISSING_PASSWORD;
		/* NOTE: max length is checked elsewhere, as it varies */
	} else
		devid = NULL;

	if (t->sdtid)
		return sdtid_decrypt(t, pass);
	else if (t->v3)
		return v3_decrypt_seed(t, pass, devid);
	else
		return v2_decrypt_seed(t, pass, devid);
}

int securid_check_devid(struct securid_token *t, const char *devid)
{
	int ret = securid_decrypt_seed(t, ".", devid);
	if (ret == ERR_BAD_DEVID || ret == ERR_MISSING_PASSWORD)
		return ERR_BAD_DEVID;
	else
		return ERR_NONE;
}

void securid_compute_tokencode(struct securid_token *t, time_t now,
			       char *code_out)
{
	uint8_t bcd_time[8];
	uint8_t key0[SID_AES_KEY_SIZE], key1[SID_AES_KEY_SIZE];
	int i, j;
	uint32_t tokencode;
	struct tm gmt;
	int pin_len = strlen(t->pin);
	int is_30 = securid_token_interval(t) == 30;

	gmtime_r(&now, &gmt);
	bcd_write(&bcd_time[0], gmt.tm_year + 1900, 2);
	bcd_write(&bcd_time[2], gmt.tm_mon + 1, 1);
	bcd_write(&bcd_time[3], gmt.tm_mday, 1);
	bcd_write(&bcd_time[4], gmt.tm_hour, 1);
	bcd_write(&bcd_time[5], gmt.tm_min & ~(is_30 ? 0x01 : 0x03), 1);
	bcd_time[6] = bcd_time[7] = 0;

	key_from_time(bcd_time, 2, t->serial, key0);
	aes128_ecb_encrypt(t->dec_seed, key0, key0);
	key_from_time(bcd_time, 3, t->serial, key1);
	aes128_ecb_encrypt(key0, key1, key1);
	key_from_time(bcd_time, 4, t->serial, key0);
	aes128_ecb_encrypt(key1, key0, key0);
	key_from_time(bcd_time, 5, t->serial, key1);
	aes128_ecb_encrypt(key0, key1, key1);
	key_from_time(bcd_time, 8, t->serial, key0);
	aes128_ecb_encrypt(key1, key0, key0);

	/* key0 now contains 4 consecutive token codes */
	if (is_30)
		i = ((gmt.tm_min & 0x01) << 3) | ((gmt.tm_sec >= 30) << 2);
	else
		i = (gmt.tm_min & 0x03) << 2;

	tokencode = (key0[i + 0] << 24) | (key0[i + 1] << 16) |
		    (key0[i + 2] << 8)  | (key0[i + 3] << 0);

	/* populate code_out backwards, adding PIN digits if available */
	j = ((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1;
	code_out[j--] = 0;
	for (i = 0; j >= 0; j--, i++) {
		uint8_t c = tokencode % 10;
		tokencode /= 10;

		if (i < pin_len)
			c += t->pin[pin_len - i - 1] - '0';
		code_out[j] = c % 10 + '0';
	}
}

int securid_encode_token(const struct securid_token *t, const char *pass,
			 const char *devid, int version, char *out)
{
	struct securid_token newt = *t;

	/* empty password means "no password" */
	if (!pass || !strlen(pass)) {
		pass = NULL;
		newt.flags &= ~FL_PASSPROT;
	} else
		newt.flags |= FL_PASSPROT;

	if (!devid || !strlen(devid)) {
		devid = NULL;
		newt.flags &= ~FL_SNPROT;
	} else
		newt.flags |= FL_SNPROT;

	if (version == 3)
		return v3_encode_token(&newt, pass, devid, out);
	else
		return v2_encode_token(&newt, pass, devid, out);
}

int securid_random_token(struct securid_token *t)
{
	time_t now = time(NULL);
	uint8_t randbytes[16], key_hash[AES_BLOCK_SIZE];
	int i;

	memset(t, 0, sizeof(*t));

	if (securid_rand(t->dec_seed, SID_AES_KEY_SIZE, 0) ||
	    securid_rand(randbytes, sizeof(randbytes), 0))
		return ERR_GENERAL;

	t->dec_seed_hash = securid_shortmac(t->dec_seed, SID_AES_KEY_SIZE);

	generate_key_hash(key_hash, NULL, NULL, &t->device_id_hash, t);
	aes128_ecb_encrypt(key_hash, t->dec_seed, t->enc_seed);
	t->has_enc_seed = 1;

	t->version = 2;
	t->flags = FL_TIMESEEDS | FLD_DIGIT_MASK | FLD_PINMODE_MASK |
		   (1 << FLD_NUMSECONDS_SHIFT) | FL_128BIT;
	t->pinmode = 3;

	for (i = 0; i < 12; i++)
		t->serial[i] = '0' + randbytes[i] % 10;

	/* set the expiration date a couple of months out */
	t->exp_date = (now - SECURID_EPOCH) / (24 * 60 * 60) + 60 +
		(randbytes[12] & 0x0f) * 30;

	return ERR_NONE;
}

time_t securid_unix_exp_date(const struct securid_token *t)
{
	/*
	 * v3 tokens encrypt the expiration date, so if the user has not
	 * been prompted for a password yet, we'll need to bypass the
	 * expiration checks.
	 */
	if (t->version == 3 && !t->exp_date)
		return 0x7fffffff;
	return SECURID_EPOCH + (t->exp_date + 1) * 60 * 60 * 24;
}

int securid_token_interval(const struct securid_token *t)
{
	if (((t->flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT) == 0)
		return 30;
	else
		return 60;
}

void securid_token_info(const struct securid_token *t,
	void (*callback)(const char *key, const char *value))
{
	char str[256];
	unsigned int i;
	struct tm exp_tm;
	time_t exp_unix_time = securid_unix_exp_date(t);

	callback("Serial number", t->serial);

	if (t->has_dec_seed) {
		for (i = 0; i < SID_AES_KEY_SIZE; i++)
			sprintf(&str[i * 3], "%02x ", t->dec_seed[i]);
		callback("Decrypted seed", str);
	}

	if (t->has_enc_seed) {
		for (i = 0; i < SID_AES_KEY_SIZE; i++)
			sprintf(&str[i * 3], "%02x ", t->enc_seed[i]);
		callback("Encrypted seed", str);

		callback("Encrypted w/password",
			t->flags & FL_PASSPROT ? "yes" : "no");
		callback("Encrypted w/devid",
			t->flags & FL_SNPROT ? "yes" : "no");
	}

	gmtime_r(&exp_unix_time, &exp_tm);
	strftime(str, 32, "%Y/%m/%d", &exp_tm);
	callback("Expiration date", str);

	callback("Key length", t->flags & FL_128BIT ? "128" : "64");

	sprintf(str, "%d",
		((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1);
	callback("Tokencode digits", str);

	sprintf(str, "%d",
		((t->flags & FLD_PINMODE_MASK) >> FLD_PINMODE_SHIFT));
	callback("PIN mode", str);

	switch ((t->flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT) {
	case 0x00:
		strcpy(str, "30");
		break;
	case 0x01:
		strcpy(str, "60");
		break;
	default:
		strcpy(str, "unknown");
	}
	callback("Seconds per tokencode", str);

	callback("App-derived", t->flags & FL_APPSEEDS ? "yes" : "no");
	callback("Feature bit 4", t->flags & FL_FEAT4 ? "yes" : "no");
	callback("Time-derived", t->flags & FL_TIMESEEDS ? "yes" : "no");
	callback("Feature bit 6", t->flags & FL_FEAT6 ? "yes" : "no");
}

int securid_check_exp(struct securid_token *t, time_t now)
{
	time_t exp_unix_time = securid_unix_exp_date(t);
	const int halfday = 60 * 60 * 12, wholeday = 60 * 60 * 24;

	/*
	 * Other soft token implementations seem to allow ~12hrs as a grace
	 * period.  Actual results will depend on how soon the server cuts
	 * off expired tokens.
	 */
	exp_unix_time += halfday;
	exp_unix_time -= now;
	return exp_unix_time / wholeday;
}

int securid_pin_format_ok(const char *pin)
{
	int i, rc;

	rc = strlen(pin);
	if (rc < MIN_PIN || rc > MAX_PIN)
		return ERR_BAD_LEN;
	for (i = 0; i < rc; i++)
		if (!isdigit(pin[i]))
			return ERR_GENERAL;
	return ERR_NONE;
}

int securid_pin_required(const struct securid_token *t)
{
	return ((t->flags & FLD_PINMODE_MASK) >> FLD_PINMODE_SHIFT) >= 2;
}

int securid_pass_required(const struct securid_token *t)
{
	return !!(t->flags & FL_PASSPROT);
}

int securid_devid_required(const struct securid_token *t)
{
	return !!(t->flags & FL_SNPROT);
}

char *securid_encrypt_pin(const char *pin, const char *password)
{
	int i;
	uint8_t buf[AES_BLOCK_SIZE], iv[AES_BLOCK_SIZE],
		passhash[AES_BLOCK_SIZE], *ret;

	if (securid_pin_format_ok(pin) != ERR_NONE)
		return NULL;

	memset(buf, 0, sizeof(buf));
	strcpy(buf, pin);
	buf[AES_BLOCK_SIZE - 1] = strlen(pin);

	securid_mac(password, strlen(password), passhash);

	if (securid_rand(iv, AES_BLOCK_SIZE, 0))
		return NULL;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		buf[i] ^= iv[i];
	aes128_ecb_encrypt(passhash, buf, buf);

	ret = malloc(AES_BLOCK_SIZE * 2 * 2 + 1);
	if (!ret)
		return NULL;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		sprintf(&ret[i * 2], "%02x", iv[i]);
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		sprintf(&ret[(AES_BLOCK_SIZE + i) * 2], "%02x", buf[i]);

	return ret;
}

int securid_decrypt_pin(const char *enc_pin, const char *password, char *pin)
{
	int i;
	uint8_t buf[AES_BLOCK_SIZE], iv[AES_BLOCK_SIZE],
		passhash[AES_BLOCK_SIZE];

	if (strlen(enc_pin) != AES_BLOCK_SIZE * 2 * 2)
		return ERR_BAD_LEN;

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		iv[i] = hex2byte(&enc_pin[i * 2]);
		buf[i] = hex2byte(&enc_pin[(i + AES_BLOCK_SIZE) * 2]);
	}

	securid_mac(password, strlen(password), passhash);
	aes128_ecb_decrypt(passhash, buf, buf);

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		buf[i] ^= iv[i];

	if (buf[AES_BLOCK_SIZE - 2] != 0 ||
	    buf[AES_BLOCK_SIZE - 1] != strlen(buf))
		return ERR_GENERAL;
	if (securid_pin_format_ok(buf) != ERR_NONE)
		return ERR_GENERAL;

	strcpy(pin, buf);
	return ERR_NONE;
}
