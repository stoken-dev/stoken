/*
 * sdtid.c - SecurID sdtid/xml parsing
 *
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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <tomcrypt.h>

#include "common.h"
#include "securid.h"

struct sdtid {
	xmlDoc			*doc;
	xmlNode			*header_node;
	xmlNode			*tkn_node;
	xmlNode			*trailer_node;

	int			error;
	int			interactive;

	char			*sn;
	uint8_t			batch_mac_key[AES_KEY_SIZE];
	uint8_t			token_mac_key[AES_KEY_SIZE];
	uint8_t			token_enc_key[AES_KEY_SIZE];
};

static const uint8_t batch_mac_iv[] =
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
static const uint8_t batch_enc_iv[] =
		{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
static const uint8_t token_mac_iv[] =
		{ 0x1b, 0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73,
		  0xb2, 0x57, 0x42, 0xd7, 0x07, 0x8b, 0x83, 0xb8 };
static const uint8_t token_enc_iv[] =
		{ 0x16, 0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90,
		  0x8b, 0x2f, 0xb1, 0x36, 0x6e, 0xa9, 0x57, 0xd3 };

struct sec_contents {
	const char		*name;
	const char		*value;
};

static const struct sec_contents header_fields[] = {
	{ "Version", "0" },
	{ "Origin", "N/A" },
	{ "Dest", "N/A" },
	{ "Name", "N/A" },
	{ "FirstToken", "N/A" },
	{ "LastToken", "N/A" },
	{ "NumTokens", "0" },
	{ "Secret", " " },
	{ "DefBirth", "2000/01/01" },
	{ "DefDeath", " " },
	{ "DefDigits", "8" },
	{ "DefInterval", "60" },
	{ "DefAlg", "1" },
	{ "DefMode", "0" },
	{ "DefPrecision", "2400" },
	{ "DefSmallWin", "630" },
	{ "DefMediumWin", "4320" },
	{ "DefLargeWin", "4320" },
	{ "DefAddPIN", "1" },
	{ "DefLocalPIN", "0" },
	{ "DefCopyProtection", "1" },
	{ "DefPinType", "0" },
	{ "DefKeypad", "1" },
	{ "DefProtLevel", "0" },
	{ "DefRevision", "0" },
	{ "DefTimeDerivedSeeds", "1" },
	{ "DefAppDerivedSeeds", "0" },
	{ "DefFormFactor", "20000001" },
	{ NULL, NULL },
};

static const struct sec_contents tkn_fields[] = {
	{ "SN", " " },
	{ "Seed", " " },
	{ "UserFirstName", " " },
	{ "UserLastName", " " },
	{ "UserLogin", " " },

	/* these are usually specified in the header instead */
	{ "Birth", NULL },
	{ "Death", NULL },
	{ "Digits", NULL },
	{ "Interval", NULL },
	{ "Alg", NULL },
	{ "Mode", NULL },
	{ "Precision", NULL },
	{ "SmallWin", NULL },
	{ "MediumWin", NULL },
	{ "LargeWin", NULL },
	{ "AddPIN", NULL },
	{ "LocalPIN", NULL },
	{ "CopyProtection", NULL },
	{ "PinType", NULL },
	{ "Keypad", NULL },
	{ "ProtLevel", NULL },
	{ "Revision", NULL },
	{ "TimeDerivedSeeds", NULL },
	{ "AppDerivedSeeds", NULL },
	{ "FormFactor", NULL },

	{ NULL, NULL },
};

static const struct sec_contents tkn_attr_fields[] = {
	{ "DeviceSerialNumber", " " },
	{ "Nickname", " " },
	{ NULL, NULL },
};

static const struct sec_contents trailer_fields[] = {
	{ "BatchSignature", " " },
	{ "BatchCertificate", " " },
	{ NULL, NULL },
};

static void err_printf(struct sdtid *s, const char *fmt, ...)
{
	va_list ap;

	if (!s->interactive)
		return;
	va_start(ap, fmt);
	fflush(stdout);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void missing_node(struct sdtid *s, const char *name)
{
	err_printf(s, "missing required xml node '%s'\n", name);
}

/************************************************************************
 * XML utility functions
 ************************************************************************/

#define XCAST(x) ((const xmlChar *)(x))

static int xmlnode_is_named(xmlNode *xml_node, const char *name)
{
	if (xml_node->type != XML_ELEMENT_NODE)
		return 0;
	return !strcmp(xml_node->name, name);
}

static xmlNode *find_child_named(xmlNode *node, const char *name)
{
	for (; ; node = node->next) {
		if (!node)
			break;
		if (xmlnode_is_named(node, name))
			return node;
	}
	return NULL;
}

static int __replace_string(struct sdtid *s, xmlNode *node,
			    const char *name, const char *value)
{
	int ret;

	for (node = node->children; node; node = node->next) {
		ret = __replace_string(s, node, name, value);
		if (ret != ERR_GENERAL)
			return ret;
		if (xmlnode_is_named(node, name)) {
			xmlChar *input = xmlEncodeSpecialChars(s->doc, value);
			if (!input)
				return ERR_NO_MEMORY;
			xmlNodeSetContent(node, input);
			return ERR_NONE;
		}
	}
	return ERR_GENERAL;
}

static int replace_string(struct sdtid *s, xmlNode *node,
			  const char *name, const char *value)
{
	int ret = __replace_string(s, node, name, value);
	if (ret != ERR_GENERAL) {
		s->error = ret;
		return ret;
	}

	/* not found => create a new string at the end of the section */
	if (xmlNewTextChild(node, NULL, XCAST(name), XCAST(value)) == NULL) {
		s->error = ERR_NO_MEMORY;
		return ERR_NO_MEMORY;
	}

	return ERR_NONE;
}

static int replace_b64(struct sdtid *s, xmlNode *node, const char *name,
		       const uint8_t *data, int len)
{
	/* this matches src/misc/base64/base64_encode.c in tomcrypt */
	unsigned long enclen = 4 * ((len + 2) / 3) + 1;
	char *out = malloc(enclen + 1);
	int ret;

	if (!out)
		return ERR_NO_MEMORY;

	/* the first character of <Seed> will be ignored by the reader */
	*out = '=';
	base64_encode(data, len, out + 1, &enclen);
	ret = replace_string(s, node, name,
			     !strcmp(name, "Seed") ? out : out + 1);

	free(out);
	return ret;
}

static char *__lookup_common(struct sdtid *s, xmlNode *node, const char *name)
{
	if (s->error != ERR_NONE || !node)
		return NULL;

	for (node = node->children; node; node = node->next) {
		char *val = __lookup_common(s, node, name);
		if (val)
			return val;
		if (xmlnode_is_named(node, name)) {
			val = xmlNodeGetContent(node);
			if (!val)
				s->error = ERR_NO_MEMORY;
			return val;
		}
	}
	return NULL;
}

static char *lookup_common(struct sdtid *s, const char *name)
{
	char *defname = NULL, *ret;

	ret = __lookup_common(s, s->tkn_node, name);
	if (ret)
		return ret;

	/* try Def<FOO> from <TKNHeader> section */
	if (asprintf(&defname, "Def%s", name) < 0) {
		s->error = ERR_NO_MEMORY;
		return NULL;
	}

	ret = __lookup_common(s, s->header_node, defname);
	free(defname);
	if (ret)
		return ret;

	return __lookup_common(s, s->header_node, name);
}

static int node_present(struct sdtid *s, const char *name)
{
	char *str = s ? lookup_common(s, name) : NULL;
	free(str);
	return !!str;
}

static char *lookup_string(struct sdtid *s, const char *name, const char *def)
{
	char *ret = lookup_common(s, name);
	if (!ret && def) {
		ret = strdup(def);
		if (!ret)
			s->error = ERR_NO_MEMORY;
	}
	return ret;
}

static int lookup_int(struct sdtid *s, const char *name, int def)
{
	char *ret = lookup_common(s, name), *endp;
	long val;

	if (!ret)
		return def;

	val = strtol(ret, &endp, 0);
	if (*endp || !*ret)
		s->error = ERR_GENERAL;

	free(ret);
	return val;
}

static int lookup_b64(struct sdtid *s, const char *name, uint8_t *out,
			 int buf_len)
{
	char *data = lookup_common(s, name), *p;
	unsigned long actual = buf_len;
	int len;

	if (!data)
		return -1;

	/* <Seed> has a bogus character at the start of the string */
	p = data;
	if (*p && !strcmp(name, "Seed"))
		p++;

	len = base64_decode(p, strlen(p), out, &actual) == CRYPT_OK ?
	      actual : -1;

	free(data);
	return len == buf_len ? 0 : -1;
}

/************************************************************************
 * Crypto functions
 ************************************************************************/

static void xor_block(uint8_t *out, const uint8_t *in)
{
	int i;
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		out[i] ^= in[i];
}

static void cbc_hash(uint8_t *result, const uint8_t *key, const uint8_t *iv,
	const uint8_t *data, int len)
{
	memcpy(result, iv, AES_BLOCK_SIZE);
	for (; len > 0; len -= AES_BLOCK_SIZE, data += AES_BLOCK_SIZE) {
		if (len >= AES_BLOCK_SIZE)
			xor_block(result, data);
		else {
			uint8_t tmp[AES_BLOCK_SIZE];
			memset(tmp, 0, sizeof(tmp));
			memcpy(tmp, data, len);
			xor_block(result, tmp);
		}
		aes128_ecb_encrypt(key, result, result);
	}
}

#define MAX_HASH_DATA		65536

struct hash_status {
	xmlNode			*root;
	uint8_t			data[MAX_HASH_DATA];
	int			pos;
	int			padding;
};

static int __hash_section(struct hash_status *hs, const char *pfx, xmlNode *node)
{
	int children = 0;
	char *longname = NULL;

	for (node = node->children; node; node = node->next) {
		char *name = (char *)node->name, *val;
		int len, ret, bytes, remain = MAX_HASH_DATA - hs->pos;

		if (node->type != XML_ELEMENT_NODE)
			continue;
		children++;

		len = strlen(name);
		if (len > 3 && !strcmp(&name[len - 3], "MAC"))
			continue;

		free(longname);
		if (asprintf(&longname, "%s.%s", pfx, (char *)node->name) < 0)
			return -1;

		ret = __hash_section(hs, longname, node);
		if (ret < 0)
			goto err;
		if (ret > 0)
			continue;

		val = (char *)xmlNodeGetContent(node);
		if (!val)
			goto err;

		bytes = snprintf(&hs->data[hs->pos], remain,
				 "%s %s\n", longname, val);
		free(val);
		if (bytes >= remain)
			goto err;

		/*
		 * This doesn't really make sense but it's required for
		 * compatibility
		 */
		hs->pos += bytes + hs->padding;
		hs->padding = hs->pos & 0xf ? : 0x10;
	}

	free(longname);
	return children;

err:
	free(longname);
	return -1;
}

static int hash_section(struct sdtid *s, xmlNode *node, uint8_t *mac,
			const uint8_t *key, const uint8_t *iv)
{
	struct hash_status hs;

	memset(&hs, 0, sizeof(hs));
	hs.root = node;
	if (__hash_section(&hs, (char *)node->name, node) < 0)
		return ERR_NO_MEMORY;

	cbc_hash(mac, key, iv, hs.data, hs.pos);
	return ERR_NONE;
}

static void hash_password(uint8_t *result, const char *pass, const char *salt0,
			  const char *salt1)
{
	uint8_t key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	uint8_t data[0x50];
	unsigned int i;

	memset(result, 0, AES_BLOCK_SIZE);
	memset(iv, 0, sizeof(iv));

	memset(key, 0, sizeof(key));
	strncpy(key, salt1, sizeof(key));

	memset(data, 0, sizeof(data));
	strncpy(&data[0x00], pass, 0x20);
	strncpy(&data[0x20], salt0, 0x20);

	for (i = 0; i < 1000; i++) {
		data[0x4f] = i >> 0;
		data[0x4e] = i >> 8;
		cbc_hash(tmp, key, iv, data, sizeof(data));
		xor_block(result, tmp);
	}
}

static void decrypt_secret(uint8_t *result, const uint8_t *enc_bin,
			   const char *str0, const uint8_t *key)
{
	memset(result, 0, AES_BLOCK_SIZE);
	strncpy(&result[0], "Secret", 8);
	strncpy(&result[8], str0, 8);
	aes128_ecb_encrypt(key, result, result);
	xor_block(result, enc_bin);
}

static void decrypt_seed(uint8_t *result, const uint8_t *enc_bin,
			 const char *str0, const uint8_t *key)
{
	memset(result, 0, AES_BLOCK_SIZE);
	strncpy(&result[0], str0, 8);
	strncpy(&result[8], "Seed", 8);
	aes128_ecb_encrypt(key, result, result);
	xor_block(result, enc_bin);
}

static void calc_key(uint8_t *result, const char *str0, const char *str1,
		     const uint8_t *key, const uint8_t *iv)
{
	uint8_t buf[0x40];

	memset(buf, 0, sizeof(buf));
	strncpy(&buf[0x00], str0, 0x20);
	strncpy(&buf[0x20], str1, 0x20);
	cbc_hash(result, key, iv, buf, sizeof(buf));
}

static int str_or_warn(struct sdtid *s, const char *name, char **out)
{
	*out = lookup_string(s, name, NULL);
	if (*out)
		return ERR_NONE;

	missing_node(s, name);
	return ERR_GENERAL;
}

static int b64_or_warn(struct sdtid *s, const char *name, uint8_t *out,
		       int buf_len)
{
	int ret = lookup_b64(s, name, out, buf_len);
	if (ret != ERR_NONE)
		missing_node(s, name);
	return ret;
}

static int generate_all_keys(struct sdtid *s, const char *pass)
{
	uint8_t secret[AES_BLOCK_SIZE], key0[AES_KEY_SIZE], key1[AES_KEY_SIZE];

	char *origin = NULL, *dest = NULL, *name = NULL;
	int ret = ERR_GENERAL;

	free(s->sn);
	if (str_or_warn(s, "SN", &s->sn) ||
	    str_or_warn(s, "Origin", &origin) ||
	    str_or_warn(s, "Dest", &dest) ||
	    str_or_warn(s, "Name", &name) ||
	    b64_or_warn(s, "Secret", secret, AES_KEY_SIZE))
		goto err;

	hash_password(key0, pass ? pass : origin, dest, name);
	decrypt_secret(key1, secret, name, key0);

	calc_key(s->batch_mac_key, "BatchMAC", name, key1, batch_mac_iv);
	calc_key(s->token_mac_key, "TokenMAC", s->sn, key1, token_mac_iv);
	calc_key(s->token_enc_key, "TokenEncrypt", s->sn, key1, token_enc_iv);
	ret = ERR_NONE;

err:
	free(origin);
	free(dest);
	free(name);
	return s->error ? : ret;
}

/************************************************************************
 * Public functions
 ************************************************************************/

int securid_decrypt_sdtid(struct securid_token *t, const char *pass)
{
	struct sdtid *s = t->sdtid;
	uint8_t good_mac0[AES_BLOCK_SIZE], mac0[AES_BLOCK_SIZE],
		good_mac1[AES_BLOCK_SIZE], mac1[AES_BLOCK_SIZE];
	int ret, mac0_passed, mac1_passed;

	if (pass && !strlen(pass))
		pass = NULL;

	ret = generate_all_keys(s, pass);
	if (ret != ERR_NONE)
		return ret;

	if (b64_or_warn(s, "Seed", t->enc_seed, AES_BLOCK_SIZE))
		return ERR_GENERAL;
	t->has_enc_seed = 1;

	if (b64_or_warn(s, "HeaderMAC", good_mac0, AES_BLOCK_SIZE) ||
	    hash_section(s, s->header_node, mac0,
			 s->batch_mac_key, batch_mac_iv))
		return ERR_GENERAL;

	if (b64_or_warn(s, "TokenMAC", good_mac1, AES_BLOCK_SIZE) ||
	    hash_section(s, s->tkn_node, mac1,
			 s->token_mac_key, token_mac_iv))
		return ERR_GENERAL;

	mac0_passed = !memcmp(mac0, good_mac0, AES_BLOCK_SIZE);
	mac1_passed = !memcmp(mac1, good_mac1, AES_BLOCK_SIZE);

	/* note that we cannot diagnose a corrupted <Secret> field */
	if (!mac0_passed && !mac1_passed)
		return pass ? ERR_DECRYPT_FAILED : ERR_MISSING_PASSWORD;

	if (!mac0_passed) {
		err_printf(s, "header MAC check failed - malformed input\n");
		return ERR_DECRYPT_FAILED;
	} else if (!mac1_passed) {
		err_printf(s, "token MAC check failed - malformed input\n");
		return ERR_DECRYPT_FAILED;
	}

	decrypt_seed(t->dec_seed, t->enc_seed, s->sn, s->token_enc_key);
	t->has_dec_seed = 1;
	return ERR_NONE;
}

static uint16_t parse_date(const char *in)
{
	struct tm tm;

	if (!in)
		return 0;
	memset(&tm, 0, sizeof(tm));
	if (sscanf(in, "%d/%d/%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) != 3)
		return 0;

	tm.tm_year -= 1900;
	tm.tm_mon--;

	return (mktime(&tm) - SECURID_EPOCH) / (24*60*60);
}

static void format_date(long in, char *out, int max_len)
{
	time_t t;
	struct tm tm;

	/* negative time = relative to NOW */
	if (in >= 0)
		t = SECURID_EPOCH + (in * 24*60*60);
	else
		t = time(NULL) - in;

	gmtime_r(&t, &tm);
	strftime(out, max_len, "%Y/%m/%d", &tm);
}

static int decode_fields(struct securid_token *t)
{
	struct sdtid *s = t->sdtid;
	char *tmps;
	int tmpi, ret;

	t->version = 2;

	tmps = lookup_string(s, "SN", NULL);
	if (!tmps || strlen(tmps) > SERIAL_CHARS) {
		missing_node(s, "SN");
		free(tmps);
		goto err;
	}
	strncpy(t->serial, tmps, SERIAL_CHARS);
	free(tmps);

	t->flags |= lookup_int(s, "TimeDerivedSeeds", 0) ? FL_TIMESEEDS : 0;
	t->flags |= lookup_int(s, "AppDerivedSeeds", 0) ? FL_APPSEEDS : 0;
	t->flags |= lookup_int(s, "Mode", 0) ? FL_FEAT4 : 0;
	t->flags |= lookup_int(s, "Alg", 0) ? FL_128BIT : 0;

	tmpi = (!!lookup_int(s, "AddPIN", 0) << 1) |
		!!lookup_int(s, "LocalPIN", 0);
	t->flags |= tmpi << FLD_PINMODE_SHIFT;

	tmpi = lookup_int(s, "Digits", 6) - 1;
	t->flags |= (tmpi << FLD_DIGIT_SHIFT) & FLD_DIGIT_MASK;

	tmpi = lookup_int(s, "Interval", 60);
	t->flags |= tmpi == 60 ? (1 << FLD_NUMSECONDS_SHIFT) : 0;

	tmps = lookup_string(s, "Death", NULL);
	t->exp_date = parse_date(tmps);
	free(tmps);
	if (!t->exp_date)
		goto err;

	if (s->error)
		return s->error;

	/*
	 * If decryption fails, prompt for a password and retry.
	 *
	 * We never set FL_SNPROT - it isn't necessary to decrypt the seed
	 * so there is no point prompting the user for it.
	 */
	ret = securid_decrypt_sdtid(t, NULL);
	if (ret == ERR_MISSING_PASSWORD) {
		t->flags |= FL_PASSPROT;
		ret = ERR_NONE;
	}

	return s->error ? : ret;

err:
	return ERR_GENERAL;
}

static int parse_sdtid(const char *in, struct sdtid *s, int which, int strict)
{
	xmlNode *batch, *node;
	int ret = ERR_GENERAL, idx = 0;

	s->doc = xmlReadMemory(in, strlen(in), "sdtid.xml", NULL,
			       s->interactive ? XML_PARSE_PEDANTIC :
			       (XML_PARSE_NOERROR | XML_PARSE_NOWARNING));
	if (!s->doc)
		return ERR_GENERAL;

	batch = find_child_named(xmlDocGetRootElement(s->doc), "TKNBatch");
	if (!batch) {
		missing_node(s, "TKNBatch");
		goto err;
	}

	s->header_node = find_child_named(batch->children, "TKNHeader");
	s->trailer_node = find_child_named(batch->children, "TKNTrailer");

	for (node = batch->children; node; node = node->next) {
		if (xmlnode_is_named(node, "TKN")) {
			if (which == -1 && s->tkn_node) {
				ret = ERR_MULTIPLE_TOKENS;
				goto err;
			}
			if (idx++ == which || which == -1)
				s->tkn_node = node;
		}
	}

	if (strict) {
		if (!s->header_node) {
			missing_node(s, "TKNHeader");
			goto err;
		}
		if (!s->tkn_node) {
			missing_node(s, "TKN");
			goto err;
		}
		if (!s->trailer_node) {
			missing_node(s, "TKNTrailer");
			goto err;
		}
	}

	return ERR_NONE;

err:
	xmlFreeDoc(s->doc);
	return ret;
}

static int decode_one(const char *in, struct securid_token *t, int which)
{
	struct sdtid *s;
	int ret;

	s = calloc(1, sizeof(*s));
	if (!s)
		return ERR_NO_MEMORY;

	s->interactive = t->interactive;

	ret = parse_sdtid(in, s, which, 1);
	if (ret) {
		free(s);
		return ret;
	}

	t->sdtid = s;
	if (decode_fields(t) != ERR_NONE) {
		ret = ERR_GENERAL;
		goto err;
	}

	return ERR_NONE;

err:
	securid_free_sdtid(s);
	return ret;
}

int securid_decode_sdtid(const char *in, struct securid_token *t)
{
	return decode_one(in, t, -1);
}

static int read_template_file(const char *filename, struct sdtid *s)
{
	ssize_t len;
	char buf[65536];
	FILE *f;

	f = fopen(filename, "r");
	if (f == NULL)
		return ERR_FILE_READ;
	len = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);

	if (len < 0)
		return ERR_FILE_READ;
	buf[len] = 0;

	if (parse_sdtid(buf, s, -1, 0) != ERR_NONE)
		return ERR_GENERAL;
	return ERR_NONE;
}

static xmlNode *fill_section(xmlNode *parent, const char *name,
			     const struct sec_contents *pairs,
			     struct sdtid *tpl)
{
	xmlNode *section;

	section = xmlNewNode(NULL, XCAST(name));
	if (!section)
		return NULL;
	if (!xmlAddChild(parent, section))
		return NULL;

	for (; pairs->name; pairs++) {
		const char *value = pairs->value;

		if (tpl) {
			char *str;
			str = __lookup_common(tpl,
					      xmlDocGetRootElement(tpl->doc),
					      pairs->name);
			if (str)
				value = str;
		}

		if (!value)
			continue;
		if (xmlNewTextChild(section, NULL, XCAST(pairs->name),
				    XCAST(value)) == NULL)
			return NULL;
	}
	return section;
}

static struct sdtid *new_sdtid(struct sdtid *tpl)
{
	struct sdtid *s;
	xmlNode *batch, *attr;

	s = calloc(1, sizeof(*s));
	if (!s)
		goto bad;

	s->doc = xmlNewDoc(XCAST("1.0"));
	if (!s->doc)
		goto bad;

	batch = xmlNewNode(NULL, XCAST("TKNBatch"));
	if (!batch)
		goto bad;
	xmlDocSetRootElement(s->doc, batch);

	s->header_node = fill_section(batch, "TKNHeader", header_fields, tpl);
	s->tkn_node = fill_section(batch, "TKN", tkn_fields, tpl);
	s->trailer_node = fill_section(batch, "TKNTrailer", trailer_fields, tpl);
	attr = fill_section(s->tkn_node, "TokenAttributes", tkn_attr_fields, tpl);

	if (!s->header_node || !s->tkn_node || !s->trailer_node || !attr)
		goto bad;

	return s;

bad:
	securid_free_sdtid(s);
	return NULL;
}

static int clone_from_template(const char *filename, struct sdtid **tpl,
			       struct sdtid **dst)
{
	int ret;

	*tpl = *dst = NULL;

	/* note that filename is OPTIONAL */
	if (filename) {
		*tpl = calloc(1, sizeof(**tpl));
		if (!*tpl)
			return ERR_NO_MEMORY;

		(*tpl)->interactive = 1;
		ret = read_template_file(filename, *tpl);
		if (ret != ERR_NONE)
			goto out;
	}

	*dst = new_sdtid(*tpl);
	if (*dst)
		return ERR_NONE;

	ret = ERR_NO_MEMORY;

out:
	securid_free_sdtid(*tpl);
	securid_free_sdtid(*dst);
	return ret;
}

static int overwrite_secret(struct sdtid *s, xmlNode *node, const char *name,
			    int paranoid)
{
	uint8_t data[AES_BLOCK_SIZE];
	int ret;

	ret = securid_rand(data, sizeof(data), paranoid);
	if (ret != ERR_NONE) {
		s->error = ret;
		return ret;
	}

	return replace_b64(s, node, name, data, sizeof(data));
}

static int recompute_macs(struct sdtid *s)
{
	uint8_t mac[AES_BLOCK_SIZE];

	if (hash_section(s, s->header_node, mac, s->batch_mac_key, batch_mac_iv) ||
	    replace_b64(s, s->header_node, "HeaderMAC", mac, sizeof(mac)) ||
	    hash_section(s, s->tkn_node, mac, s->token_mac_key, token_mac_iv) ||
	    replace_b64(s, s->tkn_node, "TokenMAC", mac, sizeof(mac))) {
		s->error = ERR_GENERAL;
		return ERR_GENERAL;
	}

	return ERR_NONE;
}

static void check_and_store_int(struct sdtid *s, struct sdtid *tpl,
				const char *name, int val)
{
	char *tmp, str[32];
	if (node_present(tpl, name))
		return;

	if (asprintf(&tmp, "Def%s", name) < 0) {
		s->error = ERR_NO_MEMORY;
		return;
	}
	snprintf(str, sizeof(str), "%d", val);
	replace_string(s, s->header_node, tmp, str);
	free(tmp);
}

static int generate_sn(char *str)
{
	uint8_t data[6];
	int i;

	if (securid_rand(data, sizeof(data), 0) != ERR_NONE)
		return ERR_GENERAL;
	for (i = 0; i < 6; i++)
		sprintf(&str[i*2], "%02d", data[i] % 100);
	return ERR_NONE;
}

int securid_issue_sdtid(const char *filename, const char *pass,
			const char *devid)
{
	struct sdtid *s = NULL, *tpl = NULL;
	int ret = ERR_GENERAL;
	uint8_t dec_seed[AES_KEY_SIZE], enc_seed[AES_KEY_SIZE];
	char str[32];

	if (clone_from_template(filename, &tpl, &s) ||
	    overwrite_secret(s, s->header_node, "Secret", 1) ||
	    securid_rand(dec_seed, sizeof(dec_seed), 1))
		goto out;

	if (!node_present(tpl, "SN")) {
		if (generate_sn(str) != ERR_NONE)
			goto out;
		replace_string(s, s->tkn_node, "SN", str);
	}

	if (devid && strlen(devid))
		replace_string(s, s->tkn_node, "DeviceSerialNumber", devid);

	ret = generate_all_keys(s, pass);
	if (ret != ERR_NONE || s->error != ERR_NONE)
		goto out;

	decrypt_seed(enc_seed, dec_seed, s->sn, s->token_enc_key);
	replace_b64(s, s->tkn_node, "Seed", enc_seed, sizeof(enc_seed));

	if (!node_present(tpl, "Birth")) {
		format_date(-1, str, 32);
		replace_string(s, s->header_node, "DefBirth", str);
	}

	if (!node_present(tpl, "Death")) {
		/* if unspecified, use (today + 5 years) */
		format_date(-5*365*24*60*60, str, 32);
		replace_string(s, s->header_node, "DefDeath", str);
	}

	recompute_macs(s);

	if (s->error != ERR_NONE)
		goto out;

	xmlDocFormatDump(stdout, s->doc, 1);
	ret = ERR_NONE;

out:
	securid_free_sdtid(tpl);
	securid_free_sdtid(s);
	memset(dec_seed, 0, sizeof(dec_seed));
	return ret;
}

int securid_export_sdtid(const char *filename, struct securid_token *t,
			 const char *pass, const char *devid)
{
	struct sdtid *s = NULL, *tpl = NULL;
	int ret;
	uint8_t dec_seed[AES_KEY_SIZE], enc_seed[AES_KEY_SIZE];

	ret = clone_from_template(filename, &tpl, &s);
	if (ret != ERR_NONE)
		return ret;

	if (!node_present(tpl, "Secret"))
		overwrite_secret(s, s->header_node, "Secret", 0);

	/* this section should largely mirror decode_fields() */

	if (!node_present(tpl, "SN"))
		replace_string(s, s->tkn_node, "SN", t->serial);

	check_and_store_int(s, tpl, "TimeDerivedSeeds",
			    !!(t->flags & FL_TIMESEEDS));
	check_and_store_int(s, tpl, "AppDerivedSeeds",
			    !!(t->flags & FL_APPSEEDS));
	check_and_store_int(s, tpl, "Mode", !!(t->flags & FL_FEAT4));
	check_and_store_int(s, tpl, "Alg", !!(t->flags & FL_128BIT));
	check_and_store_int(s, tpl, "AddPIN",
			    !!(t->flags >> (FLD_PINMODE_SHIFT + 1)));
	check_and_store_int(s, tpl, "LocalPIN",
			    !!(t->flags >> (FLD_PINMODE_SHIFT + 0)));
	check_and_store_int(s, tpl, "Digits", 1 +
			    ((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT));
	check_and_store_int(s, tpl, "Interval",
			    t->flags & FLD_NUMSECONDS_MASK ? 60 : 30);

	if (!node_present(tpl, "Death")) {
		char str[32];
		format_date(t->exp_date, str, 32);
		replace_string(s, s->header_node, "DefDeath", str);
	}

	if (devid && strlen(devid))
		replace_string(s, s->tkn_node, "DeviceSerialNumber", devid);

	ret = generate_all_keys(s, pass);
	if (ret != ERR_NONE || s->error != ERR_NONE)
		goto out;

	/* special case: this is an unencrypted seed in base64 format */
	if (node_present(tpl, "Seed")) {
		if (b64_or_warn(tpl, "Seed", dec_seed, AES_KEY_SIZE)) {
			ret = ERR_GENERAL;
			goto out;
		}
	} else {
		memcpy(dec_seed, t->dec_seed, AES_KEY_SIZE);
	}

	decrypt_seed(enc_seed, dec_seed, s->sn, s->token_enc_key);
	replace_b64(s, s->tkn_node, "Seed", enc_seed, sizeof(enc_seed));

	recompute_macs(s);

	if (s->error != ERR_NONE)
		goto out;

	xmlDocFormatDump(stdout, s->doc, 1);
	ret = ERR_NONE;

out:
	securid_free_sdtid(tpl);
	securid_free_sdtid(s);
	return ret;
}

void securid_free_sdtid(struct sdtid *s)
{
	if (!s)
		return;
	free(s->sn);
	xmlFreeDoc(s->doc);
	memset(s, 0, sizeof(*s));
	free(s);
}
