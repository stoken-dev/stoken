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

#include "securid.h"
#include "sdtid.h"
#include "stoken-internal.h"

struct sdtid {
	xmlDoc			*doc;
	xmlNode			*header_node;
	xmlNode			*tkn_node;
	xmlNode			*trailer_node;

	int			is_template;
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

#define RSA_MODULUS_SIZE	(1024 / 8)
#define HASH_SIZE		(160 / 8)

static const uint8_t batch_privkey[] =
		{ 0x30, 0x82, 0x02, 0x4c, 0x02, 0x01, 0x00, 0x02,
		  0x81, 0x81, 0x00, 0xdd, 0xa1, 0xee, 0xa6, 0xd7,
		  0x66, 0xbb, 0xeb, 0xe2, 0x96, 0x0b, 0xeb, 0x19,
		  0x75, 0x44, 0x2b, 0x97, 0x1f, 0x25, 0x66, 0xb5,
		  0xc6, 0x03, 0x8d, 0x0f, 0xbb, 0x86, 0x91, 0xbb,
		  0x40, 0x04, 0xf9, 0x36, 0x4d, 0x04, 0xe7, 0x72,
		  0x4e, 0xca, 0x59, 0x84, 0xda, 0x2c, 0x64, 0xf2,
		  0xe5, 0x5f, 0xb4, 0x47, 0xc6, 0xf1, 0xe1, 0x53,
		  0xa5, 0xea, 0x15, 0x6d, 0xb4, 0x58, 0x51, 0xa4,
		  0xdd, 0x46, 0xc1, 0x22, 0x5f, 0xa1, 0x5c, 0xa5,
		  0xfb, 0x83, 0x9e, 0x72, 0x2b, 0xc0, 0xd4, 0x46,
		  0x69, 0x8e, 0x01, 0x35, 0x2c, 0x3f, 0x82, 0x57,
		  0x42, 0xf1, 0x38, 0x50, 0xc3, 0xf0, 0x6c, 0x1e,
		  0x28, 0xd1, 0x11, 0xe1, 0x32, 0xb5, 0x2c, 0xd0,
		  0x57, 0x06, 0x33, 0x54, 0xa3, 0x3a, 0x8e, 0x48,
		  0x26, 0xfa, 0x0b, 0xf1, 0x85, 0x52, 0xe8, 0xe8,
		  0x3e, 0x07, 0x6f, 0x54, 0x79, 0x68, 0xfe, 0x53,
		  0xc0, 0x01, 0x7b, 0x02, 0x03, 0x01, 0x00, 0x01,
		  0x02, 0x71, 0x00, 0xca, 0x45, 0x93, 0xad, 0x29,
		  0x41, 0x55, 0x98, 0xbe, 0xbe, 0xfa, 0x39, 0xa2,
		  0x8e, 0x67, 0x9c, 0xf0, 0xdb, 0x38, 0x23, 0x39,
		  0x1a, 0x72, 0xfb, 0x36, 0xb4, 0x8a, 0xe8, 0x4d,
		  0xe0, 0xeb, 0xa9, 0x16, 0x69, 0xcc, 0x63, 0xfe,
		  0xea, 0xf1, 0xba, 0x29, 0x89, 0x84, 0xa2, 0xcd,
		  0x1b, 0x91, 0xf0, 0xd2, 0xe1, 0x3a, 0xb7, 0xce,
		  0xc3, 0xc9, 0x93, 0xac, 0xff, 0xbe, 0xeb, 0x24,
		  0x6f, 0xde, 0xb5, 0x8a, 0x37, 0xe2, 0x1f, 0xd4,
		  0x1e, 0x0b, 0x2e, 0xc4, 0xaf, 0x02, 0x73, 0xa7,
		  0xda, 0x33, 0x40, 0xa2, 0x22, 0xdc, 0x73, 0x63,
		  0x4b, 0xf2, 0xbd, 0xd0, 0x76, 0x18, 0xc8, 0xc5,
		  0xc6, 0x5a, 0xe7, 0x4a, 0xa9, 0x2f, 0xbb, 0xe1,
		  0xae, 0xe7, 0x3a, 0xcf, 0xd6, 0x4f, 0xa0, 0x58,
		  0x28, 0x3e, 0xe0, 0x02, 0x41, 0x00, 0xf7, 0x31,
		  0xfd, 0xe2, 0x7f, 0x4f, 0x9e, 0x3a, 0x61, 0x2e,
		  0x5d, 0x53, 0x1c, 0xc1, 0x9d, 0xc8, 0xa1, 0x69,
		  0xba, 0xe0, 0xc3, 0x01, 0x7e, 0x3d, 0xbe, 0xe0,
		  0x56, 0x81, 0x9c, 0x16, 0xe2, 0x53, 0x0f, 0xdc,
		  0xb1, 0xb6, 0xd1, 0x4a, 0xa2, 0x9c, 0x1c, 0x2e,
		  0x18, 0x53, 0x8d, 0x4e, 0x74, 0xe5, 0xb1, 0xd7,
		  0x69, 0xda, 0xf7, 0xff, 0xf5, 0xa3, 0x32, 0xd2,
		  0x37, 0x84, 0xe7, 0x86, 0xf0, 0x37, 0x02, 0x41,
		  0x00, 0xe5, 0x86, 0xd9, 0xde, 0x9e, 0xdd, 0x7a,
		  0xbe, 0xb8, 0x0f, 0x2e, 0x2e, 0x34, 0x77, 0xd5,
		  0x89, 0x12, 0x29, 0x47, 0xbd, 0xe1, 0x4c, 0xc6,
		  0x28, 0xa9, 0x42, 0x38, 0x48, 0xa4, 0x47, 0xb8,
		  0xc2, 0x0b, 0xf8, 0x93, 0xe6, 0x81, 0x40, 0xe9,
		  0x04, 0xe1, 0x4f, 0x74, 0x46, 0x93, 0xfa, 0xeb,
		  0x40, 0x2f, 0x6c, 0x13, 0xf3, 0x70, 0x0f, 0xec,
		  0x3b, 0x59, 0xa4, 0xf6, 0x68, 0x4b, 0xcd, 0x6e,
		  0xdd, 0x02, 0x40, 0x33, 0xe9, 0x70, 0xba, 0xd7,
		  0x27, 0x9e, 0x3f, 0xfe, 0x56, 0xa1, 0x4c, 0xa9,
		  0xf6, 0x53, 0x2f, 0x66, 0x0e, 0x71, 0x2b, 0x70,
		  0x68, 0x68, 0xdd, 0x88, 0xaf, 0x4e, 0x1b, 0x6b,
		  0xef, 0x36, 0x5a, 0x61, 0x33, 0x64, 0xb2, 0xd2,
		  0xe3, 0x0c, 0xa1, 0x22, 0x1d, 0xe0, 0x07, 0xf3,
		  0xdd, 0xed, 0x18, 0xab, 0xaf, 0x64, 0x50, 0x92,
		  0xd2, 0x53, 0x00, 0x91, 0xd4, 0xa9, 0xca, 0x24,
		  0x61, 0x27, 0x23, 0x02, 0x40, 0x39, 0x3c, 0xba,
		  0xa2, 0x08, 0x6d, 0xe4, 0xc9, 0x20, 0xaf, 0x30,
		  0x6d, 0xf7, 0x49, 0x96, 0xe7, 0x7a, 0xae, 0xee,
		  0xa4, 0x0c, 0x46, 0x0f, 0xf8, 0x5d, 0xd5, 0x14,
		  0xa2, 0x10, 0xcd, 0x8d, 0xe6, 0x5e, 0x03, 0xdc,
		  0x26, 0x14, 0x3f, 0x72, 0x9c, 0x73, 0xef, 0x53,
		  0x68, 0xb2, 0x48, 0x55, 0x58, 0x09, 0x3b, 0x63,
		  0x72, 0x46, 0x94, 0xc1, 0xed, 0x3e, 0xfa, 0xa3,
		  0x33, 0xf9, 0x0b, 0x3e, 0xc5, 0x02, 0x41, 0x00,
		  0x89, 0x0b, 0xa9, 0x1d, 0xaf, 0x26, 0xc4, 0x50,
		  0xf4, 0xae, 0x69, 0x61, 0x85, 0xa5, 0x82, 0x62,
		  0x25, 0x81, 0x4f, 0x02, 0xc7, 0x9a, 0x0c, 0x64,
		  0x00, 0xc4, 0x8d, 0x5d, 0x40, 0x95, 0x5c, 0x99,
		  0x70, 0xb7, 0x5b, 0x79, 0x86, 0xd9, 0xeb, 0xa4,
		  0x72, 0x6d, 0xee, 0x01, 0xdc, 0x41, 0x88, 0x27,
		  0x21, 0x3f, 0x5a, 0x55, 0x9b, 0x1f, 0xd6, 0xe5,
		  0xdd, 0x38, 0x83, 0xb4, 0xa4, 0x22, 0xac, 0x8e,
		  0x0a };

/*
 * You'd think this would contain an RSA modulus that matches batch_privkey,
 * but for whatever reason, it's completely different.
 */
static const uint8_t batch_cert[] =
		{ 0x30, 0x82, 0x02, 0x79, 0x30, 0x82, 0x01, 0x61,
		  0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x33,
		  0x43, 0x45, 0x35, 0x35, 0x38, 0x35, 0x33, 0x33,
		  0x30, 0x39, 0x46, 0x38, 0x31, 0x33, 0x30, 0x30,
		  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		  0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30, 0x41,
		  0x31, 0x3f, 0x30, 0x3d, 0x06, 0x03, 0x55, 0x04,
		  0x03, 0x13, 0x36, 0x53, 0x65, 0x63, 0x75, 0x72,
		  0x69, 0x74, 0x79, 0x20, 0x44, 0x79, 0x6e, 0x61,
		  0x6d, 0x69, 0x63, 0x73, 0x20, 0x54, 0x65, 0x63,
		  0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65,
		  0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x20,
		  0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x20,
		  0x43, 0x41, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
		  0x31, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x32, 0x30,
		  0x35, 0x31, 0x37, 0x31, 0x39, 0x32, 0x31, 0x35,
		  0x35, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x35,
		  0x31, 0x32, 0x31, 0x39, 0x32, 0x31, 0x35, 0x35,
		  0x5a, 0x30, 0x34, 0x31, 0x32, 0x30, 0x30, 0x06,
		  0x03, 0x55, 0x04, 0x03, 0x13, 0x29, 0x53, 0x65,
		  0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x44,
		  0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x73, 0x20,
		  0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f,
		  0x67, 0x69, 0x65, 0x73, 0x20, 0x41, 0x43, 0x45,
		  0x2f, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x30,
		  0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
		  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
		  0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89,
		  0x02, 0x81, 0x81, 0x00, 0xd6, 0x7a, 0x75, 0x0c,
		  0x87, 0xf7, 0x1c, 0xe1, 0xc0, 0x2b, 0x66, 0xa1,
		  0x71, 0x1c, 0xd9, 0x08, 0x9b, 0x2a, 0x20, 0x2d,
		  0x50, 0x30, 0x4a, 0xad, 0xb1, 0xd6, 0xa7, 0x29,
		  0x21, 0x27, 0xe4, 0x21, 0xad, 0x2c, 0x27, 0x4b,
		  0xbf, 0xd2, 0xdb, 0x2d, 0x46, 0x28, 0xe9, 0xc4,
		  0x31, 0x29, 0x22, 0x6d, 0xc2, 0xf8, 0xa0, 0xa5,
		  0xe0, 0xe0, 0x04, 0x06, 0xff, 0x51, 0x87, 0x14,
		  0x35, 0x7c, 0xbf, 0xed, 0xd6, 0x3b, 0xac, 0x0e,
		  0x56, 0xa5, 0x89, 0x6c, 0x68, 0x0f, 0x61, 0xe4,
		  0x2f, 0x6a, 0xcc, 0xf3, 0x01, 0x1f, 0x15, 0x46,
		  0x48, 0x87, 0xb9, 0x93, 0xad, 0x6e, 0x51, 0xb0,
		  0x30, 0x74, 0x58, 0x42, 0x31, 0xf2, 0xe1, 0xef,
		  0xbe, 0xb0, 0x47, 0xff, 0xd5, 0x67, 0xb7, 0x2e,
		  0xca, 0x9a, 0x39, 0x77, 0x77, 0x02, 0x6e, 0xf8,
		  0x07, 0x1b, 0x0a, 0xb0, 0xe1, 0x9b, 0x84, 0x09,
		  0xb2, 0xaf, 0x38, 0xd3, 0x02, 0x03, 0x01, 0x00,
		  0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
		  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00,
		  0x03, 0x82, 0x01, 0x01, 0x00, 0xab, 0xc3, 0x0c,
		  0x26, 0xcd, 0x52, 0x73, 0x3c, 0x29, 0x7d, 0xc6,
		  0x6a, 0x9f, 0xd9, 0x68, 0x33, 0xed, 0x91, 0x84,
		  0x59, 0x8d, 0xd4, 0x86, 0x62, 0x5f, 0x27, 0xaf,
		  0xcf, 0x55, 0x6f, 0x18, 0x3f, 0x46, 0x52, 0xb9,
		  0x4b, 0x6a, 0x59, 0xbf, 0x12, 0xdf, 0x7c, 0xf7,
		  0x34, 0x7f, 0x75, 0x58, 0x5c, 0x88, 0x65, 0xe6,
		  0x00, 0x0c, 0x58, 0x9d, 0x5f, 0xcc, 0xa1, 0x99,
		  0xac, 0x86, 0x35, 0xe8, 0xce, 0x62, 0x60, 0x8d,
		  0x19, 0x9f, 0xaa, 0xa1, 0xcb, 0x4b, 0x8e, 0x94,
		  0x27, 0xd9, 0xcb, 0x67, 0x60, 0x6e, 0x11, 0x57,
		  0x2b, 0x1e, 0x79, 0xfa, 0x7f, 0xd9, 0x9e, 0x22,
		  0x37, 0x8c, 0x5a, 0x6f, 0x83, 0xbe, 0x1f, 0xbc,
		  0x56, 0x2f, 0x4a, 0x24, 0xe2, 0xe8, 0xcd, 0x86,
		  0xc3, 0xa1, 0xa5, 0x0c, 0x9b, 0xee, 0x45, 0xef,
		  0x2c, 0x0a, 0xb1, 0x4b, 0x81, 0x3d, 0x14, 0x89,
		  0xd7, 0x29, 0x06, 0x24, 0x6e, 0x9d, 0x38, 0x20,
		  0x59, 0x94, 0x91, 0xa6, 0x33, 0x79, 0x1b, 0x67,
		  0x9e, 0x25, 0x44, 0x02, 0xb6, 0x4d, 0x87, 0x2e,
		  0xd8, 0x93, 0x36, 0xd6, 0x2e, 0xc1, 0x29, 0xd7,
		  0x84, 0xf7, 0x12, 0x2d, 0xc9, 0xa6, 0xc9, 0xcc,
		  0x49, 0x37, 0x40, 0x2b, 0x17, 0xd1, 0xea, 0xd8,
		  0xee, 0x1d, 0xd5, 0xff, 0xfa, 0x24, 0x21, 0xf2,
		  0x96, 0x2e, 0x1f, 0x0b, 0x89, 0xea, 0x16, 0x6d,
		  0x5e, 0x3e, 0x56, 0xda, 0xd0, 0x12, 0x88, 0x94,
		  0xc3, 0x2a, 0x9d, 0x62, 0xcc, 0x30, 0x80, 0xc3,
		  0xb2, 0x46, 0x22, 0xae, 0x19, 0x39, 0x24, 0xdc,
		  0x38, 0x47, 0x76, 0x8a, 0xa1, 0x1b, 0xc4, 0xaa,
		  0x1d, 0x2c, 0x64, 0x3e, 0xda, 0x38, 0xda, 0x11,
		  0x27, 0xa4, 0xec, 0x7d, 0x8f, 0x6a, 0xea, 0x72,
		  0xc3, 0x96, 0xa2, 0xcb, 0xcd, 0xc9, 0xf9, 0xbd,
		  0x9f, 0x09, 0x2a, 0x25, 0xf8, 0x6e, 0x24, 0x29,
		  0x4b, 0xc0, 0xec, 0xf0, 0xe5 };

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
			xmlChar *input = xmlEncodeEntitiesReentrant(s->doc,
								    value);
			if (!input)
				return ERR_NO_MEMORY;
			xmlNodeSetContent(node, input);
			free(input);
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
	unsigned long enclen = BASE64_INPUT_LEN(len);
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
			val = (char *)xmlNodeGetContent(node);
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
		stc_aes128_ecb_encrypt(key, result, result);
	}
}

#define MAX_HASH_DATA		65536

struct hash_status {
	xmlNode			*root;
	uint8_t			data[MAX_HASH_DATA];
	int			pos;
	int			padding;
	int			signing;
};

static int recursive_hash(struct hash_status *hs, const char *pfx, xmlNode *node)
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
		if (!hs->signing && len > 3 && !strcmp(&name[len - 3], "MAC"))
			continue;

		free(longname);
		if (asprintf(&longname, "%s.%s", pfx, (char *)node->name) < 0)
			return -1;

		ret = recursive_hash(hs, longname, node);
		if (ret < 0)
			goto err;
		if (ret > 0)
			continue;

		val = (char *)xmlNodeGetContent(node);
		if (!val)
			goto err;

		if (!strlen(val)) {
			/*
			 * An empty string is valid XML but it might violate
			 * the sdtid format.  We'll handle it the same bizarre
			 * way as RSA just to be safe.
			 */
			bytes = snprintf(&hs->data[hs->pos], remain,
					 "%s </%s>\n", longname, name);
		} else {
			bytes = snprintf(&hs->data[hs->pos], remain,
					 "%s %s\n", longname, val);
		}
		free(val);
		if (bytes >= remain)
			goto err;

		/*
		 * This doesn't really make sense but it's required for
		 * compatibility
		 */
		hs->pos += bytes + hs->padding;
		if (!hs->signing)
			hs->padding = hs->pos & 0xf ? : 0x10;
	}

	free(longname);
	return children;

err:
	free(longname);
	return -1;
}

static int __hash_section(struct hash_status *hs, xmlNode *node, int signing)
{
	hs->root = node;
	hs->signing = signing;
	return recursive_hash(hs, (char *)node->name, node);
}

static int hash_section(struct sdtid *s, xmlNode *node, uint8_t *mac,
			const uint8_t *key, const uint8_t *iv)
{
	struct hash_status hs;

	memset(&hs, 0, sizeof(hs));
	if (__hash_section(&hs, node, 0) < 0)
		return ERR_NO_MEMORY;

	cbc_hash(mac, key, iv, hs.data, hs.pos);
	return ERR_NONE;
}

static int sign_contents(struct sdtid *s, uint8_t *sig)
{
	struct hash_status hs;
	hash_state md;
	uint8_t hash[HASH_SIZE];
	unsigned long outlen = RSA_MODULUS_SIZE;
	rsa_key key;
	int hash_idx, rc = 0;

	memset(&hs, 0, sizeof(hs));
	if (__hash_section(&hs, s->header_node, 1) < 0)
		return ERR_NO_MEMORY;
	if (__hash_section(&hs, s->tkn_node, 1) < 0)
		return ERR_NO_MEMORY;

	sha1_init(&md);
	sha1_process(&md, hs.data, hs.pos);
	sha1_done(&md, hash);

	/*
	 * NOTE: This is set up in common.c.  If we ever decide to let library
	 * callers generate sdtid files, we will have to figure out how to
	 * call register_sha1() and set ltc_mp without disturbing other
	 * libtomcrypt users who might coexist in the same process.
	 */
	hash_idx = find_hash("sha1");
	if (hash_idx < 0)
		return ERR_GENERAL;

	if (rsa_import(batch_privkey, sizeof(batch_privkey), &key) != CRYPT_OK)
		return ERR_GENERAL;
	if (rsa_sign_hash_ex(hash, HASH_SIZE, sig, &outlen,
			     LTC_LTC_PKCS_1_V1_5, NULL, 0,
			     hash_idx, 0, &key) != CRYPT_OK)
		rc = ERR_GENERAL;

	rsa_free(&key);
	return rc;
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

	/* FIXME: this should probably use a hash if salt1 is >16 chars */
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
	stc_aes128_ecb_encrypt(key, result, result);
	xor_block(result, enc_bin);
}

static void decrypt_seed(uint8_t *result, const uint8_t *enc_bin,
			 const char *str0, const uint8_t *key)
{
	memset(result, 0, AES_BLOCK_SIZE);
	strncpy(&result[0], str0, 8);
	strncpy(&result[8], "Seed", 8);
	stc_aes128_ecb_encrypt(key, result, result);
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
	char *p;
	int len;

	*out = lookup_string(s, name, NULL);
	if (!*out) {
		missing_node(s, name);
		return ERR_GENERAL;
	}

	/* trim leading and trailing whitespace */
	len = strlen(*out);
	for (p = *out; isspace(*p); p++)
		len--;
	memmove(*out, p, len + 1);

	for (p = *out + len - 1; len && isspace(*p); p--, len--)
		*p = 0;

	return ERR_NONE;
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

int sdtid_decrypt(struct securid_token *t, const char *pass)
{
	struct sdtid *s = t->sdtid;
	uint8_t good_mac0[AES_BLOCK_SIZE], mac0[AES_BLOCK_SIZE],
		good_mac1[AES_BLOCK_SIZE], mac1[AES_BLOCK_SIZE];
	int ret, mac0_passed, mac1_passed;

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
	tmpi = tmps ? strlen(tmps) : 0;
	if (!tmpi || tmpi > SERIAL_CHARS) {
		missing_node(s, "SN");
		free(tmps);
		goto err;
	}

	/* hard token sdtid files are missing the leading zeroes */
	memset(t->serial, '0', SERIAL_CHARS);
	strncpy(&t->serial[SERIAL_CHARS - tmpi], tmps, SERIAL_CHARS);
	t->serial[SERIAL_CHARS] = 0;
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
	ret = sdtid_decrypt(t, NULL);
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
	sdtid_free(s);
	return ret;
}

int sdtid_decode(const char *in, struct securid_token *t)
{
	return decode_one(in, t, -1);
}

static int read_template_file(const char *filename, struct sdtid *s)
{
	size_t len;
	char buf[65536];
	FILE *f;

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

	if (parse_sdtid(buf, s, -1, 0) != ERR_NONE)
		return ERR_GENERAL;

	s->is_template = 1;
	return ERR_NONE;
}

static xmlNode *fill_section(xmlNode *parent, const char *name,
			     const struct sec_contents *pairs,
			     struct sdtid *tpl)
{
	xmlNode *section;

	section = xmlNewNode(NULL, XCAST(name));
	if (!section)
		goto err;
	if (!xmlAddChild(parent, section))
		goto err;

	for (; pairs->name; pairs++) {
		if (tpl) {
			char *str;
			str = __lookup_common(tpl,
					      xmlDocGetRootElement(tpl->doc),
					      pairs->name);
			if (str) {
				if (xmlNewTextChild(section, NULL,
						    XCAST(pairs->name),
						    XCAST(str)) == NULL) {
					free(str);
					goto err;
				} else {
					free(str);
					continue;
				}
			}
		}
		if (pairs->value) {
			if (xmlNewTextChild(section, NULL,
					    XCAST(pairs->name),
					    XCAST(pairs->value)) == NULL) {
				goto err;
			}
		}
	}
	return section;

err:
	xmlFreeNode(section);
	return NULL;
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
	sdtid_free(s);
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
	sdtid_free(*tpl);
	sdtid_free(*dst);
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
	uint8_t mac[AES_BLOCK_SIZE], sig[RSA_MODULUS_SIZE];

	if (hash_section(s, s->header_node, mac, s->batch_mac_key, batch_mac_iv) ||
	    replace_b64(s, s->header_node, "HeaderMAC", mac, sizeof(mac)) ||
	    hash_section(s, s->tkn_node, mac, s->token_mac_key, token_mac_iv) ||
	    replace_b64(s, s->tkn_node, "TokenMAC", mac, sizeof(mac)) ||
	    sign_contents(s, sig) ||
	    replace_b64(s, s->trailer_node, "BatchSignature", sig,
			sizeof(sig)) ||
	    replace_b64(s, s->trailer_node, "BatchCertificate", batch_cert,
			sizeof(batch_cert))) {
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

int sdtid_issue(const char *filename, const char *pass,
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
	sdtid_free(tpl);
	sdtid_free(s);
	memset(dec_seed, 0, sizeof(dec_seed));
	return ret;
}

int sdtid_export(const char *filename, struct securid_token *t,
		 const char *pass, const char *devid)
{
	struct sdtid *s = NULL, *tpl = NULL;
	int ret, tmp;
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

	tmp = (t->flags & FLD_PINMODE_MASK) >> FLD_PINMODE_SHIFT;
	check_and_store_int(s, tpl, "AddPIN", !!(tmp & 0x02));
	check_and_store_int(s, tpl, "LocalPIN", !!(tmp & 0x01));
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
	sdtid_free(tpl);
	sdtid_free(s);
	return ret;
}

void sdtid_free(struct sdtid *s)
{
	if (!s)
		return;
	free(s->sn);
	xmlFreeDoc(s->doc);
	memset(s, 0, sizeof(*s));
	free(s);
}
