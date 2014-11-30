/*
 * sdtid.h - SecurID sdtid/xml internal interfaces
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

#ifndef __STOKEN_SDTID_H__
#define __STOKEN_SDTID_H__

#include "stoken-internal.h"

struct securid_token;
struct sdtid;

STOKEN_EXPORT int sdtid_decode(const char *in, struct securid_token *t);
STOKEN_EXPORT int sdtid_decrypt(struct securid_token *t, const char *pass);
STOKEN_EXPORT int sdtid_issue(const char *filename, const char *pass,
			      const char *devid);
STOKEN_EXPORT int sdtid_export(const char *filename, struct securid_token *t,
			       const char *pass, const char *devid);
STOKEN_EXPORT void sdtid_free(struct sdtid *s);

#endif /* __STOKEN_SDTID_H__ */
