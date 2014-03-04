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

#include "common.h"
#include "securid.h"

int securid_decrypt_sdtid(struct securid_token *t, const char *pass)
{
	return ERR_GENERAL;
}

int securid_decode_sdtid(const char *in, struct securid_token *t)
{
	return ERR_GENERAL;
}

void securid_free_sdtid(struct sdtid *s)
{
	if (!s)
		return;
	free(s);
}
