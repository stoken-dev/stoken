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

#include <tomcrypt.h>

#include "stoken-internal.h"

int stc_standalone_init(void)
{
	/* libtomcrypt init for sdtid BatchSignature generation */
	ltc_mp = ltm_desc;
	if (register_hash(&sha1_desc) == -1)
		return ERR_GENERAL;
	return ERR_NONE;
}
