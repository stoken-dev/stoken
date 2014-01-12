/*
 * LibStoken.java - Java wrapper for libstoken.so
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

package org.stoken;

public class LibStoken {

	/* constants */

	public static final int SUCCESS = 0;
	public static final int INVALID_FORMAT = -1;
	public static final int IO_ERROR = -2;
	public static final int FILE_NOT_FOUND = -3;

	/* create/destroy library instances */

	public LibStoken() {
		libctx = init();
	}

	public synchronized void destroy() {
		if (libctx != 0) {
			free();
			libctx = 0;
		}
	}

	/* public APIs */

	public synchronized native int importRCFile(String path);
	public synchronized native int importString(String str);
	public synchronized native int getMinPIN();
	public synchronized native int getMaxPIN();
	public synchronized native boolean isPINRequired();
	public synchronized native boolean isPassRequired();
	public synchronized native boolean isDevIDRequired();
	public synchronized native boolean checkPIN(String PIN);
	public synchronized native boolean checkDevID(String DevID);
	public synchronized native int decryptSeed(String pass, String devID);
	public synchronized native String encryptSeed(String pass, String devID);
	public synchronized native String computeTokencode(long when, String PIN);

	/* LibStoken internals */

	long libctx;
	synchronized native long init();
	synchronized native void free();
}
