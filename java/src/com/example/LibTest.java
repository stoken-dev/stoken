/*
 * LibTest.java - stoken Java test program
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

package com.example;

import java.io.*;
import java.util.*;
import java.text.*;
import org.stoken.LibStoken;

public final class LibTest {

	private static void die(String msg) {
		System.out.println(msg);
		System.exit(1);
	}

	private static void die(String msg, int error) {
		String errors[] = { "SUCCESS", "INVALID_FORMAT", "IO_ERROR", "FILE_NOT_FOUND" };
		error = -error;
		if (error < errors.length) {
			die(msg + ": " + errors[error]);
		} else {
			die(msg + ": unknown error");
		}
	}

	private static String getline(String prompt) {
		System.out.print(prompt);

		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			String line = br.readLine();
			return line;
		} catch (IOException e) {
			die("\nI/O error");
		}
		return "";
	}

	public static void main(String argv[]) {
		System.loadLibrary("stoken-wrapper");
		LibStoken lib = new LibStoken();

		if (argv.length != 1) {
			die("usage: LibTest { <token_string> | <stokenrc_path> }");
		}

		int ret = lib.importRCFile(argv[0]);
		if (ret != LibStoken.SUCCESS) {
			ret = lib.importString(argv[0]);
			if (ret != LibStoken.SUCCESS) {
				die("Can't parse token string", ret);
			}
		}

		String devID = null;
		if (lib.isDevIDRequired()) {
			devID = getline("Enter Device ID: ");
		}
		if (!lib.checkDevID(devID)) {
			die("Device ID does not match token");
		}

		String pass = null;
		if (lib.isPassRequired()) {
			pass = getline("Enter password: ");
		}

		ret = lib.decryptSeed(pass, devID);
		if (ret != LibStoken.SUCCESS) {
			die("Unable to decrypt seed", ret);
		}

		LibStoken.StokenInfo info = lib.getInfo();

		System.out.println("SN: " + info.serial);

		Date d = new Date(info.unixExpDate * 1000);
		System.out.println("Exp: " + new SimpleDateFormat("yyyy-MM-dd").format(d));

		String PIN = null;
		if (lib.isPINRequired()) {
			PIN = getline("Enter PIN: ");
		}
		if (!lib.checkPIN(PIN)) {
			die("Invalid PIN format");
		}

		String tokencode = lib.computeTokencode(0, PIN);
		if (tokencode == null) {
			die("Unable to compute tokencode");
		}
		System.out.println("TOKENCODE: " + tokencode);

		lib.destroy();
	}
}
