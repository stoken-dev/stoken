/*
 * LibTest.java - stoken Java test program
 *
 * Copyright 2014 Kevin Cernekee <cernekee@gmail.com>
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
