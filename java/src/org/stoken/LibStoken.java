/*
 * LibStoken.java - Java wrapper for libstoken.so
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

	public static class StokenInfo {
		public String serial;
		public long unixExpDate;
		public int interval;
		public int tokenVersion;
		public boolean usesPin;
	};

	public static class StokenGUID {
		public String tag;
		public String longName;
		public String GUID;
	}

	/* public APIs */

	public synchronized native int importRCFile(String path);
	public synchronized native int importString(String str);
	public synchronized native StokenInfo getInfo();
	public synchronized native int getMinPIN();
	public synchronized native int getMaxPIN();
	public synchronized native boolean isPINRequired();
	public synchronized native boolean isPassRequired();
	public synchronized native boolean isDevIDRequired();
	public synchronized native boolean checkPIN(String PIN);
	public synchronized native boolean checkDevID(String DevID);
	public synchronized native StokenGUID[] getGUIDList();
	public synchronized native int decryptSeed(String pass, String devID);
	public synchronized native String encryptSeed(String pass, String devID);
	public synchronized native String computeTokencode(long when, String PIN);
	public synchronized native String formatTokencode(String tokencode);

	/* LibStoken internals */

	long libctx;
	synchronized native long init();
	synchronized native void free();
}
