/*
 * libstoken-test.c - example program illustrating the use of libstoken
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
 *
 * Build instructions:
 *
 *   CFLAGS=`pkg-config --cflags stoken`
 *   LIBS=`pkg-config --libs stoken`
 *   gcc -c libstoken-test.c -o libstoken-test.o $CFLAGS
 *   gcc libstoken-test.o -o libstoken-test $LIBS
 *
 * Usage:
 *
 *   # generate tokencode from ~/.stokenrc (if present)
 *   ./libstoken-test
 *
 *   # generate tokencode from a different stokenrc file
 *   ./libstoken-test /tmp/stokenrc
 *
 *   # generate tokencode from a token string provided on the command line
 *   ./libstoken-test 252503079680743142131101346153112272336172670304467711744173124152503452716757206
 *
 *   # generate tokencode from an sdtid XML file
 *   ./libstoken-test "`cat foo.sdtid`"
 */

#include <signal.h>
#include <stoken.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define BUFLEN			64

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fflush(stdout);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static int raw_read_user_input(char *out, int max_len)
{
	char *p;

	fflush(stdout);
	fflush(stderr);
	if (fgets(out, max_len, stdin) == NULL) {
		*out = 0;
		return 0;
	}
	p = strchr(out, '\n');
	if (p)
		*p = 0;
	return strlen(out);
}

static struct termios oldtio;
static void stdin_echo(int enable_echo);

static void restore_tio(int sig)
{
	stdin_echo(1);
	puts("");
	exit(1);
}

static void stdin_echo(int enable_echo)
{
	struct termios tio;
	struct sigaction sa;
	const int fd = 0;

	if (!enable_echo) {
		/* ripped from busybox bb_ask() */
		tcgetattr(fd, &oldtio);
		tcflush(fd, TCIFLUSH);
		tio = oldtio;

		tio.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL);
		tcsetattr(fd, TCSANOW, &tio);

		/* restore a sane terminal state if interrupted */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = &restore_tio;
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGHUP, &sa, NULL);
	} else
		tcsetattr(fd, TCSANOW, &oldtio);
}

static void prompt(const char *msg, char *out, int max_len)
{
	int rc;

	printf("%s", msg);

	stdin_echo(0);
	rc = raw_read_user_input(out, max_len);
	stdin_echo(1);
	puts("");

	if (rc == 0)
		die("Aborting...\n");
}

int main(int argc, char **argv)
{
	struct stoken_ctx *ctx = stoken_new();
	char devid[BUFLEN] = { 0 }, pass[BUFLEN] = { 0 }, pin[BUFLEN] = { 0 };
	char out[STOKEN_MAX_TOKENCODE + 1];
	int rc;

	if (argc >= 2) {
		char *s = argv[1];
		if (*s == '1' || *s == '2' || *s == '<') {
			rc = stoken_import_string(ctx, s);
			if (rc)
				die("stoken_import_string returned %d\n", rc);
		} else {
			rc = stoken_import_rcfile(ctx, s);
			if (rc)
				die("stoken_import_rcfile returned %d\n", rc);
		}
	} else {
		rc = stoken_import_rcfile(ctx, NULL);
		if (rc)
			die("stoken_import_rcfile returned %d\n", rc);
	}

	if (stoken_devid_required(ctx))
		prompt("Device ID: ", devid, BUFLEN);
	if (stoken_pass_required(ctx))
		prompt("Password: ", pass, BUFLEN);

	rc = stoken_decrypt_seed(ctx, pass, devid);
	if (rc)
		die("stoken_decrypt_seed returned %d\n", rc);

	if (stoken_pin_required(ctx))
		prompt("PIN: ", pin, BUFLEN);

	rc = stoken_compute_tokencode(ctx, time(NULL), pin, out);
	if (rc)
		die("stoken_compute_tokencode returned %d\n", rc);
	printf("Tokencode: %s\n", out);

	stoken_destroy(ctx);
	return 0;
}
