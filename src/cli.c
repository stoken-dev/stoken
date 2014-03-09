/*
 * cli.c - stoken command-line interface
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
 */

#include "config.h"

#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "securid.h"
#include "sdtid.h"
#include "stoken-internal.h"

static void print_token_info_line(const char *key, const char *value)
{
	/* require --seed to show anything sensitive */
	if (strcasestr(key, "seed") && !opt_seed)
		return;
	printf("%-24s: %s\n", key, value);
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
	p = index(out, '\n');
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

static void terminal_init(void)
{
	struct sigaction sa;
	const int fd = 0;

	/* restore a sane terminal state if interrupted */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &restore_tio;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	tcgetattr(fd, &oldtio);
}

static void stdin_echo(int enable_echo)
{
	struct termios tio = oldtio;
	const int fd = 0;

	if (!enable_echo) {
		/* ripped from busybox bb_ask() */
		tcflush(fd, TCIFLUSH);
		tio.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL);
		tcsetattr(fd, TCSANOW, &tio);
	} else
		tcsetattr(fd, TCSANOW, &oldtio);
}

static int read_user_input(char *out, int max_len, int hide_chars)
{
	static int first = 1;
	int rc;

	if (opt_stdin) {
		if (!first) {
			prompt("\n");
			die("error: --stdin only allows one prompt\n");
		}
		first = 0;
		return raw_read_user_input(out, max_len);
	}

	if (opt_batch) {
		prompt("\n");
		die("error: --batch mode specified but command-line input is requested\n");
	}

	stdin_echo(!hide_chars);
	rc = raw_read_user_input(out, max_len);
	stdin_echo(1);

	if (hide_chars)
		puts("");
	return rc;
}

static time_t adjusted_time(void)
{
	time_t now = time(NULL);
	long new_time;

	if (!opt_use_time)
		return now;
	else if (sscanf(opt_use_time, "+%ld", &new_time) == 1)
		return now + new_time;
	else if (sscanf(opt_use_time, "-%ld", &new_time) == 1)
		return now - new_time;
	else if (sscanf(opt_use_time, "%ld", &new_time) == 1)
		return new_time;

	die("error: invalid --use-time argument\n");
	return 0;
}

static void request_devid(struct securid_token *t, char *devid)
{
	int i, rc;

	if (opt_devid) {
		rc = securid_decrypt_seed(t, "", opt_devid);
		if (rc != ERR_BAD_DEVID) {
			strncpy(devid, opt_devid, BUFLEN);
			return;
		}
		warn("warning: --devid parameter is incorrect\n");
	}

	prompt("This token is bound to a specific device.\n");
	for (i = 0; ; i++) {
		prompt("Enter device ID from the RSA 'About' screen: ");
		read_user_input(devid, BUFLEN, 0);

		rc = securid_decrypt_seed(t, "", devid);
		if (rc != ERR_BAD_DEVID)
			return;
		if (i == 2)
			die("error: invalid device ID\n");

		prompt("Device ID does not match the token.\n");
	}
}

static void request_pass(const char *prompt_msg, struct securid_token *t,
	char *pass, char *devid)
{
	int i, rc;

	if (opt_password) {
		rc = securid_decrypt_seed(t, opt_password, devid);
		if (rc != ERR_DECRYPT_FAILED && rc != ERR_BAD_PASSWORD) {
			strncpy(pass, opt_password, BUFLEN);
			return;
		}
		warn("warning: --password parameter is incorrect\n");
	}

	for (i = 0; ; i++) {
		prompt(prompt_msg);
		read_user_input(pass, BUFLEN, 1);

		rc = securid_decrypt_seed(t, pass, devid);
		if (rc == ERR_DECRYPT_FAILED) {
			if (i == 2)
				die("error: invalid password\n");
			warn("Bad password.\n");
		} else
			break;
	}
}

static void request_new_pass(char *pass)
{
	char confirm_pass[BUFLEN];
	int len;

	if (opt_new_password) {
		len = strlen(opt_new_password);
		if (len > MAX_PASS)
			die("error: new password is too long\n");
		strncpy(pass, opt_new_password, BUFLEN);
	} else {
		prompt("Enter new password: ");
		len = read_user_input(pass, BUFLEN, 1);
		prompt("Confirm new password: ");
		read_user_input(confirm_pass, BUFLEN, 1);

		if (len > MAX_PASS)
			die("error: new password is too long\n");

		if (strcmp(pass, confirm_pass) != 0)
			die("error: passwords do not match\n");
	}
}

static void request_pin(const char *prompt_msg, char *pin)
{
	int i, rc;

	if (opt_pin) {
		rc = securid_pin_format_ok(opt_pin);
		if (rc == ERR_BAD_LEN)
			warn("warning: bad --pin argument length, ignoring\n");
		else if (rc == ERR_GENERAL)
			warn("warning: --pin argument is not numeric, ignoring\n");
		else {
			strncpy(pin, opt_pin, BUFLEN);
			return;
		}
	}

	for (i = 0; ; i++) {
		prompt(prompt_msg);
		read_user_input(pin, BUFLEN, 1);
		rc = securid_pin_format_ok(pin);

		if (rc == ERR_NONE)
			break;
		if (i == 2)
			die("error: invalid PIN\n");

		if (rc == ERR_BAD_LEN)
			warn("PIN must be %d-%d digits.  Use '0000' for no PIN.\n",
				MIN_PIN, MAX_PIN);
		else
			warn("PIN can only contain digits.\n");
	}
}

static void unlock_token(struct securid_token *t, int get_pin, char **ret_pass)
{
	char devid[BUFLEN] = { 0 }, pass[BUFLEN] = { 0 }, pin[BUFLEN];
	int rc;

	if (securid_devid_required(t))
		request_devid(t, devid);

	if (securid_pass_required(t))
		request_pass("Enter password to decrypt token: ",
			     t, pass, devid);

	rc = securid_decrypt_seed(t, pass, devid);
	if (rc != ERR_NONE)
		die("error: can't decrypt token: %s\n", stoken_errstr[rc]);

	if (t->enc_pin_str)
		if (securid_decrypt_pin(t->enc_pin_str, pass, t->pin) !=
		    ERR_NONE)
			warn("warning: can't decrypt PIN\n");

	if (ret_pass && strlen(pass))
		*ret_pass = xstrdup(pass);

	/* always allow --pin to override .stokenrc */
	if (get_pin && securid_pin_required(t) &&
	    (!strlen(t->pin) || opt_pin)) {
		request_pin("Enter PIN:", pin);
		strncpy(t->pin, pin, MAX_PIN + 1);
	}
}

static void print_formatted(const char *buf)
{
	char *formatted;

	formatted = format_token(buf);
	puts(formatted);
	free(formatted);
}

int main(int argc, char **argv)
{
	char *cmd = parse_cmdline(argc, argv, NOT_GUI);
	int rc;
	char buf[BUFLEN];
	struct securid_token *t;

	rc = common_init(cmd);
	if (rc != ERR_NONE)
		die("can't initialize: %s\n", stoken_errstr[rc]);

	t = current_token;
	if (!t)
		die("error: no token present.  Use 'stoken import' to add one.\n");

	terminal_init();

	if (!strcmp(cmd, "tokencode")) {
		int days_left = securid_check_exp(t, adjusted_time());

		if (days_left < 0 && !opt_force)
			die("error: token has expired; use --force to override\n");

		unlock_token(t, 1, NULL);
		securid_compute_tokencode(t, adjusted_time(), buf);
		puts(buf);

		if (days_left < 14 && !opt_force)
			warn("warning: token expires in %d day%s\n", days_left,
				days_left == 1 ? "" : "s");
	} else if (!strcmp(cmd, "import")) {
		char *pass;

		unlock_token(t, 0, &pass);
		if (!opt_keep_password) {
			pass = xmalloc(BUFLEN);
			request_new_pass(pass);
		}

		t->is_smartphone = 0;
		securid_encode_token(t, pass, opt_new_devid, buf);
		rc = write_token_and_pin(buf, NULL, pass);
		if (rc != ERR_NONE)
			die("rcfile: error writing new token: %s\n",
				stoken_errstr[rc]);
	} else if (!strcmp(cmd, "export")) {
		char *pass;

		unlock_token(t, 0, &pass);
		if (opt_new_password)
			pass = opt_new_password;
		else if (!opt_keep_password)
			pass = NULL;

		if (!opt_sdtid) {
			t->is_smartphone = opt_iphone || opt_android;
			securid_encode_token(t, pass, opt_new_devid, buf);
			print_formatted(buf);
		} else {
			rc = sdtid_export(opt_template, t, pass, opt_new_devid);
			if (rc != ERR_NONE)
				die("export: error writing sdtid: %s\n",
				    stoken_errstr[rc]);
		}
	} else if (!strcmp(cmd, "issue")) {
		rc = sdtid_issue(opt_template, opt_new_password, opt_new_devid);
		if (rc != ERR_NONE)
			die("issue: error generating sdtid: %s\n",
			    stoken_errstr[rc]);
	} else if (!strcmp(cmd, "show")) {
		unlock_token(t, 0, NULL);
		securid_token_info(t, &print_token_info_line);
	} else if (!strcmp(cmd, "setpin")) {
		char *pass = NULL, pin[BUFLEN], confirm_pin[BUFLEN];
		int len;

		if (opt_file || opt_token)
			die("error: setpin only operates on the rcfile token\n");

		unlock_token(t, 0, &pass);

		if (opt_new_pin) {
			if (securid_pin_format_ok(opt_new_pin) != ERR_NONE)
				die("error: invalid --new-pin format\n");
			strncpy(pin, opt_new_pin, BUFLEN);
			len = strlen(pin);
		} else {
			prompt("Enter new PIN: ");
			len = read_user_input(pin, BUFLEN, 1);
			if (len > 0 && securid_pin_format_ok(pin) != ERR_NONE)
				die("error: PIN must be 4-8 digits\n");

			prompt("Confirm new PIN: ");
			read_user_input(confirm_pin, BUFLEN, 1);
			if (strcmp(pin, confirm_pin) != 0)
				die("error: PINs do not match\n");
		}

		securid_encode_token(t, pass, NULL, buf);
		rc = write_token_and_pin(buf, len ? pin : NULL, pass);
		free(pass);

		if (rc != ERR_NONE)
			die("error: can't set PIN: %s\n", stoken_errstr[rc]);
	} else if (!strcmp(cmd, "setpass")) {
		char pass[BUFLEN];

		unlock_token(t, 0, NULL);
		request_new_pass(pass);
		securid_encode_token(t, pass, NULL, buf);

		/* just print to stdout if it didn't come from the rcfile */
		if (opt_file || opt_token)
			print_formatted(buf);
		else {
			rc = write_token_and_pin(buf,
						 strlen(t->pin) ? t->pin : NULL,
						 strlen(pass) ? pass : NULL);
			if (rc != ERR_NONE)
				die("error: can't set password: %s\n",
				    stoken_errstr[rc]);
		}
	} else
		die("error: invalid command '%s'\n", cmd);

	return 0;
}
