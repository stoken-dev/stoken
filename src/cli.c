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
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "common.h"
#include "stoken.h"
#include "securid.h"
#include "sdtid.h"
#include "stoken-internal.h"

#ifdef _WIN32

static int plat_read_user_input(char *out, int max_len, int hide_chars)
{
	/* TODO: Hide passwords */
	char *p;

	fgets(out, max_len, stdin);
	p = strchr(out, '\n');
	if (p)
		*p = 0;
	return 0;
}

static void terminal_init(void)
{
}

static int fork_and_wait(void)
{
	/* TODO */
	die("Subprocess support is not yet implemented on Windows.\n");
	return -EINVAL;
}

#else /* _WIN32 */

#include <termios.h>
#include <sys/wait.h>

static struct termios oldtio;

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

static int plat_read_user_input(char *out, int max_len, int hide_chars)
{
	char *p;
	int ret = 0;

	stdin_echo(!hide_chars);
	fflush(stdout);
	fflush(stderr);
	if (fgets(out, max_len, stdin) == NULL) {
		*out = 0;
		goto done;
	}
	p = strchr(out, '\n');
	if (p)
		*p = 0;
	ret = strlen(out);

done:
	stdin_echo(1);
	if (hide_chars && isatty(fileno(stdin)))
		puts("");
	return ret;
}

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

static int fork_and_wait(void)
{
	pid_t child = fork();

	if (child < 0)
		die("can't fork\n");
	else if (child == 0)
		return 0;
	else if (child > 0) {
		int rv;
		wait(&rv);
		if (!WIFEXITED(rv) || WEXITSTATUS(rv))
			exit(1);
	}
	return 1;
}

#endif /* _WIN32 */

static int read_user_input(char *out, int max_len, int hide_chars)
{
	static int first = 1;

	if (opt_stdin) {
		if (!first) {
			prompt("\n");
			die("error: --stdin only allows one prompt\n");
		}
		first = 0;
		return plat_read_user_input(out, max_len, hide_chars);
	}

	if (opt_batch) {
		prompt("\n");
		die("error: --batch mode specified but command-line input is requested\n");
	}

	return plat_read_user_input(out, max_len, hide_chars);
}

static void print_token_info_line(const char *key, const char *value)
{
	/* require --seed to show anything sensitive */
	if (strcasestr(key, "seed") && !opt_seed)
		return;
	printf("%-24s: %s\n", key, value);
}

static time_t adjusted_time(struct securid_token *t)
{
	time_t now = time(NULL);
	long new_time;

	if (opt_both && opt_use_time)
		die("error: --use-time and --both are mutually exclusive\n");
	if (opt_next && opt_use_time)
		die("error: --use-time and --next are mutually exclusive\n");
	if (opt_next)
		return now + securid_token_interval(t);

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
	int i;

	if (opt_devid) {
		if (securid_check_devid(t, opt_devid) == ERR_NONE) {
			xstrncpy(devid, opt_devid, BUFLEN);
			return;
		}
		warn("warning: --devid parameter is incorrect\n");
	} else {
		const struct stoken_guid *glist = stoken_get_guid_list();
		for (i = 0; glist[i].tag != NULL; i++) {
			if (securid_check_devid(t, glist[i].guid) == ERR_NONE) {
				prompt("Using class GUID for %s; use --devid to override\n",
				       glist[i].long_name);
				strncpy(devid, glist[i].guid, BUFLEN);
				return;
			}
		}
	}

	prompt("This token is bound to a specific device.\n");
	for (i = 0; ; i++) {
		prompt("Enter device ID from the RSA 'About' screen: ");
		if (read_user_input(devid, BUFLEN, 0) == 0)
			continue;

		if (securid_check_devid(t, devid) == ERR_NONE)
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
			xstrncpy(pass, opt_password, BUFLEN);
			return;
		}
		warn("warning: --password parameter is incorrect\n");
	}

	for (i = 0; ; i++) {
		prompt(prompt_msg);
		if (read_user_input(pass, BUFLEN, 1) == 0)
			continue;

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
		xstrncpy(pass, opt_new_password, BUFLEN);
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
			xstrncpy(pin, opt_pin, BUFLEN);
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
		xstrncpy(t->pin, pin, MAX_PIN + 1);
	}
}

static void print_formatted(const char *buf)
{
	char *formatted;

	formatted = format_token(buf);
	puts(formatted);
	free(formatted);
}

static void display_qr(const char *filename)
{
	const char *programs[] = {
		/*
		 * I'd like to include xdg-open here, but it insists on
		 * opening the file in the background, which races with the
		 * temporary file cleanup.
		 */
		"display",	/* ImageMagick */
		"eog",		/* Eye of GNOME */
		"gwenview",	/* KDE viewer */
		"ristretto",	/* Xfce */
		NULL,
	};
	const char **p, *user;

	if (fork_and_wait() != 0)
		return;

	user = getenv("QR_VIEWER");
	if (user) {
		execlp(user, user, filename, NULL);
		die("unable to execute '%s'\n", user);
	}

	for (p = programs; *p; p++)
		execlp(*p, *p, filename, NULL);

	die("can't find a suitable image viewer; try setting $QR_VIEWER\n");
}

static void __export_qr(const char *filename, const char *token)
{
	if (fork_and_wait() != 0)
		return;
	execlp("qrencode", "qrencode", "-l", "H", "-o", filename,
	       token, NULL);
	die("can't exec qrencode (is it in your PATH?)\n");
}

static void export_qr(const char *filename, const char *token)
{
	char *formatted;

	if (opt_blocks) {
		warn("warning: --blocks is invalid in QR mode; using --android\n");
		opt_android = 1;
		opt_blocks = 0;
	}

	if (!(opt_android || opt_iphone || opt_v3))
		opt_android = 1;

	formatted = format_token(token);

	if (filename)
		__export_qr(filename, formatted);
	else {
		char fname[64];
		int fd;

		snprintf(fname, sizeof(fname), "%s/XXXXXX.png",
			 getenv("TMPDIR") ? : "/tmp");
		fd = mkstemps(fname, 4);
		if (fd < 0)
			die("can't create temp file '%s'\n", fname);
		__export_qr(fname, formatted);
		display_qr(fname);
		unlink(fname);
	}
	free(formatted);
}

int main(int argc, char **argv)
{
	char *cmd = parse_cmdline(argc, argv, NOT_GUI);
	int rc;
	char buf[BUFLEN], buf_next[BUFLEN];
	struct securid_token *t;

	rc = common_init(cmd);
	if (rc != ERR_NONE)
		die("can't initialize: %s\n", stoken_errstr[rc]);

	if (!strcmp(cmd, "issue")) {
		rc = sdtid_issue(opt_template, opt_new_password, opt_new_devid);
		if (rc != ERR_NONE)
			die("issue: error generating sdtid: %s\n",
			    stoken_errstr[rc]);
		return 0;
	}

	t = current_token;
	if (!t)
		die("error: no token present.  Use 'stoken import' to add one.\n");

	terminal_init();

	if (!strcmp(cmd, "tokencode")) {
		int days_left;

		unlock_token(t, 1, NULL);

		days_left = securid_check_exp(t, adjusted_time(t));
		if (days_left < 0 && !opt_force)
			die("error: token has expired; use --force to override\n");

		if (opt_both) {
			opt_next = 0;
			securid_compute_tokencode(t, adjusted_time(t), buf);
			opt_next = 1;
			securid_compute_tokencode(t, adjusted_time(t), buf_next);
			printf("Current tokencode: %s\n   Next tokencode: %s\n", buf, buf_next);
		} else {
			securid_compute_tokencode(t, adjusted_time(t), buf);
			puts(buf);
		}

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
		securid_encode_token(t, pass, opt_new_devid, 2, buf);
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
			t->is_smartphone = opt_iphone || opt_android ||
					   opt_v3 || opt_show_qr || opt_qr;
			securid_encode_token(t, pass, opt_new_devid,
					     opt_v3 ? 3 : 2, buf);

			if (opt_show_qr || opt_qr)
				export_qr(opt_show_qr ? NULL : opt_qr, buf);
			else
				print_formatted(buf);
		} else {
			rc = sdtid_export(opt_template, t, pass, opt_new_devid);
			if (rc != ERR_NONE)
				die("export: error writing sdtid: %s\n",
				    stoken_errstr[rc]);
		}
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
			xstrncpy(pin, opt_new_pin, BUFLEN);
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

		securid_encode_token(t, pass, NULL, 2, buf);
		rc = write_token_and_pin(buf, len ? pin : NULL, pass);
		free(pass);

		if (rc != ERR_NONE)
			die("error: can't set PIN: %s\n", stoken_errstr[rc]);
	} else if (!strcmp(cmd, "setpass")) {
		char pass[BUFLEN];

		unlock_token(t, 0, NULL);
		request_new_pass(pass);
		securid_encode_token(t, pass, NULL, 2, buf);

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
