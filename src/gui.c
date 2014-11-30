/*
 * gui.c - stoken gtk+ interface
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gtk/gtk.h>

#include "common.h"
#include "securid.h"

#define WINDOW_TITLE		"Software Token"

#define EXP_WARN_DAYS		14

#ifdef _WIN32
#undef UIDIR
#define UIDIR			"."
#define PIXMAP_DIR		"."
#else
#define PIXMAP_DIR		DATA_DIR "/pixmaps"
#endif

static GtkWidget *tokencode_text, *next_tokencode_text, *progress_bar;

static char tokencode_str[16];
static char next_tokencode_str[16];

static int last_sec = -1;
static int token_sec;
static long time_adjustment;

static int token_days_left;
static int token_interval;
static int token_uses_pin;
static int skipped_pin;

static gboolean delete_callback(GtkWidget *widget, GdkEvent *event,
	gpointer data)
{
	gtk_main_quit();
	return FALSE;
}

static void copy_tokencode(gpointer user_data)
{
	GdkDisplay *disp = gdk_display_get_default();
	GtkClipboard *clip;
	char *str = user_data;

	/* CLIPBOARD - Control-V in most applications */
	clip = gtk_clipboard_get_for_display(disp, GDK_SELECTION_CLIPBOARD);
	gtk_clipboard_set_text(clip, str, -1);

	/* PRIMARY - middle-click in xterm */
	clip = gtk_clipboard_get_for_display(disp, GDK_SELECTION_PRIMARY);
	gtk_clipboard_set_text(clip, str, -1);
}

static void clicked_to_clipboard(GtkButton *button, gpointer user_data)
{
	copy_tokencode(user_data);
}

static gboolean press_to_clipboard(GtkWidget *widget, GdkEvent *event,
	gpointer user_data)
{
	copy_tokencode(user_data);
	return TRUE;
}

static gboolean draw_progress_bar_callback(GtkWidget *widget, cairo_t *cr,
	gpointer data)
{
	guint width, height, boundary;

	width = gtk_widget_get_allocated_width(widget);
	height = gtk_widget_get_allocated_height(widget);

	boundary = width * token_sec / (token_interval - 1);

	cairo_set_source_rgb(cr, 0.3, 0.4, 0.5);
	cairo_rectangle(cr, 0, 0, boundary, height);
	cairo_fill(cr);

	cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
	cairo_rectangle(cr, boundary, 0, width - boundary, height);
	cairo_fill(cr);

	return FALSE;
}

static time_t adjusted_time(void)
{
	return time(NULL) + time_adjustment;
}

static void parse_opt_use_time(void)
{
	long new_time;

	if (!opt_use_time)
		return;
	else if (sscanf(opt_use_time, "+%ld", &new_time) == 1)
		time_adjustment = new_time;
	else if (sscanf(opt_use_time, "-%ld", &new_time) == 1)
		time_adjustment = -new_time;
	else
		die("error: 'stoken-gui --use-time' must specify a +/- offset\n");
}

static gint update_tokencode(gpointer data)
{
	time_t now = adjusted_time();
	struct tm *tm;
	char str[128], *formatted;

	tm = gmtime(&now);
	if ((tm->tm_sec >= 30 && last_sec < 30) ||
	    (tm->tm_sec < 30 && last_sec >= 30) ||
	    last_sec == -1) {
		last_sec = tm->tm_sec;
		securid_compute_tokencode(current_token, now, tokencode_str);
		securid_compute_tokencode(current_token, now + token_interval,
			next_tokencode_str);
	}

	token_sec = token_interval - (tm->tm_sec % token_interval) - 1;
	gtk_widget_queue_draw(GTK_WIDGET(progress_bar));

	formatted = stoken_format_tokencode(tokencode_str);
	if (!formatted)
		die("out of memory\n");

	snprintf(str, sizeof(str),
		"<span size=\"xx-large\" weight=\"bold\">%s</span>",
		formatted);
	gtk_label_set_markup(GTK_LABEL(tokencode_text), str);
	free(formatted);

	if (next_tokencode_text) {
		formatted = stoken_format_tokencode(next_tokencode_str);
		if (!formatted)
			die("out of memory\n");
		gtk_label_set_text(GTK_LABEL(next_tokencode_text), formatted);
		free(formatted);
	}

	return TRUE;
}

static void __error_dialog(GtkWindow *parent, const char *heading,
	const char *msg, int is_warning)
{
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new(parent,
		parent ? GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT : 0,
		is_warning ? GTK_MESSAGE_WARNING : GTK_MESSAGE_ERROR,
		GTK_BUTTONS_OK, "%s", heading);
	gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog),
		"%s", msg);
	gtk_window_set_title(GTK_WINDOW(dialog), WINDOW_TITLE);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
	if (!is_warning)
		exit(1);
}

static void error_dialog(const char *heading, const char *msg)
{
	return __error_dialog(NULL, heading, msg, 0);
}

static void warning_dialog(GtkWidget *parent, const char *heading,
	const char *msg)
{
	return __error_dialog(GTK_WINDOW(parent), heading, msg, 1);
}

static GtkWidget *create_app_window_common(GtkBuilder *builder)
{
	GtkWidget *widget;

	progress_bar = GTK_WIDGET(
		gtk_builder_get_object(builder, "progress_bar"));
	g_signal_connect(progress_bar, "draw",
		G_CALLBACK(draw_progress_bar_callback), NULL);

	tokencode_text = GTK_WIDGET(
		gtk_builder_get_object(builder, "tokencode_text"));

	widget = GTK_WIDGET(gtk_builder_get_object(builder, "app_window"));
	g_signal_connect(widget, "delete-event", G_CALLBACK(delete_callback),
			 NULL);
	return widget;
}

static void set_red_label(GtkWidget *widget, const char *text)
{
	char tmp[BUFLEN];

	snprintf(tmp, BUFLEN,
		 "<span weight=\"bold\" foreground=\"red\">%s</span>", text);
	gtk_label_set_markup(GTK_LABEL(widget), tmp);
}

static void format_exp_date(GtkWidget *widget)
{
	time_t exp = securid_unix_exp_date(current_token);
	char tmp[BUFLEN];

	/* FIXME: localization */
	strftime(tmp, BUFLEN, "%Y-%m-%d", gmtime(&exp));

	if (token_days_left < EXP_WARN_DAYS)
		set_red_label(widget, tmp);
	else
		gtk_label_set_text(GTK_LABEL(widget), tmp);
}

/* gtk_builder_new_from_file() requires libgtk >= 3.10 */
static GtkBuilder *__gtk_builder_new_from_file(const gchar *filename)
{
	GtkBuilder *builder;

	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder, filename, NULL) == 0)
		die("can't import '%s'\n", filename);
	return builder;
}

static GtkWidget *create_app_window(void)
{
	GtkBuilder *builder;
	GtkWidget *widget;

	builder = __gtk_builder_new_from_file(UIDIR "/tokencode-detail.ui");

	/* static token info */
	widget = GTK_WIDGET(gtk_builder_get_object(builder, "token_sn_text"));
	gtk_label_set_text(GTK_LABEL(widget), current_token->serial);

	widget = GTK_WIDGET(gtk_builder_get_object(builder, "exp_date_text"));
	format_exp_date(widget);

	widget = GTK_WIDGET(gtk_builder_get_object(builder, "using_pin_text"));
	if (!token_uses_pin)
		gtk_label_set_text(GTK_LABEL(widget), "Not required");
	else if (skipped_pin)
		set_red_label(widget, "No");
	else
		gtk_label_set_text(GTK_LABEL(widget), "Yes");

	/* buttons */

	widget = GTK_WIDGET(gtk_builder_get_object(builder, "copy_button"));
	g_signal_connect(widget, "clicked", G_CALLBACK(clicked_to_clipboard),
		&tokencode_str);

	/* next tokencode */

	next_tokencode_text = GTK_WIDGET(
		gtk_builder_get_object(builder, "next_tokencode_text"));

	widget = GTK_WIDGET(gtk_builder_get_object(builder,
		"next_tokencode_eventbox"));
	g_signal_connect(widget, "button-press-event",
		G_CALLBACK(press_to_clipboard), &next_tokencode_str);

	return create_app_window_common(builder);
}

static GtkWidget *create_small_app_window(void)
{
	GtkBuilder *builder;
	GtkWidget *widget;

	builder = __gtk_builder_new_from_file(UIDIR "/tokencode-small.ui");

	widget = GTK_WIDGET(gtk_builder_get_object(builder, "event_box"));
	g_signal_connect(widget, "button-press-event",
		G_CALLBACK(press_to_clipboard), &tokencode_str);

	return create_app_window_common(builder);
}

static char *do_password_dialog(const char *ui_file)
{
	GtkBuilder *builder;
	GtkWidget *widget, *dialog;
	gint resp;
	char *ret = NULL;

	builder = __gtk_builder_new_from_file(ui_file);
	dialog = GTK_WIDGET(gtk_builder_get_object(builder, "dialog_window"));
	gtk_widget_show_all(dialog);
	resp = gtk_dialog_run(GTK_DIALOG(dialog));

	if (resp == GTK_RESPONSE_OK) {
		widget = GTK_WIDGET(gtk_builder_get_object(builder, "password"));
		ret = strdup(gtk_entry_get_text(GTK_ENTRY(widget)));
	}

	gtk_widget_destroy(dialog);
	return ret;
}

static int request_credentials(struct securid_token *t)
{
	int rc, pass_required = 0, pin_required = 0;

	if (securid_pass_required(t)) {
		pass_required = 1;
		if (opt_password) {
			rc = securid_decrypt_seed(t, opt_password, NULL);
			if (rc == ERR_DECRYPT_FAILED)
				warn("warning: --password parameter is incorrect\n");
			else if (rc != ERR_NONE)
				error_dialog("Token decrypt error",
					stoken_errstr[rc]);
			else
				pass_required = 0;
		}
	} else {
		rc = securid_decrypt_seed(t, opt_password, NULL);
		if (rc != ERR_NONE)
			error_dialog("Token decrypt error", stoken_errstr[rc]);
	}

	while (pass_required) {
		const char *pass =
			do_password_dialog(UIDIR "/password-dialog.ui");
		if (!pass)
			return ERR_MISSING_PASSWORD;
		rc = securid_decrypt_seed(t, pass, NULL);
		if (rc == ERR_NONE) {
			if (t->enc_pin_str) {
				rc = securid_decrypt_pin(t->enc_pin_str,
							 pass, t->pin);
				if (rc != ERR_NONE)
					error_dialog("PIN decrypt error",
						     stoken_errstr[rc]);
			}

			pass_required = 0;
		} else if (rc == ERR_DECRYPT_FAILED)
			warning_dialog(NULL, "Bad password",
				"Please enter the correct password for this seed.");
		else
			error_dialog("Token decrypt error", stoken_errstr[rc]);
	}

	if (securid_pin_required(t)) {
		pin_required = 1;
		if (opt_pin) {
			if (securid_pin_format_ok(opt_pin) == ERR_NONE) {
				xstrncpy(t->pin, opt_pin, MAX_PIN + 1);
				pin_required = 0;
			} else
				warn("warning: --pin argument is invalid\n");
		} else if (strlen(t->pin) || t->enc_pin_str)
			pin_required = 0;
	}

	while (pin_required) {
		const char *pin =
			do_password_dialog(UIDIR "/pin-dialog.ui");
		if (!pin) {
			skipped_pin = 1;
			xstrncpy(t->pin, "0000", MAX_PIN + 1);
			break;
		}
		if (securid_pin_format_ok(pin) != ERR_NONE) {
			warning_dialog(NULL, "Bad PIN",
				"Please enter 4-8 digits, or click Skip for no PIN.");
		} else {
			xstrncpy(t->pin, pin, MAX_PIN + 1);
			break;
		}
	}

	return ERR_NONE;
}

int main(int argc, char **argv)
{
	GtkWidget *window;
	char *cmd;

	gtk_init(&argc, &argv);
	gtk_window_set_default_icon_from_file(
		PIXMAP_DIR "/stoken-gui.png", NULL);

	cmd = parse_cmdline(argc, argv, IS_GUI);

	/* check for a couple of error conditions */

	if (common_init(cmd))
		error_dialog("Application error",
			"Unable to initialize crypto library.");

	if (!current_token)
		error_dialog("Missing token",
			"Please use 'stoken import' to add a new seed.");

	if (securid_devid_required(current_token))
		error_dialog("Unsupported token",
			"Please use 'stoken' to handle tokens encrypted with a device ID.");

	/* check for token expiration */
	parse_opt_use_time();
	token_days_left = securid_check_exp(current_token, adjusted_time());

	if (!opt_force && !opt_small) {
		if (token_days_left < 0)
			error_dialog("Token expired",
				"Please obtain a new token from your administrator.");

		if (token_days_left < EXP_WARN_DAYS) {
			char msg[BUFLEN];

			sprintf(msg, "This token will expire in %d day%s.",
				token_days_left,
				token_days_left == 1 ? "" : "s");
			warning_dialog(NULL, "Expiration warning", msg);
		}
	}

	/* request password / PIN, if missing */
	if (request_credentials(current_token) != ERR_NONE)
		return 1;

	token_interval = securid_token_interval(current_token);
	token_uses_pin = securid_pin_required(current_token);

	window = opt_small ? create_small_app_window() : create_app_window();

	update_tokencode(NULL);
	gtk_widget_show_all(window);

	g_timeout_add(250, update_tokencode, NULL);
	gtk_main();

	return 0;
}
