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

static GtkWidget *tokencode_text, *progress_bar;

static char tokencode_str[16];
static int last_min = -1;

static gboolean delete_event(GtkWidget *widget, GdkEvent *event,
	gpointer data)
{
	gtk_main_quit();
	return FALSE;
}

static gboolean clipboard_callback(GtkWidget *widget, GdkEvent *event,
	gpointer data)
{
	GdkDisplay *disp = gdk_display_get_default();
	GtkClipboard *clip;

	/* CLIPBOARD - Control-V in most applications */
	clip = gtk_clipboard_get_for_display(disp, GDK_SELECTION_CLIPBOARD);
	gtk_clipboard_set_text(clip, tokencode_str, -1);

	/* PRIMARY - middle-click in xterm */
	clip = gtk_clipboard_get_for_display(disp, GDK_SELECTION_PRIMARY);
	gtk_clipboard_set_text(clip, tokencode_str, -1);

	return FALSE;
}

static gint update_tokencode(gpointer data)
{
	time_t now = time(NULL);
	struct tm *tm;
	int sec, i, j, code_len;
	char str[16];

	tm = gmtime(&now);
	if (tm->tm_min != last_min) {
		last_min = tm->tm_min;
		securid_compute_tokencode(current_token, now, tokencode_str);
	}

	sec = 59 - tm->tm_sec;

	/* inject a space in the middle of the code, e.g. "1234 5678" */
	code_len = strlen(tokencode_str);
	for (i = 0, j = 0; i < code_len; i++) {
		if (i == code_len / 2)
			str[j++] = ' ';
		str[j++] = tokencode_str[i];
	}
	str[j] = 0;

	gtk_label_set_text(GTK_LABEL(tokencode_text), str);

	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar),
		(double)sec / 59);
	sprintf(str, "00:%02d", sec);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(progress_bar), str);

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

static GtkWidget *create_app_window(void)
{
	GtkWidget *window, *vbox, *parent, *widget;
	PangoAttrList *attr;

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_container_set_border_width(GTK_CONTAINER(window), 10);
	gtk_window_set_title(GTK_WINDOW(window), WINDOW_TITLE);

	g_signal_connect(window, "delete-event", G_CALLBACK(delete_event),
			 NULL);

	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);

	/* tokencode frame */
	parent = gtk_frame_new("Tokencode");
	gtk_box_pack_start(GTK_BOX(vbox), parent, FALSE, FALSE, 0);

	widget = gtk_table_new(5, 3, TRUE);
	gtk_container_add(GTK_CONTAINER(parent), widget);
	parent = widget;

	tokencode_text = gtk_label_new(NULL);
	attr = pango_attr_list_new();
	pango_attr_list_insert(attr, pango_attr_scale_new(PANGO_SCALE_XX_LARGE));
	pango_attr_list_insert(attr, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
	gtk_label_set_attributes(GTK_LABEL(tokencode_text), attr);
	pango_attr_list_unref(attr);

	gtk_table_attach_defaults(GTK_TABLE(parent), tokencode_text,
		0, 3, 2, 3);

	/* progress bar */
	progress_bar = gtk_progress_bar_new();
	gtk_box_pack_start(GTK_BOX(vbox), progress_bar, FALSE, FALSE, 0);

	/* hack to turn off progress bar animation seen on some themes */
	gtk_rc_parse_string("style \"default\" { engine \"\" { }\n"
		"bg[PRELIGHT] = \"#4b6785\" }\n"
		"widget_class \"*.<GtkProgressBar>\" style \"default\"");

	widget = gtk_hseparator_new();
	gtk_widget_set_size_request(widget, 200, 50);
	gtk_box_pack_start(GTK_BOX(vbox), widget, FALSE, FALSE, 0);

	/* buttons */
	parent = gtk_vbutton_box_new();
	gtk_box_set_spacing(GTK_BOX(parent), 10);
	gtk_box_pack_start(GTK_BOX(vbox), parent, FALSE, FALSE, 0);

	widget = gtk_button_new_with_label("Copy to clipboard");
	g_signal_connect(widget, "clicked", G_CALLBACK(clipboard_callback),
		NULL);
	gtk_container_add(GTK_CONTAINER(parent), widget);

	widget = gtk_button_new_with_label("Quit");
	g_signal_connect_swapped(widget, "clicked", G_CALLBACK(gtk_main_quit),
				 window);
	gtk_container_add(GTK_CONTAINER(parent), widget);

	return window;
}

static void create_password_dialog(GtkWidget **dialog,
	GtkWidget *pass_entry, GtkWidget *pin_entry)
{
	GtkWidget *table, *widget;
	int row = 0;

	*dialog = gtk_dialog_new_with_buttons(WINDOW_TITLE,
		NULL, 0,
		GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
		GTK_STOCK_QUIT, GTK_RESPONSE_REJECT,
		NULL);
	table = gtk_table_new(!!pin_entry + !!pass_entry, 2, FALSE);
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(*dialog)->vbox), table);

	if (pass_entry) {
		widget = gtk_label_new("Password:");
		gtk_table_attach_defaults(GTK_TABLE(table), widget,
			0, 1, row, row + 1);

		gtk_entry_set_max_length(GTK_ENTRY(pass_entry), MAX_PASS);
		gtk_entry_set_width_chars(GTK_ENTRY(pass_entry), MAX_PASS);
		gtk_entry_set_visibility(GTK_ENTRY(pass_entry), FALSE);

		gtk_table_attach_defaults(GTK_TABLE(table), pass_entry,
			1, 2, row, row + 1);
		row++;
	}

	if (pin_entry) {
		widget = gtk_label_new("PIN:");
		gtk_table_attach_defaults(GTK_TABLE(table), widget,
			0, 1, row, row + 1);

		gtk_entry_set_max_length(GTK_ENTRY(pin_entry), MAX_PIN);
		gtk_entry_set_width_chars(GTK_ENTRY(pin_entry), MAX_PIN);
		gtk_entry_set_visibility(GTK_ENTRY(pin_entry), FALSE);

		gtk_table_attach_defaults(GTK_TABLE(table), pin_entry,
			1, 2, row, row + 1);
		row++;
	}

	gtk_widget_show_all(*dialog);
}

static int do_password_dialog(struct securid_token *t)
{
	GtkWidget *dialog;
	GtkWidget *pass_entry = NULL, *pin_entry = NULL;
	gint resp;
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

	if (securid_pin_required(t)) {
		pin_required = 1;
		if (opt_pin) {
			if (securid_pin_format_ok(opt_pin) == ERR_NONE) {
				strncpy(t->pin, opt_pin, MAX_PIN + 1);
				pin_required = 0;
			} else
				warn("warning: --pin argument is invalid\n");
		} else if (strlen(t->pin) || t->enc_pin_str)
			pin_required = 0;
	}

	if (!pin_required && !pass_required)
		return ERR_NONE;

	if (pass_required)
		pass_entry = gtk_entry_new();
	if (pin_required)
		pin_entry = gtk_entry_new();

	create_password_dialog(&dialog, pass_entry, pin_entry);

	while (1) {
		const char *pass = NULL, *pin = NULL;

		resp = gtk_dialog_run(GTK_DIALOG(dialog));
		if (resp != GTK_RESPONSE_ACCEPT) {
			gtk_widget_destroy(dialog);
			return 1;
		}

		if (pass_required) {
			pass = gtk_entry_get_text(GTK_ENTRY(pass_entry));
			rc = securid_decrypt_seed(current_token, pass, NULL);
			if (rc == ERR_DECRYPT_FAILED) {
				warning_dialog(dialog, "Bad password",
					"Please enter the correct password for this seed.");
				continue;
			} else if (rc != ERR_NONE)
				error_dialog("Token decrypt error",
					stoken_errstr[rc]);
		}

		if (t->enc_pin_str) {
			rc = securid_decrypt_pin(t->enc_pin_str, pass, t->pin);
			if (rc != ERR_NONE)
				error_dialog("PIN decrypt error",
					stoken_errstr[rc]);
		}

		if (pin_required) {
			pin = gtk_entry_get_text(GTK_ENTRY(pin_entry));
			if (securid_pin_format_ok(pin) != ERR_NONE) {
				warning_dialog(dialog, "Bad PIN",
					"Please enter 4-8 digits, or '0000' to skip.");
				continue;
			}
			strncpy(t->pin, pin, MAX_PIN + 1);
		}
		break;
	}
	gtk_widget_destroy(dialog);

	return ERR_NONE;
}

int main(int argc, char **argv)
{
	GtkWidget *window;
	int days_left;
	char *cmd;

	gtk_init(&argc, &argv);
	gtk_window_set_default_icon_from_file(
		DATA_DIR "/pixmaps/stoken-gui.png", NULL);

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
	days_left = securid_check_exp(current_token, time(NULL));
	if (!opt_force) {
		if (days_left < 0)
			error_dialog("Token expired",
				"Please obtain a new token from your administrator.");

		if (days_left < 14) {
			char msg[BUFLEN];

			sprintf(msg, "This token will expire in %d day%s.",
				days_left, days_left == 1 ? "" : "s");
			warning_dialog(NULL, "Expiration warning", msg);
		}
	}

	/* request password + PIN, if missing */
	if (do_password_dialog(current_token) != ERR_NONE)
		return 1;

	window = create_app_window();
	update_tokencode(NULL);
	gtk_widget_show_all(window);

	g_timeout_add(250, update_tokencode, NULL);
	gtk_main();

	return 0;
}
