AUTOMAKE_OPTIONS	= foreign subdir-objects

AM_CPPFLAGS		= -DDATA_DIR=\"$(datadir)\"
AM_CFLAGS		= $(TOMCRYPT_CFLAGS) -DLTM_DESC \
			  $(LIBXML2_CFLAGS) $(NETTLE_CFLAGS) \
			  $(WFLAGS)

dist_man_MANS		= stoken.1

lib_LTLIBRARIES		= libstoken.la
libstoken_la_SOURCES	= src/library.c src/securid.c src/sdtid.c
libstoken_la_CFLAGS	= $(AM_CFLAGS)
libstoken_la_LDFLAGS	= -version-number @APIMAJOR@:@APIMINOR@
libstoken_la_LDFLAGS	+= -Wl,--version-script,@srcdir@/libstoken.map
libstoken_la_LIBADD	= $(TOMCRYPT_LIBS) $(LIBXML2_LIBS) $(NETTLE_LIBS) $(HOGWEED_LIBS)
libstoken_la_DEPENDENCIES = libstoken.map
include_HEADERS		= src/stoken.h
noinst_HEADERS		= src/common.h src/securid.h src/stoken-internal.h \
			  src/sdtid.h
pkgconfig_DATA		= stoken.pc

if USE_JNI
if JNI_STANDALONE
libstoken_la_SOURCES	+= src/jni.c
libstoken_la_CFLAGS	+= $(JNI_CFLAGS)
else
lib_LTLIBRARIES		+= libstoken-wrapper.la
libstoken_wrapper_la_SOURCES = src/jni.c
libstoken_wrapper_la_CFLAGS = $(AM_CFLAGS) $(JNI_CFLAGS)
libstoken_wrapper_la_LIBADD = libstoken.la
endif
endif

bin_PROGRAMS		= stoken
stoken_SOURCES		= src/cli.c src/common.c
stoken_LDADD		= $(LDADD) $(TOMCRYPT_LIBS) $(NETTLE_LIBS) $(HOGWEED_LIBS) libstoken.la

if ENABLE_GUI
bin_PROGRAMS		+= stoken-gui
stoken_gui_SOURCES	= src/gui.c src/common.c
stoken_gui_CFLAGS	= $(AM_CFLAGS) $(GTK_CFLAGS)
stoken_gui_CPPFLAGS	= $(AM_CPPFLAGS) -DUIDIR=\"$(uidir)\"
stoken_gui_LDADD	= $(LDADD) $(TOMCRYPT_LIBS) $(NETTLE_LIBS) $(HOGWEED_LIBS) libstoken.la $(GTK_LIBS)

dist_man_MANS		+= stoken-gui.1

icondir			= $(datadir)/pixmaps
dist_icon_DATA		= gui/stoken-gui.png

desktopdir		= $(datadir)/applications
dist_desktop_DATA	= gui/stoken-gui.desktop \
			  gui/stoken-gui-small.desktop

uidir			= $(datadir)/stoken
ui_DATA			= gui/tokencode-small.ui \
			  gui/tokencode-detail.ui \
			  gui/password-dialog.ui \
			  gui/pin-dialog.ui

endif

dist_doc_DATA		= examples/libstoken-test.c examples/sdtid-test.pl \
			  README

dist_noinst_SCRIPTS	= autogen.sh

EXTRA_DIST		= .gitignore libstoken.map CHANGES $(ui_DATA) \
			  tests/template.xml tests/sign.cmp

EXTRA_DIST		+= $(shell cd "$(top_srcdir)" && \
			     git ls-tree HEAD -r --name-only -- examples/ java/ 2>/dev/null)

TESTS			= tests/export tests/sign tests/tokencode
TESTS_ENVIRONMENT =	STOKEN=./stoken \
			TESTDIR="$(srcdir)/tests"

if ENABLE_VALGRIND
TESTS_ENVIRONMENT +=	VALGRIND="valgrind --error-exitcode=1"
endif

DISTCLEANFILES		= *~
