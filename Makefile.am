AUTOMAKE_OPTIONS	= foreign subdir-objects
ACLOCAL_AMFLAGS		= -I m4

AM_CPPFLAGS		= -DDATA_DIR=\"$(datadir)\"
AM_CFLAGS		= $(CRYPTO_CFLAGS) $(LIBXML2_CFLAGS) $(WFLAGS)

dist_man_MANS		= stoken.1

lib_LTLIBRARIES		= libstoken.la
libstoken_la_SOURCES	= src/library.c src/securid.c src/sdtid.c \
			  src/compat.c src/stc-@CRYPTO_BACKEND@.c
libstoken_la_CFLAGS	= $(AM_CFLAGS) -DLIBSTOKEN_BUILD

libstoken_la_LDFLAGS	= -version-number @APIMAJOR@:@APIMINOR@ \
			  -no-undefined
if HAVE_VSCRIPT_COMPLEX
libstoken_la_LDFLAGS	+= $(VSCRIPT_LDFLAGS),@srcdir@/libstoken.map
endif

libstoken_la_LIBADD	= $(CRYPTO_LIBS) $(LIBXML2_LIBS)
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
stoken_LDADD		= $(LDADD) $(CRYPTO_LIBS) libstoken.la

if ENABLE_GUI
bin_PROGRAMS		+= stoken-gui
stoken_gui_SOURCES	= src/gui.c src/common.c
stoken_gui_CFLAGS	= $(AM_CFLAGS) $(GTK_CFLAGS)
stoken_gui_CPPFLAGS	= $(AM_CPPFLAGS) -DUIDIR=\"$(uidir)\"
stoken_gui_LDADD	= $(LDADD) $(CRYPTO_LIBS) libstoken.la $(GTK_LIBS)

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
			  README.md

dist_noinst_SCRIPTS	= autogen.sh

EXTRA_DIST		= .gitignore libstoken.map CHANGES $(ui_DATA)

# package both variants explicitly, because @CRYPTO_BACKEND@ only picks one
EXTRA_DIST		+= src/stc-nettle.c src/stc-tomcrypt.c

GIT_EXTRA_DIST		= examples/ java/ tests/
EXTRA_DIST		+= $(shell cd "$(top_srcdir)" && \
			     git ls-tree HEAD -r --name-only -- $(GIT_EXTRA_DIST) 2>/dev/null)

TEST_EXTENSIONS		= .pipe
TESTS			= tests/export-android-v2.pipe \
			  tests/export-iphone-password.pipe \
			  tests/export-read-v3.pipe \
			  tests/export-sdtid-devid-password.pipe \
			  tests/export-v3-sdtid.pipe \
			  tests/tokencode-v2.pipe \
			  tests/tokencode-v3.pipe \
			  tests/tokencode-v4.pipe \
			  tests/tokencode-sdtid.pipe \
			  tests/mac-align.pipe

PIPE_LOG_COMPILER	= $(srcdir)/tests/pipe-wrapper.sh
dist_check_SCRIPTS	= $(TESTS) $(PIPE_LOG_COMPILER)

TESTS_ENVIRONMENT 	= STOKEN=./stoken \
			LIBTOOL="${LIBTOOL}" \
			TESTDIR="$(srcdir)/tests"

if ENABLE_VALGRIND
TESTS_ENVIRONMENT +=	VALGRIND="valgrind --error-exitcode=1"
endif

DISTCLEANFILES		= *~

.PHONY: winpkg
winpkg: $(bin_PROGRAMS)
	rm -rf winpkg
	mkdir winpkg
	cp .libs/stoken.exe winpkg/
if ENABLE_GUI
	cp .libs/stoken-gui.exe winpkg/
	cp `./win32deps.pl .libs/stoken-gui.exe` winpkg/
	cp gui/*.{ui,png} winpkg/
else
	cp .libs/stoken.exe winpkg/
	cp `./win32deps.pl .libs/stoken.exe` winpkg/
endif
	rm -f winpkg.zip
	zip -r winpkg.zip winpkg/
