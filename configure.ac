AC_PREREQ([2.61])
AC_INIT([stoken], [0.8], [cernekee@gmail.com], [stoken], [http://stoken.sf.net/])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_LIBTOOL
AC_GNU_SOURCE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Upstream's pkg.m4 (since 0.27) offers this now, but define our own
# compatible version in case the local version of pkgconfig isn't new enough.
# https://bugs.freedesktop.org/show_bug.cgi?id=48743
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
	  [AC_ARG_WITH([pkgconfigdir],
		       [AS_HELP_STRING([--with-pkgconfigdir],
		       [install directory for stoken.pc pkg-config file])],
			[],[with_pkgconfigdir='$(libdir)/pkgconfig'])
	   AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

: ${CFLAGS=""}

AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_FILES([Makefile])

# --enable-debug

AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--enable-debug],[enable debugging code and output])],
	[],
	[enable_debug="no"]
)

if test "x$enable_debug" = xyes; then
	CFLAGS="$CFLAGS -O0 -ggdb"
fi

EXTRA_PC_LIBS=""

AS_COMPILER_FLAGS(WFLAGS,
        "-Wall
         -Wextra
         -Wno-missing-field-initializers
         -Wno-sign-compare
         -Wno-pointer-sign
         -Wno-unused-parameter
         -Werror=pointer-to-int-cast
         -Wdeclaration-after-statement
         -Werror-implicit-function-declaration
         -Wformat-nonliteral
         -Wformat-security
         -Winit-self
         -Wno-missing-declarations
         -Wmissing-include-dirs
         -Wnested-externs
         -Wpointer-arith
         -Wwrite-strings")
AC_SUBST(WFLAGS, [$WFLAGS])

# mlockall() is missing on Bionic (Android)
AC_CHECK_FUNCS(mlockall)

# TODO: see if compatibility functions are needed to build on Darwin
AC_CHECK_FUNCS(strcasestr asprintf)

# gtk / stoken-gui

AC_ARG_WITH([gtk], [AS_HELP_STRING([--with-gtk],
	[build stoken-gui for gtk+ @<:@default=check@:>@])],
	[],
	[with_gtk=check])

PKG_PROG_PKG_CONFIG
if test "x$PKG_CONFIG" = x; then
	if test "x$with_gtk" = xyes; then
		AC_MSG_FAILURE([--with-gtk requires pkg-config])
	fi
	with_gtk=no
fi

enable_gui=no
AS_IF([test "x$with_gtk" != xno],
	[PKG_CHECK_MODULES([GTK], [gtk+-3.0],
		[enable_gui=yes],
		[if test "x$with_gtk" != xcheck; then
			AC_MSG_FAILURE(
				[--with-gtk was given, but test for gtk failed])
		 fi
		])
	]
)

if test $enable_gui = yes; then
	AC_MSG_CHECKING([if gtk+ is usable])

	saved_LIBS="$LIBS"
	saved_CFLAGS="$CFLAGS"
	LIBS="$LIBS $GTK_LIBS"
	CFLAGS="$CFLAGS $GTK_CFLAGS"

	AC_TRY_LINK([#include <gtk/gtk.h>], [gtk_init(NULL,NULL);],
		[AC_MSG_RESULT([yes])],
		[AC_MSG_FAILURE([unable to link gtk+ test program])])
	LIBS="$saved_LIBS"
	CFLAGS="$saved_CFLAGS"
fi

AM_CONDITIONAL([ENABLE_GUI], [test $enable_gui = yes])

# libxml2 support for sdtid file parsing

PKG_CHECK_MODULES([LIBXML2], [libxml-2.0])

# libtomcrypt
# Some distributions add a libtomcrypt.pc file, but it isn't in the upstream
# libtomcrypt distribution so we can't count on it.

tomcrypt_pkg=no

if test "x$PKG_CONFIG" != x; then
	PKG_CHECK_EXISTS([libtomcrypt], [tomcrypt_pkg=yes], [])
fi

if test $tomcrypt_pkg = no; then
	AC_SUBST(TOMCRYPT_LIBS, [-ltomcrypt])
	AC_SUBST(LIBTOMCRYPT_PC, [])
	EXTRA_PC_LIBS="$EXTRA_PC_LIBS -ltomcrypt"
else
	AC_SUBST(LIBTOMCRYPT_PC, [libtomcrypt])
	PKG_CHECK_MODULES([TOMCRYPT], libtomcrypt)
fi

saved_LIBS="$LIBS"
saved_CFLAGS="$CFLAGS"
LIBS="$LIBS $TOMCRYPT_LIBS"
CFLAGS="$CFLAGS $TOMCRYPT_CFLAGS"

AC_MSG_CHECKING([if libtomcrypt is usable])
AC_TRY_LINK([#include <tomcrypt.h>],
	[rijndael_ecb_encrypt(NULL,NULL,NULL);],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_FAILURE([unable to link libtomcrypt test program])])

LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"

AC_SUBST(EXTRA_PC_LIBS, [$EXTRA_PC_LIBS])

# JNI

AC_ARG_WITH([java],
	AS_HELP_STRING([--with-java(=DIR)],
		       [Build JNI bindings using jni.h from DIR [default=no]]),
	[], [with_java=no])

if test "$with_java" = "yes"; then
	AX_JNI_INCLUDE_DIR
	for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS; do
		  JNI_CFLAGS="$JNI_CFLAGS -I$JNI_INCLUDE_DIR"
	done
elif test "$with_java" = "no"; then
	JNI_CFLAGS=""
else
	JNI_CFLAGS="-I$with_java"
fi

if test "x$JNI_CFLAGS" != "x"; then
	oldCFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $JNI_CFLAGS"
	AC_MSG_CHECKING([jni.h usability])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <jni.h>],
		[jint foo = 0; (void)foo;])],
		AC_MSG_RESULT([yes]),
		[AC_MSG_RESULT([no])
		 AC_MSG_ERROR([unable to compile JNI test program])])
	CFLAGS="$oldCFLAGS"

	AC_SUBST(JNI_CFLAGS, [$JNI_CFLAGS])
fi

AM_CONDITIONAL(USE_JNI, [test "$JNI_CFLAGS" != ""])

AC_ARG_ENABLE([jni-standalone],
	AS_HELP_STRING([--enable-jni-standalone],
		       [build JNI stubs directly into libstoken.so [default=no]]),
	[jni_standalone=$enableval],
	[jni_standalone=no])
AM_CONDITIONAL(JNI_STANDALONE, [test $jni_standalone = yes])

# library version

libhdr=${srcdir}/src/stoken.h
APIMAJOR="`awk '/#define STOKEN_API_VER_MAJOR/ {print $3}' ${libhdr}`"
APIMINOR="`awk '/#define STOKEN_API_VER_MINOR/ {print $3}' ${libhdr}`"
AC_SUBST(APIMAJOR)
AC_SUBST(APIMINOR)

AC_CONFIG_FILES(stoken.pc)
AC_OUTPUT
