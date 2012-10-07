AC_PREREQ([2.61])
AC_INIT([stoken], [0.1], [cernekee@gmail.com], [stoken], [http://stoken.sf.net/])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_LIBTOOL

# Upstream's pkg.m4 (since 0.27) offers this now, but define our own
# compatible version in case the local version of pkgconfig isn't new enough.
# https://bugs.freedesktop.org/show_bug.cgi?id=48743
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
	  [AC_ARG_WITH([pkgconfigdir],
		       [AS_HELP_STRING([--with-pkgconfigdir],
		       [install directory for openconnect.pc pkg-config file])],
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
else
	CFLAGS="$CFLAGS -O2"
	LDFLAGS="$LDFLAGS -Wl,--strip-debug"
fi

# extra gcc flags (warnings and such)

if test "x$GCC" = "xyes"; then
	CFLAGS="$CFLAGS -Wall"
fi

AC_MSG_CHECKING([for -Wno-pointer-sign])
saved_CFLAGS="$CFLAGS"
ptrsign=yes
CFLAGS="$CFLAGS -Wno-pointer-sign"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])], [], ptrsign=no)
if test $ptrsign = no; then
	CFLAGS="$saved_CFLAGS"
	AC_MSG_RESULT([no])
else
	AC_MSG_RESULT([yes])
fi

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
	[PKG_CHECK_MODULES([GTK], [gtk+-2.0],
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

# libtomcrypt

tomcrypt_pkg=no

if test "x$PKG_CONFIG" != x; then
	PKG_CHECK_MODULES([TOMCRYPT], libtomcrypt,
			[tomcrypt_pkg=yes], [])
fi

if test $tomcrypt_pkg = no; then
	AC_SUBST(TOMCRYPT_LIBS, [-ltomcrypt])
	AC_SUBST(LIBTOMCRYPT_PC, [])
else
	AC_SUBST(LIBTOMCRYPT_PC, [libtomcrypt])
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

# library version

libhdr=${srcdir}/src/stoken.h
APIMAJOR="`awk '/#define STOKEN_API_VER_MAJOR/ {print $3}' ${libhdr}`"
APIMINOR="`awk '/#define STOKEN_API_VER_MINOR/ {print $3}' ${libhdr}`"
AC_SUBST(APIMAJOR)
AC_SUBST(APIMINOR)

AC_OUTPUT(stoken.pc)
