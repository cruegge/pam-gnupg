AC_INIT([pam-gnupg], [0.1])
AC_CONFIG_SRCDIR([src/pam_gnupg.c])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_DISABLE_STATIC

AC_PROG_CC
AC_PROG_AWK

AM_PROG_AR
LT_INIT

AC_ARG_WITH([moduledir], AS_HELP_STRING([--with-moduledir=PATH],
            [Path where PAM modules are to be installed [[/lib/security]]]),
            [moduledir="$withval"], [moduledir="/lib/security"])
AC_SUBST(moduledir)

AC_CHECK_HEADERS([security/pam_modules.h], [have_pamheader="yes"])
if test x"$have_pamheader" != x"yes"; then
   AC_MSG_ERROR([You are missing PAM headers])
fi

AC_CHECK_PROGS([GPGCONF], [gpgconf], [:])
if test x"$GPGCONF" = x:; then
    AC_MSG_ERROR([gpgconf not found])
fi

GPG_MIN_VERSION="2.1"
AC_MSG_CHECKING([whether GnuPG version is >= ${GPG_MIN_VERSION}])
GPG=$("$GPGCONF" --list-components | "$AWK" -F: '$1=="gpg" {print $3}')
GPG_VERSION=$("$GPG" --version | "$AWK" 'NR==1 {print $NF}')
AS_VERSION_COMPARE(${GPG_VERSION}, ${GPG_MIN_VERSION}, [gpg_too_old="yes"])
if test x"$gpg_too_old" = xyes; then
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([GnuPG is too old])
else
    AC_MSG_RESULT([yes])
fi

AC_PATH_PROG(GPG_CONNECT_AGENT, [gpg-connect-agent], [:],
             [$("$GPGCONF" --list-dirs bindir)])
if test x"$GPG_CONNECT_AGENT" = x:; then
    AC_MSG_ERROR([gpg-connect-agent not found])
fi
AC_DEFINE_UNQUOTED([GPG_CONNECT_AGENT], "$GPG_CONNECT_AGENT",
                   [path to gpg-connect-agent])

# From https://github.com/gpg/gnupg/blob/4c43fab/agent/agent.h#L54
AC_DEFINE([MAX_PASSPHRASE_LEN], [255],
          [Maximum passphrase length accepted by gpg-agent])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
