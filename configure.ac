AC_INIT([pam-gnupg], [0.1])
AC_CONFIG_SRCDIR([src/pam_gnupg.c])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_DISABLE_STATIC

AC_PROG_CC

AM_PROG_AR
LT_INIT

AC_CHECK_HEADERS([security/pam_modules.h], [have_pamheader="yes"])
if test x"$have_pamheader" != x"yes"; then
   AC_MSG_ERROR([You are missing PAM headers])
fi

AC_CHECK_PROGS([GPGCONF], [gpgconf], [:])
if test x"$GPGCONF" = x:; then
    AC_MSG_ERROR([gpgconf not found])
fi

AC_PATH_PROG(GPG_CONNECT_AGENT, [gpg-connect-agent], [:],
             [$("$GPGCONF" --list-dirs bindir)])
if test x"$GPG_CONNECT_AGENT" = x:; then
    AC_MSG_ERROR([gpg-connect-agent not found])
fi
AC_DEFINE_UNQUOTED([GPG_CONNECT_AGENT], "$GPG_CONNECT_AGENT",
                   [path to gpg-connect-agent])

AC_PATH_PROG(GPG_PRESET_PASSPHRASE, [gpg-preset-passphrase], [:],
             [$("$GPGCONF" --list-dirs libexecdir)])
if test x"$GPG_PRESET_PASSPHRASE" = x:; then
    AC_MSG_ERROR([gpg-preset-passphrase not found])
fi
AC_DEFINE_UNQUOTED([GPG_PRESET_PASSPHRASE], "$GPG_PRESET_PASSPHRASE",
                   [path to gpg-preset-passphrase])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT