dnl Process this file with autoconf to create configure.

AC_INIT([libnetfilter_queue], [1.0.5])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
	tar-pax no-dist-gzip dist-bzip2 1.6])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
CHECK_GCC_FVISIBILITY

case "$host" in
*-*-linux* | *-*-uclinux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

dnl Dependencies
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 0.0.41])
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])

dnl Output the makefiles
AC_CONFIG_FILES([Makefile src/Makefile
        libnetfilter_queue.pc
	include/Makefile include/libnetfilter_queue/Makefile
	include/linux/Makefile include/linux/netfilter/Makefile])

AC_ARG_WITH([doxygen], [AS_HELP_STRING([--with-doxygen],
	    [create doxygen documentation [default=no]])],
	    [], [with_doxygen=no])
AS_IF([test "x$with_doxygen" = xyes], [
	AC_CHECK_PROGS([DOXYGEN], [doxygen])
])

AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AC_OUTPUT

echo "
libnetfilter_queue configuration:
  doxygen:                      ${with_doxygen}"
