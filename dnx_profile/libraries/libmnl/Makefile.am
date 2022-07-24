include $(top_srcdir)/Make_global.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src include
DIST_SUBDIRS = src include

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmnl.pc

${pkgconfig_DATA}: ${top_builddir}/config.status
