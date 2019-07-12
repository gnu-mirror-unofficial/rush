# This file is part of GNU Rush.                  -*- Autoconf -*-
# Copyright (C) 2008-2019 Sergey Poznyakoff
#
# GNU Rush is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# GNU Rush is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Rush.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.63)
AC_INIT([GNU rush], [2.1], [bug-rush@gnu.org])
AC_CONFIG_SRCDIR([src/rush.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11.1 gnits tar-ustar dist-bzip2 dist-xz std-options])

# Enable silent rules by default:
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_YACC
AC_PROG_LEX

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([stdlib.h string.h socket.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_CHECK_TYPE(socklen_t, , AC_DEFINE(socklen_t, int, [Define to int if <sys/types.h> does not]),
[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SOCKET_H
# include <socket.h>
#endif
])

# Checks for library functions.
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([strdup strerror strrchr strtoul sysconf getdtablesize \
                flock ftruncate])

gl_INIT

# Gettext.
AM_ICONV
AM_GNU_GETTEXT([external], [need-formatstring-macros])
AM_GNU_GETTEXT_VERSION([0.18])

IMPRIMATUR_INIT(doc/imprimatur)

AC_ARG_WITH([default-config],
            AC_HELP_STRING([--with-default-config=FILE],
	                   [read the default configuration from FILE]),
            [dir=`AS_DIRNAME(["$withval"])`
	     if test -d $dir; then
	       dir=`cd $dir; pwd`
	     else
	       AC_MSG_ERROR([No such directory: $dir])
	     fi
	     name=`expr x"$withval" : '.*/\(.*\)'`
	     AC_SUBST(RUSH_DEFAULT_CONFIG, $dir/$name)])

# Initialize the test suite.
AC_CONFIG_TESTDIR(tests)
AC_CONFIG_FILES([tests/Makefile tests/atlocal])
AM_MISSING_PROG([AUTOM4TE], [autom4te])
	     
AC_CONFIG_FILES([Makefile
                 gnu/Makefile
		 lib/Makefile
		 src/Makefile
		 etc/Makefile
		 doc/Makefile
		 po/Makefile.in])
AC_OUTPUT
