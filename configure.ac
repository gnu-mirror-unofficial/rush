# This file is part of Rush.                  -*- Autoconf -*-
# Copyright (C) 2008 Sergey Poznyakoff
#
# Rush is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Rush is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Rush.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.61)
AC_INIT([rush], [1.2.90], [bug-rush@gnu.org.ua])
AC_CONFIG_SRCDIR([src/rush.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.9 gnits tar-ustar std-options])

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_PROG_INSTALL
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T

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

# Doc hints.
# Select a rendition level:
#  DISTRIB for stable releases (at most one dot in the version number)
#  and maintenance releases (two dots, patchlevel < 50)
#  PROOF for alpha releases.
#  PUBLISH can only be required manually when running make in doc/
AC_SUBST(RENDITION)
case `echo $VERSION|sed  's/[[^.]]//g'` in
""|".")  RENDITION=DISTRIB;;
"..")  if test `echo $VERSION | sed  's/.*\.//'` -lt 50; then
	 RENDITION=DISTRIB
       else
         RENDITION=PROOF
       fi;;
*)     RENDITION=PROOF;;
esac


AC_CONFIG_FILES([confpaths.h:confpaths.h.in
		 Makefile
                 gnu/Makefile
		 lib/Makefile
		 src/Makefile
		 etc/Makefile
		 doc/Makefile])
AC_OUTPUT
