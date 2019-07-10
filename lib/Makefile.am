# This file is part of GNU Rush.
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

noinst_LIBRARIES=librush.a

librush_a_SOURCES=\
 argcv.c\
 i18n.c\
 progname.c\
 readfmt.c\
 rushdb.c\
 slist.c\
 utmp.c\
 version.c\
 wildmatch.c\
 wtmp.c
nodist_librush_a_SOURCES = wordsplit.c

VPATH += $(srcdir)/wordsplit
EXTRA_DIST = \
 wordsplit/wordsplit.c\
 wordsplit/wordsplit.h

noinst_HEADERS=librush.h
AM_CPPFLAGS=\
 -I$(top_srcdir)/gnu\
 -I$(top_builddir)/gnu\
 -I$(srcdir)/wordsplit\
 -DLOCALEDIR=\"$(localedir)\"
