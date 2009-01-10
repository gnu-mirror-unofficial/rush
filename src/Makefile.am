# This file is part of Rush.
# Copyright (C) 2008, 2009 Sergey Poznyakoff
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

sbin_PROGRAMS=rush
bin_PROGRAMS=rushlast rushwho
pkgdata_DATA = rush-po.awk
EXTRA_DIST = rush-po.awk

rush_SOURCES=\
 argcv.c\
 argcv.h\
 config.c\
 defines.h\
 limits.c\
 rush.c\
 rush.h\
 socket.c\
 transform.c

rushlast_SOURCES=rushlast.c
rushwho_SOURCES=rushwho.c

INCLUDES=-I$(top_srcdir)/gnu -I$(top_builddir)/gnu -I$(top_srcdir)/lib
LDADD=../lib/librush.a ../gnu/libgnu.a

sbinPROGRAMS_INSTALL = $(INSTALL_PROGRAM) -m 4755

BUILT_SOURCES = defines.h
CLEANFILES = defines.h

defines.h: Makefile
	p=`echo rush | sed 's/$(EXEEXT)$$//'`; \
	f=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'` ; \
	echo "#define CANONICAL_PROGRAM_NAME \"$(sbindir)/$$f\"" | tr -s / > $@-t
	echo "#define SYSCONFDIR \"$(sysconfdir)\"" >> $@-t 
	echo "#define LOCALSTATEDIR \"$(localstatedir)\"" >> $@-t
	mv $@-t $@

