# This file is part of GNU Rush.
# Copyright (C) 2008, 2009, 2010 Sergey Poznyakoff
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

sbin_PROGRAMS=rush
bin_PROGRAMS=rushlast rushwho
pkgdata_DATA = rush-po.awk

rush_SOURCES=\
 cfck.c\
 config.c\
 defines.h\
 limits.c\
 map.c\
 rush.c\
 rush.h\
 rushopt.h\
 socket.c\
 transform.c

rushlast_SOURCES=rushlast.c rlopt.h
rushwho_SOURCES=rushwho.c rwopt.h
rushlast.c: rlopt.h
rushwho.c: rwopt.h
EXTRA_DIST=rush-po.awk rushopt.opt rlopt.opt rwopt.opt getopt.m4 defconf.sed
INCLUDES=-I$(top_srcdir)/gnu -I$(top_builddir)/gnu -I$(top_srcdir)/lib
LDADD=../lib/librush.a ../gnu/libgnu.a @LTLIBINTL@

sbinPROGRAMS_INSTALL = $(INSTALL_PROGRAM) -m 4755

BUILT_SOURCES = defines.h rushopt.h rwopt.h rlopt.h
CLEANFILES = defines.h
MAINTAINER_CLEANFILES = rushopt.h rwopt.h rlopt.h

defines.h: Makefile
	p=`echo rush | sed 's/$(EXEEXT)$$//'`; \
	f=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'` ; \
	echo "#define CANONICAL_PROGRAM_NAME \"$(sbindir)/$$f\"" | tr -s / > $@-t
	echo "#define SYSCONFDIR \"$(sysconfdir)\"" >> $@-t 
	echo "#define LOCALSTATEDIR \"$(localstatedir)\"" >> $@-t
	if test -n "$(RUSH_DEFAULT_CONFIG)" && \
           test -f "$(RUSH_DEFAULT_CONFIG)"; then \
           echo "#define RUSH_DEFAULT_CONFIG \\" >> $@-t; \
	   sed -f $(srcdir)/defconf.sed "$(RUSH_DEFAULT_CONFIG)" >> $@-t; \
	fi; \
	mv $@-t $@

SUFFIXES=.opt .c .h

.opt.h:
	m4 -s $(srcdir)/getopt.m4 $< | sed '1d' > $@
