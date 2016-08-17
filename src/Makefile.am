# This file is part of GNU Rush.
# Copyright (C) 2008-2016 Sergey Poznyakoff
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
AM_CPPFLAGS=-I$(top_srcdir)/gnu -I$(top_builddir)/gnu -I$(top_srcdir)/lib
LDADD=../lib/librush.a ../gnu/libgnu.a @LTLIBINTL@

change-suid-mode:
	@proglist='$(sbin_PROGRAMS)'; \
	for prog in $$proglist; do \
	  prog=$(DESTDIR)$(sbindir)/`echo $$prog | sed '$(transform)'`; \
	  if chown 0:0 $$prog && chmod u+s $$prog; then :; else \
	    echo "Cannot change $$prog to setuid root"; \
	  fi;\
	done

install-exec-hook: change-suid-mode

BUILT_SOURCES = defines.h rushopt.h rwopt.h rlopt.h
CLEANFILES = defines.h
MAINTAINER_CLEANFILES = rushopt.h rwopt.h rlopt.h

defines.h: Makefile
	$(AM_V_GEN)p=`echo rush | sed 's/$(EXEEXT)$$//'`; \
	f=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'` ; \
	echo "#define CANONICAL_PROGRAM_NAME \"$(sbindir)/$$f\"" | tr -s / > $@-t; \
	echo "#define SYSCONFDIR \"$(sysconfdir)\"" >> $@-t; \
	echo "#define LOCALSTATEDIR \"$(localstatedir)\"" >> $@-t; \
	if test -n "$(RUSH_DEFAULT_CONFIG)" && \
           test -f "$(RUSH_DEFAULT_CONFIG)"; then \
           echo "#define RUSH_DEFAULT_CONFIG \\" >> $@-t; \
	   sed -f $(srcdir)/defconf.sed "$(RUSH_DEFAULT_CONFIG)" >> $@-t; \
	fi; \
	mv $@-t $@

SUFFIXES=.opt .c .h

.opt.h:
	$(AM_V_GEN)m4 -s $(srcdir)/getopt.m4 $< | sed '1d' > $@
