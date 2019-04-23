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
# along with GNU Rush.  If not, see <http://www.gnu.org/licenses/>.

SUBDIRS=imprimatur

info_TEXINFOS=rush.texi
rush_TEXINFOS=\
 fdl.texi\
 strftime.texi

EXTRA_DIST = \
 gendocs_template

dist_man_MANS=\
 rush.8\
 rushlast.1\
 rushwho.1\
 rush-po.1\
 rush.rc.5

clean-local:
	rm -rf manual

AM_MAKEINFOFLAGS=@IMPRIMATUR_MAKEINFOFLAGS@
imprimatur_INPUT=$(info_TEXINFOS) $(rush_TEXINFOS)
include imprimatur/imprimatur.mk
CHECK_DOCS=$(top_srcdir)/@IMPRIMATUR_MODULE_DIR@/check-docs.sh

# Checking
check-format: imprimatur-format imprimatur-check-sentence-spacing
check-refs: imprimatur-refs
check-fixmes: imprimatur-fixmes
check-writeme: imprimatur-writemes
check-unrevised: imprimatur-unrevised
all-check-docs: imprimatur-basic-checks

check-docs:
	$(MAKE) -k all-check-docs

GENDOCS=$(srcdir)/gendocs.sh --no-copy-images --html '--init-file=$(abs_srcdir)/html.init'
EXTRA_DIST += gendocs.sh

TEXI2DVI=texi2dvi -t '@set $(RENDITION)' -I $(top_srcdir)/doc/imprimatur

# Make sure you set TEXINPUTS.
# TEXINPUTS=/usr/share/texmf/pdftex/plain/misc/ is ok for most distributions
.PHONY: manual
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/build-aux:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI) -t @finalout" \
	 $(GENDOCS) $(PACKAGE) '$(PACKAGE_NAME) manual'

manual.tar.bz2: manual
	tar cfj manual.tar.bz2 manual

man-tar: manual.tar.bz2
