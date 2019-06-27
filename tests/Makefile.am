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

EXTRA_DIST = $(TESTSUITE_AT) testsuite package.m4
DISTCLEANFILES       = atconfig $(check_SCRIPTS)
MAINTAINERCLEANFILES = Makefile.in $(TESTSUITE)

## ------------ ##
## package.m4.  ##
## ------------ ##

$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN){                                      \
	  echo '# Signature of the current package.'; \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])'; \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])'; \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])'; \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])'; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$(srcdir)/package.m4

#

## ------------ ##
## Test suite.  ##
## ------------ ##

TESTSUITE_AT = \
  testsuite.at\
  null.at\
  argc.at\
  command.at\
  matcharg.at\
  matchprog.at\
  uid.at\
  user.at\
  in.at\
  gid.at\
  group.at\
  and.at\
  or.at\
  compound.at\
  set.at\
  delete.at\
  transform.at\
  map.at\
  umask.at\
  newgrp.at\
  chdir.at\
  interactive.at\
  fallthrough.at\
  error.at\
  evalenv.at\
  clrenv.at\
  unsetenv.at\
  keepenv.at\
  setenv.at\
  backref.at\
  setvar.at\
  unsetvar.at\
  undef.at\
  regexp.at\
  qstr.at\
  inc00.at\
  inc01.at\
  insert.at\
  remopt.at\
  lex.at\
  legacy/argc.at\
  legacy/backref.at\
  legacy/chdir.at\
  legacy/command.at\
  legacy/delete.at\
  legacy/env.at\
  legacy/error.at\
  legacy/fallthrough.at\
  legacy/interactive.at\
  legacy/gid.at\
  legacy/map.at\
  legacy/match.at\
  legacy/matchprog.at\
  legacy/newgrp.at\
  legacy/set.at\
  legacy/setvar.at\
  legacy/transform.at\
  legacy/uid.at\
  legacy/unsetvar.at\
  legacy/umask.at

TESTSUITE = $(srcdir)/testsuite
M4=m4

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): package.m4 $(TESTSUITE_AT)
	$(AM_V_GEN)$(AUTOTEST) -I $(srcdir) testsuite.at -o $@.tmp
	$(AM_V_at)mv $@.tmp $@

atconfig: $(top_builddir)/config.status 
	cd $(top_builddir) && ./config.status tests/$@

clean-local:
	@test ! -f $(TESTSUITE) || $(SHELL) $(TESTSUITE) --clean

check-local: atconfig atlocal $(TESTSUITE)
	@$(SHELL) $(TESTSUITE)

noinst_PROGRAMS=myid
