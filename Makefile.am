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

ACLOCAL_AMFLAGS = -I m4 -I doc/imprimatur
SUBDIRS=gnu lib src etc doc po tests

# We never remove files from the configuration directory
distuninstallcheck_listfiles = \
 find $(prefix) -type f -not -path '$(sysconfdir)/*'

.PHONY: ChangeLog
ChangeLog: 
	$(AM_V_GEN)if test -d .git; then                                   \
	  cmd=$(top_srcdir)/build-aux/gitlog-to-changelog;                 \
	  $$cmd --format='%s%n%n%b%n' |                                    \
            sed '/<unknown>$$/d' | fmt -s > cl-t;                          \
	  echo "Local Variables:" >> cl-t;                                 \
	  echo "mode: change-log" >> cl-t;                                 \
	  echo "version-control: never"  >> cl-t;                          \
	  echo "buffer-read-only: t" >> cl-t;                              \
	  echo "End:" >> cl-t;                                             \
	  rm -f ChangeLog;                                                 \
	  mv cl-t ChangeLog;                                               \
	fi
