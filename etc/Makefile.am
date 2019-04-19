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

EXTRA_DIST=rush.rc

install-data-local:
	@test -d $(DESTDIR)$(sysconfdir) || \
           ${INSTALL} -d $(DESTDIR)$(sysconfdir); \
	conf=$(DESTDIR)$(sysconfdir)/rush.rc; \
	if [ -r $$conf ]; then \
		echo $$conf | sed 's,.,=,g'; \
		echo "The configuration file $$conf already exists"; \
		echo "Make sure it is up to date!"; \
		echo $$conf | sed 's,.,=,g'; \
        else \
		for file in $(EXTRA_DIST); do \
			${INSTALL} -m 640 $(top_srcdir)/etc/$$file \
			  $(DESTDIR)$(sysconfdir)/$$file; \
		done; \
	fi
