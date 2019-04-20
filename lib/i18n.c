/* This file is part of GNU Rush.                  
   Copyright (C) 2009-2019 Sergey Poznyakoff

   GNU Rush is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GNU Rush is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Rush.  If not, see <http://www.gnu.org/licenses/>. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <gettext.h>
#include <locale.h>
#include <librush.h>
#include <xalloc.h>

void
rush_i18n_init()
{
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
}

const char *
user_gettext(const char *locale, const char *domain, const char *dir,
	     const char *msg)
{
	if (locale) {
		char *save_locale = setlocale(LC_ALL, NULL);
		if (save_locale && (save_locale = strdup(save_locale))) {
			if (domain && dir)
				bindtextdomain(domain, dir);
			setlocale(LC_ALL, locale);
			msg = dgettext(domain, msg);
			setlocale(LC_ALL, save_locale);
			bindtextdomain(PACKAGE, LOCALEDIR);
			free(save_locale);
		}
	}
	return msg;
}


