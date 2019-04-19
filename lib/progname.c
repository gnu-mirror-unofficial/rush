/* This file is part of Rush.                  
   Copyright (C) 2009-2019 Sergey Poznyakoff

   Rush is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   Rush is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Rush.  If not, see <http://www.gnu.org/licenses/>. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <librush.h>

const char *program_name = NULL;

void
rush_set_program_name (const char *argv0)
{
	const char *slash;
	const char *base;

	slash = strrchr(argv0, '/');
	base = (slash != NULL ? slash + 1 : argv0);
	if (base - argv0 >= 7 && strncmp (base - 7, "/.libs/", 7) == 0
	    && strncmp (base, "lt-", 3) == 0)
		base += 3;
	program_name = base;
}
