/* This file is part of GNU Rush.                  
   Copyright (C) 2008-2019 Sergey Poznyakoff

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

#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <xalloc.h>
#include <error.h>
#include <errno.h>
#include <librush.h>

char *
rush_read_format(const char *name)
{
	struct stat st;
	size_t size;
	char *buf, *p;
	FILE *fp;
	      
	if (stat(name, &st)) 
		error(1, errno, _("cannot stat format file %s"), name);
	else if (!S_ISREG(st.st_mode))
		error(1, 0, _("%s is not a regular file"), name);
	buf = xmalloc(st.st_size + 1);
	fp = fopen(name, "r");
	if (!fp)
		error(1, errno, _("cannot open format file %s"), name);

	size = st.st_size;
	p = buf;
	while (size && fgets(p, size + 1, fp)) {
		size_t len;
		
		if (*p == ';')
			continue;
		len = strlen(p);
		size -= len;
		p += len;
	}
	*p = 0;
	fclose(fp);
	return buf;
}
