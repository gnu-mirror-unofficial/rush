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

#include "wordsplit.h"
#include "librush.h"

/* frees all elements of an argv array and the array itself */
void
argcv_free(int argc, char **argv)
{
	if (argc) {
		while (--argc >= 0)
			free(argv[argc]);
		free(argv);
	}
}

/* Make a argv an make string separated by ' '.  */
char *
argcv_string(int argc, char **argv)
{
	int i;
	slist_t slist;
	char *ret;
	
	slist = slist_create();

	for (i = 0; i < argc; i++) {
		size_t len;
		int quote;
		
		if (i)
			slist_append(slist, " ", 1);
		len = wordsplit_c_quoted_length(argv[i], 0, &quote);
		if (quote)
			slist_append(slist, "\"", 1);
		wordsplit_c_quote_copy(slist_alloc(slist, len), argv[i], 0);
		if (quote)
			slist_append(slist, "\"", 1);
	}

	slist_reduce(slist, &ret, NULL);
	slist_free(slist);

	return ret;
}

