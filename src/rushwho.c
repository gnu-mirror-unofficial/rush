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

#include <rush.h>
#include "error.h"

char *base_name = RUSH_DB;
struct rush_wtmp *wtmp = NULL;
int  display_header = 1;  /* Display header line */
char *format;

#include "rwopt.h"

void
xalloc_die()
{
	error(1, 0, _("not enough memory"));
	abort();
}


char *default_format =
	"(user 10 Login) "
	"(rule 8 Rule) "
	"(start-time 0 Start) "
	"(duration 10 Time) "
	"(pid 10 PID) "
	"(command 28 Command)"; 

int
main(int argc, char **argv)
{
	int status;
	rushdb_format_t form;
	
	rush_set_program_name(argv[0]);
	rush_i18n_init();

	format = getenv("RUSHWHO_FORMAT");
	if (!format)
		format = default_format;

	get_options(argc, argv);
	argc -= optind;
	argv += optind;

	if (argc) 
		error(1, 0, _("extra arguments"));

	if (format[0] == '@')
		format = rush_read_format(format + 1);
	form = rushdb_compile_format(format);
	if (!form) 
		error(1, 0, _("invalid format: %s"), rushdb_error_string);

	switch (rushdb_open(base_name, 0)) {
	case rushdb_result_ok:
		break;

	case rushdb_result_eof:
		exit(0);

	case rushdb_result_fail:
                error(1, errno, _("cannot open database file %s"), base_name);
	}

	if (display_header)
		rushdb_print_header(form);
	while (rush_utmp_read(RUSH_STATUS_MAP_BIT(RUSH_STATUS_INUSE),
			      &status, &wtmp) == rushdb_result_ok) {
		
		rushdb_print(form, wtmp, 1);
		free(wtmp);
	}

	rushdb_close();
	
	exit(0);
}
