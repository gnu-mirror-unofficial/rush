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
int  display_header = 1;  /* Display header line */
int forward = 0;
char *format;
unsigned long count = 0;
	
#include <rlopt.h>

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
        "(stop-time 0 Stop) "
        "(duration 7 Time) "
        "(command 32 Command)"; 

int
want_record(struct rush_wtmp *wtmp, int argc, char **argv)
{
        int i;
        if (argc == 0)
                return 1;
        for (i = 0; i < argc; i++)
                if (strcmp(argv[i], wtmp->user) == 0)
                        return 1;
        return 0;
}

int
main(int argc, char **argv)
{
        struct rush_wtmp *wtmp = NULL;
        rushdb_format_t form;
        unsigned long i;
        
	rush_set_program_name(argv[0]);
        rush_i18n_init();

        format = getenv("RUSHLAST_FORMAT");
        if (!format)
                format = default_format;

	get_options(argc, argv);
        argc -= optind;
        argv += optind;

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
        if (!forward)
                rushdb_backward_direction();
        i = 0;
        while (rush_wtmp_read(&wtmp) == 0) {
                if (want_record(wtmp, argc, argv)) {
                        rushdb_print(form, wtmp, 1);
                        if (count && ++i == count)
                                break;
                }
                free(wtmp);
        }

        rushdb_close();
        
        exit(0);
}
