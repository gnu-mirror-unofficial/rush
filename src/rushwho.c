/* This file is part of Rush.                  
   Copyright (C) 2008 Sergey Poznyakoff

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

#include <rush.h>

char *progname;

#define USAGE_OPTION 256
struct option longopts[] = {
	{ "file", required_argument, 0, 'f' },
	{ "no-header", no_argument, 0, 'H' },
	{ "format", required_argument, 0, 'F' }, 
        { "version", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { "usage", no_argument, 0, USAGE_OPTION },
        { NULL }
};


void
help()
{
	/* FIXME */
	abort();
}

void
usage()
{
	/* FIXME */
	abort();
}

void
xalloc_die()
{
	fprintf(stderr, "%s: not enough memory\n", progname);
	abort();
}


char *format =
	"(user 10 Login) "
	"(rule 8 Rule) "
	"(start-time 0 Start) "
	"(stop-time 0 Stop) "
	"(duration 7 Time) "
	"(command 10 Command)"; 

int
main(int argc, char **argv)
{
	int rc;
	char *base_name = RUSH_DB_FILE;
	struct rush_wtmp *wtmp = NULL;
	int status;
	rushdb_format_t form;
	int  display_header = 1;  /* Display header line */
	
	progname = strrchr(argv[0], '/');
        if (progname)
                progname++;
        else
                progname = argv[0];
	while ((rc = getopt_long(argc, argv, "F:f:Hhv", longopts, NULL))
	       != EOF) {
		switch (rc) {
		case 'F':
			format = optarg;
			break;
			
		case 'f':
			base_name = optarg;
			break;

		case 'H':
			display_header = 0;
			break;
			
		case 'v':
			version(progname);
			exit(0);
                                
		case 'h':
			help();
			exit(0);
			
		case USAGE_OPTION:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		fprintf(stderr, "%s: extra arguments\n", progname);
		exit(1);
	}

	form = rushdb_compile_format(format);
	if (!form) {
		fprintf(stderr, "%s: invalid format: %s\n",
			progname, rushdb_error_string);
		exit(1);
	}
	
	if (rushdb_open(base_name, 0)) {
                fprintf(stderr, "%s: cannot open database file %s: %s\n",
			progname, base_name, strerror(errno));
		exit(1);
	}

	if (display_header)
		rushdb_print_header(form);
	while (rush_utmp_read(RUSH_STATUS_MAP_BIT(RUSH_STATUS_INUSE),
			      &status, &wtmp) == rush_utmp_ok) {
		
		rushdb_print(form, wtmp, 1);
		free(wtmp);
	}

	rushdb_close();
	
	exit(0);
}
