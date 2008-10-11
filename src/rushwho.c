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


const char help_msg[] = "\
rushlast - show listing of last Rush users.\n\
Usage: rushlast [OPTIONS] [user [user...]]\n\
\n\
OPTIONS are:\n\
       -F, --format=STRING       Use STRING instead of the default format.\n\
       -f, --file=DIR            Look for database files in DIR.\n\
       -H, --no-header           Do not display header line.\n\
\n\
       -v, --version             Display program version.\n\
       -h, --help                Display this help message.\n\
       --usage                   Display a concise usage summary.\n";

void
help()
{
        fputs(help_msg, stdout);
	printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
}

const char user_msg[] = "\
rushwho [-F FORMAT] [-f DBDIR] [-Hh] [-v]\n\
        [--file DBDIR] [--format FORMAT] [--help] [--no-header] [--usage]\n\
        [--version]\n";

void
usage()
{
	fputs(user_msg, stdout);
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
	char *base_name = RUSH_DB;
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

		default:
			exit(1);
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

	switch (rushdb_open(base_name, 0)) {
	case rushdb_result_ok:
		break;

	case rushdb_result_eof:
		exit(0);

	case rushdb_result_fail:
                fprintf(stderr, "%s: cannot open database file %s: %s\n",
			progname, base_name, strerror(errno));
		exit(1);
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
