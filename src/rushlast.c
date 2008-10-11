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

#define USAGE_OPTION   256
#define FORWARD_OPTION 257
struct option longopts[] = {
	{ "file", required_argument, 0, 'f' },
	{ "no-header", no_argument, 0, 'H' },
	{ "format", required_argument, 0, 'F' },
	{ "forward", no_argument, 0, FORWARD_OPTION },
	{ "count", required_argument, 0, 'n' },
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
       --forward                 Show entries in chronological order.\n\
       -H, --no-header           Do not display header line.\n\
       -n, --count=NUM, --NUM    Show at most NUM records.\n\
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
rushlast [-F FORMAT] [-f DBDIR] [-Hh] [-n NUM] [-v]\n\
 	 [--count NUM] [--file DBDIR] [--format FORMAT] [--forward]\n\
         [--help] [--no-header] [--usage] [--version]\n";

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
	int rc;
	char *base_name = RUSH_DB;
	struct rush_wtmp *wtmp = NULL;
	rushdb_format_t form;
	int  display_header = 1;  /* Display header line */
	int forward = 0;
	unsigned long count = 0, i;
	
	progname = strrchr(argv[0], '/');
        if (progname)
                progname++;
        else
                progname = argv[0];
	opterr = 0;
	while ((rc = getopt_long(argc, argv, "F:f:Hn:hv", longopts, NULL))
	       != EOF) {
		char *p;
		
		switch (rc) {
		case 'F':
			format = optarg;
			break;
			
		case 'f':
			base_name = optarg;
			break;

		case FORWARD_OPTION:
			forward = 1;
			break;
			
		case 'H':
			display_header = 0;
			break;

		case 'n':
			count = strtoul(optarg, &p, 10);
			if (*p) {
				fprintf(stderr, "%s: invalid number (%s)\n",
					progname, optarg);
				exit(1);
			}
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
			if (c_isdigit(optopt)) {
				count = strtoul(argv[optind-1] + 1, &p, 10);
				if (*p) {
					fprintf(stderr,
						"%s: invalid number (%s)\n",
						progname, argv[optind-1]);
					exit(1);
				}
				if (optind < argc) 
					continue;
				else
					break;
			}
			fprintf(stderr, "%s: invalid option -- %c\n",
				progname, optopt);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

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