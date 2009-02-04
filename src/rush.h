/* This file is part of GNU Rush.                  
   Copyright (C) 2008, 2009 Sergey Poznyakoff

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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <xalloc.h>
#include <regex.h>
#include <c-ctype.h>
#include <argcv.h>
#include <inttostr.h>
#include "argmatch.h"

#include <defines.h>
#include <librush.h>

#ifndef SYSCONFDIR
# define SYSCONFDIR "/usr/local/etc"
#endif
#define CONFIG_FILE SYSCONFDIR "/rush.rc"
#ifndef CANONICAL_PROGRAM_NAME
# define CANONICAL_PROGRAM_NAME "/usr/local/sbin/rush"
#endif

#define RUSH_DB LOCALSTATEDIR "/rush"

#if defined HAVE_SYSCONF && defined _SC_OPEN_MAX
# define getmaxfd() sysconf(_SC_OPEN_MAX)
#elif defined (HAVE_GETDTABLESIZE)
# define getmaxfd() getdtablesize()
#else
# define getmaxfd() 256
#endif

#define ISWS(c) ((c) == ' ' || (c) == '\t')

enum error_type {
	usage_error,
	nologin_error,
	config_error,
	system_error
};

typedef struct limits_rec *limits_record_t;
typedef struct transform *transform_t;

struct rush_map {
	char *file;
	char *delim;
	char *key;
	unsigned key_field;
	unsigned val_field;
	char *defval;
};
	
enum transform_node_type {
	transform_cmdline,
	transform_arg,
	transform_map,
	transform_delarg,
	transform_setcmd,
	transform_setarg
};

struct transform_node {
	struct transform_node *next;
	enum transform_node_type type;
	int arg_no;
	int progmod;
	char *pattern;
	union {
		transform_t trans;
		struct rush_map map;
		int arg_end;
	} v;
};

/* Comparison operator */
enum cmp_op {
	cmp_eq,
	cmp_ne,
	cmp_lt,
	cmp_le,
	cmp_gt,
	cmp_ge
};

enum test_type {
	test_cmdline,
	test_arg,
	test_argc,
	test_uid,
	test_gid,
	test_user,
	test_group
};

struct test_numeric_node {
	enum cmp_op op;
	unsigned long val; /* FIXME: Should be uintmax_t? */
};

struct test_arg_node {
	int arg_no;
	regex_t regex;
};

struct test_node {
	struct test_node *next;
	enum test_type type;
	int negate;
	union {
		regex_t regex;
		struct test_arg_node arg;
		struct test_numeric_node num;
		char **strv;
	} v;
};

struct rush_sockaddr {
	socklen_t len;
	struct sockaddr *sa;
};

enum rush_three_state { rush_undefined = -1, rush_false, rush_true };

struct rush_i18n {
	char *text_domain;           /* Gettext domain, if any */
	char *localedir;             /* Locale directory, if any */
	char *locale;
};	

struct rush_rule {
	struct rush_rule *next;      /* Next config in the list */

	char *tag;
	int fall_through;
	
	/* Source location */
	const char *file;                 /* Configuration file name */
	size_t line;                      /* and line number. */
	
	/* Match parameters */
	struct test_node *test_head, *test_tail;
	
	/* Transformation parameters: */
	struct transform_node *transform_head, *transform_tail;

	/* Environment modification: */
	char **env;

	/* If not NULL, print this message on ERROR_FD and exit */
	char *error_msg;
	int error_fd;

	struct rush_i18n i18n;
	
	mode_t mask;                 /* umask */
	char *chroot_dir;            /* chroot directory */ 
	char *home_dir;              /* home directory */
	limits_record_t limits;      /* resource limits */

	enum rush_three_state fork;  /* Fork a subprocess */
	enum rush_three_state acct;  /* Run accounting */

	struct rush_sockaddr post_sockaddr;
};

struct rush_request {
        char *cmdline;         /* Command line */
        int argc;              /* Number of elements in argv */
        char **argv;           /* Command line in parsed form */
	char *prog;            /* Program file name, if different
				  from argv[0] */
        struct passwd *pw;     /* User passwd entry */
	unsigned umask;        
	char *chroot_dir;      
        char *home_dir;
	enum rush_three_state fork;
	enum rush_three_state acct;
	const struct rush_sockaddr *post_sockaddr;
	struct rush_i18n i18n;
};

#define PROGFILE(req) ((req)->prog ? (req)->prog : (req)->argv[0])
#define NO_UMASK ((mode_t)-1)

extern char *rush_config_file;
extern int lint_option;
extern unsigned sleep_time;
extern struct rush_rule *rule_head, *rule_tail;
extern unsigned debug_level;
extern int debug_option;
extern struct passwd *rush_pw;
extern char *rush_interactive_shell;

#define __debug_p(x) ((x) <= debug_level)

#define debug(lev,msg)					\
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, "%s", msg);	\
	} while(0)	
#define debug1(lev,fmt,x1)				\
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1);	\
	} while(0)
#define debug2(lev,fmt,x1,x2)				\
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1, x2);	\
	} while(0)
#define debug3(lev,fmt,x1,x2,x3)		        \
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1, x2,	\
			       x3);			\
	} while(0)
#define debug4(lev,fmt,x1,x2,x3,x4)		        \
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4);			\
	} while(0)
#define debug5(lev,fmt,x1,x2,x3,x4,x5)		        \
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4, x5);		\
	} while(0)
#define debug6(lev,fmt,x1,x2,x3,x4,x5,x6)	        \
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4, x5, x6);		\
	} while(0)
#define debug7(lev,fmt,x1,x2,x3,x4,x5,x6,x7)	        \
	do {						\
		if (__debug_p(lev))			\
			logmsg(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4, x5, x6, x7);	\
	} while(0)

void die(enum error_type type, struct rush_i18n *i18n, const char *fmt, ...)
	 ATTRIBUTE_NORETURN RUSH_PRINTFLIKE(3,4);
void logmsg(int prio, const char *fmt, ...)  RUSH_PRINTFLIKE(2,3);

int parse_limits(limits_record_t *plrec, char *str, char **endp);
int set_user_limits(const char *name, struct limits_rec *lrec);

void parse_config(void);

void set_error_msg(enum error_type type, char *text);
int string_to_error_index(const char *name);

transform_t compile_transform_expr (const char *expr);
char *transform_string (struct transform *tf, const char *input);

int post_socket_send(const struct rush_sockaddr *sockaddr,
		     const struct rush_rule *rule,
		     const struct rush_request *req);

char *make_file_name(const char *dir, const char *name);
char *expand_tilde(const char *dir, const char *home);


/* cfck.c */
#define RUSH_CHK_OWNER      0x0001
#define RUSH_CHK_IWGRP      0x0002
#define RUSH_CHK_IWOTH      0x0004
#define RUSH_CHK_LINK       0x0008
#define RUSH_CHK_DIR_IWGRP  0x0010
#define RUSH_CHK_DIR_IWOTH  0x0020
#define RUSH_CHK_ALL        \
	(RUSH_CHK_OWNER|RUSH_CHK_IWGRP|RUSH_CHK_IWOTH|\
	 RUSH_CHK_LINK|RUSH_CHK_DIR_IWGRP|RUSH_CHK_DIR_IWOTH)
#ifndef RUSH_CHK_DEFAULT
# define RUSH_CHK_DEFAULT RUSH_CHK_ALL
#endif

int check_config_permissions(const char *filename, struct stat *st);
int cfck_keyword(const char *name);


/* map.c */
char *map_string(struct rush_map *map, struct rush_request *req);
char *rush_expand_string(const char *string, struct rush_request *req);


