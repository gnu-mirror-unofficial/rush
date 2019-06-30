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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
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
#include <inttostr.h>

#include <defines.h>
#include <librush.h>
#include <wordsplit.h>

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

#ifndef LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
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

enum transform_target_type {
	target_readonly,     /* Read-only variable */
	target_command,      /* Command line */
	target_program,      /* Executable program name */
	target_arg,          /* Single command line argument */
	target_var,          /* Variable */
	target_env           /* Environment variable */
};

struct transform_target {
	enum transform_target_type type;
	union {
		char *name;
		struct {
			int idx;
			int ins;
		} arg;
	} v;
};

enum transform_node_type {
	transform_set,
	transform_delete,
	transform_map,
	transform_remopt,
};

struct option_defn {
	char *s_opt;  /* short option name with optional argument designator */
	char *l_opt;    /* optional long option name */
};

struct transform_node {
	struct transform_node *next;
	enum transform_node_type type;
	struct transform_target target;
	union {
		struct {
			char *pattern;
			transform_t trans;
		} xf;
		struct rush_map map;    /* For transform_map */
		int arg_end;            /* For tranform_delete, if target.type
					   is target_arg */
		struct option_defn remopt; /* For transform_remopt */
	} v;
};

enum test_type {
	test_cmpn,
	test_cmps,
	test_in,
	test_group,
	test_and,
	test_or,
	test_not
};

enum cmp_op {
	cmp_eq,
	cmp_ne,
	cmp_lt,
	cmp_le,
	cmp_gt,
	cmp_ge,
	cmp_match,
	cmp_in
};

typedef unsigned long rush_num_t;

struct test_node {
	enum test_type type;
	union {
		struct {
			enum cmp_op op;
			char *larg;
			union {
				char *str;
				char **strv;
				regex_t rx;
				rush_num_t num;
			} rarg;
		} cmp;
		char **groups;
		struct test_node *arg[2];
	} v;
};

struct rush_sockaddr {
	socklen_t len;
	struct sockaddr *sa;
};

enum rush_three_state { rush_undefined = -1, rush_false, rush_true };
typedef enum rush_three_state rush_bool_t;

struct rush_i18n {
	char *text_domain;           /* Gettext domain, if any */
	char *localedir;             /* Locale directory, if any */
	char *locale;
};	

struct rush_error {     /* Rush error object */
	int fd;         /* File descriptor to write to */
	int idx;        /* Index of the standard error message, or -1 for
			   user-defined message */
};

enum envar_type {
	envar_set,   /* Set variable */
	envar_unset, /* Unset variable(s) */
	envar_keep,  /* Preserve variable(s) while clearing the environment */
	envar_eval   /* Evaluate string for side effects. Discard the result */
};

struct envar {
	struct envar *next;
	enum envar_type type;
	char *name;
	char *value;
};

struct rush_rule {
	struct rush_rule *next;      /* Next rule in the list */

	char *tag;
	int fall_through;
	int interactive;
	
	/* Source location */
	const char *file;                 /* Configuration file name */
	int line;                         /* and line number. */
	
	/* Match parameters */
	struct test_node *test_node;
	
	/* Transformation parameters: */
	struct transform_node *transform_head, *transform_tail;

	/* Environment modification: */
	int clrenv;
	struct envar *envar_head, *envar_tail;

	/* If not NULL, print this message on ERROR_FD and exit */
	struct rush_error *error;

	struct rush_i18n i18n;
	
	mode_t mask;                 /* umask */
	char *chroot_dir;            /* chroot directory */ 
	char *home_dir;              /* home directory */
	gid_t gid;                   /* primary group ID */
	limits_record_t limits;      /* resource limits */

	enum rush_three_state fork;  /* Fork a subprocess */
	enum rush_three_state acct;  /* Run accounting */

	struct rush_sockaddr post_sockaddr;
};

struct rush_backref {
	char *subject;
 	regmatch_t *match;
	size_t nmatch;
	size_t maxmatch;
};

struct rush_request {
        char *cmdline;         /* Command line */
        size_t argc;           /* Number of elements in argv */
        char **argv;           /* Command line in parsed form */
	int interactive;       /* Request for interactive shell */
	char *prog;            /* Program file name, if different
				  from argv[0] */
        struct passwd *pw;     /* User passwd entry */
	unsigned umask;        
	char *chroot_dir;      
        char *home_dir;
	gid_t gid;
	enum rush_three_state fork;
	enum rush_three_state acct;
	const struct rush_sockaddr *post_sockaddr;
	struct rush_i18n i18n;

	/* Backreferences
	   The backref field contains backreferences from the recent and
	   penultimate regex matches. The backref_cur field indexes the
	   recent backreferences. Remaining slot is used as a temporary
	   storage during eventual next match. If that match succeeds, the
	   value of backref_cur is updated to reflect the fact. The
	   backref_count field keeps the actual number of backreferences
	   used in the recent match. */
	struct rush_backref backref[2]; 
	int backref_cur;
	size_t backref_count;

	/* Constructed environment */
	char **env;
	size_t env_count;
	size_t env_max;

	/* Temporary variable storage */
	char **var_kv;
	size_t var_count;
	size_t var_max;
};

#define PROGFILE(req) ((req)->prog ? (req)->prog : (req)->argv[0])
#define NO_UMASK ((mode_t)-1)
#define NO_GID ((gid_t)-1)

extern char *rush_config_file;
extern int lint_option;
extern unsigned sleep_time;
extern struct rush_rule *rule_head, *rule_tail;
extern unsigned debug_level;
extern char *dump_option;
extern int debug_option;
extern struct passwd *rush_pw;

#define __debug_p(x) ((x) <= debug_level)

#define debug(lev,fmt,...)					\
	do {							\
		if (__debug_p(lev))				\
			logmsg(LOG_DEBUG, fmt, __VA_ARGS__);	\
	} while(0)	

struct cfloc;

void die(enum error_type type, struct rush_i18n *i18n, const char *fmt, ...)
	 RUSH_NORETURN RUSH_PRINTFLIKE(3,4);
void die_usage(struct cfloc const *loc, char const *fmt, ...)
	 RUSH_NORETURN RUSH_PRINTFLIKE(2,3);
void logmsg(int prio, const char *fmt, ...)  RUSH_PRINTFLIKE(2,3);
void vlogmsg(int prio, const char *fmt, va_list ap);

enum {
	lrec_ok = 0,
	lrec_error = 1,
	lrec_badval = 2
};
limits_record_t limits_record_create(void);
int limits_record_add(limits_record_t lrec, char *str, char **endp);
int parse_limits(limits_record_t *plrec, char *str, char **endp);
int set_user_limits(const char *name, struct limits_rec *lrec);

transform_t compile_transform_expr (const char *expr, int cflags,
				    struct cfloc *loc);
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
char **rush_getvarptr(struct rush_request *req, char const *varname);
void rush_request_delvar(struct rush_request *req, char const *varname);
enum transform_target_type rush_variable_target(char const *varname);
void rush_ws_error (const char *fmt, ...);

/* dump.c */
void dump_request(struct rush_request *req, FILE *fp);

/* rush_error management */
void set_error_msg(enum error_type type, char *text);
int string_to_error_index(const char *name);

struct rush_error *new_standard_error(int fd, int idx);
struct rush_error *new_error(int fd, char const *text, int unescape);
char const *rush_error_msg(struct rush_error const *err,
			   struct rush_i18n const *i18n);


