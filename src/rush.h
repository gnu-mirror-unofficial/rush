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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include <xalloc.h>
#include <regex.h>
#include <c-ctype.h>
#include <argcv.h>

#include <defines.h>

#ifndef SYSCONFDIR
# define SYSCONFDIR "/usr/local/etc"
#endif
#define CONFIG_FILE SYSCONFDIR "/rush.rc"
#ifndef CANONICAL_PROGRAM_NAME
# define CANONICAL_PROGRAM_NAME "/usr/local/sbin/rush"
#endif

#define ISWS(c) ((c) == ' ' || (c) == '\t')

enum error_type {
	usage_error,
	nologin_error,
	config_error,
	system_error
};

typedef struct limits_rec *limits_record_t;
typedef struct slist *slist_t;
typedef struct transform *transform_t;

#define LIST_APPEND(elt, head, tail)		\
	do {					\
		if (tail)			\
			(tail)->next = elt;	\
		else				\
			head = elt;		\
		tail = elt;			\
	} while(0)

struct match_arg {
	struct match_arg *next;
	int arg_no;
	regex_t regex;
};
	
struct transform_arg {
	struct transform_arg *next;
	int arg_no;
	transform_t trans;
};

enum cmp_op {
	cmp_eq,
	cmp_ne,
	cmp_lt,
	cmp_le,
	cmp_gt,
	cmp_ge
};

struct command_config {
	struct command_config *next;
	const char *file;
	size_t line;
	regex_t regex;
	transform_t trans;
	struct match_arg *match_head, *match_tail;
	struct transform_arg *arg_head, *arg_tail;
	enum cmp_op cmp_op;
	int argc;
	mode_t mask;
	char *chroot_dir;
	char *home_dir;
	limits_record_t limits;
	uid_t min_uid;
};

extern unsigned sleep_time;
extern char *error_msg[];
extern struct command_config *config_list, *config_tail;
extern unsigned debug_level;

#define __debug_p(x) ((x) <= debug_level)

#define debug(lev,msg)					\
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, "%s", msg);	\
	} while(0)	
#define debug1(lev,fmt,x1)				\
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, fmt, x1);	\
	} while(0)
#define debug2(lev,fmt,x1,x2)				\
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, fmt, x1, x2);	\
	} while(0)
#define debug3(lev,fmt,x1,x2,x3)		        \
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, fmt, x1, x2,	\
			       x3);			\
	} while(0)
#define debug4(lev,fmt,x1,x2,x3,x4)		        \
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4);			\
	} while(0)
#define debug5(lev,fmt,x1,x2,x3,x4,x5)		        \
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4, x5);		\
	} while(0)
#define debug6(lev,fmt,x1,x2,x3,x4,x5)		        \
	do {						\
		if (__debug_p(lev))			\
			syslog(LOG_DEBUG, fmt, x1, x2,	\
			       x3, x4, x5, x6);		\
	} while(0)

void die(enum error_type type, const char *fmt, ...);

int parse_limits(limits_record_t *plrec, char *str, char **endp);
int set_user_limits(const char *name, struct limits_rec *lrec);

void parse_config(void);
void slist_append(slist_t slist, const char *p, size_t len);
char *slist_reduce(slist_t slist, char **pbuf, size_t *psize);
slist_t slist_create(void);
void slist_free(slist_t slist);

transform_t compile_transform_expr (const char *expr);
char *transform_string (struct transform *tf, const char *input);
