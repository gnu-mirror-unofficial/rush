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

#include <unistd.h>
#include <stdlib.h>
#include <gettext.h>

#define N_(s) s
#define _(s) gettext(s)

#ifndef RUSH_ARG_UNUSED
# define RUSH_ARG_UNUSED __attribute__ ((__unused__))
#endif

#ifndef RUSH_PRINTFLIKE
# define RUSH_PRINTFLIKE(fmt,narg) __attribute__ ((__format__ (__printf__, fmt, narg)))
#endif

#ifndef RUSH_NORETURN
# define RUSH_NORETURN __attribute__ ((noreturn))
#endif


extern const char *program_name;

void rush_set_program_name(const char *argv0);



struct rush_wtmp {
	size_t reclen;
	pid_t pid;
	struct timeval start;
	struct timeval stop;
	char *user;
	char *rule;
	char *command;
};
#define RUSH_WTMP_DATA_PTR(w) ((char*)&(w)->pid)

#define RUSH_STATUS_AVAIL  0
#define RUSH_STATUS_INUSE  1

#define RUSH_STATUS_MAP_ANY 0
#define RUSH_STATUS_MAP_BIT(stat) (1<<(stat))
#define RUSH_STATUS_MAP_ISSET(map, stat) ((map) & RUSH_STATUS_MAP_BIT(stat))

struct rush_utmp {
	int status;
	off_t offset;
};

#define RUSH_UTMP_NAME "utmp"
#define RUSH_WTMP_NAME "wtmp"

enum rushdb_result {
	rushdb_result_ok,
	rushdb_result_eof,
	rushdb_result_fail
};

extern mode_t rushdb_umask;
extern mode_t rushdb_dir_mode;
extern mode_t rushdb_file_mode;

enum rush_wtmp_dir {
	rush_wtmp_forward,
	rush_wtmp_backward
};

void rush_wtmp_set_dir(enum rush_wtmp_dir dir);
int rush_wtmp_rewind(void);

int rush_wtmp_open(const char *name, int rw);
enum rushdb_result rush_wtmp_read(struct rush_wtmp **pwtmp);
int rush_wtmp_seek(off_t off);
off_t rush_wtmp_append(struct rush_wtmp *wtmp);
int rush_wtmp_close(void);
int rush_wtmp_update(struct timeval *tv);

int rush_utmp_open(const char *name, int rw);
enum rushdb_result rush_utmp_read(int statmap, int *pstatus,
				     struct rush_wtmp **pwtmp);
int rush_utmp_chstatus(int status);
int rush_utmp_write(struct rush_wtmp *wtmp);
int rush_utmp_close();

void rush_utmp_lock_all(int type);
void rush_utmp_unlock_all(void);

enum rushdb_result rushdb_open(const char *base_name, int rw);
int rushdb_close(void);
int rushdb_start(struct rush_wtmp *wtmp);
int rushdb_stop(void);
void rushdb_backward_direction(void);

#define RUSH_LOCK_READ  0
#define RUSH_LOCK_WRITE 1

int rushdb_lock(int fd, size_t size, off_t offset, int whence, int type);
int rushdb_unlock(int fd, size_t size, off_t offset, int whence);


typedef struct slist *slist_t;
#define LIST_APPEND(elt, head, tail)		\
	do {					\
		if (tail)			\
			(tail)->next = elt;	\
		else				\
			head = elt;		\
		tail = elt;			\
	} while(0)

void slist_append(slist_t slist, const char *p, size_t len);
char *slist_reduce(slist_t slist, char **pbuf, size_t *psize);
slist_t slist_create(void);
void slist_free(slist_t slist);
char *slist_alloc(slist_t slist, size_t len);


void version(const char *progname);


typedef struct rushdb_format *rushdb_format_t;
extern char *rushdb_date_format;
extern char *rushdb_error_string;

rushdb_format_t rushdb_compile_format(char *fmt);
int rushdb_print(rushdb_format_t form, struct rush_wtmp *wtmp, int newline);
void rushdb_print_header(rushdb_format_t form);


char *rush_read_format(const char *name);


void rush_i18n_init(void);
const char *user_gettext(const char *locale, const char *domain,
			 const char *dir,
			 const char *msg);

void argcv_free(int argc, char **argv);
char *argcv_string(int argc, char **argv);

int wildmatch(char const *expr, char const *name, size_t len);
