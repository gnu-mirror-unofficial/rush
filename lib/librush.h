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

#include <stdlib.h>

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

#define RUSH_UTMP_SUF "ut"
#define RUSH_WTMP_SUF "wt"

extern int rush_wtmp_mode;

int rush_wtmp_open(const char *name, int rw);
int rush_wtmp_read(struct rush_wtmp **pwtmp);
int rush_wtmp_seek(off_t off);
off_t rush_wtmp_append(struct rush_wtmp *wtmp);
int rush_wtmp_close(void);
int rush_wtmp_update(struct timeval *tv);

enum rush_utmp_result {
	rush_utmp_ok,
	rush_utmp_eof,
	rush_utmp_fail
};

int rush_utmp_open(const char *name, int rw);
enum rush_utmp_result rush_utmp_read(int statmap, int *pstatus,
				     struct rush_wtmp **pwtmp);
int rush_utmp_chstatus(int status);
int rush_utmp_write(struct rush_wtmp *wtmp);
int rush_utmp_close();

int rushdb_open(const char *base_name, int rw);
int rushdb_close(void);
int rushdb_start(struct rush_wtmp *wtmp);
int rushdb_stop(void);



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


void version(const char *progname);


typedef struct rushdb_format *rushdb_format_t;
extern char *rushdb_date_format;
extern char *rushdb_error_string;

rushdb_format_t rushdb_compile_format(char *fmt);
int rushdb_print(rushdb_format_t form, struct rush_wtmp *wtmp, int newline);
void rushdb_print_header(rushdb_format_t form);


