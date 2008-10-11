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

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "librush.h"

static int wtmp_fd = -1;
static size_t wtmp_recsize = 0;
int rush_wtmp_mode = 0660;

int
rush_wtmp_open(const char *name, int rw)
{
	int fd;
	
	fd = open(name, rw ? O_RDWR|O_CREAT : O_RDONLY, rush_wtmp_mode);
	if (fd == -1)
		return -1;
	wtmp_fd = fd;
	return 0;
}

int
rush_wtmp_close()
{
	int rc = close(wtmp_fd);
	wtmp_fd = -1;
	return rc;
}

int
rush_wtmp_seek(off_t off)
{
	off_t rc = lseek(wtmp_fd, off, SEEK_SET);
	if (rc == off) {
		wtmp_recsize = 0;
		return 0;
	} 
	return 1;
}

struct rush_wtmp *
alloc_wtmp(size_t reclen)
{
	struct rush_wtmp *wtmp = malloc(sizeof(*wtmp) + reclen
					- sizeof(size_t));
	if (wtmp) 
		wtmp->reclen = reclen;
	return wtmp;
}

int
rush_wtmp_read(struct rush_wtmp **pwtmp)
{
	struct rush_wtmp *wtmprec;
	size_t reclen, left;
	char *p, *s;
	
	if (wtmp_fd == -1) {
		errno = EINVAL;
		return 1;
	}

	if (read(wtmp_fd, &reclen, sizeof(reclen)) != sizeof(reclen))
		return 1;
	wtmp_recsize = reclen;
	
	wtmprec = alloc_wtmp(reclen);
	if (!wtmprec)
		return 1;
	p = RUSH_WTMP_DATA_PTR(wtmprec);
	reclen -= sizeof(reclen);
	left = reclen;
	while (left) {
		ssize_t n = read(wtmp_fd, p, left);
		if (n == -1)
			goto errlab;
		p += n;
		left -= n;
	}
	
	p = (char*) (wtmprec + 1);
	s = p;
	wtmprec->user = s;
	s += strlen(s) + 1;
	if (s - p > reclen)
		goto errlab;
	wtmprec->rule = s;
	s += strlen(s) + 1;
	if (s - p > reclen)
		goto errlab;
	wtmprec->command = s;

	*pwtmp = wtmprec;
	return 0;

  errlab:
	free(wtmprec);
	rush_wtmp_close();
	return 1;
}

size_t
rush_wtmp_reclen(struct rush_wtmp *src)
{
	size_t reclen = sizeof(struct rush_wtmp)
		+ strlen(src->user) + 1
		+ strlen(src->rule) + 1
		+ strlen(src->command) + 1;
	return reclen;
}

struct rush_wtmp *
rush_wtmp_copy(struct rush_wtmp *src)
{
	size_t reclen = rush_wtmp_reclen(src);
	struct rush_wtmp *dst = malloc(reclen);
	if (dst) {
		char *p;
		
		dst->reclen = reclen;
		dst->start = src->start;
		dst->stop = src->stop;
		p = (char*) (dst + 1);
		strcpy(p, src->user);
		dst->user = NULL;
		p += strlen(p) + 1;
		dst->rule = NULL;
		strcpy(p, src->rule);
		p += strlen(p) + 1;
		dst->command = NULL;
		strcpy(p, src->command);
		p += strlen(p) + 1;
	}
	return dst;
}

off_t
rush_wtmp_append(struct rush_wtmp *wtmp)
{
	size_t left;
	char *p;
	off_t off;
	struct rush_wtmp *record;
	
	if (wtmp_fd == -1) {
		errno = EINVAL;
		return -1;
	}

	off = lseek(wtmp_fd, 0, SEEK_END);
	if (off == -1)
		return -1;

	record = rush_wtmp_copy(wtmp);
	
	left = record->reclen;
	p = (char*) record;
	while (left) {
		ssize_t n = write(wtmp_fd, p, left);
		if (n == -1)
			goto errlab;
		p += n;
		left -= n;
	}
	
        wtmp_recsize = record->reclen;
	free(record);
	return off;

  errlab:
	rush_wtmp_close();
	return -1;
}

int
rush_wtmp_update(struct timeval *tv)
{
	struct rush_wtmp wtmp;
	if (lseek(wtmp_fd, - wtmp_recsize, SEEK_CUR) == -1)
		return 1;
	if (read(wtmp_fd, &wtmp, sizeof wtmp) != sizeof wtmp)
		return 1;
	if (lseek(wtmp_fd, - sizeof(wtmp), SEEK_CUR) == -1)
		return 1;
	wtmp.stop = *tv;
	return write(wtmp_fd, &wtmp, sizeof wtmp) != sizeof wtmp;
}
