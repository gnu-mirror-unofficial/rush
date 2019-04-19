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

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "librush.h"

enum rush_wtmp_dir rush_wtmp_dir = rush_wtmp_forward;
static int wtmp_fd = -1;
static size_t wtmp_recsize = 0;

int
rush_wtmp_open(const char *name, int rw)
{
	int fd;
	
	fd = open(name, rw ? O_RDWR|O_CREAT : O_RDONLY, rushdb_file_mode);
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
rush_wtmp_rewind(void)
{
	int whence;
	
	switch (rush_wtmp_dir) {
	case rush_wtmp_forward:
		whence = SEEK_SET;
		break;
		
	case rush_wtmp_backward:
		whence = SEEK_END;
		break;

	default:
		/* Should not happen */
		abort();
	}
	return lseek(wtmp_fd, 0, whence) == -1;
}

void
rush_wtmp_set_dir(enum rush_wtmp_dir dir)
{
	rush_wtmp_dir = dir;
	rush_wtmp_rewind();
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

enum rushdb_result
rush_wtmp_read_fwd(struct rush_wtmp **pwtmp)
{
	struct rush_wtmp *wtmprec;
	size_t reclen, left;
	ssize_t size;
	char *p, *s;
	
	if (wtmp_fd == -1) {
		errno = EINVAL;
		return rushdb_result_fail;
	}

	size = read(wtmp_fd, &reclen, sizeof(reclen));
	if (size == 0)
		return rushdb_result_eof; 
	if (size != sizeof(reclen))
		return rushdb_result_fail;
	wtmp_recsize = reclen;
	
	wtmprec = alloc_wtmp(reclen);
	if (!wtmprec)
		return rushdb_result_fail;
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
	return rushdb_result_ok;

  errlab:
	free(wtmprec);
	rush_wtmp_close();
	return rushdb_result_fail;
}

enum rushdb_result
rush_wtmp_read(struct rush_wtmp **pwtmp)
{
	size_t reclen;
	enum rushdb_result res;
		
	switch (rush_wtmp_dir) {
	case rush_wtmp_forward:
		res = rush_wtmp_read_fwd(pwtmp);
		if (lseek(wtmp_fd, sizeof(reclen), SEEK_CUR) == -1)
			res = rushdb_result_fail;
		break;
		
	case rush_wtmp_backward:
		if (lseek(wtmp_fd, 0, SEEK_CUR) == 0)
			return rushdb_result_eof;
		if (lseek(wtmp_fd, -sizeof(reclen), SEEK_CUR) == -1)
			return rushdb_result_fail;
		if (read(wtmp_fd, &reclen, sizeof(reclen)) != sizeof(reclen))
			return rushdb_result_fail;
		if (lseek(wtmp_fd, -(reclen + sizeof(reclen)), SEEK_CUR) == -1)
			return rushdb_result_fail;
		res = rush_wtmp_read_fwd(pwtmp);
		if (res == rushdb_result_ok) {
			if (lseek(wtmp_fd, -reclen, SEEK_CUR) == -1)
				return rushdb_result_fail;
		}
		break;

	default:
		/* Should not happen */
		abort();
	}
	return res;
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
		dst->pid = src->pid;
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

	rushdb_lock(wtmp_fd, record->reclen, off, SEEK_SET, RUSH_LOCK_WRITE);
	left = record->reclen;
	p = (char*) record;
	while (left) {
		ssize_t n = write(wtmp_fd, p, left);
		if (n == -1)
			goto errlab;
		p += n;
		left -= n;
	}
	if (write(wtmp_fd, &record->reclen, sizeof(record->reclen)) !=
	    sizeof(wtmp->reclen))
		goto errlab;

	rushdb_unlock(wtmp_fd, record->reclen, off, SEEK_SET);
        wtmp_recsize = record->reclen;
	free(record);
	return off;

  errlab:
	rushdb_unlock(wtmp_fd, record->reclen, off, SEEK_SET);
	rush_wtmp_close();
	return -1;
}

int
rush_wtmp_update(struct timeval *tv)
{
	struct rush_wtmp wtmp;
	if (lseek(wtmp_fd, - (wtmp_recsize + sizeof(size_t)), SEEK_CUR) == -1)
		return 1;
	if (read(wtmp_fd, &wtmp, sizeof wtmp) != sizeof wtmp)
		return 1;
	if (lseek(wtmp_fd, - sizeof(wtmp), SEEK_CUR) == -1)
		return 1;
	wtmp.stop = *tv;
	return write(wtmp_fd, &wtmp, sizeof wtmp) != sizeof wtmp;
}
