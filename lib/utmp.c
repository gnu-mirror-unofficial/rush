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

#include "librush.h"

static int utmp_fd = -1;
static enum rushdb_result status = rushdb_result_eof;
static struct rush_utmp utmprec = { -1, 0 };

int
rush_utmp_open(const char *name, int rw)
{
	int fd;
	
	fd = open(name, rw ? O_RDWR|O_CREAT : O_RDONLY, rushdb_file_mode);
	if (fd == -1) 
		return -1;
	utmp_fd = fd;
	return 0;
}

int
rush_utmp_close()
{
	int rc = close(utmp_fd);
	utmp_fd = -1;
	return rc;
}

static enum rushdb_result
rush_utmp_read0(int statmap, int *pstatus, struct rush_wtmp **pwtmp)
{
	for (;;) {
		ssize_t n = read(utmp_fd, &utmprec, sizeof(utmprec));

		if (n == 0) 
			return rushdb_result_eof;
			
		if (n != sizeof(utmprec))
			return rushdb_result_fail;

		if (rush_wtmp_seek(utmprec.offset))
			return rushdb_result_fail;

		if (statmap == 0
		    || RUSH_STATUS_MAP_ISSET(statmap, utmprec.status)) {
			if (pwtmp && rush_wtmp_read(pwtmp))
				return rushdb_result_fail;
			break;
		}
	}
		
	*pstatus = utmprec.status;
	return rushdb_result_ok;
}

enum rushdb_result
rush_utmp_read(int statmap, int *pstatus, struct rush_wtmp **pwtmp)
{
	return status = rush_utmp_read0(statmap, pstatus, pwtmp);
}

int
rush_utmp_chstatus(int status)
{
	if (utmp_fd == -1 || utmprec.status == -1
	    || !(status == RUSH_STATUS_AVAIL || status == RUSH_STATUS_INUSE)) {
		errno = EINVAL;
		return 1;
	}
	
	if (lseek(utmp_fd, - sizeof(utmprec), SEEK_CUR) == -1)
		return 1;
	utmprec.status = status;
	if (write(utmp_fd, &utmprec, sizeof(utmprec)) != sizeof(utmprec))
		return 1;
	return 0;
}

int
rush_utmp_write(struct rush_wtmp *wtmp)
{
	int rc;
	off_t off;
	
	if (utmp_fd == -1) {
		errno = EINVAL;
		return 1;
	}

	off = rush_wtmp_append(wtmp);
	if (off == -1)
		return 1;
	if (status == rushdb_result_ok) {
		if (lseek(utmp_fd, - sizeof(utmprec), SEEK_CUR) == -1)
			return 1;
	}
	utmprec.status = RUSH_STATUS_INUSE;
	utmprec.offset = off;
	rushdb_lock(utmp_fd, sizeof(utmprec), 0, SEEK_CUR, RUSH_LOCK_WRITE);
	rc = write(utmp_fd, &utmprec, sizeof(utmprec));
	rushdb_unlock(utmp_fd, - sizeof(utmprec), 0, SEEK_CUR);
	if (rc != sizeof(utmprec))
		return 1;	
	return 0;
}

void
rush_utmp_lock_all(int type)
{
	rushdb_lock(utmp_fd, 0, 0, SEEK_SET, type);
}

void
rush_utmp_unlock_all()
{
	rushdb_unlock(utmp_fd, 0, 0, SEEK_SET);
}
