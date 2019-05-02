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

#include <rush.h>

#define SET_LIMIT_AS      0x0001
#define SET_LIMIT_CPU     0x0002
#define SET_LIMIT_DATA    0x0004
#define SET_LIMIT_FSIZE   0x0008
#define SET_LIMIT_NPROC   0x0010
#define SET_LIMIT_CORE    0x0020
#define SET_LIMIT_MEMLOCK 0x0040
#define SET_LIMIT_NOFILE  0x0080
#define SET_LIMIT_RSS     0x0100
#define SET_LIMIT_STACK   0x0200
#define SET_LIMIT_LOGINS  0x0400
#define SET_LIMIT_PRIO    0x0800

struct limits_rec {
        unsigned set;
        rlim_t   limit_as;
        rlim_t   limit_cpu;
        rlim_t   limit_data;
        rlim_t   limit_fsize;
        rlim_t   limit_nproc;
        rlim_t   limit_core;
        rlim_t   limit_memlock;
        rlim_t   limit_nofile;
        rlim_t   limit_rss;
        rlim_t   limit_stack;
        size_t   limit_logins;
        int      limit_prio;  
};

int
do_set_limit(int rlimit, rlim_t limit)
{
        struct rlimit rlim;

        debug(2, _("Setting limit %d to %lu"), rlimit, (unsigned long) limit);
        rlim.rlim_cur = limit;
        rlim.rlim_max = limit;

        if (setrlimit(rlimit, &rlim)) {
                logmsg(LOG_NOTICE, _("error setting limit: %s"), 
                       strerror(errno));
                return 1;
        }
        return 0;
}

static int
set_prio(int prio)
{
        debug(2, _("Setting priority to %d"), prio);
        if (setpriority(PRIO_PROCESS, 0, prio)) {
                logmsg(LOG_NOTICE, _("error setting priority: %s"),
                       strerror(errno));
                return 1;
        }
        return 0;
}

/* Counts the number of user logins and check against the limit */
static int
check_logins(const char *name, size_t limit)
{
        size_t count = 0;
	struct rush_wtmp *wtmp = 0;
	int status;
	
        if (limit == 0) /* maximum 0 logins ? */ {
                debug(2, _("No logins allowed for `%s'"), name);
                logmsg(LOG_ERR, _("No logins allowed for `%s'"), name);
                return 1;
        }

        debug(3, _("counting logins for %s"), name);
	switch (rushdb_open(RUSH_DB, 0)) {
	case rushdb_result_ok:
		break;

	case rushdb_result_eof:
		debug(3, "%s", _("acct database is empty"));
		return 0;

	case rushdb_result_fail:
                logmsg(LOG_ERR, _("Cannot open database %s: %s"),
                       RUSH_DB, rushdb_error_string);
		return 0;
	}

	while (rush_utmp_read(RUSH_STATUS_MAP_BIT(RUSH_STATUS_INUSE),
			      &status, &wtmp) == 0) {
		if (strcmp (wtmp->user, name) == 0) {
			if (++count >= limit)
				break;
		}
		free(wtmp);
		wtmp = NULL;
	}
	free(wtmp);

	rushdb_close();
	
        debug(3, _("counted %zu/%zu logins for %s"), count, limit, name);

        /*
         * This is called after setutmp(), so the number of logins counted
         * includes the user who is currently trying to log in.
         */
        if (count >= limit) {
                debug(2, _("Too many logins (max %zu) for %s"),
		       limit, name);
                logmsg(LOG_ERR, _("Too many logins (max %zu) for %s"),
                       limit, name);
                return 1;
        }
        return 0;
}

int
set_user_limits(const char *name, struct limits_rec *lrec)
{
        int rc = 0;

        if (!lrec)
                return 0;

	debug(2, _("Setting limits for %s"), name);

#if defined(RLIMIT_AS)
        if (lrec->set & SET_LIMIT_AS)
                rc |= do_set_limit(RLIMIT_AS, lrec->limit_as);
#endif
#if defined(RLIMIT_CPU)
        if (lrec->set & SET_LIMIT_CPU)
                rc |= do_set_limit(RLIMIT_CPU, lrec->limit_cpu);
#endif
#if defined(RLIMIT_DATA)
        if (lrec->set & SET_LIMIT_DATA)
                rc |= do_set_limit(RLIMIT_DATA, lrec->limit_data);
#endif
#if defined(RLIMIT_FSIZE)
        if (lrec->set & SET_LIMIT_FSIZE) 
                rc |= do_set_limit(RLIMIT_FSIZE, lrec->limit_fsize);
#endif
#if defined(RLIMIT_NPROC)
        if (lrec->set & SET_LIMIT_NPROC)
                rc |= do_set_limit(RLIMIT_NPROC, lrec->limit_nproc);
#endif
#if defined(RLIMIT_CORE)
        if (lrec->set & SET_LIMIT_CORE)
                rc |= do_set_limit(RLIMIT_CORE, lrec->limit_core);
#endif
#if defined(RLIMIT_MEMLOCK)
        if (lrec->set & SET_LIMIT_MEMLOCK)
                rc |= do_set_limit(RLIMIT_MEMLOCK, lrec->limit_memlock);
#endif
#if defined(RLIMIT_NOFILE)
        if (lrec->set & SET_LIMIT_NOFILE)
                rc |= do_set_limit(RLIMIT_NOFILE, lrec->limit_nofile);
#endif
#if defined(RLIMIT_RSS)
        if (lrec->set & SET_LIMIT_RSS)
                rc |= do_set_limit(RLIMIT_RSS, lrec->limit_rss);
#endif
#if defined(RLIMIT_STACK)
        if (lrec->set & SET_LIMIT_STACK)
                rc |= do_set_limit(RLIMIT_STACK, lrec->limit_stack);
#endif
        if (lrec->set & SET_LIMIT_LOGINS)
                rc |= check_logins(name, lrec->limit_logins);
        if (lrec->set & SET_LIMIT_PRIO)
                rc |= set_prio(lrec->limit_prio);
        return rc;
}

int
getlimit(char **ptr, rlim_t *rlim, int mul)
{
        unsigned long val;

        val = strtoul(*ptr, ptr, 10);
        if (val == 0)
                return 1;
        *rlim = val * mul;
        return 0;
}

limits_record_t
limits_record_create(void)
{
        struct limits_rec *lrec = xmalloc(sizeof(*lrec));
        lrec->set = 0;
	return lrec;
}

/* Parse limits string and fill appropriate fields in lrec.
 
   The string consists of _commands_, optionally separated by any amount
   of whitespace.  A command has the following form:
 
            [AaCcDdFfMmNnRrSsTtUuLlPp][0-9]+
 
   i.e. a letter followed by number, and is interpreted as follows:
 
         Command   ulimit  setrlimit()     The limit it sets
                   option    arg
         -------------------------------------------------------------
            [Aa]   a       RLIMIT_AS        max address space (KB)
            [Cc]   c       RLIMIT_CORE      max core file size (KB)
            [Dd]   d       RLIMIT_DATA      max data size (KB)
            [Ff]   f       RLIMIT_FSIZE     Maximum filesize (KB)
            [Mm]   m       RLIMIT_MEMLOCK   max locked-in-memory address
                                            space (KB)
            [Nn]   n       RLIMIT_NOFILE    max number of open files
            [Rr]   r       RLIMIT_RSS       max resident set size (KB)
            [Ss]   s       RLIMIT_STACK     max stack size (KB)
            [Tt]   t       RLIMIT_CPU       max CPU time (MIN)
            [Uu]   u       RLIMIT_NPROC     max number of processes
            [Ll]   l       (none)           max number of logins for this user
            [Pp]   p       (none)           process priority -20..20
                                            (negative = high priority)
 */
int
limits_record_add(limits_record_t lrec, char *str, char **endp)
{
	char *p;
	
	switch (*str++) {
	case 'a':
	case 'A':
		/* RLIMIT_AS - max address space (KB) */
		if (getlimit(&str, &lrec->limit_as, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_AS;
		break;
	case 't':
	case 'T':
		/* RLIMIT_CPU - max CPU time (MIN) */
		if (getlimit(&str, &lrec->limit_cpu, 60)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_CPU;
		break;
	case 'd':
	case 'D':
		/* RLIMIT_DATA - max data size (KB) */
		if (getlimit(&str, &lrec->limit_data, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_DATA;
		break;
	case 'f':
	case 'F':
		/* RLIMIT_FSIZE - Maximum filesize (KB) */
		if (getlimit(&str, &lrec->limit_fsize, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_FSIZE;
		break;
	case 'u':
	case 'U':
		/* RLIMIT_NPROC - max number of processes */
		if (getlimit(&str, &lrec->limit_nproc, 1)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_NPROC;
		break;
	case 'c':
	case 'C':
		/* RLIMIT_CORE - max core file size (KB) */
		if (getlimit(&str, &lrec->limit_core, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_CORE;
		break;
	case 'm':
	case 'M':
		/* RLIMIT_MEMLOCK - max locked-in-memory
		 * address space (KB)
		 */
		if (getlimit(&str, &lrec->limit_memlock, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_MEMLOCK;
		break;
	case 'n':
	case 'N':
		/* RLIMIT_NOFILE - max number of open files */
		if (getlimit(&str, &lrec->limit_nofile, 1)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_NOFILE;
		break;
	case 'r':
	case 'R':
		/* RLIMIT_RSS - max resident set size (KB) */
		if (getlimit(&str, &lrec->limit_rss, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_RSS;
		break;
	case 's':
	case 'S':
		/* RLIMIT_STACK - max stack size (KB) */
		if (getlimit(&str, &lrec->limit_stack, 1024)) {
			*endp = str;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_STACK;
		break;
	case 'l':
	case 'L': 
		lrec->limit_logins = strtoul(str, &p, 10);
		if (p == str) {
			*endp = p;
			return lrec_badval;
		}
		lrec->set |= SET_LIMIT_LOGINS;
		break;
	case 'p':
	case 'P':
		lrec->limit_prio = strtol(str, &p, 10);
		if (p == str) {
			*endp = p;
			return lrec_badval;
		}
		if (lrec->limit_prio > 0)
			lrec->set |= SET_LIMIT_PRIO;
		break;
	default:
		*endp = str-1;
		return lrec_error;
	}
	return 0;
}

int
parse_limits(limits_record_t *plrec, char *str, char **endp)
{
        int c;
        struct limits_rec *lrec = limits_record_create();
	int rc;
	while ((c = *str++)) {
                if (ISWS(c))
                        continue;
		rc = limits_record_add(lrec, str, endp);
		if (rc) {
			free(lrec);
			return rc;
		}
        }
        *plrec = lrec;
        return 0;
}

