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

#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <strftime.h>
#include <fprintftime.h>
#include <inttostr.h>
#include <xalloc.h>
#include <c-ctype.h>

#include "librush.h"

mode_t rushdb_umask = 022;
mode_t rushdb_dir_mode = 0777;
mode_t rushdb_file_mode = 0666;

#define ERROR_BUFFER_SIZE 1024
static char rushdb_error_buffer[ERROR_BUFFER_SIZE];
char *rushdb_error_string = rushdb_error_buffer;

static void format_error(const char *fmt, ...) RUSH_PRINTFLIKE(1,2);
	
static void
format_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(rushdb_error_buffer, sizeof(rushdb_error_buffer), fmt, ap);
	va_end(ap);
}

static char *
mkname(const char *dir, const char *file)
{
	char *s = malloc(strlen(dir) + 1 + strlen(file) + 1);
	if (s) {
		strcpy(s, dir);
		strcat(s, "/");
		strcat(s, file);
	}
	return s;
}

static enum rushdb_result
rushdb_open_internal(const char *dbdir, int rw)
{
	char *fname;
	int rc;
	struct stat st;
	
	if (stat(dbdir, &st)) {
		if (errno == ENOENT) {
			if (!rw)
				return rushdb_result_eof;
			if (mkdir(dbdir, rushdb_dir_mode)) {
				format_error(_("cannot create directory %s: %s"),
					     dbdir, strerror(errno));
				return rushdb_result_fail;
			}
		} else {
			format_error(_("cannot stat directory %s: %s"),
				     dbdir, strerror(errno));
			return rushdb_result_fail;
		}
	} else if (!S_ISDIR(st.st_mode)) {
		format_error(_("%s is not a directory"), dbdir);
		return rushdb_result_fail;
	}
	
	fname = mkname(dbdir, RUSH_UTMP_NAME);
	if (!fname) {
		format_error("%s", gettext(strerror(ENOMEM)));
		return rushdb_result_fail;
	}
	rc = rush_utmp_open(fname, rw);
	if (rc) {
		format_error(_("cannot open file %s: %s"),
			     fname, strerror(errno));
		free(fname);
		return rushdb_result_fail;
	}
	free(fname);

	fname = mkname(dbdir, RUSH_WTMP_NAME);
	if (!fname) {
		format_error("%s", gettext(strerror(ENOMEM)));
		return rushdb_result_fail;
	}
	rc = rush_wtmp_open(fname, rw);
	if (rc) {
		format_error(_("cannot open file %s: %s"),
			     fname, strerror(errno));
		free(fname);
		return rushdb_result_fail;
	}
	free(fname);
	
	return rushdb_result_ok;
}

enum rushdb_result
rushdb_open(const char *dbdir, int rw)
{
	mode_t um = umask(rushdb_umask);
	enum rushdb_result res = rushdb_open_internal(dbdir, rw);
	umask(um);
	return res;
}

int
rushdb_close()
{
	return rush_wtmp_close() || rush_utmp_close();
}

void
rushdb_backward_direction()
{
	rush_wtmp_set_dir(rush_wtmp_backward);
}


/* Locking */

static int lock_typetab[] = {
	F_RDLCK,              /* RUSH_LOCK_READ */
	F_WRLCK               /* RUSH_LOCK_WRITE */
};

int
rushdb_lock(int fd, size_t size, off_t offset, int whence, int type)
{
	struct flock fl;

	if (type < 0 || type > 1) {
		errno = EINVAL;
		return -1;
	}
		
	fl.l_type = lock_typetab[type];
	fl.l_whence = whence;
	fl.l_start = offset;
	fl.l_len = size;
	return fcntl(fd, F_SETLKW, &fl); /* FIXME: Handle EINTR */
}

int
rushdb_unlock(int fd, size_t size, off_t offset, int whence)
{
	struct flock fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = whence;
	fl.l_start = offset;
	fl.l_len = size;
	return fcntl(fd, F_SETLKW, &fl);
}


#define FDATA_FH      0
#define FDATA_STRING  1
#define FDATA_TAB     2 
#define FDATA_NEWLINE 3

struct format_key {
	struct format_key *next;
	char *name;
	char *value;
};

typedef int (*rushdb_format_fp) (int outbytes,
				 int width,
				 struct format_key *key,
				 struct rush_wtmp *);

struct rushdb_format {
	rushdb_format_t next;
	int type;
	struct format_key *key;
	union {
		struct {
			rushdb_format_fp fun;
			int width;
			char *header;
		} fh;              /* FDATA_FH */
		char *string;      /* FDATA_STRING */
		int tabstop;       /* FDATA_TAB */
		int nl;            /* FDATA_NEWLINE */
	} v;
};

char *rushdb_date_format = "%a %H:%M";

#define ALIGN_LEFT  0
#define ALIGN_RIGHT 1
#define TAB_SIZE    8


/* Key auxiliary */
static void
format_key_free(struct format_key *key)
{
	struct format_key *next;
	while (key) {
		next = key->next;
		free(key->name);
		free(key->value);
		free(key);
		key = next;
	}
}

static char *
format_key_lookup(struct format_key *key, char *name)
{
	for (; key; key = key->next) {
		if (strcmp(key->name, name) == 0)
			return key->value;
	}
	return NULL;
}

static void
form_free(struct rushdb_format *form)
{
	struct rushdb_format *next;

	while (form) {
		next = form->next;
		
		format_key_free(form->key);
		switch (form->type) {
		case FDATA_STRING:
			free(form->v.string);
			break;
		case FDATA_FH:
			free(form->v.fh.header);
			break;
		default:
			break;
		}
		free(form);

		form = next;
	}
}

static int
key_align(struct format_key *key)
{
	char *p = format_key_lookup(key, "right");
	return p ? ALIGN_RIGHT : ALIGN_LEFT;
}


static int
output_string(char *string, int width, int align)
{
	if (width == 0) 
		width = printf("%s", string);
	else if (align == ALIGN_LEFT)
		width = printf("%-*.*s", width, width, string);
	else
		width = printf("%*.*s", width, width, string);
	return width;
}

static int
output_string_key(char *string, int width, struct format_key *key)
{
	if (strlen(string) == 0) {
		char *p = format_key_lookup(key, "empty");
		if (p)
			string = p;
	}
	return output_string(string, width, key_align(key));
}

static int
output_tab(int column, int tabstop)
{
	int goal = (((column + TAB_SIZE - 1) / TAB_SIZE) + tabstop) * TAB_SIZE;
	for (;column < goal; column++)
		putchar(' ');
	return column;
}

/*FIXME: ignores key */
static int
output_duration(time_t t, int width, struct format_key *key)
{
        unsigned d,h,m,s;
	unsigned outbytes;
	char dbuf[INT_BUFSIZE_BOUND(unsigned)+1];
	char *dptr = NULL;
	unsigned fullwidth, dlen;
	
	d = t / 86400;
	t %= 86400;

	s = t % 60;
	m = t / 60;
	if (m > 59) {
		h = m / 60;
		m -= h*60;
	} else
		h = 0;
	
	fullwidth = 8;
	if (d) {
		dptr = uinttostr(d, dbuf);
		dlen = strlen(dptr);
		fullwidth += dlen + 1;
	}

	if (d) {
		if (width >= fullwidth)
			outbytes = printf("%*s+%02u:%02u:%02u",
					  width - fullwidth, dptr, h, m, s);
		else if (width >= fullwidth - 3)
			outbytes = printf("%*sd%02uh%02u",
					  width - (dlen + 5),
					   dptr, h, m);
		else if (width >= fullwidth - 5)
			outbytes = printf("%*sd%02uh",
					  width - (dlen + 3),
					  dptr, h);
		else if (width >= dlen + 1)
			outbytes = printf("%*sd",
					  width - 1, dptr);
		else {
			outbytes = width;
			while (width--)
				putchar('>');
		}
	} else {
		if (width >= 8)
			outbytes = printf("%*s%02u:%02u:%02u",
					  width - 8, "", h, m, s);
		else if (width >= 5) {
			if (h)
				outbytes = printf("%*s%02uh%02u",
						  width - 5, "", h, m);
			else
				outbytes = printf("%*s%02u:%02u",
						  width - 5, "", m, s);
		} else if (h) {
			dptr = uinttostr(h, dbuf);
			dlen = strlen(dptr);
			if (width >= dlen + 1)
				outbytes = printf("%*sh",
						  width - 1, dptr);
			else {
				outbytes = width;
				while (width--)
					putchar('>');
			}
		} else {
			dptr = uinttostr(s, dbuf);
			dlen = strlen(dptr);
			if (width >= dlen)
				outbytes = printf("%*s", width, dptr);
			else {
				dptr = uinttostr(m, dbuf);
				dlen = strlen(dptr);
				if (width >= dlen + 1)
					outbytes = printf("%*sm",
							  width - 1, dptr);
				else {
					outbytes = width;
					while (width--)
						putchar('>');
				}
			}
		}
	}

	return outbytes;
}

static int
output_time(struct timeval *tv, int width, struct format_key *key)
{
	struct tm *tm = localtime(&tv->tv_sec);
	char *fmt = format_key_lookup(key, "format");
	
	return fprintftime(stdout, fmt ? fmt : rushdb_date_format,
			   tm, 0, tv->tv_usec * 1000);
}



/* Runtime */
static int
format_user(int outbytes, int width, struct format_key *key,
	    struct rush_wtmp *wtmp)
{
	return output_string_key(wtmp->user, width, key);
}

static int
format_rule(int outbytes, int width, struct format_key *key,
	    struct rush_wtmp *wtmp)
{
	return output_string_key(wtmp->rule, width, key);
}

static int
format_command(int outbytes, int width, struct format_key *key,
	       struct rush_wtmp *wtmp)
{
	return output_string_key(wtmp->command, width, key);
}

static int
format_pid(int outbytes, int width, struct format_key *key,
	   struct rush_wtmp *wtmp)
{
	char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	return output_string_key(umaxtostr(wtmp->pid, buf), width, key);
}

static int
format_duration(int outbytes, int width, struct format_key *key,
		struct rush_wtmp *wtmp)
{
	time_t end = wtmp->stop.tv_sec;
	time_t x = (end ? end : time(NULL)) - wtmp->start.tv_sec;
	
	return output_duration(x, width, key);
}

static int
format_start(int outbytes, int width, struct format_key *key,
	     struct rush_wtmp *wtmp)
{
	return output_time(&wtmp->start, width, key);
}

static int
format_stop(int outbytes, int width, struct format_key *key,
	    struct rush_wtmp *wtmp)
{
	if (wtmp->stop.tv_sec == 0 && wtmp->stop.tv_usec == 0) 
		return output_string_key("running", width, key);
	else
		return output_time(&wtmp->stop, width, key);
}

struct format_tab {
	char *name;
	rushdb_format_fp fun;
};

static struct format_tab handlers[] = {
	{ "user", format_user },
	{ "rule", format_rule },
	{ "command", format_command },
	{ "pid", format_pid },
	{ "duration", format_duration },
	{ "time", format_start },
	{ "start-time", format_start },
	{ "stop-time", format_stop },
	{ NULL }
};

static rushdb_format_fp
_lookup(char *name)
{
	int i;
	for (i = 0; handlers[i].name; i++)
		if (strcmp(handlers[i].name, name) == 0)
			return handlers[i].fun;
	return NULL;
}



static slist_t slist;

static char *
collect_sequence(char *fmt, int (*cond)(void *, char *), void *closure)
{
	char c;
	char *p;
	
	for (p = fmt; *p && (*cond)(closure, p) == 0; p++) {
		if (*p == '\\') {
			switch (*++p) {
			case 'a':
				c = '\a';
				break;
				
			case 'b':
				c = '\b';
				break;
				
			case 'e':
				c = '\033';
				break;
				
			case 'f':
				c = '\f';
				break;
				
			case 'n':
				c = '\n';
				break;
				
			case 't':
				c = '\t';
				break;
				
			case 'r':
				c = '\r';
				break;
				
			case 'v':
				c = '\v';
				break;

			case '\n':
				continue;
				
			default:
				 c = *p;
			}
			slist_append(slist, &c, 1);
		} else if (*p == '\n')
			;
		else
			slist_append(slist, p, 1);
	}
	return p;
}

static char *
parse_string_fmt(char *fmt, rushdb_format_t form,
		  int (*cond)(void *, char *), void *closure)
{
	char c;
	char *endp = collect_sequence(fmt, cond, closure);
	
	c = 0;
	slist_append(slist, &c, 1);
	slist_reduce(slist, &form->v.string, NULL);
	form->type = FDATA_STRING;
	return endp;
}

static int
_is_closing_quote(void *closure, char *p)
{
	return *(char*)closure == *p;
}

static int
parse_quote(char **fmtp, struct rushdb_format *form)
{
	char *p;
	p = parse_string_fmt(*fmtp + 1, form, _is_closing_quote, *fmtp);
	if (!*p) {
		format_error(_("missing closing quote in string started "
			       "near `%s'"),
			     *fmtp);
		return 1;
	}
	*fmtp = p + 1;
	return 0;
}

static int
_is_open_brace(void *closure, char *p)
{
	return *p == '(';
}

static int
parse_string(char **fmtp, struct rushdb_format *form)
{
	char *p;
	p = parse_string_fmt(*fmtp, form, _is_open_brace, NULL);
	*fmtp = p;
	return 0;
}

static int
_is_delim(void *closure, char *p)
{
	return c_isspace(*p) || *p == ')';
}

static char *
get_token(char **fmtp)
{
	char *p;
	char c;
	
	while (**fmtp && c_isspace(**fmtp))
		++*fmtp;
	p = *fmtp;
	if (*p == ')') {
		slist_append(slist, p, 1);
		++*fmtp;
	} else {
		if (**fmtp == '"' || **fmtp == '\'') {
			p = collect_sequence(*fmtp + 1,
					     _is_closing_quote, *fmtp);
			if (*p == **fmtp)
				p++;
			*fmtp = p;
		} else
			*fmtp = collect_sequence(*fmtp, _is_delim, NULL);
	}
	c = 0;
	slist_append(slist, &c, 1);
	return slist_reduce(slist, &p, NULL);
}

static int
is_time_function(rushdb_format_fp fh)
{
	return fh == format_start || fh == format_stop;
}

static int
time_width(struct rushdb_format *form)
{
	time_t t = 0;
	struct tm *tm = localtime(&t);
	char *fmt = format_key_lookup(form->key, "format");
	
	return nstrftime(NULL, -1, fmt ? fmt : rushdb_date_format, 
			 tm, 0, 0);
}

static int
parse_form(char **fmtp, struct rushdb_format *form)
{
	char *formname, *p;
	struct format_key *key_head, *key_tail;
	
	++*fmtp;
	
	formname = get_token(fmtp);
	if (strcmp(formname, "newline") == 0) {
		form->type = FDATA_NEWLINE;
		p = get_token(fmtp);
		if (p[0] != ')') {
			form->v.nl = strtol(p, NULL, 0);
			p = get_token(fmtp);
		} else
			form->v.nl = 1;
	} else if (strcmp(formname, "tab") == 0) {
		form->type = FDATA_TAB;
		p = get_token(fmtp);
		if (p[0] != ')') {
			form->v.tabstop = strtol(p, NULL, 0);
			p = get_token(fmtp);
		} else
			form->v.tabstop = 1;
	} else {
		rushdb_format_fp fh;
		int arg;
		
		fh = _lookup(formname);
		if (!fh) {
			format_error("error in format spec: unknown format %s",
				     formname);
			return 1;
		}
		
		form->type = FDATA_FH;
		form->v.fh.fun = fh;
		
		/* Collect optional arguments */
		arg = 0;
		while ((p = get_token(fmtp)) != NULL &&
		       !(p[0] == ':' || p[0] == ')')) {
			arg++;
			switch (arg) {
			case 1: /* width */
				form->v.fh.width = strtol(p, NULL, 0);
				break;
			case 2: /* header */
				form->v.fh.header = xstrdup(p);
				break;
			default:
				format_error("wrong number of arguments "
					     "to form %s",
					     formname);
				return 1;
			}
		}
		
		/* Collect keyword arguments */
		key_head = NULL;
		while (p && p[0] == ':') {
			struct format_key *key = xzalloc(sizeof(*key));
			if (!key_head)
				key_head = key;
			else
				key_tail->next = key;
			key_tail = key;
			key->name = xstrdup(p + 1);
			p = get_token(fmtp);
			if (p[0] == ')' || p[0] == ':')
				key->value = xstrdup("t");
			else {
				key->value = xstrdup(p);
				p = get_token(fmtp);
			}
		}
		form->key = key_head;
		
		if (is_time_function(form->v.fh.fun))
			form->v.fh.width = time_width(form);
	}
	
	if (p[0] != ')') {
		format_error("form `%s' not closed", formname);
		return 1;
	}
	return 0;
}


rushdb_format_t 
rushdb_compile_format(char *fmt)
{
	struct rushdb_format *form_head = NULL, *form_tail;
	
	slist = slist_create();
	
	while (*fmt) {
		int rc;
		struct rushdb_format *form = xzalloc(sizeof(*form));
		if (!form_head)
			form_head = form;
		else
			form_tail->next = form;
		form_tail = form;
		
		if (*fmt == '(')
			rc = parse_form(&fmt, form);
		else if (*fmt == '"' || *fmt == '\'')
			rc = parse_quote(&fmt, form);
		else
			rc = parse_string(&fmt, form);
		
		if (rc) {
			form_free(form_head);
			form_head = NULL;
			break;
		}
	}
	
	slist_free(slist);
	
	return form_head;
}

int
rushdb_print(rushdb_format_t form, struct rush_wtmp *wtmp, int newline)
{
	int i;
	int outbytes = 0;
	
	for (; form; form = form->next) {
		switch (form->type) {
		case FDATA_FH:
			outbytes += form->v.fh.fun(outbytes,
						   form->v.fh.width,
						   form->key,
						   wtmp);
			break;
			
		case FDATA_STRING:
			outbytes += output_string(form->v.string, 0,
						  ALIGN_LEFT);
			break;
			
		case FDATA_TAB:
			outbytes += output_tab(outbytes, form->v.tabstop);
			break;
			
		case FDATA_NEWLINE:
			for (i = 0; i < form->v.nl; i++)
				putchar('\n');
			break;
			
		default:
			abort();
		}
	}
	if (newline)
		putchar('\n');
	return outbytes;
}

void
rushdb_print_header(rushdb_format_t form)
{
	int i, outbytes = 0;
	rushdb_format_t p;
	
	for (p = form; p; p = p->next) 
		if (p->type == FDATA_NEWLINE)
			return;
	
	for (; form; form = form->next) {
		switch (form->type) {
		case FDATA_FH:
			if (form->v.fh.header) 
				outbytes += output_string(form->v.fh.header,
							  form->v.fh.width,
							  ALIGN_LEFT);
			else
				outbytes += output_string("", form->v.fh.width,
							  ALIGN_LEFT);
			break;
			
		case FDATA_STRING:
			outbytes += output_string(form->v.string,
						  strlen(form->v.string),
						  ALIGN_LEFT);
			break;
			
		case FDATA_TAB:
			outbytes += output_tab(outbytes, form->v.tabstop);
			break;
			
		case FDATA_NEWLINE:
			for (i = 0; i < form->v.nl; i++)
				putchar('\n');
			break;
			
		default:
			abort();
		}
	}
	putchar('\n');
}

int
rushdb_start(struct rush_wtmp *wtmp)
{
	int status;
	enum rushdb_result result;
	int rc;

	rush_utmp_lock_all(RUSH_LOCK_WRITE);
	result = rush_utmp_read(RUSH_STATUS_MAP_BIT(RUSH_STATUS_AVAIL),
				&status, NULL);
	if (result == rushdb_result_fail) 
		rc = 1;
	else {
		gettimeofday(&wtmp->start, NULL);
		memset(&wtmp->stop, 0, sizeof(wtmp->stop));
		rc = rush_utmp_write(wtmp);
	} 
	rush_utmp_unlock_all();
	return rc;
}
		
int
rushdb_stop()
{
	struct timeval tv;
	if (rush_utmp_chstatus(RUSH_STATUS_AVAIL))
		return 1;
	gettimeofday(&tv, NULL);
	return rush_wtmp_update(&tv);
}

		
