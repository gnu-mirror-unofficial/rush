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

#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <strftime.h>
#include <fprintftime.h>
#include <inttostr.h>
#include <xalloc.h>
#include <c-ctype.h>

#include "librush.h"

static char *
mkname(const char *base, const char *suf)
{
	char *s = malloc(strlen(base) + 1 + strlen(suf) + 1);
	if (s) {
		strcpy(s, base);
		strcat(s, ".");
		strcat(s, suf);
	}
	return s;
}

int
rushdb_open(const char *base_name, int rw)
{
	char *fname;
	int rc;
	
	fname = mkname(base_name, RUSH_UTMP_SUF);
	if (!fname) 
		return 1;
	rc = rush_utmp_open(fname, rw);
	free(fname);
	if (rc)
		return 1;
	
	fname = mkname(base_name, RUSH_WTMP_SUF);
	if (!fname) 
		return 1;
	rc = rush_wtmp_open(fname, rw);
	free(fname);
	return rc;
}

int
rushdb_close()
{
	return rush_wtmp_close() || rush_utmp_close();
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
char *rushdb_error_string;

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
        int d,h,m,s;
	
        d = t / 86400;
        t %= 86400;
        
        s = t % 60;
        m = t / 60;
        if (m > 59) {
                h = m / 60;
                m -= h*60;
        } else
                h = 0;
	if (d)
		width = printf("%d+%02d:%02d", d, h, m);
        else
                width = printf("%02d:%02d", h, m);
	return width;
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
format_rule(int outbytes, int width, struct format_key *key, struct rush_wtmp *wtmp)
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
	char buf[INT_BUFSIZE_BOUND(pid_t)];
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
parse_string0(char *fmt, rushdb_format_t form,
	      int (*cond)(void *, char *), void *closure)
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
				
			default:
				c = *p;
			}
			slist_append(slist, &c, 1);
		} else
			slist_append(slist, p, 1);
	}

	c = 0;
	slist_append(slist, &c, 1);
	form->type = FDATA_STRING;
	slist_reduce(slist, &form->v.string, NULL);
	return p;
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
	p = parse_string0(*fmtp + 1, form, _is_closing_quote, *fmtp);	
	if (!*p) {
		asprintf(&rushdb_error_string,
		         "missing closing quote in string started near `%s'",
		         *fmtp);
		return 1;
	}
	*fmtp = p + 1;
	return 0;
}

static int
_is_delim(void *closure, char *p)
{
	return *p == '(';
}

static int
parse_string(char **fmtp, struct rushdb_format *form)
{
	char *p;
	p = parse_string0(*fmtp, form, _is_delim, NULL);
	*fmtp = p;
	return 0;
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
		while (**fmtp && !c_isspace(**fmtp) && **fmtp != ')')
			++*fmtp;
		slist_append(slist, p, *fmtp - p);
	}
	c = 0;
	slist_append(slist, &c, 1);
	return slist_reduce(slist, &p, NULL);
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
			asprintf(&rushdb_error_string,
			         "error in format spec: unknown format %s",
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
				asprintf(&rushdb_error_string,
					 "wrong number of arguments to form %s",
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
	}
	
	if (p[0] != ')') {
		asprintf(&rushdb_error_string,
			 "form `%s' not closed", formname);
		return 1;
	}
	return 0;
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

rushdb_format_t 
rushdb_compile_format(char *fmt)
{
	struct rushdb_format *form_head = NULL, *form_tail;

	slist = slist_create();
	
	while (*fmt) {
		int rc;
		struct rushdb_format *form = xmalloc(sizeof(*form));
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
	int width;
	
	for (p = form; p; p = p->next) 
		if (p->type == FDATA_NEWLINE)
			return;
	
	for (; form; form = form->next) {
		switch (form->type) {
		case FDATA_FH:
			width = form->v.fh.width;

			if (form->v.fh.header) {
				if (is_time_function(form->v.fh.fun))
					width = time_width(form);
				outbytes += output_string(form->v.fh.header,
							  width,
							  ALIGN_LEFT);
			} else
				output_string("", width, ALIGN_LEFT);
			break;
				
		case FDATA_STRING:
			outbytes += output_string("",
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
	enum rush_utmp_result rc;

	rc = rush_utmp_read(RUSH_STATUS_MAP_BIT(RUSH_STATUS_AVAIL),
			    &status, NULL);
	if (rc == rush_utmp_fail)
		return rc;
	gettimeofday(&wtmp->start, NULL);
	memset(&wtmp->stop, 0, sizeof(wtmp->stop));
	return rush_utmp_write(wtmp);
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
