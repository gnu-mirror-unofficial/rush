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

#include <rush.h>

static char *
skipws(char *p)
{
	while (*p && ISWS(*p))
		p++;
	return p;
}

static char *
eow(char *p)
{
	while (*p && !ISWS(*p))
		p++;
	return p;
}

static void
trimws(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && ISWS(s[len-1])) 
		s[--len] = 0;
}

static size_t
trimslash(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && s[len-1] == '\\')
		s[--len] = 0;
	return len;
}

struct input_buf {
	char *buf;
	size_t off;
	size_t size;
	const char *file;
	unsigned line;
};

int
init_input_buf(struct input_buf *ibuf, const char *file)
{
	struct stat st;
	char *p;
	size_t rest;
	int fd;
	
	if (stat (file, &st)) {
		if (errno == ENOENT) {
			debug1(1, "File %s does not exist", file);
			return 1;
		}
		die(system_error, "cannot stat file %s: %s",
		    file, strerror(errno));
	}
	
	ibuf->size = st.st_size;
	ibuf->buf = xmalloc(ibuf->size + 1);
	fd = open(file, O_RDONLY);
	if (fd == -1) 
		die(system_error, "cannot open file %s: %s",
		    file, strerror(errno));
	rest = ibuf->size;
	p = ibuf->buf;
	while (rest) {
		int n = read(fd, p, rest);
		if (n < 0) 
			die(system_error, "error reading file %s: %s",
			    file, strerror(errno));
		else if (n == 0)
			die(system_error, "read 0 bytes from file %s",
			    file);
		p += n;
		rest -= n;
	}
	*p = 0;
	close(fd);
	
	ibuf->off = 0;
	ibuf->line = 0;
	ibuf->file = file;
	return 0;
}

void
init_input_string(struct input_buf *ibuf, const char *string)
{
	ibuf->buf = xstrdup(string);
	ibuf->size = strlen(string);
	ibuf->off = 0;
	ibuf->line = 0;
	ibuf->file = "<string>";
}

void
free_input_buf(struct input_buf *ibuf)
{
	free(ibuf->buf);
}

static char *
read_line(struct input_buf *ibuf, char **pbuf, size_t *psize)
{
	slist_t slist = NULL;
	int cont;
	
	do {
		size_t len;
		char *ptr;
		if (ibuf->off >= ibuf->size) {
			if (slist)
				break;
			return NULL;
		}
		len = strcspn(ibuf->buf + ibuf->off, "\n");
		ptr = ibuf->buf + ibuf->off;
		ibuf->off += len + 1;

		if (len == 0)
			ibuf->line++;
		else if (ptr[len - 1] == '\n') {
			ibuf->line++;
			len--;
		}
		if (len > 0 && ptr[len - 1] == '\\') {
			len--;
			cont = 1;
		} else 
			cont = 0;

		if (!slist)
			slist = slist_create();
		slist_append(slist, ptr, len);
	} while (cont);
	
	slist_reduce(slist, pbuf, psize);
	slist_free(slist);
	return *pbuf;
}

int
unquote_char (int c)
{
  char *p;
  static char quotetab[] = "\\\\a\ab\bf\fn\nr\rt\t";

  for (p = quotetab; *p; p += 2) 
	  if (*p == c)
		  return p[1];
  return c;
}

char *
copy_string(const char *src)
{
	char *p;
	char *dest = xmalloc(strlen(src) + 1);
	for (p = dest; *src; ) {
		char c = *src++;
		if (c == '\\' && *src) 
			c = unquote_char(*src++);
		*p++ = c;
	}
	*p = 0;
	return dest;
}

struct command_config default_config;
#define SET_DEFAULT(f)				\
	if (default_config.f)			\
		config_tail->f = default_config.f

struct command_config *
new_command_config()
{
	struct command_config *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, config_list, config_tail);
	SET_DEFAULT(trans);
	SET_DEFAULT(arg_head);
	SET_DEFAULT(arg_tail);
	SET_DEFAULT(env);
	SET_DEFAULT(mask);
	SET_DEFAULT(chroot_dir);
	SET_DEFAULT(home_dir);
	SET_DEFAULT(limits);
	SET_DEFAULT(min_uid);
	return p;
}

int
absolute_dir_p(const char *dir)
{
	const char *p;
	enum { state_init, state_dot, state_double_dot } state = state_init;

	if (dir[0] != '/')
		return 0;
	for (p = dir; *p; p++) {
		switch (*p) {
		case '.':
			switch (state) {
			case state_init:
				state = state_dot;
				break;
			case state_dot:
				state = state_double_dot;
				break;
			case state_double_dot:
				state = state_init;
			}
			break;
			
		case '/':
			if (state != state_init) 
				return 0;
			break;

		default:
			state = state_init;
		}
	}
	return state == state_init;
}
	
int
check_dir(const char *dir, struct input_buf *ibuf)
{
	struct stat st;

	if (dir[0] == '~') {
		if (dir[1] == 0)
			return 0;
		if (!absolute_dir_p(dir + 1)) {
			syslog(LOG_NOTICE,
			       "%s:%d: not an absolute directory",
			       ibuf->file, ibuf->line);
			return 1;
		}
	} else if (!absolute_dir_p(dir)) {
		syslog(LOG_NOTICE,
		       "%s:%d: not an absolute directory",
		       ibuf->file, ibuf->line);
		return 1;
	}

	if (stat(dir, &st)) {
		syslog(LOG_NOTICE,
		       "%s:%d: cannot stat %s: %s",
		       ibuf->file, ibuf->line, dir,
		       strerror(errno));
		return 1;
	} else if (!S_ISDIR(st.st_mode)) {
		syslog(LOG_NOTICE,
		       "%s:%d: %s is not a directory",
		       ibuf->file, ibuf->line, dir);
		return 1;
	}
	return 0;
}
	
struct transform_arg *
new_transform_arg(struct command_config *cur)
{
	struct transform_arg *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, cur->arg_head, cur->arg_tail);
	return p;
}

struct match_arg *
new_match_arg(struct command_config *cur)
{
	struct match_arg *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, cur->match_head, cur->match_tail);
	return p;
}

int
parse_cmp_op (enum cmp_op *op, char **pstr)
{
	char *str = *pstr;
	if (*str == '=') {
		if (*++str == '=')
			str++;
		*op = cmp_eq;
	} else if (*str == '>') {
		if (*++str == '=') {
			str++;
			*op = cmp_ge;
		} else
			*op = cmp_gt;
	} else if (*str == '<') {
		if (*++str == '=') {
			str++;
			*op = cmp_le;
		} else
			*op = cmp_lt;
	} else if (c_isascii(*str) && c_isdigit(*str))
		*op = cmp_eq;
	else
		return 1;
	str = skipws(str);
	*pstr = str;
	return 0;
}

void
parse_input_buf(struct input_buf *ibuf, struct command_config *cur)
{
	char *buf = NULL;
	size_t size = 0;
	int err = 0;

	debug1(2, "Parsing %s", ibuf->file);
	while (read_line(ibuf, &buf, &size)) {
		char *kw, *val;
		char *p;

		p = skipws(buf);
		debug1(2, "read line: %s", p);
		if (p[0] == 0 || p[0] == '#')
			continue;
		kw = p;
		p = eow(kw);
		if (p[0]) {
			*p++ = 0;
			val = skipws(p);
			trimws(val);
		} else
			val = NULL;
		
		if (!val || !*val) {
			syslog(LOG_NOTICE,
			       "%s:%d: invalid statement: missing value",
			       ibuf->file, ibuf->line);
			err = 1;
			continue;
		}

		if (strcmp(kw, "command") == 0) {
			int cflags = REG_EXTENDED;
			int rc;
				
			cur = new_command_config();
			cur->file = ibuf->file;
			cur->line = ibuf->line;
			rc = regcomp(&cur->regex, val, cflags);
			if (rc) {
				char errbuf[512];
				regerror(rc, &cur->regex, errbuf,
					 sizeof(errbuf));
				syslog(LOG_NOTICE,
				       "%s:%d: invalid regexp: %s",
				       ibuf->file, ibuf->line, errbuf);
				err = 1;
			}
		} else if (strcmp(kw, "umask") == 0) {
			char *q;
			unsigned int n = strtoul(val, &q, 8);
			if (*q || (n & ~0777)) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid umask: %s",
				       ibuf->file, ibuf->line, val);
				err = 1;
			} else
				cur->mask = n;
		} else if (strcmp(kw, "min-uid") == 0) {
			char *q;
			unsigned uid = strtoul(val, &q, 10);
			if (*q) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid uid: %s",
				       ibuf->file, ibuf->line, val);
				err = 1;
			} else
				cur->min_uid = uid;
		} else if (strcmp(kw, "chroot") == 0) {
			char *chroot_dir = xstrdup(val);
			if (trimslash(chroot_dir) == 0) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid chroot directory",
				       ibuf->file, ibuf->line);
				err = 1;
			} else if (check_dir(chroot_dir, ibuf))
				err = 1;
			cur->chroot_dir = chroot_dir;
		} else if (strcmp(kw, "limits") == 0) {
			char *q;
			
			if (parse_limits(&cur->limits, val, &q)) {
				syslog(LOG_NOTICE,
				       "%s:%d: unknown limit: %s",
				       ibuf->file, ibuf->line, q);
				err = 1;
			}

		} else if (strcmp(kw, "transform") == 0) {
			cur->trans = compile_transform_expr(val);
		} else if (strncmp(kw, "transform", 9) == 0
			   && kw[9] == '[') {
			char *q;
			struct transform_arg *xarg;
			int n;
			
			if (kw[10] == '$') {
				n = -1;
				q = kw + 11;
			} else 
				n = strtoul(kw + 10, &q, 10);
			if (*q != ']') {
				syslog(LOG_NOTICE,
				       "%s:%d: missing ]",
				       ibuf->file, ibuf->line);
				err = 1;
				continue;
			}
			xarg = new_transform_arg(cur);
			xarg->arg_no = n;
			xarg->trans = compile_transform_expr(val);
		} else if (strncmp(kw, "match", 5) == 0
			   && kw[5] == '[') {
			int cflags = REG_EXTENDED;
			char *q;
			struct match_arg *marg;
			int n;
			int rc;
			
			if (kw[6] == '$') {
				n = -1;
				q = kw + 7;
			} else 
				n = strtoul(kw + 6, &q, 10);
			if (*q != ']') {
				syslog(LOG_NOTICE,
				       "%s:%d: missing ]",
				       ibuf->file, ibuf->line);
				err = 1;
				continue;
			}
			marg = new_match_arg(cur);
			marg->arg_no = n;
			rc = regcomp(&marg->regex, val, cflags);
			if (rc) {
				char errbuf[512];
				regerror(rc, &marg->regex, errbuf,
					 sizeof(errbuf));
				syslog(LOG_NOTICE,
				       "%s:%d: invalid regexp: %s",
				       ibuf->file, ibuf->line, errbuf);
				err = 1;
			}
		} else if (strcmp(kw, "chdir") == 0) {
			char *home_dir = cur->home_dir = xstrdup(val);
			if (trimslash(home_dir) == 0) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid home directory",
				       ibuf->file, ibuf->line);
				err = 1;
			} else if (check_dir(home_dir, ibuf))
				err = 1;
			cur->home_dir = home_dir;

		} else if (strcmp(kw, "argc") == 0) {
			char *q;
			
			if (parse_cmp_op (&cur->cmp_op, &val)) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid opcode",
				       ibuf->file, ibuf->line);
				err = 1;
			}
			cur->argc = strtoul(val, &q, 10);
			if (*q) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid number: %s",
				       ibuf->file, ibuf->line, val);
				err = 1;
			}

		} else if (strcmp(kw, "env") == 0) {
			int rc, n;
			rc = argcv_get(val, NULL, "#", &n, &cur->env);
			if (rc) {
				syslog(LOG_NOTICE,
				       "%s:%d: failed to parse value: %s",
				       ibuf->file, ibuf->line, strerror (rc));
				err = 1;
			}
			
			/* Global statements */
		} else if (strcmp(kw, "debug") == 0) {
			debug_level = strtoul(val, NULL, 0);
			debug1(0, "debug level set to %d", debug_level);
		} else if (strcmp(kw, "sleep-time") == 0) {
			char *q;
			sleep_time = strtoul(val, &q, 10);
			if (*q) {
				syslog(LOG_NOTICE,
				       "%s:%d: invalid time: %s",
				       ibuf->file, ibuf->line, val);
				err = 1;
			}
		} else if (strcmp(kw, "usage-error") == 0) 
			error_msg[usage_error] = copy_string(val);
		else if (strcmp(kw, "nologin-error") == 0) 
			error_msg[nologin_error] = copy_string(val);
		else if (strcmp(kw, "config-error") == 0)
			error_msg[config_error] = copy_string(val);
		else if (strcmp(kw, "system-error") == 0)
			error_msg[system_error] = copy_string(val);
		else {
			syslog(LOG_NOTICE,
			       "%s:%d: unknown statement: %s",
			       ibuf->file, ibuf->line, kw);
			err = 1;
		}
	}
	free(buf);
	debug1(2, "Finished parsing %s", ibuf->file);
	if (err)
		die(config_error, "error parsing config file");
}

const char default_entry[] = "\
command ^.*/sftp-server\n\
  transform[0] s,.*,bin/sftp-server,\n\
  umask 002\n\
  min-uid 1\n\
  chroot ~\n\
  chdir /";

void
parse_config()
{
	struct input_buf buf;

	memset(&default_config, 0, sizeof default_config);
	if (init_input_buf(&buf, CONFIG_FILE) == 0) {
		parse_input_buf(&buf, &default_config);
		free_input_buf(&buf);
	} else {
		init_input_string(&buf, default_entry);
		parse_input_buf(&buf, NULL);
		free_input_buf(&buf);
	}
}
