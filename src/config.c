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

static int re_flags = REG_EXTENDED;

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
		if (errno == ENOENT && !lint_option) {
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
		else if (ptr[len] == '\n') 
			ibuf->line++;
		
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
	size_t len = strlen(src);
	char *dest;
	int add_nl = len > 0 && src[len-1] != '\n';
	
	dest = xmalloc(len + (add_nl ? 1 : 0) + 1);
	for (p = dest; *src; ) {
		char c = *src++;
		if (c == '\\' && *src) 
			c = unquote_char(*src++);
		*p++ = c;
	}
	if (add_nl)
		*p++ = '\n';
	*p = 0;
	return dest;
}

struct rush_rule *
new_rush_rule()
{
	struct rush_rule *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, rule_head, rule_tail);
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
		if (dir[1] && !absolute_dir_p(dir + 1)) {
			logmsg(LOG_NOTICE,
			       "%s:%d: not an absolute directory",
			       ibuf->file, ibuf->line);
			return 1;
		}
		return 0;
	} else if (!absolute_dir_p(dir)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: not an absolute directory",
		       ibuf->file, ibuf->line);
		return 1;
	}

	if (stat(dir, &st)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: cannot stat %s: %s",
		       ibuf->file, ibuf->line, dir,
		       strerror(errno));
		return 1;
	} else if (!S_ISDIR(st.st_mode)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: %s is not a directory",
		       ibuf->file, ibuf->line, dir);
		return 1;
	}
	return 0;
}
	
struct transform_node *
new_transform_node(struct rush_rule *rule, enum transform_node_type type)
{
	struct transform_node *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, rule->transform_head, rule->transform_tail);
	p->type = type;
	return p;
}

struct test_node *
new_test_node(struct rush_rule *rule, enum test_type type)
{
	struct test_node *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, rule->test_head, rule->test_tail);
	p->type = type;
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

static char *
_parse_negation(struct test_node *node, char *val)
{
	if (val[0] == '!' && val[1] != '=') {
		node->negate = 1;
		val = skipws(val + 1);
	}
	return val;
}

int
parse_numtest(struct input_buf *ibuf, struct test_numeric_node *numtest,
	      char *val)
{
	char *q;
	
	if (parse_cmp_op (&numtest->op, &val)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: invalid opcode",
		       ibuf->file, ibuf->line);
		return 1;
	}
	numtest->val = strtoul(val, &q, 10);
	if (*q) {
		logmsg(LOG_NOTICE,
		       "%s:%d: invalid number: %s",
		       ibuf->file, ibuf->line, val);
		return 1;
	}
	return 0;
}

int
parse_strv(struct input_buf *ibuf, struct test_node *node, char *val)
{
	int n, rc = argcv_get(val, NULL, "#", &n, &node->v.strv);
	if (rc)
		logmsg(LOG_NOTICE,
		       "%s:%d: failed to parse value: %s",
		       ibuf->file, ibuf->line, strerror (rc));
	return rc;
}

void
regexp_error(struct input_buf *ibuf, regex_t *regex, int rc)
{
	char errbuf[512];
	regerror(rc, regex, errbuf, sizeof(errbuf));
	logmsg(LOG_NOTICE, "%s:%d: invalid regexp: %s",
	       ibuf->file, ibuf->line, errbuf);
}

static int
_parse_re_flags(struct input_buf *ibuf, struct rush_rule *rule,
		char *kw, char *val)
{
	int fc, i;
	char **fv;

	if ((i = argcv_get(val, NULL, "#", &fc, &fv))) {
		logmsg(LOG_NOTICE,
		       "%s:%d: failed to parse value: %s",
		       ibuf->file, ibuf->line, strerror (i));
		return 1;
	}
	for (i = 0; i < fc; i++) {
		int enable, flag;
		char *p = fv[i];
		
		switch (*p) {
		case '+':
			p++;
			enable = 1;
			break;

		case '-':
			p++;
			enable = 0;
			break;

		default:
			enable = 1;
		}
		
		if (strcmp(p, "extended") == 0) 
			flag = REG_EXTENDED;
		else if (strcmp(fv[i], "basic") == 0) {
			flag = REG_EXTENDED;
			enable = !enable;
		} else if (strcmp(fv[i], "icase") == 0
			 || strcmp(fv[i], "ignore-case") == 0)
			flag = REG_ICASE;
		else {
			logmsg(LOG_NOTICE,
			       "%s:%d: unknown regexp flag: %s",
			       ibuf->file, ibuf->line, p);
			return 1;
		}

		if (enable)
			re_flags |= flag;
		else
			re_flags &= ~flag;
	}
	argcv_free(fc, fv);
	return 0;
}

static int
_parse_command(struct input_buf *ibuf, struct rush_rule *rule,
	       char *kw, char *val)
{
	int rc;
	struct test_node *node;

	node = new_test_node(rule, test_cmdline);
	val = _parse_negation(node, val);
	rc = regcomp(&node->v.regex, val, re_flags|REG_NOSUB);
	if (rc) 
		regexp_error(ibuf, &node->v.regex, rc);
	return rc;
}
	
static int
_parse_match(struct input_buf *ibuf, struct rush_rule *rule,
	     char *kw, char *val)
{
	char *q;
	struct test_node *node;
	int rc, n;

	if (kw[1] == '$') {
		n = -1;
		q = kw + 2;
	} else 
		n = strtoul(kw + 1, &q, 10);
	if (*q != ']') {
		logmsg(LOG_NOTICE,
		       "%s:%d: missing ]",
			       ibuf->file, ibuf->line);
		return 1;
	}
	node = new_test_node(rule, test_arg);
	node->v.arg.arg_no = n;
	val = _parse_negation(node, val);
	rc = regcomp(&node->v.arg.regex, val, re_flags|REG_NOSUB);
	if (rc) 
		regexp_error(ibuf, &node->v.regex, rc);
	return rc;
}
	
static int
_parse_argc(struct input_buf *ibuf, struct rush_rule *rule,
	    char *kw, char *val)
{
	struct test_node *node = new_test_node(rule, test_argc);
	val = _parse_negation(node, val);
	return parse_numtest(ibuf, &node->v.num, val);
}

static int
_parse_uid(struct input_buf *ibuf, struct rush_rule *rule,
	   char *kw, char *val)
{
	struct test_node *node = new_test_node(rule, test_uid);
	val = _parse_negation(node, val);
	return parse_numtest(ibuf, &node->v.num, val);
}

static int
_parse_gid(struct input_buf *ibuf, struct rush_rule *rule,
	   char *kw, char *val)
{
	struct test_node *node = new_test_node(rule, test_gid);
	val = _parse_negation(node, val);
	return parse_numtest(ibuf, &node->v.num, val);
}

static int
_parse_user(struct input_buf *ibuf, struct rush_rule *rule,
	    char *kw, char *val)
{
	struct test_node *node = new_test_node(rule, test_user);
	val = _parse_negation(node, val);
	return parse_strv(ibuf, node, val);
}

static int
_parse_group(struct input_buf *ibuf, struct rush_rule *rule,
	     char *kw, char *val)
{
	struct test_node *node = new_test_node(rule, test_group);
	val = _parse_negation(node, val);
	return parse_strv(ibuf, node, val);
}

static int
_parse_umask(struct input_buf *ibuf, struct rush_rule *rule,
	     char *kw, char *val)
{
	char *q;
	unsigned int n = strtoul(val, &q, 8);
	if (*q || (n & ~0777)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: invalid umask: %s",
		       ibuf->file, ibuf->line, val);
		return 1;
	} else
		rule->mask = n;
	return 0;
}

static int
_parse_chroot(struct input_buf *ibuf, struct rush_rule *rule,
	      char *kw, char *val)
{
	char *chroot_dir = xstrdup(val);
	if (trimslash(chroot_dir) == 0) {
		logmsg(LOG_NOTICE,
		       "%s:%d: invalid chroot directory",
		       ibuf->file, ibuf->line);
		return 1;
	} else if (check_dir(chroot_dir, ibuf))
		return 1;
	rule->chroot_dir = chroot_dir;
	return 0;
}

static int
_parse_limits(struct input_buf *ibuf, struct rush_rule *rule,
	      char *kw, char *val)
{
	char *q;
			
	if (parse_limits(&rule->limits, val, &q)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: unknown limit: %s",
		       ibuf->file, ibuf->line, q);
		return 1;
	}
	return 0;
}

static int
_parse_transform(struct input_buf *ibuf, struct rush_rule *rule,
		 char *kw, char *val)
{
	struct transform_node *node;
	node = new_transform_node(rule, transform_cmdline);
	node->trans = compile_transform_expr(val);
	return 0;
}

static int
_parse_transform_ar(struct input_buf *ibuf, struct rush_rule *rule,
		    char *kw, char *val)
{
	char *q;
	struct transform_node *node;
	int n;
	
	if (kw[1] == '$') {
		n = -1;
		q = kw + 2;
	} else 
		n = strtoul(kw + 1, &q, 10);
	if (*q != ']') {
		logmsg(LOG_NOTICE,
		       "%s:%d: missing ]",
		       ibuf->file, ibuf->line);
		return 1;
	}
	node = new_transform_node(rule, transform_arg);
	node->arg_no = n;
	node->trans = compile_transform_expr(val);
	return 0;
}

static int
_parse_chdir(struct input_buf *ibuf, struct rush_rule *rule,
	     char *kw, char *val)
{
	char *home_dir = rule->home_dir = xstrdup(val);
	if (trimslash(home_dir) == 0) {
		logmsg(LOG_NOTICE,
		       "%s:%d: invalid home directory",
		       ibuf->file, ibuf->line);
		return 1;
	}
	else if (!rule->chroot_dir && check_dir(home_dir, ibuf))
		return 1;
	rule->home_dir = home_dir;
	return 0;
}

static int
_parse_env(struct input_buf *ibuf, struct rush_rule *rule,
	   char *kw, char *val)
{
	int rc, n;
	rc = argcv_get(val, NULL, "#", &n, &rule->env);
	if (rc) 
		logmsg(LOG_NOTICE,
		       "%s:%d: failed to parse value: %s",
		       ibuf->file, ibuf->line, strerror (rc));
	return rc;
}

/* Global statements */
static int
_parse_debug(struct input_buf *ibuf, struct rush_rule *rule,
	     char *kw, char *val)
{
	if (!debug_option) {
		debug_level = strtoul(val, NULL, 0);
		debug1(0, "debug level set to %d", debug_level);
	}
	return 0;
}

static int
_parse_sleep_time(struct input_buf *ibuf, struct rush_rule *rule,
		  char *kw, char *val)
{
	char *q;
	sleep_time = strtoul(val, &q, 10);
	if (*q) {
		logmsg(LOG_NOTICE,
		       "%s:%d: invalid time: %s",
		       ibuf->file, ibuf->line, val);
		return 1;
	}
	return 0;
}

static int
_parse_usage_error(struct input_buf *ibuf, struct rush_rule *rule,
		   char *kw, char *val)
{
	error_msg[usage_error] = copy_string(val);
	return 0;
}

static int
_parse_nologin_error(struct input_buf *ibuf, struct rush_rule *rule,
		     char *kw, char *val)
{
	error_msg[nologin_error] = copy_string(val);
	return 0;
}

static int
_parse_config_error(struct input_buf *ibuf, struct rush_rule *rule,
		    char *kw, char *val)
{
	error_msg[config_error] = copy_string(val);
	return 0;
}

static int
_parse_system_error(struct input_buf *ibuf, struct rush_rule *rule,
		    char *kw, char *val)
{
	error_msg[system_error] = copy_string(val);
	return 0;
}

static int
_parse_fall_through(struct input_buf *ibuf, struct rush_rule *rule,
		    char *kw, char *val)
{
	rule->fall_through = 1;
	return 0;
}

static int
_parse_exit(struct input_buf *ibuf, struct rush_rule *rule,
	    char *kw, char *val)
{
	if (c_isdigit(val[0])) {
		unsigned long n = strtoul(val, &val, 10);
		if (!ISWS(val[0]) || n > getmaxfd()) {
			logmsg(LOG_NOTICE,
			       "%s:%d: invalid file descriptor",
			       ibuf->file, ibuf->line);
			return 1;
		}
		val = skipws(val);
		rule->error_fd = n;
	} else
		rule->error_fd = 2;
	rule->error_msg = copy_string(val);
	return 0;
}


#define TOK_NONE  0x00   /* No flags */
#define TOK_ARG   0x01   /* Token requires an argument */
#define TOK_IND   0x02   /* Token must be followed by an index */
#define TOK_RUL   0x04   /* Token is valid only within a rule */

#define TOK_DFL   TOK_ARG|TOK_RUL

struct token {
	char *name;
	int flags;
	int (*parser) (struct input_buf *, struct rush_rule *,
		       char *, char *);
};


struct token toktab[] = {
	{ "command",       TOK_DFL, _parse_command },
	{ "match",         TOK_RUL|TOK_IND, _parse_match },
	{ "argc",          TOK_DFL, _parse_argc },
	{ "uid",           TOK_DFL, _parse_uid },
	{ "gid",           TOK_DFL, _parse_gid },
	{ "user",          TOK_DFL, _parse_user },
	{ "group",         TOK_DFL, _parse_group },
	{ "transform",     TOK_DFL, _parse_transform },
	{ "transform",     TOK_RUL|TOK_IND, _parse_transform_ar },
	{ "umask",         TOK_DFL, _parse_umask },
	{ "chroot",        TOK_DFL, _parse_chroot },
	{ "limits",        TOK_DFL, _parse_limits },
	{ "chdir",         TOK_DFL, _parse_chdir },
	{ "env",           TOK_DFL, _parse_env },
	{ "fall-through",  TOK_RUL, _parse_fall_through },
	{ "exit",          TOK_RUL, _parse_exit },
	{ "debug",         TOK_ARG, _parse_debug },
	{ "sleep-time",    TOK_ARG, _parse_sleep_time },
	{ "usage-error",   TOK_ARG, _parse_usage_error },
	{ "nologin-error", TOK_ARG, _parse_nologin_error },
	{ "config-error",  TOK_ARG, _parse_config_error },
	{ "system-error",  TOK_ARG, _parse_system_error },
	{ "regexp",        TOK_ARG, _parse_re_flags },
	{ NULL }
};

struct token *
find_token(const char *name, int *plen)
{
	struct token *tok;
	int len = strcspn(name, "[");
	
	for (tok = toktab; tok->name; tok++) {
		if (strncmp(tok->name, name, len) == 0
		    && (name[len] == 0 ? (tok->flags & TOK_IND) == 0
			: (tok->flags & TOK_IND))) {
			*plen = len;
			return tok;
		}
	}
	return NULL;
}

void
parse_input_buf(struct input_buf *ibuf)
{
	char *buf = NULL;
	size_t size = 0;
	int err = 0;
	struct rush_rule *rule = NULL;

	debug1(3, "Parsing %s", ibuf->file);
	while (read_line(ibuf, &buf, &size)) {
		char *kw, *val;
		char *p;
		struct token *tok;
		int len;
		
		p = skipws(buf);
		debug3(3, "%s:%d: %s", ibuf->file, ibuf->line, p);
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
		
		if (strcmp(kw, "rule") == 0) {
			rule = new_rush_rule();
			if (val && val[0])
				rule->tag = xstrdup (val);
			rule->file = ibuf->file;
			rule->line = ibuf->line;
			continue;
		}

		tok = find_token(kw, &len);
		if (!tok) {
			logmsg(LOG_NOTICE,
			       "%s:%d: unknown statement: %s",
			       ibuf->file, ibuf->line, kw);
			err = 1;
			continue;
		}

		if (tok->flags & TOK_ARG && !(val && *val)) {
			logmsg(LOG_NOTICE,
			       "%s:%d: invalid statement: missing value",
			       ibuf->file, ibuf->line);
			err = 1;
			continue;
		}

		if (tok->flags & TOK_RUL) {
			if (!rule) {
				logmsg(LOG_NOTICE,
				       "%s:%d: statement cannot be used outside a rule",
				       ibuf->file, ibuf->line);
				err = 1;
				continue;
			}
		} 
		
		err |= tok->parser(ibuf, rule, kw + len, val);
	}
	free(buf);
	debug1(3, "Finished parsing %s", ibuf->file);
	if (err)
		die(config_error, "error parsing config file");
}

#ifdef RUSH_DEFAULT_CONFIG
const char default_entry[] = 
#include RUSH_DEFAULT_CONFIG
;	
#endif

void
parse_config()
{
	struct input_buf buf;

	if (init_input_buf(&buf, rush_config_file) == 0) {
		parse_input_buf(&buf);
		free_input_buf(&buf);
#ifdef RUSH_DEFAULT_CONFIG
	} else {
		init_input_string(&buf, default_entry);
		parse_input_buf(&buf);
		free_input_buf(&buf);
#endif
	}
}
