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
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <cf.h>

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

size_t
trimslash(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && s[len-1] == '\\')
		s[--len] = 0;
	return len;
}


static int
parse_file_mode(const char *val, mode_t *mode)
{
	char *q;
	unsigned int n = strtoul(val, &q, 8);
	if (*q || (n & ~0777))
		return 1;
	*mode = n;
	return 0;
}

static int
parsegid(char *val, gid_t *pgid)
{
	struct group *grp;

	if (isdigit(val[0])) {
		char *p;
		unsigned long n = strtoul(val, &p, 10);
		
		if (*p == 0) {
			*pgid = n;
			return 0;
		}
	}
		
	grp = getgrnam(val);
	if (!grp)
		return 1;
	*pgid = grp->gr_gid;
	return 0;
}

static int
parseuid(char *val, uid_t *puid)
{
	struct passwd *pwd;

	if (isdigit(val[0])) {
		char *p;
		unsigned long n = strtoul(val, &p, 10);
		
		if (*p == 0) {
			*puid = n;
			return 0;
		}
	}
	pwd = getpwnam(val);
	if (!pwd)
		return 1;
	*puid = pwd->pw_uid;
	return 0;
}

struct input_buf {
	CFSTREAM *cf;
	char *file;
	int line;
	struct input_buf *next;
};

typedef struct input_buf *input_buf_ptr;

void
init_input_buf(input_buf_ptr *ibufptr, input_buf_ptr next,
	       CFSTREAM *cf, char const *filename, int line)
{
	input_buf_ptr ibuf;
	
	ibuf = xmalloc(sizeof(*ibuf));
	ibuf->cf = cf;
	ibuf->file = xstrdup(filename);
	ibuf->line = line;
	ibuf->next = next;
	*ibufptr = ibuf;
}
		
void
free_input_buf(input_buf_ptr *ibufptr)
{
	if (ibufptr && *ibufptr) {
		input_buf_ptr ibuf = *ibufptr;
		cfstream_close(ibuf->cf);
		/* FIXME: We cannot free ibuf->file, because it is stored
		   in rule->tag. Need a hash table for it. */
		free(ibuf);
		*ibufptr = NULL;
	}
}

static char *
read_line_plain(input_buf_ptr ibuf, char **pbuf, size_t *psize)
{
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0; 
	int c;
	
	while (1) {
		c = cfstream_getc(ibuf->cf);
		if (c == 0)
			break;
		if (len == size)
			buf = x2realloc(buf, &size);
		buf[len] = c;
		if (c == '\n') {
			ibuf->line++;
			if (len > 0 && buf[len-1] == '\\') {
				len--;
			} else 
				break;
		} else
			len++;
	}
	if (buf) {
		if (len == size)
			buf = x2realloc(buf, &size);
		buf[len] = 0;
	}
	*pbuf = buf;
	*psize = len;
	return buf;
}

static char *
read_line(input_buf_ptr *ibufptr, char **pbuf, size_t *psize)
{
	do {
		char *p = read_line_plain(*ibufptr, pbuf, psize);
		if (p)
			return p;
		else {
			input_buf_ptr next = (*ibufptr)->next;
			debug(3, _("Finished parsing %s"), (*ibufptr)->file);
			free_input_buf(ibufptr);
			*ibufptr = next;
			if (next)
				debug(3,
				      _("Resuming parsing %s from line %d"),
				      next->file, next->line);
		}
	} while (*ibufptr);
	return NULL;
}

static int
unquote_char (int c)
{
  char *p;
  static char quotetab[] = "\\\\a\ab\bf\fn\nr\rt\t";

  for (p = quotetab; *p; p += 2) 
	  if (*p == c)
		  return p[1];
  return c;
}

static char *
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
check_dir(const char *dir, input_buf_ptr ibuf)
{
	struct stat st;

	if (dir[0] == '~') {
		if (dir[1] && !absolute_dir_p(dir + 1)) {
			logmsg(LOG_NOTICE,
			       "%s:%d: %s",
			       ibuf->file, ibuf->line,
			       _("not an absolute directory name"));
			return 1;
		}
		return 0;
	} else if (!absolute_dir_p(dir)) {
		logmsg(LOG_NOTICE,
		       "%s:%d: %s",
		       ibuf->file, ibuf->line,
		       _("not an absolute directory name"));
		return 1;
	}

	if (stat(dir, &st)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: cannot stat %s: %s"),
		       ibuf->file, ibuf->line, dir,
		       strerror(errno));
		return 1;
	} else if (!S_ISDIR(st.st_mode)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: %s is not a directory"),
		       ibuf->file, ibuf->line, dir);
		return 1;
	}
	return 0;
}
	
int
parse_cmp_op(enum cmp_op *op, char **pstr)
{
	char *str = *pstr;
	if (*str == '=') {
		if (*++str == '=')
			str++;
		*op = cmp_eq;
	} else if (*str == '!') {
		if (*++str == '=')
			str++;
		*op = cmp_ne;
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
_parse_negation(struct test_node **pnode, char *val)
{
	if (val[0] == '!' && val[1] != '=') {
		struct test_node *neg = new_test_node(test_not);
		neg->v.arg[0] = *pnode;
		*pnode = neg;
		val = skipws(val + 1);
	}
	return val;
}

static int
numstrtonum(input_buf_ptr ibuf, char *val,
	    struct test_node *node)
{
	char *q;
	
	node->v.cmp.rarg.num = strtoul(val, &q, 10);
	if (*q) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: invalid number: %s"),
		       ibuf->file, ibuf->line, val);
		return 1;
	}
	return 0;
}

int
parse_numtest(input_buf_ptr ibuf, struct test_node *numtest,
	      char *val, int (*valtonum)(input_buf_ptr, char *,
					 struct test_node *))
{
	if (parse_cmp_op(&numtest->v.cmp.op, &val)
	    && val[strcspn(val, " \t")]) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: invalid opcode"),
		       ibuf->file, ibuf->line);
		return 1;
	}
	return valtonum(ibuf, val, numtest);
}

struct stmt_env {
	char *kw;              /* Keyword (with the index, if specified) */
	char *val;             /* Value */
	int argc;              /* Number of arguments (if TOK_ARGN) */
	char **argv;           /* Parsed out value */
	int index;             /* Index, if given */
	int progmod;           /* Modify program name */
	struct test_node *node;/* New node */
	input_buf_ptr ret_buf; /* Return input buffer, for TOK_NEWBUF */
};

void
regexp_error(input_buf_ptr ibuf, regex_t *regex, int rc)
{
	char errbuf[512];
	regerror(rc, regex, errbuf, sizeof(errbuf));
	logmsg(LOG_NOTICE, _("%s:%d: invalid regexp: %s"),
	       ibuf->file, ibuf->line, errbuf);
}

static int
_parse_re_flags(input_buf_ptr ibuf, struct rush_rule *rule,
		struct stmt_env *env)
{
	int fc = env->argc, i;
	char **fv = env->argv;

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
			       _("%s:%d: unknown regexp flag: %s"),
			       ibuf->file, ibuf->line, p);
			return 1;
		}

		if (enable)
			re_flags |= flag;
		else
			re_flags &= ~flag;
	}
	return 0;
}

static int
check_argc(input_buf_ptr ibuf, struct stmt_env *env, int min, int max)
{
	if (env->argc < min) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: too few arguments"),
		       ibuf->file, ibuf->line);
		return 1;
	}
	if (env->argc > max) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: too many arguments"),
		       ibuf->file, ibuf->line);
		return 1;
	}
	return 0;
}

static int
_parse_command(input_buf_ptr ibuf, struct rush_rule *rule,
	       struct stmt_env *env)
{
	int rc;
	struct test_node *node;
	const char *val;

	node = new_test_node(test_cmps);
	val = _parse_negation(&node, env->val);
	rc = regcomp(&node->v.cmp.rarg.rx, val, re_flags);
	if (rc) 
		regexp_error(ibuf, &node->v.cmp.rarg.rx, rc);
	else {
		node->v.cmp.op = cmp_match;
		node->v.cmp.larg = "$command";
	}
	env->node = node;
	return rc;
}
	
static int
_parse_match(input_buf_ptr ibuf, struct rush_rule *rule,
	     struct stmt_env *env)
{
	struct test_node *node;
	int rc;
	const char *val;
	
	node = new_test_node(test_cmps);
	val = _parse_negation(&node, env->val);
	rc = regcomp(&node->v.cmp.rarg.rx, val, re_flags);
	if (rc) 
		regexp_error(ibuf, &node->v.cmp.rarg.rx, rc);
	else {
		char buf[INT_BUFSIZE_BOUND(uintmax_t)];
		char *p = umaxtostr(env->index, buf);
		node->v.cmp.larg = xmalloc(strlen(p) + 4);
		strcpy(node->v.cmp.larg, "${");
		strcat(node->v.cmp.larg, p);
		strcat(node->v.cmp.larg, "}");
		node->v.cmp.op = cmp_match;
	}
	env->node = node;
	return rc;
}
	
static int
_parse_argc(input_buf_ptr ibuf, struct rush_rule *rule,
	    struct stmt_env *env)
{
	char *val;
	struct test_node *node = new_test_node(test_cmpn);
	env->node = node;
	val = _parse_negation(&env->node, env->val);
	node->v.cmp.larg = "$argc";
	return parse_numtest(ibuf, node, val, numstrtonum);
}

static int
uidtonum(input_buf_ptr ibuf, char *str, struct test_node *node)
{
	uid_t uid;
	
	if (parseuid(str, &uid)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: no such user: %s"),
		       ibuf->file, ibuf->line, str);
		return 1;
	}
	node->v.cmp.rarg.num = uid;
	return 0;
}

static int
_parse_uid(input_buf_ptr ibuf, struct rush_rule *rule,
	   struct stmt_env *env)
{
	char *val;
	struct test_node *node = new_test_node(test_cmpn);
	env->node = node;
	val = _parse_negation(&env->node, env->val);
	node->v.cmp.larg = "$uid";
	return parse_numtest(ibuf, node, val, uidtonum);
}

static int
gidtonum(input_buf_ptr ibuf, char *str, struct test_node *node)
{
	gid_t gid;
	
	if (parsegid(str, &gid)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: no such group: %s"),
		       ibuf->file, ibuf->line, str);
		return 1;
	}
	node->v.cmp.rarg.num = gid;
	return 0;
}

static int
_parse_gid(input_buf_ptr ibuf, struct rush_rule *rule,
	   struct stmt_env *env)
{
	char *val;
	struct test_node *node = new_test_node(test_cmpn);
	env->node = node;
	val = _parse_negation(&env->node, env->val);
	node->v.cmp.larg = "$gid";
	return parse_numtest(ibuf, node, val, gidtonum);
}

static int
_parse_user(input_buf_ptr ibuf, struct rush_rule *rule,
	    struct stmt_env *env)
{
	char *val;
	struct test_node *node;

	if (env->argc == 1) {
		node = new_test_node(test_cmps);
		val = _parse_negation(&node, env->val);
		node->v.cmp.op = cmp_eq;
		node->v.cmp.larg = "$user";
		node->v.cmp.rarg.str = xstrdup(val);
	} else {
		size_t i;
		
		node = new_test_node(test_in);
		val = _parse_negation(&node, env->argv[0]);
		node->v.cmp.op = cmp_in;
		node->v.cmp.larg = "$user";
		node->v.cmp.rarg.strv = xcalloc(env->argc + 1,
						sizeof node->v.cmp.rarg.strv[0]);
		node->v.cmp.rarg.strv[0] = xstrdup(val);
		for (i = 1; i < env->argc; i++)
			node->v.cmp.rarg.strv[i] = xstrdup(env->argv[i]);
		node->v.cmp.rarg.strv[i] = NULL;
	}
	env->node = node;
	return 0;
}

static int
_parse_group(input_buf_ptr ibuf, struct rush_rule *rule,
	     struct stmt_env *env)
{
	char *val;
	struct test_node *node;
	size_t i;
		
	node = new_test_node(test_member);
	val = _parse_negation(&node, env->argv[0]);
	node->v.groups = xcalloc(env->argc + 1, sizeof node->v.groups[0]);
	node->v.groups[0] = xstrdup(val);
	for (i = 1; i < env->argc; i++)
		node->v.groups[i] = xstrdup(env->argv[i]);
	node->v.groups[i] = NULL;
	env->node = node;
	return 0;
}

static int
_parse_umask(input_buf_ptr ibuf, struct rush_rule *rule,
	     struct stmt_env *env)
{
	return parse_file_mode(env->val, &rule->mask);
}

static int
_parse_chroot(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	char *chroot_dir = xstrdup(env->val);
	if (trimslash(chroot_dir) == 0) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: invalid chroot directory"),
		       ibuf->file, ibuf->line);
		return 1;
	} else if (check_dir(chroot_dir, ibuf))
		return 1;
	rule->chroot_dir = chroot_dir;
	return 0;
}

static int
_parse_limits(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	char *q;
			
	if (parse_limits(&rule->limits, env->val, &q)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: unknown limit: %s"),
		       ibuf->file, ibuf->line, q);
		return 1;
	}
	return 0;
}

static struct transform_node *
_parse_transform_common(input_buf_ptr ibuf, struct rush_rule *rule,
			struct stmt_env *env)
{
	struct transform_node *node;
	char *expr;
	
	if (check_argc(ibuf, env, 1, 3))
		return NULL;
	else if (env->argc == 3 && strcmp(env->argv[1], "~")) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: expected ~ as the second argument, but found %s"),
		       ibuf->file, ibuf->line, env->argv[2]);
		return NULL;
	}
	node = new_transform_node(rule, transform_set);
	switch (env->argc) {
	case 1:
		expr = env->argv[0];
		break;
	case 2:
		expr = env->argv[1];
		break;
	case 3:
		expr = env->argv[2];
		break;
	default:
		abort();
	}
	node->v.xf.trans = compile_transform_expr(expr, re_flags);
	if (env->argc > 1) 
		node->v.xf.pattern = xstrdup(env->argv[0]);
	else
		node->v.xf.pattern = NULL;
	return node;
}

static int
_parse_transform(input_buf_ptr ibuf, struct rush_rule *rule,
		 struct stmt_env *env)
{
	struct transform_node *node = _parse_transform_common(ibuf, rule, env);
	if (!node)
		return 1;
	node->target.type = target_command;
	return 0;
}

static int
_parse_transform_ar(input_buf_ptr ibuf, struct rush_rule *rule,
		    struct stmt_env *env)
{
	struct transform_node *node = _parse_transform_common(ibuf, rule, env);
	if (!node)
		return 1;
	if (env->progmod)
		node->target.type = target_program;
	else {
		node->target.type = target_arg;
		node->target.v.arg = env->index;
	}
	return 0;
}

static int
_parse_chdir(input_buf_ptr ibuf, struct rush_rule *rule,
	     struct stmt_env *env)
{
	char *home_dir = rule->home_dir = xstrdup(env->val);
	if (trimslash(home_dir) == 0) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: invalid home directory"),
		       ibuf->file, ibuf->line);
		return 1;
	} 
	rule->home_dir = home_dir;
	return 0;
}

static int
_parse_env(input_buf_ptr ibuf, struct rush_rule *rule, struct stmt_env *env)
{
	size_t i = 0;
	
	if (strcmp(env->argv[0], "-") == 0) {
		rule->clrenv = 1;
		i++;
	}
	for (; i < env->argc; i++) {
		char *name = env->argv[i];
		size_t len = strcspn(name, "=");
		char *value;
		size_t vlen;
		char *mem = NULL;
		size_t msize = 0;
		enum envar_type type;
		
		if (name[0] == '-') {
			/* Unset directive */
			name++;
			len--;
			
			if (name[len]) {
				value = name + len + 1;
				vlen = strlen(value);
			} else {
				value = NULL;
				vlen = 0;
			}
			
			type = envar_unset;
		} else if (name[len]) {
			if (len == 0)
				/* Skip erroneous entry */
				continue;
			value = name + len + 1;
			vlen = strlen(value);
			name[len] = 0;
			if (name[len-1] == '+') {
				name[--len] = 0;
				if (c_ispunct(value[0])) {
					msize = 2*len + 9 + vlen + 1;
					mem = xmalloc(msize);
					snprintf(mem, msize,
						 "${%s:-}${%s+%c}%s",
						 name, name,
						 value[0], value + 1);
				} else {
					msize = len + vlen + 6;
					snprintf(mem, msize,
						 "${%s:-}%s",
						 name, value);
				}
				value = mem;
				vlen = strlen(value);
			} else if (value[0] == '+') {
				value++;
				vlen--;

				if (vlen > 0 && c_ispunct(value[vlen-1])) {
					int c = value[vlen-1];
					value[--vlen] = 0;
					
					msize = 2*len + 10 + vlen + 1;
					mem = xmalloc(msize);
					snprintf(mem, msize,
						 "%s${%s+%c}${%s:-}",
						 value, name, c, name);
				} else {
					msize = len + vlen + 6;
					snprintf(mem, msize,
						 "%s${%s:-}",
						 value, name);
				}
				value = mem;
				vlen = strlen(value);
			}
			type = envar_set;
		} else {
			value = NULL;
			vlen = 0;
			type = envar_keep;
		}
		new_envar(rule, name, len, value, vlen, type);
		free(mem);
	}
	return 0;
}

/* Global statements */
static int
_parse_debug(input_buf_ptr ibuf, struct rush_rule *rule,
	     struct stmt_env *env)
{
	if (!debug_option) {
		debug_level = strtoul(env->val, NULL, 0);
		debug(0, _("debug level set to %d"), debug_level);
	}
	return 0;
}

static int
_parse_sleep_time(input_buf_ptr ibuf, struct rush_rule *rule,
		  struct stmt_env *env)
{
	char *q;
	sleep_time = strtoul(env->val, &q, 10);
	if (*q) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: invalid time: %s"),
		       ibuf->file, ibuf->line, env->val);
		return 1;
	}
	return 0;
}

static int
_parse_usage_error(input_buf_ptr ibuf, struct rush_rule *rule,
		   struct stmt_env *env)
{
	set_error_msg(usage_error, copy_string(env->val));
	return 0;
}

static int
_parse_nologin_error(input_buf_ptr ibuf, struct rush_rule *rule,
		     struct stmt_env *env)
{
	set_error_msg(nologin_error, copy_string(env->val));
	return 0;
}

static int
_parse_config_error(input_buf_ptr ibuf, struct rush_rule *rule,
		    struct stmt_env *env)
{
	set_error_msg(config_error, copy_string(env->val));
	return 0;
}

static int
_parse_system_error(input_buf_ptr ibuf, struct rush_rule *rule,
		    struct stmt_env *env)
{
	set_error_msg(system_error, copy_string(env->val));
	return 0;
}

static int
_parse_fall_through(input_buf_ptr ibuf, struct rush_rule *rule,
		    struct stmt_env *env RUSH_ARG_UNUSED)
{
	rule->fall_through = 1;
	return 0;
}

static int
_parse_exit(input_buf_ptr ibuf, struct rush_rule *rule,
	    struct stmt_env *env)
{
	const char *val = env->val;
	int error_fd;
	if (c_isdigit(val[0])) {
		char *p;
		unsigned long n = strtoul(val, &p, 10);
		if (!ISWS(p[0]) || n > getmaxfd()) {
			logmsg(LOG_NOTICE,
			       _("%s:%d: invalid file descriptor"),
			       ibuf->file, ibuf->line);
			return 1;
		}
		val = skipws(p);
		error_fd = n;
	} else
		error_fd = 2;
	if (val[0] == '@') {
		if (val[1] != '@')
			rule->error = new_error(error_fd, val + 1, 1);
		else {
			int n = string_to_error_index(val + 1);
			if (n == -1) {
				logmsg(LOG_NOTICE,
				       _("%s:%d: Unknown message reference"),
				       ibuf->file, ibuf->line);
				return 1;
			}
			rule->error = new_standard_error(error_fd, n);
		}
	} else
		rule->error = new_error(error_fd, val, 1);
	return 0;
}

static int
get_bool(const char *val, int *res)
{
	if (strcmp (val, "yes") == 0
	    || strcmp (val, "on") == 0
	    || strcmp (val, "t") == 0
	    || strcmp (val, "true") == 0
	    || strcmp (val, "1") == 0)
		*res = 1;
	else if (strcmp (val, "no") == 0
		 || strcmp (val, "off") == 0
		 || strcmp (val, "nil") == 0
		 || strcmp (val, "false") == 0
		 || strcmp (val, "0") == 0)
		*res = 0;
	else
		return 1;
	return 0;
}

static int
_parse_fork(input_buf_ptr ibuf, struct rush_rule *rule,
	    struct stmt_env *env)
{
	int yes;
	if (get_bool(env->val, &yes)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: expected boolean value, but found `%s'"),
		       ibuf->file, ibuf->line, env->val);
		return 1;
	}
	rule->fork = yes ? rush_true : rush_false;
	return 0;
}

static int
_parse_acct(input_buf_ptr ibuf, struct rush_rule *rule,
	    struct stmt_env *env)
{
	int yes;
	if (get_bool(env->val, &yes)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: expected boolean value, but found `%s'"),
		       ibuf->file, ibuf->line, env->val);
		return 1;
	}
	rule->acct = yes ? rush_true : rush_false;
	return 0;
}

static int
_parse_acct_file_mode(input_buf_ptr ibuf, struct rush_rule *rule,
		      struct stmt_env *env)
{
	return parse_file_mode(env->val, &rushdb_file_mode);
}

static int
_parse_acct_dir_mode(input_buf_ptr ibuf, struct rush_rule *rule,
		     struct stmt_env *env)
{
	return parse_file_mode(env->val, &rushdb_dir_mode);
}

static int
_parse_acct_umask(input_buf_ptr ibuf, struct rush_rule *rule,
		  struct stmt_env *env)
{
	return parse_file_mode(env->val, &rushdb_dir_mode);
}


static int
copy_part(const char *cstr, const char *p, char **pbuf)
{
	size_t len = p - cstr;
	char *buf = malloc(len + 1);
	if (!buf) {
		free(buf);
		return 1;
	}
	memcpy(buf, cstr, len);
	buf[len] = 0;
	*pbuf = buf;
	return 0;
}

static int
parse_conn(const char *cstr, char **pport, char **ppath)
{
	const char *p = strchr (cstr, ':');

	if (!p) {
		*pport = NULL;
		*ppath = strdup(cstr);
		return *ppath == NULL;
	} else if (copy_part(cstr, p, ppath))
		return 1;
	else
		cstr = p + 1;
	*pport = strdup(cstr);
	return *pport == NULL;
}

struct socket_family {
	char *name;
	size_t len;
	int family;
};

static struct socket_family socket_family[] = {
#define DEF(s, f) { #s, sizeof(#s)-1, f }
	DEF(inet, AF_INET),
	DEF(unix, AF_UNIX),
	DEF(local, AF_UNIX),
	{ NULL }
#undef DEF
};

static struct socket_family *
find_family(const char *s, size_t len)
{
	struct socket_family *fp;
	for (fp = socket_family; fp->name; fp++)
		if (len == fp->len)
			return fp;
	return NULL;
}

static int
parse_url(input_buf_ptr ibuf, const char *cstr, 
	  int *pfamily, char **pport, char **ppath)
{
	const char *p;
	
	p = strchr(cstr, ':');
	if (p) {
		struct socket_family *fp = find_family(cstr, p - cstr);

		if (!fp) {
			logmsg(LOG_NOTICE,
			       _("%s:%d: unknown address family"),
			       ibuf->file, ibuf->line);
			return 1;
		}

		*pfamily = fp->family;
		
		cstr = p + 1;
		if (cstr[0] == '/') {
			if (cstr[1] == '/') {
				return parse_conn(cstr + 2, pport, ppath);
			} else if (*pfamily == AF_UNIX) {
				*pport = NULL;
				*ppath = strdup(cstr);
				return *ppath == NULL;
			}
		} else {
			logmsg(LOG_NOTICE,
			       _("%s:%d: malformed URL"),
			       ibuf->file, ibuf->line);
			return 1;
		}
	} else {
		*pfamily = AF_UNIX;
		*pport = NULL;
		*ppath = strdup(cstr);
		return *ppath == NULL;
	}
	return 0;
}

static int
make_socket(input_buf_ptr ibuf, int family,
	    char *port, char *path, struct rush_sockaddr *pa)
{
	union {
		struct sockaddr sa;
		struct sockaddr_un s_un;
		struct sockaddr_in s_in;
	} addr;
	socklen_t socklen;
	short pnum;
	long num;
	char *p;
	
	switch (family) {
	case AF_UNIX:
		if (port) {
			logmsg(LOG_NOTICE,
			       _("%s:%d: port is meaningless for UNIX sockets"),
			       ibuf->file, ibuf->line);
			return 1;
		}
		if (strlen(path) > sizeof addr.s_un.sun_path) {
			errno = EINVAL;
			logmsg(LOG_NOTICE,
			       _("%s:%d: UNIX socket name too long"),
				ibuf->file, ibuf->line);
			return 1;
		}
		
		addr.sa.sa_family = PF_UNIX;
		socklen = sizeof(addr.s_un);
		strcpy(addr.s_un.sun_path, path);
		break;

	case AF_INET:
		addr.sa.sa_family = PF_INET;
		socklen = sizeof(addr.s_in);

		num = pnum = strtol(port, &p, 0);
		if (*p == 0) {
			if (num != pnum) {
				logmsg(LOG_NOTICE,
				       _("%s:%d: bad port number"),
					ibuf->file, ibuf->line);
				return -1;
			}
			pnum = htons(pnum);
		} else {
			struct servent *sp = getservbyname(port, "tcp");
			if (!sp) {
				logmsg(LOG_NOTICE,
				       _("%s:%d: unknown service name"),
				       ibuf->file, ibuf->line);
				return -1;
			}
			pnum = sp->s_port;
		}

		if (!path)
			addr.s_in.sin_addr.s_addr = INADDR_ANY;
		else {
			struct hostent *hp = gethostbyname(path);
			if (!hp) {
				logmsg(LOG_NOTICE,
				       _("%s:%d: unknown host name %s"),
				       ibuf->file, ibuf->line, path);
				return 1;
			}
			addr.sa.sa_family = hp->h_addrtype;
			switch (hp->h_addrtype) {
			case AF_INET:
				memmove(&addr.s_in.sin_addr, hp->h_addr, 4);
				addr.s_in.sin_port = pnum;
				break;

			default:
				logmsg(LOG_NOTICE,
				       _("%s:%d: unsupported address family"),
				       ibuf->file, ibuf->line);
				return 1;
			}
		}
		break;

	default:
		logmsg(LOG_NOTICE,
		       _("%s:%d: unsupported address family"),
		       ibuf->file, ibuf->line);
		return 1;
	}
	pa->len = socklen;
	pa->sa = xmalloc(socklen);
	memcpy(pa->sa, &addr.sa, socklen);
	return 0;
}
		
static int
_parse_post_socket(input_buf_ptr ibuf, struct rush_rule *rule,
		   struct stmt_env *env)
{
	int family;
	char *path;
	char *port;
	int rc;
	
	if (parse_url(ibuf, env->val,  &family, &port, &path))
		return 1;
	rc = make_socket(ibuf, family, port ? port : "tcpmux", path,
			 &rule->post_sockaddr);
	free(port);
	free(path);
	return rc;
}


static int
_parse_text_domain(input_buf_ptr ibuf, struct rush_rule *rule,
		   struct stmt_env *env)
{
	rule->i18n.text_domain = xstrdup(env->val);
	return 0;
}

static int
_parse_locale_dir(input_buf_ptr ibuf, struct rush_rule *rule,
		  struct stmt_env *env)
{
	rule->i18n.localedir = xstrdup(env->val);
	return 0;
}

static int
_parse_locale(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	const char *val;
	if (strcmp(env->val, "\"\"") == 0)
		val = "";
	else
		val = env->val;
	rule->i18n.locale = xstrdup(val);
	return 0;
}

static int
_parse_include(input_buf_ptr ibuf, struct rush_rule *rule,
	       struct stmt_env *env)
{
	char *name;
	struct stat st;
	CFSTREAM *cf;
	
	name = expand_tilde(env->val, rush_pw->pw_dir);

	if (trimslash(name) == 0) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: invalid include file name"),
		       ibuf->file, ibuf->line);
		free(name);
		return 1;
	}

	if (stat(name, &st)) {
		if (errno == ENOENT) {
			debug(1, _("Ignoring non-existing include file %s"),
			      name);
			free(name);
			env->ret_buf = NULL;
			return 0;
		}
		logmsg(LOG_NOTICE,
		       _("%s:%d: cannot stat file %s: %s"),
		       ibuf->file, ibuf->line,
		       name, strerror(errno));
		free(name);
		return 1;
	}
	if (S_ISDIR(st.st_mode)) {
		char *file = make_file_name(name, rush_pw->pw_name);
		free(name);
		if (access(file, F_OK)) {
			return 0;
		}
		name = file;
	}
	cf = cfstream_open_file(name);
	init_input_buf(&env->ret_buf, ibuf, cf, name, 1);
	free(name);
	return 0;
}

static int
_parse_include_security(input_buf_ptr ibuf, struct rush_rule *rule,
			struct stmt_env *env)
{
	int i;
	int rc = 0;
	
	for (i = 0; i < env->argc; i++) {
		if (cfck_keyword(env->argv[i])) {
			logmsg(LOG_NOTICE,
			       _("%s:%d: unknown keyword: %s"),
			       ibuf->file, ibuf->line, env->argv[i]);
			rc++;
		}
	}
	return rc;
}

static int
_parse_interactive(input_buf_ptr ibuf, struct rush_rule *rule,
		   struct stmt_env *env)
{
	rule->interactive = 1;
	return 0;
}
/*
           0     1    2    3     4       5
   map[N] FILE DELIM KEY FIELD FIELD [DEFAULT]

   map[0] /etc/rush/shells : ${user} 1 2 default
*/

static int
_parse_map_ar(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	struct transform_node *node;
	unsigned long n;
	char *p;

	if (check_argc(ibuf, env, 5, 6))
		return 1;

	node = new_transform_node(rule, transform_map);
	if (env->progmod)
		node->target.type = target_program;
	else {
		node->target.type = target_arg;
		node->target.v.arg = env->index;
	}

	node->v.map.file = xstrdup(env->argv[0]);
	node->v.map.delim = xstrdup(env->argv[1]);
	node->v.map.key = xstrdup(env->argv[2]);
	
	n = node->v.map.key_field = strtoul(env->argv[3], &p, 10);
	if (*p || n != node->v.map.key_field) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: key field is not a number"),
		       ibuf->file, ibuf->line);
		return 1;
	}

	n = node->v.map.val_field = strtoul(env->argv[4], &p, 10);
	if (*p || n != node->v.map.val_field) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: value field is not a number"),
		       ibuf->file, ibuf->line);
		return 1;
	}

	if (env->argc == 6)
		node->v.map.defval = xstrdup(env->argv[5]);
	return 0;
}

static int
_parse_delete_ar(input_buf_ptr ibuf, struct rush_rule *rule,
		 struct stmt_env *env)
{
	struct transform_node *node =
		new_transform_node(rule, transform_delete);
	node->target.type = target_arg;
	node->target.v.arg = env->index;
	node->v.arg_end = env->index;
	return 0;
}

static int
get_arg_index(char *str, char **end)
{
	if (*str == '$') {
		*end = str + 1;
		return -1;
	} 
	return strtol(str, end, 10);
}

static int
_parse_delete(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	struct transform_node *node;
	int from, to;
	char *p;
	
	if (check_argc(ibuf, env, 2, 2))
		return 1;

	from = get_arg_index(env->argv[0], &p);
	if (*p) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: %s: not a number"),
		       ibuf->file, ibuf->line, env->argv[0]);
		return 1;
	}
	to = get_arg_index(env->argv[1], &p);
	if (*p) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: %s: not a number"),
		       ibuf->file, ibuf->line, env->argv[1]);
		return 1;
	}
	
	node = new_transform_node(rule, transform_delete);
	node->target.type = target_arg;
	node->target.v.arg = from;
	node->v.arg_end = to;
	return 0;
}

static int
_parse_set(input_buf_ptr ibuf, struct rush_rule *rule,
	   struct stmt_env *env)
{
	struct transform_node *node = new_transform_node(rule, transform_set);
	node->target.type = target_command;
	node->v.xf.pattern = xstrdup(env->val);
	node->v.xf.trans = NULL;
	return 0;
}
	
static int
_parse_set_ar(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	struct transform_node *node = new_transform_node(rule, transform_set);
	if (env->progmod)
		node->target.type = target_program;
	else {
		node->target.type = target_arg;
		node->target.v.arg = env->index;
	}
	node->v.xf.pattern = xstrdup(env->val);
	node->v.xf.trans = NULL;
	return 0;
}

static int
_parse_setvar(input_buf_ptr ibuf, struct rush_rule *rule,
	      struct stmt_env *env)
{
	struct transform_node *node = new_transform_node(rule, transform_set);
	node->target.type = target_var;
	node->target.v.name = xstrdup(env->argv[0]);
	node->v.xf.pattern = xstrdup(env->argv[1]);
	node->v.xf.trans = NULL;
	return 0;
}	

static int
_parse_unsetvar(input_buf_ptr ibuf, struct rush_rule *rule,
		struct stmt_env *env)
{
	struct transform_node *node =
		new_transform_node(rule, transform_delete);
	node->target.type = target_var;
	node->target.v.name = xstrdup(env->argv[0]);
	return 0;
}	

static int
_parse_newgroup(input_buf_ptr ibuf, struct rush_rule *rule,
		struct stmt_env *env)
{
	if (parsegid(env->val, &rule->gid)) {
		logmsg(LOG_NOTICE,
		       _("%s:%d: no such group: %s"),
		       ibuf->file, ibuf->line, env->val);
		return 1;
	}
	return 0;
}


#define TOK_NONE   0x000   /* No flags */
#define TOK_ARG    0x001   /* Token requires an argument */
#define TOK_ARGN   0x002   /* Token requires one or more arguments */
#define TOK_IND    0x004   /* Token must be followed by an index */
#define TOK_RUL    0x008   /* Token is valid only within a rule */
#define TOK_NEWBUF 0x010   /* Token may create new input buffer */
#define TOK_CRT    0x024   /* Index after the token may contain ^ */
#define TOK_SED    0x042   /* Arguments contain sed-exprs */
#define TOK_ENV    0x080   /* Expand environment variables */
#define TOK_ASSC   0x104   /* Token must be followed by associative index */
#define TOK_DFL   TOK_ARG|TOK_RUL
#define TOK_DFLN  TOK_ARGN|TOK_RUL

struct token {
	char *name;
	size_t namelen;
	int flags;
	int (*parser) (input_buf_ptr, struct rush_rule *, struct stmt_env *);
};

struct token toktab[] = {
#define KW(s) s, sizeof(s)-1
	{ KW("command"),          TOK_DFL, _parse_command },
	{ KW("match"),            TOK_DFL|TOK_IND, _parse_match },
	{ KW("argc"),             TOK_DFL, _parse_argc },
	{ KW("uid"),              TOK_DFL, _parse_uid },
	{ KW("gid"),              TOK_DFL, _parse_gid },
	{ KW("user"),             TOK_DFLN, _parse_user },
	{ KW("group"),            TOK_DFLN, _parse_group },
	{ KW("transform"),        TOK_DFL|TOK_SED, _parse_transform },
	{ KW("transform"),        TOK_DFL|TOK_IND|TOK_SED|TOK_CRT,
	  _parse_transform_ar },
	{ KW("map"),              TOK_RUL|TOK_ARGN|TOK_IND|TOK_CRT,
	  _parse_map_ar },
	{ KW("delete"),           TOK_RUL|TOK_IND, _parse_delete_ar },
	{ KW("delete"),           TOK_RUL|TOK_ARGN, _parse_delete },
	{ KW("set"),              TOK_DFL, _parse_set },  
	{ KW("set"),              TOK_DFL|TOK_IND|TOK_CRT,
	  _parse_set_ar },
	{ KW("setvar"),           TOK_RUL|TOK_ARG|TOK_ASSC, _parse_setvar },
	{ KW("unsetvar"),         TOK_RUL|TOK_ASSC, _parse_unsetvar },
	{ KW("umask"),            TOK_DFL, _parse_umask },
	{ KW("chroot"),           TOK_DFL, _parse_chroot },
	{ KW("limits"),           TOK_DFL, _parse_limits },
	{ KW("chdir"),            TOK_DFL, _parse_chdir },
	{ KW("env"),              TOK_DFLN|TOK_ENV, _parse_env },
	{ KW("fork"),             TOK_DFL, _parse_fork },
	{ KW("acct"),             TOK_DFL, _parse_acct },
	{ KW("post-socket"),      TOK_DFL, _parse_post_socket },
	{ KW("text-domain"),      TOK_DFL, _parse_text_domain },
	{ KW("locale-dir"),       TOK_DFL, _parse_locale_dir },
	{ KW("locale"),           TOK_DFL, _parse_locale },
	{ KW("include"),          TOK_ARG|TOK_NEWBUF, _parse_include },
	{ KW("fall-through"),     TOK_RUL, _parse_fall_through },
	{ KW("exit"),             TOK_RUL, _parse_exit },
	{ KW("debug"),            TOK_ARG, _parse_debug },
	{ KW("sleep-time"),       TOK_ARG, _parse_sleep_time },
	{ KW("usage-error"),      TOK_ARG, _parse_usage_error },
	{ KW("nologin-error"),    TOK_ARG, _parse_nologin_error },
	{ KW("config-error"),     TOK_ARG, _parse_config_error },
	{ KW("system-error"),     TOK_ARG, _parse_system_error },
	{ KW("regexp"),           TOK_ARGN, _parse_re_flags },
	{ KW("include-security"), TOK_ARGN, _parse_include_security },
	{ KW("interactive"),      TOK_RUL, _parse_interactive }, 
	{ KW("acct-file-mode"),   TOK_ARG, _parse_acct_file_mode },
	{ KW("acct-dir-mode"),    TOK_ARG, _parse_acct_dir_mode },
	{ KW("acct-umask"),       TOK_ARG, _parse_acct_umask },
	{ KW("newgroup"),         TOK_DFL, _parse_newgroup },
	{ KW("newgrp"),           TOK_DFL, _parse_newgroup },
	{ NULL }
#undef KW
};

struct token *
find_token(const char *name, int *plen)
{
	struct token *tok;
	int len = strcspn(name, "[");
	
	for (tok = toktab; tok->name; tok++) {
		if (len == tok->namelen && strncmp(tok->name, name, len) == 0
		    && (name[len] == 0 ? (tok->flags & TOK_IND) == 0
			: (tok->flags & TOK_IND))) {
			*plen = len;
			return tok;
		}
	}
	return NULL;
}

void
parse_input_buf(input_buf_ptr ibuf)
{
	char *buf = NULL;
	size_t size = 0;
	int err = 0;
	struct rush_rule *rule = NULL;
	unsigned rule_num = 0;

	debug(3, _("Parsing %s"), ibuf->file);
	while (read_line(&ibuf, &buf, &size)) {
		char *kw, *val;
		char *p;
		struct token *tok;
		int len;
		int rc;
		struct stmt_env env;
		
		memset(&env, 0, sizeof env);

		p = skipws(buf);
		debug(3, "%s:%d: %s", ibuf->file, ibuf->line, p);
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
			rule_num++;
			rule = new_rush_rule();
			if (val && val[0])
				rule->tag = xstrdup(val);
			else {
				char buf[INT_BUFSIZE_BOUND(unsigned)];
				char *s = uinttostr(rule_num, buf);
				rule->tag = xmalloc(strlen(s) + 2);
				rule->tag[0] = '#';
				strcpy(rule->tag + 1, s);
			}
			rule->file = ibuf->file;
			rule->line = ibuf->line;
			continue;
		}

		tok = find_token(kw, &len);
		if (!tok) {
			logmsg(LOG_NOTICE,
			       _("%s:%d: unknown statement: %s"),
			       ibuf->file, ibuf->line, kw);
			err = 1;
			continue;
		}

		env.kw = kw;
		env.val = val;

		kw += len;
		if (tok->flags & TOK_IND) {
			char *q;

			if ((tok->flags & TOK_ASSC) == TOK_ASSC) {
				q = strchr(kw + 1, ']');
				if (q) {
					size_t len = q - kw - 1;
					env.argc = 2;
					env.argv = xcalloc(env.argc + 1,
							   sizeof(env.argv[0]));
					env.argv[0] = xmalloc(len + 1);
					memcpy(env.argv[0], kw + 1, len);
					env.argv[0][len] = 0;
					env.argv[1] = env.val
						       ? xstrdup(env.val)
						       : NULL;
				} /* else: handled below */
			} else if (kw[1] == '$') {
				env.index = -1;
				q = kw + 2;
			} else if (tok->flags & TOK_CRT && kw[1] == '^') {
				env.progmod = 1;
				q = kw + 2;
			} else
				env.index = strtol(kw + 1, &q, 10);
			if (*q != ']') {
				logmsg(LOG_NOTICE,
				       _("%s:%d: missing ]"),
				       ibuf->file, ibuf->line);
				err = 1;
				continue;
			}
		}
		
		if (tok->flags & (TOK_ARG | TOK_ARGN) && !(val && *val)) {
			logmsg(LOG_NOTICE,
			       _("%s:%d: invalid statement: missing value"),
			       ibuf->file, ibuf->line);
			err = 1;
			continue;
		}

		if (tok->flags & TOK_ARGN) {
			int flags = WRDSF_DEFFLAGS|WRDSF_COMMENT;
			struct wordsplit ws;

			if (tok->flags & TOK_SED)
				flags |= WRDSF_SED_EXPR;

			if (tok->flags & TOK_ENV) {
				flags &= ~WRDSF_NOVAR;
				flags |= WRDSF_ENV;
				ws.ws_env = (const char **) environ;
			}
			
			ws.ws_comment = "#";
			if (wordsplit(val, &ws, flags)) {
				logmsg(LOG_NOTICE,
				       _("%s:%d: failed to parse value: %s"),
				       ibuf->file, ibuf->line,
				       wordsplit_strerror(&ws));
				err = 1;
				continue;
			}				
			
			env.argc = ws.ws_wordc;
			env.argv = ws.ws_wordv;
			ws.ws_wordc = 0;
			ws.ws_wordv = NULL;

			wordsplit_free(&ws);
		}
		
		if (tok->flags & TOK_RUL) {
			if (!rule) {
				logmsg(LOG_NOTICE,
				       _("%s:%d: statement cannot be used outside a rule"),
				       ibuf->file, ibuf->line);
				err = 1;
				continue;
			}
		} 

		rc = tok->parser(ibuf, rule, &env);
		err |= rc;
		if (rc == 0) {
			if (tok->flags & TOK_NEWBUF && env.ret_buf) {
				env.ret_buf->next = ibuf;
				ibuf = env.ret_buf;
				debug(3, _("Parsing %s"), ibuf->file);
			}
			if (env.node) {
				if (rule->test_node) {
					struct test_node *np =
						new_test_node(test_and);
					np->v.arg[0] = rule->test_node;
					np->v.arg[1] = env.node;
					rule->test_node = np;
				} else
					rule->test_node = env.node;
			}
		}
		if (tok->flags & (TOK_ARGN|TOK_ASSC)) 
			argcv_free(env.argc, env.argv);
	}
	free(buf);
	if (err)
		die(config_error, NULL, _("errors parsing config file"));
}

void
cfparse_old(CFSTREAM *cf, char const *filename, int line)
{
	input_buf_ptr buf;

	init_input_buf(&buf, NULL, cf, filename, line - 1);
	parse_input_buf(buf);
}
