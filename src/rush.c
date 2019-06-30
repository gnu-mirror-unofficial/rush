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
#include <cf.h>

extern char **environ;

char *rush_config_file = CONFIG_FILE;
int lint_option = 0;
int scanner_test = 0;
unsigned sleep_time = 5;
unsigned debug_level;
int debug_option;
char *dump_option;
int parser_traces;
struct rush_rule *rule_head, *rule_tail;
struct passwd *rush_pw;

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

struct error_msg {
	char *text;          /* Message text */
	int custom;          /* True, if the message was customized */
};

struct error_msg error_msg[] = {
        /* usage_error */
	{ N_("You are not permitted to execute this command.\n"             
	     "Contact the systems administrator for further assistance.\n"), },
        
        /* nologin_error */
        { N_("You do not have interactive login access to this machine.\n" 
	     "Contact the systems administrator for further assistance.\n") },
        
        /* config_error */
        { N_("Local configuration error occurred.\n" 
	     "Contact the systems administrator for further assistance.\n") },
        
        /* system_error */
        { N_("A system error occurred while attempting to execute command.\n" 
	     "Contact the systems administrator for further assistance.\n") }
};

void
set_error_msg(enum error_type type, char *text)
{
	error_msg[type].text = text;
	error_msg[type].custom = 1;
}

int
string_to_error_index(const char *name)
{
	static const char *error_msg_name[] = {
		[usage_error]   = "usage-error",
		[nologin_error] = "nologin-error",
		[config_error]  = "config-error",
		[system_error]  = "system-error",
		NULL
	};
	int i;

	for (i = 0; error_msg_name[i]; i++)
		if (strcmp(error_msg_name[i], name) == 0)
			return i;
	return -1;
}

struct rush_error *
new_standard_error(int fd, int idx)
{
	struct rush_error *err = xmalloc(sizeof(*err));
	err->fd = fd;
	err->idx = idx;
	return err;
}

static inline char *
error_text_ptr(struct rush_error const *err)
{
	return (char*)(err + 1);
}

struct rush_error *
new_error(int fd, char const *text, int unescape)
{
	struct rush_error *err;
	size_t len = strlen(text);
	int add_nl = len > 0 && text[len-1] != '\n';
	int c;
	char *p;
	
	err = xmalloc(sizeof(*err) + strlen(text) + (add_nl ? 1 : 0) + 1);
	err->fd = fd;
	err->idx = -1;
	p = error_text_ptr(err);
	while ((c = *text++) != 0) {
		if (unescape && c == '\\' && *text) {
			int c1 = wordsplit_c_unquote_char(*text);
			if (c1) 
				c = c1;
			else
				c = *text;
			text++;
		}	
		*p++ = c;
	}
	if (add_nl)
		*p++ = '\n';
	*p = 0;
	
	return err;
}

char const *
rush_error_msg(struct rush_error const *err, struct rush_i18n const *i18n)
{	
	const char *msg;
	if (err->idx >= 0) {
		msg = error_msg[err->idx].text;
		if (error_msg[err->idx].custom) {
			/* If it is a customized version, translate it via
			   user-supplied i18n */
			if (i18n) 
				msg = user_gettext(i18n->locale,
						   i18n->text_domain,
						   i18n->localedir,
						   msg);
		} else
			msg = gettext(msg);
	} else
		msg = gettext(error_text_ptr(err));
	return msg;
}

void
send_msg(const char *msg, size_t len)
{
        if (write(STDERR_FILENO, msg, len) < 0) {
		logmsg(LOG_ERR,
		       _("failed to write message to stderr: %s"),
		       strerror(errno));
		if (write(STDOUT_FILENO, msg, len) < 0)
			logmsg(LOG_ERR,
			       _("failed to write message to stdout: %s"),
			       strerror(errno));
	}
}

void
vlogmsg(int prio, const char *fmt, va_list ap)
{
	if (lint_option) {
		fprintf(stderr, "%s: ", program_name);
		switch (prio) {
		case LOG_DEBUG:
			fprintf(stderr, _("Debug: "));
			break;
			
		case LOG_INFO:      
			fprintf(stderr, _("Info: "));
			break;
			
		case LOG_NOTICE:
			fprintf(stderr, _("Notice: "));
			break;

		case LOG_WARNING:
			fprintf(stderr, _("Warning: "));
			break;
			
		case LOG_ERR:       
		case LOG_CRIT:      
		case LOG_ALERT:     
		case LOG_EMERG:
			fprintf(stderr, _("Error: "));
		}
		vfprintf(stderr, fmt, ap);
		fputs("\n", stderr);
	} else
		vsyslog(prio, fmt, ap);
}

void
logmsg(int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlogmsg(prio, fmt, ap);
	va_end(ap);
}

void
die(enum error_type type, struct rush_i18n *i18n, const char *fmt, ...)
{
	if (fmt) {
		va_list ap;
		va_start(ap, fmt);
		vlogmsg(LOG_ERR, fmt, ap);
		va_end(ap);
	}
	if (!lint_option) {
		const char *msg = error_msg[type].text;
		if (error_msg[type].custom) {
			/* If it is a customized version, translate it via
			   user-supplied i18n */
			if (i18n) 
				msg = user_gettext(i18n->locale,
						   i18n->text_domain,
						   i18n->localedir,
						   msg);
		} else
			msg = gettext(msg);
		send_msg(msg, strlen(msg));
		sleep(sleep_time);
	}
        exit(1);
}

void
die_usage(struct cfloc const *loc, char const *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
	vcferror(loc, fmt, ap);
	va_end(ap);
	die(usage_error, NULL, NULL);
}

void
xalloc_die()
{
        die(system_error, NULL, _("Not enough memory"));
}

static rush_bool_t
eval_cmpn(struct test_node *node,
	  struct rush_rule *rule, struct rush_request *req)
{
	char *str = rush_expand_string(node->v.cmp.larg, req);
	char *p;
	unsigned long n;

	errno = 0;
	n = strtoul(str, &p, 0);
	if (errno || *p)
		die(system_error, NULL, _("%s: not a number"), str);
	free(str);
	switch (node->v.cmp.op) {
	case cmp_eq:
		return n == node->v.cmp.rarg.num;
	case cmp_ne:
		return n != node->v.cmp.rarg.num;
	case cmp_lt:
		return n < node->v.cmp.rarg.num;
	case cmp_le:
		return n <= node->v.cmp.rarg.num;
	case cmp_gt:
		return n > node->v.cmp.rarg.num;
	case cmp_ge:
		return n >= node->v.cmp.rarg.num;
	default:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: unrecognized opcode %d"),
		    __FILE__, __LINE__, node->v.cmp.op);
	}
}

static int
eval_regex(struct rush_request *req, regex_t *rx, char const *subj)
{
	int rc;
	struct rush_backref *bref = &req->backref[!req->backref_cur];
	size_t n = rx->re_nsub + 1;
	if (n > bref->maxmatch) {
		bref->match = xrealloc(bref->match,
				       sizeof(bref->match[0]) * n);
		bref->maxmatch = n;
	}
	rc = regexec(rx, subj, bref->maxmatch, bref->match, 0);
	if (rc == 0) {
		free(bref->subject);
		bref->subject = xstrdup(subj);
		bref->nmatch = n;
		req->backref_cur = !req->backref_cur;
	}
	return rc;
}

static rush_bool_t
eval_cmps(struct test_node *node,
	  struct rush_rule *rule, struct rush_request *req)
{
	char *str = rush_expand_string(node->v.cmp.larg, req);
	rush_bool_t res = rush_false;
	
	switch (node->v.cmp.op) {
	case cmp_eq:
		res = strcmp(str, node->v.cmp.rarg.str) == 0;
		break;
	case cmp_ne:
		res = strcmp(str, node->v.cmp.rarg.str) != 0;
		break;
	case cmp_match:
		res = ! eval_regex(req, &node->v.cmp.rarg.rx, str);
		break;
	default:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: unrecognized opcode %d"),
		    __FILE__, __LINE__, node->v.cmp.op);
	}
	free(str);
	return res;
}

static rush_bool_t
eval_in(struct test_node *node,
	struct rush_rule *rule, struct rush_request *req)
{
	size_t i;
	rush_bool_t res = rush_false;
	char *str = rush_expand_string(node->v.cmp.larg, req);

	for (i = 0; node->v.cmp.rarg.strv[i]; i++)
		if (strcmp(str, node->v.cmp.rarg.strv[i]) == 0) {
			res = rush_true;
			break;
		}
	free(str);
	return res;
}
	
static rush_bool_t
groupmember(char const *gname, struct passwd const *pw)
{
        struct group *grp = getgrnam(gname);
        if (grp) {
		char **p;
		
		if (pw->pw_gid == grp->gr_gid)
                        return rush_true;

		for (p = grp->gr_mem; *p; p++) {
			if (strcmp(*p, pw->pw_name) == 0)
				return rush_true;
		}
        }
        return rush_false;
}

static rush_bool_t
eval_member(struct test_node *node,
	    struct rush_rule *rule, struct rush_request *req)
{
	size_t i;

	for (i = 0; node->v.groups[i]; i++) {
		if (groupmember(node->v.groups[i], req->pw))
			return rush_true;
	}
	return rush_false;
}

rush_bool_t
test_eval(struct test_node *node,
	  struct rush_rule *rule, struct rush_request *req)
{
	switch (node->type) {
	case test_cmpn:
		return eval_cmpn(node, rule, req);
		
	case test_cmps:
		return eval_cmps(node, rule, req);

	case test_in:
		return eval_in(node, rule, req);

	case test_group:
		return eval_member(node, rule, req);
		
	case test_and:
		if (!test_eval(node->v.arg[0], rule, req))
			return 0;
		return test_eval(node->v.arg[1], rule, req);
		
	case test_or:
		if (test_eval(node->v.arg[0], rule, req))
			return 1;
		return test_eval(node->v.arg[1], rule, req);

	case test_not:
		return ! test_eval(node->v.arg[0], rule, req);

	default:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: unrecognized node type %d"),
		    __FILE__, __LINE__, node->type);
	}
}

char *
make_file_name(const char *dir, const char *name)
{
	size_t dlen = strlen(dir);
	size_t len = dlen + strlen(name) + 1;
	char *res = xmalloc(len + 1);
	strcpy(res, dir);
	if (dlen > 0 && res[dlen-1] != '/')
		res[dlen++] = '/';
	strcpy(res + dlen, name);
	return res;
}
 
char *
expand_tilde(const char *dir, const char *home)
{
        char *res;
        if (dir[0] == '~') {
                if (dir[1] == '/') {
                        size_t hlen = strlen(home);
                        size_t len = hlen + strlen(dir + 1);
                        res = xmalloc(len + 1);
                        strcpy(res, home);
                        if (hlen > 0 && res[hlen-1] != '/')
                                res[hlen++] = '/';
                        strcpy(res + hlen, dir + 2);
                } else
                        res = xstrdup(home);
        } else
                res = xstrdup(dir);
        return res;
}

char *
expand_dir(const char *dir, struct rush_request *req)
{
	char *exp = rush_expand_string(dir, req);
	if (exp[0] == '~') {
		char *t = expand_tilde(exp, req->pw->pw_dir);
		free(exp);
		exp = t;
	}
	return exp;
}

void
request_set_env(struct rush_request *req)
{
	size_t i;

	for (i = 0; environ[i]; i++)
		;
	req->env_count = i;
	req->env_max = i + 1;
	req->env = xcalloc(req->env_max, sizeof(req->env[0]));

	for (i = 0; i < req->env_count; i++)
		req->env[i] = xstrdup(environ[i]);
	req->env[i] = NULL;
}

static ssize_t
getenvind(struct rush_request *req, char const *name, char **pval)
{
	size_t i;
	for (i = 0; i < req->env_count; i++) {
		char const *p;
		char *q;

		for (p = name, q = req->env[i]; *p == *q; p++, q++)
			;
		if (*p == 0 && *q == '=') {
			if (pval)
				*pval = q + 1;
			return i;
		}
	}
	return -1;
}

/* Return true if VAR[0]@LEN matches EV, false if only the name part matches,
   and undefined otherwise.
   Arguments:
     EV    - a pointer to an envar entry,
     VAR   - an entry from the environ array,
     LEN   - length of the variable name part of VAR (in other words,
             position of the first = character in VAR).
*/
static enum rush_three_state
envarmatch(struct envar *ev, char const *var, int len)
{
	if (ev->value) {
		if (strncmp(ev->name, var, len) == 0) {
			return strcmp(var + len + 1, ev->value) == 0
				? rush_true
				: rush_false;
		}
	} else if (wildmatch(ev->name, var, len) == 0) {
		return rush_true;
	}
	return rush_undefined;
}

/* Return true if environ entry VAR must be kept in the environment, according
   to RULE. */
static rush_bool_t
keep_envar(struct rush_rule *rule, char const *var)
{
	struct envar *ev;
	int len = strcspn(var, "=");
	for (ev = rule->envar_head; ev; ev = ev->next) {
		if (ev->type == envar_keep) {
			enum rush_three_state res = envarmatch(ev, var, len);
			switch (res) {
			case rush_true:
			case rush_false:
				return res;
			case rush_undefined:
				/* go on */
				break;
			}
		}
	}
	return rush_false;
}

/* Unset environment variable described by EV. */
static void
unset_envar(struct rush_request *req, struct envar *ev)
{
	size_t i;
	for (i = 0; i < req->env_count; ) {
		int len = strcspn(req->env[i], "=");
		if (envarmatch(ev, req->env[i], len) == rush_true) {
			free(req->env[i]);
			memmove(req->env + i, req->env + i + 1,
				(req->env_count - i) * sizeof(req->env[0]));
			req->env_count--;
		} else
			i++;
	}
}

static void
env_setup(struct rush_rule *rule, struct rush_request *req)
{
	struct envar *ev;
	size_t i;
	
	if (rule->clrenv) {
		size_t keep_count = 0;
		for (i = 0; i < req->env_count; i++) {
			if (keep_envar(rule, req->env[i])) {
				if (i > keep_count) {
					req->env[keep_count] = req->env[i];
					req->env[i] = NULL;
				}
				keep_count++;
			} else {
				free(req->env[i]);
				req->env[i] = NULL;
			}
		}
		req->env_count = keep_count;
	}

	for (ev = rule->envar_head; ev; ev = ev->next) {
		char *val;
		ssize_t n;
		size_t len;
		
		switch (ev->type) {
		case envar_keep:
			/* Skip it */
			break;

		case envar_unset:
			unset_envar(req, ev);
			break;

		case envar_set:
			val = rush_expand_string(ev->value, req);
			n = getenvind(req, ev->name, NULL);
			if (n == -1) {
				if (req->env_count + 1 >= req->env_max)
					req->env = x2nrealloc(req->env,
							      &req->env_max,
							      sizeof(req->env[0]));
				n = req->env_count++;
				req->env[req->env_count] = NULL;
			}
			free(req->env[n]);
			len = strlen(ev->name) + strlen(val) + 2;
			req->env[n] = xmalloc(len);
			strcat(strcat(strcpy(req->env[n], ev->name), "="), val);
			free(val);
			break;

		case envar_eval:
			free(rush_expand_string(ev->value, req));
			break;
			
		default:
			die(system_error, NULL,
			    _("INTERNAL ERROR at %s:%d: invalid envar type %d"),
			    __FILE__, __LINE__, ev->type);
		}
	}
        if (__debug_p(2)) {
                logmsg(LOG_DEBUG, _("Final environment:"));
                for (i = 0; req->env[i]; i++)
                        logmsg(LOG_DEBUG, "%4zu: %s", i, req->env[i]);
        }
}

static void
reparse_cmdline(struct rush_request *req)
{
        struct wordsplit ws;
	
        argcv_free(req->argc, req->argv);
	ws.ws_options = WRDSO_NOVARSPLIT | WRDSO_NOCMDSPLIT;
	if (wordsplit(req->cmdline, &ws, WRDSF_DEFFLAGS|WRDSF_OPTIONS))
		die(system_error, &req->i18n, _("wordsplit(%s) failed: %s"),
                    req->cmdline, wordsplit_strerror(&ws));
	wordsplit_get_words(&ws, &req->argc, &req->argv);
	wordsplit_free(&ws);

	free(req->prog);
	req->prog = NULL;
}

static void
rebuild_cmdline(struct rush_request *req)
{
        free(req->cmdline);
        req->cmdline = argcv_string(req->argc, req->argv);
}


#define ARG_NO(n,argc) (((n) < 0) ? (argc) + (n) : (n))

static int
get_arg_no(int index, struct rush_request *req)
{
	int arg_no = ARG_NO(index, req->argc);
	if (arg_no < 0 || arg_no > req->argc)
		die(config_error,
		    &req->i18n, 
		    _("no argument at index %d in command: %s"),
		    index,
		    req->cmdline);
	return arg_no;
}

/* Remove from the Nth argument of the request REQ the option described
   by OPT, with its argument (if any). TAIL points to the first character
   after the option and is used to decide whether the argument follows the
   option immediately or is placed in the next argv entry.
 */
static int
remove_optarg(struct rush_request *req, struct option_defn *opt,
	      size_t n, char *tail)
{
	size_t c;

	if (opt->s_opt[1] == ':') {
		if (*tail)
			c = 1;
		else if (opt->s_opt[2] == ':')
			c = 1;
		else
			c = 2;
	} else
		c = 1;

	if (n + c < req->argc) {
		memmove(&req->argv[n], &req->argv[n + c],
			(req->argc - n + 1 - c) * sizeof req->argv[0]);
		req->argc -= c;
		return 1;
	}
	return 0;
}

/* Remove all occurrences of the option OPT from REQ.
   For the sake of clarity, in the comments below the word "argument"
   means an argv entry, and the word "parameter" means argument passed
   to an option,
 */
static void
remove_option(struct rush_request *req, struct option_defn *opt)
{
	size_t i;
	/* Length of the long option */
	size_t l_len = opt->l_opt ? strlen(opt->l_opt) : 0;
	/* Flag indicating whether a rebuild is required */
	int mod = 0;

	for (i = 1; i < req->argc; i++)	{
		char *arg = req->argv[i];
		if (*arg == '-') {
			char *p;

			++arg;
			if (*arg == '-') {
				/* It is a long option */
				/* ------------------- */

				/* Length of the argument without initial -- */
				size_t a_len;

				/* Skip past the initial -- */
				++arg;
				if (*arg == 0)
					/* No more options */
					break;
				if (opt->l_opt == NULL)
					/* No long option requested */
					continue;
				/* Check if option parameter is supplied */
				a_len = strcspn(arg, "=");
				if (l_len < a_len)
					/* Argument is longer than the option
					   name. */
					continue;
				if (arg[a_len] == '=' && opt->s_opt[1] != ':')
					/* A parameter is supplied, but the
					   option does not take any. */
					continue;
				if (memcmp(arg, opt->l_opt, a_len))
					/* Argument doesn't match initial option
					   prefix. */
					continue;
				/* Save the character following the option name
				   for further use */
				p = arg + a_len;
			} else if ((p = strchr(arg, opt->s_opt[0]))) {
				/* It is a short option */
				/* -------------------- */

				if (opt->s_opt[1] == 0) {
					/* No parameters. Delete the option
					   letter. */
					memmove(p, p + 1, strlen(p + 1) + 1);
					if (*arg) {
						/* An option cluster still
						   present in the argument:
						   no need to remove it. */
						continue;
					}
					/* Remove the argument otherwise. */
				} else if (p > arg) {
					if (p[1] || opt->s_opt[2] == ':')
						/* A parameter is supplied or
						   option takes an optional
						   parameter. Remove the option
						   and its parameter */
						*p = 0;
					/* Retain the remaining part of the
					   option cluster. */
					continue;
				}
			} else {
				/* Skip unrecognized short option */
				continue;
			}

			/* Remove the option (and its parameter, if any) */
			if (remove_optarg(req, opt, i, p + 1)) {
				i--;
				mod = 1;
			}
		}
	}
	if (mod)
		rebuild_cmdline(req);
}

static void
rush_transform(struct transform_node *node, struct rush_request *req)
{
	char **target_ptr;
	char *target_src;
	char *newval = NULL;
	int arg_no;
	void (*postprocess)(struct rush_request *) = NULL;
	
	if (node->type == transform_remopt) {
		debug(2, _("Removing option %s %s"), node->v.remopt.s_opt,
		      node->v.remopt.l_opt ? node->v.remopt.l_opt : "(null)");
		remove_option(req, &node->v.remopt);
		return;
	}

	switch (node->target.type) {
	case target_command:
		/* Command line */
		target_ptr = &req->cmdline;
		target_src = req->cmdline;
		postprocess = reparse_cmdline;
		debug(2, "%s", _("Transforming command line"));
		break;
		
	case target_program:
		/* Executable program name */
		target_ptr = &req->prog;
		target_src = PROGFILE(req);
		debug(2, _("Transforming program name (%s)"), target_src);
		break;

	case target_arg:
		/* Single command line argument */
		arg_no = get_arg_no(node->target.v.arg.idx, req);
		if (arg_no == req->argc || node->target.v.arg.ins) {
			req->argv = xrealloc(req->argv,
					     (req->argc + 2)
					      * sizeof(req->argv[0]));
			req->argc++;
			memmove(&req->argv[arg_no+1], &req->argv[arg_no],
				(req->argc - arg_no) * sizeof req->argv[0]);
			req->argv[arg_no] = NULL;
		}
		target_ptr = &req->argv[arg_no];
		target_src = req->argv[arg_no];
		postprocess = rebuild_cmdline;
		debug(2, _("Transforming argv[%d]"), arg_no);
		break;

	case target_var:
		/* Variable */
		target_ptr = rush_getvarptr(req, node->target.v.name);
		target_src = *target_ptr;
		debug(2, _("Transforming variable %s=%s"),
		      node->target.v.name, target_src ? target_src : "(null)");
		break;
		
	case target_env:
		/* Environment variable */
		die(system_error, NULL,
		    _("environment transformation is not yet implemented"));

	case target_readonly:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: can't modify read-only target"),
		    __FILE__, __LINE__);
	}

	switch (node->type) {
	case transform_set:
		if (node->v.xf.pattern) {
			newval = rush_expand_string(node->v.xf.pattern, req);
			target_src = newval;
		}

		if (node->v.xf.trans) {
			char *p = transform_string(node->v.xf.trans, target_src);
			free(newval);
			newval = p;
		}
		break;

	case transform_map:
		debug(2, _("Transformation map: %s, %s, %s, %u, %u, %s"),
		      node->v.map.file,
		      node->v.map.delim,
		      node->v.map.key,
		      node->v.map.key_field,
		      node->v.map.val_field,
		      node->v.map.defval);
		newval = map_string(&node->v.map, req);
		if (!newval)
			return;
		break;

	default:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: invalid node type %d"),
		    __FILE__, __LINE__, node->type);
		break;
	}
	
	free(*target_ptr);
	*target_ptr = newval;

	if (postprocess)
		postprocess(req);
}

static void
rush_transform_delete(struct transform_node *node, struct rush_request *req)
{
	int arg_no, arg_end, i;
	
	switch (node->target.type) {
	case target_arg:
		/* Single command line argument */
		arg_no = get_arg_no(node->target.v.arg.idx, req);
		arg_end = get_arg_no(node->v.arg_end, req);
		if (arg_end < arg_no) {
			int x = arg_end;
			arg_end = arg_no;
			arg_no = x;
		}
		debug(2, _("Deleting arguments %d-%d"), arg_no, arg_end);
		if (arg_no == 0 || arg_end == 0)
			die(config_error,
			    &req->i18n, _("Deleting argv[0] is prohibited"));
		for (i = arg_no; i <= arg_end; i++) 
			free(req->argv[i]);
		i = arg_end - arg_no + 1;
		memmove(req->argv + arg_no,
			req->argv + arg_end + 1,
			(req->argc - i) * sizeof(req->argv[0]));
		req->argc -= i;
		rebuild_cmdline(req);
		break;

	case target_var:
		rush_request_delvar(req, node->target.v.name);
		break;
		
	case target_env:
		/* Environment variable */
		die(system_error, NULL,
		    _("environment transformation is not yet implemented"));

	default:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: invalid target type %d"),
		    __FILE__, __LINE__, node->type);
	}
}

static void
run_transforms(struct rush_rule *rule, struct rush_request *req)
{
        struct transform_node *node;
	
        for (node = rule->transform_head; node; node = node->next) {
		if (node->type == transform_delete)
			rush_transform_delete(node, req);
		else
			rush_transform(node, req);
	}			
        if (__debug_p(2)) {
                int i;
		logmsg(LOG_DEBUG, _("Program name: %s"), PROGFILE(req));
                logmsg(LOG_DEBUG, _("Final arguments:"));
                for (i = 0; i < req->argc; i++)
                        logmsg(LOG_DEBUG, "% 4d: %s", i, req->argv[i]);
        }
}

static void
acct_on(struct rush_rule *rule, struct rush_request *req, pid_t pid)
{
	struct rush_wtmp wtmp;

	wtmp.pid = pid;
	wtmp.user = req->pw->pw_name;
	wtmp.rule = rule->tag;
	wtmp.command = req->cmdline;
	if (rushdb_start(&wtmp))
		die(system_error,
		    &req->i18n, 
		    _("error writing to database %s: %s"),
		    RUSH_DB, strerror(errno));
}

static void
acct_off(void)
{
	if (rushdb_stop())
		logmsg(LOG_ERR, 
		       _("error writing stop to database file %s: %s"),
		       RUSH_DB, strerror(errno));
	rushdb_close();
}

static void
fork_process(struct rush_rule *rule, struct rush_request *req)
{
	int status;
	pid_t pid;

	signal(SIGCHLD, SIG_DFL);
	
	pid = fork();

	if (pid == 0) {
		return;
	}
	
	if (pid == -1) 
		die(system_error, &req->i18n, 
		    _("%s:%d: %s: cannot fork: %s"),
		    rule->file, rule->line, rule->tag,
		    strerror(errno));

	close(0);
	close(1);
	close(2);

	if (req->acct == rush_true)
		acct_on(rule, req, pid);
	debug(2, _("Forked process %lu"), (unsigned long) pid);
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		debug(2, _("%s: subprocess exited with code %d"),
		      rule->tag, status);
	} else if (WIFSIGNALED(status)) {
		logmsg(LOG_NOTICE, _("%s: subprocess terminated on signal %d"),
		       rule->tag, WTERMSIG(status));
	} else
		logmsg(LOG_NOTICE, _("%s: subprocess terminated"), rule->tag);
	if (req->acct == rush_true) 
		acct_off();
	if (req->post_sockaddr)
		post_socket_send(req->post_sockaddr, rule, req);
	exit(0);
}

static int
membergid(gid_t gid, size_t gc, gid_t *gv)
{
	int i;
	for (i = 0; i < gc; i++)
		if (gv[i] == gid)
			return 1;
	return 0;
}

static void
get_user_groups(struct rush_request *req, size_t *pgidc, gid_t **pgidv)
{
	size_t gidc = 0, n = 0;
	gid_t *gidv = NULL;
	struct group *gr;
	
	n = 32;
	gidv = xcalloc(n, sizeof(gidv[0]));

	gidv[0] = req->gid == NO_GID ? req->pw->pw_gid : req->gid;
	gidc = 1;

	setgrent();
	while ((gr = getgrent())) {
		char **p;
		for (p = gr->gr_mem; *p; p++)
			if (strcmp(*p, req->pw->pw_name) == 0) {
				if (n == gidc) {
					n += 32;
					gidv = xrealloc(gidv,
							n * sizeof(gidv[0]));
				}
				if (!membergid(gr->gr_gid, gidc, gidv))
					gidv[gidc++] = gr->gr_gid;
			}
	}
	endgrent();
	*pgidc = gidc;
	*pgidv = gidv;
}

static void
setowner(struct rush_request *req)
{
	size_t gidc;
	gid_t *gidv;
	
	get_user_groups(req, &gidc, &gidv);
	if (setgroups(gidc, gidv) < 0)
		die(system_error, &req->i18n,
		    "setgroups: %s", strerror(errno));
	if (setgid(gidv[0]))
		die(system_error, &req->i18n, _("cannot enforce gid %lu: %s"),
                    (unsigned long) gidv[0], strerror(errno));
	free(gidv);

        if (setuid(req->pw->pw_uid))
                die(system_error, &req->i18n, _("cannot enforce uid %lu: %s"),
                    (unsigned long) req->pw->pw_uid, strerror(errno));

	if (req->pw->pw_uid && setuid(0) == 0) 
		die(system_error, &req->i18n,
		    _("seteuid(0) succeeded when it should not"));
}

static void
run_rule(struct rush_rule *rule, struct rush_request *req)
{
        debug(2, _("Rule %s at %s:%d matched"),
	      rule->tag, rule->file, rule->line);

	env_setup(rule, req);
        
	if (rule->i18n.text_domain)
		req->i18n.text_domain = rule->i18n.text_domain;
	if (rule->i18n.localedir)
		req->i18n.localedir = rule->i18n.localedir;
	if (rule->i18n.locale)
		req->i18n.locale = rule->i18n.locale;

        if (rule->error) {
		const char *msg = rush_error_msg(rule->error, &rule->i18n);
                debug(2, _("Error message: %s"), msg);
                if (write(rule->error->fd, msg, strlen(msg)) < 0)
                        die(system_error, &req->i18n, 
                            _("Error sending diagnostic message to descriptor %d: %s"),
                            rule->error->fd, strerror(errno));
                exit(1);
        }
                        
        if (set_user_limits (req->pw->pw_name, rule->limits))
                die(usage_error, &req->i18n, _("cannot set limits for %s"), 
                    req->pw->pw_name);

        run_transforms(rule, req);

        if (rule->chroot_dir) {
                char *dir = expand_dir(rule->chroot_dir, req);
                debug(2, _("Chroot dir: %s"), dir);
		free(req->chroot_dir);
		req->chroot_dir = dir;
        }
        if (rule->home_dir) {
                free(req->home_dir);
                req->home_dir = expand_dir(rule->home_dir, req);
		debug(2, _("Home dir: %s"), req->home_dir);
	}

	if (rule->gid != NO_GID) {
		req->gid = rule->gid;
		debug(2, _("GID: %lu"), (unsigned long) req->gid);
	}
	
	if (rule->post_sockaddr.len)
		req->post_sockaddr = &rule->post_sockaddr;
	
	if (rule->acct != rush_undefined)
		req->acct = rule->acct;
	
	if (req->acct == rush_true)
		req->fork = rush_true;
	else if (rule->post_sockaddr.len)
		req->fork = rush_true;
	else if (rule->fork != rush_undefined) 
		req->fork = rule->fork;

	if (rule->mask != NO_UMASK) 
		req->umask = rule->mask;

        if (rule->fall_through)
                return;

	if (req->acct == rush_true &&
	    rushdb_open(RUSH_DB, 1) != rushdb_result_ok) 
		die(system_error, &req->i18n, 
		    _("cannot open database %s: %s"),
		    RUSH_DB, rushdb_error_string);
	
	if (req->chroot_dir) {
		uid_t uid;
		struct passwd *pw;
		
		if (chroot(req->chroot_dir)) 
			die(system_error, &req->i18n,
			    _("cannot chroot to %s: %s"),
		    req->chroot_dir, strerror(errno));
		uid = req->pw->pw_uid;
		pw = getpwuid(uid);
		if (!pw)
			die(req->interactive ? nologin_error : usage_error,
			    NULL,
			    _("invalid uid %lu"), (unsigned long) uid);
		req->pw = pw;
	}

        if (req->home_dir) {
		debug(2, _("chdir %s"), req->home_dir);
		if (chdir(req->home_dir)) 
			die(system_error, &req->i18n,
			    _("cannot change to dir %s: %s"),
                    req->home_dir, strerror(errno));
	}

        debug(2, _("Executing %s, %s"), PROGFILE(req), req->cmdline);
	if (lint_option) {
		if (dump_option)
			dump_request(req, stdout);
		exit(0);
	}

	if (req->fork == rush_true) 
		fork_process(rule, req);

	setowner(req);
	
        umask(req->umask);

        execve(PROGFILE(req), req->argv, req->env);
        die(system_error, &req->i18n, _("%s:%d: %s: cannot execute %s: %s"),
            rule->file, rule->line, rule->tag,
            req->cmdline, strerror(errno));
}


static char *command = NULL;
static char *test_user_name = NULL;
static int interactive;

#include "rushopt.h"

int
main(int argc, char **argv)
{
        uid_t uid;
        struct rush_rule *rule;
        struct rush_request req;

	rush_set_program_name(argv[0]);
	rush_i18n_init();
        umask(~(mode_t)0);
        
        openlog(program_name, LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);

	get_options(argc, argv);
	cfgram_debug(parser_traces > 0);
	cflex_debug(parser_traces > 1);

	if (scanner_test) {
		cfck_keyword("none");
		if (argc > optind + 1) {
			logmsg(LOG_ERR, "%s", _("too many arguments"));
			exit(1);
		}
		cflex_test(argv[optind]);
		exit(0);
	}

	if (argc == optind + 1) {
		if (lint_option)
			rush_config_file = argv[optind];
		else
			die(usage_error, NULL, _("invalid command line"));
	} else if (argc > optind)
		die(usage_error, NULL, _("invalid command line"));
	
	/* Relinquish root privileges in test mode */
	if (lint_option) {
		if (setuid(getuid()))
			die(system_error, NULL, "setuid: %s", strerror(errno));
	}
	
	if (test_user_name) {
		struct passwd *pw = getpwnam(test_user_name);
		if (!pw)
			die(usage_error, NULL, _("invalid user name"));
		if (setreuid(pw->pw_uid, 0))
			die(system_error, NULL, "setreuid: %s",
			    strerror(errno));
	}

        uid = getuid();
        if ((rush_pw = getpwuid(uid)) == NULL)
                die(system_error, NULL,
		    _("invalid uid %lu"), (unsigned long) uid);

        debug(2, _("user %s, uid %lu"), rush_pw->pw_name,
	      (unsigned long) rush_pw->pw_uid);

        cfparse();

	if (!command) {
		if (lint_option && !interactive) 
			exit(0);
	}

        if (__debug_p(2)) {
                int i;
                logmsg(LOG_DEBUG, _("Command line:"));
                for (i = 0; i < argc; i++)
                        logmsg(LOG_DEBUG, "% 4d: %s", i, argv[i]);
                logmsg(LOG_DEBUG, _("Environment:"));
                for (i = 0; environ[i]; i++)
                        logmsg(LOG_DEBUG, "% 4d %s", i, environ[i]);
        }

	memset(&req, 0, sizeof(req));
	if (!command) {
		req.interactive = 1;
		command = "/bin/sh";
	}

	req.cmdline = xstrdup(command);
	request_set_env(&req);
	reparse_cmdline(&req);
	
        req.pw = rush_pw;
	req.umask = 022;
	req.chroot_dir = NULL;
        req.home_dir = NULL;
	req.gid = NO_GID;
	req.fork = rush_undefined;
	req.acct = rush_undefined;
	
	for (rule = rule_head; rule; rule = rule->next) {
		if (req.interactive != rule->interactive)
			continue;
                if (rule->test_node && !test_eval(rule->test_node, rule, &req))
			continue;
                if (debug_level) {
			if (req.interactive)
				logmsg(LOG_NOTICE,
				       _("Serving interactive shell request for %s by rule %s"),
				       req.pw->pw_name, rule->tag);
			else
				logmsg(LOG_NOTICE,
				       _("Serving request \"%s\" for %s by rule %s"),
				       command, req.pw->pw_name, rule->tag);
		}
                run_rule(rule, &req);
        }
	die(req.interactive ? nologin_error : usage_error, &req.i18n,
	    _("no matching rule for \"%s\", user %s"),
	    req.cmdline, req.pw->pw_name);
        return 0;
}
