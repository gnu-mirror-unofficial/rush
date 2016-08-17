/* This file is part of GNU Rush.                  
   Copyright (C) 2008-2016 Sergey Poznyakoff

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

extern char **environ;

char *rush_config_file = CONFIG_FILE;
int lint_option = 0;
unsigned sleep_time = 5;
unsigned debug_level;
int debug_option;
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
	

void
send_msg(const char *msg, size_t len)
{
        if (write(STDERR_FILENO, msg, len) < 0)
                write(STDOUT_FILENO, msg, len);
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
		case LOG_NOTICE:
			fprintf(stderr, _("Info: "));
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
        va_list ap;
        va_start(ap, fmt);
        vlogmsg(LOG_ERR, fmt, ap);
        va_end(ap);
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
xalloc_die()
{
        die(system_error, NULL, _("Not enough memory"));
}

int
is_prefix(const char *pref, const char *str)
{
        int len = strlen(pref);
        int slen = strlen(str);
        
        if (slen < len)
                return 0;
        if (memcmp(str, pref, len))
                return 0;
        if (str[len] != '/')
                return 0;
        return 1;
}

int
is_suffix(const char *suf, const char *str)
{
        int len = strlen(suf);
        int slen = strlen(str);
        
        if (slen < len)
                return 0;
        if (memcmp(str + slen - len, suf, len))
                return 0;
        if (slen > len && str[slen - len - 1] != '/')
                return 0;
        return 1;
}


int
test_request_cmdline(struct test_node *node, struct rush_request *req)
{
        return regexec(&node->v.regex, req->cmdline, 0, NULL, 0);
}

#define ARG_NO(n,argc) (((n) < 0) ? (argc) + (n) : (n))

int
test_request_arg(struct test_node *node, struct rush_request *req)
{
        int n = ARG_NO(node->v.arg.arg_no, req->argc);
        if (n < 0 || n >= req->argc)
                return 1;
        return regexec(&node->v.arg.regex, req->argv[n], 0, NULL, 0);
}

int
test_num_p(struct test_numeric_node *node, unsigned long val)
{
        switch (node->op) {
        case cmp_eq:
                return val == node->val;
        case cmp_ne:
                return val != node->val;
        case cmp_lt:
                return val < node->val;
        case cmp_le:
                return val <= node->val;
        case cmp_gt:
                return val > node->val;
        case cmp_ge:
                return val >= node->val;
        }
        return 0;
}

int
test_request_argc(struct test_node *node, struct rush_request *req)
{
        return !test_num_p(&node->v.num, req->argc);
}

int
test_request_uid(struct test_node *node, struct rush_request *req)
{
        return !test_num_p(&node->v.num, req->pw->pw_uid);
}

int
test_request_gid(struct test_node *node, struct rush_request *req)
{
        return !test_num_p(&node->v.num, req->pw->pw_gid);
}

int
groupcmp(char *gname, struct passwd *pw)
{
        struct group *grp;
        grp = getgrnam(gname);
        if (grp) {
		char **p;

		if (pw->pw_gid == grp->gr_gid)
                        return 0;

		for (p = grp->gr_mem; *p; p++) {
			if (strcmp(*p, pw->pw_name) == 0)
				return 0;
		}
        }
        return 1;
}

int
test_request_group(struct test_node *node, struct rush_request *req)
{
        char **p;
        
        for (p = node->v.strv; *p; p++) 
                if (groupcmp(*p, req->pw) == 0)
                        return 0;
        return 1;
}

int
test_request_user(struct test_node *node, struct rush_request *req)
{
        char **p;
        
        for (p = node->v.strv; *p; p++) 
                if (strcmp(*p, req->pw->pw_name) == 0)
                        return 0;
        return 1;
}

int (*test_request[])(struct test_node *, struct rush_request *) = {
        [test_cmdline]     = test_request_cmdline,
        [test_arg]         = test_request_arg,
        [test_argc]        = test_request_argc,
        [test_uid]         = test_request_uid,
        [test_gid]         = test_request_gid,
        [test_user]        = test_request_user,
        [test_group]       = test_request_group,
};

int
run_tests(struct rush_rule *rule, struct rush_request *req)
{
        struct test_node *node;
        for (node = rule->test_head; node; node = node->next) {
                int res;
                
                if (node->type >= sizeof(test_request)/sizeof(test_request[0]))
                        die(system_error,
			    &req->i18n,
                            _("%s:%d: INTERNAL ERROR: node type out of range"),
                            __FILE__, __LINE__);

                res = test_request[node->type](node, req);
                if (node->negate)
                        res = !res;
                if (res) 
                        return 1;
        }
        return 0;
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

static char *
find_env(char *name, int val)
{
        int nlen = strcspn(name, "?+=");
        int i;

        for (i = 0; environ[i]; i++) {
                size_t elen = strcspn(environ[i], "=");
                if (elen == nlen && memcmp(name, environ[i], nlen) == 0)
                        return val ? environ[i] + elen + 1 : environ[i];
        }
        return NULL;
}

static int
locate_unset(char **env, const char *name)
{
        volatile int i;
        int nlen = strcspn(name, "=");

        for (i = 0; env[i]; i++) {
                if (env[i][0] == '-') {
                        size_t elen = strcspn(env[i] + 1, "=");
                        if (elen == nlen
                            && memcmp(name, env[i] + 1, nlen) == 0) {
                                if (env[i][nlen + 1])
                                        return strcmp(name + nlen,
                                                      env[i] + 1 + nlen) == 0;
                                else
                                        return 1;
                        }
                }
        }
        return 0;
}

static char *
env_concat(char *name, size_t namelen, char *a, char *b)
{
        char *res;
        size_t len;
        
        if (a && b) {
                res = xmalloc(namelen + 1 + strlen(a) + strlen(b) + 1);
                strcpy(res + namelen + 1, a);
                strcat(res, b);
        } else if (a) {
                len = strlen(a);
                if (c_ispunct(a[len-1]))
                        len--;
                res = xmalloc(namelen + 1 + len + 1);
                memcpy(res + namelen + 1, a, len);
                res[namelen + 1 + len] = 0;
        } else /* if (a == NULL) */ {
                if (c_ispunct(b[0]))
                        b++;
		len = strlen(b);
                res = xmalloc(namelen + 1 + len + 1);
                strcpy(res + namelen + 1, b);
        }
        memcpy(res, name, namelen);
        res[namelen] = '=';
        return res;
}
        
static char **
env_setup(char **env)
{
        char **old_env = environ;
        char **new_env;
        int count, i, n;
        
        if (!env)
                return old_env;

        if (strcmp(env[0], "-") == 0) {
                old_env = NULL;
                env++;
        }
        
        /* Count new environment size */
        count = 0;
        if (old_env)
                for (i = 0; old_env[i]; i++)
                        count++;
    
        for (i = 0; env[i]; i++)
                count++;

        /* Allocate the new environment. */
        new_env = xcalloc(count + 1, sizeof new_env[0]);

        /* Populate the environment. */
        n = 0;
        
        if (old_env)
                for (i = 0; old_env[i]; i++) {
                        if (!locate_unset(env, old_env[i]))
                                new_env[n++] = old_env[i];
                }

        for (i = 0; env[i]; i++) {
                char *p;
                
                if (env[i][0] == '-') {
                        /* Skip unset directives. */
                        continue;
                } if ((p = strchr(env[i], '='))) {
                        if (p == env[i])
                                continue; /* Ignore erroneous entry */
                        if (p[-1] == '+') 
                                new_env[n++] = env_concat(env[i],
                                                          p - env[i] - 1,
                                                          find_env(env[i], 1),
                                                          p + 1);
                        else if (p[1] == '+')
                                new_env[n++] = env_concat(env[i],
                                                          p - env[i],
                                                          p + 2,
                                                          find_env(env[i], 1));
			else if (p[-1] == '?') {
				if (!find_env(env[i], 0))
					new_env[n++] = p + 1;
			} else
                                new_env[n++] = env[i];
                } else {
                        p = find_env(env[i], 0);
                        if (p)
                                new_env[n++] = p;
                }
        }
        new_env[n] = NULL;
        return new_env;
}

void
reparse_cmdline(struct rush_request *req)
{
        struct wordsplit ws;
	
        argcv_free(req->argc, req->argv);
	if (wordsplit(req->cmdline, &ws, WRDSF_DEFFLAGS))
		die(system_error, &req->i18n, _("wordsplit(%s) failed: %s"),
                    req->cmdline, wordsplit_strerror(&ws));
	wordsplit_getwords(&ws, &req->argc, &req->argv);
	wordsplit_free(&ws);

	free(req->prog);
	req->prog = NULL;
}

void
rebuild_cmdline(struct rush_request *req)
{
        free(req->cmdline);
        req->cmdline = argcv_string(req->argc, req->argv);
}

static int
get_arg_no(int index, struct rush_request *req)
{
	int arg_no = ARG_NO(index, req->argc);
	if (arg_no < 0 || arg_no >= req->argc) 
		die(config_error,
		    &req->i18n, 
		    _("no argument at index %d in command: %s"),
		    index,
		    req->cmdline);
	return arg_no;
}

static void
assign_string(char **pstr, char *val)
{
	debug(2, _("Transform: \"%s\" -> \"%s\""), *pstr ? *pstr : "", val);
	free(*pstr);
	*pstr = val;
}

void
run_transforms(struct rush_rule *rule, struct rush_request *req)
{
        struct transform_node *node;
        char *p;
        int i, arg_no, arg_end;
        int args_transformed = 0;
	char *val, **target;
	
#define GET_TGT_VAL()							\
	if (node->progmod) {						\
		arg_no = 0;						\
		target = &req->prog;					\
		val = PROGFILE(req);					\
		debug(2, _("Modifying program name (%s)"), val);	\
	} else {							\
		arg_no = get_arg_no(node->arg_no, req);			\
		target = &req->argv[arg_no];				\
		val = *target;						\
		args_transformed = 1;					\
		debug(2, _("Modifying argv[%d]"), arg_no);		\
	} 								\
	if (node->pattern) {						\
		val = rush_expand_string(node->pattern, req);		\
	}

        for (node = rule->transform_head; node; node = node->next) {
                switch (node->type) {
                case transform_cmdline:
                        if (args_transformed) {
                                rebuild_cmdline(req);
                                args_transformed = 0;
                        }
                        debug(2, "%s", _("Transforming command line"));
                        p = transform_string(node->v.trans, req->cmdline);
                        free(req->cmdline);
                        req->cmdline = p;
                        debug(2, _("Command line: %s"), req->cmdline);
                        reparse_cmdline(req);
                        break;

		case transform_setcmd:
			GET_TGT_VAL();
			if (args_transformed) {
                                rebuild_cmdline(req);
                                args_transformed = 0;
                        }
                        debug(2, "%s", _("Setting command line"));
                        free(req->cmdline);
                        req->cmdline = xstrdup(val);
                        debug(2, _("Command line: %s"), req->cmdline);
                        reparse_cmdline(req);
                        break;
			
                case transform_arg:
			GET_TGT_VAL();
                        p = transform_string(node->v.trans, val);
			assign_string(target, p);
			break;

		case transform_map:
			GET_TGT_VAL();
			debug(2,
			      _("Transformation map: %s, %s, %s, %u, %u, %s"),
			      node->v.map.file,
			      node->v.map.delim,
			      node->v.map.key,
			      node->v.map.key_field,
			      node->v.map.val_field,
			      node->v.map.defval);
                        p = map_string(&node->v.map, req);
			if (p) 
				assign_string(target, p);
			else
				args_transformed = 0;
			break;

		case transform_delarg:
			arg_no = get_arg_no(node->arg_no, req);
			arg_end = get_arg_no(node->v.arg_end, req);
			if (arg_end < arg_no) {
				int x = arg_end;
				arg_end = arg_no;
				arg_no = x;
			}
			debug(2, _("Deleting arguments %d-%d"),
			      arg_no, arg_end);
			if (arg_no == 0 || arg_end == 0)
				die(config_error,
				    &req->i18n, _("Deleting argv[0] is prohibited"));
			for (i = arg_no; i <= arg_end; i++) 
				free(req->argv[i]);
			i = arg_end - arg_no + 1;
			memmove(req->argv + arg_no,
				req->argv + arg_end + 1,
				(req->argc - i)
				  * sizeof(req->argv[0]));
			req->argc -= i;
			args_transformed = 1;
			break;

		case transform_setarg:
			GET_TGT_VAL();
			assign_string(target, val);
			break;
                }
        }

        if (args_transformed) 
                rebuild_cmdline(req);

        if (__debug_p(2)) {
                int i;
		logmsg(LOG_DEBUG, _("Program name: %s"), PROGFILE(req));
                logmsg(LOG_DEBUG, _("Final arguments:"));
                for (i = 0; i < req->argc; i++)
                        logmsg(LOG_DEBUG, "% 4d: %s", i, req->argv[i]);
        }
}

void
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

void
acct_off(void)
{
	if (rushdb_stop())
		logmsg(LOG_ERR, 
		       _("error writing stop to database file %s: %s"),
		       RUSH_DB, strerror(errno));
	rushdb_close();
}

void
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

void
run_rule(struct rush_rule *rule, struct rush_request *req)
{
        char **new_env;
		
        debug(2, _("Rule %s at %s:%d matched"),
	      rule->tag, rule->file, rule->line);

        new_env = env_setup(rule->env);
        if (__debug_p(2)) {
                int i;
                logmsg(LOG_DEBUG, _("Final environment:"));
                for (i = 0; new_env[i]; i++)
                        logmsg(LOG_DEBUG, "% 4d: %s", i, new_env[i]);
        }
        environ = new_env;
        
	if (rule->i18n.text_domain)
		req->i18n.text_domain = rule->i18n.text_domain;
	if (rule->i18n.localedir)
		req->i18n.localedir = rule->i18n.localedir;
	if (rule->i18n.locale)
		req->i18n.locale = rule->i18n.locale;

        if (rule->error_msg) {
		const char *msg = rule->error_msg;
		int custom = 1;
		
                debug(2, _("Error message: %s"), msg);
		if (msg[0] == '@') {
			int n;
			
			if (msg[1] == '@')
				msg++;
			else if ((n = string_to_error_index(msg + 1)) == -1) 
				logmsg(LOG_NOTICE,
				       _("Unknown message reference: %s\n"),
				       msg);
			else {
				msg = error_msg[n].text;
				custom = error_msg[n].custom;
			}
		} 

		if (custom) 
			msg = user_gettext(rule->i18n.locale,
					   rule->i18n.text_domain,
					   rule->i18n.localedir,
					   msg);
		else
			msg = gettext(msg);
                if (write(rule->error_fd, msg, strlen(msg)) < 0)
                        die(system_error, &req->i18n, 
                            _("Error sending diagnostic message to descriptor %d: %s"),
                            rule->error_fd, strerror(errno));
                exit(1);
        }
                        
        if (set_user_limits (req->pw->pw_name, rule->limits))
                die(usage_error, &req->i18n, _("cannot set limits for %s"), 
                    req->pw->pw_name);

        run_transforms(rule, req);

        if (rule->chroot_dir) {
                char *dir = expand_tilde(rule->chroot_dir,
                                               req->pw->pw_dir);
                debug(2, _("Chroot dir: %s"), dir);
		free(req->chroot_dir);
		req->chroot_dir = dir;
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

        if (rule->home_dir) {
                free(req->home_dir);
                req->home_dir = expand_tilde(rule->home_dir, req->pw->pw_dir);
		debug(2, _("Home dir: %s"), req->home_dir);
		if (chdir(req->home_dir)) 
			die(system_error, &req->i18n,
			    _("cannot change to dir %s: %s"),
                    req->home_dir, strerror(errno));
	}

	if (req->interactive && !req->prog) {
		char *p;
		
		req->prog = req->argv[0];
		p = strrchr(req->prog, '/');
		if (p)
			++p;
		else
			p = req->prog;
		req->argv[0] = xmalloc(strlen(p) + 2);
		req->argv[0][0] = '-';
		strcpy(req->argv[0] + 1, p);
		rebuild_cmdline(req);
	}
	
        debug(2, _("Executing %s, %s"), PROGFILE(req), req->cmdline);
	if (lint_option)
		exit(0);

	if (req->fork == rush_true) 
		fork_process(rule, req);

	setowner (req);
	
        umask(req->umask);

        execve(PROGFILE(req), req->argv, new_env);
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
	struct wordsplit ws;

	rush_set_program_name(argv[0]);
	rush_i18n_init();
        umask(~(mode_t)0);
        
        openlog(program_name, LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);

	get_options(argc, argv);

	if (argc == optind + 1) {
		if (lint_option)
			rush_config_file = argv[optind];
		else
			die(usage_error, NULL, _("invalid command line"));
	} else if (argc > optind)
		die(usage_error, NULL, _("invalid command line"));
	
	/* Relinquish root privileges in test mode */
	if (lint_option)
		setuid(getuid());
	
	if (test_user_name) {
		struct passwd *pw = getpwnam(test_user_name);
		if (!pw)
			die(usage_error, NULL, _("invalid user name"));
		setreuid(pw->pw_uid, 0);
	}

        uid = getuid();
        if ((rush_pw = getpwuid(uid)) == NULL)
                die(system_error, NULL,
		    _("invalid uid %lu"), (unsigned long) uid);

        debug(2, _("user %s, uid %lu"), rush_pw->pw_name,
	      (unsigned long) rush_pw->pw_uid);

        parse_config();

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

	if (wordsplit(req.cmdline, &ws, WRDSF_DEFFLAGS))
		die(system_error, NULL,
		    _("wordsplit(%s) failed: %s"),
		    req.cmdline, wordsplit_strerror(&ws));
	wordsplit_getwords(&ws, &req.argc, &req.argv);
	wordsplit_free(&ws);
	
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
                if (run_tests(rule, &req))
			continue;
                if (!rule)
                        break;
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
