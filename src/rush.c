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

extern char **environ;

unsigned sleep_time = 5;
unsigned debug_level;
unsigned default_umask = 022;
struct rush_rule *rule_head, *rule_tail;

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

char *error_msg[] = {
	/* usage_error */
	"You are not permitted to execute this command.\n"	       
	"Contact the systems administrator for further assistance.\n",
	
	/* nologin_error */
	"You do not have interactive login access to this machine." 
	"Contact the systems administrator for further assistance.\n",
	
	/* config_error */
	"Local configuration error occurred.\n" 
	"Contact the systems administrator for further assistance.\n",
	
	/* system_error */
	"A system error occurred while attempting to execute command.\n" 
	"Contact the systems administrator for further assistance.\n"
};

void
send_msg(const char *msg, size_t len)
{
        if (write (STDERR_FILENO, msg, len) < 0)
		write (STDOUT_FILENO, msg, len);
}

void
die(enum error_type type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
	send_msg(error_msg[type], strlen(error_msg[type]));
	sleep(sleep_time);
	exit(1);
}

void
xalloc_die()
{
	die(system_error, "Not enough memory");
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


struct rush_request {
	char *cmdline;
	int argc;
	char **argv;
	struct passwd *pw;
	char *home_dir;
};

int
test_request_cmdline(struct test_node *node, struct rush_request *req)
{
	return regexec (&node->v.regex, req->cmdline, 0, NULL, 0);
}

int
test_request_arg(struct test_node *node, struct rush_request *req)
{
	int n = node->v.arg.arg_no;
	if (n == -1)
		n = req->argc - 1;
	if (n >= req->argc)
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
	test_request_cmdline,
	test_request_arg,
	test_request_argc,
	test_request_uid,
	test_request_gid,
	test_request_user,
	test_request_group
};

int
run_tests(struct rush_rule *rule, struct rush_request *req)
{
	struct test_node *node;
	for (node = rule->test_head; node; node = node->next) {
		int res;
		
		if (node->type >= sizeof(test_request)/sizeof(test_request[0]))
			die(system_error,
			    "%s:%d: INTERNAL ERROR: node type out of range",
			    __FILE__, __LINE__);
		res = test_request[node->type](node, req);
		if (node->negate)
			res = !res;
		if (res) 
			return 1;
	}
	return 0;
}

struct rush_rule *
match_rule(struct rush_rule *rule, struct rush_request *req)
{
	if (!rule)
		rule = rule_head;
	for (; rule; rule = rule->next) {
		if (run_tests(rule, req) == 0)
			break;
	}
	return rule;
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
	int nlen = strcspn(name, "+=");
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
			else
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
	int rc;
	
	argcv_free(req->argc, req->argv);
	if ((rc = argcv_get(req->cmdline, NULL, NULL, &req->argc, &req->argv)))
		die(system_error, "argcv_get(%s) failed: %s",
		    req->cmdline, strerror(rc));
}

void
rebuild_cmdline(struct rush_request *req)
{
	int rc;
	free(req->cmdline);
	rc = argcv_string(req->argc, req->argv, &req->cmdline);
	if (rc)
		die(system_error, "argcv_string failed: %s", strerror(rc));
}

void
run_transforms(struct rush_rule *rule, struct rush_request *req)
{
	struct transform_node *node;
	char *p;
	int arg_no;
	int args_transformed = 0;
	
	for (node = rule->transform_head; node; node = node->next) {
		switch (node->type) {
		case transform_cmdline:
			if (args_transformed) {
				rebuild_cmdline(req);
				args_transformed = 0;
			}
			debug(2, "Transforming command line");
			p = transform_string(node->trans, req->cmdline);
			free(req->cmdline);
			req->cmdline = p;
			debug1(2, "Command line: %s", req->cmdline);
			reparse_cmdline(req);
			break;

		case transform_arg:
			arg_no = node->arg_no;
			if (arg_no == -1)
				arg_no = req->argc - 1;
			if (arg_no >= req->argc) 
				die(usage_error,
				    "not enough arguments in command: %s",
				    req->cmdline);
			p = transform_string(node->trans, req->argv[arg_no]);
			free(req->argv[arg_no]);
			req->argv[arg_no] = p;
			args_transformed = 1;
		}
	}

	if (args_transformed) 
		rebuild_cmdline(req);

	if (__debug_p(2)) {
		int i;
		syslog(LOG_DEBUG, "Final arguments:");
		for (i = 0; i < req->argc; i++)
			syslog(LOG_DEBUG, "% 4d: %s", i, req->argv[i]);
	}
}

void
run_rule(struct rush_rule *rule, struct rush_request *req)
{
	char **new_env;
	
	debug3(2, "Rule %s at %s:%d matched",
	       rule->tag ? rule->tag : "(untagged)", rule->file, rule->line);

	if (rule->error_msg) {
		debug1(2, "Error message: %s", rule->error_msg);
		if (write(rule->error_fd, rule->error_msg,
			  strlen(rule->error_msg)) < 0)
			die(system_error,
			    "Error sending error message to descriptor %d: %s",
			    rule->error_fd, strerror(errno));
		exit(1);
	}
			
	if (set_user_limits (req->pw->pw_name, rule->limits))
		die(usage_error, "cannot set limits for %s", req->pw->pw_name);

	run_transforms(rule, req);

	new_env = env_setup(rule->env);
	if (__debug_p(2)) {
		int i;
		syslog(LOG_DEBUG, "Final environment:");
		for (i = 0; new_env[i]; i++)
			syslog(LOG_DEBUG, "% 4d: %s", i, new_env[i]);
	}
	environ = new_env;
	
	if (rule->home_dir) {
		free(req->home_dir);
		req->home_dir = expand_tilde(rule->home_dir, req->pw->pw_dir);
	}
	
	if (rule->chroot_dir) {
		const char *dir = expand_tilde(rule->chroot_dir,
					       req->pw->pw_dir);
		debug1(2, "Chroot dir: %s", dir);
		if (chroot(dir)) 
			die(system_error, "cannot chroot to %s: %s",
			    dir, strerror(errno));
		if (req->home_dir && is_prefix(dir, req->home_dir)) {
			char *new_dir = req->home_dir + strlen(dir);
			memmove(req->home_dir, new_dir, strlen(new_dir) + 1);
		}
	}

	if (req->home_dir) 
		debug1(2, "Home dir: %s", req->home_dir);
	
	default_umask = rule->mask;
	if (rule->fall_through)
		return;
	
	if (req->home_dir && chdir(req->home_dir)) 
		die(system_error, "cannot change to dir %s: %s",
		    req->home_dir, strerror(errno));

	if (setuid(req->pw->pw_uid))
		die(system_error, "cannot enforce uid %lu: %s",
		    req->pw->pw_uid, strerror(errno));

	umask(default_umask);

	debug1(2, "executing %s", req->cmdline);
	execve(req->argv[0], req->argv, new_env);
	die(system_error, "%s:%d: %s: cannot execute %s: %s",
	    rule->file, rule->line, rule->tag ? rule->tag : "(untagged)",
	    req->cmdline, strerror(errno));
}
	
int
main(int argc, char **argv)
{
	char *p;
	int rc;
	uid_t uid;
	struct passwd *pw;
	struct rush_rule *rule;
	struct rush_request req;

	p = strrchr(argv[0], '/');
	if (p)
		p++;
	else
		p = argv[0];
	umask(~(mode_t)0);
	
	openlog(p, LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);
	parse_config();

	if (__debug_p(2)) {
		int i;
		syslog(LOG_DEBUG, "Command line:");
		for (i = 0; i < argc; i++)
			syslog(LOG_DEBUG, "% 4d: %s", i, argv[i]);
		syslog(LOG_DEBUG, "Environment:");
		for (i = 0; environ[i]; i++)
			syslog(LOG_DEBUG, "% 4d %s", i, environ[i]);
	}
	
	uid = getuid();
	if ((pw = getpwuid(uid)) == NULL)
		die(nologin_error, "invalid uid %lu", (unsigned long) uid);

	debug2(2, "user %s, uid %lu", pw->pw_name,
	       (unsigned long) pw->pw_uid);
#if 0
	if (strcmp (pw->pw_shell, CANONICAL_PROGRAM_NAME))
		die(usage_error, "invalid shell for uid %lu",
		    (unsigned long) uid, pw->pw_shell);
#endif
	if (argc != 3 || strcmp(argv[1], "-c"))
		die(usage_error, "invalid command line");

	req.cmdline = xstrdup(argv[2]);
	req.pw = pw;
	req.home_dir = NULL;
	rc = argcv_get(req.cmdline, NULL, NULL, &req.argc, &req.argv);
	if (rc)
		die(system_error,
		    "argcv_get(%s) failed: %s",
		    req.cmdline, strerror(rc));
	
	for (rule = NULL; ; rule = rule->next) {
		rule = match_rule(rule, &req);
		if (!rule)
			die(usage_error,
			    "no matching rule for \"%s\", user %s",
			    req.cmdline, pw->pw_name);
		if (debug_level && rule->tag) 
			syslog(LOG_NOTICE,
			       "Serving request \"%s\" for %s by rule %s",
			       argv[2], pw->pw_name, rule->tag);
		run_rule(rule, &req);
	} 
	
	return 0;
}
