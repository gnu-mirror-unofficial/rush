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
struct command_config *config_list, *config_tail;

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
	int fd = isatty(STDERR_FILENO) ? STDERR_FILENO : STDOUT_FILENO;
	write (fd, msg, len);
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

int
cmp_argc(struct command_config *cfg, int argc)
{
	if (cfg->argc) {
		debug3(1, "match %d %d %d",
		       argc, cfg->cmp_op, cfg->argc);
		switch (cfg->cmp_op) {
		case cmp_eq:
			return argc == cfg->argc;
		case cmp_ne:
			return argc != cfg->argc;
		case cmp_lt:
			return argc < cfg->argc;
		case cmp_le:
			return argc <= cfg->argc;
		case cmp_gt:
			return argc > cfg->argc;
		case cmp_ge:
			return argc >= cfg->argc;
		}
	}
	return 1;
}

static int
match_args(struct command_config *cfg, int argc, char **argv)
{
	struct match_arg *mp;

	if (!cmp_argc(cfg, argc))
		return 1;
	
	for (mp = cfg->match_head; mp; mp = mp->next) {
		int n = mp->arg_no;
		if (n == -1)
			n = argc - 1;
		if (n >= argc)
			return 1;
		if (regexec(&mp->regex, argv[n], 0, NULL, 0))
			return 1;
	}
	return 0;
}

struct command_config *
match_config(const char *cmdline)
{
	struct command_config *cfg;
	int rc;
	int argc;
	char **argv;

	rc = argcv_get(cmdline, NULL, NULL, &argc, &argv);
	if (rc)
		die(system_error,
		    "argcv_get(%s) failed: %s",
		    cmdline, strerror(rc));
	
	for (cfg = config_list; cfg; cfg = cfg->next) {
		if (regexec (&cfg->regex, cmdline, 0, NULL, 0) == 0) {
			if (match_args(cfg, argc, argv) == 0)
				break;
		}
	}
	argcv_free(argc, argv);
	return cfg;
}

const char *
expand_tilde(const char *dir, const char *home)
{
	if (dir[0] == '~') {
		if (dir[1] == '/') {
			size_t hlen = strlen(home);
			size_t len = hlen + strlen(dir + 1);
			char *p = xmalloc(len + 1);
			strcpy(p, home);
			if (hlen > 0 && p[hlen-1] != '/')
				p[hlen++] = '/';
			strcpy(p + hlen, dir + 2);
			dir = p;
		} else
			dir = xstrdup(home);
	}
	return dir;
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
		for (i = 0; old_env[i]; i++)
			new_env[n++] = old_env[i];

	for (i = 0; env[i]; i++) {
		char *p;
		if ((p = strchr(env[i], '='))) {
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
run_config(struct command_config *cfg, struct passwd *pw, const char *arg)
{
	int argc;
	char **argv;
	char *cmdline;
	struct transform_arg *xarg;
	const char *home_dir = NULL;
	int rc;
	char **new_env;
	
	debug2(1, "Matching config: %s:%d", cfg->file, cfg->line);
	
	if (pw->pw_uid < cfg->min_uid)
		die(nologin_error, "uid %lu out of range",
		    (unsigned long) pw->pw_uid);

	if (set_user_limits (pw->pw_name, cfg->limits))
		die(usage_error, "cannot set limits for %s", pw->pw_name);

	debug(1, "Transforming command line");
	cmdline = transform_string(cfg->trans, arg);
	debug1(1, "Command line: %s", cmdline);
	
	if ((rc = argcv_get(cmdline, NULL, NULL, &argc, &argv)))
		die(system_error, "argcv_get(%s) failed: %s",
		    cmdline, strerror(rc));

	debug(1, "Transforming arguments");
	for (xarg = cfg->arg_head; xarg; xarg = xarg->next) {
		int arg_no = xarg->arg_no;
		if (arg_no == -1)
			arg_no = argc - 1;
		if (arg_no >= argc) 
			die(usage_error, "not enough arguments in command: %s",
			    arg);
		argv[arg_no] = transform_string(xarg->trans, argv[arg_no]);
	}

	if (__debug_p(1)) {
		int i;
		syslog(LOG_DEBUG, "Final arguments:");
		for (i = 0; i < argc; i++)
			syslog(LOG_DEBUG, "% 4d: %s", i, argv[i]);
	}
	new_env = env_setup(cfg->env);
	if (__debug_p(1)) {
		int i;
		syslog(LOG_DEBUG, "Final environment:");
		for (i = 0; new_env[i]; i++)
			syslog(LOG_DEBUG, "% 4d: %s", i, new_env[i]);
	}
		
	argcv_string(argc, argv, &cmdline);

	if (cfg->mask)
		umask(cfg->mask);

	if (cfg->home_dir)
		home_dir = expand_tilde(cfg->home_dir, pw->pw_dir);

	if (cfg->chroot_dir) {
		const char *dir = expand_tilde(cfg->chroot_dir, pw->pw_dir);
		debug1(1, "Chroot dir: %s", dir);
		if (chroot(dir)) 
			die(system_error, "cannot chroot to %s: %s",
			    dir, strerror(errno));
		if (home_dir && is_prefix(dir, home_dir))
			home_dir += strlen(dir);
	}

	if (home_dir) {
		debug1(1, "Home dir: %s", home_dir);
		chdir(home_dir);
	}

	if (setuid(pw->pw_uid))
		die(system_error, "cannot enforce uid %lu: %s",
		    pw->pw_uid, strerror(errno));
	
	debug1(1, "executing %s", cmdline);
	execve(argv[0], argv, new_env);
	die(system_error, "cannot execute %s: %s",
	    cmdline, strerror(errno));
}
	
int
main(int argc, char **argv)
{
	char *p;
	uid_t uid;
	struct passwd *pw;
	struct command_config *config;
	
	p = strrchr(argv[0], '/');
	if (p)
		p++;
	else
		p = argv[0];
	umask(~(mode_t)0);
	
	openlog(p, LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);
	parse_config();

	if (__debug_p(1)) {
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

	debug2(1, "user %s, uid %lu", pw->pw_name,
	       (unsigned long) pw->pw_uid);
#if 0
	if (strcmp (pw->pw_shell, CANONICAL_PROGRAM_NAME))
		die(usage_error, "invalid shell for uid %lu",
		    (unsigned long) uid, pw->pw_shell);
#endif
	if (argc != 3 || strcmp(argv[1], "-c"))
		die(usage_error, "invalid command line");

	config = match_config(argv[2]);
	if (!config)
		die(usage_error, "no matching configuration for %s", argv[2]);
	run_config(config, pw, argv[2]);

	return 0;
}
