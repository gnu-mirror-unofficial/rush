#include <rush.h>
#include <cf.h>

void
stringbuf_init(struct stringbuf *sb)
{
	sb->buffer = NULL;
	sb->size = 0;
	sb->pos = 0;
}

void
stringbuf_free(struct stringbuf *sb)
{
	free(sb->buffer);
	stringbuf_init(sb);
}

void
stringbuf_add_char(struct stringbuf *sb, int c)
{
	if (sb->pos + 1 > sb->size)
		sb->buffer = x2realloc(sb->buffer, &sb->size);
	sb->buffer[sb->pos++] = c;
}

void
stringbuf_add_array(struct stringbuf *sb, char const *str, size_t len)
{
	while (sb->pos + len > sb->size)
		sb->buffer = x2realloc(sb->buffer, &sb->size);
	memcpy(sb->buffer + sb->pos, str, len);
	sb->pos += len;
}

void
stringbuf_add_string(struct stringbuf *sb, char const *str)
{
	stringbuf_add_array(sb, str, strlen(str));
}

void
stringbuf_add_num(struct stringbuf *sb, unsigned n)
{
	size_t i = sb->pos, j;
	do {
		static char dig[] = "0123456789";
		stringbuf_add_char(sb, dig[n % 10]);
		n /= 10;
	} while (n > 0);
	for (j = sb->pos-1; j > i; i++, j--) {
		char c = sb->buffer[i];
		sb->buffer[i] = sb->buffer[j];
		sb->buffer[j] = c;
	}
}

void
stringbuf_finish(struct stringbuf *sb)
{
	stringbuf_add_char(sb, 0);
}

void
cfpoint_format(struct cfpoint const *cfp, struct stringbuf *sb)
{
	if (cfp->filename) {
		stringbuf_add_string(sb, cfp->filename);
		stringbuf_add_char(sb, ':');
		stringbuf_add_num(sb, cfp->line);
		if (cfp->column) {
			stringbuf_add_char(sb, '.');
			stringbuf_add_num(sb, cfp->column);
		}
	}
}

void
cfloc_format(struct cfloc const *cfl, struct stringbuf *sb)
{
	cfpoint_format(&cfl->beg, sb);
	if (cfl->end.filename) {
		if (cfl->beg.filename != cfl->end.filename) {
			stringbuf_add_char(sb, '-');
			cfpoint_format(&cfl->end, sb);
		} else if (cfl->beg.line != cfl->end.line) {
			stringbuf_add_char(sb, '-');
			stringbuf_add_num(sb, cfl->end.line);
			if (cfl->end.column) {
				stringbuf_add_char(sb, '.');
				stringbuf_add_num(sb, cfl->end.column);
			}
		} else if (cfl->beg.column
			   && cfl->beg.column != cfl->end.column) {
			stringbuf_add_char(sb, '-');
			stringbuf_add_num(sb, cfl->end.column);
		}
	}
}

void
cfloc_print(struct cfloc const *cfl, FILE *fp)
{
	struct stringbuf sb;
	stringbuf_init(&sb);
	cfloc_format(cfl, &sb);
	stringbuf_finish(&sb);
	fwrite(sb.buffer, sb.pos, 1, fp);
	stringbuf_free(&sb);
}

void
vcferror(struct cfloc const *loc, char const *fmt, va_list ap)
{
	struct stringbuf sb;
	stringbuf_init(&sb);
	cfloc_format(loc, &sb);
	stringbuf_add_array(&sb, ": ", 2);
	stringbuf_add_string(&sb, fmt);
	vlogmsg(LOG_ERR, sb.buffer, ap);
	stringbuf_free(&sb);
}

void
cferror(struct cfloc const *loc, char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vcferror(loc, fmt, ap);
	va_end(ap);
}

struct cfstream_file {
	CFSTREAM base;
	FILE *fp;
};

#define CFSTREAM_BUFSIZE 1024

CFSTREAM *
cfstream_open_file(char const *filename)
{
	int fd;
	struct stat st;
	CFSTREAM *cf;

	if (stat(filename, &st)) {
		die(system_error, NULL, _("cannot stat file %s: %s"),
		    filename, strerror(errno));
	}
	if (check_config_permissions(filename, &st))
		die(config_error, NULL, _("%s: file is not safe"), filename);

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		die(system_error, NULL, _("cannot open file %s: %s"),
		    filename, strerror(errno));

	cf = xmalloc(sizeof(*cf));
	cf->fd = fd;
	cf->buffer = xmalloc(CFSTREAM_BUFSIZE);
	cf->size = CFSTREAM_BUFSIZE;
	cf->level = 0;
	cf->pos = 0;

	return cf;
}

CFSTREAM *
cfstream_open_mem(char const *buffer, size_t len)
{
	CFSTREAM *cf;

	cf = xmalloc(sizeof(*cf));
	cf->fd = -1;
	cf->buffer = xmalloc(len);
	memcpy(cf->buffer, buffer, len);
	cf->size = len;
	cf->level = len;
	cf->pos = 0;

	return cf;
}

void
cfstream_close(CFSTREAM *cf)
{
	if (cf->fd != -1)
		close(cf->fd);
	free(cf->buffer);
	free(cf);
}

static inline size_t
cfstream_buf_avail(CFSTREAM *cf)
{
	return cf->level - cf->pos;
}

static size_t
cfstream_avail(CFSTREAM *cf)
{
	size_t avail = cfstream_buf_avail(cf);
	if (avail == 0) {
		if (cf->fd == -1)
			return 0;
		else {
			ssize_t rc;

			rc = read(cf->fd, cf->buffer, cf->size);
			if (rc == -1)
				die(system_error, NULL,
				    "read: %s",
				    strerror(errno));
			cf->level = rc;
			cf->pos = 0;
			if (rc == 0)
				return 0;
			avail = cfstream_buf_avail(cf);
		}
	}
	return avail;
}

static inline size_t
cfstream_buf_free(CFSTREAM *cf)
{
	return cf->size - cf->level;
}

static inline char const *
cfstream_buf_ptr(CFSTREAM *cf)
{
	return cf->buffer + cf->pos;
}

static inline void
cfstream_buf_advance(CFSTREAM *cf, size_t n)
{
	cf->pos += n;
}

ssize_t
cfstream_read(CFSTREAM *cf, char *bufptr, size_t bufsize)
{
	size_t nrd = 0;

	while (nrd < bufsize) {
		size_t n = bufsize - nrd;
		size_t avail = cfstream_avail(cf);
		if (avail == 0)
			break;
		if (n > avail)
			n = avail;
		memcpy(bufptr + nrd, cfstream_buf_ptr(cf), n);
		cfstream_buf_advance(cf, n);
		nrd += n;
	}

	return nrd;
}

void
cfstream_putback(CFSTREAM *cf)
{
	if (cf->pos > 0)
		cf->pos--;
}

const char default_entry[] = ""
#ifdef RUSH_DEFAULT_CONFIG
RUSH_DEFAULT_CONFIG
#endif
;

static char abc[] = {
	[0] = 'v',
	[1] = 'e',
	[2] = 'r',
	[3] = 's',
	[4] = 'i',
	[5] = 'o',
	[6] = 'n',
	[7] = ' ',
	[8] = '\t',
	[9] = '\n',
	[10] = '#',
	[11] = '.',
	[12] = '0',
	[13] = '1',
	[14] = '2',
	[15] = '3',
	[16] = '4',
	[17] = '5',
	[18] = '6',
	[19] = '7',
	[20] = '8',
	[21] = '9',
	[22] = 0
};

static inline int
char2abc(int c)
{
	char *p = strchr(abc, c);
	if (p)
		return p - abc;
	return 22;
}

enum {
	state_error = 0,
	state_initial = 1,
	state_final = 14,
	state_major = 10,
	state_minor = 12,
	state_old_format = 18,
	NUM_STATES = 19
};

static int transition[][sizeof(abc)] = {
	[1] = {
		[0] = 2,
		[1] = 18,
		[2] = 18,
		[3] = 18,
		[4] = 18,
		[5] = 18,
		[6] = 18,
		[7] = 16,
		[8] = 16,
		[9] = 1,
		[10] = 17,
		[11] = 18,
		[12] = 18,
		[13] = 18,
		[14] = 18,
		[15] = 18,
		[16] = 18,
		[17] = 18,
		[18] = 18,
		[19] = 18,
		[20] = 18,
		[21] = 18,
		[22] = 17
	},
	[2] = {
		[1] = 3,
	},
	[3] = {
		[2] = 4,
	},
	[4] = {
		[3] = 5,
	},
	[5] = {
		[4] = 6,
	},
	[6] = {
		[5] = 7,
	},
	[7] = {
		[6] = 8
	},
	[8] = {
		[7] = 9,
		[8] = 9,
	},
	[9] = {
		// whitespace
		[7] = 9,
		[8] = 9,
		[12] = 10,
		[13] = 10,
		[14] = 10,
		[15] = 10,
		[16] = 10,
		[17] = 10,
		[18] = 10,
		[19] = 10,
		[20] = 10,
		[21] = 10,
	},
	[10] = {
		// major number
		[11] = 11,
		[12] = 10,
		[13] = 10,
		[14] = 10,
		[15] = 10,
		[16] = 10,
		[17] = 10,
		[18] = 10,
		[19] = 10,
		[20] = 10,
		[21] = 10,
	},

	[11] = {
		[12] = 12,
		[13] = 12,
		[14] = 12,
		[15] = 12,
		[16] = 12,
		[17] = 12,
		[18] = 12,
		[19] = 12,
		[20] = 12,
		[21] = 12,
	},

	[12] = {
		// minor number
		[7] = 13,
		[8] = 13,
		[9] = 14,
		[10] = 15,
		[12] = 12,
		[13] = 12,
		[14] = 12,
		[15] = 12,
		[16] = 12,
		[17] = 12,
		[18] = 12,
		[19] = 12,
		[20] = 12,
		[21] = 12,
	},

	[13] = {
		// optional whitespace after minor number
		[7] = 13,
		[8] = 13,
		[9] = 14,
		[10] = 15,
	},
	[14] = {
		// Final state
	},
	[15] = {
		// comment after minor
		[0] = 15,
		[1] = 15,
		[2] = 15,
		[3] = 15,
		[4] = 15,
		[5] = 15,
		[6] = 15,
		[7] = 15,
		[8] = 15,
		[9] = 14,
		[10] = 15,
		[11] = 15,
		[12] = 15,
		[13] = 15,
		[14] = 15,
		[15] = 15,
		[16] = 15,
		[17] = 15,
		[18] = 15,
		[19] = 15,
		[20] = 15,
		[21] = 15,
	},
	[16] = {
		// Initial whitespace
		[0] = 2,
		[7] = 16,
		[8] = 16,
		[9] = 1,
	},
	[17] = {
		// comment
		[0] = 17,
		[1] = 17,
		[2] = 17,
		[3] = 17,
		[4] = 17,
		[5] = 17,
		[6] = 17,
		[7] = 17,
		[8] = 17,
		[9] = 1,
		[10] = 17,
		[11] = 17,
		[12] = 17,
		[13] = 17,
		[14] = 17,
		[15] = 17,
		[16] = 17,
		[17] = 17,
		[18] = 17,
		[19] = 17,
		[20] = 17,
		[21] = 17,
	},
	[18] = {
		// exit (old format)
	}
};

void
cfparse(void)
{
	CFSTREAM *cf;
	char const *config_file_name;
	int line;
	int state;
	int major = 0;
	int minor = 0;

	if (access(rush_config_file, F_OK) == 0) {
		cf = cfstream_open_file(rush_config_file);
		config_file_name = rush_config_file;
	} else if (default_entry[0]) {
		cf = cfstream_open_mem(default_entry,
				       sizeof(default_entry) - 1);
		config_file_name = "<built-in>";
	} else {
		die(usage_error, NULL, _("configuration file does not exist and no default is provided"));
	}

	line = 1;
	state = state_initial;

	while (1) {
		int ch;

		ch = cfstream_getc(cf);
		if (ch == 0)
			die(config_error,
			    NULL, _("unrecognized config file format"));
		if (ch == '\n')
			line++;
		state = transition[state][char2abc(ch)];
		switch (state) {
		case state_major:
			major = major * 10 + ch - '0';
			break;
		case state_minor:
			minor = minor * 10 + ch - '0';
			break;
		case state_error:
			die(config_error,
			    NULL, _("unrecognized config file format"));
		case state_old_format:
			cfstream_putback(cf);
			cfparse_old(cf, config_file_name, line);
			return;
		case state_final:
			cfparse_versioned(cf, config_file_name,
					  line, major, minor);
			return;
		default:
			break;
		}
	}
}

int
parse_file_mode(const char *val, mode_t *mode, struct cfloc const *loc)
{
	char *q;
	unsigned int n = strtoul(val, &q, 8);
	if (*q || (n & ~0777)) {
		cferror(loc, "%s", _("not a valid file mode"));
		return 1;
	}
	*mode = n;
	return 0;
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

static int
check_dir(const char *dir, struct cfloc const *loc)
{
	struct stat st;

	if (dir[0] == '~') {
		if (dir[1] && !absolute_dir_p(dir + 1)) {
			cferror(loc, "%s", _("not an absolute directory name"));
			return 1;
		}
		return 0;
	} else if (!absolute_dir_p(dir)) {
		cferror(loc, "%s", _("not an absolute directory name"));
		return 1;
	}

	if (stat(dir, &st)) {
		cferror(loc, _("cannot stat %s: %s"),
			dir, strerror(errno));
		return 1;
	} else if (!S_ISDIR(st.st_mode)) {
		cferror(loc, _("%s is not a directory"), dir);
		return 1;
	}
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
copy_part(const char *cstr, const char *p, char **pbuf)
{
	size_t len = p - cstr;
	char *buf = malloc(len + 1);
	if (!buf)
		return 1;
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
parse_url(struct cfloc const *loc, const char *cstr,
	  int *pfamily, char **pport, char **ppath)
{
	const char *p;

	p = strchr(cstr, ':');
	if (p) {
		struct socket_family *fp = find_family(cstr, p - cstr);

		if (!fp) {
			cferror(loc, "%s", _("unknown address family"));
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
			cferror(loc, "%s", _("malformed URL"));
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
make_socket(struct cfloc const *loc, int family,
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
			cferror(loc, "%s",
				_("port is meaningless for UNIX sockets"));
			return 1;
		}
		if (strlen(path) > sizeof addr.s_un.sun_path) {
			errno = EINVAL;
			cferror(loc, "%s", _("UNIX socket name too long"));
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
				cferror(loc, "%s", _("bad port number"));
				return -1;
			}
			pnum = htons(pnum);
		} else {
			struct servent *sp = getservbyname(port, "tcp");
			if (!sp) {
				cferror(loc, "%s", _("unknown service name"));
				return -1;
			}
			pnum = sp->s_port;
		}

		if (!path)
			addr.s_in.sin_addr.s_addr = INADDR_ANY;
		else {
			struct hostent *hp = gethostbyname(path);
			if (!hp) {
				cferror(loc, "%s", _("unknown host name %s"),
					path);
				return 1;
			}
			addr.sa.sa_family = hp->h_addrtype;
			switch (hp->h_addrtype) {
			case AF_INET:
				memmove(&addr.s_in.sin_addr, hp->h_addr, 4);
				addr.s_in.sin_port = pnum;
				break;

			default:
				cferror(loc, "%s",
					_("unsupported address family"));
				return 1;
			}
		}
		break;

	default:
		cferror(loc, "%s", _("unsupported address family"));
		return 1;
	}
	pa->len = socklen;
	pa->sa = xmalloc(socklen);
	memcpy(pa->sa, &addr.sa, socklen);
	return 0;
}

int
attrib_umask(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	return parse_file_mode(arg, &rule->mask, loc);
}

int
attrib_chroot(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	char *chroot_dir = xstrdup(arg);
	int rc = 0;

	if (trimslash(chroot_dir) == 0) {
		cferror(loc, "%s", _("invalid chroot directory"));
		rc = 1;
	} else if (check_dir(chroot_dir, loc))
		rc = 1;

	if (rc)
		free(chroot_dir);
	else
		rule->chroot_dir = chroot_dir;
	return rc;

}

int
attrib_chdir(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	rule->home_dir = xstrdup(arg);
	if (trimslash(rule->home_dir) == 0) {
		cferror(loc, "%s", _("invalid home directory"));
		return 1;
	}
	return 0;
}

int
attrib_fork(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	int yes;
	if (get_bool(arg, &yes)) {
		cferror(loc, _("expected boolean value, but found `%s'"),
			arg);
		return 1;
	}
	rule->fork = yes ? rush_true : rush_false;
	return 0;
}

int
attrib_acct(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	int yes;
	if (get_bool(arg, &yes)) {
		cferror(loc, _("expected boolean value, but found `%s'"),
			arg);
		return 1;
	}
	rule->acct = yes ? rush_true : rush_false;
	return 0;
}

int
attrib_post_socket(struct rush_rule *rule, char const *arg,
		   struct cfloc const *loc)
{
	int family;
	char *path;
	char *port;
	int rc;

	if (parse_url(loc, arg,  &family, &port, &path))
		return 1;
	rc = make_socket(loc, family, port ? port : "tcpmux", path,
			 &rule->post_sockaddr);
	free(port);
	free(path);
	return rc;
}

static int
attrib_text_domain(struct rush_rule *rule, char const *arg,
		   struct cfloc const *loc)
{
	rule->i18n.text_domain = xstrdup(arg);
	return 0;
}

static int
attrib_locale_dir(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	rule->i18n.localedir = xstrdup(arg);
	return 0;
}

static int
attrib_locale(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	rule->i18n.locale = xstrdup(arg);
	return 0;
}

static int
attrib_interactive(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	if (get_bool(arg, &rule->interactive)) {
		cferror(loc, _("expected boolean value, but found `%s'"),
			arg);
		return 1;
	}
	return 0;
}

static int
attrib_newgroup(struct rush_rule *rule, char const *arg, struct cfloc const *loc)
{
	struct group *grp;

	if (c_isdigit(arg[0])) {
		char *p;
		unsigned long n = strtoul(arg, &p, 10);

		if (*p == 0) {
			rule->gid = n;
			return 0;
		}
	}

	grp = getgrnam(arg);
	if (!grp) {
		cferror(loc, _("no such group: %s"), arg);
		return 1;
	}
	rule->gid = grp->gr_gid;
	return 0;
}

struct rule_attrib {
	char const *name;
	rule_attrib_setter_t setter;
};

static struct rule_attrib attrib[] = {
	{ "umask",       attrib_umask },
	{ "chroot",      attrib_chroot },
	{ "chdir",       attrib_chdir },
	{ "fork",        attrib_fork },
	{ "acct",        attrib_acct },
	{ "post-socket", attrib_post_socket },
	{ "text-domain", attrib_text_domain },
	{ "locale-dir",  attrib_locale_dir },
	{ "locale",      attrib_locale },
	{ "interactive", attrib_interactive },
	{ "newgroup",    attrib_newgroup },
	{ "newgrp",      attrib_newgroup },
	{ NULL }
};

rule_attrib_setter_t
rule_attrib_lookup(char const *name)
{
	struct rule_attrib *ap;

	for (ap = attrib; ap->name; ap++)
		if (strcmp(ap->name, name) == 0)
			return ap->setter;
	return NULL;
}

static int
glattrib_debug(int argc, struct argval *arghead)
{
	debug_level = arghead->intval;
	return 0;
}

static int
glattrib_sleep_time(int argc, struct argval *arghead)
{
	sleep_time = arghead->intval;
	return 0;
}

static int
glattrib_message(int argc, struct argval *arghead)
{
	int n = string_to_error_index(arghead->strval);
	if (n == -1) {
		cferror(&arghead->loc, _("Unknown message reference"));
		return 1;
	}
	set_error_msg(n, arghead->next->strval);
	return 0;
}

static int
glattrib_regexp(int argc, struct argval *arg)
{
	for (; arg; arg = arg->next) {
		int enable, flag;
		char *p = arg->strval;

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
		else if (strcmp(p, "basic") == 0) {
			flag = REG_EXTENDED;
			enable = !enable;
		} else if (strcmp(p, "icase") == 0
			 || strcmp(p, "ignore-case") == 0)
			flag = REG_ICASE;
		else {
			cferror(&arg->loc, _("unknown regexp flag: %s"), p);
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
glattrib_include_security(int argc, struct argval *arg)
{
	int rc = 0;
	for (; arg; arg = arg->next) {
		if (cfck_keyword(arg->strval)) {
			cferror(&arg->loc, _("unknown keyword: %s"),
				arg->strval);
			rc = 1;
		}
	}
	return rc;
}

static int
glattrib_acct_file_mode(int argc, struct argval *arg)
{
	return parse_file_mode(arg->strval, &rushdb_file_mode, &arg->loc);
}

static int
glattrib_acct_dir_mode(int argc, struct argval *arg)
{
	return parse_file_mode(arg->strval, &rushdb_dir_mode, &arg->loc);
}

static int
glattrib_acct_umask(int argc, struct argval *arg)
{
	return parse_file_mode(arg->strval, &rushdb_umask, &arg->loc);
}

static struct global_attrib global_attrib[] = {
	{ "debug",            "n",  glattrib_debug },
	{ "sleep-time",       "n",  glattrib_sleep_time },
	{ "message",          "ss", glattrib_message },
	{ "regexp",           "s.", glattrib_regexp },
	{ "include-security", "s.", glattrib_include_security },
	{ "acct-file-mode",   "s",  glattrib_acct_file_mode },
	{ "acct-dir-mode",    "s",  glattrib_acct_dir_mode },
	{ "acct-umask",       "s",  glattrib_acct_umask },
	{ NULL }
};

struct global_attrib *
global_attrib_lookup(const char *name)
{
	struct global_attrib *ap;
	for (ap = global_attrib; ap->name; ap++) {
		if (strcmp(ap->name, name) == 0)
			return ap;
	}
	return NULL;
}

void
global_attrib_set(struct global_attrib *glatt,
		  int argc, struct argval *arghead,
		  struct cfloc const *loc)
{
	struct argval *arg;
	int i;

	for (i = 0, arg = arghead; arg; arg = arg->next) {
		switch (glatt->argt[i]) {
		case 'n':
			if (!arg->isnum) {
				cferror(&arg->loc, "%s",
					_("expected numeric argument"));
				return;
			}
			i++;
			break;
		case 's':
			i++;
			break;
		case '.':
			break;
		case 0:
			cferror(&arg->loc, "%s", _("too many arguments"));
			return;
		}
	}
	if (glatt->argt[i] && glatt->argt[i] != '.') {
		cferror(loc, "%s", _("not enough many arguments"));
		return;
	}

	glatt->setter(argc, arghead);
}

void
arglist_free(struct argval *arg)
{
	while (arg) {
		struct argval *next = arg->next;
		free(arg->strval);
		free(arg);
		arg = next;
	}
}
