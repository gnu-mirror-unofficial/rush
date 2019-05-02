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
			
			
		

		
