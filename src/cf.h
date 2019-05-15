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

/* String buffer */
struct stringbuf {
	char *buffer;  /* The buffer itself */
	size_t size;   /* Size of the buffer */
	size_t pos;    /* Actual number of characters in the buffer */
};

void stringbuf_init(struct stringbuf *sb);
void stringbuf_free(struct stringbuf *sb);
void stringbuf_add_char(struct stringbuf *sb, int c);
void stringbuf_add_string(struct stringbuf *sb, char const *str);
void stringbuf_add_array(struct stringbuf *sb, char const *str, size_t len);
void stringbuf_add_num(struct stringbuf *sb, unsigned n);
void stringbuf_finish(struct stringbuf *sb);

struct cfpoint {               /* A point in the configuration file */
	char const *filename;
	int line;
	int column;
};

struct cfloc {                 /* Location in the configuration file */
	struct cfpoint beg;
	struct cfpoint end;
};

#define YYLTYPE struct cfloc

#define YYLLOC_DEFAULT(Current, Rhs, N)                           \
  do                                                              \
    {                                                             \
      if (N)                                                      \
        {                                                         \
          (Current).beg = YYRHSLOC(Rhs, 1).beg;                   \
          (Current).end = YYRHSLOC(Rhs, N).end;                   \
        }                                                         \
      else                                                        \
        {                                                         \
          (Current).beg = YYRHSLOC(Rhs, 0).end;                   \
          (Current).end = (Current).beg;                          \
        }                                                         \
    } while (0)

#define YY_LOCATION_PRINT(File, Loc)                              \
	cfloc_print(&(Loc), File)

void cfpoint_format(struct cfpoint const *cfp, struct stringbuf *sb);
void cfloc_format(struct cfloc const *cfl, struct stringbuf *sb);
void cfloc_print(struct cfloc const *cfl, FILE *fp);

struct cfnumber {        /* Representation of a "number-like" string */
	int intval;      /* Numeric value */
	char *strval;    /* String value */
};

void cferror(struct cfloc const *loc, char const *fmt, ...);
void vcferror(struct cfloc const *loc, char const *fmt, va_list ap);

void yyerror(char const *msg,...);


typedef struct cfstream {
	int fd;        /* File descriptor (-1 for built-in config) */
	char *buffer;  /* Read buffer */
	size_t size;   /* Size of buffer */
	size_t level;  /* Number of data bytes available in the buffer */
	size_t pos;    /* Current read position */
	unsigned eol:1;/* 1 if the last character read was \n, 0 otherwise */
	unsigned eof:1;/* 1 if end of file has been reached */
} CFSTREAM;

CFSTREAM *cfstream_open_file(char const *filename);
CFSTREAM *cfstream_open_stdin(void);
CFSTREAM *cfstream_open_mem(char const *buffer, size_t len);
ssize_t cfstream_read(CFSTREAM *, char *, size_t);
void cfstream_close(CFSTREAM *);
void cfstream_rewind(CFSTREAM *cf);
static inline int
cfstream_getc(CFSTREAM *cf)
{
	char c;
	if (cfstream_read(cf, &c, 1) == 0)
		return 0;
	return c;
}
int cfstream_same_file(CFSTREAM *cf, struct stat const *st);

void cflex_debug(int v);
void cfgram_debug(int v);
void cflex_test(char const *file);
void dumpstr(char const *string, FILE *fp);

void cflex_setup(CFSTREAM *cf, char const *filename, int line);
int cflex_include(char const *filename, struct cfloc const *loc);
void cflex_pushargs(void);
void cflex_popargs(void);
void cflex_normal(void);
void skiptoeol(void);
void restorenormal(void);

int cfparse_old(CFSTREAM *cf, char const *filename, int line);

int yylex(void);
int yyparse(void);

void cfparse(void);
int parse_old_rc(void);

struct rush_rule *new_rush_rule(char const *tag);
struct transform_node *new_transform_node(struct rush_rule *rule,
					  enum transform_node_type type);
struct test_node *new_test_node(enum test_type type);
struct envar *new_envar(struct rush_rule *rule,
			char const *name, size_t nlen,
			char const *value, size_t vlen,
			enum envar_type type);

typedef int (*rule_attrib_setter_t) (struct rush_rule *rule,
				     char const *arg, struct cfloc const *loc);
rule_attrib_setter_t rule_attrib_lookup(char const *name);

struct argval {
	struct argval *next;
	struct cfloc loc;
	int isnum;
	char *strval;
	int intval;
};

void arglist_free(struct argval *arg);

typedef int (*global_attrib_setter_t) (int argc, struct argval *arghead);

struct global_attrib {
	char const *name;
	char *argt;
	global_attrib_setter_t setter;
};

struct global_attrib *global_attrib_lookup(const char *name);
void global_attrib_set(struct global_attrib *glatt,
		       int argc, struct argval *arghead,
		       struct cfloc const *loc);


extern int re_flags;
extern int expand_undefined;
extern struct cfloc curloc;

/* The following are shared between the two configuration parsers. Once
   the legacy parses is phased out, they will become static to cf.c */
void trimws(char *s);
size_t trimslash(char *s);
int attrib_umask(struct rush_rule *rule, char const *arg, struct cfloc const *loc);
int attrib_chroot(struct rush_rule *rule, char const *arg, struct cfloc const *loc);
int attrib_chdir(struct rush_rule *rule, char const *arg, struct cfloc const *loc);
int attrib_fork(struct rush_rule *rule, char const *arg, struct cfloc const *loc);
int attrib_acct(struct rush_rule *rule, char const *arg, struct cfloc const *loc);
int attrib_post_socket(struct rush_rule *rule, char const *arg,
		       struct cfloc const *loc);
int parse_file_mode(const char *val, mode_t *mode, struct cfloc const *loc);




	
	
