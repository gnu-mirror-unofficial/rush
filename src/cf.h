struct stringbuf {
	char *buffer;
	size_t size;
	size_t pos;
};

void stringbuf_init(struct stringbuf *sb);
void stringbuf_free(struct stringbuf *sb);
void stringbuf_add_char(struct stringbuf *sb, int c);
void stringbuf_add_string(struct stringbuf *sb, char const *str);
void stringbuf_add_array(struct stringbuf *sb, char const *str, size_t len);
void stringbuf_add_num(struct stringbuf *sb, unsigned n);
void stringbuf_finish(struct stringbuf *sb);

struct cfpoint {
	char const *filename;
	int line;
	int column;
};

struct cfloc {
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

struct cfnumber {
	int intval;
	char *strval;
};

void cferror(struct cfloc const *loc, char const *fmt, ...);
void vcferror(struct cfloc const *loc, char const *fmt, va_list ap);

void yyerror(char const *msg,...);


typedef struct cfstream {
	int fd;
	char *buffer;
	size_t size;
	size_t level;
	size_t pos;
} CFSTREAM;

CFSTREAM *cfstream_open_file(char const *filename);
CFSTREAM *cfstream_open_mem(char const *buffer, size_t len);
ssize_t cfstream_read(CFSTREAM *, char *, size_t);
void cfstream_close(CFSTREAM *);
static inline int
cfstream_getc(CFSTREAM *cf)
{
	char c;
	if (cfstream_read(cf, &c, 1) == 0)
		return 0;
	return c;
}

void cflex_debug(int v);
void cfgram_debug(int v);

void cflex_setup(CFSTREAM *cf, char const *filename, int line);
int cflex_include(char const *filename, struct cfloc const *loc);

void cfparse_old(CFSTREAM *cf, char const *filename, int line);
void cfparse_versioned(CFSTREAM *cf, char const *filename, int line,
		       int major, int minor);

int yylex(void);
int yyparse(void);

void cfparse(void);

struct rush_rule *new_rush_rule(void);
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
extern struct cfloc curloc;

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




	
	
