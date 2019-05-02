%{
#include <rush.h>
#include <sys/stat.h>
#include <cf.h>
#include <cfgram.h>
#include <assert.h>

static CFSTREAM *input_stream;
static struct stringbuf sb;

struct source_file {
	struct source_file *prev;
	char filename[1];
};

struct source_file *source_file_last;

char const *
new_source_file_name(char const *f)
{
	struct source_file *file;

	for (file = source_file_last; file; file = file->prev) {
		if (strcmp(file->filename, f) == 0)
			return file->filename;
	}

	file = xmalloc(sizeof(file[0]) + strlen(f));
	strcpy(file->filename, f);
	file->prev = source_file_last;
	source_file_last = file;
	return file->filename;
}

static struct cfloc curloc;

#define YY_USER_ACTION	(curloc.end.column += yyleng);

static inline void
advance_line(size_t n)
{
	curloc.end.line += n;
	curloc.end.column = 1;
}

static inline void
reset_loc(void)
{
	curloc.beg = curloc.end;
}

static inline int
tok(int c)
{
	yylloc = curloc;
	yylloc.end.column--;
	reset_loc();
	return c;
}

struct start_cond {
	struct start_cond *next;
	int start;
};
static struct start_cond *start_tos;

static inline void
pushstart(int newstart)
{
	struct start_cond *sc = malloc(sizeof(sc[0]));
	sc->start = YY_START;
	sc->next = start_tos;
	start_tos = sc;
	BEGIN(newstart);
}

static inline void
popstart(void)
{
	struct start_cond *tos = start_tos;
	assert(tos != NULL);
	start_tos = tos->next;
	BEGIN(tos->start);
	free(tos);
}
static void straychar(int);

#undef YY_INPUT
#define YY_INPUT(buf,result,max_size)		\
	(result) = cfstream_read(input_stream, buf, max_size)

%}
%option nounput
%option noinput
%x ARGS INMATCH QSTR VAR
%%
<INITIAL,INMATCH,ARGS>{
#.*\n       { advance_line(1);
	      BEGIN(INITIAL);
	      return tok(EOL); }
\n+         { advance_line(yyleng);
	      BEGIN(INITIAL);
	      return tok(EOL); }
[ \t]+      reset_loc();
}

<INMATCH>{
"&&"        return tok(AND);
"||"        return tok(OR);
"!"         return tok(NOT);
"=="        return tok(EQ);
"!="        return tok(NE);
"<"         return tok(LT);
"<="        return tok(LE);
">"         return tok(GT);
">="        return tok(GE);
"~"         return tok('~');
"in"        return tok(IN);
"member"    return tok(MEMBER);
}

<INITIAL>{
"rule"      { return tok(RULE); }
"set"       { BEGIN(ARGS); return tok(SET); }
"unset"     { BEGIN(ARGS); return tok(UNSET); }
"match"     { BEGIN(INMATCH); return tok(MATCH); }
"fallthrough"|"fall-through" { BEGIN(ARGS); return tok(FALLTHROUGH); }
"include"   { BEGIN(ARGS); return tok(INCLUDE); }
"limits"    { BEGIN(ARGS); return tok(LIMITS); }
"clrenv"    { BEGIN(ARGS); return tok(CLRENV); }
"setenv"    { BEGIN(ARGS); return tok(SETENV); }
"unsetenv"  { BEGIN(ARGS); return tok(UNSETENV); }
"keepenv"   { BEGIN(ARGS); return tok(KEEPENV); }
"delete"    { BEGIN(ARGS); return tok(DELETE); }
"exit"      { BEGIN(ARGS); return tok(EXIT); }
"map"       { BEGIN(ARGS); return tok(MAP); }
[A-Za-z_][A-Za-z_0-9-]* { /* FIXME: */ BEGIN(ARGS); return tok(KEYWORD); }
}

<ARGS,INMATCH>{
[0-9]+                        { yylval.num.strval = xstrdup(yytext);
				yylval.num.intval = atoi(yytext);
				return tok(NUMBER); }
[A-Za-z_][A-Za-z_0-9-]*       { yylval.str = xstrdup(yytext);
				return tok(IDENT); }
\$[A-Za-z_][A-Za-z_0-9-]*     { yylval.str = xstrdup(yytext);
				return tok(STRING);  }
\$\{[A-Za-z_][A-Za-z_0-9-]*\} { yylval.str = xstrdup(yytext);
				return tok(STRING); }
\$\{[A-Za-z_][A-Za-z_0-9-]*:?[-+=\?] {
				stringbuf_init(&sb);
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }
%[0-9]                   { yylval.str = xstrdup(yytext);
			   return tok(STRING); }
\"[^\\\"\n]*\"           { yylval.str = xmalloc(yyleng-1);
			   memcpy(yylval.str, yytext + 1, yyleng - 2);
			   yylval.str[yyleng - 2] = 0;
			   return tok(STRING); }
\"[^\\\"\n]*\\[abfnrtv]  { stringbuf_init(&sb);
			   stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
			   stringbuf_add_char(&sb,
					      wordsplit_c_unquote_char(yytext[yyleng-1]));
			   pushstart(QSTR); }
\"[^\\\"\n]*\\\"         { stringbuf_init(&sb);
			   stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
			   stringbuf_add_char(&sb, '"');
			   pushstart(QSTR); }
\"[^\\\"\n]*\\\\         { stringbuf_init(&sb);
			   stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
			   stringbuf_add_char(&sb, '\\');
			   pushstart(QSTR); }
\"[^\\\"\n]*\\\n         { stringbuf_init(&sb);
			   stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
			   advance_line(1);
			   pushstart(QSTR); }
\"[^\\\"\n]*\\[0-9]{3}   { stringbuf_init(&sb);
			   stringbuf_add_array(&sb, yytext + 1, yyleng - 5);
			   stringbuf_add_char(&sb,
					      strtoul(yytext + yyleng - 3,
						      NULL, 8));
			   pushstart(QSTR); }
\"[^\\\"\n]*\\0[xX][a-fA-F0-9]{2} {
			   stringbuf_init(&sb);
			   stringbuf_add_array(&sb, yytext + 1, yyleng - 6);
			   stringbuf_add_char(&sb,
					      strtoul(yytext + yyleng - 2,
						      NULL, 16));
			   pushstart(QSTR); }
}

<QSTR>{
[^\\\"\n]*\"             { stringbuf_add_array(&sb, yytext, yyleng - 1);
	                   stringbuf_finish(&sb);
			   yylval.str = sb.buffer;
			   popstart();
			   return tok(STRING); }
[^\\\"\n]*\\[abfnrtv]    { stringbuf_add_array(&sb, yytext, yyleng - 2);
			   stringbuf_add_char(&sb,
					      wordsplit_c_unquote_char(yytext[yyleng-1]));
			 }
[^\\\"\n]*\\\"           { stringbuf_add_array(&sb, yytext, yyleng - 2);
			   stringbuf_add_char(&sb, '"'); }
[^\\\"\n]*\\\\           { stringbuf_add_array(&sb, yytext, yyleng - 2);
			   stringbuf_add_char(&sb, '\\'); }
[^\\\"\n]*\\\n           { stringbuf_add_array(&sb, yytext, yyleng - 2);
			   advance_line(1); }
[^\\\"\n]*\\[0-9]{3}     { stringbuf_add_array(&sb, yytext, yyleng - 4);
			   stringbuf_add_char(&sb,
					      strtoul(yytext + yyleng - 3,
						      NULL, 8)); }
[^\\\"\n]*\\0[xX][a-fA-F0-9]{2} {
			   stringbuf_add_array(&sb, yytext, yyleng - 5);
			   stringbuf_add_char(&sb,
					      strtoul(yytext + yyleng - 2,
						      NULL, 16)); }
\n   { yyerror("unescaped newline in quoted string"); return BOGUS; }
}

<VAR>{
\}                            { popstart();
				if (YY_START != VAR) {
					return tok(STRING);
				}
			      }
\$[A-Za-z_][A-Za-z_0-9-]*     { stringbuf_add_array(&sb, yytext, yyleng); }
\$\{[A-Za-z_][A-Za-z_0-9-]*\} ;
\$\{[A-Za-z_][A-Za-z_0-9-]*:?[-+=\?] {
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }
%[0-9]                        { stringbuf_add_array(&sb, yytext, yyleng); }
\"[^\\\"\n]*\"                { stringbuf_add_array(&sb, yytext + 1, yyleng - 2); }
\"[^\\\"\n]*\\[abfnrtv]       { stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
				stringbuf_add_char(&sb,
						   wordsplit_c_unquote_char(yytext[yyleng-1]));
				pushstart(QSTR); }
\"[^\\\"\n]*\\\"              { stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
				stringbuf_add_char(&sb, '"');
				pushstart(QSTR); }
\"[^\\\"\n]*\\\\              { stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
				stringbuf_add_char(&sb, '\\');
				pushstart(QSTR); }
\"[^\\\"\n]*\\\n              { stringbuf_add_array(&sb, yytext + 1, yyleng - 3);
				advance_line(1);
				pushstart(QSTR); }
\"[^\\\"\n]*\\[0-9]{3}        { stringbuf_add_array(&sb, yytext + 1, yyleng - 5);
				stringbuf_add_char(&sb,
						   strtoul(yytext + yyleng - 3,
							   NULL, 8));
				pushstart(QSTR); }
\"[^\\\"\n]*\\0[xX][a-fA-F0-9]{2} {
				stringbuf_add_array(&sb, yytext + 1, yyleng - 6);
				stringbuf_add_char(&sb,
						   strtoul(yytext + yyleng - 2,
							   NULL, 16));
				pushstart(QSTR); }
[^}\"\$%]+                      { stringbuf_add_array(&sb, yytext, yyleng); }
}

<INITIAL,INMATCH,ARGS,VAR,QSTR>.   { straychar(yytext[0]); return tok(BOGUS); }
%%
void
straychar(int c)
{
	static char *start_name[] = {
		[INITIAL] = "looking for rule",
		[INMATCH] = "scanning match arguments",
		[ARGS] = "scanning arguments",
		[QSTR] = "scanning quoted string",
		[VAR] = "scanning variable reference"
	};
	if (isprint(c)) {
		yyerror("stray character %c while %s", c,
			start_name[YY_START]);
	} else {
		yyerror("stray character %03o while %s", c,
			start_name[YY_START]);
	}
}

/* Input_Stream context stack */
struct inpctx {
	struct inpctx   *prev;
	struct cfloc    loc;   /* Location */
	dev_t           dev;
	ino_t           ino;
	int             is_file;
	CFSTREAM        *input_stream;
	YY_BUFFER_STATE buf;   /* lex buffer state */
};

static struct inpctx *inpctx_tos;
static dev_t input_stream_dev;
static ino_t input_stream_ino;

static struct inpctx *
inpctx_locate(struct stat *st)
{
	struct inpctx *ctx;

	for (ctx = inpctx_tos; ctx; ctx = ctx->prev)
		if (ctx->dev == st->st_dev && ctx->ino == st->st_ino)
			break;
	return ctx;
}

static void
inpctx_push(void)
{
	struct inpctx *ctx = xmalloc(sizeof(ctx[0]));

	ctx->loc = curloc;
	ctx->dev = input_stream_dev;
	ctx->ino = input_stream_ino;
	ctx->input_stream = input_stream;
	ctx->buf = YY_CURRENT_BUFFER;
	ctx->prev = inpctx_tos;
	inpctx_tos = ctx;
}

static void
inpctx_unpush(void)
{
	struct inpctx *ctx = inpctx_tos;
	inpctx_tos = ctx->prev;
	free(ctx);
}

static int
inpctx_pop(void)
{
	struct inpctx *ctx = inpctx_tos;
	if (!ctx)
		return 1;
	inpctx_tos = ctx->prev;

	curloc = ctx->loc;
	input_stream_dev = ctx->dev;
	input_stream_ino = ctx->ino;
	input_stream = ctx->input_stream;
	yy_delete_buffer(YY_CURRENT_BUFFER);
	yy_switch_to_buffer(ctx->buf);
	free(ctx);
	return 0;
}

static void
curloc_init(char const *filename, int line)
{
	curloc.beg.filename = new_source_file_name(filename);
	curloc.beg.line = line;
	curloc.beg.column = 1;
	curloc.end = curloc.beg;
}

void
cflex_setup(CFSTREAM *cf, char const *filename, int line)
{
	curloc_init(filename, line);
	input_stream = cf;
	YY_FLUSH_BUFFER;
}

int
cflex_include(char const *filename, struct cfloc const *loc)
{
	char *name = expand_tilde(filename, rush_pw->pw_dir);
	struct stat st;
	struct inpctx *ctx;
	
	if (trimslash(name) == 0) {
		free(name);
		cferror(loc, _("invalid include file name"));
		return -1;
	}

	if (stat(name, &st)) {
		if (errno == ENOENT) {
			debug(1, _("Ignoring non-existing include file %s"),
			      name);
			free(name);
			return 0;
		} else {
			cferror(loc, _("cannot stat file %s: %s"),
				name, strerror(errno));
			free(name);
			return -1;
		}
	} 

	if (S_ISDIR(st.st_mode)) {
		char *file = make_file_name(name, rush_pw->pw_name);
		free(name);
		name = file;
		if (access(name, F_OK)) {
		        if (errno == ENOENT) {
				debug(1,
				      _("Ignoring non-existing include file %s"),
				      name);
				free(name);
				return 0;
			} else {
				cferror(loc, "access(%s): %s",
					name, strerror(errno));
				free(name);
				return -1;
			}
		}
	}

	inpctx_push();
	if ((ctx = inpctx_locate(&st))) {
		cferror(loc, "%s already included", name);
		cferror(&ctx->loc, "%s already included here", name);
		inpctx_unpush();
		free(name);
		return -1;
	}
	
	cflex_setup(cfstream_open_file(name), name, 1);
	free(name);

	return 0;
}

int
yywrap(void)
{
	return inpctx_pop();
}
