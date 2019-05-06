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

struct cfloc curloc;

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

static void
stringbuf_add_escape_dfl(struct stringbuf *sb, char const *text, size_t leng)
{
	int c = text[leng - 1];

	stringbuf_add_array(sb, text, leng - 2);
	switch (c) {
	case 'a':
		stringbuf_add_char(sb, '\a');
		break;
	case 'b':
		stringbuf_add_char(sb, '\b');
		break;
	case 'f':
		stringbuf_add_char(sb, '\f');
		break;
	case 'n':
		stringbuf_add_char(sb, '\n');
		break;
	case 'r':
		stringbuf_add_char(sb, '\r');
		break;
	case 't':
		stringbuf_add_char(sb, '\t');
		break;
	case 'v':
		stringbuf_add_char(sb, '\v');
		break;
	case '\\':
	case '\"':
		stringbuf_add_char(sb, c);
		break;
	case '\n':
		advance_line(1);
		break;
	case '%':
		stringbuf_add_array(sb, text + leng - 2, 2);
		break;
	default: {
		struct cfloc loc;
		loc.beg = loc.end = curloc.end;
		loc.beg.column -= 2;
		cferror(&loc, _("unrecognized escape \\%c"), c);
		stringbuf_add_array(sb, text + leng - 2, 2);
	}
	}
}

static void
stringbuf_add_escape_octal(struct stringbuf *sb, char const *text, size_t leng)
{
	stringbuf_add_array(sb, text, leng - 4);
	stringbuf_add_char(sb, strtoul(text + leng - 3, NULL, 8));
}

static void
stringbuf_add_escape_hex(struct stringbuf *sb, char const *text, size_t leng)
{
	stringbuf_add_array(sb, text, leng - 5);
	stringbuf_add_char(sb, strtoul(text + leng - 2, NULL, 16));
}

%}
%x NORMAL ARGS INMATCH QSTR VAR
%%
<INITIAL>{
rush[ \t]+2\.0[ \t]*$ {
	BEGIN(NORMAL);
	return tok(PREFACE);
  }
#.*\n       { advance_line(1); }
\n+         { advance_line(yyleng); }
[ \t]+      reset_loc();
.           return tok(BOGUS);
}

<NORMAL,INMATCH,ARGS>{
#.*\n       { advance_line(1);
	      BEGIN(NORMAL);
	      return tok(EOL); }
\n+         { advance_line(yyleng);
	      BEGIN(NORMAL);
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
"in"        return tok(IN);
"member"    return tok(MEMBER);
}

<NORMAL>{
"rule"      { BEGIN(ARGS); return tok(RULE); }
"global"    { return tok(GLOBAL); }
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
[A-Za-z_][A-Za-z_0-9-]* {
	if ((yylval.attrib = rule_attrib_lookup(yytext))) {
	        BEGIN(ARGS);
		return tok(ATTRIB);
	} else if ((yylval.global_attrib = global_attrib_lookup(yytext))) {
		BEGIN(ARGS);
		return tok(GLATTRIB);
	} else {
		yylval.str = xstrdup(yytext);
  	        return tok(IDENT);
        }
		}
.       return yytext[0];
}

<ARGS,INMATCH>{
[+-]?[0-9]+                   { yylval.num.strval = xstrdup(yytext);
				yylval.num.intval = atoi(yytext);
				return tok(NUMBER); }
[A-Za-z_][A-Za-z0-9_-]*       { yylval.str = xstrdup(yytext);
				return tok(IDENT); }
[A-Za-z_/+-][A-Za-z0-9_/+-]*  { yylval.str = xstrdup(yytext);
				return tok(STRING); }
\$[A-Za-z_][A-Za-z_0-9-]*     { yylval.str = xstrdup(yytext);
				return tok(STRING);  }
\$\{[A-Za-z_][A-Za-z_0-9-]*\} { yylval.str = xstrdup(yytext);
				return tok(STRING); }
\$\{[A-Za-z_][A-Za-z_0-9-]*:?[-+=\?] {
				stringbuf_init(&sb);
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }
\$[0-9]|\$\{[0-9]+\}          { yylval.str = xstrdup(yytext);
				return tok(STRING); }
\$\{[0-9]+:?[-+=\?]           {
				stringbuf_init(&sb);
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }

%[0-9]                   { yylval.str = xstrdup(yytext);
			   return tok(STRING); }
\"[^\\\"\n]*\"           { yylval.str = xmalloc(yyleng-1);
			   memcpy(yylval.str, yytext + 1, yyleng - 2);
			   yylval.str[yyleng - 2] = 0;
			   return tok(STRING); }
\"[^\\\"\n]*\\[0-9]{3}   { stringbuf_init(&sb);
			   stringbuf_add_escape_octal(&sb,
						      yytext + 1, yyleng - 1);
			   pushstart(QSTR); }
\"[^\\\"\n]*\\0[xX][a-fA-F0-9]{2} {
			   stringbuf_init(&sb);
			   stringbuf_add_escape_hex(&sb,
						    yytext + 1, yyleng - 1);
			   pushstart(QSTR); }
\"[^\\\"\n]*\\.|\"[^\\\"\n]*\\\n  {
	                   stringbuf_init(&sb);
			   stringbuf_add_escape_dfl(&sb,
						    yytext + 1, yyleng - 1);
			   pushstart(QSTR); }
"=~"                       return tok(XF);
.                          return yytext[0];
}

<QSTR>{
[^\\\"\n]*\"             { stringbuf_add_array(&sb, yytext, yyleng - 1);
	                   stringbuf_finish(&sb);
			   yylval.str = sb.buffer;
			   popstart();
			   return tok(STRING); }
[^\\\"\n]*\\[0-9]{3}     { stringbuf_add_escape_octal(&sb, yytext, yyleng); }
[^\\\"\n]*\\0[xX][a-fA-F0-9]{2} {
	                   stringbuf_add_escape_hex(&sb, yytext, yyleng); }
[^\\\"\n]*\\.|[^\\\"\n]*\\\n { stringbuf_add_escape_dfl(&sb, yytext, yyleng); }
\n   {  advance_line(1);
	yyerror("unescaped newline in quoted string"); }
.    {  straychar(yytext[0]); }
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
[^}\"\$%]+                    { stringbuf_add_array(&sb, yytext, yyleng); }
.                             { straychar(yytext[0]);
	                        stringbuf_add_char(&sb, yytext[0]); }
}
%%
void
straychar(int c)
{
	static char *start_name[] = {
		[INITIAL] = "looking for rush version clause",
		[NORMAL] = "looking for rule",
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

void
skiptoeol(void)
{
	int c;
	extern int yychar;

	if (yychar == EOL)
		return;
	c = input();
	if (c == EOF)
		return;
	do {
		if (c == '\n') {
			break;
		}
	} while ((c = input()) != EOF);
	unput('\n');
}

void
restorenormal(void)
{
	while (start_tos)
		popstart();
	BEGIN(NORMAL);
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

void
cflex_debug(int v)
{
#ifdef FLEX_DEBUG
	yy_flex_debug = v;
#endif
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

void
cflex_pushargs(void)
{
	pushstart(ARGS);
}

void
cflex_popargs(void)
{
	popstart();
}

void
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

int
parse_old_rc(void)
{
	CFSTREAM *cf = input_stream;
	char const *filename = curloc.beg.filename;
	
	YY_FLUSH_BUFFER;
	input_stream = NULL;

	cfstream_rewind(cf);
	return cfparse_old(cf, filename, 1);
}

