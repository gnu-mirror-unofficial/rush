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

/* Current input stream (yyin is not used) */
static CFSTREAM *input_stream;
/* Buffer for composing string values */
static struct stringbuf sb;

/* Names of the source files form a singly-linked list. They remain in
   the memory until the end of run because various objects refer to them
   (most notably, rush_rule). */
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

/* Current input location */
struct cfloc curloc;
/* User action is set uo to update end column. */
#define YY_USER_ACTION	(curloc.end.column += yyleng);

/* Advance the end point of the current location N lines. */
static inline void
advance_line(size_t n)
{
	curloc.end.line += n;
	curloc.end.column = 1;
}

/* Reset the start point of the current location to its end point. This
   starts the next token. */
static inline void
reset_loc(void)
{
	curloc.beg = curloc.end;
}

/* This is used in the scanner actions below to return token types. */
static inline int
tok(int c)
{
	yylloc = curloc;
	yylloc.end.column--;
	reset_loc();
	return c;
}

/* The scanner implements several exclusive conditions, some of which
   are preserved on stack. */
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
	if (!tos)
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: state stack is empty"),
		    __FILE__, __LINE__);
	start_tos = tos->next;
	BEGIN(tos->start);
	free(tos);
}

static int in_var(void);

/* Read next chunk of the input. */
#undef YY_INPUT
#define YY_INPUT(buf,result,max_size)		\
	(result) = cfstream_read(input_stream, buf, max_size)

/* Additional stringbuf function for use when processing escape sequences.
   SB is the string buffer, TEXT is the input text ending with '\' + something,
   LENG is number of bytes in it.
 */

/* Default function: TEXT ends with a C-style escape sequence (e.g. \v) or
   rush-specific \% escape.
   Unrecognized escape sequence is reported and transferred varbatim
   to the output.
   Within a ${V:-""} construct, only "\\n" and "\%" are processed, the rest
   is retained. It will be expanded by wordsplit.
*/
static void
stringbuf_add_escape_dfl(struct stringbuf *sb, char const *text, size_t leng)
{
	int c = text[leng - 1];

	if (in_var()) {
		if (c != '\n' && c != '%') {
			stringbuf_add_array(sb, text, leng);
			return;
		}
	}

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

/* TEXT ends with a '\' followed by a 3-byte octal number.
   No expansion occurs within a ${V:-""} construct.
*/
static void
stringbuf_add_escape_octal(struct stringbuf *sb, char const *text, size_t leng)
{
	if (in_var()) {
		stringbuf_add_array(sb, text, leng);
	} else {
		stringbuf_add_array(sb, text, leng - 4);
		stringbuf_add_char(sb, strtoul(text + leng - 3, NULL, 8));
	}
}

/* TEXT ends with a '\x' followed by a 2-byte hex number.
   No expansion occurs within a ${V:-""} construct.
*/
static void
stringbuf_add_escape_hex(struct stringbuf *sb, char const *text, size_t leng)
{
	if (in_var()) {
		stringbuf_add_array(sb, text, leng);
	} else {
		stringbuf_add_array(sb, text, leng - 4);
		stringbuf_add_char(sb, strtoul(text + leng - 2, NULL, 16));
	}
}

/* Input_Stream context stack */
struct inpctx {
	struct inpctx   *prev;
	struct cfloc    loc;   /* Location */
	CFSTREAM        *input_stream;
	YY_BUFFER_STATE buf;   /* lex buffer state */
};

static struct inpctx *inpctx_tos;

/* Returns 1 if an included file is being processed. */
static inline int
in_included_file(void)
{
	return inpctx_tos != NULL;
}

/* Look up in the stack for the input context matching the device and
   inode numbers from ST. */
static struct inpctx *
inpctx_locate(struct stat *st)
{
	struct inpctx *ctx;

	for (ctx = inpctx_tos; ctx; ctx = ctx->prev)
		if (cfstream_same_file(ctx->input_stream, st))
			break;
	return ctx;
}

/* Push current input context on stack. */
static void
inpctx_push(void)
{
	struct inpctx *ctx = xmalloc(sizeof(ctx[0]));

	ctx->loc = curloc;
	ctx->input_stream = input_stream;
	ctx->buf = YY_CURRENT_BUFFER;
	ctx->prev = inpctx_tos;
	inpctx_tos = ctx;
	yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));
}

/* Pop the top of stack into the current input context. */
static int
inpctx_pop(void)
{
	struct inpctx *ctx = inpctx_tos;
	if (!ctx)
		return 1;
	inpctx_tos = ctx->prev;

	curloc = ctx->loc;
	input_stream = ctx->input_stream;
	yy_delete_buffer(YY_CURRENT_BUFFER);
	yy_switch_to_buffer(ctx->buf);
	free(ctx);
	return 0;
}

/* Forward declarations */
static void straychar(int);
static int noinc(void);
%}
%x NORMAL ARGS QSTR VAR
%option nounput
%%
 /* INITIAL: The scanner is processing the initial portion of the input file,
    until the version clause ("rush X.Y\n"), upon which the NORMAL state is
    activated, or any other token, upon which the control is transferred to
    the legacy parser (see config.c).
  */
<INITIAL>{
"rush"     return RUSH;
[0-9]+\.[0-9]+  { char *p;
	          yylval.version.major = strtoul(yytext, &p, 10);
		  yylval.version.minor = strtoul(p + 1, NULL, 10);
		  return tok(T_VERSION); }
\\\n        { advance_line(1); }
#.*\n      { advance_line(1); return EOL; }
\n         { advance_line(1); return EOL; }
[ \t]+     reset_loc();
.          return tok(BOGUS);
}

<NORMAL,ARGS>{
\\\n        { advance_line(1); }
#.*\n       { advance_line(1);
	      BEGIN(NORMAL);
	      return tok(EOL); }	 
\n          { advance_line(1);
	      BEGIN(NORMAL);
	      return tok(EOL); }
[ \t]+      reset_loc();
}

 /* NORMAL: The input point is before the next keyword.
  */
<NORMAL>{
"rule"      { if (!noinc()) {
	              BEGIN(ARGS);
		      return tok(RULE);
              }
            }
"global"    { if (!noinc()) return tok(GLOBAL); }
"set"       { BEGIN(ARGS); return tok(SET); }
"unset"     { BEGIN(ARGS); return tok(UNSET); }
"insert"    { BEGIN(ARGS); return tok(INSERT); }
"match"     { BEGIN(ARGS); return tok(MATCH); }
"fallthrough"|"fall-through" { BEGIN(ARGS); return tok(FALLTHROUGH); }
"include"   { BEGIN(ARGS); return tok(INCLUDE); }
"limits"    { BEGIN(ARGS); return tok(LIMITS); }
"clrenv"    { BEGIN(ARGS); return tok(CLRENV); }
"setenv"    { BEGIN(ARGS); return tok(SETENV); }
"unsetenv"  { BEGIN(ARGS); return tok(UNSETENV); }
"keepenv"   { BEGIN(ARGS); return tok(KEEPENV); }
"evalenv"   { BEGIN(ARGS); return tok(EVALENV); }
"delete"    { BEGIN(ARGS); return tok(DELETE); }
"exit"      { BEGIN(ARGS); return tok(EXIT); }
"map"       { BEGIN(ARGS); return tok(MAP); }
"remopt"    { BEGIN(ARGS); return tok(REMOPT); }
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
.       return tok(yytext[0]);
}

 /* ARGS: Processing arguments to a configuration statement.
  */
<ARGS>{
"&&"                          return tok(AND);
"||"                          return tok(OR);
"!"                           return tok(NOT);
"=="                          return tok(EQ);
"!="                          return tok(NE);
"<"                           return tok(LT);
"<="                          return tok(LE);
">"                           return tok(GT);
">="                          return tok(GE);
"!~"                          return tok(NM);
"in"                          return tok(IN);
"group"                       return tok(GROUP);
[+-]?[0-9]+                   { yylval.num.strval = xstrdup(yytext);
				yylval.num.intval = atoi(yytext);
				return tok(NUMBER); }
[A-Za-z_][A-Za-z0-9_-]*       { yylval.str = xstrdup(yytext);
				return tok(IDENT); }
[^ \t\n\\\"!=<>(){}\[\]\$%&|~#]+ { yylval.str = xstrdup(yytext);
			  	   return tok(STRING); }
\$[A-Za-z_][A-Za-z_0-9-]*     { yylval.str = xstrdup(yytext);
				return tok(STRING);  }
\$\{[A-Za-z_][A-Za-z_0-9-]*\} { yylval.str = xstrdup(yytext);
				return tok(STRING); }
\$\{[A-Za-z_][A-Za-z_0-9-]*:?[-+=\?] {
				stringbuf_init(&sb);
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }
\$[0-9]|\$\{-?[0-9]+\}          { yylval.str = xstrdup(yytext);
				return tok(STRING); }
\$\{-?[0-9]+:?[-+=\?]           {
				stringbuf_init(&sb);
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }

\$[#@*]|%([0-9]|(\{[0-9]+\})) { yylval.str = xstrdup(yytext);
			        return tok(STRING); }
\"[^\\\"\n]*\"           { yylval.str = xmalloc(yyleng-1);
			   memcpy(yylval.str, yytext + 1, yyleng - 2);
			   yylval.str[yyleng - 2] = 0;
			   return tok(STRING); }
\"[^\\\"\n]*\\[0-9]{3}   { stringbuf_init(&sb);
			   stringbuf_add_escape_octal(&sb,
						      yytext + 1, yyleng - 1);
			   pushstart(QSTR); }
\"[^\\\"\n]*\\[xX][a-fA-F0-9]{2} {
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
.                          return tok(yytext[0]);
}

 /* QSTR: Composing a quoted string.
  */
<QSTR>{
[^\\\"\n]*\"             { stringbuf_add_array(&sb, yytext, yyleng - 1);
			   popstart();
	                   if (YY_START == ARGS) {
	                           stringbuf_finish(&sb);
			           yylval.str = sb.buffer;
			           return tok(STRING);
			   } else
				   stringbuf_add_char(&sb, yytext[yyleng-1]);
                         }
[^\\\"\n]*\\[0-9]{3}     { stringbuf_add_escape_octal(&sb, yytext, yyleng); }
[^\\\"\n]*\\[xX][a-fA-F0-9]{2} {
	                   stringbuf_add_escape_hex(&sb, yytext, yyleng); }
[^\\\"\n]*\\.|[^\\\"\n]*\\\n { stringbuf_add_escape_dfl(&sb, yytext, yyleng); }
\n   {  advance_line(1);
	yyerror("unescaped newline in quoted string"); }
.    {  straychar(yytext[0]); }
}

 /* VAR: The scanner is processing an unquoted variable reference with
    a default value (e.g. ${X:-0}).
  */
<VAR>{
\}                            { stringbuf_add_char(&sb, yytext[0]);
	                        popstart();
				if (YY_START != VAR) {
					stringbuf_finish(&sb);
					yylval.str = sb.buffer;
					return tok(STRING);
				}
			      }
\$([0-9]|(\{-?[0-9]+\})|([A-Za-z_][A-Za-z_0-9-]*)|(\{[A-Za-z_][A-Za-z_0-9-]*\}))  { stringbuf_add_array(&sb, yytext, yyleng); }
\$\{((-?[0-9]+)|([A-Za-z_][A-Za-z_0-9-]*)):?[-+=\?] {
				stringbuf_add_array(&sb, yytext, yyleng);
				pushstart(VAR); }
\"[^\\\"\n]*\"                { stringbuf_add_array(&sb, yytext, yyleng); }
\"[^\\\"\n]*\\.|\"[^\\\"\n]*\\\n { stringbuf_add_escape_dfl(&sb, yytext, yyleng);
                                   pushstart(QSTR); }
\"[^\\\"\n]*\\[0-9]{3}        { stringbuf_add_escape_octal(&sb, yytext, yyleng);
				pushstart(QSTR); }
\"[^\\\"\n]*\\[xX][a-fA-F0-9]{2} { stringbuf_add_escape_hex(&sb, yytext, yyleng);				   pushstart(QSTR); }
[^}\"\$%]+                    { stringbuf_add_array(&sb, yytext, yyleng); }
.                             { straychar(yytext[0]);
	                        stringbuf_add_char(&sb, yytext[0]); }
}
%%
/* If processing the included file, report an error, drain the input, and
   return 1. Otherwise, return 0. */
static int
noinc(void)
{
	if (in_included_file()) {
		yyerror(_("the %s statement is not allowed in included file"),
		        yytext);
		cferror(&curloc, _("skipping to the end of file"));
		while (input() != EOF)
			      ;
		return 1;
	}
	return 0;
}             

/* Return true if the quoted string being expanded occurs within a
   variable construct -- ${V:-"string"} */
static int
in_var(void)
{
	return (start_tos && start_tos->start == VAR);
}

/* Report a stray character C */
static void
straychar(int c)
{
	static char *start_name[] = {
		[INITIAL] = N_("looking for rush version clause"),
		[NORMAL] =  N_("looking for rule"),
		[ARGS] = N_("scanning arguments"),
		[QSTR] = N_("scanning quoted string"),
		[VAR] = N_("scanning variable reference")
	};
	if (isprint(c)) {
		yyerror(_("stray character %c while %s"), c,
			gettext(start_name[YY_START]));
	} else {
		yyerror(_("stray character %03o while %s"), c,
			gettext(start_name[YY_START]));
	}
}

/* Skip the input up to the next '\n' character. */
void
skiptoeol(void)
{
	int c;

	while ((c = input()) != EOF && c != '\n')
		;
}

/* Clear the start state stack and switch scanner to the NORMAL state. */
void
restorenormal(void)
{
	while (start_tos)
		popstart();
	BEGIN(NORMAL);
}

/* Initialize current location to point to this filename and line number. */
static void
curloc_init(char const *filename, int line)
{
	curloc.beg.filename = new_source_file_name(filename);
	curloc.beg.line = line;
	curloc.beg.column = 1;
	curloc.end = curloc.beg;
}

/* Switch to input from CF. FILENAME and LINE give the initial location. */
void
cflex_setup(CFSTREAM *cf, char const *filename, int line)
{
	curloc_init(filename, line);
	input_stream = cf;
	YY_FLUSH_BUFFER;
}

/* Set scanner debug level to V. */
void
cflex_debug(int v)
{
#ifdef FLEX_DEBUG
	yy_flex_debug = v;
#endif
}

/* Switch to the NORMAL condition. */
void
cflex_normal(void)
{
	BEGIN(NORMAL);
}

/* Include FILENAME. Return 0 on success, -1 on error. */
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
		ctx = ctx->prev;
		if (ctx) {
			cferror(loc, "%s already included", name);
			cferror(&ctx->loc, "%s already included here", name);
		} else
			cferror(loc, "%s: main configuration file cannot be included", name);
		inpctx_pop();
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

/* Preserve the current start state on stack and switch to ARGS. */ 
void
cflex_pushargs(void)
{
	pushstart(ARGS);
}

/* Extern interface to popstart */
void
cflex_popargs(void)
{
	popstart();
}

/* Remove trailing whitespace from S. */
void
trimws(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && ISWS(s[len-1])) 
		s[--len] = 0;
}

/* Remove trailing slashes from S. Return the length of the resulting
   string. */
size_t
trimslash(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && s[len-1] == '\\')
		s[--len] = 0;
	return len;
}

/* Rewind the input stream to the beginning and parse it as a legacy
   configuration. */
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

void
cflex_test(char const *filename)
{
	int c;
	CFSTREAM *cf;

	if (filename) {
		cf = cfstream_open_file(filename);
	} else {
		cf = cfstream_open_stdin();
		filename = "stdin";
	}
	cflex_setup(cf, filename, 1);
	BEGIN(NORMAL);
	while ((c = yylex()) != 0) {
		printf("state %d, ",YY_START);
		YY_LOCATION_PRINT(stdout, yylloc);
		printf(": ");
		switch (c) {
		case STRING:
			printf("STRING ");
			dumpstr(yylval.str, stdout);
			break;
		case IDENT:
			printf("IDENT %s", yylval.str);
			break;
		case NUMBER:
			printf("NUMBER %s", yylval.num.strval);
			break;
		case ATTRIB:
			printf("ATTRIB %s", yytext);
			break;
		case GLATTRIB:
			printf("GLATTRIB %s", yylval.global_attrib->name);
			break;
		case EOL:
			printf("EOL");
			break;
		default:
			printf("'%s'", yytext);
		}
		putchar('\n');
	}
	exit(0);
}
