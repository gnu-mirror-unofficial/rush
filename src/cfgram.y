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
#include <cf.h>
static int errors;
int re_flags = REG_EXTENDED;
static struct rush_rule *current_rule;
struct asgn {
	struct asgn *next;
	char *name;
	char *value;
};
static void add_asgn_list(struct asgn *head, enum envar_type type);
static struct transform_node *new_set_node(enum transform_node_type type,
					   char *varname,
					   struct cfloc const *loc);
%}

%error-verbose
%locations

%union {
	char *str;
	struct cfnumber num;
	int intval;
	regex_t regex;
	struct rush_rule rule;
	struct test_node *node;
	struct strlist {
		char **argv;
		size_t argc;
	} strlist;
	struct {
		int start;
		int end;
	} range;
	struct asgn *asgn;
	struct {
		struct asgn *head;
		struct asgn *tail;
	} asgn_list;
	struct limits_rec *lrec;
	rule_attrib_setter_t attrib;
	struct global_attrib *global_attrib;
	struct argval *arg;
	struct {
		int argc;
		struct argval *head;
		struct argval *tail;
	} arglist;
	struct { unsigned major, minor; } version;
}

%token <str> STRING "string"
%token <str> IDENT "identifier"
%token <num> NUMBER "number"

%token RUSH "rush"
%token <version> T_VERSION
%token RULE "rule"
%token GLOBAL "global"
%token EOL "end of line"
%token SET "set"
%token INSERT "insert"
%token REMOPT "remopt"
%token MAP "map"
%token UNSET "unset"
%token MATCH "match"
%token FALLTHROUGH "fallthrough"
%token INCLUDE "include"
%token LIMITS "limits"
%token CLRENV "clrenv"
%token SETENV "setenv"
%token UNSETENV "unsetenv"
%token KEEPENV "keepenv"
%token EVALENV "evalenv"
%token DELETE "delete"
%token EXIT "exit"
%token <attrib> ATTRIB "rule attribute"
%token <global_attrib> GLATTRIB "global attribute"
%token BOGUS "erroneous token"

%token OR "||"
%token AND "&&"
%token NOT "!"
%token EQ "=="
%token NE "!="
%token LT "<"
%token LE "<="
%token GT ">"
%token GE ">="
%token XF "=~"
%token NM "!~"
%token IN "in"
%token GROUP "group"

%left OR
%left AND
%left NOT
%nonassoc EQ NE LT LE GT GE NM XF '~' IN GROUP

%type <intval> fdescr index
%type <str> literal string optstring value defval ruleid
%type <regex> regex
%type <node> expr compound_cond simple_cond
%type <range> range
%type <lrec> resource_limits
%type <asgn> asgn
%type <asgn_list> asgn_list
%type <strlist> strlist
%type <arg> arg
%type <arglist> arglist

%%
rcfile     : skipeol select
	   ;

select     : preface skipeol content
	     {
		     if (errors)
			     YYERROR;
	     }
	   | BOGUS
	     {
		     if (parse_old_rc())
			     YYERROR;
	     }
	   ;

preface    : RUSH T_VERSION EOL
	     {
		     if ($2.major == 2 && $2.minor == 0) {
			     cflex_normal();
		     } else {
			     cferror(&@2, _("unsupported configuration file version"));
			     YYERROR;
		     }
	     }
	   ;

skipeol    : /* empty */
	   | eol
	   ;

eol        : EOL
	   | eol EOL
	   ;

content    : /* empty */
	   | rulelist
	   ;

rulelist   : rule
	   | rulelist rule
	   ;

rule       : rulehdr rulebody
	   | globhdr globbody
	   ;

globhdr    : GLOBAL eol
	   ;

globbody   : glob_stmt
	   | globbody glob_stmt
	   ;

glob_stmt  : GLATTRIB arglist eol
	     {
		     struct cfloc loc;
		     loc.beg = @1.beg;
		     loc.end = @2.end;
		     global_attrib_set($1, $2.argc, $2.head, &loc);
		     arglist_free($2.head);
	     }
	   ;

arglist    : arg
	     {
		     $$.head = $$.tail = $1;
		     $$.argc = 1;
	     }
	   | arglist arg
	     {
		     LIST_APPEND($2, $1.head, $1.tail);
		     $1.argc++;
		     $$ = $1;
	     }
	   ;

arg        : literal
	     {
		     $$ = xcalloc(1, sizeof(*$$));
		     $$->next = NULL;
		     $$->loc = @1;
		     $$->isnum = 0;
		     $$->strval = $1;
	     }
	   | NUMBER
	     {
		     $$ = xcalloc(1, sizeof(*$$));
		     $$->next = NULL;
		     $$->loc = @1;
		     $$->isnum = 1;
		     $$->strval = $1.strval;
		     $$->intval = $1.intval;
	     }
	   ;

rulehdr    : RULE ruleid eol
	     {
		     current_rule = new_rush_rule($2);
		     current_rule->file = @1.beg.filename;
		     current_rule->line = @1.beg.line;
		     free($2);
	     }
	   ;

ruleid     : /* empty */
	     {
		     $$ = NULL;
	     }
	   | string
	   ;

rulebody   : stmt
	   | rulebody stmt
	   ;

stmt       : match_stmt eol
	   | set_stmt eol
	   | map_stmt eol
	   | delete_stmt eol
	   | limits_stmt eol
	   | environ_stmt eol
	   | flowctl_stmt eol
	   | attrib_stmt eol
	   | remopt_stmt eol
	   | include_stmt skipeol
	   | error
	     {
		     skiptoeol();
		     restorenormal();
		     yyerrok;
		     yyclearin;
		     errors = 1;
	     }
	   ;

/* ******************
   Match statement
   ****************** */
match_stmt : MATCH compound_cond
	     {
		     if (current_rule->test_node) {
			     struct test_node *np = new_test_node(test_and);
			     np->v.arg[0] = current_rule->test_node;
			     np->v.arg[1] = $2;
			     current_rule->test_node = np;
		     } else
			     current_rule->test_node = $2;
	     }
	   ;

compound_cond : simple_cond
	   | compound_cond AND simple_cond
	     {
		     $$ = new_test_node(test_and);
		     $$->v.arg[0] = $1;
		     $$->v.arg[1] = $3;
	     }
	   | compound_cond OR simple_cond
	     {
		     $$ = new_test_node(test_or);
		     $$->v.arg[0] = $1;
		     $$->v.arg[1] = $3;
	     }
	   ;

simple_cond: expr
	   | NOT simple_cond
	     {
		     $$ = new_test_node(test_not);
		     $$->v.arg[0] = $2;
	     }
	   | '(' compound_cond ')'
	     {
		     $$ = $2;
	     }
	   ;

expr       : string '~' regex
	     {
		     $$ = new_test_node(test_cmps);
		     $$->v.cmp.op = cmp_match;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.rx = $3;
	     }
	   | string NM regex
	     {
		     struct test_node *np = new_test_node(test_cmps);
		     np->v.cmp.op = cmp_match;
		     np->v.cmp.larg = $1;
		     np->v.cmp.rarg.rx = $3;

		     $$ = new_test_node(test_not);
		     $$->v.arg[0] = np;
	     }
	   | string EQ literal
	     {
		     $$ = new_test_node(test_cmps);
		     $$->v.cmp.op = cmp_eq;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.str = $3;
	     }
	   | string NE literal
	     {
		     $$ = new_test_node(test_cmps);
		     $$->v.cmp.op = cmp_ne;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.str = $3;
	     }
	   | string EQ NUMBER
	     {
		     $$ = new_test_node(test_cmpn);
		     $$->v.cmp.op = cmp_eq;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.num = $3.intval;
	     }
	   | string NE NUMBER
	     {
		     $$ = new_test_node(test_cmpn);
		     $$->v.cmp.op = cmp_ne;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.num = $3.intval;
	     }
	   | string LT NUMBER
	     {
		     $$ = new_test_node(test_cmpn);
		     $$->v.cmp.op = cmp_lt;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.num = $3.intval;
	     }
	   | string LE NUMBER
	     {
		     $$ = new_test_node(test_cmpn);
		     $$->v.cmp.op = cmp_le;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.num = $3.intval;
	     }
	   | string GT NUMBER
	     {
		     $$ = new_test_node(test_cmpn);
		     $$->v.cmp.op = cmp_gt;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.num = $3.intval;
	     }
	   | string GE NUMBER
	     {
		     $$ = new_test_node(test_cmpn);
		     $$->v.cmp.op = cmp_ge;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.num = $3.intval;
	     }
	   | string IN strlist
	     {
		     $$ = new_test_node(test_in);
		     $$->v.cmp.op = cmp_in;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.strv = $3.argv;
	     }
	   | GROUP string
	     {
		     $$ = new_test_node(test_group);
		     $$->v.groups = xcalloc(2, sizeof($$->v.groups[0]));
		     $$->v.groups[0] = $2;
		     $$->v.groups[1] = NULL;
	     }
	   | GROUP strlist
	     {
		     $$ = new_test_node(test_group);
		     $$->v.groups = $2.argv;
	     }
	   ;

literal    : IDENT
	   | STRING
	   ;

string     : IDENT
	   | STRING
	   | NUMBER
	     {
		     $$ = $1.strval;
	     }
	   ;

regex      : string
	     {
		     int rc = regcomp(&$$, $1, re_flags);
		     if (rc) {
			     char errbuf[512];
			     regerror(rc, &$$, errbuf, sizeof(errbuf));
			     cferror(&@1, _("invalid regexp: %s"), $1);
			     YYERROR;
		     }
	     }
	   ;

/* ******************
   Set statement
   ****************** */
set_stmt   : SET index '=' value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg.ins = 0;
		     node->target.v.arg.idx = $2;
		     node->v.xf.pattern = $4;
		     node->v.xf.trans = NULL;
	     }
	   | INSERT index '=' value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg.ins = 1;
		     node->target.v.arg.idx = $2;
		     node->v.xf.pattern = $4;
		     node->v.xf.trans = NULL;
	     }
	   | SET index XF value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg.ins = 0;
		     node->target.v.arg.idx = $2;
		     node->v.xf.pattern = NULL;
		     node->v.xf.trans = compile_transform_expr($4, re_flags,
							       &@4);
	     }
	   | SET index '=' string '~' value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg.ins = 0;
		     node->target.v.arg.idx = $2;
		     node->v.xf.pattern = $4;
		     node->v.xf.trans = compile_transform_expr($6, re_flags,
							       &@6);
	     }
	   | INSERT index '=' string '~' value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg.ins = 1;
		     node->target.v.arg.idx = $2;
		     node->v.xf.pattern = $4;
		     node->v.xf.trans = compile_transform_expr($6, re_flags,
							       &@6);
	     }
	   | SET IDENT '=' value
	     {
		     struct transform_node *node =
			     new_set_node(transform_set, $2, &@2);
		     if (node) {
			     node->v.xf.pattern = $4;
			     node->v.xf.trans = NULL;
		     }
	     }
	   | SET IDENT XF value
	     {
		     struct transform_node *node =
			     new_set_node(transform_set, $2, &@2);
		     if (node) {
			     node->v.xf.pattern = NULL;
			     node->v.xf.trans = compile_transform_expr($4,
								       re_flags,
								       &@4);
		     }
	     }
	   | SET IDENT '=' string '~' value
	     {
		     struct transform_node *node =
			     new_set_node(transform_set, $2, &@2);
		     if (node) {
			     node->v.xf.pattern = $4;
			     node->v.xf.trans = compile_transform_expr($6,
								       re_flags,
								       &@6);
		     }
	     }
	   | UNSET IDENT
	     {
		     struct transform_node *node =
			     new_set_node(transform_delete, $2, &@2);
		     if (node) {
			     node->target.v.name = $2;
		     }
	     }
	   | UNSET index
	     {
		     if ($2 == 0) {
			     cferror(&@2, _("$0 cannot be unset"));
			     errors++;
		     } else {
			     struct transform_node *node =
				     new_transform_node(current_rule,
							transform_delete);
			     node->target.type = target_arg;
			     node->target.v.arg.ins = 0;
			     node->target.v.arg.idx = $2;
			     node->v.arg_end = $2;
		     }
	     }
	   ;

map_stmt   : MAP index value value value NUMBER NUMBER defval
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_map);
		     node->target.type = target_arg;
		     node->target.v.arg.ins = 0;
		     node->target.v.arg.idx = $2;
		     node->v.map.file = $3;
		     node->v.map.delim = $4;
		     node->v.map.key = $5;
		     node->v.map.key_field = $6.intval;
		     node->v.map.val_field = $7.intval;
		     node->v.map.defval = $8;

		     free($6.strval);
		     free($7.strval);
	     }
	   | MAP IDENT value value value NUMBER NUMBER defval
	     {
		     struct transform_node *node;

		     node = new_set_node(transform_map, $2, &@2);
		     node->target.v.name = $2;
		     node->v.map.file = $3;
		     node->v.map.delim = $4;
		     node->v.map.key = $5;
		     node->v.map.key_field = $6.intval;
		     node->v.map.val_field = $7.intval;
		     node->v.map.defval = $8;

		     free($6.strval);
		     free($7.strval);
	     }
	   ;

defval     : /* empty */
	     {
		     $$ = NULL;
	     }
	   | string
	   ;

index      : '[' NUMBER ']'
	     {
		     $$ = $2.intval;
		     free($2.strval);
	     }
	   ;

value      : string
	   ;

/* ******************
   Flowctl statement
   ****************** */
flowctl_stmt: FALLTHROUGH
	     {
		     current_rule->fall_through = 1;
	     }
	   | EXIT fdescr STRING
	     {
		     current_rule->error = new_error($2, $3, 0);
		     free($3);
	     }
	   | EXIT fdescr IDENT
	     {
		     int n = string_to_error_index($3);
		     if (n == -1) {
			     cferror(&@1, _("Unknown message reference"));
			     YYERROR;
		     } else
			     current_rule->error = new_standard_error($2, n);
		     free($3);
	     }
	   ;

fdescr     : /* empty */
	     {
		     $$ = 2;
	     }
	   | NUMBER
	     {
		     $$ = $1.intval;
		     free($1.strval);
	     }
	   ;

/* ******************
   Delete statement
   ****************** */
delete_stmt: DELETE range
	     {
		     if ($2.start == 0 || $2.end == 0) {
			     cferror(&@2, _("$0 cannot be deleted"));
			     errors++;
		     } else {
			     struct transform_node *node =
				     new_transform_node(current_rule,
							transform_delete);
			     node->target.type = target_arg;
			     node->target.v.arg.ins = 0;
			     node->target.v.arg.idx = $2.start;
			     node->v.arg_end = $2.end;
		     }
	     }
	   ;

range      : NUMBER
	     {
		     $$.start = $$.end = $1.intval;
		     free($1.strval);
	     }
	   | NUMBER NUMBER
	     {
		     $$.start = $1.intval;
		     $$.end = $2.intval;
		     free($1.strval);
		     free($2.strval);
	     }
	   ;

/* ******************
   Include statement

   In contrast to the rest of statements, the EOL must be a part of this
   one, in order to avoid spurious look-aheads.
   ****************** */
include_stmt: INCLUDE string EOL
	      {
		     if (cflex_include($2, &@2))
			     YYERROR;
		     free($2);
	      }
	    ;

/* ******************
   Limits
   ****************** */
limits_stmt : LIMITS resource_limits
	      {
		     current_rule->limits = $2;
	      }
	    ;

resource_limits: IDENT
	      {
		     char *p;
		     $$ = limits_record_create();
		     switch (limits_record_add($$, $1, &p)) {
		     case lrec_ok:
			     break;
		     case lrec_error:
			     cferror(&@1,
				     _("unrecognized resource limit: %s"),
				     p);
			     break;
		     case lrec_badval:
			     cferror(&@1,
				     _("bad value: %s"),
				     p);
			     break;
		     }
		     free($1);
	      }
	    | resource_limits IDENT
	      {
		     char *p;
		     switch (limits_record_add($1, $2, &p)) {
		     case lrec_ok:
			     break;
		     case lrec_error:
			     cferror(&@1,
				     _("unrecognized resource limit: %s"),
				     p);
			     break;
		     case lrec_badval:
			     cferror(&@1,
				     _("bad value: %s"),
				     p);
			     break;
		     }
		     free($2);
		     $$ = $1;
	     }
	    ;

/* *************************
   Remove option statement
   ************************* */
remopt_stmt: REMOPT string optstring
	     {
		     struct transform_node *node;
		     size_t n;

		     n = strspn($2 + 1, ":");
		     if ($2[n + 1]) {
			     struct cfloc loc;
			     loc.beg = @2.beg;
			     loc.beg.column += n + 1;
			     loc.end = loc.beg;
			     cferror(&loc,
				     _("invalid character in short option designator"));
			     cferror(&loc,
				     _("short option letter can be followed only by zero to two colons"));
			     errors++;
		     } else {
			     if (n > 2) {
				     struct cfloc loc;
				     loc.beg = @2.beg;
				     loc.beg.column += n;
				     loc.end = loc.beg;
				     cferror(&loc,
					     _("ignoring extra character in short option designator"));
				     cferror(&loc,
					     _("short option letter can be followed only by zero to two colons"));
			     }

			     node = new_transform_node(current_rule,
						       transform_remopt);
			     node->target.type = target_command;
			     node->v.remopt.s_opt = $2;
			     node->v.remopt.l_opt = $3;
		     }
	     }
	   ;

optstring  : /* empty */
	     {
		     $$ = NULL;
	     }
	   | string
	   ;

/* *************************
   Environment modification
   ************************* */
environ_stmt: CLRENV
	      {
		     current_rule->clrenv = 1;
	      }
	    | SETENV IDENT '=' string
	      {
		     new_envar(current_rule,
			       $2, strlen($2),
			       $4, strlen($4),
			       envar_set);
		     free($2);
		     free($4);
	      }
	    | EVALENV string
	      {
		      new_envar(current_rule,
				"", 0,
				$2, strlen($2),
				envar_eval);
		      free($2);
	      }
	    | UNSETENV asgn_list
	      {
		      add_asgn_list($2.head, envar_unset);
	      }
	    | KEEPENV asgn_list
	      {
		      add_asgn_list($2.head, envar_keep);
	      }
	    ;

asgn_list   : asgn
	      {
		      $$.head = $$.tail = $1;
	      }
	    | asgn_list asgn
	      {
		      LIST_APPEND($2, $1.head, $1.tail);
		      $$ = $1;
	      }
	    ;

asgn        : literal
	      {
		     $$ = xmalloc(sizeof(*$$));
		     $$->next = NULL;
		     $$->name = $1;
		     $$->value = NULL;
	      }
	    | IDENT '=' value
	      {
		     $$ = xmalloc(sizeof(*$$));
		     $$->next = NULL;
		     $$->name = $1;
		     $$->value = $3;
	      }
	    ;

/* *******************
   Attribute statement
   ******************* */
attrib_stmt : ATTRIB string
	      {
		      $1(current_rule, $2, &@2);
		      free($2);
	      }
	    ;

strlist     : '(' { cflex_pushargs(); } arglist ')'
	      {
		     int i;
		     struct argval *arg;

		     cflex_popargs();
		     $$.argc = $3.argc;
		     $$.argv = xcalloc($3.argc + 1, sizeof($$.argv[0]));
		     for (i = 0, arg = $3.head; i < $3.argc; i++, arg = arg->next) {
			     $$.argv[i] = arg->strval;
			     arg->strval = NULL;
		     }
		     arglist_free($3.head);
	      }
	    ;

%%
void
yyerror(char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vcferror(&curloc, fmt, ap);
	va_end(ap);
	errors = 1;
}

void
cfgram_debug(int v)
{
#ifdef YYDEBUG
	yydebug = v;
#endif
}

struct rush_rule *
new_rush_rule(char const *tag)
{
	struct rush_rule *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, rule_head, rule_tail);
	static unsigned rule_num = 0;

	rule_num++;
	if (tag && tag[0])
		p->tag = xstrdup(tag);
	else {
		char buf[INT_BUFSIZE_BOUND(unsigned)];
		char *s = uinttostr(rule_num, buf);
		p->tag = xmalloc(strlen(s) + 2);
		p->tag[0] = '#';
		strcpy(p->tag + 1, s);
	}

	p->mask = NO_UMASK;
	p->gid = NO_GID;
	p->fork = rush_undefined;
	p->acct = rush_undefined;
	return p;
}

struct transform_node *
new_transform_node(struct rush_rule *rule, enum transform_node_type type)
{
	struct transform_node *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, rule->transform_head, rule->transform_tail);
	p->type = type;
	return p;
}

struct test_node *
new_test_node(enum test_type type)
{
	struct test_node *p = xzalloc(sizeof(*p));
	p->type = type;
	return p;
}

struct envar *
new_envar(struct rush_rule *rule,
	  char const *name, size_t nlen,
	  char const *value, size_t vlen,
	  enum envar_type type)
{
	struct envar *p = xmalloc(sizeof(*p)
				  + nlen + 1
				  + (value ? vlen + 1 : 0));
	p->next = NULL;
	p->name = (char*)(p + 1);
	memcpy(p->name, name, nlen);
	p->name[nlen] = 0;
	if (value) {
		p->value = p->name + nlen + 1;
		memcpy(p->value, value, vlen);
		p->value[vlen] = 0;
	} else {
		p->value = NULL;
	}

	p->type = type;
	LIST_APPEND(p, rule->envar_head, rule->envar_tail);
	return p;
}

static void
add_asgn_list(struct asgn *head, enum envar_type type)
{
	for (; head; head = head->next) {
		new_envar(current_rule,
			  head->name, strlen(head->name),
			  head->value, head->value ? strlen(head->value) : 0,
			  type);
		free(head->name);
		free(head->value);
	}
}

static struct transform_node *
new_set_node(enum transform_node_type type,
	     char *varname,
	     struct cfloc const *loc)
{
	struct transform_node *node;
	enum transform_target_type tgt;

	tgt = rush_variable_target(varname);
	if (tgt == target_readonly) {
		cferror(loc, _("attempt to modify a read-only variable"));
		errors++;
		return NULL;
	}
	node = new_transform_node(current_rule, type);
	node->target.type = tgt;
	switch (tgt) {
	case target_command:
	case target_program:
		free(varname);
		if (type == transform_delete) {
			cferror(loc,
				_("attempt to unset a read-only variable"));
			errors++;
			return NULL;
		}
		break;
	case target_var:
		node->target.v.name = varname;
		break;
	default:
		die(system_error, NULL,
		    _("INTERNAL ERROR at %s:%d: invalid target type %d"),
		    __FILE__, __LINE__,
		    tgt);
	}
	return node;
}
