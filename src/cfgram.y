%{
#include <rush.h>
#include <cf.h>
static int errors;
int re_flags = REG_EXTENDED;
static struct rush_rule *current_rule;
struct name_entry {
	struct name_entry *next;
	char *name;
};
static void add_name_list(struct name_entry *head, enum envar_type type);
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
	struct {
		char **argv;
		size_t argc;
	} strlist;
	struct {
		int start;
		int end;
	} range;
	struct {
		struct name_entry *head;
		struct name_entry *tail;
	} name_list;
	struct limits_rec *lrec;
	rule_attrib_setter_t attrib;
	struct global_attrib *global_attrib;
	struct argval *arg;
	struct {
		int argc;
		struct argval *head;
		struct argval *tail;
	} arglist;
}

%token <str> STRING
%token <str> IDENT
%token <num> NUMBER

%token PREFACE
%token RULE
%token GLOBAL
%token EOL
%token SET
%token MAP
%token UNSET
%token MATCH
%token FALLTHROUGH
%token INCLUDE
%token LIMITS
%token CLRENV
%token SETENV
%token UNSETENV
%token KEEPENV
%token DELETE
%token EXIT
%token <attrib> ATTRIB
%token <global_attrib> GLATTRIB
%token BOGUS

%left OR
%left AND
%left NOT
%nonassoc EQ NE LT LE GT GE '~' IN MEMBER

%type <intval> fdescr index
%type <str> literal string value defval
%type <regex> regex
%type <node> expr compound_cond simple_cond
%type <range> range
%type <lrec> resource_limits
%type <name_list> name_list
%type <strlist> strlist
%type <arg> arg
%type <arglist> arglist

%%
rcfile     : PREFACE EOL rulelist
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

rulelist   : rule
	   | rulelist rule
	   ;

rule       : rulehdr rulebody
	   | globhdr globbody
	   ;

globhdr    : GLOBAL EOL
	   ;

globbody   : glob_stmt
	   | globbody glob_stmt
	   ;

glob_stmt  : GLATTRIB arglist EOL
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

rulehdr    : RULE IDENT EOL
	     {
		     current_rule = new_rush_rule();
		     current_rule->tag = $2;
	     }
	   ;

rulebody   : stmt
	   | rulebody stmt
	   ;

stmt       : match_stmt EOL
	   | set_stmt EOL
	   | map_stmt EOL
	   | delete_stmt EOL
	   | limits_stmt EOL
	   | environ_stmt EOL
	   | include_stmt EOL
	   | flowctl_stmt EOL
	   | attrib_stmt EOL
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
	   | string EQ literal
	     {
		     $$ = new_test_node(test_cmps);
		     $$->v.cmp.op = cmp_eq;
		     $$->v.cmp.larg = $1;
		     $$->v.cmp.rarg.str = $3;
	     }
	   | string NE literal
	     {
		     $$ = new_test_node(test_cmpn);
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
	   | MEMBER strlist
	     {
		     $$ = new_test_node(test_member);
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
set_stmt   : SET index value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg = $2;
		     node->v.xf.pattern = $3;
		     node->v.xf.trans = NULL;
	     }
	   | SET index '~' value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     node->target.type = target_arg;
		     node->target.v.arg = $2;
		     node->v.xf.pattern = NULL;
		     node->v.xf.trans = compile_transform_expr($4, re_flags);
	     }
	   | SET IDENT value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     if (strcmp($2, "command") == 0) {
			     node->target.type = target_command;
			     free($2);
		     } else if (strcmp($2, "program") == 0) {
			     node->target.type = target_program;
			     free($2);
		     } else {
			     node->target.type = target_var;
			     node->target.v.name = $2;
		     }
		     node->v.xf.pattern = $3;
		     node->v.xf.trans = NULL;
	     }
	   | SET IDENT '~' value
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_set);
		     if (strcmp($2, "command") == 0) {
			     node->target.type = target_command;
			     free($2);
		     } else if (strcmp($2, "program") == 0) {
			     node->target.type = target_program;
			     free($2);
		     } else {
			     node->target.type = target_var;
			     node->target.v.name = $2;
		     }
		     node->v.xf.pattern = NULL;
		     node->v.xf.trans = compile_transform_expr($4, re_flags);
	     }
	   | UNSET IDENT
	     {
		     struct transform_node *node =
			     new_transform_node(current_rule, transform_delete);
		     node->target.type = target_var;
		     node->target.v.name = $2;
	     }
	   ;

map_stmt   : MAP index value value value NUMBER NUMBER defval
	     {
		     struct transform_node *node;

		     node = new_transform_node(current_rule, transform_map);
		     node->target.type = target_arg;
		     node->target.v.arg = $2;
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

		     node = new_transform_node(current_rule, transform_map);
		     node->target.type = target_var;
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
	     }
	   | EXIT fdescr IDENT
	     {
		     int n = string_to_error_index($3);
		     if (n == -1)
			     cferror(&@1, _("Unknown message reference"));
		     else
			     current_rule->error = new_standard_error($2, n);
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
		     struct transform_node *node =
			     new_transform_node(current_rule, transform_delete);
		     node->target.type = target_arg;
		     node->target.v.arg = $2.start;
		     node->v.arg_end = $2.end;
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
   ****************** */
include_stmt: INCLUDE string
	      {
		     cflex_include($2, &@2);
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
		     $$ = $1;
	     }
	    ;

/* *************************
   Environment modification
   ************************* */
environ_stmt: CLRENV
	      {
		     current_rule->clrenv = 1;
	      }
	    | SETENV IDENT string
	      {
		     new_envar(current_rule,
			       $2, strlen($2),
			       $3, strlen($3),
			       envar_set);
	      }
	    | UNSETENV name_list
	      {
		      add_name_list($2.head, envar_unset);
	      }
	    | KEEPENV name_list
	      {
		      add_name_list($2.head, envar_keep);
	      }
	    ;

name_list   : IDENT
	      {
		     struct name_entry *np = xmalloc(sizeof(*np));
		     np->next = NULL;
		     np->name = $1;
		     $$.head = $$.tail = np;
	      }
	    | name_list IDENT
	      {
		     struct name_entry *np = xmalloc(sizeof(*np));
		     np->next = NULL;
		     np->name = $2;
		     LIST_APPEND(np, $1.head, $1.tail);
		     $$ = $1;
	      }
	    ;

/* *******************
   Attribute statement
   ******************* */
attrib_stmt : ATTRIB string
	      {
		      $1(current_rule, $2, &@2);
	      }
	    ;

strlist     : arglist
	      {
		     int i;
		     struct argval *arg;

		     $$.argc = $1.argc;
		     $$.argv = xcalloc($1.argc + 1, sizeof($$.argv[0]));
		     for (i = 0, arg = $1.head; i < $1.argc; i++, arg = arg->next) {
			     $$.argv[i] = arg->strval;
			     arg->strval = NULL;
		     }
		     arglist_free($1.head);
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
new_rush_rule(void)
{
	struct rush_rule *p = xzalloc(sizeof(*p));
	LIST_APPEND(p, rule_head, rule_tail);
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
add_name_list(struct name_entry *head, enum envar_type type)
{
	for (; head; head = head->next) {
		new_envar(current_rule,
			  head->name, strlen(head->name),
			  NULL, 0,
			  type);
		free(head->name);
	}
}
