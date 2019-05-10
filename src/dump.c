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

#include <rush.h>

struct json_dumper {
	FILE *fp;
	int indent;
	int level;
	int first;
};

static void
dumper_init(struct json_dumper *dmp, FILE *fp, int indent)
{
	dmp->fp = fp;
	dmp->indent = indent;
	dmp->level = 1;
	dmp->first = 1;
}

static void
dumper_copy(struct json_dumper *dst, struct json_dumper *src)
{
	dst->fp = src->fp;
	dst->indent = src->indent;
	dst->level = src->level + 1;
	dst->first = 1;
}

static void
dump_indent(struct json_dumper *dmp)
{
	int i;
	for (i = 0; i < dmp->indent * dmp->level; i++)
		fputc(' ', dmp->fp);
}

static void
dump_separator(struct json_dumper *dmp)
{
	if (dmp->indent) {
		fputc('\n', dmp->fp);
		dump_indent(dmp);
	} else
		fputc(' ', dmp->fp);
}

static void
dump_delim(struct json_dumper *dmp)
{
	fputc(',', dmp->fp);
	dump_separator(dmp);
}

static void
dump_id(char const *id, struct json_dumper *dmp)
{
	if (dmp->first)
		dmp->first = 0;
	else
		dump_delim(dmp);
	fprintf(dmp->fp, "\"%s\":", id);
}

static void
dump_null(char const *id, struct json_dumper *dmp)
{
	dump_id(id, dmp);
	fputs("null", dmp->fp);
}

void
dumpstr(char const *string, FILE *fp)
{
	int c;

	fputc('\"', fp);
	for (; (c = *string) != 0; string++) {
		int ec;
		if (c == '\\' || c == '\"') {
			fputc('\\', fp);
			fputc(c, fp);
		} else if (c_isprint(c))
			fputc(c, fp);
		else if ((ec = wordsplit_c_quote_char(c)) != 0) {
			fputc('\\', fp);
			fputc(ec, fp);
		} else {
			fprintf(fp, "\\%03o", c);
		}
	}
	fputc('\"', fp);
}

static void
dump_string_data(char const *string, struct json_dumper *dmp)
{
	if (!string) {
		fputs("null", dmp->fp);
		return;
	}
	dumpstr(string, dmp->fp);
}

static void
dump_string(char const *string, char const *id, struct json_dumper *dmp)
{
	dump_id(id, dmp);
	dump_string_data(string, dmp);
}

static void
dump_raw_argv(char **argv, struct json_dumper *dmp)
{
	size_t i;
	
	for (i = 0; argv[i]; i++) {
		if (i)
			dump_delim(dmp);
		dump_string_data(argv[i], dmp);
	}
}

static int
cmp_ptr(const void *a, const void *b)
{
	char ** const aptr = (char ** const) a;
	char ** const bptr = (char ** const) b;
	return strcmp (*aptr, *bptr);
}

static void
dump_argv(char **argv, char const *id, int sort, struct json_dumper *dmp)
{
	size_t i;
	struct json_dumper nest_dmp;
	
	dump_id(id, dmp);
	if (!argv) {
		fputs("null", dmp->fp);
		return;
	}
	fputc('[', dmp->fp);
	if (!argv[0]) {
		fputc(']', dmp->fp);
		return;
	}
		
	if (dmp->indent)
		fputc('\n', dmp->fp);
	
	dumper_copy(&nest_dmp, dmp);

	dump_indent(&nest_dmp);

	if (sort) {
		char **newargv;
		for (i = 0; argv[i]; i++)
			;
		newargv = xcalloc(i+1, sizeof(newargv[0]));
		for (i = 0; (newargv[i] = argv[i]) != NULL; i++)
			;
		qsort(newargv, i, sizeof(newargv[0]), cmp_ptr);
		dump_raw_argv(newargv, &nest_dmp);
		free(newargv);
	} else {
		dump_raw_argv(argv, &nest_dmp);
	}
	
	dump_separator(dmp);
	fputc(']', dmp->fp);
}

static void
dump_umax(uintmax_t val, char const *id, struct json_dumper *dmp)
{
	char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	dump_id(id, dmp);
	fputs(umaxtostr(val, buf), dmp->fp);
}	

static void
dump_octal(unsigned val, char const *id, struct json_dumper *dmp)
{
	dump_id(id, dmp);
	fprintf(dmp->fp, "%03o", val);
}

static void
dump_int(int val, char const *id, struct json_dumper *dmp)
{
	dump_id(id, dmp);
	fprintf(dmp->fp, "%d", val);
}

static char **kv_ar;

static int
cmp_idx(void const *a, void const *b)
{
	size_t const *ai = a;
	size_t const *bi = b;
	return strcmp(kv_ar[*ai], kv_ar[*bi]);
}
	
static void
dump_vars(struct rush_request *req, char const *id, struct json_dumper *dmp)
{
	dump_id(id, dmp);
	fputc('{', dmp->fp);
	if (req->var_count) {
		size_t i, ic;
		size_t *iv;
		struct json_dumper nest_dmp;

		ic = req->var_count / 2;
		iv = xcalloc(ic, sizeof(iv[0]));
		for (i = 0; i < ic; i++) {
			iv[i] = 2*i;
		}
		kv_ar = req->var_kv;
		qsort(iv, ic, sizeof(iv[0]), cmp_idx);
		
		dumper_copy(&nest_dmp, dmp);
		dump_separator(&nest_dmp);
		for (i = 0; i < ic; i++) {
			dump_id(req->var_kv[iv[i]], &nest_dmp);
			dump_string_data(req->var_kv[iv[i]+1], &nest_dmp);
		}
		dump_separator(dmp);
	}
	fputc('}', dmp->fp);
}
	
static char allkw[] =
	"cmdline,"
	"argv,"
	"prog,"
	"interactive,"
	"pw_name,"
	"pw_uid,"
	"pw_gid,"
	"pw_dir,"
	"umask,"
	"chroot_dir,"
	"home_dir,"
	"gid,"
	"fork,"
	"acct,"
	"text_domain,"
	"localedir,"
	"locale,"
	"environ,"
	"vars";

void
dump_request(struct rush_request *req, FILE *fp)
{
	size_t i;
	struct json_dumper dmp;
	struct wordsplit ws;

	ws.ws_delim = ",";
	if (strcmp(dump_option, "all") == 0)
		dump_option = allkw;
	if (wordsplit(dump_option, &ws,
		      WRDSF_DELIM
		      |WRDSF_WS|WRDSF_SQUEEZE_DELIMS
		      |WRDSF_NOVAR|WRDSF_NOCMD|WRDSF_SHOWERR))
		abort();
	
	dumper_init(&dmp, fp, 4);
	
	fputc('{', fp);
	dump_separator(&dmp);

	for (i = 0; i < ws.ws_wordc; i++) {
		if (strcmp(ws.ws_wordv[i], "cmdline") == 0)
			dump_string(req->cmdline, "cmdline", &dmp);
		else if (strcmp(ws.ws_wordv[i], "argv") == 0)
			dump_argv(req->argv, "argv", 0, &dmp);
		else if (strcmp(ws.ws_wordv[i], "prog") == 0)
			dump_string(req->prog, "prog", &dmp);
		else if (strcmp(ws.ws_wordv[i], "interactive") == 0)
			dump_int(req->interactive, "interactive", &dmp);
		else if (strcmp(ws.ws_wordv[i], "pw_name") == 0)
			dump_string(req->pw->pw_name, "pw_name", &dmp);
		else if (strcmp(ws.ws_wordv[i], "pw_uid") == 0)
			dump_umax(req->pw->pw_uid, "pw_uid", &dmp);
		else if (strcmp(ws.ws_wordv[i], "pw_gid") == 0)
			dump_umax(req->pw->pw_gid, "pw_gid", &dmp);
		else if (strcmp(ws.ws_wordv[i], "pw_dir") == 0)
			dump_string(req->pw->pw_dir, "pw_dir", &dmp);
		else if (strcmp(ws.ws_wordv[i], "umask") == 0)
			dump_octal(req->umask, "umask", &dmp);
		else if (strcmp(ws.ws_wordv[i], "chroot_dir") == 0)
			dump_string(req->chroot_dir, "chroot_dir", &dmp);
		else if (strcmp(ws.ws_wordv[i], "home_dir") == 0)
			dump_string(req->home_dir, "home_dir", &dmp);
		else if (strcmp(ws.ws_wordv[i], "gid") == 0) {
				if (req->gid == NO_GID) 
					dump_null("gid", &dmp);
				else
					dump_umax(req->gid, "gid", &dmp);
		} else if (strcmp(ws.ws_wordv[i], "fork") == 0)
			dump_int(req->fork, "fork", &dmp);
		else if (strcmp(ws.ws_wordv[i], "acct") == 0)
			dump_int(req->acct, "acct", &dmp);
		//FIXME: socket
		else if (strcmp(ws.ws_wordv[i], "text_domain") == 0)
			dump_string(req->i18n.text_domain, "text_domain", &dmp);
		else if (strcmp(ws.ws_wordv[i], "localedir") == 0)
			dump_string(req->i18n.localedir, "localedir", &dmp);
		else if (strcmp(ws.ws_wordv[i], "locale") == 0)
			dump_string(req->i18n.locale, "locale", &dmp);
		else if (strcmp(ws.ws_wordv[i], "environ") == 0)
			dump_argv(req->env, "environ", 1, &dmp);
		else if (strcmp(ws.ws_wordv[i], "vars") == 0)
			dump_vars(req, "vars", &dmp);
		else
			logmsg(LOG_ERR, _("unknown keyword: %s"), ws.ws_wordv[i]);
	}		
	if (dmp.indent)
		fputc('\n', fp);
	fputc('}', fp);
	fputc('\n', fp);

	wordsplit_free(&ws);
}

