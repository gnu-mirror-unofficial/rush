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

static inline int
d2n(int d)
{
	static char dig[] = "0123456789";
	return strchr(dig, d) - dig;
}

/* Expand references to BACKREF in INPUT. A reference begins with one
   of characters in PFX, followed by the ordinal number of the parenthesized
   subgroup (in decimal, range [0, 9]).
*/
static char *
expandref(char *input, struct rush_backref *backref, char *pfx)
{
	char *output;
	size_t output_len = strlen(input) + 1;
	size_t istart = 0, ostart = 0;
	
	output = xmalloc(output_len);
	while (input[istart]) {
		size_t len = strcspn(input + istart, pfx);
		int n;
		
		while (ostart + len >= output_len)
			output = x2realloc(output, &output_len);
		memcpy(output + ostart, input + istart, len);
		ostart += len;
		istart += len;
		if (input[istart]
		    && isdigit(input[istart + 1])
		    && (n = d2n(input[istart + 1])) < backref->nmatch) {
			len = backref->match[n].rm_eo - backref->match[n].rm_so;
			while (ostart + len >= output_len)
				output = x2realloc(output, &output_len);
			memcpy(output + ostart,
			       backref->subject + backref->match[n].rm_so, len);
			ostart += len;
			istart += 2;
		} else {
			if (ostart + 2 >= output_len)
				output = x2realloc(output, &output_len);
			memcpy(output + ostart, input + istart, 2);
			ostart += 2;
			istart += 2;
		}
	}
	output[ostart] = 0;
	return xrealloc(output, ostart + 1);
}

static const char *
var_uid(struct rush_request *req)
{
	static char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	return umaxtostr(req->pw->pw_uid, buf);
}

static const char *
var_user(struct rush_request *req)
{
	return req->pw->pw_name;
}

static const char *
var_gid(struct rush_request *req)
{
	static char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	return umaxtostr(req->pw->pw_gid, buf);
}

static const char *
var_group(struct rush_request *req)
{
	struct group *grp = getgrgid(req->pw->pw_gid);
	return grp ? grp->gr_name : var_gid(req);
}

static const char *
var_home(struct rush_request *req)
{
	return req->pw->pw_dir;
}

static const char *
var_gecos(struct rush_request *req)
{
	return req->pw->pw_gecos;
}

static const char *
var_program(struct rush_request *req)
{
	return PROGFILE(req);
}

static const char *
var_command(struct rush_request *req)
{
	return req->cmdline;
}

struct vardef {
	char *name;
	const char *(*expand)(struct rush_request *);
};

static struct vardef request_vars[] = {
	{ "user",    var_user },
	{ "group",   var_group },
	{ "uid",     var_uid },
	{ "gid",     var_gid },
	{ "home",    var_home },
	{ "gecos",   var_gecos },
	{ "program", var_program },
	{ "command", var_command },
	{ NULL }
};

static int
getvar(char **ret, const char *var, size_t len, void *clos)
{
	const char *s = NULL;
	struct rush_request *req = clos;
	
	if (c_isdigit(*var)) {
		unsigned long n;
		errno = 0;
		n = strtoul(var, NULL, 10);
		if (errno || n >= req->argc)
			return WRDSE_UNDEF;
		s = req->argv[n];
	} else {
		struct vardef *vd;
		for (vd = request_vars; vd->name; vd++) {
			if (strncmp(vd->name, var, len) == 0) {
				s = vd->expand(clos);
				break;
			}
		}
	}

	if (s) {
		char *p = strdup(s);
		if (!p)
			return WRDSE_NOSPACE;
		*ret = p;
		return WRDSE_OK;
	}

	return WRDSE_UNDEF;
}

char *
rush_expand_string(const char *string, struct rush_request *req)
{
	struct wordsplit ws;
	int wsflags = WRDSF_NOSPLIT
		      | WRDSF_NOCMD
		      | WRDSF_UNDEF
		      | WRDSF_GETVAR
		      | WRDSF_CLOSURE;
	char *result;

	ws.ws_getvar = getvar;
	ws.ws_closure = req;
	if (req->var_kv) {
		ws.ws_env = (const char **)req->var_kv;
		wsflags |= WRDSF_ENV|WRDSF_ENV_KV;
	}
	if (wordsplit(string, &ws, wsflags))
		die(system_error, &req->i18n, "%s", wordsplit_strerror(&ws));
	result = expandref(ws.ws_wordv[0], &req->backref[req->backref_cur],
			   "%");
	wordsplit_free(&ws);
	return result;
}

char *
map_string(struct rush_map *map, struct rush_request *req)
{
	char *file;
	FILE *fp;
	struct stat st;
	char *buf = NULL;
	size_t size = 0;
	size_t line = 0;
	char *key;
	char *ret = NULL;

	file = expand_tilde(map->file, req->pw->pw_dir);
	if (stat(file, &st)) {
		die(system_error, &req->i18n, _("cannot stat file %s: %s"),
		    file, strerror(errno));
	}
	if (check_config_permissions(file, &st)) 
		die(config_error, &req->i18n, _("%s: file is not safe"),
		    file);

	fp = fopen(file, "r");
	if (!fp)
		die(system_error, &req->i18n, _("%s: cannot open map file"),
		    file);

	key = rush_expand_string(map->key, req);
	while (getline(&buf, &size, fp) != -1) {
		size_t len;
		struct wordsplit ws;

		line++;
		
		len = strlen(buf);
		while (len > 0 && buf[len-1] == '\n')
			buf[--len] = 0;

		ws.ws_delim = map->delim;
		if (wordsplit(buf, &ws,
			      WRDSF_NOVAR | WRDSF_NOCMD | WRDSF_DELIM))
			die(system_error, &req->i18n,
			    _("%s:%lu: failed to parse line: %s"),
			    file, (unsigned long)line,
			    wordsplit_strerror(&ws));
			
		if (map->key_field <= ws.ws_wordc &&
		    map->val_field <= ws.ws_wordc &&
		    strcmp(ws.ws_wordv[map->key_field - 1], key) == 0)
			ret = xstrdup(ws.ws_wordv[map->val_field - 1]);

		wordsplit_free(&ws);
		
		if (ret)
			break;
	}
	fclose(fp);
	free(key);
	free(file);
	if (!ret && map->defval)
		ret = xstrdup(map->defval);
	return ret;
}
