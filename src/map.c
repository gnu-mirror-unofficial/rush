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

/* Set to 1 if expansion of undefined variables is allowed */
int expand_undefined;

static inline int
d2n(int d)
{
	static char dig[] = "0123456789";
	return strchr(dig, d) - dig;
}

static int
refno(char const *input, int *len)
{
	if (c_isdigit(input[1])) {
		*len = 2;
		return d2n(input[1]);
	} else if (input[1] == '{') {
		char const *p = input + 1;
		int n = 0;
		while (*++p && c_isdigit(*p))
			n = n * 10 + d2n(*p);
		if (*p == '}' && p > &input[1]) {
			*len = p - input + 1;
			return n;
		}
	}
	return -1;
}

/* Expand references to BACKREF in INPUT. A reference begins with one
   of characters in PFX, followed by the ordinal number of the parenthesized
   subgroup (in decimal, range [0, 9]).
*/
static char *
expandref(char const *input, struct rush_backref *backref, char *pfx)
{
	char *output;
	size_t output_len = strlen(input) + 1;
	size_t istart = 0, ostart = 0;

	output = xmalloc(output_len);
	while (input[istart]) {
		size_t len = strcspn(input + istart, pfx);
		int n, i;

		while (ostart + len >= output_len)
			output = x2realloc(output, &output_len);
		memcpy(output + ostart, input + istart, len);
		ostart += len;
		istart += len;
		if (!input[istart])
			break;
		else if (istart > 1 && input[istart-1] == '\\') {
			output[ostart-1] = input[istart];
			istart++;
		} else if ((n = refno(input + istart, &i)) >= 0
		    && n < backref->nmatch) {
			len = backref->match[n].rm_eo - backref->match[n].rm_so;
			while (ostart + len >= output_len)
				output = x2realloc(output, &output_len);
			memcpy(output + ostart,
			       backref->subject + backref->match[n].rm_so, len);
			ostart += len;
			istart += i;
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

static const char *
var_argc(struct rush_request *req)
{
	static char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	return umaxtostr(req->argc, buf);
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
	{ "argc",    var_argc },
	{ NULL }
};

char **
rush_request_getvar(struct rush_request *req, char const *varname)
{
	size_t i;
	struct vardef *vd;
	char const *s;

	if (req->var_kv) {
		for (i = 0; i < req->var_count; i += 2)
			if (strcmp(req->var_kv[i], varname) == 0)
				return &req->var_kv[i+1];
	}

	s = NULL;
	for (vd = request_vars; vd->name; vd++) {
		if (strcmp(vd->name, varname) == 0) {
			s = vd->expand(req);
			break;
		}
	}

	while (req->var_count + 3 >= req->var_max)
		req->var_kv = x2nrealloc(req->var_kv, &req->var_max,
					 sizeof(req->var_kv[0]));
	req->var_kv[req->var_count++] = xstrdup(varname);
	req->var_kv[req->var_count++] = s ? strdup(s) : NULL;
	req->var_kv[req->var_count] = NULL;

	return &req->var_kv[req->var_count - 1];
}

void
rush_request_delvar(struct rush_request *req, char const *varname)
{
	size_t i;

	for (i = 0; i < req->var_count; i += 2) {
		if (strcmp(req->var_kv[i], varname) == 0) {
			free(req->var_kv[i]);
			free(req->var_kv[i+1]);
			memmove(req->var_kv + i, req->var_kv + i + 2,
				(req->var_count - (i + 2) + 1)
				* sizeof req->var_kv[0]);
			req->var_count -= 2;
			break;
		}
	}
}

static int
getvar(char **ret, const char *var, size_t len, void *clos)
{
	struct rush_request *req = clos;
	const char *s = NULL;
	char *p;

	if (*var == '-') {
		unsigned long n;
		errno = 0;
		n = strtoul(var + 1, NULL, 10);
		if (errno || n == 0 || n > req->argc)
			return WRDSE_UNDEF;
		n = req->argc - n;
		s = req->argv[n];
	} else if (c_isdigit(*var)) {
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

		if (!s && req->env_count) {
			/* Look up in the environment */
			int i;

			for (i = 0; req->env[i]; i++) {
				if (strlen(req->env[i]) > len
				    && req->env[i][len] == '='
				    && memcmp(req->env[i], var, len) == 0) {
					s = req->env[i] + len + 1;
					break;
				}
			}
		}
	}

	if (!s)
		return WRDSE_UNDEF;
	p = strdup(s);
	if (!p)
		return WRDSE_NOSPACE;
	*ret = p;
	return WRDSE_OK;
}

char *
rush_expand_string(const char *string, struct rush_request *req)
{
	struct wordsplit ws;
	int wsflags = WRDSF_NOSPLIT
		      | WRDSF_NOCMD
		      | (expand_undefined ? 0: WRDSF_UNDEF)
		      | WRDSF_GETVAR
		      | WRDSF_CLOSURE
		      | WRDSF_OPTIONS;
	char *result;

	ws.ws_getvar = getvar;
	ws.ws_closure = req;
	ws.ws_options = WRDSO_BSKEEP_QUOTE;
	if (req->var_kv) {
		ws.ws_env = (const char **)req->var_kv;
		wsflags |= WRDSF_ENV|WRDSF_ENV_KV;
	}

	result = expandref(string, &req->backref[req->backref_cur], "%");
	if (wordsplit(result, &ws, wsflags))
		die(system_error, &req->i18n, "%s", wordsplit_strerror(&ws));
	free(result);
	result = ws.ws_wordv[0];
	ws.ws_wordv[0] = NULL;
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
