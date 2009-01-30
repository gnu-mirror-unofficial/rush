/* This file is part of GNU Rush.                  
   Copyright (C) 2008, 2009 Sergey Poznyakoff

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
#define obstack_chunk_alloc malloc
#define obstack_chunk_free free
#include <obstack.h>

struct metadef {
	char *kw;
	char *value;
	const char *(*expand)(struct metadef *, struct rush_request *);
	int static_p;
	void *storage;
};

static const char *
meta_expand(struct metadef *def, struct rush_request *req)
{
	if (!def->value) {
		if (def->expand)
			return def->expand(def, req);
		def->value = "INTERNAL ERROR: NONEXPANDABLE DATA";
		def->static_p = 1;
	}
	return def->value;
}

static const char *
find_expansion_char(int c, struct metadef *def, struct rush_request *req)
{
	for (; def->kw; def++)
		if (def->kw[1] == 0 && def->kw[0] == c)
			return meta_expand(def, req);
	return NULL;
}

static const char *
find_expansion_word(const char *kw, size_t len,
		    struct metadef *def, struct rush_request *req)
{
	for (; def->kw; def++)
		if (strlen(def->kw) == len && memcmp(def->kw, kw, len) == 0)
			return meta_expand(def, req);
	return NULL;
}

char *
meta_expand_string(const char *string, struct metadef *def,
		   struct rush_request *req)
{
	const char *p, *s;
	char *res;
	struct obstack stk;
	
	if (!string)
		return NULL;

	obstack_init(&stk);

	for (p = string; *p; ) {
		char *e;
		size_t len = strcspn(p, "$");
		obstack_grow(&stk, p, len);
		p += len;
		if (*p == '$') {
			switch (*++p) {
			case '$':
				obstack_grow(&stk, p, 1);
				p++;
				break;
	      
			case '{':
				e = strchr(p + 1, '}');
				if (e
				    && (s = find_expansion_word(p + 1,
								e - p - 1,
								def, req))) {
					obstack_grow(&stk, s, strlen(s));
					p = e + 1;
				} else {
					char *q;
					unsigned n = strtoul(p + 1, &q, 10);
					if (q == e && n < req->argc) {
						s = req->argv[n];
						len = strlen(req->argv[n]);
						p = e + 1;
					} else {
						s = p - 1;
						len = 1;
						p++;
					}
					obstack_grow(&stk, s, len);
				}
				break;
	      
			default:
				s = p - 1;
				len = 1;
				if (c_isdigit(*p)) {
					unsigned n = *p - '0';
					if (n >= req->argc) {
						s = req->argv[n];
						len = strlen(req->argv[n]);
					} 
				} else if ((s = find_expansion_char(*p, def, 
								    req))
					   != NULL) 
					len = strlen(s);
				obstack_grow(&stk, s, len);
				p++;
			}
		} else
			obstack_grow(&stk, p, 1);
	}
	obstack_1grow(&stk, 0);
	res = xstrdup(obstack_finish(&stk));
	obstack_free(&stk, NULL);
	return res;
}

const char *
meta_uid(struct metadef *def, struct rush_request *req)
{
	char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	return def->storage = xstrdup(umaxtostr(req->pw->pw_uid, buf));
}

const char *
meta_user(struct metadef *def, struct rush_request *req)
{
	return req->pw->pw_name;
}

const char *
meta_gid(struct metadef *def, struct rush_request *req)
{
	char buf[INT_BUFSIZE_BOUND(uintmax_t)];
	return def->storage = xstrdup(umaxtostr(req->pw->pw_gid, buf));
}

const char *
meta_group(struct metadef *def, struct rush_request *req)
{
	struct group *grp = getgrgid(req->pw->pw_gid);
	return grp ? grp->gr_name : meta_gid(def, req);
}

const char *
meta_home(struct metadef *def, struct rush_request *req)
{
	return req->pw->pw_dir;
}

const char *
meta_gecos(struct metadef *def, struct rush_request *req)
{
	return req->pw->pw_gecos;
}

static struct metadef mapdef[] = {
	{ "user", NULL, meta_user },
	{ "group", NULL, meta_group },
	{ "uid", NULL, meta_uid },
	{ "gid", NULL, meta_gid },
	{ "home", NULL, meta_home },
	{ "gecos", NULL, meta_gecos },
	{ NULL }
};

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

	key = meta_expand_string(map->key, mapdef, req);
	while (getline(&buf, &size, fp) != -1) {
		int fldc;
		char **fldv;
		int rc;

		line++;
		rc = argcv_get_np(buf, strlen(buf), map->delim, NULL,
				  0, &fldc, &fldv, NULL);
		if (rc)
			die(system_error, &req->i18n,
			    _("%s:%lu: failed to parse line: %s"),
			    file, (unsigned long)line, strerror(rc));
		if (map->key_field <= fldc && map->val_field <= fldc
		    && strcmp(fldv[map->key_field - 1], key) == 0) {
			ret = xstrdup(fldv[map->val_field - 1]);
			break;
		}
	}
	fclose(fp);
	free(key);
	free(file);
	if (!ret && map->defval)
		ret = xstrdup(map->defval);
	return ret;
}
