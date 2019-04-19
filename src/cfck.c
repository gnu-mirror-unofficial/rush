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
#include "dirname.h"

int config_file_checks = RUSH_CHK_DEFAULT;

/* Functions for checking file mode of the configuration file and
   its directory.
   Each of these checks certain bits and returns 0 if they are OK
   and non-0 otherwise. */

static int
check_nonroot_owner(struct stat *filest, struct stat *dirst)
{
	return filest->st_uid != 0;
}

static int
check_iwgrp(struct stat *filest, struct stat *dirst)
{
	return filest->st_mode & S_IWGRP;
}

static int
check_iwoth(struct stat *filest, struct stat *dirst)
{
	return filest->st_mode & S_IWOTH;
}

static int
check_linked_wrdir(struct stat *filest, struct stat *dirst)
{
	return ((filest->st_mode & S_IFMT) == S_IFLNK)  
		&& (dirst->st_mode & (S_IWGRP | S_IWOTH));
}

static int
check_dir_iwgrp(struct stat *filest, struct stat *dirst)
{
	return dirst->st_mode & S_IWGRP;
}

static int
check_dir_iwoth(struct stat *filest, struct stat *dirst)
{
	return dirst->st_mode & S_IWOTH;
}

/* The table of permission checkers below has this type: */
struct perm_checker
{
	int flag;              /* RUSH_CHK_ flag that enables this entry */
	char *descr;           /* Textual description to use if FUN
				  returns !0 */
	int (*fun) (struct stat *filest, struct stat *dirst);
                               /* Checker function */
};

static struct perm_checker perm_check_tab[] = {
	{ RUSH_CHK_OWNER, N_("file not owned by root"),
	  check_nonroot_owner },
	{ RUSH_CHK_IWGRP, N_("group writable configuration file"),
	  check_iwgrp },
	{ RUSH_CHK_IWOTH, N_("world writable configuration file"),
	  check_iwoth },
	{ RUSH_CHK_LINK, N_("linked configuration file in writable dir"),
	  check_linked_wrdir },
	{ RUSH_CHK_DIR_IWGRP,
	  N_("configuration file in group writable directory"),
	  check_dir_iwgrp },
	{ RUSH_CHK_DIR_IWOTH,
	  N_("configuration file in world writable directory"),
	  check_dir_iwoth },
	{ 0 }
};

/* Check if the file FILENAME has right permissions and file mode. */
int
check_config_permissions(const char *filename, struct stat *st)
{
	int i;
	struct stat dirst;
	char *dirname;
	
	dirname = dir_name(filename);
	if (stat(dirname, &dirst)) {
		logmsg(LOG_NOTICE, _("%s: cannot stat directory: %s"),
		       dirname, strerror(errno));
		free(dirname);
		return 1;
	}
	free(dirname);
	
	for (i = 0; perm_check_tab[i].flag; i++)
		if ((config_file_checks & perm_check_tab[i].flag)
		    && perm_check_tab[i].fun(st, &dirst)) {
			logmsg(LOG_NOTICE,
			       "%s: %s",
			       filename,
			       gettext(perm_check_tab[i].descr));
			return 1;
		}
	return 0;
}


static struct check_kw {
	int bits;
	char const *keyword;
} chk_args[] = {
	{ RUSH_CHK_ALL,       "all" },
	{ RUSH_CHK_OWNER,     "owner" },
	{ RUSH_CHK_IWGRP,     "iwgrp" },
	{ RUSH_CHK_IWGRP,     "groupwritablefile" }, 
	{ RUSH_CHK_IWOTH,     "iwoth" },
	{ RUSH_CHK_IWOTH,     "worldwritablefile" }, 
	{ RUSH_CHK_LINK,      "link" },
	{ RUSH_CHK_DIR_IWGRP, "dir_iwgrp" },
	{ RUSH_CHK_DIR_IWGRP, "groupwritabledir" },  
	{ RUSH_CHK_DIR_IWOTH, "dir_iwoth" },
	{ RUSH_CHK_DIR_IWOTH, "worldwritabledir" },
	{ 0, NULL }
};

int
cfck_keyword(const char *name)
{
	int negate = 0;
	char *str;
	char *kw;
	int i;
	
	str = xstrdup(name);
	for (kw = str; *kw; kw++)
		*kw = tolower(*kw);
	kw = str;
	
	if (strcmp(kw, "none") == 0) {
		negate = 1;
		kw = "all";
	} else if (strlen(kw) > 2 && strncmp(kw, "no", 2) == 0) {
		negate = 1;
		kw += 2;
	}

	for (i = 0; chk_args[i].keyword; i++)
		if (strcmp(chk_args[i].keyword, kw) == 0)
			break;
	if (chk_args[i].keyword == NULL)
		return -1;
	
	if (negate)
		config_file_checks &= ~chk_args[i].bits;
	else
		config_file_checks |= chk_args[i].bits;
	return 0;
}
	



