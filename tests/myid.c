#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>

int
main(int argc, char **argv)
{
	struct passwd *pw;
	struct group *gr;

	pw = getpwuid(getuid());
	assert(pw!=NULL);
	gr = getgrgid(pw->pw_gid);
	assert(gr!=NULL);
	printf("%s %lu %s %lu\n",
	       pw->pw_name,
	       (unsigned long) pw->pw_uid,
	       gr->gr_name,
	       (unsigned long) gr->gr_gid);
	return 0;
}
