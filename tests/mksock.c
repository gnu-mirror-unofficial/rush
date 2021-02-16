#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

int
main(int argc, char **argv)
{
	struct sockaddr_un s;
	int fd;
	
	assert(argc == 2);
	s.sun_family = AF_UNIX;
	assert(strlen(argv[1]) < sizeof(s.sun_path));
	strcpy(s.sun_path, argv[1]);
	
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}
	if (bind(fd, (struct sockaddr*)&s, sizeof(s))) {
		perror("bind");
		return 1;
	}
	return 0;
}
	
