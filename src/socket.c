/* This file is part of Rush.                  
   Copyright (C) 2008 Sergey Poznyakoff

   Rush is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   Rush is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Rush.  If not, see <http://www.gnu.org/licenses/>. */

#include <rush.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <arpa/inet.h>

int
post_socket_send(const struct rush_sockaddr *sockaddr,
		 const struct rush_rule *rule,
		 const struct rush_request *req)
{
	int domain;
	int fd;
	FILE *fp;
	
	switch (sockaddr->sa->sa_family) {
	case AF_UNIX:
		domain = PF_UNIX;
		break;

	case AF_INET:
		domain = PF_INET;
		break;

	default:
		/* should not happen */
		abort();
	}
	
	fd = socket(domain, SOCK_STREAM, 0);
	if (fd == -1) {
		logmsg(LOG_ERR, "socket: %s", strerror(errno));
		return 1;
	}
	if (connect(fd, sockaddr->sa, sockaddr->len)) {
		logmsg(LOG_ERR, "connect: %s", strerror(errno));
		return 1;
	}

	fp = fdopen(fd, "w");
	fprintf(fp, "%s %s %s\r\n", rule->tag, req->pw->pw_name,
		req->cmdline);
	fflush(fp);
	shutdown(fd, SHUT_WR);
	fclose(fp);
	return 0;
}
	       
		
	
