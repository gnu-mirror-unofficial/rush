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

int
post_socket_send(const struct rush_sockaddr *sockaddr,
		 const struct rush_rule *rule,
		 const struct rush_request *req)
{
	int domain;
	int fd;
	FILE *fp;
	char buf[128];
	char *p;
	
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

	fp = fdopen(fd, "a+");
	/* Communication takes place in accordance with TCPMUX
	   protocol (RFC 1078).  The rule tag is used as service
	   name. */
	fprintf(fp, "%s\r\n", rule->tag);
	p = fgets(buf, sizeof(buf), fp);
	if (!p)
		logmsg(LOG_ERR, _("%s: TCPMUX did not respond"), rule->tag);
	else if (*p == '+') 
		fprintf(fp, "%s %s\r\n", req->pw->pw_name, req->cmdline);
	else
		logmsg(LOG_ERR, _("%s: TCPMUX returned %s"), rule->tag, p);
	fflush(fp);
	fclose(fp);
	return 0;
}
	       
		
	
