/*
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int
rresvport_af(port, family)
	int *port;
	int family;
{
	int i, s, len;
	struct sockaddr_storage ss;
	struct sockaddr *sa;
	u_short *sport;
	
	switch (family) {
	case AF_INET:
		len = sizeof(struct sockaddr_in);
		sport = &((struct sockaddr_in *)&ss)->sin_port;
		break;
	case AF_INET6:
		len = sizeof(struct sockaddr_in6);
		sport = &((struct sockaddr_in6 *)&ss)->sin6_port;
		break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
	memset(&ss, 0, sizeof(ss));
	sa = (struct sockaddr *)&ss;
	sa->sa_len = len;
	sa->sa_family = family;

	s = socket(family, SOCK_STREAM, 0);
	if (s == -1)
		return -1;

	*sport = htons(*port);
	if (*port < IPPORT_RESERVED - 1) {
		if (bind(s, sa, len) >= 0)
			return s;
		if (errno != EADDRINUSE) {
			(void)close(s);
			return -1;
		}
	}

	for (i = IPPORT_RESERVED - 1; i > IPPORT_RESERVED / 2; i--) {
		*sport = htons(i);
		if (bind(s, sa, len) >= 0) {
			*port = i;
			return s;
		}
		if (errno != EADDRINUSE) {
			(void)close(s);
			return -1;
		}
	}

	errno = EAGAIN;
	return -1;
}

int
rresvport(port)
	int *port;
{
	return rresvport_af(port, AF_INET);
}
