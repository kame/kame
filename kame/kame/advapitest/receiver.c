/*
 * Copyright (C) 2000 WIDE Project.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#define DEFPORT 9079		/* XXX hardcoding */

char *pr_addr(struct sockaddr *addr, int numeric);

int
main(argc, argv)
    int argc;
    char *argv;
{
	int s, cc;
	char rbuf[1024]; /* XXX */
	struct sockaddr_in6 local, remote;
	struct msghdr msg;
	struct iovec msgiov;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;
	local.sin6_port = DEFPORT;

	if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0)
		err(1, "bind");

	memset(&msg, 0, sizeof(msg));
	memset(&msgiov, 0, sizeof(msgiov));
	msg.msg_name = (void *)&remote;
	msg.msg_namelen = sizeof(remote);
	msgiov.iov_len = sizeof(rbuf);
	msgiov.iov_base = (void *)rbuf;
	msg.msg_iov = &msgiov;
	msg.msg_iovlen = 1;

	if ((cc = recvmsg(s, &msg, 0)) < 0)
		err(1, "recvmsg");

	printf("%d bytes data from %s arrived.\n", cc,
	       pr_addr((struct sockaddr *)&remote, 1));

	exit(0);
}

char *
pr_addr(addr, numeric)
	struct sockaddr *addr;
	int numeric;
{
	static char buf[MAXHOSTNAMELEN];
	int flag = 0;

	if (numeric)
		flag |= NI_NUMERICHOST;
#ifdef KAME_SCOPEID
	flag |= NI_WITHSCOPEID;
#endif

	getnameinfo(addr, addr->sa_len, buf, sizeof(buf), NULL, 0, flag);

	return (buf);
}
