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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

void
rtest(name, nflag, Nflag, scopeid)
	char *name;
	int nflag, Nflag, scopeid;
{
	static char buf[MAXHOSTNAMELEN];
	int flag = 0;
	struct sockaddr_in6 sa6;

	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_family = AF_INET6;
	sa6.sin6_scope_id = scopeid;
	if (inet_pton(AF_INET6, name, (void *)&sa6.sin6_addr) != 1)
		errx(1, "inet_pton failed for %s", name);

	if (nflag)
		flag |= NI_NUMERICHOST;

#ifdef NI_NUMERICSCOPE
	if (Nflag) {
		flag |= NI_NUMERICSCOPE;
	}
#endif

	getnameinfo((struct sockaddr *)&sa6, sa6.sin6_len, buf, sizeof(buf),
		    NULL, 0, flag);

	printf("getnameinfo returned %s\n", buf);
	exit(0);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	char *name, inet6addr[INET6_ADDRSTRLEN];
	struct addrinfo hints, *res;
	int ret_ga, nflag = 0, Nflag = 0, ch, scopeid = 0, rflag = 0;
	struct sockaddr_in6 *sa6;

	while ((ch = getopt(argc, argv, "Nnrs:")) != -1) {
		char *ep;

		switch(ch) {
		case 'N':
			Nflag++;
			break;
		case 'n':
			nflag++;
			break;
		case 'r':
			rflag++;
			break;
		case 's':
			scopeid = (int)strtoul(optarg, &ep, 10);
			if (*ep != '\0')
				errx(1, "invalid scope: %s", optarg);
			break;
		default:
			errx(1,
			     "usage: %s [-Nnr] [-s scopeid] address_or_name",
			     argv[0]);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		errx(1, "address or hostname should be specified");
	name = argv[0];

	if (rflag)
		rtest(name, nflag, Nflag, scopeid);

	memset(&hints, 0, sizeof(hints));
	if (nflag)
		hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_INET6;

	ret_ga = getaddrinfo(name, NULL, &hints, &res);
	if (ret_ga)
		errx(1, "getaddrinfo for %s: %s", name, gai_strerror(ret_ga));
	if (res->ai_addr == NULL)
		errx(1, "getaddrinfo returned no address for %s", name);

	sa6 = (struct sockaddr_in6 *)res->ai_addr;
	inet_ntop(AF_INET6, (const void *)&sa6->sin6_addr,
		  inet6addr, sizeof(inet6addr));

	printf("sin6_addr = %s, scope_id = %d\n", inet6addr, sa6->sin6_scope_id); 
	
	exit(0);
}
