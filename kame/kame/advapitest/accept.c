/*	$KAME: accept.c,v 1.17 2001/09/18 02:29:53 jinmei Exp $ */
/*
 * Copyright (C) 1999 WIDE Project.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include "common.h"

static u_char *rcvmsgbuf;
static int rcvmsglen; 
int aflag, dflag, Dflag, hflag, iflag, lflag, rflag, uflag; 

void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch, s, s0, remotelen, on, proto, error;
	char *portstr = DEFAULTPORT;
	char *protostr = NULL, *addrstr = NULL;
	struct sockaddr_in6 remote;
	struct msghdr rcvmh;
	struct iovec iov[2];
	char recvbuf[1024];	/* xxx hardcoding */
	struct addrinfo hints, *res;

	while ((ch = getopt(argc, argv, "adDhilP:p:ru")) != -1)
		switch(ch) {
		case 'a':
			aflag++;
			break;
		case 'd':
			dflag++;
			break;
		case 'D':
			Dflag++;
			break;
		case 'h':
			hflag++;
			break;
		case 'i':
			iflag++;
			break;
		case 'l':
			lflag++;
			break;
		case 'p':
			portstr = optarg;
			break;
		case 'P':
			protostr = optarg;
			break;
		case 'r':
			rflag++;
			break;
		case 'u':
			uflag++;
			break;
		default:
			usage();
		}

	rcvmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		CMSG_SPACE(sizeof(int)) + 4096;	/* XXX hardcoding */
	if (rcvmsgbuf == NULL &&
	    (rcvmsgbuf = (u_char *)malloc(rcvmsglen)) == NULL)
		errx(1, "malloc failed");

	if (uflag && protostr)
		errx(1, "-u and -P options are exclusive");

	if (protostr) {
		struct protoent *ent;

		if ((ent = getprotobyname(protostr)) == NULL &&
		    (ent = getprotobynumber(protostr)) == NULL) {
			proto = atoi(protostr); /* XXX: last resort */
		} else
			proto = ent->p_proto;
	} else
		proto = uflag ? IPPROTO_UDP : IPPROTO_TCP;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	switch(proto) {
	case IPPROTO_TCP:
		hints.ai_socktype = SOCK_STREAM;
		break;
	case IPPROTO_UDP:
		hints.ai_socktype = SOCK_DGRAM;
		break;
	default:
		hints.ai_socktype = SOCK_RAW;
		/* XXX */
		portstr = NULL;
		addrstr = "::";
		break;
	}
	hints.ai_protocol = proto;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(addrstr, portstr, &hints, &res);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol))
	    < 0)
		err(1, "socket");

	on = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on,
		       sizeof(on)) < 0)
		err(1, "setsockopt(SO_REUSEADDR)");
	if ((aflag || iflag) &&
	    setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVPKTINFO)");
	/* specify to tell value of hoplimit field of received IP6 hdr */
	if ((aflag || lflag) &&
	    setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on,
		       sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVHOPLIMIT)");
	/* specify to show received dst opts hdrs before a rthdr (if any) */
	if ((aflag || Dflag) &&
	    setsockopt(s, IPPROTO_IPV6, IPV6_RECVRTHDRDSTOPTS, &on,
		       sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVRTHDRDSTOPTS)");
	/* specify to show a received dst opts header after a rthdr (if any) */
	if ((aflag || dflag) &&
	    setsockopt(s, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &on,
		       sizeof(on)) < 0)
		err(1, "setsockot(IPV6_RECVDSTOPTS)");
	/* specify to show a received hop-by-hop options header (if any) */
	if ((aflag || hflag) &&
	    setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &on, sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVHOPOPTS)");
	/* specify to show received routing headers (if any) */
	if ((aflag || rflag) &&
	    setsockopt(s, IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVRTHDR)");

	if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
		err(1, "bind");

	freeaddrinfo(res);

	if (proto == IPPROTO_TCP) {
		if (listen(s, 1) < 0)
			err(1, "listen");

		if ((s0 = accept(s, (struct sockaddr *)&remote, &remotelen))
		    < 0)
			err(1, "accept");
		close(s);
		s = s0;

		/*
		 * issue recvmsg with an empty data buffer to get optional
		 * (ancillary) data upon accepting a connection.
		 */
		memset(&rcvmh, 0, sizeof(rcvmh));
		rcvmh.msg_controllen = rcvmsglen;
		rcvmh.msg_control = (caddr_t)rcvmsgbuf;
		if (recvmsg(s, &rcvmh, 0) < 0)
			err(1, "recvmsg");

		print_options(&rcvmh);
	}

	while(1) {
		int cc;

		memset(&rcvmh, 0, sizeof(rcvmh));
		rcvmh.msg_controllen = rcvmsglen;
		rcvmh.msg_control = rcvmsgbuf;
		iov[0].iov_base = (caddr_t)recvbuf;
		iov[0].iov_len = sizeof(recvbuf);
		rcvmh.msg_iov = iov;
		rcvmh.msg_iovlen = 1;

		if ((cc = recvmsg(s, &rcvmh, 0)) < 0)
			err(1, "recvmsg");

		if (cc == 0 && rcvmh.msg_controllen == 0)
			break;

		print_options(&rcvmh);
		recvbuf[cc] = '\0';
		if (proto == IPPROTO_TCP) /* XXX */
			printf("Data: %s\n", recvbuf);
	}

	close(s);
	exit(0);
}

void
usage()
{
	fprintf(stderr, "usage: accept [-adDhilru] [-p port] [-P protocol]\n");
	exit(1);
}
