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

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#define COMPAT_RFC2292

static u_char rcvmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		       CMSG_SPACE(sizeof(int))
		       + 2064];	/* XXX for rthdr */

void print_options __P((struct msghdr *));
void print_rthdr __P((void *));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int s, s0, remotelen, on, optlen;
	short port;
	struct sockaddr_in6 local, remote;
	struct msghdr rcvmh;
	struct iovec iov[2];
	char recvbuf[1024];	/* xxx hardcoding */

	if (argc < 2)
		port = DEFAULTPORT;
	else
		port = (short)atoi(argv[1]);

	if ((s = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
		err(1, "socket");
	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;
	local.sin6_len = sizeof(local);
	local.sin6_port = htons(port);
	if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0)
		err(1, "bind");

	if (listen(s, 5) < 0)
		err(1, "listen");

	on = 1;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVPKTINFO)");
	/* specify to tell value of hoplimit field of received IP6 hdr */
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on,
		       sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVHOPLIMIT)");
	/* specify received routing headers (if any) */
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on)) < 0)
		err(1, "setsockopt(IPV6_RECVRTHDR)");

	if ((s0 = accept(s, (struct sockaddr *)&remote, &remotelen)) < 0)
		err(1, "accept");
	close(s);
	s = s0;

	optlen = sizeof(rcvmsgbuf);
#ifdef COMPAT_RFC2292
	if (getsockopt(s, IPPROTO_IPV6, IPV6_PKTOPTIONS, (void *)rcvmsgbuf,
		       &optlen) <0 )
		err(1, "getsockopt(IPV6_PKTOPTIONS)");
	rcvmh.msg_controllen = optlen;
	rcvmh.msg_control = (caddr_t)rcvmsgbuf;
#else  /* new advanced API */
	memset(&rcvmh, 0, sizeof(rcvmh));
	rcvmh.msg_controllen = optlen;
	rcvmh.msg_control = (caddr_t)rcvmsgbuf;

	if (recvmsg(s, &rcvmh, 0) < 0)
		err(1, "recvmsg");
#endif

	print_options(&rcvmh);

	while(1) {
		int cc;

		memset(&rcvmh, 0, sizeof(rcvmh));
		rcvmh.msg_controllen = sizeof(rcvmsgbuf);
		rcvmh.msg_control = (caddr_t)rcvmsgbuf;
		memset(rcvmsgbuf, 0, optlen);
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
		printf("Data: %s\n", recvbuf);
	}

	close(s);
	exit(0);
}

void
print_options(mh)
	struct msghdr *mh;
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	int *hlimp = NULL;
	char ntop_buf[INET6_ADDRSTRLEN];
	void *rthdr = NULL;

	if (mh->msg_controllen == 0) {
		printf("No IPv6 option is received\n");
		return;
	}
	
	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mh);
	     cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mh, cm)) {
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		if (cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
		}
		if (cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
			hlimp = (int *)CMSG_DATA(cm);
		if (cm->cmsg_type == IPV6_RTHDR)
			rthdr = CMSG_DATA(cm);
	}

	printf("Received IPv6 options (size %d):\n", mh->msg_controllen);
	if (pi) {
		printf("  Packetinfo: dst = %s, I/Fid = %d\n",
		       inet_ntop(AF_INET6, &pi->ipi6_addr, ntop_buf,
				 sizeof(ntop_buf)),
		       pi->ipi6_ifindex);
	}
	if (hlimp)
		printf("  Hoplimit = %d\n", *hlimp);
	if (rthdr) {
		printf("  Routing Header\n");
		print_rthdr(rthdr);
	}
}

void
print_rthdr(void *extbuf)
{
	struct in6_addr *in6;
	char ntopbuf[INET6_ADDRSTRLEN];
	struct ip6_rthdr *rh = (struct ip6_rthdr *)extbuf;
	int i, segments;

	/* print fixed part of the header */
	printf("nxt %u, len %u (%d bytes), type %u, ", rh->ip6r_nxt,
	       rh->ip6r_len, (rh->ip6r_len + 1) << 3, rh->ip6r_type);
	if ((segments = inet6_rth_segments(extbuf)) >= 0)
		printf("%d segments, ", segments);
	else
		printf("segments unknown, ");
	printf("%d left\n", rh->ip6r_segleft);

	for (i = 0; i < segments; i++) {
		in6 = inet6_rth_getaddr(extbuf, i);
		if (in6 == NULL)
			printf("   [%d]<NULL>\n", i);
		else
			printf("   [%d]%s\n", i,
			       inet_ntop(AF_INET6, (void *)in6->s6_addr,
					 ntopbuf, sizeof(ntopbuf)));
	}

	return;
}
