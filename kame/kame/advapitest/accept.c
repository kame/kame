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

static u_char *rcvmsgbuf;
static int rcvmsglen; 
int aflag, dflag, Dflag, hflag, iflag, lflag, rflag, uflag; 

void print_options __P((struct msghdr *));
void print_opthdr __P((void *));
void print_rthdr __P((void *));
void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch, s, s0, remotelen, on, proto, error;
	char *portstr = DEFAULTPORT;
	struct sockaddr_in6 remote;
	struct msghdr rcvmh;
	struct iovec iov[2];
	char recvbuf[1024];	/* xxx hardcoding */
	struct addrinfo hints, *res;

	while ((ch = getopt(argc, argv, "adDhilpru")) != EOF)
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
		case 'l':
			lflag++;
			break;
		case 'p':
			portstr = optarg;
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

	proto = uflag ? IPPROTO_UDP : IPPROTO_TCP;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = uflag ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = proto;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(NULL, portstr, &hints, &res);
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
print_options(mh)
	struct msghdr *mh;
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	int *hlimp = NULL;
	char ntop_buf[INET6_ADDRSTRLEN];
	void *hbh = NULL, *dst1 = NULL, *dst2 = NULL, *rthdr = NULL;
	char ifnambuf[IF_NAMESIZE];

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

		switch(cm->cmsg_type) {
		case IPV6_PKTINFO:
			if (cm->cmsg_len ==
			    CMSG_LEN(sizeof(struct in6_pktinfo)))
				pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
		break;

		case IPV6_HOPLIMIT:
			if (cm->cmsg_len == CMSG_LEN(sizeof(int)))
				hlimp = (int *)CMSG_DATA(cm);
			break;

		case IPV6_RTHDR:
			if (rthdr)
				printf("there're more than one rthdr (ignored).\n");
			else
				rthdr = CMSG_DATA(cm);
			break;

		case IPV6_HOPOPTS:
			hbh = CMSG_DATA(cm);
			break;

		case IPV6_RTHDRDSTOPTS:
			if (dst1)
				printf("there's more than one dstopt hdr "
				       "before a rthdr (ignored)\n");
			else
				dst1 = CMSG_DATA(cm);
			break;

		case IPV6_DSTOPTS:
			if (dst2)
				printf("there's more than one dstopt hdr "
				       "after a rthdr (ignored)\n");
			else
				dst2 = CMSG_DATA(cm);
			break;
		}
	}

	printf("Received IPv6 options (size %d):\n", mh->msg_controllen);
	if (pi) {
		printf("  Packetinfo: dst=%s, I/F=(%s, id=%d)\n",
		       inet_ntop(AF_INET6, &pi->ipi6_addr, ntop_buf,
				 sizeof(ntop_buf)),
		       if_indextoname(pi->ipi6_ifindex, ifnambuf),
		       pi->ipi6_ifindex);
	}
	if (hlimp)
		printf("  Hoplimit = %d\n", *hlimp);
	if (hbh) {
		printf("  HbH Options Header\n");
		print_opthdr(hbh);
	}
	if (dst1) {
		printf("  Destination Options Header (before rthdr)\n");
		print_opthdr(dst1);
	}
	if (rthdr) {
		printf("  Routing Header\n");
		print_rthdr(rthdr);
	}
	if (dst2) {
		printf("  Destination Options Header (after rthdr)\n");
		print_opthdr(dst2);
	}
}

void
print_opthdr(void *extbuf)
{
	struct ip6_hbh *ext;
	int currentlen;
	u_int8_t type;
	size_t extlen, len;
	void *databuf;
	size_t offset;
	u_int16_t value2;
	u_int32_t value4;

	ext = (struct ip6_hbh *)extbuf;
	extlen = (ext->ip6h_len + 1) * 8;
	printf("    nxt %u, len %u (%d bytes)\n", ext->ip6h_nxt,
	       ext->ip6h_len, extlen);

	currentlen = 0;
	while (1) {
		currentlen = inet6_opt_next(extbuf, extlen, currentlen,
					    &type, &len, &databuf);
		if (currentlen == -1)
			break;
		switch (type) {
		/*
		 * Note that inet6_opt_next automatically skips any padding
		 * optins.
		 */
		case IP6OPT_JUMBO:
			offset = 0;
			offset = inet6_opt_get_val(databuf, offset,
						   &value4, sizeof(value4));
			printf("    Jumbo Payload Opt: Length %u\n",
			       (unsigned int)ntohl(value4));
			break;
		case IP6OPT_ROUTER_ALERT:
			offset = 0;
			offset = inet6_opt_get_val(databuf, offset,
						   &value2, sizeof(value2));
			printf("    Router Alert Opt: Type %u\n",
			       ntohs(value2));
			break;
		default:
			printf("    Received Opt %u len %u\n", type, len);
			break;
		}
	}
	return;
}

void
print_rthdr(void *extbuf)
{
	struct in6_addr *in6;
	char ntopbuf[INET6_ADDRSTRLEN];
	struct ip6_rthdr *rh = (struct ip6_rthdr *)extbuf;
	int i, segments;

	/* print fixed part of the header */
	printf("    nxt %u, len %u (%d bytes), type %u, ", rh->ip6r_nxt,
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

void
usage()
{
	fprintf(stderr, "usage: accept [-adDhlru] [-p port]\n");
	exit(1);
}
