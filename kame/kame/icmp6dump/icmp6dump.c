/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

int sock;
void sock_open(void);
void dump(void);

int
main(argc, argv)
	int argc;
	char *argv[];
{
	fd_set fdset;
	int i;
	struct icmp6_filter filt;
	
	sock_open();

#ifdef ICMP6_FILTER
	if (argc == 1)
		ICMP6_FILTER_SETPASSALL(&filt);
	else {
		int type;

		ICMP6_FILTER_SETBLOCKALL(&filt);
		argc--; argv++;
		while (argc-- > 0) {
			type = atoi(*argv);
			ICMP6_FILTER_SETPASS(type, &filt);
			argv++;
		}
	}
	if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
			sizeof(filt)) < 0) {
		perror("setsockopt(ICMP6_FILTER)");
		exit(-1);
	}
#endif /*ICMP6_FILTER*/

	FD_ZERO(&fdset);
	for (;;) {
		FD_SET(sock, &fdset);
		if ((i = select(sock + 1, &fdset, NULL, NULL, NULL)) < 0)
			perror("select");
		if(i == 0)
			continue;
		else
			dump();
	}
	exit(0);
}

void
dump()
{
	int i, j;
#ifdef OLD_RAWSOCK
	struct ip6_hdr *ip6;
#endif
	struct icmp6_hdr *icmp6;
	u_char buf[1024];
	struct sockaddr_in6 from;
	int from_len = sizeof(from);
	char ntop_buf[256];

	if ((i = recvfrom(sock, buf, sizeof(buf), 0,
			  (struct sockaddr *)&from,
			  &from_len)) < 0)
		return;
#ifndef OLD_RAWSOCK
	if (i < sizeof(struct icmp6_hdr)) {
		printf("too short!\n");
		return;
	}

	icmp6 = (struct icmp6_hdr *)buf;
#else
	if (i < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
		printf("too short!\n");
		return;
	}

	ip6 = (struct ip6_hdr *)buf;
	icmp6 = (struct icmp6_hdr *)(ip6 + 1);	/*xxx*/
#endif

	printf("from %s, ", inet_ntop(AF_INET6, &from.sin6_addr,
				      ntop_buf, sizeof(ntop_buf)));
	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		printf("type=unreach,");
		switch(icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			printf("code=no route\n");
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			printf("code=admin\n");
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			printf("code=beyond scope\n");
			break;
		case ICMP6_DST_UNREACH_ADDR:
			printf("code=address\n");
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			printf("code=port\n");
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		printf("type=packet too big\n");
		break;
	case ICMP6_TIME_EXCEEDED:
		printf("type=time exceed,");
		switch(icmp6->icmp6_code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			printf("code=in trans\n");
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			printf("code=in reass\n");
			break;
		}
		break;
	case ICMP6_PARAM_PROB:
		printf("type=parameter problem,");
		switch(icmp6->icmp6_code) {
		case ICMP6_PARAMPROB_HEADER:
			printf("code=header\n");
			break;
		case ICMP6_PARAMPROB_NEXTHEADER:
			printf("code=next header\n");
			break;
		case ICMP6_PARAMPROB_OPTION:
			printf("code=option\n");
			break;
		}
		break;
	case ICMP6_ECHO_REQUEST:
		printf("type=icmp echo request\n");
		break;
	case ICMP6_ECHO_REPLY:
		printf("type=icmp echo reply\n");
		break;
	case ICMP6_FQDN_QUERY:
		printf("type=icmp FQDN query\n");
		break;
	case ICMP6_FQDN_REPLY:
		printf("type=icmp FQDN reply\n");
		break;
	case ICMP6_MEMBERSHIP_QUERY:
		printf("type=group query\n");
		break;
	case ICMP6_MEMBERSHIP_REPORT:
		printf("type=group report\n");
		break;
	case ICMP6_MEMBERSHIP_REDUCTION:
		printf("type=group termination\n");
		break;
	case ND_ROUTER_SOLICIT:
		printf("type=router solicitation\n");
		break;
	case ND_ROUTER_ADVERT:
		printf("type=router advertisement\n");
		break;
	case ND_NEIGHBOR_SOLICIT:
		printf("type=neighbor solicitation\n");
		break;
	case ND_NEIGHBOR_ADVERT:
		printf("type=neighbor advertisement\n");
		break;
	case ND_REDIRECT:
		printf("type=redirect\n");
		break;
	default:
		printf("type=unknown\n");
		break;
	}

	j = 0;
	printf("  ");
	while (j < i) {
		if (buf[j] <= 0xf)
			putchar('0');
		printf("%x", buf[j++]);
		if (j % 2 == 0)
			putchar(' ');
		if (j % 16 == 0)
			printf("\n  ");
	}
	printf("\n");
	if (j % 16 != 0)
		printf("\n");
	fflush(stdout);
}


void
sock_open()
{
	struct sockaddr_in6 me;
	
	if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
		err(1, "socket");

	memset(&me, 0, sizeof(struct sockaddr_in6));
	me.sin6_len = sizeof(struct sockaddr_in6);
	me.sin6_family = AF_INET6;

	if (bind(sock, (struct sockaddr *)&me, sizeof(me)) < 0)
		err(1, "bind");
}
