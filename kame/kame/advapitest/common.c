/*	$KAME: common.c,v 1.20 2005/06/25 19:27:01 jinmei Exp $ */

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

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

static void print_icmp6_filter __P((struct icmp6_filter *));

char *
ip6str(sa6)
	struct sockaddr_in6 *sa6;
{
	static char ip6buf[8][NI_MAXHOST];
	static int ip6round = 0;
	char *cp;
	static char invalid[] = "(invalid)";
	int flags = NI_NUMERICHOST;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];
	
	if (getnameinfo((struct sockaddr *)sa6, sizeof(*sa6), cp,
			NI_MAXHOST, NULL, 0, flags))
		return(invalid);

	return(cp);
}

void
dump_localopt(s, socktype, proto)
	int s, socktype, proto;
{
	char optbuf[4096];
	char ntopbuf[INET6_ADDRSTRLEN];
	struct in6_pktinfo *pktinfo;
	int optlen;

#ifdef IPV6_PKTINFO
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, optbuf, &optlen))
		warn("getsockopt(IPV6_PKTINFO)");
	else if (optlen == sizeof(*pktinfo)) {
		pktinfo = (struct in6_pktinfo *)optbuf;
		printf("IPV6_PKTINFO: %s, %d\n",
		       inet_ntop(AF_INET6, &pktinfo->ipi6_addr, ntopbuf,
				 sizeof(ntopbuf)),
		       pktinfo->ipi6_ifindex);
	} else
		warnx("IPV6_PKTINFO: invalid option length: %d", optlen);
#endif

#ifdef IPV6_HOPLIMIT
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_HOPLIMIT, optbuf, &optlen))
		warn("getsockopt(IPV6_HOPLIMIT)");
	else if (optlen == sizeof(int))
		printf("IPV6_HOPLIMIT: %d\n", *(int *)optbuf);
	else {
		/* this should be the case in RFC3542 */
		warnx("IPV6_HOPLIMIT: invalid option length: %d", optlen);
	}
#endif

#ifdef IPV6_NEXTHOP
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_NEXTHOP, optbuf, &optlen))
		warn("getsockopt(IPV6_NEXTHOP)");
	else if (optlen == 0) {
		printf("IPV6_NEXTHOP: no option\n");
	/* XXX: we assume the kernel only supports AF_NET6 nexthops */
	} else if (optlen == sizeof(struct sockaddr_in6)) {
		printf("IPV6_NEXTHOP: %s\n",
		       ip6str((struct sockaddr_in6 *)optbuf));
	} else
		warnx("IPV6_NEXTHOP: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RTHDR
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, optbuf, &optlen))
		warn("getsockopt(IPV6_RTHDR)");
	else {
		printf("IPV6_RTHDR:");
		if (optlen) {
			print_rthdr(optbuf);
		} else
			printf(" no option\n");
	}
#endif

#ifdef IPV6_HOPOPTS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_HOPOPTS, optbuf, &optlen))
		warn("getsockopt(IPV6_HOPOPTS)");
	else {
		printf("IPV6_HOPOPTS:");
		if (optlen) {
			print_opthdr(optbuf);
		} else
			printf(" no option\n");
	}
#endif

#ifdef IPV6_DSTOPTS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_DSTOPTS, optbuf, &optlen))
		warn("getsockopt(IPV6_DSTOPTS)");
	else {
		printf("IPV6_DSTOPTS:");
		if (optlen) {
			print_opthdr(optbuf);
		} else
			printf(" no option\n");
	}
#endif

#ifdef IPV6_RTHDRDSTOPTS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RTHDRDSTOPTS, optbuf, &optlen))
		warn("getsockopt(IPV6_RTHDRDSTOPTS)");
	else {
		printf("IPV6_RTHDRDSTOPTS:");
		if (optlen) {
			print_opthdr(optbuf);
		} else
			printf(" no option\n");
	}
#endif

#ifdef IPV6_TCLASS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, optbuf, &optlen))
		warn("getsockopt(IPV6_TCLASS)");
	else if (optlen == sizeof(int))
		printf("IPV6_TCLASS: %d\n", *(int *)optbuf);
	else
		warnx("IPV6_TCLASS: invalid option length: %d", optlen);
#endif

#ifdef IPV6_USE_MIN_MTU
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU, optbuf, &optlen))
		warn("getsockopt(IPV6_USE_MIN_MTU)");
	else if (optlen == sizeof(int))
		printf("IPV6_USE_MIN_MTU: %d\n", *(int *)optbuf);
	else
		warnx("IPV6_USE_MIN_MTU: invalid option length: %d", optlen);
#endif

#ifdef IPV6_DONTFRAG
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, optbuf, &optlen))
		warn("getsockopt(IPV6_DONTFRAG)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_DONTFRAG: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_DONTFRAG: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVPKTINFO
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVPKTINFO)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVPKTINFO: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVPKTINFO: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVHOPLIMIT
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVHOPLIMIT)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVHOPLIMIT: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVHOPLIMIT: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVRTHDR
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVRTHDR, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVRTHDR)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVRTHDR: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVRTHDR: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVHOPOPTS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPOPTS, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVHOPOPTS)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVHOPOPTS: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVHOPOPTS: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVRTHDRDSTOPTS	/* RFC3542 obsoleted this option. */
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVRTHDRDSTOPTS, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVRTHDRDSTOPTS)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVRTHDRDSTOPTS: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVRTHDRDSTOPTS: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVDSTOPTS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVDSTOPTS, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVDSTOPTS)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVDSTOPTS: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVDSTOPTS: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVTCLASS
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVTCLASS, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVTCLASS)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVTCLASS: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVTCLASS: invalid option length: %d", optlen);
#endif

#ifdef IPV6_RECVPATHMTU
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_RECVPATHMTU, optbuf, &optlen))
		warn("getsockopt(IPV6_RECVPATHMTU)");
	else if (optlen == sizeof(int)) {
		printf("IPV6_RECVPATHMTU: %s\n",
		       *(int *)optbuf ? "on" : "off");
	}
	else
		warnx("IPV6_RECVPATHMTU: invalid option length: %d", optlen);
#endif

#ifdef IPV6_CHECKSUM
	if (socktype == SOCK_RAW) {
		optlen = sizeof(optbuf);
		if (getsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, optbuf,
			       &optlen))
			warn("getsockopt(IPV6_CHECKSUM)");
		else if (optlen == sizeof(int))
			printf("IPV6_CHECKSUM: %d\n", *(int *)optbuf);
		else
			warnx("IPV6_CHECKSUM: invalid option length: %d",
			      optlen);
	}
#endif

#ifdef ICMP6_FILTER
	if (proto == IPPROTO_ICMPV6) {
		optlen = sizeof(optbuf);
		if (getsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, optbuf,
			       &optlen))
			warn("getsockopt(ICMP6_FILTER)");
		else if (optlen == sizeof(struct icmp6_filter))
			print_icmp6_filter((struct icmp6_filter *)optbuf);
		else
			warnx("ICMP6_FILTER: invalid option length: %d",
			      optlen);
	}
#endif

#ifdef IPV6_PREFER_TEMPADDR
	optlen = sizeof(optbuf);
	if (getsockopt(s, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, optbuf, &optlen))
		warn("getsockopt(IPV6_PREFER_TEMPADDR)");
	else if (optlen == sizeof(int))
		printf("IPV6_PREFER_TEMPADDR: %d\n", *(int *)optbuf);
	else
		warnx("IPV6_PREFER_TEMPADDR: invalid option length: %d", optlen);
#endif
}

static void
print_icmp6_filter(filter)
	struct icmp6_filter *filter;
{
	int i, j;
	char *indent ="ICMP6_FILTER:[";

	printf("%s", indent);
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 64; j++) {
			if (ICMP6_FILTER_WILLPASS(j, filter))
				putchar('1');
			else
				putchar('0');
		}
		if (i < 3)	/* XXX */
			printf("\n%*s", (int)strlen(indent), "");
		else
			printf("]\n");
	}
}

void
print_options(mh)
	struct msghdr *mh;
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	char ntop_buf[INET6_ADDRSTRLEN];
	char ifnambuf[IF_NAMESIZE];
	/* XXX: KAME specific at this moment */
#ifdef __KAME__
	struct ip6_mtuinfo *mtuinfo = NULL;
#endif

	if (mh->msg_controllen == 0) {
		printf("No IPv6 option is received\n");
		return;
	}

	printf("Received IPv6 options (size %d):\n", mh->msg_controllen);
	
	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(mh);
	     cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(mh, cm)) {
		/* to prevent for infinite loop. or just believe kernel? */
		if (cm->cmsg_len == 0)
			break;

		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		switch(cm->cmsg_type) {
#ifdef IPV6_PKTINFO
		case IPV6_PKTINFO:
			if (cm->cmsg_len ==
			    CMSG_LEN(sizeof(struct in6_pktinfo))) {
				pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
				printf("  Packetinfo: dst=%s, "
				       "I/F=(%s, id=%d)\n",
				       inet_ntop(AF_INET6, &pi->ipi6_addr,
						 ntop_buf, sizeof(ntop_buf)),
				       if_indextoname(pi->ipi6_ifindex,
						      ifnambuf),
				       pi->ipi6_ifindex);
			}
		break;
#endif

#ifdef IPV6_HOPLIMIT
		case IPV6_HOPLIMIT:
			if (cm->cmsg_len == CMSG_LEN(sizeof(int))) {
				printf("  Hoplimit = %d\n",
				       *(int *)CMSG_DATA(cm));
			}
			break;
#endif

#ifdef IPV6_TCLASS
		case IPV6_TCLASS:
			if (cm->cmsg_len == CMSG_LEN(sizeof(int))) {
				printf("  Traffic Class = %d\n",
				       *(int *)CMSG_DATA(cm));
			}
			break;
#endif

#ifdef IPV6_RTHDR
		case IPV6_RTHDR:
			printf("  Routing Header\n");
			print_rthdr(CMSG_DATA(cm));
			break;
#endif

#ifdef IPV6_HOPOPTS
		case IPV6_HOPOPTS:
			printf("  HbH Options Header\n");
			print_opthdr(CMSG_DATA(cm));
			break;
#endif

#ifdef IPV6_DSTOPTS
		case IPV6_DSTOPTS:
			printf("  Destination Options Header\n");
			print_opthdr(CMSG_DATA(cm));
			break;
#endif

#if defined(IPV6_PATHMTU) && defined(__KAME__)
		case IPV6_PATHMTU:
			if (cm->cmsg_len == CMSG_LEN(sizeof(*mtuinfo))) {
				mtuinfo = (struct ip6_mtuinfo *)CMSG_DATA(cm);
				printf("  Path MTU: destination=%s, "
				       "from=%s, mtu=%lu\n",
				       ip6str(&mtuinfo->ip6m_addr),
				       ip6str((struct sockaddr_in6 *)mh->msg_name),
				       (u_long)mtuinfo->ip6m_mtu);
			}
			break;
#endif
		}
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
	printf("    nxt %d, len %d (%d bytes)\n", ext->ip6h_nxt,
	       ext->ip6h_len, (int)extlen);

	currentlen = 0;
	while (1) {
		currentlen = inet6_opt_next(extbuf, extlen, currentlen,
					    &type, &len, &databuf);
		if (currentlen == -1)
			break;
		switch (type) {
		/*
		 * Note that inet6_opt_next automatically skips any padding
		 * options.
		 */
#ifdef IP6OPT_JUMBO
		case IP6OPT_JUMBO:
			offset = 0;
			offset = inet6_opt_get_val(databuf, offset,
						   &value4, sizeof(value4));
			printf("    Jumbo Payload Opt: Length %u\n",
			       (unsigned int)ntohl(value4));
			break;
#endif
#ifdef IP6OPT_ROUTER_ALERT
		case IP6OPT_ROUTER_ALERT:
			offset = 0;
			offset = inet6_opt_get_val(databuf, offset,
						   &value2, sizeof(value2));
			printf("    Router Alert Opt: Type %u\n",
			       ntohs(value2));
			break;
#endif
		default:
			printf("    Opt %d len %d\n", type, (int)len);
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
