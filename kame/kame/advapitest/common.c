/*	$KAME: common.c,v 1.7 2001/02/09 08:31:24 jinmei Exp $ */

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

#include <netdb.h>
#include <arpa/inet.h>

#include <stdio.h>

#include "common.h"

char *
ip6str(sa6)
	struct sockaddr_in6 *sa6;
{
	static char ip6buf[8][NI_MAXHOST];
	static int ip6round = 0;
	char *cp;
	static char invalid[] = "(invalid)";
	int flags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	flags |= NI_WITHSCOPEID;
#endif

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];
	
	if (getnameinfo((struct sockaddr *)sa6, sa6->sin6_len, cp,
			NI_MAXHOST, NULL, 0, flags))
		return(invalid);

	return(cp);
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
	/* XXX: KAME specific at this moment */
	struct ip6_mtuinfo *mtuinfo = NULL;

	if (mh->msg_controllen == 0) {
		printf("No IPv6 option is received\n");
		return;
	}
	
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

		case IPV6_PATHMTU:
			if (cm->cmsg_len == CMSG_LEN(sizeof(*mtuinfo)))
				mtuinfo = (struct ip6_mtuinfo *)CMSG_DATA(cm);
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
	if (mtuinfo) {
		printf("  Path MTU: destination=%s, from=%s, mtu=%lu\n",
		       ip6str(&mtuinfo->ip6m_addr),
		       ip6str((struct sockaddr_in6 *)mh->msg_name),
		       (u_long)mtuinfo->ip6m_mtu);
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
		 * options.
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
