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

/* based on cksum.c (v6d-0.21.tar.gz) */

#include "common.h"

struct ip6_opthdr {
	u_char ip6_next;
	u_char ip6_elen;
};

int all;
int debug;

static u_short in_cksum(u_short *, u_short *, int);

void
cksum6()
{
	int i;
	u_int a;
	int len = 0;
	int off, nh;
	u_char ipovly[40];
	u_short *cksum;
	struct in6_addr *finaldst;
	struct ip6_hdr *ip;
	struct ip6_opthdr *opt;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmp6_hdr *icmp;
	struct ip6_rthdr0 *rh0;
	u_char *packet = (u_char *)(buf) + sizeof(struct ether_header);
	u_char nxt = packet[6];
	
	ip = (struct ip6_hdr *)packet;
	off = sizeof(*ip);
	len = ntohs(ip->ip6_plen);
	finaldst = (struct in6_addr *)&packet[24];
	nh = ip->ip6_nxt;

	while (len > 2) {
		switch (nh) {
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			return;
		case IPPROTO_ESP:
		case IPPROTO_AH:
		case IPPROTO_NONE:
			return;
		case IPPROTO_ROUTING:
			rh0 = (struct ip6_rthdr0 *)(packet + off);
			if (rh0->ip6r0_type == 0 && rh0->ip6r0_len <= 46) {
				finaldst = (struct in6_addr *)((caddr_t)rh0 +
							       ((rh0->ip6r0_len + 1) << 3) -
							       sizeof(struct in6_addr));
		    }
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			opt  = (struct ip6_opthdr *)(packet + off);
			len -= (opt->ip6_elen << 3) + 8;
			off += (opt->ip6_elen << 3) + 8;
			nh = opt->ip6_next;
			break;
		case IPPROTO_FRAGMENT:
			opt  = (struct ip6_opthdr *)(packet + off);
			len -= sizeof(struct ip6_frag);
			off += sizeof(struct ip6_frag);
			nh = opt->ip6_next;
			break;
		case IPPROTO_TCP:
			tcp  = (struct tcphdr *)(packet + off);
			nxt = IPPROTO_TCP;
			cksum = &(tcp->th_sum);
			goto calc;
		case IPPROTO_UDP:
			udp  = (struct udphdr *)(packet + off);
			nxt = IPPROTO_UDP;
			cksum = &(udp->uh_sum);
			goto calc;
		case IPPROTO_ICMPV6:
			icmp  = (struct icmp6_hdr *)(packet + off);
			nxt = IPPROTO_ICMPV6;
			cksum = &(icmp->icmp6_cksum);
			goto calc;
		default:
			return;
		}
	}
	return;
	
 calc:
	
	bcopy(&packet[8], &ipovly[0], 16);
	bcopy(finaldst, &ipovly[16], 16);
	ipovly[32] = 0;
	ipovly[33] = 0;
	HTONS(len);
	bcopy((caddr_t)&len, ipovly + 34, 2);
	NTOHS(len);
	ipovly[36] = 0;
	ipovly[37] = 0;
	ipovly[38] = 0;
	ipovly[39] = nxt;

	*cksum = 0;
	*cksum = in_cksum((u_short *)(packet + off), (u_short *)ipovly, len);
	return;
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(u_short *addr, u_short *ph, int len)
{
	register int nleft = len;
	register int pleft = 40;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}
		
	while (pleft > 0)  {
		sum += *ph++;
		pleft -= 2;
	}
		
	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}
