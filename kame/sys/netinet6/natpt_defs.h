/*	$KAME: natpt_defs.h,v 1.19 2001/09/02 19:06:23 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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

#define	NATPTHASHSZ		(397)
#define	MAXTSLOTENTRY		(4096)

#define	SIN4(s)			((struct sockaddr_in  *)s)
#define	SIN6(s)			((struct sockaddr_in6 *)s)
#define	SZSIN4			sizeof(struct sockaddr_in)
#define	SZSIN6			sizeof(struct sockaddr_in6)


#ifdef _KERNEL
#define	isDebug(d)		(natpt_debug & (d))
#define	D_CHECKSUM		0x00000001

#define	isDump(d)		(natpt_dump  & (d))

#define	D_DIVEIN4		0x00000001
#define	D_MATCHINGRULE4		0x00000004
#define	D_TRANSLATEIPV4		0x00000010
#define	D_FRAGMENTED		0x00000100
#define	D_TRANSLATEDIPV4	0x00001000
#define	D_FAKETRACEROUTE	0x00004000

#define	D_DIVEIN6		0x00010000
#define	D_IN6REJECT		0x00020000
#define	D_IN6ACCEPT		0x00040000
#define	D_MATCHINGRULE6		0x00080000
#define	D_TRANSLATEIPV6		0x00100000
#endif	/* _KERNEL */


/*
 *
 */

struct pcv					/* sizeof(): 32[byte]	*/
{
	u_char	 sa_family;
	u_char	 ip_p;			/* IPPROTO_(ICMP[46]|TCP|UDP)	*/

	u_char	 type;
#define	NATPT_MAP64		1
#define	NATPT_MAP46		2
#define	NATPT_MAP44		3
#define	NATPT_MAPDPORT		4
#define	NATPT_MAPBIDIR		5

	u_char	 fromto;
#define	NATPT_FROM		0
#define	NATPT_TO		1

	u_char	 flags;
#define	NATPT_TRACEROUTE	0x01		/* does not use now	*/
#define	NATPT_NEEDFRAGMENT	0x02

	int		 poff;		/* payload offset		*/
	int		 plen;		/* payload length		*/

	struct mbuf	*m;
	struct tSlot	*ats;
	union {
		struct ip	*ip4;
		struct ip6_hdr	*ip6;
	}		 ip;
	union {
		caddr_t		  caddr;
		struct icmp	 *icmp4;
		struct icmp6_hdr *icmp6;
		struct tcphdr	 *tcp4;
		struct tcp6hdr	 *tcp6;
		struct udphdr	 *udp;
	}		pyld;
};


union inaddr					/* sizeof():  16[byte]	*/
{
    struct in_addr	in4;
    struct in6_addr	in6;
};


struct pAddr					/* sizeof():  40[byte]	*/
{
	u_char		sa_family;		/* address family	*/

	u_char		pType;			/* port range type	*/
#define	PORT_MINUS		1
#define	PORT_COLON		2

	u_char		prefix;			/* address mask length */
	u_char		aType;			/* address type	*/
#define	ADDR_ANY		0
#define	ADDR_SINGLE		1
#define	ADDR_MASK		2
#define	ADDR_RANGE		3

	u_short		port[2];

	union inaddr	addr[2];
#define	in4src			addr[0].in4
#define	in4dst			addr[1].in4
#define	in4Addr			addr[0].in4
#define	in4Mask			addr[1].in4
#define	in4RangeStart		addr[0].in4
#define	in4RangeEnd		addr[1].in4

#define	in6src			addr[0].in6
#define	in6dst			addr[1].in6
#define	in6Addr			addr[0].in6
#define	in6Mask			addr[1].in6
};


/* Configuration slot entry						*/

struct	cSlot					/* sizeof(): 100[byte]	*/
{
	TAILQ_ENTRY(cSlot)	csl_list;

	u_char		 type;
#define	NATPT_RULE_STATIC	1	/* rule was set by hand.	*/
#define	NATPT_RULE_DYNAMIC	2	/* rule was set by program.	*/

	u_char		 proto;
#define	NATPT_ICMPV6		0x01
#define	NATPT_ICMP		0x01
#define	NATPT_TCP		0x02
#define	NATPT_UDP		0x04

	u_char		 map;
#define	NATPT_REMAP_SPORT	0x01
#define	NATPT_COPY_SPORT	0x02
#define	NATPT_COPY_DPORT	0x10

	u_short		 cport;		/* current port, with host byte order	*/

	time_t		 tstamp;
	struct pAddr	 local;
	struct pAddr	 remote;
};


/* Translation slot entry						*/

struct tSlot					/* sizeof(): 132[byte]	*/
{
	TAILQ_ENTRY(tSlot)	tsl_list;
	TAILQ_ENTRY(tSlot)	tsl_hashl;	/* Hash chain.		*/
	TAILQ_ENTRY(tSlot)	tsl_hashr;	/* Hash chain.		*/

	u_char		 ip_p;			/* next level protocol	*/

	u_short		 hvl;
	u_short		 hvr;
	struct pAddr	 local;
	struct pAddr	 remote;
	time_t		 tstamp;
	u_long		 fromto;		/* counter	*/
	u_long		 tofrom;		/* counter	*/

	/* This pointer is used in order to open connection from FTP
	 * server when FTP non passive mode.
	 */
	struct cSlot	*csl;
	union {
		struct {
			n_short		 icd_id;
			n_short		 icd_seq;
		}			 ih_idseq;
		struct tcpstate		*tcps;
	}				 suit;

};


struct tcpstate					/* sizeof(): 32[byte]	*/
{
	u_char		state;		/* tcp status */
	char		ftpstate;
	char		rewrite[2];

	u_short		lport;		/* FTP PORT command argument	*/
	u_short		rport;		/* port connected from outside */

	long		delta[2];	/* [0]: outgoingDelta		*/
					/*	outgoingSeq - increment	*/
					/*	incomingAck - decrement	*/
					/* [1]: incomingDelta		*/
					/*	incomingSeq - increment	*/
					/*	outgoingAck - decrement	*/

	u_int32_t	seq[2];
	u_int32_t	ack[2];
};
