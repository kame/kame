/*	$KAME: natpt_defs.h,v 1.63 2002/12/16 04:37:36 fujisawa Exp $	*/

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

#define	NATPTHASHSZ	(397)
#define	MAXTSLOTENTRY	(32767)

#define	NATPT_FRGHDRSZ	(sizeof(struct ip6_hdr) + sizeof(struct ip6_frag))
#define	NATPT_MAXULP	(IPV6_MMTU - NATPT_FRGHDRSZ)

/* 64 bits of Original Data Datagram in ICMP message */
#define	ICMP4_DGRAM	8

#define	SIN4(s)		((struct sockaddr_in  *)s)
#define	SIN6(s)		((struct sockaddr_in6 *)s)
#define	SZSIN4		sizeof(struct sockaddr_in)
#define	SZSIN6		sizeof(struct sockaddr_in6)
#define	IP4HDRSZ	sizeof(struct ip)
#define	IP6HDRSZ	sizeof(struct ip6_hdr)
#define	TCPHDRSZ	sizeof(struct tcphdr)

#ifdef _KERNEL
#define	isDebug(d)	(natpt_debug & (d))
#define	D_CHECKSUM	0x00000001

#define	isDump(d)	(natpt_dump  & (d))

#define	D_DIVEIN4	0x00000001
#define	D_MATCHINGRULE4	0x00000004
#define	D_TRANSLATEIPV4	0x00000010
#define	D_FRAGMENTED	0x00000100
#define	D_TRANSLATEDIPV4	0x00001000
#define	D_FAKETRACEROUTE	0x00004000

#define	D_DIVEIN6	0x00010000
#define	D_IN6REJECT	0x00020000
#define	D_IN6ACCEPT	0x00040000
#define	D_MATCHINGRULE6	0x00080000
#define	D_TRANSLATEIPV6	0x00100000
#endif	/* _KERNEL */


/*
 *	NATPT_(GET|SET)VALUE related definitions.
 */

/* I assign semantics to each bit, but even numerical value may be good. */

#define	NATPTCTL_DEFAULT	0x01
#define	NATPTCTL_TSLOT	0x02
#define	NATPTCTL_CADDR	0x04
#define	NATPTCTL_ALL	0x80

#define	NATPTCTL_INT	1
#define	NATPTCTL_IN6ADDR	2
#define	NATPTCTL_CADDR_T	3

#define	NATPTCTL_ENABLE		0
#define	NATPTCTL_DEBUG		(NATPTCTL_ENABLE+1)
#define	NATPTCTL_DUMP		(NATPTCTL_DEBUG+1)
#define	NATPTCTL_PREFIX		(NATPTCTL_DUMP+1)
#define	NATPTCTL_FORCEFRAGMENT4	(NATPTCTL_PREFIX+1)
#define	NATPTCTL_USELOG		(NATPTCTL_FORCEFRAGMENT4+1)
#define	NATPTCTL_USESYSLOG	(NATPTCTL_USELOG+1)
#define	NATPTCTL_SESSIONS	(NATPTCTL_USESYSLOG+1)

#define	NATPTCTL_CSLHEAD	(NATPTCTL_SESSIONS+1)
#define	NATPTCTL_TSLHEAD	(NATPTCTL_CSLHEAD+1)

#define	NATPTCTL_TSLOTTIMER	(NATPTCTL_TSLHEAD+1)
#define	NATPTCTL_MAXTTYANY	(NATPTCTL_TSLOTTIMER+1)
#define	NATPTCTL_MAXTTYICMP	(NATPTCTL_MAXTTYANY+1)
#define	NATPTCTL_MAXTTYUDP	(NATPTCTL_MAXTTYICMP+1)
#define	NATPTCTL_MAXTTYTCP	(NATPTCTL_MAXTTYUDP+1)
#define	NATPTCTL_TCPT_2MSL	(NATPTCTL_MAXTTYTCP+1)
#define	NATPTCTL_TCP_MAXIDLE	(NATPTCTL_TCPT_2MSL+1)
#define	NATPTCTL_MAXFRAGMENT	(NATPTCTL_TCP_MAXIDLE+1)
#define	NATPTCTL_NULL		(NATPTCTL_MAXFRAGMENT+1)
#define	NATPTCTL_NUM		(NATPTCTL_NULL+1)

#define	NATPTCTL_NAMES {						\
	{ "translation", NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
	{ "debug",	NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
	{ "dump",	NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
	{ "prefix",	NATPTCTL_IN6ADDR,	NATPTCTL_DEFAULT },	\
	{ "forcefragment4",	NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
	{ "uselog",	NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
	{ "usesyslog",	NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
	{ "sessions",	NATPTCTL_INT,	NATPTCTL_DEFAULT },	\
								\
	{ "cSlotHead",	NATPTCTL_CADDR_T,	NATPTCTL_CADDR },	\
	{ "tSlotHead",	NATPTCTL_CADDR_T,	NATPTCTL_CADDR },	\
								\
	{ "tSlotTimer",	NATPTCTL_INT,	NATPTCTL_TSLOT },	\
	{ "maxTTLany",	NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{ "maxTTLicmp",	NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{ "maxTTLudp",	NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{ "maxTTLtcp",	NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{ "tcpt_2msl",	NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{ "tcp_maxidle", NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{ "maxFragment", NATPTCTL_INT,	NATPTCTL_TSLOT },		\
	{  NULL,	0,			0 },			\
}

#define	NATPTCTL_VARS {			\
	(caddr_t)&natpt_enable,		\
	(caddr_t)&natpt_debug,		\
	(caddr_t)&natpt_dump,		\
	(caddr_t)&natpt_prefix,		\
	(caddr_t)&natpt_forceFragment4,	\
	(caddr_t)&natpt_uselog,		\
	(caddr_t)&natpt_usesyslog,	\
	(caddr_t)&natpt_dummy,	\
}


struct natptctl_names {
	char	*ctl_name;
	u_short	ctl_type;
	u_short	ctl_attr;
};


/*
 *
 */

struct pcv {
	/* sizeof(): 32[byte] */
	u_char	 sa_family;
	u_char	 ip_p;		/* IPPROTO_(ICMP[46]|TCP|UDP) */

	u_char	 fromto;
#define	NATPT_FROM		0
#define	NATPT_TO		1

	u_char	 flags;
#define	NATPT_noFootPrint	0x01	/* no tslot entry corresponding to ICMP */
#define	NATPT_toIPv4		0x02	/* ipv[46] to ipv4 translation */
#define	NATPT_REVERSE		0x04	/* reverse direction of "bidir" rule */

#define	isReverse(cv)		((cv)->flags & NATPT_REVERSE)
#define	isRegular(cv)		(!isReverse(cv))

/* The following flags are used in IPv4->IPv6 translation */
#define	ZERO_OFFSET		0x08	/* fragment offset == 0 */
#define	FIRST_FRAGMENT		0x10	/* is first fragment? */
#define	NEXT_FRAGMENT		0x20	/* is fragment after the first? */
#define	NEED_FRAGMENT		0x40	/* need fragment? */
#define	SET_DF			0x80	/* is DF bit set? */

#define	IS_FRAGMENT		(FIRST_FRAGMENT | NEXT_FRAGMENT)

#define	isFragment(cv)		((cv)->flags & IS_FRAGMENT)
#define	isFirstFragment(cv)	((cv)->flags & FIRST_FRAGMENT)
#define	isNextFragment(cv)	((cv)->flags & NEXT_FRAGMENT)
#define	needFragment(cv)	((cv)->flags & NEED_FRAGMENT)
#define	isDFset(cv)		((cv)->flags & SET_DF)
#define isNoDF(cv)		(!isDFset(cv))
#define	isZeroOffset(cv)	((cv)->flags & ZERO_OFFSET)

	u_int16_t	poff;		/* payload offset */
	u_int16_t	plen;		/* payload length */

	struct ip6_frag	*fh;		/* Fragment header */
	struct pcvaux	*aux;
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
	} pyld;
};


struct pcvaux {
	u_short		 cksum6;
	u_short		 cksum4;
	struct ulc6	*ulc6;
	struct ulc4	*ulc4;
};


union inaddr {
	struct in_addr	in4;
	struct in6_addr	in6;
};


struct fragment {
	TAILQ_ENTRY(fragment)	frg_list;
	u_int8_t	 fg_family;		/* AF_INET{,6} (sa_family_t) */
	u_int8_t	 fg_proto;		/* protocol */
	u_char		 fg_fromto;
	u_short		 fg_id;		/* identification in v4 header */
	union inaddr	 fg_src;		/* source address */
	union inaddr	 fg_dst;		/* destination address */
	struct tSlot	*tslot;
	time_t		 tstamp;
};


struct pAddr {
	u_char		sa_family;	/* address family */

	u_char		pType;		/* port range type */
#define	PORT_MINUS		1
#define	PORT_COLON		2

	u_char		prefix;		/* address mask length */
	u_char		aType;		/* address type */
#define	ADDR_ANY		0
#define	ADDR_SINGLE		1
#define	ADDR_MASK		2
#define	ADDR_RANGE		3
#define	ADDR_REDIRECT		4	/* for set from kernel. */

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


struct mAddr {
	/* sizeof(): 60[byte] */
	struct pAddr	saddr;
#define	Local			local.saddr
#define	Remote			remote.saddr
#define	Port			saddr.port

	union inaddr	daddr;
	u_short		dport;
};


/* Configuration slot entry */

struct cSlot {
	/* sizeof(): 144[byte] */
	TAILQ_ENTRY(cSlot)	csl_list;

	int		 rnum;		/* rule number */

	u_char		 proto;
#define	NATPT_ICMPV6		0x01
#define	NATPT_ICMP		0x01
#define	NATPT_TCP		0x02
#define	NATPT_UDP		0x04

	u_char		 map;
#define	NATPT_REMAP_SPORT	0x01
#define	NATPT_REDIRECT_ADDR	0x02
#define	NATPT_REDIRECT_PORT	0x04
#define	NATPT_BIDIR		0x10

	u_short		 cport;		/* current port, with host byte order */

	time_t		 tstamp;
	time_t		 lifetime;
#define	CSLOT_INFINITE_LIFETIME	0xffffffff

	struct mAddr	 local;
	struct mAddr	 remote;
};


/* Translation slot entry */

struct tSlot {
	/* sizeof(): 132[byte] */
	TAILQ_ENTRY(tSlot)	tsl_list;
	TAILQ_ENTRY(tSlot)	tsl_hashl;	/* Hash chain. */
	TAILQ_ENTRY(tSlot)	tsl_hashr;	/* Hash chain. */

	u_char		 ip_p;			/* next level protocol */

	u_short		 hvl;
	u_short		 hvr;
	struct pAddr	 local;
	struct pAddr	 remote;
	time_t		 tstamp;
	u_long		 fromto;		/* counter */
	u_long		 tofrom;		/* counter */
	/*
	 * This pointer is used in order to open connection from FTP
	 * server when FTP non passive mode.
	 */
	struct cSlot	*csl;
	struct fragment *frg;
	union {
		struct {
			n_short		 icd_id;
			n_short		 icd_seq;
		}			 ih_idseq;
		u_int32_t		 ids[2];	/* hold echo/request id/seq */
		struct tcpstate		*tcps;
	}				 suit;
};


struct tcpstate {
	/* sizeof(): 32[byte] */
	u_char		state;		/* tcp status */
	char		ftpstate;
	char		rewrite[2];

	u_short		lport;		/* FTP PORT command argument */
	u_short		rport;		/* port connected from outside */

	long		delta[2];	/* [0]: outgoingDelta */
					/*	outgoingSeq - increment */
					/*	incomingAck - decrement */
					/* [1]: incomingDelta */
					/*	incomingSeq - increment */
					/*	outgoingAck - decrement */
	u_int32_t	seq[2];
	u_int32_t	ack[2];

	/*
	 * For a check of packet retransmission when TCP payload was
	 * modified in FTP translation.  These areas are MALLOCKed
	 * when needed and they hold TCP header before translation.
	 */
	caddr_t		pkthdr[2];	/* [0]: "local"  -> "remote" */
					/* [1]: "remote" -> "local"  */
};


struct sessions {
	u_int		tcp;
	u_int		tcps[11];	/* TCP_NSTATES */
	u_int		udp;
	u_int		icmp;
	u_int		others;
};
