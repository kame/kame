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
 *
 *	$Id: natpt_defs.h,v 1.2 1999/12/25 02:35:30 fujisawa Exp $
 */

#define	SAME		(0)

#define	NATPT_MAXHASH	(397)
#define	MAXTSLOTENTRY	(4096)

#define	SZSIN6		sizeof(struct sockaddr_in6)
#define	SZSIN		sizeof(struct sockaddr_in)

#define	CAR(p)		((p)->car)
#define	CDR(p)		((p)->cdr)
#define	CAAR(p)		(CAR(CAR(p)))
#define	CADR(p)		(CAR(CDR(p)))
#define	CDAR(p)		(CDR(CAR(p)))
#define	CDDR(p)		(CDR(CDR(p)))

#if !defined(TCP6)
#define	tcp6hdr		tcphdr
#endif


#if defined(NATPT_DEBUG) && (NATPT_DEBUG != 0)
# if defined(__STDC__)
#  define	NATPT_ASSERT(e)	((e) ? (void)0 : natpt_assert(__FILE__, __LINE__, #e))
# else	/* PCC */
#  define	NATPT_ASSERT(e)	((e) ? (void)0 : natpt_assert(__FILE__, __LINE__, "e"))
# endif
#else
# undef NATPT_DEBUG
# define	NATPT_ASSERT(e)	((void)0)
#endif

#define	ReturnEnobufs(m)	if (m == NULL) { errno = ENOBUFS; return (NULL); }


#if (defined(KERNEL)) || (defined(_KERNEL))
extern u_int		natpt_debug;

#define	isDebug(d)	(natpt_debug & (d))

#define	D_DIVEIN4			0x00010000
#define	D_PEEKOUTGOINGV4		0x00020000
#define	D_TRANSLATINGIPV4TO6		0x00100000

#define	D_DIVEIN6			0x01000000
#define	D_IN6REJECT			0x02000000
#define	D_IN6ACCEPT			0x04000000
#define	D_PEEKOUTGOINGV6		0x08000000
#define	D_TRANSLATINGIPV6TO4		0x10000000

#endif	/* defined(KERNEL)			*/


#define	fixSuMiReICMPBug	(1)

#if defined(fixSuMiReICMPBug)
#define	IPDST		(0xc48db2cb)		/* == 203.178.141.196	XXX	*/
#define	ICMPSRC		(0x02c410ac)		/* == 172.16.196.2	XXX	*/
#endif


/*
 *	OS dependencies
 */

#ifdef _KERNEL

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#define	rcb_list		list
#endif

#if defined(__NetBSD__)
/*
 * Macros for type conversion
 * dtom(x) -	convert data pointer within mbuf to mbuf pointer (XXX)
 */
#define	dtom(x)		((struct mbuf *)((long)(x) & ~(MSIZE-1)))
#endif

#endif	/* _KERNEL	*/


/*
 *	Struct definitions.
 */

typedef	struct	_cell
{
    struct  _cell   *car;
    struct  _cell   *cdr;
}   Cell;


/* Interface Box structure						*/
struct ifBox
{
    int			 side;
#define	noSide			(0)
#define	inSide			(1)
#define	outSide			(2)
    char		 ifName[IFNAMSIZ];
    struct ifnet	*ifnet;
};


/* IP ...								*/
struct _cv
{
    u_char	 ip_p;			/*				*/
    u_char	 ip_payload;		/* IPPROTO_(ICMP|TCP|UDP)	*/
    u_char	 inout;
/*	#define	NATPT_UNSPEC		(0)				*/
/*	#define	NATPT_INBOUND		(1)				*/
/*	#define	NATPT_OUTBOUND		(2)				*/
    u_char	 flags;
#define		NATPT_TRACEROUTE	(0x01)
#define		NATPT_NEEDFRAGMENT	(0x02)

    int		 poff;			/* payload offset		*/
    int		 plen;			/* payload length		*/

    struct mbuf		*m;
    struct _tSlot	*ats;
    union
    {
	struct ip	*_ip4;
	struct ip6_hdr	*_ip6;
    }		 _ip;
    union
    {
	caddr_t		  _caddr;
	struct icmp	 *_icmp4;
	struct icmp6_hdr *_icmp6;
	struct tcphdr	 *_tcp4;
	struct tcp6hdr	 *_tcp6;
	struct udphdr	 *_udp;
    }		 _payload;
};


/* IP address structure							*/
union inaddr
{
    struct in_addr	in4;
    struct in6_addr	in6;
};


struct ipaddr
{
    u_char		sa_family;		/* AF_(INET|INET6)	*/
    union inaddr	u;
};


/* IP address (source and destination) and port structure		*/
struct _pat
{
    u_char		ip_p;			/* IPPROTO_(IPV4|IPV6)	*/
    u_short		sport;
    u_short		dport;
    struct ipaddr	src;
    struct ipaddr	dst;
};


/* Translation slot entry						*/
struct	_tSlot
{
    u_char	ip_payload;
    u_char	session;
#define	NATPT_UNSPEC		(0)
#define	NATPT_INBOUND		(1)
#define	NATPT_OUTBOUND		(2)
    u_char	flags;
#define	NATPT_STATIC		(0x01)
#define	NATPT_DYNAMIC		(0x02)
#define NATPT_FAITH		(0x04)

    struct _pat	local;
    struct _pat	remote;
    time_t	tstamp;
    int		lcount;

    union
    {
	struct _idseq
	{
	    n_short		 icd_id;
	    n_short		 icd_seq;
	}			 ih_idseq;
	struct _tcpstate	*tcp;
    }				 suit;
};


struct _tcpstate
{
    short	_state;
    short	_session;
    u_long	_ip_id[2];	/* IP packet Identification			*/
				/*    [0]: current packet			*/
				/*    [1]: just before packet			*/
    u_short	_port[2];	/* [0]:outGoing srcPort, [1]:inComing dstPort	*/
/*  u_long	_iss;			initial send sequence number		*/
    u_long	_delta[3];	/* Sequence delta				*/
				/*    [0]: current     (cumulative)		*/
				/*    [1]: just before (cumulative)		*/
				/*    [2]: (this time)				*/
};


struct addrCouple
{
    u_short		family;		/* AF_(INET|INET6)			*/
    u_short		type;
#define	ADDR_ANY		(0)
#define	ADDR_SINGLE		(1)
#define	ADDR_MASK		(2)
#define	ADDR_RANGE		(3)
    union inaddr	addr[2];
};


/* Configuration slot entry auxiliary					*/
struct	_cSlotAux
{
    u_short		cport;		/* current port			*/
    union inaddr	lcomp;		/* := local & lmask		*/
};


/* Configuration slot entry						*/
struct	_cSlot
{
    struct
    {
	unsigned	flags:8;
/*	#define	NATPT_STATIC		(0x01)		*/
/*	#define	NATPT_DYNAMIC		(0x02)		*/
/*	#define NATPT_FAITH		(0x04)		*/

	unsigned	adrtype:4;
/*	#define	ADDR_ANY		(0)		*/
/*	#define	ADDR_SINGLE		(1)		*/
/*	#define	ADDR_MASK		(2)		*/
/*	#define	ADDR_RANGE		(3)		*/

	unsigned	dir:4;
/*	#define	NATPT_UNSPEC		(0)				*/
/*	#define	NATPT_INBOUND		(1)				*/
/*	#define	NATPT_OUTBOUND		(2)				*/

	unsigned	lfamily:8;	/* address family (local)	*/
	unsigned	rfamily:8;	/* address family (remote)	*/
    }c;
    
    union inaddr	 local;
    union inaddr	 lmask;
    union inaddr	 remote;
    union inaddr	 rmask;

    u_short		 sport;
    u_short		 eport;

    struct _cSlotAux	*aux;
};
