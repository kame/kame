/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$Id: ptr_defs.h,v 1.1 1999/08/12 12:41:11 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#define	SAME		(0)

#define	PTR_MAXHASH	(397)
#define	MAXTSLOTENTRY	(4096)

#define	SZSIN6		sizeof(struct sockaddr_in6)
#define	SZSIN		sizeof(struct sockaddr_in)

#define	CAR(p)		((p)->car)
#define	CDR(p)		((p)->cdr)
#define	CAAR(p)		(CAR(CAR(p)))
#define	CADR(p)		(CAR(CDR(p)))
#define	CDAR(p)		(CDR(CAR(p)))
#define	CDDR(p)		(CDR(CDR(p)))

#define	ReturnEnobufs(m)	if (m == NULL) { errno = ENOBUFS; return (NULL); }


/*
//##
//#------------------------------------------------------------------------
//#	Struct definitions.
//#------------------------------------------------------------------------
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
    u_char	 packet;
/*	#define	PTR_INBOUND		(1)				*/
/*	#define	PTR_OUTBOUND		(2)				*/
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
struct ipaddr
{
    u_char	sa_family;		/* AF_(INET|INET6)		*/
    union
    {
	struct in6_addr	in6;
	struct in_addr	in4;
    }		u;
};


/* IP address (source and destination) and port structure		*/
struct _pat
{
    u_char		ip_p;			/* IPPROTO_(IPV4|IPV6)	*/
    u_short		curport;
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
#define	PTR_INBOUND		(1)
#define	PTR_OUTBOUND		(2)
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


/* Configuration slot entry						*/
struct	_cSlot
{
    int		 type;
/*	#define NATPT_STATIC		(0x04)			*/
/*	#define NATPT_DYNAMIC		(0x08)			*/
/*	#define	TRANS_44		(0x00)			*/
/*	#define	TRANS_46		(0x04)			*/
/*	#define	TRANS_64		(0x08)			*/
/*	#define	TRANS_66		(0x0c)			*/
/*	#define PREFIX_FAITH		(0x100)			*/
/*	#define PREFIX_NATPT		(0x200)			*/
    u_short		 sport;
    u_short		 eport;
    struct ipaddr	 local;
    struct ipaddr	 lmask;
    struct ipaddr	 remote;
    caddr_t		 extra;
};
