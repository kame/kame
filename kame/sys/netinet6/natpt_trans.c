/*	$KAME: natpt_trans.c,v 1.162 2004/04/16 04:42:28 fujisawa Exp $	*/

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

#ifdef __FreeBSD__
#include "opt_natpt.h"
#endif

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <net/ethernet.h>		/* for #define ETHERMTU */
#include <net/route.h>			/* for <netinet6/ip6_var.h> */

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>

#include <netinet6/ip6_var.h>		/* for ip6_forward() */
#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_var.h>

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
#include <machine/in_cksum.h>
#endif


/*
 * The number of bytes to compare when translator examines whether TCP
 * packet was retransmitted.
 * This includes source and destination port, sequence number,
 * acknowledgement number, header length, and flags.
 */
#define	TCPCHKSZ	14


#define	FTP_DATA		20
#define	FTP_CONTROL	21
#define	TFTP		69

#if BYTE_ORDER == BIG_ENDIAN
#define	FTP4_PASV	0x50415356
#define	FTP4_PORT	0x504f5254
#define	FTP6_LPSV	0x4c505356
#define	FTP6_LPRT	0x4c505254
#define	FTP6_EPRT	0x45505254
#define	FTP6_EPSV	0x45505356
#else
#define	FTP4_PASV	0x56534150
#define	FTP4_PORT	0x54524f50
#define	FTP6_LPSV	0x5653504c
#define	FTP6_LPRT	0x5452504c
#define	FTP6_EPRT	0x54525045
#define	FTP6_EPSV	0x56535045
#endif

#define	FTPMINCMD	"CWD\r\n"
#define	FTPMINCMDLEN	strlen(FTPMINCMD)

#define	FTPS_PASV	1
#define	FTPS_PORT	2
#define	FTPS_LPRT	3
#define	FTPS_LPSV	4
#define	FTPS_EPRT	5
#define	FTPS_EPSV	6


struct pseudohdr {
	struct in_addr	ip_src, ip_dst;
	u_int16_t	ip_p;
	u_int16_t	ip_len;
};


struct ftpparam {
	u_long		cmd;
	caddr_t		arg;	/* argument in mbuf if exist */
	caddr_t		argend;
	struct sockaddr	*sa;	/* allocated */
};


#define PSEUDOHDRSZ	40	/* sizeof pseudo-header */
struct ulc6 {
	struct in6_addr	ulc_src, ulc_dst;
	u_long		ulc_len;
	u_char		ulc_zero[3];
	u_char		ulc_pr;
	union {
		struct icmp6_hdr ih;
		struct tcphdr	 th;
		struct udphdr	 uh;
	}		ulc_tu;
};

struct ulc4 {
	struct in_addr	ulc_src, ulc_dst;
	u_char		ulc_zero;
	u_char		ulc_pr;
	u_short		ulc_len;
	union {
		struct tcphdr	th;
		struct udphdr	uh;
	}		ulc_tu;
};


extern	int	udpcksum;	/* defined in netinet/udp_usrreq.c */

#ifdef __FreeBSD__
MALLOC_DECLARE(M_NATPT);
#endif


/*
 *
 */

/* for fujisawa's convenience */
/* struct mbuf	*natpt_translateIPv6To4 */
/* struct mbuf	*natpt_translateIPv4To6 */
/* struct mbuf	*natpt_translateIPv4To4 */

/* IPv6 -> IPv4 */
struct mbuf	*natpt_translateICMPv6To4	__P((struct pcv *, struct pAddr *));
void		 natpt_icmp6DstUnreach	__P((struct icmp6_hdr *, struct icmp *));
void		 natpt_icmp6Informational __P((struct pcv *, struct pcv *));
void		 natpt_icmp6MimicPayload	__P((struct pcv *, struct pcv *,
					     struct pAddr *));
void		 natpt_translatePing4to66	__P((struct pcv *, struct pcv *, int));
void		 natpt_revertICMPv6To4address	__P((struct pcv *, struct mbuf *));
struct mbuf	*natpt_translateTCPv6To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateUDPv6To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPUDPv6To4 __P((struct pcv *, struct pAddr *,
					     struct pcv *));
void		 natpt_watchUDP6		__P((struct pcv *));

/* IPv4 -> IPv6 */
struct mbuf	*natpt_translateICMPv4To6	__P((struct pcv *, struct pAddr *));
int		 natpt_icmp4Informational	__P((struct pcv *, struct pcv *));
void		 natpt_icmp4Unreach		__P((struct icmp *, struct icmp6_hdr*));
int		 natpt_icmp4MimicPayload	__P((struct pcv *, struct pcv *,
					     struct pAddr *));
struct mbuf	*natpt_translateTCPv4To6	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateUDPv4To6	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPUDPv4To6 __P((struct pcv *, struct pAddr *,
					     struct pcv *));

void		 natpt_translateFragment4to66 __P((struct pcv *, struct pAddr *));
void		 natpt_sendFragmentedTail	__P((struct pcv *, struct ip6_hdr *, struct ip6_frag *));
void		 natpt_ip6_forward	__P((struct mbuf *));

/* IPv4 -> IPv4 */
struct mbuf	*natpt_translateICMPv4To4	__P((struct pcv *, struct pAddr *));
void		 natpt_icmp4TimeExceed	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPv4To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateUDPv4To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPUDPv4To4 __P((struct pcv *, struct pAddr *,
					     struct pcv *));
void		 natpt_translatePYLD4To4	__P((struct pcv *));

/* FTP translation */
void		 natpt_translatePYLD		__P((struct pcv *, u_short *));
int		 natpt_translateFTP6CommandTo4 __P((struct pcv *));
int		 natpt_translateFTP4ReplyTo6 __P((struct pcv *));
struct ftpparam	*natpt_parseFTPdialogue	__P((caddr_t, caddr_t, struct ftpparam *));
struct sockaddr	*natpt_parseLPRT		__P((caddr_t, caddr_t, struct sockaddr_in6 *));
struct sockaddr	*natpt_parseEPRT		__P((caddr_t, caddr_t, struct sockaddr_in6 *));
struct sockaddr	*natpt_parsePORT		__P((caddr_t, caddr_t, struct sockaddr_in *));
struct sockaddr	*natpt_parse227		__P((caddr_t, caddr_t, struct sockaddr_in *));
struct sockaddr	*natpt_parse229		__P((caddr_t, caddr_t, struct sockaddr_in6 *));
int		 natpt_pton6		__P((caddr_t, caddr_t, struct in6_addr *));
int		 natpt_rewriteMbuf	__P((struct mbuf *, char *, int, char *,int));
void		 natpt_updateSeqAck	__P((struct pcv *, caddr_t, int));
void		 natpt_incrementSeq	__P((struct tcphdr *, int));
void		 natpt_decrementAck	__P((struct tcphdr *, int));

/* */

int		 natpt_updateTcpStatus	__P((struct pcv *));
int		 natpt_tcpfsm		__P((short state, int, u_char flags));
struct mbuf	*natpt_mgethdr		__P((int, int));
struct ip6_frag	*natpt_composeIPv6Hdr	__P((struct pcv *, struct pAddr *,
					     struct ip6_hdr *));
void		 natpt_composeIPv4Hdr	__P((struct pcv *, struct pAddr *,
					     struct ip *));
void		 natpt_adjustMBuf		__P((struct mbuf *, struct mbuf *));
void		 natpt_fixTCPUDP64cksum	__P((int, int, struct pcv *, struct pcv *));
void		 natpt_fixTCPUDP44cksum	__P((int, struct pcv *, struct pcv *));
int		 natpt_fixCksum		__P((int, u_char *, int, u_char *, int));


/*
 *	Translate from IPv6 to IPv4
 */

struct mbuf *
natpt_translateIPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	const char	*fn = __FUNCTION__;

	struct pcv	cv4;
	struct timeval	atv;
	struct mbuf	*m4 = NULL;

	if (isDump(D_TRANSLATEIPV6))
		natpt_logIp6(LOG_DEBUG, cv6->ip.ip6, "%s():", fn);

	microtime(&atv);
	cv6->ats->tstamp = atv.tv_sec;

	switch (cv6->ip_p) {
	case IPPROTO_ICMPV6:
		if ((m4 = natpt_translateICMPv6To4(cv6, pad)) != NULL)
			natpt_revertICMPv6To4address(cv6, m4);
		break;

	case IPPROTO_TCP:
		m4 = natpt_translateTCPv6To4(cv6, pad);
		break;

	case IPPROTO_UDP:
		m4 = natpt_translateUDPv6To4(cv6, pad);
		break;

	default:
		bzero(&cv4, sizeof(struct pcv));
		if ((m4 = natpt_translateTCPUDPv6To4(cv6, pad, &cv4)) == NULL)
			return (NULL);
		break;
	}

	if (m4)
		natpt_adjustMBuf(cv6->m, m4);

	return (m4);
}


struct mbuf *
natpt_translateICMPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	cv4;
	struct mbuf	*m4;
	struct ip	*ip4;
	struct ip6_hdr	*ip6 = mtod(cv6->m, struct ip6_hdr *);
	struct icmp	*icmp4;
	struct icmp6_hdr *icmp6;

	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->pyld.icmp6;

	if ((m4 = natpt_mgethdr(sizeof(struct ip), icmp6len)) == NULL)
		return (NULL);

	cv4.m = m4;
	cv4.ip.ip4 = ip4 = mtod(m4, struct ip *);
	cv4.pyld.caddr = (caddr_t)cv4.ip.ip4 + sizeof(struct ip);
	cv4.fromto = cv6->fromto;

	natpt_composeIPv4Hdr(cv6, pad, ip4);

	icmp6 = cv6->pyld.icmp6;
	icmp4 = cv4.pyld.icmp4;
	bzero(icmp4, sizeof(struct icmp));

	switch (cv6->pyld.icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		natpt_icmp6DstUnreach(icmp6, icmp4);
		natpt_icmp6MimicPayload(cv6, &cv4, pad);
		break;

	case ICMP6_PACKET_TOO_BIG:
		icmp4->icmp_type = ICMP_UNREACH;
		icmp4->icmp_code = ICMP_UNREACH_NEEDFRAG;
		icmp4->icmp_nextmtu = ntohl(icmp6->icmp6_mtu) -
			(sizeof(struct ip6_hdr) - sizeof(struct ip));
		HTONS(icmp4->icmp_nextmtu);
		natpt_icmp6MimicPayload(cv6, &cv4, pad);
		break;

	case ICMP6_TIME_EXCEEDED:
		icmp4->icmp_type = ICMP_TIMXCEED;
		icmp4->icmp_code = icmp6->icmp6_code;	/* code unchanged */
		natpt_icmp6MimicPayload(cv6, &cv4, pad);
		break;

	case ICMP6_PARAM_PROB:
		icmp4->icmp_type = ICMP_PARAMPROB;
		if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER) {
			icmp4->icmp_type = ICMP_UNREACH;
			icmp4->icmp_code = ICMP_UNREACH_PROTOCOL;
		} else {
			HTONL(icmp6->icmp6_pptr);
			icmp4->icmp_pptr
				= (icmp6->icmp6_pptr == 0) ? 0	/* version */
				: (icmp6->icmp6_pptr == 4) ? 2	/* payload length */
				: (icmp6->icmp6_pptr == 6) ? 9	/* next header */
				: (icmp6->icmp6_pptr == 7) ? 8	/* ttl */
				: (icmp6->icmp6_pptr == 8) ? 12	/* source address */
				: (icmp6->icmp6_pptr == 24) ? 16 /* destination address */
				:  icmp6->icmp6_pptr -
					(sizeof(struct ip6_hdr) - sizeof(struct ip));
		}

		natpt_icmp6MimicPayload(cv6, &cv4, pad);
		break;

	case ICMP6_ECHO_REQUEST:
		icmp4->icmp_type = ICMP_ECHO;
		natpt_icmp6Informational(cv6, &cv4);
		break;

	case ICMP6_ECHO_REPLY:
		icmp4->icmp_type = ICMP_ECHOREPLY;
		natpt_icmp6Informational(cv6, &cv4);
		break;

	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
	case MLD_LISTENER_DONE:
		m_freem(m4);		/* Single hop message. Silently drop. */
		return (NULL);

	default:
		m_freem(m4);		/* Silently drop. */
		return (NULL);
	}

	if ((cv6->fh != NULL)
	    && (cv6->pyld.icmp6->icmp6_type != ICMP6_DST_UNREACH)
	    && (cv6->pyld.icmp6->icmp6_type != ICMP6_TIME_EXCEEDED)) {
		u_short		  cksum6, cksum4;
		struct ulc6	  ulc6;
		struct icmp6_hdr *icmp6hdr;
		struct icmp	  icmp4hdr;

		bzero(&ulc6, sizeof(struct ulc6));
		ulc6.ulc_src = cv6->ip.ip6->ip6_src;
		ulc6.ulc_dst = cv6->ip.ip6->ip6_dst;
		ulc6.ulc_len = htonl(cv6->plen);
		ulc6.ulc_pr  = cv6->ip_p;

		icmp6hdr = (struct icmp6_hdr *)&ulc6.ulc_tu.ih;
		bcopy(cv6->pyld.icmp6, icmp6hdr, sizeof(struct icmp6_hdr));
		bcopy(cv4.pyld.icmp4, &icmp4hdr, sizeof(struct icmp));
		cksum6 = ntohs(icmp6hdr->icmp6_cksum);
		icmp6hdr->icmp6_cksum = 0;
		icmp4hdr.icmp_cksum   = 0;

		cksum4 = natpt_fixCksum(cksum6,
					(u_char *)&ulc6, PSEUDOHDRSZ + ICMP_MINLEN,
					(u_char *)&icmp4hdr, ICMP_MINLEN);
		cv4.pyld.icmp4->icmp_cksum = htons(cksum4);
	} else {
		int		 hlen;
		struct mbuf	*m4  = cv4.m;
		struct ip	*ip4 = cv4.ip.ip4;
		struct icmp	*icmp4;

#ifdef _IP_VHL
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
		hlen = ip4->ip_hl << 2;
#endif
		m4->m_data += hlen;
		m4->m_len  -= hlen;
		icmp4 = cv4.pyld.icmp4;
		icmp4->icmp_cksum = 0;
		icmp4->icmp_cksum = in_cksum(cv4.m, ip4->ip_len - hlen);
		m4->m_data -= hlen;
		m4->m_len  += hlen;
	}

	return (m4);
}


void
natpt_icmp6DstUnreach(struct icmp6_hdr *icmp6, struct icmp *icmp4)
{
	icmp4->icmp_type = ICMP_UNREACH;
	icmp4->icmp_code = 0;

	switch (icmp6->icmp6_code) {
	case ICMP6_DST_UNREACH_NOROUTE:
		icmp4->icmp_code = ICMP_UNREACH_HOST;
		break;

	case ICMP6_DST_UNREACH_ADMIN:
		icmp4->icmp_code = ICMP_UNREACH_HOST_PROHIB;
		break;

	case ICMP6_DST_UNREACH_NOTNEIGHBOR:
		icmp4->icmp_code = ICMP_UNREACH_HOST;
		break;

	case ICMP6_DST_UNREACH_ADDR:
		icmp4->icmp_code = ICMP_UNREACH_HOST;
		break;

	case ICMP6_DST_UNREACH_NOPORT:
		icmp4->icmp_code = ICMP_UNREACH_PORT;
		break;
	}
}


void
natpt_icmp6Informational(struct pcv *cv6, struct pcv *cv4)
{
	int		 dlen;
	struct ip	*ip4 = cv4->ip.ip4;
	struct ip6_hdr	*ip6 = cv6->ip.ip6;
	caddr_t		 icmp6off, icmp4off;
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->pyld.icmp6;
	struct icmp	*icmp4 = cv4->pyld.icmp4;
	struct icmp6_hdr *icmp6 = cv6->pyld.icmp6;

	icmp4->icmp_code = 0;

#if 1
	if (icmp6->icmp6_type == ICMP6_ECHO_REQUEST) {
		cv6->ats->suit.ids[1] = icmp6->icmp6_data32[0];
		icmp4->icmp_void
			= cv6->ats->suit.ids[0]
			= icmp6->icmp6_data32[0];
	} else {
		icmp4->icmp_void = cv6->ats->suit.ids[1];
	}
#else
	icmp4->icmp_id	= icmp6->icmp6_id;
	icmp4->icmp_seq	= icmp6->icmp6_seq;
#endif

	dlen = icmp6len - sizeof(struct icmp6_hdr);
	icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
	icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
	bcopy(icmp6off, icmp4off, dlen);

	ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
}


void
natpt_icmp6MimicPayload(struct pcv *cv6, struct pcv *cv4, struct pAddr *pad)
{
	int		dgramlen;
	struct ip	*icmpip4, *ip4 = cv4->ip.ip4;
	struct ip6_hdr	*icmpip6, *ip6 = cv6->ip.ip6;
	struct icmp	*icmp4;
	struct icmp6_hdr	*icmp6;
	struct udphdr	*udp4, *udp6;
	caddr_t		ip6end;
	caddr_t		icmpip6pyld, icmpip4pyld;

	ip6end = (caddr_t)(ip6 + 1) + ntohs(ip6->ip6_plen);
	icmp6 = cv6->pyld.icmp6;
	icmpip6 = (struct ip6_hdr *)((caddr_t)icmp6 + sizeof(struct icmp6_hdr));
	icmpip6pyld = natpt_pyldaddr(icmpip6, ip6end, NULL, NULL);
	if (icmpip6pyld == NULL)
		return ;

	icmp4 = cv4->pyld.icmp4;
	icmpip4 = (struct ip *)((caddr_t)icmp4 + ICMP_MINLEN);
	icmpip4pyld = (caddr_t)icmpip4 + sizeof(struct ip);

	dgramlen = min(ip6end - icmpip6pyld, ICMP4_DGRAM);

	bzero(icmpip4, sizeof(struct ip));
	bcopy(icmpip6pyld, icmpip4pyld, dgramlen);

#ifdef _IP_VHL
	icmpip4->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof(struct ip) >> 2);
#else
	icmpip4->ip_v	= IPVERSION;
	icmpip4->ip_hl	= sizeof(struct ip) >> 2;
#endif
	icmpip4->ip_tos = 0;
	icmpip4->ip_len = htons(ntohs(icmpip6->ip6_plen) + sizeof(struct ip));
	icmpip4->ip_id	= 0;
	icmpip4->ip_off = 0;
	icmpip4->ip_off |= IP_DF;
	HTONS(icmpip4->ip_off);
	icmpip4->ip_ttl = icmpip6->ip6_hlim;
	icmpip4->ip_p	= icmpip6->ip6_nxt;
#if	0
	icmpip4->ip_src = pad->in4dst;
	icmpip4->ip_dst = pad->in4src;
#else
	icmpip4->ip_src = pad->in4src;
	icmpip4->ip_dst = pad->in4dst;
#endif

	{
		int		off = (caddr_t)icmpip4 - (caddr_t)cv4->m->m_data;
		struct mbuf	*m = cv4->m;

		m->m_data += off;
		m->m_pkthdr.len = m->m_len = sizeof(struct ip);
		icmpip4->ip_sum = in_cksum(m, sizeof(struct ip));
		m->m_data -= off;
	}

	ip4->ip_len = sizeof(struct ip) + ICMP_MINLEN + sizeof(struct ip) + dgramlen;
	cv4->m->m_pkthdr.len = cv4->m->m_len = ip4->ip_len;

	if ((icmpip6->ip6_nxt == IPPROTO_TCP)
	    || (icmpip6->ip6_nxt == IPPROTO_UDP)) {
		udp4 = (struct udphdr *)icmpip4pyld;
		if ((pad->port[1] != 0) || (pad->port[0] != 0)) {
			udp4->uh_sport = pad->port[0];
			udp4->uh_dport = pad->port[1];
		}
	}

	/* recalculate UDP checksum which is inside the ICMPv6 payload */
	if (icmpip6->ip6_nxt == IPPROTO_UDP) {
		u_short		cksum4, cksum6;
		struct ulc6	ulc6;
		struct ulc4	ulc4;

		bzero(&ulc6, sizeof(struct ulc6));
		bzero(&ulc4, sizeof(struct ulc4));

		udp6 = (struct udphdr *)icmpip6pyld;
		ulc6.ulc_src = icmpip6->ip6_src;
		ulc6.ulc_dst = icmpip6->ip6_dst;
		ulc6.ulc_len = htonl(ntohs(udp6->uh_ulen));
		ulc6.ulc_pr  = IPPROTO_UDP;

		udp4 = (struct udphdr *)icmpip4pyld;
		ulc4.ulc_src = icmpip4->ip_src;
		ulc4.ulc_dst = icmpip4->ip_dst;
		ulc4.ulc_len = udp4->uh_ulen;
		ulc4.ulc_pr  = IPPROTO_UDP;

		ulc6.ulc_tu.uh.uh_sport = udp6->uh_sport;
		ulc6.ulc_tu.uh.uh_dport = udp6->uh_dport;

		ulc4.ulc_tu.uh.uh_sport = udp4->uh_sport;
		ulc4.ulc_tu.uh.uh_dport = udp4->uh_dport;

		cksum6 = ntohs(udp6->uh_sum);
		cksum4 = natpt_fixCksum(cksum6,
				       (u_char *)&ulc6, sizeof(struct ulc6),
				       (u_char *)&ulc4, sizeof(struct ulc4));
		udp4->uh_sum = htons(cksum4);
	}
}


/*
 * Improve a destination address of IPv4 packet which is involved in
 * ICMPv4.  This facility is requested by <miyata@64translator.com>,
 * but I think this is an overkill or useless.
 */
void
natpt_revertICMPv6To4address(struct pcv *cv6, struct mbuf *m4)
{
	struct cSlot *csl;
	struct ip    *ip4;

	/* revert outermost IPv4 address */
	if ((csl = natpt_lookForRule6(cv6)) != NULL) {
		ip4 = mtod(m4, struct ip *);
		ip4->ip_src = csl->Remote.in4src;
	}

	/* revert innermost IPv4 address */
	if (cv6->flags & NATPT_noFootPrint) {
		struct ip	*icmpip4;
		struct ip6_hdr	*icmpip6;
		struct icmp	*icmp4;
		struct icmp6_hdr *icmp6;
		struct sockaddr_in	*sin4;
		struct sockaddr_in6	 sin6;

		icmp6 = cv6->pyld.icmp6;
		icmpip6 = (struct ip6_hdr *)((caddr_t)icmp6 + sizeof(struct icmp6_hdr));
		ip4 = mtod(m4, struct ip *);
		icmp4 = (struct icmp *)(ip4 + 1);
		icmpip4 = (struct ip *)((caddr_t)icmp4 + ICMP_MINLEN);

		bzero(&sin6, sizeof(struct sockaddr_in6));
		sin6.sin6_family = icmpip4->ip_p; /* divert to upper layer protocol */
		sin6.sin6_addr = icmpip6->ip6_dst;
		if ((sin4 = natpt_reverseLookForRule6(&sin6)) != NULL) {
			u_short		ip_sum;
			struct in_addr	ip_old, ip_new;

			ip_sum = icmpip4->ip_sum;
			ip_old = icmpip4->ip_dst;
			ip_new = sin4->sin_addr;
			icmpip4->ip_dst = sin4->sin_addr;
			icmpip4->ip_sum
				= natpt_fixCksum(htons(ip_sum),
					(u_char *)&ip_old, sizeof(struct in_addr),
					(u_char *)&ip_new, sizeof(struct in_addr));
			NTOHS(icmpip4->ip_sum);

			if (icmpip4->ip_p == IPPROTO_UDP) {
				u_short		 uh_sum;
				struct udphdr	*icmpudp4;

				icmpudp4 = (struct udphdr *)(icmpip4 + 1);
				uh_sum = icmpudp4->uh_sum;
				icmpudp4->uh_sum
					= natpt_fixCksum(htons(uh_sum),
						(u_char *)&ip_old, sizeof(struct in_addr),
						(u_char *)&ip_new, sizeof(struct in_addr));
				NTOHS(icmpudp4->uh_sum);
			}

			/*
			 * We must re-calculate ICMP chekcsum because
			 * ICMP payload was changed.
			 */
			{
				int	hlen;

#ifdef _IP_VHL
				hlen = IP_VHL_HL(ip4->ip_vhl) << 2;
#else
				hlen = ip4->ip_hl << 2;
#endif
				m4->m_data += hlen;
				m4->m_len  -= hlen;
				icmp4->icmp_cksum = 0;
				icmp4->icmp_cksum = in_cksum(m4, ip4->ip_len - hlen);
				m4->m_data -= hlen;
				m4->m_len  += hlen;
			}
		}
	}
}


struct mbuf *
natpt_translateTCPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	cv4;
	struct mbuf	*m4;
	u_short		 ports[2];

	ports[0] = cv6->pyld.tcp6->th_sport;
	ports[1] = cv6->pyld.tcp6->th_dport;

	bzero(&cv4, sizeof(struct pcv));
	if ((m4 = natpt_translateTCPUDPv6To4(cv6, pad, &cv4)) == NULL)
		return (NULL);

	cv4.ip_p = IPPROTO_TCP;
	natpt_updateTcpStatus(&cv4);
	natpt_translatePYLD(&cv4, ports);
	if (cv4.ats->suit.tcps
	    && (cv4.ats->suit.tcps->rewrite[cv4.fromto] == 0)) {
		/* payload unchanged */
		natpt_fixTCPUDP64cksum(AF_INET6, IPPROTO_TCP, cv6, &cv4);
	} else {
		int		  hlen, dlen, tcplen;
		struct mbuf	 *m4 = cv4.m;
		struct pseudohdr *ph;
		struct tcp6hdr	 *tcp4 = cv4.pyld.tcp4;
		char		  savedip[64];

#ifdef _IP_VHL
		hlen = IP_VHL_HL(cv4.ip.ip4->ip_vhl) << 2;
#else
		hlen = cv4.ip.ip4->ip_hl << 2;
#endif

		tcplen = cv4.ip.ip4->ip_len - hlen;
		bcopy(cv4.ip.ip4, &savedip, hlen);
		dlen = hlen - sizeof(struct pseudohdr);
		m4->m_data += dlen;
		m4->m_len  -= dlen;

		ph = (struct pseudohdr *)m4->m_data;
		ph->ip_src = ((struct ip *)&savedip)->ip_src;
		ph->ip_dst = ((struct ip *)&savedip)->ip_dst;
		ph->ip_p   = htons(((struct ip *)&savedip)->ip_p);
		ph->ip_len = htons(tcplen);

		tcp4->th_sum = 0;
		tcp4->th_sum = in_cksum(m4, tcplen + sizeof(struct pseudohdr));
		m4->m_data -= dlen;
		m4->m_len  += dlen;
		bcopy(&savedip, cv4.ip.ip4, hlen);
	}

	return (m4);
}


struct mbuf *
natpt_translateUDPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	cv4;
	struct mbuf	*m4;

	bzero(&cv4, sizeof(struct pcv));
	if ((m4 = natpt_translateTCPUDPv6To4(cv6, pad, &cv4)) == NULL)
		return (NULL);

	cv4.ip_p = IPPROTO_UDP;
	natpt_watchUDP6(&cv4);
	if (udpcksum) {
		natpt_fixTCPUDP64cksum(AF_INET6, IPPROTO_UDP, cv6, &cv4);
	} else {
		cv4.pyld.udp->uh_sum = 0;
	}

	return (m4);
}


struct mbuf *
natpt_translateTCPUDPv6To4(struct pcv *cv6, struct pAddr *pad, struct pcv *cv4)
{
	struct mbuf	*m4;
	struct ip	*ip4;
	struct ip6_hdr	*ip6;
	struct tcphdr	*th;

	static struct pcvaux	aux;
	static struct ulc6	ulc;

	if ((m4 = m_copym(cv6->m, 0, M_COPYALL, M_NOWAIT)) == NULL) {
		return (NULL);
	}

	/*
	 * There is a case pointing the same data with m4 and cv6->m
	 * after m_copym, we need to prepare for incremental checksum
	 * calculation.
	 */
	bzero(&aux, sizeof(struct pcvaux));
	bzero(&ulc, sizeof(struct ulc6));

	ulc.ulc_src = cv6->ip.ip6->ip6_src;
	ulc.ulc_dst = cv6->ip.ip6->ip6_dst;
	ulc.ulc_len = htonl(cv6->plen);
	ulc.ulc_pr  = cv6->ip_p;
	if (cv6->ip_p == IPPROTO_TCP) {
		ulc.ulc_tu.th.th_sport = cv6->pyld.tcp6->th_sport;
		ulc.ulc_tu.th.th_dport = cv6->pyld.tcp6->th_dport;
		aux.cksum6 = ntohs(cv6->pyld.tcp6->th_sum);
	} else if (cv6->ip_p == IPPROTO_UDP) {
		ulc.ulc_tu.uh.uh_sport = cv6->pyld.udp->uh_sport;
		ulc.ulc_tu.uh.uh_dport = cv6->pyld.udp->uh_dport;
		aux.cksum6 = ntohs(cv6->pyld.udp->uh_sum);
	}

	aux.ulc6 = &ulc;
	cv6->aux = &aux;

	/*
	 * Start translation
	 */
    {
	int	diff;

	diff = htons(cv6->ip.ip6->ip6_plen) + sizeof(struct ip6_hdr) -
		(cv6->plen + sizeof(struct ip));
	m4->m_data += diff;
	m4->m_len  -= diff;
	m4->m_pkthdr.len -= diff;
    }

	cv4->sa_family = AF_INET;
	cv4->m = m4;
	cv4->plen = cv6->plen;
	cv4->poff = sizeof(struct ip);
	cv4->ip.ip4 = mtod(m4, struct ip *);
	cv4->pyld.caddr = (caddr_t)cv4->ip.ip4 + sizeof(struct ip);

	cv4->ats = cv6->ats;
	cv4->fromto = cv6->fromto;

	ip4 = mtod(m4, struct ip *);
	ip6 = mtod(cv6->m, struct ip6_hdr *);
	natpt_composeIPv4Hdr(cv6, pad, ip4);

	if ((cv6->ip_p == IPPROTO_TCP)
	    || (cv6->ip_p == IPPROTO_UDP)) {
	    th = (struct tcphdr *)(ip4 + 1);
	    th->th_sport = pad->port[1];
	    th->th_dport = pad->port[0];
	}

	return (m4);
}


void
natpt_watchUDP6(struct pcv *cv4)
{
	struct cSlot	*cst;

	if (cv4->fromto == NATPT_TO)
		return ;

	if (htons(cv4->pyld.udp->uh_dport) == TFTP) {
		MALLOC(cst, struct cSlot *, sizeof(struct cSlot), M_NATPT, M_NOWAIT);
		bzero(cst, sizeof(struct cSlot));
		cst->proto = NATPT_UDP;
		cst->map   = NATPT_REDIRECT_PORT;
		cst->lifetime = 32;

		cst->Local.sa_family = AF_INET;
		cst->Local.in4Addr = cv4->ats->remote.in4src;
		cst->local.dport   = cv4->ats->remote.port[1];
		cst->Local.aType   = ADDR_SINGLE;

		cst->Remote.sa_family = AF_INET6;
		cst->Remote.in6Addr = cv4->ats->local.in6src;
		cst->remote.dport   = cv4->ats->local.port[0];
		cst->Remote.aType   = ADDR_SINGLE;

		natpt_prependRule(cst);
	}
}


struct mbuf *
natpt_translateFragment6(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	cv4;
	struct mbuf	*m4;
	struct ip	*ip4;
	struct ip6_hdr	*ip6 = mtod(cv6->m, struct ip6_hdr *);

	caddr_t		frag6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		frag6len = frag6end - cv6->pyld.caddr;

	bzero(&cv4, sizeof(struct pcv));
	if ((m4 = natpt_mgethdr(sizeof(struct ip), frag6len)) == NULL)
		return (NULL);

	cv4.m = m4;
	cv4.ip.ip4 = ip4 = mtod(m4, struct ip *);
	cv4.pyld.caddr = (caddr_t)cv4.ip.ip4 + sizeof(struct ip);
	cv4.fromto = cv6->fromto;

	natpt_composeIPv4Hdr(cv6, pad, ip4);

	bcopy(cv6->pyld.caddr, cv4.pyld.caddr, frag6len);
	cv4.m->m_len = ip4->ip_len;

	if (m4)
		natpt_adjustMBuf(cv6->m, m4);

	return (m4);
}


/*
 *	Translate from IPv4 to IPv6
 */

struct mbuf *
natpt_translateIPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	const char	*fn = __FUNCTION__;

	struct pcv	cv6;
	struct timeval	atv;
	struct mbuf	*m6 = NULL;

	if (isDump(D_TRANSLATEIPV4))
		natpt_logIp4(LOG_DEBUG, cv4->ip.ip4, "%s():", fn);

	microtime(&atv);
	cv4->ats->tstamp = atv.tv_sec;

	switch (cv4->ip_p) {
	case IPPROTO_ICMP:
		m6 = natpt_translateICMPv4To6(cv4, pad);
		break;

	case IPPROTO_TCP:
		m6 = natpt_translateTCPv4To6(cv4, pad);
		break;

	case IPPROTO_UDP:
		m6 = natpt_translateUDPv4To6(cv4, pad);
		break;

	default:
		bzero(&cv6, sizeof(struct pcv));
		if ((m6 = natpt_translateTCPUDPv4To6(cv4, pad, &cv6)) == NULL)
			return (NULL);
		break;
	}

	if (m6)
		m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;

	return (m6);
}


struct mbuf *
natpt_translateICMPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	struct pcv	cv6;
	struct pAddr	pad0;
	struct mbuf	*m6;
	struct ip	*ip4 = mtod(cv4->m, struct ip *);
	struct ip6_hdr	*ip6;
	struct ip6_frag	*frag6;
	struct icmp	*icmp4;
	struct icmp6_hdr *icmp6;

	caddr_t		icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;
	int		icmp6len = 0;

	if ((m6 = natpt_mgethdr(sizeof(struct ip6_hdr), icmp4len)) == NULL)
		return (NULL);

	cv6.m = m6;
	cv6.ip.ip6 = ip6 = mtod(m6, struct ip6_hdr *);
	cv6.pyld.caddr = (caddr_t)cv6.ip.ip6 + sizeof(struct ip6_hdr);
	cv6.fromto = cv4->fromto;
	cv6.flags  = cv4->flags;

	/*
	 * Translated IPv6 source address has IPv4 source address with
	 * 96-bit NAT-PT prefix.
	 */
	bzero(&pad0, sizeof(struct pAddr));
	pad0.in6src = pad->in6src;
	pad0.in6dst = natpt_prefix;
	pad0.in6dst.s6_addr32[3] = ip4->ip_src.s_addr;
	if ((frag6 = natpt_composeIPv6Hdr(cv4, &pad0, ip6)) != NULL)
		cv6.pyld.caddr += sizeof(struct ip6_frag);

	icmp4 = cv4->pyld.icmp4;
	icmp6 = cv6.pyld.icmp6;
	bzero(icmp6, sizeof(struct icmp6_hdr));

	switch (cv4->pyld.icmp4->icmp_type) {
	case ICMP_ECHOREPLY:
		icmp6->icmp6_type = ICMP6_ECHO_REPLY;
		icmp6len = natpt_icmp4Informational(cv4, &cv6);
		if (frag6 && needFragment(cv4)) {
			cv6.fh = frag6;
			natpt_translatePing4to66(cv4, &cv6, icmp6len);
			return (NULL);
		}
		break;

	case ICMP_UNREACH:
		natpt_icmp4Unreach(icmp4, icmp6);
		icmp6len = natpt_icmp4MimicPayload(cv4, &cv6, pad);
		break;

	case ICMP_ECHO:
		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6len = natpt_icmp4Informational(cv4, &cv6);
		if (frag6 && needFragment(cv4)) {
			cv6.fh = frag6;
			natpt_translatePing4to66(cv4, &cv6, icmp6len);
			return (NULL);
		}
		break;

	case ICMP_TIMXCEED:
		icmp6 = cv6.pyld.icmp6;
		icmp6->icmp6_type = ICMP6_TIME_EXCEEDED;
		icmp6->icmp6_code = cv4->pyld.icmp4->icmp_code;
		icmp6len = natpt_icmp4MimicPayload(cv4, &cv6, pad);
		break;

	case ICMP_PARAMPROB:
		icmp6 = cv6.pyld.icmp6;
		icmp6->icmp6_type = ICMP6_PARAM_PROB;
		icmp6->icmp6_code = 0;
		icmp6len = natpt_icmp4MimicPayload(cv4, &cv6, pad);
		break;

	case ICMP_REDIRECT:
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
		m_freem(m6);	/* Single hop message. Silently drop */
		return (NULL);

	case ICMP_SOURCEQUENCH:
	case ICMP_TSTAMP:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQ:
	case ICMP_IREQREPLY:
	case ICMP_MASKREQ:
	case ICMP_MASKREPLY:
		m_freem(m6);	/* Obsoleted in ICMPv6. Silently drop */
		return (NULL);

	default:
		m_freem(m6);	/* Silently drop */
		return (NULL);
	}

	{
		int		hdrsz = 0;
		u_int32_t	off = sizeof(struct ip6_hdr);
		u_int32_t	len = sizeof(struct icmp6_hdr) + icmp6len;
		struct icmp6_hdr *icmp6 = cv6.pyld.icmp6;

		if (frag6) {
			hdrsz += sizeof(struct ip6_frag);
			off   += sizeof(struct ip6_frag);
		}

		ip6->ip6_plen = hdrsz + len;
		cv6.m->m_pkthdr.len
			= cv6.m->m_len
			= sizeof(struct ip6_hdr) + ip6->ip6_plen;

		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_cksum = in6_cksum(cv6.m, IPPROTO_ICMPV6, off, len);
	}

	HTONS(ip6->ip6_plen);
	return (m6);
}


int
natpt_icmp4Informational(struct pcv *cv4, struct pcv *cv6)
{
	int		dlen;
	struct ip	*ip4 = cv4->ip.ip4;
	caddr_t		icmp4off, icmp6off;
	caddr_t		icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;
	struct icmp	*icmp4 = cv4->pyld.icmp4;
	struct icmp6_hdr *icmp6 = cv6->pyld.icmp6;

	icmp6->icmp6_code = 0;

#if 1
	if (icmp4->icmp_type == ICMP_ECHO) {
		cv4->ats->suit.ids[1] = icmp4->icmp_void;
		icmp6->icmp6_data32[0]
			= cv4->ats->suit.ids[0]
			= icmp4->icmp_void;
	} else {
		icmp6->icmp6_data32[0] = cv4->ats->suit.ids[1];
	}
#else
	icmp6->icmp6_id	 = icmp4->icmp_id;
	icmp6->icmp6_seq = icmp4->icmp_seq;
#endif

	dlen = icmp4len - ICMP_MINLEN;
	icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
	icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
	bcopy(icmp4off, icmp6off, dlen);

	return (dlen);
}


void
natpt_icmp4Unreach(struct icmp *icmp4, struct icmp6_hdr *icmp6)
{
	icmp6->icmp6_type = ICMP6_DST_UNREACH;
	icmp6->icmp6_code = 0;

	switch (icmp4->icmp_code) {
	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case ICMP_UNREACH_PROTOCOL:
		icmp6->icmp6_type = ICMP6_PARAM_PROB;
		icmp6->icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;
		icmp6->icmp6_pptr = htonl(6);	/* point to the IPv6 Next Header field. */
		break;

	case ICMP_UNREACH_PORT:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT;
		break;

	case ICMP_UNREACH_NEEDFRAG:
		icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;
		icmp6->icmp6_code = 0;
		if (icmp4->icmp_nextmtu == 0)
			icmp6->icmp6_mtu = IPV6_MMTU;	/* xxx */
		else
			icmp6->icmp6_mtu =
				min(ETHERMTU,
				    ntohs(icmp4->icmp_nextmtu) +
				    (sizeof(struct ip6_hdr) - sizeof(struct ip)));
		HTONL(icmp6->icmp6_mtu);
		break;

	case ICMP_UNREACH_SRCFAIL:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case ICMP_UNREACH_NET_UNKNOWN:
	case ICMP_UNREACH_HOST_UNKNOWN:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case ICMP_UNREACH_ISOLATED:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case ICMP_UNREACH_NET_PROHIB:
	case ICMP_UNREACH_HOST_PROHIB:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_ADMIN;
		break;

	case ICMP_UNREACH_TOSNET:
	case ICMP_UNREACH_TOSHOST:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	default:
		break;
	}
}


int
natpt_icmp4MimicPayload(struct pcv *cv4, struct pcv *cv6, struct pAddr *pad)
{
	int		dgramlen;
	int		icmp6rest;
	struct ip	*icmpip4, *ip4 = cv4->ip.ip4;
	struct ip6_hdr	*icmpip6;
	struct icmp	*icmp4;
	struct icmp6_hdr *icmp6;
	caddr_t		icmp4off, icmp4dgramoff;
	caddr_t		icmp6off, icmp6dgramoff;
	caddr_t		icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;

	icmp6rest = MHLEN - sizeof(struct ip6_hdr) * 2 - sizeof(struct icmp6_hdr);
	dgramlen  = icmp4len - ICMP_MINLEN - sizeof(struct ip);
	dgramlen  = min(icmp6rest, dgramlen);

	icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
	icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
	icmp4dgramoff = icmp4off + sizeof(struct ip);
	icmp6dgramoff = icmp6off + sizeof(struct ip6_hdr);

	icmpip4 = (struct ip *)icmp4off;
	icmpip6 = (struct ip6_hdr *)icmp6off;
	bzero(icmpip6, sizeof(struct ip6_hdr));
	bcopy(icmp4dgramoff, icmp6dgramoff, dgramlen);

	icmpip6->ip6_flow = 0;
	icmpip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	icmpip6->ip6_vfc |=  IPV6_VERSION;
	icmpip6->ip6_plen = htons(ntohs(icmpip4->ip_len) - sizeof(struct ip));
	icmpip6->ip6_nxt  = icmpip4->ip_p;
	icmpip6->ip6_hlim = icmpip4->ip_ttl;

#if	0
	icmpip6->ip6_src  = pad->in6dst;
	icmpip6->ip6_dst  = pad->in6src;
#else
	if (cv4->flags & NATPT_noFootPrint) {
		struct in6_addr	in6addr;

		in6addr = natpt_prefix;

		in6addr.s6_addr32[3] = icmpip4->ip_src.s_addr;
		icmpip6->ip6_src = in6addr;
		in6addr.s6_addr32[3] = icmpip4->ip_dst.s_addr;
		icmpip6->ip6_dst = in6addr;
	} else {
		icmpip6->ip6_src  = pad->in6src;
		icmpip6->ip6_dst  = pad->in6dst;
	}

#endif

	switch (cv4->pyld.icmp4->icmp_type) {
	case ICMP_ECHO:	/* ping unreach */
		icmp6 = (struct icmp6_hdr *)((caddr_t)icmpip6 +
					     sizeof(struct ip6_hdr));
		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		break;

	case ICMP_PARAMPROB:
		icmp4 = cv4->pyld.icmp4;
		icmp6 = cv6->pyld.icmp6;
		icmp6->icmp6_pptr
			= (icmp4->icmp_pptr == 0) ? 0	/* version */
			: (icmp4->icmp_pptr == 2) ? 4	/* payload length */
			: (icmp4->icmp_pptr == 8) ? 7	/* hop limit */
			: (icmp4->icmp_pptr == 9) ? 6	/* next header */
			: (icmp4->icmp_pptr == 12) ? 8	/* source address */
			: (icmp4->icmp_pptr == 16) ? 24 /* destination address */
			:  icmp4->icmp_pptr +
				(sizeof(struct ip6_hdr) - sizeof(struct ip));

		HTONL(icmp6->icmp6_pptr);
		/* FALLTHROUGH */

	case ICMP_UNREACH:
	case ICMP_TIMXCEED:
		if ((cv4->flags & NATPT_noFootPrint) == 0) {
			struct udphdr	*icmpudp6;

			icmpudp6 = (struct udphdr *)((caddr_t)icmpip6 +
						     sizeof(struct ip6_hdr));
			icmpudp6->uh_sport = pad->port[0];
			icmpudp6->uh_dport = pad->port[1];
		}
		break;
	}

	/* recalculate TCP/UDP checksum which is inside the ICMPv6 payload. */
	if ((icmpip4->ip_p == IPPROTO_TCP)
	    || (icmpip4->ip_p == IPPROTO_UDP)) {
		int		hlen;
		u_short		in4_cksum, in6_cksum;
		caddr_t		icmpulp4, icmpulp6;
		struct ulc4	ulc4;
		struct ulc6	ulc6;

#ifdef _IP_VHL
		hlen = IP_VHL_HL(icmpip4->ip_vhl) << 2;
#else
		hlen = icmpip4->ip_hl << 2;
#endif
		icmpulp4 = (caddr_t)icmpip4 + hlen;
		icmpulp6 = (caddr_t)icmpip6 + sizeof(struct ip6_hdr);

		bzero(&ulc4, sizeof(struct ulc4));
		bzero(&ulc6, sizeof(struct ulc6));

		ulc4.ulc_src = icmpip4->ip_src;
		ulc4.ulc_dst = icmpip4->ip_dst;
		ulc6.ulc_src = icmpip6->ip6_src;
		ulc6.ulc_dst = icmpip6->ip6_dst;

		ulc4.ulc_tu.uh.uh_sport = ((struct udphdr *)icmpulp4)->uh_sport;
		ulc4.ulc_tu.uh.uh_dport = ((struct udphdr *)icmpulp4)->uh_dport;
		ulc6.ulc_tu.uh.uh_sport = ((struct udphdr *)icmpulp6)->uh_sport;
		ulc6.ulc_tu.uh.uh_dport = ((struct udphdr *)icmpulp6)->uh_dport;

		if (icmpip4->ip_p == IPPROTO_TCP) {
			in4_cksum = ntohs(((struct tcphdr *)icmpulp4)->th_sum);
		} else {
			in4_cksum = ntohs(((struct udphdr *)icmpulp4)->uh_sum);
		}
		in6_cksum = natpt_fixCksum(in4_cksum,
					   (u_char *)&ulc4, sizeof(struct ulc4),
					   (u_char *)&ulc6, sizeof(struct ulc6));
		if (icmpip4->ip_p == IPPROTO_TCP) {
			((struct tcphdr *)icmpulp6)->th_sum = htons(in6_cksum);
		} else {
			((struct udphdr *)icmpulp6)->uh_sum = htons(in6_cksum);
		}
	}

	return (sizeof(struct ip6_hdr) + dgramlen);
}


void
natpt_translatePing4to66(struct pcv *cv4, struct pcv *cv6, int icmp6len)
{
	u_short		 cksum6, cksum4, typecode4;
	struct ulc6	 ulc6;
	struct ip6_hdr	 ip6save;
	struct ip6_frag	 frg6save;
	struct icmp	*icmp4;
	struct icmp6_hdr *icmp6;

	icmp4 = cv4->pyld.icmp4;
	icmp6 = cv6->pyld.icmp6;
	icmp6->icmp6_id	 = icmp4->icmp_id;
	icmp6->icmp6_seq = icmp4->icmp_seq;

	typecode4 = htons((icmp4->icmp_type << 8) + icmp4->icmp_code);
	bzero(&ulc6, sizeof(struct ulc6));
	ulc6.ulc_src = cv6->ip.ip6->ip6_src;
	ulc6.ulc_dst = cv6->ip.ip6->ip6_dst;
	ulc6.ulc_len = htonl(cv4->plen);
	ulc6.ulc_pr  = IPPROTO_ICMPV6;
	ulc6.ulc_tu.ih.icmp6_type = icmp6->icmp6_type;
	ulc6.ulc_tu.ih.icmp6_code = icmp6->icmp6_code;

	cksum4 = icmp4->icmp_cksum;
	cksum6 = natpt_fixCksum(ntohs(cksum4),
				(u_char *)&typecode4, sizeof(typecode4),
				(u_char *)&ulc6,      sizeof(struct ulc6));
	icmp6->icmp6_cksum = htons(cksum6);

	ip6save = *cv6->ip.ip6;
	frg6save = *cv6->fh;
	cv6->m->m_pkthdr.len = cv6->m->m_len = IPV6_MMTU;
	cv6->m->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;
	natpt_ip6_forward(cv6->m);		/* send first fragmented packet */

	/*
	 * Then, send second fragmented v6 packet.
	 */
	natpt_sendFragmentedTail(cv4, &ip6save, &frg6save);
}


struct mbuf *
natpt_translateTCPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	struct pcv	cv6;
	struct mbuf	*m6;
	u_short		 ports[2];

	ports[0] = cv4->pyld.tcp4->th_sport;
	ports[1] = cv4->pyld.tcp4->th_dport;

	bzero(&cv6, sizeof(struct pcv));
	if ((m6 = natpt_translateTCPUDPv4To6(cv4, pad, &cv6)) == NULL)
		return (NULL);

	cv6.ip_p = IPPROTO_TCP;
	natpt_updateTcpStatus(cv4);
	natpt_translatePYLD(&cv6, ports);
	if (cv6.ats->suit.tcps
	    && (cv6.ats->suit.tcps->rewrite[cv6.fromto] == 0)) {
		/* payload unchanged */
		natpt_fixTCPUDP64cksum(AF_INET, IPPROTO_TCP, &cv6, cv4);
	} else {
		/*
		 * TCP payload was changed.  So we must re-calculate
		 * TCP checksum.
		 */
		int		 plen;
		caddr_t		 ip6;
		caddr_t		 bp, ep;
		struct tcp6hdr	*th;

		ip6 = mtod(cv6.m, caddr_t);
		plen = ntohs(((struct ip6_hdr *)ip6)->ip6_plen);
		bp = (caddr_t)cv6.pyld.tcp6;
		ep = ip6 + sizeof(struct ip6_hdr) + plen;

		th = cv6.pyld.tcp6;
		th->th_sum = 0;
		th->th_sum = in6_cksum(cv6.m, IPPROTO_TCP, bp - ip6, ep - bp);
	}

	return (m6);
}


struct mbuf *
natpt_translateUDPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	struct pcv	cv6;
	struct mbuf	*m6;
	struct udphdr	*udp4 = cv4->pyld.udp;

	if ((udp4->uh_sum == 0)
	    || (udp4->uh_sum == 65535)) {
		int		 hlen, dlen;
		struct mbuf	*m4 = cv4->m;
		struct pseudohdr *ph;
		char		 savedip[64];

		if (isFragment(cv4))
			return (NULL);	/* drop this packet */

#ifdef _IP_VHL
		hlen = IP_VHL_HL(cv4->ip.ip4->ip_vhl) << 2;
#else
		hlen = cv4->ip.ip4->ip_hl << 2;
#endif

		bcopy(cv4->ip.ip4, &savedip, hlen);
		dlen = hlen - sizeof(struct pseudohdr);
		m4->m_data += dlen;
		m4->m_len  -= dlen;

		ph = (struct pseudohdr *)m4->m_data;
		ph->ip_src = ((struct ip *)&savedip)->ip_src;
		ph->ip_dst = ((struct ip *)&savedip)->ip_dst;
		ph->ip_p   = htons(((struct ip *)&savedip)->ip_p);
		ph->ip_len = udp4->uh_ulen;

		udp4->uh_sum = 0;
		udp4->uh_sum = in_cksum(cv4->m,
					ntohs(ph->ip_len) + sizeof(struct pseudohdr));
		m4->m_data -= dlen;
		m4->m_len  += dlen;
		bcopy(&savedip, cv4->ip.ip4, hlen);
	}

	bzero(&cv6, sizeof(struct pcv));
	if ((m6 = natpt_translateTCPUDPv4To6(cv4, pad, &cv6)) == NULL)
		return (NULL);

	cv6.ip_p = IPPROTO_UDP;
	natpt_fixTCPUDP64cksum(AF_INET, IPPROTO_UDP, &cv6, cv4);
	return (m6);
}


struct mbuf *
natpt_translateTCPUDPv4To6(struct pcv *cv4, struct pAddr *pad, struct pcv *cv6)
{
	struct mbuf	*m6;
	struct ip6_hdr	*ip6;
	int		hdrsz;

	/*
	 * Drop the fragmented packet which does not have enough
	 * header.
	 */
	hdrsz = sizeof(struct udphdr);
	if (cv4->ip_p == IPPROTO_TCP)
		hdrsz = sizeof(struct tcphdr);	/* ignore tcp option */
	if (isFragment(cv4) && cv4->plen < hdrsz)	/* do we need this? */
		return (NULL);

	/*
	 * If this packet needs fragmentation, handle it with the
	 * other routine.
	 */
	if (needFragment(cv4)) {
		natpt_translateFragment4to66(cv4, pad);
		return (NULL);
	}

	/*
	 * Start real work.
	 */
	hdrsz = sizeof(struct ip6_hdr);
	if (isFragment(cv4) || isNoDF(cv4))
		hdrsz += sizeof(struct ip6_frag);
	if ((m6 = natpt_mgethdr(hdrsz, cv4->plen)) == NULL)
		return (NULL);

	bzero(cv6, sizeof(struct pcv));
	cv6->sa_family = AF_INET6;
	cv6->m = m6;
	cv6->ip.ip6 = ip6 = mtod(m6, struct ip6_hdr *);
	cv6->pyld.caddr = (caddr_t)(ip6 + 1);
	cv6->plen = cv4->plen;
	cv6->poff = cv6->pyld.caddr - (caddr_t)cv6->ip.ip6;
	cv6->ats = cv4->ats;
	cv6->fromto = cv4->fromto;

	ip6->ip6_plen = cv4->plen;
	ip6->ip6_nxt  = IPPROTO_TCP;

	if ((cv6->fh = natpt_composeIPv6Hdr(cv4, pad, ip6)) != NULL)
		cv6->pyld.caddr += sizeof(struct ip6_frag);

	bcopy(cv4->pyld.caddr, cv6->pyld.caddr, cv4->plen);
	if ((cv4->ip_p == IPPROTO_TCP)
	    || (cv4->ip_p == IPPROTO_UDP)) {
		cv6->pyld.tcp6->th_sport = pad->port[1];
		cv6->pyld.tcp6->th_dport = pad->port[0];
	}

	m6->m_pkthdr.len = m6->m_len = hdrsz + cv4->plen;
	return (m6);
}


struct mbuf *
natpt_translateFragment4to6(struct pcv *cv4, struct pAddr *pad)
{
	struct mbuf	*m6;
	struct ip6_hdr	*ip6;
	caddr_t		pyld6;

	if (NATPT_FRGHDRSZ + cv4->plen > IPV6_MMTU) {
		natpt_translateFragment4to66(cv4, pad);
		return (NULL);
	}

	if ((m6 = natpt_mgethdr(NATPT_FRGHDRSZ, cv4->plen)) == NULL)
		return (NULL);

	ip6 = mtod(m6, struct ip6_hdr *);
	pyld6 = (caddr_t)(ip6 + 1);
	if (natpt_composeIPv6Hdr(cv4, pad, ip6) != NULL)
		pyld6 += sizeof(struct ip6_frag);

	bcopy(cv4->pyld.caddr, pyld6, cv4->plen);
	m6->m_pkthdr.len = m6->m_len = NATPT_FRGHDRSZ + cv4->plen;
	m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;

	return (m6);
}


void
natpt_translateFragment4to66(struct pcv *cv4, struct pAddr *pad)
{
	struct mbuf	*m6;
	struct ip	*ip4 = mtod(cv4->m, struct ip *);
	struct ip6_hdr	*ip6,  ip6save;
	struct ip6_frag	*frg6, frg6save;
	caddr_t		pyld4 = cv4->pyld.caddr;
	caddr_t		pyld6;

	/*
	 * Form 2 fragmented v6 packet because size of v6 packet after
	 * v4->v6 translation exceeds IPV6_MMTU (1280 bytes).  This
	 * two v6 packet is sent from this routine by calling
	 * ip6_forward() directly.
	 */

	if ((m6 =natpt_mgethdr(0, IPV6_MMTU)) == NULL)
		return ;

	ip6 = mtod(m6, struct ip6_hdr *);
	pyld6 = (caddr_t)(ip6 + 1);
	frg6 = NULL;
	if ((frg6 = natpt_composeIPv6Hdr(cv4, pad, ip6)) != NULL)
		pyld6 += sizeof(struct ip6_frag);
	bcopy(cv4->pyld.caddr, pyld6, NATPT_MAXULP);

	/*
	 * Renewal of port number and change of checksum.
	 */
	if (isZeroOffset(cv4)
	    && ((cv4->ip_p == IPPROTO_TCP)
		|| (cv4->ip_p == IPPROTO_UDP))) {
		u_short		 cksum4, cksum6;
		struct ulc4	 ulc4;
		struct ulc6	 ulc6;

		((struct tcp6hdr *)pyld6)->th_sport = pad->port[1];
		((struct tcp6hdr *)pyld6)->th_dport = pad->port[0];

		bzero(&ulc4, sizeof(struct ulc4));
		ulc4.ulc_src = ip4->ip_src;
		ulc4.ulc_dst = ip4->ip_dst;
		ulc4.ulc_tu.th.th_sport = ((struct tcphdr *)pyld4)->th_sport;
		ulc4.ulc_tu.th.th_dport = ((struct tcphdr *)pyld4)->th_dport;

		bzero(&ulc6, sizeof(struct ulc6));
		ulc6.ulc_src = ip6->ip6_src;
		ulc6.ulc_dst = ip6->ip6_dst;
		ulc6.ulc_tu.th.th_sport = ((struct tcp6hdr *)pyld6)->th_sport;
		ulc6.ulc_tu.th.th_dport = ((struct tcp6hdr *)pyld6)->th_dport;

		if (cv4->ip_p == IPPROTO_TCP) {
			cksum4 = ((struct tcphdr *)pyld4)->th_sum;
			cksum6 = natpt_fixCksum(ntohs(cksum4),
						(u_char *)&ulc4, sizeof(struct ulc4),
						(u_char *)&ulc6, sizeof(struct ulc6));
			((struct tcp6hdr *)pyld6)->th_sum = htons(cksum6);
			natpt_updateTcpStatus(cv4);
		} else {
			cksum4 = ((struct udphdr *)pyld4)->uh_sum;
			cksum6 = natpt_fixCksum(ntohs(cksum4),
						(u_char *)&ulc4, sizeof(struct ulc4),
						(u_char *)&ulc6, sizeof(struct ulc6));
			((struct udphdr *)pyld6)->uh_sum = htons(cksum6);
		}
	}

	ip6save = *ip6;
	frg6save = *frg6;
	m6->m_pkthdr.len = m6->m_len = IPV6_MMTU;
	m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;
	natpt_ip6_forward(m6);		/* send first fragmented packet */

	/*
	 * Then, send second fragmented v6 packet.
	 */
	natpt_sendFragmentedTail(cv4, &ip6save, &frg6save);
}


void
natpt_sendFragmentedTail(struct pcv *cv4, struct ip6_hdr *ip6save, struct ip6_frag *fh6save)
{
	int		 offset, plen;
	struct mbuf	*m6;
	struct ip	*ip4 = mtod(cv4->m, struct ip *);
	struct ip6_hdr	*ip6;
	struct ip6_frag	*frg6;
	caddr_t		 pyld6;

	plen = cv4->plen - NATPT_MAXULP;
	if ((m6 = natpt_mgethdr(NATPT_FRGHDRSZ, plen)) == NULL)
		return ;

	ip6 = mtod(m6, struct ip6_hdr *);
	frg6 = (struct ip6_frag *)(ip6 + 1);
	pyld6 = (caddr_t)(ip6 + 1) + sizeof(struct ip6_frag);

	*ip6 = *ip6save;
	*frg6 = *fh6save;

	ip6->ip6_plen = htons(sizeof(struct ip6_frag) + plen);
	offset = ((ip4->ip_off & IP_OFFMASK) << 3) + NATPT_MAXULP;
	frg6->ip6f_offlg = htons(offset) & IP6F_OFF_MASK;
	if (ip4->ip_off & IP_MF)
		frg6->ip6f_offlg |= IP6F_MORE_FRAG;

	bcopy(cv4->pyld.caddr+NATPT_MAXULP, pyld6, plen);
	m6->m_pkthdr.len = m6->m_len = NATPT_FRGHDRSZ + plen;
	m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;
	natpt_ip6_forward(m6);		/* send second fragmented packet */
}


void
natpt_ip6_forward(struct mbuf *m)
{
	ip6_forward(m, 1);
}


/*
 * Translating From IPv4 to IPv4
 */

#ifdef NATPT_NAT
struct mbuf *
natpt_translateIPv4To4(struct pcv *cv4, struct pAddr *pad)
{
	const char	*fn = __FUNCTION__;

	struct timeval	atv;
	struct mbuf	*m4 = NULL;

	if (isDump(D_TRANSLATEIPV4))
		natpt_logIp4(LOG_DEBUG, cv4->ip.ip4, "%s():", fn);

	microtime(&atv);
	cv4->ats->tstamp = atv.tv_sec;

	switch (cv4->ip_p) {
	case IPPROTO_ICMP:
		m4 = natpt_translateICMPv4To4(cv4, pad);
		break;

	case IPPROTO_TCP:
		m4 = natpt_translateTCPv4To4(cv4, pad);
		break;

	case IPPROTO_UDP:
		m4 = natpt_translateUDPv4To4(cv4, pad);
		break;
	}

	if (m4)
		natpt_adjustMBuf(cv4->m, m4);

	return (m4);
}


struct mbuf *
natpt_translateICMPv4To4(struct pcv *cv4from, struct pAddr *pad)
{
	struct pcv	cv4to;
	struct mbuf	*m4;
	struct ip	*ip4to;
	struct icmp	*icmp4from;

	if ((m4 = m_copym(cv4from->m, 0, M_COPYALL, M_NOWAIT)) == NULL)
		return (NULL);

	bzero(&cv4to, sizeof(struct pcv));
	cv4to.m = m4;
	cv4to.ip.ip4 = ip4to = mtod(m4, struct ip *);
	cv4to.pyld.caddr = (caddr_t)ip4to + (ip4to->ip_hl << 2);
	cv4to.fromto = cv4from->fromto;

	ip4to->ip_src = pad->in4dst;
	ip4to->ip_dst = pad->in4src;

	icmp4from = cv4from->pyld.icmp4;
	switch (icmp4from->icmp_type) {
	case ICMP_ECHOREPLY:	/* do nothing */
	case ICMP_ECHO:
		break;

	case ICMP_UNREACH:
		switch (icmp4from->icmp_code) {
		case ICMP_UNREACH_PORT:
		case ICMP_UNREACH_NEEDFRAG:
			natpt_icmp4TimeExceed(&cv4to, pad);
		}
		break;

	case ICMP_TIMXCEED:
		if (icmp4from->icmp_code == ICMP_TIMXCEED_INTRANS)
			natpt_icmp4TimeExceed(&cv4to, pad);
		break;

	default:
		m_freem(m4);
		return (NULL);
	}

	return (m4);
}

void
natpt_icmp4TimeExceed(struct pcv *cv4to, struct pAddr *pad)
{
	u_short		cksum;
	struct ip	*ip4inner;
	struct udphdr	*udp4inner;
	struct {
		struct in_addr	a;
		u_int16_t	p;
	}			Dee, Dum;

	bzero(&Dee, sizeof(Dee));
	bzero(&Dum, sizeof(Dum));

	ip4inner = &cv4to->pyld.icmp4->icmp_ip;
	udp4inner = (struct udphdr *)((caddr_t)ip4inner + (ip4inner->ip_hl << 2));

	Dee.a = ip4inner->ip_src;
	Dum.a = ip4inner->ip_src = pad->in4src;
	cksum = natpt_fixCksum(ntohs(ip4inner->ip_sum),
			       (u_char *)&Dee.a, sizeof(Dee.a),
			       (u_char *)&Dum.a, sizeof(Dum.a));
	ip4inner->ip_sum = htons(cksum);

	Dee.p = udp4inner->uh_sport;
	Dum.p = udp4inner->uh_sport = pad->port[0];
	cksum = natpt_fixCksum(ntohs(cv4to->pyld.icmp4->icmp_cksum),
			       (u_char *)&Dee.p, sizeof(Dee.p),
			       (u_char *)&Dum.p, sizeof(Dum.p));
	cv4to->pyld.icmp4->icmp_cksum = htons(cksum);
}


struct mbuf *
natpt_translateTCPv4To4(struct pcv *cv4from, struct pAddr *pad)
{
	struct pcv	cv4to;
	struct mbuf	*m4;

	bzero(&cv4to, sizeof(struct pcv));
	if ((m4 = natpt_translateTCPUDPv4To4(cv4from, pad, &cv4to)) == NULL)
		return (NULL);

	cv4to.ip_p  = IPPROTO_TCP;
	natpt_updateTcpStatus(&cv4to);
	natpt_translatePYLD4To4(&cv4to);
	natpt_fixTCPUDP44cksum(IPPROTO_TCP, cv4from, &cv4to);

	return (m4);
}


struct mbuf *
natpt_translateUDPv4To4(struct pcv *cv4from, struct pAddr *pad)
{
	struct pcv	cv4to;
	struct mbuf	*m4;

	bzero(&cv4to, sizeof(struct pcv));
	if ((m4 = natpt_translateTCPUDPv4To4(cv4from, pad, &cv4to)) == NULL)
		return (NULL);

	cv4to.ip_p = IPPROTO_UDP;
	if (udpcksum) {
		natpt_fixTCPUDP44cksum(IPPROTO_UDP, cv4from, &cv4to);
	} else {
		cv4to.pyld.udp->uh_sum = 0;
	}
	return (m4);
}


struct mbuf *
natpt_translateTCPUDPv4To4(struct pcv *cv4from, struct pAddr *pad, struct pcv *cv4to)
{
	struct mbuf	*m4;
	struct ip	*ip4to;
	struct tcphdr	*tcp4to;

	static struct pcvaux	aux;
	static struct ulc4	ulc;

	if ((m4 = m_copym(cv4from->m, 0, M_COPYALL, M_NOWAIT)) == NULL)
		return (NULL);

	/*
	 * There is a case pointing the same data with m4 and cv6->m
	 * after m_copym, we need to prepare for incremental checksum
	 * calculation.
	 */
	bzero(&aux, sizeof(struct pcvaux));
	bzero(&ulc, sizeof(struct ulc4));

	ulc.ulc_src = cv4from->ip.ip4->ip_src;
	ulc.ulc_dst = cv4from->ip.ip4->ip_dst;
	ulc.ulc_len = htonl(cv4from->plen);
	ulc.ulc_pr  = cv4from->ip_p;
	if (cv4from->ip_p == IPPROTO_TCP) {
		ulc.ulc_tu.th.th_sport = cv4from->pyld.tcp4->th_sport;
		ulc.ulc_tu.th.th_dport = cv4from->pyld.tcp4->th_dport;
		aux.cksum4 = ntohs(cv4from->pyld.tcp4->th_sum);
	} else {
		ulc.ulc_tu.uh.uh_sport = cv4from->pyld.udp->uh_sport;
		ulc.ulc_tu.uh.uh_dport = cv4from->pyld.udp->uh_dport;
		aux.cksum4 = ntohs(cv4from->pyld.udp->uh_sum);
	}

	aux.ulc4 = &ulc;
	cv4from->aux = &aux;

	/*
	 * Start translation
	 */
	ip4to = mtod(m4, struct ip *);
	ip4to->ip_src = pad->in4dst;
	ip4to->ip_dst = pad->in4src;

	tcp4to = (struct tcphdr *)((caddr_t)ip4to + (ip4to->ip_hl << 2));
	tcp4to->th_sport = pad->port[1];
	tcp4to->th_dport = pad->port[0];

	cv4to->m = m4;
	cv4to->ip.ip4 = ip4to;
	cv4to->pyld.tcp4 = tcp4to;
	cv4to->ats = cv4from->ats;
	cv4to->fromto = cv4from->fromto;

	return (m4);
}


void
natpt_translatePYLD4To4(struct pcv *cv4to)
{
	int		delta = 0;
	struct tcphdr	*th4 = cv4to->pyld.tcp4;
	struct tcpstate	*ts = NULL;

	if (((cv4to->fromto == NATPT_FROM)
	     && (htons(th4->th_dport) == FTP_CONTROL))
	    || ((cv4to->fromto == NATPT_TO)
		&& htons(th4->th_sport) == FTP_CONTROL)) {
		tcp_seq	th_seq;
		tcp_seq	th_ack;

		if ((delta = natpt_translateFTP6CommandTo4(cv4to)) != 0) {
			struct mbuf	*mbf = cv4to->m;
			struct ip	*ip4 = cv4to->ip.ip4;

			ip4->ip_len += delta;
			mbf->m_len += delta;
			if (mbf->m_flags & M_PKTHDR)
				mbf->m_pkthdr.len += delta;
		}

		if ((ts = cv4to->ats->suit.tcps) == NULL)
			return ;

		th_seq = th4->th_seq;
		th_ack = th4->th_ack;

		if (ts->delta[0]) {
			if ((cv4to->fromto == NATPT_TO)
			    && (th4->th_flags & TH_ACK))
				natpt_decrementAck(th4, ts->delta[0]);
			else if (cv4to->fromto == NATPT_FROM)
				natpt_incrementSeq(th4, ts->delta[0]);
		}

		if (ts->delta[1]) {
			if ((cv4to->fromto == NATPT_FROM)
			    && (th4->th_flags & TH_ACK))
				natpt_decrementAck(th4, ts->delta[1]);
			else if (cv4to->fromto == NATPT_TO)
				natpt_incrementSeq(th4, ts->delta[1]);
		}

		if ((delta != 0)
		    && ((th_seq != ts->seq[0])
			|| (th_ack != ts->ack[0]))) {
			ts->delta[0] += delta;
			ts->seq[0] = th_seq;
			ts->ack[0] = th_ack;
		}
	}
}


struct mbuf *
natpt_translateFragment4to4(struct pcv *cv4from, struct pAddr *pad)
{
	struct pcv	cv4to;
	struct mbuf	*m4;
	struct ip	*ip4to;

	if ((m4 = m_copym(cv4from->m, 0, M_COPYALL, M_NOWAIT)) == NULL)
		return (NULL);

	bzero(&cv4to, sizeof(struct pcv));
	cv4to.m = m4;
	cv4to.ip.ip4 = mtod(m4, struct ip *);
	cv4to.pyld.caddr = (caddr_t)cv4to.ip.ip4 + sizeof(struct ip);
	cv4to.fromto = cv4from->fromto;

	ip4to = cv4to.ip.ip4;
	ip4to->ip_src = pad->in4dst;
	ip4to->ip_dst = pad->in4src;
	natpt_adjustMBuf(cv4from->m, m4);

	return (m4);
}
#endif /* NATPT_NAT */


/*
 *
 */

void
natpt_translatePYLD(struct pcv *cv, u_short * ports)
{
	int		delta = 0;
	char		tcphdr[TCPHDRSZ];

	/* Save unmodified tcp header for a check of packet retransmission. */
	bcopy(cv->pyld.tcp4, tcphdr, TCPHDRSZ);

	/*
	 * if ((outgoing session) and (ato[1] == FTP_CONTROL)
	 *     || (mae[0] == FTP_CONTROL))
	 */
	if (((cv->fromto == NATPT_FROM)
	     && (ntohs(cv->pyld.tcp4->th_dport) == FTP_CONTROL))
	    || (ntohs(ports[0]) == FTP_CONTROL)) {
		struct mbuf	*mbf = cv->m;

		/* cv holds v6/v4 packet after translation */
		if (cv->sa_family == AF_INET) {
			/* In case translation from v6 to v4 */
			struct ip	*ip4 = cv->ip.ip4;

			if ((delta = natpt_translateFTP6CommandTo4(cv)) != 0)
				ip4->ip_len += delta;
		} else {
			/* In case translatino from v4 to v6 */
			struct ip6_hdr	*ip6 = cv->ip.ip6;

			if ((delta = natpt_translateFTP4ReplyTo6(cv)) != 0)
				ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) + delta);
		}

		mbf->m_len += delta;
		if (mbf->m_flags & M_PKTHDR)
			mbf->m_pkthdr.len += delta;
	}

	natpt_updateSeqAck(cv, tcphdr, delta);
}


int
natpt_translateFTP6CommandTo4(struct pcv *cv4)
{
	int		delta = 0;
	char		*tstr;
	u_char		*h, *p;
	caddr_t		kb, kk;
	struct ip	*ip4 = cv4->ip.ip4;
	struct tcphdr	*th4 = cv4->pyld.tcp4;
	struct tSlot	*ats;
	struct tcpstate	*ts;
	struct ftpparam	ftp6;
	struct pAddr	local, remote;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	char		wow[128];

	kb = (caddr_t)th4 + (th4->th_off << 2);
	kk = (caddr_t)ip4 + ip4->ip_len;

	if (((kk - kb) < FTPMINCMDLEN)
	    || (natpt_parseFTPdialogue(kb, kk, &ftp6) == NULL))
		return (0);

	ats = cv4->ats;
	ts  = ats->suit.tcps;
	if (ftp6.cmd < 1000)
		goto FTP6response;

	/*
	 * In case FTP6 server sends command to FTP4 client.
	 */
	switch (ftp6.cmd) {
#ifdef NATPT_NAT
	case FTP4_PORT:
		ts->ftpstate = FTPS_PORT;
		if (natpt_parsePORT(ftp6.arg, kk, &sin) == NULL)
			return (0);

		local = ats->local;
		local.port[0] = sin.sin_port;
		local.port[1] = htons(FTP_DATA);
		remote = ats->remote;
		remote.port[0] = htons(FTP_DATA);
		remote.port[1] = 0;	/* this port should be remapped */

		/* This connection opens already. */
		if (ts->lport == sin.sin_port) {
			remote.port[0] = ts->rport;
		} else {
			if (natpt_remapRemote4Port(ats->csl, &remote) == NULL)
				return (0);

			if (natpt_openIncomingV4Conn(IPPROTO_TCP, &local,
						     &remote)== NULL)
				return (0);

			ts->lport = sin.sin_port;
			ts->rport = remote.port[0];
		}

		h = (u_char *)&remote.addr[1];
		p = (u_char *)&remote.port[1];
		snprintf(wow, sizeof(wow), "PORT %u,%u,%u,%u,%u,%u\r\n",
			 h[0], h[1], h[2], h[3], p[0], p[1]);

		delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), wow, strlen(wow));
		ts->rewrite[cv4->fromto] = 1;
		break;
#endif

	case FTP6_EPRT:
	case FTP6_LPRT:
		if (ftp6.cmd == FTP6_LPRT) {
			ts->ftpstate = FTPS_LPRT;
			if (natpt_parseLPRT(ftp6.arg, kk, &sin6) == NULL)
				return (0);
		} else {
			ts->ftpstate = FTPS_EPRT;
			if (natpt_parseEPRT(ftp6.arg, kk, &sin6) == NULL)
				return (0);
		}

		/* v6 client side */
		local = ats->local;
		local.port[0] = sin6.sin6_port;
		local.port[1] = htons(FTP_DATA);
		/* v4 server side */
		remote = ats->remote;
		remote.port[0] = htons(FTP_DATA);
		remote.port[1] = sin6.sin6_port;
		if ((ats->csl->map & NATPT_REMAP_SPORT)
		    && (natpt_remapRemote4Port(ats->csl, &remote) == NULL)) {
			return (0);
		}

#if useOpenTSlot
		/* This connection is established from v4 side. */
		if (natpt_openIncomingV4Conn(IPPROTO_TCP, &remote, &local) == NULL)
			return (0);
#else
		if (natpt_openTemporaryRule(IPPROTO_TCP, &remote, &local) == 0)
			return (0);
#endif

		h = (u_char *)&remote.addr[1];
		p = (u_char *)&remote.port[1];
		snprintf(wow, sizeof(wow), "PORT %u,%u,%u,%u,%u,%u\r\n",
			 h[0], h[1], h[2], h[3], p[0], p[1]);

		delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), wow, strlen(wow));
		ts->rewrite[cv4->fromto] = 1;
		break;

	case FTP6_EPSV:
		ts->ftpstate = FTPS_EPSV;
		tstr = "PASV\r\n";
		delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), tstr, strlen(tstr));
		ts->rewrite[cv4->fromto] = 1;
		break;

	case FTP6_LPSV:
		ts->ftpstate = FTPS_LPSV;
		tstr = "PASV\r\n";
		delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), tstr, strlen(tstr));
		ts->rewrite[cv4->fromto] = 1;
		break;
	}
	return (delta);

 FTP6response:;
	/*
	 * In case FTP6 server sends response to FTP4 client.
	 */
	switch (ts->ftpstate) {
	case FTPS_EPSV:
	case FTPS_PASV:
		if (ftp6.cmd != 229)
			return (0);

		if (natpt_parse229(ftp6.arg, kk, &sin6) == NULL)
			return (0);

		/*
		 * Open rule temporary for 4->6 port redirect.
		 *
		 * This part which open rule temporary is is
		 * unnecessary if you do not want to change port
		 * number with translation rule.
		 */

		/* v4 side; initiator */
		bzero(&local, sizeof(struct pAddr));
		local.sa_family = AF_INET;
		local.aType = ADDR_REDIRECT;
		local.addr[1] = ats->local.addr[1];
		local.port[1] = sin6.sin6_port;
				/* ats->[0] = v4 server address */
				/* ats->[1] = v4 client address */

		/* v6 side; responder */
		bzero(&remote, sizeof(struct pAddr));
		remote.sa_family = AF_INET6;
		remote.aType = ADDR_REDIRECT;
		remote.addr[1] = ats->remote.addr[0];
		remote.port[1] = sin6.sin6_port;
			    /* ats->[0] = v6 client address */
			    /* ats->[1] = v6 server address */

		if (natpt_openTemporaryRule(IPPROTO_TCP, &local, &remote) == 0)
			return (0);

		/*
		 * If v4 FTP client speaks EPSV, translation is
		 * unnecessary.
		 */
		if (ts->ftpstate == FTPS_EPSV)
			return (0);

		/*
		 * Rewrite FTP reply
		 *
		 * getting:   229 Entering Extended Passive Mode (|||6446|)
		 * expecting: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
		 */

		/* v4 client side */
		local = ats->local;
		h = (u_char *)&local.addr[1];
		p = (u_char *)&sin6.sin6_port;
		snprintf(wow, sizeof(wow),
			 "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u)\r\n",
			 h[0], h[1], h[2], h[3], p[0], p[1]);
		delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), wow, strlen(wow));
		ts->rewrite[cv4->fromto] = 1;
		break;

	case FTPS_PORT:
		if (ftp6.cmd != 200)
			return (0);

		snprintf(wow, sizeof(wow), "200 PORT command successful.\r\n");
		delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), wow, strlen(wow));
		ts->rewrite[cv4->fromto] = 1;
		break;
	}
	return (delta);
}


int
natpt_translateFTP4ReplyTo6(struct pcv *cv6)
{
	int		delta = 0;
	int		rv;
	char		*tstr;
	char		*d;
	u_char		*h, *p;
	caddr_t		kb, kk;
	struct ip6_hdr	*ip6 = cv6->ip.ip6;
	struct tcphdr	*th6 = cv6->pyld.tcp6;
	struct tSlot	*ats;
	struct tcpstate	*ts;
	struct pAddr	local, remote;
	struct sockaddr_in sin;
	struct ftpparam	ftp4;
	char		Wow[128];
	char		*wp;
	int		 wl;

	kb = (caddr_t)th6 + (th6->th_off << 2);
	kk = (caddr_t)ip6 + sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
	if (((kk - kb) < FTPMINCMDLEN)
	    || (natpt_parseFTPdialogue(kb, kk, &ftp4) == NULL))
		return (0);

	ats = cv6->ats;
	ts  = ats->suit.tcps;

	if (ftp4.cmd < 1000)
		goto FTP4response;

	/*
	 * In case FTP4 client sends commmand to FTP6 server.
	 */
	switch (ftp4.cmd) {
	case FTP4_PASV:
		ts->ftpstate = FTPS_PASV;
		tstr = "EPSV\r\n";
		ts->rewrite[cv6->fromto] = 1;
		delta = natpt_rewriteMbuf(cv6->m, kb, (kk-kb), tstr, strlen(tstr));
		return (delta);

	case FTP4_PORT:
		ts->ftpstate = FTPS_PORT;
		if (natpt_parsePORT(ftp4.arg, kk, &sin) == NULL)
			return (0);

		/* v6 side; initiator */
		bzero(&local, sizeof(struct pAddr));
		local.sa_family = AF_INET6;
		local.addr[0] = ats->remote.addr[0];	/* 0: v6 server address */
							/* 1: v6 translated address */

		/* v4 side; responder */
		bzero(&remote, sizeof(struct pAddr));
		remote.sa_family = AF_INET;
		remote.addr[0] = ats->local.addr[1];	/* 0: v4 client address */
							/* 1: v4 server address */

		if (natpt_openTemporaryRule(IPPROTO_TCP, &local, &remote) == 0)
			return (0);

		wp = Wow;
		wl = sizeof(Wow);

		rv = snprintf(wp, wl, "EPRT |2|");
		wp += rv;
		wl -= rv;
		rv = natpt_ntop(AF_INET6, (const u_char *)&ats->remote.addr[1], wp, wl);
		wp += rv;
		wl -= rv;
		rv = snprintf(wp, wl, "|%d|\r\n", htons(sin.sin_port));

		ts->rewrite[cv6->fromto] = 1;
		delta = natpt_rewriteMbuf(cv6->m, kb, (kk-kb), Wow, strlen(Wow));
		return (delta);


	case FTP6_EPSV:
		/*
		 * Some v4 FTP clients (e.g. FTP on FreeBSD4 or later)
		 * speak EPSV when connect to v4 FTP server.
		 * Translation is unnecessary but preparation for
		 * response from FTP server is needed.
		 */
		ts->ftpstate = FTPS_EPSV;
		return (delta);
	}

 FTP4response:;
	/*
	 * In case FTP4 server sends response to FTP6 client.
	 */
	switch (ts->ftpstate) {
	case FTPS_LPRT:
	case FTPS_EPRT:
		if (ftp4.cmd != 200)
			return (0);

		/*
		 * getting:   200 PORT command successful.
		 * expecting: 200 EPRT command successful.
		 */
		d = ftp4.arg;
		if ((d[0] == 'P') && (d[1] == 'O')) {
			d[0] = (ts->ftpstate == FTPS_LPRT) ? 'L' : 'E';
			d[1] = 'P';
		}
		ts->rewrite[cv6->fromto] = 1;
		break;

	case FTPS_LPSV:
		if (ftp4.cmd != 227)
			return (0);

		/*
		 * getting:   227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
		 * expecting: 228 Entering Long Passive Mode(...)
		 */
		if (natpt_parse227(ftp4.arg, kk, &sin) == NULL)
			return (0);

		h = (u_char *)&ats->local.in6src;
		p = (u_char *)&sin.sin_port;
		snprintf(Wow, sizeof(Wow),
			 "228 Entering Long Passive Mode "
			 "(%u,%u,"
			 "%u,%u,%u,%u,%u,%u,%u,%u,"
			 "%u,%u,%u,%u,%u,%u,%u,%u,"
			 "%u,%u,%u)\r\n",
			 IPV6_VERSION >> 4, 16,
			 h[0], h[1], h[ 2], h[ 3], h[ 4], h[ 5], h[ 6], h[ 7],
			 h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
			 2, p[0], p[1]);
		delta = natpt_rewriteMbuf(cv6->m, kb, (kk-kb), Wow, strlen(Wow));
		ts->rewrite[cv6->fromto] = 1;
		break;

	case FTPS_EPSV:
		if (ftp4.cmd != 227)
			return (0);

		/*
		 * getting:   227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
		 * expecting: 229 Entering Extended Passive Mode (|||6446|)
		 */
		if (natpt_parse227(ftp4.arg, kk, &sin) == NULL)
			return (0);
		snprintf(Wow, sizeof(Wow),
			 "229 Entering Extended Passive Mode (|||%d|)\r\n",
			 ntohs(sin.sin_port));
		delta = natpt_rewriteMbuf(cv6->m, kb, (kk-kb), Wow, strlen(Wow));
		ts->rewrite[cv6->fromto] = 1;
		break;
	}

	return (delta);
}


struct ftpparam *
natpt_parseFTPdialogue(caddr_t kb, caddr_t kk, struct ftpparam *ftp6)
{
	int	idx;
	union {
		char	byte[4];
		u_long	cmd;
	}	u;

	while ((kb < kk) && (*kb == ' '))
		kb++;	/* skip preceding blank */

	u.cmd = 0;
	if (isalpha(*kb)) {
		/* in case FTP command */
		for (idx = 0; idx < 4; idx++) {
			if (!isalpha(*kb) && (*kb != ' '))
				return (NULL);

			u.byte[idx] = islower(*kb) ? toupper(*kb) : *kb;
			if (isalpha(*kb))
				kb++;
		}
	} else if (isdigit(*kb)) {
		/* in case FTP reply */
		for (idx = 0; idx < 3; idx++, kb++) {
			if (!isdigit(*kb))
				return (NULL);

			u.cmd = u.cmd * 10 + *kb - '0';
		}
	} else
		return (NULL);	/* neither ftp command nor ftp reply */

	while ((kb < kk) && (*kb == ' '))
		kb++;

	if (kb >= kk)
		return (NULL);	/* no end of line (<CRLF>) found */

	bzero(ftp6, sizeof(struct ftpparam));
	ftp6->cmd = u.cmd;
	if ((*kb != '\r') && (*kb != '\n'))
		ftp6->arg = kb;

	return (ftp6);
}


struct sockaddr *
natpt_parseLPRT(caddr_t kb, caddr_t kk, struct sockaddr_in6 *sin6)
{
	int	port, bite;
	int	hal = 16;
	int	pal = 2;
	u_char	*d;

	bzero(sin6, sizeof(struct sockaddr_in6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;

	if (kb + 5 > kk)
		return (NULL);	/* 5 for "6,16," */
	if ((kb[0] != '6') || (kb[1] != ',')
	    || (kb[2] != '1') || (kb[3] != '6') || (kb[4] != ','))
		return (NULL);
	kb += 5;

	d = (u_char *)&sin6->sin6_addr;
	for (bite = 0; (kb < kk) && (isdigit(*kb) || (*kb == ',')); kb++) {
		if (*kb == ',') {
			*d++ = (bite & 0xff);
			bite = 0;
			if (--hal <= 0)
				break;
		} else
			bite = bite * 10 + *kb - '0';
	}

	if (hal != 0)
		return (NULL);
	if (kb + 3 > kk)
		return (NULL);	/* 3 for ",2," */
	if ((kb[0] != ',') || (kb[1] != '2') || (kb[2] != ','))
		return (NULL);
	kb += 3;

	d = (u_char *)&sin6->sin6_port;
	for (port = 0; (kb < kk) && (isdigit(*kb) || (*kb == ',')); kb++) {
		if (*kb == ',') {
			*d++ = (port & 0xff);
			port = 0;
			if (--pal <= 0)
				break;
		} else
			port = port * 10 + *kb - '0';
	}

	if (pal != 1)
		return (NULL);
	if (port > 0)
		*d = (port & 0xff);

	return ((struct sockaddr *)sin6);
}


struct sockaddr *
natpt_parseEPRT(caddr_t kb, caddr_t kk, struct sockaddr_in6 *sin6)
{
	int	port;
	caddr_t	km;

	bzero(sin6, sizeof(struct sockaddr_in6));

	if (*kb++ != '|')
		return (NULL);
	switch (*kb++) {
	case '1':
		sin6->sin6_family = AF_INET;
		break;
	case '2':
		sin6->sin6_family = AF_INET6;
		break;
	default:
		return (NULL);
	}
	if (*kb++ != '|')
		return (NULL);

	km = kb;
	while ((kb < kk) && (isxdigit(*kb) || (*kb == ':')))
		kb++;
	if (*kb != '|')
		return (NULL);
	if (natpt_pton6(km, kb++, &sin6->sin6_addr) == 0)
		return (NULL);

	port = 0;
	while ((kb < kk) && (isdigit(*kb))) {
		port = port * 10 + *kb - '0';
		kb++;
	}
	if (*kb != '|')
		return (NULL);

	sin6->sin6_port = htons(port);
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	return ((struct sockaddr *)sin6);
}


struct sockaddr *
natpt_parsePORT(caddr_t kb, caddr_t kk, struct sockaddr_in *sin)
{
	int	cnt, bite;
	u_char	*d;

	bzero(sin, sizeof(struct sockaddr_in));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;

	d = (u_char *)&sin->sin_addr;
	for (bite = 0, cnt = 4; (kb < kk) && (isdigit(*kb) || (*kb == ',')); kb++) {
		if (*kb == ',') {
			*d++ = (bite & 0xff);
			bite = 0;
			if (--cnt <= 0)
				break;
		} else
			bite = bite * 10 + *kb - '0';
	}

	if (cnt != 0)
		return (NULL);

	kb++;
	d = (u_char *)&sin->sin_port;
	for (bite = 0, cnt = 2; (kb < kk) && (isdigit(*kb) || (*kb == ',')); kb++) {
		if (*kb == ',') {
			*d++ = (bite & 0xff);
			bite = 0;
			if (--cnt <= 0)
				break;
		} else
			bite = bite * 10 + *kb - '0';
	}

	if (cnt != 1)
		return (NULL);
	if (bite > 0)
		*d = (bite & 0xff);

	return ((struct sockaddr *)sin);
}


struct sockaddr *
natpt_parse227(caddr_t kb, caddr_t kk, struct sockaddr_in *sin)
{
	int		bite;
	u_int		byte[6];
	u_short		inport;
	struct in_addr	inaddr;

	while ((kb < kk) && (*kb != '(') && !isdigit(*kb))
		kb++;

	if (*kb == '(')
		kb++;

	bite = 0;
	bzero(byte, sizeof(byte));
	while ((kb < kk) && (isdigit(*kb) || (*kb == ','))) {
		if (isdigit(*kb))
			byte[bite] = byte[bite] * 10 + *kb - '0';
		else if (*kb == ',')
			bite++;
		else
			return (NULL);

		kb++;
	}

	inaddr.s_addr  = ((byte[0] & 0xff) << 24);
	inaddr.s_addr |= ((byte[1] & 0xff) << 16);
	inaddr.s_addr |= ((byte[2] & 0xff) <<  8);
	inaddr.s_addr |= ((byte[3] & 0xff) <<  0);
	inport = ((byte[4] & 0xff) << 8) | (byte[5] & 0xff);

	bzero(sin, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(inport);
	sin->sin_addr = inaddr;

	return ((struct sockaddr *)sin);
}


struct sockaddr *
natpt_parse229(caddr_t kb, caddr_t kk, struct sockaddr_in6 *sin6)
{
	u_short port;

	while ((kb < kk) && (*kb != '(') && !isdigit(*kb))
		kb++;

	if (*kb == '(')
		kb++;

	if (strncmp(kb, "|||", 3) != 0)
		return (NULL);

	kb += 3;
	port = 0;
	while ((kb < kk) && isdigit(*kb)) {
		port = port * 10 + *kb - '0';
		kb++;
	}

	if (*kb++ != '|')
		return (NULL);

	if (*kb != ')')
		return (NULL);

	bzero(sin6, sizeof(struct sockaddr_in6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(port);

	return ((struct sockaddr *)sin6);
}


int
natpt_pton6(caddr_t kb, caddr_t kk, struct in6_addr *addr6)
{
	int		ch, col, cols;
	u_int		v, val;
	u_char		*d;
	struct in6_addr	bow;

	if ((*kb == ':') && (*(kb+1) != ':'))
		return (0);

	d = (u_char *)&bow;
	bzero(&bow, sizeof(bow));

	col = cols = val = 0;
	while (kb < kk) {
		v = 'z';
		ch = *kb++;
		if (isdigit(ch))
			v = ch - '0';
		else if (('A' <= ch) && (ch <= 'F'))
			v = ch - 55;
		else if (('a' <= ch) && (ch <= 'f'))
			v = ch - 87;
		else
			;

		if (v != 'z') {
			val = (val << 4) | v;
			if (val > 0xffff)
				return (0);
			col = 0;
			continue;
		} else if (ch == ':') {
			if (col == 0) {
				*d++ = (u_char)((val >> 8) & 0xff);
				*d++ = (u_char)( val & 0xff);
				val = 0;
				col++;
				continue;
			} else if (col == 1) {
				/* count number of colon, and advance the address
				 * which begin to write.
				 */
				int	ncol;
				caddr_t	p;

				if (cols > 0)
					return (0); /* we've already seen "::" */

				for (p = kb, ncol = 0; p < kk; p++)
					if (*p == ':')
						ncol++;

				d = (u_char *)&bow + (7-ncol)*2;
				col++;
				cols++;
				continue;
			} else
				return (0);	/* COLON continued more than 3 */
		} else
			return (0);	/* illegal character */
	}

	if (val > 0) {
		*d++ = (u_char)((val >> 8) & 0xff);
		*d++ = (u_char)( val & 0xff);
	}
	*addr6 = bow;
	return (1);
}


int
natpt_rewriteMbuf(struct mbuf *m, char *pyld, int pyldlen, char *tstr,int tstrlen)
{
	int		i;
	caddr_t		s, d, roome;

	roome = (caddr_t)m + MSIZE;
	if (m->m_flags & M_EXT)
		roome = m->m_ext.ext_buf + MCLBYTES;

	if ((roome - pyld) < tstrlen)
		return (0xdead);	/* no room in mbuf */

	s = tstr;
	d = pyld;
	for (i = 0; i < tstrlen; i++)
		*d++ = *s++;

	return (tstrlen - pyldlen);
}


void
natpt_updateSeqAck(struct pcv *cv, caddr_t tcphdr, int delta)
{
	int		fromto = 0;
	caddr_t		tp;
	struct tcphdr	*th = (struct tcphdr *)cv->pyld.caddr;
	struct tcpstate	*ts  = NULL;

	if ((cv->ats == NULL)
	    || ((ts = cv->ats->suit.tcps) == NULL))
		return ;

	if (ts->delta[0]) {
		if (cv->fromto == NATPT_FROM)
			natpt_incrementSeq(th, ts->delta[0]);
		else if ((cv->fromto == NATPT_TO) && (th->th_flags & TH_ACK))
			natpt_decrementAck(th, ts->delta[0]);
	}

	if (ts->delta[1]) {
		if (cv->fromto == NATPT_TO)
			natpt_incrementSeq(th, ts->delta[1]);
		else if ((cv->fromto == NATPT_FROM) && (th->th_flags & TH_ACK))
			natpt_decrementAck(th, ts->delta[1]);
	}

	if (cv->fromto == NATPT_TO)
		fromto = 1;

	if ((delta != 0)
	    && ((th->th_seq != ts->seq[fromto])
		|| (th->th_ack != ts->ack[fromto]))) {
#ifdef NATPT_DEBUG
		printf("%s():\n", __FUNCTION__);
		printf("  delta, fromto: %5d %5d\n", delta, fromto);
		printf("  delta, seq, ack: %5ld, %11lu, %11lu\n",
		       ts->delta[fromto], htonl(ts->seq[fromto]), htonl(ts->ack[fromto]));
#endif

		tp = ts->pkthdr[fromto];
		if (tp == NULL) {
			MALLOC(tp, caddr_t, TCPHDRSZ, M_NATPT, M_NOWAIT);
		}

		if ((ts->pkthdr[fromto] == NULL)
		    || ((tp != NULL)
			&& (bcmp(tp, tcphdr, TCPCHKSZ) != 0))) {
			bcopy(tcphdr, tp, TCPHDRSZ);
			ts->delta[fromto] += delta;
			ts->seq[fromto] = th->th_seq;
			ts->ack[fromto] = th->th_ack;
		}

		ts->pkthdr[fromto] = tp;

#ifdef NATPT_DEBUG
		printf("  delta, seq, ack: %5ld, %11lu, %11lu\n",
		       ts->delta[fromto], htonl(ts->seq[fromto]), htonl(ts->ack[fromto]));
#endif
	}
}


void
natpt_incrementSeq(struct tcphdr *th, int delta)
{
	th->th_seq = htonl(ntohl(th->th_seq) + delta);
}


void
natpt_decrementAck(struct tcphdr *th, int delta)
{
	th->th_ack = htonl(ntohl(th->th_ack) - delta);
}


/*
 *
 */
int
natpt_updateTcpStatus(struct pcv *cv)
{
	struct tSlot	*ats = cv->ats;
	struct tcpstate	*ts;

	if (ats->ip_p != IPPROTO_TCP)
		return (0);

	if ((ts = ats->suit.tcps) == NULL) {
		MALLOC(ts, struct tcpstate *, sizeof(struct tcpstate), M_NATPT, M_NOWAIT);
		if (ts == NULL)
			return (0);

		bzero(ts, sizeof(struct tcpstate));
		ts->state = TCPS_CLOSED;
		ats->suit.tcps = ts;
	}

	ts->state = natpt_tcpfsm(ts->state, cv->fromto, cv->pyld.tcp4->th_flags);

	return (0);
}


/*
//##
//#------------------------------------------------------------------------
//#	_natpt_tcpfsmSessOut

	delta(start,		eps)			-> CLOSED
	delta(CLOSED,		TH_SYN & !TH_ACK)	-> SYN_SENT
	delta(SYN_SENT,	     in	TH_SYN &  TH_ACK)	-> SYN_RCVD
	delta(SYN_RCVD,		TH_ACK)			-> ESTABLISHED
	delta(ESTABLISHED,	TH_FIN)			-> FIN_WAIT_1
	delta(FIN_WAIT_1,    in	TH_FIN | TH_ACK)	-> TIME_WAIT
	delta(FIN_WAIT_1,    in	TH_ACK)			-> FIN_WAIT_2
	delta(FIN_WAIT_1,    in	TH_FIN)			-> CLOSING
	delta(FIN_WAIT_2,    in	TH_FIN)			-> TIME_WAIT
	delta(CLOSING,		TH_ACK)			-> TIME_WAIT
	delta(TIME_WAIT,	eps)			-> CLOSED

//#------------------------------------------------------------------------
*/

int
natpt_tcpfsm(short state, int inout, u_char flags)
{
	int	rv = state;

	if (flags & TH_RST)
		return (TCPS_CLOSED);

	switch (state) {
	case TCPS_CLOSED:
		if ((inout == NATPT_FROM)
		    && (((flags & TH_SYN) != 0)
			&& (flags & TH_ACK) == 0))
			rv = TCPS_SYN_SENT;
		break;

	case TCPS_SYN_SENT:
		if ((inout == NATPT_TO)
		    && (flags & (TH_SYN | TH_ACK)))
			rv = TCPS_SYN_RECEIVED;
		break;

	case TCPS_SYN_RECEIVED:
		if ((inout == NATPT_FROM)
		    && (flags & TH_ACK))
			rv = TCPS_ESTABLISHED;
		break;

	case TCPS_ESTABLISHED:
		if ((inout == NATPT_FROM)
		    && (flags & TH_FIN))
			rv = TCPS_FIN_WAIT_1;
		break;

	case TCPS_FIN_WAIT_1:
		if (inout == NATPT_TO) {
			if (flags & (TH_FIN | TH_ACK))
				rv = TCPS_TIME_WAIT;
			else if (flags & TH_ACK)
				rv = TCPS_FIN_WAIT_2;
			else if (flags & TH_FIN)
				rv = TCPS_CLOSING;
		}
		break;

	case TCPS_CLOSING:
		if ((inout == NATPT_FROM)
		    && (flags & TH_ACK))
			rv = TCPS_TIME_WAIT;
		break;

	case TCPS_FIN_WAIT_2:
		if ((inout == NATPT_TO)
		    && (flags & TH_FIN))
			rv = TCPS_TIME_WAIT;
		break;
	}

	return (rv);
}


/*
 *
 */

struct mbuf *
natpt_mgethdr(int hlen, int len)
{
	struct mbuf	*m;

	if (hlen + len > MCLBYTES) {
		return (NULL);
	}
	MGETHDR(m, M_NOWAIT, MT_HEADER);
	if (m && (hlen + len > MHLEN)) {
		MCLGET(m, M_NOWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (m == NULL) {
		return (NULL);
	}
	m->m_pkthdr.rcvif = NULL;

	return (m);
}


struct ip6_frag *
natpt_composeIPv6Hdr(struct pcv *cv4, struct pAddr *pad, struct ip6_hdr *ip6)
{
	struct ip	*ip4 = cv4->ip.ip4;
	struct ip6_frag	*frg6 = NULL;

	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_flow |= htonl(cv4->ip.ip4->ip_tos << 20);	/* copy from TOS */
	ip6->ip6_plen = htons(cv4->plen);
	ip6->ip6_nxt  = (cv4->ip_p == IPPROTO_ICMP)
		? IPPROTO_ICMPV6
		: cv4->ip_p;
	ip6->ip6_hlim = ip4->ip_ttl;
	ip6->ip6_dst  = pad->in6src;
	ip6->ip6_src  = pad->in6dst;

	/*
	 * RFC2765 3.1 said:
	 * ... IPv4 packets with DF not set will always result in a
	 * fragment header being added to the packet ...
	 */
	if (isFragment(cv4) || needFragment(cv4) || isNoDF(cv4)) {
		frg6 = (struct ip6_frag *)(caddr_t)(ip6 + 1);
		frg6->ip6f_nxt = ip6->ip6_nxt;
		frg6->ip6f_reserved = 0;
		frg6->ip6f_offlg  = htons((ip4->ip_off & IP_OFFMASK) << 3);
		if ((ip4->ip_off & IP_MF) || needFragment(cv4))
			frg6->ip6f_offlg |= IP6F_MORE_FRAG;
		frg6->ip6f_ident  = 0;
		frg6->ip6f_ident |= ntohs(ip4->ip_id);
		HTONL(frg6->ip6f_ident);

		/* Get last fragmented packet length from given ip header. */
		if (!needFragment(cv4)
		    && ((ip4->ip_off & IP_OFFMASK) != 0)
		    && ((ip4->ip_off & IP_MF) == 0))
			ip6->ip6_plen = ip4->ip_len - sizeof(struct ip) +
				sizeof(struct ip6_frag);
		else if (needFragment(cv4))
			ip6->ip6_plen = IPV6_MMTU - sizeof(struct ip6_hdr);
		else
			ip6->ip6_plen = ip4->ip_len - sizeof(struct ip) +
				sizeof(struct ip6_frag);

		HTONS(ip6->ip6_plen);
		ip6->ip6_nxt  = IPPROTO_FRAGMENT;
	}

	return (frg6);
}


void
natpt_composeIPv4Hdr(struct pcv *cv6, struct pAddr *pad, struct ip *ip4)
{
	struct ip6_hdr	*ip6 = cv6->ip.ip6;
	struct ip6_frag	fh6;

	/*
	 * There is a case pointing the same area with ip6 and ip4, we
	 * need to save the fragment header if exists.
	 */
	if (cv6->fh) {
		fh6 = *cv6->fh;
	}

#ifdef _IP_VHL
	ip4->ip_vhl = IP_MAKE_VHL(IPVERSION, (sizeof(struct ip) >> 2));
#else
	ip4->ip_v   = IPVERSION;		/* IP version */
	ip4->ip_hl  = sizeof(struct ip) >> 2;/* header length (no IPv4 option) */
#endif
	ip4->ip_tos = (ntohl(ip6->ip6_flow) & IPV6_FLOWINFO_MASK) >> 20;
					/* copy traffic class (all 8bits) */
	ip4->ip_len = sizeof(struct ip) + cv6->plen;
	ip4->ip_id  = 0;			/* Identification */
	ip4->ip_off = 0;			/* flag and fragment offset */
	ip4->ip_ttl = ip6->ip6_hlim;	/* Time To Live */
	ip4->ip_src = pad->in4dst;		/* source addresss */
	ip4->ip_dst = pad->in4src;		/* destination address */
	ip4->ip_p = (cv6->ip_p == IPPROTO_ICMPV6)
		? IPPROTO_ICMP
		: cv6->ip_p;

	if (cv6->fh) {
		u_int16_t	offlg = ntohs(fh6.ip6f_offlg);

		ip4->ip_len = ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag)
			+ sizeof(struct ip);
		ip4->ip_id = ntohl(fh6.ip6f_ident) & 0xffff;
		HTONS(ip4->ip_id);

		ip4->ip_off = (offlg & 0xfff8) >> 3;
		if (offlg & 0x0001)
			ip4->ip_off |= IP_MF;
	} else {
		ip4->ip_off |= IP_DF;	/* RFC2765 4.1 */
	}
}


void
natpt_adjustMBuf(struct mbuf *mf, struct mbuf *mt)
{
	int		mlen;
	struct mbuf	*mm;
	struct ip	*ip4;

	ip4 = mtod(mt, struct ip *);
	ip4->ip_sum = 0;
	ip4->ip_sum = in_cksum(mt, sizeof(struct ip));
	for (mlen = 0, mm = mt; mm; mm = mm->m_next) {
		mlen += mm->m_len;
	}
	mt->m_pkthdr.len = mlen;
	mt->m_pkthdr.rcvif = mf->m_pkthdr.rcvif;
}


/*
 *
 */

void
natpt_fixTCPUDP64cksum(int header, int proto, struct pcv *cv6, struct pcv *cv4)
{
	const char	*fn = __FUNCTION__;

	u_short		cksum, cksum6;
	struct ulc6	ulc6;
	struct ulc4	ulc4;

	bzero(&ulc6, sizeof(struct ulc6));
	bzero(&ulc4, sizeof(struct ulc4));

	if (cv6->aux && cv6->aux->ulc6) {
		ulc6 = *(cv6->aux->ulc6);
		cksum6 = cv6->aux->cksum6;
	} else {
		ulc6.ulc_src = cv6->ip.ip6->ip6_src;
		ulc6.ulc_dst = cv6->ip.ip6->ip6_dst;
		ulc6.ulc_len = htonl(cv6->plen);
		ulc6.ulc_pr  = cv6->ip_p;
		cksum6 = ntohs(cv6->pyld.tcp6->th_sum);
	}

	ulc4.ulc_src = cv4->ip.ip4->ip_src;
	ulc4.ulc_dst = cv4->ip.ip4->ip_dst;
	ulc4.ulc_len = htons(cv4->plen);
	ulc4.ulc_pr  = cv4->ip_p;

	switch (proto) {
	case IPPROTO_TCP:
		if (!cv6->aux || !cv6->aux->ulc6) {
			ulc6.ulc_tu.th.th_sport = cv6->pyld.tcp6->th_sport;
			ulc6.ulc_tu.th.th_dport = cv6->pyld.tcp6->th_dport;
		}
		ulc4.ulc_tu.th.th_sport = cv4->pyld.tcp4->th_sport;
		ulc4.ulc_tu.th.th_dport = cv4->pyld.tcp4->th_dport;

		if (header == AF_INET6) {
			if (isDebug(D_CHECKSUM)) {			/* XXX */
				natpt_logMsg(LOG_DEBUG, "%s():", fn);
				natpt_log(LOG_DUMP, LOG_DEBUG, &ulc6, sizeof(ulc6));
				natpt_log(LOG_DUMP, LOG_DEBUG, &ulc4, sizeof(ulc4));
			}

			cksum = natpt_fixCksum(cksum6,
					       (u_char *)&ulc6, sizeof(struct ulc6),
					       (u_char *)&ulc4, sizeof(struct ulc4));
			cv4->pyld.tcp4->th_sum = htons(cksum);

			if (isDebug(D_CHECKSUM)) {			/* XXX */
				natpt_log(LOG_DUMP, LOG_DEBUG, cv6->ip.ip4, 32);
			}
		} else {
			cksum = natpt_fixCksum(ntohs(cv4->pyld.tcp4->th_sum),
					       (u_char *)&ulc4, sizeof(struct ulc4),
					       (u_char *)&ulc6, sizeof(struct ulc6));
			cv6->pyld.tcp6->th_sum = htons(cksum);
		}
		break;

	case IPPROTO_UDP:
		if (!cv6->aux || !cv6->aux->ulc6) {
			ulc6.ulc_tu.uh.uh_sport = cv6->pyld.udp->uh_sport;
			ulc6.ulc_tu.uh.uh_dport = cv6->pyld.udp->uh_dport;
		}
		ulc4.ulc_tu.uh.uh_sport = cv4->pyld.udp->uh_sport;
		ulc4.ulc_tu.uh.uh_dport = cv4->pyld.udp->uh_dport;

		if (header == AF_INET6) {
			cksum = natpt_fixCksum(cksum6,
					       (u_char *)&ulc6, sizeof(struct ulc6),
					       (u_char *)&ulc4, sizeof(struct ulc4));
			cv4->pyld.udp->uh_sum = htons(cksum);
		} else {
			cksum = natpt_fixCksum(ntohs(cv4->pyld.udp->uh_sum),
					       (u_char *)&ulc4, sizeof(struct ulc4),
					       (u_char *)&ulc6, sizeof(struct ulc6));
			cv6->pyld.udp->uh_sum = htons(cksum);
		}
		break;
	}
}


void
natpt_fixTCPUDP44cksum(int proto, struct pcv *cv4from, struct pcv *cv4to)
{
	u_short		cksum, cksum4;
	struct ulc4	from, to;

	bzero(&from, sizeof(struct ulc4));
	bzero(&to,   sizeof(struct ulc4));

	if (cv4from->aux && cv4from->aux->ulc4) {
		from = *(cv4from->aux->ulc4);
		cksum4 = cv4from->aux->cksum4;
	} else {
		from.ulc_src = cv4from->ip.ip4->ip_src;
		from.ulc_dst = cv4from->ip.ip4->ip_dst;
		from.ulc_len = htons(cv4from->plen);
		from.ulc_pr  = cv4from->ip_p;
		cksum4 = ntohs(cv4from->pyld.tcp4->th_sum);
	}

	to.ulc_src = cv4to->ip.ip4->ip_src;
	to.ulc_dst = cv4to->ip.ip4->ip_dst;
	to.ulc_len = htons(cv4to->plen);
	to.ulc_pr  = cv4to->ip_p;

	switch (proto) {
	case IPPROTO_TCP:
		if (!cv4from->aux || !cv4from->aux->ulc4) {
			from.ulc_tu.th.th_sport = cv4from->pyld.tcp4->th_sport;
			from.ulc_tu.th.th_dport = cv4from->pyld.tcp4->th_dport;
		}
		to.ulc_tu.th.th_sport = cv4to->pyld.tcp4->th_sport;
		to.ulc_tu.th.th_dport = cv4to->pyld.tcp4->th_dport;
		cksum = natpt_fixCksum(cksum4,
				       (u_char *)&from, sizeof(struct ulc4),
				       (u_char *)&to,	sizeof(struct ulc4));
		cv4to->pyld.tcp4->th_sum = htons(cksum);
		break;

	case IPPROTO_UDP:
		if (!cv4from->aux || !cv4from->aux->ulc4) {
			from.ulc_tu.uh.uh_sport = cv4from->pyld.udp->uh_sport;
			from.ulc_tu.uh.uh_dport = cv4from->pyld.udp->uh_dport;
		}
		to.ulc_tu.uh.uh_sport = cv4to->pyld.udp->uh_sport;
		to.ulc_tu.uh.uh_dport = cv4to->pyld.udp->uh_dport;
		cksum = natpt_fixCksum(cksum4,
				       (u_char *)&from, sizeof(struct ulc4),
				       (u_char *)&to,	sizeof(struct ulc4));
		cv4to->pyld.udp->uh_sum = htons(cksum);
		break;

	default:
		break;
	}

}


int
natpt_fixCksum(int cksum, u_char *optr, int olen, u_char *nptr, int nlen)
{
	long	x, old, new;

	x = ~cksum & 0xffff;

	while (olen) {
		if (olen == 1) {
			old = optr[0] * 256;
			x -= old & 0xff00;
			if ( x <= 0 ) { x--; x &= 0xffff; }
			break;
		} else {
			old = optr[0] * 256 + optr[1];
			x -= old & 0xffff;
			if ( x <= 0 ) { x--; x &= 0xffff; }
			optr += 2;
			olen -= 2;
		}
	}

	while (nlen) {
		if (nlen == 1) {
			new = nptr[0] * 256;
			x += new & 0xff00;
			if (x & 0x10000) { x++; x &= 0xffff; }
			break;
		} else {
			new = nptr[0] * 256 + nptr[1];
			x += new & 0xffff;
			if (x & 0x10000) { x++; x &= 0xffff; }
			nptr += 2;
			nlen -= 2;
		}
	}

	return (~x & 0xffff);
}
