/*	$KAME: natpt_trans.c,v 1.70 2001/12/17 11:33:21 fujisawa Exp $	*/

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

#include <net/route.h>				/* for <netinet6/ip6_var.h>	*/

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

#include <netinet6/ip6_var.h>			/* for ip6_forward()		*/
#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

#define	FTP_DATA			20
#define	FTP_CONTROL			21
#define	TFTP				69

#if BYTE_ORDER == BIG_ENDIAN
#define	FTP4_PORT			0x504f5254
#define	FTP6_LPSV			0x4c505356
#define	FTP6_LPRT			0x4c505254
#define	FTP6_EPRT			0x45505254
#define	FTP6_EPSV			0x45505356
#else
#define	FTP4_PORT			0x54524f50
#define	FTP6_LPSV			0x5653504c
#define	FTP6_LPRT			0x5452504c
#define	FTP6_EPRT			0x54525045
#define	FTP6_EPSV			0x56535045
#endif

#define	FTPMINCMD			"CWD\r\n"
#define	FTPMINCMDLEN			strlen(FTPMINCMD)

#define	FTPS_PORT			1
#define	FTPS_LPRT			2
#define	FTPS_LPSV			3
#define	FTPS_EPRT			4
#define	FTPS_EPSV			5


struct ftpparam
{
	u_long		 cmd;
	caddr_t		 arg;		/* argument in mbuf if exist	*/
	caddr_t		 argend;
	struct sockaddr	*sa;		/* allocated			*/
};


#define PSEUDOHDRSZ			40	/* sizeof pseudo-header	*/
struct ulc6
{
	struct in6_addr	ulc_src, ulc_dst;
	u_long		ulc_len;
	u_char		ulc_zero[3];
	u_char		ulc_pr;
	union
	{
		struct icmp6_hdr ih;
		struct tcphdr	 th;
		struct udphdr	 uh;
	}		ulc_tu;
};

struct ulc4
{
	struct in_addr	ulc_src, ulc_dst;
	u_char		ulc_zero;
	u_char		ulc_pr;
	u_short		ulc_len;
	union
	{
		struct tcphdr	th;
		struct udphdr	uh;
	}		ulc_tu;
};


extern	int	udpcksum;	/* defined in netinet/udp_usrreq.c	*/

#ifdef __FreeBSD__
MALLOC_DECLARE(M_NATPT);
#endif


/*
 *
 */

/* for fujisawa's convenience */
/* struct mbuf	*natpt_translateIPv6To4	*/
/* struct mbuf	*natpt_translateIPv4To6	*/
/* struct mbuf	*natpt_translateIPv4To4 */

/* IPv6 -> IPv4 */
struct mbuf	*natpt_translateICMPv6To4	__P((struct pcv *, struct pAddr *));
void		 natpt_icmp6DstUnreach		__P((struct pcv *, struct pcv *));
void		 natpt_icmp6PacketTooBig	__P((struct pcv *, struct pcv *));
void		 natpt_icmp6TimeExceed		__P((struct pcv *, struct pcv *));
void		 natpt_icmp6ParamProb		__P((struct pcv *, struct pcv *));
void		 natpt_icmp6EchoRequest		__P((struct pcv *, struct pcv *));
void		 natpt_icmp6EchoReply		__P((struct pcv *, struct pcv *));
void		 natpt_icmp6MimicPayload	__P((struct pcv *, struct pcv *,
						     struct pAddr *));
struct mbuf	*natpt_translateTCPv6To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateUDPv6To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPUDPv6To4	__P((struct pcv *, struct pAddr *,
						     struct pcv *));
void		 natpt_translatePYLD6To4	__P((struct pcv *));
void		 natpt_watchUDP6		__P((struct pcv *));

/* IPv4 -> IPv6 */
struct mbuf	*natpt_translateICMPv4To6	__P((struct pcv *, struct pAddr *));
void		 natpt_icmp4EchoReply		__P((struct pcv *, struct pcv *));
void		 natpt_icmp4Unreach		__P((struct pcv *, struct pcv *,
						     struct pAddr *));
void		 natpt_icmp4Echo		__P((struct pcv *, struct pcv *));
void		 natpt_icmp4Timxceed		__P((struct pcv *, struct pcv *,
						     struct pAddr *));
void		 natpt_icmp4Paramprob		__P((struct pcv *, struct pcv *));
void		 natpt_icmp4MimicPayload	__P((struct pcv *, struct pcv *,
						     struct pAddr *));
struct mbuf	*natpt_translateTCPv4To6	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateUDPv4To6	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPUDPv4To6	__P((struct pcv *, struct pAddr *,
						     struct pcv *));
void		 natpt_translatePYLD4To6	__P((struct pcv *));

void		 natpt_translateFragment4to66	__P((struct pcv *, struct pAddr *));

/* IPv4 -> IPv4 */
struct mbuf	*natpt_translateICMPv4To4	__P((struct pcv *, struct pAddr *));
void		 natpt_icmp4TimeExceed		__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPv4To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateUDPv4To4	__P((struct pcv *, struct pAddr *));
struct mbuf	*natpt_translateTCPUDPv4To4	__P((struct pcv *, struct pAddr *,
						     struct pcv *));
void		 natpt_translatePYLD4To4	__P((struct pcv *));

/* FTP translation */
int		 natpt_translateFTP6CommandTo4	__P((struct pcv *));
int		 natpt_translateFTP4ReplyTo6	__P((struct pcv *));
struct ftpparam	*natpt_parseFTPdialogue		__P((caddr_t, caddr_t, struct ftpparam *));
struct sockaddr	*natpt_parseLPRT		__P((caddr_t, caddr_t, struct sockaddr_in6 *));
struct sockaddr	*natpt_parseEPRT		__P((caddr_t, caddr_t, struct sockaddr_in6 *));
struct sockaddr	*natpt_parsePORT		__P((caddr_t, caddr_t, struct sockaddr_in *));
struct sockaddr	*natpt_parse227			__P((caddr_t, caddr_t, struct sockaddr_in *));
int		 natpt_pton6			__P((caddr_t, caddr_t, struct in6_addr *));
int		 natpt_rewriteMbuf		__P((struct mbuf *, char *, int, char *,int));
void		 natpt_incrementSeq		__P((struct tcphdr *, int));
void		 natpt_decrementAck		__P((struct tcphdr *, int));

/* */

int		 natpt_updateTcpStatus		__P((struct pcv *));
int		 natpt_tcpfsm			__P((short state, int, u_char flags));
struct mbuf	*natpt_mgethdr			__P((int, int));
struct ip6_frag	*natpt_composeIPv6Hdr		__P((struct pcv *, struct pAddr *,
						     struct ip6_hdr *));
void		 natpt_composeIPv4Hdr		__P((struct pcv *, struct pAddr *,
						     struct ip *));
void		 natpt_adjustMBuf		__P((struct mbuf *, struct mbuf *));
void		 natpt_fixTCPUDP64cksum		__P((int, int, struct pcv *, struct pcv *));
void		 natpt_fixTCPUDP44cksum		__P((int, struct pcv *, struct pcv *));
int		 natpt_fixCksum			__P((int, u_char *, int, u_char *, int));


/*
 *	Translate from IPv6 to IPv4
 */

struct mbuf *
natpt_translateIPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	const char	*fn = __FUNCTION__;

	struct timeval	 atv;
	struct mbuf	*m4 = NULL;

	if (isDump(D_TRANSLATEIPV6))
		natpt_logIp6(LOG_DEBUG, cv6->ip.ip6, "%s():", fn);

	microtime(&atv);
	cv6->ats->tstamp = atv.tv_sec;

	switch (cv6->ip_p) {
	case IPPROTO_ICMPV6:
		m4 = natpt_translateICMPv6To4(cv6, pad);
		break;

	case IPPROTO_TCP:
		m4 = natpt_translateTCPv6To4(cv6, pad);
		break;

	case IPPROTO_UDP:
		m4 = natpt_translateUDPv6To4(cv6, pad);
		break;
	}

	if (m4)
		natpt_adjustMBuf(cv6->m, m4);

	return (m4);
}


struct mbuf *
natpt_translateICMPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	 cv4;
	struct mbuf	*m4;
	struct ip	*ip4;
	struct ip6_hdr	*ip6 = mtod(cv6->m, struct ip6_hdr *);
	struct icmp	 *icmp4;
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

	switch (cv6->pyld.icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		natpt_icmp6DstUnreach(cv6, &cv4);
		natpt_icmp6MimicPayload(cv6, &cv4, pad);
		break;

	case ICMP6_PACKET_TOO_BIG:
		natpt_icmp6PacketTooBig(cv6, &cv4);
		break;

	case ICMP6_TIME_EXCEEDED:
		natpt_icmp6TimeExceed(cv6, &cv4);
		natpt_icmp6MimicPayload(cv6, &cv4, pad);
		break;

	case ICMP6_PARAM_PROB:
		natpt_icmp6ParamProb(cv6, &cv4);
		break;

	case ICMP6_ECHO_REQUEST:
		natpt_icmp6EchoRequest(cv6, &cv4);
		break;

	case ICMP6_ECHO_REPLY:
		natpt_icmp6EchoReply(cv6, &cv4);
		break;

	case MLD6_LISTENER_QUERY:
	case MLD6_LISTENER_REPORT:
	case MLD6_LISTENER_DONE:
		m_freem(m4);		/* Single hop message.	Silently drop.	*/
		return (NULL);

	default:
		m_freem(m4);		/* Silently drop.			*/
		return (NULL);
	}

	icmp4 = cv4.pyld.icmp4;
	icmp6 = cv6->pyld.icmp6;
	icmp4->icmp_id	= icmp6->icmp6_id;
	icmp4->icmp_seq	= icmp6->icmp6_seq;

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
					(u_char *)&ulc6, PSEUDOHDRSZ+ICMP_MINLEN,
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
natpt_icmp6DstUnreach(struct pcv *cv6, struct pcv *cv4)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

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
		icmp4->icmp_code = ICMP_UNREACH_SRCFAIL;
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
natpt_icmp6PacketTooBig(struct pcv *cv6, struct pcv *cv4)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;

	icmp4->icmp_type = ICMP_UNREACH;
	icmp4->icmp_code = ICMP_UNREACH_NEEDFRAG;		/* do more	*/
}


void
natpt_icmp6TimeExceed(struct pcv *cv6, struct pcv *cv4)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp4->icmp_type = ICMP_TIMXCEED;
	icmp4->icmp_code = icmp6->icmp6_code;		/* code unchanged.	*/
}


void
natpt_icmp6ParamProb(struct pcv *cv6, struct pcv *cv4)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp4->icmp_type = ICMP_PARAMPROB;			/* do more	*/
	icmp4->icmp_code = 0;

	if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER) {
		icmp4->icmp_type = ICMP_UNREACH;
		icmp4->icmp_code = ICMP_UNREACH_PROTOCOL;
	}
}


void
natpt_icmp6EchoRequest(struct pcv *cv6, struct pcv *cv4)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;

	icmp4->icmp_type = ICMP_ECHO;
	icmp4->icmp_code = 0;

	{
		int		 dlen;
		struct ip	*ip4 = cv4->ip.ip4;
		struct ip6_hdr	*ip6 = cv6->ip.ip6;
		caddr_t		 icmp6off, icmp4off;
		caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
		int		 icmp6len = icmp6end - (caddr_t)cv6->pyld.icmp6;

		dlen = icmp6len - sizeof(struct icmp6_hdr);
		icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
		icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
		bcopy(icmp6off, icmp4off, dlen);

		ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
	}
}


void
natpt_icmp6EchoReply(struct pcv *cv6, struct pcv *cv4)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;

	icmp4->icmp_type = ICMP_ECHOREPLY;
	icmp4->icmp_code = 0;

	{
		int		 dlen;
		struct ip	*ip4 = cv4->ip.ip4;
		struct ip6_hdr	*ip6 = cv6->ip.ip6;
		caddr_t		 icmp6off, icmp4off;
		caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
		int		 icmp6len = icmp6end - (caddr_t)cv6->pyld.icmp6;

		dlen = icmp6len - sizeof(struct icmp6_hdr);
		icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
		icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
		bcopy(icmp6off, icmp4off, dlen);

		ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
	}
}


void
natpt_icmp6MimicPayload(struct pcv *cv6, struct pcv *cv4, struct pAddr *pad)
{
	int			 dgramlen;
	struct ip		*icmpip4, *ip4 = cv4->ip.ip4;
	struct ip6_hdr		*icmpip6, *ip6 = cv6->ip.ip6;
	struct icmp		*icmp4;
	struct icmp6_hdr	*icmp6;
	struct udphdr		*udp4;
	caddr_t			 ip6end;
	caddr_t			 icmpip6pyld, icmpip4pyld;

	ip6end = (caddr_t)(ip6 + 1) + ntohs(ip6->ip6_plen);
	icmp6 = cv6->pyld.icmp6;
	icmpip6 = (struct ip6_hdr *)((caddr_t)icmp6 + sizeof(struct icmp6_hdr));
	icmpip6pyld = natpt_pyldaddr(icmpip6, ip6end, NULL, NULL);
	if (icmpip6pyld == NULL)
		return ;

	icmp4 = cv4->pyld.icmp4;
	icmpip4 = (struct ip *)((caddr_t)icmp4 + ICMP_MINLEN);
	icmpip4pyld = (caddr_t)icmpip4 + sizeof(struct ip);

	dgramlen = (caddr_t)icmp6 + ntohs(ip6->ip6_plen) - icmpip6pyld;

	bzero(icmpip4, sizeof(struct ip));
	bcopy(icmpip6pyld, icmpip4pyld, dgramlen);

#ifdef _IP_VHL
	icmpip4->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof(struct ip) >> 2);
#else
	icmpip4->ip_v	= IPVERSION;
	icmpip4->ip_hl	= sizeof(struct ip) >> 2;
#endif
	icmpip4->ip_tos = 0;
	icmpip4->ip_len = ntohs(icmpip6->ip6_plen) + sizeof(struct ip);
	icmpip4->ip_id	= 0;
	icmpip4->ip_off = 0;
	icmpip4->ip_ttl = icmpip6->ip6_hlim;
	icmpip4->ip_p	= icmpip6->ip6_nxt;
	icmpip4->ip_src = pad->in4dst;
	icmpip4->ip_dst = pad->in4src;

	ip4->ip_len = sizeof(struct ip) + ICMP_MINLEN + sizeof(struct ip) + dgramlen;
	cv4->m->m_pkthdr.len
		= cv4->m->m_len
		= ip4->ip_len;

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
	case ICMP6_TIME_EXCEEDED:
		udp4 = (struct udphdr *)icmpip4pyld;
		if ((pad->port[1] != 0) || (pad->port[0] != 0)) {
			udp4->uh_sport = pad->port[0];
			udp4->uh_dport = pad->port[1];
		}
		break;
	}
}


struct mbuf *
natpt_translateTCPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	 cv4;
	struct mbuf	*m4;

	bzero(&cv4, sizeof(struct pcv));
	if ((m4 = natpt_translateTCPUDPv6To4(cv6, pad, &cv4)) == NULL)
		return (NULL);

	cv4.ip_p = IPPROTO_TCP;
	natpt_updateTcpStatus(&cv4);
	natpt_translatePYLD6To4(&cv4);
	natpt_fixTCPUDP64cksum(AF_INET6, IPPROTO_TCP, cv6, &cv4);
	return (m4);
}


struct mbuf *
natpt_translateUDPv6To4(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	 cv4;
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
	} else {
		ulc.ulc_tu.uh.uh_sport = cv6->pyld.udp->uh_sport;
		ulc.ulc_tu.uh.uh_dport = cv6->pyld.udp->uh_dport;
		aux.cksum6 = ntohs(cv6->pyld.udp->uh_sum);
	}

	aux.ulc6 = &ulc;
	cv6->aux = &aux;

	/*
	 * Start translation
	 */
	m4->m_data += sizeof(struct ip6_hdr) - sizeof(struct ip);
	m4->m_pkthdr.len = m4->m_len = sizeof(struct ip) + cv6->plen;

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

	th = (struct tcphdr *)(ip4 + 1);
	th->th_sport = pad->port[1];
	th->th_dport = pad->port[0];

	return (m4);
}


void
natpt_translatePYLD6To4(struct pcv *cv4)
{
	int		 delta = 0;
	struct tcphdr	*th4 = cv4->pyld.tcp4;
	struct tcpstate	*ts  = NULL;

	if (htons(cv4->pyld.tcp4->th_dport) == FTP_CONTROL) {
		if ((delta = natpt_translateFTP6CommandTo4(cv4)) != 0) {
			struct mbuf	*mbf = cv4->m;
			struct ip	*ip4 = cv4->ip.ip4;

			ip4->ip_len += delta;
			mbf->m_len += delta;
			if (mbf->m_flags & M_PKTHDR)
				mbf->m_pkthdr.len += delta;
		}

		if ((cv4->ats == NULL)
		    || ((ts = cv4->ats->suit.tcps) == NULL))
			return ;

		if (ts->delta[0]
		    && (cv4->fromto == NATPT_FROM))
			natpt_incrementSeq(th4, ts->delta[0]);

		if (ts->delta[1]
		    && (th4->th_flags & TH_ACK)
		    && (cv4->fromto == NATPT_FROM))
			natpt_decrementAck(th4, ts->delta[1]);

		if ((delta != 0)
		    && ((th4->th_seq != ts->seq[0])
			|| (th4->th_ack != ts->ack[0])))
		{
			ts->delta[0] += delta;
			ts->seq[0] = th4->th_seq;
			ts->ack[0] = th4->th_ack;
		}
	}
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
		cst->Local.port[1] = cv4->ats->remote.port[1];
		cst->Local.aType   = ADDR_SINGLE;

		cst->Remote.sa_family = AF_INET6;
		cst->Remote.in6Addr = cv4->ats->local.in6src;
		cst->Remote.port[1] = cv4->ats->local.port[0];
		cst->Remote.aType   = ADDR_SINGLE;

		natpt_prependRule(cst);
	}
}


struct mbuf *
natpt_translateFragment6(struct pcv *cv6, struct pAddr *pad)
{
	struct pcv	 cv4;
	struct mbuf	*m4;
	struct ip	*ip4;
	struct ip6_hdr	*ip6 = mtod(cv6->m, struct ip6_hdr *);

	caddr_t		 frag6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 frag6len = frag6end - cv6->pyld.caddr;

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

	struct timeval	 atv;
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
	}

	if (m6)
		m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;

	return (m6);
}


struct mbuf *
natpt_translateICMPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	struct pcv		 cv6;
	struct mbuf		*m6;
	struct ip		*ip4 = mtod(cv4->m, struct ip *);
	struct ip6_hdr		*ip6;
	struct icmp		*icmp4;
	struct icmp6_hdr	*icmp6;
	caddr_t			 icmp4end;
	int			 icmp4len;

	icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;

	if ((m6 = natpt_mgethdr(sizeof(struct ip6_hdr), icmp4len)) == NULL)
		return (NULL);

	cv6.m = m6;
	cv6.ip.ip6 = ip6 = mtod(m6, struct ip6_hdr *);
	cv6.pyld.caddr = (caddr_t)cv6.ip.ip6 + sizeof(struct ip6_hdr);
	cv6.fromto = cv4->fromto;
	cv6.flags  = cv4->flags;

	ip6->ip6_nxt  = IPPROTO_ICMPV6;
	natpt_composeIPv6Hdr(cv4, pad, ip6);
	ip6->ip6_src.s6_addr32[0] = natpt_prefix.s6_addr32[0];
	ip6->ip6_src.s6_addr32[1] = natpt_prefix.s6_addr32[1];
	ip6->ip6_src.s6_addr32[2] = natpt_prefix.s6_addr32[2];
	ip6->ip6_src.s6_addr32[3] = ip4->ip_src.s_addr;

	switch (cv4->pyld.icmp4->icmp_type) {
	case ICMP_ECHOREPLY:
		natpt_icmp4EchoReply(cv4, &cv6);
		break;

	case ICMP_UNREACH:
		natpt_icmp4Unreach(cv4, &cv6, pad);
		natpt_icmp4MimicPayload(cv4, &cv6, pad);
		break;

	case ICMP_ECHO:
		natpt_icmp4Echo(cv4, &cv6);
		break;

	case ICMP_TIMXCEED:
		natpt_icmp4Timxceed(cv4, &cv6, pad);
		natpt_icmp4MimicPayload(cv4, &cv6, pad);
		break;

	case ICMP_PARAMPROB:
		natpt_icmp4Paramprob(cv4, &cv6);
		break;

	case ICMP_REDIRECT:
	case ICMP_ROUTERADVERT:
	case ICMP_ROUTERSOLICIT:
		m_freem(m6);		/* Single hop message.	Silently drop.	*/
		return (NULL);

	case ICMP_SOURCEQUENCH:
	case ICMP_TSTAMP:
	case ICMP_TSTAMPREPLY:
	case ICMP_IREQ:
	case ICMP_IREQREPLY:
	case ICMP_MASKREQ:
	case ICMP_MASKREPLY:
		m_freem(m6);		/* Obsoleted in ICMPv6.	 Silently drop.	*/
		return (NULL);

	default:
		m_freem(m6);		/* Silently drop.			*/
		return (NULL);
	}

	icmp4 = cv4->pyld.icmp4;
	icmp6 = cv6.pyld.icmp6;
	icmp6->icmp6_id	 = icmp4->icmp_id;
	icmp6->icmp6_seq = icmp4->icmp_seq;

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in6_cksum(cv6.m, IPPROTO_ICMPV6,
				       sizeof(struct ip6_hdr), ntohs(ip6->ip6_plen));

	return (m6);
}


void
natpt_icmp4EchoReply(struct pcv *cv4, struct pcv *cv6)
{
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp6->icmp6_type = ICMP6_ECHO_REPLY;
	icmp6->icmp6_code = 0;

	{
		int		 dlen;
		struct ip	*ip4 = cv4->ip.ip4;
		struct ip6_hdr	*ip6 = cv6->ip.ip6;
		caddr_t		 icmp4off, icmp6off;
		caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
		int		 icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;

		dlen = icmp4len - ICMP_MINLEN;
		icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
		icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
		bcopy(icmp4off, icmp6off, dlen);

		ip6->ip6_plen = ntohs(sizeof(struct icmp6_hdr) + dlen);
		cv6->m->m_pkthdr.len
			= cv6->m->m_len
			= sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);
	}
}


void
natpt_icmp4Unreach(struct pcv *cv4, struct pcv *cv6, struct pAddr *pad)
{
	struct icmp		*icmp4 = cv4->pyld.icmp4;
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp6->icmp6_type = ICMP6_DST_UNREACH;
	icmp6->icmp6_code = 0;

	switch (icmp4->icmp_code) {
	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
		break;

	case ICMP_UNREACH_PROTOCOL:					/* do more	*/
		icmp6->icmp6_type = ICMP6_PARAM_PROB;
		icmp6->icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;		/* xxx		*/
		break;

	case ICMP_UNREACH_PORT:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT;
		break;

	case ICMP_UNREACH_NEEDFRAG:					/* do more	*/
		icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;
		icmp6->icmp6_code = ICMP6_PARAMPROB_HEADER;
		break;

	case ICMP_UNREACH_SRCFAIL:
		icmp6->icmp6_code = ICMP6_DST_UNREACH_NOTNEIGHBOR;
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


void
natpt_icmp4Echo(struct pcv *cv4, struct pcv *cv6)
{
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;

	{
		int		 dlen;
		struct ip	*ip4 = cv4->ip.ip4;
		struct ip6_hdr	*ip6 = cv6->ip.ip6;
		caddr_t		 icmp4off, icmp6off;
		caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
		int		 icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;

		dlen = icmp4len - ICMP_MINLEN;
		icmp4off = (caddr_t)(cv4->pyld.icmp4) + ICMP_MINLEN;
		icmp6off = (caddr_t)(cv6->pyld.icmp6) + sizeof(struct icmp6_hdr);
		bcopy(icmp4off, icmp6off, dlen);

		ip6->ip6_plen = ntohs(sizeof(struct icmp6_hdr) + dlen);
		cv6->m->m_pkthdr.len
			= cv6->m->m_len
			= sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);
	}
}


void
natpt_icmp4Timxceed(struct pcv *cv4, struct pcv *cv6, struct pAddr *pad)
{
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp6->icmp6_type = ICMP6_TIME_EXCEEDED;
	icmp6->icmp6_code = 0;
}


void
natpt_icmp4Paramprob(struct pcv *cv4, struct pcv *cv6)
{
	struct icmp6_hdr	*icmp6 = cv6->pyld.icmp6;

	icmp6->icmp6_type = ICMP6_PARAM_PROB;
	icmp6->icmp6_code = 0;
}


void
natpt_icmp4MimicPayload(struct pcv *cv4, struct pcv *cv6, struct pAddr *pad)
{
	int		 dgramlen;
	int		 icmp6dlen, icmp6rest;
	struct ip	*icmpip4, *ip4 = cv4->ip.ip4;
	struct ip6_hdr	*icmpip6, *ip6 = cv6->ip.ip6;
	caddr_t		 icmp4off, icmp4dgramoff;
	caddr_t		 icmp6off, icmp6dgramoff;
	caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		 icmp4len = icmp4end - (caddr_t)cv4->pyld.icmp4;

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
	icmpip6->ip6_plen = htons(ntohs(icmpip4->ip_len) - sizeof(struct ip6_hdr));
	icmpip6->ip6_nxt  = icmpip4->ip_p;
	icmpip6->ip6_hlim = icmpip4->ip_ttl;
	icmpip6->ip6_src  = pad->in6dst;
	icmpip6->ip6_dst  = pad->in6src;

	icmp6dlen = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + dgramlen;
	ip6->ip6_plen = ntohs(icmp6dlen);
	cv6->m->m_pkthdr.len
		= cv6->m->m_len
		= sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);

	switch (cv4->pyld.icmp4->icmp_type) {
	case ICMP_ECHO:		/* ping unreach	*/
		{
			struct icmp6_hdr	*icmp6;

			icmp6 = (struct icmp6_hdr *)((caddr_t)icmpip6 +
						     sizeof(struct ip6_hdr));
			icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
		}
		break;

	case ICMP_UNREACH:
	case ICMP_TIMXCEED:	/* traceroute return */
		if (cv6->flags & NATPT_TRACEROUTE) {
			struct udphdr	*icmpudp6;

			icmpudp6 = (struct udphdr *)((caddr_t)icmpip6 +
						     sizeof(struct ip6_hdr));
			icmpudp6->uh_sport = pad->port[0];
			icmpudp6->uh_dport = pad->port[1];
		}
		break;
	}
}


struct mbuf *
natpt_translateTCPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	struct pcv	 cv6;
	struct mbuf	*m6;

	bzero(&cv6, sizeof(struct pcv));
	if ((m6 = natpt_translateTCPUDPv4To6(cv4, pad, &cv6)) == NULL)
		return (NULL);

	cv6.ip_p = IPPROTO_TCP;
	natpt_updateTcpStatus(cv4);
	natpt_translatePYLD4To6(&cv6);
	if (cv6.ats->suit.tcps
	    && (cv6.ats->suit.tcps->rewrite[cv6.fromto] == 0)) {
		/* payload unchanged */
		natpt_fixTCPUDP64cksum(AF_INET, IPPROTO_TCP, &cv6, cv4);
	} else {
		struct tcp6hdr	*th;

		th = cv6.pyld.tcp6;
		th->th_sum = 0;
		th->th_sum = in6_cksum(cv6.m, IPPROTO_TCP, sizeof(struct ip6_hdr),
				       cv6.m->m_pkthdr.len - sizeof(struct ip6_hdr));
	}

	return (m6);
}


struct mbuf *
natpt_translateUDPv4To6(struct pcv *cv4, struct pAddr *pad)
{
	struct pcv	 cv6;
	struct mbuf	*m6;

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
	int		 hdrsz;

	/*
	 * Drop the fragmented packet which does not have enough
	 * header.
	 */
	hdrsz = sizeof(struct udphdr);
	if (cv4->ip_p == IPPROTO_TCP)
		hdrsz = sizeof(struct tcphdr);		/* ignore tcp option	*/
	if (isFragment(cv4) && cv4->plen < hdrsz)	/* do we need this?	*/
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
	if (isFragment(cv4))
		hdrsz += sizeof(struct ip6_frag);
	if ((m6 = natpt_mgethdr(hdrsz, cv4->plen)) == NULL)
		return (NULL);

	bzero(cv6, sizeof(struct pcv));
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
	cv6->pyld.tcp6->th_sport = pad->port[1];
	cv6->pyld.tcp6->th_dport = pad->port[0];

	m6->m_pkthdr.len = m6->m_len = hdrsz + cv4->plen;
	return (m6);
}


void
natpt_translatePYLD4To6(struct pcv *cv6)
{
	int		 delta = 0;
	struct tcphdr	*th6 = cv6->pyld.tcp6;
	struct tcpstate	*ts  = NULL;

	if (htons(cv6->pyld.tcp6->th_sport) == FTP_CONTROL) {
		if ((delta = natpt_translateFTP4ReplyTo6(cv6)) != 0) {
			struct mbuf	*mbf = cv6->m;
			struct ip6_hdr	*ip6 = cv6->ip.ip6;

			ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) + delta);
			mbf->m_len += delta;
			if (mbf->m_flags & M_PKTHDR)
				mbf->m_pkthdr.len += delta;
		}

		if ((cv6->ats == NULL)
		    || ((ts = cv6->ats->suit.tcps) == NULL))
			return ;

		if (ts->delta[1]
		    && (cv6->fromto == NATPT_TO))
			natpt_incrementSeq(th6, ts->delta[1]);

		if (ts->delta[0]
		    && (th6->th_flags & TH_ACK)
		    && (cv6->fromto == NATPT_TO))
			natpt_decrementAck(th6, ts->delta[0]);

		if ((delta != 0)
		    && ((th6->th_seq != ts->seq[1])
			|| (th6->th_ack != ts ->ack[1])))
		{
			ts->delta[1] += delta;
			ts->seq[1] = th6->th_seq;
			ts->ack[1] = th6->th_ack;
		}
	}

	return ;
}


struct mbuf *
natpt_translateFragment4to6(struct pcv *cv4, struct pAddr *pad)
{
	struct mbuf	*m6;
	struct ip6_hdr	*ip6;
	caddr_t		 pyld6;

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

	return (m6);
}


void
natpt_translateFragment4to66(struct pcv *cv4, struct pAddr *pad)
{
	int		 offset;
	int		 plen;
	struct mbuf	*m6;
	struct ip	*ip4 = mtod(cv4->m, struct ip *);
	struct ip6_hdr	*ip6,  ip6save;
	struct ip6_frag	*frg6, frg6save;
	caddr_t		 pyld4 = cv4->pyld.caddr;
	caddr_t		 pyld6;

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
	if ((isFirstFragment(cv4)
	     || needFragment(cv4))
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
	ip6_forward(m6, 1);			/* send first fragmented packet */

	/*
	 * Then, send second fragmented v6 packet.
	 */

	plen = cv4->plen - NATPT_MAXULP;
	if ((m6 = natpt_mgethdr(NATPT_FRGHDRSZ, plen)) == NULL)
		return ;

	ip6 = mtod(m6, struct ip6_hdr *);
	frg6 = (struct ip6_frag *)(ip6 + 1);
	pyld6 = (caddr_t)(ip6 + 1) + sizeof(struct ip6_frag);

	*ip6 = ip6save;
	*frg6 = frg6save;

	ip6->ip6_plen = htons(sizeof(struct ip6_frag) + plen);
	offset = ((ip4->ip_off & IP_OFFMASK) << 3) + NATPT_MAXULP;
	frg6->ip6f_offlg = htons(offset) & IP6F_OFF_MASK;
	if (ip4->ip_off & IP_MF)
		frg6->ip6f_offlg |= IP6F_MORE_FRAG;

	bcopy(cv4->pyld.caddr+NATPT_MAXULP, pyld6, plen);
	m6->m_pkthdr.len = m6->m_len = NATPT_FRGHDRSZ + plen;
	ip6_forward(m6, 1);			/* send second fragmented packet */
}


/*
 *	Translating From IPv4 to IPv4
 */

#ifdef NATPT_NAT
struct mbuf *
natpt_translateIPv4To4(struct pcv *cv4, struct pAddr *pad)
{
	const char	*fn = __FUNCTION__;

	struct timeval	 atv;
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
	struct pcv	 cv4to;
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
	case ICMP_ECHOREPLY:		/* do nothing	*/
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
	u_short		 cksum;
	struct ip	*ip4inner;
	struct udphdr	*udp4inner;
	struct
	{
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
	struct pcv	 cv4to;
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
	struct pcv	 cv4to;
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
	int		 delta = 0;
	struct tcphdr	*th4 = cv4to->pyld.tcp4;
	struct tcpstate	*ts  = NULL;

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
	struct pcv	 cv4to;
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

int
natpt_translateFTP6CommandTo4(struct pcv *cv4)
{
	int			 delta = 0;
	char			*tstr;
	caddr_t			 kb, kk;
	struct ip		*ip4 = cv4->ip.ip4;
	struct tcphdr		*th4 = cv4->pyld.tcp4;
	struct tcpstate		*ts;
	struct ftpparam		 ftp6;
	struct sockaddr_in6	 sin6;
	char			 wow[128];

	kb = (caddr_t)th4 + (th4->th_off << 2);
	kk = (caddr_t)ip4 + ip4->ip_len;

	if (((kk - kb) < FTPMINCMDLEN)
	    || (natpt_parseFTPdialogue(kb, kk, &ftp6) == NULL))
		return (0);

	ts = cv4->ats->suit.tcps;
	switch(ftp6.cmd) {
#ifdef NATPT_NAT
	case FTP4_PORT:
		{
			u_char			*h, *p;
			struct tSlot		*ats;
			struct pAddr		 local, remote;
			struct sockaddr_in	 sin;

			ts->ftpstate = FTPS_PORT;
			if (natpt_parsePORT(ftp6.arg, kk, &sin) == NULL)
				return (0);

			ats = cv4->ats;
			local = ats->local;
			local.port[0] = sin.sin_port;
			local.port[1] = htons(FTP_DATA);
			remote = ats->remote;
			remote.port[0] = htons(FTP_DATA);
			remote.port[1] = 0;	/* this port should be remapped	*/

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

			h = (char *)&remote.addr[1];
			p = (char *)&remote.port[1];
			snprintf(wow, sizeof(wow), "PORT %u,%u,%u,%u,%u,%u\r\n",
				 h[0], h[1], h[2], h[3],
				 p[0], p[1]);

			delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), wow, strlen(wow));
			ts->rewrite[cv4->fromto] = 1;
		}
		break;
#endif

	case FTP6_EPRT:
	case FTP6_LPRT:
		{
			char		*h, *p;
			struct tSlot	*ats;
			struct pAddr	 local, remote;

			if (ftp6.cmd == FTP6_LPRT) {
				ts->ftpstate = FTPS_LPRT;
				if (natpt_parseLPRT(ftp6.arg, kk, &sin6) == NULL)
					return (0);
			} else {
				ts->ftpstate = FTPS_EPRT;
				if (natpt_parseEPRT(ftp6.arg, kk, &sin6) == NULL)
					return (0);
			}

			ats = cv4->ats;
			local = ats->local;
			local.port[0] = sin6.sin6_port;
			local.port[1] = htons(FTP_DATA);
			remote = ats->remote;
			remote.port[0] = htons(FTP_DATA);
			remote.port[1] = 0;	/* this port should be remapped	*/

			if (natpt_remapRemote4Port(ats->csl, &remote) == NULL)
				return (0);

			if (natpt_openIncomingV4Conn(IPPROTO_TCP, &local, &remote) == NULL)
				return (0);

			h = (char *)&remote.addr[1];
			p = (char *)&remote.port[1];
			snprintf(wow, sizeof(wow), "PORT %u,%u,%u,%u,%u,%u\r\n",
				 h[0], h[1], h[2], h[3],
				 p[0], p[1]);

			delta = natpt_rewriteMbuf(cv4->m, kb, (kk-kb), wow, strlen(wow));
			ts->rewrite[cv4->fromto] = 1;
		}
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
}


int
natpt_translateFTP4ReplyTo6(struct pcv *cv6)
{
	int			 delta = 0;
	char			*d;
	u_char			*h, *p;
	caddr_t			 kb, kk;
	struct ip6_hdr		*ip6 = cv6->ip.ip6;
	struct tcphdr		*th6 = cv6->pyld.tcp6;
	struct tSlot		*ats;
	struct tcpstate		*ts;
	struct sockaddr_in	 sin;
	struct ftpparam		 ftp4;
	char			 Wow[128];

	kb = (caddr_t)th6 + (th6->th_off << 2);
	kk = (caddr_t)ip6 + sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
	if (((kk - kb) < FTPMINCMDLEN)
	    || (natpt_parseFTPdialogue(kb, kk, &ftp4) == NULL))
		return (0);

	ats = cv6->ats;
	ts  = ats->suit.tcps;
	switch (ts->ftpstate) {
	case FTPS_LPRT:
	case FTPS_EPRT:
		if (ftp4.cmd != 200)
			return (0);

		/* getting:   200 PORT command successful.	*/
		/* expecting: 200 EPRT command successful.	*/

		d = ftp4.arg;
		if ((d[0] == 'P') && (d[1] == 'O'))
		{
			d[0] = (ts->ftpstate == FTPS_LPRT) ? 'L' : 'E';
			d[1] = 'P';
		}
		ts->rewrite[cv6->fromto] = 1;
		break;

	case FTPS_LPSV:
		if (ftp4.cmd != 227)
			return (0);

		/* getting:   227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). */
		/* expecting: 228 Entering Long Passive Mode(...)	     */

		if (natpt_parse227(ftp4.arg, kk, &sin) == NULL)
			return (0);

		h = (char *)&ats->local.in6src;
		p = (char *)&sin.sin_port;
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

		/* getting:   227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). */
		/* expecting: 229 Entering Extended Passive Mode (|||6446|)  */

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
	int		 idx;
	union
	{
		char	byte[4];
		u_long	cmd;
	}	u;

	while ((kb < kk) && (*kb == ' '))
		kb++;					/* skip preceding blank	*/

	u.cmd = 0;
	if (isalpha(*kb)) {
		/* in case FTP command	*/
		for (idx = 0; idx < 4; idx++) {
			if (!isalpha(*kb) && (*kb != ' '))
				return (NULL);

			u.byte[idx] = islower(*kb) ? toupper(*kb) : *kb;
			if (isalpha(*kb))
				kb++;
		}
	} else if (isdigit(*kb)) {
		/* in case FTP reply	*/
		for (idx = 0; idx < 3; idx++, kb++) {
			if (!isdigit(*kb))
				return (NULL);

			u.cmd = u.cmd * 10 + *kb - '0';
		}
	}
	else
		return (NULL);		/* neither ftp command nor ftp reply	*/

	while ((kb < kk) && (*kb == ' '))
		kb++;

	if (kb >= kk)
		return (NULL);		/* no end of line (<CRLF>) found	*/

	bzero(ftp6, sizeof(struct ftpparam));
	ftp6->cmd = u.cmd;
	if ((*kb != '\r') && (*kb != '\n'))
		ftp6->arg = kb;

	return (ftp6);
}


struct sockaddr *
natpt_parseLPRT(caddr_t kb, caddr_t kk, struct sockaddr_in6 *sin6)
{
	int		 port, bite;
	int		 hal = 16;
	int		 pal = 2;
	u_char		*d;

	bzero(sin6, sizeof(struct sockaddr_in6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;

	if (kb + 5 > kk)			return (NULL);	/* 5 for "6,16," */
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
		}
		else
			bite = bite * 10 + *kb - '0';
	}

	if (hal != 0)			return (NULL);
	if (kb + 3 > kk)			return (NULL);	/* 3 for ",2," */
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
		}
		else
			port = port * 10 + *kb - '0';
	}

	if (pal != 1)			return (NULL);
	if (port > 0)
		*d = (port & 0xff);

	return ((struct sockaddr *)sin6);
}


struct sockaddr *
natpt_parseEPRT(caddr_t kb, caddr_t kk, struct sockaddr_in6 *sin6)
{
	int		port;
	caddr_t		km;

	bzero(sin6, sizeof(struct sockaddr_in6));

	if (*kb++ != '|')			return (NULL);
	switch (*kb++) {
	case '1':	sin6->sin6_family = AF_INET;	break;
	case '2':	sin6->sin6_family = AF_INET6;	break;
	default:
			return (NULL);
	}
	if (*kb++ != '|')			return (NULL);

	km = kb;
	while ((kb < kk) && (isxdigit(*kb) || (*kb == ':')))
		kb++;
	if (*kb != '|')			return (NULL);
	if (natpt_pton6(km, kb++, &sin6->sin6_addr) == 0)
		return (NULL);

	port = 0;
	while ((kb < kk) && (isdigit(*kb))) {
		port = port * 10 + *kb - '0';
		kb++;
	}
	if (*kb != '|')			return (NULL);

	sin6->sin6_port = htons(port);
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	return ((struct sockaddr *)sin6);
}


struct sockaddr *
natpt_parsePORT(caddr_t kb, caddr_t kk, struct sockaddr_in *sin)
{
	int		 cnt, bite;
	u_char		*d;

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
		}
		else
			bite = bite * 10 + *kb - '0';
	}

	if (cnt != 0)			return (NULL);

	kb++;
	d = (u_char *)&sin->sin_port;
	for (bite = 0, cnt = 2; (kb < kk) && (isdigit(*kb) || (*kb == ',')); kb++) {
		if (*kb == ',') {
			*d++ = (bite & 0xff);
			bite = 0;
			if (--cnt <= 0)
				break;
		}
		else
			bite = bite * 10 + *kb - '0';
	}

	if (cnt != 1)			return (NULL);
	if (bite > 0)
		*d = (bite & 0xff);

	return ((struct sockaddr *)sin);
}


struct sockaddr *
natpt_parse227(caddr_t kb, caddr_t kk, struct sockaddr_in *sin)
{
	int			 bite;
	u_int			 byte[6];
	u_short			 inport;
	struct in_addr		 inaddr;

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


int
natpt_pton6(caddr_t kb, caddr_t kk, struct in6_addr *addr6)
{
	int		ch, col, cols;
	u_int		v, val;
	u_char	       *d;
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
					return (0);	/* we've already seen "::".	*/

				for (p = kb, ncol = 0; p < kk; p++)
					if (*p == ':')
						ncol++;

				d = (u_char *)&bow + (7-ncol)*2;
				col++;
				cols++;
				continue;
			}
			else
				return (0);	/* COLON continued more than 3.	*/
		}
		else
			return (0);	/* illegal character	*/
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
		return (0xdead);			/* no room in mbuf	*/

	s = tstr;
	d = pyld;
	for (i = 0; i < tstrlen; i++)
		*d++ = *s++;

	return (tstrlen - pyldlen);
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
		if (inout == NATPT_TO)
		{
			if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
			else if (flags & TH_ACK)	rv = TCPS_FIN_WAIT_2;
			else if (flags & TH_FIN)	rv = TCPS_CLOSING;
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
	ip6->ip6_vfc |=	 IPV6_VERSION;
	ip6->ip6_plen = htons(ip4->ip_len - sizeof(struct ip));
	ip6->ip6_nxt  = (cv4->ip_p == IPPROTO_ICMP)
		? IPPROTO_ICMPV6
		: cv4->ip_p;
	ip6->ip6_hlim = ip4->ip_ttl;
	ip6->ip6_dst  = pad->in6src;
	ip6->ip6_src  = pad->in6dst;

	if (isFragment(cv4) || needFragment(cv4)) {
		frg6 = (struct ip6_frag *)(caddr_t)(ip6 + 1);
		frg6->ip6f_nxt = ip6->ip6_nxt;
		frg6->ip6f_reserved = 0;
		frg6->ip6f_offlg  = htons((ip4->ip_off & IP_OFFMASK) << 3);
		if ((ip4->ip_off & IP_MF) || needFragment(cv4))
			frg6->ip6f_offlg |= IP6F_MORE_FRAG;
		frg6->ip6f_ident  = 0;
		frg6->ip6f_ident |= ntohs(ip4->ip_id);
		HTONL(frg6->ip6f_ident);

		/* Get last fragmented packet length from given ip header.	*/
		if (!needFragment(cv4)
		    && ((ip4->ip_off & IP_OFFMASK) != 0)
		    && ((ip4->ip_off & IP_MF) == 0))
			ip6->ip6_plen
				= ip4->ip_len
				- sizeof(struct ip)
				+ sizeof(struct ip6_frag);
		else
			ip6->ip6_plen = IPV6_MMTU - sizeof(struct ip6_hdr);
		HTONS(ip6->ip6_plen);
		ip6->ip6_nxt  = IPPROTO_FRAGMENT;
	}

	return (frg6);
}


void
natpt_composeIPv4Hdr(struct pcv *cv6, struct pAddr *pad, struct ip *ip4)
{
	struct ip6_hdr	*ip6 = cv6->ip.ip6;

#ifdef _IP_VHL
	ip4->ip_vhl = IP_MAKE_VHL(IPVERSION, (sizeof(struct ip) >> 2));
#else
	ip4->ip_v   = IPVERSION;		/* IP version				*/
	ip4->ip_hl  = sizeof(struct ip) >> 2;	/* header length (no IPv4 option)	*/
#endif
	ip4->ip_tos = 0;			/* Type Of Service			*/
	ip4->ip_len = sizeof(struct ip) + ntohs(ip6->ip6_plen);
	ip4->ip_id  = 0;			/* Identification			*/
	ip4->ip_off = 0;			/* flag and fragment offset		*/
	ip4->ip_ttl = ip6->ip6_hlim;		/* Time To Live				*/
	ip4->ip_src = pad->in4dst;		/* source addresss			*/
	ip4->ip_dst = pad->in4src;		/* destination address			*/
	ip4->ip_p = (ip6->ip6_nxt == IPPROTO_ICMPV6)
		? IPPROTO_ICMP
		: ip6->ip6_nxt;

	if (cv6->fh) {
		u_int16_t	offlg = ntohs(cv6->fh->ip6f_offlg);

		ip4->ip_len = ntohs(ip6->ip6_plen) - sizeof(struct ip6_frag)
			+ sizeof(struct ip);
		ip4->ip_id = cv6->fh->ip6f_ident & 0xffff;

		ip4->ip_off = (offlg & 0xfff8) >> 3;
		if (offlg & 0x0001)
			ip4->ip_off |= IP_MF;
		ip4->ip_p = (cv6->fh->ip6f_nxt == IPPROTO_ICMPV6)
			? IPPROTO_ICMP
			: cv6->fh->ip6f_nxt;
	}
}


void
natpt_adjustMBuf(struct mbuf *mf, struct mbuf *mt)
{
	int		 mlen;
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
