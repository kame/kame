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
//#	$Id: natpt_trans.c,v 1.2 1999/12/15 06:33:35 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <sys/param.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/kernel.h>
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/systm.h>

#include <net/if.h>
#if defined(__bsdi__)
#include <net/route.h>
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_fsm.h>

#include <netinet6/ip6.h>
#include <netinet6/icmp6.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <netinet/tcp.h>
#else
#include <netinet6/tcp6.h>
#endif

#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_list.h>
#include <netinet6/ptr_var.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static MALLOC_DEFINE(M_PM, "SuMiRe", "Packet Management by SuMiRe");
#endif

/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int		 errno;
int		 ptr_initialized;
int		 ip6_protocol_tr;

void		 tr_icmp4EchoReply		__P((struct _cv *, struct _cv *));
void		 tr_icmp4Echo			__P((struct _cv *, struct _cv *));
void		 tr_icmp6EchoRequest		__P((struct _cv *, struct _cv *));
void		 tr_icmp6EchoReply		__P((struct _cv *, struct _cv *));

static	int	 maintainTcpStatus		__P((struct _cv *));
static	int	 _ptr_tcpfsm			__P((int, int, u_short, u_char));
static	int	 _ptr_tcpfsmSessOut		__P((int, short, u_char));
static	int	 _ptr_tcpfsmSessIn		__P((int, short, u_char));

static	void	 adjustUpperLayerChecksum	__P((int, struct _cv *, struct _cv *));
static	int	 adjustChecksum			__P((int, u_char *, int, u_char *, int));


/*
//##
//#------------------------------------------------------------------------
//#	Translating From IPv4 To IPv6
//#------------------------------------------------------------------------
*/

struct mbuf *
translatingIPv4(struct _cv *cv4, struct _pat *pata)
{
    struct timeval	 atv;
    struct mbuf		*m6 = NULL;

    microtime(&atv);
    cv4->ats->tstamp = atv.tv_sec;

    switch (cv4->ip_payload)
    {
      case IPPROTO_ICMP:
	m6 = translatingICMPv4(cv4, &pata->src, &pata->dst);
	break;

      case IPPROTO_TCP:
	m6 = translatingTCPv4(cv4, &pata->src, &pata->dst);
	break;

      case IPPROTO_UDP:
	break;
    }
    
    if (m6)
	m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;

    return (m6);
}


struct mbuf *
translatingICMPv4(struct _cv *cv4, struct ipaddr *src, struct ipaddr *dst)
{
    struct _cv		 cv6;
    struct mbuf		*m6;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct icmp		*icmp4;
    struct icmp6_hdr	*icmp6;

    ip4 = mtod(cv4->m, struct ip *);
    icmp4 = cv4->_payload._icmp4;
    
    {
	caddr_t		 icmp4end;
	int		 icmp4len;

	icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

	MGETHDR(m6, M_DONTWAIT, MT_HEADER);
	if (m6 == NULL)
	{
	    errno = ENOBUFS;
	    return (NULL);
	}
	if (MHLEN < (sizeof(struct ip6_hdr) + icmp4len))
	    MCLGET(m6, M_DONTWAIT);
    }

    cv6.m = m6;
    cv6._ip._ip6 = mtod(m6, struct ip6_hdr *);
    cv6._payload._caddr = (caddr_t)cv6._ip._ip6 + sizeof(struct ip6_hdr);

    ip6 = mtod(cv6.m,  struct ip6_hdr *);
    icmp6 = cv6._payload._icmp6;;

    ip6->ip6_flow = 0;
    ip6->ip6_vfc  &= ~IPV6_VERSION_MASK;
    ip6->ip6_vfc  |= IPV6_VERSION;
    ip6->ip6_plen = 0;						/* XXX */
    ip6->ip6_nxt  = IPPROTO_ICMPV6;
    ip6->ip6_hlim = ip4->ip_ttl -1;
    ip6->ip6_src  = src->u.in6;
    ip6->ip6_dst  = dst->u.in6;

    switch (icmp4->icmp_type)
    {
      case ICMP_ECHOREPLY:
	tr_icmp4EchoReply(cv4, &cv6);
	break;

      case ICMP_ECHO:
	tr_icmp4Echo(cv4, &cv6);
	break;

      default:
	m_freem(m6);
	return (NULL);
    }

    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_cksum = in6_cksum(cv6.m, IPPROTO_ICMPV6,
				   sizeof(struct ip6_hdr), ntohs(ip6->ip6_plen));

    return (m6);
}


void
tr_icmp4EchoReply(struct _cv *cv4, struct _cv *cv6)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_ECHO_REPLY;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;

    {
	int		 dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp4off, icmp6off;
	caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		 icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

	dlen = icmp4len - ICMP_MINLEN;
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	bcopy(icmp4off, icmp6off, dlen);

	ip6->ip6_plen = ntohs(sizeof(struct icmp6_hdr) + dlen);
	cv6->m->m_pkthdr.len
	  = cv6->m->m_len
	  = sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);
    }
}


void
tr_icmp4Echo(struct _cv *cv4, struct _cv *cv6)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;

    {
	int		 dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp4off, icmp6off;
	caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		 icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

	dlen = icmp4len - ICMP_MINLEN;
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	bcopy(icmp4off, icmp6off, dlen);

	ip6->ip6_plen = ntohs(sizeof(struct icmp6_hdr) + dlen);
	cv6->m->m_pkthdr.len
	  = cv6->m->m_len
	  = sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);
    }
}


struct mbuf *
translatingTCPv4(struct _cv *cv4, struct ipaddr *src, struct ipaddr *dst)
{
    struct _cv		 cv6;
    struct mbuf		*m6;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;

    if (cv4->m->m_hdr.mh_next != NULL)
    {
	ptr_debugProbe();
	return (NULL);
    }

    if (cv4->m->m_flags & M_EXT)
    {
	if (cv4->plen + sizeof(struct ip6_hdr) > MHLEN)
	{
	    struct mbuf	*m6next;

	    m6next = m_copym(cv4->m, 0, M_COPYALL, M_DONTWAIT);
	    ReturnEnobufs(m6next);

	    m6next->m_data += cv4->poff;
	    m6next->m_len  -= cv4->poff;

	    MGETHDR(m6, M_DONTWAIT, MT_HEADER);
	    ReturnEnobufs(m6);

	    m6->m_next	= m6next;
	    m6->m_data += (MHLEN - sizeof(struct ip6_hdr));
	    m6->m_len	= sizeof(struct ip6_hdr);
	    m6->m_pkthdr.len = sizeof(struct ip6_hdr) + cv4->plen;
	    ip6 = mtod(m6, struct ip6_hdr *);

	    cv6.m = m6;
	    cv6.ip_p = cv6.ip_payload = IPPROTO_TCP;
	    cv6._ip._ip6 = mtod(m6, struct ip6_hdr *);
	    cv6._payload._caddr = m6next->m_data;
	    cv6.plen = cv4->plen;
	    cv6.poff = 0;
	}
	else	/* (sizeof(struct ip6_hdr) + cv4->plen <= MHLEN)	*/
	{
	    caddr_t	tcp4;
	    caddr_t	tcp6;

	    MGETHDR(m6, M_DONTWAIT, MT_HEADER);
	    if (m6 == NULL)
	    {
		errno = ENOBUFS;
		return (NULL);
	    }

	    ip6 = mtod(m6, struct ip6_hdr *);
	    tcp4 = (caddr_t)cv4->_payload._tcp4;
	    tcp6 = (caddr_t)ip6 + sizeof(struct ip6_hdr);
	    bcopy(tcp4, tcp6, cv4->plen);

	    m6->m_pkthdr.len
		= m6->m_len
		= sizeof(struct ip6_hdr) + cv4->plen;

	    cv6.m = m6;
	    cv6.ip_p = cv6.ip_payload = IPPROTO_TCP;
	    cv6._ip._ip6 = mtod(m6, struct ip6_hdr *);
	    cv6._payload._caddr = (caddr_t)cv6._ip._ip6 + sizeof(struct ip6_hdr);
	    cv6.plen = cv4->plen;
	    cv6.poff = cv6._payload._caddr - (caddr_t)cv6._ip._ip6;
	}
    }
    else if (cv4->plen + sizeof(struct ip6_hdr) > MHLEN)
    {
	caddr_t	tcp4;
	caddr_t	tcp6;

	MGETHDR(m6, M_DONTWAIT, MT_HEADER);
	ReturnEnobufs(m6);
	MCLGET(m6, M_DONTWAIT);

	m6->m_data += 128;	/* make struct ether_header{} space. -- too many?	*/
	m6->m_pkthdr.len = m6->m_len   = sizeof(struct ip6_hdr) + cv4->plen;
	ip6 = mtod(m6, struct ip6_hdr *);

	tcp4 = (caddr_t)cv4->_payload._tcp4;
	tcp6 = (caddr_t)ip6 + sizeof(struct ip6_hdr);
	bcopy(tcp4, tcp6, cv4->plen);

	cv6.m = m6;
	cv6.ip_p = cv6.ip_payload = IPPROTO_TCP;
	cv6._ip._ip6 = mtod(m6, struct ip6_hdr *);
	cv6._payload._caddr = tcp6;
	cv6.plen = cv4->plen;
	cv6.poff = cv6._payload._caddr - (caddr_t)cv6._ip._ip6;
    }
    else
    {
	caddr_t	tcp4;
	caddr_t	tcp6;

	MGETHDR(m6, M_DONTWAIT, MT_HEADER);
	if (m6 == NULL)
	{
	    errno = ENOBUFS;
	    return (NULL);
	}

	cv6.m = m6;
	ip6 = mtod(m6, struct ip6_hdr *);
	tcp4 = (caddr_t)cv4->_payload._tcp4;
	tcp6 = (caddr_t)ip6 + sizeof(struct ip6_hdr);
	bcopy(tcp4, tcp6, cv4->plen);

	m6->m_pkthdr.len
	    = m6->m_len
	    = sizeof(struct ip6_hdr) + cv4->plen;

	cv6.ip_p = cv6.ip_payload = IPPROTO_TCP;
	cv6._ip._ip6 = mtod(m6, struct ip6_hdr *);
	cv6._payload._caddr = (caddr_t)cv6._ip._ip6 + sizeof(struct ip6_hdr);
	cv6.plen = cv4->plen;
	cv6.poff = cv6._payload._caddr - (caddr_t)cv6._ip._ip6;
    }

    cv6.ats = cv4->ats;

    ip4 = mtod(cv4->m, struct ip *);
    ip6->ip6_flow = 0;
    ip6->ip6_vfc  &= ~IPV6_VERSION_MASK;
    ip6->ip6_vfc  |= IPV6_VERSION;
    ip6->ip6_plen = htons(cv4->plen);
    ip6->ip6_nxt  = IPPROTO_TCP;
    ip6->ip6_hlim = ip4->ip_ttl -1;
    ip6->ip6_src  = src->u.in6;
    ip6->ip6_dst  = dst->u.in6;

    maintainTcpStatus(cv4);
    adjustUpperLayerChecksum(IPPROTO_IPV4, &cv6, cv4);

    cv6._payload._tcp6->th_sum = 0;
    cv6._payload._tcp6->th_sum
	= in6_cksum(cv6.m, IPPROTO_TCP, sizeof(struct ip6_hdr), cv6.plen);

#if	0
    printf("TCPv4: %8d %8d\n",
	   cv4->m->m_pkthdr.len - sizeof(struct ip),
	   cv6.m->m_pkthdr.len  - sizeof(struct ip6_hdr));
#endif

    return (m6);
}


/*
//##
//#------------------------------------------------------------------------
//#	Translating Form IPv6 To IPv4
//#------------------------------------------------------------------------
*/

struct mbuf *
translatingIPv6(struct _cv *cv6, struct _pat *pata)
{
    struct timeval	 atv;
    struct mbuf		*m4 = NULL;

    microtime(&atv);
    cv6->ats->tstamp = atv.tv_sec;

    switch (cv6->ip_payload)
    {
      case IPPROTO_ICMP:
	m4 = translatingICMPv6(cv6, &pata->src, &pata->dst);
	break;

      case IPPROTO_TCP:
	m4 = translatingTCPv6(cv6, &pata->src, &pata->dst);
	break;

      case IPPROTO_UDP:
	m4 = translatingUDPv6(cv6, &pata->src, &pata->dst);
	break;
    }

    if (m4)
    {
	struct ip	*ip4;

	ip4 = mtod(m4, struct ip *);
	ip4->ip_sum = 0;			/* Header checksum		*/
	ip4->ip_sum = in_cksum(m4, sizeof(struct ip));
	m4->m_pkthdr.rcvif = cv6->m->m_pkthdr.rcvif;
    }

    return (m4);
}


struct mbuf *
translatingICMPv6(struct _cv *cv6, struct ipaddr *src, struct ipaddr *dst)
{
    struct _cv		 cv4;
    struct mbuf		*m4;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct icmp		*icmp4;
    struct icmp6_hdr	*icmp6;
    
    ip6 = mtod(cv6->m, struct ip6_hdr *);
    icmp6 = cv6->_payload._icmp6;

    {
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->_payload._icmp6;

	MGETHDR(m4, M_DONTWAIT, MT_HEADER);
	if (m4 == NULL)
	{
	    errno = ENOBUFS;
	    return (NULL);
	}
	if (MHLEN < (sizeof(struct ip) + icmp6len))
	    MCLGET(m4, M_DONTWAIT);
    }

    cv4.m = m4;
    cv4._ip._ip4 = mtod(m4, struct ip *);
    cv4._payload._caddr = (caddr_t)cv4._ip._ip4 + sizeof(struct ip);

    ip4 = mtod(cv4.m,  struct ip *);
    icmp4 = cv4._payload._icmp4;

    ip4->ip_v	= IPVERSION;		/* IP version				*/
    ip4->ip_hl	= 5;			/* header length (no IPv4 option)	*/
    ip4->ip_tos = 0;			/* Type Of Service			*/
    ip4->ip_len = htons(ip6->ip6_plen);	/* Payload length			*/
    ip4->ip_id	= 0;			/* Identification			*/
    ip4->ip_off = 0;			/* flag and fragment offset		*/
    ip4->ip_ttl = ip6->ip6_hlim - 1;	/* Time To Live				*/
    ip4->ip_p	= cv6->ip_payload;	/* Final Payload			*/
    ip4->ip_src = src->u.in4;		/* source addresss			*/
    ip4->ip_dst = dst->u.in4;		/* destination address			*/

    switch (icmp6->icmp6_type)
    {
      case ICMP6_ECHO_REQUEST:
	tr_icmp6EchoRequest(cv6, &cv4);
	break;

      case ICMP6_ECHO_REPLY:
	tr_icmp6EchoReply(cv6, &cv4);
	break;

      default:
	m_freem(m4);
	return (NULL);
    }

    {
	int		 hlen;
	struct mbuf	*m4  = cv4.m;
	struct ip	*ip4 = cv4._ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;

	hlen = ip4->ip_hl << 2;
	m4->m_data += hlen;
	m4->m_len  -= hlen;
	icmp4->icmp_cksum = 0;
	icmp4->icmp_cksum = in_cksum(cv4.m, ip4->ip_len - hlen);
	m4->m_data -= hlen;
	m4->m_len  += hlen;
    }

    return (m4);
}


void
tr_icmp6EchoRequest(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;
    
    icmp4->icmp_type = ICMP_ECHO;
    icmp4->icmp_code = 0;
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;

    {
	int	dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp6off, icmp4off;
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->_payload._icmp6;

	dlen = icmp6len - sizeof(struct icmp6_hdr);
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	bcopy(icmp6off, icmp4off, dlen);

	ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
    }
}


void
tr_icmp6EchoReply(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;
    
    icmp4->icmp_type = ICMP_ECHOREPLY;
    icmp4->icmp_code = 0;
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;

    {
	int	dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp6off, icmp4off;
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->_payload._icmp6;

	dlen = icmp6len - sizeof(struct icmp6_hdr);
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	bcopy(icmp6off, icmp4off, dlen);

	ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
    }
}


struct mbuf *
translatingTCPv6(struct _cv *cv6, struct ipaddr *src, struct ipaddr *dst)
{
    struct _cv		 cv4;
    struct mbuf		*m4, *m4tcp;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;

    if (cv6->m->m_hdr.mh_next != NULL)
    {
	ptr_debugProbe();
	return (NULL);
    }

    if ((cv6->m->m_flags & M_EXT)
	&& (cv6->plen + sizeof(struct ip) > MHLEN))
    {
	m4 = m_copym(cv6->m, 0, M_COPYALL, M_DONTWAIT);
	ReturnEnobufs(m4);

	m4->m_data = cv6->_payload._caddr - sizeof(struct ip);
	m4->m_pkthdr.len = m4->m_len = sizeof(struct ip) + cv6->plen;
	ip4 = mtod(m4, struct ip *);

	cv4.m = m4;
	cv4.ip_p = cv4.ip_payload = IPPROTO_TCP;
	cv4.plen = cv6->plen;
	cv4.poff = sizeof(struct ip);
	cv4._ip._ip4 = mtod(m4, struct ip *);
	cv4._payload._caddr = (caddr_t)cv4._ip._ip4 + sizeof(struct ip);
    }
    else
    {
	int	tcp6len;
	caddr_t	tcp4;
	caddr_t	tcp6;

	MGETHDR(m4, M_DONTWAIT, MT_HEADER);
	ReturnEnobufs(m4);

	ip4 = mtod(m4, struct ip *);

	tcp4 = (caddr_t)ip4 + sizeof(struct ip);
	tcp6 = (caddr_t)cv6->_payload._tcp6;
	tcp6len = (cv6->m->m_data + cv6->m->m_len) - tcp6;
	bcopy(tcp6, tcp4, tcp6len);

	m4->m_pkthdr.len = m4->m_len = sizeof(struct ip) + tcp6len;

	cv4.m = m4;
	cv4.ip_p = cv4.ip_payload = IPPROTO_TCP;
	cv4.plen = tcp6len;
	cv4._ip._ip4 = mtod(m4, struct ip *);
	cv4._payload._caddr = (caddr_t)cv4._ip._ip4 + sizeof(struct ip);
    }

    cv4.ats = cv6->ats;

    ip6 = mtod(cv6->m, struct ip6_hdr *);
    ip4->ip_v	= IPVERSION;		/* IP version				*/
    ip4->ip_hl	= 5;			/* header length (no IPv4 option)	*/
    ip4->ip_tos = 0;			/* Type Of Service			*/
    ip4->ip_len = sizeof(struct ip) + ntohs(ip6->ip6_plen);
					/* Payload length			*/
    ip4->ip_id	= 0;			/* Identification			*/
    ip4->ip_off = 0;			/* flag and fragment offset		*/
    ip4->ip_ttl = ip6->ip6_hlim - 1;	/* Time To Live				*/
    ip4->ip_p	= cv6->ip_payload;	/* Final Payload			*/
    ip4->ip_src = src->u.in4;		/* source addresss			*/
    ip4->ip_dst = dst->u.in4;		/* destination address			*/

    maintainTcpStatus(cv6);
    adjustUpperLayerChecksum(IPPROTO_IPV6, cv6, &cv4);

    {
	int		 iphlen;
	struct ip	 save_ip;
	struct tcpiphdr	*ti;

	ti = mtod(cv4.m, struct tcpiphdr *);
	iphlen = ip4->ip_hl << 2;

	save_ip = *cv4._ip._ip4;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	bzero(ti->ti_x1, sizeof(ti->ti_x1));
#else
	ti->ti_next = ti->ti_prev = 0;
	ti->ti_x1 = 0;
#endif
	ti->ti_pr = IPPROTO_TCP;
	ti->ti_len = htons(cv4.m->m_pkthdr.len - iphlen);
	ti->ti_src = save_ip.ip_src;
	ti->ti_dst = save_ip.ip_dst;

	ti->ti_sum = 0;
	ti->ti_sum = in_cksum(cv4.m, cv4.m->m_pkthdr.len);
	*cv4._ip._ip4 = save_ip;
    }

#if	0
    printf("TCPv6:\t\t%8d %8d\n",
	   cv6->m->m_pkthdr.len - sizeof(struct ip6_hdr),
	   cv4.m->m_pkthdr.len  - sizeof(struct ip));
#endif

    return (m4);
}


struct mbuf *
translatingUDPv6(struct _cv *cv6, struct ipaddr *src, struct ipaddr *dst)
{
    struct _cv		 cv4;
    struct mbuf		*m4, *m4udp;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct udphdr	*udp4;
    struct udphdr	*udp6;

    ip6 = mtod(cv6->m, struct ip6_hdr *);
    udp6 = cv6->_payload._udp;
    
    if ((m4udp = m_copym(cv6->m, cv6->poff, M_COPYALL, M_DONTWAIT)) == NULL)
    {
	errno = ENOBUFS;
	return (NULL);
    }

    MGETHDR(m4, M_DONTWAIT, MT_HEADER);
    if (m4 == NULL)
    {
	errno = ENOBUFS;
	return (NULL);
    }
    
    
    m4->m_next = m4udp;
    m4->m_len  = sizeof(struct ip);
    m4->m_pkthdr.len = m4->m_len + m4udp->m_len;

    cv4.m = m4;
    cv4._ip._ip4 = mtod(m4, struct ip *);
    cv4._payload._caddr = (caddr_t)m4udp->m_data;

    ip4 = mtod(cv4.m, struct ip *);
    udp4 = cv4._payload._udp;

    ip4->ip_v	= IPVERSION;		/* IP version				*/
    ip4->ip_hl	= 5;			/* header length (no IPv4 option)	*/
    ip4->ip_tos = 0;			/* Type Of Service			*/
    ip4->ip_len = htons(ip6->ip6_plen);	/* Payload length			*/
    ip4->ip_id	= 0;			/* Identification			*/
    ip4->ip_off = 0;			/* flag and fragment offset		*/
    ip4->ip_ttl = ip6->ip6_hlim - 1;	/* Time To Live				*/
    ip4->ip_p	= cv6->ip_payload;	/* Final Payload			*/
    ip4->ip_src = src->u.in4;		/* source addresss			*/
    ip4->ip_dst = dst->u.in4;		/* destination address			*/

    return (m4);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static int
maintainTcpStatus(struct _cv *cv)
{
    struct _tSlot	*ats = cv->ats;
    struct _tcpstate	*ts;

    if (ats->ip_payload != IPPROTO_TCP)
	return (0);							/* XXX	*/

    if ((ts = ats->suit.tcp) == NULL)
    {
	MALLOC(ts, struct _tcpstate *, sizeof(struct _tcpstate), M_PM, M_DONTWAIT);
	if (ts == NULL)
	{
	    return (0);							/* XXX	*/
	}

	bzero(ts, sizeof(struct _tcpstate));
	
	ts->_state = TCPS_CLOSED;
	ats->suit.tcp = ts;
    }

    ts->_state
	= _ptr_tcpfsm(ats->session, cv->packet, ts->_state, cv->_payload._tcp4->th_flags);

    return (0);
}


static	int
_ptr_tcpfsm(int session, int inout, u_short state, u_char flags)
{
    int		rv;

    if (flags & TH_RST)
	return (TCPS_CLOSED);

    if (session == PTR_OUTBOUND)
	rv = _ptr_tcpfsmSessOut(inout, state, flags);
    else
	rv = _ptr_tcpfsmSessIn (inout, state, flags);

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#	_ptr_tcpfsmSessOut

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

static	int
_ptr_tcpfsmSessOut(int inout, short state, u_char flags)
{
    int     rv = state;

    switch (state)
    {
      case TCPS_CLOSED:
	if ((inout == PTR_OUTBOUND)
	    && (((flags & TH_SYN) != 0)
		&& (flags & TH_ACK) == 0))
	    rv = TCPS_SYN_SENT;
	break;

      case TCPS_SYN_SENT:
	if ((inout == PTR_INBOUND)
	    && (flags & (TH_SYN | TH_ACK)))
	    rv = TCPS_SYN_RECEIVED;
	break;

      case TCPS_SYN_RECEIVED:
	if ((inout == PTR_OUTBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_ESTABLISHED;
	break;

      case TCPS_ESTABLISHED:
	if ((inout == PTR_OUTBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_FIN_WAIT_1;
	break;

      case TCPS_FIN_WAIT_1:
	if (inout == PTR_INBOUND)
	{
	    if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
	    else if (flags & TH_ACK)		rv = TCPS_FIN_WAIT_2;
	    else if (flags & TH_FIN)		rv = TCPS_CLOSING;
	}
	break;

      case TCPS_CLOSING:
	if ((inout == PTR_OUTBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_TIME_WAIT;
	break;

      case TCPS_FIN_WAIT_2:
	if ((inout == PTR_INBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_TIME_WAIT;
	break;
    }

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#	_ptr_tcpfsmSessIn

	delta(start,		eps)			-> CLOSED
	delta(CLOSED,		TH_SYN & !TH_ACK)	-> SYN_RCVD
	delta(SYN_RCVD,		TH_ACK)			-> ESTABLISHED
	delta(ESTABLISHED,   in	TH_FIN)			-> CLOSE_WAIT
	delta(ESTABLISHED,  out	TH_FIN)			-> FIN_WAIT_1
	delta(CLOSE_WAIT,   out	TH_FIN)			-> LAST_ACK
	delta(FIN_WAIT_1,	TH_FIN & TH_ACK)	-> TIME_WAIT
	delta(FIN_WAIT_1,	TH_FIN)			-> CLOSING
	delta(FIN_WAIT_1,	TH_ACK)			-> FIN_WAIT_2
	delta(CLOSING,		TH_ACK)			-> TIME_WAIT
	delta(LAST_ACK),	TH_ACK)			-> CLOSED
	delta(FIN_WAIT_2,	TH_FIN)			-> TIME_WAIT
	delta(TIME_WAIT,	eps)			-> CLOSED

//#------------------------------------------------------------------------
*/

static	int
_ptr_tcpfsmSessIn(int inout, short state, u_char flags)
{
    int		rv = state;

    switch (state)
    {
      case TCPS_CLOSED:
	if ((inout == PTR_INBOUND)
	    && (((flags & TH_SYN) != 0)
		&& (flags & TH_ACK) == 0))
	    rv = TCPS_SYN_RECEIVED;
	break;

      case TCPS_SYN_RECEIVED:
	if ((inout == PTR_INBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_ESTABLISHED;
	break;

      case TCPS_ESTABLISHED:
	if ((inout == PTR_INBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_CLOSE_WAIT;
	if ((inout == PTR_OUTBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_FIN_WAIT_1;
	break;

      case TCPS_CLOSE_WAIT:
	if ((inout == PTR_OUTBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_LAST_ACK;
	break;

      case TCPS_FIN_WAIT_1:
	if (inout == PTR_INBOUND)
	{
	    if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
	    else if (flags & TH_FIN)		rv = TCPS_CLOSING;
	    else if (flags & TH_ACK)		rv = TCPS_FIN_WAIT_2;
	}
	break;

      case TCPS_CLOSING:
	if ((inout == PTR_INBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_TIME_WAIT;
	break;

      case TCPS_LAST_ACK:
	if ((inout == PTR_INBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_CLOSED;
	break;

      case TCPS_FIN_WAIT_2:
	if ((inout == PTR_INBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_TIME_WAIT;
	break;
    }
    
    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static void
adjustUpperLayerChecksum(int proto, struct _cv *cv6, struct _cv *cv4)
{
    u_short		cksum;
    struct ipovly	ip4;
    struct ulc
    {
	struct in6_addr	ulc_src;
	struct in6_addr	ulc_dst;
	u_long		ulc_len;
	u_char		ulc_zero[3];
	u_char		ulc_nxt;
    }			ulc;
    
    bzero(&ulc, sizeof(struct ulc));
    bzero(&ip4, sizeof(struct ipovly));

    ulc.ulc_src = cv6->_ip._ip6->ip6_src;
    ulc.ulc_dst = cv6->_ip._ip6->ip6_dst;
    ulc.ulc_len = htonl(cv6->plen);
    ulc.ulc_nxt = cv6->ip_p;

    ip4.ih_src = cv4->_ip._ip4->ip_src;
    ip4.ih_dst = cv4->_ip._ip4->ip_dst;
    ip4.ih_pr  = cv4->ip_p;
    ip4.ih_len = htons(cv4->plen);

    if (proto == IPPROTO_IPV6)
    {
	cksum = adjustChecksum(ntohs(cv6->_payload._tcp6->th_sum),
			       (u_char *)&ulc, sizeof(struct ulc),
			       (u_char *)&ip4, sizeof(struct ipovly));
	cv4->_payload._tcp4->th_sum = htons(cksum);
    }
    else
    {
	cksum = adjustChecksum(ntohs(cv4->_payload._tcp4->th_sum),
			       (u_char *)&ip4, sizeof(struct ipovly),
			       (u_char *)&ulc, sizeof(struct ulc));
	cv6->_payload._tcp6->th_sum = htons(cksum);
    }
}


static int
adjustChecksum(int cksum, u_char *optr, int olen, u_char *nptr, int nlen)
{
    long	x, old, new;
    
    x = ~cksum & 0xffff;

    while (olen) 
    {
	if (olen == 1)
	{
	    old = optr[0] * 256 + optr[1];
	    x -= old & 0xff00;
	    if ( x <= 0 ) { x--; x &= 0xffff; }
	    break;
	}	
	else
	{
	    old = optr[0] * 256 + optr[1];
	    x -= old & 0xffff;
	    if ( x <= 0 ) { x--; x &= 0xffff; }
	    optr += 2;
	    olen -= 2;
	}
    }

    while (nlen)
    {
	if (nlen == 1)	
	{
	    new = nptr[0] * 256 + nptr[1];
	    x += new & 0xff00;
	    if (x & 0x10000) { x++; x &= 0xffff; }
	    break;
	}
	else
	{
	    new = nptr[0] * 256 + nptr[1];
	    x += new & 0xffff;
	    if (x & 0x10000) { x++; x &= 0xffff; }
	    nptr += 2;
	    nlen -= 2;
	}
    }

    return (~x & 0xffff);
}
