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
//#	$Id: natpt_dispatch.c,v 1.1 1999/08/12 12:41:11 shin Exp $
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

#if defined(__FreeBSD__)
# include <sys/kernel.h>
#endif

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <netinet6/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/icmp6.h>

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

static	struct _cell	*ifBox;

struct ifnet	*ptr_ip6src;
struct in6_addr	 ip6_natpt_prefix
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};
struct in6_addr	 ptr_faith_prefix
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};
struct in6_addr	 ptr_faith_prefixmask
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};

int		 ptr_in4			__P((struct mbuf *, struct mbuf **));
int		 ptr_in6			__P((struct mbuf *, struct mbuf **));
int		 ptr_out4			__P((struct mbuf *, struct mbuf **));
int		 ptr_out6			__P((struct mbuf *, struct mbuf **));
int		 ptr_incomingIPv4		__P((int, struct mbuf *, struct mbuf **));
int		 ptr_outgoingIPv4		__P((int, struct mbuf *, struct mbuf **));
int		 ptr_incomingIPv6		__P((int, struct mbuf *, struct mbuf **));
int		 ptr_outgoingIPv6		__P((int, struct mbuf *, struct mbuf **));

int		 configCv4			__P((int, struct mbuf *, struct _cv *));
int		 configCv6			__P((int, struct mbuf *, struct _cv *));
caddr_t		 foundFinalPayload		__P((struct mbuf *, int *, int *));

#if defined(__FreeBSD__)
	void	 ptrattach			__P((void *));
#endif

static void	_ptrattach			__P((void));

extern void	init_hash			__P((void));
extern void	init_tslot			__P((void));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
ptr_in4(struct mbuf *m4, struct mbuf **m6)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    int		     rv = IPPROTO_IP;

    if (ptr_initialized == 0)
	return (IPPROTO_IP);			/* goto ours		*/

    ifnet = m4->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = ptr_incomingIPv4(PTR_INBOUND,  m4, m6);
	    else
		rv = ptr_outgoingIPv4(PTR_OUTBOUND, m4, m6);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}


int
ptr_in6(struct mbuf *m6, struct mbuf **m4)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    struct ip6_hdr  *ip6;
    struct in6_addr  cand;
    int		     rv = IPPROTO_IP;

    if (ptr_initialized == 0)
	return (IPPROTO_IP);			/* goto mcastcheck	*/

    ip6 = mtod(m6, struct ip6_hdr *);

    cand.s6_addr32[0] = ip6->ip6_src.s6_addr32[0] & ptr_faith_prefixmask.s6_addr32[0];
    cand.s6_addr32[1] = ip6->ip6_src.s6_addr32[1] & ptr_faith_prefixmask.s6_addr32[1];
    cand.s6_addr32[2] = ip6->ip6_src.s6_addr32[2] & ptr_faith_prefixmask.s6_addr32[2];
    cand.s6_addr32[3] = ip6->ip6_src.s6_addr32[3] & ptr_faith_prefixmask.s6_addr32[3];
    
    if ((cand.s6_addr32[0] != ptr_faith_prefix.s6_addr32[0])
	|| (cand.s6_addr32[1] != ptr_faith_prefix.s6_addr32[1])
	|| (cand.s6_addr32[2] != ptr_faith_prefix.s6_addr32[2])
	|| (cand.s6_addr32[3] != ptr_faith_prefix.s6_addr32[3]))
	return (IPPROTO_IP);			/* goto mcastcheck	*/

#if	0
    if ((ip6->ip6_dst.s6_addr32[0] != ip6_natpt_prefix.s6_addr32[0])
	|| (ip6->ip6_dst.s6_addr32[1] != ip6_natpt_prefix.s6_addr32[1])
	|| (ip6->ip6_dst.s6_addr32[2] != ip6_natpt_prefix.s6_addr32[2]))
	return (IPPROTO_IP);			/* goto mcastcheck	*/
#endif

    ifnet = m6->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = ptr_incomingIPv6(PTR_INBOUND,  m6, m4);
	    else
		rv = ptr_outgoingIPv6(PTR_OUTBOUND, m6, m4);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}


int
ptr_out4(struct mbuf *m4, struct mbuf **m6)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    int		     rv = IPPROTO_IP;

    ifnet = m4->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = ptr_outgoingIPv4(PTR_OUTBOUND, m4, m6);
	    else
		rv = ptr_incomingIPv4(PTR_INBOUND,  m4, m6);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}



int
ptr_out6(struct mbuf *m6, struct mbuf **m4)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    int		     rv = IPPROTO_IP;

    ifnet = m6->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = ptr_outgoingIPv6(PTR_OUTBOUND, m6, m4);
	    else
		rv = ptr_incomingIPv6(PTR_INBOUND,  m6, m4);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}


int
ptr_incomingIPv4(int sess, struct mbuf *m4, struct mbuf **m6)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct ip		*ip4;

    if ((rv = configCv4(sess, m4, &cv)) == IPPROTO_MAX)
	return (IPPROTO_MAX);			/* discard this packet	*/

    if ((cv.ats = lookingForIncomingV4Hash(&cv)) == NULL)
    {
	if ((acs = lookingForIncomingV4Rule(&cv)) == NULL)
	    return (IPPROTO_IP);		/* goto ours		*/

	ip4 = mtod(m4, struct ip *);
	if (ip4->ip_ttl <= IPTTLDEC)
	{
	    n_long	dest = 0;

	    icmp_error(m4, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
	    return (IPPROTO_MAX);		/* discard this packet	*/
	}
	
	if ((cv.ats = internIncomingV4Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);		/* goto ours		*/
    }

    if ((*m6 = translatingIPv4(&cv, &cv.ats->local)) != NULL)
	return (IPPROTO_IPV6);
    
    return (IPPROTO_MAX);			/* discard this packet	*/
}


int
ptr_outgoingIPv4(int sess, struct mbuf *m4, struct mbuf **m6)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct ip		*ip4;

    if ((rv = configCv4(sess, m4, &cv)) == IPPROTO_MAX)
	return (IPPROTO_MAX);			/* discard this packet	*/

    if ((cv.ats = lookingForOutgoingV4Hash(&cv)) == NULL)
    {
	if ((acs = lookingForOutgoingV4Rule(&cv)) == NULL)
	    return (IPPROTO_IP);		/* goto ours		*/

	ip4 = mtod(m4, struct ip *);
	if (ip4->ip_ttl <= IPTTLDEC)
	{
	    n_long	dest = 0;

	    icmp_error(m4, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
	    return (IPPROTO_MAX);		/* discard this packet	*/
	}
	
	if ((cv.ats = internOutgoingV4Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);		/* goto ours		*/
    }

    if ((*m6 = translatingIPv4(&cv, &cv.ats->remote)) != NULL)
	return (IPPROTO_IPV6);
    
    return (IPPROTO_MAX);			/* discard this packet	*/
}


int
ptr_incomingIPv6(int sess, struct mbuf *m6, struct mbuf **m4)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct ip6_hdr	*ip6;

    if ((rv = configCv6(sess, m6, &cv)) == IPPROTO_MAX)
	return (IPPROTO_MAX);			/* discard this packet	*/
    
    if ((cv.ats = lookingForIncomingV6Hash(&cv)) == NULL)
    {
	if ((acs = lookingForIncomingV6Rule(&cv)) == NULL)
	    return (IPPROTO_IP);		/* goto mcastcheck	*/

	ip6 = mtod(m6, struct ip6_hdr *);
	if (ip6->ip6_hlim <= IPV6_HLIMDEC)
	{
	    icmp6_error(m6, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
	    return (IPPROTO_MAX);		/* discard this packet	*/
	}

	if ((cv.ats = internIncomingV6Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);		/* goto mcastcheck	*/
    }

    if ((*m4 = translatingIPv6(&cv, &cv.ats->local)) != NULL)
	return (IPPROTO_IPV4);

    return (IPPROTO_MAX);			/* discard this packet	*/
}


int
ptr_outgoingIPv6(int sess, struct mbuf *m6, struct mbuf **m4)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct ip6_hdr	*ip6;

    if ((rv = configCv6(sess, m6, &cv)) == IPPROTO_MAX)
	return (IPPROTO_MAX);			/* discard this packet	*/
    
    if ((cv.ats = lookingForOutgoingV6Hash(&cv)) == NULL)
    {
	if ((acs = lookingForOutgoingV6Rule(&cv)) == NULL)
	    return (IPPROTO_IP);		/* goto mcastcheck	*/

	ip6 = mtod(m6, struct ip6_hdr *);
	if (ip6->ip6_hlim <= IPV6_HLIMDEC)
	{
	    icmp6_error(m6, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
	    return (IPPROTO_MAX);		/* discard this packet	*/
	}

	if ((cv.ats = internOutgoingV6Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);		/* goto mcastcheck	*/
    }

    if ((*m4 = translatingIPv6(&cv, &cv.ats->remote)) != NULL)
	return (IPPROTO_IPV4);

    return (IPPROTO_MAX);			/* discard this packet	*/
}


int
configCv4(int sess, struct mbuf *m, struct _cv *cv)
{
    struct ip	*ip = mtod(m, struct ip *);

    bzero(cv, sizeof(struct _cv));
    cv->ip_p = ip->ip_p;
    cv->m = m;
    cv->_ip._ip4 = ip;
    cv->packet  = sess;

    switch (ip->ip_p)
    {
      case IPPROTO_ICMP:
      case IPPROTO_TCP:
      case IPPROTO_UDP:
	cv->ip_payload = ip->ip_p;
	cv->_payload._caddr = (caddr_t)((u_long *)ip + ip->ip_hl);
	cv->poff = cv->_payload._caddr - (caddr_t)cv->_ip._ip4;
	cv->plen = (caddr_t)m->m_data + m->m_len - cv->_payload._caddr;
	return (ip->ip_p);
    }

    return (IPPROTO_MAX);
}


int
configCv6(int sess, struct mbuf *m, struct _cv *cv)
{
    int			 proto;
    int			 offset;
    struct ip6_hdr	*ip6;
    caddr_t		 tcpudp;

    bzero(cv, sizeof(struct _cv));
    cv->m = m;
    cv->_ip._ip6 = mtod(m, struct ip6_hdr *);
    cv->packet  = sess;
    
    if (tcpudp = foundFinalPayload(m, &proto, &offset))
    {
	switch (proto)
	{
	  case IPPROTO_ICMP:
	  case IPPROTO_ICMPV6:
	  case IPPROTO_TCP:
	  case IPPROTO_UDP:
	    cv->ip_p = proto;
	    cv->ip_payload = proto;
	    if (proto == IPPROTO_ICMPV6)
		cv->ip_payload = IPPROTO_ICMP;
	    cv->_payload._caddr = tcpudp;	
	    cv->poff = offset;
	    cv->plen = (caddr_t)m->m_data + m->m_len - cv->_payload._caddr;
	    return (proto);
	}
    }

    return (IPPROTO_MAX);
}


caddr_t
foundFinalPayload(struct mbuf *m, int *proto, int *offset)
{
    int			 nxt;
    int			 off;
    struct ip6_hdr	*ip6;
    struct ip6_ext	*ip6ext;

    ip6 = mtod(m, struct ip6_hdr *);
    nxt = ip6->ip6_nxt;
    off = sizeof(struct ip6_hdr);
    ip6ext = (struct ip6_ext *)((struct ip6_hdr *)(ip6 + 1));
    while (nxt != IPPROTO_NONE)
    {
	switch (nxt)
	{
	  case IPPROTO_HOPOPTS:
	  case IPPROTO_ROUTING:
	  case IPPROTO_FRAGMENT:
	  case IPPROTO_DSTOPTS:
	    nxt = ip6ext->ip6e_nxt;
	    off = ip6ext->ip6e_len;
	    ip6ext = (struct ip6_ext *)(((caddr_t)ip6ext) + ip6ext->ip6e_len);
	    break;

	  case IPPROTO_NONE:
	    *proto = IPPROTO_NONE;
	    *offset = off;
	    return (NULL);

	  case IPPROTO_ICMPV6:
	  case IPPROTO_TCP:
	  case IPPROTO_UDP:
	    *proto = nxt;
	    *offset = off;
	    return ((caddr_t)ip6ext);
	}
    }

    *proto = IPPROTO_NONE;
    return (NULL);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__)
PSEUDO_SET(ptrattach, ptr);

void
ptrattach(void *dummy)
{
    _ptrattach();
}
#endif


static void
_ptrattach()
{
    ptr_initialized = 0;
    ip6_protocol_tr = 0;

    init_tslot();
}

/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/


struct ifBox *
ptr_asIfBox(char *ifName)
{
    Cell	*p;

    for (p = ifBox; p; p = CDR(p))
    {
      if (strcmp(ifName, ((struct ifBox *)CAR(p))->ifName) == SAME)
	return ((struct ifBox *)CAR(p));
    }

    return (NULL);
}


struct ifBox *
ptr_setIfBox(char *ifName)
{
    struct ifnet	*p;
    struct ifBox	*q;
    char		 Wow[IFNAMSIZ];

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    TAILQ_FOREACH(p, &ifnet, if_link)
#else
    for (p = ifnet; p; p = p->if_next)
#endif
    {
	sprintf(Wow, "%s%d%c", p->if_name, p->if_unit, '\0');
	if (strcmp(ifName, Wow) != SAME)
	    continue;

	ptr_ip6src = p;

	MALLOC(q, struct ifBox *, sizeof(struct ifBox), M_PM, M_WAITOK);
	bzero(q, sizeof(struct ifBox));

	q->ifnet = p;
	sprintf(q->ifName, "%s%d%c", p->if_name, p->if_unit, '\0');

	LST_hookup_list((Cell**)&ifBox, q);
	return (q);
    }
    return (NULL);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
ptr_debugProbe()
{
    printf("DebugProbe");
}


void
ptr_initialize()
{
    struct ifnet	*ifn;
    struct ifaddr	*ifa;
    struct ifBox	*ibox;

    if (ptr_initialized)
	return;
    
    ptr_initialized = 1;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    TAILQ_FOREACH(ifn, &ifnet, if_link)
#else
    for (ifn = ifnet; ifn; ifn = ifn->if_next)
#endif
    {
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	TAILQ_FOREACH(ifa, &ifn->if_addrhead, ifa_link)
#else
	for (ifa = ifn->if_addrlist; ifa; ifa = ifa->ifa_next)
#endif
	{
	    if (((ifa->ifa_addr->sa_family) == AF_INET)
		|| ((ifa->ifa_addr->sa_family) == AF_INET6))
	    {
		MALLOC(ibox, struct ifBox *, sizeof(struct ifBox), M_TEMP, M_WAITOK);
		sprintf(ibox->ifName, "%s%d", ifn->if_name, ifn->if_unit);
		ibox->ifnet = ifn;
		ibox->side = NULL;
		LST_hookup_list(&ifBox, ibox);
		goto nextif;
	    }
	}
      nextif:
    }
}
