/*	$KAME: natpt_dispatch.c,v 1.34 2001/12/12 14:15:09 fujisawa Exp $	*/

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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_soctl.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

int		ip6_protocol_tr;
int		natpt_initialized;
u_int		natpt_debug;
u_int		natpt_dump;
struct in6_addr	natpt_prefix;


/*
 *
 */

int		natpt_in6		__P((struct mbuf *, struct mbuf **));
int		natpt_in4		__P((struct mbuf *, struct mbuf **));
int		natpt_config6		__P((struct mbuf *, struct pcv *));
caddr_t		natpt_lastpyld		__P((struct mbuf *, int *, int *, struct ip6_frag **));
int		natpt_config4		__P((struct mbuf *, struct pcv *));

MALLOC_DEFINE(M_NATPT, "NATPT", "Network Address Translation - Protocol Translation");


/*
 *
 */

int
natpt_in6(struct mbuf *m6, struct mbuf **m4)
{
	const char	*fn = __FUNCTION__;

	struct pcv	 cv6;
	struct ip6_hdr	*ip6;
	struct in6_addr	 match;
	struct pAddr	*pad;

	if (natpt_initialized == 0)
		return (IPPROTO_IP);

	if (isDump(D_DIVEIN6))
		natpt_logMBuf(LOG_DEBUG, m6, "%s():", fn);

	ip6 = mtod(m6, struct ip6_hdr *);

	bcopy(&ip6->ip6_dst, &match, sizeof(struct in6_addr));
	match.s6_addr32[0] &= in6mask96.s6_addr32[0];
	match.s6_addr32[1] &= in6mask96.s6_addr32[1];
	match.s6_addr32[2] &= in6mask96.s6_addr32[2];
	match.s6_addr32[3] &= in6mask96.s6_addr32[3];

	if (!IN6_ARE_ADDR_EQUAL(&natpt_prefix, &match)) {
		if (isDump(D_IN6REJECT))
			natpt_logMBuf(LOG_DEBUG, m6,
				      "%s(): v6 translation rejected.", fn);

		return (IPPROTO_IP);
	}

	if (isDump(D_IN6ACCEPT))
		natpt_logMBuf(LOG_DEBUG, m6, "%s(): v6 translation accepted.", fn);

	if (natpt_config6(m6, &cv6) == IPPROTO_IP)
		return (IPPROTO_IP);

	if (cv6.ip.ip6->ip6_hlim <= IPV6_HLIMDEC) {
		icmp6_error(m6, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
		return (IPPROTO_DONE);	/* discard this packet without free */
	}

	if (cv6.fh) {
		struct cSlot	*acs;
		struct fragment	*frg;

		if ((cv6.fh->ip6f_offlg & IP6F_OFF_MASK) == 0) {
			/* first fragmented packet */
			if ((cv6.ats = natpt_lookForHash6(&cv6)) == NULL) {
				if ((acs = natpt_lookForRule6(&cv6)) == NULL)
					return (IPPROTO_IP);
				if ((cv6.ats = natpt_internHash6(acs, &cv6)) == NULL)
					return (IPPROTO_IP);
				if ((frg = natpt_internFragment6(&cv6)) == NULL)
					return (IPPROTO_IP);
				frg->tslot = cv6.ats;
			}
		} else {
			/* fragmented packet after the first */
			if ((cv6.ats = natpt_lookForFragment6(&cv6)) == NULL)
				return (IPPROTO_MAX);
		}
	} else {
		/* in case of regular packet */
		if (((cv6.ats = natpt_lookForHash6(&cv6)) == NULL)
		    && ((cv6.ats = natpt_checkICMP6return(&cv6)) != NULL)) {
			cv6.fromto = NATPT_TO;
		}

		if (cv6.ats == NULL) {
			struct cSlot	*acs;

			if ((acs = natpt_lookForRule6(&cv6)) == NULL)
				return (IPPROTO_IP);
			if ((cv6.ats = natpt_internHash6(acs, &cv6)) == NULL)
				return (IPPROTO_IP);
		}
	}

	if (cv6.fromto == NATPT_FROM) {
		pad = &cv6.ats->remote;
		cv6.ats->fromto++;
	} else {
		pad = &cv6.ats->local;
		cv6.ats->tofrom++;
	}

	if (cv6.fh && ((cv6.fh->ip6f_offlg & IP6F_OFF_MASK) != 0)) {
		/* fragmented packet after the first */
		if ((*m4 = natpt_translateFragment6(&cv6, pad)) == NULL)
			return (IPPROTO_MAX);
	} else {
		/* not fragmented or first fragmented packet */
		if ((*m4 = natpt_translateIPv6To4(&cv6, pad)) == NULL)
			return (IPPROTO_MAX);
	}

	return (IPPROTO_IPV4);
}


int
natpt_in4(struct mbuf *m4, struct mbuf **m6)
{
	const char	*fn = __FUNCTION__;

	struct pcv	 cv4;
	struct tSlot	*ats;
	struct pAddr	*pad;

	if (natpt_initialized == 0)
		return (IPPROTO_IP);

	if (isDump(D_DIVEIN4))
		natpt_logMBuf(LOG_DEBUG, m4, "%s():", fn);

	if (natpt_config4(m4, &cv4) == IPPROTO_IP)
		return (IPPROTO_IP);

	if (cv4.ip.ip4->ip_ttl <= IPTTLDEC) {
		n_long	dest = 0;

		icmp_error(m4, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
		return (IPPROTO_DONE);	/* discard this packet without free. */
	}

	if (isFragment(&cv4)) {
		struct cSlot	*acs;
		struct fragment	*frg;

		/* fragmented packet */
		if (isFirstFragment(&cv4)) {
			/* first fragmented packet */
			if ((cv4.ats = natpt_lookForHash4(&cv4)) == NULL) {
				if ((acs = natpt_lookForRule4(&cv4)) == NULL)
					return (IPPROTO_IP);
				if ((cv4.ats = natpt_internHash4(acs, &cv4)) == NULL)
					return (IPPROTO_IP);
				if ((frg = natpt_internFragment4(&cv4)) == NULL)
					return (IPPROTO_IP);
				frg->tslot = cv4.ats;
			}
		} else {
			/* fragmented packet after the first */
			if ((cv4.ats = natpt_lookForFragment4(&cv4)) == NULL)
				return (IPPROTO_MAX);
		}
	} else {
		/* regular packet */
		cv4.ats = natpt_lookForHash4(&cv4);
		if ((cv4.ats == NULL)
		    && ((ats = natpt_checkICMP(&cv4)) != NULL)) {
			cv4.fromto = NATPT_TO;
			cv4.flags |= NATPT_TRACEROUTE;
			cv4.ats = ats;
		}

		if (cv4.ats == NULL ) {
			struct cSlot	*csl;

			if ((csl = natpt_lookForRule4(&cv4)) == NULL)
				return (IPPROTO_IP);
			if ((cv4.ats = natpt_internHash4(csl, &cv4)) == NULL)
				return (IPPROTO_IP);
		}
	}

	if (cv4.fromto == NATPT_FROM) {
		pad = &cv4.ats->remote;
		cv4.ats->fromto++;
	} else {
		pad = &cv4.ats->local;
		cv4.ats->tofrom++;
	}

#ifdef NATPT_NAT
	if (pad->sa_family == AF_INET) {
		if (isNextFragment(&cv4)) {
			/* fragmented packet after the first */
			if ((*m6 = natpt_translateFragment4to4(&cv4, pad)) == NULL)
				return (IPPROTO_MAX);
		} else {
			/* not fragmented or first fragmented packet */
			if ((*m6 = natpt_translateIPv4To4(&cv4, pad)) == NULL)	/* XXX */
				return (IPPROTO_MAX);
		}
			return (IPPROTO_IPV4);
	} else
#endif
	{
		if (isNextFragment(&cv4)) {
			/* fragmented packet after the first */
			if ((*m6 = natpt_translateFragment4to6(&cv4, pad)) == NULL)
				return (IPPROTO_MAX);	/* discard this packet */
		} else {
			/* not fragmented or first fragmented packet */
			if ((*m6 = natpt_translateIPv4To6(&cv4, pad)) == NULL)	/* XXX */
				return (IPPROTO_MAX);	/* discard this packet */
		}
	}

	return (IPPROTO_IPV6);
}


int
natpt_config6(struct mbuf *m, struct pcv *cv6)
{
	int		 proto;
	int		 offset;
	caddr_t		 tcpudp;

	bzero(cv6, sizeof(struct pcv));
	cv6->sa_family = AF_INET6;
	cv6->m = m;
	cv6->ip.ip6 = mtod(m, struct ip6_hdr *);

	if ((tcpudp = natpt_lastpyld(m, &proto, &offset, &cv6->fh))) {
		switch (proto) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			cv6->ip_p = proto;
			cv6->pyld.caddr = tcpudp;
			cv6->poff = offset;
			cv6->plen = (caddr_t)m->m_data + m->m_len - cv6->pyld.caddr;
			return (proto);
		}
	}

	return (IPPROTO_IP);
}


caddr_t
natpt_lastpyld(struct mbuf *m, int *proto, int *offset, struct ip6_frag **fh)
{
	struct ip6_hdr	*ip6;
	caddr_t		 ip6end;
	caddr_t		 pyld;

	ip6 = mtod(m, struct ip6_hdr *);
	ip6end = (caddr_t)(ip6 + 1) + ntohs(ip6->ip6_plen);
	if ((pyld = natpt_pyldaddr(ip6, ip6end, proto, fh)) == NULL)
		return (NULL);
	*offset = pyld - (caddr_t)ip6;
	return (pyld);
}


caddr_t
natpt_pyldaddr(struct ip6_hdr *ip6, caddr_t ip6end, int *proto, struct ip6_frag **fh)
{
	int		 nxt;
	int		 hdrsz = 0;
	caddr_t		 ip6ext;
	struct ip6_frag *ip6fh = NULL;

	if (proto)	*proto = 0;
	if (fh)		*fh = NULL;
	ip6ext = (caddr_t)((struct ip6_hdr *)(ip6 + 1));

	nxt = ip6->ip6_nxt;
	while ((nxt != IPPROTO_NONE) && (ip6ext < ip6end)) {
		switch (nxt) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			nxt = ((struct ip6_ext *)ip6ext)->ip6e_nxt;
			ip6ext += ((((struct ip6_ext *)ip6ext)->ip6e_len + 1) << 3);
			break;

		case IPPROTO_FRAGMENT:
			/*
			 * terminate parsing if it is not the first fragment,
			 * it does not make sense to parse through it.
			 */
			ip6fh = (struct ip6_frag *)ip6ext;
			if (fh != NULL)
				*fh = ip6fh;
			nxt = ((struct ip6_frag *)ip6ext)->ip6f_nxt;
			if (proto)
				*proto = nxt;
			ip6ext += sizeof(struct ip6_frag);
			if ((ip6fh->ip6f_offlg & IP6F_OFF_MASK) != 0)
				return (ip6ext);
			break;

		case IPPROTO_ICMPV6:
			hdrsz = sizeof(struct icmp6_hdr);
			goto wayOut;

		case IPPROTO_TCP:
			hdrsz = ((struct tcp6hdr *)ip6ext)->th_off << 2;
			goto wayOut;

		case IPPROTO_UDP:
			hdrsz = sizeof(struct udphdr);
			goto wayOut;

		default:
			return (NULL);
		}
	}

	return (NULL);

 wayOut:;
	if (ip6fh
	    && ((ip6fh->ip6f_offlg & IP6F_OFF_MASK) == 0)
	    && ((ip6end - ip6ext) < hdrsz))
		return (NULL);

	if (proto)
		*proto = nxt;
	return (ip6ext);
}


int
natpt_config4(struct mbuf *m, struct pcv *cv4)
{
	int		 hdrsz = 0;
	struct ip	*ip = mtod(m, struct ip *);
	caddr_t		 ip4end;
	caddr_t		 ip4pyld;

	bzero(cv4, sizeof(struct pcv));
	cv4->sa_family = AF_INET;
	cv4->m = m;
	cv4->ip.ip4 = ip;
	cv4->ip_p = ip->ip_p;
	ip4pyld = (caddr_t)ip + (ip->ip_hl << 2);
	ip4end	= mtod(m, caddr_t) + m->m_len;

	switch (ip->ip_p) {
	case IPPROTO_ICMP:
		hdrsz = ICMP_MINLEN;
		goto wayOut;

	case IPPROTO_TCP:
		hdrsz = ((struct tcphdr *)ip4pyld)->th_off << 2;
		goto wayOut;

	case IPPROTO_UDP:
		hdrsz = sizeof(struct udphdr);
		goto wayOut;
	}
	return (IPPROTO_IP);

 wayOut:;

	/* If a fragmented packet does not have enough upper layer header,
	 * drop this packet.
	 */
	if (((ip->ip_off & (IP_MF|IP_OFFMASK|IP_RF)) == 0)
	    && ((ip->ip_off & IP_OFFMASK) == 0)
	    && ((ip4end - ip4pyld) < hdrsz))
		return (IPPROTO_IP);

	cv4->pyld.caddr = ip4pyld;
	cv4->poff = cv4->pyld.caddr - (caddr_t)cv4->ip.ip4;
	cv4->plen = (caddr_t)m->m_data + m->m_len - cv4->pyld.caddr;

	if (((ip->ip_off & IP_OFFMASK) == 0)
	    && ((ip->ip_off & IP_MF) != 0))
		cv4->flags |= FIRST_FRAGMENT;
	if ((ip->ip_off & IP_OFFMASK) != 0)
		cv4->flags |= NEXT_FRAGMENT;
	if (NATPT_FRGHDRSZ + cv4->plen > IPV6_MMTU)
		cv4->flags |= NEED_FRAGMENT;

	return (ip->ip_p);
}


/*
 *
 */

int
natpt_setPrefix(caddr_t addr)
{
	natpt_prefix = ((struct natpt_msgBox *)addr)->m_in6addr;
	natpt_logIN6addr(LOG_INFO, "NATPT prefix: ", &natpt_prefix);

	return (0);
}


int
natpt_setValue(caddr_t addr)
{
	struct natpt_msgBox	*mbox = (struct natpt_msgBox *)addr;

	switch (mbox->flags) {
	case NATPT_DEBUG:
		natpt_debug = mbox->m_uint;
		break;

	case NATPT_DUMP:
		natpt_dump = mbox->m_uint;
		break;
	}

	return (0);
}


int
natpt_testLog(caddr_t addr)
{
	struct natpt_msgBox	*mbox = (struct natpt_msgBox *)addr;
	char			*fragile;

	fragile = (char *)malloc(mbox->size, M_NATPT, M_WAITOK);
	if (fragile == NULL)
		return (ENOBUFS);
	copyin(mbox->freight, fragile, mbox->size);

	natpt_logMsg(LOG_DEBUG, fragile, mbox->size);

	FREE(fragile, M_NATPT);
	return (0);
}


int
natpt_break()
{
	const char	*fn = __FUNCTION__;

	printf("%s(): break", fn);
	return (0);
}
