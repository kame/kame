/*	$KAME: natpt_rule.c,v 1.24 2001/09/11 07:20:42 fujisawa Exp $	*/

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
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <netinet6/in6_var.h>
#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_soctl.h>
#include <netinet6/natpt_var.h>


TAILQ_HEAD(,cSlot)	csl_head;

#ifdef __FreeBSD__
MALLOC_DECLARE(M_NATPT);
#endif


/*
 *
 */

static int	 natpt_matchIn4addr	__P((struct pcv *, struct pAddr *));
static int	 natpt_matchIn6addr	__P((struct pcv *, struct pAddr *));


/*
 *
 */

struct cSlot *
natpt_lookForRule6(struct pcv *cv6)
{
	const char	*fn = __FUNCTION__;

	int		 s;
	struct cSlot	*acs;

	s = splnet();
	for (acs = TAILQ_FIRST(&csl_head);
	     acs;
	     acs = TAILQ_NEXT(acs, csl_list)) {
		if (acs->local.sa_family != AF_INET6)
			continue;

		if (acs->proto != 0) {
		    if ((cv6->ip_p == IPPROTO_ICMPV6)
			&& ((acs->proto & NATPT_ICMP) == 0))
			    continue;
		    if ((cv6->ip_p == IPPROTO_TCP)
			&& ((acs->proto & NATPT_TCP) == 0))
			    continue;
		    if ((cv6->ip_p == IPPROTO_UDP)
			&& ((acs->proto & NATPT_UDP) == 0))
			    continue;
		}

		if (natpt_matchIn6addr(cv6, &acs->local) != 0) {
			if (isDump(D_MATCHINGRULE6))
				natpt_logIp6(LOG_DEBUG, cv6->ip.ip6, "%s():", fn);
			cv6->fromto = NATPT_FROM;
			return (acs);
		}
	}
	splx(s);
	
	return (NULL);
}


struct cSlot *
natpt_lookForRule4(struct pcv *cv4)
{
	const char	*fn = __FUNCTION__;

	int		 s;
	struct cSlot	*csl;

	s = splnet();
	for (csl = TAILQ_FIRST(&csl_head);
	     csl;
	     csl = TAILQ_NEXT(csl, csl_list)) {
		if (csl->local.sa_family != AF_INET)
			continue;

		if (csl->proto != 0) {
		    if ((cv4->ip_p == IPPROTO_ICMP)
			&& ((csl->proto & NATPT_ICMP) == 0))
			    continue;
		    if ((cv4->ip_p == IPPROTO_TCP)
			&& ((csl->proto & NATPT_TCP) == 0))
			    continue;
		    if ((cv4->ip_p == IPPROTO_UDP)
			&& ((csl->proto & NATPT_UDP) == 0))
			    continue;
		}

		if (natpt_matchIn4addr(cv4, &csl->local) != 0) {
			if (isDump(D_MATCHINGRULE4))
				natpt_logIp4(LOG_DEBUG, cv4->ip.ip4, "%s():", fn);
			cv4->fromto = NATPT_FROM;
			return (csl);
		}
	}
	splx(s);
	
	return (NULL);
}


static int
natpt_matchIn6addr(struct pcv *cv6, struct pAddr *from)
{
	struct in6_addr	*in6from = &cv6->ip.ip6->ip6_src;
	struct in6_addr	 match;

	switch (from->aType) {
	case ADDR_ANY:
		goto proto;

	case ADDR_SINGLE:
		if (IN6_ARE_ADDR_EQUAL(in6from, &from->in6Addr))
			goto proto;
		return (0);

	case ADDR_MASK:
		bcopy(in6from, &match, sizeof(struct in6_addr));
		match.s6_addr32[0] &= from->in6Mask.s6_addr32[0];
		match.s6_addr32[1] &= from->in6Mask.s6_addr32[1];
		match.s6_addr32[2] &= from->in6Mask.s6_addr32[2];
		match.s6_addr32[3] &= from->in6Mask.s6_addr32[3];
	
		if (IN6_ARE_ADDR_EQUAL(&match, &from->in6Addr))
			goto proto;
		return (0);
	
	default:
		return (0);
	}

 proto:;
	if ((cv6->ip_p != IPPROTO_UDP)
	    && (cv6->ip_p != IPPROTO_TCP))
		return (1);

	if (from->port[0] == 0) {
		if (from->port[1] == 0) {
			return (1);
		} else {
			if (cv6->pyld.tcp6->th_dport == from->port[1])
				return (1);
		}
	} else {
		if (from->port[1] == 0) {
			if (cv6->pyld.tcp6->th_sport == from->port[0])
				return (1);
		} else {
			u_short	dport = ntohs(cv6->pyld.tcp6->th_sport);
			u_short	port0 = ntohs(from->port[0]);
			u_short	port1 = ntohs(from->port[1]);

			if ((dport >= port0) && (dport <= port1))
				return (1);
		}
	}

	return (0);
}


static int
natpt_matchIn4addr(struct pcv *cv4, struct pAddr *from)
{
	struct in_addr	in4from = cv4->ip.ip4->ip_src;
	struct in_addr	in4masked;

	switch (from->aType) {
	case ADDR_ANY:
		goto proto;

	case ADDR_SINGLE:
		if (in4from.s_addr == from->in4Addr.s_addr)
			goto proto;
		return (0);

	case ADDR_MASK:
		in4masked.s_addr = in4from.s_addr & from->in4Mask.s_addr;
		if (in4masked.s_addr == from->in4Addr.s_addr)
			goto proto;
		return (0);

	case ADDR_RANGE:
		if ((in4from.s_addr >= from->in4RangeStart.s_addr)
		    && (in4from.s_addr <= from->in4RangeEnd.s_addr))
			goto proto;
		return (0);

	default:
		return (0);
	}

 proto:;
	if ((cv4->ip_p != IPPROTO_UDP)
	    && (cv4->ip_p != IPPROTO_TCP))
		return (1);

	if (from->port[0] == 0) {
		if (from->port[1] == 0) {
			return (1);
		} else {
			if (cv4->pyld.tcp4->th_dport == from->port[1])
				return (1);
		}
	} else {
		if (from->port[1] == 0) {
			if (cv4->pyld.tcp4->th_sport == from->port[0])
				return (1);
		} else {
			u_short	dport = ntohs(cv4->pyld.tcp4->th_sport);
			u_short	port0 = ntohs(from->port[0]);
			u_short	port1 = ntohs(from->port[1]);

			if ((dport >= port0) && (dport <= port1))
				return (1);
		}
	}

	return (0);
}


/*
 *
 */

int
natpt_setRules(caddr_t addr)
{
	int			 s;
	struct timeval		 atv;
	struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;
	struct cSlot		*cst;
	struct pAddr		*from = NULL;

	MALLOC(cst, struct cSlot *, sizeof(struct cSlot), M_NATPT, M_NOWAIT);
	if (cst == NULL)
		return (ENOBUFS);

	copyin(mbx->freight, cst, sizeof(struct cSlot));
	from = &cst->local;
	if (from->aType == ADDR_MASK) {
		switch (from->sa_family) {
		case AF_INET:
			from->in4Mask.s_addr = htonl(0xffffffff << (32 - from->prefix));
			from->in4Addr.s_addr &= from->in4Mask.s_addr;
			break;

		case AF_INET6:
			in6_prefixlen2mask(&from->in6Mask, from->prefix);
			from->in6Addr.s6_addr32[0] &= from->in6Mask.s6_addr32[0];
			from->in6Addr.s6_addr32[1] &= from->in6Mask.s6_addr32[1];
			from->in6Addr.s6_addr32[2] &= from->in6Mask.s6_addr32[2];
			from->in6Addr.s6_addr32[3] &= from->in6Mask.s6_addr32[3];
			break;

		default:
		}
	}

	microtime(&atv);
	cst->tstamp = atv.tv_sec;
	natpt_log(LOG_CSLOT, LOG_DEBUG, (void *)cst, sizeof(struct cSlot));

	s = splnet();
	TAILQ_INSERT_TAIL(&csl_head, cst, csl_list);
	splx(s);

	return (0);
}


int
natpt_flushRules(caddr_t addr)
{
	int			 s;
	struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;

	struct cSlot		*csl, *csln;

	s = splnet();
	csl = TAILQ_FIRST(&csl_head);
	while (csl) {
		csln = TAILQ_NEXT(csl, csl_list);
		if (mbx->flags == NATPT_FLUSHALL) {
			TAILQ_REMOVE(&csl_head, csl, csl_list);
			FREE(csl, M_NATPT);
		}
		csl = csln;
	}
	splx(s);

	return (0);
}


int
natpt_setOnOff(int cmd)
{
	const char	*fn = __FUNCTION__;

	natpt_logMsg(LOG_INFO, "%s():", fn);

	switch (cmd) {
	case SIOCENBTRANS:
		ip6_protocol_tr = TRUE;
		break;

	case SIOCDSBTRANS:
		ip6_protocol_tr = FALSE;
		break;
	}
	
	return (0);
}


/*
 *
 */

void
natpt_init_rule()
{
	TAILQ_INIT(&csl_head);
}
