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
 *	$Id: natpt_rule.c,v 1.2 1999/12/25 02:35:31 fujisawa Exp $
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netinet6/in6.h>
#include <netinet6/ip6.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_soctl.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

Cell		*ptrStatic;		/* list of struct _cSlot	*/
Cell		*ptrDynamic;		/* list of struct _cSlot	*/

extern	struct in6_addr	 faith_prefix;
extern	struct in6_addr	 faith_prefixmask;
extern	struct in6_addr	 natpt_prefix;
extern	struct in6_addr	 natpt_prefixmask;


static void	 _flushPtrRules		__P((struct _cell **));


/*
 *
 */

struct _cSlot	*
lookingForIncomingV4Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = ptrStatic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->c.rfamily == AF_INET)
	    && (acs->remote.in4.s_addr == cv->_ip._ip4->ip_dst.s_addr))
	    return (acs);
    }

    for (p = ptrDynamic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);

	if ((acs->c.rfamily == AF_INET)
	    && ((acs->c.dir == NATPT_UNSPEC)
		|| (acs->c.dir == NATPT_INBOUND)))
	{
	    struct in_addr	mask4ed;

	    switch (acs->c.adrtype)
	    {
	      case ADDR_ANY:
		return (acs);

	      case ADDR_SINGLE:
		if (acs->remote.in4.s_addr == cv->_ip._ip4->ip_dst.s_addr)
		    return (acs);
		break;

	      case ADDR_MASK:
		mask4ed.s_addr = cv->_ip._ip4->ip_src.s_addr & acs->lmask.in4.s_addr;
		if (cv->_ip._ip4->ip_src.s_addr == mask4ed.s_addr)
		    return (acs);
		break;

	      case ADDR_RANGE:
		if ((cv->_ip._ip4->ip_src.s_addr >= acs->local.in4.s_addr)
		    && (cv->_ip._ip4->ip_src.s_addr <= acs->lmask.in4.s_addr))
		    return (acs);
		break;
	    }
	}
    }

    return (NULL);
}


struct _cSlot	*
lookingForOutgoingV4Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = ptrStatic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->c.lfamily == AF_INET)
	    && (acs->local.in4.s_addr == cv->_ip._ip4->ip_dst.s_addr))
	    return (acs);
    }

    for (p = ptrDynamic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if (acs->c.lfamily != AF_INET)
	    continue;

	if (acs->c.flags == NATPT_FAITH)
	{
	    if ((cv->ip_payload == IPPROTO_TCP)
		&& (acs->local.in4.s_addr ==
		    (cv->_ip._ip4->ip_src.s_addr & acs->lmask.in4.s_addr)))
		return (acs);
	}
    }

    return (NULL);
}


struct _cSlot	*
lookingForIncomingV6Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = ptrStatic; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->c.rfamily == AF_INET6)
	    && IN6_ARE_ADDR_EQUAL(&acs->remote.in6, &cv->_ip._ip6->ip6_src))
	    return (acs);
    }

    return (NULL);
}


struct _cSlot	*
lookingForOutgoingV6Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = ptrStatic; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->c.lfamily == AF_INET6)
	    && IN6_ARE_ADDR_EQUAL(&acs->local.in6, &cv->_ip._ip6->ip6_src))
	    return (acs);
    }

    for (p = ptrDynamic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->c.lfamily == AF_INET6)
	    && ((acs->c.dir == NATPT_UNSPEC)
		|| (acs->c.dir == NATPT_OUTBOUND)))
	{
	    struct in6_addr	mask6;

	    mask6.s6_addr32[0]
		= cv->_ip._ip6->ip6_src.s6_addr32[0] & acs->lmask.in6.s6_addr32[0];
	    mask6.s6_addr32[1]
		= cv->_ip._ip6->ip6_src.s6_addr32[1] & acs->lmask.in6.s6_addr32[1];
	    mask6.s6_addr32[2]
		= cv->_ip._ip6->ip6_src.s6_addr32[2] & acs->lmask.in6.s6_addr32[2];
	    mask6.s6_addr32[3]
		= cv->_ip._ip6->ip6_src.s6_addr32[3] & acs->lmask.in6.s6_addr32[3];
	    
	    if (IN6_ARE_ADDR_EQUAL(&mask6, &acs->aux->lcomp.in6))
		return (acs);
	}
    }

    return (NULL);
}


/*
 *
 */

int
_natptEnableTrans(caddr_t addr)
{
    char	Wow[64];

    sprintf(Wow, "map enable");
    natpt_logMsg(LOG_INFO, Wow, strlen(Wow));
    
    ip6_protocol_tr = 1;
    return (0);
}


int
_natptDisableTrans(caddr_t addr)
{
    char	Wow[64];

    sprintf(Wow, "map disable");
    natpt_logMsg(LOG_INFO, Wow, strlen(Wow));
    
    ip6_protocol_tr = 0;
    return (0);
}


int
_natptSetRule(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct _cSlot	*cst;
    Cell		**anchor;

#if	0
    if (((ifb = natpt_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = natpt_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);
#endif

    if ((mbx->flags & NATPT_FAITH) != 0)
	return (_natptSetFaithRule(addr));

    MALLOC(cst, struct _cSlot *, sizeof(struct _cSlot), M_TEMP, M_WAITOK);
    copyin(mbx->freight, cst, sizeof(struct _cSlot));

    anchor = &ptrStatic;
    if (cst->c.flags == NATPT_DYNAMIC)
    {
	struct _cSlotAux	*aux;

	MALLOC(aux, struct _cSlotAux *, sizeof(struct _cSlotAux), M_TEMP, M_WAITOK);
	bzero(aux, sizeof(struct _cSlotAux));
	if (cst->c.lfamily == AF_INET)
	    aux->lcomp.in4.s_addr = cst->local.in4.s_addr & cst->lmask.in4.s_addr;
	else
	{
	    aux->lcomp.in6.s6_addr32[0]
		= cst->local.in6.s6_addr32[0] & cst->lmask.in6.s6_addr32[0];
	    aux->lcomp.in6.s6_addr32[1]
		= cst->local.in6.s6_addr32[1] & cst->lmask.in6.s6_addr32[1];
	    aux->lcomp.in6.s6_addr32[2]
		= cst->local.in6.s6_addr32[2] & cst->lmask.in6.s6_addr32[2];
	    aux->lcomp.in6.s6_addr32[3]
		= cst->local.in6.s6_addr32[3] & cst->lmask.in6.s6_addr32[3];
	}
	cst->aux = aux;
	anchor = &ptrDynamic;
    }

    natpt_log(LOG_CSLOT, LOG_DEBUG, (void *)cst, sizeof(struct _cSlot));

    LST_hookup_list(anchor, cst);

    return (0);
}


int
_natptSetFaithRule(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct _cSlot	*cst;

    MALLOC(cst, struct _cSlot *, sizeof(struct _cSlot), M_TEMP, M_WAITOK);
    copyin(mbx->freight, cst, sizeof(struct _cSlot));

    LST_hookup_list(&ptrDynamic, cst);

    return (0);
}


int
_natptFlushRule(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;

    if (mbx->flags & NATPT_STATIC)
	_flushPtrRules(&ptrStatic);
    else
	_flushPtrRules(&ptrDynamic);

    return (0);
}


int
_natptSetPrefix(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct addrCouple	*load;

    MALLOC(load, struct addrCouple *, sizeof(struct addrCouple), M_TEMP, M_WAITOK);
    copyin(mbx->freight, load, SZSIN6 * 2);

    if (mbx->flags & PREFIX_FAITH)
    {
	faith_prefix	 =  load->addr[0].in6;
	faith_prefixmask =  load->addr[1].in6;
	
	natpt_logIN6addr(LOG_INFO, "FAITH prefix: ", &faith_prefix);
	natpt_logIN6addr(LOG_INFO, "FAITH prefixmask: ", &faith_prefixmask);
    }
    else if (mbx->flags & PREFIX_NATPT)
    {
	natpt_prefix	 =  load->addr[0].in6;
	natpt_prefixmask =  load->addr[1].in6;

	natpt_logIN6addr(LOG_INFO, "NATPT prefix: ", &natpt_prefix);
	natpt_logIN6addr(LOG_INFO, "NATPT prefixmask: ", &natpt_prefixmask);
    }

    FREE(load, M_TEMP);
    return (0);
}


int
_natptBreak()
{
    printf("break");

    return (0);
}


/*
 *
 */

static void
_flushPtrRules(struct _cell **anchor)
{
    struct _cell	*p0, *p1;
    struct _cSlot	*cslt;

    p0 = *anchor;
    while (p0)
    {
	p1 = p0;
	p0 = CDR(p0);

	cslt = (struct _cSlot *)CAR(p1);
	FREE(cslt, M_TEMP);
	LST_free(p1);
    }

    *anchor = NULL;
}
