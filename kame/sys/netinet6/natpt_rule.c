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
//#	$Id: natpt_rule.c,v 1.1 1999/08/12 12:41:13 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/systm.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netinet6/in6.h>
#include <netinet6/ip6.h>

#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_list.h>
#include <netinet6/ptr_soctl.h>
#include <netinet6/ptr_var.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

Cell		*ptrStatic;		/* list of struct _cSlot	*/
Cell		*ptrDynamic;		/* list of struct _cSlot	*/

extern	struct in6_addr	 ptr_faith_prefix;
extern	struct in6_addr	 ptr_faith_prefixmask;


static void	 _flushPtrRules		__P((struct _cell **));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

struct _cSlot	*
lookingForIncomingV4Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = ptrStatic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->remote.sa_family == AF_INET)
	    && (acs->remote.u.in4.s_addr == cv->_ip._ip4->ip_dst.s_addr))
	    return (acs);
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
	if ((acs->local.sa_family == AF_INET)
	    && (acs->local.u.in4.s_addr == cv->_ip._ip4->ip_dst.s_addr))
	    return (acs);
    }

    for (p = ptrDynamic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if (acs->local.sa_family != AF_INET)
	    continue;

	if (acs->type == PTR_FAITH)
	{
	    if ((cv->ip_payload == IPPROTO_TCP)
		&& (acs->local.u.in4.s_addr ==
		    (cv->_ip._ip4->ip_src.s_addr & acs->lmask.u.in4.s_addr)))
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
	if ((acs->remote.sa_family == AF_INET6)
	    && IN6_ARE_ADDR_EQUAL(&acs->remote.u.in6, &cv->_ip._ip6->ip6_src))
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
	if ((acs->local.sa_family == AF_INET6)
	    && IN6_ARE_ADDR_EQUAL(&acs->local.u.in6, &cv->_ip._ip6->ip6_src))
	    return (acs);
    }

    return (NULL);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
_ptrEnableTrans(caddr_t addr)
{
    ip6_protocol_tr = 1;
    return (0);
}


int
_ptrDisableTrans(caddr_t addr)
{
    ip6_protocol_tr = 0;
    return (0);
}


int
_ptrSetRule(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct _cSlot	*cst;
    struct sockaddr_in6	*load, *from, *to;
    Cell		**anchor;

#if	0
    if (((ifb = ptr_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = ptr_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);
#endif

    if ((mbx->flags & PTR_FAITH) != 0)
	return (_ptrSetFaithRule(addr));

   if ((mbx->flags & PTR_MASK) == PTR_STATIC)
	anchor = &ptrStatic;
    else
	anchor = &ptrDynamic;

    MALLOC(load, struct sockaddr_in6 *, SZSIN6 * 2, M_TEMP, M_WAITOK);
    copyin(mbx->freight, load, SZSIN6 * 2);
    from = load + 0;
    to   = load + 1;

    MALLOC(cst, struct _cSlot *, sizeof(struct _cSlot), M_TEMP, M_WAITOK);

    bzero(cst, sizeof(struct _cSlot));
    cst->type = mbx->flags;
    if (from->sin6_family == AF_INET)
    {
	cst->local.sa_family  = AF_INET;
	cst->local.u.in4 = ((struct sockaddr_in *)from)->sin_addr;
    }
    else
    {
	cst->local.sa_family  = AF_INET6;
	cst->local.u.in6 = from->sin6_addr;
    }
    
    if (to->sin6_family == AF_INET)
    {
	cst->remote.sa_family  = AF_INET;
	cst->remote.u.in4 = ((struct sockaddr_in *)to)->sin_addr;
    }
    else
    {
	cst->remote.sa_family  = AF_INET6;
	cst->remote.u.in6 = to->sin6_addr;
    }

    LST_hookup_list(anchor, cst);

    FREE(load, M_TEMP);
    return (0);
}


int
_ptrSetFaithRule(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct _cSlot	*cst;
    struct sockaddr_in	*load, *from, *mask;

    MALLOC(load, struct sockaddr_in *, SZSIN * 2, M_TEMP, M_WAITOK);
    copyin(mbx->freight, load, SZSIN * 2);
    from = load + 0;
    mask = load + 1;
    
    MALLOC(cst, struct _cSlot *, sizeof(struct _cSlot), M_TEMP, M_WAITOK);

    bzero(cst, sizeof(struct _cSlot));
    cst->type = PTR_FAITH;

    cst->local.sa_family = AF_INET;
    cst->local.u.in4 = from->sin_addr;
    cst->lmask.u.in4 = mask->sin_addr;

    LST_hookup_list(&ptrDynamic, cst);

    FREE(load, M_TEMP);
    return (0);
}


int
_ptrFlushRule(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;

    if (mbx->flags & PTR_STATIC)
	_flushPtrRules(&ptrStatic);
    else
	_flushPtrRules(&ptrDynamic);

    return (0);
}


int
_ptrSetPrefix(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct sockaddr_in6	*load;

    MALLOC(load, struct sockaddr_in6 *, SZSIN6 * 2, M_TEMP, M_WAITOK);
    copyin(mbx->freight, load, SZSIN6 * 2);

    if (mbx->flags & PREFIX_FAITH)
    {
	ptr_faith_prefix     =  (load + 0)->sin6_addr;
	ptr_faith_prefixmask =  (load + 1)->sin6_addr;
    }

    FREE(load, M_TEMP);
    return (0);
}



int
_ptrBreak()
{
    printf("break");

    return (0);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
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
