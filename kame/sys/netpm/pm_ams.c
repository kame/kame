/*	$KAME: pm_ams.c,v 1.2 2000/02/22 14:07:11 itojun Exp $	*/

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
//#	$SuMiRe: pm_ams.c,v 1.10 1998/09/14 19:49:34 shin Exp $
//#	$Id: pm_ams.c,v 1.2 2000/02/22 14:07:11 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <netpm/pm_include.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

Cell	*immVirtualPool;
Cell	*immRealPool;

extern	Cell		*selfAddr;
extern	struct _pmBox	*currentPmBox;


static	gAddr	    *_getGlobalAddr		__P((resCtrl *, struct in_addr *));
static	AliasPair   *_getDynamicMapEntry	__P((IPAssoc *, Cell *));
	gAddr	    *_assignAddress		__P((int, natRuleEnt *));
static	gAddr	    *_assignAddressFromSingleBlock	__P((int, addrBlock *));
static	gAddr	    *_assignAddressFromMultipleBlock	__P((int, addrBlock *));
static	gAddr	    *_assignAddress_port	__P((addrBlock *));
static	gAddr	    *_assignAddress_addr	__P((addrBlock *));
static	AliasPair   *_getImmMapEntry		__P((IPAssoc *, Cell *));
static	AliasPair   *_getNatStaticMapEntry	__P((IPAssoc *, Cell *));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

gAddr *
getGlobalAddr(natBox *nBox, struct in_addr *inaddr, int type)
{
    gAddr	*ga;

    switch (type)
    {
      case NAT_STATIC:
	if ((ga = _getGlobalAddr(&nBox->global, inaddr)) != NULL)
	{
	    if (ga->flags & ADDR_STATIC)
		return (NULL);
	    ga->flags |= ADDR_STATIC;
	    ga->linkc++;
	}
	break;
    
      case NAT_DYNAMIC:
	if ((ga = _getGlobalAddr(&nBox->global, inaddr)) != NULL)
	{
	    ga->flags |= ADDR_DYNAMIC;
	    ga->linkc++;
	}
	break;
    }

    return (ga);
}


static	gAddr *
_getGlobalAddr(resCtrl *rBox, struct in_addr *inaddr)
{
    Cell	*p;

    if (inaddr == NULL)
    {
	if (rBox->free == NULL)
	    return (NULL);

	p = rBox->free;
	rBox->free = CDR(p);
	CDR(p) = rBox->used;
	rBox->used = p;

	rBox->_free--;
	rBox->_used++;

	return ((gAddr *)CAR(p));
    }
    
    {
	Cell	*p;
	gAddr	*gac;

	for (p = rBox->free; p; p = CDR(p))
	{
	    gac = (gAddr *)CAR(p);
	    if (gac->addr.s_addr == inaddr->s_addr)
	    {
		if (LST_remove_elem(&rBox->free, gac) != NULL)
		{
		    rBox->_free--;
		    rBox->_used++;
		    LST_hookup_list(&rBox->used, gac);
		}
		return (gac);
	    }
	}

	for (p = rBox->used; p; p = CDR(p))
	{
	    gac = (gAddr *)CAR(p);
	    if (gac->addr.s_addr == inaddr->s_addr)
	    {
		return (gac);
	    }
	}
    }

    return (NULL);
}


gAddr	*
isGlobalAddr(resCtrl *rBox, struct in_addr *inaddr)
{
    Cell	*p;
    gAddr	*gac;

    if ((rBox == NULL)
	|| (inaddr == NULL))
	return (FALSE);

    for (p = rBox->free; p; p = CDR(p))
    {
	gac = (gAddr *)CAR(p);
	if (gac->addr.s_addr == inaddr->s_addr)
	    return (gac);
    }

    for (p = rBox->used; p; p = CDR(p))
    {
	gac = (gAddr *)CAR(p);
	if (gac->addr.s_addr == inaddr->s_addr)
	    return (gac);
    }

    return (FALSE);
}


void
getBackGlobalAddr(resCtrl *rCtrl, gAddr *gac, int type)
{
    gac->linkc--;

    if (type == NAT_STATIC)
	gac->flags &= ~ADDR_STATIC;
    else
    {
	if ((gac->linkc == 0)
	    || ((gac->linkc == 1)
		&& (gac->flags && ADDR_STATIC)))
	    gac->flags &= ~ADDR_DYNAMIC;
    }

    if (gac->linkc == 0)
    {
	rCtrl->_used--;
	rCtrl->_free++;
	LST_remove_elem(&rCtrl->used, gac);
	LST_hookup_list(&rCtrl->free, gac);
    }
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	NATBOX	currentPmBox->natBox

AliasPair *
pm_getMapEntry(IPAssoc *ipa)
{
    AliasPair	*ap;

    if (currentPmBox->natBox == NULL)
	return (NULL);

    if ((NATBOX->natStatic)
	&& ((ap = _getNatStaticMapEntry(ipa, NATBOX->natStatic)) != NULL))
	return (ap);

    if ((ipa->inout == OutBound)
	&& (NATBOX->natDynamic)
	&& ((ap = _getDynamicMapEntry(ipa, NATBOX->natDynamic)) != NULL))
	return (ap);

    if ((ipa->inout == InBound)
	&& (NATBOX->immBind)
	&& ((ap = _getImmMapEntry(ipa, NATBOX->immBind)) != NULL))
	return (ap);

    return (NULL);
}


static	AliasPair *
_getDynamicMapEntry(IPAssoc *ipa, Cell *ruleList)
{
    Cell	*p0, *p1;
    natRuleEnt	*nrt = NULL;
    u_long	 inaddr = ipa->ip_src.s_addr;
    u_short	 inport = ipa->th_sport;
    gAddr	*addr;
    static	 AliasPair	ap;

    for (p0 = ruleList; p0; p0 = CDR(p0))
    {
	nrt = (natRuleEnt *)CAR(p0);
	for (p1 = nrt->local; p1; p1 = CDR(p1))
	{
	    addrBlock	*in;

	    in = (addrBlock *)CAR(p1);

	    addr = NULL;
	    switch (in->type)
	    {
	      case IN_ADDR_SINGLE:
		if ((inaddr == in->addr[0].s_addr)
		    && ((in->port[0] == 0)
			|| (inport >= in->port[0] && inport<= in->port[1])))
		    addr = _assignAddress(ipa->ip_p, nrt);
		break;

	      case IN_ADDR_MASK:
		if (((inaddr & in->addr[1].s_addr) == in->ptrn.s_addr)
		    && ((in->port[0] == 0)
			|| (inport >= in->port[0] && inport<= in->port[1])))
		    addr = _assignAddress(ipa->ip_p, nrt);
		break;

	      case IN_ADDR_RANGE:
		if (((inaddr >= in->addr[0].s_addr) && (inaddr <= in->addr[1].s_addr))
		    && ((in->port[0] == 0)
			|| ((inport >= in->port[0]) && (inport <= in->port[1]))))
		    addr = _assignAddress(ipa->ip_p, nrt);
		break;
	    }
	    if (addr == NULL)
		continue;

	    bzero(&ap, sizeof(AliasPair));

	    ap.pm_type  = NAT_DYNAMIC;
	    ap.ip_p     = ipa->ip_p;
	    ap.ip_laddr = ipa->ip_src;
	    ap.ip_faddr = addr->addr;
	    ap.th_lport = ipa->th_sport;
	    ap.th_fport = addr->port;
	    ap._u.rule  = nrt;

	    return (&ap);
	}
    }

    return (NULL);
}


gAddr	*
_assignAddress(int proto, natRuleEnt *nrt)
{
    int		 cnt;
    Cell	*p;
    gAddr	*addr;
    addrBlock	*blk;

    if (nrt->gAddrLen == 1)
    {
	blk = (addrBlock *)CAR(nrt->foreign);
	addr = _assignAddressFromSingleBlock(proto, blk);
	return (addr);
    }

    for (p = nrt->foreign, cnt = nrt->gAddrLen; cnt > 0; p = CDR(p), cnt--)
    {
	blk = (addrBlock *)CAR(p);

	if ((addr = _assignAddressFromMultipleBlock(proto, blk)) != NULL)
	{
	    nrt->foreign = p;
	    return (addr);
	}
    }

    return (NULL);
}


static gAddr *
_assignAddressFromSingleBlock(int proto, addrBlock *blk)
{
    gAddr	*addr;

    if ((proto == IPPROTO_ICMP)
	|| (blk->policy == PAT_ADDRONLY))
    {
	if ((blk->gAddrCur == NULL)
	    || (CDR(blk->gAddrCur) == NULL))
	    blk->gAddrCur = blk->gList;
	else
	    blk->gAddrCur = CDR(blk->gAddrCur);

	return ((gAddr *)CAR(blk->gAddrCur));
    }

    switch (blk->policy)
    {
      default:
      case PAT_PORTFIRST:
	if (((addr = _assignAddress_port(blk)) == NULL)
	    && ((addr = _assignAddress_port(blk)) == NULL))	/* Try again */
	{
	    return (NULL);
	}
	return (addr);

      case PAT_ADDRFIRST:
	if (((addr = _assignAddress_addr(blk)) == NULL)
	    && ((addr = _assignAddress_addr(blk)) == NULL))	/* Try again */
	{
	    return (NULL);
	}
	return (addr);
    }

    return (NULL);
}


static gAddr *
_assignAddressFromMultipleBlock(int proto, addrBlock *blk)
{
    gAddr	*addr;

    if ((proto == IPPROTO_ICMP)
	|| (blk->policy == PAT_ADDRONLY))
    {
	if (blk->gAddrCur == NULL)
	    blk->gAddrCur = blk->gList;
	else if (CDR(blk->gAddrCur) != NULL)
	    blk->gAddrCur = CDR(blk->gAddrCur);
	else
	{
	    blk->gAddrCur = NULL;
	    return (NULL);
	}

	return ((gAddr *)CAR(blk->gAddrCur));
    }

    switch (blk->policy)
    {
      case PAT_PORTFIRST:
	if ((addr = _assignAddress_port(blk)) != NULL)
	{
	    return (addr);
	}
	break;

      case PAT_ADDRFIRST:
	if ((addr = _assignAddress_addr(blk)) != NULL)
	{
	    return (addr);
	}
	break;
    }

    return (NULL);
}


static gAddr *
_assignAddress_port(addrBlock *blk)
{
    gAddr	    *ga;
    static  gAddr    gaddr;

    if (blk->gAddrCur == NULL)
	blk->gAddrCur = blk->gList;

    if (blk->curport == 0)
    {
	blk->curport = blk->port[0] - 1;
	blk->pspace  = blk->port[1] - blk->port[0] + 2;
    }

    do
    {
	ga = (gAddr *)CAR(blk->gAddrCur);

	while (++blk->curport <= blk->port[1])
	{
	    blk->pspace--;
	    if (ckAppearance(blk->ip_p, ga->addr.s_addr, blk->curport) == NULL)
	    {
		gaddr.port = htons(blk->curport);
		gaddr.addr = ga->addr;
		return (&gaddr);
	    }
	}

	blk->curport = blk->port[0] - 1;
	blk->pspace  = blk->port[1] - blk->port[0] + 2;
	blk->gAddrCur = CDR(blk->gAddrCur);
    }	while (blk->gAddrCur);
    
    blk->curport = 0;
    return (NULL);
}


static	gAddr *
_assignAddress_addr(addrBlock *blk)
{
    Cell		*p;
    gAddr		*ga;
    static	gAddr	 gaddr;

    if (blk->gAddrCur == NULL)
	blk->gAddrCur = blk->gList;

    while (blk->curport <= blk->port[1])
    {
	for (p = blk->gAddrCur; p; p = CDR(p))
	{
	    ga = (gAddr *)CAR(p);
	    if (ckAppearance(blk->ip_p, ga->addr.s_addr, blk->curport) == NULL)
	    {
		gaddr.port = blk->curport;
		gaddr.addr = ga->addr;
		return (&gaddr);
	    }
	}
	blk->curport++;
    }

    blk->gAddrCur = NULL;
    return (NULL);
}


static	AliasPair *
_getImmMapEntry(IPAssoc *ipa, Cell *ruleList)
{
    Cell	*p, *q;
    virtualAddr	*va;
    realAddr	*ra;

    static	 AliasPair    ap;

    for (p = ruleList; p; p = CDR(p))
    {
	va = (virtualAddr *)CAR(p);
	if ((ipa->ip_dst.s_addr == va->virtualAddr.s_addr) && va->realAddrHead)
	{
	    ra = (realAddr *)CAR(va->realAddrHead);

	    ra->selected++;

	    if (CDR(va->realAddrHead))
	    {
		q = va->realAddrHead;
		va->realAddrHead = CDR(va->realAddrHead);
		CDR(va->realAddrTail) = q;
		va->realAddrTail = q;
	    }

	    ap.pm_type = NAT_LDIR;
	    ap.ip_p  = ipa->ip_p;
	    ap.th_lport = ipa->th_sport;
	    ap.th_fport = ipa->th_dport;
	    ap.ip_laddr.s_addr = ra->realAddr.s_addr;
	    ap.ip_faddr.s_addr = ipa->ip_src.s_addr;
	    ap._u.imm[0] = (caddr_t)va;
	    ap._u.imm[1] = (caddr_t)ra;
	    return (&ap);
	}
    }
    return (NULL);
}


static	AliasPair *
_getNatStaticMapEntry(IPAssoc *ipa, Cell *ruleList)
{
    Cell	*p;
    natRuleEnt	*nrt = NULL;
    u_long	 inaddr;
    u_short	 inport;

    static	 AliasPair    ap;

    bzero(&ap, sizeof(ap));

    for (p = ruleList; p; p = CDR(p))
    {
	addrBlock	*in;
	addrBlock	*ex;

	nrt = (natRuleEnt *)CAR(p);
	in = (addrBlock *)CAR(nrt->local);
	ex = (addrBlock *)CAR(nrt->foreign);

	if (ipa->inout == InBound)
	{
	    inaddr = ipa->ip_dst.s_addr;

	    if (((inaddr & ex->addr[1].s_addr) == ex->addr[0].s_addr)
		&& (in->addr[1].s_addr == 0xffffffff)
		&& (ex->addr[1].s_addr == 0xffffffff)
		&& (in->port[0] == 0)
		&& (ex->port[0] == 0))
	    {
		ap.pm_type = NAT_STATIC;
		ap.ip_p = ipa->ip_p;
		ap.th_lport = ipa->th_dport;
		ap.th_fport = ipa->th_dport;
		ap.ip_laddr.s_addr = in->addr[0].s_addr;
		ap.ip_faddr.s_addr = ipa->ip_src.s_addr;
		ap._u.rule = nrt;
		return (&ap);
	    }
	}
	else
	{
	    inaddr = ipa->ip_src.s_addr;
	    inport = ipa->th_sport;

	    if (((inaddr & in->addr[1].s_addr) == in->addr[0].s_addr)
		&& ((in->port[0] == 0)
		    || (inport >= in->port[0] && inport <= in->port[1])))
	    {
		ap.pm_type = NAT_STATIC;
		ap.ip_p = ipa->ip_p;
		ap.th_lport = ipa->th_sport;
		ap.th_fport = ipa->th_sport;
		ap.ip_laddr.s_addr = ipa->ip_src.s_addr;
		ap.ip_faddr.s_addr = ex->addr[0].s_addr;
		ap._u.rule = nrt;
		return (&ap);
	    }
	}	    
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
setVirtualAddr(struct in_addr *vaddr)
{
    Cell	*p;
    virtualAddr	*va;
    SelfAddr	*sa;

    for (p = immVirtualPool; p; p = CDR(p))
    {
	if (((virtualAddr *)CAR(p))->virtualAddr.s_addr == vaddr->s_addr)
	    return (EINVAL);
    }

    MALLOC(va, virtualAddr *, sizeof(virtualAddr), M_PM, M_WAITOK);
    bzero(va, sizeof(virtualAddr));

    va->NumOfRrealaddr = 0;
    va->virtualAddr = *vaddr;
    va->realAddrHead = va->realAddrTail = NULL;

    LST_hookup_list(&immVirtualPool, va);

    for (p = selfAddr; p; p = CDR(p))
    {
	sa = (SelfAddr *)CAR(p);

	if (sa->ifaddr.s_addr == vaddr->s_addr)
	    sa->addrflags |= LD_VIRTUAL;
    }

#if defined(PM_SYSLOG)
    log(LOG_NOTICE, "[ld] virtual %s\n", inet_ntoa(*vaddr));
#endif

    return (0);
}


int
unsetVirtualAddr(struct in_addr *vaddr)
{
    Cell	*p;
    virtualAddr	*va;
    SelfAddr	*sa;

    if (((va = isInVirtualAddress(vaddr)) != NULL)
	&& (va->NumOfRrealaddr == 0))
    {
	LST_remove_elem(&immVirtualPool, va);
	FREE(va, M_PM);
    }

    for (p = selfAddr; p; p = CDR(p))
    {
	sa = (SelfAddr *)CAR(p);

	if (sa->ifaddr.s_addr == vaddr->s_addr)
	    sa->addrflags &= ~LD_VIRTUAL;
    }
    
#if defined(PM_SYSLOG)
    log(LOG_NOTICE, "[ld] no virtual %s\n", inet_ntoa(*vaddr));
#endif

    return (0);
}


int
setRealAddr(struct in_addr *raddr)
{
    Cell	*p;
    realAddr	*ra;

    for (p = immRealPool; p; p = CDR(p))
    {
	if (((realAddr *)CAR(p))->realAddr.s_addr == raddr->s_addr)
	    return (EINVAL);
    }

    MALLOC(ra, realAddr *, sizeof(realAddr), M_PM, M_WAITOK);
    bzero(ra, sizeof(realAddr));

    ra->realAddr = *raddr;
    ra->threshold = 0;

    LST_hookup_list(&immRealPool, ra);

#if defined(PM_SYSLOG)
    log(LOG_NOTICE, "[ld] real %s\n", inet_ntoa(*raddr));
#endif

    return (0);
}


int
unsetRealAddr(struct in_addr *raddr)
{
    realAddr	*ra;

    if (((ra = isInRealAdddress(raddr)) != NULL)
	&& ((ra->ra_flags & RIP_BINDED) == 0))
    {
	LST_remove_elem(&immRealPool, ra);
	FREE(ra, M_PM);

#if defined(PM_SYSLOG)
	log(LOG_NOTICE, "[ld] no real %s\n", inet_ntoa(*raddr));
#endif
    }
    return (0);
}


#if defined(orphan)
virtualAddr *
hasRealAddress(struct in_addr *vaddr)
{
    Cell    *p;

    for (p = currentNatBox->immBind; p; p = CDR(p))
    {
	if (vaddr->s_addr == ((virtualAddr *)CAR(p))->virtualAddr.s_addr)
	    return ((virtualAddr *)CAR(p));
    }
    return (NULL);
}
#endif


virtualAddr *
isInVirtualAddress(struct in_addr *vaddr)
{
    Cell    *p;

    for (p = immVirtualPool; p; p = CDR(p))
    {
	if (vaddr->s_addr == ((virtualAddr *)CAR(p))->virtualAddr.s_addr)
	    return ((virtualAddr *)CAR(p));
    }
    return (NULL);
}


realAddr    *
isInRealAdddress(struct in_addr *raddr)
{
    Cell    *p;

    for (p = immRealPool; p; p = CDR(p))
    {
	if (raddr->s_addr == ((realAddr *)CAR(p))->realAddr.s_addr)
	    return ((realAddr *)CAR(p));
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
init_ams()
{
}
