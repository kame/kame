/*	$KAME: pm_dispatch.c,v 1.2 2000/02/22 14:07:11 itojun Exp $	*/

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
//#	$SuMiRe: pm_dispatch.c,v 1.7 1998/09/14 19:49:37 shin Exp $
//#	$Id: pm_dispatch.c,v 1.2 2000/02/22 14:07:11 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include "netpm/pm_include.h"
#include "netpm/pm_log.h"

#include <sys/types.h>
#include <sys/kernel.h>

#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

Cell		*pmBoxList;			/* anchor of all pmbox	*/
struct _pmBox	*currentPmBox;

int		 initialized;
int		 doNatFil;
int		 fr_nat;
int		 fr_filter;
Cell		*selfAddr;			/* list of SelfAddr	*/

#if PMDEBUG
int		 pm_debug;
#endif

#define		NOMATCHRULEPOLYCY	PM_PASS


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	int	pm_dispatch	__P((InOut, natBox *, filBoxHalf *, struct ip *, struct mbuf *));
static	int	toUs		__P((struct ip *));
static	int	fromUs		__P((struct ip *));

int		init_dispatcher		__P((void));


#if defined(__FreeBSD__)
SYSCTL_NODE(_net_inet,    OID_AUTO, pm,     CTLFLAG_RW, 0, "pm");
SYSCTL_NODE(_net_inet_pm, OID_AUTO, filter, CTLFLAG_RW, 0, "filter");
SYSCTL_NODE(_net_inet_pm, OID_AUTO, nat,    CTLFLAG_RW, 0, "nat");
SYSCTL_NODE(_net_inet_pm, OID_AUTO, route,  CTLFLAG_RW, 0, "route");

SYSCTL_INT(_net_inet_pm_filter, OID_AUTO, doNatFil, CTLFLAG_RW, &doNatFil, 0, "");
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
pm_in(struct ifnet *ifnet, struct ip *ip, struct mbuf *mbuf)
{
    Cell	*p;
    pmBox	*pmb;
    int		 rv = NOMATCHRULEPOLYCY;

    if (toUs(ip))		return (PM_PASS);

    for (p = pmBoxList; p; p = CDR(p))
    {
	pmb = (pmBox *)CAR(p);
	if (pmb->ifnet == ifnet)
	{
	    InOut	 inout;
	    filBoxHalf	*fb = NULL;

	    currentPmBox = pmb;
	    if (pmb->side == InSide)	inout = OutBound;
	    else			inout = InBound;
	    if (pmb->filBox)		fb = &pmb->filBox->i;
	    rv = pm_dispatch(inout, pmb->natBox, fb, ip, mbuf);
	    goto    exit;
	}
    }

exit:;
    return (rv);
}


int
pm_out(struct ifnet *ifnet, struct ip *ip, struct mbuf *mbuf)
{
    Cell	*p;
    pmBox	*pmb;
    int		 rv = NOMATCHRULEPOLYCY;

    if (fromUs(ip))		return (PM_PASS);

    for (p = pmBoxList; p; p = CDR(p))
    {
	pmb = (pmBox *)CAR(p);
	if (pmb->ifnet == ifnet)
	{
	    InOut	 inout;
	    filBoxHalf	*fb = NULL;

	    currentPmBox = pmb;
	    if (pmb->side == InSide)	inout = InBound;
	    else			inout = OutBound;
	    if (pmb->filBox)		fb = &pmb->filBox->o;
	    rv = pm_dispatch(inout, pmb->natBox, fb, ip, mbuf);
	    goto    exit;
	}
    }

exit:;
    return (rv);
}


int
pm_dispatch(InOut inout, natBox *nb, filBoxHalf *fb, struct ip *ip, struct mbuf *mbuf)
{
    if (fr_filter)
    {
	/* It's a policy to drop packet when no filter rule set.	     */
	if ((fb == NULL)
	    || (fb->filRuleMae == NULL))
	    goto    Nat;

/*	if (fb->filRuleMae == NULL)		return (NOMATCHRULEPOLYCY);	*/

	switch (pm_filter(fb->filRuleMae, mbuf))
	{
	  case PM_PASS:			/* Yes, go through this barrier.     */
	    goto    Nat;

	  case PM_BLOCK:		/* no,  blocked by this barrier.     */
	    return (PM_BLOCK);
	}

	/* It's a policy to drop packet when no filter rulel matched.	     */
	return (NOMATCHRULEPOLYCY);
    }

  Nat:;
    if (fr_nat)
    {
	struct	ip	*ip;

	ip = mtod(mbuf, struct ip *);
	pm_nat(inout, (u_char *)ip, mbuf, 0);
    }

  postNat:;
    if (fr_filter)
    {
	/* It's a policy to drop packet when no filter rule set.	     */
	if ((fb == NULL)
	    || (fb->filRuleAto == NULL))
	    goto    Exit;

/*	if (fb->filRuleAto == NULL)		return (NOMATCHRULEPOLYCY);	*/

	switch (pm_filter(fb->filRuleAto, mbuf))
	{
	  case PM_PASS:			/* Yes, go through this barrier.     */
	    goto    Exit;

	  case PM_BLOCK:		/* No,  blocked by this barrier.     */
	    return (PM_BLOCK);
	}

	/* It's a policy to drop packet when no filter rulel matched.	     */
	return (NOMATCHRULEPOLYCY);
    }

  Exit:;
    return (PM_PASS);
}


static	int
toUs(register struct ip *ip)
{
    Cell	*p;
    SelfAddr	*sa;

    for (p = selfAddr; p; p = CDR(p))
    {
	sa = (SelfAddr *)CAR(p);

	if (((ip->ip_dst.s_addr == sa->ifaddr.s_addr)
	     && ((sa->addrflags & NAT_GLOBAL) == 0))
	    || (ip->ip_dst.s_addr == sa->braddr.s_addr))
	    return (TRUE);
    }
    return (FALSE);
}


static	int
fromUs(register struct ip *ip)
{
    Cell	*p;
    SelfAddr	*sa;

    for (p = selfAddr; p; p = CDR(p))
    {
	sa = (SelfAddr *)CAR(p);

	if (((ip->ip_src.s_addr == sa->ifaddr.s_addr)
	     &&  ((sa->addrflags & NAT_GLOBAL) == 0))
	    || (ip->ip_src.s_addr == sa->braddr.s_addr))
	    return (TRUE);
    }
    return (FALSE);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

pmBox   *
pm_asPmBoxName(char *ifName)
{
    Cell	*p;

    for (p = pmBoxList; p; p = CDR(p))
    {
	if (strcmp(ifName, ((pmBox *)CAR(p))->ifName) == SAME)
	    return ((pmBox *)CAR(p));
    }

    return (NULL);
}


pmBox	*
pm_asPmBoxIfnet(struct ifnet *ifnet)
{
    Cell	 *p;
    struct ifnet *ifn;

    for (p = pmBoxList; p; p = CDR(p))
    {
	if (ifnet == ((pmBox *)CAR(p))->ifnet)
	    return ((pmBox *)CAR(p));
    }

    return (NULL);
}


pmBox   *
pm_setPmBox(char *ifName)
{
    struct  ifnet	*p;
    struct  _pmBox	*q;
    char	Wow[IFNAMSIZ];

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    TAILQ_FOREACH(p, &ifnet, if_link)
#else
    for (p = ifnet; p; p = p->if_next)
#endif
    {
	sprintf(Wow, "%s%d%c", p->if_name, p->if_unit, '\0');
	if (strcmp(ifName, Wow) != SAME)
	    continue;

	MALLOC(q, pmBox *, sizeof(pmBox), M_PM, M_WAITOK);
	bzero(q, sizeof(pmBox));

	q->ifnet = p;
	sprintf(Wow, "%s%d%c", p->if_name, p->if_unit, '\0');
	bcopy(Wow, q->ifName, strlen(Wow));

	LST_hookup_list(&pmBoxList,  q);
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

extern	int	doRoute;

int
init_dispatcher()
{
    if (initialized == 0)
    {
	pmBoxList = NULL;
	fr_nat    = FALSE;
	doNatFil  = FALSE;
	doRoute   = FALSE;
	if (selfAddr == NULL)
	    _getSelfAddr();

#if PMDEBUG
	pm_debug = 0xfffffff0;
#endif

	initialized = TRUE;
    }

    return (0);
}


void
_getSelfAddr()
{
    struct  ifnet   *ifn;
    struct ifaddr   *ifa;
    SelfAddr	    *sa;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    TAILQ_FOREACH(ifn, &ifnet, if_link)
#else
    for (ifn = ifnet; ifn; ifn = ifn->if_next)
#endif
    {
	int	firsttime = 0;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	TAILQ_FOREACH(ifa, &ifn->if_addrhead, ifa_link)
#else
	for (ifa = ifn->if_addrlist; ifa; ifa = ifa->ifa_next)
#endif
	{
	    if (ifa->ifa_addr->sa_family == AF_INET)
	    {
#define	SIN(s)	((struct sockaddr_in *)s)

		MALLOC(sa, SelfAddr *, sizeof(SelfAddr), M_PM, M_WAITOK);

		sa->ifaddr  = SIN(ifa->ifa_addr)->sin_addr;
		sa->braddr  = SIN(ifa->ifa_broadaddr)->sin_addr;
		sa->netmask = SIN(ifa->ifa_netmask)->sin_addr;
		sa->addrflags     = 0;
		if (firsttime != 0)
		    sa->addrflags |= MAYBE_ALIAS;
		firsttime++;

		LST_hookup_list(&selfAddr, sa);

#if defined(PM_SYSLOG)
		log(LOG_DEBUG, "[pm] selfAddr marked %s\n",
		    inet_ntoa(SIN(ifa->ifa_addr)->sin_addr));
#else
		{
		    char	WoW[LLEN];

		    sprintf(WoW, "[pm] selfAddr marked %s",
			    inet_ntoa(SIN(ifa->ifa_addr)->sin_addr));
		    pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
		}
#endif
	    }
	}
    }
}
