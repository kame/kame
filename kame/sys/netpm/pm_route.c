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
//#	$SuMiRe: pm_route.c,v 1.7 1998/09/14 19:49:56 shin Exp $
//#	$Id: pm_route.c,v 1.1 1999/08/12 12:41:10 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#include <netpm/pm_include.h>

#include <net/route.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

Cell	*routeConf;		/* List of fwdRoute		*/
int	 doRoute;


struct route	*pm_route	    __P((struct mbuf *m));
int		 _pmAddRoute	    __P((caddr_t));
int		 _pmRemoveRoute	    __P((caddr_t));
int		 _pmFlushRoute	    __P((void));
int		 doRtAlloc	    __P((struct _fwdRoute *));
int		 _pmAttachRoute	    __P((void));
int		 _pmDetachRoute	    __P((void));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	S(s)	(s.s_addr)

struct route *
pm_route(struct mbuf *m)
{
    Cell		*p;
    struct ip		*ip;
    struct _fwdRoute	*fwd;

    ip = mtod(m, struct ip *);

    for (p = routeConf; p; p = CDR(p))
    {
	fwd = (struct _fwdRoute *)CAR(p);
	if ((fwd->ip_p != IPPROTO_IP)
	    && (fwd->ip_p != ip->ip_p))
	    continue;

	switch (fwd->type[0])
	{
	  case IN_ADDR_ANY:					goto    DstAddr;

	  case IN_ADDR_SINGLE:
	    if (S(ip->ip_src) == S(fwd->ip_src[0]))		goto	DstAddr;
	    else						continue;

	  case IN_ADDR_MASK:
	    if ((S(ip->ip_src) & S(fwd->ip_src[1])) == S(fwd->ip_src[2]))
								goto    DstAddr;
	    else						continue;

	  case IN_ADDR_RANGE:
	    if ((S(ip->ip_src) >= S(fwd->ip_src[0]))
		&& (S(ip->ip_src) <= S(fwd->ip_src[1])))	goto	DstAddr;
	    else						continue;
	}

      DstAddr:;
	switch (fwd->type[1])
	{
	  case IN_ADDR_ANY:					goto    Port;

	  case IN_ADDR_SINGLE:
	    if (S(ip->ip_dst) == S(fwd->ip_dst[0]))		goto	Port;
	    else						continue;

	  case IN_ADDR_MASK:
	    if ((S(ip->ip_dst) & S(fwd->ip_dst[1])) == S(fwd->ip_dst[2]))
								goto    Port;
	    else						continue;

	  case IN_ADDR_RANGE:
	    if ((S(ip->ip_dst) >= S(fwd->ip_dst[0]))
		&& (S(ip->ip_dst) <= S(fwd->ip_dst[1])))	goto	Port;
	    else						continue;
	}

      Port:;
	switch (ip->ip_p)
	{
	  default:
	  case IPPROTO_ICMP:
	  case IPPROTO_IPIP:
	    pm_logroute(m, fwd);
	    return (fwd->_route);

	  case IPPROTO_TCP:
	  case IPPROTO_UDP:
	    {
		struct tcpiphdr	*tip;

		tip = (struct tcpiphdr *)ip;
		if (((fwd->th_sport[0] == 0)
		     || ((fwd->th_sport[1] == 0)
			 && (fwd->th_sport[0] == tip->ti_sport))
		     || ((tip->ti_sport >= fwd->th_sport[0])
			 && (tip->ti_sport <= fwd->th_sport[1])))
		    && ((fwd->th_dport[0] == 0)
			|| ((fwd->th_dport[1] == 0)
			    && (fwd->th_dport[0] == tip->ti_dport))
			|| ((tip->ti_dport >= fwd->th_dport[0])
			    && (tip->ti_dport <= fwd->th_dport[1]))))
		    {
			pm_logroute(m, fwd);
			return (fwd->_route);
		    }
	    }
	    break;
	}
    }

    pm_logroute(m, NULL);
    return (NULL);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
_pmAddRoute(caddr_t addr)
{
    int			 rv;
    int			 sz;
    Cell		*p;
    struct _fwdRoute	*fwd, *pma;

    rv = 0;
    sz = sizeof(struct _fwdRoute) - sizeof(struct route *);

    pma = &((struct _msgBox *)addr)->m_fwdRoute;
    for (p = routeConf; p; p = CDR(p))
    {
	fwd = (struct _fwdRoute *)CAR(p);
	if (bcmp(fwd, pma, sz) == 0)
	    return (EADDRINUSE);
    }

    MALLOC(fwd, fwdRoute *, sizeof(fwdRoute), M_PM, M_WAITOK);
    bcopy(pma, fwd, sizeof(fwdRoute));

    if ((rv = doRtAlloc(fwd)) == 0)
	LST_hookup_list(&routeConf, fwd);

    return (rv);
}


int
_pmRemoveRoute(caddr_t addr)
{
    int			 idx0, idx1;
    Cell		*p0, *p1;
    int			*m;
    int			 s;
    struct  _msgBox	*ib = (struct _msgBox *)addr;
    struct  _fwdRoute	*fwd;

    MALLOC(m, int *, ib->nums * ib->size, M_PM, M_WAITOK);
    bcopy(ib->freight, m, ib->nums * ib->size);

    for (p0 = routeConf, idx0 = idx1 = 0; p0; idx0++)
    {
	p1 = p0;
	p0 = CDR(p0);
	if (idx0 == m[idx1])
	{
	    idx1++;
	    fwd = (struct _fwdRoute *)CAR(p1);
	    s = splnet();
	    if (fwd->_route)
		FREE(fwd->_route, M_PM);

	    LST_remove_elem(&routeConf, fwd);
	    splx(s);
	    FREE(fwd, M_PM);
	}
	if ((m[idx1] == -1) || (idx1 >= ib->nums))
	    break;
    }

    FREE(m, M_PM);

    return (0);
}


int
_pmFlushRoute()
{
    int			 s;
    Cell		*p0, *p1;
    struct _fwdRoute	*fwd;

    p0 = routeConf;
    while (p0)
    {
	p1 = p0;
	p0 = CDR(p0);
	fwd = (struct _fwdRoute *)CAR(p1);
	s = splnet();
	if (fwd->_route)
	    FREE(fwd->_route, M_PM);

	LST_remove_elem(&routeConf, fwd);
	splx(s);
	FREE(fwd, M_PM);
    }

    return (0);
}


int
doRtAlloc(struct _fwdRoute *fwd)
{
    int			 rv = 0;
    struct  route	*rt;
    struct  sockaddr_in *sin;

    MALLOC(rt, struct route *, sizeof(struct route), M_PM, M_WAITOK);
    bzero(rt, sizeof(struct route));

    sin = (struct sockaddr_in *)&rt->ro_dst;
    sin->sin_family = AF_INET;
    sin->sin_len    = sizeof(*sin);
    sin->sin_addr   = fwd->ip_via;
    rtalloc(rt);
    if (rt->ro_rt == NULL)
	rv = EHOSTUNREACH;

    fwd->_route = rt;
    return (rv);
}
	    

/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
_pmAttachRoute()
{
    doRoute = TRUE;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[rt] enable\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[rt] enabled.");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


int
_pmDetachRoute()
{
    doRoute = FALSE;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[rt] disable\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[rt] disabled.");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}
