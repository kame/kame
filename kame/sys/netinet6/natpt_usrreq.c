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
//#	$Id: natpt_usrreq.c,v 1.1 1999/08/12 12:41:13 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#include <sys/types.h>
#include <sys/param.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/domain.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/sockio.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/raw_cb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_log.h>
#include <netinet6/ptr_soctl.h>
#include <netinet6/ptr_var.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	PTRSNDQ		(8192)
#define	PTRRCVQ		(8192)

u_long	ptr_sendspace = PTRSNDQ;
u_long	ptr_recvspace = PTRRCVQ;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static struct rawcb_list_head	ptrcb_list;
#else
static struct rawcb	ptrcb;
#endif
static struct sockaddr	ptr_dst = {2, PF_INET};
static struct sockaddr	ptr_src = {2, PF_INET};

#if	0
int	ptr_sosetopt	__P((struct socket *, int, struct mbuf *));
int	ptr_sogetopt	__P((struct socket *, int, struct mbuf *));
#endif

static	int	_ptrSetIf	__P((caddr_t));
static	int	_ptrGetIf	__P((caddr_t));

void	ptr_init	__P((void));
void	ptr_input	__P((struct mbuf *, struct sockproto *,
			     struct sockaddr *src, struct sockaddr *dst));
#if defined(__bsdi__)
int	ptr_usrreq	__P((struct socket *, int,
			     struct mbuf *, struct mbuf *, struct mbuf *));
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
int	ptr_attach	__P((struct socket *, int, struct proc *));
#else
int	ptr_attach	__P((struct socket *, int));
#endif
int	ptr_detach	__P((struct socket *));
int	ptr_disconnect	__P((struct socket *));

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
int	ptr_control	__P((struct socket *, u_long, caddr_t, struct ifnet *,
			     struct proc *));
#else
int	ptr_control	__P((struct socket *, int, caddr_t, struct ifnet *));
#endif

#if defined(__FreeBSD__)
struct pr_usrreqs ptr_usrreqs =
{
	NULL,		NULL,	ptr_attach,	NULL,
	NULL,		NULL,	ptr_control,	ptr_detach,
	ptr_disconnect,	NULL,	NULL,		NULL,
	NULL,		NULL,	NULL,		NULL,
	NULL
};
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
ptr_init()
{
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    LIST_INIT(&ptrcb_list);
#else
    ptrcb.rcb_next = ptrcb.rcb_prev = &ptrcb;
#endif
}


void
ptr_input(struct mbuf *m0, struct sockproto *proto,
	 struct sockaddr *src, struct sockaddr *dst)
{
    struct rawcb *rp;
    struct mbuf	 *m = m0;
    struct socket *last;
    int	sockets;

    last = 0;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    LIST_FOREACH(rp, &ptrcb_list, list)
#else
    for (rp = ptrcb.rcb_next; rp != &ptrcb; rp = rp->rcb_next)
#endif
    {
	if (rp->rcb_proto.sp_family != proto->sp_family)
	    continue;
	if (rp->rcb_proto.sp_protocol
	    && (rp->rcb_proto.sp_protocol != proto->sp_protocol))
	    continue;

#define	equal(a1, a2)	(bcmp((caddr_t)(a1), (caddr_t)(a2), a1->sa_len) == 0)

	if (rp->rcb_laddr && !equal(rp->rcb_laddr, dst))
	    continue;
	if (rp->rcb_faddr && !equal(rp->rcb_faddr, src))
	    continue;

	if (last)
	{
	    struct mbuf *n;

	    if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL)
	    {
		if (sbappendaddr(&last->so_rcv, src, n, (struct mbuf *)NULL) == 0)
		    m_freem(n);		/* should notify about lost packet */
		else
		{
		    sorwakeup(last);
		    sockets++;
		}
	    }
	}
	last = rp->rcb_socket;
    }

    if (last)
    {
	if (sbappendaddr(&last->so_rcv, src, m, (struct mbuf *)NULL) == 0)
	    m_freem(m);
	else
	{
	    sorwakeup(last);
	    sockets++;
	}
    }
    else
	m_freem(m);
}


#if defined(__bsdi__)
int
ptr_usrreq(struct socket *so, int req,
	  struct mbuf *m, struct mbuf *nam, struct mbuf *control)
{
    struct rawcb	*rp = sotorawcb(so);
    int			 error = 0;

    if ((rp == NULL) && (req != PRU_ATTACH))
    {
	m_freem(m);
	return (EINVAL);
    }

    switch (req)
    {
      case PRU_ATTACH:
	error = ptr_attach(so, (int)nam);
	break;

      case PRU_DETACH:
	error = ptr_detach(so);
	break;

      case PRU_DISCONNECT:
	if (rp->rcb_faddr == NULL)
	{
	    error = ENOTCONN;
	    break;
	}
	rp->rcb_faddr = NULL;
	raw_disconnect(rp);
	soisdisconnected(so);
	break;

      case PRU_SEND:
      case PRU_BIND:
      case PRU_LISTEN:
      case PRU_CONNECT:
      case PRU_ACCEPT:
      case PRU_SHUTDOWN:
      case PRU_RCVD:
      case PRU_ABORT:
	error = EOPNOTSUPP;
	break;

      case PRU_CONTROL:
	error = ptr_control(so, (int)m, (caddr_t)nam, (struct ifnet *)NULL);
	return (error);
	break;

      case PRU_SENSE:
      case PRU_RCVOOB:
      case PRU_SENDOOB:
      case PRU_SOCKADDR:
      case PRU_PEERADDR:
      case PRU_CONNECT2:
      case PRU_FASTTIMO:
      case PRU_SLOWTIMO:
      case PRU_PROTORCV:
      case PRU_PROTOSEND:
	error = EOPNOTSUPP;
	break;

      default:
	panic("raw_usrreq");
    }

    if (m != NULL)
	m_freem(m);

    return (error);
}
#endif


int
ptr_attach(struct socket *so, int proto
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	   , struct proc *p
#endif
	   )
{
    struct rawcb *rp;
    int	error;

    if (so->so_pcb == NULL)
    {
	MALLOC(rp, struct rawcb *, sizeof(*rp), M_PCB, M_WAITOK);
	so->so_pcb = (caddr_t)rp;
	bzero(rp, sizeof(*rp));
    }

    if ((rp = sotorawcb(so)) == NULL)
	return (ENOBUFS);
    if (error = soreserve(so, ptr_sendspace, ptr_recvspace))
	return (error);

    rp->rcb_socket = so;
    rp->rcb_proto.sp_family = so->so_proto->pr_domain->dom_family;
    rp->rcb_proto.sp_protocol = proto;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    LIST_INSERT_HEAD(&ptrcb_list, rp, list);
#else
    insque(rp, &ptrcb);
#endif

    /* The socket is always "connected" because
	  we always know "where" to send the packet */
    rp->rcb_faddr = &ptr_dst;
    soisconnected(so);

    return (0);
}


int
ptr_detach(struct socket *so)
{
    struct rawcb	*rp = sotorawcb(so);

    if (rp == NULL)
	return (ENOTCONN);

    so->so_pcb = NULL;
    sofree(so);
    remque(rp);
    if (rp->rcb_laddr)
	m_freem(dtom(rp->rcb_laddr));
    if (rp->rcb_faddr)
	m_freem(dtom(rp->rcb_faddr));
    FREE(rp, M_PCB);

    return (0);
}


int
ptr_disconnect(struct socket *so)
{
    struct rawcb	*rp = sotorawcb(so);

    if (rp->rcb_faddr == NULL)
	return (ENOTCONN);

    rp->rcb_faddr = NULL;
    raw_disconnect(rp);
    soisdisconnected(so);

    return (0);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
ptr_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
	    struct proc *p)
#else
ptr_control(struct socket *so, int cmd, caddr_t data, struct ifnet *ifp)
#endif
{
    if (ptr_initialized == 0)
	ptr_initialize();

    switch (cmd)
    {
      case SIOCSETIF:		return (_ptrSetIf(data));
      case SIOCGETIF:		return (_ptrGetIf(data));
      case SIOCENBTRANS:	return (_ptrEnableTrans(data));
      case SIOCDSBTRANS:	return (_ptrDisableTrans(data));
      case SIOCSETRULE:		return (_ptrSetRule(data));
      case SIOCFLUSHRULE:	return (_ptrFlushRule(data));
      case SIOCSETPREFIX:	return (_ptrSetPrefix(data));

      case SIOCBREAK:		return (_ptrBreak());
    }

    return (EINVAL);
}


static int
_ptrSetIf(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct ifBox	*ifb;

    if (((ifb = ptr_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = ptr_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);

    if (ifb->side != noSide)
    {
	char	WoW[LLEN];

	sprintf(WoW, "[ptr] interface `%s\' already configured.", mbx->m_ifName);
	ptr_log(LOG_MSG, LOG_WARNING, WoW, strlen(WoW));
	return (EALREADY);
    }

    {
	char	 WoW[LLEN];
	char	*s;

	ptr_ip6src = ifb->ifnet;
	if (mbx->flags == IF_EXTERNAL)
	    ifb->side = outSide, s = "outside";
	else
	    ifb->side = inSide,	 s = "inside";

	sprintf(WoW, "[ptr] interface `%s\' set as %s.", mbx->m_ifName, s);
	ptr_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }

    return (0);
}


static int
_ptrGetIf(caddr_t addr)
{
    struct msgBox	*mbx = (struct msgBox *)addr;
    struct ifBox	*ifb;

    if (((ifb = ptr_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = ptr_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);
    
    {
	switch (ifb->side)
	{
	  case outSide:	mbx->flags |= IF_EXTERNAL;	break;
	  case inSide:	mbx->flags |= IF_INTERNAL;	break;
	  default:	mbx->flags  = -1;		break;
	}
    }

    return (0);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

