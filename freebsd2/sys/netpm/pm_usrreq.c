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
//#	$SuMiRe: pm_usrreq.c,v 1.1 1998/09/14 19:49:58 shin Exp $
//#	$Id: pm_usrreq.c,v 1.1 1999/08/05 14:33:21 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_pm.h"
#endif

#include <sys/param.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/systm.h>
#include <sys/protosw.h>
#include <sys/domain.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <vm/vm_zone.h>
#endif

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/route.h>
#endif
#include <net/raw_cb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <netinet/in_pcb.h>
#endif
#include "netpm/pm_defs.h"
#include "netpm/pm_ioctl.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	PMSNDQ		(8192)
#define	PMRCVQ		(8192)

u_long	pm_sendspace = PMSNDQ;
u_long	pm_recvspace = PMRCVQ;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static struct rawcb_list_head	pmrcb_list;
#else
static struct rawcb	pmrcb;
#endif

static struct sockaddr	pm_dst = {2, PF_INET};
static struct sockaddr	pm_src = {2, PF_INET};


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void	pm_init		__P((void));
void	pm_input	__P((struct mbuf *m0, struct sockproto *proto,
			     struct sockaddr *src, struct sockaddr *dst));

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
int	pm_ctloutput	__P((struct socket *, struct sockopt *sopt));
#else
int	pm_ctloutput	__P((int, struct socket *, int, int, struct mbuf **));
#endif
#if !defined(__FreeBSD__) || __FreeBSD__ < 3
int	pm_usrreq	__P((struct socket *, int,
			     struct mbuf *, struct mbuf *nam, struct mbuf *));
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static int	pm_attach	__P((struct socket *, int, struct proc *));
#else
static int	pm_attach	__P((struct socket *, int));
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static int	pm_detach	__P((struct socket *));
#else
static void	pm_detach	__P((struct rawcb *));
#endif

void	pm_debugProbe	__P((char *));
int	pm_soctl	__P((struct mbuf *, struct socket *));

#if defined(__bsdi__)
void	pmattach	__P((int n));
#endif
#if defined(__FreeBSD__)
void	pmattach	__P((void *));
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
pm_init()
{
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    LIST_INIT(&pmrcb_list);
#else
    pmrcb.rcb_next = pmrcb.rcb_prev = &pmrcb;
#endif
}


void
pm_input(struct mbuf *m0, struct sockproto *proto,
	 struct sockaddr *src, struct sockaddr *dst)
{
    struct rawcb *rp;
    struct mbuf  *m = m0;
    struct socket *last;
    int	sockets;

    last = 0;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    LIST_FOREACH(rp, &pmrcb_list, list)
#else
    for (rp = pmrcb.rcb_next; rp != &pmrcb; rp = rp->rcb_next)
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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
int
pm_ctloutput(struct socket *so, struct sockopt *sopt)
{
    int	error = 0;

    if (sopt->sopt_level != IPPROTO_PM)
	return (EINVAL);

    switch (sopt->sopt_name)
    {
      case PM_SOCKOPT:
	switch (sopt->sopt_dir)
	{
	  case PRCO_SETOPT:
	    if (sopt->sopt_valsize < sizeof(struct _msgBox))
		error = EINVAL;
	    else
	    {
	        struct mbuf *m = NULL;

		if (error = soopt_getm(sopt, &m)) /* XXX */
		    break;
		if (error = soopt_mcopyin(sopt, m)) /* XXX */
		    break;
	        
		error = pm_soctl(m, so);

		if (m)
		    m_freem(m);
	    }
	    break;

	  default:
	    return (EINVAL);
	}
	break;

      default:
	return (EINVAL);
    }

    return (error);
}
#else
int
pm_ctloutput(int op, struct socket *so, int level, int optname, struct mbuf **m)
{
    struct rawcb *rp = sotorawcb(so);
    int	error = 0;

    if (level != IPPROTO_PM)
    {
	if ((op == PRCO_SETOPT) && *m)
	    (void)m_free(*m);
	return (EINVAL);
    }

    switch (optname)
    {
      case PM_SOCKOPT:
	switch (op)
	{
	  case PRCO_SETOPT:
	    if ((*m == NULL)
		|| ((*m)->m_len < sizeof(struct _msgBox)))
		error = EINVAL;
	    else
		error = pm_soctl(*m, so);
	    if (*m)
		m_free(*m);
	    break;

	  default:
	    return (EINVAL);
	}
	break;

      default:
	if (*m)
	    m_free(*m);
	return (EINVAL);
    }

    return (error);
}
#endif

#if !defined(__FreeBSD__) || __FreeBSD__ < 3
int
pm_usrreq(struct socket *so, int req,
	  struct mbuf *m, struct mbuf *nam, struct mbuf *control)
{
    struct rawcb	*rp = sotorawcb(so);
    int error = 0;

    if ((rp == NULL) && (req != PRU_ATTACH))
    {
	m_freem(m);
	return (EINVAL);
    }

    switch (req)
    {
      case PRU_ATTACH:
#if	0
	if ((so->so_state & SS_PRIV) == 0)
	{
	    error = EACCES;
	    break;
	}
#endif

#if defined(__bsdi__)
	pmattach(0);
#endif
#if defined(__FreeBSD__)
	pmattach(NULL);
#endif

	error = pm_attach(so, (int)nam);
	break;

      case PRU_DETACH:
	if (rp == NULL)
	{
	    error = ENOTCONN;
	    break;
	}
	pm_detach(rp);
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
	if (nam)
	{
	    if (rp->rcb_faddr)
	    {
		error = EISCONN;
		break;
	    }
	    rp->rcb_faddr = mtod(nam, struct sockaddr *);
	}
	else if (rp->rcb_faddr == NULL)
	{
	    error = ENOTCONN;
	    break;
	}
	error = pm_soctl(m, so);
	m = NULL;
	if (nam)
	    rp->rcb_faddr = NULL;
	break;

      case PRU_BIND:
      case PRU_LISTEN:
      case PRU_CONNECT:
      case PRU_ACCEPT:
      case PRU_SHUTDOWN:
      case PRU_RCVD:
      case PRU_ABORT:
      case PRU_CONTROL:
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

static int
pm_attach(struct socket *so, int proto
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
    if (error = soreserve(so, pm_sendspace, pm_recvspace))
	return (error);

    rp->rcb_socket = so;
    rp->rcb_proto.sp_family = so->so_proto->pr_domain->dom_family;
    rp->rcb_proto.sp_protocol = proto;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    LIST_INSERT_HEAD(&pmrcb_list, rp, list);
#else
    insque(rp, &pmrcb);
#endif

    /* The socket is always "connected" because
          we always know "where" to send the packet */
    rp->rcb_faddr = &pm_dst;
    soisconnected(so);

    return (0);
}



#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static int
pm_detach(struct socket *so)
{
    struct rawcb *rp = sotorawcb(so);

    if (rp == NULL)
	return EINVAL;
#else
static void
pm_detach(struct rawcb *rp)
{
    struct socket *so = rp->rcb_socket;
#endif

    so->so_pcb = NULL;
    sofree(so);
    remque(rp);
    if (rp->rcb_laddr)
	m_freem(dtom(rp->rcb_laddr));
    if (rp->rcb_faddr)
	m_freem(dtom(rp->rcb_faddr));
    FREE(rp, M_PCB);
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    return 0;
#endif
}

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static int
pm_abort(struct socket *so)
{
	return 0;
}

static int
pm_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return 0;
}

static int
pm_disconnect(struct socket *so)
{
    struct rawcb *rp = sotorawcb(so);

    if (rp == NULL)
	return EINVAL;

    if (rp->rcb_faddr == NULL)
        return ENOTCONN;
    rp->rcb_faddr = NULL;
    raw_disconnect(rp);
    soisdisconnected(so);
    return 0;
}

static int
pm_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	struct mbuf *control, struct proc *p)
{
    struct rawcb *rp = sotorawcb(so);
    int error = 0;

    if (rp == NULL)
	return EINVAL;
    if (addr)
    {
        if (rp->rcb_faddr)
	    return EISCONN;
	rp->rcb_faddr = addr;
    }
    else if (rp->rcb_faddr == NULL)
	return ENOTCONN;
    error = pm_soctl(m, so);
    m = NULL;
    if (addr)
	rp->rcb_faddr = NULL;
    return 0;
}

static int
pm_setsockaddr(struct socket *so, struct sockaddr **nam)
{
	return 0;
}

static int
pm_setpeeraddr(struct socket *so, struct sockaddr **nam)
{
	return 0;
}

static int
pm_shutdown(struct socket *so)
{
	return 0;
}

static int
pm_receive(struct socket *so, struct sockaddr **psa, struct uio *uio,
	   struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	return (EOPNOTSUPP);
}

static int
pm_sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
	  struct mbuf *top, struct mbuf *control, int flags, struct proc *p)
{
	return (EOPNOTSUPP);
}

struct pr_usrreqs pm_usrreqs = {
	pm_abort, pru_accept_notsupp, pm_attach, pm_bind,
	pru_connect_notsupp, pru_connect2_notsupp, pru_control_notsupp,
	pm_detach, pm_disconnect, pru_listen_notsupp, pm_setpeeraddr,
	pru_rcvd_notsupp, pru_rcvoob_notsupp, pm_send, pru_sense_null,
	pm_shutdown, pm_setsockaddr, pm_sosend,
	pm_receive, sopoll
};
#endif
