/*	$KAME: natpt_usrreq.c,v 1.17 2001/10/17 07:02:49 fujisawa Exp $	*/

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
#include <sys/domain.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>

#include <net/raw_cb.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

#define	NATPTSNDQ		(8192)
#define	NATPTRCVQ		(8192)

u_long	natpt_sendspace = NATPTSNDQ;
u_long	natpt_recvspace = NATPTRCVQ;

LIST_HEAD(,rawcb)		ptrcb;

#ifdef __FreeBSD__
MALLOC_DECLARE(M_NATPT);
#endif


/*
 *
 */

void		natpt_init		__P((void));


#ifdef __FreeBSD__
int		natpt_uabort		__P((struct socket *));
int		natpt_uattach		__P((struct socket *, int proto, struct proc *));
int		natpt_ubind		__P((struct socket *, struct sockaddr *,
					     struct proc *));
int		natpt_uconnect		__P((struct socket *, struct sockaddr *,
					     struct proc *));
int		natpt_ucontrol		__P((struct socket *, u_long, caddr_t, struct ifnet *,
					     struct proc *));
int		natpt_udetach		__P((struct socket *));
#endif

int		natpt_attach		__P((struct socket *, int));
int		natpt_detach		__P((struct socket *));
int		natpt_disconnect	__P((struct socket *));
int		natpt_control		__P((struct socket *, int, caddr_t, struct ifnet *));


struct pr_usrreqs natpt_usrreqs =
{
	natpt_uabort,		NULL,		natpt_uattach,	natpt_ubind,
	natpt_uconnect,		NULL,		natpt_ucontrol,	natpt_udetach,
	natpt_disconnect,	NULL,		NULL,		NULL,
	NULL,			NULL,		NULL,		NULL,
	NULL,			sosend,		soreceive,	sopoll
};


/*
 *
 */

void
natpt_init()
{
	natpt_initialized = 1;
	ip6_protocol_tr = 0;

	natpt_init_rule();
	natpt_init_tslot();

	LIST_INIT(&ptrcb);

	printf("NATPT initialized\n");
}


void
natpt_input(struct mbuf *m0, struct sockproto *proto,
	    struct sockaddr *src, struct sockaddr *dst)
{
	struct rawcb	*rp;
	struct mbuf	*m = m0;
	struct socket	*last;

	last = 0;
	for (rp = ptrcb.lh_first; rp != 0; rp = rp->list.le_next) {
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

		if (last) {
			struct mbuf *n;

			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if (sbappendaddr(&last->so_rcv, src, n,
						 (struct mbuf *)NULL) == 0)
					/* should notify about lost packet */
					m_freem(n);
				else {
					sorwakeup(last);
				}
			}
		}
		last = rp->rcb_socket;
	}

	if (last) {
		if (sbappendaddr(&last->so_rcv, src, m, (struct mbuf *)NULL) == 0)
			m_freem(m);
		else {
			sorwakeup(last);
		}
	}
	else
		m_freem(m);
}


#ifdef __FreeBSD__
int
natpt_uabort(struct socket *so)
{
	struct rawcb	*rp = sotorawcb(so);

	if (rp == 0)
		return (EINVAL);

	raw_disconnect(rp);
	sofree(so);
	soisdisconnected(so);

	return (0);
}


int
natpt_uattach(struct socket *so, int proto, struct proc *p)
{
	int		 error;

	if (p && (error = suser(p)) != 0)
		return (error);

	return (natpt_attach(so, proto));
}


int
natpt_ubind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return (EINVAL);
}


int
natpt_uconnect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	return (EINVAL);
}


int
natpt_ucontrol(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
	       struct proc *p)
{
	return (natpt_control(so, cmd, data, ifp));
}


int
natpt_udetach(struct socket *so)
{
	struct rawcb	*rp = sotorawcb(so);

	if (rp == 0)
		return (EINVAL);

	return (natpt_detach(so));
}

#endif	/* __FreeBSD__*/


int
natpt_attach(struct socket *so, int proto)
{
	struct rawcb	*rp;
	int		 error;

	if (so->so_pcb == NULL) {
		MALLOC(rp, struct rawcb *, sizeof(*rp), M_PCB, M_WAITOK);
		if (rp == NULL)
			return (ENOBUFS);
		bzero(rp, sizeof(*rp));
		so->so_pcb = (caddr_t)rp;
	}

	if ((rp = sotorawcb(so)) == NULL)
		return (ENOBUFS);
	if ((error = soreserve(so, natpt_sendspace, natpt_recvspace)))
		return (error);

	rp->rcb_socket = so;
	rp->rcb_proto.sp_family = so->so_proto->pr_domain->dom_family;
	rp->rcb_proto.sp_protocol = proto;
	LIST_INSERT_HEAD(&ptrcb, rp, list);

	return (0);
}


int
natpt_detach(struct socket *so)
{
	struct rawcb	*rp = sotorawcb(so);

	if (rp == NULL)
		return (ENOTCONN);

	so->so_pcb = NULL;
	sofree(so);

	LIST_REMOVE(rp, list);

	if (rp->rcb_laddr)
		m_freem(dtom(rp->rcb_laddr));
	if (rp->rcb_faddr)
		m_freem(dtom(rp->rcb_faddr));
	FREE(rp, M_PCB);

	return (0);
}


int
natpt_disconnect(struct socket *so)
{
	struct rawcb	*rp = sotorawcb(so);

	if (rp == NULL)
		return (EINVAL);

	if (rp->rcb_faddr == NULL)
		return (ENOTCONN);

	rp->rcb_faddr = NULL;
	raw_disconnect(rp);
	soisdisconnected(so);

	return (0);
}


int
natpt_control(struct socket *so, int cmd, caddr_t data, struct ifnet *ifp)
{
	switch (cmd) {
	case SIOCSETPREFIX:
		return (natpt_setPrefix(data));

	case SIOCSETRULES:
		return (natpt_setRules(data));

	case SIOCFLUSHRULE:
		return (natpt_flushRules(data));

	case SIOCENBTRANS:
	case SIOCDSBTRANS:
		return (natpt_setOnOff(cmd));

	case SIOCSETVALUE:
		return (natpt_setValue(data));

	case SIOCTESTLOG:
		return (natpt_testLog(data));

	case SIOCBREAK:
		return (natpt_break());

	default:
		break;
	}

	return (EINVAL);
}
