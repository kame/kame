/*
 * Copyright (C) 1997-1999
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: altq_fifoq.c,v 1.2 1999/10/02 05:58:59 itojun Exp $
 */

#ifndef _NO_OPT_ALTQ_H_
#include "opt_altq.h"
#endif
#ifdef FIFOQ	/* fifoq is enabled by FIFOQ option in opt_altq.h */

/*
 * FIFOQ is an altq sample implementation.  There will be little
 * need to use FIFOQ as an alternative queueing scheme.
 * But this code is provided as a template for those who want to
 * write their own queueing schemes.
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/altq_conf.h>

#include <netinet/in.h>
#include <netinet/altq.h>
#include <netinet/altq_fifoq.h>

#define FIFOQ_STATS	/* collect statistics */

/* fifoq_list keeps all fifoq_state_t's allocated. */
static fifoq_state_t *fifoq_list = NULL;

/* internal function prototypes */
static int		fifoq_enqueue __P((struct ifnet *, struct mbuf *,
					   struct pr_hdr *, int));
static struct mbuf 	*fifoq_dequeue __P((struct ifnet *, int));
static int 		fifoq_detach __P((fifoq_state_t *));
static void 		fifoq_flush __P((fifoq_state_t *));

/*
 * fifoq device interface
 */
altqdev_decl(fifoq);

int
fifoqopen(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	/* everything will be done when the queueing scheme is attached. */
	return 0;
}

/*
 * there are 2 ways to act on close.
 *   detach-all-on-close:
 *	use for the daemon style approach.  if the daemon dies, all the
 *	resource will be released.
 *   no-action-on-close:
 *	use for the command style approach.  (e.g.  fifoq on/off)
 *
 * note: close is called not on every close but when the last reference
 *       is removed (only once with multiple simultaneous references.)
 */
int
fifoqclose(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	fifoq_state_t *q;
	int err, error = 0;

	while ((q = fifoq_list) != NULL) {
		/* destroy all */
		err = fifoq_detach(q);
		if (err != 0 && error == 0)
			error = err;
	}

	return error;
}

int
fifoqioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	ioctlcmd_t cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	fifoq_state_t *q;
	struct fifoq_interface *ifacep;
	struct ifnet *ifp;
	int	error = 0;

	/* check super-user privilege */
	switch (cmd) {
	case FIFOQ_GETSTATS:
		break;
	default:
		if ((error = suser(p->p_ucred, &p->p_acflag)) != 0)
			return (error);
		break;
	}
    
	switch (cmd) {

	case FIFOQ_ENABLE:
		ifacep = (struct fifoq_interface *)addr;
		if ((q = altq_lookup(ifacep->fifoq_ifname, ALTQT_FIFOQ))
		    == NULL) {
			error = EBADF;
			break;
		}
    
		error = if_altqenable(q->q_ifp);
		break;

	case FIFOQ_DISABLE:
		ifacep = (struct fifoq_interface *)addr;
		if ((q = altq_lookup(ifacep->fifoq_ifname, ALTQT_FIFOQ))
		    == NULL) {
			error = EBADF;
			break;
		}
		error = if_altqdisable(q->q_ifp);
		break;

	case FIFOQ_IF_ATTACH:
		ifp = ifunit(((struct fifoq_interface *)addr)->fifoq_ifname);
		if (ifp == NULL) {
			error = ENXIO;
			break;
		}

		/* allocate and initialize fifoq_state_t */
		MALLOC(q, fifoq_state_t *, sizeof(fifoq_state_t),
		       M_DEVBUF, M_WAITOK);
		if (q == NULL) {
			error = ENOMEM;
			break;
		}
		bzero(q, sizeof(fifoq_state_t));

		q->q_ifp = ifp;
		q->q_head = q->q_tail = NULL;
		q->q_len = 0;
		q->q_limit = FIFOQ_LIMIT;

		/*
		 * set FIFOQ to this ifnet structure.
		 */
		error = if_altqattach(ifp, q, fifoq_enqueue, fifoq_dequeue,
				      ALTQT_FIFOQ);
		if (error) {
			FREE(q, M_DEVBUF);
			break;
		}

		/* add this state to the fifoq list */
		q->q_next = fifoq_list;
		fifoq_list = q;
		break;

	case FIFOQ_IF_DETACH:
		ifacep = (struct fifoq_interface *)addr;
		if ((q = altq_lookup(ifacep->fifoq_ifname, ALTQT_FIFOQ))
		    == NULL) {
			error = EBADF;
			break;
		}
    
		error = fifoq_detach(q);
		break;

	case FIFOQ_GETSTATS:
		do {
			struct fifoq_getstats *q_stats;

			q_stats = (struct fifoq_getstats *)addr;
			if ((q = altq_lookup(q_stats->iface.fifoq_ifname,
					     ALTQT_FIFOQ)) == NULL) {
				error = EBADF;
				break;
			}

			q_stats->q_len		= q->q_len;
			q_stats->q_limit 	= q->q_limit;
			q_stats->xmit_packets	= q->q_stats.xmit_packets;
			q_stats->xmit_bytes   	= q->q_stats.xmit_bytes;
			q_stats->drop_packets 	= q->q_stats.drop_packets;
			q_stats->drop_bytes   	= q->q_stats.drop_bytes;
		} while (0);
		break;

	case FIFOQ_CONFIG:
		do {
			struct fifoq_conf *fc;
			int limit;

			fc = (struct fifoq_conf *)addr;
			if ((q = altq_lookup(fc->iface.fifoq_ifname,
					     ALTQT_FIFOQ)) == NULL) {
				error = EBADF;
				break;
			}
			limit = fc->fifoq_limit;
			if (limit < 0)
				limit = 0;
			q->q_limit = limit;
			fc->fifoq_limit = limit;
		} while (0);
		break;

	case FIFOQ_ACC_ENABLE:
		/* enable accounting mode */
		ifacep = (struct fifoq_interface *)addr;
		if ((q = altq_lookup(ifacep->fifoq_ifname, ALTQT_FIFOQ))
		    == NULL) {
			error = EBADF;
			break;
		}
		SET_ACCOUNTING(q->q_ifp);
		break;

	case FIFOQ_ACC_DISABLE:
		/* disable accounting mode */
		ifacep = (struct fifoq_interface *)addr;
		if ((q = altq_lookup(ifacep->fifoq_ifname, ALTQT_FIFOQ))
		    == NULL) {
			error = EBADF;
			break;
		}
		CLEAR_ACCOUNTING(q->q_ifp);
		break;

	default:
		error = EINVAL;
		break;
	}
	return error;
}

/*
 * fifoq support routines
 */

/*
 * enqueue routine:
 *
 *	returns: 0 when successfully queued.
 *		 ENOBUFS when drop occurs.
 */
static int
fifoq_enqueue(ifp, m, pr_hdr, mode)
	struct ifnet *ifp;
	struct mbuf *m;
	struct pr_hdr *pr_hdr;
	int mode;
{
	fifoq_state_t *q = (fifoq_state_t *)ifp->if_altqp;

	switch (mode) {
	case ALTEQ_NORMAL:
		/* if the queue is full, drop the incoming packet(drop-tail) */
		if (q->q_len >= q->q_limit) {
#ifdef FIFOQ_STATS
			q->q_stats.drop_packets++;
			q->q_stats.drop_bytes += m->m_pkthdr.len;
#endif
			m_freem(m);
			return (ENOBUFS);
		}

		/* enqueue the packet at the taile of the queue */
		m->m_nextpkt = NULL;
		if (q->q_tail == NULL)
			q->q_head = m;
		else
			q->q_tail->m_nextpkt = m;
		q->q_tail = m;
		q->q_len++;

		/* start the driver */
		if (ifp->if_start && (ifp->if_flags & IFF_OACTIVE) == 0)
			(*ifp->if_start)(ifp);

		break;

#if defined(ALTQ_ACCOUNT) && defined(FIFOQ_STATS)
		/*
		 * altq accounting mode: used just for statistics.
		 */
	case ALTEQ_ACCOK:
		q->q_stats.xmit_packets++;
		q->q_stats.xmit_bytes += m->m_pkthdr.len;
		break;

	case ALTEQ_ACCDROP:
		q->q_stats.drop_packets++;
		q->q_stats.drop_bytes += m->m_pkthdr.len;
		break;

#endif /* ALTQ_ACCOUNT && FIFOQ_STATS */
	}
	return 0;
}

/*
 * dequeue routine:
 *	must be called in splimp.
 *
 *	returns: mbuf dequeued.
 *		 NULL when no packet is available in the queue.
 */
/*
 * ALTDQ_PEEK is provided for drivers which need to know the next packet
 * to send in advance.
 * when ALTDQ_PEEK is specified, the next packet to be dequeued is
 * returned without dequeueing the packet.
 * when ALTDQ_DEQUEUE is called *immediately after* an ALTDQ_PEEK
 * operation, the same packet should be returned.
 */
static struct mbuf *
fifoq_dequeue(ifp, mode)
	struct ifnet *ifp;
	int mode;
{
	fifoq_state_t *q = (fifoq_state_t *)ifp->if_altqp;
	struct mbuf *m = NULL;

	switch (mode) {
	case ALTDQ_DEQUEUE:
		if ((m = q->q_head) == NULL)
			break;
		if ((q->q_head = m->m_nextpkt) == NULL)
			q->q_tail = NULL;
		m->m_nextpkt = NULL;
		q->q_len--;

#ifdef FIFOQ_STATS
		q->q_stats.xmit_packets++;
		q->q_stats.xmit_bytes += m->m_pkthdr.len;
#endif
		break;
	case ALTDQ_PEEK:
		m = q->q_head;
		break;
	case ALTDQ_FLUSH:
		fifoq_flush(q);
		break;
	}
	return m;
}

static int fifoq_detach(q)
	fifoq_state_t *q;
{
	fifoq_state_t *tmp;
	int error = 0;

	if (ALTQ_IS_ON(q->q_ifp))
		if_altqdisable(q->q_ifp);

	fifoq_flush(q);

	if ((error = if_altqdetach(q->q_ifp)))
		return (error);

	if (fifoq_list == q)
		fifoq_list = q->q_next;
	else {
		for (tmp = fifoq_list; tmp != NULL; tmp = tmp->q_next)
			if (tmp->q_next == q) {
				tmp->q_next = q->q_next;
				break;
			}
		if (tmp == NULL)
			printf("fifoq_detach: no state in fifoq_list!\n");
	}

	FREE(q, M_DEVBUF);
	return (error);
}

/*
 * fifoq_flush
 * should be called in splimp or after disabling the fifoq.
 */
static void fifoq_flush(q)
	fifoq_state_t *q;
{
	struct mbuf *m;
    
	while ((m = q->q_head) != NULL) {
		q->q_head = m->m_nextpkt;
		m_freem(m);
	}
	q->q_tail = NULL;
	q->q_len = 0;
}

#ifdef KLD_MODULE

#include <net/altq_conf.h>

static struct altqsw fifoq_sw =
	{"fifoq", fifoqopen, fifoqclose, fifoqioctl};

ALTQ_MODULE(altq_fifoq, ALTQT_FIFOQ, &fifoq_sw);

#endif /* KLD_MODULE */

#endif /* FIFOQ */
