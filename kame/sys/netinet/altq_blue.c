/*
 * Copyright (C) 1997-1999
 *	Sony Computer Science Laboratory Inc.  All rights reserved.
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
 */
/*
 * Copyright (c) 1990-1994 Regents of the University of California.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: altq_blue.c,v 1.1 1999/10/01 04:38:05 kjc Exp $
 */

#ifndef _NO_OPT_ALTQ_H_
#include "opt_altq.h"
#if !defined(__FreeBSD__) || (__FreeBSD__ > 2)
#include "opt_inet.h"
#endif
#endif /* !_NO_OPT_ALTQ_H_ */
#ifdef BLUE	/* blue is enabled by BLUE option in opt_altq.h */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/conf.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/altq_conf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/altq.h>
#include <netinet/altq_classq.h>
#include <netinet/altq_blue.h>

/*
 * Blue is proposed and implemented by Wu-chang Feng <wuchang@eecs.umich.edu>.
 * more information on Blue is available from
 * http://www.eecs.umich.edu/~wuchang/blue/
 */

/* fixed-point uses 12-bit decimal places */
#define FP_SHIFT	12	/* fixed-point shift */

#define BLUE_LIMIT	200	/* default max queue lenght */
#define BLUE_STATS		/* collect statistics */

/* blue_list keeps all blue_state_t's allocated. */
static blue_queue_t *blue_list = NULL;

/* internal function prototypes */
static int blue_enqueue __P((struct ifnet *, struct mbuf *,
			    struct pr_hdr *, int));
static struct mbuf *blue_dequeue __P((struct ifnet *, int));
static int drop_early __P((blue_t *));
static int mark_ecn __P((struct pr_hdr *, int));
static int blue_detach __P((blue_queue_t *));

/*
 * blue device interface
 */
altqdev_decl(blue);

int
blueopen(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	/* everything will be done when the queueing scheme is attached. */
	return 0;
}

int
blueclose(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	blue_queue_t *rqp;
	int err, error = 0;

	while ((rqp = blue_list) != NULL) {
		/* destroy all */
		err = blue_detach(rqp);
		if (err != 0 && error == 0)
			error = err;
	}

	return error;
}

int
blueioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	ioctlcmd_t cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	blue_queue_t *rqp;
	struct blue_interface *ifacep;
	struct ifnet *ifp;
	int	error = 0;

	/* check super-user privilege */
	switch (cmd) {
	case BLUE_GETSTATS:
		break;
	default:
		if ((error = suser(p->p_ucred, &p->p_acflag)) != 0)
			return (error);
		break;
	}
    
	switch (cmd) {

	case BLUE_ENABLE:
		ifacep = (struct blue_interface *)addr;
		if ((rqp = altq_lookup(ifacep->blue_ifname, ALTQT_BLUE)) == NULL) {
			error = EBADF;
			break;
		}
		error = if_altqenable(rqp->rq_ifp);
		break;

	case BLUE_DISABLE:
		ifacep = (struct blue_interface *)addr;
		if ((rqp = altq_lookup(ifacep->blue_ifname, ALTQT_BLUE)) == NULL) {
			error = EBADF;
			break;
		}
		error = if_altqdisable(rqp->rq_ifp);
		break;

	case BLUE_IF_ATTACH:
		ifp = ifunit(((struct blue_interface *)addr)->blue_ifname);
		if (ifp == NULL) {
			error = ENXIO;
			break;
		}

		/* allocate and initialize blue_state_t */
		MALLOC(rqp, blue_queue_t *, sizeof(blue_queue_t), M_DEVBUF, M_WAITOK);
		bzero(rqp, sizeof(blue_queue_t));

		MALLOC(rqp->rq_q, class_queue_t *, sizeof(class_queue_t),
		       M_DEVBUF, M_WAITOK);
		bzero(rqp->rq_q, sizeof(class_queue_t));

		MALLOC(rqp->rq_blue, blue_t *, sizeof(blue_t), M_DEVBUF, M_WAITOK); 
		bzero(rqp->rq_blue, sizeof(blue_t));

		rqp->rq_ifp = ifp;
		qtail(rqp->rq_q) = NULL;
		qlen(rqp->rq_q) = 0;
		qlimit(rqp->rq_q) = BLUE_LIMIT;

		/* default packet time: 1000 bytes / 10Mbps * 8 * 1000000 */
		blue_init(rqp->rq_blue, 0, 800, 1000, 50000);

		/*
		 * set BLUE to this ifnet structure.
		 */
		error = if_altqattach(ifp, rqp, blue_enqueue, blue_dequeue,
				      ALTQT_BLUE);
		if (error) {
			FREE(rqp->rq_blue, M_DEVBUF);
			FREE(rqp->rq_q, M_DEVBUF);
			FREE(rqp, M_DEVBUF);
			break;
		}

		/* add this state to the blue list */
		rqp->rq_next = blue_list;
		blue_list = rqp;
		break;

	case BLUE_IF_DETACH:
		ifacep = (struct blue_interface *)addr;
		if ((rqp = altq_lookup(ifacep->blue_ifname, ALTQT_BLUE)) == NULL) {
			error = EBADF;
			break;
		}
		error = blue_detach(rqp);
		break;

	case BLUE_GETSTATS:
		do {
			struct blue_stats *q_stats;
			blue_t *rp;

			q_stats = (struct blue_stats *)addr;
			if ((rqp = altq_lookup(q_stats->iface.blue_ifname,
					     ALTQT_BLUE)) == NULL) {
				error = EBADF;
				break;
			}

			q_stats->q_len 	   = qlen(rqp->rq_q);
			q_stats->q_limit   = qlimit(rqp->rq_q);

			rp = rqp->rq_blue;
			q_stats->q_pmark = rp->blue_pmark;
			q_stats->xmit_packets  = rp->blue_stats.xmit_packets;
			q_stats->xmit_bytes    = rp->blue_stats.xmit_bytes;
			q_stats->drop_packets  = rp->blue_stats.drop_packets;
			q_stats->drop_bytes    = rp->blue_stats.drop_bytes;
			q_stats->drop_forced   = rp->blue_stats.drop_forced;
			q_stats->drop_unforced = rp->blue_stats.drop_unforced;
			q_stats->marked_packets = rp->blue_stats.marked_packets;

		} while (0);
		break;

	case BLUE_CONFIG:
		do {
			struct blue_conf *fc;
			int limit;

			fc = (struct blue_conf *)addr;
			if ((rqp = altq_lookup(fc->iface.blue_ifname,
					     ALTQT_BLUE)) == NULL) {
				error = EBADF;
				break;
			}
			limit = fc->blue_limit;
			qlimit(rqp->rq_q) = limit;
			fc->blue_limit = limit;	/* write back the new value */
			if (fc->blue_pkttime > 0)
				rqp->rq_blue->blue_pkttime = fc->blue_pkttime;
			if (fc->blue_max_pmark > 0)
				rqp->rq_blue->blue_max_pmark = fc->blue_max_pmark;
			if (fc->blue_hold_time > 0)
				rqp->rq_blue->blue_hold_time = fc->blue_hold_time;
			rqp->rq_blue->blue_flags = fc->blue_flags;
			
			blue_init(rqp->rq_blue, rqp->rq_blue->blue_flags,
				 rqp->rq_blue->blue_pkttime,
				 rqp->rq_blue->blue_max_pmark,
				 rqp->rq_blue->blue_hold_time);
		} while (0);
		break;

	case BLUE_ACC_ENABLE:
		/* enable accounting mode */
		ifacep = (struct blue_interface *)addr;
		if ((rqp = altq_lookup(ifacep->blue_ifname, ALTQT_BLUE)) == NULL) {
			error = EBADF;
			break;
		}
		SET_ACCOUNTING(rqp->rq_ifp);
		break;

	case BLUE_ACC_DISABLE:
		/* disable accounting mode */
		ifacep = (struct blue_interface *)addr;
		if ((rqp = altq_lookup(ifacep->blue_ifname, ALTQT_BLUE)) == NULL) {
			error = EBADF;
			break;
		}
		CLEAR_ACCOUNTING(rqp->rq_ifp);
		break;

	default:
		error = EINVAL;
		break;
	}
	return error;
}

static int blue_detach(rqp)
	blue_queue_t *rqp;
{
	blue_queue_t *tmp;
	int error = 0;

	if (ALTQ_IS_ON(rqp->rq_ifp))
		if_altqdisable(rqp->rq_ifp);

	_flushq(rqp->rq_q);

	if ((error = if_altqdetach(rqp->rq_ifp)))
		return (error);

	if (blue_list == rqp)
		blue_list = rqp->rq_next;
	else {
		for (tmp = blue_list; tmp != NULL; tmp = tmp->rq_next)
			if (tmp->rq_next == rqp) {
				tmp->rq_next = rqp->rq_next;
				break;
			}
		if (tmp == NULL)
			printf("blue_detach: no state found in blue_list!\n");
	}

	FREE(rqp->rq_q, M_DEVBUF);
	FREE(rqp->rq_blue, M_DEVBUF);
	FREE(rqp, M_DEVBUF);
	return (error);
}

/*
 * blue support routines
 */

int 
blue_init(rp, flags, pkttime, blue_max_pmark, blue_hold_time)
	blue_t 	*rp;
	int	flags;
	int	pkttime;
	int	blue_max_pmark;
	int	blue_hold_time;
{
	int npkts_per_sec;
	
	rp->blue_idle = 1;
	rp->blue_flags = flags;
	rp->blue_pkttime = pkttime;
	rp->blue_max_pmark = blue_max_pmark;
	rp->blue_hold_time = blue_hold_time;
	if (pkttime == 0)
		rp->blue_pkttime = 1;

	/* when the link is very slow, adjust blue parameters */
	npkts_per_sec = 1000000 / rp->blue_pkttime;
	if (npkts_per_sec < 50) {
	}
	else if (npkts_per_sec < 300) {
	}

	microtime(&rp->blue_last);
	return (0);
}

/*
 * enqueue routine:
 *
 *	returns: 0 when successfully queued.
 *		 ENOBUFS when drop occurs.
 */
static int
blue_enqueue(ifp, m, pr_hdr, mode)
	struct ifnet *ifp;
	struct mbuf *m;
	struct pr_hdr *pr_hdr;
	int mode;
{
	blue_queue_t *rqp = (blue_queue_t *)ifp->if_altqp;
	int error = 0;

	switch (mode) {
	case ALTEQ_NORMAL:
		if (blue_addq(rqp->rq_blue, rqp->rq_q, m, pr_hdr) == 0) {
			/* successfully queued.  start the driver */
			if (ifp->if_start && (ifp->if_flags & IFF_OACTIVE) == 0)
				(*ifp->if_start)(ifp);
		}
		else
			error = ENOBUFS;
		break;

#if defined(ALTQ_ACCOUNT) && defined(BLUE_STATS)
		/*
		 * altq accounting mode: used just for statistics.
		 */
	case ALTEQ_ACCOK:
		rqp->rq_blue->blue_stats.xmit_packets++;
		rqp->rq_blue->blue_stats.xmit_bytes += m->m_pkthdr.len;
		break;

	case ALTEQ_ACCDROP:
		rqp->rq_blue->blue_stats.drop_packets++;
		rqp->rq_blue->blue_stats.drop_bytes += m->m_pkthdr.len;
		break;

#endif /* ALTQ_ACCOUNT && BLUE_STATS */
	}
	return error;
}

#define DTYPE_NODROP	0	/* no drop */
#define DTYPE_FORCED	1	/* a "forced" drop */
#define DTYPE_EARLY	2	/* an "unforced" (early) drop */

int blue_addq(rp, q, m, pr_hdr)
	blue_t *rp;
	class_queue_t *q;
	struct mbuf *m;
	struct pr_hdr *pr_hdr;
{
	int droptype;
    
	/*
	 * if we were idle, this is an enqueue onto an empty queue
	 * and we should decrement marking probability
	 * 
	 */
	if (rp->blue_idle) {
		struct timeval now;
		int t;
		rp->blue_idle = 0;
		microtime(&now);
		t = (now.tv_sec - rp->blue_last.tv_sec);
		if ( t > 1) {
			rp->blue_pmark = 1;
			microtime(&rp->blue_last);
		}
		else {
			t = t * 1000000 + (now.tv_usec - rp->blue_last.tv_usec);
			if (t > rp->blue_hold_time) {
				rp->blue_pmark--;
				if (rp->blue_pmark < 0) rp->blue_pmark = 0;
				microtime(&rp->blue_last);
			}
		}
	}

	/* see if we drop early */
	droptype = DTYPE_NODROP;
	if (drop_early(rp) && qlen(q) > 1) {
		/* mark or drop by blue */
		if ((rp->blue_flags & BLUEF_ECN) &&
		    mark_ecn(pr_hdr, rp->blue_flags)) {
			/* successfully marked.  do not drop. */
#ifdef BLUE_STATS
			rp->blue_stats.marked_packets++;
#endif
		}
		else { 
			/* unforced drop by blue */
			droptype = DTYPE_EARLY;
		}
	}

	/*
	 * if the queue length hits the hard limit, it's a forced drop.
	 */
	if (droptype == DTYPE_NODROP && qlen(q) >= qlimit(q))
		droptype = DTYPE_FORCED;

	/* if successful or forced drop, enqueue this packet. */
	if (droptype != DTYPE_EARLY)
		_addq(q, m);

	if (droptype != DTYPE_NODROP) {
		if (droptype == DTYPE_EARLY) {
			/* drop the incoming packet */
#ifdef BLUE_STATS
			rp->blue_stats.drop_unforced++;
#endif
		}
		else {
			struct timeval now;
			int t;
			/* forced drop, select a victim packet in the queue. */
			m = _getq_random(q);
			microtime(&now);
			t = (now.tv_sec - rp->blue_last.tv_sec);
			t = t * 1000000 + (now.tv_usec - rp->blue_last.tv_usec);
			if (t > rp->blue_hold_time) {
				rp->blue_pmark += rp->blue_max_pmark >> 3;
				if (rp->blue_pmark > rp->blue_max_pmark)
					rp->blue_pmark = rp->blue_max_pmark;
				microtime(&rp->blue_last);
			}
#ifdef BLUE_STATS
			rp->blue_stats.drop_forced++;
#endif
		}
#ifdef BLUE_STATS
		rp->blue_stats.drop_packets++;
		rp->blue_stats.drop_bytes += m->m_pkthdr.len;
#endif
		m_freem(m);
		return (-1);
	}
	/* successfully queued */
	return (0);
}

/*
 * early-drop probability is kept in blue_pmark
 *
 */
static int drop_early(rp)
	blue_t *rp;
{
	if ((random() % rp->blue_max_pmark) < rp->blue_pmark) {
		/* drop or mark */
		return (1);
	}
	/* no drop/mark */
	return (0);
}

/*
 * try to mark CE bit to the packet.
 *    returns 1 if successfully marked, 0 otherwise.
 */
static int mark_ecn(pr_hdr, flags)
	struct pr_hdr *pr_hdr;
	int flags;
{

	switch (pr_hdr->ph_family) {
	case AF_INET:
		if (flags & BLUEF_ECN4) {
			struct ip *ip = (struct ip *)pr_hdr->ph_hdr;
	    
			if (ip->ip_tos & IPTOS_ECT) {
				/* ECN-capable, mark ECN bit. */
				if ((ip->ip_tos & IPTOS_CE) == 0) {
					long sum;
		    
					ip->ip_tos |= IPTOS_CE;
					/*
					 * update checksum (from RFC1624)
					 *	   HC' = ~(~HC + ~m + m')
					 */
					sum = ~ntohs(ip->ip_sum) & 0xffff;
					sum += 0xffff + IPTOS_CE;
					sum = (sum >> 16) + (sum & 0xffff);
					sum += (sum >> 16);  /* add carry */
		
					ip->ip_sum = htons(~sum & 0xffff);
				}
				return (1);
			}
		}
		break;
#ifdef INET6
	case AF_INET6:
		if (flags & BLUEF_ECN6) {
			struct ip6_hdr *ip6 = (struct ip6_hdr *)pr_hdr->ph_hdr;

			if (ip6->ip6_flow & (IPTOS_ECT << 20)) {
				/* ECN-capable, mark ECN bit. */
				ip6->ip6_flow |= (IPTOS_CE << 20);
				return (1);
			}
		}
		break;
#endif  /* INET6 */
	}

	/* not marked */
	return (0);
}

/*
 * dequeue routine:
 *	must be called in splimp.
 *
 *	returns: mbuf dequeued.
 *		 NULL when no packet is available in the queue.
 */

static struct mbuf *
blue_dequeue(ifp, mode)
	struct ifnet *ifp;
	int mode;
{
	blue_queue_t *rqp = (blue_queue_t *)ifp->if_altqp;
	struct mbuf *m = NULL;

	switch (mode) {
	case ALTDQ_DEQUEUE:
		m = blue_getq(rqp->rq_blue, rqp->rq_q);
		break;

	case ALTDQ_PEEK:
		m = qhead(rqp->rq_q);
		break;

	case ALTDQ_FLUSH:
		_flushq(rqp->rq_q);
		m = NULL;
		break;
	}
	return m;
}

struct mbuf *blue_getq(rp, q)
	blue_t *rp;
	class_queue_t *q;
{
	struct mbuf *m;
	
	if ((m = _getq(q)) == NULL) {
		if (rp->blue_idle == 0) {
			rp->blue_idle = 1;
			microtime(&rp->blue_last);
		}
		return NULL;
	}

	rp->blue_idle = 0;
#ifdef BLUE_STATS
	rp->blue_stats.xmit_packets++;
	rp->blue_stats.xmit_bytes += m->m_pkthdr.len;
#endif
	return (m);
}

#ifdef KLD_MODULE

#include <net/altq_conf.h>

static struct altqsw blue_sw =
	{"blue", blueopen, blueclose, blueioctl};

ALTQ_MODULE(altq_blue, ALTQT_BLUE, &blue_sw);

#endif /* KLD_MODULE */

#endif /* BLUE */
