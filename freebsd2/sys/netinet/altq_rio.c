/*
 * Copyright (C) 1998-1999
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
 * $Id: altq_rio.c,v 1.1 1999/08/05 14:33:08 itojun Exp $
 */

#ifndef _NO_OPT_ALTQ_H_
#include "opt_altq.h"
#if !defined(__FreeBSD__) || (__FreeBSD__ > 2)
#include "opt_inet.h"
#endif
#endif /* !_NO_OPT_ALTQ_H_ */
#ifdef RIO	/* rio is enabled by RIO option in opt_altq.h */

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
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/altq.h>
#include <netinet/altq_classq.h>
#include <netinet/altq_red.h>
#include <netinet/altq_rio.h>

/*
 * RIO: RED with IN/OUT bit
 *   described in
 *	"Explicit Allocation of Best Effort Packet Delivery Service"
 *	David D. Clark and Wenjia Fang, MIT Lab for Computer Science
 *	http://diffserv.lcs.mit.edu/Papers/exp-alloc-ddc-wf.{ps,pdf}
 *
 * differentiated service is still under standardization process.
 * this implementation is experimental.
 * the code is a quick prototype derived from ALTQ/RED that is derived
 * from NS.
 *
 * the profile meter/tagger implementation is different from the original.
 * while the original uses a Time Sliding Window, our implementation uses 
 * a variant of a token bucket algorithm.
 */
/*
 * AF DS (differentiated service) codepoints for ALTQ/RIO.
 * the current ALTQ/RIO uses only 1 bit for drop precedence. (no medium
 * drop precedence is supported.)
 * (the class field can be set by the traffic meter, and the classes can
 * be assigned to different queues when RIO is used with CBQ.)
 * 
 *      0   1   2   3   4   5   6   7
 *    +---+---+---+---+---+---+---+---+
 *    |   CLASS   |OUT| x   0 |  CU   |
 *    +---+---+---+---+---+---+---+---+
 *
 *    class 1: 010
 *    class 2: 011
 *    class 3: 100
 *    class 4: 101
 */
#define RIO_IN			0x00
#define RIO_OUT			0x10
#define RIO_INOUTMASK		RIO_OUT
#define IS_INPROFILE(i)		(((i) & RIO_INOUTMASK) == RIO_IN)

#define RIO_CODEPOINTMASK	0xfc
#define RIO_POOL1		0x00	/* standard codespace (xxxxx0|xx) */
#define RIO_POOL2		0x0c	/* exp/lu codespace   (xxxx11|xx) */
#define RIO_POOL3		0x04	/* exp/lu codespace   (xxxx01|xx) */
#define RIO_CLASSMASK		0xe0

/* normal red parameters */
#define W_WEIGHT	512	/* inverse of weight of EWMA (511/512) */
				/* q_weight = 0.00195 */

/* red parameters for a slow link */
#define W_WEIGHT_1	128	/* inverse of weight of EWMA (127/128) */
				/* q_weight = 0.0078125 */

/* red parameters for a very slow link (e.g., dialup) */
#define W_WEIGHT_2	64	/* inverse of weight of EWMA (63/64) */
				/* q_weight = 0.015625 */

/* fixed-point uses 12-bit decimal places */
#define FP_SHIFT	12	/* fixed-point shift */

/* red parameters for drop probability */
#define INV_P_MAX	10	/* inverse of max drop probability */
#define TH_MIN		 5	/* min threshold */
#define TH_MAX		15	/* max threshold */

/* red parameters for IN packets */
#define IN_INV_P_MAX	30	/* inverse of max drop probability */
#define IN_TH_MIN	20	/* min threshold */
#define IN_TH_MAX	40	/* max threshold */

#define RIO_LIMIT	60	/* default max queue lenght */
#define RIO_STATS		/* collect statistics */

#define	TV_DELTA(a, b, delta) {					\
	register int	xxs;					\
								\
	delta = (a)->tv_usec - (b)->tv_usec; 			\
	if ((xxs = (a)->tv_sec - (b)->tv_sec) != 0) { 		\
		if (xxs < 0) { 					\
			printf("rm_class: bogus time values");	\
			delta = 60000000;			\
		}						\
		else if (xxs > 4)  {				\
			if (xxs > 60)				\
				delta = 60000000;		\
			else					\
				delta += xxs * 1000000;		\
		}						\
                else while (xxs > 0) {				\
			delta += 1000000;			\
			xxs--;					\
		}						\
	}							\
}

/* rio_list keeps all rio_queue_t's allocated. */
static rio_queue_t *rio_list = NULL;

/* internal function prototypes */
static int rio_enqueue __P((struct ifnet *, struct mbuf *,
			    struct pr_hdr *, int));
static struct mbuf *rio_dequeue __P((struct ifnet *, int));
static int rio_detach __P((rio_queue_t *));
static u_int8_t read_dsbyte __P((struct pr_hdr *));
static __inline int write_dsbyte __P((struct pr_hdr *, u_int8_t));
static struct rio_tbm *tbm_alloc __P((int, int));
static void tbm_destroy __P((struct rio_tbm *));
static int tbm_meter __P((struct rio_tbm *, int, struct timeval *));

/*
 * rio device interface
 */
altqdev_decl(rio);

int
rioopen(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	/* everything will be done when the queueing scheme is attached. */
	return 0;
}

int
rioclose(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	rio_queue_t *rqp;
	int err, error = 0;

	while ((rqp = rio_list) != NULL) {
		/* destroy all */
		err = rio_detach(rqp);
		if (err != 0 && error == 0)
			error = err;
	}

	return error;
}

int
rioioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	ioctlcmd_t cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	rio_queue_t *rqp;
	struct rio_interface *ifacep;
	struct ifnet *ifp;
	int	error = 0;

	/* check super-user privilege */
	switch (cmd) {
	case RIO_GETSTATS:
		break;
	default:
		if ((error = suser(p->p_ucred, &p->p_acflag)) != 0)
			return (error);
		break;
	}
    
	switch (cmd) {

	case RIO_ENABLE:
		ifacep = (struct rio_interface *)addr;
		if ((rqp = altq_lookup(ifacep->rio_ifname, ALTQT_RIO)) == NULL) {
			error = EBADF;
			break;
		}
		error = if_altqenable(rqp->rq_ifp);
		break;

	case RIO_DISABLE:
		ifacep = (struct rio_interface *)addr;
		if ((rqp = altq_lookup(ifacep->rio_ifname, ALTQT_RIO)) == NULL) {
			error = EBADF;
			break;
		}
		error = if_altqdisable(rqp->rq_ifp);
		break;

	case RIO_IF_ATTACH:
		ifp = ifunit(((struct rio_interface *)addr)->rio_ifname);
		if (ifp == NULL) {
			error = ENXIO;
			break;
		}

		/* allocate and initialize rio_queue_t */
		MALLOC(rqp, rio_queue_t *, sizeof(rio_queue_t), M_DEVBUF, M_WAITOK);
		if (rqp == NULL) {
			error = ENOMEM;
			break;
		}
		bzero(rqp, sizeof(rio_queue_t));

		MALLOC(rqp->rq_q, class_queue_t *, sizeof(class_queue_t),
		       M_DEVBUF, M_WAITOK);
		if (rqp->rq_q == NULL) {
			FREE(rqp, M_DEVBUF);
			error = ENOMEM;
			break;
		}
		bzero(rqp->rq_q, sizeof(class_queue_t));

		rqp->rq_rio = rio_alloc(0, 0, 0, 0, 0, 0, 0, 0, 0);
		if (rqp->rq_rio == NULL) {
			FREE(rqp->rq_q, M_DEVBUF);
			FREE(rqp, M_DEVBUF);
			error = ENOMEM;
			break;
		}

		rqp->rq_ifp = ifp;
		qtail(rqp->rq_q) = NULL;
		qlen(rqp->rq_q) = 0;
		qlimit(rqp->rq_q) = RIO_LIMIT;
		qtype(rqp->rq_q) = Q_RIO;

		/*
		 * set RIO to this ifnet structure.
		 */
		error = if_altqattach(ifp, rqp, rio_enqueue, rio_dequeue,
				      ALTQT_RIO);
		if (error) {
			rio_destroy(rqp->rq_rio);
			FREE(rqp->rq_q, M_DEVBUF);
			FREE(rqp, M_DEVBUF);
			break;
		}

		/* add this state to the rio list */
		rqp->rq_next = rio_list;
		rio_list = rqp;
		break;

	case RIO_IF_DETACH:
		ifacep = (struct rio_interface *)addr;
		if ((rqp = altq_lookup(ifacep->rio_ifname, ALTQT_RIO)) == NULL) {
			error = EBADF;
			break;
		}
		error = rio_detach(rqp);
		break;

	case RIO_GETSTATS:
		do {
			struct rio_stats *q_stats;
			rio_t *rp;

			q_stats = (struct rio_stats *)addr;
			if ((rqp = altq_lookup(q_stats->iface.rio_ifname,
					     ALTQT_RIO)) == NULL) {
				error = EBADF;
				break;
			}

			rp = rqp->rq_rio;

			q_stats->flags = rp->rio_flags;
			
			if ((rp->rio_flags & RIOF_METERONLY) == 0) {
				bcopy(&rp->q_stat, &q_stats->q_stat,
				      sizeof(struct redstat));
				bcopy(&rp->in_stat, &q_stats->in_stat,
				      sizeof(struct redstat));

				q_stats->q_len 	= qlen(rqp->rq_q);
				q_stats->q_avg 	= rp->q.avg >> rp->rio_wshift;
				q_stats->q_limit = qlimit(rqp->rq_q);
				q_stats->in_avg = rp->in.avg >> rp->rio_wshift;
				q_stats->in_len	= rp->in_qlen;
				q_stats->weight	= rp->rio_weight;
				q_stats->q_params.inv_pmax  = rp->q.inv_pmax;
				q_stats->q_params.th_min    = rp->q.th_min;
				q_stats->q_params.th_max    = rp->q.th_max;
				q_stats->in_params.inv_pmax = rp->in.inv_pmax;
				q_stats->in_params.th_min   = rp->in.th_min;
				q_stats->in_params.th_max   = rp->in.th_max;
			}
			if (rp->rio_meter != NULL)
				bcopy(&rp->rio_meter->tb_stat,
				      &q_stats->tb_stat,
				      sizeof(struct tbmstat));
			else
				bzero(&q_stats->tb_stat,
				      sizeof(struct tbmstat));

		} while (0);
		break;

	case RIO_CONFIG:
		do {
			struct rio_conf *fc;
			rio_t	*new;
			int s, limit;

			fc = (struct rio_conf *)addr;
			if ((rqp = altq_lookup(fc->iface.rio_ifname,
					     ALTQT_RIO)) == NULL) {
				error = EBADF;
				break;
			}

			new = rio_alloc(fc->rio_weight,
					fc->in_params.inv_pmax,
					fc->in_params.th_min,
					fc->in_params.th_max,
					fc->q_params.inv_pmax,
					fc->q_params.th_min,
					fc->q_params.th_max,
					fc->rio_flags,
					fc->rio_pkttime);
			if (new == NULL) {
				error = ENOMEM;
				break;
			}

			s = splimp();
			_flushq(rqp->rq_q);
			limit = fc->rio_limit;
			if (limit < fc->q_params.th_max)
				limit = fc->q_params.th_max;
			qlimit(rqp->rq_q) = limit;

			rio_destroy(rqp->rq_rio);
			rqp->rq_rio = new;

			splx(s);

			/* write back new values */
			fc->rio_limit = limit;
			fc->in_params.inv_pmax = rqp->rq_rio->in.inv_pmax;
			fc->in_params.th_min = rqp->rq_rio->in.th_min;
			fc->in_params.th_max = rqp->rq_rio->in.th_max;
			fc->q_params.inv_pmax = rqp->rq_rio->q.inv_pmax;
			fc->q_params.th_min = rqp->rq_rio->q.th_min;
			fc->q_params.th_max = rqp->rq_rio->q.th_max;


		} while (0);
		break;

	case RIO_ADD_METER:
		do {
			struct rio_meter *rmp;

			rmp = (struct rio_meter *)addr;
			if ((rqp = altq_lookup(rmp->iface.rio_ifname,
					       ALTQT_RIO)) == NULL) {
				error = EBADF;
				break;
			}

			/* attach the traffic meter/tagger */
			error = rio_set_meter(rqp->rq_rio,
					      rmp->rate, rmp->depth,
					      rmp->codepoint);

		} while (0);

	case RIO_ACC_ENABLE:
		/* enable accounting mode */
		ifacep = (struct rio_interface *)addr;
		if ((rqp = altq_lookup(ifacep->rio_ifname, ALTQT_RIO)) == NULL) {
			error = EBADF;
			break;
		}
		SET_ACCOUNTING(rqp->rq_ifp);
		break;

	case RIO_ACC_DISABLE:
		/* disable accounting mode */
		ifacep = (struct rio_interface *)addr;
		if ((rqp = altq_lookup(ifacep->rio_ifname, ALTQT_RIO)) == NULL) {
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

static int rio_detach(rqp)
	rio_queue_t *rqp;
{
	rio_queue_t *tmp;
	int error = 0;

	if (ALTQ_IS_ON(rqp->rq_ifp))
		if_altqdisable(rqp->rq_ifp);

	_flushq(rqp->rq_q);

	if ((error = if_altqdetach(rqp->rq_ifp)))
		return (error);

	if (rio_list == rqp)
		rio_list = rqp->rq_next;
	else {
		for (tmp = rio_list; tmp != NULL; tmp = tmp->rq_next)
			if (tmp->rq_next == rqp) {
				tmp->rq_next = rqp->rq_next;
				break;
			}
		if (tmp == NULL)
			printf("rio_detach: no state found in rio_list!\n");
	}

	rio_destroy(rqp->rq_rio);
	FREE(rqp->rq_q, M_DEVBUF);
	FREE(rqp, M_DEVBUF);
	return (error);
}

/*
 * rio support routines
 */

rio_t *
rio_alloc(weight, in_inv_pmax, in_th_min, in_th_max,
	  inv_pmax, th_min, th_max, flags, pkttime)
	int	weight, in_inv_pmax, in_th_min, in_th_max;
	int	inv_pmax, th_min, th_max;
	int	flags, pkttime;
{
	rio_t 	*rp;
	int	w, i;
	int	npkts_per_sec;
	
	MALLOC(rp, rio_t *, sizeof(rio_t), M_DEVBUF, M_WAITOK);
	if (rp == NULL)
		return (NULL);
	bzero(rp, sizeof(rio_t));

	rp->q.avg = 0;
	rp->q.idle = 1;
	rp->in.avg = 0;
	rp->in.idle = 1;

	if (weight == 0)
		rp->rio_weight = W_WEIGHT;
	else
		rp->rio_weight = weight;

	if (inv_pmax == 0)
		rp->q.inv_pmax = INV_P_MAX;
	else
		rp->q.inv_pmax = inv_pmax;
	if (th_min == 0)
		rp->q.th_min = TH_MIN;
	else
		rp->q.th_min = th_min;
	if (th_max == 0)
		rp->q.th_max = TH_MAX;
	else
		rp->q.th_max = th_max;

	if (in_inv_pmax == 0)
		rp->in.inv_pmax = IN_INV_P_MAX;
	else
		rp->in.inv_pmax = in_inv_pmax;
	if (in_th_min == 0)
		rp->in.th_min = IN_TH_MIN;
	else
		rp->in.th_min = in_th_min;
	if (in_th_max == 0)
		rp->in.th_max = IN_TH_MAX;
	else
		rp->in.th_max = in_th_max;

	rp->rio_flags = flags;

	if (pkttime == 0)
		/* default packet time: 1000 bytes / 10Mbps * 8 * 1000000 */
		rp->rio_pkttime = 800;
	else 
		rp->rio_pkttime = pkttime;

	if (weight == 0) {
		/* when the link is very slow, adjust red parameters */
		npkts_per_sec = 1000000 / rp->rio_pkttime;
		if (npkts_per_sec < 50) {
			/* up to about 400Kbps */
			rp->rio_weight = W_WEIGHT_2;
		}
		else if (npkts_per_sec < 300) {
			/* up to about 2.4Mbps */
			rp->rio_weight = W_WEIGHT_1;
		}
	}

	/* calculate wshift.  weight must be power of 2 */
	w = rp->rio_weight;
	for (i = 0; w > 1; i++)
		w = w >> 1;
	rp->rio_wshift = i;
	w = 1 << rp->rio_wshift;
	if (w != rp->rio_weight) {
		printf("invalid weight value %d for red! use %d\n",
		       rp->rio_weight, w);
		rp->rio_weight = w;
	}
	
	/*
	 * th_min_s and th_max_s are scaled versions of th_min and th_max
	 * to be compared with avg.
	 */
	rp->q.th_min_s = rp->q.th_min << (rp->rio_wshift + FP_SHIFT);
	rp->q.th_max_s = rp->q.th_max << (rp->rio_wshift + FP_SHIFT);

	rp->in.th_min_s = rp->in.th_min << (rp->rio_wshift + FP_SHIFT);
	rp->in.th_max_s = rp->in.th_max << (rp->rio_wshift + FP_SHIFT);

	/*
	 * precompute probability demoninator
	 *  probd = (2 * (TH_MAX-TH_MIN) / pmax) in fixed-point
	 */
	rp->q.probd = (2 * (rp->q.th_max - rp->q.th_min) * rp->q.inv_pmax)
		<< FP_SHIFT;

	rp->in.probd = (2 * (rp->in.th_max - rp->in.th_min) * rp->in.inv_pmax)
		<< FP_SHIFT;

	/* allocate weight table */
	rp->rio_wtab = wtab_alloc(rp->rio_weight);

	microtime(&rp->q.last);
	microtime(&rp->in.last);

	return (rp);
}

void
rio_destroy(rp)
	rio_t *rp;
{
	if (rp->rio_meter != NULL)
		tbm_destroy(rp->rio_meter);
	wtab_destroy(rp->rio_wtab);
	FREE(rp, M_DEVBUF);
}

/*
 * enqueue routine:
 *
 *	returns: 0 when successfully queued.
 *		 ENOBUFS when drop occurs.
 */
static int
rio_enqueue(ifp, m, pr_hdr, mode)
	struct ifnet *ifp;
	struct mbuf *m;
	struct pr_hdr *pr_hdr;
	int mode;
{
	rio_queue_t *rqp = (rio_queue_t *)ifp->if_altqp;
	int error = 0;

	switch (mode) {
	case ALTEQ_NORMAL:
		if (rio_addq(rqp->rq_rio, rqp->rq_q, m, pr_hdr) == 0) {
			/* successfully queued.  start the driver */
			if (ifp->if_start && (ifp->if_flags & IFF_OACTIVE) == 0)
				(*ifp->if_start)(ifp);
		}
		else
			error = ENOBUFS;
		break;

#if defined(ALTQ_ACCOUNT) && defined(RIO_STATS)
		/*
		 * altq accounting mode: used just for statistics.
		 */
	case ALTEQ_ACCOK:
		if (IS_INPROFILE(read_dsbyte(pr_hdr))) {
			rqp->rq_rio->in_stat.xmit_packets++;
			rqp->rq_rio->in_stat.xmit_bytes += m->m_pkthdr.len;
		}
		rqp->rq_rio->q_stat.xmit_packets++;
		rqp->rq_rio->q_stat.xmit_bytes += m->m_pkthdr.len;
		break;

	case ALTEQ_ACCDROP:
		if (IS_INPROFILE(read_dsbyte(pr_hdr))) {
			rqp->rq_rio->in_stat.drop_packets++;
			rqp->rq_rio->in_stat.drop_bytes += m->m_pkthdr.len;
		}
		rqp->rq_rio->q_stat.drop_packets++;
		rqp->rq_rio->q_stat.drop_bytes += m->m_pkthdr.len;
		break;

#endif /* ALTQ_ACCOUNT && RIO_STATS */
	}
	return error;
}

static u_int8_t
read_dsbyte(ph)
	struct pr_hdr *ph;
{
	u_int8_t ds_byte;
	
	if (ph->ph_family == AF_INET)
		ds_byte = ((struct ip *)ph->ph_hdr)->ip_tos;
#ifdef INET6
	else if (ph->ph_family == AF_INET6) {
		u_int32_t flowlabel;
		
		flowlabel = ((struct ip6_hdr *)ph->ph_hdr)->ip6_flow;
		ds_byte = (ntohl(flowlabel) >> 20) & 0xff;
	}
#endif
	else
		ds_byte = 0; /* XXX */

	return (ds_byte);
}

static __inline int
write_dsbyte(ph, dsbyte)
	struct pr_hdr *ph;
	u_int8_t dsbyte;
{
	if (ph->ph_family == AF_INET) {
		struct ip *ip = (struct ip *)ph->ph_hdr;
		u_int8_t old;
		int32_t sum;
		
		old = ip->ip_tos;
		ip->ip_tos = dsbyte;
		/*
		 * update checksum (from RFC1624)
		 *	   HC' = ~(~HC + ~m + m')
		 */
		sum = ~ntohs(ip->ip_sum) & 0xffff;
		sum += 0xff00 + (~old & 0xff) + dsbyte;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);  /* add carry */
		
		ip->ip_sum = htons(~sum & 0xffff);
	}
#ifdef INET6
	else if (ph->ph_family == AF_INET6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)ph->ph_hdr;
		u_int32_t flowlabel;

		flowlabel = ntohl(ip6->ip6_flow);
		flowlabel = (flowlabel & ~(0xff << 20)) | (dsbyte << 20);
		ip6->ip6_flow = htonl(flowlabel);
	}
#endif
	return (0);
}

#if 1
/*
 * kludge: when a packet is dequeued, we need to know whether it is IN
 * or OUT to keep the queue length for IN-packets.
 * we use mbuf flags to pass IN/OUT info.
 */
#ifndef M_PROTO1
#define M_PROTO1	m_LINK1
#endif

#define RIOM_SET_INOUT(m, i)	\
	do { if ((i)) (m)->m_flags |= M_PROTO1; \
	     else (m)->m_flags &= ~M_PROTO1; } while (0)
#define RIOM_GET_INOUT(m)	((m)->m_flags & M_PROTO1)
#endif

int rio_addq(rp, q, m, pr_hdr)
	rio_t *rp;
	class_queue_t *q;
	struct mbuf *m;
	struct pr_hdr *pr_hdr;
{
	int avg, in_avg, droptype;
	u_int8_t dsbyte, odsbyte;
	int i, n, t;
	struct timeval now;

	dsbyte = odsbyte = read_dsbyte(pr_hdr);

	now.tv_sec = 0;
	if (rp->rio_meter != NULL) {
		/* do traffic conditioning */
		microtime(&now);
		i = tbm_meter(rp->rio_meter, m->m_pkthdr.len, &now);
		dsbyte = (dsbyte & ~rp->rio_codepointmask) |
			(rp->rio_codepoint | i);

		if (rp->rio_flags & RIOF_METERONLY) {
			droptype = DTYPE_NODROP;
			goto skip;
		}
	}

#ifdef notyet
	/*
	 * should we verify that the codepoint is valid?
	 * if not, should we rewrite the codepoint?
	 */
#endif
	in_avg = 0; /* silence gcc */
	if (IS_INPROFILE(dsbyte)) {
		/* in profile, update avg_in */
		in_avg = rp->in.avg;
		if (rp->in.idle) {
			rp->in.idle = 0;
			if (now.tv_sec == 0)
				microtime(&now);
			t = (now.tv_sec - rp->in.last.tv_sec);
			if (t > 60) {
				in_avg = 0;
			}
			else {
				t = t * 1000000 + (now.tv_usec - rp->in.last.tv_usec);
				n = t / rp->rio_pkttime;
				/* the following line does (avg = (1 - Wq)^n * avg) */
				if (n > 0)
					in_avg = (in_avg >> FP_SHIFT) *
						pow_w(rp->rio_wtab, n);
			}
		}

		/* run estimator. (avg is scaled by WEIGHT in fixed-point) */
		in_avg += (rp->in_qlen << FP_SHIFT) - (in_avg >> rp->rio_wshift);
		rp->in.avg = in_avg;		/* save the new value */

		rp->in.count++;
	}

	/* update average_total */
	avg = rp->q.avg;
	if (rp->q.idle) {
		rp->q.idle = 0;
		if (now.tv_sec == 0)
			microtime(&now);
		t = (now.tv_sec - rp->q.last.tv_sec);
		if (t > 60)
			avg = 0;
		else {
			t = t * 1000000 + (now.tv_usec - rp->q.last.tv_usec);
			n = t / rp->rio_pkttime;

			/* the following line does (avg = (1 - Wq)^n * avg) */
			if (n > 0)
				avg = (avg >> FP_SHIFT) *
					pow_w(rp->rio_wtab, n);
		}
	}
	/* run estimator. (note: avg is scaled by WEIGHT in fixed-point) */
	avg += (qlen(q) << FP_SHIFT) - (avg >> rp->rio_wshift);
	rp->q.avg = avg;		/* save the new value */

	/*
	 * red_count keeps a tally of arriving traffic that has not
	 * been dropped.
	 */
	rp->q.count++;
    
	/* see if we drop early */
	droptype = DTYPE_NODROP;
	if (IS_INPROFILE(dsbyte)) {
		if (in_avg >= rp->in.th_min_s && rp->in_qlen > 1) {
			if (in_avg >= rp->in.th_max_s) {
				/* avg >= th_max: forced drop */
				droptype = DTYPE_FORCED;
			}
			else if (rp->in.old == 0) {
				/* first exceeds th_min */
				rp->in.count = 1;
				rp->in.old = 1;
			}
			else if (drop_early((in_avg - rp->in.th_min_s) >> rp->rio_wshift,
					    rp->in.probd, rp->in.count)) {
				/* mark or drop by red */
				if ((rp->rio_flags & RIOF_ECN) &&
				    (dsbyte & IPTOS_ECT)) {
					/* ecn-capable, set ce bit. */
					dsbyte |= IPTOS_CE;
					rp->in.count = 0;
#ifdef RIO_STATS
					rp->in_stat.marked_packets++;
#endif
				}
				else { 
					/* unforced drop by red */
					droptype = DTYPE_EARLY;
				}
			}
		}
		else {
			/* avg < th_min */
			rp->in.old = 0;
		}
	}
	else {
		/* out packets */
		if (avg >= rp->q.th_min_s && qlen(q) > 1) {
			if (avg >= rp->q.th_max_s) {
				/* avg >= th_max: forced drop */
				droptype = DTYPE_FORCED;
			}
			else if (rp->q.old == 0) {
				/* first exceeds th_min */
				rp->q.count = 1;
				rp->q.old = 1;
			}
			else if (drop_early((avg - rp->q.th_min_s)
					    >> rp->rio_wshift,
					    rp->q.probd, rp->q.count)) {
				/*
				 * mark or drop by red
				 * should we allow ECN for "out" packets?
				 * (this is for further research)
				 */

				/* unforced drop by red */
				droptype = DTYPE_EARLY;
			}
		}
		else {
			/* avg < th_min */
			rp->q.old = 0;
		}
	}

 skip:
	/*
	 * if the queue length hits the hard limit, it's a forced drop.
	 */
	if (droptype == DTYPE_NODROP && qlen(q) >= qlimit(q))
		droptype = DTYPE_FORCED;

	if (droptype != DTYPE_NODROP) {
		/* always drop the incoming packet (as opposed to randomdrop) */
#ifdef RIO_STATS
		if (IS_INPROFILE(dsbyte)) {
			if (droptype == DTYPE_EARLY)
				rp->in_stat.drop_unforced++;
			else
				rp->in_stat.drop_forced++;
			rp->in_stat.drop_packets++;
			rp->in_stat.drop_bytes += m->m_pkthdr.len;
		}
		if (droptype == DTYPE_EARLY)
			rp->q_stat.drop_unforced++;
		else
			rp->q_stat.drop_forced++;
		rp->q_stat.drop_packets++;
		rp->q_stat.drop_bytes += m->m_pkthdr.len;
#endif
		if (IS_INPROFILE(dsbyte))
			rp->in.count = 0;
		rp->q.count = 0;
		m_freem(m);
		return (-1);
	}

	/* save in/out type in mbuf hdr */
	RIOM_SET_INOUT(m, IS_INPROFILE(dsbyte));

	if (IS_INPROFILE(dsbyte))
		rp->in_qlen++;

	if (rp->rio_flags & RIOF_CLEARCODEPOINT)
		dsbyte &= ~RIO_CODEPOINTMASK;

	if (dsbyte != odsbyte)
		write_dsbyte(pr_hdr, dsbyte);

	_addq(q, m);

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
rio_dequeue(ifp, mode)
	struct ifnet *ifp;
	int mode;
{
	rio_queue_t *rqp = (rio_queue_t *)ifp->if_altqp;
	struct mbuf *m = NULL;

	switch (mode) {
	case ALTDQ_DEQUEUE:
		m = rio_getq(rqp->rq_rio, rqp->rq_q);
		break;

	case ALTDQ_PEEK:
		m = qhead(rqp->rq_q);
		break;

	case ALTDQ_FLUSH:
		_flushq(rqp->rq_q);
		break;
	}
	return m;
}

struct mbuf *rio_getq(rp, q)
	rio_t *rp;
	class_queue_t *q;
{
	struct mbuf *m;
	int in_profile;
	
	if ((m = _getq(q)) == NULL) {
		if (rp->q.idle == 0) {
			rp->q.idle = 1;
			microtime(&rp->q.last);
		}
		return NULL;
	}

	rp->q.idle = 0;
#ifdef RIO_STATS
	rp->q_stat.xmit_packets++;
	rp->q_stat.xmit_bytes += m->m_pkthdr.len;
#endif

	in_profile = RIOM_GET_INOUT(m);
	if (in_profile) {
		if (--rp->in_qlen == 0) {
			if (rp->in.idle == 0) {
				rp->in.idle = 1;
				microtime(&rp->in.last);
			}
		}
		rp->in.idle = 0;
#ifdef RIO_STATS
		rp->in_stat.xmit_packets++;
		rp->in_stat.xmit_bytes += m->m_pkthdr.len;
#endif
	}

	return (m);
}

int
rio_set_meter(rp, bps, depth, codepoint)
	rio_t *rp;
	int bps;
	int depth;
	int codepoint;
{
	struct rio_tbm *new = NULL;
	int s;

	if (bps >= 0) {
		new = tbm_alloc(bps, depth);
		if (new == NULL)
			return (ENOMEM);
	}
	
	s = splimp();
	if (rp->rio_meter != NULL)
		tbm_destroy(rp->rio_meter);
	if (bps < 0) {
		splx(s);
		return (0);
	}
	rp->rio_meter = new;
	if (codepoint == -1) {
		/* no codepoint is used */
		rp->rio_codepoint = 0;
		rp->rio_codepointmask = 0;
	}
	else {
		rp->rio_codepoint = (u_int8_t)codepoint;
		rp->rio_codepointmask = RIO_CODEPOINTMASK;
	}
	splx(s);
	return (0);
}

static struct rio_tbm *
tbm_alloc(bps, depth)
	int bps;
	int depth;
{
	struct rio_tbm *tb;
	
	MALLOC(tb, struct rio_tbm *, sizeof(struct rio_tbm),
	       M_DEVBUF, M_WAITOK);
	if (tb == NULL)
		return (NULL);
	bzero(tb, sizeof(struct rio_tbm));

	tb->tb_kbps = bps / 1000;
	tb->tb_max = depth;

	tb->tb_token = tb->tb_max;
	
	/*
	 * token gets full when packet interval is more than
	 * "filluptime".
	 */
	tb->tb_filluptime = (int64_t)depth * 8 * 1000 * 1000 / bps;
	microtime(&tb->tb_last);

	return (tb);
}

static void
tbm_destroy(tb)
	struct rio_tbm *tb;
{
	FREE(tb, M_DEVBUF);
}

static int
tbm_meter(tb, pkt_size, now)
	struct rio_tbm *tb;
	int	pkt_size;
	struct timeval *now;
{
	u_int32_t token, interval;
	int	rval;
	
	TV_DELTA(now, &tb->tb_last, interval);
	if (interval >= tb->tb_filluptime)
		/* more than "filluptime", the bucket gets full */
		token = tb->tb_max;
	else {
		token = tb->tb_token;
		token += interval * tb->tb_kbps / 8 / 1000;
		if (token > tb->tb_max)
			token = tb->tb_max;
	}

	if (token >= pkt_size) {
		token -= pkt_size;
		rval = RIO_IN;
#ifdef RIO_STATS
		tb->tb_stat.in_packets++;
		tb->tb_stat.in_bytes += pkt_size;
#endif		
	}
	else
		rval = RIO_OUT;

#ifdef RIO_STATS
	tb->tb_stat.packets++;
	tb->tb_stat.bytes += pkt_size;
#endif		

	tb->tb_token = token;
	tb->tb_last = *now;

	return (rval);
}

#ifdef KLD_MODULE

#include <net/altq_conf.h>

static struct altqsw rio_sw =
	{"rio", rioopen, rioclose, rioioctl};

ALTQ_MODULE(altq_rio, ALTQT_RIO, &rio_sw);

#endif /* KLD_MODULE */

#endif /* RIO */
