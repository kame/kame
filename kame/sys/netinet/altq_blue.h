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
 * $Id: altq_blue.h,v 1.1 1999/10/01 04:38:05 kjc Exp $
 */

#ifndef _NETINET_ALTQ_BLUE_H_
#define _NETINET_ALTQ_BLUE_H_

struct blue_interface {
	char	blue_ifname[IFNAMSIZ];
};

struct blue_stats {
	struct blue_interface iface;
	int q_len;
	int q_limit;
	int q_pmark;
	quad_t xmit_packets;
	quad_t xmit_bytes;
	quad_t drop_packets;
	quad_t drop_bytes;
	quad_t drop_forced;
	quad_t drop_unforced;
	quad_t marked_packets;
};

struct blue_conf {
	struct blue_interface iface;
	int blue_limit;
	int blue_max_pmark;
	int blue_hold_time;
	int blue_pkttime;	/* average packet time in usec */
	int blue_flags;		/* see below */
};

/* blue flags */
#define BLUEF_ECN4	0x01	/* use packet marking for IPv4 packets */
#define BLUEF_ECN6	0x02	/* use packet marking for IPv6 packets */
#define BLUEF_ECN	(BLUEF_ECN4 | BLUEF_ECN6)

/* 
 * IOCTLs for BLUE
 */
#define BLUE_ENABLE		_IOW('Q', 1, struct blue_interface)
#define BLUE_DISABLE		_IOW('Q', 2, struct blue_interface)
#define	BLUE_IF_ATTACH		_IOW('Q', 3, struct blue_interface)
#define	BLUE_IF_DETACH		_IOW('Q', 4, struct blue_interface)
#define	BLUE_ACC_ENABLE		_IOW('Q', 5, struct blue_interface)
#define	BLUE_ACC_DISABLE	_IOW('Q', 6, struct blue_interface)
#define	BLUE_GETSTATS		_IOWR('Q', 7, struct blue_stats)
#define	BLUE_CONFIG		_IOWR('Q', 8, struct blue_conf)

#if defined(KERNEL) || defined(_KERNEL)

typedef struct blue {
	int blue_pkttime; 	/* average packet time in micro sec
				   used for idle calibration */
	int blue_flags;		/* blue flags */

	/* blue parameters */
	int blue_pmark;		/* 0-1000 (mark probability*10000) */
	int blue_max_pmark;	/* sets precision of marking probability */
	int blue_hold_time;	/* hold time in usec */

	int blue_idle;		/* queue was empty */
	struct timeval blue_last;  /* timestamp when the queue becomes idle */

	struct {
		quad_t xmit_packets;
		quad_t xmit_bytes;
		quad_t drop_packets;
		quad_t drop_bytes;
		quad_t drop_forced;
		quad_t drop_unforced;
		quad_t marked_packets;
	} blue_stats;
} blue_t;

typedef struct blue_queue {
	struct blue_queue *rq_next;	/* next blue_state in the list */
	struct ifnet *rq_ifp;		/* backpointer to ifnet */

	class_queue_t *rq_q;

	blue_t *rq_blue;
} blue_queue_t;

extern int blue_init __P((blue_t *, int, int, int, int));
extern int blue_addq __P((blue_t *, class_queue_t *, struct mbuf *,
			 struct pr_hdr *));
extern struct mbuf *blue_getq __P((blue_t *, class_queue_t *));

#endif /* KERNEL */

#endif /* _NETINET_ALTQ_BLUE_H_ */
