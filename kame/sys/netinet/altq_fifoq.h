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
 * $Id: altq_fifoq.h,v 1.2 1999/10/02 05:58:59 itojun Exp $
 */

#ifndef _NETINET_ALTQ_FIFOQ_H_
#define _NETINET_ALTQ_FIFOQ_H_

typedef struct fifoq_state {
	struct fifoq_state *q_next;	/* next fifoq_state in the list */
	struct ifnet *q_ifp;		/* backpointer to ifnet */

	struct mbuf *q_head;		/* head of queue */
	struct mbuf *q_tail;		/* tail of queue */
	int	q_len;			/* queue length */
	int	q_limit;		/* max queue length */

	/* statistics */
	struct {
		u_int		xmit_packets;
		u_int		drop_packets;
		u_quad_t	xmit_bytes;
		u_quad_t	drop_bytes;
	} q_stats;
} fifoq_state_t;

struct fifoq_interface {
	char	fifoq_ifname[IFNAMSIZ];
};

struct fifoq_getstats {
	struct fifoq_interface iface;
	int q_len;
	int q_limit;
	u_int		xmit_packets;
	u_int		drop_packets;
	u_quad_t	xmit_bytes;
	u_quad_t	drop_bytes;
};

struct fifoq_conf {
	struct fifoq_interface iface;
	int fifoq_limit;
};

#define FIFOQ_LIMIT	50	/* default max queue lenght */

/* 
 * IOCTLs for FIFOQ
 */
#define FIFOQ_ENABLE		_IOW('Q', 1, struct fifoq_interface)
#define FIFOQ_DISABLE		_IOW('Q', 2, struct fifoq_interface)
#define	FIFOQ_IF_ATTACH		_IOW('Q', 3, struct fifoq_interface)
#define	FIFOQ_IF_DETACH		_IOW('Q', 4, struct fifoq_interface)
#define	FIFOQ_ACC_ENABLE	_IOW('Q', 5, struct fifoq_interface)
#define	FIFOQ_ACC_DISABLE	_IOW('Q', 6, struct fifoq_interface)
#define	FIFOQ_GETSTATS		_IOWR('Q', 7, struct fifoq_getstats)
#define	FIFOQ_CONFIG		_IOWR('Q', 8, struct fifoq_conf)

#endif /* _NETINET_ALTQ_FIFOQ_H_ */
