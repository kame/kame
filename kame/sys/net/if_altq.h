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
 * $Id: if_altq.h,v 1.2 1999/10/02 05:58:57 itojun Exp $
 */
#ifndef _NET_IF_ALTQ_H_
#define _NET_IF_ALTQ_H_

struct pr_hdr;	/* for genassym */

#if defined(KERNEL) || defined(_KERNEL)

/* protocol header info is passed to an enqueue routine */
struct pr_hdr {
	u_int8_t	ph_family;	/* protocol family (e,g, PF_INET) */
	caddr_t		ph_hdr;		/* pointer to a protocol header */
};

/* if_altqflags */
#define ALTQF_READY	 0x01	/* driver supports alternate queueing */
#define ALTQF_ENABLE	 0x02	/* altq is in use */
#define ALTQF_ACCOUNTING 0x04	/* altq accounting is enabled */
#define ALTQF_CNDTNING	 0x08	/* altq traffic conditioning is enabled */
#define ALTQF_DRIVER1	 0x40	/* driver specific */

/* if_altqflags set internally only: */
#define	ALTQF_CANTCHANGE 	(ALTQF_READY)

#define ALTQ_IS_READY(ifp)	((ifp)->if_altqflags & ALTQF_READY)
#define ALTQ_IS_ON(ifp)		((ifp)->if_altqflags & ALTQF_ENABLE)
#define ALTQ_IS_CNDTNING(ifp)	((ifp)->if_altqflags & ALTQF_CNDTNING)

#define SET_ACCOUNTING(ifp)	((ifp)->if_altqflags |= ALTQF_ACCOUNTING)
#define CLEAR_ACCOUNTING(ifp)	((ifp)->if_altqflags &= ~ALTQF_ACCOUNTING)
#define SET_CNDTNING(ifp)	((ifp)->if_altqflags |= ALTQF_CNDTNING)
#define CLEAR_CNDTNING(ifp)	((ifp)->if_altqflags &= ~ALTQF_CNDTNING)

/* if_altqenqueue 4th arg */
#define ALTEQ_NORMAL	0	/* normal queueing */
#define ALTEQ_ACCOK	1	/* accounting successful queueing */
#define ALTEQ_ACCDROP	2	/* accounting packet drop */

/* if_altqdequeue 2nd arg */	
#define ALTDQ_DEQUEUE	0	/* dequeue mbuf from the queue */
#define ALTDQ_PEEK	1	/* don't dequeue mbuf from the queue */
#define ALTDQ_FLUSH	2	/* discard all the queued packets */

#define ALTQ_ACCOUNTING(ifp, m, h, mode) \
		if ((ifp)->if_altqflags & ALTQF_ACCOUNTING) \
			(ifp)->if_altqenqueue((ifp), (m), (h), (mode));

#endif /* KERNEL */

#endif /* _NET_IF_ALTQ_H_ */

