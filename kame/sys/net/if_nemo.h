/*	$KAME: if_nemo.h,v 1.1 2004/12/09 02:18:58 t-momose Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

/*
 * if_nemo.h
 */

#ifndef _NET_IF_GIF_H_
#define _NET_IF_GIF_H_


#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#if defined(_KERNEL) && !defined(_LKM)
#include "opt_inet.h"
#include "opt_mip6.h"
#endif
#endif

#include <netinet/in.h>
/* xxx sigh, why route have struct route instead of pointer? */

struct encaptab;

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
extern	void (*ng_nemo_input_p)(struct ifnet *ifp, struct mbuf **mp,
		int af);
extern	void (*ng_nemo_input_orphan_p)(struct ifnet *ifp, struct mbuf *m,
		int af);
extern	int  (*ng_nemo_output_p)(struct ifnet *ifp, struct mbuf **mp);
extern	void (*ng_nemo_attach_p)(struct ifnet *ifp);
extern	void (*ng_nemo_detach_p)(struct ifnet *ifp);
#endif

struct nemo_softc {
	struct ifnet	nemo_if;	   /* common area - must be at the top */
	struct sockaddr	*nemo_psrc; /* Physical src addr */
	struct sockaddr	*nemo_pdst; /* Physical dst addr */
	union {
		struct route  nemoscr_ro;    /* xxx */
#ifdef INET6
#if defined(NEW_STRUCT_ROUTE) || defined(__FreeBSD__)
		struct route nemoscr_ro6; /* xxx */
#else
		struct route_in6 nemoscr_ro6; /* xxx */
#endif
#endif
	} nemosc_nemoscr;
	const struct encaptab *encap_cookie4;
	const struct encaptab *encap_cookie6;
	LIST_ENTRY(nemo_softc) nemo_list; /* all nemo's are linked */

	time_t rtcache_expire;	/* expiration time of the cached route */

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	void	*nemo_si;	/* softintr handle */
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	void		*nemo_netgraph;	/* ng_nemo(4) netgraph node info */
#endif

#ifdef MIP6
	struct sockaddr	*nemo_nexthop; /* nexthop address */
#endif
};

#define nemo_ro nemosc_nemoscr.nemoscr_ro
#ifdef INET6
#define nemo_ro6 nemosc_nemoscr.nemoscr_ro6
#endif

#define GIF_MTU		(1280)	/* Default MTU */
#define	GIF_MTU_MIN	(1280)	/* Minimum MTU */
#define	GIF_MTU_MAX	(32767)	/* Maximum MTU */

extern int nnemo;
extern struct nemo_softc *nemo_softc;

/* Prototypes */
void nemoattach0 __P((struct nemo_softc *));
#ifndef __OpenBSD__
void nemo_input __P((struct mbuf *, int, struct ifnet *));
#endif
int nemo_output __P((struct ifnet *, struct mbuf *,
		    struct sockaddr *, struct rtentry *));
#if defined(__FreeBSD__) && __FreeBSD__ < 3
int nemo_ioctl __P((struct ifnet *, int, caddr_t));
#else
int nemo_ioctl __P((struct ifnet *, u_long, caddr_t));
#endif
int nemo_set_tunnel __P((struct ifnet *, struct sockaddr *, struct sockaddr *));
void nemo_delete_tunnel __P((struct ifnet *));
#ifdef __OpenBSD__
void nemo_start __P((struct ifnet *));
#endif
#ifdef GIF_ENCAPCHECK
int nemo_encapcheck __P((const struct mbuf *, int, int, void *));
#endif

#endif /* _NET_IF_GIF_H_ */
