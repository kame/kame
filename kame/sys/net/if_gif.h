/*	$KAME: if_gif.h,v 1.37 2004/05/27 05:05:10 itojun Exp $	*/

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
 * if_gif.h
 */

#ifndef _NET_IF_GIF_H_
#define _NET_IF_GIF_H_


#if defined(__FreeBSD__) || defined(__NetBSD__)
#if defined(_KERNEL) && !defined(_LKM)
#include "opt_inet.h"
#endif
#endif

#include <netinet/in.h>
/* xxx sigh, why route have struct route instead of pointer? */

struct encaptab;

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
extern	void (*ng_gif_input_p)(struct ifnet *ifp, struct mbuf **mp,
		int af);
extern	void (*ng_gif_input_orphan_p)(struct ifnet *ifp, struct mbuf *m,
		int af);
extern	int  (*ng_gif_output_p)(struct ifnet *ifp, struct mbuf **mp);
extern	void (*ng_gif_attach_p)(struct ifnet *ifp);
extern	void (*ng_gif_detach_p)(struct ifnet *ifp);
#endif

struct gif_softc {
	struct ifnet	gif_if;	   /* common area - must be at the top */
	struct sockaddr	*gif_psrc; /* Physical src addr */
	struct sockaddr	*gif_pdst; /* Physical dst addr */
	union {
		struct route  gifscr_ro;    /* xxx */
#ifdef INET6
#if defined(NEW_STRUCT_ROUTE) || defined(__FreeBSD__)
		struct route gifscr_ro6; /* xxx */
#else
		struct route_in6 gifscr_ro6; /* xxx */
#endif
#endif
	} gifsc_gifscr;
	const struct encaptab *encap_cookie4;
	const struct encaptab *encap_cookie6;
	LIST_ENTRY(gif_softc) gif_list; /* all gif's are linked */

	time_t rtcache_expire;	/* expiration time of the cached route */

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	void	*gif_si;	/* softintr handle */
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	void		*gif_netgraph;	/* ng_gif(4) netgraph node info */
#endif
};

#define gif_ro gifsc_gifscr.gifscr_ro
#ifdef INET6
#define gif_ro6 gifsc_gifscr.gifscr_ro6
#endif

#define GIF_MTU		(1280)	/* Default MTU */
#define	GIF_MTU_MIN	(1280)	/* Minimum MTU */
#define	GIF_MTU_MAX	(32767)	/* Maximum MTU */

extern int ngif;
extern struct gif_softc *gif_softc;
extern LIST_HEAD(gif_softc_list, gif_softc) gif_softc_list;

/* Prototypes */
void gifattach0 __P((struct gif_softc *));
#ifndef __OpenBSD__
void gif_input __P((struct mbuf *, int, struct ifnet *));
#endif
int gif_output __P((struct ifnet *, struct mbuf *,
		    struct sockaddr *, struct rtentry *));
int gif_ioctl __P((struct ifnet *, u_long, caddr_t));
int gif_set_tunnel __P((struct ifnet *, struct sockaddr *, struct sockaddr *));
void gif_delete_tunnel __P((struct ifnet *));
#ifdef __OpenBSD__
void gif_start __P((struct ifnet *));
#endif
#ifdef GIF_ENCAPCHECK
int gif_encapcheck __P((const struct mbuf *, int, int, void *));
#endif

#endif /* _NET_IF_GIF_H_ */
