/*	$KAME: if_sec.c,v 1.1 2001/07/25 08:43:13 itojun Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/syslog.h>
#include <machine/cpu.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#ifdef	INET
#include <netinet/in_var.h>
#include <netinet/in_gif.h>
#endif	/* INET */

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet6/in6_gif.h>
#endif /* INET6 */

#include <net/if_gif.h>
#include <net/if_sec.h>

#include "gif.h"
#include "sec.h"
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif

#include <net/net_osdep.h>

#if NGIF == 0
#error depends on gif interface, add "pseudo-device gif"
#endif

#ifdef __freeBSD__
void secattach __P((void *));
#else
void secattach __P((int));
#endif

int sec_maxunit = -1;

/* should probably synchronize with NetBSD if_clone API */
struct ifchain {
	struct ifnet *ifp;
	LIST_ENTRY(ifchain) chain;
};
static LIST_HEAD(, ifchain) ifchainhead;

void
secattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{

	LIST_INIT(&ifchainhead);
}

struct ifnet *
sec_create(unit)
	int unit;
{
	struct gif_softc *sc;
	struct ifchain *ifcp;
	int i;

	/* monotonically-increasing unit number */
	if (i == 0) {
		if (sec_maxunit < 0)
			i = 0;
		else
			i = sec_maxunit + 1;
	}

	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAIT);
	bzero(sc, sizeof(*sc));
	ifcp = malloc(sizeof(*ifcp), M_DEVBUF, M_WAIT);
	bzero(ifcp, sizeof(*ifcp));

#if defined(__NetBSD__) || defined(__OpenBSD__)
	sprintf(sc->gif_if.if_xname, "sec%d", i);
#else
	sc->gif_if.if_name = "sec";
	sc->gif_if.if_unit = i;
#endif

	if (i > sec_maxunit)
		sec_maxunit = i;

	sc->encap_cookie4 = sc->encap_cookie6 = NULL;

	/* XXX IPsec encapsulations and path MTU... */
	sc->gif_if.if_mtu    = GIF_MTU;
	sc->gif_if.if_flags  = IFF_POINTOPOINT | IFF_MULTICAST;
	/* turn off ingress filter */
	sc->gif_if.if_flags  |= IFF_LINK2;
	sc->gif_if.if_ioctl  = gif_ioctl;
#ifdef __OpenBSD__
	sc->gif_if.if_start  = gif_start;
#endif
	sc->gif_if.if_output = gif_output;
	sc->gif_if.if_type   = IFT_GIF;
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	sc->gif_if.if_snd.ifq_maxlen = IFQ_MAXLEN;
#endif
	if_attach(&sc->gif_if);
#if NBPFILTER > 0
#ifdef HAVE_OLD_BPF
	bpfattach(&sc->gif_if, DLT_NULL, sizeof(u_int));
#else
	bpfattach(&sc->gif_if.if_bpf, &sc->gif_if, DLT_NULL, sizeof(u_int));
#endif
#endif

	ifcp->ifp = (struct ifnet *)&sc->gif_if;
	LIST_INSERT_HEAD(&ifchainhead, ifcp, chain);

	return (struct ifnet *)&sc->gif_if;
}

#ifdef __FreeBSD__
PSEUDO_SET(secattach, if_sec);
#endif

int
sec_destroy(ifp)
	struct ifnet *ifp;
{
	struct ifchain *ifcp, *next;
	struct gif_softc *sc;

	for (ifcp = LIST_FIRST(&ifchainhead); ifcp; ifcp = next) {
		next = LIST_NEXT(ifcp, chain);
		sc = (struct gif_softc *)ifp;

		if (ifp == ifcp->ifp) {
			gif_delete_tunnel(ifp);
			LIST_REMOVE(ifcp, chain);
#if NBPFILTER > 0
			bpfdetach(ifp);
#endif
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 4)
			if_detach(ifp);
			free(sc, M_DEVBUF);
#endif

			return 0;
		}
	}

	return ENOENT;
}

#if 0
struct ifnet *
sec_reusable()
{
	struct ifchain *ifcp, *next;
	struct gif_softc *sc;

	for (ifcp = LIST_FIRST(&ifchainhead); ifcp; ifcp = next) {
		next = LIST_NEXT(ifcp, chain);
		sc = (struct gif_softc *)ifcp->ifp;

		if (!sc->gif_psrc)
			return ifcp->ifp;
	}

	return NULL;
}

struct ifnet *
sec_lookup(unit)
	int unit;
{
	struct ifchain *ifcp, *next;
	char buf[IFNAMSIZ];

	for (ifcp = LIST_FIRST(&ifchainhead); ifcp; ifcp = next) {
		next = LIST_NEXT(ifcp, chain);

#if defined(__NetBSD__) || defined(__OpenBSD__)
		sprintf(buf, "sec%d", unit);
		if (strcmp(buf, ifcp->ifp->if_xname) == 0)
			return ifcp->ifp;
#else
		if (ifcp->ifp->if_unit == unit)
			return ifcp->ifp;
#endif
	}

	return NULL;
}
#endif
