/*	$KAME: if_sec.c,v 1.13 2001/07/27 18:45:13 itojun Exp $	*/

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

#ifdef __FreeBSD__
void secattach __P((void *));
#else
void secattach __P((int));
#endif
static struct ifnet *sec_create __P((int));
static int sec_destroy __P((struct ifnet *));

int sec_maxunit = -1;

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

static struct ifnet *
sec_create(unit)
	int unit;
{
	struct sec_softc *sc;
	struct ifchain *ifcp;

	/* monotonically-increasing unit number */
	if (unit == 0) {
		if (0 > sec_maxunit)
			unit = 0;
		else
			unit = sec_maxunit + 1;
	}
	if (unit > sec_maxunit)
		sec_maxunit = unit;

	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAIT);
	bzero(sc, sizeof(*sc));
	ifcp = malloc(sizeof(*ifcp), M_DEVBUF, M_WAIT);
	bzero(ifcp, sizeof(*ifcp));

#if defined(__NetBSD__) || defined(__OpenBSD__)
	sprintf(sc->sc_gif.gif_if.if_xname, "sec%d", unit);
#else
	sc->sc_gif.gif_if.if_name = "sec";
	sc->sc_gif.gif_if.if_unit = unit;
#endif

	gifattach0(&sc->sc_gif);

	sc->sc_gif.gif_if.if_ioctl = sec_ioctl;

	ifcp->ifp = (struct ifnet *)&sc->sc_gif.gif_if;
	LIST_INSERT_HEAD(&ifchainhead, ifcp, chain);

	return (struct ifnet *)&sc->sc_gif.gif_if;
}

#ifdef __FreeBSD__
PSEUDO_SET(secattach, if_sec);
#endif

static int
sec_destroy(ifp)
	struct ifnet *ifp;
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 4)
	struct ifchain *ifcp, *next;

	for (ifcp = LIST_FIRST(&ifchainhead); ifcp; ifcp = next) {
		next = LIST_NEXT(ifcp, chain);

		if (ifp == ifcp->ifp) {
			gif_delete_tunnel(ifp);
			LIST_REMOVE(ifcp, chain);
#if NBPFILTER > 0
			bpfdetach(ifp);
#endif
			if_detach(ifp);
			free(ifp, M_DEVBUF);

			return 0;
		}
	}

	return ENOENT;
#else
	return EOPNOTSUPP;
#endif
}

/* must be splimp to call this */
struct ifnet *
sec_establish(psrc, pdst)
	struct sockaddr *psrc;
	struct sockaddr *pdst;
{
	struct ifchain *ifcp, *next;
	struct gif_softc *gif;
	struct ifnet *ifp;
	int error;

	for (ifcp = LIST_FIRST(&ifchainhead); ifcp; ifcp = next) {
		next = LIST_NEXT(ifcp, chain);

		gif = &((struct sec_softc *)ifcp->ifp)->sc_gif;

		if (!gif->gif_pdst || !gif->gif_psrc)
			continue;
		if (gif->gif_pdst->sa_family != pdst->sa_family ||
		    gif->gif_pdst->sa_len != pdst->sa_len ||
		    gif->gif_psrc->sa_family != psrc->sa_family ||
		    gif->gif_psrc->sa_len != psrc->sa_len)
			continue;
		if (bcmp(gif->gif_pdst, pdst, pdst->sa_len) == 0 &&
		    bcmp(gif->gif_psrc, psrc, psrc->sa_len) == 0) {
			break;
		}
	}

	if (ifcp)
		ifp = ifcp->ifp;
	else {
		ifp = sec_create(0);
		if (!ifp)
			return NULL;
		error = gif_set_tunnel(ifp, psrc, pdst);
		if (error) {
			sec_destroy(ifp);
			return NULL;
		}
	}

	((struct sec_softc *)ifp)->sc_refcnt++;
	return ifp;
}

/* must be splimp to call this */
int
sec_demolish(ifp)
	struct ifnet *ifp;
{
	struct sec_softc *sc = (struct sec_softc *)ifp;

	/* if refcnt is already negative, punt */
	if (sc->sc_refcnt <= 0)
		return EINVAL;
	if (--sc->sc_refcnt > 0)
		return 0;

	(void)gif_delete_tunnel(ifp);
	if_down(ifp);
	(void)sec_destroy(ifp);
	return 0;
}

int
sec_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
#if defined(__FreeBSD__) && __FreeBSD__ < 3
	int cmd;
#else
	u_long cmd;
#endif
	caddr_t data;
{

	/* forbid outer address changes */
	switch (cmd) {
#ifdef INET
	case SIOCSIFPHYADDR:
#endif
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif /* INET6 */
	case SIOCSLIFPHYADDR:
#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
#endif
		return EOPNOTSUPP;

	default:
		return gif_ioctl(ifp, cmd, data);
	}
}

#if 0
struct ifnet *
sec_reusable()
{
	struct ifchain *ifcp, *next;
	struct sec_softc *sc;

	for (ifcp = LIST_FIRST(&ifchainhead); ifcp; ifcp = next) {
		next = LIST_NEXT(ifcp, chain);
		sc = (struct sec_softc *)ifcp->ifp;

		if (!sc->gif_psrc && !sc->gif_pdst)
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
