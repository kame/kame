/*	$KAME: if_hif.c,v 1.71 2004/07/27 13:11:59 suz Exp $	*/

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
 * Copyright (c) 1999, 2000 and 2001 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Authors: Conny Larsson <Conny.Larsson@era.ericsson.se>
 *          Mattias Pettersson <Mattias.Pettersson@era.ericsson.se>
 *
 */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project and InternetCAR Projec\
t.
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
 *
 * Ryuji Wakikawa, Koshiro Mitsuya, Susumu Koshiba, Masafumi Watari
 * Keio University, Endo 5322, Kanagawa, Japan
 * E-mail: mip6@sfc.wide.ad.jp
 *
 */


#ifdef __FreeBSD__
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#ifdef __FreeBSD__
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#if __FreeBSD__
/*nothing*/
#else
#include <sys/ioctl.h>
#endif
#include <sys/time.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <machine/cpu.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef	INET
#include <netinet/in_var.h>
#endif	/* INET */

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>
#endif /* INET6 */

#if defined(__NetBSD__) && defined(ISO)
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#endif

#include <netinet/ip_encap.h>
#include <net/if_hif.h>

#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#include <netinet6/mip6_mncore.h>

#include "hif.h"
#ifdef __FreeBSD__
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif

#include <net/net_osdep.h>

#if NHIF > 0

extern u_int16_t mip6_dhaad_id;
extern u_int16_t mip6_mps_id;

static int hif_site_prefix_list_update_withioctl(struct hif_softc *, caddr_t);
static int hif_prefix_list_update_withprefix(struct hif_softc *, caddr_t);
static int hif_prefix_list_update_withhaaddr(struct hif_softc *, caddr_t);
static struct hif_prefix *hif_prefix_list_find_withmha(
    struct hif_prefix_list *, struct mip6_ha *);

struct hif_softc_list hif_softc_list;

#ifdef __FreeBSD__
void hifattach __P((void *));
#else
void hifattach __P((int));
#endif

#ifdef __FreeBSD__
PSEUDO_SET(hifattach, if_hif);
#endif

void
hifattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct hif_softc *sc;
	int i;

	LIST_INIT(&hif_softc_list);

	sc = malloc(NHIF * sizeof(struct hif_softc), M_DEVBUF, M_WAITOK);
	bzero(sc, NHIF * sizeof(struct hif_softc));
	for (i = 0 ; i < NHIF; sc++, i++) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		sprintf(sc->hif_if.if_xname, "hif%d", i);
#else
		sc->hif_if.if_name = "hif";
		sc->hif_if.if_unit = i;
#endif
		sc->hif_if.if_flags = IFF_MULTICAST | IFF_SIMPLEX;
		sc->hif_if.if_mtu = HIF_MTU;
		sc->hif_if.if_ioctl = hif_ioctl;
		sc->hif_if.if_output = hif_output;
		sc->hif_if.if_type = IFT_HIF;
#ifdef __NetBSD__
		sc->hif_if.if_dlt = DLT_NULL;
#endif
#ifdef __FreeBSD__
		IFQ_SET_MAXLEN(&sc->hif_if.if_snd, ifqmaxlen);
		IFQ_SET_READY(&sc->hif_if.if_snd);
#endif
		if_attach(&sc->hif_if);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		if_alloc_sadl(&sc->hif_if);
#endif
#if NBPFILTER > 0
#ifdef HAVE_NEW_BPFATTACH
		bpfattach(&sc->hif_if, DLT_NULL, sizeof(u_int));
#else
		bpfattach(&sc->hif_if.if_bpf, &sc->hif_if, DLT_NULL, sizeof(u_int));
#endif /* HAVE_NEW_BPF */
#endif /* NBPFILTER > 0 */

		sc->hif_location = HIF_LOCATION_UNKNOWN;
		sc->hif_coa_ifa = NULL;

		/* site prefix list. */
		LIST_INIT(&sc->hif_sp_list);

		/* binding update list and home agent list. */
		LIST_INIT(&sc->hif_bu_list);
		LIST_INIT(&sc->hif_prefix_list_home);
		LIST_INIT(&sc->hif_prefix_list_foreign);

		/* DHAAD related. */
		sc->hif_dhaad_id = mip6_dhaad_id++;
		sc->hif_dhaad_lastsent = 0;
		sc->hif_dhaad_count = 0;

		/* Mobile Prefix Solicitation. */
		sc->hif_mps_id = mip6_mps_id++;
		sc->hif_mps_lastsent = 0;

		sc->hif_ifid = in6addr_any;

		/* create hif_softc list */
		LIST_INSERT_HEAD(&hif_softc_list, sc, hif_entry);
	}
}

int
hif_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	caddr_t data;
{
	int s;
	struct hif_softc *sc = (struct hif_softc *)ifp;
	struct hif_ifreq *hifr = (struct hif_ifreq *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	switch(cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		/*
		 * Everything else is done at a higher level.
		 */
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {
#ifdef INET6
		case AF_INET6:
			break;
#endif
		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;

	case SIOCAHOMEPREFIX_HIF:
		error = hif_prefix_list_update_withprefix(sc, data);
		break;

	case SIOCGHOMEPREFIX_HIF:
#if 0 /* not used. */
		{
			struct mip6_prefix_ha *mpfxha;
			struct mip6_prefix *mpfx, *retmpfx;
			int i;

			retmpfx = hifr->ifr_ifru.ifr_mpfx;
			i = 0;
			for (mpfx = LIST_FIRST(&mip6_prefix_list); mpfx;
			    mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
				for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list);
				    mpfxha;
				    mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
					if (mpfxha->mpfxha_mha == NULL)
						continue;
					if (hif_ha_list_find_withmha(
					    &sc->hif_ha_list_home,
					    mpfxha->mpfxha_mha)) {
						*retmpfx = *mpfx;
						i++;
						if (i > hifr->ifr_count)
							goto ghomeprefix_done;
						retmpfx++;
						break;
					}
				}	
			}
			     
		ghomeprefix_done:
			hifr->ifr_count = i;
		}
#endif		
		break;

	case SIOCASITEPREFIX_HIF:
		error = hif_site_prefix_list_update_withioctl(sc, data);
		break;

	case SIOCAHOMEAGENT_HIF:
		error = hif_prefix_list_update_withhaaddr(sc, data);
		break;

	case SIOCGHOMEAGENT_HIF:
#if 0 /* not used. */
		{
			struct hif_ha *hha;
			struct mip6_ha *retmha;
			int i;

			i = 0;
			retmha = hifr->ifr_ifru.ifr_mha;
			for (hha = LIST_FIRST(&sc->hif_ha_list_home); hha;
			    hha = LIST_NEXT(hha, hha_entry)) {
				if (hha->hha_mha == NULL)
					continue;
				*retmha = *hha->hha_mha;
				i++;
				if (i > hifr->ifr_count)
					goto ghomeagent_done;
				retmha++;
			}
			for (hha = LIST_FIRST(&sc->hif_ha_list_foreign); hha;
			    hha = LIST_NEXT(hha, hha_entry)) {
				*retmha = *hha->hha_mha;
				i++;
				if (i > hifr->ifr_count)
					goto ghomeagent_done;
				retmha++;
			}
		ghomeagent_done:
			hifr->ifr_count = i;
		}
#endif
		break;

	case SIOCGBU_HIF:
		{
			struct mip6_bu *tmpmbu;
			struct mip6_bu *mbu = &hifr->ifr_ifru.ifr_mbu;
			int i;

			i = 0;
			for (tmpmbu = LIST_FIRST(&sc->hif_bu_list);
			     tmpmbu;
			     tmpmbu = LIST_NEXT(tmpmbu, mbu_entry)) {
				*mbu = *tmpmbu;
				i++;
				if (i > hifr->ifr_count)
					break;
				mbu++;
			}
			hifr->ifr_count = i;
		}
		break;

	case SIOCSIFID_HIF:
	{
		if (hifr == NULL) {
			error = EINVAL;
			goto hif_ioctl_done;
		}
		sc->hif_ifid = hifr->ifr_ifru.ifr_ifid;
		
		break;
	}

	default:
		error = EINVAL;
		break;
	}

 hif_ioctl_done:

	splx(s);

	return (error);
}

void
hif_save_location(sc)
	struct hif_softc *sc;
{
	sc->hif_location_prev = sc->hif_location;
}

void
hif_restore_location(sc)
	struct hif_softc *sc;
{
	sc->hif_location = sc->hif_location_prev;
}

/*
 * return the most preferable home agent entry which can be used as a
 * home agent of this hif interface.
 */
struct mip6_ha *
hif_find_preferable_ha(hif)
	struct hif_softc *hif;
{
	struct mip6_ha *mha;

	/*
	 * we assume mip6_ha_list is ordered by a preference value.
	 */
	for (mha = TAILQ_FIRST(&mip6_ha_list); mha;
	    mha = TAILQ_NEXT(mha, mha_entry)) {
		if (!hif_prefix_list_find_withmha(&hif->hif_prefix_list_home,
		    mha))
			continue;
		if (IN6_IS_ADDR_LINKLOCAL(&mha->mha_addr))
			continue;
		/* return the entry we have found first. */
		return (mha);
	}
	/* not found. */
	return (NULL);
}

/*
 * return the next preferable home agent entry which can be used as a
 * home agent of this hif interface.
 */
struct mip6_ha *
hif_find_next_preferable_ha(hif, haaddr)
	struct hif_softc *hif;
	struct in6_addr *haaddr;
{
	struct mip6_ha *curmha, *mha;

	curmha = mip6_ha_list_find_withaddr(&mip6_ha_list, haaddr);
	if (curmha == NULL)
		return (hif_find_preferable_ha(hif));

	/*
	 * we assume mip6_ha_list is ordered by a preference value.
	 */
	for (mha = TAILQ_NEXT(curmha, mha_entry); mha;
	     mha = TAILQ_NEXT(mha, mha_entry)) {
		if (!hif_prefix_list_find_withmha(&hif->hif_prefix_list_home,
		    mha))
			continue;
		/* return the entry we have found first. */
		return (mha);
	}
	/* not found. */
	return (NULL);
}

/*
 * find a hif interface which has an address specified by the argument
 * as a home address.
 */
struct hif_softc *
hif_list_find_withhaddr(haddr)
     struct in6_addr *haddr;
{
	struct hif_softc *hif;
	struct hif_prefix *hpfx;
	struct mip6_prefix *mpfx;

	for (hif = LIST_FIRST(&hif_softc_list); hif;
	    hif = LIST_NEXT(hif, hif_entry)) {
		for (hpfx = LIST_FIRST(&hif->hif_prefix_list_home); hpfx;
		    hpfx = LIST_NEXT(hpfx, hpfx_entry)) {
			mpfx = hpfx->hpfx_mpfx;
			if (IN6_ARE_ADDR_EQUAL(&mpfx->mpfx_haddr, haddr))
				return (hif);
		}
	}
	/* not found. */
	return (NULL);
}

static int
hif_prefix_list_update_withprefix(sc, data)
     struct hif_softc *sc;
     caddr_t data;
{
	struct hif_ifreq *hifr = (struct hif_ifreq *)data;
	struct mip6_prefix *nmpfx, *mpfx;
	struct hif_softc *hif;
	int error = 0;

	if (hifr == NULL) {
		return (EINVAL);
	}
	nmpfx = &hifr->ifr_ifru.ifr_mpfx;

	mpfx = mip6_prefix_list_find_withprefix(&nmpfx->mpfx_prefix,
	    nmpfx->mpfx_prefixlen);
	if (mpfx == NULL) {
		mpfx = mip6_prefix_create(&nmpfx->mpfx_prefix,
		    nmpfx->mpfx_prefixlen, nmpfx->mpfx_vltime,
		    nmpfx->mpfx_pltime);
		if (mpfx == NULL) {
			mip6log((LOG_ERR,
			    "%s:%d: mip6_prefix memory allocation failed.\n",
			     __FILE__, __LINE__));
			return (ENOMEM);
		}
		error = mip6_prefix_list_insert(&mip6_prefix_list, mpfx);
		if (error) {
			return (error);
		}

		for (hif = LIST_FIRST(&hif_softc_list); hif;
		    hif = LIST_NEXT(hif, hif_entry)) {
			if (hif == sc)
				hif_prefix_list_insert_withmpfx(
				    &hif->hif_prefix_list_home, mpfx);
			else
				hif_prefix_list_insert_withmpfx(
				    &hif->hif_prefix_list_foreign, mpfx);
		}
	}

	mip6_prefix_update_lifetime(mpfx, nmpfx->mpfx_vltime,
	    nmpfx->mpfx_pltime);

	return (0);
}

static int
hif_prefix_list_update_withhaaddr(sc, data)
     struct hif_softc *sc;
     caddr_t data;
{
	struct hif_ifreq *hifr = (struct hif_ifreq *)data;
	struct mip6_ha *nmha = (struct mip6_ha *)data;
	struct mip6_ha *mha;
	struct in6_addr prefix;
	struct mip6_prefix *mpfx;
	struct hif_softc *hif;
	int error = 0;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif

	if (hifr == NULL) {
		return (EINVAL);
	}
	nmha = &hifr->ifr_ifru.ifr_mha;
	if (IN6_IS_ADDR_UNSPECIFIED(&nmha->mha_addr)
	    ||IN6_IS_ADDR_LOOPBACK(&nmha->mha_addr)
	    ||IN6_IS_ADDR_LINKLOCAL(&nmha->mha_addr)
	    || IN6_IS_ADDR_SITELOCAL(&nmha->mha_addr))
		return (EINVAL);

	mha = mip6_ha_list_find_withaddr(&mip6_ha_list, &nmha->mha_addr);
	if (mha == NULL) {
		mha = mip6_ha_create(&nmha->mha_addr, nmha->mha_flags,
		    nmha->mha_pref, 0);
		if (mha == NULL) {
			mip6log((LOG_ERR,
			    "%s:%d: mip6_ha memory allocation failed.\n",
			    __FILE__, __LINE__));
			return (ENOMEM);
		}
		mip6_ha_list_insert(&mip6_ha_list, mha);
	}

	mha->mha_addr = nmha->mha_addr;
	mha->mha_flags = nmha->mha_flags;
	mip6_ha_update_lifetime(mha, 0);

	/* add mip6_prefix, if needed. */
	mpfx = mip6_prefix_list_find_withprefix(&mha->mha_addr, 64 /* XXX */);
	if (mpfx == NULL) {
		bzero(&prefix, sizeof(prefix));
		prefix.s6_addr32[0] = mha->mha_addr.s6_addr32[0];
		prefix.s6_addr32[1] = mha->mha_addr.s6_addr32[1];
		mpfx = mip6_prefix_create(&prefix, 64 /* XXX */, 
		    65535 /* XXX */, 0);
		if (mpfx == NULL)
			return (ENOMEM);
		error = mip6_prefix_list_insert(&mip6_prefix_list, mpfx);
		if (error)
			return (error);
		for (hif = LIST_FIRST(&hif_softc_list); hif;
		    hif = LIST_NEXT(hif, hif_entry)) {
			if (sc == hif)
				hif_prefix_list_insert_withmpfx(
				    &sc->hif_prefix_list_home, mpfx);
			else 
				hif_prefix_list_insert_withmpfx(
				    &sc->hif_prefix_list_foreign, mpfx);
		}
	}
	mip6_prefix_ha_list_insert(&mpfx->mpfx_ha_list, mha);

	return (0);
}

struct hif_prefix *
hif_prefix_list_insert_withmpfx(hif_prefix_list, mpfx)
	struct hif_prefix_list *hif_prefix_list;
	struct mip6_prefix *mpfx;
{
	struct hif_prefix *hpfx;

	if ((hif_prefix_list == NULL) || (mpfx == NULL))
		return (NULL);

	hpfx = hif_prefix_list_find_withmpfx(hif_prefix_list, mpfx);
	if (hpfx != NULL)
		return (hpfx);

	MALLOC(hpfx, struct hif_prefix *, sizeof(struct hif_prefix), M_TEMP,
	    M_NOWAIT);
	if (hpfx == NULL) {
		mip6log((LOG_ERR, "%s:%d: memory allocation failed.\n",
		    __FILE__, __LINE__));
		return (NULL);
	}
	hpfx->hpfx_mpfx = mpfx;
	LIST_INSERT_HEAD(hif_prefix_list, hpfx, hpfx_entry);

	return (hpfx);
}

void
hif_prefix_list_remove(hpfx_list, hpfx)
	struct hif_prefix_list *hpfx_list;
	struct hif_prefix *hpfx;
{
	if ((hpfx_list == NULL) || (hpfx == NULL))
		return;

	LIST_REMOVE(hpfx, hpfx_entry);
	FREE(hpfx, M_TEMP);
}

struct hif_prefix *
hif_prefix_list_find_withprefix(hif_prefix_list, prefix, prefixlen)
	struct hif_prefix_list *hif_prefix_list;
	struct in6_addr *prefix;
	int prefixlen;
{
	struct hif_prefix *hpfx;
	struct mip6_prefix *mpfx;

	for (hpfx = LIST_FIRST(hif_prefix_list); hpfx;
	    hpfx = LIST_NEXT(hpfx, hpfx_entry)) {
		mpfx = hpfx->hpfx_mpfx;
		if (in6_are_prefix_equal(prefix, &mpfx->mpfx_prefix,
			prefixlen)
		    && (prefixlen == mpfx->mpfx_prefixlen)) {
			/* found. */
			return (hpfx);
		}
	}
	/* not found. */
	return (NULL);
}

struct hif_prefix *
hif_prefix_list_find_withhaaddr(hif_prefix_list, haaddr)
	struct hif_prefix_list *hif_prefix_list;
	struct in6_addr *haaddr;
{
	struct hif_prefix *hpfx;
	struct mip6_prefix *mpfx;
	struct mip6_prefix_ha *mpfxha;
	struct mip6_ha *mha;

	for (hpfx = LIST_FIRST(hif_prefix_list); hpfx;
	    hpfx = LIST_NEXT(hpfx, hpfx_entry)) {
		mpfx = hpfx->hpfx_mpfx;
		for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list); mpfxha;
		    mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
			mha = mpfxha->mpfxha_mha;
			if (IN6_ARE_ADDR_EQUAL(&mha->mha_addr, haaddr))
				return (hpfx);
		}
	}
	/* not found. */
	return (NULL);
}

struct hif_prefix *
hif_prefix_list_find_withmpfx(hif_prefix_list, mpfx)
	struct hif_prefix_list *hif_prefix_list;
	struct mip6_prefix *mpfx;
{
	struct hif_prefix *hpfx;

	for (hpfx = LIST_FIRST(hif_prefix_list); hpfx;
	    hpfx = LIST_NEXT(hpfx, hpfx_entry)) {
		if (hpfx->hpfx_mpfx == mpfx)
			return (hpfx);
	}
	/* not found. */
	return (NULL);
}

static struct hif_prefix *
hif_prefix_list_find_withmha(hpfx_list, mha)
	struct hif_prefix_list *hpfx_list;
	struct mip6_ha *mha;
{
	struct hif_prefix *hpfx;
	struct mip6_prefix *mpfx;
	struct mip6_prefix_ha *mpfxha;

	for (hpfx = LIST_FIRST(hpfx_list); hpfx;
	    hpfx = LIST_NEXT(hpfx, hpfx_entry)) {
		mpfx = hpfx->hpfx_mpfx;
		for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list); mpfxha;
		    mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
			if (mpfxha->mpfxha_mha == mha)
				return (hpfx);
		}
	}
	/* not found. */
	return (NULL);
}

void
hif_site_prefix_list_remove(hsp_list, hsp)
	struct hif_site_prefix_list *hsp_list;
	struct hif_site_prefix *hsp;
{
	LIST_REMOVE(hsp, hsp_entry);
	FREE(hsp, M_TEMP);
}

static int
hif_site_prefix_list_update_withioctl(sc, data)
     struct hif_softc *sc;
     caddr_t data;
{
	struct hif_ifreq *hifr = (struct hif_ifreq *)data;
	struct hif_site_prefix *nhsp = (struct hif_site_prefix *)data;
	struct hif_site_prefix *hsp;

	if (hifr == NULL) {
		return (EINVAL);
	}
	nhsp = &hifr->ifr_ifru.ifr_hsp;

	for (hsp = LIST_FIRST(&sc->hif_sp_list); hsp;
	     hsp = LIST_NEXT(hsp, hsp_entry)) {
		if (!in6_are_prefix_equal(&nhsp->hsp_prefix, &hsp->hsp_prefix,
			nhsp->hsp_prefixlen))
			continue;
		if (nhsp->hsp_prefixlen != hsp->hsp_prefixlen)
			continue;
		break;
	}
	if (hsp != NULL)
		return (EEXIST);

	MALLOC(hsp, struct hif_site_prefix *, sizeof(struct hif_site_prefix),
	    M_TEMP, M_NOWAIT);
	if (hsp == NULL) {
		mip6log((LOG_ERR, "%s:%d: memory allocation failed.\n",
		    __FILE__, __LINE__));
		return (ENOMEM);
	}
	hsp->hsp_prefix = nhsp->hsp_prefix;
	hsp->hsp_prefixlen = nhsp->hsp_prefixlen;

	LIST_INSERT_HEAD(&sc->hif_sp_list, hsp, hsp_entry);

	return (0);
}

int
hif_output(ifp, m, dst, rt)
     struct ifnet *ifp;
     struct mbuf *m;
     struct sockaddr *dst;
     struct rtentry *rt;
{
	struct mip6_bu *mbu;
	struct hif_softc *hif = (struct hif_softc *)ifp;
	struct ip6_hdr *ip6;

	/* This function is copyed from looutput */

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("hif_output no HDR");

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		m_freem(m);
		return (rt->rt_flags & RTF_BLACKHOLE ? 0 :
		        rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
	}

#ifndef PULLDOWN_TEST
	/*
	 * KAME requires that the packet to be contiguous on the
	 * mbuf.  We need to make that sure.
	 * this kind of code should be avoided.
	 * XXX: fails to join if interface MTU > MCLBYTES.  jumbogram?
	 */
	if (m->m_len != m->m_pkthdr.len) {
		struct mbuf *n = NULL;
		int maxlen;

		MGETHDR(n, M_DONTWAIT, MT_HEADER);
		maxlen = MHLEN;
		if (n)
#ifdef __FreeBSD__
			m_dup_pkthdr(n, m);
#else
			M_COPY_PKTHDR(n, m);
#endif
		if (n && m->m_pkthdr.len > maxlen) {
			MCLGET(n, M_DONTWAIT);
			maxlen = MCLBYTES;
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				n = NULL;
			}
		}
		if (!n) {
			printf("looutput: mbuf allocation failed\n");
			m_freem(m);
			return ENOBUFS;
		}

		if (m->m_pkthdr.len <= maxlen) {
			m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
			n->m_len = m->m_pkthdr.len;
			n->m_next = NULL;
			m_freem(m);
		} else {
			m_copydata(m, 0, maxlen, mtod(n, caddr_t));
			m_adj(m, maxlen);
			n->m_len = maxlen;
			n->m_next = m;
		}
		m = n;
	}
#endif

	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;

	switch (dst->sa_family) {
	case AF_INET6:
		break;
	default:
		printf("hif_output: af=%d unexpected\n", dst->sa_family);
		m_freem(m);
		return (EAFNOSUPPORT);
	}

	/*
	 * if ! link-local, prepend an outer ip header and send it.
	 * if link-local, discard it.
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)
	    || IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst)
	    || IN6_IS_ADDR_SITELOCAL(&ip6->ip6_src)
	    || IN6_IS_ADDR_SITELOCAL(&ip6->ip6_dst))
		goto done;

	mbu = mip6_bu_list_find_home_registration(&hif->hif_bu_list,
	    &ip6->ip6_src);
	if (!mbu)
		goto done;

	if (IN6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr))
		goto done;

	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL)
		return (0);

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = htons((u_short)m->m_pkthdr.len - sizeof(*ip6));
	ip6->ip6_nxt = IPPROTO_IPV6;
	ip6->ip6_hlim = ip6_defhlim;
	ip6->ip6_src = mbu->mbu_coa;
	ip6->ip6_dst = mbu->mbu_paddr;
	mip6stat.mip6s_orevtunnel++;
#ifdef IPV6_MINMTU
	/* XXX */
	return (ip6_output(m, 0, 0, IPV6_MINMTU, 0, &ifp
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  ));
#else
	return (ip6_output(m, 0, 0, 0, 0, &ifp
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  ));
#endif
 done:
	m_freem(m);
	return (0);
}

#endif /* NHIF > 0 */
