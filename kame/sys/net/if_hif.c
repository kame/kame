/*	$KAME: if_hif.c,v 1.54 2003/08/07 09:30:58 keiichi Exp $	*/

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
 * Ryuji Wakikawa, Koshiro Mitsuya, Susumu Koshiba, Masashi Watari
 * Keio University, Endo 5322, Kanagawa, Japan
 * E-mail: mip6@sfc.wide.ad.jp
 *
 */


#if defined(__FreeBSD__) && __FreeBSD__ >= 3
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
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#if defined(__FreeBSD__) || __FreeBSD__ >= 3
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
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif

#include <net/net_osdep.h>

#if NHIF > 0

static int hif_site_prefix_list_update_withioctl(struct hif_softc *, caddr_t);
static int hif_ha_list_update_withmpfx(struct hif_softc *, caddr_t);
static int hif_ha_list_update_withioctl(struct hif_softc *, caddr_t);

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

	TAILQ_INIT(&hif_softc_list);

	sc = malloc(NHIF * sizeof(struct hif_softc), M_DEVBUF, M_WAIT);
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
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
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
		LIST_INIT(&sc->hif_ha_list_home);
		LIST_INIT(&sc->hif_ha_list_foreign);

		/* DHAAD related. */
		sc->hif_dhaad_id = 0;
		sc->hif_dhaad_lastsent = 0;
		sc->hif_dhaad_count = 0;

		sc->hif_ifid = in6addr_any;

		/* create hif_softc list */
		TAILQ_INSERT_TAIL(&hif_softc_list, sc, hif_entry);
	}
}

int
hif_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
#if defined(__FreeBSD__) && __FreeBSD__ < 3
	int cmd;
#else
	u_long cmd;
#endif
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
		error = hif_ha_list_update_withmpfx(sc, data);
		break;

	case SIOCGHOMEPREFIX_HIF:
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
		
		break;

	case SIOCASITEPREFIX_HIF:
		error = hif_site_prefix_list_update_withioctl(sc, data);
		break;

	case SIOCAHOMEAGENT_HIF:
		error = hif_ha_list_update_withioctl(sc, data);
		break;

	case SIOCGHOMEAGENT_HIF:
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
		break;

	case SIOCGBU_HIF:
		{
			struct mip6_bu *tmpmbu;
			struct mip6_bu *mbu = hifr->ifr_ifru.ifr_mbu;
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
		sc->hif_ifid = *hifr->ifr_ifru.ifr_ifid;
		
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

struct hif_ha *
hif_ha_list_insert(hha_list, mha)
	struct hif_ha_list *hha_list;
	struct mip6_ha *mha;
{
	struct hif_ha *hha;

	if ((hha_list == NULL) || (mha == NULL))
		panic("hha_list nor mha must not be NULL");

	MALLOC(hha, struct hif_ha *, sizeof(struct hif_ha), M_TEMP, M_NOWAIT);
	if (hha == NULL) {
		mip6log((LOG_ERR, "%s:%d: memory allocation failed.\n",
		    __FILE__, __LINE__));
		return (NULL);
	}
	hha->hha_mha = mha;
	MIP6_HA_REF(mha);
	LIST_INSERT_HEAD(hha_list, hha, hha_entry);
	return (hha);
}

void
hif_ha_list_remove(hha_list, hha)
	struct hif_ha_list *hha_list;
	struct hif_ha *hha;
{
	if ((hha_list == NULL) || (hha == NULL))
		panic("hha_list nor hha must not be NULL");

	LIST_REMOVE(hha, hha_entry);
	MIP6_HA_FREE(hha->hha_mha);
	FREE(hha, M_TEMP);
}

/*
 * return the pointer of the entity of hif_ha structure advertising
 * the specified prefix, which is listed in hif_ha_list structure.
 * even if there are more than one entitiy, return the first found
 * one.
 */
struct hif_ha *
hif_ha_list_find_withprefix(hif_ha_list, prefix, prefixlen)
	struct hif_ha_list *hif_ha_list;
	struct sockaddr_in6 *prefix;
	int prefixlen;
{
	struct hif_ha *hha;
	struct mip6_prefix_ha *mpfxha;
	struct mip6_prefix *mpfx;

	for (hha = LIST_FIRST(hif_ha_list); hha;
	    hha = LIST_NEXT(hha, hha_entry)) {
		if (hha->hha_mha == NULL)
			panic("hha_mha == NULL");
		for (mpfx = LIST_FIRST(&mip6_prefix_list); mpfx;
		    mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
			if (!in6_are_prefix_equal(&mpfx->mpfx_prefix.sin6_addr,
				&prefix->sin6_addr, prefixlen))
				continue;
			for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list); mpfxha;
			    mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
				if (mpfxha->mpfxha_mha == NULL)
					continue;
				if (hha->hha_mha == mpfxha->mpfxha_mha) {
					/* found. */
					return (hha);
				}
			}
		}
	}
	/* not found. */
	return (NULL);
}

/*
 * return the pointer of the entity of mip6_ha structure which has the
 * specified address (either link-local address or global address).
 * even if there are more than one entitiy, return the first found
 * one.
 */    
struct hif_ha *
hif_ha_list_find_withaddr(hif_ha_list, addr)
	struct hif_ha_list *hif_ha_list;
	struct sockaddr_in6 *addr;
{
	struct hif_ha *hha;

	for (hha = LIST_FIRST(hif_ha_list); hha;
	    hha = LIST_NEXT(hha, hha_entry)) {
		if (hha->hha_mha == NULL)
			panic("hha->hha_mha == NULL");
		if (SA6_ARE_ADDR_EQUAL(&hha->hha_mha->mha_lladdr, addr))
			return (hha);
		/* XXX for each gaddr. */
		if (SA6_ARE_ADDR_EQUAL(&hha->hha_mha->mha_gaddr, addr))
			return (hha);
	}
	/* not found. */
	return (NULL);
}

struct hif_ha *
hif_ha_list_find_withmpfx(hif_ha_list, mpfx)
	struct hif_ha_list *hif_ha_list;
	struct mip6_prefix *mpfx;
{
	struct mip6_prefix_ha *mpfxha;
	struct hif_ha *hha;

	for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list); mpfxha;
	     mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
		if (mpfxha->mpfxha_mha == NULL)
			continue;
		hha = hif_ha_list_find_withmha(hif_ha_list,
		    mpfxha->mpfxha_mha);
		if (hha != NULL)
			return (hha);
	}
	/* not found. */
	return (NULL);
}

struct hif_ha *
hif_ha_list_find_withmha(hif_ha_list, mha)
	struct hif_ha_list *hif_ha_list;
	struct mip6_ha *mha;
{
	struct hif_ha *hha;

	for (hha = LIST_FIRST(hif_ha_list); hha;
	    hha = LIST_NEXT(hha, hha_entry)) {
		if (hha->hha_mha == NULL)
			panic("hha->hha_mha == NULL");
		if (hha->hha_mha == mha)
			return (hha);
	}
	/* not found. */
	return (NULL);
}

struct hif_ha *
hif_ha_list_find_preferable(hif_ha_list, mpfx)
	struct hif_ha_list *hif_ha_list;
	struct mip6_prefix *mpfx;
{
	struct hif_ha *hha;

	/* XXX */
	hha = LIST_FIRST(hif_ha_list);
	if (hha)
		return(hha);
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
	if ((nhsp = hifr->ifr_ifru.ifr_hsp) == NULL) {
		return (EINVAL);
	}

	for (hsp = LIST_FIRST(&sc->hif_sp_list); hsp;
	     hsp = LIST_NEXT(hsp, hsp_entry)) {
		if (!in6_are_prefix_equal(&nhsp->hsp_prefix.sin6_addr,
			&hsp->hsp_prefix.sin6_addr, nhsp->hsp_prefixlen))
			continue;
		if (nhsp->hsp_prefix.sin6_scope_id
		    != hsp->hsp_prefix.sin6_scope_id)
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

static int
hif_ha_list_update_withioctl(sc, data)
     struct hif_softc *sc;
     caddr_t data;
{
	struct hif_ifreq *hifr = (struct hif_ifreq *)data;
	struct mip6_ha *nmha = (struct mip6_ha *)data;
	struct mip6_ha *mha;
	struct hif_ha *hha;
	int error = 0;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	if (hifr == NULL) {
		return (EINVAL);
	}
	if ((nmha = hifr->ifr_ifru.ifr_mha) == NULL) {
		return (EINVAL);
	}

	hha = hif_ha_list_find_withaddr(&sc->hif_ha_list_home,
	    &nmha->mha_lladdr);
	if (hha == NULL) {
		mha = mip6_ha_create(&nmha->mha_lladdr, &nmha->mha_gaddr,
		    nmha->mha_flags, nmha->mha_pref, nmha->mha_lifetime);
		if (mha == NULL) {
			mip6log((LOG_ERR,
			    "%s:%d: mip6_ha memory allocation failed.\n",
			    __FILE__, __LINE__));
			return (ENOMEM);
		}
		error = mip6_ha_list_insert(&mip6_ha_list, mha);
		if (error) {
			return (error);
		}
	} else
		mha = hha->hha_mha;

	mha->mha_lladdr = nmha->mha_lladdr;
	mha->mha_gaddr = nmha->mha_gaddr;
	mha->mha_flags = nmha->mha_flags;
	mha->mha_pref = nmha->mha_pref;
	mha->mha_lifetime = nmha->mha_lifetime;
	mha->mha_expire = time_second + mha->mha_lifetime;

	return (0);
}

struct hif_softc *
hif_list_find_withhaddr(haddr)
     struct sockaddr_in6 *haddr;
{
	struct hif_softc *sc;
	struct mip6_prefix *mpfx;
	struct mip6_prefix_ha *mpfxha;

	for (mpfx = LIST_FIRST(&mip6_prefix_list); mpfx;
	    mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
		if (!SA6_ARE_ADDR_EQUAL(&mpfx->mpfx_haddr, haddr))
			continue;
		for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list); mpfxha;
		     mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
			if (mpfxha->mpfxha_mha == NULL)
				continue;
			for (sc = TAILQ_FIRST(&hif_softc_list); sc;
			    sc = TAILQ_NEXT(sc, hif_entry)) {
				if (hif_ha_list_find_withmha(
				    &sc->hif_ha_list_home,
				    mpfxha->mpfxha_mha))
				    return (sc);
			}
		}
	}
	/* not found. */
	return (NULL);
}

static int
hif_ha_list_update_withmpfx(sc, data)
     struct hif_softc *sc;
     caddr_t data;
{
	struct hif_ifreq *hifr = (struct hif_ifreq *)data;
	struct mip6_prefix *nmpfx, *mpfx;
	int mpfx_is_new = 0;
	struct mip6_ha *mha;
	struct hif_ha *hha;
	int error = 0;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	if (hifr == NULL) {
		return (EINVAL);
	}
	if ((nmpfx = hifr->ifr_ifru.ifr_mpfx) == NULL) {
		return (EINVAL);
	}

	mpfx = mip6_prefix_list_find(nmpfx);
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
		mpfx_is_new = 1;
		error = mip6_prefix_list_insert(&mip6_prefix_list, mpfx);
		if (error) {
			return (error);
		}
	}

	mpfx->mpfx_vltime = nmpfx->mpfx_vltime;
	mpfx->mpfx_vlexpire = time_second + mpfx->mpfx_vltime;
	mpfx->mpfx_pltime = nmpfx->mpfx_pltime;
	mpfx->mpfx_plexpire = time_second + mpfx->mpfx_pltime;

	if (mpfx_is_new) {
		hha = hif_ha_list_find_withmpfx(&sc->hif_ha_list_home, mpfx);
		if (hha == NULL) {
			struct sockaddr_in6 any = sa6_any;
			mha = mip6_ha_create(&any, NULL, 0, 0,
			    MIP6_HA_DEFAULT_LIFETIME);
			hif_ha_list_insert(&sc->hif_ha_list_home, mha);
		} else
			mha = hha->hha_mha;
		mip6_prefix_ha_list_insert(&mpfx->mpfx_ha_list, mha);
	}

	return (0);
}

int
hif_output(ifp, m, dst, rt)
     struct ifnet *ifp;
     struct mbuf *m;
     struct sockaddr *dst;
     struct rtentry *rt;
{
	struct sockaddr_in6 src_sa, dst_sa;
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
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000 && __FreeBSD_version < 500000
			m_dup_pkthdr(n, m, M_DONTWAIT);
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
	if (ip6_getpktaddrs(m, &src_sa, &dst_sa))
		goto done;

	if (IN6_IS_ADDR_LINKLOCAL(&src_sa.sin6_addr)
	    || IN6_IS_ADDR_LINKLOCAL(&dst_sa.sin6_addr)
#ifdef MIP6_DISABLE_SITELOCAL
	    || IN6_IS_ADDR_SITELOCAL(&src_sa.sin6_addr)
	    || IN6_IS_ADDR_SITELOCAL(&dst_sa.sin6_addr)
#endif
		)
		goto done;

	mbu = mip6_bu_list_find_home_registration(&hif->hif_bu_list, &src_sa);
	if (!mbu)
		goto done;

	if (IN6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr.sin6_addr))
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
	ip6->ip6_src = mbu->mbu_coa.sin6_addr;
	ip6->ip6_dst = mbu->mbu_paddr.sin6_addr;
	if (!ip6_setpktaddrs(m, &mbu->mbu_coa, &mbu->mbu_paddr))
		goto done;
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);
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
