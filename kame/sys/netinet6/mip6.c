/*	$KAME: mip6.c,v 1.57 2001/10/03 08:19:17 keiichi Exp $	*/

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

/*
 * Copyright (c) 1999, 2000 and 2001 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Authors: Conny Larsson <Conny.Larsson@era.ericsson.se>
 *          Mattias Pettersson <Mattias.Pettersson@era.ericsson.se>
 *
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_ipsec.h"
#include "opt_mip6.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/net_osdep.h>

#include <net/if_hif.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>

#if defined(IPSEC) && !defined(__OpenBSD__)
#include <netinet6/ipsec.h>
#endif

#include <netinet6/mip6.h>

extern struct mip6_subnet_list mip6_subnet_list;
extern struct mip6_prefix_list mip6_prefix_list;

extern struct mip6_bc_list mip6_bc_list;

struct mip6_config mip6_config;

struct nd_defrouter *mip6_dr;


#ifdef __NetBSD__
struct callout mip6_pfx_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_pfx_ch;
#endif
int mip6_pfx_timer_running = 0;

static int mip6_determine_location_withndpr __P((struct hif_softc *,
						 struct in6_addr *,
						 struct nd_prefix *,
						 struct nd_defrouter *));
static int mip6_haddr_config __P((struct hif_softc *, struct ifnet *));
static int mip6_process_movement __P((struct hif_softc *, int));
static int mip6_select_coa __P((struct ifnet *));
static int mip6_remove_addrs __P((struct ifnet *));
static int mip6_attach_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_detach_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_add_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_remove_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_remove_addr __P((struct ifnet *, struct in6_ifaddr *));

/* ipv6 header manipuration functions */
static int mip6_rthdr_create_withdst __P((struct ip6_rthdr **,
					  struct in6_addr *));
static int mip6_haddr_destopt_create __P((struct ip6_dest **,
					  struct in6_addr *,
					  struct in6_addr *,
					  struct hif_softc *));
static int mip6_bu_destopt_create __P((struct ip6_dest **,
				       struct in6_addr *,
				       struct in6_addr *,
				       struct ip6_pktopts *,
				       struct hif_softc *));
static void mip6_find_offset __P((struct mip6_buffer *));
static void mip6_align_destopt __P((struct mip6_buffer *));
static caddr_t mip6_add_opt2dh __P((caddr_t, struct mip6_buffer *));

void
mip6_init()
{
	mip6_config.mcfg_debug = 1;
	mip6_config.mcfg_type = 0;

	mip6_dr = NULL;

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3) 
        callout_init(&mip6_pfx_ch);
#endif

	mip6_bu_init(); /* binding update routine initialize */
	mip6_ha_init(); /* homeagent list management initialize */
	mip6_bc_init(); /* binding cache routine initailize */
	mip6_prefix_init();
	mip6_subnet_init();

	LIST_INIT(&mip6_subnet_list);
}

/*
 * default router change is one of possible reason of movement.
 * check it.
 */
int
mip6_process_defrouter_change(dr)
	struct nd_defrouter *dr;
{
	int error = 0;
#ifdef MD_WITH_DEFROUTER_CHANGE
	struct hif_softc *sc;
	struct mip6_pfx *mpfx;
	struct nd_prefix *pr;
	int coa_changed;

	if (dr == NULL) {
		/* we lost a default router.  maybe we are isolated. */
		return (0);
	}
	if ((mip6_dr != NULL)
	    && (IN6_ARE_ADDR_EQUAL(&mip6_dr->rtaddr, &dr->rtaddr))) {
		/*
		 * the default router wan't changed.
		 */
		return (0);
	}

	/*
	 *  at this point, we have a default router that is different
	 *  from the previous default router.
	 */
	mip6_dr = dr;

	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		sc->hif_prevloc = sc->hif_location;
		for (mpfx = LIST_FIRST(&sc->hif_pfx_list);
		     mpfx;
		     mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
			for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
				if (pr->ndpr_raf_onlink
				    && mip6_pfx_list_find_withndpr(&sc->hif_pfx_list, pr, MIP6_MPFX_IS_HOME)) {
					sc->hif_location = HIF_LOCATION_HOME;
				} else {
					sc->hif_location 
						= HIF_LOCATION_FOREIGN;
				}
			}
		}
	}

	coa_change = mip6_select_coa(dr->ifp);
	if (coa_changed == -1) {
		error = -1;
		goto process_defrouter_change_done;
	}

	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		if (mip6_process_movement(sc, coa_changed)) {
			error = -1;
			goto process_defrouter_change_done;
		}
	}

 process_defrouter_change_done:
#endif /* MD_WITH_DEFROUTER_CHANGE */
	return (error);
}

/*
 * we heard a router advertisement.
 * from the advertised prefix, we may be able to check our movement.
 */
int
mip6_process_nd_prefix(saddr, ndpr, dr, m)
	struct in6_addr *saddr;
	struct nd_prefix *ndpr;
	struct nd_defrouter *dr;
	struct mbuf *m;
{
	struct hif_softc *sc;
	int coa_changed;
	int error = 0;

	if (dr == NULL) {
		struct mip6_ha *mha;
		/*
		 * advertizing router is shutting down.
		 */
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, saddr);
		if (mha) {
			error = mip6_ha_list_remove(&mip6_ha_list, mha);
		}
		return (error);
	}

	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		sc->hif_location_prev = sc->hif_location;
		sc->hif_hs_prev = sc->hif_hs_current;
		error = mip6_determine_location_withndpr(sc, saddr, ndpr, dr);
		if (error) {
			mip6log((LOG_ERR,
				 "%s: error while determining location\n",
				 __FUNCTION__));
			goto process_ndpr_done;
		}
		error = mip6_haddr_config(sc, ndpr->ndpr_ifp);
		if (error) {
			goto process_ndpr_done;
		}

	}

	/* update nd prefix list and perform addrconf. */
	(void)prelist_update(ndpr, dr, m);

	/* select a prefereable coa. */
	coa_changed = mip6_select_coa(ndpr->ndpr_ifp);
	if (coa_changed == -1) {
		error = -1;
		goto process_ndpr_done;
	}

	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		if (mip6_process_movement(sc, coa_changed)) {
			error = -1;
			goto process_ndpr_done;
		}
	}
 process_ndpr_done:
	return (error);
}

/*
 * if (ndpr == homepr) {
 *   we are home
 * }
 * if (ndpr != homepr && ra == one of home ha) {
 *   we are home
 *   ndpr is a new homepr
 * }
 * if (ndpr != homepr && ra != one of home ha) {
 *   we are foreign
 * }
 */
static int
mip6_determine_location_withndpr(sc, rtaddr, ndpr, dr)
	struct hif_softc *sc;
	struct in6_addr *rtaddr;
	struct nd_prefix *ndpr;
	struct nd_defrouter *dr;
{
	struct hif_subnet *hs, *hsbypfx, *hsbyha;
	struct mip6_subnet *ms;
	struct mip6_subnet_prefix *mspfx = NULL;
	struct mip6_subnet_ha *msha = NULL;
	struct mip6_prefix tmpmpfx, *mpfx;
	struct mip6_ha *mha;
	int mpfx_is_new, mha_is_new;
	int error = 0;

	sc->hif_location = HIF_LOCATION_UNKNOWN;
	if (!IN6_IS_ADDR_LINKLOCAL(rtaddr)) {
		mip6log((LOG_NOTICE,
			 "%s: RA from a non-linklocal router (%s).\n",
			 __FUNCTION__,
			 ip6_sprintf(rtaddr)));
		return (0);
	}

	hsbypfx = hif_subnet_list_find_withprefix(&sc->hif_hs_list_home,
						  &ndpr->ndpr_prefix.sin6_addr,
						  ndpr->ndpr_plen);
	hsbyha =  hif_subnet_list_find_withhaaddr(&sc->hif_hs_list_home,
						  rtaddr);

	if (hsbypfx) {
		/* we are home. */
		sc->hif_location = HIF_LOCATION_HOME;
		mip6log((LOG_INFO, "%s: recv home prefix.  we are home.\n",
			 __FUNCTION__));
	} else if ((hsbypfx == NULL) && hsbyha) {
		/* we are home. */
		sc->hif_location = HIF_LOCATION_HOME;
		mip6log((LOG_INFO, "%s: recv ndpr by home ha.  we are home.\n",
			 __FUNCTION__));
	} else {
		/* we are foreign. */
		sc->hif_location = HIF_LOCATION_FOREIGN;
		mip6log((LOG_INFO, "%s: we are foreign.\n",
			 __FUNCTION__));
	}

	/* update mip6_prefix_list. */
	bzero(&tmpmpfx, sizeof(tmpmpfx));
	tmpmpfx.mpfx_prefix = ndpr->ndpr_prefix.sin6_addr;
	tmpmpfx.mpfx_prefixlen = ndpr->ndpr_plen;
	mpfx_is_new = 0;
	mpfx = mip6_prefix_list_find(&tmpmpfx);
	if (mpfx) {
		/* found an existing entry.  just update it. */
		mpfx->mpfx_lifetime = ndpr->ndpr_vltime;
		mpfx->mpfx_remain = mpfx->mpfx_lifetime;
		/* XXX mpfx->mpfx_haddr; */
	} else {
		/* this is a new prefix. */
		mpfx_is_new = 1;
		mpfx = mip6_prefix_create(&ndpr->ndpr_prefix.sin6_addr,
					  ndpr->ndpr_plen,
					  ndpr->ndpr_vltime);
		if (mpfx == NULL) {
			mip6log((LOG_ERR,
				"%s: mip6_prefix memory allocation failed.\n",
				__FUNCTION__));
			return (ENOMEM);
		}
		error = mip6_prefix_list_insert(&mip6_prefix_list,
						mpfx);
		if (error) {
			return (error);
		}
	}

	/* update mip6_ha_list. */
	mha_is_new = 0;
	mha = mip6_ha_list_find_withaddr(&mip6_ha_list, rtaddr);
	if (mha) {
		/* an entry exists.  update information. */
		if (ndpr->ndpr_raf_router) {
			mha->mha_gaddr = ndpr->ndpr_prefix.sin6_addr;
		}
		mha->mha_flags = dr->flags;
	} else {
		/* this is a new ha. */
		mha_is_new = 1;
		
		mha = mip6_ha_create(rtaddr, 
				     ndpr->ndpr_raf_router ?
				     &ndpr->ndpr_prefix.sin6_addr : NULL,
				     dr->flags, 0, dr->rtlifetime);
		if (mha == NULL) {
			mip6log((LOG_ERR,
				 "%s: mip6_ha memory allcation failed.\n",
				 __FUNCTION__));
			return (ENOMEM);
		}
		error = mip6_ha_list_insert(&mip6_ha_list, mha);
		if (error) {
			return (error);
		}
		
	}

	/* create mip6_subnet_prefix if mpfx is newly created. */
	if (mpfx_is_new) {
		mspfx = mip6_subnet_prefix_create(mpfx);
		if (mspfx == NULL) {
			mip6log((LOG_ERR,
				 "%s: mip6_subnet_prefix memory allocation "
				 "failed.\n",
				 __FUNCTION__));
			return (ENOMEM);
		}
	}

	/* create mip6_subnet_ha if mha is newly created. */
	if (mha_is_new) {
		msha = mip6_subnet_ha_create(mha);
		if (msha == NULL) {
			mip6log((LOG_ERR,
				 "%s: mip6_subnet_ha memory allocation "
				 "failed.\n",
				 __FUNCTION__));
			return (ENOMEM);
		}
	}

	/*
	 * there is an mip6_subnet which has a mha advertising this
	 * ndpr.  we add newly created mip6_prefix (mip6_subnet_prefix)
	 * to that mip6_subnet.
	 */
	if (mpfx_is_new && (mha_is_new == 0)) {
		ms = mip6_subnet_list_find_withhaaddr(&mip6_subnet_list,
						      rtaddr);
		if (ms == NULL) {
			/* must not happen. */
			mip6log((LOG_ERR,
				 "%s: mha_is_new == 0, "
				 "mip6_subnet should be exist!\n",
				 __FUNCTION__));
			return (EINVAL);
		}
		error = mip6_subnet_prefix_list_insert(&ms->ms_mspfx_list,
						       mspfx);
		if (error) {
			return (error);
		}
	}

	/*
	 * there is an mip6_subnet which has a mpfx advertised by this
	 * ndpr.  we add newly created mip6_ha (mip6_subnet_ha) to that
	 * mip6_subnet.
	 */
	if ((mpfx_is_new == 0) && mha_is_new) {
		ms = mip6_subnet_list_find_withprefix(&mip6_subnet_list,
						      &ndpr->ndpr_prefix.sin6_addr,
						      ndpr->ndpr_plen);
		if (ms == NULL) {
			/* must not happen. */
			mip6log((LOG_ERR,
				 "%s: mpfx_is_new == 0, "
				 "mip6_subnet should be exist!\n",
				 __FUNCTION__));
			return (EINVAL);
		}
		error = mip6_subnet_ha_list_insert(&ms->ms_msha_list,
						   msha);
		if (error) {
			return (error);
		}
	}

	/*
	 * we have no mip6_subnet which has a prefix or ha advertised
	 * by this ndpr.  so, we create a new mip6_subnet.
	 */
	if (mpfx_is_new && mha_is_new) {
		ms = mip6_subnet_create();
		if (ms == NULL) {
			mip6log((LOG_ERR,
				 "%s: mip6_subnet memory allcation failed.\n",
				 __FUNCTION__));
			return (ENOMEM);
		}
		error = mip6_subnet_list_insert(&mip6_subnet_list, ms);
		if (error) {
			return (error);
		}

		error = mip6_subnet_prefix_list_insert(&ms->ms_mspfx_list,
						       mspfx);
		if (error) {
			return (error);
		}

		error = mip6_subnet_ha_list_insert(&ms->ms_msha_list,
						   msha);
		if (error) {
			return (error);
		}

		/* add this newly created mip6_subnet to hif_subnet_list. */
		hs = hif_subnet_create(ms);
		if (hs == NULL) {
			mip6log((LOG_ERR,
				 "%s: hif_subnet memory allocation failed.\n",
				 __FUNCTION__));
			return (ENOMEM);
		}
		if (sc->hif_location == HIF_LOCATION_HOME) {
			error = hif_subnet_list_insert(&sc->hif_hs_list_home,
						       hs);
			if (error) {
				return (error);
			}
		} else {
			error = hif_subnet_list_insert(&sc->hif_hs_list_foreign,
						       hs);
			if (error) {
				return (error);
			}
		}
	}

	/* determine current hif_subnet. */
	sc->hif_hs_current
		= hif_subnet_list_find_withprefix(&sc->hif_hs_list_home,
						  &ndpr->ndpr_prefix.sin6_addr,
						  ndpr->ndpr_plen);
	if (sc->hif_hs_current == NULL) {
		sc->hif_hs_current = 
			hif_subnet_list_find_withprefix(&sc->hif_hs_list_foreign,
							&ndpr->ndpr_prefix.sin6_addr,
							ndpr->ndpr_plen);
	}

	return (0);
}

/*
 * move home addresses.
 *
 * U/F -> H
 *   remove all addr(possibly coa) from current active ifp
 *   remove all haddr(for hifX) from hifX
 *   add all haddr(for hifX) to active ifp
 *
 * H -> H
 *   nothing to do
 *
 * F -> F
 *   nothing to do
 *
 * U/H -> F
 *   remove all haddr(for hifX) from ifp
 *   add haddr(for hifX) to hifX
 *
 * U/H/F -> U
 *   ?
 *
 */
static int
mip6_haddr_config(sc, ifp)
	struct hif_softc *sc;
	struct ifnet *ifp;
{
	switch(sc->hif_location) {
	case HIF_LOCATION_HOME:
		switch(sc->hif_location_prev) {
		case HIF_LOCATION_UNKNOWN:
		case HIF_LOCATION_FOREIGN:
			/* UNKNOWN/FOREIGN -> HOME */

			/* XXX remove old (foreign subnet's) coa */
			mip6_remove_addrs(ifp);

			/*
			 * remove all home addresses attached to hif.
			 * all physical addresses are assigned in a
			 * address autoconfiguration manner.
			 */
			mip6_detach_haddrs(sc, ifp);
			break;
		}
		break;
	case HIF_LOCATION_FOREIGN:
		switch(sc->hif_location_prev) {
		case HIF_LOCATION_FOREIGN:
			/* FOREIGN -> FOREIGN */
			/* XXX */
			break;
		case HIF_LOCATION_UNKNOWN:
		case HIF_LOCATION_HOME:
			/* UNKNOWN/HOME -> FOREIGN */
			/*
			 * attach all home addresses to the hif interface.
			 */
			mip6_attach_haddrs(sc, ifp);
			break;
		}
		break;
	case HIF_LOCATION_UNKNOWN:
		mip6log((LOG_ERR, "UNKNOWN location??\n"));
		/* XXX what should we do? */
		break;
	}

	return (0);
}

static int
mip6_process_movement(sc, coa_changed)
	struct hif_softc *sc;
	int coa_changed;
{
	/* configure coa and do home (un)regstration if needed */
	switch(sc->hif_location_prev) {
	case HIF_LOCATION_UNKNOWN:
		switch (sc->hif_location) {
		case HIF_LOCATION_FOREIGN:
			/* UNKNOWN -> FOREIGN */
			if (coa_changed) {
				/* XXX if COA changed, register coa
				   to HA and old subnets AR */
				mip6_home_registration(sc);
			}
			break;
		case HIF_LOCATION_HOME:
		case HIF_LOCATION_UNKNOWN:
			/* UNKNOWN -> UNKNOWN/HOME */
			break;
		}
		break;
	case HIF_LOCATION_FOREIGN:
		switch (sc->hif_location) {
		case HIF_LOCATION_FOREIGN:
			/* FOREIGN -> FOREIGN */
			if (coa_changed) {
				/* XXX if COA changed, register coa
				   to HA and old subnets AR */
				mip6_home_registration(sc);
			}
			break;
		case HIF_LOCATION_HOME:
			/* FOREIGN -> HOME */
			/* unregister home address */
			mip6_home_registration(sc);
			break;
		case HIF_LOCATION_UNKNOWN:
			/* FOREIGN -> UNKNOWN */
			break;
		}
		break;
	case HIF_LOCATION_HOME:
		switch (sc->hif_location) {
		case HIF_LOCATION_FOREIGN:
			/* HOME -> FOREIGN */
			if (coa_changed) {
				/* 
				 * if coa changed, register coa to HA.
				 */
				mip6_home_registration(sc);
			}
			break;
		case HIF_LOCATION_HOME:
		case HIF_LOCATION_UNKNOWN:
			/* HOME -> HOME/UNKNOWN */
			break;
		}
		break;
	}

	return (0);
}

/*
 * select coa.
 *
 * returns
 *   -1 when something wrong happens
 *    0 when coa has't changed
 *    1 when coa has changed
 */
/*
 * XXX hif_coa is a bad design.  re-consider soon!
 */
static int
mip6_select_coa(preferedifp)
	struct ifnet *preferedifp;
{
	struct hif_coa *hcoa;
	struct in6_ifaddr *ia6;
	int ret = 0;

	if (preferedifp == NULL) {
		ret = -1;
		goto select_coa_end;
	}

	mip6log((LOG_INFO,
		 "%s: prefered ifp is %s(%p)\n",
		 __FUNCTION__,
		 if_name(preferedifp), preferedifp));
	
	hcoa = hif_coa_list_find_withifp(&hif_coa_list, preferedifp);
	if (hcoa == NULL) {
		hcoa = hif_coa_create(preferedifp);
		if (hcoa == NULL) {
			ret = -1;
			goto select_coa_end;
		}
		if (hif_coa_list_insert(&hif_coa_list, hcoa)) {
			ret = -1;
			goto select_coa_end;
		}
	}
	mip6log((LOG_INFO,
		 "%s: hifcoa = %p, hifcoa->ifp = %s(%p)\n",
		 __FUNCTION__, hcoa, if_name(hcoa->hcoa_ifp), hcoa->hcoa_ifp));

	/*
	 * XXX TODO
	 * get another coa if prefered ifp didn't have a good one to use.
	 */
	ia6 = hif_coa_get_ifaddr(hcoa);
	if (ia6 == NULL) {
		ret = -1;
		goto select_coa_end;
	}
	mip6log((LOG_INFO,
		 "%s: new CoA is %s\n",
		 __FUNCTION__, ip6_sprintf(&ia6->ia_addr.sin6_addr)));

	if (!IN6_ARE_ADDR_EQUAL(&hif_coa, &ia6->ia_addr.sin6_addr)) {
		hif_coa = ia6->ia_addr.sin6_addr;
		ret = 1;
	}

 select_coa_end:
	return (ret);
}

static int
mip6_remove_addrs(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ia, *ia_next;
	struct in6_ifaddr *ia6;

	/* delete all addrs currently assigned to ifp */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ia = ifp->if_addrlist;
	     ia;
	     ia = ia_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	for (ia = TAILQ_FIRST(&ifp->if_addrhead);
	     ia;
	     ia = ia_next)
#else
	for (ia = ifp->if_addrlist.tqh_first;
	     ia;
	     ia = ia_next)
#endif
	{
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		ia_next = ia->ifa_next;
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		ia_next = TAILQ_NEXT(ia, ifa_link);
#else
		ia_next = ia->ifa_list.tqe_next;
#endif

		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		ia6 = (struct in6_ifaddr *)ia;

		if (IN6_IS_ADDR_LINKLOCAL(&ia6->ia_addr.sin6_addr))
			continue;
		if (IN6_IS_ADDR_LOOPBACK(&ia6->ia_addr.sin6_addr))
			continue;

		if (mip6_remove_addr(ifp, ia6) != 0) {
			mip6log((LOG_ERR, "address deletion (%s) failed\n",
			    ip6_sprintf(&ia6->ia_addr.sin6_addr)));
			continue;
		}
	}

	return (0);
}

/*
 * 1. remove all haddr assinged to ifp.
 * 2. add all haddr for sc to scifp.
 */
static int
mip6_attach_haddrs(sc, ifp)
	struct hif_softc *sc;
	struct ifnet *ifp;
{
	int error = 0;

	/* remove all home addresses for sc from phisical I/F. */
	error = mip6_remove_haddrs(sc, ifp);
	if (error) {
		mip6log((LOG_ERR,
			 "%s: remove haddrs from %s failed.\n",
			 __FUNCTION__, if_name(ifp)));
		return (error);
	}

	/* add home addresses for sc to hif(itself) */
	error = mip6_add_haddrs(sc, (struct ifnet *)sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s: add haddrs to %s failed.\n",
			 __FUNCTION__, if_name((struct ifnet*)sc)));
		return (error);
	}

	return (0);
}

/*
 * remove all haddr for sc from ifp.
 */
static int
mip6_remove_haddrs(sc, ifp)
	struct hif_softc *sc;
	struct ifnet *ifp;
{
	struct ifaddr *ia, *ia_next;
	struct in6_ifaddr *ia6;
	struct hif_subnet *hs;
	struct mip6_subnet *ms;
	struct mip6_subnet_prefix *mspfx;
	struct mip6_prefix *mpfx;
	int error = 0;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ia = ifp->if_addrlist;
	     ia;
	     ia = ia_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	for (ia = TAILQ_FIRST(&ifp->if_addrhead);
	     ia;
	     ia = ia_next)
#else
	for (ia = ifp->if_addrlist.tqh_first;
	     ia;
	     ia = ia_next)
#endif
	{
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		ia_next = ia->ifa_next;
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		ia_next = TAILQ_NEXT(ia, ifa_link);
#else
		ia_next = ia->ifa_list.tqe_next;
#endif

		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		ia6 = (struct in6_ifaddr *)ia;

		for (hs = TAILQ_FIRST(&sc->hif_hs_list_home); hs;
		     hs = TAILQ_NEXT(hs, hs_entry)) {
			if ((ms = hs->hs_ms) == NULL) {
				return (EINVAL);
			}
			for (mspfx = TAILQ_FIRST(&ms->ms_mspfx_list); mspfx;
			     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
				if ((mpfx = mspfx->mspfx_mpfx) == NULL) {
					return (EINVAL);
				}
				if (!in6_are_prefix_equal(&ia6->ia_addr.sin6_addr,
							  &mpfx->mpfx_prefix,
							  mpfx->mpfx_prefixlen)) {
					continue;
				}
				error = mip6_remove_addr(ifp, ia6);
				if (error) {
					mip6log((LOG_ERR, "deletion %s from %s failed\n",
						 if_name(ifp),
						 ip6_sprintf(&ia6->ia_addr.sin6_addr)));
					continue;
				}
			}
		}
	}

	return (error);
}

/*
 * 1. remove all haddr for sc from scifp.
 * 2. add all haddr to ifp.
 */
static int
mip6_detach_haddrs(sc, ifp)
	struct hif_softc *sc;
	struct ifnet *ifp;
{
	struct ifnet *hif_ifp = (struct ifnet *)sc;
	struct ifaddr *ia, *ia_next;
	struct in6_ifaddr *ia6;
	int error = 0;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ia = hif_ifp->if_addrlist;
	     ia;
	     ia = ia_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	for (ia = TAILQ_FIRST(&hif_ifp->if_addrhead);
	     ia;
	     ia = ia_next)
#else
	for (ia = hif_ifp->if_addrlist.tqh_first;
	     ia;
	     ia = ia_next)
#endif
	{
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		ia_next = ia->ifa_next;
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		ia_next = TAILQ_NEXT(ia, ifa_link);
#else
		ia_next = ia->ifa_list.tqe_next;
#endif

		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		ia6 = (struct in6_ifaddr *)ia;

		error = mip6_remove_addr(hif_ifp, ia6);
		if (error) {
			mip6log((LOG_ERR,
				 "%s: address deletion failed (%s)\n",
				 __FUNCTION__,
				 ip6_sprintf(&ia6->ia_addr.sin6_addr)));
			return (error);
		}
	}

	error = mip6_add_haddrs(sc, ifp);

	return (error);
}

/*
 * add all haddrs for sc to ifp.
 */
static int
mip6_add_haddrs(sc, ifp)
	struct hif_softc *sc;
	struct ifnet *ifp;
{
	struct hif_subnet *hs;
	struct mip6_subnet *ms;
	struct mip6_subnet_prefix *mspfx;
	struct mip6_prefix *mpfx;
	struct in6_aliasreq ifra;
	int error = 0;

	if ((sc == NULL) || (ifp == NULL)) {
		return (EINVAL);
	}

	for (hs = TAILQ_FIRST(&sc->hif_hs_list_home); hs;
	     hs = TAILQ_NEXT(hs, hs_entry)) {
		if ((ms = hs->hs_ms) == NULL) {
			return (EINVAL);
		}
		for (mspfx = TAILQ_FIRST(&ms->ms_mspfx_list); mspfx;
		     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
			if ((mpfx = mspfx->mspfx_mpfx) == NULL) {
				return (EINVAL);
			}

			/*
			 * assign home address to mip6_prefix if not
			 * assigned yet.
			 */
			if (IN6_IS_ADDR_UNSPECIFIED(&mpfx->mpfx_haddr)) {
				error = mip6_prefix_haddr_assign(mpfx, sc);
				if (error) {
					mip6log((LOG_ERR,
						 "%s: can't assign home address for prefix %s.\n",
						 __FUNCTION__,
						 ip6_sprintf(&mpfx->mpfx_prefix)));
					return (error);
				}
			}

			/* skip a prefix that has 0 lifetime. */
			if (mpfx->mpfx_lifetime == 0)
				continue;

			/* construct in6_aliasreq. */
			bzero(&ifra, sizeof(ifra));
			bcopy(if_name(ifp), ifra.ifra_name,
			      sizeof(ifra.ifra_name));
			ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
			ifra.ifra_addr.sin6_family = AF_INET6;
			ifra.ifra_addr.sin6_addr = mpfx->mpfx_haddr;
			ifra.ifra_prefixmask.sin6_len
				= sizeof(struct sockaddr_in6);
			ifra.ifra_prefixmask.sin6_family = AF_INET6;
			ifra.ifra_flags = IN6_IFF_HOME;
			if (ifp->if_type == IFT_HIF) {
				in6_prefixlen2mask(&ifra.ifra_prefixmask.sin6_addr,
						   128);
			} else {
				in6_prefixlen2mask(&ifra.ifra_prefixmask.sin6_addr,
						   mpfx->mpfx_prefixlen);
			}
			ifra.ifra_lifetime.ia6t_vltime
				= mpfx->mpfx_lifetime; /* XXX */
			ifra.ifra_lifetime.ia6t_pltime
				= mpfx->mpfx_lifetime; /* XXX */
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
			if (in6_control(NULL, SIOCAIFADDR_IN6, (caddr_t)&ifra,
					ifp, curproc))
#else
			if (in6_control(NULL, SIOCAIFADDR_IN6, (caddr_t)&ifra, ifp))
#endif
			{
				mip6log((LOG_ERR,
					 "add address failed (%s)\n",
					 ip6_sprintf(&ifra.ifra_addr.sin6_addr)));
				return (error);
			}
		}
	}

	return (0);
}

/*
 * remove addr specified by ia6 from ifp.
 */
static int
mip6_remove_addr(ifp, ia6)
	struct ifnet *ifp;
	struct in6_ifaddr *ia6;
{
	struct in6_aliasreq ifra;
	int error = 0;

	bcopy(if_name(ifp), ifra.ifra_name, sizeof(ifra.ifra_name));
	bcopy(&ia6->ia_addr, &ifra.ifra_addr, sizeof(struct sockaddr_in6));
	bcopy(&ia6->ia_prefixmask, &ifra.ifra_prefixmask,
	      sizeof(struct sockaddr_in6));

#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
	if (in6_control(NULL, SIOCDIFADDR_IN6, (caddr_t)&ifra, ifp, curproc))
#else
	if (in6_control(NULL, SIOCDIFADDR_IN6, (caddr_t)&ifra, ifp))
#endif
	{
		mip6log((LOG_ERR, "in6_control delete addr failed (%s)\n",
		    ip6_sprintf(&ifra.ifra_addr.sin6_addr)));
		error = -1;
	}

	return (error);
}

int
mip6_ioctl(cmd, data)
	u_long cmd;
	caddr_t data;
{
	struct mip6_req *mr = (struct mip6_req *)data;

	switch (cmd) {
	case SIOCENABLEMN:
		mip6log((LOG_INFO, "MN function enabled\n"));
		mip6_config.mcfg_type = MIP6_CONFIG_TYPE_MN;
		break;

	case SIOCENABLEHA:
		mip6log((LOG_INFO, "HA function enabled\n"));
		mip6_config.mcfg_type = MIP6_CONFIG_TYPE_HA;
		break;

	case SIOCGBC:
		{
			struct mip6_bc *mbc;
			struct mip6_rbc *mrbc = mr->mip6r_ru.mip6r_rbc;
			int i;

			i = 0;
			for (mbc = LIST_FIRST(&mip6_bc_list); mbc;
			     mbc = LIST_NEXT(mbc, mbc_entry)) {
				mrbc->phaddr.sin6_addr = mbc->mbc_phaddr;
				mrbc->pcoa.sin6_addr = mbc->mbc_pcoa;
				mrbc->addr.sin6_addr = mbc->mbc_addr;
				mrbc->flags = mbc->mbc_flags;
				mrbc->prefixlen = mbc->mbc_prefixlen;
				mrbc->seqno = mbc->mbc_seqno;
				mrbc->lifetime = mbc->mbc_lifetime;
				mrbc->remain = mbc->mbc_remain;
				mrbc->state = mbc->mbc_state;
				i++;
				if (i > mr->mip6r_count)
					break;
				mrbc++;
			}
			mr->mip6r_count = i;
		}
		break;
	}

	return (0);
}

/*
 ******************************************************************************
 * Function:    mip6_create_ip6hdr
 * Description: Create and fill in data for an IPv6 header to be used by
 *              packets originating from MIPv6.  In addition to this memory
 *              is reserved for payload, if necessary.
 * Ret value:   NULL if a IPv6 header could not be created.
 *              Otherwise, pointer to a mbuf including the IPv6 header.
 ******************************************************************************
 */
struct mbuf *
mip6_create_ip6hdr(ip6_src, ip6_dst, next, plen)
	struct in6_addr *ip6_src; /* Source address for packet */
	struct in6_addr *ip6_dst; /* Destination address for packet */
	u_int8_t next;            /* Next header following the IPv6 header */
	u_int32_t plen;           /* Payload length (zero if no payload */
{
	struct ip6_hdr *ip6; /* IPv6 header */
	struct mbuf *mo;     /* Ptr to mbuf allocated for output data */
	u_int32_t maxlen;

	/* Allocate memory for the IPv6 header and fill it with data */
	ip6 = (struct ip6_hdr *)malloc(sizeof(struct ip6_hdr),
				       M_TEMP, M_NOWAIT);
	if (ip6 == NULL) return NULL;
	bzero(ip6, sizeof(struct ip6_hdr));

	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = 0;
	ip6->ip6_nxt = next;
	ip6->ip6_hlim = IPV6_DEFHLIM;

	ip6->ip6_src = *ip6_src;
	ip6->ip6_dst = *ip6_dst;

	/* Allocate memory for mbuf and copy IPv6 header to mbuf. */
	maxlen = sizeof(struct ip6_hdr) + plen;
	MGETHDR(mo, M_DONTWAIT, MT_DATA);
	if (mo && (maxlen >= MHLEN)) {
		MCLGET(mo, M_DONTWAIT);
		if ((mo->m_flags & M_EXT) == 0) {
			m_free(mo);
			mo = NULL;
		}
	}
	if (mo == NULL) {
		free(ip6, M_TEMP);
		return NULL;
	}

	mo->m_len = maxlen;
	mo->m_pkthdr.len = mo->m_len;
	mo->m_pkthdr.rcvif = NULL;
	bcopy((caddr_t)ip6, mtod(mo, caddr_t), sizeof(*ip6));
	free(ip6, M_TEMP);
	return mo;
}

int
mip6_exthdr_create(m, opt, pktopt_rthdr, pktopt_haddr, pktopt_binding)
	struct mbuf *m;                   /* ip datagram */
	struct ip6_pktopts *opt;          /* pktopt passed to ip6_output */
	struct ip6_rthdr **pktopt_rthdr;  /* rthdr to be returned */
	struct ip6_dest **pktopt_haddr;   /* hoa destopt to be returned */
	struct ip6_dest **pktopt_binding; /* destination opt to be returned */
{
	struct ip6_hdr *ip6;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	struct mip6_bc *mbc;
	int error = 0;

	*pktopt_rthdr = NULL;
	*pktopt_haddr = NULL;
	*pktopt_binding = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
	src = &ip6->ip6_src; /* if this node is MN, src = HoA */
	dst = &ip6->ip6_dst; /* final destination */

	/*
	 * create a rthdr if an BC entry for the destination address exists.
	 */
	if ((opt == NULL) || (opt->ip6po_rthdr == NULL)) {
		/* 
		 * only when no rthdr is specified from the upper
		 * layer, we add a rthdr for route optimization when
		 * needed.  if a rthdr from the upper layer already
		 * exists, we use it (not route optimized).
		 */
		error = mip6_rthdr_create_withdst(pktopt_rthdr, dst);
		if (error) {
			mip6log((LOG_ERR,
				 "%s: rthdr creation failed.\n",
				 __FUNCTION__));
			goto bad;
		}
	}

	/*
	 * insert BA/BR if pending BA/BR exist.
	 */
	/* XXX */
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
	if (mbc) {
		/*
		 * there is a binding cache for the src host.  check
		 * its status and insert BR/BA if needed.
		 */
		
	}

	/* following stuff is applied only for MN. */
	if (!MIP6_IS_MN)
		return (0);

	/*
	 * find hif that has a home address that is the same
	 * to the source address of this sending ip packet
	 */
	sc = hif_list_find_withhaddr(src);
	if (sc == NULL) {
		/*
		 * this source addrss is not one of our home addresses.
		 * we don't need any special care about this packet.
		 */
		return (0);
	}

	/* check registration status */
	mbu = mip6_bu_list_find_withhaddr(&sc->hif_bu_list, src);
	if (mbu == NULL) {
		/* no registration action started yet. */
		return (0);
	}
	if (mbu->mbu_reg_state == MIP6_BU_REG_STATE_NOTREG) {
		/*
		 * we have not registered yet.  this means we are still
		 * home.
		 */
		return (0);
	}

	/* create haddr destopt. */
	error = mip6_haddr_destopt_create(pktopt_haddr, src, dst, sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s: homeaddress insertion failed.\n",
			 __FUNCTION__));
		
		goto bad;
	}

	/* create bu destopt. */
	error = mip6_bu_destopt_create(pktopt_binding, src, dst, opt, sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s: BU destopt insertion failed.\n",
			 __FUNCTION__));
		goto bad;
	}

	return (0);
 bad:
	m_freem(m);
	return (error);
}

int
mip6_rthdr_create(pktopt_rthdr, coa)
	struct ip6_rthdr **pktopt_rthdr;
	struct in6_addr *coa;
{
	struct ip6_rthdr0 *rthdr0;
	size_t len;

	len = sizeof(struct ip6_rthdr0) + sizeof(struct in6_addr);
	rthdr0 = malloc(len, M_TEMP, M_NOWAIT);
	if (rthdr0 == NULL) {
		return (ENOMEM);
	}
	bzero(rthdr0, len);

	/* rthdr0->ip6r0_nxt = will be filled later in ip6_output */
	rthdr0->ip6r0_len = 2;
	rthdr0->ip6r0_type = 0;
	rthdr0->ip6r0_segleft = 1;
	rthdr0->ip6r0_reserved = 0;
	bcopy(coa, (caddr_t)rthdr0 + sizeof(struct ip6_rthdr0),
	      sizeof(struct in6_addr));
	*pktopt_rthdr = (struct ip6_rthdr *)rthdr0;

	return (0);
}

static int
mip6_rthdr_create_withdst(pktopt_rthdr, dst)
	struct ip6_rthdr **pktopt_rthdr;
	struct in6_addr *dst;
{
	struct mip6_bc *mbc;

	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
	if (mbc == NULL) {
		/* no BC entry found. */
		return (0);
	}

	if (mip6_rthdr_create(pktopt_rthdr, &mbc->mbc_pcoa)) {
		return (-1);
	}

	return (0);
}

static int
mip6_bu_destopt_create(pktopt_mip6dest2, src, dst, opts, sc)
	struct ip6_dest **pktopt_mip6dest2;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct ip6_pktopts *opts;
	struct hif_softc *sc;
{
	struct ip6_opt_binding_update bu_opt;
	struct mip6_buffer *optbuf;
	struct mip6_bu *mbu;
	int size;

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst);
	if (mbu == NULL) {
		/* no pending BU entries */
#if 0
		/* XXX we should create BU and send when initiating
		 * connections */
		mbu = mip6_bu_create(dst, src);
		if (mbu) {
			mbu->mbu_coa = sc->hif_coa;

		}
#endif
		return (0);
	}
	if (mbu->mbu_dontsend) {
		/*
		 * mbu_dontsend is set when we receive ICMP6_PARAM_PROB
		 * against the BU sent before.
		 * this means the peer doesn't support MIP6 (at least
		 * BU destopt).  we should not send BU to such a peer.
		 */
		return (0);
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr)) {
		/*
		 * the peer addr is unspecified.  this happens when
		 * home registration occurs but no home agent address
		 * is known.
		 */
		mip6log((LOG_INFO,
			 "%s: the peer addr is unspecified.\n",
			 __FUNCTION__));
		mip6_icmp6_ha_discov_req_output(sc);
		return (0);
	}
	if (!(mbu->mbu_state & MIP6_BU_STATE_WAITSENT)) {
		/* no need to send */
		return (0);
	}

	size = sizeof(struct mip6_buffer);
	optbuf = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
	if (optbuf == NULL) {
		return (-1);
	}
	bzero(optbuf, size);
	optbuf->off = 2;

	bzero(&bu_opt, sizeof(struct ip6_opt_binding_update));
	bu_opt.ip6ou_type = IP6OPT_BINDING_UPDATE;
	bu_opt.ip6ou_len = IP6OPT_BULEN;
	bu_opt.ip6ou_flags = mbu->mbu_flags;
	if (IN6_ARE_ADDR_EQUAL(&mbu->mbu_haddr, &mbu->mbu_coa)) {
		/* this BU is for home un-registration */
		bzero(bu_opt.ip6ou_lifetime, sizeof(bu_opt.ip6ou_lifetime));
	} else {
		struct mip6_prefix *mpfx;
		u_int32_t haddr_lifetime, coa_lifetime, lifetime;

		mpfx = mip6_prefix_list_find_withhaddr(&mip6_prefix_list,
						       src);
		haddr_lifetime = mpfx->mpfx_lifetime;
		coa_lifetime = mip6_coa_get_lifetime(&mbu->mbu_coa);
		lifetime = haddr_lifetime < coa_lifetime ?
			haddr_lifetime : coa_lifetime;
		bcopy((caddr_t)&lifetime, (caddr_t)bu_opt.ip6ou_lifetime,
		      sizeof(lifetime));
		mbu->mbu_lifetime = lifetime;
		mbu->mbu_remain = lifetime;
	}
	/* set the prefix length of this binding update. */
	if (mbu->mbu_flags & IP6_BUF_HOME) {
		/* register all ifid as a home address. */
		IP6_BU_SETPREFIXLEN(&bu_opt, 64);
	} else {
		/* when registering to a CN, the prefixlen must be 0. */ 
		IP6_BU_SETPREFIXLEN(&bu_opt, 0);
	}
	bu_opt.ip6ou_seqno = mbu->mbu_seqno;
	if ((mbu->mbu_flags & IP6_BUF_ACK) == 0) {
		/*
		 * increase the sequence number of this BU entry.  the
		 * seqno of a BU with ack flag will be incremented
		 * when BA received.
		 */
		mbu->mbu_seqno++;
	}

	if (opts && opts->ip6po_dest2) {
		/* Destination header 2 already exists.  merge them. */
		size = (opts->ip6po_dest2->ip6d_len + 1) << 3;
		bcopy((caddr_t)opts->ip6po_dest2, (caddr_t)optbuf->buf, size);
		optbuf->off = size;
		mip6_find_offset(optbuf);
	}

	/* add BU option (and other user specified optiosn if any) */
	mip6_add_opt2dh((u_int8_t *)&bu_opt, optbuf);
	mip6_align_destopt(optbuf);

	*pktopt_mip6dest2 = (struct ip6_dest *)optbuf->buf;

	return (0);
}

static int
mip6_haddr_destopt_create(pktopt_haddr, src, dst, sc)
	struct ip6_dest **pktopt_haddr;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct hif_softc *sc;
{
	struct ip6_opt_home_address haddr_opt;
	struct mip6_buffer *optbuf;
	int size;
	struct mip6_bu *mbu;
	struct in6_addr *coa;

	if (*pktopt_haddr) {
		/* already allocated ? */
		return (0);
	}
	
	size = sizeof(struct mip6_buffer);
	optbuf = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
	if (optbuf == NULL)
		return (ENOMEM);
	bzero((caddr_t)optbuf, size);

	bzero(&haddr_opt, sizeof(struct ip6_opt_home_address));
	haddr_opt.ip6oh_type = IP6OPT_HOME_ADDRESS;
	haddr_opt.ip6oh_len = IP6OPT_HALEN;

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst);
	if (mbu)
		coa = &mbu->mbu_coa;
	else
		coa = &hif_coa;
	size = sizeof(struct in6_addr);
	bcopy((caddr_t)coa, haddr_opt.ip6oh_addr, size);

	/* Add Home Address option  */
	mip6_add_opt2dh((u_int8_t *)&haddr_opt, optbuf);
	mip6_align_destopt(optbuf);

	*pktopt_haddr = (struct ip6_dest *)optbuf->buf;

	return (0);
}

int
mip6_destopt_discard(pktopt_rthdr, pktopt_haddr, pktopt_mip6dest2)
	struct ip6_rthdr *pktopt_rthdr;
	struct ip6_dest *pktopt_haddr;
	struct ip6_dest *pktopt_mip6dest2;
{
	if (pktopt_rthdr)
		free(pktopt_rthdr, M_TEMP);

	if (pktopt_haddr)
		free(pktopt_haddr, M_TEMP);

	if (pktopt_mip6dest2)
		free(pktopt_mip6dest2, M_TEMP);

	return (0);
}

int
mip6_ba_destopt_create(pktopt_badest2, status, seqno, lifetime, refresh)
	struct ip6_dest **pktopt_badest2;
	u_int8_t status;
	u_int8_t seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
{
	struct ip6_opt_binding_ack ba_opt;
	struct mip6_buffer *optbuf;
	size_t size;

	size = sizeof(struct mip6_buffer);
	optbuf = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
	if (optbuf == NULL) {
		return (-1);
	}
	bzero(optbuf, size);
	optbuf->off = 3;

	bzero(&ba_opt, sizeof(struct ip6_opt_binding_ack));
	ba_opt.ip6oa_type = IP6OPT_BINDING_ACK;
	ba_opt.ip6oa_len = IP6OPT_BALEN; /* XXX consider authdata */
	ba_opt.ip6oa_status = status;
	ba_opt.ip6oa_seqno = seqno;
	bcopy((caddr_t)&lifetime, (caddr_t)ba_opt.ip6oa_lifetime,
	      sizeof(lifetime));
	bcopy((caddr_t)&refresh, (caddr_t)ba_opt.ip6oa_refresh,
	      sizeof(refresh));

	/* add BU option (and other user specified optiosn if any) */
	mip6_add_opt2dh((u_int8_t *)&ba_opt, optbuf);
	mip6_align_destopt(optbuf);

	*pktopt_badest2 = (struct ip6_dest *)optbuf->buf;

	return (0);
	
}


/*
 ******************************************************************************
 * Function:    mip6_find_offset
 * Description: If the Destination header contains data it may already have
 *              an 8 octet alignment.  The last alignment bytes in the header
 *              might be possible to remove and instead use it for options.
 *              This function adjusts the buffer offset, if possible.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_find_offset(buf)
	struct mip6_buffer *buf;  /* Destination header with options */
{
	int       ii;
	u_int8_t  new_off;

	/* Verify input */
	if ((buf == NULL) || (buf->off < 2)) return;

	/* Check the buffer for unnecessary padding */
	new_off = 2;
	for (ii = 2; ii < buf->off;) {
		if (*(buf->buf + ii) == IP6OPT_PAD1) {
			new_off = ii;
			ii += 1;
		} else if (*(buf->buf + ii) == IP6OPT_PADN) {
			new_off = ii;
			ii += *(buf->buf + ii + 1) + 2;
		} else {
			ii += *(buf->buf + ii + 1) + 2;
			new_off = ii;
		}
	}
	buf->off = new_off;
}

/*
 ******************************************************************************
 * Function:    mip6_align_destopt
 * Description: Align a destination header to a multiple of 8 octets.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_align_destopt(buf)
	struct mip6_buffer *buf;     /* IPv6 destination header to align */
{
	struct ip6_ext  *ext_hdr;
	int              rest;     /* Rest of modulo division */
	u_int8_t         padlen;   /* Number of bytes to pad */
	u_int8_t         padn;     /* Number for option type PADN */

	padn = IP6OPT_PADN;
	rest = buf->off % 8;

	if (rest == 7) {
		/* Add a PAD1 option */
		bzero((caddr_t)buf->buf + buf->off, 1);
		buf->off += 1;
	} else if (rest > 0 && rest < 7) {
		/* Add a PADN option */
		padlen = 8 - rest;
		bzero((caddr_t)buf->buf + buf->off, padlen);
		bcopy(&padn, (caddr_t)buf->buf + buf->off, 1);
		padlen = padlen - 2;
		bcopy(&padlen, (caddr_t)buf->buf + buf->off + 1, 1);
		buf->off += padlen + 2;
	}

	/* Adjust the extension header length */
	ext_hdr = (struct ip6_ext *)buf->buf;
	ext_hdr->ip6e_len = (buf->off >> 3) - 1;
	return;
}

/*
 ******************************************************************************
 * Function:    mip6_add_opt2dh
 * Description: Add Binding Update, Binding Acknowledgement, Binding Request
 *              or Home Address option to a Destination Header.  The option
 *              must be aligned when added.
 * Ret value:   Ptr where the MIPv6 option is located in the Destination header
 *              or NULL.
 ******************************************************************************
 */
caddr_t
mip6_add_opt2dh(opt, dh)
	caddr_t opt;            /* BU, BR, BA or Home Address option */
	struct mip6_buffer *dh; /* Buffer containing the IPv6 DH  */
{
	struct ip6_opt_binding_update  *bu;
	struct ip6_opt_binding_ack     *ba;
	struct ip6_opt_binding_request *br;
	struct ip6_opt_home_address    *ha;
	caddr_t                         pos;
	u_int8_t                        type, len, padn, off;
	u_int32_t                       t;
	int                             rest;

	/* Verify input */
	pos = NULL;
	if (opt == NULL || dh == NULL) return pos;
	if (dh->off < 2) {
		bzero((caddr_t)dh->buf, 2);
		dh->off = 2;
	}

	/* Add option to Destination header */
	padn = IP6OPT_PADN;
	type = *(u_int8_t*)opt;
	switch (type) {
		case IP6OPT_BINDING_UPDATE:
			/* BU alignment requirement (4n + 2) */
			rest = dh->off % 4;
			if (rest == 0) {
				/* Add a PADN option with length 0 */
				bzero((caddr_t)dh->buf + dh->off, 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				dh->off += 2;
			} else if (rest == 1) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
			} else if (rest == 3) {
				/* Add a PADN option with length 1 */
				len = 1;
				bzero((caddr_t)dh->buf + dh->off, 3);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += 3;
			}

			/* Copy option to DH */
			len = IP6OPT_BULEN + IP6OPT_MINLEN;
			off = dh->off;
			bu = (struct ip6_opt_binding_update *)opt;

			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)bu, (caddr_t)dh->buf + off, len);

			bu = (struct ip6_opt_binding_update *)(dh->buf + off);
#ifdef DIAGNOSTIC
			if (sizeof(t) != sizeof(bu->ip6ou_lifetime))
				panic("bcopy problem");
#endif
			t = htonl(*(u_int32_t *)bu->ip6ou_lifetime);
			bcopy((caddr_t)&t, bu->ip6ou_lifetime, sizeof(t));
			
			pos = dh->buf + off;
			dh->off += len;
			break;
		case IP6OPT_BINDING_ACK:
			/* BA alignment requirement (4n + 3) */
			rest = dh->off % 4;
			if (rest == 1) {
				/* Add a PADN option with length 0 */
				bzero((caddr_t)dh->buf + dh->off, 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				dh->off += 2;
			} else if (rest == 2) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
			} else if (rest == 0) {
				/* Add a PADN option with length 1 */
				len = 1;
				bzero((caddr_t)dh->buf + dh->off, 3);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += 3;
			}

			/* Copy option to DH */
			len = IP6OPT_BALEN + IP6OPT_MINLEN;
			off = dh->off;
			ba = (struct ip6_opt_binding_ack *)opt;

			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)ba, (caddr_t)dh->buf + off, len);

			ba = (struct ip6_opt_binding_ack *)(dh->buf + off);
#ifdef DIAGNOSTIC
			if (sizeof(t) != sizeof(ba->ip6oa_lifetime))
				panic("bcopy problem");
#endif
			t = htonl(*(u_int32_t *)ba->ip6oa_lifetime);
			bcopy((caddr_t)&t, ba->ip6oa_lifetime,sizeof(t));
#ifdef DIAGNOSTIC
			if (sizeof(t) != sizeof(ba->ip6oa_refresh))
				panic("bcopy problem");
#endif
			t = htonl(*(u_int32_t *)ba->ip6oa_refresh);
			bcopy((caddr_t)&t, ba->ip6oa_refresh, sizeof(t));
			
			pos = dh->buf + off;
			dh->off += len;
			break;
		case IP6OPT_BINDING_REQ:
			/* Copy option to DH */
			len = IP6OPT_BRLEN + IP6OPT_MINLEN;
			off = dh->off;
			br = (struct ip6_opt_binding_request *)opt;

			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)br, (caddr_t)dh->buf + off, len);
			
			pos = dh->buf + off;
			dh->off += len;
			break;
		case IP6OPT_HOME_ADDRESS:
			/* HA alignment requirement (8n + 6) */
			rest = dh->off % 8;
			if (rest <= 4) {
				/* Add a PADN option with length X */
				len = 6 - rest - 2;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += len + 2;
			} else if (rest == 5) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
			} else if (rest == 7) {
				/* Add a PADN option with length 5 */
				len = 5;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += len + 2;
			}

			/* Copy option to DH */
			len = IP6OPT_HALEN + IP6OPT_MINLEN;
			off = dh->off;
			ha = (struct ip6_opt_home_address *)opt;
			
			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)ha, (caddr_t)dh->buf + off, len);
			
			pos = dh->buf + off;
			dh->off += len;
			break;
	}
	return pos;
}

/*
 ******************************************************************************
 * Function:    mip6_addr_exchange
 * Description: Exchange IPv6 header source address with contents in Home
 *              Address option address field.
 * Ret value:   Void
 ******************************************************************************
 */
int
mip6_addr_exchange(m, dstm)
	struct mbuf *m;    /* includes IPv6 header */
	struct mbuf *dstm; /* includes homeaddress destopt */
{
	struct ip6_opt_home_address *ha_opt;
	struct ip6_dest *dh;
	struct ip6_hdr *ip6;
	struct in6_addr ip6_src;
	u_int8_t *opt;
	int ii, len;

	/* sanity check */
	if (!MIP6_IS_MN) {
		return (0);
	}

	if (dstm == NULL) {
		/* home address destopt not exists. */
		return (0);
	}
	
	/* Find Home Address option */
	dh = mtod(dstm, struct ip6_dest *);
	len = (dh->ip6d_len + 1) << 3;
	if (len > dstm->m_len) {
		mip6log((LOG_ERR,
			 "%s: haddr destopt illegal mbuf length.\n",
			 __FUNCTION__));
		return (EINVAL);
	}

	ha_opt = NULL;
	ii = 2;
	
	opt = (u_int8_t *)dh + ii;
	while (ii < len) {
		switch (*opt) {
			case IP6OPT_PAD1:
				ii += 1;
				opt += 1;
				break;
			case IP6OPT_HOME_ADDRESS:
				ha_opt = (struct ip6_opt_home_address *)opt;
				break;
			default:
				ii += *(opt + 1) + 2;
				opt += *(opt + 1) + 2;
				break;
		}
		if (ha_opt) break;
	}

	if (ha_opt == NULL) {
		mip6log((LOG_INFO,
			 "%s: haddr dest opt not found.\n",
			 __FUNCTION__));
		return (0);
	}

	/* Change the IP6 source address to the care-of address */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6_src = ip6->ip6_src;

	ip6->ip6_src = *(struct in6_addr *)ha_opt->ip6oh_addr;
	bcopy((caddr_t)&ip6_src, ha_opt->ip6oh_addr, sizeof(struct in6_addr));
	return (0);
}

int
mip6_process_destopt(m, dstopts, opt, dstoptlen)
	struct mbuf *m;
	struct ip6_dest *dstopts;
	u_int8_t *opt;
	int dstoptlen;
{
	int error = 0;

	switch(*opt) {
	case IP6OPT_BINDING_UPDATE:
		if ((opt - (u_int8_t *)dstopts) % 4 != 2) {
			ip6stat.ip6s_badoptions++;
			goto bad;
		}

		error = mip6_validate_bu(m, opt);
		if (error == -1) {
			mip6log((LOG_ERR,
				 "%s: invalid BU received.\n",
				 __FUNCTION__));
			goto bad;
		}
		if (error == 1) {
			/* invalid BU.  we ignore this silently */
			mip6log((LOG_NOTICE,
				 "%s: invalid BU received.  ignore this.\n",
				 __FUNCTION__));
			return (0);
		}

		if (mip6_process_bu(m, opt) != 0) {
			mip6log((LOG_ERR,
				 "%s: processing BU failed\n",
				 __FUNCTION__));
			goto bad;
		}
		break;

	case IP6OPT_BINDING_ACK:
		if (!MIP6_IS_MN)
			return (0);

		if ((opt - (u_int8_t *)dstopts) % 4 != 3) {
			ip6stat.ip6s_badoptions++;
			goto bad;
		}

		error = mip6_validate_ba(m, opt);
		if (error == -1) {
			mip6log((LOG_ERR,
				 "%s: invalid BA received.\n",
				 __FUNCTION__));
			goto bad;
		}
		if (error == 1) {
			/* invalid BA.  we ignore this silently */
			mip6log((LOG_NOTICE,
				 "%s: invalid BA received.  ignore this.\n",
				 __FUNCTION__));
			return (0);
		}

		if (mip6_process_ba(m, opt) != 0) {
			mip6log((LOG_ERR,
				 "%s: processing BA failed\n",
				 __FUNCTION__));
			goto bad;
		}
		break;

	case IP6OPT_BINDING_REQ:
		if (!MIP6_IS_MN)
			return (0);
		
		if (mip6_validate_br(m, opt)) {
			mip6log((LOG_ERR,
				 "%s: invalid BR received\n",
				 __FUNCTION__));
			goto bad;
		}

		if (mip6_process_br(m, opt) != 0) {
			mip6log((LOG_ERR,
				 "%s: processing BR failed\n",
				 __FUNCTION__));
			goto bad;
		}
		break;
	}

	return (0);
 bad:
	m_freem(m);
	return (IPPROTO_DONE);
}

u_int8_t *
mip6_destopt_find_subopt(subopt, suboptlen, subopttype)
	u_int8_t *subopt;    /* Ptr to first sub-option in current option */
	u_int8_t suboptlen;  /* Remaining option length */
	u_int8_t subopttype;
{
	u_int8_t *match = NULL;

	/* Search all sub-options for current option */
	while (suboptlen > 0) {
		if (*subopt == IP6OPT_PAD1) {
			suboptlen -= 1;
			subopt += 1;
		} else if (*subopt == subopttype) {
			match = subopt;
			break;
		} else {
			suboptlen -= *(subopt + 1) + 2;
			subopt += *(subopt + 1) + 2;
		}
		if (match)
			break;
	}

	return (match);
}


int64_t
mip6_coa_get_lifetime(coa)
	struct in6_addr *coa;
{
	struct in6_ifaddr *ia;
	int64_t lifetime;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (IN6_ARE_ADDR_EQUAL(coa, &ia->ia_addr.sin6_addr))
			break;
	}

	if (ia != NULL) {
		lifetime = ia->ia6_lifetime.ia6t_preferred - time_second;
	} else {
		lifetime = 0;
	}

	return (lifetime);
}

void
mip6_create_addr(addr, ifid, prefix, prefixlen)
	struct in6_addr *addr;
	struct in6_addr *ifid;
	struct in6_addr *prefix;
	u_int8_t prefixlen;
{
	int i, bytelen, bitlen;
	u_int8_t mask;

	bytelen = prefixlen / 8;
	bitlen = prefixlen % 8;
	for (i = 0; i < bytelen; i++)
		addr->s6_addr8[i] = prefix->s6_addr8[i];
	if (bitlen) {
		mask = 0;
		for (i = 0; i < bitlen; i++)
			mask |= (0x80 >> i);
		addr->s6_addr8[bytelen]
			= (prefix->s6_addr8[bytelen] & mask)
			| (ifid->s6_addr8[bytelen] & ~mask);

		for (i = bytelen + 1; i < 16; i++)
			addr->s6_addr8[i]
				= ifid->s6_addr8[i];
	} else {
		for (i = bytelen; i < 16; i++)
			addr->s6_addr8[i]
				= ifid->s6_addr8[i];
	}
}
