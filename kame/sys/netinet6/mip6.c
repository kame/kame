/*	$KAME: mip6.c,v 1.95 2001/12/21 00:47:39 keiichi Exp $	*/

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

static int mip6_prefix_list_update_sub __P((struct hif_softc *,
					    struct in6_addr *,
					    struct nd_prefix *,
					    struct nd_defrouter *));
static int mip6_haddr_config __P((struct hif_softc *));
static int mip6_attach_haddrs __P((struct hif_softc *));
static int mip6_detach_haddrs __P((struct hif_softc *));
static int mip6_add_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_remove_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_remove_addr __P((struct ifnet *, struct in6_ifaddr *));

/* ipv6 header manipuration functions */
static int mip6_rthdr_create __P((struct ip6_rthdr **,
				  struct in6_addr *,
				  struct ip6_pktopts *));
static int mip6_rthdr_create_withdst __P((struct ip6_rthdr **,
					  struct in6_addr *,
					  struct ip6_pktopts *));
static int mip6_haddr_destopt_create __P((struct ip6_dest **,
					  struct in6_addr *,
					  struct hif_softc *));
static int mip6_bu_destopt_create __P((struct ip6_dest **,
				       struct in6_addr *,
				       struct in6_addr *,
				       struct ip6_pktopts *,
				       struct hif_softc *));
static int mip6_babr_destopt_create __P((struct ip6_dest **,
					 struct in6_addr *,
					 struct ip6_pktopts *));
static void mip6_find_offset __P((struct mip6_buffer *));
static void mip6_align_destopt __P((struct mip6_buffer *));
static caddr_t mip6_add_opt2dh __P((caddr_t, struct mip6_buffer *));
#ifndef MIP6_DRAFT13
static int mip6_add_subopt2dh __P((u_int8_t *, struct mip6_buffer *));
#endif

void
mip6_init()
{
	mip6_config.mcfg_type = 0;
#ifdef MIP6_DEBUG
	mip6_config.mcfg_debug = 1;
#else /* MIP6_DEBUG */
	mip6_config.mcfg_debug = 0;
#endif /* MIP6_DEBUG */

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
 * we heard a router advertisement.
 * from the advertised prefix, we can find our current location.
 */
int
mip6_prefix_list_update(saddr, ndpr, dr, m)
	struct in6_addr *saddr;
	struct nd_prefix *ndpr;
	struct nd_defrouter *dr;
	struct mbuf *m;
{
	struct hif_softc *sc;
	int error = 0;

	if (dr == NULL) {
		struct mip6_ha *mha;
		/* advertizing router is shutting down. */
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, saddr);
		if (mha) {
			error = mip6_ha_list_remove(&mip6_ha_list, mha);
		}
		return (error);
	}

	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		/*
		 * determine the current location from the advertised
		 * prefix and router information.
		 */
		error = mip6_prefix_list_update_sub(sc, saddr, ndpr, dr);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: error while determining location.\n",
				 __FILE__, __LINE__));
			return (error);
		}

#if 0
		/*
		 * configure home addresses according to the home
		 * prefixes and the current location determined above.
		 */
		error = mip6_haddr_config(sc, ndpr->ndpr_ifp);
		if (error) {
			mip6log((LOG_ERR,
				"%s:%d: home address configuration error.\n",
				 __FILE__, __LINE__));
			return (error);
		}
#endif
	}

	return (0);
}

/*
 * check the recieved prefix information and associate it with the
 * existing prefix/homeagent list.
 *
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
mip6_prefix_list_update_sub(sc, rtaddr, ndpr, dr)
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
	struct in6_addr lladdr;
	int mpfx_is_new, mha_is_new;
	int location;
	int error = 0;

	location = HIF_LOCATION_UNKNOWN;
	if (!IN6_IS_ADDR_LINKLOCAL(rtaddr)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: RA from a non-linklocal router (%s).\n",
			 __FILE__, __LINE__, ip6_sprintf(rtaddr)));
		return (0);
	}
	lladdr = *rtaddr;
	/* XXX: KAME link-local hack; remove ifindex */
	lladdr.s6_addr16[1] = 0;

	mip6log((LOG_INFO,
		 "%s:%d: prefix %s from %s\n",
		 __FILE__, __LINE__,
		 ip6_sprintf(&ndpr->ndpr_prefix.sin6_addr),
		 ip6_sprintf(&lladdr)));

	hsbypfx = hif_subnet_list_find_withprefix(&sc->hif_hs_list_home,
						  &ndpr->ndpr_prefix.sin6_addr,
						  ndpr->ndpr_plen);
	hsbyha =  hif_subnet_list_find_withhaaddr(&sc->hif_hs_list_home,
						  &lladdr);

	if (hsbypfx) {
		/* we are home. */
		location = HIF_LOCATION_HOME;
	} else if ((hsbypfx == NULL) && hsbyha) {
		/* we are home. */
		location = HIF_LOCATION_HOME;
	} else {
		/* we are foreign. */
		location = HIF_LOCATION_FOREIGN;
	}

	/* update mip6_prefix_list. */
	bzero(&tmpmpfx, sizeof(tmpmpfx));
	tmpmpfx.mpfx_prefix = ndpr->ndpr_prefix.sin6_addr;
	tmpmpfx.mpfx_prefixlen = ndpr->ndpr_plen;
	mpfx_is_new = 0;
	mpfx = mip6_prefix_list_find(&tmpmpfx);
	if (mpfx) {
		/* found an existing entry.  just update it. */
		mpfx->mpfx_vltime = ndpr->ndpr_vltime;
		mpfx->mpfx_vlremain = mpfx->mpfx_vltime;
		mpfx->mpfx_pltime = ndpr->ndpr_pltime;
		mpfx->mpfx_plremain = mpfx->mpfx_pltime;
		/* XXX mpfx->mpfx_haddr; */
	} else {
		/* this is a new prefix. */
		mpfx_is_new = 1;
		mpfx = mip6_prefix_create(&ndpr->ndpr_prefix.sin6_addr,
					  ndpr->ndpr_plen,
					  ndpr->ndpr_vltime,
					  ndpr->ndpr_pltime);
		if (mpfx == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d: "
				 "mip6_prefix memory allocation failed.\n",
				 __FILE__, __LINE__));
			return (ENOMEM);
		}
		error = mip6_prefix_list_insert(&mip6_prefix_list,
						mpfx);
		if (error) {
			return (error);
		}
		mip6log((LOG_INFO,
			 "%s:%d: receive a new prefix %s\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ndpr->ndpr_prefix.sin6_addr)));
	}

	/* update mip6_ha_list. */
	mha_is_new = 0;
	mha = mip6_ha_list_find_withaddr(&mip6_ha_list, &lladdr);
	if (mha) {
		/* an entry exists.  update information. */
		if (ndpr->ndpr_raf_router) {
			mha->mha_gaddr = ndpr->ndpr_prefix.sin6_addr;
		}
		mha->mha_flags = dr->flags;
	} else {
		/* this is a new ha. */
		mha_is_new = 1;
		
		mha = mip6_ha_create(&lladdr, 
				     ndpr->ndpr_raf_router ?
				     &ndpr->ndpr_prefix.sin6_addr : NULL,
				     dr->flags, 0, dr->rtlifetime);
		if (mha == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d mip6_ha memory allcation failed.\n",
				 __FILE__, __LINE__));
			return (ENOMEM);
		}
		error = mip6_ha_list_insert(&mip6_ha_list, mha);
		if (error) {
			return (error);
		}
		mip6log((LOG_INFO,
			 "%s:%d: found a new router %s(%s)\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&lladdr),
			 ip6_sprintf(&ndpr->ndpr_prefix.sin6_addr)));
	}

	/* create mip6_subnet_prefix if mpfx is newly created. */
	if (mpfx_is_new) {
		mspfx = mip6_subnet_prefix_create(mpfx);
		if (mspfx == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d: mip6_subnet_prefix "
				 "memory allocation failed.\n",
				 __FILE__, __LINE__));
			return (ENOMEM);
		}
	}

	/* create mip6_subnet_ha if mha is newly created. */
	if (mha_is_new) {
		msha = mip6_subnet_ha_create(mha);
		if (msha == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d: mip6_subnet_ha "
				 "memory allocation failed.\n",
				 __FILE__, __LINE__));
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
						      &lladdr);
		if (ms == NULL) {
			/* must not happen. */
			mip6log((LOG_ERR,
				 "%s:%d: mha_is_new == 0, "
				 "mip6_subnet should be exist!\n",
				 __FILE__, __LINE__));
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
				 "%s:%d: mip6_determine_location_withndpr: "
				 "mpfx_is_new == 0, "
				 "mip6_subnet should be exist!\n",
				 __FILE__, __LINE__));
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
				 "%s:%d: mip6_determine_location_withndpr: "
				 "mip6_subnet memory allcation failed.\n",
				 __FILE__, __LINE__));
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
				 "%s:%d: mip6_determine_location_withndpr: "
				 "hif_subnet memory allocation failed.\n",
				 __FILE__, __LINE__));
			return (ENOMEM);
		}
		if (location == HIF_LOCATION_HOME) {
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

#if XXX
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
#endif /* XXX */

	return (0);
}

int
mip6_process_pfxlist_status_change(hif_coa)
	struct in6_addr *hif_coa; /* newly selected CoA. */
{
	struct nd_prefix *pr;
	struct hif_softc *sc;
	int error = 0;

	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		sc->hif_location = HIF_LOCATION_UNKNOWN;

		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			if (!in6_are_prefix_equal(hif_coa,
						  &pr->ndpr_prefix.sin6_addr,
						  pr->ndpr_plen))
				continue;

			if (hif_subnet_list_find_withprefix(
				    &sc->hif_hs_list_home,
				    &pr->ndpr_prefix.sin6_addr,
				    pr->ndpr_plen))
				sc->hif_location = HIF_LOCATION_HOME;
			else if (hif_subnet_list_find_withprefix(
				    &sc->hif_hs_list_foreign,
				    &pr->ndpr_prefix.sin6_addr,
				    pr->ndpr_plen))
				sc->hif_location = HIF_LOCATION_FOREIGN;
		}
		mip6log((LOG_INFO,
			 "location = %d\n", sc->hif_location));

		/*
		 * configure home addresses according to the home
		 * prefixes and the current location determined above.
		 */
		error = mip6_haddr_config(sc);
		if (error) {
			mip6log((LOG_ERR,
				"%s:%d: home address configuration error.\n",
				 __FILE__, __LINE__));
			return (error);
		}
	}

	return (0);
}

static int
mip6_haddr_config(sc)
	struct hif_softc *sc;
{
	int error = 0;

	switch (sc->hif_location) {
	case HIF_LOCATION_HOME:
		/*
		 * remove all home addresses attached to hif.
		 * all physical addresses are assigned in a
		 * address autoconfiguration manner.
		 */
		error = mip6_detach_haddrs(sc);
		
		break;

	case HIF_LOCATION_FOREIGN:
		/*
		 * attach all home addresses to the hif interface.
		 * before attach home addresses, remove home addresses
		 * from physical i/f to avoid the dupulication of
		 * address.
		 */
		error = mip6_attach_haddrs(sc);
		break;

	case HIF_LOCATION_UNKNOWN:
		break;
	}

	return (error);
}

/*
 * mip6_process_movement() is called when CoA has changed.  therefore,
 * we can call mip6_home_registration() in any case because we must
 * have moved from somewhere to somewhere.
 */
int
mip6_process_movement(void)
{
	struct hif_softc *sc;

	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		switch (sc->hif_location) {
		case HIF_LOCATION_HOME:
			/*
			 * we moved to home.  unregister our home
			 * address.
			 */
			mip6_home_registration(sc);
			break;

		case HIF_LOCATION_FOREIGN:
			/*
			 * we moved to foreign.  register the current
			 * CoA to our home agent.
			 */
			/* XXX: TODO register to the old subnet's AR. */
			mip6_home_registration(sc);
			break;

		case HIF_LOCATION_UNKNOWN:
			break;
		}
	}

	return (0);
}

/*
 * set all nd cache state of routers to ND6_LLINFO_PROBE.  this forces
 * the NUD for each router and make it quick to detach addresses those
 * are not usable.
 */
void
mip6_probe_routers(void)
{
	struct llinfo_nd6 *ln;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	ln = llinfo_nd6.ln_next;
	while (ln && ln != &llinfo_nd6) {
		if ((ln->ln_router) &&
		    ((ln->ln_state == ND6_LLINFO_REACHABLE) ||
		     (ln->ln_state == ND6_LLINFO_STALE))) {
			ln->ln_asked = 0;
			ln->ln_state = ND6_LLINFO_DELAY;
			ln->ln_expire = time_second;
		}
		ln = ln->ln_next;
	}
}
/*
 * select CoA.  preferedifp is usually the i/f which ndpr is heard.
 *
 * returns
 *   -1 when something wrong happens
 *    0 when coa hasn't changed
 *    1 when coa has changed
 */
/*
 * XXX hif_coa is a bad design.  re-consider soon!
 */
int
mip6_select_coa(preferedifp)
	struct ifnet *preferedifp;
{
	struct hif_coa *hcoa;
	struct in6_ifaddr *ia6;
	int ret = 0;

	if (preferedifp == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: preferedifp == NULL.\n",
			 __FILE__, __LINE__));
		ret = -1;
		goto select_coa_end;
	}
	
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

	/*
	 * XXX TODO
	 * get another coa if prefered ifp didn't have a good one to use.
	 */
	ia6 = hif_coa_get_ifaddr(hcoa);
	if (ia6 == NULL) {
		mip6log((LOG_NOTICE,
			 "%s:%d: no available CoA found.\n",
			 __FILE__, __LINE__));
		ret = 0;
		goto select_coa_end;
	}

	if (!IN6_ARE_ADDR_EQUAL(&hif_coa, &ia6->ia_addr.sin6_addr)) {
		hif_coa = ia6->ia_addr.sin6_addr;
		ret = 1;
		mip6log((LOG_INFO,
			 "%s:%d: CoA has changed to %s\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ia6->ia_addr.sin6_addr)));
	}

 select_coa_end:
	return (ret);
}

int
mip6_select_coa2(void)
{
	struct ifnet *ifp;
	struct ifaddr *ia, *ia_next;
	struct in6_ifaddr *ia6, *samecoa = NULL, *othercoa = NULL;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_list.tqe_next)
#endif
	{
		if (ifp->if_type == IFT_HIF)
			continue;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ia = ifp->if_addrlist; ia; ia = ia_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		for (ia = TAILQ_FIRST(&ifp->if_addrhead); ia; ia = ia_next)
#else
		for (ia = ifp->if_addrlist.tqh_first; ia; ia = ia_next)
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

			if (ia6->ia6_flags &
			    (IN6_IFF_ANYCAST
			     /* | IN6_IFF_TENTATIVE */
			     | IN6_IFF_DETACHED
			     | IN6_IFF_DUPLICATED
			     | IN6_IFF_DEPRECATED))
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&ia6->ia_addr.sin6_addr))
				continue;
			if (IN6_IS_ADDR_LOOPBACK(&ia6->ia_addr.sin6_addr))
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&ia6->ia_addr.sin6_addr))
				continue;

			/* keep CoA same as possible. */
			if (IN6_ARE_ADDR_EQUAL(&hif_coa,
					       &ia6->ia_addr.sin6_addr)) {
			    samecoa = ia6;
			    break;
			}

			/* next candidate. */
			othercoa = ia6;
		}
		if (samecoa)
			break;
	}
	if (samecoa) {
		/* CoA didn't change. */
		return (0);
	}

	if (othercoa == NULL) {
		mip6log((LOG_INFO,
			 "%s:%d: no available CoA found\n",
			 __FILE__, __LINE__));
		return (0);
	}

	hif_coa = othercoa->ia_addr.sin6_addr;
	mip6log((LOG_INFO,
		 "%s:%d: CoA has changed to %s\n",
		 __FILE__, __LINE__,
		 ip6_sprintf(&othercoa->ia_addr.sin6_addr)));
	return (1);
}

/*
 * 1. remove all haddr assinged to ifp.
 * 2. add all haddr for sc to scifp.
 */
static int
mip6_attach_haddrs(sc)
	struct hif_softc *sc;
{
	struct ifnet *ifp;
	int error = 0;

	/* remove all home addresses for sc from phisical I/F. */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_list.tqe_next)
#endif
	{
		if (ifp->if_type == IFT_HIF)
			continue;

		error = mip6_remove_haddrs(sc, ifp);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: remove haddrs from %s failed.\n",
				 __FILE__, __LINE__,
				 if_name(ifp)));
			return (error);
		}
	}

	/* add home addresses for sc to hif(itself) */
	error = mip6_add_haddrs(sc, (struct ifnet *)sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: add haddrs to %s failed.\n",
			 __FILE__, __LINE__,
			 if_name((struct ifnet*)sc)));
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
					mip6log((LOG_ERR, "%s:%d: deletion %s from %s failed\n",
						 __FILE__, __LINE__,
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
 * remove all haddr for sc (the home network) from scifp.
 */
static int
mip6_detach_haddrs(sc)
	struct hif_softc *sc;
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
		if (IN6_IS_ADDR_LINKLOCAL(&ia6->ia_addr.sin6_addr))
			continue;

		error = mip6_remove_addr(hif_ifp, ia6);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: address deletion failed (%s)\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&ia6->ia_addr.sin6_addr)));
			return (error);
		}
	}

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
	struct in6_ifaddr *ia6;
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
						 "%s:%d: can't assign home address for prefix %s.\n",
						 __FILE__, __LINE__,
						 ip6_sprintf(&mpfx->mpfx_prefix)));
					return (error);
				}
			}

			/* skip a prefix that has 0 lifetime. */
			if (mpfx->mpfx_vltime == 0)
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
			/*
			 * XXX: TODO mobile prefix sol/adv to update
			 * address lifetime.
			 */
#if 0
			ifra.ifra_lifetime.ia6t_vltime
				= mpfx->mpfx_lifetime; /* XXX */
			ifra.ifra_lifetime.ia6t_pltime
				= mpfx->mpfx_lifetime; /* XXX */
#else
			ifra.ifra_lifetime.ia6t_vltime
				= ND6_INFINITE_LIFETIME; /* XXX */
			ifra.ifra_lifetime.ia6t_pltime
				= ND6_INFINITE_LIFETIME; /* XXX */
#endif
			ia6 = in6ifa_ifpwithaddr(ifp, &ifra.ifra_addr.sin6_addr);
			error = in6_update_ifa(ifp, &ifra, ia6);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: add address (%s) failed. errno = %d\n",
					 __FILE__, __LINE__,
					 ip6_sprintf(&ifra.ifra_addr.sin6_addr),
					 error));
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

	/* address purging code is copyed from in6_control(). */
	{
		int i = 0, purgeprefix = 0;
		struct nd_prefix pr0, *pr = NULL;

		/*
		 * If the address being deleted is the only one that owns
		 * the corresponding prefix, expire the prefix as well.
		 * XXX: theoretically, we don't have to worry about such
		 * relationship, since we separate the address management
		 * and the prefix management.  We do this, however, to provide
		 * as much backward compatibility as possible in terms of
		 * the ioctl operation.
		 */
		bzero(&pr0, sizeof(pr0));
		pr0.ndpr_ifp = ifp;
		pr0.ndpr_plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr,
					     NULL);
		if (pr0.ndpr_plen == 128)
			goto purgeaddr;
		pr0.ndpr_prefix = ia6->ia_addr;
		pr0.ndpr_mask = ia6->ia_prefixmask.sin6_addr;
		for (i = 0; i < 4; i++) {
			pr0.ndpr_prefix.sin6_addr.s6_addr32[i] &=
				ia6->ia_prefixmask.sin6_addr.s6_addr32[i];
		}
		/*
		 * The logic of the following condition is a bit complicated.
		 * We expire the prefix when
		 * 1. the address obeys autoconfiguration and it is the
		 *    only owner of the associated prefix, or
		 * 2. the address does not obey autoconf and there is no
		 *    other owner of the prefix.
		 */
		if ((pr = nd6_prefix_lookup(&pr0)) != NULL &&
		    (((ia6->ia6_flags & IN6_IFF_AUTOCONF) != 0 &&
		      pr->ndpr_refcnt == 1) ||
		     ((ia6->ia6_flags & IN6_IFF_AUTOCONF) == 0 &&
		      pr->ndpr_refcnt == 0)))
			purgeprefix = 1;

	purgeaddr:
		in6_purgeaddr(&ia6->ia_ifa);
		if (pr && purgeprefix)
			prelist_remove(pr);
	}

	return (error);
}

int
mip6_ioctl(cmd, data)
	u_long cmd;
	caddr_t data;
{
	struct mip6_req *mr = (struct mip6_req *)data;
	int s;

#ifdef __NetBSD__
			s = splsoftnet();
#else
			s = splnet();
#endif

	switch (cmd) {
	case SIOCENABLEMN:
	{
		int on;
		struct hif_softc *sc;

		on = *(int *)data;
		if (on == 1) {
			mip6log((LOG_INFO,
				 "%s:%d: MN function enabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_type = MIP6_CONFIG_TYPE_MN;
		} else {
			mip6log((LOG_INFO,
				 "%s:%d: MN function disabled\n",
				 __FILE__, __LINE__));
			for (sc = TAILQ_FIRST(&hif_softc_list);
			     sc;
			     sc = TAILQ_NEXT(sc, hif_entry)) {
				mip6_detach_haddrs(sc);
				mip6_bu_list_remove_all(&sc->hif_bu_list);
			}
			hif_coa = in6addr_any;
			mip6_config.mcfg_type = 0;
		}
	}
		break;

	case SIOCENABLEHA:
		mip6log((LOG_INFO,
			 "%s:%d: HA function enabled\n",
			 __FILE__, __LINE__));
		mip6_config.mcfg_type = MIP6_CONFIG_TYPE_HA;
		break;

	case SIOCGBC:
		{
			struct mip6_bc *mbc, *rmbc;
			int i;

			rmbc = mr->mip6r_ru.mip6r_mbc;
			i = 0;
			for (mbc = LIST_FIRST(&mip6_bc_list);
			     mbc;
			     mbc = LIST_NEXT(mbc, mbc_entry)) {
				*rmbc = *mbc;
				i++;
				if (i > mr->mip6r_count)
					break;
				rmbc++;
			}
			mr->mip6r_count = i;
		}
		break;
	}

	splx(s);

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
	u_int32_t plen;           /* Payload length (zero if no payload) */
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
	ip6->ip6_hlim = ip6_defhlim;

	ip6->ip6_src = *ip6_src;
	ip6->ip6_dst = *ip6_dst;

	/* Allocate memory for mbuf and copy IPv6 header to mbuf. */
	maxlen = sizeof(*ip6) + plen;
	MGETHDR(mo, M_DONTWAIT, MT_HEADER);
	if (mo && (max_linkhdr + maxlen >= MHLEN)) {
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
	mo->m_pkthdr.rcvif = NULL;

	mo->m_len = maxlen;
	mo->m_pkthdr.len = mo->m_len;
	mo->m_data += max_linkhdr;

	bcopy((caddr_t)ip6, mtod(mo, caddr_t), sizeof(*ip6));
	free(ip6, M_TEMP);
	return mo;
}

int
mip6_exthdr_create(m, opt, mip6opt)
	struct mbuf *m;                   /* ip datagram */
	struct ip6_pktopts *opt;          /* pktopt passed to ip6_output */
	struct mip6_pktopts *mip6opt;
{
	struct ip6_hdr *ip6;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	int s, error = 0;

	mip6opt->mip6po_rthdr = NULL;
	mip6opt->mip6po_haddr = NULL;
	mip6opt->mip6po_dest2 = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
	src = &ip6->ip6_src; /* if this node is MN, src = HoA */
	dst = &ip6->ip6_dst; /* final destination */

	/*
	 * add the routing header for the route optimization if there
	 * exists a valid binding cache entry for this destination
	 * node.
	 */
#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	error = mip6_rthdr_create_withdst(&mip6opt->mip6po_rthdr, dst, opt);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: rthdr creation failed.\n",
			 __FILE__, __LINE__));
		splx(s);
		goto bad;
	}
	splx(s);

	if ((opt != NULL) &&
	    (opt->ip6po_rthdr != NULL) &&
	    (mip6opt->mip6po_rthdr != NULL)) {
		/*
		 * if the upper layer specify something special
		 * routing header by using ip6_pktopts, we replace it
		 * with the merged routing header that includes the
		 * original (the upper-layer specified) routing header
		 * and our routing header for the route optimization.
		 */
		free(opt->ip6po_rthdr, M_IP6OPT);
		if (opt->ip6po_route.ro_rt) {
			RTFREE(opt->ip6po_route.ro_rt);
			opt->ip6po_route.ro_rt = NULL;
		}
		opt->ip6po_rthdr = mip6opt->mip6po_rthdr;
		mip6opt->mip6po_rthdr = NULL;
	}

	/*
	 * insert BA/BR if pending BA/BR exist.
	 */
#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	error = mip6_babr_destopt_create(&mip6opt->mip6po_dest2, dst, opt);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: BA/BR destopt insertion failed.\n",
			 __FILE__, __LINE__));
		splx(s);
		goto bad;
	}

	/* following stuff is applied only for MN. */
	if (!MIP6_IS_MN) {
		splx(s);
		return (0);
	}

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
		splx(s);
		return (0);
	}

	/* check home registration status */
	mbu = mip6_bu_list_find_home_registration(&sc->hif_bu_list, src);
	if (mbu == NULL) {
		/* no home registration action started yet. */
		splx(s);
		return (0);
	}
	if (mbu->mbu_reg_state == MIP6_BU_REG_STATE_NOTREG) {
		/*
		 * we have not registered yet.  this means we are still
		 * home.
		 */
		splx(s);
		return (0);
	}

	/* create bu destopt. */
	error = mip6_bu_destopt_create(&mip6opt->mip6po_dest2,
				       src, dst, opt, sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: BU destopt insertion failed.\n",
			 __FILE__, __LINE__));
		splx(s);
		goto bad;
	}

	/* create haddr destopt. */
	error = mip6_haddr_destopt_create(&mip6opt->mip6po_haddr, dst, sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: homeaddress insertion failed.\n",
			 __FILE__, __LINE__));
		
		splx(s);
		goto bad;
	}

	splx(s);
	return (0);
 bad:
	return (error);
}

int
mip6_rthdr_create(pktopt_rthdr, coa, opt)
	struct ip6_rthdr **pktopt_rthdr;
	struct in6_addr *coa;
	struct ip6_pktopts *opt;
{
	struct ip6_rthdr0 *rthdr0, *orthdr0;
	int osegleft;
	struct in6_addr *ointhop = NULL, *inthop;
	size_t len;
	int i;

	/*
	 * recent discussion in the mobileip-wg concluded that the
	 * multiple rthdrs (one is specified by the caller of
	 * ip6_output, and the other is MIP6's) should be merged.  see
	 * the thread of discussion on the mopbile-ip mailing list
	 * started at 'Tue, 04 Sep 2001 12:51:34 -0700' with the
	 * subject 'Coexistence with other uses for routing header'.
	 *
	 * if we have a type0 routing header pktopt already, we should
	 * merge them.
	 */
	if ((opt != NULL) && (opt->ip6po_rthdr != NULL)) {
		orthdr0 = (struct ip6_rthdr0 *)opt->ip6po_rthdr;
		if (orthdr0->ip6r0_type == 0) {
			osegleft = orthdr0->ip6r0_segleft;
			ointhop = (struct in6_addr *)(orthdr0 + 1);
		} else {
			/* other type of the routing header. */
			return (0);
		}
	} else 
		osegleft = 0;

	len = sizeof(struct ip6_rthdr0)
		+ (sizeof(struct in6_addr) * (osegleft + 1));
	rthdr0 = malloc(len, M_IP6OPT, M_NOWAIT);
	if (rthdr0 == NULL) {
		return (ENOMEM);
	}
	bzero(rthdr0, len);

	/* rthdr0->ip6r0_nxt = will be filled later in ip6_output */
	rthdr0->ip6r0_len = (osegleft + 1) * 2;
	rthdr0->ip6r0_type = 0;
	rthdr0->ip6r0_segleft = osegleft + 1;
	rthdr0->ip6r0_reserved = 0;
	inthop = (struct in6_addr *)(rthdr0 + 1);
	for (i = 0; i < osegleft; ointhop++, inthop++) {
		bcopy((caddr_t)ointhop, (caddr_t)inthop,
		      sizeof(struct in6_addr));
		i++;
	}
	bcopy((caddr_t)coa, (caddr_t)inthop, sizeof(struct in6_addr));
	*pktopt_rthdr = (struct ip6_rthdr *)rthdr0;

	return (0);
}

static int
mip6_rthdr_create_withdst(pktopt_rthdr, dst, opt)
	struct ip6_rthdr **pktopt_rthdr;
	struct in6_addr *dst;
	struct ip6_pktopts *opt;
{
	struct mip6_bc *mbc;
	int error = 0;

	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
	if (mbc == NULL) {
		/* no BC entry found. */
		return (0);
	}

	error = mip6_rthdr_create(pktopt_rthdr, &mbc->mbc_pcoa, opt);
	if (error) {
		return (error);
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
	struct ip6_opt_binding_update bu_opt, *bu_opt_pos;
#ifndef MIP6_DRAFT13
	int suboptlen;
	struct mip6_subopt_authdata *authdata;
#endif
	struct mip6_buffer optbuf;
	struct mip6_bu *mbu;
	struct mip6_bu *hrmbu;
	int error = 0;

	/*
	 * do not send a binding update destination option to the
	 * multicast destination.
	 */
	if (IN6_IS_ADDR_MULTICAST(dst))
		return (0);

	/* find existing binding update entry for this destination. */
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst);
	hrmbu = mip6_bu_list_find_home_registration(&sc->hif_bu_list, src);
	if ((mbu == NULL) && (hrmbu != NULL) &&
	    (hrmbu->mbu_reg_state == MIP6_BU_REG_STATE_REG)) {
		struct mip6_prefix *mpfx;

		/*
		 * there is no binding update entry for this dst node.
		 * but we have a home registration entry and we are
		 * foreign now.  we should create a new binding update
		 * entry for the dst node.
		 */

		mpfx = mip6_prefix_list_find_withhaddr(&mip6_prefix_list, src);
		if (mpfx == NULL)
			return (0);

		/* create a binding update entry. */
		mbu = mip6_bu_create(dst, mpfx, &hrmbu->mbu_coa, 0, sc);
		if (mbu == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d: "
				 "a mbu entry creation failed.\n",
				 __FILE__, __LINE__));
			return (0);
		}
		mbu->mbu_state = MIP6_BU_STATE_WAITSENT;
		mip6_bu_list_insert(&sc->hif_bu_list, mbu);
	}
	if (mbu == NULL) {
		/*
		 * this is the case that the home registration is on
		 * going.  that is, (mbu == NULL) && (hrmbu != NULL)
		 * but hrmbu->reg_state != STATE_REG.
		 */
		return (0);
	}
	if (mbu->mbu_dontsend) {
		/*
		 * mbu_dontsend is set when we receive
		 * ICMP6_PARAM_PROB against the binding update sent
		 * before.  this means the peer doesn't support MIP6
		 * (at least the BU destopt).  we should not send any
		 * BU to such a peer.
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
			 "%s:%d: the peer addr is unspecified.\n",
			 __FILE__, __LINE__));
		mip6_icmp6_ha_discov_req_output(sc);
		return (0);
	}
	if (!(mbu->mbu_state & MIP6_BU_STATE_WAITSENT)) {
		/* no need to send */
		return (0);
	}

	/* update sequence number of this binding update entry. */
	mbu->mbu_seqno++;

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
		haddr_lifetime = mpfx->mpfx_pltime;
		coa_lifetime = mip6_coa_get_lifetime(&mbu->mbu_coa);
		lifetime = haddr_lifetime < coa_lifetime ?
			haddr_lifetime : coa_lifetime;
		bcopy((caddr_t)&lifetime, (caddr_t)bu_opt.ip6ou_lifetime,
		      sizeof(lifetime));
		mbu->mbu_lifetime = lifetime;
		mbu->mbu_remain = lifetime;
		mbu->mbu_refresh = mbu->mbu_lifetime;
		mbu->mbu_refremain = mbu->mbu_lifetime;
	}
#ifdef MIP6_DRAFT13
	/* set the prefix length of this binding update. */
	if (mbu->mbu_flags & IP6_BUF_HOME) {
		/* register all ifid as a home address. */
		bu_opt.ip6ou_prefixlen = 64;
	} else {
		/* when registering to a CN, the prefixlen must be 0. */ 
		bu_opt.ip6ou_prefixlen = 0;
	}
	bu_opt.ip6ou_seqno = htons(mbu->mbu_seqno);
#else
	bu_opt.ip6ou_seqno = mbu->mbu_seqno;
#endif /* MIP6_DRAFT13 */

	/* XXX MIP6_BUFFER_SIZE = IPV6_MIMMTU is OK?? */
	optbuf.buf = (u_int8_t *)malloc(MIP6_BUFFER_SIZE, M_IP6OPT, M_NOWAIT);
	if (optbuf.buf == NULL) {
		return (ENOMEM);
	}
	bzero(optbuf.buf, MIP6_BUFFER_SIZE);
	optbuf.off = 2;

	if (*pktopt_mip6dest2 == NULL) {
		if ((opts != NULL) && (opts->ip6po_dest2 != NULL)) {
			int dstoptlen;
			/*
			 * destination option 2 is specified and have
			 * not been merged yet.  merge them.
			 */
			dstoptlen = (opts->ip6po_dest2->ip6d_len + 1) << 3;
			bcopy((caddr_t)opts->ip6po_dest2, (caddr_t)optbuf.buf,
			      dstoptlen);
			optbuf.off = dstoptlen;
			mip6_find_offset(&optbuf);
		}
	} else {
		int dstoptlen;
		/*
		 * mip6dest2 is already set.  we must merge the
		 * existing destopts and the options we are going to
		 * add in the following code.
		 */
		dstoptlen = ((*pktopt_mip6dest2)->ip6d_len + 1) << 3;
		bcopy((caddr_t)(*pktopt_mip6dest2), (caddr_t)optbuf.buf,
		      dstoptlen);
		optbuf.off = dstoptlen;
		mip6_find_offset(&optbuf);
	}

	/*
	 * add a binding update destination option (and other user
	 * specified optiosns if any)
	 */
	bu_opt_pos = (struct ip6_opt_binding_update *)
		mip6_add_opt2dh((u_int8_t *)&bu_opt, &optbuf);
#ifndef MIP6_DRAFT13
	authdata = mip6_authdata_create(src, dst, &mbu->mbu_coa, bu_opt_pos);
	if (authdata == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: failed to create authdata sub-option.\n",
			 __FILE__, __LINE__));
		free(optbuf.buf, M_IP6OPT);
		return (EINVAL);
	}
	suboptlen = mip6_add_subopt2dh((u_int8_t *)authdata, &optbuf);
	bu_opt_pos->ip6ou_len += suboptlen;
	free(authdata, M_TEMP);
#endif /* !MIP6_DRAFT13 */
	
	mip6_align_destopt(&optbuf);

	if (*pktopt_mip6dest2 != NULL)
		free(*pktopt_mip6dest2, M_IP6OPT);
	*pktopt_mip6dest2 = (struct ip6_dest *)optbuf.buf;

	/* hoping that the binding update will be sent with no accident. */
	mbu->mbu_state &= ~MIP6_BU_STATE_WAITSENT;

	return (error);
}

static int
mip6_haddr_destopt_create(pktopt_haddr, dst, sc)
	struct ip6_dest **pktopt_haddr;
	struct in6_addr *dst;
	struct hif_softc *sc;
{
	struct ip6_opt_home_address haddr_opt;
	struct mip6_buffer optbuf;
	struct mip6_bu *mbu;
	struct in6_addr *coa;

	if (*pktopt_haddr) {
		/* already allocated ? */
		return (0);
	}
	
	bzero(&haddr_opt, sizeof(struct ip6_opt_home_address));
	haddr_opt.ip6oh_type = IP6OPT_HOME_ADDRESS;
	haddr_opt.ip6oh_len = IP6OPT_HALEN;

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst);
#ifdef MIP6_ALLOW_COA_FALLBACK
	if (mbu && mbu->mbu_coafallback) {
		return (0);
	}
#endif
	if (mbu)
		coa = &mbu->mbu_coa;
	else
		coa = &hif_coa;
	bcopy((caddr_t)coa, haddr_opt.ip6oh_addr, sizeof(*coa));

	optbuf.buf = (u_int8_t *)malloc(MIP6_BUFFER_SIZE, M_IP6OPT, M_NOWAIT);
	if (optbuf.buf == NULL) {
		return (ENOMEM);
	}
	bzero((caddr_t)optbuf.buf, MIP6_BUFFER_SIZE);
	optbuf.off = 2;

	/* Add Home Address option */
	mip6_add_opt2dh((u_int8_t *)&haddr_opt, &optbuf);
	mip6_align_destopt(&optbuf);

	*pktopt_haddr = (struct ip6_dest *)optbuf.buf;

	return (0);
}

int
mip6_babr_destopt_create(pktopt_mip6dest2, dst, opts)
	struct ip6_dest **pktopt_mip6dest2;
	struct in6_addr *dst;
	struct ip6_pktopts *opts;
{
	struct ip6_opt_binding_request br_opt;
	struct mip6_buffer optbuf;
	struct mip6_bc *mbc;
	int error = 0;

	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
	if (mbc == NULL) {
		/*
		 * there is no binding cache for the dst node.
		 * nothing to do.
		 */
		return (0);
	}
	if (((mbc->mbc_state & MIP6_BC_STATE_BR_WAITSENT) == 0) &&
	    ((mbc->mbc_state & MIP6_BC_STATE_BA_WAITSENT) == 0)) {
		/* check first to avoid needless bzero. */
		return (0);
	}

	/* XXX IPV6_MIMMTU is OK?? */
	optbuf.buf = (u_int8_t *)malloc(MIP6_BUFFER_SIZE, M_IP6OPT, M_NOWAIT);
	if (optbuf.buf == NULL) {
		return (ENOMEM);
	}
	bzero(optbuf.buf, MIP6_BUFFER_SIZE);
	optbuf.off = 0;

	if (*pktopt_mip6dest2 == NULL) {
		if ((opts != NULL) && (opts->ip6po_dest2 != NULL)) {
			int dstoptlen;
			/*
			 * destination option 2 is specified and have
			 * not been merged yet.  merge them.
			 */
			dstoptlen = (opts->ip6po_dest2->ip6d_len + 1) << 3;
			bcopy((caddr_t)opts->ip6po_dest2, (caddr_t)optbuf.buf,
			      dstoptlen);
			optbuf.off = dstoptlen;
			mip6_find_offset(&optbuf);
		}
	} else {
		int dstoptlen;
		/*
		 * mip6dest2 is already set.  we must merge the
		 * existing destopts and the options we are going to
		 * add in the following code.
		 */
		dstoptlen = ((*pktopt_mip6dest2)->ip6d_len + 1) << 3;
		bcopy((caddr_t)(*pktopt_mip6dest2), (caddr_t)optbuf.buf,
		      dstoptlen);
		optbuf.off = dstoptlen;
		mip6_find_offset(&optbuf);
	}

	if ((mbc->mbc_state & MIP6_BC_STATE_BR_WAITSENT) != 0) {
		/* add a binding request. */
		br_opt.ip6or_type = IP6OPT_BINDING_REQ;
		br_opt.ip6or_len = IP6OPT_BRLEN;
		mip6_add_opt2dh((u_int8_t *)&br_opt, &optbuf);
		/*
		 * hoping that the binding request will be sent with
		 * no accident.
		 */
		mbc->mbc_state &= ~MIP6_BC_STATE_BR_WAITSENT;
		/*
		 * TODO: XXX
		 * suboptions.
		 */
		/* alignment will be done at the end of this function. */
	}
	
	if ((mbc->mbc_state & MIP6_BC_STATE_BA_WAITSENT) != 0) {
		/* add a binding ack. */
		/* XXX TODO */
	}
	
	mip6_align_destopt(&optbuf);

	if (*pktopt_mip6dest2 != NULL)
		free(*pktopt_mip6dest2, M_IP6OPT);
	*pktopt_mip6dest2 = (struct ip6_dest *)optbuf.buf;

	return (error);
}

int
mip6_ba_destopt_create(pktopt_badest2, status, seqno, lifetime, refresh)
	struct ip6_dest **pktopt_badest2;
	u_int8_t status;
	MIP6_SEQNO_T seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
{
	struct ip6_opt_binding_ack ba_opt;
	struct mip6_buffer optbuf;

	optbuf.buf = (u_int8_t *)malloc(MIP6_BUFFER_SIZE, M_IP6OPT, M_NOWAIT);
	if (optbuf.buf == NULL) {
		return (ENOMEM);
	}
	bzero(optbuf.buf, MIP6_BUFFER_SIZE);
	optbuf.off = 3; /* insert leading PAD1 first for optimization. */

	bzero(&ba_opt, sizeof(struct ip6_opt_binding_ack));
	ba_opt.ip6oa_type = IP6OPT_BINDING_ACK;
	ba_opt.ip6oa_len = IP6OPT_BALEN; /* XXX consider authdata */
	ba_opt.ip6oa_status = status;
#ifdef MIP6_DRAFT13
	ba_opt.ip6oa_seqno = htons(seqno);
#else
	ba_opt.ip6oa_seqno = seqno;
#endif
	bcopy((caddr_t)&lifetime, (caddr_t)ba_opt.ip6oa_lifetime,
	      sizeof(lifetime));
	bcopy((caddr_t)&refresh, (caddr_t)ba_opt.ip6oa_refresh,
	      sizeof(refresh));

	/* add BU option (and other user specified optiosn if any) */
	mip6_add_opt2dh((u_int8_t *)&ba_opt, &optbuf);
	mip6_align_destopt(&optbuf);

	*pktopt_badest2 = (struct ip6_dest *)optbuf.buf;

	return (0);
	
}

void
mip6_destopt_discard(mip6opt)
	struct mip6_pktopts *mip6opt;
{
	if (mip6opt->mip6po_rthdr)
		free(mip6opt->mip6po_rthdr, M_IP6OPT);

	if (mip6opt->mip6po_haddr)
		free(mip6opt->mip6po_haddr, M_IP6OPT);

	if (mip6opt->mip6po_dest2)
		free(mip6opt->mip6po_dest2, M_IP6OPT);

	return;
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
	struct mip6_buffer *dh; /* Buffer containing the IPv6 DH */
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
	if (opt == NULL || dh == NULL)
		return pos;
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

			/* store lifetime in a network byte order. */
			bu = (struct ip6_opt_binding_update *)(dh->buf + off);
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

			/* store time values in a network byte order. */
			ba = (struct ip6_opt_binding_ack *)(dh->buf + off);
			t = htonl(*(u_int32_t *)ba->ip6oa_lifetime);
			bcopy((caddr_t)&t, ba->ip6oa_lifetime,sizeof(t));
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

#ifndef MIP6_DRAFT13
static int
mip6_add_subopt2dh(subopt, dh)
	u_int8_t *subopt; /* MIP6 sub-options */
	struct mip6_buffer *dh; /* Buffer containing the IPv6 DH */
{
	int suboptlen = 0;
	u_int8_t type, padn;
	u_int8_t len, off;
	int rest;

	/* verify input */
	if (subopt == NULL || dh == NULL)
		return (0);
	if (dh->off < 2) {
		/* Illegal input. */
		return (0);
	}

	/* Add sub-option to Destination option */
	padn = MIP6SUBOPT_PADN;
	type = *subopt;
	switch (type) {
		case MIP6SUBOPT_AUTHDATA:
			/*
			 * Authentication Data alignment requirement
			 * (8n + 6)
			 */
			rest = dh->off % 8;
			if (rest <= 4) {
				/* Add a PADN option with length X */
				len = 6 - rest - 2;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += len + 2;
				suboptlen += len + 2;
			} else if (rest == 5) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
				suboptlen += 1;
			} else if (rest == 7) {
				/* Add a PADN option with length 5 */
				len = 5;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += len + 2;
				suboptlen += len + 2;
			}

			/* Append sub-option to the destination option. */
			len = 2 + *(subopt + 1);
			off = dh->off;
			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)subopt, (caddr_t)dh->buf + off, len);

			suboptlen += len;

			/* adjust offset. */
			dh->off += len;
			break;
	}

	return (suboptlen);
}
#endif /* !MIP6_DRAFT13 */

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
	struct ip6_opt_home_address *haopt;
	struct ip6_dest *dstopt;
	struct ip6_hdr *ip6;
	struct in6_addr ip6_src;
	u_int8_t *opt;
	int ii, dstoptlen;

	/* sanity check */
	if (!MIP6_IS_MN) {
		return (0);
	}

	if (dstm == NULL) {
		/* home address destopt does not exist. */
		return (0);
	}
	
	/* Find Home Address option */
	dstopt = mtod(dstm, struct ip6_dest *);
	dstoptlen = (dstopt->ip6d_len + 1) << 3;
	if (dstoptlen > dstm->m_len) {
		mip6log((LOG_ERR,
			 "%s:%d: haddr destopt illegal mbuf length.\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}

	haopt = NULL;
	ii = 2;
	
	opt = (u_int8_t *)dstopt + ii;
	while (ii < dstoptlen) {
		switch (*opt) {
			case IP6OPT_PAD1:
				ii += 1;
				opt += 1;
				break;
			case IP6OPT_HOME_ADDRESS:
				haopt = (struct ip6_opt_home_address *)opt;
				break;
			default:
				ii += *(opt + 1) + 2;
				opt += *(opt + 1) + 2;
				break;
		}
		if (haopt) break;
	}

	if (haopt == NULL) {
		mip6log((LOG_INFO,
			 "%s:d: haddr dest opt not found.\n",
			 __FILE__, __LINE__));
		return (0);
	}

	/* Swap the IPv6 homeaddress and the care-of address. */
	ip6 = mtod(m, struct ip6_hdr *);
	bcopy(&ip6->ip6_src, &ip6_src, sizeof(ip6->ip6_src));
	bcopy(haopt->ip6oh_addr, &ip6->ip6_src, sizeof(haopt->ip6oh_addr));
	bcopy(&ip6_src, haopt->ip6oh_addr, sizeof(ip6_src));

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

	switch (*opt) {
	case IP6OPT_BINDING_UPDATE:
#if 0
		if ((opt - (u_int8_t *)dstopts) % 4 != 2) {
			ip6stat.ip6s_badoptions++;
			goto bad;
		}
#endif

		error = mip6_validate_bu(m, opt);
		if (error == -1) {
			mip6log((LOG_ERR,
				 "%s:%d: invalid BU received.\n",
				 __FILE__, __LINE__));
			goto bad;
		}
		if (error == 1) {
			/* invalid BU.  we ignore this silently */
			mip6log((LOG_NOTICE,
				 "%s:d: invalid BU received.  ignore this.\n",
				 __FILE__, __LINE__));
			return (0);
		}

		if (mip6_process_bu(m, opt) != 0) {
			mip6log((LOG_ERR,
				 "%s:d: processing BU failed\n",
				 __FILE__, __LINE__));
			goto bad;
		}
		break;

	case IP6OPT_BINDING_ACK:
		if (!MIP6_IS_MN)
			return (0);

#if 0
		if ((opt - (u_int8_t *)dstopts) % 4 != 3) {
			ip6stat.ip6s_badoptions++;
			goto bad;
		}
#endif

		error = mip6_validate_ba(m, opt);
		if (error == -1) {
			mip6log((LOG_ERR,
				 "%s:%d: invalid BA received.\n",
				 __FILE__, __LINE__));
			goto bad;
		}
		if (error == 1) {
			/* invalid BA.  we ignore this silently */
			mip6log((LOG_NOTICE,
				 "%s:%d: invalid BA received.  ignore this.\n",
				 __FILE__, __LINE__));
			return (0);
		}

		if (mip6_process_ba(m, opt) != 0) {
			mip6log((LOG_ERR,
				 "%s:%d: processing BA failed\n",
				 __FILE__, __LINE__));
			goto bad;
		}
		break;

	case IP6OPT_BINDING_REQ:
		if (!MIP6_IS_MN)
			return (0);

		error = mip6_validate_br(m, opt);
		if (error == -1) {
			mip6log((LOG_ERR,
				 "%s:%d: invalid BR received\n",
				 __FILE__, __LINE__));
			goto bad;
		}
		if (error == 1) {
			/* invalid BR.  we ignore this silently */
			mip6log((LOG_NOTICE,
				 "%s:%d: invalid BR received.  ignore this.\n",
				 __FILE__, __LINE__));
			return (0);
		}

		if (mip6_process_br(m, opt) != 0) {
			mip6log((LOG_ERR,
				 "%s:%d: processing BR failed\n",
				 __FILE__, __LINE__));
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
