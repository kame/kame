/*	$KAME: mip6.c,v 1.146 2002/07/24 08:53:36 k-sugyou Exp $	*/

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
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif

#if defined(MIP6_ALLOW_COA_FALLBACK) && defined(MIP6_BDT)
#error "you cannot specify both MIP6_ALLOW_COA_FALLBACK and MIP6_BDT"
#endif

#if defined(MIP6) && !defined(MIP6_DRAFT17)
#error "MIP6 is not released yet"
#endif

#ifdef __NetBSD__
#define HAVE_SHA1
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

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/scope6_var.h>

#if defined(IPSEC) && !defined(__OpenBSD__)
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#endif
#ifdef HAVE_SHA1
#include <sys/sha1.h>
#define SHA1_RESULTLEN	20
#else
#include <crypto/sha1.h>
#endif
#include <crypto/hmac.h>

#include <net/if_hif.h>

#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>

#ifndef MIP6_CONFIG_DEBUG
#ifdef MIP6_DEBUG
#define MIP6_CONFIG_DEBUG 1
#else /* MIP6_DEBUG */
#define MIP6_CONFIG_DEBUG 0
#endif /* MIP6_DEBUG */
#endif /* !MIP6_CONFIG_DEBUG */

#ifndef MIP6_CONFIG_USE_IPSEC
#define MIP6_CONFIG_USE_IPSEC 0
#endif /* !MIP6_CONFIG_USE_IPSEC */

#ifndef MIP6_CONFIG_USE_AUTHDATA
#define MIP6_CONFIG_USE_AUTHDATA 1
#endif /* !MIP6CONFIG_USE_AUTHDATA */

#ifndef MIP6_CONFIG_BC_LIFETIME_LIMIT
#define MIP6_CONFIG_BC_LIFETIME_LIMIT 30
#endif /* !MIP6_CONFIG_BC_LIFETIME_LIMIT */

#ifndef MIP6_CONFIG_HRBC_LIFETIME_LIMIT
#define MIP6_CONFIG_HRBC_LIFETIME_LIMIT 30
#endif /* !MIP6_CONFIG_HRBC_LIFETIME_LIMIT */

#ifndef MIP6_CONFIG_BU_MAXLIFETIME
#define MIP6_CONFIG_BU_MAXLIFETIME 30
#endif /* !MIP6_CONFIG_BU_MAXLIFETIME */

#ifndef MIP6_CONFIG_HRBU_MAXLIFETIME
#define MIP6_CONFIG_HRBU_MAXLIFETIME 30
#endif /* !MIP6_CONFIG_HRBU_MAXLIFETIME */

#if 1 /* #ifndef MIP6_CONFIG_BU_USE_SINGLE */
#define MIP6_CONFIG_BU_USE_SINGLE 1
#else
#define MIP6_CONFIG_BU_USE_SINGLE 0
#endif /* !MIP6_CONFIG_BU_USE_SINGLE */

extern struct mip6_subnet_list mip6_subnet_list;
extern struct mip6_prefix_list mip6_prefix_list;

extern struct mip6_bc_list mip6_bc_list;

extern struct mip6_unuse_hoa_list mip6_unuse_hoa;

struct mip6_config mip6_config;

/*
 * XXX should we dynamically allocate the space to support any number
 * of ifps?
 */
static struct mip6_preferred_ifnames mip6_preferred_ifnames;

#ifdef __NetBSD__
struct callout mip6_pfx_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_pfx_ch;
#endif
int mip6_pfx_timer_running = 0;

#ifdef MIP6_DRAFT17
mip6_nonce_t mip6_nonce[MIP6_NONCE_HISTORY];
mip6_nodekey_t mip6_nodekey[MIP6_NONCE_HISTORY];	/* this is described as 'Kcn' in the spec */
u_int16_t nonce_index;		/* the idx value pointed by nonce_head */
mip6_nonce_t *nonce_head;	/* Current position of nonce on the array mip6_nonce */
#endif /* MIP6_DRAFT17 */

static int mip6_prefix_list_update_sub __P((struct hif_softc *,
					    struct sockaddr_in6 *,
					    struct nd_prefix *,
					    struct nd_defrouter *));
static int mip6_register_current_location __P((void));
static int mip6_haddr_config __P((struct hif_softc *));
static int mip6_attach_haddrs __P((struct hif_softc *));
static int mip6_detach_haddrs __P((struct hif_softc *));
static int mip6_add_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_remove_haddrs __P((struct hif_softc *, struct ifnet *));
static int mip6_remove_addr __P((struct ifnet *, struct in6_ifaddr *));

/* ipv6 header manipuration functions */
static int mip6_rthdr_create_withdst __P((struct ip6_rthdr **,
					  struct sockaddr_in6 *,
					  struct ip6_pktopts *));
static int mip6_haddr_destopt_create __P((struct ip6_dest **,
					  struct sockaddr_in6 *,
					  struct sockaddr_in6 *,
					  struct hif_softc *));
#ifdef MIP6_DRAFT17
static void mip6_create_nonce __P((mip6_nonce_t *));
static void mip6_create_nodekey __P((mip6_nodekey_t *));
#if 0
static void mip6_update_nonce_nodekey(void);
#endif
#endif /* MIP6_DRAFT17 */

#if defined(IPSEC) && !defined(__OpenBSD__)
struct ipsecrequest *mip6_getipsecrequest __P((struct sockaddr_in6 *,
					       struct sockaddr_in6 *,
					       struct secpolicy *));
struct secpolicy *mip6_getpolicybyaddr __P((struct sockaddr_in6 *,
					    struct sockaddr_in6 *,
					    u_int));
#endif /* IPSEC && !__OpenBSD__ */

void
mip6_init()
{
	bzero(&mip6_config, sizeof(mip6_config));
	mip6_config.mcfg_type = 0;
	mip6_config.mcfg_use_ipsec = MIP6_CONFIG_USE_IPSEC;
	mip6_config.mcfg_use_authdata = MIP6_CONFIG_USE_AUTHDATA;
	mip6_config.mcfg_debug = MIP6_CONFIG_DEBUG;
	mip6_config.mcfg_bc_lifetime_limit = MIP6_CONFIG_BC_LIFETIME_LIMIT;
	mip6_config.mcfg_hrbc_lifetime_limit = MIP6_CONFIG_HRBC_LIFETIME_LIMIT;
	mip6_config.mcfg_bu_maxlifetime = MIP6_CONFIG_BU_MAXLIFETIME;
	mip6_config.mcfg_hrbu_maxlifetime = MIP6_CONFIG_HRBU_MAXLIFETIME;
	mip6_config.mcfg_bu_use_single = MIP6_CONFIG_BU_USE_SINGLE;

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
        callout_init(&mip6_pfx_ch);
#endif

	mip6_bu_init(); /* binding update routine initialize */
	mip6_ha_init(); /* homeagent list management initialize */
	mip6_bc_init(); /* binding cache routine initailize */
	mip6_prefix_init();
	mip6_subnet_init();

	LIST_INIT(&mip6_subnet_list);
	LIST_INIT(&mip6_unuse_hoa);

#ifdef MIP6_DRAFT17
	/* Initialize nonce, key, and something else for CN */
	nonce_head = mip6_nonce;
	nonce_index = 0;
	mip6_create_nonce(mip6_nonce);
	mip6_create_nodekey(mip6_nodekey);
#endif /* MIP6_DRAFT17 */
}

/*
 * we heard a router advertisement.
 * from the advertised prefix, we can find our current location.
 */
int
mip6_prefix_list_update(saddr, ndpr, dr, m)
	struct sockaddr_in6 *saddr;
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
	struct sockaddr_in6 *rtaddr;
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
	int location;
	int error = 0;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	location = HIF_LOCATION_UNKNOWN;
	if (!IN6_IS_ADDR_LINKLOCAL(&rtaddr->sin6_addr)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: RA from a non-linklocal router (%s).\n",
			 __FILE__, __LINE__, ip6_sprintf(&rtaddr->sin6_addr)));
		return (0);
	}
#if 0
	lladdr = *rtaddr;
	/* XXX: KAME link-local hack; remove ifindex */
	lladdr.s6_addr16[1] = 0;
#endif

	mip6log((LOG_INFO,
		 "%s:%d: prefix %s from %s\n",
		 __FILE__, __LINE__,
		 ip6_sprintf(&ndpr->ndpr_prefix.sin6_addr),
		 ip6_sprintf(&rtaddr->sin6_addr)));

	hsbypfx = hif_subnet_list_find_withprefix(&sc->hif_hs_list_home,
						  &ndpr->ndpr_prefix,
						  ndpr->ndpr_plen);
	hsbyha =  hif_subnet_list_find_withhaaddr(&sc->hif_hs_list_home,
						  rtaddr);

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
	tmpmpfx.mpfx_prefix = ndpr->ndpr_prefix;
	tmpmpfx.mpfx_prefixlen = ndpr->ndpr_plen;
	mpfx_is_new = 0;
	mpfx = mip6_prefix_list_find(&tmpmpfx);
	if (mpfx) {
		/* found an existing entry.  just update it. */
		mpfx->mpfx_vltime = ndpr->ndpr_vltime;
		mpfx->mpfx_vlexpire = time_second + mpfx->mpfx_vltime;
		mpfx->mpfx_pltime = ndpr->ndpr_pltime;
		mpfx->mpfx_plexpire = time_second + mpfx->mpfx_pltime;
		/* XXX mpfx->mpfx_haddr; */
	} else {
		/* this is a new prefix. */
		mpfx_is_new = 1;
		mpfx = mip6_prefix_create(&ndpr->ndpr_prefix,
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
	mha = mip6_ha_list_find_withaddr(&mip6_ha_list, rtaddr);
	if (mha) {
		/* an entry exists.  update information. */
		if (ndpr->ndpr_raf_router) {
			mha->mha_gaddr = ndpr->ndpr_prefix;
		}
		mha->mha_flags = dr->flags;
	} else {
		/* this is a new ha. */
		mha_is_new = 1;

		mha = mip6_ha_create(rtaddr,
				     ndpr->ndpr_raf_router ?
				     &ndpr->ndpr_prefix : NULL,
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
			 ip6_sprintf(&rtaddr->sin6_addr),
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
						      rtaddr);
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
						      &ndpr->ndpr_prefix,
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
	struct sockaddr_in6 *hif_coa; /* newly selected CoA. */
{
	struct hif_softc *sc;
	struct hif_subnet *hs;
	int error = 0;

	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		sc->hif_location = HIF_LOCATION_UNKNOWN;

#if 1
		for (hs = TAILQ_FIRST(&sc->hif_hs_list_home);
		     hs;
		     hs = TAILQ_NEXT(hs, hs_entry)) {
			struct mip6_subnet *ms;
			struct mip6_subnet_prefix *mspfx;

			if ((ms = hs->hs_ms) == NULL) {
				/* must not happen. */
				return (EINVAL);
			}
			for (mspfx = TAILQ_FIRST(&ms->ms_mspfx_list);
			     mspfx;
			     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
				struct mip6_prefix *mpfx;

				if ((mpfx = mspfx->mspfx_mpfx) == NULL) {
					/* must not happen. */
					return (EINVAL);
				}
				if (in6_are_prefix_equal(
					    &hif_coa->sin6_addr,
					    &mpfx->mpfx_prefix.sin6_addr,
					    mpfx->mpfx_prefixlen)) {
					sc->hif_location = HIF_LOCATION_HOME;
					goto i_know_where_i_am;
				}
			}
		}
		sc->hif_location = HIF_LOCATION_FOREIGN;
	i_know_where_i_am:
#else
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			if (!in6_are_prefix_equal(&hif_coa->sin6_addr,
						  &pr->ndpr_prefix.sin6_addr,
						  pr->ndpr_plen))
				continue;

			if (hif_subnet_list_find_withprefix(
				    &sc->hif_hs_list_home,
				    &pr->ndpr_prefix,
				    pr->ndpr_plen))
				sc->hif_location = HIF_LOCATION_HOME;
			else if (hif_subnet_list_find_withprefix(
				    &sc->hif_hs_list_foreign,
				    &pr->ndpr_prefix,
				    pr->ndpr_plen))
				sc->hif_location = HIF_LOCATION_FOREIGN;
		}
#endif
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
 * mip6_process_movement() is called (1) after prefix onlink checking
 * has finished and (2) p2p address is configured by calling
 * in6_control().  if the CoA has changed, call
 * mip6_register_current_location() to make a home registration.
 */
int
mip6_process_movement(void)
{
	int error = 0;
	int coa_changed = 0;

	hif_save_location();
	coa_changed = mip6_select_coa2();
	if (coa_changed == 1)
		error = mip6_process_pfxlist_status_change(&hif_coa);
	if (coa_changed == 1)
		error = mip6_register_current_location();
	else
		hif_restore_location();

	return (error);
}

/*
 * mip6_register_current_location() is called only when CoA has
 * changed.  therefore, we can call mip6_home_registration() in any
 * case because we must have moved from somewhere to somewhere.
 */
static int
mip6_register_current_location(void)
{
	struct hif_softc *sc;
	int error = 0;

	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		switch (sc->hif_location) {
		case HIF_LOCATION_HOME:
			/*
			 * we moved to home.  unregister our home
			 * address.
			 */
			error = mip6_home_registration(sc);
			break;

		case HIF_LOCATION_FOREIGN:
			/*
			 * we moved to foreign.  register the current
			 * CoA to our home agent.
			 */
			/* XXX: TODO register to the old subnet's AR. */
			error = mip6_home_registration(sc);
			break;

		case HIF_LOCATION_UNKNOWN:
			break;
		}
	}

	return (error);
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
	struct sockaddr_in6 ia_addr;
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
	ia_addr = ia6->ia_addr;
	if (in6_addr2zoneid(hcoa->hcoa_ifp,
			    &ia_addr.sin6_addr,
			    &ia_addr.sin6_scope_id)) {
		ret = -1;
		goto select_coa_end;
	}

	if (!SA6_ARE_ADDR_EQUAL(&hif_coa, &ia_addr)) {
		hif_coa = ia_addr;
		ret = 1;
		mip6log((LOG_INFO,
			 "%s:%d: CoA has changed to %s\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ia_addr.sin6_addr)));
	}

 select_coa_end:
	return (ret);
}

int
mip6_select_coa2(void)
{
	struct ifnet *ifp;
	struct ifaddr *ia;
	struct in6_ifaddr *ia6, *ia6_best;
	struct sockaddr_in6 ia6_addr;
	int score, score_best;

	score = score_best = -1;
	ia6 = ia6_best = NULL;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_list.tqe_next)
#endif
	{
		if (ifp->if_type == IFT_HIF)
			continue;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ia = ifp->if_addrlist;
		     ia;
		     ia = ia->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		for (ia = TAILQ_FIRST(&ifp->if_addrhead);
		     ia;
		     ia = TAILQ_NEXT(ia, ifa_link))
#else
		for (ia = ifp->if_addrlist.tqh_first;
		     ia;
		     ia = ia->ifa_list.tqe_next)
#endif
		{
			if (ia->ifa_addr->sa_family != AF_INET6)
				continue;
			ia6 = (struct in6_ifaddr *)ia;

			if (ia6->ia6_flags &
			    (IN6_IFF_ANYCAST
#ifdef MIP6_STATIC_HADDR
			     | IN6_IFF_HOME
#endif
			     /* | IN6_IFF_TENTATIVE */
			     | IN6_IFF_DETACHED
			     | IN6_IFF_DUPLICATED
			     | IN6_IFF_DEPRECATED))
				continue;

			ia6_addr = ia6->ia_addr;
			if (in6_addr2zoneid(ia6->ia_ifp,
					    &ia6_addr.sin6_addr,
					    &ia6_addr.sin6_scope_id)) {
				continue; /* XXX */
			}
			if (SA6_IS_ADDR_UNSPECIFIED(&ia6_addr))
				continue;
			if (IN6_IS_ADDR_LOOPBACK(&ia6_addr.sin6_addr))
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&ia6_addr.sin6_addr))
				continue;

			score = 0;

			/* prefer user specified CoA interfaces. */
			if (strncmp(if_name(ifp),
			    mip6_preferred_ifnames.mip6pi_ifname[0],
			    IFNAMSIZ) == 0)
				score += 4;
			if (strncmp(if_name(ifp),
			    mip6_preferred_ifnames.mip6pi_ifname[1],
			    IFNAMSIZ) == 0)
				score += 3;
			if (strncmp(if_name(ifp),
			    mip6_preferred_ifnames.mip6pi_ifname[2],
			    IFNAMSIZ) == 0)
				score += 2;

			/* keep CoA same as possible. */
			if (SA6_ARE_ADDR_EQUAL(&hif_coa, &ia6_addr))
				score += 1;

			if (score > score_best) {
				score_best = score;
				ia6_best = ia6;
			}
		}
	}

	if (ia6_best == NULL) {
		mip6log((LOG_INFO,
		    "%s:%d: no available CoA found\n", __FILE__, __LINE__));
		return (0);
	}

	/* recover scope information. */
	ia6_addr = ia6_best->ia_addr;
	if (in6_addr2zoneid(ia6_best->ia_ifp, &ia6_addr.sin6_addr,
	    &ia6_addr.sin6_scope_id)) {
		return (-1);
	}

	/* check if the CoA has been changed. */
	if (SA6_ARE_ADDR_EQUAL(&hif_coa, &ia6_addr)) {
		/* CoA has not been changed. */
		return (0);
	}

	hif_coa = ia6_addr;
	mip6log((LOG_INFO,
		 "%s:%d: CoA has changed to %s\n",
		 __FILE__, __LINE__,
		 ip6_sprintf(&ia6_addr.sin6_addr)));
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
							  &mpfx->mpfx_prefix.sin6_addr,
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
#ifdef MIP6_STATIC_HADDR
	{
		struct nd_prefix *pr;
		for (pr = nd_prefix.lh_first;
		     pr;
		     pr = pr->ndpr_next) {
			if (hif_subnet_list_find_withprefix(
				    &sc->hif_hs_list_home, &pr->ndpr_prefix,
				    pr->ndpr_plen))
				break;
		}
		if (pr != NULL)
			mip6_add_haddrs(sc, pr->ndpr_ifp);
	}
#endif

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
			if (SA6_IS_ADDR_UNSPECIFIED(&mpfx->mpfx_haddr)) {
				error = mip6_prefix_haddr_assign(mpfx, sc);
				if (error) {
					mip6log((LOG_ERR,
						 "%s:%d: can't assign home address for prefix %s.\n",
						 __FILE__, __LINE__,
						 ip6_sprintf(&mpfx->mpfx_prefix.sin6_addr)));
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
			ifra.ifra_addr.sin6_addr = mpfx->mpfx_haddr.sin6_addr;
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
	int subcmd;
	struct hif_softc *sc;
	struct mip6_req *mr = (struct mip6_req *)data;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
			s = splsoftnet();
#else
			s = splnet();
#endif

	switch (cmd) {
	case SIOCSMIP6CFG:
		subcmd = *(int *)data;
		switch (subcmd) {
		case SIOCSMIP6CFG_ENABLEMN:
#ifdef MIP6_STATIC_HADDR
			for (sc = TAILQ_FIRST(&hif_softc_list);
			     sc;
			     sc = TAILQ_NEXT(sc, hif_entry)) {
				if (IN6_IS_ADDR_UNSPECIFIED(&sc->hif_ifid)) {
					mip6log((LOG_INFO,
						 "%s:%d: "
						 "You must specify the IFID.\n",
						 __FILE__, __LINE__));
					splx(s);
					return (EINVAL);
				}
			}
#endif
			mip6log((LOG_INFO,
				 "%s:%d: MN function enabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_type = MIP6_CONFIG_TYPE_MOBILENODE;
			if (mip6_process_movement()) {
				mip6log((LOG_WARNING,
				    "%s:%d: mip6_process_movement failed.\n",
				    __FILE__, __LINE__));
				/* ignore this error... */
			}
			break;

		case SIOCSMIP6CFG_DISABLEMN:
			mip6log((LOG_INFO,
				 "%s:%d: MN function disabled\n",
				 __FILE__, __LINE__));
			for (sc = TAILQ_FIRST(&hif_softc_list);
			     sc;
			     sc = TAILQ_NEXT(sc, hif_entry)) {
				struct mip6_subnet *ms;

				mip6_detach_haddrs(sc);
				mip6_bu_list_remove_all(&sc->hif_bu_list);
				hif_subnet_list_remove_all(
					&sc->hif_hs_list_home);
				hif_subnet_list_remove_all(
					&sc->hif_hs_list_foreign);
				while (!LIST_EMPTY(&mip6_subnet_list)) {
					ms = LIST_FIRST(&mip6_subnet_list);
					mip6_subnet_list_remove(
						&mip6_subnet_list,
						ms);
				}
			}
			bzero(&hif_coa, sizeof(hif_coa));
			hif_coa.sin6_len = sizeof(hif_coa);
			hif_coa.sin6_family = AF_INET6;
			hif_coa.sin6_addr = in6addr_any;
			mip6_config.mcfg_type = 0;
			break;

		case SIOCSMIP6CFG_ENABLEHA:
			mip6log((LOG_INFO,
				 "%s:%d: HA function enabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_type = MIP6_CONFIG_TYPE_HOMEAGENT;
			break;

		case SIOCSMIP6CFG_ENABLEIPSEC:
			mip6log((LOG_INFO,
				 "%s:%d: IPsec protection enabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_use_ipsec = 1;
			break;

		case SIOCSMIP6CFG_DISABLEIPSEC:
			mip6log((LOG_INFO,
				 "%s:%d: IPsec protection disabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_use_ipsec = 0;
			break;

		case SIOCSMIP6CFG_ENABLEAUTHDATA:
			mip6log((LOG_INFO,
				 "%s:%d: Authdata protection enabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_use_authdata = 1;
			break;

		case SIOCSMIP6CFG_DISABLEAUTHDATA:
			mip6log((LOG_INFO,
				 "%s:%d: Authdata protection disabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_use_authdata = 0;
			break;

		case SIOCSMIP6CFG_ENABLEDEBUG:
			mip6log((LOG_INFO,
				 "%s:%d: debug message enabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_debug = 1;
			break;

		case SIOCSMIP6CFG_DISABLEDEBUG:
			mip6log((LOG_INFO,
				 "%s:%d: debug message disabled\n",
				 __FILE__, __LINE__));
			mip6_config.mcfg_debug = 0;
			break;

		default:
			splx(s);
			return (EINVAL);
		}
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

	case SIOCSUNUSEHA:
		{
			struct mip6_unuse_hoa *uh;

			for (uh = LIST_FIRST(&mip6_unuse_hoa);
			     uh;
			     uh = LIST_NEXT(uh, unuse_entry)) {
				if (IN6_ARE_ADDR_EQUAL(&uh->unuse_addr,
				    &mr->mip6r_ru.mip6r_sin6.sin6_addr) &&
				    uh->unuse_port
				    == mr->mip6r_ru.mip6r_sin6.sin6_port) {
					splx(s);
					return (EEXIST);
				}
			}

			uh = malloc(sizeof(struct mip6_unuse_hoa), M_IP6OPT, M_WAIT);
			if (uh == NULL) {
				splx(s);
				return (ENOBUFS);
			}

			uh->unuse_addr = mr->mip6r_ru.mip6r_sin6.sin6_addr;
			uh->unuse_port = mr->mip6r_ru.mip6r_sin6.sin6_port;
			LIST_INSERT_HEAD(&mip6_unuse_hoa, uh, unuse_entry);
		}
		break;

	case SIOCGUNUSEHA:
			/* Not yet */
		break;

	case SIOCDUNUSEHA:
		{
			struct mip6_unuse_hoa *uh, *nxt;

			for (uh = LIST_FIRST(&mip6_unuse_hoa); uh; uh = nxt) {
				nxt = LIST_NEXT(uh, unuse_entry);
				if (IN6_ARE_ADDR_EQUAL(&uh->unuse_addr,
				    &mr->mip6r_ru.mip6r_sin6.sin6_addr) &&
				    uh->unuse_port
				    == mr->mip6r_ru.mip6r_sin6.sin6_port) {
					LIST_REMOVE(uh, unuse_entry);
					free(uh, M_IP6OPT);
					break;
				}
			}
			if (uh == NULL) {
				splx(s);
				return (ENOENT);
			}
		}
		break;

	case SIOCSPREFERREDIFNAMES:
	{
		/*
		 * set preferrable ifps for selecting CoA.  we must
		 * keep the name as a string because other information
		 * (such as a pointer, interface index) may be changed
		 * when removing the devices.
		 */
		bcopy(&mr->mip6r_ru.mip6r_ifnames, &mip6_preferred_ifnames,
		    sizeof(mr->mip6r_ru.mip6r_ifnames));
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
mip6_create_ip6hdr(src_sa, dst_sa, nh, plen)
	struct sockaddr_in6 *src_sa; /* source sockaddr */
	struct sockaddr_in6 *dst_sa; /* destination sockaddr */
	u_int8_t nh; /* next header */
	u_int32_t plen; /* payload length */
{
	struct ip6_hdr *ip6; /* ipv6 header. */
	struct mbuf *m; /* a pointer to the mbuf containing ipv6 header. */
	u_int32_t maxlen;

	maxlen = sizeof(*ip6) + plen;
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && (max_linkhdr + maxlen >= MHLEN)) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (NULL);
		}
	}
	if (m == NULL)
		return (NULL);
	m->m_pkthdr.rcvif = NULL;
	m->m_data += max_linkhdr;

	/* set mbuf length. */
	m->m_pkthdr.len = m->m_len = maxlen;

	/* fill an ipv6 header. */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = htons((u_int16_t)plen);
	ip6->ip6_nxt = nh;
	ip6->ip6_hlim = ip6_defhlim;
	ip6->ip6_src = src_sa->sin6_addr;
	in6_clearscope(&ip6->ip6_src);
	ip6->ip6_dst = dst_sa->sin6_addr;
	in6_clearscope(&ip6->ip6_dst);

	if (!ip6_setpktaddrs(m, src_sa, dst_sa)) {
		m_free(m);
		return (NULL);
	}

	return (m);
}

int
mip6_exthdr_create(m, opt, mip6opt)
	struct mbuf *m;                   /* ip datagram */
	struct ip6_pktopts *opt;          /* pktopt passed to ip6_output */
	struct mip6_pktopts *mip6opt;
{
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	int s, error = 0;

	mip6opt->mip6po_rthdr = NULL;
	mip6opt->mip6po_haddr = NULL;
	mip6opt->mip6po_dest2 = NULL;
	mip6opt->mip6po_mobility = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6_getpktaddrs(m, &src, &dst))
		return (EINVAL);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	/*
	 * add the routing header for the route optimization if there
	 * exists a valid binding cache entry for this destination
	 * node.
	 */
	error = mip6_rthdr_create_withdst(&mip6opt->mip6po_rthdr, dst, opt);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: rthdr creation failed.\n",
			 __FILE__, __LINE__));
		goto bad;
	}

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

#ifdef MIP6XXX
	/XXX check nxt == IPPROTO_NONE *//* not supported piggyback */
	/*
	 * insert BA/BR if pending BA/BR exist.
	 */
	error = mip6_babr_destopt_create(&mip6opt->mip6po_dest2, dst, opt);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: BA/BR destopt insertion failed.\n",
			 __FILE__, __LINE__));
		goto bad;
	}
#endif /* MIP6XXX */

	/* following stuff is applied only for MN. */
	if (!MIP6_IS_MN) {
		goto noneed;
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
		goto noneed;
	}

	/* check registration status */
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst, src);
	if (mbu == NULL) {
		/* no registration action started yet. */
		goto noneed;
	}

	if (ip6->ip6_nxt == IPPROTO_NONE) {
		/* create a binding update mobility header. */
		error = mip6_ip6mu_create(&mip6opt->mip6po_mobility,
				  	src, dst, sc);
		if (error) {
			mip6log((LOG_ERR,
			 	"%s:%d: a binding update mobility header "
			 	"insertion failed.\n",
			 	__FILE__, __LINE__));
			goto bad;
		}
	}

	if (mbu->mbu_flags & IP6MU_HOME) {
		/* to my home agent. */
		if (mbu->mbu_fsm_state == MIP6_BU_FSM_STATE_IDLE)
			goto noneed;
	} else {
		/* to any of correspondent nodes. */
		if (mbu->mbu_fsm_state != MIP6_BU_FSM_STATE_BOUND)
			goto noneed;
	}

	/* create haddr destopt. */
	error = mip6_haddr_destopt_create(&mip6opt->mip6po_haddr,
					  src, dst, sc);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: homeaddress insertion failed.\n",
			 __FILE__, __LINE__));
		goto bad;
	}

 noneed:
	error = 0; /* normal exit. */
 bad:
	splx(s);
	return (error);
}

int
mip6_rthdr_create(pktopt_rthdr, coa, opt)
	struct ip6_rthdr **pktopt_rthdr;
	struct sockaddr_in6 *coa;
	struct ip6_pktopts *opt;
{
	struct ip6_rthdr2 *rthdr2;
	size_t len;

	/*
	 * Mobile IPv6 uses type 2 routing header for route
	 * optimization. if the packet has a type 1 routing header
	 * already, we must add a type 2 routing header after the type
	 * 1 routing header.
	 */

	len = sizeof(struct ip6_rthdr2)	+ sizeof(struct in6_addr);
	rthdr2 = malloc(len, M_IP6OPT, M_NOWAIT);
	if (rthdr2 == NULL) {
		return (ENOMEM);
	}
	bzero(rthdr2, len);

	/* rthdr2->ip6r2_nxt = will be filled later in ip6_output */
	rthdr2->ip6r2_len = 2;
	rthdr2->ip6r2_type = 2;
	rthdr2->ip6r2_segleft = 1;
	rthdr2->ip6r2_reserved = 0;
	bcopy((caddr_t)&coa->sin6_addr, (caddr_t)(rthdr2 + 1),
	      sizeof(struct in6_addr));
	*pktopt_rthdr = (struct ip6_rthdr *)rthdr2;

	return (0);
}

static int
mip6_rthdr_create_withdst(pktopt_rthdr, dst, opt)
	struct ip6_rthdr **pktopt_rthdr;
	struct sockaddr_in6 *dst;
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
mip6_haddr_destopt_create(pktopt_haddr, src, dst, sc)
	struct ip6_dest **pktopt_haddr;
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	struct hif_softc *sc;
{
	struct ip6_opt_home_address haddr_opt;
	struct mip6_buffer optbuf;
	struct mip6_bu *mbu;
	struct sockaddr_in6 *coa;

	if (*pktopt_haddr) {
		/* already allocated ? */
		return (0);
	}

	bzero(&haddr_opt, sizeof(struct ip6_opt_home_address));
	haddr_opt.ip6oh_type = IP6OPT_HOME_ADDRESS;
	haddr_opt.ip6oh_len = IP6OPT_HALEN;

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst, src);
	if (mbu && ((mbu->mbu_state & MIP6_BU_STATE_MIP6NOTSUPP) != 0)) {
		return (0);
	}
	if (mbu)
		coa = &mbu->mbu_coa;
	else
		coa = &hif_coa;
	bcopy((caddr_t)&coa->sin6_addr, haddr_opt.ip6oh_addr,
	      sizeof(struct in6_addr));

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

#ifdef MIP6XXX
int
mip6_babr_destopt_create(pktopt_mip6dest2, dst, opts)
	struct ip6_dest **pktopt_mip6dest2;
	struct sockaddr_in6 *dst;
	struct ip6_pktopts *opts;
{
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
#endif /* MIP6XXX */

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

	if (mip6opt->mip6po_mobility)
		free(mip6opt->mip6po_mobility, M_IP6OPT);

	return;
}

#if defined(IPSEC) && !defined(__OpenBSD__)
struct ipsecrequest *
mip6_getipsecrequest(src, dst, sp)
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	struct secpolicy *sp;
{
	struct ipsecrequest *isr = NULL;
	struct secasindex saidx;
	struct sockaddr_in6 *sin6;

	for (isr = sp->req; isr; isr = isr->next) {
#if 0
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL) {
			/* the rest will be handled by ipsec6_output_tunnel() */
			break;
		}
#endif /* 0 */

		/* make SA index for search proper SA */
		bcopy(&isr->saidx, &saidx, sizeof(saidx));
		saidx.mode = isr->saidx.mode;
		saidx.reqid = isr->saidx.reqid;
		sin6 = (struct sockaddr_in6 *)&saidx.src;
		if (sin6->sin6_len == 0) {
			*sin6 = *src;
			sin6->sin6_port = IPSEC_PORT_ANY;
			if (IN6_IS_SCOPE_LINKLOCAL(&src->sin6_addr)) {
				/* fix scope id for comparing SPD */
				sin6->sin6_addr.s6_addr16[1] = 0;
			}
		}
		sin6 = (struct sockaddr_in6 *)&saidx.dst;
		if (sin6->sin6_len == 0) {
			*sin6 = *dst;
			sin6->sin6_port = IPSEC_PORT_ANY;
			if (IN6_IS_SCOPE_LINKLOCAL(&dst->sin6_addr)) {
				/* fix scope id for comparing SPD */
				sin6->sin6_addr.s6_addr16[1] = 0;
			}
		}

		if (key_checkrequest(isr, &saidx) == ENOENT) {
			/*
			 * IPsec processing is required, but no SA found.
			 * I assume that key_acquire() had been called
			 * to get/establish the SA. Here I discard
			 * this packet because it is responsibility for
			 * upper layer to retransmit the packet.
			 */
#if 0
			ipsec6stat.out_nosa++;
			error = ENOENT;

			/*
			 * Notify the fact that the packet is discarded
			 * to ourselves. I believe this is better than
			 * just silently discarding. (jinmei@kame.net)
			 * XXX: should we restrict the error to TCP packets?
			 * XXX: should we directly notify sockets via
			 *      pfctlinputs?
			 *
			 * Noone have initialized rcvif until this point,
			 * so clear it.
			 */
			if ((state->m->m_flags & M_PKTHDR) != 0)
				state->m->m_pkthdr.rcvif = NULL;
			icmp6_error(state->m, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_ADMIN, 0);
			state->m = NULL; /* icmp6_error freed the mbuf */
			goto bad;
#endif /* 0 */
			return (NULL);
		}

		/* validity check */
		if (isr->sav == NULL) {
#if 0
			switch (ipsec_get_reqlevel(isr)) {
			case IPSEC_LEVEL_USE:
				continue;
			case IPSEC_LEVEL_REQUIRE:
				/* must be not reached here. */
				panic("ipsec6_output_trans: no SA found, but required.");
			}
#endif /* 0 */
			return (NULL);
		}

		/*
		 * If there is no valid SA, we give up to process.
		 * see same place at ipsec4_output().
		 */
		if (isr->sav->state != SADB_SASTATE_MATURE
		 && isr->sav->state != SADB_SASTATE_DYING) {
#if 0
			ipsec6stat.out_nosa++;
			error = EINVAL;
			goto bad;
#endif /* 0 */
			return (NULL);
		}
		break;
	}
	return (isr);
}

struct secpolicy *
mip6_getpolicybyaddr(src, dst, dir)
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	u_int dir;
{
	struct secpolicy *sp = NULL;
	struct secpolicyindex spidx;

	if (src == NULL || dst == NULL)
		return (NULL);

	bzero(&spidx, sizeof(spidx));

	*(struct sockaddr_in6 *)&spidx.src = *src;
	spidx.prefs = sizeof(struct in6_addr) << 3;
	*(struct sockaddr_in6 *)&spidx.dst = *dst;
	spidx.prefs = sizeof(struct in6_addr) << 3;
	spidx.ul_proto = IPPROTO_DSTOPTS; /* XXX */

	sp = key_allocsp(&spidx, dir);

	/* return value may be NULL. */
	return (sp);
}
#endif /* IPSEC && !__OpenBSD__ */

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

	rest = buf->off % 8;

	if (rest == 7) {
		/* Add a PAD1 option */
		bzero((caddr_t)buf->buf + buf->off, 1);
		buf->off += 1;
	} else if (rest > 0 && rest < 7) {
		/* Add a PADN option */
		padlen = 8 - rest;
		bzero((caddr_t)buf->buf + buf->off, padlen);
		*(u_int8_t *)((caddr_t)buf->buf + buf->off) = IP6OPT_PADN;
		*(u_int8_t *)((caddr_t)buf->buf + buf->off + 1) = padlen - 2;
		buf->off += padlen;
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
	struct ip6_opt_home_address    *ha;
	caddr_t                         pos;
	u_int8_t                        type, len, off;
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
	type = *(u_int8_t*)opt;
	switch (type) {
		case IP6OPT_HOME_ADDRESS:
			/* HA alignment requirement (8n + 6) */
			rest = dh->off % 8;
			if (rest <= 4) {
				/* Add a PADN option with length X */
				len = 6 - rest - 2;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				*(u_int8_t *)((caddr_t)dh->buf + dh->off++) = IP6OPT_PADN;
				*(u_int8_t *)((caddr_t)dh->buf + dh->off++) = len; /* PADN length */
				dh->off += len;
			} else if (rest == 5) {
				/* Add a PAD1 option */
				*(u_int8_t *)((caddr_t)dh->buf + dh->off++) = IP6OPT_PAD1;
			} else if (rest == 7) {
				/* Add a PADN option with length 5 */
				bzero((caddr_t)dh->buf + dh->off, 5 + 2);
				*(u_int8_t *)((caddr_t)dh->buf + dh->off++) = IP6OPT_PADN;
				*(u_int8_t *)((caddr_t)dh->buf + dh->off++) = 5; /* PADN length */
				dh->off += 5;
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

#if defined(IPSEC) && !defined(__OpenBSD__)
caddr_t
mip6_add_subopt2dh(subopt, opt, dh)
	u_int8_t *subopt; /* MIP6 sub-options */
	u_int8_t *opt; /* MIP6 destination option */
	struct mip6_buffer *dh; /* Buffer containing the IPv6 DH */
{
	int suboptlen = 0;
	caddr_t subopt_pos = NULL;
	u_int8_t type;
	u_int8_t len;
	int rest;

	/* verify input */
	if (subopt == NULL || dh == NULL)
		return (0);
	if (dh->off < 2) {
		/* Illegal input. */
		return (0);
	}

	/* Add sub-option to Destination option */
	type = *subopt;
	switch (type) {
		case MIP6OPT_AUTHDATA:
			/*
			 * Authentication Data alignment requirement
			 * (8n + 6)
			 */
			rest = dh->off % 8;
			suboptlen = 0;
			if (rest <= 4) {
				/* Add a PADN option with length X */
				len = 6 - rest - 2;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				*(u_int8_t *)((caddr_t)dh->buf + dh->off) = MIP6OPT_PADN;
				*(u_int8_t *)((caddr_t)dh->buf + dh->off + 1) = len;
				suboptlen = len + 2;
			} else if (rest == 5) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				suboptlen = 1;
			} else if (rest == 7) {
				/* Add a PADN option with length 5 */
				bzero((caddr_t)dh->buf + dh->off, 5/*len*/ + 2);
				*(u_int8_t *)((caddr_t)dh->buf + dh->off) = MIP6OPT_PADN;
				*(u_int8_t *)((caddr_t)dh->buf + dh->off + 1) = 5;
				suboptlen = 5 + 2;
			}
			dh->off += suboptlen;
			((struct ip6_opt *)opt)->ip6o_len += suboptlen;

			/* Append sub-option to the destination option. */
			suboptlen = 2 + *(subopt + 1);
			subopt_pos = (caddr_t)dh->buf + dh->off;
			bcopy((caddr_t)subopt, subopt_pos, suboptlen);

			/* adjust offset. */
			dh->off += suboptlen;
			((struct ip6_opt *)opt)->ip6o_len += suboptlen;
			break;
	}

	return (subopt_pos);
}
#endif /* IPSEC && !__OpenBSD__ */

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
	struct mbuf *n;

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
			 "%s:%d: haddr dest opt not found.\n",
			 __FILE__, __LINE__));
		return (0);
	}

	/* Swap the IPv6 homeaddress and the care-of address. */
	ip6 = mtod(m, struct ip6_hdr *);
	bcopy(&ip6->ip6_src, &ip6_src, sizeof(ip6->ip6_src));
	n = ip6_findaux(m);
	if (n) {
		struct ip6aux *ip6a;
		ip6a = mtod(n, struct ip6aux *);
		/* XXX scope */
		bcopy(haopt->ip6oh_addr, &ip6a->ip6a_src.sin6_addr,
		      sizeof(haopt->ip6oh_addr));
	}
	bcopy(haopt->ip6oh_addr, &ip6->ip6_src, sizeof(haopt->ip6oh_addr));
	bcopy(&ip6_src, haopt->ip6oh_addr, sizeof(ip6_src));

	return (0);
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
mip6_create_addr(addr, ifid, ndpr)
	struct sockaddr_in6 *addr;
	const struct sockaddr_in6 *ifid;
	struct nd_prefix *ndpr;
{
	int i, bytelen, bitlen;
	u_int8_t mask;
	struct in6_addr *prefix = &ndpr->ndpr_prefix.sin6_addr;
	u_int8_t prefixlen = ndpr->ndpr_plen;

	bzero(addr, sizeof(*addr));

	bytelen = prefixlen / 8;
	bitlen = prefixlen % 8;
	for (i = 0; i < bytelen; i++)
		addr->sin6_addr.s6_addr8[i] = prefix->s6_addr8[i];
	if (bitlen) {
		mask = 0;
		for (i = 0; i < bitlen; i++)
			mask |= (0x80 >> i);
		addr->sin6_addr.s6_addr8[bytelen]
			= (prefix->s6_addr8[bytelen] & mask)
			| (ifid->sin6_addr.s6_addr8[bytelen] & ~mask);

		for (i = bytelen + 1; i < 16; i++)
			addr->sin6_addr.s6_addr8[i]
				= ifid->sin6_addr.s6_addr8[i];
	} else {
		for (i = bytelen; i < 16; i++)
			addr->sin6_addr.s6_addr8[i]
				= ifid->sin6_addr.s6_addr8[i];
	}

	addr->sin6_len = sizeof(*addr);
	addr->sin6_family = AF_INET6;
	if (ndpr->ndpr_ifp) {
		int error;
		error = in6_addr2zoneid(ndpr->ndpr_ifp, &addr->sin6_addr,
					&addr->sin6_scope_id);
		if (error == 0)
			error = in6_embedscope(&addr->sin6_addr, addr);
		if (error != 0)
			mip6log((LOG_ERR,
				 "%s:%d: can't set scope correctly\n",
				 __FILE__, __LINE__));
	} else {
		/* no ifp is specified. */
		if (scope6_check_id(addr, ip6_use_defzone))
			mip6log((LOG_ERR,
				 "%s:%d: can't set scope correctly\n",
				 __FILE__, __LINE__));
	}
}

/* an ad-hoc supplement function to set full sockaddr src/dst to a packet */
int
mip6_setpktaddrs(m)
	struct mbuf *m;
{
	struct sockaddr_in6 src_sa, dst_sa;
	struct in6_addr *src, *dst;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	int error;

	src = &ip6->ip6_src;
	dst = &ip6->ip6_dst;

	bzero(&src_sa, sizeof(src_sa));
	bzero(&dst_sa, sizeof(dst_sa));

	src_sa.sin6_family = dst_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = dst_sa.sin6_len = sizeof(struct sockaddr_in6);
	src_sa.sin6_addr = *src;
	dst_sa.sin6_addr = *dst;

	/* recover scope zone IDs */
	if ((error = in6_recoverscope(&src_sa, src, NULL)) != 0)
		return(error);
	src_sa.sin6_addr = *src; /* XXX */
	if ((error = in6_recoverscope(&dst_sa, dst, NULL)) != 0)
		return(error);
	dst_sa.sin6_addr = *dst; /* XXX */

	if (!ip6_setpktaddrs(m, &src_sa, &dst_sa))
		return(ENOBUFS);
	return(0);
}

#ifdef MIP6_DRAFT17
static void
mip6_create_nonce(nonce)
	mip6_nonce_t *nonce;
{
	int i;

	for (i = 0; i < MIP6_NONCE_SIZE / sizeof(u_long); i++)
		((u_long *)nonce)[i] = random();
}

static void
mip6_create_nodekey(nodekey)
	mip6_nodekey_t *nodekey;
{
	int i;

	for (i = 0; i < MIP6_NODEKEY_SIZE / sizeof(u_long); i++)
		((u_long *)nodekey)[i] = random();
}

#if 0
/* This function should be called periodically */
static void
mip6_update_nonce_nodekey()
{
	nonce_index++;
	if (++nonce_head >= mip6_nonce + MIP6_NONCE_HISTORY)
		nonce_head = mip6_nonce;
	
	mip6_create_nonce(nonce_head);
	mip6_create_nodekey(mip6_nodekey + (nonce_head - mip6_nonce));
}
#endif

int
mip6_get_nonce(index, nonce)
	int index;	/* nonce index */
	mip6_nonce_t *nonce;
{
	signed int offset = index - nonce_index;

	if (offset > 0)
		return (-1);
	
	if (nonce_head + offset >= mip6_nonce + MIP6_NONCE_HISTORY)
		offset = offset - MIP6_NONCE_HISTORY;
	
	if (nonce_head + offset < mip6_nonce)
		return (-1);

	bcopy(&nonce_head[offset], nonce, sizeof(mip6_nonce_t));
	return (0);
}

int
mip6_get_nodekey(index, nodekey)
	int index;	/* nonce index */
	mip6_nodekey_t *nodekey;
{
	signed int offset = index - nonce_index;
	mip6_nodekey_t *nodekey_head;

	if (offset > 0)
		return (-1);
	
	if (nonce_head + offset >= mip6_nonce + MIP6_NONCE_HISTORY)
		offset = offset - MIP6_NONCE_HISTORY;
	
	if (nonce_head + offset < mip6_nonce)
		return (-1);

	nodekey_head = mip6_nodekey + (nonce_head - mip6_nonce);
	bcopy(&nodekey_head[offset], nodekey, sizeof(mip6_nodekey_t));

	return (0);
}

/*
 *	Check a Binding Update packet whether it is valid 
 */
int
mip6_is_valid_bu(ip6, ip6mu, ip6mulen, mopt, hoa_sa)
	struct ip6_hdr *ip6;
	struct ip6m_binding_update *ip6mu;
	int ip6mulen;
	struct mip6_mobility_options *mopt;
	struct sockaddr_in6 *hoa_sa;
{
	mip6_nonce_t home_nonce, careof_nonce;
	mip6_nodekey_t home_nodekey, coa_nodekey;
	mip6_home_cookie_t home_cookie;
	mip6_careof_cookie_t careof_cookie;
	u_int8_t key_bu[SHA1_RESULTLEN]; /* Stated as 'Kbu' in the spec */
	u_int8_t authdata[SHA1_RESULTLEN];
	u_int16_t cksum_backup;
	SHA1_CTX sha1_ctx;
	HMAC_CTX hmac_ctx;
	int restlen;

	/* Nonce index & Auth. data mobility options are required */
	if ((mopt->valid_options & (MOPT_NONCE_IDX | MOPT_AUTHDATA)) == 0) {
		mip6log((LOG_ERR,
			 "%s:%d: Nonce or Authdata is missed. (%02x)\n",
			 __FILE__, __LINE__, mopt->valid_options));
		return (EINVAL);
	}
#if RR_DBG
printf("CN: Home   Nonce IDX: %d\n", mopt->mopt_ho_nonce_idx);
printf("CN: Careof Nonce IDX: %d\n", mopt->mopt_co_nonce_idx);
#endif
	if ((mip6_get_nonce(mopt->mopt_ho_nonce_idx, &home_nonce) != 0) ||
	    (mip6_get_nonce(mopt->mopt_co_nonce_idx, &careof_nonce) != 0)) {
		mip6log((LOG_ERR,
			 "%s:%d: home or care-of Nonce cannot be acquired.\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}
#if RR_DBG
printf("CN: Home   Nonce: %*D\n", sizeof(home_nonce), &home_nonce, ":");
printf("CN: Careof Nonce: %*D\n", sizeof(careof_nonce), &careof_nonce, ":");
#endif

	if ((mip6_get_nodekey(mopt->mopt_ho_nonce_idx, &home_nodekey) != 0) ||
	    (mip6_get_nodekey(mopt->mopt_co_nonce_idx, &coa_nodekey) != 0)) {
		mip6log((LOG_ERR,
			 "%s:%d: home or care-of node key cannot be acquired.\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}
#if RR_DBG
printf("CN: Home   Nodekey: %*D\n", sizeof(home_nodekey), &home_nodekey, ":");
printf("CN: Careof Nodekey: %*D\n", sizeof(coa_nodekey), &coa_nodekey, ":");
#endif

	/* Calculate home cookie */
	mip6_create_cookie(&ip6mu->ip6mu_addr,
			   &home_nodekey, &home_nonce, home_cookie);
#if RR_DBG
printf("CN: Home Cookie: %*D\n", sizeof(home_cookie), (u_int8_t *)&home_cookie, ":");
#endif

	/* Calculate care-of cookie */
	mip6_create_cookie(&ip6->ip6_src, 
			   &coa_nodekey, &careof_nonce, careof_cookie);
#if RR_DBG
printf("CN: Care-of Cookie: %*D\n", sizeof(careof_cookie), (u_int8_t *)&careof_cookie, ":");
#endif

	/* Calculate K_bu */
	SHA1Init(&sha1_ctx);
	SHA1Update(&sha1_ctx, (caddr_t)home_cookie, sizeof(home_cookie));
	SHA1Update(&sha1_ctx, (caddr_t)careof_cookie, sizeof(careof_cookie));
	SHA1Final(key_bu, &sha1_ctx);
#if RR_DBG
printf("CN: K_bu: %*D\n", sizeof(key_bu), key_bu, ":");
#endif

	cksum_backup = ip6mu->ip6mu_cksum;
	ip6mu->ip6mu_cksum = 0;
	/* Calculate authenticator */
	hmac_init(&hmac_ctx, key_bu, sizeof(key_bu), HMAC_SHA1);
	hmac_loop(&hmac_ctx, (u_int8_t *)&ip6->ip6_src,
		  sizeof(ip6->ip6_src));
#if RR_DBG
printf("CN: Auth: %*D\n", sizeof(ip6->ip6_src), &ip6->ip6_src, ":");
#endif
	hmac_loop(&hmac_ctx, (u_int8_t *)&ip6->ip6_dst,
		  sizeof(ip6->ip6_dst));
#if RR_DBG
printf("CN: Auth: %*D\n", sizeof(ip6->ip6_dst), &ip6->ip6_dst, ":");
#endif
	hmac_loop(&hmac_ctx, (u_int8_t *)ip6mu,
		  (u_int8_t *)mopt->mopt_auth - (u_int8_t *)ip6mu);
#if RR_DBG
printf("CN: Auth: %*D\n", (u_int8_t *)mopt->mopt_auth - (u_int8_t *)ip6mu, ip6mu, ":");
#endif
	restlen = ip6mulen - (((u_int8_t *)mopt->mopt_auth - (u_int8_t *)ip6mu) + ((struct ip6m_opt_authdata *)mopt->mopt_auth)->ip6moau_len);
	if (restlen > 0) {
	    hmac_loop(&hmac_ctx,
		      mopt->mopt_auth
		      + ((struct ip6m_opt_authdata *)mopt->mopt_auth)->ip6moau_len, restlen); 
#if RR_DBG
printf("CN: Auth: %*D\n", restlen, mopt->mopt_auth + ((struct ip6m_opt_authdata *)mopt->mopt_auth)->ip6moau_len, ":");
#endif
	}
	bzero(authdata, sizeof(authdata));
	hmac_result(&hmac_ctx, authdata);
#if RR_DBG
printf("CN: Auth Data: %*D\n", sizeof(authdata), authdata, ":");
#endif
	ip6mu->ip6mu_cksum = cksum_backup;

	return (bcmp(mopt->mopt_auth + 2, authdata, sizeof(authdata)));
}

int
mip6_get_mobility_options(ip6mu, ip6mulen, mopt)
	struct ip6m_binding_update *ip6mu;
	int ip6mulen;
	struct mip6_mobility_options *mopt;
{
	u_int8_t *mh, *mhend;
	u_int16_t valid_option;

	mh = (caddr_t)(ip6mu + 1);
	mhend = (caddr_t)(ip6mu) + ip6mulen;
	mopt->valid_options = 0;

#define check_mopt_len(mopt_len)	\
	if (*(mh + 1) != mopt_len) break;
  
	while (mh < mhend) {
		valid_option = 0;
		switch (*mh) {
			case IP6MOPT_PAD1:
				mh++;
				continue;
			case IP6MOPT_PADN:
				break;
			case IP6MOPT_UID:
				check_mopt_len(4);
				valid_option = MOPT_UID;
				GET_NETVAL_S(mh + 2, mopt->mopt_uid);
				break;
			case IP6MOPT_ALTCOA:
				check_mopt_len(18);
				valid_option = MOPT_ALTCOA;
				bcopy(mh + 2, &mopt->mopt_altcoa,
				      sizeof(mopt->mopt_altcoa));
				break;
			case IP6MOPT_NONCE:
				check_mopt_len(6);
				valid_option = MOPT_NONCE_IDX;
				GET_NETVAL_S(mh + 2, mopt->mopt_ho_nonce_idx);
				GET_NETVAL_S(mh + 4, mopt->mopt_co_nonce_idx);
				break;
			case IP6MOPT_AUTHDATA:
				valid_option = MOPT_AUTHDATA;
				mopt->mopt_auth = mh;
				break;
			default:
				/*	'... MUST quietly ignore ... (6.2.1)'
				mip6log((LOG_ERR,
					 "%s:%d: invalid mobility option (%02x). \n",
				 __FILE__, __LINE__, *mh));
				 */
				break;
		}
		
		mh += *(mh + 1);
		mopt->valid_options |= valid_option;
	}

#undef check_mopt_len
	
	return (0);
}

void
mip6_create_cookie(addr, nodekey, nonce, cookie)
	struct in6_addr *addr;
	mip6_nodekey_t *nodekey;
	mip6_nonce_t *nonce;
	void *cookie;
{
	/* Generatie cookie */
	/* cookie = MAC_Kcn(saddr | nonce) */
	HMAC_CTX hmac_ctx;
	
	hmac_init(&hmac_ctx, (u_int8_t *)nodekey,
		  sizeof(mip6_nodekey_t), HMAC_SHA1);
	hmac_loop(&hmac_ctx, (u_int8_t *)addr, sizeof(struct in6_addr));
	hmac_loop(&hmac_ctx, (u_int8_t *)nonce, sizeof(mip6_nonce_t));
	hmac_result(&hmac_ctx, (u_int8_t *)cookie);
}
#endif /* MIP6_DRAFT17 */
