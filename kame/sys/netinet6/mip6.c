/*	$KAME: mip6.c,v 1.204 2003/04/03 04:44:15 keiichi Exp $	*/

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

#define HMACSIZE 16

#ifdef __NetBSD__
#define HAVE_SHA1
#endif

/*#define RR_DBG*/

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
#define MIP6_CONFIG_BC_LIFETIME_LIMIT 420
#endif /* !MIP6_CONFIG_BC_LIFETIME_LIMIT */

#ifndef MIP6_CONFIG_HRBC_LIFETIME_LIMIT
#define MIP6_CONFIG_HRBC_LIFETIME_LIMIT 420
#endif /* !MIP6_CONFIG_HRBC_LIFETIME_LIMIT */

#ifndef MIP6_CONFIG_BU_MAXLIFETIME
#define MIP6_CONFIG_BU_MAXLIFETIME 420
#endif /* !MIP6_CONFIG_BU_MAXLIFETIME */

#ifndef MIP6_CONFIG_HRBU_MAXLIFETIME
#define MIP6_CONFIG_HRBU_MAXLIFETIME 420
#endif /* !MIP6_CONFIG_HRBU_MAXLIFETIME */

#if 1 /* #ifndef MIP6_CONFIG_BU_USE_SINGLE */
#define MIP6_CONFIG_BU_USE_SINGLE 1
#else
#define MIP6_CONFIG_BU_USE_SINGLE 0
#endif /* !MIP6_CONFIG_BU_USE_SINGLE */

#define NONCE_UPDATE_PERIOD	(MIP6_COOKIE_MAX_LIFE / MIP6_NONCE_HISTORY)

extern struct mip6_subnet_list mip6_subnet_list;
extern struct mip6_prefix_list mip6_prefix_list;

extern struct mip6_bc_list mip6_bc_list;

extern struct mip6_unuse_hoa_list mip6_unuse_hoa;

struct mip6_config mip6_config;

struct mip6stat mip6stat;

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

mip6_nonce_t mip6_nonce[MIP6_NONCE_HISTORY];
mip6_nodekey_t mip6_nodekey[MIP6_NONCE_HISTORY];	/* this is described as 'Kcn' in the spec */
u_int16_t nonce_index;		/* the idx value pointed by nonce_head */
mip6_nonce_t *nonce_head;	/* Current position of nonce on the array mip6_nonce */
#ifdef __NetBSD__
struct callout mip6_nonce_upd_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_nonce_upd_ch;
#endif

static int mip6_prelist_update_sub(struct hif_softc *, struct sockaddr_in6 *,
    union nd_opts *, struct nd_defrouter *, struct mbuf *);
static int mip6_register_current_location(void);
static int mip6_haddr_config(struct hif_softc *);
static int mip6_attach_haddrs(struct hif_softc *);
static int mip6_detach_haddrs(struct hif_softc *);
static int mip6_add_haddrs(struct hif_softc *, struct ifnet *);
static int mip6_remove_haddrs(struct hif_softc *, struct ifnet *);
static int mip6_remove_addr(struct ifnet *, struct in6_ifaddr *);
static void mip6_create_nonce(mip6_nonce_t *);
static void mip6_create_nodekey(mip6_nodekey_t *);
static void mip6_update_nonce_nodekey(void *);

/* ipv6 header manipuration functions. */
static int mip6_rthdr_create_withdst(struct ip6_rthdr **,
    struct sockaddr_in6 *, struct ip6_pktopts *);
static int mip6_haddr_destopt_create(struct ip6_dest **,
    struct sockaddr_in6 *, struct sockaddr_in6 *, struct hif_softc *);

/* used for the return routability procedure. */
/* This macro will be deleted after release of MIP6 */
#ifdef RR_DBG
	extern void ipsec_hexdump __P((caddr_t, int));
#define mip6_hexdump(m,l,a)					\
		do {						\
			printf("%s", (m));			\
			ipsec_hexdump((caddr_t)(a),(l));	\
			printf("\n");				\
		} while (/*CONSTCOND*/ 0)
#else
#define mip6_hexdump(m,l,a)
#endif
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

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&mip6_pfx_ch, NULL);
#elif defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_init(&mip6_pfx_ch);
#endif

	mip6_bu_init(); /* binding update routine initialize */
	mip6_ha_init(); /* homeagent list management initialize */
	mip6_bc_init(); /* binding cache routine initailize */
	mip6_prefix_init();
	mip6_subnet_init();

	LIST_INIT(&mip6_subnet_list);
	LIST_INIT(&mip6_unuse_hoa);

	/* Initialize nonce, key, and something else for CN */
	nonce_head = mip6_nonce;
	nonce_index = 0;
	mip6_create_nonce(mip6_nonce);
	mip6_create_nodekey(mip6_nodekey);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&mip6_nonce_upd_ch, NULL);
	callout_reset(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD,
		      mip6_update_nonce_nodekey, NULL);
#elif defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_init(&mip6_nonce_upd_ch);
	callout_reset(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD,
		      mip6_update_nonce_nodekey, NULL);
#elif defined(__OpenBSD__)
	/* XXX */
#else
	timeout(mip6_update_nonce_nodekey, (caddr_t)0,
		hz * NONCE_UPDATE_PERIOD);
#endif
}

/*
 * we have heard a new router advertisement.  process if it contains
 * prefix information options for updating prefix and home agent
 * lists.
 */
int
mip6_prelist_update(saddr, ndopts, dr, m)
	struct sockaddr_in6 *saddr; /* the addr that sent this RA. */
	union nd_opts *ndopts;
	struct nd_defrouter *dr; /* NULL in case of a router shutdown. */
	struct mbuf *m; /* the received router adv. packet. */
{
	struct mip6_ha *mha;
	struct hif_softc *sc;
	int error = 0;

	/* sanity check. */
	if (saddr == NULL)
		return (EINVAL);

	/* advertizing router is shutting down. */
	if (dr == NULL) {
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, saddr);
		if (mha) {
			error = mip6_ha_list_remove(&mip6_ha_list, mha);
		}
		return (error);
	}

	/* if no prefix information is included, we have nothing to do. */
	if ((ndopts == NULL) || (ndopts->nd_opts_pi == NULL)) {
		return (0);
	}

	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		/* reorganize subnet groups. */
		error = mip6_prelist_update_sub(sc, saddr, ndopts, dr, m);
		if (error) {
			mip6log((LOG_ERR,
			    "%s:%d: failed to reorganize subnet groups.\n",
			    __FILE__, __LINE__));
			return (error);
		}
	}

	return (0);
}

int
mip6_prelist_update_sub(sc, rtaddr, ndopts, dr, m)
	struct hif_softc *sc;
	struct sockaddr_in6 *rtaddr;
	union nd_opts *ndopts;
	struct nd_defrouter *dr;
	struct mbuf *m;
{
	int location;
	struct nd_opt_hdr *ndopt;
	struct nd_opt_prefix_info *ndopt_pi;
	struct sockaddr_in6 prefix_sa;
	struct hif_subnet *hs;
	int is_home;
	int mha_is_new, mpfx_is_new;
	struct mip6_ha *mha;
	struct mip6_prefix tmpmpfx, *mpfx;
	struct mip6_subnet_prefix *mspfx = NULL;
	struct mip6_subnet_ha *msha = NULL;
	struct mip6_subnet *ms = NULL;
	int error = 0;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	/* sanity check. */
	if ((sc == NULL) || (rtaddr == NULL) || (dr == NULL)
	    || (ndopts == NULL) || (ndopts->nd_opts_pi == NULL))
		return (EINVAL);

	/* a router advertisement must be sent from a link-local address. */
	if (!IN6_IS_ADDR_LINKLOCAL(&rtaddr->sin6_addr)) {
		mip6log((LOG_NOTICE,
		    "%s:%d: the source address of a router advertisement "
		    "is not a link-local address(%s).\n",
		    __FILE__, __LINE__, ip6_sprintf(&rtaddr->sin6_addr)));
		    /* ignore. */
		    return (0);
	}

	location = HIF_LOCATION_UNKNOWN;
	is_home = 0;

	for (ndopt = (struct nd_opt_hdr *)ndopts->nd_opts_pi;
	     ndopt <= (struct nd_opt_hdr *)ndopts->nd_opts_pi_end;
	     ndopt = (struct nd_opt_hdr *)((caddr_t)ndopt
		 + (ndopt->nd_opt_len << 3))) {
		if (ndopt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
			continue;
		ndopt_pi = (struct nd_opt_prefix_info *)ndopt;

		/* sanity check of prefix information. */
		if (ndopt_pi->nd_opt_pi_len != 4) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid option "
			    "len %d for prefix information option, "
			    "ignored\n", ndopt_pi->nd_opt_pi_len));
		}
		if (128 < ndopt_pi->nd_opt_pi_prefix_len) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid prefix "
			    "len %d for prefix information option, "
			    "ignored\n", ndopt_pi->nd_opt_pi_prefix_len));
			continue;
		}
		if (IN6_IS_ADDR_MULTICAST(&ndopt_pi->nd_opt_pi_prefix)
		    || IN6_IS_ADDR_LINKLOCAL(&ndopt_pi->nd_opt_pi_prefix)) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid prefix "
			    "%s, ignored\n",
			    ip6_sprintf(&ndopt_pi->nd_opt_pi_prefix)));
			continue;
		}
		/* aggregatable unicast address, rfc2374 */
		if ((ndopt_pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) == 0x20
		    && ndopt_pi->nd_opt_pi_prefix_len != 64) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid prefixlen "
			    "%d for rfc2374 prefix %s, ignored\n",
			    ndopt_pi->nd_opt_pi_prefix_len,
			    ip6_sprintf(&ndopt_pi->nd_opt_pi_prefix)));
			continue;
		}

		bzero(&prefix_sa, sizeof(prefix_sa));
		prefix_sa.sin6_family = AF_INET6;
		prefix_sa.sin6_len = sizeof(prefix_sa);
		prefix_sa.sin6_addr = ndopt_pi->nd_opt_pi_prefix;
		hs = hif_subnet_list_find_withprefix(&sc->hif_hs_list_home,
		    &prefix_sa, ndopt_pi->nd_opt_pi_prefix_len);
		if (hs != NULL)
			is_home++;
	}

	/* check is the router is on our home agent list. */
	hs = hif_subnet_list_find_withhaaddr(&sc->hif_hs_list_home, rtaddr);

	if ((is_home != 0) || (hs != NULL)) {
		/* we are home. */
		location = HIF_LOCATION_HOME;
	} else {
		/* we are foreign. */
		location = HIF_LOCATION_FOREIGN;
	}

	for (ndopt = (struct nd_opt_hdr *)ndopts->nd_opts_pi;
	     ndopt <= (struct nd_opt_hdr *)ndopts->nd_opts_pi_end;
	     ndopt = (struct nd_opt_hdr *)((caddr_t)ndopt
		 + (ndopt->nd_opt_len << 3))) {
		if (ndopt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
			continue;
		ndopt_pi = (struct nd_opt_prefix_info *)ndopt;

#if 0 /* we can skip these checks because we have already done above. */
		/* sanity check of prefix information. */
		if (ndopt_pi->nd_opt_pi_len != 4) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid option "
			    "len %d for prefix information option, "
			    "ignored\n", ndopt_pi->nd_opt_pi_len));
		}
		if (128 < ndopt_pi->nd_opt_pi_prefix_len) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid prefix "
			    "len %d for prefix information option, "
			    "ignored\n", ndopt_pi->nd_opt_pi_prefix_len));
			continue;
		}
		if (IN6_IS_ADDR_MULTICAST(&ndopt_pi->nd_opt_pi_prefix)
		    || IN6_IS_ADDR_LINKLOCAL(&ndopt_pi->nd_opt_pi_prefix)) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid prefix "
			    "%s, ignored\n",
			    ip6_sprintf(&ndopt_pi->nd_opt_pi_prefix)));
			continue;
		}
		/* aggregatable unicast address, rfc2374 */
		if ((ndopt_pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) == 0x20
		    && ndopt_pi->nd_opt_pi_prefix_len != 64) {
			nd6log((LOG_INFO,
			    "nd6_ra_input: invalid prefixlen "
			    "%d for rfc2374 prefix %s, ignored\n",
			    ndopt_pi->nd_opt_pi_prefix_len,
			    ip6_sprintf(&ndopt_pi->nd_opt_pi_prefix)));
			continue;
		}
#endif

		bzero(&prefix_sa, sizeof(prefix_sa));
		prefix_sa.sin6_family = AF_INET6;
		prefix_sa.sin6_len = sizeof(prefix_sa);
		prefix_sa.sin6_addr = ndopt_pi->nd_opt_pi_prefix;

		/* update mip6_prefix_list. */
		bzero(&tmpmpfx, sizeof(tmpmpfx));
		tmpmpfx.mpfx_prefix.sin6_family = AF_INET6;
		tmpmpfx.mpfx_prefix.sin6_len = sizeof(tmpmpfx.mpfx_prefix);
		tmpmpfx.mpfx_prefix.sin6_addr = ndopt_pi->nd_opt_pi_prefix;
		tmpmpfx.mpfx_prefixlen = ndopt_pi->nd_opt_pi_prefix_len;
		tmpmpfx.mpfx_vltime = ntohl(ndopt_pi->nd_opt_pi_valid_time);
		tmpmpfx.mpfx_pltime = ntohl(ndopt_pi->nd_opt_pi_preferred_time);
		mpfx_is_new = 0;
		mpfx = mip6_prefix_list_find(&tmpmpfx);
		if (mpfx) {
			/* found an existing entry.  just update it. */
			mpfx->mpfx_vltime = tmpmpfx.mpfx_vltime;
			mpfx->mpfx_vlexpire = time_second + mpfx->mpfx_vltime;
			mpfx->mpfx_pltime = tmpmpfx.mpfx_pltime;
			mpfx->mpfx_plexpire = time_second + mpfx->mpfx_pltime;
			/* XXX mpfx->mpfx_haddr; */
		} else {
			/* this is a new prefix. */
			mpfx = mip6_prefix_create(&tmpmpfx.mpfx_prefix,
			    tmpmpfx.mpfx_prefixlen,
			    tmpmpfx.mpfx_vltime,
			    tmpmpfx.mpfx_pltime);
			if (mpfx == NULL) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "mip6_prefix memory allocation failed.\n",
				    __FILE__, __LINE__));
				goto skip_prefix_update;
			}
			error = mip6_prefix_list_insert(&mip6_prefix_list,
			    mpfx);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "mip6_prefix_insert_failed(%d).\n",
				    __FILE__, __LINE__, error));
				goto skip_prefix_update;
			}

			mpfx_is_new = 1;
			mip6log((LOG_INFO,
			    "%s:%d: receive a new prefix %s\n",
			    __FILE__, __LINE__,
			    ip6_sprintf(&ndopt_pi->nd_opt_pi_prefix)));
		}
	skip_prefix_update:

		/* create mip6_subnet_prefix if mpfx is newly created. */
		if (mpfx_is_new) {
			mspfx = mip6_subnet_prefix_create(mpfx);
			if (mspfx == NULL) {
				(void)mip6_prefix_list_remove(
				    &mip6_prefix_list, mpfx);
				mpfx_is_new = 0;
				mip6log((LOG_ERR,
				    "%s:%d: mip6_subnet_prefix "
				    "memory allocation failed.\n",
				    __FILE__, __LINE__));
				/* continue, anyway. */
			}
		}

		/* update mip6_ha_list. */
		mha_is_new = 0;
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, rtaddr);
		if (mha) {
			/* the entry for rtaddr exists.  update information. */
			if (ndopt_pi->nd_opt_pi_flags_reserved
			    & ND_OPT_PI_FLAG_ROUTER) {
				/*
				 * if prefix information has a router flag,
				 * that entry includes a global address
				 * of a home agent.
				 */
				mha->mha_gaddr = tmpmpfx.mpfx_prefix;
			}
			mha->mha_flags = dr->flags;
		} else {
			/* this is a new ha or a router. */
			mha = mip6_ha_create(rtaddr,
			    (ndopt_pi->nd_opt_pi_flags_reserved
			    & ND_OPT_PI_FLAG_ROUTER)
			    ? &tmpmpfx.mpfx_prefix : NULL,
			    dr->flags, 0, dr->rtlifetime);
			if (mha == NULL) {
				mip6log((LOG_ERR,
				    "%s:%d mip6_ha memory allcation failed.\n",
				    __FILE__, __LINE__));
				goto skip_ha_update;
			}
			error = mip6_ha_list_insert(&mip6_ha_list, mha);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d "
				    "mip6_ha_list_insert failed(%d).\n",
				    __FILE__, __LINE__, error));
				goto skip_ha_update;
			}

			mha_is_new = 1;
			mip6log((LOG_INFO,
			    "%s:%d: found a new router %s(%s)\n",
			    __FILE__, __LINE__,
			    ip6_sprintf(&rtaddr->sin6_addr),
			    ip6_sprintf(&tmpmpfx.mpfx_prefix.sin6_addr)));
		}
	skip_ha_update:

		/* create mip6_subnet_ha if mha is newly created. */
		if (mha_is_new) {
			msha = mip6_subnet_ha_create(mha);
			if (msha == NULL) {
				(void)mip6_ha_list_remove(&mip6_ha_list, mha);
				mha_is_new = 0;
				mip6log((LOG_ERR,
				    "%s:%d: mip6_subnet_ha "
				    "memory allocation failed.\n",
				    __FILE__, __LINE__));
				/* continue, anyway. */
			}
		}

		/*
		 * there is an mip6_subnet which has a mha advertising
		 * this ndpr.  we add newly created mip6_prefix
		 * (mip6_subnet_prefix) to that mip6_subnet.
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
		 * there is an mip6_subnet which has a mpfx advertised
		 * by this ndpr.  we add newly created mip6_ha
		 * (mip6_subnet_ha) to that mip6_subnet.
		 */
		if ((mpfx_is_new == 0) && mha_is_new) {
			ms = mip6_subnet_list_find_withprefix(&mip6_subnet_list,
			    &tmpmpfx.mpfx_prefix, tmpmpfx.mpfx_prefixlen);
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
		 * we have no mip6_subnet which has a prefix or ha
		 * advertised by this ndpr.  so, we create a new
		 * mip6_subnet.
		 */
		if (mpfx_is_new && mha_is_new) {
			ms = mip6_subnet_create();
			if (ms == NULL) {
				mip6log((LOG_ERR,
				    "%s:%d: mip6_subnet memory allcation "
				    "failed.\n",
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

			/*
			 * add this newly created mip6_subnet to
			 * hif_subnet_list.
			 */
			hs = hif_subnet_create(ms);
			if (hs == NULL) {
				mip6log((LOG_ERR,
				    "%s:%d: hif_subnet memory allocation "
				    "failed.\n",
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
	}
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
		 * from physical i/f to avoid the duplication of
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

	/* sanity check */
	if (LIST_EMPTY(&mip6_prefix_list))
		return (ENOENT);

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
	int i = 0, purgeprefix = 0;
	struct nd_prefixctl pr0;
	struct nd_prefix *pr = NULL;

	bcopy(if_name(ifp), ifra.ifra_name, sizeof(ifra.ifra_name));
	bcopy(&ia6->ia_addr, &ifra.ifra_addr, sizeof(struct sockaddr_in6));
	bcopy(&ia6->ia_prefixmask, &ifra.ifra_prefixmask,
	      sizeof(struct sockaddr_in6));

	/* address purging code is copyed from in6_control(). */

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
	pr0.ndpr_plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL);
	if (pr0.ndpr_plen == 128)
		goto purgeaddr;
	pr0.ndpr_prefix = ia6->ia_addr;
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

	return (0);
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
				mip6_bu_list_remove_all(&sc->hif_bu_list, 1);
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

	case SIOCDBC:
		if (SA6_IS_ADDR_UNSPECIFIED(&mr->mip6r_ru.mip6r_sin6)) {
			struct mip6_bc *mbc;

			/* remove all binding cache entries. */
			while ((mbc = LIST_FIRST(&mip6_bc_list)) != NULL) {
				(void)mip6_bc_list_remove(&mip6_bc_list, mbc);
			}
		} else {
			struct mip6_bc *mbc;

			/* remove a specified binding cache entry. */
			mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, 
			    &mr->mip6r_ru.mip6r_sin6);
			if (mbc != NULL) {
				(void)mip6_bc_list_remove(&mip6_bc_list, mbc);
			}
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

			MALLOC(uh, struct mip6_unuse_hoa *,
			       sizeof(struct mip6_unuse_hoa), M_IP6OPT, M_WAIT);
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
					FREE(uh, M_IP6OPT);
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
		if (mip6_process_movement()) {
			mip6log((LOG_WARNING,
			    "%s:%d: mip6_process_movement failed.\n",
			    __FILE__, __LINE__));
				/* ignore this error... */
		}
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
	struct sockaddr_in6 src;
	struct sockaddr_in6 dst;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	int s, error = 0, need_hao = 0;

	mip6opt->mip6po_rthdr2 = NULL;
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
	 * HoT messages must be delivered via a home agent even when
	 * we have a valid binding cache entry for the mobile node who
	 * have sent the corresponding HoTI message.
	 */
	/*
	 * 6.1.6 Care-of Test (CoT) Message
	 * The CoT message is always sent with the Destnation Address set to
	 * the care-of address of the mobile node; it is sent directly to the
	 * mobile node.
	 *
	 * when a mobile node is on its home link and send CoTI (this
	 * situation happens if the mobile node want to remove the
	 * binding cache entry created on the correspondent node), the
	 * source address of CoTI and the home address are same.
	 */
	if ((opt != NULL) &&
	    (opt->ip6po_mobility != NULL)) {
		if (opt->ip6po_mobility->ip6m_type == IP6M_HOME_TEST ||
		    opt->ip6po_mobility->ip6m_type == IP6M_CAREOF_TEST)
			goto skip_rthdr2;
	}

	/*
	 * create rthdr2 only if the caller of ip6_output() doesn't
	 * specify rthdr2 adready.
	 */
	if ((opt != NULL) &&
	    (opt->ip6po_rthdr2 != NULL))
		goto skip_rthdr2;

	/*
	 * add the routing header for the route optimization if there
	 * exists a valid binding cache entry for this destination
	 * node.
	 */
	error = mip6_rthdr_create_withdst(&mip6opt->mip6po_rthdr2, &dst, opt);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: rthdr creation failed.\n",
		    __FILE__, __LINE__));
		goto bad;
	}
 skip_rthdr2:

	/* the following stuff is applied only for a mobile node. */
	if (!MIP6_IS_MN) {
		goto noneed;
	}

	/*
	 * find hif that has a home address that is the same
	 * to the source address of this sending ip packet
	 */
	sc = hif_list_find_withhaddr(&src);
	if (sc == NULL) {
		/*
		 * this source addrss is not one of our home addresses.
		 * we don't need any special care about this packet.
		 */
		goto noneed;
	}

	/* check registration status */
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &dst, &src);
	if (mbu == NULL) {
		/* no registration action started yet. */
		goto noneed;
	}

	if (opt && opt->ip6po_mobility != NULL) {
		if (opt->ip6po_mobility->ip6m_type == IP6M_BINDING_UPDATE)
			need_hao = 1;
		if (opt->ip6po_mobility->ip6m_type == IP6M_HOME_TEST_INIT ||
		    opt->ip6po_mobility->ip6m_type == IP6M_CAREOF_TEST_INIT)
			goto noneed;
	}
	if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
		/* to my home agent. */
		if (!need_hao &&
		    (mbu->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_IDLE ||
		     mbu->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_WAITD))
			goto noneed;
	} else {
		/* to any of correspondent nodes. */
		if (!need_hao && !MIP6_IS_BU_BOUND_STATE(mbu))
			goto noneed;
	}
	/* create haddr destopt. */
	error = mip6_haddr_destopt_create(&mip6opt->mip6po_haddr,
					  &src, &dst, sc);
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
	MALLOC(rthdr2, struct ip6_rthdr2 *, len, M_IP6OPT, M_NOWAIT);
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

	mip6stat.mip6s_orthdr2++;

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

	MALLOC(optbuf.buf, u_int8_t *, MIP6_BUFFER_SIZE, M_IP6OPT, M_NOWAIT);
	if (optbuf.buf == NULL) {
		return (ENOMEM);
	}
	bzero((caddr_t)optbuf.buf, MIP6_BUFFER_SIZE);
	optbuf.off = 2;

	/* Add Home Address option */
	mip6_add_opt2dh((u_int8_t *)&haddr_opt, &optbuf);
	mip6_align_destopt(&optbuf);

	*pktopt_haddr = (struct ip6_dest *)optbuf.buf;

	mip6stat.mip6s_ohao++;

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
	MALLOC(optbuf.buf, u_int8_t *, MIP6_BUFFER_SIZE, M_IP6OPT, M_NOWAIT);
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
		FREE(*pktopt_mip6dest2, M_IP6OPT);
	*pktopt_mip6dest2 = (struct ip6_dest *)optbuf.buf;

	return (error);
}
#endif /* MIP6XXX */

void
mip6_destopt_discard(mip6opt)
	struct mip6_pktopts *mip6opt;
{
	if (mip6opt->mip6po_rthdr2)
		FREE(mip6opt->mip6po_rthdr2, M_IP6OPT);

	if (mip6opt->mip6po_haddr)
		FREE(mip6opt->mip6po_haddr, M_IP6OPT);

	if (mip6opt->mip6po_dest2)
		FREE(mip6opt->mip6po_dest2, M_IP6OPT);

	if (mip6opt->mip6po_mobility)
		FREE(mip6opt->mip6po_mobility, M_IP6OPT);

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
	struct m_tag *n;

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
		ip6a = (struct ip6aux *) (n + 1);
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

/* This function should be called periodically */
static void
mip6_update_nonce_nodekey(ignored_arg)
	void	*ignored_arg;
{
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD,
		      mip6_update_nonce_nodekey, NULL);
#elif defined(__OpenBSD__)
	/* XXX */
#else
	timeout(mip6_update_nonce_nodekey, (caddr_t)0,
		hz * NONCE_UPDATE_PERIOD);
#endif

	nonce_index++;
	if (++nonce_head >= mip6_nonce + MIP6_NONCE_HISTORY)
		nonce_head = mip6_nonce;

	mip6_create_nonce(nonce_head);
	mip6_create_nodekey(mip6_nodekey + (nonce_head - mip6_nonce));

	splx(s);
}

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
mip6_is_valid_bu(ip6, ip6mu, ip6mulen, mopt, hoa_sa, coa_sa, cache_req, status)
	struct ip6_hdr *ip6;
	struct ip6m_binding_update *ip6mu;
	int ip6mulen;
	struct mip6_mobility_options *mopt;
	struct sockaddr_in6 *hoa_sa, *coa_sa;
	int cache_req;	/* true if this request is cacheing */
	u_int8_t *status;
{
	u_int8_t key_bm[MIP6_KBM_LEN]; /* Stated as 'Kbm' in the spec */
	u_int8_t authdata[SHA1_RESULTLEN];
	u_int16_t cksum_backup;

	*status = IP6MA_STATUS_ACCEPTED;
	/* Nonce index & Auth. data mobility options are required */
	if ((mopt->valid_options & (MOPT_NONCE_IDX | MOPT_AUTHDATA)) 
	     != (MOPT_NONCE_IDX | MOPT_AUTHDATA)) {
		mip6log((LOG_ERR,
			 "%s:%d: Nonce or Authdata is missed. (%02x)\n",
			 __FILE__, __LINE__, mopt->valid_options));
		return (EINVAL);
	}
	if ((*status = mip6_calculate_kbm_from_index(hoa_sa, coa_sa, mopt->mopt_ho_nonce_idx, 
			mopt->mopt_co_nonce_idx, !cache_req, key_bm))) {
		return (EINVAL);
	}

	cksum_backup = ip6mu->ip6mu_cksum;
	ip6mu->ip6mu_cksum = 0;
	/* Calculate authenticator */
	mip6_calculate_authenticator(key_bm, authdata,
		&coa_sa->sin6_addr, &ip6->ip6_dst,
		(caddr_t)ip6mu, ip6mulen, 
		(u_int8_t *)mopt->mopt_auth + sizeof(struct ip6m_opt_authdata)
			 - (u_int8_t *)ip6mu, 
		MOPT_AUTH_LEN(mopt) + 2);

	ip6mu->ip6mu_cksum = cksum_backup;

	return (bcmp(mopt->mopt_auth + 2, authdata, MOPT_AUTH_LEN(mopt)));
}

int
mip6_get_mobility_options(ip6mh, hlen, ip6mhlen, mopt)
	struct ip6_mobility *ip6mh;
	int hlen, ip6mhlen;
	struct mip6_mobility_options *mopt;
{
	u_int8_t *mh, *mhend;
	u_int16_t valid_option;

	mh = (caddr_t)(ip6mh) + hlen;
	mhend = (caddr_t)(ip6mh) + ip6mhlen;
	mopt->valid_options = 0;

#define check_mopt_len(mopt_len)	\
	if (*(mh + 1) != mopt_len) goto bad;

	while (mh < mhend) {
		valid_option = 0;
		switch (*mh) {
			case IP6MOPT_PAD1:
				mh++;
				continue;
			case IP6MOPT_PADN:
				break;
			case IP6MOPT_ALTCOA:
				check_mopt_len(16);
				valid_option = MOPT_ALTCOA;
				bcopy(mh + 2, &mopt->mopt_altcoa,
				      sizeof(mopt->mopt_altcoa));
				break;
			case IP6MOPT_NONCE:
				check_mopt_len(4);
				valid_option = MOPT_NONCE_IDX;
				GET_NETVAL_S(mh + 2, mopt->mopt_ho_nonce_idx);
				GET_NETVAL_S(mh + 4, mopt->mopt_co_nonce_idx);
				break;
			case IP6MOPT_AUTHDATA:
				valid_option = MOPT_AUTHDATA;
				mopt->mopt_auth = mh;
				break;
			case IP6MOPT_REFRESH:
				check_mopt_len(2);
				valid_option = MOPT_REFRESH;
				GET_NETVAL_S(mh + 2, mopt->mopt_refresh);
				break;
			default:
				/*	'... MUST quietly ignore ... (6.2.1)'
				mip6log((LOG_ERR,
					 "%s:%d: invalid mobility option (%02x). \n",
				 __FILE__, __LINE__, *mh));
				 */
				break;
		}

		mh += *(mh + 1) + 2;
		mopt->valid_options |= valid_option;
	}

#undef check_mopt_len

	return (0);

 bad:
	return (EINVAL);
}

/* Generate keygen */
void
mip6_create_keygen_token(addr, nodekey, nonce, hc, token)
	struct in6_addr *addr;
	mip6_nodekey_t *nodekey;
	mip6_nonce_t *nonce;
	u_int8_t hc;
	void *token;		/* 64 bit */
{
	/* keygen token = HMAC_SHA1(Kcn, addr | nonce | hc) */
	HMAC_CTX hmac_ctx;
	u_int8_t result[HMACSIZE];

	hmac_init(&hmac_ctx, (u_int8_t *)nodekey,
		  sizeof(mip6_nodekey_t), HMAC_SHA1);
	hmac_loop(&hmac_ctx, (u_int8_t *)addr, sizeof(struct in6_addr));
	hmac_loop(&hmac_ctx, (u_int8_t *)nonce, sizeof(mip6_nonce_t));
	hmac_loop(&hmac_ctx, (u_int8_t *)&hc, sizeof(hc));
	hmac_result(&hmac_ctx, result);
	/* First64 */
	bcopy(result, token, 8);
}

/* For CN side function */
int
mip6_calculate_kbm_from_index(hoa_sa, coa_sa, ho_nonce_idx, co_nonce_idx, ignore_co_nonce, key_bm)
	struct sockaddr_in6 *hoa_sa;
	struct sockaddr_in6 *coa_sa;
	u_int16_t ho_nonce_idx;	/* Home Nonce Index */
	u_int16_t co_nonce_idx;	/* Care-of Nonce Index */
	int ignore_co_nonce;
	u_int8_t *key_bm;	/* needs at least MIP6_KBM_LEN bytes */
{
	mip6_nonce_t home_nonce, careof_nonce;
	mip6_nodekey_t home_nodekey, coa_nodekey;
	mip6_home_token_t home_token;
	mip6_careof_token_t careof_token;

	if (mip6_get_nonce(ho_nonce_idx, &home_nonce) != 0) {
		mip6log((LOG_ERR,
			 "%s:%d: Home Nonce cannot be acquired.\n",
			 __FILE__, __LINE__));
		return (IP6MA_STATUS_HOME_NONCE_EXPIRED);
	}
	if (mip6_get_nonce(co_nonce_idx, &careof_nonce) != 0) {
		mip6log((LOG_ERR,
			 "%s:%d: Care-of Nonce cannot be acquired.\n",
			 __FILE__, __LINE__));
		return (IP6MA_STATUS_CAREOF_NONCE_EXPIRED);
	}
	mip6_hexdump("CN: Home   Nonce: ", sizeof(home_nonce), &home_nonce);
	mip6_hexdump("CN: Careof Nonce: ", sizeof(careof_nonce), &careof_nonce);

	if ((mip6_get_nodekey(ho_nonce_idx, &home_nodekey) != 0) ||
	    (mip6_get_nodekey(co_nonce_idx, &coa_nodekey) != 0)) {
		mip6log((LOG_ERR,
			 "%s:%d: home or care-of node key cannot be acquired.\n",
			 __FILE__, __LINE__));
		return (IP6MA_STATUS_NONCE_EXPIRED);
	}
#ifdef RR_DBG
mip6_hexdump("CN: Home   Nodekey: ", sizeof(home_nodekey), &home_nodekey);
mip6_hexdump("CN: Careof Nodekey: ", sizeof(coa_nodekey), &coa_nodekey);
#endif

	/* Calculate home keygen token */
	mip6_create_keygen_token(&hoa_sa->sin6_addr,
			   &home_nodekey, &home_nonce, 0, &home_token);
#ifdef RR_DBG
mip6_hexdump("CN: Home keygen token: ", sizeof(home_token), (u_int8_t *)&home_token);
#endif

	if (!ignore_co_nonce) {
		/* Calculate care-of keygen token */
		mip6_create_keygen_token(&coa_sa->sin6_addr,
			   &coa_nodekey, &careof_nonce, 1, &careof_token);
#ifdef RR_DBG
mip6_hexdump("CN: Care-of keygen token: ", sizeof(careof_token), (u_int8_t *)&careof_token);
#endif
	}

	/* Calculate K_bm */
	mip6_calculate_kbm(&home_token,
			   ignore_co_nonce ? NULL : &careof_token, key_bm);
#ifdef RR_DBG
mip6_hexdump("CN: K_bm: ", sizeof(key_bm), key_bm);
#endif

	return (IP6MA_STATUS_ACCEPTED);
}

void
mip6_calculate_kbm(home_token, careof_token, key_bm)
	mip6_home_token_t *home_token;
	mip6_careof_token_t *careof_token;	/* could be null */
	u_int8_t *key_bm;	/* needs at least MIP6_KBM_LEN bytes */
{
	SHA1_CTX sha1_ctx;
	u_int8_t result[SHA1_RESULTLEN];

	SHA1Init(&sha1_ctx);
	SHA1Update(&sha1_ctx, (caddr_t)home_token, sizeof(*home_token));
	if (careof_token)
		SHA1Update(&sha1_ctx, (caddr_t)careof_token, sizeof(*careof_token));
	SHA1Final(result, &sha1_ctx);
	/* First 128 bit */
	bcopy(result, key_bm, MIP6_KBM_LEN);
}

/*
 *   <------------------ datalen ------------------->
 *                  <-- exclude_data_len ---> 
 *   ---------------+-----------------------+--------
 *   ^              <--                   -->
 *   data     The area excluded from calculation Auth.
 *   - - - - - - - ->
 *     exclude_offset
 */
void
mip6_calculate_authenticator(key_bm, result, addr1, addr2, data, datalen, exclude_offset, exclude_data_len)
	u_int8_t *key_bm;		/* Kbm */
	u_int8_t *result;
	struct in6_addr *addr1, *addr2;
	caddr_t data;
	size_t datalen;
	int exclude_offset;
	size_t exclude_data_len;
{
	HMAC_CTX hmac_ctx;
	int restlen;
	u_int8_t sha1_result[SHA1_RESULTLEN];

	/* Calculate authenticator (5.5.6) */
	/* MAC_Kbm(addr1, | addr2 | (BU|BA) ) */
	hmac_init(&hmac_ctx, key_bm, MIP6_KBM_LEN, HMAC_SHA1);
	hmac_loop(&hmac_ctx, (u_int8_t *)addr1, sizeof(*addr1));
	mip6_hexdump("Auth: ", sizeof(*addr1), addr1);
	hmac_loop(&hmac_ctx, (u_int8_t *)addr2, sizeof(*addr2));
	mip6_hexdump("MN: Auth: ", sizeof(*addr2), addr2);
	hmac_loop(&hmac_ctx, (u_int8_t *)data, exclude_offset);
	mip6_hexdump("MN: Auth: ", exclude_offset, data);

	/* Exclude authdata field in the mobility option to calculate authdata 
	   But it should be included padding area */
	restlen = datalen - (exclude_offset + exclude_data_len);
	if (restlen > 0) {
		hmac_loop(&hmac_ctx,
			  data + exclude_offset + exclude_data_len,
			  restlen);
		mip6_hexdump("MN: Auth: ", restlen, 
			data + exclude_offset + exclude_data_len);
	}
	hmac_result(&hmac_ctx, sha1_result);
	bcopy(sha1_result, result, MIP6_AUTHENTICATOR_LEN);
	mip6_hexdump("MN: Authdata: ", MIP6_AUTHENTICATOR_LEN, result);
}
