/*	$KAME: mip6_binding.c,v 1.37 2001/11/22 01:27:27 keiichi Exp $	*/

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

#include <net/if_hif.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>

#include <netinet6/mip6.h>

extern struct protosw mip6_tunnel_protosw;
extern struct mip6_prefix_list mip6_prefix_list;

struct mip6_bc_list mip6_bc_list;

#ifdef __NetBSD__
struct callout mip6_bu_ch = CALLOUT_INITIALIZER;
struct callout mip6_bc_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_bu_ch;
struct callout mip6_bc_ch;
#endif
static int mip6_bu_count = 0;
static int mip6_bc_count = 0;

#ifdef MIP6_DRAFT13
int mip6_use_ipsec = 0;
#endif

/* binding update functions. */
static int mip6_bu_list_remove __P((struct mip6_bu_list *, struct mip6_bu *));
static int mip6_bu_list_remove_all __P((struct mip6_bu_list *));
static int mip6_bu_list_notify_binding_change __P((struct hif_softc *));
static int mip6_bu_send_bu __P((struct mip6_bu *));
static void mip6_bu_timeout __P((void *));
static void mip6_bu_starttimer __P((void));
static void mip6_bu_stoptimer __P((void));
static int mip6_bu_encapcheck __P((const struct mbuf *, int, int, void *));

/* binding cache functions. */
#ifdef MIP6_DRAFT13
static struct mip6_bc *mip6_bc_create 
    __P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	 u_int8_t, u_int8_t, MIP6_SEQNO_T, u_int32_t, struct ifnet *));
#else
static struct mip6_bc *mip6_bc_create 
    __P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	 u_int8_t, MIP6_SEQNO_T, u_int32_t, struct ifnet *));
#endif /* MIP6_DRAFT13 */
static int mip6_bc_list_insert __P((struct mip6_bc_list *, struct mip6_bc *));
static int mip6_bc_send_ba __P((struct in6_addr *, struct in6_addr *,
				struct in6_addr *, u_int8_t, MIP6_SEQNO_T,
				u_int32_t, u_int32_t));
static int mip6_bc_proxy_control __P((struct in6_addr *, struct in6_addr *,
				      int));
static void mip6_bc_timeout __P((void *));
static void mip6_bc_starttimer __P((void));
static void mip6_bc_stoptimer __P((void));
static int mip6_bc_encapcheck __P((const struct mbuf *, int, int, void *));

static int mip6_process_hrbu __P((struct in6_addr *, struct in6_addr *,
				  struct ip6_opt_binding_update *,
				  MIP6_SEQNO_T, u_int32_t, struct in6_addr *));
static int mip6_process_hurbu __P((struct in6_addr *, struct in6_addr *,
				   struct ip6_opt_binding_update *,
				   MIP6_SEQNO_T, u_int32_t, struct in6_addr *));
static int mip6_tunnel_control __P((int, void *, 
				    int (*) __P((const struct mbuf *, int, int, void *)),
				    const struct encaptab **));
static int mip6_are_ifid_equal __P((struct in6_addr *, struct in6_addr *,
				    u_int8_t));
#ifndef MIP6_DRAFT13
static int mip6_verify_authdata __P((struct mbuf *,
				     struct ip6_opt_binding_update *,
				     struct mip6_subopt_authdata *));
#endif

#ifdef MIP6_DEBUG
void mip6_bu_print __P((struct mip6_bu *));
#endif /* MIP6_DEBUG */


/*
 * binding update management functions.
 */
void
mip6_bu_init()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3) 
        callout_init(&mip6_bu_ch);
#endif
}

/*
 * Find the BU entry specified with the destination (peer) address
 * from specified hif_softc entry.
 *
 * Returns: BU entry or NULL (if not found)
 */
struct mip6_bu *
mip6_bu_list_find_withpaddr(bu_list, paddr)
	struct mip6_bu_list *bu_list;
	struct in6_addr *paddr;
{
	struct mip6_bu *mbu;

	for (mbu = LIST_FIRST(bu_list); mbu;
	     mbu = LIST_NEXT(mbu, mbu_entry)) {
		if (IN6_ARE_ADDR_EQUAL(&mbu->mbu_paddr, paddr))
			break;
	}
	return (mbu);
}

struct mip6_bu *
mip6_bu_list_find_home_registration(bu_list, haddr)
     struct mip6_bu_list *bu_list;
     struct in6_addr *haddr;
{
	struct mip6_bu *mbu;

	for (mbu = LIST_FIRST(bu_list); mbu;
	     mbu = LIST_NEXT(mbu, mbu_entry)) {
		if (IN6_ARE_ADDR_EQUAL(&mbu->mbu_haddr, haddr) &&
		    (mbu->mbu_flags & IP6_BUF_HOME) != 0)
			break;
	}
	return (mbu);
}

struct mip6_bu *
mip6_bu_create(paddr, mpfx, coa, flags, sc)
	const struct in6_addr *paddr;
	struct mip6_prefix *mpfx;
	struct in6_addr *coa;
	u_int16_t flags;
	struct hif_softc *sc;
{
	struct mip6_bu *mbu;
	u_int32_t coa_lifetime;

	MALLOC(mbu, struct mip6_bu *, sizeof(struct mip6_bu),
	       M_TEMP, M_NOWAIT);
	if (mbu == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: memory allocation failed.\n",
			 __FILE__, __LINE__));
		return (NULL);
	}

	coa_lifetime = mip6_coa_get_lifetime(coa);

	bzero(mbu, sizeof(*mbu));
	mbu->mbu_paddr = *paddr;
	mbu->mbu_haddr = mpfx->mpfx_haddr;
	if (sc->hif_location == HIF_LOCATION_HOME) {
		/* un-registration. */
		mbu->mbu_coa = mpfx->mpfx_haddr;
		mbu->mbu_reg_state = MIP6_BU_REG_STATE_DEREGWAITACK;
	} else {
		/* registration. */
		mbu->mbu_coa = *coa;
		mbu->mbu_reg_state = MIP6_BU_REG_STATE_REGWAITACK;
	}
	if (coa_lifetime < mpfx->mpfx_lifetime) {
		mbu->mbu_lifetime = coa_lifetime;
	} else {
		mbu->mbu_lifetime = mpfx->mpfx_lifetime;
	}
	mbu->mbu_remain = mbu->mbu_lifetime;
	mbu->mbu_refresh = mbu->mbu_lifetime;
	mbu->mbu_refremain = mbu->mbu_refresh;
	mbu->mbu_acktimeout = MIP6_BA_INITIAL_TIMEOUT;
	mbu->mbu_ackremain = mbu->mbu_acktimeout;
	mbu->mbu_flags = flags;
	mbu->mbu_hif = sc;
	/* *mbu->mbu_encap = NULL; */

	return (mbu);
}

int
mip6_home_registration(sc)
	struct hif_softc *sc;
{
	struct mip6_bu *mbu;
	struct hif_subnet *hs;
	struct mip6_subnet *ms;
	struct mip6_subnet_ha *msha;

	/* find the subnet info of this home link. */
	hs = TAILQ_FIRST(&sc->hif_hs_list_home);
	if (hs == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: no home subnet\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}
	if ((ms = hs->hs_ms) == NULL) {
		/* must not happen */
		return (EINVAL);
	}

	/* check each BU entry that has a BUF flag on. */
	for (mbu = LIST_FIRST(&sc->hif_bu_list);
	     mbu;
	     mbu = LIST_NEXT(mbu, mbu_entry)) {
		if ((mbu->mbu_flags & IP6_BUF_HOME) == 0)
			continue;

		/*
		 * check if this BU entry is home registration to the
		 * HA or home registration to the AR of a foreign
		 * network.  if paddr of the BU is one of the HAs of
		 * our home link, this BU is home registration to the
		 * HA.
		 */
		msha = mip6_subnet_ha_list_find_withhaaddr(&ms->ms_msha_list,
							   &mbu->mbu_paddr);
		if (msha) {
			/* this BU is a home registration to our HA */
			break;
		}
			
	}
	if (mbu == NULL) {
		const struct in6_addr *haaddr;
		struct mip6_ha *mha;
		struct mip6_subnet_prefix *mspfx;
		struct mip6_prefix *mpfx;

		/*
		 * no home registration found.  create a new binding
		 * update entry.
		 */

		/* pick the preferable HA from the list. */
		msha = mip6_subnet_ha_list_find_preferable(&ms->ms_msha_list);
		if (msha == NULL) {
			/*
			 * if no HA is found, try to find a HA using
			 * Dynamic Home Agent Discovery.
			 */
			mip6log((LOG_INFO,
				 "%s:%d: "
				 "no home agent.  start ha discovery.\n",
				 __FILE__, __LINE__));
			mip6_icmp6_ha_discov_req_output(sc);
			haaddr = &in6addr_any;
		} else {
			if ((mha = msha->msha_mha) == NULL) {
				return (EINVAL);
			}
			haaddr = &mha->mha_gaddr;
		}

		/*
		 * pick one home prefix up to determine the home
		 * address of this MN.
		 */
		/* 
		 * XXX: which prefix to use to get a home address when
		 * we have multiple home prefixes.
		 */
		if ((mspfx = TAILQ_FIRST(&ms->ms_mspfx_list)) == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d: we don't have any home prefix.\n",
				 __FILE__, __LINE__));
			return (EINVAL);
		}
		if ((mpfx = mspfx->mspfx_mpfx) == NULL)
			return (EINVAL);
		mip6log((LOG_INFO,
			 "%s:%d: home address is %s\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&mpfx->mpfx_haddr)));

		mbu = mip6_bu_create(haaddr, mpfx, &hif_coa,
				     IP6_BUF_ACK|IP6_BUF_HOME, sc);
		if (mbu == NULL)
			return (ENOMEM);

		mip6_bu_list_insert(&sc->hif_bu_list, mbu);
	} else {
		int32_t coa_lifetime, prefix_lifetime;

		/* a BU entry exists.  update information. */

		/* update coa. */
		if (sc->hif_location == HIF_LOCATION_HOME) {
			/* un-registration. */
			mbu->mbu_coa = mbu->mbu_haddr;
			mbu->mbu_reg_state = MIP6_BU_REG_STATE_DEREGWAITACK;
		} else {
			/* registration. */
			mbu->mbu_coa = hif_coa;
			mbu->mbu_reg_state = MIP6_BU_REG_STATE_REGWAITACK;
		}

		/* update lifetime. */
		coa_lifetime = mip6_coa_get_lifetime(&mbu->mbu_coa);
		prefix_lifetime
			= mip6_subnet_prefix_list_get_minimum_lifetime(&ms->ms_mspfx_list);
		if (coa_lifetime < prefix_lifetime) {
			mbu->mbu_lifetime = coa_lifetime;
		} else {
			mbu->mbu_lifetime = prefix_lifetime;
		}
		mbu->mbu_remain = mbu->mbu_lifetime;
		mbu->mbu_refresh = mbu->mbu_lifetime;
		mbu->mbu_refremain = mbu->mbu_refresh;
		mbu->mbu_acktimeout = MIP6_BA_INITIAL_TIMEOUT;
		mbu->mbu_ackremain = mbu->mbu_acktimeout;
		/* mbu->mbu_seqno++; */
		/* XXX mbu->mbu_flags |= IP6_BUF_DAD */
	}
	mbu->mbu_state = MIP6_BU_STATE_WAITACK | MIP6_BU_STATE_WAITSENT;

	/*
	 * XXX
	 * register to a previous ar.
	 */

	return (0);
}

static int
mip6_bu_list_notify_binding_change(sc)
	struct hif_softc *sc;
{
	struct mip6_prefix *mpfx;
	struct mip6_bu *mbu, *mbu_next;
	int32_t coa_lifetime;

	/* for each BU entry, update COA and make them about to send. */
	for (mbu = LIST_FIRST(&sc->hif_bu_list);
	     mbu;
	     mbu = mbu_next) {
		mbu_next = LIST_NEXT(mbu, mbu_entry);

		if (mbu->mbu_flags & IP6_BUF_HOME) {
			/* this is a BU for our home agent */
			/*
			 * XXX
			 * must send bu with ack flag to a previous ar.
			 */
			continue;
		}
		mbu->mbu_coa = hif_coa;
		coa_lifetime = mip6_coa_get_lifetime(&mbu->mbu_coa);
		mpfx = mip6_prefix_list_find_withhaddr(&mip6_prefix_list,
						       &mbu->mbu_haddr);
		if (mpfx == NULL) {
			mip6log((LOG_NOTICE,
				 "%s:%d: expired prefix (%s).\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&mbu->mbu_haddr)));
			mip6_bu_list_remove(&sc->hif_bu_list, mbu);
			continue;
		}
		if (coa_lifetime < mpfx->mpfx_lifetime) {
			mbu->mbu_lifetime = coa_lifetime;
		} else {
			mbu->mbu_lifetime = mpfx->mpfx_lifetime;
		}
		mbu->mbu_remain = mbu->mbu_lifetime;
		mbu->mbu_refresh = mbu->mbu_lifetime;
		mbu->mbu_refremain = mbu->mbu_refresh;
		/* mbu->mbu_acktimeout = MIP6_BA_INITIAL_TIMEOUT; */
		/* mbu->mbu_ackremain = mbu->mbu_acktimeout; */
		mbu->mbu_seqno++;
		mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
		mip6_bu_send_bu(mbu);
	}

	/* start BU timer if it hasn't started already */
	/* mip6_bu_starttimer(); */

	return (0);
}

static void
mip6_bu_starttimer()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&mip6_bu_ch,
		      MIP6_BU_TIMEOUT_INTERVAL * hz,
		      mip6_bu_timeout, NULL);
#else
	timeout(mip6_bu_timeout, (void *)0,
		MIP6_BU_TIMEOUT_INTERVAL * hz);
#endif
}

static void
mip6_bu_stoptimer()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&mip6_bu_ch);
#else
	untimeout(mip6_bu_timeout, (void *)0);
#endif
}

static void
mip6_bu_timeout(arg)
	void *arg;
{
	int s;
	struct hif_softc *sc;
	int error = 0;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	mip6_bu_starttimer();

	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		struct mip6_bu *mbu, *mbu_entry;

		for (mbu = LIST_FIRST(&sc->hif_bu_list);
		     mbu != NULL; mbu = mbu_entry) {
			mbu_entry = LIST_NEXT(mbu, mbu_entry);

			/* count down timer values */
			mbu->mbu_remain -= MIP6_BU_TIMEOUT_INTERVAL;
			mbu->mbu_refremain -= MIP6_BU_TIMEOUT_INTERVAL;
			if (mbu->mbu_state & MIP6_BU_STATE_WAITACK)
				mbu->mbu_ackremain -= MIP6_BU_TIMEOUT_INTERVAL;

			/* check expiration */
			if (mbu->mbu_remain < 0) {
				mip6log((LOG_INFO,
					 "%s:%d: "
					 "an BU entry (0x%p) expired.\n",
					 __FILE__, __LINE__, mbu));
				error = mip6_bu_list_remove(&sc->hif_bu_list,
							    mbu);
				if (error) {
					mip6log((LOG_ERR,
						 "%s:%d: can't remove BU.\n",
						 __FILE__, __LINE__));
					continue;
				}
				continue;
			}

			/* check if the peer supports BU */
			if (mbu->mbu_dontsend)
				continue;

#ifdef MIP6_ALLOW_COA_FALLBACK
			/* check if the peer supports HA destopt */
			if (mbu->mbu_coafallback)
				continue;
#endif

			/* check ack status */
			if ((mbu->mbu_flags & IP6_BUF_ACK)
			    && (mbu->mbu_state & MIP6_BU_STATE_WAITACK)
			    && (mbu->mbu_ackremain < 0)) {
				mip6log((LOG_INFO,
					 "%s:%d: "
					 "ack for an BU (0x%p) timeout.\n",
					 __FILE__, __LINE__,
					 mbu));
				mbu->mbu_acktimeout *= 2;
				if (mbu->mbu_acktimeout > MIP6_BA_MAX_TIMEOUT)
					mbu->mbu_acktimeout
						= MIP6_BA_MAX_TIMEOUT;
				mbu->mbu_ackremain = mbu->mbu_acktimeout;
				mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
			}

			/* refresh check */
			if (mbu->mbu_refremain < 0) {
				/* refresh binding */
				mbu->mbu_refremain = mbu->mbu_refresh;
				if (mbu->mbu_flags & IP6_BUF_ACK) {
					mbu->mbu_acktimeout
						= MIP6_BA_INITIAL_TIMEOUT;
					mbu->mbu_ackremain
						= mbu->mbu_acktimeout;
					mbu->mbu_state
						|= MIP6_BU_STATE_WAITACK;
				}
				mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
			}

			/* send pending BUs */
			if (mbu->mbu_state & MIP6_BU_STATE_WAITSENT) {
				mip6log((LOG_INFO,
					 "%s:%d: "
					 "we have a pending BU (0x%p)\n",
					 __FILE__, __LINE__,
					 mbu));
				if (mip6_bu_send_bu(mbu)) {
					mip6log((LOG_ERR,
						 "%s:%d: sending BU from %s(%s) to %s failed.\n",
						 __FILE__, __LINE__,
						 ip6_sprintf(&mbu->mbu_haddr),
						 ip6_sprintf(&mbu->mbu_coa),
						 ip6_sprintf(&mbu->mbu_paddr)));
				}
			}
		}
	}

	splx(s);
}

/*
 * Some BUs are sent with IPv6 datagram.  But when we have no traffic to
 * the BU destination, we may have some BUs left in the BU list.  Push
 * them out.
 */
static int
mip6_bu_send_bu(mbu)
	struct mip6_bu *mbu;
{
	struct mbuf *m;
	int error = 0;

	if (IN6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr)) {
		if ((mbu->mbu_flags & IP6_BUF_HOME) != 0) {
			mip6log((LOG_INFO,
				 "%s:%d: "
				 "no home agent.  start ha discovery.\n",
				 __FILE__, __LINE__));
			mip6_icmp6_ha_discov_req_output(mbu->mbu_hif);
		}

		/* return immediately.  we need WAITSENT flag being set. */
		return (0);
	}

	/* create ipv6 header to send a binding update destination opt */
	m = mip6_create_ip6hdr(&mbu->mbu_haddr, &mbu->mbu_paddr,
			       IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: memory allocation failed.\n",
			 __FILE__, __LINE__));
		error = ENOBUFS;
		goto send_bu_end;
	}

	/* output a null packet. */
	error = ip6_output(m, NULL, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: ip6_output returns error (%d) "
			 "when sending NULL packet to send BU.\n",
			 __FILE__, __LINE__,
			 error));
		goto send_bu_end;
	}

 send_bu_end:
	/*
	 * XXX when we reset waitsent flag ?  is it correct to clear here ?
	 */
	/* mbu->mbu_state &= ~MIP6_BU_STATE_WAITSENT; */

	return (error);
}

int
mip6_bu_list_insert(bu_list, mbu)
	struct mip6_bu_list *bu_list;
	struct mip6_bu *mbu;
{
	LIST_INSERT_HEAD(bu_list, mbu, mbu_entry);

	if (mip6_bu_count == 0) {
		mip6log((LOG_INFO, "%s:%d: BU timer started.\n",
			__FILE__, __LINE__));
		mip6_bu_starttimer();
	}
	mip6_bu_count++;
		
	return (0);
}

static int
mip6_bu_list_remove(mbu_list, mbu)
	struct mip6_bu_list *mbu_list;
	struct mip6_bu *mbu;
{
	if ((mbu_list == NULL) || (mbu == NULL)) {
		return (EINVAL);
	}

	mip6log((LOG_INFO,
		 "%s:%d: removing a BU entry (0x%p).\n",
		 __FILE__, __LINE__,
		 mbu));

	LIST_REMOVE(mbu, mbu_entry);
	FREE(mbu, M_TEMP);

	mip6_bu_count--;
	if (mip6_bu_count == 0) {
		mip6_bu_stoptimer();
		mip6log((LOG_INFO,
			 "%s:%d: BU timer stopped.\n",
			__FILE__, __LINE__));
	}

	return (0);
}

static int
mip6_bu_list_remove_all(mbu_list)
	struct mip6_bu_list *mbu_list;
{
	struct mip6_bu *mbu, *mbu_next;
	int error = 0;

	if (mbu_list == NULL) {
		return (EINVAL);
	}

	for (mbu = LIST_FIRST(mbu_list);
	     mbu;
	     mbu = mbu_next) {
		mbu_next = LIST_NEXT(mbu, mbu_entry);

		error = mip6_bu_list_remove(mbu_list, mbu);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: can't remove BU.\n",
				 __FILE__, __LINE__));
			continue;
		}
	}

	return (0);
}

/*
 * validate incoming binding update.
 * draft-14 section 8.2
 */
int
mip6_validate_bu(m, opt)
	struct mbuf *m;
	u_int8_t *opt;
{
	struct ip6_hdr *ip6;
	struct mbuf *n;
	struct ip6aux *ip6a = NULL;
	struct ip6_opt_binding_update *bu_opt;
	MIP6_SEQNO_T seqno;
	struct mip6_bc *mbc;
#ifndef MIP6_DRAFT13
	int error = 0;
	struct mip6_subopt_authdata *authdata = NULL;
#endif /* !MIP6_DRAFT13 */

	ip6 = mtod(m, struct ip6_hdr *);
	bu_opt = (struct ip6_opt_binding_update *)(opt);
	    
#ifdef MIP6_DRAFT13
	/* Make sure that the BU is protected by an AH (see 4.4, 10.12). */
#ifdef IPSEC
#ifndef __OpenBSD__
	if (!mip6_use_ipsec &&
	    !((m->m_flags & M_AUTHIPHDR) && (m->m_flags & M_AUTHIPDGM))) {
		mip6log((LOG_NOTICE, "%s:%d: an unprotected BU from %s.\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ip6->ip6_src)));
		/* silently ignore */
		return (1);
	}
#endif /* __OpenBSD__ */
#endif /* IPSEC */
#endif /* MIP6_DRAFT13 */

	/* check if this packet contains a home address destopt. */
	n = ip6_findaux(m);
	if (!n) {
		mip6log((LOG_NOTICE,
			 "%s:%d: no Home Address option found "
			 "in the binding update from host %s.\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ip6->ip6_src)));
		return (1);
	}
	ip6a = mtod(n, struct ip6aux *);
	if ((ip6a == NULL) || (ip6a->ip6a_flags & IP6A_HASEEN) == 0) {
		mip6log((LOG_NOTICE,
			 "%s:%d: no Home Address option found "
			 "in the binding update from host %s.\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ip6->ip6_src)));
		return (1);
	}

	/*
	 * XXX: TODO
	 *
	 * draft-15 introduces a new sub-option to authenticate
	 * binding packets.  we should check the sub-option and make
	 * sure the packet is protected by the some authentication
	 * mechanisms.
	 */

	/* Make sure that the length field in the BU is >= IP6OPT_BULEN. */
	if (bu_opt->ip6ou_len < IP6OPT_BULEN) {
		ip6stat.ip6s_badoptions++;
		mip6log((LOG_NOTICE,
			 "%s:%d: an BU length is too short (%d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 bu_opt->ip6ou_len,
			 ip6_sprintf(&ip6->ip6_src)));
		/* silently ignore */
		return (1);
	}

	/* check sub-options. */
	if (bu_opt->ip6ou_len > IP6OPT_BULEN) {
		/* we have sub-option(s). */
		int suboptlen = bu_opt->ip6ou_len - IP6OPT_BULEN;
		u_int8_t *opt = (u_int8_t *)(bu_opt + 1);
		int optlen;
		for (optlen = 0;
		     suboptlen > 0;
		     suboptlen -= optlen, opt += optlen) {
			if (*opt != MIP6SUBOPT_PAD1 &&
			    (suboptlen < 2 || *(opt + 1) + 2 > suboptlen)) {
				mip6log((LOG_ERR,
					 "%s:%d: "
					 "sub-option too small\n",
					 __FILE__, __LINE__));
				return (-1);
			}
			switch (*opt) {
			case MIP6SUBOPT_PAD1:
				optlen = 1;
				break;
			case MIP6SUBOPT_ALTCOA:
				/* XXX */
				optlen = *(opt + 1) + 2;
				break;
#ifndef MIP6_DRAFT13
			case MIP6SUBOPT_AUTHDATA:
				authdata = (struct mip6_subopt_authdata *)opt;
				optlen = *(opt + 1) + 2;
				break;
#endif /* !MIP6_DRAFT13 */
			default:
				optlen = *(opt + 1) + 2;
				break;
			}
		}
	}
#ifndef MIP6_DRAFT13
	if (authdata == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: unprotected binding update from host %s\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ip6->ip6_src)));
	}
	if (mip6_verify_authdata(m, bu_opt, authdata)) {
		mip6log((LOG_ERR,
			 "%s:%d: authenticate binding update failed from host %s\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ip6->ip6_src)));
	}
#endif /* !MIP6_DRAFT13 */

	/* The received BU sequence number > received seqno before. */
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &ip6a->ip6a_home);
	if (mbc == NULL) {
		/* no BC yet.  create it later. */
		return (0);
	}
#ifdef MIP6_DRAFT13
	seqno = ntohs(bu_opt->ip6ou_seqno);
#else
	seqno = bu_opt->ip6ou_seqno;
#endif
	if (MIP6_LEQ(seqno, mbc->mbc_seqno)) {
		ip6stat.ip6s_badoptions++;
		mip6log((LOG_NOTICE,
			 "%s:%d: received sequence no (%d) <= current "
			 "seq no (%d) in BU from host %s.\n",
			 __FILE__, __LINE__,
			 seqno,
			 mbc->mbc_seqno, ip6_sprintf(&ip6->ip6_src)));
#ifndef MIP6_DRAFT13
		/* seqno is too small.  send TOO_SMALL error. */
		error = mip6_bc_send_ba(&mbc->mbc_addr,
					&mbc->mbc_phaddr, &mbc->mbc_pcoa,
					MIP6_BA_STATUS_SEQNO_TOO_SMALL,
					mbc->mbc_seqno,
					0, 0);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: can't send BA\n",
				 __FILE__, __LINE__));
		}
#endif /* !MIP6_DRAFT13 */
		return (1);
	}

	/* we have a valid BU */
	return (0);
}

/*
 * process incoming binding update.
 * draft-14 section 8.2 / 9.1 / 9.2
 */
int
mip6_process_bu(m, opt)
	struct mbuf *m;
	u_int8_t *opt;
{
	struct ip6_hdr *ip6;
	struct mbuf *n;
	struct ip6aux *ip6a = NULL;
	struct ip6_opt_binding_update *bu_opt;
	struct in6_addr *pcoa;
	u_int8_t *subopthead;
	struct mip6_subopt_altcoa *altcoa_subopt;
	u_int8_t suboptlen;
	u_int32_t lifetime;
	MIP6_SEQNO_T seqno;
	struct mip6_bc *mbc;
	int error = 0;

	ip6 = mtod(m, struct ip6_hdr *);
	bu_opt = (struct ip6_opt_binding_update *)(opt);

	n = ip6_findaux(m);
	if (!n) {
		/* just in case */
		return (EINVAL);
	}
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) {
		/* just in case */
		return (EINVAL);
	}

	/* find alternative coa suboption. */
	subopthead = opt + IP6OPT_MINLEN + IP6OPT_BULEN;
	suboptlen = *(opt + 1) - IP6OPT_BULEN;
	altcoa_subopt = (struct mip6_subopt_altcoa *)
		mip6_destopt_find_subopt(subopthead,
					 suboptlen,
					 MIP6SUBOPT_ALTCOA);
	if (altcoa_subopt == NULL) {
		pcoa = &ip6a->ip6a_careof;
	} else {
		pcoa = (struct in6_addr *)&altcoa_subopt->coa;
	}

	lifetime = ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime);
#ifdef MIP6_DRAFT13
	seqno = ntohs(bu_opt->ip6ou_seqno);
#else
	seqno = bu_opt->ip6ou_seqno;
#endif

	/*
	 * lifetime != 0 and haddr != coa means that this BU is a reqeust
	 * to cache binding (or home registration) for the sending MN.
	 */
	if ((lifetime != 0) && (!IN6_ARE_ADDR_EQUAL(&ip6a->ip6a_home, pcoa))) {
		/* check home registration flag. */
		if (bu_opt->ip6ou_flags & IP6_BUF_HOME) {
			/* a request for a home registration. */
			if (MIP6_IS_HA) {
				/* XXX TODO write code of section 9.1 */
				mip6_process_hrbu(&ip6a->ip6a_home,
						  pcoa,
						  bu_opt,
						  seqno,
						  lifetime,
						  &ip6->ip6_dst);
			} else {
				/* this is not acting as a homeagent. */
				/* XXX: TODO send a binding ack. */
				return (0); /* XXX is 0 OK? */
			}
		} else {
			/* a request to cache binding. */
			mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list,
							   &ip6a->ip6a_home);
			if (mbc == NULL) {
				/* create a binding cache entry. */
				mbc = mip6_bc_create(&ip6a->ip6a_home,
						     pcoa,
						     &ip6->ip6_dst,
						     bu_opt->ip6ou_flags,
#ifdef MIP6_DRAFT13
						     bu_opt->ip6ou_prefixlen,
#endif /* MIP6_DRAFT13 */
						     seqno,
						     lifetime,
						     NULL);
				if (mbc == NULL) {
					mip6log((LOG_ERR,
						 "%s:%d: mip6_bc memory "
						 "allocation failed.\n",
						 __FILE__, __LINE__));
					return (ENOMEM);
				}
				error = mip6_bc_list_insert(&mip6_bc_list,
							    mbc);
				if (error) {
					return (error);
				}
			} else {
				/* update a BC entry. */
				mbc->mbc_pcoa = *pcoa;
				mbc->mbc_flags = bu_opt->ip6ou_flags;
#ifdef MIP6_DRAFT13
				mbc->mbc_prefixlen = bu_opt->ip6ou_prefixlen;
#endif /* MIP6_DRAFT13 */
				mbc->mbc_seqno = seqno;
				mbc->mbc_lifetime = lifetime;
				mbc->mbc_remain = mbc->mbc_lifetime;
			}
			
			if (bu_opt->ip6ou_flags & IP6_BUF_ACK) {
				/* XXX send BA */
			}
		}
	}

	/*
	 * lifetime == 0 or haddr == coa meaans that this BU is a reqeust
	 * to delete cache (or home unregistration).
	 */
	if ((lifetime == 0) || (IN6_ARE_ADDR_EQUAL(&ip6a->ip6a_home, pcoa))) {
		/* check home registration flag */
		if (bu_opt->ip6ou_flags & IP6_BUF_HOME) {
			/* a request to home unregistration */
			if (MIP6_IS_HA) {
				/* XXX TODO write code of section 9.2 */
				mip6_process_hurbu(&ip6a->ip6a_home,
						   pcoa,
						   bu_opt,
						   seqno,
						   lifetime,
						   &ip6->ip6_dst);
			} else {
				/* this is not HA.  return BA with error. */
				/* XXX */
			}
		} else {
			/* a request to delete binding. */
			mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list,
							   &ip6a->ip6a_home);
			if (mbc) {
				error = mip6_bc_list_remove(&mip6_bc_list,
							    mbc);
				if (error) {
					mip6log((LOG_ERR,
						 "%s:%d: can't remove BC.\n",
						 __FILE__, __LINE__));
					return (error);
				}
			}
			if (bu_opt->ip6ou_flags & IP6_BUF_ACK) {
				/* XXX send BA */
			}
		}
	}

	return (0);
}

static int
mip6_process_hurbu(haddr0, coa, bu_opt, seqno, lifetime, haaddr)
	struct in6_addr *haddr0;
	struct in6_addr *coa;
	struct ip6_opt_binding_update *bu_opt;
	MIP6_SEQNO_T seqno;
	u_int32_t lifetime;
	struct in6_addr *haaddr;
{
	struct mip6_bc *mbc, *mbc_next;
	struct nd_prefix *pr;
	struct ifnet *hifp = NULL;
	int error = 0;
#ifdef MIP6_DRAFT13
	u_int8_t prefixlen;
#endif /* MIP6_DRAFT13 */

	/* find the home ifp of this homeaddress. */
	for(pr = nd_prefix.lh_first;
	    pr;
	    pr = pr->ndpr_next) {
		if (in6_are_prefix_equal(haddr0,
					 &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)) {
			hifp = pr->ndpr_ifp; /* home ifp. */
		}
	}
	if (hifp == NULL) {
		/*
		 * the haddr0 doesn't have an online prefix.  return a
		 * binding ack with an error NOT_HOME_SUBNET.
		 */
		if (mip6_bc_send_ba(haaddr, haddr0, coa,
				    MIP6_BA_STATUS_NOT_HOME_SUBNET,
				    seqno,
				    0,
				    0)) {
			mip6log((LOG_ERR,
				 "%s:%d: sending BA to %s(%s) failed. "
				 "send it later.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(haddr0),
				 ip6_sprintf(coa)));
		}
		return (0); /* XXX is 0 OK? */
	}
#ifdef MIP6_DRAFT13
	prefixlen = bu_opt->ip6ou_prefixlen;
	if (prefixlen == 0) {
		mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list,
						   haddr0);
		if (mbc == NULL) {
			/* XXX NOT_HOME_AGENT */
			mip6_bc_send_ba(haaddr, haddr0, coa,
					MIP6_BA_STATUS_NOT_HOME_AGENT,
					seqno,
					0,
					0);
			return (0);
		}

		/* remove rtable for proxy ND */
		if (mip6_bc_proxy_control(haddr0, haaddr, RTM_DELETE)) {
			/* XXX UNSPECIFIED */
			return (-1);
		}

		/* remove encapsulation entry */
		if (mip6_tunnel_control(MIP6_TUNNEL_DELETE,
					mbc,
					mip6_bc_encapcheck,
					&mbc->mbc_encap)) {
			/* XXX UNSPECIFIED */
			return (-1);
		}

		/* remove a BC entry. */
		error = mip6_bc_list_remove(&mip6_bc_list, mbc);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: can't remove BC.\n",
				 __FILE__, __LINE__));
			mip6_bc_send_ba(haaddr, haddr0, coa,
					MIP6_BA_STATUS_UNSPECIFIED,
					seqno,
					0,
					0);
			return (error);
		}
	} else
#endif /* MIP6_DRAFT13 */
	{
		for(mbc = LIST_FIRST(&mip6_bc_list);
		    mbc;
		    mbc = mbc_next) {
			mbc_next = LIST_NEXT(mbc, mbc_entry);

			if (mbc->mbc_ifp != hifp)
				continue;

			if (!mip6_are_ifid_equal(&mbc->mbc_phaddr,
						 haddr0,
#ifdef MIP6_DRAFT13
						 prefixlen
#else
						 64 /* XXX */
#endif /* MIP6_DRAFT13 */
				    ))
				continue;

			/* remove rtable for proxy ND */
			mip6_bc_proxy_control(&mbc->mbc_phaddr, haaddr,
					      RTM_DELETE);

			/* remove encapsulation entry */
			if (mip6_tunnel_control(MIP6_TUNNEL_DELETE,
						mbc,
						mip6_bc_encapcheck,
						&mbc->mbc_encap)) {
				/* XXX UNSPECIFIED */
				return (-1);
			}

			/* remove a BC entry. */
			error = mip6_bc_list_remove(&mip6_bc_list, mbc);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: can't remove BC.\n",
					 __FILE__, __LINE__));
				mip6_bc_send_ba(haaddr, haddr0, coa,
						MIP6_BA_STATUS_UNSPECIFIED,
						seqno,
						0,
						0);
				return (error);
			}
		}
	}

	/* return BA */
	if (mip6_bc_send_ba(haaddr, haddr0, coa,
			    MIP6_BA_STATUS_ACCEPTED,
			    seqno,
			    0,
			    0)) {
		mip6log((LOG_ERR,
			 "%s:%d: sending BA to %s(%s) failed.  send it later.\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&mbc->mbc_phaddr),
			 ip6_sprintf(&mbc->mbc_pcoa)));
	}

	return (0);
}

static int
mip6_are_ifid_equal(addr1, addr2, prefixlen)
	struct in6_addr *addr1;
	struct in6_addr *addr2;
	u_int8_t prefixlen;
{
	int bytelen, bitlen;
	u_int8_t mask;
	int i;

	bytelen = prefixlen / 8;
	bitlen = prefixlen % 8;
	mask = 0;
	for (i = 0; i < bitlen; i++) {
		mask &= (0x80 >> i);
	}

	if (bitlen) {
		if ((addr1->s6_addr8[bytelen] & ~mask)
		    != (addr2->s6_addr8[bytelen] & ~mask))
			return (0);

		if (bcmp(((caddr_t)addr1) + bytelen,
			 ((caddr_t)addr2) + bytelen,
			 16 - bytelen - 1))
			return (0);
	} else {
		if (bcmp(((caddr_t)addr1) + bytelen,
			 ((caddr_t)addr2) + bytelen,
			 16 - bytelen))
			return (0);
	}

	return (1);
}

static int
mip6_process_hrbu(haddr0, coa, bu_opt, seqno, lifetime, haaddr)
	struct in6_addr *haddr0;
	struct in6_addr *coa;
	struct ip6_opt_binding_update *bu_opt;
	MIP6_SEQNO_T seqno;
	u_int32_t lifetime;
	struct in6_addr *haaddr;
{
	struct nd_prefix *pr;
	struct ifnet *hifp = NULL;
	struct in6_addr haddr;
	struct mip6_bc *mbc = NULL;
	u_int32_t prlifetime;

	/* find the home ifp of this homeaddress. */
	for(pr = nd_prefix.lh_first;
	    pr;
	    pr = pr->ndpr_next) {
		if (in6_are_prefix_equal(haddr0,
					 &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)) {
			hifp = pr->ndpr_ifp; /* home ifp. */
		}
	}
	/* XXX really stupid to loop twice? */
	prlifetime = 0xffffffff;
	for(pr = nd_prefix.lh_first;
	    pr;
	    pr = pr->ndpr_next) {
		if (pr->ndpr_ifp != hifp) {
			/* this prefix is not a home prefix. */
			continue;
		}
		/* save minimum prefix lifetime for later use. */
		if (prlifetime > pr->ndpr_vltime)
			prlifetime = pr->ndpr_vltime;
	}
	if (hifp == NULL) {
		/*
		 * the haddr0 doesn't have an online prefix.  return a
		 * binding ack with an error NOT_HOME_SUBNET.
		 */
		if (mip6_bc_send_ba(haaddr, haddr0, coa,
				    MIP6_BA_STATUS_NOT_HOME_SUBNET,
				    seqno,
				    0,
				    0)) {
			mip6log((LOG_ERR,
				 "%s:%d: sending BA to %s(%s) failed. "
				 "send it later.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(haddr0),
				 ip6_sprintf(coa)));
		}
		return (0); /* XXX is 0 OK? */
	}
#ifdef MIP6_DRAFT13
	if (pr->ndpr_plen != bu_opt->ip6ou_prefixlen) {
		/* the haddr has an incorrect prefix length. */
		/* XXX return 136 INCORRECT SUBNET PREFIX LENGTH */
	}
#endif /* MIP6_DRAFT13 */

	/* adjust lifetime */
	if (lifetime > prlifetime)
		lifetime = prlifetime;

#ifdef MIP6_DRAFT13
	if (bu_opt->ip6ou_prefixlen == 0) {
		/*
		 * if prefixlen == 0, create a binding cache exactly
		 * for the only address specified by the sender.
		 */
		mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list,
						   haddr0);
		if (mbc == NULL) {
			/* create BC entry */
			mbc = mip6_bc_create(haddr0,
					     coa,
					     haaddr,
					     bu_opt->ip6ou_flags,
					     bu_opt->ip6ou_prefixlen,
					     seqno,
					     lifetime,
					     hifp);
			if (mbc == NULL) {
				/* XXX STATUS_RESOUCE */
				return (-1);
			}

			if (mip6_bc_list_insert(&mip6_bc_list, mbc)) {
				/* XXX STATUS_UNSPECIFIED */
				return (-1);
			}

			/* create encapsulation entry */
			if (mip6_tunnel_control(MIP6_TUNNEL_ADD,
						mbc,
						mip6_bc_encapcheck,
						&mbc->mbc_encap)) {
				/* XXX UNSPECIFIED */
				return (-1);
			}
		} else {
			/* update a BC entry. */
			mbc->mbc_pcoa = *coa;
			mbc->mbc_flags = bu_opt->ip6ou_flags;
			mbc->mbc_prefixlen = bu_opt->ip6ou_prefixlen;
			mbc->mbc_seqno = seqno;
			mbc->mbc_lifetime = lifetime;
			mbc->mbc_remain = mbc->mbc_lifetime;	

			/* modify encapsulation entry */
			if (mip6_tunnel_control(MIP6_TUNNEL_CHANGE,
						mbc,
						mip6_bc_encapcheck,
						&mbc->mbc_encap)) {
				/* XXX UNSPECIFIED */
				return (-1);
			}
		}

		/* add rtable for proxy ND */
		if (mip6_bc_proxy_control(haddr0, haaddr, RTM_ADD)) {
			/* XXX UNSPECIFIED */
			return (-1);
		}
	} else
#endif /* MIP6_DRAFT13 */
	{
		/*
		 * create/update binding cache entries for each
		 * address derived from all the routing prefixes on
		 * this router.
		 */
		for(pr = nd_prefix.lh_first;
		    pr;
		    pr = pr->ndpr_next) {
			if (!pr->ndpr_raf_onlink)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr))
				continue;
			if (pr->ndpr_ifp != hifp)
				continue;

			mip6_create_addr(&haddr, haddr0,
					 &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen);

			mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list,
							   &haddr);
			if (mbc == NULL) {
				/* create a BC entry. */
				mbc = mip6_bc_create(&haddr,
						     coa,
						     haaddr,
						     bu_opt->ip6ou_flags,
#ifdef MIP6_DRAFT13
						     bu_opt->ip6ou_prefixlen,
#endif /* MIP6_DRAFT13 */
						     seqno,
						     lifetime,
						     hifp);
				if (mip6_bc_list_insert(&mip6_bc_list, mbc))
					return (-1);

				/* create encapsulation entry */
				/* XXX */
				mip6_tunnel_control(MIP6_TUNNEL_ADD,
						    mbc,
						    mip6_bc_encapcheck,
						    &mbc->mbc_encap);

				/* add rtable for proxy ND */
				mip6_bc_proxy_control(&haddr, haaddr, RTM_ADD);
			} else {
				/* update a BC entry. */
				mbc->mbc_pcoa = *coa;
				mbc->mbc_flags = bu_opt->ip6ou_flags;
#ifdef MIP6_DRAFT13
				mbc->mbc_prefixlen = bu_opt->ip6ou_prefixlen;
#endif /* MIP6_DRAFT13 */
				mbc->mbc_seqno = seqno;
				mbc->mbc_lifetime = lifetime;
				mbc->mbc_remain = mbc->mbc_lifetime;

				/* modify encapsulation entry */
				/* XXX */
				mip6_tunnel_control(MIP6_TUNNEL_ADD,
						    mbc,
						    mip6_bc_encapcheck,
						    &mbc->mbc_encap);
			}
		}
	}

	if (bu_opt->ip6ou_flags & IP6_BUF_DAD) {
		/* XXX DAD */
	} else {
		/* return BA */
		if (mip6_bc_send_ba(haaddr, haddr0, coa,
				    MIP6_BA_STATUS_ACCEPTED,
				    seqno,
				    lifetime,
				    lifetime / 2 /* XXX */)) {
			mip6log((LOG_ERR,
				 "%s:%d: sending BA to %s(%s) failed. "
				 "send it later.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&mbc->mbc_phaddr),
				 ip6_sprintf(&mbc->mbc_pcoa)));
		}
	}

	return (0);
}

static int
mip6_bc_send_ba(src, dst, dstcoa, status, seqno, lifetime, refresh)
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *dstcoa;
	u_int8_t status;
	MIP6_SEQNO_T seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
#if 0
	struct ip6_rthdr *pktopt_rthdr;
#endif
	struct ip6_dest *pktopt_badest2;

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(src, dst, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: creating ip6hdr failed.\n",
			 __FILE__, __LINE__));
		return (-1);
	}

#if 0 /* rthdr will be added in ip6_output. */
	/* create a rthdr. */
	if (mip6_rthdr_create(&pktopt_rthdr, dstcoa)) {
		return (-1);
	}
	opt.ip6po_rthdr = pktopt_rthdr;
#endif

	if(mip6_ba_destopt_create(&pktopt_badest2,
				  status, seqno, lifetime, refresh)) {
		free(opt.ip6po_rthdr, M_TEMP);
		return (NULL);
	}
	opt.ip6po_dest2 = pktopt_badest2;

	if (ip6_output(m, &opt, NULL, 0, NULL, NULL)) {
		mip6log((LOG_ERR,
			 "%s:%d: sending ip packet error.\n",
			 __FILE__, __LINE__));
	}

	free(opt.ip6po_dest2, M_TEMP);

	return (0);
}

static int
mip6_bc_proxy_control(target, local, cmd)
	struct in6_addr *target;
	struct in6_addr *local;
	int cmd;
{
	struct sockaddr_in6 mask; /* = {sizeof(mask), AF_INET6 } */
	struct sockaddr_in6 sa6;
	struct sockaddr_dl *sdl;
        struct rtentry *rt, *nrt;
	struct ifaddr *ifa;
	struct ifnet *ifp;
	int flags, error = 0;

	switch (cmd) {
	case RTM_DELETE:
		bzero(&sa6, sizeof(struct sockaddr_in6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_len = sizeof(struct sockaddr_in6);
		sa6.sin6_addr = *target;

#ifdef __FreeBSD__
		rt = rtalloc1((struct sockaddr *)&sa6, 1, 0UL);
#else /* __FreeBSD__ */
		rt = rtalloc1((struct sockaddr *)&sa6, 1);
#endif /* __FreeBSD__ */
		if (rt == NULL)
			return EHOSTUNREACH;

		error = rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
				  rt_mask(rt), 0, (struct rtentry **)0);
		rt->rt_refcnt--;
		rt = NULL;
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: RTM_DELETE for %s returned "
				 "error = %d\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(target), error));
		}

		break;

	case RTM_ADD:
		bzero(&sa6, sizeof(struct sockaddr_in6));
		sa6.sin6_len = sizeof(struct sockaddr_in6);
		sa6.sin6_family = AF_INET6;
		sa6.sin6_addr = *target;

#ifdef __FreeBSD__
		rt = rtalloc1((struct sockaddr *)&sa6, 0, 0UL);
#else /* __FreeBSD__ */
		rt = rtalloc1((struct sockaddr *)&sa6, 0);
#endif /* __FreeBSD__ */
		if (rt && (rt->rt_flags & RTF_ANNOUNCE) != 0 &&
		    rt->rt_gateway->sa_family == AF_LINK) {
			mip6log((LOG_NOTICE,
				 "%s:%d: RTM_ADD: we are already proxy for %s\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(target)));
			return (EEXIST);
		}

		/* Create sa6 */
		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_len = sizeof(sa6);
		sa6.sin6_addr = *local;

		ifa = ifa_ifwithaddr((struct sockaddr *)&sa6);
		if (ifa == NULL)
			return EINVAL;
		sa6.sin6_addr = *target;

		/* Create sdl */
		ifp = ifa->ifa_ifp;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
		for (ifa = ifp->if_addrlist.tqh_first; ifa;
		     ifa = ifa->ifa_list.tqe_next)
#endif
			if (ifa->ifa_addr->sa_family == AF_LINK) break;

		if (!ifa)
			return EINVAL;

		MALLOC(sdl, struct sockaddr_dl *, ifa->ifa_addr->sa_len,
		       M_IFMADDR, M_NOWAIT);
		if (sdl == NULL)
			return EINVAL;
		bcopy((struct sockaddr_dl *)ifa->ifa_addr, sdl, ifa->ifa_addr->sa_len);

		/* Create mask */
		bzero(&mask, sizeof(mask));
		mask.sin6_family = AF_INET6;
		mask.sin6_len = sizeof(mask);

		in6_prefixlen2mask(&mask.sin6_addr, 128);
		flags = (RTF_STATIC | RTF_ANNOUNCE | RTA_NETMASK);

		error = rtrequest(RTM_ADD, (struct sockaddr *)&sa6,
				  (struct sockaddr *)sdl,
				  (struct sockaddr *)&mask, flags, &nrt);

		if (error == 0) {
			/* Avoid expiration */
			if (nrt) {
				nrt->rt_rmx.rmx_expire = 0;
				nrt->rt_genmask = NULL;
				nrt->rt_refcnt--;
			} else
				error = EINVAL;
		} else {
			mip6log((LOG_ERR,
				 "%s:%d: RTM_ADD for %s returned "
				 "error = %d\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(target), error));
		}
		
		{
			/* very XXX */
			struct in6_addr daddr
				= IN6ADDR_LINKLOCAL_ALLNODES_INIT;
			
			nd6_na_output(ifp, &daddr, target,
				      ND_NA_FLAG_OVERRIDE,
				      1,
				      (struct sockaddr *)sdl);
		}

		free(sdl, M_IFMADDR);

		break;

	default:
		mip6log((LOG_ERR,
			 "%s:%d: we only support RTM_ADD/DELETE operation.\n",
			 __FILE__, __LINE__));
		error = -1;
		break;
	}

	return (error);
}

/*
 * check whether this address needs dad or not
 */
int
mip6_ifa_need_dad(ia)
	struct in6_ifaddr *ia;
{
	struct hif_softc *sc = NULL;
	struct mip6_bu *mbu = NULL;
	int need_dad = 0;

	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		mbu = mip6_bu_list_find_home_registration(
			&sc->hif_bu_list,
			&ia->ia_addr.sin6_addr);
		if (mbu != NULL)
			break;
	}
if(mbu)	mip6_bu_print(mbu);
	if ((mbu == NULL) || (mbu->mbu_lifetime <= 0))
		need_dad = 1;

	return (need_dad);
}

#ifdef MIP6_DEBUG
void
mip6_bu_print(mbu)
	struct mip6_bu *mbu;
{
	mip6log((LOG_INFO,
		 "paddr      %s\n"
		 "haddr      %s\n"
		 "coa        %s\n"
		 "lifetime   %lu\n"
		 "remain     %lld\n"
		 "refresh    %lu\n"
		 "refremain  %lld\n"
		 "acktimeout %lu\n"
		 "ackremain  %lld\n"
		 "seqno      %u\n"
		 "flags      0x%x\n"
		 "state      0x%x\n"
		 "hif        0x%p\n"
		 "dontsend   %u\n"
		 "coafb      %u\n"
		 "reg_state  %u\n",
		 ip6_sprintf(&mbu->mbu_paddr),
		 ip6_sprintf(&mbu->mbu_haddr),
		 ip6_sprintf(&mbu->mbu_coa),
		 (u_long)mbu->mbu_lifetime,
		 (long long)mbu->mbu_remain,
		 (u_long)mbu->mbu_refresh,
		 (long long)mbu->mbu_refremain,
		 (u_long)mbu->mbu_acktimeout,
		 (long long)mbu->mbu_ackremain,
		 mbu->mbu_seqno,
		 mbu->mbu_flags,
		 mbu->mbu_state,
		 mbu->mbu_hif,
		 mbu->mbu_dontsend,
		 mbu->mbu_coafallback,
		 mbu->mbu_reg_state));

}
#endif /* MIP6_DEBUG */


/*
 * binding ack management functions.
 */

/*
 * Binding Ackowledgements validation.
 * draft-14 section 10.13
 */
int
mip6_validate_ba(m, opt)
	struct mbuf *m;
	u_int8_t *opt;
{
	struct ip6_hdr *ip6;
	struct ip6_opt_binding_ack *ba_opt;
	MIP6_SEQNO_T		   seqno;
	struct mip6_bu             *mbu;
	struct hif_softc           *sc;

	ip6 = mtod(m, struct ip6_hdr *);
	ba_opt = (struct ip6_opt_binding_ack *)(opt);

#ifdef MIP6_DRAFT13	    
	/* Make sure that the BA is protected by an AH (see 4.4, 10.12). */
#ifdef IPSEC
#ifndef __OpenBSD__
	if (!mip6_use_ipsec &&
	    !((m->m_flags & M_AUTHIPHDR) && (m->m_flags & M_AUTHIPDGM))) {
		mip6log((LOG_NOTICE,
			 "%s:%d: an unprotected BA from %s.\n",
			 __FILE__, __LINE__,
			 ip6_sprintf(&ip6->ip6_src)));
		/* silently ignore */
		return (1);
	}
#endif /* __OpenBSD__ */
#endif /* IPSEC */
#endif /* MIP6_DRAFT13 */

	/* Make sure that the length field in the BA is >= IP6OPT_BALEN. */
	if (ba_opt->ip6oa_len < IP6OPT_BALEN) {
		ip6stat.ip6s_badoptions++;
		mip6log((LOG_NOTICE,
			 "%s:%d: received BA is too short (%d) from host %s.\n",
			 __FILE__, __LINE__,
			 ba_opt->ip6oa_len,
			 ip6_sprintf(&ip6->ip6_src)));
		/* silently ignore */
		return (1);
	}

	/*
	 * XXX: TODO
	 *
	 * draft-15 introduces a new sub-option to authenticate
	 * binding packets.  we should check the sub-option and make
	 * sure the packet is protected by the some authentication
	 * mechanisms.
	 */

	/*
	 * check if the seq number of the send BU == the seq number of
	 * the received BA.
	 */
	sc = hif_list_find_withhaddr(&ip6->ip6_dst);
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &ip6->ip6_src);
	if (mbu == NULL) {
		mip6log((LOG_NOTICE,
			 "%s:%d: no matching BU entry found.\n",
			 __FILE__, __LINE__));
		/* silently ignore */
		return (1);
	}
#ifdef MIP6_DRAFT13
	seqno = ntohs(ba_opt->ip6oa_seqno);
#else
	seqno = ba_opt->ip6oa_seqno;
	if (ba_opt->ip6oa_status == MIP6_BA_STATUS_SEQNO_TOO_SMALL) {
		/*
		 * our HA has a greater seq number in her binging
		 * cache entriy of mine.  we should resent binding
		 * update with greater than the seq number of the
		 * already exists binding cache.  this binding ack is
		 * valid though the seq number doesn't match.
		 */
		goto validate_ba_valid;
	}
	else
#endif /* MIP6_DRAFT13 */
	if (seqno != mbu->mbu_seqno) {
		ip6stat.ip6s_badoptions++;
		mip6log((LOG_NOTICE,
			 "%s:%d: unmached sequence no "
			 "(%d recv, %d sent) from host %s.\n",
			 __FILE__, __LINE__,
			 seqno,
			 mbu->mbu_seqno,
			 ip6_sprintf(&ip6->ip6_src)));
		/* silently ignore */
		return (1);
	}

#ifndef MIP6_DRAFT13
 validate_ba_valid:
#endif /* !MIP6_DRAFT13 */
	/* we have a valid BA */
	return (0);
}

/*
 * binding acknowledgment processing
 */
int
mip6_process_ba(m, opt)
	struct mbuf *m;
	u_int8_t *opt;
{
	struct ip6_hdr *ip6;
	struct hif_softc *sc;
	struct ip6_opt_binding_ack *ba_opt;
	struct mip6_bu *mbu;
	u_int32_t lifetime;
	int error = 0;

	ip6 = mtod(m, struct ip6_hdr *);
	ba_opt = (struct ip6_opt_binding_ack *)opt;
	sc = hif_list_find_withhaddr(&ip6->ip6_dst);

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &ip6->ip6_src);
	if (mbu == NULL) {
		mip6log((LOG_NOTICE,
			 "%s:%d: no matching BU entry found from host %s.\n",
			 __FILE__, __LINE__, ip6_sprintf(&ip6->ip6_src)));
		/* ignore */
		return (0);
	}

	if (ba_opt->ip6oa_status >= MIP6_BA_STATUS_ERRORBASE) {
		mip6log((LOG_NOTICE, 
			 "%s:%d: BU rejected (error code %d).\n",
			 __FILE__, __LINE__, ba_opt->ip6oa_status));
#ifndef MIP6_DRAFT13
		if (ba_opt->ip6oa_status == MIP6_BA_STATUS_SEQNO_TOO_SMALL) {
			/* seqno is too small.  adjust it and re-send BU. */
			mbu->mbu_seqno = ba_opt->ip6oa_seqno + 1;
			mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
			return (0);
		}
#endif /* !MIP6_DRAFT13 */
		/* BU error handling... */
		error = mip6_bu_list_remove(&sc->hif_bu_list, mbu);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: can't remove BU.\n",
				 __FILE__, __LINE__));
			return (error);
		}
		/* XXX some error recovery process needed. */
		return (0);
	}

	/*
	 * the binding updated has been accepted.  reset WAIT_ACK
	 * status.
	 */
	mbu->mbu_state &= ~MIP6_BU_STATE_WAITACK;

	/*
	 * increment seqno of this binding update entry that matches
	 * with this receiving binding ack.  note that we already have
	 * incremented the seqno of the other binding update entries
	 * those don't require binding acks (the binding update
	 * entries that IP6_BUF_ACK flags are not set.)
	 */
	mbu->mbu_seqno++;

	/* update lifetime and refresh time. */
	lifetime = ntohl(*(u_int32_t *)ba_opt->ip6oa_lifetime);
	if (lifetime < mbu->mbu_lifetime) {
		int64_t remain;
		remain = mbu->mbu_remain - (mbu->mbu_lifetime - lifetime);
		if (remain < 0)
			remain = 0;
		mbu->mbu_remain = remain;
	}
	mbu->mbu_refresh = ntohl(*(u_int32_t *)ba_opt->ip6oa_refresh);
	mbu->mbu_refremain = mbu->mbu_refresh;

	if (mbu->mbu_flags & IP6_BUF_HOME) {
		/* this is from our home agent */

		if (mbu->mbu_reg_state == MIP6_BU_REG_STATE_DEREGWAITACK) {
			/* home unregsitration has completed. */

			/* notify all the CNs that we are home. */
			error = mip6_bu_list_notify_binding_change(sc);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: removing the bining cache entries of all CNs failed.\n",
					 __FILE__, __LINE__));
				return (error);
			}

			/* remove a binding update entry for our homeagent. */
			error = mip6_bu_list_remove(&sc->hif_bu_list, mbu);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: can't remove BU.\n",
					 __FILE__, __LINE__));
				return (error);
			}

			/* remove a tunnel to our homeagent. */
			error = mip6_tunnel_control(MIP6_TUNNEL_DELETE,
						   mbu,
						   mip6_bu_encapcheck,
						   &mbu->mbu_encap);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: tunnel removal failed.\n",
					 __FILE__, __LINE__));
				return (error);
			}

			error = mip6_bu_list_remove_all(&sc->hif_bu_list);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: BU remove all failed.\n",
					 __FILE__, __LINE__));
				return (error);
			}

			/* XXX: TODO send a unsolicited na. */

			/* for safty. */
			mbu->mbu_reg_state = MIP6_BU_REG_STATE_NOTREG;
		} else if (mbu->mbu_reg_state
			   == MIP6_BU_REG_STATE_REGWAITACK) {
			/* home registration completed */
			mbu->mbu_reg_state = MIP6_BU_REG_STATE_REG;

			/* create tunnel to HA */
			error = mip6_tunnel_control(MIP6_TUNNEL_CHANGE,
						    mbu,
						    mip6_bu_encapcheck,
						    &mbu->mbu_encap);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: tunnel move failed.\n",
					 __FILE__, __LINE__));
				return (error);
			}

			/* notify all the CNs that we have a new coa. */
			error = mip6_bu_list_notify_binding_change(sc);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: updating the bining cache entries of all CNs failed.\n",
					 __FILE__, __LINE__));
				return (error);
			}
		} else if (mbu->mbu_reg_state == MIP6_BU_REG_STATE_REG) {
			/* nothing to do. */
		} else {
			mip6log((LOG_NOTICE,
				 "%s:%d: unexpected condition.\n",
				 __FILE__, __LINE__));
		}
	}

	return (0);
}

#ifndef MIP6_DRAFT13
static int
mip6_verify_authdata(m, bu_opt, authdata)
	struct mbuf *m;
	struct ip6_opt_binding_update *bu_opt;
	struct mip6_subopt_authdata *authdata;
{
	/* XXX: TODO */
	return (0);
}

struct mip6_subopt_authdata *
mip6_authdata_create(src, dst, coa, bu_opt)
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *coa;
	struct ip6_opt_binding_update *bu_opt;
{
	struct mip6_subopt_authdata *authdata;
	int size;
	int authdata_size = 0;

	/* XXX: TODO */
	/* find SPI for this src, dst pair. */
	/* determine authdata_size from the SPI found above. */
	authdata_size = 0;
	size = sizeof(*authdata) + authdata_size;
	authdata = malloc(size, M_TEMP, M_NOWAIT);
	if (authdata == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: failed to alloc memory.\n",
			 __FILE__, __LINE__));
		return (NULL);
	}

	bzero((caddr_t)authdata, size);
	/* XXX: TODO */
	/* calc authdata */
	authdata->type = MIP6SUBOPT_AUTHDATA;
	authdata->len = size - 2;

	return (authdata);
}
#endif /* !MIP6_DRAFT13 */

/*
 * binding request management functions
 */
int
mip6_validate_br(m, opt)
	struct mbuf *m;
	u_int8_t *opt;
{
	/* XXX: no need to validate. */

	return (0);
}

int
mip6_process_br(m, opt)
	struct mbuf *m;
	u_int8_t *opt;
{
	struct ip6_hdr *ip6;
	struct ip6_opt_binding_request *br_opt;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	struct mip6_prefix *mpfx;
	int64_t haddr_remain, coa_remain, remain;

	ip6 = mtod(m, struct ip6_hdr *);
	br_opt = (struct ip6_opt_binding_request *)opt;

	sc = hif_list_find_withhaddr(&ip6->ip6_dst);
	if (sc == NULL) {
		/* this BR is not for our home address. */
		return (0);
	}

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &ip6->ip6_src);
	if (mbu == NULL) {
		/* XXX there is no BU for this peer.  create? */
		return (0);
	}

	mpfx = mip6_prefix_list_find_withhaddr(&mip6_prefix_list,
					       &mbu->mbu_haddr);
	if (mpfx == NULL) {
		/*
		 * there are no prefixes associated to the home address.
		 */
		/* XXX */
		return (0);
	}
	haddr_remain = mpfx->mpfx_remain;
	coa_remain = mip6_coa_get_lifetime(&mbu->mbu_coa);
	remain =  (haddr_remain < coa_remain)
		? haddr_remain : coa_remain;
	mbu->mbu_lifetime = (u_int32_t)remain;
	mbu->mbu_remain = mbu->mbu_lifetime;
	mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;

	/*
	 * TOXO: XXX
	 *
	 * unique ideintifier suboption processing.
	 */

	return (0);
}


/*
 * binding cache management functions.
 */

void
mip6_bc_init()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3) 
        callout_init(&mip6_bc_ch);
#endif
}

#ifdef MIP6_DRAFT13
static struct mip6_bc *
mip6_bc_create(phaddr, pcoa, addr, flags, prefixlen, seqno, lifetime, ifp)
	struct in6_addr *phaddr;
	struct in6_addr *pcoa;
	struct in6_addr *addr;
	u_int8_t flags;
	u_int8_t prefixlen;
	MIP6_SEQNO_T seqno;
	u_int32_t lifetime;
	struct ifnet *ifp;
#else
static struct mip6_bc *
mip6_bc_create(phaddr, pcoa, addr, flags, seqno, lifetime, ifp)
	struct in6_addr *phaddr;
	struct in6_addr *pcoa;
	struct in6_addr *addr;
	u_int8_t flags;
	MIP6_SEQNO_T seqno;
	u_int32_t lifetime;
	struct ifnet *ifp;
#endif /* MIP6_DRAFT13 */
{
	struct mip6_bc *mbc;

	MALLOC(mbc, struct mip6_bc *, sizeof(struct mip6_bc),
	       M_TEMP, M_NOWAIT);
	if (mbc == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: memory allocation failed.\n",
			 __FILE__, __LINE__));
		return (NULL);
	}
	bzero(mbc, sizeof(*mbc));

	mbc->mbc_phaddr = *phaddr;
	mbc->mbc_pcoa = *pcoa;
	mbc->mbc_addr = *addr;
	mbc->mbc_flags = flags;
#ifdef MIP6_DRAFT13
	mbc->mbc_prefixlen = prefixlen;
#endif /* MIP6_DRAFT13 */
	mbc->mbc_seqno = seqno;
	mbc->mbc_lifetime = lifetime;
	mbc->mbc_remain = mbc->mbc_lifetime;
	mbc->mbc_state = 0;
	mbc->mbc_ifp = ifp;

	return (mbc);
}

static int
mip6_bc_list_insert(mbc_list, mbc)
	struct mip6_bc_list *mbc_list;
	struct mip6_bc *mbc;
{
	LIST_INSERT_HEAD(mbc_list, mbc, mbc_entry);

	if (mip6_bc_count == 0) {
		mip6log((LOG_INFO, "%s:%d: BC timer started.\n",
			__FILE__, __LINE__));
		mip6_bc_starttimer();
	}
	mip6_bc_count++;

	return (0);
}

int
mip6_bc_list_remove(mbc_list, mbc)
	struct mip6_bc_list *mbc_list;
	struct mip6_bc *mbc;
{
	int error = 0;

	if ((mbc_list == NULL) || (mbc == NULL)) {
		return (EINVAL);
	}

	LIST_REMOVE(mbc, mbc_entry);
	if (mbc->mbc_flags & IP6_BUF_HOME) {
		error = mip6_bc_proxy_control(&mbc->mbc_phaddr, NULL,
					      RTM_DELETE);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: can't delete a proxy ND entry "
				 "for %s.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&mbc->mbc_phaddr)));
		}
	}
	FREE(mbc, M_TEMP);

	mip6_bc_count--;
	if (mip6_bc_count == 0) {
		mip6_bc_stoptimer();
		mip6log((LOG_INFO, "%s:%d: BC timer stopped.\n",
			__FILE__, __LINE__));
	}

	return (0);
}

struct mip6_bc *
mip6_bc_list_find_withphaddr(mbc_list, haddr)
	struct mip6_bc_list *mbc_list;
	struct in6_addr *haddr;
{
	struct mip6_bc *mbc;

	for (mbc = LIST_FIRST(mbc_list); mbc;
	     mbc = LIST_NEXT(mbc, mbc_entry)) {
		if (IN6_ARE_ADDR_EQUAL(&mbc->mbc_phaddr, haddr))
			break;
	}

	return (mbc);
}

struct mip6_bc *
mip6_bc_list_find_withcoa(mbc_list, pcoa)
	struct mip6_bc_list *mbc_list;
	struct in6_addr *pcoa;
{
	struct mip6_bc *mbc;

	for (mbc = LIST_FIRST(mbc_list); mbc;
	     mbc = LIST_NEXT(mbc, mbc_entry)) {
		if (IN6_ARE_ADDR_EQUAL(&mbc->mbc_pcoa, pcoa))
			break;
	}

	return (mbc);
}

static void
mip6_bc_timeout(dummy)
	void *dummy;
{
	int s;
	struct mip6_bc *mbc, *mbc_next;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif

	for (mbc = LIST_FIRST(&mip6_bc_list); mbc; mbc = mbc_next) {
		mbc_next = LIST_NEXT(mbc, mbc_entry);
		mbc->mbc_remain -= MIP6_BC_TIMEOUT_INTERVAL;

		/* expiration check */
		if (mbc->mbc_remain < 0) {
			mip6_bc_list_remove(&mip6_bc_list, mbc);
		}

		/* XXX send BR if BR_WAITSENT is remained not
		   piggybacked before */

		/* XXX set BR_WAITSENT when BC is going to expire */
		if (mbc->mbc_remain < (mbc->mbc_lifetime / 4)) { /* XXX */
			mbc->mbc_state |= MIP6_BC_STATE_BR_WAITSENT;
		}

		/* XXX send BA if BA_WAITSENT is remained not
		   piggybacked before */
		if (mbc->mbc_state & MIP6_BC_STATE_BA_WAITSENT) {
			
		}
	}

	mip6_bc_starttimer();

	splx(s);
}

static void
mip6_bc_stoptimer(void)
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&mip6_bc_ch);
#else
	untimeout(mip6_bc_timeout, (void *)0);
#endif
}

static void mip6_bc_starttimer(void)
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&mip6_bc_ch,
		      MIP6_BC_TIMEOUT_INTERVAL * hz,
		      mip6_bc_timeout, NULL);
#else
	timeout(mip6_bc_timeout, (void *)0,
		MIP6_BC_TIMEOUT_INTERVAL * hz);
#endif
}


/*
 * tunneling functions.
 */
static int
mip6_tunnel_control(action, entry, func, ep)
	int action;
	void *entry;
	int (*func) __P((const struct mbuf *, int, int, void *));
	const struct encaptab **ep;
{
	if ((entry == NULL) || (ep == NULL)) {
		return (EINVAL);
	}

	if ((action == MIP6_TUNNEL_CHANGE) && *ep) {
		encap_detach(*ep);
	}

	switch (action) {
	case MIP6_TUNNEL_ADD:
	case MIP6_TUNNEL_CHANGE:
		*ep = encap_attach_func(AF_INET6, IPPROTO_IPV6,
					func,
					&mip6_tunnel_protosw,
					(void *)entry);
		if (*ep == NULL) {
			return (EINVAL);
		}
		break;
	}

	return (0);
}

static int
mip6_bu_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip6_hdr *ip6;
	struct mip6_bu *mbu = (struct mip6_bu *)arg;
	struct hif_softc *sc;
	struct hif_subnet_list *hs_list_home, *hs_list_foreign;
	struct hif_subnet *hs;
	struct mip6_subnet *ms;
	struct mip6_subnet_prefix *mspfx;
	struct mip6_prefix *mpfx;
	struct in6_addr *encap_src, *encap_dst;
	struct in6_addr *haaddr, *myaddr, *mycoa;

	if (mbu == NULL) {
		return (0);
	}
	if ((sc = mbu->mbu_hif) == NULL) {
		return (0);
	}
	if (((hs_list_home = &sc->hif_hs_list_home) == NULL)
	    || (hs_list_foreign = &sc->hif_hs_list_foreign) == NULL) {
		return (0);
	}

	ip6 = mtod(m, struct ip6_hdr*);

	encap_src = &ip6->ip6_src;
	encap_dst = &ip6->ip6_dst;
	haaddr = &mbu->mbu_paddr;
	myaddr = &mbu->mbu_haddr;
	mycoa = &mbu->mbu_coa;

	/*
	 * check wether this packet is from the correct sender (that
	 * is, our home agent) to the CoA the mobile node has
	 * registered before.
	 */
	if (!IN6_ARE_ADDR_EQUAL(encap_src, haaddr) ||
	    !IN6_ARE_ADDR_EQUAL(encap_dst, mycoa)) {
		return (0);
	}

	/*
	 * XXX: should we compare the ifid of the inner dstaddr of the
	 * incoming packet and the ifid of the mobile node's?  these
	 * check will be done in the ip6_input and later.
	 */

	/* check mn prefix */
	for (hs = TAILQ_FIRST(hs_list_home); hs;
	     hs = TAILQ_NEXT(hs, hs_entry)) {
		if ((ms = hs->hs_ms) == NULL) {
			/* must not happen. */
			continue;
		}
		for (mspfx = TAILQ_FIRST(&ms->ms_mspfx_list); mspfx;
		     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
			if ((mpfx = mspfx->mspfx_mpfx) == NULL)	{
				/* must not happen. */
				continue;
			}
			if (!in6_are_prefix_equal(myaddr,
						  &mpfx->mpfx_prefix,
						  mpfx->mpfx_prefixlen)) {
				/* this prefix doesn't match my prefix.
				   check next. */
				continue;
			}
			goto match;
		}
	}
	for (hs = TAILQ_FIRST(hs_list_foreign); hs;
	     hs = TAILQ_NEXT(hs, hs_entry)) {
		if ((ms = hs->hs_ms) == NULL) {
			/* must not happen. */
			continue;
		}
		for (mspfx = TAILQ_FIRST(&ms->ms_mspfx_list); mspfx;
		     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
			if ((mpfx = mspfx->mspfx_mpfx) == NULL)	{
				/* must not happen. */
				continue;
			}
			if (!in6_are_prefix_equal(myaddr,
						  &mpfx->mpfx_prefix,
						  mpfx->mpfx_prefixlen)) {
				/* this prefix doesn't match my prefix.
				   check next. */
				continue;
			}
			goto match;
		}
	}
	return (0);
 match:
	return (128);
}

static int
mip6_bc_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip6_hdr *ip6;
	struct mip6_bc *mbc = (struct mip6_bc *)arg;
	struct in6_addr *encap_src, *encap_dst;
	struct in6_addr *mnaddr;

	if (mbc == NULL) {
		return (0);
	}

	ip6 = mtod(m, struct ip6_hdr*);

	encap_src = &ip6->ip6_src;
	encap_dst = &ip6->ip6_dst;
	mnaddr = &mbc->mbc_pcoa;

	/* check mn addr */
	if (!IN6_ARE_ADDR_EQUAL(encap_src, mnaddr)) {
		return (0);
	}

	/* check my addr */
	/* XXX */

	return (128);
}

/*
 ******************************************************************************
 * Function:    mip6_tunnel_input
 * Description: similar to gif_input() and in6_gif_input().
 * Ret value:	standard error codes.
 ******************************************************************************
 */
int
mip6_tunnel_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
	int s;

	ip6 = mtod(m, struct ip6_hdr *);
	m_adj(m, *offp);

	switch (proto) {
	case IPPROTO_IPV6:
	{
		struct ip6_hdr *ip6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return (IPPROTO_DONE);
		}

		ip6 = mtod(m, struct ip6_hdr *);

		s = splimp();
		if (IF_QFULL(&ip6intrq)) {
			IF_DROP(&ip6intrq);	/* update statistics */
			splx(s);
			goto bad;
		}
		IF_ENQUEUE(&ip6intrq, m);
#if 0
		/* we don't need it as we tunnel IPv6 in IPv6 only. */
		schednetisr(NETISR_IPV6);
#endif
		splx(s);
		break;
	}
	default:
		mip6log((LOG_ERR,
			 "%s:%d: protocol %d not supported.\n",
			 __FILE__, __LINE__,
			 proto));
		goto bad;
	}

	return (IPPROTO_DONE);

 bad:
	m_freem(m);
	return (IPPROTO_DONE);
}

/*
 * encapsulate the packet from the correspondent node to the mobile
 * node that is communicating.  the encap_src is to be a home agent's
 * address and the encap_dst is to be a mobile node coa, according to
 * the binding cache entry for the destined mobile node.
 */
int
mip6_tunnel_output(mp, mbc)
	struct mbuf **mp;    /* the original ipv6 packet */
	struct mip6_bc *mbc; /* the bc entry for the dst of the pkt */
{
	struct sockaddr_in6 dst;
	const struct encaptab *ep = mbc->mbc_encap;
	struct mbuf *m = *mp;
	struct in6_addr *encap_src = &mbc->mbc_addr;
	struct in6_addr *encap_dst = &mbc->mbc_pcoa;
	struct ip6_hdr *ip6;
	int len;

	bzero(&dst, sizeof(dst));
	dst.sin6_len = sizeof(struct sockaddr_in6);
	dst.sin6_family = AF_INET6;
	dst.sin6_addr = mbc->mbc_pcoa;

	if (ep->af != AF_INET6)
		return (EFAULT);

	/* Recursion problems? */

	if (IN6_IS_ADDR_UNSPECIFIED(encap_src))
		return (EFAULT);

	len = m->m_pkthdr.len; /* payload length */

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return (ENOBUFS);
	}
	ip6 = mtod(m, struct ip6_hdr *);

	/* prepend new, outer ipv6 header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: ENOBUFS in mip6_tunnel_output\n",
			 __FILE__, __LINE__));
		return (ENOBUFS);
	}

	/* fill the outer header */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
	ip6->ip6_plen	= htons((u_short)len);
	ip6->ip6_nxt	= IPPROTO_IPV6;
	ip6->ip6_hlim	= ip6_defhlim;
	ip6->ip6_src	= *encap_src;

	/* bidirectional configured tunnel mode */
	if (!IN6_IS_ADDR_UNSPECIFIED(encap_dst))
		ip6->ip6_dst = *encap_dst;
	else {
		m_freem(m);
		return ENETUNREACH;
	}
#if defined(IPV6_MINMTU) && 0
	/*
	 * force fragmentation to minimum MTU, to avoid path MTU discovery.
	 * it is too painful to ask for resend of inner packet, to achieve
	 * path MTU discovery for encapsulated packets.
	 */
	return(ip6_output(m, 0, 0, IPV6_MINMTU, 0, NULL));
#else
	return(ip6_output(m, 0, 0, 0, 0, NULL));
#endif
}

/*
 * if packet is tunneled, send BU to the peer for route optimization.
 */
/*
 * the algorithm below is worth considering
 *
 * from Hesham Soliman on mobile-ip
 * <034BEFD03799D411A59F00508BDF754603008B1F@esealnt448.al.sw.ericsson.se>
 *
 * - Did the packet contain a routing header ?
 * - Did the routing header contain the Home address of the 
 *  MN as the last segment and its CoA (as specified in the BU list) ?
 *
 * If the answer to both is yes then the packet was route optimised.
 * if no then it wasn't and it doesn't really matter whether it was 
 * tunnelled by THE HA or another node. 
 * This will have two advantages (outside the HMIPv6 area) :
 *
 * - Simpler processing in the kernel since the MIPv6 code would
 *   not have to "remember" whether the inner packet being processed
 *   now was originally tunnelled.
 *
 * - Will allow for future HA redundancy mechanisms because if the 
 *   HA crashes and another HA starts tunnelling the packet the 
 *   MN does not need to know or care. Excet of course when it's 
 *   about to refresh the Binding Cache but that can be handled 
 *   by the HA redundancy protocol.
 */
int
mip6_route_optimize(m)
	struct mbuf *m;
{
	struct mbuf *n;
	struct ip6aux *ip6a;
	struct ip6_hdr *ip6;
	struct mip6_prefix *mpfx;
	struct mip6_bu *mbu;
	struct hif_softc *sc;
	int32_t coa_lifetime;
	int error = 0;

	if (!MIP6_IS_MN) {
		/* only MN does the route optimization. */
		return (0);
	}

	ip6 = mtod(m, struct ip6_hdr *);
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
		return (0);
	}
	
	n = ip6_findaux(m);
	if (n) {
		ip6a = mtod(n, struct ip6aux *);
		if (ip6a->ip6a_flags & IP6A_ROUTEOPTIMIZED) {
			/* no need to optimize route. */
			return (0);
		}
	}
	/*
	 * this packet has no rthdr or has a rthdr not related mip6
	 * route optimization.
	 */

	/* check if we are home. */
	sc = hif_list_find_withhaddr(&ip6->ip6_dst);
	if (sc == NULL) {
		/* this dst addr is not one of our home addresses. */
		return (0);
	}
	if (sc->hif_location == HIF_LOCATION_HOME) {
		/* we are home.  no route optimization is required. */
		return (0);
	}

	/*
	 * find a mip6_prefix which has a home address of received
	 * packet.
	 */
	mpfx = mip6_prefix_list_find_withhaddr(&mip6_prefix_list,
					       &ip6->ip6_dst);
	if (mpfx == NULL) {
		/*
		 * no related prefix found.  this packet is
		 * destined to another address of this node
		 * that is not a home address.
		 */
		return (0);
	}

	/*
	 * search all binding update entries with the address of the
	 * peer sending this un-optimized packet.
	 */
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list,
					  &ip6->ip6_src);
	if (mbu == NULL) {
		/*
		 * if no binding update entry is found, this is a
		 * first packet from the peer.  create a new binding
		 * update entry for this peer.
		 */
		mbu = mip6_bu_create(&ip6->ip6_src,
				     mpfx,
				     &hif_coa,
				     0, sc);
		if (mbu == NULL) {
			error = ENOMEM;
			goto bad;
		}
		mbu->mbu_state = MIP6_BU_STATE_WAITSENT;

		mip6_bu_list_insert(&sc->hif_bu_list, mbu);
	} else {
		/*
		 * found a binding update entry.  we should resend a
		 * binding update to this peer because he is not add
		 * routing header for the route optimization.
		 */
		mbu->mbu_coa = hif_coa;
		coa_lifetime = mip6_coa_get_lifetime(&mbu->mbu_coa);
		if (coa_lifetime < mpfx->mpfx_lifetime) {
			mbu->mbu_lifetime = coa_lifetime;
		} else {
			mbu->mbu_lifetime = mpfx->mpfx_lifetime;
		}
		mbu->mbu_remain = mbu->mbu_lifetime;
		mbu->mbu_refresh = mbu->mbu_lifetime;
		mbu->mbu_refremain = mbu->mbu_refresh;
		mbu->mbu_state = MIP6_BU_STATE_WAITSENT;
	}

	return (0);
 bad:
	m_freem(m);
	return (error);
}
