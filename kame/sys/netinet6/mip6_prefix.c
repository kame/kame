/*	$KAME: mip6_prefix.c,v 1.33 2004/06/02 05:53:16 itojun Exp $	*/

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

#ifdef __FreeBSD__
#include "opt_ipsec.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_ipsec.h"
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

#if defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

#if (defined(__FreeBSD__) && __FreeBSD_version >= 501000)
#include <sys/limits.h>
#elif defined(__FreeBSD__)
#include <machine/limits.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet/ip6mh.h>

#include <net/if_hif.h>

#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#include <netinet6/mip6_mncore.h>

struct mip6_prefix_list mip6_prefix_list;

static int mip6_prefix_send_mps(struct mip6_prefix *);
static void mip6_prefix_timer(void *);

void
mip6_prefix_init(void)
{
	LIST_INIT(&mip6_prefix_list);
}

struct mip6_prefix *
mip6_prefix_create(prefix, prefixlen, vltime, pltime)
	struct in6_addr *prefix;
	u_int8_t prefixlen;
	u_int32_t vltime;
	u_int32_t pltime;
{
	struct in6_addr mask;
	struct mip6_prefix *mpfx;

	MALLOC(mpfx, struct mip6_prefix *, sizeof(struct mip6_prefix),
	       M_TEMP, M_NOWAIT);
	if (mpfx == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: memory allocation failed.\n",
			 __FILE__, __LINE__));
		return (NULL);
	}
	bzero(mpfx, sizeof(*mpfx));
	in6_prefixlen2mask(&mask, prefixlen);
	mpfx->mpfx_prefix = *prefix;
	mpfx->mpfx_prefix.s6_addr32[0] &= mask.s6_addr32[0];
	mpfx->mpfx_prefix.s6_addr32[1] &= mask.s6_addr32[1];
	mpfx->mpfx_prefix.s6_addr32[2] &= mask.s6_addr32[2];
	mpfx->mpfx_prefix.s6_addr32[3] &= mask.s6_addr32[3];
	mpfx->mpfx_prefixlen = prefixlen;
	/* XXX mpfx->mpfx_haddr; */
	LIST_INIT(&mpfx->mpfx_ha_list);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&mpfx->mpfx_timer_ch, NULL);
#elif defined(__NetBSD__) || defined(__FreeBSD__)
	callout_init(&mpfx->mpfx_timer_ch);
#elif defined(__OpenBSD__)
	timeout_set(&mpfx->mpfx_timer_ch, mip6_prefix_timer, mpfx);
#endif

	/* set initial timeout. */
	mip6_prefix_update_lifetime(mpfx, vltime, pltime);

	return (mpfx);
}


#define MIP6_PREFIX_EXPIRE_TIME(ltime) ((ltime) / 4 * 3) /* XXX */
void
mip6_prefix_update_lifetime(mpfx, vltime, pltime)
	struct mip6_prefix *mpfx;
	u_int32_t vltime;
	u_int32_t pltime;
{
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif

	if (mpfx == NULL)
		panic("mip6_prefix_update_lifetime: mpfx == NULL");

	mip6_prefix_settimer(mpfx, -1);

	mpfx->mpfx_vltime = vltime;
	mpfx->mpfx_pltime = pltime;

	if (mpfx->mpfx_vltime == ND6_INFINITE_LIFETIME) {
		mpfx->mpfx_vlexpire = 0;
	} else {
		mpfx->mpfx_vlexpire = mono_time.tv_sec + mpfx->mpfx_vltime;
	}
	if (mpfx->mpfx_pltime == ND6_INFINITE_LIFETIME) {
		mpfx->mpfx_plexpire = 0;
	} else {
		mpfx->mpfx_plexpire = mono_time.tv_sec + mpfx->mpfx_pltime;
	}

	if (mpfx->mpfx_pltime != ND6_INFINITE_LIFETIME) {
		mip6_prefix_settimer(mpfx,
		    MIP6_PREFIX_EXPIRE_TIME(mpfx->mpfx_pltime) * hz);
		mpfx->mpfx_state = MIP6_PREFIX_STATE_PREFERRED;
	} else if (mpfx->mpfx_vltime != ND6_INFINITE_LIFETIME) {
		mip6_prefix_settimer(mpfx,
		    MIP6_PREFIX_EXPIRE_TIME(mpfx->mpfx_vltime) * hz);
		mpfx->mpfx_state = MIP6_PREFIX_STATE_PREFERRED;
	}
}

int
mip6_prefix_haddr_assign(mpfx, sc)
	struct mip6_prefix *mpfx;
	struct hif_softc *sc;
{
	struct in6_addr ifid;
	int error = 0;

	if ((mpfx == NULL) || (sc == NULL)) {
		return (EINVAL);
	}
#ifdef MIP6_STATIC_HADDR
	if (!IN6_IS_ADDR_UNSPECIFIED(&sc->hif_ifid)) {
		ifid.s6_addr32[2] = sc->hif_ifid.s6_addr32[2];
		ifid.s6_addr32[3] = sc->hif_ifid.s6_addr32[3];
	} else
#endif
	{
		error = get_ifid((struct ifnet *)sc, NULL, &ifid);
		if (error)
			return (error);
	}

	/* XXX */
	mpfx->mpfx_haddr = mpfx->mpfx_prefix;
	mpfx->mpfx_haddr.s6_addr32[2] = ifid.s6_addr32[2];
	mpfx->mpfx_haddr.s6_addr32[3] = ifid.s6_addr32[3];

	return (0);
}

static int
mip6_prefix_send_mps(mpfx)
	struct mip6_prefix *mpfx;
{
	struct hif_softc *hif;
	struct mip6_bu *mbu;
	int error = 0;

	for (hif = LIST_FIRST(&hif_softc_list); hif;
	    hif = LIST_NEXT(hif, hif_entry)) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&mpfx->mpfx_haddr)) {
			mbu = mip6_bu_list_find_home_registration(
			    &hif->hif_bu_list, &mpfx->mpfx_haddr);
			if (mbu != NULL) {
				error = mip6_icmp6_mp_sol_output(
				    &mbu->mbu_haddr, &mbu->mbu_paddr);
				break;
			}
		}
	}
	return (error);
}

void
mip6_prefix_settimer(mpfx, tick)
	struct mip6_prefix *mpfx;
	long tick;
{
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif
	int s;

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif /* __FreeBSD__ */

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	if (tick < 0) {
		mpfx->mpfx_timeout = 0;
		mpfx->mpfx_ntick = 0;
#if defined(__NetBSD__) || defined(__FreeBSD__)
		callout_stop(&mpfx->mpfx_timer_ch);
#elif defined(__OpenBSD__)
		timeout_del(&mpfx->mpfx_timer_ch);
#else
		untimeout(mip6_prefix_timer, mpfx);
#endif
	} else {
		mpfx->mpfx_timeout = mono_time.tv_sec + tick / hz;
		if (tick > INT_MAX) {
			mpfx->mpfx_ntick = tick - INT_MAX;
#if defined(__NetBSD__) || defined(__FreeBSD__)
			callout_reset(&mpfx->mpfx_timer_ch, INT_MAX,
			    mip6_prefix_timer, mpfx);
#elif defined(__OpenBSD__)
			timeout_add(&mpfx->mpfx_timer_ch, INT_MAX);
#else
			timeout(mip6_prefix_timer, mpfx, INT_MAX);
#endif
		} else {
			mpfx->mpfx_ntick = 0;
#if defined(__NetBSD__) || defined(__FreeBSD__)
			callout_reset(&mpfx->mpfx_timer_ch, tick,
			    mip6_prefix_timer, mpfx);
#elif defined(__OpenBSD__)
			timeout_add(&mpfx->mpfx_timer_ch, tick);
#else
			timeout(mip6_prefix_timer, mpfx, tick);
#endif
		}
	}

	splx(s);
}

#define MIP6_MOBILE_PREFIX_SOL_INTERVAL 10 /* XXX */
static void
mip6_prefix_timer(arg)
	void *arg;
{
	int s;
	struct mip6_prefix *mpfx;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif /* __FreeBSD__ */

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif /* __FreeBSD__ */

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	mpfx = (struct mip6_prefix *)arg;

	if (mpfx->mpfx_ntick > 0) {
		if (mpfx->mpfx_ntick > INT_MAX) {
			mpfx->mpfx_ntick -= INT_MAX;
			mip6_prefix_settimer(mpfx, INT_MAX);
		} else {
			mpfx->mpfx_ntick = 0;
			mip6_prefix_settimer(mpfx, mpfx->mpfx_ntick);
		}
		splx(s);
		return;
	}

	switch (mpfx->mpfx_state) {
	case MIP6_PREFIX_STATE_PREFERRED:
		if (mip6_prefix_send_mps(mpfx)) {
			mip6log((LOG_ERR,
			    "%s:%d: sending a mobile prefix solicitation "
			    "failed\n",
			    __FILE__, __LINE__));
		}

		if (mpfx->mpfx_vlexpire >
		    mono_time.tv_sec + MIP6_MOBILE_PREFIX_SOL_INTERVAL) {
			mip6_prefix_settimer(mpfx,
			    MIP6_MOBILE_PREFIX_SOL_INTERVAL * hz);
		} else {
			mip6_prefix_settimer(mpfx,
			    (mpfx->mpfx_vlexpire - mono_time.tv_sec) * hz);
		}
		mpfx->mpfx_state = MIP6_PREFIX_STATE_EXPIRING;
		break;

	case MIP6_PREFIX_STATE_EXPIRING:
		if (mpfx->mpfx_vlexpire < mono_time.tv_sec) {
			mip6_prefix_list_remove(&mip6_prefix_list, mpfx);
			break;
		}

		if (mip6_prefix_send_mps(mpfx)) {
			mip6log((LOG_ERR,
			    "%s:%d: sending a mobile prefix solicitation "
			    "failed\n",
			    __FILE__, __LINE__));
		}

		if (mpfx->mpfx_vlexpire >
		    mono_time.tv_sec + MIP6_MOBILE_PREFIX_SOL_INTERVAL) {
			mip6_prefix_settimer(mpfx,
			    MIP6_MOBILE_PREFIX_SOL_INTERVAL * hz);
		} else {
			mip6_prefix_settimer(mpfx,
			    (mpfx->mpfx_vlexpire - mono_time.tv_sec) * hz);
		}
		mpfx->mpfx_state = MIP6_PREFIX_STATE_EXPIRING;
		break;
	}

	splx(s);
}

int
mip6_prefix_list_insert(mpfx_list, mpfx)
	struct mip6_prefix_list *mpfx_list;
	struct mip6_prefix *mpfx;
{
	if ((mpfx_list == NULL) || (mpfx == NULL)) {
		return (EINVAL);
	}

	LIST_INSERT_HEAD(mpfx_list, mpfx, mpfx_entry);

	return (0);
}

int
mip6_prefix_list_remove(mpfx_list, mpfx)
	struct mip6_prefix_list *mpfx_list;
	struct mip6_prefix *mpfx;
{
	struct hif_softc *hif;
	struct mip6_prefix_ha *mpfxha;

	if ((mpfx_list == NULL) || (mpfx == NULL)) {
		return (EINVAL);
	}

	/* remove all references from hif interfaces. */
	for (hif = LIST_FIRST(&hif_softc_list); hif;
	    hif = LIST_NEXT(hif, hif_entry)) {
		hif_prefix_list_remove(&hif->hif_prefix_list_home,
		    hif_prefix_list_find_withmpfx(&hif->hif_prefix_list_home,
			mpfx));
		hif_prefix_list_remove(&hif->hif_prefix_list_foreign,
		    hif_prefix_list_find_withmpfx(&hif->hif_prefix_list_foreign,
			mpfx));
	}

	/* remove all refernces to advertising routers. */
	while (!LIST_EMPTY(&mpfx->mpfx_ha_list)) {
		mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list);
		mip6_prefix_ha_list_remove(&mpfx->mpfx_ha_list, mpfxha);
	}

	LIST_REMOVE(mpfx, mpfx_entry);
	mip6_prefix_settimer(mpfx, -1);
	FREE(mpfx, M_TEMP);

	return (0);
}

struct mip6_prefix *
mip6_prefix_list_find_withprefix(prefix, prefixlen)
	struct in6_addr *prefix;
	int prefixlen;
{
	struct mip6_prefix *mpfx;

	for (mpfx = LIST_FIRST(&mip6_prefix_list); mpfx;
	     mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
		if (in6_are_prefix_equal(prefix, &mpfx->mpfx_prefix, prefixlen)
		    && (prefixlen == mpfx->mpfx_prefixlen)) {
			/* found. */
			return (mpfx);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_prefix *
mip6_prefix_list_find_withhaddr(mpfx_list, haddr)
     struct mip6_prefix_list *mpfx_list;
     struct in6_addr *haddr;
{
	struct mip6_prefix *mpfx;

	for (mpfx = LIST_FIRST(mpfx_list); mpfx;
	     mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
		if (IN6_ARE_ADDR_EQUAL(haddr, &mpfx->mpfx_haddr)) {
			/* found. */
			return (mpfx);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_prefix_ha *
mip6_prefix_ha_list_insert(mpfxha_list, mha)
	struct mip6_prefix_ha_list *mpfxha_list;
	struct mip6_ha *mha;
{
	struct mip6_prefix_ha *mpfxha;

	if ((mpfxha_list == NULL) || (mha == NULL))
		return (NULL);

	mpfxha = mip6_prefix_ha_list_find_withmha(mpfxha_list, mha);
	if (mpfxha != NULL)
		return (mpfxha);

	MALLOC(mpfxha, struct mip6_prefix_ha *, sizeof(struct mip6_prefix_ha),
	    M_TEMP, M_NOWAIT);
	if (mpfxha == NULL) {
		mip6log((LOG_ERR, "%s:%d: memory allocation failed.\n",
		    __FILE__, __LINE__));
		return (NULL);
	}
	mpfxha->mpfxha_mha = mha;
	LIST_INSERT_HEAD(mpfxha_list, mpfxha, mpfxha_entry);
	return (mpfxha);
}

void
mip6_prefix_ha_list_remove(mpfxha_list, mpfxha)
	struct mip6_prefix_ha_list *mpfxha_list;
	struct mip6_prefix_ha *mpfxha;
{
	LIST_REMOVE(mpfxha, mpfxha_entry);
	FREE(mpfxha, M_TEMP);
}

struct mip6_prefix_ha *
mip6_prefix_ha_list_find_withaddr(mpfxha_list, addr)
	struct mip6_prefix_ha_list *mpfxha_list;
	struct in6_addr *addr;
{
	struct mip6_prefix_ha *mpfxha;

	for (mpfxha = LIST_FIRST(mpfxha_list); mpfxha;
	     mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
		if (mpfxha->mpfxha_mha == NULL)
			continue;

		if (IN6_ARE_ADDR_EQUAL(&mpfxha->mpfxha_mha->mha_addr, addr))
			return (mpfxha);
	}
	return (NULL);
}

struct mip6_prefix_ha *
mip6_prefix_ha_list_find_withmha(mpfxha_list, mha)
	struct mip6_prefix_ha_list *mpfxha_list;
	struct mip6_ha *mha;
{
	struct mip6_prefix_ha *mpfxha;

	for (mpfxha = LIST_FIRST(mpfxha_list); mpfxha;
	     mpfxha = LIST_NEXT(mpfxha, mpfxha_entry)) {
		if (mpfxha->mpfxha_mha && (mpfxha->mpfxha_mha == mha))
			return (mpfxha);
	}
	return (NULL);
}
