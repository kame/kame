/*	$KAME: mip6_ha.c,v 1.20 2001/08/03 14:25:55 itojun Exp $	*/

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
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <netinet6/mip6.h>

extern struct mip6_subnet_list mip6_subnet_list;

struct mip6_ha_list mip6_ha_list;

#ifdef __NetBSD__
struct callout mip6_ha_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_ha_ch;
#endif
int mip6_ha_count = 0;

static void mip6_ha_timeout __P((void *));
static void mip6_ha_starttimer __P((void));
static void mip6_ha_stoptimer __P((void));
static void mip6_ha_restarttimer __P((void));

void
mip6_ha_init()
{
	LIST_INIT(&mip6_ha_list);
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3) 
        callout_init(&mip6_ha_ch);
#endif
}

struct mip6_ha *
mip6_ha_create(lladdr, gaddr, flags, pref, lifetime)
     struct in6_addr *lladdr;
     struct in6_addr *gaddr;
     u_int8_t flags;
     int16_t pref;
     int32_t lifetime;
{
	struct mip6_ha *mha = NULL;

	MALLOC(mha, struct mip6_ha *, sizeof(struct mip6_ha),
	       M_TEMP, M_NOWAIT);
	if (mha == NULL) {
		mip6log((LOG_ERR,
			 "%s: memory allocation failed.\n",
			 __FUNCTION__));
		return (NULL);
	}
	bzero(mha, sizeof(*mha));
	mha->mha_lladdr = *lladdr;
	mha->mha_gaddr = gaddr ? *gaddr : in6addr_any;
	mha->mha_flags = flags;
	mha->mha_pref = pref;
	mha->mha_lifetime = lifetime;
	mha->mha_remain = lifetime;

	return (mha);
}

void
mip6_ha_print(mha)
     struct mip6_ha *mha;
{
	if (mip6_config.mcfg_debug) {
		printf("lladdr   %s\n", ip6_sprintf(&mha->mha_lladdr));
		printf("gaddr    %s\n", ip6_sprintf(&mha->mha_gaddr));
		printf("pref     %u\n", mha->mha_pref);
		printf("lifetime %u\n", mha->mha_lifetime);
		printf("remain   %ld\n", (long)mha->mha_remain);
	}
}

int
mip6_ha_list_insert(mha_list, mha)
     struct mip6_ha_list *mha_list;
     struct mip6_ha *mha;
{
	if ((mha_list == NULL) || (mha == NULL)) {
		return (EINVAL);
	}

	LIST_INSERT_HEAD(mha_list, mha, mha_entry);

	if (mip6_ha_count == 0) {
		mip6_ha_starttimer();
		mip6log((LOG_INFO, "%s: HA timer started.\n",
			 __FUNCTION__));
	}
	mip6_ha_count++;

	return (0);
}

int
mip6_ha_list_remove(mha_list, mha)
     struct mip6_ha_list *mha_list;
     struct mip6_ha *mha;
{
	struct mip6_subnet *ms;
	struct mip6_subnet_ha *msha;

	if ((mha_list == NULL) || (mha == NULL)) {
		return (EINVAL);
	}

	mip6_ha_print(mha);

	/* walk all mip6_subnet and remove corresponding mip6_ha pointers. */
	LIST_FOREACH(ms, &mip6_subnet_list, ms_entry) {
		msha = mip6_subnet_ha_list_find_withmha(&ms->ms_msha_list, mha);
		if (msha) {
			/*
			 * do not call mip6_subnet_ha_list_remove().
			 * otherwise, you will fall into an infinite loop...
			 */
			TAILQ_REMOVE(&ms->ms_msha_list, msha, msha_entry);
			FREE(msha, M_TEMP);
		}
	}

	LIST_REMOVE(mha, mha_entry);
	FREE(mha, M_TEMP);

	mip6_ha_count--;
	if (mip6_ha_count == 0) {
		mip6_ha_stoptimer();
	}

	return (0);
}

int
mip6_ha_list_update_hainfo(mha_list, dr, hai)
     struct mip6_ha_list *mha_list;
     struct nd_defrouter *dr;
     struct nd_opt_homeagent_info *hai;
{
	int16_t pref = 0;
	u_int16_t lifetime = dr->rtlifetime;
	struct mip6_ha *mha;

	if ((mha_list == NULL) || (dr == NULL)) {
		return (EINVAL);
	}

	if (hai) {
		pref = hai->nd_opt_hai_preference;
		lifetime = hai->nd_opt_hai_lifetime;
	}

	/* find an exising entry */
	mha = mip6_ha_list_find_withaddr(mha_list, &dr->rtaddr);
	if (mha == NULL) {
		/* an entry must exist at this point. */
		return (EINVAL);
	}

	/*
	 * if received lifetime is 0, delete the entry.
	 * otherwise, update an entry.
	 */
	if (mha && lifetime == 0) {
		mip6_ha_list_remove(mha_list, mha);
	} else {
		/* reset pref and lifetime */
		mha->mha_pref = pref;
		mha->mha_lifetime = lifetime;
		mha->mha_remain = lifetime;
		/* XXX re-order by pref */
		mip6_ha_print(mha);
	}

	return (0);
}

int
mip6_ha_list_update_withndpr(mha_list, addr, ndpr)
     struct mip6_ha_list *mha_list;
     struct in6_addr *addr;
     struct nd_prefix *ndpr;
{
	struct mip6_ha *mha;

	mha = mip6_ha_list_find_withaddr(mha_list, addr);
	if (mha == NULL) {
		return (0);
	}
	mha->mha_gaddr = ndpr->ndpr_prefix.sin6_addr;
	
	return (0);
}

struct mip6_ha *
mip6_ha_list_find_withaddr(mha_list, addr)
     struct mip6_ha_list *mha_list;
     struct in6_addr *addr;
{
	struct mip6_ha *mha, *match = NULL;

	LIST_FOREACH(mha, mha_list, mha_entry) {
		if (IN6_ARE_ADDR_EQUAL(&mha->mha_lladdr, addr)) {
			match = mha;
			break;
		}
		if (IN6_ARE_ADDR_EQUAL(&mha->mha_gaddr, addr)) {
			match = mha;
			break;
		}
		if (match)
			break;
	}

	return (mha);
}

static void
mip6_ha_timeout(dummy)
     void *dummy;
{
	printf("%s: TBD.\n", __FUNCTION__);
}

static void
mip6_ha_starttimer()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&mip6_ha_ch,
		      MIP6_HA_TIMEOUT_INTERVAL * hz,
		      mip6_ha_timeout, NULL);
#else
	timeout(mip6_ha_timeout, (void *)0,
		MIP6_HA_TIMEOUT_INTERVAL * hz);
#endif
}

static void
mip6_ha_stoptimer()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&mip6_ha_ch);
#else
	untimeout(mip6_ha_timeout, (void *)0);
#endif
}

/***********************************************************************/
/***********************************************************************/
#ifdef OLD
/*
 * mip6_ha_list functions
 */

/*
 * find mip6_ha with a specified addr (linklocal or global)
 */
struct mip6_ha *
mip6_ha_list_find_withaddr(ha_list, rtaddr)
     struct mip6_ha_list *ha_list;
     struct in6_addr *rtaddr;
{
	struct mip6_ha *mha, *match;

	LIST_FOREACH(mha, ha_list, mha_entry) {
		if (IN6_ARE_ADDR_EQUAL(&mha->mha_lladdr, rtaddr)) {
			match = mha;
			break;
		}
		if (IN6_ARE_ADDR_EQUAL(&mha->mha_gaddr, rtaddr)) {
			match = mha;
			break;
		}
		if (match)
			break;
	}

	return (mha);
}

/*
 * update a global address of a mip6_ha with rtaddr
 */
int
mip6_ha_list_update_gaddr(ha_list, rtaddr, gaddr)
     struct mip6_ha_list *ha_list;
     struct in6_addr *rtaddr;
     struct in6_addr *gaddr;
{
	struct mip6_ha *mha;

	mha = mip6_ha_list_find_withaddr(ha_list, rtaddr);
	if (mha == NULL) {
		/* this address (rtaddr) is not a HA. */
		return (0);
	}
	mha->mha_gaddr = *gaddr;

	return (0);
}

int
mip6_ha_list_insert(mha_list, mha)
     struct mip6_ha_list *mha_list;
     struct mip6_ha *mha;
{
	struct hif_softc *sc;
	struct mip6_pfx *mpfx;
	struct hif_ha *hha;
	u_int8_t onhomelink;

	LIST_INSERT_HEAD(mha_list, mha, mha_entry);

	/* update each hif_ha_list */
	TAILQ_FOREACH(sc, &hif_softc_list, hif_entry) {
		onhomelink = 0;
		LIST_FOREACH(mpfx, &sc->hif_pfx_list, mpfx_entry) {
			/*
			 * if a prefix of a global addr of
			 * a specified HA equals
			 * one of the prefixes that hif holds,
			 * we consider the HA is on homelink.
			 */
			if (in6_are_prefix_equal(&mpfx->mpfx_prefix,
						 &mha->mha_gaddr,
						 mpfx->mpfx_prefixlen))
				onhomelink = 1;
		}
		hha = hif_ha_create(onhomelink, mha);
		if (hha == NULL)
			return (-1);
		if (hif_ha_list_insert(&sc->hif_ha_list, hha))
			return (-1);
	}

	/* start mip6_ha_timeout if not started yet. */
	mip6_ha_starttimer();

	return (0);
}

int
mip6_ha_list_remove(mha_list, mha)
     struct mip6_ha_list *mha_list;
     struct mip6_ha *mha;
{
	struct hif_softc *sc;
	struct mip6_pfx *mpfx;

#ifdef MIP6_DEBUG
	mip6_ha_print(mha);
#endif /* MIP6_DEBUG */

	/* reset homeagent address */
	TAILQ_FOREACH(sc, &hif_softc_list, hif_entry) {
		/* remove corresponding hif_ha entry */
		hif_ha_list_remove_withmha(&sc->hif_ha_list, mha);

		/* reset homeagent address of each mip6_pfx */
		LIST_FOREACH(mpfx, &sc->hif_pfx_list, mpfx_entry) {
			if (IN6_ARE_ADDR_EQUAL(&mha->mha_gaddr,
					       &mpfx->mpfx_haaddr)) {
				mpfx->mpfx_haaddr = in6addr_any;
			}
		}
	}

	LIST_REMOVE(mha, mha_entry);
	free(mha, M_TEMP);

	if (LIST_EMPTY(mha_list)) {
		mip6_ha_stoptimer();
	}

	return (0);
}

/*
 * update mip6_ha_list with a router advertisement information
 */
int
mip6_ha_list_update_withra(mha_list, dr, hai)
     struct mip6_ha_list *mha_list;
     struct nd_defrouter *dr;
     struct nd_opt_homeagent_info *hai;
{
	int16_t pref = 0;
	u_int16_t lifetime = dr->rtlifetime;
	struct mip6_ha *mha;

	if (hai) {
		pref = hai->nd_opt_hai_preference;
		lifetime = hai->nd_opt_hai_lifetime;
	}

	/* check exising entry */
	mha = mip6_ha_list_find_withaddr(mha_list, &dr->rtaddr);

	/* if an entry exists and received lifetime is 0, delete the entry */
	if (mha && lifetime == 0) {
		mip6_ha_list_remove(mha_list, mha);
		goto update_ha_done;
	}

	/* reset pref and lifetime */
	if (mha) {
		mha->mha_pref = pref;
		mha->mha_lifetime = lifetime;
		mha->mha_remain = lifetime;
	} else {
		/* create a new entry */
		mha = mip6_ha_create(&dr->rtaddr, NULL, pref, lifetime);
		if (mha == NULL) {
			mip6log(("%s: mip6_ha create failed\n",
				 __FUNCTION__));
			return (0);
		}
		mip6_ha_list_insert(mha_list, mha);
	}
#ifdef MIP6_DEBUG
	mip6_ha_print(mha);
#endif /* MIP6_DEBUG */

 update_ha_done:
	return (0);
}


/*
 * mip6_ha functions
 */

/* create a new mip6_ha */
struct mip6_ha *
mip6_ha_create(lladdr, gaddr, pref, lifetime)
     struct in6_addr *lladdr;
     struct in6_addr *gaddr;
     int16_t pref;
     int32_t lifetime;
{
	struct mip6_ha *mha = NULL;

	mha = malloc(sizeof(struct mip6_ha), M_TEMP, M_NOWAIT);
	if (mha != NULL) {
		mha->mha_lladdr = *lladdr;
		mha->mha_gaddr = gaddr ? *gaddr : in6addr_any;
		mha->mha_pref = pref;
		mha->mha_lifetime = lifetime;
		mha->mha_remain = lifetime;
#ifdef MIP6_DEBUG
		mip6_ha_print(mha);
#endif /* MIP6_DEBUG */
	}

	return (mha);
}

#ifdef MIP6_DEBUG
void 
mip6_ha_print(mha)
     struct mip6_ha *mha;
{
	printf("lladdr   %s\n", ip6_sprintf(&mha->mha_lladdr));
	printf("gaddr    %s\n", ip6_sprintf(&mha->mha_gaddr));
	printf("pref     %u\n", mha->mha_pref);
	printf("lifetime %u\n", mha->mha_lifetime);
	printf("remain   %ld\n", (long)mha->mha_remain);
}
#endif /* MIP6_DEBUG */

static void
mip6_ha_timeout(arg)
     void *arg;
{
	int s;
	struct mip6_ha *mha, *mha_next;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif

	for (mha = LIST_FIRST(&mip6_ha_list); mha; mha = mha_next) {
		mha_next = LIST_NEXT(mha, mha_entry);
		
		mha->mha_remain -= MIP6_HA_TIMEOUT_INTERVAL;
		if (mha->mha_remain < 0)
			mip6_ha_list_remove(&mip6_ha_list, mha);
	}
			     
	mip6_ha_restarttimer();

	splx(s);
}

static void
mip6_ha_starttimer()
{
	if ((mip6_ha_timer_running == 0) && !LIST_EMPTY(&mip6_ha_list)) {
		mip6_ha_restarttimer();
		mip6_ha_timer_running = 1;
		mip6log(("%s: start mip6_ha_timeout\n",
			 __FUNCTION__));
	}
}

static void
mip6_ha_restarttimer()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&mip6_ha_ch,
		      MIP6_HA_TIMEOUT_INTERVAL * hz,
		      mip6_ha_timeout, NULL);
#else
	timeout(mip6_ha_timeout, (void *)0,
		MIP6_HA_TIMEOUT_INTERVAL * hz);
#endif
}

static void
mip6_ha_stoptimer()
{
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&mip6_ha_ch);
#else
	untimeout(mip6_ha_timeout, (void *)0);
#endif
	mip6_ha_timer_running = 0;
}

#endif /* OLD */
