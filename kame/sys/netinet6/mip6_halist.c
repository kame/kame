/*	$KAME: mip6_halist.c,v 1.13 2004/06/02 05:53:16 itojun Exp $	*/

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

struct mip6_ha_list mip6_ha_list;

static void mip6_ha_settimer(struct mip6_ha *, long);
static void mip6_ha_timer(void *);

void
mip6_halist_init()
{
	TAILQ_INIT(&mip6_ha_list);
}

struct mip6_ha *
mip6_ha_create(addr, flags, pref, lifetime)
	struct in6_addr *addr;
	u_int8_t flags;
	u_int16_t pref;
	int32_t lifetime;
{
	struct mip6_ha *mha = NULL;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif

	if (IN6_IS_ADDR_UNSPECIFIED(addr)
	    || IN6_IS_ADDR_LOOPBACK(addr)
	    || IN6_IS_ADDR_MULTICAST(addr)) {
		mip6log((LOG_ERR,
		    "mip6_ha_create: an invalid home agent address(%s).",
		    ip6_sprintf(addr)));
		return (NULL);
	}

	if (!IN6_IS_ADDR_LINKLOCAL(addr)
	    && ((flags & ND_RA_FLAG_HOME_AGENT) == 0)) {
		mip6log((LOG_ERR,
		    "mip6_ha_create: non link-local address(%s) "
		    "must have H bit in router flags.\n",
		    ip6_sprintf(addr)));
		return (NULL);
	}

	MALLOC(mha, struct mip6_ha *, sizeof(struct mip6_ha), M_TEMP,
	    M_NOWAIT);
	if (mha == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: memory allocation failed.\n",
		    __FILE__, __LINE__));
		return (NULL);
	}
	bzero(mha, sizeof(*mha));
	mha->mha_addr = *addr;
	mha->mha_flags = flags;
	mha->mha_pref = pref;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&mha->mha_timer_ch, NULL);
#elif defined(__NetBSD__) || defined(__FreeBSD__)
	callout_init(&mha->mha_timer_ch);
#elif defined(__OpenBSD__)
	timeout_set(&mha->mha_timer_ch, mip6_ha_timer, mha);
#endif
	if (IN6_IS_ADDR_LINKLOCAL(&mha->mha_addr)) {
		mha->mha_lifetime = lifetime;
	} else {
		mha->mha_lifetime = 0; /* infinite. */
	}
	mip6_ha_update_lifetime(mha, lifetime);

	return (mha);
}

void
mip6_ha_update_lifetime(mha, lifetime)
	struct mip6_ha *mha;
	u_int16_t lifetime;
{
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif

	mip6_ha_settimer(mha, -1);
	mha->mha_lifetime = lifetime;
	if (mha->mha_lifetime != 0) {
		mha->mha_expire = mono_time.tv_sec + mha->mha_lifetime;
		mip6_ha_settimer(mha, mha->mha_lifetime * hz);
	} else {
		mha->mha_expire = 0;
	}
}

static void
mip6_ha_settimer(mha, tick)
	struct mip6_ha *mha;
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
		mha->mha_timeout = 0;
		mha->mha_ntick = 0;
#if defined(__NetBSD__) || defined(__FreeBSD__)
		callout_stop(&mha->mha_timer_ch);
#elif defined(__OpenBSD__)
		timeout_del(&mha->mha_timer_ch);
#else
		untimeout(mip6_ha_timer, mha);
#endif
	} else {
		mha->mha_timeout = mono_time.tv_sec + tick / hz;
		if (tick > INT_MAX) {
			mha->mha_ntick = tick - INT_MAX;
#if defined(__NetBSD__) || defined(__FreeBSD__)
			callout_reset(&mha->mha_timer_ch, INT_MAX,
			    mip6_ha_timer, mha);
#elif defined(__OpenBSD__)
			timeout_add(&mha->mha_timer_ch, INT_MAX);
#else
			timeout(mip6_ha_timer, ln, INT_MAX);
#endif
		} else {
			mha->mha_ntick = 0;
#if defined(__NetBSD__) || defined(__FreeBSD__)
			callout_reset(&mha->mha_timer_ch, tick,
			    mip6_ha_timer, mha);
#elif defined(__OpenBSD__)
			timeout_add(&mha->mha_timer_ch, tick);
#else
			timeout(mip6_ha_timer, mha, tick);
#endif
		}
	}

	splx(s);
}

static void
mip6_ha_timer(arg)
	void *arg;
{
	int s;
	struct mip6_ha *mha;
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

	mha = (struct mip6_ha *)arg;

	if (mha->mha_ntick > 0) {
		if (mha->mha_ntick > INT_MAX) {
			mha->mha_ntick -= INT_MAX;
			mip6_ha_settimer(mha, INT_MAX);
		} else {
			mha->mha_ntick = 0;
			mip6_ha_settimer(mha, mha->mha_ntick);
		}
		splx(s);
		return;
	}

	/*
	 * XXX reset all home agent addresses in the binding update
	 * entries.
	 */

	mip6_ha_list_remove(&mip6_ha_list, mha);

	splx(s);
}

void
mip6_ha_list_insert(mha_list, mha)
	struct mip6_ha_list *mha_list;
	struct mip6_ha *mha;
{
	struct mip6_ha *tgtmha;

	if ((mha_list == NULL) || (mha == NULL)) {
		panic("mip6_ha_list_insert: NULL pointer.");
	}

	/*
	 * insert a new entry in a proper place orderd by prefernce
	 * value.  if prefernce value is same, the new entry is placed
	 * at the end of the group which has a same prefernce value.
	 */
	for (tgtmha = TAILQ_FIRST(mha_list); tgtmha;
	    tgtmha = TAILQ_NEXT(tgtmha, mha_entry)) {
		if (tgtmha->mha_pref >= mha->mha_pref)
			continue;
		TAILQ_INSERT_BEFORE(tgtmha, mha, mha_entry);
		return;
	}
	TAILQ_INSERT_TAIL(mha_list, mha, mha_entry);

	return;
}

void
mip6_ha_list_reinsert(mha_list, mha)
	struct mip6_ha_list *mha_list;
	struct mip6_ha *mha;
{
	struct mip6_ha *tgtmha;

	if ((mha_list == NULL) || (mha == NULL)) {
		panic("mip6_ha_list_insert: NULL pointer.");
	}

	for (tgtmha = TAILQ_FIRST(mha_list); tgtmha;
	    tgtmha = TAILQ_NEXT(tgtmha, mha_entry)) {
		if (tgtmha == mha)
			break;
	}

	/* insert or move the entry to the proper place of the queue. */
	if (tgtmha != NULL)
		TAILQ_REMOVE(mha_list, tgtmha, mha_entry);
	mip6_ha_list_insert(mha_list, mha);

	return;
}
	

int
mip6_ha_list_remove(mha_list, mha)
	struct mip6_ha_list *mha_list;
	struct mip6_ha *mha;
{
	struct mip6_prefix *mpfx;
	struct mip6_prefix_ha *mpfxha, *mpfxha_next;

	if ((mha_list == NULL) || (mha == NULL)) {
		return (EINVAL);
	}

	/* remove all refernces from mip6_prefix entries. */
	for (mpfx = LIST_FIRST(&mip6_prefix_list); mpfx;
	    mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
		for (mpfxha = LIST_FIRST(&mpfx->mpfx_ha_list); mpfxha;
		    mpfxha = mpfxha_next) {
			mpfxha_next = LIST_NEXT(mpfxha, mpfxha_entry);
			if (mpfxha->mpfxha_mha == mha)
				mip6_prefix_ha_list_remove(&mpfx->mpfx_ha_list,
				    mpfxha);
		}
	}

	TAILQ_REMOVE(mha_list, mha, mha_entry);
	mip6_ha_settimer(mha, -1);
	FREE(mha, M_TEMP);

	return (0);
}

int
mip6_ha_list_update_hainfo(mha_list, dr, hai)
	struct mip6_ha_list *mha_list;
	struct nd_defrouter *dr;
	struct nd_opt_homeagent_info *hai;
{
	int16_t pref = 0;
	u_int16_t lifetime;
	struct mip6_ha *mha;

	if ((mha_list == NULL) ||
	    (dr == NULL) ||
	    !IN6_IS_ADDR_LINKLOCAL(&dr->rtaddr)) {
		return (EINVAL);
	}

	lifetime = dr->rtlifetime;
	if (hai) {
		pref = ntohs(hai->nd_opt_hai_preference);
		lifetime = ntohs(hai->nd_opt_hai_lifetime);
	}

	/* find an exising entry. */
	mha = mip6_ha_list_find_withaddr(mha_list, &dr->rtaddr);
	if (mha == NULL) {
		/* an entry must exist at this point. */
		return (EINVAL);
	}

	/*
	 * if received lifetime is 0, delete the entry.
	 * otherwise, update an entry.
	 */
	if (lifetime == 0) {
		mip6_ha_list_remove(mha_list, mha);
	} else {
		/* reset lifetime */
		mip6_ha_update_lifetime(mha, lifetime);
	}

	return (0);
}

struct mip6_ha *
mip6_ha_list_find_withaddr(mha_list, addr)
	struct mip6_ha_list *mha_list;
	struct in6_addr *addr;
{
	struct mip6_ha *mha;

	for (mha = TAILQ_FIRST(mha_list); mha;
	    mha = TAILQ_NEXT(mha, mha_entry)) {
		if (IN6_ARE_ADDR_EQUAL(&mha->mha_addr, addr))
			return (mha);
	}
	/* not found. */
	return (NULL);
}
