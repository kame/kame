/*	$KAME: mip6_subnet.c,v 1.5 2001/08/14 12:59:39 keiichi Exp $	*/

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

struct mip6_subnet_list mip6_subnet_list;

extern struct mip6_prefix_list mip6_prefix_list;

void
mip6_subnet_init(void)
{
	LIST_INIT(&mip6_subnet_list);
}

struct mip6_subnet *
mip6_subnet_create(void)
{
	struct mip6_subnet *ms;

	MALLOC(ms, struct mip6_subnet *, sizeof(struct mip6_subnet),
	       M_TEMP, M_NOWAIT);
	if (ms == NULL) {
		mip6log((LOG_ERR,
			 "%s: memory allocation failed.\n",
			 __FUNCTION__));
		return (NULL);
	}

	bzero(ms, sizeof(*ms));
	TAILQ_INIT(&ms->ms_mspfx_list);
	TAILQ_INIT(&ms->ms_msha_list);
	
	return (ms);
}

int
mip6_subnet_delete(ms)
     struct mip6_subnet *ms;
{
	struct hif_softc *sc;
	struct hif_subnet *hs;
	struct mip6_subnet_prefix *mspfx;
	struct mip6_subnet_ha *msha;
	int error = 0;

	if (ms == NULL) {
		return (EINVAL);
	}

	while(!TAILQ_EMPTY(&ms->ms_mspfx_list)) {
		mspfx = TAILQ_FIRST(&ms->ms_mspfx_list);
		TAILQ_REMOVE(&ms->ms_mspfx_list, mspfx, mspfx_entry);
		error = mip6_prefix_list_remove(&mip6_prefix_list,
						mspfx->mspfx_mpfx);
		if (error) {
			return (error);
		}
	}
	while(!TAILQ_EMPTY(&ms->ms_msha_list)) {
		msha = TAILQ_FIRST(&ms->ms_msha_list);
		TAILQ_REMOVE(&ms->ms_msha_list, msha, msha_entry);
		error = mip6_ha_list_remove(&mip6_ha_list, msha->msha_mha);
		if (error) {
			return (error);
		}
	}

	/* remove all hif_subnet that point this mip6_subnet. */
	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		for (hs = TAILQ_FIRST(&sc->hif_hs_list_home); hs;
		     hs = TAILQ_NEXT(hs, hs_entry)) {
			if (hs->hs_ms == ms) {
				error = hif_subnet_list_remove(&sc->hif_hs_list_home,
							       hs);
				if (error) {
					mip6log((LOG_ERR,
						 "%s: can't remove hif_subnet (0x%p).\n",
						 __FUNCTION__, hs));
				}
			}
		}
		for (hs = TAILQ_FIRST(&sc->hif_hs_list_foreign); hs;
		     hs = TAILQ_NEXT(hs, hs_entry)) {
			if (hs->hs_ms == ms) {
				error = hif_subnet_list_remove(&sc->hif_hs_list_home,
							       hs);
				if (error) {
					mip6log((LOG_ERR,
						 "%s: can't remove hif_subnet (0x%p).\n",
						 __FUNCTION__, hs));
				}
			}
		}
	}

	FREE(ms, M_TEMP);

	return (0);
}

int
mip6_subnet_list_insert(ms_list, ms)
     struct mip6_subnet_list *ms_list;
     struct mip6_subnet *ms;
{
	if ((ms_list == NULL) || (ms == NULL)) {
		return (EINVAL);
	}

	LIST_INSERT_HEAD(ms_list, ms, ms_entry);

	return (0);
}

int
mip6_subnet_list_remove(ms_list, ms)
     struct mip6_subnet_list *ms_list;
     struct mip6_subnet *ms;
{
	int error = 0;

	if ((ms_list == NULL) || (ms == NULL)) {
		return (EINVAL);
	}

	LIST_REMOVE(ms, ms_entry);
	error = mip6_subnet_delete(ms);

	return (error);
}

struct mip6_subnet *
mip6_subnet_list_find_withprefix(ms_list, prefix, prefixlen)
     struct mip6_subnet_list *ms_list;
     struct in6_addr *prefix;
     u_int8_t prefixlen;
{
	struct mip6_subnet *ms;
	struct mip6_subnet_prefix *mspfx;

	if ((ms_list == NULL)
	    || (prefix == NULL)
	    || (prefixlen > 128)) {
		return (NULL);
	}

	for (ms = LIST_FIRST(&mip6_subnet_list); ms;
	     ms = LIST_NEXT(ms, ms_entry)) {
		mspfx = mip6_subnet_prefix_list_find_withprefix(&ms->ms_mspfx_list,
								prefix,
								prefixlen);
		if (mspfx) {
			return (ms);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_subnet *
mip6_subnet_list_find_withhaaddr(ms_list, haaddr)
     struct mip6_subnet_list *ms_list;
     struct in6_addr *haaddr;
{
	struct mip6_subnet *ms;
	struct mip6_subnet_ha *msha;

	if ((ms_list == NULL) || (haaddr == NULL)) {
		return (NULL);
	}

	for (ms = LIST_FIRST(&mip6_subnet_list); ms;
	     ms = LIST_NEXT(ms, ms_entry)) {
		msha = mip6_subnet_ha_list_find_withhaaddr(&ms->ms_msha_list,
							   haaddr);
		if (msha) {
			return (ms);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_subnet_prefix *
mip6_subnet_prefix_create(mpfx)
     struct mip6_prefix *mpfx;
{
	struct mip6_subnet_prefix *mspfx;

	MALLOC(mspfx, struct mip6_subnet_prefix *,
	       sizeof(struct mip6_subnet_prefix), M_TEMP, M_NOWAIT);
	if (mspfx == NULL) {
		mip6log((LOG_ERR,
			 "%s: memory allocation failed.\n",
			 __FUNCTION__));
		return (NULL);
	}
	bzero(mspfx, sizeof(*mspfx));
	mspfx->mspfx_mpfx = mpfx;

	return (mspfx);
}

int
mip6_subnet_prefix_list_insert(mspfx_list, mspfx)
     struct mip6_subnet_prefix_list *mspfx_list;
     struct mip6_subnet_prefix *mspfx;
{
	if ((mspfx_list == NULL) || (mspfx == NULL)) {
		return (EINVAL);
	}

	TAILQ_INSERT_HEAD(mspfx_list, mspfx, mspfx_entry);

	return (0);
}

int
mip6_subnet_prefix_list_remove(mspfx_list, mspfx)
     struct mip6_subnet_prefix_list *mspfx_list;
     struct mip6_subnet_prefix *mspfx;
{
	int error = 0;

	if ((mspfx_list == NULL) || (mspfx == NULL)) {
		return (EINVAL);
	}

	TAILQ_REMOVE(mspfx_list, mspfx, mspfx_entry);
	error = mip6_prefix_list_remove(&mip6_prefix_list, mspfx->mspfx_mpfx);
	if (error) {
		return (error);
	}

	FREE(mspfx, M_TEMP);

	return (0);
}

struct mip6_subnet_prefix *
mip6_subnet_prefix_list_find_withmpfx(mspfx_list, mpfx)
     struct mip6_subnet_prefix_list *mspfx_list;
     struct mip6_prefix *mpfx;
{
	struct mip6_subnet_prefix *mspfx;

	if ((mspfx_list == NULL) || (mpfx == NULL)) {
		return (NULL);
	}

	for (mspfx = TAILQ_FIRST(mspfx_list); mspfx;
	     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
		if (mspfx->mspfx_mpfx == mpfx) {
			/* found. */
			return (mspfx);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_subnet_prefix *
mip6_subnet_prefix_list_find_withprefix(mspfx_list, prefix, prefixlen)
     struct mip6_subnet_prefix_list *mspfx_list;
     struct in6_addr *prefix;
     u_int8_t prefixlen;
{
	struct mip6_subnet_prefix *mspfx;
	struct mip6_prefix *mpfx;

	/*
	 * walk mip6_subnet_prefix_list and check each mip6_prefix
	 * (which is a member of mip6_subnet_prefix as a pointer) if
	 * it contains specified prefix or not.
	 */
	for (mspfx = TAILQ_FIRST(mspfx_list); mspfx;
	     mspfx = TAILQ_NEXT(mspfx, mspfx_entry)) {
		if ((mpfx = mspfx->mspfx_mpfx) == NULL) {
			/* must not happen. */
			mip6log((LOG_ERR,
				 "%s: mspfx_mpfx is a NULL pointer.\n",
				 __FUNCTION__));
			return (NULL);
		}
		if ((in6_are_prefix_equal(&mpfx->mpfx_prefix,
					  prefix,
					  prefixlen))
		    && (mpfx->mpfx_prefixlen == prefixlen)) {
			/* found. */
			return (mspfx);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_subnet_ha *
mip6_subnet_ha_create(mha)
     struct mip6_ha *mha;
{
	struct mip6_subnet_ha *msha;

	MALLOC(msha, struct mip6_subnet_ha *,
	       sizeof(struct mip6_subnet_ha), M_TEMP, M_NOWAIT);
	if (msha == NULL) {
		mip6log((LOG_ERR,
			 "%s: memory allocation failed.\n",
			 __FUNCTION__));
		return (NULL);
	}
	bzero(msha, sizeof(*msha));
	msha->msha_mha = mha;

	return (msha);
}

int
mip6_subnet_ha_list_insert(msha_list, msha)
     struct mip6_subnet_ha_list *msha_list;
     struct mip6_subnet_ha *msha;
{
	if ((msha_list == NULL) || (msha == NULL)) {
		return (EINVAL);
	}

	TAILQ_INSERT_HEAD(msha_list, msha, msha_entry);

	return (0);
}

/*
 * find preferable home agene.
 * XXX current code doesn't take a pref value into consideration.
 */
struct mip6_subnet_ha *
mip6_subnet_ha_list_find_preferable(msha_list)
     struct mip6_subnet_ha_list *msha_list;
{
	struct mip6_subnet_ha *msha;
	struct mip6_ha *mha;

	for (msha = TAILQ_FIRST(msha_list); msha;
	     msha = TAILQ_NEXT(msha, msha_entry)) {
		mha = msha->msha_mha;
		if (mha == NULL) {
			/* must not happen. */
			continue;
		}
		if (mha->mha_flags & ND_RA_FLAG_HOME_AGENT) {
			/* found. */
			return (msha);
		}
	}
	
	/* not found. */
	return (NULL);
}

struct mip6_subnet_ha *
mip6_subnet_ha_list_find_withmha(msha_list, mha)
     struct mip6_subnet_ha_list *msha_list;
     struct mip6_ha *mha;
{
	struct mip6_subnet_ha *msha;

	if ((msha_list == NULL) || (mha == NULL)) {
		return (NULL);
	}

	for (msha = TAILQ_FIRST(msha_list); msha;
	     msha = TAILQ_NEXT(msha, msha_entry)) {
		if (msha->msha_mha == mha) {
			/* found. */
			return (msha);
		}
	}

	/* not found. */
	return (NULL);
}

struct mip6_subnet_ha *
mip6_subnet_ha_list_find_withhaaddr(msha_list, haaddr)
     struct mip6_subnet_ha_list *msha_list;
     struct in6_addr *haaddr;
{
	struct mip6_subnet_ha *msha;
	struct mip6_ha *mha;

	/*
	 * walk mip6_subnet_ha_list and check each mip6_ha (which is a
	 * member of mip6_subnet_ha as a pointer) if it contains
	 * specified haaddr or not.
	 */
	for (msha = TAILQ_FIRST(msha_list); msha;
	     msha = TAILQ_NEXT(msha, msha_entry)) {
		if ((mha = msha->msha_mha) == NULL) {
			/* must not happen. */
			mip6log((LOG_ERR,
				 "%s: msha_mha is a NULL pointer.\n",
				 __FUNCTION__));
			return (NULL);
		}
		if (IN6_ARE_ADDR_EQUAL(&mha->mha_lladdr,
				       haaddr)
		    || IN6_ARE_ADDR_EQUAL(&mha->mha_gaddr,
					  haaddr)) {
			/* found. */
			return (msha);
		}
	}

	/* not found. */
	return (NULL);
}
