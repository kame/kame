/*	$KAME: mip6_halist.c,v 1.4 2003/08/25 11:28:40 keiichi Exp $	*/

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

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
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

#include <net/if_hif.h>

#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#include <netinet6/mip6_mncore.h>

struct mip6_ha_list mip6_ha_list;

void
mip6_halist_init()
{
	LIST_INIT(&mip6_ha_list);
}

struct mip6_ha *
mip6_ha_create(addr, flags, pref, lifetime)
	struct sockaddr_in6 *addr;
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
	mha->mha_lifetime = lifetime;
	mha->mha_expire = mono_time.tv_sec + mha->mha_lifetime;

	return (mha);
}

void
mip6_ha_print(mha)
	struct mip6_ha *mha;
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	mip6log((LOG_INFO,
		 "addr    %s\n"
		 "pref     %u\n"
		 "lifetime %u\n"
		 "remain   %ld\n",
		 ip6_sprintf(&mha->mha_addr.sin6_addr),
		 mha->mha_pref,
		 mha->mha_lifetime,
		 mha->mha_expire - time_second));
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

	return (0);
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

#ifdef MIP6_DEBUG
	mip6_ha_print(mha);
#endif
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

	LIST_REMOVE(mha, mha_entry);
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
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	if ((mha_list == NULL) ||
	    (dr == NULL) ||
	    !IN6_IS_ADDR_LINKLOCAL(&dr->rtaddr.sin6_addr)) {
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
	if (mha && lifetime == 0) {
		mip6_ha_list_remove(mha_list, mha);
	} else {
		/* reset pref and lifetime */
		mha->mha_pref = pref;
		mha->mha_lifetime = lifetime;
		mha->mha_expire = time_second + mha->mha_lifetime;
		/* XXX re-order by pref */
	}

	return (0);
}

struct mip6_ha *
mip6_ha_list_find_withaddr(mha_list, addr)
	struct mip6_ha_list *mha_list;
	struct sockaddr_in6 *addr;
{
	struct mip6_ha *mha;

	for (mha = LIST_FIRST(mha_list); mha;
	     mha = LIST_NEXT(mha, mha_entry)) {
		if (SA6_ARE_ADDR_EQUAL(&mha->mha_addr, addr))
			return (mha);
	}
	/* not found. */
	return (NULL);
}
