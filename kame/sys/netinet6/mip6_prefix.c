/*	$KAME: mip6_prefix.c,v 1.18 2002/03/12 11:57:55 keiichi Exp $	*/

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
#include <netinet6/in6_ifattach.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>

#include <net/if_hif.h>

#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>

struct mip6_prefix_list mip6_prefix_list;

extern struct mip6_subnet_list mip6_subnet_list;

void
mip6_prefix_init(void)
{
	LIST_INIT(&mip6_prefix_list);
}

struct mip6_prefix *
mip6_prefix_create(prefix, prefixlen, vltime, pltime)
	struct sockaddr_in6 *prefix;
	u_int8_t prefixlen;
	u_int32_t vltime;
	u_int32_t pltime;
{
	struct mip6_prefix *mpfx;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	MALLOC(mpfx, struct mip6_prefix *, sizeof(struct mip6_prefix),
	       M_TEMP, M_NOWAIT);
	if (mpfx == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: memory allocation failed.\n",
			 __FILE__, __LINE__));
		return (NULL);
	}
	bzero(mpfx, sizeof(*mpfx));
	mpfx->mpfx_prefix = *prefix;
	mpfx->mpfx_prefixlen = prefixlen;
	mpfx->mpfx_vltime = vltime;
	mpfx->mpfx_vlexpire = time_second + mpfx->mpfx_vltime;
	mpfx->mpfx_pltime = pltime;
	mpfx->mpfx_plexpire = time_second + mpfx->mpfx_pltime;
	/* XXX mpfx->mpfx_haddr; */

	return (mpfx);
}

int mip6_prefix_haddr_assign(mpfx, sc)
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
	mpfx->mpfx_haddr.sin6_addr.s6_addr32[2] = ifid.s6_addr32[2];
	mpfx->mpfx_haddr.sin6_addr.s6_addr32[3] = ifid.s6_addr32[3];

	return (0);
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
	struct mip6_subnet *ms;
	struct mip6_subnet_prefix *mspfx;

	if ((mpfx_list == NULL) || (mpfx == NULL)) {
		return (EINVAL);
	}

	for (ms = LIST_FIRST(&mip6_subnet_list); ms;
	     ms = LIST_NEXT(ms, ms_entry)) {
		mspfx = mip6_subnet_prefix_list_find_withmpfx(&ms->ms_mspfx_list,
							      mpfx);
		if (mspfx) {
			/*
			 * do not call mip6_subnet_prefix_list_remove().
			 * otherwise, you will fall into an infinite loop...
			 */
			TAILQ_REMOVE(&ms->ms_mspfx_list, mspfx, mspfx_entry);
			FREE(mspfx, M_TEMP);
		}
	}
	
	LIST_REMOVE(mpfx, mpfx_entry);
	FREE(mpfx, M_TEMP);

	return (0);
}

struct mip6_prefix *
mip6_prefix_list_find(tmpmpfx)
	struct mip6_prefix *tmpmpfx;
{
	struct mip6_prefix *mpfx;

	if (tmpmpfx == NULL) {
		return (NULL);
	}

	for (mpfx = LIST_FIRST(&mip6_prefix_list); mpfx;
	     mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
		if (in6_are_prefix_equal(&tmpmpfx->mpfx_prefix.sin6_addr,
					 &mpfx->mpfx_prefix.sin6_addr,
					 tmpmpfx->mpfx_prefixlen)
		    && (tmpmpfx->mpfx_prefixlen == mpfx->mpfx_prefixlen)) {
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
     struct sockaddr_in6 *haddr;
{
	struct mip6_prefix *mpfx;

	for (mpfx = LIST_FIRST(mpfx_list); mpfx;
	     mpfx = LIST_NEXT(mpfx, mpfx_entry)) {
		if (SA6_ARE_ADDR_EQUAL(haddr,
				       &mpfx->mpfx_haddr)) {
			/* found. */
			return (mpfx);
		}
	}

	/* not found. */
	return (NULL);
}
