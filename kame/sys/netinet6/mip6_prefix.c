#include "opt_ipsec.h"
#include "opt_mip6.h"

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

struct mip6_prefix_list mip6_prefix_list;

extern struct mip6_subnet_list mip6_subnet_list;

struct mip6_prefix *
mip6_prefix_create(prefix, prefixlen, lifetime)
     struct in6_addr *prefix;
     u_int8_t prefixlen;
     u_int32_t lifetime;
{
	struct mip6_prefix *mpfx;

	MALLOC(mpfx, struct mip6_prefix *, sizeof(struct mip6_prefix),
	       M_TEMP, M_NOWAIT);
	if (mpfx == NULL) {
		mip6log((LOG_ERR,
			 "%s: memory allocation failed.\n",
			 __FUNCTION__));
		return (NULL);
	}
	bzero(mpfx, sizeof(*mpfx));
	mpfx->mpfx_prefix = *prefix;
	mpfx->mpfx_prefixlen = prefixlen;
	mpfx->mpfx_lifetime = lifetime;
	mpfx->mpfx_remain = mpfx->mpfx_lifetime;
	mpfx->mpfx_haddr; /* XXX */

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

	error = get_ifid((struct ifnet *)sc, NULL, &ifid);
	if (error)
		return (error);

	/* XXX */
	mpfx->mpfx_haddr = mpfx->mpfx_prefix;
	mpfx->mpfx_haddr.s6_addr32[2] = ifid.s6_addr32[2];
	mpfx->mpfx_haddr.s6_addr32[3] = ifid.s6_addr32[3];

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

	LIST_FOREACH(ms, &mip6_subnet_list, ms_entry) {
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

	LIST_FOREACH(mpfx, &mip6_prefix_list, mpfx_entry) {
		if (in6_are_prefix_equal(&tmpmpfx->mpfx_prefix,
					 &mpfx->mpfx_prefix,
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
     struct in6_addr *haddr;
{
	struct mip6_prefix *mpfx;

	LIST_FOREACH(mpfx, &mip6_prefix_list, mpfx_entry) {
		if (IN6_ARE_ADDR_EQUAL(haddr,
				       &mpfx->mpfx_haddr)) {
			/* found. */
			return (mpfx);
		}
	}

	/* not found. */
	return (NULL);
}

