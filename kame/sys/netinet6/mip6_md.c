/*	$KAME: mip6_md.c,v 1.29 2001/03/29 05:34:32 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 and 2000 WIDE Project.
 * All rights reserved.
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
 * Author:  Mattias Pettersson <mattias.pettersson@era.ericsson.se>
 *
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#include "opt_ipsec.h"
#endif

/*
 * Mobile IPv6 Movement Detection for Mobile Nodes
 */
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/nd6.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <netinet/in_pcb.h>
#endif
#if !defined(__OpenBSD__) && !defined(__bsdi__)
#include <netinet6/in6_pcb.h>
#endif
#include <netinet6/mip6.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif

#include <net/net_osdep.h>

struct in6_addr	    mip6_php;		/* Primary Home Prefix */
u_int8_t	    mip6_phpl;		/* Primary Home Prefix Length */
struct nd_prefix    *mip6_phpp = NULL;	/* Primary Home Prefix Pointer */
struct nd_prefix    *mip6_pp = NULL;	/* Primary (Care-of) Prefix */
struct in6_addr	    mip6_pdr;		/* Primary Default Router */
struct ifnet	    *mip6_hifp = NULL;	/* ifp holding all Home Addresses */
int                 mip6_md_state = MIP6_MD_UNDEFINED;
int		    mip6_new_homeaddr;
/*
 *  Mobile IPv6 Home Address route state for the Mobile Node.
 *    route_state NET == MD_HOME == network route.
 *    route_state HOST == MD_FOREIGN|UNDEFINED == host route.
 */
int mip6_route_state = MIP6_ROUTE_NET; /* According to MD_UNDEFINED state. */
int mip6_max_lost_advints = MIP6_MAX_LOST_ADVINTS;
int mip6_nd6_delay = 0;
int mip6_nd6_umaxtries = 0;


/*
 ******************************************************************************
 * Function:    mip6_tell_em
 * Description: Print state change and tell event-state machine.
 * Ret value:   -
 ******************************************************************************
 */
static void
mip6_tell_em(int state,
	     struct in6_addr *hp,
	     u_int8_t hpl,
	     struct nd_prefix *pp,
	     struct in6_ifaddr *coa,
	     struct nd_defrouter *dr)  /* Phased out. Just print. */
{
#ifdef MIP6_DEBUG
	mip6_debug("\nNew state: ");
	switch (state) {
		case MIP6_MD_HOME:
			mip6_debug("HOME!\n");
			break;
		case MIP6_MD_FOREIGN:
			mip6_debug("FOREIGN!\n");
			break;
		case MIP6_MD_UNDEFINED:
			mip6_debug("UNDEFINED!\n");
			break;
	}
	mip6_debug("Home Prefix    = %s/%d\n", hp ? ip6_sprintf(hp) : "NULL",
		   hpl);
	mip6_debug("Primary Prefix = %s\n", pp ? ip6_sprintf(
		&pp->ndpr_prefix.sin6_addr) : "NULL");
	mip6_debug("Primary COA    = %s\n", coa ? ip6_sprintf(
		&coa->ia_addr.sin6_addr) : "NULL");
	mip6_debug("Default Router = %s\n", dr ? ip6_sprintf(&dr->rtaddr) 
		   : "NULL");
#endif
	mip6_move(state, hp, hpl, pp, coa);
}



/*
 ******************************************************************************
 * Function:    mip6_php_lookup
 * Description: Find an nd_prefix that matches the primary home prefix.
 *
 *		Side effect: also sets global lookup cache pointer mip6_phpp.
 * Ret value:   A pointer to the nd_prefix, or NULL if there is no such
 *		entry in the prefix list.
 ******************************************************************************
 */
static struct nd_prefix *
mip6_php_lookup(void)
{
	struct nd_prefix *p;

	/*
	 * Check if cached mip6_phpp really points to an nd_prefix
	 * that contains mip6_php and mip6_phpl.
	 */
	if (mip6_phpp != NULL && mip6_phpp->ndpr_stateflags & NDPRF_HOME &&
	    mip6_phpl == mip6_phpp->ndpr_plen &&
	    in6_are_prefix_equal(&mip6_php,
				 &mip6_phpp->ndpr_prefix.sin6_addr,
				 mip6_phpl)) {
		return (mip6_phpp);
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&mip6_php) || mip6_phpl == 0)
			/* XXX error? */
			return NULL;

		for (p = nd_prefix.lh_first; p; p = p->ndpr_next) {
			if (p->ndpr_stateflags & NDPRF_HOME &&
			    mip6_phpl == p->ndpr_plen &&
			    in6_are_prefix_equal(&mip6_php,
						 &p->ndpr_prefix.sin6_addr,
						 mip6_phpl)) {
				break;
			}
		}
		mip6_phpp = p;
		return p;
	}
}



/*
 ******************************************************************************
 * Function:    mip6_is_primhomeprefix
 * Description: Check if this nd_prefix matches the Primary Home Prefix.
 * Ret value:   1 for yes, 0 for no.
 ******************************************************************************
 */
/* XXX Can we merge this into php_lookup() function? */
int
mip6_is_primhomeprefix(struct nd_prefix *pr)
{
	struct nd_prefix *p;

	/*
	 * XXX Important: keep mip6_phpp consistent with mip6_php. If
	 * uncertain, set mip6_phpp to NULL.
	 */
	if (mip6_phpp != NULL && mip6_phpp->ndpr_stateflags & NDPRF_HOME) {
		return ((mip6_phpp == pr) ? 1 : 0);
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&mip6_php) || mip6_phpl == 0)
			return 0;

		for (p = nd_prefix.lh_first; p; p = p->ndpr_next) {
			if (p->ndpr_stateflags & NDPRF_HOME &&
			    mip6_phpl == p->ndpr_plen &&
			    in6_are_prefix_equal(&mip6_php,
						 &p->ndpr_prefix.sin6_addr,
						 mip6_phpl))
			    /* XXX also set mip6_php? */
			    return 1;
		}
		return 0;
	}
}



/*
 ******************************************************************************
 * Function:	mip6_create_ifid
 * Description:	Sets the field "ifid" in the event-state machine based on the
 *		which interface the home prefix is received. 
 *		Does not create a home address in the esm.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_create_ifid(struct ifnet *ifp,
		 struct in6_addr *prefix,
		 u_int8_t prefixlen)
{
	struct mip6_esm		*esp;
	struct ifaddr		*ifa;
	struct in6_ifaddr	*ib;
	u_int8_t		plen0;

	for (esp = mip6_esmq; esp; esp = esp->next) {
		if ((in6_are_prefix_equal(&esp->home_pref, prefix,
					  esp->prefixlen)) &&
			esp->prefixlen == prefixlen)
			break;
	}
	if (esp == NULL)
		return;
	if (!IN6_IS_ADDR_UNSPECIFIED(&esp->ifid))
		return;

	ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(ifp, 0);/* 0 is OK? */
	if (ifa)
		ib = (struct in6_ifaddr *)ifa;
	else
		return;

#if 0 /* don't care link local addr state, and always do DAD */
	/* if link-local address is not eligible, do not autoconfigure. */
	if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_NOTREADY) {
		printf("in6_ifadd: link-local address not ready\n");
		return NULL;
	}
#endif

	/* prefixlen + ifidlen must be equal to 128 */
	plen0 = in6_mask2len(&ib->ia_prefixmask.sin6_addr, NULL);
	if (prefixlen != plen0) {
		log(LOG_INFO, "%s: wrong prefixlen for %s "
		    "(prefix=%d ifid=%d)\n",
		    __FUNCTION__, if_name(ifp), prefixlen, 128 - plen0);
		return;
	}

	/* interface ID */
#define mask ib->ia_prefixmask.sin6_addr
	esp->ifid.s6_addr32[0] = (ib->ia_addr.sin6_addr.s6_addr32[0] &
				   ~mask.s6_addr32[0]);
	esp->ifid.s6_addr32[1] = (ib->ia_addr.sin6_addr.s6_addr32[1] &
				   ~mask.s6_addr32[1]);
	esp->ifid.s6_addr32[2] = (ib->ia_addr.sin6_addr.s6_addr32[2] &
				   ~mask.s6_addr32[2]);
	esp->ifid.s6_addr32[3] = (ib->ia_addr.sin6_addr.s6_addr32[3] &
				   ~mask.s6_addr32[3]);
#undef mask

#ifdef MIP6_DEBUG
	mip6_debug("%s: will use this ifid: %s\n",__FUNCTION__,
		   ip6_sprintf(&esp->ifid));
#endif
}



/*
 ******************************************************************************
 * Function:    mip6_pfxaddr_lookup
 * Description: Find a good interface address that is associated with the
 *		nd_prefix and obeys the flags.
 *		Example of flags:
 * 		  - IN6_IFF_AUTOCONF
 *		Example of negflags:
 *		  - IN6_IFF_TEMPORARY
 * Ret value:   The interface address found or NULL.
 ******************************************************************************
 */
struct in6_ifaddr *
mip6_pfxaddr_lookup(struct nd_prefix *pr, int flags, int negflags)
{
	struct in6_ifaddr *ifa6 = NULL;
	struct ifaddr *ifa;
	struct ifnet *ifp;

	if (pr == NULL)
		return NULL;

	if ((ifp = pr->ndpr_ifp) == NULL)
		return NULL;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		int ifa_plen;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		ifa6 = (struct in6_ifaddr *)ifa;

		/*
		 * Spec is not clear here, but I believe we should concentrate
		 * on unicast (i.e. not anycast) addresses.
		 * XXX: other ia6_flags? detached or duplicated?
		 */
		if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0)
			continue;
		
		ifa_plen = in6_mask2len(&ifa6->ia_prefixmask.sin6_addr, NULL);
		if (ifa_plen != pr->ndpr_plen ||
		    !in6_are_prefix_equal(&ifa6->ia_addr.sin6_addr,
					  &pr->ndpr_prefix.sin6_addr,
					  ifa_plen))
			continue;

		if ((ifa6->ia6_flags & flags) != flags)
			continue;

		if ((ifa6->ia6_flags & negflags) != 0)
			continue;

		if (IFA6_IS_INVALID(ifa6))
			continue;

		/*
		 * This behaviour could be improved.
		 */
		if (IFA6_IS_DEPRECATED(ifa6))
			continue;

		/* 
		 * At least one matched address.
		 */
		return ifa6;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:	mip6_coa_lookup
 * Description: Find a usable interface address associated with this
 *		nd_prefix.
 * Ret value:   The first interface address with same prefix or NULL.
 ******************************************************************************
 */
struct in6_ifaddr *
mip6_coa_lookup(struct nd_prefix *pr)
{
	struct in6_ifaddr *ia6;

	/*
	 * Filter out unwanted prefix types.
	 */
	if (IN6_IS_ADDR_MULTICAST(&pr->ndpr_prefix.sin6_addr) ||
	    IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr))
		return NULL;

	/* Other flags??? */
	ia6 = mip6_pfxaddr_lookup(pr, IN6_IFF_AUTOCONF,
				  IN6_IFF_ANYCAST | IN6_IFF_TEMPORARY);

	return ia6;
}



/*
 ******************************************************************************
 * Function:	mip6_update_home_addrs
 * Description:	Update home addresses. This prefix is already determined to
 *		be a home prefix. Update lifetimes etc on already existing
 *		home addresses. If no associated home address exists for this
 *		prefix, create a new home address on loopback.
 *
 *		Note: home addresses are only updated here. They are bound
 *		to loopback (lo0) and have flag IN6_IFF_HOME set.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_update_home_addrs(struct mbuf *m,
		       struct nd_prefix *pr,
		       int auth)
{
	struct ifnet *ifp = mip6_hifp;
	struct ifaddr *ifa;
	struct in6_ifaddr *ia6_match = NULL, *ia6;
	struct in6_addrlifetime lt6_tmp;
	struct mip6_esm *esp;
	int error;
#define new pr

	if ((!m) || (!pr))
		return;

	/*
	 * Outline below recycled from nd6_prelist_update(): addrconf:
	 */


	/*
	 * Address autoconfiguration based on Section 5.5.3 of RFC 2462.
	 * Note that pr must be non NULL at this point.
	 */

	/* 5.5.3 (a). Ignore the prefix without the A bit set. */
/*  	if (!new->ndpr_raf_auto) */
/*  		goto end; */

	/*
	 * 5.5.3 (b). the link-local prefix should have been ignored in
	 * nd6_ra_input.
	 */

	/*
	 * 5.5.3 (c). Consistency check on lifetimes: pltime <= vltime.
	 * This should have been done in nd6_ra_input.
	 */

 	/*
	 * 5.5.3 (d). If the prefix advertised does not match the prefix of an
	 * address already in the list, and the Valid Lifetime is not 0,
	 * form an address.  Note that even a manually configured address
	 * should reject autoconfiguration of a new address.
	 */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		struct in6_ifaddr *ifa6;
		int ifa_plen;
		u_int32_t storedlifetime;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
		long time_second = time.tv_sec;
#endif

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		ifa6 = (struct in6_ifaddr *)ifa;

		/*
		 * Spec is not clear here, but I believe we should concentrate
		 * on unicast (i.e. not anycast) addresses.
		 * XXX: other ia6_flags? detached or duplicated?
		 */
		if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0)
			continue;
		
		/* 
		 * Only update addresses marked as home addresses.
		 */
		if ((ifa6->ia6_flags & IN6_IFF_HOME) == 0)
			continue;

		ifa_plen = in6_mask2len(&ifa6->ia_prefixmask.sin6_addr, NULL);
		if (ifa_plen != new->ndpr_plen ||
		    !in6_are_prefix_equal(&ifa6->ia_addr.sin6_addr,
					  &new->ndpr_prefix.sin6_addr,
					  ifa_plen))
			continue;

		if (ia6_match == NULL) /* remember the first one */
			ia6_match = ifa6;

		/* Home addresses are regarded not autoconfigured. */
/*  		if ((ifa6->ia6_flags & IN6_IFF_AUTOCONF) == 0) */
/*  			continue; */

		/*
		 * An already autoconfigured address matched.  Now that we
		 * are sure there is at least one matched address, we can
		 * proceed to 5.5.3. (e): update the lifetimes according to the
		 * "two hours" rule and the privacy extension.
		 */
#define TWOHOUR		(120*60)
		lt6_tmp = ifa6->ia6_lifetime;

		storedlifetime = IFA6_IS_INVALID(ifa6) ? 0 :
			(lt6_tmp.ia6t_expire - time_second);

		if (TWOHOUR < new->ndpr_vltime ||
		    storedlifetime < new->ndpr_vltime) {
			lt6_tmp.ia6t_vltime = new->ndpr_vltime;
		} else if (storedlifetime <= TWOHOUR
#if 0
			   /*
			    * This condition is logically redundant, so we just
			    * omit it.
			    * See IPng 6712, 6717, and 6721.
			    */
			   && new->ndpr_vltime <= storedlifetime
#endif
			) {
			if (auth) {
				lt6_tmp.ia6t_vltime = new->ndpr_vltime;
			}
		} else {
			/*
			 * new->ndpr_vltime <= TWOHOUR &&
			 * TWOHOUR < storedlifetime
			 */
			lt6_tmp.ia6t_vltime = TWOHOUR;
		}

		/* The 2 hour rule is not imposed for preferred lifetime. */
		lt6_tmp.ia6t_pltime = new->ndpr_pltime;

		in6_init_address_ltimes(pr, &lt6_tmp);

		/*
		 * When adjusting the lifetimes of an existing temporary
		 * address, only lower the lifetimes.
		 * RFC 3041 3.3. (1).
		 * XXX: how should we modify ia6t_[pv]ltime?
		 */
		if ((ifa6->ia6_flags & IN6_IFF_TEMPORARY) != 0) {
			if (lt6_tmp.ia6t_expire == 0 || /* no expire */
			    lt6_tmp.ia6t_expire >
			    ifa6->ia6_lifetime.ia6t_expire) {
				lt6_tmp.ia6t_expire =
					ifa6->ia6_lifetime.ia6t_expire;
			}
			if (lt6_tmp.ia6t_preferred == 0 || /* no expire */
			    lt6_tmp.ia6t_preferred >
			    ifa6->ia6_lifetime.ia6t_preferred) {
				lt6_tmp.ia6t_preferred =
					ifa6->ia6_lifetime.ia6t_preferred;
			}
		}

		ifa6->ia6_lifetime = lt6_tmp;
	}
	if (ia6_match == NULL && new->ndpr_vltime) {
		/*
		 * No address matched and the valid lifetime is non-zero.
		 * Create a new address.
		 */

		/* XXX Same result every time. Only one esm. */
		for (esp = mip6_esmq; esp; esp = esp->next) {
			if (esp->prefixlen == new->ndpr_plen && 
			    in6_are_prefix_equal(&esp->home_pref, &mip6_php,
						 esp->prefixlen))
				break;
		}
		if (esp == NULL)
			return;
		if (IN6_IS_ADDR_UNSPECIFIED(&esp->ifid)) {
			log(LOG_ERR, "%s: can't create home address, no "
			    "ifid available\n", __FUNCTION__);
			return;
		}

		if ((ia6 = in6_ifadd(new, &esp->ifid)) != NULL) {
			/*
			 * note that we should use pr (not new) for reference.
			 */
/*  			pr->ndpr_refcnt++; */
/*  			ia6->ia6_ndpr = pr; */
			/*
			 * Home Addresses are regarded as not autoconfigured,
			 * since we don't have one single nd_prefix that
			 * has associated lifetimes.
			 */
			ia6->ia6_ndpr = NULL;
			ia6->ia6_flags &= ~IN6_IFF_AUTOCONF;

			ia6->ia6_flags |= IN6_IFF_HOME;

			/*
			 * If this is first address built based on the
			 * preconfigured home prefix, save it in the esm.
			 * This is actually our primary home address.
			 */
			if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)) {
				esp->home_addr = ia6->ia_addr.sin6_addr;
#ifdef MIP6_DEBUG
				mip6_debug("%s: esm home address set to %s\n",
					   __FUNCTION__,
					   ip6_sprintf(&esp->home_addr));
#endif
			}

			/*
			 * Remember to register whenever a new address is
			 * constructed.
			 */
			 if (mip6_incl_br(m))
				 mip6_new_homeaddr = 1;

			/*
			 * RFC 3041 3.3 (2).
			 * When a new public address is created as described
			 * in RFC2462, also create a new temporary address.
			 *
			 * RFC 3041 3.5.
			 * When an interface connects to a new link, a new
			 * randomized interface identifier should be generated
			 * immediately together with a new set of temporary
			 * addresses.  Thus, we specifiy 1 as the 2nd arg of
			 * in6_tmpifadd().
			 */
			if (ip6_use_tempaddr) {
				int e;
				if ((e = in6_tmpifadd(ia6, 1)) != 0) {
					log(LOG_NOTICE, "prelist_update: "
					    "failed to create a temporary "
					    "address, errno=%d\n",
					    e);
				}
			}

			/*
			 * A newly added address might affect the status
			 * of other addresses, so we check and update it.
			 * XXX: what if address duplication happens?
			 */
/*  			pfxlist_onlink_check(); */
		} else {
			/* just set an error. do not bark here. */
			error = EADDRNOTAVAIL; /* XXX: might be unused. */
		}
	}

}



/*
 ******************************************************************************
 * Function:	mip6_create_homeaddr
 * Description:	Create a home address that is static on lo0. Used in backwards 
 *		compatible start-up scenario when home address and possibly the
 *		home agent's unicast address are specfified.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_create_homeaddr(struct mip6_esm *esp)
{
	struct ifnet *ifp = esp->ifp;
	struct in6_aliasreq ifra;
	struct in6_ifaddr *ia;
	int error;
	int prefixlen = esp->prefixlen;

	/*
	 * Code recycled from in6_ifadd().
	 */

	if (esp == NULL)
		return EINVAL;

	if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)) {
		log(LOG_ERR, "%s: error - unspecified home address\n",
			   __FUNCTION__);
		return EINVAL;
	}

	if (esp->prefixlen > 64 && esp->prefixlen != 128) {
		log(LOG_ERR, "%s: error - invalid prefix length %d\n",
			   __FUNCTION__, esp->prefixlen);
		return EINVAL;
	}


	/* make ifaddr */

	bzero(&ifra, sizeof(ifra));
	/*
	 * in6_update_ifa() does not use ifra_name, but we accurately set it
	 * for safety.
	 */
	strncpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));
	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_addr.sin6_addr = esp->home_addr;

	ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	in6_len2mask(&ifra.ifra_prefixmask.sin6_addr, prefixlen);

	/*
	 * lifetime.
	 * XXX: in6_init_address_ltimes would override these values later.
	 * We should reconsider this logic. 
	 */
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
#ifdef MIP6_DEBUG
	mip6_debug("%s: note - home address %s on lo0 is set to infinite "
		   "lifetime\n", __FUNCTION__, ip6_sprintf(&esp->home_addr));
#endif

	/* XXX: scope zone ID? */

#if 0
	ifra.ifra_flags |= IN6_IFF_AUTOCONF; /* obey autoconf */
#endif
	/*
	 * temporarily set the nopfx flag to avoid conflict.
	 * XXX: we should reconsider the entire mechanism about prefix
	 * manipulation.
	 */
	ifra.ifra_flags |= IN6_IFF_NOPFX;

	/* allocate ifaddr structure, link into chain, etc. */
	if ((error = in6_update_ifa(ifp, &ifra, NULL)) != 0) {
		log(LOG_ERR,
		    "in6_ifadd: failed to make ifaddr %s on %s (errno=%d)\n",
		    ip6_sprintf(&ifra.ifra_addr.sin6_addr), if_name(ifp),
		    error);
		return(NULL);	/* ifaddr must not have been allocated. */
	}

	ia = in6ifa_ifpwithaddr(ifp, &ifra.ifra_addr.sin6_addr);

/*  		pr->ndpr_refcnt++; */
/*  		ia6->ia6_ndpr = pr; */
	/*
	 * Home Addresses are regarded as not autoconfigured,
	 * since we don't have one single nd_prefix that
	 * has associated lifetimes.
	 */
	ia->ia6_ndpr = NULL;
	ia->ia6_flags &= ~IN6_IFF_AUTOCONF;

	ia->ia6_flags |= IN6_IFF_HOME;

/*  	return(ia);*/		/* this must NOT be NULL. */
	return 0;
}



/*
 ******************************************************************************
 * Function:	mip6_select_php
 * Description:	Select a new primary home prefix from the valid home addresses.
 *		This is due to expiration of the previous primary home prefix.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_select_php(struct mip6_esm *esp)
{
	struct in6_ifaddr *ia6;
	struct in6_addrlifetime *lt6;

	if (esp == NULL)
		return;

	for (ia6 = in6_ifaddr; ia6; ia6 = ia6->ia_next) {
		/* check address lifetime */

		if ((ia6->ia6_flags & IN6_IFF_HOME) == 0)
			continue;

		lt6 = &ia6->ia6_lifetime;
		if (IFA6_IS_INVALID(ia6))
			continue;

		if (ia6->ia_ifp != esp->ifp)
			continue;

		break;
	}

	if (ia6 == NULL) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: could not find a new primary home address.\n",
			   __FUNCTION__);
#endif
		log(LOG_ERR, "%s: could not find a new primary home "
		    "address.\n", __FUNCTION__);
		return;
	}

	bcopy(&ia6->ia_addr.sin6_addr, &mip6_php, sizeof(mip6_php));
	mip6_php.s6_addr32[0] &= ia6->ia_prefixmask.sin6_addr.s6_addr32[0];
	mip6_php.s6_addr32[1] &= ia6->ia_prefixmask.sin6_addr.s6_addr32[1];
	mip6_php.s6_addr32[2] &= ia6->ia_prefixmask.sin6_addr.s6_addr32[2];
	mip6_php.s6_addr32[3] &= ia6->ia_prefixmask.sin6_addr.s6_addr32[3];

	mip6_phpl = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL);

	mip6_phpp = NULL;

	esp->home_pref = mip6_php;
	esp->prefixlen = mip6_phpl;
	esp->home_addr = ia6->ia_addr.sin6_addr;
	/* XXX ifid? */
}



/*
 ******************************************************************************
 * Function:	mip6_deprecated_addr
 * Description:	If this depracated address is a home address and corresponds 
 *		to the primary home prefix, select a new primary home prefix.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_deprecated_addr(struct in6_ifaddr *ia6)
{
	struct mip6_esm *esp;

	if (ia6 == NULL)
		return;

	if ((ia6->ia6_flags & IN6_IFF_HOME) == 0)
		return;

	/* Only find the primary home addresses. */
	for (esp = mip6_esmq; esp; esp = esp->next) {
		if (!IN6_ARE_ADDR_EQUAL(&esp->home_addr, 
				       &ia6->ia_addr.sin6_addr))
			continue;
		if (esp->type == TEMPORARY)
			continue;
		if (ia6->ia_ifp == esp->ifp)
			break;
	}
	if (esp == NULL)
		return;

	mip6_select_php(esp);
}



/*
 ******************************************************************************
 * Function:	mip6_md_init_with_prefix
 * Description: Given an event-state machine and one home prefix, create
 *		a home address if we are at home. Determine whether we are
 *		at home, at foreign or undefined and take appropriate action.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
static int
mip6_md_init_with_prefix(struct mip6_esm *esp)
{
	struct in6_ifaddr	*ia6 = NULL;
	struct nd_prefix	*pr = NULL;
	struct nd_defrouter	*dr;

	if (esp == NULL)
		return EINVAL;

	/*
	 * Look if preconfigured home prefix already exists. Don't care 
	 * about which ifp.
	 */
	if (esp->prefixlen == 0) {
		log(LOG_ERR, "%s: home prefix length == 0\n", __FUNCTION__);
		return EINVAL;
	}

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		if (esp->prefixlen == pr->ndpr_plen &&
		    in6_are_prefix_equal(&esp->home_pref,
					 &pr->ndpr_prefix.sin6_addr,
					 esp->prefixlen))
			break;
	}
	if (pr) {
		if ((ia6 = mip6_pfxaddr_lookup(pr, IN6_IFF_AUTOCONF,
					       IN6_IFF_ANYCAST | 
					       IN6_IFF_TEMPORARY)) != NULL) {
			/*
			 * This is a good home address.
			 */
			esp->home_addr = ia6->ia_addr.sin6_addr;

			/*
			 * Store the interface ID from this already existing
			 * address of the home prefix.
			 */
			
#define orig ia6->ia_addr.sin6_addr
#define mask ia6->ia_prefixmask.sin6_addr
			esp->ifid.s6_addr32[0] = (orig.s6_addr32[0] &
						  ~mask.s6_addr32[0]);
			esp->ifid.s6_addr32[1] = (orig.s6_addr32[1] &
						  ~mask.s6_addr32[1]);
			esp->ifid.s6_addr32[2] = (orig.s6_addr32[2] &
						  ~mask.s6_addr32[2]);
			esp->ifid.s6_addr32[3] = (orig.s6_addr32[3] &
						  ~mask.s6_addr32[3]);
#undef orig
#undef mask

#ifdef MIP6_DEBUG
			mip6_debug("%s: will use this ifid: %s\n",__FUNCTION__,
				   ip6_sprintf(&esp->ifid));
#endif
		}

		/* 
		 * We can be HOME, UNDEFINED or FOREIGN, with or without
		 * an address.
		 */
	}
	mip6_phpp = pr;
	mip6_php = esp->home_pref;
	mip6_phpl = esp->prefixlen;

	/* XXX Do something about defrouter? */

	/* XXX Should we have or not have an address associated with pr here?
	 * => Well, if we are home, we should have one. On the other hand, if
	 * we are undef or foreign, we should not have one. 
	 * Also important, we need to preserve good interface IDs or create
	 * new good ones. We really should stick to one ID all way through, 
	 * also for multiple addresses or prefixes and during renumbering.
	 */

	/* 
	 * XXX	  
	 * We may need to revise the procedure below, when movement 
	 * detection is written.
	 */

	/* 
	 * XXXYYY Is this line actually correct? Don't we need to check
	 * more than just first dr?
	 */
	dr = TAILQ_FIRST(&nd_defrouter);
	/* 
	 * XXXYYY 
	 * Add check for probably reachable router here as well. Mattias
	 */
	if (pr && pr->ndpr_advrtrs.lh_first && dr &&
	    pfxrtr_lookup(pr, dr)) {
		/* If we have home pfxrtrs and defrtr is one of these, then
		   we're home. */
		mip6_md_state = MIP6_MD_HOME;
/*  		mip6_route_state = MIP6_ROUTE_NET; */

		mip6_send_rs(esp, 0);
 
		mip6_pp = mip6_phpp;
		mip6_pdr = dr->rtaddr;
		mip6_tell_em(MIP6_MD_HOME, &mip6_php, mip6_phpl, NULL,
			     NULL, dr);
	}
	else {
		if (dr) {
			mip6_md_state = MIP6_MD_FOREIGN;
/*  			mip6_route_state = MIP6_ROUTE_HOST; */

			for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
				if ((pfxrtr_lookup(pr, dr) != NULL) &&
				    (ia6 = mip6_coa_lookup(pr)) != NULL) {
					break;
				}
			}
			if (pr) {
				/* 
				 * We can't send tunneled RS here; we don't
				 * know our Home Agent yet.
				 */
				mip6_pp = pr;
				mip6_pdr = dr->rtaddr;
				mip6_tell_em(MIP6_MD_FOREIGN, &mip6_php,
					     mip6_phpl, pr, ia6, dr);
			}
			else {
#ifdef MIP6_DEBUG
				mip6_debug("%s: At FOREIGN, but no primary "
					   "prefix found!\n", __FUNCTION__);
#endif
				goto undefined;
			}
		}
		else {
		  undefined:
			mip6_md_state = MIP6_MD_UNDEFINED;
/*  			mip6_route_state = MIP6_ROUTE_NET; */

			/* We can always try... */
			mip6_send_rs(esp, 0);

			mip6_pdr = in6addr_any;
			mip6_pp = NULL;
			mip6_tell_em(MIP6_MD_UNDEFINED, &mip6_php, mip6_phpl,
				     NULL, NULL, NULL);
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:	mip6_md_init_with_addr
 * Description: Given an event-state machine and one home address, create
 *		a home address on loopback. Determine whether we are at
 *		home, at foreign or undefined and take appropriate action.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
static int
mip6_md_init_with_addr(struct mip6_esm *esp)
{
	struct in6_ifaddr	*ia6 = NULL;
	struct nd_prefix	*pr = NULL;
	struct nd_defrouter	*dr;
	int			error = 0;

	if (esp == NULL)
		return EINVAL;

	/*
	 * Look if preconfigured home prefix already exists. Don't care 
	 * about which ifp.
	 */
	if (esp->prefixlen == 0) {
		log(LOG_ERR, "%s: home prefix length == 0\n", __FUNCTION__);
		return EINVAL;
	}

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		if (esp->prefixlen == pr->ndpr_plen &&
		    in6_are_prefix_equal(&esp->home_pref,
					 &pr->ndpr_prefix.sin6_addr,
					 esp->prefixlen))
			break;
	}

	if ((error = mip6_create_homeaddr(esp)) != 0)
		return error;

	mip6_phpp = pr;
	mip6_php = esp->home_pref;
	mip6_phpl = esp->prefixlen;

	/* XXX Do something about defrouter? */

	/* 
	 * XXX	  
	 * We may need to revise the procedure below, when movement 
	 * detection is written.
	 */

	/* 
	 * XXXYYY Is this line actually correct? Don't we need to check
	 * more than just first dr?
	 */
#ifdef MIP6_DEBUG
	mip6_debug("Defrouter list:\n");
	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		mip6_debug("  %s\n", ip6_sprintf(&dr->rtaddr));
	}
#endif

	dr = TAILQ_FIRST(&nd_defrouter);
	/* 
	 * XXXYYY 
	 * Add check for probably reachable router here as well. Mattias
	 */
	if (pr && pr->ndpr_advrtrs.lh_first && dr &&
	    pfxrtr_lookup(pr, dr)) {
		/* If we have home pfxrtrs and defrtr is one of these, then
		   we're home. */
		mip6_md_state = MIP6_MD_HOME;
/*  		mip6_route_state = MIP6_ROUTE_NET; */

		mip6_send_rs(esp, 0);
 
		mip6_pp = mip6_phpp;
		mip6_pdr = dr->rtaddr;
		mip6_tell_em(MIP6_MD_HOME, &mip6_php, mip6_phpl, NULL,
			     NULL, dr);
	}
	else {
		if (dr) {
			mip6_md_state = MIP6_MD_FOREIGN;
/*  			mip6_route_state = MIP6_ROUTE_HOST; */


#ifdef MIP6_DEBUG
			mip6_debug("Prefix list: (break at first hit)\n");
#endif
			for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
#ifdef MIP6_DEBUG
				struct nd_pfxrouter *search;
				mip6_debug("  P %s\n", 
					   ip6_sprintf(&pr->
						       ndpr_prefix.sin6_addr));
				for (search = pr->ndpr_advrtrs.lh_first; 
				     search; search = search->pfr_next) {
					mip6_debug("    R %s\n", 
						   (search->router) 
						   ? ip6_sprintf(
							   &search->router->
							   rtaddr) : "NULL");
				}
				mip6_debug("    lookup = %s\n",
					   pfxrtr_lookup(pr, dr) ? 
					   "yes" : "NULL");
				/* Phase out!!! */
				mip6_debug("    addr = %s\n", 
					   ip6_sprintf(&pr->ndpr_addr)); 
#endif
				if ((pfxrtr_lookup(pr, dr) != NULL) &&
				    (ia6 = mip6_coa_lookup(pr)) != NULL) {
					break;
				}
			}
			if (pr) {
				/* 
				 * Send a tunneled RS here if we
				 * know our Home Agent.
				 */
				if (!IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn))
					mip6_send_rs(esp, 1);

				mip6_pp = pr;
				mip6_pdr = dr->rtaddr;
				mip6_tell_em(MIP6_MD_FOREIGN, &mip6_php, 
					     mip6_phpl, pr, ia6, dr);
			}
			else {
#ifdef MIP6_DEBUG
				mip6_debug("%s: At FOREIGN, but no primary "
					   "prefix found!\n", __FUNCTION__);
#endif
				goto undefined;
			}
		}
		else {
		  undefined:
			mip6_md_state = MIP6_MD_UNDEFINED;
/*  			mip6_route_state = MIP6_ROUTE_NET; */

			/* We can always try... */
			mip6_send_rs(esp, 0);

			mip6_pdr = in6addr_any;
			mip6_pp = NULL;
			mip6_tell_em(MIP6_MD_UNDEFINED, &mip6_php, mip6_phpl,
				     NULL, NULL, NULL);
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_md_init
 * Description: Scan through the Event-State Machine List.
 *		Initialize every Event-State Machine depending on if it
 *		is configured with a home prefix or a full home address.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_md_init()
{
	struct mip6_esm       *esp; /* Entry in the Event State machine list */
#ifdef OLDMIP6
	struct nd_prefix      *pr, *existing_pr = NULL;
	struct nd_defrouter   *dr;
	struct in6_ifaddr     *ia;
	int                     i, s, error;
#endif /* OLDMIP6 */

	for (esp = mip6_esmq; esp; esp = esp->next) {

#ifdef MIP6_DEBUG
		if (esp != mip6_esmq)
			mip6_debug("%s: Only supporting one home "
				   "prefix in this version.\n", __FUNCTION__);
#endif
		if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)){
			/* No home address given. Only home prefix. */
			mip6_md_init_with_prefix(esp);
		}
		else {
			printf("%s: WARNING, this mode is being phased out "
			       "from Feb 2001 and on. \nYou should try "
			       "specifying only home prefix.\n", 
			       __FUNCTION__);
			mip6_md_init_with_addr(esp);
		}
	}
}


/*
 ******************************************************************************
 * Function:    mip6_select_defrtr
 * Description: Usually called as an extension to defrtrlist_del() when the
 *              previous primary default router times out. Tries to select a
 *              new default router that announces the Primary Home Prefix if 
 *              available.
 *              Manages the Movement Detection state transitions.
 *              Finally informs the event-state machine about any transitions
 *              and new default routers.
 *              Hints to a good prefix and default router to choose can be
 *              provided, which is currently used for Eager Movement Detection
 *		level 2. A disadvantage of level 2 is that the new default 
 *		router is chosen before it's two-way reachability is confirmed.
 *		Only use when you need fast handoffs.
 *              This function is tightly coupled with mip6_prelist_update().
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_select_defrtr(prhint, drhint)
	struct nd_prefix    *prhint;
	struct nd_defrouter *drhint;
{
	struct nd_prefix	*pr = NULL, *phpp;
	struct nd_defrouter	*dr, anydr;
	struct nd_pfxrouter	*pfxrtr;
	struct in6_ifaddr	*ia6 = NULL;
	struct rtentry		*rt = NULL;
	struct llinfo_nd6	*ln = NULL;
	int			s = splnet(), state;

	pr = mip6_pp;
	/* Only for sanity check */
	dr = mip6_pp ?
		defrouter_lookup(&mip6_pdr, mip6_pp->ndpr_ifp) : NULL;
	state = mip6_md_state;

#ifdef MIP6_DEBUG
	mip6_debug("\n");
#endif
#ifdef MIP6_DEBUG
	mip6_debug("%s: previous primary dr = %s.\n", __FUNCTION__,
		   ip6_sprintf(&mip6_pdr));
	mip6_debug("%s: dr = %s.\n", __FUNCTION__,
		   dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif

	if (MIP6_EAGER_PREFIX && prhint && drhint) {
		if (drhint != dr && 
		    (prhint = nd6_prefix_lookup(prhint)) != pr &&
		    pfxrtr_lookup(prhint, drhint)) {
			/*
			 * Check if hints are ok as the new defualt router
			 * and primary prefix. Otherwise use ordinary
			 * selection.
			 */
			dr = drhint;
			pr = prhint;

			/*
			 * Check Care-of Address of the prefix
			 */
			if ((ia6 = mip6_coa_lookup(pr)) != NULL) {
				state = MIP6_MD_FOREIGN;

#ifdef MIP6_DEBUG
				mip6_debug("%s: new probably reachable "
					   "defrtr %s on foreign subnet "
					   "selected in eager mode.\n",
					   __FUNCTION__, 
					   ip6_sprintf(&dr->rtaddr));
#endif

				/*
				 * Place dr first since it's prim.
				 */
				TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
				TAILQ_INSERT_HEAD(&nd_defrouter, dr, dr_entry);
				goto found;
			}
		}
	}
		
	if ( (mip6_md_state == MIP6_MD_HOME) ||
	     (mip6_md_state == MIP6_MD_UNDEFINED) ) {
		if ((pr = mip6_php_lookup()) == NULL){
#ifdef MIP6_DEBUG
			mip6_debug("%s: tried home, but no onlink home "
				   "prefix.\n", __FUNCTION__);
#endif
			goto nothome;
		} 

		if ((MIP6_EAGER_PREFIX &&
		     ((pfxrtr = LIST_FIRST(&pr->ndpr_advrtrs)) != NULL)) ||
		    (!MIP6_EAGER_PREFIX &&
		     ((pfxrtr = find_pfxlist_reachable_router(pr)) != NULL))) {
#ifdef MIP6_DEBUG
			mip6_debug("%s: there are (reachable) pfxrtrs at "
				   "home.\n", __FUNCTION__);
#endif
			if ((ia6 = mip6_coa_lookup(pr)) != NULL) {
				/* Pick first reachable pfxrtr. */
				state = MIP6_MD_HOME;

				dr = pfxrtr->router;

				/* Place dr first since its prim. */
				TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
				TAILQ_INSERT_HEAD(&nd_defrouter, dr, dr_entry);

#ifdef MIP6_DEBUG
				mip6_debug("%s: picking %s as default router "
					   "on home subnet.\n",
					   __FUNCTION__,
					   ip6_sprintf(&(dr->rtaddr)));
#endif
				goto found;
			}
		}

		if (pr->ndpr_advrtrs.lh_first == NULL) {
#ifdef MIP6_DEBUG
			mip6_debug("%s: there are no pfxrtrs at home, trying "
				   "non-home instead.\n", __FUNCTION__);
#endif
		}

		/*
		 * No home prefix defrtr found, just drop through and pick
		 * one by the ordinary procedure below.
		 */
#ifdef MIP6_DEBUG
		mip6_debug("%s: no home prefix router found.\n", __FUNCTION__);
#endif
	}
  nothome:
	/*
	 * Go through the Default Router List in search for a (probably)
	 * reachable router that advertises a prefix and with an associated
	 * Care-of Address. This is a merge from defrouter_select().
	 */
  	if (TAILQ_FIRST(&nd_defrouter)) {
		for (dr = TAILQ_FIRST(&nd_defrouter); dr;
		     dr = TAILQ_NEXT(dr, dr_entry)) {

			if ((rt = nd6_lookup(&dr->rtaddr, 0, dr->ifp)) &&
			    (ln = (struct llinfo_nd6 *)rt->rt_llinfo) &&
			    ND6_IS_LLINFO_PROBREACH(ln)) {

				/*
				 * Find a Care-of Address from a prefix
				 * announced by this router.

				 */
				for (pr = nd_prefix.lh_first; pr;
				     pr = pr->ndpr_next) {
					if ((pfxrtr_lookup(pr, dr) != NULL) &&
					    (ia6 = mip6_coa_lookup(pr))
					    != NULL) {
						state = MIP6_MD_FOREIGN;

#ifdef MIP6_DEBUG
						mip6_debug("%s: new probably reachable defrtr %s on foreign subnet selected.\n", __FUNCTION__, ip6_sprintf(&dr->rtaddr));
#endif

						/*
						 * Place dr first since
						 * it's prim.
						 */
						TAILQ_REMOVE(&nd_defrouter,
							     dr, dr_entry);
						TAILQ_INSERT_HEAD(
							&nd_defrouter,
							dr, dr_entry);

						goto found;
					}
				}
			}
		}

#ifdef OLDMIP6
/*
 * XXX
 * Don't use this at the moment. It might be a bad idea to try to
 * select an unreachable router due to Kame changes. On the other hand,
 * can we now move quickly upon detection of new prefixes? /Mattias 20010221
 *
 * Or do this only at eager 2 for instance? But what about priority of 
 * home prefix...? Same thing actually.
 */
	/*
	 * No (probably) reachable router found that matched our requirements.
	 * Go through the Default Router List again in search for any
	 * router that advertises a prefix and with an associated
	 * Care-of Address. This is a merge from defrouter_select().
	 */
		for(dr = TAILQ_FIRST(&nd_defrouter); dr; dr = TAILQ_NEXT(dr, dr_entry)){
			/*
			 * Find a Care-of Address from a prefix announced by
			 * this router.
			 */
			for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
				if ((pfxrtr_lookup(pr, dr) != NULL) &&
				    ((ia6 = mip6_coa_lookup(pr)) != NULL)) {
					state = MIP6_MD_FOREIGN;

#ifdef MIP6_DEBUG
					mip6_debug("%s: new (unreachable?) "
						   "defrtr %s on foreign subnet "
						   "selected.\n", __FUNCTION__,
						   ip6_sprintf(&dr->rtaddr));
#endif

					/* Place dr first since its prim. */
					TAILQ_REMOVE(&nd_defrouter, dr,
						     dr_entry);
					TAILQ_INSERT_HEAD(&nd_defrouter, dr,
							  dr_entry);
					goto found;
				}
			}
		}
#endif /* OLDMIP6 */
	}

	/*
	 * No new defrtr or no with an associated Care-of Address found
	 * -> State = undefined
	 */
	pr = NULL;
	dr = NULL;
	ia6 = NULL;
	state = MIP6_MD_UNDEFINED;
#ifdef MIP6_DEBUG
	mip6_debug("%s: no new good defrtr found.\n", __FUNCTION__);
#endif

  found:
#ifdef MIP6_DEBUG
	mip6_debug("%s: found: dr = %s.\n", __FUNCTION__, dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif
	if ((dr = TAILQ_FIRST(&nd_defrouter)) != NULL) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: TAILQ: dr = %s.\n", __FUNCTION__, dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif
		/*
		 * De-install the previous default gateway and install
		 * a new one.
		 * Note that if there is no reachable router in the list,
		 * the head entry will be used anyway.
		 * XXX: do we have to check the current routing table entry?
		 */
		bzero(&anydr, sizeof(anydr));
		defrouter_delreq(&anydr, 0);
		defrouter_addreq(dr);
	}
	else {
		/*
		 * The Default Router List is empty, so install the default
		 * route to an inteface.
		 * XXX: The specification does not say this mechanism should
		 * be restricted to hosts, but this would be not useful
		 * (even harmful) for routers.
		 */
		if (!ip6_forwarding) {
			/*
			 * De-install the current default route
			 * in advance.
			 */
			bzero(&anydr, sizeof(anydr));
			defrouter_delreq(&anydr, 0);
			if (nd6_defifp) {
				/*
				 * Install a route to the default interface
				 * as default route.
				 */
				defrouter_addifreq(nd6_defifp);
			}
			else	/* noisy log? */
				log(LOG_INFO, "defrouter_select: "
				    "there's no default router and no default"
				    " interface\n");
		}
	}


	/*
	 * If we grab a (unreachable) defrouter that actually is a home
	 * prefix router, we should consider ourself at home rather than
	 * default foreign.
	 */
	if (dr && ((phpp = mip6_php_lookup()) != NULL)) {
		struct nd_pfxrouter *pfxrtr;

		pfxrtr = pfxrtr_lookup(phpp, dr);
		if (pfxrtr && dr == pfxrtr->router) {
#ifdef MIP6_DEBUG
			mip6_debug("%s: dr = %s is obviously a home pfxrtr.\n", __FUNCTION__, dr ? ip6_sprintf(&dr->rtaddr) : "NULL");
#endif
			state = MIP6_MD_HOME;
			pr = mip6_phpp;
		}
	}

	/*
	 * First case: same router as last time.
	 * Second case: coming from UNDEFINED, we might have had a router, but
	 * we didn't have a care-of address.
	 */
	if (IN6_ARE_ADDR_EQUAL(&mip6_pdr,
			       (dr ? &dr->rtaddr : &in6addr_any)) &&
	    !(dr && mip6_pp == NULL)) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: Warning: Primary default router hasn't "
			   "changed! No action taken.\n", __FUNCTION__);
#endif
		return;
	}

#ifdef OLDMIP6
	/*
	 * Switch between network and host route for the Home Address
	 * in the following cases:
	 *
	 * md_state                route_state
	 *
	 * HOME -> FOREIGN         NET -> HOST
	 * UNDEFINED -> FOREIGN    NET -> HOST
	 * FOREIGN -> HOME         HOST -> NET
	 * FOREIGN -> UNDEFINED    HOST -> NET
	 */

	if ((state == MIP6_MD_HOME || state == MIP6_MD_UNDEFINED)
	    && mip6_route_state == MIP6_ROUTE_HOST) {
		error = mip6_add_ifaddr(&mip6_phpp->ndpr_addr,
					mip6_phpp->ndpr_ifp, 64,
					IN6_IFF_NODAD);
		if (error)
			printf("%s: address assignment error (errno = %d).\n",
			       __FUNCTION__, error);
		mip6_route_state = MIP6_ROUTE_NET;
	}
	else if (state == MIP6_MD_FOREIGN &&
		 mip6_route_state == MIP6_ROUTE_NET) {
		error = mip6_add_ifaddr(&mip6_phpp->ndpr_addr,
					mip6_phpp->ndpr_ifp, 128,
					IN6_IFF_NODAD);
		if (error)
			printf("%s: address assignment error (errno = %d).\n",
			       __FUNCTION__, error);
		mip6_route_state = MIP6_ROUTE_HOST;
	}
#endif /* OLDMIP6 */
	/*
	 * If the Mobile Node has changed its primary prefix (probably due to
	 * a move to a different subnet), clear the Neighbor Cache from entries
	 * cloned from the previous primary prefix. This does not happen when
	 * we keep the same prefix but change default router.
	 */
#ifdef MIP6_DEBUG
	mip6_debug("mip6_pp = %s\n", mip6_pp ? ip6_sprintf(&mip6_pp->ndpr_prefix.sin6_addr) : "NULL");
	mip6_debug("pr      = %s\n", pr ? ip6_sprintf(&pr->ndpr_prefix.sin6_addr) : "NULL");
#endif
	if (mip6_pp && (pr != mip6_pp)) {
		struct llinfo_nd6 *ln;

		/* Taken from nd6_timer() */
		ln = llinfo_nd6.ln_next;
		/* XXX BSD/OS separates this code -- itojun */
		while (ln && ln != &llinfo_nd6) {
			struct rtentry *rt;
			struct ifnet *ifp;
			struct sockaddr_in6 *dst;
			struct llinfo_nd6 *next = ln->ln_next;

			if ((rt = ln->ln_rt) == NULL) {
				ln = next;
				continue;
			}
			if ((ifp = rt->rt_ifp) == NULL) {
				ln = next;
				continue;
			}
			dst = (struct sockaddr_in6 *)rt_key(rt);
			/* sanity check */
			if (!rt)
				panic("rt=0 in %s(ln=%p)\n", __FUNCTION__, ln);
			if (!dst)
				panic("dst=0 in %s(ln=%p)\n", __FUNCTION__, ln);

			/* Skip if the address belongs to us */
			if (ln->ln_expire == 0) {
				ln = next;
				continue;
			}

#ifdef MIP6_DEBUG
			mip6_debug("Checking neighbor %s\n", dst ? ip6_sprintf(&dst->sin6_addr) : "NULL");
#endif
			if (in6_are_prefix_equal(&dst->sin6_addr,
						 &mip6_pp->
						 ndpr_prefix.sin6_addr,
						 mip6_pp->ndpr_plen)) {

			/* Fake an INCOMPLETE neighbor that we're giving up */
				if (ln->ln_hold) {
					m_freem(ln->ln_hold);
					ln->ln_hold = NULL;
				}

#ifdef MIP6_DEBUG
				mip6_debug("Deleting Neighbor %s.\n",
					   ip6_sprintf(&(satosin6(
						   rt_key(rt))->sin6_addr)));
#endif

#ifdef IPSEC
#ifndef __OpenBSD__
				key_sa_routechange(rt_key(rt));
#endif
#endif

#ifdef MIP6_DEBUG
				mip6_debug("Ref count = %d, now pfctlinput\n",
					   rt->rt_refcnt);
#endif

				/* New era */
				pfctlinput(PRC_REDIRECT_HOST, rt_key(rt));

#ifdef MIP6_DEBUG
				mip6_debug("Ref count = %d, now RTM_DELETE\n",
					   rt->rt_refcnt);
#endif
				next = nd6_free(rt);
			}
			ln = next;
			/*
			 * XXX Also remove the link-local addresses which
			 * aren't ours?
			 */
		}

		ln = llinfo_nd6.ln_next;
		while (ln && ln != &llinfo_nd6) {
			struct rtentry *rt;
			struct ifnet *ifp;
			struct sockaddr_in6 *dst;
			struct llinfo_nd6 *next = ln->ln_next;

			if ((rt = ln->ln_rt) == NULL) {
				ln = next;
				continue;
			}
			if ((ifp = rt->rt_ifp) == NULL) {
				ln = next;
				continue;
			}
			dst = (struct sockaddr_in6 *)rt_key(rt);
			/* sanity check */
			if (!rt)
				panic("rt=0 in %s(ln=%p)\n", __FUNCTION__, ln);
			if (!dst)
				panic("dst=0 in %s(ln=%p)\n", __FUNCTION__, ln);

			/* Skip if the address belongs to us */
			if (ln->ln_expire == 0) {
				ln = next;
				continue;
			}

#ifdef MIP6_DEBUG
			mip6_debug("Checking neighbor %s round 2\n", dst ? ip6_sprintf(&dst->sin6_addr) : "NULL");
#endif
			if (in6_are_prefix_equal(&dst->sin6_addr,
						 &mip6_pp->
						 ndpr_prefix.sin6_addr,
						 mip6_pp->ndpr_plen)) {

#ifdef MIP6_DEBUG
				mip6_debug("Deleting Neighbor %s round 2.\n",
					   ip6_sprintf(&(satosin6(
						   rt_key(rt))->sin6_addr)));
#endif

#ifdef MIP6_DEBUG
				mip6_debug("Ref count = %d, now RTM_DELETE\n",
					   rt->rt_refcnt);
#endif
				if (rt && rt->rt_gateway &&
				    rt->rt_gateway->sa_family == AF_LINK) {
					rtrequest(RTM_DELETE, rt_key(rt),
						  (struct sockaddr *)0,
						  rt_mask(rt), 0,
						  (struct rtentry **)0);
				}
			}
			ln = next;
			/*
			 * XXX Also remove the link-local addresses which
			 * aren't ours?
			 */
		}
	}

	/*
	 * Make decision permanent.
	 * Primary Default Router is already set above.
	 */
	mip6_md_state = state;
	mip6_pp = pr;	/* Other depend on this */
	/*
	 * Save rtaddr for next mip6_select_defrtr session.
	 */
	mip6_pdr = dr ? dr->rtaddr : in6addr_any;

	/*
	 * Assumptions made below:
	 *  - dr is the chosen Default Router
	 *  - pr is the new Primary Prefix if we're not home
	 *  - ia6 is the new Care-of Address if we're not home
	 */
	switch (mip6_md_state) {
	case MIP6_MD_HOME:
		mip6_tell_em(mip6_md_state, &mip6_php, mip6_phpl, NULL, NULL,
			     dr);
		break;

	case MIP6_MD_FOREIGN:
		mip6_tell_em(mip6_md_state, &mip6_php, mip6_phpl, pr, ia6, dr);
		break;
	case MIP6_MD_UNDEFINED:
		/*
		 * Note: we pass dr == NULL, but we might have a Default
		 * Router anyway, but with no prefix/Care-of Address
		 * associated.
		 */
		mip6_tell_em(mip6_md_state, &mip6_php, mip6_phpl, NULL, NULL,
			     NULL);
		break;
	}
	splx(s);
	return;
}


/*
 ******************************************************************************
 * Function:    mip6_prelist_update(pr, dr, was_onlink)
 * Description: A hook to ND's prelist_update(). Checks if the Home Prefix
 *              was announced and in that case tries to force the Mobile Node
 *              to select that default router. If the Mobile Node was in
 *              UNDEFINED state we want to select that router immediately, no
 *              matter what the prefix was.
 *		Finally, if we are in eager 2 mode, we select any new
 *		prefix or prefix becoming attached and associating router.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_prelist_update(pr, dr, was_onlink)
	struct nd_prefix    *pr;
	struct nd_defrouter *dr;
	u_char		    was_onlink;
{
	if (dr == NULL) {
		return;
	}
	if (mip6_is_primhomeprefix(pr)) {
		/* 
		 * It was the Primary Home Prefix that was advertised.
		 * Note: we don't want to go into default router selection
		 * during RA processing for other than the primary home
		 * prefix. Drawback: we won't move to home if RA actually
		 * contains some secondary home prefixes but not the primary.
		 * Currently, we consider such a RA configuration corrupt.
		 */
		if (mip6_md_state != MIP6_MD_HOME) {
			/*
			 * We're not home but here's a router advertising
			 * our home prefix => make it primary defrtr and
			 * we're home!
			 */
#ifdef MIP6_DEBUG
			mip6_debug("%s: returning home.\n", __FUNCTION__);
#endif
			mip6_md_state = MIP6_MD_HOME;

			/* State must be home before call. */
			if (TAILQ_FIRST(&nd_defrouter) != NULL) {
				defrouter_select();
			}
			else {
#ifdef MIP6_DEBUG
				mip6_debug("%s: Undef -> Home: no previous "
					   "router available "
					   "at this stage.\n", __FUNCTION__);
#endif
				/* XXXYYY or use defrouter_select()? */
				mip6_select_defrtr(NULL, NULL);
			}
		}
	}
	else if (mip6_md_state == MIP6_MD_UNDEFINED) {
		/*
		 * Take care of transitions from UNDEFINED to FOREIGN, when the
		 * prefix is already known. XXX Now also when the prefix is
		 * new.
		 */
		if (TAILQ_FIRST(&nd_defrouter) != NULL) {
			defrouter_select();
		}
		else {
#ifdef MIP6_DEBUG
			mip6_debug("%s: Strange, no default router available"
				   "at this stage.\n", __FUNCTION__);
#endif
			/* XXXYYY or use defrouter_select()? */
			mip6_select_defrtr(NULL, NULL);
		}
	}
	else if (MIP6_EAGER_PREFIX)
		/*
		 * Note that transistions from any to home is taken care of at
		 * code above, even in eager 2 mode.
		 * Also note that in eager mode we consider a prefix to be
		 * onlink as soon as we hear it, so onlink flag can't be used
		 * here.
		 * was_onlink == 0 for re-attached prefixes or for completetly
		 * new prefixes.
		 */
		if (!was_onlink && LIST_FIRST(&pr->ndpr_advrtrs)) {
#ifdef MIP6_DEBUG
			mip6_debug("%s: eager at re-attached or new prefix.\n",
				   __FUNCTION__);
#endif
			mip6_select_defrtr(pr, dr);
		}
}


#ifdef OLDMIP6
/*
 ******************************************************************************
 * Function:    mip6_eager_prefix(pr, dr)
 * Description:	New prefix is heard. If Eager Movement Detection level 2 is 
 * 		activated, try to make it the primary one.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_eager_prefix(pr, dr)
	struct nd_prefix    *pr;
	struct nd_defrouter *dr;
{
	if (!MIP6_EAGER_PREFIX)
		return;

	if (dr == NULL || pr == NULL) {
		return;
	}
#ifdef MIP6_DEBUG
	mip6_debug("%s: eager at new prefix.\n", __FUNCTION__);
#endif
	mip6_select_defrtr(pr, dr);
}
#endif /* OLDMIP6 */


/*
 ******************************************************************************
 * Function:    mip6_eager_md()
 * Description: If eager Movement Detection is chosen, trim parameters to a
 *              really fast hand-off. The disadvantage is that the detection
 *              becomes very exposed to go into state UNDEFINED if one single
 *              packet is lost. Even more eager Movement Detection will make
 *		the Mobile Node choose new prefixes as the Primary Prefix, even
 * 		before the previous Default Router disappears.
 *		Level 0:    eager Movement Detection off
 *		Level >= 1: eager Movement Detection on, aggressive parameters
 *		Level >= 2: same, plus handoff as soon as new prefixes appears
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_eager_md(int enable)
{
	mip6_config.eager_md = enable;
	if (enable) {
		mip6_max_lost_advints = 1;		/* Aggressive values */
		if (!mip6_nd6_delay) {
			mip6_nd6_delay = nd6_delay;		/* Store */
			mip6_nd6_umaxtries = nd6_umaxtries;	/* Store */
		}
		nd6_delay = 1;				/* Aggressive values */
		nd6_umaxtries = 1;
	}
	else {
		mip6_max_lost_advints = MIP6_MAX_LOST_ADVINTS;
		if (mip6_nd6_delay) {
			nd6_delay = mip6_nd6_delay;		/* Restore */
			nd6_umaxtries = mip6_nd6_umaxtries;	/* Restore */
			mip6_nd6_delay = 0;
			mip6_nd6_umaxtries = 0;
		}
	}
}


/*
 ******************************************************************************
 * Function:    mip6_expired_defrouter()
 * Description: If the field advint_expire (which is parallel to field
 *              expire for router lifetime) times out, allow a small number
 *              of lost Router Advertisements before doubting if this
 *              particular default router is still reachable.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_expired_defrouter(struct nd_defrouter *dr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	if (!dr)
		return;

	if (dr->advint_expire && dr->advint_expire < time_second) {
		if (++(dr->advints_lost) < mip6_max_lost_advints) {
			/* advints_lost starts at 0. max = 1 (or more). */
			dr->advint_expire = time_second + dr->advint / 1000;
#ifdef MIP6_DEBUG
			mip6_debug("Adv Int #%d lost from router %s.\n",
				   dr->advints_lost, ip6_sprintf(&dr->rtaddr));
#endif
		}
		else {
			dr->advint_expire = 0;
#ifdef MIP6_DEBUG
			mip6_debug("Adv Int #%d lost from router %s.\n",
				   dr->advints_lost, ip6_sprintf(&dr->rtaddr));
#endif
			mip6_probe_defrouter(dr);
		}
	}
}


/*
 ******************************************************************************
 * Function:    mip6_probe_defrouter()
 * Description: Probes a default router to see if it is still reachable.
 *              Ordinary Neigbor Discovery routines (NUD) takes care of the
 *              rest. Puts this router into ND state PROBE.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_probe_defrouter(struct nd_defrouter *dr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif
	struct rtentry *rt;
	struct llinfo_nd6 *ln;

	if (!dr)
		return;

	if (!(rt = nd6_lookup(&dr->rtaddr, 0, NULL)))
		return;

	if ((rt->rt_flags & RTF_GATEWAY)
	    || (rt->rt_flags & RTF_LLINFO) == 0
	    || !rt->rt_llinfo
	    || !rt->rt_gateway
	    || rt->rt_gateway->sa_family != AF_LINK) {
		/* This is not a host route. */
		return;
	}

	ln = (struct llinfo_nd6 *)rt->rt_llinfo;
	if ((ln->ln_state == ND6_LLINFO_INCOMPLETE)
	    || (ln->ln_state == ND6_LLINFO_PROBE)
	    || (ln->ln_state == ND6_LLINFO_NOSTATE))
		return;

	/* Force state to PROBE, simulate DELAY->PROBE */
	ln->ln_asked = 1;
	ln->ln_state = ND6_LLINFO_PROBE;
	ln->ln_expire = time_second +
		nd_ifinfo[rt->rt_ifp->if_index].retrans / 1000;
	nd6_ns_output(rt->rt_ifp, &dr->rtaddr, &dr->rtaddr,
		      ln, 0);
#ifdef MIP6_DEBUG
	mip6_debug("Probing defrouter %s\n", ip6_sprintf(&dr->rtaddr));
#endif
}


/*
 ******************************************************************************
 * Function:    mip6_probe_pfxrtrs()
 * Description: If a new or previously detached prefix is heard, probe (NUD)
 *              all prefix routers on the current primary prefix in order to
 *              quickly detect if we have moved. This is only enabled in
 *              eager Movement Detection (level 1 and 2).
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_probe_pfxrtrs()
{
	struct nd_pfxrouter *pfr;
	if (!mip6_config.eager_md)
		return;

	if (!mip6_pp)
		return;

#ifdef MIP6_DEBUG
	mip6_debug("New or detached prefix received, probe old routers:\n");
#endif
	for (pfr = mip6_pp->ndpr_advrtrs.lh_first;
	     pfr; pfr = pfr->pfr_next) {
		mip6_probe_defrouter(pfr->router);
	}
}


/*
 ******************************************************************************
 * Function:    mip6_store_advint(ai, dr)
 * Description: If Advertisement Interval option is available in Router
 *              Advertisements, keep a timer for this expiry parallel to the
 *              ordinary Router lifetime timer.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_store_advint(struct nd_opt_advinterval *ai,
		  struct nd_defrouter *dr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	/* Check the advertisement interval option */
	if (ai->nd_opt_adv_len != 1) {
		log(LOG_INFO, "%s: bad Advertisement Interval Option "
		    "length\n", __FUNCTION__);
	}
	else if (dr) {
		dr->advint = ntohl(ai->nd_opt_adv_interval); /* milliseconds */

		/* Sorry for delay between reception and this setting */
		dr->advint_expire = time_second + dr->advint / 1000;
		dr->advints_lost = 0;
	}
}


/*
 ******************************************************************************
 * Function:    mip6_delete_ifaddr
 * Description: Similar to "ifconfig <ifp> <addr> delete".
 * Ret value:   -
 ******************************************************************************
 */
int
mip6_delete_ifaddr(struct in6_addr *addr,
		   struct ifnet *ifp)
{
	struct in6_aliasreq  *ifra, dummy;
	struct sockaddr_in6 *sa6;
	struct	in6_ifaddr *ia, *oia;
	int s;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifa;
#endif

	bzero(&dummy, sizeof(dummy));
	ifra = &dummy;

	ifra->ifra_addr.sin6_len = sizeof(ifra->ifra_addr);
	ifra->ifra_addr.sin6_family = AF_INET6;
	ifra->ifra_addr.sin6_addr = *addr;

	sa6 = &ifra->ifra_addr;

	if (ifp == 0)
		return(EOPNOTSUPP);

	s = splnet();

	/*
	 * Code recycled from in6_control().
	 */

	/*
	 * Find address for this interface, if it exists.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
		if (sa6->sin6_addr.s6_addr16[1] == 0) {
				/* interface ID is not embedded by the user */
			sa6->sin6_addr.s6_addr16[1] =
				htons(ifp->if_index);
		}
		else if (sa6->sin6_addr.s6_addr16[1] !=
			 htons(ifp->if_index)) {
			splx(s);
			return(EINVAL);	/* ifid is contradict */
		}
		if (sa6->sin6_scope_id) {
			if (sa6->sin6_scope_id !=
			    (u_int32_t)ifp->if_index) {
				splx(s);
				return(EINVAL);
			}
			sa6->sin6_scope_id = 0; /* XXX: good way? */
		}
	}
 	ia = in6ifa_ifpwithaddr(ifp, &ifra->ifra_addr.sin6_addr);

	/*
	 * for IPv4, we look for existing in6_ifaddr here to allow
	 * "ifconfig if0 delete" to remove first IPv4 address on the
	 * interface.  For IPv6, as the spec allow multiple interface
	 * address from the day one, we consider "remove the first one"
	 * semantics to be not preferrable.
	 */
	if (ia == 0) {
		splx(s);
		return(EADDRNOTAVAIL);
	}
	/* FALLTHROUGH */

	if (ia == 0) {
		ia = (struct in6_ifaddr *)
			malloc(sizeof(*ia), M_IFADDR, M_WAITOK);
		if (ia == NULL) {
			splx(s);
			return (ENOBUFS);
		}
		bzero((caddr_t)ia, sizeof(*ia));
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
		ia->ia_ifa.ifa_dstaddr
			= (struct sockaddr *)&ia->ia_dstaddr;
		ia->ia_ifa.ifa_netmask
			= (struct sockaddr *)&ia->ia_prefixmask;

		ia->ia_ifp = ifp;
		if ((oia = in6_ifaddr) != NULL) {
			for ( ; oia->ia_next; oia = oia->ia_next)
				continue;
			oia->ia_next = ia;
		} else
			in6_ifaddr = ia;
		/* gain a refcnt for the link from in6_ifaddr */
		IFAREF(&ia->ia_ifa);

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		if ((ifa = ifp->if_addrlist) != NULL) {
			for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
				continue;
			ifa->ifa_next = &ia->ia_ifa;
		} else
			ifp->if_addrlist = &ia->ia_ifa;
#else
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, &ia->ia_ifa,
				  ifa_list);
#endif
		/* gain another refcnt for the link from if_addrlist */
		IFAREF(&ia->ia_ifa);
	}

	in6_purgeaddr(&ia->ia_ifa);

	splx(s);
	return(0);
}


#if 0
/*
 ******************************************************************************
 * Function:    mip6_delete_ifaddr
 * Description: Similar to "ifconfig <ifp> <addr> delete".
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_delete_ifaddr(struct in6_addr *addr,
                   struct ifnet *ifp)
{
    struct in6_aliasreq  in6_addreq;
    int s, error = 0;

    bzero(&in6_addreq, sizeof(in6_addreq));
    in6_addreq.ifra_addr.sin6_len = sizeof(in6_addreq.ifra_addr);
    in6_addreq.ifra_addr.sin6_family = AF_INET6;
    in6_addreq.ifra_addr.sin6_addr = *addr;

    s =splnet();
    error = in6_control(NULL, SIOCDIFADDR_IN6, (caddr_t)&in6_addreq, ifp
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
			    , NULL
#endif
			    );
    splx(s);
    if (error) {
#ifdef MIP6_DEBUG
        mip6_debug("%s: Attempt to delete addr %s failed.\n", __FUNCTION__,
              ip6_sprintf(addr));
#endif
    }
}
#endif /* 0 */

struct nd_prefix *
mip6_get_home_prefix(void)
{
	return(mip6_phpp); /* XXX */
}


int
mip6_get_md_state(void)
{
	return(mip6_md_state);
}


/*
 ******************************************************************************
 * Function:    mip6_md_exit
 * Description: Tidy up after the Mobile IPv6 Movement Detection. This is
 *              used when releasing the kernel module. All Home Addresses
 *		on loopback are released. If at home,the prefix and address
 *		will be automagically configured as specified by ND.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_md_exit()
{
/*  	struct nd_prefix *pr; */

#if 1
	panic("mip6_md_exit(): this function is broken");
#else
#warning This function is broken.
#endif
	/*
	 * XXXYYY Should use mip6_esmq when multiple Home Addresses are
	 * supported.
	 */

	mip6_phpp = NULL;
	mip6_php = in6addr_any;
	mip6_phpl = 0;
	mip6_pp = NULL;
#if 0
/* 
 * Todo: go through all ESMs and delete all home addresses on lo0 for each
 * esm.
 *
 * Clear NDPRF_HOME on prefixes.
 */
/*XXX*/	pr = mip6_phpp;
	if (pr && pr->ndpr_ifp && !IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr)) {
		mip6_delete_ifaddr(&pr->ndpr_addr, pr->ndpr_ifp);

		prelist_remove(pr);
		mip6_phpp = NULL;
		mip6_php = in6addr_any;
#ifdef MIP6_DEBUG
		mip6_debug("Home Prefix and Home Address removed.\n");
#endif
	}
#endif /* 0 */
}
