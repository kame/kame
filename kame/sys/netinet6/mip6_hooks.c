/*	$KAME: mip6_hooks.c,v 1.14 2001/03/29 05:34:32 itojun Exp $	*/

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
 * Authors: Mattias Pettersson <mattias.pettersson@era.ericsson.se>
 *          Hesham Soliman <hesham.soliman@ericsson.com.au>
 *          Martti Kuparinen <martti.kuparinen@ericsson.com>
 *
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

/*
 * These are defined in sys/netinet6/
 */

/* Home Agent-specific hooks */
extern int  (*mip6_write_config_data_ha_hook)(u_long, void *);
extern int  (*mip6_clear_config_data_ha_hook)(u_long, void *);
extern int  (*mip6_enable_func_ha_hook)(u_long, caddr_t);

/* Mobile Node-specific hooks */
extern void (*mip6_select_defrtr_hook)(struct nd_prefix *,
				       struct nd_defrouter *);
extern struct nd_prefix * (*mip6_get_home_prefix_hook)(void);
extern void (*mip6_prelist_update_hook)(struct nd_prefix *,
					struct nd_defrouter *,
					u_char);
extern void (*mip6_expired_defrouter_hook)(struct nd_defrouter *);
extern void (*mip6_eager_prefix_hook)(struct nd_prefix *pr,
				      struct nd_defrouter *dr);
extern void (*mip6_probe_pfxrtrs_hook)(void);
extern void (*mip6_store_advint_hook)(struct nd_opt_advinterval *,
				      struct nd_defrouter *);
extern int  (*mip6_get_md_state_hook)(void);
extern int  (*mip6_write_config_data_mn_hook)(u_long, void *);
extern int  (*mip6_clear_config_data_mn_hook)(u_long, caddr_t);
extern int  (*mip6_enable_func_mn_hook)(u_long, caddr_t);
extern void (*mip6_minus_a_case_hook)(struct nd_prefix *);


void
mip6_minus_a_case(struct nd_prefix *pr)
{
	struct in6_addr   addr;
	struct in6_ifaddr *ia6;

	if ((ia6 = mip6_coa_lookup(pr)) == NULL) {
		return;
	}

	addr = in6addr_any;
	mip6_esm_create(pr->ndpr_ifp, NULL, &addr, &ia6->ia_addr.sin6_addr,
			&pr->ndpr_prefix.sin6_addr,
			pr->ndpr_plen, MIP6_STATE_UNDEF, PERMANENT, 0xFFFF);
#ifdef MIP6_DEBUG
	mip6_debug("Late Home Address %s found for autoconfig'd case. Starting"
		   " Mobile IPv6.\n", ip6_sprintf(&ia6->ia_addr.sin6_addr));
#endif
	mip6_minus_a_case_hook = 0;
	mip6_enable_hooks(MIP6_SPECIFIC_HOOKS);
	mip6_md_init();
}

struct nd_prefix *
mip6_find_auto_home_addr(struct in6_ifaddr **ia6p)
{
	struct nd_prefix *pr;
#if 0
	struct in6_ifaddr *ia6;
#endif

	if (ia6p == NULL)
		return NULL;

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: scanning prefix %s (pr = %p)\n", __FUNCTION__,
			   ip6_sprintf(&pr->ndpr_prefix.sin6_addr), pr);
#endif
		if ((*ia6p = mip6_coa_lookup(pr)) == NULL) {
			continue;
		}
#if 0
		ia6 = in6ifa_ifpwithaddr(pr->ndpr_ifp, &pr->ndpr_addr);
		if (ia6 && (ia6->ia6_flags | IN6_IFF_DETACHED))
			continue;
		else
			break;  /* XXXYYY Remove in v2.0. */
#else
#ifdef MIP6_DEBUG
		mip6_debug("%s: skipping detached test on prefix %s "
			   "(pr = %p)\n", __FUNCTION__,
			   ip6_sprintf(&pr->ndpr_prefix.sin6_addr), pr);
#endif
		break;
#endif
#if 0		/* XXXYYY Add in v2.0 */
		for (pfxrtr = pr->ndpr_advrtrs.lh_first; pfxrtr;
		     pfxrtr = pfxrtr->pfr_next) {
			if ((pfxrtr->router->flags & ND_RA_FLAG_HA)
			    == ND_RA_FLAG_HA)
				break;
		}
#endif /* 0 */
	}
	if (*ia6p) {
#ifdef MIP6_DEBUG
		mip6_debug("Found an autoconfigured home address "
			   "immediately: %s\n", 
			   ip6_sprintf(&(*ia6p)->ia_addr.sin6_addr));
#endif
	}
	else {
#ifdef MIP6_DEBUG
		mip6_debug("Couldn't find an autoconfigured home address "
			   "immediately.\n");
#endif
	}
	return pr;
}


void
mip6_enable_hooks(int scope)
{
	int  s;

	/*
	 * Activate the hook functions. After this some packets might come
	 * to the module...
	 * Note: mip6_minus_a_case_hook() is an exception and is not handled
	 * here.
	 */
	s = splimp();

	if (scope == MIP6_CONFIG_HOOKS) {
		/* Activate Home Agent-specific hooks */
		mip6_write_config_data_ha_hook = mip6_write_config_data_ha;
		mip6_clear_config_data_ha_hook = mip6_clear_config_data_ha;
		mip6_enable_func_ha_hook = mip6_enable_func_ha;

		/* Activate Mobile Node-specific hooks */
		mip6_write_config_data_mn_hook = mip6_write_config_data_mn;
		mip6_clear_config_data_mn_hook = mip6_clear_config_data_mn;
		mip6_enable_func_mn_hook = mip6_enable_func_mn;
	}

	if (scope == MIP6_SPECIFIC_HOOKS) {
		/* Activate Mobile Node-specific hooks */
		if (MIP6_IS_MN_ACTIVE) {
			mip6_select_defrtr_hook = mip6_select_defrtr;
			mip6_get_home_prefix_hook = mip6_get_home_prefix;
			mip6_prelist_update_hook = mip6_prelist_update;
			mip6_expired_defrouter_hook = mip6_expired_defrouter;
#ifdef OLDMIP6
			mip6_eager_prefix_hook = mip6_eager_prefix;
#endif
			mip6_probe_pfxrtrs_hook = mip6_probe_pfxrtrs;
			mip6_store_advint_hook = mip6_store_advint;
			mip6_get_md_state_hook = mip6_get_md_state;
		}
	}
	splx(s);
	return;
}


void
mip6_disable_hooks(int scope)
{
	int  s;

	/*
	 * Deactivate the hook functions. After this some packets might not
	 * come to the module...
	 */
	s = splimp();

	if (scope == MIP6_SPECIFIC_HOOKS) {
		/* De-activate Home Agent-specific hooks */
		if (MIP6_IS_HA_ACTIVE) {
			mip6_write_config_data_ha_hook = 0;
			mip6_clear_config_data_ha_hook = 0;
			mip6_enable_func_ha_hook = 0;
		}

		/* De-activate Mobile Node-specific hooks */
		if (MIP6_IS_MN_ACTIVE) {
			mip6_select_defrtr_hook = 0;
			mip6_get_home_prefix_hook = 0;
			mip6_prelist_update_hook = 0;
			mip6_expired_defrouter_hook = 0;
			mip6_eager_prefix_hook = 0;
			mip6_probe_pfxrtrs_hook = 0;
			mip6_store_advint_hook = 0;
			mip6_get_md_state_hook = 0;
			mip6_write_config_data_mn_hook = 0;
			mip6_clear_config_data_mn_hook = 0;
			mip6_enable_func_mn_hook = 0;
			mip6_minus_a_case_hook = 0;
		}
	}
	splx(s);
	return;
}


int
mip6_attach(int module)
{
	/*
	 * Important that necessary settings have been done _before_ calling
	 * mip6_attach(), e.g. home address or home prefix specified, or 
	 * autoconfig set. "mip6config" program sees to that.
	 */

/*
  No support for modules here yet.  XXXYYY

  Old check (not valid any longer):
  #if (defined(MIP6_MN) || defined (MIP6_HA) || defined(MIP6_MODULES))
*/
	if (mip6_module) {
#ifdef MIP6_DEBUG
		char *hastr = "Home Agent";
		char *mnstr = "Mobile Node";

		mip6_debug("Can't switch operation mode from ");
		switch (mip6_module) {
			case MIP6_HA_MODULE:
				mip6_debug("%s", hastr);
				break;
			case MIP6_MN_MODULE:
				mip6_debug("%s", mnstr);
				break;
			default:
				mip6_debug("?");
		}
		mip6_debug(" to ");
		switch (module) {
			case MIP6_HA_MODULE:
				mip6_debug("%s", hastr);
				break;
			case MIP6_MN_MODULE:
				mip6_debug("%s", mnstr);
				break;
			default:
				mip6_debug("?");
		}
		mip6_debug(" \n"
			   "- please deactivate first (\"mip6config -x\")\n");
#endif		
		return EINVAL;
	}

	switch (module) {
	case MIP6_HA_MODULE:
		printf("%s: attach ha\n", __FUNCTION__); /* RM */
		mip6_module = module;
		mip6_ha_init();
		break;

	case MIP6_MN_MODULE:
		printf("%s: attach mn\n", __FUNCTION__); /* RM */
		mip6_module = module;
		mip6_mn_init();
		break;

	default:
#ifdef MIP6_DEBUG
		mip6_debug("%s: illegal attach (module = %d)\n", __FUNCTION__,
			   module);
#endif
		return EINVAL;
	}

	if (MIP6_IS_MN_ACTIVE) {
		if(mip6_get_home_prefix_hook)       /* Test arbitrary hook */
			return 0;

		/*
		 * If autoconfig state: find a global address to use as Home
		 * Address.
		 * - Take first available on any interface, else if no found:
		 * - Enable hook to wait for a Router Advertisement to give
		 *   us one.
		 */
		if (mip6_config.autoconfig) {
			struct nd_prefix *pr;
			struct in6_addr   addr;
			struct in6_ifaddr *ia6;

			addr = in6addr_any;
			if ((pr = mip6_find_auto_home_addr(&ia6)) != NULL) {
				mip6_esm_create(pr->ndpr_ifp, &addr, &addr,
						&ia6->ia_addr.sin6_addr,
						&pr->ndpr_prefix.sin6_addr,
						pr->ndpr_plen,
						MIP6_STATE_UNDEF, PERMANENT,
						0xFFFF);
				mip6_enable_hooks(MIP6_SPECIFIC_HOOKS);
				mip6_md_init();
			}
			else {
#ifdef MIP6_DEBUG
				mip6_debug("Waiting for Router Advertisement "
					   "to give me an address.\n");
#endif
				mip6_minus_a_case_hook = mip6_minus_a_case;
			}
		}
		else {
			/* Manual config */
			mip6_enable_hooks(MIP6_SPECIFIC_HOOKS);
			mip6_md_init();
		}
	}

	if (MIP6_IS_HA_ACTIVE) {
		/* XXXYYY Build anycast or is it done? */
		mip6_enable_hooks(MIP6_SPECIFIC_HOOKS);
	}
	return 0;
}


int
mip6_release(void)
{
	/* Disable the hooks */
	mip6_disable_hooks(MIP6_SPECIFIC_HOOKS);

	if (MIP6_IS_MN_ACTIVE) {
		mip6_mn_exit();
		mip6_md_exit();
	}

	if (MIP6_IS_HA_ACTIVE)
		mip6_ha_exit();

/*
  Correspondent Node functionality is never terminated.
  mip6_disable_hooks(MIP6_GENERIC_HOOKS);
  mip6_exit();
*/

	mip6_module = 0;   /* Make HA or MN inactive */

	return 0;
}
