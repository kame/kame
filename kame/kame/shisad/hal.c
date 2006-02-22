/*	$KAME: hal.c,v 1.8 2006/02/22 11:03:50 mitsuya Exp $	*/

/*
 * Copyright (C) 2005 WIDE Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif /* __NetBSD__ */
#include <netinet/in.h>
#include <netinet/ip6mh.h>
#include <netinet6/mip6.h>
#include <netinet/icmp6.h>

#include "callout.h"
#include "command.h"
#include "stat.h"
#include "shisad.h"

extern struct mip6_hpfx_list hpfx_head; 
extern struct mip6_mipif_list mipifhead;

#ifdef MIP_MN
/* search the best HA for hoainfo */
struct home_agent_list *
mip6_find_hal(hoainfo)
	struct mip6_hoainfo *hoainfo;
{
        struct mip6_hpfxl *hpfx;
	struct mip6_mipif *mipif = NULL;

	mipif = mnd_get_mipif(hoainfo->hinfo_ifindex);
	if (mipif == NULL)
		return (NULL);

	LIST_FOREACH(hpfx, &mipif->mipif_hprefx_head, hpfx_entry) {
		if (inet_are_prefix_equal(&hoainfo->hinfo_hoa, 
					  &hpfx->hpfx_prefix, hpfx->hpfx_prefixlen)) {
			return (LIST_FIRST(&hpfx->hpfx_hal_head));
		}
	}

	return (NULL);
}
#ifdef DSMIP
struct home_agent_list *
mip6_find_hal_v6(hoainfo)
	struct mip6_hoainfo *hoainfo;
{
	struct mip6_hpfxl *hpfx;
	struct mip6_mipif *mipif = NULL;
	struct home_agent_list *hal;

	mipif = mnd_get_mipif(hoainfo->hinfo_ifindex);
	if (mipif == NULL)
		return (NULL);

	LIST_FOREACH(hpfx, &mipif->mipif_hprefx_head, hpfx_entry) {
		if (inet_are_prefix_equal(&hoainfo->hinfo_hoa,
		    &hpfx->hpfx_prefix, hpfx->hpfx_prefixlen)) {
			LIST_FOREACH(hal, &hpfx->hpfx_hal_head, hal_entry) {
				if(!IN6_IS_ADDR_V4MAPPED(&hal->hal_ip6addr))
					return (hal);
			}
		}
	}

	return (NULL);
}
#endif /* DSMIP */
#endif /* MIP_MN */

#ifdef MIP_HA
struct home_agent_list *
had_add_hal(hpfx_entry, gladdr, lladdr, lifetime, preference, flag) 
	struct  mip6_hpfxl *hpfx_entry;
	struct in6_addr *gladdr;
	struct in6_addr *lladdr;
	uint16_t lifetime;
	uint16_t preference;
	int flag;
{
	struct home_agent_list *hal = NULL, *h;

	hal = mip6_get_hal(hpfx_entry, gladdr);
	if (hal && ((hal->hal_preference != preference))) {
		/* if preference is changed, need to re-arrange order of hal */
		mip6_delete_hal(hpfx_entry, gladdr);
		hal = NULL;
	}

	if (hal == NULL) {
		hal = malloc(sizeof(*hal));
		if (hal == NULL)
			return (NULL);
		memset(hal, 0, sizeof(*hal));

		if (LIST_EMPTY(&hpfx_entry->hpfx_hal_head))  {
			LIST_INSERT_HEAD(&hpfx_entry->hpfx_hal_head, hal, hal_entry);
		} else {
			LIST_FOREACH(h, &hpfx_entry->hpfx_hal_head, hal_entry) {
				if (preference >= h->hal_preference) {
					LIST_INSERT_BEFORE(h, hal, hal_entry);
					break;
				} else if (LIST_NEXT(h, hal_entry) == NULL) {
					LIST_INSERT_AFTER(h, hal, hal_entry);
					break;
				}
			}
		}
	}

	hal->hal_ip6addr = *gladdr;
	if (lladdr)
		hal->hal_lladdr = *lladdr;
	hal->hal_lifetime = lifetime;
	hal->hal_preference = preference;
	hal->hal_flag = flag;

	if (hal->hal_expire)
		update_callout_entry(hal->hal_expire, hal->hal_lifetime);
	else if (hal->hal_flag != MIP6_HAL_OWN)
		hal_set_expire_timer(hal, hal->hal_lifetime);

	if (debug)
		syslog(LOG_INFO, "Home Agent (%s, %d %d) added into home agent list\n", 
		       ip6_sprintf(gladdr), lifetime, preference);
		
	return (hal);
}

struct mip6_hpfxl *
had_add_hpfxlist(home_prefix, home_prefixlen) 
	struct in6_addr *home_prefix;
	u_int16_t home_prefixlen;
{
	struct mip6_hpfxl *hpfx = NULL;

	hpfx = mip6_get_hpfxlist(home_prefix, home_prefixlen, &hpfx_head);
	if (hpfx)
		return (hpfx);

	hpfx = malloc(sizeof(*hpfx));
	if (hpfx == NULL)
		return (NULL);
	memset(hpfx, 0, sizeof(*hpfx));

	hpfx->hpfx_prefix = *home_prefix;
	hpfx->hpfx_prefixlen = home_prefixlen;
	LIST_INIT(&hpfx->hpfx_hal_head);

	if (debug)
		syslog(LOG_INFO, "Home Prefix (%s/%d) added into home prefix list\n", 
		       ip6_sprintf(home_prefix), home_prefixlen);
	
	LIST_INSERT_HEAD(&hpfx_head, hpfx, hpfx_entry);
	return (hpfx);
}
#endif /* MIP_HA */

void
mip6_flush_hal(hpfx_entry, exception_flag)
	struct mip6_hpfxl *hpfx_entry;
	int exception_flag;
{
        struct home_agent_list *hal = NULL, *haln = NULL;

        for (hal = LIST_FIRST(&hpfx_entry->hpfx_hal_head); hal; hal = haln) {
                haln =  LIST_NEXT(hal, hal_entry);

		if (exception_flag & hal->hal_flag)
			continue;

		LIST_REMOVE(hal, hal_entry);
		hal_stop_expire_timer(hal);
		free(hal);
	}

	return;
}

void
mip6_delete_hal(hpfx_entry, gladdr) 
	struct mip6_hpfxl *hpfx_entry;
	struct in6_addr *gladdr;
{
	struct home_agent_list *hal;

	hal = mip6_get_hal(hpfx_entry, gladdr);
	if (hal == NULL)
		return;

	LIST_REMOVE(hal, hal_entry);
	hal_stop_expire_timer(hal);
	free(hal);
	hal = NULL;

	return;
}

struct home_agent_list *
mip6_get_hal(hpfx, global)
	struct mip6_hpfxl *hpfx;
	struct in6_addr *global;
{
        struct home_agent_list *hal = NULL, *haln = NULL;

        for (hal = LIST_FIRST(&hpfx->hpfx_hal_head); hal; hal = haln) {
                haln =  LIST_NEXT(hal, hal_entry);
		
		if (IN6_ARE_ADDR_EQUAL(&hal->hal_ip6addr, global))
			return (hal);
	}

	return (NULL);
}


void
hal_set_expire_timer(hal, tick)
        struct home_agent_list *hal;
        int tick;
{
        remove_callout_entry(hal->hal_expire);
        hal->hal_expire = new_callout_entry(tick, hal_expire_timer,
					    (void *)hal, "hal_expire_timer");
}

void
hal_stop_expire_timer(hal)
        struct home_agent_list *hal;
{
        remove_callout_entry(hal->hal_expire);
}

void
hal_expire_timer(arg)
        void *arg;
{
        struct home_agent_list *hal = (struct home_agent_list *)arg;

	hal_stop_expire_timer(hal);

	LIST_REMOVE(hal, hal_entry);
	free(hal);
	hal = NULL;
}

void
mip6_delete_hpfxlist(home_prefix, home_prefixlen, hpfxhead) 
	struct in6_addr *home_prefix;
	u_int16_t home_prefixlen;
	struct mip6_hpfx_list *hpfxhead;
{
	struct mip6_hpfxl *hpfx = NULL;
	struct home_agent_list *hal, *haln;

	hpfx = mip6_get_hpfxlist(home_prefix, home_prefixlen, hpfxhead);
	if (hpfx == NULL)
		return;

	for (hal = LIST_FIRST(&hpfx->hpfx_hal_head); hal;
	     hal = haln) {
		haln = LIST_NEXT(hal, hal_entry);

		LIST_REMOVE(hal, hal_entry);
		hal_stop_expire_timer(hal);
		free(hal);
		hal = NULL;
	}

	LIST_REMOVE(hpfx, hpfx_entry);
	free(hpfx);
	hpfx = NULL;
	
	return;
}

struct mip6_hpfxl *
mip6_get_hpfxlist(prefix, prefixlen, hpfxhead) 
	struct in6_addr *prefix;
	int prefixlen;
	struct mip6_hpfx_list *hpfxhead;
{
        struct mip6_hpfxl *hpl = NULL, *hpln = NULL;

        for (hpl = LIST_FIRST(hpfxhead); hpl; hpl = hpln) {
                hpln =  LIST_NEXT(hpl, hpfx_entry);
		
		if (prefixlen != hpl->hpfx_prefixlen) 
			continue;

		if (inet_are_prefix_equal(prefix, &hpl->hpfx_prefix, prefixlen))
			return (hpl);
	}
	return (NULL);
}

void
show_hal(s, head)
	int s;
	struct mip6_hpfx_list *head;
{
        struct mip6_hpfxl *hpfx;
        struct home_agent_list *hal = NULL;

	LIST_FOREACH(hpfx, head, hpfx_entry) {
		command_printf(s, "%s/%d\n ", ip6_sprintf(&hpfx->hpfx_prefix),
			       hpfx->hpfx_prefixlen);
		command_printf(s,
				"\tpltime=%d vltime=%d\n",
				hpfx->hpfx_pltime, hpfx->hpfx_vltime);
		LIST_FOREACH(hal, &hpfx->hpfx_hal_head, hal_entry) {
			command_printf(s, "\t%s ",
				ip6_sprintf(&hal->hal_ip6addr));
			command_printf(s, "\t%s\n", 
				ip6_sprintf(&hal->hal_lladdr));
#ifdef MIP_HA
			command_printf(s,
				       "\t\tlif=%d pref=%d flag=%s %s\n",
				       hal->hal_lifetime, hal->hal_preference, 
				       (hal->hal_flag & MIP6_HAL_OWN)  ? "mine" : "",
				       (hal->hal_flag & MIP6_HAL_STATIC)  ? "static" : "");
#endif /* MIP_HA */
		}
	}
}

#if defined(MIP_MN) || defined(MIP_HA)
int
receive_ra(ra, ralen, receivedifindex, in6_lladdr, in6_gladdr)
	struct nd_router_advert *ra;
	size_t ralen;
	int receivedifindex;
	struct in6_addr *in6_lladdr, *in6_gladdr;
{
	int error;
#ifdef MIP_MN
	struct mip6_mipif *mif = NULL;
	struct mip6_hpfx_mn_exclusive mnoption;
#endif /* MIP_MN */
	struct mip6_hpfxl *hpfx = NULL;
	struct mip6_hpfx_list *hpfxhead = NULL; 
	struct nd_opt_hdr *pt;

	uint16_t       hai_preference = 0;
	uint16_t       hai_lifetime = 0;
	uint8_t        hai_pfxlen = 0;

	/* parse nd_options */ 
	memset(&ndopts, 0, sizeof(ndopts));
	error = mip6_get_nd6options(&ndopts, 
				    (char *)ra + sizeof(struct nd_router_advert), 
				    ralen - sizeof(struct nd_router_advert));
	if (error)
		return (error);

	hai_lifetime = ntohs(ra->nd_ra_router_lifetime);

	/* Processing Prefix Option */
	for (pt = (struct nd_opt_hdr *)ndopts.ndpi_start;
	     pt <= (struct nd_opt_hdr *)ndopts.ndpi_end;
	     pt = (struct nd_opt_hdr *)((caddr_t)pt +
					(pt->nd_opt_len << 3))) {
		struct nd_opt_prefix_info *pi;
			
		if (pt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
			continue;

		pi = (struct nd_opt_prefix_info *)pt;

		hai_preference = 0;
		hai_lifetime = ntohs(ra->nd_ra_router_lifetime);
		hai_pfxlen = pi->nd_opt_pi_prefix_len;
		in6_gladdr = &pi->nd_opt_pi_prefix;
#if 0
		if (hai_lifetime == 0)
			hai_lifetime = ntohl(pi->nd_opt_pi_valid_time);
#endif

		/* Find the target hpfx entry */
#if defined(MIP_HA)
		hpfxhead = &hpfx_head;
#elif defined(MIP_MN) /* MIP_MN */
		LIST_FOREACH(mif, &mipifhead, mipif_entry) {
			LIST_FOREACH(hpfx, &mif->mipif_hprefx_head, hpfx_entry) {
				if (inet_are_prefix_equal(&hpfx->hpfx_prefix,
					  in6_gladdr, hai_pfxlen)) 
					goto hpfx_find;
			}
		}
	hpfx_find:
		if (mif == NULL || hpfx == NULL)
			return (0);

		hpfxhead = &mif->mipif_hprefx_head; 
#endif /* MIP_HA */
		if (hpfxhead == NULL)
			return (0);
			
		/* check H flag */
		if (!(pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ROUTER)) {
#if defined(MIP_HA)
			/* delete HAL */
			hpfx = mip6_get_hpfxlist(&pi->nd_opt_pi_prefix, 
						 pi->nd_opt_pi_prefix_len, 
						 hpfxhead);
			if (hpfx == NULL) 
				continue;

			if (mip6_get_hal(hpfx, in6_gladdr))
				mip6_delete_hal(hpfx, &pi->nd_opt_pi_prefix);
#endif /* MIP_HA */
			continue; /* MN ignores RA which not having R flag */
		}

		/* 
		 * when the prefix field does not have a global
		 * address, the RA should be ignored 
		 */
		if (IN6_IS_ADDR_LINKLOCAL(in6_gladdr)
		    || IN6_IS_ADDR_MULTICAST(in6_gladdr)
		    || IN6_IS_ADDR_LOOPBACK(in6_gladdr)
		    || IN6_IS_ADDR_V4MAPPED(in6_gladdr)
		    || IN6_IS_ADDR_UNSPECIFIED(in6_gladdr)) 
			continue;

		/* 
		 * when the prefix field does not
		 * contain 128-bit address, it should
		 * be ignored 
		 */				
		if ((in6_gladdr->s6_addr[15] == 0) && 
		    (in6_gladdr->s6_addr[14] == 0) &&
		    (in6_gladdr->s6_addr[13] == 0) &&
		    (in6_gladdr->s6_addr[12] == 0) &&
		    (in6_gladdr->s6_addr[11] == 0) &&
		    (in6_gladdr->s6_addr[10] == 0))
			continue;

		if (debug)
			syslog(LOG_INFO, "RA received from HA (%s)\n", 
			       ip6_sprintf(&pi->nd_opt_pi_prefix));

		/* Home Agent Information Option */
		if (ndopts.ndhai) {
			hai_preference = ntohs(ndopts.ndhai->nd_opt_hai_preference);
			hai_lifetime = ntohs(ndopts.ndhai->nd_opt_hai_lifetime);
			if (debug)
				syslog(LOG_INFO, 
				       "hainfo option found in RA (pref=%d,life=%d)\n", 
				       hai_preference, hai_lifetime);
		}

		/* 
		 * if lifetime is zero, correspondent HA must be 
		 * removed from home agent list 
		 */
		if (hai_lifetime == 0 || 
		    !(ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT)) {
			hpfx = mip6_get_hpfxlist(&pi->nd_opt_pi_prefix, 
						 pi->nd_opt_pi_prefix_len, 
						 hpfxhead);
			if (hpfx == NULL) 
				continue;

			if (mip6_get_hal(hpfx, in6_gladdr) == NULL) 
				continue;
			
			mip6_delete_hal(hpfx, &pi->nd_opt_pi_prefix);
		} else {

			/* 
			 * Both linklocal and global address are added
			 * into the home prefix info 
			 */
			if (in6_gladdr == NULL)
				continue;
			
			/* Retrieve home prefix info entry for the received RA */
			hpfx = mip6_get_hpfxlist(in6_gladdr, hai_pfxlen, hpfxhead);
			if (hpfx == NULL) {
#if defined(MIP_HA)			
				continue;
#else
				/* 
				 * MN should configure a new HoA for
				 * the received prefix, however, SHISA
				 * will not support this operation 
				 */
				continue;
#endif /* MIP_HA */
			}

#ifdef MIP_HA			
			/* add or update home agent list */
			if (had_add_hal(hpfx, in6_gladdr,
				in6_lladdr, hai_lifetime, hai_preference, 0) == NULL) {
				/* error = EINVAL; */
				/* break; */
				continue;
			}
			/* Update {valid, preferred} lifetime
			   with the values received RA
			*/
			/* XXX these values are defined for MNs */
			hpfx->hpfx_vltime = ntohl(pi->nd_opt_pi_valid_time);
			hpfx->hpfx_pltime = ntohl(pi->nd_opt_pi_preferred_time);
#else
			/* Update/Create Home Prefix List */ 
			memset(&mnoption, 0, sizeof(mnoption)); 
			mnoption.hpfxlist_vltime = 
				ntohl(pi->nd_opt_pi_valid_time);
			mnoption.hpfxlist_pltime = 
				ntohl(pi->nd_opt_pi_preferred_time);

			if (mnd_add_hpfxlist(in6_gladdr,hai_pfxlen, &mnoption, mif) == NULL)
				return (EINVAL);

			/* add or update the home agent list */
			if (mnd_add_hal(hpfx, in6_gladdr, 0) == NULL)
				return (EINVAL);
#endif /* MIP_HA */
		}
	}

	return (error);
}
#endif /* MIP_MN || MIP_HA */
