/*	$KAME: config.c,v 1.37 2004/06/14 05:45:29 itojun Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */


#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/ip6_mroute.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include "defs.h"
#include "config.h"
#include "vif.h"
#include "pim6.h"
#include "inet6.h"
#include "mrt.h"
#include "rp.h"
#include "pimd.h"
#include "timer.h"
#include "route.h"
#include "debug.h"

void add_phaddr(struct uvif *v, struct sockaddr_in6 *addr,
		struct in6_addr *mask, struct sockaddr_in6 *rmt_addr);

void
config_vifs_from_kernel()
{
	register struct uvif *v;
	int i;
	struct sockaddr_in6 addr, rmt_addr, *rmt;
	struct in6_addr mask;
	short flags;
	struct ifaddrs *ifap, *ifa;

	total_interfaces= 0;	/* The total number of physical interfaces */

	if (getifaddrs(&ifap))
		log_msg(LOG_ERR, errno, "getifaddrs");

	/*
	 * Loop through all of the interfaces.
	 */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct in6_ifreq ifr6;

		/*
		 * Ignore any interface for an address family other than IPv6.
		 */
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			/* Eventually may have IPv6 address later */
			total_interfaces++;
			continue;
		}

		memcpy(&addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));

		flags = ifa->ifa_flags;

		/*
		 * Get netmask of the address.
		 */
		memcpy(&mask,
		       &((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr,
		       sizeof(mask));

		/* Get remote address only in case of P2P I/F */
		if (ifa->ifa_dstaddr != NULL && (flags & IFF_POINTOPOINT)) {
			memcpy(&rmt_addr, ifa->ifa_dstaddr, sizeof(rmt_addr));
			rmt = &rmt_addr;
		} else {
			memset(&rmt_addr, 0, sizeof(rmt_addr));
			rmt = NULL;
		}

		/*
		 * Get IPv6 specific flags, and ignore an anycast address.
		 * XXX: how about a deprecated, tentative, duplicated or
		 * detached address?
		 */
		strncpy(ifr6.ifr_name, ifa->ifa_name, sizeof(ifr6.ifr_name));
		ifr6.ifr_addr = *(struct sockaddr_in6 *)ifa->ifa_addr;
		if (ioctl(udp_socket, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
			log_msg(LOG_ERR, errno, "ioctl SIOCGIFAFLAG_IN6 for %s",
			    sa6_fmt(&ifr6.ifr_addr));
		}
		else {
			if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST) {
				log_msg(LOG_DEBUG, 0, "config_vifs_from_kernel: "
				    "%s on %s is an anycast address, ignored",
				    sa6_fmt(&ifr6.ifr_addr), ifa->ifa_name);
				continue;
			}
		}

		if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr))
		{
			addr.sin6_scope_id = if_nametoindex(ifa->ifa_name);
#ifdef __KAME__
			/*
			 * Hack for KAME kernel.
			 * Set sin6_scope_id field of a link local address and clear
			 * the index embedded in the address.
			 */
			/* clear interface index */
			addr.sin6_addr.s6_addr[2] = 0;
			addr.sin6_addr.s6_addr[3] = 0;
#endif
		}
		if (rmt && IN6_IS_ADDR_LINKLOCAL(&rmt->sin6_addr))
		{
			rmt->sin6_scope_id = if_nametoindex(ifa->ifa_name);
#ifdef __KAME__
			/*
			 * Hack for KAME kernel.
			 * Set sin6_scope_id field of a link local address and clear
			 * the index embedded in the address.
			 */
			/* clear interface index */
			rmt->sin6_addr.s6_addr[2] = 0;
			rmt->sin6_addr.s6_addr[3] = 0;
#endif
		}

		/*
		 * If the address is connected to the same subnet as one
		 * already installed in the uvifs array, just add the address
		 * to the list of addresses of the uvif.
		 */
		v = find_vif(ifa->ifa_name, DONT_CREATE, default_vif_status);
		if (v != NULL) {
			add_phaddr(v, &addr, &mask, rmt);
			goto bypass_initial_addrconf;
		}

		total_interfaces++;

		/*
		 * If there is room in the uvifs array, install this interface.
		 */
		v = find_vif(ifa->ifa_name, CREATE, default_vif_status);
		if (v == NULL) {
			log_msg(LOG_DEBUG, 0,
			    "ignored implicitly disabled interface %s",
			     ifa->ifa_name);
			continue;
		}
		v->uv_dst_addr = allpim6routers_group;
		v->uv_subnetmask = mask;
		strncpy(v->uv_name, ifa->ifa_name, IFNAMSIZ);
		v->uv_ifindex = if_nametoindex(v->uv_name);
		add_phaddr(v, &addr, &mask, rmt);
	
		/* prefix local calc. (and what about add_phaddr?...) */
		for (i = 0; i < sizeof(struct in6_addr); i++)
			v->uv_prefix.sin6_addr.s6_addr[i] =
				addr.sin6_addr.s6_addr[i] & mask.s6_addr[i];
	
	bypass_initial_addrconf:
		if (flags & IFF_POINTOPOINT)
			v->uv_flags |=(VIFF_REXMIT_PRUNES | VIFF_POINT_TO_POINT);

		/*
		 * Disable multicast routing on loopback interfaces and
		 * interfaces that do not support multicast. But they are
		 * still necessary, since global addresses maybe assigned only
		 * on such interfaces.
		 */
		if ((flags & IFF_LOOPBACK) != 0 ||
		    (flags & IFF_MULTICAST) == 0)
			v->uv_flags |= VIFF_DISABLED;

		IF_DEBUG(DEBUG_IF)
			log_msg(LOG_DEBUG,0,
			    "Installing %s (%s on subnet %s) ,"
			    "as vif #%u - rate = %d",
			    v->uv_name, sa6_fmt(&addr),
			    net6name(&v->uv_prefix.sin6_addr,&mask),
			    numvifs,v->uv_rate_limit);

		if (flags & IFF_UP) {
			v->uv_flags &= ~VIFF_DOWN;
		} else {
			v->uv_flags |= VIFF_DOWN;
			vifs_down = TRUE;
		}

	}

	freeifaddrs(ifap);
}

void
add_phaddr(struct uvif *v, struct sockaddr_in6 *addr, struct in6_addr *mask, struct sockaddr_in6 *rmt)
{
	struct phaddr *pa;
	int i;
	
	if ((pa = malloc(sizeof(*pa))) == NULL)
	        log_msg(LOG_ERR, 0, "add_phaddr: memory exhausted");


	memset(pa,0,sizeof(*pa));
	pa->pa_addr= *addr;
	pa->pa_subnetmask = *mask;
	if (rmt)
		pa->pa_rmt_addr= *rmt;

	for(i = 0; i < sizeof(struct in6_addr); i++)
		pa->pa_prefix.sin6_addr.s6_addr[i] =
			addr->sin6_addr.s6_addr[i] & mask->s6_addr[i];
	pa->pa_prefix.sin6_scope_id = addr->sin6_scope_id;


	if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
		if(v->uv_linklocal) {
			log_msg(LOG_WARNING, 0,
			    "add_phaddr: found more than one link-local "
			    "address on %s",
			    v->uv_name);
		}
		v->uv_linklocal = pa;
	}

	pa->pa_next = v->uv_addrs;
	v->uv_addrs = pa;
}
