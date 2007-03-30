/*      $KAME: mdd_rtsock.c,v 1.4 2007/03/30 09:41:15 keiichi Exp $  */
/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif 
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>

#if 0
#include <ifaddrs.h>	/* For getifaddr version */
#endif

#include "mdd.h"



static char *ifmsg = NULL;
static int ifmsglen = 0;



int
get_ifmsg()
{
	int len;
	int mib[] = {CTL_NET, AF_ROUTE, 0, AF_INET6, NET_RT_IFLIST, 0};

	if (sysctl(mib, sizeof(mib)/sizeof(int), NULL, &len, NULL, 0) < 0)
		return (-1);

	ifmsg = realloc(ifmsg, len);
	if (ifmsg == NULL) {
		ifmsglen = 0;
		return (-1);
	}
	if (sysctl(mib, sizeof(mib)/sizeof(int), ifmsg, &len, NULL, 0) < 0)
		return (-1);

	ifmsglen = len;

	return (0);
}



#define ROUNDUP(a, size)					\
    (((a) & ((size)-1)) ? (1+((a) | ((size)-1))) : (a))



int
next_sa(sa)
	struct sockaddr *sa;
{
	if (sa->sa_len) {
		return (ROUNDUP(sa->sa_len, sizeof (u_long)));
	} else {
		return (sizeof(u_long));
	}
}



void
get_rtaddrs(addrs, sa, rti_info)
	int addrs;
	struct sockaddr *sa;
	struct sockaddr *rti_info[];
{
	int i;

	for (i=0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *) ((caddr_t) sa + next_sa(sa));
		} else {
			rti_info[i] = NULL;
		}
	}
}



int
is_in_ifl(index, ifl_headp)
	int index;
	struct cifl *ifl_headp;
{
	struct cif *cifp;

	LIST_FOREACH(cifp, ifl_headp, cif_entries) {
		if (if_nametoindex(cifp->cif_name) == index)
			return (1);
	}

	return (0);
}

int
get_preference_in_ifl(index, ifl_headp)
	int index;
	struct cifl *ifl_headp;
{
	struct cif *cifp;

	LIST_FOREACH(cifp, ifl_headp, cif_entries) {
		if (if_nametoindex(cifp->cif_name) == index)
			return (cifp->preference);
	}

	return (0);
}


int
get_addr_with_ifl(coacl_headp, ifl_headp)
	struct coacl *coacl_headp;
	struct cifl *ifl_headp;
{
	char *next, *limit;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr *rti_info[RTAX_MAX];
	struct coac *cp;
	struct in6_ifreq ifr6;
	struct sockaddr_in6 *sin6;
	int flags6;

	if (get_ifmsg() < 0)
		return (-1);
	
	limit = ifmsg + ifmsglen;
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;
		if (!is_in_ifl(ifm->ifm_index, ifl_headp))
			continue;
		if (ifm->ifm_type == RTM_NEWADDR) {
			ifam = (struct ifa_msghdr *)next;
			get_rtaddrs(ifam->ifam_addrs,
			    (struct sockaddr *)(ifam + 1), rti_info);

			sin6 = (struct sockaddr_in6 *)rti_info[RTAX_IFA];
			memset(&ifr6, 0, sizeof(ifr6));
			ifr6.ifr_addr = *sin6;
			if (if_indextoname(ifm->ifm_index, ifr6.ifr_name)
			    == NULL) {
				continue;
			}
			if (ioctl(sock_dg6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
				perror("ioctl(SIOCGIFAFLAG_IN6)");
				continue;
			}
			flags6 = ifr6.ifr_ifru.ifru_flags6;

			/* an address which is not ready cannot be a CoA. */
			if (flags6 & IN6_IFF_NOTREADY)
				continue;

			/* a detached addresses cannot be a CoA. */
			if (flags6 & IN6_IFF_DETACHED)
				continue;

#if 0
			/*
			 * XXX need more consideration:
			 * a home address cannot be a CoA.
			 */
			if (flags6 & IN6_IFF_HOME)
				continue;
#endif

			cp = malloc(sizeof(struct coac));
			memcpy(&cp->coa, sin6, sizeof(cp->coa));
			cp->preference = get_preference_in_ifl(ifm->ifm_index,
								ifl_headp);
			LIST_INSERT_HEAD(coacl_headp, cp, coac_entries);
		}
	}
	return (0);
}



int
in6_addrscope(addr)
	struct in6_addr *addr;
{
	int scope;

	if (addr->s6_addr[0] == 0xfe) {
		scope = addr->s6_addr[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return (__IPV6_ADDR_SCOPE_LINKLOCAL);
			break;
		case 0xc0:
			return (__IPV6_ADDR_SCOPE_SITELOCAL);
			break;
		default:
			return (__IPV6_ADDR_SCOPE_GLOBAL); /* just in case */
			break;
		}
	}


	if (addr->s6_addr[0] == 0xff) {
		scope = addr->s6_addr[1] & 0x0f;

		/*
		 * due to other scope such as reserved,
		 * return scope doesn't work.
		 */
		switch (scope) {
		case __IPV6_ADDR_SCOPE_INTFACELOCAL:
			return (__IPV6_ADDR_SCOPE_INTFACELOCAL);
			break;
		case __IPV6_ADDR_SCOPE_LINKLOCAL:
			return (__IPV6_ADDR_SCOPE_LINKLOCAL);
			break;
                case __IPV6_ADDR_SCOPE_SITELOCAL:
			return (__IPV6_ADDR_SCOPE_SITELOCAL);
			break;
		default:
			return (__IPV6_ADDR_SCOPE_GLOBAL);
			break;
		}
	}

	/*
	 * Regard loopback and unspecified addresses as global, since
	 * they have no ambiguity.
	 */
	if (bcmp(&in6addr_loopback, addr, sizeof(*addr) - 1) == 0) {
		if (addr->s6_addr[15] == 1) /* loopback */
			return (__IPV6_ADDR_SCOPE_LINKLOCAL);
		if (addr->s6_addr[15] == 0) /* unspecified */
			return (__IPV6_ADDR_SCOPE_GLOBAL); /* XXX: correct? */
	}

	return (__IPV6_ADDR_SCOPE_GLOBAL);
}


int
get_ifl(ifl_headp)
	struct cifl *ifl_headp;
{
	struct cif *cifp;
#if 1
	char *next, *limit, *ifname;
	struct if_msghdr *ifm;

	if (get_ifmsg() < 0)
		return (-1);

	limit = ifmsg + ifmsglen;
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;
		if (is_in_ifl(ifm->ifm_index, ifl_headp))
			continue;

		ifname = (char *)malloc(IFNAMSIZ);
		if (ifname == NULL)
			continue;

		if (if_indextoname(ifm->ifm_index, ifname) == NULL) {
			free(ifname);
			continue;
		}

		cifp = (struct cif *)malloc(sizeof(*cifp));
		if (cifp == NULL) {
			free(ifname);
			continue;
		}
		cifp->cif_name = ifname;
		LIST_INSERT_HEAD(ifl_headp, cifp, cif_entries);
	}
#else
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) != 0)
		return (-1);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		cifp = (struct cif *)malloc(sizeof(*cifp) + strlen(ifa->ifa_name) + 1);
		if (cifp == NULL) {
			continue;
		}
		cifp->cif_name = (char *)(cifp + 1);
		strncpy(cifp->cif_name, ifa->ifa_name, strlen(ifa->ifa_name));
		LIST_INSERT_HEAD(ifl_headp, cifp, cif_entries);
	}
	freeifaddrs(ifap);
#endif

	return (0);
}



int
del_if_from_ifl(ifl_headp, type)
	struct cifl *ifl_headp;
	int type;
{
	char *next, *limit;
	struct if_msghdr *ifm;
	struct cif *cifp;
	struct sockaddr_dl *sdl;

	if (get_ifmsg() < 0)
		return (-1);

	limit = ifmsg + ifmsglen;
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;

		if (ifm->ifm_type != RTM_IFINFO)
			continue;

		sdl = (struct sockaddr_dl *)(ifm + 1);

		if (sdl->sdl_type == type) {
		retry:
	        	LIST_FOREACH(cifp, ifl_headp, cif_entries) {
				if (if_nametoindex(cifp->cif_name)
				    != ifm->ifm_index)
					continue;

				LIST_REMOVE(cifp, cif_entries);
				free(cifp);
				goto retry;
			}
		}
	}

	return (0);
}



int
in6_mask2prefixlen(a)
	struct in6_addr *a;
{
	int bytes = sizeof(struct in6_addr)/sizeof(u_int8_t);
	u_int8_t mask;
	int i, j;

	for (i = 0; i < bytes; i++) {
		mask = 0;
		for (j = 0; j < 8; j++) {
			mask = 0x80 >> j;
			if ((mask & a->s6_addr[i]) == 0)
				return (8 * i + j);
		}
	}
	return (8 * i);
}



int
_get_hoalist()
{
	char *next, *limit;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_in6 *sin6, *sin6mask;
	struct sockaddr *rti_info[RTAX_MAX];
	struct in6_ifreq ifr6;
	int flags6;
#if 0
	int i, prefixlen;
	struct sockaddr_dl *sdl;
	int index[10], indexp=0;
#endif

	if (get_ifmsg() < 0)
		return (-1);
	
	limit = ifmsg + ifmsglen;
#if 0
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;

		if (ifm->ifm_type != RTM_IFINFO)
			continue;

		sdl = (struct sockaddr_dl *)(ifm + 1);

		if (sdl->sdl_type == IFT_MOBILEIP) {
			index[indexp++] = ifm->ifm_index;
			if (indexp >= 10)
				break;
		}
	}
#endif

	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;
		if (ifm->ifm_type != RTM_NEWADDR)
			continue;

#if 0
		for (i = 0; i < indexp; i++) {
			if (ifm->ifm_index == index[i])
				break;
		}
		if (i == indexp)
			continue;
#endif

		ifam = (struct ifa_msghdr *)next;
		get_rtaddrs(ifam->ifam_addrs,
		    (struct sockaddr *)(ifam + 1), rti_info);
		sin6 = (struct sockaddr_in6 *)rti_info[RTAX_IFA];
		sin6mask = (struct sockaddr_in6 *)rti_info[RTAX_NETMASK];

		memset(&ifr6, 0, sizeof(ifr6));
		ifr6.ifr_addr = *sin6;
		if (if_indextoname(ifm->ifm_index, ifr6.ifr_name) == NULL)
			continue;
		if (ioctl(sock_dg6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
			perror("ioctl(SIOCGIFAFLAG_IN6)");
			continue;
		}
		flags6 = ifr6.ifr_ifru.ifru_flags6;

		if (in6_addrscope(&sin6->sin6_addr)
		    != __IPV6_ADDR_SCOPE_GLOBAL)
			continue;
		if ((flags6 & IN6_IFF_HOME) == 0)
			continue;

		set_hoa(&sin6->sin6_addr,
		    in6_mask2prefixlen(&sin6mask->sin6_addr));
	}

	return (0);
}


int
in6_addr2ifindex(ia6)
	struct in6_addr *ia6;
{
	char *next, *limit;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_in6 *sin6;
	struct sockaddr *rti_info[RTAX_MAX];

	if (get_ifmsg() < 0)
		return (-1);

	limit = ifmsg + ifmsglen;
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;
		if (ifm->ifm_type != RTM_NEWADDR)
			continue;

		ifam = (struct ifa_msghdr *)next;
		get_rtaddrs(ifam->ifam_addrs,
		    (struct sockaddr *) (ifam + 1), rti_info);
		sin6 = (struct sockaddr_in6 *)rti_info[RTAX_IFA];

		if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, ia6))
			return (ifm->ifm_index);
	}

	return (-1);
}


int
in6_is_one_of_hoa(ifam, bl_headp)
	struct ifa_msghdr *ifam;
	struct bl *bl_headp;
{
	struct sockaddr_in6 *sin6;
	struct binding *bp;
	struct sockaddr *rti_info[RTAX_MAX];
		
	get_rtaddrs(ifam->ifam_addrs,
	    (struct sockaddr *)(ifam + 1), rti_info);
	sin6 = (struct sockaddr_in6 *)rti_info[RTAX_IFA];

	if (sin6 == NULL)
		return (0);

	LIST_FOREACH(bp, bl_headp, binding_entries) {
		if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &bp->hoa.sin6_addr))
			return (1);
	}

	return (0);
}



int
in6_is_on_homenetwork(ifam, bl_headp)
	struct ifa_msghdr *ifam;
	struct bl *bl_headp;
{
	struct sockaddr_in6 *sin6;
	struct binding *bp;
	struct sockaddr *rti_info[RTAX_MAX];
	int len;
	char ifname[IFNAMSIZ];


	if (if_indextoname(ifam->ifam_index, ifname) == NULL)
		return (0);
	if (strncmp(ifname, "mip", 3) == 0) {
		fprintf(stdout, "this address is assigned to mip virtual interface\n");
		return (0);	
	}

	get_rtaddrs(ifam->ifam_addrs,
	    (struct sockaddr *)(ifam + 1), rti_info);
	sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];
	if (sin6 == NULL)
		return (0);

	LIST_FOREACH(bp, bl_headp, binding_entries) {
		len = in6_matchlen(&sin6->sin6_addr, &bp->hoa.sin6_addr);
		if (len >= bp->hoa_prefixlen)
			return (1);
	}

	return (0);
}

