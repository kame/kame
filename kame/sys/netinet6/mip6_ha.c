/*	$KAME: mip6_ha.c,v 1.16 2001/03/29 05:34:32 itojun Exp $	*/

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
 * Author: Conny Larsson <Conny.Larsson@era.ericsson.se>
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
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/ioccom.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>
#include <machine/limits.h>

#include <net/net_osdep.h>


/*
 ##############################################################################
 #
 # INITIALIZATION AND EXIT FUNCTIONS
 # These functions are executed when the home agent specific MIPv6 code is
 # activated and deactivated respectively.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_ha_init
 * Description: Initialization of MIPv6 variables that must be initialized
 *              before the HA code is executed.
 ******************************************************************************
 */
void
mip6_ha_init(void)
{
	printf("Home Agent initialized\n");
}



/*
 ******************************************************************************
 * Function:    mip6_ha_exit
 * Description: This function is called when the HA module is unloaded
 *              (relesed) from the kernel.
 ******************************************************************************
 */
void
mip6_ha_exit()
{
	printf("Home Agent de-activated\n");
}



/*
 ##############################################################################
 #
 # FUNCTIONS FOR PROCESSING OF INBOUND MIPV6 OPTIONS
 # Below are functions used for processing of received MIPv6 options (BU, BA
 # and BR) and its sub-options. These options are received by the dest6_input()
 # function, which calls the mip6_dstopt() function. The mip6_dstopt() function
 # is a dispatcher function.
 # As a result of processing an option other functions will be called which
 # eventually results in either a response or an action. The functions for
 # sending responses are also defined under this section.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_accept_bu
 * Description: These checks are performed by the home agent when a Binding
 *              Update is received as part of accepting a request from a node
 *              to serve as its home agent (see 9.3).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 *              -2  Silently ignore. Process rest of packet.
 ******************************************************************************
 */
int
mip6_accept_bu(m, opt)
struct mbuf     *m;    /* Ptr to beginning of mbuf */
u_int8_t        *opt;  /* Ptr to BU option in DH */
{
	struct ip6_opt_binding_update  *bu_opt;
	struct ip6aux                  *ip6a = NULL;
	struct mbuf                    *n;
	int                             res;

	bu_opt = (struct ip6_opt_binding_update *)opt;
	if (!(bu_opt->ip6ou_flags & IP6_BUF_HOME)) {
		log(LOG_ERR,
		    "%s: H-flag must be set in BU to perform this function\n",
		    __FUNCTION__);
		return -2;
	}

	n = ip6_findaux(m);
	if (!n) return -1;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return -1;
	
	/* Is the node is a router implementing HA functionality? */
	if (!(ip6_forwarding && MIP6_IS_HA_ACTIVE)) {
		res = MIP6_BA_STATUS_HOMEREGNOSUP;
		mip6_build_send_ba(m, opt, NULL, NULL, res);
		return -2;
	}

	/* Verify that the home address is an on-link IPv6 address and
	   that the prefix length is correct. */
	res = mip6_is_addr_onlink(&ip6a->ip6a_home, bu_opt->ip6ou_prefixlen);
	if (res != 0) {
		mip6_build_send_ba(m, opt, NULL, NULL, res);
		return -2;
	}

	/* Must the home agent perform duplicate address detection? */
	if (bu_opt->ip6ou_flags & IP6_BUF_DAD) {
		/* 1. Save *m, ip6aux, opt + suboption, coa
		   2. Call in6_update_ifa  (this function calls start_dad) */
		return 0;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_is_addr_onlink
 * Description: Check if an address is an on-link IPv6 address with respect to
 *              the home agent's current prefix list (see 9.3).
 *              Check, if the prefix length for the address is non-zero, that
 *              the address length is of the same length as the correspondent
 *              prefix length (see 9.3).
 * Ret value:   0   = OK
 *              133 = Not home subnet
 *              136 = Incorrect interface identifier length
 ******************************************************************************
 */
int
mip6_is_addr_onlink(addr, prefixlen)
struct in6_addr *addr;       /* IPv6 address to check */
u_int8_t         prefixlen;  /* Prefix length for the address */
{
	struct mip6_prefix  *pr;

	for (pr = mip6_prq; pr; pr = pr->next) {
		if (in6_are_prefix_equal(addr, &pr->prefix, pr->prefixlen)) {
			if (prefixlen == 0) return 0;
			if (pr->prefixlen == prefixlen)
				return 0;
			else
				return MIP6_BA_STATUS_IFLEN;
		}
	}
	return MIP6_BA_STATUS_SUBNET;
}



/*
 ******************************************************************************
 * Function:    mip6_min_lifetime
 * Description: Decide the remaining valid lifetime for a home address. If the
 *              prefix length is zero the lifetime is the lifetime of the
 *              prefix list entry for this prefix.
 *              If the prefix length is non-zero the lifetime is the minimum
 *              remaining valid lifetime for all subnet prefixes on the mobile
 *              node's home link.
 * Ret value:   Lifetime
 ******************************************************************************
 */
u_int32_t
mip6_min_lifetime(addr, prefixlen)
struct in6_addr *addr;       /* IPv6 address to check */
u_int8_t         prefixlen;  /* Prefix length for the address */
{
	struct mip6_prefix  *pr;        /* Ptr to entries in the prexix list */
	u_int32_t            min_time;  /* Minimum life time */

	min_time = 0xffffffff;

	for (pr = mip6_prq; pr; pr = pr->next) {
		/* Different handling depending on the prefix length. */
		if (prefixlen == 0) {
			if (in6_are_prefix_equal(addr, &pr->prefix,
						 pr->prefixlen)) {
				return pr->validtime;
			}
		} else
			min_time = min(min_time, pr->validtime);
	}
	return min_time;
}



/*
 ******************************************************************************
 * Function:    mip6_proxy_update
 * Description: Update (add or remove) address in the routing table for which
 *              the home agent is going to act as proxy for.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_proxy_update(addr, local, cmd)
struct in6_addr  *addr;   /* Address to be proxy for */
struct in6_addr  *local;  /* Use this address when acting as proxy */
int               cmd;    /* RTM_{ADD,DELETE} */
{
	struct sockaddr_in6   mask; /* = {sizeof(mask), AF_INET6 } */
	struct sockaddr_in6   sa6;
	struct sockaddr_dl   *sdl;
        struct rtentry       *rt, *nrt;
	struct ifaddr        *ifa;
	struct ifnet         *ifp;
	int                   flags, error;

	if (cmd == RTM_DELETE) {
		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_len = sizeof(sa6);
		sa6.sin6_addr = *addr;

#ifdef __FreeBSD__
		rt = rtalloc1((struct sockaddr *)&sa6, 1, 0UL);
#else
		rt = rtalloc1((struct sockaddr *)&sa6, 1);
#endif
		if (rt == NULL)
			return EHOSTUNREACH;

		error = rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
				  rt_mask(rt), 0, (struct rtentry **)0);
		rt->rt_refcnt--;
		rt = NULL;
#ifdef MIP6_DEBUG
		if (error)
			mip6_debug("%s: RTM_DELETE for %s returned " 
				   "error = %d\n", __FUNCTION__, 
				   ip6_sprintf(addr), error);
#endif
		return error;
	}

	/*
	 * Case RTM_ADD
	 */

	bzero(&sa6, sizeof sa6);		
	sa6.sin6_len = sizeof(struct sockaddr_in6);
	sa6.sin6_family = AF_INET6;
	sa6.sin6_addr = *addr;

	rt = rtalloc1((struct sockaddr *)&sa6, 0
#ifdef __FreeBSD__
		      , 0
#endif /* __FreeBSD__ */
		);
	if (rt && (rt->rt_flags & RTF_ANNOUNCE) != 0 &&
	    rt->rt_gateway->sa_family == AF_LINK) {
		/*
		 * proxy NDP for single entry
		 */
#ifdef MIP6_DEBUG
		mip6_debug("%s RTM_ADD: we are already proxy for %s\n",
			   __FUNCTION__, ip6_sprintf(addr));
#endif
		return EEXIST;
	}
#if 0
		/* REMOVE THIS */
		ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(ifp,
				IN6_IFF_NOTREADY|IN6_IFF_ANYCAST);
		if (ifa) {
			proxy = 1;
			proxydl = SDL(rt->rt_gateway);
		}
	}
	if (rt)
		rtfree(rt);

	if (!ifa) {
		/* We are not proxy for this address */
	}
#endif /* 0 */

	/* Create sa6 */
	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_addr = *local;

	ifa = ifa_ifwithaddr((struct sockaddr *)&sa6);
	if (ifa == NULL)
		return EINVAL;
	sa6.sin6_addr = *addr;

	/* Create sdl */
	ifp = ifa->ifa_ifp;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
        for (ifa = ifp->if_addrlist.tqh_first; ifa;
	     ifa = ifa->ifa_list.tqe_next)
#endif
                if (ifa->ifa_addr->sa_family == AF_LINK) break;

	if (!ifa)
		return EINVAL;

	MALLOC(sdl, struct sockaddr_dl *, ifa->ifa_addr->sa_len,
	       M_IFMADDR, M_WAITOK);
	bcopy((struct sockaddr_dl *)ifa->ifa_addr, sdl, ifa->ifa_addr->sa_len);

	/* Create mask */
	bzero(&mask, sizeof(mask));
	mask.sin6_family = AF_INET6;
	mask.sin6_len = sizeof(mask);

	in6_len2mask(&mask.sin6_addr, 128);
	flags = (RTF_STATIC | RTF_ANNOUNCE | RTA_NETMASK);

	error = rtrequest(RTM_ADD, (struct sockaddr *)&sa6,
			  (struct sockaddr *)sdl,
			  (struct sockaddr *)&mask, flags, &nrt);

#ifdef MIP6_DEBUG
	if (error)
		mip6_debug("%s: RTM_ADD for %s returned error = %d\n",
			   __FUNCTION__, ip6_sprintf(addr), error);
#endif
	if (error == 0) {
		/* Avoid expiration */
		if (nrt) {
			nrt->rt_rmx.rmx_expire = 0;
			nrt->rt_genmask = NULL;
			nrt->rt_refcnt--;
		} else
			error = EINVAL;
	}

	free(sdl, M_IFMADDR);
	return error;
}



/*
 ******************************************************************************
 * Function:    mip6_proxy_control
 * Description: While a node is serving as home agent for the mobile node it
 *              must act as proxy for the mobile node and intercept any packet
 *              on the home link addressed to the mobile nodes home address,
 *              including addresses formed from other on-link prefixes, if the
 *              prefix length field was non-zero in the BU.
 *              This function adds or removes addresses in the routing table
 *              for which the home agent act as proxy for. 
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_proxy_control(bcp, cmd)
struct mip6_bc  *bcp;      /* BC entry used for proxy generation */
int              cmd;      /* RTM_{ADD, DELETE} */
{
	struct mip6_prefix  *prr;
	struct in6_addr     *laddr, *naddr, *prefix;
	u_int8_t             plen;
	int                  proxy_for_ll_addr;

	if (!MIP6_IS_HA_ACTIVE) return;

	/* Proxy only for the home address? */
	if (bcp->prefixlen == 0) {
		if (mip6_proxy_update(&bcp->peer_home, &bcp->local_home, cmd)){
			log(LOG_INFO,
			    "%s: Proxy for mobile node %s failed\n",
			    __FUNCTION__, ip6_sprintf(&bcp->peer_home));
			return;
		}
		return;
	}

	/* Home agent acting as proxy for mobile node (see 9.5) */
	proxy_for_ll_addr = 0;
	for (prr = mip6_prq; prr; prr = prr->next) {
		prefix = &prr->prefix;
		plen = prr->prefixlen;

		/* The prefix length must be equal */
		if (plen != bcp->prefixlen) continue;

		/* Build home address to be proxy for */
		naddr = mip6_in6addr(prefix, &bcp->peer_home, plen);
		if (naddr == NULL) continue;

		/* Add MN home address to routing table to be proxy for */
		mip6_proxy_update(naddr, &bcp->local_home, cmd);
		
		/* Proxy for link-local address if prefix len == 64 */
		if ((plen == 64) && !proxy_for_ll_addr) {
			laddr = mip6_in6addr(&in6addr_linklocal,
					     &bcp->peer_home, plen);
			if (laddr == NULL) {
				free(laddr, M_TEMP);
				continue;
			}
			
			mip6_proxy_update(laddr, &bcp->local_home, cmd);
			proxy_for_ll_addr = 1;
			free(laddr, M_TEMP);
		}
		free(naddr, M_TEMP);
	}
}



/*
 ##############################################################################
 #
 # IP6 OUTPUT FUNCTIONS
 # Functions used for processing of the outgoing IPv6 packet. These functions
 # are called by using the mip6_output() function, when necesary, from the
 # ip6_output() function.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_icmp6_output
 * Description: Takes care of an outgoing Router Advertisement. If the node
 *              is a home agent it will create/update a home agent list entry
 *              and a prefix list entry.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_icmp6_output(m)
struct mbuf *m;     /* Mbuf chain with IPv6 packet */
{
	struct ip6_hdr           *ip6;        /* IPv6 header */
	struct icmp6_hdr         *icmp6;      /* ICMP6 header */
	struct nd_router_advert  *ra = NULL;  /* Router Advertisement */
	struct ifnet             *ifp = NULL; /* Outgoing interface */
	struct ifaddr            *if_addr;    /* Interface address */
	struct sockaddr_in6       sin6;
	caddr_t                   icmp6buf;   /* Copy of mbuf (consequtive) */
	int                       icmp6len;

	if (!MIP6_IS_HA_ACTIVE) return;

	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6) return;

	if (!IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) return;

	/* The mbuf data must be stored consequtively to be able to
	   cast data from it. */
	icmp6len = m->m_pkthdr.len - sizeof(struct ip6_hdr);
	icmp6buf = (caddr_t)malloc(icmp6len, M_TEMP, M_NOWAIT);
	if (icmp6buf == NULL) return;

	m_copydata(m, sizeof(struct ip6_hdr), icmp6len, icmp6buf);
	icmp6 = (struct icmp6_hdr *)icmp6buf;

	/* Check if the packet shall be processed */
	if (icmp6->icmp6_type != ND_ROUTER_ADVERT) {
		free(icmp6buf, M_TEMP);
		return;
	}

	if (icmp6->icmp6_code != 0) {
		free(icmp6buf, M_TEMP);
		return;
	}

	if (icmp6len < sizeof(struct nd_router_advert)) {
		free(icmp6buf, M_TEMP);
		return;
	}

	/* Find the outgoing interface */
	bzero(&sin6, sizeof(struct sockaddr_in6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = ip6->ip6_src;

	if_addr = ifa_ifwithaddr((struct sockaddr *)&sin6);
	if (if_addr == NULL) {
		free(icmp6buf, M_TEMP);
		return;
	}
	ifp = if_addr->ifa_ifp;

	/* Look through the RA options and do appropriate updates */
	ra = (struct nd_router_advert *)icmp6;
	if (mip6_icmp6_ra_options(ifp, &ip6->ip6_src, ra, icmp6len)) {
		free(icmp6buf, M_TEMP);
		return;
	}
	free(icmp6buf, M_TEMP);
	return;
}



/*
 ##############################################################################
 #
 # IOCTL FUNCTIONS
 # These functions are called from mip6_ioctl.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_write_config_data_ha
 * Description: This function is called to write certain config values for
 *              MIPv6. The data is written into the global config structure.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_write_config_data_ha(u_long cmd, void *arg)
{
	int    retval = 0;

	switch (cmd) {
		case SIOCSHAPREF_MIP6:
			mip6_config.ha_pref =
				((struct mip6_input_data *)arg)->value;
			break;
	}
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_config_data_ha
 * Description: This function is called to clear internal lists handled by
 *              MIPv6.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_clear_config_data_ha(u_long cmd, void *data)
{
	int retval = 0;
	int s;

	s = splnet();
	switch (cmd) {
		case SIOCSHALISTFLUSH_MIP6:
			break;
	}
	splx(s);
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_enable_func_ha
 * Description: This function is called to enable or disable certain functions
 *              in mip6. The data is written into the global config struct.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_enable_func_ha(u_long cmd, caddr_t data)
{
	int enable;
	int retval = 0;
    
	enable = ((struct mip6_input_data *)data)->value;

	switch (cmd) {
		case SIOCSFWDSLUNICAST_MIP6:
			mip6_config.fwd_sl_unicast = enable;
			break;

		case SIOCSFWDSLMULTICAST_MIP6:
			mip6_config.fwd_sl_multicast = enable;
			break;
	}
	return retval;
}
