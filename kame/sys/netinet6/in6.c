/*	$KAME: in6.c,v 1.150 2001/01/23 15:41:49 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/ioctl.h>
#endif
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
#include <sys/proc.h>
#endif
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#else
#include <netinet/if_ether.h>
#endif
#ifndef SCOPEDROUTING
#if defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#endif
#endif

#include <netinet6/nd6.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/mld6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/scope6_var.h>
#ifndef SCOPEDROUTING
#if defined(__NetBSD__) || (defined(__bsdi__) && _BSDI_VERSION < 199802) || defined(__FreeBSD__)
#include <netinet6/in6_pcb.h>
#endif
#endif

#include "gif.h"
#if NGIF > 0
#include <net/if_gif.h>
#endif

#ifdef MIP6
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

struct nd_prefix *(*mip6_get_home_prefix_hook) __P((void));
#endif /* MIP6 */

#include <net/net_osdep.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
MALLOC_DEFINE(M_IPMADDR, "in6_multi", "internet multicast address");
#endif

/*
 * Definitions of some costant IP6 addresses.
 */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
const struct in6_addr in6addr_nodelocal_allnodes =
	IN6ADDR_NODELOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allnodes =
	IN6ADDR_LINKLOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allrouters =
	IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;

const struct in6_addr in6mask0 = IN6MASK0;
const struct in6_addr in6mask32 = IN6MASK32;
const struct in6_addr in6mask64 = IN6MASK64;
const struct in6_addr in6mask96 = IN6MASK96;
const struct in6_addr in6mask128 = IN6MASK128;

const struct sockaddr_in6 sa6_any = {sizeof(sa6_any), AF_INET6,
				     0, 0, IN6ADDR_ANY_INIT, 0};

#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
static int in6_lifaddr_ioctl __P((struct socket *, u_long, caddr_t,
	struct ifnet *, struct proc *));
#else
static int in6_lifaddr_ioctl __P((struct socket *, u_long, caddr_t,
	struct ifnet *));
#endif
static int in6_ifaddroute __P((struct ifnet *, struct in6_ifaddr *, int));
static void in6_unlink_ifa __P((struct in6_ifaddr *, struct ifnet *));

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
struct in6_multihead in6_multihead;	/* XXX BSS initialization */
#else
/*
 * This structure is used to keep track of in6_multi chains which belong to
 * deleted interface addresses.
 */
static LIST_HEAD(, multi6_kludge) in6_mk; /* XXX BSS initialization */

struct multi6_kludge {
	LIST_ENTRY(multi6_kludge) mk_entry;
	struct ifnet *mk_ifp;
	struct in6_multihead mk_head;
};
#endif

#ifdef MEASURE_PERFORMANCE
static void in6h_delifa __P((struct in6_ifaddr *));
static void in6h_addhash __P((struct in6hash *));
static void in6h_delhash __P((struct in6hash *));
#endif

/*
 * Check if the loopback entry will be automatically generated.
 *   if 0 returned, will not be automatically generated.
 *   if 1 returned, will be automatically generated.
 */
static int
in6_is_ifloop_auto(struct ifaddr *ifa)
{
#define SIN6(s) ((struct sockaddr_in6 *)s)
	/*
	 * If RTF_CLONING is unset, or (IFF_LOOPBACK | IFF_POINTOPOINT),
	 * or netmask is all0 or all1, then cloning will not happen,
	 * then we can't rely on its loopback entry generation.
	 */
	if ((ifa->ifa_flags & RTF_CLONING) == 0 ||
	    (ifa->ifa_ifp->if_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) ||
	    (SIN6(ifa->ifa_netmask)->sin6_len == sizeof(struct sockaddr_in6)
	     &&
	     IN6_ARE_ADDR_EQUAL(&SIN6(ifa->ifa_netmask)->sin6_addr,
				&in6mask128)) ||
	    ((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_len == 0)
		return 0;
	else
		return 1;
#undef SIN6
}

/*
 * Subroutine for in6_ifaddloop() and in6_ifremloop().
 * This routine does actual work.
 */
static void
in6_ifloop_request(int cmd, struct ifaddr *ifa)
{
	struct sockaddr_in6 lo_sa;
	struct sockaddr_in6 all1_sa;
	struct rtentry *nrt = NULL, **nrtp = NULL;
	int e;
	
	bzero(&lo_sa, sizeof(lo_sa));
	bzero(&all1_sa, sizeof(all1_sa));
	lo_sa.sin6_family = AF_INET6;
	lo_sa.sin6_len = sizeof(struct sockaddr_in6);
	all1_sa = lo_sa;
	lo_sa.sin6_addr = in6addr_loopback;
	all1_sa.sin6_addr = in6mask128;
	
	/*
	 * So we add or remove static loopback entry, here.
	 * This request for deletion could fail, e.g. when we remove
	 * an address right after adding it.
	 */
	if (cmd == RTM_ADD)
		nrtp = &nrt;
	e = rtrequest(cmd, ifa->ifa_addr,
		      (struct sockaddr *)&lo_sa,
		      (struct sockaddr *)&all1_sa,
		      RTF_UP|RTF_HOST, nrtp);
	if (e != 0) {
		log(LOG_ERR, "in6_ifloop_request: "
		    "%s operation failed for %s (errno=%d)\n",
		    cmd == RTM_ADD ? "ADD" : "DELETE",
		    ip6_sprintf(&((struct in6_ifaddr *)ifa)->ia_addr.sin6_addr),
		    e);
	}

	/*
	 * Make sure rt_ifa be equal to IFA, the second argument of the
	 * function.
	 * We need this because when we refer rt_ifa->ia6_flags in ip6_input,
	 * we assume that the rt_ifa points to the address instead of the
	 * loopback address.
	 */
	if (cmd == RTM_ADD && nrt && ifa != nrt->rt_ifa) {
		IFAFREE(nrt->rt_ifa);
		IFAREF(ifa);
		nrt->rt_ifa = ifa;
	}
	if (nrt)
		nrt->rt_refcnt--;
}

/*
 * Add ownaddr as loopback rtentry, if necessary(ex. on p2p link).
 * Because, KAME needs loopback rtentry for ownaddr check in
 * ip6_input().
 */
static void
in6_ifaddloop(struct ifaddr *ifa)
{
	if (!in6_is_ifloop_auto(ifa)) {
		struct rtentry *rt;

		/* If there is no loopback entry, allocate one. */
		rt = rtalloc1(ifa->ifa_addr, 0
#ifdef __FreeBSD__
			      , 0
#endif /* __FreeBSD__ */
			      );
		if (rt == NULL || (rt->rt_flags & RTF_HOST) == 0 ||
		    (rt->rt_ifp->if_flags & IFF_LOOPBACK) == 0)
			in6_ifloop_request(RTM_ADD, ifa);
		if (rt)
			rt->rt_refcnt--;
	}
}

/*
 * Remove loopback rtentry of ownaddr generated by in6_ifaddloop(),
 * if it exists.
 */
static void
in6_ifremloop(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia;
	struct rtentry *rt;
	int ia_count = 0;

	/*
	 * All BSD variants except BSD/OS do not remove cloned routes
	 * from an interface direct route, when removing the direct route
	 * (see comments in net/net_osdep.h). Even BSD/OS could fail to remove
	 * the cloned routes when we handle multple addresses that share a
	 * common prefix.
	 * So, we should remove the route corresponding to the deleted address
	 * regardless of the result of in6_is_ifloop_auto().
	 */

	/*
	 * Delete the entry only if exact one ifa exists. More than one ifa
	 * can exist if we assign a same single address to multiple
	 * (probably p2p) interfaces.
	 * XXX: we should avoid such a configuration in IPv6...
	 */
	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (IN6_ARE_ADDR_EQUAL(IFA_IN6(ifa), &ia->ia_addr.sin6_addr)) {
			ia_count++;
			if (ia_count > 1)
				break;
		}
	}

	if (ia_count == 1) {
		/*
		 * Before deleting, check if a corresponding loopbacked host
		 * route surely exists. With this check, we can avoid to
		 * delete an interface direct route whose destination is same
		 * as the address being removed. This can happen when remofing
		 * a subnet-router anycast address on an interface attahced
		 * to a shared medium.
		 */
		rt = rtalloc1(ifa->ifa_addr, 0
#ifdef __FreeBSD__
			      , 0
#endif /* __FreeBSD__ */
			);
		if (rt != NULL && (rt->rt_flags & RTF_HOST) != 0 &&
		    (rt->rt_ifp->if_flags & IFF_LOOPBACK) != 0) {
			rt->rt_refcnt--;
			in6_ifloop_request(RTM_DELETE, ifa);
		}
	}
}

int
in6_ifindex2scopeid(idx)
	int idx;
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct sockaddr_in6 *sin6;

	if (idx < 0 || if_index < idx)
		return -1;
	ifp = ifindex2ifnet[idx];

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr))
			return sin6->sin6_scope_id & 0xffff;
	}

	return -1;
}

int
in6_mask2len(mask, lim0)
	struct in6_addr *mask;
	u_char *lim0;
{
	int x = 0, y;
	u_char *lim = lim0, *p;

	if (lim0 == NULL ||
	    lim0 - (u_char *)mask > sizeof(*mask)) /* ignore the scope_id part */
		lim = (u_char *)mask + sizeof(*mask);
	for (p = (u_char *)mask; p < lim; x++, p++) {
		if (*p != 0xff)
			break;
	}
	y = 0;
	if (p < lim) {
		for (y = 0; y < 8; y++) {
			if ((*p & (0x80 >> y)) == 0)
				break;
		}
	}

	/*
	 * when the limit pointer is given, do a stricter check on the
	 * remaining bits.
	 */
	if (p < lim) {
		if (y != 0 && (*p & (0x00ff >> y)) != 0)
			return(-1);
		for (p = p + 1; p < lim; p++)
			if (*p != 0)
				return(-1);
	}
	
	return x * 8 + y;
}

void
in6_len2mask(mask, len)
	struct in6_addr *mask;
	int len;
{
	int i;

	bzero(mask, sizeof(*mask));
	for (i = 0; i < len / 8; i++)
		mask->s6_addr8[i] = 0xff;
	if (len % 8)
		mask->s6_addr8[i] = (0xff00 >> (len % 8)) & 0xff;
}

#define ifa2ia6(ifa)	((struct in6_ifaddr *)(ifa))
#define ia62ifa(ia6)	(&((ia6)->ia_ifa))

int
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
in6_control(so, cmd, data, ifp, p)
	struct	socket *so;
	u_long cmd;
	caddr_t	data;
	struct ifnet *ifp;
	struct proc *p;
#else
in6_control(so, cmd, data, ifp)
	struct	socket *so;
	u_long cmd;
	caddr_t	data;
	struct ifnet *ifp;
#endif
{
	struct	in6_ifreq *ifr = (struct in6_ifreq *)data;
	struct	in6_ifaddr *ia = NULL;
	struct	in6_aliasreq *ifra = (struct in6_aliasreq *)data;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	time_t time_second = (time_t)time.tv_sec;
#endif
	int privileged;

	privileged = 0;
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ == 3)
	if (p && !suser(p->p_ucred, &p->p_acflag))
		privileged++;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 4)
	if (p == NULL || !suser(p))
		privileged++;
#else
	if ((so->so_state & SS_PRIV) != 0)
		privileged++;
#endif

	switch (cmd) {
	case SIOCGETSGCNT_IN6:
	case SIOCGETMIFCNT_IN6:
		return (mrt6_ioctl(cmd, data));
	}

#ifdef MIP6
	/* These require root privileges */
	switch (cmd) {
	case SIOCSDEBUG_MIP6:
	case SIOCSBCFLUSH_MIP6:
	case SIOCSDEFCONFIG_MIP6:
	case SIOCSBRUPDATE_MIP6:
	case SIOCSENABLEBR_MIP6:
	case SIOCSATTACH_MIP6:
	case SIOCSRELEASE_MIP6:

	case SIOCSHALISTFLUSH_MIP6:
	case SIOCSHAPREF_MIP6:
	case SIOCSFWDSLUNICAST_MIP6:
	case SIOCSFWDSLMULTICAST_MIP6:

	case SIOCSFORADDRFLUSH_MIP6:
	case SIOCSHADDRFLUSH_MIP6:
	case SIOCSBULISTFLUSH_MIP6:
	case SIOCACOADDR_MIP6:
	case SIOCAHOMEADDR_MIP6:
	case SIOCSBULIFETIME_MIP6:
	case SIOCSHRLIFETIME_MIP6:
	case SIOCDCOADDR_MIP6:
	case SIOCSPROMMODE_MIP6:
	case SIOCSBU2CN_MIP6:
	case SIOCSREVTUNNEL_MIP6:
	case SIOCSAUTOCONFIG_MIP6:
	case SIOCSEAGERMD_MIP6:
		if (!privileged)
			return(EPERM);
		/* Anyone can use these or the user is root */
		/* case SIOCXVERYSAFECOMMAND_MIP6:  */
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
		return mip6_ioctl(so, cmd, data, ifp, p);
#else
		return mip6_ioctl(so, cmd, data, ifp);
#endif
	}
#endif /* MIP6 */

	if (ifp == NULL)
		return(EOPNOTSUPP);

	switch (cmd) {
	case SIOCSNDFLUSH_IN6:
	case SIOCSPFXFLUSH_IN6:
	case SIOCSRTRFLUSH_IN6:
	case SIOCSDEFIFACE_IN6:
	case SIOCSIFINFO_FLAGS:
		if (!privileged)
			return(EPERM);
		/*fall through*/
	case SIOCGIFINFO_IN6:
	case SIOCGDRLST_IN6:
	case SIOCGPRLST_IN6:
	case SIOCGNBRINFO_IN6:
	case SIOCGDEFIFACE_IN6:
		return(nd6_ioctl(cmd, data, ifp));
	}

	switch (cmd) {
	case SIOCSIFPREFIX_IN6:
	case SIOCDIFPREFIX_IN6:
	case SIOCAIFPREFIX_IN6:
	case SIOCCIFPREFIX_IN6:
	case SIOCSGIFPREFIX_IN6:
		if (!privileged)
			return(EPERM);
		/*fall through*/
	case SIOCGIFPREFIX_IN6:
		if (ip6_forwarding == 0)
			return(EPERM);
		return(in6_prefix_ioctl(so, cmd, data, ifp));
	}

	switch(cmd) {
	case SIOCSSCOPE6:
		if (!privileged)
			return(EPERM);
		return(scope6_set(ifp, ifr->ifr_ifru.ifru_scope_id));
		break;
	case SIOCGSCOPE6:
		return(scope6_get(ifp, ifr->ifr_ifru.ifru_scope_id));
		break;
	case SIOCGSCOPE6DEF:
		return(scope6_get_default(ifr->ifr_ifru.ifru_scope_id));
		break;
	}

	switch (cmd) {
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
		if (!privileged)
			return(EPERM);
		/*fall through*/
	case SIOCGLIFADDR:
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
		return in6_lifaddr_ioctl(so, cmd, data, ifp, p);
#else
		return in6_lifaddr_ioctl(so, cmd, data, ifp);
#endif
	}

	/*
	 * Find address for this interface, if it exists.
	 */
	if (ifra->ifra_addr.sin6_family == AF_INET6) { /* XXX */
		struct sockaddr_in6 *sa6 =
			(struct sockaddr_in6 *)&ifra->ifra_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
			if (sa6->sin6_addr.s6_addr16[1] == 0) {
				/* link ID is not embedded by the user */
				sa6->sin6_addr.s6_addr16[1] =
					htons(ifp->if_index);
			} else if (sa6->sin6_addr.s6_addr16[1] !=
				    htons(ifp->if_index)) {
				return(EINVAL);	/* link ID is contradict */
			}
			if (sa6->sin6_scope_id) {
				if (sa6->sin6_scope_id !=
				    (u_int32_t)ifp->if_index)
					return(EINVAL);
				sa6->sin6_scope_id = 0; /* XXX: good way? */
			}
		}
		ia = in6ifa_ifpwithaddr(ifp, &ifra->ifra_addr.sin6_addr);
	}

	switch (cmd) {
	case SIOCSIFADDR_IN6:
	case SIOCSIFDSTADDR_IN6:
	case SIOCSIFNETMASK_IN6:
		/*
		 * Since IPv6 allows a node to assign multiple addresses
		 * on a single interface, SIOCSIFxxx ioctls are not suitable
		 * and should be unused.
		 */
		/* we decided to obsolete this command (20000704) */
		return(EINVAL);

	case SIOCDIFADDR_IN6:
		/*
		 * for IPv4, we look for existing in_ifaddr here to allow
		 * "ifconfig if0 delete" to remove first IPv4 address on the
		 * interface.  For IPv6, as the spec allow multiple interface
		 * address from the day one, we consider "remove the first one"
		 * semantics to be not preferable.
		 */
		if (ia == NULL)
			return(EADDRNOTAVAIL);
		/* FALLTHROUGH */
	case SIOCAIFADDR_IN6:
		/*
		 * We always require users to specify a valid IPv6 address for
		 * the corresponding operation.
		 */
		if (ifra->ifra_addr.sin6_family != AF_INET6 ||
		    ifra->ifra_addr.sin6_len != sizeof(struct sockaddr_in6))
			return(EAFNOSUPPORT);
		if (!privileged)
			return(EPERM);

		break;

	case SIOCGIFADDR_IN6:
		/* This interface is basically deprecated. use SIOCGIFCONF. */
		/* fall through */
	case SIOCGIFAFLAG_IN6:
	case SIOCGIFNETMASK_IN6:
	case SIOCGIFDSTADDR_IN6:
	case SIOCGIFALIFETIME_IN6:
		/* must think again about its semantics */
		if (ia == NULL)
			return(EADDRNOTAVAIL);
		break;
	case SIOCSIFALIFETIME_IN6:
	    {
		struct in6_addrlifetime *lt;

		if (!privileged)
			return(EPERM);
		if (ia == NULL)
			return(EADDRNOTAVAIL);
		/* sanity for overflow - beware unsigned */
		lt = &ifr->ifr_ifru.ifru_lifetime;
		if (lt->ia6t_vltime != ND6_INFINITE_LIFETIME
		 && lt->ia6t_vltime + time_second < time_second) {
			return EINVAL;
		}
		if (lt->ia6t_pltime != ND6_INFINITE_LIFETIME
		 && lt->ia6t_pltime + time_second < time_second) {
			return EINVAL;
		}
		break;
	    }
	}

	switch (cmd) {

	case SIOCGIFADDR_IN6:
		ifr->ifr_addr = ia->ia_addr;
		break;

	case SIOCGIFDSTADDR_IN6:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return(EINVAL);
		/*
		 * XXX: should we check if ifa_dstaddr is NULL and return
		 * an error?
		 */
		ifr->ifr_dstaddr = ia->ia_dstaddr;
		break;

	case SIOCGIFNETMASK_IN6:
		ifr->ifr_addr = ia->ia_prefixmask;
		break;

	case SIOCGIFAFLAG_IN6:
		ifr->ifr_ifru.ifru_flags6 = ia->ia6_flags;
		break;

	case SIOCGIFSTAT_IN6:
		if (ifp == NULL)
			return EINVAL;
		if (in6_ifstat == NULL || ifp->if_index >= in6_ifstatmax
		 || in6_ifstat[ifp->if_index] == NULL) {
			/* return EAFNOSUPPORT? */
			bzero(&ifr->ifr_ifru.ifru_stat,
				sizeof(ifr->ifr_ifru.ifru_stat));
		} else
			ifr->ifr_ifru.ifru_stat = *in6_ifstat[ifp->if_index];
		break;

	case SIOCGIFSTAT_ICMP6:
		if (ifp == NULL)
			return EINVAL;
		if (icmp6_ifstat == NULL || ifp->if_index >= icmp6_ifstatmax ||
		    icmp6_ifstat[ifp->if_index] == NULL) {
			/* return EAFNOSUPPORT? */
			bzero(&ifr->ifr_ifru.ifru_stat,
				sizeof(ifr->ifr_ifru.ifru_icmp6stat));
		} else
			ifr->ifr_ifru.ifru_icmp6stat =
				*icmp6_ifstat[ifp->if_index];
		break;

	case SIOCGIFALIFETIME_IN6:
		ifr->ifr_ifru.ifru_lifetime = ia->ia6_lifetime;
		break;

	case SIOCSIFALIFETIME_IN6:
		ia->ia6_lifetime = ifr->ifr_ifru.ifru_lifetime;
		/* for sanity */
		if (ia->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
			ia->ia6_lifetime.ia6t_expire =
				time_second + ia->ia6_lifetime.ia6t_vltime;
		} else
			ia->ia6_lifetime.ia6t_expire = 0;
		if (ia->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
			ia->ia6_lifetime.ia6t_preferred =
				time_second + ia->ia6_lifetime.ia6t_pltime;
		} else
			ia->ia6_lifetime.ia6t_preferred = 0;
		break;

	case SIOCAIFADDR_IN6:
		return(in6_update_ifa(ifp, ifra, ia));

	case SIOCDIFADDR_IN6:
		in6_purgeaddr(&ia->ia_ifa, ifp);
		break;

	default:
		if (ifp == NULL || ifp->if_ioctl == 0)
			return(EOPNOTSUPP);
		return((*ifp->if_ioctl)(ifp, cmd, data));
	}

	return(0);
}

/*
 * Update parameters of an IPv6 interface address.
 * If necessary, a new entry is created and linked into address chains.
 * This function is separated from in6_control().
 * XXX: should this be performed under splnet()?
 */
int
in6_update_ifa(ifp, ifra, ia)
	struct ifnet *ifp;
	struct in6_aliasreq *ifra;
	struct in6_ifaddr *ia;
{
	int error = 0, hostIsNew = 1, prefixIsNew = 0, plen = -1;
	struct in6_ifaddr *oia, *ib;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifa;
#endif
	struct sockaddr_in6 dst6;
	struct in6_addrlifetime *lt;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	time_t time_second = (time_t)time.tv_sec;
#endif
#ifdef MEASURE_PERFORMANCE
	int new_ifa = 0;
#endif

	/* Validate parameters */
	if (ifp == NULL || ifra == NULL)/* this maybe redundant */
		return(EINVAL);

	/*
	 * The destination address for a p2p link must have a family
	 * of AF_UNSPEC or AF_INET6.
	 */
	if ((ifp->if_flags & IFF_POINTOPOINT) != 0 &&
	    ifra->ifra_dstaddr.sin6_family != AF_INET6 &&
	    ifra->ifra_dstaddr.sin6_family != AF_UNSPEC)
		return(EAFNOSUPPORT);
	/*
	 * The prefixmask must have a family of AF_UNSPEC or AF_INET6.
	 */
	if (ifra->ifra_prefixmask.sin6_family != AF_INET6 &&
	    ifra->ifra_prefixmask.sin6_family != AF_UNSPEC)
		return(EAFNOSUPPORT);
	/*
	 * Because the IPv6 address architecture is classless, we require
	 * users to specify a (non 0) prefix length (mask) for a new address.
	 * We also require the prefix (when specified) mask is valid, and thus
	 * reject a non-consecutive mask.
	 */
	if (ia == NULL && ifra->ifra_prefixmask.sin6_len == 0)
		return(EINVAL);
	if (ifra->ifra_prefixmask.sin6_len != 0) {
		plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr,
				    (u_char *)&ifra->ifra_prefixmask +
				    ifra->ifra_prefixmask.sin6_len);
		if (plen <= 0)
			return(EINVAL);
	}
	else {
		/*
		 * in this, ia must not be NULL. we just use its prefix length.
		 */
		plen = in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL);
	}
	/*
	 * If the destination address on a p2p interface is specified,
	 * and the address is a scoped one, validate/set the scope
	 * zone identifier.
	 */
	dst6 = ifra->ifra_dstaddr;
	if ((ifp->if_flags & IFF_POINTOPOINT) &&
	    (dst6.sin6_family == AF_INET6)) {
		int scopeid;

#ifndef SCOPEDROUTING
		if ((error = in6_recoverscope(&dst6,
					      &ifra->ifra_dstaddr.sin6_addr,
					      ifp)) != 0)
			return(error);
#endif
		scopeid = in6_addr2scopeid(ifp, &dst6.sin6_addr);
		if (dst6.sin6_scope_id == 0) /* user omit to specify the ID. */
			dst6.sin6_scope_id = scopeid;
		else if (dst6.sin6_scope_id != scopeid)
			return(EINVAL); /* scope ID mismatch. */
#ifndef SCOPEDROUTING
		if ((error = in6_embedscope(&dst6.sin6_addr, &dst6, NULL, NULL))
		    != 0)
			return(error);
		dst6.sin6_scope_id = 0; /* XXX */
#endif
	}
	/*
	 * When the destination address is specified, the corresponding
	 * prefix length must be 128.
	 */
	if (ifra->ifra_dstaddr.sin6_family == AF_INET6 && plen != 128) {
		/*
		 * The following message seems noisy, but we dare to add it for
		 * diagnosis.
		 */
		log(LOG_INFO, "in6_update_ifa: prefixlen must be 128 when "
		    "dstaddr is specified\n");
		return(EINVAL);
	}
	/* lifetime consistency check */
	lt = &ifra->ifra_lifetime;
	if (lt->ia6t_vltime != ND6_INFINITE_LIFETIME
	    && lt->ia6t_vltime + time_second < time_second) {
		return EINVAL;
	}
	if (lt->ia6t_vltime == 0) {
		/*
		 * the following log might be noisy, but this is a typical
		 * configuration mistake or a tool's bug.
		 */
		log(LOG_INFO,
		    "in6_update_ifa: valid lifetime is 0 for %s.\n",
		    ip6_sprintf(&ifra->ifra_addr.sin6_addr));
	}
	if (lt->ia6t_pltime != ND6_INFINITE_LIFETIME
	    && lt->ia6t_pltime + time_second < time_second) {
		return EINVAL;
	}

	/*
	 * If this is a new address, allocate a new ifaddr and link it
	 * into chains.
	 */
	if (ia == NULL) {
		ia = (struct in6_ifaddr *)
			malloc(sizeof(*ia), M_IFADDR, M_WAITOK);
		if (ia == NULL)
			return (ENOBUFS);
		bzero((caddr_t)ia, sizeof(*ia));
		/* Initialize the address and masks */
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
		ia->ia_addr.sin6_family = AF_INET6;
		ia->ia_addr.sin6_len = sizeof(ia->ia_addr);
		if ((ifp->if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK)) != 0) {
			/*
			 * XXX: some functions expect that ifa_dstaddr is not
			 * NULL for p2p interfaces.
			 */
			ia->ia_ifa.ifa_dstaddr
				= (struct sockaddr *)&ia->ia_dstaddr;
		} else {
			ia->ia_ifa.ifa_dstaddr = NULL;
		}
		ia->ia_ifa.ifa_netmask
			= (struct sockaddr *)&ia->ia_prefixmask;

		ia->ia_ifp = ifp;
		if ((oia = in6_ifaddr) != NULL) {
			for ( ; oia->ia_next; oia = oia->ia_next)
				continue;
			oia->ia_next = ia;
		} else
			in6_ifaddr = ia;
#ifdef __NetBSD__
		/* gain a refcnt for the link from in6_ifaddr */
		IFAREF(&ia->ia_ifa);
#endif

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		if ((ifa = ifp->if_addrlist) != NULL) {
			for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
				continue;
			ifa->ifa_next = ia62ifa(ia);
		} else
			ifp->if_addrlist = ia62ifa(ia);
#else
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, &ia->ia_ifa,
				  ifa_list);
#endif
#ifdef __NetBSD__
		/* gain another refcnt for the link from if_addrlist */
		IFAREF(&ia->ia_ifa);
#endif

#ifdef MEASURE_PERFORMANCE
		new_ifa = 1;
#endif
	}

	/* check if a new address is being added */
	if (ia->ia_addr.sin6_len &&
	    IN6_ARE_ADDR_EQUAL(&ifra->ifra_addr.sin6_addr,
			       &ia->ia_addr.sin6_addr)) {
		/*
		 * The requested address is already in the list.
		 * This means the user just wants to modify some
		 * parameters of the existing address.
		 */
		hostIsNew = 0;
	}

	/* set prefix mask */
	if (ifra->ifra_prefixmask.sin6_len) {
		/*
		 * If the prefix length for an existing address
		 * changes, (which should be rare in the current IPv6
		 * address architecture, though) scrub the route
		 * corresponding to the old prefix.
		 */
		if (ia->ia_prefixmask.sin6_len &&
		    in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL) != plen)
			in6_ifscrub(ifp, ia, 0);
		ia->ia_prefixmask = ifra->ifra_prefixmask;
	}

	/*
	 * Check if we have another address that shares the same prefix
	 * of the address being configured.  We search in all the interfaces,
	 * since the user tries to assign a same single prefix on multiple
	 * interfaces.  Such a configuration is not very healthy, but
	 * it seems too restrictive to prevent it.
	 */
	for (ib = in6_ifaddr; ib; ib = ib->ia_next) {
		int ifa6_plen;

		if (ib == ia)
			continue;

		/*
		 * we are only intersted in routes that are associated with
		 * an interface direct route.
		 */
		if ((ib->ia_ifa.ifa_flags & IFA_ROUTE) == 0)
			continue;

		ifa6_plen = in6_mask2len(&ib->ia_prefixmask.sin6_addr, NULL);
		if (plen == ifa6_plen &&
		    in6_are_prefix_equal(&ifra->ifra_addr.sin6_addr,
					 &ib->ia_addr.sin6_addr,
					 plen))
			break;
	}
	if (ib == NULL)
		prefixIsNew = 1;

	/*
	 * If a new destination address is on a p2p link, scrub the
	 * old one and install the new destination.
	 */
	if ((ifp->if_flags & IFF_POINTOPOINT) &&
	    (dst6.sin6_family == AF_INET6) &&
	    !IN6_ARE_ADDR_EQUAL(&dst6.sin6_addr,
				&ia->ia_dstaddr.sin6_addr)) {
		in6_ifscrub(ifp, ia, 0);
		ia->ia_dstaddr = dst6;
		prefixIsNew = 1; /* We lie; but effect's the same */
	}

	/* reset the interface and routing table appropriately. */
	if ((error = in6_ifinit(ifp, ia, &ifra->ifra_addr,
				hostIsNew, prefixIsNew)) != 0)
		goto unlink;

	/* update prefix list */
	if (hostIsNew) {
		int iilen;

		iilen = (sizeof(ia->ia_prefixmask.sin6_addr) << 3) - plen;
		if ((error = in6_prefix_add_ifid(iilen, ia)) != 0)
			goto unlink;
	}

	if (hostIsNew && (ifp->if_flags & IFF_MULTICAST)) {
		/*
		 * join solicited multicast addr for new host id
		 */
		struct in6_addr llsol;
		bzero(&llsol, sizeof(struct in6_addr));
		llsol.s6_addr16[0] = htons(0xff02);
		llsol.s6_addr16[1] = htons(ifp->if_index);
		llsol.s6_addr32[1] = 0;
		llsol.s6_addr32[2] = htonl(1);
		llsol.s6_addr32[3] =
			ifra->ifra_addr.sin6_addr.s6_addr32[3];
		llsol.s6_addr8[12] = 0xff;
		(void)in6_addmulti(&llsol, ifp, &error);
		if (error != 0)
			goto unlink;
	}

	ia->ia6_flags = ifra->ifra_flags;
	ia->ia6_flags &= ~IN6_IFF_DUPLICATED;	/*safety*/
	ia->ia6_flags &= ~IN6_IFF_NODAD;	/* Mobile IPv6 */

	ia->ia6_lifetime = ifra->ifra_lifetime;
	/* for sanity */
	if (ia->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME) {
		ia->ia6_lifetime.ia6t_expire =
			time_second + ia->ia6_lifetime.ia6t_vltime;
	} else
		ia->ia6_lifetime.ia6t_expire = 0;
	if (ia->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME) {
		ia->ia6_lifetime.ia6t_preferred =
			time_second + ia->ia6_lifetime.ia6t_pltime;
	} else
		ia->ia6_lifetime.ia6t_preferred = 0;

#ifdef MEASURE_PERFORMANCE
	{
		int s = splnet();
		if (new_ifa)
			in6h_addifa(ia);
		else
			in6h_rebuild(0);
		splx(s);
	}
#endif

	/*
	 * make sure to initialize ND6 information.  this is to workaround
	 * issues with interfaces with IPv6 addresses, which have never brought
	 * up.  we are assuming that it is safe to nd6_ifattach multiple times.
	 */
	nd6_ifattach(ifp);

	/*
	 * Perform DAD, if needed.
	 * XXX It may be of use, if we can administratively
	 * disable DAD.
	 */
	switch (ifp->if_type) {
	case IFT_ARCNET:
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_IEEE1394:
#ifdef IFT_IEEE80211
	case IFT_IEEE80211:
#endif
#if 0
	case IFT_ATM:
	case IFT_SLIP:
	case IFT_PPP:
#endif
		/* Mobile IPv6 modification */
		if ((ifra->ifra_flags & IN6_IFF_NODAD) == 0) {
			ia->ia6_flags |= IN6_IFF_TENTATIVE;
			nd6_dad_start((struct ifaddr *)ia, NULL);
		}
		break;
#ifdef IFT_DUMMY
	case IFT_DUMMY:
#endif
	case IFT_FAITH:
	case IFT_GIF:		/* can we really skip DAD? */
	case IFT_LOOP:
	default:
		break;
	}

	return(error);

  unlink:
	/*
	 * XXX: if a change of an existing address failed, keep the entry
	 * anyway.
	 */
	if (hostIsNew)
		in6_unlink_ifa(ia, ifp);
	return(error);
}

void
in6_purgeaddr(ifa, ifp)
	struct ifaddr *ifa;
	struct ifnet *ifp;
{
	struct in6_ifaddr *ia = (void *) ifa;

	/* stop DAD processing */
	nd6_dad_stop(ifa);

	in6_ifscrub(ifp, ia, 1);

	if (ifp->if_flags & IFF_MULTICAST) {
		/*
		 * delete solicited multicast addr for deleting host id
		 */
		struct in6_multi *in6m;
		struct in6_addr llsol;
		bzero(&llsol, sizeof(struct in6_addr));
		llsol.s6_addr16[0] = htons(0xff02);
		llsol.s6_addr16[1] = htons(ifp->if_index);
		llsol.s6_addr32[1] = 0;
		llsol.s6_addr32[2] = htonl(1);
		llsol.s6_addr32[3] =
			ia->ia_addr.sin6_addr.s6_addr32[3];
		llsol.s6_addr8[12] = 0xff;

		IN6_LOOKUP_MULTI(llsol, ifp, in6m);
		if (in6m)
			in6_delmulti(in6m);
	}

	in6_unlink_ifa(ia, ifp);
}

static void
in6_unlink_ifa(ia, ifp)
	struct in6_ifaddr *ia;
	struct ifnet *ifp;
{
	int plen, iilen;
	struct in6_ifaddr *oia;
#ifdef __NetBSD__
	int	s = splsoftnet();
#else
	int	s = splnet();
#endif

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifa;
#endif

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	if ((ifa = ifp->if_addrlist) == ia62ifa(ia))
		ifp->if_addrlist = ifa->ifa_next;
	else {
		while (ifa->ifa_next &&
		       (ifa->ifa_next != ia62ifa(ia)))
			ifa = ifa->ifa_next;
		if (ifa->ifa_next)
			ifa->ifa_next = ia62ifa(ia)->ifa_next;
		else {
			/* search failed */
			printf("Couldn't unlink in6_ifaddr from ifp\n");
		}
	}
#else
	TAILQ_REMOVE(&ifp->if_addrlist, &ia->ia_ifa, ifa_list);
#endif
#ifdef __NetBSD__
	/* release a refcnt for the link from if_addrlist */
	IFAFREE(&ia->ia_ifa);
#endif

	oia = ia;
	if (oia == (ia = in6_ifaddr))
		in6_ifaddr = ia->ia_next;
	else {
		while (ia->ia_next && (ia->ia_next != oia))
			ia = ia->ia_next;
		if (ia->ia_next)
			ia->ia_next = oia->ia_next;
		else {
			/* search failed */
			printf("Couldn't unlink in6_ifaddr from in6_ifaddr\n");
		}
	}

	if (oia->ia6_ifpr) {	/* check for safety */
		plen = in6_mask2len(&oia->ia_prefixmask.sin6_addr, NULL);
		iilen = (sizeof(oia->ia_prefixmask.sin6_addr) << 3) - plen;
		in6_prefix_remove_ifid(iilen, oia);
	}

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	if (oia->ia6_multiaddrs.lh_first != NULL)
		in6_savemkludge(oia);
#endif

#ifdef MEASURE_PERFORMANCE
	in6h_delifa(oia);
#endif

	/*
	 * release another refcnt for the link from in6_ifaddr.
	 * Note that we should decrement the refcnt at least once for all *BSD.
	 */
	IFAFREE(&oia->ia_ifa);

	splx(s);
}

void
in6_purgeif(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ifa, *nifa;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = nifa)
#else
	for (ifa = TAILQ_FIRST(&ifp->if_addrlist); ifa != NULL; ifa = nifa)
#endif
	{
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		nifa = ifa->ifa_next;
#else
		nifa = TAILQ_NEXT(ifa, ifa_list);
#endif
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		in6_purgeaddr(ifa, ifp);
	}

#if !(defined(__bsdi__) && _BSDI_VERSION >= 199802)
	in6_ifdetach(ifp);
#endif
}

/*
 * SIOC[GAD]LIFADDR.
 *	SIOCGLIFADDR: get first address. (?)
 *	SIOCGLIFADDR with IFLR_PREFIX:
 *		get first address that matches the specified prefix.
 *	SIOCALIFADDR: add the specified address.
 *	SIOCALIFADDR with IFLR_PREFIX:
 *		add the specified prefix, filling hostid part from
 *		the first link-local address.  prefixlen must be <= 64.
 *	SIOCDLIFADDR: delete the specified address.
 *	SIOCDLIFADDR with IFLR_PREFIX:
 *		delete the first address that matches the specified prefix.
 * return values:
 *	EINVAL on invalid parameters
 *	EADDRNOTAVAIL on prefix match failed/specified address not found
 *	other values may be returned from in6_ioctl()
 *
 * NOTE: SIOCALIFADDR(with IFLR_PREFIX set) allows prefixlen less than 64.
 * this is to accomodate address naming scheme other than RFC2374,
 * in the future.
 * RFC2373 defines interface id to be 64bit, but it allows non-RFC2374
 * address encoding scheme. (see figure on page 8)
 */
static int
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
in6_lifaddr_ioctl(so, cmd, data, ifp, p)
	struct socket *so;
	u_long cmd;
	caddr_t	data;
	struct ifnet *ifp;
	struct proc *p;
#else
in6_lifaddr_ioctl(so, cmd, data, ifp)
	struct socket *so;
	u_long cmd;
	caddr_t	data;
	struct ifnet *ifp;
#endif
{
	struct if_laddrreq *iflr = (struct if_laddrreq *)data;
	struct ifaddr *ifa;
	struct sockaddr *sa;

	/* sanity checks */
	if (!data || !ifp) {
		panic("invalid argument to in6_lifaddr_ioctl");
		/*NOTRECHED*/
	}

	switch (cmd) {
	case SIOCGLIFADDR:
		/* address must be specified on GET with IFLR_PREFIX */
		if ((iflr->flags & IFLR_PREFIX) == 0)
			break;
		/*FALLTHROUGH*/
	case SIOCALIFADDR:
	case SIOCDLIFADDR:
		/* address must be specified on ADD and DELETE */
		sa = (struct sockaddr *)&iflr->addr;
		if (sa->sa_family != AF_INET6)
			return EINVAL;
		if (sa->sa_len != sizeof(struct sockaddr_in6))
			return EINVAL;
		/* XXX need improvement */
		sa = (struct sockaddr *)&iflr->dstaddr;
		if (sa->sa_family && sa->sa_family != AF_INET6)
			return EINVAL;
		if (sa->sa_len && sa->sa_len != sizeof(struct sockaddr_in6))
			return EINVAL;
		break;
	default: /*shouldn't happen*/
#if 0
		panic("invalid cmd to in6_lifaddr_ioctl");
		/*NOTREACHED*/
#else
		return EOPNOTSUPP;
#endif
	}
	if (sizeof(struct in6_addr) * 8 < iflr->prefixlen)
		return EINVAL;

	switch (cmd) {
	case SIOCALIFADDR:
	    {
		struct in6_aliasreq ifra;
		struct in6_addr *hostid = NULL;
		int prefixlen;

		if ((iflr->flags & IFLR_PREFIX) != 0) {
			struct sockaddr_in6 *sin6;

			/*
			 * hostid is to fill in the hostid part of the
			 * address.  hostid points to the first link-local
			 * address attached to the interface.
			 */
			ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(ifp, 0);
			if (!ifa)
				return EADDRNOTAVAIL;
			hostid = IFA_IN6(ifa);

		 	/* prefixlen must be <= 64. */
			if (64 < iflr->prefixlen)
				return EINVAL;
			prefixlen = iflr->prefixlen;

			/* hostid part must be zero. */
			sin6 = (struct sockaddr_in6 *)&iflr->addr;
			if (sin6->sin6_addr.s6_addr32[2] != 0
			 || sin6->sin6_addr.s6_addr32[3] != 0) {
				return EINVAL;
			}
		} else
			prefixlen = iflr->prefixlen;

		/* copy args to in6_aliasreq, perform ioctl(SIOCAIFADDR_IN6). */
		bzero(&ifra, sizeof(ifra));
		bcopy(iflr->iflr_name, ifra.ifra_name,
			sizeof(ifra.ifra_name));

		bcopy(&iflr->addr, &ifra.ifra_addr,
			((struct sockaddr *)&iflr->addr)->sa_len);
		if (hostid) {
			/* fill in hostid part */
			ifra.ifra_addr.sin6_addr.s6_addr32[2] =
				hostid->s6_addr32[2];
			ifra.ifra_addr.sin6_addr.s6_addr32[3] =
				hostid->s6_addr32[3];
		}

		if (((struct sockaddr *)&iflr->dstaddr)->sa_family) {	/*XXX*/
			bcopy(&iflr->dstaddr, &ifra.ifra_dstaddr,
				((struct sockaddr *)&iflr->dstaddr)->sa_len);
			if (hostid) {
				ifra.ifra_dstaddr.sin6_addr.s6_addr32[2] =
					hostid->s6_addr32[2];
				ifra.ifra_dstaddr.sin6_addr.s6_addr32[3] =
					hostid->s6_addr32[3];
			}
		}

		ifra.ifra_prefixmask.sin6_family = AF_INET6;
		ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		in6_len2mask(&ifra.ifra_prefixmask.sin6_addr, prefixlen);

		ifra.ifra_flags = iflr->flags & ~IFLR_PREFIX;
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
		return in6_control(so, SIOCAIFADDR_IN6, (caddr_t)&ifra, ifp, p);
#else
		return in6_control(so, SIOCAIFADDR_IN6, (caddr_t)&ifra, ifp);
#endif
	    }
	case SIOCGLIFADDR:
	case SIOCDLIFADDR:
	    {
		struct in6_ifaddr *ia;
		struct in6_addr mask, candidate, match;
		struct sockaddr_in6 *sin6;
		int cmp;

		bzero(&mask, sizeof(mask));
		if (iflr->flags & IFLR_PREFIX) {
			/* lookup a prefix rather than address. */
			in6_len2mask(&mask, iflr->prefixlen);

			sin6 = (struct sockaddr_in6 *)&iflr->addr;
			bcopy(&sin6->sin6_addr, &match, sizeof(match));
			match.s6_addr32[0] &= mask.s6_addr32[0];
			match.s6_addr32[1] &= mask.s6_addr32[1];
			match.s6_addr32[2] &= mask.s6_addr32[2];
			match.s6_addr32[3] &= mask.s6_addr32[3];

			/* if you set extra bits, that's wrong */
			if (bcmp(&match, &sin6->sin6_addr, sizeof(match)))
				return EINVAL;

			cmp = 1;
		} else {
			if (cmd == SIOCGLIFADDR) {
				/* on getting an address, take the 1st match */
				cmp = 0;	/*XXX*/
			} else {
				/* on deleting an address, do exact match */
				in6_len2mask(&mask, 128);
				sin6 = (struct sockaddr_in6 *)&iflr->addr;
				bcopy(&sin6->sin6_addr, &match, sizeof(match));

				cmp = 1;
			}
		}

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
		for (ifa = ifp->if_addrlist.tqh_first;
		     ifa;
		     ifa = ifa->ifa_list.tqe_next)
#endif
		{
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (!cmp)
				break;

			bcopy(IFA_IN6(ifa), &candidate, sizeof(candidate));
#ifndef SCOPEDROUTING
			/*
			 * XXX: this is adhoc, but is necessary to allow
			 * a user to specify fe80::/64 (not /10) for a
			 * link-local address.
			 */
			if (IN6_IS_ADDR_LINKLOCAL(&candidate))
				candidate.s6_addr16[1] = 0;
#endif
			candidate.s6_addr32[0] &= mask.s6_addr32[0];
			candidate.s6_addr32[1] &= mask.s6_addr32[1];
			candidate.s6_addr32[2] &= mask.s6_addr32[2];
			candidate.s6_addr32[3] &= mask.s6_addr32[3];
			if (IN6_ARE_ADDR_EQUAL(&candidate, &match))
				break;
		}
		if (!ifa)
			return EADDRNOTAVAIL;
		ia = ifa2ia6(ifa);

		if (cmd == SIOCGLIFADDR) {
#ifndef SCOPEDROUTING
			struct sockaddr_in6 *s6;
#endif

			/* fill in the if_laddrreq structure */
			bcopy(&ia->ia_addr, &iflr->addr, ia->ia_addr.sin6_len);
#ifndef SCOPEDROUTING		/* XXX see above */
			s6 = (struct sockaddr_in6 *)&iflr->addr;
			if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
				s6->sin6_addr.s6_addr16[1] = 0;
				s6->sin6_scope_id =
					in6_addr2scopeid(ifp, &s6->sin6_addr);
			}
#endif
			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &iflr->dstaddr,
					ia->ia_dstaddr.sin6_len);
#ifndef SCOPEDROUTING		/* XXX see above */
				s6 = (struct sockaddr_in6 *)&iflr->dstaddr;
				if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
					s6->sin6_addr.s6_addr16[1] = 0;
					s6->sin6_scope_id =
						in6_addr2scopeid(ifp,
								 &s6->sin6_addr);
				}
#endif
			} else
				bzero(&iflr->dstaddr, sizeof(iflr->dstaddr));

			iflr->prefixlen =
				in6_mask2len(&ia->ia_prefixmask.sin6_addr,
					     NULL);

			iflr->flags = ia->ia6_flags;	/*XXX*/

			return 0;
		} else {
			struct in6_aliasreq ifra;

			/* fill in6_aliasreq and do ioctl(SIOCDIFADDR_IN6) */
			bzero(&ifra, sizeof(ifra));
			bcopy(iflr->iflr_name, ifra.ifra_name,
				sizeof(ifra.ifra_name));

			bcopy(&ia->ia_addr, &ifra.ifra_addr,
				ia->ia_addr.sin6_len);
			if ((ifp->if_flags & IFF_POINTOPOINT) != 0) {
				bcopy(&ia->ia_dstaddr, &ifra.ifra_dstaddr,
					ia->ia_dstaddr.sin6_len);
			} else {
				bzero(&ifra.ifra_dstaddr,
				    sizeof(ifra.ifra_dstaddr));
			}
			bcopy(&ia->ia_prefixmask, &ifra.ifra_dstaddr,
				ia->ia_prefixmask.sin6_len);

			ifra.ifra_flags = ia->ia6_flags;
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
			return in6_control(so, SIOCDIFADDR_IN6, (caddr_t)&ifra,
				ifp, p);
#else
			return in6_control(so, SIOCDIFADDR_IN6, (caddr_t)&ifra,
				ifp);
#endif
		}
	    }
	}

	return EOPNOTSUPP;	/*just for safety*/
}

/*
 * Delete any existing route for an interface and a loopback route
 * associated with the given address.
 */
void
in6_ifscrub(ifp, ia, delloop)
	struct ifnet *ifp;
	struct in6_ifaddr *ia;
	int delloop;
{
	int plen, error;
	struct in6_ifaddr *ia6, *ia6_cand = NULL;

	/* Remove ownaddr's loopback rtentry, if it exists. */
	if (delloop && ia->ia_addr.sin6_family == AF_INET6)
		in6_ifremloop(&(ia->ia_ifa));

	if ((ia->ia_flags & IFA_ROUTE) == 0)
		return;

	/*
	 * We should check the existence of dstaddr, because link-local
	 * addresses can be configured without particular destinations
	 * even on point-to-point or loopback interfaces.
	 * In this case, kernel would panic in rtinit()...
	 */
	if (ia->ia_ifa.ifa_dstaddr != NULL && /* we should ensure this... */
	    ia->ia_ifa.ifa_dstaddr->sa_family == AF_INET6)
		error = rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
	else
		error = rtinit(&(ia->ia_ifa), (int)RTM_DELETE, 0);
	if (error != 0) {
		/* this should be impossible! what should we do? */

		log(LOG_ERR, "in6_ifscrub: failed to delete interface route "
		    "(ifa=%s, errno=%d)\n",
		    ip6_sprintf(&ia->ia_addr.sin6_addr), error);
		return;		/* is this correct?  reset the flag anyway? */
	}
	ia->ia_flags &= ~IFA_ROUTE;

	/*
	 * Check if we have another address that has the same prefix of
	 * the scrubbed address.  If we have one, reinstall the corresponding
	 * interface route.
	 * We may have more than one candidates.  If they belong to different
	 * interfaces, prefer the one(s) on the same interface as of the
	 * address just deleted.
	 */
	plen = in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL);
	for (ia6 = in6_ifaddr; ia6; ia6 = ia6->ia_next) {
		int ia6_plen;

		if (ia6 == ia)
			continue;

		ia6_plen = in6_mask2len(&ia6->ia_prefixmask.sin6_addr, NULL);
		if (ia6_plen == plen &&
		    in6_are_prefix_equal(&ia->ia_addr.sin6_addr,
					 &ia6->ia_addr.sin6_addr, plen)) {

			if ((ia6->ia_ifa.ifa_flags & IFA_ROUTE) != 0) {
				/* this should be impossible! */
				log(LOG_NOTICE, "in6_ifscrub: there seem to "
				    "be more than one ifaddr that has an "
				    "interface route (%s/%d)\n",
				    ip6_sprintf(&ia6->ia_addr.sin6_addr),
				    plen);

				/*
				 * we could proceed anway, but it will probably
				 * be in vain.
				 */
				return;
			}

			if (ia6->ia_ifa.ifa_ifp == ia->ia_ifa.ifa_ifp) {
				ia6_cand = ia6;
				break;
			}
			else if (ia6_cand == NULL)
				ia6_cand = ia6;
		}
	}

	if (ia6_cand != NULL &&
	    (error = in6_ifaddroute(ifp, ia6_cand, plen)) != 0) {
		log(LOG_NOTICE,
		    "in6_ifscrub: failed to restore an interface"
		    " route for %s/%d on %s, errno = %d\n",
		    ip6_sprintf(&ia->ia_addr.sin6_addr),
		    plen, if_name(ia->ia_ifp), error);

		/* XXX: we could try other candidates, but... */
	}
}

/*
 * Initialize an interface's intetnet6 address
 * and routing table entry.
 */
int
in6_ifinit(ifp, ia, sin6, newhost, newprefix)
	struct ifnet *ifp;
	struct in6_ifaddr *ia;
	struct sockaddr_in6 *sin6;
	int newhost, newprefix;
{
	int	error = 0, plen;
	int	s = splimp();

	ia->ia_addr = *sin6;
	/*
	 * Give the interface a chance to initialize
	 * if this is its first address,
	 * and to validate the address if necessary.
	 */
	if (newhost && ifp->if_ioctl &&
	    (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia))) {
		splx(s);
		return(error);
	}
	splx(s);

	/* we could do in(6)_socktrim here, but just omit it at this moment. */

	/*
	 * We'll make an interface direct route when
	 * - prefixlen is smaller than 128, or
	 * - the destination address is specified.
	 * Even for these cases, we don't need cloning for host routes.
	 */
	plen = in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL); /* XXX  */
	if (plen == 128 && ia->ia_dstaddr.sin6_family != AF_INET6)
		newprefix = 0;
	if (plen < 128) {
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
	}

	/* this should be in in6_ifaddroute()? */
	ia->ia_ifa.ifa_metric = ifp->if_metric;
	/*
	 * Add route for the network if a new prefix is assigned.
	 * This should not fail, because we do it only when the prefix is new.
	 * We therefore return the error immediately on failure.
	 */
	if (newprefix) {
		if ((error = in6_ifaddroute(ifp, ia, plen)) != 0)
			return(error);
	}

	/* Add ownaddr as loopback rtentry, if necessary(ex. on p2p link). */
	if (newhost)
		in6_ifaddloop(&(ia->ia_ifa));

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	if (ifp->if_flags & IFF_MULTICAST)
		in6_restoremkludge(ia, ifp);
#endif

	return(error);
}

static int
in6_ifaddroute(ifp, ia, plen)
	struct ifnet *ifp;
	struct in6_ifaddr *ia;
	int plen;
{
	int flags = RTF_UP, error;

	if (plen == 128)
		flags |= RTF_HOST;

	if ((error = rtinit(&(ia->ia_ifa), (int)RTM_ADD, flags)) == 0)
		ia->ia_flags |= IFA_ROUTE;
	else
		return(error);

	return(0);
}

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
/*
 * Multicast address kludge:
 * If there were any multicast addresses attached to this interface address,
 * either move them to another address on this interface, or save them until
 * such time as this interface is reconfigured for IPv6.
 */
void
in6_savemkludge(oia)
	struct in6_ifaddr *oia;
{
	struct in6_ifaddr *ia;
	struct in6_multi *in6m, *next;

	IFP_TO_IA6(oia->ia_ifp, ia);
	if (ia) {	/* there is another address */
		for (in6m = oia->ia6_multiaddrs.lh_first; in6m; in6m = next){
			next = in6m->in6m_entry.le_next;
			IFAFREE(&in6m->in6m_ia->ia_ifa);
			IFAREF(&ia->ia_ifa);
			in6m->in6m_ia = ia;
			LIST_INSERT_HEAD(&ia->ia6_multiaddrs, in6m, in6m_entry);
		}
	} else {	/* last address on this if deleted, save */
		struct multi6_kludge *mk;

		mk = malloc(sizeof(*mk), M_IPMADDR, M_WAITOK);

		LIST_INIT(&mk->mk_head);
		mk->mk_ifp = oia->ia_ifp;

		for (in6m = oia->ia6_multiaddrs.lh_first; in6m; in6m = next){
			next = in6m->in6m_entry.le_next;
			IFAFREE(&in6m->in6m_ia->ia_ifa); /* release reference */
			in6m->in6m_ia = NULL;
			LIST_INSERT_HEAD(&mk->mk_head, in6m, in6m_entry);
		}

		if (mk->mk_head.lh_first != NULL) {
			LIST_INSERT_HEAD(&in6_mk, mk, mk_entry);
		} else {
			FREE(mk, M_IPMADDR);
		}
	}
}

/*
 * Continuation of multicast address hack:
 * If there was a multicast group list previously saved for this interface,
 * then we re-attach it to the first address configured on the i/f.
 */
void
in6_restoremkludge(ia, ifp)
	struct in6_ifaddr *ia;
	struct ifnet *ifp;
{
	struct multi6_kludge *mk;

	for (mk = in6_mk.lh_first; mk; mk = mk->mk_entry.le_next) {
		if (mk->mk_ifp == ifp) {
			struct in6_multi *in6m, *next;

			for (in6m = mk->mk_head.lh_first; in6m; in6m = next) {
				next = in6m->in6m_entry.le_next;
				in6m->in6m_ia = ia;
				IFAREF(&ia->ia_ifa);
				LIST_INSERT_HEAD(&ia->ia6_multiaddrs,
						 in6m, in6m_entry);
			}
			LIST_REMOVE(mk, mk_entry);
			free(mk, M_IPMADDR);
			break;
		}
	}
}

void
in6_purgemkludge(ifp)
	struct ifnet *ifp;
{
	struct multi6_kludge *mk;
	struct in6_multi *in6m;

	for (mk = in6_mk.lh_first; mk; mk = mk->mk_entry.le_next) {
		if (mk->mk_ifp != ifp)
			continue;

		/* leave from all multicast groups joined */
		while ((in6m = LIST_FIRST(&mk->mk_head)) != NULL)
			in6_delmulti(in6m);
		LIST_REMOVE(mk, mk_entry);
		free(mk, M_IPMADDR);
		break;
	}
}

/*
 * Add an address to the list of IP6 multicast addresses for a
 * given interface.
 */
struct	in6_multi *
in6_addmulti(maddr6, ifp, errorp)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp;
{
	struct	in6_ifaddr *ia;
	struct	in6_ifreq ifr;
	struct	in6_multi *in6m;
#ifdef __NetBSD__
	int	s = splsoftnet();
#else
	int	s = splnet();
#endif

	*errorp = 0;
	/*
	 * See if address already in list.
	 */
	IN6_LOOKUP_MULTI(*maddr6, ifp, in6m);
	if (in6m != NULL) {
		/*
		 * Found it; just increment the refrence count.
		 */
		in6m->in6m_refcount++;
	} else {
		/*
		 * New address; allocate a new multicast record
		 * and link it into the interface's multicast list.
		 */
		in6m = (struct in6_multi *)
			malloc(sizeof(*in6m), M_IPMADDR, M_NOWAIT);
		if (in6m == NULL) {
			splx(s);
			*errorp = ENOBUFS;
			return(NULL);
		}
		in6m->in6m_addr = *maddr6;
		in6m->in6m_ifp = ifp;
		in6m->in6m_refcount = 1;
		IFP_TO_IA6(ifp, ia);
		if (ia == NULL) {
			free(in6m, M_IPMADDR);
			splx(s);
			*errorp = EADDRNOTAVAIL; /* appropriate? */
			return(NULL);
		}
		in6m->in6m_ia = ia;
		IFAREF(&ia->ia_ifa); /* gain a reference */
		LIST_INSERT_HEAD(&ia->ia6_multiaddrs, in6m, in6m_entry);

		/*
		 * Ask the network driver to update its multicast reception
		 * filter appropriately for the new address.
		 */
		bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
		ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifr.ifr_addr.sin6_family = AF_INET6;
		ifr.ifr_addr.sin6_addr = *maddr6;
		if (ifp->if_ioctl == NULL)
			*errorp = ENXIO; /* XXX: appropriate? */
		else
			*errorp = (*ifp->if_ioctl)(ifp, SIOCADDMULTI,
						    (caddr_t)&ifr);
		if (*errorp) {
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
			IFAFREE(&ia->ia_ifa);
			splx(s);
			return(NULL);
		}
		/*
		 * Let MLD6 know that we have joined a new IP6 multicast
		 * group.
		 */
		mld6_start_listening(in6m);
	}
	splx(s);
	return(in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti(in6m)
	struct in6_multi *in6m;
{
	struct	in6_ifreq ifr;
#ifdef __NetBSD__
	int	s = splsoftnet();
#else
	int	s = splnet();
#endif

	if (--in6m->in6m_refcount == 0) {
		/*
		 * No remaining claims to this record; let MLD6 know
		 * that we are leaving the multicast group.
		 */
		mld6_stop_listening(in6m);

		/*
		 * Unlink from list.
		 */
		LIST_REMOVE(in6m, in6m_entry);
		if (in6m->in6m_ia) {
			IFAFREE(&in6m->in6m_ia->ia_ifa); /* release reference */
		}

		/*
		 * Notify the network driver to update its multicast
		 * reception filter.
		 */
		bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
		ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifr.ifr_addr.sin6_family = AF_INET6;
		ifr.ifr_addr.sin6_addr = in6m->in6m_addr;
		(*in6m->in6m_ifp->if_ioctl)(in6m->in6m_ifp,
					    SIOCDELMULTI, (caddr_t)&ifr);
		free(in6m, M_IPMADDR);
	}
	splx(s);
}
#else /* not FreeBSD3 */
/*
 * Add an address to the list of IP6 multicast addresses for a
 * given interface.
 */
struct	in6_multi *
in6_addmulti(maddr6, ifp, errorp)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp;
{
	struct	in6_multi *in6m;
	struct sockaddr_in6 sin6;
	struct ifmultiaddr *ifma;
	int	s = splnet();

	*errorp = 0;

	/*
	 * Call generic routine to add membership or increment
	 * refcount.  It wants addresses in the form of a sockaddr,
	 * so we build one here (being careful to zero the unused bytes).
	 */
	bzero(&sin6, sizeof sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof sin6;
	sin6.sin6_addr = *maddr6;
	*errorp = if_addmulti(ifp, (struct sockaddr *)&sin6, &ifma);
	if (*errorp) {
		splx(s);
		return 0;
	}

	/*
	 * If ifma->ifma_protospec is null, then if_addmulti() created
	 * a new record.  Otherwise, we are done.
	 */
	if (ifma->ifma_protospec != 0)
		return ifma->ifma_protospec;

	/* XXX - if_addmulti uses M_WAITOK.  Can this really be called
	   at interrupt time?  If so, need to fix if_addmulti. XXX */
	in6m = (struct in6_multi *)malloc(sizeof(*in6m), M_IPMADDR, M_NOWAIT);
	if (in6m == NULL) {
		splx(s);
		return (NULL);
	}

	bzero(in6m, sizeof *in6m);
	in6m->in6m_addr = *maddr6;
	in6m->in6m_ifp = ifp;
	in6m->in6m_ifma = ifma;
	ifma->ifma_protospec = in6m;
	LIST_INSERT_HEAD(&in6_multihead, in6m, in6m_entry);

	/*
	 * Let MLD6 know that we have joined a new IP6 multicast
	 * group.
	 */
	mld6_start_listening(in6m);
	splx(s);
	return(in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti(in6m)
	struct in6_multi *in6m;
{
	struct ifmultiaddr *ifma = in6m->in6m_ifma;
	int	s = splnet();

	if (ifma->ifma_refcount == 1) {
		/*
		 * No remaining claims to this record; let MLD6 know
		 * that we are leaving the multicast group.
		 */
		mld6_stop_listening(in6m);
		ifma->ifma_protospec = 0;
		LIST_REMOVE(in6m, in6m_entry);
		free(in6m, M_IPMADDR);
	}
	/* XXX - should be separate API for when we have an ifma? */
	if_delmulti(ifma->ifma_ifp, ifma->ifma_addr);
	splx(s);
}
#endif /* not FreeBSD3 */

/*
 * Find an IPv6 interface link-local address specific to an interface.
 */
struct in6_ifaddr *
in6ifa_ifpforlinklocal(ifp, ignoreflags)
	struct ifnet *ifp;
	int ignoreflags;
{
	struct ifaddr *ifa;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa))) {
			if ((((struct in6_ifaddr *)ifa)->ia6_flags &
			     ignoreflags) != 0)
				continue;
			break;
		}
	}

	return((struct in6_ifaddr *)ifa);
}


/*
 * find the internet address corresponding to a given interface and address.
 */
struct in6_ifaddr *
in6ifa_ifpwithaddr(ifp, addr)
	struct ifnet *ifp;
	struct in6_addr *addr;
{
	struct ifaddr *ifa;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa)))
			break;
	}

	return((struct in6_ifaddr *)ifa);
}

/*
 * Convert IP6 address to printable (loggable) representation.
 */
static char digits[] = "0123456789abcdef";
static int ip6round = 0;
char *
ip6_sprintf(addr)
struct in6_addr *addr;
{
	static char ip6buf[8][48];
	int i;
	char *cp;
	u_short *a = (u_short *)addr;
	u_char *d;
	int dcolon = 0;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (u_char *)a;
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d++ & 0xf];
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return(ip6buf[ip6round]);
}

int
in6_localaddr(in6)
	struct in6_addr *in6;
{
	struct in6_ifaddr *ia;

	if (IN6_IS_ADDR_LOOPBACK(in6) || IN6_IS_ADDR_LINKLOCAL(in6))
		return 1;

	for (ia = in6_ifaddr; ia; ia = ia->ia_next)
		if (IN6_ARE_MASKED_ADDR_EQUAL(in6, &ia->ia_addr.sin6_addr,
					      &ia->ia_prefixmask.sin6_addr))
			return 1;

	return (0);
}

int
in6_is_addr_deprecated(sa6)
	struct sockaddr_in6 *sa6;
{
	struct in6_ifaddr *ia;

	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr,
				       &sa6->sin6_addr) &&
#ifdef SCOPEDROUTING
		    ia->ia_addr.sin6_scope_id == sa6->sin6_scope_id &&
#endif
		    (ia->ia6_flags & IN6_IFF_DEPRECATED) != 0)
			return(1); /* true */

		/* XXX: do we still have to go thru the rest of the list? */
	}

	return(0);		/* false */
}

/*
 * return length of part which dst and src are equal
 * hard coding...
 */
int
in6_matchlen(src, dst)
struct in6_addr *src, *dst;
{
	int match = 0;
	u_char *s = (u_char *)src, *d = (u_char *)dst;
	u_char *lim = s + 16, r;

	while (s < lim)
		if ((r = (*d++ ^ *s++)) != 0) {
			while (r < 128) {
				match++;
				r <<= 1;
			}
			break;
		} else
			match += 8;
	return match;
}

/* XXX: to be scope conscious */
int
in6_are_prefix_equal(p1, p2, len)
	struct in6_addr *p1, *p2;
	int len;
{
	int bytelen, bitlen;

	/* sanity check */
	if (0 > len || len > 128) {
		log(LOG_ERR, "in6_are_prefix_equal: invalid prefix length(%d)\n",
		    len);
		return(0);
	}

	bytelen = len / 8;
	bitlen = len % 8;

	if (bcmp(&p1->s6_addr, &p2->s6_addr, bytelen))
		return(0);
	if (p1->s6_addr[bytelen] >> (8 - bitlen) !=
	    p2->s6_addr[bytelen] >> (8 - bitlen))
		return(0);

	return(1);
}

void
in6_prefixlen2mask(maskp, len)
	struct in6_addr *maskp;
	int len;
{
	u_char maskarray[8] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
	int bytelen, bitlen, i;

	/* sanity check */
	if (0 > len || len > 128) {
		log(LOG_ERR, "in6_prefixlen2mask: invalid prefix length(%d)\n",
		    len);
		return;
	}

	bzero(maskp, sizeof(*maskp));
	bytelen = len / 8;
	bitlen = len % 8;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

/*
 * return the best address out of the same scope
 */
struct in6_ifaddr *
in6_ifawithscope(oifp, dst)
	struct ifnet *oifp;
	struct in6_addr *dst;
{
	int dst_scope =	in6_addrscope(dst), src_scope, best_scope = 0;
	int blen = -1;
	struct ifaddr *ifa;
	struct ifnet *ifp;
	struct in6_ifaddr *ifa_best = NULL;
	
	if (oifp == NULL) {
		printf("in6_ifawithscope: output interface is not specified\n");
		return(NULL);
	}

	/*
	 * We search for all addresses on all interfaces from the beginning.
	 * Comparing an interface with the outgoing interface will be done
	 * only at the final stage of tiebreaking.
	 */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = TAILQ_FIRST(&ifnet); ifp; ifp = TAILQ_NEXT(ifp, if_list))
#endif
	{
		/*
		 * We can never take an address that breaks the scope zone
		 * of the destination.
		 */
		if (in6_addr2scopeid(ifp, dst) != in6_addr2scopeid(oifp, dst))
			continue;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
		for (ifa = ifp->if_addrlist.tqh_first; ifa;
		     ifa = ifa->ifa_list.tqe_next)
#endif
		{
			int tlen = -1, dscopecmp, bscopecmp, matchcmp;

			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;

			src_scope = in6_addrscope(IFA_IN6(ifa));

			/*
			 * Don't use an address before completing DAD
			 * nor a duplicated address.
			 */
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_NOTREADY)
				continue;

			/* XXX: is there any case to allow anycasts? */
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_ANYCAST)
				continue;

			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_DETACHED)
				continue;

			/*
			 * If this is the first address we find,
			 * keep it anyway.
			 */
			if (ifa_best == NULL)
				goto replace;

			/*
			 * ifa_best is never NULL beyond this line except
			 * within the block labeled "replace".
			 */

			/*
			 * If ifa_best has a smaller scope than dst and
			 * the current address has a larger one than
			 * (or equal to) dst, always replace ifa_best.
			 * Also, if the current address has a smaller scope
			 * than dst, ignore it unless ifa_best also has a
			 * smaller scope.
			 */
			if (IN6_ARE_SCOPE_CMP(best_scope, dst_scope) < 0 &&
			    IN6_ARE_SCOPE_CMP(src_scope, dst_scope) >= 0)
				goto replace;
			if (IN6_ARE_SCOPE_CMP(src_scope, dst_scope) < 0 &&
			    IN6_ARE_SCOPE_CMP(best_scope, dst_scope) >= 0)
				continue;

			/*
			 * A deprecated address SHOULD NOT be used in new
			 * communications if an alternate (non-deprecated)
			 * address is available and has sufficient scope.
			 * RFC 2462, Section 5.5.4.
			 */
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_DEPRECATED) {
				/*
				 * Ignore any deprecated addresses if
				 * specified by configuration.
				 */
				if (!ip6_use_deprecated)
					continue;

				/*
				 * If we have already found a non-deprecated
				 * candidate, just ignore deprecated addresses.
				 */
				if ((ifa_best->ia6_flags & IN6_IFF_DEPRECATED)
				    == 0)
					continue;
			}

			/*
			 * A non-deprecated address is always preferred
			 * to a deprecated one regardless of scopes and
			 * address matching.
			 */
			if ((ifa_best->ia6_flags & IN6_IFF_DEPRECATED) &&
			    (((struct in6_ifaddr *)ifa)->ia6_flags &
			     IN6_IFF_DEPRECATED) == 0)
				goto replace;

			/*
			 * At this point, we have two cases:
			 * 1. we are looking at a non-deprecated address,
			 *    and ifa_best is also non-deprecated.
			 * 2. we are looking at a deprecated address,
			 *    and ifa_best is also deprecated.
			 * Also, we do not have to consider a case where
			 * the scope of if_best is larger(smaller) than dst and
			 * the scope of the current address is smaller(larger)
			 * than dst. Such a case has already been covered.
			 * Tiebreaking is done according to the following
			 * items:
			 * - the scope comparison between the address and
			 *   dst (dscopecmp)
			 * - the scope comparison between the address and
			 *   ifa_best (bscopecmp)
			 * - if the address match dst longer than ifa_best
			 *   (matchcmp)
			 * - if the address is on the outgoing I/F (outI/F)
			 *
			 * Roughly speaking, the selection policy is
			 * - the most important item is scope. The same scope
			 *   is best. Then search for a larger scope.
			 *   Smaller scopes are the last resort.
			 * - A deprecated address is chosen only when we have
			 *   no address that has an enough scope, but is
			 *   prefered to any addresses of smaller scopes.
			 * - Longest address match against dst is considered
			 *   only for addresses that has the same scope of dst.
			 * - If there is no other reasons to choose one,
			 *   addresses on the outgoing I/F are preferred.
			 *
			 * The precise decision table is as follows:
			 * dscopecmp bscopecmp matchcmp outI/F | replace?
			 *    !equal     equal      N/A    Yes |      Yes (1)
			 *    !equal     equal      N/A     No |       No (2)
			 *    larger    larger      N/A    N/A |       No (3)
			 *    larger   smaller      N/A    N/A |      Yes (4)
			 *   smaller    larger      N/A    N/A |      Yes (5)
			 *   smaller   smaller      N/A    N/A |       No (6)
			 *     equal   smaller      N/A    N/A |      Yes (7)
			 *     equal    larger       (already done)
			 *     equal     equal   larger    N/A |      Yes (8)
			 *     equal     equal  smaller    N/A |       No (9)
			 *     equal     equal    equal    Yes |      Yes (a)
			 *     eaual     eqaul    equal     No |       No (b)
			 */
			dscopecmp = IN6_ARE_SCOPE_CMP(src_scope, dst_scope);
			bscopecmp = IN6_ARE_SCOPE_CMP(src_scope, best_scope);

			if (dscopecmp && bscopecmp == 0) {
				if (oifp == ifp) /* (1) */
					goto replace;
				continue; /* (2) */
			}
			if (dscopecmp > 0) {
				if (bscopecmp > 0) /* (3) */
					continue;
				goto replace; /* (4) */
			}
			if (dscopecmp < 0) {
				if (bscopecmp > 0) /* (5) */
					goto replace;
				continue; /* (6) */
			}

			/* now dscopecmp must be 0 */
			if (bscopecmp < 0)
				goto replace; /* (7) */

			/*
			 * At last both dscopecmp and bscopecmp must be 0.
			 * We need address matching against dst for
			 * tiebreaking.
			 */
			tlen = in6_matchlen(IFA_IN6(ifa), dst);
			matchcmp = tlen - blen;
			if (matchcmp > 0) /* (8) */
				goto replace;
			if (matchcmp < 0) /* (9) */
				continue;
			if (oifp == ifp) /* (a) */
				goto replace;
			continue; /* (b) */

		  replace:
			ifa_best = (struct in6_ifaddr *)ifa;
			blen = tlen >= 0 ? tlen :
				in6_matchlen(IFA_IN6(ifa), dst);
			best_scope = in6_addrscope(&ifa_best->ia_addr.sin6_addr);
		}
	}

	/* count statistics for future improvements */
	if (ifa_best == NULL)
		ip6stat.ip6s_sources_none++;
	else {
		if (oifp == ifa_best->ia_ifp)
			ip6stat.ip6s_sources_sameif[best_scope]++;
		else
			ip6stat.ip6s_sources_otherif[best_scope]++;

		if (best_scope == dst_scope)
			ip6stat.ip6s_sources_samescope[best_scope]++;
		else
			ip6stat.ip6s_sources_otherscope[best_scope]++;

		if ((ifa_best->ia6_flags & IN6_IFF_DEPRECATED) != 0)
			ip6stat.ip6s_sources_deprecated[best_scope]++;
	}

	return(ifa_best);
}

/*
 * return the best address out of the same scope. if no address was
 * found, return the first valid address from designated IF.
 */
struct in6_ifaddr *
in6_ifawithifp(ifp, dst)
	struct ifnet *ifp;
	struct in6_addr *dst;
{
	int dst_scope =	in6_addrscope(dst), blen = -1, tlen;
	struct ifaddr *ifa;
	struct in6_ifaddr *besta = 0;
	struct in6_ifaddr *dep[2];	/*last-resort: deprecated*/

	dep[0] = dep[1] = NULL;

#if 0
#ifdef MIP6
	/*
	 * This is needed to assure that the Home Address is used for
	 * outgoing packets when not at home. We can't choose any other
	 * address if we want to keep connections up during movement.
	 */
	if (mip6_get_home_prefix_hook) {	/* Only Mobile Node */
		struct nd_prefix *pr;
		if ((pr = (*mip6_get_home_prefix_hook)()) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr))
		{
			if (dst_scope == in6_addrscope(&pr->ndpr_addr)) {
#ifdef MIP6_DEBUG
				/* Noisy but useful */
				mip6_debug("%s: Local address %s is chosen "
					   "for pcb to dest %s.\n",
					   __FUNCTION__,
					   ip6_sprintf(&pr->ndpr_addr),
					   ip6_sprintf(dst));
#endif
				return(in6ifa_ifpwithaddr(ifp, &pr->ndpr_addr));
			}
		}
	}
#endif /* MIP6 */
#endif /* 0 */

	/*
	 * We first look for addresses in the same scope.
	 * If there is one, return it.
	 * If two or more, return one which matches the dst longest.
	 * If none, return one of global addresses assigned other ifs.
	 */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_ANYCAST)
			continue; /* XXX: is there any case to allow anycast? */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_NOTREADY)
			continue; /* don't use this interface */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DETACHED)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
			if (ip6_use_deprecated)
				dep[0] = (struct in6_ifaddr *)ifa;
			continue;
		}

		if (dst_scope == in6_addrscope(IFA_IN6(ifa))) {
			/*
			 * call in6_matchlen() as few as possible
			 */
			if (besta) {
				if (blen == -1)
					blen = in6_matchlen(&besta->ia_addr.sin6_addr, dst);
				tlen = in6_matchlen(IFA_IN6(ifa), dst);
				if (tlen > blen) {
					blen = tlen;
					besta = (struct in6_ifaddr *)ifa;
				}
			} else
				besta = (struct in6_ifaddr *)ifa;
		}
	}
	if (besta)
		return(besta);

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_ANYCAST)
			continue; /* XXX: is there any case to allow anycast? */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_NOTREADY)
			continue; /* don't use this interface */
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DETACHED)
			continue;
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
			if (ip6_use_deprecated)
				dep[1] = (struct in6_ifaddr *)ifa;
			continue;
		}

		return (struct in6_ifaddr *)ifa;
	}

	/* use the last-resort values, that are, deprecated addresses */
	if (dep[0])
		return dep[0];
	if (dep[1])
		return dep[1];

	return NULL;
}

/*
 * perform DAD when interface becomes IFF_UP.
 */
void
in6_if_up(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ifa;
	struct in6_ifaddr *ia;
	int dad_delay;		/* delay ticks before DAD output */

	/*
	 * special cases, like 6to4, are handled in in6_ifattach
	 */
	in6_ifattach(ifp, NULL);

	dad_delay = 0;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		ia = (struct in6_ifaddr *)ifa;
		if (ia->ia6_flags & IN6_IFF_TENTATIVE)
			nd6_dad_start(ifa, &dad_delay);
	}
}

/*
 * Calculate max IPv6 MTU through all the interfaces and store it
 * to in6_maxmtu.
 */
void
in6_setmaxmtu()
{
	unsigned long maxmtu = 0;
	struct ifnet *ifp;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = TAILQ_FIRST(&ifnet); ifp; ifp = TAILQ_NEXT(ifp, if_list))
#endif
	{
		if ((ifp->if_flags & IFF_LOOPBACK) == 0 &&
		    nd_ifinfo[ifp->if_index].linkmtu > maxmtu)
			maxmtu =  nd_ifinfo[ifp->if_index].linkmtu;
	}
	if (maxmtu)	/* update only when maxmtu is positive */
		in6_maxmtu = maxmtu;
}

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
/*
 * Convert sockaddr_in6 to sockaddr_in. Original sockaddr_in6 must be
 * v4 mapped addr or v4 compat addr
 */
void
in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin, sizeof(*sin));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	sin->sin_addr.s_addr = sin6->sin6_addr.s6_addr32[3];	
}

/* Convert sockaddr_in to sockaddr_in6 in v4 mapped addr format. */
void
in6_sin_2_v4mapsin6(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	sin6->sin6_addr.s6_addr32[0] = 0;
	sin6->sin6_addr.s6_addr32[1] = 0;
	sin6->sin6_addr.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
	sin6->sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;
}

/* Convert sockaddr_in6 into sockaddr_in. */
void
in6_sin6_2_sin_in_sock(struct sockaddr *nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 sin6;

	/*
	 * Save original sockaddr_in6 addr and convert it
	 * to sockaddr_in.
	 */
	sin6 = *(struct sockaddr_in6 *)nam;
	sin_p = (struct sockaddr_in *)nam;
	in6_sin6_2_sin(sin_p, &sin6);
}

/* Convert sockaddr_in into sockaddr_in6 in v4 mapped addr format. */
void
in6_sin_2_v4mapsin6_in_sock(struct sockaddr **nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 *sin6_p;

	MALLOC(sin6_p, struct sockaddr_in6 *, sizeof *sin6_p, M_SONAME,
	       M_WAITOK);
	sin_p = (struct sockaddr_in *)*nam;
	in6_sin_2_v4mapsin6(sin_p, sin6_p);
	FREE(*nam, M_SONAME);
	*nam = (struct sockaddr *)sin6_p;
}
#endif /*freebsd3*/

#ifdef MEASURE_PERFORMANCE
#define IN6_MAXADDRHASH 1000
#ifndef	IN6_ADDRHASH
#ifndef INET6_SERVER
#define	IN6_ADDRHASH	23
#else
#define	IN6_ADDRHASH	997
#endif
#endif

static struct in6hash in6h_hash_any = { NULL, IN6ADDR_ANY_INIT, NULL, 0 };
struct in6hash *in6hash[IN6_MAXADDRHASH];/* hash buckets for local IPv6 addrs */
int in6_nhash = IN6_ADDRHASH;		/* number of hash buckets for addrs */
int in6_hash_nullhit;

#define HASH6(in6) ((in6)->s6_addr32[0]^(in6)->s6_addr32[1]^\
	(in6)->s6_addr32[2]^(in6)->s6_addr32[3])

/*
 * Initialize the hash by adding entries for IN6ADDR_ANY
 */
void
in6h_hashinit()
{
	in6h_addhash(&in6h_hash_any);
}

void
in6h_addifa(ia)
	struct in6_ifaddr *ia;
{
	if (ia->ia6_hash.in6h_ifa == NULL)
		ia->ia6_hash.in6h_ifa = ia;

	ia->ia6_hash.in6h_addr = IA6_SIN6(ia)->sin6_addr; /* scope? */
	if (IN6_IS_ADDR_UNSPECIFIED(&ia->ia6_hash.in6h_addr))
		return;
	in6h_addhash(&ia->ia6_hash);
}

/*
 * Rebuild the hash when any interface addresses have been changed.
 * Since this should happen infrequently we remove all the interfaces
 * from the hash and add them all back.  This insures that the order
 * of addresses in the hash is consistent.
 */
void
in6h_rebuild(newhashsiz)
	int newhashsiz;		/* can be 0, meaning unchange the size */
{
	struct in6_ifaddr *ia;

	if (newhashsiz > IN6_MAXADDRHASH)
		return;		/* XXX invalid */

	for (ia = in6_ifaddr; ia != NULL; ia = ia->ia_next)
		in6h_delifa(ia);

	if (newhashsiz)
		in6_nhash = newhashsiz;

	for (ia = in6_ifaddr; ia != NULL; ia = ia->ia_next)
		in6h_addifa(ia);
}

/* Remove hash entries for local address on an in6_ifaddr. */
void
in6h_delifa(ia)
	struct in6_ifaddr *ia;
{
	if (IN6_IS_ADDR_UNSPECIFIED(&ia->ia6_hash.in6h_addr))
		return;
	in6h_delhash(&ia->ia6_hash);
	ia->ia6_hash.in6h_addr = in6addr_any;
}

static void
in6h_addhash(ih)
	struct in6hash *ih;
{
	struct in6hash **prev;

	/* Add to tail of hash list, as address is at end of address list */
	for (prev = &in6hash[HASH6(&ih->in6h_addr) % in6_nhash]; *prev;
	     prev = &((*prev)->in6h_next)) {
		/* however, we always prefer non-global addresses */
		if (IN6_IS_ADDR_LINKLOCAL(&(*prev)->in6h_addr))
			break;
	}
	ih->in6h_next = *prev;
	*prev = ih;
}

static void
in6h_delhash(ih)
	struct in6hash *ih;
{
	struct in6hash **prev;

	for (prev = &in6hash[HASH6(&ih->in6h_addr) % in6_nhash];
	     *prev != ih; prev = &((*prev)->in6h_next)) {
#ifdef DEBUG
		if (*prev == NULL)
			panic("in6h_delhash: lost entry");
#endif
	}
	*prev = (*prev)->in6h_next;
}

/*
 * Look up hash structure for specified IP address
 * and (optional) interface; matches any interface
 * if ifp is null, or this address is not associated
 * with the specified interface.
 */
struct in6hash *
in6h_lookup(addr, ifp) 
	struct in6_addr *addr;
	struct ifnet *ifp;
{
	struct in6hash *ih, *maybe_ih = NULL;

	/* just for measurement */
	if ((ih = in6hash[HASH6(addr) % in6_nhash]) == NULL)
		in6_hash_nullhit++;

	for (; ih; ih = ih->in6h_next) {
		if (IN6_ARE_ADDR_EQUAL(&ih->in6h_addr, addr)) {
			ih->in6h_hit++;

			if (ih->in6h_ifa == NULL ||
			    ih->in6h_ifa->ia_ifp == ifp || ifp == NULL)
				return (ih);
			if (maybe_ih == NULL)
				maybe_ih = ih;
		}
		else
			ih->in6h_miss++;
	}
	return (maybe_ih);
}
#endif /* MEASURE_PERFORMANCE */
