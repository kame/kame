/*	$KAME: in6_prefix.c,v 1.48 2001/07/24 08:37:55 itojun Exp $	*/

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

#include <sys/param.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/ioctl.h>
#endif
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
#include <sys/proc.h>
#endif

#include <net/if.h>
#ifdef NEW_STRUCT_ROUTE
#include <net/route.h>
#endif

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/in6_prefix.h>
#include <netinet6/ip6_var.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static MALLOC_DEFINE(M_IP6RR, "ip6rr", "IPv6 Router Renumbering Prefix");
static MALLOC_DEFINE(M_RR_ADDR, "rp_addr", "IPv6 Router Renumbering Ifid");
#endif

struct rr_prhead rr_prefix;

#ifdef __NetBSD__
struct callout in6_rr_timer_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout in6_rr_timer_ch;
#elif defined(__OpenBSD__)
struct timeout in6_rr_timer_ch;
#endif

#include <net/net_osdep.h>

static void	rp_remove __P((struct rr_prefix *rpp));

static int
rr_are_ifid_equal(struct in6_addr *ii1, struct in6_addr *ii2, int ii_len)
{
	int ii_bytelen, ii_bitlen;
	int p_bytelen, p_bitlen;

	/* sanity check */
	if (1 > ii_len ||
	    ii_len > 124) { /* as RFC2373, prefix is at least 4 bit */
		log(LOG_ERR, "rr_are_ifid_equal: invalid ifid length(%d)\n",
		    ii_len);
		return(0);
	}

	ii_bytelen = ii_len / 8;
	ii_bitlen = ii_len % 8;

	p_bytelen = sizeof(struct in6_addr) - ii_bytelen - 1;
	p_bitlen = 8 - ii_bitlen;

	if (bcmp(ii1->s6_addr + p_bytelen + 1, ii2->s6_addr + p_bytelen + 1,
		 ii_bytelen))
		return(0);
	if (((ii1->s6_addr[p_bytelen] << p_bitlen) & 0xff) !=
	    ((ii2->s6_addr[p_bytelen] << p_bitlen) & 0xff))
		return(0);

	return(1);
}

static struct rp_addr *
search_ifidwithprefix(struct rr_prefix *rpp, struct in6_addr *ifid)
{
	struct rp_addr *rap;

#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	LIST_FOREACH(rap, &rpp->rp_addrhead, ra_entry)
#else
	for (rap = rpp->rp_addrhead.lh_first; rap != NULL;
	     rap = rap->ra_entry.le_next)
#endif
	{
		if (rr_are_ifid_equal(ifid, &rap->ra_ifid,
				      (sizeof(struct in6_addr) << 3) -
				      rpp->rp_plen))
			break;
	}
	return rap;
}

void
in6_prefix_remove_ifid(int iilen, struct in6_ifaddr *ia)
{
	struct rp_addr *rap;

	if (ia->ia6_ifpr == NULL)
		return;
	rap = search_ifidwithprefix(ifpr2rp(ia->ia6_ifpr), IA6_IN6(ia));
	if (rap != NULL) {
#ifdef __NetBSD__
		int s = splsoftnet();
#else
		int s = splnet();
#endif
		LIST_REMOVE(rap, ra_entry);
		splx(s);
		if (rap->ra_addr)
			IFAFREE(&rap->ra_addr->ia_ifa);
		free(rap, M_RR_ADDR);
	}

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	if (LIST_EMPTY(&ifpr2rp(ia->ia6_ifpr)->rp_addrhead))
#else
	if (LIST_FIRST(&ifpr2rp(ia->ia6_ifpr)->rp_addrhead) == NULL)
#endif
		rp_remove(ifpr2rp(ia->ia6_ifpr));
}

void
in6_purgeprefix(ifp)
	struct ifnet *ifp;
{
	struct ifprefix *ifpr, *nextifpr;

	/* delete prefixes before ifnet goes away */
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	for (ifpr = TAILQ_FIRST(&ifp->if_prefixhead); ifpr;
	     ifpr = nextifpr)
#else
	for (ifpr = ifp->if_prefixlist; ifpr; ifpr = nextifpr)
#endif
	{
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
		nextifpr = TAILQ_NEXT(ifpr, ifpr_list);
#else
		nextifpr = ifpr->ifpr_next;
#endif
		if (ifpr->ifpr_prefix->sa_family != AF_INET6 ||
		    ifpr->ifpr_type != IN6_PREFIX_RR)
 			continue;
		(void)delete_each_prefix(ifpr2rp(ifpr), PR_ORIG_KERNEL);
	}
}

static void
rp_remove(struct rr_prefix *rpp)
{
	int s;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* unlink rp_entry from if_prefixlist */
	{
		struct ifnet *ifp = rpp->rp_ifp;
		struct ifprefix *ifpr;

#if defined(__FreeBSD__) && __FreeBSD__ >= 4
		if ((ifpr = TAILQ_FIRST(&ifp->if_prefixhead)) == rp2ifpr(rpp))
			TAILQ_FIRST(&ifp->if_prefixhead) =
				TAILQ_NEXT(ifpr, ifpr_list);
		else {
			while (TAILQ_NEXT(ifpr, ifpr_list) != NULL &&
			       (TAILQ_NEXT(ifpr, ifpr_list) != rp2ifpr(rpp)))
				ifpr = TAILQ_NEXT(ifpr, ifpr_list);
			if (TAILQ_NEXT(ifpr, ifpr_list))
				TAILQ_NEXT(ifpr, ifpr_list) =
					TAILQ_NEXT(rp2ifpr(rpp), ifpr_list);
 			else
 				printf("Couldn't unlink rr_prefix from ifp\n");
		}
#else
		if ((ifpr = ifp->if_prefixlist) == rp2ifpr(rpp))
			ifp->if_prefixlist = ifpr->ifpr_next;
		else {
			while (ifpr->ifpr_next &&
			       (ifpr->ifpr_next != rp2ifpr(rpp)))
				ifpr = ifpr->ifpr_next;
			if (ifpr->ifpr_next)
				ifpr->ifpr_next = rp2ifpr(rpp)->ifpr_next;
			else
				printf("Couldn't unlink rr_prefix from ifp\n");
		}
#endif
	}
	/* unlink rp_entry from rr_prefix list */
	LIST_REMOVE(rpp, rp_entry);
	splx(s);
	free(rpp, M_IP6RR);
}

static void
unprefer_prefix(struct rr_prefix *rpp)
{
	struct rp_addr *rap;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	for (rap = rpp->rp_addrhead.lh_first; rap != NULL;
	     rap = rap->ra_entry.le_next) {
		if (rap->ra_addr == NULL)
			continue;
		rap->ra_addr->ia6_lifetime.ia6t_preferred = time_second;
		rap->ra_addr->ia6_lifetime.ia6t_pltime = 0;
	}
}

int
delete_each_prefix(struct rr_prefix *rpp, u_char origin)
{
	int error = 0;

	if (rpp->rp_origin > origin)
		return(EPERM);

	while (rpp->rp_addrhead.lh_first != NULL) {
		struct rp_addr *rap;
		int s;

#ifdef __NetBSD__
		s = splsoftnet();
#else
		s = splnet();
#endif
		rap = LIST_FIRST(&rpp->rp_addrhead);
		if (rap == NULL) {
			splx(s);
			break;
		}
		LIST_REMOVE(rap, ra_entry);
		splx(s);
		if (rap->ra_addr == NULL) {
			free(rap, M_RR_ADDR);
			continue;
		}
		rap->ra_addr->ia6_ifpr = NULL;

		in6_purgeaddr(&rap->ra_addr->ia_ifa);
		IFAFREE(&rap->ra_addr->ia_ifa);
		free(rap, M_RR_ADDR);
	}
	rp_remove(rpp);

	return error;
}

void
in6_rr_timer(void *ignored_arg)
{
	int s;
	struct rr_prefix *rpp;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&in6_rr_timer_ch, ip6_rr_prune * hz,
	    in6_rr_timer, NULL);
#elif defined(__OpenBSD__)
	timeout_set(&in6_rr_timer_ch, in6_rr_timer, NULL);
	timeout_add(&in6_rr_timer_ch, ip6_rr_prune * hz);
#else
	timeout(in6_rr_timer, (caddr_t)0, ip6_rr_prune * hz);
#endif

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* expire */
	rpp = LIST_FIRST(&rr_prefix);
	while (rpp) {
		if (rpp->rp_expire && rpp->rp_expire < time_second) {
			struct rr_prefix *next_rpp;

			next_rpp = LIST_NEXT(rpp, rp_entry);
			delete_each_prefix(rpp, PR_ORIG_KERNEL);
			rpp = next_rpp;
			continue;
		}
		if (rpp->rp_preferred && rpp->rp_preferred < time_second)
			unprefer_prefix(rpp);
		rpp = LIST_NEXT(rpp, rp_entry);
	}
	splx(s);
}
