/*	$KAME: in6_src.c,v 1.55 2001/08/16 14:13:48 jinmei Exp $	*/

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
 *	@(#)in_pcb.c	8.2 (Berkeley) 1/4/94
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 4)
#include <sys/ioctl.h>
#endif
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#if !(defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802))
#include <netinet6/in6_pcb.h>
#endif
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#ifdef ENABLE_DEFAULT_SCOPE
#include <netinet6/scope6_var.h> 
#endif

#ifdef MIP6
#include <netinet6/mip6.h>
#endif /* MIP6 */

#include <net/net_osdep.h>

#if !defined(__bsdi__) && !defined(__OpenBSD__)
#include "loop.h"
#endif
#if defined(__NetBSD__)
extern struct ifnet loif[NLOOP];
#endif

int ip6_prefer_tempaddr = 0;

/*
 * Return an IPv6 address, which is the most appropriate for a given
 * destination and user specified options.
 * If necessary, this function lookups the routing table and returns
 * an entry to the caller for later use.
 */
#define REPLACE(r) do {\
	ip6stat.ip6s_sources_rule[(r)]++; \
 	goto replace; \
} while(0)
#define NEXT(r) do {\
	ip6stat.ip6s_sources_rule[(r)]++; \
 	goto next; 		/* XXX: we can't use 'continue' here */ \
} while(0)
#define BREAK(r) do { \
	ip6stat.ip6s_sources_rule[(r)]++; \
 	goto out; 		/* XXX: we can't use 'break' here */ \
} while(0)

struct in6_addr *
in6_selectsrc(dstsock, opts, mopts, ro, laddr, errorp)
	struct sockaddr_in6 *dstsock;
	struct ip6_pktopts *opts;
	struct ip6_moptions *mopts;
#ifdef NEW_STRUCT_ROUTE
	struct route *ro;
#else
	struct route_in6 *ro;
#endif
	struct in6_addr *laddr;
	int *errorp;
{
	struct in6_addr *dst;
	struct ifnet *ifp = NULL;
	struct in6_ifaddr *ia = NULL, *ia_best = NULL;
	struct in6_pktinfo *pi = NULL;
	struct rtentry *rt = NULL;
	int clone;
	int dst_scope = -1, best_scope = -1, best_matchlen = -1;

	dst = &dstsock->sin6_addr;
	*errorp = 0;

	/*
	 * If the source address is explicitly specified by the caller,
	 * or the socket is already bound, just use the address.
	 * ip6_output() will check scope validity.
	 */
	if (opts && (pi = opts->ip6po_pktinfo) &&
	    !IN6_IS_ADDR_UNSPECIFIED(&pi->ipi6_addr)) {
		return(&pi->ipi6_addr);
	}
	if (laddr && !IN6_IS_ADDR_UNSPECIFIED(laddr))
		return(laddr);

#ifdef MIP6
	/*
	 * XXX
	 * how to select a src address when we want to use home
	 * address when we are out and using mobile ip functionality.
	 */
	{
		struct hif_softc *sc;
		struct hif_subnet *hs;
		struct mip6_subnet *ms;
		struct mip6_subnet_prefix *mspfx;
		struct mip6_prefix *mpfx;
		struct mip6_bu *mbu;
		
		/* find the address that is currently at home. */
		TAILQ_FOREACH(sc, &hif_softc_list, hif_entry) {
			if (sc->hif_location != HIF_LOCATION_HOME)
				continue;

			hs = TAILQ_FIRST(&sc->hif_hs_list_home);
			if ((hs == NULL) || ((ms = hs->hs_ms) == NULL)) {
				/* must not happen. */
				continue;
			}
			mspfx = TAILQ_FIRST(&ms->ms_mspfx_list);
			if ((mspfx == NULL)
			    || ((mpfx = mspfx->mspfx_mpfx) == NULL)) {
				/* must not happen. */
				continue;
			}
			/*
			 * found a home address that is currently at home.
			 */
			return (&mpfx->mpfx_haddr);
		}

		/*
		 * find a home address that has been registered to its
		 * home agent.
		 */
		TAILQ_FOREACH(sc, &hif_softc_list, hif_entry) {
			LIST_FOREACH(mbu, &sc->hif_bu_list, mbu_entry) {
				if (mbu->mbu_reg_state
				    == MIP6_BU_REG_STATE_REG) {
					return (&mbu->mbu_haddr);
				}
			}
		}
		/*
		 * there is no home address suitable. fall through...
		 */
	}
#endif /* MIP6 */
	/*
	 * If the address is not specified, choose the best one based on
	 * the outgoing interface and the destination address.
	 */
	/* get the outgoing interface */
	clone = IN6_IS_ADDR_MULTICAST(&dstsock->sin6_addr) ? 0 : 1;
	if ((*errorp = in6_selectroute(dstsock, opts, mopts,
				       ro, &ifp, &rt, clone)) != 0) {
		return(NULL);
	}
	/*
	 * Adjust the "outgoing" interface.  If we're going to loop the packet
	 * back to ourselves, the ifp would be the loopback interface.
	 * However, we'd rather to know the interface associated to the
	 * destination address (which should probably be one of our own
	 * addresses.)
	 */
	if (rt && rt->rt_ifa && rt->rt_ifa->ifa_ifp)
		ifp = rt->rt_ifa->ifa_ifp;

#ifdef DIAGNOSTIC
	if (ifp == NULL)	/* this should not happen */
		panic("in6_selectsrc: NULL ifp");
#endif

	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		int new_scope = -1, new_matchlen = -1;
		int srczone, dstzone;
		struct ifnet *ifp1 = ia->ia_ifp;

		/*
		 * We'll never take an address that breaks the scope zone
		 * of the destination.  We also skip an address if its zone
		 * does not contain the outgoing interface.
		 * XXX: we should probably use sin6_scope_id here.
		 */
		if ((dstzone = in6_addr2zoneid(ifp1, dst)) < 0 ||
		    dstzone != in6_addr2zoneid(ifp, dst)) {
			continue;
		}
		if ((srczone = in6_addr2zoneid(ifp1, &ia->ia_addr.sin6_addr))
		    < 0 ||
		    srczone != in6_addr2zoneid(ifp, &ia->ia_addr.sin6_addr)) {
			continue;
		}

		/* avoid unusable addresses */
		if ((ia->ia6_flags &
		     (IN6_IFF_NOTREADY | IN6_IFF_ANYCAST | IN6_IFF_DETACHED))) {
				continue;
		}
		if (!ip6_use_deprecated && IFA6_IS_DEPRECATED(ia))
			continue;

		/* Rule 1: Prefer same address */
		if (IN6_ARE_ADDR_EQUAL(dst, &ia->ia_addr.sin6_addr)) {
			ia_best = ia;
			BREAK(1); /* there should be no better candidate */
		}

		if (ia_best == NULL)
			REPLACE(0);

		/* Rule 2: Prefer appropriate scope */
		if (dst_scope < 0)
			dst_scope = in6_addrscope(dst);
		new_scope = in6_addrscope(&ia->ia_addr.sin6_addr);
		if (IN6_ARE_SCOPE_CMP(best_scope, new_scope) < 0) {
			if (IN6_ARE_SCOPE_CMP(best_scope, dst_scope) < 0)
				REPLACE(2);
			NEXT(2);
		} else if (IN6_ARE_SCOPE_CMP(new_scope, best_scope) < 0) {
			if (IN6_ARE_SCOPE_CMP(new_scope, dst_scope) < 0)
				REPLACE(2);
			NEXT(2);
		}

		/*
		 * Rule 3: Avoid deprecated addresses.  Note that the case of
		 * !ip6_use_deprecated is already rejected above.
		 */
		if (!IFA6_IS_DEPRECATED(ia_best) && IFA6_IS_DEPRECATED(ia))
			NEXT(3);
		if (IFA6_IS_DEPRECATED(ia_best) && !IFA6_IS_DEPRECATED(ia))
			REPLACE(3);

		/* Rule 4: Prefer home addresses */
		/*
		 * XXX: This is a TODO.  We should probably merge the MIP6
		 * case above.
		 */

		/* Rule 5: Prefer outgoing interface */
		if (ia_best->ia_ifp == ifp && ia->ia_ifp != ifp)
			NEXT(5);
		if (ia_best->ia_ifp != ifp && ia->ia_ifp == ifp)
			REPLACE(5);

		/* Rule 6: Prefer matching label:  XXX not yet */

		/* Rule 7: Prefer public addresses */
		if (!(ia_best->ia6_flags & IN6_IFF_TEMPORARY) &&
		    (ia->ia6_flags & IN6_IFF_TEMPORARY)) {
			if (ip6_prefer_tempaddr)
				REPLACE(7);
			else
				NEXT(7);
		}
		if (!(ia_best->ia6_flags & IN6_IFF_TEMPORARY) &&
		    (ia->ia6_flags & IN6_IFF_TEMPORARY)) {
			if (ip6_prefer_tempaddr)
				REPLACE(7);
			else
				NEXT(7);
		}

		/* Rule 8: Use longest matching prefix. */
		new_matchlen = in6_matchlen(&ia->ia_addr.sin6_addr, dst);
		if (best_matchlen < new_matchlen)
			REPLACE(8);

		/*
		 * Last resort: just keep the current candidate.
		 * Or, do we need more rules?
		 */
		continue;

	  replace:
		ia_best = ia;
		best_scope = (new_scope >= 0 ? new_scope :
			      in6_addrscope(&ia_best->ia_addr.sin6_addr));
		best_matchlen = (new_matchlen >= 0 ? new_matchlen :
				 in6_matchlen(&ia_best->ia_addr.sin6_addr,
					      dst));

	  next:
		continue;

	  out:
		break;
	}

	if ((ia = ia_best) == NULL) {
		*errorp = EADDRNOTAVAIL;
		return(NULL);
	}
	
	return(&ia->ia_addr.sin6_addr);
}
#undef REPLACE
#undef BREAK
#undef NEXT

int
in6_selectroute(dstsock, opts, mopts, ro, retifp, retrt, clone)
	struct sockaddr_in6 *dstsock;
	struct ip6_pktopts *opts;
	struct ip6_moptions *mopts;
#ifdef NEW_STRUCT_ROUTE
	struct route *ro;
#else
	struct route_in6 *ro;
#endif
	struct ifnet **retifp;
	struct rtentry **retrt;
	int clone;		/* meaningful only for bsdi and freebsd. */
{
	int error = 0;
	struct ifnet *ifp = NULL;
	struct rtentry *rt = NULL;
	struct sockaddr_in6 *sin6_next;
	struct in6_pktinfo *pi = NULL;
	struct in6_addr *dst = &dstsock->sin6_addr;

	/* If the caller specify the outgoing interface explicitly, use it. */
	if (opts && (pi = opts->ip6po_pktinfo) != NULL && pi->ipi6_ifindex) {
		/* XXX boundary check is assumed to be already done. */
		ifp = ifindex2ifnet[pi->ipi6_ifindex];
		if (ifp != NULL &&
		    (retrt == NULL || IN6_IS_ADDR_MULTICAST(dst))) {
			/*
			 * we do not have to check nor get the route for
			 * multicast.
			 */
			goto done;
		} else
			goto getroute;
	}

	/*
	 * If the destination address is a multicast address and the outgoing
	 * interface for the address is specified by the caller, use it.
	 */
	if (IN6_IS_ADDR_MULTICAST(dst) &&
	    mopts != NULL && (ifp = mopts->im6o_multicast_ifp) != NULL) {
		goto done; /* we do not need a route for multicast. */
	}

  getroute:
	/*
	 * If the next hop address for the packet is specified by the caller,
	 * use it as the gateway.
	 */
	if (opts && opts->ip6po_nexthop) {
#ifdef NEW_STRUCT_ROUTE
		struct route *ron;
#else
		struct route_in6 *ron;
#endif

		sin6_next = satosin6(opts->ip6po_nexthop);

		/* at this moment, we only support AF_INET6 next hops */
		if (sin6_next->sin6_family != AF_INET6) {
			error = EAFNOSUPPORT; /* or should we proceed? */
			goto done;
		}

		/*
		 * If the next hop is an IPv6 address, then the node identified
		 * by that address must be a neighbor of the sending host.
		 */
		ron = &opts->ip6po_nextroute;
		if ((ron->ro_rt &&
		     (ron->ro_rt->rt_flags & (RTF_UP | RTF_LLINFO)) !=
		     (RTF_UP | RTF_LLINFO)) ||
		    !SA6_ARE_ADDR_EQUAL(satosin6(&ron->ro_dst), sin6_next)) {
			if (ron->ro_rt) {
				RTFREE(ron->ro_rt);
				ron->ro_rt = NULL;
			}
			*satosin6(&ron->ro_dst) = *sin6_next;
		}
		if (ron->ro_rt == NULL) {
			rtalloc((struct route *)ron); /* multi path case? */
			if (ron->ro_rt == NULL ||
			    !(ron->ro_rt->rt_flags & RTF_LLINFO)) {
				if (ron->ro_rt) {
					RTFREE(ron->ro_rt);
					ron->ro_rt = NULL;
				}
				return(EHOSTUNREACH);
			}
		}
		rt = ron->ro_rt;
		ifp = rt->rt_ifp;

		/*
		 * When cloning is required, try to allocate a route to the
		 * destination so that the caller can store path MTU
		 * information.
		 */
		if (!clone)
			goto done;
	}

	/*
	 * Use a cached route if it exists and is valid, else try to allocate
	 * a new one.
	 */
	if (ro) {
		int newroute = 0;

		if (ro->ro_rt &&
		    !IN6_ARE_ADDR_EQUAL(&satosin6(&ro->ro_dst)->sin6_addr,
					dst)) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)NULL;
		}
		if (ro->ro_rt == (struct rtentry *)NULL) {
			struct sockaddr_in6 *sa6;

			/* No route yet, so try to acquire one */
			newroute = 1;
			bzero(&ro->ro_dst, sizeof(struct sockaddr_in6));
			sa6 = (struct sockaddr_in6 *)&ro->ro_dst;
			sa6->sin6_family = AF_INET6;
			sa6->sin6_len = sizeof(struct sockaddr_in6);
			sa6->sin6_addr = *dst;
#ifdef SCOPEDROUTING
			sa6->sin6_scope_id = dstsock->sin6_scope_id;
#endif
			if (clone) {
#ifdef __bsdi__
				rtcalloc((struct route *)ro);
#else  /* !bsdi */
#ifdef RADIX_MPATH
				rtalloc_mpath((struct route *)ro,
				    ntohl(dstsock->sin6_addr.s6_addr32[3]));
#else
				rtalloc((struct route *)ro);
#endif /* RADIX_MPATH */
#endif /* bsdi */
			} else {
#ifdef __FreeBSD__
				ro->ro_rt = rtalloc1(&((struct route *)ro)
						     ->ro_dst, NULL, 0UL);
#else
#ifdef RADIX_MPATH
				rtalloc_mpath((struct route *)ro,
				    ntohl(dstsock->sin6_addr.s6_addr32[3]));
#else
				ro->ro_rt = rtalloc1(&((struct route *)ro)
						     ->ro_dst, NULL);
#endif /* RADIX_MPATH */
#endif /* __FreeBSD__ */
			}
		}

		/*
		 * do not care about the result if we have the nexthop
		 * explicitly specified.
		 */
		if (opts && opts->ip6po_nexthop)
			goto done;

		if (ro->ro_rt) {
			ifp = ro->ro_rt->rt_ifp;

			if (ifp == NULL) { /* can this really happen? */
				RTFREE(ro->ro_rt);
				ro->ro_rt = NULL;
			}
		}
		if (ro->ro_rt == NULL)
			error = EHOSTUNREACH;
		rt = ro->ro_rt;

		/*
		 * Check if the outgoing interface conflicts with
		 * the interface specified by ipi6_ifindex (if specified).
		 * Note that loopback interface is always okay.
		 * (this may happen when we are sending a packet to one of
		 *  our own addresses.)
		 */
		if (opts && opts->ip6po_pktinfo
		    && opts->ip6po_pktinfo->ipi6_ifindex) {
			if (!(ifp->if_flags & IFF_LOOPBACK) &&
			    ifp->if_index !=
			    opts->ip6po_pktinfo->ipi6_ifindex) {
				return(EHOSTUNREACH);
			}
		}
	}

  done:
	if (ifp == NULL) {
		return(error);
	}
	if (retifp != NULL)
		*retifp = ifp;
	if (retrt != NULL)
		*retrt = rt;	/* rt may be NULL */
	
	return(0);
}

/*
 * Default hop limit selection. The precedence is as follows:
 * 1. Hoplimit value specified via ioctl.
 * 2. (If the outgoing interface is detected) the current
 *     hop limit of the interface specified by router advertisement.
 * 3. The system default hoplimit.
*/
#ifdef HAVE_NRL_INPCB
#define in6pcb		inpcb
#define in6p_hops	inp_hops	
#endif
int
in6_selecthlim(in6p, ifp)
	struct in6pcb *in6p;
	struct ifnet *ifp;
{
	if (in6p && in6p->in6p_hops >= 0)
		return(in6p->in6p_hops);
	else if (ifp)
		return(nd_ifinfo[ifp->if_index].chlim);
	else
		return(ip6_defhlim);
}
#ifdef HAVE_NRL_INPCB
#undef in6pcb
#undef in6p_hops
#endif

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined(__OpenBSD__)
/*
 * Find an empty port and set it to the specified PCB.
 */
#ifdef HAVE_NRL_INPCB	/* XXX: I really hate such ugly macros...(jinmei) */
#define in6pcb		inpcb
#define in6p_socket	inp_socket
#define in6p_lport	inp_lport
#define in6p_head	inp_head
#define in6p_flags	inp_flags
#define IN6PLOOKUP_WILDCARD INPLOOKUP_WILDCARD
#endif
int
in6_pcbsetport(laddr, in6p)
	struct in6_addr *laddr;
	struct in6pcb *in6p;
{
	struct socket *so = in6p->in6p_socket;
	struct in6pcb *head = in6p->in6p_head;
	u_int16_t last_port, lport = 0;
	int wild = 0;
	void *t;
	u_int16_t min, max;

	/* XXX: this is redundant when called from in6_pcbbind */
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0 &&
	   ((so->so_proto->pr_flags & PR_CONNREQUIRED) == 0 ||
	    (so->so_options & SO_ACCEPTCONN) == 0))
		wild = IN6PLOOKUP_WILDCARD;

	if (in6p->in6p_flags & IN6P_LOWPORT) {
#ifdef __NetBSD__
#ifndef IPNOPRIVPORTS
		struct proc *p = curproc;		/* XXX */

		if (p == 0 || (suser(p->p_ucred, &p->p_acflag) != 0))
			return (EACCES);
#endif
#else
		if ((so->so_state & SS_PRIV) == 0)
			return (EACCES);
#endif
		min = ip6_lowportmin;
		max = ip6_lowportmax;
	} else {
		min = ip6_anonportmin;
		max = ip6_anonportmax;
	}

	/* value out of range */
	if (head->in6p_lport < min)
		head->in6p_lport = min;
	else if (head->in6p_lport > max)
		head->in6p_lport = min;
	last_port = head->in6p_lport;
	goto startover;	/*to randomize*/
	for (;;) {
		lport = htons(head->in6p_lport);
		if (IN6_IS_ADDR_V4MAPPED(laddr)) {
#ifdef HAVE_NRL_INPCB
#ifdef INPLOOKUP_WILDCARD6
			wild &= ~INPLOOKUP_WILDCARD6;
#endif
#endif
#if 0
			t = in_pcblookup_bind(&tcbtable,
					      (struct in_addr *)&in6p->in6p_laddr.s6_addr32[3],
					      lport);
#else
			t = NULL;
#endif
		} else {
#ifdef HAVE_NRL_INPCB
#ifdef INPLOOKUP_WILDCARD4
			wild &= ~INPLOOKUP_WILDCARD4;
#endif
			/* XXX: ugly cast... */
			t = in_pcblookup(head, (struct in_addr *)&zeroin6_addr,
					 0, (struct in_addr *)laddr,
					 lport, wild | INPLOOKUP_IPV6);
#else
			t = in6_pcblookup(head, &zeroin6_addr, 0, laddr,
					  lport, wild);
#endif
		}
		if (t == 0)
			break;
	  startover:
		if (head->in6p_lport >= max)
			head->in6p_lport = min;
		else
			head->in6p_lport++;
		if (head->in6p_lport == last_port)
			return (EADDRINUSE);
	}

	in6p->in6p_lport = lport;
	return(0);		/* success */
}
#ifdef HAVE_NRL_INPCB
#undef in6pcb
#undef in6p_socket
#undef in6p_lport
#undef in6p_head
#undef in6p_flags
#undef IN6PLOOKUP_WILDCARD
#endif
#endif /* !FreeBSD3 && !OpenBSD*/

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3)
/*
 * XXX: this is borrowed from in6_pcbbind(). If possible, we should
 * share this function by all *bsd*...
 */
int
in6_pcbsetport(laddr, inp, p)
	struct in6_addr *laddr;
	struct inpcb *inp;
	struct proc *p;
{
	struct socket *so = inp->inp_socket;
	u_int16_t lport = 0, first, last, *lastport;
	int count, error = 0, wild = 0;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;

	/* XXX: this is redundant when called from in6_pcbbind */
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = INPLOOKUP_WILDCARD;

	inp->inp_flags |= INP_ANONPORT;

	if (inp->inp_flags & INP_HIGHPORT) {
		first = ipport_hifirstauto;	/* sysctl */
		last  = ipport_hilastauto;
		lastport = &pcbinfo->lasthi;
	} else if (inp->inp_flags & INP_LOWPORT) {
#if __FreeBSD__ >= 4
		if (p && (error = suser(p)))
#else
		if (p && (error = suser(p->p_ucred, &p->p_acflag)))
#endif
			return error;
		first = ipport_lowfirstauto;	/* 1023 */
		last  = ipport_lowlastauto;	/* 600 */
		lastport = &pcbinfo->lastlow;
	} else {
		first = ipport_firstauto;	/* sysctl */
		last  = ipport_lastauto;
		lastport = &pcbinfo->lastport;
	}
	/*
	 * Simple check to ensure all ports are not used up causing
	 * a deadlock here.
	 *
	 * We split the two cases (up and down) so that the direction
	 * is not being tested on each round of the loop.
	 */
	if (first > last) {
		/*
		 * counting down
		 */
		count = first - last;

		do {
			if (count-- < 0) {	/* completely used? */
				/*
				 * Undo any address bind that may have
				 * occurred above.
				 */
				inp->in6p_laddr = in6addr_any;
				return (EAGAIN);
			}
			--*lastport;
			if (*lastport > first || *lastport < last)
				*lastport = first;
			lport = htons(*lastport);
		} while (in6_pcblookup_local(pcbinfo,
					     &inp->in6p_laddr, lport, wild));
	} else {
		/*
			 * counting up
			 */
		count = last - first;

		do {
			if (count-- < 0) {	/* completely used? */
				/*
				 * Undo any address bind that may have
				 * occurred above.
				 */
				inp->in6p_laddr = in6addr_any;
				return (EAGAIN);
			}
			++*lastport;
			if (*lastport < first || *lastport > last)
				*lastport = first;
			lport = htons(*lastport);
		} while (in6_pcblookup_local(pcbinfo,
					     &inp->in6p_laddr, lport, wild));
	}

	inp->inp_lport = lport;
	if (in_pcbinshash(inp) != 0) {
		inp->in6p_laddr = in6addr_any;
		inp->inp_lport = 0;
		return (EAGAIN);
	}

	return(0);
}
#endif

/*
 * generate kernel-internal form (scopeid embedded into s6_addr16[1]).
 * If the address scope of is link-local, embed the interface index in the
 * address.  The routine determines our precedence
 * between advanced API scope/interface specification and basic API
 * specification.
 *
 * this function should be nuked in the future, when we get rid of
 * embedded scopeid thing.
 *
 * XXX actually, it is over-specification to return ifp against sin6_scope_id.
 * there can be multiple interfaces that belong to a particular scope zone
 * (in specification, we have 1:N mapping between a scope zone and interfaces).
 * we may want to change the function to return something other than ifp.
 */
int
in6_embedscope(in6, sin6, in6p, ifpp)
	struct in6_addr *in6;
	const struct sockaddr_in6 *sin6;
#ifdef HAVE_NRL_INPCB
	struct inpcb *in6p;
#define in6p_outputopts	inp_outputopts6
#define in6p_moptions	inp_moptions6
#else
	struct in6pcb *in6p;
#endif
	struct ifnet **ifpp;
{
	struct ifnet *ifp = NULL;
	u_int32_t scopeid;

	*in6 = sin6->sin6_addr;
	scopeid = sin6->sin6_scope_id;
	if (ifpp)
		*ifpp = NULL;

	/*
	 * don't try to read sin6->sin6_addr beyond here, since the caller may
	 * ask us to overwrite existing sockaddr_in6
	 */

#ifdef ENABLE_DEFAULT_SCOPE
	if (scopeid == 0)
		scopeid = scope6_addr2default(in6);
#endif

	if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
		struct in6_pktinfo *pi;

		/*
		 * KAME assumption: link id == interface id
		 */

		if (in6p && in6p->in6p_outputopts &&
		    (pi = in6p->in6p_outputopts->ip6po_pktinfo) &&
		    pi->ipi6_ifindex) {
			ifp = ifindex2ifnet[pi->ipi6_ifindex];
			in6->s6_addr16[1] = htons(pi->ipi6_ifindex);
		} else if (in6p && IN6_IS_ADDR_MULTICAST(in6) &&
			   in6p->in6p_moptions &&
			   in6p->in6p_moptions->im6o_multicast_ifp) {
			ifp = in6p->in6p_moptions->im6o_multicast_ifp;
			in6->s6_addr16[1] = htons(ifp->if_index);
		} else if (scopeid) {
			/* boundary check */
			if (scopeid < 0 || if_index < scopeid)
				return ENXIO;  /* XXX EINVAL? */
			ifp = ifindex2ifnet[scopeid];
			/* XXX assignment to 16bit from 32bit variable */
			in6->s6_addr16[1] = htons(scopeid & 0xffff);
		}

		if (ifpp)
			*ifpp = ifp;
	}

	return 0;
}
#ifdef HAVE_NRL_INPCB
#undef in6p_outputopts
#undef in6p_moptions
#endif

/*
 * generate standard sockaddr_in6 from embedded form.
 * touches sin6_addr and sin6_scope_id only.
 *
 * this function should be nuked in the future, when we get rid of
 * embedded scopeid thing.
 */
int
in6_recoverscope(sin6, in6, ifp)
	struct sockaddr_in6 *sin6;
	const struct in6_addr *in6;
	struct ifnet *ifp;
{
	u_int32_t zoneid;

	sin6->sin6_addr = *in6;

	/*
	 * don't try to read *in6 beyond here, since the caller may
	 * ask us to overwrite existing sockaddr_in6
	 */

	sin6->sin6_scope_id = 0;
	if (IN6_IS_SCOPE_LINKLOCAL(in6) || IN6_IS_ADDR_MC_INTFACELOCAL(in6)) {
		/*
		 * KAME assumption: link id == interface id
		 */
		zoneid = ntohs(sin6->sin6_addr.s6_addr16[1]);
		if (zoneid) {
			/* sanity check */
			if (zoneid < 0 || if_index < zoneid)
				return ENXIO;
			if (ifp && ifp->if_index != zoneid)
				return ENXIO;
			sin6->sin6_addr.s6_addr16[1] = 0;
			sin6->sin6_scope_id = zoneid;
		}
	}

	return 0;
}

/*
 * just clear the embedded scope identifer.
 * XXX: currently used for bsdi4 only as a supplement function.
 */
void
in6_clearscope(addr)
	struct in6_addr *addr;
{
	if (IN6_IS_SCOPE_LINKLOCAL(addr) || IN6_IS_ADDR_MC_INTFACELOCAL(addr))
		addr->s6_addr16[1] = 0;
}
