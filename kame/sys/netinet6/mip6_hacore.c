/*	$KAME: mip6_hacore.c,v 1.8 2003/07/28 11:58:14 t-momose Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.  All rights reserved.
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
 * Authors: Conny Larsson <Conny.Larsson@era.ericsson.se>
 *          Mattias Pettersson <Mattias.Pettersson@era.ericsson.se>
 *
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet6.h"
#include "opt_ipsec.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif

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

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>
#include <netinet6/scope6_var.h>

#include <netinet/ip_encap.h>

#include <net/if_hif.h>

#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#include <netinet6/mip6_hacore.h>

/* home registration processing. */
static int mip6_dad_start(struct mip6_bc *);

int
mip6_process_hrbu(bi)
	struct mip6_bc *bi;
{
	struct nd_prefix *pr, *llpr = NULL;
	struct ifnet *hifp = NULL;
	struct sockaddr_in6 lladdr;
	struct mip6_bc *llmbc = NULL;
	struct mip6_bc *mbc = NULL;
	struct mip6_bc *prim_mbc = NULL;
	u_int32_t prlifetime = 0;
	int busy = 0;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	/* find the home ifp of this homeaddress. */
	for (pr = nd_prefix.lh_first;
	    pr;
	    pr = pr->ndpr_next) {
		if (in6_are_prefix_equal(&bi->mbc_phaddr.sin6_addr,
					 &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)) {
			hifp = pr->ndpr_ifp; /* home ifp. */
			prlifetime = pr->ndpr_vltime;
		}
	}
	if (hifp == NULL) {
		/*
		 * the haddr0 doesn't have an online prefix.  return a
		 * binding ack with an error NOT_HOME_SUBNET.
		 */
		bi->mbc_status = IP6MA_STATUS_NOT_HOME_SUBNET;
		bi->mbc_send_ba = 1;
		return (0); /* XXX is 0 OK? */
	}

	/* find the link-local prefix of the home ifp. */
	if ((bi->mbc_flags & IP6MU_LINK) != 0) {
		for (pr = nd_prefix.lh_first;
		     pr;
		     pr = pr->ndpr_next) {
			if (hifp != pr->ndpr_ifp) {
				/* this prefix is not a home prefix. */
				continue;
			}
			/* save link-local prefix. */
			if (IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr)) {
				llpr = pr;
				continue;
			}
		}
	}

	if (prlifetime < 4) {	/* lifetime in units of 4 sec */
		/* XXX BA's lifetime is zero */
		mip6log((LOG_ERR,
			 "%s:%d: invalid prefix lifetime %lu sec(s).",
			 __FILE__, __LINE__,
			 (u_long)prlifetime));
		bi->mbc_status = IP6MA_STATUS_UNSPECIFIED;
		bi->mbc_send_ba = 1;
		bi->mbc_lifetime = 0;
		bi->mbc_refresh = 0;
		return (0); /* XXX is 0 OK? */
	}
	/* sanity check */
	if (bi->mbc_lifetime < 4) {
		/* XXX lifetime > DAD timer */
		/* XXX lifetime > 4 (units of 4 secs) */
		mip6log((LOG_ERR,
			 "%s:%d: invalid lifetime %lu sec(s).",
			 __FILE__, __LINE__,
			 (u_long)bi->mbc_lifetime));
		return (0); /* XXX is 0 OK? */
	}

	/* adjust lifetime */
	if (bi->mbc_lifetime > prlifetime)
		bi->mbc_lifetime = prlifetime;

	/*
	 * - L=0: defend the given address.
	 * - L=1: defend both the given non link-local unicast (home)
	 *        address and the derived link-local.
	 */
	/*
	 * at first, check an existing binding cache entry for the
	 * link-local.
	 */
	if ((bi->mbc_flags & IP6MU_LINK) != 0 && llpr != NULL) {
		mip6_create_addr(&lladdr,
				 (const struct sockaddr_in6 *)&bi->mbc_phaddr,
				 llpr);
		llmbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &lladdr);
		if (llmbc == NULL) {
			/*
			 * create a new binding cache entry for the
			 * link-local.
			 */
			llmbc = mip6_bc_create(&lladdr, &bi->mbc_pcoa,
			    &bi->mbc_addr, bi->mbc_flags, bi->mbc_seqno,
			    bi->mbc_lifetime, hifp);
			if (llmbc == NULL) {
				/* XXX INSUFFICIENT RESOURCE error */
				return (-1);
			}

			/* start DAD processing. */
			llmbc->mbc_state |= MIP6_BC_STATE_DAD_WAIT;
			mip6_dad_start(llmbc);
		} else if ((llmbc->mbc_state & MIP6_BC_STATE_DAD_WAIT) != 0) {
			llmbc->mbc_pcoa = bi->mbc_pcoa;
			llmbc->mbc_seqno = bi->mbc_seqno;
			busy++;
		} else {
			/*
			 * update the existing binding cache entry for
			 * the link-local.
			 */
			llmbc->mbc_pcoa = bi->mbc_pcoa;
			llmbc->mbc_flags = bi->mbc_flags;
			llmbc->mbc_seqno = bi->mbc_seqno;
			llmbc->mbc_lifetime = bi->mbc_lifetime;
			llmbc->mbc_expire
				= time_second + llmbc->mbc_lifetime;
			/* sanity check for overflow. */
			if (llmbc->mbc_expire < time_second)
				llmbc->mbc_expire = 0x7fffffff;
#ifdef MIP6_CALLOUTTEST
			mip6_timeoutentry_update(llmbc->mbc_timeout, llmbc->mbc_expire);
			mip6_timeoutentry_update(llmbc->mbc_brr_timeout, llmbc->mbc_expire - mbc->mbc_lifetime / 4);
#endif /* MIP6_CALLOUTTEST */
			llmbc->mbc_state &= ~MIP6_BC_STATE_BR_WAITSENT;
			/* modify encapsulation entry */
			/* XXX */
			if (mip6_tunnel_control(MIP6_TUNNEL_CHANGE, llmbc,
				mip6_bc_encapcheck, &llmbc->mbc_encap)) {
				/* XXX error */
			}
		}
		llmbc->mbc_flags |= IP6MU_CLONED;
	}

	/*
	 * next, check an existing binding cache entry for the unicast
	 * (home) address.
	 */
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &bi->mbc_phaddr);
	if (mbc == NULL) {
		/* create a binding cache entry for the home address. */
		mbc = mip6_bc_create(&bi->mbc_phaddr, &bi->mbc_pcoa,
		    &bi->mbc_addr, bi->mbc_flags, bi->mbc_seqno,
		    bi->mbc_lifetime, hifp);
		if (mbc == NULL) {
			/* XXX STATUS_RESOUCE */
			return (-1);
		}

		/* mark that we should do DAD later in this function. */
		mbc->mbc_state |= MIP6_BC_STATE_DAD_WAIT;
		prim_mbc = mbc;

		/*
		 * if the request has IP6MU_LINK flag, refer the
		 * link-local entry.
		 */
		if (bi->mbc_flags & IP6MU_LINK) {
			mbc->mbc_llmbc = llmbc;
			llmbc->mbc_refcnt++;
		}
	} else if ((mbc->mbc_state & MIP6_BC_STATE_DAD_WAIT) != 0) {
		mbc->mbc_pcoa = bi->mbc_pcoa;
		mbc->mbc_seqno = bi->mbc_seqno;
		busy++;
	} else {
		/*
		 * update the existing binding cache entry for the
		 * home address.
		 */
		mbc->mbc_pcoa = bi->mbc_pcoa;
		mbc->mbc_flags = bi->mbc_flags;
		mbc->mbc_seqno = bi->mbc_seqno;
		mbc->mbc_lifetime = bi->mbc_lifetime;
		mbc->mbc_expire = time_second + mbc->mbc_lifetime;
		/* sanity check for overflow. */
		if (mbc->mbc_expire < time_second)
			mbc->mbc_expire = 0x7fffffff;
		mbc->mbc_state &= ~MIP6_BC_STATE_BR_WAITSENT;
#ifdef MIP6_CALLOUTTEST
		mip6_timeoutentry_update(mbc->mbc_timeout, mbc->mbc_expire);
		/* mip6_timeoutentry_update(mbc->mbc_brr_timeout, mbc->mbc_expire - mbc->mbc_lifetime / 4); */
#endif /* MIP6_CALLOUTTEST */

		/* modify the encapsulation entry. */
		if (mip6_tunnel_control(MIP6_TUNNEL_CHANGE, mbc,
			mip6_bc_encapcheck, &mbc->mbc_encap)) {
			/* XXX UNSPECIFIED */
			return (-1);
		}
	}

	if (busy) {
		mip6log((LOG_INFO, "%s:%d: DAD INCOMPLETE\n",
			 __FILE__, __LINE__));
		return(0);
	}

	if (prim_mbc) {
		/*
		 * a new binding cache is created. start DAD
		 * proccesing.
		 */
		mip6_dad_start(prim_mbc);
	} else {
		/*
		 * a binding cache entry is updated.  return a binding
		 * ack.
		 */
		bi->mbc_refresh = bi->mbc_lifetime * MIP6_REFRESH_LIFETIME_RATE / 100;
		if (bi->mbc_refresh < MIP6_REFRESH_MINLIFETIME)
			bi->mbc_refresh = bi->mbc_lifetime < MIP6_REFRESH_MINLIFETIME ?
				  bi->mbc_lifetime : MIP6_REFRESH_MINLIFETIME;
		bi->mbc_status = IP6MA_STATUS_ACCEPTED;
		bi->mbc_send_ba = 1;
	}

	return (0);
}

int
mip6_process_hurbu(bi)
	struct mip6_bc *bi;
{
	struct mip6_bc *mbc;
	struct nd_prefix *pr;
	struct ifnet *hifp = NULL;
	int error = 0;

	/* find the home ifp of this homeaddress. */
	for (pr = nd_prefix.lh_first;
	    pr;
	    pr = pr->ndpr_next) {
		if (in6_are_prefix_equal(&bi->mbc_phaddr.sin6_addr,
					 &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)) {
			hifp = pr->ndpr_ifp; /* home ifp. */
		}
	}
	if (hifp == NULL) {
		/*
		 * the haddr0 doesn't have an online prefix.  return a
		 * binding ack with an error NOT_HOME_SUBNET.
		 */
		bi->mbc_status = IP6MA_STATUS_NOT_HOME_SUBNET;
		bi->mbc_send_ba = 1;
		bi->mbc_lifetime = bi->mbc_refresh = 0;
		return (0); /* XXX is 0 OK? */
	}

	/* remove a global unicast home binding cache entry. */
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &bi->mbc_phaddr);
	if (mbc == NULL) {
		/* XXX panic */
		return (0);
	}
	if ((bi->mbc_flags & IP6MU_LINK) &&  (mbc->mbc_llmbc != NULL)) {
		/* remove a link-local binding cache entry. */
		error = mip6_bc_list_remove(&mip6_bc_list, mbc->mbc_llmbc);
		if (error) {
			mip6log((LOG_ERR,
			    "%s:%d: can't remove BC.\n",
			    __FILE__, __LINE__));
			bi->mbc_status = IP6MA_STATUS_UNSPECIFIED;
			bi->mbc_send_ba = 1;
			bi->mbc_lifetime = bi->mbc_refresh = 0;
			return (error);
		}
	}
	error = mip6_bc_list_remove(&mip6_bc_list, mbc);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: can't remove BC.\n",
		    __FILE__, __LINE__));
		bi->mbc_status = IP6MA_STATUS_UNSPECIFIED;
		bi->mbc_send_ba = 1;
		bi->mbc_lifetime = bi->mbc_refresh = 0;
		return (error);
	}

	/* return BA */
	bi->mbc_lifetime = 0; /* ID-19 10.3.2. the lifetime MUST be 0. */
	bi->mbc_send_ba = 1;	/* Need it ? */
	
	return (0);
}

int
mip6_bc_proxy_control(target, local, cmd)
	struct sockaddr_in6 *target;
	struct sockaddr_in6 *local;
	int cmd;
{
	struct sockaddr_in6 mask; /* = {sizeof(mask), AF_INET6 } */
	struct sockaddr_in6 taddr, sa6;
	struct sockaddr_dl *sdl;
        struct rtentry *rt, *nrt;
	struct ifaddr *ifa;
	struct ifnet *ifp;
	int flags, error = 0;

	/* Create sa6 */
	bzero(&sa6, sizeof(sa6));
	sa6 = *local;
#ifndef SCOPEDROUTING
	sa6.sin6_scope_id = 0;
#endif
	ifa = ifa_ifwithaddr((struct sockaddr *)&sa6);
	if (ifa == NULL)
		return (EINVAL);
	ifp = ifa->ifa_ifp;

	bzero(&taddr, sizeof(taddr));
	taddr = *target;
	if (in6_addr2zoneid(ifp, &taddr.sin6_addr,
			    &taddr.sin6_scope_id)) {
		mip6log((LOG_ERR,
			 "%s:%d: in6_addr2zoneid failed\n",
			 __FILE__, __LINE__));
		return(EIO);
	}
	error = in6_embedscope(&taddr.sin6_addr, &taddr);
	if (error != 0) {
		return(error);
	}
#ifndef SCOPEDROUTING
	taddr.sin6_scope_id = 0;
#endif

	switch (cmd) {
	case RTM_DELETE:
#ifdef __FreeBSD__
		rt = rtalloc1((struct sockaddr *)&taddr, 0, 0UL);
#else /* __FreeBSD__ */
		rt = rtalloc1((struct sockaddr *)&taddr, 0);
#endif /* __FreeBSD__ */
		if (rt)
			rt->rt_refcnt--;
		if (rt == NULL ||
		    (rt->rt_flags & RTF_HOST) == 0 ||
		    (rt->rt_flags & RTF_ANNOUNCE) == 0) {
			return 0; /* EHOSTUNREACH */
		}
		error = rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
				  rt_mask(rt), 0, (struct rtentry **)0);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: RTM_DELETE for %s returned "
				 "error = %d\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&target->sin6_addr), error));
		}
		rt = NULL;

		break;

	case RTM_ADD:
#ifdef __FreeBSD__
		rt = rtalloc1((struct sockaddr *)&taddr, 0, 0UL);
#else /* __FreeBSD__ */
		rt = rtalloc1((struct sockaddr *)&taddr, 0);
#endif /* __FreeBSD__ */
		if (rt)
			rt->rt_refcnt--;
		if (rt && (rt->rt_flags & RTF_HOST) != 0) {
			if ((rt->rt_flags & RTF_ANNOUNCE) != 0 &&
			    rt->rt_gateway->sa_family == AF_LINK) {
				mip6log((LOG_NOTICE,
					 "%s:%d: RTM_ADD: we are already proxy for %s\n",
					 __FILE__, __LINE__,
					 ip6_sprintf(&target->sin6_addr)));
				return (EEXIST);
			}
			if ((rt->rt_flags & RTF_LLINFO) != 0) {
				/* nd cache exist */
				rtrequest(RTM_DELETE, rt_key(rt),
					  (struct sockaddr *)0,
					  rt_mask(rt), 0, (struct rtentry **)0);
				rt = NULL;
			} else {
				/* XXX Path MTU entry? */
				mip6log((LOG_ERR,
					 "%s:%d: entry exist %s: rt_flags=0x%x\n",
					 __FILE__, __LINE__,
					 ip6_sprintf(&target->sin6_addr),
					 (int)rt->rt_flags));
			}
		}

#ifdef __NetBSD__
		sdl = ifp->if_sadl;
#else
		/* sdl search */
	{
		struct ifaddr *ifa_dl;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifa_dl = ifp->if_addrlist; ifa_dl; ifa_dl = ifa->ifa_next)
#else
		for (ifa_dl = ifp->if_addrlist.tqh_first; ifa_dl;
		     ifa_dl = ifa_dl->ifa_list.tqe_next)
#endif
			if (ifa_dl->ifa_addr->sa_family == AF_LINK) break;

		if (!ifa_dl)
			return EINVAL;

		sdl = (struct sockaddr_dl *)ifa_dl->ifa_addr;
	}
#endif /* __NetBSD__ */

		/* Create mask */
		bzero(&mask, sizeof(mask));
		mask.sin6_family = AF_INET6;
		mask.sin6_len = sizeof(mask);

		in6_prefixlen2mask(&mask.sin6_addr, 128);
		flags = (RTF_STATIC | RTF_HOST | RTF_ANNOUNCE);

		error = rtrequest(RTM_ADD, (struct sockaddr *)&taddr,
				  (struct sockaddr *)sdl,
				  (struct sockaddr *)&mask, flags, &nrt);

		if (error == 0) {
			/* Avoid expiration */
			if (nrt) {
				nrt->rt_rmx.rmx_expire = 0;
				nrt->rt_refcnt--;
			} else
				error = EINVAL;
		} else {
			mip6log((LOG_ERR,
				 "%s:%d: RTM_ADD for %s returned "
				 "error = %d\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&target->sin6_addr), error));
		}

		{
			/* very XXX */
			struct sockaddr_in6 daddr;

			bzero(&daddr, sizeof(daddr));
			daddr.sin6_family = AF_INET6;
			daddr.sin6_len = sizeof(daddr);
			daddr.sin6_addr = in6addr_linklocal_allnodes;
			if (in6_addr2zoneid(ifp, &daddr.sin6_addr,
					    &daddr.sin6_scope_id)) {
				/* XXX: should not happen */
				mip6log((LOG_ERR,
					 "%s:%d: in6_addr2zoneid failed\n",
					 __FILE__, __LINE__));
				error = EIO; /* XXX */
			}
			if (error == 0) {
				error = in6_embedscope(&daddr.sin6_addr,
						       &daddr);
			}
			if (error == 0) {
				nd6_na_output(ifp, &daddr, &taddr,
					      ND_NA_FLAG_OVERRIDE,
					      1,
					      (struct sockaddr *)sdl);
			}
		}

		break;

	default:
		mip6log((LOG_ERR,
			 "%s:%d: we only support RTM_ADD/DELETE operation.\n",
			 __FILE__, __LINE__));
		error = -1;
		break;
	}

	return (error);
}

void
mip6_restore_proxynd_entry(m)
	struct mbuf *m;
{
	struct mip6_bc *mbc;
	
	mbc = mip6_temp_deleted_proxy(m);
	if (mbc)
		mip6_bc_proxy_control(&mbc->mbc_phaddr, &mbc->mbc_addr, RTM_ADD);
}

struct mip6_bc *
mip6_temp_deleted_proxy(m)
	struct mbuf *m;
{
	struct m_tag *n;
	struct mip6_bc *mbc = NULL;
	struct sockaddr_in6 src, dst;
	struct ip6aux *ip6a;
	
	n = ip6_findaux(m);
	if (!n)
		return NULL;

	ip6a = (struct ip6aux *) (n + 1);
	if ((ip6a->ip6a_flags & IP6A_TEMP_PROXYND_DEL) &&
	     ip6_getpktaddrs(m, &src, &dst) == 0) {
		mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &dst);
		ip6a->ip6a_flags &= ~IP6A_TEMP_PROXYND_DEL;
	}

	return (mbc);
}

int
mip6_bc_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip6_hdr *ip6;
	struct mip6_bc *mbc = (struct mip6_bc *)arg;
	struct sockaddr_in6 encap_src;
	struct sockaddr_in6 *mnaddr;

	if (mbc == NULL) {
		return (0);
	}

	ip6 = mtod(m, struct ip6_hdr*);
	if (!ip6_findaux((struct mbuf *)m) ||
	    ip6_getpktaddrs((struct mbuf *)m, &encap_src, NULL))
		return (0);

	mnaddr = &mbc->mbc_pcoa;

	/* check mn addr */
	if (!SA6_ARE_ADDR_EQUAL(&encap_src, mnaddr)) {
		return (0);
	}

	/* check my addr */
	/* XXX */

	return (128);
}

static int
mip6_dad_start(mbc)
	struct  mip6_bc *mbc;
{
	struct in6_ifaddr *ia;

	if (mbc->mbc_dad != NULL)
		return (EEXIST);

	MALLOC(ia, struct in6_ifaddr *, sizeof(*ia), M_IFADDR, M_NOWAIT);
	if (ia == NULL)
		return (ENOBUFS);

	bzero((caddr_t)ia, sizeof(*ia));
	ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	ia->ia_addr.sin6_family = AF_INET6;
	ia->ia_addr.sin6_len = sizeof(ia->ia_addr);
	ia->ia_ifp = mbc->mbc_ifp;
	ia->ia6_flags |= IN6_IFF_TENTATIVE;
	sa6_copy_addr(&mbc->mbc_phaddr, &ia->ia_addr);
	if (in6_addr2zoneid(ia->ia_ifp, &ia->ia_addr.sin6_addr,
			    &ia->ia_addr.sin6_scope_id)) {
		FREE(ia, M_IFADDR);
		return (EINVAL);
	}
	in6_embedscope(&ia->ia_addr.sin6_addr, &ia->ia_addr);
	IFAREF(&ia->ia_ifa);
	mbc->mbc_dad = ia;
	nd6_dad_start((struct ifaddr *)ia, NULL);

	return (0);
}

int
mip6_dad_stop(mbc)
	struct  mip6_bc *mbc;
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)mbc->mbc_dad;

	if (ia == NULL)
		return (ENOENT);
	nd6_dad_stop((struct ifaddr *)ia);
	FREE(ia, M_IFADDR);
	mbc->mbc_dad = NULL;
	return (0);
}

struct ifaddr *
mip6_dad_find(taddr, ifp)
	struct in6_addr *taddr;
	struct ifnet *ifp;
{
	struct mip6_bc *mbc;
	struct in6_ifaddr *ia;

	for (mbc = LIST_FIRST(&mip6_bc_list);
	    mbc;
	    mbc = LIST_NEXT(mbc, mbc_entry)) {
		if ((mbc->mbc_state & MIP6_BC_STATE_DAD_WAIT) == 0)
			continue;
		if (mbc->mbc_ifp != ifp || mbc->mbc_dad == NULL)
			continue;
		ia = (struct in6_ifaddr *)mbc->mbc_dad;
		if (IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, taddr))
			return ((struct ifaddr *)ia);
	}

	return (NULL);
}

int
mip6_dad_success(ifa)
	struct ifaddr *ifa;
{
	struct  mip6_bc *mbc = NULL;

	for (mbc = LIST_FIRST(&mip6_bc_list);
	    mbc;
	    mbc = LIST_NEXT(mbc, mbc_entry)) {
		if (mbc->mbc_dad == ifa)
			break;
	}
	if (!mbc)
		return (ENOENT);

	FREE(ifa, M_IFADDR);
	mbc->mbc_dad = NULL;
	mbc->mbc_state &= ~MIP6_BC_STATE_DAD_WAIT;

	/* create encapsulation entry */
	mip6_tunnel_control(MIP6_TUNNEL_ADD, mbc, mip6_bc_encapcheck,
	    &mbc->mbc_encap);

	/* add rtable for proxy ND */
	mip6_bc_proxy_control(&mbc->mbc_phaddr, &mbc->mbc_addr, RTM_ADD);

	/* if this entry has been cloned by L=1 flag, just return. */
	if ((mbc->mbc_flags & IP6MU_CLONED) != 0)
		return (0);

	/* return a binding ack. */
	if (mip6_bc_send_ba(&mbc->mbc_addr, &mbc->mbc_phaddr, &mbc->mbc_pcoa,
	    IP6MA_STATUS_ACCEPTED, mbc->mbc_seqno, mbc->mbc_lifetime,
	    mbc->mbc_lifetime / 2 /* XXX */, NULL)) {
		mip6log((LOG_ERR,
		    "%s:%d: sending BA to %s(%s) failed. send it later.\n",
		    __FILE__, __LINE__,
		    ip6_sprintf(&mbc->mbc_phaddr.sin6_addr),
		    ip6_sprintf(&mbc->mbc_pcoa.sin6_addr)));
	}

	return (0);
}

int
mip6_dad_duplicated(ifa)
	struct ifaddr *ifa;
{
	return mip6_dad_error(ifa, IP6MA_STATUS_DAD_FAILED);
}

int
mip6_dad_error(ifa, err)
	struct ifaddr *ifa;
	int err;
{
	struct mip6_bc *mbc = NULL, *llmbc = NULL;
	struct mip6_bc *gmbc = NULL, *gmbc_next = NULL;
	int error;

	for (mbc = LIST_FIRST(&mip6_bc_list);
	    mbc;
	    mbc = LIST_NEXT(mbc, mbc_entry)) {
		if (mbc->mbc_dad == ifa)
			break;
	}
	if (!mbc)
		return (ENOENT);

	FREE(ifa, M_IFADDR);
	mbc->mbc_dad = NULL;

	if ((mbc->mbc_flags & IP6MU_CLONED) != 0) {
		/*
		 * DAD for a link-local address failed.  clear all
		 * references from other binding caches.
		 */
		llmbc = mbc;
		for (gmbc = LIST_FIRST(&mip6_bc_list);
		    gmbc;
		    gmbc = gmbc_next) {
			gmbc_next = LIST_NEXT(gmbc, mbc_entry);
			if (((gmbc->mbc_flags & IP6MU_LINK) != 0)
			    && ((gmbc->mbc_flags & IP6MU_CLONED) == 0)
			    && (gmbc->mbc_llmbc == llmbc)) {
				gmbc_next = LIST_NEXT(gmbc, mbc_entry);
				if ((gmbc->mbc_state
					& MIP6_BC_STATE_DAD_WAIT) != 0) {
					gmbc->mbc_dad = NULL;
					error = mip6_bc_list_remove(
					    &mip6_bc_list, llmbc);
					if (error) {
						mip6log((LOG_ERR,
						    "%s:%d: can't remove a binding cache entry.\n",
						    __FILE__, __LINE__));
						/* what should I do? */
					}

					/* return a binding ack. */
					mip6_bc_send_ba(&gmbc->mbc_addr,
					    &gmbc->mbc_phaddr, &gmbc->mbc_pcoa,
					    err, gmbc->mbc_seqno, 0, 0, NULL);

					/*
					 * update gmbc_next, beacuse removing
					 * llmbc may invalidate gmbc_next.
					 */
					gmbc_next = LIST_NEXT(gmbc, mbc_entry);
					error = mip6_bc_list_remove(
					    &mip6_bc_list, gmbc);
					if (error) {
						mip6log((LOG_ERR,
						    "%s:%d: can't remove a binding cache entry.\n",
						    __FILE__, __LINE__));
						/* what should I do? */
					}
				} else {
					/*
					 * DAD for a lladdr failed, but
					 * a related BC's DAD had been
					 * succeeded.  does this happen?
					 */
				}
			}
		}
		return (0);
	} else {
		/*
		 * if this binding cache has a related link-local
		 * binding cache entry, decrement the refcnt of the
		 * entry.
		 */
		if (mbc->mbc_llmbc != NULL) {
			error = mip6_bc_list_remove(&mip6_bc_list,
			    mbc->mbc_llmbc);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: can't remove "
				    "a link-local binding cache entry.\n",
				    __FILE__, __LINE__));
				/* what should I do? */
			}
		}
	}

	/* return a binding ack. */
	mip6_bc_send_ba(&mbc->mbc_addr, &mbc->mbc_phaddr, &mbc->mbc_pcoa, err,
	    mbc->mbc_seqno, 0, 0, NULL);
	error = mip6_bc_list_remove(&mip6_bc_list, mbc);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: can't remove BC.\n",
		    __FILE__, __LINE__));
		/* what should I do? */
	}

	return (0);
}

/*
 * encapsulate the packet from the correspondent node to the mobile
 * node that is communicating.  the encap_src is to be a home agent's
 * address and the encap_dst is to be a mobile node coa, according to
 * the binding cache entry for the destined mobile node.
 */
int
mip6_tunnel_output(mp, mbc)
	struct mbuf **mp;    /* the original ipv6 packet */
	struct mip6_bc *mbc; /* the bc entry for the dst of the pkt */
{
	const struct encaptab *ep = mbc->mbc_encap;
	struct mbuf *m = *mp;
	struct sockaddr_in6 *encap_src = &mbc->mbc_addr;
	struct sockaddr_in6 *encap_dst = &mbc->mbc_pcoa;
	struct ip6_hdr *ip6;
	int len, error = 0;

	if (ep->af != AF_INET6) {
		mip6log((LOG_ERR,
			 "%s:%d: illegal address family type %d\n",
			 __FILE__, __LINE__, ep->af));
		return (EFAULT);
	}

	/* Recursion problems? */

	if (SA6_IS_ADDR_UNSPECIFIED(encap_src)) {
		mip6log((LOG_ERR,
			 "%s:%d: the encap source address is unspecified\n",
			 __FILE__, __LINE__));
		return (EFAULT);
	}

	len = m->m_pkthdr.len; /* payload length */

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m) {
			mip6log((LOG_ERR,
				 "%s:%d: m_pullup failed\n",
				 __FILE__, __LINE__));
			return (ENOBUFS);
		}
	}
	ip6 = mtod(m, struct ip6_hdr *);

	/* prepend new, outer ipv6 header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: outer header allocation failed\n",
			 __FILE__, __LINE__));
		return (ENOBUFS);
	}

	/* fill the outer header */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = htons((u_short)len);
	ip6->ip6_nxt = IPPROTO_IPV6;
	ip6->ip6_hlim = ip6_defhlim;
	ip6->ip6_src = encap_src->sin6_addr;

	/* bidirectional configured tunnel mode */
	if (!SA6_IS_ADDR_UNSPECIFIED(encap_dst))
		ip6->ip6_dst = encap_dst->sin6_addr;
	else {
		mip6log((LOG_ERR,
			 "%s:%d: the encap dest address is unspecified\n",
			 __FILE__, __LINE__));
		m_freem(m);
		return (ENETUNREACH);
	}
	if (ip6_setpktaddrs(m, encap_src, encap_dst) == NULL) {
		m_freem(m);
		return (error);
	}

	mip6stat.mip6s_orevtunnel++;

#if defined(IPV6_MINMTU) && 0
	/*
	 * force fragmentation to minimum MTU, to avoid path MTU discovery.
	 * it is too painful to ask for resend of inner packet, to achieve
	 * path MTU discovery for encapsulated packets.
	 */
	return (ip6_output(m, 0, 0, IPV6_MINMTU, 0, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  ));
#else
	return (ip6_output(m, 0, 0, 0, 0, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  ));
#endif
}

int
mip6_icmp6_tunnel_input(m, off, icmp6len)
	struct mbuf *m;
	int off;
	int icmp6len;
{
	struct mbuf *n;
	struct ip6_hdr *ip6, *otip6, oip6, *nip6;
	int otip6off, nxt;
	struct sockaddr_in6 dst_sa, oip6src_sa, oip6dst_sa;
	struct icmp6_hdr *icmp6, *nicmp6;
	struct mip6_bc *mbc;
	int error = 0;

	if (!MIP6_IS_HA) {
		/*
		 * this check is needed only for the node that is
		 * acting as a home agent.
		 */
		return (0);
	}

	/* get packet addresses. */
	if (ip6_getpktaddrs(m, NULL, &dst_sa))
		return (EINVAL);

	/* check if we have enough icmp payload size. */
	if (icmp6len < sizeof(*otip6) + sizeof(oip6)) {
		/*
		 * we don't have enough size of icmp payload.  to
		 * determine that this icmp is against the tunneled
		 * packet, we at least have two ip header, one is for
		 * tunneling from a home agent to a correspondent node
		 * and the other is a original header from a mobile
		 * node to the correspondent node.
		 */
		return (0);
	}

	/*
	 * check if this icmp is generated on the way from a home
	 * agent to a mobile node by encapsulating an original packet
	 * which is from a correspondent node to the mobile node.  if
	 * so, relay this icmp to the sender of the original packet.
	 *
	 * the icmp packet against the encapsulated packet looks like
	 * as follows.
	 *
	 *   ip(src=??,dst=ha)
	 *     |icmp|ip(src=ha,dst=mncoa)|ip(src=cn,dst=mnhoa)|payload
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
	if (icmp6->icmp6_type >= 128) {
		/*
		 * this is not an icmp error message.  no need to
		 * relay.
		 */
		return (0);
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off + sizeof(*icmp6), sizeof(*otip6), EINVAL);
	otip6 = (struct ip6_hdr *)(mtod(m, caddr_t) + off + sizeof(*icmp6));
#else
	IP6_EXTHDR_GET(otip6, struct ip6_hdr *, m, off + sizeof(*icmp6),
		       sizeof(*otip6));
	if (otip6 == NULL)
		return (EINVAL);
#endif
	otip6off = off + sizeof(*icmp6) + sizeof(*otip6);
	nxt = otip6->ip6_nxt;
	while (nxt != IPPROTO_IPV6) {
		int off;

		off = otip6off;
		otip6off = ip6_nexthdr(m, off, nxt, &nxt);
		if ((otip6off < 0) ||
		    (otip6off < off) ||
		    (otip6off == off)) {
			/* too short or there is no ip hdr in this
			 * icmp payload. */
			return (0);
		}
		off = otip6off;
	}
	if (m->m_pkthdr.len < otip6off + sizeof(oip6)) {
		/* too short icmp packet. */
		return (0);
	}
	m_copydata(m, otip6off, sizeof(oip6), (caddr_t)&oip6);
	/* create a src addr of the original packet. */
	oip6src_sa.sin6_len = sizeof(oip6src_sa);
	oip6src_sa.sin6_family = AF_INET6;
	oip6src_sa.sin6_addr = oip6.ip6_src;
	if (in6_addr2zoneid(m->m_pkthdr.rcvif, &oip6src_sa.sin6_addr,
			   &oip6src_sa.sin6_scope_id))
		return (0); /* XXX */
	if (in6_embedscope(&oip6src_sa.sin6_addr, &oip6src_sa))
		return (0); /* XXX */
	/* create a dst addr of the original packet. */
	oip6dst_sa.sin6_len = sizeof(oip6dst_sa);
	oip6dst_sa.sin6_family = AF_INET6;
	oip6dst_sa.sin6_addr = oip6.ip6_dst;
	if (in6_addr2zoneid(m->m_pkthdr.rcvif, &oip6dst_sa.sin6_addr,
			   &oip6dst_sa.sin6_scope_id))
		return (0); /* XXX */
	if (in6_embedscope(&oip6dst_sa.sin6_addr, &oip6dst_sa))
		return (0); /* XXX */

	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &oip6dst_sa);
	if (mbc == NULL) {
		/* we are not a home agent of this mobile node ?? */
		return (0);
	}

	n = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf allocation failed.\n",
			 __FILE__, __LINE__));
		/* continue, anyway. */
		return (0);
	}
	m_adj(n, otip6off);
	M_PREPEND(n, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr),
		  M_DONTWAIT);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf prepend for ip6/icmp6 failed.\n",
			 __FILE__, __LINE__));
		/* continue. */
		return (0);
	}
	if (!ip6_setpktaddrs(n, &dst_sa, &oip6src_sa)) {
		m_freem(n);
		return (0);
	}
	/* fill the ip6_hdr. */
	nip6 = mtod(n, struct ip6_hdr *);
	nip6->ip6_flow = 0;
	nip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	nip6->ip6_vfc |= IPV6_VERSION;
	nip6->ip6_plen = htons(n->m_pkthdr.len - sizeof(struct ip6_hdr));
	nip6->ip6_nxt = IPPROTO_ICMPV6;
	nip6->ip6_hlim = ip6_defhlim;
	nip6->ip6_src = dst_sa.sin6_addr;
	in6_clearscope(&nip6->ip6_src);
	nip6->ip6_dst = oip6src_sa.sin6_addr;
	in6_clearscope(&nip6->ip6_dst);

	/* fill the icmp6_hdr. */
	nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
	nicmp6->icmp6_type = icmp6->icmp6_type;
	nicmp6->icmp6_code = icmp6->icmp6_code;
	nicmp6->icmp6_data32[0] = icmp6->icmp6_data32[0];

	/* XXX modify icmp data in some case.  (ex. TOOBIG) */

	/* calculate the checksum. */
	nicmp6->icmp6_cksum = 0;
	nicmp6->icmp6_cksum = in6_cksum(n, IPPROTO_ICMPV6,
					sizeof(*nip6), ntohs(nip6->ip6_plen));

	/* XXX IPSEC? */

	error = ip6_output(n, NULL, NULL, 0, NULL, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  );
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: send failed. (errno = %d)\n",
			 __FILE__, __LINE__, error));
		/* continue processing 'm' (the original icmp). */
		return (0);
	}

	return (0);
}
