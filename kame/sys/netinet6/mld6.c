/*	$KAME: mld6.c,v 1.62 2002/10/04 12:00:44 suz Exp $	*/

/*
 * Copyright (c) 2002 INRIA. All rights reserved.
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
 *	This product includes software developed by INRIA and its
 *	contributors.
 * 4. Neither the name of INRIA nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Implementation of Multicast Listener Discovery, Version 2.
 *
 * Developed by Hitoshi Asaeda, INRIA, August 2002.
 */

/*
 * Copyright (C) 1998 WIDE Project.
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
 * Copyright (c) 1988 Stephen Deering.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
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
 *	@(#)igmp.c	8.1 (Berkeley) 7/19/93
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
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/kernel.h>
#include <sys/malloc.h>
#endif
#ifdef __OpenBSD__
#include <dev/rndvar.h>
#endif

#ifdef __FreeBSD__
#include <net/ethernet.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#ifdef IFT_VRRP
#include <net/if_vrrp_var.h>
#endif
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mld6_var.h>
#ifdef MLDV2
#include <netinet6/in6_msf.h>
#endif
#include <net/net_osdep.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static MALLOC_DEFINE(M_MRTABLE, "mrt", "multicast routing table");
#endif

/*
 * Protocol constants
 */

/*
 * time between repetitions of a node's initial report of interest in a
 * multicast address(in seconds)
 */
#define MLD_UNSOLICITED_REPORT_INTERVAL	10

int mldmaxsrcfilter = IP_MAX_SOURCE_FILTER;
int mldsomaxsrc = SO_MAX_SOURCE_FILTER;
int mldalways_v2 = 0;

struct router6_info *Head6;

static struct ip6_pktopts ip6_opts;
static int mld_group_timers_are_running;
static int mld_interface_timers_are_running;
static int mld_state_change_timers_are_running;
static const struct sockaddr_in6 *all_nodes_linklocal;
static const struct sockaddr_in6 *all_routers_linklocal;
#ifdef MLDV2
static const struct sockaddr_in6 *all_v2routers_linklocal;
#endif
static const int ignflags = (IN6_IFF_NOTREADY|IN6_IFF_ANYCAST) & 
			    ~IN6_IFF_TENTATIVE;

#ifdef MLDV2
static const int qhdrlen = MLD_V2_QUERY_MINLEN;	/* mldv2 query header */
static const int rhdrlen = 8;	/* mldv2 report header */
static const int ghdrlen = 20;	/* mld group report header */
static const int addrlen = sizeof(struct in6_addr);
#endif

#if defined(MLDV2) && defined(__FreeBSD__)
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet6_icmp6);
#endif
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_MLD_MAXSRCFILTER, mld_maxsrcfilter, CTLFLAG_RW,
	&mldmaxsrcfilter, IP_MAX_SOURCE_FILTER, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_MLD_SOMAXSRC, mld_somaxsrc, CTLFLAG_RW,
	&mldsomaxsrc, SO_MAX_SOURCE_FILTER, "");
SYSCTL_INT(_net_inet6_icmp6, ICMPV6CTL_MLD_ALWAYSV2, mld_alwaysv2, CTLFLAG_RW,
	&mldalways_v2, 0, "");
#endif

#define	SOURCE_RECORD_LEN(numsrc)	(numsrc * addrlen)

#define	GET_REPORT_SOURCE_HEAD(in6m, type, iasl) { \
	if ((type) == ALLOW_NEW_SOURCES) \
		(iasl) = (in6m)->in6m_source->i6ms_alw; \
	else if ((type) == BLOCK_OLD_SOURCES) \
		(iasl) = (in6m)->in6m_source->i6ms_blk; \
	else if ((type) == CHANGE_TO_INCLUDE_MODE) \
		(iasl) = (in6m)->in6m_source->i6ms_toin; \
	else if ((type) == CHANGE_TO_EXCLUDE_MODE) \
		(iasl) = (in6m)->in6m_source->i6ms_toex; \
	else { \
		if ((in6m)->in6m_state == MLD_SG_QUERY_PENDING_MEMBER) \
			(iasl) = (in6m)->in6m_source->i6ms_rec; \
		else \
			(iasl) = (in6m)->in6m_source->i6ms_cur; \
	} \
}

static void mld6_sendpkt(struct in6_multi *, int, const struct sockaddr_in6 *);

static struct mld_hdr * mld_allocbuf(struct mbuf **, int, struct in6_multi *,
				     int);
#ifdef MLDV2
static struct router6_info *find_rt6i(struct ifnet *);
void mld_sendbuf(struct mbuf *, struct ifnet *);
int mld_set_timer(struct ifnet *, struct router6_info *, struct mld_hdr *,
		  int, u_int8_t);
void mld_set_hostcompat(struct ifnet *, struct router6_info *, int);
int mld_record_queried_source(struct in6_multi *, struct mld_hdr *, int);
void mld_send_all_current_state_report(struct ifnet *);
int mld_send_current_state_report(struct mbuf **, int *, struct in6_multi *);
static int mld_create_group_record(struct mbuf *, int *, struct in6_multi *,
			    u_int16_t, u_int16_t *, u_int8_t);
static void mld_cancel_pending_response(struct ifnet *, struct router6_info *);
#endif

void
mld6_init()
{
	static u_int8_t hbh_buf[8];
	struct ip6_hbh *hbh = (struct ip6_hbh *)hbh_buf;
	u_int16_t rtalert_code = htons((u_int16_t)IP6OPT_RTALERT_MLD);

	static struct sockaddr_in6 all_nodes_linklocal0;
	static struct sockaddr_in6 all_routers_linklocal0;
#ifdef MLDV2
	static struct sockaddr_in6 all_v2routers_linklocal0;
#endif

	mld_group_timers_are_running = 0;
	mld_interface_timers_are_running = 0;
	mld_state_change_timers_are_running = 0;

	/* ip6h_nxt will be fill in later */
	hbh->ip6h_len = 0;	/* (8 >> 3) - 1 */

	/* XXX: grotty hard coding... */
	hbh_buf[2] = IP6OPT_PADN;	/* 2 byte padding */
	hbh_buf[3] = 0;
	hbh_buf[4] = IP6OPT_RTALERT;
	hbh_buf[5] = IP6OPT_RTALERT_LEN - 2;
	bcopy((caddr_t)&rtalert_code, &hbh_buf[6], sizeof(u_int16_t));

	all_nodes_linklocal0.sin6_family = AF_INET6;
	all_nodes_linklocal0.sin6_len = sizeof(struct sockaddr_in6);
	all_nodes_linklocal0.sin6_addr = in6addr_linklocal_allnodes;

	all_nodes_linklocal = &all_nodes_linklocal0;

	all_routers_linklocal0.sin6_family = AF_INET6;
	all_routers_linklocal0.sin6_len = sizeof(struct sockaddr_in6);
	all_routers_linklocal0.sin6_addr = in6addr_linklocal_allrouters;

	all_routers_linklocal = &all_routers_linklocal0;

#ifdef MLDV2
	all_v2routers_linklocal0.sin6_family = AF_INET6;
	all_v2routers_linklocal0.sin6_len = sizeof(struct sockaddr_in6);
	all_v2routers_linklocal0.sin6_addr = in6addr_linklocal_allv2routers;

	all_v2routers_linklocal = &all_v2routers_linklocal0;
#endif

	init_ip6pktopts(&ip6_opts);
	ip6_opts.ip6po_hbh = hbh;

	Head6 = NULL;
}


#ifdef MLDV2
struct router6_info *
rt6i_init(ifp)
	struct ifnet *ifp;
{
	struct router6_info *rti = NULL;

	MALLOC(rti, struct router6_info *, sizeof *rti, M_MRTABLE, M_NOWAIT);
	if (rti == NULL)
		return NULL;

	rti->rt6i_ifp = ifp;
	rti->rt6i_timer1 = 0;
	rti->rt6i_timer2 = 0;
	rti->rt6i_qrv = MLD_DEF_RV;
	rti->rt6i_qqi = MLD_DEF_QI;
	rti->rt6i_qri = MLD_DEF_QRI / MLD_TIMER_SCALE;
	rti->rt6i_type = MLD_V2_ROUTER;
	rti->rt6i_next = Head6;
	Head6 = rti;
	return (rti);
}


static struct router6_info *
find_rt6i(ifp)
	struct ifnet *ifp;
{
        register struct router6_info *rti = Head6;

        while (rti) {
                if (rti->rt6i_ifp == ifp) {
                        return rti;
                }
                rti = rti->rt6i_next;
        }
	if ((rti = rt6i_init(ifp)) == NULL)
		return NULL;
        return rti;
}
#endif /* MLDV2 */


void
#ifdef MLDV2
mld6_start_listening(in6m, type)
	struct in6_multi *in6m;
	u_int8_t type;			/* State-Change report type */
#else
mld6_start_listening(in6m)
	struct in6_multi *in6m;
#endif
{
#ifdef MLDV2
	struct mbuf *m = NULL;
	int buflen = 0;
	int timer_init = 1;		/* indicate timer initialization */
#endif
	struct sockaddr_in6 all_sa;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	/*
	 * This function must not be called before mld6_init().
	 * We've once experienced the violation of the order, so we put an
	 * explicit assertion here.
	 */
	if (all_nodes_linklocal == NULL)
		panic("mld6_start_listening: called too early");

	/*
	 * RFC2710 page 10:
	 * The node never sends a Report or Done for the link-scope all-nodes
	 * address.
	 * MLD messages are never sent for multicast addresses whose scope is 0
	 * (reserved) or 1 (node-local).
	 */
	all_sa = *all_nodes_linklocal;
	if (in6_addr2zoneid(in6m->in6m_ifp, &all_sa.sin6_addr,
	    &all_sa.sin6_scope_id) ||
	    in6_embedscope(&all_sa.sin6_addr, &all_sa)) {
		/* XXX: this should not happen! */
		in6m->in6m_timer = 0;
		in6m->in6m_state = MLD_OTHERLISTENER;
	}
	if (SA6_ARE_ADDR_EQUAL(&in6m->in6m_sa, &all_sa) ||
	    IPV6_ADDR_MC_SCOPE(&in6m->in6m_sa.sin6_addr) <
	    IPV6_ADDR_SCOPE_LINKLOCAL) {
		in6m->in6m_timer = 0;
		in6m->in6m_state = MLD_OTHERLISTENER;
	} else {
#ifdef MLDV2
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER)
			mld_send_state_change_report(&m, &buflen, in6m,
						     type, timer_init);
		else
#endif
		{
			mld6_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
			in6m->in6m_timer =
				MLD_RANDOM_DELAY(MLD_UNSOLICITED_REPORT_INTERVAL *
						 PR_FASTHZ);
			in6m->in6m_state = MLD_IREPORTEDLAST;
			mld_group_timers_are_running = 1;
		}
	}
	splx(s);
}

void
mld6_stop_listening(in6m)
	struct in6_multi *in6m;
{
	struct sockaddr_in6 all_sa, allrouter_sa;

	all_sa = *all_nodes_linklocal;
	if (in6_addr2zoneid(in6m->in6m_ifp, &all_sa.sin6_addr,
	    &all_sa.sin6_scope_id) ||
	    in6_embedscope(&all_sa.sin6_addr, &all_sa)) {
		/* XXX: this should not happen! */
		return;
	}
	/* XXX: necessary when mrouting */
	allrouter_sa = *all_routers_linklocal;
	if (in6_addr2zoneid(in6m->in6m_ifp, &allrouter_sa.sin6_addr,
	    &allrouter_sa.sin6_scope_id)) {
		/* XXX impossible */
		return;
	}
	if (in6_embedscope(&allrouter_sa.sin6_addr, &allrouter_sa)) {
		/* XXX impossible */
		return;
	}

	if (in6m->in6m_state == MLD_IREPORTEDLAST &&
	    !SA6_ARE_ADDR_EQUAL(&in6m->in6m_sa, &all_sa) &&
	    IPV6_ADDR_MC_SCOPE(&in6m->in6m_sa.sin6_addr) >
	    IPV6_ADDR_SCOPE_INTFACELOCAL) {
		mld6_sendpkt(in6m, MLD_LISTENER_DONE, &allrouter_sa);
	}
}

void
mld6_input(m, off)
	struct mbuf *m;
	int off;
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct mld_hdr *mldh;
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct in6_multi *in6m = NULL;
	struct sockaddr_in6 all_sa, mc_sa;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	struct ifmultiaddr *ifma;
#else
	struct in6_ifaddr *ia;
#endif
	int timer = 0;		/* timer value in the MLD query header */
#ifdef MLDV2
	struct mldv2_hdr *mldv2h;
	int query_type = 0;
	u_int16_t mldlen;
	struct router6_info *rt6i;
#endif

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(*mldh),);
	mldh = (struct mld_hdr *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(mldh, struct mld_hdr *, m, off, sizeof(*mldh));
	if (mldh == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
#endif
#ifdef MLDV2
	mldv2h = (struct mldv2_hdr *) mldh;
#endif

	/* source address validation */
	ip6 = mtod(m, struct ip6_hdr *); /* in case mpullup */
	if (!(IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) ||
	      IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src))) {
#if 0				/* do not log in an input path */
		log(LOG_INFO,
		    "mld6_input: src %s is not link-local (grp=%s)\n",
		    ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&mldh->mld_addr));
#endif
		/*
		 * spec (RFC2710) does not explicitly
		 * specify to discard the packet from a non link-local
		 * source address. But we believe it's expected to do so.
		 */
		m_freem(m);
		return;
	}

	/* convert the multicast address into a full sockaddr form */
	bzero(&mc_sa, sizeof(mc_sa));
	mc_sa.sin6_family = AF_INET6;
	mc_sa.sin6_len = sizeof(mc_sa);
	mc_sa.sin6_addr = mldh->mld_addr;
	if (in6_addr2zoneid(ifp, &mc_sa.sin6_addr, &mc_sa.sin6_scope_id) ||
	    in6_embedscope(&mc_sa.sin6_addr, &mc_sa)) {
		/* XXX: this should not happen! */
		m_freem(m);
		return;
	}

#ifdef MLDV2
	rt6i = find_rt6i(ifp);
	if (rt6i == NULL) {
#ifdef MLDV2_DEBUG
		printf("mld_input(): cannot find router6_info at link#%d\n", ifp->if_index);
#endif
		m_freem(m);
		return;	/* XXX */
	}
#endif /* MLDV2 */

	/*
	 * In the MLD specification, there are 3 states and a flag.
	 *
	 * In Non-Listener state, we simply don't have a membership record.
	 * In Delaying Listener state, our timer is running (in6m->in6m_timer)
	 * In Idle Listener state, our timer is not running (in6m->in6m_timer==0)
	 *
	 * The flag is in6m->in6m_state, it is set to MLD_OTHERLISTENER if
	 * we have heard a report from another member, or MLD_IREPORTEDLAST
	 * if we sent the last report.
	 */
	switch (mldh->mld_type) {
	case MLD_LISTENER_QUERY:
		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN6_IS_ADDR_UNSPECIFIED(&mldh->mld_addr) &&
		    !IN6_IS_ADDR_MULTICAST(&mldh->mld_addr))
			break;	/* print error or log stat? */

		all_sa = *all_nodes_linklocal;
		if (in6_addr2zoneid(ifp, &all_sa.sin6_addr,
		    &all_sa.sin6_scope_id) ||
		    in6_embedscope(&all_sa.sin6_addr, &all_sa)) {
			/* XXX: this should not happen! */
			break;
		}

#ifdef MLDV2
		/*
		 * MLD version and Query type check.
		 * MLDv1 Query: length = 24 octets AND Max-Resp-Code = 0
		 * MLDv2 Query: length >= 28 octets AND Max-Resp-Code != 0
		 * (MLDv1 implementation must accept only the first 24
		 * octets of the query message)
		 */
		mldlen = m->m_pkthdr.len - off;
		if (mldlen == MLD_MINLEN)
			query_type = MLD_V1_QUERY;
		else if (mldlen > MLD_MINLEN && mldlen < MLD_V2_QUERY_MINLEN) {
#ifdef MLDV2_DEBUG
			printf("mld_input: ignores MLD packet with improper length (%d)\n", mldlen);
#endif
			m_freem(m);
			return;
		} else {
			/* mldlen >= MLD_V2_QUERY_MINLEN */
			if (IN6_IS_ADDR_UNSPECIFIED(&mldh->mld_addr) &&
			    mldv2h->mld_numsrc == 0)
				query_type = MLD_V2_GENERAL_QUERY;
			else if (IN6_IS_ADDR_MULTICAST(&mldh->mld_addr) &&
				 mldv2h->mld_numsrc == 0)
				query_type = MLD_V2_GROUP_QUERY;
			else if (IN6_IS_ADDR_MULTICAST(&mldh->mld_addr) &&
				 ntohs(mldv2h->mld_numsrc) > 0)
				query_type = MLD_V2_GROUP_SOURCE_QUERY;
			else {
#ifdef MLDV2_DEBUG
				printf("mld_input: ignores MLD packet with invalid format(%d)\n", mldlen);
#endif
				m_freem(m);
				return;
			}
		}
#endif

		/*
		 * - Start the timers in all of our membership records
		 *   that the query applies to for the interface on
		 *   which the query arrived excl. those that belong
		 *   to the "all-nodes" group (ff02::1).
		 * - Restart any timer that is already running but has
		 *   A value longer than the requested timeout.
		 * - Use the value specified in the query message as
		 *   the maximum timeout.
		 */

		/*
		 * XXX: System timer resolution is too low to handle Max
		 * Response Delay, so set 1 to the internal timer even if
		 * the calculated value equals to zero when Max Response
		 * Delay is positive.
		 */
		timer = ntohs(mldh->mld_maxdelay) * PR_FASTHZ / MLD_TIMER_SCALE;
		if (timer == 0 && mldh->mld_maxdelay)
			timer = 1;

#ifdef MLDV2
		if (query_type != MLD_V1_QUERY) {
			if (mld_set_timer(ifp, rt6i, mldh, mldlen, query_type)
			    != 0) {
#ifdef MLDV2_DEBUG
				printf("XXX: mld_input: receive bad query\n");
#endif
				m_freem(m);
				return;
			}
			break;
		}
#endif

#ifdef __FreeBSD__
		for (ifma = LIST_FIRST(&ifp->if_multiaddrs);
		     ifma;
		     ifma = LIST_NEXT(ifma, ifma_link))
#else
		IFP_TO_IA6(ifp, ia);
		if (ia == NULL)
			return; /* XXX */
		for (in6m = LIST_FIRST(&ia->ia6_multiaddrs);
		     in6m;
		     in6m = LIST_NEXT(in6m, in6m_entry))
#endif
		{
#ifdef __FreeBSD__
			if (ifma->ifma_addr->sa_family != AF_INET6)
				continue;
			in6m = (struct in6_multi *)ifma->ifma_protospec;
#endif

			if (SA6_ARE_ADDR_EQUAL(&in6m->in6m_sa, &all_sa) ||
			    IPV6_ADDR_MC_SCOPE(&in6m->in6m_sa.sin6_addr) <
			    IPV6_ADDR_SCOPE_LINKLOCAL)
				continue;

			if (!IN6_IS_ADDR_UNSPECIFIED(&mldh->mld_addr) &&
			    !IN6_ARE_ADDR_EQUAL(&mldh->mld_addr,
						&in6m->in6m_sa.sin6_addr))
				continue;

			if (timer == 0) {
				/* send a report immediately */
				mld6_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
				in6m->in6m_timer = 0; /* reset timer */
				in6m->in6m_state = MLD_IREPORTEDLAST;
			} else if (in6m->in6m_timer == 0 || /*idle state*/
				   in6m->in6m_timer > timer) {
				in6m->in6m_timer = MLD_RANDOM_DELAY(timer);
				mld_group_timers_are_running = 1;
			}
		}

#ifdef MLDV2
		/*
		 * MLDv1 Querier Present is set to Older Version Querier
		 * Present Timeout seconds whenever an MLDv1 General Query
		 * is received.
		 */
		if (mldalways_v2 == 0 &&
		    IN6_ARE_ADDR_EQUAL(&mldh->mld_addr, &in6addr_any))
			mld_set_hostcompat(ifp, rt6i, query_type);
#endif
		break;

	case MLD_LISTENER_REPORT:
		/*
		 * For fast leave to work, we have to know that we are the
		 * last person to send a report for this group.  Reports
		 * can potentially get looped back if we are a multicast
		 * router, so discard reports sourced by me.
		 * Note that it is impossible to check IFF_LOOPBACK flag of
		 * ifp for this purpose, since ip6_mloopback pass the physical
		 * interface to looutput.
		 */
		if (m->m_flags & M_LOOP) /* XXX: grotty flag, but efficient */
			break;

		if (!IN6_IS_ADDR_MULTICAST(&mldh->mld_addr))
			break;

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN6_LOOKUP_MULTI(&mc_sa, ifp, in6m);
		if (in6m) {
			in6m->in6m_timer = 0; /* transit to idle state */
			in6m->in6m_state = MLD_OTHERLISTENER; /* clear flag */
		}
		break;
	default:
#if 0
		/*
		 * this case should be impossible because of filtering in
		 * icmp6_input().  But we explicitly disabled this part
		 * just in case.
		 */
		log(LOG_ERR, "mld6_input: illegal type(%d)", mldh->mld_type);
#endif
		break;
	}

	m_freem(m);
}

void
mld6_fasttimeo()
{
	struct in6_multi *in6m;
	struct in6_multistep step;
	struct ifnet *ifp = NULL;
#ifdef MLDV2
	/*
	 * Both of Current-State Record timer and State-Change Record timer
	 * are controled.
	 */
	struct router6_info *rt6i;
	struct mbuf *cm, *sm;
	int cbuflen, sbuflen;
#endif
	int s;

	/*
	 * Quick check to see if any work needs to be done, in order
	 * to minimize the overhead of fasttimo processing.
	 */
	if (!mld_group_timers_are_running && !mld_interface_timers_are_running
	    && !mld_state_change_timers_are_running)
		return;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

#ifdef MLDV2
	if (mld_interface_timers_are_running) {
		mld_interface_timers_are_running = 0;
		for (rt6i = Head6;
		     rt6i;
		     rt6i = rt6i->rt6i_next) {
			if (rt6i->rt6i_timer2 == 0)
				; /* do nothing */
			else if (--rt6i->rt6i_timer2 == 0)
				mld_send_all_current_state_report
						(rt6i->rt6i_ifp);
			else
				mld_interface_timers_are_running = 1;
		}
	}
#endif

#ifndef MLDV2
	if (!mld_group_timers_are_running)
#else
	if (!mld_group_timers_are_running &&
	    !mld_state_change_timers_are_running)
#endif
	{
		splx(s);
		return;
	}

	mld_group_timers_are_running = 0;
#ifdef MLDV2
	mld_state_change_timers_are_running = 0;
	cm = sm = NULL;
	cbuflen = sbuflen = 0;
#endif
	IN6_FIRST_MULTI(step, in6m);
	ifp = in6m->in6m_ifp;
	while (in6m != NULL) {
		if (in6m->in6m_timer == 0)
			goto next_in6m; /* do nothing */

		--in6m->in6m_timer;
		if (in6m->in6m_timer > 0) {
			mld_group_timers_are_running = 1;
			goto bypass_state_transition;
		}
#ifdef MLDV2
		if (in6m->in6m_rti->rt6i_type == MLD_V1_ROUTER) {
#endif
			mld6_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
			in6m->in6m_state = MLD_IREPORTEDLAST;
#ifdef MLDV2
		} else if ((in6m->in6m_state
			    == MLD_G_QUERY_PENDING_MEMBER) ||
			   (in6m->in6m_state
			    == MLD_SG_QUERY_PENDING_MEMBER)) {
			if ((cm != NULL) && (ifp != in6m->in6m_ifp)) {
				mld_sendbuf(cm, ifp);
				cm = NULL;
			}
			(void)mld_send_current_state_report
				(&cm, &cbuflen, in6m);
			ifp = in6m->in6m_ifp;
			in6m->in6m_state = MLD_OTHERLISTENER;
		}
#endif

	bypass_state_transition:
#ifdef MLDV2
		if (IPV6_ADDR_MC_SCOPE(&in6m->in6m_sa.sin6_addr)
		    <= IPV6_ADDR_SCOPE_LINKLOCAL)
			goto next_in6m; /* skip */

		if (in6m->in6m_source == NULL)
			goto next_in6m;

		if (in6m->in6m_source->i6ms_timer == 0)
			goto next_in6m; /* do nothing */

		--in6m->in6m_source->i6ms_timer;
		if (in6m->in6m_source->i6ms_timer > 0) {
			mld_state_change_timers_are_running = 1;
			goto next_in6m;
		}

		if ((sm != NULL) && (ifp != in6m->in6m_ifp)) {
			mld_sendbuf(sm, ifp);
			sm = NULL;
		}

		/*
		 * Check if this report was pending Source-List-Change
		 * report or not. It is only the case that robvar was
		 * not reduced here. (XXX rarely, QRV may be changed
		 * in a same timing.)
		 */
		if (in6m->in6m_source->i6ms_robvar
		    == in6m->in6m_rti->rt6i_qrv) {
			mld_send_state_change_report(&sm, &sbuflen,
						     in6m, (u_int8_t)0, (int)1);
			sm = NULL;
		} else if (in6m->in6m_source->i6ms_robvar > 0) {
			mld_send_state_change_report(&sm, &sbuflen,
						     in6m, (u_int8_t)0, (int)0);
			ifp = in6m->in6m_ifp;
		}

		if (in6m->in6m_source->i6ms_robvar != 0) {
			in6m->in6m_source->i6ms_timer =
				MLD_RANDOM_DELAY(MLDV2_UNSOL_INTVL * PR_FASTHZ);
			mld_state_change_timers_are_running = 1;
		}
#endif
	next_in6m:
		IN6_NEXT_MULTI(step, in6m);
	}

#ifdef MLDV2
	if (cm != NULL)
		mld_sendbuf(cm, ifp);
	if (sm != NULL)
		mld_sendbuf(sm, ifp);
#endif

	splx(s);
}

#ifdef MLDV2
void
mld_slowtimeo()
{
	struct router6_info *rt6i;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	for (rt6i = Head6; rt6i != 0; rt6i = rt6i->rt6i_next) {
		if (rt6i->rt6i_timer1 == 0) {
			if (rt6i->rt6i_type != MLD_V2_ROUTER)
				rt6i->rt6i_type = MLD_V2_ROUTER;
		} else if (rt6i->rt6i_timer1 > 0) {
			--rt6i->rt6i_timer1;
			if (rt6i->rt6i_timer2 > 0)
				rt6i->rt6i_timer2 = 0;
		}
	}
	splx(s);
}
#endif

static void
mld6_sendpkt(in6m, type, dst)
	struct in6_multi *in6m;
	int type;
	const struct sockaddr_in6 *dst;
{
	struct mbuf *mh;
	struct mld_hdr *mldh;
	struct ip6_hdr *ip6 = NULL;
	struct ip6_moptions im6o;
	struct ifnet *ifp = in6m->in6m_ifp;
	struct in6_ifaddr *ia = NULL;
	struct sockaddr_in6 src_sa, dst_sa;

#ifdef IFT_VRRP
	if (ifp->if_type == IFT_VRRP) {
		ifp = ((struct ifvrrp *)ifp->if_softc)->ifv_p;
		if (ifp == NULL)
			return;
	}
#endif

	/*
	 * At first, find a link local address on the outgoing interface
	 * to use as the source address of the MLD packet.
	 * We do not reject tentative addresses for MLD report to deal with
	 * the case where we first join a link-local address.
	 */
	if ((ia = in6ifa_ifpforlinklocal(ifp, ignflags)) == NULL)
		return;
	if ((ia->ia6_flags & IN6_IFF_TENTATIVE))
		ia = NULL;

	/* Allocate two mbufs to store IPv6 header and MLD header */
	mldh = mld_allocbuf(&mh, MLD_MINLEN, in6m, type);
	if (mldh == NULL)
		return;

	/* fill src/dst here */
	ip6 = mtod(mh, struct ip6_hdr *);
	ip6->ip6_src = ia ? ia->ia_addr.sin6_addr : in6addr_any;
	ip6->ip6_dst = dst ? dst->sin6_addr : in6m->in6m_sa.sin6_addr;

	/* set packet addresses in a full sockaddr_in6 form */
	bzero(&src_sa, sizeof(src_sa));
	bzero(&dst_sa, sizeof(dst_sa));
	src_sa.sin6_family = dst_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = dst_sa.sin6_len = sizeof(struct sockaddr_in6);
	src_sa.sin6_addr = ip6->ip6_src;
	dst_sa.sin6_addr = ip6->ip6_dst;
	/* 
	 * in6_addr2zoneid() and ip6_setpktaddrs() are called at actual
	 * advertisement time 
	 */
	if (in6_addr2zoneid(ifp, &src_sa.sin6_addr, &src_sa.sin6_scope_id) ||
	    in6_addr2zoneid(ifp, &dst_sa.sin6_addr, &dst_sa.sin6_scope_id)) {
		/* XXX: impossible */
		m_free(mh);
		return;
	}
	if (!ip6_setpktaddrs(mh, &src_sa, &dst_sa)) {
		m_free(mh);
		return;
	}

	mldh->mld_addr = in6m->in6m_sa.sin6_addr;
	in6_clearscope(&mldh->mld_addr); /* XXX */

	mldh->mld_cksum = in6_cksum(mh, IPPROTO_ICMPV6, sizeof(struct ip6_hdr),
				    MLD_MINLEN);

	/* construct multicast option */
	bzero(&im6o, sizeof(im6o));
	im6o.im6o_multicast_ifp = ifp;
	im6o.im6o_multicast_hlim = 1;

	/*
	 * Request loopback of the report if we are acting as a multicast
	 * router, so that the process-level routing daemon can hear it.
	 */
	im6o.im6o_multicast_loop = (ip6_mrouter != NULL);

	/* increment output statictics */
	icmp6stat.icp6s_outhist[type]++;
	icmp6_ifstat_inc(ifp, ifs6_out_msg);
	switch (type) {
	case MLD_LISTENER_QUERY:
		icmp6_ifstat_inc(ifp, ifs6_out_mldquery);
		break;
	case MLD_LISTENER_REPORT:
		icmp6_ifstat_inc(ifp, ifs6_out_mldreport);
		break;
	case MLD_LISTENER_DONE:
		icmp6_ifstat_inc(ifp, ifs6_out_mlddone);
		break;
	}

	ip6_output(mh, &ip6_opts, NULL, ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL);
}

static struct mld_hdr *
mld_allocbuf(mh, len, in6m, type)
	struct mbuf **mh;
	int len;
	struct in6_multi *in6m;
	int type;
{
	struct mbuf *md;
	struct mld_hdr *mldh;
	struct ip6_hdr *ip6;

	/*
	 * Allocate mbufs to store ip6 header and MLD header.
	 * We allocate 2 mbufs and make chain in advance because
	 * it is more convenient when inserting the hop-by-hop option later.
	 */
	MGETHDR(*mh, M_DONTWAIT, MT_HEADER);
	if (*mh == NULL)
		return NULL;
	MGET(md, M_DONTWAIT, MT_DATA);

	/* uses cluster in case of MLDv2 */
	if (md && 
	    (len > MLD_MINLEN || type == MLDV2_LISTENER_REPORT)) {
		/* XXX: assumes len is less than 2K Byte */
		MCLGET(md, M_DONTWAIT);
		if ((md->m_flags & M_EXT) == 0) {
			m_free(md);
			md = NULL;
		}
	}
	if (md == NULL) {
		m_free(*mh);
		*mh = NULL;
		return NULL;
	}
	(*mh)->m_next = md;
	md->m_next = NULL;

	(*mh)->m_pkthdr.rcvif = NULL;
	(*mh)->m_pkthdr.len = sizeof(struct ip6_hdr) + len;
	(*mh)->m_len = sizeof(struct ip6_hdr);
	MH_ALIGN(*mh, sizeof(struct ip6_hdr));

	/* fill in the ip6 header */
	ip6 = mtod(*mh, struct ip6_hdr *);
	bzero(ip6, sizeof(*ip6));
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	/* ip6_hlim will be set by im6o.im6o_multicast_hlim */
	/* ip6_src/dst will be set by mld_sendpkt() or mld_sendbuf() */

	/* fill in the MLD header as much as possible */
	md->m_len = len;
	mldh = mtod(md, struct mld_hdr *);
	bzero(mldh, len);
	mldh->mld_type = type;
	return mldh;
}

#ifdef MLDV2
void
mld_sendbuf(mh, ifp)
	struct mbuf *mh;
	struct ifnet *ifp;
{
	struct ip6_hdr *ip6;
	struct mld_report_hdr *mld_rhdr;
	struct mld_group_record_hdr *mld_ghdr;
	int len;
	u_int16_t i;
	struct ip6_moptions im6o;
	struct mbuf *md;
	struct in6_ifaddr *ia = NULL;
	struct sockaddr_in6 src_sa, dst_sa;

#ifdef IFT_VRRP
	if (ifp->if_type == IFT_VRRP) {
		ifp = ((struct ifvrrp *)ifp->if_softc)->ifv_p;
		if (ifp == NULL)
			return;
	}
#endif

	/*
	 * At first, find a link local address on the outgoing interface
	 * to use as the source address of the MLD packet.
	 * We do not reject tentative addresses for MLD report to deal with
	 * the case where we first join a link-local address.
	 */
	if ((ia = in6ifa_ifpforlinklocal(ifp, ignflags)) == NULL)
		return;
	if ((ia->ia6_flags & IN6_IFF_TENTATIVE))
		ia = NULL;

	/* 
	 * assumes IPv6 header and MLD header are located in the 1st and
	 * 2nd mbuf respecitively. (done in mld_allocbuf())
	 */
	if (mh == NULL) {
#ifdef MLDV2_DEBUG
		printf("mld_sendbuf: mbuf is NULL\n");
#endif
		return;
	}
	md = mh->m_next;

	/* fill src/dst here */
	ip6 = mtod(mh, struct ip6_hdr *);
	ip6->ip6_src = ia ? ia->ia_addr.sin6_addr : in6addr_any;
	ip6->ip6_dst = all_v2routers_linklocal->sin6_addr;

	/* set packet addresses in a full sockaddr_in6 form */
	bzero(&src_sa, sizeof(src_sa));
	bzero(&dst_sa, sizeof(dst_sa));
	src_sa.sin6_family = dst_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = dst_sa.sin6_len = sizeof(struct sockaddr_in6);
	src_sa.sin6_addr = ip6->ip6_src;
	dst_sa.sin6_addr = ip6->ip6_dst;
	/* 
	 * in6_addr2zoneid() and ip6_setpktaddrs() are called at actual
	 * advertisement time 
	 */
	if (in6_addr2zoneid(ifp, &src_sa.sin6_addr, &src_sa.sin6_scope_id) ||
	    in6_addr2zoneid(ifp, &dst_sa.sin6_addr, &dst_sa.sin6_scope_id))
		/* XXX: impossible */
		return;

	if (!ip6_setpktaddrs(mh, &src_sa, &dst_sa))
		return;

	mld_rhdr = mtod(md, struct mld_report_hdr *);
	len = sizeof(struct mld_report_hdr);
	for (i = 0; i < mld_rhdr->mld_grpnum; i++) {
		mld_ghdr = (struct mld_group_record_hdr *)
					((char *)mld_rhdr + len);
		len += ghdrlen + SOURCE_RECORD_LEN(mld_ghdr->numsrc);
		HTONS(mld_ghdr->numsrc);
	}
	HTONS(mld_rhdr->mld_grpnum);
	mld_rhdr->mld_cksum = 0;

	mld_rhdr->mld_cksum = in6_cksum(mh, IPPROTO_ICMPV6,
					sizeof(struct ip6_hdr), len);
	im6o.im6o_multicast_ifp = ifp;
	im6o.im6o_multicast_hlim = ip6_defmcasthlim;
	im6o.im6o_multicast_loop = (ip6_mrouter != NULL);

	/* XXX: ToDo: create MLDv2 statistics field */
	icmp6_ifstat_inc(ifp, ifs6_out_mldreport);
	ip6_output(mh, &ip6_opts, NULL, ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL);
}


/*
 * Timer adjustment on reception of an MLDv2 Query.
 */
#define	in6mm_src	in6m->in6m_source
int
mld_set_timer(ifp, rti, mld, mldlen, query_type)
	struct ifnet *ifp;
	struct router6_info *rti;
	struct mld_hdr *mld;
	int mldlen;
	u_int8_t query_type;
{
	struct in6_multi *in6m;
	struct in6_multistep step;
	struct mldv2_hdr *mldh = (struct mldv2_hdr *) mld;
	int timer;			/* Max-Resp-Timer */
	int timer_i = 0;		/* interface timer */
	int timer_g = 0;		/* group timer */
	int error;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	/*
	 * Parse QRV, QQI, and QRI timer values.
	 */
	if (((rti->rt6i_qrv = MLD_QRV(mldh->mld_rtval)) == 0) ||
	    (rti->rt6i_qrv > 7))
		rti->rt6i_qrv = MLD_DEF_RV;

	if ((mldh->mld_qqi > 0) && (mldh->mld_qqi < 128))
		rti->rt6i_qqi = mldh->mld_qqi;
	else if (mldh->mld_qqi >= 128)
		rti->rt6i_qqi = ((MLD_QQIC_MANT(mldh->mld_qqi) | 0x10)
				<< (MLD_QQIC_EXP(mldh->mld_qqi) + 3));
	else
		rti->rt6i_qqi = MLD_DEF_QI;

	rti->rt6i_qri = ntohs(mldh->mld_maxdelay);
	if (rti->rt6i_qri >= rti->rt6i_qqi * MLD_TIMER_SCALE)
		rti->rt6i_qri = (rti->rt6i_qqi - 1);
		/* XXX tentatively adjusted */
	else
		rti->rt6i_qri /= MLD_TIMER_SCALE;

	if ((ntohs(mldh->mld_maxdelay) > 0) &&
	    (ntohs(mldh->mld_maxdelay) < 32768))
		timer = ntohs(mldh->mld_maxdelay);
	else
		timer = (MLD_MRC_MANT(mldh->mld_maxdelay) | 0x1000)
			<< (MLD_MRC_EXP(mldh->mld_maxdelay) + 3);

	/*
	 * Set interface timer if the query is Generic Query.
	 * Get group timer if the query is not Generic Query.
	 */
	if (query_type == MLD_V2_GENERAL_QUERY) {
		timer_i = timer * PR_FASTHZ / MLD_TIMER_SCALE;
		timer_i = MLD_RANDOM_DELAY(timer_i);
		if (mld_interface_timers_are_running &&
		    (rti->rt6i_timer2 != 0) && (rti->rt6i_timer2 < timer_i))
		    	; /* don't need to update interface timer */
		else {
			rti->rt6i_timer2 = timer_i;
			mld_interface_timers_are_running = 1;
		}
	} else { /* G or SG query */
		timer_g = timer * PR_FASTHZ / MLD_TIMER_SCALE;
		timer_g = MLD_RANDOM_DELAY(timer_g);
	}

	IN6_FIRST_MULTI(step, in6m);
	while (in6m != NULL) {
		if (SS_IS_LOCAL_GROUP(&in6m->in6m_sa) || in6m->in6m_ifp != ifp)
			goto next_multi;

		if ((in6mm_src->i6ms_grpjoin == 0) &&
		    (in6mm_src->i6ms_mode == MCAST_INCLUDE) &&
		    (in6mm_src->i6ms_cur->numsrc == 0))
			goto next_multi; /* no need to consider any timer */

		if (query_type == MLD_V2_GENERAL_QUERY) {
			/* Any previously pending response to Group- or
			 * Group-and-Source-Specific Query is canceled, if 
			 * pending group timer is not sooner than new 
			 * interface timer. 
			 */
			if (!mld_group_timers_are_running)
				goto next_multi;
			if (in6m->in6m_timer <= rti->rt6i_timer2)
				goto next_multi;
			in6m->in6m_state = MLD_OTHERLISTENER;
			in6m->in6m_timer = 0;
			in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
			in6mm_src->i6ms_rec->numsrc = 0;
			goto next_multi;
		} else if (!IN6_ARE_ADDR_EQUAL(&in6m->in6m_sa.sin6_addr, &mldh->mld_addr))
			goto next_multi;

		/*
		 * If interface timer is sooner than new group timer,
		 * just ignore this Query for this group address.
		 */
		if (mld_interface_timers_are_running &&
		    (rti->rt6i_timer2 < timer_g)) {
			in6m->in6m_state = MLD_OTHERLISTENER;
			in6m->in6m_timer = 0;
			break;
		}

		/* Receive Group-Specific Query */
		if (query_type == MLD_V2_GROUP_QUERY) {
			/*
			 * Group-Source list is cleared and a single response is
			 * scheduled, and group timer is set the earliest of the
			 * remaining time for the pending report and the 
			 * selected delay.
			 */
			if ((in6m->in6m_state != MLD_G_QUERY_PENDING_MEMBER) &&
			    (in6m->in6m_state != MLD_SG_QUERY_PENDING_MEMBER)) {
				mld_group_timers_are_running = 1;
				in6m->in6m_timer = timer_g;
			} else {
				in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
				in6mm_src->i6ms_rec->numsrc = 0;
				in6m->in6m_timer = min(in6m->in6m_timer, timer_g);
			}
			in6m->in6m_state = MLD_G_QUERY_PENDING_MEMBER;
			break;
		}

		/* Receive Group-and-Source-Specific Query */
		if (in6m->in6m_state == MLD_G_QUERY_PENDING_MEMBER) {
			/*
			 * If there is a pending response for this group's
			 * Group-Specific Query, then queried sources are not
			 * recorded and pending status is not changed. Only the
			 * timer may be changed.
			 */
			 in6m->in6m_timer = min(in6m->in6m_timer, timer_g);
			 break;
		}
		/* Queried sources are augmented. */
		if ((error = mld_record_queried_source(in6m, mld, mldlen)) > 0) {
			/* XXX: ToDo: ICMPv6 error statistics */
			splx(s);
			return error;
		} else if (error == 0) {
			if (in6m->in6m_timer != 0)
				in6m->in6m_timer = min(in6m->in6m_timer, timer_g);
			else {
				mld_group_timers_are_running = 1;
				in6m->in6m_timer = timer_g;
			}
			in6m->in6m_state = MLD_SG_QUERY_PENDING_MEMBER;
		}
		break;

next_multi:
		IN6_NEXT_MULTI(step, in6m);
	} /* while */

	splx(s);
	return 0;
}

/*
 * Set MLD Host Compatibility Mode.
 */
void
mld_set_hostcompat(ifp, rti, query_ver)
	struct ifnet *ifp;
	struct router6_info *rti;
	int query_ver;
{
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else   
	int s = splnet();
#endif

	/*
	 * Keep Older Version Querier Present timer.
	 */
	if (query_ver == MLD_V1_ROUTER) {
		rti->rt6i_timer1 = rti->rt6i_qrv * rti->rt6i_qqi + rti->rt6i_qri;
		rti->rt6i_timer1 *= PR_SLOWHZ;
	}

	/*
	 * Check/set host compatibility mode. Whenever a host changes
	 * its compatability mode, cancel all its pending response and
	 * retransmission timers.
	 */
	if (rti->rt6i_timer1 > 0) {
		if (rti->rt6i_type != MLD_V1_ROUTER) {
			rti->rt6i_type = MLD_V1_ROUTER;
			mld_cancel_pending_response(ifp, rti);
		}
	}

	splx(s);
}

/*
 * Parse source addresses from MLDv2 Group-and-Source-Specific Query message
 * and merge them in a recorded source list.
 * If no pending source was recorded, return -1.
 * If some source was recorded as a reply for Group-and-Source-Specific Query,
 * return 0.
 */ 
int
mld_record_queried_source(in6m, mld, mldlen)
	struct in6_multi *in6m;
	struct mld_hdr *mld;
	int mldlen;
{
	struct in6_addr_source *curias;
	u_int16_t numsrc, i;
	int ref_count;
	struct sockaddr_in6 src;
	int recorded = 0;
	struct mldv2_hdr *mldh = (struct mldv2_hdr *) mld;

	mldlen -= qhdrlen; /* remaining source list */
	numsrc = ntohs(mldh->mld_numsrc);
	if (numsrc != mldlen / addrlen)
	    return EOPNOTSUPP; /* XXX */

	bzero(&src, sizeof(src));
	src.sin6_family = AF_INET6;
	src.sin6_len = sizeof(src);
	for (i = 0; i < numsrc && mldlen >= addrlen; i++, mldlen -= addrlen) {
		bcopy(&mldh->mld_src[i], &src, sizeof(mldh->mld_src[i]));
		if (in6mm_src->i6ms_grpjoin > 0) {
			ref_count = in6_merge_msf_source_addr(in6mm_src->i6ms_rec, &src, IMS_ADD_SOURCE);
			if (ref_count < 0) {
				in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
				in6mm_src->i6ms_rec->numsrc = 0;
				return ENOBUFS;
			}
			if (ref_count == 1)
				++in6mm_src->i6ms_rec->numsrc;
			recorded = 1;
			continue;
		}

		LIST_FOREACH(curias, in6mm_src->i6ms_cur->head, i6as_list) {
			/* sanity check */
			if (curias->i6as_addr.sin6_family != src.sin6_family)
				continue;

			if (SS_CMP(&curias->i6as_addr, <, &src))
				continue;

			if (SS_CMP(&curias->i6as_addr, ==, &src)) {
				if (in6mm_src->i6ms_mode != MCAST_INCLUDE)
					break;
				ref_count = in6_merge_msf_source_addr
					(in6mm_src->i6ms_rec,
					 &src, IMS_ADD_SOURCE);
				if (ref_count < 0) {
				 	in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
					in6mm_src->i6ms_rec->numsrc = 0;
					return ENOBUFS;
				}
				if (ref_count == 1)
					++in6mm_src->i6ms_rec->numsrc;
				recorded = 1;
				break;
			}

			/* curias->i6as_addr > src */
			if (in6mm_src->i6ms_mode == MCAST_EXCLUDE) {
				ref_count = in6_merge_msf_source_addr
						(in6mm_src->i6ms_rec,
						 &src, IMS_ADD_SOURCE);
				if (ref_count < 0) {
					in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
					in6mm_src->i6ms_rec->numsrc = 0;
					return ENOBUFS;
				}
				if (ref_count == 1)
					++in6mm_src->i6ms_rec->numsrc;
				recorded = 1;
			}

			break;
		}

		if (!curias) {
			if (in6mm_src->i6ms_mode == MCAST_EXCLUDE) {
				ref_count = in6_merge_msf_source_addr
						(in6mm_src->i6ms_rec,
						 &src, IMS_ADD_SOURCE);
				if (ref_count < 0) {
					in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
					in6mm_src->i6ms_rec->numsrc = 0;
					return ENOBUFS;
				}
				if (ref_count == 1)
					++in6mm_src->i6ms_rec->numsrc;
				recorded = 1;
			}
		}
	}

	if (i != numsrc) {
		in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
		in6mm_src->i6ms_rec->numsrc = 0;
		return EOPNOTSUPP; /* XXX */
	}

	return ((recorded == 0) ? -1 : 0);
}

/*
 * Send Current-State Report for General Query response.
 */
void
mld_send_all_current_state_report(ifp)
	struct ifnet *ifp;
{
	struct mbuf *m = NULL;
	int buflen = 0;
	struct in6_multi *in6m;
	struct in6_multistep step;

	IN6_FIRST_MULTI(step, in6m);
	while (in6m != NULL) {
		if (in6m->in6m_ifp != ifp || SS_IS_LOCAL_GROUP(&in6m->in6m_sa))
			goto next_multi;

		if (mld_send_current_state_report(&m, &buflen, in6m) != 0)
			return;
next_multi:
		IN6_NEXT_MULTI(step, in6m);
	}
	if (m != NULL)
		mld_sendbuf(m, ifp);
}

/*
 * Send Current-State Report for Group- and Group-and-Source-Sepcific Query
 * response.
 */
int
mld_send_current_state_report(m0, buflenp, in6m)
	struct mbuf **m0;	/* mbuf is inherited to put multiple group
				 * records in one message */
	int *buflenp;
	struct in6_multi *in6m;
{
	struct mbuf *m = *m0;
	u_int16_t max_len;
	u_int16_t numsrc = 0, src_once, src_done = 0;
	u_int8_t type = 0;
	int error = 0;

	if (SS_IS_LOCAL_GROUP(&in6m->in6m_sa) ||
		(in6m->in6m_ifp->if_flags & IFF_LOOPBACK) != 0)
	    return 0;

	/* MCLBYTES is the maximum length even if if_mtu is too big. */
	max_len = (in6m->in6m_ifp->if_mtu < MCLBYTES) ?
				in6m->in6m_ifp->if_mtu : MCLBYTES;

	if (in6mm_src->i6ms_mode == MCAST_INCLUDE)
		type = MODE_IS_INCLUDE;
	else if (in6mm_src->i6ms_mode == MCAST_EXCLUDE)
		type = MODE_IS_EXCLUDE;

	/*
	 * Prepare record for General, Group-Specific, and Group-and-Source-
	 * Specific Query.
	 */
	if (in6m->in6m_state == MLD_SG_QUERY_PENDING_MEMBER) {
		type = MODE_IS_INCLUDE; /* always */
		numsrc = in6mm_src->i6ms_rec->numsrc;
	} else
		numsrc = in6mm_src->i6ms_cur->numsrc;

	if (type == MODE_IS_INCLUDE && numsrc == 0)
		return 0; /* no need to send Current-State Report */

	/*
	 * If Report type is MODE_IS_EXCLUDE, a single Group Record is sent,
	 * containing as many source addresses as can fit, and the remaining
	 * source addresses are not reported.
	 */
	if (type == MODE_IS_EXCLUDE) {
		if (max_len < SOURCE_RECORD_LEN(numsrc)
		    + sizeof(struct ip6_hdr) + rhdrlen + ghdrlen)
			numsrc = (max_len - sizeof(struct ip6_hdr)
			    - rhdrlen - ghdrlen) / addrlen;
	}

	if (m == NULL) {
		mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
		if (error != 0) {
#ifdef MLDV2_DEBUG
			printf("mld_send_current_state_report: error preparing new report header 1.\n");
#endif
			return error;
		}
		m = *m0;
		*buflenp = 0;
	} else {
		if (ghdrlen + SOURCE_RECORD_LEN(numsrc) > M_TRAILINGSPACE(m)) {
			/*
			 * When remaining buffer is not enough to insert new 
			 * group record, send current buffer and create a new 
			 * buffer for this record.
			 */
			mld_sendbuf(m, in6m->in6m_ifp);
			m = NULL;
			mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (error != 0) {
#ifdef MLDV2_DEBUG
				printf("mld_send_current_state_report: error preparing new report header 2.\n");
#endif
				return error;
			}
			m = *m0;
			*buflenp = 0;
		}
	} /* m == NULL */

	if (type == MODE_IS_EXCLUDE) {
		/*
		 * The number of sources of MODE_IS_EXCLUDE record is already
		 * adjusted to fit in one buffer.
		 */
		if (mld_create_group_record(m, buflenp, in6m, numsrc,
					   &src_done, type) != numsrc) {
#ifdef MLDV2_DEBUG
			printf("mld_send_current_state_report: error of sending MODE_IS_EXCLUDE report?\n");
#endif
			m_freem(m);
			return EOPNOTSUPP; /* XXX source address insert didn't
					    * finished. strange... */
		}
	} else {
		while (1) {
			/* XXX Some security implication? */
			src_once = mld_create_group_record(m, buflenp, in6m,
							   numsrc, &src_done,
							   type);

			if (numsrc <= src_done)
				 break;	/* finish insertion */
			/*
			 * Source address insert didn't finished, so, send this 
			 * MLD report here and try to make separate message
			 * with remaining sources.
			 */
			 mld_sendbuf(m, in6m->in6m_ifp);
			 m = NULL;
			 mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (error != 0) {
#ifdef MLDV2_DEBUG
				printf("mld_send_current_state_report: error preparing additional report header.\n");
#endif
				return error;
			}
			m = *m0;
			*buflenp = 0;
		} /* while */
	}

	/*
	 * If pending query was Group-and-Source-Specific Query, pending
	 * (merged) source list is cleared.
	 */
	if (in6m->in6m_state == MLD_SG_QUERY_PENDING_MEMBER) {
		in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
		in6mm_src->i6ms_rec->numsrc = 0;
	}
	in6m->in6m_state = MLD_OTHERLISTENER;
	in6m->in6m_timer = 0;

	return 0;
}

/*
 * Send State-Change Report (Filter-Mode-Change Report and Source-List-Change
 * Report).
 * If report type is not specified (i.e., "0"), it indicates that requested
 * State-Change report may consist of Source-List-Change record. However, if
 * there is also a pending Filter-Mode-Change report for the group, Source-
 * List-Change report is not sent and kept as a scheduled report.
 */
void
mld_send_state_change_report(m0, buflenp, in6m, type, timer_init)
	struct mbuf **m0;
	int *buflenp;
	struct in6_multi *in6m;
	u_int8_t type;
	int timer_init;		/* set this when IPMulticastListen() invoked */
{
	struct mbuf *m = *m0;
	u_int16_t max_len;
	u_int16_t numsrc = 0, src_once, src_done = 0;
	int error = 0;

	if (SS_IS_LOCAL_GROUP(&in6m->in6m_sa) ||
		(in6m->in6m_ifp->if_flags & IFF_LOOPBACK) != 0)
		return;

	/*
	 * If there is pending Filter-Mode-Change report, Source-List-Change
	 * report will be merged in an another message and scheduled to be
	 * sent after Filter-Mode-Change report is sent.
	 */
	if (in6mm_src->i6ms_toex != NULL) {
		/* Initial TO_EX request must specify "type". */
		if (type == 0) {
			if (timer_init &&
			    ((in6mm_src->i6ms_alw != NULL &&
			    in6mm_src->i6ms_alw->numsrc > 0) ||
			    (in6mm_src->i6ms_blk != NULL &&
			    in6mm_src->i6ms_blk->numsrc > 0)))
				return; /* scheduled later */
			type = CHANGE_TO_EXCLUDE_MODE;
		}
	}
	if (in6mm_src->i6ms_toin != NULL) {
		/* Initial TO_IN request must specify "type". */
		if (type == 0) {
			if (timer_init &&
			    ((in6mm_src->i6ms_alw != NULL &&
			    in6mm_src->i6ms_alw->numsrc > 0) ||
			    (in6mm_src->i6ms_blk != NULL &&
			    in6mm_src->i6ms_blk->numsrc > 0)))
				return; /* scheduled later */

			type = CHANGE_TO_INCLUDE_MODE;
		}
	}
	if (timer_init) {
		in6mm_src->i6ms_robvar = in6m->in6m_rti->rt6i_qrv;
		in6mm_src->i6ms_timer
			= MLD_RANDOM_DELAY(MLD_UNSOL_INTVL * PR_FASTHZ);
	} else if (!(in6mm_src->i6ms_robvar > 0))
		return;

	/* MCLBYTES is the maximum length even if if_mtu is too big. */
	max_len = (in6m->in6m_ifp->if_mtu < MCLBYTES) ?
				in6m->in6m_ifp->if_mtu : MCLBYTES;

	/*
	 * If Report type is CHANGE_TO_EXCLUDE_MODE, a single Group Record
	 * is sent, containing as many source addresses as can fit, and the
	 * remaining source addresses are not reported.
	 * Note that numsrc may or may not be 0.
	 */
	if (type == CHANGE_TO_EXCLUDE_MODE) {
		numsrc = in6mm_src->i6ms_toex->numsrc;
		if (max_len < SOURCE_RECORD_LEN(numsrc)
			+ sizeof(struct ip6_hdr) + rhdrlen + ghdrlen)
			/* toex's numsrc should be fit in a single message. */
			numsrc = (max_len - sizeof(struct ip6_hdr)
				- rhdrlen - ghdrlen) / addrlen;
	} else if (type == CHANGE_TO_INCLUDE_MODE) {
		numsrc = in6mm_src->i6ms_toin->numsrc;
	} else { /* ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES */
		numsrc = 0;
		if (in6mm_src->i6ms_alw != NULL)
			numsrc = in6mm_src->i6ms_alw->numsrc;
		if (in6mm_src->i6ms_blk != NULL)
			numsrc = max(numsrc, in6mm_src->i6ms_blk->numsrc);
		if (numsrc == 0) {
			/*
			 * XXX following is tentative process. this should not
		 	 * be executed. this is just to avoid "loop" by timer.
			 */
			if (*m0 != NULL) {
			 	mld_sendbuf(*m0, in6m->in6m_ifp);
				*m0 = NULL;
			} else if (in6mm_src->i6ms_robvar > 0)
				--in6mm_src->i6ms_robvar;
			return;
		}
	}

	if (m == NULL) {
		mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
		if (error != 0) {
#ifdef MLDV2_DEBUG
			printf("mld_send_state_change_report: error preparing new report header.\n");
#endif
			return; /* robvar is not reduced */
		}
		m = *m0;
		*buflenp = 0;
	} else {
		if (ghdrlen + SOURCE_RECORD_LEN(numsrc)
		    > M_TRAILINGSPACE(m) - sizeof(struct ip6_hdr) - *buflenp) {
			/*
			 * When remaining buffer is not enough to insert new 
			 * group record, send current buffer and create a new
			 * buffer for this record.
			 */
			 mld_sendbuf(m, in6m->in6m_ifp);
			 m = NULL;
			 mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (error != 0) {
#ifdef MLDV2_DEBUG
				printf("mld_send_state_change_report: error preparing new report header.\n");
#endif
				return; 
			}
			m = *m0;
			*buflenp = 0;
		}
	}

	/* creates records based on type and finish this function */
	if (type == CHANGE_TO_EXCLUDE_MODE) {
		/*
		 * The number of sources of CHANGE_TO_EXCLUDE_MODE 
		 * record is already adjusted to fit in one buffer.
		 */
		if (mld_create_group_record(m, buflenp, in6m, numsrc,
					    &src_done, type) != numsrc) {
#ifdef MLDV2_DEBUG
			printf("mld_send_state_change_report: error of sending CHANGE_TO_EXCLUDE_MODE report?\n");
#endif
			m_freem(m);
			return; 
			/* XXX source address insert didn't finished.
			* strange... robvar is not reduced */
		}
		if (timer_init) {
			mld_state_change_timers_are_running = 1;
			mld_sendbuf(m, in6m->in6m_ifp);
		}

		if (--in6mm_src->i6ms_robvar != 0)
			return;

		if (in6mm_src->i6ms_toex != NULL) {
			/* For TO_EX list, it MUST be deleted after 
			 * retransmission is done. This is because 
			 * mld_fasttimo() doesn't know if the pending TO_EX 
			 * report exists or not. */
			 in6_free_msf_source_list(in6mm_src->i6ms_toex->head);
			 FREE(in6mm_src->i6ms_toex->head, M_MSFILTER);
			 FREE(in6mm_src->i6ms_toex, M_MSFILTER);
			 in6mm_src->i6ms_toex = NULL;
		 }
		 /* Prepare scheduled Source-List-Change Report */
		 if ((in6mm_src->i6ms_alw != NULL &&
		     in6mm_src->i6ms_alw->numsrc > 0) ||
		     (in6mm_src->i6ms_blk != NULL &&
		     in6mm_src->i6ms_blk->numsrc > 0)) {
			mld_state_change_timers_are_running = 1;
			in6mm_src->i6ms_robvar = in6m->in6m_rti->rt6i_qrv;
			in6mm_src->i6ms_timer
		 	     = MLD_RANDOM_DELAY(MLD_UNSOL_INTVL * PR_FASTHZ);
		} else
			in6mm_src->i6ms_timer = 0;

		return;
	}

	if (type == CHANGE_TO_INCLUDE_MODE) {
		while (1) {
			/* XXX Some security implication? */
			src_once = mld_create_group_record(m,
					buflenp, in6m, numsrc,
					&src_done, type);
			if (numsrc <= src_done)
				break;	/* finish insertion */

			mld_sendbuf(m, in6m->in6m_ifp);
			m = NULL;
			mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (error != 0) {
#ifdef MLDV2_DEBUG
				printf("mld_send_state_change_report: error preparing additional report header.\n");
#endif
				return;
			}
			m = *m0;
			*buflenp = 0;
		}

		if (timer_init) {
			mld_state_change_timers_are_running = 1;
			mld_sendbuf(m, in6m->in6m_ifp);
		}
		if (--in6mm_src->i6ms_robvar != 0)
			return;

		if (in6mm_src->i6ms_toin != NULL) {
			/* For TO_IN list, it MUST be deleted
			 * after retransmission is done. This is
			 * because mld_fasttimo() doesn't know 
			 * if the pending TO_IN report exists 
			 * or not. */
			in6_free_msf_source_list(in6mm_src->i6ms_toin->head);
			FREE(in6mm_src->i6ms_toin->head, M_MSFILTER);
			FREE(in6mm_src->i6ms_toin, M_MSFILTER);
			in6mm_src->i6ms_toin = NULL;
		}
		/* Prepare scheduled Source-List-Change Report */
		if ((in6mm_src->i6ms_alw != NULL &&
		    in6mm_src->i6ms_alw->numsrc > 0) ||
		     (in6mm_src->i6ms_blk != NULL &&
		     in6mm_src->i6ms_blk->numsrc > 0)) {
			mld_state_change_timers_are_running = 1;
			in6mm_src->i6ms_robvar = in6m->in6m_rti->rt6i_qrv;
			in6mm_src->i6ms_timer
			    = MLD_RANDOM_DELAY(MLD_UNSOL_INTVL * PR_FASTHZ);
		} else
			in6mm_src->i6ms_timer = 0;

		return;
	}

	/* ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES */
	if ((in6mm_src->i6ms_alw != NULL) &&
	    (in6mm_src->i6ms_alw->numsrc != 0)) {
		type = ALLOW_NEW_SOURCES;
	} else if ((in6mm_src->i6ms_blk != NULL) &&
		(in6mm_src->i6ms_blk->numsrc != 0)) {
		type = BLOCK_OLD_SOURCES;
	} else {
#ifdef MLDV2_DEBUG
		printf("improper allow list and block list");
#endif
		return;
	}

	while (1) {
		/* XXX Some security implication? */
		if (type == ALLOW_NEW_SOURCES)
			numsrc = in6mm_src->i6ms_alw->numsrc;
		else if (type == BLOCK_OLD_SOURCES)
			numsrc = in6mm_src->i6ms_blk->numsrc;
		else /* finish group record insertion */
			break;
		src_once = mld_create_group_record(m, buflenp, in6m,
				numsrc, &src_done, type);
		if (numsrc > src_done) {
			mld_sendbuf(m, in6m->in6m_ifp);
			m = NULL;
			mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (error != 0) {
#ifdef MLDV2_DEBUG
				printf("mld_send_state_change_report: error preparing additional report header.\n");
#endif
				return;
			}
			m = *m0;
			*buflenp = 0;
		} else { /* next group record */
			if ((type == ALLOW_NEW_SOURCES) &&
			    (in6mm_src->i6ms_blk != NULL) &&
			    (in6mm_src->i6ms_blk->numsrc != 0))
				type = BLOCK_OLD_SOURCES;
			else
				type = 0;
			src_done = 0;
		}
	}
	if (timer_init) {
		mld_state_change_timers_are_running = 1;
		mld_sendbuf(m, in6m->in6m_ifp);
	}
	if (--in6mm_src->i6ms_robvar == 0) {
		if ((in6mm_src->i6ms_alw != NULL) &&
		    (in6mm_src->i6ms_alw->numsrc != 0)) {
			in6_free_msf_source_list(in6mm_src->i6ms_alw->head);
			in6mm_src->i6ms_alw->numsrc = 0;
		}
		if ((in6mm_src->i6ms_blk != NULL) &&
	    	    (in6mm_src->i6ms_blk->numsrc != 0)) {
		    	in6_free_msf_source_list(in6mm_src->i6ms_blk->head);
			in6mm_src->i6ms_blk->numsrc = 0;
		}
		in6mm_src->i6ms_timer = 0;
	}

	return;
}

static int
mld_create_group_record(mh, buflenp, in6m, numsrc, done, type)
	struct mbuf *mh;
	int *buflenp;
	struct in6_multi *in6m;
	u_int16_t numsrc;
	u_int16_t *done;
	u_int8_t type;
{
	/* assumes IPv6 header and MLD data are separeted into different mbuf */
	struct mbuf *md = mh->m_next;
	struct ip6_hdr *ip6;
	struct mld_report_hdr *mld_rhdr;
	struct mld_group_record_hdr *mld_ghdr;
	struct in6_addr_source *ias;
	struct in6_addr_slist *iasl = NULL;
	u_int16_t i, total;
	int mfreelen;
	u_int16_t iplen;

	ip6 = mtod(mh, struct ip6_hdr *);
	iplen = ntohs(ip6->ip6_plen);
	mld_rhdr = mtod(md, struct mld_report_hdr *);
	++mld_rhdr->mld_grpnum;

	mld_ghdr = (struct mld_group_record_hdr *) 
			((char *)(mld_rhdr + 1) + *buflenp);
	mld_ghdr->record_type = type;
	mld_ghdr->auxlen = 0;
	mld_ghdr->numsrc = 0;
	bcopy(&in6m->in6m_sa.sin6_addr, &mld_ghdr->group, sizeof(mld_ghdr->group));
	*buflenp += ghdrlen;
	md->m_len += ghdrlen;
	iplen += ghdrlen;
	mh->m_pkthdr.len += ghdrlen;
	mfreelen = MCLBYTES - *buflenp;

	GET_REPORT_SOURCE_HEAD(in6m, type, iasl);
	total = 0;
	i = 0;
	if (iasl != NULL) {
		for (ias = LIST_FIRST(iasl->head); total < *done;
				total++, ias = LIST_NEXT(ias, i6as_list))
			; /* adjust a source pointer. */
		/* Insert source address to mbuf */
		for (; i < numsrc && ias != NULL && mfreelen > addrlen;
				i++, total++, mfreelen -= addrlen,
				ias = LIST_NEXT(ias, i6as_list))
			bcopy(&ias->i6as_addr.sin6_addr,
			      &mld_ghdr->src[i], sizeof(mld_ghdr->src[i]));
	}

	*done = total;

	mld_ghdr->numsrc = i;
	*buflenp += SOURCE_RECORD_LEN(i);
	md->m_len += SOURCE_RECORD_LEN(i);
	iplen += SOURCE_RECORD_LEN(i);
	ip6->ip6_plen = htons(iplen);
	mh->m_pkthdr.len += SOURCE_RECORD_LEN(i);

	return i;
}

/*
 * Cancel all MLDv2 pending response and retransmission timers on an
 * interface.
 */
static void
mld_cancel_pending_response(ifp, rti)
	struct ifnet *ifp;
	struct router6_info *rti;
{
	struct in6_multi *in6m;
	struct in6_multistep step;

	rti->rt6i_timer2 = 0;
	IN6_FIRST_MULTI(step, in6m);
	while (in6m != NULL) {
		if (in6m->in6m_ifp != ifp)
			goto next_multi;
		if (SS_IS_LOCAL_GROUP(&in6m->in6m_sa))
			goto next_multi;
		if (in6mm_src == NULL)
			goto next_multi;

		in6mm_src->i6ms_robvar = 0;
		in6mm_src->i6ms_timer = 0;
		in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
		in6mm_src->i6ms_rec->numsrc = 0;
		if (in6mm_src->i6ms_alw != NULL) {
			in6_free_msf_source_list(in6mm_src->i6ms_alw->head);
			in6mm_src->i6ms_alw->numsrc = 0;
		}
		if (in6mm_src->i6ms_blk != NULL) {
			in6_free_msf_source_list(in6mm_src->i6ms_blk->head);
			in6mm_src->i6ms_blk->numsrc = 0;
		}
		if (in6mm_src->i6ms_toin != NULL) {
			in6_free_msf_source_list(in6mm_src->i6ms_toin->head);
			/* For TO_IN list, it MUST be deleted. */
			FREE(in6mm_src->i6ms_toin->head, M_MSFILTER);
			FREE(in6mm_src->i6ms_toin, M_MSFILTER);
			in6mm_src->i6ms_toin = NULL;
		}
		if (in6mm_src->i6ms_toex != NULL) {
			in6_free_msf_source_list(in6mm_src->i6ms_toex->head);
			/* For TO_EX list, it MUST be deleted. */
			FREE(in6mm_src->i6ms_toex->head, M_MSFILTER);
			FREE(in6mm_src->i6ms_toex, M_MSFILTER);
			in6mm_src->i6ms_toex = NULL;
		}

next_multi:
		IN6_NEXT_MULTI(step, in6m);
	}
}
#undef in6mm_src

#ifndef __FreeBSD__
int
mld_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	int error;

	/* All sysctl names at this level are terminal. */
	if (namelen != 1)
		return ENOTDIR;

	switch (name[0]) {
	case ICMPV6CTL_MLD_MAXSRCFILTER:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &mldmaxsrcfilter);
		break;
	case ICMPV6CTL_MLD_SOMAXSRC:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &mldsomaxsrc);
		break;
	case ICMPV6CTL_MLD_ALWAYSV2:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &mldalways_v2);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}
#endif /* MLDV2 */
#endif /* !__FreeBSD__ */
