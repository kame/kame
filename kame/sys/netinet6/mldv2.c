/*	$KAME: mldv2.c,v 1.25 2004/07/05 03:10:14 jinmei Exp $	*/

/*
 * Copyright (c) 2002 INRIA. All rights reserved.
 *
 * Implementation of Multicast Listener Discovery, Version 2.
 * Developed by Hitoshi Asaeda, INRIA, August 2002.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of INRIA nor the names of its contributors may be
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

#ifdef __FreeBSD__
#include "opt_inet.h"
#include "opt_inet6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#ifndef MLDV2
/* 
 * this file is not used at all if MLDv2 is disabled.
 * separated from mld6.c (KAME Rev 1.92).
 * includes part of in6.c (KAME Rev 1.360).
 */
#else
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/protosw.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#ifdef __FreeBSD__
#include <sys/kernel.h>
#include <sys/malloc.h>
#endif
#ifdef __OpenBSD__
#include <dev/rndvar.h>
#endif

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mld6_var.h>
#include <netinet6/in6_msf.h>

#ifdef __FreeBSD__
#include <net/ethernet.h>
#endif
#include <net/if_arp.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#else
#ifdef __OpenBSD__
#include <netinet/if_ether.h>
#endif
#endif
#include <net/if_types.h>

#include <net/net_osdep.h>

#ifdef __FreeBSD__
static MALLOC_DEFINE(M_MRTABLE, "mrt", "multicast routing table");
#endif

#ifdef __FreeBSD__
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

#ifdef MLDV2_DEBUG
int mld_debug = 1;
#else
int mld_debug = 0;
#endif

struct router6_info *Head6;

static struct ip6_pktopts ip6_opts;
static int mld_group_timers_are_running;
static int mld_interface_timers_are_running;
static int mld_state_change_timers_are_running;
static const struct sockaddr_in6 *all_nodes_linklocal;
static const struct sockaddr_in6 *all_routers_linklocal;
static const struct sockaddr_in6 *all_v2routers_linklocal;
static const int ignflags = (IN6_IFF_NOTREADY|IN6_IFF_ANYCAST) & 
			    ~IN6_IFF_TENTATIVE;

static const int qhdrlen = MLD_V2_QUERY_MINLEN;	/* mldv2 query header */
static const int rhdrlen = 8;	/* mldv2 report header */
static const int ghdrlen = 20;	/* mld group report header */
static const int addrlen = sizeof(struct in6_addr);

#ifdef __FreeBSD__
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

static void mld_sendbuf(struct mbuf *, struct ifnet *);
int mld_set_timer(struct ifnet *, struct router6_info *, struct mld_hdr *,
		  u_int16_t, u_int8_t);
void mld_set_hostcompat(struct ifnet *, struct router6_info *, int);
int mld_record_queried_source(struct in6_multi *, struct mld_hdr *, u_int16_t);
void mld_send_all_current_state_report(struct ifnet *);
int mld_send_current_state_report(struct mbuf **, int *, struct in6_multi *);

static void mld_sendpkt(struct in6_multi *, int, const struct in6_addr *);

static struct mld_hdr * mld_allocbuf(struct mbuf **, int, struct in6_multi *,
	int);
static struct router6_info *find_rt6i(struct ifnet *);
static int mld_create_group_record(struct mbuf *, int *, struct in6_multi *,
			    u_int16_t, u_int16_t *, u_int8_t);
static void mld_cancel_pending_response(struct ifnet *, struct router6_info *);

void
mld_init()
{
	static u_int8_t hbh_buf[8];
	struct ip6_hbh *hbh = (struct ip6_hbh *)hbh_buf;
	u_int16_t rtalert_code = htons((u_int16_t)IP6OPT_RTALERT_MLD);

	static struct sockaddr_in6 all_nodes_linklocal0;
	static struct sockaddr_in6 all_routers_linklocal0;
	static struct sockaddr_in6 all_v2routers_linklocal0;

	mld_group_timers_are_running = 0;
	mld_interface_timers_are_running = 0;
	mld_state_change_timers_are_running = 0;

	/* ip6h_nxt will be fill in later */
	hbh->ip6h_len = 0;	/* (8 >> 3) - 1 */

	/* XXX: grotty hard coding... */
	hbh_buf[2] = IP6OPT_PADN;	/* 2 byte padding */
	hbh_buf[3] = 0;
	hbh_buf[4] = IP6OPT_ROUTER_ALERT;
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

	all_v2routers_linklocal0.sin6_family = AF_INET6;
	all_v2routers_linklocal0.sin6_len = sizeof(struct sockaddr_in6);
	all_v2routers_linklocal0.sin6_addr = in6addr_linklocal_allv2routers;

	all_v2routers_linklocal = &all_v2routers_linklocal0;

	ip6_initpktopts(&ip6_opts);
	ip6_opts.ip6po_hbh = hbh;

	Head6 = NULL;
}


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


void
mld_start_listening(in6m, type)
	struct in6_multi *in6m;
	u_int8_t type;			/* State-Change report type */
{
	struct mbuf *m = NULL;
	int buflen = 0;
	int timer_init = 1;		/* indicate timer initialization */
	struct sockaddr_in6 all_sa;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	/*
	 * This function must not be called before mld_init().
	 * We've once experienced the violation of the order, so we put an
	 * explicit assertion here.
	 */
	if (all_nodes_linklocal == NULL)
		panic("mld_start_listening: called too early");

	/*
	 * RFC2710 page 10:
	 * The node never sends a Report or Done for the link-scope all-nodes
	 * address.
	 * MLD messages are never sent for multicast addresses whose scope is 0
	 * (reserved) or 1 (node-local).
	 */
	all_sa = *all_nodes_linklocal;
	if (in6_addr2zoneid(in6m->in6m_ifp, &all_sa.sin6_addr,
	    &all_sa.sin6_scope_id)) {
		/* XXX: this should not happen! */
		in6m->in6m_timer = 0;
		in6m->in6m_state = MLD_OTHERLISTENER;
	}
	if (in6_embedscope(&all_sa.sin6_addr, &all_sa)) {
		/* XXX: this should not happen! */
		panic("mld_start_listening: should not happen");
	}
	if (IN6_ARE_ADDR_EQUAL(&in6m->in6m_addr, &all_sa.sin6_addr) ||
	    IPV6_ADDR_MC_SCOPE(&in6m->in6m_addr) <
	    IPV6_ADDR_SCOPE_LINKLOCAL) {
		mldlog((LOG_DEBUG,
		    "mld_start_listening: not send report for %s\n",
		    ip6_sprintf(&in6m->in6m_addr)));
		in6m->in6m_timer = 0;
		in6m->in6m_state = MLD_OTHERLISTENER;
	} else {
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			mldlog((LOG_DEBUG,
			    "mld_start_listening: send v2 report for %s\n",
			    ip6_sprintf(&in6m->in6m_addr)));
			mld_send_state_change_report(&m, &buflen, in6m,
			    type, timer_init);
		} else {
			mldlog((LOG_DEBUG,
			    "mld_start_listening: send v1 report for %s\n",
			    ip6_sprintf(&in6m->in6m_addr)));
			mld_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
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
mld_stop_listening(in6m)
	struct in6_multi *in6m;
{
	struct in6_addr allnode, allrouter;
	struct sockaddr_in6 sa6;

	sa6 = *all_nodes_linklocal;
	if (in6_addr2zoneid(in6m->in6m_ifp, &sa6.sin6_addr,
	    &sa6.sin6_scope_id) || in6_embedscope(&allrouter, &sa6)) {
		/* XXX: this should not happen! */
		return;
	}
	sa6 = *all_routers_linklocal;
	if (in6_addr2zoneid(in6m->in6m_ifp, &sa6.sin6_addr,
	    &sa6.sin6_scope_id) || in6_embedscope(&allrouter, &sa6)) {
		/* XXX impossible */
		return;
	}
	if (in6m->in6m_state == MLD_IREPORTEDLAST &&
	    !IN6_ARE_ADDR_EQUAL(&in6m->in6m_addr, &allnode) &&
	    IPV6_ADDR_MC_SCOPE(&in6m->in6m_addr) >
	    IPV6_ADDR_SCOPE_INTFACELOCAL) {
		mld_sendpkt(in6m, MLD_LISTENER_DONE, &allrouter);
	}
}

void
mld_input(m, off)
	struct mbuf *m;
	int off;
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct mld_hdr *mldh;
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct in6_multi *in6m = NULL;
	struct sockaddr_in6 all_sa, mc_sa;
#ifdef __FreeBSD__
	struct ifmultiaddr *ifma;
#else
	struct in6_ifaddr *ia;
#endif
	int timer = 0;		/* timer value in the MLD query header */
	struct mldv2_hdr *mldv2h;
	int query_ver = 0;
	int query_type;
	u_int16_t mldlen;
	struct router6_info *rt6i;

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

	/* source address validation */
	ip6 = mtod(m, struct ip6_hdr *); /* in case mpullup */
	if (!IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
		/*
		 * RFC3590 allows the IPv6 unspecified address as the source
		 * address of MLD report and done messages.  However, as this
		 * same document says, this special rule is for snooping
		 * switches and the RFC requires routers to discard MLD packets
		 * with the unspecified source address.  The RFC only talks
		 * about hosts receiving an MLD query or report in Security
		 * Considerations, but this is probably the correct intention.
		 * RFC3590 does not talk about other cases than link-local and
		 * the unspecified source addresses, but we believe the same
		 * rule should be applied.
		 * As a result, we only allow link-local addresses as the
		 * source address; otherwise, simply discard the packet.
		 */
#if 0
		/*
		 * XXX: do not log in an input path to avoid log flooding,
		 * though RFC3590 says "SHOULD log" if the source of a query
		 * is the unspecified address.
		 */
		log(LOG_INFO,
		    "mld_input: src %s is not link-local (grp=%s)\n",
		    ip6_sprintf(&ip6->ip6_src), ip6_sprintf(&mldh->mld_addr));
#endif
		goto end;
	}

	/* convert the multicast address into a full sockaddr form */
	bzero(&mc_sa, sizeof(mc_sa));
	mc_sa.sin6_family = AF_INET6;
	mc_sa.sin6_len = sizeof(mc_sa);
	mc_sa.sin6_addr = mldh->mld_addr;
	if (in6_addr2zoneid(ifp, &mc_sa.sin6_addr, &mc_sa.sin6_scope_id))
		goto end; /* XXX: this should not happen! */
	if (in6_embedscope(&mc_sa.sin6_addr, &mc_sa))
		goto end; /* XXX: this should not happen! */

	rt6i = find_rt6i(ifp);
	if (rt6i == NULL) {
		mldlog((LOG_DEBUG,
			"mld_input(): cannot find router6_info at link#%d\n",
			ifp->if_index));
		goto end;
	}

	/* 
	 * just transit to idle state preparing for MLDv1-fallback:
	 * same as mld_input in mld6.c
	 */
	if (mldh->mld_type == MLD_LISTENER_REPORT) {
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
			goto end;

		if (!IN6_IS_ADDR_MULTICAST(&mc_sa.sin6_addr))
			goto end;

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN6_LOOKUP_MULTI(mc_sa.sin6_addr, ifp, in6m);
		if (in6m) {
			in6m->in6m_timer = 0; /* transit to idle state */
			in6m->in6m_state = MLD_OTHERLISTENER; /* clear flag */
		}
		goto end;
	}

	if (mldh->mld_type != MLD_LISTENER_QUERY)
		goto end;

	/* MLDv1/v2 Query */
	if (ifp->if_flags & IFF_LOOPBACK)
		goto end;

	if (!IN6_IS_ADDR_UNSPECIFIED(&mc_sa.sin6_addr) &&
	    !IN6_IS_ADDR_MULTICAST(&mc_sa.sin6_addr))
		goto end;	/* print error or log stat? */

	/* XXX: there should be no error here! */
	all_sa = *all_nodes_linklocal;
	if (in6_addr2zoneid(ifp, &all_sa.sin6_addr, &all_sa.sin6_scope_id))
		goto end;
	if (in6_embedscope(&all_sa.sin6_addr, &all_sa))
		goto end;

	/*
	 * MLD version and Query type check.
	 * MLDv1 Query: length = 24 octets AND Max-Resp-Code = 0
	 * MLDv2 Query: length >= 28 octets AND Max-Resp-Code != 0
	 * (MLDv1 implementation must accept only the first 24
	 * octets of the query message)
	 */
	mldlen = m->m_pkthdr.len - off;
	if (mldlen > MLD_MINLEN && mldlen < MLD_V2_QUERY_MINLEN) {
		mldlog((LOG_DEBUG, "invalid MLD packet(len=%d)\n", mldlen));
		goto end;
	}
	if (mldlen == MLD_MINLEN) {
		rt6i->rt6i_type = query_ver = MLD_V1_ROUTER;
		mldlog((LOG_DEBUG, "regard it as MLDv1 Query from %s for %s\n",
		       ip6_sprintf(&ip6->ip6_src),
		       ip6_sprintf(&mldh->mld_addr)));
		goto mldv1_query;
	}

	/* MLDv2 Query: fall back to MLDv1 Query, if necessary */
	query_ver = MLD_V2_ROUTER;

	/* no buffer-overrun here, since mldlen >= MLD_V2_QUERY_MINLEN */
	mldv2h = (struct mldv2_hdr *) mldh;
	if (query_ver != MLD_V2_ROUTER)
		goto end;

	/* judge query type */
	if (IN6_IS_ADDR_UNSPECIFIED(&mc_sa.sin6_addr)) {
		if (mldv2h->mld_numsrc != 0) {
			mldlog((LOG_DEBUG, "invalid general query(numsrc=%d)\n",
				mldv2h->mld_numsrc));
			goto end;
		}
		query_type = MLD_V2_GENERAL_QUERY;
		mldlog((LOG_DEBUG, "MLDv2 general Query\n"));
		goto set_timer;
	} 
	if (IN6_IS_ADDR_MULTICAST(&mc_sa.sin6_addr)) {
		if (mldv2h->mld_numsrc == 0) {
			query_type = MLD_V2_GROUP_QUERY;
			mldlog((LOG_DEBUG, "MLDv2 group Query\n"));
		} else {
			query_type = MLD_V2_GROUP_SOURCE_QUERY;
			mldlog((LOG_DEBUG, "MLDv2 source-group Query\n"));
		}
		goto set_timer;
	}
	mldlog((LOG_DEBUG, "invalid MLDv2 Query (group=%s)\n",
		ip6_sprintf(&mldh->mld_addr)));
	goto end;

set_timer:
	if (rt6i->rt6i_type == MLD_V1_ROUTER)
		goto mldv1_query;
	if (mld_set_timer(ifp, rt6i, mldh, mldlen, query_type) != 0)
		mldlog((LOG_DEBUG, "mld_input: receive bad query\n"));
	goto end;

mldv1_query:
	/* MLDv1 Query: same as mld_input in mld6.c */
	timer = ntohs(mldh->mld_maxdelay) * PR_FASTHZ / MLD_TIMER_SCALE;
	if (timer == 0 && mldh->mld_maxdelay)
		timer = 1;

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link)
#elif defined(__FreeBSD__)
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

		if (IN6_ARE_ADDR_EQUAL(&in6m->in6m_addr, &all_sa.sin6_addr) ||
		    IPV6_ADDR_MC_SCOPE(&in6m->in6m_addr) <
		    IPV6_ADDR_SCOPE_LINKLOCAL)
			continue;

		if (!IN6_IS_ADDR_UNSPECIFIED(&mc_sa.sin6_addr) &&
		    !IN6_ARE_ADDR_EQUAL(&mc_sa.sin6_addr, &in6m->in6m_addr))
			continue;

		if (timer == 0) {
			mldlog((LOG_DEBUG, "send an MLDv1 report now\n"));
			/* send a report immediately */
			mld_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
			in6m->in6m_timer = 0; /* reset timer */
			in6m->in6m_state = MLD_IREPORTEDLAST;
		} else if (in6m->in6m_timer == 0 || /*idle state*/
			   in6m->in6m_timer > timer) {
			mldlog((LOG_DEBUG, "invoke a MLDv1 timer\n"));
			in6m->in6m_timer = MLD_RANDOM_DELAY(timer);
			mld_group_timers_are_running = 1;
		}
	}

	/*
	 * MLDv1 Querier Present is set to Older Version Querier Present 
	 * Timeout seconds whenever an MLDv1 General Query is received.
	 */
	if (mldalways_v2 == 0 &&
	    IN6_ARE_ADDR_EQUAL(&mc_sa.sin6_addr, &in6addr_any)) {
		mldlog((LOG_DEBUG, "shift to MLDv1-compat mode\n"));
		mld_set_hostcompat(ifp, rt6i, query_ver);
	}
	goto end;

end:
	m_freem(m);
	return;
}

void
mld_fasttimeo()
{
	struct in6_multi *in6m;
	struct in6_multistep step;
	struct ifnet *ifp = NULL;
	struct router6_info *rt6i;
	struct mbuf *cm, *sm;
	int cbuflen, sbuflen;
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

	if (mld_interface_timers_are_running) {
		mld_interface_timers_are_running = 0;
		for (rt6i = Head6; rt6i; rt6i = rt6i->rt6i_next) {
			if (rt6i->rt6i_timer2 == 0)
				continue; /* do nothing */

			rt6i->rt6i_timer2--;
			if (rt6i->rt6i_timer2 > 0) {
				mld_interface_timers_are_running = 1;
				continue;
			}
			mld_send_all_current_state_report(rt6i->rt6i_ifp);
		}
	}

	if (!mld_group_timers_are_running &&
	    !mld_state_change_timers_are_running) {
		splx(s);
		return;
	}

	mld_group_timers_are_running = 0;
	mld_state_change_timers_are_running = 0;
	cm = sm = NULL;
	cbuflen = sbuflen = 0;
	IN6_FIRST_MULTI(step, in6m);
	if (in6m == NULL) {
		splx(s);
		return;
	}
	ifp = in6m->in6m_ifp;
	while (in6m != NULL) {
		if (in6m->in6m_timer == 0)
			goto next_in6m; /* do nothing */

		--in6m->in6m_timer;
		if (in6m->in6m_timer > 0) {
			mld_group_timers_are_running = 1;
			goto state_change_timer;
		}

		/* Current-State Record timer */
		if (in6m->in6m_rti->rt6i_type == MLD_V1_ROUTER) {
			mldlog((LOG_DEBUG, "mld_fasttimeo: v1 report\n"));
			mld_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
			in6m->in6m_state = MLD_IREPORTEDLAST;
		} else if (in6m->in6m_state == MLD_G_QUERY_PENDING_MEMBER ||
			   in6m->in6m_state == MLD_SG_QUERY_PENDING_MEMBER) {
			if (cm != NULL && ifp != in6m->in6m_ifp) {
				mldlog((LOG_DEBUG, "mld_fasttimeo: v2 report\n"));
				mld_sendbuf(cm, ifp);
				cm = NULL;
			}
			mld_send_current_state_report(&cm, &cbuflen, in6m);
			ifp = in6m->in6m_ifp;
			in6m->in6m_state = MLD_OTHERLISTENER;
		}

	state_change_timer:
		/* State-Change Record timer */
		if (!in6_is_mld_target(&in6m->in6m_addr))
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

		if (sm != NULL && ifp != in6m->in6m_ifp) {
			mld_sendbuf(sm, ifp);
			sm = NULL;
		}

		/*
		 * Check if this report was pending Source-List-Change
		 * report or not. It is only the case that robvar was
		 * not reduced here. (XXX rarely, QRV may be changed
		 * in a same timing.)
		 */
		mldlog((LOG_DEBUG, "mld_fasttimeo: handles pending report\n"));
		if (in6m->in6m_source->i6ms_robvar
		    == in6m->in6m_rti->rt6i_qrv) {
		    	/* 
			 * immediately advertise the calculated MLD report,
			 * so you don't have to update ifp for the buffered 
			 * MLD report message.
			 */
			mld_send_state_change_report(&sm, &sbuflen, in6m, 0, 1);
			sm = NULL;
		} else if (in6m->in6m_source->i6ms_robvar > 0) {
			mld_send_state_change_report(&sm, &sbuflen, in6m, 0, 0);
			ifp = in6m->in6m_ifp;
		}

		if (in6m->in6m_source->i6ms_robvar != 0) {
			in6m->in6m_source->i6ms_timer =
				MLD_RANDOM_DELAY(MLDV2_UNSOL_INTVL * PR_FASTHZ);
			mld_state_change_timers_are_running = 1;
		}
	next_in6m:
		IN6_NEXT_MULTI(step, in6m);
	}

	if (cm != NULL)
		mld_sendbuf(cm, ifp);
	if (sm != NULL)
		mld_sendbuf(sm, ifp);

	splx(s);
}

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

static void
mld_sendpkt(in6m, type, dst)
	struct in6_multi *in6m;
	int type;
	const struct in6_addr *dst;
{
	struct mbuf *mh;
	struct mld_hdr *mldh;
	struct ip6_hdr *ip6 = NULL;
	struct ip6_moptions im6o;
	struct ifnet *ifp = in6m->in6m_ifp;
	struct in6_ifaddr *ia = NULL;

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
	ip6->ip6_dst = dst ? *dst : in6m->in6m_addr;

	mldh->mld_addr = in6m->in6m_addr;
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

#ifdef __FreeBSD__
	ip6_output(mh, &ip6_opts, NULL,
		   ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL, NULL);
#else
	ip6_output(mh, &ip6_opts, NULL,
		   ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL);
#endif
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
	if (md && (len > MLD_MINLEN || type == MLDV2_LISTENER_REPORT)) {
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

static void
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
		mldlog((LOG_DEBUG, "mld_sendbuf: mbuf is NULL\n"));
		return;
	}
	md = mh->m_next;

	/* fill src/dst here */
	/* set packet addresses in a full sockaddr_in6 form */
	bzero(&src_sa, sizeof(src_sa));
	bzero(&dst_sa, sizeof(dst_sa));
	src_sa.sin6_family = dst_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = dst_sa.sin6_len = sizeof(struct sockaddr_in6);
	src_sa.sin6_addr = ia ? ia->ia_addr.sin6_addr : in6addr_any;
	dst_sa.sin6_addr = all_v2routers_linklocal->sin6_addr;

	 /*
	  * XXX: it's impossible to fail at these functions here,
	  * but check the return value for sanity
	  */
	if (in6_addr2zoneid(ifp, &src_sa.sin6_addr, &src_sa.sin6_scope_id))
		return;
	if (in6_embedscope(&src_sa.sin6_addr, &src_sa))
		return;
	if (in6_addr2zoneid(ifp, &dst_sa.sin6_addr, &dst_sa.sin6_scope_id))
		return;
	if (in6_embedscope(&dst_sa.sin6_addr, &dst_sa))
		return;

	ip6 = mtod(mh, struct ip6_hdr *);
	ip6->ip6_src = src_sa.sin6_addr;
	ip6->ip6_dst = dst_sa.sin6_addr;
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
#ifdef __FreeBSD__
	ip6_output(mh, &ip6_opts, NULL,
		   ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL, NULL);
#else
	ip6_output(mh, &ip6_opts, NULL,
		   ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL);
#endif
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
	u_int16_t mldlen;
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

	mldlog((LOG_DEBUG, "mld_set_timer: qrv=%d,qqi=%d,qri=%d,timer=%d\n",
		rti->rt6i_qrv, rti->rt6i_qqi, rti->rt6i_qri, timer));
	/*
	 * Set interface timer if the query is Generic Query.
	 * Get group timer if the query is not Generic Query.
	 */
	if (query_type == MLD_V2_GENERAL_QUERY) {
		timer_i = timer * PR_FASTHZ / MLD_TIMER_SCALE;
		if (timer_i == 0)
			timer_i = 1;
		timer_i = MLD_RANDOM_DELAY(timer_i);
		if (mld_interface_timers_are_running &&
		    (rti->rt6i_timer2 != 0) && (rti->rt6i_timer2 < timer_i)) {
			mldlog((LOG_DEBUG, "mld_set_timer: don't do anything as appropriate I/F timer (%d) is already running (planned=%d)\n", rti->rt6i_timer2, timer_i));
		    	; /* don't need to update interface timer */
		} else {
			mldlog((LOG_DEBUG, "mld_set_timer: set I/F timer to %d\n", timer_i));
			rti->rt6i_timer2 = timer_i;
			mld_interface_timers_are_running = 1;
		}
	} else { /* G or SG query */
		timer_g = timer * PR_FASTHZ / MLD_TIMER_SCALE;
		if (timer_g == 0)
			timer_g = 1;
		timer_g = MLD_RANDOM_DELAY(timer_g);
		mldlog((LOG_DEBUG, "mld_set_timer: set group timer to %d\n", timer_g));
	}

	IN6_FIRST_MULTI(step, in6m);
	while (in6m != NULL) {
		if (!in6_is_mld_target(&in6m->in6m_addr) ||
		    in6m->in6m_ifp != ifp)
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
			mldlog((LOG_DEBUG,
			    "mld_set_timer: clears pending response\n"));
			in6m->in6m_state = MLD_OTHERLISTENER;
			in6m->in6m_timer = 0;
			in6_free_msf_source_list(in6mm_src->i6ms_rec->head);
			in6mm_src->i6ms_rec->numsrc = 0;
			goto next_multi;
		} else if (!IN6_ARE_ADDR_EQUAL(&in6m->in6m_addr,
		    &mldh->mld_addr))
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

	mldlog((LOG_DEBUG,
		"mld_set_compat: query_ver=%d for %s\n",
		query_ver, if_name(ifp)));
	/*
	 * Keep Older Version Querier Present timer.
	 */
	if (query_ver == MLD_V1_ROUTER) {
		mldlog((LOG_DEBUG, "mld_set_compat: just keep the timer\n"));
		rti->rt6i_timer1 = rti->rt6i_qrv * rti->rt6i_qqi + rti->rt6i_qri;
		rti->rt6i_timer1 *= PR_SLOWHZ;
	}

	/*
	 * Check/set host compatibility mode. Whenever a host changes
	 * its compatability mode, cancel all its pending response and
	 * retransmission timers.
	 */
	mldlog((LOG_DEBUG, "mld_set_compat: timer=%d\n", rti->rt6i_timer1));
	if (rti->rt6i_timer1 > 0) {
		if (rti->rt6i_type != MLD_V1_ROUTER) {
			mldlog((LOG_DEBUG, "mld_set_compat: "
				"set timer to MLDv1-compat mode\n"));
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
	u_int16_t mldlen;
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
		if (in6m->in6m_ifp != ifp ||
		    !in6_is_mld_target(&in6m->in6m_addr))
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
	struct mld_hdr *mldh;

	if (!in6_is_mld_target(&in6m->in6m_addr) ||
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
		mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
		if (mldh == NULL) {
			mldlog((LOG_DEBUG, "mld_send_current_state_report: error preparing new report header\n"));
			return ENOBUFS;
		}
		m = *m0;
		*buflenp = 0;
	} else {
		if (ghdrlen + SOURCE_RECORD_LEN(numsrc) > MCLBYTES - *buflenp) {
			/*
			 * When remaining buffer is not enough to insert new 
			 * group record, send current buffer and create a new 
			 * buffer for this record.
			 */
			mld_sendbuf(m, in6m->in6m_ifp);
			m = NULL;
			mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (mldh == NULL) {
				mldlog((LOG_DEBUG, "mld_send_current_state_report: error preparing new report header.\n"));
				return ENOBUFS;
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
			mldlog((LOG_DEBUG, "mld_send_current_state_report: error of sending MODE_IS_EXCLUDE report?\n"));
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
			mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (mldh == NULL) {
				mldlog((LOG_DEBUG, "mld_send_current_state_report: error preparing additional report header.\n"));
				return ENOBUFS;
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
	struct mld_hdr *mldh;

	if (!in6_is_mld_target(&in6m->in6m_addr) ||
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
		if (in6mm_src->i6ms_toex != NULL)
			numsrc = in6mm_src->i6ms_toex->numsrc;
		if (max_len < SOURCE_RECORD_LEN(numsrc)
			+ sizeof(struct ip6_hdr) + rhdrlen + ghdrlen)
			/* toex's numsrc should be fit in a single message. */
			numsrc = (max_len - sizeof(struct ip6_hdr)
				- rhdrlen - ghdrlen) / addrlen;
	} else if (type == CHANGE_TO_INCLUDE_MODE) {
		if (in6mm_src->i6ms_toin != NULL)
			numsrc = in6mm_src->i6ms_toin->numsrc;
	} else { /* ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES */
		if (in6mm_src->i6ms_alw != NULL)
			numsrc = in6mm_src->i6ms_alw->numsrc;
		if (in6mm_src->i6ms_blk != NULL)
			numsrc = max(numsrc, in6mm_src->i6ms_blk->numsrc);
		/*
		 * XXX following is tentative process. this should not 
		 * be executed. this is just to avoid "loop" by timer.
		 */
		if (numsrc == 0) {
			if (*m0 != NULL) {
				mld_sendbuf(*m0, in6m->in6m_ifp);
				*m0 = NULL;
			} else if (in6mm_src->i6ms_robvar > 0) {
				--in6mm_src->i6ms_robvar;
			}
			return;
		}
	}

	if (m == NULL) {
		mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
		if (mldh == NULL) {
			mldlog((LOG_DEBUG, "mld_send_state_change_report: error preparing new report header.\n"));
			return; /* robvar is not reduced */
		}
		m = *m0;
		*buflenp = 0;
	} else {
		if (ghdrlen + SOURCE_RECORD_LEN(numsrc) > MCLBYTES - *buflenp) {
			/*
			 * When remaining buffer is not enough to insert new 
			 * group record, send current buffer and create a new
			 * buffer for this record.
			 */
			mld_sendbuf(m, in6m->in6m_ifp);
			m = NULL;
			mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (mldh == NULL) {
				mldlog((LOG_DEBUG,
					"mld_send_state_change_report: "
					"error preparing new report header.\n"));
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
			mldlog((LOG_DEBUG, "mld_send_state_change_report: "
				"error of sending "
				"CHANGE_TO_EXCLUDE_MODE report?\n"));
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
			 * mld_fasttimeo() doesn't know if the pending TO_EX 
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
			mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (mldh == NULL) {
				mldlog((LOG_DEBUG,
					"mld_send_state_change_report: "
					"error preparing additional report header.\n"));
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
			 * because mld_fasttimeo() doesn't know 
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
		mldlog((LOG_DEBUG, "improper allow list and block list"));
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
			mldlog((LOG_DEBUG,
				"mld_send_current_state_report: "
				"re-allocbuf4\n"));
			mldh = mld_allocbuf(m0, rhdrlen, in6m, MLDV2_LISTENER_REPORT);
			if (mldh == NULL) {
				mldlog((LOG_DEBUG, 
					"mld_send_state_change_report: "
					"error preparing additional report header.\n"));
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
	bcopy(&in6m->in6m_addr, &mld_ghdr->group, sizeof(mld_ghdr->group));
	in6_clearscope(&mld_ghdr->group); /* XXX */
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
				ias = LIST_NEXT(ias, i6as_list)) {
			bcopy(&ias->i6as_addr.sin6_addr,
			      &mld_ghdr->src[i], sizeof(mld_ghdr->src[i]));
			in6_clearscope(&mld_ghdr->src[i]); /* XXX */
		}
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
		if (!in6_is_mld_target(&in6m->in6m_addr))
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
#endif /* !__FreeBSD__ */


/* 
 * provided for backward compatibility
 */
struct	in6_multi *
in6_addmulti(maddr6, ifp, errorp, delay)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp;
	int delay;		/* XXX unused */
{
	return in6_addmulti2(maddr6, ifp, errorp, 0, NULL, MCAST_EXCLUDE, 1);
}

void
in6_delmulti(in6m)
	struct in6_multi *in6m;
{
	int error;

	in6_delmulti2(in6m, &error, 0, NULL, MCAST_EXCLUDE, 1);
}

#ifndef __FreeBSD__
/*
 * Add an address to the list of IP6 multicast addresses for a given interface.
 * Add source addresses to the list also, if upstream router is MLDv2 capable
 * and the number of source is not 0.
 */
struct	in6_multi *
in6_addmulti2(maddr6, ifp, errorp, numsrc, src, mode, init)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp;
	u_int16_t numsrc;
	struct sockaddr_storage *src;
	u_int mode;			/* requested filter mode by socket */
	int init;			/* indicate initial join by socket */
{
	struct	in6_ifaddr *ia;
	struct	in6_ifreq ifr;
	struct	in6_multi *in6m;
	struct	mbuf *m = NULL;
	struct	i6as_head *newhead = NULL;/* this may become new current head */
	u_int	curmode;		/* current filter mode */
	u_int	newmode;		/* newly calculated filter mode */
	u_int16_t curnumsrc;		/* current i6ms_cur->numsrc */
	u_int16_t newnumsrc;		/* new i6ms_cur->numsrc */
	int	timer_init = 1;		/* indicate timer initialization */
	int	buflen = 0;
	u_int8_t type = 0;		/* State-Change report type */
	struct	router6_info *rt6i;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int	s = splsoftnet();
#else
	int	s = splnet();
#endif

	*errorp = 0;

	/*
	 * MCAST_INCLUDE with empty source list means (*,G) leave.
	 */
	if ((mode == MCAST_INCLUDE) && (numsrc == 0)) {
		*errorp = EINVAL;
		splx(s);
		return NULL;
	}

	/*
	 * See if address already in list.
	 */
	IN6_LOOKUP_MULTI(*maddr6, ifp, in6m);
	if (in6m != NULL) {
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			++in6m->in6m_refcount;
			splx(s);
			return in6m;
		}

		/*
		 * Found it; merge source addresses in in6m_source and send
		 * State-Change Report.
		 */
		curmode = in6m->in6m_source->i6ms_mode;
		curnumsrc = in6m->in6m_source->i6ms_cur->numsrc;
		/*
		 * Add each source address to in6m_source and get new source
		 * filter mode and its calculated source list.
		 */
		*errorp = in6_addmultisrc(in6m, numsrc, src, mode, init,
					  &newhead, &newmode, &newnumsrc);
		if (*errorp != 0) {
			splx(s);
			return NULL;
		}
		if (newhead != NULL) {
			/*
			 * Merge new source list to current pending report's
			 * source list.
			 */
			*errorp = in6_merge_msf_state(in6m, newhead, newmode,
						      newnumsrc);
			if (*errorp > 0) {
				/* State-Change Report will not be sent.
				 * Just return immediately. */
				/* Each ias linked from newhead is used by new
				 * curhead, so only newhead is freed. */
				FREE(newhead, M_MSFILTER);
				*errorp = 0; /* to make caller behave as
					      * normal */
				splx(s);
				return in6m;
			}
		} else {
			/* Only newhead was merged in a former function. */
			in6m->in6m_source->i6ms_mode = newmode;
			in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
		}

		/*
		 * Let MLD know that we have joined an IP multicast group
		 * with source list if upstream router is MLDv2 capable.
		 * If there was no pending source list change, an ALLOW or a
		 * BLOCK State-Change Report will not be sent, but a TO_IN or
		 * a TO_EX State-Change Report will be sent in any case.
		 */
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode || curnumsrc != newnumsrc) {
				if (curmode != newmode) {
					if (newmode == MCAST_INCLUDE)
						type = CHANGE_TO_INCLUDE_MODE;
					else
						type = CHANGE_TO_EXCLUDE_MODE;
				}
				mld_send_state_change_report
				(&m, &buflen, in6m, type, timer_init);
			}
		} else {
			/*
			 * If MSF's pending records exist, they must be deleted.
			 * Otherwise, ALW or BLK record will be blocked or
			 * pending list will never be clened when upstream
			 * router switches to MLDv2. XXX
			 */
			in6_clear_all_pending_report(in6m);
		}
		*errorp = 0;
		/* for this group address, init join request by the socket. */
		if (init)
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
			return (NULL);
		}

		bzero(in6m, sizeof(*in6m));
		in6m->in6m_addr = *maddr6;
		in6m->in6m_ifp = ifp;
		in6m->in6m_refcount = 1;
		IFP_TO_IA6(ifp, ia);
		if (ia == NULL) {
			free(in6m, M_IPMADDR);
			splx(s);
			*errorp = EADDRNOTAVAIL; /* appropriate? */
			return (NULL);
		}
		in6m->in6m_ia = ia;
		IFAREF(&ia->ia_ifa); /* gain a reference */
		LIST_INSERT_HEAD(&ia->ia6_multiaddrs, in6m, in6m_entry);

		/*
		 * Ask the network driver to update its multicast reception
		 * filter appropriately for the new address.
		 */
		bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
		ifr.ifr_addr.sin6_family = AF_INET6;
		ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
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
			return (NULL);
		}
		/*
		 * Let MLD6 know that we have joined a new IP6 multicast
		 * group.
		 */
		for (rt6i = Head6; rt6i != 0; rt6i = rt6i->rt6i_next) {
			if (rt6i->rt6i_ifp == in6m->in6m_ifp) {
				in6m->in6m_rti = rt6i;
				break;
			}
		}
		if (rt6i == NULL) {
			if ((rt6i = rt6i_init(in6m->in6m_ifp)) == NULL) {
				LIST_REMOVE(in6m, in6m_entry);
				free(in6m, M_IPMADDR);
				*errorp = ENOBUFS;
				splx(s);
				return NULL;
			} else
				in6m->in6m_rti = rt6i;
		}

		in6m->in6m_source = NULL;
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			splx(s);
			return in6m;
		}

		if ((*errorp = in6_addmultisrc(in6m, numsrc, src, mode, init,
		    &newhead, &newmode, &newnumsrc)) != 0) {
			in6_free_all_msf_source_list(in6m);
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
			splx(s);
			return NULL;
		}

		/* Only newhead was merged in a former function. */
		curmode = in6m->in6m_source->i6ms_mode;
		in6m->in6m_source->i6ms_mode = newmode;
		in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;

		/*
		 * Let MLD know that we have joined a new IP6 multicast
		 * group (MLD version is checked in mld_start_listening()).
		 */
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode) {
				if (newmode == MCAST_INCLUDE)
					/* never happen? */
					type = CHANGE_TO_INCLUDE_MODE;
				else
					type = CHANGE_TO_EXCLUDE_MODE;
			}
		}
		mld_start_listening(in6m, type);
	}
	if (newhead != NULL)
		/* Each ias is linked from new curhead, so only newhead
		 * is freed */
		FREE(newhead, M_MSFILTER);

	splx(s);
	return (in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti2(in6m, errorp, numsrc, src, mode, final)
	struct in6_multi *in6m;
	int *errorp;			/* return code of each sub routine */	
	u_int16_t numsrc;
	struct sockaddr_storage *src;
	u_int mode;			/* requested filter mode by socket */
	int final;			/* indicate complete leave by socket */
{
	struct	in6_ifreq ifr;
	struct	in6_ifaddr *ia;
	struct	mbuf *m = NULL;
	struct	i6as_head *newhead = NULL;/* this may become new current head */
	u_int	curmode;		/* current filter mode */
	u_int	newmode;		/* newly calculated filter mode */
	u_int16_t curnumsrc;		/* current i6ms_cur->numsrc */
	u_int16_t newnumsrc;		/* new i6ms_cur->numsrc */
	int	timer_init = 1;		/* indicate timer initialization */
	int	buflen = 0;
	u_int8_t type = 0;		/* State-Change report type */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int	s = splsoftnet();
#else
	int	s = splnet();
#endif

	if ((mode == MCAST_INCLUDE) && (numsrc == 0)) {
		*errorp = EINVAL;
		splx(s);
		return;
	}

	if (!in6_is_mld_target(&in6m->in6m_addr)) {
		if (--in6m->in6m_refcount == 0) {
			/*
			 * Unlink from list.
			 */
			LIST_REMOVE(in6m, in6m_entry);
			if (in6m->in6m_ia) {
				/* release reference */
				IFAFREE(&in6m->in6m_ia->ia_ifa);
			}

			/*
			 * Delete all references of this multicasting group
			 * from the membership arrays
			 */
			for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
				struct in6_multi_mship *imm;
				LIST_FOREACH(imm, &ia->ia6_memberships,
				    i6mm_chain) {
					if (imm->i6mm_maddr == in6m)
						imm->i6mm_maddr = NULL;
				}
			}

			/*
			 * Notify the network driver to update its multicast
			 * reception filter.
			 */
			bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
			ifr.ifr_addr.sin6_family = AF_INET6;
			ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
			ifr.ifr_addr.sin6_addr = in6m->in6m_addr;
			(*in6m->in6m_ifp->if_ioctl)(in6m->in6m_ifp,
			    SIOCDELMULTI, (caddr_t)&ifr);
			free(in6m, M_IPMADDR);
		}
		splx(s);
		return; 
	}

	curmode = in6m->in6m_source->i6ms_mode;
	curnumsrc = in6m->in6m_source->i6ms_cur->numsrc;
	/*
	 * Delete each source address from in6m_source and get new source
	 * filter mode and its calculated source list, and send State-Change
	 * Report if needed.
	 */
	if ((*errorp = in6_delmultisrc(in6m, numsrc, src, mode, final,
	    &newhead, &newmode, &newnumsrc)) != 0) {
		splx(s);
		return;
	}
	if (newhead != NULL) {
		if ((*errorp = in6_merge_msf_state
				(in6m, newhead, newmode, newnumsrc)) > 0) {
			/* State-Change Report will not be sent. Just return
			 * immediately. */
			FREE(newhead, M_MSFILTER);
			splx(s);
			return;
		}
	} else {
		/* Only newhead was merged in a former function. */
		in6m->in6m_source->i6ms_mode = newmode;
		in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
	}

	/* for this group address, final leave request by the socket. */
	if (final)
		--in6m->in6m_refcount;

	if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
		if (curmode != newmode || curnumsrc != newnumsrc) {
			if (curmode != newmode) {
				if (newmode == MCAST_INCLUDE)
					type = CHANGE_TO_INCLUDE_MODE;
				else
					type = CHANGE_TO_EXCLUDE_MODE;
			}
			mld_send_state_change_report
				(&m, &buflen, in6m, type, timer_init);
		}
	} else {
		/*
		 * If MSF's pending records exist, they must be deleted.
		 * Otherwise, ALW or BLK record will be blocked or pending
		 * list will never be clened when upstream router switches
		 * to MLDv2. XXX
		 */
		in6_clear_all_pending_report(in6m);
		if (in6m->in6m_refcount == 0) {
			in6m->in6m_source->i6ms_robvar = 0;
			mld_stop_listening(in6m);
		}
	}

	if (in6m->in6m_refcount == 0) {
		/*
		 * We cannot use timer for robstness times report
		 * transmission when in6m_refcount becomes 0, since in6m
		 * itself will be removed here. So, in this case, report
		 * retransmission will be done quickly. XXX my spec.
		 */
		timer_init = 0;
		while (in6m->in6m_source->i6ms_robvar > 0) {
			m = NULL;
			buflen = 0;
			mld_send_state_change_report
				(&m, &buflen, in6m, type, timer_init);
			if (m != NULL)
				mld_sendbuf(m, in6m->in6m_ifp);
		}
		in6_free_all_msf_source_list(in6m);
		LIST_REMOVE(in6m, in6m_entry);
		if (in6m->in6m_ia) {
			/* release reference */
			IFAFREE(&in6m->in6m_ia->ia_ifa);
		}
		bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
		ifr.ifr_addr.sin6_family = AF_INET6;
		ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifr.ifr_addr.sin6_addr = in6m->in6m_addr;
		(*in6m->in6m_ifp->if_ioctl)(in6m->in6m_ifp,
		    SIOCDELMULTI, (caddr_t)&ifr);
		free(in6m, M_IPMADDR);
	}
	*errorp = 0;
	if (newhead != NULL)
		FREE(newhead, M_MSFILTER);
	splx(s);
}

/*
 * Add an address to the list of IPv6 multicast addresses for a given interface.
 * Add source addresses to the list also, if upstream router is MLDv2 capable
 * and the number of source is not 0.
 */
struct in6_multi *
in6_modmulti2(ap, ifp, error, numsrc, src, mode, old_num, old_src, old_mode,
    init, grpjoin)
	struct in6_addr *ap;
	struct ifnet *ifp;
	int *error;			/* return code of each sub routine */
	u_int16_t numsrc, old_num;
	struct sockaddr_storage *src, *old_src;
	u_int mode, old_mode;		/* requested/current filter mode */
	int init;			/* indicate initial join by socket */
	u_int grpjoin;			/* on/off of (*,G) join by socket */
{
	struct mbuf *m = NULL;
	struct in6_multi *in6m;
	struct in6_ifreq ifr;
	struct in6_ifaddr *ia;
	struct i6as_head *newhead = NULL;/* this becomes new ims_cur->head */
	u_int curmode;			/* current filter mode */
	u_int newmode;			/* newly calculated filter mode */
	u_int16_t newnumsrc;		/* new ims_cur->numsrc */
	u_int16_t curnumsrc;		/* current ims_cur->numsrc */
	int timer_init = 1;		/* indicate timer initialization */
	int buflen = 0;
	u_int8_t type = 0;		/* State-Change report type */
	struct router6_info *rti;
	int s;

	*error = 0; /* initialize */

	if ((mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE) ||
		(old_mode != MCAST_INCLUDE && old_mode != MCAST_EXCLUDE)) {
	    *error = EINVAL;
	    return NULL;
	}

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	/*
	 * See if address already in list.
	 */
	IN6_LOOKUP_MULTI(*ap, ifp, in6m);

	if (in6m != NULL) {
		/*
		* If requested multicast address is local address, update
		* the condition, join or leave, based on a requested filter.
		*/
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			if (numsrc != 0) {
				mldlog((LOG_DEBUG,
				    "in6_modmulti: "
				    "source filter not supported for %s\n",
				    ip6_sprintf(&in6m->in6m_addr)));
				splx(s);
				*error = EINVAL;
				return NULL;
				/*
				 * source filter is not supported for
				 * local group address.
				 */
			}
			if (mode == MCAST_INCLUDE) {
				if (--in6m->in6m_refcount == 0) {
					/*
					 * Unlink from list.
					 */
					LIST_REMOVE(in6m, in6m_entry);
					IFAFREE(&in6m->in6m_ia->ia_ifa);
					/*
					 * Notify the network driver to update
					 * its multicast reception filter.
					 */
					ifr.ifr_addr.sin6_family = AF_INET6;
					ifr.ifr_addr.sin6_len =
					    sizeof(struct sockaddr_in6);
					bcopy(&in6m->in6m_addr,
					    &ifr.ifr_addr.sin6_addr,
					    sizeof(ifr.ifr_addr.sin6_addr));
					(*in6m->in6m_ifp->if_ioctl)(in6m->in6m_ifp,
					    SIOCDELMULTI, (caddr_t)&ifr);
					free(in6m, M_IPMADDR);
				}
				splx(s);
				return NULL; /* not an error! */
			} else if (mode == MCAST_EXCLUDE) {
				++in6m->in6m_refcount;
				splx(s);
				return in6m;
			}
		}

		curmode = in6m->in6m_source->i6ms_mode;
		curnumsrc = in6m->in6m_source->i6ms_cur->numsrc;
		*error = in6_modmultisrc(in6m, numsrc, src, mode, old_num,
					 old_src, old_mode, grpjoin,
					 &newhead, &newmode, &newnumsrc);
		if (*error != 0) {
			splx(s);
			return NULL;
		}
		if (newhead != NULL) {
			/*
			 * Merge new source list to current pending report's
			 * source list.
			 */
			*error = in6_merge_msf_state(in6m, newhead, newmode,
						     newnumsrc);
			if (*error > 0) {
				/*
				 * State-Change Report will not be sent.
				 * Just return immediately.
				 */
				FREE(newhead, M_MSFILTER);
				splx(s);
				return in6m;
			}
		} else {
			/* Only newhead was merged. */
			in6m->in6m_source->i6ms_mode = newmode;
			in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
		}

		/*
		 * Let MLD know that we have joined an IPv6 multicast group with
		 * source list if upstream router is MLDv2 capable.
		 * If there was no pending source list change, an ALLOW or a
		 * BLOCK State-Change Report will not be sent, but a TO_IN or a
		 * TO_EX State-Change Report will be sent in any case.
		 */
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode || curnumsrc != newnumsrc ||
			    old_num) {
				if (curmode != newmode) {
					if (newmode == MCAST_INCLUDE)
						type = CHANGE_TO_INCLUDE_MODE;
					else
						type = CHANGE_TO_EXCLUDE_MODE;
				}
				mld_send_state_change_report(&m, &buflen, in6m,
				    type, timer_init);
			}
		} else {
			/*
			 * If MSF's pending records exist, they must be deleted.
			 */
			in6_clear_all_pending_report(in6m);
		}
		*error = 0;
		/* for this group address, initial join request by the socket. */
		if (init)
			++in6m->in6m_refcount;

	} else {
		/*
		 * If there is some sources to be deleted, or if the request is
		 * join a local group address with some filtered address,
		 * return.
		 */
		if ((old_num != 0) || (!in6_is_mld_target(ap) && numsrc != 0)) {
			*error = EINVAL;
			splx(s);
			return NULL;
		}

		/*
		 * New address; allocate a new multicast record and link it into
		 * the interface's multicast list.
		 */
		in6m = (struct in6_multi *)malloc(sizeof(*in6m), M_IPMADDR,
		    M_NOWAIT);
		if (in6m == NULL) {
			*error = ENOBUFS;
			splx(s);
			return NULL;
		}

		bzero(in6m, sizeof(*in6m));
		in6m->in6m_addr = *ap;
		in6m->in6m_ifp = ifp;
		in6m->in6m_refcount = 1;
		in6m->in6m_timer = 0;
		IFP_TO_IA6(ifp, ia);
		if (ia == NULL) {
			free(in6m, M_IPMADDR);
			*error = ENOBUFS /*???*/;
			splx(s);
			return NULL;
		}
		in6m->in6m_ia = ia;
		IFAREF(&in6m->in6m_ia->ia_ifa);
		LIST_INSERT_HEAD(&ia->ia6_multiaddrs, in6m, in6m_entry);
		/*
		 * Ask the network driver to update its multicast reception
		 * filter appropriately for the new address.
		 */
		bzero(&ifr.ifr_addr, sizeof(struct sockaddr_in6));
		ifr.ifr_addr.sin6_family = AF_INET6;
		ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifr.ifr_addr.sin6_addr = *ap;
		if ((ifp->if_ioctl == NULL) ||
		    (*ifp->if_ioctl)(ifp, SIOCADDMULTI, (caddr_t)&ifr) != 0) {
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
			*error = EINVAL /*???*/;
			splx(s);
			return NULL;
		}

		for (rti = Head6; rti != 0; rti = rti->rt6i_next) {
			if (rti->rt6i_ifp == in6m->in6m_ifp) {
				in6m->in6m_rti = rti;
				break;
			}
		}
		if (rti == 0) {
			if ((rti = rt6i_init(in6m->in6m_ifp)) == NULL) {
				LIST_REMOVE(in6m, in6m_entry);
				free(in6m, M_IPMADDR);
				*error = ENOBUFS;
				splx(s);
				return NULL;
			} else
				in6m->in6m_rti = rti;
		}

		in6m->in6m_source = NULL;
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			splx(s);
			return in6m;
		}

		if ((*error = in6_modmultisrc(in6m, numsrc, src, mode, 0, NULL,
		    MCAST_INCLUDE, grpjoin, &newhead, &newmode,
		    &newnumsrc)) != 0) {
			in6_free_all_msf_source_list(in6m);
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
			splx(s);
			return NULL;
		}
		/* Only newhead was merged in a former function. */
		curmode = in6m->in6m_source->i6ms_mode;
		in6m->in6m_source->i6ms_mode = newmode;
		in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;

		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode) {
				if (newmode == MCAST_INCLUDE) {
					/* never happen??? */
					type = CHANGE_TO_INCLUDE_MODE;
				} else
					type = CHANGE_TO_EXCLUDE_MODE;
			}
			mld_send_state_change_report(&m, &buflen, in6m, type,
			    timer_init);
		} else {
			struct in6_multi_mship *imm;
			/*
			 * If MSF's pending records exist, they must be deleted.
			 */
			in6_clear_all_pending_report(in6m);
			imm = in6_joingroup(in6m->in6m_ifp, &in6m->in6m_addr,
			    error, 0);
			if (imm) {
				LIST_INSERT_HEAD(&ia->ia6_multiaddrs, in6m,
				    in6m_entry);
			} else {
				mldlog((LOG_WARNING,
				    "in6_modmulti: addmulti failed for "
				    "%s on %s (errno=%d)\n",
				    ip6_sprintf(&in6m->in6m_addr),
				    if_name(in6m->in6m_ifp), *error));
			}
		}
		*error = 0;
	}
	if (newhead != NULL)
		FREE(newhead, M_MSFILTER);

	splx(s);
	return in6m;
}

#else /* not FreeBSD */

/*
 * Add an address to the list of IP6 multicast addresses for a given interface.
 * Add source addresses to the list also, if upstream router is MLDv2 capable
 * and the number of source is not 0.
 */
struct	in6_multi *
in6_addmulti2(maddr6, ifp, errorp, numsrc, src, mode, init)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp;
	u_int16_t numsrc;
	struct sockaddr_storage *src;
	u_int mode;			/* requested filter mode by socket */
	int init;			/* indicate initial join by socket */
{
	struct in6_multi *in6m;
	struct ifmultiaddr *ifma;
	struct sockaddr_in6 sa6;
	struct mbuf *m = NULL;
	struct i6as_head *newhead = NULL;/* this may become new ims_cur->head */
	u_int curmode;			/* current filter mode */
	u_int newmode;			/* newly calculated filter mode */
	u_int16_t curnumsrc;		/* current ims_cur->numsrc */
	u_int16_t newnumsrc;		/* new ims_cur->numsrc */
	int timer_init = 1;		/* indicate timer initialization */
	int buflen = 0;
	u_int8_t type = 0;		/* State-Change report type */
	struct router6_info *rti;
	int	s = splnet();

	*errorp = 0;

	/*
	 * MCAST_INCLUDE with empty source list means (*,G) leave.
	 */
	if ((mode == MCAST_INCLUDE) && (numsrc == 0)) {
	    *errorp = EINVAL;
	    splx(s);
	    return NULL;
	}
	/*
	 * Call generic routine to add membership or increment
	 * refcount.  It wants addresses in the form of a sockaddr,
	 * so we build one here (being careful to zero the unused bytes).
	 */
	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(struct sockaddr_in6);
	sa6.sin6_addr = *maddr6;
	*errorp = if_addmulti(ifp, (struct sockaddr *)&sa6, &ifma);
	if (*errorp) {
		splx(s);
		return NULL;
	}

	/*
	 * If ifma->ifma_protospec is null, then if_addmulti() created
	 * a new record.  Otherwise, we are done.
	 */
	if (ifma->ifma_protospec != 0) {
		in6m = (struct in6_multi *) ifma->ifma_protospec;
		/*
		 * Found it; merge source addresses in in6m_source and send
		 * State-Change Report if needed, and increment the reference
		 * count. just return if group address is not the target of 
		 * MLDv2 (i.e. ffx1::/16, ff02::1).  (ifma_refcount is already
		 * counted up in if_addmulti())
		 */
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			splx(s);
			return in6m;
		}

		curmode = in6m->in6m_source->i6ms_mode;
		curnumsrc = in6m->in6m_source->i6ms_cur->numsrc;
		/*
	 	 * Add each source address to in6m_source and get new source
		 * filter mode and its calculated source list.
		 */
		if ((*errorp = in6_addmultisrc(in6m, numsrc, src, mode, init,
			 	    &newhead, &newmode, &newnumsrc)) != 0) {
			splx(s);
			return NULL;
		}
		if (newhead != NULL) {
			mldlog((LOG_DEBUG, "in6_addmultisrc: non-NULL newhead\n"));
			/*
			 * Merge new source list to current pending report's 
			 * source list.
			 */
			if ((*errorp = in6_merge_msf_state
					(in6m, newhead, newmode, newnumsrc)) > 0) {
				mldlog((LOG_DEBUG, "in6_addmultisrc: in6_merge_msf_state failed\n"));
				/* 
				 * State-Change Report will not be sent. Just 
				 * return immediately. 
				 * Each ias linked from newhead is used by new 
				 * curhead, so only newhead is freed. 
				 */
				FREE(newhead, M_MSFILTER);
				*errorp = 0; /* to make caller behave as normal */
				splx(s);
				return in6m;
			}
		} else {
			mldlog((LOG_DEBUG, "in6_addmultisrc: NULL newhead\n"));
			/* Only newhead was merged in a former function. */
			in6m->in6m_source->i6ms_mode = newmode;
			in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
		}

		/*
	 	 * Let MLD know that we have joined an IPv6 multicast group with
		 * source list if upstream router is MLDv2 capable.
		 * If there was no pending source list change, an ALLOW or a
		 * BLOCK State-Change Report will not be sent, but a TO_IN or a
		 * TO_EX State-Change Report will be sent in any case.
		 */
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode || curnumsrc != newnumsrc) {
				if (curmode != newmode) {
					if (newmode == MCAST_INCLUDE)
						type = CHANGE_TO_INCLUDE_MODE;
					else
						type = CHANGE_TO_EXCLUDE_MODE;
				}
				mldlog((LOG_DEBUG, "in6_addmultisrc: send current status\n"));
				mld_send_state_change_report
					(&m, &buflen, in6m, type, timer_init);
			}
			 else {
				mldlog((LOG_DEBUG, "in6_addmultisrc: do nothing since there's no change (mode=%d->%d, numsrc=%d->%d)\n", curmode, newmode, curnumsrc, newnumsrc));
			}
		} else {
			mldlog((LOG_DEBUG, "in6_addmultisrc: clear MLDv2 stat since I'm MLDv1\n"));
			/*
			 * If MSF's pending records exist, they must be deleted.
			 * Otherwise, ALW or BLK record will be blocked or pending
			 * list will never be cleaned when upstream router 
			 * switches to MLDv2. XXX
			 */
			 in6_clear_all_pending_report(in6m);
		 }
		 *errorp = 0;
		splx(s);
		return ifma->ifma_protospec;
	}

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
	in6m->in6m_refcount = 1;
	in6m->in6m_ifma = ifma;
	ifma->ifma_protospec = in6m;
	LIST_INSERT_HEAD(&in6_multihead, in6m, in6m_entry);

	/*
	 * Let MLD6 know that we have joined a new IPv6 multicast
	 * group.
	 */
	for (rti = Head6; rti != 0; rti = rti->rt6i_next) {
		if (rti->rt6i_ifp == in6m->in6m_ifp) {
		    in6m->in6m_rti = rti;
		    break;
		}
	}
	if (rti == NULL) {
		if ((rti = rt6i_init(in6m->in6m_ifp)) == NULL) {
			 LIST_REMOVE(in6m, in6m_entry);
			 free(in6m, M_IPMADDR);
			 *errorp = ENOBUFS;
			 splx(s);
			 return NULL;
	    	}
		in6m->in6m_rti = rti;
	}

	in6m->in6m_source = NULL;
	if (!in6_is_mld_target(&in6m->in6m_addr)) {
		splx(s);
		return in6m;
	}

	if ((*errorp = in6_addmultisrc(in6m, numsrc, src, mode, init,
	    &newhead, &newmode, &newnumsrc)) != 0) {
		in6_free_all_msf_source_list(in6m);
		LIST_REMOVE(in6m, in6m_entry);
		free(in6m, M_IPMADDR);
		splx(s);
		return NULL;
	}
	/* Only newhead was merged in a former function. */
	curmode = in6m->in6m_source->i6ms_mode;
	in6m->in6m_source->i6ms_mode = newmode;
	in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;

	/*
	 * Let MLD know that we have joined a new IPv6 multicast group
	 * (MLD version is checked in mld_start_listening()).
	 */
	if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
		if (curmode != newmode) {
			if (newmode == MCAST_INCLUDE)
				/* never happen? */
				type = CHANGE_TO_INCLUDE_MODE;
			else 
				type = CHANGE_TO_EXCLUDE_MODE;
		}
	}
	mld_start_listening(in6m, type);
	*errorp = 0;
	if (newhead != NULL)
	    /* Each i6as is linked from new curhead, so only newhead (not
	     * ias_list) is freed */
	    FREE(newhead, M_MSFILTER);
	splx(s);
	return (in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti2(in6m, error, numsrc, src, mode, final)
	struct in6_multi *in6m;
	int *error;			/* return code of each sub routine */	
	u_int16_t numsrc;
	struct sockaddr_storage *src;
	u_int mode;			/* requested filter mode by socket */
	int final;			/* indicate complete leave by socket */
{
	struct mbuf *m = NULL;
	struct i6as_head *newhead = NULL;/* this may become new ims_cur->head */
	u_int curmode;			/* current filter mode */
	u_int newmode;			/* newly calculated filter mode */
	u_int16_t curnumsrc;		/* current ims_cur->numsrc */
	u_int16_t newnumsrc;		/* new ims_cur->numsrc */
	int timer_init = 1;		/* indicate timer initialization */
	int buflen = 0;
	u_int8_t type = 0;		/* State-Change report type */
	struct ifmultiaddr *ifma = in6m->in6m_ifma;
	int	s = splnet();

	if ((mode == MCAST_INCLUDE) && (numsrc == 0)) {
		*error = EINVAL;
		splx(s);
		return;
	}
	if (!in6_is_mld_target(&in6m->in6m_addr)) {
		if (ifma->ifma_refcount == 1) {
			ifma->ifma_protospec = 0;
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
		}
		if_delmulti(ifma->ifma_ifp, ifma->ifma_addr);
		splx(s);
		return;
	}

	curmode = in6m->in6m_source->i6ms_mode;
	curnumsrc = in6m->in6m_source->i6ms_cur->numsrc;
	/*
	 * Delete each source address from inm_source and get new source
	 * filter mode and its calculated source list, and send State-Change
	 * Report if needed.
	 */
	if ((*error = in6_delmultisrc(in6m, numsrc, src, mode, final,
				      &newhead, &newmode, &newnumsrc)) != 0) {
		splx(s);
		return;
	}
	if (newhead != NULL) {
		if ((*error = in6_merge_msf_state
				(in6m, newhead, newmode, newnumsrc)) > 0) {
			mldlog((LOG_DEBUG, "in6_delmulti: state-change report not sent, (error=%d)\n", *error));
			/* State-Change Report will not be sent. Just return 
			 * immediately. */
			FREE(newhead, M_MSFILTER);
			splx(s);
			return;
		}
	} else {
		/* Only newhead was merged in a former function. */
		in6m->in6m_source->i6ms_mode = newmode;
		in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
	}

	if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
		if (curmode != newmode || curnumsrc != newnumsrc) {
			if (curmode != newmode) {
				if (newmode == MCAST_INCLUDE)
					type = CHANGE_TO_INCLUDE_MODE;
				else
					type = CHANGE_TO_EXCLUDE_MODE;
			}
			mld_send_state_change_report
				(&m, &buflen, in6m, type, timer_init);
		}
	} else {
		/*
		 * If MSF's pending records exist, they must be deleted.
		 * Otherwise, ALW or BLK record will be blocked or pending
		 * list will never be cleaned when upstream router switches
		 * to MLDv2 (XXX)
		 */
		in6_clear_all_pending_report(in6m);
		if (in6m->in6m_refcount == 0) {
			in6m->in6m_source->i6ms_robvar = 0;
			mld_stop_listening(in6m);
		}
	}
	/*
	 * If this is a final leave request by the socket, decrease refcount.
	 */
	if (final) {
		if (ifma->ifma_refcount == 1) {
			/*
			 * We cannot use timer for robstness times report
			 * transmission when ifma->ifma_refcount becomes 0,
			 * since in6m itself will be removed here. So, in 
			 * this case, report retransmission will be done 
			 * quickly.XXX my spec.
			 */
			while (in6m->in6m_source->i6ms_robvar > 0) {
				m = NULL;
				buflen = 0;
				mld_send_state_change_report
					(&m, &buflen, in6m, type, 0);
				if (m != NULL)
					mld_sendbuf(m, in6m->in6m_ifp);
			}
			/*
			 * Unlink from list.
			 */
			in6_free_all_msf_source_list(in6m);
			ifma->ifma_protospec = 0;
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
		}
		if_delmulti(ifma->ifma_ifp, ifma->ifma_addr);
	}
	*error = 0;
	if (newhead != NULL)
		FREE(newhead, M_MSFILTER);
	splx(s);
}

/*
 * Add an address to the list of IPv6 multicast addresses for a given interface.
 * Add source addresses to the list also, if upstream router is MLDv2 capable
 * and the number of source is not 0.
 */
struct in6_multi *
in6_modmulti2(ap, ifp, error, numsrc, src, mode,
		old_num, old_src, old_mode, init, grpjoin)
	struct in6_addr *ap;
	struct ifnet *ifp;
	int *error;			/* return code of each sub routine */
	u_int16_t numsrc, old_num;
	struct sockaddr_storage *src, *old_src;
	u_int mode, old_mode;		/* requested/current filter mode */
	int init;			/* indicate initial join by socket */
	u_int grpjoin;			/* on/off of (*,G) join by socket */
{
	struct mbuf *m = NULL;
	struct in6_multi *in6m;
	struct ifmultiaddr *ifma = NULL;
	struct i6as_head *newhead = NULL;/* this becomes new i6ms_cur->head */
	u_int curmode;			/* current filter mode */
	u_int newmode;			/* newly calculated filter mode */
	u_int16_t curnumsrc;		/* current i6ms_cur->numsrc */
	u_int16_t newnumsrc;		/* new i6ms_cur->numsrc */
	int timer_init = 1;		/* indicate timer initialization */
	int buflen = 0;
	u_int8_t type = 0;		/* State-Change report type */
	struct router6_info *rti;
	int s;

	*error = 0; /* initialize */

	if ((mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE) ||
	    (old_mode != MCAST_INCLUDE && old_mode != MCAST_EXCLUDE)) {
		*error = EINVAL;
		return NULL;
	}

	s = splnet();

	/*
	 * See if address already in list.
	 */
	IN6_LOOKUP_MULTI(*ap, ifp, in6m);

	if (in6m != NULL) {
		/*
		 * If requested multicast address is local address, update
		 * the condition, join or leave, based on a requested filter.
		 */
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			if (numsrc != 0) {
				mldlog((LOG_DEBUG,
				    "in6_modmulti: source filter not supported for %s\n",
				    ip6_sprintf(&in6m->in6m_addr)));
				splx(s);
				*error = EINVAL;
				return NULL;
				/*
				 * source filter is not supported for
				 * local group address.
				 */
			}
			if (mode == MCAST_INCLUDE) {
				if (ifma->ifma_refcount == 1) {
					ifma->ifma_protospec = 0;
					LIST_REMOVE(in6m, in6m_entry);
					free(in6m, M_IPMADDR);
				}
				if_delmulti(ifma->ifma_ifp, ifma->ifma_addr);
				splx(s);
				return NULL; /* not an error! */
			} else if (mode == MCAST_EXCLUDE) {
				++in6m->in6m_refcount;
				splx(s);
				return in6m;
			}
		}

		curmode = in6m->in6m_source->i6ms_mode;
		curnumsrc = in6m->in6m_source->i6ms_cur->numsrc;
		if ((*error = in6_modmultisrc(in6m, numsrc, src, mode,
		    old_num, old_src, old_mode, grpjoin, &newhead, &newmode,
		    &newnumsrc)) != 0) {
			splx(s);
			return NULL;
		}
		if (newhead != NULL) {
			/*
			 * Merge new source list to current pending report's
			 * source list.
			 */
			if ((*error = in6_merge_msf_state(in6m, newhead,
			    newmode, newnumsrc)) > 0) {
				/*
				 * State-Change Report will not be sent. Just
				 * return immediately. */
				FREE(newhead, M_MSFILTER);
				splx(s);
				return in6m;
			}
		} else {
			/* Only newhead was merged. */
			in6m->in6m_source->i6ms_mode = newmode;
			in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
		}

		/*
		 * Let MLD know that we have joined an IPv6 multicast group with
		 * source list if upstream router is MLDv2 capable.
		 * If there was no pending source list change, an ALLOW or a
		 * BLOCK State-Change Report will not be sent, but a TO_IN or a
		 * TO_EX State-Change Report will be sent in any case.
		 */
		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode || curnumsrc != newnumsrc ||
			    old_num) {
				if (curmode != newmode) {
					if (newmode == MCAST_INCLUDE)
						type = CHANGE_TO_INCLUDE_MODE;
					else
						type = CHANGE_TO_EXCLUDE_MODE;
				}
				mld_send_state_change_report
					(&m, &buflen, in6m, type, timer_init);
			}
		} else {
			/*
			 * If MSF's pending records exist, they must be deleted.
			 */
			in6_clear_all_pending_report(in6m);
		}
		*error = 0;
		/*
		 * for this group address, initial join request by the socket.
		 */
		if (init)
			++in6m->in6m_refcount;

	} else {
		struct sockaddr_in6 sa6;

		/*
		 * If there is some sources to be deleted, or if the request is
		 * join a local group address with some filtered address,
		 * return.
		 */
		if ((old_num != 0) || (!in6_is_mld_target(ap) && numsrc != 0)) {
			*error = EINVAL;
			splx(s);
			return NULL;
		}

		/*
		 * New address; allocate a new multicast record and link it into
		 * the interface's multicast list.
		 */
		in6m = (struct in6_multi *)malloc(sizeof(*in6m), M_IPMADDR,
		    M_NOWAIT);
		if (in6m == NULL) {
			*error = ENOBUFS;
			splx(s);
			return NULL;
		}
		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_len = sizeof(struct sockaddr_in6);
		sa6.sin6_addr = *ap;
		*error = if_addmulti(ifp, (struct sockaddr *)&sa6, &ifma);
		if (*error) {
			free(in6m, M_IPMADDR);
			splx(s);
			return NULL;
		}
		if (ifma->ifma_protospec != NULL) {
			mldlog((LOG_DEBUG,
			    "in6_modmulti: "
			    "there's a corresponding if_multiaddr "
			    "although IN6_LOOKUP_MULTI fails \n"));
			free(in6m, M_IPMADDR);
			splx(s);
			return NULL;
		}

		bzero(in6m, sizeof(*in6m));
		in6m->in6m_addr = *ap;
		in6m->in6m_ifp = ifp;
		in6m->in6m_refcount = 1;
		in6m->in6m_ifma = ifma;
		ifma->ifma_protospec = in6m;
		LIST_INSERT_HEAD(&in6_multihead, in6m, in6m_entry);

		for (rti = Head6; rti != 0; rti = rti->rt6i_next) {
			if (rti->rt6i_ifp == in6m->in6m_ifp) {
				in6m->in6m_rti = rti;
				break;
			}
		}
		if (rti == NULL) {
			if ((rti = rt6i_init(in6m->in6m_ifp)) == NULL) {
				LIST_REMOVE(in6m, in6m_entry);
				free(in6m, M_IPMADDR);
				*error = ENOBUFS;
				splx(s);
				return NULL;
			}
			in6m->in6m_rti = rti;
		}

		in6m->in6m_source = NULL;
		if (!in6_is_mld_target(&in6m->in6m_addr)) {
			splx(s);
			return in6m;
		}

		*error = in6_modmultisrc(in6m, numsrc, src, mode, 0, NULL,
					MCAST_INCLUDE, grpjoin, &newhead,
					&newmode, &newnumsrc);
		if (*error != 0) {
			in6_free_all_msf_source_list(in6m);
			LIST_REMOVE(in6m, in6m_entry);
			free(in6m, M_IPMADDR);
			splx(s);
			return NULL;
		}
		/* Only newhead was merged in a former function. */
		curmode = in6m->in6m_source->i6ms_mode;
		in6m->in6m_source->i6ms_mode = newmode;
		in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;

		if (in6m->in6m_rti->rt6i_type == MLD_V2_ROUTER) {
			if (curmode != newmode) {
				if (newmode == MCAST_INCLUDE) {
					/* never happen??? */
					type = CHANGE_TO_INCLUDE_MODE;
				} else
					type = CHANGE_TO_EXCLUDE_MODE;
			}
			mld_send_state_change_report(&m, &buflen, in6m, type,
			    timer_init);
		} else {
			/*
			 * If MSF's pending records exist, they must be deleted.
			 */
			in6_clear_all_pending_report(in6m);
			in6_joingroup(in6m->in6m_ifp, &in6m->in6m_addr,
			    error, 0);
#if 0
			if (imm) {
				LIST_INSERT_HEAD(in6m->, imm,
				    i6mm_chain);
			} else {
				nd6log((LOG_WARNING,
				    "in6_modmulti: addmulti failed for "
				    "%s on %s (errno=%d)\n",
				    ip6_sprintf(&in6m->in6m_addr),
				    if_name(in6m->in6m_ifp), *error));
			}
#endif
		}
		*error = 0;
	}
	if (newhead != NULL)
		FREE(newhead, M_MSFILTER);

	splx(s);
	return in6m;
}
#endif /* not FreeBSD */

/* 
 * check if the given address should be announced via MLDv1/v2.
 */
int
in6_is_mld_target(group)
	struct in6_addr *group;
{
	struct in6_addr tmp = *group;

	if (!IN6_IS_ADDR_MULTICAST(group))
		return 0;
	if (IPV6_ADDR_MC_SCOPE(group) < IPV6_ADDR_SCOPE_LINKLOCAL)
		return 0;

	/*
	 * link index may be embedded into group address, so it has to be 
	 * cleared before being compared to ff02::1.
	 */
	in6_clearscope(&tmp);
	if (IN6_ARE_ADDR_EQUAL(&tmp, &in6addr_linklocal_allnodes))
		return 0;
	
	return 1;
}

struct in6_multi_mship *
in6_joingroup(ifp, addr, errorp, delay)
	struct ifnet *ifp;
	struct in6_addr *addr;
	int *errorp;
	int delay;		/* unused for now */
{
	struct in6_multi_mship *imm;
	int error = 0;

	imm = malloc(sizeof(*imm), M_IPMADDR, M_NOWAIT);
	if (!imm) {
		*errorp = ENOBUFS;
		return NULL;
	}

	bzero(imm, sizeof(*imm));
	IMO_MSF_ALLOC(imm->i6mm_msf);
	if (error != 0) {
		*errorp = error;
		return NULL;
	}
	imm->i6mm_maddr = in6_addmulti(addr, ifp, errorp, delay);
	imm->i6mm_msf->msf_grpjoin++;
	if (*errorp != 0) {
		IMO_MSF_FREE(imm->i6mm_msf);
		LIST_REMOVE(imm, i6mm_chain);
		FREE(imm, M_IPMADDR);
		return NULL;
	}
	return imm;
}

int
in6_leavegroup(imm)
	struct in6_multi_mship *imm;
{
	u_int16_t numsrc = 0;
	struct sockaddr_storage *del_ss = NULL;
	u_int mode;
	int final = 1;
	int error;

	if (imm->i6mm_maddr) {
		struct sock_msf *msf = imm->i6mm_msf;
		error = in6_getmopt_source_list(msf, &numsrc, &del_ss, &mode);
		if (error != 0) {
			/* XXX strange... panic? */
			if (del_ss != NULL)
				FREE(del_ss, M_IPMOPTS);
			return error;
		}
		in6_delmulti2(imm->i6mm_maddr, &error, numsrc, del_ss,
			     mode, final);
		if (del_ss != NULL)
			FREE(del_ss, M_IPMOPTS);
		in6_freemopt_source_list(msf, msf->msf_head, msf->msf_blkhead);
		IMO_MSF_FREE(msf);
	}
	free(imm, M_IPMADDR);
	return 0;
}


#ifndef __FreeBSD__
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

		for (mk = in6_mk.lh_first; mk; mk = mk->mk_entry.le_next) {
			if (mk->mk_ifp == oia->ia_ifp)
				break;
		}
		if (mk == NULL) /* this should not happen! */
			panic("in6_savemkludge: no kludge space");

		for (in6m = oia->ia6_multiaddrs.lh_first; in6m; in6m = next){
			next = in6m->in6m_entry.le_next;
			IFAFREE(&in6m->in6m_ia->ia_ifa); /* release reference */
			in6m->in6m_ia = NULL;
			LIST_INSERT_HEAD(&mk->mk_head, in6m, in6m_entry);
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
			LIST_INIT(&mk->mk_head);
			break;
		}
	}
}

/*
 * Allocate space for the kludge at interface initialization time.
 * Formerly, we dynamically allocated the space in in6_savemkludge() with
 * malloc(M_WAITOK).  However, it was wrong since the function could be called
 * under an interrupt context (software timer on address lifetime expiration).
 * Also, we cannot just give up allocating the strucutre, since the group
 * membership structure is very complex and we need to keep it anyway.
 * Of course, this function MUST NOT be called under an interrupt context.
 * Specifically, it is expected to be called only from in6_ifattach(), though
 * it is a global function.
 */
void
in6_createmkludge(ifp)
	struct ifnet *ifp;
{
	struct multi6_kludge *mk;

	for (mk = in6_mk.lh_first; mk; mk = mk->mk_entry.le_next) {
		/* If we've already had one, do not allocate. */
		if (mk->mk_ifp == ifp)
			return;
	}

	mk = malloc(sizeof(*mk), M_IPMADDR, M_WAITOK);

	bzero(mk, sizeof(*mk));
	LIST_INIT(&mk->mk_head);
	mk->mk_ifp = ifp;
	LIST_INSERT_HEAD(&in6_mk, mk, mk_entry);
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
		while ((in6m = LIST_FIRST(&mk->mk_head)) != NULL) {
			int error;
			/* ToDo: should remove all multicast entries */
			in6_delmulti2(in6m, &error, 0, NULL, MCAST_EXCLUDE, 1);
		}
		LIST_REMOVE(mk, mk_entry);
		free(mk, M_IPMADDR);
		break;
	}
}
#endif /* !FreeBSD */
#endif /* MLDV2 */
