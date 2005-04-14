/*	$KAME: mld6.c,v 1.111 2005/04/14 06:22:41 suz Exp $	*/

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

#ifdef MLDV2
/* mldv2.c is used on behalf of this, if MLDv2 is enabled */
#else
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/protosw.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/kernel.h>
#if defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif
#ifdef __FreeBSD__
#include <sys/malloc.h>
#endif
#ifdef __OpenBSD__
#include <dev/rndvar.h>
#endif

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mld6_var.h>

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
 * multicast address (in seconds)
 */
#define MLD_UNSOLICITED_REPORT_INTERVAL	10

int mldmaxsrcfilter = IP_MAX_SOURCE_FILTER;
int mldsomaxsrc = SO_MAX_SOURCE_FILTER;
int mld_verion = 1;

struct router6_info *Head6;

static struct ip6_pktopts ip6_opts;
static const struct sockaddr_in6 *all_nodes_linklocal;
static const struct sockaddr_in6 *all_routers_linklocal;
static const int ignflags = (IN6_IFF_NOTREADY|IN6_IFF_ANYCAST) & 
			    ~IN6_IFF_TENTATIVE;

static void mld_start_listening(struct in6_multi *);
static void mld_sendpkt(struct in6_multi *, int, const struct in6_addr *);

static struct mld_hdr * mld_allocbuf(struct mbuf **, int, struct in6_multi *,
	int);
static void mld_starttimer(struct in6_multi *);
static void mld_stoptimer(struct in6_multi *);
static void mld_timeo(struct in6_multi *);
static u_long mld_timerresid(struct in6_multi *);

void
mld_init()
{
	static u_int8_t hbh_buf[8];
	struct ip6_hbh *hbh = (struct ip6_hbh *)hbh_buf;
	u_int16_t rtalert_code = htons((u_int16_t)IP6OPT_RTALERT_MLD);

	static struct sockaddr_in6 all_nodes_linklocal0;
	static struct sockaddr_in6 all_routers_linklocal0;

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

	ip6_initpktopts(&ip6_opts);
	ip6_opts.ip6po_hbh = hbh;

	Head6 = NULL;
}

static void
mld_starttimer(in6m)
	struct in6_multi *in6m;
{
	struct timeval now;

	microtime(&now);
	in6m->in6m_timer_expire.tv_sec = now.tv_sec + in6m->in6m_timer / hz;
	in6m->in6m_timer_expire.tv_usec = now.tv_usec +
	    (in6m->in6m_timer % hz) * (1000000 / hz);
	if (in6m->in6m_timer_expire.tv_usec > 1000000) {
		in6m->in6m_timer_expire.tv_sec++;
		in6m->in6m_timer_expire.tv_usec -= 1000000;
	}

	/* start or restart the timer */
#if defined(__NetBSD__) || defined(__FreeBSD__)
	callout_reset(in6m->in6m_timer_ch, in6m->in6m_timer,
	    (void (*) __P((void *)))mld_timeo, in6m);
#else
	timeout_set(in6m->in6m_timer_ch,
	    (void (*) __P((void *)))mld_timeo, in6m);
	timeout_add(in6m->in6m_timer_ch, in6m->in6m_timer);
#endif
}

static void
mld_stoptimer(in6m)
	struct in6_multi *in6m;
{
	if (in6m->in6m_timer == IN6M_TIMER_UNDEF)
		return;

#if defined(__NetBSD__) || defined(__FreeBSD__)
	callout_stop(in6m->in6m_timer_ch);
#elif defined(__OpenBSD__)
	timeout_del(in6m->in6m_timer_ch);
#endif

	in6m->in6m_timer = IN6M_TIMER_UNDEF;
}

static void
mld_timeo(in6m)
	struct in6_multi *in6m;
{
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	in6m->in6m_timer = IN6M_TIMER_UNDEF;

#if defined(__NetBSD__) || defined(__FreeBSD__)
	callout_stop(in6m->in6m_timer_ch);
#elif defined(__OpenBSD__)
	timeout_del(in6m->in6m_timer_ch);
#endif

	switch (in6m->in6m_state) {
	case MLD_REPORTPENDING:
		mld_start_listening(in6m);
		break;
	default:
		mld_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
		break;
	}

	splx(s);
}

static u_long
mld_timerresid(in6m)
	struct in6_multi *in6m;
{
	struct timeval now, diff;

	microtime(&now);

	if (now.tv_sec > in6m->in6m_timer_expire.tv_sec ||
	    (now.tv_sec == in6m->in6m_timer_expire.tv_sec &&
	    now.tv_usec > in6m->in6m_timer_expire.tv_usec)) {
		return (0);
	}
	diff = in6m->in6m_timer_expire;
	diff.tv_sec -= now.tv_sec;
	diff.tv_usec -= now.tv_usec;
	if (diff.tv_usec < 0) {
		diff.tv_sec--;
		diff.tv_usec += 1000000;
	}

	/* return the remaining time in milliseconds */
	return (((u_long)(diff.tv_sec * 1000000 + diff.tv_usec)) / 1000);
}

static void
mld_start_listening(in6m)
	struct in6_multi *in6m;
{
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
	    &all_sa.sin6_scope_id)) {
		/* XXX: this should not happen! */
		in6m->in6m_timer = IN6M_TIMER_UNDEF;
		in6m->in6m_state = MLD_OTHERLISTENER;
	}
	if (in6_embedscope(&all_sa.sin6_addr, &all_sa)) {
		/* XXX: this should not happen! */
		panic("mld6_start_listening: should not happen");
	}
	if (IN6_ARE_ADDR_EQUAL(&in6m->in6m_addr, &all_sa.sin6_addr) ||
	    IPV6_ADDR_MC_SCOPE(&in6m->in6m_addr) <
	    IPV6_ADDR_SCOPE_LINKLOCAL) {
		in6m->in6m_timer = IN6M_TIMER_UNDEF;
		in6m->in6m_state = MLD_OTHERLISTENER;
	} else {
		mld_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
		in6m->in6m_timer = arc4random() %
		    (MLD_UNSOLICITED_REPORT_INTERVAL * hz);
		in6m->in6m_state = MLD_IREPORTEDLAST;

		mld_starttimer(in6m);
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
		m_freem(m);
		return;
	}

	/* convert the multicast address into a full sockaddr form */
	bzero(&mc_sa, sizeof(mc_sa));
	mc_sa.sin6_family = AF_INET6;
	mc_sa.sin6_len = sizeof(mc_sa);
	mc_sa.sin6_addr = mldh->mld_addr;
	if (in6_addr2zoneid(ifp, &mc_sa.sin6_addr, &mc_sa.sin6_scope_id)) {
		/* XXX: this should not happen! */
		m_freem(m);
		return;
	}
	if (in6_embedscope(&mc_sa.sin6_addr, &mc_sa)) {
		/* XXX: this should not happen! */
		m_freem(m);
		return;
	}

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

		if (!IN6_IS_ADDR_UNSPECIFIED(&mc_sa.sin6_addr) &&
		    !IN6_IS_ADDR_MULTICAST(&mc_sa.sin6_addr))
			break;	/* print error or log stat? */

		all_sa = *all_nodes_linklocal;
		if (in6_addr2zoneid(ifp, &all_sa.sin6_addr,
		    &all_sa.sin6_scope_id)) {
			/* XXX: this should not happen! */
			break;
		}
		if (in6_embedscope(&all_sa.sin6_addr, &all_sa)) {
			/* XXX: this should not happen! */
			break;
		}

		/*
		 * - Start the timers in all of our membership records
		 *   that the query applies to for the interface on
		 *   which the query arrived excl. those that belong
		 *   to the "all-nodes" group (ff02::1).
		 * - Restart any timer that is already running but has
		 *   a value longer than the requested timeout.
		 * - Use the value specified in the query message as
		 *   the maximum timeout.
		 */
		timer = ntohs(mldh->mld_maxdelay);

#ifdef __FreeBSD__
		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link)
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

			if (in6m->in6m_state == MLD_REPORTPENDING)
				continue; /* we are not yet ready */

			if (IN6_ARE_ADDR_EQUAL(&in6m->in6m_addr,
			    &all_sa.sin6_addr) ||
			    IPV6_ADDR_MC_SCOPE(&in6m->in6m_addr) <
			    IPV6_ADDR_SCOPE_LINKLOCAL)
				continue;

			if (!IN6_IS_ADDR_UNSPECIFIED(&mc_sa.sin6_addr) &&
			    !IN6_ARE_ADDR_EQUAL(&mc_sa.sin6_addr,
			    &in6m->in6m_addr))
				continue;

			if (timer == 0) {
				/* send a report immediately */
				mld_stoptimer(in6m);
				mld_sendpkt(in6m, MLD_LISTENER_REPORT, NULL);
				in6m->in6m_state = MLD_IREPORTEDLAST;
			} else if (in6m->in6m_timer == IN6M_TIMER_UNDEF ||
			    mld_timerresid(in6m) > (u_long)timer) {
				in6m->in6m_timer = arc4random() %
				    (int)(((long)timer * hz) / 1000);
				mld_starttimer(in6m);
			}
		}
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

		if (!IN6_IS_ADDR_MULTICAST(&mc_sa.sin6_addr))
			break;

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN6_LOOKUP_MULTI(mc_sa.sin6_addr, ifp, in6m);
		if (in6m) {
			mld_stoptimer(in6m); /* transit to idle state */
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
		log(LOG_ERR, "mld_input: illegal type(%d)", mldh->mld_type);
#endif
		break;
	}

	m_freem(m);
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
	ip6_output(mh, &ip6_opts, NULL, ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL,
	    NULL);
#elif defined(__NetBSD__)
	ip6_output(mh, &ip6_opts, NULL, ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL,
	    NULL);
#else
	ip6_output(mh, &ip6_opts, NULL, ia ? 0 : IPV6_UNSPECSRC, &im6o, NULL);
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



#ifndef __FreeBSD__
/*
 * Add an address to the list of IP6 multicast addresses for a given interface.
 */
struct	in6_multi *
in6_addmulti(maddr6, ifp, errorp, delay)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp, delay;
{
	struct	in6_ifaddr *ia;
	struct	in6_ifreq ifr;
	struct	in6_multi *in6m;
#if defined(__NetBSD__) || defined(__OpenBSD__)
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
			return (NULL);
		}

		bzero(in6m, sizeof(*in6m));
		in6m->in6m_addr = *maddr6;
		in6m->in6m_ifp = ifp;
		in6m->in6m_refcount = 1;
		in6m->in6m_timer = IN6M_TIMER_UNDEF;
		in6m->in6m_timer_ch =
		    malloc(sizeof(*in6m->in6m_timer_ch), M_IPMADDR, M_NOWAIT);
		if (in6m->in6m_timer_ch == NULL) {
			free(in6m, M_IPMADDR);
			splx(s);
			return (NULL);
		}
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

#ifdef __NetBSD__
		callout_init(in6m->in6m_timer_ch);
#elif defined(__OpenBSD__)
		bzero(in6m->in6m_timer_ch, sizeof(*in6m->in6m_timer_ch));
#endif
		in6m->in6m_timer = delay;
		if (in6m->in6m_timer > 0) {
			in6m->in6m_state = MLD_REPORTPENDING;
			mld_starttimer(in6m);

			splx(s);
			return (in6m);
		}

		/*
		 * Let MLD6 know that we have joined a new IP6 multicast
		 * group.
		 */
		mld_start_listening(in6m);
	}
	splx(s);
	return (in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti(in6m)
	struct in6_multi *in6m;
{
	struct	in6_ifreq ifr;
	struct	in6_ifaddr *ia;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int	s = splsoftnet();
#else
	int	s = splnet();
#endif

	mld_stoptimer(in6m);

	if (--in6m->in6m_refcount == 0) {
		/*
		 * No remaining claims to this record; let MLD6 know
		 * that we are leaving the multicast group.
		 */
		mld_stop_listening(in6m);

		/*
		 * Unlink from list.
		 */
		LIST_REMOVE(in6m, in6m_entry);
		if (in6m->in6m_ia) {
			IFAFREE(&in6m->in6m_ia->ia_ifa); /* release reference */
		}

		/*
		 * Delete all references of this multicasting group from
		 * the membership arrays
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
		free(in6m->in6m_timer_ch, M_IPMADDR);
		free(in6m, M_IPMADDR);
	}
	splx(s);
}

#else /* not FreeBSD */

/*
 * Add an address to the list of IP6 multicast addresses for a given interface.
 */
struct	in6_multi *
in6_addmulti(maddr6, ifp, errorp, delay)
	struct in6_addr *maddr6;
	struct ifnet *ifp;
	int *errorp, delay;
{
	struct in6_multi *in6m;
	struct ifmultiaddr *ifma;
	struct sockaddr_in6 sa6;
	int	s = splnet();

	*errorp = 0;

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
		return (NULL);
	}

	/*
	 * If ifma->ifma_protospec is null, then if_addmulti() created
	 * a new record.  Otherwise, we are done.
	 */
	if (ifma->ifma_protospec != 0) {
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
	in6m->in6m_timer = IN6M_TIMER_UNDEF;
	ifma->ifma_protospec = in6m;
	in6m->in6m_timer_ch = malloc(sizeof(*in6m->in6m_timer_ch), M_IPMADDR,
	    M_NOWAIT);
	if (in6m->in6m_timer_ch == NULL) {
		free(in6m, M_IPMADDR);
		splx(s);
		return (NULL);
	}
	LIST_INSERT_HEAD(&in6_multihead, in6m, in6m_entry);

	callout_init(in6m->in6m_timer_ch, 0);
	in6m->in6m_timer = delay;
	if (in6m->in6m_timer > 0) {
		in6m->in6m_state = MLD_REPORTPENDING;
		mld_starttimer(in6m);

		splx(s);
		return (in6m);
	}

	/*
	 * Let MLD6 know that we have joined a new IPv6 multicast
	 * group.
	 */
	mld_start_listening(in6m);
	splx(s);
	return (in6m);
}

/*
 * Delete a multicast address record.
 */
void
in6_delmulti(in6m)
	struct in6_multi *in6m;
{
	struct ifmultiaddr *ifma = in6m->in6m_ifma;
	int s = splnet();

	if (ifma->ifma_refcount == 1) {
		/*
		 * No remaining claims to this record; let MLD6 know
		 * that we are leaving the multicast group.
		 */
		mld_stoptimer(in6m);
		mld_stop_listening(in6m);
		ifma->ifma_protospec = 0;
		LIST_REMOVE(in6m, in6m_entry);
		free(in6m->in6m_timer_ch, M_IPMADDR);
		free(in6m, M_IPMADDR);
	}
	/* XXX - should be separate API for when we have an ifma? */
	if_delmulti(ifma->ifma_ifp, ifma->ifma_addr);
	splx(s);
}
#endif /* not FreeBSD */

struct in6_multi_mship *
in6_joingroup(ifp, addr, errorp, delay)
	struct ifnet *ifp;
	struct in6_addr *addr;
	int *errorp, delay;
{
	struct in6_multi_mship *imm;

	imm = malloc(sizeof(*imm), M_IPMADDR, M_NOWAIT);
	if (!imm) {
		*errorp = ENOBUFS;
		return NULL;
	}

	bzero(imm, sizeof(*imm));
	imm->i6mm_maddr = in6_addmulti(addr, ifp, errorp, delay);
	if (!imm->i6mm_maddr) {
		/* *errorp is alrady set */
		free(imm, M_IPMADDR);
		return NULL;
	}
	return imm;
}

int
in6_leavegroup(imm)
	struct in6_multi_mship *imm;
{

	if (imm->i6mm_maddr) {
		in6_delmulti(imm->i6mm_maddr);
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
		for (in6m = oia->ia6_multiaddrs.lh_first; in6m; in6m = next) {
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

		for (in6m = oia->ia6_multiaddrs.lh_first; in6m; in6m = next) {
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
			in6_delmulti(in6m);
		}
		LIST_REMOVE(mk, mk_entry);
		free(mk, M_IPMADDR);
		break;
	}
}
#endif /* FreeBSD */

#endif /* !MLDV2 */
