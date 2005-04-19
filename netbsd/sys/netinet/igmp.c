/*	$NetBSD: igmp.c,v 1.36 2003/08/22 21:53:02 itojun Exp $	*/

/*
 * Copyright (c) 2002 INRIA. All rights reserved.
 *
 * Implementation of Internet Group Management Protocol, Version 3.
 * Developed by Hitoshi Asaeda, INRIA, February 2002.
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
 * Internet Group Management Protocol (IGMP) routines.
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994.
 * Modified by Bill Fenner, Xerox PARC, Feb 1995.
 *
 * MULTICAST Revision: 1.3
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: igmp.c,v 1.36 2003/08/22 21:53:02 itojun Exp $");

#include "opt_mrouting.h"

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/igmp_var.h>

#include <machine/stdarg.h>

#define IP_MULTICASTOPTS	0

MALLOC_DEFINE(M_MSFILTER, "msfilter", "multicast source filter");
struct pool igmp_rti_pool;
struct igmpstat igmpstat;
int igmp_timers_are_running;
LIST_HEAD(, router_info) rti_head = LIST_HEAD_INITIALIZER(rti_head);

int interface_timers_are_running;
int state_change_timers_are_running;
#ifdef IGMPV3
int igmpsendwithra = 1;		/* send packets with no Router Alert option */
#else
int igmpsendwithra = 0;
#endif
int igmpdropwithnora = 0;	/* accept packets with no Router Alert option */
int igmpmaxsrcfilter = IP_MAX_SOURCE_FILTER;
int igmpsomaxsrc = SO_MAX_SOURCE_FILTER;
/* 
 * igmp_version:
 *	0: igmpv3 with compat-mode
 *	1: igmpv1 only
 *	2: igmpv2 only
 *	3: igmpv3 without compat-mode
 */
int igmp_version = 0;
static struct mbuf *router_alert;
#ifdef IGMPV3
static int qhdrlen = IGMP_v3_QUERY_MINLEN;
static int rhdrlen = IGMP_MINLEN;
static int ghdrlen = IGMP_MINLEN;
static int addrlen = sizeof(struct in_addr);
#endif

#define	SOURCE_RECORD_LEN(numsrc)	(numsrc * (sizeof(u_int32_t)))

#define	GET_REPORT_SOURCE_HEAD(inm, type, iasl) {			\
	if ((type) == ALLOW_NEW_SOURCES)				\
		(iasl) = (inm)->inm_source->ims_alw;			\
	else if ((type) == BLOCK_OLD_SOURCES)				\
		(iasl) = (inm)->inm_source->ims_blk;			\
	else if ((type) == CHANGE_TO_INCLUDE_MODE)			\
		(iasl) = (inm)->inm_source->ims_toin;			\
	else if ((type) == CHANGE_TO_EXCLUDE_MODE)			\
		(iasl) = (inm)->inm_source->ims_toex;			\
	else {								\
		if ((inm)->inm_state == IGMP_SG_QUERY_PENDING_MEMBER)	\
			(iasl) = (inm)->inm_source->ims_rec;		\
		else							\
			(iasl) = (inm)->inm_source->ims_cur;		\
	}								\
}

#define	SET_REPORTHDR(m, numsrc) do {					\
	MGETHDR((m), M_DONTWAIT, MT_HEADER);				\
	if ((m) != NULL &&						\
		MHLEN - max_linkhdr < sizeof(struct ip)			\
				      + rhdrlen + ghdrlen		\
				      + SOURCE_RECORD_LEN((numsrc))) {	\
		MCLGET((m), M_DONTWAIT);				\
		if (((m)->m_flags & M_EXT) == 0) {			\
			m_freem((m));					\
			error = ENOBUFS;				\
			break;						\
		}							\
	}								\
	if ((m) == NULL) {						\
		error = ENOBUFS;					\
		break;							\
	}								\
	(m)->m_data += max_linkhdr;					\
	ip = mtod((m), struct ip *);					\
	buflen = sizeof(struct ip);					\
	ip->ip_len = sizeof(struct ip) + rhdrlen;			\
	ip->ip_tos = 0xc0;						\
	ip->ip_off = 0;							\
	ip->ip_p = IPPROTO_IGMP;					\
	ip->ip_src = zeroin_addr;					\
	ip->ip_dst.s_addr = INADDR_NEW_ALLRTRS_GROUP;			\
	igmp_rhdr = (struct igmp_report_hdr *)((char *)ip + buflen);	\
	igmp_rhdr->igmp_type = IGMP_v3_HOST_MEMBERSHIP_REPORT;		\
	igmp_rhdr->igmp_reserved1 = 0;					\
	igmp_rhdr->igmp_reserved2 = 0;					\
	igmp_rhdr->igmp_grpnum = 0;					\
	buflen += rhdrlen;						\
	(m)->m_len = sizeof(struct ip) + rhdrlen;			\
	(m)->m_pkthdr.len = sizeof(struct ip) + rhdrlen;		\
	(m)->m_pkthdr.rcvif = (struct ifnet *)0;			\
} while (0)

void igmp_sendpkt __P((struct in_multi *, int));
int igmp_set_timer __P((struct ifnet *, struct router_info *, struct igmp *,
				int, u_int8_t));
void igmp_set_hostcompat __P((struct ifnet *, struct router_info *, int));
int igmp_record_queried_source __P((struct in_multi *, struct igmp *, int));
void igmp_send_all_current_state_report __P((struct ifnet *));
int igmp_send_current_state_report __P((struct mbuf **, int *,
				struct in_multi *));
int igmp_create_group_record __P((struct mbuf *, int *, struct in_multi *,
				u_int16_t, u_int16_t *, u_int8_t));
void igmp_cancel_pending_response __P((struct ifnet *, struct router_info *));
static int rti_fill __P((struct in_multi *));
static struct router_info *rti_find __P((struct ifnet *));
static void rti_delete __P((struct ifnet *));

void
igmp_init()
{
	struct ipoption *ra;

	igmp_timers_are_running = 0;
	pool_init(&igmp_rti_pool, sizeof(struct router_info), 0, 0, 0, "igmppl",
	    NULL);

	interface_timers_are_running = 0; /* used only by IGMPv3 */
	state_change_timers_are_running = 0; /* used only by IGMPv3 */

	/*
	 * Prepare Router Alert option to use in outgoing packets.
	 */
	MGET(router_alert, M_DONTWAIT, MT_DATA);
	ra = mtod(router_alert, struct ipoption *);
	ra->ipopt_dst.s_addr = 0;
	ra->ipopt_list[0] = IPOPT_RA;	/* Router Alert option */
	ra->ipopt_list[1] = 0x04;	/* 4 bytes long */
	ra->ipopt_list[2] = 0x00;
	ra->ipopt_list[3] = 0x00;
	router_alert->m_len = sizeof(ra->ipopt_dst) + ra->ipopt_list[1];
}

struct router_info *
rti_init(ifp)
	struct ifnet *ifp;
{
	struct router_info *rti;

	rti = pool_get(&igmp_rti_pool, PR_NOWAIT);
	if (rti == NULL)
		return NULL;

	rti->rti_ifp = ifp;
#ifndef IGMPV3
	rti->rti_type = IGMP_v2_ROUTER;
#else
	rti->rti_timer1 = 0;
	rti->rti_timer2 = 0;
	rti->rti_timer3 = 0;
	rti->rti_qrv = IGMP_DEF_RV;
	rti->rti_qqi = IGMP_DEF_QI;
	rti->rti_qri = IGMP_DEF_QRI / IGMP_TIMER_SCALE;
	switch (igmp_version) {
	case 0:
		rti->rti_type = IGMP_v3_ROUTER;
		break;
	case 1:
		rti->rti_type = IGMP_v1_ROUTER;
		break;
	case 2:
		rti->rti_type = IGMP_v2_ROUTER;
		break;
	case 3:
		rti->rti_type = IGMP_v3_ROUTER;
		break;
	default:
		/* impossible */
		break;
	}
#endif
	LIST_INSERT_HEAD(&rti_head, rti, rti_link);
	return (rti);
}

static int
rti_fill(inm)
	struct in_multi *inm;
{
	struct router_info *rti;

	LIST_FOREACH(rti, &rti_head, rti_link) {
		if (rti->rti_ifp == inm->inm_ifp) {
			inm->inm_rti = rti;
			if (rti->rti_type == IGMP_v1_ROUTER)
				return (IGMP_v1_HOST_MEMBERSHIP_REPORT);
			else
				return (IGMP_v2_HOST_MEMBERSHIP_REPORT);
		}
	}

	if ((rti = rti_init(inm->inm_ifp)) == NULL)
		return -1;
	inm->inm_rti = rti;
	return (IGMP_v2_HOST_MEMBERSHIP_REPORT);
}

static struct router_info *
rti_find(ifp)
	struct ifnet *ifp;
{
	struct router_info *rti;

	LIST_FOREACH(rti, &rti_head, rti_link) {
		if (rti->rti_ifp == ifp)
			return (rti);
	}

	if ((rti = rti_init(ifp)) == NULL)
		return NULL;
	else
		return (rti);
}

static void
rti_delete(ifp)
	struct ifnet *ifp;
{
	struct router_info *rti, *nxt;

	LIST_FOREACH(rti, &rti_head, rti_link) {
		nxt = LIST_NEXT(rti, rti_link);
		if (rti->rti_ifp == ifp) {
			LIST_REMOVE(rti, rti_link);
			pool_put(&igmp_rti_pool, rti);
		}
	}
}

/*
 * Check whether IGMP message carries Router Alert option.
 */
int
igmp_get_router_alert(m)
	struct mbuf *m;
{
	struct ip *ip = mtod(m, struct ip *);
	struct igmp *igmp;
	int minlen;
	int iphlen, optlen;

	++igmpstat.igps_rcv_total;

	/*
	 * Validate IP Time-to-Live
	 */
	if (ip->ip_ttl != 1) {
		++igmpstat.igps_rcv_badttl;
		return -1;
	}

	/*
	 * Validate lengths
	 */
#ifdef _IP_VHL
	iphlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	iphlen = ip->ip_hl << 2;
#endif
	minlen = iphlen + IGMP_MINLEN;
	if (ip->ip_len < minlen) {
		++igmpstat.igps_rcv_tooshort;
		return -1;
	}

	if (((m->m_flags & M_EXT) && (ip->ip_src.s_addr & IN_CLASSA_NET) == 0)
				|| m->m_len < minlen) {
		if ((m = m_pullup(m, minlen)) == 0) {
			++igmpstat.igps_rcv_tooshort;
			return -1;
		}
		ip = mtod(m, struct ip *);
	}

	optlen = iphlen - sizeof(struct ip);
	igmp = (struct igmp *)((caddr_t)ip + optlen);

	/*
	 * Check IGMP message type and its Router Alert requirement.
	 */
	switch (igmp->igmp_type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		if (igmp->igmp_code == 0) /* IGMPv1 */
			return 0;
		if (igmpdropwithnora && (ip_check_router_alert(ip) != 0)) {
			++igmpstat.igps_rcv_nora;
			return -1;
		} else
			return 0;
	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		return 0;
	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
	case IGMP_HOST_LEAVE_MESSAGE:
		if (igmpdropwithnora && (ip_check_router_alert(ip) != 0)) {
			++igmpstat.igps_rcv_nora;
			return -1;
		} else
			return 0;
	}
	return 0;
}

void
#if __STDC__
igmp_input(struct mbuf *m, ...)
#else
igmp_input(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{
	int proto;
	int iphlen, igmplen;
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip *ip = mtod(m, struct ip *);
	struct igmp *igmp;
#ifdef PULLDOWN_TEST
	struct mbuf *n;
	int off;
#endif
	int query_ver;
	u_int minlen;
	struct in_multi *inm;
	struct in_multistep step;
	struct router_info *rti;
	struct in_ifaddr *ia;
	u_int timer;
	va_list ap;
	u_int16_t ip_len;

#if defined(IGMPV3) && defined(MROUTING)
	extern struct socket *ip_mrouter;
#endif /* IGMPV3 && MROUTING */

	va_start(ap, m);
	iphlen = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	/*
	 * Check length and validate checksum
	 */
	if (ip->ip_len > ifp->if_mtu)
		++igmpstat.igps_rcv_toolong;
	minlen = iphlen + IGMP_MINLEN;
	ip_len = ntohs(ip->ip_len);
	if (ip_len < minlen) {
		++igmpstat.igps_rcv_tooshort;
		m_freem(m);
		return;
	}
	igmplen = ip->ip_len - iphlen;
#ifdef PULLDOWN_TEST
	if ((n = m_pulldown(m, iphlen, igmplen, &off)) == NULL) {
		++igmpstat.igps_rcv_query_fails;
		m_freem(m);
		return;
	}

	igmp = (struct igmp *)(mtod(n, caddr_t) + off);
	/* No need to assert alignment here. */
	if (in_cksum(n, igmplen)) {
		++igmpstat.igps_rcv_badsum;
		m_freem(m);
		return;
	}
#else
	m->m_data += iphlen;
	m->m_len -= iphlen;
	igmp = mtod(m, struct igmp *);
  	/* No need to assert alignment here. */
	if (in_cksum(m, igmplen)) {
		++igmpstat.igps_rcv_badsum;
		m_freem(m);
		return;
	}
	m->m_data -= iphlen;
	m->m_len += iphlen;
#endif

	if ((rti = rti_find(ifp)) == NULL) {
		++igmpstat.igps_rcv_query_fails;
		m_freem(m);
		return; /* XXX */
	}

	switch (igmp->igmp_type) {

	case IGMP_HOST_MEMBERSHIP_QUERY:
		/*
		 * "Tentative" IGMP version check.
		 * IGMPv1 Query: length = 8 octets AND Max-Resp-Code = 0
		 * IGMPv2 Query: length = 8 octets AND Max-Resp-Code != 0
		 * IGMPv3 Query: length >= 12 octets
		 * IGMPv1 and v2 implementation must accept only the first 8
		 * octets of the query message.
		 *
		 * if sysctl variable "igmp_version" is set to 1 or 2,
		 * query-type will be IGMPv1 or v2 respectively, regardless of
		 * the packet size.
		 */
		if (igmplen == IGMP_MINLEN || igmp_version == 2)
			query_ver = IGMP_v2_QUERY; /* or IGMP_v1_QUERY */
#ifdef IGMPV3
		else if (igmplen >= IGMP_v3_QUERY_MINLEN)
			query_ver = IGMP_v3_QUERY;
#endif
		else { /* igmplen > 8 && igmplen < 12 */
			++igmpstat.igps_rcv_badqueries; /* invalid query */
			m_freem(m);
			return;
		}

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		/*
		 * Note IGMPv1's igmp_code is *always* 0, and IGMPv2's
		 * igmp_code *must not* be 0. This means only correct v1 query
		 * must come through this "if" routine.
		 */
		if ((igmp->igmp_code == 0) && (query_ver != IGMP_v3_QUERY)) {

			query_ver = IGMP_v1_QUERY; /* overwrite */
			++igmpstat.igps_rcv_v1_queries;
			if (ip->ip_dst.s_addr != INADDR_ALLHOSTS_GROUP) {
				++igmpstat.igps_rcv_badqueries;
				m_freem(m);
				return;
			}

#ifdef IGMPV3
start_v1:
#endif
			/*
			 * Start the timers in all of our membership records
			 * for the interface on which the query arrived,
			 * except those that are already running and those
			 * that belong to a "local" group (224.0.0.X).
			 */
			IN_FIRST_MULTI(step, inm);
			while (inm != NULL) {
				if (inm->inm_ifp == ifp &&
				    inm->inm_timer == 0 &&
				    !IN_LOCAL_GROUP(inm->inm_addr.s_addr)) {
					inm->inm_state = IGMP_DELAYING_MEMBER;
					inm->inm_timer = IGMP_RANDOM_DELAY
						(IGMP_MAX_HOST_REPORT_DELAY *
						 PR_FASTHZ);
					igmp_timers_are_running = 1;
				}
				IN_NEXT_MULTI(step, inm);
			}
#ifndef IGMPV3
			rti->rti_age = 0;
#else
			if (igmp_version == 0)
				igmp_set_hostcompat(ifp, rti, query_ver);
#endif
		/*
		 * Note if IGMPv2's igmp_code is 0, that message must
		 * not be correct query msg. This means correct v2 query
		 * must come through this "else" routine.
		 */
		} else {
			if (query_ver == IGMP_v2_QUERY) {
				++igmpstat.igps_rcv_v2_queries;
				if (!IN_MULTICAST(ip->ip_dst.s_addr)) {
					++igmpstat.igps_rcv_badqueries;
					m_freem(m);
					return;
				}
			}
		}

		/*
		 * Adjust timer for scheduling responses to IGMPv2 query.
		 */
		if (query_ver == IGMP_v2_QUERY) {
#ifdef IGMPV3
start_v2:
#endif
			/*
			 * Start the timers in all of our membership records
			 * for the interface on which the query arrived,
			 * except those that are already running and those
			 * that belong to a "local" group (224.0.0.X).  For
			 * timers already running, check if they need to be
			 * reset.
			 */
			timer = igmp->igmp_code * PR_FASTHZ / IGMP_TIMER_SCALE;
			if (timer == 0)
				timer = 1;
			IN_FIRST_MULTI(step, inm);
			while (inm != NULL) {
				if (inm->inm_ifp == ifp &&
				    !IN_LOCAL_GROUP(inm->inm_addr.s_addr) &&
				    (ip->ip_dst.s_addr == INADDR_ALLHOSTS_GROUP 
				    || in_hosteq(ip->ip_dst, inm->inm_addr))) {
					switch (inm->inm_state) {
					case IGMP_DELAYING_MEMBER:
						if (inm->inm_timer <= timer)
							break;
						/* FALLTHROUGH */
					case IGMP_IDLE_MEMBER:
					case IGMP_LAZY_MEMBER:
					case IGMP_AWAKENING_MEMBER:
#ifdef IGMPV3
					case IGMP_G_QUERY_PENDING_MEMBER:
					case IGMP_SG_QUERY_PENDING_MEMBER:
#endif
						inm->inm_state =
						    IGMP_DELAYING_MEMBER;
						inm->inm_timer =
						    IGMP_RANDOM_DELAY(timer);
						igmp_timers_are_running = 1;
						break;
					case IGMP_SLEEPING_MEMBER:
						inm->inm_state =
						    IGMP_AWAKENING_MEMBER;
						break;
					}
				}
				IN_NEXT_MULTI(step, inm);
			}
#ifdef IGMPV3
			/*
			 * IGMPv2 Querier Present is set to Older Version
			 * Querier Present Timeout seconds whenever an IGMPv2
			 * General Query is received.
			 */
			if (igmp_version == 0 &&
			    in_hosteq(igmp->igmp_group, zeroin_addr))
				igmp_set_hostcompat(ifp, rti, query_ver);
#endif
		}
#ifdef IGMPV3
		/*
		 * Adjust timer for scheduling responses to IGMPv3 query.
		 */
		else if (query_ver == IGMP_v3_QUERY) {
			u_int8_t query_type;

			++igmpstat.igps_rcv_v3_queries;

			/*
			 * Check query types and keep source list if needed.
			 */
			if (in_hosteq(igmp->igmp_group, zeroin_addr) &&
					(igmp->igmp_numsrc == 0)) {
				if (ip->ip_dst.s_addr
					!= INADDR_ALLHOSTS_GROUP) {
					++igmpstat.igps_rcv_badqueries;
					m_freem(m);
					return;
				}
				query_type = IGMP_v3_GENERAL_QUERY;
			} else if (IN_MULTICAST(igmp->igmp_group.s_addr) &&
					(igmp->igmp_numsrc == 0))
				query_type = IGMP_v3_GROUP_QUERY;
			else if (IN_MULTICAST(igmp->igmp_group.s_addr) &&
					(ntohs(igmp->igmp_numsrc) > 0))
				query_type = IGMP_v3_GROUP_SOURCE_QUERY;
			else {
				++igmpstat.igps_rcv_badqueries;
				m_freem(m);
				return;
			}

#ifdef MROUTING /* XXX */
			if (ip_mrouter != NULL) {
				if (IGMP_SFLAG(igmp->igmp_rtval) != 0) {
				/* XXX not yet */
				/* suppress the normal timer updates */
				}
			} else {
				/* XXX not yet */
				/* suppress the querier election or the normal
				 * "host-side" processing of a Query */
			}
#endif

			/* 
			 * Dispatch this query to make an appropriate
			 * version's reply.
			 */
			if (rti->rti_type == IGMP_v1_ROUTER)
				goto start_v1;
			else if (rti->rti_type == IGMP_v2_ROUTER) 
				goto start_v2;

			if (igmp_set_timer(ifp, rti, igmp, igmplen, query_type)
					!= 0) {
#ifdef IGMPV3_DEBUG
				printf("igmp_input: receive bad query\n");
#endif
				m_freem(m);
				return;
			}
		}
#endif /* IGMPV3 */

		break;

	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		++igmpstat.igps_rcv_reports;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN_MULTICAST(igmp->igmp_group.s_addr) ||
		    !in_hosteq(igmp->igmp_group, ip->ip_dst)) {
			++igmpstat.igps_rcv_badreports;
			m_freem(m);
			return;
		}

		/*
		 * KLUDGE: if the IP source address of the report has an
		 * unspecified (i.e., zero) subnet number, as is allowed for
		 * a booting host, replace it with the correct subnet number
		 * so that a process-level multicast routing daemon can
		 * determine which subnet it arrived from.  This is necessary
		 * to compensate for the lack of any way for a process to
		 * determine the arrival interface of an incoming packet.
		 */
		if ((ip->ip_src.s_addr & IN_CLASSA_NET) == 0) {
			IFP_TO_IA(ifp, ia);		/* XXX */
			if (ia)
				ip->ip_src.s_addr = ia->ia_subnet;
		}

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);
		if (inm != NULL) {
			inm->inm_timer = 0;
			++igmpstat.igps_rcv_ourreports;

			switch (inm->inm_state) {
			case IGMP_IDLE_MEMBER:
			case IGMP_LAZY_MEMBER:
			case IGMP_AWAKENING_MEMBER:
			case IGMP_SLEEPING_MEMBER:
				inm->inm_state = IGMP_SLEEPING_MEMBER;
				break;
			case IGMP_DELAYING_MEMBER:
				if (inm->inm_rti->rti_type == IGMP_v1_ROUTER)
					inm->inm_state = IGMP_LAZY_MEMBER;
				else /* IGMP_v2_ROUTER */
					inm->inm_state = IGMP_SLEEPING_MEMBER;
				break;
			}
		}

		break;

	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
#ifdef MROUTING
		/*
		 * Make sure we don't hear our own membership report.  Fast
		 * leave requires knowing that we are the only member of a
		 * group.
		 */
		IFP_TO_IA(ifp, ia);			/* XXX */
		if (ia && in_hosteq(ip->ip_src, ia->ia_addr.sin_addr))
			break;
#endif

		++igmpstat.igps_rcv_reports;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN_MULTICAST(igmp->igmp_group.s_addr) ||
		    !in_hosteq(igmp->igmp_group, ip->ip_dst)) {
			++igmpstat.igps_rcv_badreports;
			m_freem(m);
			return;
		}

		/*
		 * KLUDGE: if the IP source address of the report has an
		 * unspecified (i.e., zero) subnet number, as is allowed for
		 * a booting host, replace it with the correct subnet number
		 * so that a process-level multicast routing daemon can
		 * determine which subnet it arrived from.  This is necessary
		 * to compensate for the lack of any way for a process to
		 * determine the arrival interface of an incoming packet.
		 */
		if ((ip->ip_src.s_addr & IN_CLASSA_NET) == 0) {
#ifndef MROUTING
			IFP_TO_IA(ifp, ia);		/* XXX */
#endif
			if (ia)
				ip->ip_src.s_addr = ia->ia_subnet;
		}

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);
		if (inm != NULL) {
			inm->inm_timer = 0;
			++igmpstat.igps_rcv_ourreports;

			switch (inm->inm_state) {
			case IGMP_DELAYING_MEMBER:
			case IGMP_IDLE_MEMBER:
			case IGMP_AWAKENING_MEMBER:
				inm->inm_state = IGMP_LAZY_MEMBER;
				break;
			case IGMP_LAZY_MEMBER:
			case IGMP_SLEEPING_MEMBER:
				break;
			}
		}

		break;

	}

	/*
	 * Pass all valid IGMP packets up to any process(es) listening
	 * on a raw IGMP socket.
	 */
	rip_input(m, iphlen, proto);
	return;
}

int
igmp_joingroup(inm)
	struct in_multi *inm;
{
	int report_type;
	int s = splsoftnet();

	inm->inm_state = IGMP_IDLE_MEMBER;

	if (!IN_LOCAL_GROUP(inm->inm_addr.s_addr) &&
	    (inm->inm_ifp->if_flags & IFF_LOOPBACK) == 0) {
		report_type = rti_fill(inm);
		if (report_type == 0)
			return ENOMEM;
		igmp_sendpkt(inm, report_type);
		inm->inm_state = IGMP_DELAYING_MEMBER;
		inm->inm_timer = IGMP_RANDOM_DELAY(
		    IGMP_MAX_HOST_REPORT_DELAY * PR_FASTHZ);
		igmp_timers_are_running = 1;
	} else
		inm->inm_timer = 0;
	splx(s);
	return 0;
}

void
igmp_leavegroup(inm)
	struct in_multi *inm;
{

	switch (inm->inm_state) {
	case IGMP_DELAYING_MEMBER:
	case IGMP_IDLE_MEMBER:
		if (!IN_LOCAL_GROUP(inm->inm_addr.s_addr) &&
		    (inm->inm_ifp->if_flags & IFF_LOOPBACK) == 0)
			if (inm->inm_rti->rti_type == IGMP_v2_ROUTER)
				igmp_sendpkt(inm, IGMP_HOST_LEAVE_MESSAGE);
		break;
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
	case IGMP_SLEEPING_MEMBER:
		break;
	}
}

void
igmp_fasttimo()
{
	struct in_multi *inm;
	struct in_multistep step;
	struct ifnet *ifp = NULL;
#ifdef IGMPV3
	/*
	 * Both of Current-State Record timer and State-Change Record timer
	 * are controled.
	 */
	struct router_info *rti;
	struct mbuf *cm, *sm;
	int cbuflen, sbuflen;
#endif
	int s;

	/*
	 * Quick check to see if any work needs to be done, in order to
	 * minimize the overhead of fasttimo processing.
	 */
	if (!igmp_timers_are_running && !interface_timers_are_running
			&& !state_change_timers_are_running)
		return;

	s = splsoftnet();

#ifdef IGMPV3
	if (interface_timers_are_running) {
		interface_timers_are_running = 0;
		LIST_FOREACH(rti, &rti_head, rti_link) {
			if (rti->rti_timer3 == 0)
				; /* do nothing */
			else if (--rti->rti_timer3 == 0)
				igmp_send_all_current_state_report
						(rti->rti_ifp);
			else
				interface_timers_are_running = 1;
		}
	}
#endif

#ifndef IGMPV3
	if (!igmp_timers_are_running)
#else
	if (!igmp_timers_are_running && !state_change_timers_are_running)
#endif
	{
		splx(s);
		return;
	}
	igmp_timers_are_running = 0;
#ifdef IGMPV3
	state_change_timers_are_running = 0;
	cm = sm = NULL;
	cbuflen = sbuflen = 0;
#endif
	IN_FIRST_MULTI(step, inm);
	ifp = inm->inm_ifp;
	while (inm != NULL) {
		if (inm->inm_timer == 0)
			; /* do nothing */
		else if (--inm->inm_timer == 0) {
			if (inm->inm_state == IGMP_DELAYING_MEMBER) {
				if (inm->inm_rti->rti_type == IGMP_v1_ROUTER)
					igmp_sendpkt(inm,
					    IGMP_v1_HOST_MEMBERSHIP_REPORT);
				else
					igmp_sendpkt(inm,
					    IGMP_v2_HOST_MEMBERSHIP_REPORT);
				inm->inm_state = IGMP_IDLE_MEMBER;
#ifdef IGMPV3
			} else if ((inm->inm_state
					== IGMP_G_QUERY_PENDING_MEMBER) ||
				   (inm->inm_state
					== IGMP_SG_QUERY_PENDING_MEMBER)) {
				if ((cm != NULL) && (ifp != inm->inm_ifp)) {
					igmp_sendbuf(cm, ifp);
					cm = NULL;
				}
				(void)igmp_send_current_state_report
						(&cm, &cbuflen, inm);
				ifp = inm->inm_ifp;
#endif
			}
		} else
			igmp_timers_are_running = 1;

#ifdef IGMPV3
		if (!is_igmp_target(&inm->inm_addr))
			; /* skip */
		else if (inm->inm_source->ims_timer == 0)
			; /* do nothing */
		else if (--inm->inm_source->ims_timer == 0) {
			if ((sm != NULL) && (ifp != inm->inm_ifp)) {
				igmp_sendbuf(sm, ifp);
				sm = NULL;
			}
			/* Check if this report was pending Source-List-Change
			 * report or not. It is only the case that robvar was
			 * not reduced here. (XXX rarely, QRV may be changed
			 * in a same timing.) */
			if (inm->inm_source->ims_robvar
					== inm->inm_rti->rti_qrv) {
				igmp_send_state_change_report(&sm, &sbuflen,
						inm, (u_int8_t)0, (int)1);
				sm = NULL;
			} else if (inm->inm_source->ims_robvar > 0) {
				igmp_send_state_change_report(&sm, &sbuflen,
						inm, (u_int8_t)0, (int)0);
				ifp = inm->inm_ifp;
			}
			if (inm->inm_source->ims_robvar != 0) {
				inm->inm_source->ims_timer = IGMP_RANDOM_DELAY
						(IGMP_UNSOL_INTVL * PR_FASTHZ);
				state_change_timers_are_running = 1;
			}
		} else
			state_change_timers_are_running = 1;
#endif
		IN_NEXT_MULTI(step, inm);
	}
#ifdef IGMPV3
	if (cm != NULL)
		igmp_sendbuf(cm, ifp);
	if (sm != NULL)
		igmp_sendbuf(sm, ifp);
#endif
	splx(s);
}

void
igmp_slowtimo()
{
	struct router_info *rti;
	int s;

	s = splsoftnet();
	LIST_FOREACH(rti, &rti_head, rti_link) {
#ifndef IGMPV3
		if (rti->rti_type == IGMP_v1_ROUTER &&
		    ++rti->rti_age >= IGMP_AGE_THRESHOLD) {
			rti->rti_type = IGMP_v2_ROUTER;
		}
#else
		if ((rti->rti_timer1 == 0) && (rti->rti_timer2 == 0)) {
			switch (igmp_version) {
			case 1:
				if (rti->rti_type != IGMP_v1_ROUTER)
					rti->rti_type = IGMP_v1_ROUTER;
				break;
			case 2:
				if (rti->rti_type != IGMP_v2_ROUTER)
					rti->rti_type = IGMP_v2_ROUTER;
				break;
			case 0:
			case 3:
				if (rti->rti_type != IGMP_v3_ROUTER)
					rti->rti_type = IGMP_v3_ROUTER;
				break;
			default:
				/* impossible */
				break;
			}
		} else if ((rti->rti_timer1 == 0) && (rti->rti_timer2 > 0)) {
			--rti->rti_timer2;
			switch (igmp_version) {
			case 1:
				if (rti->rti_type != IGMP_v1_ROUTER)
					rti->rti_type = IGMP_v1_ROUTER;
				break;
			case 0:
			case 2:
			case 3:
				if (rti->rti_type != IGMP_v2_ROUTER)
					rti->rti_type = IGMP_v2_ROUTER;
				break;
			default:
				/* impossible */
				break;
			}
		} else if (rti->rti_timer1 > 0) {
			--rti->rti_timer1;
			if (rti->rti_timer2 > 0)
				rti->rti_timer2 = 0;
		}
#endif
	}
	splx(s);
}

void
igmp_sendpkt(inm, type)
	struct in_multi *inm;
	int type;
{
	struct mbuf *m;
	struct igmp *igmp;
	struct ip *ip;
	struct ip_moptions imo;
#ifdef MROUTING
	extern struct socket *ip_mrouter;
#endif /* MROUTING */

	if (type < 0)
		return;
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return;
	/*
	 * Assume max_linkhdr + sizeof(struct ip) + IGMP_MINLEN
	 * is smaller than mbuf size returned by MGETHDR.
	 */
	m->m_data += max_linkhdr;
	m->m_len = sizeof(struct ip) + IGMP_MINLEN;
	m->m_pkthdr.len = sizeof(struct ip) + IGMP_MINLEN;

	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = htons(sizeof(struct ip) + IGMP_MINLEN);
	ip->ip_off = htons(0);
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src = zeroin_addr;
	if (type == IGMP_HOST_LEAVE_MESSAGE)
		ip->ip_dst.s_addr = INADDR_ALLRTRS_GROUP;
	else
		ip->ip_dst = inm->inm_addr;

	m->m_data += sizeof(struct ip);
	m->m_len -= sizeof(struct ip);
	igmp = mtod(m, struct igmp *);
	igmp->igmp_type = type;
	igmp->igmp_code = 0;
	igmp->igmp_group = inm->inm_addr;
	igmp->igmp_cksum = 0;
	igmp->igmp_cksum = in_cksum(m, IGMP_MINLEN);
	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);

	imo.imo_multicast_ifp = inm->inm_ifp;
	imo.imo_multicast_ttl = 1;
#ifdef RSVP_ISI
	imo.imo_multicast_vif = -1;
#endif
	/*
	 * Request loopback of the report if we are acting as a multicast
	 * router, so that the process-level routing daemon can hear it.
	 */
#ifdef MROUTING
	imo.imo_multicast_loop = (ip_mrouter != NULL);
#else
	imo.imo_multicast_loop = 0;
#endif /* MROUTING */

	if (igmpsendwithra && inm->inm_rti->rti_type == IGMP_v2_ROUTER) {
		ip_output(m, router_alert, (struct route *)0,
			  IP_MULTICASTOPTS, &imo);
	} else { /* IGMPv1 or IGMPv2 with no RA restriction */
		ip_output(m, (struct mbuf *)0, (struct route *)0,
			  IP_MULTICASTOPTS, &imo);
	}
	++igmpstat.igps_snd_v1v2_reports;
}

#ifdef IGMPV3
void
igmp_sendbuf(m, ifp)
	struct mbuf *m;
	struct ifnet *ifp;
{
	struct igmp_report_hdr *igmp_rhdr;
	struct igmp_group_record_hdr *igmp_ghdr;
	int len;
	u_int16_t i;
	struct ip_moptions imo;
#ifdef MROUTING
	extern struct socket *ip_mrouter;
#endif /* MROUTING */

	/*
	 * Insert check sum and send the message.
	 */
	if (m == NULL) {
#ifdef IGMPV3_DEBUG
		printf("igmp_sendbuf: mbuf is NULL\n");
#endif
		return;
	}
	m->m_data += sizeof(struct ip);
	m->m_len -= sizeof(struct ip);
	igmp_rhdr = mtod(m, struct igmp_report_hdr *);
	len = sizeof(struct igmp_report_hdr);
	for (i = 0; i < igmp_rhdr->igmp_grpnum; i++) {
		igmp_ghdr = (struct igmp_group_record_hdr *)
					((char *)igmp_rhdr + len);
		len += ghdrlen + SOURCE_RECORD_LEN(igmp_ghdr->numsrc);
		HTONS(igmp_ghdr->numsrc);
	}
	HTONS(igmp_rhdr->igmp_grpnum);
	igmp_rhdr->igmp_cksum = 0;
	igmp_rhdr->igmp_cksum = in_cksum(m, len);
	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);

	imo.imo_multicast_ifp = ifp;
	imo.imo_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
#ifdef RSVP_ISI
	imo.imo_multicast_vif = -1;
#endif
#ifdef MROUTING
	imo.imo_multicast_loop = (ip_mrouter != NULL);
#else
	imo.imo_multicast_loop = 0;
#endif
	if (igmpsendwithra)
		ip_output(m, router_alert, (struct route *)0,
				IP_MULTICASTOPTS, &imo);
	else
		ip_output(m, (struct mbuf *)0, (struct route *)0,
				IP_MULTICASTOPTS, &imo);
	++igmpstat.igps_snd_v3_reports;
}

/*
 * Timer adjustment on reception of an IGMPv3 Query.
 */
int
igmp_set_timer(ifp, rti, igmp, igmplen, query_type)
	struct ifnet *ifp;
	struct router_info *rti;
	struct igmp *igmp;
	int igmplen;
	u_int8_t query_type;
{
	struct in_multi *inm;
	struct in_multistep step;
	int timer;			/* Max-Resp-Timer */
	int timer_i = 0;		/* interface timer */
	int timer_g = 0;		/* group timer */
	int error;
	int s = splsoftnet();

	/*
	 * Parse QRV, QQI, and QRI timer values.
	 */
	if (((rti->rti_qrv = IGMP_QRV(igmp->igmp_rtval)) == 0) ||
				(rti->rti_qrv > 7))
	    rti->rti_qrv = IGMP_DEF_RV;
	if ((igmp->igmp_qqi > 0) && (igmp->igmp_qqi < 128))
	    rti->rti_qqi = igmp->igmp_qqi;
	else if (igmp->igmp_qqi >= 128)
	    rti->rti_qqi = ((IGMP_MANT(igmp->igmp_qqi) | 0x10)
				<< (IGMP_EXP(igmp->igmp_qqi) + 3));
	else
	    rti->rti_qqi = IGMP_DEF_QI;
	rti->rti_qri = igmp->igmp_code;
	if (rti->rti_qri >= rti->rti_qqi)
	    rti->rti_qri = (rti->rti_qqi - 1) / IGMP_TIMER_SCALE;
	    /* XXX tentatively adjusted */
	else
	    rti->rti_qri /= IGMP_TIMER_SCALE;

	if ((igmp->igmp_code > 0) && (igmp->igmp_code < 128))
	    timer = igmp->igmp_code;
	else
	    timer = (IGMP_MANT(igmp->igmp_code) | 0x10)
			<< (IGMP_EXP(igmp->igmp_code) + 3);

	/*
	 * Set interface timer if the query is Generic Query.
	 * Get group timer if the query is not Generic Query.
	 */
	if (query_type == IGMP_v3_GENERAL_QUERY) {
	    timer_i = timer * PR_FASTHZ / IGMP_TIMER_SCALE;
	    timer_i = IGMP_RANDOM_DELAY(timer_i);
	    if (interface_timers_are_running &&
			(rti->rti_timer3 != 0) && (rti->rti_timer3 < timer_i))
		; /* don't need to update interface timer */
	    else {
		rti->rti_timer3 = timer_i;
		interface_timers_are_running = 1;
	    }
	} else { /* G or SG query */
	    timer_g = timer * PR_FASTHZ / IGMP_TIMER_SCALE;
	    timer_g = IGMP_RANDOM_DELAY(timer_g);
	}

	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
	    if (!is_igmp_target(&inm->inm_addr) || inm->inm_ifp != ifp)
		goto next_multi;

	    if ((inm->inm_source->ims_grpjoin == 0) &&
		(inm->inm_source->ims_mode == MCAST_INCLUDE) &&
		(inm->inm_source->ims_cur->numsrc == 0))
		goto next_multi; /* no need to consider any timer */

	    if (query_type == IGMP_v3_GENERAL_QUERY) {
		/* Any previously pending response to Group- or
		 * Group-and-Source-Specific Query is canceled, if pending
		 * group timer is not sooner than new interface timer. */
		if (!igmp_timers_are_running)
		    goto next_multi;
		if (inm->inm_timer <= rti->rti_timer3)
		    goto next_multi;
		inm->inm_state = IGMP_IDLE_MEMBER;
		inm->inm_timer = 0;
		in_free_msf_source_list(inm->inm_source->ims_rec->head);
		inm->inm_source->ims_rec->numsrc = 0;
		goto next_multi;
	    } else if (!in_hosteq(inm->inm_addr, igmp->igmp_group))
		goto next_multi;

	    /*
	     * If interface timer is sooner than new group timer,
	     * just ignore this Query for this group address.
	     */
	    if (interface_timers_are_running && (rti->rti_timer3 < timer_g)) {
		inm->inm_state = IGMP_IDLE_MEMBER;
		inm->inm_timer = 0;
		break;
	    }

	    /* Receive Group-Specific Query */
	    if (query_type == IGMP_v3_GROUP_QUERY) {
		/*
		 * Group-Source list is cleared and a single response is
		 * scheduled, and group timer is set the earliest of the
		 * remaining time for the pending report and the selected
		 * delay.
		 */
		if ((inm->inm_state != IGMP_G_QUERY_PENDING_MEMBER) &&
		    (inm->inm_state != IGMP_SG_QUERY_PENDING_MEMBER)) {
		    igmp_timers_are_running = 1;
		    inm->inm_timer = timer_g;
		} else {
		    in_free_msf_source_list(inm->inm_source->ims_rec->head);
		    inm->inm_source->ims_rec->numsrc = 0;
		    inm->inm_timer = min(inm->inm_timer, timer_g);
		}
		inm->inm_state = IGMP_G_QUERY_PENDING_MEMBER;
		break;
	    }

	    /* Receive Group-and-Source-Specific Query */
	    if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER) {
		/*
		 * If there is a pending response for this group's
		 * Group-Specific Query, then queried sources are not
		 * recorded and pending status is not changed. Only the
		 * timer may be changed.
		 */
		inm->inm_timer = min(inm->inm_timer, timer_g);
		break;
	    }
	    /* Queried sources are augmented. */
	    if ((error = igmp_record_queried_source(inm, igmp, igmplen)) > 0) {
		if (error == EOPNOTSUPP)
		    ++igmpstat.igps_rcv_badqueries;
		else
		    ++igmpstat.igps_rcv_query_fails;
		splx(s);
		return error;
	    } else if (error == 0) {
		if (inm->inm_timer != 0)
			inm->inm_timer = min(inm->inm_timer, timer_g);
		else {
			igmp_timers_are_running = 1;
			inm->inm_timer = timer_g;
		}
		inm->inm_state = IGMP_SG_QUERY_PENDING_MEMBER;
	    }
	    break;
next_multi:
	    IN_NEXT_MULTI(step, inm);
	} /* while */

	splx(s);
	return 0;
}

/*
 * Set IGMP Host Compatibility Mode.
 */
void
igmp_set_hostcompat(ifp, rti, query_ver)
	struct ifnet *ifp;
	struct router_info *rti;
	int query_ver;
{
	int s = splsoftnet();

	/*
	 * Keep Older Version Querier Present timer.
	 */
	if (query_ver == IGMP_v1_QUERY) {
		rti->rti_timer1 = rti->rti_qrv * rti->rti_qqi + rti->rti_qri;
		rti->rti_timer1 *= PR_SLOWHZ;
	} else if (query_ver == IGMP_v2_QUERY) {
		rti->rti_timer2 = rti->rti_qrv * rti->rti_qqi + rti->rti_qri;
		rti->rti_timer2 *= PR_SLOWHZ;
	}

	/*
	 * Check/set host compatibility mode. Whenever a host changes
	 * its compatability mode, cancel all its pending response and
	 * retransmission timers.
	 */
	if ((rti->rti_timer1 == 0) && (rti->rti_timer2 > 0)) {
		if (rti->rti_type != IGMP_v2_ROUTER) {
			rti->rti_type = IGMP_v2_ROUTER;
			igmp_cancel_pending_response(ifp, rti);
		}
	} else if (rti->rti_timer1 > 0) {
		if (rti->rti_type != IGMP_v1_ROUTER) {
			rti->rti_type = IGMP_v1_ROUTER;
			igmp_cancel_pending_response(ifp, rti);
		}
	}

	splx(s);
}

/*
 * Parse source addresses from IGMPv3 Group-and-Source-Specific Query message
 * and merge them in a recorded source list.
 * If no pending source was recorded, return -1.
 * If some source was recorded as a reply for Group-and-Source-Specific Query,
 * return 0.
 */ 
int
igmp_record_queried_source(inm, igmp, igmplen)
	struct in_multi *inm;
	struct igmp *igmp;
	int igmplen;
{
	struct in_addr_source *curias;
	u_int16_t numsrc, i;
	int ref_count;
	struct sockaddr_in src;
	int recorded = 0;

	igmplen -= qhdrlen; /* remaining source list */
	numsrc = ntohs(igmp->igmp_numsrc);
	if (numsrc != igmplen / addrlen)
	    return EOPNOTSUPP; /* XXX */

	for (i = 0; i < numsrc && igmplen >= addrlen; i++, igmplen -= addrlen) {
	    bzero(&src, sizeof(src));
	    src.sin_family = AF_INET;
	    src.sin_len = sizeof(src);
	    src.sin_addr = igmp->src[i];
	    if (inm->inm_source->ims_grpjoin > 0) {
		if ((ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_rec,
					 &src, IMS_ADD_SOURCE)) < 0) {
		    in_free_msf_source_list(inm->inm_source->ims_rec->head);
		    inm->inm_source->ims_rec->numsrc = 0;
		    return ENOBUFS;
		}
		if (ref_count == 1)
		    ++inm->inm_source->ims_rec->numsrc;
		recorded = 1;
		continue;
	    }

	    LIST_FOREACH(curias, inm->inm_source->ims_cur->head, ias_list) {
		/* sanity check */
		if (curias->ias_addr.sin_family != src.sin_family)
		    continue;

		if (SS_CMP(&curias->ias_addr, <, &src))
		    continue;

		if (SS_CMP(&curias->ias_addr, ==, &src)) {
		    if (inm->inm_source->ims_mode != MCAST_INCLUDE)
			break;
		    ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_rec,
					 &src, IMS_ADD_SOURCE);
		    if (ref_count < 0) {
			in_free_msf_source_list(inm->inm_source->ims_rec->head);
			inm->inm_source->ims_rec->numsrc = 0;
			return ENOBUFS;
		    }
		    if (ref_count == 1)
			++inm->inm_source->ims_rec->numsrc;
		    recorded = 1;
		    break;
		}

		/* curias->ias_addr > src */
		if (inm->inm_source->ims_mode == MCAST_EXCLUDE) {
		    ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_rec,
					 &src, IMS_ADD_SOURCE);
		    if (ref_count < 0) {
			in_free_msf_source_list(inm->inm_source->ims_rec->head);
			inm->inm_source->ims_rec->numsrc = 0;
			return ENOBUFS;
		    }
		    if (ref_count == 1)
			++inm->inm_source->ims_rec->numsrc;
		    recorded = 1;
		}

		break;
	    }

	    if (!curias) {
		if (inm->inm_source->ims_mode == MCAST_EXCLUDE) {
		    ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_rec,
					 &src, IMS_ADD_SOURCE);
		    if (ref_count < 0) {
			in_free_msf_source_list(inm->inm_source->ims_rec->head);
			inm->inm_source->ims_rec->numsrc = 0;
			return ENOBUFS;
		    }
		    if (ref_count == 1)
			++inm->inm_source->ims_rec->numsrc;
		    recorded = 1;
		}
	    }
	}

	if (i != numsrc) {
	    in_free_msf_source_list(inm->inm_source->ims_rec->head);
	    inm->inm_source->ims_rec->numsrc = 0;
	    return EOPNOTSUPP; /* XXX */
	}

	return ((recorded == 0) ? -1 : 0);
}

/*
 * Send Current-State Report for General Query response.
 */
void
igmp_send_all_current_state_report(ifp)
	struct ifnet *ifp;
{
	struct mbuf *m = NULL;
	int buflen = 0;
	struct in_multi *inm;
	struct in_multistep step;

	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		if (inm->inm_ifp != ifp || !is_igmp_target(&inm->inm_addr))
			goto next_multi;

		if (igmp_send_current_state_report(&m, &buflen, inm) != 0)
			return;
next_multi:
		IN_NEXT_MULTI(step, inm);
	}
	if (m != NULL)
		igmp_sendbuf(m, ifp);
}

/*
 * Send Current-State Report for Group- and Group-and-Source-Sepcific Query
 * response.
 */
int
igmp_send_current_state_report(m0, buflenp, inm)
	struct mbuf **m0;	/* mbuf is inherited to put multiple group
				 * records in one message */
	int *buflenp;
	struct in_multi *inm;
{
	struct mbuf *m = *m0;
	struct ip *ip;
	struct igmp_report_hdr *igmp_rhdr;
	int buflen;
	u_int16_t max_len;
	u_int16_t numsrc, src_once, src_done = 0;
	u_int8_t type = 0;
	int error = 0;

	if (!is_igmp_target(&inm->inm_addr) ||
		(inm->inm_ifp->if_flags & IFF_LOOPBACK) != 0)
	    return 0;

	/* MCLBYTES is the maximum length even if if_mtu is too big. */
	max_len = (inm->inm_ifp->if_mtu < MCLBYTES) ?
				inm->inm_ifp->if_mtu : MCLBYTES;

	if (inm->inm_source->ims_mode == MCAST_INCLUDE)
	    type = MODE_IS_INCLUDE;
	else if (inm->inm_source->ims_mode == MCAST_EXCLUDE)
	    type = MODE_IS_EXCLUDE;

	/*
	 * Prepare record for General, Group-Specific, and Group-and-Source-
	 * Specific Query.
	 */
	if (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER) {
	    type = MODE_IS_INCLUDE; /* always */
	    numsrc = inm->inm_source->ims_rec->numsrc;
	} else
	    numsrc = inm->inm_source->ims_cur->numsrc;

	if (type == MODE_IS_INCLUDE && numsrc == 0)
	    return 0; /* no need to send Current-State Report */

	/*
	 * If Report type is MODE_IS_EXCLUDE, a single Group Record is sent,
	 * containing as many source addresses as can fit, and the remaining
	 * source addresses are not reported.
	 */
	if (type == MODE_IS_EXCLUDE) {
	    if (max_len < SOURCE_RECORD_LEN(numsrc)
				+ sizeof(struct ip) + rhdrlen + ghdrlen)
		numsrc = (max_len - sizeof(struct ip)
				- rhdrlen - ghdrlen) / addrlen;
	}

	if (m == NULL) {
	    SET_REPORTHDR(*m0, numsrc);
	    if (error != 0) {
#ifdef IGMPV3_DEBUG
		printf("igmp_send_current_state_report: error preparing new report header.\n");
#endif
		return error;
	    }
	    m = *m0;
	    *buflenp = buflen;
	} else {
	    if (ghdrlen + SOURCE_RECORD_LEN(numsrc) > M_TRAILINGSPACE(m)) {
		/*
		 * When remaining buffer is not enough to insert new group
		 * record, send current buffer and create a new buffer for
		 * this record.
		 */
		igmp_sendbuf(m, inm->inm_ifp);
		m = NULL;
		SET_REPORTHDR(*m0, numsrc);
		if (error != 0) {
#ifdef IGMPV3_DEBUG
		    printf("igmp_send_current_state_report: error preparing new report header.\n");
#endif
		    return error;
		}
		m = *m0;
		*buflenp = buflen;
	    }
	} /* m == NULL */

	if (type == MODE_IS_EXCLUDE) {
	    /*
	     * The number of sources of MODE_IS_EXCLUDE record is already
	     * adjusted to fit in one buffer.
	     */
	    if (igmp_create_group_record(m, buflenp, inm, numsrc,
					 &src_done, type) != numsrc) {
#ifdef IGMPV3_DEBUG
		printf("igmp_send_current_state_report: error of sending MODE_IS_EXCLUDE report?\n");
#endif
		m_freem(m);
		return EOPNOTSUPP; /* XXX source address insert didn't
				    * finished. strange... */
	    }
	} else {
	    while (1) {
		/* XXX Some security implication? */
		src_once = igmp_create_group_record
				(m, buflenp, inm, numsrc, &src_done, type);
		if (numsrc > src_done) {
		    /*
		     * Source address insert didn't finished, so, send this
		     * IGMP report here and try to make separate message
		     * with remaining sources.
		     */
		    igmp_sendbuf(m, inm->inm_ifp);
		    m = NULL;
		    SET_REPORTHDR(*m0, numsrc - src_done);
		    if (error != 0) {
#ifdef IGMPV3_DEBUG
			printf("igmp_send_current_state_report: error preparing additional report header.\n");
#endif
			return error;
		    }
		    m = *m0;
		    *buflenp = buflen;
		} else /* finish insertion */
		    break;
	    } /* while */
	}

	/*
	 * If pending query was Group-and-Source-Specific Query, pending
	 * (merged) source list is cleared.
	 */
	if (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER) {
	    in_free_msf_source_list(inm->inm_source->ims_rec->head);
	    inm->inm_source->ims_rec->numsrc = 0;
	}
	inm->inm_state = IGMP_IDLE_MEMBER;
	inm->inm_timer = 0;

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
igmp_send_state_change_report(m0, buflenp, inm, type, timer_init)
	struct mbuf **m0;
	int *buflenp;
	struct in_multi *inm;
	u_int8_t type;
	int timer_init;		/* set this when IPMulticastListen() invoked */
{
	struct mbuf *m = *m0;
	struct ip *ip;
	struct igmp_report_hdr *igmp_rhdr;
	u_int16_t max_len;
	u_int16_t numsrc, src_once, src_done = 0;
	int buflen;
	int error = 0;

	if (!is_igmp_target(&inm->inm_addr) ||
		(inm->inm_ifp->if_flags & IFF_LOOPBACK) != 0)
	    return;

	/*
	 * If there is pending Filter-Mode-Change report, Source-List-Change
	 * report will be merged in an another message and scheduled to be
	 * sent after Filter-Mode-Change report is sent.
	 */
	if (inm->inm_source->ims_toex != NULL) {
	    /* Initial TO_EX request must specify "type". */
	    if (type == 0) {
		if (timer_init &&
			((inm->inm_source->ims_alw != NULL &&
				inm->inm_source->ims_alw->numsrc > 0) ||
			 (inm->inm_source->ims_blk != NULL &&
				inm->inm_source->ims_blk->numsrc > 0)))
		    return; /* scheduled later */

		type = CHANGE_TO_EXCLUDE_MODE;
	    }
	}
	if (inm->inm_source->ims_toin != NULL) {
	    /* Initial TO_IN request must specify "type". */
	    if (type == 0) {
		if (timer_init &&
			((inm->inm_source->ims_alw != NULL &&
				inm->inm_source->ims_alw->numsrc > 0) ||
			 (inm->inm_source->ims_blk != NULL &&
				inm->inm_source->ims_blk->numsrc > 0)))
		    return; /* scheduled later */

		type = CHANGE_TO_INCLUDE_MODE;
	    }
	}
	if (timer_init) {
	    inm->inm_source->ims_robvar = inm->inm_rti->rti_qrv;
	    inm->inm_source->ims_timer
			= IGMP_RANDOM_DELAY(IGMP_UNSOL_INTVL * PR_FASTHZ);
	} else if (!(inm->inm_source->ims_robvar > 0))
	    return;

	/* MCLBYTES is the maximum length even if if_mtu is too big. */
	max_len = (inm->inm_ifp->if_mtu < MCLBYTES) ?
				inm->inm_ifp->if_mtu : MCLBYTES;

	/*
	 * If Report type is CHANGE_TO_EXCLUDE_MODE, a single Group Record
	 * is sent, containing as many source addresses as can fit, and the
	 * remaining source addresses are not reported.
	 * Note that numsrc may or may not be 0.
	 */
	if (type == CHANGE_TO_EXCLUDE_MODE) {
	    numsrc = inm->inm_source->ims_toex->numsrc;
	    if (max_len < SOURCE_RECORD_LEN(numsrc)
				+ sizeof(struct ip) + rhdrlen + ghdrlen)
		/* toex's numsrc should be fit in a single message. */
		numsrc = (max_len - sizeof(struct ip)
				- rhdrlen - ghdrlen) / addrlen;
	} else if (type == CHANGE_TO_INCLUDE_MODE) {
	    numsrc = inm->inm_source->ims_toin->numsrc;
	} else { /* ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES */
	    numsrc = 0;
	    if (inm->inm_source->ims_alw != NULL)
		numsrc = inm->inm_source->ims_alw->numsrc;
	    if (inm->inm_source->ims_blk != NULL)
		numsrc = max(numsrc, inm->inm_source->ims_blk->numsrc);
	    if (numsrc == 0) {
		/* XXX following is tentative process. this should not be
		 * executed. this is just to avoid "loop" by timer. */
		if (*m0 != NULL) {
		    igmp_sendbuf(*m0, inm->inm_ifp);
		    *m0 = NULL;
		} else if (inm->inm_source->ims_robvar > 0)
		    --inm->inm_source->ims_robvar;
		return;
	    }
	}

	if (m == NULL) {
	    SET_REPORTHDR(*m0, numsrc);
	    if (error != 0) {
#ifdef IGMPV3_DEBUG
		printf("igmp_send_state_change_report: error preparing new report header.\n");
#endif
		return; /* robvar is not reduced */
	    }
	    m = *m0;
	    *buflenp = buflen;
	} else {
	    if (ghdrlen + SOURCE_RECORD_LEN(numsrc)
			> M_TRAILINGSPACE(m) - sizeof(struct ip) - *buflenp) {
		/*
		 * When remaining buffer is not enough to insert new group
		 * record, send current buffer and create a new buffer for
		 * this record.
		 */
		igmp_sendbuf(m, inm->inm_ifp);
		m = NULL;
		SET_REPORTHDR(*m0, numsrc);
		if (error != 0) {
#ifdef IGMPV3_DEBUG
		    printf("igmp_send_state_change_report: error preparing new report header.\n");
#endif
		    return;
		}
		m = *m0;
		*buflenp = buflen;
	    }
	}

	if ((type == CHANGE_TO_INCLUDE_MODE) ||
			(type == CHANGE_TO_EXCLUDE_MODE)) {
	    if (type == CHANGE_TO_EXCLUDE_MODE) {
		/*
		 * The number of sources of CHANGE_TO_EXCLUDE_MODE record is
		 * already adjusted to fit in one buffer.
		 */
		if (igmp_create_group_record
				(m, buflenp, inm, numsrc, &src_done, type)
				!= numsrc) {
#ifdef IGMPV3_DEBUG
		    printf("igmp_send_state_change_report: error of sending CHANGE_TO_EXCLUDE_MODE report?\n");
#endif
		    m_freem(m);
		    return; /* XXX source address insert didn't finished.
			     * strange... robvar is not reduced */
		}
		if (timer_init) {
		    state_change_timers_are_running = 1;
		    igmp_sendbuf(m, inm->inm_ifp);
		}
		if (--inm->inm_source->ims_robvar == 0) {
		    if (inm->inm_source->ims_toex != NULL) {
			/* For TO_EX list, it MUST be deleted after
			 * retransmission is done. This is because
			 * igmp_fasttimo() doesn't know if the pending TO_EX
			 * report exists or not. */
			in_free_msf_source_list
					(inm->inm_source->ims_toex->head);
			FREE(inm->inm_source->ims_toex->head, M_MSFILTER);
			FREE(inm->inm_source->ims_toex, M_MSFILTER);
			inm->inm_source->ims_toex = NULL;
		    }
		    /* Prepare scheduled Source-List-Change Report */
		    if ((inm->inm_source->ims_alw != NULL &&
				inm->inm_source->ims_alw->numsrc > 0) ||
			 (inm->inm_source->ims_blk != NULL &&
				inm->inm_source->ims_blk->numsrc > 0)) {
			state_change_timers_are_running = 1;
			inm->inm_source->ims_robvar = inm->inm_rti->rti_qrv;
			inm->inm_source->ims_timer
			    = IGMP_RANDOM_DELAY(IGMP_UNSOL_INTVL * PR_FASTHZ);
		    } else
			inm->inm_source->ims_timer = 0;
		}
	    } else if (type == CHANGE_TO_INCLUDE_MODE) {
		while (1) {
		    /* XXX Some security implication? */
		    src_once = igmp_create_group_record
					(m, buflenp, inm, numsrc,
					 &src_done, type);
		    if (numsrc > src_done) {
			igmp_sendbuf(m, inm->inm_ifp);
			m = NULL;
			SET_REPORTHDR(*m0, numsrc - src_done);
			if (error != 0) {
#ifdef IGMPV3_DEBUG
			    printf("igmp_send_state_change_report: error preparing additional report header.\n");
#endif
			    return;
			}
			m = *m0;
			*buflenp = buflen;
		    } else { /* finish insertion */
			break;
		    }
		}
		if (timer_init) {
		    state_change_timers_are_running = 1;
		    igmp_sendbuf(m, inm->inm_ifp);
		}
		if (--inm->inm_source->ims_robvar == 0) {
		    if (inm->inm_source->ims_toin != NULL) {
			/* For TO_IN list, it MUST be deleted after
			 * retransmission is done. This is because
			 * igmp_fasttimo() doesn't know if the pending TO_IN
			 * report exists or not. */
			in_free_msf_source_list
					(inm->inm_source->ims_toin->head);
			FREE(inm->inm_source->ims_toin->head, M_MSFILTER);
			FREE(inm->inm_source->ims_toin, M_MSFILTER);
			inm->inm_source->ims_toin = NULL;
		    }
		    /* Prepare scheduled Source-List-Change Report */
		    if ((inm->inm_source->ims_alw != NULL &&
				inm->inm_source->ims_alw->numsrc > 0) ||
			 (inm->inm_source->ims_blk != NULL &&
				inm->inm_source->ims_blk->numsrc > 0)) {
			state_change_timers_are_running = 1;
			inm->inm_source->ims_robvar = inm->inm_rti->rti_qrv;
			inm->inm_source->ims_timer
			    = IGMP_RANDOM_DELAY(IGMP_UNSOL_INTVL * PR_FASTHZ);
		    } else
			inm->inm_source->ims_timer = 0;
		}
	    }

	} else { /* ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES */
	    if ((inm->inm_source->ims_alw != NULL) &&
			(inm->inm_source->ims_alw->numsrc != 0))
		type = ALLOW_NEW_SOURCES;
	    else if ((inm->inm_source->ims_blk != NULL) &&
			(inm->inm_source->ims_blk->numsrc != 0))
		type = BLOCK_OLD_SOURCES;
	    else
		return;

	    while (1) {
		/* XXX Some security implication? */
		if (type == ALLOW_NEW_SOURCES)
		    numsrc = inm->inm_source->ims_alw->numsrc;
		else if (type == BLOCK_OLD_SOURCES)
		    numsrc = inm->inm_source->ims_blk->numsrc;
		else /* finish group record insertion */
		    break;
		src_once = igmp_create_group_record
					(m, buflenp, inm, numsrc,
					 &src_done, type);
		if (numsrc > src_done) {
		    igmp_sendbuf(m, inm->inm_ifp);
		    m = NULL;
		    SET_REPORTHDR(*m0, numsrc - src_done);
		    if (error != 0) {
#ifdef IGMPV3_DEBUG
			printf("igmp_send_state_change_report: error preparing additional report header.\n");
#endif
			return;
		    }
		    m = *m0;
		    *buflenp = buflen;
		} else { /* next group record */
		    if ((type == ALLOW_NEW_SOURCES) &&
				(inm->inm_source->ims_blk != NULL) &&
				(inm->inm_source->ims_blk->numsrc != 0))
			type = BLOCK_OLD_SOURCES;
		    else
			type = 0;
		    src_done = 0;
		}
	    }
	    if (timer_init) {
		state_change_timers_are_running = 1;
		igmp_sendbuf(m, inm->inm_ifp);
	    }
	    if (--inm->inm_source->ims_robvar == 0) {
		if ((inm->inm_source->ims_alw != NULL) &&
		    		(inm->inm_source->ims_alw->numsrc != 0)) {
		    in_free_msf_source_list(inm->inm_source->ims_alw->head);
		    inm->inm_source->ims_alw->numsrc = 0;
		}
		if ((inm->inm_source->ims_blk != NULL) &&
		    		(inm->inm_source->ims_blk->numsrc != 0)) {
		    in_free_msf_source_list(inm->inm_source->ims_blk->head);
		    inm->inm_source->ims_blk->numsrc = 0;
		}
		inm->inm_source->ims_timer = 0;
	    }
	}

	return;
}

int
igmp_create_group_record(m, buflenp, inm, numsrc, done, type)
	struct mbuf *m;
	int *buflenp;
	struct in_multi *inm;
	u_int16_t numsrc;
	u_int16_t *done;
	u_int8_t type;
{
	struct ip *ip;
	struct igmp_report_hdr *igmp_rhdr;
	struct igmp_group_record_hdr *igmp_ghdr;
	struct in_addr_source *ias;
	struct in_addr_slist *iasl;
	u_int16_t i, total;
	int mfreelen;

	ip = mtod(m, struct ip *);
	igmp_rhdr = (struct igmp_report_hdr *)((char *)ip + sizeof(*ip));
	++igmp_rhdr->igmp_grpnum;

	igmp_ghdr = (struct igmp_group_record_hdr *)((char *)ip + *buflenp);
	igmp_ghdr->record_type = type;
	igmp_ghdr->auxlen = 0;
	igmp_ghdr->numsrc = 0;
	igmp_ghdr->group.s_addr = inm->inm_addr.s_addr;
	ip->ip_len += ghdrlen;
	m->m_len += ghdrlen;
	m->m_pkthdr.len += ghdrlen;
	mfreelen = M_TRAILINGSPACE(m) - *buflenp;

	GET_REPORT_SOURCE_HEAD(inm, type, iasl);
	total = 0;
	i = 0;
	if (iasl != NULL) {
		for (ias = LIST_FIRST(iasl->head); total < *done;
				total++, ias = LIST_NEXT(ias, ias_list))
			; /* adjust a source pointer. */
		/* Insert source address to mbuf */
		for (; i < numsrc && ias != NULL && mfreelen > addrlen;
				i++, total++, mfreelen -= addrlen,
				ias = LIST_NEXT(ias, ias_list))
			bcopy(&ias->ias_addr.sin_addr, 
			      &igmp_ghdr->src[i], sizeof(igmp_ghdr->src[i]));
	}

	*done = total;
	ip->ip_len += SOURCE_RECORD_LEN(i);
	igmp_ghdr->numsrc = i;
	*buflenp += ghdrlen + SOURCE_RECORD_LEN(i);
	m->m_len += SOURCE_RECORD_LEN(i);
	m->m_pkthdr.len += SOURCE_RECORD_LEN(i);
	return i;
}

/*
 * Cancel all IGMPv3 pending response and retransmission timers on an
 * interface.
 */
void
igmp_cancel_pending_response(ifp, rti)
	struct ifnet *ifp;
	struct router_info *rti;
{
	struct in_multi *inm;
	struct in_multistep step;

	rti->rti_timer3 = 0;
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
	    if (inm->inm_ifp != ifp)
		goto next_multi;
	    if (!is_igmp_target(&inm->inm_addr))
		goto next_multi;
	    if (inm->inm_source == NULL)
		goto next_multi;

	    inm->inm_source->ims_robvar = 0;
	    inm->inm_source->ims_timer = 0;
	    in_free_msf_source_list(inm->inm_source->ims_rec->head);
	    inm->inm_source->ims_rec->numsrc = 0;
	    if (inm->inm_source->ims_alw != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_alw->head);
		inm->inm_source->ims_alw->numsrc = 0;
	    }
	    if (inm->inm_source->ims_blk != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_blk->head);
		inm->inm_source->ims_blk->numsrc = 0;
	    }
	    if (inm->inm_source->ims_toin != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_toin->head);
		/* For TO_IN list, it MUST be deleted. */
		FREE(inm->inm_source->ims_toin->head, M_MSFILTER);
		FREE(inm->inm_source->ims_toin, M_MSFILTER);
		inm->inm_source->ims_toin = NULL;
	    }
	    if (inm->inm_source->ims_toex != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_toex->head);
		/* For TO_EX list, it MUST be deleted. */
		FREE(inm->inm_source->ims_toex->head, M_MSFILTER);
		FREE(inm->inm_source->ims_toex, M_MSFILTER);
		inm->inm_source->ims_toex = NULL;
	    }

next_multi:
	    IN_NEXT_MULTI(step, inm);
	}
}
#endif /* IGMPV3 */

#ifdef __OpenBSD__
int
igmp_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
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
	case IGMPCTL_SENDWITHRA:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &igmpsendwithra);
		break;
	case IGMPCTL_DROPWITHNORA:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &igmpdropwithnora);
		break;
	case IGMPCTL_MAXSRCFILTER:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &igmpmaxsrcfilter);
		break;
	case IGMPCTL_SOMAXSRC:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &igmpsomaxsrc);
		break;
	case IGMPCTL_VERSION:
		error = sysctl_int(oldp, oldlenp, newp, newlen,
				   &igmp_version);
		break;
	default:
		error = ENOPROTOOPT;
		break;
	}
	return error;
}
#endif

void
igmp_purgeif(ifp)
	struct ifnet *ifp;
{

	rti_delete(ifp);
}

int
is_igmp_target(grp)
	struct in_addr *grp;
{
	if (!IN_MULTICAST(grp->s_addr))
		return 0;
	if (grp->s_addr == INADDR_ALLHOSTS_GROUP)
		return 0;
	return 1;
}
