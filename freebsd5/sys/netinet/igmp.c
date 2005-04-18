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
 * $FreeBSD: src/sys/netinet/igmp.c,v 1.46 2004/06/11 03:42:37 rwatson Exp $
 */

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
 * Internet Group Management Protocol (IGMP) routines.
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994.
 * Modified by Bill Fenner, Xerox PARC, Feb 1995.
 * Modified to fully comply to IGMPv2 by Bill Fenner, Oct 1995.
 * Modified to support IGMPv3 by Hitoshi Asaeda, Feb 2002.
 *
 * MULTICAST Revision: 3.5.1.4
 */

#include "opt_inet.h"
#include "opt_mac.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/igmp.h>
#include <netinet/igmp_var.h>

#include <machine/in_cksum.h>

static MALLOC_DEFINE(M_IGMP, "igmp", "igmp state");
MALLOC_DEFINE(M_MSFILTER, "msfilter", "multicast source filter");

static struct router_info	*find_rti(struct ifnet *ifp);
static void	igmp_sendpkt(struct in_multi *, int, unsigned long);

SLIST_HEAD(, router_info) router_info_head;
static struct igmpstat igmpstat;
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

SYSCTL_STRUCT(_net_inet_igmp, IGMPCTL_STATS, stats, CTLFLAG_RW, &igmpstat,
    igmpstat, "");
SYSCTL_INT(_net_inet_igmp, IGMPCTL_MAXSRCFILTER, maxsrcfilter, CTLFLAG_RW,
	&igmpmaxsrcfilter, IP_MAX_SOURCE_FILTER, "");
SYSCTL_INT(_net_inet_igmp, IGMPCTL_SOMAXSRC, somaxsrc, CTLFLAG_RW,
	&igmpsomaxsrc, SO_MAX_SOURCE_FILTER, "");
SYSCTL_INT(_net_inet_igmp, IGMPCTL_VERSION, igmp_version, CTLFLAG_RW,
	&igmp_version, 0, "");

/*
 * igmp_mtx protects all mutable global variables in igmp.c, as well as
 * the data fields in struct router_info.  In general, a router_info
 * structure will be valid as long as the referencing struct in_multi is
 * valid, so no reference counting is used.  We allow unlocked reads of
 * router_info data when accessed via an in_multi read-only.
 */
static struct mtx igmp_mtx;
static int igmp_timers_are_running;
static int interface_timers_are_running;
static int state_change_timers_are_running;
int igmpdropwithnora = 0;	/* accept packets with no Router Alert option */
#ifdef IGMPV3
static int qhdrlen = IGMP_V3_QUERY_MINLEN;
static int rhdrlen = IGMP_MINLEN;
static int ghdrlen = IGMP_MINLEN;
static int addrlen = sizeof(struct in_addr);
#endif

#define	SOURCE_RECORD_LEN(numsrc)	(numsrc*(sizeof(u_int32_t)))

#define	GET_REPORT_SOURCE_HEAD(inm, type, iasl) { \
	if ((type) == ALLOW_NEW_SOURCES) \
		(iasl) = (inm)->inm_source->ims_alw; \
	else if ((type) == BLOCK_OLD_SOURCES) \
		(iasl) = (inm)->inm_source->ims_blk; \
	else if ((type) == CHANGE_TO_INCLUDE_MODE) \
		(iasl) = (inm)->inm_source->ims_toin; \
	else if ((type) == CHANGE_TO_EXCLUDE_MODE) \
		(iasl) = (inm)->inm_source->ims_toex; \
	else { \
		if ((inm)->inm_state == IGMP_SG_QUERY_PENDING_MEMBER) \
			(iasl) = (inm)->inm_source->ims_rec; \
		else \
			(iasl) = (inm)->inm_source->ims_cur; \
	} \
}

#define	SET_REPORTHDR(m, numsrc) do { \
	MGETHDR((m), M_DONTWAIT, MT_HEADER); \
	if ((m) != NULL && \
		MHLEN - max_linkhdr < sizeof(struct ip) + rhdrlen + ghdrlen \
					+ SOURCE_RECORD_LEN((numsrc))) { \
		MCLGET((m), M_DONTWAIT); \
		if (((m)->m_flags & M_EXT) == 0) { \
			m_freem((m)); \
			error = ENOBUFS; \
			break; \
		} \
	} \
	if ((m) == NULL) { \
		error = ENOBUFS; \
		break; \
	} \
	(m)->m_data += max_linkhdr; \
	ip = mtod((m), struct ip *); \
	buflen = sizeof(struct ip); \
	ip->ip_len = sizeof(struct ip) + rhdrlen; \
	ip->ip_tos = 0xc0; \
	ip->ip_off = 0; \
	ip->ip_p = IPPROTO_IGMP; \
	ip->ip_src.s_addr = INADDR_ANY; \
	ip->ip_dst.s_addr = htonl(INADDR_NEW_ALLRTRS_GROUP); \
	igmp_rhdr = (struct igmp_report_hdr *)((char *)ip + buflen); \
	igmp_rhdr->igmp_type = IGMP_V3_MEMBERSHIP_REPORT; \
	igmp_rhdr->igmp_reserved1 = 0; \
	igmp_rhdr->igmp_reserved2 = 0; \
	igmp_rhdr->igmp_grpnum = 0; \
	buflen += rhdrlen; \
	(m)->m_len = sizeof(struct ip) + rhdrlen; \
	(m)->m_pkthdr.len = sizeof(struct ip) + rhdrlen; \
	(m)->m_pkthdr.rcvif = (struct ifnet *)0; \
} while(0)
 
static int igmp_set_timer(struct ifnet *, struct router_info *, struct igmp *,
			int, u_int8_t);
static void igmp_set_hostcompat(struct ifnet *, struct router_info *, int);
static int igmp_record_queried_source(struct in_multi *, struct igmp *, int);
static void igmp_send_all_current_state_report(struct ifnet *);
static int igmp_send_current_state_report(struct mbuf **, int *, struct in_multi *);
int igmp_create_group_record(struct mbuf *, int *, struct in_multi *,
			     u_int16_t, u_int16_t *, u_int8_t);
void igmp_cancel_pending_response(struct ifnet *, struct router_info *);

/*
 * XXXRW: can we define these such that these can be made const?  In any
 * case, these shouldn't be changed after igmp_init() and therefore don't
 * need locking.
 */
static u_long igmp_all_hosts_group;
static u_long igmp_all_rtrs_group;

static struct mbuf *router_alert;
static struct route igmprt;

#ifdef IGMP_DEBUG
#define	IGMP_PRINTF(x)	printf(x)
#else
#define	IGMP_PRINTF(x)
#endif

void
igmp_init(void)
{
	struct ipoption *ra;

	/*
	 * To avoid byte-swapping the same value over and over again.
	 */
	igmp_all_hosts_group = htonl(INADDR_ALLHOSTS_GROUP);
	igmp_all_rtrs_group = htonl(INADDR_ALLRTRS_GROUP);

	igmp_timers_are_running = 0;
	interface_timers_are_running = 0; /* used only by IGMPv3 */
	state_change_timers_are_running = 0; /* used only by IGMPv3 */

	/*
	 * Construct a Router Alert option to use in outgoing packets
	 */
	MGET(router_alert, M_DONTWAIT, MT_DATA);
	ra = mtod(router_alert, struct ipoption *);
	ra->ipopt_dst.s_addr = 0;
	ra->ipopt_list[0] = IPOPT_RA;	/* Router Alert Option */
	ra->ipopt_list[1] = 0x04;	/* 4 bytes long */
	ra->ipopt_list[2] = 0x00;
	ra->ipopt_list[3] = 0x00;
	router_alert->m_len = sizeof(ra->ipopt_dst) + ra->ipopt_list[1];

	mtx_init(&igmp_mtx, "igmp_mtx", NULL, MTX_DEF);
	SLIST_INIT(&router_info_head);
}

struct router_info *
rti_init(ifp)
	struct ifnet *ifp;
{
	struct router_info *rti;

	/*
	 * XXXRW: return value of malloc not checked, despite M_NOWAIT.
	 */
	MALLOC(rti, struct router_info *, sizeof *rti, M_IGMP, M_NOWAIT);
	if (rti == NULL)
		return NULL;

	rti->rti_ifp = ifp;
#ifndef IGMPV3
	rti->rti_type = IGMP_v2_ROUTER;
	rti->rti_time = 0;
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
	SLIST_INSERT_HEAD(&router_info_head, rti, rti_list);
	return (rti);
}


static struct router_info *
find_rti(struct ifnet *ifp)
{
	struct router_info *rti;

	mtx_assert(&igmp_mtx, MA_OWNED);
	IGMP_PRINTF("[igmp.c, _find_rti] --> entering \n");
	SLIST_FOREACH(rti, &router_info_head, rti_list) {
		if (rti->rti_ifp == ifp) {
			IGMP_PRINTF(
			    "[igmp.c, _find_rti] --> found old entry \n");
			return rti;
		}
	}
	if ((rti = rti_init(ifp)) == NULL)
		return NULL;
	IGMP_PRINTF("[igmp.c, _find_rti] --> created an entry \n");
	return rti;
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

	if (((m->m_flags & M_EXT) &&
	    (ntohl(ip->ip_src.s_addr) & IN_CLASSA_NET) == 0) ||
	    m->m_len < minlen) {
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
	case IGMP_V1_MEMBERSHIP_REPORT:
		return 0;
	case IGMP_V2_MEMBERSHIP_REPORT:
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
igmp_input(register struct mbuf *m, int off)
{
	register int iphlen = off;
	register struct igmp *igmp;
	register struct ip *ip;
	register int igmplen;
	register struct ifnet *ifp = m->m_pkthdr.rcvif;
	register int minlen;
	int query_ver;
	int query_type;
	register struct in_multi *inm;
	register struct in_ifaddr *ia;
	struct in_multistep step;
	struct router_info *rti;
	int timer; /** timer value in the igmp query header **/
#ifdef IGMPV3
	int error;
#endif

	ip = mtod(m, struct ip *);
	igmplen = ip->ip_len;

	/*
	 * Check length and validate checksum
	 */
	if (ip->ip_len > ifp->if_mtu) {
		++igmpstat.igps_rcv_toolong;
		goto end;
	}
	minlen = iphlen + IGMP_MINLEN;
	if ((m->m_flags & M_EXT || m->m_len < minlen) &&
	    (m = m_pullup(m, minlen)) == 0) {
		++igmpstat.igps_rcv_tooshort;
		return;
	}

	/*
	 * Validate checksum
	 */
	m->m_data += iphlen;
	m->m_len -= iphlen;
	igmp = mtod(m, struct igmp *);
	if (in_cksum(m, igmplen)) {
		++igmpstat.igps_rcv_badsum;
		goto end;
	}
	m->m_data -= iphlen;
	m->m_len += iphlen;

	ip = mtod(m, struct ip *);
	timer = igmp->igmp_code * PR_FASTHZ / IGMP_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	mtx_lock(&igmp_mtx);
	rti = find_rti(ifp);
	mtx_unlock(&igmp_mtx);
	if (rti == NULL) {
		++igmpstat.igps_rcv_query_fails;
		goto end; /* XXX */
	}

	/*
	 * In the IGMPv2 specification, there are 3 states and a flag.
	 *
	 * In Non-Member state, we simply don't have a membership record.
	 * In Delaying Member state, our timer is running (inm->inm_timer)
	 * In Idle Member state, our timer is not running (inm->inm_timer==0)
	 *
	 * The flag is inm->inm_state, it is set to IGMP_OTHERMEMBER if
	 * we have heard a report from another member, or IGMP_IREPORTEDLAST
	 * if I sent the last report.
	 */
	switch (igmp->igmp_type) {
	case IGMP_MEMBERSHIP_QUERY:
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
		else if (igmplen >= IGMP_V3_QUERY_MINLEN)
			query_ver = IGMP_v3_QUERY;
#endif
		else { /* igmplen > 8 && igmplen < 12 */
			++igmpstat.igps_rcv_badqueries; /* invalid query */
			goto end;
		}

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		/*
		 * Note IGMPv1's igmp_code is *always* 0, and IGMPv2's
		 * igmp_code *must not* be 0. This means only correct v1 query
		 * must come through this "if" routine.
		 */
		if ((igmp->igmp_code == 0) && (query_ver != IGMP_v3_QUERY)) {

			mtx_lock(&igmp_mtx);
#ifndef IGMPV3
			query_ver = IGMP_v1_QUERY; /* overwrite */
			rti->rti_type = IGMP_v1_ROUTER;
			rti->rti_time = 0;
#else
			if (igmp_version == 0)
				igmp_set_hostcompat(ifp, rti, query_ver);
#endif
			mtx_unlock(&igmp_mtx);

			timer = IGMP_MAX_HOST_REPORT_DELAY * PR_FASTHZ;

			if (ip->ip_dst.s_addr != igmp_all_hosts_group ||
			    igmp->igmp_group.s_addr != 0) {
				++igmpstat.igps_rcv_badqueries;
				goto end;
			}
			++igmpstat.igps_rcv_v1_queries;
			goto igmpv1_query;
			/*
			 * Note if IGMPv2's igmp_code is 0, that message must
			 * not be correct query msg. This means correct v2 query
			 * must go through the following "if" statement.
			 */
		}
		if (query_ver == IGMP_v2_QUERY) {
			++igmpstat.igps_rcv_v2_queries;
			if (!IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
				++igmpstat.igps_rcv_badqueries;
				goto end;
			}
			goto igmpv2_query;
		}

#ifdef IGMPV3
		/*
		 * Adjust timer for scheduling responses to IGMPv3 query.
		 */
		if (query_ver != IGMP_v3_QUERY)
			goto end;
		++igmpstat.igps_rcv_v3_queries;

		/* Check query types and keep source list if needed. */
		if (igmp->igmp_group.s_addr == INADDR_ANY) {
			if (igmp->igmp_numsrc != 0) {
				++igmpstat.igps_rcv_badqueries;
				goto end;
			}
			if (ip->ip_dst.s_addr != htonl(INADDR_ALLHOSTS_GROUP)) {
				++igmpstat.igps_rcv_badqueries;
				goto end;
			}
			query_type = IGMP_V3_GENERAL_QUERY;
			goto set_timer;
		}
		if (IN_MULTICAST(ntohl(igmp->igmp_group.s_addr))) {
			if (igmp->igmp_numsrc == 0) {
				query_type = IGMP_V3_GROUP_QUERY;
			} else {
				query_type = IGMP_V3_GROUP_SOURCE_QUERY;
			}
			goto set_timer;
		}
		++igmpstat.igps_rcv_badqueries;
		goto end;

set_timer:
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
			goto igmpv1_query;
		else if (rti->rti_type == IGMP_v2_ROUTER)
			goto igmpv2_query;

		mtx_lock(&igmp_mtx);
		error = igmp_set_timer(ifp, rti, igmp, igmplen, query_type);
		mtx_unlock(&igmp_mtx);
		if (error != 0) {
#ifdef IGMPV3_DEBUG
			printf("igmp_input: receive bad query\n");
#endif
			goto end;
		}
#endif /* IGMPV3 */
		break;

igmpv1_query:
igmpv2_query:
		/*
		 * - Start the timers in all of our membership records
		 *   that the query applies to for the interface on
		 *   which the query arrived excl. those that belong
		 *   to the "all-hosts" group (224.0.0.1).
		 * - Restart any timer that is already running but has
		 *   a value longer than the requested timeout.
		 * - Use the value specified in the query message as
		 *   the maximum timeout.
		 */
		timer = igmp->igmp_code * PR_FASTHZ / IGMP_TIMER_SCALE;
		if (timer == 0)
			timer = 1;
		IN_FIRST_MULTI(step, inm);
		while (inm != NULL) {
			if (inm->inm_ifp == ifp &&
			    inm->inm_addr.s_addr != igmp_all_hosts_group &&
			    (igmp->igmp_group.s_addr == 0 ||
			     igmp->igmp_group.s_addr == inm->inm_addr.s_addr)) {
				if (inm->inm_timer == 0 ||
				    inm->inm_timer > timer) {
					inm->inm_state = IGMP_IREPORTEDLAST;
					inm->inm_timer =
					    IGMP_RANDOM_DELAY(timer);
					igmp_timers_are_running = 1;
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
		mtx_lock(&igmp_mtx);
		if (igmp->igmp_group.s_addr == INADDR_ANY) {
		    if (igmp_version == 3)
			goto end;
		    igmp_set_hostcompat(ifp, rti, query_ver);
		}
		mtx_unlock(&igmp_mtx);
#endif
		break;

	case IGMP_V1_MEMBERSHIP_REPORT:
	case IGMP_V2_MEMBERSHIP_REPORT:
		/*
		 * For fast leave to work, we have to know that we are the
		 * last person to send a report for this group.  Reports
		 * can potentially get looped back if we are a multicast
		 * router, so discard reports sourced by me.
		 */
		IFP_TO_IA(ifp, ia);
		if (ia && ip->ip_src.s_addr == IA_SIN(ia)->sin_addr.s_addr)
			break;

		++igmpstat.igps_rcv_reports;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN_MULTICAST(ntohl(igmp->igmp_group.s_addr))) {
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
		if ((ntohl(ip->ip_src.s_addr) & IN_CLASSA_NET) == 0)
			if (ia) ip->ip_src.s_addr = htonl(ia->ia_subnet);

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);

		if (inm != NULL) {
			inm->inm_timer = 0;
			++igmpstat.igps_rcv_ourreports;

			inm->inm_state = IGMP_OTHERMEMBER;
			break;
		}

		break;
	}

	/*
	 * Pass all valid IGMP packets up to any process(es) listening
	 * on a raw IGMP socket.
	 */
	rip_input(m, off);

end:
	m_freem(m);
	return;
}

void
igmp_joingroup(struct in_multi *inm)
{
	int s = splnet();

	if (inm->inm_addr.s_addr == igmp_all_hosts_group
	    || inm->inm_ifp->if_flags & IFF_LOOPBACK) {
		inm->inm_timer = 0;
		inm->inm_state = IGMP_OTHERMEMBER;
	} else {
		mtx_lock(&igmp_mtx);
		inm->inm_rti = find_rti(inm->inm_ifp);
		mtx_unlock(&igmp_mtx);
		igmp_sendpkt(inm, inm->inm_rti->rti_type, 0);
		inm->inm_timer = IGMP_RANDOM_DELAY(
					IGMP_MAX_HOST_REPORT_DELAY*PR_FASTHZ);
		inm->inm_state = IGMP_IREPORTEDLAST;
		igmp_timers_are_running = 1;
	}
	splx(s);
}

void
igmp_leavegroup(struct in_multi *inm)
{

	if (inm->inm_state == IGMP_IREPORTEDLAST &&
	    inm->inm_addr.s_addr != igmp_all_hosts_group &&
	    !(inm->inm_ifp->if_flags & IFF_LOOPBACK) &&
	    inm->inm_rti->rti_type == IGMP_v2_ROUTER)
		igmp_sendpkt(inm, IGMP_V2_LEAVE_GROUP, igmp_all_rtrs_group);
}

void
igmp_fasttimo(void)
{
	register struct in_multi *inm;
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
	 * Quick check to see if any work needs to be done, in order
	 * to minimize the overhead of fasttimo processing.
	 */

	if (!igmp_timers_are_running && !interface_timers_are_running
		&& !state_change_timers_are_running)
		return;

	s = splnet();

#ifdef IGMPV3
	if (interface_timers_are_running) {
		interface_timers_are_running = 0;
		SLIST_FOREACH(rti, &router_info_head, rti_list) {
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
			goto state_change_timer; /* do nothing */
		--inm->inm_timer;
		if (inm->inm_timer > 0) {
			igmp_timers_are_running = 1;
			goto state_change_timer;
		}

		/* Current-State Record timer */
		if (inm->inm_state == IGMP_IREPORTEDLAST) {
			igmp_sendpkt(inm, inm->inm_rti->rti_type, 0);
			inm->inm_state = IGMP_IREPORTEDLAST;
#ifdef IGMPV3
		} else if ((inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER) ||
			   (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER)) {
			if ((cm != NULL) && (ifp != inm->inm_ifp)) {
				igmp_sendbuf(cm, ifp);
				cm = NULL;
			}
			(void)igmp_send_current_state_report(&cm, &cbuflen, inm);
			ifp = inm->inm_ifp;
#endif
		}

state_change_timer:
#ifdef IGMPV3
		/* State-Change Record timer */
		if (IN_LOCAL_GROUP(ntohl(inm->inm_addr.s_addr)))
			goto next_inm; /* skip */

		if (inm->inm_source->ims_timer == 0)
			goto next_inm; /* skip */

		--inm->inm_source->ims_timer;
		if (inm->inm_source->ims_timer == 0) {
			state_change_timers_are_running = 1;
			goto next_inm;
		}

		if ((sm != NULL) && (ifp != inm->inm_ifp)) {
			igmp_sendbuf(sm, ifp);
			sm = NULL;
		}
		/* 
		 * Check if this report was pending Source-List-Change
		 * report or not. It is only the case that robvar was
		 * not reduced here. (XXX rarely, QRV may be changed
		 * in a same timing.)
		 */
		if (inm->inm_source->ims_robvar == inm->inm_rti->rti_qrv) {
			/* 
			 * immediately advertise the calculated IGMP report,
			 * so that you don't have to update ifp for the buffered
			 * IGMP report message
			 */
			igmp_send_state_change_report(&sm, &sbuflen, inm, 0, 1);
			sm = NULL;
		} else if (inm->inm_source->ims_robvar > 0) {
			igmp_send_state_change_report(&sm, &sbuflen, inm, 0, 0);
			ifp = inm->inm_ifp;
		}

		if (inm->inm_source->ims_robvar != 0) {
			inm->inm_source->ims_timer =
			    IGMP_RANDOM_DELAY(IGMP_UNSOL_INTVL * PR_FASTHZ);
			state_change_timers_are_running = 1;
		}
#endif
next_inm:
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
igmp_slowtimo(void)
{
	int s = splnet();
	struct router_info *rti;

	IGMP_PRINTF("[igmp.c,_slowtimo] -- > entering \n");
	mtx_lock(&igmp_mtx);
	SLIST_FOREACH(rti, &router_info_head, rti_list) {
#ifndef IGMPV3
		if (rti->rti_type == IGMP_V1_ROUTER) {
			rti->rti_time++;
			if (rti->rti_time >= IGMP_AGE_THRESHOLD)
				rti->rti_type = IGMP_V2_ROUTER;
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
			case 2:
				if (rti->rti_type != IGMP_v2_ROUTER)
					rti->rti_type = IGMP_v2_ROUTER;
				break;
			case 0:
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
	mtx_unlock(&igmp_mtx);
	IGMP_PRINTF("[igmp.c,_slowtimo] -- > exiting \n");
	splx(s);
}

static void
igmp_sendpkt(struct in_multi *inm, int type, unsigned long addr)
{
	struct mbuf *m;
	struct igmp *igmp;
	struct ip *ip;
	struct ip_moptions imo;

	if (type < 0)
		return;
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return;

	m->m_pkthdr.rcvif = loif;
#ifdef MAC
	mac_create_mbuf_linklayer(inm->inm_ifp, m);
#endif
	m->m_pkthdr.len = sizeof(struct ip) + IGMP_MINLEN;
	MH_ALIGN(m, IGMP_MINLEN + sizeof(struct ip));
	m->m_data += sizeof(struct ip);
	m->m_len = IGMP_MINLEN;
	igmp = mtod(m, struct igmp *);
	igmp->igmp_type = type;
	igmp->igmp_code = 0;
	igmp->igmp_group = inm->inm_addr;
	igmp->igmp_cksum = 0;
	igmp->igmp_cksum = in_cksum(m, IGMP_MINLEN);

	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);
	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = sizeof(struct ip) + IGMP_MINLEN;
	ip->ip_off = 0;
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src.s_addr = INADDR_ANY;
	ip->ip_dst.s_addr = addr ? addr : igmp->igmp_group.s_addr;

	imo.imo_multicast_ifp  = inm->inm_ifp;
	imo.imo_multicast_ttl  = 1;
	imo.imo_multicast_vif  = -1;
	/*
	 * Request loopback of the report if we are acting as a multicast
	 * router, so that the process-level routing daemon can hear it.
	 */
	imo.imo_multicast_loop = (ip_mrouter != NULL);

	/*
	 * XXX
	 * Do we have to worry about reentrancy here?  Don't think so.
	 */
	ip_output(m, router_alert, &igmprt, 0, &imo, NULL);

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
		igmp_ghdr->numsrc = htons(igmp_ghdr->numsrc);
	}
	igmp_rhdr->igmp_grpnum = htons(igmp_rhdr->igmp_grpnum);
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

	ip_output(m, router_alert, &igmprt, 0, &imo
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
		 ,NULL
#endif
		 );
	++igmpstat.igps_snd_v3_reports;
}

/*
 * Timer adjustment on reception of an IGMPv3 Query.
 */
static int
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
	int s = splnet();

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

	if (igmp->igmp_code == 0)
	    /*
	     * XXX: this interval prevents an IGMP-report flooding caused by 
	     * an IGMP-query with Max-Reponce-Code=0 (KAME local design)
	     */
	     timer = 10;
	else if (igmp->igmp_code < 128)
	    timer = igmp->igmp_code;
	else
	    timer = (IGMP_MANT(igmp->igmp_code) | 0x10)
			<< (IGMP_EXP(igmp->igmp_code) + 3);

	/*
	 * Set interface timer if the query is Generic Query.
	 * Get group timer if the query is not Generic Query.
	 */
	if (query_type == IGMP_V3_GENERAL_QUERY) {
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
	    if (IN_LOCAL_GROUP(ntohl(inm->inm_addr.s_addr))
	        || inm->inm_ifp != ifp)
		goto next_multi;

	    if ((inm->inm_source->ims_grpjoin == 0) &&
		(inm->inm_source->ims_mode == MCAST_INCLUDE) &&
		(inm->inm_source->ims_cur->numsrc == 0))
		goto next_multi; /* no need to consider any timer */

	    if (query_type == IGMP_V3_GENERAL_QUERY) {
		/* Any previously pending response to Group- or
		 * Group-and-Source-Specific Query is canceled, if pending
		 * group timer is not sooner than new interface timer. */
		if (!igmp_timers_are_running)
		    goto next_multi;
		if (inm->inm_timer <= rti->rti_timer3)
		    goto next_multi;
		inm->inm_state = IGMP_OTHERMEMBER;
		inm->inm_timer = 0;
		in_free_msf_source_list(inm->inm_source->ims_rec->head);
		inm->inm_source->ims_rec->numsrc = 0;
		goto next_multi;
	    } else if (inm->inm_addr.s_addr != igmp->igmp_group.s_addr)
		goto next_multi;

	    /*
	     * If interface timer is sooner than new group timer,
	     * just ignore this Query for this group address.
	     */
	    if (interface_timers_are_running && (rti->rti_timer3 < timer_g)) {
		inm->inm_state = IGMP_OTHERMEMBER;
		inm->inm_timer = 0;
		break;
	    }

	    /* Receive Group-Specific Query */
	    if (query_type == IGMP_V3_GROUP_QUERY) {
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
	    error = igmp_record_queried_source(inm, igmp, igmplen);
	    if (error > 0) {
		if (error == EOPNOTSUPP)
		    ++igmpstat.igps_rcv_badqueries;
		else
		    ++igmpstat.igps_rcv_query_fails;
		splx(s);
		return error;
	    }
	    if (error < 0)
	    	break;	/* no need to do any additional things */

	    inm->inm_state = IGMP_SG_QUERY_PENDING_MEMBER;
	    if (inm->inm_timer != 0)
		inm->inm_timer = min(inm->inm_timer, timer_g);
	    else {
		igmp_timers_are_running = 1;
		inm->inm_timer = timer_g;
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
static void
igmp_set_hostcompat(ifp, rti, query_ver)
	struct ifnet *ifp;
	struct router_info *rti;
	int query_ver;
{
	int s = splnet();

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
 * and merge them in a recorded source list as specified in RFC3810 6.3 (3).
 * If the recorded source list cannot be kept in memory, return an error code.
 * If no pending source was recorded, return -1.
 * If some source was recorded as a reply for Group-and-Source-Specific Query,
 * return 0.
 */ 
static int
igmp_record_queried_source(inm, igmp, igmplen)
	struct in_multi *inm;
	struct igmp *igmp;
	int igmplen;
{
	u_int16_t numsrc, i;
	int ref_count;
	struct sockaddr_in sin;
	int recorded = 0;

	igmplen -= qhdrlen; /* remaining source list */
	numsrc = ntohs(igmp->igmp_numsrc);
	if (numsrc != igmplen / addrlen)
	    return EOPNOTSUPP; /* XXX */

	for (i = 0; i < numsrc && igmplen >= addrlen; i++, igmplen -= addrlen) {
	    bzero(&sin, sizeof(sin));
	    sin.sin_family = AF_INET;
	    sin.sin_len = sizeof(sin);
	    sin.sin_addr = igmp->src[i];
	    if (match_msf4_per_if(inm, &sin.sin_addr, &inm->inm_addr) == 0)
		continue;

	    ref_count = in_merge_msf_source_addr(inm->inm_source->ims_rec,
					 &sin, IMS_ADD_SOURCE);
	    if (ref_count < 0) {
	    	if (inm->inm_source->ims_rec->numsrc)
			in_free_msf_source_list(inm->inm_source->ims_rec->head);
		inm->inm_source->ims_rec->numsrc = 0;
		return ENOBUFS;
	    }
	    if (ref_count == 1)
		++inm->inm_source->ims_rec->numsrc; /* new entry */

	    recorded = 1;
	}

	return ((recorded == 0) ? -1 : 0);
}

/*
 * Send Current-State Report for General Query response.
 */
static void
igmp_send_all_current_state_report(ifp)
	struct ifnet *ifp;
{
	struct mbuf *m = NULL;
	int buflen = 0;
	struct in_multi *inm;
	struct in_multistep step;

	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		if (inm->inm_ifp != ifp ||
		    IN_LOCAL_GROUP(ntohl(inm->inm_addr.s_addr)))
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
static int
igmp_send_current_state_report(m0, buflenp, inm)
	struct mbuf **m0;	/* mbuf is inherited to put multiple group
				 * records in one message */
	int *buflenp;
	struct in_multi *inm;
{
	struct mbuf *m = *m0;
	struct ip *ip;
	struct igmp_report_hdr *igmp_rhdr;
	int buflen = 0;
	u_int16_t max_len;
	u_int16_t numsrc, src_once, src_done = 0;
	u_int8_t type = 0;
	int error = 0;

	if (IN_LOCAL_GROUP(ntohl(inm->inm_addr.s_addr)) ||
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
	inm->inm_state = IGMP_OTHERMEMBER;
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
	int buflen = 0;
	int error = 0;

	if (IN_LOCAL_GROUP(ntohl(inm->inm_addr.s_addr)) ||
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
			      &igmp_ghdr->src[i].s_addr,
			      sizeof(igmp_ghdr->src[i]));
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
	    if (IN_LOCAL_GROUP(ntohl(inm->inm_addr.s_addr)))
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
