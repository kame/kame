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
 *	from: @(#)igmp_var.h	8.1 (Berkeley) 7/19/93
 * $FreeBSD: src/sys/netinet/igmp_var.h,v 1.20 2004/04/07 20:46:13 imp Exp $
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

#ifndef _NETINET_IGMP_VAR_H_
#define _NETINET_IGMP_VAR_H_

/*
 * Internet Group Management Protocol (IGMP),
 * implementation-specific definitions.
 *
 * Written by Steve Deering, Stanford, May 1988.
 *
 * MULTICAST Revision: 3.5.1.3
 */

#include <netinet/igmp.h>
#ifdef IGMPV3
#include <netinet/in_msf.h>
#endif

struct igmpstat {
	u_int	igps_rcv_total;		/* total IGMP messages received */
	u_int	igps_rcv_tooshort;	/* received with too few bytes */
	u_int	igps_rcv_toolong;	/* received messages over MTU size */
	u_int	igps_rcv_badsum;	/* received with bad checksum */
	u_int	igps_rcv_badttl;	/* received with bad TTL */
	u_int	igps_rcv_nora;		/* received with no Router Alert */
	u_int	igps_rcv_v1_queries;	/* received v1 membership queries */
	u_int	igps_rcv_v2_queries;	/* received v2 membership queries */
	u_int	igps_rcv_v3_queries;	/* received v3 membership queries */
	u_int	igps_rcv_badqueries;	/* received invalid queries */
	u_int	igps_rcv_query_fails;	/* receiving membership query fails */
	u_int	igps_rcv_reports;	/* received v1/v2 membership reports */
	u_int	igps_rcv_badreports;	/* received invalid v1/v2 reports */
	u_int	igps_rcv_ourreports;	/* received v1/v2 reports for our grp */
	u_int	igps_snd_v1v2_reports;	/* sent v1/v2 membership reports */
	u_int	igps_snd_v3_reports;	/* sent v3 membership reports */
};

#ifdef _KERNEL
#define IGMP_RANDOM_DELAY(X) (random() % (X) + 1)

/*
 * States for IGMPv2's leave processing
 */
#define IGMP_OTHERMEMBER			0
#define IGMP_IREPORTEDLAST			1

/*
 * States for the IGMPv3's state table.
 */
#define	IGMP_QUERY_PENDING_MEMBER	2	/* pending General Query */
#define	IGMP_G_QUERY_PENDING_MEMBER	3	/* pending Grp-specific Query */
#define	IGMP_SG_QUERY_PENDING_MEMBER	4	/* pending Grp-Src-specific Q.*/

/*
 * We must remember what version the subnet's querier is.
 * We conveniently use the IGMP message type for the proper
 * membership report to keep this state.
 */
#define IGMP_v1_ROUTER		IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_v2_ROUTER		IGMP_V2_MEMBERSHIP_REPORT
#define	IGMP_v3_ROUTER		IGMP_V3_MEMBERSHIP_REPORT

/* backward compatibility for old FreeBSDs */
#define IGMP_V1_ROUTER		IGMP_v1_ROUTER
#define IGMP_V2_ROUTER		IGMP_v2_ROUTER
#define	IGMP_V3_ROUTER		IGMP_v3_ROUTER

/*
 * IGMP Query version
 */
#define	IGMP_v1_QUERY		IGMP_v1_ROUTER
#define	IGMP_v2_QUERY		IGMP_v2_ROUTER
#define	IGMP_v3_QUERY		IGMP_v3_ROUTER

/*
 * Revert to new router if we haven't heard from an old router in
 * this amount of time.
 * Note this timer only affects with no IGMPv3 configuration.
 */
#define IGMP_AGE_THRESHOLD			540

/*
 * IGMPv3 default variables
 */
#define	IGMP_DEF_RV		2	/* Default Robustness Variable */
#define	IGMP_DEF_QI		125	/* Query Interval (125 sec.) */
#define	IGMP_DEF_QRI		100	/* Query Response Interval (10 sec.) */
#define	IGMP_OQPI		((IGMP_DEF_RV * IGMP_DEF_QI) + IGMP_DEF_QRI/2)
#define	IGMP_GMI		((IGMP_DEF_RV * IGMP_DEF_QI) + IGMP_DEF_QRI)
#define	IGMP_START_INTVL	IGMP_DEF_QI/4
#define	IGMP_START_CNT		IGMP_DEF_RV
#define	IGMP_LAST_INTVL		1	/* Last Member Query Interval (sec.) */
#define	IGMP_LAST_CNT		IGMP_DEF_RV
#define	IGMP_UNSOL_INTVL	1	/* Unsolicited Report Interval (sec.) */
#define	IGMP_DEF_QUERY		10	/* v1 Max. Response Time (sec.) */

#ifdef IGMPV3_DEBUG
#define igmplog(x)	do { if (1) log x; } while (/*CONSTCOND*/ 0)
#else
#define igmplog(x)	/* empty */
#endif

void	igmp_init(void);
struct	router_info * rti_init(struct ifnet *);
void	igmp_input(struct mbuf *, int);
void	igmp_joingroup(struct in_multi *);
void	igmp_leavegroup(struct in_multi *);
void	igmp_sendbuf(struct mbuf *, struct ifnet *);
void	igmp_fasttimo(void);
void	igmp_slowtimo(void);
int	igmp_get_router_alert(struct mbuf *);
void	igmp_send_state_change_report(struct mbuf **, int *,
				      struct in_multi *, u_int8_t, int);
int	is_igmp_target(struct in_addr *);

SYSCTL_DECL(_net_inet_igmp);

#endif

/*
 * Names for IGMP sysctl objects
 */
#define IGMPCTL_STATS		1	/* statistics (read-only) */
#define	IGMPCTL_SENDWITHRA	2	/* kern sends IGMP with Router Alert */
#define	IGMPCTL_DROPWITHNORA	3	/* kern drops IGMP with no Rtr Alert */
#define	IGMPCTL_MAXSRCFILTER	4	/* max sources per group per interface*/
#define	IGMPCTL_SOMAXSRC	5	/* max sources per socket per group */
#define	IGMPCTL_VERSION		6
#define	IGMPCTL_MAXID		6

#define IGMPCTL_NAMES { \
	{ 0, 0 }, \
	{ "stats", CTLTYPE_STRUCT }, \
	{ "sendwithra", CTLTYPE_INT }, \
	{ "dropwithnora", CTLTYPE_INT }, \
	{ "maxsrcfilter", CTLTYPE_INT }, \
	{ "somaxsrc", CTLTYPE_INT }, \
	{ "always_v3", CTLTYPE_INT }, \
}

#endif
