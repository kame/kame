/* 
 * $Id: config.h,v 1.1 1999/08/08 23:29:40 itojun Exp $
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
 * Copyright(C)1997 by Hitach, Ltd.
 */

/* 
 * The GLOBAL CONFIGURATION PART.
 */

#define MODE_UNSPEC	-1
#define MODE_QUIET	0
#define MODE_SUPPLY	1

/* 
 * The scheme uses to generate the update message.
 */
#define SCHEME_UNSPEC	-1
#define RT6_NOHORZN	0	/* No split horizon */
#define RT6_HORZN	1	/* Split horizon to be used */
#define RT6_POISON	2	/* Split horizon w poison reverse to be used */

/*
 * Packet trace enable/disable.
 */
#define TRACE_OFF	(0==1)
#define TRACE_ON	(!TRACE_OFF)

/*
 * Constants for calculating maximum number of RTEs.
 */
#define DEFAULT_HDRLEN	48	/* Size of UDP+IP+RIPng headers */
#define DEFAULT_MTU	576	/* Default link MTU used */

#define DEFAULT_METRIC	1
#define DEFAULT_RTTAG	0
#define DEFAULT_AUTH	NULL
#define DEFAULT_COMPATIBLE	0

/*
 * This structure gives the statistic for the route.
 */
struct prefix {
	struct in6_addr prf_addr;	/* Prefix to aggregate */
	int prf_len;			/* Prefix length */
};

struct rte_stat {
	short rts_metric;		/* Metric for the route */
	u_short rts_tagval;		/* Tagvalue for the route */
};

/* 
 * The ROUTE CONFIGURATION PART
 */

/*
 * This is structure for static route entries, and will be freed after
 * the installation.
 */
struct static_rt {
	struct static_rt *sta_next;	/* Next route entry */
	struct prefix sta_prefix;	/* Destination prefix */
	struct in6_addr sta_gw;		/* Gateway address */
	struct rte_stat sta_rtstat;
	struct interface *sta_ifp;	/* to get ifpaddr */
};

/*
 * The datastructure for the ignore prefix addressed in the route 
 * configuration file. Multiple "ignore prefix" command will be supported
 */
struct ign_prefix {
	struct ign_prefix *igp_next;	/* Next ignore prefix */
	struct prefix igp_prefix;	/* Prefix to be ignored */
	struct in6_addr igp_mask;	/* Mask for the prefix */
};

/*
 * The INTERFACE CONFIGURATION PART
 */
struct nexthop_rte {
	struct nexthop_rte *nh_next;
	struct prefix nh_prf;		/* Prefix (Key for matching)*/
	struct in6_addr nh_mask;
	struct in6_addr nh_addr;	/* Next hop address */
};

#define CTL_LISTEN   1
#define CTL_NOLISTEN 0
#define CTL_SEND     1
#define CTL_NOSEND   0
struct control {
	struct control     *ctl_next;
	struct sockaddr_in6 ctl_addr;
	int                 ctl_pass; /* Could be CTL_LISTEN/CTL_NOLISTEN or
					 CTL_SEND/CTL_NOSEND */
};

#define AGR_NOTSENT FALSE
#define AGR_SENDING     1
#define AGR_SENT        2
struct aggregate {
	struct aggregate *agr_next;
	struct prefix agr_pref;
	struct in6_addr agr_mask;
	struct rte_stat agr_stat;
	int agr_sent;
};

#define DEFAULT_METRIC_OUT  0

struct int_config {
	struct int_config *int_next;
	char int_name[IFNAMSIZ];	/* Interface name */
	int int_scheme;			/* Poison, Horizon, Nonhorizon */
	int int_inpass;			/* CTL_LISTEN/CTL_NOLISTEN */
	struct control *int_ctlin;	/* In control List */
	int int_outpass;		/* CTL_SEND/CTL_NOSEND */
	struct control *int_ctlout;	/* Out control List */ 
	struct aggregate *int_aggr;	/* Aggregate List */
	boolean int_site;		/* interface belongs to site or not */
	struct rte_stat *int_dstat;
	struct rte_stat *int_dfilter;	/* If TRUE, filter default entry. */
	struct aggregate *int_filter;	/* list of the RTE to be filtered */
	short int_metric_in;
	short int_metric_out;
	struct nexthop_rte *int_nhop;	/* NHE which will be put */
	int int_propagate;
};
