/* 
 * $Id: route6d.h,v 1.1.1.1 1999/08/08 23:29:41 itojun Exp $
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
 * RIPng commands, version and port number.
 */
#define RIP6_REQUEST	1
#define RIP6_RESPONSE	2
#define RIP6_VERSION	1 
#define RIP6_PORT	521 

/*
 * Nexthop entry values.
 */
#define RIP6_NEXTHOP_METRIC	0xFF
#define RIP6_NEXTHOP_RTAG	0
#define RIP6_NEXTHOP_PLEN	0
#define RIP6_HOPS		255

#define MIN_PREFLEN		0
#define MAX_PREFLEN		128
#define HOPCOUNT_INFINITY	16

#define MIN_TAG			0
#define MAX_TAG			0xFF  

#define URANGE			30
#define TRANGE			5
#define RELAX_INTERVAL		5 /* min. interval between two regular
				     updates */

/*
 * Timer constants.
 */
#define TIMER_RATE	15	/* Alarm clocks every 15 seconds (default) */
#define SUPPLY_INTERVAL	30	/* Time to supply tables */
#define MIN_WAITTIME	2	/* Min. interval to broadcast changes */
#define MAX_WAITTIME	5	/* Max. time to delay changes */
#define EXPIRE_TIME	180	/* Time to mark entry invalid */
#define GARBAGE_TIME	300	/* Time to garbage collect */

/*
 * Structure for the route entry.
 */
struct route_entry {
	struct in6_addr rip6_addr;	/* Destination/nexthop address */
	u_short rip6_rtag;		/* Route tag */
	u_char  rip6_prflen;		/* Prefix length */
	u_char  rip6_metric;		/* Metric for the route */
};

/*
 * RIPng header structure.
 */
struct rip6 {
	u_char  rip6_cmd;		/* RIPng command */
	u_char  rip6_ver;		/* RIPng version number */
	u_short rip6_mbz;		/* MUST BE ZERO field */
	struct route_entry rip6_rte[1];	/* Route entry */
};
