/* 
 * $Id: admin.h,v 1.1 1999/08/08 23:29:40 itojun Exp $
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
 * request type
 */
#define ADM_TABLE  0x1
#define ADM_STAT   0x2
#define ADM_SIGNAL 0x4
#define ADM_EXEC   0x8

/*
 * Packet size for exchange between route6d and rip6admin
 */ 
#define ADM_BUFSIZE  (sizeof(struct rt_table) * MAX_KERNEL_ROUTES6)
#define ADM_PKTSIZE  (sizeof(struct rt_table) * 16)
#define ADM_SHMSIZE  sizeof(int)

/*
 * To flag end of data from the route6d on the socket.
 */
#define ADM_EOF      0xFF 

/*
 * structure used for passing request info to route6d.
 * and reply from route6d.
 */
struct info_detail {
	u_char id_type;		/* value: TABLE or STAT */
	u_char id_prflen;	/* prefix length */
	struct in6_addr id_addr;/* prefix to be searched for */   
};

/*
 * structure used to get statistics per interface.
 */
struct per_if_info {
	char pi_ifname[IFNAMSIZ];	/* interface name */
	u_long pi_badpkt;		/* count for bad packets received */
	u_long pi_badrte;		/* count for bad RTEs received */
	u_long pi_updates;		/* count for update sent by route6d */
};

/*
 * structure used to get statistics information from route6d.
 */
struct statistic {
	u_long st_grccount;	/* no of routes changed by route6d */
	u_long st_gqcount;	/* no of valid queries */
};

/*
 * structure used to get routing table information from route6d.
 */
struct rt_table {
	struct in6_addr rt_dest;	/* destination address */
	u_char rt_prflen;		/* prefix length */
	u_char rt_metric;		/* metric for the route */
	u_short rt_flag;		/* flags */
	struct in6_addr rt_gway;	/* gateway address */ 
	char rt_ifname[IFNAMSIZ];	/* interface name */
};  
