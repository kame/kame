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

struct ripinfo6 {
  struct in6_addr rip6_dest;
  u_int16_t       rip6_tag;
  u_char          rip6_plen;
  u_char          rip6_metric;
};

struct aggrinfo {
  struct rt_entry     *ag_agg;      /* an aggregated route                 */
  struct rt_entry     *ag_explt;    /* list of explicit routes             */
  struct rtproto      *ag_rtp;      /* protocol I/F list to be advertised  */
  u_int16_t            ag_refcnt;   /* reference count for specific routes */
  u_int16_t            ag_flags;    /* AGGR_ADVDONE / AGGR_NOADVD          */
};

struct filtinfo {		/* XXX: we may need more information */
	struct filtinfo *filtinfo_next;
	struct filtinfo *filtinfo_prev;
	u_int32_t	filtinfo_stat; /* counter for statistics */
	struct in6_addr filtinfo_addr; /* prefix to be filtered */
	u_char		filtinfo_plen; /* prefix length to be filtered */
};

/* flags for filters agains the default route */
#define DEFAULT_FILTERIN    0x1
#define DEFAULT_FILTEROUT   0x2
#define DEFAULT_RESTRICTIN  0x4
#define DEFAULT_RESTRICTOUT 0x8

struct rt_entry {
  struct rt_entry     *rt_next;
  struct rt_entry     *rt_prev;
  struct ripinfo6      rt_ripinfo;  /* RIPng's formatted info             */
  struct in6_addr      rt_bgw;	/* BGP next hop(XXX: too many members...) */
  struct in6_addr      rt_gw;       /* gateway   (linklocal or global)    */
  struct {
    struct in6_addr	_rt_gw;
    struct ifinfo	*_rt_gwif;
  } rt_gwinfo;
  struct { /* source of the gateway (for BGP routes only) */
    int type;
    struct rt_entry *entry;
  } rt_gwsrc;
  u_long               rt_flags;    /* rtm_flags                          */
  task                *rt_riptime;  /* RIPng timer                        */
  struct rtproto       rt_proto;    /* protocol from which this route got */
  struct aspath       *rt_aspath;   /* AS path                            */
  struct aggrinfo      rt_aggr;     /* aggregate info                     */
  time_t rt_time;		/* last update time (BGP routes only) */
};

#define rt_gw rt_gwinfo._rt_gw
#define rt_gwif rt_gwinfo._rt_gwif
#define rt_gwsrc_type rt_gwsrc.type
#define rt_gwsrc_entry rt_gwsrc.entry

/* bgpd internal flags for a route entry */
#define RTF_INSTALLED		0x01000000
#define RTF_BGPDIFSTATIC        0x02000000
#define RTF_BGPDGWSTATIC        0x04000000
#define RTF_IGP_EGP_SYNC        0x10000000
#define RTF_NH_NOT_LLADDR       0x20000000
#define RTF_SENDANYWAY          0x40000000
#define RTF_CHANGED             0x80000000
#define RTF_ROUTE_H             0xffff

#define AGGR_ADVDONE            0x1
#define AGGR_NOADVD             0x2

struct rt_entry *igp_enable_rte __P((struct rt_entry *));

struct rt_entry *aggregatable   __P((struct rt_entry *));
void             aggr_ifinit    __P(());
void             aggr_flush     __P(());
void             aggr_ckconf    __P(());
int              aggr_advable   __P((struct rt_entry *, struct rtproto *));

/* route filtering related functions */
int		 find_filter  __P((struct filtinfo *, struct filtinfo *));
struct filtinfo *filter_check __P((struct filtinfo *, struct in6_addr *, int));
struct filtinfo *restrict_check __P((struct filtinfo *, struct in6_addr *, int));
int output_filter_check __P((struct filterset *, int, struct ripinfo6 *));
