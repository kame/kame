/*	$KAME: vif.h,v 1.28 2004/06/09 16:29:19 suz Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.        
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.        
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#ifndef VIF_H
#define VIF_H

extern int total_interfaces;
extern int default_vif_status;
extern int udp_socket;
extern struct uvif uvifs[];
extern mifi_t numvifs;
extern int vifs_down; 
extern int phys_vif;
extern mifi_t reg_vif_num;

#define NO_VIF            	((mifi_t)MAXMIFS) /* An invalid vif index */
#define DEFAULT_METRIC 		1
#define VIFF_DOWN		0x000100
#define VIFF_DISABLED       	0x000200
#define VIFF_QUERIER		0x000400
#define VIFF_REXMIT_PRUNES	0x004000
#define VIFF_DR			0x040000
#define VIFF_NONBRS		0x080000
#define VIFF_PIM_NBR            0x200000
#define VIFF_POINT_TO_POINT	0x400000	
#define VIFF_NOLISTENER         0x800000       /* no listener on the link   */
#define VIFF_ENABLED       	0x1000000
#define NBRTYPE 		u_long
#define NBRBITS			sizeof(NBRTYPE) *8


extern if_set if_nullset;
#define IF_ISEMPTY(p) (memcmp((p), &if_nullset, sizeof(if_nullset)) == 0)
#define IF_SAME(p1, p2) (memcmp((p1),(p2),sizeof(*(p1))) == 0)
#define IF_CLR_MASK(p, mask) \
  {\
    int idx;\
    for (idx = 0; idx < sizeof(*(p))/sizeof(fd_mask); idx++) {\
        (p)->ifs_bits[idx] &= ~((mask)->ifs_bits[idx]);\
    }\
  }
#define IF_MERGE(p1, p2, result) \
  {\
    int idx;\
    for (idx = 0; idx < sizeof(*(p1))/sizeof(fd_mask); idx++) {\
        (result)->ifs_bits[idx] = (p1)->ifs_bits[idx]|(p2)->ifs_bits[idx]; \
    }\
  } 

typedef struct {
	NBRTYPE hi;
	NBRTYPE lo;
} nbrbitmap_t;

struct vf_element {
	struct vf_element 			*vfe_next;
	struct sockaddr_in6 		*vfe_addr;
	struct in6_addr 			vfe_mask;
	int							vfe_flags;
#define VFRF_EXACT 0x0001
};

#define VFT_ACCEPT 1
#define VFT_DENY   2
#define VFF_BIDIR 1

struct vif_filter {
	int 				vf_type;
	int 				vf_flags;
	struct vf_element 	*vf_filter;
};

struct listaddr {
	struct listaddr *al_next; /* link to next addr, MUST BE FIRST */
	struct sockaddr_in6 al_addr; /* local group or neighbor address */
	struct listaddr *sources; /* list of sources for this group */

	/* 
	 * al_timer contains a lifetime of this entry regarding MLD.  
	 * It corrensponds to many kinds of lifetimes.
	 * [MLDv1]
	 * - remaining time until the next Query (v->uv_querier->al_timer)
	 * - group-expiry timer (v->uv_group->al_timer)
	 * - LLQT value (v->uv_group->al_timer)
	 * [MLDv2]
	 * - remaining time until the next query (v->uv_querier->al_timer)
	 * - filter-timer (v->uv_group->al_timer)
	 * - source-expiry timer (v->uv_group->sources->al_timer)
	 * - group LLQT (v->uv_group->al_timer)
	 * - source LLQT (v->uv_group->sources->al_timer)
	 *
	 *  Please keep in mind that the actual timeout is handled by
	 *  callout-queue corresponding to its al_timerid, except
	 *  Query transmission.
	 */
	u_long al_timer;
	time_t al_ctime; /* entry creation time */

	u_int16 filter_mode; /* filter mode for mldv2 */
	u_int16 comp_mode; /* compatibility mode */
	union {
		u_int32 alu_genid; /* generation id for neighbor */
		/* a host which reported membership */
		struct sockaddr_in6 alu_reporter;
	} al_alu;
	u_char al_pv; /* router protocol version */
	u_char al_mv;  /* router mrouted version */
	u_char al_index; /* neighbor index */
	u_long al_timerid; /* timer for group membership */
	u_long al_query; /* timer for repeated leave query */
	u_long al_checklist; /* TRUE I'm in checking listener state */
	int32_t al_rob;	  /* robustness */
	u_int16 al_flags; /* flags related to this neighbor */
};

enum { LESSTHANLLQI = 1, MORETHANLLQI };
#define al_genid al_alu.alu_genid
#define al_reporter al_alu.alu_reporter

/*
 * User level Virtual Interface structure 
 *
 * A "virtual interface" is either a physical, multicast-capable interface
 * (called a "phyint"), a virtual point-to-point link (called a "tunnel")
 * or a "register vif" used by PIM. The register vif is used by the     
 * Designated Router (DR) to send encapsulated data packets to the
 * Rendevous Point (RP) for a particular group. The data packets are
 * encapsulated in PIM messages (IPPROTO_PIM = 103) and then unicast to
 * the RP.
 * (Note: all addresses, subnet numbers and masks are kept in NETWORK order.)
 */
struct uvif {
	u_int uv_flags;		
	u_char uv_metric;		/* VIFF_ flags defined below */
	u_char uv_admetric;		/* advertised cost of this vif */
	u_int uv_rate_limit;		/* rate limit on this vif */

	struct phaddr *uv_linklocal;	/* link-local address of this vif */
	struct sockaddr_in6 uv_rmt_addr;/* remote end-point addr (tunnels only)*/
	struct sockaddr_in6 uv_dst_addr;/* destination for PIM messages */
	struct sockaddr_in6 uv_prefix;	/* prefix (phyints only) */
	struct in6_addr	uv_subnetmask;	/* subnet mask (phyints only) */

	char uv_name[IFNAMSIZ];	/* interface name */
	u_int uv_ifindex;	/* index of the interface */
	u_int uv_siteid;	/* index of the site on the interface */

	struct listaddr *uv_groups; /* list of local groups  (phyints only) */
	struct lisaddr *uv_dvmrp_neighbors;
	nbrbitmap_t uv_nbrmap;	/* bitmap of active neighboring routers */
	struct listaddr	*uv_querier; /* MLD querier on vif */
	int uv_prune_lifetime;	/* Prune lifetime or 0 for default  */
	struct vif_acl *uv_acl;	/* access control list of groups */
	int uv_leaftimer;	/* time until this vif is considrd leaf */
	struct phaddr *uv_addrs; /* Additional addresses on this vif */
	struct vif_filter *uvfilter; /* Route filters on this vif */
	u_int16 uv_pim_hello_timer; /* timer for sending PIM hello msgs */
	u_int16	uv_gq_timer;	/* Group Query timer */
	u_int16	uv_jp_timer;	/* Join/Prune timer */
	u_int16 uv_stquery_cnt;	/* Startup Query Count */
	u_int16 uv_mld_version;	/* mld version of this mif */
	u_int16 uv_mld_robustness; /* robustness variable of this vif (mld6 protocol) */
	u_int32 uv_mld_query_interval; /* query interval of this vif (mld6 protocol) */
	u_int32 uv_mld_query_rsp_interval;  /* query response interval of this vif (mld6 protocol) */
	u_int32 uv_mld_llqi; /* last listener query interval */
	int uv_local_pref;	/* default local preference for assert */
	int uv_local_metric;	/* default local metric for assert */
	struct pim_nbr_entry *uv_pim_neighbors;	/* list of PIM nbr routers */

	void *config_attr;	/* temporary buffer while parsing config */

	/* the followings are to collect statistics */
	/* incoming PIM6 packets on this interface */
	u_quad_t uv_in_pim6_hello;
	u_quad_t uv_in_pim6_join_prune;
	u_quad_t uv_in_pim6_bootsrap;
	u_quad_t uv_in_pim6_assert;
	/* outgoing PIM6 packets on this interface */
	u_quad_t uv_out_pim6_hello;
	u_quad_t uv_out_pim6_join_prune;
	u_quad_t uv_out_pim6_bootsrap;
	u_quad_t uv_out_pim6_assert;
	/* incoming MLD packets on this interface */
	u_quad_t uv_in_mld_query;
	u_quad_t uv_in_mld_report;
	u_quad_t uv_in_mld_done;
	/* outgoing MLD packets on this interface */
	u_quad_t uv_out_mld_query;
	u_quad_t uv_out_mld_report;
	u_quad_t uv_out_mld_done;
	/* statistics about the forwarding cache in kernel */
	u_quad_t uv_cache_miss;
	u_quad_t uv_cache_notcreated;
	/* occurrences of timeouts */
	u_quad_t uv_pim6_nbr_timo;
	u_quad_t uv_listener_timo;
	u_quad_t uv_querier_timo;
	u_quad_t uv_outif_timo;	/* outgoing interfaces timers */
};

struct phaddr {
	struct phaddr 		*pa_next;
	struct sockaddr_in6 	pa_addr;
	struct sockaddr_in6 	pa_rmt_addr;	/* valid only in case of P2P I/F */
	struct sockaddr_in6 	pa_prefix;
	struct in6_addr 	pa_subnetmask;
};


/* The Access Control List (list with scoped addresses) member */

struct vif_acl {
	struct vif_acl 		*acl_next;
	struct sockaddr_in6 	acl_addr;
	struct in6_addr		acl_mask;
};

/*  
 * Used to get the RPF neighbor and IIF info
 * for a given source from the unicast routing table.
 */

struct rpfctl {
    struct sockaddr_in6 source; /* the source for which we want iif and rpfnbr */
    struct sockaddr_in6 rpfneighbor;/* next hop towards the source */
    mifi_t iif; /* the incoming interface to reach the next hop */
}; 




extern void    init_vifs __P((void));
extern void    stop_all_vifs __P((void));
extern void    check_vif_state __P((void));
struct sockaddr_in6 * max_global_address __P((void));
struct sockaddr_in6 * uv_global __P((mifi_t));
extern mifi_t   local_address  __P((struct sockaddr_in6 *src));
struct sockaddr_in6 * local_iface __P((char *ifname));
extern mifi_t   find_vif_direct     __P((struct sockaddr_in6 *src));
extern mifi_t  find_vif_direct_local   __P((struct sockaddr_in6 *src));
extern int vif_forwarder __P((if_set *p1 ,if_set *p2));
extern if_set *vif_and __P((if_set *p1, if_set *p2, if_set *result)); 
extern if_set *vif_xor __P((if_set *p1, if_set *p2, if_set *result));
extern struct uvif *find_vif __P((char *ifname, int, int));
extern char *mif_name __P((mifi_t));
#endif
