/*	$KAME: mrt.h,v 1.15 2004/06/09 19:03:20 suz Exp $	*/

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


#ifndef MRT_H
#define MRT_H

/* flags for the mrt entries */

#define MRTF_SPT                0x0001  /* iif toward source                */
#define MRTF_WC                 0x0002  /* (*,G) entry                      */
#define MRTF_RP                 0x0004  /* iif toward RP                    */
#define MRTF_NEW                0x0008  /* new created routing entry        */
#define MRTF_1ST		0x0010	/* first hop entry		    */
#define MRTF_IIF_REGISTER   	0x0020  /* ???                              */
#define MRTF_REGISTER       	0x0080  /* ???                              */ 
#define MRTF_KERNEL_CACHE   	0x0200  /* a mirror for the kernel cache    */ 
#define MRTF_NULL_OIF       	0x0400  /* null oif cache..     ???         */
#define MRTF_REG_SUPP       	0x0800  /* register suppress    ???         */
#define MRTF_ASSERTED       	0x1000  /* upstream is not that of src ???  */
#define MRTF_SG        		0x2000  /* (S,G) pure, not hanging off of (*,G)*/
#define MRTF_PMBR      		0x4000  /* (*,*,RP) entry (for interop)     */
#define MRTF_MFC_CLONE_SG 	0x8000  /* clone (S,G) MFC from (*,G) or (*,*,RP) */

#define CREATE                  TRUE 
#define DONT_CREATE             FALSE


#define MFC_MOVE_FORCE      0x1
#define MFC_UPDATE_FORCE    0x2


/* Macro to duplicate oif info (oif bits, timers) */

#define VOIF_COPY(from , to )					\
	do {								\
		IF_COPY(&from->joined_oifs , &to->joined_oifs);		\
		IF_COPY(&from->oifs ,&to->oifs );			\
		IF_COPY(&from->leaves , &to->leaves);			\
		IF_COPY(&from->pruned_oifs , &to->pruned_oifs);		\
		IF_COPY(&from->asserted_oifs ,&to->asserted_oifs);	\
		bcopy(from->vif_timers , to->vif_timers ,		\
		numvifs*sizeof(from->vif_timers[0]));			\
		bcopy(from->vif_deletion_delay , to->vif_deletion_delay,\
		numvifs*sizeof(from->vif_deletion_delay[0]));		\
	} while (0)


#define FREE_MRTENTRY(mrtentry_ptr)					\
	do {								\
		kernel_cache_t *prev;					\
		kernel_cache_t *next;					\
									\
		free((char *)((mrtentry_ptr)->vif_timers));		\
		free((char *)((mrtentry_ptr)->vif_deletion_delay));	\
		for (next = (mrtentry_ptr)->kernel_cache; next != NULL; ) {\
			prev=next;					\
			next=next->next;				\
			free(prev);					\
		}							\
		free((char *)(mrtentry_ptr));				\
	} while (0)

/*
 * The complicated structure used by the more complicated Join/Prune
 * message building
 */

typedef struct build_jp_message {
	struct build_jp_message	*next;	/* Used to chain the free entries */
	u_int8 	*jp_message;		/* The Join/Prune message */
	u_int32 jp_message_size;	/* Size of Join/Prune message in bytes */
	u_int16 holdtime;		/* Join/Prune message holdtime field */
	struct sockaddr_in6 curr_group;	/* Current group address */
	u_int8 	curr_group_msklen;	/* Current group masklen */ 	
	u_int8 	*join_list;		/* working area for join addresses */
	u_int32	join_list_size;		/* size of join_list in bytes */
	u_int16	join_addr_number;	/* Number of join addresses in join_list */
	u_int8 	*prune_list;		/* working area for prune addresses */
	u_int32	prune_list_size; 	/* size of prune_list in bytes */	
	u_int16	prune_addr_number;	/* Number of prune addresses in prune_list*/
	u_int8 	*rp_list_join;		/* working area for RP join addresses */
	u_int32	rp_list_join_size;	/* size of rp_list_join in bytes */
	u_int16	rp_list_join_number;	/* Number of RP addresses in rp_list_join     */
	u_int8 	*rp_list_prune;		/* working area for RP prune addresses   */
	u_int32	rp_list_prune_size;	/* size of rp_list_prune in bytes */
	u_int16	rp_list_prune_number;	/* Number of RP addresses in rp_list_prune */
	u_int8 *num_groups_ptr;	/* Pointer to number_of_groups in jp_message  */
} build_jp_message_t;


typedef struct pim_nbr_entry {
	struct pim_nbr_entry 	*next; /* link to next neighbor */
	struct pim_nbr_entry 	*prev; /* link to prev neighbor */ 
	struct sockaddr_in6 	address; /* (primary) neighbor address */
	struct phaddr		*aux_addrs; /* additional addresses */
	mifi_t 			vifi;   /* which interface */
	u_int16 		timer; 	/* for timing out neighbor */

	/* A structure for Join/Prune message construction */
	build_jp_message_t	*build_jp_message; 
} pim_nbr_entry_t;

typedef struct srcentry {
	struct srcentry *next;		/* link to next entry */
	struct srcentry *prev;		/* link to prev entry */
	struct sockaddr_in6 address;	/* source or RP address */
	struct mrtentry *mrtlink;	/* link to routing entries */
	mifi_t incoming;		/* incoming vif */
	struct pim_nbr_entry *upstream;	/* upstream router */
	u_int32	metric;		/* Unicast Routing Metric to the source */
	u_int32	preference;    /* The metric preference (for assers)*/		
	u_int16	timer;		/* Entry timer??? Delete?    */	
	struct cand_rp	*cand_rp;	/* Used if this is rpentry_t */
} srcentry_t;
typedef srcentry_t rpentry_t;

/* (RP<->group) matching table related structures */

typedef struct cand_rp {
	struct cand_rp 	*next;		/* Next candidate RP */
	struct cand_rp 	*prev;		/* Previous candidate RP */
	struct rp_grp_entry *rp_grp_next;	/* The rp_grp_entry chain for that RP */
	rpentry_t *rpentry;	/* Pointer to the RP entry */
} cand_rp_t;

typedef struct grp_mask {
	struct grp_mask 	*next;
	struct grp_mask 	*prev;
	struct rp_grp_entry 	*grp_rp_next;
	struct sockaddr_in6 	group_addr;
	struct in6_addr 	group_mask;
	struct in6_addr 	hash_mask;
	u_int16	fragment_tag;	/* Used for garbage collection    */
	u_int8	group_rp_number;	/* Used when assembling segments  */
} grp_mask_t;

typedef struct rp_grp_entry {
	struct rp_grp_entry 	*rp_grp_next;	/* Next entry for same RP */
	struct rp_grp_entry 	*rp_grp_prev;	/* Prev entry for same RP */
	struct rp_grp_entry 	*grp_rp_next;	/* Next entry for same grp prefix */
	struct rp_grp_entry 	*grp_rp_prev;	/* Prev entry for same grp prefix */
	struct grpentry		*grplink; 	/* Link to all grps via this entry*/	
	u_int16	advholdtime;	/* advertised holdtime */
	u_int16 holdtime;	/* RP holdtime (will be aged) */
	u_int16	fragment_tag;   /* fragment tag from the received BSR message */
	
	u_int8	priority;	/* RP priority */
	u_int8	origin;		/* Where it's learned from (smaller one is preferred) */
#define	RP_ORIGIN_STATIC 0
#define	RP_ORIGIN_BSR    1

	grp_mask_t*group;	/* Pointer to (group,mask) entry */
	cand_rp_t *rp;		/* Pointer to the RP */
} rp_grp_entry_t;

typedef struct grpentry {
	struct grpentry *next;		/* link to next entry                */
	struct grpentry *prev;		/* link to prev entry                */
	struct grpentry *rpnext;	/* next grp for the same RP          */
	struct grpentry *rpprev;	/* prev grp for the same RP          */
	struct sockaddr_in6 group;	/* subnet group of multicasts        */
	struct sockaddr_in6 rpaddr;	/* The IPv6 address of the RP        */
	struct mrtentry *mrtlink;	/* link to (S,G) routing entries     */
	rp_grp_entry_t  *active_rp_grp;	/* Pointer to the active rp_grp entry*/
	struct mrtentry *grp_route;	/* Pointer to the (*,G) routing entry*/
} grpentry_t;

typedef struct mrtentry {
	struct mrtentry	*grpnext;	/* next entry of same group         */
	struct mrtentry	*grpprev;	/* prev entry of same group         */
	struct mrtentry *srcnext;	/* next entry of same source        */
	struct mrtentry *srcprev;	/* prev entry of same source        */
	struct grpentry *group;		/* pointer to group entry           */
	struct srcentry *source;	/* pointer to source entry (or RP)  */
	mifi_t incoming;		/* the iif (either toward S or RP)  */
	if_set oifs;			/* The current result oifs          */
	if_set joined_oifs;		/* The joined oifs (Join received)  */
	if_set pruned_oifs;		/* The pruned oifs (Prune received) */
	if_set asserted_oifs;		/* The asserted oifs (lost Assert)  */
	if_set leaves;			/* Has directly connected members   */
	struct pim_nbr_entry *upstream;	/* upstream router, needed because of
					 * the asserts it may be different than
                			 * the source (or RP) upstream router.
                                       	 */

	u_int32 metric;		/* Routing Metric for this entry */
	u_int32	preference;	/* The metric preference value      */
	struct sockaddr_in6 pmbr_addr;	/* The PMBR address (for interop)   */
	u_int16 *vif_timers;	 	/* vifs timer list                  */	
	u_int16	*vif_deletion_delay;	/* vifs deletion delay list    */

	u_int16	flags;			/* The MRTF_* flags                 */
	u_int16	timer;			/* entry timer                      */
	u_int16	jp_timer;		/* The Join/Prune timer             */
	u_int16	rs_timer;		/* Register-Suppression Timer       */
	u_int 	assert_timer;
	u_int 	assert_rate_timer;
	struct 	kernel_cache *kernel_cache;	/* List of the kernel cache entries */
#ifdef RSRR
	struct rsrr_cache   *rsrr_cache;    /* Used to save RSRR requests for
                                             * routes change notification.
					     */
#endif /* RSRR */
} mrtentry_t;


/*
 * Used to get forwarded data related counts (number of packet, number of
 * bits, etc)
 */

struct sg_count {
	u_quad_t pktcnt;	/*  Number of packets for (s,g) */
	u_quad_t bytecnt;	/*  Number of bytes for (s,g)   */
	u_quad_t wrong_if;	/*  Number of packets received on wrong iif for (s,g) */	
};

/*
 * Structure to keep track of existing (S,G) MFC entries in the kernel
 * for particular (*,G) or (*,*,RP) entry. We must keep track for
 * each active source which doesn't have (S,G) entry in the daemon's
 * routing table. We need to keep track of such sources for two reasons:
 *
 *    (1) If the kernel does not support (*,G) MFC entries (currently, the
 * "official" mcast code doesn't), we must know all installed (s,G) entries
 * in the kernel and modify them if the iif or oif for the (*,G) changes.
 *
 *    (2) By checking periodically the traffic coming from the shared tree,
 * we can either delete the idle sources or switch to the shortest path.
 *
 * Note that even if we have (*,G) implemented in the kernel, we still
 * need to have this structure because of (2)
 */


typedef struct kernel_cache {
	struct kernel_cache *next;
	struct kernel_cache *prev;
	struct sockaddr_in6 source;
	struct sockaddr_in6 group;
	struct sg_count sg_count;	/* The (s,g) data related counters */
} kernel_cache_t;

struct vif_count {
    u_long icount;        /* Input packet count on vif  */
    u_long ocount;        /* Output packet count on vif */
    u_long ibytes;        /* Input byte count on vif */
    u_long obytes;        /* Output byte count on vif */
}; 

/* globals and functions exportations */

extern srcentry_t *srclist;
extern grpentry_t *grplist;

extern void init_pim6_mrt __P((void));
extern mrtentry_t   *find_route  __P((struct sockaddr_in6 *source,
                          	      struct sockaddr_in6 *group,
                          	      u_int16 flags, char create)); 
extern grpentry_t *find_group __P((struct sockaddr_in6 *group));
extern srcentry_t *find_source __P((struct sockaddr_in6 *source));
extern void delete_mrtentry __P((mrtentry_t *mrtentry_ptr));
extern void delete_srcentry __P((srcentry_t *srcentry_ptr));
extern void delete_grpentry __P((grpentry_t *grpentry_ptr));
extern void delete_mrtentry_all_kernel_cache __P((mrtentry_t *mrtentry_ptr));
extern void delete_single_kernel_cache __P((mrtentry_t *mrtentry_ptr,
                        		    	kernel_cache_t *kernel_cache_ptr));
extern void delete_single_kernel_cache_addr __P((mrtentry_t *mrtentry_ptr,
                             			struct sockaddr_in6 *source,
                             			struct sockaddr_in6 *group));
extern void add_kernel_cache __P((mrtentry_t *mrtentry_ptr,
                         	  struct sockaddr_in6 *source,
				  struct sockaddr_in6 *group, u_int16 flags));

#endif
