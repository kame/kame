/*	$KAME: mip6.h,v 1.13 2001/03/29 05:34:31 itojun Exp $	*/

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
 * Copyright (c) 1999, 2000 and 2001 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Authors: Conny Larsson <Conny.Larsson@era.ericsson.se>
 *          Mattias Pettersson <Mattias.Pettersson@era.ericsson.se>
 *
 */

#ifndef _NETINET6_MIP6_H_
#define _NETINET6_MIP6_H_

#include <netinet6/nd6.h>
#include <netinet/icmp6.h>

struct ifnet;

/*
 * Definition For Mobile Internet Protocol Version 6.
 * Draft draft-ietf-mobileip-ipv6-13.txt
 */

/* Definition of MIPv6 states for the Event-State machine */
#define MIP6_STATE_UNDEF      0x01
#define MIP6_STATE_HOME       0x02
#define MIP6_STATE_DEREG      0x03
#define MIP6_STATE_NOTREG     0x04
#define MIP6_STATE_REG        0x05
#define MIP6_STATE_REREG      0x06
#define MIP6_STATE_REGNEWCOA  0x07


/* Definition of states used by the move detection algorithm used by MIPv6. */
#define MIP6_MD_BOOT       0x01
#define MIP6_MD_UNDEFINED  0x02
#define MIP6_MD_HOME       0x03
#define MIP6_MD_FOREIGN    0x04


/* Definition of Home Address route states used by the move detection
   algorithm used by MIPv6. */
#define MIP6_ROUTE_NET     0x01
#define MIP6_ROUTE_HOST    0x02


/* Type of node calling mip6_tunnel */
#define MIP6_NODE_MN    0x01
#define MIP6_NODE_HA    0x02


/* Movement Detection default values */
#define MIP6_MAX_LOST_ADVINTS   3


/* Scope for hook activation */
#define MIP6_GENERIC_HOOKS     0x01
#define MIP6_SPECIFIC_HOOKS    0x02
#define MIP6_CONFIG_HOOKS      0x03


/* Definition of states for tunnels set up by the Home Agent and the MN. */
#define MIP6_TUNNEL_ADD   0
#define MIP6_TUNNEL_MOVE  1
#define MIP6_TUNNEL_DEL   2


/* Definition of length for different destination options */
#define IP6OPT_BULEN       8   /* Length of BU option */
#define IP6OPT_BALEN      11   /* Length of BA option */
#define IP6OPT_BRLEN       0   /* Length of BR option */
#define IP6OPT_HALEN      16   /* Length of HA option */
#define IP6OPT_UIDLEN      2   /* Length of Unique Identifier sub-option */
#define IP6OPT_COALEN     16   /* Length of Alternate COA sub-option */


/* Definition of sub-options used by the Destination Options */
#define IP6SUBOPT_UNIQUEID  0x02   /* Unique Identifier (BU, BR) */
#define IP6SUBOPT_ALTCOA    0x04   /* Alternate COA (BU) */


/* Definition of timers for signals */
#define MIP6_BU_LIFETIME          600  /* Lifetime for BU (s) */
#define MIP6_BU_LIFETIME_HAFN      60  /* Lifetime for BU sent to HA on
					  previous network (s) */
#define MIP6_BU_LIFETIME_HADISCOV  16  /* Lifetime for BU when Dynamic Home
                                          Agent Address Discovery (s) */
#define MIP6_MAX_FAST_UPDATES       5  /* Max number of fast updates (BUs)
                                          being sent */
#define MIP6_MAX_UPDATE_RATE        1  /* Rate limiting for sending successive
                                          fast BUs (sec) */
#define MIP6_SLOW_UPDATE_RATE      10  /* Rate limiting for sending successive
                                          slow BUs (sec) */
#define MIP6_MAX_BINDACK_TIMEOUT  256  /* Max time to wait for a BA */
#define MIP6_MAX_ADVERT_REXMIT      3  /* Max retransmission of NA when
                                          returning to home link */


/* Definition of Binding Acknowledgement status field */
#define MIP6_BA_STATUS_ACCEPT         0  /* Binding Update accepted */
#define MIP6_BA_STATUS_UNSPEC       128  /* Reason unspecified */
#define MIP6_BA_STATUS_PROHIBIT     130  /* Administratively prohibited */
#define MIP6_BA_STATUS_RESOURCE     131  /* Insufficient resources */
#define MIP6_BA_STATUS_HOMEREGNOSUP 132  /* Home registration not supported */
#define MIP6_BA_STATUS_SUBNET       133  /* Not home subnet */
#define MIP6_BA_STATUS_IFLEN        136  /* Incorrect interface id length */
#define MIP6_BA_STATUS_NOTHA        137  /* Not home agent for this MN */
#define MIP6_BA_STATUS_DAD          138  /* DAD failed */


/* Macro for modulo 2^^16 comparison */
#define MIP6_LEQ(a,b)   ((int16_t)((a)-(b)) <= 0)


/* Macros started with MIP6_ADDR is Mobile IPv6 local */
#define MIP6_ADDR_ANYCAST_HA   0x7e

#if BYTE_ORDER == BIG_ENDIAN
#define MIP6_ADDR_INT32_ULL	0xfe800000  /* Unicast Link Local */
#define MIP6_ADDR_INT32_USL	0xfec00000  /* Unicast Site Local */
#define MIP6_ADDR_INT32_AHA1	0xfffffffe  /* Anycast Home Agent bit 97-128 */
#define MIP6_ADDR_INT32_AHA2	0xfdffffff  /* Anycast Home Agent bit 65-96  */
#elif BYTE_ORDER == LITTLE_ENDIAN
#define MIP6_ADDR_INT32_ULL	0x000080fe
#define MIP6_ADDR_INT32_USL	0x0000c0fe
#define MIP6_ADDR_INT32_AHA1	0xfeffffff
#define MIP6_ADDR_INT32_AHA2	0xfffffffd
#endif


/* Definition of some useful macros to handle IP6 addresses */
extern struct in6_addr in6addr_linklocal;
extern struct in6_addr in6addr_sitelocal;
extern struct in6_addr in6addr_aha_64;     /* 64 bits identifier */
extern struct in6_addr in6addr_aha_nn;     /* 121-nn bits identifier */


/* Definition of id for sending of Dynamic Home Agent Address Discovery. */
u_int16_t mip6_hadiscov_id;

/* Definition of event-state machine type. */
enum esm_type {PERMANENT, TEMPORARY};


/* Configuration parameters needed for MIPv6. Controlled by the user */
struct mip6_static_addr {
	LIST_ENTRY(mip6_static_addr) addr_entry;  /* Next IPv6 address list */
	struct ifnet      *ifp;	        /* Interface */
	u_int8_t           prefix_len;	/* Prefix length for address */
	struct in6_addr    ip6_addr;	/* Address used at foreign network */
};


/*
 * fna_list          List of pre-assigned care-of addresses to be used at
 *                   foreign networks that the MN might visit
 * bu_lifetime       Used by the MN when sending a BU to the CN if it wants
 *                   to use a smaller value than received in the home
 *                   registration acknowledgement
 * br_update         Indicates when the CN sends a BR to the MN. The value
 *                   should be given as percentage of the bu_lifetime
 * ha_pref           Preference for the Home Agent
 * hr_lifetime       Default life time for home registration (only sent to the
 *                   Home Agent)
 * fwd_sl_unicast    Enable forwarding of site local unicast dest addresses
 * fwd_sl_multicast  Enable forwarding of site local multicast dest addresses
 * enable_prom_mode  Enable link layer promiscus mode (used by move detection)
 * enable_bu_to_cn   Enable BU being sent to the CN (Route optimization on/off)
 * enable_rev_tunnel Enable tunneling of packets from MN to CN via Home Agent
 * enable_br         Enable sending BR to the MN
 * autoconfig        Only enable MIP6 if the mip6 deamon is running
 * eager_md          Enable eager Movement Detection
 */
struct mip6_config {
	LIST_HEAD(fna_list, mip6_static_addr)  fna_list;
	u_int32_t  bu_lifetime;
	u_int8_t   br_update;
	int16_t    ha_pref;
	u_int32_t  hr_lifetime;
	u_int8_t   fwd_sl_unicast;
	u_int8_t   fwd_sl_multicast;
	u_int8_t   enable_prom_mode;
	u_int8_t   enable_bu_to_cn;
	u_int8_t   enable_rev_tunnel;
	u_int8_t   enable_br;
	u_int8_t   autoconfig;
	u_int8_t   eager_md;
};


/* Unique Identifier sub-option format */
struct mip6_subopt_uid {
	u_int8_t  type;   /* Sub-option type */
	u_int8_t  len;    /* Length (octets) excl. type and len fields */
	u_int8_t  uid[2]; /* Unique identifier */
} __attribute__ ((__packed__));


/* Alternate Care-of Address sub-option format */
struct mip6_subopt_altcoa {
	u_int8_t  type;     /* Sub-option type */
	u_int8_t  len;      /* Length (octets) excl. type and len fields */
	u_int8_t  coa[16];  /* Alternate COA */
} __attribute__ ((__packed__));


/* Buffer for storing a consequtive sequence of sub-options */
struct mip6_buffer {
	int        off;          /* Offset in buffer */
	u_int8_t   buf[2048];    /* Must be at least IPV6_MMTU */
};


/* The event-state machine must be maintained for each Home Address. */
struct mip6_hadiscov {
	struct mip6_buffer  *hal;       /* List of Home Agent addresses */
	u_int16_t            pos;       /* Position for entry in list to use */
	u_int16_t            sent_hadiscov_id;
};

struct mip6_esm {
	struct mip6_esm       *next;      /* Ptr to next entry in the list */
	struct ifnet          *ifp;       /* Interface for home address */
	const struct encaptab *ep;	  /* Encapsulation attach (MN -> HA) */
	int                    state;     /* State for the home address */
	enum esm_type          type;      /* Type of event-state machine */
	struct in6_addr        home_addr; /* Home address */
	struct in6_addr        home_pref; /* Home prefix */
	struct in6_addr        ifid;      /* I/f ID, this group of addresses */
	u_int8_t               prefixlen; /* Prefix_len for Home Address */
	u_int16_t              lifetime;  /* If type=PERMANENT 0xFFFF */
	struct in6_addr        ha_hn;     /* HA address (home link) */
	struct in6_addr        coa;       /* Current primary care-of address */
	struct mip6_hadiscov  *hadiscov;  /* Dynamic HA Address Discovery */
};


/* Binding Cache parameters. Bindings for other IPv6 nodes. */
/* Maintained by each node. */
struct mip6_bc_info {
	u_int32_t  br_interval;   /* % of mip6_lifetime, max 60s, min 2s */
	u_int8_t   sent_brs;      /* Number of sent BRs to a Mobile Node */
	time_t     lasttime;      /* Time when BR was last sent */
};

struct mip6_bc {
	struct mip6_bc        *next;       /* Next entry in the list */
	struct in6_addr        local_home; /* Local nodes home address */
	struct in6_addr        peer_home;  /* Home Address for peer MN  */
	struct in6_addr        peer_coa;   /* COA for peer MN */
	u_int32_t              lifetime;   /* Remaining lifetime  */
	u_int8_t               flags;      /* Received flags in BU */
	u_int8_t               prefixlen;  /* Prefix length in last BU */
	u_int16_t              seqno;      /* Maximum sequence number */
	const struct encaptab *ep;         /* Encapsulation attach (HA->MN) */
	struct mip6_bc_info    info;       /* Arbitrary info (if not HA) */
};



/* Binding Update List parameters. Information for each BU sent by this MN */
/* Each MN maintains this list. */
struct mip6_retrans {
	struct ip6_opt_binding_update *opt;        /* BU option */
	struct mip6_buffer            *subopt;     /* BU sub-options */
	u_int32_t                      ba_timeout; /* Exponential back-off */
	u_int8_t                       timeleft;   /* Next retransmission */
};

struct mip6_update {
	u_int32_t    sent_bus;      /* Number of sent BU to a MN */
	u_int8_t     update_rate;   /* Seconds between consequtive BUs */
};
	
struct mip6_bul {
	struct mip6_bul     *next;           /* Next entry in the list */
	struct in6_addr      peer_home;      /* Dst address for sent BU */
	struct in6_addr      local_home;     /* Home Address or previous COA */
	struct in6_addr      local_coa;      /* COA sent in the BU */
	u_int32_t            sent_lifetime;  /* Initial lifetime in sent BU */
	u_int32_t            lifetime;       /* Remaining binding lifetime */
	u_int32_t            refresh;        /* Refresh time for the BU */
	u_int16_t            seqno;          /* Last seq number sent */
	time_t               lasttime;       /* Time when BU was last sent */
	u_int8_t             send_flag;      /* Send future BU (T/F) */
	u_int8_t             flags;          /* A, H-bit in sent BU */
	struct mip6_retrans  retrans;        /* If A-bit set in flags */
	struct mip6_update   update;         /* If A-bit not set in flags */
};

#define bul_opt        retrans.opt
#define bul_subopt     retrans.subopt
#define bul_timeout    retrans.ba_timeout
#define bul_timeleft   retrans.timeleft
#define bul_sent       update.sent_bus
#define bul_rate       update.update_rate


/* Home Agent List parameters. Information about each other HA on the link
   that this node is serving as a HA. One HA list for each link it is
   serving. */
/* Each HA maintains this list. */
struct mip6_halst {
	struct mip6_halst  *next;       /* Ptr to next entry in the list */
	struct ifnet       *ifp;        /* Receiving/sending interface */
	struct in6_addr     ll_addr;    /* HA link-local address */
	u_int16_t           lifetime;   /* Remaining HA lifetime */
	int16_t             pref;       /* Preference for this HA */
};

struct mip6_addrlst {
	struct mip6_addrlst  *next;       /* Ptr to next entry in the list */
	struct mip6_halst    *hap;        /* HA advertising this address */
	struct in6_addr       ip6_addr;   /* Global IPv6 address */
};

struct mip6_prefix {
	struct mip6_prefix  *next;	  /* Next entry in the list */
	struct ifnet        *ifp;         /* Receiving/sending interface */
	struct in6_addr      prefix;      /* Prefix (on-link) */
	u_int8_t             prefixlen;   /* Prefix length for */
	u_int8_t             flags;       /* Flags in prefix info */
	u_int32_t            timecnt;     /* Timeout value */
	u_int32_t            validtime;   /* Valid lifetime */
	u_int32_t            preftime;    /* Preferred lifetime */
	struct mip6_addrlst *addrlst;     /* List of global addresses */
} __attribute__ ((packed));


/* Neighbor Advertisement information stored for retransmission when the
   Mobile Node is returning to its Home Network or the Home Agent is
   requested to act as a proxy for the Mobile Node when it is moving to a
   Foreign Network. */
struct mip6_na
{
	struct mip6_na   *next;         /* Ptr to next entry in the list */
	struct ifnet     *ifp;          /* Interface for sending the NA */
	struct in6_addr   target_addr;  /* Target address for MN */
	u_long            flags;        /* Flags for the NA message */
	int               link_opt;     /* Incl. target link layer address
					   option (0 = no / 1 = yes) */
	int               no;           /* Remaining times to send the NA */
};

#ifdef _KERNEL

#define MIP6_IS_MN_ACTIVE ((mip6_module & MIP6_MN_MODULE) == MIP6_MN_MODULE)
#define MIP6_IS_HA_ACTIVE ((mip6_module & MIP6_HA_MODULE) == MIP6_HA_MODULE)

#define MIP6_EAGER_PREFIX 	(mip6_config.eager_md >= 2)
#define MIP6_EAGER_FREQ		5	 /* Run nd6_timer 5 times more often */

/* External definition of global variables. */
extern struct mip6_esm     *mip6_esmq;    /* Ptr to list of Home Addresses */
extern struct mip6_bc      *mip6_bcq;     /* First entry in the BC list */
extern struct mip6_prefix  *mip6_prq;     /* First entry in prefix list */
extern struct mip6_bul     *mip6_bulq;
extern struct mip6_halst   *mip6_haq;
extern struct mip6_na      *mip6_naq;
extern struct mip6_config   mip6_config;  /* Config parameters for MIP6 */

extern struct in6_addr      mip6_php;     /* Primary Home Prefix */
extern u_int8_t             mip6_phpl;    /* Primary Home Prefix Length */
extern struct nd_prefix    *mip6_phpp;	  /* Primary Home Prefix Pointer */
extern struct nd_prefix    *mip6_pp;      /* Primary (Care-of) Prefix */
extern struct in6_addr      mip6_pdr;     /* Primary Default Router */
extern struct ifnet        *mip6_hifp;    /* ifp of Home Addresses */
extern int                  mip6_new_homeaddr;

extern u_int8_t mip6_module;           /* Info about loaded modules (MN/HA) */
extern int      mip6_md_state;         /* Movement Detection state */
extern int      mip6_route_state;      /* Home Address route state */
extern int      mip6_max_lost_advints; /* No. lost Adv before start of NUD */
extern int      mip6_nd6_delay;
extern int      mip6_nd6_umaxtries;


/* External declaration of function prototypes (mip6_io.c) */
extern int mip6_route_optimize
	__P((struct mbuf *));
extern int mip6_dstopt
        __P((struct mbuf *, struct ip6_dest *, u_int8_t *, int));
extern void mip6_print_subopt
        __P((u_int8_t *, u_int8_t));
extern void mip6_print_opt
        __P((struct mbuf *, u_int8_t *));
extern void mip6_find_offset
        __P((struct mip6_buffer *));
extern void mip6_add_subopt2buf
        __P((u_int8_t *, struct mip6_buffer *));
extern u_int8_t *mip6_add_opt2dh
        __P((u_int8_t *, struct mip6_buffer *));
extern void mip6_add_subopt2dh
        __P((struct mip6_buffer *, struct mip6_buffer *, u_int8_t *));
extern void mip6_align
        __P((struct mip6_buffer *));
extern int mip6_output
        __P((struct mbuf *, struct ip6_pktopts **));
extern int mip6_add_rh
        __P((struct ip6_pktopts **, struct mip6_bc *));
extern int mip6_add_ha
        __P((struct mbuf *, struct ip6_pktopts **, struct mip6_esm *));
extern void mip6_addr_exchange
        __P((struct mbuf *, struct mbuf *));
extern int mip6_add_bu
        __P((struct ip6_pktopts **, struct mip6_esm *, struct in6_addr *));
extern int mip6_tunnel_input
        __P((struct mbuf **, int *,  int));
extern int mip6_tunnel_output
        __P((struct mbuf **, struct mip6_bc *));


/* External declaration of function prototypes (mip6.c) */
extern void mip6_init
	__P((void));
extern void mip6_exit
	__P((void));
extern int mip6_validate_bu
	__P((struct mbuf *, u_int8_t *));
extern int mip6_validate_subopt
	__P((struct ip6_dest *, u_int8_t *, u_int8_t));
extern int mip6_process_bu
	__P((struct mbuf *, u_int8_t *));
extern struct mip6_subopt_uid *mip6_find_subopt_uid
	__P((u_int8_t *, u_int8_t));
extern struct mip6_subopt_altcoa *mip6_find_subopt_altcoa
	__P((u_int8_t *, u_int8_t));
extern struct mip6_bc *mip6_cache_binding
	__P((struct mbuf *, u_int8_t *, struct in6_addr *));
extern int mip6_build_send_ba
	__P((struct mbuf *, u_int8_t *, struct mip6_bc *,
	     struct mip6_buffer *, u_int8_t));
extern struct mbuf *mip6_create_ip6hdr
	__P((struct in6_addr *, struct in6_addr *, u_int8_t, u_int32_t));
extern struct ip6_rthdr *mip6_create_rh
	__P((struct in6_addr *, u_int8_t));
extern struct ip6_opt_binding_ack *mip6_create_ba
	__P((u_int8_t, u_int16_t, u_int32_t));
extern int mip6_send_ba
	__P((struct mbuf *, struct ip6_rthdr *, struct ip6_dest *));
extern struct in6_addr *mip6_in6addr
	__P((const struct in6_addr *, struct in6_addr *, int));
extern void mip6_intercept_control
	__P((struct in6_addr *, u_int8_t, u_long));
extern void mip6_intercept_packet
	__P((struct in6_addr *, u_long, struct ifnet *));
extern int mip6_tunnel
	__P((struct in6_addr *, struct in6_addr *, int, int, void *));
extern int mip6_icmp6_input
	__P((struct mbuf *, int, int));
extern void mip6_icmp6_find_addr
	__P((u_int8_t *, int, struct in6_addr **, struct in6_addr **));
extern int mip6_icmp6_ra
	__P((struct mbuf *, int, int));
extern int mip6_icmp6_ra_options
	__P((struct ifnet *, struct in6_addr *,
	     struct nd_router_advert *, int));
extern int mip6_add_ifaddr
	__P((struct in6_addr *, struct ifnet *, int, int));
extern struct mip6_bc *mip6_bc_find
	__P((struct in6_addr *, struct in6_addr *));
extern struct mip6_bc *mip6_bc_create
	__P((struct mbuf *, u_int8_t *, struct in6_addr *, u_int32_t));
extern void mip6_bc_update
	__P((u_int8_t *, struct mip6_bc *, struct in6_addr *, u_int32_t));
extern int mip6_bc_delete
	__P((struct mip6_bc *, struct mip6_bc **));
extern struct mip6_na *mip6_na_delete
	__P((struct mip6_na *));
extern struct mip6_prefix *mip6_prefix_find
	__P((struct ifnet *, struct in6_addr *, u_int8_t));
extern struct mip6_prefix *mip6_prefix_create
	__P((struct ifnet *, struct in6_addr *, u_int8_t, u_int8_t,
	     u_int32_t, u_int32_t));
extern void mip6_prefix_update
	__P((struct mip6_prefix *, u_int8_t, u_int32_t, u_int32_t));
extern int mip6_prefix_add_addr
	__P((struct mip6_prefix *, struct in6_addr *, struct mip6_halst *));
extern struct mip6_prefix *mip6_prefix_delete
	__P((struct mip6_prefix *));
extern struct mip6_halst *mip6_hal_find
	__P((struct ifnet *, struct in6_addr *));
extern struct mip6_halst *mip6_hal_create
	__P((struct ifnet *, struct in6_addr *, u_int16_t, u_int16_t));
extern void mip6_hal_sort
	__P((struct mip6_halst *));
extern struct mip6_halst *mip6_hal_delete
	__P((struct mip6_halst *));
extern void mip6_timer_na
	__P((void *));
extern void mip6_timer_bc
	__P((void *));
extern void mip6_timer_prefix
	__P((void *));
extern void mip6_timer_hal
	__P((void *));

#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
extern int mip6_ioctl __P((struct socket *, u_long, caddr_t, struct ifnet *,
			   struct proc *));
#else
extern int mip6_ioctl __P((struct socket *, u_long, caddr_t, struct ifnet *));
#endif

#ifdef MIP6_DEBUG
void mip6_debug __P((char *, ...));
#endif

extern void mip6_enable_debug
	__P((int));
extern void mip6_print_sec
	__P((u_int32_t));
extern int mip6_write_config_data
	__P((u_long, caddr_t));
extern int mip6_clear_config_data
	__P((u_long, caddr_t));
extern int mip6_enable_func
	__P((u_long, caddr_t));


/* External declaration of function prototypes (mip6_md.c) */
extern int mip6_is_primhomeprefix
	__P((struct nd_prefix *));
extern void mip6_create_ifid
	__P((struct ifnet *, struct in6_addr *, u_int8_t));
extern struct in6_ifaddr * mip6_pfxaddr_lookup
	__P((struct nd_prefix *, int, int));
extern struct in6_ifaddr * mip6_coa_lookup
	__P((struct nd_prefix *));
extern void mip6_update_home_addrs
	__P((struct mbuf *, struct nd_prefix *, int));
extern int mip6_create_homeaddr
	__P((struct mip6_esm *));
extern void mip6_select_php
	__P((struct mip6_esm *));
extern void mip6_deprecated_addr
	__P((struct in6_ifaddr *));
extern void mip6_md_init
	__P((void));
extern void mip6_select_defrtr
	__P((struct nd_prefix *, struct nd_defrouter *));
extern void mip6_prelist_update
	__P((struct nd_prefix *, struct nd_defrouter *, u_char));
extern void mip6_eager_prefix
        __P((struct nd_prefix *, struct nd_defrouter *));
extern void mip6_eager_md
	__P((int enable));
extern void mip6_expired_defrouter
	__P((struct nd_defrouter *dr));
extern void mip6_probe_defrouter
	__P((struct nd_defrouter *dr));
extern void mip6_probe_pfxrtrs
	__P((void));
extern void mip6_store_advint
	__P((struct nd_opt_advinterval *, struct nd_defrouter *));
extern int mip6_delete_ifaddr
	__P((struct in6_addr *addr, struct ifnet *ifp));
extern struct nd_prefix *mip6_get_home_prefix
	__P((void));
extern int mip6_get_md_state
	__P((void));
extern void mip6_md_exit
	__P((void));


/* External declaration of function prototypes (mip6_mn.c) */
extern void mip6_mn_init
	__P((void));
extern void mip6_mn_exit
	__P((void));
extern int mip6_validate_ba
	__P((struct mbuf *, u_int8_t *));
extern int mip6_process_ba
	__P((struct mbuf *, u_int8_t *));
extern int mip6_ba_error
	__P((struct mbuf *, u_int8_t *));
extern int mip6_process_br
	__P((struct mbuf *, u_int8_t *));
extern int mip6_send_bu
	__P((struct mip6_bul *, struct ip6_opt_binding_update *,
	     struct mip6_buffer *));
extern void mip6_update_cns
	__P((struct ip6_opt_binding_update *, struct mip6_buffer *,
	     struct in6_addr *, struct in6_addr *, u_int32_t));
extern struct ip6_opt_binding_update *mip6_create_bu
	__P((u_int8_t, u_int8_t, u_int32_t));
extern void mip6_move
	__P((int, struct in6_addr *, u_int8_t, struct nd_prefix *,
	     struct in6_ifaddr *));
extern int mip6_move_home
	__P((struct in6_addr *, u_int8_t, struct in6_addr *));
extern int mip6_move_hn2fn
	__P((struct in6_addr *, u_int8_t, struct in6_addr *));
extern int mip6_move_fn2fn
	__P((struct in6_addr *, u_int8_t, struct in6_addr *));
extern int mip6_update_fn
	__P((struct in6_addr *, u_int8_t, struct in6_addr *,
	     struct in6_addr *));
extern int mip6_send_hadiscov
	__P((struct mip6_esm *));
extern int mip6_icmp6_hadiscov_reply
	__P((struct mbuf *, int, int));
extern u_int32_t mip6_prefix_lifetime
	__P((struct in6_addr *, u_int8_t));
extern struct in6_addr *mip6_in6addr_any
	__P((const struct in6_addr *, int));
extern struct mip6_bul *mip6_bul_find
	__P((struct in6_addr *, struct in6_addr *));
extern struct mip6_bul *mip6_bul_create
	__P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	     u_int32_t, u_int8_t));
extern struct mip6_bul *mip6_bul_delete
	__P((struct mip6_bul *));
extern void mip6_bul_clear_state
	__P((struct mip6_bul *));
extern struct mip6_esm *mip6_esm_find
	__P((struct in6_addr *, u_int8_t));
extern struct mip6_esm *mip6_esm_create
	__P((struct ifnet *, struct in6_addr *, struct in6_addr *,
	     struct in6_addr *, struct in6_addr *,
	     u_int8_t, int, enum esm_type, u_int16_t));
extern struct mip6_esm *mip6_esm_delete
	__P((struct mip6_esm *));
extern void mip6_timer_bul
	__P((void *));
extern int mip6_bul_retransmit
	__P((struct mip6_bul *));
extern int mip6_bul_refresh
	__P((struct mip6_bul *, struct mip6_esm *));
extern void mip6_timer_esm
	__P((void *));
extern int mip6_write_config_data_mn
	__P((u_long, void *));
extern int mip6_clear_config_data_mn
	__P((u_long, caddr_t));
extern int mip6_enable_func_mn
	__P((u_long, caddr_t));
extern int mip6_incl_br
	__P((struct mbuf *));
extern void mip6_send_rs
	__P((struct mip6_esm *,int));
extern void mip6_rs_output
	__P((struct ifnet *));
extern int mip6_tunneled_rs_output
	__P((struct in6_addr *, struct in6_addr *));
extern void mip6_dhaad_reply
	__P((void *));


/* External declaration of function prototypes (mip6_ha.c). */
extern void mip6_ha_init
	__P((void));
extern void mip6_ha_exit
	__P((void));
extern int mip6_accept_bu
	__P((struct mbuf *, u_int8_t *));
extern int mip6_is_addr_onlink
	__P((struct in6_addr *, u_int8_t));
extern u_int32_t mip6_min_lifetime
	__P((struct in6_addr *, u_int8_t));
extern int mip6_proxy_update
	__P((struct in6_addr *, struct in6_addr *, int));
extern void mip6_proxy_control
	__P((struct mip6_bc *, int));
extern void mip6_icmp6_output
	__P((struct mbuf *));
extern int mip6_write_config_data_ha
	__P((u_long, void *));
extern int mip6_clear_config_data_ha
	__P((u_long, void *));
extern int mip6_enable_func_ha
	__P((u_long, caddr_t));


/* External declaration of function prototypes (mip6_hooks.c). */
extern void mip6_minus_a_case
	__P((struct nd_prefix *));
extern struct nd_prefix *mip6_find_auto_home_addr
	__P((struct in6_ifaddr **));
extern void mip6_enable_hooks
	__P((int));
extern void mip6_disable_hooks
	__P((int));
extern int mip6_attach
	__P((int));
extern int mip6_release
	__P((void));

#endif /* _KERNEL */

#endif /* not _NETINET6_MIP6_H_ */
