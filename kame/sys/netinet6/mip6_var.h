/*	$KAME: mip6_var.h,v 1.69 2002/11/01 10:10:09 keiichi Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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

#ifndef _MIP6_VAR_H_
#define _MIP6_VAR_H_

#define GET_NETVAL_S(p, v)	bcopy((p), &(v), sizeof(v)), v = ntohs(v)
#define GET_NETVAL_L(p, v)	bcopy((p), &(v), sizeof(v)), v = ntohl(v)
#define SET_NETVAL_S(p, v)	do {					\
					u_int16_t s = htons(v);		\
					bcopy(&s, (p), sizeof(s));	\
				} while (0)
#define SET_NETVAL_L(p, v)	do {					\
					u_int32_t s = htonl(v);		\
					bcopy(&s, (p), sizeof(s));	\
				} while (0)

#define MIP6_COOKIE_MAX_LIFE	240
#define MIP6_COOKIE_SIZE	8
#define HOME_COOKIE_SIZE	8
#define CAREOF_COOKIE_SIZE	8
#define MIP6_NONCE_SIZE		8	/* recommended by the spec (5.2.2) */
					/* must be multiple of size of u_short */
#define MIP6_NODEKEY_SIZE	20	/* This size is specified at 5.2.1 in mip6 spec */
#define MIP6_NONCE_HISTORY	10
typedef u_int8_t mip6_nonce_t[MIP6_NONCE_SIZE];
typedef u_int8_t mip6_nodekey_t[MIP6_NODEKEY_SIZE];
typedef u_int8_t mip6_cookie_t[MIP6_COOKIE_SIZE];
typedef u_int8_t mip6_home_cookie_t[HOME_COOKIE_SIZE];
typedef u_int8_t mip6_careof_cookie_t[CAREOF_COOKIE_SIZE];
#define MIP6_KBU_LEN		16
#define MIP6_AUTHENTICATOR_LEN	12

#define MIP6_MAX_RR_BINDING_LIFE	420

/* Callout table for MIP6 structures */
struct mip6_timeout {
	TAILQ_ENTRY(mip6_timeout)	mto_entry;
	time_t				mto_expire;
	LIST_HEAD(, mip6_timeout_entry)	mto_timelist;
};

struct mip6_timeout_entry {
	LIST_ENTRY(mip6_timeout_entry)	mtoe_entry;
	caddr_t				mtoe_ptr;
	struct mip6_timeout		*mtoe_timeout;
};

struct mip6_prefix {
	LIST_ENTRY(mip6_prefix) mpfx_entry;
	struct sockaddr_in6     mpfx_prefix;
	u_int8_t                mpfx_prefixlen;
	u_int32_t               mpfx_vltime;
	time_t                  mpfx_vlexpire;
	u_int32_t               mpfx_pltime;
	time_t                  mpfx_plexpire;
	struct sockaddr_in6     mpfx_haddr;
};
LIST_HEAD(mip6_prefix_list, mip6_prefix);

#define MIP6_PREFIX_TIMEOUT_INTERVAL 5

/* XXX the home agent entry.  not good. */
struct mip6_ha {
	LIST_ENTRY(mip6_ha) mha_entry;
	struct sockaddr_in6 mha_lladdr;    /* XXX link-local addr */
	struct sockaddr_in6 mha_gaddr;     /* XXX global addr */
	u_int8_t            mha_flags;     /* RA flags */
	int16_t             mha_pref;      /* preference */
	u_int16_t           mha_lifetime;  /* HA lifetime */
	time_t              mha_expire;    /* expiration time of this HA. */
};
LIST_HEAD(mip6_ha_list, mip6_ha);

#define MIP6_HA_TIMEOUT_INTERVAL 5

struct mip6_subnet_prefix {
	TAILQ_ENTRY(mip6_subnet_prefix) mspfx_entry;
	struct mip6_prefix              *mspfx_mpfx;
};

struct mip6_subnet_ha {
	TAILQ_ENTRY(mip6_subnet_ha) msha_entry;
	struct mip6_ha              *msha_mha;
};

/*
 * the subnet infomation.  this entry includes the routers and the
 * prefixes those have some relations each other.
 */
struct mip6_subnet {
	LIST_ENTRY(mip6_subnet)                         ms_entry;
	TAILQ_HEAD(mip6_subnet_prefix_list, mip6_subnet_prefix) ms_mspfx_list;
	TAILQ_HEAD(mip6_subnet_ha_list, mip6_subnet_ha) ms_msha_list;
	int ms_refcnt;
};
LIST_HEAD(mip6_subnet_list, mip6_subnet);

#define MIP6_SUBNET_TIMEOUT_INTERVAL 10

/* the binding update list entry. */
struct mip6_bu {
	LIST_ENTRY(mip6_bu) mbu_entry;
	struct sockaddr_in6 mbu_paddr;      /* peer addr of this BU */
	struct sockaddr_in6 mbu_haddr;      /* HoA */
	struct sockaddr_in6 mbu_coa;        /* CoA */
	u_int16_t           mbu_lifetime;   /* BU lifetime */
	u_int16_t           mbu_refresh;    /* refresh frequency */
	u_int16_t           mbu_seqno;      /* sequence number */
	u_int8_t            mbu_flags;      /* BU flags */
	mip6_cookie_t       mbu_mobile_cookie;
	u_int16_t           mbu_home_nonce_index;
	mip6_home_cookie_t  mbu_home_cookie;
	u_int16_t           mbu_careof_nonce_index;
        mip6_careof_cookie_t mbu_careof_cookie;
	u_int8_t            mbu_pri_fsm_state; /* primary fsm state. */
	u_int8_t            mbu_sec_fsm_state; /* secondary fsm state. */
	time_t              mbu_expire;     /* expiration time of this BU. */
	time_t              mbu_retrans;    /* retrans/refresh timo value. */
	u_int8_t            mbu_retrans_count;
	time_t              mbu_failure;    /* failure timo value. */
	u_int8_t            mbu_state;
	struct hif_softc    *mbu_hif;       /* back pointer to hif */
	const struct encaptab *mbu_encap;
};
#define MIP6_BU_STATE_BUNOTSUPP   0x04
#define MIP6_BU_STATE_MIP6NOTSUPP 0x80

/* states for the primary fsm. */
#define MIP6_BU_PRI_FSM_STATE_IDLE	0
#define MIP6_BU_PRI_FSM_STATE_RRINIT	1
#define MIP6_BU_PRI_FSM_STATE_RRREDO	2
#define MIP6_BU_PRI_FSM_STATE_RRDEL	3
#define MIP6_BU_PRI_FSM_STATE_WAITA	4
#define MIP6_BU_PRI_FSM_STATE_WAITAR	5
#define MIP6_BU_PRI_FSM_STATE_WAITD	6
#define MIP6_BU_PRI_FSM_STATE_BOUND	7
#define MIP6_IS_BU_BOUND_STATE(mbu)					\
	(((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_RRREDO)	\
	|| ((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_WAITAR)	\
	|| ((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_BOUND))
#define MIP6_IS_BU_WAITA_STATE(mbu)					\
	(((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_WAITA)	\
	|| ((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_WAITAR)	\
	|| ((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_WAITD))
#define MIP6_IS_BU_RR_STATE(mbu)					\
	(((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_RRINIT)	\
	|| ((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_RRREDO)	\
	|| ((mbu)->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_RRDEL))

/* states for the secondary fsm. */
#define MIP6_BU_SEC_FSM_STATE_START	0
#define MIP6_BU_SEC_FSM_STATE_WAITHC	1
#define MIP6_BU_SEC_FSM_STATE_WAITH	2
#define MIP6_BU_SEC_FSM_STATE_WAITC	3

/* events for the primary fsm. */
#define MIP6_BU_PRI_FSM_EVENT_MOVEMENT		0
#define MIP6_BU_PRI_FSM_EVENT_RETURNING_HOME	1
#define MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET	2
#define MIP6_BU_PRI_FSM_EVENT_RR_DONE		3
#define MIP6_BU_PRI_FSM_EVENT_RR_FAILED		4
#define MIP6_BU_PRI_FSM_EVENT_BRR		5
#define MIP6_BU_PRI_FSM_EVENT_BA		6
#define MIP6_BU_PRI_FSM_EVENT_NO_BINDING	7
#define MIP6_BU_PRI_FSM_EVENT_UNVERIFIED_HAO	8
#define MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE	9
#define MIP6_BU_PRI_FSM_EVENT_ICMP_PARAMPROB	10
#define MIP6_BU_PRI_FSM_EVENT_RETRANS_TIMER	11
#define MIP6_BU_PRI_FSM_EVENT_REFRESH_TIMER	12
#define MIP6_BU_PRI_FSM_EVENT_FAILURE_TIMER	13
#define MIP6_BU_IS_PRI_FSM_EVENT(ev) ((ev) <= MIP6_BU_PRI_FSM_EVENT_FAILURE_TIMER)

/* events for the secondary fsm. */
#define MIP6_BU_SEC_FSM_EVENT_START_RR		14
#define MIP6_BU_SEC_FSM_EVENT_START_HOME_RR	15
#define MIP6_BU_SEC_FSM_EVENT_STOP_RR		16
#define MIP6_BU_SEC_FSM_EVENT_HOT		17
#define MIP6_BU_SEC_FSM_EVENT_COT		18
#define MIP6_BU_SEC_FSM_EVENT_RETRANS_TIMER	19
#define MIP6_BU_IS_SEC_FSM_EVENT(ev) (!MIP6_BU_IS_PRI_FSM_EVENT((ev)))

#define MIP6_BU_TIMEOUT_INTERVAL 1
#define MIP6_BU_SAWAIT_INTERVAL 4

#define MIP6_HOT_TIMEOUT 5

/* the binding cache entry. */
struct mip6_bc {
	LIST_ENTRY(mip6_bc)   mbc_entry;
	struct sockaddr_in6   mbc_phaddr;    /* peer home address */
	struct sockaddr_in6   mbc_pcoa;      /* peer coa */
	struct sockaddr_in6   mbc_addr;      /* my addr (needed?) */
	u_int8_t              mbc_status;    /* BA statue */
	u_int8_t	      mbc_send_ba;   /* nonzero means BA should be sent */
	u_int32_t             mbc_refresh;   /* Using for sending BA */
	u_int8_t              mbc_flags;     /* recved BU flags */
	u_int16_t             mbc_seqno;     /* recved BU seqno */
	u_int32_t             mbc_lifetime;  /* recved BU lifetime */
	time_t                mbc_expire;    /* expiration time of this BC. */
	u_int8_t              mbc_state;     /* BC state */
	struct ifnet          *mbc_ifp;      /* ifp that the BC belongs to. */
	                                     /* valid only when BUF_HOME. */
	const struct encaptab *mbc_encap;    /* encapsulation from MN */
	void		      *mbc_dad;	     /* dad handler */
#ifdef MIP6_CALLOUTTEST
	struct mip6_timeout_entry *mbc_timeout;
	struct mip6_timeout_entry *mbc_brr_timeout;
#endif /* MIP6_CALLOUTTEST */
};
LIST_HEAD(mip6_bc_list, mip6_bc);

#define MIP6_BC_STATE_BA_WAITSENT 0x01
#define MIP6_BC_STATE_BR_WAITSENT 0x02
#define MIP6_BC_STATE_DAD_WAIT	  0x04

#define MIP6_BC_TIMEOUT_INTERVAL 1
#define MIP6_REFRESH_MINLIFETIME 2
#define MIP6_REFRESH_LIFETIME_RATE 50

#define MIP6_TUNNEL_ADD    0
#define MIP6_TUNNEL_CHANGE 1
#define MIP6_TUNNEL_DELETE 2

/* Macro for modulo 2^^16 comparison */
#define MIP6_LEQ(a,b)   ((int16_t)((a)-(b)) <= 0)

struct mip6_config {
	u_int8_t mcfg_type;
	u_int8_t mcfg_use_ipsec;
	u_int8_t mcfg_use_authdata;
	u_int8_t mcfg_debug;
	u_int32_t mcfg_bc_lifetime_limit;
	u_int32_t mcfg_hrbc_lifetime_limit;
	u_int32_t mcfg_bu_maxlifetime;
	u_int32_t mcfg_hrbu_maxlifetime;
	u_int8_t mcfg_bu_use_single;
};
#define MIP6_CONFIG_TYPE_MOBILENODE 1
#define MIP6_CONFIG_TYPE_HOMEAGENT 2

#define MIP6_IS_MN (mip6_config.mcfg_type == MIP6_CONFIG_TYPE_MOBILENODE)
#define MIP6_IS_HA (mip6_config.mcfg_type == MIP6_CONFIG_TYPE_HOMEAGENT)

/* packet options used by the mip6 packet output processing routine. */
struct mip6_pktopts {
	struct ip6_rthdr *mip6po_rthdr2;
	struct ip6_dest *mip6po_haddr;
	struct ip6_dest *mip6po_dest2;
	struct ip6_mobility *mip6po_mobility;
};

/* buffer for storing a consequtive sequence of sub-options. */
struct mip6_buffer {
	int      off;  /* Offset in buffer */
	u_int8_t *buf; /* Must be at least IPV6_MMTU */
};
#define MIP6_BUFFER_SIZE 1500 /* XXX 1500 ? */

#define IP6OPT_HALEN  16 /* Length of HA option */

struct mip6_mobility_options {
	u_int16_t valid_options;	/* shows valid options in this structure */
	u_int16_t	mopt_uid;		/* Unique ID */
	struct in6_addr mopt_altcoa;		/* Alternate CoA */
	u_int16_t	mopt_ho_nonce_idx;	/* Home Nonce Index */
	u_int16_t	mopt_co_nonce_idx;	/* Care-of Nonce Index */
	caddr_t mopt_auth;			/* Authenticator */
	u_int16_t	mopt_refresh;		/*  Refresh Interval */
};

#define MOPT_UID	0x0001
#define MOPT_ALTCOA	0x0002
#define MOPT_NONCE_IDX	0x0004
#define MOPT_AUTHDATA	0x0008
#define MOPT_REFRESH	0x0010

#define MOPT_AUTH_LEN(mopts)	(int)(*((mopts)->mopt_auth + 1))

/*
 * the list entry to hold the destination addresses which do not use a
 * home address as a source address when communicating.
 */
struct mip6_unuse_hoa {
	LIST_ENTRY (mip6_unuse_hoa) unuse_entry;
	struct in6_addr unuse_addr;
	u_int16_t unuse_port;
};
LIST_HEAD(mip6_unuse_hoa_list, mip6_unuse_hoa);

/*
 * Mobile IPv6 related statistics.
 */
struct mip6stat {
	u_quad_t mip6s_mobility;	/* Mobility Header recieved */
	u_quad_t mip6s_omobility;	/* Mobility Header sent */
	u_quad_t mip6s_hoti;		/* HoTI recieved */
	u_quad_t mip6s_ohoti;		/* HoTI sent */
	u_quad_t mip6s_coti;		/* CoTI received */
	u_quad_t mip6s_ocoti;		/* CoTI sent */
	u_quad_t mip6s_hot;		/* HoT received */
	u_quad_t mip6s_ohot;		/* HoT sent */
	u_quad_t mip6s_cot;		/* CoT received */
	u_quad_t mip6s_ocot;		/* CoT sent */
	u_quad_t mip6s_bu;		/* BU received */
	u_quad_t mip6s_obu;		/* BU sent */
	u_quad_t mip6s_ba;		/* BA received */
	u_quad_t mip6s_ba_hist[256];	/* BA status input histgram */
	u_quad_t mip6s_oba;		/* BA sent */
	u_quad_t mip6s_oba_hist[256];	/* BA status output histgram */
	u_quad_t mip6s_br;		/* BR received */
	u_quad_t mip6s_obr;		/* BR sent */
	u_quad_t mip6s_be;		/* BE received */
	u_quad_t mip6s_be_hist[256];	/* BE status input histogram */
	u_quad_t mip6s_obe;		/* BE sent */
	u_quad_t mip6s_obe_hist[256];	/* BE status output histogram */
	u_quad_t mip6s_hao;		/* HAO received */
	u_quad_t mip6s_unverifiedhao;	/* unverified HAO received */
	u_quad_t mip6s_ohao;		/* HAO sent */
	u_quad_t mip6s_rthdr2;		/* RTHDR2 received */
	u_quad_t mip6s_orthdr2;		/* RTHDR2 sent */
	u_quad_t mip6s_revtunnel;	/* reverse tunnel input */
	u_quad_t mip6s_orevtunnel;	/* reverse tunnel output */
	u_quad_t mip6s_checksum;	/* bad checksum */
	u_quad_t mip6s_payloadproto;	/* payload proto != no nxt header */
	u_quad_t mip6s_unknowntype;	/* unknown MH type value */
	u_quad_t mip6s_nohif;		/* not my home address */
	u_quad_t mip6s_nobue;		/* no related BUE */
	u_quad_t mip6s_hotcookie;	/* HoT cookie mismatch */
	u_quad_t mip6s_cotcookie;	/* CoT cookie mismatch */
	u_quad_t mip6s_unprotected;	/* not IPseced signaling */
	u_quad_t mip6s_haopolicy;	/* BU is discarded due to bad HAO */
	u_quad_t mip6s_rrauthfail;	/* RR authentication failed */
	u_quad_t mip6s_seqno;		/* seqno mismatch */
	u_quad_t mip6s_paramprobhao;	/* ICMP paramprob for HAO received */
	u_quad_t mip6s_paramprobmh;	/* ICMP paramprob for MH received */
};

#ifdef _KERNEL
struct encaptab;

extern struct mip6_config mip6_config;
extern struct mip6_ha_list mip6_ha_list; /* Global val holding all HAs */
#ifdef MIP6_DRAFT18
extern u_int16_t nonce_index;		/* Current noce index */
#endif /* MIP6_DRAFT18 */
extern struct mip6stat mip6stat;	/* statistics */

void mip6_init __P((void));

int mip6_prefix_list_update		__P((struct sockaddr_in6 *,
					     struct nd_prefix *,
					     struct nd_defrouter *,
					     struct mbuf *));
int mip6_process_pfxlist_status_change	__P((struct sockaddr_in6 *));
void mip6_probe_routers			__P((void));
int mip6_select_coa			__P((struct ifnet *));
int mip6_select_coa2			__P((void));
int mip6_process_movement		__P((void));

int mip6_ifa_need_dad			__P((struct in6_ifaddr *));
int64_t mip6_coa_get_lifetime		__P((struct in6_addr *));

struct mbuf *mip6_create_ip6hdr		 __P((struct sockaddr_in6 *,
					      struct sockaddr_in6 *,
					      u_int8_t,
					      u_int32_t));
int mip6_exthdr_create			 __P((struct mbuf *,
					      struct ip6_pktopts *,
					      struct mip6_pktopts *));
int mip6_ip6mu_create			__P((struct ip6_mobility **,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     struct hif_softc *));
int mip6_ip6ma_create			__P((struct ip6_mobility **,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     u_int8_t,
					     u_int16_t,
					     u_int32_t,
					     u_int32_t,
					     struct mip6_mobility_options *));
int mip6_ip6me_create			__P((struct ip6_mobility **,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     u_int8_t,
					     struct sockaddr_in6 *));
int mip6_process_hrbu __P((struct mip6_bc *));
int mip6_process_hurbu __P((struct mip6_bc *));
int mip6_bu_destopt_create		__P((struct ip6_dest **,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     struct ip6_pktopts *,
					     struct hif_softc *));
int mip6_ba_destopt_create		 __P((struct ip6_dest **,
					      struct sockaddr_in6 *,
					      struct sockaddr_in6 *,
					      u_int8_t,
					      u_int16_t,
					      u_int32_t,
					      u_int32_t));
int mip6_rthdr_create			__P((struct ip6_rthdr **,
					     struct sockaddr_in6 *,
					     struct ip6_pktopts *));
void mip6_destopt_discard		__P((struct mip6_pktopts *));
caddr_t mip6_add_opt2dh __P((caddr_t, struct mip6_buffer *));
void mip6_find_offset __P((struct mip6_buffer *));
void mip6_align_destopt __P((struct mip6_buffer *));
#if defined(IPSEC) && !defined(__OpenBSD__)
caddr_t mip6_add_subopt2dh __P((u_int8_t *, u_int8_t *,
				       struct mip6_buffer *));
#endif /* IPSEC && !__OpenBSD__ */
int mip6_addr_exchange			__P((struct mbuf *,
					     struct mbuf *));
int mip6_process_destopt		__P((struct mbuf *,
					     struct ip6_dest *,
					     u_int8_t *, int));
void mip6_create_addr			__P((struct sockaddr_in6 *,
					     const struct sockaddr_in6 *,
					     struct nd_prefix *));
struct mip6_bc *mip6_bc_list_find_withcoa
					__P((struct mip6_bc_list *,
					     struct sockaddr_in6 *));

int mip6_ioctl				__P((u_long, caddr_t));
int mip6_tunnel_input			__P((struct mbuf **, int *, int));
int mip6_tunnel_output			__P((struct mbuf **,
					     struct mip6_bc *));
int mip6_route_optimize			__P((struct mbuf *));
int mip6_icmp6_input			__P((struct mbuf *, int, int));
int mip6_icmp6_tunnel_input		__P((struct mbuf *, int, int));
int mip6_icmp6_dhaad_req_output(struct hif_softc *);
int mip6_icmp6_mp_sol_output		__P((struct mip6_prefix *,
					     struct mip6_ha *));
int mip6_bdt_create			__P((struct hif_softc *,
					     struct sockaddr_in6 *));

/* mip6_prefix management */
void mip6_prefix_init			__P((void));
struct mip6_prefix *mip6_prefix_create	__P((struct sockaddr_in6 *, u_int8_t,
					     u_int32_t, u_int32_t));
int mip6_prefix_haddr_assign		__P((struct mip6_prefix *,
					     struct hif_softc *));
int mip6_prefix_list_insert		__P((struct mip6_prefix_list *,
					     struct mip6_prefix *));
int mip6_prefix_list_remove		__P((struct mip6_prefix_list *,
					     struct mip6_prefix *mpfx));
struct mip6_prefix *mip6_prefix_list_find
					__P((struct mip6_prefix *));
struct mip6_prefix *mip6_prefix_list_find_withhaddr
					__P((struct mip6_prefix_list *,
					     struct sockaddr_in6 *haddr));

/* subnet information management */
void mip6_subnet_init			__P((void));
struct mip6_subnet *mip6_subnet_create	__P((void));
int mip6_subnet_delete			__P((struct mip6_subnet *));
int mip6_subnet_list_insert		__P((struct mip6_subnet_list *,
					     struct mip6_subnet *));
int mip6_subnet_list_remove		__P((struct mip6_subnet_list *,
					     struct mip6_subnet *));
struct mip6_subnet *mip6_subnet_list_find_withprefix
					__P((struct mip6_subnet_list *,
					     struct sockaddr_in6 *, u_int8_t));
struct mip6_subnet *mip6_subnet_list_find_withmpfx
					__P((struct mip6_subnet_list *,
					     struct mip6_prefix *));
struct mip6_subnet *mip6_subnet_list_find_withhaaddr
					__P((struct mip6_subnet_list *,
					     struct sockaddr_in6 *));
struct mip6_subnet_prefix *mip6_subnet_prefix_create
					__P((struct mip6_prefix *));
int mip6_subnet_prefix_list_insert	__P((struct mip6_subnet_prefix_list *,
					     struct mip6_subnet_prefix *));
int mip6_subnet_prefix_list_remove	__P((struct mip6_subnet_prefix_list *,
					     struct mip6_subnet_prefix *));
struct mip6_subnet_prefix *mip6_subnet_prefix_list_find_withmpfx
					__P((struct mip6_subnet_prefix_list *,
					     struct mip6_prefix *mpfx));
struct mip6_subnet_prefix *mip6_subnet_prefix_list_find_withprefix
					__P((struct mip6_subnet_prefix_list *,
					     struct sockaddr_in6 *, u_int8_t));
int32_t mip6_subnet_prefix_list_get_minimum_lifetime
					__P((struct mip6_subnet_prefix_list *));
struct mip6_subnet_ha *mip6_subnet_ha_create
					__P((struct mip6_ha *));
int mip6_subnet_ha_list_insert		__P((struct mip6_subnet_ha_list *,
					     struct mip6_subnet_ha *));
struct mip6_subnet_ha *mip6_subnet_ha_list_find_preferable
					__P((struct mip6_subnet_ha_list *));
struct mip6_subnet_ha *mip6_subnet_ha_list_find_withmha
					__P((struct mip6_subnet_ha_list *,
					     struct mip6_ha *));
struct mip6_subnet_ha *mip6_subnet_ha_list_find_withhaaddr
					__P((struct mip6_subnet_ha_list *,
					     struct sockaddr_in6 *haaddr));


/* homeagent list management */
void mip6_ha_init			__P((void));
/* mip6_ha functions */
struct mip6_ha *mip6_ha_create		__P((struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     u_int8_t, int16_t, int32_t));
int mip6_ha_list_insert			__P((struct mip6_ha_list *,
					     struct mip6_ha *mha));
int mip6_ha_list_remove			__P((struct mip6_ha_list*,
					     struct mip6_ha *mha));
struct mip6_ha *mip6_ha_list_find_withaddr
					__P((struct mip6_ha_list *,
					     struct sockaddr_in6 *));
int mip6_ha_list_update_hainfo		__P((struct mip6_ha_list *,
					     struct nd_defrouter *,
					     struct nd_opt_homeagent_info *));
int mip6_ha_list_update_withndpr	__P((struct mip6_ha_list *,
					     struct sockaddr_in6 *,
					     struct nd_prefix *));
int mip6_ha_list_update_gaddr		__P((struct mip6_ha_list*,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *));

/* binding update management */
void mip6_bu_init			__P((void));
struct mip6_bu *mip6_bu_create		__P((const struct sockaddr_in6 *,
					     struct mip6_prefix *,
					     struct sockaddr_in6 *,
					     u_int16_t,
					     struct hif_softc *));
int mip6_bu_list_insert			__P((struct mip6_bu_list *,
					     struct mip6_bu *));
int mip6_bu_list_remove __P((struct mip6_bu_list *, struct mip6_bu *));
int mip6_bu_list_notify_binding_change __P((struct hif_softc *));
int mip6_tunnel_control __P((int, void *,
			     int (*) __P((const struct mbuf *,
					  int, int, void *)),
			     const struct encaptab **));
int mip6_bu_list_remove_all		__P((struct mip6_bu_list *));
struct mip6_bu *mip6_bu_list_find_withpaddr
					__P((struct mip6_bu_list *,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *));
struct mip6_bu *mip6_bu_list_find_home_registration
					__P((struct mip6_bu_list *,
					     struct sockaddr_in6 *));
int mip6_bu_encapcheck __P((const struct mbuf *, int, int, void *));
int mip6_home_registration(struct hif_softc *);
int mip6_home_registration2(struct mip6_bu *);
int mip6_validate_bu			__P((struct mbuf *, u_int8_t *));
int mip6_process_bu			__P((struct mbuf *, u_int8_t *));

int mip6_ip6mhi_input			__P((struct mbuf *,
					     struct ip6m_home_test_init *,
					     int));
int mip6_ip6mci_input			__P((struct mbuf *,
					     struct ip6m_careof_test_init *,
					     int));
int mip6_ip6mh_input			__P((struct mbuf *,
					     struct ip6m_home_test *,
					     int));
int mip6_ip6mc_input			__P((struct mbuf *,
					     struct ip6m_careof_test *,
					     int));
int mip6_ip6mu_input			__P((struct mbuf *,
					     struct ip6m_binding_update *,
					     int));
int mip6_ip6ma_input			__P((struct mbuf *,
					     struct ip6m_binding_ack *,
					     int));
int mip6_ip6me_input			__P((struct mbuf *,
					     struct ip6m_binding_error *,
					     int));
int mip6_ip6mhti_input			__P((struct mbuf *,
					     struct ip6m_home_test_init *,
					     int));
int mip6_bu_fsm				__P((struct mip6_bu *, int, void *));
int mip6_bu_send_hoti			__P((struct mip6_bu *));
int mip6_bu_send_coti			__P((struct mip6_bu *));
int mip6_bu_send_cbu			__P((struct mip6_bu *));
int mip6_bu_send_bu			__P((struct mip6_bu *));

/* binding ack management */
int mip6_validate_ba			__P((struct mbuf *, u_int8_t *));
int mip6_process_ba			__P((struct mbuf *, u_int8_t *));

/* binding request management */
int mip6_validate_br			__P((struct mbuf *, u_int8_t *));
int mip6_process_br			__P((struct mbuf *, u_int8_t *));

/* binding cache management */
void mip6_bc_init			__P((void));
int mip6_bc_register			__P((struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     u_int16_t, u_int16_t, u_int32_t));
int mip6_bc_update			__P((struct mip6_bc *,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *,
					     u_int16_t, u_int16_t, u_int32_t));
int mip6_bc_delete			__P((struct mip6_bc *));
int mip6_bc_list_remove			__P((struct mip6_bc_list *,
					     struct mip6_bc *));
struct mip6_bc *mip6_bc_list_find_withphaddr
					__P((struct mip6_bc_list *,
					     struct sockaddr_in6 *));
struct mip6_bc *mip6_bc_list_find_withpcoa
					__P((struct mip6_bc_list *,
					     struct sockaddr_in6 *));
int mip6_bc_send_ba __P((struct sockaddr_in6 *, struct sockaddr_in6 *,
			 struct sockaddr_in6 *, u_int8_t, u_int16_t,
			 u_int32_t, u_int32_t, struct mip6_mobility_options *));
int mip6_bc_send_bm			__P((struct mbuf *,
					     struct in6_addr *));
int mip6_dad_success			__P((struct ifaddr *));
int mip6_dad_duplicated			__P((struct ifaddr *));
int mip6_dad_error			__P((struct ifaddr *, int));
struct ifaddr *mip6_dad_find		__P((struct in6_addr *, struct ifnet *));

#define mip6log(arg) do { if (mip6_config.mcfg_debug) log arg;} while (0)
void mip6_ha_print __P((struct mip6_ha *));

int mip6_setpktaddrs __P((struct mbuf *));
#ifdef MIP6_DRAFT18
int mip6_get_nonce __P((int, mip6_nonce_t *));
int mip6_get_nodekey __P((int, mip6_nodekey_t *));
int mip6_is_valid_bu (struct ip6_hdr *, struct ip6m_binding_update *,
		      int, struct mip6_mobility_options *,
		      struct sockaddr_in6 *, struct sockaddr_in6 *);
int mip6_get_mobility_options __P((struct ip6_mobility *, int,
				   int, struct mip6_mobility_options *));
void mip6_create_cookie __P((struct in6_addr *,
			     mip6_nodekey_t *, mip6_nonce_t *,
			     void *));
void mip6_calculate_kbu(mip6_home_cookie_t *, mip6_careof_cookie_t *, u_int8_t *);
int  mip6_calculate_kbu_from_index(struct sockaddr_in6 *, struct sockaddr_in6 *, u_int16_t, u_int16_t, u_int8_t *);
void mip6_calculate_authenticator(u_int8_t *, u_int8_t *, 
	struct in6_addr *, struct in6_addr *,
	caddr_t, size_t, int, size_t);
#endif /* MIP6_DRAFT18 */

#endif /* _KERNEL */

#endif /* !_MIP6_VAR_H_ */
