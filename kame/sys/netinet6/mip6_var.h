/*	$KAME: mip6_var.h,v 1.117 2004/05/21 08:17:58 itojun Exp $	*/

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

#if defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

#define GET_NETVAL_S(p, v)	bcopy((p), &(v), sizeof(v)), v = ntohs(v)
#define GET_NETVAL_L(p, v)	bcopy((p), &(v), sizeof(v)), v = ntohl(v)
#define SET_NETVAL_S(p, v)	do {					\
					u_int16_t s = htons(v);		\
					bcopy(&s, (p), sizeof(s));	\
				} while (/*CONSTCOND*/ 0)
#define SET_NETVAL_L(p, v)	do {					\
					u_int32_t s = htonl(v);		\
					bcopy(&s, (p), sizeof(s));	\
				} while (/*CONSTCOND*/ 0)

/* Mobile IPv6 related I/O control numbers. */
#define SIOCSMIP6CFG _IOW('m', 120, int)
#define SIOCSMIP6CFG_ENABLEMN        0
#define SIOCSMIP6CFG_DISABLEMN       1
#define SIOCSMIP6CFG_ENABLEHA        2
#define SIOCSMIP6CFG_ENABLEIPSEC     3
#define SIOCSMIP6CFG_DISABLEIPSEC    4
#define SIOCSMIP6CFG_ENABLEDEBUG     128
#define SIOCSMIP6CFG_DISABLEDEBUG    129
#define SIOCGBC               _IOWR('m', 122, struct mip6_req)
#define SIOCSUNUSEHA          _IOW('m', 123, struct mip6_req)
#define SIOCGUNUSEHA          _IOWR('m', 124, struct mip6_req)
#define SIOCDUNUSEHA          _IOW('m', 125, struct mip6_req)
#define SIOCDBC               _IOW('m', 126, struct mip6_req)
#define SIOCSPREFERREDIFNAMES _IOW('m', 127, struct mip6_req)

struct mip6_preferred_ifnames {
	char mip6pi_ifname[3][IFNAMSIZ];
	/* is 3 enough? or should it be dynamic? */
};
struct mip6_req {
	u_int8_t mip6r_count;
	union {
		struct mip6_bc *mip6r_mbc;
		struct in6_addr mip6r_in6;
		struct sockaddr_in6 mip6r_ssin6;
		struct mip6_preferred_ifnames mip6r_ifnames;
	} mip6r_ru;
};

/* the binding cache entry. */
struct mip6_bc {
	LIST_ENTRY(mip6_bc)   mbc_entry;
	struct in6_addr       mbc_phaddr;    /* peer home address */
	struct in6_addr       mbc_pcoa;      /* peer coa */
	struct in6_addr       mbc_addr;      /* my addr (needed?) */
	u_int8_t              mbc_status;    /* BA statue */
	u_int8_t	      mbc_send_ba;   /* nonzero means BA should be sent */
	u_int32_t             mbc_refresh;   /* Using for sending BA */
	u_int16_t             mbc_flags;     /* recved BU flags */
	u_int16_t             mbc_seqno;     /* recved BU seqno */
	u_int32_t             mbc_lifetime;  /* recved BU lifetime */
	time_t                mbc_expire;    /* expiration time of this BC. */
	u_int8_t              mbc_state;     /* BC state */
	struct ifnet          *mbc_ifp;      /* ifp that the BC belongs to. */
	                                     /* valid only when BUF_HOME. */
	const struct encaptab *mbc_encap;    /* encapsulation from MN */
	void		      *mbc_dad;	     /* dad handler */
	time_t		      mbc_mpa_exp;   /* expiration time for sending MPA */
	                                     /* valid only when BUF_HOME. */
	struct mip6_bc        *mbc_llmbc;
	u_int32_t             mbc_refcnt;
	u_int                 mbc_brr_sent;
#if defined(__NetBSD__) || defined(__FreeBSD__)
	struct callout        mbc_timer_ch;
#elif defined(__OpenBSD__)
	struct timeout        mbc_timer_ch;
#endif
};
LIST_HEAD(mip6_bc_list, mip6_bc);

#define MIP6_IS_BC_DAD_WAIT(mbc) ((mbc)->mbc_dad != NULL)

#define MIP6_BC_FSM_STATE_BOUND  0
#define MIP6_BC_FSM_STATE_WAITB  1
#define MIP6_BC_FSM_STATE_WAITB2 2

#define MIP6_REFRESH_MINLIFETIME 2
#define MIP6_REFRESH_LIFETIME_RATE 50

/* return routability parameters. */
#define MIP6_MAX_NONCE_LIFE	240
#define MIP6_COOKIE_SIZE	8
#define MIP6_HOME_TOKEN_SIZE	8
#define MIP6_CAREOF_TOKEN_SIZE	8
#define MIP6_NONCE_SIZE		8	/* recommended by the spec (5.2.2) */
					/* must be multiple of size of u_short */
#define MIP6_NODEKEY_SIZE	20	/* This size is specified at 5.2.1 in mip6 spec */
#define MIP6_NONCE_HISTORY	10
typedef u_int8_t mip6_nonce_t[MIP6_NONCE_SIZE];
typedef u_int8_t mip6_nodekey_t[MIP6_NODEKEY_SIZE];
typedef u_int8_t mip6_cookie_t[MIP6_COOKIE_SIZE];
typedef u_int8_t mip6_home_token_t[MIP6_HOME_TOKEN_SIZE];
typedef u_int8_t mip6_careof_token_t[MIP6_CAREOF_TOKEN_SIZE];
#define MIP6_KBM_LEN		20
#define MIP6_AUTHENTICATOR_LEN	12

#define MIP6_MAX_RR_BINDING_LIFE	420

/* the binding update list entry. */
struct mip6_bu {
	LIST_ENTRY(mip6_bu) mbu_entry;
	struct in6_addr     mbu_paddr;      /* peer addr of this BU */
	struct in6_addr     mbu_haddr;      /* HoA */
	struct in6_addr     mbu_coa;        /* CoA */
	u_int16_t           mbu_lifetime;   /* BU lifetime */
	u_int16_t           mbu_refresh;    /* refresh frequency */
	u_int16_t           mbu_seqno;      /* sequence number */
	u_int16_t           mbu_flags;      /* BU flags */
	mip6_cookie_t       mbu_mobile_cookie;
	u_int16_t           mbu_home_nonce_index;
	mip6_home_token_t   mbu_home_token; /* home keygen token */
	u_int16_t           mbu_careof_nonce_index;
        mip6_careof_token_t mbu_careof_token; /* careof keygen token */
	u_int8_t            mbu_pri_fsm_state; /* primary fsm state */
	u_int8_t            mbu_sec_fsm_state; /* secondary fsm state */
	time_t              mbu_expire;     /* expiration time of this BU */
	time_t              mbu_retrans;    /* retrans/refresh timo value */
	u_int8_t            mbu_retrans_count;
	time_t              mbu_failure;    /* failure timo value */
	u_int8_t            mbu_state;      /* local status */
	struct hif_softc    *mbu_hif;       /* back pointer to hif */
	const struct encaptab *mbu_encap;
};
LIST_HEAD(mip6_bu_list, mip6_bu);

#define MIP6_BU_STATE_DISABLE     0x01
#define MIP6_BU_STATE_FIREWALLED  0x80
#define MIP6_BU_STATE_NEEDTUNNEL \
    (MIP6_BU_STATE_DISABLE | MIP6_BU_STATE_FIREWALLED)

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

/*
 * Default binding refresh interval value, when a home agent doesn't
 * specify refresh interval by binding refresh option.
 */
#define MIP6_BU_DEFAULT_REFRESH_INTERVAL(lifetime) ((lifetime) >> 2)

#define MIP6_BU_TIMEOUT_INTERVAL 1

#define MIP6_HOT_TIMEOUT 5

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

struct mip6_ha {
	TAILQ_ENTRY(mip6_ha) mha_entry;
	struct in6_addr      mha_addr ;    /* lladdr or global addr */
	u_int8_t             mha_flags;    /* RA flags */
	u_int16_t            mha_pref;     /* home agent preference */
	u_int16_t            mha_lifetime; /* router lifetime */
	time_t               mha_expire;

	time_t               mha_timeout;  /* next timeout time. */
	long                 mha_ntick;
#if defined(__NetBSD__) || defined(__FreeBSD__)
	struct callout       mha_timer_ch;
#elif defined(__OpenBSD__)
	struct timeout       mha_timer_ch;
#endif
};
TAILQ_HEAD(mip6_ha_list, mip6_ha);

struct mip6_prefix_ha {
	LIST_ENTRY(mip6_prefix_ha) mpfxha_entry;
	struct mip6_ha             *mpfxha_mha;
};

struct mip6_prefix {
	LIST_ENTRY(mip6_prefix) mpfx_entry;
	struct in6_addr         mpfx_prefix;
	u_int8_t                mpfx_prefixlen;
	u_int32_t               mpfx_vltime;
	time_t                  mpfx_vlexpire;
	u_int32_t               mpfx_pltime;
	time_t                  mpfx_plexpire;
	struct in6_addr         mpfx_haddr;
	LIST_HEAD(mip6_prefix_ha_list, mip6_prefix_ha) mpfx_ha_list;
	int                     mpfx_refcnt;

	int                     mpfx_state;
	time_t                  mpfx_timeout;
	long                    mpfx_ntick;
#if defined(__NetBSD__) || defined(__FreeBSD__)
	struct callout          mpfx_timer_ch;
#elif defined(__OpenBSD__)
	struct timeout          mpfx_timer_ch;
#endif
};
LIST_HEAD(mip6_prefix_list, mip6_prefix);
#define MIP6_PREFIX_STATE_PREFERRED 0
#define MIP6_PREFIX_STATE_EXPIRING  1

/* packet options used by the mip6 packet output processing routine. */
struct mip6_pktopts {
	struct ip6_rthdr *mip6po_rthdr2;
	struct ip6_dest *mip6po_haddr;
};

struct mip6_mobility_options {
	u_int16_t valid_options;	/* shows valid options in this structure */
	struct in6_addr mopt_altcoa;		/* Alternate CoA */
	u_int16_t	mopt_ho_nonce_idx;	/* Home Nonce Index */
	u_int16_t	mopt_co_nonce_idx;	/* Care-of Nonce Index */
	caddr_t mopt_auth;			/* Authenticator */
	u_int16_t	mopt_refresh;		/*  Refresh Interval */
};

#define MOPT_ALTCOA	0x0001
#define MOPT_NONCE_IDX	0x0002
#define MOPT_AUTHDATA	0x0004
#define MOPT_REFRESH	0x0008

#define MOPT_AUTH_LEN(mopts)	(int)(*((mopts)->mopt_auth + 1))

/*
 * configuration knobs.  defined in mip6_cncore.c.
 */
extern int mip6ctl_nodetype;
extern int mip6ctl_use_ipsec;
extern int mip6ctl_debug;
extern u_int32_t mip6ctl_bc_lifetime_limit;
extern u_int32_t mip6ctl_hrbc_lifetime_limit;
extern u_int32_t mip6ctl_bu_maxlifetime;
extern u_int32_t mip6ctl_hrbu_maxlifetime;

#define MIP6_NODETYPE_CORRESPONDENT_NODE 0
#define MIP6_NODETYPE_MOBILE_NODE 1
#define MIP6_NODETYPE_HOME_AGENT 2

#define MIP6_IS_MN (mip6ctl_nodetype == MIP6_NODETYPE_MOBILE_NODE)
#define MIP6_IS_HA (mip6ctl_nodetype == MIP6_NODETYPE_HOME_AGENT)

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
	u_quad_t mip6s_hinitcookie;	/* home init cookie mismatch */
	u_quad_t mip6s_cinitcookie;	/* careof init cookie mismatch */
	u_quad_t mip6s_unprotected;	/* not IPseced signaling */
	u_quad_t mip6s_haopolicy;	/* BU is discarded due to bad HAO */
	u_quad_t mip6s_rrauthfail;	/* RR authentication failed */
	u_quad_t mip6s_seqno;		/* seqno mismatch */
	u_quad_t mip6s_paramprobhao;	/* ICMP paramprob for HAO received */
	u_quad_t mip6s_paramprobmh;	/* ICMP paramprob for MH received */
	u_quad_t mip6s_invalidcoa;	/* Invalid Care-of address */
	u_quad_t mip6s_invalidopt;	/* Invalid mobility options */
	u_quad_t mip6s_circularrefered;	/* Circular reference */
};

#endif /* !_MIP6_VAR_H_ */

