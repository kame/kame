/*	$KAME: mip6_mncore.h,v 1.1 2003/04/23 09:15:51 keiichi Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.  All rights reserved.
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

#ifndef _MIP6_MNCORE_H_
#define _MIP6_MNCORE_H_

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
	mip6_home_token_t  mbu_home_token;  /* home keygen token */
	u_int16_t           mbu_careof_nonce_index;
        mip6_careof_token_t mbu_careof_token; /* careof keygen token */
	u_int8_t            mbu_pri_fsm_state; /* primary fsm state */
	u_int8_t            mbu_sec_fsm_state; /* secondary fsm state */
	time_t              mbu_expire;     /* expiration time of this BU */
	time_t              mbu_retrans;    /* retrans/refresh timo value */
	u_int8_t            mbu_retrans_count;
	time_t              mbu_failure;    /* failure timo value */
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

struct mip6_prefix {
	LIST_ENTRY(mip6_prefix) mpfx_entry;
	struct sockaddr_in6     mpfx_prefix;
	u_int8_t                mpfx_prefixlen;
	u_int32_t               mpfx_vltime;
	time_t                  mpfx_vlexpire;
	u_int32_t               mpfx_pltime;
	time_t                  mpfx_plexpire;
	struct sockaddr_in6     mpfx_haddr;
	u_int16_t		mpfx_mpsid;	/* Used for MPS */
	u_int8_t		mpfx_sentmps;	/* 1: sent MPS to HA with above ID */
};
LIST_HEAD(mip6_prefix_list, mip6_prefix);

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

/* buffer for storing a consequtive sequence of sub-options. */
struct mip6_buffer {
	int      off;  /* Offset in buffer */
	u_int8_t *buf; /* Must be at least IPV6_MMTU */
};
#define MIP6_BUFFER_SIZE 1500 /* XXX 1500 ? */

#define IP6OPT_HALEN  16 /* Length of HA option */

#ifdef _KERNEL

extern struct mip6_ha_list mip6_ha_list;
extern struct mip6_prefix_list mip6_prefix_list;
extern struct mip6_subnet_list mip6_subnet_list;
extern struct mip6_unuse_hoa_list mip6_unuse_hoa;
extern struct mip6_preferred_ifnames mip6_preferred_ifnames;

/* Mobile IPv6 mobile node functions. */
/* initialization. */
void mip6_mn_init(void);
void mip6_bu_init(void);
void mip6_halist_init(void);
void mip6_prefix_init(void);
void mip6_subnet_init(void);

/* movement processing. */
int mip6_prelist_update(struct sockaddr_in6 *, union nd_opts *,
    struct nd_defrouter *, struct mbuf *);
void mip6_probe_routers(void);
int mip6_process_movement(void);
int mip6_process_pfxlist_status_change(struct sockaddr_in6 *);
int mip6_select_coa2(void);
int mip6_detach_haddrs(struct hif_softc *);
int mip6_ifa_need_dad(struct in6_ifaddr *);
int mip6_route_optimize(struct mbuf *);

/* binding update entry processing. */
int mip6_bu_list_remove_all(struct mip6_bu_list *, int);
struct mip6_bu *mip6_bu_list_find_home_registration(struct mip6_bu_list *,
    struct sockaddr_in6 *);
struct mip6_bu *mip6_bu_list_find_withpaddr(struct mip6_bu_list *,
    struct sockaddr_in6 *, struct sockaddr_in6 *);
int mip6_home_registration2(struct mip6_bu *);
int mip6_bu_encapcheck(const struct mbuf *, int, int, void *);
int mip6_bu_fsm(struct mip6_bu *, int, void *);
int mip6_bu_send_hoti(struct mip6_bu *);
int mip6_bu_send_coti(struct mip6_bu *);
int mip6_bu_send_bu(struct mip6_bu *);
int mip6_bu_send_cbu(struct mip6_bu *);

/* home agent list processing. */
struct mip6_ha *mip6_ha_create(struct sockaddr_in6 *, struct sockaddr_in6 *,
    u_int8_t, int16_t, int32_t);
int mip6_ha_list_insert(struct mip6_ha_list *, struct mip6_ha *mha);
int mip6_ha_list_remove(struct mip6_ha_list*, struct mip6_ha *mha);
struct mip6_ha *mip6_ha_list_find_withaddr(struct mip6_ha_list *,
    struct sockaddr_in6 *);
int mip6_ha_list_update_hainfo(struct mip6_ha_list *, struct nd_defrouter *,
    struct nd_opt_homeagent_info *);
int mip6_ha_list_update_withndpr(struct mip6_ha_list *, struct sockaddr_in6 *,
    struct nd_prefix *);
int mip6_ha_list_update_gaddr(struct mip6_ha_list*, struct sockaddr_in6 *,
    struct sockaddr_in6 *);

/* prefix list processing. */
struct mip6_prefix *mip6_prefix_create(struct sockaddr_in6 *, u_int8_t,
    u_int32_t, u_int32_t);
int mip6_prefix_list_insert(struct mip6_prefix_list *, struct mip6_prefix *);
int mip6_prefix_list_remove(struct mip6_prefix_list *,
    struct mip6_prefix *mpfx);
struct mip6_prefix *mip6_prefix_list_find(struct mip6_prefix *);
int mip6_prefix_haddr_assign(struct mip6_prefix *, struct hif_softc *);

/* subnet list processing. */
struct mip6_subnet *mip6_subnet_create(void);
int mip6_subnet_delete(struct mip6_subnet *);
int mip6_subnet_list_insert(struct mip6_subnet_list *, struct mip6_subnet *);
int mip6_subnet_list_remove(struct mip6_subnet_list *, struct mip6_subnet *);
struct mip6_subnet *mip6_subnet_list_find_withprefix(struct mip6_subnet_list *,
    struct sockaddr_in6 *, u_int8_t);
struct mip6_subnet *mip6_subnet_list_find_withhaaddr(struct mip6_subnet_list *,
    struct sockaddr_in6 *);
struct mip6_subnet *mip6_subnet_list_find_withmpfx(struct mip6_subnet_list *,
    struct mip6_prefix *);

/* subnet_ha list processing. */
struct mip6_subnet_ha *mip6_subnet_ha_create(struct mip6_ha *);
int mip6_subnet_ha_list_insert(struct mip6_subnet_ha_list *,
    struct mip6_subnet_ha *);
struct mip6_subnet_ha *mip6_subnet_ha_list_find_preferable(
    struct mip6_subnet_ha_list *);
struct mip6_subnet_ha *mip6_subnet_ha_list_find_withmha(
    struct mip6_subnet_ha_list *, struct mip6_ha *);
struct mip6_subnet_ha *mip6_subnet_ha_list_find_withhaaddr(
    struct mip6_subnet_ha_list *, struct sockaddr_in6 *haaddr);

/* subnet_prefix list processing. */
struct mip6_subnet_prefix *mip6_subnet_prefix_create(struct mip6_prefix *);
int mip6_subnet_prefix_list_insert(struct mip6_subnet_prefix_list *,
    struct mip6_subnet_prefix *);
int mip6_subnet_prefix_list_remove(struct mip6_subnet_prefix_list *,
    struct mip6_subnet_prefix *);
struct mip6_subnet_prefix *mip6_subnet_prefix_list_find_withprefix(
    struct mip6_subnet_prefix_list *, struct sockaddr_in6 *, u_int8_t);
struct mip6_subnet_prefix *mip6_subnet_prefix_list_find_withmpfx(
    struct mip6_subnet_prefix_list *, struct mip6_prefix *mpfx);
struct mip6_prefix *mip6_prefix_list_find_withhaddr(struct mip6_prefix_list *,
    struct sockaddr_in6 *haddr);
int32_t mip6_subnet_prefix_list_get_minimum_lifetime(
    struct mip6_subnet_prefix_list *);

/* IPv6 extention header processing. */
int mip6_haddr_destopt_create(struct ip6_dest **, struct sockaddr_in6 *,
    struct sockaddr_in6 *, struct hif_softc *);
int mip6_addr_exchange(struct mbuf *, struct mbuf *);

/* Mobility Header processing. */
int mip6_ip6mh_input(struct mbuf *, struct ip6m_home_test *, int);
int mip6_ip6mc_input(struct mbuf *, struct ip6m_careof_test *, int);
int mip6_ip6ma_input(struct mbuf *, struct ip6m_binding_ack *, int);
int mip6_ip6me_input(struct mbuf *, struct ip6m_binding_error *, int);
int mip6_ip6mhi_create(struct ip6_mobility **, struct mip6_bu *);
int mip6_ip6mci_create(struct ip6_mobility **, struct mip6_bu *);
int mip6_ip6mu_create(struct ip6_mobility **, struct sockaddr_in6 *,
    struct sockaddr_in6 *, struct hif_softc *);

/* ICMPv6 processing. */
int mip6_icmp6_input(struct mbuf *, int, int);
int mip6_icmp6_dhaad_req_output(struct hif_softc *);
int mip6_icmp6_mp_sol_output(struct mip6_prefix *, struct mip6_ha *);

#ifdef MIP6_DEBUG
void mip6_bu_print(struct mip6_bu *);
#endif /* MIP6_DEBUG */
void mip6_ha_print(struct mip6_ha *);
#endif /* _KERNEL */

#endif /* _MIP6_MNCORE_H_ */
