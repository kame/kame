/*	$KAME: mip6_var.h,v 1.28 2002/03/01 09:37:38 keiichi Exp $	*/

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

#ifdef MIP6_DRAFT13
#define MIP6_SEQNO_T u_int16_t
#else
#define MIP6_SEQNO_T u_int8_t
#endif /* MIP6_DRAFT13 */

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
	struct sockaddr_in6 mbu_haddr;      /* home address */
	struct sockaddr_in6 mbu_coa;        /* COA */
	u_int32_t           mbu_lifetime;   /* BU lifetime */
	time_t              mbu_expire;     /* expiration time of this BU. */
	u_int32_t           mbu_refresh;    /* refresh frequency */
	time_t              mbu_refexpire;  /* expiration time of refresh. */
	u_int32_t           mbu_acktimeout; /* current ack timo value */
	time_t              mbu_ackexpire;  /* expiration time of ack. */
	MIP6_SEQNO_T        mbu_seqno;      /* sequence number */
	u_int8_t            mbu_flags;      /* BU flags */
	u_int8_t            mbu_state;
	u_int8_t            mbu_reg_state;  /* registration status */
	struct hif_softc    *mbu_hif;       /* back pointer to hif */
	const struct encaptab *mbu_encap;
};
#define MIP6_BU_REG_STATE_NOTREG       0x01
#define MIP6_BU_REG_STATE_REGWAITACK   0x02
#define MIP6_BU_REG_STATE_REG          0x03
#define MIP6_BU_REG_STATE_DEREGWAITACK 0x04

#define MIP6_BU_STATE_WAITSENT    0x01
#define MIP6_BU_STATE_WAITACK     0x02
#define MIP6_BU_STATE_BUNOTSUPP   0x04
#define MIP6_BU_STATE_MIP6NOTSUPP 0x80

#define MIP6_BU_TIMEOUT_INTERVAL 1
#define MIP6_BU_SAWAIT_INTERVAL 4

/* the binding cache entry. */
struct mip6_bc {
	LIST_ENTRY(mip6_bc)   mbc_entry;
	struct sockaddr_in6   mbc_phaddr;    /* peer home address */
	struct sockaddr_in6   mbc_pcoa;      /* peer coa */
	struct sockaddr_in6   mbc_addr;      /* my addr (needed?) */
	u_int8_t              mbc_status;    /* BA statue */
	u_int8_t              mbc_flags;     /* recved BU flags */
#ifdef MIP6_DRAFT13
	u_int8_t              mbc_prefixlen; /* recved BU prefixlen */
#endif /* MIP6_DRAFT13 */
	MIP6_SEQNO_T          mbc_seqno;     /* recved BU seqno */
	u_int32_t             mbc_lifetime;  /* recved BU lifetime */
	time_t                mbc_expire;    /* expiration time of this BC. */
	u_int8_t              mbc_state;     /* BC state */
	struct ifnet          *mbc_ifp;      /* ifp that the BC belongs to. */
	                                     /* valid only when BUF_HOME. */
	const struct encaptab *mbc_encap;    /* encapsulation from MN */
	void		      *mbc_dad;	     /* dad handler */
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

#ifdef MIP6_DRAFT13
/* Macro for modulo 2^^16 comparison */
#define MIP6_LEQ(a,b)   ((int16_t)((a)-(b)) <= 0)
#else
/* Macro for modulo 2^^8 comparison */
#define MIP6_LEQ(a,b)   ((int8_t)((a)-(b)) <= 0)
#endif /* MIP6_DRAFT13 */

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
	struct ip6_rthdr *mip6po_rthdr;
	struct ip6_dest *mip6po_haddr;
	struct ip6_dest *mip6po_dest2;
};

/* buffer for storing a consequtive sequence of sub-options. */
struct mip6_buffer {
	int      off;  /* Offset in buffer */
	u_int8_t *buf; /* Must be at least IPV6_MMTU */
};
#define MIP6_BUFFER_SIZE 1500 /* XXX 1500 ? */

/* definition of length for different destination options. */
#define IP6OPT_BULEN   8 /* Length of BU option */
#define IP6OPT_BALEN  11 /* Length of BA option */
#define IP6OPT_BRLEN   0 /* Length of BR option */
#define IP6OPT_HALEN  16 /* Length of HA option */
#define IP6OPT_UIDLEN  2 /* Length of Unique Identifier sub-option */
#define IP6OPT_COALEN 16 /* Length of Alternate COA sub-option */
#define IP6OPT_AUTHDATALEN 4 /* Minimum length of Authentication Data sub-option */

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

#ifdef _KERNEL
struct encaptab;

extern struct mip6_config mip6_config;
extern struct mip6_ha_list mip6_ha_list; /* Global val holding all HAs */

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
int mip6_ba_destopt_create		 __P((struct ip6_dest **,
					      struct sockaddr_in6 *,
					      struct sockaddr_in6 *,
					      u_int8_t,
					      MIP6_SEQNO_T,
					      u_int32_t,
					      u_int32_t));
int mip6_rthdr_create			__P((struct ip6_rthdr **,
					     struct sockaddr_in6 *,
					     struct ip6_pktopts *));
void mip6_destopt_discard		__P((struct mip6_pktopts *));
int mip6_addr_exchange			__P((struct mbuf *,
					     struct mbuf *));
int mip6_process_destopt		__P((struct mbuf *,
					     struct ip6_dest *,
					     u_int8_t *, int));
u_int8_t *mip6_destopt_find_subopt	__P((u_int8_t *,
					     u_int8_t, u_int8_t));
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
int mip6_icmp6_ha_discov_req_output	__P((struct hif_softc *));
int mip6_icmp6_mp_sol_output		__P((struct mip6_prefix *,
					     struct mip6_ha *));
#if 0
int mip6_tunneled_rs_output		__P((struct hif_softc *,
					     struct mip6_pfx *));
#endif

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
int mip6_bu_list_remove_all		__P((struct mip6_bu_list *));
struct mip6_bu *mip6_bu_list_find_withpaddr
					__P((struct mip6_bu_list *,
					     struct sockaddr_in6 *,
					     struct sockaddr_in6 *));
struct mip6_bu *mip6_bu_list_find_home_registration
					__P((struct mip6_bu_list *,
					     struct sockaddr_in6 *));
int mip6_home_registration		__P((struct hif_softc *));
int mip6_validate_bu			__P((struct mbuf *, u_int8_t *));
int mip6_process_bu			__P((struct mbuf *, u_int8_t *));

/* binding ack management */
int mip6_validate_ba			__P((struct mbuf *, u_int8_t *));
int mip6_process_ba			__P((struct mbuf *, u_int8_t *));

/* binding request management */
int mip6_validate_br			__P((struct mbuf *, u_int8_t *));
int mip6_process_br			__P((struct mbuf *, u_int8_t *));

/* binding cache management */
void mip6_bc_init			__P((void));
int mip6_bc_list_remove			__P((struct mip6_bc_list *,
					     struct mip6_bc *));
struct mip6_bc *mip6_bc_list_find_withphaddr
					__P((struct mip6_bc_list *,
					     struct sockaddr_in6 *));
struct mip6_bc *mip6_bc_list_find_withpcoa
					__P((struct mip6_bc_list *,
					     struct sockaddr_in6 *));
#if defined(IPSEC) && !defined(__OpenBSD__)
#ifndef MIP6_DRAFT13
struct secasvar;
struct mip6_subopt_authdata *mip6_authdata_create
					__P((struct secasvar *));
int mip6_bu_authdata_calc __P((struct secasvar *,
			       struct in6_addr *,
			       struct in6_addr *,
			       struct in6_addr *,
			       struct ip6_opt_binding_update *,
			       struct mip6_subopt_authdata *,
			       caddr_t));
int mip6_ba_authdata_calc __P((struct secasvar *,
			       struct in6_addr *,
			       struct in6_addr *,
			       struct ip6_opt_binding_ack *,
			       struct mip6_subopt_authdata *,
			       caddr_t));
#endif /* !MIP6_DRAFT13 */
#endif /* IPSEC && !__OpenBSD__ */

int mip6_dad_success			__P((struct ifaddr *));
int mip6_dad_duplicated			__P((struct ifaddr *));
struct ifaddr *mip6_dad_find		__P((struct in6_addr *, struct ifnet *));

#define mip6log(arg) do { if (mip6_config.mcfg_debug) log arg;} while (0)
void mip6_ha_print __P((struct mip6_ha *));

int mip6_setpktaddrs __P((struct mbuf *));
#endif /* _KERNEL */

#endif /* !_MIP6_VAR_H_ */
