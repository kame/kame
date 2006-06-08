/*	$KAME: shisad.h,v 1.37 2006/06/08 12:02:00 keiichi Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#ifndef _SHISAD_SHISAD_H_
#define _SHISAD_SHISAD_H_

extern struct mip6_mninfo mninfo;
extern int mipsock, mhsock, icmp6sock;
#ifdef DSMIP
extern int udp4sock;
extern int raw4sock;
#endif
extern struct mip6stat mip6stat;
extern struct mip6_hinfo_list hoa_head;

/* protocol constants. */
#define DHAAD_RETRIES		4
#define MAX_BINDACK_TIMEOUT	32
#define INITIAL_DHAAD_TIMEOUT	3
#define INITIAL_BINDACK_TIMEOUT	1

#define MAX_DHAAD_TIMEOUT	(INITIAL_DHAAD_TIMEOUT << DHAAD_RETRIES)
#define INITIAL_HOTI_COTI_TIMEOUT	1
#define MAX_HOTI_COTI_TIMEOUT		32

/* protocol configuration variables. */
extern int initial_bindack_timeout_first_reg_count;

/* return routability parameters. */
#define MIP6_MAX_TOKEN_LIFE	210
#define MIP6_MAX_NONCE_LIFE	240
#define MIP6_COOKIE_SIZE	8
#define MIP6_TOKEN_SIZE		8
#define MIP6_NONCE_SIZE		8       /* recommended by the spec (5.2.2) */
					/* must be multiple of size of u_short */
#define MIP6_NODEKEY_SIZE	20      /* This size is specified at 5.2.1 in mip6 spec */
#define MIP6_NONCE_HISTORY	10
#define MIP6_NONCE_REFRESH	60
#define MIP6_BRR_INTERVAL	3
#define MIP6_KBM_SIZE		20
#define MIP6_AUTHENTICATOR_SIZE	12
#define MIP6_MAX_RR_BINDING_LIFE	420
#define MIP6_DEFAULT_BINDING_LIFE	10
#define MIP6_HOAOPT_PADLEN 4 /* length of Padding for HoA destination option */

typedef u_int8_t mip6_nonce_t[MIP6_NONCE_SIZE];
typedef u_int8_t mip6_nodekey_t[MIP6_NODEKEY_SIZE];
typedef u_int8_t mip6_cookie_t[MIP6_COOKIE_SIZE];
typedef u_int8_t mip6_token_t[MIP6_TOKEN_SIZE];
typedef u_int8_t mip6_kbm_t[MIP6_KBM_SIZE];
typedef u_int8_t mip6_authenticator_t[MIP6_AUTHENTICATOR_SIZE];

/* Macro for modulo 2^^16 comparison */
#define MIP6_LEQ(a,b)   ((int16_t)((a)-(b)) <= 0)

#define TIMESUB(a,b) ((a)->tv_sec - (b)->tv_sec)

/* Calculation pad length to be appended */
/* xn + y; x must be 2^m */
#define MIP6_PADLEN(cur_offset, x, y)	\
	((((x) + (y)) - ((cur_offset) & ((x) - 1))) & ((x) - 1))
#define MIP6_FILL_PADDING(buf, padlen)			\
	do {						\
		bzero((buf), (padlen));			\
	 	if ((padlen) > 1) {			\
			(buf)[0] = IP6OPT_PADN;		\
			(buf)[1] = (padlen) - 2;	\
		}					\
	} while (/*CONSTCOND*/ 0)

#define CND_COMMAND_PORT	7777
#define MND_COMMAND_PORT	7778
#define MRD_COMMAND_PORT	7778
#define HAD_COMMAND_PORT	7778

#define CND_PIDFILE	"/var/run/cnd.pid"
#define MND_PIDFILE	"/var/run/mnd.pid"
#define MRD_PIDFILE	"/var/run/mrd.pid"
#define HAD_PIDFILE	"/var/run/had.pid"

#ifndef SYSCONFDIR
#define SYSCONFDIR	"/usr/local/v6/etc"
#endif
#define CND_CONFFILE	SYSCONFDIR "/shisa/cnd.conf"
#define MND_CONFFILE	SYSCONFDIR "/shisa/mnd.conf"
#define MRD_CONFFILE	SYSCONFDIR "/shisa/mrd.conf"
#define HAD_CONFFILE	SYSCONFDIR "/shisa/had.conf"

#define MND_NORO_FILE 	"/etc/ro.deny"

/*
 * homeprefix_info -> homeprefix_info -> ...
 *      |
 *      +-ha_list -> ha_list -> ...
 */
struct home_agent_list {
	LIST_ENTRY(home_agent_list) hal_entry;

	/* common for mobile node and home agent */
        struct in6_addr hal_lladdr;  /* Link-local address of HA */
        struct in6_addr hal_ip6addr; /* global IPv6 address of HA */

	int             hal_flag;
#define MIP6_HAL_OWN    0x01
#define MIP6_HAL_STATIC 0x02
#define MIP6_HAL_RA	0x04

	/* HA exclusive field: it is used when ha receives RA */
	struct mip6_halist_ha_exclusive {
		u_int16_t halist_lifetime;   /* Remaining lifetime */
		u_int16_t halist_preference; /* Preference for this HA */
	} hal_for_ha;
#define hal_lifetime hal_for_ha.halist_lifetime
#define hal_preference hal_for_ha.halist_preference

        CALLOUT_HANDLE        hal_expire;   /* callout handle for expiration */
};
LIST_HEAD(home_agent_list_head, home_agent_list);

struct mip6_hpfxl {
	LIST_ENTRY(mip6_hpfxl) hpfx_entry;
	
	/* common for mobile node and home agent */
	struct in6_addr     hpfx_prefix;     /* home prefix (may
                                                contail full IPv6
                                                address) */
	u_int8_t            hpfx_prefixlen;  /* home prefix length */
	u_int8_t	    hpfx_flags;
	struct home_agent_list_head hpfx_hal_head;   /* home agent list head */

	struct mip6_mipif   *hpfx_mipif;
	/* mn exclusive field: it is used when mn receives MPA */
	struct mip6_hpfx_mn_exclusive {
		u_int32_t hpfxlist_vltime;
		time_t    hpfxlist_vlexpire;
		u_int32_t hpfxlist_pltime;
		time_t    hpfxlist_plexpire;
		time_t    hpfxlist_timeout;      /* expiration time */
		CALLOUT_HANDLE hpfxlist_retrans; /* callout handle for
                                                    retrans */
	} hpfx_for_mn;
#define hpfx_vltime   hpfx_for_mn.hpfxlist_vltime
#define hpfx_vlexpire hpfx_for_mn.hpfxlist_vlexpire
#define hpfx_pltime   hpfx_for_mn.hpfxlist_pltime
#define hpfx_plexpire hpfx_for_mn.hpfxlist_plexpire
#define hpfx_timeout  hpfx_for_mn.hpfxlist_timeout
#define hpfx_retrans  hpfx_for_mn.hpfxlist_retrans
};
LIST_HEAD(mip6_hpfx_list, mip6_hpfxl);

/* mip6_nonce_addrs structure is chained from mip6_nonces_info
 */
struct binding_cache;
struct mip6_nonce_blockedbce {
	LIST_ENTRY(mip6_nonce_blockedbce)	nb_entry;
	struct binding_cache	*nb_bc;
};

/* For Correspondent Node */
struct mip6_nonces_info {
	struct mip6_nonces_info *next, *prev;
	u_int16_t nonce_index;
	u_int8_t  nonce[MIP6_NONCE_SIZE];
	u_int8_t  node_key[MIP6_NODEKEY_SIZE];
	time_t	  nonce_lasttime; /*  generated time */
	LIST_HEAD(, mip6_nonce_blockedbce) nb_head;
};

/*
 * Per Home Address 
 *  hoa_info: Home Address Information
 *    +- bul: Binding Update List
 *
 * Per Home Link 
 *  mip_if: Virtual IF information
 *    +- hpfx: Home Prefix List
 *        +- hal: Home Agent List
 *
 * hoa_info ---> hoa_info -> hoa_info.. 
 *    +      
 *    +--bul -> bul -> bul..
 *    |
 *    +--mpfx -> mpfx -> mpfx.. (NEMO only)
 *
 * mip_if -> mip_if -> mip_if..
 *   +
 *   +-- hpfx -> hpfx -> hpfx..
 *        +-- hal -> hal -> hal..
 */
LIST_HEAD(binding_update_list_head, binding_update_list);
struct binding_update_list {
	LIST_ENTRY(binding_update_list) bul_entry;
	struct in6_addr     bul_peeraddr;   /* peer addr of this BU */
	struct in6_addr     bul_coa;        /* CoA */
	u_int16_t           bul_lifetime;   /* BU lifetime */
	u_int16_t           bul_refresh;    /* refresh frequency */
	u_int16_t           bul_seqno;      /* sequence number */
	u_int16_t           bul_flags;      /* BU flags */

	/* The last time when mn sent the BU */
	time_t		    bul_bu_lastsent;

	mip6_cookie_t       bul_home_cookie;
	u_int16_t           bul_home_nonce_index;
	mip6_token_t        bul_home_token;   /* home keygen token */

	mip6_cookie_t       bul_careof_cookie;
	u_int16_t           bul_careof_nonce_index;
	mip6_token_t        bul_careof_token; /* careof keygen token */

	struct mip6_hoainfo *bul_hoainfo; /* backpointer to hoa_info */
	int                 bul_home_ifindex; /* ifindex of home network */

	u_int8_t            bul_reg_fsm_state;/* registration state */
	u_int8_t            bul_rr_fsm_state; /* rr state */

	CALLOUT_HANDLE      bul_retrans;      /* callout handle for retrans */
	u_int8_t            bul_retrans_time;
	CALLOUT_HANDLE      bul_expire;       /* callout handle for failure */
	u_int8_t            bul_state;        /* local status */

#ifdef MIP_MCOA
	u_int16_t           bul_bid;          /* Binding Unique Identifier */
	struct binding_update_list_head bul_mcoa_head;
#endif /* MIP_MCOA */
#ifdef DSMIP
	struct in_addr      bul_v4hoa;
#endif /* DSMIP */
};

#define MIP6_BUL_STATE_DISABLE    0x01

/* 
 * it contains host information for which mnd does not run Route
 * Opitimization (such as RR)
 */
struct noro_host_list { 
	LIST_ENTRY(noro_host_list) noro_entry;
	struct in6_addr noro_host;
	int  prefixlen; /* currently not supported yet */
};
LIST_HEAD(no_ro_head, noro_host_list);

#ifdef MIP_NEMO
/* NEMO Prefix Table */
struct nemo_pt {
	struct sockaddr_storage pt_ss_prefix;  /* mobile network prefix */
	u_int8_t                pt_prefixlen;  /* mobile network prefix len */
	int                     pt_regmode;    /* Registration mode */
#define NEMO_IMPLICIT 0x01         /* Implicit mode */ 
#define NEMO_EXPLICIT 0x02         /* Explicit mode */ 
#define NEMO_ROUTING  0x03         /* no plan to support this */
};

/* NEMO Prefix Table of Home Agent */
struct nemo_hptable {
	LIST_ENTRY(nemo_hptable) hpt_entry;
	
	struct nemo_pt      hpt;
	struct in6_addr     hpt_hoa;        /* home address of MR */
};
#define hpt_ss_prefix hpt.pt_ss_prefix
#define hpt_prefixlen hpt.pt_prefixlen
#define hpt_regmode   hpt.pt_regmode
LIST_HEAD(nemo_hpt_list, nemo_hptable);
extern struct nemo_hpt_list hpt_head;

/* NEMO Mobile Network Prefix Entries (Prefix Table of Mobile Router) */
struct nemo_mptable {
	LIST_ENTRY(nemo_mptable) mpt_entry;
	
	struct nemo_pt      mpt;
	struct mip6_hoainfo *mpt_hoainfo;   /* backpointer to hoa_info */
	struct in6_addr      mpt_ha;        /* HA address (if 0 then HAAD) */

	/* xxx lifetime etc?! */
};
#define mpt_ss_prefix mpt.pt_ss_prefix
#define mpt_prefixlen mpt.pt_prefixlen
#define mpt_regmode   mpt.pt_regmode
LIST_HEAD(nemo_mpt_list, nemo_mptable);
#endif /* MIP_NEMO */

/* Home Address information (each HoA related info) */
struct mip6_hoainfo {
	LIST_ENTRY(mip6_hoainfo) hinfo_entry;

	struct in6_addr hinfo_hoa; /* Home Address */
	struct in_addr  hinfo_v4hoa; /* Home Address */

	/* if_index of mip virtual interface where HoA is assigned */
	u_int16_t hinfo_ifindex;
	u_int8_t  hinfo_location;   /* Location where mn is located */   

        u_int16_t hinfo_dhaad_id;      
	time_t    hinfo_dhaad_lastsent;
        u_int16_t hinfo_mps_id;
	time_t    hinfo_mps_lastsent;

	struct binding_update_list_head hinfo_bul_head; 	/* Binding Update List */
#ifdef MIP_NEMO
	struct nemo_mpt_list hinfo_mpt_head; 	/* Mobile Network Prefix */
#endif /* MIP_NEMO */
};
LIST_HEAD(mip6_hinfo_list, mip6_hoainfo);

#define MNINFO_MN_UNKNOWN 0x00
#define MNINFO_MN_HOME    0x01
#define MNINFO_MN_FOREIGN 0x02


/* MIP Virtual Interface Information (each Home Link info) */
struct mip6_mipif {
        LIST_ENTRY(mip6_mipif) mipif_entry;

	struct mip6_hpfx_list mipif_hprefx_head;

	u_int16_t mipif_ifindex;

	u_int16_t mipif_mps_id;
	time_t    mipif_mps_lastsent;

	/* will be added later */
};
LIST_HEAD(mip6_mipif_list, mip6_mipif);

/* Parsing MH options */
struct mip6_mobility_options {
	struct ip6_mh_opt_refresh_advice *opt_refresh;
	struct ip6_mh_opt_altcoa *opt_altcoa;
	struct ip6_mh_opt_nonce_index *opt_nonce;
	struct ip6_mh_opt_auth_data *opt_auth;

#ifdef MIP_NEMO
#define NEMO_MAX_ALLOW_PREFIX 10
	struct ip6_mh_opt_prefix *opt_prefix[NEMO_MAX_ALLOW_PREFIX];
	int opt_prefix_count;
#endif /* MIP_NEMO */
#ifdef MIP_MCOA
	struct ip6_mh_opt_bid *opt_bid;
#endif /* MIP_MCOA */
#ifdef DSMIP
	struct ip6_mh_opt_ipv4_hoa *opt_v4hoa;
#endif /* DSMIP */
};

/* Binding Cache */
struct binding_cache {
        LIST_ENTRY(binding_cache) bc_entry;
        struct in6_addr       bc_hoa;       /* peer home address */
        struct in6_addr       bc_coa;       /* peer coa */
	struct in6_addr       bc_realcoa;
        struct in6_addr       bc_myaddr;    /* my addr */
        u_int8_t              bc_state;     /* state of this bce */
#define BC_STATE_VALID		0
#define BC_STATE_DEPRECATED	1
#define BC_STATE_UNDER_DAD	2
#define BC_STATE_MAX		2
        u_int16_t             bc_flags;     /* recved BU flags */
        u_int16_t             bc_seqno;     /* recved BU seqno */
        u_int32_t             bc_lifetime;  /* recved BU lifetime */

        time_t                bc_expire;    /* expiration time of this BC. */
        CALLOUT_HANDLE        bc_refresh;   /* callout handle for retrans */
        u_int8_t              bc_refresh_count;
	u_int8_t	      bc_authmethod;
#define BC_AUTH_NONE		0
#define BC_AUTH_IPSEC		1
#define BC_AUTH_RR		2

	/* valid only when BUF_HOME */
        void                  *bc_dad;      /* dad handler */
        time_t                bc_mpa_exp;   /* expiration time for MPA */
        struct binding_cache *bc_llmbc;
	struct binding_cache *bc_glmbc;
        u_int32_t             bc_refcnt;
        u_int                 bc_brr_sent;
#ifdef MIP_MCOA
	u_int16_t             bc_bid; /* Binding Unique Identifier */
#endif /* MIP_MCOA */
};
LIST_HEAD(binding_cache_head, binding_cache);

struct nd6options {
	struct nd_opt_prefix_info *ndpi_start, *ndpi_end;	/* could be multiple */
	struct nd_opt_adv_interval *ndadvi;
	struct nd_opt_homeagent_info *ndhai;
};
extern struct nd6options ndopts;
extern int debug, namelookup;

/* mh.c */
void mhsock_open(void);
void mhsock_close(void);
int  mh_input_common(int);
int  get_mobility_options(struct ip6_mh *, int, int, 
			 struct mip6_mobility_options *);
int  in6_mask2len(struct in6_addr *, u_char *);
int  mh_input(struct in6_addr *, struct in6_addr *, 
   struct in6_addr *, struct in6_addr *, struct ip6_mh *, int);
#ifdef MIP_MCOA
int  get_bid_option(struct ip6_mh *, int, int);
#endif /* MIP_MCOA */
int  send_brr(struct in6_addr *, struct in6_addr *);
int  send_hoti(struct binding_update_list *);
int  send_coti(struct binding_update_list *);
int  send_bu(struct binding_update_list *);
int  send_be(struct in6_addr *, struct in6_addr *, 
	    struct in6_addr *, u_int8_t);
int  send_hot(struct ip6_mh_home_test_init *, struct in6_addr *, 
	     struct in6_addr *);
int  send_cot(struct ip6_mh_careof_test_init *, struct in6_addr *, 
	     struct in6_addr *);
int  send_ba(struct in6_addr *, struct in6_addr *, struct in6_addr *, struct in6_addr *, 
	    u_int16_t, mip6_kbm_t *, u_int8_t, u_int16_t, u_int16_t, int, u_int16_t);
int send_mps(struct mip6_hpfxl *);

/* rr.c */
void mip6_calculate_kbm(mip6_token_t *, mip6_token_t *, mip6_kbm_t *);
void mip6_calculate_authenticator(mip6_kbm_t *, struct in6_addr *, 
    struct in6_addr *, caddr_t, size_t, int, size_t, mip6_authenticator_t *);
struct mip6_nonces_info *get_nonces(u_int16_t);
struct mip6_nonces_info * generate_nonces(struct mip6_nonces_info *);
void init_nonces (void);
void create_keygentoken(struct in6_addr *, struct mip6_nonces_info *, 
			u_int8_t *, u_int8_t);
void retain_bc_to_nonce(struct mip6_nonces_info *, struct binding_cache *);
int check_nonce_reuse(struct mip6_nonces_info *, struct in6_addr *, struct in6_addr *);

/* binding.c */
struct binding_update_list *bul_get(struct in6_addr *, struct in6_addr *);
struct binding_update_list *bul_insert(struct mip6_hoainfo *,  struct in6_addr *, struct in6_addr *, u_int16_t, u_int16_t);
int bul_check_ifid(struct mip6_hoainfo *);
#ifdef MIP_MCOA
struct binding_update_list *bul_mcoa_get(struct in6_addr *, struct in6_addr *, u_int16_t);
#endif /* MIP_MCOA */
void bul_remove(struct binding_update_list *);
struct binding_update_list *bul_get_nohoa(char *, struct in6_addr *, struct in6_addr *);
struct binding_update_list *bul_get_homeflag(struct in6_addr *);

struct mip6_hoainfo *hoainfo_find_withhoa(struct in6_addr *);
struct mip6_hoainfo *hoainfo_insert(struct in6_addr *, u_int16_t); 
int hoainfo_remove(struct in6_addr *);
struct mip6_hoainfo *hoainfo_get_withdhaadid (u_int16_t);
void mip6_bc_init(void);
void mip6_flush_kernel_bc(void);
void mip6_bc_delete(struct binding_cache *);
void mip6_bc_refresh_timer(void *);
void mipsock_bc_request(struct binding_cache *, u_char);
void mip6_dad_order(int, struct in6_addr *);
#define mip6_dad_start(addr)	mip6_dad_order(MIPM_DAD_DO, addr)
#define mip6_dad_stop(addr)	mip6_dad_order(MIPM_DAD_STOP, addr)
void mip6_dad_done(int, struct in6_addr *);
void command_show_bc(int, char *);
void command_show_kbc(int, char *);

void command_show_bul(int, char *);
void command_show_kbul(int, char *);
struct binding_cache *mip6_bc_lookup(struct in6_addr *, struct in6_addr *, 
    u_int16_t);
struct binding_cache *mip6_bc_add(struct in6_addr *, struct in6_addr *, 
    struct in6_addr *, u_int32_t, u_int16_t, u_int16_t, u_int16_t, u_int8_t);

/* network.c */
int set_ip6addr(char *, struct in6_addr *, int, int);
int delete_ip6addr(char *, struct in6_addr *, int);
int send_unsolicited_na(int, struct in6_addr *);

#ifdef MIP_NEMO
int nemo_tun_set(struct sockaddr *, struct sockaddr *, u_int16_t, int);
int nemo_tun_del(char *);
int route_add(struct sockaddr *, struct sockaddr *, struct sockaddr *, int,
    u_int16_t);
int route_del(u_int16_t);
u_int16_t  get_ifindex_from_address(struct in6_addr *);
struct sockaddr_in6 *nemo_ar_get(struct in6_addr *coa, 
				 struct sockaddr_in6 *);
int nemo_gif_ar_set(char *, struct in6_addr *);
int nemo_ifflag_set(char *, short); 
int nemo_ifflag_get(char *);
#endif /* MIP_NEMO */

/* common.c */
struct mip_msghdr;
int  mipsock_input_common(int);
void mipsock_open(void);
int  mipsock_nodetype_request(u_int8_t, u_int8_t);
int mipsock_behint_input(struct mip_msghdr *);
void icmp6sock_open(void);
#ifdef DSMIP
int  udp4_input_common(int);
void udp4sock_open(void);
void raw4sock_open(void);
#endif
int  icmp6_input_common(int);
int mip6_get_nd6options(struct nd6options *, char *, int);
void mip6_create_addr(struct in6_addr *, const struct in6_addr *, 
		      struct in6_addr *, u_int8_t);
void hal_set_expire_timer(struct home_agent_list *, int);
void hal_stop_expire_timer(struct home_agent_list *);
void command_show_stat(int, char *);
struct ip6_hdr;
struct ip6_rthdr2 *find_rthdr2(struct ip6_hdr *);

/* cnd.c */
int cn_receive_dst_unreach(struct icmp6_hdr *);

/* mnd.c */
int mipsock_bul_request(struct binding_update_list *, u_char);
int mipsock_recv_mdinfo(struct mip_msghdr *);
int bul_update_by_mipsock_w_hoa(struct in6_addr *, struct in6_addr *, 
				u_int16_t);
int mipsock_md_update_bul_byifindex(u_int16_t, struct in6_addr *);
int mipsock_md_dereg_bul(struct in6_addr *, struct in6_addr *, u_int16_t);
#ifdef DSMIP
int v4_sendmessage(char *, int, u_int, struct in6_addr *, struct in6_addr *, struct in6_addr *, struct in6_addr *, struct in6_addr *);
#endif
int send_haadreq(struct mip6_hoainfo *, int, struct in6_addr *);
struct home_agent_list *mnd_add_hal(struct  mip6_hpfxl *, struct in6_addr *, int);
struct mip6_hpfxl *mnd_add_hpfxlist(struct in6_addr *, 
		    u_int16_t, struct mip6_hpfx_mn_exclusive *, 
				    struct mip6_mipif *);
struct mip6_mipif *mnd_get_mipif(u_int16_t);
int set_default_bu_lifetime(struct mip6_hoainfo *);
int receive_hadisc_reply(struct mip6_dhaad_rep *, size_t);
int receive_mpa(struct mip6_prefix_advert *, size_t, struct binding_update_list *);
struct noro_host_list *noro_get(struct in6_addr *);
void noro_add(struct in6_addr *);
void hpfxlist_expire_timer(void *);
#ifdef DSMIP
struct in_addr *mnd_get_v4hoa_by_ifindex(u_int16_t);
#endif /* DSMIP */

/* had.c */
int mipsock_input(struct mip_msghdr *);
int had_is_ha_if(u_int16_t);
#ifdef MIP_HA
u_int16_t ha_if(void);
#else
#define ha_if()		(0)
#endif
struct mip6_hpfxl *had_is_myhomenet(struct in6_addr *);
int send_haadrep(struct in6_addr *, struct in6_addr *, 
		 struct mip6_dhaad_req *, u_short);
int send_mpa(struct in6_addr *, u_int16_t, u_short);
int relay_icmp6_error(struct icmp6_hdr *, size_t, u_short);

/* nemo_var.c */
#ifdef MIP_NEMO
struct nemo_mptable *nemo_mpt_get(struct mip6_hoainfo *,
    struct sockaddr_storage *, u_int8_t);
struct nemo_mptable *nemo_mpt_add(struct mip6_hoainfo *,
    struct sockaddr_storage *, u_int8_t, int);
struct nemo_hptable *nemo_hpt_get(struct sockaddr_storage *, u_int8_t,
    struct in6_addr *);
struct nemo_hptable *nemo_hpt_add(struct in6_addr *, struct sockaddr_storage *,
    u_int8_t, int);

#define NEMOPREFIXINFO "./nemo_prefixtable.conf"
void nemo_parse_conf(void);
void command_show_pt(int, char *);

#endif /* MIP_NEMO */

/* hal.c */
struct home_agent_list *mip6_find_hal(struct mip6_hoainfo *);
#ifdef DSMIP
struct home_agent_list *mip6_find_hal_v6(struct mip6_hoainfo *);
#endif /* DSMIP */
struct home_agent_list *had_add_hal(struct mip6_hpfxl *, struct in6_addr *, 
			     struct in6_addr *, u_int16_t, u_int16_t, int);
struct mip6_hpfxl *had_add_hpfxlist(struct in6_addr *, u_int16_t);
void mip6_flush_hal(struct mip6_hpfxl *, int);
void mip6_delete_hal(struct mip6_hpfxl *, struct in6_addr *);
struct home_agent_list *mip6_get_hal(struct mip6_hpfxl *, struct in6_addr *);
void hxplist_stop_expire_timer(struct mip6_hpfxl *);
void hpfxlist_set_expire_timer(struct mip6_hpfxl *, int);
void hal_expire_timer(void *);
void mip6_delete_hpfxlist(struct in6_addr *, u_int16_t, 
			  struct mip6_hpfx_list *);
struct mip6_hpfxl *mip6_get_hpfxlist(struct in6_addr *, int, 
				     struct mip6_hpfx_list *);
void show_hal(int, struct mip6_hpfx_list *);
int receive_ra(struct nd_router_advert *, size_t, int, struct in6_addr *, struct in6_addr *);

/* other utility functions */
int inet_are_prefix_equal(void *, void *, int);
char *hexdump(void *, size_t);
const char *ip6_sprintf(const struct in6_addr *addr);
int kernel_debug(int);

#endif /* _SHISAD_SHISAD_H_ */
