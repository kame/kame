/*	$KAME: mip6_var.h,v 1.88 2003/04/23 09:15:52 keiichi Exp $	*/

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
#define SIOCSMIP6CFG_ENABLEAUTHDATA  5
#define SIOCSMIP6CFG_DISABLEAUTHDATA 6
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
		struct sockaddr_in6 mip6r_sin6;
		struct mip6_preferred_ifnames mip6r_ifnames;
	} mip6r_ru;
};

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
	time_t		      mbc_mpa_exp;  /* expiration time for sending MPA */
	                                     /* valid only when BUF_HOME. */
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

/* packet options used by the mip6 packet output processing routine. */
struct mip6_pktopts {
	struct ip6_rthdr *mip6po_rthdr2;
	struct ip6_dest *mip6po_haddr;
	struct ip6_dest *mip6po_dest2;
	struct ip6_mobility *mip6po_mobility;
};

struct mip6_mobility_options {
	u_int16_t valid_options;	/* shows valid options in this structure */
	u_int16_t	mopt_uid;		/* Unique ID */
	struct in6_addr mopt_altcoa;		/* Alternate CoA */
	u_int16_t	mopt_ho_nonce_idx;	/* Home Nonce Index */
	u_int16_t	mopt_co_nonce_idx;	/* Care-of Nonce Index */
	caddr_t mopt_auth;			/* Authenticator */
	u_int16_t	mopt_refresh;		/*  Refresh Interval */
};

#define MOPT_UID	0x0001	/* unused */
#define MOPT_ALTCOA	0x0002
#define MOPT_NONCE_IDX	0x0004
#define MOPT_AUTHDATA	0x0008
#define MOPT_REFRESH	0x0010

#define MOPT_AUTH_LEN(mopts)	(int)(*((mopts)->mopt_auth + 1))

#define MIP6_COOKIE_MAX_LIFE	240
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

/*
 * Mobile IPv6 configuration knobs.
 */
struct mip6_config {
	u_int8_t mcfg_type;
	u_int8_t mcfg_use_ipsec;
	u_int8_t mcfg_use_authdata;
	u_int8_t mcfg_debug;
	u_int32_t mcfg_bc_lifetime_limit;
	u_int32_t mcfg_hrbc_lifetime_limit;
	u_int32_t mcfg_bu_maxlifetime;
	u_int32_t mcfg_hrbu_maxlifetime;
};
#define MIP6_CONFIG_TYPE_MOBILENODE 1
#define MIP6_CONFIG_TYPE_HOMEAGENT 2

#define MIP6_IS_MN (mip6_config.mcfg_type == MIP6_CONFIG_TYPE_MOBILENODE)
#define MIP6_IS_HA (mip6_config.mcfg_type == MIP6_CONFIG_TYPE_HOMEAGENT)

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
};

#endif /* !_MIP6_VAR_H_ */

