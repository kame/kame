/*	$KAME: mip6.h,v 1.31 2001/11/29 04:38:38 keiichi Exp $	*/

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

#ifndef _MIP6_H_
#define _MIP6_H_

#include <net/if_hif.h>

#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <netinet/ip_encap.h>

#include <netinet6/mip6_var.h>

#define SIOCENABLEMN _IOW('m', 120, int)
#define SIOCENABLEHA _IOW('m', 121, int)
#define SIOCGBC      _IOWR('m', 122, struct mip6_req)

struct mip6_req {
	u_int8_t mip6r_count;
	union {
		struct mip6_bc *mip6r_mbc;
	} mip6r_ru;
};

/* protocol constants */
#define MIP6_HA_DEFAULT_LIFETIME   1800
#define MIP6_MAX_UPDATE_RATE       5
#define MIP6_MAX_PFX_ADV_DELAY     1000
#define MIP6_DHAAD_INITIAL_TIMEOUT 2
#define MIP6_DHAAD_RETRIES         3

#define MIP6SUBOPT_PAD1     0x00
#define MIP6SUBOPT_PADN     0x01
#define MIP6SUBOPT_UNIQID   0x02
#ifdef MIP6_DRAFT13
#define MIP6SUBOPT_ALTCOA   0x04
#else
#define MIP6SUBOPT_ALTCOA   0x03
#define MIP6SUBOPT_AUTHDATA 0x04
#endif /* MIP6_DRAFT13 */

/* Unique Identifier sub-option format. */
struct mip6_subopt_uniqid {
	u_int8_t type; /* 0x02 */
	u_int8_t len;  /* == 2 */
	u_int16_t id;  /* uniqid */
} __attribute__ ((__packed__));

/* Alternate Care-of Address sub-option format. */
struct mip6_subopt_altcoa {
	u_int8_t type;    /* 0x04 for draft-13, 0x03 for newer drafts */
	u_int8_t len;     /* == 16 */
	u_int8_t coa[16]; /* Alternate COA */
} __attribute__ ((__packed__));

/* Autnentication Data sub-option format. */
struct mip6_subopt_authdata {
	u_int8_t type; /* 0x04 */
	u_int8_t len;
	u_int32_t spi; /* security parameter index */
	/* followed by authentication data (variable length) */
} __attribute__ ((__packed__));

#ifdef _KERNEL

#define MIP6_BU_HOME_REG   0
#define MIP6_BU_HOME_UNREG 1

#define MIP6_BA_INITIAL_TIMEOUT  1
#define MIP6_BA_MAX_TIMEOUT      256
#define MIP6_BA_STATUS_ERRORBASE 128

#define MIP6_TUNNEL_ADD    0
#define MIP6_TUNNEL_CHANGE 1
#define MIP6_TUNNEL_DELETE 2

extern struct mip6_config mip6_config;

extern struct nd_defrouter *mip6_dr;
extern struct mip6_ha_list mip6_ha_list; /* Global val holding all HAs */

void mip6_init __P((void));

int mip6_process_nd_prefix		__P((struct in6_addr *,
					     struct nd_prefix *,
					     struct nd_defrouter *,
					     struct mbuf *));
int mip6_process_defrouter_change	__P((struct nd_defrouter *));

int mip6_ifa_need_dad			__P((struct in6_ifaddr *));
int64_t mip6_coa_get_lifetime		__P((struct in6_addr *));

struct mbuf *mip6_create_ip6hdr		 __P((struct in6_addr *,
					      struct in6_addr *,
					      u_int8_t,
					      u_int32_t));
int mip6_exthdr_create			 __P((struct mbuf *,
					      struct ip6_pktopts *,
					      struct mip6_pktopts *));
int mip6_rthdr_create			__P((struct ip6_rthdr **,
					     struct in6_addr *));
int mip6_ba_destopt_create		 __P((struct ip6_dest **,
					      u_int8_t,
					      MIP6_SEQNO_T,
					      u_int32_t,
					      u_int32_t));
void mip6_destopt_discard		__P((struct mip6_pktopts *));
int mip6_addr_exchange			__P((struct mbuf *,
					     struct mbuf *));
int mip6_process_destopt		__P((struct mbuf *,
					     struct ip6_dest *,
					     u_int8_t *, int));
u_int8_t *mip6_destopt_find_subopt	__P((u_int8_t *,
					     u_int8_t, u_int8_t));
void mip6_create_addr			__P((struct in6_addr *,
					     struct in6_addr *,
					     struct in6_addr *,
					     u_int8_t));
struct mip6_bc *mip6_bc_list_find_withcoa
					__P((struct mip6_bc_list *,
					     struct in6_addr *));

int mip6_ioctl				__P((u_long, caddr_t));
int mip6_tunnel				__P((struct in6_addr *,
					     struct in6_addr *,
					     int, const struct encaptab **));
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
struct mip6_prefix *mip6_prefix_create	__P((struct in6_addr *, u_int8_t,
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
					     struct in6_addr *haddr));

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
					     struct in6_addr *, u_int8_t));
struct mip6_subnet *mip6_subnet_list_find_withmpfx
					__P((struct mip6_subnet_list *,
					     struct mip6_prefix *));
struct mip6_subnet *mip6_subnet_list_find_withhaaddr
					__P((struct mip6_subnet_list *,
					     struct in6_addr *));
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
					     struct in6_addr *, u_int8_t));
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
					     struct in6_addr *haaddr));


/* homeagent list management */
void mip6_ha_init			__P((void));
/* mip6_ha functions */
struct mip6_ha *mip6_ha_create		__P((struct in6_addr *,
					     struct in6_addr *,
					     u_int8_t, int16_t, int32_t));
int mip6_ha_list_insert			__P((struct mip6_ha_list *,
					     struct mip6_ha *mha));
int mip6_ha_list_remove			__P((struct mip6_ha_list*,
					     struct mip6_ha *mha));
struct mip6_ha *mip6_ha_list_find_withaddr
					__P((struct mip6_ha_list *,
					     struct in6_addr *));
int mip6_ha_list_update_hainfo		__P((struct mip6_ha_list *,
					     struct nd_defrouter *,
					     struct nd_opt_homeagent_info *));
int mip6_ha_list_update_withndpr	__P((struct mip6_ha_list *,
					     struct in6_addr *,
					     struct nd_prefix *));
int mip6_ha_list_update_gaddr		__P((struct mip6_ha_list*,
					     struct in6_addr *,
					     struct in6_addr *));

/* binding update management */
void mip6_bu_init			__P((void));
struct mip6_bu *mip6_bu_create		__P((const struct in6_addr *,
					     struct mip6_prefix *,
					     struct in6_addr *,
					     u_int16_t,
					     struct hif_softc *));
int mip6_bu_list_insert			__P((struct mip6_bu_list *,
					     struct mip6_bu *));
struct mip6_bu *mip6_bu_list_find_withpaddr
					__P((struct mip6_bu_list *,
					     struct in6_addr *));
struct mip6_bu *mip6_bu_list_find_home_registration
					__P((struct mip6_bu_list *,
					     struct in6_addr *));
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
					     struct in6_addr *));
struct mip6_bc *mip6_bc_list_find_withpcoa
					__P((struct mip6_bc_list *,
					     struct in6_addr *));

struct mip6_subopt_authdata *mip6_authdata_create
					__P((struct in6_addr *,
					     struct in6_addr *,
					     struct in6_addr *,
					     struct ip6_opt_binding_update *));

#define mip6log(arg) do { if (mip6_config.mcfg_debug) log arg;} while (0)
void mip6_ha_print __P((struct mip6_ha *));

#endif /* _KERNEL */

#endif /* !_MIP6_H_ */
