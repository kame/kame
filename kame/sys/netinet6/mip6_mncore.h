/*	$KAME: mip6_mncore.h,v 1.10 2003/08/20 13:31:14 keiichi Exp $	*/

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
extern struct mip6_unuse_hoa_list mip6_unuse_hoa;
extern struct mip6_preferred_ifnames mip6_preferred_ifnames;

/* Mobile IPv6 mobile node functions. */
/* initialization. */
void mip6_mn_init(void);
void mip6_bu_init(void);
void mip6_halist_init(void);
void mip6_prefix_init(void);

/* movement processing. */
int mip6_prelist_update(struct sockaddr_in6 *, union nd_opts *,
    struct nd_defrouter *, struct mbuf *);
void mip6_probe_routers(void);
void mip6_process_movement(void);
int mip6_process_pfxlist_status_change(struct hif_softc *);
int mip6_select_coa(struct hif_softc *);
int mip6_detach_haddrs(struct hif_softc *);
int mip6_ifa_need_dad(struct in6_ifaddr *);
int mip6_route_optimize(struct mbuf *);

/* binding update entry processing. */
int mip6_bu_list_remove(struct mip6_bu_list *, struct mip6_bu *);
int mip6_bu_list_remove_all(struct mip6_bu_list *, int);
struct mip6_bu *mip6_bu_list_find_home_registration(struct mip6_bu_list *,
    struct sockaddr_in6 *);
struct mip6_bu *mip6_bu_list_find_withpaddr(struct mip6_bu_list *,
    struct sockaddr_in6 *, struct sockaddr_in6 *);
int mip6_home_registration(struct hif_softc *);
int mip6_home_registration2(struct mip6_bu *);
int mip6_bu_encapcheck(const struct mbuf *, int, int, void *);
int mip6_bu_fsm(struct mip6_bu *, int, void *);
int mip6_bu_send_hoti(struct mip6_bu *);
int mip6_bu_send_coti(struct mip6_bu *);
int mip6_bu_send_bu(struct mip6_bu *);
int mip6_bu_send_cbu(struct mip6_bu *);

/* home agent list processing. */
struct mip6_ha *mip6_ha_create(struct sockaddr_in6 *, struct sockaddr_in6 *,
    u_int8_t, u_int16_t, int32_t);
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
struct mip6_prefix *mip6_prefix_list_find_withprefix(struct sockaddr_in6 *,
    int);
struct mip6_prefix *mip6_prefix_list_find_withhaddr(struct mip6_prefix_list *,
    struct sockaddr_in6 *);
int mip6_prefix_haddr_assign(struct mip6_prefix *, struct hif_softc *);
void mip6_prefix_settimer(struct mip6_prefix *, long);

/* advertising router list management. */
struct mip6_prefix_ha *mip6_prefix_ha_list_insert(struct mip6_prefix_ha_list *,
    struct mip6_ha *);
void mip6_prefix_ha_list_remove(struct mip6_prefix_ha_list *,
    struct mip6_prefix_ha *);
struct mip6_prefix_ha *mip6_prefix_ha_list_find_withaddr(
    struct mip6_prefix_ha_list *, struct sockaddr_in6 *);
struct mip6_prefix_ha *mip6_prefix_ha_list_find_withmha(
    struct mip6_prefix_ha_list *, struct mip6_ha *);

/* IPv6 extention header processing. */
int mip6_haddr_destopt_create(struct ip6_dest **, struct sockaddr_in6 *,
    struct sockaddr_in6 *, struct hif_softc *);
int mip6_mobile_node_exthdr_size(struct sockaddr_in6 *, struct sockaddr_in6 *);
int mip6_addr_exchange(struct mbuf *, struct mbuf *);

/* Mobility Header processing. */
int mip6_ip6mh_input(struct mbuf *, struct ip6m_home_test *, int);
int mip6_ip6mc_input(struct mbuf *, struct ip6m_careof_test *, int);
int mip6_ip6ma_input(struct mbuf *, struct ip6m_binding_ack *, int);
int mip6_ip6mr_input(struct mbuf *, struct ip6m_binding_request *, int);
int mip6_ip6me_input(struct mbuf *, struct ip6m_binding_error *, int);
int mip6_ip6mhi_create(struct ip6_mobility **, struct mip6_bu *);
int mip6_ip6mci_create(struct ip6_mobility **, struct mip6_bu *);
int mip6_ip6mu_create(struct ip6_mobility **, struct sockaddr_in6 *,
    struct sockaddr_in6 *, struct hif_softc *);

/* ICMPv6 processing. */
int mip6_icmp6_input(struct mbuf *, int, int);
int mip6_icmp6_dhaad_req_output(struct hif_softc *);
int mip6_icmp6_mp_sol_output(struct sockaddr_in6 *, struct sockaddr_in6 *);

#ifdef MIP6_DEBUG
void mip6_bu_print(struct mip6_bu *);
#endif /* MIP6_DEBUG */
void mip6_ha_print(struct mip6_ha *);
#endif /* _KERNEL */

#endif /* _MIP6_MNCORE_H_ */
