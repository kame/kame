/*	$KAME: mip6_cncore.h,v 1.11 2003/12/05 01:35:17 keiichi Exp $	*/

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

#ifndef _MIP6_CNCORE_H_
#define _MIP6_CNCORE_H_

#ifdef _KERNEL

/* Macro for modulo 2^^16 comparison */
#define MIP6_LEQ(a,b)   ((int16_t)((a)-(b)) <= 0)

#define MIP6_TUNNEL_ADD    0
#define MIP6_TUNNEL_CHANGE 1
#define MIP6_TUNNEL_DELETE 2

/* Calculation pad length to be appended */
/* xn + y; x must be 2^m */
#define MIP6_PADLEN(cur_offset, x, y)	\
	((x + y) - ((cur_offset) % (x))) % (x)

extern struct ip6protosw mip6_tunnel_protosw;
extern struct mip6_bc_list mip6_bc_list;

extern struct mip6_config mip6_config;
extern struct mip6stat mip6stat;

/* Mobile IPv6 correspondent node functions. */
/* initialization and control functions. */
void mip6_init(void);
int mip6_ioctl(u_long, caddr_t);

/* IPv6 extention header processing. */
struct mbuf *mip6_create_ip6hdr(struct sockaddr_in6 *, struct sockaddr_in6 *,
    u_int8_t, u_int32_t);
int mip6_exthdr_create(struct mbuf *, struct ip6_pktopts *,
    struct mip6_pktopts *);
int mip6_rthdr_create(struct ip6_rthdr **, struct sockaddr_in6 *,
    struct ip6_pktopts *);
int mip6_exthdr_size(struct sockaddr_in6 *, struct sockaddr_in6 *);
void mip6_destopt_discard(struct mip6_pktopts *);

/* binding cache entry processing. */
void mip6_bc_init(void);
struct mip6_bc *mip6_bc_create(struct sockaddr_in6 *, struct sockaddr_in6 *,
    struct sockaddr_in6 *, u_int8_t, u_int16_t, u_int32_t, struct ifnet *);
int mip6_bc_list_remove(struct mip6_bc_list *, struct mip6_bc *);
struct mip6_bc *mip6_bc_list_find_withphaddr(struct mip6_bc_list *,
    struct sockaddr_in6 *);
int mip6_bc_send_ba(struct sockaddr_in6 *, struct sockaddr_in6 *,
    struct sockaddr_in6 *, u_int8_t, u_int16_t, u_int32_t, u_int32_t,
    struct mip6_mobility_options *);

/* return routablity processing. */
int mip6_get_nonce(u_int16_t, mip6_nonce_t *);
int mip6_get_nodekey(u_int16_t, mip6_nodekey_t *);
int mip6_create_keygen_token(struct in6_addr *, mip6_nodekey_t *,
    mip6_nonce_t *, u_int8_t, void *);
int mip6_is_valid_bu(struct ip6_hdr *, struct ip6_mh_binding_update *,
    int, struct mip6_mobility_options *, struct sockaddr_in6 *,
    struct sockaddr_in6 *, int, u_int8_t *);
int mip6_calculate_kbm_from_index(struct sockaddr_in6 *, struct sockaddr_in6 *,
    u_int16_t, u_int16_t, int, u_int8_t *);
void mip6_calculate_kbm(mip6_home_token_t *, mip6_careof_token_t *,
    u_int8_t *);
int mip6_calculate_authenticator(u_int8_t *, u_int8_t *, struct in6_addr *,
    struct in6_addr *, caddr_t, size_t, int, size_t);

/* Mobility Header processing. */
int mip6_ip6mhi_input(struct mbuf *, struct ip6_mh_home_test_init *, int);
int mip6_ip6mci_input(struct mbuf *, struct ip6_mh_careof_test_init *, int);
int mip6_ip6mu_input(struct mbuf *, struct ip6_mh_binding_update *, int);
int mip6_ip6ma_create(struct ip6_mh **, struct sockaddr_in6 *,
    struct sockaddr_in6 *, struct sockaddr_in6 *, u_int8_t, u_int16_t,
    u_int32_t, u_int32_t, struct mip6_mobility_options *);
int mip6_ip6me_create(struct ip6_mh **, struct sockaddr_in6 *,
    struct sockaddr_in6 *, u_int8_t, struct sockaddr_in6 *);
int mip6_get_mobility_options(struct ip6_mh *, int, int,
    struct mip6_mobility_options *);
int mip6_cksum(struct sockaddr_in6 *, struct sockaddr_in6 *, u_int32_t,
    u_int8_t, char *);

/* ICMPv6 processing. */
int mip6_icmp6_input(struct mbuf *, int, int);

/* core functions for mobile node and home agent. */
#if defined(MIP6_HOME_AGENT) || defined(MIP6_MOBILE_NODE)
struct nd_prefix;
void mip6_create_addr(struct sockaddr_in6 *, const struct sockaddr_in6 *,
    struct nd_prefix *);
int mip6_tunnel_input(struct mbuf **, int *, int);
int mip6_tunnel_control(int, void *,
    int (*)(const struct mbuf *, int, int, void *), const struct encaptab **);
#endif /* MIP6_HOME_AGENT || MIP6_MOBILE_NODE */

#ifndef __FreeBSD__
int mip6_sysctl __P((int *, u_int, void *, size_t *, void *, size_t));
#endif

/* for diagnostics. */
#define mip6log(arg) do {	\
	if (mip6ctl_debug)	\
	    log arg;		\
} while (/*CONSTCOND*/ 0)

#ifdef RR_DBG
	extern void ipsec_hexdump(caddr_t, int);
#define mip6_hexdump(m,l,a)			\
		do {				\
			printf("%s", (m));	\
			ipsec_hexdump((caddr_t)(a),(l)); \
			printf("\n");		\
		} while (/*CONSTCOND*/ 0)
#endif

#endif /* _KERNEL */

#endif /* _MIP6_CNCORE_H_ */
