/*	$KAME: if_hif.h,v 1.3 2001/09/20 10:22:13 keiichi Exp $	*/

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

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project and InternetCAR Projec\
t.
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
 *
 * Ryuji Wakikawa, Koshiro Mitsuya, Susumu Koshiba, Masashi Watari
 * Keio University, Endo 5322, Kanagawa, Japan
 * E-mail: mip6@sfc.wide.ad.jp
 *
 */

#ifndef _NET_IF_HIF_H_
#define _NET_IF_HIF_H_

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#if defined(_KERNEL) && !defined(_LKM)
#include "opt_inet6.h"
#endif
#endif

#include <netinet/in.h>
#include <netinet6/mip6_var.h>

#define HIF_MTU 1500 /* XXX */

#define HIF_LOCATION_UNKNOWN 0x00
#define HIF_LOCATION_HOME    0x01
#define HIF_LOCATION_FOREIGN 0x02

#define SIOCAHOMEPREFIX_HIF _IOW('i', 120, struct hif_ifreq)
#define SIOCGHOMEPREFIX_HIF _IOWR('i', 121, struct hif_ifreq)
#define SIOCAHOMEAGENT_HIF  _IOW('i', 122, struct hif_ifreq)
#define SIOCGHOMEAGENT_HIF  _IOWR('i', 123, struct hif_ifreq)
#define SIOCGBU_HIF         _IOWR('i', 125, struct hif_ifreq)

struct hif_ifreq {
	char     ifr_name[IFNAMSIZ];
	u_int8_t ifr_count;
	union {
		struct mip6_prefix *ifr_mpfx;
		struct mip6_ha     *ifr_mha;
		struct mip6_bu     *ifr_mbu;
	} ifr_ifru;
};

#define ifrmpfx_prefix    ifr_ifru.ifr_mpfx->mpfx_prefix
#define ifrmpfx_prefixlen ifr_ifru.ifr_mpfx->mpfx_prefixlen
#define ifrmpfx_lifetime  ifr_ifru.ifr_mpfx->mpfx_lifetime
#define ifrmpfx_remain    ifr_ifru.ifr_mpfx->mpfx_remain
#define ifrmpfx_haddr     ifr_ifru.ifr_mpfx->mpfx_haddr

#define ifrmha_lladdr     ifr_ifru.ifr_mha->mha_lladdr
#define ifrmha_gaddr      ifr_ifru.ifr_mha->mha_gaddr
#define ifrmha_flags      ifr_ifru.ifr_mha->mha_flags
#define ifrmha_pref       ifr_ifru.ifr_mha->mha_pref
#define ifrmha_lifetime   ifr_ifru.ifr_mha->mha_lifetime
#define ifrmha_remain     ifr_ifru.ifr_mha->mha_remain

#define ifrmbu_paddr      ifr_ifru.ifr_mbu->paddr
#define ifrmbu_haddr      ifr_ifru.ifr_mbu->haddr
#define ifrmbu_coa        ifr_ifru.ifr_mbu->coa
#define ifrmbu_lifetime   ifr_ifru.ifr_mbu->lifetime
#define ifrmbu_expire     ifr_ifru.ifr_mbu->remain
#define ifrmbu_refresh    ifr_ifru.ifr_mbu->refresh
#define ifrmbu_refexpire  ifr_ifru.ifr_mbu->refremain
#define ifrmbu_acktimeout ifr_ifru.ifr_mbu->acktimeout
#define ifrmbu_ackexpire  ifr_ifru.ifr_mbu->ackremain
#define ifrmbu_seqno      ifr_ifru.ifr_mbu->seqno
#define ifrmbu_flags      ifr_ifru.ifr_mbu->flags
#define ifrmbu_reg_state  ifr_ifru.ifr_mbu->reg_state
#define ifrmbu_state      ifr_ifru.ifr_mbu->state
#define ifrmbu_dontsend   ifr_ifru.ifr_mbu->dontsend

#ifdef _KERNEL

TAILQ_HEAD(hif_softc_list, hif_softc) hif_softc_list;
TAILQ_HEAD(hif_coa_list, hif_coa) hif_coa_list;
struct in6_addr hif_coa;

struct hif_subnet {
	TAILQ_ENTRY(hif_subnet) hs_entry;
	struct mip6_subnet      *hs_ms;
};
TAILQ_HEAD(hif_subnet_list, hif_subnet);

struct hif_softc {
	struct ifnet hif_if;
	TAILQ_ENTRY(hif_softc) hif_entry;
	int                    hif_location;             /* cur location */
	int                    hif_location_prev; /* XXX */

#ifdef MIP6_OLD
	LIST_HEAD(mip6_pfx_list, mip6_pfx) hif_pfx_list; /* list of pfxes */
	LIST_HEAD(hif_ha_list, hif_ha) hif_ha_list;      /* list of HAs */
#endif
	LIST_HEAD(mip6_bu_list, mip6_bu) hif_bu_list;    /* list of BUs */
	struct hif_subnet_list hif_hs_list_home;
	struct hif_subnet_list hif_hs_list_foreign;
	struct hif_subnet      *hif_hs_current;
	struct hif_subnet      *hif_hs_prev;
	u_int16_t              hif_hadiscovid;
};

struct hif_coa {
	TAILQ_ENTRY(hif_coa) hcoa_entry;
	struct ifnet         *hcoa_ifp;
};

#ifdef MIP6_OLD
struct hif_ha {
	LIST_ENTRY(hif_ha) hha_entry;
	u_int8_t           hha_onhomelink;
	struct mip6_ha     *hha_mha;
};
#endif

#if defined(__FreeBSD__) && __FreeBSD__ < 3
int hif_ioctl				__P((struct ifnet *, int, caddr_t));
#else
int hif_ioctl				__P((struct ifnet *, u_long, caddr_t));
#endif
int hif_output				__P((struct ifnet *, struct mbuf *,
					     struct sockaddr *,
					     struct rtentry *));

/* XXX hif_coa management. this is bad design. re-consider. */
struct hif_coa *hif_coa_create		__P((struct ifnet *));
struct in6_ifaddr *hif_coa_get_ifaddr	__P((struct hif_coa *));

int hif_coa_list_insert			__P((struct hif_coa_list *,
					     struct hif_coa *));
struct hif_coa *hif_coa_list_find_withifp
					__P((struct hif_coa_list *,
					     struct ifnet *));

/* hif_subnet management. */
struct hif_subnet *hif_subnet_create	__P((struct mip6_subnet *));
int hif_subnet_list_insert		__P((struct hif_subnet_list *,
					     struct hif_subnet *));
int hif_subnet_list_remove		__P((struct hif_subnet_list *,
					      struct hif_subnet *));
struct hif_subnet *hif_subnet_list_find_withprefix
					__P((struct hif_subnet_list *,
					     struct in6_addr *,
					     u_int8_t));
struct hif_subnet *hif_subnet_list_find_withhaaddr
					__P((struct hif_subnet_list *,
					     struct in6_addr *));


struct hif_softc *hif_list_find_withhaddr __P((struct in6_addr *));

struct hif_ha *hif_ha_create __P((u_int8_t, struct mip6_ha *));

#if 0
int hif_ha_list_insert __P((struct hif_ha_list *, struct hif_ha *hha));
int hif_ha_list_remove_withmha __P((struct hif_ha_list *, struct mip6_ha *));
int hif_ha_list_isonhomelink __P((struct hif_ha_list *, struct in6_addr *));
struct hif_ha *hif_ha_list_find_onhomelink __P((struct hif_ha_list *));
struct hif_ha *hif_ha_list_find_preferable __P((struct hif_ha_list *));
struct hif_ha *hif_ha_list_find_withaddr __P((struct hif_ha_list *,
					      struct in6_addr *));
#endif

#endif /* _KERNEL */

#endif /* !_NET_IF_HIF_H_ */
