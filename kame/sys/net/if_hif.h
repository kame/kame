/*	$KAME: if_hif.h,v 1.29 2004/02/13 04:52:33 keiichi Exp $	*/

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
 * Ryuji Wakikawa, Koshiro Mitsuya, Susumu Koshiba, Masafumi Watari
 * Keio University, Endo 5322, Kanagawa, Japan
 * E-mail: mip6@sfc.wide.ad.jp
 *
 */

#ifndef _NET_IF_HIF_H_
#define _NET_IF_HIF_H_

#include <netinet6/mip6_var.h>

#define HIF_MTU 1280 /* XXX */

#define HIF_LOCATION_UNKNOWN 0x00
#define HIF_LOCATION_HOME    0x01
#define HIF_LOCATION_FOREIGN 0x02

struct hif_prefix {
	LIST_ENTRY(hif_prefix) hpfx_entry;
	struct mip6_prefix     *hpfx_mpfx;
};
LIST_HEAD(hif_prefix_list, hif_prefix);

struct hif_site_prefix {
	LIST_ENTRY(hif_site_prefix) hsp_entry;
	struct in6_addr             hsp_prefix;
	u_int8_t                    hsp_prefixlen;
};
LIST_HEAD(hif_site_prefix_list, hif_site_prefix);

struct hif_softc {
	struct ifnet hif_if;
	LIST_ENTRY(hif_softc)  hif_entry;
	int                    hif_location;            /* cur location */
	int                    hif_location_prev;       /* XXX */
	struct in6_ifaddr      *hif_coa_ifa;
	struct hif_site_prefix_list hif_sp_list;
	struct mip6_bu_list    hif_bu_list;             /* list of BUs */
	struct hif_prefix_list hif_prefix_list_home;
	struct hif_prefix_list hif_prefix_list_foreign;
	u_int16_t              hif_dhaad_id;
	long                   hif_dhaad_lastsent;
	u_int8_t               hif_dhaad_count;
	u_int16_t              hif_mps_id;
	long                   hif_mps_lastsent;
	struct in6_addr        hif_ifid;
};
LIST_HEAD(hif_softc_list, hif_softc);

#define SIOCAHOMEPREFIX_HIF _IOW('i', 120, struct hif_ifreq)
#define SIOCGHOMEPREFIX_HIF _IOWR('i', 121, struct hif_ifreq)
#define SIOCAHOMEAGENT_HIF  _IOW('i', 122, struct hif_ifreq)
#define SIOCGHOMEAGENT_HIF  _IOWR('i', 123, struct hif_ifreq)
/* 124 */
#define SIOCGBU_HIF         _IOWR('i', 125, struct hif_ifreq)
#define SIOCSIFID_HIF       _IOW('i', 126, struct hif_ifreq)
#define SIOCGIFID_HIF       _IOWR('i', 127, struct hif_ifreq)
#define SIOCASITEPREFIX_HIF _IOW('i', 128, struct hif_ifreq)
#define SIOCGSITEPREFIX_HIF _IOWR('i', 129, struct hif_ifreq)

struct hif_ifreq {
	char     ifr_name[IFNAMSIZ];
	u_int8_t ifr_count;
	union {
		struct mip6_prefix ifr_mpfx;
		struct mip6_ha     ifr_mha;
		struct mip6_bu     ifr_mbu;
		struct in6_addr    ifr_ifid;
		struct hif_site_prefix ifr_hsp;
	} ifr_ifru;
};

#ifdef _KERNEL

extern struct hif_softc_list hif_softc_list;

struct hif_softc *hif_list_find_withhaddr(struct in6_addr *);

int hif_ioctl(struct ifnet *, u_long, caddr_t);
int hif_output(struct ifnet *, struct mbuf *, struct sockaddr *,
    struct rtentry *);
void hif_save_location(struct hif_softc *);
void hif_restore_location(struct hif_softc *);
struct mip6_ha *hif_find_preferable_ha(struct hif_softc *);
struct mip6_ha *hif_find_next_preferable_ha(struct hif_softc *,
    struct in6_addr *);

struct hif_prefix *hif_prefix_list_insert_withmpfx(struct hif_prefix_list *,
    struct mip6_prefix *);
void hif_prefix_list_remove(struct hif_prefix_list *, struct hif_prefix *);
struct hif_prefix *hif_prefix_list_find_withprefix(struct hif_prefix_list *,
    struct in6_addr *, int);
struct hif_prefix *hif_prefix_list_find_withhaaddr(struct hif_prefix_list *,
    struct in6_addr *);
struct hif_prefix *hif_prefix_list_find_withmpfx(struct hif_prefix_list *,
    struct mip6_prefix *);

void hif_site_prefix_list_remove(struct hif_site_prefix_list *,
    struct hif_site_prefix *);

#endif /* _KERNEL */

#endif /* !_NET_IF_HIF_H_ */
