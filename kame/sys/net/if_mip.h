/*	$KAME: if_mip.h,v 1.4 2006/04/12 12:19:31 t-momose Exp $	*/

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

#ifndef _NET_IF_MIP_H_
#define _NET_IF_MIP_H_

#define MIP_MTU 1280

#if !defined(__APPLE__) || (defined(__APPLE__) && defined(KERNEL_PRIVATE))
struct mip_softc {
	struct ifnet          mip_if;
	LIST_ENTRY(mip_softc) mip_entry;
#ifdef __APPLE__
	u_long	mip_proto; /* dlil protocol attached */
#endif
};
LIST_HEAD(mip_softc_list, mip_softc);
#endif /* (__APPLE__) || ((__APPLE__) && (KERNEL_PRIVATE)) */

struct bul6info {
        struct in6_addr     bul_peeraddr;   /* peer addr of this BU */
        struct in6_addr     bul_hoa;        /* HoA */
        struct in6_addr     bul_coa;        /* CoA */
        u_int16_t           bul_flags;      /* Flag Ack, LL, Key, Home flag */
	u_int16_t           bul_ifindex;
	u_int16_t           bul_bid;        /* Binding Unique Identifier */
};

struct if_bulreq {
        char    ifbu_ifname[IFNAMSIZ];
	int     ifbu_len;
	int               ifbu_count;
	struct bul6info   *ifbu_info;
};


#ifdef _KERNEL

extern struct mip_softc_list mip_softc_list;

int mip_ioctl(struct ifnet *, u_long, caddr_t);
int mip_output(struct ifnet *, struct mbuf *, struct sockaddr *,
    struct rtentry *rt);

int mip_is_mip_softc(struct ifnet *);

#endif /* _KERNEL*/

#endif /* !_NET_IF_MIP_H_ */
