/*	$KAME: if_vrrp_var.h,v 1.3 2003/02/19 10:13:16 ono Exp $ */

/*
 * Copyright (C) 2002 WIDE Project.
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

#ifndef _NET_IF_VRRP_VAR_H_
#define	_NET_IF_VRRP_VAR_H_	1

#ifdef _KERNEL
struct vrrp_mc_entry {
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	struct ether_addr		mc_addr;
	SLIST_ENTRY(vrrp_mc_entry)	mc_entries;
#else
	LIST_ENTRY(vrrp_mc_entry)	mc_entries;
	union {
		struct ether_multi	*mcu_enm;
	} mc_u;
	struct sockaddr_storage		mc_addr;
#endif
};

#define	mc_enm		mc_u.mcu_enm

struct	ifvrrp {
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
        struct  arpcom ifv_ac;
#else
        struct  ethercom ifv_ec;
#endif
	struct	ifnet *ifv_p;	/* parent inteface of this vrrp */
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	SLIST_HEAD(__vrrp_mchead, vrrp_mc_entry)	vrrp_mc_listhead;
#else
	LIST_HEAD(__vrrp_mchead, vrrp_mc_entry)	vrrp_mc_listhead;
#endif
	LIST_ENTRY(ifvrrp) ifv_list;
	struct resource *r_unit;	/* resource allocated for this unit */
};
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
#define	ifv_if	ifv_ac.ac_if
#else
#define	ifv_if	ifv_ec.ec_if
#endif
#endif /* _KERNEL */

/* sysctl(3) tags, for compatibility purposes */
#define	VRRPCTL_PROTO	1
#define	VRRPCTL_MAX	2

/*
 * Configuration structure for SIOCSETVRRP and SIOCGETVRRP ioctls.
 */
struct	vrrpreq {
	u_int32_t vr_parent_index;
	struct sockaddr vr_lladdr;
};
#define	SIOCSETVRRP	SIOCSIFGENERIC
#define	SIOCGETVRRP	SIOCGIFGENERIC

#ifdef _KERNEL
int    vrrp_input(struct ether_header *eh, struct mbuf *m);
extern int nvrrp_active;
#endif

#endif /* _NET_IF_VRRP_VAR_H_ */
