/*	$KAME: if_vrrp_var.h,v 1.2 2002/07/10 07:21:02 ono Exp $ */

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
	struct ether_addr		mc_addr;
	SLIST_ENTRY(vrrp_mc_entry)	mc_entries;
};

struct	ifvrrp {
	struct  arpcom ifv_ac;
	struct	ifnet *ifv_p;	/* parent inteface of this vrrp */
#if 0
	struct	ifv_linkmib {
		int	ifvm_parent;
		u_int16_t ifvm_proto; /* encapsulation ethertype */
		u_int16_t ifvm_tag; /* tag to apply on packets leaving if */
	}	ifv_mib;
#endif
	SLIST_HEAD(__vrrp_mchead, vrrp_mc_entry)	vrrp_mc_listhead;
	LIST_ENTRY(ifvrrp) ifv_list;
	struct resource *r_unit;	/* resource allocated for this unit */
};
#define	ifv_if	ifv_ac.ac_if
#endif /* _KERNEL */

#define	EVL_ENCAPLEN	4	/* length in octets of encapsulation */

/* sysctl(3) tags, for compatibility purposes */
#define	VRRPCTL_PROTO	1
#define	VRRPCTL_MAX	2

/*
 * Configuration structure for SIOCSETVRRP and SIOCGETVRRP ioctls.
 */
struct	vrrpreq {
	char	vlr_parent[IFNAMSIZ];
};
#define	SIOCSETVRRP	SIOCSIFGENERIC
#define	SIOCGETVRRP	SIOCGIFGENERIC

#endif /* _NET_IF_VRRP_VAR_H_ */
