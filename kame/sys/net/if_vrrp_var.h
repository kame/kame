/*
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net/if_vlan_var.h,v 1.5.2.3 2001/12/04 20:01:54 brooks Exp $
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
