/*	$KAME: dccp6_var.h,v 1.2 2003/10/18 07:52:00 itojun Exp $	*/

/*
 * Copyright (c) 2003 Joacim Häggmark
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: dccp6_var.h,v 1.2 2003/10/18 07:52:00 itojun Exp $
 */

#ifndef _NETINET_DCCP6_VAR_H_
#define _NETINET_DCCP6_VAR_H_

struct	dccpip6hdr {
	struct 	ip6_hdr di_i6;		/* ip6 structure */
	struct	dccphdr di_d;		/* dccp header */
};

#define di6_src		di_i6.ip6_src
#define di6_dst		di_i6.ip6_dst
#define di6_nxt		di_i6.ip6_nxt
#define di6_len		di_i6.ip6_plen
#define di6_flow	di_i6.ip6_flow
#define di6_vfc		di_i6.ip6_vfc

#ifdef _KERNEL
SYSCTL_DECL(_net_inet6_dccp6);

extern struct	pr_usrreqs dccp6_usrreqs;

void	dccp6_ctlinput(int, struct sockaddr *, void *);
int	dccp6_input(struct mbuf **, int *, int);

#endif
#endif
