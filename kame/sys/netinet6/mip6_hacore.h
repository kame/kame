/*	$KAME: mip6_hacore.h,v 1.3 2003/07/28 11:58:14 t-momose Exp $	*/

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

#ifndef _MIP6_HACORE_H_
#define _MIP6_HACORE_H_

#ifdef _KERNEL

/* Mobile IPv6 home agent functions. */
/* home registration processing. */
int mip6_process_hrbu(struct mip6_bc *);
int mip6_process_hurbu(struct mip6_bc *);
int mip6_bc_proxy_control(struct sockaddr_in6 *, struct sockaddr_in6 *, int);
void mip6_restore_proxynd_entry(struct mbuf *);
struct mip6_bc *mip6_temp_deleted_proxy(struct mbuf *);
int mip6_bc_encapcheck(const struct mbuf *, int, int, void *);
struct ifaddr *mip6_dad_find(struct in6_addr *,	struct ifnet *);
int mip6_dad_stop(struct mip6_bc *);
int mip6_dad_success(struct ifaddr *);
int mip6_dad_duplicated(struct ifaddr *);
int mip6_dad_error(struct ifaddr *, int);

/* bi-directional tunneling processing. */
int mip6_tunnel_output(struct mbuf **, struct mip6_bc *);
int mip6_icmp6_tunnel_input(struct mbuf *, int, int);

#endif /* _KERNEL */

#endif /* _MIP6_HACORE_H_ */
