/*	$KAME: if_stf.h,v 1.11 2007/06/14 12:09:42 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#ifndef _NET_IF_STF_H_
#define _NET_IF_STF_H_

#ifdef _KERNEL

#include "stf.h"

struct stf_softc {
	struct ifnet	sc_if;	   /* common area */
	union {
		struct route  __sc_ro4;
#ifndef NEW_STRUCT_ROUTE
		struct route_in6 __sc_ro6; /* just for safety */
#endif
	} __sc_ro46;
#define sc_ro	__sc_ro46.__sc_ro4
	const struct encaptab *encap_cookie;
	LIST_ENTRY(stf_softc) sc_list; /* all stf's are linked */

	time_t rtcache_expire;	/* expiration time of the cached route */
};
#endif


#ifdef _KERNEL
#ifdef __FreeBSD__
void in_stf_input(struct mbuf *, int);
#else
void in_stf_input(struct mbuf *, ...);
#endif

#endif /* _KERNEL */
#endif /* _NET_IF_STF_H_ */
