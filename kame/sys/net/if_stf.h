/*	$KAME: if_stf.h,v 1.7 2003/01/08 08:47:23 suz Exp $	*/

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
#if NSTF == 2
#define ISATAP
#endif

struct stf_softc {
	/* if_physical determines stf to work in 6to4 or ISATAP */
	struct ifnet	sc_if;	   /* common area */
	union {
		struct route  __sc_ro4;
#ifndef NEW_STRUCT_ROUTE
		struct route_in6 __sc_ro6; /* just for safety */
#endif
	} __sc_ro46;
#define sc_ro	__sc_ro46.__sc_ro4
	const struct encaptab *encap_cookie;
	int sc_mode;	/* 6to4 or ISATAP */
	LIST_ENTRY(stf_softc) sc_list; /* all stf's are linked */
};

struct isatap_rtr {
	TAILQ_ENTRY(isatap_rtr) isr_entry;
	struct sockaddr isr_addr;	/* IPv4 router address of ISATAP router */
};
#endif


/* stf mode to identify tunnelling mode */
#define STFM_6TO4   0
#define STFM_ISATAP 1

#ifndef SIOCSISATAPRTR
#define SIOCSISATAPRTR SIOCSIFGENERIC
#endif

#ifndef SIOCGISATAPRTR
#define SIOCGISATAPRTR SIOCGIFGENERIC
#endif

#ifndef SIOCDISATAPRTR
#define SIOCDISATAPRTR SIOCDIFGENERIC
#endif

#ifdef _KERNEL
#define STF_IS_6TO4(x) \
	((((struct stf_softc *) (x))->sc_if.if_type == IFT_STF) && \
	 (((struct stf_softc *) (x))->sc_mode == STFM_6TO4))
#ifdef ISATAP
#define STF_IS_ISATAP(x) \
	((((struct stf_softc *) (x))->sc_if.if_type == IFT_STF) && \
	 (((struct stf_softc *) (x))->sc_mode == STFM_ISATAP))
#else
#define STF_IS_ISATAP(x)  0	/* disable ISATAP */
#endif

#if (defined(__FreeBSD__) && __FreeBSD__ >= 4)
void in_stf_input __P((struct mbuf *, int));
#else
void in_stf_input __P((struct mbuf *, ...));
#endif /* (defined(__FreeBSD__) && __FreeBSD__ >= 4) */

#ifndef __FreeBSD__
extern int fill_isatap_rtrlist __P((void *, size_t *, size_t));
#endif
#endif /* _KERNEL */
#endif /* _NET_IF_STF_H_ */
