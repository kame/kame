/*	$KAME: nd6_ind.c,v 1.1 2001/06/28 04:34:59 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#include "opt_ipsec.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/ioctl.h>
#endif
#include <sys/syslog.h>
#include <sys/queue.h>
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif
#ifdef __OpenBSD__
#include <dev/rndvar.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>

#ifdef __OpenBSD__	/*don't confuse KAME ipsec with OpenBSD ipsec*/
#undef IPSEC
#endif

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif

#include <net/net_osdep.h>

#define SDL(s) ((struct sockaddr_dl *)s)

void
nd6_ins_input(m, off, icmp6len)
	struct mbuf *m;
	int off, icmp6len;
{
 freeit:
	m_freem(m);
	return;

 bad:
	m_freem(m);
}


void
nd6_ins_output(ifp, daddr6, taddr6, ln, dad)
	struct ifnet *ifp;
	const struct in6_addr *daddr6, *taddr6;
	struct llinfo_nd6 *ln;	/* for source address determination */
	int dad;	/* duplicated address detection */
{
	return;
}


void
nd6_ina_input(m, off, icmp6len)
	struct mbuf *m;
	int off, icmp6len;
{
 freeit:
	m_freem(m);
	return;

 bad:
	m_freem(m);
}


void
nd6_ina_output(ifp, daddr6, taddr6, flags, tlladdr, sdl0)
	struct ifnet *ifp;
	const struct in6_addr *daddr6, *taddr6;
	u_long flags;
	int tlladdr;		/* 1 if include target link-layer address */
	struct sockaddr *sdl0;	/* sockaddr_dl (= proxy NA) or NULL */
{
	return;
}
