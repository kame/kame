/*	$KAME: mobility6.c,v 1.3 2002/06/18 03:02:44 k-sugyou Exp $	*/

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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined(__OpenBSD__) && !(defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/icmp6.h>
#ifdef MIP6
#include <net/if_hif.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>
#endif

/*
 * Mobility header processing.
 */
int
mobility6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
	struct ip6_mobility *mh6;
	int off = *offp, mh6len;

	ip6 = mtod(m, struct ip6_hdr *);

	/* validation of the length of the header */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(*mh6), IPPROTO_DONE);
	mh6 = (struct ip6_mobility *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(mh6, struct ip6_mobility *, m, off, sizeof(*mh6));
	if (mh6 == NULL)
		return (IPPROTO_DONE);
#endif
	mh6len = mh6->ip6m_len << 3;
	if (mh6len < IP6M_MINLEN) {
		/* too small */
		goto bad;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, mh6len, IPPROTO_DONE);
	mh6 = (struct ip6_mobility *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(mh6, struct ip6_mobility *, m, off, mh6len);
	if (mh6 == NULL)
		return (IPPROTO_DONE);
#endif
	off += mh6len;

	/* XXX sanity check. */

	switch (mh6->ip6m_type) {
	case IP6M_HOME_TEST_INIT:
		if (mip6_ip6mhi_input(m, (struct ip6m_home_test_init *)mh6,
		    mh6len) < 0)
			goto bad;
		break;

	case IP6M_CAREOF_TEST_INIT:
		if (mip6_ip6mci_input(m, (struct ip6m_careof_test_init *)mh6,
		    mh6len) < 0)
			goto bad;
		break;

	case IP6M_HOME_TEST:
		if (mip6_ip6mh_input(m, (struct ip6m_home_test *)mh6,
		    mh6len) < 0)
			goto bad;
		break;

	case IP6M_CAREOF_TEST:
		if (mip6_ip6mc_input(m, (struct ip6m_careof_test *)mh6,
		    mh6len) < 0)
			goto bad;
		break;

	case IP6M_BINDING_REQUEST:
		break;

	case IP6M_BINDING_UPDATE:
		if (mip6_ip6mu_input(m, (struct ip6m_binding_update *)mh6,
		    mh6len) < 0)
			goto bad;
		break;

	case IP6M_BINDING_ACK:
		if (mip6_ip6ma_input(m, (struct ip6m_binding_ack *)mh6,
		    mh6len) < 0)
			goto bad;
		break;

	case IP6M_BINDING_ERROR:
		break;

	default:
		break;
	}

	*offp = off;
	return (mh6->ip6m_pproto);

 bad:
	m_freem(m);
	return (IPPROTO_DONE);
}

