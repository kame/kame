/*	$KAME: mobility6.c,v 1.15 2002/11/01 11:09:51 keiichi Exp $	*/

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
#include <sys/syslog.h>

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
	struct mbuf *n; /* for ip6aux */
	struct ip6_hdr *ip6;
	struct ip6_mobility *mh6;
	int off = *offp, mh6len;
	int sum;

	mip6stat.mip6s_mobility++;

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
	mh6len = (mh6->ip6m_len + 1) << 3;
	if (mh6len < IP6M_MINLEN) {
		/* too small */
		m_freem(m);
		ip6stat.ip6s_toosmall++;
		return (IPPROTO_DONE);
	}

	if (mh6->ip6m_pproto != IPPROTO_NONE) {
		mip6log((LOG_INFO, "%s:%d: Payload Proto %d.\n",
			__FILE__, __LINE__, mh6->ip6m_pproto));
		/* 9.2.1 silently discard */
		m_freem(m);
		mip6stat.mip6s_payloadproto++;
		return (IPPROTO_DONE);
	}

	/*
	 * calculate the checksum
	 */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, mh6len, IPPROTO_DONE);
	mh6 = (struct ip6_mobility *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(mh6, struct ip6_mobility *, m, off, mh6len);
	if (mh6 == NULL)
		return (IPPROTO_DONE);
#endif
	if ((sum = in6_cksum(m, IPPROTO_MOBILITY, off, mh6len)) != 0) {
		mip6log((LOG_ERR,
		    "%s:%d: Mobility Header checksum error(%d|%x) %s\n",
		    __FILE__, __LINE__,
		    mh6->ip6m_type, sum, ip6_sprintf(&ip6->ip6_src)));
		m_freem(m);
		mip6stat.mip6s_checksum++;
		return (IPPROTO_DONE);
	}

	off += mh6len;

	/* XXX sanity check. */

	switch (mh6->ip6m_type) {
	case IP6M_HOME_TEST_INIT:
		if (mip6_ip6mhi_input(m, (struct ip6m_home_test_init *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6M_CAREOF_TEST_INIT:
		if (mip6_ip6mci_input(m, (struct ip6m_careof_test_init *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6M_HOME_TEST:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6mh_input(m, (struct ip6m_home_test *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6M_CAREOF_TEST:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6mc_input(m, (struct ip6m_careof_test *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6M_BINDING_REQUEST:
		if (!MIP6_IS_MN)
			break;
		/* XXX */
		break;

	case IP6M_BINDING_UPDATE:
		if (mip6_ip6mu_input(m, (struct ip6m_binding_update *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6M_BINDING_ACK:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6ma_input(m, (struct ip6m_binding_ack *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6M_BINDING_ERROR:
		if (mip6_ip6me_input(m, (struct ip6m_binding_error *)mh6,
		    mh6len) != 0)
			return (IPPROTO_DONE);
		break;

	default:
		/*
		 * if we receive a MH packet which type is unknown,
		 * send a binding error message.
		 */
		n = ip6_findaux(m);
		if (n) {
			struct ip6aux *ip6a;
			struct sockaddr_in6 src_sa;
			struct sockaddr_in6 *home_sa, sin6;

			ip6a = mtod(n, struct ip6aux *);
			src_sa = ip6a->ip6a_src;
			home_sa = &ip6a->ip6a_src;
			if ((ip6a->ip6a_flags & IP6A_HASEEN) != 0) {
				/*
				 * HAO exists and swapped already at
				 * this point.  send a binding error
				 * to CoA of the sending node.
				 */
				src_sa.sin6_addr = ip6a->ip6a_coa;
			} else {
				/*
				 * if no HAO exists, the home address
				 * field of the binding error message
				 * must be an unspecified address.
				 */
				bzero(&sin6, sizeof(sin6));
				sin6.sin6_family = AF_INET6;
				sin6.sin6_len = sizeof(sin6);
				sin6.sin6_addr = in6addr_any;
				home_sa = &sin6;
			}
			(void)mobility6_send_be(&ip6a->ip6a_dst, &src_sa,
			    IP6ME_STATUS_UNKNOWN_MH_TYPE, home_sa);
		}
		m_freem(m);
		mip6stat.mip6s_unknowntype++;
		return (IPPROTO_DONE);
		break;
	}

	*offp = off;

	return (mh6->ip6m_pproto);
}

/*
 * send binding error message.
 * XXX duplicated code.  see dest6_send_be().
 */
int
mobility6_send_be(src, dst, status, home)
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	u_int8_t status;
	struct sockaddr_in6 *home;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	/*
	 * XXX a binding message must be rate limited (per host?).
	 */

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(src, dst, IPPROTO_NONE, 0);
	if (m == NULL)
		return (ENOMEM);

	error = mip6_ip6me_create(&opt.ip6po_mobility, src, dst, status, home);
	if (error) {
		m_freem(m);
		goto free_ip6pktopts;
	}

	/* output a binding missing message. */
	mip6stat.mip6s_obe++;
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error)
		goto free_ip6pktopts;

 free_ip6pktopts:
	if (opt.ip6po_mobility)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (error);
}
