/*	$KAME: mobility6.c,v 1.34 2004/05/26 07:41:32 itojun Exp $	*/

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
#include <sys/socketvar.h>
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
#ifdef __NetBSD__
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/icmp6.h>

#ifdef __FreeBSD__
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#elif defined(__OpenBSD__)
#include <netinet/in_pcb.h>
#else
#include <netinet6/in6_pcb.h>
#endif

#ifdef MIP6
#include <netinet/ip6mh.h>
#include <net/if_hif.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#ifdef MIP6_MOBILE_NODE
#include <netinet6/mip6_mncore.h>
#endif /* MIP6_MOBILE_NODE */
#endif /* MIP6 */

#include <net/net_osdep.h>

#if defined (__OpenBSD__)
extern struct inpcbtable rawin6pcbtable;
#elif !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
extern struct in6pcb rawin6pcb;
#else
extern struct inpcbhead ripcb;
#endif

static struct timeval ip6me_ppslim_last;
static int ip6me_pps_count = 0;
static int ip6me_ppslim = 60; /* XXX must be configurable. */

static int mobility6_be_ratelimit(const struct in6_addr *,
    const struct in6_addr *, const int);
static int mobility6_rip6_input(struct mbuf **, int);

/*
 * Mobility header processing.
 */
int
mobility6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	struct m_tag *n; /* for ip6aux */
	struct ip6_hdr *ip6;
	struct ip6_mh *mh;
	int off = *offp, mhlen;
	int sum;

	mip6stat.mip6s_mobility++;

	ip6 = mtod(m, struct ip6_hdr *);

	/* validation of the length of the header */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(*mh), IPPROTO_DONE);
	mh = (struct ip6_mh *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(mh, struct ip6_mh *, m, off, sizeof(*mh));
	if (mh == NULL)
		return (IPPROTO_DONE);
#endif
	mhlen = (mh->ip6mh_len + 1) << 3;
	if (mhlen < IP6M_MINLEN) {
		/* too small */
		ip6stat.ip6s_toosmall++;
		/* 9.2 discard and SHOULD send ICMP Parameter Problem */
		icmp6_error(m, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_HEADER,
			    (caddr_t)&mh->ip6mh_len - (caddr_t)ip6);
		return (IPPROTO_DONE);
	}

	if (mh->ip6mh_proto != IPPROTO_NONE) {
		mip6log((LOG_INFO, "%s:%d: Payload Proto %d.\n",
			__FILE__, __LINE__, mh->ip6mh_proto));
		/* 9.2 discard and SHOULD send ICMP Parameter Problem */
		mip6stat.mip6s_payloadproto++;
		icmp6_error(m, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_HEADER,
			    (caddr_t)&mh->ip6mh_proto - (caddr_t)ip6);
		return (IPPROTO_DONE);
	}

	/*
	 * calculate the checksum
	 */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, mhlen, IPPROTO_DONE);
	mh = (struct ip6_mh *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(mh, struct ip6_mh *, m, off, mhlen);
	if (mh == NULL)
		return (IPPROTO_DONE);
#endif
	if ((sum = in6_cksum(m, IPPROTO_MH, off, mhlen)) != 0) {
		mip6log((LOG_ERR,
		    "%s:%d: Mobility Header checksum error(%d|%x) %s\n",
		    __FILE__, __LINE__,
		    mh->ip6mh_type, sum, ip6_sprintf(&ip6->ip6_src)));
		m_freem(m);
		mip6stat.mip6s_checksum++;
		return (IPPROTO_DONE);
	}

	off += mhlen;

	/* XXX sanity check. */

	switch (mh->ip6mh_type) {
	case IP6_MH_TYPE_HOTI:
		if (mip6_ip6mhi_input(m, (struct ip6_mh_home_test_init *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6_MH_TYPE_COTI:
		if (mip6_ip6mci_input(m, (struct ip6_mh_careof_test_init *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;

#if defined(MIP6) && defined(MIP6_MOBILE_NODE)
	case IP6_MH_TYPE_HOT:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6mh_input(m, (struct ip6_mh_home_test *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6_MH_TYPE_COT:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6mc_input(m, (struct ip6_mh_careof_test *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6_MH_TYPE_BRR:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6mr_input(m, (struct ip6_mh_binding_request *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6_MH_TYPE_BACK:
		if (!MIP6_IS_MN)
			break;
		if (mip6_ip6ma_input(m, (struct ip6_mh_binding_ack *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;

	case IP6_MH_TYPE_BERROR:
		if (mip6_ip6me_input(m, (struct ip6_mh_binding_error *)mh,
		    mhlen) != 0)
			return (IPPROTO_DONE);
		break;
#endif /* MIP6 && MIP6_MOBILE_NODE */

	case IP6_MH_TYPE_BU:
		if (mip6_ip6mu_input(m, (struct ip6_mh_binding_update *)mh,
		    mhlen) != 0)
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
			struct in6_addr src, home;

			ip6a = (struct ip6aux *) (n + 1);
			src = ip6->ip6_src;
			if ((ip6a->ip6a_flags & IP6A_HASEEN) != 0) {
				home = ip6->ip6_src;
				if ((ip6a->ip6a_flags & IP6A_SWAP) != 0) {
					/*
					 * HAO exists and swapped
					 * already at this point.
					 * send a binding error to CoA
					 * of the sending node.
					 */
					src = ip6a->ip6a_coa;
				} else {
					/*
					 * HAO exists but not swapped
					 * yet.
					 */
					home = ip6a->ip6a_coa;
				}
			} else {
				/*
				 * if no HAO exists, the home address
				 * field of the binding error message
				 * must be an unspecified address.
				 */
				home = in6addr_any;
			}
			(void)mobility6_send_be(&ip6->ip6_dst, &src,
			    IP6_MH_BES_UNKNOWN_MH, &home);
		}
		mip6stat.mip6s_unknowntype++;
		break;
	}

	/* deliver the packet to appropriate sockets */
	if (mobility6_rip6_input(&m, *offp) == IPPROTO_DONE) {
		/* in error case, IPPROTO_DONE is returned. */
		return (IPPROTO_DONE);
	}

	*offp = off;

	return (mh->ip6mh_proto);
}

/*
 * send a binding error message.
 */
int
mobility6_send_be(src, dst, status, home)
	struct in6_addr *src;
	struct in6_addr *dst;
	u_int8_t status;
	struct in6_addr *home;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	/* a binding message must be rate limited. */
	if (mobility6_be_ratelimit(dst, home, status))
		return (0); /* rate limited. */

	ip6_initpktopts(&opt);

	m = mip6_create_ip6hdr(src, dst, IPPROTO_NONE, 0);
	if (m == NULL)
		return (ENOMEM);

	error = mip6_ip6me_create(&opt.ip6po_mh, src, dst, status, home);
	if (error) {
		m_freem(m);
		goto free_ip6pktopts;
	}

	/* output a binding missing message. */
	mip6stat.mip6s_obe++;
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  );
	if (error)
		goto free_ip6pktopts;

 free_ip6pktopts:
	if (opt.ip6po_mh)
		FREE(opt.ip6po_mh, M_IP6OPT);

	return (error);
}

static int
mobility6_be_ratelimit(dst, hoa, status)
	const struct in6_addr *dst;	/* not used at this moment */
	const struct in6_addr *hoa;	/* not used at this moment */
	const int status;		/* not used at this moment */
{
	int ret;

	ret = 0;	/* okay to send */

	/* PPS limit */
	if (!ppsratecheck(&ip6me_ppslim_last, &ip6me_pps_count,
	    ip6me_ppslim)) {
		/* The packet is subject to rate limit */
		ret++;
	}

	return ret;
}

static int
mobility6_rip6_input(mp, off)
	struct mbuf **mp;
	int off;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
	struct ip6_mh *mh;
	struct sockaddr_in6 fromsa;
	struct in6pcb *in6p;
	struct in6pcb *last = NULL;
	struct mbuf *opts = NULL;

	ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
	/* this is assumed to be safe. */
	mh = (struct ip6_mh *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(mh, struct ip6_mh *, m, off, sizeof(*mh));
	if (mh == NULL) {
		/* m is already reclaimed */
		return (IPPROTO_DONE);
	}
#endif
		
	/*
	 * XXX: the address may have embedded scope zone ID, which should be
	 * hidden from applications.
	 */
	bzero(&fromsa, sizeof(fromsa));
	fromsa.sin6_family = AF_INET6;
	fromsa.sin6_len = sizeof(struct sockaddr_in6);
	if (in6_recoverscope(&fromsa, &ip6->ip6_src, m->m_pkthdr.rcvif) != 0) {
		m_freem(m);
		return (IPPROTO_DONE);
	}

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	LIST_FOREACH(in6p, &ripcb, inp_list)
#elif defined(__OpenBSD__)
	for (in6p = rawin6pcbtable.inpt_queue.cqh_first;
	     in6p != (struct inpcb *)&rawin6pcbtable.inpt_queue;
	     in6p = in6p->inp_queue.cqe_next)
#else
	for (in6p = rawin6pcb.in6p_next;
	     in6p != &rawin6pcb; in6p = in6p->in6p_next)
#endif
	{
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		if ((in6p->inp_vflag & INP_IPV6) == 0)
			continue;
#endif
#ifdef __FreeBSD__
		if (in6p->inp_ip_p != IPPROTO_MH)
#else
		if (in6p->in6p_ip6.ip6_nxt != IPPROTO_MH)
#endif
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		if (last) {
			struct	mbuf *n = NULL;

			/*
			 * Recent network drivers tend to allocate a single
			 * mbuf cluster, rather than to make a couple of
			 * mbufs without clusters.  Also, since the IPv6 code
			 * path tries to avoid m_pullup(), it is highly
			 * probable that we still have an mbuf cluster here
			 * even though the necessary length can be stored in an
			 * mbuf's internal buffer.
			 * Meanwhile, the default size of the receive socket
			 * buffer for raw sockets is not so large.  This means
			 * the possibility of packet loss is relatively higher
			 * than before.  To avoid this scenario, we copy the
			 * received data to a separate mbuf that does not use
			 * a cluster, if possible.
			 * XXX: it is better to copy the data after stripping
			 * intermediate headers.
			 */
			if ((m->m_flags & M_EXT) && m->m_next == NULL &&
			    m->m_len <= MHLEN) {
				MGET(n, M_DONTWAIT, m->m_type);
				if (n != NULL) {
#ifdef __OpenBSD__
					/* shouldn't this be M_DUP_PKTHDR? */
					M_MOVE_PKTHDR(n, m);
#elif defined(__FreeBSD__)
					m_dup_pkthdr(n, m);
#else
					M_COPY_PKTHDR(n, m);
#endif
					bcopy(m->m_data, n->m_data, m->m_len);
					n->m_len = m->m_len;
				}
			}
			if (n != NULL ||
			    (n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if (last->in6p_flags & IN6P_CONTROLOPTS)
					ip6_savecontrol(last, n, &opts);
				/* strip intermediate headers */
				m_adj(n, off);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
				    (struct sockaddr *)&fromsa, n, opts)
				    == 0) {
					/* should notify about lost packet */
					m_freem(n);
					if (opts) {
						m_freem(opts);
					}
				} else
					sorwakeup(last->in6p_socket);
				opts = NULL;
			}
		}
		last = in6p;
	}
	if (last) {
		if (last->in6p_flags & IN6P_CONTROLOPTS)
			ip6_savecontrol(last, m, &opts);
		/* strip intermediate headers */
		m_adj(m, off);

		/* avoid using mbuf clusters if possible (see above) */
		if ((m->m_flags & M_EXT) && m->m_next == NULL &&
		    m->m_len <= MHLEN) {
			struct mbuf *n;

			MGET(n, M_DONTWAIT, m->m_type);
			if (n != NULL) {
#ifdef __OpenBSD__
				/* shouldn't this be M_DUP_PKTHDR? */
				M_MOVE_PKTHDR(n, m);
#elif defined(__FreeBSD__)
				m_dup_pkthdr(n, m);
#else
				M_COPY_PKTHDR(n, m);
#endif
				bcopy(m->m_data, n->m_data, m->m_len);
				n->m_len = m->m_len;

				m_freem(m);
				m = n;
			}
		}
		if (sbappendaddr(&last->in6p_socket->so_rcv,
		    (struct sockaddr *)&fromsa, m, opts) == 0) {
			m_freem(m);
			if (opts)
				m_freem(opts);
		} else
			sorwakeup(last->in6p_socket);
	} else {
		m_freem(m);
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}
