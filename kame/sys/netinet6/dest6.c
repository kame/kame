/*	$KAME: dest6.c,v 1.41 2002/06/08 19:52:07 itojun Exp $	*/

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
#include <netinet6/scope6_var.h>

#ifdef MIP6
#include <net/if_hif.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>
#endif /* MIP6 */

#ifdef MIP6
static int	dest6_send_bm __P((struct sockaddr_in6 *,
				   struct sockaddr_in6 *,
				   struct sockaddr_in6 *));
#endif /* MIP6 */

#ifdef MIP6
extern struct mip6_bc_list mip6_bc_list;
#endif /* MIP6 */

/*
 * Destination options header processing.
 */
int
dest6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	int off = *offp, dstoptlen, optlen;
	struct ip6_dest *dstopts;
	struct mbuf *n;
	struct ip6_opt_home_address *haopt = NULL;
	struct sockaddr_in6 *src_sa, *dst_sa, home_sa;
	struct ip6aux *ip6a = NULL;
	u_int8_t *opt;
	struct ip6_hdr *ip6;

	ip6 = mtod(m, struct ip6_hdr *);

	/* validation of the length of the header */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(*dstopts), IPPROTO_DONE);
	dstopts = (struct ip6_dest *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(dstopts, struct ip6_dest *, m, off, sizeof(*dstopts));
	if (dstopts == NULL)
		return IPPROTO_DONE;
#endif
	dstoptlen = (dstopts->ip6d_len + 1) << 3;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, dstoptlen, IPPROTO_DONE);
	dstopts = (struct ip6_dest *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(dstopts, struct ip6_dest *, m, off, dstoptlen);
	if (dstopts == NULL)
		return IPPROTO_DONE;
#endif
	off += dstoptlen;
	dstoptlen -= sizeof(struct ip6_dest);
	opt = (u_int8_t *)dstopts + sizeof(struct ip6_dest);

	/* search header for all options. */
	for (optlen = 0; dstoptlen > 0; dstoptlen -= optlen, opt += optlen) {
		if (*opt != IP6OPT_PAD1 &&
		    (dstoptlen < IP6OPT_MINLEN || *(opt + 1) + 2 > dstoptlen)) {
			ip6stat.ip6s_toosmall++;
			goto bad;
		}

		switch (*opt) {
		case IP6OPT_PAD1:
			optlen = 1;
			break;
		case IP6OPT_PADN:
			optlen = *(opt + 1) + 2;
			break;
		case IP6OPT_HOME_ADDRESS:
			/* HA option must appear only once */
			n = ip6_addaux(m);
			if (!n) {
				/* not enough core */
				goto bad;
			}
			ip6a = mtod(n, struct ip6aux *);
			if ((ip6a->ip6a_flags & IP6A_HASEEN) != 0) {
				/* XXX icmp6 paramprob? */
				goto bad;
			}

			haopt = (struct ip6_opt_home_address *)opt;
			optlen = haopt->ip6oh_len + 2;

			if (optlen != sizeof(*haopt)) {
				ip6stat.ip6s_toosmall++;
				goto bad;
			}

			/* XXX check header ordering */

			if (ip6_getpktaddrs(m, &src_sa, &dst_sa)) {
				/* must not happen. */
				goto bad;
			}
			bzero(&home_sa, sizeof(home_sa));
			home_sa.sin6_len = sizeof(home_sa);
			home_sa.sin6_family = AF_INET6;
			bcopy(haopt->ip6oh_addr, &home_sa.sin6_addr,
			      sizeof(struct in6_addr));
			if (scope6_check_id(&home_sa, ip6_use_defzone)
			    != 0)
				goto bad;

#ifdef MIP6
			/* check whether this HAO is 'verified'. */
			if (mip6_bc_list_find_withphaddr(
				&mip6_bc_list, &home_sa) != NULL) {
				/*
				 * we have a corresponding binding
				 * cache entry for the home address
				 * includes in this HAO.
				 */
				goto verified;
			}
			/* next, check if we have a ESP header.  */
#if 0
			if (dstopts->ip6d_nxt == IPPROTO_ESP) {
				/*
				 * this packet is protected by ESP.
				 * leave the validation to the ESP
				 * processing routine.
				 */
				goto verified;
			}
#else
			goto verified;
#endif
			/*
			 * we have neither a corresponding binding
			 * cache nor ESP header. we have no clue to
			 * beleive this HAO is a correct one.
			 */
			(void)dest6_send_bm(dst_sa, src_sa, &home_sa);
			goto bad;
		verified:
#endif /* MIP6 */

			/* store the CoA in a aux. */
			bcopy(&ip6a->ip6a_src.sin6_addr, &ip6a->ip6a_coa, 
			    sizeof(ip6a->ip6a_coa));
			ip6a->ip6a_flags |= IP6A_HASEEN;

			/*
			 * reject invalid home-addresses
			 */
			/* XXX linklocal-address is not supported */
			if (IN6_IS_ADDR_MULTICAST(&home_sa.sin6_addr) ||
			    IN6_IS_ADDR_LINKLOCAL(&home_sa.sin6_addr) ||
			    IN6_IS_ADDR_V4MAPPED(&home_sa.sin6_addr)  ||
			    IN6_IS_ADDR_UNSPECIFIED(&home_sa.sin6_addr) ||
			    IN6_IS_ADDR_LOOPBACK(&home_sa.sin6_addr)) {
				ip6stat.ip6s_badscope++;
				goto bad;
			}

			/*
			 * Currently, no valid sub-options are
			 * defined for use in a Home Address option.
			 */

			break;

		default:		/* unknown option */
			optlen = ip6_unknown_opt(opt, m,
			    opt - mtod(m, u_int8_t *));
			if (optlen == -1)
				return (IPPROTO_DONE);
			optlen += 2;
			break;
		}
	}

	/* if haopt is non-NULL, we are sure we have seen fresh HA option */
	if (haopt && ip6a &&
	    (ip6a->ip6a_flags & (IP6A_HASEEN | IP6A_SWAP)) == IP6A_HASEEN) {
		/* XXX should we do this at all?  do it now or later? */
		/* XXX interaction with 2292bis IPV6_RECVDSTOPT */
		/* XXX interaction with ipsec - should be okay */
		/* XXX icmp6 responses is modified - which is bad */
		bcopy(haopt->ip6oh_addr, &ip6->ip6_src,
		    sizeof(ip6->ip6_src));
		bcopy(haopt->ip6oh_addr, &ip6a->ip6a_src.sin6_addr,
		    sizeof(ip6a->ip6a_src.sin6_addr));
		bcopy(&ip6a->ip6a_coa, haopt->ip6oh_addr,
		    sizeof(haopt->ip6oh_addr));
#if 0
		/* XXX linklocal address is (currently) not supported */
		if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
			ip6->ip6_src.s6_addr16[1]
				= htons(m->m_pkthdr.rcvif->if_index);
#endif
		ip6a->ip6a_flags |= IP6A_SWAP;
	}

	*offp = off;
	return (dstopts->ip6d_nxt);

  bad:
	m_freem(m);
	return (IPPROTO_DONE);
}

#ifdef MIP6
/*
 * send a binding missing message.
 */
static int
dest6_send_bm(src, dst, home)
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
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

	error = mip6_ip6me_create(&opt.ip6po_mobility, src, dst,
				  IP6ME_STATUS_NO_BINDING, home);
	if (error) {
		m_freem(m);
		goto free_ip6pktopts;
	}
				  
	/* output a binding missing message. */
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error)
		goto free_ip6pktopts;

 free_ip6pktopts:
	if (opt.ip6po_mobility)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (error);
}
#endif /* MIP6 */
