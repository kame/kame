/*	$KAME: dest6.c,v 1.67 2004/05/24 11:29:08 itojun Exp $	*/

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

#ifdef __FreeBSD__
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
#ifdef __NetBSD__
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/icmp6.h>
#include <netinet6/scope6_var.h>

#ifdef MIP6
#include <netinet/ip6mh.h>
#include <net/if_hif.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#endif /* MIP6 */

#ifdef MIP6
static int	dest6_swap_hao __P((struct ip6_hdr *, struct ip6aux *,
				    struct ip6_opt_home_address *));
static int	dest6_nextopt __P((struct mbuf *, int, struct ip6_opt *));
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
	u_int8_t *opt;
#ifdef MIP6
	struct m_tag *n;
	struct in6_addr home;
	struct ip6_opt_home_address *haopt = NULL;
	struct ip6aux *ip6a = NULL;
	struct ip6_hdr *ip6;
	struct mip6_bc *mbc;
	int verified = 0;

	ip6 = mtod(m, struct ip6_hdr *);
#endif

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
#ifdef MIP6
		case IP6OPT_HOME_ADDRESS:
			/* HAO must appear only once */
			n = ip6_addaux(m);
			if (!n) {
				/* not enough core */
				goto bad;
			}
			ip6a = (struct ip6aux *) (n + 1);
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

			bcopy(haopt->ip6oh_addr, &home,
			    sizeof(struct in6_addr));

			bcopy(&home, &ip6a->ip6a_coa, sizeof(ip6a->ip6a_coa));
			ip6a->ip6a_flags |= IP6A_HASEEN;

			mip6stat.mip6s_hao++;

			/* check whether this HAO is 'verified'. */
			if ((mbc = mip6_bc_list_find_withphaddr(
				&mip6_bc_list, &home)) != NULL) {
				/*
				 * we have a corresponding binding
				 * cache entry for the home address
				 * includes in this HAO.
				 */
				if (IN6_ARE_ADDR_EQUAL(&mbc->mbc_pcoa,
				    &ip6->ip6_src))
					verified = 1;
			}
			/*
			 * we have neither a corresponding binding
			 * cache nor ESP header. we have no clue to
			 * beleive this HAO is a correct one.
			 */
			/*
			 * Currently, no valid sub-options are
			 * defined for use in a Home Address option.
			 */

			break;
#endif /* MIP6 */
		default:		/* unknown option */
			optlen = ip6_unknown_opt(opt, m,
			    opt - mtod(m, u_int8_t *));
			if (optlen == -1)
				return (IPPROTO_DONE);
			optlen += 2;
			break;
		}
	}

#ifdef MIP6
	/* if haopt is non-NULL, we are sure we have seen fresh HA option */
	if (verified)
		if (dest6_swap_hao(ip6, ip6a, haopt) < 0)
			goto bad;
#endif /* MIP6 */

	*offp = off;
	return (dstopts->ip6d_nxt);

  bad:
	m_freem(m);
	return (IPPROTO_DONE);
}

#ifdef MIP6
static int
dest6_swap_hao(ip6, ip6a, haopt)
	struct ip6_hdr *ip6;
	struct ip6aux *ip6a;
	struct ip6_opt_home_address *haopt;
{

	if ((ip6a->ip6a_flags & (IP6A_HASEEN | IP6A_SWAP)) != IP6A_HASEEN)
		return (EINVAL);

	/* XXX should we do this at all?  do it now or later? */
	/* XXX interaction with 2292bis IPV6_RECVDSTOPT */
	/* XXX interaction with ipsec - should be okay */
	/* XXX icmp6 responses is modified - which is bad */
	bcopy(&ip6->ip6_src, &ip6a->ip6a_coa, sizeof(ip6a->ip6a_coa));
	bcopy(haopt->ip6oh_addr, &ip6->ip6_src, sizeof(ip6->ip6_src));
	bcopy(&ip6a->ip6a_coa, haopt->ip6oh_addr, sizeof(haopt->ip6oh_addr));
#if 0
	/* XXX linklocal address is (currently) not supported */
	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
		ip6->ip6_src.s6_addr16[1] = htons(m->m_pkthdr.rcvif->if_index);
#endif
	ip6a->ip6a_flags |= IP6A_SWAP;

	return (0);
}

static int
dest6_nextopt(m, off, ip6o)
	struct mbuf *m;
	int off;
	struct ip6_opt *ip6o;
{
	u_int8_t type;

	if (ip6o->ip6o_type != IP6OPT_PAD1)
		off += 2 + ip6o->ip6o_len;
	else
		off += 1;
	if (m->m_pkthdr.len < off + 1)
		return -1;
	m_copydata(m, off, sizeof(type), (caddr_t)&type);

	switch (type) {
	case IP6OPT_PAD1:
		ip6o->ip6o_type = type;
		ip6o->ip6o_len = 0;
		return off;
	default:
		if (m->m_pkthdr.len < off + 2)
			return -1;
		m_copydata(m, off, sizeof(ip6o), (caddr_t)ip6o);
		if (m->m_pkthdr.len < off + 2 + ip6o->ip6o_len)
			return -1;
		return off;
	}
}

int
dest6_mip6_hao(m, mhoff, nxt)
	struct mbuf *m;
	int mhoff, nxt;
{
	struct ip6_hdr *ip6;
	struct ip6aux *ip6a;
	struct ip6_opt ip6o;
	struct m_tag *n;
	struct in6_addr home;
	struct ip6_opt_home_address haopt;
	struct ip6_mh mh;
	int newoff, off, proto, swap;

	/* XXX should care about destopt1 and destopt2.  in destopt2,
           hao and src must be swapped. */
	if ((nxt == IPPROTO_HOPOPTS) || (nxt == IPPROTO_DSTOPTS)) {
		return (0);
	}
	n = ip6_findaux(m);
	if (!n)
		return (0);
	ip6a = (struct ip6aux *) (n + 1);

	if ((ip6a->ip6a_flags & (IP6A_HASEEN | IP6A_SWAP)) != IP6A_HASEEN)
		return (0);

	ip6 = mtod(m, struct ip6_hdr *);
	/* find home address */
	off = 0;
	proto = IPPROTO_IPV6;
	while (1) {
		int nxt;
		newoff = ip6_nexthdr(m, off, proto, &nxt);
		if (newoff < 0 || newoff < off)
			return (0);	/* XXX */
		off = newoff;
		proto = nxt;
		if (proto == IPPROTO_DSTOPTS)
			break;
	}
	ip6o.ip6o_type = IP6OPT_PADN;
	ip6o.ip6o_len = 0;
	while (1) {
		newoff = dest6_nextopt(m, off, &ip6o);
		if (newoff < 0)
			return (0);	/* XXX */
		off = newoff;
		if (ip6o.ip6o_type == IP6OPT_HOME_ADDRESS)
			break;
	}
	m_copydata(m, off, sizeof(struct ip6_opt_home_address),
	    (caddr_t)&haopt);

	swap = 0;
	if (nxt == IPPROTO_AH || nxt == IPPROTO_ESP)
		swap = 1;
	if (nxt == IPPROTO_MH) {
		m_copydata(m, mhoff, sizeof(mh), (caddr_t)&mh);
		if (mh.ip6mh_type == IP6_MH_TYPE_BU)
			swap = 1;
		else if (mh.ip6mh_type == IP6_MH_TYPE_HOTI ||
			 mh.ip6mh_type == IP6_MH_TYPE_COTI)
			return (-1);
		else if (mh.ip6mh_type > IP6_MH_TYPE_MAX)
			swap = 1;	/* must be sent BE with UNRECOGNIZED_TYPE */
	}

	home = *(struct in6_addr *)haopt.ip6oh_addr;
	/*
	 * reject invalid home-addresses
	 */
	if (IN6_IS_ADDR_MULTICAST(&home) ||
	    IN6_IS_ADDR_LINKLOCAL(&home) ||
	    IN6_IS_ADDR_V4MAPPED(&home)  ||
	    IN6_IS_ADDR_UNSPECIFIED(&home) ||
	    IN6_IS_ADDR_LOOPBACK(&home)) {
		ip6stat.ip6s_badscope++;
		if (!(nxt == IPPROTO_MH && mh.ip6mh_type == IP6_MH_TYPE_BU)) {
			/* BE is sent only when the received packet is 
			   not BU */
			(void)mobility6_send_be(&ip6->ip6_dst, &ip6->ip6_src, 
			    IP6_MH_BES_UNKNOWN_HAO, &home);
		}
		return (-1);
	}

	if (swap) {
		int error;
		error = dest6_swap_hao(ip6, ip6a, &haopt);
		if (error)
			return (error);
		m_copyback(m, off, sizeof(struct ip6_opt_home_address),
		    (caddr_t)&haopt);		/* XXX */
		return (0);
	}

	/* reject */
	mip6stat.mip6s_unverifiedhao++;
	mobility6_send_be(&ip6->ip6_dst, &ip6->ip6_src,
	    IP6_MH_BES_UNKNOWN_HAO, &home);

	return (-1);
}
#endif /* MIP6 */
