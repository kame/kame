/*	$KAME: mip6_icmp6.c,v 1.54 2002/10/09 17:24:46 itojun Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_ipsec.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#elif defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet/in_pcb.h>
#else
#include <netinet6/in6_pcb.h>
#endif

#ifdef IPSEC
#ifdef __OpenBSD__
#include <netinet/ip_ah.h>
#include <netinet/ip_esp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#else
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif /* IPSEC */

#include <net/if_hif.h>

#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>

extern struct mip6_bc_list mip6_bc_list;
extern struct mip6_subnet_list mip6_subnet_list;

u_int16_t mip6_hadiscovid = 0;

static const struct sockaddr_in6 haanyaddr_ifid64 = {
	sizeof(struct sockaddr_in6),	/* sin6_len */
	AF_INET6,			/* sin6_family */
	0,				/* sin6_port */
	0,				/* sin6_flowinfo */
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}},
	0				/* sin6_scope_id */
};
static const struct sockaddr_in6 haanyaddr_ifidnn = {
	sizeof(struct sockaddr_in6),	/* sin6_len */
	AF_INET6,			/* sin6_family */
	0,				/* sin6_port */
	0,				/* sin6_flowinfo */
	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}},
	0				/* sin6_scope_id */
};

static void mip6_icmp6_find_addr __P((struct mbuf *, int, int,
				      struct sockaddr_in6 *,
				      struct sockaddr_in6 *));
static int mip6_icmp6_ha_discov_rep_input __P((struct mbuf *, int, int));
static int mip6_ha_discov_ha_list_insert __P((struct hif_softc *,
					      struct mip6_ha *));
static int mip6_icmp6_create_haanyaddr __P((struct sockaddr_in6 *,
					    struct mip6_prefix *));
static int mip6_icmp6_create_linklocal __P((struct in6_addr *,
					    struct in6_addr *));

int
mip6_icmp6_input(m, off, icmp6len)
	struct mbuf *m;
	int off;
	int icmp6len;
{
	struct ip6_hdr *ip6;
	caddr_t origip6;
	struct icmp6_hdr *icmp6;
	u_int32_t pptr;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	struct mip6_bc *mbc;
	struct sockaddr_in6 laddr, paddr;
	int error = 0;

	/* header pullup/down is already done in icmp6_input(). */
	ip6 = mtod(m, struct ip6_hdr *);
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		/*
		 * the contacting mobile node might move to somewhere.
		 * in current code, we remove the corresponding
		 * binding cache entry immediately.  should we be more
		 * patient?
		 */
		IP6_EXTHDR_CHECK(m, off, icmp6len, EINVAL);
		mip6_icmp6_find_addr(m, off, icmp6len, &laddr, &paddr);
		mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &paddr);
		if (mbc && (mbc->mbc_flags & IP6MU_HOME) == 0) {
			mip6log((LOG_INFO,
				 "%s:%d: "
				 "a mobile node (%s) moved.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(&paddr.sin6_addr)));
			mip6_bc_list_remove(&mip6_bc_list, mbc);
		}
		break;

	case ICMP6_HADISCOV_REPLY:
		if (!MIP6_IS_MN)
			break;
		error = mip6_icmp6_ha_discov_rep_input(m, off, icmp6len);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: failed to process a DHAAD reply.\n",
				 __FILE__, __LINE__));
			return (error);
		}
		break;

	case ICMP6_MOBILEPREFIX_SOLICIT:
		if (!MIP6_IS_HA)
			break;
		/* XXX: TODO */
		break;

	case ICMP6_MOBILEPREFIX_ADVERT:
		if (!MIP6_IS_MN)
			break;
		/* XXX: TODO */
		break;

	case ICMP6_PARAM_PROB:
		if (!MIP6_IS_MN)
			break;

		pptr = ntohl(icmp6->icmp6_pptr);
		if ((sizeof(*icmp6) + pptr + 1) > icmp6len) {
			/*
			 * we can't get the detail of the
			 * packet, ignore this...
			 */
			break;
		}

		switch (icmp6->icmp6_code) {
		case ICMP6_PARAMPROB_OPTION:
			/*
			 * XXX: TODO
			 *
			 * should we mcopydata??
			 */
			origip6 = (caddr_t)(icmp6 + 1);
			switch (*(u_int8_t *)(origip6 + pptr)) {
			case IP6OPT_HOME_ADDRESS:
				/*
				 * the peer doesn't recognize HAO.
				 */
				mip6stat.mip6s_paramprobhao++;

				IP6_EXTHDR_CHECK(m, off, icmp6len, EINVAL);
				mip6_icmp6_find_addr(m, off, icmp6len,
						     &laddr, &paddr);
				mip6log((LOG_NOTICE,
					 "%s:%d: a node (%s) doesn't support a home address destopt.\n",
					 __FILE__, __LINE__,
					 ip6_sprintf(&paddr.sin6_addr)));
				/*
				 * if the peer doesn't support HAO, we
				 * must use bi-directional tunneling
				 * to contiue communication.
				 */
				for (sc = TAILQ_FIRST(&hif_softc_list);
				     sc;
				     sc = TAILQ_NEXT(sc, hif_entry)) {
					mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &paddr, &laddr);
					mip6_bu_fsm(mbu, MIP6_BU_FSM_EVENT_ICMP_PARAMPROB_RECEIVED, NULL);
				}
				break;
			}
			break;

		case ICMP6_PARAMPROB_NEXTHEADER:
			origip6 = (caddr_t)(icmp6 + 1);
			switch (*(u_int8_t *)(origip6 + pptr)) {
			case IPPROTO_MOBILITY:
				/*
				 * the peer doesn't recognize mobility header.
				 */
				mip6stat.mip6s_paramprobmh++;

				IP6_EXTHDR_CHECK(m, off, icmp6len, EINVAL);
				mip6_icmp6_find_addr(m, off, icmp6len,
						     &laddr, &paddr);
				mip6log((LOG_NOTICE,
					 "%s:%d: a node (%s) doesn't support "
					 "Mobile IPv6.\n",
					 __FILE__, __LINE__,
					 ip6_sprintf(&paddr.sin6_addr)));
				for (sc = TAILQ_FIRST(&hif_softc_list);
				     sc;
				     sc = TAILQ_NEXT(sc, hif_entry)) {
					mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &paddr, &laddr);
					mip6_bu_fsm(mbu, MIP6_BU_FSM_EVENT_ICMP_PARAMPROB_RECEIVED, NULL);
				}
				break;
			}
			break;
		}
		break;
	}

	return (0);
}

int
mip6_icmp6_tunnel_input(m, off, icmp6len)
	struct mbuf *m;
	int off;
	int icmp6len;
{
	struct mbuf *n;
	struct ip6_hdr *ip6, *otip6, oip6, *nip6;
	int otip6off, nxt;
	struct sockaddr_in6 oip6dst;
	struct icmp6_hdr *icmp6, *nicmp6;
	struct mip6_bc *mbc;
	int error = 0;

	if (!MIP6_IS_HA) {
		/*
		 * this check is needed only for a node that is acting
		 * as a homeagent.
		 */
		return (0);
	}

	/* check if we have enough icmp payload size. */
	if (icmp6len < sizeof(*otip6) + sizeof(oip6)) {
		/*
		 * we don't have enough size of icmp payload.  to
		 * determine that this icmp is against the tunneled
		 * ip, we at least have two ip header, one is for
		 * tunneling from the home agent to the correspondent
		 * node and the other is the original header from the
		 * mobile node to the correspondent node.
		 */
		return (0);
	}

	/*
	 * check if this icmp is generated on the way to sending from
	 * a home agent to a mobile node by encapsulating the original
	 * packet.  if so, relay this icmp to the sender of the
	 * original packet.
	 *
	 * the icmp packet against the encapsulated packet looks like
	 * as follows.
	 *
	 *   ip(src=??,dst=ha)
	 *     |icmp|ip(src=ha,dst=mncoa)|ip(src=cn,dst=mnhoa)|payload
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
	if (icmp6->icmp6_type >= 128) {
		/*
		 * this is not an icmp error message.  no need to
		 * relay.
		 */
		return (0);
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off + sizeof(*icmp6), sizeof(*otip6), EINVAL);
	otip6 = (struct ip6_hdr *)(mtod(m, caddr_t) + off + sizeof(*icmp6));
#else
	IP6_EXTHDR_GET(otip6, struct ip6_hdr *, m, off + sizeof(*icmp6),
		       sizeof(*otip6));
	if (otip6 == NULL)
		return (EINVAL);
#endif
	otip6off = off + sizeof(*icmp6) + sizeof(*otip6);
	nxt = otip6->ip6_nxt;
	while (nxt != IPPROTO_IPV6) {
		int off;

		off = otip6off;
		otip6off = ip6_nexthdr(m, off, nxt, &nxt);
		if ((otip6off < 0) ||
		    (otip6off < off) ||
		    (otip6off == off)) {
			/* too short or there is no ip hdr in this
			 * icmp payload. */
			return (0);
		}
		off = otip6off;
	}
	if (m->m_pkthdr.len < otip6off + sizeof(oip6)) {
		/* too short icmp packet. */
		return (0);
	}
	m_copydata(m, otip6off, sizeof(oip6), (caddr_t)&oip6);
	oip6dst.sin6_len = sizeof(oip6dst);
	oip6dst.sin6_family = AF_INET6;
	oip6dst.sin6_addr = oip6.ip6_dst;
	if (in6_addr2zoneid(m->m_pkthdr.rcvif, &oip6dst.sin6_addr,
			   &oip6dst.sin6_scope_id))
		return (0); /* XXX */

	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &oip6dst);
	if (mbc == NULL) {
		/* we are not a home agent of this mobile node ?? */
		return (0);
	}

	n = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf allocation failed.\n",
			 __FILE__, __LINE__));
		/* continue, anyway. */
		return (0);
	}
	m_adj(n, otip6off);
	M_PREPEND(n, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr),
		  M_DONTWAIT);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf prepend for ip6/icmp6 failed.\n",
			 __FILE__, __LINE__));
		/* continue. */
		return (0);
	}
	/* fill the ip6_hdr. */
	nip6 = mtod(n, struct ip6_hdr *);
	nip6->ip6_flow = 0;
	nip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	nip6->ip6_vfc |= IPV6_VERSION;
	nip6->ip6_plen = htons(n->m_pkthdr.len - sizeof(struct ip6_hdr));
	nip6->ip6_nxt = IPPROTO_ICMPV6;
	nip6->ip6_hlim = ip6_defhlim;
	nip6->ip6_src = ip6->ip6_dst;
	nip6->ip6_dst = oip6.ip6_src;

	/* fill the icmp6_hdr. */
	nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
	nicmp6->icmp6_type = icmp6->icmp6_type;
	nicmp6->icmp6_code = icmp6->icmp6_code;
	nicmp6->icmp6_data32[0] = icmp6->icmp6_data32[0];

	/* XXX modify icmp data in some case.  (ex. TOOBIG) */

	/* calculate the checksum. */
	nicmp6->icmp6_cksum = 0;
	nicmp6->icmp6_cksum = in6_cksum(n, IPPROTO_ICMPV6,
					sizeof(*nip6), ntohs(nip6->ip6_plen));

	/* XXX IPSEC? */

	if ((error = mip6_setpktaddrs(n)) != 0) { /* XXX */
		m_freem(n);
		return (0);
	}
	error = ip6_output(n, NULL, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: send failed. (errno = %d)\n",
			 __FILE__, __LINE__, error));
		/* continue processing 'm' (the original icmp). */
		return (0);
	}

	return (0);
}

static void
mip6_icmp6_find_addr(m, icmp6off, icmp6len, sin6local, sin6peer)
	struct mbuf *m;
	int icmp6off;
	int icmp6len; /* Total icmp6 payload length */
	struct sockaddr_in6 *sin6local; /* Local home address */
	struct sockaddr_in6 *sin6peer; /* Peer home address */
{
	caddr_t icmp6;
	struct ip6_opt_home_address *haddr_opt; /* Home Address option */
	struct ip6_hdr *ip6;                    /* IPv6 header */
	struct ip6_ext *ehdr;                   /* Extension header */
	struct in6_addr *la;                    /* Local home address */
	struct in6_addr *pa;                    /* Peer home address */
	struct ip6_rthdr2 *rh;                  /* Routing header */
	u_int8_t *eopt, nxt, optlen;
	int off, elen, eoff;
	int rlen, addr_off;

	icmp6 = mtod(m, caddr_t) + icmp6off;
	off = sizeof(struct icmp6_hdr);
	ip6 = (struct ip6_hdr *)(icmp6 + off);
	nxt = ip6->ip6_nxt;
	off += sizeof(struct ip6_hdr);

	la = &ip6->ip6_src;
	pa = &ip6->ip6_dst;

	/* Search original IPv6 header extensions for Routing Header type 0
	   and for home address option (if I'm a mobile node). */
	while ((off + 2) < icmp6len) {
		if (nxt == IPPROTO_DSTOPTS) {
			ehdr = (struct ip6_ext *)(icmp6 + off);
			elen = (ehdr->ip6e_len + 1) << 3;
			eoff = 2;
			eopt = icmp6 + off + eoff;
			while ((eoff + 2) < elen) {
				if (*eopt == IP6OPT_PAD1) {
					eoff += 1;
					eopt += 1;
					continue;
				}
				if (*eopt == IP6OPT_HOME_ADDRESS) {
					optlen = *(eopt + 1) + 2;
					if ((off + eoff + optlen) > icmp6len)
						break;

					haddr_opt = (struct ip6_opt_home_address *)eopt;
					la = (struct in6_addr *)
						haddr_opt->ip6oh_addr;
					eoff += optlen;
					eopt += optlen;
					continue;
				}
				eoff += *(eopt + 1) + 2;
				eopt += *(eopt + 1) + 2;
			}
			nxt = ehdr->ip6e_nxt;
			off += (ehdr->ip6e_len + 1) << 3;
			continue;
		}
		if (nxt == IPPROTO_ROUTING) {
			rh = (struct ip6_rthdr2 *)(icmp6 + off);
			rlen = (rh->ip6r2_len + 1) << 3;
			if ((off + rlen) > icmp6len) break;
			if ((rh->ip6r2_type != 2) || (rh->ip6r2_len % 2)) {
				nxt = rh->ip6r2_nxt;
				off += (rh->ip6r2_len + 1) << 3;
				continue;
			}

			addr_off = 8 + (((rh->ip6r2_len / 2) - 1) << 3);
			pa = (struct in6_addr *)(icmp6 + off + addr_off);

			nxt = rh->ip6r2_nxt;
			off += (rh->ip6r2_len + 1) << 3;
			continue;
		}
		if (nxt == IPPROTO_HOPOPTS) {
			ehdr = (struct ip6_ext *)(icmp6 + off);
			nxt = ehdr->ip6e_nxt;
			off += (ehdr->ip6e_len + 1) << 3;
			continue;
		}

		/* Only look at the unfragmentable part.  Other headers
		   may be present but they are of no interest. */
		break;
	}

	sin6local->sin6_len = sizeof(*sin6local);
	sin6local->sin6_family = AF_INET6;
	sin6local->sin6_addr = *la;
	in6_addr2zoneid(m->m_pkthdr.rcvif, &sin6local->sin6_addr,
			&sin6local->sin6_scope_id); /* XXX */

	sin6peer->sin6_len = sizeof(*sin6peer);
	sin6peer->sin6_family = AF_INET6;
	sin6peer->sin6_addr = *pa;
	in6_addr2zoneid(m->m_pkthdr.rcvif, &sin6peer->sin6_addr,
			&sin6peer->sin6_scope_id); /* XXX */
}

static int
mip6_icmp6_ha_discov_rep_input(m, off, icmp6len)
	struct mbuf *m;
	int off;
	int icmp6len;
{
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *sin6src, *sin6dst;
	struct ha_discov_rep *hdrep;
	u_int16_t hdrep_id;
	struct mip6_ha *mha, *mha_prefered = NULL;
	struct in6_addr *haaddrs, *haaddrptr;
	struct sockaddr_in6 lladdr;
	int i, hacount = 0, found = 0;
	struct hif_softc *sc;
	struct mip6_bu *mbu;

	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6_getpktaddrs(m, &sin6src, &sin6dst)) {
		m_freem(m);
		return (EINVAL);
	}
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len, EINVAL);
	hdrep = (struct ha_discov_rep *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(hdrep, struct ha_discov_rep *, m, off, icmp6len);
	if (hdrep == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: failed to EXTHDR_GET.\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}
#endif
	haaddrs = (struct in6_addr *)(hdrep + 1);

	/* sainty check. */
	if (hdrep->discov_rep_code != 0) {
		m_freem(m);
		return (EINVAL);
	}

	/* find hif that matches this receiving hadiscovid of DHAAD reply. */
	hdrep_id = hdrep->discov_rep_id;
	hdrep_id = ntohs(hdrep_id);
	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		if (sc->hif_hadiscovid == hdrep_id)
			break;
	}
	if (sc == NULL) {
		/*
		 * no matching hif.  maybe this DHAAD reply is too late.
		 */
		return (0);
	}

	/* reset rate limitation factor. */
	sc->hif_hadiscov_count = 0;

	/*
	 * check if the home agent list contains sending the home
	 * agent's own address.
	 */
	hacount = (icmp6len - sizeof(struct ha_discov_rep))
		/ sizeof(struct in6_addr);
	haaddrptr = haaddrs;
	for (i = 0; i < hacount; i++) {
		/* XXX: check if these addresses are global. */
		if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, haaddrptr)) {
			found = 1;
			break;
		}
		haaddrptr++;
	}

	/*
	 * install home agents to the internal home agent list.
	 */
	if (found == 0) {
		/*
		 * if the home agent list of the DHAAD reply doesn't
		 * include the address of ip6_src field (that is, the
		 * address of the home agent sending this DHAAD reply
		 * packet), the address is considered as a most
		 * preferable.
		 */
		/* XXX: TODO
		 *
		 * how do we make the HA specified in the ip src field
		 * as a most preferable one ?
		 */
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, sin6src);
		if (mha) {
			/*
			 * if this home agent already exists in the list,
			 * update its lifetime.
			 */
			/*
			 * XXX: TODO
			 *
			 * how to get the REAL lifetime of the home agent?
			 */
			mha->mha_lifetime = MIP6_HA_DEFAULT_LIFETIME; /* XXX */
		} else {
			/*
			 * create a new home agent entry and insert it
			 * to the internal home agent list
			 * (mip6_ha_list).
			 */
			/*
			 * XXX: TODO
			 *
			 * DHAAD reply doesn't include home agents'
			 * link-local addresses.  how we decide for
			 * each hoem agent link-local address?  and
			 * lifetime determination is a problem, also.
			 */
			bzero(&lladdr, sizeof(lladdr));
			lladdr.sin6_len = sizeof(lladdr);
			lladdr.sin6_family = AF_INET6;
			mip6_icmp6_create_linklocal(&lladdr.sin6_addr,
						    &sin6src->sin6_addr);
			in6_addr2zoneid(m->m_pkthdr.rcvif, &lladdr.sin6_addr,
					&lladdr.sin6_scope_id); /* XXX */
			mha = mip6_ha_create(&lladdr, sin6src,
					     ND_RA_FLAG_HOME_AGENT,
					     0, MIP6_HA_DEFAULT_LIFETIME);
			if (mha == NULL) {
				mip6log((LOG_ERR,
					 "%s:%d: mip6_ha create failed\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (ENOMEM);
			}
			mip6_ha_list_insert(&mip6_ha_list, mha);
			mip6_ha_discov_ha_list_insert(sc, mha);
		}
		mha_prefered = mha;
	}

	/* install HAs specified in the HA list */
	haaddrptr = haaddrs;
	for (i = 0; i < hacount; i++) {
		struct sockaddr_in6 haaddr;

		bzero(&haaddr, sizeof(haaddr));
		haaddr.sin6_len = sizeof(haaddr);
		haaddr.sin6_family = AF_INET6;
		haaddr.sin6_addr = *haaddrptr;
		in6_addr2zoneid(m->m_pkthdr.rcvif, &haaddr.sin6_addr,
				&haaddr.sin6_scope_id); /* XXX */
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, &haaddr);
		if (mha) {
			/* XXX: TODO the same problem above. */
			mha->mha_lifetime = MIP6_HA_DEFAULT_LIFETIME;
		} else {
			struct sockaddr_in6 haaddr;

			/* XXX: TODO the same problem above. */
			bzero(&lladdr, sizeof(lladdr));
			lladdr.sin6_len = sizeof(lladdr);
			lladdr.sin6_family = AF_INET6;
			mip6_icmp6_create_linklocal(&lladdr.sin6_addr,
						    haaddrptr);
			in6_addr2zoneid(m->m_pkthdr.rcvif, &lladdr.sin6_addr,
					&lladdr.sin6_scope_id);
			bzero(&haaddr, sizeof(haaddr));
			haaddr.sin6_len = sizeof(haaddr);
			haaddr.sin6_family = AF_INET6;
			haaddr.sin6_addr = *haaddrptr;
			in6_addr2zoneid(m->m_pkthdr.rcvif, &haaddr.sin6_addr,
					&haaddr.sin6_scope_id);
			mha = mip6_ha_create(&lladdr, &haaddr,
					     ND_RA_FLAG_HOME_AGENT,
					     0, MIP6_HA_DEFAULT_LIFETIME);
			if (mha == NULL) {
				mip6log((LOG_ERR,
					 "%s:%d: mip6_ha create failed\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (ENOMEM);
			}
			mip6_ha_list_insert(&mip6_ha_list, mha);
			mip6_ha_discov_ha_list_insert(sc, mha);
		}
		if (mha_prefered == NULL) {
			/*
			 * the home agent listed at the top of the
			 * DHAAD reply packet is the most preferable
			 * one.  of course, if the reply includes the
			 * address which is the same to the ip6_src
			 * address, it is the one.
			 */
			mha_prefered = mha;
		}
	}

	/*
	 * search bu_list and do home registration pending.  each
	 * binding update entry which can't proceed because of no home
	 * agent has an field of a home agent address equals to an
	 * unspecified address.
	 */
	for (mbu = LIST_FIRST(&sc->hif_bu_list); mbu;
	     mbu = LIST_NEXT(mbu, mbu_entry)) {
		if ((mbu->mbu_flags & IP6MU_HOME)
		    && SA6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr)) {
			/* home registration. */
			mbu->mbu_paddr = mha_prefered->mha_gaddr;
			if ((mbu->mbu_state & MIP6_BU_STATE_WAITSENT) != 0) {
				if (mip6_bu_send_bu(mbu)) {
					mip6log((LOG_ERR,
						 "%s:%d: "
						 "sending a binding update "
						 "from %s(%s) to %s failed.\n",
						 __FILE__, __LINE__,
						 ip6_sprintf(&mbu->mbu_haddr.sin6_addr),
						 ip6_sprintf(&mbu->mbu_coa.sin6_addr),
						 ip6_sprintf(&mbu->mbu_paddr.sin6_addr)));
				}
			}
		}
	}

	return (0);
}

static int
mip6_ha_discov_ha_list_insert(sc, mha)
	struct hif_softc *sc;
	struct mip6_ha *mha;
{
	struct hif_subnet *hs;
	struct mip6_subnet *ms;
	struct mip6_subnet_ha *msha;
	int error = 0;

	hs = TAILQ_FIRST(&sc->hif_hs_list_home);
	if (hs == NULL) {
		/* must not happen. */
		mip6log((LOG_ERR,
			 "%s:%d: receive a DHAAD reply.  "
			 "but we have no home subnet???\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}
	if ((ms = hs->hs_ms) == NULL)
		return (EINVAL);

	msha = mip6_subnet_ha_create(mha);
	if (msha == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: can't create msha\n",
			 __FILE__, __LINE__));
		return (ENOMEM);
	}

	error = mip6_subnet_ha_list_insert(&ms->ms_msha_list, msha);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: insert msha entry to msha_list failed.\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}

	return (0);
}

int
mip6_icmp6_ha_discov_req_output(sc)
	struct hif_softc *sc;
{
	struct sockaddr_in6 haanyaddr;
	struct hif_subnet *hs;
	struct mip6_subnet_prefix *mspfx;
	struct mip6_prefix *mpfx;
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct ha_discov_req *hdreq;
	u_int32_t icmp6len, off;
	int error;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	/* pick up one home subnet. */
	hs = TAILQ_FIRST(&sc->hif_hs_list_home);
	if ((hs == NULL) || (hs->hs_ms == NULL)) {
		/* we must have at least one home subnet. */
		return (EINVAL);
	}

	/* rate limitation. */
	if (sc->hif_hadiscov_count != 0) {
		if (sc->hif_hadiscov_lastsent + (1 << sc->hif_hadiscov_count)
		   > time_second)
			return (0);
	}

	/*
	 * we must determine the home agent subnet anycast address.
	 * to do this, we pick up one home prefix from the home subnet
	 * information.
	 */
	mspfx = TAILQ_FIRST(&hs->hs_ms->ms_mspfx_list);
	if ((mspfx == NULL) || ((mpfx = mspfx->mspfx_mpfx) == NULL)) {
		return (EINVAL);
	}
	if (mip6_icmp6_create_haanyaddr(&haanyaddr, mpfx))
		return (EINVAL);

	/* allocate the buffer for the ip packet and DHAAD request. */
	icmp6len = sizeof(struct ha_discov_req);
	m = mip6_create_ip6hdr(&hif_coa, &haanyaddr,
			       IPPROTO_ICMPV6, icmp6len);
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: "
			 "mbuf allocation for a DHAAD request failed\n",
			 __FILE__, __LINE__));

		return (ENOBUFS);
	}

	sc->hif_hadiscovid = mip6_hadiscovid++;

	ip6 = mtod(m, struct ip6_hdr *);
	hdreq = (struct ha_discov_req *)(ip6 + 1);
	bzero((caddr_t)hdreq, sizeof(struct ha_discov_req));
	hdreq->discov_req_type = ICMP6_HADISCOV_REQUEST;
	hdreq->discov_req_code = 0;
	hdreq->discov_req_id = htons(sc->hif_hadiscovid);

	/* calculate checksum for this DHAAD request packet. */
	off = sizeof(struct ip6_hdr);
	hdreq->discov_req_cksum = in6_cksum(m, IPPROTO_ICMPV6, off, icmp6len);

	/* send the DHAAD request packet to the home agent anycast address. */
	if (!ip6_setpktaddrs(m, &hif_coa, &haanyaddr)) {
		m_freem(m);
		return (EINVAL);
	}
	error = ip6_output(m, NULL, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: "
			 "failed to send a DHAAD request (errno = %d)\n",
			 __FILE__, __LINE__, error));
		return (error);
	}

	/* update rate limitation factor. */
	sc->hif_hadiscov_lastsent = time_second;
	if (sc->hif_hadiscov_count++ > MIP6_DHAAD_RETRIES) {
		/*
		 * XXX the spec says that the number of retires for
		 * DHAAD request is restricted to DHAAD_RETRIES(=3).
		 * But, we continue retrying until we receive a reply.
		 */
		sc->hif_hadiscov_count = MIP6_DHAAD_RETRIES;
	}

	return (0);
}

static int
mip6_icmp6_create_haanyaddr(haanyaddr, mpfx)
	struct sockaddr_in6 *haanyaddr;
	struct mip6_prefix *mpfx;
{
	struct nd_prefix ndpr;

	if (mpfx == NULL)
		return (EINVAL);

	bzero(&ndpr, sizeof(ndpr));
	ndpr.ndpr_prefix = mpfx->mpfx_prefix;
	ndpr.ndpr_plen = mpfx->mpfx_prefixlen;

	if (mpfx->mpfx_prefixlen == 64)
		mip6_create_addr(haanyaddr, &haanyaddr_ifid64, &ndpr);
	else
		mip6_create_addr(haanyaddr, &haanyaddr_ifidnn, &ndpr);

	return (0);
}

static int
mip6_icmp6_create_linklocal(lladdr, ifid)
	struct in6_addr *lladdr;
	struct in6_addr *ifid;
{
	bzero(lladdr, sizeof(struct in6_addr));
	lladdr->s6_addr[0] = 0xfe;
	lladdr->s6_addr[1] = 0x80;
	lladdr->s6_addr32[2] = ifid->s6_addr32[2];
	lladdr->s6_addr32[3] = ifid->s6_addr32[3];

	return (0);
}

int
mip6_icmp6_mp_sol_output(mpfx, mha)
	struct mip6_prefix *mpfx;
	struct mip6_ha *mha;
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct mobile_prefix_solicit *mp_sol;
	int icmp6len;
	int maxlen;
	int error;

	/* estimate the size of message. */
	maxlen = sizeof(*ip6) + sizeof(*mp_sol);
	/* XXX we must determine the link type of our home address
	   instead using hardcoded '6' */
	maxlen += (sizeof(struct nd_opt_hdr) + 6 + 7) & ~7;
	if (max_linkhdr + maxlen >= MCLBYTES) {
		mip6log((LOG_ERR,
			 "%s:%d: too large cluster reqeust.\n",
			 __FILE__, __LINE__));
		return (EINVAL);
	}

	/* get packet header. */
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return (ENOBUFS);
	m->m_pkthdr.rcvif = NULL;

	icmp6len = sizeof(*mp_sol);
	m->m_pkthdr.len = m->m_len = sizeof(*ip6) + icmp6len;
	m->m_data += max_linkhdr;

	/* fill the mobile prefix solicitation. */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = ip6_defhlim;
	ip6->ip6_src = mpfx->mpfx_haddr.sin6_addr;
	ip6->ip6_dst = mha->mha_gaddr.sin6_addr;
	mp_sol = (struct mobile_prefix_solicit *)(ip6 + 1);
	mp_sol->mp_sol_type = ICMP6_MOBILEPREFIX_SOLICIT;
	mp_sol->mp_sol_code = 0;
	mp_sol->mp_sol_reserved = 0;

	/* calculate checksum. */
	ip6->ip6_plen = htons((u_short)icmp6len);
	mp_sol->mp_sol_cksum = 0;
	mp_sol->mp_sol_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), icmp6len);

	if (!ip6_setpktaddrs(m, &mpfx->mpfx_haddr, &mha->mha_gaddr)) {
		m_freem(m);
		return (EINVAL);
	}
	error = ip6_output(m, 0, 0, 0, 0,NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: mobile prefix sol send failed (code = %d)\n",
			 __FILE__, __LINE__, error));
	}

	return (error);
}

#if 0
int
mip6_tunneled_rs_output(sc, mpfx)
	struct hif_softc *sc;
	struct mip6_pfx *mpfx;
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct nd_router_solicit *nd_rs;
	int icmp6len;
	int maxlen;

	/* estimate the size of message. */
	maxlen = sizeof(*ip6) + sizeof(*nd_rs);
	/* XXX we must determine the link type of our home address
	   instead using hardcoded '6' */
	maxlen += (sizeof(struct nd_opt_hdr) + 6 + 7) & ~7;
	if (max_linkhdr + maxlen >= MCLBYTES) {
#ifdef DIAGNOSTIC
		printf("%s:%d: max_linkhdr + maxlen >= MCLBYTES (%d + %d > %d)\n",
		       __FILE__, __LINE__, max_linkhdr, maxlen, MCLBYTES);
#endif /* DIAGNOSTIC */
		return (-1);
	}

	/* get inner packet header. */
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return (-1);
	m->m_pkthdr.rcvif = NULL;

	icmp6len = sizeof(*nd_rs);
	m->m_pkthdr.len = m->m_len = sizeof(*ip6) + icmp6len;
	m->m_data += max_linkhdr;

	/* fill router solicitation packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	ip6->ip6_src = mpfx->mpfx_haddr;
	ip6->ip6_dst = mpfx->mpfx_haaddr;
	mip6log((LOG_INFO, "%s:%d: inner src %s\ninner dst%s\n",
		 __FILE__, __LINE__,
		 ip6_sprintf(&ip6->ip6_src),
		 ip6_sprintf(&ip6->ip6_dst)));

	nd_rs = (struct nd_router_solicit *)(ip6 + 1);
	nd_rs->nd_rs_type = ND_ROUTER_SOLICIT;
	nd_rs->nd_rs_code = 0;
	nd_rs->nd_rs_reserved = 0;

	/*
	 * XXX
	 * source link layer address option
	 */

	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_rs->nd_rs_cksum = 0;
	nd_rs->nd_rs_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), icmp6len);

#ifdef IPSEC
	/* Don't lookup socket */
	(void)ipsec_setsocket(m, NULL);
#endif /* IPSEC */

	/* prepend outer packet header. */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf allocation falied\n",
			 __FILE__, __LINE__));
		return (-1);
	}

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = htons((u_short)m->m_pkthdr.len);
	ip6->ip6_nxt = IPPROTO_IPV6;
	ip6->ip6_hlim = IPV6_DEFHLIM;
	ip6->ip6_src = hif_coa;
	ip6->ip6_dst = mpfx->mpfx_haaddr;
	mip6log((LOG_INFO, "%s:%d: outer src %s\nouter dst%s\n",
		 __FILE__, __LINE__,
		 ip6_sprintf(&ip6->ip6_src),
		 ip6_sprintf(&ip6->ip6_dst)));

	if ((mip6_setpktaddrs(m)) != 0) { /* XXX */
		m_freem(m);
		return (-1);
	}
	return (ip6_output(m, 0, 0, 0, 0,NULL));
}

#endif /* 0 tunneled rs */
