/*	$KAME: mip6_icmp6.c,v 1.18 2001/10/18 08:16:47 keiichi Exp $	*/

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
#include "opt_mip6.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/net_osdep.h>

#include <net/if_hif.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>

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

#include <netinet6/mip6.h>

extern struct mip6_bc_list mip6_bc_list;

u_int16_t mip6_hadiscovid = 0;

static struct in6_addr haanyaddr_ifid64 =
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}};
static struct in6_addr haanyaddr_ifidnn =
	{{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}};

static void mip6_icmp6_find_addr __P((caddr_t, int,
				      struct in6_addr **, struct in6_addr **));
static int mip6_icmp6_ha_discov_req_input __P((struct mbuf *, int, int));
static int mip6_icmp6_ha_discov_rep_input __P((struct mbuf *, int, int));
static int mip6_ha_discov_ha_list_insert __P((struct hif_softc *,
					      struct mip6_ha *));
static int mip6_icmp6_create_haanyaddr __P((struct in6_addr *,
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
	struct in6_addr *laddr, *paddr;

	ip6 = mtod(m, struct ip6_hdr *);
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		/*
		 * the contacting MN might move to somewhere.  in
		 * current code, we remove a related BC entry
		 * immediately.  should we be more patient ?
		 */
		mip6_icmp6_find_addr((caddr_t)icmp6, icmp6len, &laddr, &paddr);
		mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, paddr);
		if (mbc) {
			mip6log((LOG_INFO,
				 "%s:%d: a MN (%s) moved.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(paddr)));
			mip6_bc_list_remove(&mip6_bc_list, mbc);
		}
		break;

	case ICMP6_HADISCOV_REQUEST:
		if (!MIP6_IS_HA)
			break;
		if (mip6_icmp6_ha_discov_req_input(m, off, icmp6len)) {
			m_freem(m);
		}
		break;

	case ICMP6_HADISCOV_REPLY:
		if (!MIP6_IS_MN)
			break;
		if (mip6_icmp6_ha_discov_rep_input(m, off, icmp6len)) {
			m_freem(m);
		}
		break;

	case ICMP6_MOBILEPREFIX_SOLICIT:
	case ICMP6_MOBILEPREFIX_ADVERT:
		/* XXX TODO */
		break;

	case ICMP6_PARAM_PROB:
		if (!MIP6_IS_MN)
			break;
		if (icmp6->icmp6_code != ICMP6_PARAMPROB_OPTION)
			break;

		pptr = ntohl(icmp6->icmp6_pptr);
		if ((sizeof(struct icmp6_hdr) + pptr + 1) > icmp6len) {
			/* we can't get packet detail, ignore this... */
			break;
		}
		
		origip6 = (caddr_t)icmp6 + sizeof(struct icmp6_hdr);
		switch (*(u_int8_t *)(origip6 + pptr)) {
		case IP6OPT_BINDING_UPDATE:
			mip6_icmp6_find_addr((caddr_t)icmp6, icmp6len,
					     &laddr, &paddr);
			/*
			 * a node that doesn't support MIP6 returns
			 * an icmp paramprob on recieving BU.
			 * we shold avoid further sending of BU to that node.
			 * (draft-13 10.14)
			 */
			for (sc = TAILQ_FIRST(&hif_softc_list);
			     sc;
			     sc = TAILQ_NEXT(sc, hif_entry)) {
				mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list,
								  paddr);
				if (mbu) {
					mip6log((LOG_INFO,
						 "%s:%d: a node (%s) doesn't support a binding update destopt.\n",
						 __FILE__, __LINE__,
						 ip6_sprintf(paddr)));
					mbu->mbu_dontsend = 1;
				}
			}
			break;
		case IP6OPT_HOME_ADDRESS:
			/*
			 * all IPv6 node must support a home address option.
			 */
			mip6_icmp6_find_addr((caddr_t)icmp6, icmp6len,
					     &laddr, &paddr);
			mip6log((LOG_NOTICE,
				 "%s:%d: a node (%s) doesn't support a home address destopt.\n",
				 __FILE__, __LINE__,
				 ip6_sprintf(paddr)));
#ifdef MIP6_ALLOW_COA_FALLBACK
			for (sc = TAILQ_FIRST(&hif_softc_list);
			     sc;
			     sc = TAILQ_NEXT(sc, hif_entry)) {
				mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list,
								  paddr);
				if (mbu) {
					mbu->mbu_dontsend = 1;
					mbu->mbu_coafallback = 1;
				}
			}
#endif
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
	struct ip6_hdr *ip6, otip6, oip6, *nip6;
	struct icmp6_hdr *icmp6, *nicmp6;
	int plen;
	struct mip6_bc *mbc;
	int error = 0;

	if (!MIP6_IS_HA) {
		/*
		 * this check is needed only for a node that is acting
		 * a home agent.
		 */
		return (0);
	}
	
	/*
	 * check if this icmp is generated on the way to sending from
	 * ha to mn by encapsulating.  if so, relay this icmp to the
	 * sender of an original packet.
	 *
	 * the icmp packet against the tunneled packet looks like as
	 * follows.
	 *   ip(src=??,dst=ha)
	 *     |icmp|ip(src=ha,dst=mnhoa)|ip(src=cn,dst=mnhoa)|payload
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	plen = ip6->ip6_plen;
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
	if (icmp6->icmp6_type >= 128) {
		/*
		 * this is not an icmp error message. no need to
		 * relay.
		 */
		return (0);
	} 
	if (plen < (sizeof(*icmp6) + sizeof(otip6) + sizeof(oip6))) {
		/* this is not an icmp against the tunneled packet. */
		return (0);
	}
	/* original tunneled ip6 hdr is not guaranteed to be continuous. */
	m_copydata(m, off + sizeof(*icmp6), sizeof(otip6), (caddr_t)&otip6);

	/*
	 * XXX
	 * must check extension headers...
	 */
	if (otip6.ip6_nxt != IPPROTO_IPV6) {
		/* this packet is not tunneled. */
		/* XXX we must chase extension haeders... */
		return (0);
	}

	/* length check is already done.  we can copy immediately. */
	m_copydata(m, off + sizeof(*icmp6) + sizeof(otip6),
		   sizeof(oip6), (caddr_t)&oip6);
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &oip6.ip6_dst);
	if (mbc == NULL) {
		/* we are not a homeagent of this mn?? */
		return (0);
	}

	n = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf allocation failed.\n",
			 __FILE__, __LINE__));
		/* continue, anyway */
		return (0);
	}
	m_adj(n, off + sizeof(*icmp6) + sizeof(otip6));
	M_PREPEND(n, sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr),
		  M_DONTWAIT);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf prepend for ip6/icmp6 failed.\n",
			 __FILE__, __LINE__));
		/* continue */
		return (0);
	}
	/* fill the ip6 hdr */
	nip6 = mtod(n, struct ip6_hdr *);
	nip6->ip6_flow = 0;
	nip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	nip6->ip6_vfc |= IPV6_VERSION;
	nip6->ip6_plen = htons(n->m_pkthdr.len - sizeof(struct ip6_hdr));
	nip6->ip6_nxt = IPPROTO_ICMPV6;
	nip6->ip6_hlim = IPV6_DEFHLIM;
	nip6->ip6_src = ip6->ip6_dst;
	nip6->ip6_dst = oip6.ip6_src;

	/* fill the icmp6 hdr */
	nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
	nicmp6->icmp6_type = icmp6->icmp6_type;
	nicmp6->icmp6_code = icmp6->icmp6_code;
	nicmp6->icmp6_data32[0] = icmp6->icmp6_data32[0];

	/* XXX modify icmp data in some case.  (ex. TOOBIG) */

	/* calculate checksum */
	nicmp6->icmp6_cksum = 0;
	nicmp6->icmp6_cksum = in6_cksum(n, IPPROTO_ICMPV6, 
					sizeof(*nip6), ntohs(nip6->ip6_plen));

	/* XXX IPSEC? */

	error = ip6_output(n, NULL, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: send failed. (errno = %d)\n",
			 __FILE__, __LINE__, error));
		m_freem(n);
		/* continue processing 'm' (the original icmp) */
		return (0);
	}

	return (0);
}

static void
mip6_icmp6_find_addr(icmp6, icmp6len, laddr, paddr)
	caddr_t icmp6; /* Pointer to beginning of icmp6 payload */
	int icmp6len; /* Total icmp6 payload length */
	struct in6_addr **laddr; /* Local home address */
	struct in6_addr **paddr; /* Peer home address */
{
	struct ip6_opt_home_address *haddr_opt; /* Home Address option */
	struct ip6_hdr *ip6;                    /* IPv6 header */
	struct ip6_ext *ehdr;                   /* Extension header */
	struct in6_addr *la;                    /* Local home address */
	struct in6_addr *pa;                    /* Peer home address */
	struct ip6_rthdr0 *rh;                  /* Routing header */
	u_int8_t *eopt, nxt, optlen;     
	int off, elen, eoff;
	int rlen, addr_off;

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
			rh = (struct ip6_rthdr0 *)(icmp6 + off);
			rlen = (rh->ip6r0_len + 1) << 3;
			if ((off + rlen) > icmp6len) break;
			if (rh->ip6r0_type != 0) break;
			if ((rh->ip6r0_type != 0) || (rh->ip6r0_len % 2)) {
				nxt = rh->ip6r0_nxt;
				off += (rh->ip6r0_len + 1) << 3;
				continue;
			}

			addr_off = 8 + (((rh->ip6r0_len / 2) - 1) << 3);
			pa = (struct in6_addr *)(icmp6 + off + addr_off);

			nxt = rh->ip6r0_nxt;
			off += (rh->ip6r0_len + 1) << 3;
			continue;
		} else {
			ehdr = (struct ip6_ext *)(icmp6 + off);
			nxt = ehdr->ip6e_nxt;
			off += (ehdr->ip6e_len + 1) << 3;
			continue;
		}

		
		/* Only look at the unfragmentable part.  Other headers
		   may be present but they are of no interest. */
		break;
	}

	*laddr = la;
	*paddr = pa;
}

/*
 * dynamic homeagent discovery request input routine.
 */
static int
mip6_icmp6_ha_discov_req_input(m, off, icmp6len)
	struct mbuf *m; /* points ip header */
	int off;
	int icmp6len;
{
	struct ip6_hdr *ip6, *ip6_rep;
	struct ha_discov_req *hdreq;
	struct ha_discov_rep *hdrep;
	int hdreplen;
	struct in6_addr *haddr;
	struct in6_ifaddr *haifa;
	struct in6_addr *halist;
	int halistlen;
	struct mbuf *n;
	int error = 0;

	ip6 = mtod(m, struct ip6_hdr *);
	/* ha_discov_req may not continuous */
	IP6_EXTHDR_GET(hdreq, struct ha_discov_req *, m,
		       off, sizeof(*hdreq));
	haddr = &hdreq->ha_dreq_home;

	/* 
	 * find a home agent address based on the homeaddress of the
	 * mobile node.
	 */
    {
	struct sockaddr_in6 haddr_sin;

	bzero(&haddr_sin, sizeof(haddr_sin));
	haddr_sin.sin6_len = sizeof(haddr_sin);
	haddr_sin.sin6_family = AF_INET6;
	haddr_sin.sin6_addr = *haddr;

	haifa = (struct in6_ifaddr *)
		ifa_ifwithnet((struct sockaddr *)&haddr_sin);
    }

        /* XXX TODO */
	/* collect ha list on the home link and create a list */

	/* create a home agent address list */
	/* XXX */
	halistlen = sizeof(struct in6_addr) * 1; /* XXX */
	MALLOC(halist, struct in6_addr *, halistlen, M_TEMP, M_NOWAIT);
	if (halist == NULL) {
		m_freem(m);
		return (ENOBUFS);
	}
	bcopy((caddr_t)&haifa->ia_addr.sin6_addr, (caddr_t)halist,
	      sizeof(struct in6_addr));
	
	/*
	 * create a ha discovery reply packet
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(haddr)) {
		/*
		 * in case that a mn has no valid home address.  the
		 * mobile node will send a home agent discovery from
		 * its CoA.  use the CoA as a dest addr of the reply
		 * message.
		 */
		haddr = &ip6->ip6_src;
	}
	hdreplen = sizeof(*hdrep);
	n = mip6_create_ip6hdr(&haifa->ia_addr.sin6_addr, &ip6->ip6_src,
			       IPPROTO_ICMPV6, hdreplen + halistlen);
	if (n == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: mbuf allocation failed\n",
			 __FILE__, __LINE__));
		/* free the input packet */
		m_freem(m);
		FREE(halist, M_TEMP);
		return (ENOBUFS);
	}
	ip6_rep = mtod(n, struct ip6_hdr *);
	hdrep = (struct ha_discov_rep *)(ip6_rep + 1);
	hdrep->discov_rep_type = ICMP6_HADISCOV_REPLY;
	hdrep->discov_rep_code = 0;
	hdrep->discov_rep_cksum = 0;
	hdrep->discov_rep_id = hdreq->discov_req_id;
	/* copy halist at the end of the hdrep packet */
	bcopy((caddr_t)halist, (caddr_t)(hdrep + 1), halistlen);
	FREE(halist, M_TEMP);

	/* calcurate checksum */
	hdrep->discov_rep_cksum = in6_cksum(n, IPPROTO_ICMPV6,
					    sizeof(struct ip6_hdr),
					    n->m_pkthdr.len
					    - sizeof(struct ip6_hdr));

	error = ip6_output(n, NULL, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: send failed (errno = %d)\n",
			 __FILE__, __LINE__, error));
	}

	return (0);
}

static int
mip6_icmp6_ha_discov_rep_input(m, off, icmp6len)
	struct mbuf *m;
	int off;
	int icmp6len;
{
	struct ip6_hdr *ip6;
	struct ha_discov_rep *hdrep;
	u_int16_t hdrep_id;
	struct mip6_ha *mha, *mha_prefered = NULL;
	struct in6_addr *haaddrs, *haaddrptr, lladdr;
	int i, hacount = 0, found = 0;
	struct hif_softc *sc;
	struct mip6_bu *mbu;

	ip6 = mtod(m, struct ip6_hdr *);
	hdrep = (struct ha_discov_rep *)(ip6 + 1);
	haaddrs = (struct in6_addr *)(hdrep + 1);

	/* sainty check ... */
	if (hdrep->discov_rep_code != 0)
		return (EINVAL);

	/* find hif that matches this receiving hadiscovid. */
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
		 * no matching hif.  maybe this reply is too late.
		 */
		return (0);
	}

	/*
	 * check if the home agent list contains sending home agent's
	 * address.
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
	 * install homeagent to the list.
	 */
	if (found == 0) {
		/* 
		 * if the HA list doesn't include an addr of 
		 * ip_src field, the addr is considered as a most 
		 * preferable.
		 * draft-13 9.2
		 */
		/* XXX how do we make the HA specified in the ip src field
		   as a most preferable one ? */
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, &ip6->ip6_src);
		if (mha) {
			/*
			 * if this ha already exists in the list,
			 * update its lifetime.
			 */
			mha->mha_lifetime = MIP6_HA_DEFAULT_LIFETIME;
		} else {
			/*
			 * create a new ha entry and insert to mip6_ha_list.
			 */
			mip6_icmp6_create_linklocal(&lladdr, &ip6->ip6_src);
			mha = mip6_ha_create(&lladdr, &ip6->ip6_src,
					     ND_RA_FLAG_HOME_AGENT,
					     0, MIP6_HA_DEFAULT_LIFETIME);
			if (mha == NULL) {
				mip6log((LOG_ERR,
					 "%s:%d: mip6_ha create failed\n",
					 __FILE__, __LINE__));
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
		mha = mip6_ha_list_find_withaddr(&mip6_ha_list, haaddrptr);
		if (mha) {
			mha->mha_lifetime = MIP6_HA_DEFAULT_LIFETIME;
		} else {
			mip6_icmp6_create_linklocal(&lladdr, haaddrptr);
			mha = mip6_ha_create(&lladdr, haaddrptr,
					     ND_RA_FLAG_HOME_AGENT,
					     0, MIP6_HA_DEFAULT_LIFETIME);
			if (mha == NULL) {
				mip6log((LOG_ERR,
					 "%s:%d: mip6_ha create failed\n",
					 __FILE__, __LINE__));
				return (ENOMEM);
			}
			mip6_ha_list_insert(&mip6_ha_list, mha);
			mip6_ha_discov_ha_list_insert(sc, mha);
		}
		if (mha_prefered == NULL)
			mha_prefered = mha;
	}

#if 0
	/* register to the new home agent. */
	for (sc = TAILQ_FIRST(&hif_softc_list); sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		if (sc->hif_location == HIF_LOCATION_HOME)
			continue;

		mip6_home_registration(sc);
	}
#endif
	/* XXX */
	/* search bu_list and do home registration pending. */
	for (mbu = LIST_FIRST(&sc->hif_bu_list); mbu;
	     mbu = LIST_NEXT(mbu, mbu_entry)) {
		if ((mbu->mbu_flags & IP6_BUF_HOME)
		    && IN6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr)) {
			/* home registration */
			mbu->mbu_paddr = mha_prefered->mha_gaddr;
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
		/* must not happen */
		mip6log((LOG_ERR,
			 "%s:%d: receive dhaad reply.  "
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
	struct in6_addr haanyaddr;
	struct hif_subnet *hs;
	struct mip6_subnet_prefix *mspfx;
	struct mip6_prefix *mpfx;
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct ha_discov_req *hdreq;
	u_int32_t icmp6len, off;
	int error;

	hs = TAILQ_FIRST(&sc->hif_hs_list_home);
	if ((hs == NULL) || (hs->hs_ms == NULL)) {
		return (EINVAL);
	}
	mspfx = TAILQ_FIRST(&hs->hs_ms->ms_mspfx_list);
	if ((mspfx == NULL) || ((mpfx = mspfx->mspfx_mpfx) == NULL)) {
		return (EINVAL);
	}
	
	if (mip6_icmp6_create_haanyaddr(&haanyaddr, mpfx))
		return (EINVAL);

	icmp6len = sizeof(struct ha_discov_req);
	m = mip6_create_ip6hdr(&hif_coa, &haanyaddr,
			       IPPROTO_ICMPV6, icmp6len);
	if (m == NULL) {
		mip6log((LOG_ERR, "%s:%d: mbuf allocation failed\n",
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
	hdreq->ha_dreq_home = mpfx->mpfx_haddr;

	/* calculate checksum for ICMP6 packet */
	off = sizeof(struct ip6_hdr);
	hdreq->discov_req_cksum = in6_cksum(m, IPPROTO_ICMPV6,
					       off, icmp6len);

	/* send the ICMP6 packet to the home agent anycast address. */
	error = ip6_output(m, NULL, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR, "%s:%d: send failed (errno = %d)\n",
			 __FILE__, __LINE__, error));
	}

	return (0);
}

static int
mip6_icmp6_create_haanyaddr(haanyaddr, mpfx)
	struct in6_addr *haanyaddr;
	struct mip6_prefix *mpfx;
{
	if (mpfx == NULL)
		return (-1);

	if (mpfx->mpfx_prefixlen == 64) {
	  mip6_create_addr(haanyaddr, &haanyaddr_ifid64,
			   &mpfx->mpfx_prefix, 64);
	} else {
	  mip6_create_addr(haanyaddr, &haanyaddr_ifidnn,
			   &mpfx->mpfx_prefix, mpfx->mpfx_prefixlen);
	}

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

	return(ip6_output(m, 0, 0, 0, 0,NULL));
}

#endif /* 0 tunneled rs */
