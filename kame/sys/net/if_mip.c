/*	$Id: if_mip.c,v 1.1 2004/12/09 02:18:56 t-momose Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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
#include "opt_mip6.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6_var.h>

#include <net/if_mip.h>

#include "mip.h"
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif

#include <net/net_osdep.h>

#if NMIP > 0
#include <netinet6/in6_var.h>
#include <netinet6/mip6.h>

extern struct mip6stat mip6stat;

struct mip_softc_list mip_softc_list;

#ifdef __FreeBSD__
void mipattach(void *);
#else
void mipattach(int);
#endif

#ifdef __FreeBSD__
PSEUDO_SET(mipattach, if_mip);
#endif

void
mipattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct mip_softc *sc;
	int i;

	LIST_INIT(&mip_softc_list);

	sc = malloc(NMIP * sizeof(struct mip_softc), M_DEVBUF, M_WAITOK);
	bzero(sc, NMIP * sizeof(struct mip_softc));
	for (i = 0 ; i < NMIP; sc++, i++) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		sprintf(sc->mip_if.if_xname, "mip%d", i);
#elif defined(__FreeBSD__) && __FreeBSD_version > 501000
		if_initname(&sc->mip_if, "mip", i);
#else
		sc->mip_if.if_name = "mip";
		sc->mip_if.if_unit = i;
#endif
		sc->mip_if.if_flags = IFF_MULTICAST | IFF_SIMPLEX;
		sc->mip_if.if_mtu = MIP_MTU;
		sc->mip_if.if_ioctl = mip_ioctl;
		sc->mip_if.if_output = mip_output;
		sc->mip_if.if_type = IFT_MIP;
#ifdef __NetBSD__
		sc->mip_if.if_dlt = DLT_NULL;
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
		IFQ_SET_MAXLEN(&sc->mip_if.if_snd, ifqmaxlen);
		IFQ_SET_READY(&sc->mip_if.if_snd);
#endif
		if_attach(&sc->mip_if);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		if_alloc_sadl(&sc->mip_if);
#endif
#if NBPFILTER > 0
#ifdef HAVE_NEW_BPFATTACH
		bpfattach(&sc->mip_if, DLT_NULL, sizeof(u_int));
#else
		bpfattach(&sc->mip_if.if_bpf, &sc->mip_if, DLT_NULL, sizeof(u_int));
#endif /* HAVE_NEW_BPF */
#endif /* NBPFILTER > 0 */

		/* XXX
		 * various mip_softc initialization should be here.
		 */

		/* create mip_softc list */
		LIST_INSERT_HEAD(&mip_softc_list, sc, mip_entry);
	}
}

int
mip_output(ifp, m, dst, rt)
     struct ifnet *ifp;
     struct mbuf *m;
     struct sockaddr *dst;
     struct rtentry *rt;
{
	struct mip6_bul_internal *mbul;
	struct ip6_hdr *ip6;

	/* This function is copyed from looutput */

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("mip_output no HDR");

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		m_freem(m);
		return (rt->rt_flags & RTF_BLACKHOLE ? 0 :
		    rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
	}

#ifndef PULLDOWN_TEST
	/*
	 * KAME requires that the packet to be contiguous on the
	 * mbuf.  We need to make that sure.
	 * this kind of code should be avoided.
	 * XXX: fails to join if interface MTU > MCLBYTES.  jumbogram?
	 */
	if (m->m_len != m->m_pkthdr.len) {
		struct mbuf *n = NULL;
		int maxlen;

		MGETHDR(n, M_DONTWAIT, MT_HEADER);
		maxlen = MHLEN;
		if (n)
#ifdef __FreeBSD__
			m_dup_pkthdr(n, m);
#else
			M_COPY_PKTHDR(n, m);
#endif
		if (n && m->m_pkthdr.len > maxlen) {
			MCLGET(n, M_DONTWAIT);
			maxlen = MCLBYTES;
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				n = NULL;
			}
		}
		if (!n) {
			printf("mip_output: mbuf allocation failed\n");
			m_freem(m);
			return ENOBUFS;
		}

		if (m->m_pkthdr.len <= maxlen) {
			m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
			n->m_len = m->m_pkthdr.len;
			n->m_next = NULL;
			m_freem(m);
		} else {
			m_copydata(m, 0, maxlen, mtod(n, caddr_t));
			m_adj(m, maxlen);
			n->m_len = maxlen;
			n->m_next = m;
		}
		m = n;
	}
#endif

	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;

	switch (dst->sa_family) {
	case AF_INET6:
		/*
		 * if ! link-local, prepend an outer ip header and
		 * send it.  if link-local, discard it.
		 */
		ip6 = mtod(m, struct ip6_hdr *);
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)
		    || IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)
		    || IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src)
		    || IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src)
		    || IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src))
			goto done;
		if(IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst)
		    || IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst)
		    || IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst)
		    || IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst))
			goto done;

		/*
		 * find the home registration entry for this source
		 * address.
		 */
		mbul = mip6_bul_get_home_agent(&ip6->ip6_src);
		if (!mbul)
			goto done;

		if (IN6_IS_ADDR_UNSPECIFIED(&mbul->mbul_peeraddr))
			goto done;

		M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
		if (m && m->m_len < sizeof(struct ip6_hdr))
			m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return (0);

		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_flow = 0;
		ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
		ip6->ip6_vfc |= IPV6_VERSION;
		ip6->ip6_plen = htons((u_short)m->m_pkthdr.len - sizeof(*ip6));
		ip6->ip6_nxt = IPPROTO_IPV6;
		ip6->ip6_hlim = ip6_defhlim;
		ip6->ip6_src = mbul->mbul_coa;
		ip6->ip6_dst = mbul->mbul_peeraddr;
		mip6stat.mip6s_orevtunnel++;
#ifdef IPV6_MINMTU
		/* XXX */
		return (ip6_output(m, 0, 0, IPV6_MINMTU, 0, &ifp
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
		    , NULL
#endif
		    ));
#else
		return (ip6_output(m, 0, 0, 0, 0, &ifp
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
		   , NULL
#endif
		    ));
#endif
 done:
		break;
	default:
		printf("mip_output: af=%d unexpected\n", dst->sa_family);
		m_freem(m);
		return (EAFNOSUPPORT);
	}

	m_freem(m);
	return (0);
}

int
mip_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
#if defined(__FreeBSD__) && __FreeBSD__ < 3
	int cmd;
#else
	u_long cmd;
#endif
	caddr_t data;
{
	int s, error;
	struct ifreq *ifr = (struct ifreq *)data;
#if NMIP > 0
	struct if_bulreq *bulreq;
	struct mip6_bul_internal *mbul = NULL, *nmbul = NULL;
	struct bul6info *bul6;
	int addlen = sizeof(struct if_bulreq) + sizeof(struct bul6info);

        register struct ifaddr *ifa;
        struct in6_ifaddr *ia6;
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	error = 0;

	switch(cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		/*
		 * Everything else is done at a higher level.
		 */
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr == 0) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {
#ifdef INET6
		case AF_INET6:
			break;
#endif
		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;
#if NMIP > 0
	case SIOGBULIST:
		if (!MIP6_IS_MN)
			return EOPNOTSUPP;

		bulreq = (struct if_bulreq *)data;
		bul6 = bulreq->ifbu_info;
		bulreq->ifbu_count = 0;
		
#ifdef __FreeBSD__
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link)
#elif defined(__NetBSD__)
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) 
#endif
		{
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;

			ia6 = (struct in6_ifaddr *)ifa;
			if (LIST_EMPTY(&ia6->ia6_mbul_list)) 
				continue;
			
			for (mbul = LIST_FIRST(&ia6->ia6_mbul_list); mbul;
			     mbul = nmbul) {
				nmbul = LIST_NEXT(mbul, mbul_entry);
				
				if (addlen > bulreq->ifbu_len) 
					break; /* no buffer space to add BUL */
				
				bcopy(&mbul->mbul_peeraddr, &bul6->bul_peeraddr, 
				      sizeof(mbul->mbul_peeraddr));
				printf("adding entry %s\n", ip6_sprintf(&mbul->mbul_peeraddr));
				bcopy(&mbul->mbul_hoa, &bul6->bul_hoa, 
				      sizeof(mbul->mbul_hoa));
				bcopy(&mbul->mbul_coa, &bul6->bul_coa, 
				      sizeof(mbul->mbul_coa));
				bul6->bul_flags = mbul->mbul_flags;
				bul6->bul_ifindex = mbul->mbul_mip->mip_if.if_index;
				
				bul6 += sizeof(struct bul6info);
				addlen += sizeof(struct bul6info);
				bulreq->ifbu_count ++;
			}
		}
		break;
#endif
	default:
		error = EINVAL;
		break;
	}

	splx(s);

	return (error);
}

int
mip_is_mip_softc(ifp)
	struct ifnet *ifp;
{
	struct mip_softc *mipsc;

	for (mipsc = LIST_FIRST(&mip_softc_list); mipsc;
	     mipsc = LIST_NEXT(mipsc, mip_entry)) {
		if ((caddr_t)ifp == (caddr_t)mipsc)
			return (1);
	}
	return (0);
}

#endif /* NMIP > 0 */
