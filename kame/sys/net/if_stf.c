/*	$KAME: if_stf.c,v 1.4 2000/03/10 14:02:00 itojun Exp $	*/

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

/*
 * 6to4 interface, based on draft-ietf-ngtrans-6to4-03.txt
 *
 * Section 6 in 03 draft looks impractical, as we cannot transmit IPv6 packet
 * to "all PIM routers multicast" address (ff02::d) on 6to4 pseudo link.
 * Therefore, we have removed IFF_MULTICAST from the interface.
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/ioctl.h>
#endif
#include <sys/protosw.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/malloc.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/if_types.h>
#include <net/if_stf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_gif.h>
#include <netinet6/in6_var.h>
#include <netinet/ip_ecn.h>

#include <netinet/ip_encap.h>

#include <machine/stdarg.h>

#include <net/net_osdep.h>

#include "bpfilter.h"
#include "stf.h"
#include "gif.h"	/*XXX*/

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#if NGIF > 0
#include <net/if_gif.h>
#endif

#if NSTF > 0
#if NSTF != 1
# error only single stf interface allowed
#endif

#define IN6_IS_ADDR_6TO4(x)	(ntohs((x)->s6_addr16[0]) == 0x2002)
#define GET_V4(x)	((struct in_addr *)(&(x)->s6_addr16[1]))

struct stf_softc {
	struct ifnet	sc_if;	   /* common area */
	union {
		struct route  __sc_ro4;   
		struct route_in6 __sc_ro6; /* just for safety */
	} __sc_ro46;
#define sc_ro	__sc_ro46.__sc_ro4
	const struct encaptab *encap_cookie;
};

static struct stf_softc *stf;
static int nstf = 1;

#if NGIF > 0
extern int ip_gif_ttl;	/*XXX*/
#else
static int ip_gif_ttl = 40;	/*XXX*/
#endif

extern struct protosw in_stf_protosw;

#ifdef __FreeBSD__
void stfattach __P((void *));
#else
void stfattach __P((int));
#endif
static int stf_encapcheck __P((const struct mbuf *, int, int, void *));
static struct in6_ifaddr *stf_getsrcifa6 __P((struct ifnet *));
static int stf_output __P((struct ifnet *, struct mbuf *, struct sockaddr *,
	struct rtentry *));
static void stf_rtrequest __P((int, struct rtentry *, struct sockaddr *));
#if defined(__FreeBSD__) && __FreeBSD__ < 3
static int stf_ioctl __P((struct ifnet *, int, caddr_t));
#else
static int stf_ioctl __P((struct ifnet *, u_long, caddr_t));
#endif

void
stfattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct stf_softc *sc;
	int i;
	const struct encaptab *p;

	stf = malloc(nstf * sizeof(struct stf_softc), M_DEVBUF, M_WAIT);
	bzero(stf, nstf * sizeof(struct stf_softc));
	sc = stf;

	/* XXX just in case... */
	for (i = 0; i < nstf; i++) {
		sc = &stf[i];
		bzero(sc, sizeof(*sc));

		p = encap_attach_func(AF_INET, IPPROTO_IPV6, stf_encapcheck,
		    &in_stf_protosw, &sc);
		if (p == NULL)
			continue;

#if defined(__NetBSD__) || defined(__OpenBSD__)
		sprintf(sc->sc_if.if_xname, "stf%d", i);
#else
		sc->sc_if.if_name = "stf";
		sc->sc_if.if_unit = i;
#endif
		sc->sc_if.if_mtu    = IPV6_MMTU;
		sc->sc_if.if_flags  = 0;
		sc->sc_if.if_ioctl  = stf_ioctl;
		sc->sc_if.if_output = stf_output;
		sc->sc_if.if_type   = IFT_STF;
		if_attach(&sc->sc_if);
#if NBPFILTER > 0
#ifdef HAVE_OLD_BPF
		bpfattach(&sc->sc_if, DLT_NULL, sizeof(u_int));
#else
		bpfattach(&sc->sc_if.if_bpf, &sc->sc_if, DLT_NULL, sizeof(u_int));
#endif
#endif
	}
}

#ifdef __FreeBSD__
PSEUDO_SET(stfattach, if_stf);
#endif

static int
stf_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip ip;
	struct in6_ifaddr *ia6;
	struct stf_softc *sc;

	sc = (struct stf_softc *)arg;

	if (proto != IPPROTO_IPV6)
		return 0;

	m_copydata((struct mbuf *)m, 0, sizeof(ip), (caddr_t)&ip);

	if (ip.ip_v != 4)
		return 0;

	ia6 = stf_getsrcifa6(&sc->sc_if);
	if (ia6 == NULL)
		return 0;
	if (bcmp(GET_V4(&ia6->ia_addr.sin6_addr), &ip.ip_dst,
	    sizeof(ip.ip_dst)) != 0)
		return 0;

	return 1;
}

static struct in6_ifaddr *
stf_getsrcifa6(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ia;
	struct in_ifaddr *ia4;
	struct sockaddr_in6 *sin6;
	struct in_addr in;

	for (ia = ifp->if_addrlist.tqh_first;
	     ia;
	     ia = ia->ifa_list.tqe_next) {
		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		sin6 = (struct sockaddr_in6 *)ia->ifa_addr;
		if (!IN6_IS_ADDR_6TO4(&sin6->sin6_addr))
			continue;

		bcopy(GET_V4(&sin6->sin6_addr), &in, sizeof(in));
#ifdef __NetBSD__
		INADDR_TO_IA(in, ia4);
#else
# error the operating system is not supported yet
#endif
		if (ia4 == NULL)
			continue;

		return (struct in6_ifaddr *)ia;
	}

	return NULL;
}

static int
stf_output(ifp, m, dst, rt)
	struct ifnet *ifp;
	struct mbuf *m;
	struct sockaddr *dst;
	struct rtentry *rt;
{
	struct stf_softc *sc;
	struct sockaddr_in6 *dst6;
	struct sockaddr_in *dst4;
	u_int8_t tos;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct in6_ifaddr *ia6;

	sc = (struct stf_softc*)ifp;
	dst6 = (struct sockaddr_in6 *)dst;

	/* just in case */
	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		return ENETDOWN;
	}

	/*
	 * If we don't have an ip4 address that match my inner ip6 address,
	 * we shouldn't generate output.  Without this check, we'll end up
	 * using wrong IPv4 source.
	 */
	ia6 = stf_getsrcifa6(ifp);
	if (ia6 == NULL) {
		m_freem(m);
		return ENETDOWN;
	}

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return ENOBUFS;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	tos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;

	M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip))
		m = m_pullup(m, sizeof(struct ip));
	if (m == NULL)
		return ENOBUFS;
	ip = mtod(m, struct ip *);

	bzero(ip, sizeof(*ip));

	bcopy(GET_V4(&((struct sockaddr_in6 *)&ia6->ia_addr)->sin6_addr),
	    &ip->ip_src, sizeof(ip->ip_src));
	bcopy(GET_V4(&dst6->sin6_addr), &ip->ip_dst, sizeof(ip->ip_dst));
	ip->ip_p = IPPROTO_IPV6;
	ip->ip_ttl = ip_gif_ttl;	/*XXX*/
	ip->ip_len = m->m_pkthdr.len;	/*host order*/
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &ip->ip_tos, &tos);

	dst4 = (struct sockaddr_in *)&sc->sc_ro.ro_dst;
	if (dst4->sin_family != AF_INET ||
	    bcmp(&dst4->sin_addr, &ip->ip_dst, sizeof(ip->ip_dst)) != 0) {
		/* cache route doesn't match */
		dst4->sin_family = AF_INET;
		dst4->sin_len = sizeof(struct sockaddr_in);
		bcopy(&ip->ip_dst, &dst4->sin_addr, sizeof(dst4->sin_addr));
		if (sc->sc_ro.ro_rt) {
			RTFREE(sc->sc_ro.ro_rt);
			sc->sc_ro.ro_rt = NULL;
		}
	}

	if (sc->sc_ro.ro_rt == NULL) {
		rtalloc(&sc->sc_ro);
		if (sc->sc_ro.ro_rt == NULL) {
			m_freem(m);
			return ENETUNREACH;
		}
	}

#ifndef __OpenBSD__
	return ip_output(m, NULL, &sc->sc_ro, 0, NULL);
#else
	return ip_output(m, NULL, &sc->sc_ro, 0, NULL, NULL);
#endif
}

void
#if __STDC__
in_stf_input(struct mbuf *m, ...)
#else
in_stf_input(m, va_alist)
	register struct mbuf *m;
#endif
{
	int off, proto;
	struct stf_softc *sc;
	struct ip *ip;
	struct ip6_hdr *ip6;
	u_int8_t otos, itos;
	int s, isr;
	struct ifqueue *ifq = NULL;
	struct ifnet *ifp;
	va_list ap;

	va_start(ap, m);
	off = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	if (proto != IPPROTO_IPV6) {
		m_freem(m);
		return;
	}

	ip = mtod(m, struct ip *);

	sc = (struct stf_softc *)encap_getarg(m);

	if (sc == NULL || (sc->sc_if.if_flags & IFF_UP) == 0) {
		m_freem(m);
		return;
	}

	ifp = &sc->sc_if;

	/* reject packets with multicast outer destination */
	if (IN_MULTICAST(ip->ip_dst.s_addr)) {
		m_freem(m);
		return;
	}

	otos = ip->ip_tos;
	m_adj(m, off);

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
	if ((ifp->if_flags & IFF_LINK1) != 0)
		ip_ecn_egress(ECN_ALLOWED, &otos, &itos);
	ip6->ip6_flow &= ~htonl(0xff << 20);
	ip6->ip6_flow |= htonl((u_int32_t)itos << 20);

	m->m_pkthdr.rcvif = ifp;
	
#if NBPFILTER > 0
	if (ifp->if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int af = AF_INET6;
		
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
#ifdef HAVE_OLD_BPF
		bpf_mtap(gifp, &m0);
#else
		bpf_mtap(ifp->if_bpf, &m0);
#endif
	}
#endif /*NBPFILTER > 0*/

	/*
	 * Put the packet to the network layer input queue according to the
	 * specified address family.
	 * See net/if_gif.c for possible issues with packet processing
	 * reorder due to extra queueing.
	 */
	ifq = &ip6intrq;
	isr = NETISR_IPV6;

	s = splimp();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);	/* update statistics */
		m_freem(m);
		splx(s);
		return;
	}
	IF_ENQUEUE(ifq, m);
	schednetisr(isr);
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	splx(s);
}

/* ARGSUSED */
static void
stf_rtrequest(cmd, rt, sa)
	int cmd;
	struct rtentry *rt;
	struct sockaddr *sa;
{

	if (rt)
		rt->rt_rmx.rmx_mtu = IPV6_MMTU;
}

static int
stf_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
#if defined(__FreeBSD__) && __FreeBSD__ < 3
	int cmd;
#else
	u_long cmd;
#endif
	caddr_t data;
{
	struct ifaddr *ifa;
	struct ifreq *ifr;
	struct sockaddr_in6 *sin6;
	int error;

	error = 0;
	switch (cmd) {
	case SIOCSIFADDR:
		ifa = (struct ifaddr *)data;
		if (ifa == NULL || ifa->ifa_addr->sa_family != AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_6TO4(&sin6->sin6_addr)) {
			ifa->ifa_rtrequest = stf_rtrequest;
			ifp->if_flags |= IFF_UP;
		} else
			error = EINVAL;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		ifr = (struct ifreq *)data;
		if (ifr && ifr->ifr_addr.sa_family == AF_INET6)
			;
		else
			error = EAFNOSUPPORT;
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

#endif /* NSTF > 0 */
