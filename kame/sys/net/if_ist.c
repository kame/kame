/*	$KAME: if_ist.c,v 1.5 2004/12/18 02:08:37 suz Exp $	*/

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
 * ISATAP interface, based on draft-ietf-ngtrans-isatap-12.txt
 */

#if defined(__FreeBSD__)
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_global.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/proc.h>
#endif
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#ifndef __FreeBSD__
#include <sys/ioctl.h>
#endif
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif
#include <sys/syslog.h>
#include <machine/cpu.h>

#ifdef __FreeBSD__
#include <sys/malloc.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/if_types.h>

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
#ifdef __OpenBSD__
#include <netinet/ip_ipsp.h>
#endif

#include <machine/stdarg.h>

#include <net/net_osdep.h>
#include <net/if_ist.h>

#ifdef __FreeBSD__
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif
#include "ist.h"
#include "gif.h"	/*XXX*/

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#if NGIF > 0
#include <net/if_gif.h>
#endif

#if NIST > 0

#define IN6_IS_ADDR_ISATAP(x)	(ntohl((x)->s6_addr32[2]) == 0x00005efe)

/*
 * XXX: Return a pointer with 16-bit aligned.  Don't cast it to
 * struct in_addr *; use bcopy() instead.
 */
#define GET_V4(x, y) ((caddr_t)(&(y)->s6_addr16[6]))


LIST_HEAD(, ist_softc) ist_softc_list;
static struct ist_softc *ist;
TAILQ_HEAD(isatap_rtrlist, isatap_rtr) isatap_rtrlist;
static int nist;

#if NGIF > 0
extern int ip_gif_ttl;	/*XXX*/
#else
static int ip_gif_ttl = 40;	/*XXX*/
#endif
#ifndef __OpenBSD__
static int ist_rtcachettl = 10; /* XXX appropriate value? configurable? */
#endif

extern struct domain inetdomain;
struct protosw in_ist_protosw =
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR,
  in_ist_input,
#if defined(__FreeBSD__) && __FreeBSD_version >= 502010
  (pr_output_t *)rip_output,
#else
  rip_output,
#endif
  0,		rip_ctloutput,
#ifdef __FreeBSD__
  0,
#else
  rip_usrreq,
#endif
  0,            0,              0,              0,
#ifdef __FreeBSD__
  &rip_usrreqs
#endif
};

#ifdef __FreeBSD__
void istattach(void *);
#else
void istattach(int);
#endif
static int ist_encapcheck(const struct mbuf *, int, int, void *);
static struct in6_ifaddr *ist_getsrcifa6(struct ifnet *);
static int isatap_match_prefix(struct ifnet *, struct in6_addr *);
static int ist_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	struct rtentry *);
static int ist_checkaddr4(struct ist_softc *, struct in_addr *,
	struct ifnet *);
static int ist_checkaddr6(struct ist_softc *, struct in6_addr *,
	struct ifnet *);
static int ist_checkaddr46(struct ist_softc *, struct in_addr *,
	struct in6_addr *);
static void ist_rtrequest(int, struct rtentry *, struct rt_addrinfo *);
static int ist_ioctl(struct ifnet *, u_long, caddr_t);
#ifdef __FreeBSD__	 
static int fill_isatap_rtrlist(struct sysctl_req *);	 
#else	 
int fill_isatap_rtrlist(void *, size_t *, size_t);	 
#endif

void
istattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct ist_softc *sc;
	int i;
	const struct encaptab *p;

	if (nist == 0)
		TAILQ_INIT(&isatap_rtrlist);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	nist = dummy;
#else
	nist = NIST;
#endif
	ist = malloc(nist * sizeof(struct ist_softc), M_DEVBUF, M_WAITOK);
	bzero(ist, nist * sizeof(struct ist_softc));
	sc = ist;

	/* XXX just in case... */
	for (i = 0; i < nist; i++) {
		sc = &ist[i];
		bzero(sc, sizeof(*sc));
#if defined(__NetBSD__) || defined(__OpenBSD__)
		snprintf(sc->sc_if.if_xname, sizeof(sc->sc_if.if_xname),
		     "ist%d", i);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 502010
		if_initname(&sc->sc_if, "ist", i);
#else
		sc->sc_if.if_name = "ist";
		sc->sc_if.if_unit = i;
#endif

		p = encap_attach_func(AF_INET, IPPROTO_IPV6, ist_encapcheck,
		    &in_ist_protosw, sc);
		if (p == NULL) {
			printf("%s: attach failed\n", if_name(&sc->sc_if));
			continue;
		}
		sc->encap_cookie = p;

		sc->sc_if.if_addrlen = 0;
		sc->sc_if.if_mtu    = IPV6_MMTU;
		sc->sc_if.if_ioctl  = ist_ioctl;
		sc->sc_if.if_output = ist_output;
		sc->sc_if.if_type   = IFT_IST;
#ifdef __NetBSD__
		sc->sc_if.if_dlt = DLT_NULL;
#endif
		/* turn off ingress filter */
		sc->sc_if.if_flags  |= IFF_LINK2;
		sc->sc_if.if_flags |= IFF_MULTICAST;
		sc->sc_if.if_flags |= IFF_POINTOPOINT;	/* XXX */

#ifdef __FreeBSD__
		sc->sc_if.if_snd.ifq_maxlen = IFQ_MAXLEN;
#endif
		if_attach(&sc->sc_if);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		if_alloc_sadl(&sc->sc_if);
#endif
#if NBPFILTER > 0
#ifdef HAVE_NEW_BPFATTACH
		bpfattach(&sc->sc_if, DLT_NULL, sizeof(u_int));
#else
		bpfattach(&sc->sc_if.if_bpf, &sc->sc_if, DLT_NULL, sizeof(u_int));
#endif
#endif
		LIST_INSERT_HEAD(&ist_softc_list, sc, sc_list);
	}
}

#ifdef __FreeBSD__
PSEUDO_SET(istattach, if_ist);
#endif

static int
ist_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip ip;
	struct in6_ifaddr *ia6;
	struct ist_softc *sc;

	sc = (struct ist_softc *)arg;
	if (sc == NULL)
		return 0;

	if ((sc->sc_if.if_flags & IFF_UP) == 0)
		return 0;

	/* IFF_LINK0 means "no decapsulation" */
	if ((sc->sc_if.if_flags & IFF_LINK0) != 0)
		return 0;

	if (proto != IPPROTO_IPV6)
		return 0;

	/* LINTED const cast */
#ifdef __FreeBSD__
	m_copydata(m, 0, sizeof(ip), (caddr_t)&ip);
#else
	m_copydata((struct mbuf *)m, 0, sizeof(ip), (caddr_t)&ip);
#endif

	if (ip.ip_v != 4)
		return 0;

	ia6 = ist_getsrcifa6(&sc->sc_if);
	if (ia6 == NULL)
		return 0;

	/*
	 * check if IPv4 dst matches the IPv4 address derived from the
	 * local ISATAP address.
	 * success on: dst = 10.1.1.1, ia6->ia_addr = (prefix)::5efe:0a01:0101
	 */
	if (bcmp(GET_V4(sc, &ia6->ia_addr.sin6_addr), &ip.ip_dst,
	    sizeof(ip.ip_dst)) != 0)
		return 0;

	/*
	 * IPv4 src must be the ISATAP router IPv4 address
	 * if the IPv6 src does not belong to the ISATAP prefix of this 
	 * interface (draft-ietf-ngtrans-isatap-08.txt 4.5).
	 * However, it is checked later on.
	 */
	/* ist interface makes single side match only */
	return 32;
}

static struct in6_ifaddr *
ist_getsrcifa6(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ia;
	struct in_ifaddr *ia4;
	struct sockaddr_in6 *sin6;
	struct in_addr in;
	struct ist_softc *sc;

	sc = (struct ist_softc *)ifp;

	for (ia = ifp->if_addrlist.tqh_first; ia; ia = ia->ifa_list.tqe_next) {
		if (ia->ifa_addr == NULL)
			continue;
		if (ia->ifa_addr->sa_family != AF_INET6)
			continue;
		sin6 = (struct sockaddr_in6 *)ia->ifa_addr;

		/*
		 * assumes the embeddd IPv4 address is unique per among	 
		 * multiple ISATAP prefixed on an ISATAP interface	 
		 * XXX: really okay?	 
		 */	 
		if (!IN6_IS_ADDR_ISATAP(&sin6->sin6_addr))
			continue;

		bcopy(GET_V4(sc, &sin6->sin6_addr), &in, sizeof(in));
#ifdef __NetBSD__
		INADDR_TO_IA(in, ia4);
#else
#if __OpenBSD__
		for (ia4 = in_ifaddr.tqh_first;
		     ia4;
		     ia4 = ia4->ia_list.tqe_next)
#else
		for (ia4 = TAILQ_FIRST(&in_ifaddrhead);
		     ia4;
		     ia4 = TAILQ_NEXT(ia4, ia_link))
#endif
		{
			if (ia4->ia_addr.sin_addr.s_addr == in.s_addr)
				break;
		}
#endif
		if (ia4 == NULL)
			continue;

		return (struct in6_ifaddr *)ia;
	}

	return NULL;
}

static int	 
isatap_match_prefix(ifp, addr6)	 
	struct ifnet *ifp;	 
	struct in6_addr *addr6;	 
{
	struct ifaddr *ia;	 
	struct in6_ifaddr *ia6;	 
	struct sockaddr_in6 sa6, *sin6, *mask6;	 
	struct stf_softc *sc;	 

	sc = (struct stf_softc *)ifp;	 

	bzero(&sa6, sizeof(sa6));	 
	sa6.sin6_family = AF_INET6;	 
	sa6.sin6_len = sizeof(sa6);	 
	sa6.sin6_addr = *addr6;	 
	if (in6_addr2zoneid(ifp, addr6, &sa6.sin6_scope_id)) {	 
		return 0;	 
	}	 
	if (in6_embedscope(&sa6.sin6_addr, &sa6)) {	 
		return 0;	 
	}	 

	for (ia = ifp->if_addrlist.tqh_first; ia; ia = ia->ifa_list.tqe_next) {
		if (ia->ifa_addr == NULL)	 
			continue;
		if (ia->ifa_addr->sa_family != AF_INET6)	 
			continue;
		ia6 = (struct in6_ifaddr *)ia;
		sin6 = &ia6->ia_addr;
		mask6 = &ia6->ia_prefixmask;
		if (!IN6_IS_ADDR_ISATAP(&sin6->sin6_addr))
			continue;
		if (IN6_ARE_MASKED_ADDR_EQUAL(&sa6.sin6_addr, &sin6->sin6_addr,	 
		    &mask6->sin6_addr))
			return 1;
	}	 

	return 0;	 
}

#ifndef offsetof
#define offsetof(s, e) ((int)&((s *)0)->e)
#endif

static int
ist_output(ifp, m, dst, rt)
struct ifnet *ifp;
struct mbuf *m;
struct sockaddr *dst;
struct rtentry *rt;
{
#ifdef __OpenBSD__
	struct ist_softc *sc;
	struct sockaddr_in6 *dst6;
	struct in_addr in4;
	caddr_t ptr;
	struct tdb tdb;
	struct xformsw xfs;
	int error;
	int hlen, poff;
	struct ip6_hdr *ip6;
	struct in6_ifaddr *ia6;
	struct mbuf *mp;
	u_int16_t plen;

	sc = (struct ist_softc*)ifp;
	dst6 = (struct sockaddr_in6 *)dst;

	/* just in case */
	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ifp->if_oerrors++;
		return ENETDOWN;
	}

	/*
	 * If we don't have an ip4 address that match my inner ip6 address,
	 * we shouldn't generate output.  Without this check, we'll end up
	 * using wrong IPv4 source.
	 */
	ia6 = ist_getsrcifa6(ifp);
	if (ia6 == NULL) {
		m_freem(m);
		ifp->if_oerrors++;
		return ENETDOWN;
	}

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m) {
			ifp->if_oerrors++;
			return ENOBUFS;
		}
	}
	ip6 = mtod(m, struct ip6_hdr *);

	/*
	 * Pickup the right outer dst addr from the list of candidates.
	 * ip6_dst has priority as it may be able to give us shorter IPv4 hops.
	 */
	ptr = NULL;
	if (IN6_IS_ADDR_ISATAP(&ip6->ip6_dst) &&	 
	    isatap_match_prefix(&sc->sc_if, &ip6->ip6_dst)) {
		ptr = GET_V4(sc, &ip6->ip6_dst);
	}
	if (IN6_IS_ADDR_ISATAP(&dst6->sin6_addr)) {
		ptr = GET_V4(sc, &dst6->sin6_addr);
	}
	if (ptr == NULL) {
		m_freem(m);
		ifp->if_oerrors++;
		return ENETUNREACH;
	}
	bcopy(ptr, &in4, sizeof(in4));

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
		u_int32_t af = AF_INET6;
		
		m0.m_flags = 0;
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
		bpf_mtap(ifp->if_bpf, &m0);
	}
#endif /*NBPFILTER > 0*/

	/* setup dummy tdb.  it highly depends on ipipoutput() code. */
	bzero(&tdb, sizeof(tdb));
	bzero(&xfs, sizeof(xfs));
	tdb.tdb_src.sin.sin_family = AF_INET;
	tdb.tdb_src.sin.sin_len = sizeof(struct sockaddr_in);
	bcopy(GET_V4(sc, &((struct sockaddr_in6 *)&ia6->ia_addr)->sin6_addr),
	    &tdb.tdb_src.sin.sin_addr, sizeof(tdb.tdb_src.sin.sin_addr));
	tdb.tdb_dst.sin.sin_family = AF_INET;
	tdb.tdb_dst.sin.sin_len = sizeof(struct sockaddr_in);
	bcopy(&in4, &tdb.tdb_dst.sin.sin_addr, sizeof(tdb.tdb_dst.sin.sin_addr));
	tdb.tdb_xform = &xfs;
	xfs.xf_type = -1;	/* not XF_IP4 */

	hlen = sizeof(struct ip6_hdr);
	poff = offsetof(struct ip6_hdr, ip6_nxt);

	/* encapsulate into IPv4 packet */
	mp = NULL;
	error = ipip_output(m, &tdb, &mp, hlen, poff);
	if (error) {
		ifp->if_oerrors++;
		return error;
	} else if (mp == NULL) {
		ifp->if_oerrors++;
		return EFAULT;
	}

	m = mp;

	/* ip_output needs host-order length.  it should be nuked */
	m_copydata(m, offsetof(struct ip, ip_len), sizeof(u_int16_t),
	    (caddr_t) &plen);
	NTOHS(plen);
	m_copyback(m, offsetof(struct ip, ip_len), sizeof(u_int16_t),
	    (caddr_t) &plen);

	ifp->if_opackets++;
	return ip_output(m, NULL, NULL, 0, NULL, NULL);
#else /* !OpenBSD */
	struct ist_softc *sc;
	struct sockaddr_in6 *dst6;
	struct in_addr in4;
	caddr_t ptr;
	struct sockaddr_in *dst4;
	u_int8_t tos;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct in6_ifaddr *ia6;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

	sc = (struct ist_softc*)ifp;
	dst6 = (struct sockaddr_in6 *)dst;

	/* just in case */
	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		ifp->if_oerrors++;
		return ENETDOWN;
	}

	/*
	 * If we don't have an ip4 address that match my inner ip6 address,
	 * we shouldn't generate output.  Without this check, we'll end up
	 * using wrong IPv4 source.
	 */
	ia6 = ist_getsrcifa6(ifp);
	if (ia6 == NULL) {
		m_freem(m);
		ifp->if_oerrors++;
		return ENETDOWN;
	}

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m) {
			ifp->if_oerrors++;
			return ENOBUFS;
		}
	}
	ip6 = mtod(m, struct ip6_hdr *);
	tos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;

	/*
	 * Pickup the right outer dst addr from the list of candidates.
	 * ip6_dst has priority as it may be able to give us shorter IPv4 hops.
	 */
	ptr = NULL;
	if (IN6_IS_ADDR_ISATAP(&ip6->ip6_dst) &&
	    isatap_match_prefix(&sc->sc_if, &ip6->ip6_dst)) {
		ptr = GET_V4(sc, &ip6->ip6_dst);
	}
	if (IN6_IS_ADDR_ISATAP(&dst6->sin6_addr)) {
		ptr = GET_V4(sc, &dst6->sin6_addr);
	}
	if (ptr == NULL) {
		m_freem(m);
		ifp->if_oerrors++;
		return ENETUNREACH;
	}
	bcopy(ptr, &in4, sizeof(in4));

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
		u_int32_t af = AF_INET6;
		
		m0.m_flags = 0;
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
#ifdef HAVE_NEW_BPF
		bpf_mtap(ifp, &m0);
#else
		bpf_mtap(ifp->if_bpf, &m0);
#endif
	}
#endif /*NBPFILTER > 0*/

	M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip))
		m = m_pullup(m, sizeof(struct ip));
	if (m == NULL) {
		ifp->if_oerrors++;
		return ENOBUFS;
	}
	ip = mtod(m, struct ip *);

	bzero(ip, sizeof(*ip));

	bcopy(GET_V4(sc, &((struct sockaddr_in6 *)&ia6->ia_addr)->sin6_addr),
	    &ip->ip_src, sizeof(ip->ip_src));
	bcopy(&in4, &ip->ip_dst, sizeof(ip->ip_dst));
	ip->ip_p = IPPROTO_IPV6;
	ip->ip_ttl = ip_gif_ttl;	/*XXX*/
	ip->ip_len = m->m_pkthdr.len;	/*host order*/
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &ip->ip_tos, &tos);
	else
		ip_ecn_ingress(ECN_NOCARE, &ip->ip_tos, &tos);

	dst4 = (struct sockaddr_in *)&sc->sc_ro.ro_dst;

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif
	/*
	 * Check if the cached route is still valid.  If not, create another
	 * one. (see comments in netinet/in_gif.c:in_gif_output())
	 */
	if (sc->sc_ro.ro_rt && (!(sc->sc_ro.ro_rt->rt_flags & RTF_UP) ||
	    dst4->sin_family != AF_INET ||
	    bcmp(&dst4->sin_addr, &ip->ip_dst, sizeof(ip->ip_dst)) != 0 ||
	    sc->rtcache_expire == 0 || mono_time.tv_sec >= sc->rtcache_expire)) {
		/*
		 * The cache route doesn't match, has been invalidated, or has
		 * expired.
		 */
		RTFREE(sc->sc_ro.ro_rt);
		sc->sc_ro.ro_rt = NULL;
	}
	if (sc->sc_ro.ro_rt == NULL) {
		bzero(dst, sizeof(*dst));
		dst4->sin_family = AF_INET;
		dst4->sin_len = sizeof(struct sockaddr_in);
		bcopy(&ip->ip_dst, &dst4->sin_addr, sizeof(dst4->sin_addr));

		rtalloc(&sc->sc_ro);
		if (sc->sc_ro.ro_rt == NULL) {
			m_freem(m);
			ifp->if_oerrors++;
			return ENETUNREACH;
		}

		/* if it constitutes infinite encapsulation, punt. */
		if (sc->sc_ro.ro_rt->rt_ifp == ifp) {
			RTFREE(sc->sc_ro.ro_rt);
			sc->sc_ro.ro_rt = NULL;
			m_freem(m);
			ifp->if_oerrors++;
			return ENETUNREACH;	/* XXX */
		}

		sc->rtcache_expire = mono_time.tv_sec + ist_rtcachettl;
	}
	ifp->if_opackets++;
	return ip_output(m, NULL, &sc->sc_ro, 0, NULL
#ifdef __FreeBSD__
			, NULL
#endif
			);
#endif
}

static int
ist_checkaddr4(sc, in, inifp)
	struct ist_softc *sc;
	struct in_addr *in;
	struct ifnet *inifp;	/* incoming interface */
{
	struct in_ifaddr *ia4;

	/*
	 * reject packets with the following address:
	 * 224.0.0.0/4 0.0.0.0/8 127.0.0.0/8 255.0.0.0/8
	 * (the last three is not explicitly mentioned
	 *  in draft-ietf-ngtrans-isatap-08.txt, but they
	 *  should be rejected)
	 */
#if defined(__OpenBSD__) || defined(__NetBSD__)
	if (IN_MULTICAST(in->s_addr))
#else
	if (IN_MULTICAST(ntohl(in->s_addr)))
#endif
		return -1;
	switch ((ntohl(in->s_addr) & 0xff000000) >> 24) {
	case 0: case 127: case 255:
		return -1;
	}

	/*
	 * reject packets with broadcast
	 */
#if defined(__OpenBSD__) || defined(__NetBSD__)
	for (ia4 = in_ifaddr.tqh_first; ia4; ia4 = ia4->ia_list.tqe_next)
#else
	for (ia4 = TAILQ_FIRST(&in_ifaddrhead);
	     ia4;
	     ia4 = TAILQ_NEXT(ia4, ia_link))
#endif
	{
		if ((ia4->ia_ifa.ifa_ifp->if_flags & IFF_BROADCAST) == 0)
			continue;
		if (in->s_addr == ia4->ia_broadaddr.sin_addr.s_addr)
			return -1;
	}

	/*
	 * perform ingress filter
	 */
	if (sc && (sc->sc_if.if_flags & IFF_LINK2) == 0 && inifp) {
		struct sockaddr_in sin;
		struct rtentry *rt;

		bzero(&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(struct sockaddr_in);
		sin.sin_addr = *in;
#ifdef __FreeBSD__
		rt = rtalloc1((struct sockaddr *)&sin, 0, 0UL);
#else
		rt = rtalloc1((struct sockaddr *)&sin, 0);
#endif
		if (!rt || rt->rt_ifp != inifp) {
#if 0
			log(LOG_WARNING, "%s: packet from 0x%x dropped "
			    "due to ingress filter\n", if_name(&sc->sc_if),
			    (u_int32_t)ntohl(sin.sin_addr.s_addr));
#endif
			if (rt)
				rtfree(rt);
			return -1;
		}
		rtfree(rt);
	}

	return 0;
}

static int
ist_checkaddr6(sc, in6, inifp)
	struct ist_softc *sc;
	struct in6_addr *in6;
	struct ifnet *inifp;	/* incoming interface */
{

	/*
	 * check ISATAP addresses
	 */
	if (IN6_IS_ADDR_ISATAP(in6) && isatap_match_prefix(&sc->sc_if, in6)) {
		struct in_addr in4;
		bcopy(GET_V4(sc, in6), &in4, sizeof(in4));
		return ist_checkaddr4(sc, &in4, inifp);
	}

	/*
	 * reject anything that look suspicious.  the test is implemented
	 * in ip6_input too, but we check here as well to
	 * (1) reject bad packets earlier, and
	 * (2) to be safe against future ip6_input change.
	 */
	if (IN6_IS_ADDR_V4COMPAT(in6) || IN6_IS_ADDR_V4MAPPED(in6))
		return -1;

	/*
	 * if the destination IPv6 address is multicast, then it	 
	 * has to be ff02::2, otherwise discarded	 
	 */	 
	if (!IN6_IS_ADDR_MULTICAST(in6))
		return 0;	 
	if (IN6_ARE_ADDR_EQUAL(in6, &in6addr_linklocal_allrouters))
		return 0;	 
	return -1;	 
}

/*	 
 * to see the combination of the outer IPv4 address and the inner
 * IPv6 address are appropriate (draft-ietf-ngtrans-isatap-08.txt 4.5 Rule #2)
 * you must check the validity of each address by stf_checkaddr[46] in advance.
 */
static int
ist_checkaddr46(sc, in, in6)
	struct ist_softc *sc;
	struct in_addr *in;
	struct in6_addr *in6;
{
	struct isatap_rtr *rtr;

	/*
	 * if the source address is not ISATAP prefix, then
	 * the outer IPv4 source address MUST be an ISATAP router's one
	 */
	if (isatap_match_prefix(&sc->sc_if, in6))
		return 0;

	TAILQ_FOREACH(rtr, &isatap_rtrlist, isr_entry) {
		struct sockaddr_in *ptr;	 

		ptr = (struct sockaddr_in *) &rtr->isr_addr;
		if (in->s_addr == ptr->sin_addr.s_addr)
			return 0;
	}
 
	return -1;
}

void
#ifdef __FreeBSD__
in_ist_input(m, off)
	struct mbuf *m;
	int off;
#else
#if __STDC__
in_ist_input(struct mbuf *m, ...)
#else
in_ist_input(m, va_alist)
	struct mbuf *m;
#endif
#endif /* __FreeBSD__ */
{
#ifndef __FreeBSD__
	int off, proto;
	va_list ap;
#else
	int proto;
#endif /* __FreeBSD__ */
	struct ist_softc *sc;
	struct ip *ip;
	struct ip6_hdr *ip6;
	u_int8_t otos, itos;
#if !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
	int s;
#endif
	int isr;
	struct ifqueue *ifq = NULL;
	struct ifnet *ifp;

#ifndef __FreeBSD__
	va_start(ap, m);
	off = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);
#endif /* __FreeBSD__ */

	ip = mtod(m, struct ip *);
#ifdef __FreeBSD__
	proto = ip->ip_p;
#endif

	if (proto != IPPROTO_IPV6) {
		m_freem(m);
		return;
	}

	sc = (struct ist_softc *)encap_getarg(m);

	if (sc == NULL || (sc->sc_if.if_flags & IFF_UP) == 0) {
		m_freem(m);
		return;
	}

	ifp = &sc->sc_if;

	/*
	 * perform sanity check against outer src/dst.
	 * for source, perform ingress filter as well.
	 */
	if (ist_checkaddr4(sc, &ip->ip_dst, NULL) < 0 ||
	    ist_checkaddr4(sc, &ip->ip_src, m->m_pkthdr.rcvif) < 0) {
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

	/*
	 * perform sanity check against inner src/dst.
	 * for source, perform ingress filter as well.
	 */
	if (ist_checkaddr6(sc, &ip6->ip6_dst, NULL) < 0 ||
	    ist_checkaddr6(sc, &ip6->ip6_src, m->m_pkthdr.rcvif) < 0) {
		m_freem(m);
		return;
	}

	/*
	 * perform sanity check against inner/outer source address.
	 */
	if (ist_checkaddr46(sc, &ip->ip_src, &ip6->ip6_src) < 0) {
		m_freem(m);
		return;
	}
	itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
	if (ip_ecn_egress((ifp->if_flags & IFF_LINK1) ?
			  ECN_ALLOWED : ECN_NOCARE, &otos, &itos) == 0) {
		m_freem(m);
		return;
	}
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
		u_int32_t af = AF_INET6;
		
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
#ifdef HAVE_NEW_BPF
		bpf_mtap(ifp, &m0);
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

#if (defined(__FreeBSD__) && __FreeBSD_version >= 500000)
	if (!IF_HANDOFF(ifq, m, NULL))
		return;
#else
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splnet();
#else
	s = splimp();
#endif
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);	/* update statistics */
		m_freem(m);
		splx(s);
		return;
	}
	IF_ENQUEUE(ifq, m);
#endif

	schednetisr(isr);
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
#if !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
	splx(s);
#endif
}

/* ARGSUSED */
static void
ist_rtrequest(cmd, rt, info)
	int cmd;
	struct rtentry *rt;
	struct rt_addrinfo *info;
{

	if (rt)
		rt->rt_rmx.rmx_mtu = IPV6_MMTU;
}

static int
ist_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	caddr_t data;
{
#if defined(__NetBSD__) || defined(__OpenBSD__)
	struct proc *p = curproc;	/* XXX */
#endif
	struct ifaddr *ifa;
	struct ifreq *ifr;
	struct ist_softc *sc;
	struct sockaddr_in6 *sin6;
	struct in_addr addr;
	int error;
	int s;
	struct isatap_rtr *rtr;

	error = 0;
	ifr = (struct ifreq *)data;
	sc = (struct ist_softc *) ifp;		

	switch (cmd) {
	case SIOCSIFADDR:
		ifa = (struct ifaddr *)data;
		if (ifa == NULL || ifa->ifa_addr->sa_family != AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (!IN6_IS_ADDR_ISATAP(&sin6->sin6_addr)) {
			error = EINVAL;
			break;
		}

		bcopy(GET_V4(sc, &sin6->sin6_addr), &addr, sizeof(addr));
		ifa->ifa_rtrequest = ist_rtrequest;
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifr && ifr->ifr_addr.sa_family == AF_INET6)
			;
		else
			error = EAFNOSUPPORT;
		break;
	case SIOCSISATAPRTR:
#ifdef __NetBSD__
		if (p && (error = suser(p->p_ucred, &p->p_acflag)) != 0)
			break;
#elif defined(__OpenBSD__)
		if (p && (error = suser(p, 0)) != 0)
			break;
#endif	 

		/* check the given ISATAP router address */
		if (ifr->ifr_addr.sa_family != AF_INET) {
			error = EAFNOSUPPORT;
			break;
		}
		addr = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr;
		if (ist_checkaddr4(sc, &addr, NULL) < 0) {
			error = EFAULT;
			break;
		}
		TAILQ_FOREACH(rtr, &isatap_rtrlist, isr_entry) {
			struct sockaddr_in *ptr;

			ptr = (struct sockaddr_in *) &rtr->isr_addr;
			if (addr.s_addr == ptr->sin_addr.s_addr) {
				error = EEXIST;
				return 0;
			}
		}

		rtr = malloc(sizeof(*rtr), M_IFADDR, M_WAITOK);
		bzero(rtr, sizeof(*rtr));
		bcopy(&ifr->ifr_addr, &rtr->isr_addr, ifr->ifr_addr.sa_len);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		s = splnet();
#else
		s = splimp();
#endif
		TAILQ_INSERT_TAIL(&isatap_rtrlist, rtr, isr_entry);
		splx(s);
		/* IPv6 default route will be installed by RA */
		break;

	case SIOCDISATAPRTR:
#ifdef __NetBSD__
		if (p && (error = suser(p->p_ucred, &p->p_acflag)) != 0)
			break;
#elif defined(__OpenBSD__)
		if (p && (error = suser(p, 0)) != 0)
			break;
#endif	 
		/* check the given ISATAP router address */	 
		if (ifr->ifr_addr.sa_family != AF_INET) {
			error = EAFNOSUPPORT;
			break;
		}
		addr = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr;
		if (ist_checkaddr4(sc, &addr, NULL) < 0) {
			error = EFAULT;
			break;
		}
		TAILQ_FOREACH(rtr, &isatap_rtrlist, isr_entry) {
			struct sockaddr_in *ptr;

			ptr = (struct sockaddr_in *) &rtr->isr_addr;
			if (addr.s_addr != ptr->sin_addr.s_addr)
				continue;

#if defined(__NetBSD__) || defined(__OpenBSD__)
			s = splnet();
#else
			s = splimp();
#endif
			TAILQ_REMOVE(&isatap_rtrlist, rtr, isr_entry);
			free(rtr, M_IFADDR);
			splx(s);
			return error;
		}
		error = EADDRNOTAVAIL;
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

#ifdef __FreeBSD__
static int ist_sysctl_isatap_rtrlist(SYSCTL_HANDLER_ARGS);
SYSCTL_DECL(_net_inet6_ip6);
SYSCTL_NODE(_net_inet6_ip6, IPV6CTL_ISATAPRTR, isatap_rtrlist, CTLFLAG_RD,
	    &ist_sysctl_isatap_rtrlist, "");

static int
ist_sysctl_isatap_rtrlist(SYSCTL_HANDLER_ARGS)
{
	if (req->newptr)
		return EPERM;	 
	return (fill_isatap_rtrlist(req));	 
}
#endif /* __FreeBSD__ */

#ifndef __FreeBSD__
int
fill_isatap_rtrlist(oldp, oldlenp, ol)
	void *oldp;
	size_t *oldlenp, ol;
#else
static int
fill_isatap_rtrlist(req)
	struct sysctl_req *req;
#endif
{
	int error = 0;
	struct isatap_rtr *isr;
	struct sockaddr_in *o = NULL, *oe = NULL;
#ifdef __FreeBSD__
	struct sockaddr_in dbuf;
#else
	size_t len = 0;
#endif

#ifndef __FreeBSD__	 
	if (oldp) {
		o = (struct sockaddr_in *) oldp;
		oe = (struct sockaddr_in *) ((caddr_t)oldp + *oldlenp);
	}
#endif

	TAILQ_FOREACH(isr, &isatap_rtrlist, isr_entry) {
#ifdef __FreeBSD__
		o = &dbuf;
		oe = o + 1;
#endif
		if (
#ifndef __FreeBSD__
		    oldp &&
#endif
		    o + 1 <= oe) {
			bzero(o, sizeof(*o));
			bcopy(&isr->isr_addr, o, isr->isr_addr.sa_len);
		}

#ifndef __FreeBSD__
		len += sizeof(*o);
		if (o)
			o++;
#else
		error = SYSCTL_OUT(req, o, sizeof(*o));
		if (error)
			break;
#endif
	}

#ifndef __FreeBSD__
	*oldlenp = len;
	if (oldp && (len > ol))
		error = ENOMEM;
#endif

	return error;
}
#endif /* NIST > 0 */
