/*	$KAME: if_gif.c,v 1.108 2004/05/26 09:54:46 itojun Exp $	*/

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
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#include "opt_iso.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#ifdef __FreeBSD__
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#ifdef __FreeBSD__
/*nothing*/
#else
#include <sys/ioctl.h>
#endif
#include <sys/time.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <machine/cpu.h>
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
#include <machine/intr.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>
#if defined(__FreeBSD__) && __FreeBSD_version > 502000
#include <net/pfil.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef	INET
#include <netinet/in_var.h>
#include <netinet/in_gif.h>
#endif	/* INET */

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_gif.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>
#endif /* INET6 */

#if defined(__NetBSD__) && defined(ISO)
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#endif

#include <netinet/ip_encap.h>
#include <net/if_gif.h>

#include "gif.h"
#ifdef __FreeBSD__
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif
#ifdef __OpenBSD__
#include "bridge.h"
#endif

#include <net/net_osdep.h>

#if NGIF > 0

LIST_HEAD(, gif_softc) gif_softc_list;

#ifdef __FreeBSD__
void gifattach __P((void *));
#else
void gifattach __P((int));
#endif
#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
void gifnetisr __P((void));
#endif
void gifintr __P((void *));
#if defined(__NetBSD__) && defined(ISO)
static struct mbuf *gif_eon_encap(struct mbuf *);
static struct mbuf *gif_eon_decap(struct ifnet *, struct mbuf *);
#endif

/*
 * gif global variable definitions
 */
int ngif;			/* number of interfaces */
struct gif_softc *gif_softc = NULL;

void
gifattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct gif_softc *sc;
	int i;

	LIST_INIT(&gif_softc_list);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	ngif = dummy;
#else
	ngif = NGIF;
#endif
	gif_softc = sc = malloc(ngif * sizeof(struct gif_softc),
	    M_DEVBUF, M_WAIT);
	bzero(sc, ngif * sizeof(struct gif_softc));
	for (i = 0; i < ngif; sc++, i++) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		snprintf(sc->gif_if.if_xname, sizeof(sc->gif_if.if_xname),
		    "gif%d", i);
#elif defined(__FreeBSD__) && __FreeBSD_version > 501000
		if_initname(&sc->gif_if, "gif", i);
#else
		sc->gif_if.if_name = "gif";
		sc->gif_if.if_unit = i;
#endif
		gifattach0(sc);
		LIST_INSERT_HEAD(&gif_softc_list, sc, gif_list);
	}
}

void
gifattach0(sc)
	struct gif_softc *sc;
{

	sc->encap_cookie4 = sc->encap_cookie6 = NULL;

	sc->gif_if.if_addrlen = 0;
	sc->gif_if.if_mtu    = GIF_MTU;
	sc->gif_if.if_flags  = IFF_POINTOPOINT | IFF_MULTICAST;
	/* turn off ingress filter */
	sc->gif_if.if_flags  |= IFF_LINK2;
	sc->gif_if.if_ioctl  = gif_ioctl;
#ifdef __OpenBSD__
	sc->gif_if.if_start  = gif_start;
#endif
	sc->gif_if.if_output = gif_output;
	sc->gif_if.if_type   = IFT_GIF;
#ifdef __NetBSD__
	sc->gif_if.if_dlt = DLT_NULL;
#endif
#ifdef __FreeBSD__
	IFQ_SET_MAXLEN(&sc->gif_if.if_snd, IFQ_MAXLEN);
#endif
	IFQ_SET_READY(&sc->gif_if.if_snd);
	if_attach(&sc->gif_if);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	if_alloc_sadl(&sc->gif_if);
#endif
#if NBPFILTER > 0
#ifdef HAVE_NEW_BPFATTACH
	bpfattach(&sc->gif_if, DLT_NULL, sizeof(u_int));
#else
	bpfattach(&sc->gif_if.if_bpf, &sc->gif_if, DLT_NULL, sizeof(u_int));
#endif
#endif
}

#ifdef __FreeBSD__
PSEUDO_SET(gifattach, if_gif);
#endif

#ifdef __OpenBSD__
void
gif_start(ifp)
	struct ifnet *ifp;
{
#if NBRIDGE > 0
	struct sockaddr dst;
#endif /* NBRIDGE */

	struct mbuf *m;
	int s;

#if NBRIDGE > 0
	bzero(&dst, sizeof(dst));

	/*
	 * XXX The assumption here is that only the ethernet bridge
	 * uses the start routine of this interface, and it's thus
	 * safe to do this.
	 */
	dst.sa_family = AF_LINK;
#endif /* NBRIDGE */

	for (;;) {
#ifdef __NetBSD__
		s = splnet();
#else
		s = splimp();
#endif
		IFQ_DEQUEUE(&ifp->if_snd, m);
		splx(s);

		if (m == NULL) return;

#if NBRIDGE > 0
		/* Sanity check -- interface should be member of a bridge */
		if (ifp->if_bridge == NULL) m_freem(m);
		else gif_output(ifp, m, &dst, NULL);
#else
		m_freem(m);
#endif /* NBRIDGE */
	}
}
#endif

#ifdef GIF_ENCAPCHECK
int
gif_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip ip;
	struct gif_softc *sc;

	sc = (struct gif_softc *)arg;
	if (sc == NULL)
		return 0;

	if ((sc->gif_if.if_flags & IFF_UP) == 0)
		return 0;

	/* no physical address */
	if (!sc->gif_psrc || !sc->gif_pdst)
		return 0;

	switch (proto) {
#ifdef INET
	case IPPROTO_IPV4:
		break;
#endif
#ifdef INET6
	case IPPROTO_IPV6:
		break;
#endif
#if defined(__NetBSD__) && defined(ISO)
	case IPPROTO_EON:
		break;
#endif
	default:
		return 0;
	}

	/* Bail on short packets */
	if (m->m_pkthdr.len < sizeof(ip))
		return 0;

	/* LINTED const cast */
	m_copydata((struct mbuf *)m, 0, sizeof(ip), (caddr_t)&ip);

	switch (ip.ip_v) {
#ifdef INET
	case 4:
		if (sc->gif_psrc->sa_family != AF_INET ||
		    sc->gif_pdst->sa_family != AF_INET)
			return 0;
		return gif_encapcheck4(m, off, proto, arg);
#endif
#ifdef INET6
	case 6:
		if (m->m_pkthdr.len < sizeof(struct ip6_hdr))
			return 0;
		if (sc->gif_psrc->sa_family != AF_INET6 ||
		    sc->gif_pdst->sa_family != AF_INET6)
			return 0;
		return gif_encapcheck6(m, off, proto, arg);
#endif
	default:
		return 0;
	}
}
#endif

int
gif_output(ifp, m, dst, rt)
	struct ifnet *ifp;
	struct mbuf *m;
	struct sockaddr *dst;
	struct rtentry *rt;	/* added in net2 */
{
	struct gif_softc *sc = (struct gif_softc*)ifp;
	int error = 0;
	static int called = 0;	/* XXX: MUTEX */
	ALTQ_DECL(struct altq_pktattr pktattr;)
	int s;
	struct m_tag *mtag;

	IFQ_CLASSIFY(&ifp->if_snd, m, dst->sa_family, &pktattr);

	/*
	 * gif may cause infinite recursion calls when misconfigured.
	 * We'll prevent this by limiting packets from going through a gif
	 * interface up to once.
	 */
	for (mtag = m_tag_find(m, PACKET_TAG_GIF, NULL); mtag;
	     mtag = m_tag_find(m, PACKET_TAG_GIF, mtag)) {
		if (bcmp((caddr_t)(mtag + 1), &ifp, sizeof(struct ifnet *))
		    == 0) {
			m_freem(m);
			error = EIO;	/* is there better errno? */
			goto end;
		}
	}

	mtag = m_tag_get(PACKET_TAG_GIF, sizeof(struct ifnet *), M_NOWAIT);
	if (!mtag) {
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
		_IF_DROP(&ifp->if_snd);
#else
		IF_DROP(&ifp->if_snd);
#endif
		m_freem(m);
		error = ENOMEM;
		goto end;

	}
	bcopy(&ifp, (caddr_t)(mtag + 1), sizeof(struct ifnet *));
	m_tag_prepend(m, mtag);

	m->m_flags &= ~(M_BCAST|M_MCAST);
	if (!(ifp->if_flags & IFF_UP) ||
	    sc->gif_psrc == NULL || sc->gif_pdst == NULL) {
		m_freem(m);
		error = ENETDOWN;
		goto end;
	}

	/* inner AF-specific encapsulation */
	switch (dst->sa_family) {
#if defined(__NetBSD__) && defined(ISO)
	case AF_ISO:
		m = gif_eon_encap(m);
		if (!m) {
			error = ENOBUFS;
			goto end;
		}
		break;
#endif
	default:
		break;
	}

	/* XXX should we check if our outer source is legal? */

	/* use DLT_NULL encapsulation here to pass inner af type */
	M_PREPEND(m, sizeof(int), M_DONTWAIT);
	if (!m) {
		error = ENOBUFS;
		goto end;
	}
	*mtod(m, int *) = dst->sa_family;

	s = splnet();
	IFQ_ENQUEUE(&ifp->if_snd, m, &pktattr, error);
	if (error) {
		splx(s);
		goto end;
	}
	splx(s);

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	softintr_schedule(sc->gif_si);
#else
	/* XXX bad spl level? */
	gifnetisr();
#endif
	error = 0;

  end:
	called = 0;		/* reset recursion counter */
	if (error)
		ifp->if_oerrors++;
	return error;
}

#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
void
gifnetisr()
{
	struct gif_softc *sc;

	for (sc = LIST_FIRST(&gif_softc_list); sc != NULL;
	     sc = LIST_NEXT(sc, gif_list)) {
		gifintr(sc);
	}
}
#endif

void
gifintr(arg)
	void *arg;
{
	struct gif_softc *sc;
	struct ifnet *ifp;
	struct mbuf *m;
	int family;
	int len;
	int s;
	int error;

	sc = (struct gif_softc *)arg;
	ifp = &sc->gif_if;

	/* output processing */
	while (1) {
		s = splnet();
		IFQ_DEQUEUE(&sc->gif_if.if_snd, m);
		splx(s);
		if (m == NULL)
			break;

		/* grab and chop off inner af type */
		if (sizeof(int) > m->m_len) {
			m = m_pullup(m, sizeof(int));
			if (!m) {
				ifp->if_oerrors++;
				continue;
			}
		}
		family = *mtod(m, int *);
#if NBPFILTER > 0
		if (ifp->if_bpf) {
#ifdef HAVE_NEW_BPF
			bpf_mtap(ifp, m);
#else
			bpf_mtap(ifp->if_bpf, m);
#endif
		}
#endif
		m_adj(m, sizeof(int));

		len = m->m_pkthdr.len;

		/* dispatch to output logic based on outer AF */
		switch (sc->gif_psrc->sa_family) {
#ifdef INET
		case AF_INET:
			error = in_gif_output(ifp, family, m);
			break;
#endif
#ifdef INET6
		case AF_INET6:
			error = in6_gif_output(ifp, family, m);
			break;
#endif
		default:
			m_freem(m);		
			error = ENETDOWN;
			break;
		}

		if (error)
			ifp->if_oerrors++;
		else {
			ifp->if_opackets++;	
			ifp->if_obytes += len;
		}
	}
}

#ifndef __OpenBSD__	/* on openbsd, ipip_input() does it instead */
void
gif_input(m, af, ifp)
	struct mbuf *m;
	int af;
	struct ifnet *ifp;
{
#if !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
	int s;
#endif
	int isr;
	struct ifqueue *ifq = NULL;

	if (ifp == NULL) {
		/* just in case */
		m_freem(m);
		return;
	}

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
		u_int32_t af1 = af;
		
		m0.m_flags = 0;
		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af1;
		
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
	 * Note: older versions of gif_input directly called network layer
	 * input functions, e.g. ip6_input, here.  We changed the policy to
	 * prevent too many recursive calls of such input functions, which
	 * might cause kernel panic.  But the change may introduce another
	 * problem; if the input queue is full, packets are discarded.
	 * The kernel stack overflow really happened, and we believed
	 * queue-full rarely occurs, so we changed the policy.
	 */
	switch (af) {
#ifdef INET
	case AF_INET:
		ifq = &ipintrq;
		isr = NETISR_IP;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		ifq = &ip6intrq;
		isr = NETISR_IPV6;
		break;
#endif
#if defined(__NetBSD__) && defined(ISO)
	case AF_ISO:
		m = gif_eon_decap(ifp, m);
		if (!m)
			return;
		ifq = &clnlintrq;
		isr = NETISR_ISO;
		break;
#endif
	default:
		m_freem(m);
		return;
	}

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	if (!IF_HANDOFF(ifq, m, NULL))
		return;
#else
#ifdef __NetBSD__
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

	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	/* we need schednetisr since the address family may change */
	schednetisr(isr);

#if !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
	splx(s);
#endif
	return;
}
#endif /*!OpenBSD*/

/* XXX how should we handle IPv6 scope on SIOC[GS]IFPHYADDR? */
int
gif_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
	u_long cmd;
	caddr_t data;
{
	struct gif_softc *sc  = (struct gif_softc*)ifp;
	struct ifreq     *ifr = (struct ifreq*)data;
	int error = 0, size;
	struct sockaddr *dst, *src;
#ifdef	SIOCSIFMTU /* xxx */
	u_long mtu;
#endif

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		break;
		
	case SIOCSIFDSTADDR:
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
#ifndef __FreeBSD__
		switch (ifr->ifr_addr.sa_family) {
#ifdef INET
		case AF_INET:	/* IP supports Multicast */
			break;
#endif /* INET */
#ifdef INET6
		case AF_INET6:	/* IP6 supports Multicast */
			break;
#endif /* INET6 */
		default:  /* Other protocols doesn't support Multicast */
			error = EAFNOSUPPORT;
			break;
		}
#endif
		break;

#ifdef	SIOCSIFMTU /* xxx */
	case SIOCGIFMTU:
		break;

	case SIOCSIFMTU:
		mtu = ifr->ifr_mtu;
		if (mtu < GIF_MTU_MIN || mtu > GIF_MTU_MAX)
			return (EINVAL);
		ifp->if_mtu = mtu;
		break;
#endif /* SIOCSIFMTU */

#ifdef INET
	case SIOCSIFPHYADDR:
#endif
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif /* INET6 */
	case SIOCSLIFPHYADDR:
		switch (cmd) {
#ifdef INET
		case SIOCSIFPHYADDR:
			src = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in_aliasreq *)data)->ifra_dstaddr);
			break;
#endif
#ifdef INET6
		case SIOCSIFPHYADDR_IN6:
			src = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_addr);
			dst = (struct sockaddr *)
				&(((struct in6_aliasreq *)data)->ifra_dstaddr);
			break;
#endif
		case SIOCSLIFPHYADDR:
			src = (struct sockaddr *)
				&(((struct if_laddrreq *)data)->addr);
			dst = (struct sockaddr *)
				&(((struct if_laddrreq *)data)->dstaddr);
			break;
		default:
			return EINVAL;
		}

		/* sa_family must be equal */
		if (src->sa_family != dst->sa_family)
			return EINVAL;

		/* validate sa_len */
		switch (src->sa_family) {
#ifdef INET
		case AF_INET:
			if (src->sa_len != sizeof(struct sockaddr_in))
				return EINVAL;
			break;
#endif
#ifdef INET6
		case AF_INET6:
			if (src->sa_len != sizeof(struct sockaddr_in6))
				return EINVAL;
			break;
#endif
		default:
			return EAFNOSUPPORT;
		}
		switch (dst->sa_family) {
#ifdef INET
		case AF_INET:
			if (dst->sa_len != sizeof(struct sockaddr_in))
				return EINVAL;
			break;
#endif
#ifdef INET6
		case AF_INET6:
			if (dst->sa_len != sizeof(struct sockaddr_in6))
				return EINVAL;
			break;
#endif
		default:
			return EAFNOSUPPORT;
		}

		/* check sa_family looks sane for the cmd */
		switch (cmd) {
		case SIOCSIFPHYADDR:
			if (src->sa_family == AF_INET)
				break;
			return EAFNOSUPPORT;
#ifdef INET6
		case SIOCSIFPHYADDR_IN6:
			if (src->sa_family == AF_INET6)
				break;
			return EAFNOSUPPORT;
#endif /* INET6 */
		case SIOCSLIFPHYADDR:
			/* checks done in the above */
			break;
		}

		error = gif_set_tunnel(&sc->gif_if, src, dst);
		break;

#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
		gif_delete_tunnel(&sc->gif_if);
		break;
#endif
			
	case SIOCGIFPSRCADDR:
#ifdef INET6
	case SIOCGIFPSRCADDR_IN6:
#endif /* INET6 */
		if (sc->gif_psrc == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_psrc;
		switch (cmd) {
#ifdef INET
		case SIOCGIFPSRCADDR:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#ifdef INET6
		case SIOCGIFPSRCADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;
			
	case SIOCGIFPDSTADDR:
#ifdef INET6
	case SIOCGIFPDSTADDR_IN6:
#endif /* INET6 */
		if (sc->gif_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->gif_pdst;
		switch (cmd) {
#ifdef INET
		case SIOCGIFPDSTADDR:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#ifdef INET6
		case SIOCGIFPDSTADDR_IN6:
			dst = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			size = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCGLIFPHYADDR:
		if (sc->gif_psrc == NULL || sc->gif_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}

		/* copy src */
		src = sc->gif_psrc;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->addr);
		size = sizeof(((struct if_laddrreq *)data)->addr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);

		/* copy dst */
		src = sc->gif_pdst;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->dstaddr);
		size = sizeof(((struct if_laddrreq *)data)->dstaddr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);
		break;

	case SIOCSIFFLAGS:
		/* if_ioctl() takes care of it */
		break;

	default:
		error = EINVAL;
		break;
	}
 bad:
	return error;
}

int
gif_set_tunnel(ifp, src, dst)
	struct ifnet *ifp;
	struct sockaddr *src;
	struct sockaddr *dst;
{
	struct gif_softc *sc = (struct gif_softc *)ifp;
	struct gif_softc *sc2;
	struct sockaddr *osrc, *odst, *sa;
	int s;
	int error = 0; 

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	for (sc2 = LIST_FIRST(&gif_softc_list); sc2 != NULL;
	     sc2 = LIST_NEXT(sc2, gif_list)) {
		if (sc2 == sc)
			continue;
		if (!sc2->gif_pdst || !sc2->gif_psrc)
			continue;
		if (sc2->gif_pdst->sa_family != dst->sa_family ||
		    sc2->gif_pdst->sa_len != dst->sa_len ||
		    sc2->gif_psrc->sa_family != src->sa_family ||
		    sc2->gif_psrc->sa_len != src->sa_len)
			continue;
#ifndef XBONEHACK
		/* can't configure same pair of address onto two gifs */
		if (bcmp(sc2->gif_pdst, dst, dst->sa_len) == 0 &&
		    bcmp(sc2->gif_psrc, src, src->sa_len) == 0) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
#endif

		/* XXX both end must be valid? (I mean, not 0.0.0.0) */
	}

	/* XXX we can detach from both, but be polite just in case */
	if (sc->gif_psrc)
		switch (sc->gif_psrc->sa_family) {
#ifdef INET
		case AF_INET:
			(void)in_gif_detach(sc);
			break;
#endif
#ifdef INET6
		case AF_INET6:
			(void)in6_gif_detach(sc);
			break;
#endif
		}

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	sc->gif_si = softintr_establish(IPL_SOFTNET, gifintr, sc);
	if (sc->gif_si == NULL) {
		error = ENOMEM;
		goto bad;
	}
#endif

	osrc = sc->gif_psrc;
	sa = (struct sockaddr *)malloc(src->sa_len, M_IFADDR, M_WAITOK);
	bcopy((caddr_t)src, (caddr_t)sa, src->sa_len);
	sc->gif_psrc = sa;

	odst = sc->gif_pdst;
	sa = (struct sockaddr *)malloc(dst->sa_len, M_IFADDR, M_WAITOK);
	bcopy((caddr_t)dst, (caddr_t)sa, dst->sa_len);
	sc->gif_pdst = sa;

	switch (sc->gif_psrc->sa_family) {
#ifdef INET
	case AF_INET:
		error = in_gif_attach(sc);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		/* Check validity of the scope zone ID of the addresses. */
		if ((error = scope6_check_id((struct sockaddr_in6 *)sc->gif_psrc,
					     0)) != 0 ||
		    (error = scope6_check_id((struct sockaddr_in6 *)sc->gif_pdst,
					     0)) != 0) {
			break;
		}
		error = in6_gif_attach(sc);
		break;
#endif
	}
	if (error) {
		/* rollback */
		free((caddr_t)sc->gif_psrc, M_IFADDR);
		free((caddr_t)sc->gif_pdst, M_IFADDR);
		sc->gif_psrc = osrc;
		sc->gif_pdst = odst;
		goto bad;
	}

	if (osrc)
		free((caddr_t)osrc, M_IFADDR);
	if (odst)
		free((caddr_t)odst, M_IFADDR);

	if (sc->gif_psrc && sc->gif_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);

	return 0;

 bad:
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->gif_si) {
		softintr_disestablish(sc->gif_si);
		sc->gif_si = NULL;
	}
#endif
	if (sc->gif_psrc && sc->gif_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);

	return error;
}

void
gif_delete_tunnel(ifp)
	struct ifnet *ifp;
{
	struct gif_softc *sc = (struct gif_softc *)ifp;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->gif_si) {
		softintr_disestablish(sc->gif_si);
		sc->gif_si = NULL;
	}
#endif
	if (sc->gif_psrc) {
		free((caddr_t)sc->gif_psrc, M_IFADDR);
		sc->gif_psrc = NULL;
	}
	if (sc->gif_pdst) {
		free((caddr_t)sc->gif_pdst, M_IFADDR);
		sc->gif_pdst = NULL;
	}
	/* it is safe to detach from both */
#ifdef INET
	(void)in_gif_detach(sc);
#endif
#ifdef INET6
	(void)in6_gif_detach(sc);
#endif

	if (sc->gif_psrc && sc->gif_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);
}

#if defined(__NetBSD__) && defined(ISO)
struct eonhdr {
	u_int8_t version;
	u_int8_t class;
	u_int16_t cksum;
};

/*
 * prepend EON header to ISO PDU
 */
static struct mbuf *
gif_eon_encap(struct mbuf *m)
{
	struct eonhdr *ehdr;

	M_PREPEND(m, sizeof(*ehdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(*ehdr))
		m = m_pullup(m, sizeof(*ehdr));
	if (m == NULL)
		return NULL;
	ehdr = mtod(m, struct eonhdr *);
	ehdr->version = 1;
	ehdr->class = 0;		/* always unicast */
#if 0
	/* calculate the checksum of the eonhdr */
	{
		struct mbuf mhead;
		memset(&mhead, 0, sizeof(mhead));
		ehdr->cksum = 0;
		mhead.m_data = (caddr_t)ehdr;
		mhead.m_len = sizeof(*ehdr);
		mhead.m_next = 0;
		iso_gen_csum(&mhead, offsetof(struct eonhdr, cksum),
		    mhead.m_len);
	}
#else
	/* since the data is always constant we'll just plug the value in */
	ehdr->cksum = htons(0xfc02);
#endif
	return m;
}

/*
 * remove EON header and check checksum
 */
static struct mbuf *
gif_eon_decap(struct ifnet *ifp, struct mbuf *m)
{
	struct eonhdr *ehdr;

	if (m->m_len < sizeof(*ehdr) &&
	    (m = m_pullup(m, sizeof(*ehdr))) == NULL) {
		ifp->if_ierrors++;
		return NULL;
	}
	if (iso_check_csum(m, sizeof(struct eonhdr))) {
		m_freem(m);
		return NULL;
	}
	m_adj(m, sizeof(*ehdr));
	return m;
}
#endif /*ISO*/
#endif /*NGIF > 0*/
