/*	$KAME: if_nemo.c,v 1.1 2004/12/09 02:18:58 t-momose Exp $	*/

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
#include "opt_iso.h"
#include "opt_mip6.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#if defined(__FreeBSD__) || __FreeBSD__ >= 3
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
#include <net/if_nemo.h>

#include "nemo.h"
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
#include "bpf.h"
#define NBPFILTER	NBPF
#else
#include "bpfilter.h"
#endif
#ifdef __OpenBSD__
#include "bridge.h"
#endif

#include <net/net_osdep.h>

#if NNEMO > 0

LIST_HEAD(, nemo_softc) nemo_softc_list;

#ifdef __FreeBSD__
void nemoattach __P((void *));
#else
void nemoattach __P((int));
#endif
#ifndef __HAVE_GENERIC_SOFT_INTERRUPTS
void nemonetisr __P((void));
#endif
void nemointr __P((void *));
#if defined(__NetBSD__) && defined(ISO)
static struct mbuf *nemo_eon_encap(struct mbuf *);
static struct mbuf *nemo_eon_decap(struct ifnet *, struct mbuf *);
#endif

/*
 * nemo global variable definitions
 */
int nnemo;			/* number of interfaces */
struct nemo_softc *nemo_softc = NULL;

void
nemoattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct nemo_softc *sc;
	int i;

	LIST_INIT(&nemo_softc_list);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	nnemo = dummy;
#else
	nnemo = NNEMO;
#endif
	nemo_softc = sc = malloc(nnemo * sizeof(struct nemo_softc),
	    M_DEVBUF, M_WAIT);
	bzero(sc, nnemo * sizeof(struct nemo_softc));
	for (i = 0; i < nnemo; sc++, i++) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
		snprintf(sc->nemo_if.if_xname, sizeof(sc->nemo_if.if_xname),
		    "nemo%d", i);
#elif defined(__FreeBSD__) && __FreeBSD_version > 501000
		if_initname(&sc->nemo_if, "nemo", i);
#else
		sc->nemo_if.if_name = "nemo";
		sc->nemo_if.if_unit = i;
#endif
		nemoattach0(sc);
		LIST_INSERT_HEAD(&nemo_softc_list, sc, nemo_list);
	}
}

void
nemoattach0(sc)
	struct nemo_softc *sc;
{

	sc->encap_cookie4 = sc->encap_cookie6 = NULL;

	sc->nemo_if.if_addrlen = 0;
	sc->nemo_if.if_mtu    = GIF_MTU;
	sc->nemo_if.if_flags  = IFF_POINTOPOINT | IFF_MULTICAST;
	/* turn off ingress filter */
	sc->nemo_if.if_flags  |= IFF_LINK2;
	sc->nemo_if.if_ioctl  = nemo_ioctl;
#ifdef __OpenBSD__
	sc->nemo_if.if_start  = nemo_start;
#endif
	sc->nemo_if.if_output = nemo_output;
	sc->nemo_if.if_type   = IFT_GIF;
#ifdef __NetBSD__
	sc->nemo_if.if_dlt = DLT_NULL;
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	IFQ_SET_MAXLEN(&sc->nemo_if.if_snd, IFQ_MAXLEN);
#endif
	IFQ_SET_READY(&sc->nemo_if.if_snd);
	if_attach(&sc->nemo_if);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	if_alloc_sadl(&sc->nemo_if);
#endif
#if NBPFILTER > 0
#ifdef HAVE_NEW_BPFATTACH
	bpfattach(&sc->nemo_if, DLT_NULL, sizeof(u_int));
#else
	bpfattach(&sc->nemo_if.if_bpf, &sc->nemo_if, DLT_NULL, sizeof(u_int));
#endif
#endif
#ifdef MIP6
	sc->nemo_nexthop = NULL;
#endif
}

#ifdef __FreeBSD__
PSEUDO_SET(nemoattach, if_nemo);
#endif

#ifdef __OpenBSD__
void
nemo_start(ifp)
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
		else nemo_output(ifp, m, &dst, NULL);
#else
		m_freem(m);
#endif /* NBRIDGE */
	}
}
#endif

#ifdef GIF_ENCAPCHECK
int
nemo_encapcheck(m, off, proto, arg)
	const struct mbuf *m;
	int off;
	int proto;
	void *arg;
{
	struct ip ip;
	struct nemo_softc *sc;

	sc = (struct nemo_softc *)arg;
	if (sc == NULL)
		return 0;

	if ((sc->nemo_if.if_flags & IFF_UP) == 0)
		return 0;

	/* no physical address */
	if (!sc->nemo_psrc || !sc->nemo_pdst)
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
		if (sc->nemo_psrc->sa_family != AF_INET ||
		    sc->nemo_pdst->sa_family != AF_INET)
			return 0;
		return nemo_encapcheck4(m, off, proto, arg);
#endif
#ifdef INET6
	case 6:
		if (m->m_pkthdr.len < sizeof(struct ip6_hdr))
			return 0;
		if (sc->nemo_psrc->sa_family != AF_INET6 ||
		    sc->nemo_pdst->sa_family != AF_INET6)
			return 0;
		return nemo_encapcheck6(m, off, proto, arg);
#endif
	default:
		return 0;
	}
}
#endif

int
nemo_output(ifp, m, dst, rt)
	struct ifnet *ifp;
	struct mbuf *m;
	struct sockaddr *dst;
	struct rtentry *rt;	/* added in net2 */
{
	struct nemo_softc *sc = (struct nemo_softc*)ifp;
	int error = 0;
	static int called = 0;	/* XXX: MUTEX */
	ALTQ_DECL(struct altq_pktattr pktattr;)
	int s;
	struct m_tag *mtag;

	IFQ_CLASSIFY(&ifp->if_snd, m, dst->sa_family, &pktattr);

	/*
	 * nemo may cause infinite recursion calls when misconfigured.
	 * We'll prevent this by limiting packets from going through a nemo
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
	    sc->nemo_psrc == NULL || sc->nemo_pdst == NULL) {
		m_freem(m);
		error = ENETDOWN;
		goto end;
	}

	/* inner AF-specific encapsulation */
	switch (dst->sa_family) {
#if defined(__NetBSD__) && defined(ISO)
	case AF_ISO:
		m = nemo_eon_encap(m);
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
	softintr_schedule(sc->nemo_si);
#else
	/* XXX bad spl level? */
	nemonetisr();
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
nemonetisr()
{
	struct nemo_softc *sc;

	for (sc = LIST_FIRST(&nemo_softc_list); sc != NULL;
	     sc = LIST_NEXT(sc, nemo_list)) {
		nemointr(sc);
	}
}
#endif

void
nemointr(arg)
	void *arg;
{
	struct nemo_softc *sc;
	struct ifnet *ifp;
	struct mbuf *m;
	int family;
	int len;
	int s;
	int error;

	sc = (struct nemo_softc *)arg;
	ifp = &sc->nemo_if;

	/* output processing */
	while (1) {
		s = splnet();
		IFQ_DEQUEUE(&sc->nemo_if.if_snd, m);
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
		switch (sc->nemo_psrc->sa_family) {
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
nemo_input(m, af, ifp)
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
	 * Note: older versions of nemo_input directly called network layer
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
		m = nemo_eon_decap(ifp, m);
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
nemo_ioctl(ifp, cmd, data)
	struct ifnet *ifp;
#if defined(__FreeBSD__) && __FreeBSD__ < 3
	int cmd;
#else
	u_long cmd;
#endif
	caddr_t data;
{
	struct nemo_softc *sc  = (struct nemo_softc*)ifp;
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
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
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
#endif /*not FreeBSD3*/
		break;

#ifdef	SIOCSIFMTU /* xxx */
	case SIOCGIFMTU:
		break;

	case SIOCSIFMTU:
#ifdef __bsdi__
		mtu = *(short *)ifr->ifr_data;
#else
		mtu = ifr->ifr_mtu;
#endif
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

		error = nemo_set_tunnel(&sc->nemo_if, src, dst);
		break;

#ifdef SIOCDIFPHYADDR
	case SIOCDIFPHYADDR:
		nemo_delete_tunnel(&sc->nemo_if);
		break;
#endif
			
	case SIOCGIFPSRCADDR:
#ifdef INET6
	case SIOCGIFPSRCADDR_IN6:
#endif /* INET6 */
		if (sc->nemo_psrc == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->nemo_psrc;
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
		if (sc->nemo_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->nemo_pdst;
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
		if (sc->nemo_psrc == NULL || sc->nemo_pdst == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}

		/* copy src */
		src = sc->nemo_psrc;
		dst = (struct sockaddr *)
			&(((struct if_laddrreq *)data)->addr);
		size = sizeof(((struct if_laddrreq *)data)->addr);
		if (src->sa_len > size)
			return EINVAL;
		bcopy((caddr_t)src, (caddr_t)dst, src->sa_len);

		/* copy dst */
		src = sc->nemo_pdst;
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
#ifdef MIP6
	case SIOCSIFPHYNEXTHOP: 
#ifdef INET6
	case SIOCSIFPHYNEXTHOP_IN6: {
#endif /* INET6 */
		struct sockaddr *nh = NULL;
		int nhlen = 0;

		switch (ifr->ifr_addr.sa_family) {
#ifdef INET
		case AF_INET:	/* IP supports Multicast */
			error = EAFNOSUPPORT;
			break;
#endif /* INET */
#ifdef INET6
		case AF_INET6:	/* IP6 supports Multicast */
			nh = (struct sockaddr *)
				&(((struct in6_ifreq *)data)->ifr_addr);
			nhlen = sizeof(((struct in6_ifreq *)data)->ifr_addr);
			break;
#endif /* INET6 */
		default:  /* Other protocols doesn't support Multicast */
			error = EAFNOSUPPORT;
			break;
		}

		if (error)
			return error;

		/* if pointer is null, allocate memory */
		if (sc->nemo_nexthop == NULL) {
			sc->nemo_nexthop = (struct sockaddr *)malloc(nhlen, M_IFADDR, M_WAITOK);
			if (sc->nemo_nexthop == NULL)
				return ENOMEM;

			bzero(sc->nemo_nexthop, nhlen);
		}
		/* set request address into nemo_nexthop */
		bcopy(nh, sc->nemo_nexthop, nhlen);
		in6_embedscope(&satosin6(sc->nemo_nexthop)->sin6_addr, satosin6(sc->nemo_nexthop));
		break;
	}
	case SIOCGIFPHYNEXTHOP: 
#ifdef INET6
	case SIOCGIFPHYNEXTHOP_IN6: {
#endif /* INET6 */
		if (sc->nemo_nexthop == NULL) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		src = sc->nemo_nexthop;
		switch (cmd) {
#ifdef INET
		case SIOCGIFPHYNEXTHOP:
			dst = &ifr->ifr_addr;
			size = sizeof(ifr->ifr_addr);
			break;
#endif /* INET */
#ifdef INET6
		case SIOCGIFPHYNEXTHOP_IN6:
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
	}
	case SIOCDIFPHYNEXTHOP: 
		/* if pointer is not null, free the memory */
		if (sc->nemo_nexthop) 
			free(sc->nemo_nexthop, M_IFADDR);
		sc->nemo_nexthop = NULL;
		break;
#endif
	default:
		error = EINVAL;
		break;
	}
 bad:
	return error;
}

int
nemo_set_tunnel(ifp, src, dst)
	struct ifnet *ifp;
	struct sockaddr *src;
	struct sockaddr *dst;
{
	struct nemo_softc *sc = (struct nemo_softc *)ifp;
	struct nemo_softc *sc2;
	struct sockaddr *osrc, *odst, *sa;
	int s;
	int error = 0; 

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	for (sc2 = LIST_FIRST(&nemo_softc_list); sc2 != NULL;
	     sc2 = LIST_NEXT(sc2, nemo_list)) {
		if (sc2 == sc)
			continue;
		if (!sc2->nemo_pdst || !sc2->nemo_psrc)
			continue;
		if (sc2->nemo_pdst->sa_family != dst->sa_family ||
		    sc2->nemo_pdst->sa_len != dst->sa_len ||
		    sc2->nemo_psrc->sa_family != src->sa_family ||
		    sc2->nemo_psrc->sa_len != src->sa_len)
			continue;
#ifndef XBONEHACK
		/* can't configure same pair of address onto two nemos */
		if (bcmp(sc2->nemo_pdst, dst, dst->sa_len) == 0 &&
		    bcmp(sc2->nemo_psrc, src, src->sa_len) == 0) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
#endif

		/* XXX both end must be valid? (I mean, not 0.0.0.0) */
	}

	/* XXX we can detach from both, but be polite just in case */
	if (sc->nemo_psrc)
		switch (sc->nemo_psrc->sa_family) {
#ifdef INET
		case AF_INET:
			(void)in_gif_detach((struct gif_softc *)sc);
			break;
#endif
#ifdef INET6
		case AF_INET6:
			(void)in6_gif_detach((struct gif_softc *)sc);
			break;
#endif
		}

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	sc->nemo_si = softintr_establish(IPL_SOFTNET, nemointr, sc);
	if (sc->nemo_si == NULL) {
		error = ENOMEM;
		goto bad;
	}
#endif

	osrc = sc->nemo_psrc;
	sa = (struct sockaddr *)malloc(src->sa_len, M_IFADDR, M_WAITOK);
	bcopy((caddr_t)src, (caddr_t)sa, src->sa_len);
	sc->nemo_psrc = sa;

	odst = sc->nemo_pdst;
	sa = (struct sockaddr *)malloc(dst->sa_len, M_IFADDR, M_WAITOK);
	bcopy((caddr_t)dst, (caddr_t)sa, dst->sa_len);
	sc->nemo_pdst = sa;

	switch (sc->nemo_psrc->sa_family) {
#ifdef INET
	case AF_INET:
		error = in_gif_attach((struct gif_softc *)sc);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		/* Check validity of the scope zone ID of the addresses. */
		if ((error = scope6_check_id((struct sockaddr_in6 *)sc->nemo_psrc,
					     0)) != 0 ||
		    (error = scope6_check_id((struct sockaddr_in6 *)sc->nemo_pdst,
					     0)) != 0) {
			break;
		}
		error = in6_gif_attach((struct gif_softc *)sc);
		break;
#endif
	}
	if (error) {
		/* rollback */
		free((caddr_t)sc->nemo_psrc, M_IFADDR);
		free((caddr_t)sc->nemo_pdst, M_IFADDR);
		sc->nemo_psrc = osrc;
		sc->nemo_pdst = odst;
		goto bad;
	}

	if (osrc)
		free((caddr_t)osrc, M_IFADDR);
	if (odst)
		free((caddr_t)odst, M_IFADDR);

	if (sc->nemo_psrc && sc->nemo_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);

	return 0;

 bad:
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->nemo_si) {
		softintr_disestablish(sc->nemo_si);
		sc->nemo_si = NULL;
	}
#endif
	if (sc->nemo_psrc && sc->nemo_pdst)
		ifp->if_flags |= IFF_RUNNING;
	else
		ifp->if_flags &= ~IFF_RUNNING;
	splx(s);

	return error;
}

void
nemo_delete_tunnel(ifp)
	struct ifnet *ifp;
{
	struct nemo_softc *sc = (struct nemo_softc *)ifp;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	if (sc->nemo_si) {
		softintr_disestablish(sc->nemo_si);
		sc->nemo_si = NULL;
	}
#endif
	if (sc->nemo_psrc) {
		free((caddr_t)sc->nemo_psrc, M_IFADDR);
		sc->nemo_psrc = NULL;
	}
	if (sc->nemo_pdst) {
		free((caddr_t)sc->nemo_pdst, M_IFADDR);
		sc->nemo_pdst = NULL;
	}
#ifdef MIP6
	if (sc->nemo_nexthop) {
		free((caddr_t)sc->nemo_nexthop, M_IFADDR);
		sc->nemo_nexthop = NULL;
	}
#endif /* MIP6 */

	/* it is safe to detach from both */
#ifdef INET
	(void)in_gif_detach((struct gif_softc *)sc);
#endif
#ifdef INET6
	(void)in6_gif_detach((struct gif_softc *)sc);
#endif

	if (sc->nemo_psrc && sc->nemo_pdst)
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
nemo_eon_encap(struct mbuf *m)
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
nemo_eon_decap(struct ifnet *ifp, struct mbuf *m)
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
#endif /*NNEMO > 0*/
