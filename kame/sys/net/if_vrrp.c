/*      $KAME: if_vrrp.c,v 1.6 2003/02/19 17:04:46 suz Exp $ */

/*
 * Copyright (C) 2002 WIDE Project.
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

#if defined(__FreeBSD__)
#include "opt_inet.h"
#include "opt_inet6.h"
#else
#ifdef __NetBSD__
#include "opt_inet.h"
#include "bpfilter.h"
#endif
#endif

#if defined(__FreeBSD__) && __FreeBSD__ >= 4
#ifndef NVRRP
#include "vrrp.h"
#endif
#else
#include "vrrp.h"
#endif

#include <sys/param.h>
#include <sys/kernel.h>
#if defined(__FreeBSD__)
#include <sys/malloc.h>
#endif
#include <sys/mbuf.h>
#if defined(__FreeBSD__)
#include <sys/module.h>
#endif
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#if defined(__FreeBSD__)
#include <machine/bus.h>	/* XXX: Shouldn't really be required! */
#include <sys/rman.h>
#else    <sys/proc.h>
#endif

#if NBPFILTER > 0 || defined(__FreeBSD__)
#include <net/bpf.h>
#endif
#if defined(__FreeBSD__)
#include <net/ethernet.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#ifdef INET
#include <netinet/in.h>
#if defined(__NetBSD__)
#include <net/if_ether.h>
#include <netinet/if_inarp.h>
#else
#include <netinet/if_ether.h>
#endif
#endif

#include <net/if_vrrp_var.h>

#ifdef __FreeBSD__
void vrrpattach(void *);
static MALLOC_DEFINE(M_VRRP, "vrrp", "VRRP Interface");
#else
void vrrpattach(int);
#endif
void vrrpattach0(struct ifvrrp *);

LIST_HEAD(, ifvrrp) ifv_list;

#ifdef __FreeBSD__
#define IFP2MAC(IFP) (((struct arpcom *)IFP)->ac_enaddr)
#else
#define IFP2MAC(IFP) (LLADDR((IFP)->if_sadl))
#endif

static	void vrrp_start(struct ifnet *ifp);
static	int vrrp_ioctl(struct ifnet *ifp, u_long cmd, caddr_t addr);
#ifdef __FreeBSD__
static	int vrrp_setmulti(struct ifnet *ifp);
#endif
static	int vrrp_unconfig(struct ifnet *ifp);
static	int vrrp_config(struct ifvrrp *ifv, struct ifnet *p);

int nvrrp_active = 0;

#if defined(__FreeBSD__)
/*
 * Program our multicast filter. What we're actually doing is
 * programming the multicast filter of the parent. This has the
 * side effect of causing the parent interface to receive multicast
 * traffic that it doesn't really want, which ends up being discarded
 * later by the upper protocol layers. Unfortunately, there's no way
 * to avoid this: there really is only one physical interface.
 */
static int
vrrp_setmulti(struct ifnet *ifp)
{
	struct ifnet		*ifp_p;
	struct ifmultiaddr	*ifma, *rifma = NULL;
	struct ifvrrp		*sc;
	struct vrrp_mc_entry	*mc = NULL;
	struct sockaddr_dl	sdl;
	int			error;

	/* Find the parent. */
	sc = ifp->if_softc;
	ifp_p = sc->ifv_p;

	/*
	 * If we don't have a parent, just remember the membership for
	 * when we do.
	 */
	if (ifp_p == NULL)
		return (0);

	bzero((char *)&sdl, sizeof sdl);
	sdl.sdl_len = sizeof sdl;
	sdl.sdl_family = AF_LINK;
	sdl.sdl_index = ifp_p->if_index;
	sdl.sdl_type = IFT_ETHER;
	sdl.sdl_alen = ETHER_ADDR_LEN;

	/* First, remove any existing filter entries. */
	while(SLIST_FIRST(&sc->vrrp_mc_listhead) != NULL) {
		mc = SLIST_FIRST(&sc->vrrp_mc_listhead);
		bcopy((char *)&mc->mc_addr, LLADDR(&sdl), ETHER_ADDR_LEN);
		error = if_delmulti(ifp_p, (struct sockaddr *)&sdl);
		if (error)
			return (error);
		SLIST_REMOVE_HEAD(&sc->vrrp_mc_listhead, mc_entries);
		free(mc, M_VRRP);
	}

	/* Now program new ones. */
	LIST_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		mc = malloc(sizeof(struct vrrp_mc_entry), M_VRRP, M_WAITOK);
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    (char *)&mc->mc_addr, ETHER_ADDR_LEN);
		SLIST_INSERT_HEAD(&sc->vrrp_mc_listhead, mc, mc_entries);
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    LLADDR(&sdl), ETHER_ADDR_LEN);
		error = if_addmulti(ifp_p, (struct sockaddr *)&sdl, &rifma);
		if (error)
			return (error);
	}

	return (0);
}

#else /* NetBSD */
static int
vrrp_ether_addmulti(struct ifvrrp *ifv, struct ifreq *ifr)
{
	struct vrrp_mc_entry *mc;
	u_int8_t addrlo[ETHER_ADDR_LEN], addrhi[ETHER_ADDR_LEN];
	int error;

	if (ifr->ifr_addr.sa_len > sizeof(struct sockaddr_storage))
		return (EINVAL);

	error = ether_addmulti(ifr, &ifv->ifv_ec);
	if (error != ENETRESET)
		return (error);

	/*
	 * This is new multicast address.  We have to tell parent
	 * about it.  Also, remember this multicast address so that
	 * we can delete them on unconfigure.
	 */
	MALLOC(mc, struct vrrp_mc_entry *, sizeof(struct vrrp_mc_entry),
	    M_DEVBUF, M_NOWAIT);
	if (mc == NULL) {
		error = ENOMEM;
		goto alloc_failed;
	}

	/*
	 * As ether_addmulti() returns ENETRESET, following two
	 * statement shouldn't fail.
	 */
	(void)ether_multiaddr(&ifr->ifr_addr, addrlo, addrhi);
	ETHER_LOOKUP_MULTI(addrlo, addrhi, &ifv->ifv_ec, mc->mc_enm);
	memcpy(&mc->mc_addr, &ifr->ifr_addr, ifr->ifr_addr.sa_len);
	LIST_INSERT_HEAD(&ifv->vrrp_mc_listhead, mc, mc_entries);

	error = (*ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCADDMULTI,
	    (caddr_t)ifr);
	if (error != 0)
		goto ioctl_failed;
	return (error);

 ioctl_failed:
	LIST_REMOVE(mc, mc_entries);
	FREE(mc, M_DEVBUF);
 alloc_failed:
	(void)ether_delmulti(ifr, &ifv->ifv_ec);
	return (error);
}

static int
vrrp_ether_delmulti(struct ifvrrp *ifv, struct ifreq *ifr)
{
	struct ether_multi *enm;
	struct vrrp_mc_entry *mc;
	u_int8_t addrlo[ETHER_ADDR_LEN], addrhi[ETHER_ADDR_LEN];
	int error;

	/*
	 * Find a key to lookup vrrp_mc_entry.  We have to do this
	 * before calling ether_delmulti for obvious reason.
	 */
	if ((error = ether_multiaddr(&ifr->ifr_addr, addrlo, addrhi)) != 0)
		return (error);
	ETHER_LOOKUP_MULTI(addrlo, addrhi, &ifv->ifv_ec, enm);

	error = ether_delmulti(ifr, &ifv->ifv_ec);
	if (error != ENETRESET)
		return (error);

	/* We no longer use this multicast address.  Tell parent so. */
	error = (*ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCDELMULTI,
	    (caddr_t)ifr);
	if (error == 0) {
		/* And forget about this address. */
		for (mc = LIST_FIRST(&ifv->vrrp_mc_listhead); mc != NULL;
		    mc = LIST_NEXT(mc, mc_entries)) {
			if (mc->mc_enm == enm) {
				LIST_REMOVE(mc, mc_entries);
				FREE(mc, M_DEVBUF);
				break;
			}
		}
		KASSERT(mc != NULL);
	} else
		(void)ether_addmulti(ifr, &ifv->ifv_ec);
	return (error);
}
#endif

/*
 * Delete any multicast address we have asked to add form parent
 * interface.  Called when the vrrp is being unconfigured.
 */
static int
vrrp_ether_purgemulti(struct ifvrrp *ifv)
{
	struct ifnet *ifp = ifv->ifv_p;		/* Parent. */
	struct vrrp_mc_entry *mc;
#if defined(__FreeBSD__)
	struct sockaddr_dl sdl;
	int error;
	/*
	 * Since the interface is being unconfigured, we need to
	 * empty the list of multicast groups that we may have joined
	 * while we were alive from the parent's list.
	 */
	bzero((char *)&sdl, sizeof sdl);
	sdl.sdl_len = sizeof sdl;
	sdl.sdl_family = AF_LINK;
	sdl.sdl_index = ifp->if_index;
	sdl.sdl_type = IFT_ETHER;
	sdl.sdl_alen = ETHER_ADDR_LEN;
	
	while(SLIST_FIRST(&ifv->vrrp_mc_listhead) != NULL) {
	    mc = SLIST_FIRST(&ifv->vrrp_mc_listhead);
	    bcopy((char *)&mc->mc_addr, LLADDR(&sdl), ETHER_ADDR_LEN);
	    error = if_delmulti(ifp, (struct sockaddr *)&sdl);
	    if (error)
		return (error);
	    SLIST_REMOVE_HEAD(&ifv->vrrp_mc_listhead, mc_entries);
	    free(mc, M_VRRP);
	}
#else
	union {
		struct ifreq ifreq;
		struct {
			char ifr_name[IFNAMSIZ];
			struct sockaddr_storage ifr_ss;
		} ifreq_storage;
	} ifreq;
	struct ifreq *ifr = &ifreq.ifreq;

	memcpy(ifr->ifr_name, ifp->if_xname, IFNAMSIZ);
	while ((mc = LIST_FIRST(&ifv->vrrp_mc_listhead)) != NULL) {
		memcpy(&ifr->ifr_addr, &mc->mc_addr, mc->mc_addr.ss_len);
		(void)(*ifp->if_ioctl)(ifp, SIOCDELMULTI, (caddr_t)ifr);
		LIST_REMOVE(mc, mc_entries);
		FREE(mc, M_DEVBUF);
	}
#endif
	return 0;
}

#ifdef __FreeBSD__
PSEUDO_SET(vrrpattach, if_vrrp);
#endif

void
vrrpattach(dummy)
#ifdef __FreeBSD__
	void *dummy;
#else
	int dummy;
#endif
{
	struct ifvrrp *ifv;
	struct ifnet *ifp;
	int i, nvrrp;
    
	LIST_INIT(&ifv_list);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	nvrrp = dummy;
#else
	nvrrp = NVRRP;
#endif
	nvrrp_active = 0;

#ifdef VRRP_DEBUG
	printf("vrrpattach nvrrp=%d\n", nvrrp);
#endif

	ifv = malloc(nvrrp * sizeof(struct ifvrrp),
	    M_DEVBUF, M_WAIT);
	bzero(ifv, nvrrp * sizeof(struct ifvrrp));
	for (i = 0; i < nvrrp; ifv++, i++) {
		ifp = &ifv->ifv_if;
#if defined(__NetBSD__)
		sprintf(ifp->if_xname, "vrrp%d", i);
#else
		ifp->if_name = "vrrp";
		ifp->if_unit = i;
#endif
		vrrpattach0(ifv);
		LIST_INSERT_HEAD(&ifv_list, ifv, ifv_list);
	}
}

void
vrrpattach0(ifv)
	struct ifvrrp *ifv;
{
	struct ifnet *ifp;
#ifdef __NetBSD__
	u_int8_t mac_dummy[ETHER_ADDR_LEN];
#endif

#ifdef __FreeBSD__
	SLIST_INIT(&ifv->vrrp_mc_listhead);
#else
	LIST_INIT(&ifv->vrrp_mc_listhead);
#endif

	ifp = &ifv->ifv_if;
	ifp->if_softc = ifv;

#ifdef __FreeBSD__
	ether_ifattach(ifp, ETHER_BPF_SUPPORTED);
	ifp->if_output = ether_output;
#endif

#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
#endif
	IFQ_SET_READY(&ifp->if_snd);
#ifdef __NetBSD__
	if_attach(ifp);
	bzero(mac_dummy, ETHER_ADDR_LEN);
	ether_ifattach(ifp, &mac_dummy[0]);
#endif

	/* NB: mtu is not set here */
	ifp->if_ioctl = vrrp_ioctl;
	ifp->if_start = vrrp_start;
	ifp->if_type = IFT_VRRP;

	ifp->if_flags |= (IFF_UP |IFF_MULTICAST);
}

static void
vrrp_start(struct ifnet *ifp)
{
	struct ifvrrp *ifv;
	struct ifnet *p;
	struct mbuf *m;
	int error, len;
	short mflags;
	ALTQ_DECL(struct altq_pktattr pktattr;)

	ifv = ifp->if_softc;
	p = ifv->ifv_p;

	ifp->if_flags |= IFF_OACTIVE;
	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == 0)
			break;
		if (ifp->if_bpf)
#ifdef __FreeBSD__
			bpf_mtap(ifp, m);
#else
#if NBPFILTER > 0
			bpf_mtap(ifp->if_bpf, m);
#endif
#endif
		/*
		 * Do not run parent's if_start() if the parent is not up,
		 * or parent's driver will cause a system crash.
		 */
		if ((p->if_flags & (IFF_UP | IFF_RUNNING)) !=
					(IFF_UP | IFF_RUNNING)) {
			m_freem(m);
			ifp->if_data.ifi_collisions++;
			continue;
		}

#ifdef ALTQ
		/*
		 * If ALTQ is enabled on the parent interface, do
		 * classification; the queueing discipline might
		 * not require classification, but might require
		 * the address family/header pointer in the pktattr.
		 */
		if (ALTQ_IS_ENABLED(&p->if_snd))
			altq_etherclassify(&p->if_snd, m, &pktattr);
#endif
		/*
		 * Send it, precisely as ether_output() would have.
		 * We are already running at splimp.
		 */
		mflags = m->m_flags;
		len = m->m_pkthdr.len;
		IFQ_ENQUEUE(&p->if_snd, m, NULL, error);
		if (error) {
			/* mbuf is already freed */
			ifp->if_oerrors++;
			continue;
		}
		ifp->if_opackets++;
		p->if_obytes += len;
		if (mflags & M_MCAST)
			p->if_omcasts++;
		if ((p->if_flags & IFF_OACTIVE) == 0)
			p->if_start(p);
	}
	ifp->if_flags &= ~IFF_OACTIVE;

	return;
}

int
vrrp_input(struct ether_header *eh, struct mbuf *m)
{
	struct ifvrrp *ifv;
	struct mbuf *mcp;
	struct ether_header ehcp;

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	     ifv = LIST_NEXT(ifv, ifv_list)) {
		struct ifnet *ifp = ifv->ifv_p;
		struct m_tag *mtag;
		if (m->m_pkthdr.rcvif == ifp &&
		    ((eh->ether_dhost[0] & 1) != 0 ||
		    bcmp((caddr_t) eh->ether_dhost, IFP2MAC(&ifv->ifv_if), ETHER_ADDR_LEN) == 0)) {
			mcp = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
#ifdef VRRP_DEBUG
			printf("vrrp_input matched(%s,%x:%x:%x:%x:%x:%x ",
			    ifv->ifv_if.if_xname,
			    (LLADDR(ifv->ifv_if.if_sadl))[0], 
			    (LLADDR(ifv->ifv_if.if_sadl))[1], 
			    (LLADDR(ifv->ifv_if.if_sadl))[2], 
			    (LLADDR(ifv->ifv_if.if_sadl))[3], 
			    (LLADDR(ifv->ifv_if.if_sadl))[4], 
			    (LLADDR(ifv->ifv_if.if_sadl))[5]);
			printf("dhost=%x:%x:%x:%x:%x:%x)\n",
			    eh->ether_dhost[0], 
			    eh->ether_dhost[1],
			    eh->ether_dhost[2], 
			    eh->ether_dhost[3],
			    eh->ether_dhost[4], 
			    eh->ether_dhost[5]);
#endif
			if (mcp == NULL)
				return (-1);
			mcp->m_pkthdr.rcvif = &ifv->ifv_if;
			ifv->ifv_if.if_ipackets++;
			ehcp = *eh;
			mtag = m_tag_get(PACKET_TAG_VRRP, sizeof(u_int), M_NOWAIT);
			if (mtag == NULL) {
				ifp->if_oerrors++;
				continue;
			}
			bcopy(&ifp, (caddr_t)(mtag + 1), sizeof(struct ifnet *));
			m_tag_prepend(mcp, mtag);
#if defined(__NetBSD__)
			(*ifp->if_input)(&ifv->ifv_if, mcp);
#else /* FreeBSD */
			ether_input(&ifv->ifv_if, &ehcp, mcp);
#endif
		}
	}
	return 0;
}

static int
vrrp_config(struct ifvrrp *ifv, struct ifnet *p)
{

	if (p->if_data.ifi_type != IFT_ETHER)
		return EPROTONOSUPPORT;
	if (ifv->ifv_p)
		return EBUSY;
	ifv->ifv_p = p;
	ifv->ifv_if.if_mtu = p->if_mtu;

	/*
	 * Copy only a selected subset of flags from the parent.
	 * Other flags are none of our business.
	 */
	ifv->ifv_if.if_flags = (p->if_flags &
	    (IFF_UP | IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX | IFF_POINTOPOINT));

	/*
	 * Configure multicast addresses that may already be
	 * joined on the vrrp device.
	 */
#if defined(__FreeBSD__)
	(void)vrrp_setmulti(&ifv->ifv_if);
#endif

	/*
	 * increment active vrrp interface 
	 */
	nvrrp_active++;

	/*
	 * XXX
	 */
	return ifpromisc(p, 1);

}

static int
vrrp_unconfig(struct ifnet *ifp)
{
	struct ifvrrp *ifv;
	struct ifnet *p;
	int error;

	ifv = ifp->if_softc;
	p = ifv->ifv_p;

	if (p) {
		
		/*
		 * XXX
		 */
		error = ifpromisc(p, 0);
		/*
		 * ignore error;
		 */
		error = vrrp_ether_purgemulti(ifv);
		/*
		 * ignore error;
		 */

		/*
		 * decrement active vrrp interface 
		 */
		nvrrp_active--;
	}

	/* Disconnect from parent. */
	ifv->ifv_p = NULL;
	ifv->ifv_if.if_mtu = ETHERMTU;

	return 0;
}

static int
vrrp_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifnet *p;
	struct ifreq *ifr;
	struct ifvrrp *ifv;
	struct vrrpreq vrrpreq;
	static char dummy_mac[ETHER_ADDR_LEN];
	u_int ifindex;
	int error = 0;

	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;
	ifv = ifp->if_softc;

#ifdef VRRP_DEBUG
	printf("vrrp_ioctl %x\n", (int) cmd);
#endif

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			arp_ifinit(ifp, ifa);
			break;
#endif
		default:
			break;
		}
		break;

	case SIOCGIFADDR:
		{
			struct sockaddr *sa;

			sa = (struct sockaddr *) &ifr->ifr_data;
			bcopy(IFP2MAC(ifp),
			      (caddr_t) sa->sa_data, ETHER_ADDR_LEN);
		}
		break;

	case SIOCSIFMTU:
		/*
		 * Set the interface MTU.
		 * This is bogus. The underlying interface might support
	 	 * jumbo frames.
		 */
		if (ifr->ifr_mtu > ETHERMTU) {
			error = EINVAL;
		} else {
			ifp->if_mtu = ifr->ifr_mtu;
		}
		break;

	case SIOCSETVRRP:
		error = copyin(ifr->ifr_data, &vrrpreq, sizeof vrrpreq);
		if (error)
			break;
		if ((ifindex = vrrpreq.vr_parent_index) == 0) {
			vrrp_unconfig(ifp);
			if (ifp->if_flags & IFF_UP) {
#ifdef __NetBSD__
				int s = splnet();
#else
				int s = splimp();
#endif
				if_down(ifp);
				splx(s);
			}		
/*			ifp->if_flags &= ~IFF_RUNNING;*/
/*			ifp->if_flags = 0;*/
			ifp->if_flags = IFF_MULTICAST;
			bzero(dummy_mac, ETHER_ADDR_LEN);
#ifdef __FreeBSD__
			if ((error = if_setlladdr(ifp, dummy_mac, ETHER_ADDR_LEN)) != 0) {
				break;
			}
#else
			bcopy(dummy_mac, IFP2MAC(ifp), ifp->if_addrlen);
#endif
			break;
		}
                if (if_index < ifindex) {
                        error = ENOENT;
                        break;
                }
		
#if defined(__FreeBSD__) && __FreeBSD__ >= 5
                p = ifnet_byindex(ifindex);
#else
                p = ifindex2ifnet[ifindex];
#endif
                if (p == NULL) {
                        error = EADDRNOTAVAIL;
                        break;
                }

		if (vrrpreq.vr_lladdr.sa_len != ETHER_ADDR_LEN) {
			error = EINVAL;
			break;
		}

#ifdef __FreeBSD__
		if ((error = if_setlladdr(ifp, vrrpreq.vr_lladdr.sa_data, ETHER_ADDR_LEN)) != 0) {
			break;
		}
#else
		bcopy(vrrpreq.vr_lladdr.sa_data, IFP2MAC(ifp), ifp->if_addrlen);
#endif
#ifdef VRRP_DEBUG
		printf("lladdr=%x:%x:%x:%x:%x:%x",
		    (LLADDR(ifp->if_sadl))[0], 
		    (LLADDR(ifp->if_sadl))[1], 
		    (LLADDR(ifp->if_sadl))[2], 
		    (LLADDR(ifp->if_sadl))[3], 
		    (LLADDR(ifp->if_sadl))[4], 
		    (LLADDR(ifp->if_sadl))[5]);
#endif
		error = vrrp_config(ifv, p);
		if (error)
			break;
		ifp->if_flags |= IFF_RUNNING;
		{
#ifdef __NetBSD__
			int s = splnet();
#else
			int s = splimp();
#endif
			if_up(ifp);
			splx(s);
		}
		break;
		
	case SIOCGETVRRP:
		ifindex = 0;
		
		if (ifv->ifv_p) {
			ifindex = ifv->ifv_p->if_index;
		}
		error = copyout(&ifindex, ifr->ifr_data, sizeof ifindex);
		break;

	case SIOCSIFFLAGS:
		/*
		 * We don't support promiscuous mode
		 * right now because it would require help from the
		 * underlying drivers, which hasn't been implemented.
		 */
		break;
#if defined(__FreeBSD__)
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = vrrp_setmulti(ifp);
		break;
#else
	case SIOCADDMULTI:
		error = (ifv->ifv_p != NULL) ?
		  vrrp_ether_addmulti(ifv, ifr) : EINVAL;
		break;

	case SIOCDELMULTI:
		error = (ifv->ifv_p != NULL) ?
		  vrrp_ether_delmulti(ifv, ifr) : EINVAL;
		break;

#endif
	default:
		error = EINVAL;
	}
	return error;
}

