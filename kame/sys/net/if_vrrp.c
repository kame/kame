/*      $KAME: if_vrrp.c,v 1.2 2002/07/10 07:21:01 ono Exp $ */

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

#ifndef NVRRP
#include "vrrp.h"
#endif
#include "opt_inet.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <machine/bus.h>	/* XXX: Shouldn't really be required! */
#include <sys/rman.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_vrrp_var.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#define VRRPNAME	"vrrp"
#define VRRP_MAXUNIT	0x7fff	/* ifp->if_unit is only 15 bits */

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_VRRP, vrrp, CTLFLAG_RW, 0, "VRRP");
SYSCTL_NODE(_net_link_vrrp, PF_LINK, link, CTLFLAG_RW, 0, "for consistency");

static MALLOC_DEFINE(M_VRRP, "vrrp", "VRRP Interface");
static struct rman vrrpunits[1];
static LIST_HEAD(, ifvrrp) ifv_list;

static	int vrrp_clone_create(struct if_clone *, int *);
static	void vrrp_clone_destroy(struct ifnet *);
static	void vrrp_start(struct ifnet *ifp);
static	void vrrp_ifinit(void *foo);
static	int vrrp_input(struct ether_header *eh, struct mbuf *m);
static	int vrrp_ioctl(struct ifnet *ifp, u_long cmd, caddr_t addr);
static	int vrrp_setmulti(struct ifnet *ifp);
static	int vrrp_unconfig(struct ifnet *ifp);
static	int vrrp_config(struct ifvrrp *ifv, struct ifnet *p);

struct if_clone vrrp_cloner =
    IF_CLONE_INITIALIZER("vrrp", vrrp_clone_create, vrrp_clone_destroy);

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
		return(0);

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
			return(error);
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
			return(error);
	}

	return(0);
}

static int
vrrp_modevent(module_t mod, int type, void *data) 
{ 
	int i;
	int err;

	switch (type) { 
	case MOD_LOAD: 
		vrrpunits->rm_type = RMAN_ARRAY;
		vrrpunits->rm_descr = "configurable if_vrrp units";
		err = rman_init(vrrpunits);
		if (err != 0)
			return (err);
		err = rman_manage_region(vrrpunits, 0, VRRP_MAXUNIT);
		if (err != 0) {
			printf("%s: vrrpunits: rman_manage_region: Failed %d\n",
			    VRRPNAME, err);
			rman_fini(vrrpunits);
			return (err);
		}
		LIST_INIT(&ifv_list);
		vrrp_input_p = vrrp_input;
		if_clone_attach(&vrrp_cloner);
		for(i = 0; i < NVRRP; i ++) {
			err = vrrp_clone_create(&vrrp_cloner, &i);
			KASSERT(err == 0,
			    ("Unexpected error creating initial VRRPs"));
		}
		break; 
	case MOD_UNLOAD: 
		if_clone_detach(&vrrp_cloner);
		vrrp_input_p = NULL;
		while (!LIST_EMPTY(&ifv_list))
			vrrp_clone_destroy(&LIST_FIRST(&ifv_list)->ifv_if);
		err = rman_fini(vrrpunits);
		if (err != 0)
			 return (err);
		break;
	} 
	return 0; 
} 

static moduledata_t vrrp_mod = { 
	"if_vrrp", 
	vrrp_modevent, 
	0
}; 

DECLARE_MODULE(if_vrrp, vrrp_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);

static int
vrrp_clone_create(struct if_clone *ifc, int *unit)
{
	struct resource *r;
	struct ifvrrp *ifv;
	struct ifnet *ifp;
	int s;

	if (*unit > VRRP_MAXUNIT)
		return (ENXIO);

	if (*unit < 0) {
		r  = rman_reserve_resource(vrrpunits, 0, VRRP_MAXUNIT, 1,
		    RF_ALLOCATED | RF_ACTIVE, NULL);
		if (r == NULL)
			return (ENOSPC);
		*unit = rman_get_start(r);
	} else {
		r  = rman_reserve_resource(vrrpunits, *unit, *unit, 1,
		    RF_ALLOCATED | RF_ACTIVE, NULL);
		if (r == NULL)
			return (EEXIST);
	}

	ifv = malloc(sizeof(struct ifvrrp), M_VRRP, M_WAITOK);
	memset(ifv, 0, sizeof(struct ifvrrp));
	ifp = &ifv->ifv_if;
	SLIST_INIT(&ifv->vrrp_mc_listhead);

	s = splnet();
	LIST_INSERT_HEAD(&ifv_list, ifv, ifv_list);
	splx(s);

	ifp->if_softc = ifv;
	ifp->if_name = "vrrp";
	ifp->if_unit = *unit;
	ifv->r_unit = r;
	/* NB: flags are not set here */
#if 0
	ifp->if_linkmib = &ifv->ifv_mib;
	ifp->if_linkmiblen = sizeof ifv->ifv_mib;
#endif
	/* NB: mtu is not set here */

	ifp->if_init = vrrp_ifinit;
	ifp->if_start = vrrp_start;
	ifp->if_ioctl = vrrp_ioctl;
	ifp->if_output = ether_output;
	IFQ_SET_MAXLEN(&ifp->if_snd, ifqmaxlen);
	IFQ_SET_READY(&ifp->if_snd);
	ether_ifattach(ifp, ETHER_BPF_SUPPORTED);
	/* Now undo some of the damage... */
	ifp->if_data.ifi_type = IFT_VRRP;

	ifp->if_flags |= (IFF_UP |IFF_MULTICAST);

	return (0);
}

static void
vrrp_clone_destroy(struct ifnet *ifp)
{
	struct ifvrrp *ifv = ifp->if_softc;
	int s;
	int err;

	s = splnet();
	LIST_REMOVE(ifv, ifv_list);
	vrrp_unconfig(ifp);
	splx(s);

	ether_ifdetach(ifp, ETHER_BPF_SUPPORTED);

	err = rman_release_resource(ifv->r_unit);
	KASSERT(err == 0, ("Unexpected error freeing resource"));
	free(ifv, M_VRRP);
}

static void
vrrp_ifinit(void *foo)
{
	return;
}

static void
vrrp_start(struct ifnet *ifp)
{
	struct ifvrrp *ifv;
	struct ifnet *p;
#if 0
	struct ether_header *eh;
#endif
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
			bpf_mtap(ifp, m);

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

static int
vrrp_input(struct ether_header *eh, struct mbuf *m)
{
#define IFP2AC(IFP) ((struct arpcom *)IFP)
	struct ifvrrp *ifv;
	struct mbuf *mcp;

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	    ifv = LIST_NEXT(ifv, ifv_list)) {
		if (m->m_pkthdr.rcvif == ifv->ifv_p
		    && ((eh->ether_dhost[0] & 1) != 0
		    || bcmp((caddr_t) eh->ether_dhost, IFP2AC(ifv)->ac_enaddr, ETHER_ADDR_LEN) == 0)) {
			mcp = m_copym(m, 0, M_COPYALL, M_DONTWAIT);
			if (mcp == NULL)
				return -1;
			mcp->m_pkthdr.rcvif = &ifv->ifv_if;
			ifv->ifv_if.if_ipackets++;
			ether_demux(&ifv->ifv_if, eh, mcp);
		}
	}
	return 0;
}

static int
vrrp_config(struct ifvrrp *ifv, struct ifnet *p)
{
#if 0
	struct ifaddr *ifa1, *ifa2;
	struct sockaddr_dl *sdl1, *sdl2;
#endif

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
	 * Set up our ``Ethernet address'' to reflect the underlying
	 * physical interface's.
	 */
#if 0
	ifa1 = ifnet_addrs[ifv->ifv_if.if_index - 1];
	ifa2 = ifnet_addrs[p->if_index - 1];
	sdl1 = (struct sockaddr_dl *)ifa1->ifa_addr;
	sdl2 = (struct sockaddr_dl *)ifa2->ifa_addr;
	sdl1->sdl_type = IFT_ETHER;
	sdl1->sdl_alen = ETHER_ADDR_LEN;
	bcopy(LLADDR(sdl2), LLADDR(sdl1), ETHER_ADDR_LEN);
	bcopy(LLADDR(sdl2), ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);
#endif
#if 0
	ifa1 = ifnet_addrs[ifv->ifv_if.if_index - 1];
	sdl1 = (struct sockaddr_dl *)ifa1->ifa_addr;
	sdl1->sdl_type = IFT_ETHER;
	sdl1->sdl_alen = ETHER_ADDR_LEN;
	bzero(LLADDR(sdl1), ETHER_ADDR_LEN);
	bzero(ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);
#endif
	/*
	 * Configure multicast addresses that may already be
	 * joined on the vrrp device.
	 */
	(void)vrrp_setmulti(&ifv->ifv_if);

	/*
	 * XXX
	 */
	return ifpromisc(p, 1);

}

static int
vrrp_unconfig(struct ifnet *ifp)
{
#if 0
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
#endif
	struct vrrp_mc_entry *mc;
	struct ifvrrp *ifv;
	struct ifnet *p;
	int error;

	ifv = ifp->if_softc;
	p = ifv->ifv_p;

	if (p) {
		struct sockaddr_dl sdl;

		/*
		 * XXX
		 */
		error = ifpromisc(p, 0);
		if (error)
			return error;

		/*
		 * Since the interface is being unconfigured, we need to
		 * empty the list of multicast groups that we may have joined
		 * while we were alive from the parent's list.
		 */
		bzero((char *)&sdl, sizeof sdl);
		sdl.sdl_len = sizeof sdl;
		sdl.sdl_family = AF_LINK;
		sdl.sdl_index = p->if_index;
		sdl.sdl_type = IFT_ETHER;
		sdl.sdl_alen = ETHER_ADDR_LEN;

		while(SLIST_FIRST(&ifv->vrrp_mc_listhead) != NULL) {
			mc = SLIST_FIRST(&ifv->vrrp_mc_listhead);
			bcopy((char *)&mc->mc_addr, LLADDR(&sdl), ETHER_ADDR_LEN);
			error = if_delmulti(p, (struct sockaddr *)&sdl);
			if (error)
				return(error);
			SLIST_REMOVE_HEAD(&ifv->vrrp_mc_listhead, mc_entries);
			free(mc, M_VRRP);
		}
	}

	/* Disconnect from parent. */
	ifv->ifv_p = NULL;
	ifv->ifv_if.if_mtu = ETHERMTU;

#if 0
	/* Clear our MAC address. */
	ifa = ifnet_addrs[ifv->ifv_if.if_index - 1];
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_ETHER;
	sdl->sdl_alen = ETHER_ADDR_LEN;
	bzero(LLADDR(sdl), ETHER_ADDR_LEN);
	bzero(ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);
#endif

	return 0;
}

static int
vrrp_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifnet *p;
	struct ifreq *ifr;
	struct ifvrrp *ifv;
	int ifindex;
	int error = 0;

	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;
	ifv = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			arp_ifinit(&ifv->ifv_ac, ifa);
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
			bcopy(((struct arpcom *)ifp->if_softc)->ac_enaddr,
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

	case SIOCSIFLLADDR:
		return if_setlladdr(ifp,
				    ifr->ifr_addr.sa_data, ifr->ifr_addr.sa_len);

	case SIOCSETVRRP:
		error = copyin(ifr->ifr_data, &ifindex, sizeof ifindex);
		if (error)
			break;
		if (ifindex  == 0) {
			vrrp_unconfig(ifp);
			if (ifp->if_flags & IFF_UP) {
				int s = splimp();
				if_down(ifp);
				splx(s);
			}		
/*			ifp->if_flags &= ~IFF_RUNNING;*/
/*			ifp->if_flags = 0;*/
			ifp->if_flags = IFF_MULTICAST;
			break;
		}
                if (ifindex < 0 || if_index < ifindex) {
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
		error = vrrp_config(ifv, p);
		if (error)
			break;
		ifp->if_flags |= IFF_RUNNING;
		{
			int s = splimp();
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
#if 0
		if (ifr->ifr_flags & (IFF_PROMISC)) {
			ifp->if_flags &= ~(IFF_PROMISC);
			error = EINVAL;
		}
#endif
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = vrrp_setmulti(ifp);
		break;
	default:
		error = EINVAL;
	}
	return error;
}
