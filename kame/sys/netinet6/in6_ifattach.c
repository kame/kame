/*	$KAME: in6_ifattach.c,v 1.44 2000/04/11 05:56:33 itojun Exp $	*/

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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#ifdef __bsdi__
#include <crypto/md5.h>
#elif defined(__OpenBSD__)
#include <sys/md5k.h>
#else
#include <sys/md5.h>
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#ifndef __NetBSD__
#include <netinet/if_ether.h>
#endif

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>

#include <net/net_osdep.h>

static	struct in6_addr llsol;

struct in6_ifstat **in6_ifstat = NULL;
struct icmp6_ifstat **icmp6_ifstat = NULL;
size_t in6_ifstatmax = 0;
size_t icmp6_ifstatmax = 0;
unsigned long in6_maxmtu = 0;

static int get_rand_ifid __P((struct ifnet *, struct in6_addr *));
static int get_hw_ifid __P((struct ifnet *, struct in6_addr *));
static int get_ifid __P((struct ifnet *, struct in6_addr *));

#define EUI64_GBIT	0x01
#define EUI64_UBIT	0x02
#define EUI64_TO_IFID(in6)	do {(in6)->s6_addr[8] ^= EUI64_UBIT; } while (0)
#define EUI64_GROUP(in6)	((in6)->s6_addr[8] & EUI64_GBIT)
#define EUI64_INDIVIDUAL(in6)	(!EUI64_GROUP(in6))
#define EUI64_LOCAL(in6)	((in6)->s6_addr[8] & EUI64_UBIT)
#define EUI64_UNIVERSAL(in6)	(!EUI64_LOCAL(in6))

#define IFID_LOCAL(in6)		(!EUI64_LOCAL(in6))
#define IFID_UNIVERSAL(in6)	(!EUI64_UNIVERSAL(in6))

/*dummy*/
int
in6_ifattach_getifid(ifp)
	struct ifnet *ifp;
{
	return 0;
}

/*
 * Generate a last-resort interface identifier, when the machine has no
 * IEEE802/EUI64 address sources.
 * The goal here is to get an interface identifier that is
 * (1) random enough and (2) does not change across reboot.
 * We currently use MD5(hostname) for it.
 */
static int
get_rand_ifid(ifp, in6)
	struct ifnet *ifp;
	struct in6_addr *in6;	/*upper 64bits are preserved */
{
	MD5_CTX ctxt;
	u_int8_t digest[16];
#ifdef __FreeBSD__
	int hostnamelen	= strlen(hostname);
#endif

#if 0
	/* we need at least several letters as seed for ifid */
	if (hostnamelen < 3)
		return -1;
#endif

	/* generate 8 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof(ctxt));
	MD5Init(&ctxt);
	MD5Update(&ctxt, hostname, hostnamelen);
	MD5Final(digest, &ctxt);

	/* assumes sizeof(digest) > sizeof(ifid) */
	bcopy(digest, &in6->s6_addr[8], 8);

	/* make sure to set "u" bit to local, and "g" bit to individual. */
	in6->s6_addr[8] &= ~EUI64_GBIT;	/* g bit to "individual" */
	in6->s6_addr[8] |= EUI64_UBIT;	/* u bit to "local" */

	/* convert EUI64 into IPv6 interface identifier */
	EUI64_TO_IFID(in6);

	return 0;
}

/*
 * Get interface identifier for the specified interface.
 */
static int
get_hw_ifid(ifp, in6)
	struct ifnet *ifp;
	struct in6_addr *in6;	/*upper 64bits are preserved */
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	u_int8_t *addr;
	size_t addrlen;
	static u_int8_t allzero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	static u_int8_t allone[8] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
	for (ifa = ifp->if_addrlist.tqh_first;
	     ifa;
	     ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl == NULL)
			continue;
		if (sdl->sdl_alen == 0)
			continue;

		goto found;
	}

	return -1;

found:
	addr = LLADDR(sdl);
	addrlen = sdl->sdl_alen;

	/* get EUI64 */
	switch (ifp->if_type) {
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_ATM:
		/* IEEE802/EUI64 cases - what others? */

		/* look at IEEE802/EUI64 only */
		if (addrlen != 8 && addrlen != 6)
			return -1;

		/*
		 * check for invalid MAC address - on bsdi, we see it a lot
		 * since wildboar configures all-zero MAC on pccard before
		 * card insertion.
		 */
		if (bcmp(addr, allzero, addrlen) == 0)
			return -1;
		if (bcmp(addr, allone, addrlen) == 0)
			return -1;

		/* make EUI64 address */
		if (addrlen == 8)
			bcopy(addr, &in6->s6_addr[8], 8);
		else if (addrlen == 6) {
			in6->s6_addr[8] = addr[0];
			in6->s6_addr[9] = addr[1];
			in6->s6_addr[10] = addr[2];
			in6->s6_addr[11] = 0xff;
			in6->s6_addr[12] = 0xff;
			in6->s6_addr[13] = addr[3];
			in6->s6_addr[14] = addr[4];
			in6->s6_addr[15] = addr[5];
		}
		break;
	case IFT_ARCNET:
		if (addrlen != 1)
			return -1;

		bzero(&in6->s6_addr[8], 8);
		in6->s6_addr[15] = addr[0];

		in6->s6_addr[8] &= ~EUI64_GBIT;	/* g bit to "individual" */
		in6->s6_addr[8] |= EUI64_UBIT;	/* u bit to "local" */
		break;
	default:
		return -1;
	}

	/* sanity check: g bit must not indicate "group" */
	if (EUI64_GROUP(in6))
		return -1;

	/* convert EUI64 into IPv6 interface identifier */
	EUI64_TO_IFID(in6);

	return 0;
}

/*
 * Get interface identifier for the specified interface.  If it is not
 * available on ifp0, borrow interface identifier from other information
 * sources.
 */
static int
get_ifid(ifp0, in6)
	struct ifnet *ifp0;
	struct in6_addr *in6;
{
	struct ifnet *ifp;

	/* first, try to get it from the interface itself */
	if (get_hw_ifid(ifp0, in6) == 0) {
#ifdef ND6_DEBUG
		printf("%s: got interface identifier from itself\n",
		    if_name(ifp0));
#endif
		goto success;
	}

	/* next, try to get it from some other hardware interface */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_list.tqe_next)
#endif
	{
		if (ifp == ifp0)
			continue;
		if (get_hw_ifid(ifp, in6) != 0)
			continue;
		/*
		 * to borrow ifid from other interface, ifid needs to be
		 * globally unique
		 */
		if (IFID_UNIVERSAL(in6)) {

#ifdef ND6_DEBUG
			printf("%s: borrow interface identifier from %s\n",
			    if_name(ifp0), if_name(ifp));
#endif
			goto success;
		}
	}

	/* last resort: get from random number source */
	if (get_rand_ifid(ifp, in6) == 0) {
#ifdef ND6_DEBUG
		printf("%s: interface identifier generated by random number\n",
		    if_name(ifp0));
#endif
		goto success;
	}

	printf("%s: failed to get interface identifier", if_name(ifp0));
	return -1;

success:
#ifdef ND6_DEBUG
	printf("%s: ifid: "
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		if_name(ifp0),
		in6->s6_addr[8], in6->s6_addr[9],
		in6->s6_addr[10], in6->s6_addr[11],
		in6->s6_addr[12], in6->s6_addr[13],
		in6->s6_addr[14], in6->s6_addr[15]);
#endif
	return 0;
}

/*
 * XXX multiple loopback interface needs more care.  for instance,
 * nodelocal address needs to be configured onto only one of them.
 */
void
in6_ifattach(ifp, type, laddr, noloop)
	struct ifnet *ifp;
	u_int type;
	caddr_t laddr;	/* not used any more */
	/* size_t laddrlen; */
	int noloop;	/* not used any more */
{
	static size_t if_indexlim = 8;
	struct sockaddr_in6 mltaddr;
	struct sockaddr_in6 mltmask;
	struct sockaddr_in6 gate;
	struct sockaddr_in6 mask;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr **ifap;
#endif

	struct in6_ifaddr *ia, *ib, *oia;
	struct ifaddr *ifa;
	int rtflag = 0;

	if ((ifp->if_flags & IFF_MULTICAST) == 0) {
		printf("%s: not multicast capable, IPv6 not enabled\n",
			if_name(ifp));
		return;
	}

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 *	struct in6_ifstat **in6_ifstat
	 *	struct icmp6_ifstat **icmp6_ifstat
	 */
	if (in6_ifstat == NULL || icmp6_ifstat == NULL
	 || if_index >= if_indexlim) {
		size_t n;
		caddr_t q;
		size_t olim;

		olim = if_indexlim;
		while (if_index >= if_indexlim)
			if_indexlim <<= 1;

		/* grow in6_ifstat */
		n = if_indexlim * sizeof(struct in6_ifstat *);
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		bzero(q, n);
		if (in6_ifstat) {
			bcopy((caddr_t)in6_ifstat, q,
				olim * sizeof(struct in6_ifstat *));
			free((caddr_t)in6_ifstat, M_IFADDR);
		}
		in6_ifstat = (struct in6_ifstat **)q;
		in6_ifstatmax = if_indexlim;

		/* grow icmp6_ifstat */
		n = if_indexlim * sizeof(struct icmp6_ifstat *);
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		bzero(q, n);
		if (icmp6_ifstat) {
			bcopy((caddr_t)icmp6_ifstat, q,
				olim * sizeof(struct icmp6_ifstat *));
			free((caddr_t)icmp6_ifstat, M_IFADDR);
		}
		icmp6_ifstat = (struct icmp6_ifstat **)q;
		icmp6_ifstatmax = if_indexlim;
	}

	/*
	 * To prevent to assign link-local address to PnP network
	 * cards multiple times.
	 * This is lengthy for P2P and LOOP but works.
	 */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	ifa = ifp->if_addrlist;
	if (ifa != NULL) {
		for ( ; ifa; ifa = ifa->ifa_next) {
			ifap = &ifa->ifa_next;
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&satosin6(ifa->ifa_addr)->sin6_addr))
				return;
		}
	} else
		ifap = &ifp->if_addrlist;
#else
	ifa = TAILQ_FIRST(&ifp->if_addrlist);
	if (ifa != NULL) {
		for ( ; ifa; ifa = TAILQ_NEXT(ifa, ifa_list)) {
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&satosin6(ifa->ifa_addr)->sin6_addr))
				return;
		}
	} else {
		TAILQ_INIT(&ifp->if_addrlist);
	}
#endif

	/*
	 * link-local address
	 */
	ia = (struct in6_ifaddr *)malloc(sizeof(*ia), M_IFADDR, M_WAITOK);
	bzero((caddr_t)ia, sizeof(*ia));
	ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	if (ifp->if_flags & IFF_POINTOPOINT)
		ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
	else
		ia->ia_ifa.ifa_dstaddr = NULL;
	ia->ia_ifa.ifa_netmask = (struct sockaddr *)&ia->ia_prefixmask;
	ia->ia_ifp = ifp;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	*ifap = (struct ifaddr *)ia;
#else
	TAILQ_INSERT_TAIL(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif
	ia->ia_ifa.ifa_refcnt++;

	/*
	 * Also link into the IPv6 address chain beginning with in6_ifaddr.
	 * kazu opposed it, but itojun & jinmei wanted.
	 */
	if ((oia = in6_ifaddr) != NULL) {
		for (; oia->ia_next; oia = oia->ia_next)
			continue;
		oia->ia_next = ia;
	} else
		in6_ifaddr = ia;
	ia->ia_ifa.ifa_refcnt++;

	ia->ia_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ia->ia_prefixmask.sin6_family = AF_INET6;
	ia->ia_prefixmask.sin6_addr = in6mask64;

	bzero(&ia->ia_addr, sizeof(struct sockaddr_in6));
	ia->ia_addr.sin6_len = sizeof(struct sockaddr_in6);
	ia->ia_addr.sin6_family = AF_INET6;
	ia->ia_addr.sin6_addr.s6_addr16[0] = htons(0xfe80);
	ia->ia_addr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	ia->ia_addr.sin6_addr.s6_addr32[1] = 0;

	if (ifp->if_flags & IFF_LOOPBACK) {
		ia->ia_addr.sin6_addr.s6_addr32[2] = 0;
		ia->ia_addr.sin6_addr.s6_addr32[3] = htonl(1);
	} else {
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
		rtflag = RTF_CLONING;
		if (get_ifid(ifp, &ia->ia_addr.sin6_addr) != 0) {
			printf("invalid ifid\n");
			/* XXX should cleanup the mess */
		}
		bzero(&ia->ia_dstaddr, sizeof(struct sockaddr_in6));
		ia->ia_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
		ia->ia_dstaddr.sin6_family = AF_INET6;
	}

	ia->ia_ifa.ifa_metric = ifp->if_metric;

	if (ifp->if_ioctl != NULL) {
		int s;
		int error;

		/*
		 * give the interface a chance to initialize, in case this
		 * is the first address to be added.
		 */
		s = splimp();
		error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia);
		splx(s);

		if (error) {
			switch (error) {
			case EAFNOSUPPORT:
				printf("%s: IPv6 not supported\n",
					if_name(ifp));
				break;
			default:
				printf("%s: SIOCSIFADDR error %d\n",
					if_name(ifp), error);
				break;
			}

			/* undo changes */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
			*ifap = NULL;
#else
			TAILQ_REMOVE(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif
			IFAFREE(&ia->ia_ifa);
			if (oia)
				oia->ia_next = ia->ia_next;
			else
				in6_ifaddr = ia->ia_next;
			IFAFREE(&ia->ia_ifa);
			return;
		}
	}

	/* add route to the interface. */
	rtrequest(RTM_ADD,
		  (struct sockaddr *)&ia->ia_addr,
		  (struct sockaddr *)&ia->ia_addr,
		  (struct sockaddr *)&ia->ia_prefixmask,
		  RTF_UP|rtflag,
		  (struct rtentry **)0);
	ia->ia_flags |= IFA_ROUTE;

	if (ifp->if_flags & IFF_POINTOPOINT) {
		/*
		 * route local address to loopback
		 */
		bzero(&gate, sizeof(gate));
		gate.sin6_len = sizeof(struct sockaddr_in6);
		gate.sin6_family = AF_INET6;
		gate.sin6_addr = in6addr_loopback;
		bzero(&mask, sizeof(mask));
		mask.sin6_len = sizeof(struct sockaddr_in6);
		mask.sin6_family = AF_INET6;
		mask.sin6_addr = in6mask64;
		rtrequest(RTM_ADD,
			  (struct sockaddr *)&ia->ia_addr,
			  (struct sockaddr *)&gate,
			  (struct sockaddr *)&mask,
			  RTF_UP|RTF_HOST,
			  (struct rtentry **)0);
	}

	/*
	 * loopback address
	 */
	ib = (struct in6_ifaddr *)NULL;
	if (ifp->if_flags & IFF_LOOPBACK) {
		ib = (struct in6_ifaddr *)
			malloc(sizeof(*ib), M_IFADDR, M_WAITOK);
		bzero((caddr_t)ib, sizeof(*ib));
		ib->ia_ifa.ifa_addr = (struct sockaddr *)&ib->ia_addr;
		ib->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ib->ia_dstaddr;
		ib->ia_ifa.ifa_netmask = (struct sockaddr *)&ib->ia_prefixmask;
		ib->ia_ifp = ifp;

		ia->ia_next = ib;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		ia->ia_ifa.ifa_next = (struct ifaddr *)ib;
#else
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, (struct ifaddr *)ib,
			ifa_list);
#endif
		ib->ia_ifa.ifa_refcnt++;

		ib->ia_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		ib->ia_prefixmask.sin6_family = AF_INET6;
		ib->ia_prefixmask.sin6_addr = in6mask128;
		ib->ia_addr.sin6_len = sizeof(struct sockaddr_in6);
		ib->ia_addr.sin6_family = AF_INET6;
		ib->ia_addr.sin6_addr = in6addr_loopback;

		/*
		 * Always initialize ia_dstaddr (= broadcast address)
		 * to loopback address, to make getifaddr happier.
		 *
		 * For BSDI, it is mandatory.  The BSDI version of
		 * ifa_ifwithroute() rejects to add a route to the loopback
		 * interface.  Even for other systems, loopback looks somewhat
		 * special.
		 */
		ib->ia_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
		ib->ia_dstaddr.sin6_family = AF_INET6;
		ib->ia_dstaddr.sin6_addr = in6addr_loopback;

		ib->ia_ifa.ifa_metric = ifp->if_metric;

		rtrequest(RTM_ADD,
			  (struct sockaddr *)&ib->ia_addr,
			  (struct sockaddr *)&ib->ia_addr,
			  (struct sockaddr *)&ib->ia_prefixmask,
			  RTF_UP|RTF_HOST,
			  (struct rtentry **)0);

		ib->ia_flags |= IFA_ROUTE;
	}

	/*
	 * join multicast
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		int error;	/* not used */

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
		/* Restore saved multicast addresses(if any). */
		in6_restoremkludge(ia, ifp);
#endif

		bzero(&mltmask, sizeof(mltmask));
		mltmask.sin6_len = sizeof(struct sockaddr_in6);
		mltmask.sin6_family = AF_INET6;
		mltmask.sin6_addr = in6mask32;

		/*
		 * join link-local all-nodes address
		 */
		bzero(&mltaddr, sizeof(mltaddr));
		mltaddr.sin6_len = sizeof(struct sockaddr_in6);
		mltaddr.sin6_family = AF_INET6;
		mltaddr.sin6_addr = in6addr_linklocal_allnodes;
		mltaddr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		rtrequest(RTM_ADD,
			  (struct sockaddr *)&mltaddr,
			  (struct sockaddr *)&ia->ia_addr,
			  (struct sockaddr *)&mltmask,
			  RTF_UP|RTF_CLONING,  /* xxx */
			  (struct rtentry **)0);
		(void)in6_addmulti(&mltaddr.sin6_addr, ifp, &error);

		if (ifp->if_flags & IFF_LOOPBACK) {
			/*
			 * join node-local all-nodes address
			 */
			mltaddr.sin6_addr = in6addr_nodelocal_allnodes;
			rtrequest(RTM_ADD,
				  (struct sockaddr *)&mltaddr,
				  (struct sockaddr *)&ib->ia_addr,
				  (struct sockaddr *)&mltmask,
				  RTF_UP,
				  (struct rtentry **)0);
			(void)in6_addmulti(&mltaddr.sin6_addr, ifp, &error);
		} else {
			/*
			 * join solicited multicast address
			 */
			bzero(&llsol, sizeof(llsol));
			llsol.s6_addr16[0] = htons(0xff02);
			llsol.s6_addr16[1] = htons(ifp->if_index);
			llsol.s6_addr32[1] = 0;
			llsol.s6_addr32[2] = htonl(1);
			llsol.s6_addr32[3] = ia->ia_addr.sin6_addr.s6_addr32[3];
			llsol.s6_addr8[12] = 0xff;
			(void)in6_addmulti(&llsol, ifp, &error);
		}
	}

	/* update dynamically. */
	if (in6_maxmtu < ifp->if_mtu)
		in6_maxmtu = ifp->if_mtu;

	if (in6_ifstat[ifp->if_index] == NULL) {
		in6_ifstat[ifp->if_index] = (struct in6_ifstat *)
			malloc(sizeof(struct in6_ifstat), M_IFADDR, M_WAITOK);
		bzero(in6_ifstat[ifp->if_index], sizeof(struct in6_ifstat));
	}
	if (icmp6_ifstat[ifp->if_index] == NULL) {
		icmp6_ifstat[ifp->if_index] = (struct icmp6_ifstat *)
			malloc(sizeof(struct icmp6_ifstat), M_IFADDR, M_WAITOK);
		bzero(icmp6_ifstat[ifp->if_index], sizeof(struct icmp6_ifstat));
	}

	/* initialize NDP variables */
	nd6_ifattach(ifp);

	/* mark the address TENTATIVE, if needed. */
	switch (ifp->if_type) {
	case IFT_ARCNET:
	case IFT_ETHER:
	case IFT_FDDI:
#if 0
	case IFT_ATM:
	case IFT_SLIP:
	case IFT_PPP:
#endif
		ia->ia6_flags |= IN6_IFF_TENTATIVE;
		/* nd6_dad_start() will be called in in6_if_up */
		break;
	case IFT_DUMMY:
	case IFT_GIF:	/*XXX*/
	case IFT_LOOP:
	case IFT_FAITH:
	default:
		break;
	}

	return;
}

/*
 * NOTE: in6_ifdetach() does not support loopback if at this moment.
 */
void
in6_ifdetach(ifp)
	struct ifnet *ifp;
{
	struct in6_ifaddr *ia, *oia;
	struct ifaddr *ifa;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifaprev = NULL;
#endif
	struct rtentry *rt;
	short rtflags;
	struct sockaddr_in6 sin6;
	struct in6_multi *in6m;
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	struct in6_multi *in6m_next;
#endif

	/* nuke prefix list.  this may try to remove some of ifaddrs as well */
	in6_purgeprefix(ifp);

	/* remove neighbor management table */
	nd6_purge(ifp);

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_INET6
		 || !IN6_IS_ADDR_LINKLOCAL(&satosin6(&ifa->ifa_addr)->sin6_addr)) {
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
			ifaprev = ifa;
#endif
			continue;
		}

		ia = (struct in6_ifaddr *)ifa;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
		/* leave from all multicast groups joined */
		while ((in6m = LIST_FIRST(&oia->ia6_multiaddrs)) != NULL)
			in6_delmulti(in6m);
#endif

		/* remove from the routing table */
		if ((ia->ia_flags & IFA_ROUTE)
		 && (rt = rtalloc1((struct sockaddr *)&ia->ia_addr, 0
#ifdef __FreeBSD__
				, 0UL
#endif
				))) {
			rtflags = rt->rt_flags;
			rtfree(rt);
			rtrequest(RTM_DELETE,
				(struct sockaddr *)&ia->ia_addr,
				(struct sockaddr *)&ia->ia_addr,
				(struct sockaddr *)&ia->ia_prefixmask,
				rtflags, (struct rtentry **)0);
		}

		/* remove from the linked list */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		if (ifaprev)
			ifaprev->ifa_next = ifa->ifa_next;
		else
			ifp->if_addrlist = ifa->ifa_next;
#else
		TAILQ_REMOVE(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif

		/* also remove from the IPv6 address chain(itojun&jinmei) */
		oia = ia;
		if (oia == (ia = in6_ifaddr))
			in6_ifaddr = ia->ia_next;
		else {
			while (ia->ia_next && (ia->ia_next != oia))
				ia = ia->ia_next;
			if (ia->ia_next)
				ia->ia_next = oia->ia_next;
#ifdef ND6_DEBUG
			else
				printf("%s: didn't unlink in6ifaddr from "
				    "list\n", if_name(ifp));
#endif
		}

		free(ia, M_IFADDR);
	}

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	/* leave from all multicast groups joined */
	for (in6m = LIST_FIRST(&in6_multihead); in6m; in6m = in6m_next) {
		in6m_next = LIST_NEXT(in6m, in6m_entry);
		if (in6m->in6m_ifp != ifp)
			continue;
		in6_delmulti(in6m);
		in6m = NULL;
	}
#endif

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	/* cleanup multicast address kludge table, if there is any */
	in6_purgemkludge(ifp);
#endif

	/* remove neighbor management table */
	nd6_purge(ifp);

	/* remove route to link-local allnodes multicast (ff02::1) */
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = in6addr_linklocal_allnodes;
	sin6.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
#ifndef __FreeBSD__
	if ((rt = rtalloc1((struct sockaddr *)&sin6, 0)) != NULL)
#else
	if ((rt = rtalloc1((struct sockaddr *)&sin6, 0, 0UL)) != NULL)
#endif
	{
		rtrequest(RTM_DELETE, (struct sockaddr *)rt_key(rt),
			rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
		rtfree(rt);
	}
}
