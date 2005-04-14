/*	$OpenBSD: if_pflog.c,v 1.9 2003/05/14 08:42:00 canacar Exp $	*/
/*
 * The authors of this code are John Ioannidis (ji@tla.org),
 * Angelos D. Keromytis (kermit@csd.uch.gr) and 
 * Niels Provos (provos@physnet.uni-hamburg.de).
 *
 * This code was written by John Ioannidis for BSD/OS in Athens, Greece, 
 * in November 1995.
 *
 * Ported to OpenBSD and NetBSD, with additional transforms, in December 1996,
 * by Angelos D. Keromytis.
 *
 * Additional transforms and features in 1997 and 1998 by Angelos D. Keromytis
 * and Niels Provos.
 *
 * Copyright (C) 1995, 1996, 1997, 1998 by John Ioannidis, Angelos D. Keromytis
 * and Niels Provos.
 * Copyright (c) 2001, Angelos D. Keromytis, Niels Provos.
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software. 
 * You may use this code under the GNU public license if you so wish. Please
 * contribute changes back to the authors under this freer than GPL license
 * so that we may further the use of strong encryption without limitations to
 * all.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#ifdef __FreeBSD__
#include "opt_inet.h"
#include "opt_inet6.h"
#endif
#ifdef _KERNEL_OPT
#include "opt_inet.h"
#endif

#ifdef __FreeBSD__
#include "bpf.h"
#define NBPFILTER NBPF
#else
#include "bpfilter.h"
#endif
#include "pflog.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#ifndef __FreeBSD__
#include <sys/ioctl.h>
#else
#include <sys/kernel.h>
#include <sys/sockio.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>

#ifdef	INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#ifdef __FreeBSD__
#include <machine/in_cksum.h>
#endif

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/nd6.h>
#endif /* INET6 */

#include <net/pfvar.h>
#include <net/if_pflog.h>

#include <net/net_osdep.h>

#define PFLOGMTU	(32768 + MHLEN + MLEN)

#ifdef PFLOGDEBUG
#define DPRINTF(x)    do { if (pflogdebug) printf x ; } while (0)
#else
#define DPRINTF(x)
#endif

struct pflog_softc pflogif[NPFLOG];

#ifdef __FreeBSD__
void	pflogattach(void *);
PSEUDO_SET(pflogattach, if_pflog);
#else
void	pflogattach(int);
#endif
int	pflogoutput(struct ifnet *, struct mbuf *, struct sockaddr *,
	    	       struct rtentry *);
int	pflogioctl(struct ifnet *, u_long, caddr_t);
void	pflogrtrequest(int, struct rtentry *, struct sockaddr *);
void	pflogstart(struct ifnet *);

#ifndef __FreeBSD__
extern int ifqmaxlen;
#endif

#ifdef __FreeBSD__
void
pflogattach(void *pflog)
#else
void
pflogattach(int npflog)
#endif
{
	struct ifnet *ifp;
	int i;

	bzero(pflogif, sizeof(pflogif));

	for (i = 0; i < NPFLOG; i++) {
		ifp = &pflogif[i].sc_if;
#ifdef __FreeBSD__
		if_initname(ifp, "pflog", i);
#else
		snprintf(ifp->if_xname, sizeof ifp->if_xname, "pflog%d", i);
#endif
		ifp->if_softc = &pflogif[i];
		ifp->if_mtu = PFLOGMTU;
		ifp->if_ioctl = pflogioctl;
		ifp->if_output = pflogoutput;
		ifp->if_start = pflogstart;
		ifp->if_type = IFT_PFLOG;
		ifp->if_snd.ifq_maxlen = ifqmaxlen;
		ifp->if_hdrlen = PFLOG_HDRLEN;
		if_attach(ifp);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		ifp->if_addrlen = 0;
		if_alloc_sadl(ifp);
#endif

#if NBPFILTER > 0
#ifndef HAVE_NEW_BPFATTACH
		bpfattach(&pflogif[i].sc_if.if_bpf, ifp, DLT_PFLOG,
			  PFLOG_HDRLEN);
#else
		bpfattach(ifp, DLT_PFLOG, PFLOG_HDRLEN);
#endif
#endif
	}
}

/*
 * Start output on the pflog interface.
 */
void
pflogstart(struct ifnet *ifp)
{
	struct mbuf *m;
	int s;

	for (;;) {
#ifdef __OpenBSD__
		s = splimp();
#else
		s = splnet();
#endif
#ifdef __FreeBSD__
		IFQ_LOCK(&ifp->if_snd);
#else
		IF_DROP(&ifp->if_snd);
#endif
		IF_DEQUEUE(&ifp->if_snd, m);
#ifdef __FreeBSD__
		IFQ_UNLOCK(&ifp->if_snd);
#endif
		splx(s);

		if (m == NULL)
			return;
		else
			m_freem(m);
	}
}

int
pflogoutput(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
	struct rtentry *rt)
{
	m_freem(m);
	return (0);
}

/* ARGSUSED */
void
pflogrtrequest(int cmd, struct rtentry *rt, struct sockaddr *sa)
{
	if (rt)
		rt->rt_rmx.rmx_mtu = PFLOGMTU;
}

/* ARGSUSED */
int
pflogioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	switch (cmd) {
	case SIOCSIFADDR:
	case SIOCAIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			ifp->if_flags |= IFF_RUNNING;
		else
			ifp->if_flags &= ~IFF_RUNNING;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

int
pflog_packet(struct ifnet *ifp, struct mbuf *m, sa_family_t af, u_int8_t dir,
    u_int8_t reason, struct pf_rule *rm, struct pf_rule *am,
    struct pf_ruleset *ruleset)
{
#if NBPFILTER > 0
	struct ifnet *ifn;
	struct pfloghdr hdr;
	struct mbuf m1;

	if (ifp == NULL || m == NULL || rm == NULL)
		return (-1);

	hdr.length = PFLOG_REAL_HDRLEN;
	hdr.af = af;
	hdr.action = rm->action;
	hdr.reason = reason;
	memcpy(hdr.ifname, if_name(ifp), sizeof(hdr.ifname));

	if (am == NULL) {
		hdr.rulenr = htonl(rm->nr);
		hdr.subrulenr = -1;
		bzero(hdr.ruleset, sizeof(hdr.ruleset));
	} else {
		hdr.rulenr = htonl(am->nr);
		hdr.subrulenr = htonl(rm->nr);
		if (ruleset == NULL)
			bzero(hdr.ruleset, sizeof(hdr.ruleset));
		else
			memcpy(hdr.ruleset, ruleset->name,
			    sizeof(hdr.ruleset));

			
	}
	hdr.dir = dir;

#ifdef INET
	if (af == AF_INET && dir == PF_OUT) {
		struct ip *ip;

		ip = mtod(m, struct ip *);
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(m, ip->ip_hl << 2);
	}
#endif /* INET */

	m1.m_next = m;
	m1.m_len = PFLOG_HDRLEN;
	m1.m_data = (char *) &hdr;

	ifn = &(pflogif[0].sc_if);

	if (ifn->if_bpf) {
#ifndef __FreeBSD__
		bpf_mtap(ifn->if_bpf, &m1);
#else
#ifdef HAVE_NEW_BPF
		bpf_mtap(ifn, &m1);
#else
		bpf_mtap(ifn->if_bpf, &m1);
#endif
#endif
	}
#endif

	return (0);
}
