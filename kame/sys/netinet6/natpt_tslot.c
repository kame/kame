/*	$KAME: natpt_tslot.c,v 1.35 2001/12/11 11:34:10 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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
#include "opt_natpt.h"
#endif

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/systm.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

static int		*tSlotEntry;
static int		 tSlotEntryMax;
static int		 tSlotEntryUsed;

static time_t		 maxFragment;
static time_t		 frgmntTimer;
static time_t		 tSlotTimer;
static time_t		 maxTTLany;
static time_t		 maxTTLicmp;
static time_t		 maxTTLudp;
static time_t		 maxTTLtcp;

static time_t		 natpt_TCPT_2MSL;
static time_t		 natpt_tcp_maxidle;


struct tslhash
{
	TAILQ_HEAD(tslhead,tSlot)	tslhead;
	int				curlen;
	int				maxlen;
};


TAILQ_HEAD(,tSlot)	 tsl_head;
struct tslhash		 tslhashl[NATPTHASHSZ];
struct tslhash		 tslhashr[NATPTHASHSZ];

TAILQ_HEAD(,fragment)	 frg_head;


#ifdef __FreeBSD__
MALLOC_DECLARE(M_NATPT);
#endif


/*
 *
 */

struct tSlot	*natpt_lookForHash		__P((struct pcv *, struct tslhash *, int));
static int	 natpt_hash4			__P((struct pcv *));
static int	 natpt_hash6			__P((struct pcv *));
static int	 natpt_hashPad4			__P((struct pAddr *));
static int	 natpt_hashPad6			__P((struct pAddr *));
static int	 natpt_hashSin4			__P((struct sockaddr_in *));
static int	 natpt_hashSin6			__P((struct sockaddr_in6 *));
static int	 natpt_hashPJW			__P((u_char *, int));

static void	 natpt_expireFragment		__P((void *));
static void	 natpt_expireTSlot		__P((void *));
static void	 natpt_removeTSlotEntry		__P((struct tSlot *));


/*
 *
 */

struct tSlot *
natpt_lookForHash6(struct pcv *cv)
{
	int		hv;
	struct tSlot	*ats;

	hv = natpt_hash6(cv);
	if (((ats = natpt_lookForHash(cv, &tslhashl[hv], NATPT_FROM)) == NULL)
	    && ((ats = natpt_lookForHash(cv, &tslhashr[hv], NATPT_TO)) == NULL))
		return (NULL);

	return (ats);
}


struct tSlot *
natpt_lookForHash4(struct pcv *cv)
{
	int		 hv;
	struct tSlot	*ats;

	hv = natpt_hash4(cv);
	if (((ats = natpt_lookForHash(cv, &tslhashl[hv], NATPT_FROM)) == NULL)
	    && ((ats = natpt_lookForHash(cv, &tslhashr[hv], NATPT_TO)) == NULL))
		return (NULL);

	return (ats);
}


struct tSlot *
natpt_internHash6(struct cSlot *acs, struct pcv *cv6)
{
	int		 s;
	int		 hvl, hvr;
	struct tslhash	*thl, *thr;
	struct pAddr	*local, *remote;
	struct tSlot	*ats;

	MALLOC(ats, struct tSlot *, sizeof(struct tSlot), M_NATPT, M_NOWAIT);
	if (ats == NULL) {
		return (NULL);
	}

	bzero(ats, sizeof(struct tSlot));

	local = &ats->local;
	local->sa_family = AF_INET6;
	local->in6src = cv6->ip.ip6->ip6_src;
	local->in6dst = cv6->ip.ip6->ip6_dst;
	if ((cv6->ip_p == IPPROTO_TCP)
	    || (cv6->ip_p == IPPROTO_UDP)) {
		local->port[0] = cv6->pyld.tcp6->th_sport;
		local->port[1] = cv6->pyld.tcp6->th_dport;
	}

	remote = &ats->remote;
	remote->sa_family = AF_INET;
	remote->in4src.s_addr = cv6->ip.ip6->ip6_dst.s6_addr32[3];
	remote->in4dst = acs->Remote.in4src;
	if ((cv6->ip_p == IPPROTO_TCP)
	    || (cv6->ip_p == IPPROTO_UDP)) {
		remote->port[0] = cv6->pyld.tcp6->th_dport;
		remote->port[1] = cv6->pyld.tcp6->th_sport;

		if (acs->map & NATPT_REMAP_SPORT)
			natpt_remapRemote4Port(acs, remote);
	}

	ats->ip_p = cv6->ip_p;
	ats->csl = acs;

	ats->hvl = hvl = natpt_hashPad6(local);
	thl = &tslhashl[hvl];
	ats->hvr = hvr = natpt_hashPad4(remote);
	thr = &tslhashr[hvr];

	s = splnet();
	thl->curlen++;
	thl->maxlen = max(thl->maxlen, thl->curlen);
	thr->curlen++;
	thr->maxlen = max(thr->maxlen, thr->curlen);

	TAILQ_INSERT_TAIL(&tsl_head, ats, tsl_list);
	TAILQ_INSERT_TAIL(&thl->tslhead, ats, tsl_hashl);
	TAILQ_INSERT_TAIL(&thr->tslhead, ats, tsl_hashr);
	splx(s);

	return (ats);
}


struct tSlot *
natpt_internHash4(struct cSlot *acs, struct pcv *cv4)
{
	int		 s;
	int		 hvl, hvr;
	struct tslhash	*thl, *thr;
	struct pAddr	*local, *remote;
	struct tSlot	*ats;

	MALLOC(ats, struct tSlot *, sizeof(struct tSlot), M_NATPT, M_NOWAIT);
	if (ats == NULL) {
		return (NULL);
	}

	bzero(ats, sizeof(struct tSlot));

	local = &ats->local;
	local->sa_family = AF_INET;
	local->in4src = cv4->ip.ip4->ip_src;
	local->in4dst = cv4->ip.ip4->ip_dst;
	if ((cv4->ip_p == IPPROTO_TCP)
	    || (cv4->ip_p == IPPROTO_UDP)) {
		local->port[0] = cv4->pyld.tcp4->th_sport;
		local->port[1] = cv4->pyld.tcp4->th_dport;
	}

	remote = &ats->remote;
#ifdef NATPT_NAT
	if ((acs->map & NATPT_BIDIR)
	    && (cv4->fromto == NATPT_TO)
	    && (acs->Local.sa_family == AF_INET)) {
		remote->sa_family = AF_INET;
		remote->in4src = acs->Local.in4Addr;
		remote->in4dst = cv4->ip.ip4->ip_src;
		if ((cv4->ip_p == IPPROTO_TCP)
		    || (cv4->ip_p == IPPROTO_UDP)) {
			remote->port[0] = cv4->pyld.tcp4->th_dport;
			remote->port[1] = cv4->pyld.tcp4->th_sport;
		}
		cv4->fromto = NATPT_FROM;			/* XXX */
	} else if (acs->Remote.sa_family == AF_INET) {
		remote->sa_family = AF_INET;
		remote->in4src = cv4->ip.ip4->ip_dst;
		remote->in4dst = acs->Remote.in4Addr;
		if ((cv4->ip_p == IPPROTO_TCP)
		    || (cv4->ip_p == IPPROTO_UDP)) {
			remote->port[0] = cv4->pyld.tcp4->th_dport;
			remote->port[1] = cv4->pyld.tcp4->th_sport;
			if (acs->map & NATPT_REMAP_SPORT)
				natpt_remapRemote4Port(acs, remote);
		}
	} else
#endif
	{
		remote->sa_family = AF_INET6;
		remote->in6src = acs->Remote.in6src;
		if (acs->map & NATPT_REDIRECT_ADDR)
			remote->in6src = acs->remote.daddr.in6;
		remote->in6dst = natpt_prefix;
		remote->in6dst.s6_addr32[3] = cv4->ip.ip4->ip_src.s_addr;
		if ((cv4->ip_p == IPPROTO_TCP)
		    || (cv4->ip_p == IPPROTO_UDP)) {
			remote->port[0] = cv4->pyld.tcp4->th_dport;
			remote->port[1] = cv4->pyld.tcp4->th_sport;

			if (acs->map & NATPT_REDIRECT_PORT)
				remote->port[0] = acs->remote.dport;
			if (acs->map & NATPT_REMAP_SPORT)
				natpt_remapRemote4Port(acs, remote);
		}
	}

	ats->ip_p = cv4->ip_p;
	ats->csl = acs;

	ats->hvl = hvl = natpt_hashPad4(local);
	thl = &tslhashl[hvl];
#ifdef NATPT_NAT
	if (acs->Remote.sa_family == AF_INET)
		hvr = natpt_hashPad4(remote);
	else
#endif
		hvr = natpt_hashPad6(remote);
	ats->hvr = hvr;
	thr = &tslhashr[hvr];

	s = splnet();
	thl->curlen++;
	thl->maxlen = max(thl->maxlen, thl->curlen);
	thr->curlen++;
	thr->maxlen = max(thr->maxlen, thr->curlen);

	TAILQ_INSERT_TAIL(&tsl_head, ats, tsl_list);
	TAILQ_INSERT_TAIL(&thl->tslhead, ats, tsl_hashl);
	TAILQ_INSERT_TAIL(&thr->tslhead, ats, tsl_hashr);
	splx(s);

	return (ats);
}


struct tSlot *
natpt_openIncomingV4Conn(int proto, struct pAddr *local, struct pAddr *remote)
{
	int		 s;
	int		 hvl, hvr;
	struct tslhash	*thl, *thr;
	struct tSlot	*ats;
	struct tcpstate	*ts;

	MALLOC(ats, struct tSlot *, sizeof(struct tSlot), M_NATPT, M_NOWAIT);
	if (ats == NULL)
		return (NULL);

	/* Should we think about UDP?	*/
	MALLOC(ts, struct tcpstate *, sizeof(struct tcpstate), M_NATPT, M_NOWAIT);
	if (ts == NULL) {
		FREE(ats, M_NATPT);
		return (NULL);
	}

	bzero(ats, sizeof(struct tSlot));
	ats->ip_p = proto;
	ats->local = *local;
	ats->remote = *remote;

	bzero(ts, sizeof(struct tcpstate));
	ts->state = TCPS_CLOSED;
	ats->suit.tcps = ts;

#ifdef NATPT_NAT
	if (local->sa_family == AF_INET)
		hvl = natpt_hashPad4(local);
	else
#endif
		hvl = natpt_hashPad6(local);

	thl = &tslhashl[hvl];
	hvr = natpt_hashPad4(remote);
	thr = &tslhashr[hvr];

	s = splnet();
	thl->curlen++;
	thl->maxlen = max(thl->maxlen, thl->curlen);
	thr->curlen++;
	thr->maxlen = max(thr->maxlen, thr->curlen);

	TAILQ_INSERT_TAIL(&tsl_head, ats, tsl_list);
	TAILQ_INSERT_TAIL(&thl->tslhead, ats, tsl_hashl);
	TAILQ_INSERT_TAIL(&thr->tslhead, ats, tsl_hashr);
	splx(s);

	return (ats);
}


struct tSlot *
natpt_checkICMP(struct pcv *cv4)
{
	int			 hvr;
	struct ip		*icmpip4;
	struct udphdr		*icmpudp4 = NULL;
	struct sockaddr_in	 src, dst;
	struct tslhash		*thr;
	struct tSlot		*ats;

	if ((cv4->ip_p != IPPROTO_ICMP)
	    || ((cv4->pyld.icmp4->icmp_type != ICMP_UNREACH)
		&& (cv4->pyld.icmp4->icmp_type != ICMP_TIMXCEED)))
		return (NULL);

	bzero(&src, sizeof(struct sockaddr_in));
	bzero(&dst, sizeof(struct sockaddr_in));
	icmpip4 = &cv4->pyld.icmp4->icmp_ip;
	src.sin_addr = icmpip4->ip_src;
	dst.sin_addr = icmpip4->ip_dst;

	if ((icmpip4->ip_p == IPPROTO_UDP)
	    || (icmpip4->ip_p == IPPROTO_TCP)) {
		icmpudp4 = (struct udphdr *)((caddr_t)icmpip4 + (icmpip4->ip_hl << 2));

		src.sin_port = icmpudp4->uh_sport;
		dst.sin_port = icmpudp4->uh_dport;
	}

	hvr = ((natpt_hashSin4(&src) + natpt_hashSin4(&dst)) % NATPTHASHSZ);
	thr = &tslhashr[hvr];

	for (ats = TAILQ_FIRST(&thr->tslhead);
	     ats;
	     ats = TAILQ_NEXT(ats, tsl_hashr)) {

		struct pAddr	*pad;

		pad = &ats->remote;

		if (pad->sa_family != AF_INET)
			continue;
		if (icmpip4->ip_src.s_addr != pad->in4dst.s_addr)
			continue;
		if (icmpip4->ip_dst.s_addr != pad->in4src.s_addr)
			continue;

		if (icmpudp4) {
			if (icmpudp4->uh_sport != pad->port[1])
				continue;
			if (icmpudp4->uh_dport != pad->port[0])
				continue;
		}

		return (ats);
	}

	return (NULL);
}


struct pAddr *
natpt_remapRemote4Port(struct cSlot *acs, struct pAddr *remote)
{
	u_short		 cport, sport, eport;
	int		 firsttime = 0;
	int		 hvr;
	struct tslhash	*thr;
	struct pAddr	 pad;

	/*
	 * In case mapping port number,
	 * acs->remote.port[0..1] has source port mapping range (from command line).
	 *     remote->port[0..1] has actual translation slot info.
	 */

	cport = acs->cport;
	sport = ntohs(acs->Remote.port[0]);
	eport = ntohs(acs->Remote.port[1]);

	if (cport == 0)
		cport = sport - 1;

	bzero(&pad, sizeof(struct pAddr));
	pad.sa_family = AF_INET;
	pad.in4src = remote->in4src;
	pad.in4dst = remote->in4dst;
	pad.port[0] = remote->port[0];

	for (;;) {
		while (++cport <= eport) {
			pad.port[1] = htons(cport);
			hvr = natpt_hashPad4(&pad);
			thr = &tslhashr[hvr];
			if (TAILQ_EMPTY(&thr->tslhead)) {
				acs->cport = cport;
				remote->port[1] = htons(cport);
				return (remote);
			}
		}

		if (firsttime == 0)
			firsttime++,
				cport = sport - 1;
		else
			return (NULL);
	}

	return (NULL);					/* make gcc happy */
}


/*
 *
 */

struct fragment *
natpt_internFragment6(struct pcv *cv6)
{
	int			 s;
	struct fragment		*frg;
	struct timeval		 atv;

	MALLOC(frg, struct fragment *, sizeof(struct fragment), M_NATPT, M_NOWAIT);
	if (frg == NULL) {
		return (NULL);
	}

	bzero(frg, sizeof(struct fragment));
	frg->fg_proto = cv6->ip_p;
	frg->fg_family = AF_INET6;
	frg->fg_src.in6 = cv6->ip.ip6->ip6_src;
	frg->fg_dst.in6 = cv6->ip.ip6->ip6_dst;
	microtime(&atv);
	frg->tstamp = atv.tv_sec;

	s = splnet();
	TAILQ_INSERT_TAIL(&frg_head, frg, frg_list);
	splx(s);

	return (frg);
}


struct fragment *
natpt_internFragment4(struct pcv *cv4)
{
	int			 s;
	struct fragment		*frg;
	struct timeval		 atv;

	MALLOC(frg, struct fragment *, sizeof(struct fragment), M_NATPT, M_NOWAIT);
	if (frg == NULL) {
		return (NULL);
	}

	bzero(frg, sizeof(struct fragment));
	frg->fg_family = AF_INET;
	frg->fg_proto = cv4->ip_p;
	frg->fg_id = cv4->ip.ip4->ip_id;
	frg->fg_src.in4 = cv4->ip.ip4->ip_src;
	frg->fg_dst.in4 = cv4->ip.ip4->ip_dst;
	microtime(&atv);
	frg->tstamp = atv.tv_sec;

	s = splnet();
	TAILQ_INSERT_TAIL(&frg_head, frg, frg_list);
	splx(s);

	return (frg);
}


struct tSlot *
natpt_lookForFragment6(struct pcv *cv6)
{
	struct fragment		 *frg;

	for (frg = TAILQ_FIRST(&frg_head);
	     frg;
	     frg = TAILQ_NEXT(frg, frg_list)) {
		if (frg->fg_family != AF_INET6)
			continue;
		if (cv6->ip_p != frg->fg_proto)
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&frg->fg_src.in6, &cv6->ip.ip6->ip6_src))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&frg->fg_dst.in6, &cv6->ip.ip6->ip6_dst))
			continue;
		return (frg->tslot);
	}

	return (NULL);
}


struct tSlot *
natpt_lookForFragment4(struct pcv *cv4)
{
	struct fragment		 *frg;

	for (frg = TAILQ_FIRST(&frg_head);
	     frg;
	     frg = TAILQ_NEXT(frg, frg_list)) {
		if (frg->fg_family != AF_INET)
			continue;
		if (cv4->ip_p != frg->fg_proto)
			continue;
		if (frg->fg_id != cv4->ip.ip4->ip_id)
			continue;
		if (frg->fg_src.in4.s_addr != cv4->ip.ip4->ip_src.s_addr)
			continue;
		if (frg->fg_dst.in4.s_addr != cv4->ip.ip4->ip_dst.s_addr)
			continue;
		return (frg->tslot);
	}

	return (NULL);
}


static void
natpt_expireFragment(void *ignored_arg)
{
	struct timeval	 atv;
	struct fragment	*frg, *frgn;

	timeout(natpt_expireFragment, (caddr_t)0, frgmntTimer);
	microtime(&atv);

	frg = TAILQ_FIRST(&frg_head);
	while (frg) {
		frgn = TAILQ_NEXT(frg, frg_list);
		if ((atv.tv_sec - frg->tstamp) >= maxFragment) {
			int	 s;

			s = splnet();
			TAILQ_REMOVE(&frg_head, frg, frg_list);
			splx(s);
			FREE(frg, M_NATPT);
		}
		frg = frgn;
	}

}


/*
 *
 */

struct tSlot *
natpt_lookForHash(struct pcv *cv, struct tslhash *th, int side)
{
	struct ip6_hdr	*ip6;
	struct ip	*ip4;
	struct pAddr	*pad;
	struct tSlot	*ats;

	ats = TAILQ_FIRST(&th->tslhead);
	while (ats) {
		if (side == NATPT_FROM) {
			if (cv->sa_family != ats->local.sa_family)
				goto next;
			pad = &ats->local;
		} else {
			if (cv->sa_family != ats->remote.sa_family)
				goto next;
			pad = &ats->remote;
		}

		if (cv->sa_family == AF_INET6) {
			ip6 = cv->ip.ip6;
			if (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &pad->in6src)
			    || !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &pad->in6dst))
				goto next;
			if ((cv->ip_p == IPPROTO_TCP)
			    || (cv->ip_p == IPPROTO_UDP)) {
				if (cv->pyld.tcp6->th_sport != pad->port[0])
					goto next;
				if (cv->pyld.tcp6->th_dport != pad->port[1])
					goto next;
			}
		} else {
			ip4 = cv->ip.ip4;
			if ((ip4->ip_src.s_addr != pad->in4src.s_addr)
			    || (ip4->ip_dst.s_addr != pad->in4dst.s_addr))
				goto next;
			if ((cv->ip_p == IPPROTO_TCP)
			    || (cv->ip_p == IPPROTO_UDP)) {
				if (cv->pyld.tcp6->th_sport != pad->port[0])
					goto next;
				if (cv->pyld.tcp6->th_dport != pad->port[1])
					goto next;
			}
		}

		cv->fromto = side;
		return (ats);

	next:;
		if (side == NATPT_FROM)
			ats = TAILQ_NEXT(ats, tsl_hashl);
		else
			ats = TAILQ_NEXT(ats, tsl_hashr);
	}

	return (NULL);
}


static int
natpt_hash6(struct pcv *cv)
{
	struct ip6_hdr		*ip6;
	struct sockaddr_in6	 src, dst;

	bzero(&src, sizeof(struct sockaddr_in6));
	bzero(&dst, sizeof(struct sockaddr_in6));

	ip6 = cv->ip.ip6;
	src.sin6_addr = ip6->ip6_src;
	dst.sin6_addr = ip6->ip6_dst;

	if ((cv->ip_p == IPPROTO_TCP) || (cv->ip_p == IPPROTO_UDP)) {
		struct tcp6hdr	*tcp6 = cv->pyld.tcp6;

		src.sin6_port = tcp6->th_sport;
		dst.sin6_port = tcp6->th_dport;
	}

	return ((natpt_hashSin6(&src) + natpt_hashSin6(&dst)) %	NATPTHASHSZ);
}


static int
natpt_hash4(struct pcv *cv)
{
	struct ip		*ip;
	struct sockaddr_in	 src, dst;

	bzero(&src, sizeof(struct sockaddr_in));
	bzero(&dst, sizeof(struct sockaddr_in));

	ip = cv->ip.ip4;
	src.sin_addr = ip->ip_src;
	dst.sin_addr = ip->ip_dst;

	if ((ip->ip_p == IPPROTO_TCP) || (ip->ip_p == IPPROTO_UDP)) {
		struct tcphdr	*tcp = cv->pyld.tcp4;

		src.sin_port = tcp->th_sport;
		dst.sin_port = tcp->th_dport;
	}

	return ((natpt_hashSin4(&src) + natpt_hashSin4(&dst)) % NATPTHASHSZ);
}


static int
natpt_hashPad6(struct pAddr *pad6)
{
	struct sockaddr_in6	src, dst;

	bzero(&src, sizeof(struct sockaddr_in6));
	bzero(&dst, sizeof(struct sockaddr_in6));

	src.sin6_port = pad6->port[0];
	src.sin6_addr = pad6->in6src;
	dst.sin6_port = pad6->port[1];
	dst.sin6_addr = pad6->in6dst;

	return ((natpt_hashSin6(&src) + natpt_hashSin6(&dst)) % NATPTHASHSZ);
}


static int
natpt_hashPad4(struct pAddr *pad4)
{
	struct sockaddr_in	src, dst;

	bzero(&src, sizeof(struct sockaddr_in));
	bzero(&dst, sizeof(struct sockaddr_in));

	src.sin_port = pad4->port[0];
	src.sin_addr = pad4->in4src;
	dst.sin_port = pad4->port[1];
	dst.sin_addr = pad4->in4dst;

	return ((natpt_hashSin4(&src) + natpt_hashSin4(&dst)) % NATPTHASHSZ);
}


static int
natpt_hashSin6(struct sockaddr_in6 *sin6)
{
	int	byte;

	sin6->sin6_flowinfo = 0;
	byte = sizeof(sin6->sin6_port)
		+ sizeof(sin6->sin6_flowinfo)
		+ sizeof(sin6->sin6_addr);
	return (natpt_hashPJW((char *)&sin6->sin6_port, byte));
}


static int
natpt_hashSin4(struct sockaddr_in *sin4)
{
	int	byte;

	byte = sizeof(sin4->sin_port) + sizeof(sin4->sin_addr);
	return (natpt_hashPJW((char *)&sin4->sin_port, byte));
}


/*	CAUTION								*/
/*	This hash routine is byte order sensitive.  Be Careful.		*/

static int
natpt_hashPJW(u_char *s, int len)
{
	u_int	c;
	u_int	h, g;

	for (c = h = g = 0; c < len; c++, s++) {
		h = (h << 4) + (*s);
		if ((g = h & 0xf0000000)) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h % NATPTHASHSZ);
}


/*
 *
 */

static void
natpt_expireTSlot(void *ignored_arg)
{
	struct timeval	 atv;
	struct tSlot	*tsl, *tsln;

	timeout(natpt_expireTSlot, (caddr_t)0, tSlotTimer);
	microtime(&atv);

	tsl = TAILQ_FIRST(&tsl_head);
	while (tsl) {
		tsln = TAILQ_NEXT(tsl, tsl_list);
		switch (tsl->ip_p) {
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			if ((atv.tv_sec - tsl->tstamp) >= maxTTLicmp)
				natpt_removeTSlotEntry(tsl);
			break;

		case IPPROTO_UDP:
			if ((atv.tv_sec - tsl->tstamp) >= maxTTLudp)
				natpt_removeTSlotEntry(tsl);
			break;

		case IPPROTO_TCP:
			switch (tsl->suit.tcps->state) {
			case TCPS_CLOSED:
				if ((atv.tv_sec - tsl->tstamp) >= natpt_TCPT_2MSL)
					natpt_removeTSlotEntry(tsl);
				break;

			case TCPS_SYN_SENT:
			case TCPS_SYN_RECEIVED:
				if ((atv.tv_sec - tsl->tstamp) >= natpt_tcp_maxidle)
					natpt_removeTSlotEntry(tsl);
				break;

			case TCPS_ESTABLISHED:
				if ((atv.tv_sec - tsl->tstamp) >= maxTTLtcp)
					natpt_removeTSlotEntry(tsl);
				break;

			case TCPS_FIN_WAIT_1:
			case TCPS_FIN_WAIT_2:
				if ((atv.tv_sec - tsl->tstamp) >= natpt_tcp_maxidle)
					natpt_removeTSlotEntry(tsl);
				break;

			case TCPS_TIME_WAIT:
				if ((atv.tv_sec - tsl->tstamp) >= natpt_TCPT_2MSL)
					natpt_removeTSlotEntry(tsl);
				break;

			default:
				if ((atv.tv_sec - tsl->tstamp) >= maxTTLtcp)
					natpt_removeTSlotEntry(tsl);
				break;
			}
			break;

		default:
			if ((atv.tv_sec - tsl->tstamp) >= maxTTLany)
				natpt_removeTSlotEntry(tsl);
		}

		tsl = tsln;
	}
}


static void
natpt_removeTSlotEntry(struct tSlot *ats)
{
	int	s;

	if ((ats->ip_p == IPPROTO_TCP)
	    && (ats->suit.tcps != NULL))
		FREE(ats->suit.tcps, M_NATPT);

	s = splnet();
	TAILQ_REMOVE(&tsl_head, ats, tsl_list);
	TAILQ_REMOVE(&tslhashl[ats->hvl].tslhead, ats, tsl_hashl);
	TAILQ_REMOVE(&tslhashr[ats->hvr].tslhead, ats, tsl_hashr);
	splx(s);

	FREE(ats, M_NATPT);
}


/*
 *
 */

void
natpt_init_tslot()
{
	int		iter;

	tSlotEntry = NULL;
	tSlotEntryMax = MAXTSLOTENTRY;
	tSlotEntryUsed = 0;

	tSlotTimer = 60 * hz;
	frgmntTimer = 60 * hz;
	timeout(natpt_expireTSlot, (caddr_t)0, tSlotTimer);
	timeout(natpt_expireFragment, (caddr_t)0, frgmntTimer);

	maxFragment = 120;				/* [sec]	*/

	natpt_TCPT_2MSL	  = 120;			/* [sec]	*/
	natpt_tcp_maxidle = 600;			/* [sec]	*/

	maxTTLicmp = maxTTLudp = natpt_TCPT_2MSL;
	maxTTLtcp  = maxTTLany = 86400;			/* [sec]	*/

	TAILQ_INIT(&frg_head);
	TAILQ_INIT(&tsl_head);
	for (iter = 0; iter < NATPTHASHSZ; iter++) {
		TAILQ_INIT(&tslhashl[iter].tslhead);
		TAILQ_INIT(&tslhashr[iter].tslhead);
	}
}
