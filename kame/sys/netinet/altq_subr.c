/*
 * Copyright (C) 1997-1999
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: altq_subr.c,v 1.1 1999/08/05 17:18:21 itojun Exp $
 */

#ifdef ALTQ
#ifndef _NO_OPT_ALTQ_H_
#include "opt_altq.h"
#if !defined(__FreeBSD__) || (__FreeBSD__ > 2)
#include "opt_inet.h"
#endif
#endif /* !_NO_OPT_ALTQ_H_ */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <vm/vm.h>
#include <sys/sysctl.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <net/altq_conf.h>
#include <netinet/altq.h>

/*
 * internal function prototypes
 */
static int 	extract_ports4 __P((struct mbuf *, struct ip *,
				    struct flowinfo_in *));
#ifdef INET6
static int 	extract_ports6 __P((struct mbuf *, struct ip6_hdr *,
				    struct flowinfo_in6 *));
#endif
static int	apply_filter4 __P((u_int32_t, struct flow_filter *,
				   struct flowinfo_in *));
static int	apply_ppfilter4 __P((u_int32_t, struct flow_filter *,
				     struct flowinfo_in *));
#ifdef INET6
static int	apply_filter6 __P((u_int32_t, struct flow_filter6 *,
					   struct flowinfo_in6 *));
#endif
#ifdef CBQ_RIO
static int	apply_tosfilter4 __P((u_int32_t, struct flow_filter *,
					     struct flowinfo_in *));
#endif
static u_long	get_filt_handle __P((struct acc_classifier *, int));
static struct acc_filter *filth_to_filtp __P((struct acc_classifier *,
					      u_long));
static u_int32_t filt2fibmask __P((struct flow_filter *));

static void 	ip4f_cache __P((struct ip *, struct flowinfo_in *));
static int 	ip4f_lookup __P((struct ip *, struct flowinfo_in *));
static int 	ip4f_init __P((void));
static struct ip4_frag	*ip4f_alloc __P((void));
static void 	ip4f_free __P((struct ip4_frag *));

/*
 * alternate queueing support routines
 */
/* look up the queue state by the interface name and the queuing type. */
void *
altq_lookup(name, type)
	char *name;
	int type;
{
	struct ifnet *ifp;

	if ((ifp = ifunit(name))) {
		if (type != ALTQT_NONE && ifp->if_altqtype != type)
			return NULL;
		return (void *)ifp->if_altqp;
	}

	return NULL;
}

int
if_altqattach(ifp, queue_state, enqueue, dequeue, type)
	struct ifnet *ifp;
	void *queue_state;
	int (*enqueue)(struct ifnet *, struct mbuf *, struct pr_hdr *, int);
	struct mbuf *(*dequeue)(struct ifnet *, int);
{
	if (!ALTQ_IS_READY(ifp))
		return ENXIO;
	if (ALTQ_IS_ON(ifp))
		return EBUSY;
	if (ifp->if_altqp != NULL)
		return EEXIST;
	ifp->if_altqp = queue_state;
	ifp->if_altqenqueue = enqueue;
	ifp->if_altqdequeue = dequeue;
	ifp->if_altqflags &= ALTQF_CANTCHANGE;
	ifp->if_altqtype = type;
#ifdef ALTQ_KLD
	altq_module_incref(type);
#endif
	return 0;
}

int
if_altqdetach(ifp)
	struct ifnet *ifp;
{
	if (!ALTQ_IS_READY(ifp))
		return ENXIO;
	if (ALTQ_IS_ON(ifp))
		return EBUSY;

#ifdef ALTQ_KLD
	altq_module_declref(ifp->if_altqtype);
#endif
	ifp->if_altqp = NULL;
	ifp->if_altqenqueue = NULL;
	ifp->if_altqdequeue = NULL;
	ifp->if_altqflags &= ALTQF_CANTCHANGE;
	ifp->if_altqtype = ALTQT_NONE;
	return 0;
}

int
if_altqenable(ifp)
	struct ifnet *ifp;
{
	struct mbuf *m;
	int s;
    
	if (!ALTQ_IS_READY(ifp))
		return ENXIO;
	if (ALTQ_IS_ON(ifp))
		return 0;

	s = splimp();
	do {
		IF_DEQUEUE(&ifp->if_snd, m);
		if (m)
			m_freem(m);
	} while (m);

	ifp->if_altqflags |= ALTQF_ENABLE;
	splx(s);

	return 0;
}

int
if_altqdisable(ifp)
	struct ifnet *ifp;
{
	int s;
    
	if (!ALTQ_IS_ON(ifp))
		return 0;

	s = splimp();
	(void)(*ifp->if_altqdequeue)(ifp, ALTDQ_FLUSH);
	ifp->if_altqflags &= ~ALTQF_ENABLE;
	splx(s);
	return 0;
}

void
altq_assert(file, line, failedexpr)
	const char *file, *failedexpr;
	int line;
{
	(void)printf("altq assertion \"%s\" failed: file \"%s\", line %d\n",
		     failedexpr, file, line);
	panic("altq assertion");
	/* NOTREACHED */
}

#ifndef IPPROTO_ESP
#define IPPROTO_ESP	50		/* encapsulating security payload */
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH	51		/* authentication header */
#endif

/* 
 * extract flow information from a given packet.
 * pr_hdr holds a pointer to the ip header.  filt_mask shows flowinfo
 * fields required.
 * we assume the ip header is in one mbuf, and addresses and ports are
 * in network byte order.
 */
int 
altq_extractflow(m, pr_hdr, flow, filt_bmask)
	struct mbuf *m;
	struct pr_hdr *pr_hdr;
	struct flowinfo *flow;
	u_int32_t	filt_bmask;
{

	switch (pr_hdr->ph_family) {
	case PF_INET: {
		struct flowinfo_in *fin;
		struct ip *ip;

		ip = (struct ip *)pr_hdr->ph_hdr;

		if (ip->ip_v != 4)
			break;
		
		fin = (struct flowinfo_in *)flow;
		fin->fi_len = sizeof(struct flowinfo_in);
		fin->fi_family = AF_INET;

		fin->fi_proto = ip->ip_p;
		fin->fi_tos = ip->ip_tos;

		fin->fi_src.s_addr = ip->ip_src.s_addr;
		fin->fi_dst.s_addr = ip->ip_dst.s_addr;
    
		if (filt_bmask & FIMB4_PORTS)
			/* if port info is required, extract port numbers */
			extract_ports4(m, ip, fin);
		else {
			fin->fi_sport = 0;
			fin->fi_dport = 0;
			fin->fi_gpi = 0;
		}
		return (1);
	}
		
#ifdef INET6
	case PF_INET6: {
		struct flowinfo_in6 *fin6;
		struct ip6_hdr *ip6;

		ip6 = (struct ip6_hdr *)pr_hdr->ph_hdr;
		/* should we check the ip version? */
		
		fin6 = (struct flowinfo_in6 *)flow;
		fin6->fi6_len = sizeof(struct flowinfo_in6);
		fin6->fi6_family = AF_INET6;

		fin6->fi6_proto = ip6->ip6_nxt;
		fin6->fi6_tclass   = (ntohl(ip6->ip6_flow) >> 20) & 0xff;

		fin6->fi6_flowlabel = ip6->ip6_flow & htonl(0x000fffff);
		fin6->fi6_src = ip6->ip6_src;
		fin6->fi6_dst = ip6->ip6_dst;

		if ((filt_bmask & FIMB6_PORTS) ||
		    ((filt_bmask & FIMB6_PROTO)
		     && ip6->ip6_nxt > IPPROTO_IPV6))
			/*
			 * if port info is required, or proto is required
			 * but there are option headers, extract port
			 * and protocol numbers.
			 */
			extract_ports6(m, ip6, fin6);
		else {
			fin6->fi6_sport = 0;
			fin6->fi6_dport = 0;
			fin6->fi6_gpi = 0;
		}
		return (1);
	}
#endif /* INET6 */

	default:
#ifdef ALTQ_DEBUG
		printf("altq_extractflow: unknown proto family=%d\n", pr_hdr->ph_family);
#endif
		break;
	}

	/* failed */
	flow->fi_len = sizeof(struct flowinfo);
	flow->fi_family = AF_UNSPEC;
	return (0);
}

/*
 * helper routine to extract port numbers
 */
/* structure for ipsec and ipv6 option header template */
struct _opt6 {
	u_int8_t	opt6_nxt;	/* next header */
	u_int8_t	opt6_hlen;	/* header extension length */
	u_int16_t	_pad;
	u_int32_t	ah_spi;		/* security parameter index
					   for authentication header */
};

/*
 * extract port numbers from a ipv4 packet.
 */
static int
extract_ports4(m, ip, fin)
	struct mbuf *m;
	struct ip *ip;
	struct flowinfo_in *fin;
{
	struct mbuf *m0;
	u_short ip_off;
	u_int8_t proto;
	int 	off;
	
	fin->fi_sport = 0;
	fin->fi_dport = 0;
	fin->fi_gpi = 0;
	
	ip_off = ntohs(ip->ip_off);
	/* if it is a fragment, try cached fragment info */
	if (ip_off & IP_OFFMASK) {
		ip4f_lookup(ip, fin);
		return (1);
	}

	/* locate the mbuf containing the protocol header */
	for (m0 = m; m0 != NULL; m0 = m0->m_next)
		if (((caddr_t)ip >= m0->m_data) &&
		    ((caddr_t)ip < m0->m_data + m0->m_len))
			break;
	if (m0 == NULL) {
#ifdef ALTQ_DEBUG
		printf("extract_ports4: can't locate header! ip=0x%x\n", ip);
#endif
		return (0);
	}
	off = ((caddr_t)ip - m0->m_data) + (ip->ip_hl << 2);
	proto = ip->ip_p;

#ifdef ALTQ_IPSEC
 again:
#endif
	while (off >= m0->m_len) {
		off -= m0->m_len;
		m0 = m0->m_next;
	}
	ASSERT(m0->m_len >= off + 4);

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP: {
		struct udphdr *udp;
		
		udp = (struct udphdr *)(mtod(m0, caddr_t) + off);
		fin->fi_sport = udp->uh_sport;
		fin->fi_dport = udp->uh_dport;
		fin->fi_proto = proto;
		}
		break;

#ifdef ALTQ_IPSEC
	case IPPROTO_ESP:
		if (fin->fi_gpi == 0){
			u_int32_t *gpi;
			
			gpi = (u_int32_t *)(mtod(m0, caddr_t) + off);
			fin->fi_gpi   = *gpi;
		}
		fin->fi_proto = proto;
		break;

	case IPPROTO_AH: {
			/* get next header and header length */
			struct _opt6 *opt6;

			opt6 = (struct _opt6 *)(mtod(m0, caddr_t) + off);
			proto = opt6->opt6_nxt;
			off += 8 + (opt6->opt6_hlen * 4);
			if (fin->fi_gpi == 0)
				fin->fi_gpi = opt6->ah_spi;
		}
		/* goto the next header */
		goto again;
#endif  /* ALTQ_IPSEC */

	default:
		fin->fi_proto = proto;
		return (0);
	}

	/* if this is a first fragment, cache it. */
	if (ip_off & IP_MF)
		ip4f_cache(ip, fin);

	return (1);
}

#ifdef INET6
static int
extract_ports6(m, ip6, fin6)
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct flowinfo_in6 *fin6;
{
	struct mbuf *m0;
	int	off;
	u_int8_t proto;
	
	fin6->fi6_gpi   = 0;
	fin6->fi6_sport = 0;
	fin6->fi6_dport = 0;
	
	/* locate the mbuf containing the protocol header */
	for (m0 = m; m0 != NULL; m0 = m0->m_next)
		if (((caddr_t)ip6 >= m0->m_data) &&
		    ((caddr_t)ip6 < m0->m_data + m0->m_len))
			break;
	if (m0 == NULL) {
#ifdef ALTQ_DEBUG
		printf("extract_ports6: can't locate header! ip6=0x%x\n", ip6);
#endif
		return (0);
	}
	off = ((caddr_t)ip6 - m0->m_data) + sizeof(struct ip6_hdr);

	proto = ip6->ip6_nxt;
	do {
		while (off >= m0->m_len) {
			off -= m0->m_len;
			m0 = m0->m_next;
		}
		ASSERT(m0->m_len >= off + 4);

		switch (proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP: {
			struct udphdr *udp;
			
			udp = (struct udphdr *)(mtod(m0, caddr_t) + off);
			fin6->fi6_sport = udp->uh_sport;
			fin6->fi6_dport = udp->uh_dport;
			fin6->fi6_proto = proto;
			}
			return (1);
			
		case IPPROTO_ESP:
			if (fin6->fi6_gpi == 0) {
				u_int32_t *gpi;
			
				gpi = (u_int32_t *)(mtod(m0, caddr_t) + off);
				fin6->fi6_gpi   = *gpi;
			}
			fin6->fi6_proto = proto;
			return (1);

		case IPPROTO_AH: {
			/* get next header and header length */
			struct _opt6 *opt6;

			opt6 = (struct _opt6 *)(mtod(m0, caddr_t) + off);
			if (fin6->fi6_gpi == 0)
				fin6->fi6_gpi = opt6->ah_spi;
			proto = opt6->opt6_nxt;
			off += 8 + (opt6->opt6_hlen * 4);
			/* goto the next header */
			break;
			}

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS: {
			/* get next header and header length */
			struct _opt6 *opt6;

			opt6 = (struct _opt6 *)(mtod(m0, caddr_t) + off);
			proto = opt6->opt6_nxt;
			off += (opt6->opt6_hlen + 1) * 8;
			/* goto the next header */
			break;
			}
				
		case IPPROTO_FRAGMENT:
			/* ipv6 fragmentations are not supported yet */
		default:
			fin6->fi6_proto = proto;
			return (0);
		}
	} while (1);
	/*NOTREACHED*/
}
#endif /* INET6 */

/*
 * altq common classifier
 */
int acc_add_filter(classifier, filter, class, phandle)
	struct acc_classifier *classifier;
	struct flow_filter *filter;
	void	*class;
	u_long	*phandle;
{
	struct acc_filter *afp;
	int	i, s;

#ifdef INET6
	if (filter->ff_flow.fi_family != AF_INET &&
	    filter->ff_flow.fi_family != AF_INET6)
		return (EINVAL);
#else
	if (filter->ff_flow.fi_family != AF_INET)
		return (EINVAL);
#endif
		
	MALLOC(afp, struct acc_filter *, sizeof(struct acc_filter),
	       M_DEVBUF, M_WAITOK);
	if (afp == NULL)
		return (ENOMEM);
	bzero(afp, sizeof(struct acc_filter));

	afp->f_filter = *filter;
	afp->f_class = class;

	i = ACC_WILDCARD_INDEX;
	if (filter->ff_flow.fi_family == AF_INET) {
		struct flow_filter *filter4 = &afp->f_filter;
		
		/*
		 * if address is 0, it's a wildcard.  if address mask
		 * isn't set, use full mask.
		 */
		if (filter4->ff_flow.fi_dst.s_addr == 0)
			filter4->ff_mask.mask_dst.s_addr = 0;
		else if (filter4->ff_mask.mask_dst.s_addr == 0)
			filter4->ff_mask.mask_dst.s_addr = 0xffffffff;
		if (filter4->ff_flow.fi_src.s_addr == 0)
			filter4->ff_mask.mask_src.s_addr = 0;
		else if (filter4->ff_mask.mask_src.s_addr == 0)
			filter4->ff_mask.mask_src.s_addr = 0xffffffff;

		/*
		 * if dst address is a wildcard, use hash-entry
		 * ACC_WILDCARD_INDEX.
		 */
		if (filter4->ff_mask.mask_dst.s_addr != 0xffffffff)
			i = ACC_WILDCARD_INDEX;
		else
			i = ACC_GET_HASH_INDEX(filter4->ff_flow.fi_dst.s_addr);
	}
#ifdef INET6
	else if (filter->ff_flow.fi_family == AF_INET6) {
		struct flow_filter6 *filter6 =
			(struct flow_filter6 *)&afp->f_filter;
#ifndef IN6MASK0 /* taken from kame ipv6 */
#define IN6MASK0	{{{ 0, 0, 0, 0 }}}
#define IN6MASK128	{{{ 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff }}}
		const struct in6_addr in6mask0 = IN6MASK0;
		const struct in6_addr in6mask128 = IN6MASK128;
#endif

		if (IN6_IS_ADDR_UNSPECIFIED(&filter6->ff_flow6.fi6_dst))
			filter6->ff_mask6.mask6_dst = in6mask0;
		else if (IN6_IS_ADDR_UNSPECIFIED(&filter6->ff_mask6.mask6_dst))
			filter6->ff_mask6.mask6_dst = in6mask128;
		if (IN6_IS_ADDR_UNSPECIFIED(&filter6->ff_flow6.fi6_src))
			filter6->ff_mask6.mask6_src = in6mask0;
		else if (IN6_IS_ADDR_UNSPECIFIED(&filter6->ff_mask6.mask6_src))
			filter6->ff_mask6.mask6_src = in6mask128;
		
		if (filter6->ff_flow6.fi6_flowlabel == 0)
			i = ACC_WILDCARD_INDEX;
		else
			i = ACC_GET_HASH_INDEX(filter6->ff_flow6.fi6_flowlabel);
	}
#endif /* INET6 */

	afp->f_handle = get_filt_handle(classifier, i);

	/* update filter bitmask */
	afp->f_fbmask = filt2fibmask(filter);
	classifier->acc_fbmask |= afp->f_fbmask;

	/* add the filter to the head of the filter list. */
	s = splimp();
	LIST_INSERT_HEAD(&classifier->acc_filters[i], afp, f_chain);
	splx(s);

	*phandle = afp->f_handle;
	return (0);
}

int acc_delete_filter(classifier, handle)
	struct acc_classifier *classifier;
	u_long handle;
{
	struct acc_filter *afp;
	int	s;

	if ((afp = filth_to_filtp(classifier, handle)) == NULL)
		return (EINVAL);

	s = splimp();
	LIST_REMOVE(afp, f_chain);
	splx(s);

	FREE(afp, M_DEVBUF);

	/* todo: update filt_bmask */

	return (0);
}

/*
 * delete filters referencing to the specified class.
 * if the all flag is not 0, delete all the filters.
 */
int acc_discard_filters(classifier, class, all)
	struct acc_classifier *classifier;
	void	*class;
	int	all;
{
	struct acc_filter *afp;
	int	i, s;

	s = splimp();
	for (i = 0; i < ACC_FILTER_TABLESIZE; i++) {
		do {
			LIST_FOREACH(afp, &classifier->acc_filters[i], f_chain)
				if (all || afp->f_class == class) {
					LIST_REMOVE(afp, f_chain);
					FREE(afp, M_DEVBUF);
					/* start again from the head */
					break;
				}
		} while (afp != NULL);
	}
	splx(s);

	if (all)
		classifier->acc_fbmask = 0;

	return (0);
}

void *acc_classify(classifier, flowinfo)
	struct acc_classifier *classifier;
	struct flowinfo *flowinfo;
{
	struct acc_filter *afp;
	int	i;

	if (flowinfo->fi_family == AF_INET) {
		/* currently only AF_INET is supported */
		struct flowinfo_in *fp = (struct flowinfo_in *)flowinfo;
	
#ifdef CBQ_RIO
		if ((classifier->acc_fbmask & FIMB4_ALL) == FIMB4_TOS) {
			/* only tos is used */
			LIST_FOREACH(afp,
				 &classifier->acc_filters[ACC_WILDCARD_INDEX],
				 f_chain)
				if (apply_tosfilter4(afp->f_fbmask,
						     &afp->f_filter, fp))
					/* filter matched */
					return (afp->f_class);
		}
		else
#endif 		
		if ((classifier->acc_fbmask &
		     (~(FIMB4_PROTO|FIMB4_SPORT|FIMB4_DPORT) & FIMB4_ALL))
		    == 0) {
			/* only proto and ports are used */
			LIST_FOREACH(afp,
				 &classifier->acc_filters[ACC_WILDCARD_INDEX],
				 f_chain)
				if (apply_ppfilter4(afp->f_fbmask,
						    &afp->f_filter, fp))
					/* filter matched */
					return (afp->f_class);
		}
		else {
			/* get the filter hash entry from its dest address */
			i = ACC_GET_HASH_INDEX(fp->fi_dst.s_addr);
			do {
				/*
				 * go through this loop twice.  first for dst
				 * hash, second for wildcards.
				 */
				LIST_FOREACH(afp, &classifier->acc_filters[i],
					     f_chain)
					if (apply_filter4(afp->f_fbmask,
							  &afp->f_filter, fp))
						/* filter matched */
						return (afp->f_class);
				
				/*
				 * check again for filters with a dst addr
				 * wildcard.
				 * (daddr == 0 || dmask != 0xffffffff).
				 */
				if (i != ACC_WILDCARD_INDEX)
					i = ACC_WILDCARD_INDEX;
				else
					break;
			} while (1);
		}
	}
#ifdef INET6
	else if (flowinfo->fi_family == AF_INET6) {
		struct flowinfo_in6 *fp6 = (struct flowinfo_in6 *)flowinfo;
	
		/* get the filter hash entry from its flow ID */
		if (fp6->fi6_flowlabel != 0)
			i = ACC_GET_HASH_INDEX(fp6->fi6_flowlabel);
		else
			/* flowlable can be zero */
			i = ACC_WILDCARD_INDEX;

		/* go through this loop twice.  first for flow hash, second
		   for wildcards. */
		do {
			LIST_FOREACH(afp, &classifier->acc_filters[i], f_chain)
				if (apply_filter6(afp->f_fbmask,
					(struct flow_filter6 *)&afp->f_filter,
					fp6))
					/* filter matched */
					return (afp->f_class);

			/*
			 * check again for filters with a wildcard.
			 */
			if (i != ACC_WILDCARD_INDEX)
				i = ACC_WILDCARD_INDEX;
			else
				break;
		} while (1);
	}
#endif /* INET6 */

	/* no filter matched */
	return (NULL);
}

static int
apply_filter4(fbmask, filt, pkt)
	u_int32_t	fbmask;
	struct flow_filter *filt;
	struct flowinfo_in *pkt;
{
	if (filt->ff_flow.fi_family != AF_INET)
		return (0);
	if ((fbmask & FIMB4_SPORT) && filt->ff_flow.fi_sport != pkt->fi_sport)
		return (0);
	if ((fbmask & FIMB4_DPORT) && filt->ff_flow.fi_dport != pkt->fi_dport)
		return (0);
	if ((fbmask & FIMB4_DADDR) &&
	    filt->ff_flow.fi_dst.s_addr !=
	    (pkt->fi_dst.s_addr & filt->ff_mask.mask_dst.s_addr))
		return (0);
	if ((fbmask & FIMB4_SADDR) &&
	    filt->ff_flow.fi_src.s_addr !=
	    (pkt->fi_src.s_addr & filt->ff_mask.mask_src.s_addr))
		return (0);
	if ((fbmask & FIMB4_PROTO) && filt->ff_flow.fi_proto != pkt->fi_proto)
		return (0);
	if ((fbmask & FIMB4_TOS) && filt->ff_flow.fi_tos !=
	    (pkt->fi_tos & filt->ff_mask.mask_tos))
		return (0);
	if ((fbmask & FIMB4_GPI) && filt->ff_flow.fi_gpi != (pkt->fi_gpi))
		return (0);
	/* match */
	return (1);
}

/*
 * filter matching function optimized for a common case that checks
 * only protocol and port numbers
 */
static int
apply_ppfilter4(fbmask, filt, pkt)
	u_int32_t	fbmask;
	struct flow_filter *filt;
	struct flowinfo_in *pkt;
{
	if (filt->ff_flow.fi_family != AF_INET)
		return (0);
	if ((fbmask & FIMB4_SPORT) && filt->ff_flow.fi_sport != pkt->fi_sport)
		return (0);
	if ((fbmask & FIMB4_DPORT) && filt->ff_flow.fi_dport != pkt->fi_dport)
		return (0);
	if ((fbmask & FIMB4_PROTO) && filt->ff_flow.fi_proto != pkt->fi_proto)
		return (0);
	/* match */
	return (1);
}

#ifdef CBQ_RIO
/*
 * filter matching function only for tos field.
 */
static int
apply_tosfilter4(fbmask, filt, pkt)
	u_int32_t	fbmask;
	struct flow_filter *filt;
	struct flowinfo_in *pkt;
{
	if (filt->ff_flow.fi_family != AF_INET)
		return (0);
	if ((fbmask & FIMB4_TOS) && filt->ff_flow.fi_tos !=
	    (pkt->fi_tos & filt->ff_mask.mask_tos))
		return (0);
	/* match */
	return (1);
}
#endif /* CBQ_RIO */

#ifdef INET6
static int
apply_filter6(fbmask, filt, pkt)
	u_int32_t	fbmask;
	struct flow_filter6 *filt;
	struct flowinfo_in6 *pkt;
{
	if (filt->ff_flow6.fi6_family != AF_INET6)
		return (0);
	if ((fbmask & FIMB6_FLABEL) &&
	    filt->ff_flow6.fi6_flowlabel != pkt->fi6_flowlabel)
		return (0);
	if ((fbmask & FIMB6_PROTO) &&
	    filt->ff_flow6.fi6_proto != pkt->fi6_proto)
		return (0);
	if ((fbmask & FIMB6_SPORT) &&
	    filt->ff_flow6.fi6_sport != pkt->fi6_sport)
		return (0);
	if ((fbmask & FIMB6_DPORT) &&
	    filt->ff_flow6.fi6_dport != pkt->fi6_dport)
		return (0);
	if (fbmask & FIMB6_SADDR) {
		if (filt->ff_flow6.fi6_src.s6_addr32[0] !=
		    (pkt->fi6_src.s6_addr32[0] &
		     filt->ff_mask6.mask6_src.s6_addr32[0]))
			return (0);
		if (filt->ff_flow6.fi6_src.s6_addr32[1] !=
		    (pkt->fi6_src.s6_addr32[1] &
		     filt->ff_mask6.mask6_src.s6_addr32[1]))
			return (0);
		if (filt->ff_flow6.fi6_src.s6_addr32[2] !=
		    (pkt->fi6_src.s6_addr32[2] &
		     filt->ff_mask6.mask6_src.s6_addr32[2]))
			return (0);
		if (filt->ff_flow6.fi6_src.s6_addr32[3] !=
		    (pkt->fi6_src.s6_addr32[3] &
		     filt->ff_mask6.mask6_src.s6_addr32[3]))
			return (0);
	}
	if (fbmask & FIMB6_DADDR) {
		if (filt->ff_flow6.fi6_dst.s6_addr32[0] !=
		    (pkt->fi6_dst.s6_addr32[0] &
		     filt->ff_mask6.mask6_dst.s6_addr32[0]))
			return (0);
		if (filt->ff_flow6.fi6_dst.s6_addr32[1] !=
		    (pkt->fi6_dst.s6_addr32[1] &
		     filt->ff_mask6.mask6_dst.s6_addr32[1]))
			return (0);
		if (filt->ff_flow6.fi6_dst.s6_addr32[2] !=
		    (pkt->fi6_dst.s6_addr32[2] &
		     filt->ff_mask6.mask6_dst.s6_addr32[2]))
			return (0);
		if (filt->ff_flow6.fi6_dst.s6_addr32[3] !=
		    (pkt->fi6_dst.s6_addr32[3] &
		     filt->ff_mask6.mask6_dst.s6_addr32[3]))
			return (0);
	}
	if ((fbmask & FIMB6_TCLASS) &&
	    filt->ff_flow6.fi6_tclass !=
	    (pkt->fi6_tclass & filt->ff_mask6.mask6_tclass))
		return (0);
	if ((fbmask & FIMB6_GPI) &&
	    filt->ff_flow6.fi6_gpi != pkt->fi6_gpi)
		return (0);
	/* match */
	return (1);
}
#endif /* INET6 */

/*
 *  filter handle:
 *	bit 20-28: index to the filter hash table
 *	bit  0-19: unique id in the hash bucket.
 */
static u_long get_filt_handle(classifier, i)
	struct acc_classifier *classifier;
	int	i;
{
	static u_long handle_number = 1;
	u_long 	handle;
	struct acc_filter *afp;

	while (1) {
		handle = handle_number++ & 0x000fffff;

		if (LIST_EMPTY(&classifier->acc_filters[i]))
			break;

		LIST_FOREACH(afp, &classifier->acc_filters[i], f_chain)
			if ((afp->f_handle & 0x000fffff) == handle)
				break;
		if (afp == NULL)
			break;
		/* this handle is already used, try again */
	}

	return ((i << 20) | handle);
}

/* convert filter handle to filter pointer */
static struct acc_filter *
filth_to_filtp(classifier, handle)
	struct acc_classifier *classifier;
	u_long handle;
{
	struct acc_filter *afp;
	int	i;

	i = ACC_GET_HINDEX(handle);

	LIST_FOREACH(afp, &classifier->acc_filters[i], f_chain)
		if (afp->f_handle == handle)
			return (afp);

	return (NULL);
}

/* create flowinfo bitmask */
static u_int32_t
filt2fibmask(filt)
	struct flow_filter *filt;
{
	u_int32_t mask = 0;
#ifdef INET6
	struct flow_filter6 *filt6;
#endif

	switch (filt->ff_flow.fi_family) {
	case AF_INET:
		if (filt->ff_flow.fi_proto != 0)
			mask |= FIMB4_PROTO;
		if (filt->ff_flow.fi_tos != 0)
			mask |= FIMB4_TOS;
		if (filt->ff_flow.fi_dst.s_addr != 0)
			mask |= FIMB4_DADDR;
		if (filt->ff_flow.fi_src.s_addr != 0)
			mask |= FIMB4_SADDR;
		if (filt->ff_flow.fi_sport != 0)
			mask |= FIMB4_SPORT;
		if (filt->ff_flow.fi_dport != 0)
			mask |= FIMB4_DPORT;
		if (filt->ff_flow.fi_gpi != 0)
			mask |= FIMB4_GPI;
		break;
#ifdef INET6
	case AF_INET6:
		filt6 = (struct flow_filter6 *)filt;

		if (filt6->ff_flow6.fi6_proto != 0)
			mask |= FIMB6_PROTO;
		if (filt6->ff_flow6.fi6_tclass != 0)
			mask |= FIMB6_TCLASS;
		if (!IN6_IS_ADDR_UNSPECIFIED(&filt6->ff_flow6.fi6_dst))
			mask |= FIMB6_DADDR;
		if (!IN6_IS_ADDR_UNSPECIFIED(&filt6->ff_flow6.fi6_src))
			mask |= FIMB6_SADDR;
		if (filt6->ff_flow6.fi6_sport != 0)
			mask |= FIMB6_SPORT;
		if (filt6->ff_flow6.fi6_dport != 0)
			mask |= FIMB6_DPORT;
		if (filt6->ff_flow6.fi6_gpi != 0)
			mask |= FIMB6_GPI;
		if (filt6->ff_flow6.fi6_flowlabel != 0)
			mask |= FIMB6_FLABEL;
		break;
#endif /* INET6 */
	}
	return (mask);
}


/*
 * helper functions to handle IPv4 fragments.
 * currently only in-sequence fragments are handled.
 *	- fragment info is cached in a LRU list.
 *	- when a first fragment is found, cache its flow info.
 *	- when a non-first fragment is found, lookup the cache.
 */

struct ip4_frag {
    TAILQ_ENTRY(ip4_frag) ip4f_chain;
    char    ip4f_valid;
    u_short ip4f_id;
    struct flowinfo_in ip4f_info;
};

static TAILQ_HEAD(ip4f_list, ip4_frag) ip4f_list; /* IPv4 fragment cache */

#define IP4F_TABSIZE		8	/* IPv4 fragment cache size */


static void ip4f_cache(ip, fin)
	struct ip *ip;
	struct flowinfo_in *fin;
{
	struct ip4_frag *fp;

	if (TAILQ_EMPTY(&ip4f_list)) {
		/* first time call, allocate fragment cache entries. */
		if (ip4f_init() < 0)
			/* allocation failed! */
			return;
	}

	fp = ip4f_alloc();
	fp->ip4f_id = ip->ip_id;

	/* save port numbers */
	fp->ip4f_info.fi_sport = fin->fi_sport;
	fp->ip4f_info.fi_dport = fin->fi_dport;
	fp->ip4f_info.fi_gpi   = fin->fi_gpi;
}

static int ip4f_lookup(ip, fin)
	struct ip *ip;
	struct flowinfo_in *fin;
{
	struct ip4_frag *fp;

	for (fp = TAILQ_FIRST(&ip4f_list); fp != NULL && fp->ip4f_valid;
	     fp = TAILQ_NEXT(fp, ip4f_chain))
		if (ip->ip_id == fp->ip4f_id &&
		    ip->ip_src.s_addr == fp->ip4f_info.fi_src.s_addr &&
		    ip->ip_dst.s_addr == fp->ip4f_info.fi_dst.s_addr &&
		    ip->ip_p == fp->ip4f_info.fi_proto) {

			/* found the matching entry */
			fin->fi_sport = fp->ip4f_info.fi_sport;
			fin->fi_dport = fp->ip4f_info.fi_dport;
			fin->fi_gpi   = fp->ip4f_info.fi_gpi;

			if ((ntohs(ip->ip_off) & IP_MF) == 0)
				/* this is the last fragment,
				   release the entry. */
				ip4f_free(fp);

			return (1);
		}

	/* no matching entry found */
	return (0);
}

static int ip4f_init(void)
{
	struct ip4_frag *fp;
	int i;
    
	TAILQ_INIT(&ip4f_list);
	for (i=0; i<IP4F_TABSIZE; i++) {
		MALLOC(fp, struct ip4_frag *, sizeof(struct ip4_frag),
		       M_DEVBUF, M_NOWAIT);
		if (fp == NULL) {
			printf("ip4f_initcache: can't alloc cache entry!\n");
			return (-1);
		}
		fp->ip4f_valid = 0;
		TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
	}
	return (0);
}

static struct ip4_frag *ip4f_alloc(void)
{
	struct ip4_frag *fp;

	/* reclaim an entry at the tail, put it at the head */
	fp = TAILQ_LAST(&ip4f_list, ip4f_list);
	TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
	fp->ip4f_valid = 1;
	TAILQ_INSERT_HEAD(&ip4f_list, fp, ip4f_chain);
	return (fp);
}

static void ip4f_free(fp)
	struct ip4_frag *fp;
{
	TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
	fp->ip4f_valid = 0;
	TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
}

/*
 * make a control type ip header.  fake an ICMP type for now.
 */
int altq_mkctlhdr(pr_hdr)
	struct pr_hdr *pr_hdr;
{
	static struct ip *ip = NULL;

	if (ip == NULL) {
		MALLOC(ip, struct ip *, sizeof(struct ip), M_DEVBUF, M_WAITOK);
		if (ip == NULL) {
			printf("altq_mkctlhdr: malloc failed!\n");
			return (-1);
		}
		ip->ip_len = htons(sizeof(struct ip));
		ip->ip_v = 4;
		ip->ip_hl = sizeof(struct ip) >> 2;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_tos = 0;
		ip->ip_src.s_addr = htonl(0);	/* XXX */
		ip->ip_dst.s_addr = htonl(0);	/* XXX */
	}
	pr_hdr->ph_family = AF_INET;
	pr_hdr->ph_hdr = (caddr_t)ip;
	return (0);
}

#endif /* ALTQ */
