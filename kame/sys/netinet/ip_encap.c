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
/*
 * My grandfather said that there's a devil lives in tunnelling technology...
 *
 * We have surprisingly many protocol that want packets with IP protocol
 * #4 or #41.  Here's a list of protocols that want protocol #41:
 *	RFC1933 configured tunnel
 *	RFC1933 automatic tunnel
 *	RFC2401 IPsec tunnel
 *	RFC2473 IPv6 generic packet tunnelling
 *	RFC2529 6over4 tunnel
 *	mobile-ip6 (uses RFC2473)
 *	6to4 tunnel
 * Here's a list of protocol that want protocol #4:
 *	RFC1853 IPv4-in-IPv4 tunnel
 *	RFC2344 reverse tunnelling for mobile-ip4
 *	RFC2401 IPsec tunnel
 * Well, what can I say.  They impose different en/decapsulation mechanism
 * from each other, so they need separate protocol handler.  The only one
 * we can easily determine by protocol # is IPsec, which always has
 * AH/ESP/IPComp header right after outer IP header.
 *
 * So, clearly good old protosw does not work for protocol #4 and #41.
 * The code will let you match protocol via src/dst address pair.
 */

#ifdef __FreeBSD__
#include "opt_mrouting.h"
#endif
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_encap.h>
#ifdef MROUTING
#include <netinet/ip_mroute.h>
#endif /* MROUTING */

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#endif

#include <machine/stdarg.h>

#include <net/net_osdep.h>

struct encaptab {
	LIST_ENTRY(encaptab) chain;
	int af;
	int proto;			/* -1: don't care, I'll check myself */
	struct sockaddr_storage src;	/* my addr */
	struct sockaddr_storage srcmask;
	struct sockaddr_storage dst;	/* remote addr */
	struct sockaddr_storage dstmask;
	struct protosw *psw;		/* only pr_input will be used */
	void *arg;			/* passed via m->m_pkthdr.aux */
};

static int mask_match __P((const struct encaptab *, const struct sockaddr *,
		const struct sockaddr *));

LIST_HEAD(, encaptab) encaptab;

void
encap_init()
{
	LIST_INIT(&encaptab);
}

void
#if __STDC__
encap4_input(struct mbuf *m, ...)
#else
encap4_input(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{
	int off, proto;
	struct ip *ip;
	struct sockaddr_in s, d;
	struct encaptab *ep;
	va_list ap;

	va_start(ap, m);
	off = va_arg(ap, int);
#ifndef __OpenBSD__
	proto = va_arg(ap, int);
#endif
	va_end(ap);

	ip = mtod(m, struct ip *);
#ifdef __OpenBSD__
	proto = ip->ip_p;
#endif

	bzero(&s, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_len = sizeof(struct sockaddr_in);
	s.sin_addr = ip->ip_src;
	bzero(&d, sizeof(d));
	d.sin_family = AF_INET;
	d.sin_len = sizeof(struct sockaddr_in);
	d.sin_addr = ip->ip_dst;

	for (ep = LIST_FIRST(&encaptab); ep; ep = LIST_NEXT(ep, chain)) {
		if (ep->proto >= 0 && ep->proto != proto)
			continue;
		/* it's inbound traffic, we need to match in reverse order */
		if (mask_match(ep, (struct sockaddr *)&d,
		    (struct sockaddr *)&s) == 0)
			continue;

		/* found a match */
		if (ep->psw && ep->psw->pr_input) {
			m->m_pkthdr.aux = ep->arg;	/*XXX*/
			(*ep->psw->pr_input)(m, off, proto);
		} else
			m_freem(m);
		return;
	}

#ifdef MROUTING
	/* for backward compatibility */
	if (proto == IPPROTO_IPV4) {
		ipip_input(m, off, proto);
		return;
	}
#endif /*MROUTING*/

	/* last resort: inject to raw socket */
	rip_input(m, off, proto);
}

#ifdef INET6
int
encap6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp;
	int proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
	struct sockaddr_in6 s, d;
	struct ip6protosw *psw;
	struct encaptab *ep;

	ip6 = mtod(m, struct ip6_hdr *);

	bzero(&s, sizeof(s));
	s.sin6_family = AF_INET6;
	s.sin6_len = sizeof(struct sockaddr_in6);
	s.sin6_addr = ip6->ip6_src;
	bzero(&d, sizeof(d));
	d.sin6_family = AF_INET6;
	d.sin6_len = sizeof(struct sockaddr_in6);
	d.sin6_addr = ip6->ip6_dst;

	for (ep = LIST_FIRST(&encaptab); ep; ep = LIST_NEXT(ep, chain)) {
		if (ep->proto >= 0 && ep->proto != proto)
			continue;
		/* it's inbound traffic, we need to match in reverse order */
		if (mask_match(ep, (struct sockaddr *)&d,
		    (struct sockaddr *)&s) == 0)
			continue;

		/* found a match */
		psw = (struct ip6protosw *)ep->psw;
		if (psw && psw->pr_input) {
			m->m_pkthdr.aux = ep->arg;	/*XXX*/
			return (*psw->pr_input)(mp, offp, proto);
		} else {
			m_freem(m);
			return IPPROTO_DONE;
		}
	}

	/* last resort: inject to raw socket */
	return rip6_input(mp, offp, proto);
}
#endif

/*
 * sp (src ptr) is always my side, and dp (dst ptr) is always remote side.
 * length of mask (sm and dm) is assumed to be same as sp/dp.
 * Return value will be necessary as input (cookie) for encap_detach().
 */
void *
encap_attach(af, proto, sp, sm, dp, dm, psw, arg)
	int af;
	int proto;
	struct sockaddr *sp, *sm;
	struct sockaddr *dp, *dm;
	struct protosw *psw;
	void *arg;
{
	struct encaptab *ep;
	int error;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* sanity check on args */
	if (sp->sa_len > sizeof(ep->src) || dp->sa_len > sizeof(ep->dst)) {
		error = EINVAL;
		goto fail;
	}
	if (sp->sa_len != dp->sa_len) {
		error = EINVAL;
		goto fail;
	}
	if (af != sp->sa_family || af != dp->sa_family) {
		error = EINVAL;
		goto fail;
	}

	/* check if anyone have already attached with exactly same config */
	for (ep = LIST_FIRST(&encaptab); ep; ep = LIST_NEXT(ep, chain)) {
		if (ep->af != af)
			continue;
		if (ep->proto != proto)
			continue;
		if (ep->src.ss_len != sp->sa_len ||
		    bcmp(&ep->src, sp, sp->sa_len) != 0 ||
		    bcmp(&ep->srcmask, sm, sp->sa_len) != 0)
			continue;
		if (ep->dst.ss_len != dp->sa_len ||
		    bcmp(&ep->dst, dp, dp->sa_len) != 0 ||
		    bcmp(&ep->dstmask, dm, dp->sa_len) != 0)
			continue;

		error = EEXIST;
		goto fail;
	}

	ep = malloc(sizeof(*ep), M_NETADDR, M_NOWAIT);	/*XXX*/
	if (ep == NULL) {
		error = ENOBUFS;
		goto fail;
	}

	ep->af = af;
	ep->proto = proto;
	bcopy(sp, &ep->src, sp->sa_len);
	bcopy(sm, &ep->srcmask, sp->sa_len);
	bcopy(dp, &ep->dst, dp->sa_len);
	bcopy(dm, &ep->dstmask, dp->sa_len);
	ep->psw = psw;
	ep->arg = arg;

	/*
	 * XXX order of insertion will determine the priority in lookup
	 */
	LIST_INSERT_HEAD(&encaptab, ep, chain);
	error = 0;
	splx(s);
	return (void *)ep;

fail:
	splx(s);
	return NULL;
}

int
encap_detach(cookie)
	void *cookie;
{
	struct encaptab *ep = (struct encaptab *)cookie;
	struct encaptab *p;

	for (p = LIST_FIRST(&encaptab); p; p = LIST_NEXT(p, chain)) {
		if (p == ep) {
			LIST_REMOVE(p, chain);
			free(p, M_NETADDR);	/*XXX*/
			return 0;
		}
	}

	return EINVAL;
}

static int
mask_match(ep, sp, dp)
	const struct encaptab *ep;
	const struct sockaddr *sp;
	const struct sockaddr *dp;
{
	struct sockaddr_storage s;
	struct sockaddr_storage d;
	int i;
	u_int8_t *p, *q, *r;

	if (sp->sa_len > sizeof(s) || dp->sa_len > sizeof(d))
		return 0;
	if (sp->sa_family != ep->af || dp->sa_family != ep->af)
		return 0;
	if (sp->sa_len != ep->src.ss_len || dp->sa_len != ep->dst.ss_len)
		return 0;

	p = (u_int8_t *)sp;
	q = (u_int8_t *)&ep->srcmask;
	r = (u_int8_t *)&s;
	for (i = 0 ; i < sp->sa_len; i++)
		r[i] = p[i] & q[i];

	p = (u_int8_t *)dp;
	q = (u_int8_t *)&ep->dstmask;
	r = (u_int8_t *)&d;
	for (i = 0 ; i < dp->sa_len; i++)
		r[i] = p[i] & q[i];

	/* need to overwrite len/family portion as we don't compare them */
	s.ss_len = sp->sa_len;
	s.ss_family = sp->sa_family;
	d.ss_len = dp->sa_len;
	d.ss_family = dp->sa_family;

	if (bcmp(&s, &ep->src, ep->src.ss_len) == 0 &&
	    bcmp(&d, &ep->dst, ep->dst.ss_len) == 0) {
		return 1;
	} else
		return 0;
}
