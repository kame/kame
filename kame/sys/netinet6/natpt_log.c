/*	$KAME: natpt_log.c,v 1.18 2002/08/19 10:24:58 fujisawa Exp $	*/

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
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <machine/stdarg.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

static struct sockaddr	natpt_dst = {2, PF_INET};
static struct sockaddr	natpt_src = {2, PF_INET};

static int	natpt_logpAddr	__P((char *, struct pAddr *, u_char **, size_t *));
static int	natpt_ntop4 __P((const u_char *, char *, size_t));
static int	natpt_ntop6 __P((const u_char *, char *, size_t));


/*
 *
 */

#define	SZWOW			256
#define	SZGETA			16

void
natpt_logMsg(int priorities, char *format, ...)
{
	int		 rv;
	u_char		 wow[SZWOW+SZGETA];
	va_list		 ap;

	if (natpt_usesyslog || natpt_uselog) {
		va_start(ap, format);
		rv = vsnprintf(wow, SZWOW, format, ap);
		if (natpt_uselog) {
			natpt_log(LOG_MSG, priorities, (void *)wow, strlen(wow)+1);
		}
		if (natpt_usesyslog) {
			wow[rv] = '\n';
			wow[rv+1] = '\0';
			log(priorities, wow);
		}
		va_end(ap);
	}
}


void
natpt_logMBuf(int priorities, struct mbuf *m, ...)
{
	int		 rv;
	char		*format;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, m);
	if ((format = va_arg(ap, char *)) != NULL) {
		rv = vsnprintf(wow, sizeof(wow), format, ap);
		natpt_log(LOG_MSG,  priorities, (void *)wow, strlen(wow)+1);
	}
	va_end(ap);

	natpt_log(LOG_DUMP, priorities, (void *)m->m_data, min(m->m_len, LBFSZ));
}


void
natpt_logIp6(int priorities, struct ip6_hdr *ip6, ...)
{
	int		 rv;
	char		*format;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, ip6);
	if ((format = va_arg(ap, char *)) != NULL) {
		rv = vsnprintf(wow, sizeof(wow), format, ap);
		natpt_log(LOG_MSG,  priorities, (void *)wow, strlen(wow)+1);
	}
	va_end(ap);

	natpt_log(LOG_IP6, priorities, (void *)ip6, sizeof(struct ip6_hdr)+8);
}


void
natpt_logIp4(int priorities, struct ip *ip4, ...)
{
	int		 rv;
	char		*format;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, ip4);
	if ((format = va_arg(ap, char *)) != NULL) {
		rv = vsnprintf(wow, sizeof(wow), format, ap);
		natpt_log(LOG_MSG,  priorities, (void *)wow, strlen(wow)+1);
	}
	va_end(ap);

	natpt_log(LOG_IP4, priorities, (void *)ip4, ((ip4->ip_hl << 2) + 20));
}


int
natpt_log(int type, int priorities, void *item, size_t size)
{
	struct sockproto	 proto;
	struct	mbuf	*m;
	struct	lbuf	*p;

	if ((m = natpt_lbuf(type, priorities, size)) == NULL)
		return (ENOBUFS);

	p = (struct lbuf *)m->m_data;
	m_copyback(m, sizeof(struct l_hdr), p->l_hdr.lh_size, (caddr_t)item);

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_AHIP;
	natpt_input(m, &proto, &natpt_src, &natpt_dst);

	return (0);
}


int
natpt_logIN6addr(int priorities, char *msg, struct in6_addr *sin6addr)
{
	int		 size, msgsz;
	struct	mbuf	*m;
	struct	lbuf	*p;

	msgsz = strlen(msg)+1;
	size = sizeof(struct l_hdr) + IN6ADDRSZ + msgsz;

	if ((m = natpt_lbuf(LOG_IN6ADDR, priorities, size)) == NULL)
		return (ENOBUFS);

	{
		struct sockproto	proto;

		p = (struct lbuf *)m->m_pktdat;
		bcopy(sin6addr, p->l_addr.in6addr, sizeof(struct in6_addr));
		strncpy(p->l_msg, msg, min(msgsz, MSGSZ-1));
		p->l_msg[MSGSZ-1] = '\0';

		proto.sp_family = AF_INET;
		proto.sp_protocol = IPPROTO_AHIP;
		natpt_input(m, &proto, &natpt_src, &natpt_dst);
	}

	return (0);
}


struct mbuf *
natpt_lbuf(int type, int priorities, size_t size)
{
	struct	mbuf	*m;
	struct	lbuf	*p;
	int		 maxlen;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

	if (size + sizeof(struct l_hdr) > MCLBYTES)
		return (NULL);

	MGETHDR(m, M_NOWAIT, MT_DATA);
	maxlen = MHLEN;
	if (size + sizeof(struct l_hdr) > MHLEN) {
		MCLGET(m, M_NOWAIT);
		maxlen = MCLBYTES;
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return (NULL);

	m->m_pkthdr.len = m->m_len = maxlen;
	m->m_pkthdr.rcvif = NULL;

	p = (struct lbuf *)m->m_data;
	p->l_hdr.lh_type = type;
	p->l_hdr.lh_pri	 = priorities;
	p->l_hdr.lh_size = size;
#ifdef __FreeBSD__
	microtime(&mono_time);
#endif
	p->l_hdr.lh_sec = mono_time.tv_sec;
	p->l_hdr.lh_usec = mono_time.tv_usec;

	return (m);
}


/*
 *
 */

void
natpt_logTSlot(int priorities, struct tSlot *tsl, char dir, int num)
{
	int		 wl, rv;
	u_char		*pr;
	u_char		*wp;
	u_char		 wow[SZWOW+SZGETA];

	if ((natpt_usesyslog == 0) && (natpt_uselog == 0))
		return ;

	wl = SZWOW;
	wp = wow;

	rv = snprintf(wp, wl, "%ctSlot=%p, nSlots=%d", dir, tsl, num);
	wp += rv;
	wl -= rv;

	if (dir == '+') {
		switch (tsl->ip_p) {
		case IPPROTO_ICMP:	pr = "icmp";	break;
		case IPPROTO_TCP:	pr = "tcp";	break;
		case IPPROTO_UDP:	pr = "udp";	break;
		case IPPROTO_ICMPV6:	pr = "icmp6";	break;
		default:		pr = "unknown";	break;
		}
		rv = snprintf(wp, wl, ", proto=%s", pr);
		wp += rv;
		wl -= rv;

		rv = natpt_logpAddr(", from=", &tsl->local,  &wp, &wl);
		rv = natpt_logpAddr(", to=", &tsl->remote, &wp, &wl);
	}

	rv = wp - wow;
	if (natpt_uselog) {
		wow[rv] = '\0';
		natpt_log(LOG_MSG, priorities, (void *)wow, rv+1);
	}
	if (natpt_usesyslog) {
		wow[rv] = '\n';
		wow[rv+1] = '\0';
		log(priorities, wow);
	}
}


void
natpt_logFSlot(int priority, struct fragment *frg, char dir)
{
	int		 wl, rv;
	u_char		*pr;
	u_char		*wp;
	u_char		 wow[SZWOW+SZGETA];

	if ((natpt_usesyslog == 0) && (natpt_uselog == 0))
		return ;

	wl = SZWOW;
	wp = wow;

	rv = snprintf(wp, wl, "%cfSlot=%p", dir, frg);
	wp += rv;
	wl -= rv;

	if (dir == '+') {
		switch (frg->fg_proto) {
		case IPPROTO_ICMP:	pr = "icmp";	break;
		case IPPROTO_TCP:	pr = "tcp";	break;
		case IPPROTO_UDP:	pr = "udp";	break;
		case IPPROTO_ICMPV6:	pr = "icmp6";	break;
		default:		pr = "unknown";	break;
		}
		rv = snprintf(wp, wl, ", proto=%s", pr);
		wp += rv;
		wl -= rv;

		rv = snprintf(wp, wl, ", src="); wp += rv; wl -= rv;
		rv = natpt_ntop(frg->fg_family, (const void *)&frg->fg_src, wp, wl);
		wp += rv; wl -= rv;

		rv = snprintf(wp, wl, ", dst="); wp += rv; wl -= rv;
		rv = natpt_ntop(frg->fg_family, (const void *)&frg->fg_dst, wp, wl);
		wp += rv; wl -= rv;

		rv = snprintf(wp, wl, ", tSlot=%p", frg->tslot);
		wp += rv; wl -= rv;
	}

	rv = wp - wow;
	if (natpt_uselog) {
		wow[rv] = '\0';
		natpt_log(LOG_MSG, priority, (void *)wow, rv+1);
	}
	if (natpt_usesyslog) {
		wow[rv] = '\n';
		wow[rv+1] = '\0';
		log(priority, wow);
	}
}


static int
natpt_logpAddr(char *from, struct pAddr *src, u_char **wp, size_t *wl)
{
	int	rv;
	u_char	*wps = *wp;

	rv = snprintf(*wp, *wl, from);
	*wp += rv;
	*wl -= rv;
	rv = natpt_ntop(src->sa_family, (const void *)&src->addr[0], *wp, *wl);
	*wp += rv;
	*wl -= rv;

	if (src->port[0] != 0) {
		rv = snprintf(*wp, *wl, ", port=%d", ntohs(src->port[0]));
		*wp += rv;
		*wl -= rv;
	}

	return (*wp - wps);
}


/*
 * These code came from /usr/src/lib/libc/net/inet_ntop.c.  I changed
 * these routine to return the number of character converted into.
 */

#define	NS_IN6ADDRSZ		16	/* IPv6 T_AAAA */
#define	NS_INT16SZ		2	/* #/bytes of data in a u_int16_t */

#define	LOCAL			tsl->local
#define	REMOTE			tsl->remote

int
natpt_ntop(int af, const void *src, char *dst, size_t size)
{
	switch (af) {
	case AF_INET:
		return (natpt_ntop4(src, dst, size));
	case AF_INET6:
		return (natpt_ntop6(src, dst, size));
	}

	return (0);
}


static int
natpt_ntop4(const u_char *src, char *dst, size_t size)
{
	int	rv;
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];

	if ((rv = sprintf(tmp, fmt, src[0], src[1], src[2], src[3])) > size) {
		return (0);
	}

	strcpy(dst, tmp);
	return (rv);
}


static int
natpt_ntop6(const u_char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!natpt_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (0);
			tp += strlen(tp);
			break;
		}
		tp += (size_t)sprintf(tp, "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		return (0);
	}

	strcpy(dst, tmp);
	return (tp - tmp - 1);		/* remove count of last '\0' */
}
