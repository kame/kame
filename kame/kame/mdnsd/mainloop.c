/*	$KAME: mainloop.c,v 1.43 2001/03/09 13:51:39 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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
 * multicast DNS resolver, based on draft-aboba-dnsext-mdns-00.txt.
 *
 * TODO:
 * - query timeout
 * - cache replies seen, honor TTL
 * - advert cached entries (non-authoritative)
 * - negative cache on explicit failure reply
 * - negative cache on NXRRSET reply on query timeout
 * - attach additional section on reply
 * - random delay before reply
 * - EDNS0 receiver buffer size notification
 * - multiple replies
 *	- how long should we wait for subsequent replies?
 *	- conflict resolution
 * - [phmb]-mode configuration - is it necessary?
 * - spec conformance check
 *
 * 00 -> 01 difference:
 * - 01 specification requires us to query names under "lcl.arpa" only.
 *   For example, we cannot use 01 mdns to lookup address against
 *   "starfruit.itojun.org".  We are allowed to use 01 mdns, only when we
 *   lookup "starfruit.lcl.arpa" only.  (Q: what should we do about reverse
 *   mapping?)
 * - 00 mdns resolver queries to linklocal and local multicast group address.
 *   01 mdns resolver will query linklocal multicast group address only.
 * - 00 defines AA (authoritative answer) bit handling, and allows hosts to
 *   respond with cached data.  01 drops the comment, puts it as future
 *   study, and forbids to answer using cached data.
 *
 * draft-aboba-dnsext-mdns-01 -> draft-ietf-dnsext-mdns-00 difference:
 * - the former uses "foo.lcl.arpa" as the local name.
 *   the latter uses "foo.local.arpa".
 * - the latter has more limitation on retransmission (MUST NOT repeat more
 *   than 5 times.  interval has to be 0.1 seconds or longer, and should be
 *   exponentially increased).
 * - TC and RA bits handling.
 * - IP TTL/hoplimit value must be 255.
 * - clarified that no unicast queries should be used for local.arpa, and
 *   it is okay to query normal (unicast) DNS server for outside of local.arpa.
 * - name server device must not listen to multicast queries.
 * - more security section.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#include <ctype.h>

#include <arpa/nameser.h>
#include <arpa/inet.h>

#include "mdnsd.h"
#include "db.h"
#include "mediator_compat.h"

static int mainloop0 __P((struct sockdb *));
static int conf_mediator __P((struct sockdb *));
static char *encode_name __P((char **, int, const char *));
static char *decode_name __P((const char **, int));
static int dnsdump __P((const char *, const char *, int,
	const struct sockaddr *));
static int ptr2in __P((const char *, struct in_addr *));
static int ptr2in6 __P((const char *, struct in6_addr *));
static int match_ptrquery __P((const char *));
static int encode_myaddrs __P((const char *, u_int16_t, u_int16_t, char *,
	int, int, int *, int));
#if 0
static const struct sockaddr *getsa __P((const char *, const char *, int));
#endif
static int getans __P((char *, int, struct sockaddr *));
static int relay __P((struct sockdb *, char *, int, struct sockaddr *));
static int serve __P((struct sockdb *, char *, int, struct sockaddr *));

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	0x7f000001
#endif

#ifndef offsetof
#define offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

void
mainloop()
{
	int i, fdmax;
	fd_set rfds, wfds;
	struct timeval timeo;
	struct sockdb *sd;

	while (1) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		fdmax =  -1;
		for (sd = LIST_FIRST(&sockdb); sd; sd = LIST_NEXT(sd, link)) {
			FD_SET(sd->s, &rfds);
			if (sd->s > fdmax)
				fdmax = sd->s;
		}
		memset(&timeo, 0, sizeof(timeo));
		timeo = hz;
		signo = 0;
		i = select(fdmax + 1, &rfds, &wfds, NULL, &timeo);
		if (i < 0) {
			if (errno == EINTR) {
				if (signo == SIGUSR1)
					status();
				continue;
			}
			err(1, "select");
			/*NOTREACHED*/
		} else if (i == 0) {
			dbtimeo();
			continue;
		}

		for (i = 0; i < fdmax + 1; i++) {
			if (!FD_ISSET(i, &rfds))
				continue;
			sd = sock2sockdb(i);
			if (sd->type == S_MEDIATOR)
				conf_mediator(sd);
			else
				mainloop0(sd);
		}
	}
}

static int
mainloop0(sd)
	struct sockdb *sd;
{
	struct sockaddr_storage from;
	int fromlen;
	char buf[8 * 1024];
	int l;
	struct nsdb *ns;

	/*
	 * XXX we need to get destination address of incoming packet.
	 * reason 1: we need to forbid recursion for multicast query.
	 *	to check it, we need to know the destination address.
	 * reason 2: for unicast query, we need to flip the src/dst
	 *	pair.
	 * reason 3: we do not want to be hosed by fake multicast reply.
	 */
	fromlen = sizeof(from);
	l = recvfrom(sd->s, buf, sizeof(buf), 0, (struct sockaddr *)&from,
	    &fromlen);
	if (l < 0) {
		if (dflag)
			warn("recvfrom");
		return -1;
	}

	/* reachability confirmation statistics */
	for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
		if (fromlen != ns->addr.ss_len ||
		    memcmp(&from, &ns->addr, fromlen) != 0)
			continue;
		ns->prio++;
		gettimeofday(&ns->lastrx, NULL);
		if (dflag) {
			printnsdb(ns);
			printf("ns %p reachable\n", ns);
		}
	}

	if (ismyaddr((struct sockaddr *)&from)) {
		/*
		 * if we are the authoritative server, send
		 * answer back directly.
		 * otherwise, relay lookup request from local
		 * node to multicast-capable servers.
		 */
		if (serve(sd, buf, l, (struct sockaddr *)&from) != 0)
			relay(sd, buf, l, (struct sockaddr *)&from);
	} else {
		/*
		 * if got a query from remote, try to transmit answer.
		 * if we got a reply to our multicast query,
		 * fill it into our local answer cache and send
		 * the reply to the originator.
		 */
		if (serve(sd, buf, l, (struct sockaddr *)&from) != 0)
			getans(buf, l, (struct sockaddr *)&from);
	}

	return 0;
}

static int
conf_mediator(sd)
	struct sockdb *sd;
{
	struct sockaddr_storage from;
	int fromlen;
	char buf[8 * 1024];
	int l;
	struct mediator_control_msg *msg;
	char *p;

	fromlen = sizeof(from);
	l = recvfrom(sd->s, buf, sizeof(buf), 0, (struct sockaddr *)&from,
	    &fromlen);
	if (l < 0) {
		if (dflag)
			warn("recvfrom");
		return -1;
	}

	if (l != sizeof(*msg))
		return -1;
	msg = (struct mediator_control_msg *)buf;
	if (ntohl(msg->version) != MEDIATOR_CTRL_VERSION)
		return -1;
	for (p = msg->serveraddr;
	     p < &msg->serveraddr[sizeof(msg->serveraddr)];
	     p++) {
		if (*p == '\0')
			break;
		if (!isprint(*p))
			return -1;
	}
	/* overrun */
	if (p >= &msg->serveraddr[sizeof(msg->serveraddr)])
		return -1;
	if (*p != '\0')
		return -1;

	if (msg->lifetime == 0xffffffff)
		(void)addserv(msg->serveraddr, -1, "mediator conf");
	else {
		(void)addserv(msg->serveraddr, ntohl(msg->lifetime),
		    "mediator conf");
	}
	return 0;
}

static char *
encode_name(bufp, len, n)
	char **bufp;
	int len;
	const char *n;
{
	char *buf = *bufp;
	char *p;
	const char *q, *dot;

	/* name MUST be terminated by dot */
	if (!strlen(n))
		return NULL;
	if (n[strlen(n) - 1] != '.')
		return NULL;

	/* -1 is for terminating dot */
	if (len < strlen(n) - 1)
		return NULL;

	p = buf;
	q = n;
	while (p - buf < len && *q) {
		dot = strchr(q, '.');
		if (!dot)
			return NULL;
		if (p - buf + (dot - q) >= len)
			return NULL;
		*p++ = (dot - q);
		memcpy(p, q, dot - q);
		p += dot - q;
		q = dot + 1;
	}
	if (*q)
		return NULL;
	if (p - buf + 1 >= len)
		return NULL;
	*p++ = '\0';	/*termination*/

	*bufp = p;
	return buf;
}

static char *
decode_name(bufp, len)
	const char **bufp;
	int len;
{
	char *str;
	char *p;
	const char *q;
	const char *buf = *bufp;

	str = (char *)malloc(len);
	if (str == NULL)
		return NULL;
	p = str;
	q = buf;
	while (p - str < len && q - buf < len) {
		/* compression is not supported yet */
		if (*q > 63 || *q < 0) {
			dprintf("(compressed name decoding not supported)\n");
			goto fail;
		}

		if (q - buf + *q + 1 > len)
			goto fail;

		if (*q == 0) {
			if (p - str + 1 < len) {
				/* full qualified domain name */
				*p = '\0';
				q++;
			} else
				goto fail;

			*bufp = q;
			return str;
		}

		if (p - str + *q + 1 > len)
			goto fail;
		memcpy(p, q + 1, *q);
		p += *q;
		*p++ = '.';
		q += *q + 1;
	}

fail:
	free(str);
	return NULL;
}

static int
dnsdump(title, buf, len, from)
	const char *title;
	const char *buf;
	int len;
	const struct sockaddr *from;
{
	int i;
	char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
	HEADER *hp;
	const char *d, *n;
	int count;

	printf("===\n%s\n", title);

	if (getnameinfo(from, from->sa_len, hbuf, sizeof(hbuf),
	    pbuf, sizeof(pbuf), niflags) != 0) {
		strncpy(hbuf, "?", sizeof(hbuf));
		strncpy(pbuf, "?", sizeof(pbuf));
	}

	printf("host %s port %s myaddr %d\n", hbuf, pbuf, ismyaddr(from));
#if 1
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%08x: ", i);
		printf("%02x", buf[i] & 0xff);
		if (i % 16 == 15)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");
#endif

	if (sizeof(*hp) > len) {
		printf("packet too short, %d\n", len);
		return -1;
	}
	hp = (HEADER *)buf;
	printf("id: %04x qr: %u opcode: %u rcode: %u %u/%u/%u/%u/%u/%u/%u\n",
	    ntohs(hp->id), hp->qr, hp->opcode, hp->rcode,
	    hp->qr, hp->aa, hp->tc, hp->rd, hp->ra, hp->ad, hp->cd);
	printf("qd: %u an: %u ns: %u ar: %u\n",
	    ntohs(hp->qdcount), ntohs(hp->ancount), ntohs(hp->nscount), 
	    ntohs(hp->arcount));

	if (len > sizeof(*hp)) {
		d = (char *)(hp + 1);

		/* print questions section */
		count = ntohs(hp->qdcount);
		if (count)
			printf("question section:\n");
		while (count--) {
			if (d - buf > len)
				break;
			n = decode_name(&d, len - (d - buf));
			if (!n)
				break;
			if (d - buf + 4 > len)
				break;
			printf("%s", n);
			printf(" qtype %u qclass %u\n",
			    ntohs(*(u_int16_t *)&d[0]),
			    ntohs(*(u_int16_t *)&d[2]));
			d += 4;
			/* LINTED const cast */
			free((char *)n);
		}

		/* print answers section */
		count = ntohs(hp->ancount);
		if (count)
			printf("answers section:\n");
		while (count--) {
			if (d - buf > len)
				break;
			n = decode_name(&d, len - (d - buf));
			if (!n)
				break;
			if (d - buf + 10 > len)
				break;
			if (d - buf + 10 + ntohs(*(u_int16_t *)&d[8]) > len)
				break;
			printf("%s", n);
			printf(" qtype %u qclass %u",
			    ntohs(*(u_int16_t *)&d[0]),
			    ntohs(*(u_int16_t *)&d[2]));
			printf(" ttl %d rdlen %u ",
			    (int32_t)ntohl(*(u_int32_t *)&d[4]),
			    ntohs(*(u_int16_t *)&d[8]));
			for (i = 0; i < ntohs(*(u_int16_t *)&d[8]); i++)
				printf("%02x", d[10 + i] & 0xff);
			d += 10 + ntohs(*(u_int16_t *)&d[8]);
			printf("\n");

			/* LINTED const cast */
			free((char *)n);
		}
	}

	return 0;
}

static int
ptr2in(n, in)
	const char *n;
	struct in_addr *in;
{
	const char *p;
	char *q;
	unsigned long x;
	const char *ep;
	char a[4];
	int l;
	const char *top = "in-addr.arpa.";

	l = strlen(n);
	if (l > strlen(top) && strcmp(n + l - strlen(top), top) == 0)
		ep = n + l - strlen(top);
	else
		return -1;

	l = 0;
	p = n;
	while (l < 4 && p < ep) {
		q = NULL;
		x = strtoul(p, &q, 10);
		if (x & ~0xff)
			return -1;
		if (*q != '.')
			return -1;
		q++;
		a[3 - l] = x & 0xff;
		l++;

		p = q;
	}

	if (l != 4)
		return -1;
	memcpy(in, a, sizeof(*in));
	return 0;
}

static int
ptr2in6(n, in6)
	const char *n;
	struct in6_addr *in6;
{
	const char *p;
	char *q;
	unsigned long x;
	const char *ep;
	int l;
	const char *top = "ip6.int.";

	l = strlen(n);
	if (l != strlen(top) + 2 * 128 / 4)
		return -1;
	if (l > strlen(top) && strcmp(n + l - strlen(top), top) == 0)
		ep = n + l - strlen(top);
	else
		return -1;

	l = 0;
	p = n;
	while (l < 128 / 4 && p < ep) {
		q = NULL;
		if (!isxdigit(*p))
			return -1;
		x = strtoul(p, &q, 16);
		if (x & ~0xf)
			return -1;
		if (p + 1 != q || *q != '.')
			return -1;
		q++;
		if (l % 2)
			in6->s6_addr[15 - l / 2] |= (x & 0xf) << 4;
		else
			in6->s6_addr[15 - l / 2] = x & 0xf;
		l++;

		p = q;
	}

	if (l != 128 / 4)
		return -1;
	return 0;
}

static int
match_ptrquery(n)
	const char *n;
{
	struct ifaddrs *ifap = NULL, *ifa;
	struct in_addr in;
	struct in6_addr in6;
	int af, alen, off;
	char *addr;
	const char *ifmatch;

	ifmatch = NULL;
	if (ptr2in(n, &in) == 0) {
		af = AF_INET;
		alen = sizeof(in);
		addr = (char *)&in;
		off = offsetof(struct sockaddr_in, sin_addr);
	} else if (ptr2in6(n, &in6) == 0) {
		af = AF_INET6;
		alen = sizeof(in6);
		addr = (char *)&in6;
		off = offsetof(struct sockaddr_in6, sin6_addr);

		if (IN6_IS_ADDR_LOOPBACK(&in6) || IN6_IS_ADDR_V4MAPPED(&in6) ||
		    IN6_IS_ADDR_V4COMPAT(&in6) || IN6_IS_ADDR_MULTICAST(&in6)) {
			goto fail;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&in6)) {
#ifdef __KAME__
			*(u_int16_t *)&in6.s6_addr[2] =
			    htons(if_nametoindex(intface));
#endif
			ifmatch = intface;
		}
	} else
		goto fail;

	if (getifaddrs(&ifap) != 0)
		goto fail;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != af)
			continue;
		if (ifmatch && strcmp(ifa->ifa_name, ifmatch) != 0)
			continue;
		if (ifa->ifa_addr->sa_len < off + alen)
			continue;
		if (memcmp(((char *)ifa->ifa_addr) + off, addr, alen) == 0) {
			freeifaddrs(ifap);
			return 1;
		}
	}

fail:
	if (ifap)
		freeifaddrs(ifap);
	return 0;
}

static int
encode_myaddrs(n, type, class, replybuf, off, buflen, naddrs, scoped)
	const char *n;
	u_int16_t type;
	u_int16_t class;
	char *replybuf;
	int off;
	int buflen;
	int *naddrs;
	int scoped;
{
	struct ifaddrs *ifap = NULL, *ifa;
	char *p;
	size_t alen;
	char *abuf;
	u_int16_t ntype, nclass;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct in6_addr in6;
	int scopecnt;

	p = replybuf + off;
	*naddrs = 0;

	if (getifaddrs(&ifap) != 0)
		goto fail;

	scopecnt = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		switch (type) {
		case T_A:
			if (ifa->ifa_addr->sa_family == AF_INET)
				break;
			continue;
		case T_AAAA:
			if (ifa->ifa_addr->sa_family == AF_INET6)
				break;
			continue;
		case T_ANY:
			if (ifa->ifa_addr->sa_family == AF_INET ||
			    ifa->ifa_addr->sa_family == AF_INET6)
				break;
			continue;
		default:
			goto fail;
		}

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (ntohl(sin->sin_addr.s_addr) == INADDR_ANY ||
			    IN_CLASSD(sin->sin_addr.s_addr))
				continue;
			if (ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK)
				continue;
			alen = sizeof(sin->sin_addr);
			abuf = (char *)&sin->sin_addr;
			ntype = T_A;
			nclass = C_IN;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
				continue;
			if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
				continue;

			/* XXX be careful about scope issue! */
			if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
				if (!scoped)
					continue;
				if (strcmp(ifa->ifa_name, intface) != 0)
					continue;
				scopecnt++;
			}
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				if (!scoped)
					continue;
				if (strcmp(ifa->ifa_name, intface) != 0)
					continue;

				in6 = sin6->sin6_addr;
				if (*(u_int16_t *)&in6.s6_addr[2])
					in6.s6_addr[2] = in6.s6_addr[3] = 0;
				alen = sizeof(in6);
				abuf = (char *)&in6;
				scopecnt++;
			} else {
				alen = sizeof(sin6->sin6_addr);
				abuf = (char *)&sin6->sin6_addr;
			}

			ntype = T_AAAA;
			nclass = C_IN;
			break;
		default:
			continue;
		}

		if (encode_name(&p, buflen - (p - replybuf), n) == NULL)
			goto fail;
		if (p - replybuf + sizeof(u_int16_t) * 3 + sizeof(u_int32_t) + alen >= buflen)
			goto fail;

		/* XXX alignment */
		*(u_int16_t *)p = htons(ntype);
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(nclass);
		p += sizeof(u_int16_t);
		*(int32_t *)p = htonl(scopecnt ? 0 : 30);	/*TTL*/
		p += sizeof(int32_t);
		*(u_int16_t *)p = htons(alen);
		p += sizeof(u_int16_t);
		memcpy(p, abuf, alen);
		p += alen;
		(*naddrs)++;
	}

	freeifaddrs(ifap);
	return p - (replybuf + off);

fail:
	if (ifap)
		freeifaddrs(ifap);
	return -1;
}

#if 0
static const struct sockaddr *
getsa(host, port, socktype)
	const char *host;
	const char *port;
	int socktype;
{
	static struct sockaddr_storage ss;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = socktype;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return NULL;
	if (res->ai_addrlen > sizeof(ss)) {
		freeaddrinfo(res);
		return NULL;
	}
	memcpy(&ss, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return (const struct sockaddr *)&ss;
}
#endif

static int
getans(buf, len, from)
	char *buf;
	int len;
	struct sockaddr *from;
{
	HEADER *ohp, *hp;
	struct qcache *qc;
	const char *on = NULL, *n = NULL;
	const char *d, *od;

	if (sizeof(*hp) > len)
		return -1;
	hp = (HEADER *)buf;

	if (dflag)
		dnsdump("getans I", buf, len, from);

	/* we handle successful replies only  XXX negative cache */
	if (hp->qr != 1 || hp->rcode != NOERROR)
		return -1;

	for (qc = LIST_FIRST(&qcache); qc; qc = LIST_NEXT(qc, link)) {
		if (hp->id == qc->id)
			break;
	}
	if (!qc)
		return -1;
	ohp = (HEADER *)qc->qbuf;

	/* validate reply against original query */
	d = (const char *)(hp + 1);
	n = decode_name(&d, len - (d - buf));
	if (!n || len - (d - buf) < 4)
		goto fail;
	od = (const char *)(ohp + 1);
	on = decode_name(&od, qc->qlen - (od - qc->qbuf));
	dprintf("validate reply: query=%s reply=%s\n", on, n);
	if (!on || qc->qlen - (od - qc->qbuf) < 4)
		goto fail;
	if (strcmp(n, on) != 0 || memcmp(d, od, 4) != 0)
		goto fail;

	hp->id = ohp->id;
	hp->ra = 1;	/* XXX recursion?? */
	if (dflag)
		dnsdump("getans O", buf, len, (struct sockaddr *)&qc->from);
	if (len > PACKETSZ) {
		len = PACKETSZ;
		hp->tc = 1;
	}
	if (sendto(qc->sd->s, buf, len, 0, (struct sockaddr *)&qc->from,
	    qc->from.ss_len) != len) {
		delqcache(qc);
		goto fail;
	}
	delqcache(qc);

	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}
	if (on) {
		/* LINTED const cast */
		free((char *)on);
	}
	return 0;

fail:
	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}
	if (on) {
		/* LINTED const cast */
		free((char *)on);
	}
	return -1;
}

static int
relay(sd, buf, len, from)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
{
	const struct sockaddr *sa;
	HEADER *hp;
	struct qcache *qc;
	struct nsdb *ns;
	int sent;
	int ord;

	if (sizeof(*hp) > len)
		return -1;
	hp = (HEADER *)buf;

	if (dflag)
		dnsdump("relay I", buf, len, from);
	if (hp->qr == 0 && hp->opcode == QUERY) {
		/* query - relay it */
		qc = newqcache(from, buf, len);
		qc->sd = sd;

		ord = hp->rd;

		if (len > PACKETSZ) {
			len = PACKETSZ;
			hp->tc = 1;
		}
		qc->id = hp->id = htons(dnsid);
		dnsid = (dnsid + 1) % 0x10000;

		sent = 0;
		for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
			if (dflag)
				printnsdb(ns);

			sd = af2sockdb(ns->addr.ss_family,
			    ns->type == N_MULTICAST ? S_MULTICAST : S_UNICAST);
			if (sd == NULL)
				continue;

			hp->rd = ord;
			/* never ask for recursion on multicast query */
			if (ns->type == N_MULTICAST)
				hp->rd = 0;

			sa = (struct sockaddr *)&ns->addr;

			if (dflag)
				dnsdump("relay O", buf, len, sa);
			if (sendto(sd->s, buf, len, 0, sa, sa->sa_len) == len) {
#if 0
				dprintf("sock %d sent\n", i);
#endif
				sent++;
				gettimeofday(&ns->lasttx, NULL);
			}
		}

		if (sent == 0) {
			dprintf("no matching socket, not sent\n");
			delqcache(qc);
			return -1;
		} else
			dprintf("sent to %d sockets\n", sent);

		return 0;
	} else
		return -1;
}

/*
 * XXX should defer transmission with random delay, and supress duplicated
 * replies (mdns-00 page 3)
 */
static int
serve(sd, buf, len, from)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
{
	HEADER *hp;
	const char *n = NULL;
	u_int16_t type, class;
	const char *d;
	char *p, *q;
	char replybuf[8 * 1024];
	int l;
	int count;
	int scoped;
	const struct addrinfo *ai;

	if (dflag)
		dnsdump("serve I", buf, len, from);

	if (from->sa_family == AF_INET6 &&
	    (IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)from)->sin6_addr) ||
	     IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)from)->sin6_addr))) {
		scoped = lflag;
	} else
		scoped = 0;

	/* we handle queries only */
	if (sizeof(*hp) > len)
		return -1;
	hp = (HEADER *)buf;
	if (hp->qr != 0 || hp->opcode != QUERY)
		goto fail;
	if (ntohs(hp->qdcount) != 1)	/*XXX*/
		goto fail;

	d = (const char *)(hp + 1);
	n = decode_name(&d, len - (d - buf));
	if (!n || len - (d - buf) < 4)
		goto fail;
	type = ntohs(*(u_int16_t *)&d[0]);
	class = ntohs(*(u_int16_t *)&d[2]);
	d += 4;		/* "d" points to end of question section */
	if (class != C_IN)
		goto fail;

	if (strcmp(hostname, n) == 0 ||
	    (strlen(hostname) + 1 == strlen(n) &&
	     strncmp(hostname, n, strlen(hostname)) == 0)) {
		/* hostname for forward query - advertise my addresses */
		memcpy(replybuf, buf, d - buf);
		hp = (HEADER *)replybuf;
		p = replybuf + (d - buf);
		hp->qr = 1;	/* it is response */
		hp->aa = 1;	/* authoritative answer */
		hp->ra = 0;	/* recursion not available */
		hp->rcode = NOERROR;

		count = 0;
		l = encode_myaddrs(n, type, class, replybuf, d - buf,
		    sizeof(replybuf), &count, scoped);
		if (l <= 0)
			goto fail;
		p += l;
		hp->ancount = htons(count);

		if (dflag)
			dnsdump("serve O", replybuf, p - replybuf, from);

		if (p - replybuf > PACKETSZ) {
			p = replybuf + PACKETSZ;
			hp->tc = 1;
		}
		sendto(sd->s, replybuf, p - replybuf, 0, from, from->sa_len);

		if (n) {
			/* LINTED const cast */
			free((char *)n);
		}
		return 0;
	} else if (type == T_PTR && match_ptrquery(n)) {
		/* ptr record for reverse query - advertise my name */
		memcpy(replybuf, buf, d - buf);
		hp = (HEADER *)replybuf;
		p = replybuf + (d - buf);
		hp->qr = 1;	/* it is response */
		hp->aa = 1;	/* authoritative answer */
		hp->ra = 0;	/* recursion not available */
		hp->rcode = NOERROR;

		count = 0;
		if (encode_name(&p, sizeof(replybuf) - (p - replybuf), n)
		    == NULL)
			goto fail;
		if (p + 10 - replybuf > sizeof(replybuf))
			goto fail;
		/* XXX alignment */
		*(u_int16_t *)p = htons(type);	/*PTR*/
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(class);	/*IN*/
		p += sizeof(u_int16_t);
		*(int32_t *)p = htonl(30);	/*TTL*/
		p += sizeof(int32_t);
		q = p;
		*(u_int16_t *)p = htons(0);	/*filled later*/
		p += sizeof(u_int16_t);
		if (encode_name(&p, sizeof(replybuf) - (p - replybuf), hostname)
		    == NULL)
			goto fail;
		*(u_int16_t *)q = htons(p - q - sizeof(u_int16_t));
		hp->ancount = htons(1);

		if (dflag)
			dnsdump("serve P", replybuf, p - replybuf, from);

		if (p - replybuf > PACKETSZ) {
			p = replybuf + PACKETSZ;
			hp->tc = 1;
		}
		sendto(sd->s, replybuf, p - replybuf, 0, from, from->sa_len);

		if (n) {
			/* LINTED const cast */
			free((char *)n);
		}
		return 0;
	} else if (type == T_SRV && dnsserv &&
		   strcmp("_dns._udp.lcl.", n) == 0) {
		/* DNS server query - advert DNS server */
		memcpy(replybuf, buf, d - buf);
		hp = (HEADER *)replybuf;
		p = replybuf + (d - buf);
		hp->qr = 1;	/* it is response */
		hp->aa = 1;	/* authoritative answer */
		hp->ra = 0;	/* recursion not available */
		hp->rcode = NOERROR;

		/* answers section */
		if (encode_name(&p, sizeof(replybuf) - (p - replybuf), n)
				== NULL) {
			goto fail;
		}
		if (p + 16 - replybuf > sizeof(replybuf))
			goto fail;
		/* XXX alignment */
		*(u_int16_t *)p = htons(type);	/*SRV*/
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(class);	/*IN*/
		p += sizeof(u_int16_t);
		*(int32_t *)p = htonl(30);	/*TTL*/
		p += sizeof(int32_t);
		q = p;
		*(u_int16_t *)p = htons(0);	/*filled later*/
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(0);	/*priority*/
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(0);	/*weight*/
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(53);	/*port*/
		p += sizeof(u_int16_t);
		if (encode_name(&p, sizeof(replybuf) - (p - replybuf), dnsserv)
				== NULL) {
			goto fail;
		}
		*(u_int16_t *)q = htons(p - q - sizeof(u_int16_t));
		hp->ancount = htons(1);

		/* additional records */
		for (ai = dnsserv_ai; ai; ai = ai->ai_next) {
			const char *addr;
			int alen;
			u_int16_t t;

			switch (ai->ai_family) {
			case AF_INET:
				t = T_A;
				addr = (char *)&((struct sockaddr_in *)ai->ai_addr)->sin_addr;
				alen = 4;
				break;
			case AF_INET6:
				t = T_AAAA;
				addr = (char *)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
				alen = 16;
				break;
			default:
				addr = NULL;	/*fool gcc*/
				alen = 0;	/*fool gcc*/
				continue;
			}

			if (encode_name(&p, sizeof(replybuf) - (p - replybuf), n)
					== NULL) {
				goto fail;
			}
			if (p + 10 + alen - replybuf > sizeof(replybuf))
				goto fail;
			/* XXX alignment */
			*(u_int16_t *)p = htons(t);
			p += sizeof(u_int16_t);
			*(u_int16_t *)p = htons(C_IN);	/*IN*/
			p += sizeof(u_int16_t);
			*(int32_t *)p = htonl(30);	/*TTL*/
			p += sizeof(int32_t);
			q = p;
			*(u_int16_t *)p = htons(0);	/*filled later*/
			p += sizeof(u_int16_t);
			memcpy(p, addr, alen);
			p += alen;
			*(u_int16_t *)q = htons(p - q - sizeof(u_int16_t));
			hp->arcount = htons(ntohs(hp->arcount) + 1);
		}

		if (dflag)
			dnsdump("serve D", replybuf, p - replybuf, from);

		if (p - replybuf > PACKETSZ) {
			p = replybuf + PACKETSZ;
			hp->tc = 1;
		}
		sendto(sd->s, replybuf, p - replybuf, 0, from, from->sa_len);

		if (n) {
			/* LINTED const cast */
			free((char *)n);
		}
		return 0;
	}

fail:
	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}
	return -1;
}
