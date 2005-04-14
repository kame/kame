/*	$KAME: mainloop.c,v 1.9 2005/04/14 06:22:35 suz Exp $	*/

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
 * reverse lookup by ICMPv6 node information query
 * draft-itojun-ipv6-nodeinfo-revlookup-00.txt
 *
 * TODO:
 * - query timeout - naive code is checked in
 * - cache replies seen, honor TTL
 * - negative cache on explicit failure reply
 * - negative cache on NXRRSET reply on query timeout
 * - attach additional section on reply
 * - random delay before reply
 * - as querier, retry without EDNS0 on FormError
 * - as querier, retry by TCP on truncated response (EDNS0??)
 * - multiple replies
 *	- how long should we wait for subsequent replies?
 *	- conflict resolution
 * - spec conformance check
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <netinet/in.h>
#include <netinet/icmp6.h>
#ifdef __KAME__
#include <sys/ioctl.h>
#include <netinet6/in6_var.h>
#endif
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

#include "revlookupd.h"
#include "db.h"

static int recv_dns __P((struct sockdb *));
static int recv_dns0 __P((struct sockdb *, int));
static int recv_icmp6 __P((struct sockdb *));
static char *encode_name __P((char **, int, const char *));
static char *decode_name __P((const char **, int));
static int decode_edns0 __P((const HEADER *, const char **, int));
static int update_edns0 __P((const HEADER *, char *, int, size_t));
static int dnsdump __P((const char *, const char *, int,
	const struct sockaddr *, int));
static int ptr2in __P((const char *, struct in_addr *));
static int ptr2in6 __P((const char *, struct in6_addr *));
static int match_ptrquery __P((const char *));
static int getans_dns __P((char *, int, struct sockaddr *, int));
static int getans_icmp6 __P((char *, int, struct sockaddr *, int));
static int getans_icmp6_fqdn __P((char *, int, struct sockaddr *, int));
static int relay __P((struct sockdb *, char *, int, struct sockaddr *, int));
static ssize_t ping6 __P((char *, size_t, const struct qcache *,
	const struct in6_addr *, const struct in6_addr *, int));
static int serve __P((struct sockdb *, char *, int, struct sockaddr *, int));
static int serve_query __P((struct sockdb *, char *, int, struct sockaddr *,
	int, int, int));

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	0x7f000001
#endif

#ifndef offsetof
#define offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

#ifndef T_OPT
#define T_OPT	41	/* OPT pseudo-RR, RFC2761 */
#endif
#ifndef NS_UPDATE_OP
#define NS_UPDATE_OP	5
#endif
#ifndef C_NONE
#define C_NONE	254
#endif
#ifndef YXRRSET
#define YXRRSET	7
#endif

#define RECVBUFSIZ	(8 * 1024)

#define SERVE_DONE	0
#define SERVE_RELAY	1
#define SERVE_GETANS	2

/* return next dnsid to use, in network byte order */
static u_int16_t
next_dnsid()
{
	u_int16_t ret;

	ret = htons(dnsid);
	dnsid = (dnsid + 1) % 0x10000;
	return ret;
}

void
mainloop()
{
	int i, fdmax;
	fd_set rfds, wfds;
	struct timeval timeo;
	struct sockdb *sd, *nsd;

	while (1) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		fdmax = -1;
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
			switch (sd->type) {
			case S_TCP:
				nsd = newsockdb(accept(sd->s, NULL, 0), sd->af);
				if (nsd) {
					nsd->type = sd->type;
					if (nsd->s >= 0)
						recv_dns(nsd);
					else {
						close(nsd->s);
						delsockdb(nsd);
					}
				}
				break;
			case S_ICMP6:
				(void)recv_icmp6(sd);
				break;
			default:
				(void)recv_dns(sd);
				break;
			}
		}
	}
}

/* the function hides TCP/UDP differences as much as possible. */
static int
recv_dns(sd)
	struct sockdb *sd;
{
	u_int16_t vclen;

	if (sd->type == S_TCP) {
		if (read(sd->s, &vclen, sizeof(vclen)) < 0) {
			if (dflag)
				warn("read");
			return -1;
		}
		vclen = ntohs(vclen);
	} else
		vclen = 0;

	return recv_dns0(sd, vclen);
}

/*
 * process inbound DNS-formatted packet.  it could be either query/reply,
 * and could be from remote/local.
 */
static int
recv_dns0(sd, vclen)
	struct sockdb *sd;
	int vclen;
{
	struct sockaddr_storage from_ss;
	struct sockaddr *from;
	int fromlen;
	char buf[RECVBUFSIZ];
	ssize_t l;
	struct nsdb *ns;

	from = (struct sockaddr *)&from_ss;
	fromlen = sizeof(from_ss);

	l = recvfrom(sd->s, buf, sizeof(buf), 0, from, &fromlen);
	if (l < 0) {
		if (dflag)
			warn("recvfrom");
		return -1;
	}
	if (vclen && vclen != l) {
		if (dflag)
			warnx("length mismatch");
		return -1;
	}

	/* reachability confirmation statistics */
	for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
		if (fromlen != ns->addrlen || memcmp(from, ns->addr, fromlen))
			continue;
		ns->prio++;
		gettimeofday(&ns->lastrx, NULL);
		if (dflag) {
			printnsdb(ns);
			printf("ns %p reachable\n", ns);
		}
		ns->nresponse++;
	}

	switch (serve(sd, buf, l, from, fromlen)) {
	case SERVE_DONE:
		break;
	case SERVE_RELAY:
		/*
		 * if we are the authoritative server, send
		 * answer back directly.
		 * otherwise, relay lookup request from local
		 * node to multicast-capable servers.
		 */
		relay(sd, buf, l, from, fromlen);
		break;
	case SERVE_GETANS:
		/*
		 * if got a query from remote, try to transmit answer.
		 * if we got a reply to our multicast query,
		 * fill it into our local answer cache and send
		 * the reply to the originator.
		 */
		getans_dns(buf, l, from, fromlen);
		break;
	}

	return 0;
}

/*
 * process inbound ICMPv6-formatted packet.
 */
static int
recv_icmp6(sd)
	struct sockdb *sd;
{
	struct sockaddr_storage from_ss;
	struct sockaddr *from;
	int fromlen;
	char buf[RECVBUFSIZ];
	ssize_t l;
	struct icmp6_hdr *icmp6;
	char hbuf[NI_MAXHOST];

	if (dflag)
		printf("recv_icmp6 I\n");

	from = (struct sockaddr *)&from_ss;
	fromlen = sizeof(from_ss);
	l = recvfrom(sd->s, buf, sizeof(buf), 0, from, &fromlen);

	if (getnameinfo(from, fromlen, hbuf, sizeof(hbuf),
	    NULL, 0, niflags))
		strlcpy(hbuf, "?", sizeof(hbuf));

	if (sizeof(*icmp6) > l) {
		if (dflag)
			printf("ICMPv6: too short from %s\n", hbuf);
		return 0;
	}
	icmp6 = (struct icmp6_hdr *)buf;

	if (dflag)
		printf("ICMPv6: type %u code %u from %s\n",
		    icmp6->icmp6_type, icmp6->icmp6_code, hbuf);

	/* got a query reply */
	if (icmp6->icmp6_type == ICMP6_NI_REPLY && 
	    icmp6->icmp6_code == ICMP6_NI_SUCCESS)
		getans_icmp6(buf, l, from, fromlen);

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
			if (p - str + 1 > len)
				goto fail;

			/* full qualified domain name */
			*p = '\0';
			q++;

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

/* bufp has to point additional section */
static int
decode_edns0(hp, bufp, len)
	const HEADER *hp;
	const char **bufp;
	int len;
{
	int edns0len;
	const char *buf = *bufp;

	if (ntohs(hp->arcount) != 1 || len != 11)
		return -1;
	if (buf[0] != 0)	/* . */
		return -1;
	buf++;
	if (ntohs(*(u_int16_t *)&buf[0]) != T_OPT || buf[4] != NOERROR ||
	    buf[5] != 0)
		return -1;
	if (ntohs(*(u_int16_t *)&buf[6]) != 0)	/*MBZ*/
		return -1;
	if (ntohs(*(u_int16_t *)&buf[8]) != 0)	/*RDLEN*/
		return -1;

	edns0len = ntohs(*(u_int16_t *)&buf[2]);
	buf += 10;
	*bufp = buf;
	return edns0len;
}

/* buf has to point additional section */
static int
update_edns0(hp, buf, len, edns0len)
	const HEADER *hp;
	char *buf;
	int len;
	size_t edns0len;
{
	u_int16_t v;

	if (ntohs(hp->arcount) != 1 || len != 11)
		return -1;
	if (buf[0] != 0)	/* . */
		return -1;
	buf++;
	if (ntohs(*(u_int16_t *)&buf[0]) != T_OPT || buf[4] != NOERROR ||
	    buf[5] != 0)
		return -1;
	if (ntohs(*(u_int16_t *)&buf[6]) != 0)	/*MBZ*/
		return -1;
	if (ntohs(*(u_int16_t *)&buf[8]) != 0)	/*RDLEN*/
		return -1;

	v = htons(edns0len & 0xffff);
	memcpy(&buf[2], &v, sizeof(v));
	return edns0len;
}

static int
dnsdump(title, buf, len, from, fromlen)
	const char *title;
	const char *buf;
	int len;
	const struct sockaddr *from;
	int fromlen;
{
	int i;
	char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
	HEADER *hp;
	const char *d, *n;
	int count;

	printf("===\n%s\n", title);

	if (getnameinfo(from, fromlen, hbuf, sizeof(hbuf),
	    pbuf, sizeof(pbuf), niflags) != 0) {
		strlcpy(hbuf, "?", sizeof(hbuf));
		strlcpy(pbuf, "?", sizeof(pbuf));
	}

	printf("host %s port %s myaddr %d\n", hbuf, pbuf,
	    ismyaddr(from, fromlen));
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

		/* print authority section */
		count = ntohs(hp->nscount);
		if (count)
			printf("authority section:\n");
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

		/* print additional section */
		count = ntohs(hp->arcount);
		if (count)
			printf("additional section:\n");
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
	const char *top1 = "ip6.int.";
	const char *top2 = "ip6.arpa.";

	l = strlen(n);
	if (l == strlen(top1) + 2 * 128 / 4)
		;
	else if (l == strlen(top2) + 2 * 128 / 4)
		;
	else
		return -1;
	if (l > strlen(top1) && strcmp(n + l - strlen(top1), top1) == 0)
		ep = n + l - strlen(top1);
	else if (l > strlen(top2) && strcmp(n + l - strlen(top2), top2) == 0)
		ep = n + l - strlen(top2);
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

/*
 * parse DNS responses to past relay_dns(), and relay them back to the
 * original querier.
 *
 * also handle replies that contain our UNIQUE data
 */
static int
getans_dns(buf, len, from, fromlen)
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	HEADER *ohp, *hp;
	struct qcache *qc;
	const char *on = NULL, *n = NULL;
	const char *d, *od;
	int ret;

	if (sizeof(*hp) > len)
		return -1;
	hp = (HEADER *)buf;

	if (dflag)
		dnsdump("getans I", buf, len, from, fromlen);

	if (hp->qr != 1)
		return -1;

	d = (const char *)(hp + 1);
	n = decode_name(&d, len - (d - buf));
	if (!n || len - (d - buf) < 4)
		goto fail;

	for (qc = LIST_FIRST(&qcache); qc; qc = LIST_NEXT(qc, link)) {
		if (hp->id == qc->id)
			break;
	}
	if (!qc)
		return -1;

	ohp = (HEADER *)qc->qbuf;

	/* validate reply against original query */
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
		dnsdump("getans O", buf, len, qc->from, qc->fromlen);
	if (qc->sd->type == S_TCP) {
		u_int16_t l16;

		l16 = htons(len & 0xffff);
		(void)write(qc->sd->s, &l16, sizeof(l16));
	} else if (len > qc->rbuflen) {
		len = qc->rbuflen;
		hp->tc = 1;
	}
	if (++qc->nreplies > 1) {
		printf("duplicate answer %d to %s\n", qc->nreplies, n);
		ret = sendto(qc->sd->s, qc->rbuf, qc->rlen, 0, from,
		    fromlen);
	} else {
		qc->rbuf = malloc(len);
		if (qc->rbuf == NULL)
			goto fail;
		qc->rlen = len;
		memcpy(qc->rbuf, buf, len);
		ret = sendto(qc->sd->s, buf, len, 0, qc->from,
		    qc->fromlen);
	}

	if (qc->sd->type == S_TCP) {
		close(qc->sd->s);
		delsockdb(qc->sd);
	}

	delqcache(qc);

	if (ret != len)
		goto fail;

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

/*
 * parse ICMPv6 responses to past relay_icmp6(), construct DNS response and
 * send back to the original querier.
 */
static int
getans_icmp6(buf, len, from, fromlen)
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	struct icmp6_nodeinfo *ni6;
	u_int16_t qtype;

	if (sizeof(*ni6) > len)
		return -1;
	ni6 = (struct icmp6_nodeinfo *)buf;
	qtype = ntohs(ni6->ni_qtype);

	switch (qtype) {
	case NI_QTYPE_FQDN:
		return getans_icmp6_fqdn(buf, len, from, fromlen);
	default:
		return -1;
	}
}

static int
getans_icmp6_fqdn(buf, len, from, fromlen)
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	struct icmp6_nodeinfo *ni6;
	u_int32_t *ttl;
	char dnsbuf[RECVBUFSIZ];
	HEADER *ohp, *hp;
	struct qcache *qc;
	const char *on = NULL;
	char *n = NULL;
	const char *d;
	char *p, *q;

	if (dflag)
		printf("getans_icmp6_fqdn\n");

	if (sizeof(*ni6) + sizeof(*ttl) > len)
		return -1;
	ni6 = (struct icmp6_nodeinfo *)buf;
	ttl = (u_int32_t *)(ni6 + 1);

	if (dflag) {
		int i;
		printf("FQDN reply: ");
		for (i = 0; i < len; i++)
			printf("%02x", buf[i] & 0xff);
		printf("\n");
		printf("TTL=%d\n", (int32_t)ntohl(*ttl));
	}

	d = (const char *)(ttl + 1);
	n = (char *)decode_name(&d, len - (d - buf));
	if (!n) {
		int nl, i;

		dprintf("decode_name failed\n");

		/*
		 * older KAME code uses non-DNS name encoding (len + name)
		 */
		if (d[0] != len - (d - buf) - 1)
			return -1;
		nl = len - (d - buf) - 1;
		d++;
		for (i = 0; i < nl; i++)
			if ((d[i] & 0x80) != 0 || !isascii(d[i]))
				return -1;
		n = malloc(nl + 1);
		if (!n)
			return -1;
		memcpy(n, d, nl);
		n[nl] = '\0';
	}

	dprintf("name=%s\n", n);

	for (qc = LIST_FIRST(&qcache); qc; qc = LIST_NEXT(qc, link)) {
		if (memcmp(ni6->icmp6_ni_nonce, &qc->id, sizeof(qc->id)) == 0)
			break;
	}
	if (!qc)
		goto fail;

	/* validate reply against original query */
	ohp = (HEADER *)qc->qbuf;
	p = (char *)(ohp + 1);
	on = decode_name((const char **)&p, qc->qlen - (p - qc->qbuf));
	dprintf("validate reply: query=%s reply=%s\n", on, n);
	if (!on || qc->qlen - (p - qc->qbuf) < 4)
		goto fail;
	if (strlen(n) == 0 || strlen(on) == 0)
		goto fail;

	dprintf("validated\n");

	p += 4;	/* skip type/class */

	memset(dnsbuf, 0, sizeof(dnsbuf));
	memcpy(dnsbuf, qc->qbuf, p - qc->qbuf);
	hp = (HEADER *)dnsbuf;
	*hp = *ohp;
	p = dnsbuf + (p - qc->qbuf);

	hp->qr = 1;	/* it is response */
	hp->aa = 0;	/* non-authoritative */
	hp->ra = 0;	/* recursion not available */
	hp->rcode = NOERROR;

	if (encode_name(&p, sizeof(dnsbuf) - (p - dnsbuf), on) == NULL)
		goto fail;
	if (p - dnsbuf + sizeof(u_int16_t) * 3 + sizeof(u_int32_t)
	    >= sizeof(dnsbuf))
		goto fail;
	*(u_int16_t *)p = htons(T_PTR);
	p += sizeof(u_int16_t);
	*(u_int16_t *)p = htons(C_IN);
	p += sizeof(u_int16_t);
	*(int32_t *)p = *ttl;	/*TTL*/
	p += sizeof(int32_t);
	q = p;
	*(u_int16_t *)p = htons(0);	/*filled later*/
	p += sizeof(u_int16_t);
	if (encode_name(&p, sizeof(dnsbuf) - (p - dnsbuf), n) == NULL)
		goto fail;
	*(u_int16_t *)q = htons(p - q - sizeof(u_int16_t));
	hp->ancount = htons(1);

	if (dflag)
		dnsdump("serve O", dnsbuf, p - dnsbuf, from, fromlen);

	/* XXX TC bit processing */

	sendto(qc->sd->s, dnsbuf, p - dnsbuf, 0, qc->from, qc->fromlen);

	if (on) {
		/* LINTED const cast */
		free((char *)on);
	}
	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}

	return 0;

fail:
	if (on) {
		/* LINTED const cast */
		free((char *)on);
	}
	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}

	return -1;
}

/*
 * if it is an reverse lookup, issue an ICMPv6 node information query.
 * otherwise, relay inbound DNS packet to remote DNS server
 * (unicast UDP or TCP).
 */
static int
relay(sd, buf, len, from, fromlen)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	HEADER *hp;
	struct qcache *qc;
	struct nsdb *ns;
	int sent;
	int ord;
	const char *n = NULL;
	const char *d;
	enum sdtype servtype;	/* type of server we want to relay to */
	size_t rbuflen = PACKETSZ;
	int edns0len = -1;
	char *edns0 = NULL;
	struct timeval tv;
	u_int16_t type, class;
	struct in6_addr in6;
	struct sockaddr_in6 sin6;
	char icmp6buf[RECVBUFSIZ];
	int nodeinfo;
	int icmplen;

	if (sizeof(*hp) > len)
		return -1;
	hp = (HEADER *)buf;
	d = (const char *)(hp + 1);
	n = decode_name(&d, len - (d - buf));
	if (!n || len - (d - buf) < 4) {
		/* LINTED const cast */
		free((char *)n);
		return -1;
	}
	type = ntohs(*(u_int16_t *)&d[0]);
	class = ntohs(*(u_int16_t *)&d[2]);
	d += 4;	/* skip type/class on query */

	/* XXX should drop assumption on packet format */
	if (ntohs(hp->qdcount) == 1 && ntohs(hp->ancount) == 0 &&
	    ntohs(hp->nscount) == 0) {
		edns0 = buf + (d - buf);
		edns0len = decode_edns0(hp, &d, len - (d - buf));
		if (edns0len > 0 && edns0len > rbuflen) {
			if (dflag)
				printf("EDNS0: %d\n", edns0len);
			rbuflen = edns0len;
		} else {
			/* invalid, too small */
			edns0len = -1;
		}
	}

	if (dflag)
		dnsdump("relay I", buf, len, from, fromlen);

	if (type == T_PTR && ptr2in6(n, &in6) == 0)
		nodeinfo = 1;
	else
		nodeinfo = 0;

	/* LINTED const cast */
	free((char *)n);

	/* if the querier's buffer size is bigger than mine, lower it */
	if (rbuflen > RECVBUFSIZ && edns0) {
		if (update_edns0(hp, edns0, len - (edns0 - buf),
		    RECVBUFSIZ) < 0)
			return -1;
		dprintf("lower EDNS0 to %lu on relay\n", (u_long)RECVBUFSIZ);
	}

	if (!(hp->qr == 0 && hp->opcode == QUERY))
		return -1;

	/* query - relay it */
	qc = newqcache(from, fromlen, buf, len);
	gettimeofday(&qc->ttq, NULL);
	qc->ttq.tv_sec += MDNS_TIMEO;
	qc->sd = sd;
	qc->rbuflen = rbuflen;

	ord = hp->rd;

	qc->id = hp->id = next_dnsid();

	sent = 0;

	if (nodeinfo) {
		icmplen = ping6(icmp6buf, sizeof(icmp6buf), qc, &in6, &in6, 0);

		sd = af2sockdb(PF_INET6, S_ICMP6);
		if (sd == NULL)
			return -1;

		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_len = sizeof(sin6);
		memcpy(&sin6.sin6_addr, &in6, sizeof(sin6.sin6_addr));
		/* XXX assumes link scope zone == interface index */
		if (IN6_IS_ADDR_LINKLOCAL(&in6))
			sin6.sin6_scope_id = if_nametoindex(intface);

		/* multicast outgoing interface is already configured */
		sent = 0;
		if (sendto(sd->s, icmp6buf, icmplen, 0,
		    (struct sockaddr *)&sin6, sin6.sin6_len) == icmplen) {
#if 0
			dprintf("sock %d sent\n", i);
#endif
			sent++;
		}
	}

	if (nodeinfo &&
	    (IN6_IS_ADDR_LINKLOCAL(&in6) || IN6_IS_ADDR_SITELOCAL(&in6)))
		goto done;

	for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
		if (dflag)
			printnsdb(ns);

		gettimeofday(&tv, 0);
		if (ns->dormant.tv_sec != -1) {
			if (tv.tv_sec > ns->dormant.tv_sec) {
				if (dflag)
					printf("ns %p dormant\n", ns);
				continue;
			} else {
				/* reset dormant flags */
				ns->dormant.tv_sec = -1;
				ns->dormant.tv_usec = -1;
				ns->nquery = ns->nresponse = 0;
			}
		}

		if (0 > edns0len && len > PACKETSZ) {
			/* no EDNS0 on big message -> use TCP */
			servtype = S_TCP;
		} else
			servtype = S_UDP;

		sd = af2sockdb(ns->addr->sa_family, servtype);
		if (sd == NULL)
			continue;

		hp->rd = ord;

		if (dflag)
			dnsdump("relay O", buf, len, ns->addr,
			    ns->addrlen);
		if (sd->type == S_TCP) {
			u_int16_t l16;

			l16 = htons(len & 0xffff);
			(void)write(sd->s, &l16, sizeof(l16));
		}
		if (sendto(sd->s, buf, len, 0, ns->addr, ns->addrlen) == len) {
#if 0
			dprintf("sock %d sent\n", i);
#endif
			sent++;
			gettimeofday(&ns->lasttx, NULL);
			ns->nquery++;
		}
	}

done:
	if (sent == 0) {
		dprintf("no matching socket, not sent\n");
		delqcache(qc);
		return -1;
	} else
		dprintf("sent to %d sockets\n", sent);

	return 0;
}

/*
 * construct ping6 packet.
 */
static ssize_t
ping6(buf, siz, qc, addr6, subj6, mode)
	char *buf;
	size_t siz;
	const struct qcache *qc;
	const struct in6_addr *addr6;
	const struct in6_addr *subj6;
	int mode;
{
	struct icmp6_nodeinfo *ni6;
	ssize_t l;

	l = sizeof(*ni6) + sizeof(*subj6);
	if (l > siz)
		return -1;

	switch (mode) {
	case 0:	/* ping6 -w */
		ni6 = (struct icmp6_nodeinfo *)buf;
		memset(ni6, 0, sizeof(*ni6));
		ni6->ni_type = ICMP6_NI_QUERY;
		ni6->ni_code = ICMP6_NI_SUBJ_IPV6;
		ni6->ni_qtype = htons(NI_QTYPE_FQDN);
		memcpy(ni6->icmp6_ni_nonce, &qc->id, sizeof(qc->id));
		memcpy(ni6 + 1, subj6, sizeof(*subj6));
		break;
	default:
		return -1;
	}

	return l;
}

static int
serve_query(sd, buf, len, from, fromlen, scoped, loopback)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
	int scoped;
	int loopback;
{
	HEADER *hp = (HEADER *)buf;
	const char *n = NULL;
	u_int16_t type, class;
	const char *d;
	char *p, *q;
	char replybuf[RECVBUFSIZ];
	int count;
	size_t rbuflen = PACKETSZ;

	if (hp->qr != 0)
		return SERVE_GETANS;
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

	/* XXX should drop assumption on packet format */
	if (ntohs(hp->ancount) == 0 && ntohs(hp->nscount) == 0) {
		int edns0len;
		edns0len = decode_edns0(hp, &d, len - (d - buf));
		if (edns0len > 0 && edns0len > rbuflen) {
			if (dflag)
				printf("EDNS0: %d\n", edns0len);
			rbuflen = edns0len;
		}
	}

	if (type == T_PTR && match_ptrquery(n)) {
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
			dnsdump("serve P", replybuf, p - replybuf, from,
			    fromlen);

		if (sd->type == S_TCP) {
			u_int16_t l16;

			l16 = htons((p - replybuf) & 0xffff);
			(void)write(sd->s, &l16, sizeof(l16));
		} else if (p - replybuf > rbuflen) {
			p = replybuf + rbuflen;
			hp->tc = 1;
		}
		sendto(sd->s, replybuf, p - replybuf, 0, from, fromlen);

		if (n) {
			/* LINTED const cast */
			free((char *)n);
		}
		return SERVE_DONE;
	} else
		return SERVE_RELAY;

fail:
	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}
	return SERVE_DONE;	/* error */
}

/*
 * parse inbound DNS query packet, and try to respond with answer from
 * local configuration (like hostname, ifconfig).
 */
static int
serve(sd, buf, len, from, fromlen)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	HEADER *hp;
	int scoped, loopback;

	if (dflag)
		dnsdump("serve I", buf, len, from, fromlen);

	if (from->sa_family == AF_INET6 &&
	    (IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)from)->sin6_addr) ||
	     IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)from)->sin6_addr))) {
		scoped = lflag;
	} else
		scoped = 0;
	if (from->sa_family == AF_INET &&
	    ((struct sockaddr_in *)from)->sin_addr.s_addr == INADDR_LOOPBACK) {
		loopback = 1;
	} else if (from->sa_family == AF_INET6 &&
	    IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)from)->sin6_addr)) {
		loopback = 1;
	} else
		loopback = 0;

	if (len < sizeof(*hp))
		return SERVE_DONE; /* drop */
	hp = (HEADER *)buf;
	switch (hp->opcode) {
	case QUERY:
		return serve_query(sd, buf, len, from, fromlen,
		    scoped, loopback);
	default:
		return SERVE_DONE; /* drop */
	}
}
