/*	$KAME: mainloop.c,v 1.22 2000/05/31 12:12:58 itojun Exp $	*/

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

#include "mdnsd.h"
#include "db.h"
#include "mediator_compat.h"

static int mainloop0 __P((int));
static int conf_mediator __P((int));
static char *encode_name __P((char **, int, const char *));
static char *decode_name __P((const char **, int));
static int dnsdump __P((const char *, const char *, int,
	const struct sockaddr *));
static int encode_myaddrs __P((const char *, u_int16_t, u_int16_t, char *,
	int, int, int *));
#if 0
static const struct sockaddr *getsa __P((const char *, const char *, int));
#endif
static int getans __P((int, char *, int, struct sockaddr *));
static int relay __P((char *, int, struct sockaddr *));
static int serve __P((int, char *, int, struct sockaddr *));

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	0x7f000001
#endif

void
mainloop()
{
	int i, fdmax;
	fd_set rfds, wfds;
	struct timeval timeo;

	while (1) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		fdmax =  -1;
		for (i = 0; i < nsock; i++) {
			FD_SET(sock[i], &rfds);
			if (sock[i] > fdmax)
				fdmax = sock[i];
		}
		memset(&timeo, 0, sizeof(timeo));
		timeo = hz;
		i = select(fdmax + 1, &rfds, &wfds, NULL, &timeo);
		if (i < 0) {
			err(1, "select");
			/*NOTREACHED*/
		} else if (i == 0) {
			dbtimeo();
			continue;
		}

		for (i = 0; i < nsock; i++) {
			if (FD_ISSET(sock[i], &rfds)) {
				if (sockflag[i] & SOCK_MEDIATOR)
					conf_mediator(i);
				else
					mainloop0(i);
			}
		}
	}
}

static int
mainloop0(i)
	int i;
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
	l = recvfrom(sock[i], buf, sizeof(buf), 0, (struct sockaddr *)&from,
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
		if (dflag)
			printnsdb(ns);
	}

	if (ismyaddr((struct sockaddr *)&from)) {
		/*
		 * if we are the authoritative server, send
		 * answer back directly.
		 * otherwise, relay lookup request from local
		 * node to multicast-capable servers.
		 */
		if (serve(sock[0], buf, l, (struct sockaddr *)&from) != 0)
			relay(buf, l, (struct sockaddr *)&from);
	} else {
		/*
		 * if got a query from remote, try to transmit answer.
		 * if we got a reply to our multicast query,
		 * fill it into our local answer cache and send
		 * the reply to the originator.
		 */
		if (serve(sock[0], buf, l, (struct sockaddr *)&from) != 0)
			getans(sock[0], buf, l, (struct sockaddr *)&from);
	}

	return 0;
}

static int
conf_mediator(i)
	int i;
{
	struct sockaddr_storage from;
	int fromlen;
	char buf[8 * 1024];
	int l;
	struct mediator_control_msg *msg;
	char *p;

	fromlen = sizeof(from);
	l = recvfrom(sock[i], buf, sizeof(buf), 0, (struct sockaddr *)&from,
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
	if (*p != '\0')
		return -1;

	if (msg->lifetime == 0xffffffff)
		(void)addserv(msg->serveraddr, -1);
	else
		(void)addserv(msg->serveraddr, ntohl(msg->lifetime));
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
#if 0
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
encode_myaddrs(n, type, class, replybuf, off, buflen, naddrs)
	const char *n;
	u_int16_t type;
	u_int16_t class;
	char *replybuf;
	int off;
	int buflen;
	int *naddrs;
{
	struct ifaddrs *ifap = NULL, *ifa;
	char *p;
	size_t alen;
	char *abuf;
	u_int16_t ntype, nclass;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct in6_addr in6;

	p = replybuf + off;
	*naddrs = 0;

	if (getifaddrs(&ifap) != 0)
		goto fail;

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
#if 1
			/* XXX be careful about scope issue! */
			if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr))
				continue;
#endif
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				in6 = sin6->sin6_addr;
				if (*(u_int16_t *)&in6.s6_addr[2])
					in6.s6_addr[2] = in6.s6_addr[3] = 0;
				alen = sizeof(in6);
				abuf = (char *)&in6;
#if 1
				/* XXX be careful about scope issue! */
				continue;
#endif
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
		*(int32_t *)p = htonl(30);	/*TTL*/
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
getans(s, buf, len, from)
	int s;
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
	hp->ra = 0;	/* recursion not supported */
	if (dflag)
		dnsdump("getans O", buf, len, (struct sockaddr *)&qc->from);
	if (sendto(s, buf, len, 0, (struct sockaddr *)&qc->from,
	    qc->from.ss_len) != len) {
		delqcache(qc);
		goto fail;
	}
	delqcache(qc);

	if (n)
		free((char *)n);
	if (on)
		free((char *)on);
	return 0;

fail:
	if (n)
		free((char *)n);
	if (on)
		free((char *)on);
	return -1;
}

static int
relay(buf, len, from)
	char *buf;
	int len;
	struct sockaddr *from;
{
	const struct sockaddr *sa;
	HEADER *hp;
	struct qcache *qc;
	struct nsdb *ns;
	int i, sent;
	int ord;

	if (sizeof(*hp) > len)
		return -1;
	hp = (HEADER *)buf;

	if (dflag)
		dnsdump("relay I", buf, len, from);
	if (hp->qr == 0 && hp->opcode == QUERY) {
		/* query, no recurse - multicast it */
		qc = newqcache(from, buf, len);

		ord = hp->rd;

		qc->id = hp->id = htons(dnsid);
		dnsid = (dnsid + 1) % 0x10000;

		sent = 0;
		for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
			for (i = 0; i < nsock; i++) {
				if (sockaf[i] != ns->addr.ss_family)
					continue;

				hp->rd = ord;
				/* never ask for recursion on multicast query */
				if (ns->flags == NSDB_MULTICAST)
					hp->rd = 0;

				sa = (struct sockaddr *)&ns->addr;

				if (dflag)
					dnsdump("relay O", buf, len, sa);
				if (sendto(sock[i], buf, len, 0, sa,
				    sa->sa_len) == len) {
					sent++;
					gettimeofday(&ns->lasttx, NULL);
					break;	/* try the next nameserver */
				}
			}
		}

		if (sent == 0) {
			delqcache(qc);
			return -1;
		}

		return 0;
	} else
		return -1;
}

/*
 * XXX should defer transmission with random delay, and supress duplicated
 * replies (mdns-00 page 3)
 */
static int
serve(s, buf, len, from)
	int s;
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

	if (dflag)
		dnsdump("serve I", buf, len, from);

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
		    sizeof(replybuf), &count);
		if (l <= 0)
			goto fail;
		p += l;
		hp->ancount = htons(count);

		if (dflag)
			dnsdump("serve O", replybuf, p - replybuf, from);

		sendto(s, replybuf, p - replybuf, 0, from, from->sa_len);

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
		/* XXX alignment */
		*(u_int16_t *)p = htons(type);
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(class);
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

		if (dflag)
			dnsdump("serve D", replybuf, p - replybuf, from);

		sendto(s, replybuf, p - replybuf, 0, from, from->sa_len);

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
