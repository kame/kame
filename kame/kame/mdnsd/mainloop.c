/*	$KAME: mainloop.c,v 1.7 2000/05/30 16:13:13 itojun Exp $	*/

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
 * - negative cache on explicit failure reply, or query timeout
 * - attach additional section on reply
 * - random delay before reply
 * - spec conformance check
 * - EDNS0 receiver buffer size notification
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

#include <arpa/nameser.h>

#include "mdnsd.h"

struct qcache {
	LIST_ENTRY(qcache) link;
	struct sockaddr_storage from;
	char *qbuf;	/* original query packet */
	int qlen;
	u_int16_t id;	/* id on relayed query - net endian */
};

struct acache {
	LIST_ENTRY(acache) link;
};

static LIST_HEAD(, qcache) qcache;
#if 0
static LIST_HEAD(, acache) acache;
#endif

static char *encode_name __P((char **, int, const char *));
static char *decode_name __P((const char **, int));
static int hexdump __P((const char *, const char *, int,
	const struct sockaddr *));
static int encode_myaddrs __P((const char *, u_int16_t, u_int16_t, char *,
	int, int, int *));
static const struct sockaddr *getsa __P((const char *, const char *, int));
static struct qcache *newqcache __P((const struct sockaddr *, char *, int));
static void delqcache __P((struct qcache *));
static int getans __P((char *, int, struct sockaddr *));
static int relay __P((char *, int, struct sockaddr *));
static int serve __P((char *, int, struct sockaddr *));

void
mainloop()
{
	struct sockaddr_storage from;
	int fromlen;
	char buf[8 * 1024];
	int l;

	while (1) {
		fromlen = sizeof(from);
		l = recvfrom(insock, buf, sizeof(buf), 0,
		    (struct sockaddr *)&from, &fromlen);
		if (l < 0)
			err(1, "recvfrom");

		/*
		 * XXX don't permit recursion for multicast query,
		 * mdns-00 section 5 - we need to get destination address,
		 * or we need to split listening socket into two
		 */

		if (ismyaddr((struct sockaddr *)&from)) {
			/*
			 * if we are the authoritative server, send answer
			 * back directly.
			 * otherwise, relay lookup request from local node
			 * to multicast-capable servers.
			 */
			if (serve(buf, l, (struct sockaddr *)&from) != 0)
				relay(buf, l, (struct sockaddr *)&from);
		} else {
			/*
			 * if got a query from remote, try to transmit answer.
			 * if we got a reply to our multicast query, fill
			 * it into our local answer cache and send the reply
			 * to the originator.
			 */
			if (serve(buf, l, (struct sockaddr *)&from) != 0)
				getans(buf, l, (struct sockaddr *)&from);
		}
	}
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
		if (*q > 63 || *q < 0)
			goto fail;

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
hexdump(title, buf, len, from)
	const char *title;
	const char *buf;
	int len;
	const struct sockaddr *from;
{
	int i;
	char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
#ifdef NI_WITHSCOPEID
	const int niflags = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int niflags = NI_NUMERICHOST;
#endif
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
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%08x: ", i);
		printf("%02x", buf[i] & 0xff);
		if (i % 16 == 15)
			printf("\n");
	}
	if (len % 16 != 0)
		printf("\n");

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
			for (i = 0; i < ntohs(*(u_int16_t *)&d[8]); i++) {
				printf("%02x", d[10 + i] & 0xff);
			}
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

static struct qcache *
newqcache(from, buf, len)
	const struct sockaddr *from;
	char *buf;
	int len;
{
	struct qcache *qc;

	if (from->sa_len > sizeof(qc->from))
		return NULL;

	qc = (struct qcache *)malloc(sizeof(*qc));
	if (qc == NULL)
		return NULL;
	memset(qc, 0, sizeof(*qc));
	qc->qbuf = (char *)malloc(len);
	if (qc->qbuf == NULL) {
		free(qc);
		return NULL;
	}

	memcpy(&qc->from, from, from->sa_len);
	memcpy(qc->qbuf, buf, len);
	qc->qlen = len;

	LIST_INSERT_HEAD(&qcache, qc, link);
	return qc;
}

static void
delqcache(qc)
	struct qcache *qc;
{
	LIST_REMOVE(qc, link);
	if (qc->qbuf)
		free(qc->qbuf);
	free(qc);
}

static int
getans(buf, len, from)
	char *buf;
	int len;
	struct sockaddr *from;
{
	HEADER *hp;
	struct qcache *qc;

	hp = (HEADER *)buf;

	hexdump("getans I", buf, len, from);

	/* we handle successful replies only  XXX negative cache */
	if (hp->qr != 1 || hp->rcode != NOERROR)
		return -1;

	for (qc = LIST_FIRST(&qcache); qc; qc = LIST_NEXT(qc, link)) {
		if (hp->id == qc->id)
			break;
	}
	if (!qc)
		return -1;

	/* XXX validate reply against original query */
	hp->id = ((HEADER *)qc->qbuf)->id;
	hp->rd = 0;
	hexdump("getans O", buf, len, (struct sockaddr *)&qc->from);
	if (sendto(insock, buf, len, 0, (struct sockaddr *)&qc->from,
	    qc->from.ss_len) != len) {
		delqcache(qc);
		return -1;
	}
	delqcache(qc);
	return 0;
#if 0
	if (hp->qr == 0 && hp->opcode == QUERY) {
		/* query, no recurse - multicast it */
		qc = newqcache(from, buf, len);

		/* never ask for recursion */
		hp->rd = 0;

		qc->id = hp->id = htons(dnsid);
		dnsid = (dnsid + 1) % 0x10000;

		sa = getsa(MDNS_GROUP6, dstport, SOCK_DGRAM);
		if (!sa) {
			delqcache(qc);
			return -1;
		}
		hexdump("relay O", buf, len, sa);
		if (sendto(insock, buf, len, 0, sa, sa->sa_len) != len) {
			delqcache(qc);
			return -1;
		}
		return 0;
	} else
		return -1;
#endif
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

	hp = (HEADER *)buf;

	hexdump("relay I", buf, len, from);
	if (hp->qr == 0 && hp->opcode == QUERY) {
		/* query, no recurse - multicast it */
		qc = newqcache(from, buf, len);

		/* never ask for recursion */
		hp->rd = 0;

		qc->id = hp->id = htons(dnsid);
		dnsid = (dnsid + 1) % 0x10000;

		sa = getsa(MDNS_GROUP6, dstport, SOCK_DGRAM);
		if (!sa) {
			delqcache(qc);
			return -1;
		}
		hexdump("relay O", buf, len, sa);
		if (sendto(insock, buf, len, 0, sa, sa->sa_len) != len) {
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
serve(buf, len, from)
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

	hexdump("serve I", buf, len, from);

	/* we handle queries only */
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

		hexdump("serve O", replybuf, p - replybuf, from);

		sendto(insock, replybuf, p - replybuf, 0, from, from->sa_len);

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

		hexdump("serve D", replybuf, p - replybuf, from);

		sendto(insock, replybuf, p - replybuf, 0, from, from->sa_len);

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
