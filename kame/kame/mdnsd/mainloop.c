#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
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

static char *encode_name __P((char **, int, const char *));
static char *decode_name __P((const char **, int));
static int hexdump __P((const char *, int, const struct sockaddr *));
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
			 * if we have the answer, send it back.
			 * otherwise, relay lookup request from local node.
			 */
			if (serve(buf, l, (struct sockaddr *)&from) != 0) {
				/* relay lookup request from local node */
				relay(buf, l, (struct sockaddr *)&from);
			}
		} else {
			/* look at cache, return something */
			serve(buf, l, (struct sockaddr *)&from);
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
hexdump(buf, len, from)
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
		}
	}

	return 0;
}

static int
relay(buf, len, from)
	char *buf;
	int len;
	struct sockaddr *from;
{
	hexdump(buf, len, from);
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
			if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				continue;
#endif
			alen = sizeof(sin6->sin6_addr);
			abuf = (char *)&sin6->sin6_addr;
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
		*(u_int32_t *)p = htonl(30);	/*TTL*/
		p += sizeof(u_int32_t);
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
	char *p;
	char replybuf[8 * 1024];
	int l;
	int count;

	hexdump(buf, len, from);

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
	switch (type) {
	case T_A:
	case T_AAAA:
	case T_ANY:
		break;
	default:
		goto fail;
	}

	/* validate hostname for forward query  XXX reverse query*/
	printf("%s %s %u %u\n", hostname, n, type, class);
	if (strcmp(hostname, n) == 0)
		;
	else if (strlen(hostname) + 1 == strlen(n) &&
		 strncmp(hostname, n, strlen(hostname)) == 0)
		;
	else
		goto fail;

	/* construct reply packet */
	memcpy(replybuf, buf, d - buf);
	hp = (HEADER *)replybuf;
	p = replybuf + (d - buf);
	hp->qr = 1;	/* it is response */
	hp->aa = 1;	/* authoritative answer */
	hp->ra = 0;	/* recursion not available */
	hp->rcode = NOERROR;

	count = 0;
	l = encode_myaddrs(n, type, class, replybuf, d - buf, sizeof(replybuf),
	    &count);
	if (l < 0)
		goto fail;
	p += l;
	hp->ancount = htons(count);

	hexdump(replybuf, p - replybuf, from);

	sendto(insock, replybuf, p - replybuf, 0, from, from->sa_len);

	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}
	return 0;

fail:
	if (n) {
		/* LINTED const cast */
		free((char *)n);
	}
	return -1;
}
