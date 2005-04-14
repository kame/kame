/*	$KAME: mainloop.c,v 1.97 2005/04/14 06:22:34 suz Exp $	*/

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
 * multicast DNS resolver, based on draft-ietf-dnsext-mdns-03.txt.
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
 * - set hoplimit on reply to 255, verify
 * - for -N, we should be using "ping6 -a ag -N -I if0 fqdn", not
 *   "ping6 -w -I if0 ff02::1".  however, the deployemnt status of the latest
 *   icmp6 node information query is still low.  not sure what should we do.
 *
 * draft-aboba-dnsext-mdns-00 -> draft-aboba-dnsext-mdns-01 differences:
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
 * draft-aboba-dnsext-mdns-01 -> draft-ietf-dnsext-mdns-00 differences:
 * - the former uses "foo.lcl.arpa" as the local name.
 *   the latter uses "foo.local.arpa".
 * - the latter has more limitation on retransmission (MUST NOT repeat more
 *   than 5 times.  interval has to be 0.1 seconds or longer, and should be
 *   exponentially increased).
 * - TC and RA bits handling.
 * - IP TTL/hoplimit value must be 255.
 * - clarified that no unicast queries should be used for local.arpa, and
 *   it is okay to query normal (unicast) DNS server for outside of local.arpa.
 * - normal name server devices must not listen to multicast queries.
 * - more security section.
 *
 * draft-ietf-dnsext-mdns-00 -> draft-ietf-dnsext-mdns-03 differences:
 * - sender behavior change.
 *   00: repetition < 5 times, interval > 0.1 second.  exponential backoff.
 *   03: repetition < 3 times, interval > 1 second.  random interval.
 * - NXRRSET rule.  00: cache 5 second, 03: no text
 * - conflict detection.  00: query, 03: dynamic update
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

#include "mdnsd.h"
#include "db.h"
#include "mediator_compat.h"

static int recv_dns __P((struct sockdb *));
static int recv_dns0 __P((struct sockdb *, int));
static int recv_icmp6 __P((struct sockdb *));
static int conf_mediator __P((struct sockdb *));
static char *encode_name __P((char **, int, const char *));
static char *decode_name __P((const char **, int));
static int decode_edns0 __P((const HEADER *, const char **, int));
static int update_edns0 __P((const HEADER *, char *, int, size_t));
static int dnsdump __P((const char *, const char *, int,
	const struct sockaddr *, int));
static int ptr2in __P((const char *, struct in_addr *));
static int ptr2in6 __P((const char *, struct in6_addr *));
static int match_ptrquery __P((const char *));
static int encode_myaddrs __P((const char *, u_int16_t, u_int16_t, char *,
	int, int, int *, int, int));
static int ismyname __P((const char *));
static int islocalname __P((const char *));
#if 0
static const struct sockaddr *getsa __P((const char *, const char *, int));
#endif
static int getans_dns __P((char *, int, struct sockaddr *, int));
static int getans_icmp6 __P((char *, int, struct sockaddr *, int));
static int getans_icmp6_fqdn __P((char *, int, struct sockaddr *, int));
static int getans_icmp6_nodeaddr __P((char *, int, struct sockaddr *, int));
static int relay __P((struct sockdb *, char *, int, struct sockaddr *, int));
static int relay_dns __P((struct sockdb *, char *, int, struct sockaddr *,
	int));
static int relay_icmp6 __P((struct sockdb *, char *, int, struct sockaddr *,
	int));
static ssize_t ping6 __P((char *, size_t, const struct qcache *, const char *,
	const char *, int));
static int serve __P((struct sockdb *, char *, int, struct sockaddr *, int));
static int serve_query __P((struct sockdb *, char *, int, struct sockaddr *,
	int, int, int));
static int serve_update __P((struct sockdb *, char *, int, struct sockaddr *,
	int, int, int));
static void reply __P((struct sockdb *, const char *, int, struct sockaddr *,
	int, int, int, int));
static int useful_sockaddr_in __P((const struct sockaddr_in *, int));
static int useful_sockaddr_in6 __P((const struct sockaddr_in6 *, int,
	const char *, const char *, int, int *));
static int in2ptr __P((const struct in_addr *, char *, size_t));
static int in62ptr __P((const struct in6_addr *, char *, size_t));
static int send_update __P((const char *, int, int));

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

static int
send_update(name, type, class)
	const char *name;
	int type;
	int class;
{
	char buf[RECVBUFSIZ], *p = buf;
	HEADER *hp = (HEADER *)buf;
	struct nsdb *ns;
	size_t len;

	memset(hp, 0, sizeof(*hp));
	hp->id = next_dnsid();
	hp->qr = 0;
	hp->opcode = NS_UPDATE_OP;
	hp->qdcount = htons(1);	/* zocount */
	hp->ancount = htons(1);	/* prcount */
	hp->nscount = htons(0);	/* upcount */
	hp->arcount = htons(0);	/* adcount */

	p = buf + sizeof(*hp);

	/* zone section */
	if (encode_name(&p, sizeof(buf) - (p - buf), name) == NULL)
		goto fail;
	if (p - buf < 2 * sizeof(u_int16_t))
		goto fail;
	*(u_int16_t *)p = htons(T_SOA);
	p += sizeof(u_int16_t);
	*(u_int16_t *)p = htons(class);
	p += sizeof(u_int16_t);

	/* pre-req section */
	if (encode_name(&p, sizeof(buf) - (p - buf), name) == NULL)
		goto fail;
	if (p - buf < 3 * sizeof(u_int16_t) + sizeof(u_int32_t))
		goto fail;
	*(u_int16_t *)p = htons(type);
	p += sizeof(u_int16_t);
	*(u_int16_t *)p = htons(C_NONE);
	p += sizeof(u_int16_t);
	*(u_int32_t *)p = htons(0);	/* TTL */
	p += sizeof(u_int32_t);
	*(u_int16_t *)p = htons(0); /* RDLENGTH */
	p += sizeof(u_int16_t);
	
	/* update section empty */	
	/* additional section empty */

	len = p - buf;

	for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
		struct sockdb *sd;

		if (ns->type != N_MULTICAST)
			continue;
		sd = af2sockdb(ns->addr->sa_family, S_MULTICAST);
		if (sd == NULL)
			continue;
		if (sendto(sd->s, buf, len, 0, ns->addr, ns->addrlen) != len)
			; /* some error traps? */
	}

	return 0;

fail:
	return -1;
}

/* send updates for all our unique RR */
int
send_updates()
{
	struct ifaddrs *ifap = NULL, *ifa;
	int have_a = 0, have_aaaa = 0;
	char label[256];

	if (getifaddrs(&ifap) != 0)
		goto fail;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
		    {
			struct sockaddr_in *sin4;

			sin4 = (struct sockaddr_in *)ifa->ifa_addr;
			if (!useful_sockaddr_in(sin4, 0))
				continue;

			have_a = 1;
			in2ptr(&sin4->sin_addr, label, sizeof(label));
			send_update(label, T_PTR, C_IN);
			break;
		    }
		case AF_INET6:
		    {
			struct sockaddr_in6 *sin6;
			int dummy;

			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (!useful_sockaddr_in6(sin6, 0, intface,
			    ifa->ifa_name, lflag, &dummy))
				continue;

			have_aaaa = 1;
			in62ptr(&sin6->sin6_addr, label, sizeof(label));
			send_update(label, T_PTR, C_IN);
			break;
		    }
		default:
			break;
		}
	}
	freeifaddrs(ifap);

	if (have_a)
		send_update(hostname, T_A, C_IN);
	if (have_aaaa)
		send_update(hostname, T_AAAA, C_IN);
	return 0;

fail:
	if (ifap)
		freeifaddrs(ifap);
	return -1;
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
			case S_MEDIATOR:
				(void)conf_mediator(sd);
				break;
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

	/*
	 * XXX we need to get destination address of incoming packet.
	 * reason 1: we need to forbid recursion for multicast query.
	 *	to check it, we need to know the destination address.
	 * reason 2: for unicast query, we need to flip the src/dst
	 *	pair.
	 * reason 3: we do not want to be hosed by fake multicast reply.
	 * reason 4: for newer specs, local.arpa (or lcl.arpa) queries must be
	 *	handled iff the query is sent to multicast address.
	 * reason 5: for newer specs, PTR query must return local.arpa (or
	 *	lcl.arpa) zone iff the query is sent to multicast address.
	 */
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

static int
conf_mediator(sd)
	struct sockdb *sd;
{
	struct sockaddr_storage from;
	int fromlen;
	char buf[RECVBUFSIZ];
	ssize_t l;
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

/* return 1 if this v4 address `sin' is something that should be exported */
static int
useful_sockaddr_in(sin4, loopback)
	const struct sockaddr_in *sin4;
	int loopback;
{
	if (ntohl(sin4->sin_addr.s_addr) == INADDR_ANY ||
	    IN_MULTICAST(ntohl(sin4->sin_addr.s_addr)))
		return (0);
	if (ntohl(sin4->sin_addr.s_addr) == INADDR_LOOPBACK && !loopback)
		return (0);
	return (1);
}

/* return 1 if this v6 address `sin6' is something that should be exported */
static int
useful_sockaddr_in6(sin6, loopback, intface, ifaname, scoped, scopecnt)
	const struct sockaddr_in6 *sin6;
	int loopback;
	const char *intface;
	const char *ifaname;
	int scoped;
	int *scopecnt;
{
	if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
	    IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
		return (0);
	if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) && !loopback)
		return (0);

	/* XXX be careful about scope issue! */
	if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
		if (!scoped)
			return (0);
		if (strcmp(ifaname, intface) != 0)
			return (0);
		(*scopecnt)++;
	}
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		if (!scoped)
			return (0);
		if (strcmp(ifaname, intface) != 0)
			return (0);
		(*scopecnt)++;
	}
	return (1);
}

static int
in2ptr(in, name, namesize)
	const struct in_addr *in;
	char *name;
	size_t namesize;
{
	u_int32_t n = ntohl(in->s_addr);

	return (snprintf(name, namesize, "%u.%u.%u.%u.in-addr.arpa.",
	    (n >> 0) & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff,
	    (n >> 24) & 0xff));
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
in62ptr(in6, name, namesize)
	const struct in6_addr *in6;
	char *name;
	size_t namesize;
{
	const u_int8_t *n = in6->s6_addr;

	return (snprintf(name, namesize,
	    "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
	    "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.int.",
	    n[15] & 0x0f, n[15] >> 4,
	    n[14] & 0x0f, n[14] >> 4,
	    n[13] & 0x0f, n[13] >> 4,
	    n[12] & 0x0f, n[12] >> 4,
	    n[11] & 0x0f, n[11] >> 4,
	    n[10] & 0x0f, n[10] >> 4,
	    n[9] & 0x0f, n[9] >> 4,
	    n[8] & 0x0f, n[8] >> 4,
	    n[7] & 0x0f, n[7] >> 4,
	    n[6] & 0x0f, n[6] >> 4,
	    n[5] & 0x0f, n[5] >> 4,
	    n[4] & 0x0f, n[4] >> 4,
	    n[3] & 0x0f, n[3] >> 4,
	    n[2] & 0x0f, n[2] >> 4,
	    n[1] & 0x0f, n[1] >> 4,
	    n[0] & 0x0f, n[0] >> 4));
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
#ifdef HAVE_SA_LEN
		if (ifa->ifa_addr->sa_len < off + alen)
			continue;
#else
		/*
		 * We assume that sa_len is the same if sa_family is the same,
		 * however, it is not a safe assumption to make, so we
		 * check if sa_family is the ones we know of.
		 */
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			continue;
		}
#endif
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
encode_myaddrs(n, type, class, replybuf, off, buflen, naddrs, scoped, loopback)
	const char *n;
	u_int16_t type;
	u_int16_t class;
	char *replybuf;
	int off;
	int buflen;
	int *naddrs;
	int scoped;
	int loopback;
{
	struct ifaddrs *ifap = NULL, *ifa;
	char *p;
	size_t alen;
	char *abuf;
	u_int16_t ntype, nclass;
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;
	struct in6_addr in6;
	int scopecnt;
#ifdef __KAME__
	struct in6_ifreq ifr6;
	int s;
#endif

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
			sin4 = (struct sockaddr_in *)ifa->ifa_addr;
			if (!useful_sockaddr_in(sin4, loopback))
				continue;
			alen = sizeof(sin4->sin_addr);
			abuf = (char *)&sin4->sin_addr;
			ntype = T_A;
			nclass = C_IN;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (!useful_sockaddr_in6(sin6, loopback,
			    intface, ifa->ifa_name, scoped, &scopecnt))
				continue;

			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
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

#ifdef __KAME__
			/* check if the address is ready for use */
			s = socket(AF_INET6, SOCK_DGRAM, 0);
			if (s < 0)
				continue;
			memset(&ifr6, 0, sizeof(ifr6));
			strncpy(ifr6.ifr_name, ifa->ifa_name,
			    sizeof(ifr6.ifr_name));
			ifr6.ifr_addr = *sin6;
			if (ioctl(s, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
				close(s);
				continue;
			}
			close(s);
			if ((ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST) != 0)
				continue;
			if ((ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_NOTREADY) != 0)
				continue;
#endif

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

static int
ismyname(n)
	const char *n;
{

	if (strcmp(hostname, n) == 0)
		return 1;
	else if (islocalname(n) &&
	    strncmp(n, hostname, strlen(n) - strlen(MDNS_LOCALDOM)) == 0)
		return 1;
	else
		return 0;
}

static int
islocalname(n)
	const char *n;
{

	if (strlen(n) > strlen(MDNS_LOCALDOM) &&
	    strcmp(n + strlen(n) - strlen(MDNS_LOCALDOM), MDNS_LOCALDOM) == 0)
		return 1;
	else
		return 0;
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

	/*
	 * only handle successful replies over multicast, any reply
	 * over unicast
	 */
	if (qc->type == N_MULTICAST && hp->rcode != NOERROR)
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
	if (qc->type != N_MULTICAST)

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
	case NI_QTYPE_NODEADDR:
		return getans_icmp6_nodeaddr(buf, len, from, fromlen);
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
	char *p;

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
	if (strcmp(on, n) == 0)
		;
	else if (strlen(on) > strlen(n) && strncmp(on, n, strlen(n)) == 0 &&
	     strcmp(on + strlen(n), ".") == 0)
		;
	else if (strlen(on) > strlen(n) && strncmp(on, n, strlen(n)) == 0 &&
	     strcmp(on + strlen(n), "." MDNS_LOCALDOM) == 0)
		;
	else if (strlen(on) > strlen(n) && strncmp(on, n, strlen(n)) == 0 &&
	     n[strlen(n) - 1] == '.' &&
	     strcmp(on + strlen(n), MDNS_LOCALDOM) == 0)
		;
	else
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
	if (p - dnsbuf + sizeof(u_int16_t) * 3 + sizeof(u_int32_t) +
	    sizeof(struct in6_addr) >= sizeof(dnsbuf))
		goto fail;
	*(u_int16_t *)p = htons(T_AAAA);
	p += sizeof(u_int16_t);
	*(u_int16_t *)p = htons(C_IN);
	p += sizeof(u_int16_t);
	*(int32_t *)p = *ttl;	/*TTL*/
	p += sizeof(int32_t);
	*(u_int16_t *)p = htons(sizeof(struct in6_addr));
	p += sizeof(u_int16_t);
	memcpy(p, &((struct sockaddr_in6 *)from)->sin6_addr,
	    sizeof(struct in6_addr));
	p += sizeof(struct in6_addr);
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

static int
getans_icmp6_nodeaddr(buf, len, from, fromlen)
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	struct icmp6_nodeinfo *ni6;
	char dnsbuf[RECVBUFSIZ];
	HEADER *ohp, *hp;
	struct qcache *qc;
	const char *on = NULL;
	const char *d, *e;
	char *p;
	struct nodeaddr {
		int32_t ttl;
		struct in_addr in6;
	} *nodeaddr;

#if 0
	/* length validation has already been done */
	if (sizeof(*ni6) > len)
		return -1;
#endif
	ni6 = (struct icmp6_nodeinfo *)buf;

	if (dflag) {
		int i;
		printf("nodeaddr reply: ");
		for (i = 0; i < len; i++)
			printf("%02x", buf[i] & 0xff);
		printf("\n");
	}

	d = (const char *)(ni6 + 1);
	e = buf + len;
	nodeaddr = (struct nodeaddr *)d;
	if ((e - d) % sizeof(*nodeaddr))
		return -1;

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
	dprintf("validate reply: query=%s\n", on);
	if (!on || qc->qlen - (p - qc->qbuf) < 4)
		goto fail;
	if (strlen(on) == 0)
		goto fail;
	/* XXX more validation! */

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
	hp->ancount = htons(0);

	while (nodeaddr < (struct nodeaddr *)e) {
		if (encode_name(&p, sizeof(dnsbuf) - (p - dnsbuf), on) == NULL)
			goto fail;
		if (p - dnsbuf + sizeof(u_int16_t) * 3 + sizeof(u_int32_t) +
		    sizeof(struct in6_addr) >= sizeof(dnsbuf))
			goto fail;
		*(u_int16_t *)p = htons(T_AAAA);
		p += sizeof(u_int16_t);
		*(u_int16_t *)p = htons(C_IN);
		p += sizeof(u_int16_t);
		*(int32_t *)p = nodeaddr->ttl;	/*TTL*/
		p += sizeof(int32_t);
		*(u_int16_t *)p = htons(sizeof(struct in6_addr));
		p += sizeof(u_int16_t);
		memcpy(p, &nodeaddr->in6, sizeof(struct in6_addr));
		p += sizeof(struct in6_addr);
		hp->ancount = htons(ntohs(hp->ancount) + 1);
		nodeaddr++;
	}

	if (dflag)
		dnsdump("serve O", dnsbuf, p - dnsbuf, from, fromlen);

	/* XXX TC bit processing */

	sendto(qc->sd->s, dnsbuf, p - dnsbuf, 0, qc->from, qc->fromlen);

	if (on) {
		/* LINTED const cast */
		free((char *)on);
	}

	return 0;

fail:
	if (on) {
		/* LINTED const cast */
		free((char *)on);
	}

	return -1;
}

static int
relay(sd, buf, len, from, fromlen)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{

	if (!Nflag)
		return relay_dns(sd, buf, len, from, fromlen);
	else
		return relay_icmp6(sd, buf, len, from, fromlen);
}

/*
 * relay inbound DNS packet to remote DNS server (unicast UDP, multicast UDP
 * or TCP).
 */
static int
relay_dns(sd, buf, len, from, fromlen)
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
	int multicast, unicast;
	const char *n = NULL;
	const char *d;
	enum sdtype servtype;	/* type of server we want to relay to */
	size_t rbuflen = PACKETSZ;
	int edns0len = -1;
	char *edns0 = NULL;
	struct timeval tv;

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

	/* if the querier's buffer size is bigger than mine, lower it */
	if (rbuflen > RECVBUFSIZ && edns0) {
		if (update_edns0(hp, edns0, len - (edns0 - buf),
		    RECVBUFSIZ) < 0) {
			/* LINTED const cast */
			free((char *)n);
			return -1;
		}
		dprintf("lower EDNS0 to %lu on relay\n", (u_long)RECVBUFSIZ);
	}

	if (islocalname(n)) {
		multicast = 1;
		unicast = 0;
	} else {
		multicast = 0;
		unicast = 1;
	}
	/* LINTED const cast */
	free((char *)n);

	if (hp->qr == 0 && hp->opcode == QUERY) {
		/* query - relay it */
		qc = newqcache(from, fromlen, buf, len,
		    multicast ? N_MULTICAST : N_UNICAST);
		gettimeofday(&qc->ttq, NULL);
		qc->ttq.tv_sec += MDNS_TIMEO;
		qc->sd = sd;
		qc->rbuflen = rbuflen;

		ord = hp->rd;

		qc->id = hp->id = next_dnsid();

		sent = 0;
		for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
			if (dflag)
				printnsdb(ns);
			switch (ns->type) {
			case N_MULTICAST:
				if (!multicast)
					continue;
				break;
			case N_UNICAST:
				if (!unicast)
					continue;
				break;
			}

			gettimeofday(&tv, 0);
#if 0
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
#endif

			if (0 > edns0len && len > PACKETSZ) {
				/* no EDNS0 on big message -> use TCP */
				if (multicast)
					continue;
				servtype = S_TCP;
			} else if (ns->type == N_MULTICAST)
				servtype = S_MULTICAST;
			else
				servtype = S_UNICAST;

			sd = af2sockdb(ns->addr->sa_family, servtype);
			if (sd == NULL)
				continue;

			hp->rd = ord;
			/* never ask for recursion on multicast query */
			if (ns->type == N_MULTICAST)
				hp->rd = 0;

			if (dflag)
				dnsdump("relay O", buf, len, ns->addr,
				    ns->addrlen);
			if (sd->type == S_TCP) {
				u_int16_t l16;

				l16 = htons(len & 0xffff);
				(void)write(sd->s, &l16, sizeof(l16));
			}
			if (sendto(sd->s, buf, len, 0, ns->addr,
			    ns->addrlen) == len) {
#if 0
				dprintf("sock %d sent\n", i);
#endif
				sent++;
				gettimeofday(&ns->lasttx, NULL);
				ns->nquery++;
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
 * parse inbound DNS packet and issue an ICMPv6 name information query.
 * or TCP).
 */
static int
relay_icmp6(sd, buf, len, from, fromlen)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
{
	HEADER *hp;
	struct qcache *qc;
	int sent;
	const char *n = NULL;
	const char *d;
	size_t rbuflen = PACKETSZ;
	int edns0len = -1;
	struct addrinfo hints, *res;
	char icmp6buf[RECVBUFSIZ];
	u_int16_t qtype, qclass;
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	int salen;

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
	qtype = ntohs(*(u_int16_t *)&d[0]);
	qclass = ntohs(*(u_int16_t *)&d[2]);
	if (!(qtype == T_AAAA && qclass == C_IN)) {
		/* LINTED const cast */
		free((char *)n);
		return -1;
	}
	d += 4;	/* skip type/class on query */

	/* XXX should drop assumption on packet format */
	if (ntohs(hp->qdcount) == 1 && ntohs(hp->ancount) == 0 &&
	    ntohs(hp->nscount) == 0) {
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

	if (rbuflen > RECVBUFSIZ)
		rbuflen = RECVBUFSIZ;

	if (!islocalname(n)) {
		/* LINTED const cast */
		free((char *)n);
		return -1;
	}

	/* LINTED const cast */
	free((char *)n);

	if (dflag)
		dnsdump("relay I", buf, len, from, fromlen);
	if (hp->qr == 0 && hp->opcode == QUERY) {
		/* query - relay it */
		qc = newqcache(from, fromlen, buf, len, N_MULTICAST);
		gettimeofday(&qc->ttq, NULL);
		qc->ttq.tv_sec += MDNS_TIMEO;
		qc->sd = sd;
		qc->rbuflen = rbuflen;
		qc->id = next_dnsid();

		len = ping6(icmp6buf, sizeof(icmp6buf), qc, "ff02::1",
		    "ff02::1", 0);

		sd = af2sockdb(PF_INET6, S_ICMP6);
		if (sd == NULL)
			return -1;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_INET6;
		hints.ai_socktype = SOCK_RAW;
		hints.ai_protocol = IPPROTO_ICMPV6;
		if (getaddrinfo("ff02::1", NULL, &hints, &res))
			return -1;
		if (res->ai_next || res->ai_family != AF_INET6 ||
		    res->ai_addrlen > sizeof(ss)) {
			freeaddrinfo(res);
			return -1;
		}
		memcpy(&ss, res->ai_addr, res->ai_addrlen);
		salen = res->ai_addrlen;
		freeaddrinfo(res);

		/* multicast outgoing interface is already configured */
		sent = 0;
		if (sendto(sd->s, icmp6buf, len, 0, sa, salen) == len) {
#if 0
			dprintf("sock %d sent\n", i);
#endif
			sent++;
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
 * construct ping6 packet.
 */
static ssize_t
ping6(buf, siz, qc, addr, subj, mode)
	char *buf;
	size_t siz;
	const struct qcache *qc;
	const char *addr;
	const char *subj;
	int mode;
{
	struct icmp6_nodeinfo *ni6;
	struct in6_addr addr6;
	struct in6_addr subj6;
	struct addrinfo hints, *res;
	ssize_t l;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;
	if (getaddrinfo(addr, NULL, &hints, &res))
		return -1;
	if (res->ai_next || res->ai_family != AF_INET6) {
		freeaddrinfo(res);
		return -1;
	}
	memcpy(&addr6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
	    sizeof(addr6));
	freeaddrinfo(res);

	if (getaddrinfo(subj, NULL, &hints, &res))
		return -1;
	if (res->ai_next || res->ai_family != AF_INET6) {
		freeaddrinfo(res);
		return -1;
	}
	memcpy(&subj6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
	    sizeof(subj6));
	freeaddrinfo(res);

	l = sizeof(*ni6) + sizeof(subj6);
	if (l > siz)
		return -1;

	switch (mode) {
	case 0:	/* ping6 -w */
		ni6 = (struct icmp6_nodeinfo *)buf;
		memset(ni6, 0, sizeof(*ni6));
		ni6->ni_type = ICMP6_NI_QUERY;
		ni6->ni_code = /* ICMP6_NI_SUBJ_IPV6 */ 0;
		ni6->ni_qtype = htons(NI_QTYPE_FQDN);
		memcpy(ni6->icmp6_ni_nonce, &qc->id, sizeof(qc->id));
		memcpy(ni6 + 1, &subj6, sizeof(subj6));
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
	int l;
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

	if (ismyname(n)) {
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
		    sizeof(replybuf), &count, scoped, loopback);
		if (l <= 0)
			goto fail;
		p += l;
		hp->ancount = htons(count);

		if (dflag)
			dnsdump("serve O", replybuf, p - replybuf, from,
			    fromlen);

		if (sd->type == S_TCP) {
			u_int16_t l16;

			l16 = htons((p - replybuf) & 0xffff);
			(void)write(sd->s, &l16, sizeof(l16));
		} else if (p - replybuf > rbuflen) {
			p -= l;
			hp->ancount = 0;
			hp->tc = 1;
		}
		sendto(sd->s, replybuf, p - replybuf, 0, from, fromlen);

		if (n) {
			/* LINTED const cast */
			free((char *)n);
		}
		return SERVE_DONE;
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

static void
reply(sd, buf, len, from, fromlen, scoped, loopback, errorcode)
	struct sockdb *sd;
	const char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
	int scoped;
	int loopback;
	int errorcode;
{
	char replybuf[RECVBUFSIZ];
	HEADER *hp;

	memcpy(replybuf, buf, len);
	hp = (HEADER *)replybuf;
	hp->qr = 1;
	hp->aa = 1;
	hp->ra = 0;
	hp->rcode = errorcode;
	hp->ancount = htons(0);
	hp->nscount = htons(0);
	hp->arcount = htons(0);

	if (sd->type == S_TCP) {
		u_int16_t l16;

		l16 = htons(len & 0xffff);
		(void)write(sd->s, &l16, sizeof(l16));
	}
	sendto(sd->s, replybuf, len, 0, from, fromlen);
}

static int
serve_update(sd, buf, len, from, fromlen, scoped, loopback)
	struct sockdb *sd;
	char *buf;
	int len;
	struct sockaddr *from;
	int fromlen;
	int scoped;
	int loopback;
{
	HEADER *hp = (HEADER *)buf;
	const char *n1 = NULL, *n2 = NULL;
	const char *d;
	u_int16_t type, class;
	u_int16_t type_pre, class_pre;

	if (ntohs(hp->qdcount) != 1)
		return SERVE_DONE;
	d = (const char *)(hp + 1);
	n1 = decode_name(&d, len - (d - buf));
	if (!n1 || len - (d - buf) < 4)
		goto fail;
	type = ntohs(*(u_int16_t *)&d[0]);
	class = ntohs(*(u_int16_t *)&d[2]);
	d += 4;		/* "d" points to end of zone section */
	if (class != C_IN)
		goto fail;
	if (!ismyname(n1) && !match_ptrquery(n1))
		goto fail;

	if (hp->qr == 1) {
		if (hp->rcode == YXRRSET)
			printf("collision on name %s\n", n1);
	} else {
		if (ntohs(hp->ancount) != 1)
			goto fail;

		/* pre-req section */
		n2 = decode_name(&d, len - (d - buf));
		if (!n2 || len - (d - buf) < 4)
			goto fail;
		if (strcmp(n1, n2) != 0)
			goto fail;
		type_pre = ntohs(*(u_int16_t *)&d[0]);
		class_pre = ntohs(*(u_int16_t *)&d[2]);
		d += 4;		/* "d" points to end of zone section */

		if (class_pre == C_NONE) {
			reply (sd, buf, d - buf, from, fromlen, scoped,
			    loopback, YXRRSET);
			goto fail;
		}
	}
	
fail:
	if (n1) {
		/* LINTED const cast */
		free((char *)n1);
	}
	if (n2) {
		/* LINTED const cast */
		free((char *)n2);
	}
	return SERVE_DONE;	/* error */
}

/*
 * parse inbound DNS query packet, and try to respond with answer from
 * local configuration (like hostname, ifconfig).
 *
 * XXX should defer response with random delay, and supress duplicated
 * replies (mdns-00 page 3)
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
	    ntohl(((struct sockaddr_in *)from)->sin_addr.s_addr) == INADDR_LOOPBACK) {
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
	case NS_UPDATE_OP:
		return serve_update(sd, buf, len, from, fromlen,
		    scoped, loopback);
	default:
		return SERVE_DONE; /* drop */
	}
}
