 /*	$KAME: wru.c,v 1.13 2005/04/14 06:22:37 suz Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/queue.h>

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/if_dl.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <netdb.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

/* for compatibility with old definitions */
#ifndef NI_QTYPE_NODENAME
#define NI_QTYPE_NODENAME NI_QTYPE_DNSNAME
#endif
#ifndef NI_NODENAME_FLAG_VALIDTTL
#define NI_NODENAME_FLAG_VALIDTTL NI_FQDN_FLAG_VALIDTTL
#endif

static void update_nonce __P((u_int8_t *, size_t));
static int do_reply __P((char *, int, int, char *, struct sockaddr *,
			 socklen_t));
static char *dnsdecode __P((const u_char **, const u_char *,
			    const u_char *, u_char *, size_t));
static void pr_nodeaddr __P((struct icmp6_nodeinfo *, int));

static int set_zone __P((struct sockaddr *));
static void timeval_add __P((struct timeval *, struct timeval *,
			     struct timeval *));
static void timeval_sub __P((struct timeval *, struct timeval *,
			     struct timeval *));
static char *sa2str __P((struct sockaddr *, socklen_t));
static void usage __P((void));

static int opt_flags;
#define F_VERBOSE 0x1
#define F_MULTIWAIT 0x2
#define F_SINGLEWAIT 0x4
#define F_TRYALL 0x8

#define DEFAULTHOST "ff02::1"

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch, ret_ga, i, s;
	int qtype = NI_QTYPE_NODENAME;
	int nicode = ICMP6_NI_SUBJ_IPV6;
	int qdatalen = sizeof(struct in6_addr), qbuflen;
	int count = 1;
	int rsbsize = 81920;	/* about 40 clusters */
	char *host, *zone = NULL, *qbuf, *qdata, rbuf[2048];
	u_int16_t qflags = 0;
	u_int8_t nonce[8];
	struct addrinfo hints, *res, *res0;
	struct icmp6_filter filter;
	struct icmp6_nodeinfo *ni;
	fd_set *fdmaskp;
	int fdmasks;
	int interval = 1;
	struct timeval tv_interval;
#ifndef __OpenBSD__
	int ident;
	struct timeval tv;
#endif

	while ((ch = getopt(argc, argv, "1Ama:c:i:vz:")) != -1) {
		switch (ch) {
		case '1':
			opt_flags |= F_SINGLEWAIT;
			break;

		case 'A':
			opt_flags |= F_TRYALL;
			break;

		case 'a':
		{
			char *cp;

			qtype = NI_QTYPE_NODEADDR;
			for (cp = optarg; *cp != '\0'; cp++) {
				switch (*cp) {
				case 'a':
					qflags |= NI_NODEADDR_FLAG_ALL;
					break;
				case 'c':
				case 'C':
					qflags |= NI_NODEADDR_FLAG_COMPAT;
					break;
				case 'l':
				case 'L':
					qflags |= NI_NODEADDR_FLAG_LINKLOCAL;
					break;
				case 's':
				case 'S':
					qflags |= NI_NODEADDR_FLAG_SITELOCAL;
					break;
				case 'g':
				case 'G':
					qflags |= NI_NODEADDR_FLAG_GLOBAL;
					break;
				case 'A': /* experimental. not in the spec */
#ifdef NI_NODEADDR_FLAG_ANYCAST
					qflags |= NI_NODEADDR_FLAG_ANYCAST;
					break;
#else
					errx(1, "-a A is not supported on "
					     "the platform");
#endif
				default:
					usage();
				}
			}
		}
		break;

		case 'c':
			count = atoi(optarg);
			break;

		case 'i':
			interval = atoi(optarg);
			break;

		case 'm':
			opt_flags |= F_MULTIWAIT;
			break;

		case 'v':
			opt_flags |= F_VERBOSE;
			break;

		case 'z':
			zone = optarg;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((opt_flags & F_SINGLEWAIT) && (opt_flags & F_MULTIWAIT))
		errx(1, "-1 and -m are exclusive");

	if (argc < 1)
		host = DEFAULTHOST;
	else
		host = argv[0];

	if (zone) {
		int newhostlen;
		char *newhost, *cp;

		/* construct host%zone */
		if (asprintf(&newhost, "%s%%%s", host, zone) < 0)
			err(1, "malloc");
			/* NOTREACHED */
		host = newhost;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;
	ret_ga = getaddrinfo(host, NULL, &hints, &res0);
	if (ret_ga)
		errx(1, "%s", gai_strerror(ret_ga));
	if (argc < 1 && !zone) {
		/* try to set the default link ID */
		if (res0->ai_next) {
			errx(1,
			     "getaddrinfo returned multiple addresses for %s",
			     DEFAULTHOST);
		}
		set_zone(res0->ai_addr);
	}

	/* set up a query socket */
	if ((s = socket(res0->ai_family, res0->ai_socktype,
			res0->ai_protocol)) < 0) {
		err(1, "socket");
	}
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_NI_REPLY, &filter);
	if (setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
		       sizeof(filter)) < 0) {
		err(1, "setsockopt(ICMP6_FILTER");
	}
	/*
	 * enlarge the size of the receive socket buffer.
	 * the default size of (some versions of) BSDs is too small to store
	 * about 10 mbuf clusters at a same time.
	 */
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&rsbsize,
		       sizeof(rsbsize))) {
		err(1, "setsockopt(SO_RCVBUF, %d)", rsbsize);
	}

	/* allocate an array of FD masks for select(2) */
	fdmasks = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
	if ((fdmaskp = malloc(fdmasks)) == NULL)
		err(1, "malloc(%d)", fdmasks);

	/* set the wait interval */
	memset(&tv_interval, 0, sizeof(tv_interval));
	tv_interval.tv_sec = interval;

	/*
	 * allocate a buffer for queries, then construct constant members of
	 * the query.
	 */
	qbuflen = qdatalen + sizeof(struct icmp6_nodeinfo);
	if ((qbuf = malloc(qbuflen)) == NULL)
		err(1, "malloc(%d)", qdatalen);
	ni = (struct icmp6_nodeinfo *)qbuf;
	ni->ni_type = ICMP6_NI_QUERY;
	ni->ni_code = nicode;
	ni->ni_qtype = htons(qtype);
	ni->ni_flags = qflags;
	memset(nonce, 0, sizeof(nonce));

	/* initialize of random number generation for nonce */
#ifndef __OpenBSD__
	ident = getpid() & 0xFFFF;
	gettimeofday(&tv, NULL);
	srand((unsigned int)(tv.tv_sec ^ tv.tv_usec ^ (long)ident));
#endif

	for (res = res0; res; res = res->ai_next) {
		struct sockaddr_in6 *dst = (struct sockaddr_in6 *)res->ai_addr;
		int multiwait = 0, success = 0;

		qdata = (char *)&dst->sin6_addr;
		qdatalen = sizeof(struct in6_addr);
		if ((opt_flags & F_MULTIWAIT))
			multiwait = 1;
		else if (IN6_IS_ADDR_MULTICAST(&dst->sin6_addr) &&
			 !(opt_flags & F_SINGLEWAIT)) {
			multiwait = 1;
		}

		for (i = 0; i < count; i++) {
			struct sockaddr_storage from_ss;
			struct sockaddr *from = (struct sockaddr *)&from_ss;
			socklen_t fromlen;
			struct timeval remain, current, timeo;
			int cc, n;

			/* update a query packet with dynamic parameters */
			update_nonce(nonce, sizeof(nonce));
			memcpy(ni->icmp6_ni_nonce, nonce, sizeof(nonce));
			if (qdata)
				memcpy(ni + 1, qdata, qdatalen);

			gettimeofday(&current, NULL);
			timeval_add(&current, &tv_interval, &timeo);

			/* send the query */
			if (sendto(s, qbuf, qbuflen, 0,
				   res->ai_addr, res->ai_addrlen) < 0) {
				warn("sendto");
				goto nextaddress;
			}

			/* wait for a reply */
		  wait_reply:
			timeval_sub(&timeo, &current, &remain);
			memset(fdmaskp, 0, fdmasks); /* XXX */
			FD_SET(s, fdmaskp);
			if ((n = select(s + 1, fdmaskp, NULL,
					NULL, &remain)) < 0) {
				err(1, "select");
			} else if (n == 0) /* timeout */
				break;

			/* get a reply */
			fromlen = sizeof(from_ss);
			cc = recvfrom(s, rbuf, sizeof(rbuf), 0,
				      from, &fromlen);
			if (cc < 0)
				err(1, "recvfrom");

			/* validate and print the reply. */
			if (do_reply(rbuf, cc, qtype, nonce,
				     from, fromlen) == 0) {
				success = 1;
			}

			if (multiwait)
				goto wait_reply;

			if (success)
				break;
		}

	  nextaddress:
		if (success && !(opt_flags & F_TRYALL))
			break;
	}

	freeaddrinfo(res0);
	free(fdmaskp);
	free(qbuf);

	exit(0);
}

static void
update_nonce(nonce, nsize)
	u_int8_t *nonce;
	size_t nsize;
{
	int i;

#ifndef __OpenBSD__
	memset(nonce, 0, nsize);
	for (i = 0; i < nsize; i += sizeof(int))
		*((int *)&nonce[i]) = rand();
#else
	memset(nonce, 0, nsize);
	for (i = 0; i < nsize; i += sizeof(u_int32_t))
		*((u_int32_t *)&nonce[i]) = arc4random();
#endif
}

static int
do_reply(buf, len, qtype, nonce, from, fromlen)
	char *buf, *nonce;
	int len, qtype;
	struct sockaddr *from;
	socklen_t fromlen;
{
#define safeputc(c)	printf((isprint((c)) ? "%c" : "\\%03o"), c)
	int i;
	u_int16_t rflags;
	char *cp, *end = buf + len;
	char dnsname[MAXDNAME + 1];
	struct icmp6_nodeinfo *ni = (struct icmp6_nodeinfo *)buf;
	struct sockaddr_in6 *from6 = (struct sockaddr_in6 *)from;
	int32_t ttl;

	/* validate the from address */
	if (fromlen != sizeof(*from6)) {
		warnx("fromlen is odd: %d", fromlen);
		return(-1);
	}
	if (from->sa_family != AF_INET6) {
		warnx("invalid address family of the source: %d",
		      from->sa_family);
		return(-1);
	}

	/* validate the packet */
	if (len < sizeof(*ni)) {
		if ((opt_flags & F_VERBOSE)) {
			printf("Invalid reply length (%d) from %s", len,
			       sa2str(from, fromlen));
		}
		return(-1);
	}
	if (ni->ni_type != ICMP6_NI_REPLY) {
		if ((opt_flags & F_VERBOSE)) {
			printf("Mismatched ICMP type (%x) from %s\n",
			       ni->ni_type, sa2str(from, fromlen));
		}
		return(-1);
	}
	if (ni->ni_qtype != htons(qtype)) {
		if ((opt_flags & F_VERBOSE)) {
			printf("Mismatched qtype (%x) from %s\n",
			       ntohs(ni->ni_qtype), sa2str(from, fromlen));
		}
		return(-1);
	}
	if (memcmp(ni->icmp6_ni_nonce, nonce, sizeof(ni->icmp6_ni_nonce))) {
		if ((opt_flags & F_VERBOSE)) {
			printf("Mismatched nonce from %s",
			       sa2str(from, fromlen));
		}
		return(-1);
	}
	rflags = ni->ni_flags;
	
	switch(ntohs(ni->ni_code)) {
	case ICMP6_NI_SUCCESS:
		break;
	case ICMP6_NI_REFUSED:
		if ((opt_flags & F_VERBOSE))
			printf("query refused from %s, qtype 0x%x\n",
			       sa2str(from, fromlen), qtype);
		return(-1);
	case ICMP6_NI_UNKNOWN:
		if ((opt_flags & F_VERBOSE))
			printf("%s did not know the qtype 0x%x\n",
			       sa2str(from, fromlen), qtype);
		return(-1);
	default:
		if ((opt_flags & F_VERBOSE))
			printf("unknown code from %s: 0x%x\n",
			       sa2str(from, fromlen), qtype);
		return(-1);
	}

	cp = (char *)(ni + 1);
	switch(qtype) {
	case NI_QTYPE_NODENAME:
		printf("%s is ", sa2str(from, fromlen));

		if (end - cp < sizeof(ttl))
			break;
		ttl = ntohl(*(int32_t *)cp);
		cp += sizeof(ttl);

		if (*cp == end - cp - 1) {
			/* the sender implemented an old version */
			cp++;	/* skip length */
			while (cp < end) {
				safeputc(*cp & 0xff);
				cp++;
			}

			if ((opt_flags & F_VERBOSE))
				printf(" (old spec)");
		} else {
			i = 0;
			while (cp < end) {
				if (dnsdecode((const u_char **)&cp, end,
					      (const u_char *)(ni + 1),
					      dnsname, sizeof(dnsname))
				    == NULL) {
					printf("???");
					break;
				}
				/*
				 * name-lookup special handling for truncated
				 * name
				 */
				if (cp + 1 <= end && !*cp &&
				    strlen(dnsname) > 0) {
					dnsname[strlen(dnsname) - 1] = '\0';
					cp++;
				}
				printf("%s%s", i > 0 ? "," : "", dnsname);
			}
		}

		if ((opt_flags & F_VERBOSE) ||
		    (rflags & NI_NODENAME_FLAG_VALIDTTL))
			printf(" (TTL=%ld)", (long int)ttl);

		putchar('\n');
		break;

	case NI_QTYPE_NODEADDR:
		printf("%s has ", sa2str(from, fromlen));
		pr_nodeaddr(ni, end - (char *)ni);
		break;
	}

	return(0);
#undef safeputc
}		

static char *
dnsdecode(sp, ep, base, buf, bufsiz)
	const u_char **sp;
	const u_char *ep;
	const u_char *base;	/*base for compressed name*/
	u_char *buf;
	size_t bufsiz;
{
	int i;
	const u_char *cp;
	char cresult[MAXDNAME + 1];
	const u_char *comp;
	int l;

	cp = *sp;
	*buf = '\0';

	if (cp >= ep)
		return NULL;
	while (cp < ep) {
		i = *cp;
		if (i == 0 || cp != *sp) {
			if (strlcat(buf, ".", bufsiz) >= bufsiz)
				return NULL;	/* result overrun */
		}
		if (i == 0)
			break;
		cp++;

		if ((i & 0xc0) == 0xc0 && cp - base > (i & 0x3f)) {
			/* DNS compression */
			if (!base)
				return NULL;

			comp = base + (i & 0x3f);
			if (dnsdecode(&comp, cp, base, cresult,
			    sizeof(cresult)) == NULL)
				return NULL;
			if (strlcat(buf, cresult, bufsiz) >= bufsiz)
				return NULL;	/* result overrun */
			break;
		} else if ((i & 0x3f) == i) {
			if (i > ep - cp)
				return NULL;	/* source overrun */
			while (i-- > 0 && cp < ep) {
				l = snprintf(cresult, sizeof(cresult),
				    isprint(*cp) ? "%c" : "\\%03o", *cp & 0xff);
				if (l >= sizeof(cresult) || l < 0)
					return NULL;
				if (strlcat(buf, cresult, bufsiz) >= bufsiz)
					return NULL;	/* result overrun */
				cp++;
			}
		} else
			return NULL;	/* invalid label */
	}
	if (i != 0)
		return NULL;	/* not terminated */
	cp++;
	*sp = cp;
	return buf;
}

static void
pr_nodeaddr(ni, nilen)
	struct icmp6_nodeinfo *ni;
	int nilen;
{
	u_char *cp = (u_char *)(ni + 1);
	char ntop_buf[INET6_ADDRSTRLEN];
	int withttl = 0;

	nilen -= sizeof(struct icmp6_nodeinfo);

	if ((opt_flags & F_VERBOSE)) {
		if (ni->ni_flags & NI_NODEADDR_FLAG_TRUNCATE)
			(void)printf(" truncated");
	}
	putchar('\n');
	if (nilen <= 0)
		printf("  no address\n");

	/*
	 * In icmp-name-lookups 05 and later, TTL of each returned address
	 * is contained in the resposne. We try to detect the version
	 * by the length of the data, but note that the detection algorithm
	 * is incomplete. We assume the latest draft by default.
	 */
	if (nilen % (sizeof(u_int32_t) + sizeof(struct in6_addr)) == 0)
		withttl = 1;
	while (nilen > 0) {
		u_int32_t ttl;

		if (withttl) {
			/* XXX: alignment? */
			ttl = (u_int32_t)ntohl(*(u_int32_t *)cp);
			cp += sizeof(u_int32_t);
			nilen -= sizeof(u_int32_t);
		}

		if (inet_ntop(AF_INET6, cp, ntop_buf, sizeof(ntop_buf)) ==
		    NULL) {
			strlcpy(ntop_buf, "?", sizeof(ntop_buf));
		}
		printf("  %s", ntop_buf);
		if (withttl) {
			if (ttl == 0xffffffff) {
				/*
				 * XXX: can this convention be applied to all
				 * type of TTL (i.e. non-ND TTL)?
				 */
				printf("(TTL=infty)");
			}
			else
				printf("(TTL=%u)", ttl);
		}
		putchar('\n');

		nilen -= sizeof(struct in6_addr);
		cp += sizeof(struct in6_addr);
	}
}

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define NEXTSA(s) \
	((s) = (struct sockaddr *)(ROUNDUP((s)->sa_len) + (char *)(s)))
static int
set_zone(dst)
	struct sockaddr *dst;
{
	size_t needed;
	int mib[] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };
	int s;
	char *buf, *next, *lim, ifname[IFNAMSIZ];
	struct rt_msghdr *rtm;
	struct in6_ndifreq ndifreq;
	u_long defif;
	u_int32_t zoneid = 0;

	/*
	 * first try to get the default interface in the kernel,
	 * if specified.
	 */
	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&ndifreq, 0, sizeof(ndifreq));
	strlcpy(ndifreq.ifname, "lo0", sizeof(ndifreq.ifname)); /* dummy */

	if (ioctl(s, SIOCGDEFIFACE_IN6, (caddr_t)&ndifreq) < 0)
 		err(1, "ioctl(SIOCGDEFIFACE_IN6)");
	close(s);

	if ((defif = ndifreq.ifindex) > 0)
		goto setzone;

	/* then get the default route, and use the outgoing interface. */
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
		err(1, "route sysctl estimate");
	if ((buf = malloc(needed)) == 0)
		errx(1, "out of space");
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
		err(1, "sysctl of routing table");
	lim  = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		struct sockaddr *sa;

		rtm = (struct rt_msghdr *)next;
		if ((rtm->rtm_addrs & (RTA_DST | RTA_NETMASK)) !=
		    (RTA_DST | RTA_NETMASK)) {
			continue;
		}

		/* get the destination, skip it if it's not :: */
		sa = (struct sockaddr *)(rtm + 1);
		if (sa->sa_family != AF_INET6 ||
		    !IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)sa)->sin6_addr)) {
			continue;
		}

		/* get the netmask, skip it if it's not the null mask */
		NEXTSA(sa);
		if ((rtm->rtm_addrs & RTA_GATEWAY))
			NEXTSA(sa);
		if (sa->sa_family != AF_UNSPEC || sa->sa_len > 0)
			continue;

		defif = rtm->rtm_index;
		goto setzone;
	}
	warnx("can't find the default interface");
	return(0);		/* exit? */

  setzone:
	if (if_indextoname(defif, ifname) == NULL)
		err(1, "if_indextoname(%d)", defif);
#ifdef HAVE_SCOPELIB
	if (inet_zoneid(dst->sa_family, addr2scopetype(dst), ifname, &zoneid))
		err(1, "inet_zoneid");
#else
 	{
		struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;
 
		if (IN6_IS_ADDR_LINKLOCAL(&dst6->sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&dst6->sin6_addr)) {
			zoneid = defif;
		}
	}
#endif
	((struct sockaddr_in6 *)dst)->sin6_scope_id = zoneid;

	return(0);
}

static char *
sa2str(sa, salen)
	struct sockaddr *sa;
	socklen_t salen;
{
	static char buf[8][NI_MAXHOST];
	static int round = 0;
	char *cp;

	round = (round + 1) & 7;
	cp = buf[round];

	if (getnameinfo(sa, salen, cp, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
		strlcpy(cp, "???", sizeof(buf[round]));

	return(cp);
}

/* result = a + b */
#define MILLION 1000000
static void
timeval_add(struct timeval *a, struct timeval *b, struct timeval *result)
{
	long l;

	if ((l = a->tv_usec + b->tv_usec) < MILLION) {
		result->tv_usec = l;
		result->tv_sec = a->tv_sec + b->tv_sec;
	}
	else {
		result->tv_usec = l - MILLION;
		result->tv_sec = a->tv_sec + b->tv_sec + 1;
	}
}

/* result = a - b.  if a < b, result will be 0. */
static void
timeval_sub(struct timeval *a, struct timeval *b, struct timeval *result)
{
	long l;

	if (a->tv_sec < b->tv_sec ||
	    (a->tv_sec == b->tv_sec && a->tv_sec <= b->tv_usec)) {
		result->tv_sec = result->tv_usec = 0;
	} if ((l = a->tv_usec - b->tv_usec) >= 0) {
		result->tv_usec = l;
		result->tv_sec = a->tv_sec - b->tv_sec;
	}
	else {
		result->tv_usec = MILLION + l;
		result->tv_sec = a->tv_sec - b->tv_sec - 1;
	}
}

static void
usage()
{
	fprintf(stderr, "usage: wru [-(1|m)] [-Av] [-a [aAclsg]] "
		"[-c count] [-i interval] [-z zone] [host]\n");
	exit(1);
}
