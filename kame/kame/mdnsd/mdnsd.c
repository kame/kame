/*	$KAME: mdnsd.c,v 1.14 2000/05/31 11:59:41 itojun Exp $	*/

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
#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "mdnsd.h"
#include "db.h"
#include "mediator_compat.h"

#define MAXSOCK		20

u_int16_t dnsid;
const char *srcport = "53";
const char *dstport = MDNS_PORT;
const char *dnsserv = NULL;
const char *intface = NULL;
int sockaf[MAXSOCK];
int sock[MAXSOCK];
int sockflag[MAXSOCK];
int nsock = 0;
int family = PF_UNSPEC;
static char hostnamebuf[MAXHOSTNAMELEN];
const char *hostname = NULL;
static int mcasthops = 1;
static int mcastloop = 0;
int dflag = 1;
struct timeval hz = { 1, 0 };	/* timeout every 1 second */
static int mflag;

static void usage __P((void));
static int getsock __P((int, const char *, const char *, int, int));
static int getsock0 __P((const struct addrinfo *));
static int join __P((int, int, const char *));
static int join0 __P((int, const struct addrinfo *));
static int setif __P((int, int, const char *));
static int iscanon __P((const char *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	int i;
	int ready4, ready6;

	while ((ch = getopt(argc, argv, "46d:h:i:mp:P:")) != EOF) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'd':
			if (iscanon(optarg) == 0) {
				errx(1, "%s: not a canonical name", optarg);
				/*NOTREACHED*/
			}
			dnsserv = optarg;
			break;
		case 'D':
			dflag++;
		case 'h':
			hostname = optarg;
			break;
		case 'i':
			intface = optarg;
			break;
		case 'm':
			mflag++;
			break;
		case 'p':
			srcport = optarg;
			break;
		case 'P':
			dstport = optarg;
			mcastloop = 1;
			break;
		default:
			usage();
			exit(1);
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (!intface) {
		usage();
		exit(1);
		/*NOTREACHED*/
	}
	while (argc-- > 0) {
		if (addserv(*argv, -1) != 0) {
			errx(1, "%s: failed to add it to db", *argv);
			/*NOTREACHED*/
		}
		argv++;
	}

	srandom(time(NULL) ^ getpid());
	dnsid = random() & 0xffff;

	if (getsock(family, NULL, srcport, SOCK_DGRAM, AI_PASSIVE) != 0) {
		err(1, "getsock");
		/*NOTREACHED*/
	}
	if (nsock == 0) {
		errx(1, "no socket");
		/*NOTREACHED*/
	}
	dprintf("%d sockets available\n", nsock);

	if (mflag) {
		int i;

		i = nsock;
		if (getsock(AF_INET, NULL, MEDIATOR_CTRL_PORT, SOCK_DGRAM, 0)
		    != 0) {
			err(1, "getsock(mediator)");
			/*NOTREACHED*/
		}
		if (i == nsock) {
			errx(1, "no mediator socket");
			/*NOTREACHED*/
		}
		for (/*nothing*/; i < nsock; i++) {
			sockflag[i] |= SOCK_MEDIATOR;
			dprintf("%d: mediator socket\n", i);
		}
	}

	ready4 = ready6 = 0;
	for (i = 0; i < nsock; i++) {
		if ((sockflag[i] & SOCK_MEDIATOR) != 0)
			continue;

		switch (sockaf[i]) {
		case AF_INET6:
			ready6++;
			if (join(sock[0], sockaf[i], MDNS_GROUP6) < 0) {
				err(1, "join");
				/*NOTREACHED*/
			}
			break;
#if 0
		case AF_INET:
			ready4++;
			break;
#endif
		}

		if (setif(sock[i], sockaf[i], intface) < 0) {
			errx(1, "setif");
			/*NOTREACHED*/
		}
	}

	if (ready4)
		(void)addserv(MDNS_GROUP4, -1);
	if (ready6)
		(void)addserv(MDNS_GROUP6, -1);

	if (LIST_FIRST(&nsdb) == NULL) {
		errx(1, "no DNS server to contact");
		/*NOTREACHED*/
	}

	if (!hostname) {
		if (gethostname(hostnamebuf, sizeof(hostnamebuf)) != 0) {
			err(1, "gethostname");
			/*NOTREACHED*/
		}
		hostname = hostnamebuf;
	}
	dprintf("hostname=\"%s\"\n", hostname);

	mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr,
"usage: mdnsd [-46Dm] [-d server] [-h hostname] [-p srcport] [-P dstport]\n"
"             -i iface [userv...]\n");
}

static int
getsock(af, host, serv, socktype, flags)
	int af;
	const char *host;
	const char *serv;
	int socktype, flags;
{
	struct addrinfo hints, *res, *ai;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = socktype;
	hints.ai_flags = flags;
	error = getaddrinfo(host, serv, &hints, &res);
	if (error) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (nsock < sizeof(sock) / sizeof(sock[0])) {
			sock[nsock] = getsock0(ai);
			sockaf[nsock] =ai->ai_family;
			if (sock[nsock] >= 0)
				nsock++;
		} else
			break;
	}

	freeaddrinfo(res);
	return 0;
}

static int
getsock0(ai)
	const struct addrinfo *ai;
{
	int s;
	const int yes = 1;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
#ifdef IN_WITHSCOPEID
	const int niflags = NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
#else
	const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#endif

	if (dflag &&
	    getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf), niflags) == 0) {
		dprintf("getsock0: %s %s\n", hbuf, sbuf);
	}

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s < 0) {
		dprintf("socket: %s\n", strerror(errno));
		return -1;
	}
	if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		dprintf("bind: %s\n", strerror(errno));
		close(s);
		return -1;
	}

	switch (ai->ai_family) {
	case AF_INET6:
		(void)setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		    &mcasthops, sizeof(mcasthops));
		(void)setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		    &mcastloop, sizeof(mcastloop));
		(void)setsockopt(s, IPPROTO_IPV6, SO_REUSEPORT,
		    &yes, sizeof(yes));
#ifdef IPV6_USE_MIN_MTU
		(void)setsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU,
		    &yes, sizeof(yes));
#endif
		break;
	case AF_INET:
		(void)setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
		    &mcasthops, sizeof(mcasthops));
		(void)setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
		    &mcastloop, sizeof(mcastloop));
		(void)setsockopt(s, IPPROTO_IP, SO_REUSEPORT,
		    &yes, sizeof(yes));
		break;
	}

	return s;
}

static int
join(s, af, group)
	int s;
	int af;
	const char *group;
{
	struct addrinfo hints, *res, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	if (getaddrinfo(group, "0", &hints, &res) != 0)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		if (join0(s, ai) < 0)
			return -1;
	}
	freeaddrinfo(res);

	return 0;
}

static int
join0(s, ai)
	int s;
	const struct addrinfo *ai;
{
	struct ipv6_mreq mreq6;

	switch (ai->ai_family) {
	case AF_INET6:
		memset(&mreq6, 0, sizeof(mreq6));
		mreq6.ipv6mr_interface = if_nametoindex(intface);
		if (mreq6.ipv6mr_interface == 0) {
			errno = EINVAL;
			return -1;
		}
		memcpy(&mreq6.ipv6mr_multiaddr,
		    &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		    sizeof(mreq6.ipv6mr_multiaddr));
		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
		    sizeof(mreq6)) != 0) {
			return -1;
		}
		break;
	case AF_INET:
		/* XXX do something */
		break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	return 0;
}

static int
setif(s, af, iface)
	int s;
	int af;
	const char *iface;
{
	unsigned int outif;
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sin;
	int ret;

	switch (af) {
	case AF_INET6:
		outif = if_nametoindex(intface);
		if (outif == 0) {
			errno = EINVAL;
			return -1;
		}
		return setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		    &outif, sizeof(outif));
	case AF_INET:
		if (getifaddrs(&ifap) != 0)
			return -1;
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			if (strcmp(ifa->ifa_name, iface) != 0)
				continue;
			if ((ifa->ifa_flags & IFF_UP) == 0)
				continue;

			break;
		}
		if (ifa == NULL) {
			freeifaddrs(ifap);
			errno = EADDRNOTAVAIL;
			return -1;
		}
		sin = (struct sockaddr_in *)ifa->ifa_addr;
		ret = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
		    &sin->sin_addr, sizeof(sin->sin_addr));
		freeifaddrs(ifap);
		return ret;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
}

static int
iscanon(n)
	const char *n;
{
#if 0
	struct addrinfo hints, *res;
	int ret;
#endif

	if (strlen(n) == 0)
		return 0;
	if (n[strlen(n) - 1] != '.')
		return 0;

#if 0
	/*
	 * XXX the code fragment does not work.  /etc/resolv.conf will have
	 * "nameserver 0.0.0.0" to point to mdnsd itself!
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(n, "0", &hints, &res) != 0)
		return 0;
	if (!res->ai_canonname) {
		freeaddrinfo(res);
		return 0;
	}
	if (strcmp(res->ai_canonname, n) == 0 ||
	    (strlen(n) == strlen(res->ai_canonname) + 1 &&
	     strncmp(res->ai_canonname, n, strlen(res->ai_canonname)) == 0))
		ret = 1;
	else
		ret = 0;
	freeaddrinfo(res);
	return ret;
#else
	return 1;
#endif
}

int
addserv(n, ttl)
	const char *n;
	int ttl;
{
	struct addrinfo hints, *res;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int flags;
	struct nsdb *ns;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(n, dstport, &hints, &res) != 0)
		return -1;
	if (res->ai_next) {
		freeaddrinfo(res);
		return -1;
	}
	switch (res->ai_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)res->ai_addr;
		if (IN_MULTICAST(sin->sin_addr.s_addr))
			flags = NSDB_MULTICAST;
		else
			flags = NSDB_UNICAST;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)res->ai_addr;
		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			flags = NSDB_MULTICAST;
		else
			flags = NSDB_UNICAST;
		break;
	default:
		flags = 0;
		break;
	}
	ns = newnsdb(res->ai_addr, n, flags);
	if (ns == NULL) {
		freeaddrinfo(res);
		return -1;
	}
	if (ttl < 0) {
		ns->expire.tv_sec = -1;
		ns->expire.tv_usec = -1;
	} else {
		gettimeofday(&ns->expire, NULL);
		ns->expire.tv_sec += ttl;
	}

	dprintf("added server %s\n", n);

	freeaddrinfo(res);
	return 0;
}

int
ismyaddr(sa)
	const struct sockaddr *sa;
{
	struct sockaddr_storage ss[2];
	u_int32_t scope[2], loscope;
	struct ifaddrs *ifap, *ifa;
	int ret;
	char h1[NI_MAXHOST], h2[NI_MAXHOST];
	char p[NI_MAXSERV];
#ifdef NI_WITHSCOPEID
	const int niflag = NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
#else
	const int niflag = NI_NUMERICHOST | NI_NUMERICSERV;
#endif

	if (sa->sa_len > sizeof(ss[0]))
		return 0;

	memcpy(&ss[0], sa, sa->sa_len);
	scope[0] = 0;
	loscope = if_nametoindex("lo0");	/*XXX*/
#ifdef __KAME__
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&ss[0];
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr)) {
			*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] = 0;
			scope[0] = sin6->sin6_scope_id;
			sin6->sin6_scope_id = 0;
		}
	}
#endif
	h1[0] = h2[0] = '\0';
	if (getnameinfo((struct sockaddr *)&ss[0], ss[0].ss_len, h1, sizeof(h1),
	    p, sizeof(p), niflag) != 0)
		return 0;
#if 1	/*just for experiment - to run two servers on a single node*/
	if (strcmp(p, dstport) == 0)
		return 0;
#endif

	if (getifaddrs(&ifap) != 0)
		return 0;
	ret = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != sa->sa_family)
			continue;
		if (ifa->ifa_addr->sa_len != sa->sa_len ||
		    ifa->ifa_addr->sa_len > sizeof(ss[1])) {
			continue;
		}
		memcpy(&ss[1], ifa->ifa_addr, ifa->ifa_addr->sa_len);
		scope[1] = 0;
#ifdef __KAME__
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)&ss[1];
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr)) {
				scope[1] = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
				sin6->sin6_addr.s6_addr[2] = 0;
				sin6->sin6_addr.s6_addr[3] = 0;
			}
		}
#endif
		if (getnameinfo((struct sockaddr *)&ss[1], ss[1].ss_len,
		    h2, sizeof(h2), NULL, 0, niflag) != 0)
			continue;
		if (strcmp(h1, h2) != 0)
			continue;
		/*
		 * due to traditional BSD loopback packet handling,
		 * it is possible to get packet from loopback interface
		 * instead of real interface.
		 */
		if (scope[0] != scope[1] && scope[0] != loscope)
			continue;

		ret = 1;
		break;
	}

	freeifaddrs(ifap);
	return ret;
}

int
#if __STDC__
dprintf(const char *fmt, ...)
#else
dprintf(fmt, va_alist)
	char *fmt;
#endif
{
	va_list ap;
	int ret = 0;

#if __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	if (dflag)
		ret = vfprintf(stderr, fmt, ap);
	va_end(ap);
	return ret;
}
