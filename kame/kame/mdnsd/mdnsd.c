/*	$KAME: mdnsd.c,v 1.2 2000/05/21 03:20:04 itojun Exp $	*/

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
#include <ifaddrs.h>

#include "mdnsd.h"

const char *dnsserv = NULL;
const char *intface = NULL;
int insock;
int af = AF_INET;
static char hostnamebuf[MAXHOSTNAMELEN];
const char *hostname = NULL;

static void usage __P((void));
static int getsock __P((int, const char *, int, int));
static int getsock0 __P((const struct addrinfo *));
static int join __P((int, const char *));
static int join0 __P((int, const struct addrinfo *));
static int setif __P((int, const char *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	const char *port = MDNS_PORT;

	while ((ch = getopt(argc, argv, "46d:i:p:")) != EOF) {
		switch (ch) {
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 'd':
			dnsserv = optarg;
			break;
		case 'i':
			intface = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			usage();
			exit(1);
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0 || !intface) {
		usage();
		exit(1);
		/*NOTREACHED*/
	}

	insock = getsock(af, port, SOCK_DGRAM, AI_PASSIVE);
	if (insock < 0) {
		err(1, "getsock");
		/*NOTREACHED*/
	}

	if (af == AF_INET6) {
		if (join(insock, MDNS_GROUP6) < 0) {
			err(1, "join");
			/*NOTREACHED*/
		}

		if (setif(insock, intface) < 0) {
			errx(1, "setif");
			/*NOTREACHED*/
		}
	}

	if (gethostname(hostnamebuf, sizeof(hostnamebuf)) != 0) {
		err(1, "gethostname");
		/*NOTREACHED*/
	}
	hostname = hostnamebuf;

	mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: mdnsd [-46] [-d server] [-p port] -i iface\n");
}

/* XXX todo: multiple sockets */
static int
getsock(af, serv, socktype, flags)
	int af;
	const char *serv;
	int socktype, flags;
{
	struct addrinfo hints, *res;
	int error;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = socktype;
	hints.ai_flags = flags;
	error = getaddrinfo(NULL, serv, &hints, &res);
	if (error) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	ret = getsock0(res);
	freeaddrinfo(res);
	return ret;
}

static int
getsock0(ai)
	const struct addrinfo *ai;
{
	int s;

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s < 0)
		return -1;
	if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
		close(s);
		return -1;
	}

	return s;
}

static int
join(s, group)
	int s;
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
setif(s, iface)
	int s;
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

int
ismyaddr(sa)
	const struct sockaddr *sa;
{
	struct sockaddr_storage ss;
	struct ifaddrs *ifap, *ifa;
	int ret;
	char h1[NI_MAXHOST], h2[NI_MAXHOST];
#ifdef NI_WITHSCOPEID
	const int niflag = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int niflag = NI_NUMERICHOST;
#endif

	if (sa->sa_len > sizeof(ss))
		return 0;
	if (getnameinfo(sa, sa->sa_len, h1, sizeof(h1), NULL, 0, niflag) != 0)
		return 0;
	if (getifaddrs(&ifap) != 0)
		return 0;

	memcpy(&ss, sa, sa->sa_len);
	sa = (struct sockaddr *)&ss;
#ifdef __KAME__
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)sin6;
		if (sin6->sin6_scope_id &&
		    (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
		     IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr))) {
			*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] =
			    htons(sin6->sin6_scope_id);
			sin6->sin6_scope_id = 0;
		}
	}
#endif
	ret = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != sa->sa_family)
			continue;
		if (ifa->ifa_addr->sa_len != sa->sa_len)
			continue;
		if (getnameinfo(ifa->ifa_addr, ifa->ifa_addr->sa_len,
		    h2, sizeof(h2), NULL, 0, niflag) != 0)
			continue;
		if (strcmp(h1, h2) != 0)
			continue;

		ret = 1;
		break;
	}

	freeifaddrs(ifap);
	return ret;
}
