/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
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
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <ifaddrs.h>

#ifndef IPV6_ADDR_SCOPE_RESERVED
#define IPV6_ADDR_SCOPE_RESERVED	0x00
#endif
#ifndef IPV6_ADDR_SCOPE_NODELOCAL
#define IPV6_ADDR_SCOPE_NODELOCAL	0x01
#endif
#ifndef IPV6_ADDR_SCOPE_LINKLOCAL
#define IPV6_ADDR_SCOPE_LINKLOCAL	0x02
#endif
#ifndef IPV6_ADDR_SCOPE_SITELOCAL
#define IPV6_ADDR_SCOPE_SITELOCAL	0x05
#endif
#ifndef IPV6_ADDR_SCOPE_ORGLOCAL
#define IPV6_ADDR_SCOPE_ORGLOCAL	0x08	/* just used in this file */
#endif
#ifndef IPV6_ADDR_SCOPE_GLOBAL
#define IPV6_ADDR_SCOPE_GLOBAL		0x0e
#endif

char *pname;
char *addr, *port;
char *file = NULL;
char *ifname = NULL;
int hlim = 0;
int scope_limit = IPV6_ADDR_SCOPE_RESERVED;
u_int debug = 0;

void Usage __P((void));
int parse __P((int, char **));
int bind_srcaddr __P((struct addrinfo *, int, char *, int));

void
Usage()
{
	printf("Usage: %s [-l hlim] [-i ifname [-s scope]] "
		"addr port [file]\n", pname);
	printf("\tscope: 1, 2, 5 or 14\n");
}

int
main(ac, av)
	int ac;
	char **av;
{
	int s;
	struct addrinfo hints, *res;
	int error;

	parse(ac, av);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, port, &hints, &res);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));

	switch (res->ai_family) {
	case AF_INET6:
	case AF_INET:
		break;
	default:
		errno = EAFNOSUPPORT;
		err(1, "%s %s", addr, port);
	}

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
		err(1, "socket");

	/* set interface to send and bind. */
	if (ifname != NULL) {
		int ifindex;
		struct in_addr a;

		ifindex = if_nametoindex(ifname);
		if (ifindex == 0)
			err(1, "if_nametoindex");
		switch (res->ai_family) {
		case AF_INET6:
			error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
					&ifindex, sizeof(ifindex));
			if (error < 0)
				err(1, "setsockopt(IPV6_MULTICAST_IF)");
			break;
		case AF_INET:
			a.s_addr = htonl(ifindex);
			error = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
					&a, sizeof(a));
			if (error < 0)
				err(1, "setsockopt(IP_MULTICAST_IF)");
			break;
		}

		error = bind_srcaddr(res, s, ifname, scope_limit);
		if (error < 0)
			errx(1, "Failed to bind source address.");
	}

	/* set hop-limit */
	if (hlim != 0) {
		u_char ttl;

		switch (res->ai_family) {
		case AF_INET6:
			error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
					&hlim, sizeof(hlim));
			if (error < 0)
				err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
			break;
		case AF_INET:
			ttl = hlim & 0xff;
			error = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
					&ttl, sizeof(ttl));
			if (error < 0)
				err(1, "setsockopt(IP_MULTICAST_TTL)");
			break;
		}
	}

	/* main */
    {
	int fd = STDIN_FILENO;	/* default: stdin */
	int len;
	char buf[BUFSIZ];

	if (file != NULL) {
		fd = open(file, O_RDONLY);
		if (fd < 0)
			err(1, "open");
	}

	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		len = sendto(s, buf, len, 0, res->ai_addr, res->ai_addrlen);
		if (len < 0) {
			close(fd);
			close(s);
			err(1, "send");
		}
	}

	close(fd);
    }

	close(s);
	exit(0);
}

int
bind_srcaddr(res, so, ifname, scope_limit)
	struct addrinfo *res;
	int so;
	char *ifname;
	int scope_limit;
{
	struct ifaddrs *ifa, *ifap, *match;
	struct in6_addr *a;
	int scope_max;

	/* XXX no scope support for IPv4 yet */
	if (res->ai_family != AF_INET6)
		return 0;

	if (getifaddrs(&ifap) != 0)
		return -1;

	match = NULL;
	scope_max = IPV6_ADDR_SCOPE_NODELOCAL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (res->ai_family != ifa->ifa_addr->sa_family)
			continue;

		a = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

		if (IN6_IS_ADDR_LOOPBACK(a))
			continue;

		if (IN6_IS_ADDR_LINKLOCAL(a) &&
		    scope_limit >= IPV6_ADDR_SCOPE_LINKLOCAL &&
		    scope_max < IPV6_ADDR_SCOPE_LINKLOCAL) {
			scope_max = IPV6_ADDR_SCOPE_LINKLOCAL;
			match = ifa;
			continue;
		}

		if (IN6_IS_ADDR_SITELOCAL(a) &&
		    scope_limit >= IPV6_ADDR_SCOPE_SITELOCAL &&
		    scope_max < IPV6_ADDR_SCOPE_SITELOCAL) {
			scope_max = IPV6_ADDR_SCOPE_SITELOCAL;
			match = ifa;
			continue;
		}

		if (scope_max < IPV6_ADDR_SCOPE_GLOBAL &&
		    scope_limit >= IPV6_ADDR_SCOPE_GLOBAL) {
			scope_max = IPV6_ADDR_SCOPE_GLOBAL;
			match = ifa;
			continue;
		}
	}

	if (!match) {
		freeifaddrs(ifap);
		return -1;
	}

	if (bind(so, match->ifa_addr, match->ifa_addr->sa_len) < 0) {
		freeifaddrs(ifap);
		return -1;
	}

	freeifaddrs(ifap);
	return 0;
}

int
parse(ac, av)
	int ac;
	char **av;
{
	int c;

	pname = *av;

	while ((c = getopt(ac, av, "hdl:i:s:")) != -1) {
		switch (c) {
		case 'l':
			hlim = atoi(optarg);
			break;
		case 'i':
			ifname = optarg;
			break;
		case 's':
			scope_limit = atoi(optarg);
			break;
		case 'd':
			debug++;
			break;
		case 'h':
			Usage();
			exit (0);
		default:
			Usage();
			exit (1);
		}
	}

	/* check ifname and scope */
	if (ifname == NULL && scope_limit != IPV6_ADDR_SCOPE_RESERVED) {
		warnx("Ignore scope.");
	} else
	if (scope_limit != IPV6_ADDR_SCOPE_RESERVED
	 && scope_limit != IPV6_ADDR_SCOPE_NODELOCAL
	 && scope_limit != IPV6_ADDR_SCOPE_LINKLOCAL
	 && scope_limit != IPV6_ADDR_SCOPE_SITELOCAL
	 && scope_limit != IPV6_ADDR_SCOPE_GLOBAL) {
		warnx("Invalid scope.\n");
		Usage();
		exit (1);
	}

	if (ifname != NULL && scope_limit == IPV6_ADDR_SCOPE_RESERVED)
		scope_limit = IPV6_ADDR_SCOPE_GLOBAL;

	ac -= optind;
	av += optind;

	switch (ac) {
	case 3:
		file = *(av + 2);
	case 2:
		addr = *av;
		port = *(av + 1);
		break;
	default:
		Usage();
		exit (1);
	}

	return 0;
}
