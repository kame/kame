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
#include <netinet6/in6.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>

#ifndef IPV6_ADDR_SCOPE_RESERVED
#define IPV6_ADDR_SCOPE_RESERVED	0x00
#endif

char *pname;
char *addr, *port;
char *file = NULL;
char *ifname = NULL;
int hlim = 0;
int scope_limit = IPV6_ADDR_SCOPE_RESERVED;
u_int debug = 0;

void Usage __P((void));
int parse __P((int ac, char **av));
int bind_srcaddr __P((int so, char *ifname, int scope_limit));

void
Usage()
{
	printf("Usage: %s [-l hlim] [-i ifname [-s scope]] "
		"(addr) (port) [file]\n",
		pname);
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
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, port, &hints, &res);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
		err(1, "socket:");

	/* set interface to send and bind. */
	if (ifname != NULL) {
		int ifindex;

		ifindex = if_nametoindex(ifname);
		if (ifindex == 0)
			err(1, "if_nametoindex");
		error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				&ifindex, sizeof(ifindex));
		if (error < 0)
			err(1, "setsockopt(IPV6_MULTICAST_IF)");

		error = bind_srcaddr(s, ifname, scope_limit);
		if (error < 0)
			errx(1, "Failed to bind source address.");
	}

	/* set hop-limit */
	if (hlim != 0) {
		error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				&hlim, sizeof(hlim));
		if (error < 0)
			err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
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
bind_srcaddr(so, ifname, scope_limit)
	int so;
	char *ifname;
	int scope_limit;
{
	int so_tmp;
	static struct ifconf ifc;
	static char buf[32768];

	so_tmp = socket(AF_INET, SOCK_DGRAM, 0);
	if (so_tmp < 0)
		return(-1);

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;

	if (ioctl(so_tmp, SIOCGIFCONF, (char *)&ifc) < 0)
		return(-1);

	(void)close(so_tmp);

    {
	struct sockaddr *saddr;
	int scope_max;
	caddr_t p;
	int error;

#define _IFREQ_NAME(p) (((struct ifreq *)p)->ifr_name)
#define _IFREQ_NAMELEN(p) (sizeof(((struct ifreq *)p)->ifr_name))

#define _IFREQ_SADDR(p) ((struct sockaddr *)&((struct ifreq *)p)->ifr_addr)
#define _IFREQ_S6ADDR(p) \
	(&((struct sockaddr_in6 *)_IFREQ_SADDR(p))->sin6_addr)

#define _IFREQ_ADDRLEN(p) (((struct ifreq *)p)->ifr_addr.sa_len)
#define _IFREQ_LEN(p) \
  (_IFREQ_NAMELEN(p) + _IFREQ_ADDRLEN(p) > sizeof(struct ifreq) \
    ? _IFREQ_NAMELEN(p) + _IFREQ_ADDRLEN(p) : sizeof(struct ifreq))

	saddr = NULL;
	scope_max = IPV6_ADDR_SCOPE_NODELOCAL;

	for (p = (caddr_t)(ifc.ifc_req);
	     ifc.ifc_len > 0;
	     ifc.ifc_len -= _IFREQ_LEN(p), p += _IFREQ_LEN(p)) {

		if (memcmp(_IFREQ_NAME(p), ifname, strlen(ifname)))
			continue;
		if (_IFREQ_SADDR(p)->sa_family != AF_INET6)
			continue;
		if (IN6_IS_ADDR_LOOPBACK(_IFREQ_S6ADDR(p)))
			continue;

		if (IN6_IS_ADDR_LINKLOCAL(_IFREQ_S6ADDR(p))
		 && scope_limit >= IPV6_ADDR_SCOPE_LINKLOCAL
		 && scope_max < IPV6_ADDR_SCOPE_LINKLOCAL) {
			scope_max = IPV6_ADDR_SCOPE_LINKLOCAL;
			saddr = _IFREQ_SADDR(p);
			continue;
		}

		if (IN6_IS_ADDR_SITELOCAL(_IFREQ_S6ADDR(p))
		 && scope_limit >= IPV6_ADDR_SCOPE_SITELOCAL
		 && scope_max < IPV6_ADDR_SCOPE_SITELOCAL) {
			scope_max = IPV6_ADDR_SCOPE_SITELOCAL;
			saddr = _IFREQ_SADDR(p);
			continue;
		}

		if (scope_max < IPV6_ADDR_SCOPE_GLOBAL
		 && scope_limit >= IPV6_ADDR_SCOPE_GLOBAL) {
			scope_max = IPV6_ADDR_SCOPE_GLOBAL;
			saddr = _IFREQ_SADDR(p);
			continue;
		}
	}

	if (saddr == NULL)
		return -1;

	error = bind(so, saddr, saddr->sa_len);
	if (error < 0)
		return -1;
    }

	return 0;
}

int
parse(ac, av)
	int ac;
	char **av;
{
	int c;

	pname = *av;

	while ((c = getopt(ac, av, "hdl:i:s:")) != EOF) {
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
