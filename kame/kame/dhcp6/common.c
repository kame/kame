/*
 * Copyright (C) 1998 and 1999 WIDE Project.
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
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>

#include <dhcp6.h>
#include <common.h>

int
getifaddr(addr, ifnam, prefix, plen)
	struct in6_addr *addr;
	char *ifnam;
	struct in6_addr *prefix;
	int plen;
{
	int s;
	unsigned int maxif;
	struct ifreq *iflist;
	struct ifconf ifconf;
	struct ifreq *ifr, *ifr_end;
	struct sockaddr_in6 sin6;
	int error;

#if 0
	maxif = if_maxindex() + 1;
#else
	maxif = 1;
#endif
	iflist = (struct ifreq *)malloc(maxif * BUFSIZ);	/* XXX */
	if (!iflist) {
		errx(1, "not enough core");
		/*NOTREACHED*/
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		err(1, "socket(SOCK_DGRAM)");
		/*NOTREACHED*/
	}
	memset(&ifconf, 0, sizeof(ifconf));
	ifconf.ifc_req = iflist;
	ifconf.ifc_len = maxif * BUFSIZ;	/* XXX */
	if (ioctl(s, SIOCGIFCONF, &ifconf) < 0) {
		err(1, "ioctl(SIOCGIFCONF)");
		/*NOTREACHED*/
	}
	close(s);

	/* Look for this interface in the list */
	error = ENOENT;
	ifr_end = (struct ifreq *) (ifconf.ifc_buf + ifconf.ifc_len);
	for (ifr = ifconf.ifc_req;
	     ifr < ifr_end;
	     ifr = (struct ifreq *) ((char *) &ifr->ifr_addr
				    + ifr->ifr_addr.sa_len)) {
		if (strcmp(ifnam, ifr->ifr_name) != 0)
			continue;
		if (ifr->ifr_addr.sa_family != AF_INET6)
			continue;
		memcpy(&sin6, &ifr->ifr_addr, ifr->ifr_addr.sa_len);
		if (plen % 8 == 0) {
			if (memcmp(&sin6.sin6_addr, prefix, plen / 8) != 0)
				continue;
		} else {
			struct in6_addr a, m;
			int i;
			memcpy(&a, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
			memset(&m, 0, sizeof(m));
			memset(&m, 0xff, plen / 8);
			m.s6_addr[plen / 8] = (0xff00 >> (plen % 8)) & 0xff;
			for (i = 0; i < sizeof(a); i++)
				a.s6_addr[i] &= m.s6_addr[i];

			if (memcmp(&a, prefix, plen / 8) != 0)
				continue;
		}
		memcpy(addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
		error = 0;
		break;
	}

	free(iflist);
	close(s);
	return error;
}

int
transmit_sa(s, sa, hlim, buf, len)
	int s;
	struct sockaddr *sa;
	int hlim;
	char *buf;
	size_t len;
{
	int error;

	if (hlim && setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hlim,
			sizeof(hlim)) < 0) {
		err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
		/*NOTREACHED*/
	}

	error = sendto(s, buf, len, 0, sa, sa->sa_len);

	return (error != len) ? -1 : 0;
}

int
transmit(s, addr, port, hlim, buf, len)
	int s;
	char *addr;
	char *port;
	int hlim;
	char *buf;
	size_t len;
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, port, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo(%s): %s", addr, gai_strerror(error));
		/*NOTREACHED*/
	}
	if (res->ai_next) {
		errx(1, "getaddrinfo(%s): %s", addr,
			"resolved to multiple addrs");
		/*NOTREACHED*/
	}

	error = transmit_sa(s, res->ai_addr, hlim, buf, len);

	freeaddrinfo(res);
	return (error != len) ? -1 : 0;
}

long
random_between(x, y)
	long x;
	long y;
{
	long ratio;

	ratio = 1 << 16;
	while ((y - x) * ratio < (y - x))
		ratio = ratio / 2;
	return x + (y - x) * (ratio - 1) / random() & (ratio - 1);
}
