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
#include <sys/ioctl.h>
#include <sys/queue.h>
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
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>

#ifdef HAVE_GETIFADDRS 
# ifdef HAVE_IFADDRS_H
#  define USE_GETIFADDRS
#  include <ifaddrs.h>
# endif
#endif

#include <dhcp6.h>
#include <common.h>

int foreground;
int debug_thresh;

#if 0
static unsigned int if_maxindex __P((void));
#endif
static int in6_matchflags __P((struct sockaddr *, char *, int));

#if 0
static unsigned int
if_maxindex()
{
	struct if_nameindex *p, *p0;
	unsigned int max = 0;

	p0 = if_nameindex();
	for (p = p0; p && p->if_index && p->if_name; p++) {
		if (max < p->if_index)
			max = p->if_index;
	}
	if_freenameindex(p0);
	return max;
}
#endif

int
getifaddr(addr, ifnam, prefix, plen, strong, ignoreflags)
	struct in6_addr *addr;
	char *ifnam;
	struct in6_addr *prefix;
	int plen;
	int strong;		/* if strong host model is required or not */
	int ignoreflags;
{
#ifdef USE_GETIFADDRS
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 sin6;
	int error = -1;

	if (getifaddrs(&ifap) != 0) {
		err(1, "getifaddr: getifaddrs");
		/*NOTREACHED*/
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		int s1, s2;

		if (strong && strcmp(ifnam, ifa->ifa_name) != 0)
			continue;

		/* in any case, ignore interfaces in different scope zones. */
		if ((s1 = in6_addrscopebyif(prefix, ifnam)) < 0 ||
		    (s2 = in6_addrscopebyif(prefix, ifa->ifa_name)) < 0 ||
		     s1 != s2)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (ifa->ifa_addr->sa_len > sizeof(sin6))
			continue;

		if (in6_matchflags(ifa->ifa_addr, ifa->ifa_name, ignoreflags))
			continue;

		memcpy(&sin6, ifa->ifa_addr, ifa->ifa_addr->sa_len);
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
		}
#endif
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

			if (memcmp(&a, prefix, plen / 8) != 0 ||
			    a.s6_addr[plen / 8] !=
			    (prefix->s6_addr[plen / 8] & m.s6_addr[plen / 8]))
				continue;
		}
		memcpy(addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(addr))
			addr->s6_addr[2] = addr->s6_addr[3] = 0; 
#endif
		error = 0;
		break;
	}

	freeifaddrs(ifap);
	return(error);
#else
	int s;
	unsigned int maxif;
	struct ifreq *iflist;
	struct ifconf ifconf;
	struct ifreq *ifr, *ifr_end;
	struct sockaddr_in6 sin6;
	int error;

#if 1
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
		int s1, s2;

		if (strong && strcmp(ifnam, ifr->ifr_name) != 0)
			continue;

		/* in any case, ignore interfaces in different scope zones. */
		if ((s1 = in6_addrscopebyif(prefix, ifnam)) < 0 ||
		    (s2 = in6_addrscopebyif(prefix, ifr->ifr_name)) < 0 ||
		     s1 != s2)
			continue;

		if (ifr->ifr_addr.sa_family != AF_INET6)
			continue;
		if (ifr->ifr_addr.sa_len > sizeof(sin6))
			continue;

		if (in6_matchflags(&ifr->ifr_addr, ifr->ifr_name, ignoreflags))
			continue;

		memcpy(&sin6, &ifr->ifr_addr, ifr->ifr_addr.sa_len);


#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
		}
#endif
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

			if (memcmp(&a, prefix, plen / 8) != 0 ||
			    a.s6_addr[plen / 8] !=
			    (prefix->s6_addr[plen / 8] & m.s6_addr[plen / 8]))
				continue;
		}
		memcpy(addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(addr))
			addr->s6_addr[2] = addr->s6_addr[3] = 0;
#endif
		error = 0;
		break;
	}

	free(iflist);
	close(s);
	return error;
#endif
}

int
in6_addrscopebyif(addr, ifnam)
	struct in6_addr *addr;
	char *ifnam;
{
	u_int ifindex; 

	if ((ifindex = if_nametoindex(ifnam)) == 0)
		return(-1);

	if (IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MC_LINKLOCAL(addr))
		return(ifindex);

	if (IN6_IS_ADDR_SITELOCAL(addr) || IN6_IS_ADDR_MC_SITELOCAL(addr))
		return(1);	/* XXX */

	if (IN6_IS_ADDR_MC_ORGLOCAL(addr))
		return(1);	/* XXX */

	return(1);		/* treat it as global */
}

/* XXX: this code assumes getifaddrs(3) */
const char *
getdev(addr)
	struct sockaddr_in6 *addr;
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *a6;
	static char ret_ifname[IF_NAMESIZE];

	if (getifaddrs(&ifap) != 0) {
		err(1, "getdev: getifaddrs");
		/* NOTREACHED */
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		a6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (!IN6_ARE_ADDR_EQUAL(&a6->sin6_addr, &addr->sin6_addr) ||
		    a6->sin6_scope_id != addr->sin6_scope_id)
			continue;

		break;
	}

	if (ifa)
		strlcpy(ret_ifname, ifa->ifa_name, sizeof(ret_ifname));
	freeifaddrs(ifap);

	return(ifa ? ret_ifname : NULL);
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

	if (hlim == 0)
		hlim = 64;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hlim,
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
	return error;
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
	return x + ((y - x) * (ratio - 1) / random() & (ratio - 1));
}

char *
addr2str(sa)
	struct sockaddr *sa;
{
	static char addrbuf[8][NI_MAXHOST];
	static int round = 0;
	char *cp;

	round = (round + 1) & 7;
	cp = addrbuf[round];

	getnameinfo(sa, sa->sa_len, cp, NI_MAXHOST, NULL, 0,
		    NI_NUMERICHOST|NI_WITHSCOPEID);

	return(cp);
}

char *
in6addr2str(in6, scopeid)
	struct in6_addr *in6;
	int scopeid;
{
	struct sockaddr_in6 sa6;

	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_addr = *in6;
	sa6.sin6_scope_id = scopeid;

	return(addr2str((struct sockaddr *)&sa6));
}

/* return IPv6 address scope type. caller assumes that smaller is narrower. */
int
in6_scope(addr)
	struct in6_addr *addr;
{
	int scope;

	if (addr->s6_addr[0] == 0xfe) {
		scope = addr->s6_addr[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return 2; /* link-local */
			break;
		case 0xc0:
			return 5; /* site-local */
			break;
		default:
			return 14; /* global: just in case */
			break;
		}
	}

	/* multicast scope. just return the scope field */
	if (addr->s6_addr[0] == 0xff)
		return(addr->s6_addr[1] & 0x0f);

	if (bcmp(&in6addr_loopback, addr, sizeof(addr) - 1) == 0) {
		if (addr->s6_addr[15] == 1) /* loopback */
			return 1;
		if (addr->s6_addr[15] == 0) /* unspecified */
			return 0; /* XXX: good value? */
	}

	return 14;		/* global */
}

static int
in6_matchflags(addr, ifnam, flags)
	struct sockaddr *addr;
	char *ifnam;
	int flags;
{
	int s;
	struct in6_ifreq ifr6;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		warn("in6_matchflags: socket(DGRAM6)");
		return(-1);
	}
	memset(&ifr6, 0, sizeof(ifr6));
	strncpy(ifr6.ifr_name, ifnam, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = *(struct sockaddr_in6 *)addr;

	if (ioctl(s, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		warn("in6_matchflags: ioctl(SIOCGIFAFLAG_IN6, %s)",
		     addr2str(addr));
		close(s);
		return(-1);
	}

	close(s);

	return(ifr6.ifr_ifru.ifru_flags6 & flags);
}

void
setloglevel(debuglevel)
	int debuglevel;
{
	if (foreground) {
		switch(debuglevel) {
		case 0:
			debug_thresh = LOG_ERR;
			break;
		case 1:
			debug_thresh = LOG_INFO;
			break;
		default:
			debug_thresh = LOG_DEBUG;
			break;
		}
	} else {
		switch(debuglevel) {
		case 0:
			setlogmask(LOG_UPTO(LOG_ERR));
			break;
		case 1:
			setlogmask(LOG_UPTO(LOG_INFO));
			break;
		}
	}
}

void
dprintf(int level, const char *fmt, ...)
{
	va_list ap;
	char logbuf[LINE_MAX];

	va_start(ap, fmt);
	vsnprintf(logbuf, sizeof(logbuf), fmt, ap);

	if (foreground && debug_thresh >= level)
		fprintf(stderr, "%s\n", logbuf);
	else
		syslog(level, "%s", logbuf);
}
