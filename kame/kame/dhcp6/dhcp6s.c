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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <dhcp6.h>
#include <common.h>

struct servtab {
	struct servtab *next;
	u_int32_t pref;
	struct in6_addr llcli;
	struct in6_addr relay;
	struct in6_addr serv;
};

int dump = 0;
int debug = 0;
#define dprintf(x)	{ if (debug) fprintf x; }
char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
struct servtab *servtab;

/* behavior constant */
#define SOLICIT_RETRY	2

static void usage __P((void));
static void mainloop __P((void));
static int getifaddr __P((struct in6_addr *, char *, struct in6_addr *, int));
static int transmit_sa __P((int, struct sockaddr *, int, char *, size_t));
static int transmit __P((int, char *, char *, int, char *, size_t));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static ssize_t server6_recv __P((int, char *, size_t));
static ssize_t server6_react __P((int, char *, size_t));
static int server6_react_solicit __P((int, char *, size_t));

int
main(argc, argv)
	int argc;
	char **argv;
{
	extern int optind;
	extern char *optarg;
	int ch;

	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "dD")) != EOF) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'D':
			dump++;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		/*NOTREACHED*/
	}
	device = argv[0];

	mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: dhcp6s intface\n");
	exit(0);
}

static void
mainloop()
{
	server6_init();
	server6_mainloop();
}

#if 0
void
callback_register(fd, cap, func)
	int fd;
	pcap_t *cap;
	void (*func)();
{
	if (MAXCALLBACK <= ncallbacks) {
		errx(1, "callback exceeds limit(%d), try increase MAXCALLBACK",
			MAXCALLBACK);
		/*NOTREACHED*/
	}
	if (fd && cap) {
		errx(1, "internal error: both fd and cap are present");
		/*NOTREACHED*/
	}

	if (maxfd < fd)
		maxfd = fd;

	callbacks[ncallbacks].fd = fd;
	callbacks[ncallbacks].cap = cap;
	callbacks[ncallbacks].func = func;
	ncallbacks++;
}
#endif

static int
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

static int
transmit_sa(s, sa, hlim, buf, len)
	int s;
	struct sockaddr *sa;
	int hlim;
	char *buf;
	size_t len;
{
	int error;

	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hlim,
			sizeof(hlim)) < 0) {
		err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
		/*NOTREACHED*/
	}

	error = sendto(s, buf, len, 0, sa, sa->sa_len);

	return (error != len) ? -1 : 0;
}

static int
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

static long
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

/*------------------------------------------------------------*/

void
server6_init()
{
	struct addrinfo hints;
	struct addrinfo *res, *res2;
	int error;
	int ifidx;
	struct ipv6_mreq mreq6;

	ifidx = if_nametoindex(device);
	if (ifidx == 0)
		errx(1, "invalid interface %s", device);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		err(1, "socket(insock)");
		/*NOTREACHED*/
	}
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind(insock)");
		/*NOTREACHED*/
	}
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		err(1, "setsockopt(insock, IPV6_MULTICAST_IF)");
		/*NOTREACHED*/
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
		&((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
		sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq6, sizeof(mreq6))) {
		err(1, "setsockopt(insock, IPV6_JOIN_GROUP)");
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLSERVER, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
		&((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
		sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq6, sizeof(mreq6))) {
		err(1, "setsockopt(insock, IPV6_JOIN_GROUP)");
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		err(1, "socket(outsock)");
		/*NOTREACHED*/
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		err(1, "setsockopt(outsock, IPV6_MULTICAST_IF)");
		/*NOTREACHED*/
	}
	freeaddrinfo(res);

#if 0
	/* set interface to use */
	ifidx = if_nametoindex(device);
	if (!ifidx) {
		err(1, "if_nametoindex(%s)", device);
		/*NOTREACHED*/
	}
#endif

	servtab = NULL;

#if 0
	callback_register(s, NULL, capture_dhcpc6);
#endif
}

static void
tvfix(tv)
	struct timeval *tv;
{
	long s;
	s = tv->tv_usec / (1000 * 1000);
	tv->tv_usec %= (1000 * 1000);
	tv->tv_sec += s;
}

static void
server6_mainloop()
{
	int bigsock;
	int ret;
	fd_set r;
	char abuf[BUFSIZ], sbuf[BUFSIZ];
	ssize_t l;

	while (1) {
		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, NULL);
		switch (ret) {
		case -1:
		case 0:
			err(1, "select");
			/*NOTREACHED*/
		default:
			break;
		}
		if (FD_ISSET(insock, &r)) {
			l = server6_recv(insock, abuf, sizeof(abuf));
			server6_react(1, abuf, l);	/*XXX*/
		}
	}
}

static ssize_t
server6_recv(s, buf, siz)
	int s;
	char *buf;
	size_t siz;
{
	ssize_t len;
	struct sockaddr_storage from;
	socklen_t fromlen;

	fromlen = sizeof(from);
	if ((len = recvfrom(s, buf, siz, 0,
			(struct sockaddr *)&from, &fromlen)) < 0) {
		err(1, "recvfrom(inbound)");
		/*NOTREACHED*/
	}
	return len;
}

static ssize_t
server6_react(agent, buf, siz)
	int agent;	/* 0: servsock, 1: insock */
	char *buf;
	size_t siz;
{
	union dhcp6 *dh6;

	dh6 = (union dhcp6 *)buf;
	dprintf((stderr, "msgtype=%d\n", dh6->dh6_msgtype));
	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT:
		server6_react_solicit(agent, buf, siz);
		break;
	case DH6_ADVERT:
	case DH6_REQUEST:
	case DH6_REPLY:
	case DH6_RELEASE:
	case DH6_RECONFIG:
		break;
	default:
		fprintf(stderr, "invalid msgtype %d\n", dh6->dh6_msgtype);
	}
}

/* 6.1. Receiving DHCP Solicit Messages */
/* 6.2. Sending DHCP Advertise Messages */
static int
server6_react_solicit(agent, buf, siz)
	int agent;	/* 0: servsock, 1: insock */
	char *buf;
	size_t siz;
{
	struct dhcp6_solicit *dh6s;
	struct dhcp6_advert *dh6a;
	char sbuf[BUFSIZ];
	ssize_t len;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr myaddr, target;
	int hlim;

	dprintf((stderr, "react_solicit\n"));

	if (siz < sizeof(*dh6s)) {
		dprintf((stderr, "react_solicit: short packet\n"));
		return -1;
	}
	dh6s = (struct dhcp6_solicit *)buf;

	if (!agent) {
		if (IN6_IS_ADDR_UNSPECIFIED(&dh6s->dh6sol_relayaddr)
		 || IN6_IS_ADDR_LINKLOCAL(&dh6s->dh6sol_relayaddr)) {
			dprintf((stderr, "react_solicit: invalid relayaddr "
				"to server addr\n"));
			return -1;
		}
	} else {
		if (dh6s->dh6sol_prefixsiz != 0) {
			dprintf((stderr, "react_solicit: invalid prefixsiz %d "
				"(must be zero)\n", dh6s->dh6sol_prefixsiz));
			return -1;
		}
	}
	if (!IN6_IS_ADDR_LINKLOCAL(&dh6s->dh6sol_cliaddr)) {
		dprintf((stderr, "react_solicit: invalid cliaddr\n"));
		return -1;
	}

#if 0
	if ((dh6s->dh6sol_flags & DH6SOL_CLOSE) != 0)
		server6_flush(&dh6s->dh6sol_cliaddr, NULL);
#endif

	if (!agent) {
		usleep(1000 * random_between(SERVER_MIN_ADV_DELAY,
			SERVER_MAX_ADV_DELAY));
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	memcpy(&dst, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	dh6a = (struct dhcp6_advert *)sbuf;
	len = sizeof(*dh6a);
	memset(dh6a, 0, sizeof(*dh6a));
	dh6a->dh6adv_msgtype = DH6_ADVERT;
	memcpy(&dh6a->dh6adv_cliaddr, &dh6s->dh6sol_cliaddr,
		sizeof(dh6s->dh6sol_cliaddr));
	if (!IN6_IS_ADDR_UNSPECIFIED(&dh6s->dh6sol_relayaddr)) {
		memcpy(&dh6a->dh6adv_relayaddr, &dh6s->dh6sol_relayaddr,
			sizeof(dh6s->dh6sol_relayaddr));
		dst.sin6_addr = dh6a->dh6adv_relayaddr;
		inet_pton(AF_INET6, "fec0::", &target, sizeof(target));
		if (getifaddr(&myaddr, device, &target, 10) != 0) {
			inet_pton(AF_INET6, "2000::", &target, sizeof(target));
			if (getifaddr(&myaddr, device, &target, 3) != 0) {
				errx(1, "no matching address on %s", device);
				/*NOTREACHED*/
			}
		}
		hlim = 64;
	} else {
		dst.sin6_addr = dh6s->dh6sol_cliaddr;
		dst.sin6_scope_id = if_nametoindex(device);
		dh6a->dh6adv_flags = DH6ADV_SERVPRESENT;
		inet_pton(AF_INET6, "fe80::", &target, sizeof(target));
		if (getifaddr(&myaddr, device, &target, 10) != 0) {
			errx(1, "no matching address on %s", device);
			/*NOTREACHED*/
		}
		hlim = 1;
	}
#ifdef __KAME__
	if (IN6_IS_ADDR_LINKLOCAL(&myaddr))
		myaddr.s6_addr[2] = myaddr.s6_addr[3] = 0;
#endif
	memcpy(&dh6a->dh6adv_serveraddr, &myaddr, sizeof(myaddr));
	dh6a->dh6adv_pref = 255;	/*XXX*/

	if (transmit_sa(outsock, (struct sockaddr *)&dst, hlim, sbuf, len) != 0) {
		err(1, "transmit failed");
		/*NOTREACHED*/
	}
}

#if 0
static void
server6_findserv()
{
	struct timeval w;
	fd_set r;
	int timeo;
	int ret;
	time_t sendtime, delaytime, waittime, t;
	struct servtab *st = NULL;
	struct servtab *p, *q;
	enum { WAIT, DELAY } mode;

	/* send solicit, wait for advert */
	timeo = 0;
	sendtime = time(NULL);
	delaytime = MIN_SOLICIT_DELAY;
	delaytime += (MAX_SOLICIT_DELAY - MIN_SOLICIT_DELAY)
		* (random() & 0xff) / 0xff;
	waittime = 0;
	while (1) {
		t = time(NULL);
		dprintf((stderr, "sendtime=%ld waittime=%d delaytime=%d\n",
			(long)sendtime, (int)waittime, (int)delaytime));
		if (waittime && waittime < delaytime) {
			if (sendtime + waittime > t) {
				w.tv_sec = waittime - (t - sendtime);
				w.tv_usec = 0;
				mode = WAIT;
			} else if (sendtime + delaytime > t) {
				w.tv_sec = delaytime - (t - sendtime);
				w.tv_usec = 0;
				mode = DELAY;
			}
		} else {
			if (sendtime + delaytime > t) {
				w.tv_sec = delaytime - (t - sendtime);
				w.tv_usec = 0;
				mode = DELAY;
			} else if (sendtime + waittime > t) {
				w.tv_sec = waittime - (t - sendtime);
				w.tv_usec = 0;
				mode = WAIT;
			}
		}
		ret = select(insock + 1, &r, NULL, NULL, &w);
		switch (ret) {
		case -1:
			err(1, "select");
			/*NOTREACHED*/
		case 0:
			if (mode == WAIT && st) {
				/* we have more than 1 reply, receive timeout */
				goto found;
			}

			if (mode == WAIT) {
			} else {
				if (timeo >= SOLICIT_RETRY)
					goto found;

				dprintf((stderr, "send solicit\n"));
				server6_sendsolicit(outsock);
				timeo++;
				sendtime = time(NULL);
				delaytime *= 2;
				delaytime += (MAX_SOLICIT_DELAY - MIN_SOLICIT_DELAY)
					* (random() & 0xff) / 0xff;
				waittime = ADV_CLIENT_WAIT;
			}
			break;
		default:
			p = (struct servtab *)malloc(sizeof(struct servtab));
			memset(p, 0, sizeof(*p));
			if (server6_recvadvert(insock, p) < 0) {
				free(p);
				break;
			}
			p->next = st;
			st = p;
			if (p->pref == ~0)
				goto found;
			break;
		}
	}

found:
	q = NULL;
	for (p = st; p; p = p->next) {
		if (q == NULL || p->pref > q->pref)
			q = p;
	}
	if (q == NULL) {
		errx(1, "no dhcp6 server found");
		/*NOTREACHED*/
	}
}
#endif
