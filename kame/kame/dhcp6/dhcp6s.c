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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>

#include <dhcp6.h>
#include <dhcp6opt.h>
#include <common.h>

struct servtab {
	struct servtab *next;
	u_int32_t pref;
	struct in6_addr llcli;
	struct in6_addr relay;
	struct in6_addr serv;
};

int debug = 0;
#define dprintf(x)	{ if (debug) fprintf x; }
char *device = NULL;
#if 0
char *dnsserv = "3ffe:501:4819::42";
char *dnsdom = "kame.net."
#else
char *dnsserv = NULL;
char *dnsdom = NULL;
#endif

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
struct servtab *servtab;

static void usage __P((void));
static void mainloop __P((void));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static ssize_t server6_recv __P((int, char *, size_t));
static ssize_t server6_react __P((int, char *, size_t));
static int server6_react_solicit __P((int, char *, size_t));
static int server6_react_request __P((int, char *, size_t));

int
main(argc, argv)
	int argc;
	char **argv;
{
	extern int optind;
	extern char *optarg;
	int ch;
	struct in6_addr a;

	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "dn:N:")) != EOF) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'n':
			if (inet_pton(AF_INET6, optarg, &a, sizeof(a)) != 1) {
				errx(1, "invalid DNS server %s", optarg);
				/*NOTREACHED*/
			}
			dnsserv = optarg;
			break;
		case 'N':
			dnsdom = optarg;
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

	if (!debug)
		daemon(0, 0);

	mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: dhcp6s [-d] [-n dnsserv] [-N dnsdom] intface\n");
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
	int agent;	/* 0: via relay, 1: direct */
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
		break;
	case DH6_REQUEST:
		server6_react_request(agent, buf, siz);
		break;
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
	int agent;	/* 0: via relay, 1: direct */
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

	/* build new client-agent binding if not present */

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
		if (inet_pton(AF_INET6, "2000::", &target, sizeof(target)) != 1) {
			errx(1, "inet_pton failed");
			/*NOTREACHED*/
		}
		if (getifaddr(&myaddr, device, &target, 3) != 0) {
			if (inet_pton(AF_INET6, "fec0::", &target, sizeof(target)) != 1) {
				errx(1, "inet_pton failed");
				/*NOTREACHED*/
			}
			if (getifaddr(&myaddr, device, &target, 10) != 0) {
				errx(1, "no matching address on %s", device);
				/*NOTREACHED*/
			}
		}
		hlim = 0;
	} else {
		dst.sin6_addr = dh6s->dh6sol_cliaddr;
		dst.sin6_scope_id = if_nametoindex(device);
		dh6a->dh6adv_flags = DH6ADV_SERVPRESENT;
		if (inet_pton(AF_INET6, "fe80::", &target, sizeof(target)) != 1) {
			errx(1, "inet_pton failed");
			/*NOTREACHED*/
		}
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

/* 6.3. DHCP Request and Reply Message Processing */
static int
server6_react_request(agent, buf, siz)
	int agent;	/* 0: via relay, 1: direct */
	char *buf;
	size_t siz;
{
	struct dhcp6_request *dh6r;
	struct dhcp6_reply *dh6p;
	char sbuf[BUFSIZ];
	ssize_t len;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr *servaddr = NULL;
	struct in6_addr myaddr, target;
	int hlim;
	struct dhcp6_opt *opt;
	char *ext;
	time_t t;
	struct tm *tm;
	struct dhcp6e extbuf;

	dprintf((stderr, "react_request\n"));

	if (siz < sizeof(*dh6r)) {
		dprintf((stderr, "react_request: short packet\n"));
		return -1;
	}
	dh6r = (struct dhcp6_request *)buf;

	if (!agent) {
		if (IN6_IS_ADDR_UNSPECIFIED(&dh6r->dh6req_relayaddr)
		 || IN6_IS_ADDR_LINKLOCAL(&dh6r->dh6req_relayaddr)) {
			dprintf((stderr, "react_request: invalid relayaddr "
				"to server addr\n"));
			return -1;
		}
	}
	if (!IN6_IS_ADDR_LINKLOCAL(&dh6r->dh6req_cliaddr)) {
		dprintf((stderr, "react_request: invalid cliaddr\n"));
		return -1;
	}
	if ((dh6r->dh6req_flags & DH6REQ_SERVPRESENT) != 0) {
		if (siz < sizeof(*dh6r) + sizeof(struct in6_addr)) {
			dprintf((stderr, "react_request: short packet\n"));
			return -1;
		}
		servaddr = (struct in6_addr *)(dh6r + 1);
	}

#if 0
	if ((dh6s->dh6sol_flags & DH6SOL_CLOSE) != 0)
		server6_flush(&dh6s->dh6sol_cliaddr, NULL);
#endif

	/* build new client-agent binding if not present */

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

	dh6p = (struct dhcp6_reply *)sbuf;
	len = sizeof(*dh6p);
	memset(dh6p, 0, sizeof(*dh6p));
	dh6p->dh6rep_msgtype = DH6_REPLY;
	if ((dh6r->dh6req_flags & DH6REQ_SERVPRESENT) != 0) {
		dst.sin6_addr = dh6r->dh6req_relayaddr;
		if (inet_pton(AF_INET6, "fec0::", &target, sizeof(target)) != 1) {
			errx(1, "inet_pton failed");
			/*NOTREACHED*/
		}
		if (getifaddr(&myaddr, device, &target, 10) != 0) {
			if (inet_pton(AF_INET6, "2000::", &target, sizeof(target)) != 1) {
				errx(1, "inet_pton failed");
				/*NOTREACHED*/
			}
			if (getifaddr(&myaddr, device, &target, 3) != 0) {
				errx(1, "no matching address on %s", device);
				/*NOTREACHED*/
			}
		}
		hlim = 64;
	} else {
		/* XXX should use ip src on request */
		dst.sin6_addr = dh6r->dh6req_cliaddr;
		dst.sin6_scope_id = if_nametoindex(device);
		if (inet_pton(AF_INET6, "fe80::", &target, sizeof(target)) != 1) {
			errx(1, "inet_pton failed");
			/*NOTREACHED*/
		}
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
	dh6p->dh6rep_xid = dh6r->dh6req_xid;

	/* attach extensions */
	ext = (char *)(dh6p + 1);

	/* DNS server */
	opt = dhcp6opttab_byname("Domain Name Server");
	if (opt && dnsserv) {
		extbuf.dh6e_type = htons(opt->code);
		extbuf.dh6e_len = htons(sizeof(struct in6_addr));
		memcpy(ext, &extbuf, sizeof(extbuf));
		if (inet_pton(AF_INET6, dnsserv, ext + sizeof(extbuf),
				sizeof(struct in6_addr)) != 1) {
			errx(1, "inet_pton failed");
			/*NOTREACHED*/
		}
		ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
	}

	/* DNS domain */
	opt = dhcp6opttab_byname("Domain Name");
	if (opt && dnsdom) {
		int dnsdom_len;

		dnsdom_len = strlen(dnsdom);
		extbuf.dh6e_type = htons(opt->code);
		extbuf.dh6e_len = htons(dnsdom_len);	/*XXX alignment?*/
		memcpy(ext, &extbuf, sizeof(extbuf));
		memset(ext + sizeof(extbuf), 0, ntohs(extbuf.dh6e_len));
		strncpy(ext + sizeof(extbuf), dnsdom, ntohs(extbuf.dh6e_len));
		ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
	}

	/* timezone */
	(void)time(&t);
	tm = localtime(&t);
	if (tm) {
		opt = dhcp6opttab_byname("Time Offset");
		if (opt) {
			union {
				u_int32_t ui;
				int32_t i;
			} tzoff;		/* ugly! */

			tzoff.i = (int32_t)tm->tm_gmtoff;

			extbuf.dh6e_type = htons(opt->code);
			extbuf.dh6e_len = htons(sizeof(u_int32_t));
			memcpy(ext, &extbuf, sizeof(extbuf));
			*(u_int32_t *)(ext + sizeof(extbuf)) = tzoff.ui;
			ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
			len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		}

		opt = dhcp6opttab_byname("IEEE 1003.1 POSIX Timezone");
		if (opt) {
			int zone_len;

			zone_len = strlen(tm->tm_zone);
			extbuf.dh6e_type = htons(opt->code);
			extbuf.dh6e_len = htons(zone_len);	/*XXX alignment?*/
			memcpy(ext, &extbuf, sizeof(extbuf));
			memset(ext + sizeof(extbuf), 0, ntohs(extbuf.dh6e_len));
			strncpy(ext + sizeof(extbuf), tm->tm_zone,
				ntohs(extbuf.dh6e_len));
			ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
			len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		}
	}

	if (transmit_sa(outsock, (struct sockaddr *)&dst, hlim, sbuf, len) != 0) {
		err(1, "transmit failed");
		/*NOTREACHED*/
	}
}
