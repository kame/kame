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
#include <sys/uio.h>
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
#include <errno.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <netinet/in.h>
#include <netinet6/in6_var.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>

#include <dhcp6.h>
#include <common.h>

struct dnslist {
	TAILQ_ENTRY(dnslist) link;
	struct in6_addr addr;
};
TAILQ_HEAD(, dnslist) dnslist;

static int debug = 0;

char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */

static struct msghdr rmh;
static char rdatabuf[BUFSIZ];
static int rmsgctllen;
static char *rmsgctlbuf;

static struct in6_addr link_local_prefix, site_local_prefix, global_prefix;
#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

static void usage __P((void));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static ssize_t server6_recv __P((int, struct sockaddr *, int *));
static void server6_react __P((size_t, struct sockaddr *, int));
static int server6_react_informreq __P((char *, size_t, struct sockaddr *, int));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	struct in6_addr a;
	struct dnslist *dle;
	char *progname;

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	TAILQ_INIT(&dnslist);
	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "dDfn:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'D':
			debug = 2;
			break;
		case 'f':
			foreground++;
			break;
		case 'n':
			if (inet_pton(AF_INET6, optarg, &a) != 1) {
				errx(1, "invalid DNS server %s", optarg);
				/* NOTREACHED */
			}
			if ((dle = malloc(sizeof *dle)) == NULL) {
				errx(1, "malloc failed for a DNS server");
				/* NOTREACHED */
			}
			dle->addr = a;
			TAILQ_INSERT_TAIL(&dnslist, dle, link);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		/* NOTREACHED */
	}
	device = argv[0];

	if (foreground == 0) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
	}
	setloglevel(debug);

	server6_init();

	server6_mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr,
		"usage: dhcp6s [-dDf] [-n dnsserv] intface\n");
	exit(0);
}

/*------------------------------------------------------------*/

void
server6_init()
{
	struct addrinfo hints;
	struct addrinfo *res, *res2;
	int error;
	int ifidx;
	int on = 1;
	struct ipv6_mreq mreq6;
	static struct iovec iov[2];

	ifidx = if_nametoindex(device);
	if (ifidx == 0)
		errx(1, "invalid interface %s", device);

	/* initialize constant variables */
	if (inet_pton(AF_INET6, "fe80::", &link_local_prefix) != 1) {
		errx(1, "inet_pton failed for fec0::");
		/* NOTREACHED */
	}
	if (inet_pton(AF_INET6, "fec0::", &site_local_prefix) != 1) {
		errx(1, "inet_pton failed for fec0::");
		/* NOTREACHED */
	}
	if (inet_pton(AF_INET6, "2000::", &global_prefix) != 1) {
		errx(1, "inet_pton failed");
		/* NOTREACHED */
	}

	/* initialize send/receive buffer */
	iov[0].iov_base = (caddr_t)rdatabuf;
	iov[0].iov_len = sizeof(rdatabuf);
	rmh.msg_iov = iov;
	rmh.msg_iovlen = 1;
	rmsgctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	if ((rmsgctlbuf = (char *)malloc(rmsgctllen)) == NULL) {
		errx(1, "memory allocation failed");
		/* NOTREACHED */
	}

	/* initialize socket */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		err(1, "socket(insock)");
		/* NOTREACHED */
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEPORT,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(insock, SO_REUSEPORT)");
		/* NOTREACHED */
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEADDR,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(insock, SO_REUSEADDR)");
		/* NOTREACHED */
	}
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind(insock)");
		/* NOTREACHED */
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
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
		/* NOTREACHED */
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
		/* NOTREACHED */
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		err(1, "socket(outsock)");
		/* NOTREACHED */
	}
	/* set outgoing interface of multicast packets for DHCP reconfig */
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	    &ifidx, sizeof(ifidx)) < 0) {
		err(1, "setsockopt(outsock, IPV6_MULTICAST_IF)");
		/* NOTREACHED */
	}
	/* make the socket write-only */
	if (shutdown(outsock, 0)) {
		err(1, "shutdown(outbound, 0)");
		/* NOTREACHED */
	}
	freeaddrinfo(res);
}

static void
server6_mainloop()
{
	int ret;
	fd_set r;
	ssize_t l;
	struct sockaddr_storage from;
	int fromlen;

	while (1) {
		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, NULL);
		switch (ret) {
		case -1:
		case 0:
			dprintf(LOG_ERR, "select: %s", strerror(errno));
			exit(1);
			/* NOTREACHED */
		default:
			break;
		}
		if (FD_ISSET(insock, &r)) {
			fromlen = sizeof(from);
			l = server6_recv(insock, (struct sockaddr *)&from,
			    &fromlen);
			if (l > 0) {
				server6_react(l, (struct sockaddr *)&from,
				    fromlen);
			}
		}
	}
}

static ssize_t
server6_recv(s, from, fromlen)
	int s;
	struct sockaddr *from;
	int *fromlen;
{
	ssize_t len;

	len = recvfrom(s, rdatabuf, sizeof(rdatabuf), 0, from, fromlen);
	if (len < 0) {
		dprintf(LOG_WARNING, "recvfrom: %s", strerror(errno));
		return(-1);	/* should assert? */
	}
	dprintf(LOG_DEBUG, "server6_recv: from %s, size %d",
	    addr2str(from), len); 

	return len;
}

static void
server6_react(siz, from, fromlen)
	size_t siz;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6 *dh6;

	if (siz < sizeof(*dh6)) {
		dprintf(LOG_INFO, "relay6_react: short packet");
		return;
	}

	dh6 = (struct dhcp6 *)rdatabuf;
	dprintf(LOG_DEBUG, "msgtype=%d", dh6->dh6_msgtype);

	switch (dh6->dh6_msgtype) {
	case DH6_INFORM_REQ:
		server6_react_informreq(rdatabuf, siz, from, fromlen);
		break;
	default:
		dprintf(LOG_INFO, "unknown msgtype %d", dh6->dh6_msgtype);
		break;
	}
}

static int
server6_react_informreq(buf, siz, from, fromlen)
	char *buf;
	size_t siz;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6 *dh6r;
	struct dhcp6 *dh6p;
	char sbuf[BUFSIZ];
	ssize_t len;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct dhcp6opt *opt;
	char *ext, *ep, *p;

	dprintf(LOG_DEBUG, "react_request");

	if (siz < sizeof(*dh6r)) {
		dprintf(LOG_INFO, "react_request: short packet");
		return(-1);
	}
	dh6r = (struct dhcp6 *)buf;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
		/* NOTREACHED */
	}
	memcpy(&dst, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (sizeof(struct dhcp6) + sizeof(struct in6_addr) > sizeof(sbuf)) {
		dprintf(LOG_ERR, "buffer size assumption failed");
		exit(1);
		/* NOTREACHED */
	}

	dh6p = (struct dhcp6 *)sbuf;
	ep = sbuf + sizeof(sbuf);
	len = sizeof(*dh6p);
	memset(dh6p, 0, sizeof(*dh6p));
	ext = (char *)(dh6p + 1);
	dh6p->dh6_msgtypexid = dh6r->dh6_msgtypexid;
	dh6p->dh6_msgtype = DH6_REPLY;
	if (getifaddr(&dh6p->dh6_servaddr, device, &global_prefix, GLOBAL_PLEN,
	    0, IN6_IFF_INVALID) != 0) {
		dprintf(LOG_ERR, "could not get global address");
		exit(1);
		/* NOTREACHED */
	}

	/*
	 * attach extensions.
	 */
	/* DNS server */
	opt = (struct dhcp6opt *)ext;
	if (ext + sizeof(*opt) + sizeof(struct in6_addr) <= ep &&
	    TAILQ_FIRST(&dnslist)) {
		struct dnslist *d;

		opt->dh6opt_type = htons(DH6OPT_DNS);
		opt->dh6opt_len = 0;
		len += sizeof(*opt);

		p = (char *)(opt + 1);
		for (d = TAILQ_FIRST(&dnslist); d; d = TAILQ_NEXT(d, link)) {
			if (p + sizeof(struct in6_addr) > ep)
				break;

			memcpy(p, &d->addr, sizeof(struct in6_addr));
			opt->dh6opt_len += sizeof(struct in6_addr);
			p += sizeof(struct in6_addr);
			len += sizeof(struct in6_addr);
		}
		opt->dh6opt_len = htons(opt->dh6opt_len);
	}

	dst.sin6_addr = ((struct sockaddr_in6 *)from)->sin6_addr;
	dst.sin6_scope_id = ((struct sockaddr_in6 *)from)->sin6_scope_id;

	if (transmit_sa(outsock, (struct sockaddr *)&dst, 0, sbuf, len) != 0) {
		dprintf(LOG_ERR, "transmit to %s failed",
			addr2str((struct sockaddr *)&dst));
		/* NOTREACHED */
	}

	return 0;
}
