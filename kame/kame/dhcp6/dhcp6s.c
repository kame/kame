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
#include <dhcp6opt.h>
#include <common.h>

struct servtab {
	struct servtab *next;
	u_int32_t pref;
	struct in6_addr llcli;
	struct in6_addr relay;
	struct in6_addr serv;
};

struct dnslist {
	TAILQ_ENTRY(dnslist) link;
	struct in6_addr addr;
};
TAILQ_HEAD(, dnslist) dnslist;

static int debug = 0;

char *device = NULL;
char *dnsdom = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */

static struct msghdr rmh;
static char rdatabuf[BUFSIZ];
static int rmsgctllen;
static char *rmsgctlbuf;

struct servtab *servtab;

static struct in6_addr link_local_prefix, site_local_prefix, global_prefix;
#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

static void usage __P((void));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static ssize_t server6_recv __P((int, struct in6_pktinfo *));
static void server6_react __P((size_t, struct in6_pktinfo *));
static int server6_react_solicit __P((char *, size_t, struct in6_pktinfo *));
static int server6_react_request __P((char *, size_t, struct in6_pktinfo *));

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
	while ((ch = getopt(argc, argv, "dDfn:N:")) != -1) {
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
		case 'N':
			dnsdom = optarg;
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
	server6_init();

	if (foreground == 0) {
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
		if (daemon(0, 0) < 0)
			err(1, "daemon");
	}
	setloglevel(debug);

	server6_mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr,
		"usage: dhcp6s [-dDf] [-n dnsserv] [-N dnsdom] intface\n");
	exit(0);
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
		/* NOTREACHED */
	}
	if (fd && cap) {
		errx(1, "internal error: both fd and cap are present");
		/* NOTREACHED */
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

	/* initiilize socket */
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
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(IPV6_RECVPKTINFO)");
	}
#else
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_PKTINFO,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(IPV6_PKTINFO)");
	}
#endif
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

	servtab = NULL;
}

#if 0
static void
tvfix(tv)
	struct timeval *tv;
{
	long s;
	s = tv->tv_usec / (1000 * 1000);
	tv->tv_usec %= (1000 * 1000);
	tv->tv_sec += s;
}
#endif

static void
server6_mainloop()
{
	int ret;
	fd_set r;
	ssize_t l;
	struct in6_pktinfo rcvpktinfo;

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
			if ((l = server6_recv(insock, &rcvpktinfo)) > 0)
				server6_react(l, &rcvpktinfo);
		}
	}
}

static ssize_t
server6_recv(s, rcvpi)
	int s;
	struct in6_pktinfo *rcvpi;
{
	ssize_t len;
	struct sockaddr_storage from;
	struct in6_pktinfo *pi = NULL;
	struct cmsghdr *cm;

	rmh.msg_control = (caddr_t)rmsgctlbuf;
	rmh.msg_controllen = rmsgctllen;
	rmh.msg_name = (caddr_t)&from;
	rmh.msg_namelen = sizeof(from);

	if ((len = recvmsg(s, &rmh, 0)) < 0) {
		dprintf(LOG_WARNING, "recvmsg: %s", strerror(errno));
		return(-1);	/* should assert? */
	}
	dprintf(LOG_DEBUG, "server6_recv: from %s, size %d",
		addr2str((struct sockaddr *)&from), len); 

	/* get optional information as ancillary data (if available) */
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&rmh); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&rmh, cm)) {
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		switch(cm->cmsg_type) {
		case IPV6_PKTINFO:
			pi = (struct in6_pktinfo *)CMSG_DATA(cm);
			break;
		}
	}
	if (rcvpi) {
		if (pi == NULL) {
			dprintf(LOG_WARNING,
				"server6_recv: we need rcvif but we couldn't");
			return(-1);
		}

		*rcvpi = *pi;
	}

	return len;
}

static void
server6_react(siz, rcvpi)
	size_t siz;
	struct in6_pktinfo *rcvpi; /* incoming interface */
{
	union dhcp6 *dh6;

	if (siz < 1) {		/* we need at least 1 byte to check type */
		dprintf(LOG_INFO, "relay6_react: short packet");
		return;
	}

	dh6 = (union dhcp6 *)rdatabuf;
	dprintf(LOG_DEBUG, "msgtype=%d", dh6->dh6_msgtype);

	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT:
		server6_react_solicit(rdatabuf, siz, rcvpi);
		break;
	case DH6_ADVERT:
		break;
	case DH6_REQUEST:
		server6_react_request(rdatabuf, siz, rcvpi);
		break;
	case DH6_REPLY:
	case DH6_RELEASE:
	case DH6_RECONFIG:
		break;
	default:
		dprintf(LOG_INFO, "invalid msgtype %d", dh6->dh6_msgtype);
	}
}

/* 10.5.1. Receipt of Solicit messages */
/* 10.5.2. Creation and sending of Advertise messages */
static int
server6_react_solicit(buf, siz, rcvpi)
	char *buf;
	size_t siz;
	struct in6_pktinfo *rcvpi;
{
	struct dhcp6_solicit *dh6s;
	struct dhcp6_advert *dh6a;
	char sbuf[BUFSIZ], ifnam[IF_NAMESIZE];
	ssize_t len;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr servaddr;
	int hlim, agent;

	dprintf(LOG_DEBUG, "react_solicit");

	if (if_indextoname(rcvpi->ipi6_ifindex, ifnam) == NULL) {
		/* it should be impossible, so we might have to assert here */
		dprintf(LOG_WARNING, "if_nametoindex failed for ID %d",
			rcvpi->ipi6_ifindex);
		return(-1);
	}

	if (siz < sizeof(*dh6s)) {
		dprintf(LOG_INFO, "react_solicit: short packet");
		return(-1);
	}
	dh6s = (struct dhcp6_solicit *)buf;

	/* 10.1. Solicit Message Validation */
	if (!IN6_IS_ADDR_LINKLOCAL(&dh6s->dh6sol_cliaddr)) {
		dprintf(LOG_INFO,
			 "react_solicit: invalid cliaddr: %s",
			 in6addr2str(&dh6s->dh6sol_cliaddr, 0));
		return(-1);
	}

	agent = !IN6_IS_ADDR_UNSPECIFIED(&dh6s->dh6sol_relayaddr);
	if (agent) {
		int plen = DH6SOL_SOLICIT_PLEN(ntohs(dh6s->dh6sol_plen_id));

		if (plen == 0) {
			dprintf(LOG_INFO,
				"react_solicit: 0 prefix length is not "
				"allowed when relayed");
			return(-1);
		}

		if (IN6_IS_ADDR_LINKLOCAL(&dh6s->dh6sol_relayaddr) ||
		    IN6_IS_ADDR_LOOPBACK(&dh6s->dh6sol_relayaddr)) {
			dprintf(LOG_INFO,
				"react_solicit: bad relay address %s",
				 in6addr2str(&dh6s->dh6sol_relayaddr, 0));
			return(-1);
		}
		/*
		 * If the relay address has a smaller scope than the scope of
		 * the solicitation's destination, the solicitation message
		 * message might have broken a scope boundary.
		 */
		if (in6_scope(&dh6s->dh6sol_relayaddr) <
		    in6_scope(&rcvpi->ipi6_addr)) {
			dprintf(LOG_INFO,
				"react_solicit: bad relay address %s with dst %s",
				 in6addr2str(&dh6s->dh6sol_relayaddr, 0),
				 in6addr2str(&rcvpi->ipi6_addr, 0));
			return(-1);
		}
	}

	if (agent) {		/* relay address is specified */
		/*
		 * The ``relay-address'' field MUST contain an address of
		 * sufficient scope that is reachable by the server.
		 * Otherwise, the solicitation must be discarded.
		 */
		if (IN6_IS_ADDR_SITELOCAL(&dh6s->dh6sol_relayaddr)) {
			if (getifaddr(&servaddr, ifnam, &site_local_prefix,
				      SITE_LOCAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
				if (getifaddr(&servaddr, ifnam, &global_prefix,
					      GLOBAL_PLEN, 0, IN6_IFF_INVALID)
				    != 0) {
					dprintf(LOG_INFO,
						"react_solicit: can't find "
						"server address for relay %s",
						in6addr2str(&dh6s->dh6sol_relayaddr, 0));
					return(-1);
				}
			}
		}
		else if (getifaddr(&servaddr, ifnam, &global_prefix,
			      GLOBAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
			dprintf(LOG_WARNING,
				"react_solicit: can't find global on %s",
				 ifnam);
			return(-1);
		}
	} else {
		if (getifaddr(&servaddr, ifnam, &link_local_prefix,
			      LINK_LOCAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
			dprintf(LOG_WARNING,
				"react_solicit: can't find link-local on %s",
				 ifnam);
			/*
			 * This situation should be fairely serious.
			 * Should we assert here?
			 */
			return(-1);
		}
	}

#if 0
	if ((dh6s->dh6sol_flags & DH6SOL_CLOSE) != 0)
		server6_flush(&dh6s->dh6sol_cliaddr, NULL);
#endif
	if ((dh6s->dh6sol_flags & DH6SOL_PREFIX) != 0) {
		dprintf(LOG_INFO,
			"react_solicit: P bit is set, but not implemented");
		/* proceed anyway */
	}

	/*
	 * Build new client-agent binding if not present
	 * XXX: not implemented yet.
	 */

	/* prepare advertise message */
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
	if (agent) {
		dst.sin6_addr = dh6s->dh6sol_relayaddr;
		hlim = 0;
	} else {
		dst.sin6_addr = dh6s->dh6sol_cliaddr;
		dst.sin6_scope_id = rcvpi->ipi6_ifindex;
		hlim = 1;
	}

	dh6a = (struct dhcp6_advert *)sbuf;
	len = sizeof(*dh6a);
	memset(dh6a, 0, sizeof(*dh6a));
	dh6a->dh6adv_msgtype = DH6_ADVERT;
	/* Copy soclit-ID. XXX: note that it's a 9bit field... */
	memcpy(&dh6a->dh6adv_rsv_id, &dh6s->dh6sol_plen_id, 2);
	dh6a->dh6adv_rsv_id &= 0x01;
	memcpy(&dh6a->dh6adv_cliaddr, &dh6s->dh6sol_cliaddr,
		sizeof(dh6s->dh6sol_cliaddr));
	/* copy the relay address (regardless of its value) */
	memcpy(&dh6a->dh6adv_relayaddr, &dh6s->dh6sol_relayaddr,
	       sizeof(dh6s->dh6sol_relayaddr));

	memcpy(&dh6a->dh6adv_serveraddr, &servaddr, sizeof(servaddr));
	dh6a->dh6adv_pref = DEFAULT_SERVER_PREFERENCE;

	if (transmit_sa(outsock, (struct sockaddr *)&dst, hlim, sbuf, len) != 0) {
		/* XXX: can we believe errno has a valid value? */
		dprintf(LOG_WARNING, "transmit to %s failed",
			addr2str((struct sockaddr *)&dst), strerror(errno));
		return(-1);
	}
	return(0);
}

/*
 * 15/12 drafts are silent about padding requirement,
 * and string termination requirement for extensions.
 * at IETF48 dhc session, author confirmed that:
 * - no string termination character
 * - no padding (= unaligned extensions)
 */
/* 11.6.1. Receipt of Request messages */
/* 11.6.3. Creation and sending of Reply messages */
static int
server6_react_request(buf, siz, rcvpi)
	char *buf;
	size_t siz;
	struct in6_pktinfo *rcvpi;
{
	struct dhcp6_request *dh6r;
	struct dhcp6_reply *dh6p;
	char sbuf[BUFSIZ], ifnam[IF_NAMESIZE];
	ssize_t len;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr myaddr, target;
	struct dhcp6_opt *opt;
	char *ext, *ep;
	time_t t;
	struct tm *tm;
	struct dhcp6e extbuf;
	int agent;
/* 15/12 draft was unclear - author confirmed, no zero termination */
#define PADLEN0(x)	((x))
/* 15/12 draft was unclear - author confirmed, no padding */
#define PADLEN(x)	(PADLEN0((x)))

	dprintf(LOG_DEBUG, "react_request");

	if (if_indextoname(rcvpi->ipi6_ifindex, ifnam) == NULL) {
		/* it should be impossible, so we might have to assert here */
		dprintf(LOG_ERR, "if_nametoindex failed for ID %d",
			rcvpi->ipi6_ifindex);
		return(-1);
	}
	if (siz < sizeof(*dh6r)) {
		dprintf(LOG_INFO, "react_request: short packet");
		return(-1);
	}
	dh6r = (struct dhcp6_request *)buf;

	/* 11.1. Request Message Validation */

	/*
	 * ``client's link-local address'' field MUST contain a valid link-local
	 * address.
	 */
	if (!IN6_IS_ADDR_LINKLOCAL(&dh6r->dh6req_cliaddr)) {
		dprintf(LOG_INFO,
			"react_request: invalid cliaddr: %s",
			in6addr2str(&dh6r->dh6req_cliaddr, 0));
		return(-1);
	}

	/*
	 * The ``server-address'' field value MUST match one of the
	 * server's addresses.
	 */
	if (getifaddr(&target, ifnam, &dh6r->dh6req_serveraddr, 128,
		      0, 0) != 0) {
		dprintf(LOG_WARNING, "server6_react_request: "
			"server-address %s does not match",
			in6addr2str(&dh6r->dh6req_serveraddr,
				    in6_addrscopebyif(&dh6r->dh6req_serveraddr,
						      ifnam)));
		return(-1);
	}

	/*
	 * If the ``relay-address'' field is not the zero address, then that
	 * field's value MUST contain an address of sufficient scope as to be
	 * reachable by the server.
	 */
	if ((agent = !IN6_IS_ADDR_UNSPECIFIED(&dh6r->dh6req_relayaddr)) != 0) {
		if (IN6_IS_ADDR_LINKLOCAL(&dh6r->dh6req_relayaddr) ||
		    IN6_IS_ADDR_LOOPBACK(&dh6r->dh6req_relayaddr)) {
			dprintf(LOG_INFO,
				"react_request: bad relay address %s",
				in6addr2str(&dh6r->dh6req_relayaddr, 0));
			return(-1);
		}

		/*
		 * If the relay address has a smaller scope than the scope of
		 * the request's destination, the request message might have
		 * broken a scope boundary.
		 */
		if (in6_scope(&dh6r->dh6req_relayaddr) <
		    in6_scope(&rcvpi->ipi6_addr)) {
			dprintf(LOG_INFO,
				"react_request: bad relay address %s with dst %s",
				in6addr2str(&dh6r->dh6req_relayaddr, 0),
				in6addr2str(&rcvpi->ipi6_addr, 0));
			return(-1);
		}

		/* If we have a global address, there's no problem. */
		if (getifaddr(&myaddr, ifnam, &global_prefix,
			      GLOBAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
			if (!IN6_IS_ADDR_SITELOCAL(&dh6r->dh6req_relayaddr)) {
				dprintf(LOG_INFO,
					"react_request: relay has a too large scope: %s",
					in6addr2str(&dh6r->dh6req_relayaddr, 0));
				return(-1);
			}
			/* relay is site-local, so site-local is OK as well */
			if (getifaddr(&myaddr, ifnam, &site_local_prefix,
				      SITE_LOCAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
				dprintf(LOG_INFO,
					"react_request: relay has a too large scope: %s",
					in6addr2str(&dh6r->dh6req_relayaddr, 0));
				return(-1);
			}
		}
	}

	/*
	 * If the client has set the ``C'' bit, the server MUST release all
	 * releasable resources currently associated with the client's binding
	 * that do not appear in the ``extensions'' field.
	 */
	if ((dh6r->dh6req_flags & DH6REQ_CLOSE) != 0) {
		dprintf(LOG_INFO,
			"react_request: C bit is set, but ignore it");
		/* proceed anyway */
	}

	/*
	 * If the client has set the ``R'' bit, the server MUST delete any
	 * transaction-ID cache entries it is maintaining for this client, if
	 * the server implements such a cache.
	 */
	if ((dh6r->dh6req_flags & DH6REQ_REBOOT) != 0) {
		dprintf(LOG_INFO,
			"react_request: C bit is set, but we have no cache");
	}

	/*
	 * The ``extensions'' field contains an authentication extension,
	 * and the server cannot successfully authenticate the client.
	 */

	/* build new client-agent binding if not present */
	/* not implemented yet */

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

	if (sizeof(struct dhcp6_reply) + sizeof(struct in6_addr) > sizeof(sbuf)) {
		dprintf(LOG_ERR, "buffer size assumption failed");
		exit(1);
		/* NOTREACHED */
	}

	dh6p = (struct dhcp6_reply *)sbuf;
	ep = sbuf + sizeof(sbuf);
	len = sizeof(*dh6p);
	memset(dh6p, 0, sizeof(*dh6p));
	ext = (char *)(dh6p + 1);
	dh6p->dh6rep_msgtype = DH6_REPLY;
	dh6p->dh6rep_xid = dh6r->dh6req_xid;
	dh6p->dh6rep_cliaddr = dh6r->dh6req_cliaddr;
	if (agent) {
		memcpy(dh6p + 1, &dh6r->dh6req_relayaddr,
		       sizeof(struct in6_addr));
		dh6p->dh6rep_flagandstat |= DH6REP_RELAYPRESENT;

		len += sizeof(struct in6_addr);
		ext += sizeof(struct in6_addr);

		dst.sin6_addr = dh6r->dh6req_relayaddr;
		dst.sin6_scope_id = in6_addrscopebyif(&dh6r->dh6req_relayaddr,
						      ifnam);
	} else {
		dst.sin6_addr = dh6r->dh6req_cliaddr;
		dst.sin6_scope_id = in6_addrscopebyif(&dh6r->dh6req_cliaddr,
						      ifnam);
	}

	/*
	 * attach extensions.
	 */
	/* DNS server */
	opt = dhcp6opttab_byname("Domain Name Server");
	if (opt) {
		struct dnslist *d;

		for (d = TAILQ_FIRST(&dnslist); d; d = TAILQ_NEXT(d, link)) {
			if (ext + sizeof(extbuf) + sizeof(struct in6_addr) > ep)
				break;

			extbuf.dh6e_type = htons(opt->code);
			extbuf.dh6e_len = htons(sizeof(struct in6_addr));
			memcpy(ext, &extbuf, sizeof(extbuf));
			memcpy(ext + sizeof(extbuf), &d->addr,
			       sizeof(struct in6_addr));
			ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
			len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		}
	}

	/* DNS domain */
	opt = dhcp6opttab_byname("Domain Name");
	if (opt && dnsdom &&
	    ext + sizeof(extbuf) + PADLEN(strlen(dnsdom)) <= ep) {
		int dnsdom_len;

		dnsdom_len = strlen(dnsdom);
		extbuf.dh6e_type = htons(opt->code);
		extbuf.dh6e_len = PADLEN(dnsdom_len);
		extbuf.dh6e_len = htons(extbuf.dh6e_len);
		memcpy(ext, &extbuf, sizeof(extbuf));
		memset(ext + sizeof(extbuf), 0, ntohs(extbuf.dh6e_len));
		memcpy(ext + sizeof(extbuf), dnsdom, ntohs(extbuf.dh6e_len));
		ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
	}

	/* timezone */
	(void)time(&t);
	tm = localtime(&t);
	if (tm) {
		opt = dhcp6opttab_byname("Time Offset");
		if (opt && ext + sizeof(extbuf) + sizeof(u_int32_t) <= ep) {
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
		if (opt &&
		    ext + sizeof(extbuf) + PADLEN(strlen(tm->tm_zone)) <= ep) {
			int zone_len;

			zone_len = strlen(tm->tm_zone);
			extbuf.dh6e_type = htons(opt->code);
			extbuf.dh6e_len = PADLEN(zone_len);
			extbuf.dh6e_len = htons(extbuf.dh6e_len);
			memcpy(ext, &extbuf, sizeof(extbuf));
			memset(ext + sizeof(extbuf), 0, ntohs(extbuf.dh6e_len));
			memcpy(ext + sizeof(extbuf), tm->tm_zone,
			    strlen(tm->tm_zone));
			ext += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
			len += sizeof(extbuf) + ntohs(extbuf.dh6e_len);
		}
	}

	if (transmit_sa(outsock, (struct sockaddr *)&dst, 0, sbuf, len) != 0) {
		dprintf(LOG_ERR, "transmit to %s failed",
			addr2str((struct sockaddr *)&dst));
		/* NOTREACHED */
	}

	return 0;
#undef PADLEN0
#undef PADLEN
}
