/*	$KAME: dhcp6relay.c,v 1.34 2002/09/24 14:20:49 itojun Exp $	*/
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
#include <sys/queue.h>
#include <sys/uio.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <netinet6/in6_var.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>		/* XXX: freebsd2 needs this for opt{arg,ind} */
#include <errno.h>
#include <err.h>
#include <string.h>

#include <dhcp6.h>
#include <common.h>

static int ssock;		/* socket for servers */
static int csock;		/* socket for clients */
static int icmp6sock;		/* socket to receive ICMPv6 errors */
static int maxfd;		/* maxi file descriptor for select(2) */

static int debug = 0;

char *device = NULL;		/* must be global */

static char *rmsgctlbuf, *smsgctlbuf;
static int rmsgctllen, smsgctllen;
static struct msghdr rmh, smh;
static char rdatabuf[BUFSIZ];
static struct in6_pktinfo *spktinfo;

static int mhops = DEFAULT_SOLICIT_HOPCOUNT;

static struct sockaddr_in6 sa6_all_servers, sa6_client;

struct prefix_list {
	TAILQ_ENTRY(prefix_list) plink;
	struct sockaddr_in6 paddr; /* contains meaningless but enough members */
	int plen;
};
TAILQ_HEAD(, prefix_list) global_prefixes; /* list of non-link-local prefixes */
static char *global_strings[] = {
	"fec0::/10", "2000::/3",
};

static void usage __P((void));
static struct prefix_list *make_prefix __P((char *));
static void relay6_init __P((void));
static void relay6_loop __P((void));
static int relay6_recv __P((int, char *));
static void relay6_react __P((size_t, char *, char *, int));
static void relay6_react_solicit __P((char *, size_t, char *));
static void relay6_react_advert __P((char *, size_t, char *));
static void relay6_forward_response __P((char *, size_t, struct in6_addr *,
	const char *));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	char *progname;
	char *p;

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	while((ch = getopt(argc, argv, "dDfH:")) != -1) {
		switch(ch) {
		case 'd':
			debug = 1;
			break;
		case 'D':
			debug = 2;
			break;
		case 'f':
			foreground++;
			break;
		case 'H':
			p = NULL;
			mhops = (int)strtoul(optarg, &p, 10);
			if (!*optarg || *p) {
				errx(1, "illegal hop limit: %s", optarg);
				/* NOTREACHED */
			}
			if (mhops <= 0 || mhops > 255) {
				errx(1, "illegal hop limit: %d", mhops);
				/* NOTREACHED */
			}
			break;
		default:
			usage();
			exit(0);
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

	relay6_init();

	relay6_loop();

	exit(0);
}

static void
usage()
{
	fprintf(stderr,
		"usage: dhcp6relay [-dDf] [-H hoplim] intface\n");
	exit(0);
}

static struct prefix_list *
make_prefix(pstr0)
	char *pstr0;
{
	struct prefix_list *pent;
	char *p, *ep;
	int plen;
	char pstr[BUFSIZ];
	struct in6_addr paddr;

	/* make a local copy for safety */
	if (strlcpy(pstr, pstr0, sizeof(pstr)) >= sizeof(pstr)) {
		dprintf(LOG_WARNING,
			"prefix string too long (maybe bogus): %s", pstr0);
		return (NULL);
	}

	/* parse the string */
	if ((p = strchr(pstr, '/')) == NULL)
		plen = 128; /* assumes it as a host prefix */
	else {
		if (p[1] == '\0') {
			dprintf(LOG_WARNING,
				"no prefix length (ignored): %s", p + 1);
			return (NULL);
		}
		plen = (int)strtoul(p + 1, &ep, 10);
		if (*ep != '\0') {
			dprintf(LOG_WARNING,
				"illegal prefix length (ignored): %s", p + 1);
			return (NULL);
		}
		*p = '\0';
	}
	if (inet_pton(AF_INET6, pstr, &paddr) != 1) {
		dprintf(LOG_ERR, "inet_pton failed for %s", pstr); /* warn? */
		exit(1);
		/* NOTREACHED */
	}

	/* allocate a new entry */
	if ((pent = (struct prefix_list *)malloc(sizeof(*pent))) == NULL) {
		dprintf(LOG_ERR, "memory allocation failed");
		exit(1);
		/* NOTREACHED */
	}

	/* fill in each member of the entry */
	memset(pent, 0, sizeof(*pent));
	pent->paddr.sin6_family = AF_INET6;
	pent->paddr.sin6_len = sizeof(struct sockaddr_in6);
	pent->paddr.sin6_addr = paddr;
	pent->plen = plen;

	return (pent);
}


static void
relay6_init()
{
	struct addrinfo hints;
	struct addrinfo *res, *res2;
	int i, ifidx, error;
	struct ipv6_mreq mreq6;
	int type;
	struct icmp6_filter filt;
	int on = 1;
	static struct iovec iov[2];
	struct cmsghdr *cm;

	/* initialize non-link-local prefixes list */
	TAILQ_INIT(&global_prefixes);
	for (i = 0; global_strings[i]; i++) {
		struct prefix_list *p;
		
		if ((p = make_prefix(global_strings[i])) != NULL)
			TAILQ_INSERT_TAIL(&global_prefixes, p, plink);
	}

	/* initialize special socket addresses */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(DH6ADDR_ALLSERVER, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	if (res->ai_family != PF_INET6 ||
	    res->ai_addrlen < sizeof(sa6_all_servers)) {
		/* this should be impossible, but check for safety */
		errx(1, "getaddrinfor returned a bogus address");
		/* NOTREACHED */
	}
	memcpy(&sa6_all_servers, res->ai_addr, sizeof(sa6_all_servers));
	freeaddrinfo(res);

	/* initialize send/receive buffer */
	iov[0].iov_base = (caddr_t)rdatabuf;
	iov[0].iov_len = sizeof(rdatabuf);
	rmh.msg_iov = iov;
	rmh.msg_iovlen = 1;
	rmsgctllen = smsgctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	if ((rmsgctlbuf = (char *)malloc(rmsgctllen)) == NULL) {
		errx(1, "memory allocation failed");
		/* NOTREACHED */
	}
	if ((smsgctlbuf = (char *)malloc(smsgctllen)) == NULL) {
		errx(1, "memory allocation failed");
		/* NOTREACHED */
	}
	smh.msg_controllen = smsgctllen;
	smh.msg_control = smsgctlbuf;
	cm = (struct cmsghdr *)CMSG_FIRSTHDR(&smh);
	cm->cmsg_len = CMSG_LEN(sizeof(*spktinfo));
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	spktinfo = (struct in6_pktinfo *)CMSG_DATA((struct cmsghdr *)cm);

	/*
	 * Setup a socket to communicate with clients.
	 */
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
		/* NOTREACHED */
	}
	csock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (csock < 0) {
		err(1, "socket(csock)");
		/* NOTREACHED */
	}
	if (csock > maxfd)
		maxfd = csock;
	if (setsockopt(csock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
		err(1, "setsockopt(csock, SO_REUSEPORT)");
		/* NOTREACHED */
	}
	if (setsockopt(csock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		err(1, "setsockopt(csock, SO_REUSEADDR)");
		/* NOTREACHED */
	}
	if (setsockopt(csock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		err(1, "setsockopt(csock, IPV6_V6ONLY)");
		/* NOTREACHED */
	}
	if (bind(csock, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind(csock)");
		/* NOTREACHED */
	}
	freeaddrinfo(res);
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(csock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(IPV6_RECVPKTINFO)");
		/* NOTREACHED */
	}
#else
	if (setsockopt(csock, IPPROTO_IPV6, IPV6_PKTINFO,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(IPV6_PKTINFO)");
		/* NOTREACHED */
	}
#endif

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLAGENT, 0, &hints, &res2);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
		&((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
		sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(csock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq6, sizeof(mreq6))) {
		err(1, "setsockopt(csock, IPV6_JOIN_GROUP)");
	}
	freeaddrinfo(res2);

	/*
	 * Setup a socket to communicate with servers.
	 */
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	ssock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (ssock < 0) {
		err(1, "socket(outsock)");
		/* NOTREACHED */
	}
	if (ssock > maxfd)
		maxfd = ssock;
	if (setsockopt(ssock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
		err(1, "setsockopt(ssock, SO_REUSEPORT)");
		/* NOTREACHED */
	}
	if (setsockopt(ssock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		err(1, "setsockopt(ssock, IPV6_V6ONLY)");
		/* NOTREACHED */
	}
	if (bind(ssock, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind(ssock)");
		/* NOTREACHED */
	}
	memcpy(&sa6_client, res->ai_addr, sizeof(sa6_client));
	freeaddrinfo(res);

	if (setsockopt(ssock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &mhops,
		       sizeof(mhops)) < 0) {
		err(1, "setsockopt(ssock, IPV6_MULTICAST_HOPS(%d))", mhops);
		/* NOTREACHED */
	}
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(ssock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(IPV6_RECVPKTINFO)");
		/* NOTREACHED */
	}
#else
	if (setsockopt(ssock, IPPROTO_IPV6, IPV6_PKTINFO,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(IPV6_PKTINFO)");
		/* NOTREACHED */
	}
#endif

	/*
	 * Setup a socket to receive ICMPv6 errors.
	 */
	if ((icmp6sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		err(1, "socket(ICMPV6)");
		/* NOTREACHED */
	}
	if (icmp6sock > maxfd) maxfd = icmp6sock;
	/* set filter to receive error messages only */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	for (type = 0; type < 128; type++)
		ICMP6_FILTER_SETPASS(type, &filt);
	if (setsockopt(icmp6sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		       sizeof(filt)) < 0)
		err(1, "setsockopt(ICMP6_FILTER)");
}

static void
relay6_loop()
{
	fd_set readfds;
	char rdev[IF_NAMESIZE];
	int e, cc;

	while(1) {
		/* we'd rather use FD_COPY here, but it's not POSIX friendly */
		FD_ZERO(&readfds);
		FD_SET(csock, &readfds);
		FD_SET(ssock, &readfds);
		FD_SET(icmp6sock, &readfds);

		e = select(maxfd + 1, &readfds, NULL, NULL, NULL);
		switch(e) {
		case 0:		/* impossible in our situation */
			errx(1, "select returned 0");
				/* NOTREACHED */
		case -1:
			err(1, "select");
				/* NOTREACHED */
		default:
			break;
		}

		if (FD_ISSET(csock, &readfds) &&
		    (cc = relay6_recv(csock, rdev)) > 0)
			relay6_react(cc, rdatabuf, rdev, 1);

		if (FD_ISSET(ssock, &readfds) &&
		    (cc = relay6_recv(ssock, rdev)) > 0)
			relay6_react(cc, rdatabuf, rdev, 0);

		if (FD_ISSET(icmp6sock, &readfds) &&
		    (cc = relay6_recv(icmp6sock, NULL)) > 0) {
#ifdef notyet
			icmp6_react();
#endif 
		}
	}
}

static int
relay6_recv(s, rdevice)
	int s;
	char *rdevice;
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
		return (-1);	/* should assert? */
	}

	dprintf(LOG_DEBUG, "relay6_recv: from %s, size %d",
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
	if (rdevice) {
		if (pi == NULL) {
			dprintf(LOG_WARNING, "relay6_recv: "
				"failed to get the arrival interface");
			return (-1);
		}
		if (if_indextoname(pi->ipi6_ifindex, rdevice) == NULL) {
			dprintf(LOG_WARNING, "if_indextoname(id = %d): %s",
				pi->ipi6_ifindex, strerror(errno));
			return (-1);
		}
	}

	return (len);
}

static void
relay6_react(siz, buf, dev, fromclient)
	size_t siz;
	int fromclient;
	char *buf, *dev;
{
	union dhcp6 *dh6;

	if (siz < 1) {		/* we need at least 1 byte to check type */
		dprintf(LOG_DEBUG, "relay6_react: short packet");
		return;
	}
	
	dh6 = (union dhcp6 *)buf;
	dprintf(LOG_DEBUG, "relay6_react: msgtype=%d", dh6->dh6_msgtype);

	if (fromclient) {
		switch (dh6->dh6_msgtype) {
		case DH6_SOLICIT:
			relay6_react_solicit(buf, siz, dev);
			break;
		case DH6_REQUEST:
#ifdef notyet
			relay6_react_request(buf, siz, dev);
#endif 
			break;
		default:
			fprintf(stderr, "invalid msgtype (%d) from client",
				dh6->dh6_msgtype);
			break;
		}
	}
	else {
		switch (dh6->dh6_msgtype) {
		case DH6_ADVERT:
			relay6_react_advert(buf, siz, dev);
			break;
		case DH6_REPLY:
#ifdef notyet
			relay6_react_reply(buf, siz, dev);
#endif
			break;
		default:
			fprintf(stderr, "invalid msgtype (%d) from server",
				dh6->dh6_msgtype);
			break;
		}
	}
}
	
static void
relay6_react_solicit(buf, siz, dev)
	char *buf, *dev;
	size_t siz;
{
	struct dhcp6_solicit *dh6s;
	struct prefix_list *p;
	static struct iovec iov[2];
	struct in6_addr myaddr;
	int plen;
	u_char *cp_plen;

	dprintf(LOG_DEBUG, "relay6_react_solicit");

	if (siz < sizeof(*dh6s)) {
		dprintf(LOG_INFO,
			"relay6_react_solicit: short packet (size = %d)", siz);
		return;
	}
	dh6s = (struct dhcp6_solicit *)buf;

	if (!IN6_IS_ADDR_LINKLOCAL(&dh6s->dh6sol_cliaddr)) {
		dprintf(LOG_INFO,
			"relay6_react_solicit: client address (%s) is not "
			"link-local", in6addr2str(&dh6s->dh6sol_cliaddr, 0));
		return;
	}

	/*
	 * When sending a DHCP Solicit message, a client MUST set the Relay
	 * Address field to 16 octets of zeros, and zero the prefix-size
	 * field.
	 * But we just warn if the client did not conformed to these rules.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(&dh6s->dh6sol_relayaddr)) {
		dprintf(LOG_INFO,
			"relay6_react_solicit: relay address (%s) is not "
			"the Unspecified address (ignored)",
			in6addr2str(&dh6s->dh6sol_relayaddr, 0));
	}

	/* find a non-link-local address and fill in the relay address field */
	memset(&myaddr, 0, sizeof(myaddr));
	for (p = TAILQ_FIRST(&global_prefixes); p; p = TAILQ_NEXT(p, plink)) {
		if (getifaddr(&myaddr, dev, &p->paddr.sin6_addr,
			      p->plen, 0, IN6_IFF_INVALID) == 0) /* found */
			break;
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&myaddr)) {
		dprintf(LOG_WARNING,
			"relay6_react_solicit: can't find a non-link-local "
			"address on %s", dev);
		return;
	}
	dh6s->dh6sol_relayaddr = myaddr;
	/*
	 * Also places the number of bits of that make up the subnet prefix
	 * for this address in the ``prefix-len'' field of the Solicit.
	 * XXX: we blindly assume the length is 64 for now...
	 */
	cp_plen = (u_char *)&dh6s->dh6sol_plen_id;
	plen = 64;		/* XXX */
	*cp_plen &= 0x01; /* clear prefix-len for safety */
	*cp_plen |= ((plen & 0xff) << 1);

	/* set the source address and the outgoing interface */
	memset(spktinfo, 0, sizeof(*spktinfo));
	spktinfo->ipi6_addr = myaddr;
	if ((spktinfo->ipi6_ifindex = if_nametoindex(dev)) == 0) {
		/* this must not occur, so we might have to assert here */
		dprintf(LOG_WARNING,
			"relay6_react_solicit: invlalid interface: %s", dev);
		return;
	}

	/* forward the solictation to servers */
	smh.msg_name = (caddr_t)&sa6_all_servers;
	smh.msg_namelen = sizeof(sa6_all_servers);
	iov[0].iov_base = buf;
	iov[0].iov_len = siz;
	smh.msg_iov = iov;
	smh.msg_iovlen = 1;

	if (sendmsg(ssock, &smh, 0) != siz)
		dprintf(LOG_WARNING, "relay6_react_solicit: sendmsg failed "
			"(ifid = %d, src = %s): %s",
			spktinfo->ipi6_ifindex,
			in6addr2str(&spktinfo->ipi6_addr, 0), strerror(errno));
}

static void
relay6_react_advert(buf, siz, dev)
	char *buf, *dev;
	size_t siz;
{
	struct dhcp6_advert *dh6a;
	struct sockaddr_in6 sa6_relay;
	const char *sdev;

	dprintf(LOG_DEBUG, "relay6_react_advert");

	if (siz < sizeof(*dh6a)) {
		dprintf(LOG_INFO,
			"relay6_react_advert: short packet (size = %d)", siz);
		return;
	}
	dh6a = (struct dhcp6_advert *)buf;

	memset(&sa6_relay, 0, sizeof(sa6_relay));
	sa6_relay.sin6_family = AF_INET6;
	sa6_relay.sin6_len = sizeof(sa6_relay);
	sa6_relay.sin6_addr = dh6a->dh6adv_relayaddr;
	sa6_relay.sin6_scope_id = in6_addrscopebyif(&dh6a->dh6adv_relayaddr,
						    dev);

	if (!IN6_IS_ADDR_LINKLOCAL(&dh6a->dh6adv_cliaddr)) {
		dprintf(LOG_INFO,
			"relay6_react_advert: client address (%s) is not "
			"link-local", in6addr2str(&dh6a->dh6adv_cliaddr, 0));
		return;
	}

	/*
	 * Note that sdev is necessarily equal to dev, if we take the weak
	 * host model.
	 */
	if ((sdev = getdev(&sa6_relay)) == NULL) {
		dprintf(LOG_WARNING,
			"relay6_react_advert: can't detect interface from %s",
			addr2str((struct sockaddr *)&sa6_relay));
		return;
	}

	relay6_forward_response(buf, siz, &dh6a->dh6adv_cliaddr, sdev);
}

static void
relay6_forward_response(buf, siz, cliaddr, dev)
	char *buf;
	size_t siz;
	struct in6_addr *cliaddr;
	const char *dev;
{
	static struct iovec iov[2];

	dprintf(LOG_DEBUG, "relay6_forward_response");

	sa6_client.sin6_addr = *cliaddr;

	smh.msg_name = (caddr_t)&sa6_client;
	smh.msg_namelen = sizeof(sa6_client);
	iov[0].iov_base = buf;
	iov[0].iov_len = siz;
	smh.msg_iov = iov;
	smh.msg_iovlen = 1;
	memset(spktinfo, 0, sizeof(*spktinfo));

	/* set the outgoing interface */
	if ((spktinfo->ipi6_ifindex = if_nametoindex(dev)) == 0) {
		/* this must not occur, so we might have to assert here */
		dprintf(LOG_ERR,
			"relay6_forward_response: invlalid interface: %s", dev);
		return;
	}

	if (sendmsg(ssock, &smh, 0) != siz)
		dprintf(LOG_WARNING,
			"relay6_forward_response: sendmsg failed on %s :%s",
			dev, strerror(errno));
}
