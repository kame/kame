/*	$KAME: dhcp6s.c,v 1.65 2002/05/01 10:43:09 jinmei Exp $	*/
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
#include <config.h>

struct dnslist {
	TAILQ_ENTRY(dnslist) link;
	struct in6_addr addr;
};
TAILQ_HEAD(, dnslist) dnslist;

static int debug = 0;

char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */

static const struct sockaddr_in6 *sa6_any_downstream;
static struct msghdr rmh;
static char rdatabuf[BUFSIZ];
static int rmsgctllen;
static char *rmsgctlbuf;
static struct duid server_duid;

#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

#define DUID_FILE "/etc/dhcp6s_duid"
#define DHCP6S_CONF "/usr/local/v6/etc/dhcp6s.conf"

static void usage __P((void));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static ssize_t server6_recv __P((int, struct sockaddr *, int *));
static void server6_react __P((struct dhcp_if *, size_t,
			       struct sockaddr *, int));
static int server6_react_informreq __P((struct dhcp_if *, char *, size_t,
					struct dhcp6_optinfo *,
					struct sockaddr *, int));
static int server6_react_solicit __P((struct dhcp_if *, char *, size_t,
				      struct dhcp6_optinfo *,
				      struct sockaddr *, int));
static int server6_send_reply __P((struct dhcp_if *, struct dhcp6 *,
				   struct dhcp6_optinfo *,
				   struct sockaddr *, int));

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

	ifinit(device);

	if ((cfparse(DHCP6S_CONF)) != 0) {
		dprintf(LOG_ERR, "failed to parse configuration file");
		exit(1);
	}

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
	static struct sockaddr_in6 sa6_any_downstream_storage;

	ifidx = if_nametoindex(device);
	if (ifidx == 0) {
		dprintf(LOG_ERR, "invalid interface %s", device);
		exit(1);
	}

	/* get our DUID */
	if (get_duid(DUID_FILE, &server_duid)) {
		dprintf(LOG_ERR, "failed to get a DUID");
		exit(1);
	}

	/* initialize send/receive buffer */
	iov[0].iov_base = (caddr_t)rdatabuf;
	iov[0].iov_len = sizeof(rdatabuf);
	rmh.msg_iov = iov;
	rmh.msg_iovlen = 1;
	rmsgctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	if ((rmsgctlbuf = (char *)malloc(rmsgctllen)) == NULL) {
		dprintf(LOG_ERR, "memory allocation failed");
		exit(1);
	}

	/* initialize socket */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		dprintf(LOG_ERR, "socket(insock): %s", strerror(errno));
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEPORT,
		       &on, sizeof(on)) < 0) {
		dprintf(LOG_ERR, "setsockopt(insock, SO_REUSEPORT): %s",
			strerror(errno));
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEADDR,
		       &on, sizeof(on)) < 0) {
		dprintf(LOG_ERR, "setsockopt(insock, SO_REUSEADDR): %s",
			strerror(errno));
		exit(1);
	}
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		dprintf(LOG_ERR, "bind(insock): %s", strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
	    &((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
	    sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    &mreq6, sizeof(mreq6))) {
		dprintf(LOG_ERR, "setsockopt(insock, IPV6_JOIN_GROUP)",
			strerror(errno));
		exit(1);
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLSERVER, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
	    &((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
	    sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    &mreq6, sizeof(mreq6))) {
		dprintf(LOG_ERR, "setsockopt(insock, IPV6_JOIN_GROUP): %s",
			strerror(errno));
		exit(1);
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		dprintf(LOG_ERR, "socket(outsock): %s", strerror(errno));
		exit(1);
	}
	/* set outgoing interface of multicast packets for DHCP reconfig */
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	    &ifidx, sizeof(ifidx)) < 0) {
		dprintf(LOG_ERR, "setsockopt(outsock, IPV6_MULTICAST_IF): %s",
			strerror(errno));
		exit(1);
	}
	/* make the socket write-only */
	if (shutdown(outsock, 0)) {
		dprintf(LOG_ERR, "shutdown(outbound, 0): %s", strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	memcpy(&sa6_any_downstream_storage, res->ai_addr, res->ai_addrlen);
	sa6_any_downstream =
		(const struct sockaddr_in6*)&sa6_any_downstream_storage;
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
	struct dhcp_if *ifp;	/* XXX: multiple-interface support */

	if ((ifp = find_ifconf(device)) == NULL) {
		dprintf(LOG_ERR, "interface %s not configured", device);
		exit(1);
	}

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
				server6_react(ifp, l, (struct sockaddr *)&from,
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
server6_react(ifp, siz, from, fromlen)
	struct dhcp_if *ifp;
	size_t siz;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6 *dh6;
	struct dhcp6opt *opt, *eopt;
	struct dhcp6_optinfo optinfo;

	if (siz < sizeof(*dh6)) {
		dprintf(LOG_INFO, "server6_react: short packet");
		return;
	}

	dh6 = (struct dhcp6 *)rdatabuf;

	dprintf(LOG_DEBUG, "server6_react: react to %s",
		dhcpmsgstr(dh6->dh6_msgtype));

	/*
	 * parse and validate options in the request
	 */
	dhcp6_init_options(&optinfo);
	opt = (struct dhcp6opt *)(dh6 + 1);
	eopt = (struct dhcp6opt *)(rdatabuf + siz);
	if (dhcp6_get_options(opt, eopt, &optinfo) < 0) {
		dprintf(LOG_INFO,
			"server6_react: failed to parse options");
		return;
	}

	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT:
		(void)server6_react_solicit(ifp, rdatabuf, siz, &optinfo,
					    from, fromlen);
		break;
	case DH6_INFORM_REQ:
		(void)server6_react_informreq(ifp, rdatabuf, siz, &optinfo,
					      from, fromlen);
		break;
	default:
		dprintf(LOG_INFO, "unknown or unsupported msgtype %s",
			dhcpmsgstr(dh6->dh6_msgtype));
		break;
	}
}

static int
server6_react_solicit(ifp, buf, siz, optinfo, from, fromlen)
	struct dhcp_if *ifp;
	char *buf;
	size_t siz;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	/*
	 * Servers MUST discard any Solicit messages that do not include a
	 * Client Identifier option. [dhcpv6-24 Section 15.2]
	 */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO,
			"server6_react_solicit: no client ID option");
		return(-1);
	}

	/*
	 * If the client has included a Rapid Commit option and the server
	 * has been configured to respond with committed address assignments
	 * and other resources, responds to the Solicit with a Reply message.
	 * [dhcpv6-24 Section 17.2.1]
	 */
	if (optinfo->rapidcommit && (ifp->allow_flags & DHCIFF_RAPID_COMMIT)) {
		/* notyet: create and record the bindings for the client */
		return(server6_send_reply(ifp, (struct dhcp6 *)buf, optinfo,
					  from, fromlen));
	} else {
		/* we don't support this case */
		dprintf(LOG_INFO, "server6_react_solicit: failed to react: "
			"rapid commit disabled or not requested");
		return(-1);
	}

	return(0);
}

static int
server6_react_informreq(ifp, buf, siz, optinfo, from, fromlen)
	struct dhcp_if *ifp;
	char *buf;
	size_t siz;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	/* if a server information is included, it must match ours. */
	if (optinfo->serverID.duid_len &&
	    (optinfo->serverID.duid_len != server_duid.duid_len ||
	     memcmp(optinfo->serverID.duid_id, server_duid.duid_id,
		    server_duid.duid_len))) {
		dprintf(LOG_INFO,
			"server6_react_informreq: server DUID mismatch");
		return(-1);
	}

	return(server6_send_reply(ifp, (struct dhcp6 *)buf, optinfo,
				  from, fromlen));
}

static int
server6_send_reply(ifp, origmsg, optinfo, from, fromlen)
	struct dhcp_if *ifp;
	struct dhcp6 *origmsg;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	char replybuf[BUFSIZ];
	char *dnsbuf = NULL, *p;
	struct sockaddr_in6 dst;
	int len, ns, optlen;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo roptinfo;
	struct dnslist *d;

	if (sizeof(struct dhcp6) > sizeof(replybuf)) {
		dprintf(LOG_ERR, "buffer size assumption failed");
		exit(1);
		/* NOTREACHED */
	}

	dh6 = (struct dhcp6 *)replybuf;
	len = sizeof(*dh6);
	memset(dh6, 0, sizeof(*dh6));
	dh6->dh6_msgtypexid = origmsg->dh6_msgtypexid;
	dh6->dh6_msgtype = DH6_REPLY;

	/*
	 * attach necessary options
	 */
	dhcp6_init_options(&roptinfo);

	/*
	 * if we're reacting to a solicit with a rapid commit option,
	 * add the option in the reply as well.
	 */
	if (origmsg->dh6_msgtype == DH6_SOLICIT)
		roptinfo.rapidcommit = 1;

	/* server information option */
	roptinfo.serverID = server_duid;

	/* copy client information back (if provided) */
	if (optinfo->clientID.duid_id)
		roptinfo.clientID = optinfo->clientID;

	/* DNS server */
	for (ns = 0, d = TAILQ_FIRST(&dnslist); d; d = TAILQ_NEXT(d, link))
		ns++;
	if (ns) {
		roptinfo.dns.n = ns;
		if ((dnsbuf = malloc(sizeof(struct in6_addr) * ns)) == NULL) {
			dprintf(LOG_WARNING, "server6_react_informreq: "
				"malloc failed for DNS list");
			goto end;
		}
		for (p = dnsbuf, d = TAILQ_FIRST(&dnslist); d;
		     d = TAILQ_NEXT(d, link)) {
			memcpy(p, &d->addr, sizeof(struct in6_addr));
			p += sizeof(struct in6_addr);
		}
		roptinfo.dns.list = dnsbuf;
	}

	/* set options in the reply message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(replybuf +
							    sizeof(replybuf)),
					&roptinfo)) < 0) {
		dprintf(LOG_INFO, "server6_react_informreq: "
			"failed to construct reply options");
		goto end;
	}
	len += optlen;

	dst = *sa6_any_downstream;
	dst.sin6_addr = ((struct sockaddr_in6 *)from)->sin6_addr;
	dst.sin6_scope_id = ((struct sockaddr_in6 *)from)->sin6_scope_id;

	if (transmit_sa(outsock, (struct sockaddr *)&dst,
			0, replybuf, len) != 0) {
		dprintf(LOG_ERR, "transmit to %s failed",
			addr2str((struct sockaddr *)&dst));
		/* NOTREACHED */
	}

  end:
	if (dnsbuf)
		free(dnsbuf);

	return 0;
}
