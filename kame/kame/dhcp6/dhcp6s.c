/*	$KAME: dhcp6s.c,v 1.77 2002/05/17 01:37:50 jinmei Exp $	*/
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

static int debug = 0;

const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_SERVER;

char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */

static const struct sockaddr_in6 *sa6_any_downstream;
static struct msghdr rmh;
static char rdatabuf[BUFSIZ];
static int rmsgctllen;
static char *rmsgctlbuf;
static struct duid server_duid;
static struct dnsq dnslist;

#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

#define DUID_FILE "/etc/dhcp6s_duid"
#define DHCP6S_CONF "/usr/local/v6/etc/dhcp6s.conf"

static void usage __P((void));
static void server6_init __P((void));
static void server6_mainloop __P((void));
static int server6_recv __P((int));
static int server6_react_solicit __P((struct dhcp6_if *, struct dhcp6 *,
				      struct dhcp6_optinfo *,
				      struct sockaddr *, int));
static int server6_react_request __P((struct dhcp6_if *,
				      struct in6_pktinfo *, struct dhcp6 *,
				      struct dhcp6_optinfo *,
				      struct sockaddr *, int));
static int server6_react_informreq __P((struct dhcp6_if *, struct dhcp6 *,
					struct dhcp6_optinfo *,
					struct sockaddr *, int));
static int server6_send __P((int, struct dhcp6_if *, struct dhcp6 *,
			     struct dhcp6_optinfo *,
			     struct sockaddr *, int,
			     struct dhcp6_optinfo *));

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
		dprintf(LOG_ERR, "%s" "failed to parse configuration file",
			FNAME);
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
	static struct iovec iov;
	static struct sockaddr_in6 sa6_any_downstream_storage;

	ifidx = if_nametoindex(device);
	if (ifidx == 0) {
		dprintf(LOG_ERR, "%s" "invalid interface %s", FNAME, device);
		exit(1);
	}

	/* get our DUID */
	if (get_duid(DUID_FILE, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to get a DUID", FNAME);
		exit(1);
	}

	/* initialize send/receive buffer */
	iov.iov_base = (caddr_t)rdatabuf;
	iov.iov_len = sizeof(rdatabuf);
	rmh.msg_iov = &iov;
	rmh.msg_iovlen = 1;
	rmsgctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	if ((rmsgctlbuf = (char *)malloc(rmsgctllen)) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed", FNAME);
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
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		dprintf(LOG_ERR, "%s" "socket(insock): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEPORT, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s" "setsockopt(insock, SO_REUSEPORT): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEADDR, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s" "setsockopt(insock, SO_REUSEADDR): %s",
			FNAME, strerror(errno));
		exit(1);
	}
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(inbound, IPV6_RECVPKTINFO): %s",
			FNAME, strerror(errno));
		exit(1);
	}
#else
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_PKTINFO, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(inbound, IPV6_PKTINFO): %s",
			FNAME, strerror(errno));
		exit(1);
	}
#endif
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		dprintf(LOG_ERR, "%s" "bind(insock): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res2);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
	    &((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
	    sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    &mreq6, sizeof(mreq6))) {
		dprintf(LOG_ERR, "%s" "setsockopt(insock, IPV6_JOIN_GROUP)",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(DH6ADDR_ALLSERVER, DH6PORT_UPSTREAM,
			    &hints, &res2);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_interface = ifidx;
	memcpy(&mreq6.ipv6mr_multiaddr,
	    &((struct sockaddr_in6 *)res2->ai_addr)->sin6_addr,
	    sizeof(mreq6.ipv6mr_multiaddr));
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
	    &mreq6, sizeof(mreq6))) {
		dprintf(LOG_ERR,
			"%s" "setsockopt(insock, IPV6_JOIN_GROUP): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res2);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		dprintf(LOG_ERR, "%s" "socket(outsock): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	/* set outgoing interface of multicast packets for DHCP reconfig */
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	    &ifidx, sizeof(ifidx)) < 0) {
		dprintf(LOG_ERR,
			"%s" "setsockopt(outsock, IPV6_MULTICAST_IF): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	/* make the socket write-only */
	if (shutdown(outsock, 0)) {
		dprintf(LOG_ERR, "%s" "shutdown(outbound, 0): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
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

	while (1) {
		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, NULL);
		switch (ret) {
		case -1:
		case 0:
			dprintf(LOG_ERR, "%s" "select: %s",
				FNAME, strerror(errno));
			exit(1);
			/* NOTREACHED */
		default:
			break;
		}
		if (FD_ISSET(insock, &r))
			server6_recv(insock);
	}
}

static int
server6_recv(s)
	int s;
{
	ssize_t len;
	struct sockaddr_storage from;
	int fromlen;
	struct msghdr mhdr;
	struct iovec iov;
	char cmsgbuf[BUFSIZ];
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	struct dhcp6opt *opt, *eopt;
	struct dhcp6_optinfo optinfo;

	memset(&iov, 0, sizeof(iov));
	memset(&mhdr, 0, sizeof(mhdr));

	iov.iov_base = rdatabuf;
	iov.iov_len = sizeof(rdatabuf);
	mhdr.msg_name = &from;
	mhdr.msg_namelen = sizeof(from);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (caddr_t)cmsgbuf;
	mhdr.msg_controllen = sizeof(cmsgbuf);

	if ((len = recvmsg(insock, &mhdr, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "recvmsg: %s", FNAME, strerror(errno));
		return -1;
	}

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&mhdr); cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&mhdr, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
		}
	}
	if (pi == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to get packet info", FNAME);
		return -1;
	}
	if ((ifp = find_ifconfbyid((unsigned int)pi->ipi6_ifindex)) == NULL) {
		dprintf(LOG_INFO, "%s" "unexpected interface (%d)", FNAME,
			(unsigned int)pi->ipi6_ifindex);
		return;
	}

	if (len < sizeof(*dh6)) {
		dprintf(LOG_INFO, "%s" "short packet", FNAME);
		return -1;
	}
	
	dh6 = (struct dhcp6 *)rdatabuf;

	dprintf(LOG_DEBUG, "%s" "received %s from %s", FNAME,
		dhcpmsgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&from));

	/*
	 * parse and validate options in the request
	 */
	dhcp6_init_options(&optinfo);
	if (dhcp6_get_options((struct dhcp6opt *)(dh6 + 1),
			      (struct dhcp6opt *)(rdatabuf + len),
			      &optinfo) < 0) {
		dprintf(LOG_INFO, "%s" "failed to parse options", FNAME);
		return -1;
	}

	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT:
		(void)server6_react_solicit(ifp, dh6, &optinfo,
					    (struct sockaddr *)&from, fromlen);
		break;
	case DH6_REQUEST:
		(void)server6_react_request(ifp, pi, dh6, &optinfo,
					    (struct sockaddr *)&from, fromlen);
		break;
	case DH6_INFORM_REQ:
		(void)server6_react_informreq(ifp, dh6, &optinfo,
					      (struct sockaddr *)&from,
					      fromlen);
		break;
	default:
		dprintf(LOG_INFO, "%s" "unknown or unsupported msgtype %s",
			FNAME, dhcpmsgstr(dh6->dh6_msgtype));
		break;
	}

	dhcp6_clear_options(&optinfo);

	return 0;
}

static int
server6_react_solicit(ifp, dh6, optinfo, from, fromlen)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6_optinfo roptinfo;
	struct host_conf *client_conf;
	struct dhcp6_optconf *opt;
	int resptype;

	/*
	 * Servers MUST discard any Solicit messages that do not include a
	 * Client Identifier option. [dhcpv6-24 Section 15.2]
	 */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no client ID option", FNAME);
		return(-1);
	} else {
		dprintf(LOG_DEBUG, "%s" "client ID %s", FNAME,
			duidstr(&optinfo->clientID));
	}

	/* get per-host configuration for the client, if any. */
	if ((client_conf = find_hostconf(&optinfo->clientID))) {
		dprintf(LOG_DEBUG, "%s" "found a host configuration for %s",
			FNAME, client_conf->name);
	}

	/*
	 * configure necessary options based on the options in solicit.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	roptinfo.serverID = server_duid;

	/* copy client information back (if provided) */
	if (optinfo->clientID.duid_id)
		roptinfo.clientID = optinfo->clientID;

	/* preference (if configured) */
	if (ifp->server_pref != DH6OPT_PREF_UNDEF)
		roptinfo.pref = ifp->server_pref;

	/* DNS server */
	roptinfo.dnslist = dnslist;

	/*
	 * see if we have information for requested options, and if so,
	 * configure corresponding options.
	 */
	for (opt = optinfo->requests; opt; opt = opt->next) {
		switch(opt->type) {
		case DH6OPT_PREFIX_DELEGATION:
			if (client_conf &&
			    !TAILQ_EMPTY(&client_conf->prefix)) {
				roptinfo.prefix = client_conf->prefix;
			}
			break;
		}
	}

	if (optinfo->rapidcommit && (ifp->allow_flags & DHCIFF_RAPID_COMMIT)) {
		/*
		 * If the client has included a Rapid Commit option and the
		 * server has been configured to respond with committed address
		 * assignments and other resources, responds to the Solicit
		 * with a Reply message.
		 * [dhcpv6-24 Section 17.2.1]
		 */
		roptinfo.rapidcommit = 1;

		/* notyet: create and record the bindings for the client */
		;

		resptype = DH6_REPLY;
	} else
		resptype = DH6_ADVERTISE;

	return(server6_send(resptype, ifp, dh6, optinfo, from, fromlen,
			    &roptinfo));
}

static int
server6_react_request(ifp, pi, dh6, optinfo, from, fromlen)
	struct dhcp6_if *ifp;
	struct in6_pktinfo *pi;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6_optinfo roptinfo;
	struct host_conf *client_conf;
	struct dhcp6_optconf *opt;

	/* message validation according to Section 15.4 of dhcpv6-24 */

	/* the message must include a Server Identifier option */
	if (optinfo->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	}
	/* the contents of the Server Identifier option must match ours */
	if (duidcmp(&optinfo->serverID, &server_duid)) {
		dprintf(LOG_INFO, "%s" "server ID mismatch", FNAME);
		return -1;
	}
	/* the message must include a Client Identifier option */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	}

	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	roptinfo.serverID = server_duid;
	/* copy client information back */
	roptinfo.clientID = optinfo->clientID;

	/*
	 * When the server receives a Request message via unicast from a
	 * client to which the server has not sent a unicast option, the server
	 * discards the Request message and responds with a Reply message
	 * containing a status code option with value UseMulticast and no other
	 * options.
	 * [dhcpv6-24 18.2.1]
	 * (Our current implementation has never sent a unicast option.)
	 */
	if (!IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
		dprintf(LOG_INFO, "%s" "unexpected unicast message", FNAME);

		return -1;	/* XXX */
#ifdef notyet
		return(server6_send(DH6_REPLY, ifp, dh6, optinfo, from,
				    fromlen, &roptinfo));
#endif
	}

	/* get per-host configuration for the client, if any. */
	if ((client_conf = find_hostconf(&optinfo->clientID))) {
		dprintf(LOG_DEBUG, "%s" "found a host configuration named %s",
			FNAME, client_conf->name);
	}

	/*
	 * See if we have to make a binding of some configuration information
	 * for the client.
	 * (Note that our implementation does not assign addresses (nor will)).
	 */
	for (opt = optinfo->requests; opt; opt = opt->next) {
		switch(opt->type) {
		case DH6OPT_PREFIX_DELEGATION:
			if (client_conf &&
			    !TAILQ_EMPTY(&client_conf->prefix)) {
				/* create a binding for the prefix. (notyet) */
				roptinfo.prefix = client_conf->prefix;
			}
			break;
		}
	}

	/*
	 * Adds options to the Reply message for any other configuration
	 * information to be assigned to the client.
	 */
	/* DNS server */
	roptinfo.dnslist = dnslist;

	/* send a reply message. */
	return(server6_send(DH6_REPLY, ifp, dh6, optinfo, from, fromlen,
			    &roptinfo));
}

static int
server6_react_informreq(ifp, dh6, optinfo, from, fromlen)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6_optinfo roptinfo;

	/* if a server information is included, it must match ours. */
	if (optinfo->serverID.duid_len &&
	    duidcmp(&optinfo->serverID, &server_duid)) {
		dprintf(LOG_INFO, "%s" "server DUID mismatch", FNAME);
		return(-1);
	}

	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	roptinfo.serverID = server_duid;

	/* copy client information back (if provided) */
	if (optinfo->clientID.duid_id)
		roptinfo.clientID = optinfo->clientID;

	/* DNS server */
	roptinfo.dnslist = dnslist;

	return(server6_send(DH6_REPLY, ifp, dh6, optinfo, from, fromlen,
			    &roptinfo));
}

static int
server6_send(type, ifp, origmsg, optinfo, from, fromlen, roptinfo)
	int type;
	struct dhcp6_if *ifp;
	struct dhcp6 *origmsg;
	struct dhcp6_optinfo *optinfo, *roptinfo;
	struct sockaddr *from;
	int fromlen;
{
	char replybuf[BUFSIZ];
	struct sockaddr_in6 dst;
	int len, optlen;
	struct dhcp6 *dh6;

	if (sizeof(struct dhcp6) > sizeof(replybuf)) {
		dprintf(LOG_ERR, "%s" "buffer size assumption failed", FNAME);
		return(-1);
	}

	dh6 = (struct dhcp6 *)replybuf;
	len = sizeof(*dh6);
	memset(dh6, 0, sizeof(*dh6));
	dh6->dh6_msgtypexid = origmsg->dh6_msgtypexid;
	dh6->dh6_msgtype = (u_int8_t)type;

	/* set options in the reply message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(replybuf +
							    sizeof(replybuf)),
					roptinfo)) < 0) {
		dprintf(LOG_INFO, "%s" "failed to construct reply options",
			FNAME);
		return(-1);
	}
	len += optlen;

	/* specify the destination and send the reply */
	dst = *sa6_any_downstream;
	dst.sin6_addr = ((struct sockaddr_in6 *)from)->sin6_addr;
	dst.sin6_scope_id = ((struct sockaddr_in6 *)from)->sin6_scope_id;
	if (transmit_sa(outsock, (struct sockaddr *)&dst,
			replybuf, len) != 0) {
		dprintf(LOG_ERR, "%s" "transmit %s to %s failed", FNAME,
			dhcpmsgstr(type), addr2str((struct sockaddr *)&dst));
		return(-1);
	}

	dprintf(LOG_DEBUG, "%s" "transmit %s to %s", FNAME,
		dhcpmsgstr(type), addr2str((struct sockaddr *)&dst));

	return 0;
}
