/*	$KAME: dhcp6s.c,v 1.95 2003/01/06 06:34:41 jinmei Exp $	*/
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
#include <limits.h>

#include <dhcp6.h>
#include <config.h>
#include <common.h>
#include <timer.h>

typedef enum { DHCP6_BINDING_IA } dhcp6_bindingtype_t;

struct dhcp6_binding {
	TAILQ_ENTRY(dhcp6_binding) link;

	dhcp6_bindingtype_t type;

	/* identifier of the binding */
	struct duid clientid;
	/* additional identifiers for IA-based bindings */
	int iatype;
	u_int32_t iaid;

	/*
	 * configuration information of this binding,
	 * which is type-dependent.
	 */
	union {
		struct dhcp6_list uv_list;
	} val;
#define val_list val.uv_list

	u_int32_t duration;
	time_t updatetime;
	struct dhcp6_timer *timer;
};
static TAILQ_HEAD(, dhcp6_binding) dhcp6_binding_head;

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
static struct dhcp6_list arg_dnslist;

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
static int server6_react_renew __P((struct dhcp6_if *,
				     struct in6_pktinfo *, struct dhcp6 *,
				     struct dhcp6_optinfo *,
				     struct sockaddr *, int));
static int server6_react_rebind __P((struct dhcp6_if *,
				     struct dhcp6 *, struct dhcp6_optinfo *,
				     struct sockaddr *, int));
static int server6_react_informreq __P((struct dhcp6_if *, struct dhcp6 *,
					struct dhcp6_optinfo *,
					struct sockaddr *, int));
static int server6_send __P((int, struct dhcp6_if *, struct dhcp6 *,
			     struct dhcp6_optinfo *,
			     struct sockaddr *, int,
			     struct dhcp6_optinfo *));
static int make_ia_stcode __P((int, u_int32_t, u_int16_t,
    struct dhcp6_list *));
static int make_binding_ia __P((struct dhcp6_listval *, struct dhcp6_list *,
    struct dhcp6_optinfo *));
static int make_ia __P((struct dhcp6_listval *, struct dhcp6_list *,
    struct dhcp6_list *, struct host_conf *, int));
static int make_match_ia __P((struct dhcp6_listval *, struct dhcp6_list *,
    struct dhcp6_list *));
static void calc_ia_timo __P((struct dhcp6_ia *, struct dhcp6_list *,
    struct host_conf *));
static void update_binding_duration __P((struct dhcp6_binding *));
static struct dhcp6_binding *add_binding __P((struct duid *,
    dhcp6_bindingtype_t, int, u_int32_t, void *));
static struct dhcp6_binding *find_binding __P((struct duid *,
    dhcp6_bindingtype_t, int, u_int32_t));
static void update_binding __P((struct dhcp6_binding *));
static void remove_binding __P((struct dhcp6_binding *));
static void free_binding __P((struct dhcp6_binding *));
static struct dhcp6_timer *binding_timo __P((void *));
static char *bindingstr __P((struct dhcp6_binding *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	struct in6_addr a;
	struct dhcp6_listval *dlv;
	char *progname, *conffile = DHCP6S_CONF;

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	TAILQ_INIT(&arg_dnslist);

	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "c:dDfn:")) != -1) {
		switch (ch) {
		case 'c':
			conffile = optarg;
			break;
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
			warnx("-n dnsserv option was obsoleted.  "
			    "use configuration file.");
			if (inet_pton(AF_INET6, optarg, &a) != 1) {
				errx(1, "invalid DNS server %s", optarg);
				/* NOTREACHED */
			}
			if ((dlv = malloc(sizeof *dlv)) == NULL) {
				errx(1, "malloc failed for a DNS server");
				/* NOTREACHED */
			}
			dlv->val_addr6 = a;
			TAILQ_INSERT_TAIL(&arg_dnslist, dlv, link);
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

	if ((cfparse(conffile)) != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse configuration file",
			FNAME);
		exit(1);
	}
	/* prohibit a mixture of old and new style of DNS server config */
	if (!TAILQ_EMPTY(&arg_dnslist)) {
		if (!TAILQ_EMPTY(&dnslist)) {
			dprintf(LOG_INFO, "%s" "do not specify DNS servers "
			    "both by command line and by configuration file.",
			    FNAME);
			exit(1);
		}
		dnslist = arg_dnslist;
		TAILQ_INIT(&arg_dnslist);
	}

	server6_init();

	server6_mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr,
		"usage: dhcp6s [-c configfile] [-dDf] intface\n");
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

	TAILQ_INIT(&dhcp6_binding_head);

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
	if (setsockopt(insock, IPPROTO_IPV6, IPV6_V6ONLY,
	    &on, sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
		    "setsockopt(inbound, IPV6_V6ONLY): %s",
		    FNAME, strerror(errno));
		exit(1);
	}
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
	struct timeval *w;
	int ret;
	fd_set r;

	while (1) {
		w = dhcp6_check_timer();

		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, w);
		switch (ret) {
		case -1:
			dprintf(LOG_ERR, "%s" "select: %s",
				FNAME, strerror(errno));
			exit(1);
			/* NOTREACHED */
		case 0:		/* timeout */
			break;
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
		return (-1);
	}
	fromlen = mhdr.msg_namelen;

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
		return (-1);
	}
	if ((ifp = find_ifconfbyid((unsigned int)pi->ipi6_ifindex)) == NULL) {
		dprintf(LOG_INFO, "%s" "unexpected interface (%d)", FNAME,
		    (unsigned int)pi->ipi6_ifindex);
		return (-1);
	}

	if (len < sizeof(*dh6)) {
		dprintf(LOG_INFO, "%s" "short packet", FNAME);
		return (-1);
	}
	
	dh6 = (struct dhcp6 *)rdatabuf;

	dprintf(LOG_DEBUG, "%s" "received %s from %s", FNAME,
	    dhcp6msgstr(dh6->dh6_msgtype),
	    addr2str((struct sockaddr *)&from));

	/*
	 * A server MUST discard any Solicit, Confirm, Rebind or
	 * Information-request messages it receives with a unicast
	 * destination address.
	 * [dhcpv6-28 Section 15.]
	 */
	if (!IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr) &&
	    (dh6->dh6_msgtype == DH6_SOLICIT ||
	    dh6->dh6_msgtype == DH6_CONFIRM ||
	    dh6->dh6_msgtype == DH6_REBIND ||
	    dh6->dh6_msgtype == DH6_INFORM_REQ)) {
		dprintf(LOG_INFO, "%s" "invalid unicast message", FNAME);
		return (-1);
	}

	/*
	 * parse and validate options in the request
	 */
	dhcp6_init_options(&optinfo);
	if (dhcp6_get_options((struct dhcp6opt *)(dh6 + 1),
	    (struct dhcp6opt *)(rdatabuf + len), &optinfo) < 0) {
		dprintf(LOG_INFO, "%s" "failed to parse options", FNAME);
		return (-1);
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
	case DH6_RENEW:
		(void)server6_react_renew(ifp, pi, dh6, &optinfo,
		    (struct sockaddr *)&from, fromlen);
		break;
	case DH6_REBIND:
		(void)server6_react_rebind(ifp, dh6, &optinfo,
		    (struct sockaddr *)&from, fromlen);
		break;
	case DH6_INFORM_REQ:
		(void)server6_react_informreq(ifp, dh6, &optinfo,
		    (struct sockaddr *)&from, fromlen);
		break;
	default:
		dprintf(LOG_INFO, "%s" "unknown or unsupported msgtype %s",
		    FNAME, dhcp6msgstr(dh6->dh6_msgtype));
		break;
	}

	dhcp6_clear_options(&optinfo);

	return (0);
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
	struct dhcp6_listval *opt;
	int resptype, do_binding = 0, error;

	/*
	 * Servers MUST discard any Solicit messages that do not include a
	 * Client Identifier option. [dhcpv6-28 Section 15.2]
	 */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no client ID option", FNAME);
		return (-1);
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
	if (duidcpy(&roptinfo.serverID, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto fail;
	}

	/* copy client information back (if provided) */
	if (optinfo->clientID.duid_id &&
	    duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto fail;
	}

	/* preference (if configured) */
	if (ifp->server_pref != DH6OPT_PREF_UNDEF)
		roptinfo.pref = ifp->server_pref;

	/* DNS server */
	if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
		dprintf(LOG_ERR, "%s" "failed to copy DNS servers", FNAME);
		goto fail;
	}

	/*
	 * see if we have information for requested options, and if so,
	 * configure corresponding options.
	 */
	if (optinfo->rapidcommit && (ifp->allow_flags & DHCIFF_RAPID_COMMIT))
		do_binding = 1;

	/*
	 * The delegating router MUST include an IA_PD option, identifying any
	 * prefix(es) that the delegating router will delegate to the
	 * requesting router.
	 * [dhcpv6-opt-prefix-delegation-01 Section 10.2]
	 */
	if (!TAILQ_EMPTY(&optinfo->iapd_list)) {
		int found = 0;
		struct dhcp6_list conflist;
		struct dhcp6_listval *iapd;

		TAILQ_INIT(&conflist);

		/* make a local copy of the configured prefixes */
		if (client_conf &&
		    dhcp6_copy_list(&conflist, &client_conf->prefix_list)) {
			dprintf(LOG_NOTICE, "%s" "failed to make local data",
			    FNAME);
			goto fail;
		}

		for (iapd = TAILQ_FIRST(&optinfo->iapd_list); iapd;
		    iapd = TAILQ_NEXT(iapd, link)) {
			/*
			 * find an appropriate prefix for each IA_PD,
			 * removing the adopted prefixes from the list.
			 */
			if (make_ia(iapd, &conflist, &roptinfo.iapd_list,
			    client_conf, do_binding) > 0)
				found = 1;
		}

		dhcp6_clear_list(&conflist);

		if (!found) {
			/*
			 * If the delegating router will not assign any
			 * prefixes to any IA_PDs in a subsequent Request from
			 * the requesting router, the delegating router MUST
			 * send an Advertise message to the requesting router
			 * that includes a Status Code option with code
			 * NoPrefixAvail.
			 * [dhcpv6-opt-prefix-delegation-01 Section 10.2]
			 */
			u_int16_t stcode = DH6OPT_STCODE_NOPREFIXAVAIL;

			if (dhcp6_add_listval(&roptinfo.stcode_list,
			    DHCP6_LISTVAL_STCODE, &stcode, NULL) == NULL)
				goto fail;
		}
	}

	if (optinfo->rapidcommit && (ifp->allow_flags & DHCIFF_RAPID_COMMIT)) {
		/*
		 * If the client has included a Rapid Commit option and the
		 * server has been configured to respond with committed address
		 * assignments and other resources, responds to the Solicit
		 * with a Reply message.
		 * [dhcpv6-28 Section 17.2.1]
		 */
		roptinfo.rapidcommit = 1;
		resptype = DH6_REPLY;
	} else
		resptype = DH6_ADVERTISE;

	error = server6_send(resptype, ifp, dh6, optinfo, from, fromlen,
			     &roptinfo);
	dhcp6_clear_options(&roptinfo);
	return (error);

  fail:
	dhcp6_clear_options(&roptinfo);
	return (-1);
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

	/* message validation according to Section 15.4 of dhcpv6-28 */

	/* the message must include a Server Identifier option */
	if (optinfo->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return (-1);
	}
	/* the contents of the Server Identifier option must match ours */
	if (duidcmp(&optinfo->serverID, &server_duid)) {
		dprintf(LOG_INFO, "%s" "server ID mismatch", FNAME);
		return (-1);
	}
	/* the message must include a Client Identifier option */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return (-1);
	}

	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	if (duidcpy(&roptinfo.serverID, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto fail;
	}
	/* copy client information back */
	if (duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto fail;
	}

	/*
	 * When the server receives a Request message via unicast from a
	 * client to which the server has not sent a unicast option, the server
	 * discards the Request message and responds with a Reply message
	 * containing a Status Code option with value UseMulticast, a Server
	 * Identifier option containing the server's DUID, the Client
	 * Identifier option from the client message and no other options.
	 * [dhcpv6-28 18.2.1]
	 * (Our current implementation never sends a unicast option.)
	 */
	if (!IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
		u_int16_t stcode = DH6OPT_STCODE_USEMULTICAST;

		dprintf(LOG_INFO, "%s" "unexpected unicast message from %s",
		    FNAME, addr2str(from));
		if (dhcp6_add_listval(&roptinfo.stcode_list,
		    DHCP6_LISTVAL_STCODE, &stcode, NULL) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a status code",
			    FNAME);
			goto fail;
		}
		server6_send(DH6_REPLY, ifp, dh6, optinfo, from,
		    fromlen, &roptinfo);
		goto end;
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
	
	/*
	 * When a delegating router receives a Request message from a
	 * requesting router that contains an IA_PD option, and the delegating
	 * router is authorized to delegate prefix(es) to the requesting
	 * router, the delegating router selects the prefix(es) to be delegated
	 * to the requesting router.
	 * [dhcpv6-opt-prefix-delegation-01 Section 11.2]
	 */
	if (!TAILQ_EMPTY(&optinfo->iapd_list)) {
		struct dhcp6_list conflist;
		struct dhcp6_listval *iapd;

		TAILQ_INIT(&conflist);

		/* make a local copy of the configured prefixes */
		if (client_conf &&
		    dhcp6_copy_list(&conflist, &client_conf->prefix_list)) {
			dprintf(LOG_NOTICE, "%s" "failed to make local data",
			    FNAME);
			goto fail;
		}

		for (iapd = TAILQ_FIRST(&optinfo->iapd_list); iapd;
		    iapd = TAILQ_NEXT(iapd, link)) {
			/*
			 * Find an appropriate prefix for each IA_PD,
			 * removing the adopted prefixes from the list.
			 * The prefixes will be bound to the client.
			 */
			if (make_ia(iapd, &conflist, &roptinfo.iapd_list,
			    client_conf, 1) == 0) {
				/*
				 * We could not find any prefixes for the IA.
				 * dhcpv6-28 specifies to include NoAddrAvail
				 * for the IA in the address configuration
				 * case (Section 18.2.1).  We follow the same
				 * logic for prefix delegation as well.
				 */
				struct dhcp6_list *stcode_list;

				if (make_ia_stcode(DHCP6_LISTVAL_IAPD,
				    iapd->val_ia.iaid,
				    DH6OPT_STCODE_NOPREFIXAVAIL,
				    &roptinfo.iapd_list)) {
					dprintf(LOG_NOTICE, "%s"
					    "failed to make an option list"
					    FNAME);
					dhcp6_clear_list(&conflist);
					goto fail;
				}
			}
		}

		dhcp6_clear_list(&conflist);
	}

	/*
	 * If the Request message contained an Option Request option, the
	 * server MUST include options in the Reply message for any options in
	 * the Option Request option the server is configured to return to the
	 * client.
	 * [dhcpv6-26 18.2.1]
	 * Note: our current implementation always includes all information
	 * that we can provide.  So we do not have to check the option request
	 * options.
	 */
#if 0
	for (opt = TAILQ_FIRST(&optinfo->reqopt_list); opt;
	     opt = TAILQ_NEXT(opt, link)) {
		;
	}
#endif

	/*
	 * Add options to the Reply message for any other configuration
	 * information to be assigned to the client.
	 */
	/* DNS server */
	if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
		dprintf(LOG_ERR, "%s" "failed to copy DNS servers", FNAME);
		goto fail;
	}

	/* send a reply message. */
	(void)server6_send(DH6_REPLY, ifp, dh6, optinfo, from, fromlen,
			   &roptinfo);

  end:
	dhcp6_clear_options(&roptinfo);
	return (0);

  fail:
	dhcp6_clear_options(&roptinfo);
	return (-1);
}

static int
server6_react_renew(ifp, pi, dh6, optinfo, from, fromlen)
	struct dhcp6_if *ifp;
	struct in6_pktinfo *pi;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6_optinfo roptinfo;
	struct dhcp6_listval *iapd;

	/* message validation according to Section 15.6 of dhcpv6-28 */

	/* the message must include a Server Identifier option */
	if (optinfo->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return (-1);
	}
	/* the contents of the Server Identifier option must match ours */
	if (duidcmp(&optinfo->serverID, &server_duid)) {
		dprintf(LOG_INFO, "%s" "server ID mismatch", FNAME);
		return (-1);
	}
	/* the message must include a Client Identifier option */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return (-1);
	}

	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	if (duidcpy(&roptinfo.serverID, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto fail;
	}
	/* copy client information back */
	if (duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto fail;
	}

	/*
	 * When the server receives a Renew message via unicast from a
	 * client to which the server has not sent a unicast option, the server
	 * discards the Request message and responds with a Reply message
	 * containing a status code option with value UseMulticast, a Server
	 * Identifier option containing the server's DUID, the Client
	 * Identifier option from the client message and no other options.
	 * [dhcpv6-28 18.2.3]
	 * (Our current implementation never sends a unicast option.)
	 */
	if (!IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr)) {
		u_int16_t stcode = DH6OPT_STCODE_USEMULTICAST;

		dprintf(LOG_INFO, "%s" "unexpected unicast message from %s",
		    FNAME, addr2str(from));
		if (dhcp6_add_listval(&roptinfo.stcode_list,
		    DHCP6_LISTVAL_STCODE, &stcode, NULL) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a status code",
			    FNAME);
			goto fail;
		}
		server6_send(DH6_REPLY, ifp, dh6, optinfo, from,
		    fromlen, &roptinfo);
		goto end;
	}

	/*
	 * Locates the client's binding and verifies that the information
	 * from the client matches the information stored for that client.
	 * (Note that our implementation does not assign addresses (nor will)).
	 */
	for (iapd = TAILQ_FIRST(&optinfo->iapd_list); iapd;
	    iapd = TAILQ_NEXT(iapd, link)) {
		if (make_binding_ia(iapd, &roptinfo.iapd_list, optinfo))
			goto fail;
	}

	/* add other configuration information */
	/* DNS server */
	if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
		dprintf(LOG_ERR, "%s" "failed to copy DNS list");
		goto fail;
	}

	(void)server6_send(DH6_REPLY, ifp, dh6, optinfo, from, fromlen,
			   &roptinfo);

  end:
	dhcp6_clear_options(&roptinfo);
	return (0);

  fail:
	dhcp6_clear_options(&roptinfo);
	return (-1);
}

static int
server6_react_rebind(ifp, dh6, optinfo, from, fromlen)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	struct dhcp6_optinfo *optinfo;
	struct sockaddr *from;
	int fromlen;
{
	struct dhcp6_optinfo roptinfo;
	struct dhcp6_binding *binding;
	struct dhcp6_listval *iapd;

	/* message validation according to Section 15.7 of dhcpv6-28 */

	/* the message must include a Client Identifier option */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return (-1);
	}

	/* the message must not include a server Identifier option */
	if (optinfo->serverID.duid_len) {
		dprintf(LOG_INFO, "%s" "server ID option is included in "
		    "a rebind message", FNAME);
		return (-1);
	}

	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	if (duidcpy(&roptinfo.serverID, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto fail;
	}
	/* copy client information back */
	if (duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto fail;
	}

	/*
	 * Locates the client's binding and verifies that the information
	 * from the client matches the information stored for that client.
	 */
	for (iapd = TAILQ_FIRST(&optinfo->iapd_list); iapd;
	    iapd = TAILQ_NEXT(iapd, link)) {
		if (make_binding_ia(iapd, &roptinfo.iapd_list, optinfo))
			goto fail;
	}

	/* add other configuration information */
	/* DNS server */
	if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
		dprintf(LOG_ERR, "%s" "failed to copy DNS list");
		goto fail;
	}

	(void)server6_send(DH6_REPLY, ifp, dh6, optinfo, from, fromlen,
			   &roptinfo);

	dhcp6_clear_options(&roptinfo);
	return (0);

  fail:
	dhcp6_clear_options(&roptinfo);
	return (-1);
}

static int
make_binding_ia(iapd, retlist, optinfo)
	struct dhcp6_listval *iapd;
	struct dhcp6_list *retlist;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_binding *binding;
	struct host_conf *client_conf;

	/* get per-host configuration for the client, if any. */
	if ((client_conf = find_hostconf(&optinfo->clientID))) {
		dprintf(LOG_DEBUG, "%s" "found a host configuration named %s",
			FNAME, client_conf->name);
	}

	if ((binding = find_binding(&optinfo->clientID, DHCP6_BINDING_IA,
	    iapd->type, iapd->val_ia.iaid)) == NULL) {
		/*
		 * If the delegating router cannot find a binding for
		 * the requesting router's IA_PD the delegating router
		 * returns the IA_PD containing no prefixes with a
		 * Status Code option set to NoBinding in the Reply
		 * message.
		 * [dhcpv6-opt-prefix-delegation-01 Section 11.2]
		 * See also: [dhcpv6-28 Section 18.2.3]
		 */
		struct dhcp6_list *stcode_list;

		if (make_ia_stcode(iapd->type, iapd->val_ia.iaid,
		    DH6OPT_STCODE_NOBINDING, retlist)) {
			dprintf(LOG_NOTICE, "%s"
			    "failed to make an option list" FNAME);
			return (-1);
		}
	} else {	/* we found a binding */
		struct dhcp6_list ialist;
		struct dhcp6_listval *lv;
		struct dhcp6_prefix prefix;
		struct dhcp6_ia ia;

		TAILQ_INIT(&ialist);
		update_binding(binding);

		/* see if each information to be renewed is still valid. */
		for (lv = TAILQ_FIRST(&iapd->sublist); lv;
		    lv = TAILQ_NEXT(lv, link)) {
			switch (iapd->type) {
			case DHCP6_LISTVAL_IAPD:
				if (lv->type != DHCP6_LISTVAL_PREFIX6)
					continue;

				prefix = lv->val_prefix6;
				if (!dhcp6_find_listval(&binding->val_list,
				    DHCP6_LISTVAL_PREFIX6, &prefix, 0)) {
					dprintf(LOG_DEBUG, "%s"
					    "%s/%d is not found in %s", FNAME,
					    in6addr2str(&prefix.addr, 0),
					    prefix.plen, bindingstr(binding));
					prefix.pltime = 0;
					prefix.vltime = 0;
				}

				if (dhcp6_add_listval(&ialist,
				    DHCP6_LISTVAL_PREFIX6, &prefix, NULL)
				    == NULL) {
					dprintf(LOG_NOTICE, "%s" "failed  to "
					    "copy binding info", FNAME);
					dhcp6_clear_list(&ialist);
					return (-1);
				}
			}
		}

		memset(&ia, 0, sizeof(ia));
		ia.iaid = binding->iaid;
		/* determine appropriate T1 and T2 */
		calc_ia_timo(&ia, &ialist, client_conf);

		if (dhcp6_add_listval(retlist, iapd->type,
		    &ia, &ialist) == NULL) {
			dhcp6_clear_list(&ialist);
			return (-1);
		}
		dhcp6_clear_list(&ialist);
	}

	return (0);
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
	int error;

	/* if a server information is included, it must match ours. */
	if (optinfo->serverID.duid_len &&
	    duidcmp(&optinfo->serverID, &server_duid)) {
		dprintf(LOG_INFO, "%s" "server DUID mismatch", FNAME);
		return (-1);
	}

	/*
	 * configure necessary options based on the options in request.
	 */
	dhcp6_init_options(&roptinfo);

	/* server information option */
	if (duidcpy(&roptinfo.serverID, &server_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto fail;
	}

	/* copy client information back (if provided) */
	if (optinfo->clientID.duid_id &&
	    duidcpy(&roptinfo.clientID, &optinfo->clientID)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto fail;
	}

	/* DNS server */
	if (dhcp6_copy_list(&roptinfo.dns_list, &dnslist)) {
		dprintf(LOG_ERR, "%s" "failed to copy DNS servers", FNAME);
		goto fail;
	}

	error = server6_send(DH6_REPLY, ifp, dh6, optinfo, from, fromlen,
	    &roptinfo);

	dhcp6_clear_options(&roptinfo);
	return (error);

  fail:
	dhcp6_clear_options(&roptinfo);
	return (-1);
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
		return (-1);
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
		return (-1);
	}
	len += optlen;

	/* specify the destination and send the reply */
	dst = *sa6_any_downstream;
	dst.sin6_addr = ((struct sockaddr_in6 *)from)->sin6_addr;
	dst.sin6_scope_id = ((struct sockaddr_in6 *)from)->sin6_scope_id;
	if (transmit_sa(outsock, (struct sockaddr *)&dst,
			replybuf, len) != 0) {
		dprintf(LOG_ERR, "%s" "transmit %s to %s failed", FNAME,
			dhcp6msgstr(type), addr2str((struct sockaddr *)&dst));
		return (-1);
	}

	dprintf(LOG_DEBUG, "%s" "transmit %s to %s", FNAME,
		dhcp6msgstr(type), addr2str((struct sockaddr *)&dst));

	return (0);
}

static int
make_ia_stcode(iatype, iaid, stcode, retlist)
	int iatype;
	u_int16_t stcode;
	u_int32_t iaid;
	struct dhcp6_list *retlist;
{
	struct dhcp6_list stcode_list;
	struct dhcp6_ia ia_empty;

	memset(&ia_empty, 0, sizeof(ia_empty));
	ia_empty.iaid = iaid;

	TAILQ_INIT(&stcode_list);
	if (dhcp6_add_listval(&stcode_list, DHCP6_LISTVAL_STCODE,
	    &stcode, NULL) == NULL) {
		dprintf(LOG_NOTICE, "%s"
		    "failed to make an option list",
		    FNAME);
		return (-1);
	}

	if (dhcp6_add_listval(retlist, iatype,
	    &ia_empty, &stcode_list) == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to make an option list",
		    FNAME);
		dhcp6_clear_list(&stcode_list);
		return (-1);
	}
	dhcp6_clear_list(&stcode_list);

	return (0);
}

static int
make_ia(spec, conflist, retlist, client_conf, do_binding)
	struct dhcp6_listval *spec;
	struct dhcp6_list *conflist, *retlist;
	struct host_conf *client_conf;
	int do_binding;
{
	struct dhcp6_binding *binding;
	struct dhcp6_list ialist;
	struct dhcp6_listval *specia;
	struct dhcp6_ia ia;
	int found = 0;

	/*
	 * If we happen to have a binding already, update the binding and
	 * return it.  Perhaps the request is being retransmitted.
	 */
	if ((binding = find_binding(&client_conf->duid, DHCP6_BINDING_IA,
	    spec->type, spec->val_ia.iaid)) != NULL) {
		struct dhcp6_list *blist = &binding->val_list;
		struct dhcp6_listval *bia, *v;

		dprintf(LOG_DEBUG, "%s" "we have a binding already: %s",
		    FNAME, bindingstr(binding));

		update_binding(binding);

		memset(&ia, 0, sizeof(ia));
		ia.iaid = spec->val_ia.iaid;
		/* determine appropriate T1 and T2 */
		calc_ia_timo(&ia, blist, client_conf);
		if (dhcp6_add_listval(retlist, spec->type, &ia, blist)
		    == NULL) {
			dprintf(LOG_NOTICE, "%s"
			    "failed to copy binding info", FNAME);
			return (0);
		}

		/* remove bound values from the configuration */
		for (bia = TAILQ_FIRST(blist); bia;
		    bia = TAILQ_NEXT(bia, link)) {
			if ((v = dhcp6_find_listval(conflist,
			    bia->type, &bia->uv, 0)) != NULL) {
				found++;
				TAILQ_REMOVE(conflist, v, link);
				dhcp6_clear_listval(v);
			}
		}

		return (found);
	}

	/*
	 * trivial case:
	 * if the configuration is empty, we cannot make any IA.
	 */
	if (TAILQ_EMPTY(conflist))
		return (0);

	TAILQ_INIT(&ialist);

	/* First, check if we can meet the client's requirement */
	for (specia = TAILQ_FIRST(&spec->sublist); specia;
	    specia = TAILQ_NEXT(specia, link)) {
		/* try to find an IA that matches the spec best. */
		if (make_match_ia(specia, conflist, &ialist))
			found++;
	}
	if (found == 0) {
		struct dhcp6_listval *v;

		/* use the first IA in the configuration list */
		v = TAILQ_FIRST(conflist);
		if (dhcp6_add_listval(&ialist, v->type, &v->uv, NULL)) {
			found = 1;
			TAILQ_REMOVE(conflist, v, link);
			dhcp6_clear_listval(v);
		}
	}
	if (found) {
		memset(&ia, 0, sizeof(ia));
		ia.iaid = spec->val_ia.iaid;
		/* determine appropriate T1 and T2 */
		calc_ia_timo(&ia, &ialist, client_conf);

		/* make a binding for the set if necessary */
		if (found && do_binding) {
			if (add_binding(&client_conf->duid, DHCP6_BINDING_IA,
			    spec->type, spec->val_ia.iaid, &ialist) == NULL) {
				dprintf(LOG_NOTICE, "%s" "failed to make a"
				    " binding", FNAME);
				found = 0;
			}
		}
		if (found) {
			/* make an IA for the set */
			if (dhcp6_add_listval(retlist, spec->type,
			    &ia, &ialist) == NULL)
				found = 0;
		}
		dhcp6_clear_list(&ialist);
	}

	return (found);
}

static int
make_match_ia(spec, conflist, retlist)
	struct dhcp6_listval *spec;
	struct dhcp6_list *conflist, *retlist;
{
	struct dhcp6_listval *match;
	int matched = 0;

	/* do we have the exact value specified? */
	match = dhcp6_find_listval(conflist, spec->type, &spec->uv, 0);

	/* if not, make further search specific to the IA type. */
	if (!match) {
		switch (spec->type) {
		case DHCP6_LISTVAL_PREFIX6:
			match = dhcp6_find_listval(conflist, spec->type,
			    &spec->uv, MATCHLIST_PREFIXLEN);
			break;
		}
	}

	/*
	 * if found, remove the matched entry from the configuration list
	 * and copy the value in the returned list.
	 */
	if (match) {
		if (dhcp6_add_listval(retlist, match->type,
		    &match->uv, NULL)) {
			matched = 1;
			TAILQ_REMOVE(conflist, match, link);
			dhcp6_clear_listval(match);
		}
	}

	return (matched);
}

static void
calc_ia_timo(ia, ialist, client_conf)
	struct dhcp6_ia *ia;
	struct dhcp6_list *ialist; /* this should not be empty */
	struct host_conf *client_conf; /* unused yet */
{
	struct dhcp6_listval *iav;
	u_int32_t base = DHCP6_DURATITION_INFINITE;
	int iatype;

	iatype = TAILQ_FIRST(ialist)->type;
	for (iav = TAILQ_FIRST(ialist); iav; iav = TAILQ_NEXT(iav, link)) {
		if (iav->type != iatype) {
			dprintf(LOG_ERR, "%s"
			    "assumption failure: IA list is not consistent",
			    FNAME);
			exit (1); /* XXX */
		}
		switch (iatype) {
		case DHCP6_LISTVAL_PREFIX6:
			if (base == DHCP6_DURATITION_INFINITE ||
			    iav->val_prefix6.pltime < base)
				base = iav->val_prefix6.pltime;
			break;
		}
	}

	switch (iatype) {
	case DHCP6_LISTVAL_PREFIX6:
		/*
		 * Configure the timeout parameters as recommended in
		 * Section 8 of dhcpv6-opt-prefix-delegation-01.
		 * We could also set the parameters to 0 if we let the client
		 * decide the renew timing (not implemented yet).
		 */
		if (base == DHCP6_DURATITION_INFINITE) {
			ia->t1 = DHCP6_DURATITION_INFINITE;
			ia->t2 = DHCP6_DURATITION_INFINITE;
		} else {
			ia->t1 = base / 2;
			ia->t2 = (base * 4) / 5;
		}
		break;
	}
}

static void
update_binding_duration(binding)
	struct dhcp6_binding *binding;
{
	struct dhcp6_list *ia_list = &binding->val_list;
	struct dhcp6_listval *iav;
	int duration = DHCP6_DURATITION_INFINITE;
	u_int32_t past, lifetime, min_lifetime;
	time_t now = time(NULL);

	min_lifetime = 0;
	past = (u_int32_t)(now >= binding->updatetime ?
	    now - binding->updatetime : 0);

	switch (binding->type) {
	case DHCP6_BINDING_IA:
		/*
		 * Binding configuration is a list of IA parameters.
		 * Determine the minimum valid lifetime.
		 */
		for (iav = TAILQ_FIRST(ia_list); iav;
		    iav = TAILQ_NEXT(iav, link)) {
			switch (binding->iatype) {
			case DHCP6_LISTVAL_IAPD:
				lifetime = iav->val_prefix6.vltime;
				break;
			}

			if (min_lifetime == 0 ||
			    (lifetime != DHCP6_DURATITION_INFINITE &&
			    lifetime < min_lifetime))
				min_lifetime = lifetime;
		}

		if (past < min_lifetime)
			duration = min_lifetime - past;
		else
			duration = 0;

		break;
	default:
		/* should be internal error. */
		dprintf(LOG_ERR, "%s" "unknown binding type (%d)", FNAME,
		    binding->type);
		return;
	}

	binding->duration = duration;
}

static struct dhcp6_binding *
add_binding(clientid, btype, iatype, iaid, val0)
	struct duid *clientid;
	dhcp6_bindingtype_t btype;
	int iatype;
	u_int32_t iaid;
	void *val0;
{
	struct dhcp6_binding *binding = NULL;
	u_int32_t duration = DHCP6_DURATITION_INFINITE;
	char *val = NULL;

	if ((binding = malloc(sizeof(*binding))) == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to allocate memory", FNAME);
		return (NULL);
	}
	memset(binding, 0, sizeof(*binding));
	binding->type = btype;
	if (duidcpy(&binding->clientid, clientid)) {
		dprintf(LOG_NOTICE, "%s" "failed to copy DUID");
		goto fail;
	}
	binding->iatype = iatype;
	binding->iaid = iaid;

	/* construct configuration information for this binding */
	switch (btype) {
	case DHCP6_BINDING_IA:
		TAILQ_INIT(&binding->val_list);
		if (dhcp6_copy_list(&binding->val_list,
		    (struct dhcp6_list *)val0)) {
			dprintf(LOG_NOTICE, "%s" "failed to copy binding data",
			    FNAME);
			goto fail;
		}
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected binding type(%d)",
		    FNAME, btype);
		goto fail;
	}

	/* calculate duration and start timer accordingly */
	binding->updatetime = time(NULL);
	update_binding_duration(binding);
	if (binding->duration != DHCP6_DURATITION_INFINITE) {
		struct timeval timo;

		binding->timer = dhcp6_add_timer(binding_timo, binding);
		if (binding->timer == NULL) {
			dprintf(LOG_NOTICE, "%s" "failed to add timer", FNAME);
			goto fail;
		}
		timo.tv_sec = (long)duration;
		timo.tv_usec = 0;
		dhcp6_set_timer(&timo, binding->timer);
	}

	TAILQ_INSERT_TAIL(&dhcp6_binding_head, binding, link);

	dprintf(LOG_DEBUG, "%s" "add a new binding %s", FNAME,
	    bindingstr(binding));

	return (binding);

  fail:
	if (binding)
		free_binding(binding);
	return (NULL);
}

static struct dhcp6_binding *
find_binding(clientid, btype, iatype, iaid)
	struct duid *clientid;
	dhcp6_bindingtype_t btype;
	int iatype;
	u_int32_t iaid;
{
	struct dhcp6_binding *bp;
	struct dhcp6_prefix *pfx0, *pfx;

	for (bp = TAILQ_FIRST(&dhcp6_binding_head); bp;
	    bp = TAILQ_NEXT(bp, link)) {
		if (bp->type != btype || duidcmp(&bp->clientid, clientid))
			continue;

		if (btype == DHCP6_BINDING_IA &&
		    (bp->iatype != iatype || bp->iaid != iaid))
			continue;

		return (bp);
	}

	return (NULL);
}

static void
update_binding(binding)
	struct dhcp6_binding *binding;
{
	struct timeval timo;

	dprintf(LOG_DEBUG, "%s" "update binding %s for %s", FNAME,
	    bindingstr(binding), duidstr(&binding->clientid));

	/* update timestamp and calculate new duration */
	binding->updatetime = time(NULL);
	update_binding_duration(binding);

	/* if the lease duration is infinite, there's nothing to do. */
	if (binding->duration == DHCP6_DURATITION_INFINITE)
		return;

	/* reset the timer with the duration */
	timo.tv_sec = (long)binding->duration;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, binding->timer);
}

static void
remove_binding(binding)
	struct dhcp6_binding *binding;
{
	dprintf(LOG_DEBUG, "%s" "remove a binding %s", FNAME,
	    bindingstr(binding));

	if (binding->timer)
		dhcp6_remove_timer(&binding->timer);

	TAILQ_REMOVE(&dhcp6_binding_head, binding, link);

	free_binding(binding);
}

static void
free_binding(binding)
	struct dhcp6_binding *binding;
{
	duidfree(&binding->clientid);

	/* free configuration info in a type dependent manner. */
	switch (binding->type) {
	case DHCP6_BINDING_IA:
		dhcp6_clear_list(&binding->val_list);
		break;
	default:
		dprintf(LOG_ERR, "%s" "unknown binding type %d", FNAME,
		    binding->type);
		break;
	}

	free(binding);
}

static struct dhcp6_timer *
binding_timo(arg)
	void *arg;
{
	struct dhcp6_binding *binding = (struct dhcp6_binding *)arg;
	struct dhcp6_list *ia_list = &binding->val_list;
	struct dhcp6_listval *iav, *iav_next;
	time_t now = time(NULL);
	u_int32_t past, lifetime;
	struct timeval timo;

	past = (u_int32_t)(now >= binding->updatetime ?
	    now - binding->updatetime : 0);

	switch (binding->type) {
	case DHCP6_BINDING_IA:
		for (iav = TAILQ_FIRST(ia_list); iav; iav = iav_next) {
			iav_next = TAILQ_NEXT(iav, link);

			switch (binding->iatype) {
			case DHCP6_LISTVAL_IAPD:
				lifetime = iav->val_prefix6.vltime;
				break;
			}

			if (lifetime != DHCP6_DURATITION_INFINITE &&
			    lifetime <= past) {
				dprintf(LOG_DEBUG, "%s" "bound prefix %s/%d"
				    " in %s has expired", FNAME,
				    in6addr2str(&iav->val_prefix6.addr, 0),
				    iav->val_prefix6.plen,
				    bindingstr(binding));
				TAILQ_REMOVE(ia_list, iav, link);
				dhcp6_clear_listval(iav);
			}
		}

		/* If all IA parameters has expired, remove the binding. */
		if (TAILQ_EMPTY(ia_list)) {
			remove_binding(binding);
			return (NULL);
		}

		break;
	default:
		dprintf(LOG_ERR, "%s" "unknown binding type %d", FNAME,
		    binding->type);
		return (NULL);	/* XXX */
	}

	update_binding_duration(binding);

	/* if the lease duration is infinite, there's nothing to do. */
	if (binding->duration == DHCP6_DURATITION_INFINITE)
		return;

	/* reset the timer with the duration */
	timo.tv_sec = (long)binding->duration;
	timo.tv_usec = 0;
	dhcp6_set_timer(&timo, binding->timer);

	return (binding->timer);
}

static char *
bindingstr(binding)
	struct dhcp6_binding *binding;
{
	struct dhcp6_prefix *pfx;
	static char strbuf[LINE_MAX];	/* XXX: thread unsafe */
	char *iatype;

	switch (binding->type) {
	case DHCP6_BINDING_IA:
		switch (binding->iatype) {
		case DHCP6_LISTVAL_IAPD:
			iatype = "PD";
			break;
		}

		snprintf(strbuf, sizeof(strbuf),
		    "[IA: duid=%s, type=%s, iaid=%lu, duration=%lu]",
		    duidstr(&binding->clientid), iatype, binding->iaid,
		    binding->duration);
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected binding type(%d)", FNAME,
			binding->type);
		return ("???");
	}

	return (strbuf);
}
