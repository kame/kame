/*	$KAME: dhcp6c.c,v 1.90 2002/06/21 06:51:45 jinmei Exp $	*/
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
#include <sys/uio.h>
#include <sys/queue.h>
#include <errno.h>
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
#include <net/if_dl.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <ifaddrs.h>

#include <dhcp6.h>
#include <config.h>
#include <common.h>
#include <timer.h>
#include <prefixconf.h>

static int debug = 0;
static int signaled = 0;

const dhcp6_mode_t dhcp6_mode = DHCP6_MODE_CLIENT;

char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
int rtsock;	/* routing socket */

#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

static const struct sockaddr_in6 *sa6_allagent;
static struct duid client_duid;

static void usage __P((void));
static void client6_init __P((void));
static void client6_mainloop __P((void));
static struct dhcp6_serverinfo *find_server __P((struct dhcp6_if *,
						 struct duid *));
static struct dhcp6_serverinfo *select_server __P((struct dhcp6_if *));
static void client6_send __P((struct dhcp6_event *));
static int client6_recv __P((void));
static int client6_recvadvert __P((struct dhcp6_if *, struct dhcp6 *,
				   ssize_t, struct dhcp6_optinfo *));
static int client6_recvreply __P((struct dhcp6_if *, struct dhcp6 *,
				  ssize_t, struct dhcp6_optinfo *));
static void client6_sleep __P((void));
void client6_hup __P((int));
static struct dhcp6_event *find_event_withid __P((struct dhcp6_if *,
						  u_int32_t));
static int sa2plen __P((struct sockaddr_in6 *));
static void get_rtaddrs __P((int, struct sockaddr *, struct sockaddr **));

struct dhcp6_timer *client6_timo __P((void *));
void client6_send_renew __P((struct dhcp6_event *));
void client6_send_rebind __P((struct dhcp6_event *));

#define DHCP6C_CONF "/usr/local/v6/etc/dhcp6c.conf"
#define DHCP6C_PIDFILE "/var/run/dhcp6c.pid"
#define DUID_FILE "/etc/dhcp6c_duid"

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch, pid;
	char *progname, *conffile = DHCP6C_CONF;
	FILE *pidfp;
	struct dhcp6_if *ifp;
	struct dhcp6_event *ev;

	srandom(time(NULL) & getpid());

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	while ((ch = getopt(argc, argv, "c:dDf")) != -1) {
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
		default:
			usage();
			exit(0);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		exit(0);
	}
	device = argv[0];

	if (foreground == 0) {
		if (daemon(0, 0) < 0)
			err(1, "daemon");
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
	}
	setloglevel(debug);

	/* dump current PID */
	pid = getpid();
	if ((pidfp = fopen(DHCP6C_PIDFILE, "w")) != NULL) {
		fprintf(pidfp, "%d\n", pid);
		fclose(pidfp);
	}

	ifinit(device);

	if ((cfparse(conffile)) != 0) {
		dprintf(LOG_ERR, "%s" "failed to parse configuration file",
			FNAME);
		exit(1);
	}

	client6_init();

	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		/* create an event for the initial delay */
		if ((ev = dhcp6_create_event(ifp, DHCP6S_INIT)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to create an event",
				FNAME);
			exit(1);
		}
		TAILQ_INSERT_TAIL(&ifp->event_list, ev, link);
		if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a timer for %s",
				FNAME, ifp->ifname);
			exit(1);
		}
		dhcp6_reset_timer(ev);
	}

	client6_mainloop();
	exit(0);
}

static void
usage()
{

	fprintf(stderr, "usage: dhcpc [-c configfile] [-dDf] intface\n");
}

/*------------------------------------------------------------*/

void
client6_init()
{
	struct addrinfo hints, *res;
	static struct sockaddr_in6 sa6_allagent_storage;
	int error, on = 1;
	struct dhcp6_if *ifp;
	struct dhcp6_event *ev;
	int ifidx;

	ifidx = if_nametoindex(device);
	if (ifidx == 0) {
		dprintf(LOG_ERR, "if_nametoindex(%s)");
		exit(1);
	}

	/* get our DUID */
	if (get_duid(DUID_FILE, &client_duid)) {
		dprintf(LOG_ERR, "%s" "failed to get a DUID", FNAME);
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		dprintf(LOG_ERR, "%s" "socket(inbound)", FNAME);
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEPORT,
		       &on, sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s" "setsockopt(inbound, SO_REUSEPORT): %s",
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
		dprintf(LOG_ERR, "%s" "bind(inbonud): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		dprintf(LOG_ERR, "%s" "socket(outbound): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(outbound, IPV6_MULTICAST_IF): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s"
			"setsockopt(outsock, IPV6_MULTICAST_LOOP): %s",
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

	/*
	 * bind the well-known incoming port to the outgoing socket
	 * for interoperability with some servers.
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	if (setsockopt(outsock, SOL_SOCKET, SO_REUSEPORT,
		       &on, sizeof(on)) < 0) {
		dprintf(LOG_ERR, "%s" "setsockopt(inbound, SO_REUSEPORT): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	if (bind(outsock, res->ai_addr, res->ai_addrlen) < 0) {
		dprintf(LOG_ERR, "%s" "bind(inbonud): %s",
			FNAME, strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	/* open a routing socket to watch the routing table */
	if ((rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "open a routing socket: %s",
			FNAME, strerror(errno));
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "%s" "getaddrinfo: %s",
			FNAME, gai_strerror(error));
		exit(1);
	}
	memcpy(&sa6_allagent_storage, res->ai_addr, res->ai_addrlen);
	sa6_allagent = (const struct sockaddr_in6 *)&sa6_allagent_storage;
	freeaddrinfo(res);

	/* client interface configuration */
	if ((ifp = find_ifconfbyname(device)) == NULL) {
		dprintf(LOG_ERR, "%s" "interface %s not configured",
			FNAME, device);
		exit(1);
	}
	ifp->outsock = outsock;

	prefix6_init();
}

static void
client6_mainloop()
{
	struct timeval *w;
	int ret;
	fd_set r;

	while(1) {
		w = dhcp6_check_timer();

		FD_ZERO(&r);
		FD_SET(insock, &r);

		ret = select(insock + 1, &r, NULL, NULL, w);

		switch (ret) {
		case -1:
			dprintf(LOG_ERR, "%s" "select: %s",
				FNAME, strerror(errno));
			exit(1); /* XXX: signal case? */
		case 0:	/* timeout */
			break;	/* dhcp6_check_timer() will treat the case */
		default: /* received a packet */
			client6_recv();
		}
	}
}

struct dhcp6_timer *
client6_timo(arg)
	void *arg;
{
	struct dhcp6_event *ev = (struct dhcp6_event *)arg;
	struct dhcp6_if *ifp;

	ifp = ev->ifp;
	ev->timeouts++;
	if (ev->max_retrans_cnt && ev->timeouts > ev->max_retrans_cnt) {
		dprintf(LOG_INFO, "%s" "no responses were received", FNAME);
		dhcp6_remove_event(ev);	/* XXX: should free event data? */
		return(NULL);
	}

	switch(ev->state) {
	case DHCP6S_INIT:
		ev->timeouts = 0; /* indicate to generate a new XID. */
		if ((ifp->send_flags & DHCIFF_INFO_ONLY))
			ev->state = DHCP6S_INFOREQ;
		else
			ev->state = DHCP6S_SOLICIT;
		dhcp6_set_timeoparam(ev); /* XXX */
		/* fall through */
	case DHCP6S_INFOREQ:
		client6_send(ev);
		break;
	case DHCP6S_RENEW:
	case DHCP6S_REBIND:
		if (!TAILQ_EMPTY(&ev->data_list)) {
			if (ev->state == DHCP6S_RENEW)
				client6_send_renew(ev);
			else
				client6_send_rebind(ev);
		} else {
			dprintf(LOG_INFO, "%s"
			    "all information to be updated were canceled",
			    FNAME);
			dhcp6_remove_event(ev);
			return(NULL);
		}
		break;
	case DHCP6S_SOLICIT:
		if (ifp->servers) {
			ifp->current_server = select_server(ifp);
			if (ifp->current_server == NULL) {
				/* this should not happen! */
				dprintf(LOG_ERR, "%s" "can't find a server"
					FNAME);
				exit(1); /* XXX */
			}
			ev->timeouts = 0;
			ev->state = DHCP6S_REQUEST;
			dhcp6_set_timeoparam(ev);
		}
		client6_send(ev);
		break;
	}

	dhcp6_reset_timer(ev);

	return(ev->timer);
}

static struct dhcp6_serverinfo *
select_server(ifp)
	struct dhcp6_if *ifp;
{
	struct dhcp6_serverinfo *s;

	/*
	 * pick the best server according to dhcpv6-24 Section 17.1.3
	 * XXX: we currently just choose the one that is active and has the
	 * highest preference.
	 */
	for (s = ifp->servers; s; s = s->next) {
		if (s->active) {
			dprintf(LOG_DEBUG, "%s" "picked a server (ID: %s)",
				FNAME, duidstr(&s->optinfo.serverID));
			return(s);
		}
	}

	return(NULL);
}

/* sleep until an event to activiate myself occurs */
/* ARGSUSED */
void
client6_hup(sig)
	int sig;
{

	dprintf(LOG_INFO, "%s" "received a SIGHUP", FNAME);
	signaled = 1;
}

static int
sa2plen(sa6)
	struct sockaddr_in6 *sa6;
{
	int masklen;
	u_char *p, *lim;
	
	p = (u_char *)(&sa6->sin6_addr);
	lim = (u_char *)sa6 + sa6->sin6_len;
	for (masklen = 0; p < lim; p++) {
		switch (*p) {
		case 0xff:
			masklen += 8;
			break;
		case 0xfe:
			masklen += 7;
			break;
		case 0xfc:
			masklen += 6;
			break;
		case 0xf8:
			masklen += 5;
			break;
		case 0xf0:
			masklen += 4;
			break;
		case 0xe0:
			masklen += 3;
			break;
		case 0xc0:
			masklen += 2;
			break;
		case 0x80:
			masklen += 1;
			break;
		case 0x00:
			break;
		default:
			return(-1);
		}
	}

	return(masklen);
}

static void
client6_sleep()
{
	char msg[2048], *lim;
	struct rt_msghdr *rtm;
	int n, ret;
	fd_set r;
	struct sockaddr *sa, *dst, *mask, *rti_info[RTAX_MAX];

	dprintf(LOG_DEBUG, "%s" "start sleeping", FNAME);

	if (signal(SIGHUP, client6_hup) == SIG_ERR) {
		dprintf(LOG_WARNING, "%s" "failed to set signal: %s",
			FNAME, strerror(errno));
		/* XXX: assert? */
	}

  again:
	signaled = 0;
	FD_ZERO(&r);
	FD_SET(rtsock, &r);

	ret = select(rtsock + 1, &r, NULL, NULL, NULL);
	if (ret == -1) { 
		if (errno == EINTR && signaled) {
			dprintf(LOG_INFO, "%s" "signal from a user received."
				FNAME);
			goto activate;
		}
		dprintf(LOG_WARNING, "%s" "select was interrupted by an "
			"unexpected signal", FNAME);
		goto again;	/* XXX: or assert? */
	}

	n = read(rtsock, msg, sizeof(msg));
	if (n < 0) {
		dprintf(LOG_WARNING, "%s" "read failed: %s", FNAME,
			strerror(errno));
		goto again;
	}
	dprintf(LOG_DEBUG, "%s" "received a routing message (len = %d)",
		FNAME, n);

	lim = msg + n;
	for (rtm = (struct rt_msghdr *)msg;
	     rtm < (struct rt_msghdr *)lim;
	     rtm = (struct rt_msghdr *)(((char *)rtm) + rtm->rtm_msglen)) {
		/* just for safety */
		if (!rtm->rtm_msglen) {
			dprintf(LOG_WARNING, "%s" "rtm_msglen is 0 "
				"(msgbuf=%p lim=%p rtm=%p)",
				FNAME, msg, lim, rtm);
			break;
		}
		dprintf(LOG_DEBUG, "%s" "message type=%d", FNAME,
			rtm->rtm_type);

		if (rtm->rtm_type != RTM_ADD)
			continue;

		sa = (struct sockaddr *)(rtm + 1);
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
		if ((dst = rti_info[RTAX_DST]) == NULL ||
		    dst->sa_family != AF_INET6 ||
		    (mask = rti_info[RTAX_NETMASK]) == NULL)
			continue;

		if (IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)dst)->sin6_addr) &&
		    sa2plen((struct sockaddr_in6 *)mask) == 0) {
			struct sockaddr *gw;

			dprintf(LOG_INFO, "%s" "default router has changed. "
				"activate DHCPv6.", FNAME);
			if ((gw = rti_info[RTAX_GATEWAY]) != NULL) {
				switch (gw->sa_family) {
				case AF_INET6:
					dprintf(LOG_INFO, "%s"
						"new gateway: %s", FNAME,
						addr2str(gw));
					break;
				case AF_LINK:
				{
					struct sockaddr_dl *sdl;
					char ifnambuf[IF_NAMESIZE];

					sdl = (struct sockaddr_dl *)gw;
					if (if_indextoname(sdl->sdl_index,
							   ifnambuf) != NULL) {
						dprintf(LOG_INFO, "%s"
							"new default to %s",
							FNAME, ifnambuf);
					} else {
						dprintf(LOG_INFO, "%s"
							"new default to ?",
							FNAME);
					}
					break;
				}
				}
			}

			goto activate;
		}
		else {
			dprintf(LOG_DEBUG, "%s"
				"rtmsg add dst = %s, mask = %s", FNAME,
				addr2str(dst), addr2str(mask));
		}
	}

	goto again;

  activate:
	/* stop the signal handler and wake up */
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		dprintf(LOG_WARNING, "%s" "failed to reset signal: %s",
			FNAME, strerror(errno));
	dprintf(LOG_DEBUG, "%s" "activated", FNAME);
	return;
}

/* used by client6_sleep */
#define ROUNDUP(a, size) \
	(((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

#define NEXT_SA(ap) (ap) = (struct sockaddr *) \
	((caddr_t)(ap) + ((ap)->sa_len ? ROUNDUP((ap)->sa_len,\
						 sizeof(u_long)) :\
			  			 sizeof(u_long)))
static void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int i;
	
	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			NEXT_SA(sa);
		} else
			rti_info[i] = NULL;
	}
}

static void
client6_send(ev)
	struct dhcp6_event *ev;
{
	struct dhcp6_if *ifp;
	char buf[BUFSIZ];
	struct sockaddr_in6 dst;
	int error;
	struct dhcp6 *dh6;
	struct dhcp6opt *opt;
	struct dhcp6_optinfo optinfo;
	ssize_t optlen, len;

	ifp = ev->ifp;

	dh6 = (struct dhcp6 *)buf;
	memset(dh6, 0, sizeof(*dh6));

	switch(ev->state) {
	case DHCP6S_SOLICIT:
		dh6->dh6_msgtype = DH6_SOLICIT;
		break;
	case DHCP6S_REQUEST:
		if (ifp->current_server == NULL) {
			dprintf(LOG_ERR, "%s" "assumption failure", FNAME);
			exit(1); /* XXX */
		}
		dh6->dh6_msgtype = DH6_REQUEST;
		break;
	case DHCP6S_INFOREQ:
		dh6->dh6_msgtype = DH6_INFORM_REQ;
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected state");
		exit(1);	/* XXX */
	}
	if (ev->timeouts == 0) {
		/*
		 * A client MUST leave the transaction-ID unchanged in
		 * retransmissions of a message. [dhcpv6-24 15.1]
		 */
		ev->xid = random() & DH6_XIDMASK;
		dprintf(LOG_DEBUG, "%s" "a new XID (%x) is generated",
			FNAME, ev->xid);
	}
	dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
	dh6->dh6_xid |= htonl(ev->xid);
	len = sizeof(*dh6);

	/*
	 * construct options
	 */
	dhcp6_init_options(&optinfo);

	/* server ID */
	if (ev->state == DHCP6S_REQUEST) {
		if (duidcpy(&optinfo.serverID,
		    &ifp->current_server->optinfo.serverID)) {
			dprintf(LOG_ERR, "%s" "failed to copy server ID",
			    FNAME);
			goto end;
		}
	}

	/* client ID */
	if (duidcpy(&optinfo.clientID, &client_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto end;
	}

	/* rapid commit */
	if (ev->state == DHCP6S_SOLICIT &&
	    (ifp->send_flags & DHCIFF_RAPID_COMMIT)) {
		optinfo.rapidcommit = 1;
	}

	/* option request options */
	if (dhcp6_copy_list(&optinfo.reqopt_list, &ifp->reqopt_list)) {
		dprintf(LOG_ERR, "%s" "failed to copy requested options",
		    FNAME);
		goto end;
	}

	/* configuration information provided by the server */
	if (ev->state == DHCP6S_REQUEST) {
		/* do we have to check if we wanted prefixes? */
		if (dhcp6_copy_list(&optinfo.prefix_list,
		    &ifp->current_server->optinfo.prefix_list)) {
			dprintf(LOG_ERR, "%s" "failed to copy prefixes",
			    FNAME);
			goto end;
		}
	}

	/* set options in the message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(buf + sizeof(buf)),
					&optinfo)) < 0) {
		dprintf(LOG_INFO, "%s" "failed to construct options", FNAME);
		goto end;
	}
	len += optlen;

	/*
	 * Unless otherwise specified, a client sends DHCP messages to the
	 * All_DHCP_Relay_Agents_and_Servers or the DHCP_Anycast address.
	 * [dhcpv6-24 Section 13.]
	 * Our current implementation always follows the case.
	 */
	dst = *sa6_allagent;
	dst.sin6_scope_id = ifp->linkid;

	if (transmit_sa(ifp->outsock, (struct sockaddr *)&dst, buf, len)
	    != 0) {
		dprintf(LOG_ERR, "%s" "transmit failed", FNAME);
		goto end;
	}

	dprintf(LOG_DEBUG, "%s" "send %s to %s", FNAME,
		dhcp6msgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&dst));

  end:
	dhcp6_clear_options(&optinfo);
	return;
}

void
client6_send_renew(ev)
	struct dhcp6_event *ev;
{
	struct dhcp6_if *ifp;
	struct dhcp6_eventdata *evd;
	struct dhcp6_optinfo optinfo;
	struct dhcp6_listval *dlv;
	struct dhcp6 *dh6;
	char buf[BUFSIZ];
	ssize_t optlen, len;
	struct sockaddr_in6 dst;

	ifp = ev->ifp;
	
	dh6 = (struct dhcp6 *)buf;
	memset(dh6, 0, sizeof(*dh6));
	dh6->dh6_msgtype = DH6_RENEW;
	if (ev->timeouts == 0) {
		ev->xid = random() & DH6_XIDMASK;
		dprintf(LOG_DEBUG, "%s" "a new XID (%x) is generated",
			FNAME, ev->xid);
	}
	dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
	dh6->dh6_xid |= htonl(ev->xid);
	len = sizeof(*dh6);

	/*
	 * construct options
	 */
	dhcp6_init_options(&optinfo);

	/* server ID */
	if (duidcpy(&optinfo.serverID, &ev->serverid)) {
		dprintf(LOG_ERR, "%s" "failed to copy server ID", FNAME);
		goto end;
	}

	/* client ID */
	if (duidcpy(&optinfo.clientID, &client_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto end;
	}

	/* configuration information to be renewed */
	for (evd = TAILQ_FIRST(&ev->data_list); evd;
	     evd = TAILQ_NEXT(evd, link)) {
		switch(evd->type) {
		case DHCP6_DATA_PREFIX:
			if (dhcp6_add_listval(&optinfo.prefix_list,
			    &((struct dhcp6_siteprefix *)evd->data)->prefix,
			    DHCP6_LISTVAL_PREFIX6) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add a "
				    "prefix", FNAME);
				goto end;
			}
			break;
		default:
			dprintf(LOG_ERR, "%s" "unexpected event data (d)",
				FNAME, evd->type);
			exit(1);
		}
	}

	/* set options in the message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(buf + sizeof(buf)),
					&optinfo)) < 0) {
		dprintf(LOG_INFO, "%s" "failed to construct options", FNAME);
		goto end;
	}
	len += optlen;

	/*
	 * Unless otherwise specified, a client sends DHCP messages to the
	 * All_DHCP_Relay_Agents_and_Servers or the DHCP_Anycast address.
	 * [dhcpv6-24 Section 13.]
	 * Our current implementation always follows the case.
	 */
	dst = *sa6_allagent;
	dst.sin6_scope_id = ifp->linkid;

	if (transmit_sa(ifp->outsock, (struct sockaddr *)&dst, buf,
			len) != 0) {
		dprintf(LOG_ERR, "%s" "transmit failed", FNAME);
		goto end;
	}

	dprintf(LOG_DEBUG, "%s" "send %s to %s", FNAME,
		dhcp6msgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&dst));

  end:
	dhcp6_clear_options(&optinfo);
	return;
}

void
client6_send_rebind(ev)
	struct dhcp6_event *ev;
{
	struct dhcp6_if *ifp;
	struct dhcp6_eventdata *evd;
	struct dhcp6_optinfo optinfo;
	struct dhcp6_listval *dlv;
	struct dhcp6 *dh6;
	char buf[BUFSIZ];
	ssize_t optlen, len;
	struct sockaddr_in6 dst;

	ifp = ev->ifp;
	
	dh6 = (struct dhcp6 *)buf;
	memset(dh6, 0, sizeof(*dh6));
	dh6->dh6_msgtype = DH6_REBIND;
	if (ev->timeouts == 0) {
		ev->xid = random() & DH6_XIDMASK;
		dprintf(LOG_DEBUG, "%s" "a new XID (%x) is generated",
			FNAME, ev->xid);
	}
	dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
	dh6->dh6_xid |= htonl(ev->xid);
	len = sizeof(*dh6);

	/*
	 * construct options
	 */
	dhcp6_init_options(&optinfo);

	/* client ID */
	if (duidcpy(&optinfo.clientID, &client_duid)) {
		dprintf(LOG_ERR, "%s" "failed to copy client ID", FNAME);
		goto end;
	}

	/* configuration information to be rebound */
	for (evd = TAILQ_FIRST(&ev->data_list); evd;
	     evd = TAILQ_NEXT(evd, link)) {
		switch(evd->type) {
		case DHCP6_DATA_PREFIX:
			if (dhcp6_add_listval(&optinfo.prefix_list,
			    &((struct dhcp6_siteprefix *)evd->data)->prefix,
			    DHCP6_LISTVAL_PREFIX6) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add a "
				    "prefix", FNAME);
				goto end;
			}
			break;
		default:
			dprintf(LOG_ERR, "%s"
			    "unexpected event data (type %d)",
			    FNAME, evd->type);
			exit(1);
		}
	}

	/* set options in the message */
	if ((optlen = dhcp6_set_options((struct dhcp6opt *)(dh6 + 1),
					(struct dhcp6opt *)(buf + sizeof(buf)),
					&optinfo)) < 0) {
		dprintf(LOG_INFO, "%s" "failed to construct options", FNAME);
		goto end;
	}
	len += optlen;

	/*
	 * Unless otherwise specified, a client sends DHCP messages to the
	 * All_DHCP_Relay_Agents_and_Servers or the DHCP_Anycast address.
	 * [dhcpv6-24 Section 13.]
	 * Our current implementation always follows the case.
	 */
	dst = *sa6_allagent;
	dst.sin6_scope_id = ifp->linkid;

	if (transmit_sa(ifp->outsock, (struct sockaddr *)&dst, buf,
			len) != 0) {
		dprintf(LOG_ERR, "%s" "transmit failed", FNAME);
		goto end;
	}

	dprintf(LOG_DEBUG, "%s" "send %s to %s", FNAME,
		dhcp6msgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&dst));

  end:
	dhcp6_clear_options(&optinfo);
	return;
}

static int
client6_recv()
{
	char rbuf[BUFSIZ], cmsgbuf[BUFSIZ];
	struct msghdr mhdr;
	struct iovec iov;
	struct sockaddr_storage from;
	struct dhcp6_if *ifp;
	struct dhcp6opt *p, *ep;
	struct dhcp6_optinfo optinfo;
	ssize_t len;
	struct dhcp6 *dh6;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;

	memset(&iov, 0, sizeof(iov));
	memset(&mhdr, 0, sizeof(mhdr));

	iov.iov_base = (caddr_t)rbuf;
	iov.iov_len = sizeof(rbuf);
	mhdr.msg_name = (caddr_t)&from;
	mhdr.msg_namelen = sizeof(from);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (caddr_t)cmsgbuf;
	mhdr.msg_controllen = sizeof(cmsgbuf);
	if ((len = recvmsg(insock, &mhdr, 0)) < 0) {
		dprintf(LOG_ERR, "%s" "recvmsg: %s", FNAME, strerror(errno));
		return;
	}

	/* detect receiving interface */
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
		return;
	}

	if ((ifp = find_ifconfbyid((unsigned int)pi->ipi6_ifindex)) == NULL) {
		dprintf(LOG_INFO, "%s" "unexpected interface (%d)", FNAME,
			(unsigned int)pi->ipi6_ifindex);
		return;
	}

	if (len < sizeof(*dh6)) {
		dprintf(LOG_INFO, "%s" "short packet", FNAME);
		return;
	}

	dh6 = (struct dhcp6 *)rbuf;

	dprintf(LOG_DEBUG, "%s" "receive %s from %s on %s", FNAME,
		dhcp6msgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&from), ifp->ifname);

	/* get options */
	dhcp6_init_options(&optinfo);
	p = (struct dhcp6opt *)(dh6 + 1);
	ep = (struct dhcp6opt *)((char *)dh6 + len);
	if (dhcp6_get_options(p, ep, &optinfo) < 0) {
		dprintf(LOG_INFO, "%s" "failed to parse options", FNAME);
		return;
	}

	switch(dh6->dh6_msgtype) {
	case DH6_ADVERTISE:
		(void)client6_recvadvert(ifp, dh6, len, &optinfo);
		break;
	case DH6_REPLY:
		(void)client6_recvreply(ifp, dh6, len, &optinfo);
		break;
	default:
		dprintf(LOG_INFO, "%s" "received an unexpected message (%s) "
			"from %s", FNAME, dhcp6msgstr(dh6->dh6_msgtype),
			addr2str((struct sockaddr *)&from));
		break;
	}

  end:
	dhcp6_clear_options(&optinfo);
	return;
}

static int
client6_recvadvert(ifp, dh6, len, optinfo0)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	ssize_t len;
	struct dhcp6_optinfo *optinfo0;
{
	struct dhcp6_serverinfo *newserver, *s, **sp;
	struct dhcp6_optinfo optinfo;
	struct dhcp6_event *ev;

	/* find the corresponding event based on the received xid */
	ev = find_event_withid(ifp, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
	if (ev == NULL) {
		dprintf(LOG_INFO, "%s" "XID mismatch", FNAME);
		return -1;
	}

	if (ev->state != DHCP6S_SOLICIT ||
	    (ifp->send_flags & DHCIFF_RAPID_COMMIT)) {
		dprintf(LOG_INFO, "%s" "unexpected advertise", FNAME);
		return -1;
	}

	/* packet validation based on Section 15.3 of dhcpv6-24. */
	if (optinfo0->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	} else {
		dprintf(LOG_DEBUG, "%s" "server ID: %s, pref=%d", FNAME,
			duidstr(&optinfo0->serverID),
			optinfo0->pref);
	}
	if (optinfo0->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no client ID option", FNAME);
		return -1;
	}
	if (duidcmp(&optinfo0->clientID, &client_duid)) {
		dprintf(LOG_INFO, "%s" "client DUID mismatch", FNAME);
		return -1;
	}

	/*
	 * The client MUST ignore any Advertise message that includes a Status
	 * Code option containing the value AddrUnavail.
	 * [dhcpv6-24, Section 17.1.3].
	 * XXX: we should not follow this when we do not need addresses!!
	 */
	;

	/* ignore the server if it is known */
	if (find_server(ifp, &optinfo0->serverID)) {
		dprintf(LOG_INFO, "%s" "duplicated server (ID: %s)",
			FNAME, duidstr(&optinfo0->serverID));
		return -1;
	}

	/* keep the server */
	dhcp6_init_options(&optinfo);
	if (dhcp6_copy_options(optinfo0, &optinfo)) {
		dprintf(LOG_ERR, "%s" "failed to copy options", FNAME);
		return -1;
	}
	if ((newserver = malloc(sizeof(*newserver))) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed for server",
			FNAME);
		return -1;
	}
	memset(newserver, 0, sizeof(*newserver));
	if (optinfo0->pref != DH6OPT_PREF_UNDEF)
		newserver->pref = optinfo0->pref;
	newserver->optinfo = optinfo;
	newserver->active = 1;
	for (sp = &ifp->servers; *sp; sp = &(*sp)->next) {
		if ((*sp)->pref != DH6OPT_PREF_MAX &&
		    (*sp)->pref < newserver->pref) {
			break;
		}
	}
	newserver->next = *sp;
	*sp = newserver;

	/* if the server has an extremely high preference, just use it. */
	if (newserver->pref == DH6OPT_PREF_MAX) {
		ev->timeouts = 0;
		ev->state = DHCP6S_REQUEST;
		ifp->current_server = newserver;

		client6_send(ev);

		dhcp6_set_timeoparam(ev);
		dhcp6_reset_timer(ev);
	} else if (ifp->servers->next == NULL) {
		struct timeval *rest, elapsed, tv_rt, tv_irt, timo;

		/*
		 * If this is the first advertise, adjust the timer so that
		 * the client can collect other servers until IRT elapses.
		 * XXX: we did not want to do such "low level" timer
		 *      calculation here.
		 */
		rest = dhcp6_timer_rest(ev->timer);
		tv_rt.tv_sec = (ev->retrans * 1000) / 1000000;
		tv_rt.tv_usec = (ev->retrans * 1000) % 1000000;
		tv_irt.tv_sec = (ev->init_retrans * 1000) / 1000000;
		tv_irt.tv_usec = (ev->init_retrans * 1000) % 1000000;
		timeval_sub(&tv_rt, rest, &elapsed);
		if (TIMEVAL_LEQ(elapsed, tv_irt))
			timeval_sub(&tv_irt, &elapsed, &timo);
		else
			timo.tv_sec = timo.tv_usec = 0;

		dprintf(LOG_DEBUG, "%s" "reset timer for %s to %d.%06d",
			FNAME, ifp->ifname,
			(int)timo.tv_sec, (int)timo.tv_usec);

		dhcp6_set_timer(&timo, ev->timer);
	}

	return 0;
}

static struct dhcp6_serverinfo *
find_server(ifp, duid)
	struct dhcp6_if *ifp;
	struct duid *duid;
{
	struct dhcp6_serverinfo *s;

	for (s = ifp->servers; s; s = s->next) {
		if (duidcmp(&s->optinfo.serverID, duid) == 0)
			return(s);
	}

	return(NULL);
}

static int
client6_recvreply(ifp, dh6, len, optinfo)
	struct dhcp6_if *ifp;
	struct dhcp6 *dh6;
	ssize_t len;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_listval *lv;
	struct dhcp6_event *ev;

	/* find the corresponding event based on the received xid */
	ev = find_event_withid(ifp, ntohl(dh6->dh6_xid) & DH6_XIDMASK);
	if (ev == NULL) {
		dprintf(LOG_INFO, "%s" "XID mismatch", FNAME);
		return -1;
	}

	if (ev->state != DHCP6S_INFOREQ &&
	    ev->state != DHCP6S_REQUEST &&
	    ev->state != DHCP6S_RENEW &&
	    ev->state != DHCP6S_REBIND &&
	    (ev->state != DHCP6S_SOLICIT ||
	     !(ifp->send_flags & DHCIFF_RAPID_COMMIT))) {
		dprintf(LOG_INFO, "%s" "unexpected reply", FNAME);
		return -1;
	}

	/* A Reply message must contain a Server ID option */
	if (optinfo->serverID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no server ID option", FNAME);
		return -1;
	}

	/*
	 * DUID in the Client ID option (which must be contained for our
	 * client implementation) must match ours.
	 */
	if (optinfo->clientID.duid_len == 0) {
		dprintf(LOG_INFO, "%s" "no client ID option", FNAME);
		return -1;
	}
	if (duidcmp(&optinfo->clientID, &client_duid)) {
		dprintf(LOG_INFO, "%s" "client DUID mismatch", FNAME);
		return -1;
	}

	/*
	 * The client MAY choose to report any status code or message from the
	 * status code option in the Reply message.
	 * [dhcpv6-24 Section 18.1.6]
	 */
	for (lv = TAILQ_FIRST(&optinfo->stcode_list); lv;
	     lv = TAILQ_NEXT(lv, link)) {
		dprintf(LOG_INFO, "%s" "status code: %s",
		    FNAME, dhcp6_stcodestr(lv->val_num));
	}

	if (!TAILQ_EMPTY(&optinfo->dns_list)) {
		struct dhcp6_listval *d;
		int i = 0;

		for (d = TAILQ_FIRST(&optinfo->dns_list); d;
		     d = TAILQ_NEXT(d, link), i++) {
			dprintf(LOG_DEBUG, "%s" "nameserver[%d] %s",
				FNAME, i, in6addr2str(&d->val_addr6, 0));
		}
	}

	if (ev->state == DHCP6S_RENEW || ev->state == DHCP6S_REBIND) {
		/*
		 * Update configuration information to be renewed or rebound.
		 * Note that the returned list is empty, in which case
		 * the waiting information should be removed.
		 */
		prefix6_update(ev, &optinfo->prefix_list, &optinfo->serverID);
	} else {
		for (lv = TAILQ_FIRST(&optinfo->prefix_list); lv;
		     lv = TAILQ_NEXT(lv, link)) {
			prefix6_add(ifp, &lv->val_prefix6, &optinfo->serverID);
		}
	}

	dhcp6_remove_event(ev);
	dprintf(LOG_DEBUG, "%s" "got an expected reply, sleeping.", FNAME);

	return 0;
}

static struct dhcp6_event *
find_event_withid(ifp, xid)
	struct dhcp6_if *ifp;
	u_int32_t xid;
{
	struct dhcp6_event *ev;

	for (ev = TAILQ_FIRST(&ifp->event_list); ev;
	     ev = TAILQ_NEXT(ev, link)) {
		if (ev->xid == xid)
			return(ev);
	}

	return(NULL);
}
