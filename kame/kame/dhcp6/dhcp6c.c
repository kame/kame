/*	$KAME: dhcp6c.c,v 1.65 2002/05/01 06:00:00 jinmei Exp $	*/
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
#ifdef __FreeBSD__
#include <sys/queue.h>
#endif
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
#include <common.h>
#include <config.h>

static int debug = 0;
static int signaled = 0;

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
static void client6_send __P((struct dhcp_if *, int));
static int client6_getreply __P((void));
static int client6_recv __P((struct dhcp_if *));
static int client6_recvreply __P((struct dhcp_if *, struct dhcp6 *, ssize_t));
static void client6_sleep __P((void));
void client6_hup __P((int));
static int sa2plen __P((struct sockaddr_in6 *));
static void get_rtaddrs __P((int, struct sockaddr *, struct sockaddr **));
static void tvfix __P((struct timeval *));
static void reset_timer __P((struct dhcp_if *));
static void set_timeoparam __P((struct dhcp_if *));

#define DHCP6C_CONF "/usr/local/v6/etc/dhcp6c.conf"
#define DHCP6C_PIDFILE "/var/run/dhcp6c.pid"
#define DUID_FILE "/etc/dhcp6c_duid"

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch, pid;
	char *progname;
	FILE *pidfp;

	srandom(time(NULL) & getpid());

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	while ((ch = getopt(argc, argv, "dDf")) != -1) {
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

	ifinit(device);

	if ((cfparse(DHCP6C_CONF)) != 0) {
		dprintf(LOG_ERR, "failed to parse configuration file");
		exit(1);
	}

	client6_init();

	/* dump current PID */
	pid = getpid();
	if ((pidfp = fopen(DHCP6C_PIDFILE, "w")) != NULL) {
		fprintf(pidfp, "%d\n", pid);
		fclose(pidfp);
	}

	client6_mainloop();
	exit(0);
}

static void
usage()
{

	fprintf(stderr, "usage: dhcpc [-dDf] intface\n");
}

/*------------------------------------------------------------*/

void
client6_init()
{
	struct addrinfo hints;
	struct addrinfo *res;
	static struct sockaddr_in6 sa6_allagent_storage;
	int error, on = 1;
	int ifidx;

	ifidx = if_nametoindex(device);
	if (ifidx == 0) {
		dprintf(LOG_ERR, "if_nametoindex(%s)");
		exit(1);
	}

	/* get our DUID */
	if (get_duid(DUID_FILE, &client_duid)) {
		dprintf(LOG_ERR, "failed to get a DUID");
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		dprintf(LOG_ERR, "socket(inbound)");
		exit(1);
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEPORT,
		       &on, sizeof(on)) < 0) {
		dprintf(LOG_ERR, "setsockopt(inbound, SO_REUSEPORT)");
		exit(1);
	}
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		dprintf(LOG_ERR, "bind(inbonud): %s", strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		dprintf(LOG_ERR, "socket(outbound): %s", strerror(errno));
		exit(1);
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		dprintf(LOG_ERR,
			"setsockopt(outbound, IPV6_MULTICAST_IF): %s",
			strerror(errno));
		exit(1);
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on,
		       sizeof(on)) < 0) {
		dprintf(LOG_ERR,
			"setsockopt(outsock, IPV6_MULTICAST_LOOP): %s",
			strerror(errno));
		exit(1);
	}
	/* make the socket write-only */
	if (shutdown(outsock, 0)) {
		dprintf(LOG_ERR, "shutdown(outbound, 0): %s", strerror(errno));
		exit(1);
	}
	freeaddrinfo(res);

	/* open a routing socket to watch the routing table */
	if ((rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		dprintf(LOG_ERR, "open a routing socket: %s", strerror(errno));
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		dprintf(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
		exit(1);
	}
	memcpy(&sa6_allagent_storage, res->ai_addr, res->ai_addrlen);
	sa6_allagent = (const struct sockaddr_in6 *)&sa6_allagent_storage;
	freeaddrinfo(res);
}

static void
client6_mainloop()
{
	struct dhcp_if *ifp;	/* XXX: multiple-interface support */
	struct timeval finish, w;
	int ret;
	fd_set r;

	if ((ifp = find_ifconf(device)) == NULL) {
		dprintf(LOG_ERR, "interface %s not configured", ifp);
		exit(1);
	}

  restart:
	while(1) {
		reset_timer(ifp);

		if (gettimeofday(&finish, NULL) < 0) {
			dprintf(LOG_ERR, "gettimeofday failed");
			exit(1); /* XXX */
		}

		finish.tv_sec += ifp->retrans / 1000;
		finish.tv_usec += (ifp->retrans * 1000000) % 1000000;
		tvfix(&finish);

		while (1) {
			FD_ZERO(&r);
			FD_SET(insock, &r);

			if (gettimeofday(&w, NULL) < 0) {
				dprintf(LOG_ERR, "gettimeofday failed");
				exit(1); /* XXX */
			}
			w.tv_sec = finish.tv_sec - w.tv_sec;
			w.tv_usec = finish.tv_usec - w.tv_usec;
			if (w.tv_usec < 0) {
				w.tv_sec--;
				w.tv_usec += 1000000;
			}
			if (w.tv_sec < 0)
				ret = 0;
			else
				ret = select(insock + 1, &r, NULL, NULL, &w);

			switch (ret) {
			case -1:
				dprintf(LOG_ERR, "select");
				exit(1); /* XXX: signal case? */
			case 0:	/* timeout */
				ifp->timo++;
				if (ifp->max_retrans_cnt &&
				    ifp->timo > ifp->max_retrans_cnt) {
					dprintf(LOG_NOTICE, "client6_mainloop:"
						" no responses were received.");
					exit(0); /* XXX */
				}
				switch(ifp->state) {
				case DHCP6S_INIT:
					ifp->timo = 0;
					if ((ifp->flags & DHCIFF_INFO_ONLY))
						ifp->state = DHCP6S_INFOREQ;
					else
						ifp->state = DHCP6S_SOLICIT;
					set_timeoparam(ifp);
					break;
				case DHCP6S_SOLICIT:
				case DHCP6S_INFOREQ:
					client6_send(ifp, outsock);
					break;
				}
				break;
			default: /* received a packet */
				if ((ret = client6_recv(ifp)) == 0)
					goto sleep; /* done */
				if (ret < 0)
					continue;
				/* restart with a new state */
			}

			if (ret == 0) /* retransmission */
				break;
		}
	}

  sleep:
	client6_sleep();
	ifp->state = DHCP6S_INIT;
	set_timeoparam(ifp);
	goto restart;
}

/* sleep until an event to activiate myself occurs */
/* ARGSUSED */
void
client6_hup(sig)
	int sig;
{

	dprintf(LOG_INFO, "client6_hup: received a SIGHUP");
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

	dprintf(LOG_DEBUG, "client6_sleep: start sleeping");

	if (signal(SIGHUP, client6_hup) == SIG_ERR) {
		dprintf(LOG_WARNING,
			"client6_sleep: failed to set signal: %s",
			strerror(errno));
		/* XXX: assert? */
	}

  again:
	signaled = 0;
	FD_ZERO(&r);
	FD_SET(rtsock, &r);

	ret = select(rtsock + 1, &r, NULL, NULL, NULL);
	if (ret == -1) { 
		if (errno == EINTR && signaled) {
			dprintf(LOG_INFO,
				"client6_sleep: signal from a user received."
				" activate DHCPv6.");
			goto activate;
		}
		dprintf(LOG_WARNING,
			"client6_sleep: select was interrupted by an "
			"unexpected signal");
		goto again;	/* XXX: or assert? */
	}

	n = read(rtsock, msg, sizeof(msg)); /* would block here */
	if (n < 0) {
		dprintf(LOG_WARNING, "client6_sleep: read failed: %s",
			strerror(errno));
		goto again;
	}
	dprintf(LOG_DEBUG,
		"client6_sleep: received a routing message (len = %d)", n);

	lim = msg + n;
	for (rtm = (struct rt_msghdr *)msg;
	     rtm < (struct rt_msghdr *)lim;
	     rtm = (struct rt_msghdr *)(((char *)rtm) + rtm->rtm_msglen)) {
		/* just for safety */
		if (!rtm->rtm_msglen) {
			dprintf(LOG_WARNING, "client6_sleep: rtm_msglen is 0 "
				"(msgbuf=%p lim=%p rtm=%p)", msg, lim, rtm);
			break;
		}
		dprintf(LOG_DEBUG, "client6_sleep: message type=%d",
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

			dprintf(LOG_INFO,
				"client6_sleep: default router has changed. "
				"activate DHCPv6.");
			if ((gw = rti_info[RTAX_GATEWAY]) != NULL) {
				switch (gw->sa_family) {
				case AF_INET6:
					dprintf(LOG_INFO,
						"  new gateway: %s",
						addr2str(gw));
					break;
				case AF_LINK:
				{
					struct sockaddr_dl *sdl;
					char ifnambuf[IF_NAMESIZE];

					sdl = (struct sockaddr_dl *)gw;
					if (if_indextoname(sdl->sdl_index,
							   ifnambuf) != NULL) {
						dprintf(LOG_INFO,
							"  new default to %s",
							ifnambuf);
					}
					else {
						dprintf(LOG_INFO,
							"  new default to ?");
					}
					break;
				}
				}
			}

			goto activate;
		}
		else {
			dprintf(LOG_DEBUG,
				"client6_sleep: rtmsg add dst = %s, mask = %s",
				addr2str(dst), addr2str(mask));
		}
	}

	goto again;

  activate:
	/* stop the signal handler and wake up */
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		dprintf(LOG_WARNING,
			"client6_sleep: failed to reset signal: %s",
			strerror(errno));
	dprintf(LOG_DEBUG, "client6_sleep: activated");
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
		}
		else
			rti_info[i] = NULL;
	}
}

static void
client6_send(ifp, s)
	struct dhcp_if *ifp;
{
	char buf[BUFSIZ];
	struct sockaddr_in6 dst;
	int error;
	struct dhcp6 *dh6;
	struct dhcp6opt *opt;
	ssize_t len;

	dh6 = (struct dhcp6 *)buf;
	memset(dh6, 0, sizeof(*dh6));

	switch(ifp->state) {
	case DHCP6S_SOLICIT:
		dh6->dh6_msgtype = DH6_SOLICIT;
		break;
	case DHCP6S_INFOREQ:
		dh6->dh6_msgtype = DH6_INFORM_REQ;
		break;
	}
	ifp->xid = random() & DH6_XIDMASK;
	dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
	dh6->dh6_xid |= htonl(ifp->xid);
	len = sizeof(*dh6);

	/* client ID */
	opt = (struct dhcp6opt *)(dh6 + 1);
	opt->dh6opt_type = htons(DH6OPT_CLIENTID);
	opt->dh6opt_len = htons(client_duid.duid_len);
	len += sizeof(*opt) + client_duid.duid_len;
	if (len > sizeof(buf)) {
		dprintf(LOG_NOTICE, "internal buffer short for DUID");
		return;
	}
	memcpy((void *)(opt + 1), client_duid.duid_id, client_duid.duid_len);
	opt = (struct dhcp6opt *)(buf + len);

	/* rapid commit */
	if (ifp->state == DHCP6S_SOLICIT &&
	    (ifp->flags & DHCIFF_RAPID_COMMIT)) {
		len += sizeof(*opt);
		if (len > sizeof(buf)) {
			dprintf(LOG_NOTICE,
				"internal buffer short for rapid commit");
			return;
		}
		opt->dh6opt_type = htons(DH6OPT_RAPID_COMMIT);
		opt->dh6opt_len = 0;

		opt++;
	}

	switch (ifp->state) {
	case DHCP6S_SOLICIT:
	case DHCP6S_INFOREQ:
		dst = *sa6_allagent;
		dst.sin6_scope_id = ifp->linkid;
		break;
	}

	if (transmit_sa(s, (struct sockaddr *)&dst, 0, buf, len) != 0) {
		dprintf(LOG_ERR, "transmit failed");
		return;
	}
	
	dprintf(LOG_DEBUG, "send %s to %s", dhcpmsgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&dst));
}

static int
client6_recv(ifp)
	struct dhcp_if *ifp;
{
	int s = insock;		/* XXX */
	char rbuf[BUFSIZ];
	struct sockaddr_storage from;
	socklen_t fromlen;
	ssize_t len;
	struct dhcp6 *dh6;

	fromlen = sizeof(from);
	if ((len = recvfrom(s, rbuf, sizeof(rbuf), 0,
	    (struct sockaddr *)&from, &fromlen)) < 0) {
		dprintf(LOG_ERR, "recvfrom(inbound): %s", strerror(errno));
		return -1;
	}

	if (len < sizeof(*dh6)) {
		dprintf(LOG_INFO, "client6_recv: short packet");
		return -1;
	}

	dh6 = (struct dhcp6 *)rbuf;

	dprintf(LOG_DEBUG, "receive %s from %s", dhcpmsgstr(dh6->dh6_msgtype),
		addr2str((struct sockaddr *)&from));

	switch(dh6->dh6_msgtype) {
	case DH6_REPLY:
		/*
		 * we only expect reply messages when we've sent an
		 * information-request message or sent a solicit message
		 * with a rapid commit option.
		 */
		if (ifp->state == DHCP6S_INFOREQ ||
		    (ifp->state == DHCP6S_SOLICIT &&
		     (ifp->flags & DHCIFF_RAPID_COMMIT))) {
			client6_recvreply(ifp, dh6, len);
		} else {
			dprintf(LOG_INFO, "client6_recv: unexpected reply");
			return(-1);
		}
		break;
	}

	return(0);		/* we've done */
}

/*
 * 18.1.6. Receipt of Reply message in response to a Information-request
 * message
 */
static int
client6_recvreply(ifp, dh6, len)
	struct dhcp_if *ifp;
	struct dhcp6 *dh6;
	ssize_t len;
{
	char *cp;
	char buf[BUFSIZ];
	struct dhcp6opt *p, *ep, *np;
	int i;
	struct in6_addr in6;
	struct duid reply_duid;

	/*
	 * The ``transaction-ID'' field value MUST match the value we
	 * used in our Information-request message.
	 */
	if (ifp->xid != (ntohl(dh6->dh6_xid) & DH6_XIDMASK)) {
		dprintf(LOG_INFO, "client6_recvreply: XID mismatch");
		return -1;
	}

	/* option processing */

	p = (struct dhcp6opt *)(dh6 + 1);
	ep = (struct dhcp6opt *)((char *)dh6 + len);

	/* A Reply message must contain a Server ID option */
	if ((get_dhcp6_option(p, ep, DH6OPT_SERVERID, NULL)) < 0) {
		dprintf(LOG_INFO, "client6_recvreply: no server ID option");
		return -1;
	}

	/*
	 * DUID in the Client ID option (which must be contained for our
	 * client implementation) must match ours.
	 */
	if ((get_dhcp6_option(p, ep, DH6OPT_CLIENTID, &reply_duid)) < 0) {
		dprintf(LOG_INFO, "client6_recvreply: no client ID option");
		return -1;
	}
	if (reply_duid.duid_len != client_duid.duid_len ||
	    memcmp(reply_duid.duid_id, client_duid.duid_id,
		   client_duid.duid_len)) {
		dprintf(LOG_INFO, "client6_recvreply: client DUID mismatch");
		return -1;
	}

	while (p + 1 <= ep) {
		cp = (char *)(p + 1);
		np = (struct dhcp6opt *)(cp + ntohs(p->dh6opt_len));
		/* option length field overrun */
		if (np > ep)
			goto malformed;

		switch (ntohs(p->dh6opt_type)) {
		case DH6OPT_DNS:
			if (ntohs(p->dh6opt_len) % sizeof(in6) ||
			    ntohs(p->dh6opt_len) == 0)
				goto malformed;
			for (i = 0; i < ntohs(p->dh6opt_len); i += sizeof(in6)) {
				memcpy(&in6, &cp[i], sizeof(in6));
				fprintf(stderr, "nameserver %s\n",
				    inet_ntop(AF_INET6, &in6, buf, sizeof(buf)));
			}
			break;
		default:
			/* ignore */
			break;
		}

		p = np;
	}

	return 0;

 malformed:
	dprintf(LOG_INFO, "client6_recvreply: malformed option");
	return -1;
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
set_timeoparam(ifp)
	struct dhcp_if *ifp;
{
	ifp->retrans = 0;
	ifp->init_retrans = 0;
	ifp->max_retrans_cnt = 0;
	ifp->max_retrans_dur = 0;
	ifp->max_retrans_time = 0;

	switch(ifp->state) {
	case DHCP6S_SOLICIT:
		ifp->init_retrans = SOL_TIMEOUT;
		ifp->max_retrans_time = SOL_MAX_RT;
		break;
	case DHCP6S_INFOREQ:
		ifp->init_retrans = INF_TIMEOUT;
		ifp->max_retrans_time = INF_MAX_RT;
		break;
	}
}

static void
reset_timer(ifp)
	struct dhcp_if *ifp;
{
	long t;
	double n, r;
	char *statestr;

	/* XXX: should the random factor be calculated each time? */
	r = ((double)(random() % 2000) - 1000) / 1000;

	switch(ifp->state) {
	case DHCP6S_INIT:
		ifp->retrans = (random() % (MAX_SOL_DELAY - MIN_SOL_DELAY)) +
			MIN_SOL_DELAY;
		break;
	default:
		if (ifp->timo == 0)
			n = 2 * ifp->init_retrans + r * ifp->init_retrans;
		else {
			n = 2 * ifp->retrans + r * ifp->retrans;
			if (ifp->max_retrans_time &&
			    n > ifp->max_retrans_time) {
				n = ifp->max_retrans_time +
					r * ifp->max_retrans_time;
			}
		}
		ifp->retrans = (long)n;
		break;
	}

	switch(ifp->state) {
	case DHCP6S_INIT:
		statestr = "INIT";
		break;
	case DHCP6S_SOLICIT:
		statestr = "SOLICIT";
		break;
	case DHCP6S_INFOREQ:
		statestr = "INFOREQ";
		break;
	default:
		statestr = "???"; /* XXX */
		break;
	}

	dprintf(LOG_DEBUG, "reset timer for %s:, state=%s, timer=%ld",
		ifp->ifname, statestr, ifp->retrans);
}
