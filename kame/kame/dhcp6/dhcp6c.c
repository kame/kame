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

#include <dhcp6.h>
#include <dhcp6opt.h>
#include <common.h>

struct servtab {
	TAILQ_ENTRY(servtab) st_list;
	u_int8_t st_pref;
	struct in6_addr st_llcli;
	struct in6_addr st_relay;
	struct in6_addr st_serv;
	u_int16_t st_xid;
};

#ifdef MEDIATOR
#ifndef MEDIATOR_CTRL_PORT
#define MEDIATOR_CTRL_PORT 13863
#endif
#ifndef MEDIATOR_CTRL_VERSION
#define MEDIATOR_CTRL_VERSION 1
#endif

/* control structure to communicate with mediator */
struct mediator_control_msg {
	int version;
	int lifetime;
	char serveraddr[128];
};
static struct mediator_control_msg mediator_msg;
#endif 

static int debug = 0;
static int signaled = 0;

char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
int rtsock;	/* routing socket */
TAILQ_HEAD(, servtab) servtab;

static struct in6_addr link_local_prefix, site_local_prefix, global_prefix;
#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

#if 0
#define MAXCALLBACK	30
static struct callback {
	int fd;
	pcap_t *cap;
	void (*func)();
} callbacks[MAXCALLBACK];
static int ncallbacks = 0;
static int maxfd = -1;
#endif

static u_int16_t current_solicit_id;
static struct in6_addr current_cliaddr;

#define MAX_SOLICIT_ID	0x1ff	/* all 1 in 9 bits */

/* behavior constant */
#define SOLICIT_RETRY	2
#define REQUEST_RETRY	10

static void usage __P((void));
#if 0
void callback_register __P((int, pcap_t *, void (*)()));
#endif
static void client6_init __P((void));
static void client6_mainloop __P((void));
static void client6_findserv __P((void));
static int client6_getreply __P((struct servtab *));
static void client6_sendsolicit __P((int, int));
static int client6_recvadvert __P((int, struct servtab *));
static void client6_sendrequest __P((int, struct servtab *));
static int client6_recvreply __P((int, struct servtab *));
static void client6_sleep __P((void));
void client6_hup __P((int));
static int sa2plen __P((struct sockaddr_in6 *));
static void get_rtaddrs __P((int, struct sockaddr *, struct sockaddr **));
static void tvfix __P((struct timeval *));

#define DHCP6C_PIDFILE "/var/run/dhcp6c.pid"

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

	client6_init();

	if (foreground == 0) {
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
		if (daemon(0, 0) < 0)
			err(1, "daemon");
	}

	setloglevel(debug);

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
client6_init()
{
	struct addrinfo hints;
	struct addrinfo *res;
	int error, on = 1;
	int ifidx;

	ifidx = if_nametoindex(device);
	if (ifidx == 0)
		errx(1, "if_nametoindex(%s)", device);

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

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		err(1, "socket(inbound)");
		/* NOTREACHED */
	}
	if (setsockopt(insock, SOL_SOCKET, SO_REUSEPORT,
		       &on, sizeof(on)) < 0) {
		err(1, "setsockopt(inbound, SO_REUSEPORT)");
		/* NOTREACHED */
	}
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind(inbonud)");
		/* NOTREACHED */
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		err(1, "socket(outbound)");
		/* NOTREACHED */
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		err(1, "setsockopt(outbound, IPV6_MULTICAST_IF)");
		/* NOTREACHED */
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on,
		       sizeof(on)) < 0) {
		err(1, "setsockopt(outsock, IPV6_MULTICAST_LOOP)");
		/* NOTREACHED */
	}
	/* make the socket write-only */
	if (shutdown(outsock, 0)) {
		err(1, "shutdown(outbound, 0)");
		/* NOTREACHED */
	}
	freeaddrinfo(res);

	TAILQ_INIT(&servtab);

	/* open a routing socket to watch the routing table */
	if ((rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
		err(1, "open a routing socket");
}

static void
client6_mainloop()
{
	struct servtab *p;

	do {
		client6_findserv();

		if (TAILQ_FIRST(&servtab)) {
			p = TAILQ_FIRST(&servtab);
			dprintf(LOG_DEBUG, "primary server: pref=%u addr=%s",
				p->st_pref, in6addr2str(&p->st_serv, 0));

			for (p = TAILQ_FIRST(&servtab); p;
			     p = TAILQ_NEXT(p, st_list)) {
				if (client6_getreply(p) < 0)
					continue;
				break;
			}
		} else
			dprintf(LOG_NOTICE, "no server found");

		client6_sleep();
	} while(1);
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
				"client6_sleep: signal from a user recieved."
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
client6_addserv(p)
	struct servtab *p;
{
	struct servtab *q;

	/* XXX: those two loops are a bit lengthy */
	for (q = TAILQ_FIRST(&servtab); q; q = TAILQ_NEXT(q, st_list)) {
		if (IN6_ARE_ADDR_EQUAL(&q->st_serv, &p->st_serv)) {
			dprintf(LOG_INFO, "client6_addserv: duplicated server "
				"(%s) found", in6addr2str(&p->st_serv, 0));
			free(p);
			return;
		}
	}
	for (q = TAILQ_FIRST(&servtab); q; q = TAILQ_NEXT(q, st_list)) {
		if (p->st_pref > q->st_pref) {
			TAILQ_INSERT_BEFORE(q, p, st_list);
			return;
		}
	}
	TAILQ_INSERT_TAIL(&servtab, p, st_list);
}

static void
client6_findserv()
{
	struct timeval w;
	fd_set r;
	int timeo;
	int ret;
	time_t sendtime, delaytime, waittime, t;
	struct servtab *p;
	enum { WAIT, DELAY } mode;

	/* send solicit, wait for advert */
	timeo = 0;
	sendtime = time(NULL);
	delaytime = random_between(MIN_SOLICIT_DELAY, MAX_SOLICIT_DELAY);
	waittime = 0;
	while (1) {
		t = time(NULL);
		dprintf(LOG_DEBUG, "sendtime=%ld waittime=%d delaytime=%d",
			(long)sendtime, (int)waittime, (int)delaytime);
		mode = WAIT;	/* to fake a nosiy compiler */
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
		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, &w);
		switch (ret) {
		case -1:
			err(1, "select");
			/* NOTREACHED */
		case 0:
			if (mode == WAIT && TAILQ_FIRST(&servtab) != NULL) {
				/* we have more than 1 reply and timeouted */
				return;
			}

			if (mode == WAIT) {
			} else {
				if (timeo >= SOLICIT_RETRY)
					return;

				dprintf(LOG_DEBUG, "send solicit");
				if (++current_solicit_id > MAX_SOLICIT_ID)
					current_solicit_id = 1;
				client6_sendsolicit(outsock,
						    current_solicit_id);
				++timeo;
				sendtime = time(NULL);
				delaytime *= 2;
				delaytime += random_between(MIN_SOLICIT_DELAY,
					MAX_SOLICIT_DELAY);
				waittime = ADV_CLIENT_WAIT;
			}
			break;
		default:
			p = (struct servtab *)malloc(sizeof(struct servtab));
			memset(p, 0, sizeof(*p));
			if (client6_recvadvert(insock, p) < 0) {
				free(p);
				break;
			}
			client6_addserv(p);

			/*
			 * XXX: we should hear more advertisements and
			 * choose the primary server. But currently, we just
			 * take the first server.
			 */
			return;
			break;
		}
	}
}

static int
client6_getreply(p)
	struct servtab *p;
{
	struct timeval w, finish;
	fd_set r;
	int timeo;
	int ret;
	long reply_msg_timeo_usec;

	/* sanity checks */
	if (IN6_IS_ADDR_MULTICAST(&p->st_relay)
	 || IN6_IS_ADDR_MULTICAST(&p->st_serv)) {
		dprintf(LOG_DEBUG,
			"client6_getreply: "
			"invlalid server (%s) or relay (%s)",
			in6addr2str(&p->st_serv, 0),
			in6addr2str(&p->st_relay, 0));
		return(-1);
	}

	timeo = 0;
	reply_msg_timeo_usec = REPLY_MSG_TIMEOUT * 100;
	if (gettimeofday(&finish, NULL) < 0)
		err(1, "gettimeofday");
	finish.tv_sec += reply_msg_timeo_usec / 1000000;
	finish.tv_usec += reply_msg_timeo_usec % 1000000;
	tvfix(&finish);
	client6_sendrequest(outsock, p);
	while (1) {
		/* 11.4.2. Time out and retransmission of Request Messages */
		FD_ZERO(&r);
		FD_SET(insock, &r);
		if (gettimeofday(&w, NULL) < 0)
			err(1, "gettimeofday");
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
			err(1, "select");
			/* NOTREACHED */
		case 0:
			timeo++;
			reply_msg_timeo_usec *= 2;
			if (timeo >= REQUEST_RETRY) {
				dprintf(LOG_NOTICE,
					"client6_getreply: no replies "
					"are received. give up.");
				return(-1);
			}
			/* re-compute timeout */
			if (gettimeofday(&finish, NULL) < 0)
				err(1, "gettimeofday");
			finish.tv_sec += reply_msg_timeo_usec / 1000000;
			finish.tv_usec += reply_msg_timeo_usec % 1000000;
			tvfix(&finish);
			client6_sendrequest(outsock, p);
			break;
		default:
			if (client6_recvreply(insock, p) < 0)
				continue;
			return(0);
		}
	}

	return(-1);
}

/* 10.3.1. Creation and sending of the Solicit message */
static void
client6_sendsolicit(s, solicitid)
	int s, solicitid;
{
	char buf[BUFSIZ];
	struct dhcp6_solicit *dh6s;
	size_t len;
	const int firsttime = 1;

	dh6s = (struct dhcp6_solicit *)buf;
	len = sizeof(*dh6s);
	memset(dh6s, 0, sizeof(*dh6s));
	dh6s->dh6sol_msgtype = DH6_SOLICIT;
	dh6s->dh6sol_plen_id = htons(solicitid & 0xffff);
	if (getifaddr(&dh6s->dh6sol_cliaddr, device, &link_local_prefix,
		      LINK_LOCAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
		errx(1, "getifaddr failed");
		/* NOTREACHED */
	}
	current_cliaddr = dh6s->dh6sol_cliaddr;

	if (firsttime) {	/* XXX: currently we have no cache */
		/* erase any server state */
		dh6s->dh6sol_flags = DH6SOL_CLOSE;
	}

	if (transmit(s, DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, 1, buf, len) != 0) {
		err(1, "transmit failed");
		/* NOTREACHED */
	}
}

/* 10.3.3. Receipt of Advertise messages */
static int
client6_recvadvert(s, serv)
	int s;
	struct servtab *serv;
{
	char buf[BUFSIZ];
	struct dhcp6_advert *dh6a;
	ssize_t len;
	struct sockaddr_storage from;
	socklen_t fromlen;
	u_int16_t solid;

	memset(serv, 0, sizeof(*serv));

	fromlen = sizeof(from);
	if ((len = recvfrom(s, buf, sizeof(buf), 0,
			(struct sockaddr *)&from, &fromlen)) < 0) {
		err(1, "recvfrom(inbound)");
		/* NOTREACHED */
	}

	if (len < sizeof(*dh6a))
		return(-1);
	dh6a = (struct dhcp6_advert *)buf;
	if (dh6a->dh6adv_msgtype != DH6_ADVERT)
		return(-1);

	/* 10.2. Advertise Message Validation */
	/*
	 * The ``Solicit-ID'' field value MUST match the value that
	 * we used in the Solicit message.
	 */
	memcpy(&solid, &dh6a->dh6adv_rsv_id, sizeof(solid));
	dprintf(LOG_DEBUG, "solicit ID: %d (expected %d)",
		DH6SOL_SOLICIT_ID(ntohs(solid)), current_solicit_id);
	if (DH6SOL_SOLICIT_ID(ntohs(solid)) != current_solicit_id) {
		dprintf(LOG_DEBUG, "client6_recvadvert: solicit ID mismatch");
		return(-1);
	}

	/*
	 * The ``client's link-local address'' field value MUST match
	 * the link-local address of the interface upon which we
	 * sent the Solicit message.
	 */
	if (!IN6_ARE_ADDR_EQUAL(&dh6a->dh6adv_cliaddr, &current_cliaddr)) {
		dprintf(LOG_DEBUG,
			"client6_recvadvert: client address mismatch");
		return(-1);
	}

	serv->st_pref = dh6a->dh6adv_pref;
	serv->st_relay = dh6a->dh6adv_relayaddr;
	serv->st_serv = dh6a->dh6adv_serveraddr;
	serv->st_llcli = dh6a->dh6adv_cliaddr;

	if (IN6_IS_ADDR_MULTICAST(&serv->st_serv)) { /* do we need this? */
		memset(serv, 0, sizeof(*serv));
		return(-1);
	}

	/* extension handling */

	return(0);
}

/* 11.4.1. Creation and sending of Request messages */
static void
client6_sendrequest(s, p)
	int s;
	struct servtab *p;
{
	int offlinkserv = 0, direct;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr myaddr;
	char buf[BUFSIZ];
	struct dhcp6_request *dh6r;
	const int firsttime = 1; /* currently we don't implement any cache */

	dh6r = (struct dhcp6_request *)buf;
	memset(dh6r, 0, sizeof(*dh6r));
	dh6r->dh6req_msgtype = DH6_REQUEST;

	/*
	 * Unless the Request message is created in response to a
	 * Reconfigure-init message, the client generates a transaction
	 * ID in the range of 1024--65535 and inserts this value in the
	 * ``transaction-ID'' field.
	 */
	p->st_xid = random_between(MIN_CLIENT_XID, MAX_CLIENT_XID);
	dh6r->dh6req_xid = htons(p->st_xid);
	if (getifaddr(&dh6r->dh6req_cliaddr, device, &link_local_prefix,
		      LINK_LOCAL_PLEN, 0, IN6_IFF_INVALID) != 0) {
		errx(1, "getifaddr failed");
		/* NOTREACHED */
	}
	p->st_llcli = dh6r->dh6req_cliaddr; /* we can override this */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	memcpy(&dst, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	/*
	 * Place the address of the destination server in the
	 * ``server-address'' field.
	 */
	dh6r->dh6req_serveraddr = p->st_serv;

	/*
	 * If the client is not on the same link as the destination server,
	 * place the appropriate relay's address in the ``relay-address''
	 * field.
	 */
	if (!IN6_IS_ADDR_LINKLOCAL(&p->st_serv)) {
		offlinkserv = 1;

		dh6r->dh6req_relayaddr = p->st_relay;
	}

	/* Set the C bit if this is the first request. */
	if (firsttime)
		dh6r->dh6req_flags |= DH6REQ_CLOSE;

	/* XXX: should we set the R bit as well? */

	/*
	 * If the client already has an IP address of sufficient scope to
	 * directly reach the server, then the client SHOULD unicast the
	 * Request to the server.  Otherwise, if the server is off-link,
	 * the client unicasts the Request message to the appropriate relay.
	 */
	if (offlinkserv) {
		/* check scope */
		if (getifaddr(&myaddr, device, &global_prefix, GLOBAL_PLEN,
			      0, IN6_IFF_INVALID) == 0 ||
		    (IN6_IS_ADDR_SITELOCAL(&p->st_serv) &&
		     getifaddr(&myaddr, device, &site_local_prefix,
			       SITE_LOCAL_PLEN, 0, IN6_IFF_INVALID)))
			direct = 1;
		else
			direct = 0;
	}
	else
		direct = 1;
	if (direct) {
		memcpy(&dst.sin6_addr, &p->st_serv, sizeof(p->st_serv));
		dst.sin6_scope_id = in6_addrscopebyif(&p->st_serv, device);
	}
	else {
		memcpy(&dst.sin6_addr, &p->st_relay, sizeof(p->st_relay));
		dst.sin6_scope_id = in6_addrscopebyif(&p->st_relay, device);
	}

	if (transmit_sa(s, (struct sockaddr *)&dst, 0,
			buf, sizeof(*dh6r)) != 0) {
		err(1, "transmit failed");
		/* NOTREACHED */
	}

	dprintf(LOG_DEBUG, "send request to %s",
		addr2str((struct sockaddr *)&dst));
		 
}

/* 11.4.3. Receipt of Reply message in response to a Request */
static int
client6_recvreply(s, serv)
	int s;
	struct servtab *serv;
{
	char rbuf[BUFSIZ], buf[BUFSIZ];
	struct dhcp6_reply *dh6r;
	ssize_t len;
	struct sockaddr_storage from;
	socklen_t fromlen;
	char *cp, *ep;
	struct dhcp6_opt *p;
	u_int16_t code, elen;
	int i;

	fromlen = sizeof(from);
	if ((len = recvfrom(s, rbuf, sizeof(rbuf), 0,
			(struct sockaddr *)&from, &fromlen)) < 0) {
		dprintf(LOG_ERR, "recvfrom(inbound): %s", strerror(errno));
		return(-1);
	}

	if (len < 1) {		/* we need at least 1 byte to check type */
		dprintf(LOG_WARNING, "relay6_react: short packet");
		return(-1);
	}

	dh6r = (struct dhcp6_reply *)rbuf;
	if (dh6r->dh6rep_msgtype != DH6_REPLY)
		return(-1);	/* should be siletly discarded */

	if (len < sizeof(*dh6r)) {
		dprintf(LOG_WARNING, "client6_recvreply: short packet (len=%d)",
			len);
		return(-1);
	}

	/* 11.2. Reply Message Validation */

	/*
	 * The ``transaction-ID'' field value MUST match the value we
	 * used in our Request (or Release) message.
	 */
	if (serv->st_xid != ntohs(dh6r->dh6rep_xid)) {
		dprintf(LOG_WARNING, "client6_recvreply: XID mismatch");
		return(-1);
	}

	/*
	 * The ``client's link-local address'' field value MUST match
	 * the link-local address of the interface upon which we
	 * sent in our Request (or Release) message.
	 */
	if (!IN6_ARE_ADDR_EQUAL(&dh6r->dh6rep_cliaddr, &serv->st_llcli)) {
		dprintf(LOG_WARNING,
			"client6_recvreply: client address mismatch");
		return(-1);
	}

	/*
	 * If the Reply message contains an authentication extension, then the
	 * messages MUST be correctly authenticated.
	 * XXX: not implemented yet.
	 */
	
	/*
	 * If the ``status'' field contains a non-zero value, 
	 * report the error status.
	 */
	if ((dh6r->dh6rep_flagandstat & DH6REP_STATMASK) != 0) {
		dprintf(LOG_WARNING,
			"client6_recvreply: status indicates an error (%d)",
			dh6r->dh6rep_flagandstat & DH6REP_STATMASK);
		return(-1);
	}

	/* extension handling */
	cp = (char *)(dh6r + 1);
	if ((dh6r->dh6rep_flagandstat & DH6REP_RELAYPRESENT) != 0)
		cp += sizeof(struct in6_addr);
	ep = rbuf + len;
	for (; cp < ep; cp += elen + 4) {
		if (cp + 4 > ep) {
			dprintf(LOG_NOTICE,
				"client6_recvreply: malformed extension");
			break;
		}

		code = ntohs(*(u_int16_t *)&cp[0]);
		if (code != 65535)
			elen = ntohs(*(u_int16_t *)&cp[2]);
		else
			elen = 0;
		if (cp + 4 + elen > ep) {
			dprintf(LOG_NOTICE,
				"client6_recvreply: malformed extension");
			break;
		}
		
		p = dhcp6opttab_bycode(code);
		if (p == NULL) {
			dprintf(LOG_NOTICE, "unknown, len=%d", len);
			continue;
		}

		/* sanity check on length */
		switch (p->len) {
		case OL6_N:
			break;
		case OL6_16N:
			if (elen % 16 != 0)
				return(-1);
			break;
		case OL6_Z:
			if (elen != 0)
				return(-1);
			break;
		default:
			if (elen != p->len)
				return(-1);
			break;
		}

		dprintf(LOG_DEBUG, "%s:", p->name);

		switch(code) {
#ifdef MEDIATOR
		case OC6_DNS:
		{
			struct sockaddr_in to_mediator;
			struct in6_addr in6;
			int s = -1;
			char *ap;

			if ( (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
				dprintf(LOG_WARNING,
					"client6_recvreply: socket: %s",
					strerror(errno));
				break;
			}

			bzero((char *)&to_mediator, sizeof(to_mediator));
			to_mediator.sin_family = AF_INET;
			to_mediator.sin_len = sizeof(to_mediator);
			to_mediator.sin_port= htons(MEDIATOR_CTRL_PORT);
			inet_aton("127.0.0.1", &to_mediator.sin_addr);

			memset(&mediator_msg, 0, sizeof(mediator_msg));
			mediator_msg.version = htonl(MEDIATOR_CTRL_VERSION);
			mediator_msg.lifetime = -1; /* XXX: never expire */

			for (ap = cp + 4; ap < cp + 4 + elen;
			     ap += sizeof(struct in6_addr)) {
				/*
				 * use a separate pointer to avoid alignment
				 * issues.
				 */
				memcpy(&in6, ap, sizeof(struct in6_addr));

				strlcpy(mediator_msg.serveraddr,
				    in6addr2str(&in6, 0),
				    sizeof(mediator_msg.serveraddr));
			       
				dprintf(LOG_DEBUG,
					"Notifing to mediator: server %s",
					mediator_msg.serveraddr);
				if (sendto(s, &mediator_msg,
					   sizeof(mediator_msg), 0,
					   (struct sockaddr *)(&to_mediator),
					   sizeof(to_mediator)) < 0) {
					dprintf(LOG_WARNING,
						"client6_recvreply: "
						"sendto mediator: %s",
						strerror(errno));
				}
			}
		}
		break;
#endif /* MEDIATOR */
		}

		switch (p->type) {
		case OT6_V6:
			for (i = 0; i < elen; i += 16) {
				inet_ntop(AF_INET6, &cp[4 + i], buf,
					sizeof(buf));
				if (i != 0)
					dprintf(LOG_DEBUG, ",");
				dprintf(LOG_DEBUG, "  %s", buf);
			}
			break;
		case OT6_STR:
			/*
			 * 15/12 drafts are silent about padding requirement,
			 * and string termination requirement for extensions.
			 * at IETF48 dhc session, author confirmed that:
			 * - no string termination character
			 * - no padding (= unaligned extensions)
			 */
			if (sizeof(buf) >= elen + 1) {
				/*
				 * do not use strcpy/strlcpy here, because
				 * padding requirement is unclear in spec.
				 */
				memset(&buf, 0, sizeof(buf));
				memcpy(buf, &cp[4], elen);
				buf[elen] = '\0';
			} else
				strlcpy(buf, "?", sizeof(buf));
			dprintf(LOG_DEBUG, "  %s", buf);
			break;
		case OT6_NUM:
			dprintf(LOG_DEBUG, "%d",
				(u_int32_t)ntohl(*(u_int32_t *)&cp[4]));
			break;
		default:
			/*
			 * 15/12 drafts are silent about padding requirement,
			 * and string termination requirement for extensions.
			 * at IETF48 dhc session, author confirmed that:
			 * - no string termination character
			 * - no padding (= unaligned extensions)
			 */
			for (i = 0; i < elen; i++)
				dprintf(LOG_DEBUG, "  %02x", cp[4 + i] & 0xff);
		}
	}

	return(0);
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
