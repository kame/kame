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

static int debug = 0;
static int signaled = 0;

char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
int rtsock;	/* routing socket */

static struct in6_addr link_local_prefix, site_local_prefix, global_prefix;
#define LINK_LOCAL_PLEN 10
#define SITE_LOCAL_PLEN 10
#define GLOBAL_PLEN 3

static u_int32_t current_xid;

/* behavior constant */
#define SOLICIT_RETRY	2
#define REQUEST_RETRY	10

static void usage __P((void));
static void client6_init __P((void));
static void client6_mainloop __P((void));
static int client6_getreply __P((void));
static void client6_sendinform __P((int));
static int client6_recvreply __P((int));
static void client6_sleep __P((void));
void client6_hup __P((int));
static int sa2plen __P((struct sockaddr_in6 *));
static void get_rtaddrs __P((int, struct sockaddr *, struct sockaddr **));
static void tvfix __P((struct timeval *));
static long retransmit_timer __P((long, long, long));
static ssize_t gethwid __P((char *, int, const char *));

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

	/* open a routing socket to watch the routing table */
	if ((rtsock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0)
		err(1, "open a routing socket");
}

static void
client6_mainloop()
{

	do {
		(void)client6_getreply();

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

static int
client6_getreply()
{
	struct timeval w, finish;
	fd_set r;
	int ret;
	int timeo;
	long retrans;

	timeo = 0;
	retrans = retransmit_timer(0, INF_TIMEOUT * 1000, INF_MAX_RT * 1000);
	if (gettimeofday(&finish, NULL) < 0)
		err(1, "gettimeofday");
	finish.tv_sec += retrans / 1000000;
	finish.tv_usec += retrans % 1000000;
	tvfix(&finish);
	client6_sendinform(outsock);
	while (1) {
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
			if (timeo >= REQUEST_RETRY) {
				dprintf(LOG_NOTICE,
					"client6_getreply: no replies "
					"were received. give up.");
				return(-1);
			}
			/* re-compute timeout */
			retrans = retransmit_timer(retrans,
			    INF_TIMEOUT * 1000, INF_MAX_RT * 1000);
			if (gettimeofday(&finish, NULL) < 0)
				err(1, "gettimeofday");
			finish.tv_sec += retrans / 1000000;
			finish.tv_usec += retrans % 1000000;
			tvfix(&finish);
			client6_sendinform(outsock);
			break;
		default:
			if (client6_recvreply(insock) < 0)
				continue;
			return 0;
		}
	}

	return -1;
}

/* 18.1.5. Creation and Transmission of Inform messages */
static void
client6_sendinform(s)
	int s;
{
	int offlinkserv = 0, direct;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr myaddr;
	char buf[BUFSIZ];
	struct dhcp6 *dh6;
	struct dhcp6opt *opt;
	const int firsttime = 1; /* currently we don't implement any cache */
	ssize_t len, l;
	char *p, *p0, *ep;

	dh6 = (struct dhcp6 *)buf;
	memset(dh6, 0, sizeof(*dh6));
	dh6->dh6_msgtype = DH6_INFORM_REQ;

	current_xid = random() & DH6_XIDMASK;
	dh6->dh6_xid &= ~ntohl(DH6_XIDMASK);
	dh6->dh6_xid |= htonl(current_xid);
	len = sizeof(*dh6);

	/* DUID */
	opt = (struct dhcp6opt *)(dh6 + 1);
	opt->dh6opt_type = htons(DH6OPT_DUID);
	p0 = p = (char *)(opt + 1);
	ep = buf + sizeof(buf);
	*(u_int16_t *)p = htons(1);	/* DUID type: time + hw addr */
	p += sizeof(u_int16_t);
	*(u_int32_t *)p = htonl(time(NULL) - 946684800); /* Jan 1, 2000 */
	p += sizeof(u_int32_t);
	l = gethwid(p, ep - p, device);
	if (l < 0) {
		errx(1, "client6_sendinform: could not get hwid");
		/* NOTREACHED */
	}
	p += l;
	opt->dh6opt_len = htons(p - p0);
	len += sizeof(*opt) + (p - p0);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/* NOTREACHED */
	}
	if (sizeof(dst) != res->ai_addrlen) {
		errx(1, "getaddrinfo: invalid size");
		/* NOTREACHED */
	}
	memcpy(&dst, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (transmit_sa(s, (struct sockaddr *)&dst, 0, buf, len) != 0) {
		err(1, "transmit failed");
		/* NOTREACHED */
	}

	dprintf(LOG_DEBUG, "send request to %s",
	    addr2str((struct sockaddr *)&dst));
		 
}

/* 18.1.6. Receipt of Reply message in response to a Inform message */
static int
client6_recvreply(s)
	int s;
{
	char rbuf[BUFSIZ], buf[BUFSIZ];
	struct dhcp6 *dh6;
	ssize_t len;
	struct sockaddr_storage from;
	socklen_t fromlen;
	char *cp;
	struct dhcp6opt *p, *ep, *np;
	u_int16_t code, elen;
	int i;
	struct in6_addr in6;

	fromlen = sizeof(from);
	if ((len = recvfrom(s, rbuf, sizeof(rbuf), 0,
	    (struct sockaddr *)&from, &fromlen)) < 0) {
		dprintf(LOG_ERR, "recvfrom(inbound): %s", strerror(errno));
		return -1;
	}

	if (len < sizeof(*dh6)) {
		dprintf(LOG_WARNING, "client6_recvreply: short packet");
		return -1;
	}

	dh6 = (struct dhcp6 *)rbuf;
	if (dh6->dh6_msgtype != DH6_REPLY)
		return -1;	/* should be siletly discarded */

	/*
	 * The ``transaction-ID'' field value MUST match the value we
	 * used in our Inform message.
	 */
	if (current_xid != (ntohl(dh6->dh6_xid) & DH6_XIDMASK)) {
		dprintf(LOG_WARNING, "client6_recvreply: XID mismatch");
		return -1;
	}

	p = (struct dhcp6opt *)(dh6 + 1);
	ep = (struct dhcp6opt *)(rbuf + len);
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
	dprintf(LOG_WARNING, "client6_recvreply: malformed option");
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

static long
retransmit_timer(cur, irt, mrt)
	long cur;
	long irt;
	long mrt;
{
	double n;
	double r;

	r = ((double)(random() % 2000) - 1000) / 1000;
	if (cur == 0)
		n = 2 * irt + r * irt;
	else {
		n = 2 * cur + r * cur;
		if (n > mrt)
			n = mrt + r * mrt;
	}
	return (long)n;
}

static ssize_t
gethwid(buf, len, ifname)
	char *buf;
	int len;
	const char *ifname;
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_dl *sdl;
	ssize_t l;

	if (getifaddrs(&ifap) < 0)
		return -1;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (len < 2 + sdl->sdl_alen)
			goto fail;
		*(u_int16_t *)&buf[0] = htons(sdl->sdl_type);
		memcpy(&buf[2], LLADDR(sdl), sdl->sdl_alen);
		l = sizeof(u_int16_t) + sdl->sdl_alen;
		freeifaddrs(ifap);
		return l;
	}

  fail:
	freeifaddrs(ifap);
	return -1;
}
