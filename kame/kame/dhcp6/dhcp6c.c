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
#include <sys/errno.h>
#include <sys/ioctl.h>
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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>

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

int debug = 0;
#define dprintf(x)	{ if (debug) fprintf x; }
char *device = NULL;

int insock;	/* inbound udp port */
int outsock;	/* outbound udp port */
TAILQ_HEAD(, servtab) servtab;

#if 0
#define MAXCALLBACK	30
static struct callback {
	int fd;
	pcap_t *cap;
	void (*func)();
} callbacks[MAXCALLBACK];
static int ncallbacks = 0;
static int maxfd = -1;

#define PCAP_TIMEOUT	100	/*ms*/
#endif

/* behavior constant */
#define SOLICIT_RETRY	2
#define REQUEST_RETRY	2

static void usage __P((void));
static void mainloop __P((void));
#if 0
void callback_register __P((int, pcap_t *, void (*)()));
#endif
static void client6_init __P((void));
static void client6_mainloop __P((void));
static void client6_findserv __P((void));
static int client6_getreply __P((struct servtab *));
static void client6_sendsolicit __P((int));
static int client6_recvadvert __P((int, struct servtab *));
static void client6_sendrequest __P((int, struct servtab *));
static int client6_recvreply __P((int, struct servtab *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	extern int optind;
	extern char *optarg;
	int ch;

	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "d")) != EOF) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		/*NOTREACHED*/
	}
	device = argv[0];

	mainloop();
	exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: dhcpc [-d] intface\n");
	exit(0);
}

static void
mainloop()
{
#if 0
	int error;
	u_char pktbuf[BUFSIZ];
	fd_set fds, fds0;
	int nfd;
	struct timeval tv;
	int i;
#endif

	client6_init();
	client6_mainloop();

#if 0
	FD_ZERO(&fds0);
	for (i = 0; i < ncallbacks; i++) {
		if (callbacks[i].cap)
			FD_SET(callbacks[i].cap->fd, &fds0);	/*XXX*/
		else if (callbacks[i].fd)
			FD_SET(callbacks[i].fd, &fds0);
	}
	while (1) {
		fds = fds0;
		if (debug) {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		} else {
			tv.tv_sec = 0;
			tv.tv_usec = PCAP_TIMEOUT * 1000;
		}
		nfd = select(maxfd + 1, &fds, NULL, NULL, &tv);
		switch (nfd) {
		case -1:
			err(1, "select");
			/*NOTREACHED*/
		case 0:
			/* timeout */
			dprintf((stderr, "timeout\n"));
			continue;
		}

		dprintf((stderr, "captured\n"));
		for (i = 0; i < ncallbacks; i++) {
			if (FD_ISSET(callbacks[i].fd, &fds0)) {
				if (callbacks[i].cap) {
					pcap_dispatch(callbacks[i].cap, 0,
						callbacks[i].func, pktbuf);
				} else if (callbacks[i].fd)
					(*callbacks[i].func)(callbacks[i].fd);
			}
		}
	}
#endif
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
		/*NOTREACHED*/
	}
	if (fd && cap) {
		errx(1, "internal error: both fd and cap are present");
		/*NOTREACHED*/
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
	int error;
	int ifidx;

	ifidx = if_nametoindex(device);
	if (ifidx == 0)
		errx(1, "if_nametoindex(%s)", device);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, DH6PORT_DOWNSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	insock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (insock < 0) {
		err(1, "socket(inbound)");
		/*NOTREACHED*/
	}
	if (bind(insock, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind(inbonud)");
		/*NOTREACHED*/
	}
	freeaddrinfo(res);

	hints.ai_flags = 0;
	error = getaddrinfo(NULL, DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	outsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (outsock < 0) {
		err(1, "socket(outbound)");
		/*NOTREACHED*/
	}
	if (setsockopt(outsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			&ifidx, sizeof(ifidx)) < 0) {
		err(1, "setsockopt(outbound, IPV6_MULTICAST_IF)");
		/*NOTREACHED*/
	}
	freeaddrinfo(res);

#if 0
	/* set interface to use */
	ifidx = if_nametoindex(device);
	if (!ifidx) {
		err(1, "if_nametoindex(%s)", device);
		/*NOTREACHED*/
	}
#endif

	TAILQ_INIT(&servtab);

#if 0
	callback_register(s, NULL, capture_dhcpc6);
#endif
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
client6_mainloop()
{
	struct servtab *p;
	char hbuf[BUFSIZ];

	client6_findserv();

	if (TAILQ_FIRST(&servtab) == NULL) {
		errx(1, "no server found");
		/*NOTREACHED*/
	}
	p = TAILQ_FIRST(&servtab);
	inet_ntop(AF_INET6, &p->st_serv, hbuf, sizeof(hbuf));
	dprintf((stderr, "primary server: pref=%u addr=%s\n",
		p->st_pref, hbuf));

	for (p = TAILQ_FIRST(&servtab); p; p = TAILQ_NEXT(p, st_list)) {
		if (client6_getreply(p) < 0)
			continue;
		break;
	}
}

static void
client6_addserv(p)
	struct servtab *p;
{
	struct servtab *q;

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
	struct servtab *p, *q;
	enum { WAIT, DELAY } mode;

	/* send solicit, wait for advert */
	timeo = 0;
	sendtime = time(NULL);
	delaytime = random_between(MIN_SOLICIT_DELAY, MAX_SOLICIT_DELAY);
	waittime = 0;
	while (1) {
		t = time(NULL);
		dprintf((stderr, "sendtime=%ld waittime=%d delaytime=%d\n",
			(long)sendtime, (int)waittime, (int)delaytime));
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
			/*NOTREACHED*/
		case 0:
			if (mode == WAIT && TAILQ_FIRST(&servtab) != NULL) {
				/* we have more than 1 reply and timeouted */
				return;
			}

			if (mode == WAIT) {
			} else {
				if (timeo >= SOLICIT_RETRY)
					return;

				dprintf((stderr, "send solicit\n"));
				client6_sendsolicit(outsock);
				timeo++;
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
			if (p->st_pref == 255)
				return;
			break;
		}
	}
}

static int
client6_getreply(p)
	struct servtab *p;
{
	struct timeval w;
	fd_set r;
	int timeo;
	int ret;

	/* sanity checks */
	if (IN6_IS_ADDR_MULTICAST(&p->st_relay)
	 || IN6_IS_ADDR_MULTICAST(&p->st_serv)) {
		return -1;
	}

	timeo = 0;
	while (1) {
		w.tv_sec = REPLY_MSG_TIMEOUT;
		w.tv_usec = 0;
		client6_sendrequest(outsock, p);
		FD_ZERO(&r);
		FD_SET(insock, &r);
		ret = select(insock + 1, &r, NULL, NULL, &w);
		switch (ret) {
		case -1:
			err(1, "select");
			/*NOTREACHED*/
		case 0:
			timeo++;
			if (timeo >= REQUEST_RETRY)
				return -1;
			break;
		default:
			if (client6_recvreply(insock, p) <0)
				return -1;
			return 0;
		}
	}

	return -1;
}

/* 5.2. Sending DHCP Solicit Messages */
static void
client6_sendsolicit(s)
	int s;
{
	char buf[BUFSIZ];
	struct dhcp6_solicit *dh6s;
	size_t len;
	const int firsttime = 1;
	struct in6_addr target;

	dh6s = (struct dhcp6_solicit *)buf;
	len = sizeof(*dh6s);
	memset(dh6s, 0, sizeof(*dh6s));
	dh6s->dh6sol_msgtype = DH6_SOLICIT;
	inet_pton(AF_INET6, "fe80::", &target, sizeof(target));
	if (getifaddr(&dh6s->dh6sol_cliaddr, device, &target, 10) != 0) {
		errx(1, "getifaddr failed");
		/*NOTREACHED*/
	}
#ifdef __KAME__
	dh6s->dh6sol_cliaddr.s6_addr[2] = 0;
	dh6s->dh6sol_cliaddr.s6_addr[3] = 0;
#endif
	if (firsttime) {
		/* erase any server state */
		dh6s->dh6sol_flags = DH6SOL_CLOSE;
	} else {
		/* set past agent addr into (struct in6_addr *)(dh6s + 1) */
		len += sizeof(struct in6_addr);
	}

	if (transmit(s, DH6ADDR_ALLAGENT, DH6PORT_UPSTREAM, 1, buf, len) != 0) {
		err(1, "transmit failed");
		/*NOTREACHED*/
	}
}

/* 5.3. Receiving DHCP Advertise Messages */
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

	memset(serv, 0, sizeof(*serv));

	fromlen = sizeof(from);
	if ((len = recvfrom(s, buf, sizeof(buf), 0,
			(struct sockaddr *)&from, &fromlen)) < 0) {
		err(1, "recvfrom(inbound)");
		/*NOTREACHED*/
	}

	if (len < sizeof(*dh6a))
		return -1;
	dh6a = (struct dhcp6_advert *)buf;
	if (dh6a->dh6adv_msgtype != DH6_ADVERT)
		return -1;
	serv->st_pref = dh6a->dh6adv_pref;
	if ((dh6a->dh6adv_flags & DH6ADV_SERVPRESENT) == 0)
		serv->st_serv = dh6a->dh6adv_relayaddr;
	else {
		serv->st_relay = dh6a->dh6adv_relayaddr;
		serv->st_serv = dh6a->dh6adv_serveraddr;
	}
	serv->st_llcli = dh6a->dh6adv_cliaddr;
	if (IN6_IS_ADDR_MULTICAST(&serv->st_serv)) {
		memset(serv, 0, sizeof(*serv));
		return -1;
	}

	/* extension handling */

	return 0;
}

/* 5.4. Sending DHCP Request Messages */
static void
client6_sendrequest(s, p)
	int s;
	struct servtab *p;
{
	int offlinkserv, offlink;
	struct sockaddr_in6 dst;
	struct addrinfo hints, *res;
	int error;
	struct in6_addr myaddr, target;
	char buf[BUFSIZ];
	size_t len;
	struct dhcp6_request *dh6r;
	int hlim;

	dh6r = (struct dhcp6_request *)buf;
	len = sizeof(*dh6r);
	memset(dh6r, 0, sizeof(*dh6r));
	dh6r->dh6req_msgtype = DH6_REQUEST;
	dh6r->dh6req_flags = DH6REQ_CLOSE | DH6REQ_REBOOT;
	dh6r->dh6req_xid = p->st_xid;
	inet_pton(AF_INET6, "fe80::", &target, sizeof(target));
	if (getifaddr(&dh6r->dh6req_cliaddr, device, &target, 10) != 0) {
		errx(1, "getifaddr failed");
		/*NOTREACHED*/
	}
#ifdef __KAME__
	dh6r->dh6req_cliaddr.s6_addr[2] = 0;
	dh6r->dh6req_cliaddr.s6_addr[3] = 0;
#endif
	memcpy(&dh6r->dh6req_relayaddr, &p->st_relay, sizeof(p->st_relay));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo("::", DH6PORT_UPSTREAM, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo: %s", gai_strerror(error));
		/*NOTREACHED*/
	}
	memcpy(&dst, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (!IN6_IS_ADDR_LINKLOCAL(&p->st_serv)) {
		offlinkserv = 1;

		/* is it possible to transmit packets to offlink dst? */
		offlink = 1;
		inet_pton(AF_INET6, "2000::", &target, sizeof(target));
		if (getifaddr(&myaddr, device, &target, 3) != 0) {
			inet_pton(AF_INET6, "fec0::", &target, sizeof(target));
			if (getifaddr(&myaddr, device, &target, 10) != 0)
				offlink = 0;
		}
	} else {
		offlink = 0;
		offlinkserv = 0;
	}
	if (!offlink) {
		inet_pton(AF_INET6, "fe80::", &target, sizeof(target));
		if (getifaddr(&myaddr, device, &target, 10) != 0) {
			errx(1, "getifaddr failed");
			/*NOTREACHED*/
		}
	}

	if (!offlinkserv) {
		memcpy(&dst.sin6_addr, &p->st_serv, sizeof(p->st_serv));
		dst.sin6_scope_id = if_nametoindex(device);
		hlim = 1;
	} else {
		if (offlink) {
			memcpy(&dst.sin6_addr, &p->st_serv, sizeof(p->st_serv));
			hlim = 0;
		} else {
			memcpy(&dst.sin6_addr, &p->st_relay,
				sizeof(p->st_relay));
			dst.sin6_scope_id = if_nametoindex(device);

			dh6r->dh6req_flags |= DH6REQ_SERVPRESENT;
			memcpy(dh6r + 1, &p->st_serv, sizeof(p->st_serv));
			len += sizeof(p->st_serv);
			hlim = 1;
		}
	}

	if (transmit_sa(s, (struct sockaddr *)&dst, hlim, buf, len) != 0) {
		err(1, "transmit failed");
		/*NOTREACHED*/
	}
}

/* 5.5. Receiving DHCP Reply Messages */
static int
client6_recvreply(s, serv)
	int s;
	struct servtab *serv;
{
	char buf[BUFSIZ];
	struct dhcp6_reply *dh6r;
	ssize_t len;
	struct sockaddr_storage from;
	socklen_t fromlen;
	char *cp, *ep;
	struct dhcp6_opt *p;
	u_int16_t code, elen;
	int i;

	fromlen = sizeof(from);
	if ((len = recvfrom(s, buf, sizeof(buf), 0,
			(struct sockaddr *)&from, &fromlen)) < 0) {
		err(1, "recvfrom(inbound)");
		/*NOTREACHED*/
	}

	if (len < sizeof(*dh6r))
		return -1;
	dh6r = (struct dhcp6_reply *)buf;
	if (dh6r->dh6rep_msgtype != DH6_REPLY)
		return -1;
	if (serv->st_xid != dh6r->dh6rep_xid)
		return -1;
	if ((dh6r->dh6rep_flagandstat & DH6REP_STATMASK) != 0)
		return -1;

	/* extension handling */
	cp = (char *)(dh6r + 1);
	if ((dh6r->dh6rep_flagandstat & DH6REP_CLIPRESENT) != 0)
		cp += sizeof(struct in6_addr);
	ep = buf + len;
	while (cp < ep) {
		code = ntohs(*(u_int16_t *)&cp[0]);
		if (code != 65535)
			elen = ntohs(*(u_int16_t *)&cp[2]);
		else
			elen = 0;
		p = dhcp6opttab_bycode(code);
		if (p == NULL) {
			printf("unknown, len=%d\n", len);
			cp += elen + 4;
			continue;
		}

		/* sanity check on length */
		switch (p->len) {
		case OL6_N:
			break;
		case OL6_16N:
			if (elen % 16 != 0)
				return -1;
			break;
		case OL6_Z:
			if (elen != 0)
				return -1;
			break;
		default:
			if (elen != p->len)
				return -1;
			break;
		}

		printf("%s, ", p->name);
		switch (p->type) {
		case OT6_V6:
			for (i = 0; i < elen; i += 16) {
				inet_ntop(AF_INET6, &cp[4 + i], buf,
					sizeof(buf));
				if (i != 0)
					printf(",");
				printf("%s", buf);
			}
			break;
		case OT6_STR:
			memset(&buf, 0, sizeof(buf));
			strncpy(buf, &cp[4], elen);
			printf("%s", buf);
			break;
		case OT6_NUM:
			printf("%d", (u_int32_t)ntohl(*(u_int32_t *)&cp[4]));
			break;
		default:
			for (i = 0; i < elen; i++)
				printf("%02x", cp[4 + i] & 0xff);
		}
		printf("\n");
		cp += len + 4;
	}

	return 0;
}
