#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <dhcp6.h>
#include <common.h>

struct servtab {
	TAILQ_ENTRY(servtab) st_list;
	u_int32_t st_pref;
	struct in6_addr st_llcli;
	struct in6_addr st_relay;
	struct in6_addr st_serv;
};

int dump = 0;
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

static void usage __P((void));
static void mainloop __P((void));
#if 0
void callback_register __P((int, pcap_t *, void (*)()));
#endif
static int transmit __P((int, char *, char *, int, char *, size_t));
static void client6_init __P((void));
static void client6_mainloop __P((void));
static void client6_findserv __P((void));
static void client6_sendsolicit __P((int));
static int client6_recvadvert __P((int, struct servtab *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	extern int optind;
	extern char *optarg;
	int ch;

	srandom(time(NULL) & getpid());
	while ((ch = getopt(argc, argv, "dD")) != EOF) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'D':
			dump++;
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
	fprintf(stderr, "usage: dhcpc intface\n");
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

static int
getlifaddr(addr, ifnam)
	struct in6_addr *addr;
	char *ifnam;
{
	int s;
	unsigned int maxif;
	struct ifreq *iflist;
	struct ifconf ifconf;
	struct ifreq *ifr, *ifr_end;
	struct sockaddr_in6 sin6;
	int error;

#if 0
	maxif = if_maxindex() + 1;
#else
	maxif = 1;
#endif
	iflist = (struct ifreq *)malloc(maxif * BUFSIZ);	/* XXX */
	if (!iflist) {
		errx(1, "not enough core");
		/*NOTREACHED*/
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		err(1, "socket(SOCK_DGRAM)");
		/*NOTREACHED*/
	}
	memset(&ifconf, 0, sizeof(ifconf));
	ifconf.ifc_req = iflist;
	ifconf.ifc_len = maxif * BUFSIZ;	/* XXX */
	if (ioctl(s, SIOCGIFCONF, &ifconf) < 0) {
		err(1, "ioctl(SIOCGIFCONF)");
		/*NOTREACHED*/
	}
	close(s);

	/* Look for this interface in the list */
	error = ENOENT;
	ifr_end = (struct ifreq *) (ifconf.ifc_buf + ifconf.ifc_len);
	for (ifr = ifconf.ifc_req;
	     ifr < ifr_end;
	     ifr = (struct ifreq *) ((char *) &ifr->ifr_addr
				    + ifr->ifr_addr.sa_len)) {
		if (strcmp(ifnam, ifr->ifr_name) != 0)
			continue;
		if (ifr->ifr_addr.sa_family != AF_INET6)
			continue;
		memcpy(&sin6, &ifr->ifr_addr, ifr->ifr_addr.sa_len);
		if (!IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
			continue;
		memcpy(addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
		error = 0;
		break;
	}

	free(iflist);
	close(s);
	return error;
}

static int
transmit(s, addr, port, hlim, buf, len)
	int s;
	char *addr;
	char *port;
	int hlim;
	char *buf;
	size_t len;
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, port, &hints, &res);
	if (error) {
		errx(1, "getaddrinfo(%s): %s", addr, gai_strerror(error));
		/*NOTREACHED*/
	}
	if (res->ai_next) {
		errx(1, "getaddrinfo(%s): %s", addr,
			"resolved to multiple addrs");
		/*NOTREACHED*/
	}

	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hlim,
			sizeof(hlim)) < 0) {
		err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
		/*NOTREACHED*/
	}

	error = sendto(s, buf, len, 0, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);
	return (error != len) ? -1 : 0;
}

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
	client6_findserv();
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
	struct servtab *st = NULL;
	struct servtab *p, *q;
	enum { WAIT, DELAY } mode;

	/* send solicit, wait for advert */
	timeo = 0;
	sendtime = time(NULL);
	delaytime = MIN_SOLICIT_DELAY;
	delaytime += (MAX_SOLICIT_DELAY - MIN_SOLICIT_DELAY)
		* (random() & 0xff) / 0xff;
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
			if (mode == WAIT && st) {
				/* we have more than 1 reply, receive timeout */
				goto found;
			}

			if (mode == WAIT) {
			} else {
				if (timeo >= SOLICIT_RETRY)
					goto found;

				dprintf((stderr, "send solicit\n"));
				client6_sendsolicit(outsock);
				timeo++;
				sendtime = time(NULL);
				delaytime *= 2;
				delaytime += (MAX_SOLICIT_DELAY - MIN_SOLICIT_DELAY)
					* (random() & 0xff) / 0xff;
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
			if (p->st_pref == ~0)
				goto found;
			break;
		}
	}

found:
	p = TAILQ_FIRST(&servtab);
	if (p == NULL) {
		errx(1, "no dhcp6 server found");
		/*NOTREACHED*/
	}
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

	dh6s = (struct dhcp6_solicit *)buf;
	len = sizeof(*dh6s);
	memset(dh6s, 0, sizeof(*dh6s));
	dh6s->dh6sol_msgtype = DH6_SOLICIT;
	if (getlifaddr(&dh6s->dh6sol_cliaddr, device) != 0) {
		errx(1, "getlifaddr failed");
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
	if ((dh6a->dh6adv_flags & DH6ADV_SERVPREF) == 0) {
		serv->st_pref = ~0;
		if ((dh6a->dh6adv_flags & DH6ADV_SERVPRESENT) == 0)
			serv->st_serv = dh6a->dh6adv_relayaddr;
		else {
			serv->st_relay = dh6a->dh6adv_relayaddr;
			serv->st_serv = dh6a->dh6adv_serveraddr;
		}
		serv->st_llcli = dh6a->dh6adv_cliaddr;
	} else {
		struct dhcp6_advert_pref *dh6ap;
		dh6ap = (struct dhcp6_advert_pref *)dh6a;
		serv->st_pref = ntohl(dh6ap->dh6adv_pref);
		if ((dh6ap->dh6adv_flags & DH6ADV_SERVPRESENT) == 0)
			serv->st_serv = dh6ap->dh6adv_relayaddr;
		else {
			serv->st_relay = dh6ap->dh6adv_relayaddr;
			serv->st_serv = dh6ap->dh6adv_serveraddr;
		}
		serv->st_llcli = dh6ap->dh6adv_cliaddr;
	}
	if (IN6_IS_ADDR_MULTICAST(&serv->st_serv)) {
		memset(serv, 0, sizeof(*serv));
		return -1;
	}

	/* extension handling */

	return 0;
}
