/*	$KAME: mdnsd.c,v 1.61 2004/12/09 02:18:26 t-momose Exp $	*/

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
#include <sys/param.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#if __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <syslog.h>
#include <signal.h>

#include "mdnsd.h"
#include "db.h"
#include "mediator_compat.h"
#include "pathnames.h"

u_int16_t dnsid;
const char *srcport = "53";
const char *dstport = DNS_PORT;
const char *mdstport = MDNS_PORT;
const char *intface = NULL;
int family = PF_UNSPEC;
static char hostnamebuf[MAXHOSTNAMELEN];
const char *hostname = NULL;
static int mcasthops6 = 1;
static int mcastloop6 = 0;
static unsigned char mcasthops4 = 1;
static unsigned char mcastloop4 = 0;
int dflag = 0;
int fflag = 0;
int lflag = 0;
struct timeval hz = { 1, 0 };	/* timeout every 1 second */
static int mflag = 0;
int Nflag = 0;
const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
int signo = 0;
int dormantcount = 5;
int dormanttime = 5;

int main __P((int, char **));
static void usage __P((void));
static int getsock __P((int, const char *, const char *, int, int,
	enum sdtype));
static int getsock0 __P((const struct addrinfo *));
static int join __P((int, int, const char *));
static int join0 __P((int, const struct addrinfo *));
static int setif __P((int, int, const char *));
static int iscanon __P((const char *));
static RETSIGTYPE sighandler __P((int));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	int ready4, ready6;
	struct sockdb *sd, *snext;
	int nsock;

	while ((ch = getopt(argc, argv, "46Dfh:i:lmNp:P:r:")) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'D':
			dflag++;
			break;
		case 'f':
			fflag++;
			break;
		case 'h':
			if (iscanon(optarg) == 0) {
				errx(1, "%s: not a canonical name", optarg);
				/*NOTREACHED*/
			}
			hostname = optarg;
			break;
		case 'i':
			if (if_nametoindex(optarg) == 0) {
				errx(1, "%s: invalid interface", optarg);
				/*NOTREACHED*/
			}
			intface = optarg;
			break;
		case 'l':
			lflag++;
			break;
		case 'm':
			mflag++;
			break;
		case 'N':
			if (geteuid() != 0) {
				errx(1, "must be root to use -N");
				/*NOTREACHED*/
			}
			Nflag++;
			break;
		case 'p':
			srcport = optarg;
			break;
		case 'P':
			mdstport = optarg;
			mcastloop4 = 1;
			mcastloop6 = 1;
			break;
		case 'r':
			dstport = optarg;
			break;
		default:
			usage();
			exit(1);
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (!intface) {
		usage();
		exit(1);
		/*NOTREACHED*/
	}

	while (argc-- > 0) {
		if (addserv(*argv, -1, "arg") != 0) {
			errx(1, "%s: failed to add it to db", *argv);
			/*NOTREACHED*/
		}
		argv++;
	}
	if (LIST_FIRST(&nsdb) == NULL) {
		errx(1, "no DNS server to contact");
		/*NOTREACHED*/
	}

#ifdef HAVE_ARC4RADOM
	dnsid = arc4random() & 0xffff;
#else
	srandom(time(NULL) ^ getpid());
	dnsid = random() & 0xffff;
#endif

	if (!hostname) {
		if (gethostname(hostnamebuf, sizeof(hostnamebuf)) != 0) {
			err(1, "gethostname");
			/*NOTREACHED*/
		}

		/* append trailing dot to make it look like FQDN */
		if (strlen(hostnamebuf) > 0 &&
		    hostnamebuf[strlen(hostnamebuf) - 1] != '.' &&
		    strlen(hostnamebuf) + 2 < sizeof(hostnamebuf)) {
			char *p;
			p = hostnamebuf + strlen(hostnamebuf);
			*p++ = '.';
			*p = '\0';
		}
		if (iscanon(hostnamebuf) == 0) {
			errx(1, "%s: hostname is not a canonical name",
			    hostnamebuf);
			/*NOTREACHED*/
		}

		hostname = hostnamebuf;
	}
	dprintf("hostname=\"%s\"\n", hostname);

	if (!fflag) {
		daemon(0, 0);
		syslog(LOG_INFO, "started\n");
	} else
		dprintf("started\n");

	if (getsock(family, NULL, srcport, SOCK_DGRAM, AI_PASSIVE,
	    S_MULTICAST) != 0) {
		syslog(LOG_ERR, "getsock: %m");
		exit(1);
		/*NOTREACHED*/
	}
	if (LIST_FIRST(&sockdb) == NULL) {
		syslog(LOG_ERR, "no socket");
		exit(1);
		/*NOTREACHED*/
	}

	if (getsock(family, NULL, "0", SOCK_DGRAM, AI_PASSIVE, S_UNICAST)
	    != 0) {
		syslog(LOG_ERR, "getsock: %m");
		exit(1);
		/*NOTREACHED*/
	}

	if (getsock(family, NULL, srcport, SOCK_STREAM, AI_PASSIVE, S_TCP)
	    != 0) {
		syslog(LOG_ERR, "getsock: %m");
		exit(1);
		/*NOTREACHED*/
	}

	if (getsock(AF_INET6, "::", NULL, SOCK_RAW, AI_PASSIVE, S_ICMP6)
	    != 0) {
		syslog(LOG_ERR, "getsock: %m");
		exit(1);
		/*NOTREACHED*/
	}

	if (mflag) {
		if (getsock(AF_INET, NULL, MEDIATOR_CTRL_PORT, SOCK_DGRAM, 0,
		    S_MEDIATOR) != 0) {
			syslog(LOG_ERR, "getsock(mediator): %m");
			exit(1);
			/*NOTREACHED*/
		}
	}

	ready4 = ready6 = 0;
	nsock = 0;
	for (sd = LIST_FIRST(&sockdb); sd; sd = snext) {
		snext = LIST_NEXT(sd, link);
		nsock++;

		switch (sd->type) {
		case S_MEDIATOR:
		case S_UNICAST:
		case S_TCP:
			continue;
		case S_MULTICAST:
		case S_ICMP6:
			break;
		}

		switch (sd->af) {
		case AF_INET6:
			ready6++;
			if (join(sd->s, sd->af, MDNS_GROUP6) < 0) {
				/*
				 * don't make it fatal error, as we'll see join
				 * failure if the kernel is v4/v6 dual stack
				 * and there's no valid IPv6 global address.
				 */
				warn("join");
				close(sd->s);
				delsockdb(sd);
				continue;
			}
			if (setif(sd->s, sd->af, intface) < 0) {
				syslog(LOG_ERR, "interface %s unusable",
				    intface);
				exit(1);
				/*NOTREACHED*/
			}
			break;
		case AF_INET:
			ready4++;
			if (join(sd->s, sd->af, MDNS_GROUP4) < 0) {
				/*
				 * don't make it fatal error, as we'll see join
				 * failure if the kernel is v4/v6 dual stack
				 * and there's no valid IPv4 global address.
				 */
				warn("join");
				close(sd->s);
				delsockdb(sd);
				continue;
			}
			if (setif(sd->s, sd->af, intface) < 0) {
				syslog(LOG_ERR, "interface %s unusable",
				    intface);
				exit(1);
				/*NOTREACHED*/
			}
			break;
		}
	}

	if (ready4)
		(void)addserv(MDNS_GROUP4, -1, "mcast");
	if (ready6)
		(void)addserv(MDNS_GROUP6, -1, "mcast");

	signal(SIGUSR1, sighandler);

	send_updates();

	mainloop();
	exit(0);
}

static void
usage()
{

	fprintf(stderr,
"usage: mdnsd [-46DflmN] [-h hostname] [-p srcport] [-P dstport]\n"
"             [-r relayport] -i iface [server...]\n");
}

static int
getsock(af, host, serv, socktype, flags, stype)
	int af;
	const char *host;
	const char *serv;
	int socktype, flags;
	enum sdtype stype;
{
	struct addrinfo hints, *res, *ai;
	int error;
	struct sockdb *sd;
	int s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = socktype;
	if (stype == S_ICMP6)
		hints.ai_protocol = IPPROTO_ICMPV6;
	hints.ai_flags = flags | AI_NUMERICHOST;
	error = getaddrinfo(host, serv, &hints, &res);
	if (error) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		s = getsock0(ai);
		if (s < 0)
			continue;
		sd = newsockdb(s, ai->ai_family);
		if (sd == NULL) {
			close(s);
			continue;
		}
		sd->type = stype;
		dprintf("sock %d type %d\n", sd->s, sd->type);
	}

	freeaddrinfo(res);
	return 0;
}

static int
getsock0(ai)
	const struct addrinfo *ai;
{
	int s;
	const int yes = 1;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	if (dflag &&
	    getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf), niflags) == 0) {
		dprintf("getsock0: %s %s\n", hbuf, sbuf);
	}

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s < 0) {
		dprintf("socket: %s\n", strerror(errno));
		return -1;
	}
#ifdef IPV6_V6ONLY
	if (ai->ai_family == AF_INET6) {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
		    &yes, sizeof(yes)) < 0)
			err(1, "setsockopt(IPV6_V6ONLY)");
	}
#endif
	if (ai->ai_socktype == SOCK_STREAM || ai->ai_socktype == SOCK_DGRAM)
		if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			dprintf("bind: %s\n", strerror(errno));
			close(s);
			return -1;
		}
	if (ai->ai_socktype == SOCK_STREAM && listen(s, 5) < 0) {
		dprintf("listen: %s\n", strerror(errno));
		return -1;
	}

	switch (ai->ai_family) {
	case AF_INET6:
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		    &mcasthops6, sizeof(mcasthops6)) < 0)
			err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		    &mcastloop6, sizeof(mcastloop6)) < 0)
			err(1, "setsockopt(IPV6_MULTICAST_LOOP)");
		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
		    &yes, sizeof(yes)) < 0)
			err(1, "setsockopt(SO_REUSEPORT)");
#ifdef IPV6_USE_MIN_MTU
		if (setsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU,
		    &yes, sizeof(yes)) < 0)
			err(1, "setsockopt(IPV6_USE_MIN_MTU)");
#endif
		break;
	case AF_INET:
		if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
		    &mcasthops4, sizeof(mcasthops4)) < 0)
			err(1, "setsockopt(IP_MULTICAST_TTL)");
		if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
		    &mcastloop4, sizeof(mcastloop4)) < 0)
			err(1, "setsockopt(IP_MULTICAST_LOOP)");
		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
		    &yes, sizeof(yes)) < 0)
			err(1, "setsockopt(SO_REUSEPORT)");
		break;
	}

	return s;
}

static int
join(s, af, group)
	int s;
	int af;
	const char *group;
{
	struct addrinfo hints, *res, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(group, "0", &hints, &res) != 0)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		if (join0(s, ai) < 0)
			return -1;
	}
	freeaddrinfo(res);

	return 0;
}

static int
join0(s, ai)
	int s;
	const struct addrinfo *ai;
{
	struct ip_mreq mreq4;
	struct ipv6_mreq mreq6;

	switch (ai->ai_family) {
	case AF_INET6:
		memset(&mreq6, 0, sizeof(mreq6));
		mreq6.ipv6mr_interface = if_nametoindex(intface);
		if (mreq6.ipv6mr_interface == 0) {
			errno = EINVAL;
			return -1;
		}
		memcpy(&mreq6.ipv6mr_multiaddr,
		    &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		    sizeof(mreq6.ipv6mr_multiaddr));
		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
		    sizeof(mreq6)) != 0) {
			return -1;
		}
		break;
	case AF_INET:
		memset(&mreq4, 0, sizeof(mreq4));
		mreq4.imr_multiaddr =
		    ((struct sockaddr_in *)ai->ai_addr)->sin_addr;
		if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4,
		    sizeof(mreq4)) != 0) {
			return -1;
		}
		break;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	return 0;
}

static int
setif(s, af, iface)
	int s;
	int af;
	const char *iface;
{
	unsigned int outif;
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sin;
	int ret;

	switch (af) {
	case AF_INET6:
		outif = if_nametoindex(intface);
		if (outif == 0) {
			errno = EINVAL;
			return -1;
		}
		return setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		    &outif, sizeof(outif));
	case AF_INET:
		if (getifaddrs(&ifap) != 0)
			return -1;
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			if (strcmp(ifa->ifa_name, iface) != 0)
				continue;
			if ((ifa->ifa_flags & IFF_UP) == 0)
				continue;
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;

			break;
		}
		if (ifa == NULL) {
			freeifaddrs(ifap);
			errno = EADDRNOTAVAIL;
			return -1;
		}
		sin = (struct sockaddr_in *)ifa->ifa_addr;
		ret = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
		    &sin->sin_addr, sizeof(sin->sin_addr));
		freeifaddrs(ifap);
		return ret;
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
}

static int
iscanon(n)
	const char *n;
{
	const char *p;
	int dot;

	if (strlen(n) == 0)
		return 0;
	if (n[strlen(n) - 1] != '.')
		return 0;

	/* require at least three dots: host.baa.com. */
	dot = 0;
	for (p = n; *p; p++) {
		if (*p == '.')
			dot++;
	}
	if (dot < 3)
		return 0;

	/* but no two subsequent dots */
	if (strstr(n, ".."))
		return 0;

	return 1;
}

int
addserv(n, ttl, comment)
	const char *n;
	int ttl;
	const char *comment;
{
	struct addrinfo hints, *res;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct nsdb *ns;
	int multicast;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if ((error = getaddrinfo(n, "0", &hints, &res)) != 0)
		return -1;
#if 0
	if (res->ai_next) {
		freeaddrinfo(res);
		return -1;
	}
#endif
	switch (res->ai_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)res->ai_addr;
		multicast = IN_MULTICAST(ntohl(sin->sin_addr.s_addr)) ? 1 : 0;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)res->ai_addr;
		multicast = IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr) ? 1 : 0;
		break;
	default:
		multicast = 0;
		break;
	}
	freeaddrinfo(res);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(n, multicast ? mdstport : dstport, &hints, &res) != 0)
		return -1;
#if 0
	if (res->ai_next) {
		freeaddrinfo(res);
		return -1;
	}
#endif

	ns = newnsdb(res->ai_addr, res->ai_addrlen, comment);
	if (ns == NULL) {
		freeaddrinfo(res);
		return -1;
	}
	ns->type = multicast ? N_MULTICAST : N_UNICAST;
	if (ttl < 0) {
		ns->expire.tv_sec = -1;
		ns->expire.tv_usec = -1;
	} else {
		gettimeofday(&ns->expire, NULL);
		ns->expire.tv_sec += ttl;
	}

	dprintf("added server %s\n", n);

	freeaddrinfo(res);
	return 0;
}

int
ismyaddr(sa, salen)
	const struct sockaddr *sa;
	int salen;
{
	struct sockaddr_storage ss[2];
	u_int32_t scope[2], loscope;
	struct ifaddrs *ifap, *ifa;
	int ret;
	char h1[NI_MAXHOST], h2[NI_MAXHOST];
	char p[NI_MAXSERV];
	const int niflag = NI_NUMERICHOST | NI_NUMERICSERV;

	if (salen > sizeof(ss[0]))
		return 0;

	memcpy(&ss[0], sa, salen);
	scope[0] = 0;
	loscope = if_nametoindex("lo0");	/*XXX*/
#ifdef __KAME__
	if (((struct sockaddr *)&ss[0])->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&ss[0];
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr)) {
			*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] = 0;
			scope[0] = sin6->sin6_scope_id;
			sin6->sin6_scope_id = 0;
		}
	}
#endif
	h1[0] = h2[0] = '\0';
	if (getnameinfo((struct sockaddr *)&ss[0], salen, h1, sizeof(h1),
	    p, sizeof(p), niflag) != 0)
		return 0;
#if 1	/*just for experiment - to run two servers on a single node*/
	if (strcmp(p, dstport) == 0)
		return 0;
#endif

	if (getifaddrs(&ifap) != 0)
		return 0;
	ret = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != sa->sa_family)
			continue;
#ifdef HAVE_SA_LEN
		if (ifa->ifa_addr->sa_len != salen ||
		    ifa->ifa_addr->sa_len > sizeof(ss[1])) {
			continue;
		}
#else
		/*
		 * We assume that sa_len is the same if sa_family is the same,
		 * however, it is not a safe assumption to make, so we
		 * check if sa_family is the ones we know of.
		 */
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			continue;
		}
#endif
		memcpy(&ss[1], ifa->ifa_addr, salen);
		scope[1] = 0;
#ifdef __KAME__
		if (((struct sockaddr *)&ss[1])->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)&ss[1];
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
			    IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr)) {
				scope[1] = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
				sin6->sin6_addr.s6_addr[2] = 0;
				sin6->sin6_addr.s6_addr[3] = 0;
			}
		}
#endif
		if (getnameinfo((struct sockaddr *)&ss[1], salen,
		    h2, sizeof(h2), NULL, 0, niflag) != 0)
			continue;
		if (strcmp(h1, h2) != 0)
			continue;
		/*
		 * due to traditional BSD loopback packet handling,
		 * it is possible to get packet from loopback interface
		 * instead of real interface.
		 */
		if (scope[0] != scope[1] && scope[0] != loscope)
			continue;

		ret = 1;
		break;
	}

	freeifaddrs(ifap);
	return ret;
}

static RETSIGTYPE
sighandler(sig)
	int sig;
{
	signo = sig;
}

/*
 * NOTE: ctime(3) appends \n to output
 */
void
status()
{
	FILE *fp;
	time_t t;
	struct nsdb *ns;
	struct sockdb *sd;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	const char *p;
	struct sockaddr_storage ss;
	int sslen;

	if (fflag)
		fp = stderr;
	else
		fp = fopen(_PATH_DUMP, "a");
	if (fp == NULL)
		return;

	t = time(NULL);
	fprintf(fp, "mdnsd status dump at %s", ctime(&t));
	fprintf(fp, "\n");

	fprintf(fp, "DNS servers:\n");
	for (ns = LIST_FIRST(&nsdb); ns; ns = LIST_NEXT(ns, link)) {
		if (getnameinfo(ns->addr, ns->addrlen,
		    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), niflags) != 0) {
			strlcpy(hbuf, "invalid", sizeof(hbuf));
			strlcpy(sbuf, "invalid", sizeof(sbuf));
		}
		switch (ns->type) {
		case N_UNICAST:
			p = "unicast";
			break;
		case N_MULTICAST:
			p = "multicast";
			break;
		default:
			p = "invalid type";
			break;
		}
		fprintf(fp, "%*s%s port %s: %s (%s)\n", 4, "", hbuf, sbuf,
		    ns->comment, p);

#if 0
		fprintf(fp, "%*sprio %d", 6, "", ns->prio);
		t = (time_t)ns->expire.tv_sec;
		if (t)
			fprintf(fp, " expire %s", ctime(&t));
		else
			fprintf(fp, " expire %s", "never\n");
#endif
	}
	fprintf(fp, "\n");

	fprintf(fp, "sockets:\n");
	for (sd = LIST_FIRST(&sockdb); sd; sd = LIST_NEXT(sd, link)) {
		sslen = sizeof(ss);
		if (getsockname(sd->s, (struct sockaddr *)&ss, &sslen) < 0) {
			fprintf(fp, "%*s(invalid)\n", 4, "");
			continue;
		}
		if (getnameinfo((struct sockaddr *)&ss, sslen,
		    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), niflags) != 0) {
			strlcpy(hbuf, "invalid", sizeof(hbuf));
			strlcpy(sbuf, "invalid", sizeof(sbuf));
		}
		switch (sd->type) {
		case S_UNICAST:
			p = "unicast";
			break;
		case S_MULTICAST:
			p = "multicast";
			break;
		case S_MEDIATOR:
			p = "mediator";
			break;
		case S_TCP:
			p = "tcp";
			break;
		default:
			p = "invalid type";
			break;
		}
		fprintf(fp, "%*s%s port %s (%s)\n", 4, "", hbuf, sbuf, p);
	}

	fprintf(fp, "\n");

	if (!fflag)
		fclose(fp);
}

int
#if __STDC__
dprintf(const char *fmt, ...)
#else
dprintf(fmt, va_alist)
	char *fmt;
#endif
{
	va_list ap;
	int ret = 0;

#if __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	if (fflag)
		ret = vfprintf(stderr, fmt, ap);
	else {
		vsyslog(LOG_DEBUG, fmt, ap);
		ret = 0;
	}
	va_end(ap);
	return ret;
}
