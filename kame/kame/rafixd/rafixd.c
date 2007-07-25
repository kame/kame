/*	$KAME: rafixd.c,v 1.12 2007/07/25 05:32:03 itojun Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.
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
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>

#include "rafixd.h"

#ifndef howmany
#define	howmany(x, y)	(((x) + ((y) - 1)) / (y))
#endif

#define PURGE_MIN_DELAY 500
#define PURGE_MAX_DELAY 1500

static int debug_thresh = LOG_ERR;
static int foreground, rcvcmsglen;
static struct ifinfo *iflist;
static struct prefix *plist;
static struct msghdr rcvmhdr;
static struct in6_addr all_nodes_addr; 
static struct iovec rcviov[2];
static struct router_list router_list;
static struct timeval tm_max =	{0x7fffffff, 0x7fffffff};

static int add_interface __P((char *));
static struct ifinfo *find_interface __P((unsigned int));

static int add_prefix __P((char *));
static struct prefix *match_prefix __P((struct in6_addr *, int));

static struct router *find_router __P((struct in6_addr *, struct ifinfo *));
static void remove_router __P((struct router *));
static void add_router __P((struct in6_addr *, struct ifinfo *));
static void purge_router __P((struct router *));

static int bpf_open __P((char *));
static int linkhdrlen __P((int, char *));
static int form_ether __P((u_char *, int));
static void cksum6 __P((u_char *, int, int));
static u_short in_cksum __P((u_short *, u_short *, int));

static int sockopen __P((void));
static void recv_ra __P((int));

static void prefix6_mask __P((struct in6_addr *, int));
static char *addr2str __P((struct sockaddr *));
static char *in6addr2str __P((struct in6_addr *, int));

static struct timeval *check_timer __P((void));
static void timeval_sub __P((struct timeval *, struct timeval *,
    struct timeval *));
static void timeval_add __P((struct timeval *, struct timeval *,
    struct timeval *));

static void dprintf __P((int, const char *, const char *, ...));
static void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int i, s, ch, fdmasks;
	int debug = 0;
	char *progname;
	fd_set *fdsetp, *selectfdp;

	if ((progname = strrchr(*argv, '/')) == NULL)
		progname = *argv;
	else
		progname++;

	while ((ch = getopt(argc, argv, "dDp:f")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'D':
			debug = 2;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'p':
			if (add_prefix(optarg))
				exit(1);
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	if (!foreground) {
		daemon(0, 0);
		openlog(progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);
		switch(debug) {
		case 0:
			setlogmask(LOG_UPTO(LOG_ERR));
			break;
		case 1:
			setlogmask(LOG_UPTO(LOG_INFO));
			break;
		}
	} else {
		switch(debug) {
		case 0:
			debug_thresh = LOG_ERR;
			break;
		case 1:
			debug_thresh = LOG_INFO;
			break;
		default:
			debug_thresh = LOG_DEBUG;
			break;
		}
	}

	for (i = 0; i < argc; i++) {
		if (add_interface(argv[i]))
			exit(1);
	}

#ifndef HAVE_ARC4RANDOM
	srandom(time(NULL) & getpid());
#endif

	TAILQ_INIT(&router_list);

	if (inet_pton(AF_INET6, "ff02::1", &all_nodes_addr) != 1) {
		dprintf(LOG_ERR, FNAME, "failed to convert all nodes address");
		exit(1);
	}

	if ((s = sockopen()) < 0)
		exit(1);

	fdmasks = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
	if ((fdsetp = malloc(fdmasks)) == NULL) {
		dprintf(LOG_NOTICE, FNAME, "fd mask allocation failed");
		exit(1);
	}
	if ((selectfdp = malloc(fdmasks)) == NULL) {
		dprintf(LOG_NOTICE, FNAME, "fd set allocation failed");
		exit(1);
	}
	memset(fdsetp, 0, fdmasks);
	FD_SET(s, fdsetp);

	while (1) {
		int e;
		struct timeval *timeout;

		memcpy(selectfdp, fdsetp, fdmasks);

		timeout = check_timer();
		e = select(s + 1, selectfdp, NULL, NULL, timeout);

		if (FD_ISSET(s, selectfdp))
			recv_ra(s);
	}

	exit(0);
}

static int
add_interface(ifname)
	char *ifname;
{
	struct ifinfo *ifp;
	unsigned int index;

	/* check duplication */
	for (ifp = iflist; ifp; ifp = ifp->next) {
		if (strcmp(ifp->ifname, ifname) == 0) {
			dprintf(LOG_INFO, FNAME, "duplicated interface: %s",
			    ifname);
			return (0);
		}
	}

	/* validate interface name */
	if ((index = if_nametoindex(ifname)) == 0) {
		dprintf(LOG_INFO, FNAME, "bad interface name: %s", ifname);
		return (-1);
	}

	/* add the interface */
	if ((ifp = malloc(sizeof(*ifp))) == NULL) {
		dprintf(LOG_NOTICE, FNAME, "memory allocation failed");
		return (-1);
	}
	memset(ifp, 0, sizeof(*ifp));
	/*
	 * strlcpy() is okay since we have a margin for a NUL in ifp->ifname.
	 */
	strlcpy(ifp->ifname, ifname, sizeof(ifp->ifname));
	ifp->ifindex = index;

	ifp->next = iflist;
	iflist = ifp;

	dprintf(LOG_DEBUG, FNAME, "added interface %s", ifname);

	return (0);
}

static struct ifinfo *
find_interface(index)
	unsigned int index;
{
	struct ifinfo *ifp;

	for (ifp = iflist; ifp; ifp = ifp->next) {
		if (ifp->ifindex == index)
			return (ifp);
	}

	return (NULL);
}

static int
add_prefix(pstr0)
	char *pstr0;
{
	char *pstr, *slash;
	struct in6_addr paddr0, paddr;
	int plen;
	struct prefix *pent, *new;

	if ((pstr = strdup(pstr0)) == NULL) {
		warnx("failed to duplicate a prefix string");
		return (-1);
	}

	/* parse the string */
	if ((slash = strchr(pstr, '/')) == NULL) {
		warnx("bad prefix: %s", pstr0);
		goto bad;
	}
	*slash = '\0';
	if (inet_pton(AF_INET6, pstr, &paddr0) != 1) {
		warnx("bad prefix address: %s", pstr0);
		goto bad;
	}
	plen = atoi(slash + 1);
	if (plen < 0 || plen > 128) {
		warnx("bad prefix length: %s", pstr0);
		goto bad;
	}

	/* clear trailing garbage */
	paddr = paddr0;
	prefix6_mask(&paddr, plen);
	if (!IN6_ARE_ADDR_EQUAL(&paddr0, &paddr))
		warnx("prefix %s has a bogus trailing bits", pstr0);

	/* check duplication */
	for (pent = plist; pent; pent = pent->next) {
		if (IN6_ARE_ADDR_EQUAL(&pent->paddr, &paddr) &&
		    pent->plen == plen) {
			warnx("duplicated prefix: %s", pstr0);
			goto bad;
		}
	}

	/* add the prefix */
	if ((new = malloc(sizeof(*new))) == NULL) {
		warnx("memory allocation failed");
		goto bad;
	}
	memset(new, 0, sizeof(*new));
	new->paddr = paddr;
	new->plen = plen;

	new->next = plist;
	plist = new;

	free(pstr);
	return (0);

  bad:
	free(pstr);
	return (-1);
}

static struct prefix * 
match_prefix(paddr, plen)
	struct in6_addr *paddr;
	int plen;
{
	int i, l;
	u_char m;
	struct prefix *pent;

	for (pent = plist; pent; pent = pent->next) {
		if (plen < pent->plen)
			continue;

		for (i = 0, l = pent->plen; l > 7; l -= 8, i++) {
			if (pent->paddr.s6_addr[i] != paddr->s6_addr[i])
				goto nextprefix;
		}
		if (l) {
			m = 0xff << (8 - l);
			if (pent->paddr.s6_addr[i] != (paddr->s6_addr[i] & m))
				goto nextprefix;
		}
		return (pent);

	  nextprefix:
		;
	}

	return (NULL);
}

/*
 * Router list manipulation
 */
static struct router *
find_router(in6, ifp)
	struct in6_addr *in6;
	struct ifinfo *ifp;
{
	struct router *rtp;

	for (rtp = TAILQ_FIRST(&router_list); rtp;
	    rtp = TAILQ_NEXT(rtp, link)) {
		if (rtp->interface == ifp &&
		    IN6_ARE_ADDR_EQUAL(&rtp->address, in6)) {
			return (rtp);
		}
	}

	return (NULL);
}

static void
remove_router(rtp)
	struct router *rtp;
{
	dprintf(LOG_INFO, FNAME, "remove a router: %s on %s",
	    in6addr2str(&rtp->address, 0), rtp->interface->ifname);

	TAILQ_REMOVE(&router_list, rtp, link);
	free(rtp);
}

static void
add_router(in6, ifp)
	struct in6_addr *in6;
	struct ifinfo *ifp;
{
	struct router *new;
	u_int32_t delay;
	struct timeval now, tv_delay;

	if ((new = malloc(sizeof(*new))) == NULL) {
		dprintf(LOG_NOTICE, FNAME, "memory allocation failed");
		return;
	}
	memset(new, 0, sizeof(*new));

	new->interface = ifp;
	new->address = *in6;

#ifdef HAVE_ARC4RANDOM
	delay = arc4random();
#else
	delay = (u_int32_t)random();
#endif
	delay = (delay % (PURGE_MAX_DELAY - PURGE_MIN_DELAY)) +
	    PURGE_MIN_DELAY;
	tv_delay.tv_sec = delay / 1000;
	tv_delay.tv_usec = (delay % 1000) * 1000;
	gettimeofday(&now, NULL);
	timeval_add(&now, &tv_delay, &new->expire);

	dprintf(LOG_DEBUG, FNAME, "added a bogus router %s on %s "
	    "expiring in %lumsec", in6addr2str(in6, 0), ifp->ifname, delay);

	TAILQ_INSERT_TAIL(&router_list, new, link);
}

static void
purge_router(rtp)
	struct router *rtp;
{
	u_char *sendbuf = NULL;
	int fd, lhlen, sendlen;
	struct ip6_hdr *ip6;
	struct nd_router_advert *ra;

	if ((fd = bpf_open(rtp->interface->ifname)) < 0)
		return;
	lhlen = linkhdrlen(fd, rtp->interface->ifname);
	if (lhlen < 0) {
		dprintf(LOG_NOTICE, FNAME, "unsupported interface %s",
		    rtp->interface->ifname);
		goto end;
	}

	sendlen = lhlen + sizeof(struct ip6_hdr) +
	    sizeof(struct nd_router_advert);
	if ((sendbuf = malloc(sendlen)) == NULL) {
		dprintf(LOG_NOTICE, FNAME, "failed to allocate send buffer");
		goto end;
	}
	memset(sendbuf, 0, sendlen);

	/* construct the IPv6 header */
	ip6 = (struct ip6_hdr *)(sendbuf + lhlen);
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = htons(sizeof(*ra));
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	ip6->ip6_src = rtp->address;
	ip6->ip6_dst = all_nodes_addr;

	/* construct the RA header */
	ra = (struct nd_router_advert *)(ip6 + 1);
	ra->nd_ra_type = ND_ROUTER_ADVERT;
	ra->nd_ra_router_lifetime = 0;

	if (form_ether(sendbuf, sizeof(*ip6) + sizeof(*ra)) == 0) {
		int slen;

		if ((slen = write(fd, sendbuf, sendlen)) < 0) {
			dprintf(LOG_NOTICE, FNAME, "bpf write failed: %s",
			    strerror(errno));
		} else {
			dprintf(LOG_DEBUG, FNAME,
			    "sent a purge packet on %s, len = %d",
			    rtp->interface->ifname, slen);
		}
	}

	free(sendbuf);

  end:
	close(fd);
	return;
}

/*
 * Bpf related routines
 */
static int
bpf_open(iface)
	char *iface;
{
	int n = 0, fd;
	char dev[16];
	struct ifreq ifr;
	
	do {
		snprintf(dev, sizeof(dev), "/dev/bpf%d", n++);
		fd = open(dev, O_RDWR);
	} while (fd < 0 && n < 4);

	if (fd < 0) {
		dprintf(LOG_NOTICE, FNAME, "failed to open a bpf interface");
		return (-1);
	}

	if (ioctl(fd, BIOCIMMEDIATE, &n) < 0) {
		dprintf(LOG_NOTICE, FNAME, "ioctl(BIOCIMMEDIATE): %s",
		    strerror(errno));
		return (-1);
	}

	bzero(&ifr, sizeof(ifr));
	/*
	 * Note: don't use strlcpy() here.  ifr.ifr_name does not need to be
	 * NUL-terminated, and iface is a NUL-terminated string.
	 */
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
		perror("ioctl(BIOCSETIF)");
		return (-1);
	}
	return (fd);
}

static int
linkhdrlen(fd, iface)
	int fd;
	char *iface;
{
	u_int v;

	if (ioctl(fd, BIOCGDLT, (caddr_t)&v) < 0) {
		dprintf(LOG_NOTICE, FNAME, "ioctl(BIOCGDLT): %s",
		    strerror(errno));
		return (-1);
	}

	switch (v) {
	case DLT_EN10MB:
		return (sizeof(struct ether_header));
	default:
		return (-1);
	}

	return (-1);
}

static int
form_ether(buf, psize)
	u_char *buf;
	int psize;
{
	struct ether_header *ether;
	struct ip6_hdr *ip6;
	
	ether = (struct ether_header *)buf;
	ip6 = (struct ip6_hdr *)(ether + 1);

	ether->ether_type = htons(0x86dd); /* Ether type for IPv6 */
	if (IN6_IS_ADDR_MULTICAST(&(ip6->ip6_dst))) {
		ether->ether_dhost[0] = 0x33;
		ether->ether_dhost[1] = 0x33;
		ether->ether_dhost[2] = ip6->ip6_dst.s6_addr[12];
		ether->ether_dhost[3] = ip6->ip6_dst.s6_addr[13];
		ether->ether_dhost[4] = ip6->ip6_dst.s6_addr[14];
		ether->ether_dhost[5] = ip6->ip6_dst.s6_addr[15];
	} else {
		ether->ether_dhost[0] = ip6->ip6_dst.s6_addr[8] & 0xfd;
		ether->ether_dhost[1] = ip6->ip6_dst.s6_addr[9];
		ether->ether_dhost[2] = ip6->ip6_dst.s6_addr[10];
		ether->ether_dhost[3] = ip6->ip6_dst.s6_addr[13];
		ether->ether_dhost[4] = ip6->ip6_dst.s6_addr[14];
		ether->ether_dhost[5] = ip6->ip6_dst.s6_addr[15];
	}		

	cksum6(buf, sizeof(struct ether_header), psize);

	return (0);
}

static void
cksum6(buf, linkhdrlen, size)
	u_char *buf;
	int linkhdrlen, size;
{
	u_int16_t plen;
	u_char ipovly[40];
	u_short *cksum;
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)(buf + linkhdrlen);
	plen = ntohs(ip6->ip6_plen);

	bcopy(&ip6->ip6_src, &ipovly[0], 16);
	bcopy(&ip6->ip6_dst, &ipovly[16], 16);
	ipovly[32] = 0;
	ipovly[33] = 0;
	plen = htons(plen);
	bcopy((caddr_t)&plen, ipovly + 34, 2);
	plen = ntohs(plen);
	ipovly[36] = 0;
	ipovly[37] = 0;
	ipovly[38] = 0;
	ipovly[39] = IPPROTO_ICMPV6;

	cksum = &((struct icmp6_hdr *)(ip6 + 1))->icmp6_cksum;
	*cksum = in_cksum((u_short *)(ip6 + 1), (u_short *)ipovly, (int)plen);
}

static u_short
in_cksum(addr, ph, len)
	u_short *addr, *ph;
	int len;
{
	register int nleft = len;
	register int pleft = 40;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}
		
	while (pleft > 0)  {
		sum += *ph++;
		pleft -= 2;
	}
		
	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */

	return(answer);
}

/*
 * IPv6 address manipulation
 */
static void
prefix6_mask(in6, plen)
	struct in6_addr *in6;
	int plen;
{
	int i;
	u_char *cp;
	struct in6_addr mask6;

	for (cp = (u_char *)&mask6; plen > 7; plen -= 8)
		*cp++ = 0xff;
	*cp = 0xff << (8 - plen);

	for (i = 0; i < 16; i++)
		in6->s6_addr[i] &= mask6.s6_addr[i];

	return;
}

static char *
addr2str(sa)
	struct sockaddr *sa;
{
	static char addrbuf[8][NI_MAXHOST]; /* XXX */
	static int round = 0;
	char *cp;

	round = (round + 1) & 7;
	cp = addrbuf[round];

	getnameinfo(sa, sa->sa_len, cp, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

	return (cp);
}

static char *
in6addr2str(in6, scopeid)
	struct in6_addr *in6;
	int scopeid;
{
	struct sockaddr_in6 sa6;

	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_addr = *in6;
	sa6.sin6_scope_id = scopeid;

	return (addr2str((struct sockaddr *)&sa6));
}

/*
 * Handle incoming RA
 */
static int
sockopen()
{
	static u_char *rcvcmsgbuf = NULL;
	int s, on;
	static u_char answer[1500];
	struct icmp6_filter filt;

	rcvcmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	    CMSG_SPACE(sizeof(int));
	if (rcvcmsgbuf == NULL && (rcvcmsgbuf = malloc(rcvcmsglen)) == NULL) {
		dprintf(LOG_ERR, FNAME, "malloc for receive msghdr failed");
		return (-1);
	}

	if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		dprintf(LOG_ERR, FNAME, "socket: %s", strerror(errno));
		return (-1);
	}

	/* specify to tell receiving interface */
	on = 1;
#ifdef IPV6_RECVPKTINFO
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
	    sizeof(on)) < 0) {
		dprintf(LOG_ERR, FNAME, "IPV6_RECVPKTINFO: %s",
		    strerror(errno));
		goto bad;
	}
#else
	if (setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &on,
	    sizeof(on)) < 0) {
		dprintf(LOG_ERR, FNAME, "IPV6_PKTINFO: %s",
		    strerror(errno));
		goto bad;
	}
#endif

	/* specify to tell value of hoplimit field of received IP6 hdr */
	on = 1;
#ifdef IPV6_RECVHOPLIMIT
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on,
	    sizeof(on)) < 0) {
		dprintf(LOG_ERR, FNAME, "IPV6_RECVHOPLIMIT: %s",
		    strerror(errno));
		goto bad;
	}
#else
	if (setsockopt(s, IPPROTO_IPV6, IPV6_HOPLIMIT, &on,
	    sizeof(on)) < 0) {
		dprintf(LOG_ERR, FNAME, "IPV6_HOPLIMIT: %s",
		    strerror(errno));
		goto bad;
	}
#endif

	/* specfiy to accept only router advertisements on the socket */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	if (setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
	    sizeof(filt)) == -1) {
		dprintf(LOG_ERR, FNAME, "setsockopt(ICMP6_FILTER): %s",
		    strerror(errno));
		goto bad;
	}

	/* initialize msghdr for receiving packets */
	rcviov[0].iov_base = (caddr_t)answer;
	rcviov[0].iov_len = sizeof(answer);
	rcvmhdr.msg_iov = rcviov;
	rcvmhdr.msg_iovlen = 1;
	rcvmhdr.msg_control = (caddr_t)rcvcmsgbuf;

	return(s);

  bad:
	close(s);
	return (-1);
}

static void
recv_ra(s)
	int s;
{
	struct sockaddr_in6 from;
	struct icmp6_hdr *icp;
	struct nd_router_advert *rap;
	struct in6_pktinfo *pi = NULL;
	struct cmsghdr *cm;
	struct ifinfo *ifp;
	struct nd_opt_hdr *hdr;
	int len, optlen, resid;

	rcvmhdr.msg_name = &from;
	rcvmhdr.msg_namelen = sizeof(from);
	rcvmhdr.msg_controllen = rcvcmsglen;

	if ((len = recvmsg(s, &rcvmhdr, 0)) < 0) {
		dprintf(LOG_NOTICE, FNAME, "recvmsg: %s", strerror(errno));
		return;
	}

	/* extract packet information */
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&rcvmhdr);
	    cm && cm->cmsg_len;
	    cm = (struct cmsghdr *)CMSG_NXTHDR(&rcvmhdr, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
		}
	}
	if (pi == NULL) {
		dprintf(LOG_ERR, FNAME, "failed to get receiving packet info");
		return;
	}

	if ((ifp = find_interface(pi->ipi6_ifindex)) == NULL) {
		char ifn[IF_NAMESIZE];

		dprintf(LOG_INFO, FNAME,
		    "received a packet from %s on an unexpected interface: %s",
		    addr2str((struct sockaddr *)&from),
		    if_indextoname(pi->ipi6_ifindex, ifn));
		return;
	}

	icp = (struct icmp6_hdr *)rcvmhdr.msg_iov[0].iov_base;
	if (icp->icmp6_type != ND_ROUTER_ADVERT) {
		/* XXX: impossible */
		dprintf(LOG_ERR, FNAME,
		    "unexpected icmp type (%d) from %s on %s",
		    icp->icmp6_type, addr2str((struct sockaddr *)&from),
		    ifp->ifname);
	}

	dprintf(LOG_DEBUG, FNAME, "received a packet from %s to %s on %s",
	    addr2str((struct sockaddr *)&from),
	    in6addr2str(&pi->ipi6_addr, 0), ifp->ifname);

	/* Parse the RA.  XXX: message validation */
	rap = (struct nd_router_advert *)icp;
	if (rap->nd_ra_router_lifetime == 0) {
		struct router *rtp;

		if ((rtp = find_router(&from.sin6_addr, ifp)) != NULL) {
			dprintf(LOG_INFO, FNAME,
			    "a bogus router %s was purged",
			    addr2str((struct sockaddr *)&from));
			remove_router(rtp);
		}
		return;
	}
	/*
	 * Now we have a router that has a positive lifetime.
	 * Check if it advertises a bogus prefix.
	 */
	resid = len - sizeof(*rap);
	for (hdr = (struct nd_opt_hdr *)(rap + 1), optlen = 0; resid > 0;
	    resid -= optlen) {
		if (resid < sizeof(struct nd_opt_hdr)) {
			dprintf(LOG_INFO, FNAME,
			    "short RA option header from %s",
			    addr2str((struct sockaddr *)&from));
			break;
		}

		hdr = (struct nd_opt_hdr *)((caddr_t)hdr + optlen);
		optlen = hdr->nd_opt_len << 3;
		if (hdr->nd_opt_len == 0) {
			dprintf(LOG_INFO, FNAME,
			    "bad ND option: 0 length (type = %d) from %s",
			    hdr->nd_opt_type,
			    addr2str((struct sockaddr *)&from));
			break;
		}
		if (resid < optlen) {
			dprintf(LOG_INFO, FNAME,
			    "short RA for options from %s",
			    addr2str((struct sockaddr *)&from));
			break;
		}

		if (hdr->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
			struct nd_opt_prefix_info *ndpi;

			ndpi = (struct nd_opt_prefix_info *)hdr;

			if (ndpi->nd_opt_pi_len != 4) {
				dprintf(LOG_INFO, FNAME,
				    "bad prefix information: "
				    "invalid len (%d) from %s",
				    ndpi->nd_opt_pi_len,
				    addr2str((struct sockaddr *)&from));
				continue;
			}

			if (ndpi->nd_opt_pi_prefix_len > 128) {
				dprintf(LOG_INFO, FNAME,
				    "bad prefix information: "
				    "invalid prefix len (%d) from %s",
				    ndpi->nd_opt_pi_prefix_len,
				    addr2str((struct sockaddr *)&from));
				continue;
			}

			dprintf(LOG_DEBUG, FNAME,
			    "RA prefix: %s/%d",
			    in6addr2str(&ndpi->nd_opt_pi_prefix, 0),
			    ndpi->nd_opt_pi_prefix_len);

			if (match_prefix(&ndpi->nd_opt_pi_prefix,
			    ndpi->nd_opt_pi_prefix_len)) {
				dprintf(LOG_INFO, FNAME,
				    "received a bogus prefix %s/%d from %s",
				    in6addr2str(&ndpi->nd_opt_pi_prefix, 0),
				    ndpi->nd_opt_pi_prefix_len,
				    addr2str((struct sockaddr *)&from));
				    
				if (!find_router(&from.sin6_addr, ifp))
					add_router(&from.sin6_addr, ifp);
			}
		}
	}
}

/*
 * Timer related functions
 */
/* a < b */
#define TIMEVAL_LT(a, b) (((a).tv_sec < (b).tv_sec) ||\
			  (((a).tv_sec == (b).tv_sec) && \
			    ((a).tv_usec < (b).tv_usec)))

/* a <= b */
#define TIMEVAL_LEQ(a, b) (((a).tv_sec < (b).tv_sec) ||\
			   (((a).tv_sec == (b).tv_sec) &&\
			    ((a).tv_usec <= (b).tv_usec)))

/* a == b */
#define TIMEVAL_EQ(a, b) (((a).tv_sec==(b).tv_sec) && \
			  ((a).tv_usec==(b).tv_usec))

static struct timeval *
check_timer()
{
	static struct timeval returnval;
	struct timeval now, timer;
	struct router *rtp, *rtp_next;

	gettimeofday(&now, NULL);

	timer = tm_max;

	for (rtp = TAILQ_FIRST(&router_list); rtp; rtp = rtp_next) {
		rtp_next = TAILQ_NEXT(rtp, link);

		if (TIMEVAL_LEQ(rtp->expire, now)) {
			dprintf(LOG_DEBUG, FNAME,
			    "purge timer for %s on %s has expired",
			    in6addr2str(&rtp->address, 0),
			    rtp->interface->ifname);

			purge_router(rtp);
			remove_router(rtp);
			continue;
		}

		if (TIMEVAL_LT(rtp->expire, timer))
			timer = rtp->expire;
	}

	if (TIMEVAL_EQ(timer, tm_max)) {
		dprintf(LOG_DEBUG, FNAME, "there is no timer");
		return (NULL);
	} else if (TIMEVAL_LT(timer, now)) {
		/* this may occur when the interval is too small */
		returnval.tv_sec = returnval.tv_usec = 0;
	} else
		timeval_sub(&timer, &now, &returnval);

	dprintf(LOG_DEBUG, FNAME, "New timer is %ld:%06ld",
	    (long)returnval.tv_sec, (long)returnval.tv_usec);

	return (&returnval);
}

/*
 * result = a - b
 * XXX: this function assumes that a >= b.
 */
#define MILLION 1000000
void
timeval_sub(a, b, result)
	struct timeval *a, *b, *result;
{
	long l;

	if ((l = a->tv_usec - b->tv_usec) >= 0) {
		result->tv_usec = l;
		result->tv_sec = a->tv_sec - b->tv_sec;
	} else {
		result->tv_usec = MILLION + l;
		result->tv_sec = a->tv_sec - b->tv_sec - 1;
	}
}

/* result = a + b */
static void
timeval_add(a, b, result)
	struct timeval *a, *b, *result;
{
	long l;

	if ((l = a->tv_usec + b->tv_usec) < MILLION) {
		result->tv_usec = l;
		result->tv_sec = a->tv_sec + b->tv_sec;
	} else {
		result->tv_usec = l - MILLION;
		result->tv_sec = a->tv_sec + b->tv_sec + 1;
	}
}
#undef MILLION

/*
 * Logging
 */
static void
dprintf(int level, const char *fname, const char *fmt, ...)
{
	va_list ap;
	char logbuf[LINE_MAX];
	int printfname = 1;

	va_start(ap, fmt);
	vsnprintf(logbuf, sizeof(logbuf), fmt, ap);

	if (*fname == '\0')
		printfname = 0;

	if (foreground && debug_thresh >= level) {
		time_t now;
		struct tm *tm_now;
		const char *month[] = {
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
		};

		if ((now = time(NULL)) < 0)
			exit(1); /* XXX */
		tm_now = localtime(&now);
		fprintf(stderr, "%s%s%3s/%02d/%04d %02d:%02d:%02d %s\n",
		    fname, printfname ? ": " : "",
		    month[tm_now->tm_mon], tm_now->tm_mday,
		    tm_now->tm_year + 1900,
		    tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
		    logbuf);
	} else
		syslog(level, "%s%s%s", fname, printfname ? ": " : "", logbuf);
}

static void
usage()
{
	fprintf(stderr, "usage: rafixd [-dDf] [-p prefix] interfaces...\n");

	exit(1);
}
