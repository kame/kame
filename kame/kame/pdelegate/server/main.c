/*	$KAME: main.c,v 1.1 2001/03/04 13:31:56 itojun Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.
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
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <err.h>
#include <netdb.h>

#include "pdelegate.h"
#include "sock.h"

int main __P((int, char **));
static void usage __P((void));
static void mainloop __P((void));
static struct timeval *settimeo __P((struct timeval *, struct timeval *));
static void send_discover __P((int));
static int receive_discover __P((int, struct sockaddr *, int *));
static int sethops __P((int, int));

int s;
int dflag = 0;
const char *iface;

int
main(argc, argv)
	int argc;
	char **argv;
{
	char c;
	unsigned int ifindex;

	while ((c = getopt(argc, argv, "d")) != EOF) {
		switch (c) {
		case 'd':
			dflag++;
			break;
		default:
			usage();
			exit(1);
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		exit(1);
	}
	iface = argv[0];
	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		errx(1, "%s: invalid interface", iface);
		/*NOTREACHED*/
	}

	s = sockopen();
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex,
	    sizeof(ifindex)) < 0) {
		err(1, "setsockopt(IPV6_MULTICAST_IF)");
		/*NOTREACHED*/
	}
	if (!dflag) {
		struct icmp6_filter filt;

		ICMP6_FILTER_SETBLOCKALL(&filt);
		ICMP6_FILTER_SETPASS(ICMP6_PREFIX_REQUEST, &filt);
		if (setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		    sizeof(filt)) < 0) {
			err(1, "setsockopt(ICMP6_FILTER)");
			/*NOTREACHED*/
		}
	}
	mainloop();
}

static void
usage()
{

	fprintf(stderr, "usage: pdelegated [-d] iface\n");
}

static struct timeval *
settimeo(tvp, prev)
	struct timeval *tvp;
	struct timeval *prev;
{
	struct timeval now;

	gettimeofday(&now, NULL);

	now.tv_sec -= prev->tv_sec;
	now.tv_usec -= prev->tv_usec;
	while (now.tv_usec < 0) {
		now.tv_sec--;
		now.tv_usec += 1000000;
	}

	tvp->tv_sec -= now.tv_sec;
	tvp->tv_usec -= now.tv_usec;
	while (tvp->tv_usec < 0) {
		tvp->tv_sec--;
		tvp->tv_usec += 1000000;
	}

	if (tvp->tv_sec < 0)
		return NULL;
	else
		return tvp;
}

static void
mainloop()
{
	fd_set *fds;
	size_t fdssize;
	int n;
	struct sockaddr_storage from;
	int fromlen;
	char buf[4096];
	ssize_t l;
	struct icmp6_hdr *p;

	fdssize = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
	if (sizeof(*fds) > fdssize)
		fdssize = sizeof(*fds);
	fds = (fd_set *)malloc(fdssize);
	if (!fds) {
		err(1, NULL);	/* rely upon SUSv2 malloc behavior */
		/*NOTREACHED*/
	}

	while (1) {
		memset(fds, 0, fdssize);
		FD_SET(s, fds);
		n = select(s + 1, fds, NULL, NULL, NULL);
		warnx("select, n=%d", n);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "select");
			/*NOTREACHED*/
		}

		fromlen = sizeof(from);
		l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from,
		    &fromlen);
		if (l < 0) {
			warn("recvfrom");
			/*NOTREACHED*/
		}

		if (l < sizeof(*p)) {
			warnx("bogus packet length");
			continue;
		}

		p = (struct icmp6_hdr *)buf;
		warnx("type=%u code=%u", p->icmp6_type, p->icmp6_code);

		if (p->icmp6_type != ICMP6_PREFIX_REQUEST) {
			warnx("unknown type");
			continue;
		}

		switch (p->icmp6_code) {
		case ICMP6_PR_DELEGATOR_QUERY:
			receive_dquery(s, buf, l, (struct sockaddr *)&from,
			    fromlen);
			break;
		case ICMP6_PR_INITIAL_REQUEST:
		case ICMP6_PR_RENEWAL_REQUEST:
		case ICMP6_PR_PREFIX_RETURN:
			warnx("code not supported yet");
			break;
		default:
			warnx("unknown code");
			break;
		}
	}
}

int
receive_dquery(s, rbuf, l, from, fromlen)
	int s;
	const char *rbuf;
	ssize_t l;
	struct sockaddr *from;
	int fromlen;
{
	const struct icmp6_prefix_request *p;
	char hbuf[NI_MAXHOST];
	struct icmp6_prefix_delegation reply;
	char sbuf[4096];

	if (l < sizeof(*p)) {
		warnx("too short message");
		return -1;
	}
	p = (const struct icmp6_prefix_request *)rbuf;

	if ((p->icmp6_pr_hdr.icmp6_pr_flaglen & ICMP6_PR_FLAGS_SCOPE) != 0) {
		warnx("we do not serve site-local prefixes");
		return -1;
	}
	if ((p->icmp6_pr_hdr.icmp6_pr_flaglen & ICMP6_PR_LEN_MASK) != 0 ||
	    !IN6_IS_ADDR_UNSPECIFIED(&p->icmp6_pr_prefix)) {
		warnx("invalid prefix %s/%d", inet_ntop(AF_INET6,
		    &p->icmp6_pr_prefix, hbuf, sizeof(hbuf)),
		    p->icmp6_pr_hdr.icmp6_pr_flaglen & ICMP6_PR_LEN_MASK);
		return -1;
	}

	memset(&reply, 0, sizeof(reply));
	reply.icmp6_pd_hdr.icmp6_type = ICMP6_PREFIX_DELEGATION;
	reply.icmp6_pd_hdr.icmp6_code = ICMP6_PD_PREFIX_DELEGATOR;
	reply.icmp6_pd_hdr.icmp6_pd_flaglen = 0;	/* S bit = 0, global */
	reply.icmp6_pd_rtlen = 0;	/* S bit = 0, global */
	if (sethops(s, 1) < 0) {
		errx(1, "sethops");
		/*NOTREACHED*/
	}

	if (sendto(s, &reply, sizeof(reply), 0, from, fromlen) < 0)
		return -1;

	return 0;
}

static int
sethops(s, hops)
	int s;
	int hops;
{

	if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops,
	    sizeof(hops)) < 0)
		return -1;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
	    sizeof(hops)) < 0)
		return -1;

	return 0;
}
