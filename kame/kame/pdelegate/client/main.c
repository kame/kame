/*	$KAME: main.c,v 1.2 2001/03/04 22:38:20 itojun Exp $	*/

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
	if (!if_nametoindex(iface)) {
		errx(1, "%s: invalid interface", iface);
		/*NOTREACHED*/
	}

	s = sockopen();
	if (!dflag) {
		struct icmp6_filter filt;

		ICMP6_FILTER_SETBLOCKALL(&filt);
		ICMP6_FILTER_SETPASS(ICMP6_PREFIX_DELEGATION, &filt);
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

	fprintf(stderr, "usage: pdelegate [-d] iface\n");
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
	int state = 0;
	fd_set *fds;
	size_t fdssize;
	int n;
	struct timeval tv, *tvp;
	struct timeval prev;
	int retry;
	struct sockaddr_storage from;
	int fromlen;

	fdssize = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
	if (sizeof(*fds) > fdssize)
		fdssize = sizeof(*fds);
	fds = (fd_set *)malloc(fdssize);
	if (!fds) {
		err(1, NULL);	/* rely upon SUSv2 malloc behavior */
		/*NOTREACHED*/
	}

	while (1) {
		tvp = NULL;

		switch (state) {
		case 0:
			/* send discover */
			send_discover(s);
			state = 1;
			tv.tv_sec = ICMP6_PD_QUERY_INTERVAL;
			tv.tv_usec = 0;
			tvp = &tv;
			retry = ICMP6_PD_QUERY_RETRY_MAX;
			break;
		case 1:
			if (n == 0) {
				warnx("discovery retry");
				if (retry-- > 0) {
					warnx("foo");
					send_discover(s);
					state = 1;
					tvp = settimeo(&tv, &prev);
					if (!tvp) {
						/* timeout exceeded, reset */
						tv.tv_sec =
						    ICMP6_PD_QUERY_INTERVAL;
						tv.tv_usec = 0;
						tvp = &tv;
					}
				} else {
					/* retry exceeded */
					errx(1, "no delegator, retry exceeded");
					/*NOTREACHED*/
				}
			} else {
				/* got discovery reply? */
				fromlen = sizeof(from);
				if (receive_discover(s,
				    (struct sockaddr *)&from, &fromlen) < 0) {
					/* no, it is not */
					send_discover(s);
					state = 1;
					tvp = settimeo(&tv, &prev);
					if (!tvp) {
						/* timeout exceeded, reset */
						tv.tv_sec =
						    ICMP6_PD_QUERY_INTERVAL;
						tv.tv_usec = 0;
						tvp = &tv;
					}
				} else {
					/* got discovery reply */
#if 0
					send_initquery(s);
#endif
					state = 2;
					tv.tv_sec = ICMP6_PD_QUERY_INTERVAL;
					tv.tv_usec = 0;
					tvp = &tv;
				}
			}
			break;
		}

	again:
		memset(fds, 0, fdssize);
		FD_SET(s, fds);
		warnx("select, timeout=%d.%06d", tvp ? tvp->tv_sec : -1,
		    tvp ? tvp->tv_usec : 0);
		warnx("state: %d retry: %d", state, retry);
		gettimeofday(&prev, NULL);
		n = select(s + 1, fds, NULL, NULL, tvp);
		warnx("select, n=%d", n);
		if (n < 0) {
			if (errno == EINTR)
				goto again;
			err(1, "select");
			/*NOTREACHED*/
		}
	}
}

static void
send_discover(s)
	int s;
{
	struct icmp6_prefix_request req;
	struct addrinfo hints, *res, *res0;
	char dest[NI_MAXHOST];
	int error;

	warnx("send_discover");

	if (sethops(s, 1) < 0) {
		errx(1, "sethops");
		/*NOTREACHED*/
	}

	memset(&req, 0, sizeof(req));
	req.icmp6_pr_hdr.icmp6_type = ICMP6_PREFIX_REQUEST;
	req.icmp6_pr_hdr.icmp6_code = ICMP6_PR_DELEGATOR_QUERY;
	req.icmp6_pr_hdr.icmp6_pr_flaglen = 0;	/* global scope */

#ifndef __KAME__
#error kame systems only
#endif
	if (dflag)
		snprintf(dest, sizeof(dest), "ff02::1%%%s", iface);	/*XXX*/
	else {
		/* XXX local agreement */
		snprintf(dest, sizeof(dest), "ff02::20%%%s", iface);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;
	error = getaddrinfo(dest, NULL, &hints, &res0);
	if (error) {
		errx(1, "%s", gai_strerror(error));
		/*NOTREACHED*/
	}
	for (res = res0; res; res = res->ai_next) {
		if (sendto(s, &req, sizeof(req), 0, res->ai_addr,
		    res->ai_addrlen) < 0)
			continue;
		break;
	}

	if (!res) {
		err(1, "sendto");
		/*NOTREACHED*/
	}

	freeaddrinfo(res0);
}

static int
receive_discover(s, from, fromlenp)
	int s;
	struct sockaddr *from;
	int *fromlenp;
{
	char buf[4096];
	ssize_t l;
	struct icmp6_prefix_delegation *p;
	struct addrinfo hints, *res, *res0;
	char dest[NI_MAXHOST];
	int error;

	l = recvfrom(s, buf, sizeof(buf), 0, from, fromlenp);
	if (l < 0 || l < sizeof(*p))
		return -1;
	p = (struct icmp6_prefix_delegation *)buf;
	if (p->icmp6_pd_hdr.icmp6_type != ICMP6_PREFIX_DELEGATION ||
	    p->icmp6_pd_hdr.icmp6_code != ICMP6_PD_PREFIX_DELEGATOR)
		return -1;

	/* XXX more validation */

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
