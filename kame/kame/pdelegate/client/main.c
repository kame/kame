/*	$KAME: main.c,v 1.15 2001/11/13 12:38:49 jinmei Exp $	*/

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

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/icmp6.h>

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <netdb.h>

#include "pdelegate.h"
#include "sock.h"

int main __P((int, char **));
static void usage __P((void));
static void mainloop __P((int));
static void send_discover __P((int));
static int receive_discover __P((int, struct sockaddr *, int *));
static void send_initreq __P((int, const struct sockaddr *, int));
static int receive_initreq __P((int, struct sockaddr *, int *, int *));
static int receive __P((int, char *, size_t, struct sockaddr *, int *));
static int sethops __P((int, int));
static int cmpsockaddr __P((const struct sockaddr *, int,
	const struct sockaddr *, int));

int dflag = 0;
int vflag = 0;
int prefixlen = 64;
const char *iface;

int
main(argc, argv)
	int argc;
	char **argv;
{
	char c;
	int sock;
	unsigned long v;
	char *ep;

	while ((c = getopt(argc, argv, "dl:v")) != EOF) {
		switch (c) {
		case 'd':
			dflag++;
			break;
		case 'l':
			ep = NULL;
			v = strtoul(optarg, &ep, 10);
			if (!ep || *ep) {
				errx(1, "invalid argument");
				/*NOTREACHED*/
			}
			prefixlen = (int)v;
			break;
		case 'v':
			vflag++;
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

	sock = sockopen();
	if (!dflag) {
		struct icmp6_filter filt;

		ICMP6_FILTER_SETBLOCKALL(&filt);
		ICMP6_FILTER_SETPASS(ICMP6_PREFIX_REQUEST, &filt);
		ICMP6_FILTER_SETPASS(ICMP6_PREFIX_DELEGATION, &filt);
		if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		    sizeof(filt)) < 0) {
			err(1, "setsockopt(ICMP6_FILTER)");
			/*NOTREACHED*/
		}
	}
	mainloop(sock);
	exit(0);
}

static void
usage()
{

	fprintf(stderr, "usage: pdelegate [-vd] [-l prefixlen] iface\n");
}

static void
mainloop(s)
	int s;
{
	int state = 0;
	fd_set *fds;
	size_t fdssize;
	int n;
	struct timeval tv, *tvp;
	struct timeval prev, cur, timeo;
	int retry;
	struct sockaddr_storage serv;
	int servlen;
	struct sockaddr_storage from;
	int fromlen;
	char buf[4096];
	struct icmp6_prefix_delegation *p;
	int ecode;

#define settimeo(x)	do { timeo = cur; timeo.tv_sec += (x); } while (0)
#define clrtimeo(x)	do { timeo.tv_sec = timeo.tv_usec = 0; } while (0)
	fdssize = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
	if (sizeof(*fds) > fdssize)
		fdssize = sizeof(*fds);
	fds = (fd_set *)malloc(fdssize);
	if (!fds) {
		err(1, NULL);	/* rely upon SUSv2 malloc behavior */
		/*NOTREACHED*/
	}

	while (1) {
		gettimeofday(&cur, NULL);

		switch (state) {
		case 0:
			/* send discover */
			send_discover(s);
			state = 1;
			settimeo(ICMP6_PD_QUERY_INTERVAL);
			retry = ICMP6_PD_QUERY_RETRY_MAX;
			break;
		case 1:
			if (n == 0) {
				if (vflag)
					warnx("discovery retry");
				if (retry-- > 0) {
					send_discover(s);
					state = 1;
					settimeo(ICMP6_PD_QUERY_INTERVAL);
				} else {
					/* retry exceeded */
					errx(1, "no delegator, retry exceeded");
					/*NOTREACHED*/
				}
			} else {
				/* got discovery reply? */
				servlen = sizeof(serv);
				if (receive_discover(s,
				    (struct sockaddr *)&serv, &servlen) < 0) {
					/* no, it is not - once again */
					state = 1;
					break;
				}
				p = (struct icmp6_prefix_delegation *)buf;

				/* got discovery reply, send initreq */
				send_initreq(s, (struct sockaddr *)&serv,
				    servlen);
				state = 2;
				settimeo(ICMP6_PD_INITIAL_INTERVAL);
				retry = ICMP6_PD_INITIAL_RETRY_MAX;
			}
			break;
		case 2:
			if (n == 0) {
				if (vflag)
					warnx("initreq retry");
				if (retry-- > 0) {
					send_initreq(s,
					    (struct sockaddr *)&serv, servlen);
					state = 2;
					settimeo(ICMP6_PD_INITIAL_INTERVAL);
				} else {
					/* retry exceeded */
					errx(1, "no response from delegator "
					    "for initreq");
					/*NOTREACHED*/
				}
			} else {
				/* got prefix return? */
				fromlen = sizeof(from);
				if (receive_initreq(s, (struct sockaddr *)&from,
				    &fromlen, &ecode) < 0) {
					if (ecode) {
						errx(1, "fatal error");
						/*NOTREACHED*/
					}

					/* type/code mismatch - once again */
					state = 2;
					break;
				}
				if (!cmpsockaddr((struct sockaddr *)&serv,
				    servlen, (struct sockaddr *)&from,
				    fromlen)) {
					if (vflag)
						warnx("a reply from different server");
					state = 2;
					break;
				}

				if (vflag)
					warnx("successful");
				exit(0);
			}
			break;
		default:
			errx(1, "unknown state %d", state);
			/*NOTREACHED*/
		}

	again:
		memset(fds, 0, fdssize);
		FD_SET(s, fds);
		if (timeo.tv_sec) {
			tv.tv_sec = timeo.tv_sec - cur.tv_sec;
			tv.tv_usec = timeo.tv_usec - cur.tv_usec;
			while (tv.tv_usec < 0) {
				tv.tv_usec += 1000000;
				tv.tv_sec -= 0;
			}
			if (tv.tv_sec >= 0)
				tvp = &tv;
			else
				tvp = NULL;
		} else
			tvp = NULL;
		if (vflag) {
			warnx("select, timeout=%ld.%06ld",
			    tvp ? tvp->tv_sec : -1, tvp ? tvp->tv_usec : 0);
			warnx("state: %d retry: %d", state, retry);
		}
		gettimeofday(&prev, NULL);
		n = select(s + 1, fds, NULL, NULL, tvp);
		if (vflag)
			warnx("select, n=%d", n);
		if (n < 0) {
			if (errno == EINTR)
				goto again;
			err(1, "select");
			/*NOTREACHED*/
		}
	}
#undef settimeo
}

static void
send_discover(s)
	int s;
{
	struct icmp6_prefix_request req;
	struct addrinfo hints, *res, *res0;
	char dest[NI_MAXHOST];
	int error;

	if (vflag)
		warnx("send_discover");

	if (sethops(s, 1) < 0) {
		errx(1, "sethops");
		/*NOTREACHED*/
	}

	memset(&req, 0, sizeof(req));
	req.icmp6_pr_hdr.icmp6_type = ICMP6_PREFIX_REQUEST;
	req.icmp6_pr_hdr.icmp6_code = ICMP6_PR_DELEGATOR_QUERY;
	/* global scope */
	req.icmp6_pr_hdr.icmp6_pr_flaglen &= ~ICMP6_PR_FLAGS_SCOPE;

#ifndef __KAME__
#error kame systems only
#endif
	if (dflag)
		snprintf(dest, sizeof(dest), "ff02::2%%%s", iface);	/*XXX*/
	else {
		/* XXX local agreement */
		snprintf(dest, sizeof(dest), "%s%%%s", ALLDELEGATORS, iface);
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

	l = receive(s, buf, sizeof(buf), from, fromlenp);
	if (l < 0)
		return -1;
	p = (struct icmp6_prefix_delegation *)buf;
	if (p->icmp6_pd_hdr.icmp6_code != ICMP6_PD_PREFIX_DELEGATOR)
		return -1;

	/* XXX more validation */

	return 0;
}

static void
send_initreq(s, serv, servlen)
	int s;
	const struct sockaddr *serv;
	int servlen;
{
	struct icmp6_prefix_request req;

	if (vflag)
		warnx("send_initreq");

	if (sethops(s, 1) < 0) {
		errx(1, "sethops");
		/*NOTREACHED*/
	}

	memset(&req, 0, sizeof(req));
	req.icmp6_pr_hdr.icmp6_type = ICMP6_PREFIX_REQUEST;
	req.icmp6_pr_hdr.icmp6_code = ICMP6_PR_INITIAL_REQUEST;
	req.icmp6_pr_hdr.icmp6_pr_flaglen = prefixlen;
	/* global scope */
	req.icmp6_pr_hdr.icmp6_pr_flaglen &= ~ICMP6_PR_FLAGS_SCOPE;

	if (sendto(s, &req, sizeof(req), 0, serv, servlen) < 0) {
		err(1, "sendto");
		/*NOTREACHED*/
	}
}

static int
receive_initreq(s, from, fromlenp, ecode)
	int s;
	struct sockaddr *from;
	int *fromlenp;
	int *ecode;
{
	char buf[4096];
	ssize_t l;
	struct icmp6_prefix_delegation *p;
	char hbuf[NI_MAXHOST];
	const int niflags = NI_NUMERICHOST;
	struct sockaddr_in6 sin6;
	unsigned int plen;	/* delegated prefixlen */

	*ecode = 0;

	l = receive(s, buf, sizeof(buf), from, fromlenp);
	if (l < 0)
		return -1;
	p = (struct icmp6_prefix_delegation *)buf;

	/* XXX more validation */

	switch (p->icmp6_pd_hdr.icmp6_code) {
	case ICMP6_PD_AUTH_REQUIRED:
	case ICMP6_PD_AUTH_FAILED:
		if (vflag)
			warnx("authentication failed");
		*ecode = p->icmp6_pd_hdr.icmp6_code;
		return -1;
	case ICMP6_PD_PREFIX_UNAVAIL:
		if (vflag)
			warnx("prefix unavailable");
		*ecode = p->icmp6_pd_hdr.icmp6_code;
		return -1;
	case ICMP6_PD_PREFIX_DELEGATED:
		/* we assume prefixlen to match up */
		plen = p->icmp6_pd_hdr.icmp6_pd_flaglen & ICMP6_PD_LEN_MASK;
		if (plen != prefixlen) {
			if (vflag)
				warnx("bogus prefixlen %u != requested %d",
				    plen, prefixlen);
			return -1;
		}
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_addr = p->icmp6_pd_prefix;
		if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6),
		    hbuf, sizeof(hbuf), NULL, 0, niflags) != 0)
			return -1;
		printf("%s/%u\n", hbuf, plen);
		return 0;
	default:
		*ecode = p->icmp6_pd_hdr.icmp6_code;
		if (vflag)
			warnx("unexpected reply %u\n",
			    p->icmp6_pd_hdr.icmp6_code);
		return -1;
	}
}

static ssize_t
receive(s, buf, blen, from, fromlenp)
	int s;
	char *buf;
	size_t blen;
	struct sockaddr *from;
	int *fromlenp;
{
	ssize_t l;
	struct icmp6_prefix_delegation *p;

	l = recvfrom(s, buf, blen, 0, from, fromlenp);
	if (l < 0 || l < sizeof(*p))
		return -1;
	p = (struct icmp6_prefix_delegation *)buf;
	if (p->icmp6_pd_hdr.icmp6_type != ICMP6_PREFIX_DELEGATION)
		return -1;
	/* XXX we need a global prefix */
	if ((p->icmp6_pd_hdr.icmp6_pd_flaglen & ICMP6_PD_FLAGS_SCOPE) != 0) {
		if (vflag)
			warnx("address scope is not global");
		return -1;
	}
	/* routing protocol field is yet to be standardized */
	if (p->icmp6_pd_hdr.icmp6_pd_rtproto) {
		if (vflag)
			warnx("bogus routing protocol field");
		return -1;
	}
	/* routing information field is yet to be standardized */
	if (p->icmp6_pd_rtlen || l != sizeof(*p)) {
		if (vflag)
			warnx("bogus routing information field");
		return -1;
	}

	/* XXX more validation */

	return l;
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

static int
cmpsockaddr(a, alen, b, blen)
	const struct sockaddr *a;
	int alen;
	const struct sockaddr *b;
	int blen;
{
	char abuf[NI_MAXHOST], bbuf[NI_MAXHOST];
	const int niflags = NI_NUMERICHOST;

	if (getnameinfo(a, alen, abuf, sizeof(abuf), NULL, 0, niflags))
		return 0;
	if (getnameinfo(b, blen, bbuf, sizeof(bbuf), NULL, 0, niflags))
		return 0;
	if (strcmp(abuf, bbuf) == 0)
		return 1;
	else
		return 0;
}
