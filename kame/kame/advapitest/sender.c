/*	$KAME: sender.c,v 1.16 2001/06/20 12:35:12 jinmei Exp $ */
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
#include <sys/uio.h>

#include <netinet/in.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include "common.h"

#define DEFPORT 9079

int dsthdr1len, dsthdr2len, hbhlen;
char *hlimp = NULL;
int hlim;

struct msghdr msg;
struct cmsghdr *cmsgp = NULL;

static int calc_opthlen __P((int));
static void setopthdr __P((int, int));
static void usage __P((void));
static int mflag;

#ifndef IPV6_MINMTU
#define IPV6_MINMTU 1280
#endif

int
main(argc, argv)
    int argc;
    char *argv[];
{
	int i, s;
	int rthlen = 0, ip6optlen = 0, hops = 0, error;
	char *portstr = DEFAULTPORT;
	char *finaldst;
	struct iovec msgiov;
	char *e, *databuf;
	int datalen = 1, ch;
	int minmtu = 0;
	struct addrinfo hints, *res;
	extern int optind;
	extern void *malloc();
	extern char *optarg;
	int socktype = SOCK_DGRAM;
	int proto = IPPROTO_UDP;

	while ((ch = getopt(argc, argv, "d:D:h:l:M:mp:s:")) != -1)
		switch(ch) {
		case 'D':
			dsthdr1len = atoi(optarg);
			break;
		case 'd':
			dsthdr2len = atoi(optarg);
			break;
		case 'h':
			hbhlen = atoi(optarg);
			break;
		case 'l':
			hlimp = optarg;
			break;
		case 'm':
			mflag++;
			break;
		case 'p':
			portstr = optarg;
			break;
		case 's':
			datalen = strtol(optarg, &e, 10);
			if (datalen <= 0 || *optarg == '\0' || *e != '\0')
				errx(1, "illegal datalen value -- %s", optarg);
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	memset(&msg, 0, sizeof(msg));

	if ((databuf = (char *)malloc(datalen)) == 0)
		errx(1, "can't allocate memory\n");
	memset(databuf, 0, sizeof(datalen));

	if (hbhlen > 0) ip6optlen += CMSG_SPACE(calc_opthlen(hbhlen));
	if (dsthdr1len > 0) ip6optlen += CMSG_SPACE(calc_opthlen(dsthdr1len));
	if (dsthdr2len > 0) ip6optlen += CMSG_SPACE(calc_opthlen(dsthdr2len));
	if (hlimp != NULL) {
		hlim = atoi(hlimp);
#if 0
		/* intentionally omit the check to see the kernel behavior. */
		if (hlim < 0 || hlim > 255)
			errx(1, "invalid hop limit: %d", hlim);
#endif
		ip6optlen += CMSG_SPACE(sizeof(int));
	}
	if (argc > 1) {		/* intermediate node(s) exist(s) */
		hops = argc - 1;
		rthlen = inet6_rth_space(IPV6_RTHDR_TYPE_0, hops);
		ip6optlen += CMSG_SPACE(rthlen);
	}
	if (ip6optlen) {
		char *scmsg;

		if ((scmsg = (char *)malloc(ip6optlen)) == 0)
			errx(1, "can't allocate enough memory");
		msg.msg_control = (caddr_t)scmsg;
		msg.msg_controllen = ip6optlen;
		cmsgp = (struct cmsghdr *)scmsg;
	}

	if (argc == 0)
		usage();

	if (hlimp != NULL) {
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_HOPLIMIT;

		/* I believe there should be no alignment problem here */
		*(int *)CMSG_DATA(cmsgp) = hlim;
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (hbhlen > 0) setopthdr(hbhlen, IPV6_HOPOPTS);
	if (dsthdr1len > 0) setopthdr(dsthdr1len, IPV6_RTHDRDSTOPTS);
	if (dsthdr2len > 0) setopthdr(dsthdr2len, IPV6_DSTOPTS);
	if (argc > 1) {
		struct ip6_rthdr *rthdr;
		struct in6_addr middle;

		cmsgp->cmsg_len = CMSG_LEN(rthlen);
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_RTHDR;
		rthdr = (struct ip6_rthdr *)CMSG_DATA(cmsgp);

		rthdr = inet6_rth_init((void *)rthdr, rthlen,
				       IPV6_RTHDR_TYPE_0, argc - 1);
		if (rthdr == NULL)
			errx(1, "can't initialize rthdr");
		
		inet6_rth_init((void *)rthdr, rthlen, IPV6_RTHDR_TYPE_0, hops);

		for (i = 0; i < hops; i++) {
			inet_pton(AF_INET6, argv[i], &middle);

			if (inet6_rth_add(rthdr, &middle))
				errx(1, "inet6_rth_add failed");
		}

		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	finaldst = argv[argc - 1];

	if (strcmp(portstr, "echo") == 0) {
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)databuf;

		socktype = SOCK_RAW;
		proto = IPPROTO_ICMPV6;
		portstr = NULL;

		icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = socktype;
	hints.ai_protocol = proto;

	error = getaddrinfo(finaldst, portstr, &hints, &res);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));
	if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol))
	    < 0)
		err(1, "socket");

	if (mflag) {
		int on = 1;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPATHMTU, &on,
			       sizeof(on)) != 0)
			err(1, "setsockopt(IPV6_RECVPATHMTU)");
	}

	if (minmtu) {
		int on = 1;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &on,
			       sizeof(on)) != 0)
			err(1, "setsockopt(IPV6_USE_MIN_MTU)");
	}

#if 0
	bzero(&local, sizeof(local));
	local.sin6_family = AF_INET6;
	if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0)
		err(1, "bind");
#endif

	msg.msg_name = (void *)res->ai_addr;
	msg.msg_namelen = res->ai_addrlen;
	msgiov.iov_base = (void *)databuf;
	msgiov.iov_len = datalen;
	msg.msg_iov = &msgiov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	if (sendmsg(s, &msg, 0) != datalen)
		err(1, "sendmsg");

	freeaddrinfo(res);

	if (mflag) {
		int cc;		/* almost unused */
		struct sockaddr_storage ss_from;
		u_char cbuf[1024]; /* XXX: do not hardcode */

		memset(&msg, 0, sizeof(msg));
		msg.msg_name = (caddr_t)&ss_from;
		msg.msg_namelen = sizeof(ss_from);
		msg.msg_control = (caddr_t)cbuf;
		msg.msg_controllen = sizeof(cbuf);
		msgiov.iov_base = (void *)databuf;
		msgiov.iov_len = datalen;
		msg.msg_iov = &msgiov;
		msg.msg_iovlen = 1;

		if ((cc = recvmsg(s, &msg, 0)) < 0)
			err(1, "recvmsg");

		print_options(&msg);
	}

	exit(0);
}

static int
calc_opthlen(optlen)
	int optlen;
{
	int opthlen;

	if ((opthlen = inet6_opt_init(NULL, 0)) == -1)
		errx(1, "inet6_opt_init(NULL) failed");
	if ((opthlen = inet6_opt_append(NULL, 0, opthlen,
					10, /* dummy opt */
					optlen, 1,
					NULL)) == -1)
		errx(1, "inet6_opt_append(NULL, %d)", optlen);
	if ((opthlen = inet6_opt_finish(NULL, 0, opthlen)) == -1)
		errx(1, "inet6_opt_finish(NULL, %d)", opthlen);

	return(opthlen);
}

static void
setopthdr(optlen, hdrtype)
	int optlen, hdrtype;
{
	int i, opthlen = 0, curlen;
	char *hdrbuf, *optbuf;
	void *optp = NULL;

	opthlen = calc_opthlen(optlen);	/* XXX: duplicated calculation */
	cmsgp->cmsg_len = CMSG_LEN(opthlen);
	cmsgp->cmsg_level = IPPROTO_IPV6;
	cmsgp->cmsg_type = hdrtype;
	hdrbuf = CMSG_DATA(cmsgp);

	if ((curlen = inet6_opt_init(hdrbuf, opthlen)) == -1)
		errx(1, "inet6_opt_init(opth, %d)", opthlen);
	if ((curlen = inet6_opt_append(hdrbuf, opthlen, curlen,
				       10, /* dummy */
				       optlen, 1, &optp)) == -1)
		errx(1, "inet6_opt_append (cur=%d, optlen=%d, opthlen=%d)",
		     curlen, optlen, opthlen);
	/* make option buffer */
	if ((optbuf = malloc(optlen)) == NULL)
		err(1, "memory allocation for option buffer failed");
	for (i = 0; i < optlen; i++)
		optbuf[i] = i % 256;
	(void)inet6_opt_set_val(optp, 0, (void *)optbuf, optlen);
	if (inet6_opt_finish(hdrbuf, opthlen, curlen) == -1)
		errx(1, "inet6_opt_finish(opthlen=%d, curlen=%d)",
		     opthlen, curlen);

	free(optbuf);

	cmsgp = CMSG_NXTHDR(&msg, cmsgp);
}

static void
usage()
{
	fprintf(stderr, "usage: sender [-d optlen] [-D optlen] [-h optlen] "
		"[-l hoplimit] [-m] [-p port] [-s packetsize] "
		"IPv6addrs...\n");
	exit(1);
}
