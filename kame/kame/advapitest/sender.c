/*	$KAME: sender.c,v 1.34 2004/04/05 12:46:39 suz Exp $ */
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

int dsthdr1len = -1, dsthdr2len = -1, hbhlen = -1;
int stickydsthdr1len = -1, stickydsthdr2len = -1, stickyhbhlen = -1;
char *hlimp, *stickyhlimp, *basicapihlimp;
char *tclassp, *stickytclassp;
int hlim, tclass;

struct msghdr msg;
struct sockaddr *sa_next, *sticky_sa_next;
int nextlen = 0, stickynextlen = 0;
struct sockaddr_storage ss_next, sticky_ss_next;
struct cmsghdr *cmsgp = NULL;

static int calc_opthlen __P((int));
static void setopthdr __P((int, int, char *));
static void usage __P((void));
static int Pflag, mflag, cflag;

#ifndef IPV6_MINMTU
#define IPV6_MINMTU 1280
#endif

int
main(argc, argv)
    int argc;
    char *argv[];
{
	int i, s, isconnected = 0;
	int rthlen = 0, ip6optlen = 0, hops = 0, error;
	char *portstr = DEFAULTPORT;
	char *finaldst;
	char *nexthop = NULL, *stickynexthop = NULL;
	char *tempaddrp = NULL, *stickytempaddrp = NULL;
	int tempaddr;
	struct iovec msgiov;
	char *e, *databuf, *stickybuf;
	int stickylen;
	int datalen = 1, ch;
	int Mflag = 0, sMflag = 0;
	int minmtu, stickyminmtu;
	int dontfrag = -1, stickydontfrag = -1;
	struct addrinfo hints, *res;
	extern int optind;
	extern void *malloc();
	int sticky = 0;
	int socktype = SOCK_DGRAM;
	int proto = IPPROTO_UDP;
	int verbose = 0;

#define STICKYCHECK \
	do { \
		sticky = 0; \
		if (strcmp("sticky", optarg) == 0) { \
			optarg = argv[optind++]; \
			if (optarg == NULL || *optarg == '-') \
				 usage(); \
			sticky = 1; \
		} \
	} while (0)

	while ((ch = getopt(argc, argv, "cD:d:f:h:l:L:M:mn:Pp:s:t:T:v")) != -1)
		switch(ch) {
		case 'c':
			cflag++;
			break;
		case 'D':
			STICKYCHECK;
			if (sticky)
				stickydsthdr1len = atoi(optarg);
			else
				dsthdr1len = atoi(optarg);
			break;
		case 'd':
			STICKYCHECK;
			if (sticky)
				stickydsthdr2len = atoi(optarg);
			else
				dsthdr2len = atoi(optarg);
			break;
		case 'f':
			STICKYCHECK;
			if (sticky)
				stickydontfrag = atoi(optarg);
			else
				dontfrag = atoi(optarg);
			break;
		case 'h':
			STICKYCHECK;
			if (sticky)
				stickyhbhlen = atoi(optarg);
			else
				hbhlen = atoi(optarg);
			break;
		case 'l':
			STICKYCHECK;
			if (sticky)
				stickyhlimp = optarg;
			else
				hlimp = optarg;
			break;
		case 'L':
			basicapihlimp = optarg;
			break;
		case 'M':
			STICKYCHECK;
			if (sticky) {
				sMflag++;
				if (*optarg == 'd')
					stickyminmtu = -1;
				else
					stickyminmtu = atoi(optarg);
			} else {
				Mflag++;
				if (*optarg == 'd')
					minmtu = -1;
				else
					minmtu = atoi(optarg);
			} break;
		case 'm':
 			mflag++;
			break;
		case 'n':
			STICKYCHECK;
			if (sticky)
				stickynexthop = optarg;
			else
				nexthop = optarg;
			break;
		case 'P':
			Pflag++;
			break;
		case 'p':
			portstr = optarg;
			break;
		case 's':
			datalen = strtol(optarg, &e, 10);
			if (datalen <= 0 || *optarg == '\0' || *e != '\0')
				errx(1, "illegal datalen value -- %s", optarg);
			break;
		case 't':
			STICKYCHECK;
			if (sticky)
				stickytclassp = optarg;
			else
				tclassp = optarg;
			break;
		case 'T':
			STICKYCHECK;
			if (sticky)
				stickytempaddrp = optarg;
			else
				tempaddrp = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
#undef STICKYCHECK
	argc -= optind;
	argv += optind;

	memset(&msg, 0, sizeof(msg));

	if ((databuf = (char *)malloc(datalen)) == 0)
		errx(1, "can't allocate memory\n");
	memset(databuf, 0, sizeof(datalen));

	if (hbhlen >= 0) ip6optlen += CMSG_SPACE(calc_opthlen(hbhlen));
	if (dsthdr1len >= 0) ip6optlen += CMSG_SPACE(calc_opthlen(dsthdr1len));
	if (dsthdr2len >= 0) ip6optlen += CMSG_SPACE(calc_opthlen(dsthdr2len));
	if (hlimp != NULL) {
		hlim = atoi(hlimp);
#if 0
		/* intentionally omit the check to see the kernel behavior. */
		if (hlim < 0 || hlim > 255)
			errx(1, "invalid hop limit: %d", hlim);
#endif
		ip6optlen += CMSG_SPACE(sizeof(int));
	}
	if (dontfrag >= 0)
		ip6optlen += CMSG_SPACE(sizeof(int));
	if (Mflag)
		ip6optlen += CMSG_SPACE(sizeof(int));
	if (tclassp)
		ip6optlen += CMSG_SPACE(sizeof(int));
	if (tempaddrp)
		ip6optlen += CMSG_SPACE(sizeof(int));
#ifdef IPV6_NEXTHOP
	if (nexthop != NULL) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM; /* not used */
		hints.ai_protocol = IPPROTO_UDP; /* not used */
		error = getaddrinfo(nexthop, NULL, &hints, &res);
		if (error)
			errx(1, "getaddrinfo for nexthop: %s",
			     gai_strerror(error));
		memcpy(&ss_next, res->ai_addr, res->ai_addrlen);
		nextlen = res->ai_addrlen;
		sa_next = (struct sockaddr *)&ss_next;
		freeaddrinfo(res);

		ip6optlen += CMSG_SPACE(nextlen);
	}
	if (stickynexthop != NULL) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM; /* not used */
		hints.ai_protocol = IPPROTO_UDP; /* not used */
		error = getaddrinfo(stickynexthop, NULL, &hints, &res);
		if (error)
			errx(1, "getaddrinfo for sticky nexthop: %s",
			     gai_strerror(error));
		memcpy(&sticky_ss_next, res->ai_addr, res->ai_addrlen);
		stickynextlen = res->ai_addrlen;
		sticky_sa_next = (struct sockaddr *)&sticky_ss_next;
		freeaddrinfo(res);
	}
#endif
#ifdef IPV6_RTHDR_TYPE_0
	if (argc > 1) {		/* intermediate node(s) exist(s) */
		hops = argc - 1;
		rthlen = inet6_rth_space(IPV6_RTHDR_TYPE_0, hops);
		ip6optlen += CMSG_SPACE(rthlen);
	}
#endif
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

#ifdef IPV6_RTHDR
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
			if (inet_pton(AF_INET6, argv[i], &middle) != 1)
				errx(1, "invalid IPv6 address %s", argv[i]);
			if (inet6_rth_add(rthdr, &middle))
				errx(1, "inet6_rth_add failed");
		}

		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
#endif
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

	if (cflag && !isconnected) {
		if (connect(s, res->ai_addr, res->ai_addrlen))
			err(1, "connect");
		isconnected++;
	}

	if (verbose) {
		printf("default values of socket options: \n");
		dump_localopt(s, socktype, proto);
	}

#ifdef IPV6_HOPLIMIT
	if (hlimp != NULL) {
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_HOPLIMIT;

		/* I believe there should be no alignment problem here */
		*(int *)CMSG_DATA(cmsgp) = hlim;
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}

	/*
	 * RFC3542 obsoleted sticky hlim option, but we intentionally try
	 * to set this option to see what happens.
	 */
	if (stickyhlimp != NULL) {
		hlim = atoi(stickyhlimp);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_HOPLIMIT,
			       &hlim, sizeof(hlim))) {
			warn("setsockopt(IPV6_HOPLIMIT, %d)", hlim);
		}
	}

	/*
	 * If given, specify the hop limit value by the basic API.
	 * We ignore errors because we're testing for the advanced API.
	 */
	if (basicapihlimp != NULL) {
		hlim = atoi(basicapihlimp);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
		    &hlim, sizeof (hlim))) {
			warn("setsockopt(IPV6_UNICAST_HOPS, %d)", hlim);
		}
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		    &hlim, sizeof (hlim))) {
			warn("setsockopt(IPV6_MULTICAST_HOPS, %d)", hlim);
		}
	}
#endif
#ifdef IPV6_HOPOPTS
	if (hbhlen >= 0)
		setopthdr(hbhlen, IPV6_HOPOPTS, NULL);
	if (stickyhbhlen >= 0) {
		stickylen = calc_opthlen(stickyhbhlen);
		if ((stickybuf = malloc(stickylen)) == NULL)
			err(1, "malloc");
		setopthdr(stickyhbhlen, IPV6_HOPOPTS, stickybuf);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_HOPOPTS, stickybuf,
			       stickylen)) {
			warn("setsockopt(IPV6_HOPOPTS)");
		}
		free(stickybuf);
	}
#endif
#ifdef IPV6_RTHDRDSTOPTS
	if (dsthdr1len >= 0)
		setopthdr(dsthdr1len, IPV6_RTHDRDSTOPTS, NULL);
	if (stickydsthdr1len >= 0) {
		stickylen = calc_opthlen(stickydsthdr1len);
		if ((stickybuf = malloc(stickylen)) == NULL)
			err(1, "malloc");
		setopthdr(stickydsthdr1len, IPV6_RTHDRDSTOPTS, stickybuf);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_RTHDRDSTOPTS, stickybuf,
			       stickylen)) {
			warn("setsockopt(IPV6_RTHDRDSTOPTS)");
		}
		free(stickybuf);
	}
#endif
#ifdef IPV6_DSTOPTS
	if (dsthdr2len >= 0)
		setopthdr(dsthdr2len, IPV6_DSTOPTS, NULL);
	if (stickydsthdr2len >= 0) {
		stickylen = calc_opthlen(stickydsthdr2len);
		if ((stickybuf = malloc(stickylen)) == NULL)
			err(1, "malloc");
		setopthdr(stickydsthdr2len, IPV6_DSTOPTS, stickybuf);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_DSTOPTS, stickybuf,
			       stickylen)) {
			warn("setsockopt(IPV6_DSTOPTS)");
		}
		free(stickybuf);
	}
#endif
#ifdef IPV6_NEXTHOP
	if (sa_next != NULL) {
		cmsgp->cmsg_len = CMSG_LEN(nextlen);
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_NEXTHOP;
		memcpy(CMSG_DATA(cmsgp), sa_next, nextlen);
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (sticky_sa_next != NULL) {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_NEXTHOP, sticky_sa_next,
			       stickynextlen)) {
			warn("setsockopt(IPV6_NEXTHOP)");
		}
	}
#endif

#ifdef IPV6_RECVPATHMTU
	if (mflag) {
		int on = 1;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPATHMTU, &on,
			       sizeof(on)) != 0)
			err(1, "setsockopt(IPV6_RECVPATHMTU)");
	}
#endif

#ifdef IPV6_USE_MIN_MTU
	if (Mflag) {
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_USE_MIN_MTU;

		/* I believe there should be no alignment problem here */
		*(int *)CMSG_DATA(cmsgp) = minmtu;
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (sMflag) {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_USE_MIN_MTU,
			       &stickyminmtu, sizeof(int)) != 0) {
			err(1, "setsockopt(IPV6_USE_MIN_MTU)");
		}
	}
#endif

#ifdef IPV6_DONTFRAG
	if (dontfrag >= 0) {
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_DONTFRAG;

		/* I believe there should be no alignment problem here */
		*(int *)CMSG_DATA(cmsgp) = dontfrag;
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (stickydontfrag >= 0) {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, &stickydontfrag,
			       sizeof(int)) != 0)
			err(1, "setsockopt(IPV6_DONTFRAG)");
	}
#endif

#ifdef IPV6_TCLASS
	if (tclassp != NULL) {
		tclass = atoi(tclassp);
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_TCLASS;

		/* I believe there should be no alignment problem here */
		*(int *)CMSG_DATA(cmsgp) = tclass;
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (stickytclassp != NULL) {
		tclass = atoi(stickytclassp);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS,
			       &tclass, sizeof(tclass))) {
			warn("setsockopt(IPV6_TCLASS, %d)", tclass);
		}
	}
#endif

#ifdef IPV6_PREFER_TEMPADDR
	if (tempaddrp != NULL) {
		tempaddr = atoi(tempaddrp);
		cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = IPV6_PREFER_TEMPADDR;

		/* I believe there should be no alignment problem here */
		*(int *)CMSG_DATA(cmsgp) = tempaddr;
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (stickytempaddrp != NULL) {
		tempaddr = atoi(stickytempaddrp);
		if (setsockopt(s, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
		    &tempaddr, sizeof(tempaddr))) {
			warn("setsockopt(IPV6_PREFER_TEMPADDR, %d)", tempaddr);
		}
	}
#endif

#ifdef IPV6_PATHMTU
	if (Pflag) {
		struct ip6_mtuinfo mtuinfo;
		int optlen = sizeof(mtuinfo);

		if (!isconnected) {
			if (connect(s, res->ai_addr, res->ai_addrlen))
				errx(1, "connect");
			isconnected++;
		}
		if (getsockopt(s, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo,
			       &optlen)) {
			errx(1, "getsockopt(IPV6_PATHMTU)");
		}
		printf("Current path MTU is %ld\n", (long)mtuinfo.ip6m_mtu);
	}
#endif

	if (verbose) {
		printf("\nsocket option values after configuring them: \n");
		dump_localopt(s, socktype, proto);
	}

#if 0
	bzero(&local, sizeof(local));
	local.sin6_family = AF_INET6;
	if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0)
		err(1, "bind");
#endif

	if (!isconnected) {
		msg.msg_name = (void *)res->ai_addr;
		msg.msg_namelen = res->ai_addrlen;
	}
	msgiov.iov_base = (void *)databuf;
	msgiov.iov_len = datalen;
	msg.msg_iov = &msgiov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	if (sendmsg(s, &msg, 0) != datalen)
		err(1, "sendmsg");

	freeaddrinfo(res);

	if (mflag) {
		u_char cbuf[1024], recvbuf[1024]; /* XXX: do not hardcode */

		while(1) {
			int cc;
			struct sockaddr_storage ss_from;

			memset(&msg, 0, sizeof(msg));
			memset(&cbuf, 0, sizeof(cbuf));

			msg.msg_name = (caddr_t)&ss_from;
			msg.msg_namelen = sizeof(ss_from);
			msg.msg_control = (caddr_t)cbuf;
			msg.msg_controllen = sizeof(cbuf);
			msgiov.iov_base = (void *)recvbuf;
			msgiov.iov_len = sizeof(recvbuf);
			msg.msg_iov = &msgiov;
			msg.msg_iovlen = 1;

			if ((cc = recvmsg(s, &msg, 0)) < 0)
				err(1, "recvmsg");

			printf("received %d bytes from %s\n", cc,
			       ip6str((struct sockaddr_in6 *)&ss_from));

			print_options(&msg);
		}
	}

	exit(0);
}

static int
calc_opthlen(optlen)
	int optlen;
{
	int opthlen;

	if (optlen == 0)
		return(0);

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
setopthdr(optlen, hdrtype, hdrbuf)
	int optlen, hdrtype;
	char *hdrbuf;		/* sticky option if non NULL */
{
	int i, opthlen = 0, curlen;
	int sticky = (hdrbuf != NULL);
	char *optbuf;
	void *optp = NULL;

	opthlen = calc_opthlen(optlen);	/* XXX: duplicated calculation */
	if (!sticky) {
		cmsgp->cmsg_len = CMSG_LEN(opthlen);
		cmsgp->cmsg_level = IPPROTO_IPV6;
		cmsgp->cmsg_type = hdrtype;
		hdrbuf = CMSG_DATA(cmsgp);
	}

	if (optlen == 0)
		goto end;

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

  end:
	if (!sticky)
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
}

static void
usage()
{
	fprintf(stderr,
		"usage: sender [-c] (connect socket)\n"
		"              [-d dstoptlen] [-d sticky sticky_dstoptlen]\n"
		"              [-D rhdstoptlen] [-D sticky sticky_rhdstoptlen]\n"
		"              [-f (0|1)] [-f sticky (0|1)] (dontfrag flag)\n"
		"              [-h hbhoptlen] [-h sticky sticky_hbhoptlen]\n"
		"              [-l hoplimit] [-l sticky sticky_hoplimit]\n"
		"              [-L basicAPI_hoplimit]\n"
		"              [-m] (enable recvpathmtu)\n"
		"              [-M (d|0|1)] [-M sticky (d|0|1)] (minmtu flag)\n"
		"              [-n nexthop] [-n sticky sticky_nexthop]\n"
		"              [-P] (get current path MTU)\n"
		"              [-p portnum|\'echo\']\n"
		"              [-s packetsize]\n"
		"              [-t tclass] [-t sticky sticky_tclass]\n"
		"              [-T tempaddr] [-T sticky sticky_tempaddr]\n"
		"              [-v] (verbose output)\n"
		"              IPv6addrs...\n");
	exit(1);
}
