/*
 * Copyright (C) 1999 WIDE Project.
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

/*	$Id: mpsend.c,v 1.1.1.1 1999/12/06 06:26:33 jinmei Exp $	*/

#include "mping.h"

double interval = DEFAULT_INTERVAL;
int size = DEFAULT_SIZE;
int hlim = DEFAULT_HOPLIMIT;
char *port = DEFAULT_PORT;
char *ifname = NULL;		/* no default interface this time */
char *maddr = NULL;		/* no default multicast address this time */
int count = 0;
int verbose = 0;
char *argv0;

void usage __P((void));

void
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	int s, error;
	int int_sec, int_usec;
	u_char *buf, *p;
	struct addrinfo hints, *res;
	struct timeval tp;
	struct mping *mp;

	argv0 = *argv;
	while ((ch = getopt(argc, argv, "c:i:l:m:p:t:s:v")) != -1)
		switch (ch) {
		case 'c':
			count = atoi(optarg);
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'l':
			hlim = atoi(optarg);
			break;
		case 'm':
			maddr = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 't':
			interval = atof(optarg);
			break;
		case 's':
			size = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			exit(-1);
		}
	argc -= optind;
	argv += optind;

	if (maddr == NULL) {
		fprintf(stderr, "need to specify destination address\n");
		exit(-1);
	}
	if (size < sizeof(struct mping))
		size = sizeof(struct mping);
	if (size > MAX_MSGSIZE)
		size = MAX_MSGSIZE;

	if (verbose) {
		fprintf(stderr, "%s current config is as follows:\n", argv0);
		fprintf(stderr, "\tifname:      %s\n", ifname);
		fprintf(stderr, "\tmaddr:       %s\n", maddr);
		fprintf(stderr, "\thlim:        %d\n", hlim);
		fprintf(stderr, "\tport:        %s\n", port);
		fprintf(stderr, "\tinterval:    %f\n", interval);
		fprintf(stderr, "\tsize:        %d\n", size);
		fprintf(stderr, "\tcount:       %d\n", count);
	}

	if (interval < 1.0 && getuid() != 0) {
		fprintf(stderr, "Only superuser can specify interval smaller than 1 second\n");
		exit(-1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	if ((error = getaddrinfo(maddr, port, &hints, &res)) != 0)
		err(1, "%s", gai_strerror(error));
	if (verbose) {
		u_char *p;
		int i;

		fprintf(stderr, "\tai_family:   %d\n", res->ai_family);
		fprintf(stderr, "\tai_socktype: %d\n", res->ai_socktype);
		fprintf(stderr, "\tai_protocol: %d\n", res->ai_protocol);
		fprintf(stderr, "\tai_addrlen:  %d\n", res->ai_addrlen);
		fprintf(stderr, "\tai_addr:     ");
		for (p = (u_char *)res->ai_addr, i = res->ai_addrlen; i;
			i--, p++) {
			fprintf(stderr, "%02x ", *p);
			if (i == 21)
				fprintf(stderr, "\n\t\t     ");
		}
		fprintf(stderr, "\n");
	}

	if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol))
		< 0) 
		err(1, "%s", strerror(errno));

	if (IN6_IS_ADDR_MULTICAST(&(((struct sockaddr_in6 *)(res->ai_addr))->sin6_addr))) {
		int ifindex;

		if (ifname == NULL) {
			fprintf(stderr, "need to specify ifname for multicast\n");
			exit(-1);
		}
		ifindex = if_nametoindex(ifname);
		if (verbose)
			fprintf(stderr, "\tifindex   : %d\n", ifindex);
		error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				&ifindex, sizeof(ifindex));
		if (error < 0)
			err(1, "setsockopt(IPV6_MULTICAST_IF)");
		error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			&hlim, sizeof(hlim));
		if (error < 0)
			err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
	}
	if ((buf = (u_char *)malloc(size)) == NULL)
		err(1, NULL);
	mp = (struct mping *)buf;

	if (gettimeofday(&tp, NULL) < 0)
		err(1, NULL);
	srandom(tp.tv_sec + tp.tv_usec);
	mp->m_sessid = random();
	fprintf(stderr, "session id: %ld (%08lx)\n",
		mp->m_sessid, mp->m_sessid);
	mp->m_seq = 0;
	for (p = buf + sizeof(struct mping); p < buf + size; p++)
		*p = (buf - p) & 0xff;
	int_sec = (int)interval;
	int_usec = (int)((interval - (double)int_sec) * 1000000);
	mp->m_interval.tv_sec = int_sec;
	mp->m_interval.tv_usec = int_usec;

	if (verbose == 0)
		daemon(0, 0);

	while (1) {
		if (verbose)
			fprintf(stderr, "sending %d bytes\n", size);
		error = sendto(s, buf, size, 0, res->ai_addr, res->ai_addrlen);
		if (error < 0)
			err(1, "sendto");
		if (count > 0 && --count == 0)
			break;
		mp->m_seq++;
		if (int_sec > 0)
			sleep(int_sec);
		if (int_usec > 0)
			usleep(int_usec);
	}
	freeaddrinfo(res);
	exit(0);
}

void
usage()
{
	fprintf(stderr, "%s [-c count][-l hoplimit][-p port][-s size][-t interval][-v] -i interface -m mcastaddr\n", argv0);
}
