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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <netinet/ip6.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#define DEFPORT 9079

void usage();

int
main(argc, argv)
    int argc;
    char *argv[];
{
	int i, s;
	char *finaldst;
	struct sockaddr_in6 local, remote;
	struct in6_addr middle;
	struct cmsghdr *cmsgp;
	struct msghdr msg;
	struct iovec msgiov;
	void *ptr;
	char *e, *databuf;
	int datalen = 1, ch;
	extern int optind;
	extern void *malloc();
	extern char *optarg;

	while ((ch = getopt(argc, argv, "s:")) != EOF)
		switch(ch) {
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

	if ((databuf = (char *)malloc(datalen)) == 0)
		errx(1, "can't allocate memory\n");

	memset(&msg, 0, sizeof(msg));

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		exit(-1);
	}

	if (argc == 0)
		usage();

	if (argc > 1) {
		if ((ptr = malloc(inet6_rthdr_space(IPV6_RTHDR_TYPE_0, argc - 1))) == 0) {
			fprintf(stderr, "sender: can't alloca memory\n");
			exit(1);
		}
		if ((cmsgp = inet6_rthdr_init(ptr, IPV6_RTHDR_TYPE_0)) == 0) {
			fprintf(stderr, "sender: can't initialize rthdr.\n");
			exit(1);
		}
		for (i = 0; i < argc - 1; i++) {
			inet_pton(AF_INET6, argv[i], &middle);
			if (inet6_rthdr_add(cmsgp, &middle, IPV6_RTHDR_STRICT)) {
				fprintf(stderr, "sender: can't add a node\n");
				exit(1);
			}
		}
		if (inet6_rthdr_lasthop(cmsgp, IPV6_RTHDR_STRICT)) {
			fprintf(stderr, "sender: can't set the last flag.\n");
			exit(1);
		}
		msg.msg_control = (caddr_t)cmsgp;
		msg.msg_controllen = ALIGN(cmsgp->cmsg_len);
	}
	finaldst = argv[argc - 1];

	remote.sin6_family = AF_INET6;
	remote.sin6_port =  DEFPORT;
	inet_pton(AF_INET6, finaldst, &remote.sin6_addr);

	bzero(&local, sizeof(local));
	local.sin6_family = AF_INET6;

	if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0){
		perror("bind");
		exit(-1);
	}

	msg.msg_name = (void *)&remote;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msgiov.iov_base = (void *)databuf;
	msgiov.iov_len = datalen;
	msg.msg_iov = &msgiov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	if (sendmsg(s, &msg, 0) != datalen) {
		perror("sendmsg");
		exit(-1);
	}

	exit(0);
}

void
usage()
{
	fprintf(stderr, "usage: sender [-s packetsize] IPv6addrs...\n");
	exit(1);
}
