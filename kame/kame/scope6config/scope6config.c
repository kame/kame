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
#include <sys/ioctl.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int i, s, ch;
	struct in6_ifreq ifreq;
	u_int32_t linkid = 0, siteid = 0, orgid = 0;

	while ((ch = getopt(argc, argv, "l:s:o:")) != -1) {
		switch(ch) {
		case 'l':
			linkid = atoi(optarg);
			break;
		case 's':
			siteid = atoi(optarg);
			break;
		case 'o':
			orgid = atoi(optarg);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr,
			"usage: scope6config [-l linkid] [-s siteid] "
			"[-o orgid] ifname\n");
		exit(1);
	}

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, argv[0], sizeof(ifreq.ifr_name));

	if (linkid || siteid || orgid) {
		ifreq.ifr_ifru.ifru_scope_id[2] = linkid;
		ifreq.ifr_ifru.ifru_scope_id[5] = siteid;
		ifreq.ifr_ifru.ifru_scope_id[8] = orgid;
		if (ioctl(s, SIOCSSCOPE6, (caddr_t)&ifreq) < 0)
			err(1, "ioctl(SIOCSSCOPE6)");
	}

	if (ioctl(s, SIOCGSCOPE6, (caddr_t)&ifreq) < 0)
		err(1, "ioctl(SIOCGSCOPE6)");

	for (i = 0; i < 16; i++)
		printf("%d, ", ifreq.ifr_ifru.ifru_scope_id[i]);

	putchar('\n');

	exit(0);
}
