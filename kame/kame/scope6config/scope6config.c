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
#include <sys/queue.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif

#include <netinet/in.h>
#include <netinet6/in6_var.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <ifaddrs.h>

static int scopeconfig __P((const char *, u_int32_t, u_int32_t, u_int32_t));
static int print_default __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	u_int32_t linkid = 0, siteid = 0, orgid = 0;
	int aflag = 0;
	int error;
	struct ifaddrs *ifap, *ifa;

	while ((ch = getopt(argc, argv, "al:s:o:")) != -1) {
		switch(ch) {
		case 'a':
			aflag++;
			break;
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

	if ((aflag && argc != 0) || (!aflag && argc != 1)) {
		fprintf(stderr,
			"usage: scope6config [-l linkid] [-s siteid] "
			"[-o orgid] interface\n");
		fprintf(stderr,
			"       scope6config default\n");
		fprintf(stderr,
			"       scope6config -a\n");
		exit(1);
	}

	if (argc > 0 && strcasecmp(argv[0], "default") == 0)
		error = print_default();
	else if (!aflag)
		error = scopeconfig(argv[0], linkid, siteid, orgid);
	else {
		const char *prev;

		if (getifaddrs(&ifap) != 0) {
			err(1, "getifaddrs");
			/*NOTREACHED*/
		}

		prev = NULL;
		error = 0;
		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			if (prev && strcmp(prev, ifa->ifa_name) == 0)
				continue;
			error = scopeconfig(ifa->ifa_name, 0, 0, 0);
			if (error)
				break;
			prev = ifa->ifa_name;
		}
		freeifaddrs(ifap);
	}
	exit(error);
}

static int
scopeconfig(name, linkid, siteid, orgid)
	const char *name;
	u_int32_t linkid;
	u_int32_t siteid;
	u_int32_t orgid;
{
	struct in6_ifreq ifreq;
	int i, s;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name));

	if (linkid || siteid || orgid) {
		ifreq.ifr_ifru.ifru_scope_id[2] = linkid;
		ifreq.ifr_ifru.ifru_scope_id[5] = siteid;
		ifreq.ifr_ifru.ifru_scope_id[8] = orgid;
		if (ioctl(s, SIOCSSCOPE6, (caddr_t)&ifreq) < 0)
			err(1, "ioctl(SIOCSSCOPE6)");
	}

	if (ioctl(s, SIOCGSCOPE6, (caddr_t)&ifreq) < 0)
		err(1, "ioctl(SIOCGSCOPE6)");

	printf("%s:", name);
	for (i = 0; i < 16; i++)
		printf("%s %d", i ? "," : "", ifreq.ifr_ifru.ifru_scope_id[i]);

	putchar('\n');

	close(s);
	return 0;
}

static int
print_default()
{
	struct in6_ifreq ifreq;
	int s, i;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, "lo0", sizeof(ifreq.ifr_name));	/* lo0 is dummy */

	if (ioctl(s, SIOCGSCOPE6DEF, (caddr_t)&ifreq) < 0)
		err(1, "ioctl(SIOCGSCOPE6DEF)");

	printf("default:");
	for (i = 0; i < 16; i++)
		printf("%s %d", i ? "," : "", ifreq.ifr_ifru.ifru_scope_id[i]);

	putchar('\n');

	close(s);
	return 0;
}
