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
 *    without loop prior written permission.
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
/*
 * $Id: libtest.c,v 1.1 1999/10/26 05:51:54 itojun Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <netinet/in.h>
#include <arpa/inet.h>

int main __P((int, char **));
static void usage __P((void));
static int test_pton __P((void));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	extern int optind;
	extern char *optarg;
	int failure = 0;

	while ((ch = getopt(argc, argv, "")) != EOF) {
		switch (ch) {
		default:
			usage();
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage();
		exit(1);
	}

	failure += test_pton();
	printf("%d failure%s\n", failure, failure > 1 ? "s" : "");
	exit(failure);
}

static void
usage()
{
	fprintf(stderr, "usage: libtest\n");
}

static int
test_pton()
{
	struct in6_addr a;

	/* test for broken inet_pton() (pre BIND82) */
	switch (inet_pton(AF_INET6, "0:1:2:3:4:5:6:7:", &a)) {
	case 1:
		break;
	case 0:
		return 0;	/* fine */
	case -1:
		break;
	default:
		break;
	}

	printf("the OS has broken inet_pton()\n");
	return 1;
}
