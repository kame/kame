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
 * $Id: libtest.c,v 1.6 1999/11/03 20:13:53 itojun Exp $
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
static int test_getnameinfo __P((void));
static int test_getnameinfo0 __P((const struct sockaddr *, const char *,
	const char *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	extern int optind;
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
	failure += test_getnameinfo();

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
#define FUNCNAME	"test_pton"
	struct in6_addr a;
	int success = 0;

	/* test for broken inet_pton() (pre BIND82) */
	if (inet_pton(AF_INET6, "0:1:2:3:4:5:6:7:", &a) == 0)
		success++;
	else
		printf("%s: test 1 failed\n", FUNCNAME);
	if (inet_pton(AF_INET6, "0:1:2:3:4:5:6:7@", &a) == 0)
		success++;
	else
		printf("%s: test 2 failed\n", FUNCNAME);

	if (success != 2) {
		printf("the OS has broken inet_pton()\n");
		return 1;
	} else
		return 0;
#undef FUNCNAME
}

static int
test_getnameinfo()
{
#if 1
	struct sockaddr_storage ss;
#else
	struct {
		char buf[128];
	} ss;
#endif
	struct sockaddr *sa;
	struct sockaddr_in *sin;

	sa = (struct sockaddr *)&ss;
	sin = (struct sockaddr_in *)&ss;
	memset(sin, 0, sizeof(*sin));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ntohl(0x7f000001);
	sin->sin_port = ntohs(9876);

	return test_getnameinfo0(sa, "127.0.0.1", "9876");
}

static int
test_getnameinfo0(sa, hans, pans)
	const struct sockaddr *sa;
	const char *hans;
	const char *pans;
{
#define FUNCNAME	"test_getnameinfo"
	char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
	int i, j, k, l;
	int fail;
	int ntest;

	fail = 0;
	ntest = 0;

	/*
	 * host/serv with NULL, or hostlen/servlen with 0, should not
	 * raise any error.
	 */
	for (i = 0; i < 3 * 3; i++) {
		/* the initialization here is for fool too-picky gcc setting */
		char *h = NULL, *p = NULL;
		int hl = 0, pl = 0;

		switch (i % 3) {
		case 0:	h = hbuf; hl = 0; break;
		case 1:	h = NULL; hl = sizeof(hbuf); break;
		case 2:	h = NULL; hl = 0; break;
		}
		switch ((i / 3) % 3) {
		case 0:	p = pbuf; pl = 0; break;
		case 1:	p = NULL; pl = sizeof(pbuf); break;
		case 2:	p = NULL; pl = 0; break;
		}
		ntest++;
		if (getnameinfo(sa, sa->sa_len, h, hl, p, pl,
				NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
			printf("%s: test %d failed\n", FUNCNAME, ntest);
			fail++;
		}

	}

	/* success case: it should return correct result */
	ntest++;
	memset(hbuf, 0, sizeof(hbuf));
	memset(pbuf, 0, sizeof(pbuf));
	if (getnameinfo(sa, sa->sa_len, hbuf, sizeof(hbuf), pbuf, sizeof(pbuf),
			NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		if (strcmp(hans, hbuf) == 0 && strcmp(pans, pbuf) == 0) {
			;
		} else {
			printf("%s: test %d failed with %s/%s\n", FUNCNAME,
				ntest, hbuf, pbuf);
		}
	} else {
		printf("%s: test %d failed\n", FUNCNAME, ntest);
	}

	/*
	 * RFC2553/X-open getnameinfo spec on short buffer.
	 * RFC2553 behavior - should raise error if the room is not enough.
	 * X/open behavior - caller must supply enough buffer.
	 */
	ntest++;
	j = k = l = 0;
	for (i = 1; i < strlen(hans); i++) {
		memset(hbuf, 0, sizeof(hbuf));
		if (getnameinfo(sa, sa->sa_len, hbuf, i, NULL, 0,
				NI_NUMERICHOST) != 0) {
			/* RFC2553 */
			j++;
		} else {
			if (strncmp(hans, hbuf, strlen(hbuf)) == 0) {
				/* X/open */
				k++;
			} else {
				printf("%s: test %d failed with len=%d\n",
					FUNCNAME, ntest, i);
				fail++;
			}
		}
		l++;
	}
	for (i = 1; i < strlen(pans); i++) {
		memset(pbuf, 0, sizeof(pbuf));
		if (getnameinfo(sa, sa->sa_len, NULL, 0, pbuf, i,
				NI_NUMERICSERV) != 0) {
			/* RFC2553 */
			j++;
		} else {
			if (strncmp(pans, pbuf, strlen(pbuf)) == 0) {
				/* X/open */
				k++;
			} else {
				printf("%s: test %d failed with len=%d\n",
					FUNCNAME, ntest, i);
				fail++;
			}
		}
		l++;
	}
	if (j == l && k == 0)
		printf("%s: RFC2553 behavior on short buffer\n", FUNCNAME);
	else if (j == 0 && k == l)
		printf("%s: X/open behavior on short buffer\n", FUNCNAME);
	else {
		printf("%s: test %d failed - random behavior (%d/%d)\n",
			FUNCNAME, ntest, j, k);
		fail++;
	}

	return fail ? 1 : 0;
#undef FUNCNAME
}
