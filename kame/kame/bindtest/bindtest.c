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
 * $Id: bindtest.c,v 1.7 1999/10/06 08:08:22 itojun Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <netinet/in.h>

int main __P((int, char **));
static void usage __P((void));
static struct addrinfo *getres __P((int, const char *, const char *));
static const char *printres __P((struct addrinfo *));
static int test __P((const char *, struct addrinfo *, struct addrinfo *));

static struct addrinfo *wild4, *wild6;
static struct addrinfo *loop4, *loop6;
static struct addrinfo *one4, *map4;
static char *port = NULL;
static int socktype = SOCK_DGRAM;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	extern int optind;
	extern char *optarg;

	while ((ch = getopt(argc, argv, "p:t")) != EOF) {
		switch (ch) {
		case 'p':
			port = strdup(optarg);
			break;
		case 't':
			socktype = SOCK_STREAM;
			break;
		default:
			usage();
			exit(1);
		}
	}

#if 0
	if (port == NULL)
		port = allocport();
#endif

	if (port == NULL) {
		errx(1, "no port specified");
		/*NOTREACHED*/
	}

	wild4 = getres(AF_INET, NULL, port);
	wild6 = getres(AF_INET6, NULL, port);
	loop4 = getres(AF_INET, "127.0.0.1", port);
	loop6 = getres(AF_INET6, "::1", port);
	one4 = getres(AF_INET, "0.0.0.1", port);
	map4 = getres(AF_INET6, "::ffff:127.0.0.1", port);

	printf("starting tests, socktype = %s\n",
		socktype == SOCK_DGRAM ? "SOCK_DGRAM" : "SOCK_STREAM");
#define TESTIT(x, y)	test(#x " then " #y, (x), (y))
#define TESTALL(x) \
do { \
	TESTIT(x, wild4); \
	TESTIT(x, wild6); \
	TESTIT(x, loop4); \
	TESTIT(x, loop6); \
	TESTIT(x, one4); \
	TESTIT(x, map4); \
} while (0)

	TESTALL(wild4);
	TESTALL(wild6);
	TESTALL(loop4);
	TESTALL(loop6);
	TESTALL(one4);
	TESTALL(map4);

	exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: bindtest [-t] -p port\n");
}

static struct addrinfo *
getres(af, host, port)
	int af;
	const char *host;
	const char *port;
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(host, port, &hints, &res);
	return res;
}

static const char *
printres(res)
	struct addrinfo *res;
{
	char hbuf[MAXHOSTNAMELEN], pbuf[10];
	static char buf[sizeof(hbuf) + sizeof(pbuf)];

	getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf),
		pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	snprintf(buf, sizeof(buf), "%s/%s", hbuf, pbuf);
	return buf;
}

static int
test(title, a, b)
	const char *title;
	struct addrinfo *a;
	struct addrinfo *b;
{
	int sa = -1, sb = -1;

	printf("%s\n", title);

#if 0
	printf("\tallocating socket for %s\n", printres(a));
#endif
	sa = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (sa < 0) {
		printf("\tfailed socket for %s, %s\n",
			printres(a), strerror(errno));
		goto fail;
	}
#if 0
	printf("\tallocating socket for %s\n", printres(b));
#endif
	sb = socket(b->ai_family, b->ai_socktype, b->ai_protocol);
	if (sb < 0) {
		printf("\tfailed socket for %s, %s\n",
			printres(b), strerror(errno));
		goto fail;
	}

	printf("\tbind socket for %s\n", printres(a));
	if (bind(sa, a->ai_addr, a->ai_addrlen) < 0) {
		printf("\tfailed bind for %s, %s\n",
			printres(a), strerror(errno));
		goto fail;
	}

	printf("\tbind socket for %s\n", printres(b));
	if (bind(sb, b->ai_addr, b->ai_addrlen) < 0) {
		printf("\tfailed bind for %s, %s\n",
			printres(b), strerror(errno));
		goto fail;
	}

	if (sa >= 0)
		close(sa);
	if (sb >= 0)
		close(sb);
	return 0;

fail:
	if (sa >= 0)
		close(sa);
	if (sb >= 0)
		close(sb);
	return -1;
}
