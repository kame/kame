/*	$KAME: bindtest.c,v 1.21 2001/05/08 01:59:11 jinmei Exp $	*/

/*
 * Copyright (C) 2000 USAGI/WIDE Project.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>

#include <netinet/in.h>

static struct testitem{
	const char *name;
	const int family;	/* sa_family_t is not widely defined */
	const char *host;
	struct addrinfo *res;
} testitems[] = {
	{ "wild4",	AF_INET,	NULL,			NULL },
	{ "wild6",	AF_INET6,	NULL,			NULL },
	{ "loop4",	AF_INET,	"127.0.0.1",		NULL },
	{ "loop6",	AF_INET6,	"::1",			NULL },
	{ "wildm",	AF_INET6,	"::ffff:0.0.0.0",	NULL },
	{ "loopm",	AF_INET6,	"::ffff:127.0.0.1",	NULL },
	{ "onem",	AF_INET6,	"::ffff:0.0.0.1",	NULL },
	{ "one4",	AF_INET,	"0.0.0.1",		NULL },
	{ NULL,		0,		NULL,			NULL }
};

int main __P((int, char **));
static void usage __P((void));
static struct addrinfo *getres __P((int, const char *, const char *));
static const char *printsa __P((struct sockaddr *, socklen_t));
static const char *printres __P((struct addrinfo *));
static int test __P((struct testitem *, struct testitem *));
static void sendtest __P((int, int, struct testitem *));
static void conntest __P((int, int, struct testitem *));

static char *port = NULL;
static int socktype = SOCK_DGRAM;
static int summary = 0;
static int reuseaddr = 0;
static int reuseport = 0;
static int connect1st = 0;
static int connect2nd = 0;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	extern char *optarg;
	struct testitem *testi, *testj;

	while ((ch = getopt(argc, argv, "12APp:st")) != EOF) {
		switch (ch) {
		case '1':
			connect1st = 1;
			break;
		case '2':
			connect2nd = 1;
			break;
		case 'A':
			reuseaddr = 1;
#ifndef SO_REUSEADDR
			errx(1, "SO_REUSEADDR is not supported");
#endif
			break;
		case 'P':
			reuseport = 1;
#ifndef SO_REUSEPORT
			errx(1, "SO_REUSEPORT is not supported");
#endif
			break;
		case 'p':
			port = strdup(optarg);
			break;
		case 's':
			summary = 1;
			break;
		case 't':
			socktype = SOCK_STREAM;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (connect1st && connect2nd) {
		fprintf(stderr, "-1 and -2 are exclusive.\n");
		exit(1);
	}

#if 0
	if (port == NULL)
		port = allocport();
#endif

	if (port == NULL) {
		usage();
		exit(1);
	}

	for (testi = testitems; testi->name; testi++) {
		testi->res = getres(testi->family, testi->host, port);
		if (!testi->res)
			errx(1, "getaddrinfo failed");
	}

	printf("starting tests, socktype = %s%s%s",
	    socktype == SOCK_DGRAM ? "SOCK_DGRAM" : "SOCK_STREAM",
	    reuseaddr ? ", SO_REUSEADDR" : "",
	    reuseport ? ", SO_REUSEPORT" : "");
	if (socktype == SOCK_STREAM && (connect1st != 0 || connect2nd != 0))
		printf(" , connect to %s", (connect1st != 0) ? "1st" : "2nd");
	putchar('\n');
	if (summary) {
		for (testi = testitems; testi->name; testi++)
			printf("\t%s", testi->name);
		printf("\n");
	}
	for (testi = testitems; testi->name; testi++) {
		if (summary)
			printf("%s:", testi->name);
		for (testj = testitems; testj->name; testj++)
			test(testi, testj);
		if (summary)
			printf("\n");
	}

	exit(0);
}

static void
usage()
{

	fprintf(stderr, "usage: bindtest [-[1|2]APst] -p port\n");
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
printsa(sa, salen)
	struct sockaddr *sa;
	socklen_t salen;
{
	char hbuf[MAXHOSTNAMELEN], pbuf[10];
	static char buf[sizeof(hbuf) + sizeof(pbuf)];

	getnameinfo(sa, salen, hbuf, sizeof(hbuf),
		pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	snprintf(buf, sizeof(buf), "%s/%s", hbuf, pbuf);

	return(buf);
}

static const char *
printres(res)
	struct addrinfo *res;
{
	return(printsa(res->ai_addr, res->ai_addrlen));
}

static int
test(t1, t2)
	struct testitem *t1;
	struct testitem *t2;
{
	struct addrinfo *a = t1->res;
	struct addrinfo *b = t2->res;
	int sa = -1, sb = -1;
	const int yes = 1;

	if (!summary)
		printf("%s then %s\n", t1->name, t2->name);

#if 0
	if (!summary)
		printf("\tallocating socket for %s\n", printres(a));
#endif
	sa = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (sa < 0) {
		if (summary)
			printf("\tfailed socket for %s, %s\n",
			       printres(a), strerror(errno));
		else
			printf("\t!1");
		goto fail;
	}
#if 0
	if (!summary)
		printf("\tallocating socket for %s\n", printres(b));
#endif
	sb = socket(b->ai_family, b->ai_socktype, b->ai_protocol);
	if (sb < 0) {
		if (!summary)
		 	printf("\tfailed socket for %s, %s\n",
			       printres(b), strerror(errno));
		else
			printf("\t!2");
		goto fail;
	}

#ifdef SO_REUSEADDR
	if (reuseaddr) {
		if (setsockopt(sa, SOL_SOCKET, SO_REUSEADDR, &yes,
		    sizeof(yes)) < 0) {
			if (!summary)
				printf("\tfailed setsockopt(SO_REUSEADDR) "
				    "for %s, %s\n", printres(a),
				    strerror(errno));
			else
				printf("\t?A");
			goto fail;
		}
		if (setsockopt(sb, SOL_SOCKET, SO_REUSEADDR, &yes,
		    sizeof(yes)) < 0) {
			if (!summary)
				printf("\tfailed setsockopt(SO_REUSEADDR) "
				    "for %s, %s\n", printres(b),
				    strerror(errno));
			else
				printf("\t!A");
			goto fail;
		}
	}
#endif

#ifdef SO_REUSEPORT
	if (reuseport) {
		if (setsockopt(sa, SOL_SOCKET, SO_REUSEPORT, &yes,
		    sizeof(yes)) < 0) {
			if (!summary)
				printf("\tfailed setsockopt(SO_REUSEPORT) "
				    "for %s, %s\n", printres(a),
				    strerror(errno));
			else
				printf("\t?P");
			goto fail;
		}
		if (setsockopt(sb, SOL_SOCKET, SO_REUSEPORT, &yes,
		    sizeof(yes)) < 0) {
			if (!summary)
				printf("\tfailed setsockopt(SO_REUSEPORT) "
				    "for %s, %s\n", printres(b),
				    strerror(errno));
			else
				printf("\t!P");
			goto fail;
		}
	}
#endif

	if (!summary)
		printf("\tbind socket for %s\n", printres(a));
	if (bind(sa, a->ai_addr, a->ai_addrlen) < 0) {
		if (!summary)
			printf("\tfailed bind for %s, %s\n",
			       printres(a), strerror(errno));
		else
			printf("\t?1(%d)", errno);
		goto fail;
	}

	if (!summary)
		printf("\tbind socket for %s\n", printres(b));
	if (bind(sb, b->ai_addr, b->ai_addrlen) < 0) {
		if (!summary)
			printf("\tfailed bind for %s, %s\n",
			       printres(b), strerror(errno));
		else {
			if (errno == EADDRINUSE)
				printf("\tx");
			else
				printf("\t?2(%d)", errno);
		}
		goto fail;
	}

	if (summary)
		printf("\to");

	if (summary)
		putchar('[');
	if (socktype == SOCK_DGRAM) {
		if (t1->host != NULL)
			sendtest(sa, sb, t1);
		else if (summary)
			putchar('-');
		if (t2->host != NULL)
			sendtest(sa, sb, t2);
		else if (summary)
			putchar('-');
	} else if (reuseaddr != 0 || reuseport != 0) {
		/*
		 * We skip the test unless the REUSExxx option(s) is specified.
		 * Otherwise, remaining TIME_WAIT sockets would prevent
		 * succeeding sockets from being bound.
		 */
		if (t1->host != NULL && connect1st)
			conntest(sa, sb, t1);
		else if (summary)
			putchar('-');
		if (t2->host != NULL && connect2nd)
			conntest(sa, sb, t2);
		else if (summary)
			putchar('-');
	}
	if (summary)
		putchar(']');

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

static void
sendtest(sa, sb, t)
	int sa, sb;
	struct testitem *t;
{
	int s = -1, maxfd;
	int i, cc, e;
	int recva = 0, recvb = 0;
	unsigned char buf[10], recvbuf[128];
	fd_set fdset, fdset0;
	struct timeval timo;
	struct sockaddr_storage ss;
	struct sockaddr *from = (struct sockaddr *)&ss;
	socklen_t fromlen;

	if ((s = socket(t->res->ai_family, t->res->ai_socktype,
			t->res->ai_protocol)) < 0) {
		if (!summary) {
			printf("\tfailed to open a socket for sending: %s\n",
			       strerror(errno));
		} else
			putchar('x');
		goto done;
	}
	if ((sendto(s, buf, sizeof(buf), 0, t->res->ai_addr,
		    t->res->ai_addrlen)) < 0) {
		if (!summary) {
			printf("\tfailed to send a packet to %s: %s\n",
			       printres(t->res), strerror(errno));
		} else
			putchar('x');
		goto done;
	} else if (!summary)
		printf("\tsend %d bytes to %s\n", sizeof(buf),
		       printres(t->res));

	FD_ZERO(&fdset0);
	FD_SET(sa, &fdset0);
	FD_SET(sb, &fdset0);
	maxfd = (sa > sb) ? sa : sb;
	timo.tv_sec = 1;
	timo.tv_usec = 0;

	for (i = 0; i < 2; i++) { /* try 2 times, just in case. */
		fdset = fdset0;
		if ((e = select(maxfd + 1, &fdset, NULL, NULL, &timo)) < 0) {
			if (!summary) {
				printf("\tfailed to select: %s\n",
				       strerror(errno));
			} else
				putchar('x');
			goto done;
		}
		if (e == 0)	/* timeout */
			break;
		if (FD_ISSET(sa, &fdset)) {
			fromlen = sizeof(ss);
			if ((cc = recvfrom(sa, recvbuf, sizeof(recvbuf), 0,
					   from, &fromlen)) < 0) {
				if (!summary) {
					printf("\tfailed to recvfrom on the "
					       "1st socket: %s\n",
					       strerror(errno));
				}
				else
					; /* ignore it */
			} else {
				if (!summary) {
					printf("\trecv %d bytes from %s on "
					       "the 1st socket\n",
					       cc, printsa(from, fromlen));
				} else
					recva++;
			}
		}
		if (FD_ISSET(sb, &fdset)) {
			fromlen = sizeof(ss);
			if ((cc = recvfrom(sb, recvbuf, sizeof(recvbuf), 0,
					   from, &fromlen)) < 0) {
				if (!summary) {
					printf("\tfailed to recvfrom on the "
					       "2nd socket: %s\n",
					       strerror(errno));
				}
				else
					; /* ignore it */
			} else {
				if (!summary) {
					printf("\trecv %d bytes from %s on "
					       "the 2nd socket\n",
					       cc, printsa(from, fromlen));
				} else
					recvb++;
			}
		}
	}

	if (summary) {
		if (recva && recvb)
			putchar('b');
		else if (recva)
			putchar('1');
		else if (recvb)
			putchar('2');
		else
			putchar('0');
	}

  done:
	if (s >= 0)
		close(s);
}

static void
conntest(sa, sb, t)
	int sa, sb;
	struct testitem *t;
{
	int s = -1, maxfd;
	int e;
	int recva = 0, recvb = 0;
	fd_set fdset, fdset0;
	struct timeval timo;
	struct sockaddr_storage ss;
	struct sockaddr *from = (struct sockaddr *)&ss;
	socklen_t fromlen;
	int flags;

	listen(sa, 5);
	listen(sb, 5);
	
	if ((s = socket(t->res->ai_family, t->res->ai_socktype,
			t->res->ai_protocol)) < 0) {
		if (!summary) {
			printf("\tfailed to open a socket for connecting: %s\n",
			       strerror(errno));
		} else
			putchar('x');
		goto done;
	}
	flags = fcntl(s, F_GETFL, 0);
	flags |= O_NONBLOCK;
	if (fcntl(s, F_SETFL, flags) < 0) {
		if (!summary) {
			printf("\tfailed to make connecting socket "
			       "non-blocking: %s\n", strerror(errno));
		} else
			putchar('x');
		goto done;
	}

	if ((connect(s, t->res->ai_addr, t->res->ai_addrlen)) < 0 &&
	    errno != EINPROGRESS) {
		if (!summary) {
			printf("\tfailed to connect a packet to %s: %s\n",
			       printres(t->res), strerror(errno));
		} else
			putchar('x');
		goto done;
	} else if (!summary)
		printf("\ttried to connect to %s\n", printres(t->res));

	FD_ZERO(&fdset0);
	FD_SET(sa, &fdset0);
	FD_SET(sb, &fdset0);
	maxfd = (sa > sb) ? sa : sb;
	timo.tv_sec = 1;
	timo.tv_usec = 0;

	fdset = fdset0;
	if ((e = select(maxfd + 1, &fdset, NULL, NULL, &timo)) < 0) {
		if (!summary) {
			printf("\tfailed to select: %s\n", strerror(errno));
		} else
			putchar('x');
		goto done;
	}
	if (FD_ISSET(sa, &fdset)) {
		fromlen = sizeof(ss);
		if (accept(sa, from, &fromlen) < 0) {
			if (!summary) {
				printf("\tfailed to accept on the "
				       "1st socket: %s\n", strerror(errno));
			}
			else
				; /* ignore it */
		} else {
			if (!summary) {
				printf("\taccepted a connection from %s on "
				       "the 1st socket\n",
				       printsa(from, fromlen));
			} else
				recva++;
		}
	}
	if (FD_ISSET(sb, &fdset)) {
		fromlen = sizeof(ss);
		if (accept(sb, from, &fromlen) < 0) {
			if (!summary) {
				printf("\tfailed to accept on the "
				       "2nd socket: %s\n", strerror(errno));
			}
			else
				; /* ignore it */
		} else {
			if (!summary) {
				printf("\taccepted a connection from %s on "
				       "the 2nd socket\n",
				       printsa(from, fromlen));
			} else
				recvb++;
		}
	}

	if (summary) {
		if (recva && recvb) /* NB: should be impossible for TCP */
			putchar('b');
		else if (recva)
			putchar('1');
		else if (recvb)
			putchar('2');
		else
			putchar('0');
	}

  done:
	if (s >= 0)
		close(s);
}
