/*	$USAGI: bindtest.c,v 1.12 2001/11/15 15:37:16 yoshfuji Exp $	*/
/*	$KAME: bindtest.c,v 1.56 2004/06/14 05:15:48 itojun Exp $	*/

/*
 * Copyright (C) 2000,2001 USAGI/WIDE Project.
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
#include <fcntl.h>

#include <netinet/in.h>
#include <net/if.h>

/* too ugly... */
#ifdef _USAGI
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY	26
#endif
#endif

#ifndef IF_NAMESIZE
#define IF_NAMESIZE	IFNAMSIZ
#endif

char mcast4_host[INET_ADDRSTRLEN] = "224.0.0.1";
char mcast6_host[INET6_ADDRSTRLEN+1+IF_NAMESIZE] = "ff02::1";

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
	{ "mcast6",	AF_INET6,	mcast6_host,		NULL },
	{ "mcast4",	AF_INET,	mcast4_host,		NULL },
	{ NULL,		0,		NULL,			NULL }
};

#ifndef __P
#define __P(x)	x
#endif

#ifdef _AIX43
/* XXX AIX does not have sockaddr_storage */
#define sockaddr_storage sockaddr_in6
#endif

int main __P((int, char **));
static void usage __P((void));
static void printversion __P((void));
static struct addrinfo *getres __P((int, const char *, const char *, int));
static const char *printsa __P((struct sockaddr *, socklen_t));
static const char *printres __P((struct addrinfo *));
static int test __P((struct testitem *, struct testitem *));
static void sendtest __P((int, int, struct addrinfo *));
static void conntest __P((int, int, struct addrinfo *));

static char *versionstr = "$KAME: bindtest.c,v 1.56 2004/06/14 05:15:48 itojun Exp $"
			  "\n"
			  "$USAGI: bindtest.c,v 1.12 2001/11/15 15:37:16 yoshfuji Exp $";
static char *port = NULL;
static char *otheraddr = NULL;
static char *bcastaddr = NULL;
static struct addrinfo *oai, *oai6, *bai6;
static int socktype = SOCK_DGRAM;
static int v6only = 0;
static int summary = 0;
static int reuseaddr = 0;
static int reuseport = 0;
static int connect1st = 0;
static int connect2nd = 0;
static int delayedlisten = 0;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	extern char *optarg;
	struct testitem *testi, *testj;
	char otheraddr6[NI_MAXHOST], bcastaddr6[NI_MAXHOST];;

	while ((ch = getopt(argc, argv, "126Ab:lm:M:o:Pp:stvV")) != -1) {
		switch (ch) {
		case '1':
			connect1st = 1;
			break;
		case '2':
			connect2nd = 1;
			break;
		case '6':
#ifndef IPV6_V6ONLY
			fprintf(stderr, "IPV6_V6ONLY is not supported\n");
			exit(1);
#endif
			v6only = 1;
			break;
		case 'A':
			reuseaddr = 1;
#ifndef SO_REUSEADDR
			fprintf(stderr, "SO_REUSEADDR is not supported\n");
			exit(1);
#endif
			break;
		case 'b':
			bcastaddr = optarg;
			break;
		case 'l':
			delayedlisten = 1;
			break;
		case 'm':
			strncpy(mcast4_host, optarg, sizeof(mcast4_host));
			mcast4_host[sizeof(mcast4_host)-1] = '\0';
			break;
		case 'M':
			strncpy(mcast6_host, optarg, sizeof(mcast6_host));
			mcast6_host[sizeof(mcast6_host)-1] = '\0';
			break;
		case 'P':
			reuseport = 1;
#ifndef SO_REUSEPORT
			fprintf(stderr, "SO_REUSEPORT is not supported\n");
			exit(1);
#endif
			break;
		case 'o':
			otheraddr = optarg;
			break;
		case 'p':
			port = strdup(optarg);
			if (!port) {
				fprintf(stderr, "strdup failed\n");
				exit(1);
			}
			break;
		case 's':
			summary = 1;
			break;
		case 't':
			socktype = SOCK_STREAM;
			break;
		case 'v':
			printversion();
			exit(0);
		case 'V':
			printf("%s\n", versionstr);
			exit(0);
		default:
			usage();
			exit(1);
		}
	}

	/* option consistency check */
	if ((connect1st && connect2nd) || (connect1st && otheraddr) ||
	    (connect2nd && otheraddr)){
		fprintf(stderr, "-1, -2, and -o are exclusive.\n");
		exit(1);
	}
	if ((connect1st || connect2nd) && socktype != SOCK_STREAM) {
		fprintf(stderr, "-1 or -2 must be specified with -t.\n");
		exit(1);
	}
	if (bcastaddr) {
		if (summary) {
			fprintf(stderr, "-b and -s can't coexist.\n");
			exit(1);
		}
		if (socktype != SOCK_DGRAM) {
			fprintf(stderr, "-s can only allow for UDP.\n");
			exit(1);
		}
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
		testi->res = getres(testi->family, testi->host, port,
				    AI_PASSIVE);
		if (!testi->res) {
			fprintf(stderr, "getaddrinfo failed\n");
			exit(1);
		}
		if (strncmp(testi->name, "mcast", 5) == 0) {
			switch(testi->family) {
			case AF_INET6:
				if (!IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)testi->res->ai_addr)->sin6_addr))
					fprintf(stderr, "non-multicast address for %s\n", testi->name);
				break;
			case AF_INET:
				if (!IN_MULTICAST(ntohl(((struct sockaddr_in *)testi->res->ai_addr)->sin_addr.s_addr)))
					fprintf(stderr, "non-multicast address for %s\n", testi->name);
				break;
			}
		}
	}

	if (otheraddr != NULL) {
		if ((oai = getres(AF_INET, otheraddr, port, 0)) == NULL) {
			if ((oai6 = getres(AF_INET6, otheraddr, port, 0))
			    == NULL) {
				fprintf(stderr, "getaddrinfo failed\n");
				exit(1);
			}
		} else if (socktype == SOCK_DGRAM) {
			if (strlen("::ffff:") + strlen(otheraddr) + 1 >
			    sizeof(otheraddr6)) {
				fprintf(stderr, "too long hostname %s",
				     otheraddr);
				exit(1);
			}
			strcpy(otheraddr6, "::ffff:");
			strcat(otheraddr6, otheraddr);
			if ((oai6 = getres(AF_INET6, otheraddr6, port, 0))
			    == NULL) {
				fprintf(stderr, "getaddrinfo failed\n");
				exit(1);
			}
		}
	}
	if (bcastaddr != NULL) {
		if (strlen("::ffff:") + strlen(bcastaddr) + 1 >
		    sizeof(bcastaddr6)) {
			fprintf(stderr, "too long hostname %s",
				bcastaddr);
			exit(1);
		}
		strcpy(bcastaddr6, "::ffff:");
		strcat(bcastaddr6, bcastaddr);
		if ((bai6 = getres(AF_INET6, bcastaddr6, port, 0))
		    == NULL) {
			fprintf(stderr, "getaddrinfo failed\n");
			exit(1);
		}
	}

	printf("starting tests, socktype = %s%s%s",
	    socktype == SOCK_DGRAM ? "SOCK_DGRAM" : "SOCK_STREAM",
	    reuseaddr ? ", SO_REUSEADDR" : "",
	    reuseport ? ", SO_REUSEPORT" : "");
#ifdef IPV6_V6ONLY
	printf("%s", v6only ? ", V6ONLY" : ", !V6ONLY");
#endif
	if (socktype == SOCK_STREAM &&
	    (connect1st != 0 || connect2nd != 0 || otheraddr != NULL)) {
		printf(", connect to ");
		if (connect1st != 0)
			printf("1st");
		if (connect2nd != 0)
			printf("2nd");
		if (oai != NULL)
			printf("other");
		if (oai6 != NULL)
			printf("other6");
	}
	if (socktype == SOCK_STREAM && delayedlisten == 1)
		printf(", delayed listen");
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
	fprintf(stderr, "usage: bindtest [-126APlstvV] "
		"[-b IPv4 broadcast addr] [-o IPv4address] "
		"[-m IPv4 multicast addr] [-M IPv6 multicast addr] "
		"-p port\n");
}

static void
printversion()
{
	char *ver, *beg, *end;

	if ((ver = strdup(versionstr)) == NULL) {
		fprintf(stderr, "strdup failed\n");
		exit(1);
	}

	if ((beg = strchr(ver, ':')) == NULL)
		beg = ver;
 	else if ((end = strchr(beg + 1, '$')) != NULL)
		*end = '\0';
	printf("%s\n", beg + 1);
	free(ver);
}

static struct addrinfo *
getres(af, host, port, flags)
	int af;
	const char *host;
	const char *port;
	int flags;
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = socktype;
	hints.ai_flags = flags;
	error = getaddrinfo(host, port, &hints, &res);
	if (error)
		res = NULL;
	return res;
}

static const char *
printsa(sa, salen)
	struct sockaddr *sa;
	socklen_t salen;
{
	char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
	static char buf[sizeof(hbuf) + sizeof(pbuf)];
	int error;

	error = getnameinfo(sa, salen, hbuf, sizeof(hbuf), pbuf, sizeof(pbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error) {
		strcpy(hbuf, "?");
		strcpy(pbuf, "?");
	}
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
		if (!summary)
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

#ifdef IPV6_V6ONLY
	if (a->ai_family == AF_INET6 &&
	    setsockopt(sa, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
		       sizeof(v6only)) < 0) {
		if (!summary)
			printf("\tfailed setsockopt(IPV6_V6ONLY, %d) "
			       "for %s, %s\n", v6only, printres(a),
			       strerror(errno));
		else
			printf("\t?6");
		goto fail;
	}
	if (b->ai_family == AF_INET6 &&
	    setsockopt(sb, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
		       sizeof(v6only)) < 0) {
		if (!summary)
			printf("\tfailed setsockopt(IPV6_V6ONLY, %d) "
			       "for %s, %s\n", v6only, printres(b),
			       strerror(errno));
		else
			printf("\t?6");
		goto fail;
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
	if (socktype == SOCK_STREAM && delayedlisten == 0 &&
	    listen(sa, 5) < 0) {
		if (!summary)
			printf("\tfailed listen on for %s: %s\n",
			       printres(a), strerror(errno));
		else
			printf("\tL1?(%d)", errno);
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
	if (socktype == SOCK_STREAM && delayedlisten == 0 &&
	    listen(sb, 5) < 0) {
		if (!summary)
			printf("\tfailed listen on for %s: %s\n",
			       printres(b), strerror(errno));
		else
			printf("\tL2?(%d)", errno);
		goto fail;
	}

	if (summary)
		printf("\t");

	if (summary)
		putchar('[');
	if (socktype == SOCK_DGRAM) {
		if (t1->host != NULL)
			sendtest(sa, sb, t1->res);
		else if (summary)
			putchar('-');
		if (t2->host != NULL)
			sendtest(sa, sb, t2->res);
		else if (summary)
			putchar('-');
		if (oai != NULL)
			sendtest(sa, sb, oai);
		if (oai6 != NULL)
			sendtest(sa, sb, oai6);
		if (bai6 != NULL)
			sendtest(sa, sb, bai6);
		else if (summary)
			putchar('-');
	} else if (socktype == SOCK_STREAM &&
		   (reuseaddr != 0 || reuseport != 0)) {
		/*
		 * We skip the test unless the REUSExxx option(s) is specified.
		 * Otherwise, remaining TIME_WAIT sockets would prevent
		 * succeeding sockets from being bound.
		 */
		if (t1->host != NULL && connect1st)
			conntest(sa, sb, t1->res);
		else if (summary)
			putchar('-');
		if (t2->host != NULL && connect2nd)
			conntest(sa, sb, t2->res);
		else if (summary)
			putchar('-');
		if (oai != NULL)
			conntest(sa, sb, oai);
		else if (summary)
			putchar('-');
		if (oai6 != NULL)
			conntest(sa, sb, oai6);
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
sendtest(sa, sb, ai)
	int sa, sb;
	struct addrinfo *ai;
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

	if ((s = socket(ai->ai_family, ai->ai_socktype,
			ai->ai_protocol)) < 0) {
		if (!summary) {
			printf("\tfailed to open a socket for sending: %s\n",
			       strerror(errno));
		} else
			putchar('s');
		goto done;
	}
	if (bcastaddr) {
		int on = 1;

		if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))
		    < 0) {
			printf("\tfailed setsockopt(SO_BROADCAST) "
				       "for %s, %s\n", printres(ai),
				       strerror(errno));
		}
	}
#ifdef IPV6_V6ONLY
	if (ai->ai_family == AF_INET6) {
		int v = v6only ? 1 : 0;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof(v))
		    < 0) {
			if (!summary) {
				printf("\tfailed setsockopt(IPV6_V6ONLY) "
				       "for %s, %s\n", printres(ai),
				       strerror(errno));
			} else
				putchar('6');
			goto done;
		}
	}
#endif
	if ((sendto(s, buf, sizeof(buf), 0, ai->ai_addr,
		    ai->ai_addrlen)) < 0) {
		if (!summary) {
			printf("\tfailed to send a packet to %s: %s\n",
			       printres(ai), strerror(errno));
		} else
			putchar('x');
		goto done;
	} else if (!summary)
		printf("\tsend %lu bytes to %s\n", (unsigned long)sizeof(buf),
		       printres(ai));

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
conntest(sa, sb, ai)
	int sa, sb;
	struct addrinfo *ai;
{
	int s = -1, maxfd;
	int newsa = -1, newsb = -1;
	int e;
	int recva = 0, recvb = 0;
	fd_set fdset, fdset0;
	struct timeval timo;
	struct sockaddr_storage ss;
	struct sockaddr *from = (struct sockaddr *)&ss;
	socklen_t fromlen;
	int flags;

	if (delayedlisten && listen(sa, 5) < 0) {
		if (!summary) {
			printf("\tfailed to listen for the 1st socket: %s\n",
			       strerror(errno));
		} else
			putchar('l');
		goto done;
	}
	if (delayedlisten && listen(sb, 5) < 0) {
		if (!summary) {
			printf("\tfailed to listen for the 2nd socket: %s\n",
			       strerror(errno));
		} else
			putchar('L');
		goto done;
	}
	
	if ((s = socket(ai->ai_family, ai->ai_socktype,
			ai->ai_protocol)) < 0) {
		if (!summary) {
			printf("\tfailed to open a socket for connecting: %s\n",
			       strerror(errno));
		} else
			putchar('s');
		goto done;
	}
#ifdef IPV6_V6ONLY
	if (ai->ai_family == AF_INET6) {
		int v = v6only ? 1 : 0;

		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof(v))
		    < 0) {
			if (!summary) {
				printf("\tfailed setsockopt(IPV6_V6ONLY) "
				       "for %s, %s\n", printres(ai),
				       strerror(errno));
			} else
				putchar('6');
			goto done;
		}
	}
#endif
	flags = fcntl(s, F_GETFL, 0);
	flags |= O_NONBLOCK;
	if (fcntl(s, F_SETFL, flags) < 0) {
		if (!summary) {
			printf("\tfailed to make connecting socket "
			       "non-blocking: %s\n", strerror(errno));
		} else
			putchar('f');
		goto done;
	}

	if ((connect(s, ai->ai_addr, ai->ai_addrlen)) < 0 &&
	    errno != EINPROGRESS) {
		if (!summary) {
			printf("\tfailed to connect a packet to %s: %s\n",
			       printres(ai), strerror(errno));
		} else
			putchar('c');
		goto done;
	} else if (!summary)
		printf("\ttried to connect to %s\n", printres(ai));

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
		if ((newsa = accept(sa, from, &fromlen)) < 0) {
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
		if ((newsb = accept(sb, from, &fromlen)) < 0) {
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
	if (newsa >= 0)
		close(newsa);
	if (newsb >= 0)
		close(newsb);
}
