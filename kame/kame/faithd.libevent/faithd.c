/*
 * Copyright (C) 2002 WIDE Project.
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
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include "event.h"
#include "prefix.h"
#include "faithd.h"

static char *configfile = NULL;
static int foreground = 0;
static int logstderr = 0;

#define MAXSOCK	100

int main __P((int, char **));
static void usage __P((void));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	int s[MAXSOCK];
	void (*callback[MAXSOCK]) __P((int, short, void *arg));
	struct event event[MAXSOCK];
	int smax;
	struct addrinfo hints, *res, *res0;
	int error;
	int i, t;
	const int yes = 1;

	while ((ch = getopt(argc, argv, "dDf:")) != -1) {
		switch (ch) {
		case 'd':
			logstderr = 1;
			break;
		case 'D':
			foreground = 1;
			break;
		case 'f':
			configfile = optarg;
			break;
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		usage();
		exit(1);
	}

	if (config_load(configfile) < 0 && configfile) {
		errx(1, "%s", configfile);
		/*NOTREACHED*/
	}

	smax = 0;
	while (argc-- > 0) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE;
		error = getaddrinfo(NULL, *argv, &hints, &res0);
		if (error) {
			errx(1, "%s: %s", *argv, gai_strerror(error));
			/*NOTREACHED*/
		}

		t = smax;
		for (res = res0; res && smax < MAXSOCK; res = res->ai_next) {
			s[smax] = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
			if (s[smax] < 0)
				continue;
			if (setsockopt(s[smax], SOL_SOCKET, SO_REUSEADDR, &yes,
			    sizeof(yes)) < 0) {
				close(s[smax]);
				continue;
			}
			if (setsockopt(s[smax], IPPROTO_IPV6, IPV6_FAITH, &yes,
			    sizeof(yes)) < 0) {
				close(s[smax]);
				continue;
			}
#ifdef IPV6_V6ONLY
			if (setsockopt(s[smax], IPPROTO_IPV6, IPV6_V6ONLY, &yes,
			    sizeof(yes)) < 0) {
				close(s[smax]);
				continue;
			}
#endif
			if (bind(s[smax], res->ai_addr, res->ai_addrlen) < 0) {
				close(s[smax]);
				continue;
			}
			if (listen(s[smax], 5) < 0) {
				close(s[smax]);
				continue;
			}
			if (ntohs(((struct sockaddr_in6 *)res->ai_addr)->sin6_port) == 21)
				callback[smax] = ftp_doaccept;
			else
				callback[smax] = tcp_doaccept;

			smax++;
		}

		if (smax == t) {
			errx(1, "could not open service %s", *argv);
			/*NOTREACHED*/
		}

		freeaddrinfo(res0);
		argv++;
	}
	if (smax >= MAXSOCK) {
		errx(1, "too many listening sockets");
		/*NOTREACHED*/
	}

	if (!foreground)
		if (daemon(0, 0) < 0) {
			err(1, "daemon");
			/*NOTREACHED*/
		}

	signal(SIGPIPE, SIG_IGN);

	event_init();
	for (i = 0; i < smax; i++) {
		event_set(&event[i], s[i], EV_READ, callback[i], &event[i]);
		event_add(&event[i], NULL);
	}
	event_dispatch();

	exit(0);
}

static void
usage()
{

	fprintf(stderr, "usage: faithd [-dD] [-f configfile] service...\n");
}

#ifdef __STD__
void
logmsg(level, msg, ...)
	int level;
	const char *msg;
#else
void
logmsg(int level, const char *msg, ...)
#endif
{
	va_list ap;

#ifdef __STDC__
	va_start(ap, msg);
#else
	va_start(ap);
#endif
	if (logstderr) {
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	} else
		vsyslog(level, msg, ap);
	va_end(ap);
}
