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

struct connection {
	int s;
	struct event inbound;
	struct event outbound;
	char buf[1024 * 16];
	ssize_t len;
	int shutdown;	/* read terminated */
};

struct relay {
	struct connection r;
	struct connection w;
};

static char *configfile = NULL;
static int foreground = 0;

#define MAXSOCK	100

int main __P((int, char **));
static void usage __P((void));
static void logmsg __P((int, const char *, ...));
static void sighandler __P((int));
static void doaccept __P((int, short, void *));
static void outbound __P((int, short, void *));
static void inbound __P((int, short, void *));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	int s[MAXSOCK];
	struct event event[MAXSOCK];
	int smax;
	struct addrinfo hints, *res, *res0;
	int error;
	int i;
	const int yes = 1;

	while ((ch = getopt(argc, argv, "Df:")) != -1) {
		switch (ch) {
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

		for (res = res0; res && smax < MAXSOCK; res = res->ai_next) {
			s[smax] = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
			if (s[smax] < 0)
				continue;
			if (setsockopt(s[smax], IPPROTO_IPV6, IPV6_FAITH, &yes,
			    sizeof(yes)) < 0) {
				close(s[smax]);
				continue;
			}
			if (bind(s[smax], res->ai_addr, res->ai_addrlen) < 0) {
				close(s[smax]);
				continue;
			}
			if (listen(s[smax], 5) < 0) {
				close(s[smax]);
				continue;
			}

			smax++;
		}

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

	signal(SIGPIPE, sighandler);

	event_init();
	for (i = 0; i < smax; i++) {
		event_set(&event[i], s[i], EV_READ, doaccept, &event[i]);
		event_add(&event[i], NULL);
	}
	event_dispatch();
}

static void
usage()
{
	fprintf(stderr, "usage: faithd [-D] [-f configfile] port...\n");
}

#ifdef __STD__
static void
logmsg(level, msg, ...)
	int level;
	const char *msg;
#else
static void
logmsg(int level, const char *msg, ...)
#endif
{
	va_list ap;

#ifdef __STDC__
	va_start(ap, msg);
#else
	va_start(ap);
#endif
	if (foreground) {
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	} else
		vsyslog(level, msg, ap);
	va_end(ap);
}

static void
sighandler(sig)
	int sig;
{

	logmsg(LOG_WARNING, "got signal %d", sig);
}

static void
doaccept(parent, event, arg)
	int parent;
	short event;
	void *arg;
{
	struct event *pev = (struct event *)arg;
	struct relay *relay;
	struct sockaddr_in6 from;
	socklen_t fromlen;
	struct sockaddr_in6 to;
	socklen_t tolen;
	struct sockaddr_in relayto;
	socklen_t relaytolen;
	const struct config *conf;
	char h1[NI_MAXHOST], h2[NI_MAXHOST], sbuf[NI_MAXSERV];

	event_add(pev, NULL);

	relay = (struct relay *)malloc(sizeof(*relay));
	if (!relay) {
		return;
	}
	memset(relay, 0, sizeof(*relay));

	fromlen = sizeof(from);
	relay->r.s = accept(parent, (struct sockaddr *)&from, &fromlen);
	if (relay->r.s < 0)
		return;
	if (from.sin6_family != AF_INET6) {
		close(relay->r.s);
		free(relay);
		return;
	}

	tolen = sizeof(to);
	if (getsockname(relay->r.s, (struct sockaddr *)&to, &tolen) < 0) {
		close(relay->r.s);
		free(relay);
		return;
	}

	memset(&relayto, 0, sizeof(relayto));
	relayto.sin_family = AF_INET;
	relaytolen = relayto.sin_len = sizeof(struct sockaddr_in);
	memcpy(&relayto.sin_addr, &to.sin6_addr.s6_addr[12],
	    sizeof(relayto.sin_addr));
	relayto.sin_port = to.sin6_port;

	getnameinfo((struct sockaddr *)&from, fromlen, h1, sizeof(h1), NULL, 0,
	    NI_NUMERICHOST);
	getnameinfo((struct sockaddr *)&relayto, relaytolen, h2, sizeof(h2),
	    sbuf, sizeof(sbuf), NI_NUMERICHOST);
	logmsg(LOG_INFO, "relaying %s -> %s, service %s", h1, h2, sbuf);

	conf = config_match((struct sockaddr *)&from,
	    (struct sockaddr *)&relayto);
	if (!conf || !conf->permit) {
		char dst4[NI_MAXHOST], serv[NI_MAXSERV];

		getnameinfo((struct sockaddr *)&relayto, relaytolen, dst4,
		    sizeof(dst4), serv, sizeof(serv), NI_NUMERICHOST);
		if (conf)
			syslog(LOG_ERR,
			    "translation to [%s]:%s not permitted for %s",
			    dst4, serv, prefix_string(&conf->match));
		else
			syslog(LOG_ERR,
			    "translation to [%s]:%s not permitted", dst4, serv);
		close(relay->r.s);
		free(relay);
		return;
	}

	relay->w.s = socket(AF_INET, SOCK_STREAM, 0);
	if (relay->w.s < 0) {
		close(relay->r.s);
		free(relay);
		return;
	}
	if (connect(relay->w.s, (struct sockaddr *)&relayto, relaytolen) < 0) {
		close(relay->r.s);
		close(relay->w.s);
		free(relay);
		return;
	}

	event_set(&relay->r.inbound, relay->r.s, EV_READ, inbound, relay);
	event_set(&relay->w.inbound, relay->w.s, EV_READ, inbound, relay);
	event_set(&relay->r.outbound, relay->r.s, EV_WRITE, outbound, relay);
	event_set(&relay->w.outbound, relay->w.s, EV_WRITE, outbound, relay);
	event_add(&relay->r.inbound, NULL);
	event_add(&relay->w.inbound, NULL);
}

static void
outbound(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct relay *relay = (struct relay *)arg;
	struct connection *r, *w;
	ssize_t l;

	if (relay->w.s == s) {
		r = &relay->r;
		w = &relay->w;
	} else {
		r = &relay->w;
		w = &relay->r;
	}

	if (r->len > 0) {
		l = write(w->s, r->buf, r->len);
		if (l < 0) {
			logmsg(LOG_ERR, "write fail, errno=%d", errno);
			event_add(&w->outbound, NULL);
		} else if (l == 0) {
			shutdown(w->s, SHUT_WR);
			shutdown(r->s, SHUT_RD);
			r->shutdown++;
			if (w->shutdown) {
				close(r->s);
				close(w->s);
				free(relay);
			}
		} else if (l < r->len) {
			memmove(&r->buf[0], &r->buf[l], r->len - l);
			r->len -= l;
			event_add(&w->outbound, NULL);
		} else {
			r->len = 0;
			event_add(&r->inbound, NULL);
		}
	} else
		event_add(&r->inbound, NULL);
}

static void
inbound(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct relay *relay = (struct relay *)arg;
	struct connection *r, *w;
	ssize_t l;

	if (relay->r.s == s) {
		r = &relay->r;
		w = &relay->w;
	} else {
		r = &relay->w;
		w = &relay->r;
	}

	l = read(r->s, r->buf, sizeof(r->buf));
	if (l < 0) {
		logmsg(LOG_ERR, "read fail, errno=%d", errno);
		event_add(&r->inbound, NULL);
	} else if (l == 0) {
		shutdown(r->s, SHUT_RD);
		shutdown(w->s, SHUT_WR);
		r->shutdown++;
		if (w->shutdown) {
			close(r->s);
			close(w->s);
			free(relay);
		}
	} else {
		event_add(&w->outbound, NULL);
		r->len = l;
	}
}
