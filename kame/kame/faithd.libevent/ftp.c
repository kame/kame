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
#include <string.h>
#include <err.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
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

enum state { NONE, LPSV, EPSV };

struct datarelay {
	struct event xfer;
	struct sockaddr_in datato;
	struct connection r;
	struct connection w;
};

struct relay {
	struct connection cli;	/* client -> faithd */
	struct connection ser;	/* faithd -> server */
	enum state state;
};

static void data_doaccept __P((int, short, void *));
static void outbound __P((int, short, void *));
static void inbound __P((int, short, void *));
static void resout __P((int, short, void *));
static void cmdout __P((int, short, void *));
static void resin __P((int, short, void *));
static void cmdin __P((int, short, void *));

void
data_doaccept(parent, event, arg)
	int parent;
	short event;
	void *arg;
{
	struct datarelay *relay = (struct datarelay *)arg;
	struct sockaddr_in6 from;
	socklen_t fromlen;
	struct sockaddr_in relayto;
	socklen_t relaytolen;
	const struct config *conf;
	char h1[NI_MAXHOST], h2[NI_MAXHOST], s1[NI_MAXSERV], s2[NI_MAXSERV];

	fromlen = sizeof(from);
	relay->r.s = accept(parent, (struct sockaddr *)&from, &fromlen);
	if (relay->r.s < 0)
		return;
	if (from.sin6_family != AF_INET6) {
		close(relay->r.s);
		close(parent);
		free(relay);
		return;
	}

	close(parent);

	relayto = relay->datato;
	relaytolen = sizeof(relay->datato);

	getnameinfo((struct sockaddr *)&from, fromlen, h1, sizeof(h1),
	    s1, sizeof(s1), NI_NUMERICHOST | NI_NUMERICSERV);
	getnameinfo((struct sockaddr *)&relayto, relaytolen, h2, sizeof(h2),
	    s2, sizeof(s2), NI_NUMERICHOST | NI_NUMERICSERV);
	logmsg(LOG_INFO, "relaying [%s]:%s -> [%s]:%s, service ftpdata",
	    h1, s1, h2, s2);

	/* XXX this shouldn't happen, but the symptom happens on freebsd45 */
	if (IN6_IS_ADDR_V4MAPPED(&from.sin6_addr)) {
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
	struct datarelay *relay = (struct datarelay *)arg;
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
		if (l < 0 && errno == EAGAIN)
			event_add(&w->outbound, NULL);
		else if (l <= 0) {
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
	struct datarelay *relay = (struct datarelay *)arg;
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
	if (l < 0 && errno == EAGAIN) {
		event_add(&r->inbound, NULL);
	} else if (l <= 0) {
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

void
ftp_doaccept(parent, event, arg)
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
	relay->cli.s = accept(parent, (struct sockaddr *)&from, &fromlen);
	if (relay->cli.s < 0)
		return;
	if (from.sin6_family != AF_INET6) {
		close(relay->cli.s);
		free(relay);
		return;
	}

	tolen = sizeof(to);
	if (getsockname(relay->cli.s, (struct sockaddr *)&to, &tolen) < 0) {
		close(relay->cli.s);
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

	/* XXX this shouldn't happen, but the symptom happens on freebsd45 */
	if (IN6_IS_ADDR_V4MAPPED(&from.sin6_addr)) {
		close(relay->cli.s);
		free(relay);
		return;
	}

	conf = config_match((struct sockaddr *)&from,
	    (struct sockaddr *)&relayto);
	if (!conf || !conf->permit) {
		char src6[NI_MAXHOST], dst4[NI_MAXHOST];
		char sserv[NI_MAXSERV], dserv[NI_MAXSERV];

		getnameinfo((struct sockaddr *)&from, fromlen, src6,
		    sizeof(src6), sserv, sizeof(sserv), NI_NUMERICHOST);
		getnameinfo((struct sockaddr *)&relayto, relaytolen, dst4,
		    sizeof(dst4), dserv, sizeof(dserv), NI_NUMERICHOST);
		if (conf)
			syslog(LOG_ERR,
			    "translation from [%s]:%s to [%s]:%s not permitted for %s",
			    src6, sserv, dst4, dserv,
			    prefix_string(&conf->match));
		else
			syslog(LOG_ERR,
			    "translation from [%s]:%s to [%s]:%s not permitted",
			    src6, sserv, dst4, dserv);
		close(relay->cli.s);
		free(relay);
		return;
	}

	relay->ser.s = socket(AF_INET, SOCK_STREAM, 0);
	if (relay->ser.s < 0) {
		close(relay->cli.s);
		free(relay);
		return;
	}
	if (connect(relay->ser.s, (struct sockaddr *)&relayto,
	    relaytolen) < 0) {
		close(relay->cli.s);
		close(relay->ser.s);
		free(relay);
		return;
	}

	relay->state = NONE;
	event_set(&relay->cli.inbound, relay->cli.s, EV_READ, cmdin, relay);
	event_set(&relay->ser.outbound, relay->ser.s, EV_WRITE, cmdout, relay);
	event_set(&relay->ser.inbound, relay->ser.s, EV_READ, resin, relay);
	event_set(&relay->cli.outbound, relay->cli.s, EV_WRITE, resout, relay);
	event_add(&relay->cli.inbound, NULL);
	event_add(&relay->ser.inbound, NULL);
}

static void
resout(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct relay *relay = (struct relay *)arg;
	struct connection *r, *w;
	ssize_t l;

	if (relay->cli.s != s) {
		logmsg(LOG_ERR, "invalid state: resout");
		close(relay->ser.s);
		close(relay->cli.s);
		free(relay);
	}

	if (relay->ser.len > 0) {
		l = write(s, relay->ser.buf, relay->ser.len);
		if (l < 0 && errno == EAGAIN)
			event_add(&relay->cli.outbound, NULL);
		else if (l <= 0) {
			shutdown(relay->cli.s, SHUT_WR);
			shutdown(relay->ser.s, SHUT_RD);
			relay->cli.shutdown++;
			if (relay->ser.shutdown) {
				close(relay->cli.s);
				close(relay->ser.s);
				free(relay);
			}
		} else if (l < relay->ser.len) {
			memmove(&relay->ser.buf[0], &relay->ser.buf[l],
			    relay->ser.len - l);
			relay->ser.len -= l;
			event_add(&relay->cli.outbound, NULL);
		} else {
			relay->ser.len = 0;
			event_add(&relay->ser.inbound, NULL);
		}
	} else
		event_add(&relay->ser.inbound, NULL);
}

static void
cmdout(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct relay *relay = (struct relay *)arg;
	struct connection *r, *w;
	ssize_t l;

	if (relay->ser.s != s) {
		logmsg(LOG_ERR, "invalid state: cmdout");
		close(relay->cli.s);
		close(relay->ser.s);
		free(relay);
	}

	if (relay->cli.len > 0) {
		l = write(s, relay->cli.buf, relay->cli.len);
		if (l < 0 && errno == EAGAIN)
			event_add(&relay->ser.outbound, NULL);
		else if (l <= 0) {
			shutdown(relay->ser.s, SHUT_WR);
			shutdown(relay->cli.s, SHUT_RD);
			relay->ser.shutdown++;
			if (relay->cli.shutdown) {
				close(relay->ser.s);
				close(relay->cli.s);
				free(relay);
			}
		} else if (l < relay->cli.len) {
			memmove(&relay->cli.buf[0], &relay->cli.buf[l],
			    relay->cli.len - l);
			relay->cli.len -= l;
			event_add(&relay->ser.outbound, NULL);
		} else {
			relay->cli.len = 0;
			event_add(&relay->cli.inbound, NULL);
		}
	} else
		event_add(&relay->cli.inbound, NULL);
}

static void
resin(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct relay *relay = (struct relay *)arg;
	struct datarelay *datarelay;
	struct connection *r, *w;
	ssize_t l;
	char errmsg[1024];
	int n;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	socklen_t salen;
	const int on = 1;
	char *p, *ep;
	int ho[4], po[2];

	if (relay->ser.s != s) {
		logmsg(LOG_ERR, "invalid state: cmdin");
		close(relay->ser.s);
		close(relay->cli.s);
		free(relay);
	}

	l = read(s, relay->ser.buf + relay->ser.len,
	    sizeof(relay->ser.buf) - relay->ser.len);
	if (l < 0 && errno == EAGAIN) {
		event_add(&relay->ser.inbound, NULL);
		return;
	} else if (l <= 0) {
		shutdown(relay->ser.s, SHUT_RD);
		shutdown(relay->cli.s, SHUT_WR);
		relay->ser.shutdown++;
		if (relay->cli.shutdown) {
			close(relay->ser.s);
			close(relay->cli.s);
			free(relay);
		}
		return;
	}

	relay->ser.len += l;
	if (relay->ser.len == 0) {
		/* shouldn't happen */
		event_add(&relay->ser.inbound, NULL);
		return;
	}
	if (relay->ser.buf[relay->ser.len - 1] != '\n') {
		event_add(&relay->ser.inbound, NULL);
		return;
	}

	switch (relay->state) {
	case NONE:
		event_add(&relay->cli.outbound, NULL);
		break;
	case EPSV:
	case LPSV:
		/* recv: 227 Entering Passive Mode (x,x,x,x,x,x) */
		/* send: 228 Entering Long Passive Mode (...) */
		/* send: 229 Entering Extended Passive Mode (|||x|) */
		if (strncmp(relay->ser.buf, "227 ", 4) != 0) {
	epsvfail:
			memcpy(errmsg, relay->ser.buf, 3);
			errmsg[3] = '\0';
	epsvfail1:
			relay->ser.len = snprintf(relay->ser.buf,
			    sizeof(relay->ser.buf), "501 unexpected: %s\r\n",
			    errmsg);
			event_add(&relay->cli.outbound, NULL);
			break;
		}
		ep = &relay->ser.buf[relay->ser.len];
		*ep = '\0';
		p = strrchr(relay->ser.buf, ' ');
		if (!p)
			goto epsvfail;
		if (*p == ' ' && p + 1 < ep)
			p++;
		if (*p == '(' && p + 1 < ep)	/*)*/
			p++;
		n = sscanf(p, "%u,%u,%u,%u,%u,%u",
		    &ho[0], &ho[1], &ho[2], &ho[3], &po[0], &po[1]);
		if (n != 6)
			goto epsvfail;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(struct sockaddr_in);
		for (n = 0; n < 4; n++)
			sin.sin_addr.s_addr |=
			    htonl((ho[n] & 0xff) << ((3 - n) * 8));
		sin.sin_port = htons(((po[0] & 0xff) << 8) + (po[1] & 0xff));

		salen = sizeof(sin6);
		if (getsockname(relay->cli.s, (struct sockaddr *)&sin6,
		    &salen) < 0) {
			snprintf(errmsg, sizeof(errmsg),
			    "getsockname: %s", strerror(errno));
			goto epsvfail1;
		}
		sin6.sin6_port = htons(0);

		s = socket(AF_INET6, SOCK_STREAM, 0);
		if (s < 0) {
			snprintf(errmsg, sizeof(errmsg),
			    "socket: %s", strerror(errno));
			goto epsvfail1;
		}
		if (setsockopt(s, IPPROTO_IPV6, IPV6_FAITH, &on,
		    sizeof(on)) < 0) {
			close(s);
			snprintf(errmsg, sizeof(errmsg),
			    "setsockopt: %s", strerror(errno));
			goto epsvfail1;
		}
		if (bind(s, (struct sockaddr *)&sin6, salen) < 0) {
			/*
			 * on some of the KAME platforms (including freebsd4)
			 * bind(2) with arbitrary address does not go
			 * successful even with IPV6_FAITH.
			 * as a workaround, bind(2) to wildcard.
			 * this behavior violates EPSV spec.
			 */
			memset(&sin6.sin6_addr, 0, sizeof(sin6.sin6_addr));
			sin6.sin6_scope_id = 0;
			if (bind(s, (struct sockaddr *)&sin6, salen) < 0) {
				close(s);
				snprintf(errmsg, sizeof(errmsg),
				    "bind: %s", strerror(errno));
				goto epsvfail1;
			}
		}
		if (listen(s, 1) < 0) {
			close(s);
			snprintf(errmsg, sizeof(errmsg),
			    "listen: %s", strerror(errno));
			goto epsvfail1;
		}
		salen = sizeof(sin6);
		if (getsockname(s, (struct sockaddr *)&sin6, &salen) < 0) {
			close(s);
			snprintf(errmsg, sizeof(errmsg),
			    "getsockname: %s", strerror(errno));
			goto epsvfail1;
		}

		datarelay = (struct datarelay *)malloc(sizeof(*relay));
		if (!datarelay) {
			close(s);
			snprintf(errmsg, sizeof(errmsg),
			    "malloc: %s", strerror(errno));
			goto epsvfail1;
			return;
		}
		memset(datarelay, 0, sizeof(*datarelay));

		datarelay->datato = sin;
		event_set(&datarelay->xfer, s, EV_READ, data_doaccept,
		    datarelay);
		event_add(&datarelay->xfer, NULL);

		if (relay->state == EPSV) {
			relay->ser.len = snprintf(relay->ser.buf,
			    sizeof(relay->ser.buf),
			    "229 Entering Extended Passive Mode (|||%u|)\r\n",
			    ntohs(sin6.sin6_port));
		} else {
			u_int16_t port;
			u_int8_t *ap, *pp;
#define UC(x)	((x) & 0xff)

			port = sin6.sin6_port;

			/*
			 * use control connection's endpoint address, as
			 * data connection may not be bound to specific address
			 * due to the kernel bug - see bind(2) calls above.
			 */
			salen = sizeof(sin6);
			if (getsockname(relay->cli.s, (struct sockaddr *)&sin6,
			    &salen) < 0) {
				close(s);
				snprintf(errmsg, sizeof(errmsg),
				    "malloc: %s", strerror(errno));
				goto epsvfail1;
			}

			ap = (u_int8_t *)&sin6.sin6_addr;
			pp = (u_int8_t *)&port;

			relay->ser.len = snprintf(relay->ser.buf,
			    sizeof(relay->ser.buf),
"228 Entering Long Passive Mode (%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u)\r\n",
			    6, 16, UC(ap[0]), UC(ap[1]), UC(ap[2]), UC(ap[3]),
			    UC(ap[4]), UC(ap[5]), UC(ap[6]), UC(ap[7]),
			    UC(ap[8]), UC(ap[9]), UC(ap[10]), UC(ap[11]),
			    UC(ap[12]), UC(ap[13]), UC(ap[14]), UC(ap[15]),
			    2, UC(pp[0]), UC(pp[1]));
		}
		event_add(&relay->cli.outbound, NULL);
		break;
	default:
		event_add(&relay->cli.outbound, NULL);
		break;
	}
}

static void
cmdin(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct relay *relay = (struct relay *)arg;
	struct connection *r, *w;
	ssize_t l;
	char cmd[1024];
	char *p, *ep;

	if (relay->cli.s != s) {
		logmsg(LOG_ERR, "invalid state: cmdin");
		close(relay->cli.s);
		close(relay->ser.s);
		free(relay);
	}

	l = read(s, relay->cli.buf + relay->cli.len,
	    sizeof(relay->cli.buf) - relay->cli.len);
	if (l < 0 && errno == EAGAIN) {
		event_add(&relay->cli.inbound, NULL);
		return;
	} else if (l <= 0) {
		shutdown(relay->cli.s, SHUT_RD);
		shutdown(relay->ser.s, SHUT_WR);
		relay->cli.shutdown++;
		if (relay->ser.shutdown) {
			close(relay->cli.s);
			close(relay->ser.s);
			free(relay);
		}
		return;
	}

	relay->cli.len += l;
	if (relay->cli.len == 0) {
		/* shouldn't happen */
		event_add(&relay->cli.inbound, NULL);
		return;
	}
	if (relay->cli.buf[relay->cli.len - 1] != '\n') {
		event_add(&relay->cli.inbound, NULL);
		return;
	}

	ep = &relay->cli.buf[relay->cli.len];
	for (p = relay->cli.buf; p < ep; p++)
		if (!isalpha(*p))
			break;
	if (p - relay->cli.buf + 1 > sizeof(cmd)) {
		relay->ser.len = snprintf(relay->ser.buf,
		    sizeof(relay->ser.buf), "502 command too long.\r\n");
		event_add(&relay->cli.outbound, NULL);
		relay->cli.len = 0;
		event_add(&relay->cli.inbound, NULL);
		return;
	}

	memcpy(cmd, relay->cli.buf, p - relay->cli.buf);
	cmd[p - relay->cli.buf] = '\0';

	/* commands that are not relayed */
	if (strncasecmp(relay->cli.buf, "EPSV ALL", 8) == 0) {
		relay->ser.len = snprintf(relay->ser.buf,
		    sizeof(relay->ser.buf), "502 not implemented.\r\n");
		event_add(&relay->cli.outbound, NULL);
		relay->cli.len = 0;
		event_add(&relay->cli.inbound, NULL);
		return;
	}
	if (strcasecmp(cmd, "EPRT") == 0 || strcasecmp(cmd, "LPRT") == 0 ||
	    strcasecmp(cmd, "PORT") == 0 || strcasecmp(cmd, "PASV") == 0) {
		relay->ser.len = snprintf(relay->ser.buf,
		    sizeof(relay->ser.buf), "502 %s not implemented.\r\n", cmd);
		event_add(&relay->cli.outbound, NULL);
		relay->cli.len = 0;
		event_add(&relay->cli.inbound, NULL);
		return;
	}

	if (strcasecmp(cmd, "EPSV") == 0) {
		/* EPSV -> PASV */
		relay->cli.len = snprintf(relay->cli.buf,
		    sizeof(relay->cli.buf), "PASV\r\n");
		relay->state = EPSV;
	} else if (strcasecmp(cmd, "LPSV") == 0) {
		/* LPSV -> PASV */
		relay->cli.len = snprintf(relay->cli.buf,
		    sizeof(relay->cli.buf), "PASV\r\n");
		relay->state = LPSV;
	} else if (relay->state == EPSV &&
	    (strcasecmp(cmd, "STOR") == 0 || strcasecmp(cmd, "STOU") == 0 ||
	     strcasecmp(cmd, "RETR") == 0 || strcasecmp(cmd, "LIST") == 0 ||
	     strcasecmp(cmd, "NLST") == 0 || strcasecmp(cmd, "APPE") == 0)) {
		/* data transfer begins */
		relay->state = NONE;
	} else {
		/* simply relay */
	}
	event_add(&relay->ser.outbound, NULL);
}
