/*	$KAME: tcp.c,v 1.2 2002/06/11 04:29:50 itojun Exp $	*/

/*
 * Copyright (C) 1997 and 1998 WIDE Project.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <netinet/in.h>

#include "faithd.h"
#include "event.h"

static void except __P((int, short, void *));
static void outbound __P((int, short, void *));
static void inbound __P((int, short, void *));

struct evarg {
	int s;
	struct event inbound;
	struct event outbound;
	struct event except;
	int rdshutdown;
	char buf[1024 * 16];
	ssize_t len;
	char oob;
	int hasoob;
};

static void
except(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct evarg *side = (struct evarg *)arg;
	struct evarg *r, *w;
	int atmark;
	char ch;
	int error;
	ssize_t l;

	if (side[0].s == s) {
		r = &side[0];
		w = &side[1];
	} else {
		r = &side[1];
		w = &side[0];
	}

	r->hasoob = 0;
	event_add(&r->except, NULL);
	error = ioctl(r->s, SIOCATMARK, &atmark);
	if (error >= 0 && atmark == 1) {
	again:
		l = read(s, &ch, 1);
		if (l < 0) {
			if (errno == EINTR)
				goto again;
			exit_failure("reading oob data failed: %s",
			    strerror(errno));
		} else if (l == 1) {
			r->oob = ch;
			r->hasoob = 1;
			event_add(&w->outbound, NULL);
		}
	}
}

static void
outbound(s, event, arg)
	int s;
	short event;
	void *arg;
{
	struct evarg *side = (struct evarg *)arg;
	struct evarg *w, *r;
	ssize_t l;

	/* beware - in this case, backwards */
	if (side[0].s == s) {
		w = &side[0];
		r = &side[1];
	} else {
		w = &side[1];
		r = &side[0];
	}

	if (r->hasoob) {
	again:
		l = send(w->s, &r->oob, 1, MSG_OOB);
		if (l < 0) {
			if (errno != EAGAIN)
				exit_failure("sending oob data failed: %s",
				    strerror(errno));
			event_add(&w->outbound, NULL);
		} else if (l == 0) {
			exit_failure("sending oob data failed: %s",
			    strerror(errno));
			event_add(&w->outbound, NULL);
		} else
			r->hasoob = 0;
	}

	if (r->len > 0) {
		l = write(w->s, r->buf, r->len);
		if (l < 0)
			exit(1);
		else if (l == 0) {
			shutdown(w->s, SHUT_WR);
			shutdown(r->s, SHUT_RD);
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
	struct evarg *side = (struct evarg *)arg;
	struct evarg *r, *w;
	ssize_t l;

	if (side[0].s == s) {
		r = &side[0];
		w = &side[1];
	} else {
		r = &side[1];
		w = &side[0];
	}

	l = read(r->s, r->buf, sizeof(r->buf));
	if (l < 0)
		exit(1);
	else if (l == 0) {
		shutdown(r->s, SHUT_RD);
		shutdown(w->s, SHUT_WR);
		event_del(&r->except);
	} else {
		event_add(&w->outbound, NULL);
		r->len = l;
	}
}

void
tcp_relay(int s_src, int s_dst, const char *service)
{
	int i;
	struct evarg side[2];

	syslog(LOG_INFO, "starting %s relay", service);

	memset(&side[0], 0, sizeof(side[0]));
	memset(&side[1], 0, sizeof(side[1]));
	side[0].s = s_src;
	side[1].s = s_dst;

	event_init();

	for (i = 0; i < 2; i++) {
		event_set(&side[i].inbound, side[i].s, EV_READ, inbound,
		    (void *)side);
		event_set(&side[i].outbound, side[i].s, EV_WRITE, outbound,
		    (void *)side);
		event_set(&side[i].except, side[i].s, EV_EXCEPT, except,
		    (void *)side);

		event_add(&side[i].inbound, NULL);
		event_add(&side[i].except, NULL);
	}

	event_dispatch();
	exit_success("terminating %s relay", service);
}
