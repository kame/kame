/*	$KAME: db.c,v 1.2 2000/05/31 05:46:29 itojun Exp $	*/

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
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>

#include <arpa/nameser.h>

#include "mdnsd.h"
#include "db.h"

struct qchead qcache;
#if 0
struct achead acache;
#endif
struct schead scache;
struct nshead nsdb;

int
dbtimeo()
{
	struct scache *sc, *nsc;
	struct timeval tv;
	int errcnt;

	(void)gettimeofday(&tv, NULL);

	errcnt = 0;
	for (sc = LIST_FIRST(&scache); sc; sc = nsc) {
		nsc = LIST_NEXT(sc, link);

		if (sc->sockidx < 0) {
			dprintf("invalid scache entry %p\n", sc);
			delscache(sc);
			continue;
		}
		if (sc->tts.tv_sec > tv.tv_sec)
			continue;
		if (sc->tts.tv_sec == tv.tv_sec && sc->tts.tv_usec > tv.tv_usec)
			continue;

		if (sendto(sc->sockidx, sc->sbuf, sc->slen, 0,
		    (struct sockaddr *)&sc->to, sc->to.ss_len) < 0)
			errcnt++;
		delscache(sc);
	}

	return errcnt == 0 ? 0 : -1;
}

struct qcache *
newqcache(from, buf, len)
	const struct sockaddr *from;
	char *buf;
	int len;
{
	struct qcache *qc;

	if (from->sa_len > sizeof(qc->from))
		return NULL;

	qc = (struct qcache *)malloc(sizeof(*qc));
	if (qc == NULL)
		return NULL;
	memset(qc, 0, sizeof(*qc));
	qc->qbuf = (char *)malloc(len);
	if (qc->qbuf == NULL) {
		free(qc);
		return NULL;
	}

	memcpy(&qc->from, from, from->sa_len);
	memcpy(qc->qbuf, buf, len);
	qc->qlen = len;

	LIST_INSERT_HEAD(&qcache, qc, link);
	return qc;
}

void
delqcache(qc)
	struct qcache *qc;
{

	LIST_REMOVE(qc, link);
	if (qc->qbuf)
		free(qc->qbuf);
	free(qc);
}

struct scache *
newscache(sidx, from, to, buf, len)
	int sidx;
	const struct sockaddr *from, *to;
	char *buf;
	int len;
{
	struct scache *sc;

	if (from->sa_len > sizeof(sc->from) || to->sa_len > sizeof(sc->to))
		return NULL;

	sc = (struct scache *)malloc(sizeof(*sc));
	if (sc == NULL)
		return NULL;
	memset(sc, 0, sizeof(*sc));
	sc->sbuf = (char *)malloc(len);
	if (sc->sbuf == NULL) {
		free(sc);
		return NULL;
	}

	sc->sockidx = -1;
	memcpy(&sc->from, from, from->sa_len);
	memcpy(&sc->to, to, to->sa_len);
	memcpy(sc->sbuf, buf, len);
	sc->slen = len;

	LIST_INSERT_HEAD(&scache, sc, link);
	return sc;
}

void
delscache(sc)
	struct scache *sc;
{

	LIST_REMOVE(sc, link);
	if (sc->sbuf)
		free(sc->sbuf);
	free(sc);
}

struct nsdb *
newnsdb(addr, comment, flags)
	const struct sockaddr *addr;
	const char *comment;
	int flags;
{
	struct nsdb *ns;

	if (addr->sa_len > sizeof(ns->addr))
		return NULL;

	ns = (struct nsdb *)malloc(sizeof(*ns));
	if (ns == NULL)
		return NULL;
	memset(ns, 0, sizeof(*ns));

	memcpy(&ns->addr, addr, addr->sa_len);
	if (comment)
		ns->comment = strdup(comment);
	ns->flags = flags;

	LIST_INSERT_HEAD(&nsdb, ns, link);
	return ns;
}

void
delnsdb(ns)
	struct nsdb *ns;
{

	LIST_REMOVE(ns, link);
	if (ns->comment)
		free(ns->comment);
	free(ns);
}
