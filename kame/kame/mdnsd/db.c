/*	$KAME: db.c,v 1.10 2001/05/02 11:07:56 itojun Exp $	*/

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

#include <arpa/nameser.h>
#include <arpa/inet.h>

#include "mdnsd.h"
#include "db.h"

struct qchead qcache;
#if 0
struct achead acache;
#endif
struct schead scache;
struct nshead nsdb;
struct sockhead sockdb;

int
dbtimeo()
{
	struct qcache *qc, *nqc;
	struct scache *sc, *nsc;
	struct nsdb *ns, *nns;
	struct timeval tv;
	int errcnt;

	(void)gettimeofday(&tv, NULL);

	/* check query cache */
	errcnt = 0;
	for (qc = LIST_FIRST(&qcache); qc; qc = nqc) {
		HEADER *hp;

		nqc = LIST_NEXT(qc, link);

		if (qc->ttq.tv_sec > tv.tv_sec)
			continue;
		if (qc->ttq.tv_sec == tv.tv_sec && qc->ttq.tv_usec > tv.tv_usec)
			continue;

		/* send NXDOMAIN to querier */
		hp = (HEADER *)qc->qbuf;
		hp->rcode = NXDOMAIN;
		if (sendto(qc->sd->s, qc->qbuf, qc->qlen, 0,
		    (struct sockaddr *)&qc->from, qc->from.ss_len) < 0)
			errcnt++;

		dprintf("query %p expired\n", qc);
		delqcache(qc);
	}

	/* check transmit queue */
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

	/* check expiry of servers */
	for (ns = LIST_FIRST(&nsdb); ns; ns = nns) {
		nns = LIST_NEXT(ns, link);

#if 0
		if (dflag)
			printnsdb(ns);
#endif

		if (ns->expire.tv_sec == -1 && ns->expire.tv_usec == -1)
			continue;

		if (ns->expire.tv_sec > tv.tv_sec)
			continue;
		if (ns->expire.tv_sec == tv.tv_sec &&
		    ns->expire.tv_usec > tv.tv_usec)
			continue;

		if (dflag)
			printnsdb(ns);
		dprintf("ns %p expired\n", ns);
		delnsdb(ns);
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
newnsdb(addr, comment)
	const struct sockaddr *addr;
	const char *comment;
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

void
printnsdb(ns)
	struct nsdb *ns;
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	printf("ns %p", ns);
	if (getnameinfo((struct sockaddr *)&ns->addr, ns->addr.ss_len,
	    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), niflags) == 0) {
		printf(" %s %s", hbuf, sbuf);
	} else
		printf(" addr? serv?");
	printf(" type %d prio %d", ns->type, ns->prio);
	if (ns->expire.tv_sec == -1 && ns->expire.tv_usec == -1)
		printf(" expire never");
	else
		printf(" expire %lu", (u_long)ns->expire.tv_sec);
	printf(" lasttx %lu", (u_long)ns->lasttx.tv_sec);
	printf(" lastrx %lu", (u_long)ns->lastrx.tv_sec);
	if (ns->comment)
		printf(" comment \"%s\"", ns->comment);

	printf("\n");
}

struct sockdb *
newsockdb(s, af)
	int s;
	int af;
{
	struct sockdb *sd;

	sd = (struct sockdb *)malloc(sizeof(*sd));
	if (sd == NULL)
		return NULL;
	memset(sd, 0, sizeof(*sd));

	sd->s = s;
	sd->af = af;

	LIST_INSERT_HEAD(&sockdb, sd, link);
	return sd;
}

struct sockdb *
sock2sockdb(s)
	int s;
{
	struct sockdb *sd;

	for (sd = LIST_FIRST(&sockdb); sd; sd = LIST_NEXT(sd, link)) {
		if (sd->s == s)
			return sd;
	}
	return NULL;
}

struct sockdb *
af2sockdb(af, type)
	int af;
	enum sdtype type;
{
	struct sockdb *sd;

	for (sd = LIST_FIRST(&sockdb); sd; sd = LIST_NEXT(sd, link)) {
		if (sd->af != af)
			continue;
		if (sd->type != type)
			continue;
		return sd;
	}
	return NULL;
}

void
delsockdb(sd)
	struct sockdb *sd;
{

	LIST_REMOVE(sd, link);
	free(sd);
}
