/*	$KAME: db.h,v 1.18 2001/08/21 12:34:49 itojun Exp $	*/

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

struct sockdb;
enum nstype { N_UNICAST, N_MULTICAST };
struct qcache {
	LIST_ENTRY(qcache) link;
	struct sockaddr_storage from_ss;
	struct sockaddr *from;
	char *qbuf;	/* original query packet */
	int qlen;
	u_int16_t id;	/* id on relayed query - net endian */
	struct sockdb *sd;	/* inbound socket for query */
	struct timeval ttq;	/* time to quit */
	size_t rbuflen;	/* receive buffer size of the querier - for EDNS0 */
	enum nstype type;	/* mcast or unicast */
};

struct scache {
	LIST_ENTRY(scache) link;
	struct timeval tts;	/* time to send */
	char *sbuf;		/* answer to send */
	int slen;
	struct sockaddr_storage from_ss;
	struct sockaddr *from;
	struct sockaddr_storage to_ss;
	struct sockaddr *to;
	int sockidx;
};

struct nsdb {
	LIST_ENTRY(nsdb) link;
	struct sockaddr_storage addr_ss;
	struct sockaddr *addr;
	char *comment;
	enum nstype type;
	int prio;
	int nquery;
	int nresponse;
	struct timeval dormant;	/* the time when the server go usable again */
	struct timeval expire;	/* the time when the server gets unusable */
	struct timeval lasttx;	/* last packet transmit */
	struct timeval lastrx;	/* last packet delivery */
};

enum sdtype { S_UNICAST, S_MULTICAST, S_MEDIATOR, S_TCP, S_ICMP6 };
struct sockdb {
	LIST_ENTRY(sockdb) link;
	int af;
	int s;
	enum sdtype type;
};

extern LIST_HEAD(qchead, qcache) qcache;
extern LIST_HEAD(schead, scache) scache;
extern LIST_HEAD(nshead, nsdb) nsdb;
extern LIST_HEAD(sockhead, sockdb) sockdb;

extern int dbtimeo __P((void));
extern struct qcache *newqcache __P((const struct sockaddr *, char *, int,
	enum nstype));
extern void delqcache __P((struct qcache *));
extern struct scache *newscache __P((int, const struct sockaddr *,
	const struct sockaddr *, char *, int));
extern void delscache __P((struct scache *));
extern struct nsdb *newnsdb __P((const struct sockaddr *, const char *));
extern void delnsdb __P((struct nsdb *));
extern void printnsdb __P((struct nsdb *));
extern struct sockdb *newsockdb __P((int, int));
extern struct sockdb *sock2sockdb __P((int));
extern struct sockdb *af2sockdb __P((int, enum sdtype));
extern void delsockdb __P((struct sockdb *));
