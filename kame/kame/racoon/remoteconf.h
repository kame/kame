/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
/* YIPS @(#)$Id: remoteconf.h,v 1.4 2000/01/18 21:41:52 sakane Exp $ */

/* remote configuration */

#include <sys/queue.h>

struct etypes {
	int type;
	struct etypes *next;
};

struct remoteconf {
	struct sockaddr *remote;	/* remote IP address */
					/* if family is AF_UNSPEC, that is
					 * for anonymous configuration. */

	struct etypes *etypes;		/* exchange type list. the head
					 * is a type to be sent first. */
	int doitype;			/* doi type */
	int sittype;			/* situation type */
	int identtype;			/* identifier type */
	int certtype;			/* certificate type if need */
	int nonce_size;			/* the number of bytes of nonce */
	int keepalive;			/* XXX may not use */
	int dh_group;			/* use it when only aggressive mode */
	struct dhgroup *dhgrp;		/* use it when only aggressive mode */

	int retry_counter;		/* copy from lcconf, will be updated. */
	int retry_interval;		/* copy from lcconf, will be updated. */
	int count_persend;		/* copy from lcconf, will be updated. */

	struct isakmpsa *proposal;	/* proposal list */
	LIST_ENTRY(remoteconf) chain;	/* next remote conf */
};

struct dhgroup;

/* ISAKMP SA specification */
struct isakmpsa {
	int prop_no;
	int trns_no;
	time_t lifetime;
	int lifebyte;
	int enctype;
	int encklen;
	int authmethod;
	int hashtype;
	int dh_group;			/* don't use it if aggressive mode */
	struct dhgroup *dhgrp;		/* don't use it if aggressive mode */

	struct isakmpsa *next;		/* next transform */
	struct remoteconf *rmconf;	/* backpointer to remoteconf */
};

struct remoteconf *getrmconf __P((struct sockaddr *remote));
extern struct remoteconf *newrmconf __P((void));
extern void delrmconf __P((struct remoteconf *rmconf));
extern void delisakmpsa __P((struct isakmpsa *sa));
extern void deletypes __P((struct etypes *e));
extern void insrmconf __P((struct remoteconf *new));
extern void flushrmconf __P((void));
extern void initrmconf __P((void));
extern struct etypes *check_etypeok
	__P((struct remoteconf *rmconf, u_int8_t etype));

extern struct isakmpsa *newisakmpsa __P((void));
extern void insisakmpsa __P((struct isakmpsa *new, struct remoteconf *rmconf));
