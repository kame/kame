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
/* YIPS @(#)$Id: policy.h,v 1.1 2000/01/09 01:31:30 itojun Exp $ */

#include <sys/queue.h>

/* refs. ipsec.h */
struct policyindex {
	u_int8_t dir;                   /* see ipsec.h */
	struct sockaddr_storage src;    /* IP src address for SP */
	struct sockaddr_storage dst;    /* IP dst address for SP */
	u_int8_t prefs;                 /* prefix length in bits for src */
	u_int8_t prefd;                 /* prefix length in bits for dst */
	u_int16_t ul_proto;             /* upper layer Protocol */
	int action;			/* see ipsec.h */

	struct ipsecpolicy *policy;	/* NULL if action is not IPsec. */
	struct ph2handle *ph2;		/* backpointer to ipsecsahandler */

	LIST_ENTRY(policyindex) chain;
};

/* IPsec policy */
struct ipsecpolicy {
	int pfs_group;			/* only use when pfs is required. */
	struct dhgroup *pfsgrp;		/* only use when pfs is required. */

	struct ipsecsa *proposal;	/* proposal list */
	struct policyindex *spidx;	/* backpointer to policyindex */
};

/* IPsec SA specification */
/* the most of values are defined by ipsec doi. */
/* XXX should be held like struct prop_pair ?. */
struct ipsecsa {
	int prop_no;
	int trns_no;
	time_t lifetime;
	int lifebyte;
	int proto_id;
	int ipsec_level;		/* see ipsec.h */
	int encmode;
	int enctype;
	int encklen;
	int authtype;
	int comptype;

	int pfs_group;			/* only perpose for acceptable check. */

	struct sockaddr *dst;		/* peers address of SA */

	struct ipsecsa *bundles;	/* chain of sa boundle. */
	struct ipsecsa *next;		/* next other proposal */
	struct ipsecpolicy *ipsp;	/* backpointer to ipsecpolicy */
};

extern struct policyindex *getspidx __P((struct policyindex *spidx));
extern int cmpspidx __P((struct policyindex *a, struct policyindex *b));
extern struct policyindex *newspidx __P((void));
extern void delspidx __P((struct policyindex *spidx));
extern void insspidx __P((struct policyindex *spidx));
extern void remspidx __P((struct policyindex *spidx));
extern void initspidx __P((void));

extern struct ipsecpolicy *newipsp __P((void));

extern struct ipsecsa *newipsa __P((void));
extern void insipsa __P((struct ipsecsa *new, struct ipsecpolicy *ipsp));

extern char *spidx2str __P((struct policyindex *spidx));
