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
/* YIPS @(#)$Id: sainfo.h,v 1.1 2000/04/24 07:37:44 sakane Exp $ */

#include <sys/queue.h>

/* SA info */
struct sainfo {
	int identtype;
	vchar_t *name;			/* info name. e.g. IP address, FQDN.*/

	time_t lifetime;
	int lifebyte;
	int pfs_group;			/* only use when pfs is required. */
	int myidenttype;		/* local identifier type */
	struct sainfoalg *algs[MAXALGCLASS];

	LIST_ENTRY(sainfo) chain;
};

/* algorithm type */
struct sainfoalg {
	int alg;
	int encklen;			/* key length if encryption algorithm */
	struct sainfoalg *next;
};

extern struct sainfo *getsainfo __P((caddr_t, int));
extern struct sainfo *newsainfo __P((void));
extern void delsainfo __P((struct sainfo *));
extern void inssainfo __P((struct sainfo *));
extern void remsainfo __P((struct sainfo *));
extern void flushsainfo __P((void));
extern void initsainfo __P((void));
extern struct sainfoalg *newsainfoalg __P((void));
extern void inssainfoalg __P((struct sainfoalg **, struct sainfoalg *));
extern const char * sainfo2str __P((const struct sainfo *si));
