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
/* YIPS @(#)$Id: misc.h,v 1.1.1.1 1999/08/08 23:31:24 itojun Exp $ */

#define YDUMP_BIN 0
#define YDUMP_HEX 1

#define GET_NEWBUF(dst, t, src, len) \
	((dst) = (t)get_newbuf((src), (len)))

struct sockaddr;

extern char _addr1_[BUFADDRSIZE], _addr2_[BUFADDRSIZE];

extern int plog0 __P((const char *, ...));
extern int plog __P((const char *, const char *, ...));
extern int plog2 __P((struct sockaddr *, const char *, const char *,
	...));
extern int pdump __P((void *, int, int));
extern u_char *mem2str __P((const u_char *, int));
extern char *strtob __P((char *, int, int *));

extern int saddrcmp_woport __P((struct sockaddr *addr1,
	struct sockaddr *addr2));
extern int saddrcmp __P((struct sockaddr *addr1, struct sockaddr *addr2));
extern caddr_t hexstr2val __P((caddr_t buf, u_int len));
extern void *get_newbuf __P((void *src, u_int len));
extern struct sockaddr *get_localaddr __P((struct sockaddr *));
extern int recvfromto __P((int, void *, size_t, int, struct sockaddr *,
	int *, struct sockaddr *, int *));
extern int sendfromto __P((int, const void *, size_t, struct sockaddr *,
	struct sockaddr *));
extern int setsockopt_bypass __P((int so, int family));
extern const char *debug_location __P((char *, int, char *));
