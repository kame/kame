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
 *
 *	$Id: miscvar.h,v 1.4 2000/02/18 11:39:54 fujisawa Exp $
 */

void		 setInterface		__P((char *, int));
void		 setPrefix		__P((int, struct addrinfo *, int));
void		 setFaithRule		__P((struct pAddr *));
void		 setRule		__P((int, int, struct pAddr *, struct pAddr *));
void		 setFromAnyRule		__P((int, int, int, u_short *, struct pAddr *));
void		 flushRule		__P((int));
void		 enableTranslate	__P((int));
void		 setValue		__P((char *, int));
void		 testLog		__P((char *));
void		 debugBreak		__P((void));

int		 soctl			__P((int, u_long, ...));

struct addrinfo	*getAddrInfo		__P((int, char *));
struct pAddr	*getAddrPort		__P((int, int, struct addrinfo *, void *));
struct pAddr	*setAddrPort		__P((struct pAddr *, u_short *));

int		 in6_prefix2len		__P((struct in6_addr *));

int		 in4_mask2len		__P((struct in_addr *));
int		 in6_mask2len		__P((struct in6_addr *));
struct in_addr	*in4_len2mask		__P((int));
struct in6_addr *in6_len2mask		__P((int));

void		 debugProbe		__P((char *));
void		 openFD			__P((void));
void		 closeFD		__P((void));
void		 init_misc		__P((void));


