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
/* YIPS @(#)$Id: debug.h,v 1.1.1.1 1999/08/08 23:31:20 itojun Exp $ */

#define DEBUG_INFO    0x00000002
#define DEBUG_NOTIFY  0x00000004
#define DEBUG_DEBUG   0x00000008

#define DEBUG_DATE    0x00000010
#define DEBUG_ADDR    0x00000020
#define DEBUG_DUMP    0x00000040
#define DEBUG_STAMP   0x00000080

#define DEBUG_CONF    0x40000000
#define DEBUG_SCHED2  0x20000000
#define DEBUG_SCHED   0x10000000
#define DEBUG_CRYPT   0x08000000
#define DEBUG_KEY     0x04000000	/* DH, AUTH_KEY, HASH, SKEYID, KEYMAT */
#define DEBUG_SA      0x00100000
#define DEBUG_IPSEC   0x00x00000
#define DEBUG_NET     0x00020000
#define DEBUG_PFKEY   0x00010000
#define DEBUG_PCOMM   0x00000100
#define DEBUG_ADMIN   0x00000200
#define DEBUG_MISC    0x00000400

#define DEBUG_DSA     (DEBUG_DUMP | DEBUG_SA)
#define DEBUG_DCRYPT  (DEBUG_DUMP | DEBUG_CRYPT)
#define DEBUG_DKEY    (DEBUG_DUMP | DEBUG_KEY)
#define DEBUG_DNET    (DEBUG_DUMP | DEBUG_NET)
#define DEBUG_DPFKEY  (DEBUG_DUMP | DEBUG_PFKEY)
#define DEBUG_DMISC   (DEBUG_DUMP | DEBUG_MISC)

#if defined(YIPS_DEBUG)
#define YIPSDEBUG(lev,arg) if ((debug & (lev)) == (lev)) { arg; }
#else
#define YIPSDEBUG(lev,arg)
#endif /* defined(YIPS_DEBUG) */

#define YIPSLOG(lev,arg) if ((debug & (lev)) == (lev)) { arg; }

#ifdef HAVE_FUNCTION_MACRO
#define LOCATION	debug_location(__FILE__, __LINE__, __FUNCTION__)
#else
#define LOCATION	debug_location(__FILE__, __LINE__, NULL)
#endif

/* define by main.c */
extern char *pname;
extern unsigned long debug;
extern int f_debug;
extern int f_local;
extern int af;
extern int vflag;
