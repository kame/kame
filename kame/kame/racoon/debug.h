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
/* YIPS @(#)$Id: debug.h,v 1.3 2000/02/09 05:18:07 sakane Exp $ */

#define DEBUG_INFO	0x00000002	/*XX*/
#define DEBUG_NOTIFY	0x00000004	/*XX*/
#define DEBUG_DEBUG	0x00000008	/* output plog() to stdout */

#define DEBUG_DATE	0x00000010	/*XX*/
#define DEBUG_ADDR	0x00000020	/*XX*/
#define DEBUG_STAMP	0x10000080	/* stamp */
#define DEBUG_USEFUL	0x20000000	/* use better during debugging */
#define DEBUG_SVERB	0x80000000	/* super verbose */

#define DEBUG_CONF	0x08000000	/* configuration. not output to log */
#define DEBUG_FUNC	0x04000000	/* print function name */
#define DEBUG_CRYPT	0x00800000	/*XX*/
#define DEBUG_PFKEY	0x00400000	/* PF_KEY */
#define DEBUG_KEY	0x00200000	/*XX*/
#define DEBUG_IPSEC	0x00100000	/*XX*/
#define DEBUG_SA	0x00080000	/*XX*/
#define DEBUG_NET	0x00040000	/*XX*/
#define DEBUG_CERT	0x00001000	/* certificate */
#define DEBUG_PCOMM	0x00000800	/*XX*/
#define DEBUG_ADMIN	0x00000400	/*XX*/
#define DEBUG_MISC	0x00000200	/*XX*/

#define DEBUG_DSA	(DEBUG_SVERB | DEBUG_SA)
#define DEBUG_DCRYPT	(DEBUG_SVERB | DEBUG_CRYPT)
#define DEBUG_DKEY	(DEBUG_SVERB | DEBUG_KEY)
#define DEBUG_DNET	(DEBUG_SVERB | DEBUG_NET)
#define DEBUG_DPFKEY	(DEBUG_SVERB | DEBUG_PFKEY)
#define DEBUG_DCERT	(DEBUG_SVERB | DEBUG_CERT)
#define DEBUG_DMISC	(DEBUG_SVERB | DEBUG_MISC)

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
extern u_int32_t debug;
extern int f_debugcmd;
extern int f_local;
extern int vflag;
