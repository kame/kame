/*	$KAME: mld6.h,v 1.4 2002/04/03 05:37:54 itojun Exp $	*/

/*
 * Copyright (C) 1998 WIDE Project.
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

/*
 * Constans for Multicast Listener Discovery protocol for IPv6.
 */
#define MLD6_ROBUSTNESS_VARIABLE		2
#define MLD6_QUERY_INTERVAL 125	/* in seconds */
#define MLD6_QUERY_RESPONSE_INTERVAL 10000 /* in milliseconds */
#ifndef MLD6_TIMER_SCALE
#define MLD6_TIMER_SCALE 1000
#endif 
#define MLD6_LISTENER_INTERVAL (MLD6_ROBUSTNESS_VARIABLE * \
				MLD6_QUERY_INTERVAL + \
				MLD6_QUERY_RESPONSE_INTERVAL / MLD6_TIMER_SCALE)
#define	MLD6_LAST_LISTENER_QUERY_INTERVAL	1000 /* in milliseconds */
#define	MLD6_LAST_LISTENER_QUERY_COUNT		MLD6_ROBUSTNESS_VARIABLE
#define MLD6_OTHER_QUERIER_PRESENT_INTERVAL (MLD6_ROBUSTNESS_VARIABLE * \
		MLD6_QUERY_INTERVAL + \
		MLD6_QUERY_RESPONSE_INTERVAL / (2 * MLD6_TIMER_SCALE))

/* portability with older KAME headers */
#ifndef MLD_LISTENER_QUERY
#define MLD_LISTENER_QUERY	MLD6_LISTENER_QUERY
#define MLD_LISTENER_REPORT	MLD6_LISTENER_REPORT
#define MLD_LISTENER_DONE	MLD6_LISTENER_DONE
#define MLD_MTRACE_RESP		MLD6_MTRACE_RESP
#define MLD_MTRACE		MLD6_MTRACE
#define mld_hdr		mld6_hdr
#define mld_type	mld6_type
#define mld_code	mld6_code
#define mld_cksum	mld6_cksum
#define mld_maxdelay	mld6_maxdelay
#define mld_reserved	mld6_reserved
#define mld_addr	mld6_addr
#endif
