/* 
 * $Id: macros.h,v 1.1.1.1 1999/08/08 23:29:41 itojun Exp $
 */

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

/*
 * Copyright(C)1997 by Hitachi, Ltd.
 */

#define CHECK_ETE( rp ) \
  ( IN6_IS_ADDR_UNSPECIFIED(&(rp->rip6_addr)) && (rp->rip6_prflen == 0) \
  && (rp->rip6_metric == HOPCOUNT_INFINITY) ) 

#define CHECK_NHE( rp ) \
  (rp->rip6_metric == 0xFF)

#define CHECK_RAE( rp ) \
  ((rp->rip6_prflen == 0) && (rp->rip6_metric <= HOPCOUNT_INFINITY) && (rp->rip6_metric > 0) )

#define HEURISTIC_UPDATE( lrt, rp ) \
  ( (lrt->rp_metric == rp->rip6_metric) && (lrt->rp_timer > EXPIRE_TIME/2) )

#define  IS_PREFIX_VALID( rp ) \
  ( rp->rip6_prflen <= MAX_PREFLEN )

#define  IS_METRIC_VALID( rp ) \
  ((rp->rip6_metric > 0) && ( rp->rip6_metric <= HOPCOUNT_INFINITY ) )

#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define WAIT_FOR_SIGHUP()\
  do{\
    alarm(0);\
    halted = 1;\
    signal( SIGUSR1, SIG_IGN );\
    signal( SIGUSR2, SIG_IGN );\
    signal( SIGINT, SIG_IGN ); \
    syslog( LOG_ERR, "HALT (use rip6admin restart)" );\
    while( 1 ) { \
      sleep( 1000 );\
    }\
  }while(0)

/* used in parse_config(): STATIC IGNORE */
/* prefixlen == 0 IS VALID. (for ignore all route & trace packet) */
#define IS_PTON_VALID( prefix, pref_len, pref_in6 )\
  ( (strlen(prefix) > 0) &&\
    (pref_len >= MIN_PREFLEN ) &&\
    (pref_len <= MAX_PREFLEN ) &&\
    (inet_pton(AF_INET6, prefix, pref_in6) > 0 ) )  

#define IS_VALID_ADDRESS( address, address_in6 )\
  ( (strlen(address) > 0 ) && \
    (inet_pton(AF_INET6, address, address_in6) > 0 ) )  

#define IN6_IS_ADDR_BLOCK0( address )\
  ( (address)->s6_addr[0] == 0 )
#define IN6_IS_ADDR_BLOCK1( address )\
  ( (address)->s6_addr[0] == 1 )
