/*	$KAME: tcp6_timer.h,v 1.2 2000/02/22 14:04:36 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp_timer.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET6_TCP6_TIMER_H_
#define _NETINET6_TCP6_TIMER_H_

/*
 * Definitions of the TCP6 timers.  These timers are counted
 * down PR_SLOWHZ times a second.
 */
#define	TCP6T_NTIMERS	4

#define	TCP6T_REXMT	0		/* retransmit */
#define	TCP6T_PERSIST	1		/* retransmit persistance */
#define	TCP6T_KEEP	2		/* keep alive */
#define	TCP6T_2MSL	3		/* 2*msl quiet time timer */

/*
 * The TCP6T_REXMT timer is used to force retransmissions.
 * The TCP6 has the TCP6T_REXMT timer set whenever segments
 * have been sent for which ACKs are expected but not yet
 * received.  If an ACK is received which advances tp->snd_una,
 * then the retransmit timer is cleared (if there are no more
 * outstanding segments) or reset to the base value (if there
 * are more ACKs expected).  Whenever the retransmit timer goes off,
 * we retransmit one unacknowledged segment, and do a backoff
 * on the retransmit timer.
 *
 * The TCP6T_PERSIST timer is used to keep window size information
 * flowing even if the window goes shut.  If all previous transmissions
 * have been acknowledged (so that there are no retransmissions in progress),
 * and the window is too small to bother sending anything, then we start
 * the TCP6T_PERSIST timer.  When it expires, if the window is nonzero,
 * we go to transmit state.  Otherwise, at intervals send a single byte
 * into the peer's window to force him to update our window information.
 * We do this at most as often as TCP6T_PERSMIN time intervals,
 * but no more frequently than the current estimate of round-trip
 * packet time.  The TCP6T_PERSIST timer is cleared whenever we receive
 * a window update from the peer.
 *
 * The TCP6T_KEEP timer is used to keep connections alive.  If an
 * connection is idle (no segments received) for TCP6TV_KEEP_INIT amount of time,
 * but not yet established, then we drop the connection.  Once the connection
 * is established, if the connection is idle for TCP6TV_KEEP_IDLE time
 * (and keepalives have been enabled on the socket), we begin to probe
 * the connection.  We force the peer to send us a segment by sending:
 *	<SEQ=SND.UNA-1><ACK=RCV.NXT><CTL=ACK>
 * This segment is (deliberately) outside the window, and should elicit
 * an ack segment in response from the peer.  If, despite the TCP6T_KEEP
 * initiated segments we cannot elicit a response from a peer in TCP6T_MAXIDLE
 * amount of time probing, then we drop the connection.
 */

/*
 * Time constants.
 */
#define	TCP6TV_MSL	( 30*PR_SLOWHZ)		/* max seg lifetime (hah!) */
#define	TCP6TV_SRTTBASE	0			/* base roundtrip time;
						   if 0, no idea yet */
#define	TCP6TV_SRTTDFLT	(  2*PR_SLOWHZ)		/* assumed RTT if no info */

#define	TCP6TV_PERSMIN	(  5*PR_SLOWHZ)		/* retransmit persistance */
#define	TCP6TV_PERSMAX	( 60*PR_SLOWHZ)		/* maximum persist interval */

#define	TCP6TV_KEEP_INIT	( 75*PR_SLOWHZ)		/* initial connect keep alive */
#define	TCP6TV_KEEP_IDLE	(120*60*PR_SLOWHZ)	/* dflt time before probing */
#define	TCP6TV_KEEPINTVL	( 75*PR_SLOWHZ)		/* default probe interval */
#define	TCP6TV_KEEPCNT	8			/* max probes before drop */

#define	TCP6TV_MIN	(  1*PR_SLOWHZ)		/* minimum allowable value */
#define	TCP6TV_REXMTMAX	( 64*PR_SLOWHZ)		/* max allowable REXMT value */

#define	TCP6_LINGERTIME	120			/* linger at most 2 minutes */

#define	TCP6_MAXRXTSHIFT	12			/* maximum retransmits */

#ifdef	TCP6TIMERS
char *tcp6timers[] =
    { "REXMT", "PERSIST", "KEEP", "2MSL" };
#endif

/*
 * Force a time value to be in a certain range.
 */
#define	TCP6T_RANGESET(tv, value, tvmin, tvmax) { \
	(tv) = (value); \
	if ((tv) < (tvmin)) \
		(tv) = (tvmin); \
	else if ((tv) > (tvmax)) \
		(tv) = (tvmax); \
}

#ifdef _KERNEL
extern int tcp6_maxidle;			/* time to drop after starting probes */
extern int tcp6_ttl;			/* time to live for TCP6 segs */
extern int tcp6_backoff[];
#endif

#endif /* !_NETINET6_TCP6_TIMER_H_ */
