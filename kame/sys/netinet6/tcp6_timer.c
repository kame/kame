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
 * Copyright (c) 1996, 1997 Berkeley Software Design, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that this notice is retained,
 * the conditions in the following notices are met, and terms applying
 * to contributors in the following notices also apply to Berkeley
 * Software Design, Inc.
 *
 *	BSDI tcp_timer.c,v 2.9 1997/01/16 14:06:35 karels Exp
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
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
 *	@(#)tcp_timer.c	8.2 (Berkeley) 5/24/95
 */

#ifndef TUBA_INCLUDE
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#endif /* TUBA_INCLUDE */

#if 0
extern	int tcp6_keepidle;
extern	int tcp6_keepintvl;
extern	int tcp6_keepcnt;
extern	int tcp6_maxpersistidle;
#endif
int	tcp6_maxidle;

/*
 * Fast timeout routine for processing delayed acks
 */
void
tcp6_fasttimo()
{
	register struct tcp6cb *t6p, *t6pnext;
#ifdef __NetBSD__
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	for (t6p = tcp6_delacks.lh_first; t6p; t6p = t6pnext) {
		t6pnext = t6p->t_delacks.le_next;
		t6p->t_flags |= TF_ACKNOW;
		tcp6stat.tcp6s_delack++;
		/* we assume that tcp6_output will invoke tcp6_delack_done() */
		(void) tcp6_output(t6p);
	}
	splx(s);
}

/*
 * Tcp protocol timeout routine called every 500 ms.
 * Updates the timers in all active tcb6's and
 * causes finite state machine actions if timers expire.
 */
void
tcp6_slowtimo()
{
	register struct in6pcb *ip6, *ip6nxt;
	register struct tcp6cb *t6p = (struct tcp6cb *)NULL;
#ifdef __NetBSD__
	int s = splsoftnet();
#else
	int s = splnet();
#endif
	register int i;
#if 0
	extern int tcp6_msltime;
#endif
	struct rtentry *rt;
	static int syn_cache_last = 0;

	tcp6_maxidle = tcp6_keepcnt * tcp6_keepintvl;
	/*
	 * Search through tcb6's and update active timers.
	 */
	ip6 = tcb6.in6p_next;
	if (ip6 == 0) {
		splx(s);
		return;
	}
	for (; ip6 != &tcb6; ip6 = ip6nxt) {
		ip6nxt = ip6->in6p_next;
		t6p = intotcp6cb(ip6);
		if (t6p == 0 || t6p->t_state == TCP6S_LISTEN)
			continue;
		/*
		 * The first part of the connection queue contains
		 * connections in states before TIME_WAIT; stop
		 * at the first TIME_WAIT connection.
		 */
		if (t6p->t_state == TCP6S_TIME_WAIT)
			break;
		for (i = 0; i < TCP6T_NTIMERS; i++) {
			if (t6p->t_timer[i] && --t6p->t_timer[i] == 0) {
				(void) tcp6_usrreq(ip6->in6p_socket,
				    PRU_SLOWTIMO, (struct mbuf *)0,
				    (struct mbuf *)i, (struct mbuf *)0
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
				    , 0
#endif
				    );
				if (ip6nxt->in6p_prev != ip6)
					goto t6pgone;
			}
		}
		if (((rt = ip6->in6p_route.ro_rt) != NULL) &&
		    ((rt->rt_rmx.rmx_locks & RTV_MTU) == 0) &&
		    ((rt->rt_flags & RTF_PROBEMTU) != 0))
			tcp6_agepathmtu(ip6, rt);
		t6p->t_idle++;
		if (t6p->t_rtt)
			t6p->t_rtt++;
t6pgone:
		;
	}
	/*
	 * If we did not hit the end of the queue, we must
	 * have hit the oldest connection in TIME_WAIT state.
	 * Decrement its remaining time; if expired, time out
	 * this connection and each following connection with
	 * no additional remaining time.
	 */
	if ((ip6 != &tcb6) && (--t6p->t_timer[TCP6T_2MSL] <= 0)) {
		for (;;) {
			ip6nxt = ip6->in6p_next;
			(void) tcp6_usrreq(ip6->in6p_socket,
			    PRU_SLOWTIMO, (struct mbuf *)0,
			    (struct mbuf *)TCP6T_2MSL, (struct mbuf *)0
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
			    , 0
#endif
			    );
			if ((ip6 = ip6nxt) == &tcb6)
				break;
			t6p = intotcp6cb(ip6);
			if (t6p->t_timer[TCP6T_2MSL])
				break;
		}
	}
	if (tcp6_msltime > 0)
		--tcp6_msltime;
	tcp6_iss += TCP6_ISSINCR/PR_SLOWHZ;		/* increment iss */
#ifdef TCP6_COMPAT_42
	if ((int)tcp6_iss < 0)
		tcp6_iss = TCP6_ISSINCR;			/* XXX */
#endif
	tcp6_now++;					/* for timestamps */
	if (++syn_cache_last >= tcp6_syn_cache_interval) {
		syn_cache_timer6(syn_cache_last);
		syn_cache_last = 0;
	}
	splx(s);
}
#ifndef TUBA_INCLUDE

/*
 * Cancel all timers for TCP6 t6p.
 */
void
tcp6_canceltimers(t6p)
	struct tcp6cb *t6p;
{
	register int i;

	for (i = 0; i < TCP6T_NTIMERS; i++)
		t6p->t_timer[i] = 0;
}

int	tcp6_backoff[TCP6_MAXRXTSHIFT + 1] =
    { 1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64 };

int tcp6_totbackoff = 511;	/* sum of tcp6_backoff[] */

/*
 * TCP6 timer processing.
 */
struct tcp6cb *
tcp6_timers(t6p, timer)
	register struct tcp6cb *t6p;
	int timer;
{
	register int rexmt;

	switch (timer) {

	/*
	 * 2 MSL timeout in shutdown went off.  If we're closed but
	 * still waiting for peer to close and connection has been idle
	 * too long, or if 2MSL time is up from TIME_WAIT, delete connection
	 * control block.  Otherwise, check again in a bit.
	 */
	case TCP6T_2MSL:
		if (t6p->t_state != TCP6S_TIME_WAIT &&
		    t6p->t_idle <= tcp6_maxidle)
			t6p->t_timer[TCP6T_2MSL] = tcp6_keepintvl;
		else
			t6p = tcp6_close(t6p);
		break;

	/*
	 * Retransmission timer went off.  Message has not
	 * been acked within retransmit interval.  Back off
	 * to a longer retransmit interval and retransmit one segment.
	 */
	case TCP6T_REXMT:
		if (++t6p->t_rxtshift > TCP6_MAXRXTSHIFT) {
			t6p->t_rxtshift = TCP6_MAXRXTSHIFT;
			tcp6stat.tcp6s_timeoutdrop++;
			t6p = tcp6_drop(t6p, t6p->t_softerror ?
			    t6p->t_softerror : ETIMEDOUT);
			break;
		}
		tcp6stat.tcp6s_rexmttimeo++;
		rexmt = TCP6_REXMTVAL(t6p) * tcp6_backoff[t6p->t_rxtshift];
		TCP6T_RANGESET(t6p->t_rxtcur, rexmt,
		    t6p->t_rttmin, TCP6TV_REXMTMAX);
		t6p->t_timer[TCP6T_REXMT] = t6p->t_rxtcur;
		/*
		 * If losing, let the lower level know and try for
		 * a better route.  Also, if we backed off this far,
		 * our srtt estimate is probably bogus.  Clobber it
		 * so we'll take the next rtt measurement as our srtt;
		 * move the current srtt into rttvar to keep the current
		 * retransmit times until then.
		 */
		if (t6p->t_rxtshift > TCP6_MAXRXTSHIFT / 4) {
			in6_losing(t6p->t_in6pcb);
			t6p->t_rttvar += (t6p->t_srtt >> TCP6_RTT_SHIFT);
			t6p->t_srtt = 0;
		}
		t6p->snd_nxt = t6p->snd_una;
		/*
		 * If timing a segment in this window, stop the timer.
		 */
		t6p->t_rtt = 0;
		/*
		 * Close the congestion window down to one segment
		 * (we'll open it by one segment for each ack we get).
		 * Since we probably have a window's worth of unacked
		 * data accumulated, this "slow start" keeps us from
		 * dumping all that data as back-to-back packets (which
		 * might overwhelm an intermediate gateway).
		 *
		 * There are two phases to the opening: Initially we
		 * open by one mss on each ack.  This makes the window
		 * size increase exponentially with time.  If the
		 * window is larger than the path can handle, this
		 * exponential growth results in dropped packet(s)
		 * almost immediately.  To get more time between 
		 * drops but still "push" the network to take advantage
		 * of improving conditions, we switch from exponential
		 * to linear window opening at some threshhold size.
		 * For a threshhold, we use half the current window
		 * size, truncated to a multiple of the mss.
		 *
		 * (the minimum cwnd that will give us exponential
		 * growth is 2 mss.  We don't allow the threshhold
		 * to go below this.)
		 */
		{
		u_int win = min(t6p->snd_wnd, t6p->snd_cwnd) / 2 / t6p->t_maxseg;
		if (win < 2)
			win = 2;
		t6p->snd_cwnd = t6p->t_maxseg;
		t6p->snd_ssthresh = win * t6p->t_maxseg;
		t6p->t_dupacks = 0;
		}
		(void) tcp6_output(t6p);
		break;

	/*
	 * Persistance timer into zero window.
	 * Force a byte to be output, if possible.
	 */
	case TCP6T_PERSIST:
		tcp6stat.tcp6s_persisttimeo++;
		/*
		 * Hack: if the peer is dead/unreachable, we do not
		 * time out if the window is closed.  After a full
		 * backoff, drop the connection if the idle time
		 * (no responses to probes) reaches the maximum
		 * backoff that we would use if retransmitting.
		 */
		if (t6p->t_rxtshift == TCP6_MAXRXTSHIFT &&
		    (t6p->t_idle >= tcp6_maxpersistidle ||
		    t6p->t_idle >= TCP6_REXMTVAL(t6p) * tcp6_totbackoff)) {
			tcp6stat.tcp6s_persistdrop++;
			t6p = tcp6_drop(t6p, ETIMEDOUT);
			break;
		}
		tcp6_setpersist(t6p);
		t6p->t_force = 1;
		(void) tcp6_output(t6p);
		t6p->t_force = 0;
		break;

	/*
	 * Keep-alive timer went off; send something
	 * or drop connection if idle for too long.
	 */
	case TCP6T_KEEP:
		tcp6stat.tcp6s_keeptimeo++;
		if (t6p->t_state < TCP6S_ESTABLISHED)
			goto dropit;
		if (t6p->t_in6pcb->in6p_socket->so_options & SO_KEEPALIVE &&
		    t6p->t_state <= TCP6S_CLOSE_WAIT) {
		    	if (t6p->t_idle >= tcp6_keepidle + tcp6_maxidle)
				goto dropit;
			/*
			 * Send a packet designed to force a response
			 * if the peer is up and reachable:
			 * either an ACK if the connection is still alive,
			 * or an RST if the peer has closed the connection
			 * due to timeout or reboot.
			 * Using sequence number t6p->snd_una-1
			 * causes the transmitted zero-length segment
			 * to lie outside the receive window;
			 * by the protocol spec, this requires the
			 * correspondent TCP6 to respond.
			 */
			tcp6stat.tcp6s_keepprobe++;
#ifdef TCP6_COMPAT_42
			/*
			 * The keepalive packet must have nonzero length
			 * to get a 4.2 host to respond.
			 */
			(void) tcp6_respond(t6p, t6p->t_template->i6t_i,
			    &t6p->t_template->i6t_t, (struct mbuf *)NULL,
			    t6p->rcv_nxt - 1, t6p->snd_una - 1, 0);
#else
			(void) tcp6_respond(t6p, &t6p->t_template->i6t_i,
			    &t6p->t_template->i6t_t, (struct mbuf *)NULL,
			    t6p->rcv_nxt, t6p->snd_una - 1, 0);
#endif
			t6p->t_timer[TCP6T_KEEP] = tcp6_keepintvl;
		} else
			t6p->t_timer[TCP6T_KEEP] = tcp6_keepidle;
		break;
	dropit:
		tcp6stat.tcp6s_keepdrops++;
		t6p = tcp6_drop(t6p, ETIMEDOUT);
		break;
	}
	return (t6p);
}
#endif /* TUBA_INCLUDE */
