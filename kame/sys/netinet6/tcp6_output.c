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
 *	BSDI tcp_output.c,v 2.11 1997/01/16 14:06:34 karels Exp
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
 *	@(#)tcp_output.c	8.4 (Berkeley) 5/24/95
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#ifdef __NetBSD__	/*XXX*/
#include "opt_ipsec.h"
#endif
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet6/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/tcp6.h>
#define	TCP6OUTFLAGS
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#include <netinet6/tcp6_debug.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#ifdef notyet
extern struct mbuf *m_copypack();
#endif


#define MAX_TCP6OPTLEN	32	/* max # bytes that go in options */

/*
 * Tcp output routine: figure out what should be sent and send it.
 */
int
tcp6_output(t6p)
	struct tcp6cb *t6p;
{
	struct	socket *so = t6p->t_in6pcb->in6p_socket;
	long	len, win;
	int	off, flags, error;
	struct	mbuf *m;
	struct	ip6_hdr *ip6;
	struct	tcp6hdr *th;
	u_char	opt[MAX_TCP6OPTLEN];
	u_int	optlen, hdrlen, exthdrlen;
	int	idle, sendalot;

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (t6p->t_flags & TF_WASIDLE) ? 1 : (t6p->snd_max == t6p->snd_una);
	if (idle) {
		if (t6p->t_idle >= t6p->t_rxtcur)
			/*
			 * We have been idle for "a while" and no acks are
			 * expected to clock out any data we send --
			 * slow start to get ack "clock" running again.
			 */
			t6p->snd_cwnd = 2*t6p->t_maxseg;
#if 0 /*XXX*/
		if (somoretosend(so)) {
			t6p->t_flags |= TF_WASIDLE;
			idle = 0;
			goto again;
		}
#endif
	}
	t6p->t_flags &= ~TF_WASIDLE;
again:
	sendalot = 0;
	off = t6p->snd_nxt - t6p->snd_una;
	win = min(t6p->snd_wnd, t6p->snd_cwnd);

	flags = tcp6_outflags[t6p->t_state];
	/*
	 * If in persist timeout with window of 0, send 1 byte.
	 * Otherwise, if window is small but nonzero
	 * and timer expired, we will send what we can
	 * and go to transmit state.
	 */
	if (t6p->t_force) {
		if (win == 0) {
			/*
			 * If we still have some data to send, then
			 * clear the FIN bit.  Usually this would
			 * happen below when it realizes that we
			 * aren't sending all the data.  However,
			 * if we have exactly 1 byte of unset data,
			 * then it won't clear the FIN bit below,
			 * and if we are in persist state, we wind
			 * up sending the packet without recording
			 * that we sent the FIN bit.
			 *
			 * We can't just blindly clear the FIN bit,
			 * because if we don't have any more data
			 * to send then the probe will be the FIN
			 * itself.
			 */
			if (off < so->so_snd.sb_cc)
				flags &= ~TH_FIN;
			win = 1;
		} else {
			t6p->t_timer[TCP6T_PERSIST] = 0;
			t6p->t_rxtshift = 0;
		}
	}

	if (win < so->so_snd.sb_cc) {
		len = win - off;
		if (idle) {
			t6p->t_flags |= TF_WASIDLE;
			idle = 0;
		}
	} else
		len = so->so_snd.sb_cc - off;

	if (len < 0) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be -1.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back
		 * to (closed) window, and set the persist timer
		 * if it isn't already going.  If the window didn't
		 * close completely, just wait for an ACK.
		 */
		len = 0;
		if (win == 0) {
			t6p->t_timer[TCP6T_REXMT] = 0;
			t6p->t_rxtshift = 0;
			t6p->snd_nxt = t6p->snd_una;
			if (t6p->t_timer[TCP6T_PERSIST] == 0)
				tcp6_setpersist(t6p);
		}
	}
	if (len > t6p->t_maxseg) {
		len = t6p->t_maxseg;
		sendalot = 1;
	}
	if (SEQ_LT(t6p->snd_nxt + len, t6p->snd_una + so->so_snd.sb_cc))
		flags &= ~TH_FIN;

	win = sbspace(&so->so_rcv);

	/*
	 * Sender silly window avoidance.  If connection is idle
	 * and can send all data or a maximum segment,
	 * or are forced, do it; otherwise don't bother.
	 * If peer's buffer is tiny, then send
	 * when window is at least half open.
	 * If retransmitting (possibly after persist timer forced us
	 * to send into a small window), then must resend.
	 */
	if (len) {
		if (len == t6p->t_maxseg)
			goto send;
		if ((idle || t6p->t_flags & TF_NODELAY) &&
		    len + off >= so->so_snd.sb_cc)
			goto send;
		if (t6p->t_force)
			goto send;
		if (len >= t6p->max_sndwnd / 2)
			goto send;
		if (SEQ_LT(t6p->snd_nxt, t6p->snd_max))
			goto send;
	}

	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 *
	 * Of course, if we've already received the FIN, there's
	 * no point in sending out a window update.
	 */
	if (win > 0 && !TCP6S_HAVERCVDFIN(t6p->t_state)) {
		/* 
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP6_MAXWIN << t6p->rcv_scale.
		 */
		long adv = min(win, (long)TCP6_MAXWIN << t6p->rcv_scale) -
			(t6p->rcv_adv - t6p->rcv_nxt);

		if (adv >= (long) (2 * t6p->t_maxseg))
			goto send;
		if (2 * adv >= (long) so->so_rcv.sb_hiwat)
			goto send;
	}

	/*
	 * Send if we owe peer an ACK.
	 */
	if (t6p->t_flags & TF_ACKNOW)
		goto send;
	if (flags & (TH_SYN|TH_RST))
		goto send;
	if (SEQ_GT(t6p->snd_up, t6p->snd_nxt))
		goto send;
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, or we're retransmitting the FIN,
	 * then we need to send.
	 */
	if (flags & TH_FIN && ((t6p->t_flags & TF_SENTFIN) == 0 ||
	    SEQ_LT(t6p->snd_nxt, t6p->snd_max)))
		goto send;

	/*
	 * TCP6 window updates are not reliable, rather a polling protocol
	 * using ``persist'' packets is used to insure receipt of window
	 * updates.  The three ``states'' for the output side are:
	 *	idle			not doing retransmits or persists
	 *	persisting		to move a small or zero window
	 *	(re)transmitting	and thereby not persisting
	 *
	 * t6p->t_timer[TCP6T_PERSIST]
	 *	is set when we are in persist state.
	 * t6p->t_force
	 *	is set when we are called to send a persist packet.
	 * t6p->t_timer[TCP6T_REXMT]
	 *	is set when we are retransmitting
	 * The output side is idle when both timers are zero.
	 *
	 * If send window is too small, there is data to transmit, and no
	 * retransmit or persist is pending, then go to persist state.
	 * If nothing happens soon, send when timer expires:
	 * if window is nonzero, transmit what we can,
	 * otherwise force out a byte.
	 */
	if (so->so_snd.sb_cc && t6p->t_timer[TCP6T_REXMT] == 0 &&
	    t6p->t_timer[TCP6T_PERSIST] == 0) {
		t6p->t_rxtshift = 0;
		tcp6_setpersist(t6p);
	}

	/*
	 * No reason to send a segment, just return.
	 */
	return (0);

send:
	/*
	 * Before ESTABLISHED, force sending of initial options
	 * unless TCP6 set not to do any options.
	 * NOTE: we assume that the IP6/TCP6 header plus TCP6 options
	 * always fit in a single mbuf, leaving room for a maximum
	 * link header, i.e.
	 *	max_linkhdr + sizeof(struct ip6tcp) + optlen <= MHLEN
	 */
	optlen = 0;
	hdrlen = sizeof(struct ip6tcp); 
	if (flags & TH_SYN) {
		t6p->snd_nxt = t6p->iss;
		if ((t6p->t_flags & TF_NOOPT) == 0) {
			u_short mss;

			opt[0] = TCP6OPT_MAXSEG;
			opt[1] = 4;
			mss = htons((u_short) tcp6_send_mss(t6p));
			bcopy((caddr_t)&mss, (caddr_t)(opt + 2), sizeof(mss));
			optlen = 4;
	 
			if (t6p->t_flags & TF_USE_SCALE) {
				*((u_long *) (opt + optlen)) = htonl(
					TCP6OPT_NOP << 24 |
					TCP6OPT_WINDOW << 16 |
					TCP6OLEN_WINDOW << 8 |
					t6p->request_r_scale);
				optlen += 4;
			}
		}
 	}

	/* length occupied by IPv6 extension headers */
	exthdrlen = ip6_optlen(t6p->t_in6pcb);
#ifdef IPSEC
	exthdrlen += ipsec6_hdrsiz_tcp(t6p);
#endif

 	/*
	 * Send a timestamp and echo-reply if this is a SYN and our side 
	 * wants to use timestamps (TF_SEND_TSTMP is set) or both our side
	 * and our peer have sent timestamps in our SYN's.
 	 */
 	if (t6p->t_flags & TF_SEND_TSTMP && (flags & TH_RST) == 0) {
		u_long *lp = (u_long *)(opt + optlen);
 
 		/* Form timestamp option as shown in appendix A of RFC 1323. */
 		*lp++ = htonl(TCP6OPT_TSTAMP_HDR);
 		*lp++ = htonl(tcp6_now);
 		*lp   = htonl(t6p->ts_recent);
 		optlen += TCP6OLEN_TSTAMP_APPA;
 	}

 	hdrlen += optlen;

#if 1 /*def already_accounted_for*/
	/*
	 * Adjust data length if insertion of options will
	 * bump the packet length beyond the t_maxseg length.
	 */
	if (len > t6p->t_maxseg - optlen - exthdrlen) {
		len = t6p->t_maxseg - optlen - exthdrlen;
		sendalot = 1;
		flags &= ~TH_FIN;
	}
#endif


#ifdef DIAGNOSTIC
 	if (max_linkhdr + hdrlen > MHLEN)
		panic("tcp6hdr too big");
#endif

	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		if (t6p->t_force && len == 1)
			tcp6stat.tcp6s_sndprobe++;
		else if (SEQ_LT(t6p->snd_nxt, t6p->snd_max)) {
			tcp6stat.tcp6s_sndrexmitpack++;
			tcp6stat.tcp6s_sndrexmitbyte += len;
		} else {
			tcp6stat.tcp6s_sndpack++;
			tcp6stat.tcp6s_sndbyte += len;
		}
#ifdef notyet
		if ((m = m_copypack(so->so_snd.sb_mb, off,
		    (int)len, max_linkhdr + hdrlen)) == 0) {
			error = ENOBUFS;
			goto out;
		}
		/*
		 * m_copypack left space for our hdr; use it.
		 */
		m->m_len += hdrlen;
		m->m_data -= hdrlen;
#else
		MGETHDR(m, M_DONTWAIT, MT_HEADER);
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;
		if (len <= MHLEN - hdrlen - max_linkhdr) {
			m_copydata(so->so_snd.sb_mb, off, (int) len,
			    mtod(m, caddr_t) + hdrlen);
			m->m_len += len;
		} else {
			m->m_next = m_copy(so->so_snd.sb_mb, off, (int) len);
			if (m->m_next == 0) {
				(void) m_free(m);
				error = ENOBUFS;
				goto out;
			}
		}
#endif
		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 */
		if (off + len == so->so_snd.sb_cc)
			flags |= TH_PUSH;
	} else {
		if (t6p->t_flags & TF_ACKNOW)
			tcp6stat.tcp6s_sndacks++;
		else if (flags & (TH_SYN|TH_FIN|TH_RST))
			tcp6stat.tcp6s_sndctrl++;
		else if (SEQ_GT(t6p->snd_up, t6p->snd_nxt))
			tcp6stat.tcp6s_sndurg++;
		else
			tcp6stat.tcp6s_sndwinup++;

		MGETHDR(m, M_DONTWAIT, MT_HEADER);
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;
	}
	m->m_pkthdr.rcvif = (struct ifnet *)0;
	ip6 = mtod(m, struct ip6_hdr *);
	th = (struct tcp6hdr *)(ip6 + 1);
	if (t6p->t_template == 0)
		panic("tcp6_output");
	bcopy((caddr_t)t6p->t_template, (caddr_t)ip6, sizeof(struct ip6tcp));
	/*
	 * we separately set hoplimit for every segment, since the user
	 * might want to change the value via setsockopt. Also, desired
	 * default hop limit might be changed via Neighbor Discovery.
	 */
	ip6->ip6_hlim = in6_selecthlim(t6p->t_in6pcb,
				       t6p->t_in6pcb->in6p_route.ro_rt ?
				       t6p->t_in6pcb->in6p_route.ro_rt->rt_ifp
				       : NULL);

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if (flags & TH_FIN && t6p->t_flags & TF_SENTFIN && 
	    t6p->snd_nxt == t6p->snd_max)
		t6p->snd_nxt--;
	/*
	 * If we are doing retransmissions, then snd_nxt will
	 * not reflect the first unsent octet.  For ACK only
	 * packets, we do not want the sequence number of the
	 * retransmitted packet, we want the sequence number
	 * of the next unsent octet.  So, if there is no data
	 * (and no SYN or FIN), use snd_max instead of snd_nxt
	 * when filling in th_seq.  But if we are in persist
	 * state, snd_max might reflect one byte beyond the
	 * right edge of the window, so use snd_nxt in that
	 * case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */
	if (len || (flags & (TH_SYN|TH_FIN)) || t6p->t_timer[TCP6T_PERSIST])
		th->th_seq = htonl(t6p->snd_nxt);
	else
		th->th_seq = htonl(t6p->snd_max);
	th->th_ack = htonl(t6p->rcv_nxt);
	if (optlen) {
		bcopy((caddr_t)opt, (caddr_t)(th + 1), optlen);
		th->th_off = (sizeof(struct tcp6hdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (win < (long)(so->so_rcv.sb_hiwat / 4) && win < (long)t6p->t_maxseg)
		win = 0;
	if (win > (long)TCP6_MAXWIN << t6p->rcv_scale)
		win = (long)TCP6_MAXWIN << t6p->rcv_scale;
	if (win < (long)(t6p->rcv_adv - t6p->rcv_nxt))
		win = (long)(t6p->rcv_adv - t6p->rcv_nxt);
	th->th_win = htons((u_short) (win>>t6p->rcv_scale));

	/*
	 * If no urgent pointer is outstanding, then we pull the
	 * urgent pointer to the left edge of the send window so
	 * that it doesn't drift into the send window on sequence
	 * number wraparound.  Otherwise, if the urgent pointer
	 * points into/after this packet, add it in.
	 */
	if (SEQ_GT(t6p->snd_up, t6p->snd_una)) {
		if (SEQ_GT(t6p->snd_up, t6p->snd_nxt)) {
			int urp = t6p->snd_up - t6p->snd_nxt;
			/*
			 * Internally we store the urgent pointer as the first
			 * byte of non-urgent data.  But in the packet, the
			 * urgent pointer is supposed to be the last byte of
			 * urgent data.  If the user specified TF_STDURG then
			 * use this behavior, otherwise use the old method.
			 */
			if (t6p->t_flags & TF_STDURG)
				urp--;
			if (urp > 65535)
				urp = 65535;
			th->th_urp = htons((u_short)urp);
			th->th_flags |= TH_URG;
		}
	} else
		t6p->snd_up = t6p->snd_una;

	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */
	if (t6p->t_force == 0 || t6p->t_timer[TCP6T_PERSIST] == 0) {
		tcp6_seq startseq = t6p->snd_nxt;

		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (flags & (TH_SYN|TH_FIN)) {
			if (flags & TH_SYN)
				t6p->snd_nxt++;
			if (flags & TH_FIN) {
				t6p->snd_nxt++;
				t6p->t_flags |= TF_SENTFIN;
			}
		}
		t6p->snd_nxt += len;
		if (SEQ_GT(t6p->snd_nxt, t6p->snd_max)) {
			t6p->snd_max = t6p->snd_nxt;
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 */
			if (t6p->t_rtt == 0) {
				t6p->t_rtt = 1;
				t6p->t_rtseq = startseq;
				tcp6stat.tcp6s_segstimed++;
			}
		}

		/*
		 * Set retransmit timer if not currently set,
		 * and not doing an ack or a keep-alive probe.
		 * Initial value for retransmit timer is smoothed
		 * round-trip time + 2 * round-trip time variance.
		 * Initialize shift counter which is used for backoff
		 * of retransmit time.
		 */
		if (t6p->t_timer[TCP6T_REXMT] == 0 &&
		    t6p->snd_nxt != t6p->snd_una) {
			t6p->t_timer[TCP6T_REXMT] = t6p->t_rxtcur;
			if (t6p->t_timer[TCP6T_PERSIST]) {
				t6p->t_timer[TCP6T_PERSIST] = 0;
				t6p->t_rxtshift = 0;
			}
		}
	} else
		if (SEQ_GT(t6p->snd_nxt + len, t6p->snd_max))
			t6p->snd_max = t6p->snd_nxt + len;

	/*
	 * Trace.
	 */
	if (so->so_options & SO_DEBUG)
		tcp6_trace(TA_OUTPUT, t6p->t_state, t6p, ip6, th, 0);

	m->m_pkthdr.len = hdrlen + len;

#if 0				/* ip6_plen will be filled in ip6_output. */
	ip6->ip6_plen = htons((u_short)(m->m_pkthdr.len - sizeof(struct ip6_hdr)));
#endif 
	th->th_sum = in6_cksum(m, IPPROTO_TCP, sizeof(struct ip6_hdr),
			       m->m_pkthdr.len - sizeof(struct ip6_hdr));

#ifdef IPSEC
	m->m_pkthdr.rcvif = (struct ifnet *)so;
#endif /*IPSEC*/

#if BSD >= 43
	error = ip6_output(m, t6p->t_in6pcb->in6p_outputopts,
			   &t6p->t_in6pcb->in6p_route,
			   so->so_options & SO_DONTROUTE, 0, NULL);
#else
	error = ip6_output(m, (struct mbuf *)0, &t6p->t_in6pcb->in6p_route, 
			   so->so_options & SO_DONTROUTE, NULL);
#endif
	if (error) {
out:
		switch (error) {
		case EMSGSIZE:
			/*
			 * The Path MTU must have changed.  Re-get
			 * the mtu information, and resend.
			 * XXX Should we check for a valid route???
			 */
			t6p->snd_nxt -= len;
			win = t6p->t_maxseg;
			len = t6p->t_in6pcb->in6p_route.ro_rt->rt_rmx.rmx_mtu
				- sizeof(struct ip6tcp);
			tcp6_changemss(t6p, len);
			if (t6p->t_maxseg < win)
				goto again;
			/* XXX FALL THROUGH if maxseg didn't get smaller! */

		case ENOBUFS:
			tcp6_quench(t6p->t_in6pcb, 0);
			/*
			 * If we can't send, make sure there is something
			 * to get us going again later.  Persist state
			 * is not necessarily right, but it is close enough.
			 */
			if (t6p->t_timer[TCP6T_REXMT] == 0 &&
			    t6p->t_timer[TCP6T_PERSIST] == 0) {
				t6p->t_rxtshift = 0;
				tcp6_setpersist(t6p);
			}
			error = 0;
			break;

		case EHOSTUNREACH:
		case ENETDOWN:
			if (TCP6S_HAVERCVDSYN(t6p->t_state)) {
				t6p->t_softerror = error;
				error = 0;
			}
			break;

		default:
			break;
		}

		return (error);
	}
	tcp6stat.tcp6s_sndtotal++;

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if (win > 0 && SEQ_GT(t6p->rcv_nxt+win, t6p->rcv_adv))
		t6p->rcv_adv = t6p->rcv_nxt + win;
	t6p->last_ack_sent = t6p->rcv_nxt;
	t6p->t_flags &= ~TF_ACKNOW;
	tcp6_delack_done(t6p);
	if (sendalot)
		goto again;
	return (0);
}

void
tcp6_setpersist(t6p)
	register struct tcp6cb *t6p;
{
	register int t = ((t6p->t_srtt >> 2) + t6p->t_rttvar) >> 1;

	if (t6p->t_timer[TCP6T_REXMT])
		panic("tcp6_output REXMT");
	/*
	 * Start/restart persistance timer.
	 */
	TCP6T_RANGESET(t6p->t_timer[TCP6T_PERSIST],
	    t * tcp6_backoff[t6p->t_rxtshift],
	    TCP6TV_PERSMIN, TCP6TV_PERSMAX);
	if (t6p->t_rxtshift < TCP6_MAXRXTSHIFT)
		t6p->t_rxtshift++;
}
