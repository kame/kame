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
 *	BSDI tcp_var.h,v 2.13 1997/01/16 14:06:37 karels Exp
 */

/*
 * Copyright (c) 1982, 1986, 1993, 1994, 1995
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
 *	@(#)tcp_var.h	8.4 (Berkeley) 5/24/95
 */

#ifndef _NETINET6_TCP6_VAR_H_
#define _NETINET6_TCP6_VAR_H_

/*
 * Kernel variables for tcp6.
 */

struct ip6tcp {
	struct ip6_hdr	i6t_i;
	struct tcp6hdr	i6t_t;
};

struct ip6tcpreass {
	caddr_t	i6tr_next, i6tr_prev;
	struct	tcp6hdr *i6tr_t;
	struct	mbuf *i6tr_m;
	u_char	i6tr_x1;			
	u_char	i6tr_pr;			
	short	i6tr_len;
	u_long	i6tr_x2;
	struct	in6_addr i6tr_dst;
};

/*
 * Tcp6 control block, one per tcp6; fields:
 */
struct tcp6cb {
	struct	ip6tcpreass *seg_next;	/* sequencing queue */
	struct	ip6tcpreass *seg_prev;
	short	t_state;		/* state of this connection */
	short	t_timer[TCP6T_NTIMERS];	/* tcp6 timers */
	short	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	short	t_rxtcur;		/* current retransmit value */
	short	t_dupacks;		/* consecutive dup acks recd */
	u_short	t_maxseg;		/* maximum segment size */
	char	t_force;		/* 1 if forcing out a byte */
	u_short	t_flags;
#define	TF_ACKNOW	0x0001		/* ack peer immediately */
/* #define TF_DELACK	0x0002		 * ack, but try to delay it */
#define	TF_NODELAY	0x0004		/* don't delay packets to coalesce */
#define	TF_NOOPT	0x0008		/* don't use tcp6 options */
#define	TF_SENTFIN	0x0010		/* have sent FIN */
#define	TF_USE_SCALE	0x0020		/* request/use window scaling */
#define	TF_SEND_TSTMP	0x0040		/* request/send timestamps */
#define	TF_SACK_PERMIT	0x0200		/* other side said I could SACK */
#define	TF_STDURG	0x0400		/* URG ptr is last byte of urg data */
#define	TF_WASIDLE	0x0800		/* tcp6_output() was idle on last call */

	struct	ip6tcp *t_template;	/* skeletal packet for transmit */
	struct	in6pcb *t_in6pcb;	/* back pointer to internet pcb */
/*
 * The following fields are used as in the protocol specification.
 * See RFC783, Dec. 1981, page 21.
 */
/* send sequence variables */
	tcp6_seq snd_una;		/* send unacknowledged */
	tcp6_seq snd_nxt;		/* send next */
	tcp6_seq snd_up;		/* send urgent pointer */
	tcp6_seq snd_wl1;		/* window update seg seq number */
	tcp6_seq snd_wl2;		/* window update seg ack number */
	tcp6_seq iss;			/* initial send sequence number */
	u_long	snd_wnd;		/* send window */
/* receive sequence variables */
	u_long	rcv_wnd;		/* receive window */
	tcp6_seq rcv_nxt;		/* receive next */
	tcp6_seq rcv_up;		/* receive urgent pointer */
	tcp6_seq irs;			/* initial receive sequence number */
/*
 * Additional variables for this implementation.
 */
/* receive variables */
	tcp6_seq rcv_adv;		/* advertised window */
/* retransmit variables */
	tcp6_seq snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
/* congestion control (for slow start, source quench, retransmit after loss) */
	u_long	snd_cwnd;		/* congestion-controlled window */
	u_long	snd_ssthresh;		/* snd_cwnd size threshhold for
					 * for slow start exponential to
					 * linear switch
					 */
/*
 * transmit timing stuff.  See below for scale of srtt and rttvar.
 * "Variance" is actually smoothed difference.
 */
	short	t_rtt;			/* round trip time */
	u_short	t_rttmin;		/* minimum rtt allowed */
	tcp6_seq t_rtseq;		/* sequence number being timed */
	short	t_srtt;			/* smoothed round-trip time */
	short	t_rttvar;		/* variance in round-trip time */
	u_long	t_idle;			/* inactivity time */
	u_long	max_sndwnd;		/* largest window peer has offered */

/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
#define	TCP6OOB_HAVEDATA	0x01
#define	TCP6OOB_HADDATA		0x02
	short	t_softerror;		/* possible error not yet reported */

/* RFC 1323 variables */
	u_char	snd_scale;		/* window scaling for send window */
	u_char	rcv_scale;		/* window scaling for recv window */
	u_char	request_r_scale;	/* pending window scaling */
	u_char	requested_s_scale;
	u_long	ts_recent;		/* timestamp echo data */
	u_long	ts_recent_age;		/* when last updated */
	tcp6_seq	last_ack_sent;

/* TUBA stuff */
	caddr_t	t_tuba_pcb;		/* next level down pcb for TCP6 over z */

/* should be moved up */
	LIST_ENTRY(tcp6cb) t_delacks;	/* list of connections needing delack */
	u_short	t_peermaxseg;		/* MSS offered by peer */
};

/* This structure should not exceed 32 bytes. XXX */
struct syn_cache6 {
	struct	syn_cache6 *sc_next;
	u_long	sc_tstmp:1,
		sc_hash:31;
	struct	in6_addr sc_src;
	struct	in6_addr sc_dst;
	tcp6_seq sc_irs;
	tcp6_seq sc_iss;
	u_short	sc_sport;
	u_short	sc_dport;
	u_short	sc_peermaxseg;
	u_char	sc_timer;
	u_char	sc_request_r_scale:4,
		sc_requested_s_scale:4;
};

struct syn_cache_head6 {
	struct	syn_cache6 *sch_first;		/* First entry in the bucket */
	struct	syn_cache6 *sch_last;		/* Last entry in the bucket */
	struct	syn_cache_head6 *sch_headq;	/* The next non-empty bucket */
	short	sch_timer_sum;			/* Total time in this bucket */
	u_short	sch_length;			/* @ # elements in bucket */
};

#define	intotcp6cb(ip6)	((struct tcp6cb *)(ip6)->in6p_ppcb)
#define	sototcp6cb(so)	(intotcp6cb(sotoin6pcb(so)))

/*
 * The following results in generation of delayed acks
 * in the opposite order in which they were requested...
 */
#define	tcp6_delack(t6p) { \
	if ((t6p)->t_delacks.le_prev == 0) \
		LIST_INSERT_HEAD(&tcp6_delacks, (t6p), t_delacks); \
}

#define	tcp6_delack_done(t6p) { \
	if ((t6p)->t_delacks.le_prev) { \
		LIST_REMOVE((t6p), t_delacks); \
		(t6p)->t_delacks.le_prev = 0; \
	} \
}

/*
 * Cancel 2msl timer (to restart, or to delete connection prematurely):
 * if this is the newest 2msl connection, reduce the total time for
 * the queue, otherwise transfer the remaining time to the next newest
 * 2msl connection.
 */
#define	tcp6_cancel2msl(in6p, t6p) { \
	if (in6p->in6p_next == &tcb6) \
		tcp6_msltime -= t6p->t_timer[TCP6T_2MSL]; \
	else \
		intotcp6cb(in6p->in6p_next)->t_timer[TCP6T_2MSL] += \
		    t6p->t_timer[TCP6T_2MSL]; \
}

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP6_RTT_SCALE		8	/* multiplier for srtt; 3 bits frac. */
#define	TCP6_RTT_SHIFT		3	/* shift for srtt; 3 bits frac. */
#define	TCP6_RTTVAR_SCALE	4	/* multiplier for rttvar; 2 bits */
#define	TCP6_RTTVAR_SHIFT	2	/* multiplier for rttvar; 2 bits */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TCP6_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define	TCP6_REXMTVAL(t6p) \
	(((t6p)->t_srtt >> TCP6_RTT_SHIFT) + (t6p)->t_rttvar)

/* XXX
 * We want to avoid doing m_pullup on incoming packets but that
 * means avoiding dtom on the tcp6 reassembly code.  That in turn means
 * keeping an mbuf pointer in the reassembly queue (since we might
 * have a cluster).  As a quick hack, the source & destination
 * port numbers (which are no longer needed once we've located the
 * tcp6cb) are overlayed with an mbuf pointer.
 */
#define REASS_MBUF6(i6tr) (*(struct mbuf **)&((i6tr)->i6tr_m))

/*
 * TCP6 statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	tcp6stat {
	u_quad_t tcp6s_connattempt;	/* connections initiated */
	u_quad_t tcp6s_accepts;		/* connections accepted */
	u_quad_t tcp6s_connects;	/* connections established */
	u_quad_t tcp6s_drops;		/* connections dropped */
	u_quad_t tcp6s_conndrops;	/* embryonic connections dropped */
	u_quad_t tcp6s_closed;		/* conn. closed (includes drops) */
	u_quad_t tcp6s_segstimed;	/* segs where we tried to get rtt */
	u_quad_t tcp6s_rttupdated;	/* times we succeeded */
	u_quad_t tcp6s_delack;		/* delayed acks sent */
	u_quad_t tcp6s_timeoutdrop;	/* conn. dropped in rxmt timeout */
	u_quad_t tcp6s_rexmttimeo;	/* retransmit timeouts */
	u_quad_t tcp6s_persisttimeo;	/* persist timeouts */
	u_quad_t tcp6s_keeptimeo;	/* keepalive timeouts */
	u_quad_t tcp6s_keepprobe;	/* keepalive probes sent */
	u_quad_t tcp6s_keepdrops;	/* connections dropped in keepalive */

	u_quad_t tcp6s_sndtotal;	/* total packets sent */
	u_quad_t tcp6s_sndpack;		/* data packets sent */
	u_quad_t tcp6s_sndbyte;		/* data bytes sent */
	u_quad_t tcp6s_sndrexmitpack;	/* data packets retransmitted */
	u_quad_t tcp6s_sndrexmitbyte;	/* data bytes retransmitted */
	u_quad_t tcp6s_sndrexmitfast;	/* Fast retransmits */
	u_quad_t tcp6s_sndacks;		/* ack-only packets sent */
	u_quad_t tcp6s_sndprobe;	/* window probes sent */
	u_quad_t tcp6s_sndurg;		/* packets sent with URG only */
	u_quad_t tcp6s_sndwinup;	/* window update-only packets sent */
	u_quad_t tcp6s_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	u_quad_t tcp6s_rcvtotal;	/* total packets received */
	u_quad_t tcp6s_rcvpack;		/* packets received in sequence */
	u_quad_t tcp6s_rcvbyte;		/* bytes received in sequence */
	u_quad_t tcp6s_rcvbadsum;	/* packets received with ccksum errs */
	u_quad_t tcp6s_rcvbadoff;	/* packets received with bad offset */
	u_quad_t tcp6s_rcvshort;	/* packets received too short */
	u_quad_t tcp6s_rcvduppack;	/* duplicate-only packets received */
	u_quad_t tcp6s_rcvdupbyte;	/* duplicate-only bytes received */
	u_quad_t tcp6s_rcvpartduppack;	/* packets with some duplicate data */
	u_quad_t tcp6s_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	u_quad_t tcp6s_rcvoopack;	/* out-of-order packets received */
	u_quad_t tcp6s_rcvoobyte;	/* out-of-order bytes received */
	u_quad_t tcp6s_rcvpackafterwin;	/* packets with data after window */
	u_quad_t tcp6s_rcvbyteafterwin;	/* bytes rcvd after window */
	u_quad_t tcp6s_rcvafterclose;	/* packets rcvd after "close" */
	u_quad_t tcp6s_rcvwinprobe;	/* rcvd window probe packets */
	u_quad_t tcp6s_rcvdupack;	/* rcvd duplicate acks */
	u_quad_t tcp6s_rcvacktoomuch;	/* rcvd acks for unsent data */
	u_quad_t tcp6s_rcvackpack;	/* rcvd ack packets */
	u_quad_t tcp6s_rcvackbyte;	/* bytes acked by rcvd acks */
	u_quad_t tcp6s_rcvwinupd;	/* rcvd window update packets */
	u_quad_t tcp6s_pawsdrop;	/* segments dropped due to PAWS */
	u_quad_t tcp6s_predack;		/* times hdr predict ok for acks */
	u_quad_t tcp6s_preddat;		/* times hdr predict ok for data pkts */
	u_quad_t tcp6s_pcbcachemiss;
	u_quad_t tcp6s_persistdrop;	/* timeout in persist state */
	u_quad_t tcp6s_badsyn;		/* bogus SYN, e.g. premature ACK */
	u_quad_t tcp6s_droppedsyn;	/* dropped SYN's because sonewconn() failed */

	/* These statistics deal with the SYN cache. */
	u_quad_t tcp6s_sc_added;	/* # of entries added */
	u_quad_t tcp6s_sc_completed;	/* # of connections completed */
	u_quad_t tcp6s_sc_timed_out;	/* # of entries timed out */
	u_quad_t tcp6s_sc_overflowed;	/* # dropped due to overflow */
	u_quad_t tcp6s_sc_reset;	/* # dropped due to RST */
	u_quad_t tcp6s_sc_unreach;	/* # dropped due to ICMP unreach */
	u_quad_t tcp6s_sc_bucketoverflow;/* # dropped due to bucket overflow */
	u_quad_t tcp6s_sc_aborted;	/* # of entries aborted (no mem) */
	u_quad_t tcp6s_sc_dupesyn;	/* # of duplicate SYNs received */
	u_quad_t tcp6s_sc_dropped;	/* # of SYNs dropped (no route/mem) */
};

#ifdef _KERNEL
extern struct	in6pcb tcb6;	/* head of queue of active tcp6cb's */
extern struct	tcp6stat tcp6stat; /* tcp6 statistics */
extern u_long	tcp6_now;	/* for RFC 1323 timestamps */
extern int	tcp6_msltime;	/* total of 2MSL timers already in queue */
extern int	tcp6_roundsize;
extern int	tcp6_roundfrac;

extern int	tcp6_listen_hash_size;
extern int	tcp6_conn_hash_size;
extern LIST_HEAD(tcp6_hash_list, in6pcb) tcp6_listen_hash[], tcp6_conn_hash[];
extern LIST_HEAD(tcp6_delacks, tcp6cb) tcp6_delacks;

extern int	tcp6_syn_cache_size;
extern int	tcp6_syn_cache_timeo;
extern struct	syn_cache_head6 tcp6_syn_cache[], *tcp6_syn_cache_first;
extern u_long	syn_cache_count6;

struct	tcp6_opt_info;

int	 tcp6_attach __P((struct socket *));
void	 tcp6_canceltimers __P((struct tcp6cb *));
struct tcp6cb *
	 tcp6_close __P((struct tcp6cb *));
void	 tcp6_ctlinput __P((int, struct sockaddr *, void *));
int	 tcp6_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
struct tcp6cb *
	 tcp6_disconnect __P((struct tcp6cb *));
struct tcp6cb *
	 tcp6_drop __P((struct tcp6cb *, int));
void	 tcp6_dooptions __P((struct tcp6cb *,
	    u_char *, int, struct tcp6hdr *, struct tcp6_opt_info *));
void	 tcp6_drain __P((void));
void	 tcp6_fasttimo __P((void));
void	 tcp6_init __P((void));
int	 tcp6_input __P((struct mbuf **, int *, int));
struct rtentry *
	 tcp6_rtlookup __P((register struct in6pcb *));
u_int	 tcp6_maxseg __P((struct tcp6cb *, u_int));
void	 tcp6_maxseg_init __P((struct tcp6cb *));
void	 tcp6_peer_mss __P((struct tcp6cb *, u_int));
u_long	 tcp6_send_mss __P((struct tcp6cb *));
void	 tcp6_changemss __P((register struct tcp6cb *, u_int));
void	 tcp6_agepathmtu __P((struct in6pcb *, struct rtentry *));
struct tcp6cb *
	 tcp6_newtcp6cb __P((struct in6pcb *));
void	 tcp6_notify __P((struct in6pcb *, int));
int	 tcp6_output __P((struct tcp6cb *));
void	 tcp6_pulloutofband __P((struct socket *,
				 struct tcp6hdr *, struct mbuf *, int));
void	 tcp6_quench __P((struct in6pcb *, int));
void	 tcp6_mtudisc __P((struct in6pcb *, int));
int	 tcp6_reass __P((struct tcp6cb *, struct ip6tcpreass *,
			 struct tcp6hdr *, struct mbuf *, int));
int	 tcp6_respond __P((struct tcp6cb *, struct ip6_hdr *, struct tcp6hdr *,
			   struct mbuf *, u_long, u_long, int));
void	 tcp6_setpersist __P((struct tcp6cb *));
void	 tcp6_slowtimo __P((void));
int	 tcp6_sysctl __P((int *, u_int, void *, size_t *, void *, size_t));
struct ip6tcp *
	 tcp6_template __P((struct tcp6cb *));
struct tcp6cb *
	 tcp6_timers __P((struct tcp6cb *, int));
void	 tcp6_trace __P((int, int, struct tcp6cb *, struct ip6_hdr *,
			 struct tcp6hdr *, int));
struct tcp6cb *
	 tcp6_usrclosed __P((struct tcp6cb *));
#ifndef __NetBSD__
int	 tcp6_usrreq __P((struct socket *,
	    int, struct mbuf *, struct mbuf *, struct mbuf *));
#else
int	 tcp6_usrreq __P((struct socket *,
	    int, struct mbuf *, struct mbuf *, struct mbuf *, struct proc *));
#endif
void	 tcp6_xmit_timer __P((struct tcp6cb *, int));

int	 syn_cache_add6 __P((struct socket *, struct mbuf *, int, u_char *,
	    int, struct tcp6_opt_info *));
void	 syn_cache_unreach6 __P((struct ip6_hdr *, struct tcp6hdr *));
struct socket *
	 syn_cache_get6 __P((struct socket *so, struct mbuf *, int, int));
void	 syn_cache_insert6 __P((struct syn_cache6 *, struct syn_cache6 ***,
	    struct syn_cache_head6 **));
struct syn_cache6 *
	 syn_cache_lookup6 __P((struct ip6_hdr *, struct tcp6hdr *,
			       struct syn_cache6 ***,
			       struct syn_cache_head6 **));
void	 syn_cache_reset6 __P((struct ip6_hdr *, struct tcp6hdr *));
int	 syn_cache_respond6 __P((struct syn_cache6 *, struct mbuf *,
				 struct ip6_hdr *, struct tcp6hdr *,
				 long, u_long));
void	 syn_cache_timer6 __P((int));

#endif

#endif /* !_NETINET6_TCP6_VAR_H_ */
