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
 *	BSDI tcp_input.c,v 2.20 1997/01/16 14:06:33 karels Exp
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994
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
 *	@(#)tcp_input.c	8.5 (Berkeley) 4/10/94
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#ifdef __NetBSD__	/*XXX*/
#include "opt_ipsec.h"
#endif
#endif

#ifndef TUBA_INCLUDE
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#ifdef __FreeBSD__
#include <sys/syslog.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet6/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#include <netinet6/tcp6_debug.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/nd6.h>
#include <netinet6/icmp6.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /*IPSEC*/

#include "faith.h"

struct tcp6stat	tcp6stat;

u_long	tcp6_now;
struct in6pcb tcb6;

int	tcp6rexmtthresh = 3;
struct	ip6_hdr ip6_save;
struct	tcp6hdr tcp6_save;
struct	in6pcb *tcp6_last_in6pcb = &tcb6;

int tcp6_msltime;
struct tcp6_delacks tcp6_delacks;

#ifdef __FreeBSD__
extern int tcp_log_in_vain;
#endif

#endif /* TUBA_INCLUDE */
#define TCP6_PAWS_IDLE	(24 * 24 * 60 * 60 * PR_SLOWHZ)

/* for modulo comparisons of timestamps */
#define TSTMP_LT(a,b)	((int)((a)-(b)) < 0)
#define TSTMP_GEQ(a,b)	((int)((a)-(b)) >= 0)

static struct in6pcb *tcp6_listen_lookup __P((struct in6_addr, u_short,
		struct ifnet *));
static struct in6pcb *tcp6_conn_lookup __P((struct in6_addr, u_short,
		struct in6_addr, u_short));
static void tcp6_start2msl __P((struct in6pcb *, struct tcp6cb *));
static void tcp6_rtt_init __P((struct tcp6cb *, struct rtentry *));
static int  tcp6_mss_round __P((int));

/*
 * Neighbor Discovery, Neighbor Unreachability Detection
 * Upper layer hint.
 */
#define ND6_HINT(t6p) \
do { \
	if (t6p && t6p->t_in6pcb && t6p->t_in6pcb->in6p_route.ro_rt) \
		nd6_nud_hint(t6p->t_in6pcb->in6p_route.ro_rt, NULL); \
} while (0)

/*
 * TCP6 SYN caching information
 */

u_long	syn_cache_count6;
u_long	syn_hash61, syn_hash62;

#define SYN_HASH6(sa, sp, dp) \
	((((sa)->s6_addr32[0]^(sa)->s6_addr32[1]^(sa)->s6_addr32[2]^\
	   (sa)->s6_addr32[3]^syn_hash61) \
	  *((((dp)<<16)+(sp))^syn_hash62)) & 0x7fffffff) 

#define	eptosp(ep, e, s)	((struct s *)((char *)(ep) - \
			    ((char *)(&((struct s *)0)->e) - (char *)0)))
#define	SYN_CACHE_RM6(sc, p, scp) \
do {									\
	*(p) = (sc)->sc_next;						\
	if ((sc)->sc_next)						\
		(sc)->sc_next->sc_timer += (sc)->sc_timer;		\
	else {								\
		(scp)->sch_timer_sum -= (sc)->sc_timer;			\
		if ((scp)->sch_timer_sum <= 0)				\
			(scp)->sch_timer_sum = -1;			\
		/* If need be, fix up the last pointer */		\
		if ((scp)->sch_first)					\
			(scp)->sch_last = eptosp(p, sc_next, syn_cache6); \
	}								\
	(scp)->sch_length--;						\
	syn_cache_count6--;						\
} while (0)

#if defined(__FreeBSD__) || defined(__bsdi__)
#define sb_notify(x)	((x)->sb_flags & SB_NOTIFY)
#endif

/*
 * Look for in6pcb for listening TCP6 socket
 * for incoming connection request for dst/dport
 * using hash on destination (local) port.
 */
static struct in6pcb *
tcp6_listen_lookup(dst, dport, ifp)
	struct in6_addr dst;
	u_short dport;
	struct ifnet *ifp;
{
	struct in6pcb *in6p, *maybe = NULL;

	for (in6p = tcp6_listen_hash[dport % tcp6_listen_hash_size].lh_first; in6p;
	     in6p = in6p->in6p_hlist.le_next) {
#if defined(NFAITH) && NFAITH > 0
		if (ifp && ifp->if_type == IFT_FAITH
		 && !(in6p->in6p_flags & IN6P_FAITH)) {
			continue;
		}
#endif
		if (in6p->in6p_lport != dport)
			continue;
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr)) {
			if (maybe == NULL)
				maybe = in6p;
		} else if (IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &dst))
			return (in6p);
	}
	return (maybe);
}

/*
 * Look for in6pcb for associated (connected) TCP6 socket
 * for incoming packet with specified src/dst addr and port,
 * using hash on both addresses and ports.
 */
static struct in6pcb *
tcp6_conn_lookup(src, sport, dst, dport)
	struct in6_addr src;
	u_short sport;
	struct in6_addr dst;
	u_short dport;
{
	struct in6pcb *in6p;
	u_long hash;
	hash = IN6_HASH(&src, sport, &dst, dport);
	for (in6p = tcp6_conn_hash[hash % tcp6_conn_hash_size].lh_first; in6p;
	    in6p = in6p->in6p_hlist.le_next) {
		if (in6p->in6p_hash != hash)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &src) &&
		    in6p->in6p_fport == sport &&
		    in6p->in6p_lport == dport &&
		    IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &dst))
			return (in6p);
	}
	return (NULL);
}

static void
tcp6_start2msl(in6p, t6p)
	struct in6pcb *in6p;
	struct tcp6cb *t6p;
{

	/*
	 * The newest connection already on the 2MSL part of the queue
	 * will time out in tcp6_msltime ticks.  Set the additional time
	 * for this connection (if any).  The time for the newest
	 * connection will then be 2 * TCP6TV_MSL.
	 */
	t6p->t_timer[TCP6T_2MSL] = 2 * TCP6TV_MSL - tcp6_msltime;
	tcp6_msltime = 2 * TCP6TV_MSL;

	remque(in6p);
	/*
	 * XXX insque, but place at tail.
	 * Should replace insque/remque with circleq.
	 */
	in6p->in6p_prev = tcb6.in6p_prev;
	tcb6.in6p_prev = in6p;
	in6p->in6p_next = &tcb6;
	in6p->in6p_prev->in6p_next = in6p;
}

/*
 * Insert segment t6i into reassembly queue of tcp6 with
 * control block t6p.  Return TH_FIN if reassembly now includes
 * a segment with FIN.  The macro form does the common case inline
 * (segment is the next to be received on an established connection,
 * and the queue is empty), avoiding linkage into and removal
 * from the queue and repetition of various conversions.
 * Request delayed ack for segments received in order, but ack immediately
 * when segments are out of order (so fast retransmit can work).
 */
#define	TCP6_REASS(t6p, i6tr, th, m, so, flags, len) { \
	if ((th)->th_seq == (t6p)->rcv_nxt && \
	    (t6p)->seg_next == (struct ip6tcpreass *)(t6p) && \
	    (t6p)->t_state == TCP6S_ESTABLISHED) { \
		tcp6_delack(t6p); \
		(t6p)->rcv_nxt += (len); \
		flags = (th)->th_flags & TH_FIN; \
		tcp6stat.tcp6s_rcvpack++;\
		tcp6stat.tcp6s_rcvbyte += (len);\
		ND6_HINT(t6p);\
		sbappend(&(so)->so_rcv, (m)); \
		sorwakeup(so); \
	} else { \
		(flags) = tcp6_reass((t6p), (i6tr), (th), (m), (len)); \
		t6p->t_flags |= TF_ACKNOW; \
	} \
}
#ifndef TUBA_INCLUDE

int
tcp6_reass(t6p, i6tr, th, m, len)
	struct tcp6cb *t6p;
	struct ip6tcpreass *i6tr;
	struct tcp6hdr *th;
	struct mbuf *m;
	int len;
{
	struct ip6tcpreass *q;
	struct socket *so = t6p->t_in6pcb->in6p_socket;
	int flags;

	/*
	 * Call with i6tr==0 after become established to
	 * force pre-ESTABLISHED data up to user socket.
	 */
	if (i6tr == 0)
		goto present;

	if (i6tr) {
		i6tr->i6tr_t = th; 
		i6tr->i6tr_len = (u_short)len;
	}
	/*
	 * Find a segment which begins after this one does.
	 */
	for (q = t6p->seg_next; q != (struct ip6tcpreass *)t6p;
	     q = (struct ip6tcpreass *)q->i6tr_next)
		if (SEQ_GT(q->i6tr_t->th_seq, th->th_seq))
			break;

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 */
	if ((struct ip6tcpreass *)q->i6tr_prev != (struct ip6tcpreass *)t6p) {
		register int i;
		q = (struct ip6tcpreass *)q->i6tr_prev;
		/* conversion to int (in i) handles seq wraparound */
		i = q->i6tr_t->th_seq + q->i6tr_len - th->th_seq;
		if (i > 0) {
			if (i >= i6tr->i6tr_len) {
				tcp6stat.tcp6s_rcvduppack++;
				tcp6stat.tcp6s_rcvdupbyte += i6tr->i6tr_len;
				m_freem(m);
				return (0);
			}
			m_adj(m, i);
			i6tr->i6tr_len -= i;
			i6tr->i6tr_t->th_seq += i;
		}
		q = (struct ip6tcpreass *)(q->i6tr_next);
	}
	tcp6stat.tcp6s_rcvoopack++;
	tcp6stat.tcp6s_rcvoobyte += i6tr->i6tr_len;
	REASS_MBUF6(i6tr) = m;		/* XXX */

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (q != (struct ip6tcpreass *)t6p) {
		register int i = (i6tr->i6tr_t->th_seq + i6tr->i6tr_len)
			- q->i6tr_t->th_seq;
		if (i <= 0)
			break;
		if (i < q->i6tr_len) {
			q->i6tr_t->th_seq += i;
			q->i6tr_len -= i;
			m_adj(REASS_MBUF6(q), i);
			break;
		}
		q = (struct ip6tcpreass *)q->i6tr_next;
		m = REASS_MBUF6((struct ip6tcpreass *)q->i6tr_prev);
		remque(q->i6tr_prev);
		m_freem(m);
	}

	/*
	 * Stick new segment in its place.
	 */
	insque(i6tr, q->i6tr_prev);

present:
	/*
	 * Present data to user, advancing rcv_nxt through
	 * completed sequence space.
	 */
	if (TCP6S_HAVERCVDSYN(t6p->t_state) == 0)
		return (0);
	i6tr = t6p->seg_next;
	if (i6tr == (struct ip6tcpreass *)t6p ||
	    i6tr->i6tr_t->th_seq != t6p->rcv_nxt)
		return (0);
	if (t6p->t_state == TCP6S_SYN_RECEIVED && i6tr->i6tr_len)
		return (0);
	do {
		t6p->rcv_nxt += i6tr->i6tr_len;
		flags = i6tr->i6tr_t->th_flags & TH_FIN;
		remque(i6tr);
		m = REASS_MBUF6(i6tr);
		i6tr = (struct ip6tcpreass *)i6tr->i6tr_next;
		ND6_HINT(t6p);
		if (so->so_state & SS_CANTRCVMORE)
			m_freem(m);
		else
			sbappend(&so->so_rcv, m);
	} while (i6tr != (struct ip6tcpreass *)t6p &&
		 i6tr->i6tr_t->th_seq == t6p->rcv_nxt);
	sorwakeup(so);
	return (flags);
}

struct tcp6_opt_info {
	int	ts_present;
	u_long	ts_val;
	u_long	ts_ecr;
	u_long	maxseg;
};


/*
 * TCP6 input routine, follows pages 65-76 of the
 * protocol specification dated September, 1981 very closely.
 */
int
tcp6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
	struct in6pcb *in6p;
	u_char *optp = NULL;
	int off = *offp;
	int optlen = 0;
	int tlen, toff, len;
	struct tcp6cb *t6p = 0;
	int thflags;
	struct socket *so = (struct socket *)NULL;
	int todrop, acked, ourfinisacked, needoutput = 0;
	int hdroptlen = 0;
	short ostate = 0; /*just to avoid warning*/
#if 0
	struct in6_addr laddr;
#endif
	int dropsocket = 0;
	int iss = 0;
	u_long thwin;
	struct tcp6_opt_info opti;

	tcp6stat.tcp6s_rcvtotal++;

#if 1
	/* XXX not a good place to put this into... */
	if (m && (m->m_flags & M_ANYCAST6)) {
		icmp6_error(m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR,
			(caddr_t)&ip6->ip6_dst - (caddr_t)ip6);
		return IPPROTO_DONE;
	}
#endif

	opti.ts_present = 0;
	opti.maxseg = 0;

	IP6_EXTHDR_CHECK(m, off, sizeof(struct tcp6hdr), IPPROTO_DONE);
	ip6 = mtod(m, struct ip6_hdr *);

	/* Be proactive about malicious use of IPv4 mapped address */
	if (IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst)) {
		/* XXX stat */
		goto drop;
	}

	/*
	 * Checksum extended TCP6 header and data.
	 */
	tlen = ntohs(ip6->ip6_plen) - off + sizeof(*ip6);
	if (in6_cksum(m, IPPROTO_TCP, off, tlen)) {
		tcp6stat.tcp6s_rcvbadsum++;
		goto drop;
	}
#endif /* TUBA_INCLUDE */

	/*
	 * Check that TCP6 offset makes sense,
	 * pull out TCP6 options and adjust length.
	 */
	th = (struct tcp6hdr *)((caddr_t)ip6 + off);
	toff = th->th_off << 2;
	if (toff < sizeof (struct tcp6hdr) || toff > tlen) {
		tcp6stat.tcp6s_rcvbadoff++;
		goto drop;
	}
	len = tlen - toff;

	if (toff > sizeof (struct tcp6hdr)) {
		IP6_EXTHDR_CHECK(m, off, toff, IPPROTO_DONE);

		optlen = toff - sizeof (struct tcp6hdr);
		optp = (u_char *)(th + 1);
		/* 
		 * Do quick retrieval of timestamp options ("options
		 * prediction?").  If timestamp is the only option and it's
		 * formatted as recommended in RFC 1323 appendix A, we
		 * quickly get the values now and not bother calling
		 * tcp6_dooptions(), etc.
		 */
		if ((optlen == TCP6OLEN_TSTAMP_APPA ||
		     (optlen > TCP6OLEN_TSTAMP_APPA &&
			optp[TCP6OLEN_TSTAMP_APPA] == TCP6OPT_EOL)) &&
		     *(u_long *)optp == htonl(TCP6OPT_TSTAMP_HDR) &&
		    (th->th_flags & TH_SYN) == 0) {
			opti.ts_present = 1;
			opti.ts_val = ntohl(*(u_long *)(optp + 4));
			opti.ts_ecr = ntohl(*(u_long *)(optp + 8));
			optp = NULL;	/* we've parsed the options */
		}
	}
	thflags = th->th_flags;

	/*
	 * Locate pcb for segment.
	 */
findpcb:
	in6p = tcp6_last_in6pcb;
	if (in6p->in6p_lport != th->th_dport ||
	    in6p->in6p_fport != th->th_sport ||
	    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src) ||
	    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst)) {
		if ((in6p = tcp6_conn_lookup(ip6->ip6_src, th->th_sport,
					     ip6->ip6_dst, th->th_dport))
		    == NULL &&
		    ((thflags & (TH_SYN|TH_ACK)) == TH_SYN || syn_cache_count6)) {
			in6p = tcp6_listen_lookup(ip6->ip6_dst, th->th_dport,
				m->m_pkthdr.rcvif);
		}
		if (in6p)
			tcp6_last_in6pcb = in6p;
		++tcp6stat.tcp6s_pcbcachemiss;
	}

#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (in6p != NULL && ipsec6_in_reject(m, in6p)) {
		ipsec6stat.in_polvio++;
		goto drop;
	}
#endif /*IPSEC*/

	/*
	 * Compute mbuf offset to TCP data segment.
	 */
	hdroptlen = off + toff;

/* found: */
	/* We can modify IP6 header */
	
	NTOHL(th->th_seq);
	NTOHL(th->th_ack);
	NTOHS(th->th_win);
	NTOHS(th->th_urp);
/*	t6i->t6i_len = len;  */ /* xxx reass*/
	
	/*
	 * If the state is CLOSED (i.e., TCB6 does not exist) then
	 * all data in the incoming segment is discarded.
	 * If the TCB6 exists but is in CLOSED state, it is embryonic,
	 * but should either do a listen or a connect soon.
	 */
	if (in6p == 0) {
#ifdef __FreeBSD__
		if (tcp_log_in_vain && thflags & TH_SYN) {
			char buf[INET6_ADDRSTRLEN];

			strcpy(buf, ip6_sprintf(&ip6->ip6_dst));
			log(LOG_INFO,
			    "Connection attempt to TCP %s:%d from %s:%d\n",
			    buf, ntohs(th->th_dport),
			    ip6_sprintf(&ip6->ip6_src), ntohs(th->th_sport));
		}
#endif
		goto dropwithreset;
	}
	t6p = intotcp6cb(in6p);
	if (t6p == 0)
		goto dropwithreset;
	if (t6p->t_state == TCP6S_CLOSED)
		goto drop;
	
	/* Unscale the window into a 32-bit value. */
	if ((thflags & TH_SYN) == 0)
		thwin = th->th_win << t6p->snd_scale;
	else
		thwin = th->th_win;

	/* save packet options if user wanted */
	if (in6p->in6p_flags & IN6P_CONTROLOPTS) {
		if (in6p->in6p_options) {
			m_freem(in6p->in6p_options);
			in6p->in6p_options = 0;
		}
		ip6_savecontrol(in6p, &in6p->in6p_options, ip6, m);
	}

	so = in6p->in6p_socket;
	if (so->so_options & (SO_DEBUG|SO_ACCEPTCONN)) {
		if (so->so_options & SO_DEBUG) {
			ostate = t6p->t_state;
			ip6_save = *ip6;
			tcp6_save = *th;
		}
		if (so->so_options & SO_ACCEPTCONN) {
			struct in6pcb *oin6p = sotoin6pcb(so);
			struct socket *oso;
			/*
			 * XXX need to defer this check for IPsec
			 * see netinet/tcp_input.c
			 */
			if ((thflags & (TH_RST|TH_ACK|TH_SYN)) != TH_SYN) {
				if (thflags & TH_RST)
					syn_cache_reset6(ip6, th);
				else if (thflags & TH_ACK) {
					so = syn_cache_get6(so, m, off, len);
					if (so == NULL) {
						tcp6stat.tcp6s_badsyn++;
						t6p = NULL;
						goto dropwithreset;
					} else if (so == (struct socket *)(-1))
						m = NULL;
					else {
						in6p = sotoin6pcb(so);
						t6p = intotcp6cb(in6p);
						thwin <<= t6p->snd_scale;
						goto after_listen;
					}
				}
				goto drop;
			}
			oso = so;
			so = sonewconn(so, 0);
			/*
			 * Don't add to the SYN cache if established
			 * connections aren't being accept()ed.
			 */
			if (so == 0) {
				if (oso->so_qlen < oso->so_qlimit &&
				    syn_cache_add6(oso, m, off,
					    optp, optlen, &opti)) {
					m = NULL;
				} else
					tcp6stat.tcp6s_droppedsyn++;
				goto drop;
			}
			/*
			 * This is ugly, but ....
			 *
			 * Mark socket as temporary until we're
			 * committed to keeping it.  The code at
			 * ``drop'' and ``dropwithreset'' check the
			 * flag dropsocket to see if the temporary
			 * socket created here should be discarded.
			 * We mark the socket as discardable until
			 * we're committed to it below in TCP6S_LISTEN.
			 */
			dropsocket++;
			in6p = sotoin6pcb(so);
			in6p->in6p_laddr = ip6->ip6_dst;
			in6p->in6p_lport = th->th_dport;
			/* inherit socket options from the listening socket */
			in6p->in6p_flags |=
				(oin6p->in6p_flags & IN6P_CONTROLOPTS);
			if (in6p->in6p_flags & IN6P_CONTROLOPTS) {
				if (in6p->in6p_options) {
					m_freem(in6p->in6p_options);
					in6p->in6p_options = 0;
				}
				ip6_savecontrol(in6p, &in6p->in6p_options,
						ip6, m);
			}
#ifdef IPSEC
			/* copy old policy into new socket's */
			if (ipsec_copy_policy(sotoin6pcb(oso)->in6p_sp,
			                      in6p->in6p_sp))
				printf("tcp6_input: could not copy policy\n");
#endif

			t6p = intotcp6cb(in6p);
			t6p->t_state = TCP6S_LISTEN;

			/* Compute proper scaling value from buffer space
			 */
			while (t6p->request_r_scale < TCP6_MAX_WINSHIFT &&
			   TCP6_MAXWIN << t6p->request_r_scale < so->so_rcv.sb_hiwat)
				t6p->request_r_scale++;
		}
	}

after_listen:
	/*
	 * Segment received on connection.
	 * Reset idle time and keep-alive timer.
	 */
	t6p->t_idle = 0;
	if (t6p->t_state >= TCP6S_ESTABLISHED)
		t6p->t_timer[TCP6T_KEEP] = tcp6_keepidle;

	/*
	 * Process options if not in LISTEN state,
	 * else do it below (after getting remote address).
	 */
	if (optp && t6p->t_state != TCP6S_LISTEN)
		tcp6_dooptions(t6p, optp, optlen, th, &opti);

	/* 
	 * Header prediction: check for the two common cases
	 * of a uni-directional data xfer.  If the packet has
	 * no control flags, is in-sequence, the window didn't
	 * change and we're not retransmitting, it's a
	 * candidate.  If the length is zero and the ack moved
	 * forward, we're the sender side of the xfer.  Just
	 * free the data acked & wake any higher level process
	 * that was blocked waiting for space.  If the length
	 * is non-zero and the ack didn't move, we're the
	 * receiver side.  If we're getting packets in-order
	 * (the reassembly queue is empty), add the data to
	 * the socket buffer and note that we need a delayed ack.
	 */
	if (t6p->t_state == TCP6S_ESTABLISHED &&
	    (thflags & (TH_SYN|TH_FIN|TH_RST|TH_URG|TH_ACK)) == TH_ACK &&
	    (!opti.ts_present || TSTMP_GEQ(opti.ts_val, t6p->ts_recent)) &&
	    th->th_seq == t6p->rcv_nxt &&
	    thwin && thwin == t6p->snd_wnd &&
	    t6p->snd_nxt == t6p->snd_max) {

		/* 
		 * If last ACK falls within this segment's sequence numbers,
		 *  record the timestamp.
		 */
		if (opti.ts_present && SEQ_LEQ(th->th_seq, t6p->last_ack_sent) &&
		    SEQ_LT(t6p->last_ack_sent, th->th_seq + len)) {
			t6p->ts_recent_age = tcp6_now;
			t6p->ts_recent = opti.ts_val;
		}

		if (len == 0) { /* xxx */
			if (SEQ_GT(th->th_ack, t6p->snd_una) &&
			    SEQ_LEQ(th->th_ack, t6p->snd_max) &&
			    t6p->snd_cwnd >= t6p->snd_wnd &&
			    t6p->t_dupacks == 0) {
				/*
				 * this is a pure ack for outstanding data.
				 */
				++tcp6stat.tcp6s_predack;
				if (opti.ts_present)
					tcp6_xmit_timer(t6p,
					    tcp6_now - opti.ts_ecr + 1);
				else if (t6p->t_rtt &&
					 SEQ_GT(th->th_ack, t6p->t_rtseq))
					tcp6_xmit_timer(t6p, t6p->t_rtt);
				acked = th->th_ack - t6p->snd_una;
				tcp6stat.tcp6s_rcvackpack++;
				tcp6stat.tcp6s_rcvackbyte += acked;
				ND6_HINT(t6p);
				sbdrop(&so->so_snd, acked);
				t6p->snd_una = th->th_ack;
				m_freem(m);

				/*
				 * If all outstanding data are acked, stop
				 * retransmit timer, otherwise restart timer
				 * using current (possibly backed-toff) value.
				 * If process is waiting for space,
				 * wakeup/selwakeup/signal.  If data
				 * are ready to send, let tcp6_output
				 * decide between more output or persist.
				 */
				if (t6p->snd_una == t6p->snd_max)
					t6p->t_timer[TCP6T_REXMT] = 0;
				else if (t6p->t_timer[TCP6T_PERSIST] == 0)
					t6p->t_timer[TCP6T_REXMT] = t6p->t_rxtcur;

				if (sb_notify(&so->so_snd))
					sowwakeup(so);
				if (so->so_snd.sb_cc)
					(void) tcp6_output(t6p);
				return IPPROTO_DONE;
			}
		} else if (th->th_ack == t6p->snd_una &&
			   t6p->seg_next == (struct ip6tcpreass *)t6p &&
			   len <= sbspace(&so->so_rcv)) {
			/*
			 * this is a pure, in-sequence data packet
			 * with nothing on the reassembly queue and
			 * we have enough buffer space to take it.
			 */
			++tcp6stat.tcp6s_preddat;
			t6p->rcv_nxt += len;
			tcp6stat.tcp6s_rcvpack++;
			tcp6stat.tcp6s_rcvbyte += len;
			/*
			 * Drop TCP6, IP6 headers and TCP6 options then add
			 * data to socket buffer.
			 */
			ND6_HINT(t6p);
			m_adj(m, hdroptlen);
			sbappend(&so->so_rcv, m);
			sorwakeup(so);
			tcp6_delack(t6p);
			return IPPROTO_DONE;
		}
	}

	/*
	 * Calculate amount of space in receive window,
	 * and then do TCP6 input processing.
	 * Receive window is amount of space in rcv queue,
	 * but not less than advertised window.
	 */
	{ int win;

	win = sbspace(&so->so_rcv);
	if (win < 0)
		win = 0;
	t6p->rcv_wnd = max(win, (int)(t6p->rcv_adv - t6p->rcv_nxt));
	}

	switch (t6p->t_state) {

	/*
	 * If the state is LISTEN then ignore segment if it contains an RST.
	 * If the segment contains an ACK then it is bad and send a RST.
	 * If it does not contain a SYN then it is not interesting; drop it.
	 * Don't bother responding if the destination was a broadcast.
	 * Otherwise initialize t6p->rcv_nxt, and t6p->irs, select an initial
	 * t6p->iss, and send a segment:
	 *     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
	 * Also initialize t6p->snd_nxt to t6p->iss+1 and t6p->snd_una to
	 * t6p->iss.
	 * Fill in remote peer address fields if not previously specified.
	 * Enter SYN_RECEIVED state, and process any other fields of this
	 * segment in this state.
	 */
	case TCP6S_LISTEN: {
#ifdef already_done
		if (thflags & TH_RST)
			goto drop;
		if (thflags & TH_ACK)
			goto dropwithreset;
		if ((thflags & TH_SYN) == 0)
			goto drop;
#endif
		/*
		 * RFC1122 4.2.3.10, p. 104: discard bcast/mcast SYN
		 * in6_broadcast() should never return true on a received
		 * packet with M_BCAST not set.
		 */
		if (m->m_flags & (M_BCAST|M_MCAST|M_ANYCAST6) ||
		    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
			goto drop;
#if 1
		/*
		 * Perhaps this should be a call/macro
		 * to a function like in6_pcbconnect(), but almost
		 * all of the checks have been done: we know
		 * that the association is unique, and the
		 * local address is always set here.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr))
			in6p->in6p_laddr = ip6->ip6_dst;
		in6p->in6p_faddr = ip6->ip6_src;
		in6p->in6p_fport = th->th_sport;
#else
		struct sockaddr_in6 sin6;

		/*
		 * We assume that in6_pcbconnectok uses only sin6_addr
		 * and sin6_port; family and length are uninitialized.
		 */
		sin6.sin6_addr = ip6->ip6_src;
		sin6.sin6_port = th->th_sport;
		laddr = in6p->in6p_laddr;
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr))
			in6p->in6p_laddr = ip6->ip6_dst;
		if (in6_pcbconnectok(in6p, &sin6)) {
			in6p->in6p_laddr = laddr;
			goto drop;
		}
#endif
		in6p->in6p_hash = IN6_HASH(&ip6->ip6_src, th->th_sport,
					   &ip6->ip6_dst, th->th_dport);
		LIST_INSERT_HEAD(&tcp6_conn_hash[in6p->in6p_hash %
		    tcp6_conn_hash_size], in6p, in6p_hlist);
		t6p->t_template = tcp6_template(t6p);
		if (t6p->t_template == 0) {
			t6p = tcp6_drop(t6p, ENOBUFS);
			dropsocket = 0;		/* socket is already gone */
			goto drop;
		}
		if (optp)
			tcp6_dooptions(t6p, optp, optlen, th, &opti);
		else
			t6p->t_flags &= ~(TF_SEND_TSTMP | TF_USE_SCALE);
		if (iss)
			t6p->iss = iss;
		else
			t6p->iss = tcp6_iss;
		tcp6_iss += TCP6_ISSINCR/4;
		t6p->irs = th->th_seq;
		tcp6_sendseqinit(t6p);
		tcp6_rcvseqinit(t6p);
		t6p->t_flags |= TF_ACKNOW;
		t6p->t_state = TCP6S_SYN_RECEIVED;
		t6p->t_timer[TCP6T_KEEP] = tcp6_conntimeo;
		dropsocket = 0;		/* committed to socket */
		tcp6stat.tcp6s_accepts++;
		tcp6_peer_mss(t6p, opti.maxseg);
		goto trimthenstep6;
		}

	/*
	 * If the state is SYN_SENT:
	 *	if seg contains an ACK, but not for our SYN, drop the input.
	 *	if seg contains a RST, then drop the connection.
	 *	if seg does not contain SYN, then drop it.
	 * Otherwise this is an acceptable SYN segment
	 *	initialize t6p->rcv_nxt and t6p->irs
	 *	if seg contains ack then advance t6p->snd_una
	 *	if SYN has been acked change to ESTABLISHED else SYN_RCVD state
	 *	arrange for segment to be acked (eventually)
	 *	continue processing rest of data/controls, beginning with URG
	 */
	case TCP6S_SYN_SENT:
		if ((thflags & TH_ACK) &&
		    (SEQ_LEQ(th->th_ack, t6p->iss) ||
		     SEQ_GT(th->th_ack, t6p->snd_max)))
			goto dropwithreset;
		if (thflags & TH_RST) {
			if (thflags & TH_ACK)
				t6p = tcp6_drop(t6p, ECONNREFUSED);
			goto drop;
		}
		if ((thflags & TH_SYN) == 0)
			goto drop;
		if (thflags & TH_ACK) {
			t6p->snd_una = th->th_ack;
			if (SEQ_LT(t6p->snd_nxt, t6p->snd_una))
				t6p->snd_nxt = t6p->snd_una;
		}
		t6p->t_timer[TCP6T_REXMT] = 0;
		t6p->irs = th->th_seq;
		tcp6_rcvseqinit(t6p);
		t6p->t_flags |= TF_ACKNOW;
		/*
		 * If we received options, tcp6_dooptions will set the
		 * option flags; if there were none, we use neither
		 * timestamp nor window scaling options.
		 */
		if (optp == NULL)
			t6p->t_flags &= ~(TF_SEND_TSTMP | TF_USE_SCALE);
		tcp6_peer_mss(t6p, opti.maxseg);
		if (thflags & TH_ACK && SEQ_GT(t6p->snd_una, t6p->iss)) {
			tcp6stat.tcp6s_connects++;
			soisconnected(so);
			t6p->t_state = TCP6S_ESTABLISHED;
			/* Do window scaling on this connection? */
			if (t6p->t_flags & TF_USE_SCALE) {
				t6p->snd_scale = t6p->requested_s_scale;
				t6p->rcv_scale = t6p->request_r_scale;
			}
			(void) tcp6_reass(t6p, 0, 0, 0, 0);
			/*
			 * if we didn't have to retransmit the SYN,
			 * use its rtt as our initial srtt & rtt var.
			 */
			if (t6p->t_rtt)
				tcp6_xmit_timer(t6p, t6p->t_rtt);
			/*
			 * Since new data was acked (the SYN), open the
			 * congestion window by one MSS.  We do this
			 * here, because we won't go through the normal
			 * ACK processing below.  And since this is the
			 * start of the connection, we know we are in
			 * the exponential phase of slow-start.
			 */
			t6p->snd_cwnd += t6p->t_maxseg;
		} else
			t6p->t_state = TCP6S_SYN_RECEIVED;

trimthenstep6:
		/* Do maxseg initialization */
		tcp6_maxseg_init(t6p);

		/*
		 * Advance th->th_seq to correspond to first data byte.
		 * If data, trim to stay within window,
		 * dropping FIN if necessary.
		 */
		th->th_seq++;
		if (len > t6p->rcv_wnd) {
			todrop = len - t6p->rcv_wnd;
			m_adj(m, -todrop);
			len = t6p->rcv_wnd;
			thflags &= ~TH_FIN;
			tcp6stat.tcp6s_rcvpackafterwin++;
			tcp6stat.tcp6s_rcvbyteafterwin += todrop;
		}
		t6p->snd_wl1 = th->th_seq - 1;
		t6p->rcv_up = th->th_seq;
		goto step6;

	/*
	 * If the state is SYN_RECEIVED:
	 *	If seg contains an ACK, but not for our SYN, drop the input
	 *	and generate an RST.  See page 36, rfc793
	 */
	case TCP6S_SYN_RECEIVED:
		if ((thflags & TH_ACK) &&
		    (SEQ_LEQ(th->th_ack, t6p->iss) ||
		     SEQ_GT(th->th_ack, t6p->snd_max)))
			goto dropwithreset;
		break;
	}

	/*
	 * States other than LISTEN or SYN_SENT.
	 * First check timestamp, if present.
	 * Then check that at least some bytes of segment are within 
	 * receive window.  If segment begins before rcv_nxt,
	 * drop leading data (and SYN); if nothing left, just ack.
	 * 
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment
	 * and it's less than ts_recent, drop it.
	 */
	if (opti.ts_present && (thflags & TH_RST) == 0 && t6p->ts_recent &&
	    TSTMP_LT(opti.ts_val, t6p->ts_recent)) {

		/* Check to see if ts_recent is over 24 days old.  */
		if ((int)(tcp6_now - t6p->ts_recent_age) > TCP6_PAWS_IDLE) {
			/*
			 * Invalidate ts_recent.  If this segment updates
			 * ts_recent, the age will be reset later and ts_recent
			 * will get a valid value.  If it does not, setting
			 * ts_recent to zero will at least satisfy the
			 * requirement that zero be placed in the timestamp
			 * echo reply when ts_recent isn't valid.  The
			 * age isn't reset until we get a valid ts_recent
			 * because we don't want out-of-order segments to be
			 * dropped when ts_recent is old.
			 */
			t6p->ts_recent = 0;
		} else {
			tcp6stat.tcp6s_rcvduppack++;
			tcp6stat.tcp6s_rcvdupbyte += len;
			tcp6stat.tcp6s_pawsdrop++;
			goto dropafterack;
		}
	}

	todrop = t6p->rcv_nxt - th->th_seq;
	if (todrop > 0) {
		if (thflags & TH_SYN) {
			thflags &= ~TH_SYN;
			th->th_seq++;
			if (th->th_urp > 1) 
				th->th_urp--;
			else
				thflags &= ~TH_URG;
			todrop--;
		}
		if (todrop >= len) {
			tcp6stat.tcp6s_rcvduppack++;
			tcp6stat.tcp6s_rcvdupbyte += len;
			/*
			 * If segment is just one to the left of the window,
			 * check three special cases:
			 * 1. Don't toss RST in response to 4.2-style keepalive.
			 * 2. If the only thing to drop is a FIN, we can drop
			 *    it, but check the ACK or we will get into FIN
			 *    wars if our FINs crossed (both CLOSING).
			 * 3. If we have sent a window probe, it may or may not
			 *    have been accepted.  If window probes crossed,
			 *    we must accept ACK on segments one to the left
			 *    of the window, or we can get ACK wars after
			 *    exchanging probes.  (After sending a probe,
			 *    ACK-only packets are sent with the pre-probe
			 *    sequence number.)
			 * In any of these cases, send ACK to resynchronize,
			 * but keep on processing for RST or ACK.
			 */
			if (((thflags & TH_FIN || todrop == 1) &&
			    todrop == len + 1)
#ifdef TCP6_COMPAT_42
			  || (thflags & TH_RST && th->th_seq == t6p->rcv_nxt - 1)
#endif
			   ) {
				todrop = len;
				thflags &= ~TH_FIN;
			} else {
				/*
				 * Handle the case when a bound socket connects
				 * to itself. Allow packets with a SYN and
				 * an ACK to continue with the processing.
				 */
				if (todrop != 0 || (thflags & TH_ACK) == 0)
					goto dropafterack;
			}
			t6p->t_flags |= TF_ACKNOW;
		} else {
			tcp6stat.tcp6s_rcvpartduppack++;
			tcp6stat.tcp6s_rcvpartdupbyte += todrop;
		}
		hdroptlen += todrop;	/* drop from head afterwards */
		th->th_seq += todrop;
		len -= todrop;
		if (th->th_urp > todrop)
			th->th_urp -= todrop;
		else {
			thflags &= ~TH_URG;
			th->th_urp = 0;
		}
	}

	/*
	 * If new data are received on a connection after the
	 * user processes are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) &&
	    t6p->t_state > TCP6S_CLOSE_WAIT && len) {
		t6p = tcp6_close(t6p);
		tcp6stat.tcp6s_rcvafterclose++;
		goto dropwithreset;
	}

	/*
	 * If segment ends after window, drop trailing data
	 * (and PUSH and FIN); if nothing left, just ACK.
	 */
	todrop = (th->th_seq + len) - (t6p->rcv_nxt + t6p->rcv_wnd);
	if (todrop > 0) {
		tcp6stat.tcp6s_rcvpackafterwin++;
		if (todrop >= len) {
			tcp6stat.tcp6s_rcvbyteafterwin += len;
			/*
			 * If a new connection request is received
			 * while in TIME_WAIT, drop the old connection
			 * and start over if the sequence numbers
			 * are above the previous ones.
			 */
			if (thflags & TH_SYN &&
			    t6p->t_state == TCP6S_TIME_WAIT &&
			    SEQ_GT(th->th_seq, t6p->rcv_nxt)) {
				iss = t6p->snd_nxt + TCP6_ISSINCR;
				t6p = tcp6_close(t6p);
				goto findpcb;
			}
			/*
			 * If window is closed can only take segments at
			 * window edge, and have to drop data and PUSH from
			 * incoming segments.  Continue processing, but
			 * remember to ack.  Otherwise, drop segment
			 * and ack.
			 */
			if (t6p->rcv_wnd == 0 && th->th_seq == t6p->rcv_nxt) {
				t6p->t_flags |= TF_ACKNOW;
				tcp6stat.tcp6s_rcvwinprobe++;
			} else
				goto dropafterack;
		} else
			tcp6stat.tcp6s_rcvbyteafterwin += todrop;
		m_adj(m, -todrop);
		len -= todrop;
		thflags &= ~(TH_PUSH|TH_FIN);
	}

	/*
	 * If last ACK falls within this segment's sequence numbers,
	 * record its timestamp.
	 */
	if (opti.ts_present && SEQ_LEQ(th->th_seq, t6p->last_ack_sent) &&
	    SEQ_LT(t6p->last_ack_sent, th->th_seq + len +
	    ((thflags & (TH_SYN|TH_FIN)) != 0))) {
		t6p->ts_recent_age = tcp6_now;
		t6p->ts_recent = opti.ts_val;
	}

	/*
	 * If the RST bit is set examine the state:
	 *    SYN_RECEIVED STATE:
	 *	If passive open, return to LISTEN state.
	 *	If active open, inform user that connection was refused.
	 *    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
	 *	Inform user that connection was reset, and close tcb6.
	 *    CLOSING, LAST_ACK, TIME_WAIT STATES
	 *	Close the tcb6.
	 */
	if (thflags&TH_RST) switch (t6p->t_state) {

	case TCP6S_SYN_RECEIVED:
		so->so_error = ECONNREFUSED;
		goto close;

	case TCP6S_ESTABLISHED:
	case TCP6S_FIN_WAIT_1:
	case TCP6S_FIN_WAIT_2:
	case TCP6S_CLOSE_WAIT:
		so->so_error = ECONNRESET;
	close:
		t6p->t_state = TCP6S_CLOSED;
		tcp6stat.tcp6s_drops++;
		t6p = tcp6_close(t6p);
		goto drop;

	case TCP6S_CLOSING:
	case TCP6S_LAST_ACK:
	case TCP6S_TIME_WAIT:
		t6p = tcp6_close(t6p);
		goto drop;
	}

	/*
	 * If a SYN is in the window, then this is an
	 * error and we send an RST and drop the connection.
	 */
	if (thflags & TH_SYN) {
		t6p = tcp6_drop(t6p, ECONNRESET);
		goto dropwithreset;
	}

	/*
	 * If the ACK bit is toff we drop the segment and return.
	 */
	if ((thflags & TH_ACK) == 0)
		goto drop;
	
	/*
	 * Ack processing.
	 */
	switch (t6p->t_state) {

	/*
	 * In SYN_RECEIVED state if the ack ACKs our SYN then enter
	 * ESTABLISHED state and continue processing, otherwise
	 * send an RST.
	 */
	case TCP6S_SYN_RECEIVED:
		if (SEQ_GT(t6p->snd_una, th->th_ack) ||
		    SEQ_GT(th->th_ack, t6p->snd_max))
			goto dropwithreset;
		tcp6stat.tcp6s_connects++;
		soisconnected(so);
		t6p->t_state = TCP6S_ESTABLISHED;
		/* Do window scaling? */
		if (t6p->t_flags & TF_USE_SCALE) {
			t6p->snd_scale = t6p->requested_s_scale;
			t6p->rcv_scale = t6p->request_r_scale;
		}
		(void) tcp6_reass(t6p, 0, 0, 0, 0);
		t6p->snd_wl1 = th->th_seq - 1;
		/* fall into ... */

	/*
	 * In ESTABLISHED state: drop duplicate ACKs; ACK out of range
	 * ACKs.  If the ack is in the range
	 *	t6p->snd_una < th->th_ack <= t6p->snd_max
	 * then advance t6p->snd_una to th->th_ack and drop
	 * data from the retransmission queue.  If this ACK reflects
	 * more up to date window information we update our window information.
	 */
	case TCP6S_ESTABLISHED:
	case TCP6S_FIN_WAIT_1:
	case TCP6S_FIN_WAIT_2:
	case TCP6S_CLOSE_WAIT:
	case TCP6S_CLOSING:
	case TCP6S_LAST_ACK:
	case TCP6S_TIME_WAIT:

		if (SEQ_LEQ(th->th_ack, t6p->snd_una)) {
			/*
			 * Duplicate/old ACK processing.
			 * Increments t_dupacks:
			 *	Pure duplicate (same seq/ack/window, no data)
			 * Doesn't affect t_dupacks:
			 *	Data packets.
			 *	Normal window updates (window opens)
			 * Resets t_dupacks:
			 *	New data ACKed.
			 *	Window shrinks
			 *	Old ACK
			 */
			if (len)
				break;
			/*
			 * If we get an old ACK, there is probably packet
			 * reordering going on.  Be conservative and reset
			 * t_dupacks so that we are less agressive in
			 * doing a fast retransmit.
			 */
			if (th->th_ack != t6p->snd_una) {
				t6p->t_dupacks = 0;
				break;
			}
			if (thwin == t6p->snd_wnd) {
				tcp6stat.tcp6s_rcvdupack++;
				/*
				 * If we have outstanding data (other than
				 * a window probe), this is a completely
				 * duplicate ack (ie, window info didn't
				 * change), the ack is the biggest we've
				 * seen and we've seen exactly our rexmt
				 * threshhold of them, assume a packet
				 * has been dropped and retransmit it.
				 * Kludge snd_nxt & the congestion
				 * window so we send only this one
				 * packet.
				 *
				 * We know we're losing at the current
				 * window size so do congestion avoidance
				 * (set ssthresh to half the current window
				 * and pull our congestion window back to
				 * the new ssthresh).
				 *
				 * Dup acks mean that packets have left the
				 * network (they're now cached at the receiver) 
				 * so bump cwnd by the amount in the receiver
				 * to keep a constant cwnd packets in the
				 * network.
				 */
				if (t6p->t_timer[TCP6T_REXMT] == 0)
					t6p->t_dupacks = 0;
				else if (++t6p->t_dupacks == tcp6rexmtthresh) {
					tcp6_seq onxt = t6p->snd_nxt;
					u_int win =
					    min(t6p->snd_wnd, t6p->snd_cwnd) / 2 /
						t6p->t_maxseg;

					if (win < 2)
						win = 2;
					t6p->snd_ssthresh = win * t6p->t_maxseg;
					t6p->t_timer[TCP6T_REXMT] = 0;
					t6p->t_rtt = 0;
					t6p->snd_nxt = th->th_ack;
					t6p->snd_cwnd = t6p->t_maxseg;
					tcp6stat.tcp6s_sndrexmitfast++;
					(void) tcp6_output(t6p);
					t6p->snd_cwnd = t6p->snd_ssthresh +
					       t6p->t_maxseg * t6p->t_dupacks;
					if (SEQ_GT(onxt, t6p->snd_nxt))
						t6p->snd_nxt = onxt;
					goto drop;
				} else if (t6p->t_dupacks > tcp6rexmtthresh) {
					t6p->snd_cwnd += t6p->t_maxseg;
					(void) tcp6_output(t6p);
					goto drop;
				}
			} else if (thwin < t6p->snd_wnd) {
				/*
				 * The window was retracted!  Previous dup
				 * ACKs may have been due to packets arriving
				 * after the shrunken window, not a missing
				 * packet, so play it safe and reset t_dupacks
				 */
				t6p->t_dupacks = 0;
			}
			break;
		}
		/*
		 * If the congestion window was inflated to account
		 * for the other side's cached packets, retract it.
		 */
		if (t6p->t_dupacks >= tcp6rexmtthresh &&
		    t6p->snd_cwnd > t6p->snd_ssthresh)
			t6p->snd_cwnd = t6p->snd_ssthresh;
		t6p->t_dupacks = 0;
		if (SEQ_GT(th->th_ack, t6p->snd_max)) {
			tcp6stat.tcp6s_rcvacktoomuch++;
			goto dropafterack;
		}
		acked = th->th_ack - t6p->snd_una;
		tcp6stat.tcp6s_rcvackpack++;
		tcp6stat.tcp6s_rcvackbyte += acked;

		/*
		 * If we have a timestamp reply, update smoothed
		 * round trip time.  If no timestamp is present but
		 * transmit timer is running and timed sequence
		 * number was acked, update smoothed round trip time.
		 * Since we now have an rtt measurement, cancel the
		 * timer backoff (cf., Phil Karn's retransmit alg.).
		 * Recompute the initial retransmit timer.
		 */
		if (opti.ts_present)
			tcp6_xmit_timer(t6p, tcp6_now - opti.ts_ecr + 1);
		else if (t6p->t_rtt && SEQ_GT(th->th_ack, t6p->t_rtseq))
			tcp6_xmit_timer(t6p, t6p->t_rtt);

		/*
		 * If all outstanding data is acked, stop retransmit
		 * timer and remember to restart (more output or persist).
		 * If there is more data to be acked, restart retransmit
		 * timer, using current (possibly backed-toff) value.
		 */
		if (th->th_ack == t6p->snd_max) {
			t6p->t_timer[TCP6T_REXMT] = 0;
			needoutput = 1;
		} else if (t6p->t_timer[TCP6T_PERSIST] == 0)
			t6p->t_timer[TCP6T_REXMT] = t6p->t_rxtcur;
		/*
		 * When new data is acked, open the congestion window.
		 * If the window gives us less than ssthresh packets
		 * in flight, open exponentially (maxseg per packet).
		 * Otherwise open linearly: maxseg per window
		 * (maxseg * (maxseg / cwnd) per packet).
		 */
		{
		register u_int cw = t6p->snd_cwnd;
		register u_int incr = t6p->t_maxseg;

		if (cw > t6p->snd_ssthresh)
			incr = incr * incr / cw;
		t6p->snd_cwnd = min(cw + incr, TCP6_MAXWIN<<t6p->snd_scale);
		}
		if (acked > so->so_snd.sb_cc) {
			t6p->snd_wnd -= so->so_snd.sb_cc;
			sbdrop(&so->so_snd, (int)so->so_snd.sb_cc);
			ourfinisacked = 1;
		} else {
			sbdrop(&so->so_snd, acked);
			t6p->snd_wnd -= acked;
			ourfinisacked = 0;
		}
		if (sb_notify(&so->so_snd))
			sowwakeup(so);
		t6p->snd_una = th->th_ack;
		if (SEQ_LT(t6p->snd_nxt, t6p->snd_una))
			t6p->snd_nxt = t6p->snd_una;

		switch (t6p->t_state) {

		/*
		 * In FIN_WAIT_1 STATE in addition to the processing
		 * for the ESTABLISHED state if our FIN is now acknowledged
		 * then enter FIN_WAIT_2.
		 */
		case TCP6S_FIN_WAIT_1:
			if (ourfinisacked) {
				/*
				 * If we can't receive any more
				 * data, then closing user can proceed.
				 * Starting the timer is contrary to the
				 * specification, but if we don't get a FIN
				 * we'll hang forever.
				 */
				if (so->so_state & SS_CANTRCVMORE) {
					soisdisconnected(so);
					t6p->t_timer[TCP6T_2MSL] = tcp6_maxidle;
				}
				t6p->t_state = TCP6S_FIN_WAIT_2;
			}
			break;

	 	/*
		 * In CLOSING STATE in addition to the processing for
		 * the ESTABLISHED state if the ACK acknowledges our FIN
		 * then enter the TIME-WAIT state, otherwise ignore
		 * the segment.
		 */
		case TCP6S_CLOSING:
			if (ourfinisacked) {
				t6p->t_state = TCP6S_TIME_WAIT;
				tcp6_canceltimers(t6p);
				tcp6_start2msl(in6p, t6p);
				soisdisconnected(so);
			}
			break;

		/*
		 * In LAST_ACK, we may still be waiting for data to drain
		 * and/or to be acked, as well as for the ack of our FIN.
		 * If our FIN is now acknowledged, delete the TCB6,
		 * enter the closed state and return.
		 */
		case TCP6S_LAST_ACK:
			if (ourfinisacked) {
				t6p = tcp6_close(t6p);
				goto drop;
			}
			break;

		/*
		 * In TIME_WAIT state the only thing that should arrive
		 * is a retransmission of the remote FIN.  Acknowledge
		 * it and restart the finack timer.
		 */
		case TCP6S_TIME_WAIT:
			tcp6_cancel2msl(in6p, t6p);
			tcp6_start2msl(in6p, t6p);
			goto dropafterack;
		}
	}

step6:
	/*
	 * Update window information.
	 * Don't look at window if no ACK: TAC's send garbage on first SYN.
	 */
	if ((thflags & TH_ACK) &&
	    (SEQ_LT(t6p->snd_wl1, th->th_seq) ||
	    (t6p->snd_wl1 == th->th_seq &&
	    (SEQ_LT(t6p->snd_wl2, th->th_ack) ||
	     (t6p->snd_wl2 == th->th_ack && (thwin > t6p->snd_wnd)))))) {
		/* keep track of pure window updates */
		if (len == 0 &&
		    t6p->snd_wl2 == th->th_ack && thwin > t6p->snd_wnd)
			tcp6stat.tcp6s_rcvwinupd++;
		t6p->snd_wnd = thwin;
		t6p->snd_wl1 = th->th_seq;
		t6p->snd_wl2 = th->th_ack;
		if (t6p->snd_wnd > t6p->max_sndwnd)
			t6p->max_sndwnd = t6p->snd_wnd;
		needoutput = 1;
	}

	/*
	 * Process segments with URG.
	 */
	if ((thflags & TH_URG) && th->th_urp &&
	    TCP6S_HAVERCVDFIN(t6p->t_state) == 0) {
		/*
		 * This is a kludge, but if we receive and accept
		 * random urgent pointers, we'll crash in
		 * soreceive.  It's hard to imagine someone
		 * actually wanting to send this much urgent data.
		 */
		if (th->th_urp + so->so_rcv.sb_cc > sb_max) {
			th->th_urp = 0;			/* XXX */
			thflags &= ~TH_URG;		/* XXX */
			goto dodata;			/* XXX */
		}
		/*
		 * If this segment advances the known urgent pointer,
		 * then mark the data stream.  This should not happen
		 * in CLOSE_WAIT, CLOSING, LAST_ACK or TIME_WAIT STATES since
		 * a FIN has been received from the remote side. 
		 * In these states we ignore the URG.
		 *
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section as the original 
		 * spec states (in one of two places).
		 */
		if (SEQ_GT(th->th_seq+th->th_urp, t6p->rcv_up)) {
			t6p->rcv_up = th->th_seq + th->th_urp;
			so->so_oobmark = so->so_rcv.sb_cc +
			    (t6p->rcv_up - t6p->rcv_nxt) - 1;
			if (so->so_oobmark == 0)
				so->so_state |= SS_RCVATMARK;
			sohasoutofband(so);
			t6p->t_oobflags &= ~(TCP6OOB_HAVEDATA | TCP6OOB_HADDATA);
		}
		/*
		 * Remove out of band data so doesn't get presented to user.
		 * This can happen independent of advancing the URG pointer,
		 * but if two URG's are pending at once, some out-of-band
		 * data may creep in... ick.
		 */
		if (th->th_urp <= len
#ifdef SO_OOBINLINE
		     && (so->so_options & SO_OOBINLINE) == 0
#endif
		     )
			tcp6_pulloutofband(so, th, m, hdroptlen);
	} else
		/*
		 * If no out of band data is expected,
		 * pull receive urgent pointer along
		 * with the receive window.
		 */
		if (SEQ_GT(t6p->rcv_nxt, t6p->rcv_up))
			t6p->rcv_up = t6p->rcv_nxt;
dodata:							/* XXX */

	/*
	 * Process the segment text, merging it into the TCP6 sequencing queue,
	 * and arranging for acknowledgment of receipt if necessary.
	 * This process logically involves adjusting t6p->rcv_wnd as data
	 * is presented to the user (this happens in tcp6_usrreq.c,
	 * case PRU_RCVD).  If a FIN has already been received on this
	 * connection then we just ignore the text.
	 */
	if ((len || (thflags&TH_FIN)) &&
	    TCP6S_HAVERCVDFIN(t6p->t_state) == 0) {
		int xxx;
		m_adj(m, hdroptlen);
		TCP6_REASS(t6p, (struct ip6tcpreass *)ip6, th, m, so,
			   thflags, len);
		/*
		 * Note the amount of data that peer has sent into
		 * our window, in order to estimate the sender's
		 * buffer size.
		 */
		/* xxx whats' this? kazu */
		xxx = so->so_rcv.sb_hiwat - (t6p->rcv_adv - t6p->rcv_nxt);
	} else {
		m_freem(m);
		thflags &= ~TH_FIN;
	}

	/*
	 * If FIN is received ACK the FIN and let the user know
	 * that the connection is closing.
	 */
	if (thflags & TH_FIN) {
		if (TCP6S_HAVERCVDFIN(t6p->t_state) == 0) {
			socantrcvmore(so);
			t6p->t_flags |= TF_ACKNOW;
			t6p->rcv_nxt++;
		}
		switch (t6p->t_state) {

	 	/*
		 * In SYN_RECEIVED and ESTABLISHED STATES
		 * enter the CLOSE_WAIT state.
		 */
		case TCP6S_SYN_RECEIVED:
		case TCP6S_ESTABLISHED:
			t6p->t_state = TCP6S_CLOSE_WAIT;
			break;

	 	/*
		 * If still in FIN_WAIT_1 STATE FIN has not been acked so
		 * enter the CLOSING state.
		 */
		case TCP6S_FIN_WAIT_1:
			t6p->t_state = TCP6S_CLOSING;
			break;

	 	/*
		 * In FIN_WAIT_2 state enter the TIME_WAIT state,
		 * starting the time-wait timer, turning toff the other 
		 * standard timers.
		 */
		case TCP6S_FIN_WAIT_2:
			t6p->t_state = TCP6S_TIME_WAIT;
			tcp6_canceltimers(t6p);
			tcp6_start2msl(in6p, t6p);
			soisdisconnected(so);
			break;

		/*
		 * In TIME_WAIT state restart the 2 MSL time_wait timer.
		 */
		case TCP6S_TIME_WAIT:
			tcp6_cancel2msl(in6p, t6p);
			tcp6_start2msl(in6p, t6p);
			break;
		}
	}
	if (so->so_options & SO_DEBUG)
		tcp6_trace(TA_INPUT, ostate, t6p, &ip6_save, &tcp6_save, 0);

	/*
	 * Return any desired output.
	 */
	if (needoutput || (t6p->t_flags & TF_ACKNOW))
		(void) tcp6_output(t6p);
	return IPPROTO_DONE;

dropafterack:
	/*
	 * Generate an ACK dropping incoming segment if it occupies
	 * sequence space, where the ACK reflects our state.
	 */
	if (thflags & TH_RST)
		goto drop;
	m_freem(m);
	t6p->t_flags |= TF_ACKNOW;
	(void) tcp6_output(t6p);
	return IPPROTO_DONE;

dropwithreset:
	/*
	 * Generate a RST, dropping incoming segment.
	 * Make ACK acceptable to originator of segment.
	 * Don't bother to respond if destination was broadcast/multicast.
	 */
	if ((thflags & TH_RST) || m->m_flags & (M_BCAST|M_MCAST|M_ANYCAST6) ||
	    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
		goto drop;
	if (thflags & TH_ACK)
		(void) tcp6_respond(t6p, ip6, th, m, (tcp6_seq)0,
				    th->th_ack, TH_RST);
	else {
		if (thflags & TH_SYN)
			len++;
		(void) tcp6_respond(t6p, ip6, th, m,
				    th->th_seq + len, (tcp6_seq)0,
		    TH_RST|TH_ACK);
	}
	/* destroy temporarily created socket */
	if (dropsocket)
		(void) soabort(so);
	return IPPROTO_DONE;

drop:
	/*
	 * Drop space held by incoming segment and return.
	 */
	if (t6p && (t6p->t_in6pcb->in6p_socket->so_options & SO_DEBUG))
		tcp6_trace(TA_DROP, ostate, t6p, &ip6_save, &tcp6_save, 0);
	m_freem(m);
	/* destroy temporarily created socket */
	if (dropsocket)
		(void) soabort(so);
	return IPPROTO_DONE;
#ifndef TUBA_INCLUDE
}

void
tcp6_dooptions(t6p, cp, cnt, th, oi)
	struct tcp6cb *t6p;
	u_char *cp;
	int cnt;
	struct tcp6hdr *th;
	struct tcp6_opt_info *oi;
{
	u_short mss;
	int opt, optlen;
	int scale_present = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCP6OPT_EOL)
			break;
		if (opt == TCP6OPT_NOP)
			optlen = 1;
		else {
			optlen = cp[1];
			if (optlen <= 0)
				break;
		}
		switch (opt) {

		default:
			continue;

		case TCP6OPT_MAXSEG:
			if (optlen != TCP6OLEN_MAXSEG)
				continue;
			if (!(th->th_flags & TH_SYN))
				continue;
			bcopy((char *) cp + 2, (char *) &mss, sizeof(mss));
			oi->maxseg = ntohs(mss);
			break;

		case TCP6OPT_WINDOW:
			if (optlen != TCP6OLEN_WINDOW)
				continue;
			if (!(th->th_flags & TH_SYN))
				continue;
			scale_present = 1;
			t6p->requested_s_scale = min(cp[2], TCP6_MAX_WINSHIFT);
			break;

		case TCP6OPT_TIMESTAMP:
			if (optlen != TCP6OLEN_TIMESTAMP)
				continue;
			oi->ts_present = 1;
			bcopy((char *)cp + 2, (char *) &oi->ts_val,
					sizeof(oi->ts_val));
			NTOHL(oi->ts_val);
			bcopy((char *)cp + 6, (char *) &oi->ts_ecr,
					sizeof(oi->ts_ecr));
			NTOHL(oi->ts_ecr);

			/* 
			 * A timestamp received in a SYN makes
			 * it ok to send timestamp requests and replies.
			 */
			if (th->th_flags & TH_SYN) {
				t6p->ts_recent = oi->ts_val;
				t6p->ts_recent_age = tcp6_now;
			}
			break;
		}
	}
	if (th->th_flags & TH_SYN) {
		if (oi->ts_present == 0)
			t6p->t_flags &= ~TF_SEND_TSTMP;
		if (scale_present == 0)
			t6p->t_flags &= ~TF_USE_SCALE;
	}
}

/*
 * Pull out of band byte out of a segment so
 * it doesn't appear in the user's data queue.
 * It is still reflected in the segment length for
 * sequencing purposes.
 */
void
tcp6_pulloutofband(so, th, m, off)
	struct socket *so;
	struct tcp6hdr *th;
	register struct mbuf *m;
	int off;
{
	int cnt = off + th->th_urp - 1;
	
	while (cnt >= 0) {
		if (m->m_len > cnt) {
			char *cp = mtod(m, caddr_t) + cnt;
			struct tcp6cb *t6p = sototcp6cb(so);

			t6p->t_iobc = *cp;
			t6p->t_oobflags |= TCP6OOB_HAVEDATA;
			bcopy(cp+1, cp, (unsigned)(m->m_len - cnt - 1));
			m->m_len--;
			return;
		}
		cnt -= m->m_len;
		m = m->m_next;
		if (m == 0)
			break;
	}
	panic("tcp6_pulloutofband");
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
void
tcp6_xmit_timer(t6p, rtt)
	register struct tcp6cb *t6p;
	short rtt;
{
	register short delta;

	tcp6stat.tcp6s_rttupdated++;
	if (t6p->t_srtt != 0) {
		/*
		 * srtt is stored as fixed point with 3 bits after the
		 * binary point (i.e., scaled by 8).  The following magic
		 * is equivalent to the smoothing algorithm in rfc793 with
		 * an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		 * point).  Adjust rtt to origin 0.
		 */
		delta = rtt - 1 - (t6p->t_srtt >> TCP6_RTT_SHIFT);
		if ((t6p->t_srtt += delta) <= 0)
			t6p->t_srtt = 1;
		/*
		 * We accumulate a smoothed rtt variance (actually, a
		 * smoothed mean difference), then set the retransmit
		 * timer to smoothed rtt + 4 times the smoothed variance.
		 * rttvar is stored as fixed point with 2 bits after the
		 * binary point (scaled by 4).  The following is
		 * equivalent to rfc793 smoothing with an alpha of .75
		 * (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
		 * rfc793's wired-in beta.
		 */
		if (delta < 0)
			delta = -delta;
		delta -= (t6p->t_rttvar >> TCP6_RTTVAR_SHIFT);
		if ((t6p->t_rttvar += delta) <= 0)
			t6p->t_rttvar = 1;
	} else {
		/* 
		 * No rtt measurement yet - use the unsmoothed rtt.
		 * Set the variance to half the rtt (so our first
		 * retransmit happens at 3*rtt).
		 */
		t6p->t_srtt = rtt << TCP6_RTT_SHIFT;
		t6p->t_rttvar = rtt << (TCP6_RTTVAR_SHIFT - 1);
	}
	t6p->t_rtt = 0;
	t6p->t_rxtshift = 0;

	/*
	 * the retransmit should happen at rtt + 4 * rttvar.
	 * Because of the way we do the smoothing, srtt and rttvar
	 * will each average +1/2 tick of bias.  When we compute
	 * the retransmit timer, we want 1/2 tick of rounding and
	 * 1 extra tick because of +-1/2 tick uncertainty in the
	 * firing of the timer.  The bias will give us exactly the
	 * 1.5 tick we need.  But, because the bias is
	 * statistical, we have to test that we don't drop below
	 * the minimum feasible timer (which is 2 ticks).
	 */
	TCP6T_RANGESET(t6p->t_rxtcur, TCP6_REXMTVAL(t6p),
	    t6p->t_rttmin, TCP6TV_REXMTMAX);
	
	/*
	 * We received an ack for a packet that wasn't retransmitted;
	 * it is probably safe to discard any error indications we've
	 * received recently.  This isn't quite right, but close enough
	 * for now (a route might have failed after we sent a segment,
	 * and the return path might not be symmetrical).
	 */
	t6p->t_softerror = 0;
}

/*
 * Check if there's an initial rtt or rttvar.
 * Convert from the route-table units to
 * scaled multiples of the slow timeout timer.
 */

static void
tcp6_rtt_init(t6p, rt)
	register struct tcp6cb *t6p;
	register struct rtentry *rt;
{
	register int rtt;

	if (t6p->t_srtt == 0 && (rtt = rt->rt_rmx.rmx_rtt)) {
		/*
		 * XXX the lock bit for RTT indicates that the value
		 * is also a minimum value; this is subject to time.
		 */
		if (rt->rt_rmx.rmx_locks & RTV_RTT)
			t6p->t_rttmin = rtt / (RTM_RTTUNIT / PR_SLOWHZ);
		t6p->t_srtt = rtt / (RTM_RTTUNIT / (PR_SLOWHZ * TCP6_RTT_SCALE));
		if (rt->rt_rmx.rmx_rttvar)
			t6p->t_rttvar = rt->rt_rmx.rmx_rttvar /
			    (RTM_RTTUNIT / (PR_SLOWHZ * TCP6_RTTVAR_SCALE));
		else
			/* default variation is +- 1 rtt */
			t6p->t_rttvar =
			    t6p->t_srtt * TCP6_RTTVAR_SCALE / TCP6_RTT_SCALE;
		TCP6T_RANGESET(t6p->t_rxtcur,
		    ((t6p->t_srtt >> 2) + t6p->t_rttvar) >> 1,
		    t6p->t_rttmin, TCP6TV_REXMTMAX);
	}
}

u_int
tcp6_maxseg(t6p, maxseg)
	register struct tcp6cb *t6p;
	register u_int maxseg;
{
#if 0
	/*
	 * See whether we (may) need to save space
	 * for timestamp options.
	 *
	 * now handled in tcp6_output().
	 */
	if (t6p->t_flags & TF_USE_SCALE)
		maxseg -= TCP6OLEN_TSTAMP_APPA;
#endif
	return(tcp6_mss_round(maxseg));
}

static int
tcp6_mss_round(val)
	int val;
{
	int frag;

	if (val > tcp6_roundsize &&
	    (frag = val % tcp6_roundsize) <= val / tcp6_roundfrac)
		val -= frag;
	return (val);
}


void
tcp6_maxseg_init(t6p)
	struct tcp6cb *t6p;
{
	struct rtentry *rt;
	struct socket *so;
	u_long bufsize;
	u_int maxseg;

	if ((so = t6p->t_in6pcb->in6p_socket) == NULL)
		return;
	rt = tcp6_rtlookup(t6p->t_in6pcb);
	maxseg = t6p->t_maxseg;

	/*
	 * If there's a pipesize, change the socket buffer
	 * to that size.  Make the socket buffers an integral
	 * number of mss units; if the mss is larger than
	 * the socket buffer, make the socket buffer one mss.
	 */
#ifdef RTV_SPIPE
	if ((rt == NULL) || (bufsize = rt->rt_rmx.rmx_sendpipe) == 0)
#endif
		bufsize = so->so_snd.sb_hiwat;
	if (bufsize < maxseg)
		bufsize = maxseg;
	else if (bufsize > maxseg) {
		bufsize = roundup(bufsize, maxseg);
		if (bufsize > sb_max)
			bufsize = sb_max;
		(void)sbreserve(&so->so_snd, bufsize);
	}
}

/*
 * Get the rtentry structure for a TCP6 connection.  If the
 * route has gone down or it hasn't been allocated, we
 * allocate it.
 */
struct rtentry *
tcp6_rtlookup(in6p)
	register struct in6pcb *in6p;
{
	struct route_in6 *ro;
	register struct rtentry *rt;

	ro = &in6p->in6p_route;
	if ((rt = ro->ro_rt) != 0) {
		if (rt->rt_flags & RTF_UP)
			return(rt);
		RTFREE(rt);
		ro->ro_rt = (struct rtentry *)0;
	}

	/* No route yet, so try to acquire one */
	if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
		bzero(&ro->ro_dst, sizeof(struct sockaddr_in6));
		ro->ro_dst.sin6_family = AF_INET6;
		ro->ro_dst.sin6_len = sizeof(struct sockaddr_in6);
		((struct sockaddr_in6 *) &ro->ro_dst)->sin6_addr =
			in6p->in6p_faddr;
#ifdef __bsdi__			/* bsdi needs rtcalloc to clone a route */
		rtcalloc((struct route *)ro);
#else
		rtalloc((struct route *)ro);
#endif 

	}
	return(ro->ro_rt);
}

/*
 * Determine a reasonable value for maxseg size.
 * If the route is known, check route for mtu.
 * If none, use an mss that can be handled on the outgoing
 * interface without forcing IP6 to fragment; if bigger than
 * an mbuf cluster (MCLBYTES), round down to nearest multiple of MCLBYTES
 * to utilize large mbufs.  If no route is found, route has no mtu,
 * or the destination isn't local, use a default, hopefully conservative
 * size (usually 512 or the default IP6 max size, but no more than the mtu
 * of the interface), as we can't discover anything about intervening
 * gateways or networks.  We also initialize the congestion/slow start
 * window to be a single segment if the destination isn't local.
 * While looking at the routing entry, we also initialize other path-dependent
 * parameters from pre-set or cached values in the routing entry.
 *
 * If (potentially) using the timestamp option, the mss value that
 * we send to the peer is not reduced for the option.  However, we
 * set t_maxseg to a value small enough for the option if we will
 * be sending it.
 */
void
tcp6_peer_mss(t6p, offer)
	register struct tcp6cb *t6p;
	u_int offer;
{
	register struct rtentry *rt;
	struct ifnet *ifp;
	register int mss;		/* mss is size to offer */
	int maxseg = 0;			/* magseg is size for t_maxseg */
	u_long bufsize;
	struct in6pcb *in6p;
	struct socket *so;
#if 0
	extern int tcp6_mssdflt;
#endif

	in6p = t6p->t_in6pcb;

	if (offer)
		t6p->t_peermaxseg = offer;

	if ((rt = tcp6_rtlookup(in6p)) == (struct rtentry *)0)
		return;

	ifp = rt->rt_ifp;
	so = in6p->in6p_socket;

#ifdef RTV_MTU	/* if route characteristics exist ... */

	/* While we're here, do any initial rtt or rttvar initialization.  */
	tcp6_rtt_init(t6p, rt);

	/* if there's an mtu associated with the route, use it */
	if (rt->rt_rmx.rmx_mtu)
		mss = rt->rt_rmx.rmx_mtu - sizeof(struct ip6tcp);
	else
#endif /* RTV_MTU */
	{
#if 1
		mss = nd_ifinfo[ifp->if_index].linkmtu;
#else
		mss = ifp->if_mtu;
#endif
		mss -= sizeof(struct ip6tcp);
		if (tcp6_pmtu == 0 && !in6_localaddr(&in6p->in6p_faddr))
			mss = min(mss, tcp6_mssdflt);
	}
	/*
	 * The current mss, t_maxseg, is initialized to the default value.
	 * If we compute a smaller value, reduce the current mss.
	 * If we compute a larger value, return it for use in sending
	 * a max seg size option, but don't store it for use
	 * unless we received an offer at least that large from peer.
	 * However, do not accept offers under 32 bytes.
	 */

	if (offer)
		mss = min(mss, offer);

	mss = max(mss, 32);		/* sanity */
	if (mss < t6p->t_maxseg || offer != 0) {
		maxseg = t6p->t_maxseg = tcp6_maxseg(t6p, mss);
		tcp6_maxseg_init(t6p);

#ifdef RTV_RPIPE
		if ((bufsize = rt->rt_rmx.rmx_recvpipe) == 0)
#endif
			bufsize = so->so_rcv.sb_hiwat;
		if (bufsize < mss)
			bufsize = mss;
		/*
		 * The following is problematical.
		 * If using timestamp options, the peer may send
		 * packets smaller than mss, and may round down
		 * the maxseg to a "nice" value (as we do).
		 */
		if (bufsize > mss) {
			bufsize = roundup(bufsize, mss);
			if (bufsize > sb_max)
				bufsize = sb_max;
			(void)sbreserve(&so->so_rcv, bufsize);
		}
	}
	t6p->snd_cwnd = maxseg;

#ifdef RTV_SSTHRESH
	if (rt->rt_rmx.rmx_ssthresh) {
		/*
		 * There's some sort of gateway or interface
		 * buffer limit on the path.  Use this to set
		 * the slow start threshhold, but set the
		 * threshold to no less than 2*maxseg.
		 */
		t6p->snd_ssthresh = max(2 * maxseg, rt->rt_rmx.rmx_ssthresh);
	}
#endif /* RTV_MTU */
	return;
}

/*
 * Determine the maxiumum segment size to use when sending a
 * TCP6 MAXSEG option.  We want to use the MTU of our the interface
 * that the other side will be using to send traffic to us on.
 * For local connections, that means using the interface that the
 * route points to, but for remote connections we don't know for
 * sure which interface that is.  So, we use the largest MTU of
 * all our interfaces to provide the maximum flexibility for
 * inbound MTU discovery code.  But for loopback interfaces, we
 * just use the MTU of the loopback interface.
 */
u_long
tcp6_send_mss(t6p)
	struct tcp6cb *t6p;
{
	register struct in6pcb *in6p = t6p->t_in6pcb;
	register struct rtentry *rt;
	struct ifnet *ifp;
	register unsigned long mss;		/* size to offer */

	mss = in6_maxmtu;

	if (((rt = tcp6_rtlookup(in6p)) == (struct rtentry *)0) ||
	    ((ifp = rt->rt_ifp) == (struct ifnet *)0)) {
		if ((mss == 0) &&
		    ((rt == 0) || ((mss = rt->rt_rmx.rmx_mtu) == 0)))
			mss = tcp6_mssdflt + sizeof(struct ip6tcp);
	} else if ((ifp->if_flags & IFF_LOOPBACK) || mss == 0) {
#if 1
		mss = nd_ifinfo[ifp->if_index].linkmtu;
#else
		mss = ifp->if_mtu;
#endif
	}

	mss -= sizeof(struct ip6tcp);

	if (tcp6_43maxseg && !in6_localaddr(&in6p->in6p_faddr))
		mss = min(mss, tcp6_mssdflt);

	/*
	 * Never offer a MAXSEG under 32 bytes.
	 */
	mss = max(mss, 32);
	return (mss);
}

#endif /* TUBA_INCLUDE */

void
syn_cache_insert6(sc, prevp, headp)
	struct syn_cache6 *sc;
	struct syn_cache6 ***prevp;
	struct syn_cache_head6 **headp;
{
	struct syn_cache_head6 *scp, *scp2, *sce;
	struct syn_cache6 *sc2;
	static u_int timeo_val;

	/* Initialize the hash secrets when adding the first entry */
	if (syn_cache_count6 == 0) {
		struct timeval tv;
		microtime(&tv);
		syn_hash61 = random() ^ (u_long)sc;
		syn_hash62 = random() ^ tv.tv_usec;
	}

	sc->sc_hash = SYN_HASH6(&sc->sc_src, sc->sc_sport, sc->sc_dport);
	sc->sc_next = NULL;
	scp = &tcp6_syn_cache[sc->sc_hash % tcp6_syn_cache_size];
	*headp = scp;

	/*
	 * Make sure that we don't overflow the per-bucket
	 * limit or the total cache size limit.
	 */
	if (scp->sch_length >= tcp6_syn_bucket_limit) {
		tcp6stat.tcp6s_sc_bucketoverflow++;
		sc2 = scp->sch_first;
		scp->sch_first = sc2->sc_next;
		FREE(sc2, M_PCB);
	} else if (syn_cache_count6 >= tcp6_syn_cache_limit) {
		tcp6stat.tcp6s_sc_overflowed++;
		/*
		 * The cache is full.  Toss the first (i.e, oldest)
		 * element in this bucket.
		 */
		scp2 = scp;
		if (scp2->sch_first == NULL) {
			sce = &tcp6_syn_cache[tcp6_syn_cache_size];
			for (++scp2; scp2 != scp; scp2++) {
				if (scp2 >= sce)
					scp2 = &tcp6_syn_cache[0];
				if (scp2->sch_first)
					break;
			}
		}
		sc2 = scp2->sch_first;
		if (sc2 == NULL) {
			FREE(sc, M_PCB);
			return;
		}
		if ((scp2->sch_first = sc2->sc_next) == NULL)
			scp2->sch_last = NULL;
		else
			sc2->sc_next->sc_timer += sc2->sc_timer;
		FREE(sc2, M_PCB);
	} else {
		scp->sch_length++;
		syn_cache_count6++;
	}
	tcp6stat.tcp6s_sc_added++;

	/*
	 * Put it into the bucket.
	 */
	if (scp->sch_first == NULL)
		*prevp = &scp->sch_first;
	else
		*prevp = &scp->sch_last->sc_next;
	**prevp = sc;
	scp->sch_last = sc;

	/*
	 * If the timeout value has changed
	 *   1) force it to fit in a u_char
	 *   2) Run the timer routine to truncate all
	 *	existing entries to the new timeout value.
	 */
	if (timeo_val != tcp6_syn_cache_timeo) {
		tcp6_syn_cache_timeo = min(tcp6_syn_cache_timeo, UCHAR_MAX);
		if (timeo_val > tcp6_syn_cache_timeo)
			syn_cache_timer6(timeo_val - tcp6_syn_cache_timeo);
		timeo_val = tcp6_syn_cache_timeo;
	}
	if (scp->sch_timer_sum > 0)
		sc->sc_timer = tcp6_syn_cache_timeo - scp->sch_timer_sum;
	else if (scp->sch_timer_sum == 0) {
		/* When the bucket timer is 0, it is not in the cache queue.  */
		scp->sch_headq = tcp6_syn_cache_first;
		tcp6_syn_cache_first = scp;
		sc->sc_timer = tcp6_syn_cache_timeo;
	}
	scp->sch_timer_sum = tcp6_syn_cache_timeo;
}

/*
 * Walk down the cache list, decrementing the timer of
 * the first element on each entry.  If the timer goes
 * to zero, remove it and all successive entries with
 * a zero timer.
 */
void
syn_cache_timer6(interval)
	int interval;
{
	struct syn_cache_head6 *scp, **pscp;
	struct syn_cache6 *sc, *scn;
	int n;


	pscp = &tcp6_syn_cache_first;
	scp = tcp6_syn_cache_first;
	while (scp) {
		/*
		 * Remove any empty hash buckets
		 * from the cache queue.
		 */
		if ((sc = scp->sch_first) == NULL) {
			*pscp = scp->sch_headq;
			scp->sch_headq = NULL;
			scp->sch_timer_sum = 0;
			scp->sch_first = scp->sch_last = NULL;
			scp->sch_length = 0;
			scp = *pscp;
			continue;
		}

		scp->sch_timer_sum -= interval;
		if (scp->sch_timer_sum <= 0)
			scp->sch_timer_sum = -1;
		n = interval;
		while (sc->sc_timer <= n) {
			n -= sc->sc_timer;
			scn = sc->sc_next;
			tcp6stat.tcp6s_sc_timed_out++;
			syn_cache_count6--;
			FREE(sc, M_PCB);
			scp->sch_length--;
			if ((sc = scn) == NULL)
				break;
		}
		if ((scp->sch_first = sc) != NULL) {
			sc->sc_timer -= n;
			pscp = &scp->sch_headq;
			scp = scp->sch_headq;
		}
	}
}

/*
 * Find an entry in the syn cache.
 */
struct syn_cache6 *
syn_cache_lookup6(ip6, th, prevp, headp)
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
	struct syn_cache6 ***prevp;
	struct syn_cache_head6 **headp;
{
	struct syn_cache6 *sc, **prev;
	struct syn_cache_head6 *head;
	u_long hash;

	hash = SYN_HASH6(&ip6->ip6_src, th->th_sport, th->th_dport);

	head = &tcp6_syn_cache[hash % tcp6_syn_cache_size];
	*headp = head;
	prev = &head->sch_first;
	for (sc = head->sch_first; sc; prev = &sc->sc_next, sc = sc->sc_next) {
		if (sc->sc_hash != hash)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&sc->sc_src, &ip6->ip6_src) &&
		    sc->sc_sport == th->th_sport &&
		    sc->sc_dport == th->th_dport &&
		    IN6_ARE_ADDR_EQUAL(&sc->sc_dst, &ip6->ip6_dst)) {
			*prevp = prev;
			return (sc);
		}
	}
	return (NULL);
}

/*
 * This function gets called when we receive an ACK for a
 * socket in the LISTEN state.  We look up the connection
 * in the syn cache, and if its there, we pull it out of
 * the cache and turn it into a full-blown connection in
 * the SYN-RECEIVED state.
 */
struct socket *
syn_cache_get6(so, m, off, len)
	struct socket *so;
	struct mbuf *m;
	int off;
	int len;
{
	struct syn_cache6 *sc, **sc_prev;
	struct syn_cache_head6 *head;
	register struct in6pcb *in6p;
	register struct tcp6cb *t6p = 0;
	register struct tcp6hdr *th;
	struct ip6_hdr *ip6;
	long win;
#ifdef IPSEC
	struct socket *oso;
#endif

	ip6 = mtod(m, struct ip6_hdr *);
	th = (struct tcp6hdr *)((caddr_t)ip6 + off);
	if ((sc = syn_cache_lookup6(ip6, th, &sc_prev, &head)) == NULL)
		return (NULL);

	win = sbspace(&so->so_rcv);
	if (win > TCP6_MAXWIN)
		win = TCP6_MAXWIN;

	/*
	 * Verify the sequence and ack numbers.
	 */
	if ((th->th_ack != sc->sc_iss + 1) ||
	    SEQ_LEQ(th->th_seq, sc->sc_irs) ||
	    SEQ_GT(th->th_seq, sc->sc_irs + 1 + win)) {
		(void) syn_cache_respond6(sc, m, ip6, th, win, 0);
		return ((struct socket *)(-1));
	}

	/* Remove this cache entry */
	SYN_CACHE_RM6(sc, sc_prev, head);

	/*
	 * Ok, create the full blown connection, and set things up
	 * as they would have been set up if we had created the
	 * connection when the SYN arrived.  If we can't create
	 * the connection, abort it.
	 */
#ifdef IPSEC
	oso = so;
#endif
	so = sonewconn(so, SS_ISCONNECTED);
	if (so == NULL) {
		(void) tcp6_respond(NULL, ip6, th, m, th->th_seq + len, /* xxx */
		    (tcp6_seq)0, TH_RST|TH_ACK);
		so = (struct socket *)(-1);
		tcp6stat.tcp6s_sc_aborted++;
		goto done;
	}

	in6p = sotoin6pcb(so);
	in6p->in6p_laddr = sc->sc_dst;
	in6p->in6p_lport = sc->sc_dport;
	in6p->in6p_faddr = sc->sc_src;
	in6p->in6p_fport = sc->sc_sport;
	if (in6p->in6p_flags & IN6P_CONTROLOPTS) {
		if (in6p->in6p_options) {
			m_freem(in6p->in6p_options);
			in6p->in6p_options = 0;
		}
		ip6_savecontrol(in6p, &in6p->in6p_options, ip6, m);
	}
#ifdef IPSEC
	/* copy old policy into new socket's */
	if (ipsec_copy_policy(sotoin6pcb(oso)->in6p_sp, in6p->in6p_sp))
		printf("syn_cache_get6: could not copy policy\n");
#endif

	t6p = intotcp6cb(in6p);
	t6p->t_state = TCP6S_SYN_RECEIVED;

	if (sc->sc_request_r_scale != 15) {
		t6p->requested_s_scale = sc->sc_requested_s_scale;
		t6p->request_r_scale = sc->sc_request_r_scale;
		t6p->snd_scale = sc->sc_requested_s_scale;
		t6p->rcv_scale = sc->sc_request_r_scale;
	} else
		t6p->t_flags &= ~TF_USE_SCALE;
	if (!sc->sc_tstmp)
		t6p->t_flags &= ~TF_SEND_TSTMP;

	in6p->in6p_hash = IN6_HASH(&sc->sc_src, sc->sc_sport,
	    &sc->sc_dst, sc->sc_dport);
	LIST_INSERT_HEAD(&tcp6_conn_hash[in6p->in6p_hash %
	    tcp6_conn_hash_size], in6p, in6p_hlist);
	t6p->t_template = tcp6_template(t6p);
	if (t6p->t_template == 0) {
		t6p = tcp6_drop(t6p, ENOBUFS);
		so = (struct socket *)(-1);
		m_freem(m);
		tcp6stat.tcp6s_sc_aborted++;
		goto done;
	}
	t6p->iss = sc->sc_iss;
	t6p->irs = sc->sc_irs;
	tcp6_sendseqinit(t6p);
	tcp6_rcvseqinit(t6p);
	t6p->t_timer[TCP6T_KEEP] = tcp6_conntimeo;
	tcp6stat.tcp6s_accepts++;
	(void) tcp6_peer_mss(t6p, sc->sc_peermaxseg);
	tcp6_maxseg_init(t6p);
	t6p->snd_wl1 = sc->sc_irs;
	t6p->rcv_up = sc->sc_irs + 1;

	/*
	 * This is what whould have happened in tcp6_ouput() when
	 * the SYN,ACK was sent.
	 */
	t6p->snd_up = t6p->snd_una;
	t6p->snd_max = t6p->snd_nxt = t6p->iss+1;
	t6p->t_timer[TCP6T_REXMT] = t6p->t_rxtcur;
	if (win > 0 && SEQ_GT(t6p->rcv_nxt+win, t6p->rcv_adv))
		t6p->rcv_adv = t6p->rcv_nxt + win;
	t6p->last_ack_sent = t6p->rcv_nxt;

	tcp6stat.tcp6s_sc_completed++;
done:
	FREE(sc, M_PCB);
	return (so);
}

/*
 * This function is called when we get a RST for a
 * non-existant connection, so that we can see if the
 * connection is in the syn cache.  If it is, zap it.
 */

void
syn_cache_reset6(ip6, th)
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
{
	struct syn_cache6 *sc, **sc_prev;
	struct syn_cache_head6 *head;

	if ((sc = syn_cache_lookup6(ip6, th, &sc_prev, &head)) == NULL)
		return;
	if (SEQ_LT(th->th_seq, sc->sc_irs) ||
	    SEQ_GT(th->th_seq, sc->sc_irs + 1))
		return;
	SYN_CACHE_RM6(sc, sc_prev, head);
	tcp6stat.tcp6s_sc_reset++;
	FREE(sc, M_PCB);
}

void
syn_cache_unreach6(ip6, th)
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
{
	struct syn_cache6 *sc, **sc_prev;
	struct syn_cache_head6 *head;
	struct ip6_hdr ip62;
	struct tcp6hdr th2;

	ip62.ip6_dst = ip6->ip6_src;
	ip62.ip6_src = ip6->ip6_dst;	
	th2.th_sport = th->th_dport;
	th2.th_dport = th->th_sport;	

	if ((sc = syn_cache_lookup6(&ip62, &th2, &sc_prev, &head)) == NULL)
		return;
	/* If the sequence number != sc_iss, then it's a bogus ICMP msg */
	if (ntohl(th->th_seq) != sc->sc_iss)
		return;
	SYN_CACHE_RM6(sc, sc_prev, head);
	tcp6stat.tcp6s_sc_unreach++;
	FREE(sc, M_PCB);
}

/*
 * Given a LISTEN socket and an inbound SYN request, add
 * this to the syn cache, and send back a SYN,ACK to the
 * source.
 */

int
syn_cache_add6(so, m, off, optp, optlen, oi)
	struct socket *so;
	struct mbuf *m;
	int off;
	u_char *optp;
	int optlen;
	struct tcp6_opt_info *oi;
{
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
	struct tcp6cb tb;
	long win;
	struct syn_cache6 *sc, **sc_prev;
	struct syn_cache_head6 *scp;

	if (tcp6_syn_cache_limit == 0)		/* see if it is disabled */
		return (0);

	ip6 = mtod(m, struct ip6_hdr *);
	th = (struct tcp6hdr *)((caddr_t)ip6 + off);

	if (m->m_flags & (M_BCAST|M_MCAST|M_ANYCAST6) ||
	    IN6_IS_ADDR_MULTICAST(&ip6->ip6_src) ||
	    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
		return (0);

	/*
	 * Initialize some local state.
	 */
	win = sbspace(&so->so_rcv);
	if (win > TCP6_MAXWIN)
		win = TCP6_MAXWIN;

	if (optp) {
		tb.t_flags = TF_SEND_TSTMP|TF_USE_SCALE;
		tcp6_dooptions(&tb, optp, optlen, th, oi);
	} else
		tb.t_flags = 0;

	/*
	 * See if we already have an entry for this connection.
	 */
	if ((sc = syn_cache_lookup6(ip6, th, &sc_prev, &scp)) != NULL) {
		tcp6stat.tcp6s_sc_dupesyn++;
		if (syn_cache_respond6(sc, m, ip6, th, win, tb.ts_recent) == 0) {
			tcp6stat.tcp6s_sndacks++;
			tcp6stat.tcp6s_sndtotal++;
		}
		return (1);
	}

	MALLOC(sc, struct syn_cache6 *, sizeof(*sc), M_PCB, M_NOWAIT);
	if (sc == NULL)
		return (0);
	/*
	 * Fill in the cache, and put the necessary TCP6
	 * options into the reply.
	 */
	sc->sc_src = ip6->ip6_src;
	sc->sc_dst = ip6->ip6_dst;
	sc->sc_sport = th->th_sport;
	sc->sc_dport = th->th_dport;
	sc->sc_irs = th->th_seq;
	sc->sc_iss = tcp6_iss;
	tcp6_iss += TCP6_ISSINCR/4;
	sc->sc_peermaxseg = oi->maxseg;
	sc->sc_tstmp = (tb.t_flags & TF_SEND_TSTMP) ? 1 : 0;
	if (tb.t_flags & TF_USE_SCALE) {
		sc->sc_requested_s_scale = tb.requested_s_scale;
		sc->sc_request_r_scale = 0;
		while (sc->sc_request_r_scale < TCP6_MAX_WINSHIFT &&
		    TCP6_MAXWIN << sc->sc_request_r_scale <
		    so->so_rcv.sb_hiwat)
			sc->sc_request_r_scale++;
	} else {
		sc->sc_requested_s_scale = 15;
		sc->sc_request_r_scale = 15;
	}
	if (syn_cache_respond6(sc, m, ip6, th, win, tb.ts_recent) == 0) {
		syn_cache_insert6(sc, &sc_prev, &scp);
		tcp6stat.tcp6s_sndacks++;
		tcp6stat.tcp6s_sndtotal++;
	} else {
		FREE(sc, M_PCB);
		tcp6stat.tcp6s_sc_dropped++;
	}
	return (1);
}

int
syn_cache_respond6(sc, m, ip6, th, win, ts)
	struct syn_cache6 *sc;
	struct mbuf *m;
	struct ip6_hdr *ip6;
	register struct tcp6hdr *th;
	long win;
	u_long ts;
{
	u_char *optp;
	int optlen;
	u_short mss;

	mss = in6_maxmtu - sizeof(struct ip6_hdr) - sizeof(struct tcp6hdr);
	if (tcp6_43maxseg && !in6_localaddr(&ip6->ip6_dst))
		mss = min(mss, tcp6_mssdflt);

	/*
	 * Tack on the TCP6 options.  If there isn't enough trailing
	 * space for them, move up the fixed header to make space.
	 */
	optlen = 4 + (sc->sc_request_r_scale != 15 ? 4 : 0) +
	    (sc->sc_tstmp ? TCP6OLEN_TSTAMP_APPA : 0);
	if (optlen > M_TRAILINGSPACE(m)) {
		if (M_LEADINGSPACE(m) >= optlen) {
			m->m_data -= optlen;
			m->m_len += optlen;
		} else {
			struct mbuf *m0 = m;
			if ((m = m_gethdr(M_DONTWAIT, MT_HEADER)) == NULL) {
				m_freem(m0);
				return (ENOBUFS);
			}
			MH_ALIGN(m, sizeof(struct ip6_hdr)
				 + sizeof(struct tcp6hdr) + optlen);
			m->m_next = m0;	/* this gets freed below */
		}
		bcopy((caddr_t)ip6, mtod(m, caddr_t), sizeof(*ip6));
		ip6 = mtod(m, struct ip6_hdr *);
		bcopy((caddr_t)th, (caddr_t)(ip6 + 1), sizeof(*th));
		th = (struct tcp6hdr *)(ip6 + 1);
	}

	optp = (u_char *)(th + 1);
	*((u_long *)optp) = htonl(TCP6OPT_MAXSEG << 24 | 4 << 16 | mss);
	optlen = 4;
	if (sc->sc_request_r_scale != 15) {
		*((u_long *) (optp + optlen)) = htonl(
			TCP6OPT_NOP << 24 |
			TCP6OPT_WINDOW << 16 |
			TCP6OLEN_WINDOW << 8 |
			sc->sc_request_r_scale);
		optlen += 4;
	}
	if (sc->sc_tstmp) {
		u_long *lp = (u_long *)(optp + optlen);
		/* Form timestamp option as shown in appendix A of RFC 1323. */
		*lp++ = htonl(TCP6OPT_TSTAMP_HDR);
		*lp++ = htonl(tcp6_now);
		*lp   = htonl(ts);
		optlen += TCP6OLEN_TSTAMP_APPA;
	}
	/*
	 * Toss any trailing mbufs.  No need to worry about
	 * m_len and m_pkthdr.len, since tcp6_respond() will
	 * unconditionally set them.
	 */
	if (m->m_next) {
		m_freem(m->m_next);
		m->m_next = NULL;
	}

	/*
	 * Fill in the fields that tcp6_respond() will not touch, and
	 * then send the response.
	 */
	th->th_off = (sizeof (struct tcp6hdr) + optlen) >> 2;
	th->th_win = htons(win);
	return (tcp6_respond(NULL, ip6, th, m, sc->sc_irs + 1, sc->sc_iss,
	    TH_SYN|TH_ACK));
}
