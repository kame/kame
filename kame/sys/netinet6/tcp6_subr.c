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
 *	BSDI tcp_subr.c,v 2.11 1997/01/16 14:06:35 karels Exp
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
 *	@(#)tcp_subr.c	8.2 (Berkeley) 5/24/95
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#ifdef __NetBSD__	/*XXX*/
#include "opt_ipsec.h"
#endif
#endif

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#ifdef __NetBSD__
#include <sys/pool.h>
#endif
#include <sys/syslog.h>

#include <net/route.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet6/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/icmp6.h>
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#include <netinet6/ip6protosw.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

/* patchable/settable parameters for tcp6 */
#if 0
extern	int tcp6_mssdflt;
extern	int tcp6_rttdflt;
extern	int tcp6_do_rfc1323;
#endif

#ifndef __bsdi__
extern int ip_next_mtu __P((int, int));	/*XXX netinet/ip_icmp.c */
#endif

extern struct in6pcb *tcp6_last_in6pcb;

#ifdef __NetBSD__
static struct pool tcp6_template_pool;
#endif

/*
 * Tcp initialization
 */
void
tcp6_init()
{
#ifdef __NetBSD__
	pool_init(&tcp6_template_pool, sizeof(struct ip6tcp), 0, 0, 0,
		"tcp6tmpl", 0, NULL, NULL, M_MBUF);
#endif
	tcp6_iss = random();	/* wrong, but better than a constant */
	tcb6.in6p_next = tcb6.in6p_prev = &tcb6;
	if (max_protohdr < sizeof(struct ip6tcp)) /* xxx */
		max_protohdr = sizeof(struct ip6tcp); /* xxx */
	if (max_linkhdr + sizeof(struct ip6tcp) > MHLEN) /* xxx */
		panic("tcp6_init");
}

/*
 * Create template to be used to send tcp6 packets on a connection.
 * Call after host entry created, allocates an mbuf and fills
 * in a skeletal tcp6/ip6 header, minimizing the amount of work
 * necessary when the connection is used.
 */
struct ip6tcp *
tcp6_template(t6p)
	struct tcp6cb *t6p;
{
	register struct in6pcb *in6p = t6p->t_in6pcb;
	register struct ip6tcp *n;

	if ((n = t6p->t_template) == 0) {
#ifdef __NetBSD__
		n = pool_get(&tcp6_template_pool, PR_NOWAIT);
#else
		n = malloc(sizeof(*n), M_TEMP, M_NOWAIT);
#endif
		if (n == NULL)
			return (NULL);
	}
	n->i6t_i.ip6_flow = in6p->in6p_flowinfo & IPV6_FLOWINFO_MASK;
	if (ip6_auto_flowlabel) {
		n->i6t_i.ip6_flow &= ~IPV6_FLOWLABEL_MASK;
		n->i6t_i.ip6_flow |= 
			(htonl(ip6_flow_seq++) & IPV6_FLOWLABEL_MASK);
	}
	n->i6t_i.ip6_vfc = IPV6_VERSION;
	n->i6t_i.ip6_plen = htons(sizeof(struct tcp6hdr));
	n->i6t_i.ip6_nxt = IPPROTO_TCP;
	n->i6t_i.ip6_hlim = in6_selecthlim(in6p, in6p->in6p_route.ro_rt ?
					   in6p->in6p_route.ro_rt->rt_ifp :
					   NULL);
	n->i6t_i.ip6_src = in6p->in6p_laddr;
	n->i6t_i.ip6_dst = in6p->in6p_faddr;
	n->i6t_t.th_sport = in6p->in6p_lport;
	n->i6t_t.th_dport = in6p->in6p_fport;
	n->i6t_t.th_seq = 0;
	n->i6t_t.th_ack = 0;
	n->i6t_t.th_x2 = 0;
	n->i6t_t.th_off = 5;
	n->i6t_t.th_flags = 0;
	n->i6t_t.th_win = 0;
	n->i6t_t.th_sum = 0;
	n->i6t_t.th_urp = 0;
	return (n);
}

/*
 * Send a single message to the TCP6 at address specified by
 * the given TCP6/IP6 header.  If m == 0, then we make a copy
 * of the ip6/th and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP6
 * template for a connection t6p->t_template.  If flags are given
 * then we send a message back to the TCP6 which originated the
 * segment ti, and discard the mbuf containing it and any other
 * attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 */
int
tcp6_respond(t6p, ip6, th, m, ack, seq, flags)
	struct tcp6cb *t6p;
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
	struct mbuf *m;
	tcp6_seq ack, seq;
	int flags;
{
	struct ip6_hdr *nip6;
	struct tcp6hdr *nth;
	int tlen;
	int win = 0;
	struct route_in6 *ro = 0;
	struct in6pcb *in6p = NULL;
	struct ifnet *oifp = NULL;

	if (t6p) {
		win = sbspace(&t6p->t_in6pcb->in6p_socket->so_rcv);
		in6p = t6p->t_in6pcb;
		ro = &t6p->t_in6pcb->in6p_route;
		if (ro->ro_rt)
			oifp = ro->ro_rt->rt_ifp;
	}
	if (m == 0) {
		m = m_gethdr(M_DONTWAIT, MT_HEADER);
		if (m == NULL)
			return(ENOBUFS);
#ifdef TCP6_COMPAT_42
		tlen = 1;
#else
		tlen = 0;
#endif
		m->m_data += max_linkhdr;
		nip6 = mtod(m, struct ip6_hdr *);
		*nip6 = *ip6;
		nth = (struct tcp6hdr *)(nip6 + 1);
		*nth = *th;
		flags = TH_ACK;
	} else {
		m_freem(m->m_next);
		m->m_next = 0;
		m->m_data = (caddr_t)ip6;
		m->m_len = sizeof (struct ip6tcp);
		nip6 = ip6;
		nth = (struct tcp6hdr *)(nip6 + 1);
		tlen = 0;
#define xchg(a,b,type) { type t; t=a; a=b; b=t; }
		xchg(ip6->ip6_dst, ip6->ip6_src, struct in6_addr);
		if (th != nth) {
			/*
			 * this is the case if an extension header exists
			 * between the IPv6 header and the TCP header.
			 */
			nth->th_sport = th->th_sport;
			nth->th_dport = th->th_dport;
		}
		xchg(nth->th_dport, nth->th_sport, u_short);
#undef xchg
	}

	nth->th_seq = htonl(seq);
	nth->th_ack = htonl(ack);
	nth->th_x2 = 0;
	if ((flags & TH_SYN) == 0) {
		if (t6p)
			nth->th_win = htons((u_short) (win >> t6p->rcv_scale));
		else
			nth->th_win = htons((u_short)win);
		nth->th_off = sizeof (struct tcp6hdr) >> 2;
		tlen += sizeof (struct tcp6hdr);
	} else
		tlen += nth->th_off << 2;
	m->m_len = tlen + sizeof (struct ip6_hdr);
	m->m_pkthdr.len = tlen + sizeof (struct ip6_hdr);
	m->m_pkthdr.rcvif = (struct ifnet *) 0;
	nip6->ip6_plen = htons((u_short)tlen);
	nip6->ip6_nxt = IPPROTO_TCP;
	nip6->ip6_hlim = in6_selecthlim(in6p, oifp);
	nip6->ip6_flow &= ~IPV6_FLOWLABEL_MASK;
	if (ip6_auto_flowlabel)
		nip6->ip6_flow |= (htonl(ip6_flow_seq++) & IPV6_FLOWLABEL_MASK);
	nth->th_flags = flags;
	nth->th_urp = 0;
	nth->th_sum = 0;
	nth->th_sum = in6_cksum(m, IPPROTO_TCP, sizeof(struct ip6_hdr), tlen);
#ifdef IPSEC
	m->m_pkthdr.rcvif = t6p ? (struct ifnet *)t6p->t_in6pcb->in6p_socket
				: NULL;
#endif /*IPSEC*/
	return(ip6_output(m, NULL, ro, 0, NULL, NULL));
}

/*
 * Create a new TCP6 control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.
 */
struct tcp6cb *
tcp6_newtcp6cb(in6p)
	struct in6pcb *in6p;
{
	register struct tcp6cb *t6p;

	t6p = malloc(sizeof(*t6p), M_PCB, M_NOWAIT);
	if (t6p == NULL)
		return ((struct tcp6cb *)0);
	bzero((char *) t6p, sizeof(struct tcp6cb));
	t6p->seg_next = t6p->seg_prev = (struct ip6tcpreass *)t6p;
	t6p->t_maxseg = tcp6_mssdflt;
	t6p->t_peermaxseg = tcp6_mssdflt;

	t6p->t_flags = tcp6_do_rfc1323 ? (TF_USE_SCALE|TF_SEND_TSTMP) : 0;
	t6p->t_in6pcb = in6p;
	/*
	 * Init srtt to TCP6TV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 4 * rttvar gives
	 * reasonable initial retransmit time (tcp6_rttdflt seconds).
	 */
	t6p->t_srtt = TCP6TV_SRTTBASE;
	t6p->t_rttvar = tcp6_rttdflt * PR_SLOWHZ /* / 4 << 2 */;
	t6p->t_rttmin = TCP6TV_MIN;
	TCP6T_RANGESET(t6p->t_rxtcur, TCP6_REXMTVAL(t6p),
	    TCP6TV_MIN, TCP6TV_REXMTMAX);
	t6p->snd_cwnd = TCP6_MAXWIN << TCP6_MAX_WINSHIFT;
	t6p->snd_ssthresh = TCP6_MAXWIN << TCP6_MAX_WINSHIFT;
	in6p->in6p_ip6.ip6_hlim = in6_selecthlim(in6p,
						 in6p->in6p_route.ro_rt ?
						 in6p->in6p_route.ro_rt->rt_ifp
						 : NULL);
	in6p->in6p_ppcb = (caddr_t)t6p;
	return (t6p);
}

/*
 * Drop a TCP6 connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcp6cb *
tcp6_drop(t6p, errno)
	register struct tcp6cb *t6p;
	int errno;
{
	struct socket *so = t6p->t_in6pcb->in6p_socket;

	if (TCP6S_HAVERCVDSYN(t6p->t_state)) {
		t6p->t_state = TCP6S_CLOSED;
		(void) tcp6_output(t6p);
		tcp6stat.tcp6s_drops++;
	} else
		tcp6stat.tcp6s_conndrops++;
	if (errno == ETIMEDOUT && t6p->t_softerror)
		errno = t6p->t_softerror;
	so->so_error = errno;
	return (tcp6_close(t6p));
}

/*
 * Close a TCP6 control block:
 *	discard all space held by the tcp6
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcp6cb *
tcp6_close(t6p)
	register struct tcp6cb *t6p;
{
	register struct ip6tcpreass *t;
	struct in6pcb *in6p = t6p->t_in6pcb;
	struct socket *so = in6p->in6p_socket;
	register struct mbuf *m;
#ifdef RTV_RTT
	register struct rtentry *rt;

	/*
	 * If we sent enough data to get some meaningful characteristics,
	 * save them in the routing entry.  'Enough' is arbitrarily 
	 * defined as the sendpipesize (default 4K) * 16.  This would
	 * give us 16 rtt samples assuming we only get one sample per
	 * window (the usual case on a long haul net).  16 samples is
	 * enough for the srtt filter to converge to within 5% of the correct
	 * value; fewer samples and we could save a very bogus rtt.
	 *
	 * Don't update the default route's characteristics and don't
	 * update anything that the user "locked".
	 */
	if (SEQ_LT(t6p->iss + so->so_snd.sb_hiwat * 16, t6p->snd_max) &&
	    (rt = in6p->in6p_route.ro_rt) &&
	    (IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)rt_key(rt))->sin6_addr))){
		register u_long i = 0;

		if ((rt->rt_rmx.rmx_locks & RTV_RTT) == 0) {
			i = t6p->t_srtt *
			    (RTM_RTTUNIT / (PR_SLOWHZ * TCP6_RTT_SCALE));
			if (rt->rt_rmx.rmx_rtt && i)
				/*
				 * filter this update to half the old & half
				 * the new values, converting scale.
				 * See route.h and tcp6_var.h for a
				 * description of the scaling constants.
				 */
				rt->rt_rmx.rmx_rtt =
				    (rt->rt_rmx.rmx_rtt + i) / 2;
			else
				rt->rt_rmx.rmx_rtt = i;
		}
		if ((rt->rt_rmx.rmx_locks & RTV_RTTVAR) == 0) {
			i = t6p->t_rttvar *
			    (RTM_RTTUNIT / (PR_SLOWHZ * TCP6_RTTVAR_SCALE));
			if (rt->rt_rmx.rmx_rttvar && i)
				rt->rt_rmx.rmx_rttvar =
				    (rt->rt_rmx.rmx_rttvar + i) / 2;
			else
				rt->rt_rmx.rmx_rttvar = i;
		}
		/*
		 * update the pipelimit (ssthresh) if it has been updated
		 * already or if a pipesize was specified & the threshhold
		 * got below half the pipesize.  I.e., wait for bad news
		 * before we start updating, then update on both good
		 * and bad news.
		 */
		if (((rt->rt_rmx.rmx_locks & RTV_SSTHRESH) == 0 &&
		    (i = t6p->snd_ssthresh) && rt->rt_rmx.rmx_ssthresh) ||
		    (i < (rt->rt_rmx.rmx_sendpipe / 2))) {
			/*
			 * convert the limit from user data bytes to
			 * packets then to packet data bytes.
			 */
			i = (i + t6p->t_maxseg / 2) / t6p->t_maxseg;
			if (i < 2)
				i = 2;
			i *= (u_long)(t6p->t_maxseg + sizeof(struct ip6tcp));
			if (rt->rt_rmx.rmx_ssthresh)
				rt->rt_rmx.rmx_ssthresh =
				    (rt->rt_rmx.rmx_ssthresh + i) / 2;
			else
				rt->rt_rmx.rmx_ssthresh = i;
		}
	}
#endif /* RTV_RTT */
	/* free the reassembly queue, if any */
	t = t6p->seg_next;
	while (t != (struct ip6tcpreass *)t6p) {
		t = (struct ip6tcpreass *)t->i6tr_next;
		m = REASS_MBUF6((struct ip6tcpreass *)t->i6tr_prev);
		remque(t->i6tr_prev);
		m_freem(m);
	}
	if (t6p->t_template) {
#ifdef __NetBSD__
		pool_put(&tcp6_template_pool, t6p->t_template);
#else
		free(t6p->t_template, M_TEMP);
#endif
	}
	tcp6_delack_done(t6p);	/* just in case */
	if (t6p->t_state == TCP6S_TIME_WAIT)
		tcp6_cancel2msl(in6p, t6p);
	free(t6p, M_PCB);
	in6p->in6p_ppcb = 0;

	/*
	 * Flush any remaining data.  We might have data in the output queue
	 * if connection was reset, and the socket might not be closed
	 * for a while if user does not notice.
	 */
	sbdrop(&so->so_snd, (int)so->so_snd.sb_cc);
	soisdisconnected(so);

	/* clobber input pcb cache if we're closing the cached connection */
	if (in6p == tcp6_last_in6pcb)
		tcp6_last_in6pcb = &tcb6;
	if (in6p->in6p_hlist.le_prev)	/* XXX */
		LIST_REMOVE(in6p, in6p_hlist);
	in6_pcbdetach(in6p);
	tcp6stat.tcp6s_closed++;
	return ((struct tcp6cb *)0);
}

void
tcp6_drain()
{

}

/*
 * Notify a tcp6 user of an asynchronous error;
 * store error as soft error, but wake up user
 * (for now, won't do anything until can select for soft error).
 */
void
tcp6_notify(in6p, error)
	struct in6pcb *in6p;
	int error;
{
	register struct tcp6cb *t6p = (struct tcp6cb *)in6p->in6p_ppcb;
	register struct socket *so = in6p->in6p_socket;

	/*
	 * If we are hooked up, do not report errors directly,
	 * but record them as soft errors in case we time out.
	 * If connection hasn't completed, has retransmitted several times,
	 * and receives a second error, give up now.  This is better
	 * than waiting a long time to establish a connection that
	 * can never complete.
	 */
#if 0
	if (t6p->t_state == TCP6S_ESTABLISHED &&
	     (error == EHOSTUNREACH || error == ENETUNREACH ||
	      error == EHOSTDOWN)) {
		t6p->t_softerror = error;
		return;
	} else
#endif
	if (t6p->t_state < TCP6S_ESTABLISHED && t6p->t_rxtshift >= 3 &&
	    t6p->t_softerror)
		so->so_error = error;
	else 
		t6p->t_softerror = error;
	wakeup((caddr_t) &so->so_timeo);
	sorwakeup(so);
	sowwakeup(so);
}

void
tcp6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	register struct tcp6hdr *thp;
	struct tcp6hdr th;
	void (*notify) __P((struct in6pcb *, int)) = tcp6_notify;
	int nmatch;
	struct sockaddr_in6 sa6;
	struct mbuf *m;
	struct ip6_hdr *ip6;
	int off;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;
	if (cmd == PRC_QUENCH)
		notify = tcp6_quench;
	else if (cmd == PRC_MSGSIZE)
		notify = tcp6_mtudisc;
	else if (!PRC_IS_REDIRECT(cmd) &&
		 ((unsigned)cmd > PRC_NCMDS || inet6ctlerrmap[cmd] == 0))
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		struct ip6ctlparam *ip6cp = (struct ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
	} else {
		m = NULL;
		ip6 = NULL;
	}

	/* translate addresses into internal form */
	sa6 = *(struct sockaddr_in6 *)sa;
	if (IN6_IS_ADDR_LINKLOCAL(&sa6.sin6_addr))
		sa6.sin6_addr.s6_addr16[1] = htons(m->m_pkthdr.rcvif->if_index);
	if (ip6) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */
		struct ip6_hdr ip6_tmp;

		/* translate addresses into internal form */
		ip6_tmp = *ip6;
		if (IN6_IS_ADDR_LINKLOCAL(&ip6_tmp.ip6_src))
			ip6_tmp.ip6_src.s6_addr16[1] =
				htons(m->m_pkthdr.rcvif->if_index);
		if (IN6_IS_ADDR_LINKLOCAL(&ip6_tmp.ip6_dst))
			ip6_tmp.ip6_dst.s6_addr16[1] =
				htons(m->m_pkthdr.rcvif->if_index);

		if (m->m_len < off + sizeof(th)) {
			/*
			 * this should be rare case,
			 * so we compromise on this copy...
			 */
			m_copydata(m, off, sizeof(th), (caddr_t)&th);
			thp = &th;
		} else
			thp = (struct tcp6hdr *)(mtod(m, caddr_t) + off);
		nmatch = in6_pcbnotify(&tcb6, (struct sockaddr *)&sa6,
				       thp->th_dport, &ip6_tmp.ip6_src,
				       thp->th_sport, cmd, notify);
		if (nmatch == 0 && syn_cache_count6 &&
		    (inet6ctlerrmap[cmd] == EHOSTUNREACH ||
		     inet6ctlerrmap[cmd] == ENETUNREACH ||
		     inet6ctlerrmap[cmd] == EHOSTDOWN))
			syn_cache_unreach6(&ip6_tmp, thp);
	} else {
		(void) in6_pcbnotify(&tcb6, (struct sockaddr *)&sa6, 0,
				     &zeroin6_addr, 0, cmd, notify);
	}
}

/*
 * When a source quench is received, close congestion window
 * to one segment.  We will gradually open it again as we proceed.
 */
void
tcp6_quench(in6p, errno)
	struct in6pcb *in6p;
	int errno;
{
	struct tcp6cb *t6p = intotcp6cb(in6p);

	if (t6p)
		t6p->snd_cwnd = t6p->t_maxseg;
}

/*
 * When a Destination Unreachable/Fragmentation Needed and DF set
 * is received, this routine is called for every TCP6 connection that
 * has a problematic destination:
 *	If current route isn't route-to-host then purge it and get new route;
 *		icmp6_mtudisc() has already created a new route for us to use
 *	Change t_maxseg
 *	Retransmit dropped segment
 * Note that some of these connections might NOT need to retransmit;
 * we accept that there may be a few spurious retransmissions.
 */
void
tcp6_mtudisc(in6p, errno)
	struct in6pcb *in6p;
	int errno;
{
	struct tcp6cb *t6p = intotcp6cb(in6p);
	struct route_in6 *ro = &(in6p->in6p_route);
	int usable_mtu;

	if (t6p == NULL)
		return;

	/*
	 * Note that we only re-route if we already had a route;
	 * this should avoid creating a route if SO_DONTROUTE was set
	 */
	if (ro->ro_rt == NULL)
		return;

	/*
	 * Make sure we have a route-to-host for this destination.
	 */
	if ((ro->ro_rt->rt_flags & RTF_HOST) == 0) {
		in6_rtchange(in6p, 0);
#ifdef __FreeBSD__
		rtcalloc((struct route *)ro);
#else
		rtalloc((struct route *)ro);
#endif
		if (ro->ro_rt == NULL) {
			printf("tcp6_mtudisc: no new route?\n");
			tcp6_changemss(t6p, TCP6_MSS);
			return;
		}
		if ((ro->ro_rt->rt_flags & RTF_HOST) == 0) {
			printf("tcp6_mtudisc: new route not to host?\n");
			usable_mtu = ro->ro_rt->rt_ifp->if_mtu
					- sizeof(struct ip6tcp);
			tcp6_changemss(t6p, min(usable_mtu, TCP6_MSS));
			return;
		}
	}

	usable_mtu = ro->ro_rt->rt_rmx.rmx_mtu - sizeof(struct ip6tcp);
	tcp6_changemss(t6p, usable_mtu);

	/*
	 * If there is more than 1 segment of unacknowledged data,
	 * force a retransmission of the (probably) lost datagrams
	 */
	if (SEQ_GT(t6p->snd_una, t6p->snd_nxt + t6p->t_maxseg)) {
		t6p->snd_nxt = t6p->snd_una;
		(void) tcp6_output(t6p);
	}
}

/*
 * Called when the MSS should change to reflect a new MTU value.
 */
void
tcp6_changemss(t6p, usable_mtu)
	register struct tcp6cb *t6p;
	u_int usable_mtu;
{
	u_int win;
	int newmaxseg;

	newmaxseg = tcp6_maxseg(t6p, min(usable_mtu, t6p->t_peermaxseg));

	if (t6p->t_maxseg == newmaxseg)
		return;				/* no change */

	t6p->t_maxseg = newmaxseg;

	/*
	 * Readjust things that depend upon t_maxseg
	 * (code copied from tcp6_timer.c in the REXMT case)
	 */
	win = min(t6p->snd_wnd, t6p->snd_cwnd) / 2 / t6p->t_maxseg;
	if (win < 2)
		win = 2;
	t6p->snd_cwnd = t6p->t_maxseg;
	t6p->snd_ssthresh = win * t6p->t_maxseg;
	t6p->t_dupacks = 0;
}

/*
 * Check to see if our Path MTU information is out of date.
 * If so, try again to use a higher MTU and see if things have
 * improved.
 */

void
tcp6_agepathmtu(in6p, rt)
	struct in6pcb *in6p;
	register struct rtentry *rt;
{
	unsigned int usable_mtu;
	unsigned int rt_mtu = rt->rt_rmx.rmx_mtu;
	time_t expire_at;
#ifdef __bsdi__
	extern unsigned int mtu_table[];
	unsigned int *mtup;
#endif

#ifdef __bsdi__
	for (mtup = mtu_table; *mtup; mtup++) {
		if (mtup[1] <= rt_mtu)
			break;
	}
	usable_mtu = *mtup;
#else
	/* Find the next higher MTU plateau */
	usable_mtu = ip_next_mtu(rt_mtu, -1);
#endif

	/* Don't try an MTU greater than the if_mtu! */
	if (usable_mtu > rt->rt_ifp->if_mtu)
		usable_mtu = rt->rt_ifp->if_mtu;

	if (usable_mtu > rt_mtu) {
		expire_at = time.tv_sec + pmtu_probe;
		rt->rt_rmx.rmx_mtu = usable_mtu;

		usable_mtu -= sizeof(struct ip6tcp);
		tcp6_changemss(intotcp6cb(in6p), usable_mtu);
	} else {
		expire_at = time.tv_sec + pmtu_expire;
	}
	rt->rt_flags &= ~RTF_PROBEMTU;
	rt->rt_rmx.rmx_expire = expire_at;
}

#ifdef IPSEC
/* compute ESP/AH header size for TCP, including tunnel outer IP header. */
size_t
ipsec6_hdrsiz_tcp(t6p)
	struct tcp6cb *t6p;
{
	struct in6pcb *in6p;
	struct mbuf *m;
	size_t hdrsiz;

	if (!t6p || !t6p->t_template || !(in6p = t6p->t_in6pcb))
		return 0;
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (!m)
		return 0;
	m->m_pkthdr.len = m->m_len = sizeof(struct ip6tcp);
	bcopy(t6p->t_template, mtod(m, u_char *), sizeof(struct ip6tcp));

	hdrsiz = ipsec6_hdrsiz(m, IPSEC_DIR_OUTBOUND, in6p);	/* XXX dir !!*/

	m_free(m);
	return hdrsiz;
}
#endif /*IPSEC*/
