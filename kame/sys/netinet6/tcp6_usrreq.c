/*	$KAME: tcp6_usrreq.c,v 1.12 2000/02/22 14:04:37 itojun Exp $	*/

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
 *	BSDI tcp_usrreq.c,v 2.15 1997/01/16 14:06:36 karels Exp
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1993, 1995
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
 *	@(#)tcp_usrreq.c	8.5 (Berkeley) 6/21/95
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#include <netinet6/tcp6_debug.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

/*
 * TCP6 protocol interface to socket abstraction.
 */
extern	char *tcp6states[];

/*
 * Process a TCP6 user request for TCP6 tb.  If this is a send request
 * then m is the mbuf chain of send data.  If this is a timer expiration
 * (called from the software clock routine), then timertype tells which timer.
 */
/*ARGSUSED*/
int
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
tcp6_usrreq(so, req, m, nam, control, p)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
#else
tcp6_usrreq(so, req, m, nam, control)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
#endif
{
	register struct in6pcb *in6p;
	register struct tcp6cb *t6p = (struct tcp6cb *)NULL;
	int s;
	int error = 0;
	int ostate;

	/* 
	 * Mapped addr support for PRU_CONTROL is not necessary.
	 * See comments at udp6_usrreq().
	 */
	if (req == PRU_CONTROL)
		return (in6_control(so, (u_long)m, (caddr_t)nam,
			(struct ifnet *)control
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
			, p
#endif
			));
	if (control && control->m_len) {
		m_freem(control);
		if (m && req != PRU_SENSE && req != PRU_RCVOOB)
			m_freem(m);
		return (EINVAL);
	}

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	in6p = sotoin6pcb(so);
	/*
	 * When a TCP6 is attached to a socket, then there will be
	 * a (struct in6pcb) pointed at by the socket, and this
	 * structure will point at a subsidary (struct tcp6cb).
	 */
	if (in6p == 0 && req != PRU_ATTACH) {
		splx(s);
		if (m && req != PRU_SENSE && req != PRU_RCVOOB)
			m_freem(m);
		return (ENOTCONN);
	}
	if (in6p) {
		t6p = intotcp6cb(in6p);
		/* WHAT IF T6P IS 0? */
#ifdef KPROF
		tcp6_acounts[t6p->t_state][req]++;
#endif
		ostate = t6p->t_state;
	} else
		ostate = 0;
	switch (req) {

	/*
	 * TCP6 attaches to socket via PRU_ATTACH, reserving space,
	 * and an internet control block.
	 */
	case PRU_ATTACH:
		/* 
		 * MAPPED_ADDR spec: always attach for v6, only when 
		 * necessary for v4 
		 */
		if (in6p) {
			error = EISCONN;
			break;
		}
		error = tcp6_attach(so);
		if (error)
			break;
		if ((so->so_options & SO_LINGER) && so->so_linger == 0)
			so->so_linger = TCP6_LINGERTIME;
		t6p = sototcp6cb(so);
		break;

	/*
	 * PRU_DETACH detaches the TCP6 protocol from the socket.
	 * If the protocol state is non-embryonic, then can't
	 * do this directly: have to initiate a PRU_DISCONNECT,
	 * which may finish later; embryonic TCB6's can just
	 * be discarded here.
	 */
	case PRU_DETACH:
		if (t6p->t_state > TCP6S_LISTEN)
			t6p = tcp6_disconnect(t6p);
		else
			t6p = tcp6_close(t6p);
		break;

	/*
	 * Give the socket an address.
	 */
	case PRU_BIND:
		error = in6_pcbbind(in6p, nam);
		if (error)
			break;
		break;

	/*
	 * Prepare to accept connections.
	 */
	case PRU_LISTEN:
		if (in6p->in6p_lport == 0)
			error = in6_pcbbind(in6p, (struct mbuf *)0);
		if (error == 0) {
			if (in6p->in6p_hlist.le_prev)	/* XXX */
				LIST_REMOVE(in6p, in6p_hlist);
			in6p->in6p_hash = in6p->in6p_lport;
			LIST_INSERT_HEAD(&tcp6_listen_hash[in6p->in6p_lport %
			    tcp6_listen_hash_size], in6p, in6p_hlist);
			t6p->t_state = TCP6S_LISTEN;
		}
		break;

	/*
	 * Initiate connection to peer.
	 * Create a template for use in transmissions on this connection.
	 * Enter SYN_SENT state, and mark socket as connecting.
	 * Start keep-alive timer, and seed output sequence space.
	 * Send initial segment on connection.
	 */
	case PRU_CONNECT:
		if (in6p->in6p_lport == 0) {
			error = in6_pcbbind(in6p, (struct mbuf *)0);
			if (error)
				break;
		}
		error = in6_pcbconnect(in6p, nam);
		if (error)
			break;
		if (in6p->in6p_hlist.le_prev)	/* XXX */
			LIST_REMOVE(in6p, in6p_hlist);
		in6p->in6p_hash = IN6_HASH(&in6p->in6p_faddr, in6p->in6p_fport,
		    &in6p->in6p_laddr, in6p->in6p_lport);
		LIST_INSERT_HEAD(&tcp6_conn_hash[in6p->in6p_hash %
		    tcp6_conn_hash_size], in6p, in6p_hlist);
		t6p->t_template = tcp6_template(t6p);
		if (t6p->t_template == 0) {
			in6_pcbdisconnect(in6p);
			error = ENOBUFS;
			break;
		}
		/* Compute window scaling to request.  */
		while (t6p->request_r_scale < TCP6_MAX_WINSHIFT &&
		    (TCP6_MAXWIN << t6p->request_r_scale) < so->so_rcv.sb_hiwat)
			t6p->request_r_scale++;
		soisconnecting(so);
		tcp6stat.tcp6s_connattempt++;
		t6p->t_state = TCP6S_SYN_SENT;
		t6p->t_timer[TCP6T_KEEP] = tcp6_conntimeo;
		t6p->iss = tcp6_iss; tcp6_iss += TCP6_ISSINCR/4;
		tcp6_sendseqinit(t6p);
		error = tcp6_output(t6p);
		break;

	/*
	 * Create a TCP6 connection between two sockets.
	 */
	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	/*
	 * Initiate disconnect from peer.
	 * If connection never passed embryonic stage, just drop;
	 * else if don't need to let data drain, then can just drop anyways,
	 * else have to begin TCP6 shutdown process: mark socket disconnecting,
	 * drain unread data, state switch to reflect user close, and
	 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
	 * when peer sends FIN and acks ours.
	 *
	 * SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC TCP6CB.
	 */
	case PRU_DISCONNECT:
		t6p = tcp6_disconnect(t6p);
		break;

	/*
	 * Accept a connection.  Essentially all the work is
	 * done at higher levels; just return the address
	 * of the peer, storing through addr.
	 */
	case PRU_ACCEPT:
		in6_setpeeraddr(in6p, nam);
		break;

	/*
	 * Mark the connection as being incapable of further output.
	 */
	case PRU_SHUTDOWN:
		socantsendmore(so);
		t6p = tcp6_usrclosed(t6p);
		if (t6p)
			error = tcp6_output(t6p);
		break;

	/*
	 * After a receive, possibly send window update to peer.
	 */
	case PRU_RCVD:
		/*
		 * soreceive() calls this function when a user receives
		 * ancillary data on a listening socket. We don't call
		 * tcp6_output in such a case, since there is no header
		 * template for a listening socket and hence the kernel
		 * will panic.
		 */
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) != 0)
			(void) tcp6_output(t6p);
		break;

	/*
	 * Do a send by putting data in output queue and updating urgent
	 * marker if URG set.  Possibly send more data.
	 */
	case PRU_SEND:
		sbappend(&so->so_snd, m);
		error = tcp6_output(t6p);
		break;

	/*
	 * Abort the TCP6.
	 */
	case PRU_ABORT:
		t6p = tcp6_drop(t6p, ECONNABORTED);
		break;

	case PRU_SENSE:
		((struct stat *) m)->st_blksize = so->so_snd.sb_hiwat;
		splx(s);
		return (0);

	case PRU_RCVOOB:
		if ((so->so_oobmark == 0 &&
		    (so->so_state & SS_RCVATMARK) == 0) ||
		    so->so_options & SO_OOBINLINE ||
		    t6p->t_oobflags & TCP6OOB_HADDATA) {
			error = EINVAL;
			break;
		}
		if ((t6p->t_oobflags & TCP6OOB_HAVEDATA) == 0) {
			error = EWOULDBLOCK;
			break;
		}
		m->m_len = 1;
		*mtod(m, caddr_t) = t6p->t_iobc;
		if (((int)nam & MSG_PEEK) == 0)
			t6p->t_oobflags ^= (TCP6OOB_HAVEDATA | TCP6OOB_HADDATA);
		break;

	case PRU_SENDOOB:
		if (sbspace(&so->so_snd) < -512) {
			m_freem(m);
			error = ENOBUFS;
			break;
		}
		/*
		 * According to RFC961 (Assigned Protocols) and RFC
		 * 1122 (Host Requirements), the urgent pointer points
		 * to the last octet of urgent data, not the first octet
		 * of non-urgent data.  However, internally we store the
		 * urgent pointer as the first byte of non-urgent data.
		 * If the user has specified TCP6_STDURG, then tcp6_output()
		 * will adjust the urgent offset that it fills into the
		 * packet to point to the last byte of urgent data, not
		 * the first byte of non-urgent data.
		 */
		sbappend(&so->so_snd, m);
		t6p->snd_up = t6p->snd_una + so->so_snd.sb_cc;
		t6p->t_force = 1;
		error = tcp6_output(t6p);
		t6p->t_force = 0;
		break;

	case PRU_SOCKADDR:
		in6_setsockaddr(in6p, nam);
		break;

	case PRU_PEERADDR:
		in6_setpeeraddr(in6p, nam);
		break;

	/*
	 * TCP6 slow timer went off; going through this
	 * routine for tracing's sake.
	 */
	case PRU_SLOWTIMO:
		/* not called in MAPPED ADDR case. */
		t6p = tcp6_timers(t6p, (int)nam);
		req |= (int)nam << 8;		/* for debug's sake */
		break;

	default:
		panic("tcp6_usrreq");
	}
	if (t6p && (so->so_options & SO_DEBUG))
		tcp6_trace(TA_USER, ostate, t6p, 0, 0, req);
	splx(s);
	return (error);
}

int
tcp6_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
	int error = 0, s;
	struct in6pcb *in6p;
	register struct tcp6cb *t6p;
	register struct mbuf *m;
	register int i;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	in6p = sotoin6pcb(so);
	if (in6p == NULL) {
		splx(s);
		if (op == PRCO_SETOPT && *mp)
			(void) m_free(*mp);
		return (ECONNRESET);
	}
	if (level != IPPROTO_TCP) {
		error = ip6_ctloutput(op, so, level, optname, mp);
		splx(s);
		return (error);
	}
	t6p = intotcp6cb(in6p);

	switch (op) {

	case PRCO_SETOPT:
		m = *mp;
		switch (optname) {

		case TCP6_NODELAY:
			if (m == NULL || m->m_len < sizeof (int))
				error = EINVAL;
			else if (*mtod(m, int *))
				t6p->t_flags |= TF_NODELAY;
			else
				t6p->t_flags &= ~TF_NODELAY;
			break;

		case TCP6_MAXSEG:
			if (m && (i = *mtod(m, int *)) > 0 && i <= t6p->t_maxseg)
				t6p->t_maxseg = i;
			else
				error = EINVAL;
			break;

		case TCP6_STDURG:
			if (m == NULL || m->m_len < sizeof (int))
				error = EINVAL;
			else if (*mtod(m, int *))
				t6p->t_flags |= TF_STDURG;
			else
				t6p->t_flags &= ~TF_STDURG;
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (m)
			(void) m_free(m);
		break;

	case PRCO_GETOPT:
		*mp = m = m_get(M_WAIT, MT_SOOPTS);
		m->m_len = sizeof(int);

		switch (optname) {
		case TCP6_NODELAY:
			*mtod(m, int *) = t6p->t_flags & TF_NODELAY;
			break;
		case TCP6_MAXSEG:
			*mtod(m, int *) = t6p->t_maxseg;
			break;
		case TCP6_STDURG:
			*mtod(m, int *) = t6p->t_flags & TF_STDURG;
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}
	splx(s);
	return (error);
}

/*
 * Attach TCP6 protocol to socket, allocating
 * internet protocol control block, tcp6 control block,
 * bufer space, and entering LISTEN state if to accept connections.
 */
int
tcp6_attach(so)
	struct socket *so;
{
	register struct tcp6cb *t6p;
	struct in6pcb *in6p;
	int error;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, (u_long)tcp6_sendspace,
		    (u_long)tcp6_recvspace);
		if (error)
			return (error);
	}
	error = in6_pcballoc(so, &tcb6);
	if (error)
		return (error);
	in6p = sotoin6pcb(so);
#ifdef IPSEC
	error = ipsec_init_policy(so, &in6p->in6p_sp);
	if (error != 0) {
		in6_pcbdetach(in6p);
		return (error);
	}
#endif /*IPSEC*/
	t6p = tcp6_newtcp6cb(in6p);
	if (t6p == 0) {
		int nofd = so->so_state & SS_NOFDREF;	/* XXX */

		so->so_state &= ~SS_NOFDREF;	/* don't free the socket yet */
		in6_pcbdetach(in6p);
		so->so_state |= nofd;
		return (ENOBUFS);
	}
	t6p->t_state = TCP6S_CLOSED;
	in6p->in6p_cksum = -1;	/* just to be sure */
	return (0);
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
struct tcp6cb *
tcp6_disconnect(t6p)
	register struct tcp6cb *t6p;
{
	struct socket *so = t6p->t_in6pcb->in6p_socket;

	if (t6p->t_state < TCP6S_ESTABLISHED)
		t6p = tcp6_close(t6p);
	else if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		t6p = tcp6_drop(t6p, 0);
	else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		t6p = tcp6_usrclosed(t6p);
		if (t6p)
			(void) tcp6_output(t6p);
	}
	return (t6p);
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
struct tcp6cb *
tcp6_usrclosed(t6p)
	register struct tcp6cb *t6p;
{

	switch (t6p->t_state) {

	case TCP6S_CLOSED:
	case TCP6S_LISTEN:
	case TCP6S_SYN_SENT:
		t6p->t_state = TCP6S_CLOSED;
		t6p = tcp6_close(t6p);
		break;

	case TCP6S_SYN_RECEIVED:
	case TCP6S_ESTABLISHED:
		t6p->t_state = TCP6S_FIN_WAIT_1;
		break;

	case TCP6S_CLOSE_WAIT:
		t6p->t_state = TCP6S_LAST_ACK;
		break;

	case TCP6S_FIN_WAIT_2:
		/*
		 * We can't receive any more data; start the timer
		 * so that if we don't get a FIN, we won't hang forever.
		 */
		if (t6p->t_timer[TCP6T_2MSL] == 0 &&
		    t6p->t_in6pcb->in6p_socket->so_state & SS_CANTRCVMORE)
			t6p->t_timer[TCP6T_2MSL] = tcp6_maxidle;
		break;
	}
	if (t6p && t6p->t_state >= TCP6S_FIN_WAIT_2)
		soisdisconnected(t6p->t_in6pcb->in6p_socket);
	return (t6p);
}

#ifdef __NetBSD__
#include <vm/vm.h>
#include <sys/sysctl.h>

int
tcp6_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{

	/* All sysctl names at this level are terminal. */
	if (namelen != 1)
		return ENOTDIR;

	switch (name[0]) {

	case TCP6CTL_MSSDFLT:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_mssdflt);
	case TCP6CTL_DO_RFC1323:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&tcp6_do_rfc1323);
	case TCP6CTL_KEEPIDLE:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_keepidle);
	case TCP6CTL_KEEPINTVL:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_keepintvl);
	case TCP6CTL_KEEPCNT:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_keepcnt);
	case TCP6CTL_MAXPERSISTIDLE:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&tcp6_maxpersistidle);
	case TCP6CTL_SENDSPACE:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_sendspace);
	case TCP6CTL_RECVSPACE:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_recvspace);
	case TCP6CTL_CONNTIMEO:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_conntimeo);
	case TCP6CTL_PMTU:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_pmtu);
	case TCP6CTL_PMTU_EXPIRE:
		return sysctl_int(oldp, oldlenp, newp, newlen, &pmtu_expire);
	case TCP6CTL_PMTU_PROBE:
		return sysctl_int(oldp, oldlenp, newp, newlen, &pmtu_probe);
	case TCP6CTL_43MAXSEG:
		return sysctl_int(oldp, oldlenp, newp, newlen, &tcp6_43maxseg);
	case TCP6CTL_STATS:
		return sysctl_rdstruct(oldp, oldlenp, newp,
				&tcp6stat, sizeof(tcp6stat));
	case TCP6CTL_SYN_CACHE_LIMIT:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&tcp6_syn_cache_limit);
	case TCP6CTL_SYN_BUCKET_LIMIT:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&tcp6_syn_bucket_limit);
	case TCP6CTL_SYN_CACHE_INTER:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&tcp6_syn_cache_interval);
	default:
		return ENOPROTOOPT;
	}
	/* NOTREACHED */
}
#endif /* __NetBSD__ */

#ifdef __bsdi__
int *tcp6_sysvars[] = TCP6CTL_VARS;

/*
 * Sysctl for tcp6 variables.
 */
tcp6_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	if (name[0] >= TCP6CTL_MAXID)
		return (EOPNOTSUPP);
	switch (name[0]) {
	case TCP6CTL_STATS:
		return sysctl_rdtrunc(oldp, oldlenp, newp, &tcp6stat,
		    sizeof(tcp6stat));

	default:
		return (sysctl_int_arr(tcp6_sysvars, name, namelen,
		    oldp, oldlenp, newp, newlen));
	}
}
#endif
