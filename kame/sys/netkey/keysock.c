/*	$NetBSD: keysock.c,v 1.31 2004/05/31 04:29:01 itojun Exp $	*/

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

#ifdef __FreeBSD__
#include "opt_ipsec.h"
#endif

/* This code has derived from sys/net/rtsock.c on FreeBSD 2.2.5 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#ifdef __FreeBSD__
#include <sys/lock.h>
#include <sys/sysctl.h>
#endif
#include <sys/mbuf.h>
#ifdef __FreeBSD__
#include <sys/malloc.h>
#include <sys/mutex.h>
#endif
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#ifdef __NetBSD__
#include <sys/proc.h>
#include <sys/queue.h>
#endif

#include <net/raw_cb.h>
#include <net/route.h>
#include <netinet/in.h>

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key.h>
#include <netkey/keysock.h>
#include <netkey/key_debug.h>

#include <machine/stdarg.h>

struct sockaddr key_dst = { 2, PF_KEY, };
struct sockaddr key_src = { 2, PF_KEY, };

struct pfkeystat pfkeystat;

static int key_sendup0(struct rawcb *, struct mbuf *, int, int);

#ifdef __FreeBSD__
static int key_receive(struct socket *, struct sockaddr **, struct uio *,
	struct mbuf **, struct mbuf **, int *);
#else
static int key_receive(struct socket *, struct mbuf **, struct uio *,
	struct mbuf **, struct mbuf **, int *);
#endif

static int
#ifdef __FreeBSD__
key_receive(struct socket *so, struct sockaddr **paddr, struct uio *uio,
	struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
#else
key_receive(struct socket *so, struct mbuf **paddr, struct uio *uio,
	struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
#endif
{
	struct rawcb *rp = sotorawcb(so);
	struct keycb *kp = (struct keycb *)rp;
	int error;

#ifndef __FreeBSD__
	error = (*kp->kp_receive)(so, paddr, uio, mp0, controlp, flagsp);
#else
	error = soreceive(so, paddr, uio, mp0, controlp, flagsp);
#endif
	if (kp->kp_queue &&
	    sbspace(&rp->rcb_socket->so_rcv) > kp->kp_queue->m_pkthdr.len)
		sorwakeup(so);

	return error;
}

#ifndef __FreeBSD__
/*
 * key_usrreq()
 * derived from net/rtsock.c:route_usrreq()
 */
int
#ifndef __NetBSD__
key_usrreq(struct socket *so, int req, struct mbuf *m, struct mbuf *nam,
	struct mbuf *control)
#else
key_usrreq(struct socket *so, int req, struct mbuf *m, struct mbuf *nam,
	struct mbuf *control, struct proc *p)
#endif /*__NetBSD__*/
{
	int error = 0;
	struct keycb *kp = (struct keycb *)sotorawcb(so);
	int s;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (req == PRU_ATTACH) {
		kp = (struct keycb *)malloc(sizeof(*kp), M_PCB, M_WAITOK);
		so->so_pcb = (caddr_t)kp;
		if (so->so_pcb)
			bzero(so->so_pcb, sizeof(*kp));
	}
	if (req == PRU_DETACH && kp) {
		int af = kp->kp_raw.rcb_proto.sp_protocol;
		struct mbuf *n;

		if (af == PF_KEY)
			key_cb.key_count--;
		key_cb.any_count--;

		key_freereg(so);

		while (kp->kp_queue) {
			n = kp->kp_queue->m_nextpkt;
			kp->kp_queue->m_nextpkt = NULL;
			m_freem(kp->kp_queue);
			kp->kp_queue = n;
		}
	}

#ifndef __NetBSD__
	error = raw_usrreq(so, req, m, nam, control);
#else
	error = raw_usrreq(so, req, m, nam, control, p);
#endif
	m = control = NULL;	/* reclaimed in raw_usrreq */
	kp = (struct keycb *)sotorawcb(so);
	if (req == PRU_ATTACH && kp) {
		int af = kp->kp_raw.rcb_proto.sp_protocol;
		if (error) {
			pfkeystat.sockerr++;
			free((caddr_t)kp, M_PCB);
			so->so_pcb = (caddr_t) 0;
			splx(s);
			return (error);
		}

		kp->kp_promisc = kp->kp_registered = 0;

		kp->kp_receive = so->so_receive;
		so->so_receive = key_receive;

		if (af == PF_KEY) /* XXX: AF_KEY */
			key_cb.key_count++;
		key_cb.any_count++;
		kp->kp_raw.rcb_laddr = &key_src;
		kp->kp_raw.rcb_faddr = &key_dst;
		soisconnected(so);
		so->so_options |= SO_USELOOPBACK;
	}
	splx(s);
	return (error);
}
#endif /* other than FreeBSD >= 3 */

/*
 * key_output()
 */
int
#if __STDC__
key_output(struct mbuf *m, ...)
#else
key_output(struct mbuf *m, va_alist)
#endif
{
	struct sadb_msg *msg;
	int len, error = 0;
	int s;
	struct socket *so;
	va_list ap;

	va_start(ap, m);
	so = va_arg(ap, struct socket *);
	va_end(ap);

	if (m == 0)
		panic("key_output: NULL pointer was passed.");

	pfkeystat.out_total++;
	pfkeystat.out_bytes += m->m_pkthdr.len;

	len = m->m_pkthdr.len;
	if (len < sizeof(struct sadb_msg)) {
		pfkeystat.out_tooshort++;
		error = EINVAL;
		goto end;
	}

	if (m->m_len < sizeof(struct sadb_msg)) {
		if ((m = m_pullup(m, sizeof(struct sadb_msg))) == 0) {
			pfkeystat.out_nomem++;
			error = ENOBUFS;
			goto end;
		}
	}

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("key_output: not M_PKTHDR ??");

	KEYDEBUG(KEYDEBUG_KEY_DUMP, kdebug_mbuf(m));

	msg = mtod(m, struct sadb_msg *);
	pfkeystat.out_msgtype[msg->sadb_msg_type]++;
	if (len != PFKEY_UNUNIT64(msg->sadb_msg_len)) {
		pfkeystat.out_invlen++;
		error = EINVAL;
		goto end;
	}

	/*XXX giant lock*/
#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	error = key_parse(m, so);
	m = NULL;
	splx(s);
end:
	if (m)
		m_freem(m);
	return error;
}

/*
 * send message to the socket.
 */
static int
key_sendup0(struct rawcb *rp, struct mbuf *m, int promisc, int canwait)
{
	struct keycb *kp = (struct keycb *)rp;
	struct mbuf *n;
	int error = 0;

	if (canwait) {
		if (kp->kp_queue) {
			for (n = kp->kp_queue; n && n->m_nextpkt;
			    n = n->m_nextpkt)
				;
			n->m_nextpkt = m;
			m = kp->kp_queue;
			kp->kp_queue = NULL;
		} else
			m->m_nextpkt = NULL;	/* just for safety */
	} else
		m->m_nextpkt = NULL;

	for (; m && error == 0; m = n) {
		n = m->m_nextpkt;

		if (promisc) {
			struct sadb_msg *pmsg;

			M_PREPEND(m, sizeof(struct sadb_msg), M_NOWAIT);
			if (m && m->m_len < sizeof(struct sadb_msg))
				m = m_pullup(m, sizeof(struct sadb_msg));
			if (!m) {
				pfkeystat.in_nomem++;
				error = ENOBUFS;
				goto recovery;
			}
			m->m_pkthdr.len += sizeof(*pmsg);

			pmsg = mtod(m, struct sadb_msg *);
			bzero(pmsg, sizeof(*pmsg));
			pmsg->sadb_msg_version = PF_KEY_V2;
			pmsg->sadb_msg_type = SADB_X_PROMISC;
			pmsg->sadb_msg_len = PFKEY_UNIT64(m->m_pkthdr.len);
			/* pid and seq? */

			pfkeystat.in_msgtype[pmsg->sadb_msg_type]++;
		}

		if (canwait &&
		    sbspace(&rp->rcb_socket->so_rcv) < m->m_pkthdr.len) {
			error = EAGAIN;
			goto recovery;
		}

		m->m_nextpkt = NULL;

		if (!sbappendaddr(&rp->rcb_socket->so_rcv,
		    (struct sockaddr *)&key_src, m, NULL)) {
			pfkeystat.in_nomem++;
			error = ENOBUFS;
			goto recovery;
		} else {
			sorwakeup(rp->rcb_socket);
			error = 0;
		}
	}
	return (error);

recovery:
	if (kp->kp_queue) {
		/*
		 * insert m to the head of queue, as normally mbuf on the queue
		 * is less important than others.
		 */
		if (m) {
			m->m_nextpkt = kp->kp_queue;
			kp->kp_queue = m;
		}
	} else {
		/* recover the queue */
		if (!m) {
			/* first ENOBUFS case */
			kp->kp_queue = n;
		} else {
			kp->kp_queue = m;
			m->m_nextpkt = n;
		}
	}
	return (error);
}

/* so can be NULL if target != KEY_SENDUP_ONE */
int
key_sendup_mbuf(struct socket *so, struct mbuf *m, int target)
{
	struct mbuf *n;
	struct keycb *kp;
	int sendup;
	struct rawcb *rp;
	int error = 0;
	int canwait;

	if (m == NULL)
		panic("key_sendup_mbuf: NULL pointer was passed.");
	if (so == NULL && target == KEY_SENDUP_ONE)
		panic("key_sendup_mbuf: NULL pointer was passed.");

	canwait = target & KEY_SENDUP_CANWAIT;
	target &= ~KEY_SENDUP_CANWAIT;

	pfkeystat.in_total++;
	pfkeystat.in_bytes += m->m_pkthdr.len;
	if (m->m_len < sizeof(struct sadb_msg)) {
		m = m_pullup(m, sizeof(struct sadb_msg));
		if (m == NULL) {
			pfkeystat.in_nomem++;
			return ENOBUFS;
		}
	}
	if (m->m_len >= sizeof(struct sadb_msg)) {
		struct sadb_msg *msg;
		msg = mtod(m, struct sadb_msg *);
		pfkeystat.in_msgtype[msg->sadb_msg_type]++;
	}

#ifdef __NetBSD__
	for (rp = rawcb.lh_first; rp; rp = rp->rcb_list.le_next)
#elif defined(__FreeBSD__)
	LIST_FOREACH(rp, &rawcb_list, list)
#else
	for (rp = rawcb.rcb_next; rp != &rawcb; rp = rp->rcb_next)
#endif
	{
		if (rp->rcb_proto.sp_family != PF_KEY)
			continue;
		if (rp->rcb_proto.sp_protocol &&
		    rp->rcb_proto.sp_protocol != PF_KEY_V2) {
			continue;
		}

		kp = (struct keycb *)rp;

		/*
		 * If you are in promiscuous mode, and when you get broadcasted
		 * reply, you'll get two PF_KEY messages.
		 * (based on pf_key@inner.net message on 14 Oct 1998)
		 */
		if (((struct keycb *)rp)->kp_promisc) {
			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				(void)key_sendup0(rp, n, 1, canwait);
				n = NULL;
			}
		}

		/* the exact target will be processed later */
		if (so && sotorawcb(so) == rp)
			continue;

		sendup = 0;
		switch (target) {
		case KEY_SENDUP_ONE:
			/* the statement has no effect */
			if (so && sotorawcb(so) == rp)
				sendup++;
			break;
		case KEY_SENDUP_ALL:
			sendup++;
			break;
		case KEY_SENDUP_REGISTERED:
			if (kp->kp_registered)
				sendup++;
			break;
		}
		pfkeystat.in_msgtarget[target]++;

		if (!sendup)
			continue;

		if ((n = m_copy(m, 0, (int)M_COPYALL)) == NULL) {
			m_freem(m);
			pfkeystat.in_nomem++;
			return ENOBUFS;
		}

		/*
		 * ignore error even if queue is full.  PF_KEY does not
		 * guarantee the delivery of the message.
		 * this is important when target == KEY_SENDUP_ALL.
		 */
		key_sendup0(rp, n, 0, canwait);

		n = NULL;
	}

	if (so) {
		error = key_sendup0(sotorawcb(so), m, 0, canwait);
		m = NULL;
	} else {
		error = 0;
		m_freem(m);
	}
	return error;
}

#ifdef __FreeBSD__
/*
 * key_abort()
 * derived from net/rtsock.c:rts_abort()
 */
static int
key_abort(struct socket *so)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_abort(so);
	splx(s);
	return error;
}

/*
 * key_attach()
 * derived from net/rtsock.c:rts_attach()
 */
static int
key_attach(struct socket *so, int proto, struct thread *p)
{
	struct keycb *kp;
	int s, error;

	if (sotorawcb(so) != 0)
		return EISCONN;	/* XXX panic? */
	kp = (struct keycb *)malloc(sizeof *kp, M_PCB, M_WAITOK); /* XXX */
	if (kp == 0)
		return ENOBUFS;
	bzero(kp, sizeof *kp);

	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications (like RTM_REDIRECT or RTM_LOSING) while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)kp;
	error = raw_usrreqs.pru_attach(so, proto, p);
	kp = (struct keycb *)sotorawcb(so);
	if (error) {
		free(kp, M_PCB);
		so->so_pcb = (caddr_t) 0;
		splx(s);
		return error;
	}

	kp->kp_promisc = kp->kp_registered = 0;

	if (kp->kp_raw.rcb_proto.sp_protocol == PF_KEY) /* XXX: AF_KEY */
		key_cb.key_count++;
	key_cb.any_count++;
	kp->kp_raw.rcb_laddr = &key_src;
	kp->kp_raw.rcb_faddr = &key_dst;
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;

	splx(s);
	return 0;
}

/*
 * key_bind()
 * derived from net/rtsock.c:rts_bind()
 */
static int
key_bind(struct socket *so, struct sockaddr *nam, struct thread *p)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_bind(so, nam, p); /* xxx just EINVAL */
	splx(s);
	return error;
}

/*
 * key_connect()
 * derived from net/rtsock.c:rts_connect()
 */
static int
key_connect(struct socket *so, struct sockaddr *nam, struct thread *p)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_connect(so, nam, p); /* XXX just EINVAL */
	splx(s);
	return error;
}

/*
 * key_detach()
 * derived from net/rtsock.c:rts_detach()
 */
static int
key_detach(struct socket *so)
{
	struct keycb *kp = (struct keycb *)sotorawcb(so);
	struct mbuf *n;
	int s, error;

	s = splnet();
	if (kp != 0) {
		if (kp->kp_raw.rcb_proto.sp_protocol == PF_KEY)
			key_cb.key_count--;
		key_cb.any_count--;

		key_freereg(so);

		while (kp->kp_queue) {
			n = kp->kp_queue->m_nextpkt;
			kp->kp_queue->m_nextpkt = NULL;
			m_freem(kp->kp_queue);
			kp->kp_queue = n;
		}
	}
	error = raw_usrreqs.pru_detach(so);
	splx(s);
	return error;
}

/*
 * key_disconnect()
 * derived from net/rtsock.c:key_disconnect()
 */
static int
key_disconnect(struct socket *so)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_disconnect(so);
	splx(s);
	return error;
}

/*
 * key_peeraddr()
 * derived from net/rtsock.c:rts_peeraddr()
 */
static int
key_peeraddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_peeraddr(so, nam);
	splx(s);
	return error;
}

/*
 * key_send()
 * derived from net/rtsock.c:rts_send()
 */
static int
key_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	struct mbuf *control, struct thread *p)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_send(so, flags, m, nam, control, p);
	splx(s);
	return error;
}

/*
 * key_shutdown()
 * derived from net/rtsock.c:rts_shutdown()
 */
static int
key_shutdown(struct socket *so)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_shutdown(so);
	splx(s);
	return error;
}

/*
 * key_sockaddr()
 * derived from net/rtsock.c:rts_sockaddr()
 */
static int
key_sockaddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;

	s = splnet();
	error = raw_usrreqs.pru_sockaddr(so, nam);
	splx(s);
	return error;
}

struct pr_usrreqs key_usrreqs = {
	key_abort, pru_accept_notsupp,
	key_attach,
	key_bind,
	key_connect,
	pru_connect2_notsupp, pru_control_notsupp, key_detach,
	key_disconnect, pru_listen_notsupp, key_peeraddr,
	pru_rcvd_notsupp,
	pru_rcvoob_notsupp, key_send, pru_sense_null, key_shutdown,
	key_sockaddr, sosend, key_receive, sopoll
};
#endif /* __FreeBSD__ >= 3 */

#ifdef __FreeBSD__
/* sysctl */
SYSCTL_NODE(_net, PF_KEY, key, CTLFLAG_RW, 0, "Key Family");
#endif

/*
 * Definitions of protocols supported in the KEY domain.
 */

extern struct domain keydomain;

struct protosw keysw[] = {
{ SOCK_RAW,	&keydomain,	PF_KEY_V2,	PR_ATOMIC|PR_ADDR,
  0,		
#ifdef __FreeBSD__
  (pr_output_t *)key_output,
#else
  key_output,
#endif
  raw_ctlinput,	0,
#ifdef __FreeBSD__
  0,
#else
  key_usrreq,
#endif
  raw_init,	0,		0,		0,
#ifdef __NetBSD__
  0,
#elif defined(__FreeBSD__)
  &key_usrreqs
#endif
}
};

struct domain keydomain =
    { PF_KEY, "key", key_init, 0, 0,
      keysw, &keysw[sizeof(keysw)/sizeof(keysw[0])] };

#ifdef __FreeBSD__
DOMAIN_SET(key);
#endif
