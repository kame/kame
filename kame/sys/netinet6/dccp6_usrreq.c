/*	$KAME: dccp6_usrreq.c,v 1.7 2004/10/28 04:33:26 itojun Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.
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

#define DCCP_DEBUG_ON

#ifndef __OpenBSD__
#include "opt_inet.h"
#include "opt_dccp.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#ifdef __NetBSD__
#include <sys/pool.h>
#endif
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
#include <sys/sx.h>
#endif
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/queue.h>

#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
#include <vm/uma.h>
#else
#include <vm/vm_zone.h>
#endif
#endif

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_var.h>
#ifndef __OpenBSD__
#include <netinet6/in6_pcb.h>
#endif
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/dccp.h>
#include <netinet/dccp_var.h>
#include <netinet6/dccp6_var.h>
#include <netinet/dccp_cc_sw.h>

#ifdef __FreeBSD__
#include <machine/in_cksum.h>
#endif

#ifndef __FreeBSD__
#include <machine/stdarg.h>
#endif

#ifdef __OpenBSD__
#include <dev/rndvar.h>
#endif

#if !defined(__FreeBSD__) || __FreeBSD_version < 500000
#define	INP_INFO_LOCK_INIT(x,y)
#define	INP_INFO_WLOCK(x)
#define INP_INFO_WUNLOCK(x)
#define	INP_INFO_RLOCK(x)
#define INP_INFO_RUNLOCK(x)
#define	INP_LOCK(x)
#define INP_UNLOCK(x)
#endif

int
dccp6_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp;
	DCCP_DEBUG((LOG_INFO, "In dccp6_input!\n"));
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, *offp, sizeof(struct dccphdr), IPPROTO_DONE);
#endif

	dccp_input(m, *offp);
	return IPPROTO_DONE;
}

void
dccp6_ctlinput(int cmd, struct sockaddr *sa, void *d)
{
	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;
	
	/* FIX LATER */
}

int
#ifdef __FreeBSD__
#if __FreeBSD_version >= 500000
dccp6_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
#else
dccp6_bind(struct socket *so, struct sockaddr *nam, struct proc *td)
#endif
#else
dccp6_bind(struct socket *so, struct mbuf *m, struct proc *td)
#endif
{
#ifndef __NetBSD__
	struct inpcb *inp;
#else
	struct in6pcb *in6p;
#endif
#ifndef __FreeBSD__
	struct sockaddr *nam;
#endif
	int s, error;
	struct sockaddr_in6 *sin6p;

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_bind!\n"));
#ifdef __FreeBSD__
	s = splnet();
#else
	s = splsoftnet();
#endif
	INP_INFO_WLOCK(&dccpbinfo);
#ifndef __NetBSD__
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		DCCP_DEBUG((LOG_INFO, "dccp6_bind: inp == 0!\n"));
		splx(s);
		return EINVAL;
	}
#else
	in6p = sotoin6pcb(so);
	if (in6p == 0) {
		DCCP_DEBUG((LOG_INFO, "dccp6_bind: in6p == 0!\n"));
		splx(s);
		return EINVAL;
	}
#endif
	/* Do not bind to multicast addresses! */
#ifndef __FreeBSD__
	nam = mtod(m, struct sockaddr *);
#endif
	sin6p = (struct sockaddr_in6 *)nam;
	if (sin6p->sin6_family == AF_INET6 &&
	    IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr)) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		splx(s);
		return EAFNOSUPPORT;
	}
	INP_LOCK(inp);

#ifdef __FreeBSD__
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
#elif defined(__NetBSD__)
	in6todccpcb(in6p)->inp_vflag &= ~INP_IPV4;
	in6todccpcb(in6p)->inp_vflag |= INP_IPV6;
#else
	inp->inp_flags &= ~INP_IPV4;
	inp->inp_flags |= INP_IPV6;
#endif
	
#ifdef __FreeBSD__
	error = in6_pcbbind(inp, nam, td);
#elif __NetBSD__
	error = in6_pcbbind(in6p, m, td);
#else
	error = in6_pcbbind(inp, m);
#endif
	INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return error;
}

int
#ifdef __FreeBSD__
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp6_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
#else
dccp6_connect(struct socket *so, struct sockaddr *nam, struct proc *td)
#endif
#else
dccp6_connect(struct socket *so, struct mbuf *m, struct proc *td)
#endif
{
#ifndef __NetBSD__
	struct inpcb *inp;
#else
	struct in6pcb *in6p;
#endif
	struct dccpcb *dp;
	int s, error;
	struct sockaddr_in6 *sin6;
#ifndef __FreeBSD__
	struct sockaddr *nam;
#endif
	char test[2];

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_connect!\n"));

#ifdef __FreeBSD__
	s = splnet();
#else
	s = splsoftnet();
#endif

#ifndef __NetBSD__
	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		return EINVAL;
	}
	INP_LOCK(inp);
	if (inp->inp_faddr.s_addr != INADDR_ANY) {
		INP_UNLOCK(inp);
		INP_INFO_WUNLOCK(&dccpbinfo);
		return EISCONN;
	}

	dp = (struct dccpcb *)inp->inp_ppcb;
#else
	in6p = sotoin6pcb(so);
	if (in6p == 0) {
		return EINVAL;
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
		return EISCONN;
	}

	dp = (struct dccpcb *)in6p->in6p_ppcb;
#endif
	if (dp->state == DCCPS_ESTAB) {
		DCCP_DEBUG((LOG_INFO, "Why are we in connect when we already have a established connection?\n"));
	}

	dp->who = DCCP_CLIENT;
	dp->seq_snd = arc4random() % 16777216;

#ifndef __FreeBSD__
	nam = mtod(m, struct sockaddr *);
#endif
	sin6 = (struct sockaddr_in6 *)nam;
	if (sin6->sin6_family == AF_INET6
	    && IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
		splx(s);
		error = EAFNOSUPPORT;
		goto bad;
	}

#ifdef __FreeBSD__
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	inp->inp_inc.inc_isipv6 = 1;
#elif defined(__OpenBSD__)
	inp->inp_flags &= ~INP_IPV4;
	inp->inp_flags |= INP_IPV6;
#else
	dp->inp_vflag &= ~INP_IPV4;
	dp->inp_vflag |= INP_IPV6;
#endif

#ifdef __FreeBSD__
	error = dccp_doconnect(so, nam, td, 1);
#else
	error = dccp_doconnect(so, m, td, 1);
#endif

	if (error != 0)
		goto bad;

#ifdef __OpenBSD__
	timeout_set(&dp->retrans_timer, dccp_retrans_t, dp);
	timeout_add(&dp->retrans_timer, dp->retrans);
	timeout_set(&dp->connect_timer, dccp_connect_t, dp);
	timeout_add(&dp->connect_timer, DCCP_CONNECT_TIMER);
#else
	callout_reset(&dp->retrans_timer, dp->retrans, dccp_retrans_t, dp);
	callout_reset(&dp->connect_timer, DCCP_CONNECT_TIMER, dccp_connect_t, dp);
#endif

	test[0] = dp->pref_cc;
	/* FIX THIS LATER */
	if (dp->pref_cc == 2) {
		test[1] = 3;
	} else {
		test[1] = 2;
	}
	dccp_add_feature(dp, DCCP_OPT_CHANGE, DCCP_FEATURE_CC, test, 2);
	dccp_add_feature(dp, DCCP_OPT_PREFER, DCCP_FEATURE_CC, test, 2);

	error = dccp_output(dp, 0);

bad:
	INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return error;
}


int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp6_listen(struct socket *so, struct thread *td)
#else
dccp6_listen(struct socket *so, struct proc *td)
#endif
{
#ifndef __NetBSD__
	struct inpcb *inp;
#else
	struct in6pcb *in6p;
#endif
	struct dccpcb *dp;
	int error = 0;
#ifdef __FreeBSD__
	int s = splnet();
#else
	int s = splsoftnet();
#endif

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_listen!\n"));

	INP_INFO_RLOCK(&dccpbinfo);
#ifndef __NetBSD__
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	dp = (struct dccpcb *)inp->inp_ppcb;
	DCCP_DEBUG((LOG_INFO, "Checking inp->inp_lport!\n"));
	if (inp->inp_lport == 0) {
#ifdef __OpenBSD__
		error = in6_pcbbind(inp, (struct mbuf *)0);
#else
		inp->inp_vflag &= ~INP_IPV4;
		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0)
			inp->inp_vflag |= INP_IPV4;
		error = in6_pcbbind(inp, (struct sockaddr *)0, td);
#endif
	}
#else
	in6p = sotoin6pcb(so);
	if (in6p == 0) {
		splx(s);
		return EINVAL;
	}
	dp = in6todccpcb(in6p);
	DCCP_DEBUG((LOG_INFO, "Checking in6p->in6p_lport!\n"));
	if (in6p->in6p_lport == 0) {
		error = in6_pcbbind(in6p, (struct mbuf *)0, td);
	}
#endif
	if (error == 0) {
		dp->state = DCCPS_LISTEN;
		dp->who = DCCP_LISTENER;
		dp->seq_snd = 512;
	}
	INP_UNLOCK(inp);
	splx(s);
	return error;
}

int
#ifdef __FreeBSD__
dccp6_accept(struct socket *so, struct sockaddr **nam)
#else
dccp6_accept(struct socket *so, struct mbuf *m)
#endif
{
#ifndef __NetBSD__
	struct inpcb *inp = NULL;
#else
	struct in6pcb *in6p = NULL;
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	struct in_addr	addr;
	struct in6_addr	addr6;
	in_port_t port = 0;
	int v4 = 0;
#endif
	int error = 0;
	int s;

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_accept!\n"));

	if (so->so_state & SS_ISDISCONNECTED) {
		DCCP_DEBUG((LOG_INFO, "so_state && SS_ISDISCONNECTED!, so->state = %i\n", so->so_state));
		return ECONNABORTED;
	}

#ifdef __FreeBSD__
	s = splnet();
#else
	s = splsoftnet();
#endif

	INP_INFO_RLOCK(&dccpbinfo);
#ifndef __NetBSD__
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}
#else
	in6p = sotoin6pcb(so);
	if (in6p == 0) {
		splx(s);
		return EINVAL;
	}
#endif
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
#ifdef __FreeBSD__
#if __FreeBSD_version >= 500000
	port = inp->inp_fport;

	if (inp->inp_vflag & INP_IPV4) {
		v4 = 1;
		addr = inp->inp_faddr;
	} else {
		addr6 = inp->in6p_faddr;
	}
#else
	in6_mapped_peeraddr(so, nam);
#endif
#elif defined(__NetBSD__)
	in6_setpeeraddr(in6p, m);
#else
	in6_setpeeraddr(inp, m);
#endif

	INP_UNLOCK(inp);
	splx(s);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	if (error == 0) {
		if (v4)
			*nam = in6_v4mapsin6_sockaddr(port, &addr);
		else
			*nam = in6_sockaddr(port, &addr6);
	}
#endif
	return error;
}


#ifdef __FreeBSD__
struct pr_usrreqs dccp6_usrreqs = {
	dccp_abort, dccp6_accept, dccp_attach, dccp6_bind, dccp6_connect, 
	pru_connect2_notsupp, in6_control, dccp_detach, dccp_disconnect, 
	dccp6_listen, in6_mapped_peeraddr, pru_rcvd_notsupp, 
	pru_rcvoob_notsupp, dccp_send, pru_sense_null, dccp_shutdown,
	in6_mapped_sockaddr, sosend, soreceive, sopoll
};
#endif

#ifndef __FreeBSD__
int
dccp6_usrreq(struct socket *so, int req, struct mbuf *m,
	     struct mbuf *nam, struct mbuf *control,
	     struct proc *p)
{
#ifdef __NetBSD__
	struct in6pcb *in6p = sotoin6pcb(so);
#else
	struct inpcb *in6p = sotoinpcb(so);
#endif
	int s;
	int error = 0;
	int family;

	family = so->so_proto->pr_domain->dom_family;

	if (req == PRU_CONTROL) {
		switch (family) {
		case PF_INET6:
			error = in6_control(so, (long)m, (caddr_t)nam,
			    (struct ifnet *)control, p);
			break;
		default:
			error =	 EAFNOSUPPORT;
		}
		return (error);
	}
#ifdef __NetBSD__
	if (req == PRU_PURGEIF) {
		struct ifnet *ifn = (struct ifnet *)control;
		switch (family) {
		case PF_INET6:
			in6_pcbpurgeif0(&dccpb6, ifn);
			in6_purgeif (ifn);
			in6_pcbpurgeif(&dccpb6, ifn);
			break;
		default:
			return (EAFNOSUPPORT);
		}
		return (0);
	}
#endif

	if (in6p == 0 && req != PRU_ATTACH)
	{
		error = EINVAL;
		goto release;
	}

	s = splsoftnet();

	switch (req) {
	case PRU_ATTACH:
		error = dccp_attach(so, family, p);
		break;

	case PRU_DETACH:
		error = dccp_detach(so);
		break;

	case PRU_BIND:
		if (!nam) {
			splx(s);
			return (EINVAL);
		}
		error  = dccp6_bind(so, nam, p);
		break;

	case PRU_LISTEN:
		error = dccp6_listen(so, p);
		break;

	case PRU_CONNECT:
		if (!nam) {
			splx(s);
			return (EINVAL);
		}
		error = dccp6_connect(so, nam, p);
		break;

	case PRU_DISCONNECT:
		error = dccp_disconnect(so);
		break;

	case PRU_ACCEPT:
		if (!nam) {
			splx(s);
			return (EINVAL);
		}
		error = dccp6_accept(so, nam);
		break;

	case PRU_SHUTDOWN:
		error = dccp_shutdown(so);
		break;

	case PRU_RCVD:
		error = EAFNOSUPPORT;
		break;

	case PRU_SEND:
		if (control && control->m_len) {
			m_freem(control);
			m_freem(m);
			error = EINVAL;
			break;
		}
		/* Flags are ignored */
		error = dccp_send(so, 0, m, nam, control, p);
		break;
	case PRU_ABORT:
		error = dccp_abort(so);
		break;

	case PRU_SENSE:
		error = 0;
		break;

	case PRU_RCVOOB:
	case PRU_SENDOOB:
		error = EAFNOSUPPORT;
		break;

	case PRU_PEERADDR:
		if (!nam) {
			splx(s);
			return (EINVAL);
		}
		in6_setpeeraddr(in6p, nam);
		break;

	case PRU_SOCKADDR:
		if (!nam) {
			splx(s);
			return (EINVAL);
		}
		in6_setsockaddr(in6p, nam);
		break;

	case PRU_SLOWTIMO:
		error = 0;
		break;

	default:
		panic("dccp6_usrreq");
	}

 release:
	splx(s);
	return (error);
}
#endif
