/*	$NetBSD$	*/

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
 *	@(#)udp_usrreq.c	8.6 (Berkeley) 5/23/95
 */

#include "opt_ipsec.h"
#include "opt_ipkdb.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/domain.h>
#include <sys/pool.h>

#include <vm/vm.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/sctp.h>
#include <netinet/sctp_var.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#endif

#ifdef PULLDOWN_TEST
#ifndef INET6
/* always need ip6.h for IP6_EXTHDR_GET */
#include <netinet/ip6.h>
#endif
#endif

#include "faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_faith.h>
#endif

#include <machine/stdarg.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /*IPSEC*/

static	void sctp_notify __P((struct inpcb *, int));

#ifndef SCDBHASHSIZE
#define	SCDBHASHSIZE	128
#endif
int	scdbhashsize = SCDBHASHSIZE;
struct pool sctpcb_pool;
struct inpcbtable scdbtable;

void
sctp_init()
{

	pool_init(&sctpcb_pool, sizeof(struct sctpcb), 0, 0, 0, "sctpcbpl",
	    0, NULL, NULL, M_PCB);
	in_pcbinit(&scdbtable, scdbhashsize, scdbhashsize);
}

void
#if __STDC__
sctp_input(struct mbuf *m, ...)
#else
sctp_input(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{

	m_freem(m);
}

static void
sctp_notify(inp, errno)
	struct inpcb *inp;
	int errno;
{

	inp->inp_socket->so_error = errno;
	sorwakeup(inp->inp_socket);
	sowwakeup(inp->inp_socket);
}

void *
sctp_ctlinput(cmd, sa, v)
	int cmd;
	struct sockaddr *sa;
	void *v;
{
	struct ip *ip = v;
	struct sctp_hdr *sctph;
	void (*notify) __P((struct inpcb *, int)) = sctp_notify;
	int errno;

	if (sa->sa_family != AF_INET
	 || sa->sa_len != sizeof(struct sockaddr_in))
		return NULL;
	if ((unsigned)cmd >= PRC_NCMDS)
		return NULL;
	errno = inetctlerrmap[cmd];
	if (PRC_IS_REDIRECT(cmd))
		notify = in_rtchange, ip = 0;
	else if (cmd == PRC_HOSTDEAD)
		ip = 0;
	else if (errno == 0)
		return NULL;
	if (ip) {
		sctph = (struct sctp_hdr *)((caddr_t)ip + (ip->ip_hl << 2));
		in_pcbnotify(&scdbtable, satosin(sa)->sin_addr, sctph->sh_dport,
		    ip->ip_src, sctph->sh_sport, errno, notify);

		/* XXX mapped address case */
	} else
		in_pcbnotifyall(&scdbtable, satosin(sa)->sin_addr, errno,
		    notify);
	return NULL;
}

int
#if __STDC__
sctp_output(struct mbuf *m, ...)
#else
sctp_output(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{

	m_freem(m);
	return 0;
}

int	sctp_sendspace = 9216;		/* really max datagram size */
int	sctp_recvspace = 40 * (1024 + sizeof(struct sockaddr_in));
					/* 40 1K datagrams */

struct sctpcb *
sctp_newsctpcb(family, aux)
	int family;
	void *aux;
{
	struct sctpcb *sp;

	switch (family) {
	case AF_INET:
		break;
	default:
		return NULL;	/*EAFNOSUPPORT*/
	}

	sp = pool_get(&sctpcb_pool, PR_NOWAIT);
	if (sp == NULL)
		return NULL;
	bzero(sp, sizeof(*sp));

	switch (family) {
	case AF_INET:
		sp->sc_inpcb = (struct inpcb *)aux;
		sp->sc_inpcb->inp_ip.ip_ttl = ip_defttl;
		sp->sc_inpcb->inp_ppcb = (caddr_t)sp;
		break;
	}
	return sp;
}

int
sctp_attach(so)
	struct socket *so;
{
	struct sctpcb *sp;
	struct inpcb *inp;
	int error;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, sctp_sendspace, sctp_recvspace);
		if (error)
			return error;
	}
	error = in_pcballoc(so, &scdbtable);
	if (error)
		return error;
	inp = sotoinpcb(so);
#ifdef IPSEC
	if (inp) {
		error = ipsec_init_policy(so, &inp->inp_sp);
		if (error != 0) {
			in_pcbdetach(inp);
			return error;
		}
	}
#endif /*IPSEC*/
	if (inp)
		sp = sctp_newsctpcb(AF_INET, (void *)inp);
	if (!sp) {
		int nofd = so->so_state & SS_NOFDREF;	/*XXX*/
		so->so_state &= ~SS_NOFDREF;
		if (inp)
			in_pcbdetach(inp);
		so->so_state |= nofd;
		return ENOBUFS;
	}
	sp->sc_state = SCTPS_CLOSED;
	return 0;
}

struct sctpcb *
sctp_close(sp)
	struct sctpcb *sp;
{
	struct socket *so;
	struct inpcb *inp;

	inp = sp->sc_inpcb;
	pool_put(&sctpcb_pool, sp);
	if (inp) {
		so = inp->inp_socket;
		inp->inp_ppcb = NULL;
		soisdisconnected(so);
		in_pcbdetach(inp);
	}
	return NULL;
}

/*ARGSUSED*/
int
sctp_usrreq(so, req, m, nam, control, p)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
{
	struct inpcb *inp = NULL;
	struct sctpcb *sp = NULL;
	int s;
	int error = 0;

	if (req == PRU_CONTROL)
		return (in_control(so, (long)m, (caddr_t)nam,
		    (struct ifnet *)control, p));

	if (req == PRU_PURGEIF) {
		in_purgeif((struct ifnet *)control);
		in_pcbpurgeif(&scdbtable, (struct ifnet *)control);
		return (0);
	}

	s = splsoftnet();
	inp = sotoinpcb(so);
	if (inp)
		sp = intosctpcb(inp);
#ifdef DIAGNOSTIC
	if (req != PRU_SEND && req != PRU_SENDOOB && control)
		panic("udp_usrreq: unexpected control mbuf");
#endif
	if (inp == 0 && req != PRU_ATTACH) {
		error = EINVAL;
		goto release;
	}

	/*
	 * Note: need to block udp_input while changing
	 * the udp pcb queue and/or pcb addresses.
	 */
	switch (req) {

	case PRU_ATTACH:
		if (inp != 0) {
			error = EISCONN;
			break;
		}
		error = sctp_attach(so);
		break;

	case PRU_DETACH:
		(void)sctp_close(sp);
		break;

	case PRU_BIND:
		error = in_pcbbind(inp, nam, p);
		break;

#if 0
	case PRU_LISTEN:
		error = EOPNOTSUPP;
		break;

	case PRU_CONNECT:
		error = in_pcbconnect(inp, nam);
		if (error)
			break;
		soisconnected(so);
		break;

	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	case PRU_DISCONNECT:
		/*soisdisconnected(so);*/
		so->so_state &= ~SS_ISCONNECTED;	/* XXX */
		in_pcbdisconnect(inp);
		inp->inp_laddr = zeroin_addr;		/* XXX */
		in_pcbstate(inp, INP_BOUND);		/* XXX */
		break;

	case PRU_SHUTDOWN:
		socantsendmore(so);
		break;

	case PRU_RCVD:
		error = EOPNOTSUPP;
		break;

	case PRU_SEND:
		if (control && control->m_len) {
			m_freem(control);
			m_freem(m);
			error = EINVAL;
			break;
		}
	{
		struct in_addr laddr;			/* XXX */

		if (nam) {
			laddr = inp->inp_laddr;		/* XXX */
			if ((so->so_state & SS_ISCONNECTED) != 0) {
				error = EISCONN;
				goto die;
			}
			error = in_pcbconnect(inp, nam);
			if (error) {
			die:
				m_freem(m);
				break;
			}
		} else {
			if ((so->so_state & SS_ISCONNECTED) == 0) {
				error = ENOTCONN;
				goto die;
			}
		}
		error = udp_output(m, inp);
		if (nam) {
			in_pcbdisconnect(inp);
			inp->inp_laddr = laddr;		/* XXX */
			in_pcbstate(inp, INP_BOUND);	/* XXX */
		}
	}
		break;

	case PRU_SENSE:
		/*
		 * stat: don't bother with a blocksize.
		 */
		splx(s);
		return (0);

	case PRU_RCVOOB:
		error =  EOPNOTSUPP;
		break;

	case PRU_SENDOOB:
		m_freem(control);
		m_freem(m);
		error =  EOPNOTSUPP;
		break;

	case PRU_SOCKADDR:
		in_setsockaddr(inp, nam);
		break;

	case PRU_PEERADDR:
		in_setpeeraddr(inp, nam);
		break;
#endif

	default:
		panic("sctp_usrreq");
	}

release:
	splx(s);
	return (error);
}
