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

#include <netinet/ip6.h>
#ifdef INET6
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

static u_int32_t sctp_itag;		/* XXX should be more random */

void
sctp_init()
{
#ifndef __OpenBSD__
	struct timeval tv;
#endif

	pool_init(&sctpcb_pool, sizeof(struct sctpcb), 0, 0, 0, "sctpcbpl",
	    0, NULL, NULL, M_PCB);
	in_pcbinit(&scdbtable, scdbhashsize, scdbhashsize);

#ifndef __OpenBSD__
	microtime(&tv);
	sctp_itag = random() ^ tv.tv_usec;
#else
	sctp_itag = arc4random();
#endif
}

#ifdef INET6
int
sctp6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{

	sctp_input(*mp, *offp, proto);
	return IPPROTO_DONE;
}
#endif

void
#if __STDC__
sctp_input(struct mbuf *m, ...)
#else
sctp_input(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{
	va_list ap;
	int iphlen, proto;
	int af;
	struct ip *ip;
#ifdef INET6
	struct ip6_hdr *ip6;
#endif
	struct sctp_hdr *sctp;
	struct sctpcb *sp;
	struct inpcb *inp;
	struct sctp_chunk *chunk;

	va_start(ap, m);
	iphlen = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

#ifdef DIAGNOSTIC
	if (m->m_len < sizeof(*ip))
		panic("m_len too short");
#endif
	ip = mtod(m, struct ip *);
	ip6 = NULL;
	switch (ip->ip_v) {
	case 4:
		af = AF_INET;

		/* pedant */
		if (IN_MULTICAST(ip->ip_dst.s_addr))
			goto drop;
		break;
#ifdef INET6
	case 6:
		af = AF_INET6;
		ip = NULL;
#ifdef DIAGNOSTIC
		if (m->m_len < sizeof(*ip6))
			panic("m_len too short");
#endif
		ip6 = mtod(m, struct ip6_hdr *);
		break;
#endif
	default:
		/* EAFNOSUPPORT */
		goto drop;
	}

	/* drop if too short.  check it in a cheap way */
	if (m->m_pkthdr.len < iphlen + sizeof(*sctp) + sizeof(*chunk))
		goto drop;
	if (ip->ip_len < iphlen + sizeof(*sctp) + sizeof(*chunk))
		goto drop;
	if (ip->ip_len > m->m_pkthdr.len)
		goto drop;

	/* trim if the packet has trailing garbage */
	if (ip->ip_len > m->m_pkthdr.len)
		m_adj(m, ip->ip_len);

	IP6_EXTHDR_GET(sctp, struct sctp_hdr *, m, iphlen, sizeof(*sctp));
	if (sctp == NULL) {
		/* m is already freed */
		return;
	}
	IP6_EXTHDR_GET(chunk, struct sctp_chunk *, m, iphlen + sizeof(*sctp),
	    sizeof(*chunk));
	if (chunk == NULL) {
		/* m is already freed */
		return;
	}

	/*
	 * find a relevant pcb.  we lookup pcb before checksum, based on
	 * experience in netbsd tcp code (checksum is more expensive in
	 * many cases).
	 */
	inp = NULL;
	switch (af) {
	case AF_INET:
		inp = in_pcblookup_connect(&scdbtable, ip->ip_src,
		    sctp->sh_sport, ip->ip_dst, sctp->sh_dport);
		if (!inp)
			inp = in_pcblookup_bind(&scdbtable, ip->ip_dst,
			    sctp->sh_dport);
		break;
#ifdef INET6
	case AF_INET6:
#endif
	default:
		goto drop;
	}

	if (inp)
		sp = intosctpcb(inp);
	else
		sp = NULL;

	/* XXX test verification tag here */

	/* XXX checksum here */

	printf("got a sctp packet, sp=%p, chunk type=%u\n", sp, chunk->sc_type);

drop:
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
sctp_output(sp)
	struct sctpcb *sp;
{
	struct mbuf *m;
	int len;
	int hlen;
	int af = AF_INET;
	struct sctp_chunk_init *init;
	struct ip *ip;
#ifdef INET6
	struct ip6_hdr *ip6;
#endif
	struct sctp_hdr *sctp;
	struct inpcb *inp;
	u_int32_t vtag;

	inp = sp->sc_inpcb;

	switch (af) {
	case AF_INET:
		hlen = sizeof(struct ip);
		break;
#ifdef INET6
	case AF_INET6:
		hlen = sizeof(struct ip6_hdr);
		break;
#endif
	default:
		return EAFNOSUPPORT;
	}
	hlen += sizeof(struct sctp_hdr);

	switch (sp->sc_state) {
	case SCTPS_COOKIE_WAIT:	/*connection attempt*/
		len = sizeof(struct sctp_chunk_init);
		MGETHDR(m, M_DONTWAIT, MT_HEADER);
		if (m && max_linkhdr + hlen + len > MHLEN) {
			MCLGET(m, M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_free(m);
				m = NULL;
			}
		}
		if (!m)
			return ENOBUFS;
		m->m_len = 0;
		m->m_len = M_TRAILINGSPACE(m);
		m->m_data += (max_linkhdr + hlen);
		m->m_len -= (max_linkhdr + hlen);
		if (m->m_len < len) {
			m_free(m);
			return ENOBUFS;
		}
		m->m_len = len;
		m->m_pkthdr.len = len;

		init = mtod(m, struct sctp_chunk_init *);
		bzero(init, sizeof(*init));
		init->sc_init_chunk.sc_type = SCTP_INIT;
		init->sc_init_chunk.sc_len = htons(sizeof(init));
		init->sc_init_itag = sp->sc_litag;
		init->sc_init_arwnd = htonl(10);	/*XXX*/
		init->sc_init_ostream = htons(1);
		init->sc_init_istream = htons(1);
		init->sc_init_tsn = sp->sc_litag;	/*XXX*/
		vtag = htonl(0);
		break;
		
	default:
		return EINVAL;
	}

	/*
	 * attach IP header
	 */
	M_PREPEND(m, hlen, M_DONTWAIT);
	if (!m)
		return ENOBUFS;
	switch (af) {
	case AF_INET:
		ip = mtod(m, struct ip *);
		sctp = (struct sctp_hdr *)(ip + 1);
		bzero(ip, sizeof(*ip));
		bzero(sctp, sizeof(*sctp));
		ip->ip_src = inp->inp_laddr;
		ip->ip_dst = inp->inp_faddr;
		ip->ip_len = m->m_pkthdr.len;
		ip->ip_ttl = inp->inp_ip.ip_ttl; /* XXX */
		ip->ip_tos = inp->inp_ip.ip_tos; /* XXX */
		ip->ip_p = IPPROTO_SCTP;
		sctp->sh_sport = inp->inp_lport;
		sctp->sh_dport = inp->inp_fport;
		sctp->sh_vtag = vtag;
		break;

#ifdef INET6
	case AF_INET6:
		ip6 = mtod(m, struct ip6_hdr *);
		sctp = (struct sctp_hdr *)(ip6 + 1);
		m_freem(m);
		return 0;
#endif

	default:
		return EAFNOSUPPORT;
	}

	/* XXX sctp->sh_cksum */

#ifdef IPSEC
	if (ipsec_setsocket(m, inp->inp_socket) != 0) {
		m_freem(m);
		return ENOBUFS;
	}
#endif

	return ip_output(m, inp->inp_options, &inp->inp_route,
	    inp->inp_socket->so_options & (SO_DONTROUTE | SO_BROADCAST),
	    inp->inp_moptions);
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
		in_pcbpurgeif0(&scdbtable, (struct ifnet *)control);
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
#endif

	case PRU_CONNECT:
		if (inp->inp_lport == 0) {
			error = in_pcbbind(inp, (struct mbuf *)0,
			    (struct proc *)0);
			if (error)
				break;
		}
		error = in_pcbconnect(inp, nam);
		if (error)
			break;
		soisconnecting(so);
		/* XXX more initialization here */
		sp->sc_litag = sctp_itag++;
		sp->sc_state = SCTPS_COOKIE_WAIT;
		error = sctp_output(sp);
		break;

#if 0
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
