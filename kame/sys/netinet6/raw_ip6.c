/*	$KAME: raw_ip6.c,v 1.168 2007/06/14 12:09:44 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)raw_ip.c	8.2 (Berkeley) 1/4/94
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__	/* XXX */
#include "opt_ipsec.h"
#include "opt_mip6.h"
#endif

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#ifdef __NetBSD__
#include <sys/proc.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet/icmp6.h>
#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#else
#include <netinet6/in6_pcb.h>
#endif
#include <netinet6/nd6.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>
#include <netinet6/raw_ip6.h>

#ifdef MIP6
#include <netinet/ip6mh.h>
#endif /* MIP6 */

#ifdef __OpenBSD__
#undef IPSEC
#endif

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /* IPSEC */

#include <machine/stdarg.h>

#include "faith.h"
#if defined(NFAITH) && 0 < NFAITH
#include <net/if_faith.h>
#endif

#include <net/net_osdep.h>

#ifdef HAVE_NRL_INPCB
/* inpcb members */
#define in6pcb		inpcb
#define in6p_laddr	inp_laddr6
#define in6p_faddr	inp_faddr6
#define in6p_icmp6filt	inp_icmp6filt
#define in6p_route	inp_route6
#define in6p_socket	inp_socket
#define in6p_flags	inp_flags
#define in6p_moptions	inp_moptions6
#define in6p_outputopts	inp_outputopts6
#define in6p_ip6	inp_ipv6
#define in6p_flowinfo	inp_flowinfo
#define in6p_sp		inp_sp
#define in6p_next	inp_next
#define in6p_prev	inp_prev
/* macro names */
#define sotoin6pcb	sotoinpcb
/* function names */
#define in6_pcbdetach	in_pcbdetach
#define in6_rtchange	in_rtchange
#endif

#ifdef __OpenBSD__
struct	inpcbtable rawin6pcbtable;
#else
extern struct inpcbtable rawcbtable;
struct  inpcbtable raw6cbtable;
#endif
#define ifatoia6(ifa)	((struct in6_ifaddr *)(ifa))

/*
 * Raw interface to IP6 protocol.
 */

struct rip6stat rip6stat;

/*
 * Initialize raw connection block queue.
 */
void
rip6_init(void)
{

#ifdef __OpenBSD__
	in_pcbinit(&rawin6pcbtable, 1);
#else
	in6_pcbinit(&raw6cbtable, 1, 1);
#endif
}

/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
int
rip6_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp, *opts = NULL;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
#ifdef __NetBSD__
	struct inpcb_hdr *inph;
#endif
	struct in6pcb *in6p;
	struct in6pcb *last = NULL;
	struct sockaddr_in6 rip6src;

	rip6stat.rip6s_ipackets++;

	bzero(&rip6src, sizeof(rip6src));
	rip6src.sin6_family = AF_INET6;
	rip6src.sin6_len = sizeof(struct sockaddr_in6);
	rip6src.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&rip6src) != 0) {
		m_freem(m);
		return IPPROTO_DONE;
	}

#if defined(NFAITH) && 0 < NFAITH
	if (faithprefix(&ip6->ip6_dst)) {
		/* send icmp6 host unreach? */
		m_freem(m);
		return IPPROTO_DONE;
	}
#endif

	/* Be proactive about malicious use of IPv4 mapped address */
	if (IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst)) {
		/* XXX stat */
		m_freem(m);
		return IPPROTO_DONE;
	}

#ifdef __OpenBSD__
	for (in6p = rawin6pcbtable.inpt_queue.cqh_first;
	     in6p != (struct inpcb *)&rawin6pcbtable.inpt_queue;
	     in6p = in6p->inp_queue.cqe_next)
#else
        CIRCLEQ_FOREACH(inph, &raw6cbtable.inpt_queue, inph_queue)
#endif
	{
#ifdef __NetBSD__
                in6p = (struct in6pcb *)inph;
#endif

#ifdef HAVE_NRL_INPCB
		if (!(in6p->in6p_flags & INP_IPV6))
			continue;
#endif
		if (in6p->in6p_ip6.ip6_nxt &&
		    in6p->in6p_ip6.ip6_nxt != proto)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr) &&
		    !IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr, &ip6->ip6_src))
			continue;
		if (in6p->in6p_cksum != -1) {
			rip6stat.rip6s_isum++;
			if (in6_cksum(m, proto, *offp,
			    m->m_pkthdr.len - *offp)) {
				rip6stat.rip6s_badsum++;
				continue;
			}
		}
		if (last) {
			struct	mbuf *n;

#ifdef IPSEC
			/*
			 * Check AH/ESP integrity.
			 */
			if (ipsec6_in_reject(m, last)) {
				ipsec6stat.in_polvio++;
				/* do not inject data into pcb */
			} else
#endif /* IPSEC */
			if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL) {
				if (last->in6p_flags & IN6P_CONTROLOPTS)
					ip6_savecontrol(last, n, &opts);
				/* strip intermediate headers */
				m_adj(n, *offp);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
				    (struct sockaddr *)&rip6src, n, opts) == 0) {
					m_freem(n);
					if (opts)
						m_freem(opts);
					rip6stat.rip6s_fullsock++;
				} else
					sorwakeup(last->in6p_socket);
				opts = NULL;
			}
		}
		last = in6p;
	}
#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (last && ipsec6_in_reject(m, last)) {
		m_freem(m);
		ipsec6stat.in_polvio++;
		ip6stat.ip6s_delivered--;
		/* do not inject data into pcb */
	} else
#endif /* IPSEC */
	if (last) {
		if (last->in6p_flags & IN6P_CONTROLOPTS)
			ip6_savecontrol(last, m, &opts);
		/* strip intermediate headers */
		m_adj(m, *offp);
		if (sbappendaddr(&last->in6p_socket->so_rcv,
		    (struct sockaddr *)&rip6src, m, opts) == 0) {
			m_freem(m);
			if (opts)
				m_freem(opts);
			rip6stat.rip6s_fullsock++;
		} else
			sorwakeup(last->in6p_socket);
	} else {
		rip6stat.rip6s_nosock++;
		if (m->m_flags & M_MCAST)
			rip6stat.rip6s_nosockmcast++;
		if (proto == IPPROTO_NONE)
			m_freem(m);
		else {
			u_int8_t *prvnxtp = ip6_get_prevhdr(m, *offp); /* XXX */
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_protounknown);
			icmp6_error(m, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_NEXTHEADER,
			    prvnxtp - mtod(m, u_int8_t *));
		}
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}

void
rip6_ctlinput(int cmd, struct sockaddr *sa, void *d)
{
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int off;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	void *cmdarg;
	void (*notify)(struct in6pcb *, int) = in6_rtchange;
	int nxt;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd))
		notify = in6_rtchange, d = NULL;
	else if (cmd == PRC_HOSTDEAD)
		d = NULL;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	else if (cmd == PRC_MSGSIZE) {
		/* special code is present, see below */
		notify = in6_rtchange;
	}
#endif
	else if (inet6ctlerrmap[cmd] == 0)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
		cmdarg = ip6cp->ip6c_cmdarg;
		sa6_src = ip6cp->ip6c_src;
		nxt = ip6cp->ip6c_nxt;
	} else {
		m = NULL;
		ip6 = NULL;
		cmdarg = NULL;
		sa6_src = &sa6_any;
		nxt = -1;
	}

#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (ip6 && cmd == PRC_MSGSIZE) {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
		int valid = 0;
		struct in6pcb *in6p;

		/*
		 * Check to see if we have a valid raw IPv6 socket
		 * corresponding to the address in the ICMPv6 message
		 * payload, and the protocol (ip6_nxt) meets the socket.
		 * XXX chase extension headers, or pass final nxt value
		 * from icmp6_notify_error()
		 */
		in6p = NULL;
#ifdef __NetBSD__
		in6p = in6_pcblookup_connect(&raw6cbtable, &sa6->sin6_addr, 0,
		    (struct in6_addr *)&sa6_src->sin6_addr, 0, 0);
#elif defined(__OpenBSD__)
		in6p = in6_pcbhashlookup(&rawin6pcbtable, &sa6->sin6_addr, 0,
		    (struct in6_addr *)&sa6_src->sin6_addr, 0);
#endif
#if 0
		if (!in6p) {
			/*
			 * As the use of sendto(2) is fairly popular,
			 * we may want to allow non-connected pcb too.
			 * But it could be too weak against attacks...
			 * We should at least check if the local
			 * address (= s) is really ours.
			 */
#ifdef __NetBSD__
			in6p = in6_pcblookup_bind(&rawin6pcb, sa6, 0, 0);
#elif defined(__OpenBSD__)
			in6p = in_pcblookup(&rawin6pcbtable, sa6, 0,
			    sa6_src, 0, INPLOOKUP_WILDCARD | INPLOOKUP_IPV6);
#endif
		}
#endif /* 0 */

		if (in6p && in6p->in6p_ip6.ip6_nxt &&
		    in6p->in6p_ip6.ip6_nxt == nxt)
			valid++;

		/*
		 * Depending on the value of "valid" and routing table
		 * size (mtudisc_{hi,lo}wat), we will:
		 * - recalculate the new MTU and create the
		 *   corresponding routing entry, or
		 * - ignore the MTU change notification.
		 */
		icmp6_mtudisc_update((struct ip6ctlparam *)d,
		    (struct sockaddr_in6 *)sa, valid);

		/*
		 * regardless of if we called icmp6_mtudisc_update(),
		 * we need to call in6_pcbnotify(), to notify path
		 * MTU change to the userland (RFC 3542), because
		 * some unconnected sockets may share the same
		 * destination and want to know the path MTU.
		 */
	}
#endif

#ifdef __OpenBSD__
	(void) in6_pcbnotify(&rawin6pcbtable, sa, 0,
	    (struct sockaddr *)sa6_src, 0, cmd, cmdarg, notify);
#else
	(void) in6_pcbnotify(&raw6cbtable, sa, 0,
	    (struct sockaddr *)sa6_src, 0, cmd, cmdarg, notify);
#endif
}

/*
 * Generate IPv6 header and pass packet to ip6_output.
 * Tack on options user may have setup with control call.
 */
int
#if __STDC__
rip6_output(struct mbuf *m, ...)
#else
rip6_output(struct mbuf *m, va_alist)
#endif
{
	struct socket *so;
	struct sockaddr_in6 *dstsock;
	struct mbuf *control;
	struct ip6_hdr *ip6;
	struct in6pcb *in6p;
	u_int	plen = m->m_pkthdr.len;
	int error = 0, scope_ambiguous = 0;
	struct ip6_pktopts opt, *optp;
	struct ifnet *oifp = NULL;
	int type, code;		/* for ICMPv6 output statistics only */
	int priv = 0;
	va_list ap;
	struct in6_addr *in6;

	va_start(ap, m);
	so = va_arg(ap, struct socket *);
	dstsock = va_arg(ap, struct sockaddr_in6 *);
	control = va_arg(ap, struct mbuf *);
	va_end(ap);

	in6p = sotoin6pcb(so);
#ifdef __FreeBSD__
	INP_LOCK(in6p);
#endif

	priv = 0;
#if defined(__NetBSD__) || defined(__FreeBSD__)
    {
	struct proc *p = curproc;	/* XXX */

	if (p && !suser(p->p_ucred, &p->p_acflag))
		priv = 1;
    }
#else
	if ((so->so_state & SS_PRIV) != 0)
		priv = 1;
#endif

	if (control) {
		if ((error = ip6_setpktopts(control, &opt,
		    in6p->in6p_outputopts,
		    priv, so->so_proto->pr_protocol)) != 0) {
			goto bad;
		}
		optp = &opt;
	} else
		optp = in6p->in6p_outputopts;

	if (!(so->so_state & SS_ISCONNECTED)) {
		if (dstsock->sin6_scope_id == 0 && !ip6_use_defzone)
			scope_ambiguous = 1;
		if ((error = sa6_embedscope(dstsock, ip6_use_defzone)) != 0)
			goto bad;
	}

	/*
	 * For an ICMPv6 packet, we should know its type and code
	 * to update statistics.
	 */
	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icmp6;
		if (m->m_len < sizeof(struct icmp6_hdr) &&
		    (m = m_pullup(m, sizeof(struct icmp6_hdr))) == NULL) {
			error = ENOBUFS;
			goto bad;
		}
		icmp6 = mtod(m, struct icmp6_hdr *);
		type = icmp6->icmp6_type;
		code = icmp6->icmp6_code;
	} else {
		type = 0;
		code = 0;
	}

	M_PREPEND(m, sizeof(*ip6), M_DONTWAIT);
	if (!m) {
		error = ENOBUFS;
		goto bad;
	}
	ip6 = mtod(m, struct ip6_hdr *);

	/* Source address selection. */
	if ((in6 = in6_selectsrc(dstsock, optp,
	    in6p->in6p_moptions, &in6p->in6p_route, &in6p->in6p_laddr, &oifp,
	    &error)) == 0) {
		if (error == 0)
			error = EADDRNOTAVAIL;
		goto bad;
	}
	ip6->ip6_src = *in6;
	if (oifp && scope_ambiguous &&
	    (error = in6_setscope(&dstsock->sin6_addr, oifp, NULL))
	    != 0) {
		goto bad;
	}
	ip6->ip6_dst = dstsock->sin6_addr;

	/* fill in the rest of the IPv6 header fields */
	ip6->ip6_flow = in6p->in6p_flowinfo & IPV6_FLOWINFO_MASK;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
#if 0				/* ip6_plen will be filled in ip6_output. */
	ip6->ip6_plen = htons((u_int16_t)plen);
#endif
	ip6->ip6_nxt = in6p->in6p_ip6.ip6_nxt;
	ip6->ip6_hlim = in6_selecthlim(in6p, oifp);

	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6 ||
#ifdef MIP6
	    so->so_proto->pr_protocol == IPPROTO_MH ||
#endif /* MIP6 */
	    in6p->in6p_cksum != -1) {
		struct mbuf *n;
		int off;
		u_int16_t *sump;
		int sumoff;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member)) /* XXX */
#endif

		/* compute checksum */
		if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
			off = offsetof(struct icmp6_hdr, icmp6_cksum);
#ifdef MIP6
		else if (so->so_proto->pr_protocol == IPPROTO_MH)
			off = offsetof(struct ip6_mh, ip6mh_cksum);
#endif /* MIP6 */
		else
			off = in6p->in6p_cksum;
		if (plen < off + 1) {
			error = EINVAL;
			goto bad;
		}
		off += sizeof(struct ip6_hdr);

		n = m_pulldown(m, off, sizeof(*sump), &sumoff);
		if (n == NULL) {
			m = NULL;
			error = ENOBUFS;
			goto bad;
		}
		sump = (u_int16_t *)(mtod(n, caddr_t) + sumoff);
		*sump = 0;
		*sump = in6_cksum(m, ip6->ip6_nxt, sizeof(*ip6), plen);
	}

#ifdef IPSEC
	if (ipsec_setsocket(m, so) != 0) {
		error = ENOBUFS;
		goto bad;
	}
#endif /* IPSEC */

#ifdef __NetBSD__
	error = ip6_output(m, optp, &in6p->in6p_route, 0,
	    in6p->in6p_moptions, NULL, &oifp);
#else
	error = ip6_output(m, optp, &in6p->in6p_route, 0,
	    in6p->in6p_moptions, &oifp);
#endif
	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
		if (oifp)
			icmp6_ifoutstat_inc(oifp, type, code);
		icmp6stat.icp6s_outhist[type]++;
	} else
		rip6stat.rip6s_opackets++;

	goto freectl;

 bad:
	if (m)
		m_freem(m);

 freectl:
	if (control) {
		ip6_clearpktopts(&opt, -1);
		m_freem(control);
	}
#ifdef __FreeBSD__
	INP_UNLOCK(in6p);
#endif
	return (error);
}

/*
 * Raw IPv6 socket option processing.
 */
int
rip6_ctloutput(int op, struct socket *so, int level, int optname,
	struct mbuf **mp)
{
	int error = 0;

	switch (level) {
	case IPPROTO_IPV6:
		switch (optname) {
		case MRT6_INIT:
		case MRT6_DONE:
		case MRT6_ADD_MIF:
		case MRT6_DEL_MIF:
		case MRT6_ADD_MFC:
		case MRT6_DEL_MFC:
		case MRT6_PIM:
			if (op == PRCO_SETOPT) {
				error = ip6_mrouter_set(optname, so, *mp);
				if (*mp)
					(void)m_free(*mp);
			} else if (op == PRCO_GETOPT)
				error = ip6_mrouter_get(optname, so, mp);
			else
				error = EINVAL;
			return (error);
		case IPV6_CHECKSUM:
			return (ip6_raw_ctloutput(op, so, level, optname, mp));
		default:
			return (ip6_ctloutput(op, so, level, optname, mp));
		}

	case IPPROTO_ICMPV6:
		/*
		 * XXX: is it better to call icmp6_ctloutput() directly
		 * from protosw?
		 */
		return (icmp6_ctloutput(op, so, level, optname, mp));

	default:
		if (op == PRCO_SETOPT && *mp)
			m_free(*mp);
		return EINVAL;
	}
}

extern	u_long rip6_sendspace;
extern	u_long rip6_recvspace;

int
rip6_usrreq(struct socket *so, int req, struct mbuf *m, 
	struct mbuf *nam, struct mbuf *control, struct proc *p)
{
	struct in6pcb *in6p = sotoin6pcb(so);
	int s;
	int error = 0;
	int priv;

	priv = 0;
#if defined(__NetBSD__) || defined(__FreeBSD__)
	if (p && !suser(p->p_ucred, &p->p_acflag))
		priv++;
#else
	if ((so->so_state & SS_PRIV) != 0)
		priv++;
#endif

	if (req == PRU_CONTROL)
		return (in6_control(so, (u_long)m, (caddr_t)nam,
		    (struct ifnet *)control, p));

#ifdef __NetBSD__
	if (req == PRU_PURGEIF) {
		in6_pcbpurgeif0(&raw6cbtable, (struct ifnet *)control);
		in6_purgeif((struct ifnet *)control);
		in6_pcbpurgeif(&raw6cbtable, (struct ifnet *)control);
		return (0);
	}
#endif

	switch (req) {
	case PRU_ATTACH:
		if (in6p)
			panic("rip6_attach");
		if (!priv) {
			error = EACCES;
			break;
		}
#if defined(__NetBSD__) || defined(__OpenBSD__)
		s = splsoftnet();
#else
		s = splnet();
#endif
		if ((error = soreserve(so, rip6_sendspace, rip6_recvspace)) != 0) {
			splx(s);
			break;
		}
#ifdef __OpenBSD__
		if ((error = in_pcballoc(so, &rawin6pcbtable)) != 0)
#else
		if ((error = in6_pcballoc(so, &raw6cbtable)) != 0)
#endif
		{
			splx(s);
			break;
		}
		splx(s);
		in6p = sotoin6pcb(so);
		in6p->in6p_ip6.ip6_nxt = (long)nam;
		in6p->in6p_cksum = -1;

		MALLOC(in6p->in6p_icmp6filt, struct icmp6_filter *,
		    sizeof(struct icmp6_filter), M_PCB, M_NOWAIT);
		if (in6p->in6p_icmp6filt == NULL) {
			in6_pcbdetach(in6p);
			error = ENOMEM;
			break;
		}
		ICMP6_FILTER_SETPASSALL(in6p->in6p_icmp6filt);
		break;

	case PRU_DISCONNECT:
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			error = ENOTCONN;
			break;
		}
		in6p->in6p_faddr = in6addr_any;
		so->so_state &= ~SS_ISCONNECTED;	/* XXX */
		break;

	case PRU_ABORT:
		soisdisconnected(so);
		/* FALLTHROUGH */
	case PRU_DETACH:
		if (in6p == 0)
			panic("rip6_detach");
		if (so == ip6_mrouter)
			ip6_mrouter_done();
		/* xxx: RSVP */
		if (in6p->in6p_icmp6filt) {
			FREE(in6p->in6p_icmp6filt, M_PCB);
			in6p->in6p_icmp6filt = NULL;
		}
		in6_pcbdetach(in6p);
		break;

	case PRU_BIND:
	    {
		struct sockaddr_in6 *addr = mtod(nam, struct sockaddr_in6 *);
		struct ifaddr *ia = NULL;

		if (nam->m_len != sizeof(*addr)) {
			error = EINVAL;
			break;
		}
		if ((ifnet.tqh_first == 0) || (addr->sin6_family != AF_INET6)) {
			error = EADDRNOTAVAIL;
			break;
		}
		if ((error = sa6_embedscope(addr, ip6_use_defzone)) != 0)
			break;
#if defined(__NetBSD__) || defined(__OpenBSD__)
		/*
		 * we don't support mapped address here, it would confuse
		 * users so reject it
		 */
		if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr)) {
			error = EADDRNOTAVAIL;
			break;
		}
#endif
		if (IN6_IS_ADDR_UNSPECIFIED(&addr->sin6_addr) &&
		    (ia = ifa_ifwithaddr((struct sockaddr *)addr)) == 0) {
			error = EADDRNOTAVAIL;
			break;
		}
		if (ia && ((struct in6_ifaddr *)ia)->ia6_flags &
		    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|
		     IN6_IFF_DETACHED|IN6_IFF_DEPRECATED)) {
			error = EADDRNOTAVAIL;
			break;
		}
		in6p->in6p_laddr = in6addr_any;
		break;
	    }

	case PRU_CONNECT:
	{
		struct sockaddr_in6 *addr = mtod(nam, struct sockaddr_in6 *);
		struct in6_addr *src = NULL;
		struct sockaddr_in6 sin6;
		struct ifnet *ifp;
		int scope_ambiguous = 0;

		if (nam->m_len != sizeof(*addr)) {
			error = EINVAL;
			break;
		}
		if (ifnet.tqh_first == 0) {
			error = EADDRNOTAVAIL;
			break;
		}
		if (addr->sin6_family != AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}

		/* protect *addr */
		sin6 = *addr;
		addr = &sin6;

		/*
		 * Application should provide a proper zone ID or the use of
		 * default zone IDs should be enabled.  Unfortunately, some
		 * applications do not behave as it should, so we need a
		 * workaround.  Even if an appropriate ID is not determined,
		 * we'll see if we can determine the outgoing interface.  If we
		 * can, determine the zone ID based on the interface below.
		 */
		if (addr->sin6_scope_id == 0 && !ip6_use_defzone)
			scope_ambiguous = 1;
		if ((error = sa6_embedscope(addr, ip6_use_defzone)) != 0)
			break;

		/* Source address selection. XXX: need pcblookup? */
		src = in6_selectsrc(addr, in6p->in6p_outputopts,
		    in6p->in6p_moptions, &in6p->in6p_route,
		    &in6p->in6p_laddr, &ifp, &error);
		if (src == NULL) {
			if (error == 0)
				error = EADDRNOTAVAIL;
			break;
		}
		if (ifp && scope_ambiguous) {
			error = in6_setscope(&addr->sin6_addr, ifp, NULL);
			if (error != 0)
				break;
		}
		in6p->in6p_faddr = addr->sin6_addr;
		in6p->in6p_laddr = *src;
		soisconnected(so);
		break;
	}

	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	/*
	 * Mark the connection as being incapable of futther input.
	 */
	case PRU_SHUTDOWN:
		socantsendmore(so);
		break;
	/*
	 * Ship a packet out. The appropriate raw output
	 * routine handles any messaging necessary.
	 */
	case PRU_SEND:
	{
		struct sockaddr_in6 tmp;
		struct sockaddr_in6 *dst;

		/* always copy sockaddr to avoid overwrites */
		if (so->so_state & SS_ISCONNECTED) {
			if (nam) {
				error = EISCONN;
				break;
			}
			/* XXX */
			bzero(&tmp, sizeof(tmp));
			tmp.sin6_family = AF_INET6;
			tmp.sin6_len = sizeof(struct sockaddr_in6);
			bcopy(&in6p->in6p_faddr, &tmp.sin6_addr,
			    sizeof(struct in6_addr));
			dst = &tmp;
		} else {
			if (nam == NULL) {
				error = ENOTCONN;
				break;
			}
			if (nam->m_len != sizeof(tmp)) {
				error = EINVAL;
				break;
			}

			tmp = *mtod(nam, struct sockaddr_in6 *);
			dst = &tmp;

			if (dst->sin6_family == AF_UNSPEC) {
				/*
				 * XXX: we allow this case for backward
				 * compatibility to buggy applications that
				 * rely on old (and wrong) kernel behavior.
				 */
				log(LOG_INFO, "rip6 SEND: address family is "
				    "unspec. Assume AF_INET6\n");
				dst->sin6_family = AF_INET6;
			} else if (dst->sin6_family != AF_INET6) {
				error = EAFNOSUPPORT;
				break;
			}
		}
		error = rip6_output(m, so, dst, control);
		m = NULL;
		break;
	}

	case PRU_SENSE:
		/*
		 * stat: don't bother with a blocksize
		 */
		return (0);
	/*
	 * Not supported.
	 */
	case PRU_RCVOOB:
	case PRU_RCVD:
	case PRU_LISTEN:
	case PRU_ACCEPT:
	case PRU_SENDOOB:
		error = EOPNOTSUPP;
		break;

	case PRU_SOCKADDR:
		in6_setsockaddr(in6p, nam);
		break;

	case PRU_PEERADDR:
		in6_setpeeraddr(in6p, nam);
		break;

	default:
		panic("rip6_usrreq");
	}
	if (m != NULL)
		m_freem(m);
	return (error);
}
