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
 *
 * $FreeBSD: src/sys/netinet6/raw_ip6.c,v 1.7.2.7 2003/01/24 05:11:35 sam Exp $
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

#include "opt_ipsec.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6_mroute.h>
#include <netinet/icmp6.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/scope6_var.h>
#include <netinet6/raw_ip6.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/ipsec6.h>
#endif /* FAST_IPSEC */

#ifdef MLDV2
#include <netinet6/in6_msf.h>
#endif

#include <machine/stdarg.h>

#define	satosin6(sa)	((struct sockaddr_in6 *)(sa))
#define	ifatoia6(ifa)	((struct in6_ifaddr *)(ifa))

/*
 * Raw interface to IP6 protocol.
 */

extern struct	inpcbhead ripcb;
extern struct	inpcbinfo ripcbinfo;
extern u_long	rip_sendspace;
extern u_long	rip_recvspace;

struct rip6stat rip6stat;

/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
int
rip6_input(mp, offp, proto)
	struct	mbuf **mp;
	int	*offp, proto;
{
	struct mbuf *m = *mp;
	register struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	register struct inpcb *in6p;
	struct inpcb *last = 0;
	struct mbuf *opts = NULL;
	struct sockaddr_in6 fromsa;

	rip6stat.rip6s_ipackets++;

	if (faithprefix_p != NULL && (*faithprefix_p)(&ip6->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		m_freem(m);
		return IPPROTO_DONE;
	}

	init_sin6(&fromsa, m); /* general init */

	LIST_FOREACH(in6p, &ripcb, inp_list) {
		if ((in6p->in6p_vflag & INP_IPV6) == 0)
			continue;
		if (in6p->in6p_ip6_nxt &&
		    in6p->in6p_ip6_nxt != proto)
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
#ifdef MLDV2
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
			if (match_msf6_per_socket(in6p, &ip6->ip6_src,
						  &ip6->ip6_dst) == 0)
				continue;
		}
#endif
		if (last) {
			struct mbuf *n = m_copy(m, 0, (int)M_COPYALL);

#ifdef IPSEC
			/*
			 * Check AH/ESP integrity.
			 */
			if (n && ipsec6_in_reject_so(n, last->inp_socket)) {
				m_freem(n);
				ipsec6stat.in_polvio++;
				/* do not inject data into pcb */
			} else
#endif /*IPSEC*/
#ifdef FAST_IPSEC
			/*
			 * Check AH/ESP integrity.
			 */
			if (n && ipsec6_in_reject(n, last)) {
				m_freem(n);
				/* do not inject data into pcb */
			} else
#endif /*FAST_IPSEC*/
			if (n) {
				if (last->in6p_flags & IN6P_CONTROLOPTS ||
				    last->in6p_socket->so_options & SO_TIMESTAMP)
					ip6_savecontrol(last, n, &opts);
				/* strip intermediate headers */
				m_adj(n, *offp);
				if (sbappendaddr(&last->in6p_socket->so_rcv,
						(struct sockaddr *)&fromsa,
						 n, opts) == 0) {
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
	if (last && ipsec6_in_reject_so(m, last->inp_socket)) {
		m_freem(m);
		ipsec6stat.in_polvio++;
		ip6stat.ip6s_delivered--;
		/* do not inject data into pcb */
	} else
#endif /*IPSEC*/
#ifdef FAST_IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (last && ipsec6_in_reject(m, last)) {
		m_freem(m);
		ip6stat.ip6s_delivered--;
		/* do not inject data into pcb */
	} else
#endif /*FAST_IPSEC*/
	if (last) {
		if (last->in6p_flags & IN6P_CONTROLOPTS ||
		    last->in6p_socket->so_options & SO_TIMESTAMP)
			ip6_savecontrol(last, m, &opts);
		/* strip intermediate headers */
		m_adj(m, *offp);
		if (sbappendaddr(&last->in6p_socket->so_rcv,
				(struct sockaddr *)&fromsa, m, opts) == 0) {
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
			char *prvnxtp = ip6_get_prevhdr(m, *offp); /* XXX */
			icmp6_error(m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_NEXTHEADER,
				    prvnxtp - mtod(m, char *));
		}
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}

void
rip6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int off = 0;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	void *cmdarg;
	void (*notify) __P((struct inpcb *, int)) = in6_rtchange;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd))
		notify = in6_rtchange, d = NULL;
	else if (cmd == PRC_HOSTDEAD)
		d = NULL;
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
	} else {
		m = NULL;
		ip6 = NULL;
		cmdarg = NULL;
		sa6_src = &sa6_any;
	}

	(void) in6_pcbnotify(&ripcb, sa, 0, (const struct sockaddr *)sa6_src,
			     0, cmd, cmdarg, notify);
}

/*
 * Generate IPv6 header and pass packet to ip6_output.
 * Tack on options user may have setup with control call.
 */
int
rip6_output(m, so, dstsock, control)
	struct mbuf *m;
	struct socket *so;
	struct sockaddr_in6 *dstsock;
	struct mbuf *control;
{
	struct in6_addr *dst;
	struct ip6_hdr *ip6;
	struct inpcb *in6p;
	u_int	plen = m->m_pkthdr.len;
	int error = 0;
	struct ip6_pktopts opt, *optp;
	struct ifnet *oifp = NULL;
	int type = 0, code = 0;		/* for ICMPv6 output statistics only */
	int priv = 0;
	struct in6_addr *in6;

	in6p = sotoin6pcb(so);

	priv = 0;
	if (so->so_cred->cr_uid == 0)
		priv = 1;
	dst = &dstsock->sin6_addr;
	if (control) {
		if ((error = ip6_setpktopts(control, &opt,
		    in6p->in6p_outputopts, priv,
		    so->so_proto->pr_protocol)) != 0) {
			goto bad;
		}
		optp = &opt;
	} else
		optp = in6p->in6p_outputopts;

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
	}

	M_PREPEND(m, sizeof(*ip6), M_WAIT);
	ip6 = mtod(m, struct ip6_hdr *);

	/* Source address selection. */
	if ((in6 = in6_selectsrc(dstsock, optp, in6p->in6p_moptions,
	    &in6p->in6p_route, &in6p->in6p_laddr, &oifp, &error)) == NULL) {
		if (error == 0)
			error = EADDRNOTAVAIL;
		goto bad;
	}
	ip6->ip6_src = *in6;

	if (oifp && dstsock->sin6_scope_id == 0 &&
	    (error = scope6_setzoneid(oifp, dstsock)) != 0) { /* XXX */
		goto bad;
	}
	ip6->ip6_dst = dstsock->sin6_addr;

	/* fill in the rest of the IPv6 header fields */
	ip6->ip6_flow = (ip6->ip6_flow & ~IPV6_FLOWINFO_MASK) |
		(in6p->in6p_flowinfo & IPV6_FLOWINFO_MASK);
	ip6->ip6_vfc = (ip6->ip6_vfc & ~IPV6_VERSION_MASK) |
		(IPV6_VERSION & IPV6_VERSION_MASK);
	/* ip6_plen will be filled in ip6_output, so not fill it here. */
	ip6->ip6_nxt = in6p->in6p_ip6_nxt;
	ip6->ip6_hlim = in6_selecthlim(in6p, oifp);

	if (so->so_proto->pr_protocol == IPPROTO_ICMPV6 ||
	    in6p->in6p_cksum != -1) {
		struct mbuf *n;
		int off;
		u_int16_t *p;

		/* compute checksum */
		if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
			off = offsetof(struct icmp6_hdr, icmp6_cksum);
		else
			off = in6p->in6p_cksum;
		if (plen < off + 1) {
			error = EINVAL;
			goto bad;
		}
		off += sizeof(struct ip6_hdr);

		n = m;
		while (n && n->m_len <= off) {
			off -= n->m_len;
			n = n->m_next;
		}
		if (!n)
			goto bad;
		p = (u_int16_t *)(mtod(n, caddr_t) + off);
		*p = 0;
		*p = in6_cksum(m, ip6->ip6_nxt, sizeof(*ip6), plen);
	}

#ifdef IPSEC
	if (ipsec_setsocket(m, so) != 0) {
		error = ENOBUFS;
		goto bad;
	}
#endif /*IPSEC*/

	oifp = NULL;		/* just in case */
	error = ip6_output(m, optp, &in6p->in6p_route, 0,
			   in6p->in6p_moptions, &oifp
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , in6p
#endif
			  );
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
	return(error);
}

/*
 * Raw IPv6 socket option processing.
 */
int
rip6_ctloutput(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int error;

	if (sopt->sopt_level == IPPROTO_ICMPV6)
		/*
		 * XXX: is it better to call icmp6_ctloutput() directly
		 * from protosw?
		 */
		return(icmp6_ctloutput(so, sopt));
	else if (sopt->sopt_level != IPPROTO_IPV6)
		return (EINVAL);

	error = 0;

	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case MRT6_INIT:
		case MRT6_DONE:
		case MRT6_ADD_MIF:
		case MRT6_DEL_MIF:
		case MRT6_ADD_MFC:
		case MRT6_DEL_MFC:
		case MRT6_PIM:
			error = ip6_mrouter_get(so, sopt);
			break;
		case IPV6_CHECKSUM:
			error = ip6_raw_ctloutput(so, sopt);
			break;
		default:
			error = ip6_ctloutput(so, sopt);
			break;
		}
		break;

	case SOPT_SET:
		switch (sopt->sopt_name) {
		case MRT6_INIT:
		case MRT6_DONE:
		case MRT6_ADD_MIF:
		case MRT6_DEL_MIF:
		case MRT6_ADD_MFC:
		case MRT6_DEL_MFC:
		case MRT6_PIM:
			error = ip6_mrouter_set(so, sopt);
			break;
		case IPV6_CHECKSUM:
			error = ip6_raw_ctloutput(so, sopt);
			break;
		default:
			error = ip6_ctloutput(so, sopt);
			break;
		}
		break;
	}

	return (error);
}

static int
rip6_attach(struct socket *so, int proto, struct proc *p)
{
	struct inpcb *inp;
	int error, s;

	inp = sotoinpcb(so);
	if (inp)
		panic("rip6_attach");
	if (p && (error = suser(p)) != 0)
		return error;

	error = soreserve(so, rip_sendspace, rip_recvspace);
	if (error)
		return error;
	s = splnet();
	error = in_pcballoc(so, &ripcbinfo, p);
	splx(s);
	if (error)
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV6;
	inp->in6p_ip6_nxt = (long)proto;
	inp->in6p_hops = -1;	/* use kernel default */
	inp->in6p_cksum = -1;
	MALLOC(inp->in6p_icmp6filt, struct icmp6_filter *,
	       sizeof(struct icmp6_filter), M_PCB, M_NOWAIT);
	ICMP6_FILTER_SETPASSALL(inp->in6p_icmp6filt);
	return 0;
}

static int
rip6_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0)
		panic("rip6_detach");
	/* xxx: RSVP */
	if (so == ip6_mrouter)
		ip6_mrouter_done();
	if (inp->in6p_icmp6filt) {
		FREE(inp->in6p_icmp6filt, M_PCB);
		inp->in6p_icmp6filt = NULL;
	}
	in6_pcbdetach(inp);
	return 0;
}

static int
rip6_abort(struct socket *so)
{
	soisdisconnected(so);
	return rip6_detach(so);
}

static int
rip6_disconnect(struct socket *so)
{
	struct inpcb *inp = sotoinpcb(so);

	if ((so->so_state & SS_ISCONNECTED) == 0)
		return ENOTCONN;
	inp->in6p_faddr = in6addr_any;
	return rip6_abort(so);
}

static int
rip6_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)nam;
	struct ifaddr *ia = NULL;
	int error = 0;
#ifndef SCOPEDROUTING
	u_int32_t lzone;
#endif

	if (nam->sa_len != sizeof(*addr))
		return EINVAL;
	if (nam->sa_family != AF_INET6)
		return EAFNOSUPPORT;
	if (TAILQ_EMPTY(&ifnet) || addr->sin6_family != AF_INET6)
		return EADDRNOTAVAIL;
	if ((error = scope6_check_id(addr, ip6_use_defzone)) != 0)
		return(error);
#ifndef SCOPEDROUTING
	lzone = addr->sin6_scope_id;
	addr->sin6_scope_id = 0; /* for ifa_ifwithaddr */
#endif

	if (!IN6_IS_ADDR_UNSPECIFIED(&addr->sin6_addr) &&
	    (ia = ifa_ifwithaddr((struct sockaddr *)addr)) == 0)
		return EADDRNOTAVAIL;
	if (ia &&
	    ((struct in6_ifaddr *)ia)->ia6_flags &
	    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|
	     IN6_IFF_DETACHED|IN6_IFF_DEPRECATED)) {
		return(EADDRNOTAVAIL);
	}
#ifndef SCOPEDROUTING
	addr->sin6_scope_id = lzone;
#endif
	inp->in6p_laddr = addr->sin6_addr;
	return 0;
}

static int
rip6_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)nam;
	struct in6_addr *in6a = NULL;
	struct ifnet *ifp = NULL;
	int error = 0;

	if (nam->sa_len != sizeof(*addr))
		return EINVAL;
	if (TAILQ_EMPTY(&ifnet))
		return EADDRNOTAVAIL;
	if (addr->sin6_family != AF_INET6)
		return EAFNOSUPPORT;
	if ((error = scope6_check_id(addr, ip6_use_defzone)) != 0)
		return(error);

	/* Source address selection. XXX: need pcblookup? */
	in6a = in6_selectsrc(addr, inp->in6p_outputopts,
			     inp->in6p_moptions, &inp->in6p_route,
			     &inp->in6p_laddr, &ifp, &error);
	if (in6a == NULL)
		return (error ? error : EADDRNOTAVAIL);

	/* see above */
	if (ifp && addr->sin6_scope_id == 0 &&
	    (error = scope6_setzoneid(ifp, addr)) != 0) { /* XXX */
		return(error);
	}
	if ((error = in6_embedscope(&inp->in6p_faddr, addr)) != 0)
		return(error);
	inp->in6p_laddr = *in6a;
	soisconnected(so);
	return 0;
}

static int
rip6_shutdown(struct socket *so)
{
	socantsendmore(so);
	return 0;
}

static int
rip6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct proc *p)
{
	int error = 0;
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in6 tmp;
	struct sockaddr_in6 *dst;

	/* always copy sockaddr to avoid overwrites */
	if (so->so_state & SS_ISCONNECTED) {
		if (nam) {
			m_freem(m);
			return EISCONN;
		}
		/* XXX */
		bzero(&tmp, sizeof(tmp));
		tmp.sin6_family = AF_INET6;
		tmp.sin6_len = sizeof(struct sockaddr_in6);
		bcopy(&inp->in6p_faddr, &tmp.sin6_addr,
		      sizeof(struct in6_addr));
		dst = &tmp;
	} else {
		if (nam == NULL) {
			m_freem(m);
			return ENOTCONN;
		}
		if (nam->sa_len != sizeof(struct sockaddr_in6)) {
			m_freem(m);
			return(EINVAL);
		}
		tmp = *(struct sockaddr_in6 *)nam;
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
			m_freem(m);
			return(EAFNOSUPPORT);
		}
		if ((error = scope6_check_id(dst, ip6_use_defzone)) != 0) {
			m_freem(m);
			return(error);
		}
	}
	return rip6_output(m, so, dst, control);
}

struct pr_usrreqs rip6_usrreqs = {
	rip6_abort, pru_accept_notsupp, rip6_attach, rip6_bind, rip6_connect,
	pru_connect2_notsupp, in6_control, rip6_detach, rip6_disconnect,
	pru_listen_notsupp, in6_setpeeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, rip6_send, pru_sense_null, rip6_shutdown,
	in6_setsockaddr, sosend, soreceive, sopoll
};
