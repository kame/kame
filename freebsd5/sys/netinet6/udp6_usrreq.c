/*	$FreeBSD: src/sys/netinet6/udp6_usrreq.c,v 1.33 2003/02/19 22:32:43 jlemon Exp $	*/
/*	$KAME: udp6_usrreq.c,v 1.27 2001/05/21 05:45:10 jinmei Exp $	*/

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
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)udp_var.h	8.1 (Berkeley) 6/10/93
 */

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/mld6_var.h>
#ifdef MLDV2
#include <netinet6/in6_msf.h>
#endif
#include <netinet6/udp6_var.h>
#include <netinet6/scope6_var.h>

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /* IPSEC */

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#include <netipsec/ipsec6.h>
#endif /* FAST_IPSEC */

/*
 * UDP protocol inplementation.
 * Per RFC 768, August, 1980.
 */

extern	struct protosw inetsw[];
static	int udp6_detach __P((struct socket *so));

int
udp6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp, *opts;
	register struct ip6_hdr *ip6;
	register struct udphdr *uh;
	register struct inpcb *in6p;
	int off = *offp;
	int plen, ulen;
	struct sockaddr_in6 src, dst, fromsa, tosa;
#ifdef MLDV2
	struct sock_msf *msf;
	struct ip6_moptions *im6o;
	struct in6_multi_mship *imm;
	struct sock_msf_source *msfsrc;
#endif	

	opts = NULL;

	ip6 = mtod(m, struct ip6_hdr *);

	if (faithprefix_p != NULL && (*faithprefix_p)(&ip6->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		m_freem(m);
		return IPPROTO_DONE;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(struct udphdr), IPPROTO_DONE);
	ip6 = mtod(m, struct ip6_hdr *);
	uh = (struct udphdr *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(uh, struct udphdr *, m, off, sizeof(*uh));
	if (!uh)
		return IPPROTO_DONE;
#endif

	/*
	 * extract full sockaddr structures for the src/dst addresses,
	 * and make local copies of them.
	 */
	if (ip6_getpktaddrs(m, &src, &dst)) {
		m_freem(m);
		goto bad;
	}

	/*
	 * XXX: the address may have embedded scope zone ID, which should be
	 * hidden from applications.
	 */
	fromsa = src;
	tosa = dst;
#ifndef SCOPEDROUTING
	in6_clearscope(&fromsa.sin6_addr);
	in6_clearscope(&tosa.sin6_addr);
#endif

	udpstat.udps_ipackets++;

	plen = ntohs(ip6->ip6_plen) - off + sizeof(*ip6);
	ulen = ntohs((u_short)uh->uh_ulen);

	if (plen != ulen) {
		udpstat.udps_badlen++;
		goto bad;
	}

	/*
	 * Checksum extended UDP header and data.
	 */
	if (uh->uh_sum == 0) {
		udpstat.udps_nosum++;
		goto bad;
	}
	if (in6_cksum(m, IPPROTO_UDP, off, ulen) != 0) {
		udpstat.udps_badsum++;
		goto bad;
	}

	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct	inpcb *last;
		struct	sockaddr_in6 fromsa2, tosa2; /* only with addr info */
		
		bzero(&fromsa2, sizeof(fromsa2));
		bzero(&tosa2, sizeof(tosa2));
		fromsa2.sin6_family = tosa2.sin6_family = AF_INET6;
		fromsa2.sin6_len = tosa2.sin6_len = sizeof(struct sockaddr_in6);
		fromsa2.sin6_addr = fromsa.sin6_addr;
		tosa2.sin6_addr = tosa.sin6_addr;
		fromsa2.sin6_scope_id = fromsa.sin6_scope_id;
		tosa2.sin6_scope_id = tosa.sin6_scope_id;

		/*
		 * Deliver a multicast datagram to all sockets
		 * for which the local and remote addresses and ports match
		 * those of the incoming datagram.  This allows more than
		 * one process to receive multicasts on the same port.
		 * (This really ought to be done for unicast datagrams as
		 * well, but that would cause problems with existing
		 * applications that open both address-specific sockets and
		 * a wildcard socket listening to the same port -- they would
		 * end up receiving duplicates of every unicast datagram.
		 * Those applications open the multiple sockets to overcome an
		 * inadequacy of the UDP socket interface, but for backwards
		 * compatibility we avoid the problem here rather than
		 * fixing the interface.  Maybe 4.5BSD will remedy this?)
		 */

		/*
		 * In a case that laddr should be set to the link-local
		 * address (this happens in RIPng), the multicast address
		 * specified in the received packet does not match with
		 * laddr. To cure this situation, the matching is relaxed
		 * if the receiving interface is the same as one specified
		 * in the socket and if the destination multicast address
		 * matches one of the multicast groups specified in the socket.
		 */

		/*
		 * Construct sockaddr format source address.
		 */
		fromsa.sin6_port = uh->uh_sport;
		/*
		 * KAME note: traditionally we dropped udpiphdr from mbuf here.
		 * We need udphdr for IPsec processing so we do that later.
		 */

		/*
		 * Locate pcb(s) for datagram.
		 * (Algorithm copied from raw_intr().)
		 */
		last = NULL;
		LIST_FOREACH(in6p, &udb, inp_list) {
			if ((in6p->inp_vflag & INP_IPV6) == 0)
				continue;
			if (in6p->in6p_lport != uh->uh_dport)
				continue;
			if (!SA6_IS_ADDR_UNSPECIFIED(&in6p->in6p_lsa)) {
				if (!SA6_ARE_ADDR_EQUAL(&in6p->in6p_lsa, &tosa))
					continue;
			}
			if (!SA6_IS_ADDR_UNSPECIFIED(&in6p->in6p_fsa)) {
				if (!SA6_ARE_ADDR_EQUAL(&in6p->in6p_fsa,
							&fromsa) ||
				    in6p->in6p_fport != uh->uh_sport) {
					continue;
				}
			}

#ifdef MLDV2
#ifdef IPSEC
#define PASS_TO_PCB6() \
	do { \
		if (last != NULL) { \
			struct mbuf *n; \
			/* check AH/ESP integrity. */ \
			if (ipsec6_in_reject_so(m, last->in6p_socket)) \
				ipsec6stat.in_polvio++; \
				/* do not inject data to pcb */ \
			else \
			if ((n = m_copy(m, 0, M_COPYALL)) != NULL) { \
				/* \
				 * KAME NOTE: do not m_copy(m, offset, ...) above. \
				 * sbappendaddr() expects M_PKTHDR, and m_copy() \
				 * only if offset is 0. will copy M_PKTHDR \
				 *  \
				 */ \
				if (last->in6p_flags & IN6P_CONTROLOPTS \
				    || last->in6p_socket->so_options & SO_TIMESTAMP) \
					ip6_savecontrol(last, n, &opts); \
				m_adj(n, off + sizeof(struct udphdr)); \
				if (sbappendaddr(&last->in6p_socket->so_rcv, \
						(struct sockaddr *)&fromsa, \
						n, opts) == 0) { \
					m_freem(n); \
					if (opts) \
						m_freem(opts); \
					udpstat.udps_fullsock++; \
				} else \
					sorwakeup(last->in6p_socket); \
				opts = NULL; \
			} \
		} \
		last = in6p; \
	} while (0)
#else /* !IPSEC */
#define PASS_TO_PCB6() \
	do { \
		if (last != NULL) { \
			/* \
			 * KAME NOTE: do not m_copy(m, offset, ...) above. \
			 * sbappendaddr() expects M_PKTHDR, and m_copy() \
			 * only if offset is 0. will copy M_PKTHDR \
			 *  \
			 */ \
			if (last->in6p_flags & IN6P_CONTROLOPTS \
			    || last->in6p_socket->so_options & SO_TIMESTAMP) \
				ip6_savecontrol(last, n, &opts); \
			m_adj(n, off + sizeof(struct udphdr)); \
			if (sbappendaddr(&last->in6p_socket->so_rcv, \
					(struct sockaddr *)&fromsa, \
					n, opts) == 0) { \
				m_freem(n); \
				if (opts) \
					m_freem(opts); \
				udpstat.udps_fullsock++; \
			} else { \
				sorwakeup(last->in6p_socket); \
				opts = NULL; \
			} \
		} \
		last = inp; \
	} while (0)
#endif /* IPSEC */
			/*
			 * Receive multicast data which fits MSF condition.
			 * In MSF comparison, we use from/tosa2 to ignore
			 * port number information.
			 */
			if ((im6o = in6p->in6p_moptions) == NULL)
				continue;
			for (imm = LIST_FIRST(&im6o->im6o_memberships);
			     imm != NULL;
			     imm = LIST_NEXT(imm, i6mm_chain)) {

				if (SS_CMP(&imm->i6mm_maddr->in6m_sa,
				    !=, &tosa2))
					continue;

				msf = imm->i6mm_msf;
				if (msf == NULL) {
					mldlog((LOG_DEBUG, "unexpected case occured at %s:%d",
					       __FILE__, __LINE__));
					continue;
				}

				/* receive data from any source */
				if (msf->msf_grpjoin != 0) {
					PASS_TO_PCB6();
					break;
				}
				goto search_allow_list;

			search_allow_list:
				if (msf->msf_numsrc == 0)
					goto search_block_list;

				LIST_FOREACH(msfsrc, msf->msf_head, list) {
					if (msfsrc->src.ss_family != AF_INET6)
						continue;
					if (SS_CMP(&msfsrc->src, <, &fromsa2))
						continue;
					if (SS_CMP(&msfsrc->src, >, &fromsa2)) {
						/* terminate search, as there
						 * will be no match */
						break;
					}

					PASS_TO_PCB6();
					break;
				}

			search_block_list:
				if (msf->msf_blknumsrc == 0)
					goto end_of_search;

				LIST_FOREACH(msfsrc, msf->msf_blkhead, list) {
					if (msfsrc->src.ss_family != AF_INET6)
						continue;
					if (SS_CMP(&msfsrc->src, <, &fromsa2))
						continue;
					if (SS_CMP(&msfsrc->src, >, &fromsa2)) {
						/* blocks since the src matched
						 * with block list */
						break;
					}

					/* terminate search, as there will be
					 * no match */
					msfsrc = NULL;
					break;
				}
				/* blocks since the source matched with block
				 * list */
				if (msfsrc == NULL)
					PASS_TO_PCB6();

			end_of_search:
				goto next_inp;
			}
			if (imm == NULL)
				continue;
#undef PASS_TO_PCB6
#else /* MLDV2 */
			if (last != NULL) {
				struct	mbuf *n;

#ifdef IPSEC
				/*
				 * Check AH/ESP integrity.
				 */
				if (ipsec6_in_reject(m, last))
					ipsec6stat.in_polvio++;
					/* do not inject data into pcb */
				else
#endif /* IPSEC */
#ifdef FAST_IPSEC
				/*
				 * Check AH/ESP integrity.
				 */
				if (ipsec6_in_reject(m, last))
					;
				else
#endif /* FAST_IPSEC */
				if ((n = m_copy(m, 0, M_COPYALL)) != NULL) {
					/*
					 * KAME NOTE: do not
					 * m_copy(m, offset, ...) above.
					 * sbappendaddr() expects M_PKTHDR,
					 * and m_copy() will copy M_PKTHDR
					 * only if offset is 0.
					 */
					if (last->in6p_flags & IN6P_CONTROLOPTS
					    || last->in6p_socket->so_options & SO_TIMESTAMP)
						ip6_savecontrol(last, n, &opts);

					m_adj(n, off + sizeof(struct udphdr));
					if (sbappendaddr(&last->in6p_socket->so_rcv,
							(struct sockaddr *)&fromsa,
							n, opts) == 0) {
						m_freem(n);
						if (opts)
							m_freem(opts);
						udpstat.udps_fullsock++;
					} else
						sorwakeup(last->in6p_socket);
					opts = NULL;
				}
			}
#endif /* !MLDV2 */
			last = in6p;
			/*
			 * Don't look for additional matches if this one does
			 * not have either the SO_REUSEPORT or SO_REUSEADDR
			 * socket options set.  This heuristic avoids searching
			 * through all pcbs in the common case of a non-shared
			 * port.  It assumes that an application will never
			 * clear these options after setting them.
			 */
			if ((last->in6p_socket->so_options &
			     (SO_REUSEPORT|SO_REUSEADDR)) == 0)
				break;
#ifdef MLDV2
		next_inp:;
#endif
		}

		if (last == NULL) {
			/*
			 * No matching pcb found; discard datagram.
			 * (No need to send an ICMP Port Unreachable
			 * for a broadcast or multicast datgram.)
			 */
			udpstat.udps_noport++;
			udpstat.udps_noportmcast++;
			goto bad;
		}
#ifdef IPSEC
		/*
		 * Check AH/ESP integrity.
		 */
		if (ipsec6_in_reject(m, last)) {
			ipsec6stat.in_polvio++;
			goto bad;
		}
#endif /* IPSEC */
#ifdef FAST_IPSEC
		/*
		 * Check AH/ESP integrity.
		 */
		if (ipsec6_in_reject(m, last)) {
			goto bad;
		}
#endif /* FAST_IPSEC */
		if (last->in6p_flags & IN6P_CONTROLOPTS
		    || last->in6p_socket->so_options & SO_TIMESTAMP)
			ip6_savecontrol(last, m, &opts);

		m_adj(m, off + sizeof(struct udphdr));
		if (sbappendaddr(&last->in6p_socket->so_rcv,
				(struct sockaddr *)&fromsa, m, opts) == 0) {
			udpstat.udps_fullsock++;
			goto bad;
		}
		sorwakeup(last->in6p_socket);
		return IPPROTO_DONE;
	}
	/*
	 * Locate pcb for datagram.
	 */
	in6p = in6_pcblookup_hash(&udbinfo, &src, uh->uh_sport,
				  &dst, uh->uh_dport, 1,
				  m->m_pkthdr.rcvif);
	if (in6p == 0) {
		if (log_in_vain) {
			char buf[INET6_ADDRSTRLEN];

			strcpy(buf, ip6_sprintf(&ip6->ip6_dst));
			log(LOG_INFO,
			    "Connection attempt to UDP [%s]:%d from [%s]:%d\n",
			    buf, ntohs(uh->uh_dport),
			    ip6_sprintf(&ip6->ip6_src), ntohs(uh->uh_sport));
		}
		udpstat.udps_noport++;
		if (m->m_flags & M_MCAST) {
			printf("UDP6: M_MCAST is set in a unicast packet.\n");
			udpstat.udps_noportmcast++;
			goto bad;
		}
		icmp6_error(m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT, 0);
		return IPPROTO_DONE;
	}
#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (ipsec6_in_reject(m, in6p)) {
		ipsec6stat.in_polvio++;
		goto bad;
	}
#endif /* IPSEC */
#ifdef FAST_IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (ipsec6_in_reject(m, in6p)) {
		goto bad;
	}
#endif /* FAST_IPSEC */

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	fromsa.sin6_port = uh->uh_sport;
	if (in6p->in6p_flags & IN6P_CONTROLOPTS
	    || in6p->in6p_socket->so_options & SO_TIMESTAMP)
		ip6_savecontrol(in6p, m, &opts);
	m_adj(m, off + sizeof(struct udphdr));
	if (sbappendaddr(&in6p->in6p_socket->so_rcv,
			(struct sockaddr *)&fromsa, m, opts) == 0) {
		udpstat.udps_fullsock++;
		goto bad;
	}
	sorwakeup(in6p->in6p_socket);
	return IPPROTO_DONE;
bad:
	if (m)
		m_freem(m);
	if (opts)
		m_freem(opts);
	return IPPROTO_DONE;
}

void
udp6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	struct udphdr uh;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int off = 0;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	void *cmdarg;
	struct inpcb *(*notify) __P((struct inpcb *, int)) = udp_notify;
	struct udp_portonly {
		u_int16_t uh_sport;
		u_int16_t uh_dport;
	} *uhp;

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

	if (ip6) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */

		/* check if we can safely examine src and dst ports */
		if (m->m_pkthdr.len < off + sizeof(*uhp))
			return;

		bzero(&uh, sizeof(uh));
		m_copydata(m, off, sizeof(*uhp), (caddr_t)&uh);

		(void) in6_pcbnotify(&udb, sa,
				     uh.uh_dport, 
				     (const struct sockaddr *)ip6cp->ip6c_src,
				     uh.uh_sport, cmd, cmdarg, notify);
	} else
		(void) in6_pcbnotify(&udb, sa, 0,
				     (const struct sockaddr *)sa6_src,
				     0, cmd, cmdarg, notify);
}

static int
udp6_getcred(SYSCTL_HANDLER_ARGS)
{
	struct xucred xuc;
	struct sockaddr_in6 addrs[2];
	struct inpcb *inp;
	int error, s;

	error = suser(req->td);
	if (error)
		return (error);

	if (req->newlen != sizeof(addrs))
		return (EINVAL);
	if (req->oldlen != sizeof(struct xucred))
		return (EINVAL);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);
	if ((error = scope6_check_id(&addrs[0], ip6_use_defzone)) != 0 ||
	    (error = scope6_check_id(&addrs[1], ip6_use_defzone)) != 0) {
		return (error);
	}
	s = splnet();
	inp = in6_pcblookup_hash(&udbinfo, &addrs[1], addrs[1].sin6_port,
				 &addrs[0], addrs[0].sin6_port,
				 1, NULL);
	if (!inp || !inp->inp_socket) {
		error = ENOENT;
		goto out;
	}
	cru2x(inp->inp_socket->so_cred, &xuc);
	error = SYSCTL_OUT(req, &xuc, sizeof(struct xucred));
out:
	splx(s);
	return (error);
}

SYSCTL_PROC(_net_inet6_udp6, OID_AUTO, getcred, CTLTYPE_OPAQUE|CTLFLAG_RW,
	    0, 0,
	    udp6_getcred, "S,xucred", "Get the xucred of a UDP6 connection");

static int
udp6_abort(struct socket *so)
{
	struct inpcb *inp;
	int s;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;	/* ??? possible? panic instead? */
	soisdisconnected(so);
	s = splnet();
	in6_pcbdetach(inp);
	splx(s);
	return 0;
}

static int
udp6_attach(struct socket *so, int proto, struct thread *td)
{
	struct inpcb *inp;
	int s, error;

	inp = sotoinpcb(so);
	if (inp != 0)
		return EINVAL;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, udp_sendspace, udp_recvspace);
		if (error)
			return error;
	}
	s = splnet();
	error = in_pcballoc(so, &udbinfo, td);
	splx(s);
	if (error)
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV6;
	if (!ip6_v6only)
		inp->inp_vflag |= INP_IPV4;
	inp->in6p_hops = -1;	/* use kernel default */
	inp->in6p_cksum = -1;	/* just to be sure */
	/*
	 * XXX: ugly!!
	 * IPv4 TTL initialization is necessary for an IPv6 socket as well,
	 * because the socket may be bound to an IPv6 wildcard address,
	 * which may match an IPv4-mapped IPv6 address.
	 */
	inp->inp_ip_ttl = ip_defttl;
	return 0;
}

static int
udp6_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int s, error;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;

	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		struct sockaddr_in6 *sin6_p;

		sin6_p = (struct sockaddr_in6 *)nam;

		if (SA6_IS_ADDR_UNSPECIFIED(sin6_p))
			inp->inp_vflag |= INP_IPV4;
		else if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
			struct sockaddr_in sin;

			in6_sin6_2_sin(&sin, sin6_p);
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
			s = splnet();
			error = in_pcbbind(inp, (struct sockaddr *)&sin, td);
			splx(s);
			return error;
		}
	}

	s = splnet();
	error = in6_pcbbind(inp, nam, td);
	splx(s);
	return error;
}

static int
udp6_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int s, error;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;

	if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0) {
		struct sockaddr_in6 *sin6_p;

		sin6_p = (struct sockaddr_in6 *)nam;
		if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
			struct sockaddr_in sin;

			if (inp->inp_faddr.s_addr != INADDR_ANY)
				return EISCONN;
			in6_sin6_2_sin(&sin, sin6_p);
			s = splnet();
			error = in_pcbconnect(inp, (struct sockaddr *)&sin, td);
			splx(s);
			if (error == 0) {
				inp->inp_vflag |= INP_IPV4;
				inp->inp_vflag &= ~INP_IPV6;
				soisconnected(so);
			}
			return error;
		}
	}
	if (!SA6_IS_ADDR_UNSPECIFIED(&inp->in6p_fsa))
		return EISCONN;
	s = splnet();
	error = in6_pcbconnect(inp, nam, td);
	splx(s);
	if (error == 0) {
		if (!ip6_v6only) { /* should be non mapped addr */
			inp->inp_vflag &= ~INP_IPV4;
			inp->inp_vflag |= INP_IPV6;
		}
		soisconnected(so);
	}
	return error;
}

static int
udp6_detach(struct socket *so)
{
	struct inpcb *inp;
	int s;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;
	s = splnet();
	in6_pcbdetach(inp);
	splx(s);
	return 0;
}

static int
udp6_disconnect(struct socket *so)
{
	struct inpcb *inp;
	int s;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;

#ifdef INET
	if (inp->inp_vflag & INP_IPV4) {
		struct pr_usrreqs *pru;

		pru = inetsw[ip_protox[IPPROTO_UDP]].pr_usrreqs;
		return ((*pru->pru_disconnect)(so));
	}
#endif

	if (SA6_IS_ADDR_UNSPECIFIED(&inp->in6p_fsa))
		return ENOTCONN;

	s = splnet();
	in6_pcbdisconnect(inp);
	sa6_copy_addr(&sa6_any, &inp->in6p_lsa);
	splx(s);
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
	return 0;
}

static int
udp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	  struct mbuf *control, struct thread *td)
{
	struct inpcb *inp;
	int error = 0;

	inp = sotoinpcb(so);
	if (inp == 0) {
		error = EINVAL;
		goto bad;
	}

	if (addr) {
		if (addr->sa_len != sizeof(struct sockaddr_in6)) { 
			error = EINVAL;
			goto bad;
		}
		if (addr->sa_family != AF_INET6) {
			error = EAFNOSUPPORT;
			goto bad;
		}
	}

#ifdef INET
	if (!ip6_v6only) {
		int hasv4addr;
		struct sockaddr_in6 *sin6 = 0;

		if (addr == 0)
			hasv4addr = (inp->inp_vflag & INP_IPV4);
		else {
			sin6 = (struct sockaddr_in6 *)addr;
			hasv4addr = IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)
				? 1 : 0;
		}
		if (hasv4addr) {
			struct pr_usrreqs *pru;

			if ((inp->inp_flags & IN6P_IPV6_V6ONLY)) {
				/* 
				 * since a user of this socket set the
				 * IPV6_V6ONLY flag, we discard this
				 * datagram destined to a v4 addr.
				 */
				return EINVAL;
			}
			if (!SA6_IS_ADDR_UNSPECIFIED(&inp->in6p_lsa)
			    && !IN6_IS_ADDR_V4MAPPED(&inp->in6p_laddr)) {
				/*
				 * when remote addr is IPv4-mapped
				 * address, local addr should not be
				 * an IPv6 address; since you cannot
				 * determine how to map IPv6 source
				 * address to IPv4.
				 */
				return EINVAL;
			}
			if (sin6)
				in6_sin6_2_sin_in_sock(addr);
			pru = inetsw[ip_protox[IPPROTO_UDP]].pr_usrreqs;
			error = ((*pru->pru_send)(so, flags, m, addr, control,
						  td));
			/* addr will just be freed in sendit(). */
			return error;
		}
	}
#endif

	return udp6_output(inp, m, addr, control, td);

  bad:
	m_freem(m);
	return(error);
}

struct pr_usrreqs udp6_usrreqs = {
	udp6_abort, pru_accept_notsupp, udp6_attach, udp6_bind, udp6_connect,
	pru_connect2_notsupp, in6_control, udp6_detach, udp6_disconnect,
	pru_listen_notsupp, in6_mapped_peeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, udp6_send, pru_sense_null, udp_shutdown,
	in6_mapped_sockaddr, sosend, soreceive, sopoll
};
