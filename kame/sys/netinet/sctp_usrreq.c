/*	$KAME: sctp_usrreq.c,v 1.17 2002/07/30 04:12:35 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_usrreq.c,v 1.151 2002/04/04 16:49:14 lei Exp	*/

/*
 * Copyright (c) 2001, 2002 Cisco Systems, Inc.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Cisco Systems, Inc.
 * 4. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CISCO SYSTEMS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CISCO SYSTEMS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef __OpenBSD__
#include "opt_ipsec.h"
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet6.h"
#include "opt_inet.h"
#endif
#if defined(__NetBSD__)
#include "opt_inet.h"
#endif

#ifndef __OpenBSD__
#include "opt_sctp.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <net/if.h>
#include <net/if_types.h>
#if defined(__FreeBSD__)
#include <net/if_var.h>
#endif

#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_asconf.h>
#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif /*IPSEC*/

#include <net/net_osdep.h>

#if defined(__FreeBSD__)
#include <vm/vm_zone.h>
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/pool.h>
#endif

#if defined(HAVE_NRL_INPCB) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#ifndef in6pcb
#define in6pcb		inpcb
#endif
#ifndef sotoin6pcb
#define sotoin6pcb      sotoinpcb
#endif
#endif


#ifdef SCTP_DEBUG
extern u_int32_t sctp_debug_on;
#endif /* SCTP_DEBUG */

extern struct sctp_epinfo sctppcbinfo;

static int sctp_detach __P((struct socket *so));

void
sctp_init()
{
	/* Init the SCTP pcb in sctp_pcb.c */
	sctp_pcb_init();
}

#ifdef INET6
void
ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip)
{
	bzero(ip6, sizeof(*ip6));

	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = ip->ip_len;
	ip6->ip6_nxt = ip->ip_p;
	ip6->ip6_hlim = ip->ip_ttl;
	ip6->ip6_src.s6_addr32[2] = ip6->ip6_dst.s6_addr32[2] =
		IPV6_ADDR_INT32_SMP;
	ip6->ip6_src.s6_addr32[3] = ip->ip_src.s_addr;
	ip6->ip6_dst.s6_addr32[3] = ip->ip_dst.s_addr;
}
#endif /* INET6 */

static void
sctp_notify_mbuf(struct sctp_inpcb *inp,
		 struct sctp_tcb *stcb,
		 struct sctp_nets *netp,
		 struct ip *ip,
		 struct sctphdr *sh)

{
	struct icmp *icmph;
	int totsz;
	u_short nxtsz;

	/* protection */
	if ((inp == NULL) || (stcb == NULL) || (netp == NULL) ||
	    (ip == NULL) || (sh == NULL)) {
		return;
	}
	/* First job is to verify the vtag matches what I would send */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag)) {
		return;
	}
	icmph = (struct icmp *)((caddr_t)ip - (sizeof(struct icmp) -
					       sizeof(struct ip)));
	if (icmph->icmp_type != ICMP_UNREACH) {
		/* We only care about unreachable */
		return;
	}
	if (icmph->icmp_code != ICMP_UNREACH_NEEDFRAG) {
		/* not a unreachable message due to frag. */
		/* FIX ME : We should check for unreachable protocol,
		 * destintation and port to clean up any association...
		 * Destination Unreach - network died.
		 * Protocol unreach and Port unreach - peer is dead.
		 */
		return;
	}
	totsz = ip->ip_len;
	nxtsz = ntohs(icmph->icmp_seq);
	if (nxtsz == 0) {
		/*
		 * old type router that does not tell us what the next size
		 * mtu is. Rats we will have to guess (in a educated fashion
		 * of course)
		 */
		nxtsz = find_next_best_mtu(totsz);
	}
	/* Stop any PMTU timer */
	sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, NULL);

	/* Adjust destination size limit */
	if (netp->mtu > nxtsz) {
		netp->mtu = nxtsz;
	}
	/* now what about the ep? */
	if (stcb->asoc.smallest_mtu > nxtsz) {
		struct sctp_tmit_chunk *chk;
		struct sctp_stream_out *strm;
		/* Adjust that too */
		stcb->asoc.smallest_mtu = nxtsz;
		/* now off to subtract IP_DF flag if needed */

		TAILQ_FOREACH(chk, &stcb->asoc.send_queue, sctp_next) {
			if ((chk->send_size+IP_HDR_SIZE) > nxtsz) {
				chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
			}
		}
		TAILQ_FOREACH(chk, &stcb->asoc.sent_queue, sctp_next) {
			if ((chk->send_size+IP_HDR_SIZE) > nxtsz) {
				/*
				 * For this guy we also mark for immediate
				 * resend since we sent to big of chunk
				 */
				chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
				chk->sent = SCTP_DATAGRAM_RESEND;
			}
		}
		TAILQ_FOREACH(strm, &stcb->asoc.out_wheel, next_spoke) {
			TAILQ_FOREACH(chk, &strm->outqueue, sctp_next) {
				if ((chk->send_size+IP_HDR_SIZE) > nxtsz) {
					chk->flags |= CHUNK_FLAGS_FRAGMENT_OK;
				}
			}
		}
	}
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, NULL);
}


void
sctp_notify(struct sctp_inpcb *inp,
	    int errno,
	    struct sctphdr *sh,
	    struct sockaddr *to,
	    struct sctp_tcb *tcb,
	    struct sctp_nets *net)
{
	/* protection */
	if ((inp == NULL) || (tcb == NULL) || (net == NULL) ||
	    (sh == NULL) || (to == NULL)) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("sctp-notify, bad call\n");
		}
#endif /* SCTP_DEBUG */
		return;
	}
	/* First job is to verify the vtag matches what I would send */
	if (ntohl(sh->v_tag) != (tcb->asoc.peer_vtag)) {
		return;
	}
	if ((errno == EHOSTUNREACH) || (errno == EHOSTDOWN)) {
		/*
		 * Here we will either abort the INIT (if we are forming
		 * an association) or mark the destination as down.
		 */
		if (((tcb->asoc.state & SCTP_STATE_MASK) ==
		     SCTP_STATE_COOKIE_WAIT) ||
		    ((tcb->asoc.state & SCTP_STATE_MASK) ==
		     SCTP_STATE_COOKIE_ECHOED)) {
			/*
			 * We have no alternative... the association can't
			 * be setup with the address we were given.
			 */
			sctp_abort_notification(tcb, SCTP_PEER_FAULTY);
			sctp_free_assoc(inp, tcb);
		} else {
			if (net->dest_state & SCTP_ADDR_REACHABLE) {
				/* Ok that destination is NOT reachable */
				net->dest_state &= ~SCTP_ADDR_REACHABLE;
				net->dest_state |= SCTP_ADDR_NOT_REACHABLE;
				net->error_count = net->failure_threshold + 1;
				sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
						tcb,
						SCTP_FAILED_THRESHOLD,
						(void *)net);
			}
		}
	} else {
		/* Send all others to the app */
		if (inp->sctp_socket) {
			inp->sctp_socket->so_error = errno;
			sctp_sowwakeup(inp, inp->sctp_socket);
		}
	}
}

#if defined(__FreeBSD__)
void
#else
void *
#endif
sctp_ctlinput(cmd, sa, vip)
	int cmd;
	struct sockaddr *sa;
	void *vip;
{
	struct ip *ip = vip;
	struct sctphdr *sh;
	int s;

	if (sa->sa_family != AF_INET ||
	    ((struct sockaddr_in *)sa)->sin_addr.s_addr == INADDR_ANY) {
#if defined(__FreeBSD__)
		return;
#else
		return(NULL);
#endif
	}

	if (PRC_IS_REDIRECT(cmd)) {
		ip = 0;
	} else if ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0) {
#if defined(__FreeBSD__)
		return;
#else
		return(NULL);
#endif
	}
	if (ip) {
		struct sctp_inpcb *inp;
		struct sctp_tcb *stcb;
		struct sctp_nets *netp;
		struct sockaddr_in to,from;

		sh = (struct sctphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		bzero(&to, sizeof(to));
		bzero(&from, sizeof(from));
		from.sin_family = to.sin_family = AF_INET;
		from.sin_family = to.sin_len = sizeof(to);
		from.sin_port = sh->src_port;
		from.sin_addr = ip->ip_src;
		to.sin_port = sh->dest_port;
		to.sin_addr = ip->ip_dst;
		/*
		 * 'to' will holds the destination of the packet that failed
		 * to be sent.
		 * 'from' holds our local endpoint address.
		 * Thus for our call we reverse the to and the from in the
		 * lookup.
		 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		s = splsoftnet();
#else
		s = splnet();
#endif
		stcb = sctp_findassociation_addr_sa((struct sockaddr *)&from,
						    (struct sockaddr *)&to,
						    &inp, &netp);

		if (stcb != NULL && inp && (inp->sctp_socket != NULL)) {
			if (cmd != PRC_MSGSIZE) {
				int cm;
				if (cmd == PRC_HOSTDEAD) {
					cm = EHOSTUNREACH;
				} else {
					cm = inet6ctlerrmap[cmd];
				}
				sctp_notify(inp, cm, sh,
					    (struct sockaddr *)&to, stcb,
					    netp);
			} else {
				/*
				 * Here we must handle possible ICMP size
				 * messages
				 */
				sctp_notify_mbuf(inp, stcb, netp, ip, sh);
			}
		} else {
			if (PRC_IS_REDIRECT(cmd) && inp) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
				s = splsoftnet();
#else
				s = splnet();
#endif
				in_rtchange((struct inpcb *)inp,
					    inetctlerrmap[cmd]);
			}
		}
		splx(s);
	}
#if defined(__FreeBSD__)
	return;
#else
	return(NULL);
#endif
}

#if defined(__FreeBSD__)
static int
sctp_pcblist(SYSCTL_HANDLER_ARGS)
{
	int error, i, n, s;
	struct inpcb *inp, **inp_list;
	struct sctp_inpcb *s_inp;
	inp_gen_t gencnt;
	struct xinpgen xig;

	if (req->oldptr == 0) {
		n = sctppcbinfo.ipi_count_ep;
		req->oldidx = 2 * (sizeof xig) + (n + n/8) *
			sizeof(struct xsctp_inpcb);
		return 0;
	}

	if (req->newptr != 0)
		return EPERM;

	/* OK, now we're committed to doing something. */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	gencnt = sctppcbinfo.ipi_gencnt_ep;
	n = sctppcbinfo.ipi_count_ep;
	splx(s);

	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error)
		return error;

	inp_list = malloc(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == 0)
		return ENOMEM;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	for (s_inp = sctppcbinfo.listhead.lh_first, i = 0;
	     s_inp && i < n;
	     s_inp = s_inp = s_inp->sctp_list.le_next) {
		inp = (struct inpcb *)s_inp;
		if (inp->inp_gencnt <= gencnt && !prison_xinpcb(req->p, inp))
			inp_list[i++] = inp;
	}
	splx(s);
	n = i;

	error = 0;
	s_inp = sctppcbinfo.listhead.lh_first;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		if (inp->inp_gencnt <= gencnt) {
			struct xsctp_inpcb xs;
			xs.xs_len = sizeof xs;
			/* XXX should avoid extra copy */
			bcopy(inp, &xs.xs_inp, sizeof *inp);
			if (s_inp != NULL) {
				struct sockaddr_in *sinfrom;
				struct sockaddr_in *sinto;
				struct sockaddr_in6 *sin6from;
				struct sockaddr_in6 *sin6to;
				struct sockaddr_storage to_store;
				struct sockaddr_storage from_store;
				struct sctp_nets *netp = NULL;
				struct sctp_tcb *scbp, scb;

				bcopy(s_inp, &xs.xs_sctp_inpcb,
				      sizeof xs.xs_sctp_inpcb);

				if (inp->inp_vflag == INP_IPV4) {
					sinto = (struct sockaddr_in *)&to_store;
					sinfrom = (struct sockaddr_in *)&from_store;
					sinto->sin_family = AF_INET;
					sinfrom->sin_family = AF_INET;
					sinto->sin_port = inp->inp_fport;
					sinto->sin_addr = inp->inp_faddr;
					sinfrom->sin_port = inp->inp_lport;
					sinfrom->sin_addr = inp->inp_laddr;
					scbp = sctp_findassociation_ep_addr(&s_inp, (struct sockaddr *)sinto, &netp, (struct sockaddr *)sinfrom);
				} else {
					sin6to = (struct sockaddr_in6 *)&to_store;
					sin6from = (struct sockaddr_in6 *)&from_store;
					sin6to->sin6_family = AF_INET6;
					sin6from->sin6_family = AF_INET6;
					sin6to->sin6_port = inp->inp_fport;
					sin6to->sin6_addr = inp->in6p_faddr;
					sin6from->sin6_port = inp->inp_fport;
					sin6to->sin6_addr = inp->in6p_faddr;
					scbp = sctp_findassociation_ep_addr(&s_inp, (struct sockaddr *)sin6to, &netp, (struct sockaddr *)sin6from);
				}
				if (scbp == NULL) {
					scb.asoc.state = SCTP_CLOSED;
					scbp = &scb;
				}
				bcopy(scbp, &xs.xs_sctp_tcb,
				      sizeof xs.xs_sctp_tcb);
			} else {
				bzero((char *) &xs.xs_sctp_inpcb,
				      sizeof xs.xs_sctp_inpcb);
				bzero((char *) &xs.xs_sctp_tcb,
				      sizeof xs.xs_sctp_tcb);
			}
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xs.xs_socket);
			error = SYSCTL_OUT(req, &xs, sizeof xs);
			s_inp = s_inp = s_inp->sctp_list.le_next;
		}
	}

	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
		s = splsoftnet();
#else
		s = splnet();
#endif
		xig.xig_gen = sctppcbinfo.ipi_gencnt_ep;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = sctppcbinfo.ipi_count_ep;
		splx(s);
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	free(inp_list, M_TEMP);
	return error;
}

SYSCTL_PROC(_net_inet_sctp, SCTPCTL_PCBLIST, pcblist, CTLFLAG_RD, 0, 0,
	    sctp_pcblist, "S,xinpcb", "List of active SCTP sockets");
#endif  /* #if defined(__FreeBSD__) */

#if defined(__FreeBSD__)
static int
sctp_getcred(SYSCTL_HANDLER_ARGS)
{
	struct sockaddr_in addrs[2];
	struct sctp_inpcb *inp;
	int error, s;

	error = suser(req->p);
	if (error)
		return (error);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	inp = sctp_pcb_findep((struct sockaddr *)&addrs[0]);
	if (inp == NULL || inp->sctp_socket == NULL) {
		error = ENOENT;
		goto out;
	}
	error = SYSCTL_OUT(req, inp->sctp_socket->so_cred, sizeof(struct ucred));
 out:
	splx(s);
	return (error);
}


SYSCTL_PROC(_net_inet_sctp, OID_AUTO, getcred, CTLTYPE_OPAQUE|CTLFLAG_RW,
	    0, 0, sctp_getcred, "S,ucred", "Get the ucred of a SCTP connection");

#endif /* #if defined(__FreeBSD__) */

u_long	sctp_sendspace = (32 * 1024);	/* really max datagram size */
/* 64 1K datagrams */
#if defined(__FreeBSD__)
SYSCTL_INT(_net_inet_sctp, SCTPCTL_MAXDGRAM, maxdgram, CTLFLAG_RW,
	   &sctp_sendspace, 0, "Maximum outgoing SCTP datagram size");
#endif

u_long	sctp_recvspace = 64 * (1024 +
#ifdef INET6
			       sizeof(struct sockaddr_in6)
#else
			       sizeof(struct sockaddr_in)
#endif
			       );

#if defined(__FreeBSD__)
SYSCTL_INT(_net_inet_sctp, SCTPCTL_RECVSPACE, recvspace, CTLFLAG_RW,
	   &sctp_recvspace, 0,"Maximum incoming SCTP datagram size");
#endif


static int
sctp_abort(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;	/* ??? possible? panic instead? */
	soisdisconnected(so);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	sctp_inpcb_free(inp,1);
	splx(s);
	return 0;
}

static int
sctp_attach(struct socket *so, int proto, struct proc *p)
{
	struct sctp_inpcb *inp;
	struct inpcb *ip_inp;
	int s, error;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp != 0)
		return EINVAL;

	error = soreserve(so, sctp_sendspace, sctp_recvspace);
	if (error)
		return error;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	error = sctp_inpcb_alloc(so);

	splx(s);
	if (error)
		return error;

	inp = (struct sctp_inpcb *)so->so_pcb;
	inp->sctp_flags &= ~SCTP_PCB_FLAGS_BOUND_V6;	/* I'm not v6! */
	ip_inp = &inp->ip_inp.inp;
#ifndef __FreeBSD__
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ip_defttl;
#else
	ip_inp->inp_vflag |= INP_IPV4;
	ip_inp->inp_ip_ttl = ip_defttl;
#endif

#ifdef IPSEC
#ifndef __OpenBSD__
	error = ipsec_init_pcbpolicy(so, &ip_inp->inp_sp);
	if (error != 0) {
		sctp_inpcb_free(inp,1);
		return error;
	}
#endif
#endif /*IPSEC*/
	return 0;
}

static int
sctp_bind(struct socket *so, struct sockaddr *addr, struct proc *p)
{
	struct sctp_inpcb *inp;
	int s, error;

#ifdef INET6
	if (addr->sa_family != AF_INET)
		/* must be a v4 address! */
		return EINVAL;
#endif /* INET6 */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	error = sctp_inpcb_bind(so, addr, p);
	splx(s);
	return error;
}


static int
sctp_detach(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	sctp_inpcb_free(inp,0);
	splx(s);
	return 0;
}

static int
sctp_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	  struct mbuf *control, struct proc *p)
{
	struct sctp_inpcb *inp;
	int error;
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		if (control) {
			m_freem(control);
			control = NULL;
		}
		m_freem(m);
		return EINVAL;
	}
	/* Got to have an to address if we are NOT a connected socket */
	if ((addr == NULL) &&
	   (((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == SCTP_PCB_FLAGS_CONNECTED) ||
	    ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) == SCTP_PCB_FLAGS_TCPTYPE))) {
		return sctp_output(inp, m, addr, control, p);
	} else if (addr == NULL) {
		error = EDESTADDRREQ;
		m_freem(m);
		if (control) {
			m_freem(control);
			control = NULL;
		}
		return(error);
	}
#ifdef INET6
	if (addr->sa_family != AF_INET) {
		/* must be a v4 address! */
		m_freem(m);
		if (control) {
			m_freem(control);
			control = NULL;
		}
		error = EDESTADDRREQ;
		return EINVAL;
	}
#endif /* INET6 */

	return sctp_output(inp, m, addr, control, p);
}

static int
sctp_disconnect(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		return(ENOTCONN);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		if (LIST_EMPTY(&inp->sctp_asoc_list)) {
			/* No connection */
			splx(s);
			return(ENOTCONN);
		} else {
			int some_on_streamwheel = 0;
			struct sctp_association *asoc;
			struct sctp_tcb *tcb;

			tcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (tcb == NULL)
				return(EINVAL);

			asoc = &tcb->asoc;
			if (!TAILQ_EMPTY(&asoc->out_wheel)) {
				/* Check to see if some data queued */
				struct sctp_stream_out *outs;
				TAILQ_FOREACH(outs, &asoc->out_wheel,
					      next_spoke) {
					if (!TAILQ_EMPTY(&outs->outqueue)) {
						some_on_streamwheel = 1;
						break;
					}
				}
			}

			if (TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue) &&
			    (some_on_streamwheel == 0)) {
				/* there is nothing queued to send, so done */
				if ((asoc->state & SCTP_STATE_MASK) !=
				    SCTP_STATE_SHUTDOWN_SENT) {
				/* only send SHUTDOWN 1st time thru */
					sctp_send_shutdown(tcb,
							   tcb->asoc.primary_destination);
					asoc->state = SCTP_STATE_SHUTDOWN_SENT;
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN,
							 tcb->sctp_ep, tcb,
							 asoc->primary_destination);
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD,
							 tcb->sctp_ep, tcb,
							 asoc->primary_destination);
				}
			} else {
				/*
				 * we still got (or just got) data to send,
				 * so set SHUTDOWN_PENDING
				 */
				/*
				 * XXX sockets draft says that MSG_EOF should
				 * be sent with no data.
				 * currently, we will allow user data to be
				 * sent first and move to SHUTDOWN-PENDING
				 */
				asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
			}
			return(0);
		}
	} else {
		/* UDP model does not support this */
		return EOPNOTSUPP;
	}
}

int
sctp_shutdown(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

	/* For UDP model this is a invalid call */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) {
		/* Restore the flags that the soshutdown took away. */
		so->so_state &= ~SS_CANTRCVMORE;
		/* This proc will wakeup for read and do nothing (I hope) */
		splx(s);
		return(EOPNOTSUPP);
	}
#ifdef SCTP_TCP_MODEL_SUPPORT
	/*
	 * Ok if we reach here its the TCP model and it is either a SHUT_WR
	 * or SHUT_RDWR. This means we put the shutdown flag against it.
	 */
	{
		int some_on_streamwheel = 0;
		struct sctp_tcb *tcb;
		struct sctp_association *asoc;
		socantsendmore(so);

		tcb = LIST_FIRST(&inp->sctp_asoc_list);
		if (tcb == NULL) {
			/* Ok we hit the case that the shutdown
			 * call was made after an abort or something.
			 * Nothing to do now.
			 */
			return(0);
		}
		asoc = &tcb->asoc;

		if (!TAILQ_EMPTY(&asoc->out_wheel)) {
			/* Check to see if some data queued */
			struct sctp_stream_out *outs;
			TAILQ_FOREACH(outs, &asoc->out_wheel, next_spoke) {
				if (!TAILQ_EMPTY(&outs->outqueue)) {
					some_on_streamwheel = 1;
					break;
				}
			}
		}
		if (TAILQ_EMPTY(&asoc->send_queue) &&
		    TAILQ_EMPTY(&asoc->sent_queue) &&
		    (some_on_streamwheel == 0)) {
			/* there is nothing queued to send, so I'm done... */
			if ((asoc->state & SCTP_STATE_MASK) !=
			    SCTP_STATE_SHUTDOWN_SENT) {
				/* only send SHUTDOWN the first time through */
				sctp_send_shutdown(tcb,
						   tcb->asoc.primary_destination);
				asoc->state = SCTP_STATE_SHUTDOWN_SENT;
				sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN,
						 tcb->sctp_ep, tcb,
						 asoc->primary_destination);
				sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD,
						 tcb->sctp_ep, tcb,
						 asoc->primary_destination);
			}
		} else {
			/*
			 * we still got (or just got) data to send, so
			 * set SHUTDOWN_PENDING
			 */
			asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
		}
	}
	splx(s);
	return 0;
#endif
	splx(s);
	return(EOPNOTSUPP);
}

/*
 * copies a "user" presentable address
 * removes embedded scope, etc.
 * returns 0 on success, 1 on error
 */
static uint32_t
sctp_fill_user_address(struct sockaddr_storage *ss, struct sockaddr *sa)
{
	struct sockaddr_in6 lsa6;
	sa = (struct sockaddr *)sctp_recover_scope((struct sockaddr_in6 *)sa,
						   &lsa6);
	memcpy(ss, sa, sa->sa_len);
	return(0);
}


static int
sctp_fill_up_addresses(struct sctp_inpcb *inp,
		       struct sctp_tcb *tcb,
		       int limit,
		       struct sockaddr_storage *sas)
{
	struct ifnet *ifn;
	struct ifaddr *ifa;
	int loopback_scope, ipv4_local_scope, local_scope, site_scope, actual;
	actual = 0;
	if (limit <= 0)
		return(actual);

	if (tcb) {
		/* Turn on all the appropriate scope */
		loopback_scope = tcb->asoc.loopback_scope;
		ipv4_local_scope = tcb->asoc.ipv4_local_scope;
		local_scope = tcb->asoc.local_scope;
		site_scope = tcb->asoc.site_scope;
	} else {
		/* Turn on ALL scope, since we look at the EP */
		loopback_scope = ipv4_local_scope = local_scope =
			site_scope = 1;
	}

	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		TAILQ_FOREACH(ifn, &ifnet, if_list) {
			if ((loopback_scope == 0) &&
			    (ifn->if_type == IFT_LOOP)) {
				/* Skip loopback if loopback_scope not set */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if (tcb) {
				/*
				 * For the BOUND-ALL case, the list
				 * associated with a TCB is Always
				 * considered a reverse list.. i.e.
				 * it lists addresses that are NOT
				 * part of the association. If this
				 * is one of those we must skip it.
				 */
					if (sctp_is_addr_restricted(tcb,
								    ifa->ifa_addr)) {
						continue;
					}
				}
				if (ifa->ifa_addr->sa_family == AF_INET) {
					struct sockaddr_in *sin;
					sin = (struct sockaddr_in *)ifa->ifa_addr;
					if (sin->sin_addr.s_addr == 0) {
						/* we skip unspecifed addresses */
						continue;
					}
					if ((ipv4_local_scope == 0) &&
					    (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr))) {
						continue;
					}
					memcpy(sas, sin, sizeof(*sin));
					sas = (struct sockaddr_storage *)((caddr_t)sas + sizeof(*sin));
					actual += sizeof(*sin);
					if (actual >= limit) {
						return(actual);
					}
				} else if (ifa->ifa_addr->sa_family ==
					   AF_INET6) {
					struct sockaddr_in6 *sin6, lsa6;
					sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
						/* we skip unspecifed addresses */
						continue;
					}
					if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
						if (local_scope == 0)
							continue;
						if (sin6->sin6_scope_id == 0) {
							lsa6 = *sin6;
							if (in6_recoverscope(&lsa6,
									     &lsa6.sin6_addr,
									     NULL))
								/* bad link local address */
								continue;
							sin6 = &lsa6;
						}
					}
					if ((site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr))) {
						continue;
					}
					memcpy(sas, sin6, sizeof(*sin6));
					sas = (struct sockaddr_storage *)((caddr_t)sas + sizeof(*sin6));
					actual += sizeof(*sin6);
					if (actual >= limit) {
						return(actual);
					}
				}
			}
		}
	} else {
		struct sctp_laddr *laddr;
		/*
		 * If we have a TCB and we do NOT support ASCONF (it's
		 * turned off or otherwise) then the list is always the
		 * true list of addresses (the else case below).  Otherwise
		 * the list on the association is a list of addresses that
		 * are NOT part of the association.
		 */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) {
			/* The list is a NEGATIVE list */
			LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
				if (tcb) {
					if (sctp_is_addr_restricted(tcb, laddr->ifa->ifa_addr)) {
						continue;
					}
				}
				if (sctp_fill_user_address(sas, laddr->ifa->ifa_addr))
					continue;
				sas = (struct sockaddr_storage *)((caddr_t)sas +
								  laddr->ifa->ifa_addr->sa_len);
				actual += laddr->ifa->ifa_addr->sa_len;
				if (actual >= limit) {
					return(actual);
				}
			}
		} else {
			/* The list is a positive list if present */
			if (tcb) {
				/* Must use the specific association list */
				LIST_FOREACH(laddr, &tcb->asoc.sctp_local_addr_list,
					     sctp_nxt_addr) {
					if (sctp_fill_user_address(sas,
								   laddr->ifa->ifa_addr))
						continue;
					sas = (struct sockaddr_storage *)((caddr_t)sas +
									  laddr->ifa->ifa_addr->sa_len);
					actual += laddr->ifa->ifa_addr->sa_len;
					if (actual >= limit) {
						return(actual);
					}
				}
			} else {
				/* No endpoint so use the endpoints individual list */
				LIST_FOREACH(laddr, &inp->sctp_addr_list,
					     sctp_nxt_addr) {
					if (sctp_fill_user_address(sas,
								   laddr->ifa->ifa_addr))
						continue;
					sas = (struct sockaddr_storage *)((caddr_t)sas +
									  laddr->ifa->ifa_addr->sa_len);
					actual += laddr->ifa->ifa_addr->sa_len;
					if (actual >= limit) {
						return(actual);
					}
				}
			}
		}
	}
	return(actual);
}

static int
sctp_count_max_addresses(struct sctp_inpcb *inp)
{
	int cnt = 0;
	/*
	 * In both sub-set bound an bound_all cases we return the MAXIMUM
	 * number of addresses that you COULD get. In reality the sub-set
	 * bound may have an exclusion list for a given TCB OR in the
	 * bound-all case a TCB may NOT include the loopback or other
	 * addresses as well.
	 */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		struct ifnet *ifn;
		struct ifaddr *ifa;

		TAILQ_FOREACH(ifn, &ifnet, if_list) {
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				/* Count them if they are the right type */
				if (ifa->ifa_addr->sa_family == AF_INET)
					cnt += sizeof(struct sockaddr_in);
				else if (ifa->ifa_addr->sa_family == AF_INET6)
					cnt += sizeof(struct sockaddr_in6);
			}
		}
	} else {
		struct sctp_laddr *laddr;
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			cnt += laddr->ifa->ifa_addr->sa_len;
		}
	}
	return(cnt);
}

extern int sctp_cwnd_posts[SCTP_CWND_POSTS_LIST];
extern int sctp_cwnd_old[SCTP_CWND_POSTS_LIST];
extern long sctp_onqueue[SCTP_CWND_POSTS_LIST];
extern int sctp_chunksout[SCTP_CWND_POSTS_LIST];
extern char sctp_wherefrom[SCTP_CWND_POSTS_LIST];
extern int sctp_rwndval[SCTP_CWND_POSTS_LIST];
extern int sctp_post_at;



static int
sctp_optsget(struct socket *so,
	     int opt,
	     struct mbuf **mp)
{
	struct sctp_inpcb *inp;
	struct mbuf *m;
	int error, optval=0;
	struct sctp_tcb *tcb;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;
	error = 0;

	if (mp == NULL) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("optsget:MP is NULL EINVAL\n");
		}
#endif /* SCTP_DEBUG */
		return(EINVAL);
	}
	m = *mp;
	if (m == NULL) {
		/* Got to have a mbuf */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("Huh no mbuf\n");
		}
#endif /* SCTP_DEBUG */
		return(EINVAL);
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_USRREQ2) {
		printf("optsget opt:%lxx sz:%u\n", (unsigned long)opt,
		       m->m_len);
	}
#endif /* SCTP_DEBUG */

	switch(opt) {
	case SCTP_NODELAY:
	case SCTP_AUTOCLOSE:
	case SCTP_DISABLE_FRAGMENTS:
	case SCTP_I_WANT_MAPPED_V4_ADDR:
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ2) {
			printf("other stuff\n");
		}
#endif /* SCTP_DEBUG */
		switch(opt) {
		case SCTP_DISABLE_FRAGMENTS:
			optval = inp->sctp_flags & SCTP_PCB_FLAGS_NO_FRAGMENT;
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
			optval = inp->sctp_flags & SCTP_I_WANT_MAPPED_V4_ADDR;
			break;
		case SCTP_NODELAY:
			optval = inp->sctp_flags & SCTP_PCB_FLAGS_NODELAY;
			break;
		case SCTP_AUTOCLOSE:
			if ((inp->sctp_flags & SCTP_PCB_FLAGS_AUTOCLOSE) ==
			    SCTP_PCB_FLAGS_AUTOCLOSE)
				optval = inp->sctp_ep.auto_close_time;
			else
				optval = 0;
			break;

		default:
			error = ENOPROTOOPT;
		} /* end switch(sopt->sopt_name) */
		if (opt != SCTP_AUTOCLOSE) {
			/* make it an "on/off" value */
			optval = (optval != 0);
		}
		if (m->m_len < sizeof(int)) {
			error = EINVAL;
		}
		if (error == 0) {
			/* return the option value */
			*mtod(m, int *) = optval;
		}
		break;
	case SCTP_GET_SNDBUF_USE:
		if (m->m_len < sizeof(struct sctp_sockstat)) {
			error = EINVAL;
		} else {
			struct sctp_sockstat *ss;
			struct sctp_tcb *tcb;
			struct sctp_association *asoc;
			ss = mtod(m,struct sctp_sockstat *);

			tcb = sctp_findassociation_associd(ss->ss_assoc_id);
			if (tcb == NULL) {
				error = ENOTCONN;
			} else {
				asoc = &tcb->asoc;
				ss->ss_total_sndbuf = (u_int32_t)asoc->total_output_queue_size;
				ss->ss_total_mbuf_sndbuf = (u_int32_t)asoc->total_output_mbuf_queue_size;
				ss->ss_total_recv_buf = (u_int32_t)(asoc->size_on_delivery_queue +
								    asoc->size_on_reasm_queue +
								    asoc->size_on_all_streams);
				error = 0;
			}
		}
		break;
	case SCTP_PRINT_CWND_UPDATES:
	{
		int i;
		for (i = sctp_post_at; i < SCTP_CWND_POSTS_LIST; i++) {
			printf("old:%d->new:%d onQueue:%d sent:%d from:%d rwnd:%d\n",
			       sctp_cwnd_old[i],
			       sctp_cwnd_posts[i],
			       (int)sctp_onqueue[i],
			       sctp_chunksout[i],
			       (int)sctp_wherefrom[i],
			       sctp_rwndval[i]
				);
		}
		for (i = 0; i < sctp_post_at; i++) {
			printf("old:%d->new:%d onQueue:%d sent:%d from:%d rwnd:%d\n",
			       sctp_cwnd_old[i],
			       sctp_cwnd_posts[i],
			       (int)sctp_onqueue[i],
			       sctp_chunksout[i],
			       (int)sctp_wherefrom[i],
			       sctp_rwndval[i]
				);
		}
	}
	break;
	case SCTP_SET_DEBUG_LEVEL:
#ifdef SCTP_DEBUG
	{
		u_int32_t *level;
		if (m->m_len < sizeof(u_int32_t)) {
			error = EINVAL;
			break;
		}
		level = mtod(m, u_int32_t *);
		error = 0;
		*level = sctp_debug_on;
		printf("Returning DEBUG LEVEL %x is set\n",
		       (u_int)sctp_debug_on);
	}
#else /* SCTP_DEBUG */
	error = EOPNOTSUPP;
#endif
	break;
	case SCTP_GET_PEGS:
	{
		u_int32_t *pt;
		if (m->m_len < sizeof(sctp_pegs)) {
			error = EINVAL;
			break;
		}
		pt = mtod(m, u_int32_t *);
		memcpy(pt, sctp_pegs, sizeof(sctp_pegs));
	}
	break;
	case SCTP_SET_EVENTS:
	{
		struct sctp_event_subscribe *events;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ2) {
			printf("get events\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_event_subscribe)) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ2) {
				printf("M->M_LEN is %d not %d\n",
				       (int)m->m_len,
				       (int)sizeof(struct sctp_event_subscribe));
			}
#endif /* SCTP_DEBUG */
			error = EINVAL;
			break;
		}
		events = mtod(m,struct sctp_event_subscribe *);
		memset(events, 0, sizeof(events));

		if (inp->sctp_flags & SCTP_PCB_FLAGS_RECVDATAIOEVNT)
			events->sctp_data_io_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_RECVASSOCEVNT)
			events->sctp_association_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_RECVPADDREVNT)
			events->sctp_address_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_RECVSENDFAILEVNT)
			events->sctp_send_failure_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_RECVPEERERR)
			events->sctp_peer_error_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT)
			events->sctp_shutdown_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_PDAPIEVNT)
			events->sctp_partial_delivery_event = 1;

		if (inp->sctp_flags & SCTP_PCB_FLAGS_ADAPTIONEVNT)
			events->sctp_adaption_layer_event = 1;

	}
	break;

	case SCTP_SET_ADAPTION_LAYER_BITS:
		if (m->m_len < sizeof(int)) {
			error = EINVAL;
			break;
		}
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("getadaption ind\n");
		}
#endif /* SCTP_DEBUG */
		*mtod(m, int *) = inp->sctp_ep.adaption_layer_indicator;
		break;
	case SCTP_SET_INITIAL_DBG_SEQ:
		if (m->m_len < sizeof(int)) {
			error = EINVAL;
			break;
		}
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("get initial dbg seq\n");
		}
#endif /* SCTP_DEBUG */
		*mtod(m, int *) = inp->sctp_ep.initial_sequence_debug;
		break;
	case SCTP_GET_LOCAL_ADDR_SIZE:
		if (m->m_len < sizeof(int)) {
			error = EINVAL;
			break;
		}
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("get local sizes\n");
		}
#endif /* SCTP_DEBUG */
		*mtod(m, int *) = sctp_count_max_addresses(inp);
		break;
	case SCTP_GET_REMOTE_ADDR_SIZE:
	{
		sctp_assoc_t *assoc_id;
		u_int32_t *val, sz;
		struct sctp_nets *net;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("get remote size\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(sctp_assoc_t)) {
			printf("no len\n");
			error = EINVAL;
			break;
		}
		assoc_id = mtod(m, sctp_assoc_t *);
		val = mtod(m, u_int32_t *);
		printf("Looking at assoc id %lx\n",
		       (unsigned long)assoc_id);
		tcb = sctp_findassociation_ep_asocid(inp, *assoc_id);
		if (tcb == NULL) {
			printf("no tcb\n");
			error = EINVAL;
			break;
		}
		*val = 0;
		sz = 0;
		/* Count the sizes */
		TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
			if (((struct sockaddr *)&net->ra._l_addr)->sa_family == AF_INET) {
				sz += sizeof(struct sockaddr_in);
				printf("Adding a size for ipv4 now %d\n",sz);
			} else {
				sz += sizeof(struct sockaddr_in6);
				printf("Adding a size for ipv6 now %d\n",sz);
			}
		}
		printf("Final return is sz:%d\n", sz);
		*val = sz;
	}
	break;
	case SCTP_GET_PEER_ADDRESSES:
		/*
		 * Get the address information, an array of sockaddr_storage
		 * is passed in to fill up.
		 */
	{
		int cpsz, left;
		struct sockaddr_storage *sas;
		struct sctp_nets *net;
		struct sctp_getaddresses *saddr;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("get peer addresses\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_getaddresses)) {
			error = EINVAL;
			break;
		}
		left = m->m_len - sizeof(struct sctp_getaddresses);
		saddr = mtod(m,struct sctp_getaddresses *);
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp,
							     saddr->sget_assoc_id);
		if (tcb == NULL) {
			error = ENOENT;
			break;
		}
		m->m_len = sizeof(struct sctp_getaddresses);
		sas = (struct sockaddr_storage *)&saddr->addr[0];
		TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
			if (((struct sockaddr *)&net->ra._l_addr)->sa_family == AF_INET) {
				cpsz = sizeof(struct sockaddr_in);
			} else {
				cpsz = sizeof(struct sockaddr_in6);
			}
			if (left < cpsz) {
				/* not enough room. */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
					printf("Out of room\n");
				}
#endif /* SCTP_DEBUG */
				break;
			}
			memcpy(sas,&net->ra._l_addr,cpsz);
			sas = (struct sockaddr_storage *)((caddr_t)sas + cpsz);
			left -= cpsz;
			m->m_len += cpsz;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ2) {
				printf("left now:%d mlen:%d\n",
				       left,m->m_len);
			}
#endif /* SCTP_DEBUG */
		}
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
		printf("All done\n");
	}
#endif /* SCTP_DEBUG */
	break;
	case SCTP_GET_LOCAL_ADDRESSES:
	{
		int limit, actual;
		struct sockaddr_storage *sas;
		struct sctp_getaddresses *saddr;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("get local addresses\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_getaddresses)) {
			error = EINVAL;
			break;
		}
		saddr = mtod(m, struct sctp_getaddresses *);

		if (saddr->sget_assoc_id) {
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_asocid(inp, saddr->sget_assoc_id);
		} else {
			tcb = NULL;
		}
		sas = (struct sockaddr_storage *)&saddr->addr[0];
		limit = m->m_len - sizeof(sctp_assoc_t);
		actual = sctp_fill_up_addresses(inp, tcb, limit, sas);
		m->m_len = sizeof(struct sockaddr_storage) + actual;
	}
	break;
	case SCTP_SET_PEER_ADDR_PARAMS:
	case SCTP_GET_PEER_ADDR_PARAMS:
	{
		struct sctp_paddrparams *paddrp;
		struct sctp_nets *netp;

#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("Getting peer_addr_params\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_paddrparams)) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ2) {
				printf("Hmm m->m_len:%d is to small\n",
				       m->m_len);
			}
#endif /* SCTP_DEBUG */
			error = EINVAL;
			break;
		}
		paddrp = mtod(m, struct sctp_paddrparams *);

		netp = NULL;
		if ((((struct sockaddr *)&paddrp->spp_address)->sa_family == AF_INET) ||
		    (((struct sockaddr *)&paddrp->spp_address)->sa_family == AF_INET6)) {
				/* Lookup via address */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
				printf("Ok we need to lookup a param\n");
			}
#endif /* SCTP_DEBUG */
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_addr(&inp,
								   (struct sockaddr *)&paddrp->spp_address,
								   &netp,
								   NULL);
			if (tcb == NULL) {
				error = ENOENT;
				break;
			}
		} else if (paddrp->spp_assoc_id) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
				printf("In spp_assoc_id find type\n");
			}
#endif /* SCTP_DEBUG */
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_asocid(inp, paddrp->spp_assoc_id);
			if (tcb == NULL) {
				error = ENOENT;
				break;
			}
		} else {
			/* Effects the Endpoint */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
				printf("User wants EP level info\n");
			}
#endif /* SCTP_DEBUG */
			tcb = NULL;
		}
		if (tcb) {
			/* Applys to the specific association */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
				printf("In TCB side\n");
			}
#endif /* SCTP_DEBUG */
			if (netp) {
				paddrp->spp_pathmaxrxt = netp->failure_threshold;
			} else {
				/* No destination so return default value */
				paddrp->spp_pathmaxrxt = tcb->asoc.def_net_failure;
			}
			paddrp->spp_hbinterval = tcb->asoc.heart_beat_delay;
			paddrp->spp_assoc_id = (sctp_assoc_t)(tcb);
		} else {
			/* Use endpoint defaults */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
				printf("In EP levle info\n");
			}
#endif /* SCTP_DEBUG */
			paddrp->spp_pathmaxrxt = inp->sctp_ep.def_net_failure;
			paddrp->spp_hbinterval = inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_HEARTBEAT];
			paddrp->spp_assoc_id = (sctp_assoc_t)0;
		}
	}
	break;
	case SCTP_GET_PEER_ADDR_INFO:
	{
		struct sctp_paddrinfo *paddri;
		struct sctp_nets *netp;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("GetPEER ADDR_INFO\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_paddrinfo)) {
			error = EINVAL;
			break;
		}
		paddri = mtod(m,struct sctp_paddrinfo *);
		netp = NULL;
		if ((((struct sockaddr *)&paddri->spinfo_address)->sa_family == AF_INET) ||
		    (((struct sockaddr *)&paddri->spinfo_address)->sa_family == AF_INET6)) {
				/* Lookup via address */
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_addr(&inp,
								   (struct sockaddr *)&paddri->spinfo_address,
								   &netp, NULL);
		} else {
			tcb = NULL;
		}
		if ((tcb == NULL) || (netp == NULL)) {
			error = ENOENT;
			break;
		}
		paddri->spinfo_state = netp->dest_state;
		paddri->spinfo_cwnd = netp->cwnd;
		paddri->spinfo_srtt = netp->lastsa;
		paddri->spinfo_rto = netp->RTO;
		paddri->spinfo_assoc_id = (sctp_assoc_t)tcb;
	}
	break;
	case SCTP_PCB_STATUS:
	{
		struct sctp_pcbinfo *spcb;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("PCB status\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_pcbinfo)) {
			error = EINVAL;
			break;
		}
		spcb = mtod(m,struct sctp_pcbinfo *);
		sctp_fill_pcbinfo(spcb);
	}
	break;
	case SCTP_STATUS:
	{
		struct sctp_nets *net;
		struct sctp_status *sstat;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("SCTP status\n");
		}
#endif /* SCTP_DEBUG */

		if (m->m_len < sizeof(struct sctp_status)) {
			error = EINVAL;
			break;
		}
		sstat = mtod(m,struct sctp_status *);
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, sstat->sstat_assoc_id);
		if (tcb == NULL) {
			error = EINVAL;
			break;
		}
		/*
		 * I think passing the state is fine since
		 * sctp_constants.h will be available to the user
		 * land.
		 */
		sstat->sstat_state = tcb->asoc.state;
		sstat->sstat_rwnd = tcb->asoc.peers_rwnd;
		sstat->sstat_unackdata = tcb->asoc.sent_queue_cnt;
		/*
		 * We can't include chunks that have been passed
		 * to the socket layer. Only things in queue.
		 */
		sstat->sstat_penddata = (tcb->asoc.cnt_on_delivery_queue +
					 tcb->asoc.cnt_on_reasm_queue +
					 tcb->asoc.cnt_on_all_streams);


		sstat->sstat_instrms = tcb->asoc.streamincnt;
		sstat->sstat_outstrms = tcb->asoc.streamoutcnt;
		sstat->sstat_fragmentation_point = tcb->asoc.smallest_mtu;

		memcpy(&sstat->sstat_primary.spinfo_address,
		       &tcb->asoc.primary_destination->ra._l_addr,
		       ((struct sockaddr *)(&tcb->asoc.primary_destination->ra._l_addr))->sa_len);
		net = tcb->asoc.primary_destination;
		/*
		 * Again the user can get info from sctp_constants.h
		 * for what the state of the network is.
		 */
		sstat->sstat_primary.spinfo_state = net->dest_state;
		sstat->sstat_primary.spinfo_cwnd = net->cwnd;
		sstat->sstat_primary.spinfo_srtt = net->lastsa;
		sstat->sstat_primary.spinfo_rto = net->RTO;
		sstat->sstat_primary.spinfo_mtu = net->mtu;
		sstat->sstat_primary.spinfo_assoc_id = (sctp_assoc_t)tcb;
	}
	break;
	case SCTP_RTOINFO:
	{
		struct sctp_rtoinfo *srto;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("RTO Info\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_rtoinfo)) {
			error = EINVAL;
			break;
		}
		srto = mtod(m,struct sctp_rtoinfo *);
		if (srto->srto_assoc_id == 0) {
				/* Endpoint only please */
			srto->srto_initial = inp->sctp_ep.initial_rto;
			srto->srto_max = inp->sctp_ep.sctp_maxrto;
			srto->srto_min = inp->sctp_ep.sctp_minrto;
			break;
		}
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, srto->srto_assoc_id);
		if (tcb == NULL) {
			error = EINVAL;
			break;
		}
		srto->srto_initial = tcb->asoc.initial_rto;
		srto->srto_max = inp->sctp_ep.sctp_maxrto;
		srto->srto_min = inp->sctp_ep.sctp_minrto;
	}
	break;
	case SCTP_ASSOCINFO:
	{
		struct sctp_assocparams *sasoc;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("Associnfo\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_assocparams)) {
			error = EINVAL;
			break;
		}
		sasoc = mtod(m,struct sctp_assocparams *);
		if (sasoc->sasoc_assoc_id) {
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_asocid(inp,
								     sasoc->sasoc_assoc_id);
			if (tcb == NULL) {
				error = ENOENT;
				break;
			}
		} else {
			tcb = NULL;
		}
		if (tcb) {
			sasoc->sasoc_asocmaxrxt = tcb->asoc.max_send_times;
			sasoc->sasoc_number_peer_destinations = tcb->asoc.numnets;
			sasoc->sasoc_peer_rwnd = tcb->asoc.peers_rwnd;
			sasoc->sasoc_local_rwnd = tcb->asoc.my_rwnd;
			sasoc->sasoc_cookie_life = tcb->asoc.cookie_life;
		} else {
			sasoc->sasoc_asocmaxrxt = inp->sctp_ep.max_send_times;
			sasoc->sasoc_number_peer_destinations = 0;
			sasoc->sasoc_peer_rwnd = 0;
			sasoc->sasoc_local_rwnd = sbspace(&inp->sctp_socket->so_rcv);
			sasoc->sasoc_cookie_life = inp->sctp_ep.def_cookie_life;
		}
	}
	break;
	case SCTP_DEFAULT_SEND_PARAM:
	{
		struct sctp_sndrcvinfo *s_info;

		if (m->m_len != sizeof(struct sctp_sndrcvinfo)) {
			error = EINVAL;
			break;
		}
		s_info = mtod(m,struct sctp_sndrcvinfo *);
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp,s_info->sinfo_assoc_id);
		if (tcb == NULL) {
			error = ENOENT;
			break;
		}
		/* Copy it out */
		*s_info = tcb->asoc.def_send;
	}
	case SCTP_INITMSG:
	{
		struct sctp_initmsg *sinit;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("initmsg\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_initmsg)) {
			error = EINVAL;
			break;
		}
		sinit = mtod(m, struct sctp_initmsg *);
		sinit->sinit_num_ostreams = inp->sctp_ep.pre_open_stream_count;
		sinit->sinit_max_instreams = inp->sctp_ep.max_open_streams_intome;
		sinit->sinit_max_attempts = inp->sctp_ep.max_init_times;
		sinit->sinit_max_init_timeo = inp->sctp_ep.initial_init_rto_max;
	}
	break;
	case SCTP_SET_PRIMARY_ADDR:
		/* we allow a "get" operation on this */
	{
		struct sctp_setprim *ssp;

#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("setprimary\n");
		}
#endif /* SCTP_DEBUG */
		if (m->m_len < sizeof(struct sctp_setprim)) {
			error = EINVAL;
			break;
		}
		ssp = mtod(m, struct sctp_setprim *);
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, ssp->ssp_assoc_id);
		if (tcb == NULL) {
				/* one last shot, try it by the address in */
			struct sctp_nets *netp;
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif
				tcb = sctp_findassociation_ep_addr(&inp,
								   (struct sockaddr *)&ssp->ssp_addr,
								   &netp,NULL);
			if (tcb == NULL) {
				error = EINVAL;
				break;
			}
		}
				/* simply copy out the sockaddr_storage... */
		memcpy(&ssp->ssp_addr,
		       &tcb->asoc.primary_destination->ra._l_addr,
		       ((struct sockaddr *)&tcb->asoc.primary_destination->ra._l_addr)->sa_len);

	}
	break;
	case SCTP_SET_PEER_PRIMARY_ADDR:
		/*
		 * FIX: How can we know what his primary is?
		 * I don't see anyway to know this!!
		 */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("Huh how do I get peer primary\n");
		}
#endif /* SCTP_DEBUG */
		break;
	default:
		error = ENOPROTOOPT;
		break;
	} /* end switch(sopt->sopt_name) */
	return(error);
}

static int
sctp_optsset(struct socket *so,
	     int opt,
	     struct mbuf **mp)
{
	int error, *mopt, set_opt;
	struct mbuf *m;
	struct sctp_tcb *tcb;
	struct sctp_inpcb *inp;

	if (mp == NULL) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("optsset:MP is NULL EINVAL\n");
		}
#endif /* SCTP_DEBUG */
		return(EINVAL);
	}
	m = *mp;
	if (m == NULL)
		return(EINVAL);

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

	error = 0;
	switch(opt) {
	case SCTP_NODELAY:
	case SCTP_AUTOCLOSE:
	case SCTP_DISABLE_FRAGMENTS:
	case SCTP_I_WANT_MAPPED_V4_ADDR:
		/* copy in the option value */
		if (m->m_len < sizeof(int)) {
			error = EINVAL;
			break;
		}
		mopt = mtod(m,int *);
		set_opt = 0;
		if (error)
			break;
		switch(opt) {
		case SCTP_DISABLE_FRAGMENTS:
			set_opt = SCTP_PCB_FLAGS_NO_FRAGMENT;
			break;
		case SCTP_I_WANT_MAPPED_V4_ADDR:
			if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
				set_opt = SCTP_PCB_FLAGS_NEEDS_MAPPED_V4;
			} else {
				return(EINVAL);
			}
			break;
		case SCTP_NODELAY:
			set_opt = SCTP_PCB_FLAGS_NODELAY;
			break;
		case SCTP_AUTOCLOSE:
			set_opt = SCTP_PCB_FLAGS_AUTOCLOSE;
			/*
			 * The value is in ticks.
			 * Note this does not effect old associations, only
			 * new ones.
			 */
			inp->sctp_ep.auto_close_time = *mopt;
			break;
		}
		if (*mopt != 0) {
			inp->sctp_flags |= set_opt;
		} else {
			inp->sctp_flags &= ~set_opt;
		}
		break;
	case SCTP_LIST_IN_STREAMS:
	{
		struct sctp_tcb *tcb;
		struct sctp_stream_in *strm;
		struct sctp_tmit_chunk *chk;
		int i,cnt;
		struct sctp_association *asoc;
		LIST_FOREACH(tcb, &inp->sctp_asoc_list, sctp_tcblist) {
			asoc = &tcb->asoc;
			for (i = 0; i < asoc->streamincnt; i++) {
				strm = &asoc->strmin[i];
				cnt = 0;
				TAILQ_FOREACH(chk, &strm->inqueue,
					      sctp_next) {
					cnt++;
				}
				if (cnt) {
					printf("Assoc:%lx stream:%d has %d chunks in queue\n",
					       (unsigned long)tcb, i,
					       cnt);

				}
			}
		}
	}
	break;
	case SCTP_DUMP_SEND_T_Q:
	{
		struct sctp_tcb *tcb;
		struct sctp_tmit_chunk *chk;
		struct sctp_association *asoc;
		if (LIST_EMPTY(&inp->sctp_asoc_list)) {
			printf("Nothing to dump\n");
			break;
		}
		LIST_FOREACH(tcb, &inp->sctp_asoc_list, sctp_tcblist) {
			asoc = &tcb->asoc;
			printf("Assoc %lx send_queue\n",
			       (unsigned long)asoc);
			TAILQ_FOREACH(chk, &asoc->send_queue,
				      sctp_next) {
				printf("chk:%lx TSN:%x sent:%d snd_count:%d sz:%d\n",
				       (unsigned long)chk,
				       chk->rec.data.TSN_seq,
				       chk->sent,
				       chk->snd_count,
				       chk->send_size);
			}
			printf("Assoc %lx sent_queue\n",
			       (unsigned long)asoc);
			TAILQ_FOREACH(chk, &asoc->sent_queue,
				      sctp_next) {
				printf("chk:%lx TSN:%x sent:%d snd_count:%d sz:%d\n",
				       (unsigned long)chk,
				       chk->rec.data.TSN_seq,
				       chk->sent,
				       chk->snd_count,
				       chk->send_size);
			}
		}
	}
	case SCTP_LIST_DELIVERY_Q:
	{
		struct sctp_tcb *tcb;
		struct sctp_association *asoc;
		if (TAILQ_EMPTY(&inp->sctp_queue_list)) {
			printf("Those awaiting events is empty\n");
		} else {
			TAILQ_FOREACH(tcb, &inp->sctp_queue_list,
				      sctp_toqueue) {
				printf("Assoc:%lx is waiting on the socket\n",
				       (unsigned long)tcb);
			}
		}
		printf("Socket stats:\n");
		printf("cc:%d hiwat:%d lowat:%d mbcnt:%d mbmax:%d\n",
		       (int)inp->sctp_socket->so_rcv.sb_cc,
		       (int)inp->sctp_socket->so_rcv.sb_hiwat,
		       (int)inp->sctp_socket->so_rcv.sb_lowat,
		       (int)inp->sctp_socket->so_rcv.sb_mbcnt,
		       (int)inp->sctp_socket->so_rcv.sb_mbmax);
		LIST_FOREACH(tcb, &inp->sctp_asoc_list, sctp_tcblist) {
			asoc = &tcb->asoc;
			printf("tcb:%lx has %d on dq (%d sz) rwnd:%d\n",
			       (unsigned long)tcb,
			       (int)asoc->cnt_on_delivery_queue,
			       (int)asoc->size_on_delivery_queue,
			       (int)asoc->my_rwnd);
		}
	}
	break;
	case SCTP_PRINT_A_STREAM:
	{
		struct sctp_tcb *tcb;
		struct sctp_stream_in *strm;
		struct sctp_tmit_chunk *chk;
		struct sctp_association *asoc;
		int cnt,*num;

		num = mtod(m, int *);
		if (*num < 0) {
			error = EINVAL;
			break;
		}
		if (m->m_len < sizeof(int)) {
			error = EINVAL;
			break;
		}
		LIST_FOREACH(tcb, &inp->sctp_asoc_list, sctp_tcblist) {
			asoc = &tcb->asoc;
			strm = &asoc->strmin[*num];
			if (*num >asoc->streamincnt) {
				continue;
			}
			cnt = 0;
			TAILQ_FOREACH(chk, &strm->inqueue, sctp_next) {
				printf("Chunk[%d] ssn:%d tsn:%x sz:%d(%d) flgs:%x\n",
				       cnt,
				       chk->rec.data.stream_seq,
				       chk->rec.data.TSN_seq,
				       chk->send_size,
				       chk->book_size,
				       chk->rec.data.rcv_flags);
				cnt++;
			}
		}

	}
	break;
	case SCTP_SET_DEBUG_LEVEL:
#ifdef SCTP_DEBUG
	{
		u_int32_t *level;
		if (m->m_len < sizeof(u_int32_t)) {
			error = EINVAL;
			break;
		}
		level = mtod(m,u_int32_t *);
		error = 0;
		sctp_debug_on = (*level & (SCTP_DEBUG_ALL |
					   SCTP_DEBUG_NOISY));
		printf("SETTING DEBUG LEVEL to %x\n",
		       (u_int)sctp_debug_on);

	}
#else
	error = EOPNOTSUPP;
#endif /* SCTP_DEBUG */
	break;
	case SCTP_SET_EVENTS:
	{
		struct sctp_event_subscribe *events;
		if (m->m_len < sizeof(struct sctp_event_subscribe)) {
			error = EINVAL;
			break;
		}
		events = mtod(m,struct sctp_event_subscribe *);
		if (events->sctp_data_io_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_RECVDATAIOEVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_RECVDATAIOEVNT;
		}

		if (events->sctp_association_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_RECVASSOCEVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_RECVASSOCEVNT;
		}

		if (events->sctp_address_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_RECVPADDREVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_RECVPADDREVNT;
		}

		if (events->sctp_send_failure_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_RECVSENDFAILEVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_RECVSENDFAILEVNT;
		}

		if (events->sctp_peer_error_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_RECVPEERERR;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_RECVPEERERR;
		}

		if (events->sctp_shutdown_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT;
		}

		if (events->sctp_partial_delivery_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_PDAPIEVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_PDAPIEVNT;
		}

		if (events->sctp_adaption_layer_event) {
			inp->sctp_flags |= SCTP_PCB_FLAGS_ADAPTIONEVNT;
		} else {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_ADAPTIONEVNT;
		}
	}
	break;

	case SCTP_SET_ADAPTION_LAYER_BITS:
	{
		struct sctp_setadaption *adap_bits;
		if (m->m_len < sizeof(struct sctp_setadaption)) {
			error = EINVAL;
			break;
		}
		adap_bits = mtod(m, struct sctp_setadaption *);
		inp->sctp_ep.adaption_layer_indicator = adap_bits->ssb_adaption_ind;
	}
	break;
	case SCTP_SET_INITIAL_DBG_SEQ:
	{
		u_int32_t *vvv;
		if (m->m_len < sizeof(u_int32_t)) {
			error = EINVAL;
			break;
		}
		vvv = mtod(m, u_int32_t *);
		inp->sctp_ep.initial_sequence_debug = *vvv;
	}
	break;
	case SCTP_DEFAULT_SEND_PARAM:
	{
		struct sctp_sndrcvinfo *s_info;

		if (m->m_len != sizeof(struct sctp_sndrcvinfo)) {
			error = EINVAL;
			break;
		}
		s_info = mtod(m, struct sctp_sndrcvinfo *);
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, s_info->sinfo_assoc_id);
		if (tcb == NULL) {
			error = ENOENT;
			break;
		}
		/* Validate things */
		if (s_info->sinfo_stream > tcb->asoc.streamoutcnt) {
			error = EINVAL;
			break;
		}
		/* Mask off the flags that are allowed */
		s_info->sinfo_flags = (s_info->sinfo_flags &
				       (MSG_UNORDERED | MSG_ADDR_OVER |
					MSG_PR_SCTP | MSG_PR_BUFFER));
		/* Copy it in */
		tcb->asoc.def_send = *s_info;
	}
	break;
	case SCTP_SET_PEER_ADDR_PARAMS:
	case SCTP_GET_PEER_ADDR_PARAMS:
	{
		struct sctp_paddrparams *paddrp;
		struct sctp_nets *netp;
		if (m->m_len < sizeof(struct sctp_paddrparams)) {
			error = EINVAL;
			break;
		}
		paddrp = mtod(m, struct sctp_paddrparams *);
		netp = NULL;
		if ((((struct sockaddr *)&paddrp->spp_address)->sa_family == AF_INET) ||
		    (((struct sockaddr *)&paddrp->spp_address)->sa_family == AF_INET6)) {
				/* Lookup via address */
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif
				tcb = sctp_findassociation_ep_addr(&inp,
								   (struct sockaddr *)&paddrp->spp_address,
								   &netp, NULL);
			if (tcb == NULL) {
				error = ENOENT;
				break;
			}
		} else if (paddrp->spp_assoc_id) {
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_asocid(inp, paddrp->spp_assoc_id);
			if (tcb == NULL) {
				error = ENOENT;
				break;
			}
		} else {
				/* Effects the Endpoint */
			tcb = NULL;
		}
		if (tcb) {
				/* Applys to the specific association */
			if (paddrp->spp_pathmaxrxt) {
				if (netp) {
					if (paddrp->spp_pathmaxrxt)
						netp->failure_threshold = paddrp->spp_pathmaxrxt;
				} else {
					if (paddrp->spp_pathmaxrxt)
						tcb->asoc.def_net_failure = paddrp->spp_pathmaxrxt;
				}
			}
			if ((paddrp->spp_hbinterval != 0) && (paddrp->spp_hbinterval != 0xffffffff)) {
				/* Just a set */
				int old;
				if (netp) {
					netp->dest_state &= ~SCTP_ADDR_NOHB;
				} else {
					old = tcb->asoc.heart_beat_delay;
					tcb->asoc.heart_beat_delay = paddrp->spp_hbinterval;
					if (old == 0) {
				/* Turn back on the timer */
						sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, tcb, netp);
					}
				}
			} else if (paddrp->spp_hbinterval == 0xffffffff) {
				/* on demand HB */
				sctp_send_hb(tcb,1,netp);
			} else {
				if (netp == NULL) {
					/* off on association */
					if (tcb->asoc.heart_beat_delay)
						sctp_timer_stop(SCTP_TIMER_TYPE_HEARTBEAT, inp, tcb, netp);
					tcb->asoc.heart_beat_delay = 0;
				} else {
					netp->dest_state |= SCTP_ADDR_NOHB;
				}
			}
		} else {
				/* Use endpoint defaults */
			if (paddrp->spp_pathmaxrxt)
				inp->sctp_ep.def_net_failure = paddrp->spp_pathmaxrxt;
			if (paddrp->spp_hbinterval)
				inp->sctp_ep.sctp_timeoutticks[SCTP_TIMER_HEARTBEAT] = paddrp->spp_hbinterval;
		}
	}
	break;
	case SCTP_RTOINFO:
	{
		struct sctp_rtoinfo *srto;
		if (m->m_len < sizeof(struct sctp_rtoinfo)) {
			error = EINVAL;
			break;
		}
		srto = mtod(m, struct sctp_rtoinfo *);
		if (srto->srto_assoc_id == 0) {
			/* If we have a null assoc, its for the endpoint */
			if (srto->srto_initial > 10)
				inp->sctp_ep.initial_rto = srto->srto_initial;
			if (srto->srto_max > 10)
				inp->sctp_ep.sctp_maxrto = srto->srto_max;
			if (srto->srto_min > 10)
				inp->sctp_ep.sctp_minrto = srto->srto_min;
			break;
		}
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, srto->srto_assoc_id);
		if (tcb == NULL) {
			error = EINVAL;
			break;
		}
		/* Set in ms we hope :-) */
		if (srto->srto_initial > 10)
			tcb->asoc.initial_rto = srto->srto_initial;
		if (srto->srto_max > 10)
			inp->sctp_ep.sctp_maxrto = srto->srto_max;
		if (srto->srto_min > 10)
			inp->sctp_ep.sctp_minrto = srto->srto_min;
	}
	break;
	case SCTP_ASSOCINFO:
	{
		struct sctp_assocparams *sasoc;

		if (m->m_len < sizeof(struct sctp_assocparams)) {
			error = EINVAL;
			break;
		}
		sasoc = mtod(m, struct sctp_assocparams *);
		if (sasoc->sasoc_assoc_id) {
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_asocid(inp,
								     sasoc->sasoc_assoc_id);
			if (tcb == NULL) {
				error = ENOENT;
				break;
			}

		} else {
			tcb = NULL;
		}
		if (tcb) {
			if (sasoc->sasoc_asocmaxrxt)
				tcb->asoc.max_send_times = sasoc->sasoc_asocmaxrxt;
			sasoc->sasoc_number_peer_destinations = tcb->asoc.numnets;
			sasoc->sasoc_peer_rwnd = 0;
			sasoc->sasoc_local_rwnd = 0;
			if (tcb->asoc.cookie_life)
				tcb->asoc.cookie_life = sasoc->sasoc_cookie_life;
		} else {
			if (sasoc->sasoc_asocmaxrxt)
				inp->sctp_ep.max_send_times = sasoc->sasoc_asocmaxrxt;
			sasoc->sasoc_number_peer_destinations = 0;
			sasoc->sasoc_peer_rwnd = 0;
			sasoc->sasoc_local_rwnd = 0;
			if (sasoc->sasoc_cookie_life)
				inp->sctp_ep.def_cookie_life = sasoc->sasoc_cookie_life;
		}
	}
	break;
	case SCTP_INITMSG:
	{
		struct sctp_initmsg *sinit;

		if (m->m_len < sizeof(struct sctp_initmsg)) {
			error = EINVAL;
			break;
		}
		sinit = mtod(m, struct sctp_initmsg *);
		if (sinit->sinit_num_ostreams)
			inp->sctp_ep.pre_open_stream_count = sinit->sinit_num_ostreams;

		if (sinit->sinit_max_instreams)
			inp->sctp_ep.max_open_streams_intome = sinit->sinit_max_instreams;

		if (sinit->sinit_max_attempts)
			inp->sctp_ep.max_init_times = sinit->sinit_max_attempts;

		if (sinit->sinit_max_init_timeo > 10)
				/* We must be at least a 100ms (we set in ticks) */
			inp->sctp_ep.initial_init_rto_max = sinit->sinit_max_init_timeo;
	}
	break;
	case SCTP_SET_PRIMARY_ADDR:
	{
		struct sctp_setprim *spa;
		struct sctp_nets *net,*lnet;
		if (m->m_len < sizeof(struct sctp_setprim)) {
			error = EINVAL;
			break;
		}
		spa = mtod(m,struct sctp_setprim *);

#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, spa->ssp_assoc_id);
		if (tcb == NULL) {
				/* One last shot */
#ifdef SCTP_TCP_MODEL_SUPPORT
			if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
				tcb = LIST_FIRST(&inp->sctp_asoc_list);
			else
#endif /* SCTP_TCP_MODEL_SUPPORT */
				tcb = sctp_findassociation_ep_addr(&inp,
								   (struct sockaddr *)&spa->ssp_addr,
								   &net, NULL);
			if (tcb == NULL) {
				error = EINVAL;
				break;
			}
		} else {
			net = sctp_findnet(tcb,(struct sockaddr *)&spa->ssp_addr);
			if (net == NULL) {
				error = EINVAL;
				break;
			}
		}
		if (net != tcb->asoc.primary_destination) {
				/* Ok we need to set it */
			lnet = tcb->asoc.primary_destination;
			lnet->next_tsn_at_change = net->next_tsn_at_change = tcb->asoc.sending_seq;
			if (net->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
				net->dest_state |= SCTP_ADDR_DOUBLE_SWITCH;
			}
			net->dest_state |= SCTP_ADDR_SWITCH_PRIMARY;
				/* Now set in the new primary */
			tcb->asoc.primary_destination = net;
		}
	}
	break;
	case SCTP_SET_PEER_PRIMARY_ADDR:
	{
		struct sctp_setpeerprim *sspp;
		if (m->m_len < sizeof(struct sctp_setpeerprim)) {
			error = EINVAL;
			break;
		}
		sspp = mtod(m, struct sctp_setpeerprim *);

#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
		else
#endif /* SCTP_TCP_MODEL_SUPPORT */
			tcb = sctp_findassociation_ep_asocid(inp, sspp->sspp_assoc_id);
		if (tcb == NULL) {
			error = EINVAL;
			break;
		}
		if (sctp_set_primary_addr(tcb, (struct sockaddr *)&sspp->sspp_addr) != 0) {
			error = EINVAL;
			break;
		}
	}
	break;
	case SCTP_BINDX_ADD_ADDR:
	{
		struct sctp_getaddresses *addrs;

		/* see if we're bound all already! */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
			error = EINVAL;
			break;
		}
		if (m->m_len < sizeof(struct sctp_getaddresses)) {
			error = EINVAL;
			break;
		}
		addrs = mtod(m, struct sctp_getaddresses *);
		if (addrs->sget_assoc_id == 0) {
				/* add the address */
			error = sctp_addr_mgmt_ep_sa(inp, addrs->addr,
						     SCTP_ADD_IP_ADDRESS);
		} else {
				/* FIX: decide whether we allow assoc based bindx */
		}
	}
	break;
	case SCTP_BINDX_REM_ADDR:
	{
		struct sctp_getaddresses *addrs;
		/* see if we're bound all already! */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
			error = EINVAL;
			break;
		}
		if (m->m_len < sizeof(struct sctp_getaddresses)) {
			error = EINVAL;
			break;
		}
		addrs = mtod(m, struct sctp_getaddresses *);
		if (addrs->sget_assoc_id == 0) {
				/* delete the address */
			sctp_addr_mgmt_ep_sa(inp, addrs->addr,
					     SCTP_DEL_IP_ADDRESS);
		} else {
				/* FIX: decide whether we allow assoc based bindx */
		}
	}
	break;
	default:
		error = ENOPROTOOPT;
		break;
	} /* end switch(opt) */
	return(error);
}


#if defined(__FreeBSD__)

int
sctp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct mbuf *m=NULL;
	struct sctp_inpcb *inp;
	int s, error;

	inp = (struct sctp_inpcb *)so->so_pcb;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (inp == 0) {
		splx(s);
		/* I made the same as TCP since we are not setup? */
		return(ECONNRESET);
	}
	if (sopt->sopt_level != IPPROTO_SCTP) {
		/* wrong proto level... send back up to IP */
#ifdef INET6
		if (INP_CHECK_SOCKAF(so, AF_INET6))
			error = ip6_ctloutput(so, sopt);
		else
#endif /* INET6 */
			error = ip_ctloutput(so, sopt);
		splx(s);
		return(error);
	}
	if (sopt->sopt_valsize > MCLBYTES) {
		/*
		 * Restrict us down to a cluster size, that's all we can
		 * pass either way...
		 */
		sopt->sopt_valsize = MCLBYTES;
	}
	if (sopt->sopt_valsize) {

		m = m_get(M_WAIT, MT_DATA);
		if (sopt->sopt_valsize > MLEN) {
			MCLGET(m, M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_freem(m);
				splx(s);
				return (ENOBUFS);
			}
		}
		error = sooptcopyin(sopt, mtod(m, caddr_t), sopt->sopt_valsize,
				    sopt->sopt_valsize);
		if (error) {
			(void) m_free(m);
			goto out;
		}
		m->m_len = sopt->sopt_valsize;
	}
	if (sopt->sopt_dir == SOPT_SET) {
		error = sctp_optsset(so, sopt->sopt_name, &m);
	} else if (sopt->sopt_dir == SOPT_GET) {
		error = sctp_optsget(so, sopt->sopt_name, &m);
	} else {
		error = EINVAL;
	}
	if (m != NULL) {
		error = sooptcopyout(sopt, mtod(m, caddr_t), m->m_len);
		m_freem(m);
	}
 out:
	splx(s);
	return(error);
}

#else
/* NetBSD and OpenBSD */
int
sctp_ctloutput(op, so, level, optname, mp)
     int op;
     struct socket *so;
     int level, optname;
     struct mbuf **mp;
{
	int s, error;
	struct inpcb *inp;
#ifdef INET6
	struct in6pcb *in6p;
#endif
	int family;	/* family of the socket */

	family = so->so_proto->pr_domain->dom_family;
	error = 0;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	switch (family) {
	case PF_INET:
		inp = sotoinpcb(so);
#ifdef INET6
		in6p = NULL;
#endif
		break;
#ifdef INET6
	case PF_INET6:
		inp = NULL;
		in6p = sotoin6pcb(so);
		break;
#endif
	default:
		splx(s);
		return EAFNOSUPPORT;
	}
#ifndef INET6
	if (inp == NULL)
#else
		if (inp == NULL && in6p == NULL)
#endif
		{
			splx(s);
			if (op == PRCO_SETOPT && *mp)
				(void) m_free(*mp);
			return (ECONNRESET);
		}
	if (level != IPPROTO_SCTP) {
		switch (family) {
		case PF_INET:
			error = ip_ctloutput(op, so, level, optname, mp);
			break;
#ifdef INET6
		case PF_INET6:
			error = ip6_ctloutput(op, so, level, optname, mp);
			break;
#endif
		}
		splx(s);
		return (error);
	}
	/* Ok if we reach here it is a SCTP option we hope */
	if (op == PRCO_SETOPT) {
		error = sctp_optsset(so, optname, mp);
		if (*mp)
			(void) m_free(*mp);
	} else if (op ==  PRCO_GETOPT) {
		error = sctp_optsget(so, optname, mp);
	} else {
		error = EINVAL;
	}
	splx(s);
	return(error);
}

#endif

static int
sctp_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif
	int error = 0;
	struct sctp_inpcb *inp;
	struct sctp_tcb *tcb;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
	        printf("Connect called in SCTP to ");
		sctp_print_address(nam);
                printf("Port %d\n",ntohs(((struct sockaddr_in *)nam)->sin_port));
	}
#endif /* SCTP_DEBUG */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		splx(s);
		/* I made the same as TCP since we are not setup? */
		return(ECONNRESET);
	}
#ifdef INET6
	if (((inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) == 0) &&
	    (nam->sa_family == AF_INET6)) {
		splx(s);
		return(EINVAL);
	}
#endif /* INET6 */
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) ==
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* Bind a ephemeral port */
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		error = sctp_inpcb_bind(so, (struct sockaddr *)&sin, p);
		if (error) {
			splx(s);
			return(error);
		}
	}
	/* Now do we connect? */

#ifdef SCTP_TCP_MODEL_SUPPORT
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
		splx(s);
		return(EADDRINUSE);
	}
#endif /* SCTP_TCP_MODEL_SUPPORT */
#ifdef SCTP_TCP_MODEL_SUPPORT
	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
		tcb = LIST_FIRST(&inp->sctp_asoc_list);
	else
#endif /* SCTP_TCP_MODEL_SUPPORT */
		tcb = sctp_findassociation_ep_addr(&inp, nam, NULL, NULL);

	if (tcb != NULL) {
		/* Already have or am bring up an association */
		splx(s);
		return(EALREADY);
	}
	/* We are GOOD to go */
	tcb = sctp_aloc_assoc(inp, nam, 1, &error);
	if (tcb == NULL) {
		/* Gak! no memory */
		splx(s);
#ifdef SCTP_DEBUG
		printf("Can't allocate a TCB?\n");
#endif
		return(error);
	}
#ifdef SCTP_TCP_MODEL_SUPPORT
	if (tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		tcb->sctp_ep->sctp_flags |= SCTP_PCB_FLAGS_CONNECTED;
		/* Set the connected flag so we can queue data */
		so->so_state |= SS_ISCONNECTED;
	}
#endif
	tcb->asoc.state = SCTP_STATE_COOKIE_WAIT;
	SCTP_GETTIME_TIMEVAL(&tcb->asoc.time_entered);
	sctp_send_initiate(inp, tcb);
	splx(s);
	return error;
}

int
sctp_usr_recvd(struct socket *so, int flags)
{
	int s;
	/*
	 * The user has received some data, we may be able to stuff more
	 * up the socket. And we need to possibly update the rwnd.
	 */
	struct sctp_inpcb *inp;
	struct sctp_tcb *tcb;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		splx(s);
		/* I made the same as TCP since we are not setup? */
		return(ECONNRESET);
	}
	/*
	 * Grab the first one on the list. It will re-insert itself if
	 * it runs out of room
	 */
	tcb = TAILQ_FIRST(&inp->sctp_queue_list);
	if (tcb) {
		/*
		 * Question: should we go further than just the first
		 * entry? By only doing one assoc we limit how long we
		 * spend here.
		 */
		u_int32_t rwnd;
		rwnd = tcb->asoc.my_rwnd;

		TAILQ_REMOVE(&inp->sctp_queue_list, tcb, sctp_toqueue);
		tcb->on_toqueue = 0;

		sctp_service_queues(tcb, &tcb->asoc);
		sctp_set_rwnd(tcb, &tcb->asoc);
		/* if we increase by 1 or more MTU's (smallest MTUs of all nets)
		 * we send a window update sack
		 */
		if (tcb->asoc.my_rwnd >= (rwnd + tcb->asoc.smallest_mtu)) {
			if (callout_pending(&tcb->asoc.dack_timer.timer)) {
				/* If the timer is up, stop it */
				sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
						tcb->sctp_ep, tcb, NULL);
			}
			/* Send the sack, with the new rwnd */
			sctp_send_sack(tcb);
			/* Now do the output */
			sctp_chunk_output(inp, tcb, 10);
		}
	}
	splx(s);
	return(0);
}

int
sctp_listen(struct socket *so, struct proc *p)
{
	/*
	 * Note this module depends on the protocol processing being
	 * called AFTER any socket level flags and backlog are applied
	 * to the socket. The traditional way that the socket flags are
	 * applied is AFTER protocol processing. We have made a change
	 * to the sys/kern/uipc_socket.c module to reverse this but this
	 * MUST be in place if the socket API for SCTP is to work properly.
	 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif
	int error = 0;
	struct sctp_inpcb *inp;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		splx(s);
		/* I made the same as TCP since we are not setup? */
		return(ECONNRESET);
	}
#ifdef SCTP_TCP_MODEL_SUPPORT
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
		splx(s);
		return(EADDRINUSE);
	}
#endif /* SCTP_TCP_MODEL_SUPPORT */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) {
		/* We must do a bind. */
		if ((error = sctp_inpcb_bind(so, (struct sockaddr *)NULL,
					     p))) {
			/* bind error, probably perm */
			splx(s);
			return(error);
		}
	}
	if (inp->sctp_socket->so_qlimit) {
		if (inp->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) {
			/*
			 * For the UDP model we must TURN OFF the ACCEPT
			 * flags since we do NOT allow the accept() call.
			 * The TCP model (when present) will do accept which
			 * then prohibits connect().
			 */
			inp->sctp_socket->so_options &= ~SO_ACCEPTCONN;
		}
		inp->sctp_flags |= SCTP_PCB_FLAGS_ACCEPTING;
	} else {
		if (inp->sctp_flags & SCTP_PCB_FLAGS_ACCEPTING) {
			/*
			 * Turning off the listen flags if the backlog is
			 * set to 0 (i.e. qlimit is 0).
			 */
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_ACCEPTING;
			inp->sctp_socket->so_options &= ~SO_ACCEPTCONN;
		}
	}
	splx(s);
	return(error);
}

int
sctp_accept(struct socket *so,
#if defined(__FreeBSD__)
	    struct sockaddr **nam
#else
	    struct sockaddr *nam
#endif
	    )
{
#ifdef SCTP_TCP_MODEL_SUPPORT
#if defined(__NetBSD__) || defined(__OpenBSD__)
	int s = splsoftnet();
#else
	int s = splnet();
#endif
	struct sctp_tcb *tcb;
	struct sockaddr *prim;
	struct sctp_inpcb *inp;

	inp = (struct sctp_inpcb *)so->so_pcb;

	if (inp == 0) {
		splx(s);
		return(ECONNRESET);
	}
	if (so->so_state & SS_ISDISCONNECTED) {
		splx(s);
		return(ECONNABORTED);
	}
	if (inp == 0) {
		splx(s);
		return (EINVAL);
	}
	tcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (tcb == NULL) {
		splx(s);
		return(ECONNRESET);
	}
	prim = (struct sockaddr *)&tcb->asoc.primary_destination->ra._l_addr;
	if (prim->sa_family == AF_INET) {
		struct sockaddr_in *sin;
#if defined(__FreeBSD__)
		MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME,
		       M_WAITOK | M_ZERO);
#else
		sin = (struct sockaddr_in *)nam;
		bzero((caddr_t)sin, sizeof (*sin));
#endif
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_port = ((struct sockaddr_in *)prim)->sin_port;
		sin->sin_addr = ((struct sockaddr_in *)prim)->sin_addr;
#if defined(__FreeBSD__)
		*nam = (struct sockaddr *)sin;
#endif
	} else {
		struct sockaddr_in6 *sin6;
#if defined(__FreeBSD__)
		MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6, M_SONAME,
		       M_WAITOK | M_ZERO);
#else
		sin6 = (struct sockaddr_in6 *)nam;
#endif
		bzero((caddr_t)sin6, sizeof (*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_port = ((struct sockaddr_in6 *)prim)->sin6_port;

		sin6->sin6_addr = ((struct sockaddr_in6 *)prim)->sin6_addr;
		if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
			/*      sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);*/
			in6_recoverscope(sin6, &sin6->sin6_addr, NULL);  /* skip ifp check */
		else
			sin6->sin6_scope_id = 0;	/*XXX*/
#if defined(__FreeBSD__)
		*nam = (struct sockaddr *)sin6;
#endif
	}
	/* Wake any delayed sleep action */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) {
		inp->sctp_flags &= ~SCTP_PCB_FLAGS_DONT_WAKE;
		if (inp->sctp_flags & SCTP_PCB_FLAGS_WAKEOUTPUT) {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_WAKEOUTPUT;
			if (sowriteable(inp->sctp_socket))
				sowwakeup(inp->sctp_socket);
		}
		if (inp->sctp_flags & SCTP_PCB_FLAGS_WAKEINPUT) {
			inp->sctp_flags &= ~SCTP_PCB_FLAGS_WAKEINPUT;
			if (soreadable(inp->sctp_socket))
				sorwakeup(inp->sctp_socket);
		}
	}
	splx(s);
	return(0);
#else
	/* No TCP model, we don't support accept then */
	return(EOPNOTSUPP);
#endif
}

int
sctp_ingetaddr(struct socket *so,
#if defined(__FreeBSD__)
	       struct sockaddr **nam
#else
	       struct sockaddr *nam
#endif
	       )
{
	int s;
	register struct sockaddr_in *sin;
	struct sctp_inpcb *inp;
	/*
	 * Do the malloc first in case it blocks.
	 */
#if defined(__FreeBSD__)
	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME, M_WAITOK |
	       M_ZERO);
#else
	sin = (struct sockaddr_in *)nam;
	memset(sin,0,sizeof(*sin));
#endif
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (!inp) {
		splx(s);
#if defined(__FreeBSD__)
		free(sin, M_SONAME);
#endif
		return ECONNRESET;
	}
	sin->sin_port = inp->sctp_lport;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* For the bound all case you get back 0 */
		sin->sin_addr.s_addr = 0;
	} else {
		/* Take the first IPv4 address in the list */
		struct sctp_laddr *laddr;
		int fnd = 0;
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sin_a;
				sin_a = (struct sockaddr_in *)laddr->ifa->ifa_addr;
				sin->sin_addr = sin_a->sin_addr;
				fnd = 1;
				break;
			}
		}
		if (!fnd) {
			splx(s);
#if defined(__FreeBSD__)
			free(sin, M_SONAME);
#endif
			return ENOENT;
		}
	}
	splx(s);
#if defined(__FreeBSD__)
	*nam = (struct sockaddr *)sin;
#endif
	return(0);
}

int
sctp_peeraddr(struct socket *so,
#if defined(__FreeBSD__)
	      struct sockaddr **nam
#else
	      struct sockaddr *nam
#endif
	      )
{
	int s, fnd;
	register struct sockaddr_in *sin, *sin_a;
	struct sctp_inpcb *inp;
	struct sctp_tcb *tcb;
	struct sctp_nets *net;

	/* Do the malloc first in case it blocks. */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0) {
		/* UDP type and listeners will drop out here */
		return(ENOTCONN);
	}
#if defined(__FreeBSD__)
	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME, M_WAITOK |
	       M_ZERO);
#else
	sin = (struct sockaddr_in *)nam;
	memset(sin,0,sizeof(*sin));
#endif
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* We must recapture incase we blocked */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (!inp) {
		splx(s);
#if defined(__FreeBSD__)
		free(sin, M_SONAME);
#endif
		return ECONNRESET;
	}
	tcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (tcb == NULL) {
		splx(s);
#if defined(__FreeBSD__)
		free(sin, M_SONAME);
#endif
		return ECONNRESET;
	}
	fnd = 0;
	TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
		sin_a = (struct sockaddr_in *)&net->ra._l_addr;
		if (sin_a->sin_family == AF_INET) {
			fnd = 1;
			sin->sin_port = tcb->rport;
			sin->sin_addr = sin_a->sin_addr;
			break;
		}
	}
	if (!fnd) {
		/* No IPv4 address */
		splx(s);
#if defined(__FreeBSD__)
		free(sin, M_SONAME);
#endif
		return ENOENT;
	}
	splx(s);
#if defined(__FreeBSD__)
	*nam = (struct sockaddr *)sin;
#endif
	return(0);
}

#if defined(__FreeBSD__)
struct pr_usrreqs sctp_usrreqs = {
	sctp_abort, sctp_accept, sctp_attach, sctp_bind, sctp_connect,
	pru_connect2_notsupp, in_control, sctp_detach, sctp_disconnect,
	sctp_listen, sctp_peeraddr, sctp_usr_recvd, pru_rcvoob_notsupp,
	sctp_send, pru_sense_null, sctp_shutdown, sctp_ingetaddr, sosend,
	soreceive, sopoll
};

#else
#if defined(__NetBSD__)
int
sctp_usrreq(so, req, m, nam, control, p)
     struct socket *so;
     int req;
     struct mbuf *m, *nam, *control;
     struct proc *p;
#else
int
sctp_usrreq(so, req, m, nam, control)
     struct socket *so;
     int req;
     struct mbuf *m, *nam, *control;
#endif
{
	int s;
	int error = 0;
	int family;

	family = so->so_proto->pr_domain->dom_family;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (req == PRU_CONTROL) {
		switch (family) {
		case PF_INET:
			error = in_control(so, (long)m, (caddr_t)nam,
					   (struct ifnet *)control
#if defined(__NetBSD__)
					   , p
#endif
				);
			break;
#ifdef INET6
		case PF_INET6:
			error = in6_control(so, (long)m, (caddr_t)nam,
					    (struct ifnet *)control
#if defined(__NetBSD__)
					    , p
#else
					    , (struct proc *)0
#endif
				);
			break;
#endif
		default:
			error =  EAFNOSUPPORT;
		}
		splx(s);
		return(error);
	}
#ifdef __NetBSD__
	if (req == PRU_PURGEIF) {
		struct ifnet *ifn;
		struct ifaddr *ifa;
		ifn = (struct ifnet *)control;
		TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
			if (ifa->ifa_addr->sa_family == family) {
				sctp_delete_ip_address(ifa);
			}
		}
		switch (family) {
		case PF_INET:
			in_purgeif (ifn);
			break;
#ifdef INET6
		case PF_INET6:
			in6_purgeif (ifn);
			break;
#endif /* INET6 */
		default:
			splx(s);
			return (EAFNOSUPPORT);
		}
		splx(s);
		return (0);
	}
#endif
	switch (req) {
	case PRU_ATTACH:
		error = sctp_attach(so, family
#if defined(__NetBSD__)
				    , p
#else
				    , (struct proc *)NULL
#endif
			);
		break;
	case PRU_DETACH:
		error = sctp_detach(so);
		break;
	case PRU_BIND:
	{
		struct sockaddr *name;
		if (nam)
			name = mtod(nam, struct sockaddr *);
		else
			return(EINVAL);
		error  = sctp_bind(so, name
#if defined(__NetBSD__)
				   , p
#else
				   , (struct proc *)NULL
#endif
			);
	}
	break;
	case PRU_LISTEN:
		error = sctp_listen(so
#if defined(__NetBSD__)
				    , p
#else
				    , (struct proc *)NULL
#endif
			);
		break;
	case PRU_CONNECT:
	{
		struct sockaddr *name;
		if (nam)
			name = mtod(nam, struct sockaddr *);
		else
			return(EINVAL);
		error = sctp_connect(so, name
#if defined(__NetBSD__)
				     , p
#else
				     , (struct proc *)NULL
#endif
			);
	}
	break;
	case PRU_DISCONNECT:
		error = sctp_disconnect(so);
		break;
	case PRU_ACCEPT:
	{
		struct sockaddr *name;
		if (nam)
			name = mtod(nam, struct sockaddr *);
		else
			return(EINVAL);
		error = sctp_accept(so, name);
	}
	break;
	case PRU_SHUTDOWN:
		error = sctp_shutdown(so);
		break;

	case PRU_RCVD:
		/* Flags are ignored */
		error = sctp_usr_recvd(so, 0);
		break;

	case PRU_SEND:
	{
		struct sockaddr *name;
		if (nam)
			name = mtod(nam, struct sockaddr *);
		else
			name = (struct sockaddr *)NULL;
		/* Flags are ignored */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_USRREQ1) {
			printf("Send called on V4 side\n");
		}
#endif
		error = sctp_send(so, 0, m, name, control
#if defined(__NetBSD__)
				  , p
#else
				  , (struct proc *)NULL
#endif
			);
	}
	break;

	case PRU_ABORT:
		error = sctp_abort(so);
		break;

	case PRU_SENSE:
		error = 0;
		break;
	case PRU_RCVOOB:
		error = EAFNOSUPPORT;
		break;
	case PRU_SENDOOB:
		error = EAFNOSUPPORT;
		break;
	case PRU_PEERADDR:
	{
		struct sockaddr *name;
		if (nam)
			name = mtod(nam, struct sockaddr *);
		else
			return(EINVAL);
		error = sctp_peeraddr(so, name);
	}
	break;
	case PRU_SOCKADDR:
	{
		struct sockaddr *name;
		if (nam)
			name = mtod(nam, struct sockaddr *);
		else
			return(EINVAL);

		error = sctp_ingetaddr(so, name);
	}
	break;
	case PRU_SLOWTIMO:
		error = 0;
		break;
	default:
	};
	splx(s);
	return (error);
}
#endif
