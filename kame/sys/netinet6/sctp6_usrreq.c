/*	$KAME: sctp6_usrreq.c,v 1.7 2002/06/09 14:44:03 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet6/sctp6_usrreq.c,v 1.81 2002/04/04 21:53:15 randall Exp	*/

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
#include "opt_inet.h"
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet6.h"
#include "opt_inet.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif
#ifndef __OpenBSD__
#include "opt_ipsec.h"
#endif

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_var.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_input.h>
#include <netinet/sctp_asconf.h>
#include <netinet6/ip6_var.h>
#include <netinet/ip6.h>
#if !defined(__OpenBSD__) && !(defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/icmp6.h>
#include <netinet6/sctp6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/nd6.h>

#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#endif
#endif /*IPSEC*/

#include "faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_faith.h>
#endif

extern struct protosw inetsw[];
extern struct sctp_epinfo sctppcbinfo;

static	int sctp6_detach __P((struct socket *so));

#ifndef __FreeBSD__

extern void in6_sin_2_v4mapsin6 (struct sockaddr_in *sin,
				 struct sockaddr_in6 *sin6);
extern void in6_sin6_2_sin (struct sockaddr_in *,
			    struct sockaddr_in6 *sin6);
extern void in6_sin6_2_sin_in_sock(struct sockaddr *nam);

/*
 * Convert sockaddr_in6 to sockaddr_in.  Original sockaddr_in6 must be
 * v4 mapped addr or v4 compat addr
 */
void
in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin, sizeof(*sin));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	sin->sin_addr.s_addr = sin6->sin6_addr.s6_addr32[3];
}

/* Convert sockaddr_in to sockaddr_in6 in v4 mapped addr format. */
void
in6_sin_2_v4mapsin6(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	sin6->sin6_addr.s6_addr32[0] = 0;
	sin6->sin6_addr.s6_addr32[1] = 0;
	sin6->sin6_addr.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
	sin6->sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;
}

/* Convert sockaddr_in6 into sockaddr_in. */
void
in6_sin6_2_sin_in_sock(struct sockaddr *nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 sin6;

	/*
	 * Save original sockaddr_in6 addr and convert it
	 * to sockaddr_in.
	 */
	sin6 = *(struct sockaddr_in6 *)nam;
	sin_p = (struct sockaddr_in *)nam;
	in6_sin6_2_sin(sin_p, &sin6);
}

#endif /* not freebsd */


int
sctp6_input(mp, offp, proto)
     struct mbuf **mp;
     int *offp, proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
	struct sctphdr *sh;
	struct sctp_inpcb *in6p;
	struct sctp_nets *netp;
	u_int32_t check, calc_check;
	struct inpcb *in6p_ip;
	struct sctp_chunkhdr *ch;
	struct ip6_recvpktopts opts;
	int length, mlen, offset, iphlen;
	u_int8_t ecn_bits;
	struct sctp_tcb *stcb;

	int off = *offp;

	iphlen = off;
	bzero(&opts, sizeof(opts));

	IP6_EXTHDR_CHECK(m, off, sizeof(struct sctphdr), IPPROTO_DONE);

	ip6 = mtod(m, struct ip6_hdr *);

#if defined(NFAITH) && NFAITH > 0
#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version <= 430000
#if defined(NFAITH) && 0 < NFAITH
	if (faithprefix(&ip6->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		m_freem(m);
		return IPPROTO_DONE;
	}
#endif
#else

#if defined(__FreeBSD__) && __FreeBSD__ >= 4
	if (faithprefix_p != NULL && (*faithprefix_p)(&ip6->ip6_dst)) {
		/* XXX send icmp6 host/port unreach? */
		m_freem(m);
		return IPPROTO_DONE;
	}
#else
	if(faithprefix(&ip6->ip6_dst)){
		m_freem(m);
		return IPPROTO_DONE;
	}
#endif
#endif /* __FreeBSD_cc_version */

#endif /* NFAITH defined and > 0 */
	sctp_pegs[SCTP_INPKTS]++;

	offset = iphlen + sizeof(struct sctphdr) +
		sizeof(struct sctp_chunkhdr);
	if (m->m_len < offset) {
		if ((m = m_pullup(m, offset)) == 0) {
			sctp_pegs[SCTP_HDR_DROPS]++;
			return IPPROTO_DONE;
		}
		ip6 = mtod(m, struct ip6_hdr *);
	}
	sh = (struct sctphdr *)((caddr_t)ip6 + iphlen);
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));

	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		/* No multi-cast support in SCTP */
		sctp_pegs[SCTP_IN_MCAST]++;
		goto out_of;
	}

	check = sh->checksum;		/* save incoming checksum */
	sh->checksum = 0;		/* prepare for calc */
	calc_check = sctp_calculate_sum(m, &mlen, iphlen);
	if (calc_check != check) {
		sctp_pegs[SCTP_BAD_CSUM]++;
		goto out_of;
	}
	/* destination port of 0 is illegal, based on RFC2960. */
	if (sh->dest_port == 0){
		goto out_of;
	}
	/*
	 * Locate pcb and tcb for datagram
	 * sctp_findassociation_addr() wants IP/SCTP/first chunk header...
	 */
	stcb = sctp_findassociation_addr(m, iphlen, &in6p, &netp);
	if (in6p == NULL) {
		sctp_pegs[SCTP_NOPORTS]++;
		sctp6_send_abort(m,ip6,sh,off,0,NULL);
		m_freem(m);
		return IPPROTO_DONE;
	}
	in6p_ip = (struct inpcb *)in6p;
#ifdef IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
#ifdef __OpenBSD__
  {
    struct inpcb *i_inp;
    struct m_tag *mtag;
    struct tdb_ident *tdbi;
    struct tdb *tdb;
    int error,s;

    i_inp = in6p_ip;
    mtag = m_tag_find(m, PACKET_TAG_IPSEC_IN_DONE, NULL);
    s = splnet();
    if (mtag != NULL) {
      tdbi = (struct tdb_ident *)(mtag + 1);
      tdb = gettdb(tdbi->spi, &tdbi->dst, tdbi->proto);
    } else
      tdb = NULL;
    ipsp_spd_lookup(m, AF_INET, iphlen, &error,
		    IPSP_DIRECTION_IN, tdb, i_inp);

    /* Latch SA only if the socket is connected */
    if (i_inp->inp_tdb_in != tdb &&
	(i_inp->inp_socket->so_state & SS_ISCONNECTED)) {
      if (tdb) {
	tdb_add_inp(tdb, i_inp, 1);
	if (i_inp->inp_ipsec_remoteid == NULL &&
	    tdb->tdb_srcid != NULL) {
	  i_inp->inp_ipsec_remoteid = tdb->tdb_srcid;
	  tdb->tdb_srcid->ref_count++;
	}
	if (i_inp->inp_ipsec_remotecred == NULL &&
	    tdb->tdb_remote_cred != NULL) {
	  i_inp->inp_ipsec_remotecred =
	    tdb->tdb_remote_cred;
	  tdb->tdb_remote_cred->ref_count++;
	}
	if (i_inp->inp_ipsec_remoteauth == NULL &&
	    tdb->tdb_remote_auth != NULL) {
	  i_inp->inp_ipsec_remoteauth =
	    tdb->tdb_remote_auth;
	  tdb->tdb_remote_auth->ref_count++;
	}
      } else { /* Just reset */
	TAILQ_REMOVE(&i_inp->inp_tdb_in->tdb_inp_in, i_inp,
		     inp_tdb_in_next);
	i_inp->inp_tdb_in = NULL;
      }
    }
    splx(s);
    /* Error or otherwise drop-packet indication. */
    if (error)
      goto out_of;
  }
#else
	if (ipsec6_in_reject_so(m, in6p->sctp_socket)) {
		ipsec6stat.in_polvio++;
		goto out_of;
	}
#endif
#endif /*IPSEC*/

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	if ((in6p->ip_inp.inp.inp_flags & INP_CONTROLOPTS)
#ifndef __OpenBSD__
	    || (in6p->sctp_socket->so_options & SO_TIMESTAMP)
#endif
	    ) {
#ifdef __FreeBSD__
#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version >= 440000
		ip6_savecontrol(in6p_ip, ip6, m, &opts);
#else
		ip6_savecontrol(in6p_ip, ip6, m, &opts, NULL);
#endif /* __FreeBSD_cc_version */
#else
		ip6_savecontrol((struct in6pcb *)in6p_ip, ip6, m, &opts);
#endif
	}

	/*
	 * CONTROL chunk processing
	 */
	length = ntohs(ip6->ip6_plen) - sizeof(struct sctphdr);
	offset -= sizeof(struct sctp_chunkhdr);
	ecn_bits = ((ntohl(ip6->ip6_flow) >> 20) & 0x000000ff);
	{
		int s;
		s = splnet();
		(void)sctp_common_input_processing(in6p, stcb, netp, sh,
						   ch, m, iphlen, offset,
						   length, ecn_bits);
		splx(s);
	}
	/* XXX this stuff below gets moved to appropriate parts later... */
 out_of:
	if (m)
		m_freem(m);
	if (opts.head)
		m_freem(opts.head);
	return IPPROTO_DONE;
}


static void
sctp6_notify_mbuf(struct sctp_inpcb *inp,
		  struct icmp6_hdr *icmp6,
		  struct sctphdr *sh,
		  struct sctp_tcb *stcb,
		  struct sctp_nets *netp)

{
	int nxtsz;

	if ((inp == NULL) || (stcb == NULL) || (netp == NULL) ||
	    (icmp6 == NULL) || (sh == NULL)) {
		return;
	}

	/* First do we even look at it? */
	if (ntohl(sh->v_tag) != (stcb->asoc.peer_vtag)) {
		return;
	}

	if (icmp6->icmp6_type != ICMP6_PACKET_TOO_BIG) {
		/* not PACKET TO BIG */
		return;
	}
	/*
	 * ok we need to look closely. We could even get smarter and
	 * look at anyone that we sent to in case we get a different
	 * ICMP that tells us there is no way to reach a host, but for
	 * this impl, all we care about is MTU discovery.
	 */
	nxtsz = ntohl(icmp6->icmp6_mtu);
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
				 * resend since we sent too big of chunk
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
sctp6_ctlinput(cmd, pktdst, d)
     int cmd;
     struct sockaddr *pktdst;
     void *d;
{
	struct sctphdr sh;
	struct ip6ctlparam *ip6cp = NULL;
	int s, cm;

	if (pktdst->sa_family != AF_INET6 ||
	    pktdst->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd)) {
		d = NULL;
	} else if (inet6ctlerrmap[cmd] == 0) {
		return;
	}

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
	} else {
		ip6cp = (struct ip6ctlparam *)NULL;
	}

	if (ip6cp) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */
		/* check if we can safely examine src and dst ports */
		struct sctp_inpcb *inp;
		struct sctp_tcb *stcb;
		struct sctp_nets *netp;
		struct sockaddr_in6 final;

		if (ip6cp->ip6c_m == NULL ||
		    ip6cp->ip6c_m->m_pkthdr.len < (ip6cp->ip6c_off + sizeof(sh)))
			return;

		bzero(&sh, sizeof(sh));
		bzero(&final, sizeof(final));
		inp = NULL;
		netp = NULL;
		m_copydata(ip6cp->ip6c_m, ip6cp->ip6c_off, sizeof(sh),
			   (caddr_t)&sh);
		ip6cp->ip6c_src->sin6_port = sh.src_port;
		final.sin6_len = sizeof(final);
		final.sin6_family = AF_INET6;
#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version < 440000
		final.sin6_addr = *ip6cp->ip6c_finaldst;
#else
		final.sin6_addr = ((struct sockaddr_in6 *)pktdst)->sin6_addr;
#endif /* __FreeBSD_cc_version */
		final.sin6_port = sh.dest_port;
		stcb = sctp_findassociation_addr_sa((struct sockaddr *)ip6cp->ip6c_src,
						    (struct sockaddr *)&final,
						    &inp,&netp);
		s = splnet();
		if (stcb != NULL && inp && (inp->sctp_socket != NULL)) {
			if (cmd == PRC_MSGSIZE) {
				sctp6_notify_mbuf(inp,
						  ip6cp->ip6c_icmp6,
						  &sh,
						  stcb,
						  netp);
			} else {
				if (cmd == PRC_HOSTDEAD) {
					cm = EHOSTUNREACH;
				} else {
					cm = inet6ctlerrmap[cmd];
				}
				sctp_notify(inp, cm, &sh,
					    (struct sockaddr *)&final,
					    stcb, netp);
			}
		} else {
			if (PRC_IS_REDIRECT(cmd) && inp) {
#ifdef __OpenBSD__
				in_rtchange((struct inpcb *)inp,
					    inetctlerrmap[cmd]);
#else
				in6_rtchange((struct in6pcb *)inp,
					     inet6ctlerrmap[cmd]);
#endif
			}
		}
		splx(s);
	}
}

/*
 * this routine can probably be collasped into the one in sctp_userreq.c
 * since they do the same thing and now we lookup with a sockaddr
 */
#ifdef __FreeBSD__
static int
sctp6_getcred(SYSCTL_HANDLER_ARGS)
{
	struct sockaddr_in6 addrs[2];
	struct sctp_inpcb *inp;
	int error, s;

	error = suser(req->p);
	if (error)
		return (error);

	if (req->newlen != sizeof(addrs))
		return (EINVAL);
	if (req->oldlen != sizeof(struct ucred))
		return (EINVAL);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);
	s = splnet();

	inp = sctp_pcb_findep((struct sockaddr *)&addrs[0]);
	if (inp == NULL || inp->sctp_socket == NULL) {
		error = ENOENT;
		goto out;
	}
	error = SYSCTL_OUT(req, inp->sctp_socket->so_cred,
			   sizeof(struct ucred));

 out:
	splx(s);
	return (error);
}

SYSCTL_PROC(_net_inet6_sctp6, OID_AUTO, getcred, CTLTYPE_OPAQUE|CTLFLAG_RW,
	    0, 0,
	    sctp6_getcred, "S,ucred", "Get the ucred of a SCTP6 connection");

#endif

/* This is the same as the sctp_abort() could be made common */
static int
sctp6_abort(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;	/* ??? possible? panic instead? */
	soisdisconnected(so);
	s = splnet();
	sctp_inpcb_free(inp,1);
	splx(s);
	return 0;
}

static int
sctp6_attach(struct socket *so, int proto, struct proc *p)
{
	struct in6pcb *inp6;
	int s, error;
	struct sctp_inpcb *inp;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp != NULL)
		return EINVAL;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, sctp_sendspace, sctp_recvspace);
		if (error)
			return error;
	}
	s = splnet();
	error = sctp_inpcb_alloc(so);
	splx(s);
	if (error)
		return error;
	inp = (struct sctp_inpcb *)so->so_pcb;
	inp->sctp_flags |= SCTP_PCB_FLAGS_BOUND_V6;	/* I'm v6! */
	inp6 = (struct in6pcb *)inp;

#if defined(__FreeBSD__)
	inp6->inp_vflag |= INP_IPV6;
#else
#if defined(__OpenBSD__)
	inp->ip_inp.inp.inp_flags |= INP_IPV6;
#else
	inp->inp_vflag |=  INP_IPV6;
#endif
#endif
	inp6->in6p_hops = -1;	        /* use kernel default */
	inp6->in6p_cksum = -1;	/* just to be sure */
#ifdef INET
	/*
	 * XXX: ugly!!
	 * IPv4 TTL initialization is necessary for an IPv6 socket as well,
	 * because the socket may be bound to an IPv6 wildcard address,
	 * which may match an IPv4-mapped IPv6 address.
	 */
#if defined(__FreeBSD__)
	inp6->inp_ip_ttl = ip_defttl;
#else
	inp->inp_ip_ttl = ip_defttl;
#endif
#endif
	/*
	 * Hmm what about the IPSEC stuff that is missing here but
	 * in sctp_attach()?
	 */
	return 0;
}

static int
sctp6_bind(struct socket *so, struct sockaddr *addr, struct proc *p)
{
	struct sctp_inpcb *inp;
	struct inpcb *inp6;
	int s, error;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;

	inp6 = &inp->ip_inp.inp;
#if defined(__FreeBSD__)
	inp6->inp_vflag &= ~INP_IPV4;
	inp6->inp_vflag |= INP_IPV6;
#else
#if defined(__OpenBSD__)
	inp->ip_inp.inp.inp_flags &= ~INP_IPV4;
	inp->ip_inp.inp.inp_flags |= INP_IPV6;
#else
	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
#endif
#endif
	if (
#ifdef __OpenBSD__
	     (0) /* we always do dual bind */
#else
	     (inp6->inp_flags & IN6P_IPV6_V6ONLY)
#endif
	     == 0){
		if (addr->sa_family == AF_INET) {
			/* binding v4 addr to v6 socket, so reset flags */
#if defined(__FreeBSD__)
			inp6->inp_vflag |= INP_IPV4;
			inp6->inp_vflag &= ~INP_IPV6;
#else
#if defined(__OpenBSD__)
			inp->ip_inp.inp.inp_flags |= INP_IPV4;
			inp->ip_inp.inp.inp_flags &= ~INP_IPV6;
#else
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
#endif
#endif
		} else {
			struct sockaddr_in6 *sin6_p;
			sin6_p = (struct sockaddr_in6 *)addr;

			if (IN6_IS_ADDR_UNSPECIFIED(&sin6_p->sin6_addr)){
#if defined(__FreeBSD__)
			  inp6->inp_vflag |= INP_IPV4;
#else
#if defined(__OpenBSD__)
			  inp->ip_inp.inp.inp_flags |= INP_IPV4;
#else
			  inp->inp_vflag |= INP_IPV4;
#endif
#endif
			}
			else if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
				struct sockaddr_in sin;
				in6_sin6_2_sin(&sin, sin6_p);
#if defined(__FreeBSD__)
				inp6->inp_vflag |= INP_IPV4;
				inp6->inp_vflag &= ~INP_IPV6;
#else
#if defined(__OpenBSD__)
				inp->ip_inp.inp.inp_flags |= INP_IPV4;
				inp->ip_inp.inp.inp_flags &= ~INP_IPV6;

#else
				inp->inp_vflag |= INP_IPV4;
				inp->inp_vflag &= ~INP_IPV6;
#endif
#endif
				s = splnet();
				error = sctp_inpcb_bind(so, (struct sockaddr *)&sin, p);
				splx(s);
				return error;
			}
		}
	} else {
		/* IPV6_V6ONLY socket */
		if (addr->sa_family == AF_INET) {
			/* can't bind v4 addr to v6 only socket! */
			return EINVAL;
		} else {
			struct sockaddr_in6 *sin6_p;
			sin6_p = (struct sockaddr_in6 *)addr;

			if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr))
				/* can't bind v4-mapped addrs either! */
				/* NOTE: we don't support SIIT */
				return EINVAL;
		}
	}
	s = splnet();
	error = sctp_inpcb_bind(so, addr, p);
	splx(s);
	return error;
}

/*This could be made common with sctp_detach() since they are identical */
static int
sctp6_detach(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0)
		return EINVAL;
	s = splnet();
	sctp_inpcb_free(inp,0);
	splx(s);
	return 0;
}

static int
sctp6_disconnect(struct socket *so)
{
	struct sctp_inpcb *inp;
	int s;

	s = splnet();		/* XXX */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == NULL) {
		splx(s);
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
			if (tcb == NULL) {
				splx(s);
				return(EINVAL);
			}
			asoc = &tcb->asoc;
			if (!TAILQ_EMPTY(&asoc->out_wheel)) {
				/* Check to see if some data queued */
				struct sctp_stream_out *outs;
				TAILQ_FOREACH(outs, &asoc->out_wheel,
					      next_spoke){
					if (!TAILQ_EMPTY(&outs->outqueue)) {
						some_on_streamwheel = 1;
						break;
					}
				}
			}

			if (TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue) &&
			    (some_on_streamwheel == 0)) {
				/* nothing queued to send, so I'm done... */
				if ((asoc->state & SCTP_STATE_MASK) !=
				    SCTP_STATE_SHUTDOWN_SENT) {
					/* only send SHUTDOWN the first time */
					sctp_send_shutdown(tcb, tcb->asoc.primary_destination);
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
				 * be sent with no data.  currently, we will
				 * allow user data to be sent first and move
				 * to SHUTDOWN-PENDING
				 */
				asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
			}
			splx(s);
			return(0);
		}
	} else {
		/* UDP model does not support this */
		splx(s);
		return EOPNOTSUPP;
	}
}

static int
sctp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	   struct mbuf *control, struct proc *p)
{
	struct sctp_inpcb *inp;
	struct inpcb *in_inp;
	/* No SPL needed since sctp_output does this */
#ifdef INET
	struct sockaddr_in6 *sin6;
#endif /* INET */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
	        if (control) {
			m_freem(control);
			control = NULL;
		}
		m_freem(m);
		return EINVAL;
	}
	in_inp = (struct inpcb *)inp;

#ifdef SCTP_TCP_MODEL_SUPPORT
	/* For the TCP model we may get a NULL addr, if we
	 * are a connected socket thats ok.
	 */
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) &&
	    (addr == NULL)) {
	        return sctp_output(inp, m, addr, control, p);
	}
#endif
	if (addr == NULL) {
		m_freem(m);
		if (control) {
			m_freem(control);
			control = NULL;
		}
		return(EDESTADDRREQ);
	}

#ifdef INET
	sin6 = (struct sockaddr_in6 *)addr;
	if (
#ifdef __OpenBSD__
	    (0)	/* We don't allow V6 only bind in openbsd */
#else
	    (in_inp->inp_flags & IN6P_IPV6_V6ONLY)
#endif
	    ){
		/*
		 * if IPV6_V6ONLY flag, we discard datagrams
		 * destined to a v4 addr or v4-mapped addr
		 */
		if (addr->sa_family == AF_INET) {
			return EINVAL;
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			return EINVAL;
		}
	}

	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if(
#ifdef __FreeBSD__
		   ip6_mapped_addr_on
#else
		   ip6_v6only
#endif

		   ) {
			struct sockaddr_in sin;
			/* convert v4-mapped into v4 addr and send */
			in6_sin6_2_sin(&sin, sin6);
			return sctp_output(inp, m, (struct sockaddr *)&sin,
					   control, p);
		} else {
			/* mapped addresses aren't enabled */
			return EINVAL;
		}
	} else
#endif /* INET */
		return sctp_output(inp, m, addr, control, p);
}

static int
sctp6_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int s = splnet();
	int error = 0;
	struct sctp_inpcb *inp;
	struct sctp_tcb *tcb;
	struct sockaddr *addr;
#ifdef INET
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage ss;
#endif /* INET */

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (inp == 0) {
		splx(s);
		return(ECONNRESET);	/* I made the same as TCP since
					 * we are not setup? */
	}
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) ==
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* Bind a ephemeral port */
		struct sockaddr_in6 sin6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_family = AF_INET6;
		error = sctp6_bind(so, (struct sockaddr *)&sin6, p);
		if (error) {
			splx(s);
			return(error);
		}
	}
#ifdef SCTP_TCP_MODEL_SUPPORT
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)) {
		/* We are already connected AND the TCP model */
		splx(s);
		return(EADDRINUSE);
	}
#endif

#ifdef INET
	sin6 = (struct sockaddr_in6 *)nam;
	if (
#ifdef __OpenBSD__
	    (0)	/* dual bind only */
#else
	    (inp->ip_inp.inp.inp_flags & IN6P_IPV6_V6ONLY)
#endif
	    ) {
		/*
		 * if IPV6_V6ONLY flag, ignore connections
		 * destined to a v4 addr or v4-mapped addr
		 */
		if (nam->sa_family == AF_INET) {
			splx(s);
			return EINVAL;
		}
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
			splx(s);
		return EINVAL;
	}

	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if(
#ifdef __FreeBSD__
		   ip6_mapped_addr_on
#else
		   ip6_v6only
#endif
		   ) {
			/* convert v4-mapped into v4 addr */
			in6_sin6_2_sin((struct sockaddr_in *)&ss, sin6);
			addr = (struct sockaddr *)&ss;
		} else {
			/* mapped addresses aren't enabled */
			splx(s);
			return EINVAL;
		}
	} else
#endif /* INET */
		addr = nam;	/* for true v6 address case */

	/* Now do we connect? */
#ifdef SCTP_TCP_MODEL_SUPPORT
	if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED)
		tcb = LIST_FIRST(&inp->sctp_asoc_list);
	else
#endif /* SCTP_TCP_MODEL_SUPPORT */
		tcb = sctp_findassociation_ep_addr(&inp, addr, NULL, NULL);

	if (tcb != NULL) {
		/* Already have or am bring up an association */
		splx(s);
		return(EALREADY);
	}
	/* We are GOOD to go */
	tcb = sctp_aloc_assoc(inp, addr, 1);
	if (tcb == NULL) {
		/* Gak! no memory */
		splx(s);
		return(ENOMEM);
	}
	tcb->asoc.state = SCTP_STATE_COOKIE_WAIT;
	SCTP_GETTIME_TIMEVAL(&tcb->asoc.time_entered);
	sctp_send_initiate(inp, tcb);
	splx(s);
	return error;
}


static int
sctp6_getaddr(struct socket *so,
#ifdef __FreeBSD__
	      struct sockaddr **nam
#else
	      struct sockaddr *nam
#endif
	      )
{
	register struct sockaddr_in6 *sin6;
	struct sctp_inpcb *inp;
	/*
	 * Do the malloc first in case it blocks.
	 */
#ifdef __FreeBSD__
	MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6, M_SONAME,
	       M_WAITOK | M_ZERO);
#else
	sin6 = (struct sockaddr_in6 *)nam;
#endif
	bzero(sin6,sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);

	inp = (struct sctp_inpcb *)so->so_pcb;
	if (!inp) {
#ifdef __FreeBSD__
		free(sin6, M_SONAME);
#endif
		return ECONNRESET;
	}

	sin6->sin6_port = inp->sctp_lport;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* For the bound all case you get back 0 */
		memset(&sin6->sin6_addr, 0, sizeof(sin6->sin6_addr));
	} else {
		/* Take the first IPv6 address in the list */
		struct sctp_laddr *laddr;
		int fnd = 0;
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa->ifa_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin_a;
				sin_a = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
				sin6->sin6_addr = sin_a->sin6_addr;
				fnd = 1;
				break;
			}
		}
		if (!fnd) {
#ifdef __FreeBSD__
			free(sin6, M_SONAME);
#endif
			return ENOENT;
		}
	}
	/* Scoping things for v6 */
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		/* skip ifp check below */
		in6_recoverscope(sin6, &sin6->sin6_addr, NULL);
	else
		sin6->sin6_scope_id = 0;	/*XXX*/
#ifdef __FreeBSD__
	*nam = (struct sockaddr *)sin6;
#endif
	return(0);
}

static int
sctp6_peeraddr(struct socket *so,
#ifdef __FreeBSD__
	       struct sockaddr **nam
#else
	       struct sockaddr *nam
#endif
	       )
{
	int fnd;
	register struct sockaddr_in6 *sin6,*sin_a;
	struct sctp_inpcb *inp;
	struct sctp_tcb *tcb;
	struct sctp_nets *net;
	/*
	 * Do the malloc first in case it blocks.
	 */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0) {
		/* UDP type and listeners will drop out here */
		return(ENOTCONN);
	}
#ifdef __FreeBSD__
	MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6, M_SONAME,
	       M_WAITOK | M_ZERO);
#else
	sin6 = (struct sockaddr_in6 *)nam;
	bzero(sin6, sizeof(*sin6));
#endif
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);

	/* We must recapture incase we blocked */
	inp = (struct sctp_inpcb *)so->so_pcb;
	if (!inp) {
#ifdef __FreeBSD__
		free(sin6, M_SONAME);
#endif
		return ECONNRESET;
	}
	tcb = LIST_FIRST(&inp->sctp_asoc_list);
	if(tcb == NULL){
#ifdef __FreeBSD__
		free(sin6, M_SONAME);
#endif
		return ECONNRESET;
	}
	fnd = 0;
	TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
		sin_a = (struct sockaddr_in6 *)&net->ra._l_addr;
		if (sin_a->sin6_family == AF_INET) {
			fnd = 1;
			sin6->sin6_port = tcb->rport;
			sin6->sin6_addr = sin_a->sin6_addr;
			break;
		}
	}
	if (!fnd) {
		/* No IPv4 address */
#ifdef __FreeBSD__
		free(sin6, M_SONAME);
#endif
		return ENOENT;
	}
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
	else
		sin6->sin6_scope_id = 0;	/*XXX*/
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_addr.s6_addr16[1] = 0;
#ifdef __FreeBSD__
	*nam = (struct sockaddr *)sin6;
#endif
	return(0);
}

static int
sctp6_in6getaddr(struct socket *so,
#ifdef __FreeBSD__
		 struct sockaddr **nam
#else
		 struct sockaddr *nam
#endif
		 )
{
	struct inpcb *inp = sotoinpcb(so);
	int	error,s;

	if (inp == NULL)
		return EINVAL;

	s = splnet();
	/* allow v6 addresses precedence */
	error = sctp6_getaddr(so, nam);
	if (error) {
		/* try v4 next if v6 failed */
		error = sctp_ingetaddr(so, nam);
		if (error){
			splx(s);
			return(error);
		}
		/* if I'm V6ONLY, convert it to v4-mapped */
		if (
#ifdef __OpenBSD__
		    (0)	/* dual bind only */
#else
		    (inp->inp_flags & IN6P_IPV6_V6ONLY)
#endif
		    ) {
			struct sockaddr_in6 sin6;
#ifdef __FreeBSD__
			in6_sin_2_v4mapsin6((struct sockaddr_in *)*nam, &sin6);
			memcpy(*nam, &sin6, sizeof(struct sockaddr_in6));
#else
			in6_sin_2_v4mapsin6((struct sockaddr_in *)nam, &sin6);
			memcpy(nam, &sin6, sizeof(struct sockaddr_in6));
#endif
		}
	}
	splx(s);
	return(error);
}


static int
sctp6_getpeeraddr(struct socket *so,
#ifdef __FreeBSD__
		  struct sockaddr **nam
#else
		  struct sockaddr *nam
#endif
		  )
{
	struct inpcb *inp = sotoinpcb(so);
	int	error,s;

	if (inp == NULL)
		return EINVAL;

	s = splnet();
	/* allow v6 addresses precedence */
	error = sctp6_peeraddr(so, nam);
	if (error) {
		/* try v4 next if v6 failed */
		error = sctp_peeraddr(so, nam);
		if (error){
			splx(s);
			return(error);
		}
		/* if I'm V6ONLY, convert it to v4-mapped */
		if (
#ifdef __OpenBSD__
		    (0) /* dual bind only */
#else
		    (inp->inp_flags & IN6P_IPV6_V6ONLY)
#endif
		    ) {
			struct sockaddr_in6 sin6;
#ifdef __FreeBSD__
			in6_sin_2_v4mapsin6((struct sockaddr_in *)*nam, &sin6);
			memcpy(*nam, &sin6, sizeof(struct sockaddr_in6));
#else
			in6_sin_2_v4mapsin6((struct sockaddr_in *)nam, &sin6);
			memcpy(nam, &sin6, sizeof(struct sockaddr_in6));
#endif
		}
	}
	splx(s);
	return error;
}

#if defined(__FreeBSD__)
struct pr_usrreqs sctp6_usrreqs = {
	sctp6_abort, sctp_accept, sctp6_attach, sctp6_bind,
	sctp6_connect, pru_connect2_notsupp, in6_control,
	sctp6_detach, sctp6_disconnect, sctp_listen, sctp6_getpeeraddr,
	sctp_usr_recvd, pru_rcvoob_notsupp, sctp6_send, pru_sense_null,
	sctp_shutdown, sctp6_in6getaddr, sosend, soreceive, sopoll
};

#else

int
#if defined(__NetBSD__) || defined(__OpenBSD__)
sctp6_usrreq(so, req, m, nam, control, p)
     struct socket *so;
     int req;
     struct mbuf *m, *nam, *control;
     struct proc *p;
#else
sctp6_usrreq(so, req, m, nam, control)
     struct socket *so;
     int req;
     struct mbuf *m, *nam, *control;
#endif
{
	int s;
	int error = 0;
	int family;

	s = splnet();
	family = so->so_proto->pr_domain->dom_family;

	if (req == PRU_CONTROL) {
		switch (family) {
		case PF_INET:
			error = in_control(so, (long)m, (caddr_t)nam,
					   (struct ifnet *)control
#if defined(__NetBSD__)
					   , p
#endif
					   );
#ifdef INET6
		case PF_INET6:
			error = in6_control(so, (long)m, (caddr_t)nam,
					    (struct ifnet *)control
#if defined(__NetBSD__) || defined(__OpenBSD__)
					    , p
#endif
					    );
#endif
		default:
			error = EAFNOSUPPORT;
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
			in_purgeif(ifn);
			break;
#ifdef INET6
		case PF_INET6:
			in6_purgeif(ifn);
			break;
#endif
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
		error = sctp6_attach(so, family,
#if defined(__NetBSD__) || defined(__OpenBSD__)
				     p
#else
				     (struct proc *)NULL
#endif
				     );
		break;
	case PRU_DETACH:
		error = sctp6_detach(so);
		break;
	case PRU_BIND:
		{
			struct sockaddr *name;
			name = mtod(nam, struct sockaddr *);
			error  = sctp6_bind(so, name,
#if defined(__NetBSD__) || defined(__OpenBSD__)
					    p
#else
					    (struct proc *)NULL
#endif
					    );
		}
		break;
	case PRU_LISTEN:
		error = sctp_listen(so, p);
		break;
	case PRU_CONNECT:
		{
			struct sockaddr *name;
			name = mtod(nam, struct sockaddr *);
			error = sctp6_connect(so, name,
#if defined(__NetBSD__) || defined(__OpenBSD__)
					      p
#else
					      (struct proc *)NULL
#endif
					      );
		}
		break;
	case PRU_DISCONNECT:
		error = sctp6_disconnect(so);
		break;
	case PRU_ACCEPT:
		{
			struct sockaddr *name;
			name = mtod(nam, struct sockaddr *);
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
			name = mtod(nam,struct sockaddr *);
			/* Flags are ignored */
			error = sctp6_send(so, 0, m, name, control,
#if defined(__NetBSD__) || defined(__OpenBSD__)
					   p
#else
					   (struct proc *)NULL
#endif
					   );
		}
		break;

	case PRU_ABORT:
		error = sctp6_abort(so);
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
			name = mtod(nam, struct sockaddr *);
			error = sctp6_getpeeraddr(so, name);
		}
		break;
	case PRU_SOCKADDR:
		{
			struct sockaddr *name;
			name = mtod(nam, struct sockaddr *);
			error = sctp6_in6getaddr(so, name);
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
