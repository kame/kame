/*	$KAME: dccp_usrreq.c,v 1.13 2003/10/20 12:22:51 ono Exp $	*/

/*
 * Copyright (c) 2003 Joacim Häggmark, Magnus Erixzon, Nils-Erik Mattsson 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Id: dccp_usrreq.c,v 1.47 2003/07/31 11:23:08 joahag-9 Exp
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

#include "opt_inet6.h"
#include "opt_dccp.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/kernel.h>
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
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_var.h>
#ifdef INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#endif
#include <netinet/dccp.h>
#include <netinet/dccp_var.h>
#include <netinet/dccp6_var.h>
#include <netinet/dccp_cc_sw.h>

#include <machine/in_cksum.h>

#undef DEBUG
#undef ACKDEBUG

#if defined(DEBUG)
#define DCCP_DEBUG(args) log args
#else
#define DCCP_DEBUG(args)
#endif

#ifdef ACKDEBUG
#define ACK_DEBUG(args) log args
#else
#define ACK_DEBUG(args)
#endif

#define DEFAULT_CCID 2

#if !defined(__FreeBSD__) || __FreeBSD_version < 500000
#define	INP_INFO_LOCK_INIT(x,y)
#define	INP_INFO_WLOCK(x)
#define INP_INFO_WUNLOCK(x)
#define	INP_INFO_RLOCK(x)
#define INP_INFO_RUNLOCK(x)
#define	INP_LOCK(x)
#define INP_UNLOCK(x)
#endif

/* Congestion control switch table */
extern struct dccp_cc_sw cc_sw[];

int	dccp_log_in_vain = 1;
SYSCTL_INT(_net_inet_dccp, OID_AUTO, dccp_log_in_vain, CTLFLAG_RW, 
    &dccp_log_in_vain, 0, "Log all incoming DCCP packets");

struct	inpcbhead dccpb;		/* from dccp_var.h */
struct	inpcbinfo dccpbinfo;

#ifndef UDBHASHSIZE
#define UDBHASHSIZE 16
#endif

u_long	dccp_sendspace = 32768;
u_long	dccp_recvspace = 65536;

struct	dccpstat dccpstat;	/* from dccp_var.h */
SYSCTL_STRUCT(_net_inet_dccp, DCCPCTL_STATS, stats, CTLFLAG_RW,
    &dccpstat, dccpstat, "DCCP statistics (struct dccpstat, netinet/dccp_var.h)");

static struct	sockaddr_in dccp_in = { sizeof(dccp_in), AF_INET };

static int dccp_detach(struct socket *so);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
static int dccp_doconnect(struct dccpcb *, struct sockaddr *, struct thread *, int);
#else
static int dccp_doconnect(struct dccpcb *, struct sockaddr *, struct proc *, int);
#endif
static struct dccpcb * dccp_close(struct dccpcb *);
static int dccp_disconnect2(struct dccpcb *);
int dccp_get_option(char *, int, int, char *,int);
void dccp_parse_options(struct dccpcb *, char *, int);
int dccp_add_feature(struct dccpcb *, u_int8_t, u_int8_t,  char *, u_int8_t);
int dccp_remove_feature(struct dccpcb *, u_int8_t, u_int8_t);
int dccp_add_feature_option(struct dccpcb *, u_int8_t, u_int8_t, char *, u_int8_t);
void dccp_feature_neg(struct dccpcb *, u_int8_t, u_int8_t, u_int8_t, char *);
void dccp_retrans_t(void *);
void dccp_close_t(void *);
void dccp_timewait_t(void *);
void dccp_connect_t(void *);

/* Ack Vector functions */
#define DCCP_VECTORSIZE 512 /* initial ack and cwnd-vector size. Multiple of 8 ! */
void dccp_use_ackvector(struct dccpcb *dp);
void dccp_update_ackvector(struct dccpcb *dp, u_int32_t seqno);
void dccp_increment_ackvector(struct dccpcb *dp, u_int32_t seqno);
u_int16_t dccp_generate_ackvector(struct dccpcb *dp, u_char *);
u_char dccp_ackvector_state(struct dccpcb *dp, u_int32_t seqnr);


/*
 * DCCP initialization
 *
 */
void
dccp_init()
{
	INP_INFO_LOCK_INIT(&dccpbinfo, "dccp");
	DCCP_DEBUG((LOG_INFO, "Initializing DCCP!\n"));
	LIST_INIT(&dccpb);
	dccpbinfo.listhead = &dccpb;
	dccpbinfo.hashbase = hashinit(UDBHASHSIZE, M_PCB, &dccpbinfo.hashmask);
	dccpbinfo.porthashbase = hashinit(UDBHASHSIZE, M_PCB,
					&dccpbinfo.porthashmask);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	dccpbinfo.ipi_zone = uma_zcreate("dccpcb", sizeof(struct inp_dp), NULL,
	    NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(dccpbinfo.ipi_zone, maxsockets);
#else
	dccpbinfo.ipi_zone = zinit("udpcb", sizeof(struct inp_dp), maxsockets,
				 ZONE_INTERRUPT, 0);
#endif
}

#ifdef INET6
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
#endif

void
dccp_input(struct mbuf *m, int off)
{
	int iphlen = off;
	struct ip *ip = NULL;
	struct dccphdr *dh;
	struct inpcb *inp, *oinp;
	struct dccpcb *dp;
	struct ipovly *ipov = NULL;
	struct dccp_requesthdr *drqh;
	struct dccp_ackhdr *dah = NULL;
	struct dccp_resethdr *drth;
	struct socket *so;
	u_char *optp = NULL;
	struct mbuf *opts = 0;
	int len, data_off, extrah_len, optlen;
	struct ip save_ip;
	char options[DCCP_MAX_OPTIONS];
	char test[2];
	u_int32_t cslen, seqnr, low_seqnr, high_seqnr;
	int isipv6 = 0;
#ifdef INET6
	struct ip6_hdr *ip6 = NULL;
	struct sockaddr_in6 src_sa6, dst_sa6;
#endif


	DCCP_DEBUG((LOG_INFO, "Got DCCP packet!\n"));

	dccpstat.dccps_ipackets++;
	dccpstat.dccps_ibytes += m->m_pkthdr.len;

#ifdef INET6
	isipv6 = (mtod(m, struct ip *)->ip_v == 6) ? 1 : 0;
#endif


#ifdef INET6
	if (isipv6) {
		DCCP_DEBUG((LOG_INFO, "Got DCCP ipv6 packet, iphlen = %u!\n", iphlen));
		ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
		dh = (struct dccphdr *)((caddr_t)ip6 + iphlen);
#else
		IP6_EXTHDR_GET(dh, struct dccphdr *, m, iphlen, sizeof(*dh));
		if (dh == NULL) {
			dccpstat.dccps_badlen++;
			return;
		}
#endif
	} else
#endif
	{
		/*
		 * Strip IP options, if any; should skip this,
		 * make available to user, and use on returned packets,
		 * but we don't yet have a way to check the checksum
		 * with options still present.
		 */
		if (iphlen > sizeof (struct ip)) {
			ip_stripoptions(m, (struct mbuf *)0);
			iphlen = sizeof(struct ip);
		}

		/*
		 * Get IP and DCCP header together in first mbuf.
		 */
		ip = mtod(m, struct ip *);
#ifndef PULLDOWN_TEST
		if (m->m_len < iphlen + sizeof(struct dccphdr)) {
			if ((m = m_pullup(m, iphlen + sizeof(struct dccphdr))) == 0) {
				DCCP_DEBUG((LOG_INFO, "Dropping packet, to short?\n"));
				dccpstat.dccps_drops++;
				return;
			}
			ip = mtod(m, struct ip *);
		}
		dh = (struct dccphdr *)((caddr_t)ip + iphlen);
#else
		IP6_EXTHDR_GET(dh, struct dccphdr *, m, iphlen, sizeof(*dh));
		if (dh == NULL) {
			dccpstat.dccps_badlen++;
			return;
		}
#endif

		/*
		 * Construct sockaddr format source address.
		 * Stuff source address and datagram in user buffer.
		 */
		dccp_in.sin_port = dh->dh_sport;
		dccp_in.sin_addr = ip->ip_src;
	}

	DCCP_DEBUG((LOG_INFO, "Header info: cslen = %u ndp = %u, off = %u, type = %u, reserved = %u, seq = %u\n", dh->dh_cslen, dh->dh_ndp, dh->dh_off, dh->dh_type, dh->dh_res, ntohl(dh->dh_seq << 8)));


	/*
	 * Make mbuf data length reflect DCCP length.
	 * If not enough data to reflect DCCP length, drop.
	 */

#ifdef INET6
	if (isipv6)
		len = m->m_pkthdr.len - off;
	else
		len = ip->ip_len;
#else
	len = ip->ip_len;
#endif

	if (len < sizeof(struct dccphdr)) {
			DCCP_DEBUG((LOG_INFO, "Dropping DCCP packet!\n"));
			dccpstat.dccps_badlen++;
			goto badunlocked;
	}
	/*
	 * Save a copy of the IP header in case we want restore it
	 * for sending a DCCP reset packet in response.
	 */
	if (!isipv6) {
		save_ip = *ip;
		ipov = (struct ipovly *)ip;
	}

	if (dh->dh_cslen == 15) {
		cslen = len;
	} else {
		cslen = dh->dh_off * 4 + dh->dh_cslen * 4;
		if (cslen > len)
			cslen = len;
	}
	

	DCCP_DEBUG((LOG_INFO, "Checksum extend header and data! dh->dh_cslen = %u, cslen = %u, len = %u, dh->dh_sum = 0x%04x\n", dh->dh_cslen, cslen, len, dh->dh_sum));

	/*
	 * Checksum extended DCCP header and data.
	 */
	
#ifdef INET6
	if (isipv6) {
		if (in6_cksum(m, IPPROTO_DCCP, off, cslen) != 0) {
			DCCP_DEBUG((LOG_INFO, "Bad checksum, not dropping packet!, dh->dh_sum = 0x%04x\n", dh->dh_sum));
			dccpstat.dccps_badsum++;
		} else {
			DCCP_DEBUG((LOG_INFO, "Correct checksum, dh->dh_sum = 0x%04x off = %u, cslen = %u\n", dh->dh_sum, off, cslen));
		}
	} else
#endif
	{
	bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
	((struct ipovly *)ip)->ih_len = htons(len);
	dh->dh_sum = in_cksum(m, cslen + sizeof (struct ip));

	if (dh->dh_sum) {
	/*	DCCP_DEBUG((LOG_INFO, "Bad checksum, not dropping packet!, dh->dh_sum = 0x%04x\n", dh->dh_sum)); */
		DCCP_DEBUG((LOG_INFO, "Bad checksum, dropping packet!, dh->dh_sum = 0x%04x\n", dh->dh_sum));
		dccpstat.dccps_badsum++;
		m_freem(m);
		return;
	}
	}

	INP_INFO_WLOCK(&dccpbinfo);

	/*
	 * Locate pcb for datagram.
	 */
#ifdef INET6
	if (isipv6) {
		if (ip6_getpktaddrs(m, &src_sa6, &dst_sa6))
			goto badunlocked;
		inp = in6_pcblookup_hash(&dccpbinfo, &src_sa6, dh->dh_sport,
		    &dst_sa6, dh->dh_dport, 1, m->m_pkthdr.rcvif);
	} else
#endif
	{
		inp = in_pcblookup_hash(&dccpbinfo, ip->ip_src, dh->dh_sport,
		    ip->ip_dst, dh->dh_dport, 1, m->m_pkthdr.rcvif);
	}

	if (inp == NULL) {
		if (dccp_log_in_vain) {
#ifdef INET6
			char dbuf[INET6_ADDRSTRLEN+2], sbuf[INET6_ADDRSTRLEN+2];
#else
			char dbuf[4*sizeof "123"], sbuf[4*sizeof "123"];
#endif

#ifdef INET6
			if (isipv6) {
				strcpy(dbuf, "[");
				strcpy(sbuf, "[");
				strcat(dbuf, ip6_sprintf(&ip6->ip6_dst));
				strcat(sbuf, ip6_sprintf(&ip6->ip6_src));
				strcat(dbuf, "]");
				strcat(sbuf, "]");
			} else
#endif
			{
				strcpy(dbuf, inet_ntoa(ip->ip_dst));
				strcpy(sbuf, inet_ntoa(ip->ip_src));
			}
			log(LOG_INFO,
			    "Connection attempt to DCCP %s:%d from %s:%d\n",
			    dbuf, ntohs(dh->dh_dport), sbuf,
			    ntohs(dh->dh_sport));
		}
		dccpstat.dccps_noport++;

	/*
	 * We should send DCCP reset here but we can't call dccp_output since we
	 * have no dccpcb. A icmp unreachable works great but the specs says DCCP reset :(
	 *
	 * if (!isipv6) {
	 *	*ip = save_ip;
	 *	ip->ip_len += iphlen;
	 *	icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0); 
	 * } 
	 */

		INP_INFO_WUNLOCK(&dccpbinfo);
		return;
	}
	INP_LOCK(inp);

	dp = (struct dccpcb *)inp->inp_ppcb;

	if (dp == 0) {
		INP_UNLOCK(inp);
		INP_INFO_WUNLOCK(&dccpbinfo);
		goto badunlocked;
	}

	if (dp->state == DCCPS_CLOSED) {
		DCCP_DEBUG((LOG_INFO, "We are in closed state, dropping packet and sending reset!\n"));
		if (dh->dh_type != DCCP_TYPE_RESET)
			dccp_output(dp, DCCP_TYPE_RESET + 2);
		INP_UNLOCK(inp);
		INP_INFO_WUNLOCK(&dccpbinfo);
		goto badunlocked;
	}

	so = inp->inp_socket;

	if (so->so_options & SO_ACCEPTCONN) {
		DCCP_DEBUG((LOG_INFO, "so->options & SO_ACCEPTCONN! dp->state = %i\n", dp->state));
		so = sonewconn(so, SS_ISCONNECTED);
		if (so == 0) {
			DCCP_DEBUG((LOG_INFO, "Error, sonewconn failed!\n"));
			INP_UNLOCK(inp);
			INP_INFO_WUNLOCK(&dccpbinfo);
			goto badunlocked;
		}

		oinp = inp;
		inp = sotoinpcb(so);
		INP_LOCK(inp);

#ifdef INET6
		if (isipv6) {
			inp->in6p_laddr = ip6->ip6_dst;
			inp->in6p_faddr = ip6->ip6_src;
		} else 
#endif
		{
			inp->inp_laddr = ip->ip_dst;
			inp->inp_faddr = ip->ip_src;
		}
		inp->inp_lport = dh->dh_dport;
		inp->inp_fport = dh->dh_sport;

		if (in_pcbinshash(inp) != 0) {
			DCCP_DEBUG((LOG_INFO, "Error, in_pcbinshash failed!\n"));
			INP_UNLOCK(inp);
			INP_INFO_WUNLOCK(&dccpbinfo);
			goto badunlocked;
		}

		dp = (struct dccpcb *)inp->inp_ppcb;
		dp->state = DCCPS_LISTEN;
		dp->who = DCCP_SERVER;
		dp->cslen = ((struct dccpcb *)oinp->inp_ppcb)->cslen;
		dp->avgpsize = ((struct dccpcb *)oinp->inp_ppcb)->avgpsize;
		dp->seq_snd = arc4random() % 16777216;
		INP_UNLOCK(oinp);
		DCCP_DEBUG((LOG_INFO, "New dp = %u, dp->state = %u!\n", (int)dp, dp->state));
	}

	INP_INFO_WUNLOCK(&dccpbinfo);

	/*
	 * Check if sequence number is inside the loss window 
	 */

	seqnr = ntohl(dh->dh_seq << 8);
	
	if (dp->gsn_rcv == 1073741824)  {
		dp->gsn_rcv = seqnr;
	}

	low_seqnr = (dp->gsn_rcv - (dp->loss_window / 3)) % 16777216;
	high_seqnr = (dp->gsn_rcv + (dp->loss_window / 3 * 2)) % 16777216;

	if (! (DCCP_SEQ_GT(seqnr, low_seqnr) && DCCP_SEQ_LT(seqnr, high_seqnr))) {
		dccpstat.dccps_badseq++;
		DCCP_DEBUG((LOG_INFO, "Recieved DCCP packet with bad sequence number = %u (low_seqnr = %u, high_seqnr = %u)\n", seqnr, low_seqnr, high_seqnr));
		INP_UNLOCK(inp);
		goto badunlocked;
	}

	/* dp->gsn_rcv should always be the highest received valid sequence number */
	if (DCCP_SEQ_GT(seqnr, dp->gsn_rcv))
		dp->gsn_rcv = seqnr;

	/* Just ignore DCCP-Move for now */
	if (dh->dh_type == DCCP_TYPE_DATA) {
		extrah_len = 0;
		optp = (u_char *)(dh + 1);
	} else if (dh->dh_type == DCCP_TYPE_REQUEST) {
		drqh = (struct dccp_requesthdr *)(dh + 1);
		optp = (u_char *)(drqh + 1);
		extrah_len = 4;
	} else if (dh->dh_type == DCCP_TYPE_RESET) {
		extrah_len = 8 ;
		drth = (struct dccp_resethdr *)(dh + 1);
		optp = (u_char *)(drth + 1);
	} else {
		extrah_len = 4;
		dah = (struct dccp_ackhdr *)(dh + 1);
		optp = (u_char *)(dah + 1);

	}

	data_off = (dh->dh_off * 4);

	dp->seq_rcv = seqnr;
	dp->ack_rcv = 0; /* Clear it for now */
	dp->type_rcv = dh->dh_type;
	dp->len_rcv = m->m_len - data_off - iphlen; /* Correct length ? */
	dp->ndp_rcv = dh->dh_ndp;
	
	optlen = data_off - (sizeof(struct dccphdr) + extrah_len);

	if (optlen < 0) {
		DCCP_DEBUG((LOG_INFO, "Data offset is smaller then it could be, optlen = %i data_off = %i, m_len = %i, iphlen = %i extrah_len = %i !\n", optlen, data_off, m->m_len, iphlen, extrah_len));
		INP_UNLOCK(inp);
		goto badunlocked;
	}

	if (optlen > 0) {
		if (optlen > DCCP_MAX_OPTIONS) {
			DCCP_DEBUG((LOG_INFO, "Error, more options (%i) then DCCP_MAX_OPTIONS options!\n", optlen));
			INP_UNLOCK(inp);
			goto badunlocked;
		}

		DCCP_DEBUG((LOG_INFO, "Parsing DCCP options, optlen = %i\n", optlen));
		bcopy(optp, options, optlen);
		dccp_parse_options(dp, options, optlen);
	}

	DCCP_DEBUG((LOG_INFO, "BEFORE state check, Got a %u packet while in %u state, who = %u!\n", dh->dh_type, dp->state, dp->who));

	if (dp->state == DCCPS_LISTEN) {
		switch(dh->dh_type) {

		case DCCP_TYPE_REQUEST:
			DCCP_DEBUG((LOG_INFO, "Got DCCP REQUEST\n"));
			dp->state = DCCPS_REQUEST;
			if (dp->cc_in_use[1] < 0) {
				/* To be compatible with Linux implementation */
				test[0] = DEFAULT_CCID;
				if (test[0] == 2) {
					test[1] = 3;
				} else {
					test[1] = 2;
				}	
				dccp_add_feature(dp, DCCP_OPT_CHANGE, DCCP_FEATURE_CC, test, 2);
			}
			if (len > data_off) {
				dccp_add_option(dp, DCCP_OPT_DATA_DISCARD, test, 0);
			}
			dp->connect_timer = timeout(dccp_connect_t, dp, DCCP_CONNECT_TIMER);
			dccp_output(dp, 0);
			break;


		/* These are ok if the sender has a valid init Cookie */
		case DCCP_TYPE_ACK:
		case DCCP_TYPE_DATAACK:
		case DCCP_TYPE_DATA:
			DCCP_DEBUG((LOG_INFO, "Got DCCP ACK/DATAACK/DATA, should check init cookie...\n"));
			dccp_output(dp, DCCP_TYPE_RESET + 2);
			break;

		case DCCP_TYPE_RESET:
			DCCP_DEBUG((LOG_INFO, "Got DCCP RESET\n"));
			dp->state = DCCPS_TIME_WAIT;
			dp = dccp_close(dp);
			return;

		default:
			DCCP_DEBUG((LOG_INFO, "Got a %u packet while in listen stage!\n", dh->dh_type));
			/* Force send reset. */
			dccp_output(dp, DCCP_TYPE_RESET + 2);
		}


	} else if (dp->state == DCCPS_REQUEST) {
		switch(dh->dh_type) {
		case DCCP_TYPE_RESPONSE:
			DCCP_DEBUG((LOG_INFO, "Got DCCP REPSONSE\n"));
			dp->ack_rcv = ntohl(dah->dah_ack << 8); /* Ack num */
			dp->ack_snd = dp->seq_rcv;

			untimeout(dccp_retrans_t, dp, dp->retrans_timer);
			untimeout(dccp_connect_t, dp, dp->connect_timer);

			/* First check if we have negotiated a cc */
			if (dp->cc_in_use[0] > 0 && dp->cc_in_use[1] > 0) {
				DCCP_DEBUG((LOG_INFO, "Setting DCCPS_ESTAB & soisconnected\n"));
				dp->state = DCCPS_ESTAB;
				dccpstat.dccps_connects++;
				soisconnected(inp->inp_socket);
			} else {
				dp->state = DCCPS_RESPOND;
				DCCP_DEBUG((LOG_INFO, "CC negotiation is not finished, cc_in_use[0] = %u, cc_in_use[1] = %u\n",dp->cc_in_use[0], dp->cc_in_use[1]));

			}
			dccp_output(dp, 0);
			break;

		case DCCP_TYPE_RESET:
			DCCP_DEBUG((LOG_INFO, "Got DCCP RESET\n"));
			dp->state = DCCPS_TIME_WAIT;
			dp = dccp_close(dp);
			return;

		default:
			DCCP_DEBUG((LOG_INFO, "Got a %u packet while in REQUEST stage!\n", dh->dh_type));
			/* Force send reset. */
			dccp_output(dp, DCCP_TYPE_RESET + 2);
			if (dh->dh_type == DCCP_TYPE_CLOSE) {
				dp = dccp_close(dp);
				return;
			} else {
				untimeout(dccp_retrans_t, dp, dp->retrans_timer);
				dp->state = DCCPS_TIME_WAIT;
			}
		}
	} else if (dp->state == DCCPS_RESPOND) {
		switch(dh->dh_type) {

		case DCCP_TYPE_REQUEST:
			break;
		case DCCP_TYPE_ACK:
		case DCCP_TYPE_DATAACK:
			DCCP_DEBUG((LOG_INFO, "Got DCCP ACK/DATAACK\n"));

			untimeout(dccp_connect_t, dp, dp->connect_timer);

			dp->ack_rcv = ntohl(dah->dah_ack << 8); /* Ack num */

			if (dp->cc_in_use[0] > 0 && dp->cc_in_use[1] > 0) {
				DCCP_DEBUG((LOG_INFO, "Setting DCCPS_ESTAB & soisconnected\n"));
				dp->state = DCCPS_ESTAB;
				dccpstat.dccps_connects++;
				soisconnected(inp->inp_socket);
			} else {
				DCCP_DEBUG((LOG_INFO, "CC negotiation is not finished, cc_in_use[0] = %u, cc_in_use[1] = %u\n",dp->cc_in_use[0], dp->cc_in_use[1]));
				/* Force an output!!! */
				dp->ack_snd = dp->seq_rcv;
				dccp_output(dp, 0);
			}

			if (dh->dh_type == DCCP_TYPE_DATAACK && dp->cc_in_use[1] > 0) {
				DCCP_DEBUG((LOG_INFO, "Calling *cc_sw[%u].cc_recv_packet_recv!\n", dp->cc_in_use[1]));
				(*cc_sw[dp->cc_in_use[1]].cc_recv_packet_recv)(dp->cc_state[1], options, optlen); 
			}
			break;
		case DCCP_TYPE_CLOSE:
			dccp_output(dp, DCCP_TYPE_CLOSE + 1);
			dp = dccp_close(dp);
			return;
		case DCCP_TYPE_RESET:
			dp->state = DCCPS_TIME_WAIT;
			untimeout(dccp_retrans_t, dp, dp->retrans_timer);
			break;

		default:
			DCCP_DEBUG((LOG_INFO, "Got a %u packet while in response stage!\n", dh->dh_type));
			/* Force send reset. */
			dccp_output(dp, DCCP_TYPE_RESET + 2);
		}
	} else if (dp->state == DCCPS_ESTAB) {
		switch(dh->dh_type) {

		case DCCP_TYPE_DATA:
			DCCP_DEBUG((LOG_INFO, "Got DCCP DATA, state = %i, cc_in_use[1] = %u\n", dp->state, dp->cc_in_use[1]));
			
			if (dp->cc_in_use[1] > 0) {
				DCCP_DEBUG((LOG_INFO, "Calling *cc_sw[%u].cc_recv_packet_recv!\n", dp->cc_in_use[1]));
				(*cc_sw[dp->cc_in_use[1]].cc_recv_packet_recv)(dp->cc_state[1], options, optlen);
			}
			break;
	
		case DCCP_TYPE_ACK:
			DCCP_DEBUG((LOG_INFO, "Got DCCP ACK\n"));
			dp->ack_rcv = ntohl(dah->dah_ack << 8); /* Ack num */
			if (dp->cc_in_use[1] > 0) {
				/* This is called so Acks on Acks can be handled */
				DCCP_DEBUG((LOG_INFO, "Calling *cc_sw[%u].cc_recv_packet_recv!\n", dp->cc_in_use[1]));
				(*cc_sw[dp->cc_in_use[1]].cc_recv_packet_recv)(dp->cc_state[1], options, optlen); 
			}
			break;
	
		case DCCP_TYPE_DATAACK:
			DCCP_DEBUG((LOG_INFO, "Got DCCP DATAACK\n"));
			dp->ack_rcv = ntohl(dah->dah_ack << 8); /* Ack num */
			if (dp->cc_in_use[1] > 0) {
				DCCP_DEBUG((LOG_INFO, "Calling *cc_sw[%u].cc_recv_packet_recv!\n", dp->cc_in_use[1]));
				(*cc_sw[dp->cc_in_use[1]].cc_recv_packet_recv)(dp->cc_state[1], options, optlen); 
			}
			break;
	
		case DCCP_TYPE_CLOSEREQ:
			DCCP_DEBUG((LOG_INFO, "Got DCCP CLOSEREQ, state = estab\n"));
			if (dp->who == DCCP_CLIENT) {
				dccp_disconnect2(dp);
			} else {
				dccp_output(dp, DCCP_TYPE_RESET + 2);
			}
			break;
	
		case DCCP_TYPE_CLOSE:
			DCCP_DEBUG((LOG_INFO, "Got DCCP CLOSE, state = estab\n"));
			dp->state = DCCPS_SERVER_CLOSE; /* So disconnect2 doesn't send CLOSEREQ */
			dccp_disconnect2(dp);
			dccp_output(dp, DCCP_TYPE_RESET + 2);
			dccp_close(dp);
			goto badunlocked;
			break;
	
		case DCCP_TYPE_RESET:
			DCCP_DEBUG((LOG_INFO, "Got DCCP RESET\n"));
			dp->state = DCCPS_TIME_WAIT;
			untimeout(dccp_retrans_t, dp, dp->retrans_timer);
			dp->timewait_timer = timeout(dccp_timewait_t, dp, DCCP_TIMEWAIT_TIMER);
			break;
	
		case DCCP_TYPE_MOVE:
			DCCP_DEBUG((LOG_INFO, "Got DCCP MOVE\n"));
			break;

		default:
			DCCP_DEBUG((LOG_INFO, "Got a %u packet while in established stage!\n", dh->dh_type));
		}

	} else if (dp->state == DCCPS_SERVER_CLOSE) {
		/* Server */
		switch(dh->dh_type) {
		case DCCP_TYPE_CLOSE:
			DCCP_DEBUG((LOG_INFO, "Got DCCP CLOSE (State DCCPS_SERVER_CLOSE)\n"));
			untimeout(dccp_retrans_t, dp, dp->retrans_timer);
			dccp_output(dp, DCCP_TYPE_RESET + 2);
			dp = dccp_close(dp);
			return;
		case DCCP_TYPE_RESET:
			DCCP_DEBUG((LOG_INFO, "Got DCCP RESET\n"));
			untimeout(dccp_retrans_t, dp, dp->retrans_timer);
			dccp_output(dp, DCCP_TYPE_RESET + 2);
			dp->state = DCCPS_TIME_WAIT;
			break;
		default:
			DCCP_DEBUG((LOG_INFO, "Got a %u packet while in server_close stage!\n", dh->dh_type));
		}

	} else if (dp->state == DCCPS_CLIENT_CLOSE) {
		/* Client */
		switch(dh->dh_type) {
		case DCCP_TYPE_CLOSE:
			/* Ignore */
			break;
		case DCCP_TYPE_CLOSEREQ:
			DCCP_DEBUG((LOG_INFO, "Got DCCP CLOSEREQ, state = DCCPS_CLIENT_CLOSE\n"));
			/* Just resend close */
			dccp_output(dp, 0);
			break;
		case DCCP_TYPE_RESET:
			DCCP_DEBUG((LOG_INFO, "Got DCCP RESET\n"));
			untimeout(dccp_retrans_t, dp, dp->retrans_timer);
			dp->state = DCCPS_TIME_WAIT;
			dp->timewait_timer = timeout(dccp_timewait_t, dp, DCCP_TIMEWAIT_TIMER);
			break;
		default:
			DCCP_DEBUG((LOG_INFO, "Got a %u packet while in client_close stage!\n", dh->dh_type));

		}
	} else {
		DCCP_DEBUG((LOG_INFO, "Got a %u packet while in %u state!\n", dh->dh_type, dp->state));
		if (dh->dh_type != DCCP_TYPE_RESET) {
			/* Force send reset. */
			DCCP_DEBUG((LOG_INFO, "Force sending a request!\n"));
			dccp_output(dp, DCCP_TYPE_RESET + 2);
		}
	}

	if (dh->dh_type == DCCP_TYPE_DATA ||
	    dh->dh_type == DCCP_TYPE_ACK  ||
	    dh->dh_type == DCCP_TYPE_DATAACK) {
		DCCP_DEBUG((LOG_INFO, "ACK = %u\n", dp->ack_rcv));
		if (dp->cc_in_use[0] > 0) {
			(*cc_sw[dp->cc_in_use[0]].cc_send_packet_recv)(dp->cc_state[0],options, optlen);
		}
		
	}

	if (dh->dh_type == DCCP_TYPE_DATA || dh->dh_type == DCCP_TYPE_DATAACK) {
		if (so->so_state & SS_CANTRCVMORE) {
			DCCP_DEBUG((LOG_INFO, "state & SS_CANTRCVMORE...!\n"));
			m_freem(m);
			if (opts)
				m_freem(opts);
		} else {
			m_adj(m, (iphlen + data_off));
			DCCP_DEBUG((LOG_INFO, "Calling sbappend!\n"));
			sbappend(&so->so_rcv, m);
		}
		DCCP_DEBUG((LOG_INFO, "Calling sorwakeup...!\n"));
		sorwakeup(so);
	} else {
		m_freem(m);
		if (opts)
			m_freem(opts);
	}
	if (dp)
		INP_UNLOCK(inp);

	return;

badunlocked:
	m_freem(m);
	if (opts)
		m_freem(opts);
	return;
}

/*
 * Notify a dccp user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
struct inpcb *
#else
void
#endif
dccp_notify(struct inpcb *inp, int errno)
{
	inp->inp_socket->so_error = errno;
	sorwakeup(inp->inp_socket);
	sowwakeup(inp->inp_socket);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	return inp;
#else
	return;
#endif
}

/*
 * Called when we get ICMP errors (destination unrechable,
 * parameter problem, source quench, time exceeded and redirects)
 */
void
dccp_ctlinput(int cmd, struct sockaddr *sa, void *vip)
{
	struct ip *ip = vip;
	struct dccphdr *dh;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	struct inpcb *(*notify)(struct inpcb *, int) = dccp_notify;
#else
	void (*notify)(struct inpcb *, int) = dccp_notify;
#endif
        struct in_addr faddr;
	struct inpcb *inp;
	int s;

	faddr = ((struct sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
        	return;

	if (PRC_IS_REDIRECT(cmd)) {
		ip = 0;
		notify = in_rtchange;
	} else if (cmd == PRC_HOSTDEAD)
		ip = 0;
	else if ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0)
		return;
	if (ip) {
		s = splnet();
		dh = (struct dccphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		INP_INFO_RLOCK(&dccpbinfo);
		inp = in_pcblookup_hash(&dccpbinfo, faddr, dh->dh_dport,
                    ip->ip_src, dh->dh_sport, 0, NULL);
		if (inp != NULL) {
			INP_LOCK(inp);
			if (inp->inp_socket != NULL) {
				(*notify)(inp, inetctlerrmap[cmd]);
			}
			INP_UNLOCK(inp);
		}
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
	} else
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
		in_pcbnotifyall(&dccpbinfo, faddr, inetctlerrmap[cmd], notify);
#else
		in_pcbnotifyall(&dccpb, faddr, inetctlerrmap[cmd], notify);
#endif
}

#ifdef INET6
void
dccp6_ctlinput(int cmd, struct sockaddr *sa, void *d)
{
	if (sa->sa_family != AF_INET6 || sa->sa_len != sizeof(struct sockaddr_in6))
        	return;
	
	/* FIX LATER */
}
#endif

/* 
 * Called by getsockopt and setsockopt.
 *
 */
int
dccp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int optval, s, error = 0;
	struct inpcb	*inp;
	struct dccpcb	*dp;


	s = splnet();
	INP_INFO_RLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == NULL) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		return (ECONNRESET);
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	
	if (sopt->sopt_level != IPPROTO_DCCP) {
		/* Let ip have it. */
#ifdef INET6
		if (INP_CHECK_SOCKAF(so, AF_INET6))
			error = ip6_ctloutput(so, sopt);
		else 
#endif
			error = ip_ctloutput(so, sopt);
		INP_UNLOCK(inp);
		splx(s);
		return(error);
	}

	dp = (struct dccpcb *)inp->inp_ppcb;
	switch (sopt->sopt_dir) {
	case SOPT_SET:
	      switch (sopt->sopt_name) {
		case DCCP_CCID:
		case DCCP_CSLEN:
		case DCCP_TFRC_AVGPSIZE:
		case DCCP_MAXSEG:
			error = sooptcopyin(sopt, &optval, sizeof optval, sizeof optval);

			if (error)
				break;

			switch (sopt->sopt_name) {
			case DCCP_CCID:
				/* Add check that optval is a CCID we support!!! */
				if (optval == 2 || optval == 3 || optval == 0) {
					dp->pref_cc = optval;
				} else {
					error = EINVAL;
				}
				break;
			case DCCP_CSLEN:
				if (optval > 15 || optval < 0) {
					error = EINVAL;
				} else {
					dp->cslen = optval;
				}
				break;
			case DCCP_TFRC_AVGPSIZE:
				if (optval > 65536 || optval < 0) {
					error = EINVAL;
				} else {
					dp->avgpsize = optval;
				}
				break;
			case DCCP_MAXSEG:
				if (optval > 0 && optval <= dp->d_maxseg) {
					dp->d_maxseg = optval;
				} else {
					error = EINVAL;
				}
				break;
			}

			break;

		default:
			error = ENOPROTOOPT;
		}

	      break;

	case SOPT_GET:
		switch (sopt->sopt_name) {
		case DCCP_CCID:
			optval = dp->pref_cc;
			break;
		case DCCP_CSLEN:
			optval = dp->cslen;
			break;
		case DCCP_TFRC_AVGPSIZE:
			optval = dp->avgpsize;
			break;
		case DCCP_MAXSEG:
			optval = dp->d_maxseg;
			break;
		default:
			error = ENOPROTOOPT;
		}

		if (error == 0) {
			error = sooptcopyout(sopt, &optval, sizeof optval);
		}
		break;
	}

	INP_UNLOCK(inp);
	splx(s);
	return error;
}

int
dccp_output(struct dccpcb *dp, u_int8_t extra)
{
	struct inpcb *inp = dp->d_inpcb;
	struct socket *so = inp->inp_socket;
	struct mbuf *m;

	struct ip *ip = NULL;
	struct dccphdr *dh;
	struct dccp_requesthdr *drqh;
	struct dccp_ackhdr *dah;
	struct dccp_resethdr *drth;
	u_char *optp = NULL;
	int error = 0;
	int off, sendalot, t, i;
	u_int32_t hdrlen, optlen, extrah_len, cslen;
	u_int8_t type;
	char options[DCCP_MAX_OPTIONS *2];
	long len;
	int isipv6 = 0;
#ifdef INET6
	struct ip6_hdr *ip6 = NULL;

	isipv6 = (dp->d_inpcb->inp_vflag & INP_IPV6) != 0;
#endif

	DCCP_DEBUG((LOG_INFO, "Going to send a DCCP packet!\n"));
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_assert(&dp->d_inpcb->inp_mtx, MA_OWNED);
#endif

	if (dp->state != DCCPS_ESTAB && extra == 1) {
		/* Only let cc decide when to resend if we are in establised state */
		return 0;
	}

again:
	sendalot = 0;


	off = 0; /* off not needed for dccp because we do not need to wait for ACK
		    before removing the packet   */
	len = (long)so->so_snd.sb_cc;
	optlen = 0;

	/* Check with CC if we can send... */
	if (dp->cc_in_use[0] > 0 && dp->state == DCCPS_ESTAB) {
		DCCP_DEBUG((LOG_INFO, "Calling *cc_sw[%u].cc_send_packet!\n", dp->cc_in_use[0]));
		if (!(*cc_sw[dp->cc_in_use[0]].cc_send_packet)(dp->cc_state[0], len)) {
			DCCP_DEBUG((LOG_INFO, "Not allowed to send right now\n"));
			return 0;
		}
	}

	if (len > dp->d_maxseg) {
		len = dp->d_maxseg;
		sendalot = 1;
	}

	if (extra == DCCP_TYPE_RESET + 2) {
		DCCP_DEBUG((LOG_INFO, "Force sending of DCCP TYPE_RESET!\n"));
		type = DCCP_TYPE_RESET;
		extrah_len = 8;
	} else if (dp->state <= DCCPS_REQUEST && dp->who == DCCP_CLIENT) {
		DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_REQUEST!\n"));
		type = DCCP_TYPE_REQUEST;
		dp->state = DCCPS_REQUEST;
		extrah_len = 4;
	} else if (dp->state == DCCPS_REQUEST && dp->who == DCCP_SERVER) {
		DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_RESPONSE!\n"));
		type = DCCP_TYPE_RESPONSE;
		dp->state = DCCPS_RESPOND;
		extrah_len = 4;
	} else if (dp->state == DCCPS_RESPOND) {
		DCCP_DEBUG((LOG_INFO, "Still in feature neg, sending DCCP TYPE_ACK!\n"));
		type = DCCP_TYPE_ACK;
		extrah_len = 4;
	} else if (dp->state == DCCPS_ESTAB) {
		if (dp->ack_snd && len) {
			DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_DATAACK!\n"));
			type = DCCP_TYPE_DATAACK;
			/*(u_int32_t *)&extrah = dp->seq_rcv; */
			extrah_len = 4;
		} else if (dp->ack_snd) {
			DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_ACK!\n"));
			type = DCCP_TYPE_ACK;
			extrah_len = 4;
		} else if (len) {
			DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_DATA!\n"));
			type = DCCP_TYPE_DATA;
			extrah_len = 0;
		} else {
		  DCCP_DEBUG((LOG_INFO, "No ack or data to send!\n"));
		  return 0;
		}
	} else if (dp->state == DCCPS_CLIENT_CLOSE) {
		DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_CLOSE!\n"));
		type = DCCP_TYPE_CLOSE;
		extrah_len = 4;
	} else if (dp->state == DCCPS_SERVER_CLOSE) {
		DCCP_DEBUG((LOG_INFO, "Sending DCCP TYPE_CLOSEREQ!\n"));
		type = DCCP_TYPE_CLOSEREQ;
		extrah_len = 4;
	} else {
		DCCP_DEBUG((LOG_INFO, "Hey, we should never get here, state = %u\n", dp->state));
		return 1;
	}

	/* Adding options. */
	if (dp->optlen) {
		DCCP_DEBUG((LOG_INFO, "Copying options from dp->options!\n"));
		bcopy(dp->options, options , dp->optlen);
		optlen = dp->optlen;
		dp->optlen = 0;
	}

	if (dp->featlen && (optlen + dp->featlen < DCCP_MAX_OPTIONS)) {
		DCCP_DEBUG((LOG_INFO, "Copying options from dp->features!\n"));
		bcopy(dp->features, options + optlen, dp->featlen);
		optlen += dp->featlen;
	}

	t = optlen % 4;

	if (t) {
		t = 4 - t;
		for (i = 0 ; i<t; i++) {
			options[optlen] = 0;
			optlen++;
		}
	}

#ifdef INET6
	if (isipv6) {
		DCCP_DEBUG((LOG_INFO, "Sending ipv6 packet...\n"));
		hdrlen = sizeof(struct ip6_hdr) + sizeof(struct dccphdr) +
		    extrah_len + optlen;
	} else
#endif
		hdrlen = sizeof(struct ip) + sizeof(struct dccphdr) +
		    extrah_len + optlen;

	if (len > (dp->d_maxseg - extrah_len - optlen)) {
		len = dp->d_maxseg - extrah_len - optlen;
		sendalot = 1;
	}
	
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL) {
		error = ENOBUFS;
		goto release;
	}
	
	m->m_data += max_linkhdr;
	m->m_len = hdrlen;

#ifdef INET6
	if (MHLEN < hdrlen + max_linkhdr) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			error = ENOBUFS;
			goto release;
		}
	}
#endif

	if (len) { /* We have data to send */
		if (len <= MHLEN - hdrlen - max_linkhdr) {
			m_copydata(so->so_snd.sb_mb, off, (int) len,
			mtod(m, caddr_t) + hdrlen);
			m->m_len += len;
		} else {
			m->m_next = m_copy(so->so_snd.sb_mb, off, (int) len);
			if (m->m_next == 0) {
				error = ENOBUFS;
				goto release;
			}
		}
	} else {
		dp->ndp++;
	}

	m->m_pkthdr.rcvif = (struct ifnet *)0;

	if (!isipv6 && (len + hdrlen) > IP_MAXPACKET) {
		error = EMSGSIZE;
		goto release;
	}

	/*
	 * Fill in mbuf with extended DCCP header
	 * and addresses and length put into network format.
	 */
#ifdef INET6
	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);
		dh = (struct dccphdr *)(ip6 + 1);
		ip6->ip6_flow = (ip6->ip6_flow & ~IPV6_FLOWINFO_MASK) |
			(inp->in6p_flowinfo & IPV6_FLOWINFO_MASK);
		ip6->ip6_vfc = (ip6->ip6_vfc & ~IPV6_VERSION_MASK) |
			 (IPV6_VERSION & IPV6_VERSION_MASK);
		ip6->ip6_nxt = IPPROTO_DCCP;
		ip6->ip6_src = inp->in6p_laddr;
		ip6->ip6_dst = inp->in6p_faddr;
	} else 
#endif
	{
		ip = mtod(m, struct ip *);
		dh = (struct dccphdr *)(ip + 1);
		bzero(ip, sizeof(ip));
		ip->ip_p = IPPROTO_DCCP;
		ip->ip_src = inp->inp_laddr;
		ip->ip_dst = inp->inp_faddr;
	}

	dh->dh_sport = inp->inp_lport;
	dh->dh_dport = inp->inp_fport;
	dh->dh_cslen = dp->cslen;
	dh->dh_ndp = (dp->ndp % 16);
	dh->dh_type = type;
	dh->dh_res = 0; /* Reserved field should be zero */

	dh->dh_off = 3 + (extrah_len / 4) + (optlen / 4);

	dp->seq_snd = (dp->seq_snd + 1) % 16777216;
	dh->dh_seq = htonl(dp->seq_snd) >> 8;

	DCCP_DEBUG((LOG_INFO, "Sending with seq %u, (dp->seq_snd = %u)\n\n", dh->dh_seq, dp->seq_snd));

	if (dh->dh_type == DCCP_TYPE_REQUEST) {
		drqh = (struct dccp_requesthdr *)(dh + 1);
		drqh->drqh_sname = 0; /* Service name must be 0 if not used */
		optp = (u_char *)(drqh + 1);

	} else if (dh->dh_type == DCCP_TYPE_RESET) {
		drth = (struct dccp_resethdr *)(dh + 1);
		drth->drth_res = 0; /* Reserved field should be zero */
		drth->drth_ack = htonl(dp->seq_rcv) >> 8;
		drth->drth_reason = 0; /* FIX, must be able to specify reason  */
		drth->drth_data1 = 0;
		drth->drth_data2 = 0;
		drth->drth_data3 = 0;
		optp = (u_char *)(drth + 1);

	} else if (extrah_len) {
		dah = (struct dccp_ackhdr *)(dh + 1);
		dah->dah_res = 0; /* Reserved field should be zero */

		if (dp->state == DCCPS_ESTAB) {
			dah->dah_ack = htonl(dp->ack_snd) >> 8;
			dp->ack_snd = 0;
		} else
			dah->dah_ack = htonl(dp->seq_rcv) >> 8;
		
		optp = (u_char *)(dah + 1);

	} else {
		optp = (u_char *)(dh + 1);

	}

	if (optlen)
		bcopy(options, optp , optlen);

	m->m_pkthdr.len = hdrlen + len;

	if (dh->dh_cslen == 15) {
		cslen = len;
	} else {
		cslen = 4 * dh->dh_cslen;
		if (cslen > len)
			cslen = len;
	}

	/*
	 * Set up checksum 
	 */
	m->m_pkthdr.csum_flags = CSUM_IP; /* Do not allow the network card to calculate the checksum */

#ifdef INET6
	if (isipv6) {
		dh->dh_sum = in6_cksum(m, IPPROTO_DCCP, sizeof(struct ip6_hdr), sizeof(struct dccphdr) + extrah_len + optlen + cslen);
	} else
#endif
	{
	      	dh->dh_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		    htons((u_short)len + sizeof(struct dccphdr) + extrah_len + optlen + IPPROTO_DCCP)); 
		dh->dh_sum = in_cksum_skip(m, hdrlen + cslen, 20);
		m->m_pkthdr.csum_data = offsetof(struct dccphdr, dh_sum);

		ip->ip_len = hdrlen + len;
		ip->ip_ttl = inp->inp_ip_ttl;	/* XXX */
		ip->ip_tos = inp->inp_ip_tos;	/* XXX */
	}

	DCCP_DEBUG((LOG_INFO, "Calculated checksum,  dh->dh_cslen = %u, cslen = %u, len = %li hdrlen = %u, dh->dh_sum = 0x%04x\n", dh->dh_cslen, cslen, len, hdrlen, dh->dh_sum));

	dccpstat.dccps_opackets++;
	dccpstat.dccps_obytes += m->m_pkthdr.len;

#ifdef INET6
	if (isipv6) {
		DCCP_DEBUG((LOG_INFO, "Calling ip_output6, mbuf->m_len = %u, mbuf->m_pkthdr.len = %u\n", m->m_len, m->m_pkthdr.len));
		error = ip6_output(m, inp->in6p_outputopts, &inp->in6p_route,
		    (inp->inp_socket->so_options & SO_DONTROUTE), NULL, NULL, inp);
	} else
#endif
	{
		DCCP_DEBUG((LOG_INFO, "Calling ip_output, mbuf->m_len = %u, mbuf->m_pkthdr.len = %u\n", m->m_len, m->m_pkthdr.len));
		error = ip_output(m, inp->inp_options, &inp->inp_route,
		    (inp->inp_socket->so_options & SO_DONTROUTE), 0, inp);
	}

	if (error) {
		DCCP_DEBUG((LOG_INFO, "IP output failed!\n"));
		return(error);
	}

	sbdrop(&inp->inp_socket->so_snd, len);
	sowwakeup(inp->inp_socket);
	if (dp->cc_in_use[0] > 0  && dp->state == DCCPS_ESTAB) {
		DCCP_DEBUG((LOG_INFO, "Calling *cc_sw[%u].cc_send_packet_sent!\n", dp->cc_in_use[0]));
		if (sendalot) {
			(*cc_sw[dp->cc_in_use[0]].cc_send_packet_sent)(dp->cc_state[0], 1,len);
			goto again;
		} else {
			(*cc_sw[dp->cc_in_use[0]].cc_send_packet_sent)(dp->cc_state[0], 0,len);
		}
	} else {
		if (sendalot)
			goto again;
	}

	return (0);

release:
	m_freem(m);
	return (error);
}


static int
dccp_abort(struct socket *so)
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int s = splnet();

	DCCP_DEBUG((LOG_INFO, "Entering dccp_abort!\n"));
	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		return EINVAL;
	}

	dp = (struct dccpcb *)inp->inp_ppcb;
	dccp_disconnect2(dp);

	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return 0;
}

static struct dccpcb *
dccp_close(struct dccpcb *dp)
{
	struct inpcb *inp = dp->d_inpcb;
	struct socket *so = inp->inp_socket;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_close!\n"));

	/* Stop all timers */
	untimeout(dccp_connect_t, dp, dp->connect_timer);
	untimeout(dccp_retrans_t, dp, dp->retrans_timer);
	untimeout(dccp_close_t, dp, dp->close_timer);
	untimeout(dccp_timewait_t, dp, dp->timewait_timer);

	if (dp->cc_in_use[0] > 0)
		(*cc_sw[dp->cc_in_use[0]].cc_send_free)(dp->cc_state[0]);
	if (dp->cc_in_use[1] > 0)
		(*cc_sw[dp->cc_in_use[1]].cc_recv_free)(dp->cc_state[1]);

	inp->inp_ppcb = NULL;
	dp->d_inpcb = NULL;
	soisdisconnected(so);
	in_pcbdetach(inp);
	return ((struct dccpcb *)0);
}

/*
 * Runs when a new socket is created with the
 * socket system call or sonewconn.
 */
static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp_attach(struct socket *so, int proto, struct thread *td)
#else
dccp_attach(struct socket *so, int proto, struct proc *td)
#endif
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int error = 0;
	int s = splnet();

	DCCP_DEBUG((LOG_INFO, "Entering dccp_attach!\n"));
	INP_INFO_WLOCK(&dccpbinfo);

	inp = sotoinpcb(so);
	if (inp != 0) {
		error = EINVAL;
		goto out;
	}

	error = soreserve(so, dccp_sendspace, dccp_recvspace);
	error = in_pcballoc(so, &dccpbinfo, td);
	if (error)
		goto out;

	inp = sotoinpcb(so);

#ifdef INET6
	if (INP_CHECK_SOCKAF(so, AF_INET6)) {
		DCCP_DEBUG((LOG_INFO, "We are a ipv6 socket!!!\n"));
		inp->inp_vflag |= INP_IPV6;
	} else
#endif
		inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ip_defttl;

	dp = dccp_newdccpcb(inp);
	if (dp == 0) {
		int nofd = so->so_state & SS_NOFDREF;
		so->so_state &= ~SS_NOFDREF;
#ifdef INET6
		if (INP_CHECK_SOCKAF(so, AF_INET6)) {
			in6_pcbdetach(inp);
		} else
#endif
			in_pcbdetach(inp);
		so->so_state |= nofd;
		error = ENOBUFS;
		goto out;
	}
	dp->state = DCCPS_CLOSED;
out:
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return error;
}

static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
#else
dccp_bind(struct socket *so, struct sockaddr *nam, struct proc *td)
#endif
{
	struct inpcb *inp;
	int s, error;
	struct sockaddr_in *sinp;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_bind!\n"));
	s = splnet();
	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}

	/* Do not bind to multicast addresses! */
	sinp = (struct sockaddr_in *)nam;
	if (sinp->sin_family == AF_INET &&
		IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		return EAFNOSUPPORT;
	}
	INP_LOCK(inp);
	error = in_pcbbind(inp, nam, td);
	INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return error;
}

#ifdef INET6
static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp6_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
#else
dccp6_bind(struct socket *so, struct sockaddr *nam, struct proc *td)
#endif
{
	struct inpcb *inp;
	int s, error;
	struct sockaddr_in6 *sin6p;

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_bind!\n"));
	s = splnet();
	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		DCCP_DEBUG((LOG_INFO, "dccp6_bind: inp == 0!\n"));
		splx(s);
		return EINVAL;
	}
	/* Do not bind to multicast addresses! */
	sin6p = (struct sockaddr_in6 *)nam;
	if (sin6p->sin6_family == AF_INET6 &&
		IN6_IS_ADDR_MULTICAST(&sin6p->sin6_addr)) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		return EAFNOSUPPORT;
	}
	INP_LOCK(inp);

	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	
	error = in6_pcbbind(inp, nam, td);
	INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return error;
}
#endif


/*
 * Initiates a connection to a server
 * Called by the connect system call.
 */
static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
#else
dccp_connect(struct socket *so, struct sockaddr *nam, struct proc *td)
#endif
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int s, error;
	struct sockaddr_in *sin;
	char test[2];

	DCCP_DEBUG((LOG_INFO, "Entering dccp_connect!\n"));

	s = splnet();

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

	if (dp->state == DCCPS_ESTAB) {
		DCCP_DEBUG((LOG_INFO, "Why are we in connect when we already have a established connection?\n"));
	}

	dp->who = DCCP_CLIENT;
	dp->seq_snd = arc4random() % 16777216;

	dccpstat.dccps_connattempt++;

	sin = (struct sockaddr_in *)nam;
	if (sin->sin_family == AF_INET
	    && IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
		splx(s);
		error = EAFNOSUPPORT;
		goto bad;
	}

	error = dccp_doconnect(dp, nam, td, 0);

	if (error != 0)
		goto bad;

	dp->retrans_timer = timeout(dccp_retrans_t, dp, dp->retrans);
	dp->connect_timer = timeout(dccp_connect_t, dp, DCCP_CONNECT_TIMER);

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

#ifdef INET6
static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp6_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
#else
dccp6_connect(struct socket *so, struct sockaddr *nam, struct proc *td)
#endif
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int s, error;
	struct sockaddr_in *sin;
	char test[2];

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_connect!\n"));

	s = splnet();

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

	if (dp->state == DCCPS_ESTAB) {
		DCCP_DEBUG((LOG_INFO, "Why are we in connect when we already have a established connection?\n"));
	}

	dp->who = DCCP_CLIENT;
	dp->seq_snd = arc4random() % 16777216;

	sin = (struct sockaddr_in *)nam;
	if (sin->sin_family == AF_INET
	    && IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
		splx(s);
		error = EAFNOSUPPORT;
		goto bad;
	}

	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	inp->inp_inc.inc_isipv6 = 1;

	error = dccp_doconnect(dp, nam, td, 1);

	if (error != 0)
		goto bad;

	dp->retrans_timer = timeout(dccp_retrans_t, dp, dp->retrans);
	dp->connect_timer = timeout(dccp_connect_t, dp, DCCP_CONNECT_TIMER);

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
#endif

/*
 *
 *
 */
static int
dccp_doconnect(struct dccpcb *dp, struct sockaddr *nam,
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
    struct thread *td,
#else
    struct proc *td,
#endif
    int isipv6)
{ 
	struct inpcb *inp = dp->d_inpcb;
	struct socket *so = inp->inp_socket;
#ifdef INET6
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)nam;
	struct sockaddr_in6 *addr6;
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	struct in_addr laddr;
	u_short	lport;
#else
	struct inpcb *oinp;
	struct sockaddr_in *sin = (struct sockaddr_in *)nam;
	struct sockaddr_in *ifaddr;
#endif
	int error = 0;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_doconnect!\n"));


	if (inp->inp_lport == 0) {
#ifdef INET6
		if (isipv6) {
			DCCP_DEBUG((LOG_INFO, "Running in6_pcbbind!\n"));
			error = in6_pcbbind(inp, (struct sockaddr *)0, td);
		} else
#endif
			error = in_pcbbind(inp, (struct sockaddr *)0, td);
		if (error)
			return error;
	}

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	laddr = inp->inp_laddr;
        lport = inp->inp_lport;
#endif

#ifdef INET6
	if (isipv6)
		error = in6_pcbladdr(inp, nam, &addr6);
	else
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
		error = in_pcbconnect_setup(inp, nam, &laddr.s_addr, &lport,
			&inp->inp_faddr.s_addr, &inp->inp_fport, NULL, td);
#else
	{
		error = in_pcbladdr(inp, nam, &ifaddr);
		if (error)
			return error;
		oinp = in_pcblookup_hash(inp->inp_pcbinfo,
		    sin->sin_addr, sin->sin_port,
		    inp->inp_laddr.s_addr != INADDR_ANY ? inp->inp_laddr
		    : ifaddr->sin_addr,
		    inp->inp_lport,  0, NULL);
		if (oinp) {
			return EADDRINUSE;
		}
		if (inp->inp_laddr.s_addr == INADDR_ANY)
			inp->inp_laddr = ifaddr->sin_addr;
		inp->inp_faddr = sin->sin_addr;
		inp->inp_fport = sin->sin_port;
	}
#endif
	if (error)
		return error;

#ifdef INET6
	if (isipv6) {
		if (SA6_IS_ADDR_UNSPECIFIED(&inp->in6p_lsa)) {
			inp->in6p_lsa.sin6_addr = addr6->sin6_addr;
			inp->in6p_lsa.sin6_scope_id = addr6->sin6_scope_id;
		}
		inp->in6p_faddr = sin6->sin6_addr;
		inp->inp_fport = sin6->sin6_port;
		if ((sin6->sin6_flowinfo & IPV6_FLOWINFO_MASK) != 0)
			inp->in6p_flowinfo = sin6->sin6_flowinfo;
	} else
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	inp->inp_laddr = laddr;
#endif

	in_pcbrehash(inp);
	
	soisconnecting(so);
	return error;
}

/*
 * Detaches the DCCP protocol from the socket.
 *
 */
static int
dccp_detach(struct socket *so)
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int s = splnet();

	DCCP_DEBUG((LOG_INFO, "Entering dccp_detach!\n"));
	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}
	INP_LOCK(inp);
	dp = (struct dccpcb *)inp->inp_ppcb;
	if (! dccp_disconnect2(dp))
		INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return 0;
}

/*
 * 
 *
 */
static int
dccp_disconnect(struct socket *so)
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int s = splnet();

	DCCP_DEBUG((LOG_INFO, "Entering dccp_disconnect!\n"));
	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		return EINVAL;
	}
	INP_LOCK(inp);
	if (inp->inp_faddr.s_addr == INADDR_ANY) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		INP_UNLOCK(inp);
		return ENOTCONN;
	}

	dp = (struct dccpcb *)inp->inp_ppcb;

	if (!dccp_disconnect2(dp))
		INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
	return 0;
}

/*
 * If we have don't have a established connection
 * we can call dccp_close, otherwise we can just
 * set SS_ISDISCONNECTED and flush the receive queue.
 */
static int
dccp_disconnect2(struct dccpcb *dp)
{
	struct socket *so = dp->d_inpcb->inp_socket;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_disconnect2!\n"));

	if (dp->state < DCCPS_ESTAB) {
		dccp_close(dp);
		return 1;
	} else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		if (dp->state == DCCPS_ESTAB) {
			dp->retrans = 100;
			dp->retrans_timer = timeout(dccp_retrans_t, dp, dp->retrans);
			dp->close_timer = timeout(dccp_close_t, dp, DCCP_CLOSE_TIMER);
			if (dp->who == DCCP_CLIENT) {
				dp->state = DCCPS_CLIENT_CLOSE;
			} else {
				dp->state = DCCPS_SERVER_CLOSE;
			}
			dccp_output(dp, 0);
		}
	}
	return 0;
}

static int
dccp_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	    struct mbuf *control, 
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	    struct thread *td)
#else
	    struct proc *td)
#endif
{
	struct inpcb	*inp;
	struct dccpcb	*dp;
	int		error = 0;
	int		isipv6 = 0;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_send!\n"));

	INP_INFO_WLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_WUNLOCK(&dccpbinfo);
		m_freem(m);
		return EINVAL;
	}
	INP_LOCK(inp);

#ifdef INET6
	isipv6 = addr && addr->sa_family == AF_INET6;
#endif

	dp = (struct dccpcb *)inp->inp_ppcb;
	if (dp->state != DCCPS_ESTAB) {
		DCCP_DEBUG((LOG_INFO, "We have no established connection!\n"));
	}

	if (control != NULL) {
		DCCP_DEBUG((LOG_INFO, "We got a control message!\n"));
		/* Are we going to use control messages??? */
		if (control->m_len) {
			m_freem(control);
		}
	}


	if (sbspace(&so->so_snd) < -512) {
		m_freem(m);
		error = ENOBUFS;
		goto out;
	}

	sbappend(&so->so_snd, m);

	if (addr && dp->state == DCCPS_CLOSED) {
		error = dccp_doconnect(dp, addr, td, isipv6);
		if (error)
			goto out;
	}

	error = dccp_output(dp, 0);

out:
	INP_UNLOCK(inp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	return error; 
}

/*
 * Sets socket to SS_CANTSENDMORE 
 */
int
dccp_shutdown(struct socket *so)
{
	struct inpcb *inp;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_shutdown!\n"));
	INP_INFO_RLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		return EINVAL;
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	socantsendmore(so);
	INP_UNLOCK(inp);
	return 0;
}

static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp_listen(struct socket *so, struct thread *td)
#else
dccp_listen(struct socket *so, struct proc *td)
#endif
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int error = 0;
	int s = splnet();

	DCCP_DEBUG((LOG_INFO, "Entering dccp_listen!\n"));

	INP_INFO_RLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	dp = (struct dccpcb *)inp->inp_ppcb;
	if (inp->inp_lport == 0)
		error = in_pcbbind(inp, (struct sockaddr *)0, td);
	if (error == 0) {
		dp->state = DCCPS_LISTEN;
		dp->who = DCCP_LISTENER;
	}
	INP_UNLOCK(inp);
	splx(s);
	return error;
}

#ifdef INET6
static int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
dccp6_listen(struct socket *so, struct thread *td)
#else
dccp6_listen(struct socket *so, struct proc *td)
#endif
{
	struct inpcb *inp;
	struct dccpcb *dp;
	int error = 0;
	int s = splnet();

	DCCP_DEBUG((LOG_INFO, "Entering dccp6_listen!\n"));

	INP_INFO_RLOCK(&dccpbinfo);
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
		inp->inp_vflag &= ~INP_IPV4;
		if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0)
			inp->inp_vflag |= INP_IPV4;
		error = in6_pcbbind(inp, (struct sockaddr *)0, td);
	}
	if (error == 0) {
		dp->state = DCCPS_LISTEN;
		dp->who = DCCP_LISTENER;
		dp->seq_snd = 512;
	}
	INP_UNLOCK(inp);
	splx(s);
	return error;
}
#endif

/*
 * Accepts a connection (accept system call)
 */
static int
dccp_accept(struct socket *so, struct sockaddr **nam)
{
	struct inpcb *inp = NULL;
	struct dccpcb *dp = NULL;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	struct in_addr addr;
	in_port_t port = 0;
#endif
	int error = 0;
	int s;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_accept!\n"));

	if (so->so_state & SS_ISDISCONNECTED) {
		DCCP_DEBUG((LOG_INFO, "so_state && SS_ISDISCONNECTED!, so->state = %i\n", so->so_state));
		return ECONNABORTED;
	}

	s = splnet();

	INP_INFO_RLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	dp = (struct dccpcb *)inp->inp_ppcb;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	port = inp->inp_fport;
	addr = inp->inp_faddr;
#else
	in_setpeeraddr(so, nam);
#endif

	INP_UNLOCK(inp);
	splx(s);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	if (error == 0)
		*nam = in_sockaddr(port, &addr);
#endif
	return error;
}

static int
dccp6_accept(struct socket *so, struct sockaddr **nam)
{
	struct inpcb *inp = NULL;
	struct dccpcb *dp = NULL;
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

	s = splnet();

	INP_INFO_RLOCK(&dccpbinfo);
	inp = sotoinpcb(so);
	if (inp == 0) {
		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		return EINVAL;
	}
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	dp = (struct dccpcb *)inp->inp_ppcb;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
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

/*
 * Initializes a new DCCP control block
 * (in_pcballoc in attach has already allocated memory for it)
 */
struct dccpcb *
dccp_newdccpcb(struct inpcb *inp)
{
	struct inp_dp		*id;
	struct dccpcb	*dp;

	DCCP_DEBUG((LOG_INFO, "Creating a new dccpcb!\n"));

	id = (struct inp_dp *)inp;
	dp = &id->dp;
	bzero((char *) dp, sizeof(struct dccpcb));

	callout_handle_init(&dp->connect_timer);
	callout_handle_init(&dp->retrans_timer);
	callout_handle_init(&dp->close_timer);
	callout_handle_init(&dp->timewait_timer);

	dp->d_inpcb = inp;
	dp->ndp = 0;
	dp->loss_window = 1000;
	dp->cslen = 15;
	dp->pref_cc = DEFAULT_CCID;
	dp->who = DCCP_UNDEF;
	dp->seq_snd = 0;
	dp->seq_rcv = 0;
	dp->gsn_rcv = 1073741824;
	dp->optlen = 0;
	dp->cc_in_use[0] = -1;
	dp->cc_in_use[1] = -1;
	dp->av_size = 0; /* no ack vector initially */
	dp->remote_ackvector = 0; /* no ack vector on remote side initially */
	dp->retrans = 200;
	dp->avgpsize = 0;
	dp->d_maxseg = 1400;
	
	inp->inp_ppcb = (caddr_t)dp;
	return dp;
}

int
dccp_add_option(struct dccpcb *dp, u_int8_t opt, char *val, u_int8_t val_len) {
	return dccp_add_feature_option(dp, opt, 0, val, val_len);
}

int
dccp_add_feature_option(struct dccpcb *dp, u_int8_t opt, u_int8_t feature, char *val, u_int8_t val_len)
{
	int i;
	DCCP_DEBUG((LOG_INFO, "Entering dccp_add_option, opt = %u, val_len = %u\n", opt, val_len));

	if (DCCP_MAX_OPTIONS > (dp->optlen + val_len + 2)) {
		dp->options[dp->optlen] = opt;
		if (opt < 32) {
			dp->optlen++;
		} else {
			if (opt == DCCP_OPT_CONFIRM) {
				dp->options[dp->optlen + 1] = val_len + 3;
				dp->options[dp->optlen +2] = feature;
				dp->optlen += 3;
			} else {
				dp->options[dp->optlen + 1] = val_len + 2;
				dp->optlen += 2;
			}
	
			for (i = 0; i<val_len; i++) {
				dp->options[dp->optlen] = val[i];
				dp->optlen++;
			}
		}
	} else {
		DCCP_DEBUG((LOG_INFO, "No room for more options, optlen = %u\n", dp->optlen));
		return -1;
	}

	return 0;
}

/**
 * Searches "options" for given option type. if found, the data is copied to buffer
 * and returns the data length.
 * Returns 0 if option type not found
 **/
int
dccp_get_option(char *options, int optlen, int type, char *buffer, int buflen)
{
	int i, j, size;
	u_int8_t t;
	
	for (i=0; i < optlen;) {
		t = options[i++];
		if (t >= 32){		  
			size = options[i++] - 2;
			if (t == type) {
				if (size > buflen)
					return 0;
				for (j = 0; j < size; j++)
					buffer[j] = options[i++];
				return size;
			}
			i += size;
		}
	}
	/* If we get here the options was not found */
	return 0;
}

void
dccp_parse_options(struct dccpcb *dp, char *options, int optlen)
{
	u_int8_t opt, size, i, j;
	char val[8];

	for (i = 0; i < optlen; i++) {
		opt = options[i];

		DCCP_DEBUG((LOG_INFO, "Parsing opt: 0x%02x\n", opt));

		if (opt < 32) {
			switch(opt) {
			    case DCCP_OPT_PADDING:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_PADDING!\n"));
				break;
			    case DCCP_OPT_DATA_DISCARD:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_DATA_DISCARD!\n"));
				break;
			    case DCCP_OPT_SLOW_RECV:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_SLOW_RECV!\n"));
				break;
			    case DCCP_OPT_BUF_CLOSED:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_BUF_CLOSED!\n"));
				break;
			    default:
				DCCP_DEBUG((LOG_INFO, "Got an unknown option, option = %u!\n", opt));
			}
		} else if (opt > 32 && opt < 36) {
			size = options[i+ 1];
			if (size < 3 || size > 10) {
				DCCP_DEBUG((LOG_INFO, "Error, option size = %u\n", size));
				return;
			}
			/* Feature negotiations are options 33 to 35 */ 
			DCCP_DEBUG((LOG_INFO, "Got option %u, size = %u, feature = %u\n", opt, size, options[i+2]));
			bcopy(options + i + 3, val, size -3);
			DCCP_DEBUG((LOG_INFO, "Calling dccp_feature neg(%u, %u, options[%u + 1], %u)!\n", (u_int)dp, opt, i+ 1, (size - 3)));
			dccp_feature_neg(dp, opt, options[i+2], (size -3) , val);
			i += size - 1;

		} else if (opt < 128) {
			size = options[i+ 1];
			if (size < 3 || size > 10) {
				DCCP_DEBUG((LOG_INFO, "Error, option size = %u\n", size));
				return;
			}

			switch(opt) {
			    case DCCP_OPT_IGNORED:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_IGNORED!\n"));
				if (size != 4) {
					DCCP_DEBUG((LOG_INFO, "Error, got a DCCP_OPT_IGNORED but size = %u (should be 4)\n", size));
					return;
				}
				if (options[2] > 32 && options[2] < 36) {
					/* Feature negotiations */
					DCCP_DEBUG((LOG_INFO, "Remote DCCP did not understand feature %u, running dccp_remove_feature(dp, %u, %u)\n", options[3], options[2], options[3]));
					dccp_remove_feature(dp, options[2], options[3]);
				}
				break;

			    case DCCP_OPT_RECV_BUF_DROPS:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_RECV_BUF_DROPS, size = %u!\n", size));
				for (j=2; j < size; j++) {
					DCCP_DEBUG((LOG_INFO, "val[%u] = %u ", j-1, options[i+j]));
				}
				DCCP_DEBUG((LOG_INFO, "\n"));
				break;

			    case DCCP_OPT_TIMESTAMP:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_TIMESTAMP, size = %u\n", size));

				/* Adding TimestampEcho to next outgoing */
				bcopy(options + i + 2, val, 4);
				bzero(val + 4, 4);
				dccp_add_option(dp, DCCP_OPT_TIMESTAMP_ECHO, val, 8);
				break;
				
			    case DCCP_OPT_TIMESTAMP_ECHO:
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_TIMESTAMP_ECHO, size = %u\n",size));
				for (j=2; j < size; j++) {
					DCCP_DEBUG((LOG_INFO, "val[%u] = %u ", j-1, options[i+j]));
				}
				DCCP_DEBUG((LOG_INFO, "\n"));

				/*
				bcopy(options + i + 2, &(dp->timestamp_echo), 4);
				bcopy(options + i + 6, &(dp->timestamp_elapsed), 4);
				ACK_DEBUG((LOG_INFO, "DATA; echo = %u , elapsed = %u\n",
					   dp->timestamp_echo, dp->timestamp_elapsed));
				*/
				
				break;

			case DCCP_OPT_ACK_VECTOR0:
			case DCCP_OPT_ACK_VECTOR1:
				/* Dont do nothing here. Let the CC deal with it */
				break;
				
			default:
				DCCP_DEBUG((LOG_INFO, "Got an unknown option, option = %u, size = %u!\n", opt, size));
				break;

			}
			i += size - 1;

		} else {
			DCCP_DEBUG((LOG_INFO, "Got a CCID option, do nothing!"));
			size = options[i+ 1];
			if (size < 3 || size > 10) {
				DCCP_DEBUG((LOG_INFO, "Error, option size = %u\n", size));
				return;
			}
			i += size - 1;
		}
	}

}

int
dccp_add_feature(struct dccpcb *dp, u_int8_t opt, u_int8_t feature, char *val, u_int8_t val_len)
{
	int i;
	DCCP_DEBUG((LOG_INFO, "Entering dccp_add_feature, opt = %u, feature = %u, val_len = %u\n", opt, feature, val_len));

	if (DCCP_MAX_OPTIONS > (dp->featlen + val_len + 3)) {
		dp->features[dp->featlen] = opt;
		dp->features[dp->featlen + 1] = val_len + 3;
		dp->features[dp->featlen +2] = feature;
		dp->featlen += 3;
		for (i = 0; i<val_len; i++) {
			dp->features[dp->featlen] = val[i];
			dp->featlen++;
		}
	} else {
		DCCP_DEBUG((LOG_INFO, "No room for more features, featlen = %u\n", dp->featlen));
		return -1;
	}

	return 0;
}

int
dccp_remove_feature(struct dccpcb *dp, u_int8_t opt, u_int8_t feature)
{
	int i = 0, j = 0, k;
	u_int8_t t_opt, t_feature, len;
	DCCP_DEBUG((LOG_INFO, "Entering dccp_remove_feature, featlen = %u, opt = %u, feature = %u\n", dp->featlen, opt, feature));

	while (i < dp->featlen) {
		t_opt = dp->features[i];
		len = dp->features[i+ 1];

		if (i + len > dp->featlen) {
			DCCP_DEBUG((LOG_INFO, "Error, len = %u and i(%u) + len > dp->featlen (%u)\n", len, i, dp->featlen));
			return 1;
		}
		t_feature = dp->features[i+2];

		if (t_opt == opt && t_feature == feature) {
			i += len;
		} else {
			if (i != j) {
				for (k = 0; k < len; k++) {
					dp->features[j+k] = dp->features[i+k];
				}
			}
			i += len;
			j += len;
		}
	}
	dp->featlen = j;
	DCCP_DEBUG((LOG_INFO, "Exiting dccp_remove_feature, featlen = %u\n", dp->featlen));
	return 0;
}

void
dccp_feature_neg(struct dccpcb *dp, u_int8_t opt, u_int8_t feature, u_int8_t val_len, char *val)
{
	char ignored[2];
	DCCP_DEBUG((LOG_INFO, "Running dccp_feature_neg, opt = %u, feature = %u len = %u ", opt, feature, val_len));

	switch(feature) {
		case DCCP_FEATURE_CC:
			DCCP_DEBUG((LOG_INFO, "Got CCID negotiation, opt = %u, val[0] = %u\n", opt, val[0]));
			if (opt == DCCP_OPT_CHANGE) {
				if (val[0] == 2 || val[0] == 3 || val[0] == 0) {
					DCCP_DEBUG((LOG_INFO, "Sending DCCP_OPT_CONFIRM on CCID %u\n", val[0]));
					dccp_remove_feature(dp, DCCP_OPT_PREFER, DCCP_FEATURE_CC);
					dccp_remove_feature(dp, DCCP_OPT_CONFIRM, DCCP_FEATURE_CC);
					dccp_add_feature_option(dp, DCCP_OPT_CONFIRM, DCCP_FEATURE_CC , val, 1);
					if (dp->cc_in_use[0] < 1) {
						dp->cc_state[0] = (*cc_sw[val[0] + 1].cc_send_init)(dp);
						dp->cc_in_use[0] = val[0] + 1;
					} else {
						DCCP_DEBUG((LOG_INFO, "We already have negotiated a CC!!!\n"));
					}
				}
			} else if (opt == DCCP_OPT_PREFER) {
				if (val[0] == 2 || val[0] == 3 || val[0] == 0) {
					DCCP_DEBUG((LOG_INFO, "Sending DCCP_OPT_CHANGE on CCID %u\n", val[0]));
					dccp_remove_feature(dp, DCCP_OPT_CHANGE, DCCP_FEATURE_CC);
					dccp_add_feature(dp, DCCP_OPT_CHANGE, DCCP_FEATURE_CC, val, 1);
					if (dp->cc_in_use[1] < 1) {
						dp->cc_in_use[1] = 0;
					} else {
						DCCP_DEBUG((LOG_INFO, "We already have negotiated a CC!!!\n"));
					}
				}
			} else if (opt == DCCP_OPT_CONFIRM) {
				DCCP_DEBUG((LOG_INFO, "Got DCCP_OPT_CONFIRM on CCID %u\n", val[0]));
				dccp_remove_feature(dp, DCCP_OPT_CHANGE, DCCP_FEATURE_CC);
				if (dp->cc_in_use[1] < 1) {
					dp->cc_state[1] = (*cc_sw[val[0] + 1].cc_recv_init)(dp);
					dp->cc_in_use[1] = val[0] + 1;
				} else {
					DCCP_DEBUG((LOG_INFO, "We already have negotiated a CC!!!\n"));
				}
			}
		
		break;

		case DCCP_FEATURE_ACKVECTOR:
			ACK_DEBUG((LOG_INFO, "Got _Use Ack Vector_\n"));
			if (opt == DCCP_OPT_CHANGE) {
				if (val[0] == 1) {
					dccp_use_ackvector(dp);
					dccp_remove_feature(dp, DCCP_OPT_CONFIRM, DCCP_FEATURE_ACKVECTOR);
					dccp_add_feature_option(dp, DCCP_OPT_CONFIRM, DCCP_FEATURE_ACKVECTOR , val, 1);
				} else {
					ACK_DEBUG((LOG_INFO, "ERROR. Strange val %u\n", val[0]));
				}
			} else if (opt == DCCP_OPT_CONFIRM) {
					dccp_remove_feature(dp, DCCP_OPT_CONFIRM, DCCP_FEATURE_ACKVECTOR);
			if (val[0] == 1) {
					dp->remote_ackvector = 1;
					ACK_DEBUG((LOG_INFO,"Remote side confirmed AckVector usage\n"));
				} else {
					ACK_DEBUG((LOG_INFO, "ERROR. Strange val %u\n", val[0]));
				}
			} else if (opt == DCCP_OPT_PREFER) {
				ACK_DEBUG((LOG_INFO, "Prefer Ack Vector? MENTAL!!!!\n"));
			}
			break;
			
        	case DCCP_FEATURE_ACKRATIO:
                        if (opt == DCCP_OPT_CHANGE) {
				bcopy(val , &(dp->ack_ratio), 1);
                                ACK_DEBUG((LOG_INFO, "Feature: Change Ack Ratio to %u\n", dp->ack_ratio));
                        }
                        break;
			
		case DCCP_FEATURE_ECN:
		case DCCP_FEATURE_MOBILITY:
		default:
			ignored[0] = opt;
			ignored[1] = feature;
			dccp_add_option(dp, DCCP_OPT_IGNORED, ignored, 2);
		break;

	}
}

static int
dccp_pcblist(SYSCTL_HANDLER_ARGS)
{

	int error, i, n, s;
	struct inpcb *inp, **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == 0) {
		n = dccpbinfo.ipi_count;
		req->oldidx = 2 * (sizeof xig)
		        + (n + n/8) * sizeof(struct xdccpcb);
		return 0;
        }


	if (req->newptr != 0)
		return EPERM;


	/*
	 * OK, now we're committed to doing something.
	 */
	s = splnet();
	gencnt = dccpbinfo.ipi_gencnt;
	n = dccpbinfo.ipi_count;
	splx(s);

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	sysctl_wire_old_buffer(req, 2 * (sizeof xig)
	        + n * sizeof(struct xdccpcb));
#endif

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
        
	s = splnet();
	INP_INFO_RLOCK(&dccpbinfo);

	for (inp = LIST_FIRST(dccpbinfo.listhead), i = 0; inp && i < n;
	     inp = LIST_NEXT(inp, inp_list)) {
INP_LOCK(inp);
		if (inp->inp_gencnt <= gencnt &&
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
		    cr_canseesocket(req->td->td_ucred, inp->inp_socket) == 0)
#else
		    !prison_xinpcb(req->p, inp))
#endif
			inp_list[i++] = inp;
		INP_UNLOCK(inp);
	}
	INP_INFO_RUNLOCK(&dccpbinfo);
	splx(s);
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		INP_LOCK(inp);

		if (inp->inp_gencnt <= gencnt) {
			struct xdccpcb xd;
			caddr_t	inp_ppcb;
			xd.xd_len = sizeof xd;
			/* XXX should avoid extra copy */
			bcopy(inp, &xd.xd_inp, sizeof *inp);
			inp_ppcb = inp->inp_ppcb;
			if (inp_ppcb != NULL)
				bcopy(inp_ppcb, &xd.xd_dp, sizeof xd.xd_dp);
			else
				bzero((char *) &xd.xd_dp, sizeof xd.xd_dp);
			if (inp->inp_socket)
       				 sotoxsocket(inp->inp_socket, &xd.xd_socket);
			error = SYSCTL_OUT(req, &xd, sizeof xd);
		}
                INP_UNLOCK(inp);
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		s = splnet();
		INP_INFO_RLOCK(&dccpbinfo);
		xig.xig_gen = dccpbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = dccpbinfo.ipi_count;


		INP_INFO_RUNLOCK(&dccpbinfo);
		splx(s);
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	free(inp_list, M_TEMP);
	return error;
}

SYSCTL_PROC(_net_inet_dccp, DCCPCTL_PCBLIST, pcblist, CTLFLAG_RD, 0, 0,
            dccp_pcblist, "S,xdccpcb", "List of active DCCP sockets");


void dccp_timewait_t(void *dcb)
{
	struct dccpcb *dp = dcb;
	int s; 

	DCCP_DEBUG((LOG_INFO, "Entering dccp_timewait_t!\n"));
	s = splnet();
	INP_INFO_WLOCK(&dccpbinfo);
	INP_LOCK(dp->d_inpcb);
	dccp_close(dp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
}

void dccp_connect_t(void *dcb)
{
	struct dccpcb *dp = dcb;
	int s;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_connect_t!\n"));
	s = splnet();
	INP_INFO_WLOCK(&dccpbinfo);
	INP_LOCK(dp->d_inpcb);
	dccp_close(dp);
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
}

void dccp_close_t(void *dcb)
{
	struct dccpcb *dp = dcb;
	int s;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_close_t!\n"));
	s = splnet();
	INP_INFO_WLOCK(&dccpbinfo);
	dp->state = DCCPS_TIME_WAIT; /* HMM */
	if (dp->who == DCCP_SERVER) {
		INP_LOCK(dp->d_inpcb);
		dccp_output(dp, DCCP_TYPE_RESET + 2);
		dccp_close(dp);
	} else {
		INP_LOCK(dp->d_inpcb);
		dccp_output(dp, DCCP_TYPE_RESET + 2);
		/*dp->state = DCCPS_TIME_WAIT; */
		dp->timewait_timer = timeout(dccp_timewait_t, dp, DCCP_TIMEWAIT_TIMER);
		INP_UNLOCK(dp->d_inpcb);
	}
	INP_INFO_WUNLOCK(&dccpbinfo);
	splx(s);
}

void dccp_retrans_t(void *dcb)
{
	struct dccpcb *dp = dcb;
	struct inpcb *inp;
	int s;

	DCCP_DEBUG((LOG_INFO, "Entering dccp_retrans_t!\n"));
	s = splnet();
	INP_INFO_RLOCK(&dccpbinfo);
	inp = dp->d_inpcb;
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);
	untimeout(dccp_retrans_t, dp, dp->retrans_timer);
	dccp_output(dp, 0);
	dp->retrans = dp->retrans * 2;
	timeout(dccp_retrans_t, dp, dp->retrans);
	INP_UNLOCK(inp);
	splx(s);
}


/*
 * This is the wrapper function for in_setsockaddr.  We just pass down 
 * the pcbinfo for in_setsockaddr to lock.  We don't want to do the locking 
 * here because in_setsockaddr will call malloc and might block.
 */
static int
dccp_sockaddr(struct socket *so, struct sockaddr **nam)
{
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	return (in_setsockaddr(so, nam, &dccpbinfo));
#else
	return (in_setsockaddr(so, nam));
#endif
}

/*
 * This is the wrapper function for in_setpeeraddr.  We just pass down
 * the pcbinfo for in_setpeeraddr to lock.
 */
static int
dccp_peeraddr(struct socket *so, struct sockaddr **nam)
{
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	return (in_setpeeraddr(so, nam, &dccpbinfo));
#else
	return (in_setpeeraddr(so, nam));
#endif
}

struct pr_usrreqs dccp_usrreqs = {
	dccp_abort, dccp_accept, dccp_attach, dccp_bind, dccp_connect, 
	pru_connect2_notsupp, in_control, dccp_detach, dccp_disconnect, 
	dccp_listen, dccp_peeraddr, pru_rcvd_notsupp, 
	pru_rcvoob_notsupp, dccp_send, pru_sense_null, dccp_shutdown,
	dccp_sockaddr, sosend, soreceive, sopoll
};

#ifdef INET6
struct pr_usrreqs dccp6_usrreqs = {
	dccp_abort, dccp6_accept, dccp_attach, dccp6_bind, dccp6_connect, 
	pru_connect2_notsupp, in6_control, dccp_detach, dccp_disconnect, 
	dccp6_listen, in6_mapped_peeraddr, pru_rcvd_notsupp, 
	pru_rcvoob_notsupp, dccp_send, pru_sense_null, dccp_shutdown,
	in6_mapped_sockaddr, sosend, soreceive, sopoll
};
#endif

/****** Ack Vector functions *********/

/**
 * Initialize and allocate mem for Ack Vector
 **/
void dccp_use_ackvector(struct dccpcb *dp)
{
	ACK_DEBUG((LOG_INFO,"Initializing AckVector\n"));
	if (dp->ackvector > 0) {
		ACK_DEBUG((LOG_INFO, "It was already initialized!!!\n"));
		return;
	}
	dp->av_size = DCCP_VECTORSIZE;
	/* need 2 bits per entry */
	dp->ackvector = malloc(dp->av_size/4, M_PCB, M_DONTWAIT | M_ZERO);
	if (dp->ackvector == 0) {
		DCCP_DEBUG((LOG_INFO, "Unable to allocate memory for ackvector\n"));
		/* What to do now? */
		dp->av_size = 0;
		return;
	}
	memset(dp->ackvector, 0xff, dp->av_size/4);
	dp->av_hs = dp->av_ts = 0;
	dp->av_hp = dp->ackvector;
}

/**
 * Set 'seqnr' as the new head in ackvector
 **/
void dccp_update_ackvector(struct dccpcb *dp, u_int32_t seqnr)
{
	int32_t gap;
	u_char *t;

	/* Ignore wrapping for now */
	
	ACK_DEBUG((LOG_INFO,"New head in ackvector: %u\n", seqnr));
	
	if (dp->av_size == 0) {
		ACK_DEBUG((LOG_INFO, "Update: AckVector NOT YET INITIALIZED!!!\n"));
		dccp_use_ackvector(dp);
	}
	
	if (seqnr > dp->av_hs) {
		gap = seqnr - dp->av_hs;
	} else {
		/* We received obsolete information */
		return;
	}
	
	t = dp->av_hp + (gap/4);
	if (t >= (dp->ackvector + (dp->av_size/4)))
		t -= (dp->av_size / 4); /* ackvector wrapped */
	dp->av_hp = t;
	dp->av_hs = seqnr;
}

/**
 * We've received a packet. store in local av so it's included in
 * next Ack Vector sent
 **/
void dccp_increment_ackvector(struct dccpcb *dp, u_int32_t seqnr)
{
	u_int32_t offset, dc;
	int32_t gap;
	u_char *t, *n;
	
	DCCP_DEBUG((LOG_INFO, "Entering dccp_increment_ackvecktor\n"));
	if (dp->av_size == 0) {
		ACK_DEBUG((LOG_INFO, "Increment: AckVector NOT YET INITIALIZED!!!\n"));
		dccp_use_ackvector(dp);
	}
	
	if (dp->av_hs == dp->av_ts) {
		/* Empty ack vector */
		dp->av_hs = dp->av_ts = seqnr;
	}

	/* Check for wrapping */
	if (seqnr >= dp->av_hs) {
		/* Not wrapped */
		gap = seqnr - dp->av_hs;
	} else {
		/* Wrapped */
		gap = seqnr + 0x1000000 - dp->av_hs; /* seq nr = 24 bits */
	}

	if (gap >= dp->av_size) {
		/* gap is bigger than ackvector size? baaad */
		/* maybe we should increase the ackvector here */
		DCCP_DEBUG((LOG_INFO, "increment_ackvector error. gap: %d, av_size: %d, seqnr: %d\n",
                            gap, dp->av_size, seqnr));
		return;
	}
	
	offset = gap % 4; /* hi or low 2 bits to mark */
	t = dp->av_hp + (gap/4);
	if (t >= (dp->ackvector + (dp->av_size/4)))
		t -= (dp->av_size / 4); /* ackvector wrapped */
	
	*t = *t & (~(0x03 << (offset *2))); /* turn off bits, 00 is rcvd, 11 is missing */

	dp->av_ts = seqnr + 1;
	if (dp->av_ts == 0x1000000)
		dp->av_ts = 0;

	if (gap > (dp->av_size - 128)) {
		n = malloc(dp->av_size/2, M_PCB, M_DONTWAIT | M_ZERO); /* old size * 2 */
		memset (n + dp->av_size / 4, 0xff, dp->av_size / 4); /* new half all missing */
		dc = (dp->ackvector + (dp->av_size/4)) - dp->av_hp;
		memcpy (n, dp->av_hp, dc); /* tail to end */
		memcpy (n+dc, dp->ackvector, dp->av_hp - dp->ackvector); /* start to tail */
		dp->av_size = dp->av_size * 2; /* counted in items, so it';s a doubling */
		free (dp->ackvector, M_PCB);
		dp->av_hp = dp->ackvector = n;
	}
}

/**
 * Generates the ack vector to send in outgoing packet.
 * These are backwards (first packet in ack vector is packet indicated by Ack Number,
 * subsequent are older packets).
 **/

u_int16_t dccp_generate_ackvector(struct dccpcb *dp, u_char *buf)
{
	int32_t j;
	u_int32_t i;
	u_int16_t cnt, oldlen, bufsize;
	u_char oldstate, st;

	bufsize = 16;
	cnt = 0;

	oldstate = 0x04; /* bad value */
	oldlen = 0;
	
	if (dp->av_size == 0) {
		ACK_DEBUG((LOG_INFO, "Generate: AckVector NOT YET INITIALIZED!!!\n"));
		return 0;
	}

	if (dp->seq_rcv > dp->av_ts) {
		/* AckNum is beyond our av-list , so we'll start with some
		 * 0x3 (Packet not yet received) */
		j = dp->seq_rcv - dp->av_ts -1;
		do {
			/* state | length */
			oldstate = 0x03;
			if (j > 63)
				oldlen = 63;
			else
				oldlen = j;
			
			buf[cnt] = (0x03 << 6) | oldlen;
			cnt++;
			if (cnt == bufsize) {
				/* I've skipped the realloc bshit */
				/* PANIC */
			}
			j-=63;
		} while (j > 0);
	}
	
	/* Ok now we're at dp->av_ts (unless AckNum is lower) */
	i = (dp->seq_rcv < dp->av_ts) ? dp->seq_rcv : dp->av_ts;
	st = dccp_ackvector_state(dp, i);

	if (st == oldstate) {
		cnt--;
		oldlen++;
	} else {
		oldlen = 0;
		oldstate = st;
	}

	if (dp->av_ts > dp->av_hs) {
		do {
			i--;
			st = dccp_ackvector_state(dp, i);
			if (st == oldstate && oldlen < 64) {
				oldlen++;
			} else {
				buf[cnt] = (oldstate << 6) | (oldlen & 0x3f);
				cnt++;
				oldlen = 0;
				oldstate = st;
				if (cnt == bufsize) {
					/* PANIC */
				}
			}
			
		} while (i > dp->av_hs);
	} else {
		/* It's wrapped */
		do {
			i--;
			st = dccp_ackvector_state(dp, i);
			if (st == oldstate && oldlen < 64) {
				oldlen++;
			} else {
				buf[cnt] = (oldstate << 6) | (oldlen & 0x3f);
				cnt++;
				oldlen = 0;
				oldstate = st;
				if (cnt == bufsize) {
					/* PANIC */
				}
			}
			
		} while (i > 0);
		i = 0x1000000;
		do {
			i--;
			st = dccp_ackvector_state(dp, i);
			if (st == oldstate && oldlen < 64) {
				oldlen++;
			} else {
				buf[cnt] = (oldstate << 6) | (oldlen & 0x3f);
				cnt++;
				oldlen = 0;
				oldstate = st;
				if (cnt == bufsize) {
					/* PANIC */
				}
			}
		} while (i > dp->av_hs);
	}
	
	/* add the last one */
	buf[cnt] = (oldstate << 6) | (oldlen & 0x3f);
	cnt++;

	return cnt;
}

u_char dccp_ackvector_state(struct dccpcb *dp, u_int32_t seqnr)
{
	u_int32_t gap, offset;
	u_char *t;

	/* Check for wrapping */
	if (seqnr >= dp->av_hs) {
		/* Not wrapped */
		gap = seqnr - dp->av_hs;
	} else {
		/* Wrapped */
		gap = seqnr + 0x1000000 - dp->av_hs; /* seq nr = 24 bits */
	}

	if (gap >= dp->av_size) {
		/* gap is bigger than ackvector size? baaad */
		return 0x03;
	}

	offset = gap % 4 *2;
	t = dp->av_hp + (gap/4);
	if (t >= (dp->ackvector + (dp->av_size/4)))
		t -= (dp->av_size / 4); /* wrapped */
	
	return ((*t & (0x03 << offset)) >> offset);
}

/****** End of Ack Vector functions *********/

/* No cc functions */
void* dccp_nocc_init(struct dccpcb *pcb){
  return (void*) 1;
}

void  dccp_nocc_free(void *ccb){
}

int   dccp_nocc_send_packet(void *ccb, long size){
  return 1;
}

void  dccp_nocc_send_packet_sent(void *ccb, int moreToSend, long size){
}

void  dccp_nocc_packet_recv(void *ccb, char* options ,int optlen){
}

