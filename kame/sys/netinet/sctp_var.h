/*	$KAME: sctp_var.h,v 1.7 2002/09/18 01:00:26 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_var.h,v 1.46 2002/04/04 16:53:46 randall Exp	*/

#ifndef _NETINET_SCTP_VAR_H_
#define _NETINET_SCTP_VAR_H_

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
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet6.h"
#include "opt_inet.h"
#endif

#if defined(__NetBSD__)
#include "opt_inet.h"
#endif

#ifndef __OpenBSD__
#include <sys/socketvar.h>
#endif

#include <netinet/sctp_pcb.h>
#include <netinet/sctp_uio.h>

/* SCTP Kernel structures */

/*
 * SCTP_INPCB structure exported to user-land via sysctl(3).
 * Evil hack: declare only if in_pcb.h and sys/socketvar.h have been
 * included.  Not all of our clients do.
 */
#ifdef __FreeBSD__
struct  xsctp_inpcb {
	size_t xs_len;
	struct inpcb		xs_inp;
	struct sctp_inpcb	xs_sctp_inpcb;
	struct sctp_tcb		xs_sctp_tcb;
	struct xsocket		xs_socket;
	u_quad_t		xs_alignment_hack;
};
#endif /* __FreeBSD__ */

/*
 * Names for SCTP sysctl objects
 */
#define SCTPCTL_STATS		1	/* statistics (read-only) */
#define	SCTPCTL_MAXDGRAM	2	/* max datagram size */
#define	SCTPCTL_RECVSPACE	3	/* default receive buffer space */
#define	SCTPCTL_PCBLIST		4	/* list of PCBs for SCTP sockets */
#if 0 /* skip 5 and 6 for now */
#define SCTPCTL_ASOC_CNT	5	/* number of assoc for zinit */
#define SCTPCTL_SCALE_VAL	6	/* how to scale up for addr's */
#endif
#define SCTPCTL_AUTOASCONF      5       /* auto asconf enable/disable flag */
#define SCTPCTL_MAXID		6

#if 0
#define SCTPCTL_NAMES { \
	{ 0, 0 }, \
	{ "stats", CTLTYPE_STRUCT }, \
	{ "maxdgram", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "pcblist", CTLTYPE_STRUCT }, \
	{ "asoccount", CTLTYPE_INT }, \
	{ "asocscale", CTLTYPE_INT }, \
        { "autoasconf", CTLTYPE_INT }, \
}
#else
#define SCTPCTL_NAMES { \
	{ 0, 0 }, \
	{ "stats", CTLTYPE_STRUCT }, \
	{ "maxdgram", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "pcblist", CTLTYPE_STRUCT }, \
        { "autoasconf", CTLTYPE_INT }, \
}
#endif /* if 0 */

#ifdef _KERNEL

#ifdef __FreeBSD__
SYSCTL_DECL(_net_inet_sctp);
extern struct	pr_usrreqs sctp_usrreqs;

#else /* to __FreeBSD__ */

#if defined(__NetBSD__)
int sctp_usrreq __P((struct socket *, int, struct mbuf *, struct mbuf *,
		      struct mbuf *, struct proc *));
#else /* to __NetBSD__ */
int sctp_usrreq __P((struct socket *, int, struct mbuf *, struct mbuf *,
		      struct mbuf *));
#endif /* __NetBSD__/else */

#endif /* __FreeBSD__ */


#define	sctp_sbspace(sb) ((long) ((sb)->sb_hiwat - (sb)->sb_cc))

extern u_long	sctp_sendspace;
extern u_long	sctp_recvspace;

#if defined(__OpenBSD__)
void sctp_fasttim(void);
#endif
#if defined(__FreeBSD__)
void	sctp_ctlinput __P((int, struct sockaddr *, void *));
int	sctp_ctloutput __P((struct socket *, struct sockopt *));
void	sctp_input __P((struct mbuf *, int));
#else
void*	sctp_ctlinput __P((int, struct sockaddr *, void *));
int	sctp_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
void	sctp_input __P((struct mbuf *, ... ));
#endif /* __FreeBSD__ */

void	sctp_init __P((void));
int	sctp_shutdown __P((struct socket *so));

void	sctp_notify __P((struct sctp_inpcb *, int, struct sctphdr *,
			 struct sockaddr *, struct sctp_tcb *,
			 struct sctp_nets *));

int sctp_usr_recvd __P((struct socket *so, int flags));


#ifdef INET6
void ip_2_ip6_hdr __P((struct ip6_hdr *ip6, struct ip *ip));
#endif /* INET6 */

int sctp_bindx(struct socket *so, int sd, struct sockaddr_storage *addrs,
	       int addrcnt, int flags, struct proc *p);

int sctp_peeloff(struct socket *so, struct socket *nso, int sd,
		 sctp_assoc_t assoc_id, int *addrlen);

int sctp_ingetaddr(struct socket *so,
#if defined(__FreeBSD__)
		   struct sockaddr **nam
#else
		   struct sockaddr *nam
#endif
);

int sctp_peeraddr(struct socket *so,
#if defined(__FreeBSD__)
		  struct sockaddr **nam
#else
		  struct sockaddr *nam
#endif
);

int sctp_listen(struct socket *so, struct proc *p);

int sctp_accept(struct socket *so,
#if defined(__FreeBSD__)
		struct sockaddr **nam
#else
		struct sockaddr *nam
#endif
);

#endif /* _KERNEL */

#endif /* !_NETINET_SCTP_VAR_H_ */
