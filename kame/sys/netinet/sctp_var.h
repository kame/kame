/*	$KAME: sctp_var.h,v 1.20 2004/05/26 10:08:01 itojun Exp $	*/

/*
 * Copyright (c) 2001, 2002, 2003, 2004 Cisco Systems, Inc.
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

#ifndef _NETINET_SCTP_VAR_H_
#define _NETINET_SCTP_VAR_H_

#ifndef __OpenBSD__
#include <sys/socketvar.h>
#endif

/* SCTP Kernel structures */


/*
 * Names for SCTP sysctl objects
 */
#define	SCTPCTL_MAXDGRAM	1	/* max datagram size */
#define	SCTPCTL_RECVSPACE	2	/* default receive buffer space */
#define SCTPCTL_AUTOASCONF      3       /* auto asconf enable/disable flag */
#define SCTPCTL_MAXID		3

#define SCTPCTL_NAMES { \
	{ 0, 0 }, \
	{ "maxdgram", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "autoasconf", CTLTYPE_INT }, \
}


#ifdef _KERNEL

#ifdef __FreeBSD__
SYSCTL_DECL(_net_inet_sctp);
extern struct	pr_usrreqs sctp_usrreqs;

#else /* to __FreeBSD__ */

#ifdef __NetBSD__
int sctp_usrreq __P((struct socket *, int, struct mbuf *, struct mbuf *,
		      struct mbuf *, struct proc *));
#else /* to __NetBSD__ */
int sctp_usrreq __P((struct socket *, int, struct mbuf *, struct mbuf *,
		      struct mbuf *));
#endif /* __NetBSD__/else */

#endif /* __FreeBSD__ */


#define	sctp_sbspace(sb) ((long) (((sb)->sb_hiwat > (sb)->sb_cc) ? ((sb)->sb_hiwat - (sb)->sb_cc) : 0))

extern int	sctp_sendspace;
extern int	sctp_recvspace;

struct sctp_nets;
struct sctp_inpcb;
struct sctp_tcb;
struct sctphdr;

#ifdef __OpenBSD__
void sctp_fasttim(void);
#endif
#ifdef __FreeBSD__
void	sctp_ctlinput __P((int, struct sockaddr *, void *));
int	sctp_ctloutput __P((struct socket *, struct sockopt *));
void	sctp_input __P((struct mbuf *, int));
#else
void*	sctp_ctlinput __P((int, struct sockaddr *, void *));
int	sctp_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
void	sctp_input __P((struct mbuf *, ... ));
#endif /* __FreeBSD__ */

void	sctp_init __P((void));
int	sctp_shutdown __P((struct socket *));

void	sctp_notify __P((struct sctp_inpcb *, int, struct sctphdr *,
			 struct sockaddr *, struct sctp_tcb *,
			 struct sctp_nets *));

int sctp_usr_recvd __P((struct socket *, int));


void ip_2_ip6_hdr __P((struct ip6_hdr *, struct ip *));

int sctp_bindx(struct socket *, int, struct sockaddr_storage *,
	int, int, struct proc *);

/* can't use sctp_assoc_t here */
int sctp_peeloff(struct socket *, struct socket *, int, caddr_t, int *);

int sctp_ingetaddr(struct socket *,
#ifdef __FreeBSD__
		   struct sockaddr **
#else
		   struct mbuf *
#endif
);

int sctp_peeraddr(struct socket *,
#ifdef __FreeBSD__
		  struct sockaddr **
#else
		  struct mbuf *
#endif
);

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
int sctp_listen(struct socket *, struct thread *);
#else
int sctp_listen(struct socket *, struct proc *);
#endif

int sctp_accept(struct socket *,
#ifdef __FreeBSD__
		struct sockaddr **
#else
		struct sockaddr *
#endif
);

#if defined(__NetBSD__) || defined(__OpenBSD__)
int	 sctp_sysctl(int *, u_int, void *, size_t *, void *, size_t);
#endif

#endif /* _KERNEL */

#endif /* !_NETINET_SCTP_VAR_H_ */
