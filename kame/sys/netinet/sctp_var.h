/*	$KAME: sctp_var.h,v 1.1 2000/12/27 05:55:07 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#ifndef _NETINET_SCTP_VAR_H_
#define _NETINET_SCTP_VAR_H_

enum sctpstate {
	SCTPS_CLOSED,
	SCTPS_COOKIE_WAIT,
	SCTPS_COOKIE_ECHOED,
	SCTPS_ESTABLISHED,
	SCTPS_SHUTDOWN_PEND,
	SCTPS_SHUTDOWN_SENT,
	SCTPS_SHUTDOWN_RCVD,
	SCTPS_SHUTDOWN_ACK_SENT,
};

struct sctpcb {
	struct inpcb *sc_inpcb;
	enum sctpstate sc_state;

	/* cookie */
	size_t sc_cookiesize;
	u_int8_t *sc_cookie;
};

#ifdef _KERNEL
#define	intosctpcb(ip)	((struct sctpcb *)(ip)->inp_ppcb)
#define	sotosctpcb(so)	(intosctpcb(sotoinpcb(so)))

void sctp_init __P((void));
void sctp_input __P((struct mbuf *, ...));
void *sctp_ctlinput __P((int, struct sockaddr *, void *));
int sctp_output __P((struct mbuf *, ...));
struct sctpcb *sctp_newsctpcb __P((int, void *));
int sctp_attach __P((struct socket *));
struct sctpcb *sctp_close __P((struct sctpcb *));
int sctp_usrreq __P((struct socket *, int, struct mbuf *, struct mbuf *,
	struct mbuf *, struct proc *));
#endif

#endif /* _NETINET_SCTP_VAR_H_ */
