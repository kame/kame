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
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)tcp_debug.c	8.1 (Berkeley) 6/10/93
 */

#ifdef TCP6DEBUG
/* load symbolic names */
#define PRUREQUESTS
#define TCP6STATES
#define	TCP6TIMERS
#define	TANAMES
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>

#include <net/route.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_fsm.h>
#include <netinet6/tcp6_seq.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#include <netinet6/tcp6_debug.h>

#ifdef TCP6DEBUG
int	tcp6consdebug = 0;
#endif
/*
 * Tcp debug routines
 */
void
tcp6_trace(act, ostate, t6p, ip6, th, req)
	short act, ostate;
	struct tcp6cb *t6p;
	struct ip6_hdr *ip6;
	struct tcp6hdr *th;
	int req;
{
#ifdef TCP6DEBUG
	tcp6_seq seq, ack;
	int len, flags;
#endif /*TCP6DEBUG*/
	struct tcp6_debug *t6d = &tcp6_debug[tcp6_debx++];

	if (tcp6_debx == TCP6_NDEBUG)
		tcp6_debx = 0;
	t6d->t6d_time = iptime(); /* xxx */
	t6d->t6d_act = act;
	t6d->t6d_ostate = ostate;
	t6d->t6d_tcb = (caddr_t)t6p;
	if (t6p)
		t6d->t6d_cb = *t6p;
	else
		bzero((caddr_t)&t6d->t6d_cb, sizeof (*t6p));
	if (ip6 && th) {
		t6d->t6d_i = *ip6;
		t6d->t6d_t = *th;
	} else {
		bzero((caddr_t)&t6d->t6d_i, sizeof (*ip6));
		bzero((caddr_t)&t6d->t6d_t, sizeof (*th));
	}
	t6d->t6d_req = req;
#ifdef TCP6DEBUG
	if (tcp6consdebug == 0)
		return;
	if (t6p)
		printf("%x %s:", t6p, tcp6states[ostate]);
	else
		printf("???????? ");
	printf("%s ", tanames[act]);
	switch (act) {

	case TA_INPUT:
	case TA_OUTPUT:
	case TA_DROP:
		if (ip6 == 0)
			break;
		seq = th->th_seq;
		ack = th->th_ack;
		len = th->th_len; /* xxx */
		if (act == TA_OUTPUT) {
			seq = ntohl(seq);
			ack = ntohl(ack);
			len = ntohs((u_short)len);
		}
		if (act == TA_OUTPUT)
			len -= sizeof (struct tcp6hdr);
		if (len)
			printf("[%x..%x)", seq, seq+len);
		else
			printf("%x", seq);
		printf("@%x, urp=%x", ack, th->th_urp);
		flags = th->th_flags;
		if (flags) {
#ifndef lint
			char *cp = "<";
#define pf(f) { if (th->th_flags&TH_/**/f) { printf("%s%s", cp, "f"); cp = ","; } }
			pf(SYN); pf(ACK); pf(FIN); pf(RST); pf(PUSH); pf(URG);
#endif
			printf(">");
		}
		break;

	case TA_USER:
		printf("%s", prurequests[req&0xff]);
		if ((req & 0xff) == PRU_SLOWTIMO)
			printf("<%s>", tcp6timers[req>>8]);
		break;
	}
	if (t6p)
		printf(" -> %s", tcp6states[t6p->t_state]);
	/* print out internal state of t6p !?! */
	printf("\n");
	if (t6p == 0)
		return;
	printf("\trcv_(nxt,wnd,up) (%x,%x,%x) snd_(una,nxt,max) (%x,%x,%x)\n",
	    t6p->rcv_nxt, t6p->rcv_wnd, t6p->rcv_up, t6p->snd_una, t6p->snd_nxt,
	    t6p->snd_max);
	printf("\tsnd_(wl1,wl2,wnd) (%x,%x,%x)\n",
	    t6p->snd_wl1, t6p->snd_wl2, t6p->snd_wnd);
#endif /* TCP6DEBUG */
}
