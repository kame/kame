/*	$KAME: sctputil.h,v 1.1 2002/04/15 08:34:07 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctputil.h,v 1.36 2002/04/01 21:59:20 randall Exp	*/

#ifndef __sctputil_h__
#define __sctputil_h__

/*
 * Copyright (C) 2002 Cisco Systems Inc,
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

#ifdef _KERNEL
u_int32_t sctp_select_initial_TSN(struct sctp_pcb *m);

u_int32_t sctp_select_a_tag(struct sctp_inpcb *m);

void
sctp_init_asoc(struct sctp_inpcb *m,struct sctp_association *asoc,int for_a_init);

void
sctp_fill_random_store(struct sctp_pcb *m);


int
sctp_timer_start(int t_type,
		 struct sctp_inpcb *ep, 
		 struct sctp_tcb *tcb,
		 struct sctp_nets *net);

int
sctp_timer_stop(int t_type,
		struct sctp_inpcb *ep, 
		struct sctp_tcb *tcb,
		struct sctp_nets *net);

u_int32_t
sctp_calculate_sum(struct mbuf *m,
		   int32_t *pktlen,
		   u_int32_t offset);

void
sctp_mtu_size_reset(struct sctp_association *asoc,
		    u_long mtu);

int
find_next_best_mtu(int cursiz);

u_int32_t
sctp_calculate_rto(struct sctp_tcb *tcb,
		   struct sctp_association *assoc,
		   struct sctp_nets *net,
		   struct timeval *old);

caddr_t
sctp_m_getptr(struct mbuf *m, int off, int len, u_int8_t *ptr);

struct sctp_paramhdr *
sctp_get_next_param(struct mbuf *m, 
		    int offset, 
		    struct sctp_paramhdr *pull, 
		    int pull_limit);

int
sctp_add_pad_tombuf(struct mbuf *m, int padlen);

int
sctp_pad_lastmbuf(struct mbuf *m,int padval);

void
sctp_ulp_notify(u_int32_t notification, struct sctp_tcb *stcb,
		u_int32_t error, void *data);

void
sctp_report_all_outbound(struct sctp_tcb *stcb);

void
sctp_abort_notification(struct sctp_tcb *stcb,int error);

/* We abort responding to an IP packet for some reason */
void
sctp_abort_association(struct sctp_inpcb *inp,
		       struct sctp_tcb *stcb,
		       struct mbuf *m,
		       int iphlen,
		       struct mbuf *operr);

/* We choose to abort via user input */
void
sctp_abort_an_association(struct sctp_inpcb *inp,
			  struct sctp_tcb *stcb,
			  int error,
			  struct mbuf *operr);

void
sctp_handle_ootb(struct sctp_inpcb *ep,
		 struct mbuf *,int iphlen,
		 int offset, int length,
		 struct mbuf *operr);

int sctp_is_there_an_abort_here(struct mbuf *m,int off);
uint32_t sctp_is_same_scope(struct sockaddr_in6 *addr1,
			    struct sockaddr_in6 *addr2);
struct sockaddr_in6 *
sctp_recover_scope(struct sockaddr_in6 *addr, struct sockaddr_in6 *lsa6);

const char * sctp_ntop4(const u_char *src, char *dst, size_t size);
const char * sctp_ntop6(const u_char *src, char *dst, size_t size);
void sctp_print_address(struct sockaddr *sa);

int	sbappendaddr_nocheck __P((struct sockbuf *sb, struct sockaddr *asa,
	    struct mbuf *m0, struct mbuf *control));

#endif /* KERNEL */
#endif
