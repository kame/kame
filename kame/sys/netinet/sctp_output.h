/*	$KAME: sctp_output.h,v 1.2 2002/05/20 05:50:03 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_output.h,v 1.33 2002/04/01 21:59:20 randall Exp	*/

#ifndef __sctp_output_h__
#define __sctp_output_h__

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



#include <netinet/sctp_header.h>
#ifdef _KERNEL
void
sctp_send_initiate(struct sctp_inpcb *inp,
		   struct sctp_tcb *tcb);

void
sctp_send_initiate_ack(struct sctp_inpcb *inp,
		       struct sctp_association *asoc,
		       struct mbuf *input_mbufs,
		       int iphlen);

struct mbuf *
sctp_arethere_unrecognized_parameters(struct mbuf *in_initpkt,
				      int param_offset,
				      int *abort_processing);
void
sctp_queue_op_err(struct sctp_tcb *stcb,struct mbuf *op_err);

int
sctp_send_cookie_echo(struct mbuf *m, 
		      int offset, 
		      struct sctp_tcb *stcb,
		      struct sctp_nets *netp);
int
sctp_send_cookie_ack(struct sctp_tcb *stcb);

void
sctp_send_heartbeat_ack(struct sctp_tcb *stcb,
			struct mbuf *m,
			int offset,
			int chk_length,
			struct sctp_nets *netp);

int
sctp_is_addr_restricted(register struct sctp_tcb *tcb,
			struct sockaddr *addr);


int
sctp_send_shutdown_complete(struct sctp_tcb *stcb,struct sctp_nets *net);

int
sctp_send_shutdown_complete2(struct sctp_inpcb *ep,
			     struct sockaddr *to,
			     u_int32_t vtag);

int
sctp_send_shutdown_ack(struct sctp_tcb *stcb,struct sctp_nets *net);

int
sctp_send_shutdown(struct sctp_tcb *stcb,struct sctp_nets *net);

int
sctp_send_asconf(struct sctp_tcb *stcb, struct sctp_nets *netp);

int
sctp_send_asconf_ack(struct sctp_tcb *stcb, uint32_t retrans);

void
sctp_toss_old_cookies(struct sctp_association *asoc);

void
sctp_toss_old_asconf(struct sctp_tcb *stcb);

void
sctp_fix_ecn_echo(struct sctp_association *asoc);

int
sctp_output(struct sctp_inpcb *inp,
	    struct mbuf *m,
	    struct sockaddr *addr,
	    struct mbuf *control,
	    struct proc *p);

int
sctp_chunk_output(struct sctp_inpcb *inp,
		  struct sctp_tcb *tcb,
		  int from_time_out);
void
sctp_send_abort_tcb(struct sctp_tcb *stcb,struct mbuf *operr);

void
send_forward_tsn(struct sctp_tcb *stcb,
		 struct sctp_association *asoc);

void
sctp_send_sack(struct sctp_tcb *stcb);

void
sctp_send_hb(struct sctp_tcb *tcb,int user_req,struct sctp_nets *u_net);

void
sctp_send_ecn_echo(struct sctp_tcb *tcb,struct sctp_nets *net,u_int32_t high_tsn);

void
sctp_send_cwr(struct sctp_tcb *tcb,struct sctp_nets *net,u_int32_t high_tsn);

void
sctp_handle_ecn_cwr(struct sctp_cwr_chunk *cwr,
		    struct sctp_tcb *tcb);

void
sctp_send_abort(struct mbuf *m,
		struct ip *oip,
		struct sctphdr *osh,
		int off,
		u_int32_t vtag,
		struct mbuf *operr);
void
sctp6_send_abort(struct mbuf *m,
		 struct ip6_hdr *oip,
		 struct sctphdr *osh,
		 int off,
		 u_int32_t vtag,
		 struct mbuf *operr);
void
sctp_send_operr_to(struct mbuf *m,int iphlen, 
		   struct mbuf *scm,
		   struct sctphdr *ohdr,
		   u_int32_t vtag);

#endif
#endif
