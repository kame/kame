/*	$KAME: sctp_indata.h,v 1.1 2002/04/15 08:34:07 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_indata.h,v 1.12 2002/04/01 21:59:20 randall Exp	*/

#ifndef __sctp_indata_h__
#define __sctp_indata_h__

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
void
sctp_set_rwnd(struct sctp_tcb *stcb,
	      struct sctp_association *asoc);

void
sctp_handle_sack(struct sctp_sack_chunk *cp, struct sctp_tcb *stcb,
		 struct sctp_nets *netp);

/* draft-ietf-tsvwg-usctp */
void
sctp_handle_forward_tsn(struct sctp_tcb *stcb,
			struct sctp_forward_tsn_chunk *fwd);


void
sctp_try_advance_peer_ack_point(struct sctp_tcb *stcb,
				struct sctp_association *asoc);



void
sctp_service_queues(struct sctp_tcb *stcb,
		    struct sctp_association *asoc);

void
sctp_update_acked(struct sctp_tcb *stcb,
		  struct sctp_shutdown_chunk *cp,
		  struct sctp_nets *netp);
int
sctp_process_data(struct mbuf *m,
		  struct sctp_inpcb *inp,
		  struct sctp_tcb *stcb,
		  struct sctp_nets *netp,
		  int iphlen,
		  int *offset,
		  int *length,
		  u_int32_t *high_tsn);
#endif
#endif
