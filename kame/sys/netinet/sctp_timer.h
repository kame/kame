/*	$KAME: sctp_timer.h,v 1.2 2002/05/20 05:50:03 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_timer.h,v 1.7 2002/04/01 21:59:20 randall Exp	*/

#ifndef __sctp_timer_h__
#define __sctp_timer_h__

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
struct sctp_nets *
sctp_find_alternate_net(struct sctp_tcb *tcb,
			struct sctp_nets *net);

int
sctp_threshold_management(struct sctp_inpcb *ep,
			  struct sctp_tcb *tcb,
			  struct sctp_nets *net,
			  u_short threshold);

void
sctp_t3rxt_timer(struct sctp_inpcb *ep,
		 struct sctp_tcb *tcb,
		 struct sctp_nets *net);
void
sctp_t1init_timer(struct sctp_inpcb *ep,
		  struct sctp_tcb *tcb,
		  struct sctp_nets *net);
void
sctp_shutdown_timer(struct sctp_inpcb *ep,
		    struct sctp_tcb *tcb,
		    struct sctp_nets *net);
void
sctp_heartbeat_timer(struct sctp_inpcb *ep,
		     struct sctp_tcb *tcb,
		     struct sctp_nets *net);

void sctp_cookie_timer(struct sctp_inpcb *ep,
		       struct sctp_tcb *tcb,
		       struct sctp_nets *net);

void sctp_pathmtu_timer(struct sctp_inpcb *ep,
			struct sctp_tcb *tcb,
			struct sctp_nets *net);

void sctp_shutdownack_timer(struct sctp_inpcb *ep,
			 struct sctp_tcb *tcb,
			 struct sctp_nets *net);

void sctp_asconf_timer(struct sctp_inpcb *ep,
		       struct sctp_tcb *tcb,
		       struct sctp_nets *net);

void sctp_autoclose_timer(struct sctp_inpcb *ep,
			  struct sctp_tcb *tcb,
			  struct sctp_nets *net);

void
sctp_audit_retranmission_queue(struct sctp_association *asoc);

#endif
#endif
