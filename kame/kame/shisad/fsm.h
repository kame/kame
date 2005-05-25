/*	$KAME: fsm.h,v 1.2 2005/05/25 01:49:24 keiichi Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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

#ifndef _SHISAD_FSM_H_
#define _SHISAD_FSM_H_

/* states for the primary fsm. */
#define MIP6_BUL_REG_FSM_STATE_IDLE		0
#define MIP6_BUL_REG_FSM_STATE_RRINIT		1
#define MIP6_BUL_REG_FSM_STATE_RRREDO		2
#define MIP6_BUL_REG_FSM_STATE_RRDEL		3
#define MIP6_BUL_REG_FSM_STATE_WAITA		4
#define MIP6_BUL_REG_FSM_STATE_WAITAR		5
#define MIP6_BUL_REG_FSM_STATE_WAITD		6
#define MIP6_BUL_REG_FSM_STATE_BOUND		7
#define MIP6_BUL_REG_FSM_STATE_DHAAD		8

/* states for the secondary fsm. */
#define MIP6_BUL_RR_FSM_STATE_START	0
#define MIP6_BUL_RR_FSM_STATE_WAITHC	1
#define MIP6_BUL_RR_FSM_STATE_WAITH	2
#define MIP6_BUL_RR_FSM_STATE_WAITC	3
#define MIP6_BUL_IS_RR_FSM_RUNNING(bul)				\
	(((bul)->bul_rr_fsm_state == MIP6_BUL_RR_FSM_STATE_WAITHC)	\
	 || ((bul)->bul_rr_fsm_state == MIP6_BUL_RR_FSM_STATE_WAITH)	\
	 || ((bul)->bul_rr_fsm_state == MIP6_BUL_RR_FSM_STATE_WAITC))

/* events for the registration fsm. */
#define MIP6_BUL_FSM_EVENT_MOVEMENT		0
#define MIP6_BUL_FSM_EVENT_RETURNING_HOME	1
#define MIP6_BUL_FSM_EVENT_REVERSE_PACKET	2
#define MIP6_BUL_FSM_EVENT_RR_DONE		3
#define MIP6_BUL_FSM_EVENT_RR_FAILED		4
#define MIP6_BUL_FSM_EVENT_BRR			5
#define MIP6_BUL_FSM_EVENT_BACK			6
#define MIP6_BUL_FSM_EVENT_REGISTERED		7
#define MIP6_BUL_FSM_EVENT_DEREGISTERED		8
#define MIP6_BUL_FSM_EVENT_UNKNOWN_HAO		9
#define MIP6_BUL_FSM_EVENT_UNKNOWN_MH		10
#define MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB	11
#define MIP6_BUL_FSM_EVENT_EXPIRE_TIMER		12
#define MIP6_BUL_FSM_EVENT_DHAAD_REPLY		13
#define MIP6_BUL_IS_REG_FSM_EVENT(ev)				\
	(((ev) >= 0)						\
	 && ((ev) <= MIP6_BUL_FSM_EVENT_DHAAD_REPLY))

/* events for the rr fsm. */
#define MIP6_BUL_FSM_EVENT_START_RR		20
#define MIP6_BUL_FSM_EVENT_START_HOME_RR	21
#define MIP6_BUL_FSM_EVENT_STOP_RR		22
#define MIP6_BUL_FSM_EVENT_HOT			23
#define MIP6_BUL_FSM_EVENT_COT			24
#define MIP6_BUL_IS_RR_FSM_EVENT(ev)		\
	(((ev) >= MIP6_BUL_FSM_EVENT_START_RR)	\
	 && (((ev) <= MIP6_BUL_FSM_EVENT_COT)))

/* timeout events */
#define MIP6_BUL_FSM_EVENT_RETRANS_TIMER	30

struct fsm_message {
	struct in6_addr *fsmm_src;
	struct in6_addr *fsmm_dst;
	struct in6_addr *fsmm_hoa;
	struct in6_addr *fsmm_rtaddr;
	void *fsmm_data;
	size_t fsmm_datalen;
};

int bul_kick_fsm_by_mh(struct in6_addr *, struct in6_addr *, struct in6_addr *,
    struct in6_addr *, struct ip6_mh *, int);
int bul_kick_fsm(struct binding_update_list *, int, struct fsm_message *);
void bul_retrans_timer(void *);
void bul_expire_timer(void *);

#endif /* !_SHISAD_FSM_H_ */
