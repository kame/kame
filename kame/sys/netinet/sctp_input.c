/*	$KAME: sctp_input.c,v 1.5 2002/06/09 16:29:54 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_input.c,v 1.189 2002/04/04 18:37:12 randall Exp	*/

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

#ifndef __OpenBSD__
#include "opt_ipsec.h"
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_compat.h"
#include "opt_inet6.h"
#include "opt_inet.h"
#endif
#if defined(__NetBSD__)
#include "opt_inet.h"
#endif
#ifndef __OpenBSD__
#include "opt_sctp.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#if defined (__OpenBSD__)
#include <netinet/sctp_callout.h>
#else
#include <sys/callout.h>
#endif
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/syslog.h>

#include <machine/limits.h>
#include <machine/cpu.h>

#if defined(__FreeBSD__)
#include <vm/vm_zone.h>
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/pool.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif /* INET6 */

#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_var.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_input.h>
#include <netinet/sctp_hashdriver.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_asconf.h>

#ifndef __FreeBSD__
#include <machine/stdarg.h>
#endif

#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif /*IPSEC*/

#ifdef SCTP_DEBUG
extern u_int32_t sctp_debug_on;
#endif



static struct sockaddr_in sctp_in = { sizeof(sctp_in), AF_INET };

#ifdef INET6
struct sctp_in6 {
	struct sockaddr_in6	sin6_sin;
	u_char			sin6_init_done : 1;
} sctp_in6 = {
	{ sizeof(sctp_in6.sin6_sin), AF_INET6 },
	0
};

struct sctp_ip6 {
	struct ip6_hdr		sip6_ip6;
	u_char			sip6_init_done : 1;
} sctp_ip6;
#endif /* INET6 */

static struct mbuf *
sctp_generate_invmanparam(int err)
{
	/* Return a MBUF with a invalid mandatory parameter */
	struct mbuf *m;
	MGET(m,M_DONTWAIT,MT_DATA);
	if(m){
		struct sctp_paramhdr *ph;
		m->m_len = sizeof(struct sctp_paramhdr);
		ph = mtod(m,struct sctp_paramhdr *);
		ph->param_length = htons(sizeof(struct sctp_paramhdr));
		ph->param_type = htons(err);
	}
	return(m);
}

/* INIT handler */
static void
sctp_handle_init(struct mbuf *m, struct sctp_init_chunk *cp,
		 struct sctp_inpcb *inp, struct sctp_tcb *stcb,
		 struct sctp_nets *netp,
		 int iphlen)
{
	struct sctp_init *init;
	struct sctp_association *assoc;
	struct mbuf *op_err;
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_init: handling INIT tcb:%x\n",(u_int)stcb);
	}
#endif
	op_err = NULL;
	init = &cp->init;
	/* First are we accepting? */
	if(((inp->sctp_flags & SCTP_PCB_FLAGS_ACCEPTING) == 0) ||
	   (inp->sctp_socket->so_qlimit == 0)){
		sctp_abort_association(inp, stcb, m, iphlen,op_err);
		return;
	}
	if(ntohs(cp->ch.chunk_length) < sizeof(struct sctp_init_chunk)){
		/* Invalid length */
		op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(inp, stcb, m, iphlen, op_err);
		return;
	}
	/* validate parameters */
	if (init->initiate_tag == 0) {
		/* protocol error... send abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(inp, stcb, m, iphlen, op_err);
		return;
	}
	if (ntohl(init->a_rwnd) < SCTP_MIN_RWND) {
		/* invalid parameter... send abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(inp, stcb, m, iphlen, op_err);
		return;
	}
	if (init->num_inbound_streams == 0) {
		/* protocol error... send abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(inp, stcb, m, iphlen, op_err);
		return;
	}
	if (init->num_outbound_streams == 0) {
		/* protocol error... send abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(inp, stcb, m, iphlen, op_err);
		return;
	}

	/* send an INIT-ACK w/cookie */
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT3){
		printf("sctp_handle_init: sending INIT-ACK\n");
	}
#endif
	assoc = NULL;
	if (stcb != NULL){
		assoc = &stcb->asoc;
	}
	/* make sure that IP/SCTP/INIT msg are in first mbuf */
	if (m->m_len < (iphlen + sizeof(struct sctp_init_msg))) {
		if ((m = m_pullup(m, iphlen + sizeof(struct sctp_init_msg))) == 0) {
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("PULLUP FAILS???\n");
			}
#endif
			sctp_pegs[SCTP_HDR_DROPS]++;
			return;
		}
	}
	sctp_send_initiate_ack(inp, assoc, m, iphlen);
}

/*
 * process peer "INIT/INIT-ACK" chunk
 * returns value < 0 on error
 */

extern struct sctp_epinfo sctppcbinfo;

static int
sctp_process_init(struct sctp_init_chunk *cp, struct sctp_tcb *stcb,
		  struct sctp_nets *netp)
{
	struct sctp_init *init;
	struct sctp_association *assoc;
	int i;

	init = &cp->init;
	assoc = &stcb->asoc;
	/* save off parameters */
	assoc->peer_vtag = ntohl(init->initiate_tag);
	assoc->peers_rwnd = ntohl(init->a_rwnd);
	if (assoc->pre_open_streams > ntohs(init->num_inbound_streams)) {
   	        int newcnt;
		struct sctp_stream_out *outs;
		struct sctp_tmit_chunk *chk;

		/* cut back on number of streams */
		newcnt = ntohs(init->num_inbound_streams);
		/* This if is probably not needed but I am cautious */
		if (assoc->strmout) {
			/* First make sure no data chunks are trapped */
			for (i=newcnt; i < assoc->pre_open_streams; i++) {
				outs = &assoc->strmout[i];
				chk = TAILQ_FIRST(&outs->outqueue);
				while (chk) {
					TAILQ_REMOVE(&outs->outqueue, chk,
						     sctp_next);
					sctp_ulp_notify(SCTP_NOTIFY_DG_FAIL, stcb, SCTP_NOTIFY_DATAGRAM_UNSENT, chk);
					if (chk->data) {
						m_freem(chk->data);
						chk->data = NULL;
					}
					sctp_free_remote_addr(chk->whoTo);
					chk->whoTo = NULL;
					chk->asoc = NULL;
					/* Free the chunk */
#if defined(__FreeBSD__)
					zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
					pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
					sctppcbinfo.ipi_count_chunk--;
					if((int)sctppcbinfo.ipi_count_chunk < 0){
						panic("Chunk count is negative");
					}
					sctppcbinfo.ipi_gencnt_chunk++;
					chk = TAILQ_FIRST(&outs->outqueue);
				}
			}
		}
		/* cut back the count and abandon the upper streams */
		assoc->pre_open_streams = newcnt;
	}
	assoc->streamincnt = ntohs(init->num_outbound_streams);
	if (assoc->streamincnt > MAX_SCTP_STREAMS) {
		assoc->streamincnt = MAX_SCTP_STREAMS;
	}

	assoc->streamoutcnt = assoc->pre_open_streams;
	/* init tsn's */
	assoc->highest_tsn_inside_map = assoc->asconf_seq_in = ntohl(init->initial_tsn) - 1;
	assoc->mapping_array_base_tsn = ntohl(init->initial_tsn);
	assoc->cumulative_tsn = assoc->asconf_seq_in;
	assoc->last_echo_tsn = assoc->asconf_seq_in;
	assoc->advanced_peer_ack_point = assoc->last_acked_seq;
	/* open the requested streams */
	if (assoc->strmin != NULL) {
		/* Free the old ones */
		free(assoc->strmin,M_PCB);
	}
	assoc->strmin = (struct sctp_stream_in *)malloc(
		(assoc->streamincnt *
		 sizeof(struct sctp_stream_in)),
		M_PCB,
		M_NOWAIT);
	if (assoc->strmin == NULL) {
		/* we didn't get memory for the streams! */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("process_init: couldn't get memory for the streams!\n");
		}
#endif
		return(-1);
	}
	for (i=0; i<assoc->streamincnt; i++) {
		assoc->strmin[i].stream_no = i;
		assoc->strmin[i].last_sequence_delivered = 0xffff;
		/* U-stream ranges will be set when the cookie
		 * is unpacked. Or for the INIT sender they
		 * are un set (if u-sctp not supported) when the
		 * INIT-ACK arrives.
		 */
		TAILQ_INIT(&assoc->strmin[i].inqueue);
		/* we are not on any wheel, u-sctp streams
		 * will go on the wheel when they have data waiting
		 * for reorder.
		 */
		assoc->strmin[i].next_spoke.tqe_next = 0;
		assoc->strmin[i].next_spoke.tqe_prev = 0;
	}

	/* load_address_from_init will put the addresses into the
	 * association when the COOKIE is processed or the INIT-ACK
	 * is processed. Both types of COOKIE's existing and new
	 * call this routine. It will remove addresses that
	 * are no longer in the association (for the restarting
	 * case where addresses are removed). Up front when the
	 * INIT arrives we will discard it if it is a restart
	 * and new addresses have been added.
	 */
	return(0);
}

/*
 * INIT-ACK message processing/consumption
 * returns value < 0 on error
 */
static int
sctp_process_init_ack(struct mbuf *m, int offset,
		      struct sctp_init_ack_chunk *cp,
		      struct sctp_tcb *stcb, struct sctp_nets *netp,
		      int iphlen)
{
	struct sctp_association *assoc;
	struct mbuf *op_err;
	int retval, abort_flag;
	unsigned int sz_of_initack;
	/* First verify that we have no illegal param's */
	abort_flag = 0;
	op_err = NULL;
	op_err = sctp_arethere_unrecognized_parameters(m,
						       (offset +
							sizeof(struct sctp_init_chunk)),
						       &abort_flag);
	if (abort_flag) {
		/* Send an abort and notify peer */
		if(op_err != NULL){
			sctp_abort_association(stcb->sctp_ep,
					       stcb,
					       m,iphlen,op_err);
		}else{
			/* Just notify (abort_assoc does this if
			 * we send an abort).
			 */
			sctp_abort_notification(stcb,0);
		}
		/* No sense in further INIT's since
		 * we will get the same param back
		 */
		sctp_free_assoc(stcb->sctp_ep,stcb);
		return(-1);
	}
	assoc = &stcb->asoc;
	/* process the peer's parameters in the INIT-ACK */
	retval = sctp_process_init((struct sctp_init_chunk *)cp, stcb, netp);
	if (retval < 0) {
		return(retval);
	}
	sz_of_initack = (unsigned int)(ntohs(cp->ch.chunk_length) +
				       iphlen +
				       sizeof(struct sctphdr));

	/* load all addresses */
	if(sctp_load_addresses_from_init(stcb,m,iphlen,
					 (offset + sizeof(struct sctp_init_chunk)),
					 (struct sockaddr *)NULL,(int)sz_of_initack)
		){
		/* Huh, we should abort */
		sctp_abort_notification(stcb,0);
		sctp_free_assoc(stcb->sctp_ep,stcb);
		return(-1);
	}
	if (op_err) {
		sctp_queue_op_err(stcb,op_err);
		/* queuing will steal away the mbuf chain to the out queue */
		op_err = NULL;
	}
	/* extract the cookie and queue it to "echo" it back... */
	retval = sctp_send_cookie_echo(m, offset, stcb, netp);
	if(retval < 0){
		/* No cookie, we probably should
		 * send a op error.
		 * But in any case if it is a no cookie in
		 * the INIT-ACK, we can abandon the peer, its broke.
		 */
		if(retval == -3){
			/* We abort with an error of
			 * missing mandatory param.
			 */
			struct mbuf *op_err;
			op_err = sctp_generate_invmanparam(SCTP_CAUSE_MISS_PARAM);
			if(op_err){
				/* Expand beyond to include the mandatory param cookie */
				struct sctp_inv_mandatory_param *mp;
				op_err->m_len = sizeof(struct sctp_inv_mandatory_param);
				mp = mtod(op_err,struct sctp_inv_mandatory_param *);
				/* Subtract the reserved param */
				mp->length = htons((sizeof(struct sctp_inv_mandatory_param)-2));
				mp->num_param = htonl(1);
				mp->param = htons(SCTP_STATE_COOKIE);
				mp->resv = 0;
			}
			sctp_abort_association(stcb->sctp_ep, stcb, m, iphlen,op_err);
		}
		return(retval);
	}

	/*
	 * Cancel the INIT timer, We do this first before queueing
	 * the cookie. We always cancel at the primary to assue that
	 * we are canceling the timer started by the INIT which always
	 * goes to the primary.
	 */
	sctp_timer_stop(SCTP_TIMER_TYPE_INIT, stcb->sctp_ep, stcb,
			assoc->primary_destination);

	/* calculate the RTO */
	netp->RTO = sctp_calculate_rto(stcb, assoc, netp, &assoc->time_entered);

	return(0);
}

static void
sctp_handle_heartbeat_ack(struct sctp_heartbeat_chunk *hb,
			  struct sctp_tcb *tcb,
			  struct sctp_nets *netp)
{
	struct sockaddr_storage store;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sctp_nets *r_net;
	struct timeval tv;

	if(ntohs(hb->ch.chunk_length) != sizeof(struct sctp_heartbeat_chunk)){
		/* Invalid length */
		return;
	}

	sin = (struct sockaddr_in *)&store;
	sin6 = (struct sockaddr_in6 *)&store;


	memset(&store,0,sizeof(store));
	if(hb->heartbeat.hb_info.addr_family == AF_INET){
		sin->sin_family = hb->heartbeat.hb_info.addr_family;
		sin->sin_len = hb->heartbeat.hb_info.addr_len;
		sin->sin_port = tcb->rport;
		memcpy(&sin->sin_addr,hb->heartbeat.hb_info.address,
		       sizeof(sin->sin_addr));
	}else{
		sin6->sin6_family = hb->heartbeat.hb_info.addr_family;
		sin6->sin6_len = hb->heartbeat.hb_info.addr_len;
		sin6->sin6_port = tcb->rport;
		memcpy(&sin6->sin6_addr,hb->heartbeat.hb_info.address,
		       sizeof(sin6->sin6_addr));
	}
	r_net = sctp_findnet(tcb,(struct sockaddr *)sin);
	if(r_net == NULL){
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("Huh? I can't find the address I sent it to, discard\n");
		}
#endif
		return;
	}
	r_net->error_count = 0;
	r_net->hb_responded = 1;
	tv.tv_sec = hb->heartbeat.hb_info.time_value_1;
	tv.tv_usec = hb->heartbeat.hb_info.time_value_2;
	if(r_net->dest_state & SCTP_ADDR_NOT_REACHABLE){
		r_net->dest_state &= ~SCTP_ADDR_NOT_REACHABLE;
		r_net->dest_state |= SCTP_ADDR_REACHABLE;
		sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_UP,
				tcb,
				SCTP_HEARTBEAT_SUCCESS,
				(void *)r_net);
		/* now was it the primary? if so restore */
		if(r_net->dest_state & SCTP_ADDR_WAS_PRIMARY){
			tcb->asoc.primary_destination = r_net;
			r_net->dest_state &= ~SCTP_ADDR_WAS_PRIMARY;
		}
	}
	/* Now lets do a RTO with this */
	r_net->RTO = sctp_calculate_rto(tcb,&tcb->asoc,r_net,&tv);
}

static void
sctp_handle_abort(struct sctp_abort_chunk *cp, struct sctp_tcb *stcb,
		  struct sctp_nets *netp)
{
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_abort: handling ABORT\n");
	}
#endif
	if (stcb == NULL)
		return;
	/* verify that the destination addr is in the association */
	/* ignore abort for addresses being deleted */

	/* stop any receive timers */
	sctp_timer_stop(SCTP_TIMER_TYPE_RECV, stcb->sctp_ep, stcb, netp);
	/* notify user of the abort and clean up... */
	sctp_abort_notification(stcb,0);
	/* free the tcb */
	sctp_free_assoc(stcb->sctp_ep, stcb);
	if(stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
		/* Yes, so can we purge ourself now */
		if(LIST_FIRST(&stcb->sctp_ep->sctp_asoc_list) == NULL){
			/* finish the job now */
			sctp_inpcb_free(stcb->sctp_ep,1);
		}
	}

#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_abort: finished\n");
	}
#endif
}

static void
sctp_handle_shutdown(struct sctp_shutdown_chunk *cp, struct sctp_tcb *stcb,
		     struct sctp_nets *netp)
{
	struct sctp_association *assoc;
	int some_on_streamwheel;
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_shutdown: handling SHUTDOWN\n");
	}
#endif
	if (stcb == NULL)
		return;

	if(ntohs(cp->ch.chunk_length) != sizeof(struct sctp_shutdown_chunk)){
		/* update current data status */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("Warning Shutdown NOT the expected size.. skipping (%d:%d)\n",
			       ntohs(cp->ch.chunk_length),sizeof(struct sctp_shutdown_chunk));
		}
#endif
	}else{
		sctp_update_acked(stcb,cp,netp);
	}
	assoc = &stcb->asoc;
	/* goto SHUTDOWN_RECEIVED state to block new requests */
	if((assoc->state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_RECEIVED){
		if ((assoc->state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_SENT) {
			assoc->state = SCTP_STATE_SHUTDOWN_RECEIVED;
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Moving to SHUTDOWN-RECEIVED state\n");
			}
#endif
		}

		/* notify upper layer that peer has initiated a shutdown */
		sctp_ulp_notify(SCTP_NOTIFY_PEER_SHUTDOWN, stcb, 0, NULL);

		/* reset time */
		SCTP_GETTIME_TIMEVAL(&assoc->time_entered);
	}
	/* Now are we there yet? */
	some_on_streamwheel = 0;
	if (!TAILQ_EMPTY(&assoc->out_wheel)) {
		/* Check to see if some data queued */
		struct sctp_stream_out *outs;
		TAILQ_FOREACH(outs,&assoc->out_wheel,next_spoke) {
			if (!TAILQ_EMPTY(&outs->outqueue)) {
				some_on_streamwheel = 1;
				break;
			}
		}
	}
	if (!TAILQ_EMPTY(&assoc->send_queue) ||
	    !TAILQ_EMPTY(&assoc->sent_queue) ||
	    some_on_streamwheel) {
		/* By returning we will push more data out */
		return;
	} else {
		/* no outstanding data to send, so move on... */
		/* send SHUTDOWN-ACK */
		sctp_send_shutdown_ack(stcb,stcb->asoc.primary_destination);
		/* move to SHUTDOWN-ACK-SENT state */
		assoc->state = SCTP_STATE_SHUTDOWN_ACK_SENT;
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("moving to SHUTDOWN_ACK state\n");
		}
#endif
		/* start SHUTDOWN timer */
		sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNACK, stcb->sctp_ep,
				 stcb, netp);
	}
}

static void
sctp_handle_shutdown_ack(struct sctp_shutdown_ack_chunk *cp,
			 struct sctp_tcb *stcb, struct sctp_nets *netp)
{
	struct sctp_association *assoc;
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_shutdown_ack: handling SHUTDOWN ACK\n");
	}
#endif
	if (stcb == NULL)
		return;

	assoc = &stcb->asoc;
	/* process according to association state */
	if (((assoc->state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_SENT) &&
	    ((assoc->state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_ACK_SENT)) {
		/* unexpected SHUTDOWN-ACK... so ignore... */
		return;
	}
	/* notify upper layer protocol */
	sctp_ulp_notify(SCTP_NOTIFY_ASSOC_DOWN, stcb, 0, NULL);
	/* are the queues empty? */
	if (!TAILQ_EMPTY(&assoc->send_queue) ||
	    !TAILQ_EMPTY(&assoc->sent_queue) ||
	    !TAILQ_EMPTY(&assoc->out_wheel)) {
		sctp_report_all_outbound(stcb);
	}
	/* stop the timer */
	sctp_timer_stop(SCTP_TIMER_TYPE_SHUTDOWN, stcb->sctp_ep, stcb, netp);
	/* send SHUTDOWN-COMPLETE */
	sctp_send_shutdown_complete(stcb,netp);
	/* free the TCB */
	sctp_free_assoc(stcb->sctp_ep, stcb);
	/* is the socket gone ? */
	if(stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
		/* Yes, so can we purge ourself now */
		if(LIST_FIRST(&stcb->sctp_ep->sctp_asoc_list) == NULL){
			/* finish the job now */
			sctp_inpcb_free(stcb->sctp_ep,1);
		}
	}
}

static void
sctp_process_unrecog_chunk(struct sctp_tcb *tcb,
			   struct sctp_paramhdr *phdr,
			   struct sctp_nets *netp)
{
	/*
	 * Skip past the param header and then we will find the chunk that
	 * caused the problem. There are two possiblities ASCONF or FWD-TSN
	 * other than that and our peer must be broken.
	 */
	struct sctp_chunkhdr *chk;

	chk = (struct sctp_chunkhdr *)((caddr_t)phdr + sizeof(*phdr));
	switch(chk->chunk_type){
	case SCTP_ASCONF_ACK:
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("Strange peer, snds ASCONF but does not recongnize asconf-ack?\n");
		}
#endif
	case SCTP_ASCONF:
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("Peer does not support ASCONF/ASCONF-ACK chunks\n");
		}
#endif /* SCTP_DEBUG */
		sctp_asconf_cleanup(tcb, netp);
		break;
	case SCTP_FORWARD_CUM_TSN:
		tcb->asoc.peer_supports_usctp = 0;
		break;
	default:
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("Peer does not support chunk type %d(%x)??\n",
			       chk->chunk_type,(u_int)chk->chunk_type);
		}
#endif
		break;
	}
}

void
sctp_process_unrecog_param(struct sctp_tcb *tcb,
			   struct sctp_paramhdr *phdr)
{
	/* Skip past the param header and then we will find the param that
	 * caused the problem.  There are a number of param's in a ASCONF
	 * OR the u-stream param these will turn of specific features.
	 */
	struct sctp_paramhdr *pbad;

	pbad = phdr + 1;
	switch(ntohs(pbad->param_type)){
		/* u-sctp draft */
	case SCTP_UNRELIABLE_STREAM:
		tcb->asoc.peer_supports_usctp = 0;
		break;
		/* draft-ietf-tsvwg-addip-sctp */
	case SCTP_ADD_IP_ADDRESS:
	case SCTP_DEL_IP_ADDRESS:
		tcb->asoc.peer_supports_asconf = 0;
		break;
	case SCTP_SET_PRIM_ADDR:
		tcb->asoc.peer_supports_asconf_setprim = 0;
		break;
	case SCTP_SUCCESS_REPORT:
	case SCTP_ERROR_CAUSE_IND:
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("Huh, the peer does not support success? or error cause?\n");
			printf("Turning off ASCONF to this strange peer\n");
		}
#endif
		tcb->asoc.peer_supports_asconf = 0;
		tcb->asoc.peer_supports_asconf_setprim = 0;
		break;
	default:
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("Peer does not support base param type %d(%x)??\n",
			       pbad->param_type,(u_int)pbad->param_type);
		}
#endif
		break;
	}
}


static void
sctp_handle_error(struct sctp_chunkhdr *ch,
		  struct sctp_tcb *tcb,
		  struct sctp_nets *net,
		  int chklen)
{
	struct sctp_paramhdr *phdr;
	u_short error_type;
	u_short error_len;
	struct sctp_association *asoc;

	int adjust;
	/* parse through all of the errors and process */
	asoc = &tcb->asoc;
	phdr = (struct sctp_paramhdr *)((caddr_t)ch + sizeof(struct sctp_chunkhdr));
	chklen -= sizeof(struct sctp_chunkhdr);
	while(chklen >= sizeof(struct sctp_paramhdr)){
		/* Process an Error Cause */
		error_type = ntohs(phdr->param_type);
		error_len = ntohs(phdr->param_length);
		switch(error_type){
		case SCTP_CAUSE_INV_STRM:
		case SCTP_CAUSE_MISS_PARAM:
		case SCTP_CAUSE_INVALID_PARAM:
		case SCTP_CAUSE_NOUSER_DATA:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Software error we got a %d back? We have a bug :/ (or do they?)\n",
				       error_type);
			}
#endif
			break;
		case SCTP_CAUSE_STALE_COOKIE:
			/* We only act if we have echoed a cookie and are waiting. */
			if((asoc->state&SCTP_STATE_MASK) == SCTP_STATE_COOKIE_ECHOED){
				int *p;
				p = (int *)((caddr_t)phdr + sizeof(*phdr));
				/* Save the time doubled */
				asoc->cookie_preserve_req = ntohl(*p) << 1;
				asoc->stale_cookie_count++;
				if(asoc->stale_cookie_count > asoc->max_init_times){
					sctp_abort_notification(tcb,0);
					/* now free the asoc */
					sctp_free_assoc(tcb->sctp_ep,tcb);
					return;
				}
				/* blast back to INIT state */
				asoc->state &= ~SCTP_STATE_COOKIE_ECHOED;
				asoc->state |= SCTP_STATE_COOKIE_WAIT;
				sctp_timer_stop(SCTP_TIMER_TYPE_COOKIE,tcb->sctp_ep,tcb,net);
				sctp_send_initiate(tcb->sctp_ep,tcb);
			}
			break;
		case SCTP_CAUSE_UNRESOLV_ADDR:
			/* Nothing we can do here, we don't do hostname addresses
			 * so if the peer does not like my IPv6 (or IPv4 for that
			 * matter) it does not matter. If they don't support that
			 * type of address, they can NOT possibly get that packet
			 * type... i.e. with no IPv6 you can't recieve a IPv6 packet.
			 * so we can safely ignore this one. If we ever added
			 * support for HOSTNAME Addresses, then we would need
			 * to do something here.
			 */
			break;
		case SCTP_CAUSE_UNRECOG_CHUNK:
			sctp_process_unrecog_chunk(tcb,phdr,net);
			break;
		case SCTP_CAUSE_UNRECOG_PARAM:
			sctp_process_unrecog_param(tcb,phdr);
			break;
		case SCTP_CAUSE_COOKIE_IN_SHUTDOWN:
			/* We ignore this since the timer will drive
			 * out a new cookie anyway and there timer
			 * will drive us to send a SHUTDOWN_COMPLETE. We
			 * can't send one here since we don't have their
			 * tag.
			 */
			break;
		case SCTP_CAUSE_DELETEING_LAST_ADDR:
		case SCTP_CAUSE_OPERATION_REFUSED:
		case SCTP_CAUSE_DELETING_SRC_ADDR:
			/* We should NOT get these here, but in a ASCONF-ACK. */
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT2){
				printf("Peer sends ASCONF errors in a Operational Error?<%d>?\n",
				       error_type);
			}
#endif
			break;
		case SCTP_CAUSE_OUT_OF_RESC:
			/* And what, pray tell do we do with the fact
			 * that the peer is out of resources? Not
			 * really sure we could do anything but abort.
			 * I suspect this should have came WITH an
			 * abort instead of in a OP-ERROR.
			 */
			break;
		default:
			break;
		}
		adjust = SCTP_SIZE32(error_len);
		chklen -= adjust;
		phdr = (struct sctp_paramhdr *)((caddr_t)phdr + adjust);
	}
}

static void
sctp_unpack_usctp_streams(struct sctp_tcb *stcb,
			  struct sctp_init_ack_chunk *initack_cp,
			  struct mbuf *m,
			  int offset)
{
	/* Ok we must examine the INIT-ACK to see what I sent in
	 * terms of the U-SCTP streams. This module is only called
	 * if the peer supports U-SCTP.
	 */
	struct sctp_paramhdr *phdr,phold;
	int len,augment,at;
	int my_len;


	phdr = (struct sctp_paramhdr *)((caddr_t)initack_cp + sizeof(struct sctp_init_chunk));
	len = ntohs(initack_cp->ch.chunk_length) - sizeof(struct sctp_init_chunk);
	at = sizeof(struct sctp_init_chunk);

	while(len){
		phdr = sctp_get_next_param(m,(offset+at),&phold,sizeof(struct sctp_paramhdr));
		if(phdr == NULL){
			break;
		}
		if(ntohs(phdr->param_type) == SCTP_UNRELIABLE_STREAM){
			/* Found a u-sctp parameter, process it */
			my_len = ntohs(phdr->param_length);
			if(my_len != sizeof(struct sctp_paramhdr)){
				goto next_param;
			}
			stcb->asoc.peer_supports_usctp = 1;
		}
	next_param:
		augment = SCTP_SIZE32(ntohs(phdr->param_length));
		at += augment;
		len -= augment;
		if(len <= 0){
			break;
		}
	}
}



static int
sctp_handle_init_ack(struct mbuf *m, struct sctp_init_ack_chunk *cp,
		     struct sctp_tcb *stcb, struct sctp_nets *netp,
		     int offset, int iphlen)
{
	struct sctp_init_ack *init_ack;
	int *state;
	struct mbuf *op_err;

#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_init_ack: handling INIT-ACK\n");
	}
#endif
	if (stcb == NULL) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_init_ack: TCB is null\n");
		}
#endif
		return(-1);
	}
	if(ntohs(cp->ch.chunk_length) < sizeof(struct sctp_init_ack_chunk)){
		/* Invalid length */
		op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(stcb->sctp_ep, stcb, m, iphlen, op_err);
		return(-1);
	}
	init_ack = &cp->init;
	/* validate parameters */
	if (init_ack->initiate_tag == 0) {
		/* protocol error... send an abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(stcb->sctp_ep, stcb, m, iphlen,op_err);
		return(-1);
	}
	if (ntohl(init_ack->a_rwnd) < SCTP_MIN_RWND) {
		/* protocol error... send an abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(stcb->sctp_ep, stcb, m, iphlen,op_err);
		return(-1);
	}
	if (init_ack->num_inbound_streams == 0) {
		/* protocol error... send an abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(stcb->sctp_ep, stcb, m, iphlen,op_err);
		return(-1);
	}
	if (init_ack->num_outbound_streams == 0) {
		/* protocol error... send an abort */
	        op_err = sctp_generate_invmanparam(SCTP_CAUSE_INVALID_PARAM);
		sctp_abort_association(stcb->sctp_ep, stcb, m, iphlen,op_err);
		return(-1);
	}

	/* process according to association state... */
	state = &stcb->asoc.state;
	switch (*state & SCTP_STATE_MASK) {
	case SCTP_STATE_COOKIE_WAIT:
		/* this is the expected state for this chunk */
		/* process the INIT-ACK parameters */
		if (sctp_process_init_ack(m, offset, cp, stcb, netp, iphlen) < 0) {
			/* error in parsing parameters */
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT2){
				printf("sctp_process_init_ack: error in msg, discarding\n");
			}
#endif
			return(-1);
		}
		/* update our state */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("moving to COOKIE-ECHOED state\n");
		}
#endif
		if (*state & SCTP_STATE_SHUTDOWN_PENDING) {
			*state = SCTP_STATE_COOKIE_ECHOED | SCTP_STATE_SHUTDOWN_PENDING;
		} else {
			*state = SCTP_STATE_COOKIE_ECHOED;
		}

		/* reset the RTO calc */
		stcb->asoc.overall_error_count = 0;
		SCTP_GETTIME_TIMEVAL(&stcb->asoc.time_entered);
		if (stcb->asoc.peer_supports_usctp) {
			sctp_unpack_usctp_streams(stcb,cp,m,offset);
		}

		/* collapse the init timer back in case of a exponential backoff */
		sctp_timer_start(SCTP_TIMER_TYPE_COOKIE, stcb->sctp_ep,
				 stcb, netp);
		/*
		 * the send at the end of the inbound data processing will
		 * cause the cookie to be sent
		 */
		break;
	case SCTP_STATE_SHUTDOWN_SENT:
		/* incorrect state... discard */
		break;
	case SCTP_STATE_COOKIE_ECHOED:
		/* incorrect state... discard */
		break;
	case SCTP_STATE_OPEN:
		/* incorrect state... discard */
		break;
	case SCTP_STATE_EMPTY:
	case SCTP_STATE_INUSE:
	default:
		/* incorrect state... discard */
		return(-1);
		break;
	} /* end switch assoc state */
	return(0);
}


/*
 * handle a state cookie for an existing association
 * m: input packet mbuf chain-- assumes a pullup on IP/SCTP/COOKIE-ECHO chunk
 *    note: this is a "split" mbuf and the cookie signature does not exist
 * offset: offset into mbuf to the cookie-echo chunk
 */
static struct sctp_tcb *
sctp_process_cookie_existing(struct mbuf *m, int offset, int iphlen,
			     struct sctp_inpcb *inp, struct sctp_tcb *stcb,
			     struct sctp_nets *netp,
			     struct sctp_state_cookie *cookie, int length,
			     int *notification,
			     struct sockaddr *to)
{
	struct sctp_association *assoc;
	struct sctp_init_chunk *init_cp, tmp_init;
	struct sctp_init_ack_chunk *initack_cp, tmp_initack;
	int sz_of_init;
	int init_offset;
	int retval;

	/* I know that the TCB is non-NULL from the caller */
	assoc = &stcb->asoc;


	if ((assoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_ACK_SENT) {
		/* SHUTDOWN came in after sending INIT-ACK */
		struct mbuf *op_err;
		struct sctp_cookie_while_shutting_down *scm;

		sctp_send_shutdown_ack(stcb,stcb->asoc.primary_destination);
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: got a cookie, while shutting down!\n");
		}
#endif
		MGETHDR(op_err,M_DONTWAIT, MT_HEADER);
		if(op_err == NULL)
			/* FOOBAR */
			return(NULL);
		/* pre-reserve some space */
		op_err->m_data += sizeof(struct ip6_hdr);
		/* Set the len */
		op_err->m_len = op_err->m_pkthdr.len = sizeof(struct sctp_cookie_while_shutting_down);
		scm = mtod(op_err,struct sctp_cookie_while_shutting_down *);
		scm->ch.chunk_type = SCTP_OPERATION_ERROR;
		scm->ch.chunk_flags = 0;
		scm->ch.chunk_length = htons((op_err->m_len-sizeof(struct sctphdr)));
		scm->ph.param_type = htons(SCTP_CAUSE_COOKIE_IN_SHUTDOWN);
		scm->ph.param_length = htons(sizeof(struct sctp_paramhdr));
		sctp_send_operr_to(m,iphlen,op_err,&scm->sh,cookie->peers_vtag);
		return(NULL);
	}
	/*
	 * find and validate the INIT chunk in the cookie (peer's info)
	 * the INIT should start after the cookie-echo header struct
	 * (chunk header, state cookie header struct)
	 */
	offset += sizeof(struct sctp_cookie_echo_chunk);
	init_offset = offset;

	init_cp = (struct sctp_init_chunk *)
		sctp_m_getptr(m, offset, sizeof(struct sctp_init_chunk),
			      (u_int8_t *)&tmp_init);
	if (init_cp == NULL) {
		/* could not pull a INIT chunk in cookie */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("process_cookie_existing: could not pull INIT chunk hdr\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	if (init_cp->ch.chunk_type != SCTP_INITIATION) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("process_cookie_existing: could not find INIT chunk!\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	sz_of_init = (unsigned int)(ntohs(init_cp->ch.chunk_length) + init_offset);

	/*
	 * find and validate the INIT-ACK chunk in the cookie (my info)
	 * the INIT-ACK follows the INIT chunk
	 */
	offset += ntohs(init_cp->ch.chunk_length);
	initack_cp = (struct sctp_init_ack_chunk *)
		sctp_m_getptr(m, offset, sizeof(struct sctp_init_ack_chunk),
			      (u_int8_t *)&tmp_initack);
	if (initack_cp == NULL) {
		/* could not pull INIT-ACK chunk in cookie */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("process_cookie_existing: could not pull INIT-ACK chunk hdr\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	if (initack_cp->ch.chunk_type != SCTP_INITIATION_ACK) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("process_cookie_existing: could not find INIT-ACK chunk!\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	if ((ntohl(initack_cp->init.initiate_tag) == assoc->my_vtag) &&
	    (ntohl(init_cp->init.initiate_tag) == assoc->peer_vtag)) {
		/*
		 * case D in Section 5.2.4 Table 2: MMAA
		 * process accordingly to get into the OPEN state
		 */
		switch (assoc->state & SCTP_STATE_MASK) {
		case SCTP_STATE_COOKIE_WAIT:
			/*
			 * INIT was sent, but got got a COOKIE_ECHO with
			 * the correct tags... just accept it...
			 */
			/* First we must process the INIT !! */
			retval = sctp_process_init(init_cp, stcb, netp);
			if (retval < 0) {
#ifdef SCTP_DEBUG
				printf("process_cookie_existing: INIT processing failed\n");
#endif
				return(NULL);
			}
			/* intentional fall through to below... */

		case SCTP_STATE_COOKIE_ECHOED:
			/* Duplicate INIT case */
			/* Here we have already processed the INIT so no problem */
			sctp_timer_stop(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, netp);
			sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, netp);
			sctp_timer_stop(SCTP_TIMER_TYPE_INIT, inp, stcb, netp);
			sctp_timer_stop(SCTP_TIMER_TYPE_COOKIE, inp, stcb, netp);
			/* update current state */
			if (assoc->state & SCTP_STATE_SHUTDOWN_PENDING) {
				assoc->state = SCTP_STATE_OPEN | SCTP_STATE_SHUTDOWN_PENDING;
			} else {
				assoc->state = SCTP_STATE_OPEN;
			}
			/* notify upper layer */
			*notification = SCTP_NOTIFY_ASSOC_UP;
			/* start the path MTU raise and heartbeat timers */
			sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, netp);
			sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, netp);
			if(stcb->asoc.sctp_autoclose_ticks &&
			   (inp->sctp_flags & SCTP_PCB_FLAGS_AUTOCLOSE)){
				sctp_timer_start(SCTP_TIMER_TYPE_AUTOCLOSE, inp, stcb, NULL);
			}
			break;
		default:
			/*
			 * we're in the OPEN state (or beyond), so peer
			 * must have simply lost the COOKIE-ACK
			 */
			break;
		} /* end switch */

		/* We ignore the return code here.. not sure if we should
		 * somehow abort.. but we do have an existing asoc. This
		 * really should not fail.
		 */
		if(sctp_load_addresses_from_init(stcb, m, iphlen,
						 (init_offset + sizeof(struct sctp_init_chunk)),
						 to,sz_of_init)){
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Weird cookie load_address failure on cookie existing - 1\n");
			}
#endif
			;
		}

		/* now do we enable u-sctp? */
		if (stcb->asoc.peer_supports_usctp) {
			/* Yes, we must set all the streams that we told him
			 * about in the INIT-ACK.
			 */
			sctp_unpack_usctp_streams(stcb, initack_cp,m,offset);
		}
		/* respond with a COOKIE-ACK */
		sctp_send_cookie_ack(stcb);
		return(stcb);
	} /* end if */
	if ((ntohl(initack_cp->init.initiate_tag) != assoc->my_vtag) &&
	    (ntohl(init_cp->init.initiate_tag) == assoc->peer_vtag) &&
	    (cookie->tie_tag_my_vtag == 0) &&
	    (cookie->tie_tag_peer_vtag == 0)) {
		/*
		 * case C in Section 5.2.4 Table 2: XMOO
		 * silently discard
		 */
		return(NULL);

	}
	if ((ntohl(initack_cp->init.initiate_tag) == assoc->my_vtag) &&
	    ((ntohl(init_cp->init.initiate_tag) != assoc->peer_vtag) ||
	     (init_cp->init.initiate_tag == 0))) {
		/*
		 * case B in Section 5.2.4 Table 2: MXAA or MOAA
		 * my info should be ok, re-accept peer info
		 */
	        sctp_timer_stop(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, netp);
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, netp);
		sctp_timer_stop(SCTP_TIMER_TYPE_INIT, inp, stcb, netp);
		sctp_timer_stop(SCTP_TIMER_TYPE_COOKIE, inp, stcb, netp);
		/* start the path MTU raise and heartbeat timers */
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, netp);
		sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, netp);
		if(stcb->asoc.sctp_autoclose_ticks &&
		   (inp->sctp_flags & SCTP_PCB_FLAGS_AUTOCLOSE)){
			sctp_timer_start(SCTP_TIMER_TYPE_AUTOCLOSE, inp, stcb, NULL);
		}
		assoc->my_rwnd = ntohl(initack_cp->init.a_rwnd);
		assoc->pre_open_streams = ntohs(initack_cp->init.num_outbound_streams);
		assoc->init_seq_number = ntohl(initack_cp->init.initial_tsn);
		assoc->sending_seq = assoc->asconf_seq_out = assoc->init_seq_number;
		assoc->t3timeout_highest_marked = assoc->asconf_seq_out;
		assoc->last_cwr_tsn = assoc->init_seq_number - 1;
		assoc->asconf_seq_in = assoc->last_acked_seq =
			assoc->init_seq_number - 1;
		assoc->advanced_peer_ack_point = assoc->last_acked_seq;

		/* process the INIT info (peer's info) */
		retval = sctp_process_init(init_cp, stcb, netp);
		if (retval < 0) {
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("process_cookie_existing: INIT processing failed\n");
			}
#endif
			return(NULL);
		}
		if(sctp_load_addresses_from_init(stcb,
						 m, iphlen,
						 (init_offset + sizeof(struct sctp_init_chunk)),
						 to,sz_of_init)){
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Weird cookie load_address failure on cookie existing - 2\n");
			}
#endif
			;
		}

		/* now do we enable u-sctp? */
		if (stcb->asoc.peer_supports_usctp) {
			/* Yes, we must set all the streams that we told him
			 * about in the INIT-ACK.
			 */
			sctp_unpack_usctp_streams(stcb, initack_cp,m, offset);
		}
		if((assoc->state & SCTP_STATE_COOKIE_WAIT) ||
		   (assoc->state & SCTP_STATE_COOKIE_ECHOED)){
			*notification = SCTP_NOTIFY_ASSOC_UP;
		}
		if (assoc->state & SCTP_STATE_SHUTDOWN_PENDING) {
			assoc->state = SCTP_STATE_OPEN | SCTP_STATE_SHUTDOWN_PENDING;
		} else {
			assoc->state = SCTP_STATE_OPEN;
		}
		sctp_send_cookie_ack(stcb);
		return(stcb);
	}

	if (((ntohl(initack_cp->init.initiate_tag) != assoc->my_vtag) &&
	     (ntohl(init_cp->init.initiate_tag) != assoc->peer_vtag)) &&
	    (cookie->tie_tag_my_vtag == assoc->my_vtag) &&
	    (cookie->tie_tag_peer_vtag == assoc->peer_vtag) &&
	    (cookie->tie_tag_peer_vtag != 0)) {
		/*
		 * case A in Section 5.2.4 Table 2: XXMM (peer restarted)
		 */
		sctp_timer_stop(SCTP_TIMER_TYPE_INIT, inp, stcb, netp);
		sctp_timer_stop(SCTP_TIMER_TYPE_COOKIE, inp, stcb, netp);
		sctp_timer_stop(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, netp);
		sctp_timer_stop(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, netp);

		/* notify upper layer */
		*notification = SCTP_NOTIFY_ASSOC_RESTART;

		/* send up all the data */
		sctp_report_all_outbound(stcb);

		/* process the INIT-ACK info (my info) */
		assoc->my_vtag = ntohl(initack_cp->init.initiate_tag);
		assoc->my_rwnd = ntohl(initack_cp->init.a_rwnd);
		assoc->pre_open_streams = ntohs(initack_cp->init.num_outbound_streams);
		assoc->init_seq_number = ntohl(initack_cp->init.initial_tsn);
		assoc->sending_seq = assoc->asconf_seq_out = assoc->init_seq_number;
		assoc->t3timeout_highest_marked = assoc->asconf_seq_out;
		assoc->last_cwr_tsn = assoc->init_seq_number - 1;
		assoc->asconf_seq_in = assoc->last_acked_seq =
			assoc->init_seq_number - 1;
		assoc->advanced_peer_ack_point = assoc->last_acked_seq;

		/* process the INIT info (peer's info) */
		retval = sctp_process_init(init_cp, stcb, netp);
		if (retval < 0) {
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("process_cookie_existing: INIT processing failed\n");
			}
#endif
			return(NULL);
		}

		/* start the path MTU raise and heartbeat timers */
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, netp);
		sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, netp);

		if(sctp_load_addresses_from_init(stcb,
						 m, iphlen,
						 (init_offset + sizeof(struct sctp_init_chunk)),
						 to,sz_of_init)){
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Weird cookie load_address failure on cookie existing - 3\n");
			}
#endif
			;
		}

		/* now do we enable u-sctp? */
		if (stcb->asoc.peer_supports_usctp) {
			/* Yes, we must set all the streams that we told him
			 * about in the INIT-ACK.
			 */
			sctp_unpack_usctp_streams(stcb, initack_cp,m, offset);
		}
		if (assoc->state & SCTP_STATE_SHUTDOWN_PENDING) {
			assoc->state = SCTP_STATE_OPEN | SCTP_STATE_SHUTDOWN_PENDING;
		} else {
			assoc->state = SCTP_STATE_OPEN;
		}
		/* respond with a COOKIE-ACK */
		sctp_send_cookie_ack(stcb);

		return(stcb);
	}
	/* all other cases... */
	return(NULL);
}

/*
 * handle a state cookie for a new association
 * m: input packet mbuf chain-- assumes a pullup on IP/SCTP/COOKIE-ECHO chunk
 *    note: this is a "split" mbuf and the cookie signature does not exist
 * offset: offset into mbuf to the cookie-echo chunk
 * length: length of the cookie chunk
 * to: where the init was from
 * returns a new TCB
 */

static struct sctp_tcb *
sctp_process_cookie_new(struct mbuf *m, int offset, int iphlen,
			struct sctp_inpcb *inp, struct sctp_nets **netp,
			struct sctp_state_cookie *cookie, int length,
			struct sockaddr *to,
			struct sockaddr *dest,
			int *notification)
{
	struct sctp_tcb *stcb;
	struct sctp_init_chunk *init_cp, tmp_init;
	struct sctp_init_ack_chunk *initack_cp, tmp_initack;
	struct sockaddr *ep_addr;
	struct sockaddr_storage sa_store;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ip *iph;
	struct sctphdr *sh;
	struct sctp_association *assoc;
	int init_offset;
	int initack_offset;
	int retval;
	int addrlen;
	int sz_of_init,xxx;
	/*
	 * find and validate the INIT chunk in the cookie (peer's info)
	 * the INIT should start after the cookie-echo header struct
	 * (chunk header, state cookie header struct)
	 */
	init_offset = offset + sizeof(struct sctp_cookie_echo_chunk);
	init_cp = (struct sctp_init_chunk *)
		sctp_m_getptr(m, init_offset, sizeof(struct sctp_init_chunk),
			      (u_int8_t *)&tmp_init);
	if (init_cp == NULL) {
		/* could not pull a INIT chunk in cookie */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("process_cookie_new: could not pull INIT chunk hdr\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	if (init_cp->ch.chunk_type != SCTP_INITIATION) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("HUH? process_cookie_new: could not find INIT chunk!\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	xxx = ntohs(init_cp->ch.chunk_length);
	sz_of_init = (unsigned int)(xxx + init_offset);
	initack_offset = init_offset + xxx;
	/*
	 * find and validate the INIT-ACK chunk in the cookie (my info)
	 * the INIT-ACK follows the INIT chunk
	 */
	initack_cp = (struct sctp_init_ack_chunk *)
		sctp_m_getptr(m, initack_offset,
			      sizeof(struct sctp_init_ack_chunk),
			      (u_int8_t *)&tmp_initack);
	if (initack_cp == NULL) {
		/* could not pull INIT-ACK chunk in cookie */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("process_cookie_new: could not pull INIT-ACK chunk hdr\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	if (initack_cp->ch.chunk_type != SCTP_INITIATION_ACK) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			u_int8_t *pp;
			pp = (u_int8_t *)initack_cp;
			printf("process_cookie_new: could not find INIT-ACK chunk!\n");
			printf("Found bytes %x %x %x %x at postion %d\n",
			       (u_int)pp[0],
			       (u_int)pp[1],
			       (u_int)pp[2],
			       (u_int)pp[3],
			       initack_offset);
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	/* get endpoint source ("from") address and port */
	memset((caddr_t)&sa_store, 0, sizeof(sa_store));
	sin = (struct sockaddr_in *)&sa_store;
	sin6 = (struct sockaddr_in6 *)&sa_store;
	ep_addr = (struct sockaddr *)&sa_store;
	iph = mtod(m, struct ip *);
	/* This will work no matter which IP we have
	 * V6 or V4
	 */
	sh = (struct sctphdr *)((caddr_t)iph + iphlen);
	if(to->sa_family == AF_INET){
		/* source addr is IPv4 */
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);
		sin->sin_addr = ((struct sockaddr_in *)to)->sin_addr;
		sin->sin_port = sh->src_port;
	} else {
		/* source addr is IPv6 */
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		sin6->sin6_addr = ((struct sockaddr_in6 *)to)->sin6_addr;
		sin6->sin6_port = sh->src_port;
		sin6->sin6_scope_id = cookie->scope_id;
	}
	/*
	 * now that we know the INIT/INIT-ACK are in place,
	 * create a new TCB and popluate
	 */
	stcb = sctp_aloc_assoc(inp, ep_addr, 0);
	if (stcb == NULL) {
		struct mbuf *op_err;
		/* memory problem? */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("process_cookie_new: no room for another TCB!\n");
		}
#endif /* SCTP_DEBUG */
		op_err = sctp_generate_invmanparam(SCTP_CAUSE_OUT_OF_RESC);
		sctp_abort_association(inp, (struct sctp_tcb *)NULL, m, iphlen,op_err);
		return(NULL);
	}
	/* get the correct sctp_nets */
	*netp = sctp_findnet(stcb, ep_addr);
	assoc = &stcb->asoc;
	/* get scope variables out of cookie */
	assoc->ipv4_local_scope = cookie->ipv4_scope;
	assoc->site_scope = cookie->site_scope;
	assoc->local_scope = cookie->local_scope;
	assoc->loopback_scope = cookie->loopback_scope;


	if((assoc->ipv4_addr_legal != cookie->ipv4_addr_legal) ||
	   (assoc->ipv6_addr_legal != cookie->ipv6_addr_legal)){
		struct mbuf *op_err;
		/* Houstin we have a problem. The EP changed while
		 * the cookie was in flight. Only recourse is
		 * to abort the association.
		 */
		op_err = sctp_generate_invmanparam(SCTP_CAUSE_OUT_OF_RESC);
		sctp_abort_association(inp, (struct sctp_tcb *)NULL, m, iphlen,op_err);
		return(NULL);
	}

	/* process the INIT-ACK info (my info) */
	assoc->my_vtag = ntohl(initack_cp->init.initiate_tag);
	assoc->my_rwnd = ntohl(initack_cp->init.a_rwnd);
	assoc->pre_open_streams = ntohs(initack_cp->init.num_outbound_streams);
	assoc->init_seq_number = ntohl(initack_cp->init.initial_tsn);
	assoc->sending_seq = assoc->asconf_seq_out = assoc->init_seq_number;
	assoc->t3timeout_highest_marked = assoc->asconf_seq_out;
	assoc->last_cwr_tsn = assoc->init_seq_number - 1;
	assoc->asconf_seq_in = assoc->last_acked_seq =
		assoc->init_seq_number - 1;
	assoc->advanced_peer_ack_point = assoc->last_acked_seq;
	/* process the INIT info (peer's info) */
	retval = sctp_process_init(init_cp, stcb, *netp);
	if (retval < 0) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("process_cookie_new: INIT processing failed\n");
		}
#endif
		sctp_free_assoc(inp, stcb);
		return(NULL);
	}
	/* load all addresses */
	if(sctp_load_addresses_from_init(stcb, m, iphlen,
					 init_offset + sizeof(struct sctp_init_chunk),to,
					 sz_of_init)){
		sctp_free_assoc(inp, stcb);
		return(NULL);
	}
	/* now do we enable u-sctp? */
	if (stcb->asoc.peer_supports_usctp) {
		/* Yes, we must set all the streams that we told him
		 * about in the INIT-ACK.
		 */
		sctp_unpack_usctp_streams(stcb, initack_cp,m,initack_offset);
	}

	if (to) {
		/*
		 * Use the to address to verify the address the INIT was
		 * sent from is added
		 */
		struct sctp_tcb *t_tcb;
		struct sctp_inpcb *ep;
		ep = stcb->sctp_ep;
		t_tcb = sctp_findassociation_ep_addr(&ep,to,NULL,dest);
		if(ep != stcb->sctp_ep){
			/* We have a problem. This should NOT happen */
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Endpoint did NOT match? TSNH\n");
			}
#endif
			sctp_free_assoc(inp, stcb);
			return(NULL);
		}
		if (t_tcb == NULL) {
			/* we must add the source address */
			/* no scope set here since we have a tcb already. */
			sctp_add_remote_addr(stcb,to,0);
		}
	}
	/* update current state */
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT1){
		printf("moving to OPEN state\n");
	}
#endif
	if (assoc->state & SCTP_STATE_SHUTDOWN_PENDING) {
		assoc->state = SCTP_STATE_OPEN | SCTP_STATE_SHUTDOWN_PENDING;
	} else {
		assoc->state = SCTP_STATE_OPEN;
	}
	/* calculate the RTT */
	(*netp)->RTO = sctp_calculate_rto(stcb, assoc, *netp, &cookie->time_entered);
	/*
	 * add our local addresses which I sent in the INIT-ACK
	 * if we're doing ASCONFs, check to see if we have any new
	 * local addresses that need to get added to the peer
	 * (eg. addresses changed while cookie echo in flight)
	 * this needs to be done after we go to the OPEN state to
	 * do the correct asconf processing.
	 * else, make sure we have the correct addresses in our lists
	 */
	addrlen = offset + length -
		(initack_offset + sizeof(struct sctp_init_ack_chunk));
	offset = initack_offset + sizeof(struct sctp_init_ack_chunk);
	sctp_check_address_list(stcb, m, offset, addrlen,
				cookie->local_scope,
				cookie->site_scope,
				cookie->ipv4_scope,
				cookie->loopback_scope);

	/* set up to notify upper layer */
	*notification = SCTP_NOTIFY_ASSOC_UP;
	/* start the path MTU raise and heartbeat timers */
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, inp, stcb, *netp);
	sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, inp, stcb, *netp);
	if (stcb->asoc.sctp_autoclose_ticks &&
	    (inp->sctp_flags & SCTP_PCB_FLAGS_AUTOCLOSE)) {
		sctp_timer_start(SCTP_TIMER_TYPE_AUTOCLOSE, inp, stcb, NULL);
	}

	/* respond with a COOKIE-ACK */
	sctp_send_cookie_ack(stcb);

	return(stcb);
}


/*
 * handles a COOKIE-ECHO message
 * stcb: modified to either a new or left as existing (non-NULL) TCB
 */
static struct mbuf *
sctp_handle_cookie_echo(struct mbuf *m, int offset, int iphlen,
			struct sctp_inpcb **inp, struct sctp_tcb **stcb,
			struct sctp_nets **netp,
			struct sctphdr *sctphdr)
{
	struct sctp_cookie_echo_chunk *cookie_cp, tmp_cookie_cp;
	struct sctp_state_cookie *cookie;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	struct sockaddr *to;
	struct sctp_pcb *ep;
	struct mbuf *m_sig;
	u_int8_t calc_sig[SCTP_SIGNATURE_SIZE], tmp_sig[SCTP_SIGNATURE_SIZE];
	u_int8_t *sig;
	u_int8_t cookie_ok = 0;
	int size_of_pkt, sig_offset, cookie_offset;
	int cookie_len;
	struct timeval now;
	u_int32_t time_expires;
	struct sockaddr_storage dest_store;
	struct sockaddr *localep_sa = (struct sockaddr *)&dest_store;
	struct ip *iph;
	int notification=0;

#ifdef SCTP_TCP_MODEL_SUPPORT
	int had_a_existing_tcb=0;
#endif
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_cookie: handling COOKIE-ECHO\n");
	}
#endif

	if (inp == NULL) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("sctp_handle_cookie: null inpcb!\n");
		}
#endif
		return(NULL);
	}
	/* First get the destination address setup too. */
	iph = mtod(m,struct ip *);
	if(iph->ip_v == IPVERSION){
		/* its IPv4 */
		struct sockaddr_in *sin;
		sin = (struct sockaddr_in *)(localep_sa);
		memset(sin,0,sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_port = sctphdr->dest_port;
		sin->sin_addr.s_addr = iph->ip_dst.s_addr ;
	}else{
		/* its IPv6 */
		struct ip6_hdr *ip6;
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)(localep_sa);
		memset(sin6,0,sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		ip6 = mtod(m, struct ip6_hdr *);
		sin6->sin6_port = sctphdr->dest_port;
		sin6->sin6_addr = ip6->ip6_dst;
	}
	/* get pointer to COOKIE-ECHO chunk + state_cookie parameter */
	cookie_cp = (struct sctp_cookie_echo_chunk *)
		sctp_m_getptr(m, offset, sizeof(struct sctp_cookie_echo_chunk), (u_int8_t *)&tmp_cookie_cp);
	if (cookie_cp == NULL) {
		/* could not pull a COOKIE ECHO chunk 'header'... */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("sctp_handle_cookie: could not pull COOKIE-ECHO chunk\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	cookie = &cookie_cp->cookie;
	cookie_offset = offset + sizeof(struct sctp_chunkhdr);
	cookie_len = ntohs(cookie_cp->ch.chunk_length);

	/* compute size of packet */
	if (m->m_flags & M_PKTHDR) {
		size_of_pkt = m->m_pkthdr.len;
	} else {
		/* Should have a pkt hdr really */
		struct mbuf *mat;
		mat = m;
		size_of_pkt = 0;
		while (mat != NULL) {
			size_of_pkt += mat->m_len;
			mat = mat->m_next;
		}
	}
	if ((cookie_len > size_of_pkt) ||
	    (cookie_len < (sizeof(struct sctp_cookie_echo_chunk) +
			   sizeof(struct sctp_init_chunk) +
			   sizeof(struct sctp_init_ack_chunk) +
			   SCTP_SIGNATURE_SIZE
		    )
		    )){
		/* cookie too long!  or too small */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: cookie_len=%u, pkt size=%u\n", cookie_len, size_of_pkt);
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
	/*
	 * split off the signature into its own mbuf (since it
	 * should not be calculated in the sctp_hash_digest_m() call).
	 */
	sig_offset = offset + cookie_len - SCTP_SIGNATURE_SIZE;
	if (sig_offset > size_of_pkt) {
		/* packet not correct size! */
		/* XXX this may already be accounted for earlier... */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: sig offset=%u, pkt size=%u\n", sig_offset, size_of_pkt);
		}
#endif
		return(NULL);
	}
	m_sig = m_split(m, sig_offset, M_DONTWAIT);
	if (m_sig == NULL) {
		/* out of memory or ?? */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("sctp_handle_cookie: couldn't m_split the signature\n");
		}
#endif
		return(NULL);
	}
	/*
	 * compute the signature/digest for the cookie
	 */
	ep = &(*inp)->sctp_ep;
	/* which cookie is it? */
	if ((cookie->time_entered.tv_sec < ep->time_of_secret_change) &&
	    (ep->current_secret_number != ep->last_secret_number)) {
		/* it's the old cookie */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: old cookie sig\n");
		}
#endif
		sctp_hash_digest_m((char *)ep->secret_key[(int)ep->last_secret_number],
				   SCTP_SECRET_SIZE, m,
				   cookie_offset, calc_sig);
	}else{
		/* it's the current cookie */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: current cookie sig\n");
		}
#endif
		sctp_hash_digest_m((char *)ep->secret_key[(int)ep->current_secret_number],
				   SCTP_SECRET_SIZE, m,
				   cookie_offset, calc_sig);
	}
	/* get the signature */
	sig = (u_int8_t *)sctp_m_getptr(m_sig, 0, SCTP_SIGNATURE_SIZE, (u_int8_t *)&tmp_sig);
	if (sig == NULL) {
		/* couldn't find signature */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("sctp_handle_cookie: couldn't pull the signature\n");
		}
#endif
		return(NULL);
	}
	/*
	 * Now before we continue we must reconstruct our mbuf so
	 * that normal processing of any other chunks will work.
	 */
	{
		struct mbuf *m_at;
		m_at = m;
		while (m_at->m_next != NULL) {
			m_at = m_at->m_next;
		}
		m_at->m_next = m_sig;
		if (m_sig->m_flags & M_PKTHDR) {
			/* Add back to the pkt hdr of main m chain */
			m->m_pkthdr.len += m_sig->m_pkthdr.len;
		}
	}
	/* compare the received digest with the computed digest */
	if (memcmp(calc_sig, sig, SCTP_SIGNATURE_SIZE) != 0) {
		/* try the old cookie? */
		if ((cookie->time_entered.tv_sec == ep->time_of_secret_change) &&
		    (ep->current_secret_number != ep->last_secret_number)) {
			/* compute digest with old */
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT2){
				printf("sctp_handle_cookie: old cookie sig\n");
			}
#endif
			sctp_hash_digest_m((char *)ep->secret_key[(int)ep->last_secret_number],
					   SCTP_SECRET_SIZE, m,
					   cookie_offset, calc_sig);
			/* compare */
			if (memcmp(calc_sig, sig, SCTP_SIGNATURE_SIZE) == 0)
				cookie_ok = 1;
		}
	} else {
		cookie_ok = 1;
	}

	if (cookie_ok == 0) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("handle_cookie_echo: cookie signature validation failed!\n");
			printf("offset = %u, cookie_offset = %u, sig_offset = %u\n",
			       (u_int32_t)offset, cookie_offset, sig_offset);
		}
#endif
		return(NULL);
	}
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("handle_cookie_echo: cookie signature validation passed\n");
	}
#endif

	/*
	 * check the cookie timestamps to be sure it's not stale
	 */
	SCTP_GETTIME_TIMEVAL(&now);
	/* Expire time is in Ticks, so we convert to seconds */
	time_expires = cookie->time_entered.tv_sec + cookie->cookie_life;
	if ((now.tv_sec > time_expires) ||
	    ((now.tv_sec == time_expires) &&
	     (now.tv_usec > cookie->time_entered.tv_usec))) {
		/* cookie is stale! */
		struct mbuf *op_err;
		struct sctp_stale_cookie_msg *scm;
		u_int32_t tim;
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT3){
			printf("sctp_handle_cookie: got a STALE cookie!\n");
		}
#endif
		MGETHDR(op_err,M_DONTWAIT, MT_HEADER);
		if (op_err == NULL)
			/* FOOBAR */
			return(NULL);
		/* pre-reserve some space */
		op_err->m_data += sizeof(struct ip6_hdr);
		/* Set the len */
		op_err->m_len = op_err->m_pkthdr.len = sizeof(struct sctp_stale_cookie_msg);
		scm = mtod(op_err,struct sctp_stale_cookie_msg *);
		scm->ch.chunk_type = SCTP_OPERATION_ERROR;
		scm->ch.chunk_flags = 0;
		scm->ch.chunk_length = htons((op_err->m_len-sizeof(struct sctphdr)));
		scm->ph.param_type = htons(SCTP_CAUSE_STALE_COOKIE);
		scm->ph.param_length = htons((sizeof(struct sctp_paramhdr) +
					      (sizeof(u_int32_t))));
		/* seconds to usec */
		tim = (now.tv_sec - time_expires) * 1000000;
		/* add in usec */
		if (tim == 0)
			tim = now.tv_usec - cookie->time_entered.tv_usec;
		scm->time_usec = htonl(tim);
		sctp_send_operr_to(m, iphlen, op_err, &scm->sh,
				   cookie->peers_vtag);
		return(NULL);
	}
	/*
	 * Now we must see with the lookup address if we have an existing
	 * asoc. This will only happen if we were in the COOKIE-WAIT state
	 * and a INIT collided with us and somewhere the peer sent the
	 * cookie on another address besides the single address our assoc
	 * had for him. In this case we will have one of the tie-tags set
	 * at least AND the address field in the cookie can be used to
	 * look it up.
	 */
	to = NULL;
	if (cookie->addr_type == SCTP_IPV6_ADDRESS) {
		memset(&sin6,0,sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_port = sctphdr->src_port;
		sin6.sin6_scope_id = cookie->scope_id;
		memcpy(&sin6.sin6_addr.s6_addr,
		       cookie->address,
		       sizeof(sin6.sin6_addr.s6_addr));
		to = (struct sockaddr *)&sin6;
	} else if(cookie->addr_type == SCTP_IPV4_ADDRESS) {
		memset(&sin,0,sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(sin);
		sin.sin_port = sctphdr->src_port;
		sin.sin_addr.s_addr = cookie->address[0];
		to = (struct sockaddr *)&sin;
	}
	if ((*stcb == NULL) && to) {
		/* Yep, lets check */
		*stcb = sctp_findassociation_ep_addr(inp, to, netp, localep_sa);
	}

	cookie_len -= SCTP_SIGNATURE_SIZE;
	if (*stcb == NULL) {
		/* this is the "normal" case... get a new TCB */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: processing NEW cookie\n");
		}
#endif
		*stcb = sctp_process_cookie_new(m, offset, iphlen,
						*inp, netp,
						cookie, cookie_len,
						to, localep_sa,
						&notification);
	} else {
		/* this is abnormal... cookie-echo on existing TCB */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("sctp_handle_cookie: processing EXISTING cookie\n");
		}
#endif
#ifdef SCTP_TCP_MODEL_SUPPORT
		had_a_existing_tcb = 1;
#endif
		*stcb = sctp_process_cookie_existing(m, offset, iphlen, *inp,
						     *stcb, *netp,
						     cookie, cookie_len,
						     &notification, to);
	}

	if (*stcb == NULL) {
		/* still no TCB... must be bad cookie-echo */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("handle_cookie_echo: ACK! don't have a TCB!\n");
		}
#endif /* SCTP_DEBUG */
		return(NULL);
	}
#ifdef SCTP_TCP_MODEL_SUPPORT
	if((*inp)->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE){
		if(!had_a_existing_tcb ||
		   (((*inp)->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) == 0)){
			/* If we have a NEW cookie or the connect never reaced
			 * the connected state during collision we must do the
			 * TCP accept thing.
			 */
			struct socket *so,*oso;
			struct sctp_inpcb *n_inp;
			if(notification == SCTP_NOTIFY_ASSOC_RESTART){
				/* For a restart we will keep the same socket, no
				 * need to do anything. I THINK!!
				 */
				sctp_ulp_notify(notification, *stcb, 0, NULL);
				return(m);
			}
			oso = (*inp)->sctp_socket;
			so = sonewconn(oso,SS_ISCONNECTED);
			if(so == NULL){
				struct mbuf *op_err;
				/* Too many sockets */
#ifdef SCTP_DEBUG
				if(sctp_debug_on & SCTP_DEBUG_INPUT1){
					printf("process_cookie_new: no room for another socket!\n");
				}
#endif /* SCTP_DEBUG */
				op_err = sctp_generate_invmanparam(SCTP_CAUSE_OUT_OF_RESC);
				sctp_abort_association(*inp, (struct sctp_tcb *)NULL, m, iphlen,op_err);
				sctp_free_assoc(*inp, *stcb);
				return(NULL);
			}
			n_inp = (struct sctp_inpcb *)so->so_pcb;
			n_inp->sctp_flags = (SCTP_PCB_FLAGS_TCPTYPE |
					     SCTP_PCB_FLAGS_CONNECTED |
					     SCTP_PCB_FLAGS_IN_TCPPOOL |
					     (SCTP_PCB_COPY_FLAGS & (*inp)->sctp_flags) |
					     SCTP_PCB_FLAGS_DONT_WAKE);
			n_inp->sctp_socket = so;

			/* Now we must move it from one hash table to another and
			 * get the tcb in the right place.
			 */
			sctp_move_pcb_and_assoc(*inp,n_inp,*stcb);

			/* Switch over to the new guy */
			*inp = n_inp;
			sctp_ulp_notify(notification, *stcb, 0, NULL);
			return(m);
		}
	}
#endif
	if((notification) && ((*inp)->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE)){
		sctp_ulp_notify(notification, *stcb, 0, NULL);
	}
	return(m);
}

static void
sctp_handle_cookie_ack(struct sctp_cookie_ack_chunk *cp, struct sctp_tcb *stcb,
		       struct sctp_nets *netp)
{
	struct sctp_association *assoc;
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_cookie_ack: handling COOKIE-ACK\n");
	}
#endif
	if (stcb == NULL)
		return;

	assoc = &stcb->asoc;

	sctp_timer_stop(SCTP_TIMER_TYPE_COOKIE, stcb->sctp_ep, stcb, netp);

	/* process according to association state */
	if ((assoc->state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_ECHOED) {
		/* state change only needed when I am in right state */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT2){
			printf("moving to OPEN state\n");
		}
#endif
		if (assoc->state & SCTP_STATE_SHUTDOWN_PENDING) {
			assoc->state = SCTP_STATE_OPEN | SCTP_STATE_SHUTDOWN_PENDING;
		} else {
			assoc->state = SCTP_STATE_OPEN;
		}

		/* update RTO */
		if (assoc->overall_error_count == 0){
			netp->RTO = sctp_calculate_rto(stcb,assoc, netp,
						       &assoc->time_entered);
		}
		SCTP_GETTIME_TIMEVAL(&assoc->time_entered);
		sctp_ulp_notify(SCTP_NOTIFY_ASSOC_UP, stcb, 0, NULL);
		/* start the path MTU raise and heartbeat timers */
		sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, stcb->sctp_ep,
				 stcb, netp);
		sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT, stcb->sctp_ep,
				 stcb, netp);
		if (stcb->asoc.sctp_autoclose_ticks &&
		    (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_AUTOCLOSE)) {
			sctp_timer_start(SCTP_TIMER_TYPE_AUTOCLOSE,
					 stcb->sctp_ep, stcb, NULL);
		}

		/*
		 * set ASCONF timer if ASCONFs are pending and allowed
		 * (eg. addresses changed when init/cookie echo in flight)
		 */
		if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) &&
		    (stcb->asoc.peer_supports_asconf) &&
		    (!TAILQ_EMPTY(&stcb->asoc.asconf_queue))) {
			sctp_timer_start(SCTP_TIMER_TYPE_ASCONF,
					 stcb->sctp_ep, stcb,
					 stcb->asoc.primary_destination);
		}

	}
	/* Toss the cookie if I can */
	sctp_toss_old_cookies(assoc);
	if(!TAILQ_EMPTY(&assoc->sent_queue)){
		/* Restart the timer if we have pending data */
		struct sctp_tmit_chunk *chk;
		chk = TAILQ_FIRST(&assoc->sent_queue);
		if(chk){
			sctp_timer_start(SCTP_TIMER_TYPE_SEND,
					 stcb->sctp_ep,
					 stcb,
					 chk->whoTo);
		}
	}

}

static void
sctp_handle_ecn_echo(struct sctp_ecne_chunk *ecne,
		     struct sctp_tcb *tcb)
{
	struct sctp_nets *net;

	if(ntohs(ecne->ch.chunk_length) != sizeof(struct sctp_ecne_chunk)){
		return;
	}
	net = tcb->asoc.primary_destination;
	if (compare_with_wrap(ntohl(ecne->tsn), tcb->asoc.last_cwr_tsn, MAX_TSN)){
		/* We pay no attention to the net, only the primary
		 * counts here. Only time this strategy will fail is
		 * if a change primary was done just before the ecn
		 * signal arrived. But this is a rare occurance we
		 * hope. For retrans' the ECN marks are not set per
		 * the ECN RFC so no danger on retrans.
		 */
		net->ssthresh = net->cwnd / 2;
		if (net->ssthresh < net->mtu) {
			net->ssthresh = net->mtu;
			/* here back off the timer as well, to slow us down */
			net->RTO <<= 2;
		}
		net->cwnd = net->ssthresh;
		tcb->asoc.last_cwr_tsn = ntohl(ecne->tsn);
	}
	/*
	 * We always send a CWR this way if our previous one was lost
	 * our peer will get an update.
	 */
	sctp_send_cwr(tcb, net, tcb->asoc.last_cwr_tsn);
}


static void
sctp_handle_shutdown_complete(struct sctp_shutdown_complete_chunk *cp,
			      struct sctp_tcb *stcb, struct sctp_nets *netp)
{
	struct sctp_association *assoc;
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT2){
		printf("sctp_handle_shutdown_complete: handling SHUTDOWN-COMPLETE\n");
	}
#endif
	if (stcb == NULL)
		return;

	assoc = &stcb->asoc;
	/* process according to association state */
	if ((assoc->state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_ACK_SENT) {
		/* unexpected SHUTDOWN-COMPLETE... so ignore... */
		return;
	}
	/* notify upper layer protocol */
	sctp_ulp_notify(SCTP_NOTIFY_ASSOC_DOWN, stcb, 0, NULL);
	/* are the queues empty? */
	if (!TAILQ_EMPTY(&assoc->send_queue) ||
	    !TAILQ_EMPTY(&assoc->sent_queue) ||
	    !TAILQ_EMPTY(&assoc->out_wheel)) {
		sctp_report_all_outbound(stcb);
	}
	/* stop the timer */
	sctp_timer_stop(SCTP_TIMER_TYPE_SHUTDOWN, stcb->sctp_ep, stcb, netp);
	/* free the TCB */
	sctp_free_assoc(stcb->sctp_ep, stcb);
	if(stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
		/* Yes, so can we purge ourself now */
		if(LIST_FIRST(&stcb->sctp_ep->sctp_asoc_list) == NULL){
			/* finish the job now */
			sctp_inpcb_free(stcb->sctp_ep,1);
		}
	}
	return;
}


/*
 * handles all control chunks in a packet
 * inputs:
 * - m: mbuf chain, assumed to still contain IP/SCTP header
 * - stcb: is the tcb found for this packet
 * - offset: offset into the mbuf chain to first chunkhdr
 * - length: is the length of the complete packet
 * outputs:
 * - length: modified to remaining length after control processing
 * - netp: modified to new sctp_nets after cookie-echo processing
 * - return NULL to discard the packet (ie. no assoc, bad packet,...)
 *   otherwise return the tcb for this packet
 */
static struct sctp_tcb *
sctp_process_control(struct mbuf *m, struct sctp_inpcb *inp,
		     struct sctp_tcb *stcb, struct sctp_nets **netp,
		     int iphlen, int *offset, int *length)
{
	struct sctphdr *sctphdr;
	struct sctp_chunkhdr *ch;
	struct sctp_association *assoc;
	u_int32_t vtag_in;
	int num_chunks = 0;	/* number of control chunks processed */
	int chk_length, ret;

	/* How big should this be, and should it be alloc'd?
	 * Lets try the d-mtu-ceiling for now (2k) and that should
	 * hopefully work ... until we get into jumbo grams and such..
	 */
	static u_int8_t chunk_buf[DEFAULT_CHUNK_BUFFER];


#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INPUT1) {
		printf("sctp_process_control: iphlen=%u, offset=%u, length=%u stcb:%x\n",
		       iphlen, *offset, *length, (u_int)stcb);
	}
#endif /* SCTP_DEBUG */
	/* get pointer to the first chunk header */
	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, *offset, sizeof(struct sctp_chunkhdr), chunk_buf);

	/* validate chunk header length... */
	if (ntohs(ch->chunk_length) < sizeof(struct sctp_chunkhdr)) {
		return(NULL);
	}

	/*
	 * validate the verification tag
	 */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
		printf("sctp_process_control: validating vtags\n");
	}
#endif /* SCTP_DEBUG */
	sctphdr = (struct sctphdr *)(mtod(m, caddr_t) + iphlen);
	vtag_in = ntohl(sctphdr->v_tag);
	if (ch->chunk_type == SCTP_INITIATION) {
		if (vtag_in != 0) {
			/* protocol error- silently discard... */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
				printf("sctp_process_control: INIT with vtag != 0\n");
			}
#endif /* SCTP_DEBUG */
			sctp_pegs[SCTP_BAD_VTAGS]++;
			return(NULL);
		}
	} else if ((ch->chunk_type != SCTP_INITIATION_ACK) &&
		   (ch->chunk_type != SCTP_COOKIE_ECHO)) {
		/*
		 * first check if it's an ASCONF with an unknown src addr
		 * we need to look inside to find the association
		 */
		if ((ch->chunk_type == SCTP_ASCONF) && (stcb == NULL)) {
			struct sctp_asconf_chunk *acp;
			struct sockaddr_storage sa_store;
			struct sockaddr *sa = (struct sockaddr *)&sa_store;
			struct sockaddr_storage dest_store;
			struct sockaddr *localep_sa = (struct sockaddr *)&dest_store;
			struct ip *iph;
			struct sctp_ipv6addr_param *p_addr;

			/* First get the destination address setup too. */

			iph = mtod(m, struct ip *);
			if (iph->ip_v == IPVERSION) {
				/* its IPv4 */
				struct sockaddr_in *sin;
				sin = (struct sockaddr_in *)(localep_sa);
				memset(sin,0,sizeof(*sin));
				sin->sin_family = AF_INET;
				sin->sin_len = sizeof(*sin);
				sin->sin_port = sctphdr->dest_port;
				sin->sin_addr.s_addr = iph->ip_dst.s_addr ;
			} else {
				/* its IPv6 */
				struct ip6_hdr *ip6;
				struct sockaddr_in6 *sin6;
				sin6 = (struct sockaddr_in6 *)(localep_sa);
				memset(sin6,0,sizeof(*sin6));
				sin6->sin6_family = AF_INET6;
				sin6->sin6_len = sizeof(struct sockaddr_in6);
				ip6 = mtod(m, struct ip6_hdr *);
				sin6->sin6_port = sctphdr->dest_port;
				sin6->sin6_addr = ip6->ip6_dst;
			}
			/* try lookup up assoc using the correlation address */
			acp = (struct sctp_asconf_chunk *)sctp_m_getptr(m, *offset, sizeof(struct sctp_asconf_chunk), chunk_buf);
			if (acp == NULL) {
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
					printf("sctp_process_control: failed to get asconf chunk header\n");
				}
#endif /* SCTP_DEBUG */
				return(NULL);
			}

			p_addr = (struct sctp_ipv6addr_param *)sctp_m_getptr(m, *offset+sizeof(struct sctp_asconf_chunk), sizeof(struct sctp_paramhdr), chunk_buf);
			if (p_addr == NULL) {
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
					printf("sctp_process_control: failed to get asconf lookup addr\n");
				}
#endif /* SCTP_DEBUG */
				return(NULL);
			}
			p_addr->ph.param_type = ntohs(p_addr->ph.param_type);
			p_addr->ph.param_length = ntohs(p_addr->ph.param_length);

			/* get the correlation address */
			if (p_addr->ph.param_type == SCTP_IPV6_ADDRESS) {
				/* ipv6 address param */
				struct sockaddr_in6 *sin6;

				if (p_addr->ph.param_length != sizeof(struct sctp_ipv6addr_param))
					return(NULL);

				p_addr = (struct sctp_ipv6addr_param *)sctp_m_getptr(m, *offset+sizeof(struct sctp_asconf_chunk), sizeof(struct sctp_ipv6addr_param), chunk_buf);
				if (p_addr == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
						printf("sctp_process_control: failed to get asconf v6 lookup addr\n");
					}
#endif /* SCTP_DEBUG */
				}
				sin6 = (struct sockaddr_in6 *)&sa_store;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_len = sizeof(struct sockaddr_in6);
				sin6->sin6_port = sctphdr->src_port;
				memcpy(&sin6->sin6_addr, p_addr->addr, sizeof(struct in6_addr));
			} else if (p_addr->ph.param_type == SCTP_IPV4_ADDRESS) {
				/* ipv4 address param */
				struct sockaddr_in *sin;

				if (p_addr->ph.param_length != sizeof(struct sctp_ipv4addr_param))
					return(NULL);

				p_addr = (struct sctp_ipv6addr_param *)sctp_m_getptr(m, *offset+sizeof(struct sctp_asconf_chunk), sizeof(struct sctp_ipv4addr_param), chunk_buf);
				if (p_addr == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
						printf("sctp_process_control: failed to get asconf v4 lookup addr\n");
					}
#endif /* SCTP_DEBUG */
				}
				sin = (struct sockaddr_in *)&sa_store;
				sin->sin_family = AF_INET;
				sin->sin_len = sizeof(struct sockaddr_in);
				sin->sin_port = sctphdr->src_port;
				memcpy(&sin->sin_addr, p_addr->addr, sizeof(struct in_addr));
			} else {
				/* invalid address param type */
				return(NULL);
			}

			stcb = sctp_findassociation_ep_addr(&inp, sa, netp,
							    localep_sa);
		}
		if (stcb == NULL) {
			/* no association, so it's out of the blue... */
			sctp_handle_ootb(inp, m, iphlen, *offset, *length,
					 NULL);
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
				printf("sctp_process_control: handling OOTB packet, chunk type=%xh\n",
				       ch->chunk_type);
			}
#endif /* SCTP_DEBUG */
			*length = 0;
			return(NULL);
		}
		assoc = &stcb->asoc;
		/* ABORT and SHUTDOWN can use either v_tag... */
		if ((ch->chunk_type == SCTP_ABORT_ASSOCIATION) ||
		    (ch->chunk_type == SCTP_SHUTDOWN_COMPLETE)) {
			if ((vtag_in == assoc->my_vtag) ||
			    ((ch->chunk_flags & SCTP_HAD_NO_TCB) &&
			     (vtag_in == assoc->peer_vtag))) {
				/* this is valid */
			} else {
				/* drop this packet... */
				sctp_pegs[SCTP_BAD_VTAGS]++;
				return(NULL);
			}
		} else if (ch->chunk_type == SCTP_SHUTDOWN_ACK) {
			if (vtag_in != assoc->my_vtag) {
				/*
				 * this could be a stale SHUTDOWN-ACK or the
				 * peer never got the SHUTDOWN-COMPLETE and
				 * is still hung; we have started a new assoc
				 * but it won't complete until the shutdown is
				 * completed
				 */
				sctp_send_shutdown_complete(stcb, stcb->asoc.primary_destination);
				return(NULL);
			}
		} else {
			/* for all other chunks, vtag must match */

			if (vtag_in != assoc->my_vtag) {
				/* invalid vtag... */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
					printf("invalid vtag: %xh, expect %xh\n", vtag_in, assoc->my_vtag);
				}
#endif /* SCTP_DEBUG */
				sctp_pegs[SCTP_BAD_VTAGS]++;
				*length = 0;
				return(NULL);
			}
		}
	} /* end if SCTP_INIT_ACK, SCTP_COOKIE_ECHO */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
		printf("sctp_process_control: vtags ok, processing ctrl chunks\n");
	}
#endif /* SCTP_DEBUG */

	/*
	 * process all control chunks...
	 */
	while (IS_SCTP_CONTROL(ch)) {
		/* validate chunk length */
		chk_length = ntohs(ch->chunk_length);
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INPUT2) {
			printf("sctp_process_control: processing a chunk type=%u, len=%u\n", ch->chunk_type, chk_length);
		}
#endif /* SCTP_DEBUG */
		if ((chk_length < sizeof(struct sctp_chunkhdr)) ||
		    (*length < chk_length)) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INPUT3) {
				printf("sctp_process_control: length issue *length:%u < chk_length:%u\n", *length,
				       chk_length);
			}
#endif /* SCTP_DEBUG */
			*length = 0;
			return(NULL);
		}

		/*
		 * INIT-ACK only gets the init ack "header" portion only
		 * COOKIE-ECHO and ASCONF only gets the chunk header
		 * (already done), all others get a complete chunk
		 */
		if (ch->chunk_type == SCTP_INITIATION_ACK) {
			/* get an init-ack chunk */
			ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, *offset, sizeof(struct sctp_init_ack), chunk_buf);
		} else if ((ch->chunk_type != SCTP_COOKIE_ECHO) &&
			   (ch->chunk_type != SCTP_ASCONF)) {
			/* get a complete chunk... */
			if (chk_length > sizeof(chunk_buf)) {
				struct mbuf *oper;
				struct sctp_paramhdr *phdr;
				oper = NULL;
				MGETHDR(oper, M_DONTWAIT, MT_HEADER);
				if (oper) {
					/* pre-reserve some space */
					oper->m_data += sizeof(struct sctp_chunkhdr);
					phdr = mtod(oper, struct sctp_paramhdr *);
					phdr->param_type = htons(SCTP_CAUSE_OUT_OF_RESC);
					phdr->param_length = htons(sizeof(struct sctp_paramhdr));
					sctp_queue_op_err(stcb,oper);
				}
				return(NULL);
			}
			ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, *offset, chk_length, chunk_buf);
		}
		num_chunks++;
		/* Save off the last place we got a control from */
		if((*netp) && stcb){
			stcb->asoc.last_control_chunk_from = *netp;
		}
		switch (ch->chunk_type) {
		case SCTP_INITIATION:
			/* must be first and only chunk */
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_INIT\n");
			}
#endif /* SCTP_DEBUG */
			if(stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
				/* We are not interested anymore */
				*length = 0;
				return(NULL);
			}
			if ((num_chunks > 1) ||
			    (*length > SCTP_SIZE32(chk_length))) {
				*length = 0;
				return(NULL);
			}
			sctp_handle_init(m, (struct sctp_init_chunk *)ch,
					 inp, stcb, *netp, iphlen);
			*length = 0;
			return(NULL);
			break;
		case SCTP_INITIATION_ACK:
			/* must be first and only chunk */
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_INIT-ACK\n");
			}
#endif /* SCTP_DEBUG */
			if(stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
				/* We are not interested anymore */
				*length = 0;
				return(NULL);
			}

			if ((num_chunks > 1) ||
			    (*length > SCTP_SIZE32(chk_length))) {
#ifdef SCTP_DEBUG
				if(sctp_debug_on & SCTP_DEBUG_INPUT3){
					printf("Length is %d rounded chk_length:%d .. dropping\n",
					       *length,SCTP_SIZE32(chk_length));
				}
#endif
				*length = 0;
				return(NULL);
			}
			ret = sctp_handle_init_ack(m, (struct sctp_init_ack_chunk *)ch, stcb, *netp, *offset, iphlen);
			/* Special case, I must call the output routine
			 * to get the cookie echoed
			 */
			if((stcb) && ret == 0)
				sctp_chunk_output(stcb->sctp_ep, stcb, 2);
			*length = 0;
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("All done INIT-ACK processing\n");
			}
#endif
			return(NULL);
			break;
		case SCTP_SELECTIVE_ACK:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_SACK\n");
			}
#endif /* SCTP_DEBUG */
			sctp_pegs[SCTP_PEG_SACKS_SEEN]++;
			sctp_handle_sack((struct sctp_sack_chunk *)ch, stcb, *netp);
			break;
		case SCTP_HEARTBEAT_REQUEST:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_HEARTBEAT\n");
			}
#endif /* SCTP_DEBUG */
			sctp_pegs[SCTP_HB_RECV]++;
			sctp_send_heartbeat_ack(stcb, m, *offset, chk_length, *netp);

			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;
			break;
		case SCTP_HEARTBEAT_ACK:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_HEARTBEAT-ACK\n");
			}
#endif /* SCTP_DEBUG */

			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;

			sctp_pegs[SCTP_HB_ACK_RECV]++;
			sctp_handle_heartbeat_ack((struct sctp_heartbeat_chunk *)ch, stcb, *netp);
			break;
		case SCTP_ABORT_ASSOCIATION:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_ABORT\n");
			}
#endif /* SCTP_DEBUG */
			sctp_handle_abort((struct sctp_abort_chunk *)ch,
					  stcb, *netp);
			*length = 0;	/* discard any remaining chunks... */
			return(NULL);
			break;
		case SCTP_SHUTDOWN:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_SHUTDOWN\n");
			}
#endif /* SCTP_DEBUG */
			sctp_handle_shutdown((struct sctp_shutdown_chunk *)ch,
					     stcb, *netp);
			break;
		case SCTP_SHUTDOWN_ACK:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_SHUTDOWN-ACK\n");
			}
#endif /* SCTP_DEBUG */
			sctp_handle_shutdown_ack((struct sctp_shutdown_ack_chunk *)ch, stcb, *netp);
			*length = 0;
			return(NULL);
			break;
		case SCTP_OPERATION_ERROR:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_OP-ERR\n");
			}
#endif /* SCTP_DEBUG */
			sctp_handle_error(ch, stcb, *netp, chk_length);
			break;
		case SCTP_COOKIE_ECHO:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_COOKIE-ECHO stcb is %x\n",(u_int)stcb);
			}
#endif /* SCTP_DEBUG */
			if(stcb &&(stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
				/* We are not interested anymore */
				*length = 0;
				return(NULL);
			}
			{
				struct mbuf *ret_buf;
				ret_buf = sctp_handle_cookie_echo(m, *offset,
								  iphlen, &inp,
								  &stcb, netp,
								  sctphdr);
#ifdef SCTP_DEBUG
				if(sctp_debug_on & SCTP_DEBUG_INPUT3){
					printf("ret_buf:%x length:%d off:%d\n",
					       (u_int)ret_buf,*length,*offset);
				}
#endif /* SCTP_DEBUG */

				if (ret_buf == NULL) {
#ifdef SCTP_DEBUG
					if(sctp_debug_on & SCTP_DEBUG_INPUT3){
						printf("GAK, null buffer\n");
					}
#endif /* SCTP_DEBUG */
					*length = 0;
					return(NULL);
				}
				if(!TAILQ_EMPTY(&stcb->asoc.sent_queue)){
					/* Restart the timer if we have pending data */
					struct sctp_tmit_chunk *chk;
					chk = TAILQ_FIRST(&stcb->asoc.sent_queue);
					if(chk){
						sctp_timer_start(SCTP_TIMER_TYPE_SEND,
								 stcb->sctp_ep,
								 stcb,
								 chk->whoTo);
					}
				}
			}
			break;
		case SCTP_COOKIE_ACK:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_COOKIE-ACK\n");
			}
#endif /* SCTP_DEBUG */
			if(stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)){
				/* We are not interested anymore */
				*length = 0;
				return(NULL);
			}
			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;
			sctp_handle_cookie_ack((struct sctp_cookie_ack_chunk *)ch, stcb, *netp);
			break;
		case SCTP_ECN_ECHO:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_ECN-ECHO\n");
			}
#endif /* SCTP_DEBUG */
			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;
			sctp_handle_ecn_echo((struct sctp_ecne_chunk *)ch, stcb);
			break;
		case SCTP_ECN_CWR:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_ECN-CWR\n");
			}
#endif /* SCTP_DEBUG */
			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;

			sctp_handle_ecn_cwr((struct sctp_cwr_chunk *)ch, stcb);
			break;
		case SCTP_SHUTDOWN_COMPLETE:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_SHUTDOWN-COMPLETE\n");
			}
#endif /* SCTP_DEBUG */
			/* must be first and only chunk */
			if ((num_chunks > 1) ||
			    (*length > SCTP_SIZE32(chk_length))) {
				*length = 0;
				return(NULL);
			}
			sctp_handle_shutdown_complete((struct sctp_shutdown_complete_chunk *)ch, stcb, *netp);
			*length = 0;
			return(NULL);
			break;
		case SCTP_ASCONF:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_ASCONF\n");
			}
#endif /* SCTP_DEBUG */
			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;

			sctp_handle_asconf(m, *offset, (struct sctp_asconf_chunk *)ch, stcb, *netp);
			break;
		case SCTP_ASCONF_ACK:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_ASCONF-ACK\n");
			}
#endif /* SCTP_DEBUG */
			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;

			sctp_handle_asconf_ack(m, *offset, (struct sctp_asconf_ack_chunk *)ch, stcb, *netp);
			break;
		case SCTP_FORWARD_CUM_TSN:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT3){
				printf("SCTP_FWD-TSN\n");
			}
#endif /* SCTP_DEBUG */
			/* He's alive so give him credit */
			stcb->asoc.overall_error_count = 0;

			sctp_handle_forward_tsn(stcb, (struct sctp_forward_tsn_chunk *)ch);
			stcb->asoc.overall_error_count = 0;
			break;
		default:
			/* it's an unknown chunk! */
			if ((ch->chunk_type & 0x40) && (stcb != NULL)) {
				struct mbuf *mm;
				struct sctp_paramhdr *phd;
				MGETHDR(mm,M_DONTWAIT,MT_HEADER);
				if(mm){
					phd = mtod(mm,struct sctp_paramhdr *);
					/* We cheat and use param type since we
					 * did not bother to define a error cause struct.
					 * They are the same basic format with different
					 * names.
					 */
					phd->param_type = htons(SCTP_CAUSE_UNRECOG_CHUNK);
					phd->param_length = htons(chk_length+sizeof(*phd));
					mm->m_len = sizeof(*phd);
					mm->m_next = m_copym(m, *offset,
							     SCTP_SIZE32(chk_length),
							     M_DONTWAIT);
					if(mm->m_next){
						mm->m_pkthdr.len = SCTP_SIZE32(chk_length) + sizeof(*phd);
						sctp_queue_op_err(stcb,mm);
					}else{
						m_freem(mm);
#ifdef SCTP_DEBUG
						if(sctp_debug_on & SCTP_DEBUG_INPUT1){
							printf("Gak can't copy the chunk into operr %d bytes\n",
							       chk_length);
						}
#endif
					}
#ifdef SCTP_DEBUG
				}else{
					if(sctp_debug_on & SCTP_DEBUG_INPUT3){
						printf("Gak can't mgethdr for op-err of unrec chunk\n");
					}
#endif
				}
			}
			if ((ch->chunk_type & 0x80) == 0) {
				/* discard this packet */
				*length = 0;
				return(NULL);
			} /* else skip this bad chunk and continue... */
			break;
		} /* switch(ch->chunk_type) */
		/* get the next chunk */
		*offset += SCTP_SIZE32(chk_length);
		*length -= SCTP_SIZE32(chk_length);
		if (*length <= 0) {
			/* no more data left in the mbuf chain */
			break;
		}
		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, *offset, sizeof(struct sctp_chunkhdr), chunk_buf);
		if (ch == NULL) {
			*length = 0;
			return(NULL);
		}
	} /* while */

	return(stcb);
}


static void
sctp_process_ecn_marked(struct sctp_tcb *stcb,
			struct sctp_nets *net,
			u_int32_t high_tsn,
			u_int8_t ecn_bits)
{
	/* Process the ECN bits we have something set so
	 * we must look to see if it is ECN(0) or ECN(1) or CE
	 */
	if((ecn_bits & SCTP_CE_BITS) == SCTP_CE_BITS){
		/* we possibly must notify the sender that a congestion
		 * window reduction is in order. We do this
		 * by adding a ECNE chunk to the output chunk
		 * queue. The incoming CWR will remove this chunk.
		 */
		if(compare_with_wrap(high_tsn,stcb->asoc.last_echo_tsn,MAX_TSN)){
			/* Yep, we need to add a ECNE */
			sctp_send_ecn_echo(stcb,net,high_tsn);
			stcb->asoc.last_echo_tsn = high_tsn;
		}
	}else if((ecn_bits & SCTP_ECT1_BIT) == SCTP_ECT1_BIT){
		/* we only add to the nonce sum for ECT1, ECT0
		 * does not change the NS bit (that we have
		 * yet to find a way to send it yet).
		 */
		stcb->asoc.nonce_sum_in++;
		/* Drag up the last_echo point if cumack is larger since we
		 * don't want the point falling way behind by more than 2^^31
		 * and then having it be incorrect.
		 */
		if(compare_with_wrap(stcb->asoc.cumulative_tsn,stcb->asoc.last_echo_tsn,MAX_TSN)){
			stcb->asoc.last_echo_tsn = stcb->asoc.cumulative_tsn;
		}
	}else if((ecn_bits & SCTP_ECT0_BIT) == SCTP_ECT0_BIT){
		/* Drag up the last_echo point if cumack is larger since we
		 * don't want the point falling way behind by more than 2^^31
		 * and then having it be incorrect.
		 */
		if(compare_with_wrap(stcb->asoc.cumulative_tsn,stcb->asoc.last_echo_tsn,MAX_TSN)){
			stcb->asoc.last_echo_tsn = stcb->asoc.cumulative_tsn;
		}
	}
}

/*
 * common input chunk processing (v4 and v6)
 */
int
sctp_common_input_processing(struct sctp_inpcb *inp,
			     struct sctp_tcb *stcb,
			     struct sctp_nets *netp,
			     struct sctphdr *sh,
			     struct sctp_chunkhdr *ch,
			     struct mbuf *m,
			     int iphlen,
			     int offset,
			     int length,
			     u_int8_t ecn_bits) {

	/*
	 * Control chunk processing
	 */
	u_int32_t high_tsn;

	sctp_pegs[SCTP_DATAGRAMS_RCVD]++;
	if (IS_SCTP_CONTROL(ch)) {
		/* process the control portion of the SCTP packet */
		stcb = sctp_process_control(m, inp, stcb, &netp, iphlen,
					    &offset, &length);
	} else {
		/*
		 * no control chunks, so pre-process DATA chunks
		 * (these checks are taken care of by control processing)
		 */
		if (stcb == NULL){
			/* out of the blue DATA chunk */
			sctp_handle_ootb(inp, m, iphlen, offset, length,
					 NULL);

			return(1);
		}
		if (stcb->asoc.my_vtag != ntohl(sh->v_tag)) {
			/* v_tag mismatch! */
			sctp_pegs[SCTP_BAD_VTAGS]++;
			return(1);
		}
	}
	if (stcb == NULL) {
		/*
		 * no valid TCB for this packet,
		 * or we found it's a bad packet while processing control,
		 * or we're done with this packet (done or skip rest of data),
		 * so we drop it...
		 */
		return(1);
	}
#ifdef SCTP_DEBUG
	if(sctp_debug_on & SCTP_DEBUG_INPUT1){
		printf("Ok, control finished time to look for data (%d) offset:%d\n",
		       length,offset);
	}
#endif /* SCTP_DEBUG */
	/*
	 * DATA chunk processing
	 */
	/* plow through the data chunks while length > 0 */
	if (length > 0) {
		int ret_v;
		/*
		 * First check to make sure our state is correct.
		 * We would not get here unless we really did have a
		 * tag, so we don't abort if this happens, just
		 * dump the chunk silently.
		 */
		switch(stcb->asoc.state & SCTP_STATE_MASK){
		case SCTP_STATE_EMPTY:	/* should not happen */
		case SCTP_STATE_INUSE:	/* should not happen */
		case SCTP_STATE_COOKIE_WAIT:	/* dump data in this state */
		case SCTP_STATE_COOKIE_ECHOED:/* dump data in this state */
		case SCTP_STATE_SHUTDOWN_RECEIVED: 	/* This is a peer error */
		case SCTP_STATE_SHUTDOWN_ACK_SENT:
		default:
#ifdef SCTP_DEBUG
			if(sctp_debug_on & SCTP_DEBUG_INPUT1){
				printf("Got data in invalid state %d.. dropping\n",stcb->asoc.state);
			}
#endif
			return(1);
			break;
		case SCTP_STATE_OPEN:
		case SCTP_STATE_SHUTDOWN_SENT:
			break;
		}
		/* take care of ECN */
		/* plow through the data chunks while length > 0 */
		ret_v = sctp_process_data(m, inp, stcb, netp, iphlen, &offset,
					  &length, &high_tsn);
		/* Anything important needs to have been m_copy'ed in process_data */
		if(ret_v == 0){
			if (stcb->asoc.ecn_allowed &&
			    (ecn_bits & (SCTP_ECT0_BIT|SCTP_ECT1_BIT))) {
				/* The packet is marked for congestion */
				sctp_process_ecn_marked(stcb, netp, high_tsn,
							ecn_bits);
			}
		}else{
			return(0);
		}
	}
	/* trigger send of any chunks in queue... */
	sctp_chunk_output(inp, stcb, 3);
	return(0);
}


#if defined(__OpenBSD__)
static void
sctp_saveopt(struct sctp_inpcb *inp,
	     struct mbuf **mp,
	     struct ip *ip,
	     struct mbuf *m)
{
	if (inp->ip_inp.inp.inp_flags & INP_RECVDSTADDR) {
		*mp = sbcreatecontrol((caddr_t) &ip->ip_dst,
				      sizeof(struct in_addr), IP_RECVDSTADDR, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
}

#endif

#if defined(__FreeBSD__)
void
sctp_input(m, off)
	struct mbuf *m;
	int off;
#else
void
#if __STDC__
sctp_input(struct mbuf *m, ...)
#else
sctp_input(m, va_alist)
	struct mbuf *m;
#endif
#endif
{
	int iphlen,s;
	u_int8_t ecn_bits;
	struct ip *ip;
	struct sctphdr *sh;
	struct sctp_inpcb *inp;
	struct mbuf *opts = 0;
#ifdef INET6
	struct ip6_recvpktopts opts6;
#endif /* INET6 */
	u_int32_t check, calc_check;
	struct sctp_nets *netp;
	struct sctp_tcb *stcb;
	struct sctp_chunkhdr *ch;
	int length, mlen, offset;
#if defined(__OpenBSD__) && defined(IPSEC)
	struct inpcb *i_inp;
	struct m_tag *mtag;
	struct tdb_ident *tdbi;
	struct tdb *tdb;
	int error;
#endif

#ifndef __FreeBSD__
	int off;
	va_list ap;

	va_start(ap, m);
	iphlen = off = va_arg(ap, int);
	va_end(ap);
#else
	iphlen = off;
#endif
	sctp_pegs[SCTP_INPKTS]++;

#ifdef INET6
	bzero(&opts6, sizeof(opts6));
#endif /* INET6 */

	/*
	 * Strip IP options, we don't allow any in or out.
	 */
	if (iphlen > sizeof(struct ip)) {
		ip_stripoptions(m, (struct mbuf *)0);
		iphlen = sizeof(struct ip);
	}

	/*
	 * Get IP, SCTP, and first chunk header together in first mbuf.
	 */
	ip = mtod(m, struct ip *);
	offset = iphlen + sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr);
	if (m->m_len < offset) {
		if ((m = m_pullup(m, offset)) == 0) {
			sctp_pegs[SCTP_HDR_DROPS]++;
			return;
		}
		ip = mtod(m, struct ip *);
	}
	sh = (struct sctphdr *)((caddr_t)ip + iphlen);
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));

	/* SCTP does not allow broadcasts or multicasts */
	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) ||
	    in_broadcast(ip->ip_dst, m->m_pkthdr.rcvif)) {
		sctp_pegs[SCTP_IN_MCAST]++;
		goto bad;
	}

	/* validate SCTP checksum */
	check = sh->checksum;	/* save incoming checksum */
	sh->checksum = 0;		/* prepare for calc */
	calc_check = sctp_calculate_sum(m, &mlen, iphlen);
	if (calc_check != check) {
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("sctp_input: checksum failed!\n");
		}
#endif /* SCTP_DEBUG */
		sctp_pegs[SCTP_BAD_CSUM]++;
		goto bad;
	}

	/* validate mbuf chain length with IP payload length */
	if (mlen < (ip->ip_len - iphlen))
		goto bad;

	/* destination port of 0 is illegal, based on RFC2960. */
	if (sh->dest_port == 0)
		goto bad;

	/*
	 * Locate pcb and tcb for datagram
	 * sctp_findassociation_addr() wants IP/SCTP/first chunk header...
	 */
	stcb = sctp_findassociation_addr(m, iphlen, &inp, &netp);
	if (inp == NULL) {
		sctp_pegs[SCTP_NOPORTS]++;
#ifdef ICMP_BANDLIM
		/*
		 * we use the bandwidth limiting to protect against
		 * sending too many ABORTS all at once. In this case
		 * these count the same as an ICMP message.
		 */
		if (badport_bandlim(0) < 0)
			goto bad;
#endif /* ICMP_BANDLIM */
#ifdef SCTP_DEBUG
		if(sctp_debug_on & SCTP_DEBUG_INPUT1){
			printf("Sending a ABORT from packet entry!\n");
		}
#endif
		sctp_send_abort(m, ip, sh, iphlen, 0, NULL);
		m_freem(m);
		return;
	}
#ifdef IPSEC
	/*
	 * I very much doubt any of the IPSEC stuff will
	 * work but I have no idea, so I will leave it
	 * in place.
	 */
#ifdef __OpenBSD__
	{
		i_inp = &inp->ip_inp.inp;
		mtag = m_tag_find(m, PACKET_TAG_IPSEC_IN_DONE, NULL);
		s = splnet();
		if (mtag != NULL) {
			tdbi = (struct tdb_ident *)(mtag + 1);
			tdb = gettdb(tdbi->spi, &tdbi->dst, tdbi->proto);
		} else
			tdb = NULL;
		ipsp_spd_lookup(m, AF_INET, iphlen, &error,
				IPSP_DIRECTION_IN, tdb, i_inp);

		/* Latch SA only if the socket is connected */
		if (i_inp->inp_tdb_in != tdb &&
		    (i_inp->inp_socket->so_state & SS_ISCONNECTED)) {
			if (tdb) {
				tdb_add_inp(tdb, i_inp, 1);
				if (i_inp->inp_ipsec_remoteid == NULL &&
				    tdb->tdb_srcid != NULL) {
					i_inp->inp_ipsec_remoteid = tdb->tdb_srcid;
					tdb->tdb_srcid->ref_count++;
				}
				if (i_inp->inp_ipsec_remotecred == NULL &&
				    tdb->tdb_remote_cred != NULL) {
					i_inp->inp_ipsec_remotecred =
						tdb->tdb_remote_cred;
					tdb->tdb_remote_cred->ref_count++;
				}
				if (i_inp->inp_ipsec_remoteauth == NULL &&
				    tdb->tdb_remote_auth != NULL) {
					i_inp->inp_ipsec_remoteauth =
						tdb->tdb_remote_auth;
					tdb->tdb_remote_auth->ref_count++;
				}
			} else { /* Just reset */
				TAILQ_REMOVE(&i_inp->inp_tdb_in->tdb_inp_in, i_inp,
					     inp_tdb_in_next);
				i_inp->inp_tdb_in = NULL;
			}
		}
		splx(s);
		/* Error or otherwise drop-packet indication. */
		if (error)
			goto bad;
	}
#else
	if (ipsec4_in_reject_so(m, inp->ip_inp.inp.inp_socket)) {
		ipsecstat.in_polvio++;
		goto bad;
	}
#endif
#endif /* IPSEC */

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	if ((inp->ip_inp.inp.inp_flags & INP_CONTROLOPTS)
#ifndef __OpenBSD__
	    || (inp->sctp_socket->so_options & SO_TIMESTAMP)
#endif
		) {
#ifdef __OpenBSD__
		sctp_saveopt(inp,&opts,ip,m);
#else
		ip_savecontrol((struct inpcb *)inp, &opts, ip, m);
#endif
	}

	/*
	 * common chunk processing
	 */
#if defined(__FreeBSD__) || defined(__OpenBSD__)
	length = ip->ip_len - sizeof(struct sctphdr);
#else
	length = ip->ip_len - (sizeof(struct sctphdr) + (ip->ip_hl << 2));
#endif
	offset -= sizeof(struct sctp_chunkhdr);

	ecn_bits = ip->ip_tos;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (sctp_common_input_processing(inp, stcb, netp, sh, ch, m, iphlen,
					 offset, length, ecn_bits)) {
		splx(s);
		goto bad;
	}
	splx(s);
	m_freem(m);
	if(opts)
		m_freem(opts);
	return;
 bad:
	m_freem(m);
	if (opts)
		m_freem(opts);
	return;
}
