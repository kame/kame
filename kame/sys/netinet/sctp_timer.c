/*	$KAME: sctp_timer.c,v 1.11 2002/10/09 18:01:22 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_timer.c,v 1.60 2002/04/04 17:47:19 randall Exp	*/

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
#ifndef __OpenBSD__
#include <sys/domain.h>
#endif
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#ifdef INET6
#include <sys/domain.h>
#endif

#include <machine/limits.h>

#if defined(__FreeBSD__)
#include <vm/vm_zone.h>
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/pool.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#define _IP_VHL
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif /* INET6 */

#include "faith.h"

#include <netinet/sctp_pcb.h>

#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif /* IPSEC */

#include <netinet/sctp_timer.h>
#include <netinet/sctputil.h>
#include <netinet6/sctp6_var.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_hashdriver.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_indata.h>
#include <netinet/sctp_asconf.h>

#ifdef SCTP_DEBUG
extern u_int32_t sctp_debug_on;
#endif /* SCTP_DEBUG */


void
sctp_audit_retranmission_queue(struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
		printf("Audit invoked on send queue cnt:%d onqueue:%d\n",
		       asoc->sent_queue_retran_cnt,
		       asoc->sent_queue_cnt);
	}
#endif /* SCTP_DEBUG */
	asoc->sent_queue_retran_cnt = 0;
	asoc->sent_queue_cnt = 0;
	TAILQ_FOREACH(chk, &asoc->sent_queue, sctp_next) {
		if (chk->sent == SCTP_DATAGRAM_RESEND) {
			asoc->sent_queue_retran_cnt++;
		}
		asoc->sent_queue_cnt++;
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
		printf("Audit completes retran:%d onqueue:%d\n",
		       asoc->sent_queue_retran_cnt,
		       asoc->sent_queue_cnt);
	}
#endif /* SCTP_DEBUG */
}

int
sctp_threshold_management(struct sctp_inpcb *ep,
			  struct sctp_tcb *tcb,
			  struct sctp_nets *net,
			  u_short threshold)
{
	if (net) {
		net->error_count++;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
			printf("Error count for %x now %d thresh:%d\n",
			       (u_int)net,
			       net->error_count, net->failure_threshold);
		}
#endif /* SCTP_DEBUG */
		if (net->error_count > net->failure_threshold) {
			/* We had a threshold failure */
			if (net->dest_state & SCTP_ADDR_REACHABLE) {
				net->dest_state &= ~SCTP_ADDR_REACHABLE;
				net->dest_state |= SCTP_ADDR_NOT_REACHABLE;
				sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
						tcb,
						SCTP_FAILED_THRESHOLD,
						(void *)net);
			}
		}
#ifdef SCTP_ALTERNATE_ROUTE
		if (net->error_count > 1) {
			/* try to find a different route */
 		        struct rtentry *rt;
			if (net->ra.ro_rt) {
				rt = rtalloc_alternate((struct sockaddr *)&net->ra._l_addr,
						       net->ra.ro_rt, 0);
				if (rt != net->ra.ro_rt) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_TIMER2) {
						printf("Got a new route old:%x ifp:%x new:%x ifp:%x\n",
						       (u_int)net->ra.ro_rt,
						       (u_int)net->ra.ro_rt->rt_ifp,
						       (u_int)rt,
						       (u_int)rt->rt_ifp);
					}
#endif /* SCTP_DEBUG */
					RTFREE(net->ra.ro_rt);
					net->ra.ro_rt = rt;
				} else {
					RTFREE(rt);
				}
			}
		}
#endif
	}
	if (tcb == NULL)
		return (0);
	tcb->asoc.overall_error_count++;
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
		printf("Overall error count for %x now %d thresh:%d\n",
		       (u_int)&tcb->asoc,
		       (int)tcb->asoc.overall_error_count,
		       (int)threshold);
	}
#endif /* SCTP_DEBUG */

	if (tcb->asoc.overall_error_count > threshold) {
		/* Abort notification sends a ULP notify */
		sctp_abort_an_association(ep, tcb, SCTP_FAILED_THRESHOLD,
					  NULL);
		if (ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE) {
			/* Yes, so can we purge ourself now */
			if (LIST_FIRST(&ep->sctp_asoc_list) == NULL) {
				/* finish the job now */
				sctp_inpcb_free(ep,1);
			}
		}
		return (1);
	}
	return (0);
}

struct sctp_nets *
sctp_find_alternate_net(struct sctp_tcb *tcb,
			struct sctp_nets *net)
{
	/* Find and return an alternate network if possible */
	struct sctp_nets *alt, *mnet;
	int once;

	if (tcb->asoc.numnets == 1) {
		/* No others but net */
		return (TAILQ_FIRST(&tcb->asoc.nets));
	}
	mnet = net;
	once = 0;

	if (mnet == NULL) {
		mnet = TAILQ_FIRST(&tcb->asoc.nets);
	}
	do {
		alt = TAILQ_NEXT(mnet, sctp_next);
		if (alt == NULL) {
			once++;
			if (once > 1) {
				break;
			}
			alt = TAILQ_FIRST(&tcb->asoc.nets);
		}
		if (alt->ra.ro_rt == NULL) {
			alt->ra.ro_rt = rtalloc_alternate((struct sockaddr *)&alt->ra._l_addr,
							  NULL, 0);
		}
		if (((alt->dest_state & SCTP_ADDR_REACHABLE) ==
		     SCTP_ADDR_REACHABLE) && (alt->ra.ro_rt != NULL)) {
			/* Found a reachable address */
			break;
		}
		mnet = alt;
	} while (alt != NULL);

	if (alt == NULL) {
		/* Case where NO insv network exists (dormant state) */
		/* we rotate destinations */
		once = 0;
		mnet = net;
		do {
			alt = TAILQ_NEXT(mnet, sctp_next);
			if (alt == NULL) {
				once++;
				if (once > 1) {
					break;
				}
				alt = TAILQ_FIRST(&tcb->asoc.nets);
			}
			if (alt != net) {
				/* Found an alternate address */
				break;
			}
			mnet = alt;
		} while (alt != NULL);
	}
	if (alt == NULL) {
		return (net);
	}
	return (alt);
}

static void
sctp_backoff_on_timeout(struct sctp_inpcb *ep,
			struct sctp_nets *net,
			int win_probe)
{
	net->RTO <<= 1;
	if (net->RTO > ep->sctp_ep.sctp_maxrto) {
		net->RTO = ep->sctp_ep.sctp_maxrto;
	}
	if (win_probe == 0) {
		/* We don't apply penalty to window probe scenarios */
		net->ssthresh = net->cwnd >> 1;
		if (net->ssthresh < (net->mtu << 1)) {
			net->ssthresh = (net->mtu << 1);
		}
		net->cwnd = net->mtu;
		net->partial_bytes_acked = 0;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
			printf("collapse cwnd to 1MTU ssthresh to %d\n",
			       net->ssthresh);
		}
#endif /* SCTP_DEBUG */

	}
}

static int
sctp_mark_all_for_resend(struct sctp_tcb *tcb,
			 struct sctp_nets *net,
			 struct sctp_nets *alt)
{

	/*
	 * Mark all chunks that were sent to *net for retransmission.
	 * Move them to alt for there destination as well.
	 */
	struct sctp_tmit_chunk *chk;
	struct sctp_nets *lnets;
	int win_probes, non_win_probes, orig_rwnd, orig_flight, audit_tf;
	/* none in flight now */
	audit_tf = 0;
	tcb->asoc.total_flight -= net->flight_size;
	if (tcb->asoc.total_flight < 0) {
		audit_tf = 1;
		tcb->asoc.total_flight = 0;
	}
	orig_rwnd = tcb->asoc.peers_rwnd;
	orig_flight = net->flight_size;
	tcb->asoc.peers_rwnd += net->flight_size;
	net->flight_size = 0;
	net->rto_pending = 0;
	net->fast_retran_ip= 0;
	win_probes = non_win_probes = 0;
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER2) {
		printf("Marking ALL un-acked for retransmission at t3-timeout\n");
	}
#endif /* SCTP_DEBUG */
	/* Now on to each chunk */
	TAILQ_FOREACH(chk, &tcb->asoc.sent_queue, sctp_next) {
		if ((chk->whoTo == net) && (chk->sent < SCTP_DATAGRAM_ACKED)) {
			/* found one to mark */
			if (chk->sent != SCTP_DATAGRAM_RESEND)
				tcb->asoc.sent_queue_retran_cnt++;
			chk->sent = SCTP_DATAGRAM_RESEND;
			chk->rec.data.doing_fast_retransmit = 0;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER3) {
				printf("TSN:%x\n", chk->rec.data.TSN_seq);
			}
#endif /* SCTP_DEBUG */
			/* Clear any time so NO RTT is being done */
			chk->sent_rcv_time.tv_sec = 0;
			chk->sent_rcv_time.tv_usec = 0;
			/* Bump up the count */
			if (compare_with_wrap(chk->rec.data.TSN_seq,
					      tcb->asoc.t3timeout_highest_marked,
					      MAX_TSN)) {
				/* TSN_seq > than t3timeout so update */
				tcb->asoc.t3timeout_highest_marked = chk->rec.data.TSN_seq;
			}
			if (alt != net) {
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = alt;
				alt->ref_count++;
			}
			if ((chk->rec.data.state_flags & SCTP_WINDOW_PROBE) !=
			    SCTP_WINDOW_PROBE) {
				non_win_probes++;
			} else {
				chk->rec.data.state_flags = 0;
				win_probes++;
			}
		}
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_TIMER3) {
		printf("**************************\n");
	}
#endif /* SCTP_DEBUG */
	/* Now check for a ECN Echo that may be stranded */
	TAILQ_FOREACH(chk, &tcb->asoc.control_send_queue, sctp_next) {
		if ((chk->whoTo == net) &&
		    (chk->rec.chunk_id == SCTP_ECN_ECHO)) {
			sctp_free_remote_addr(chk->whoTo);
			chk->whoTo = alt;
			alt->ref_count++;
		}
	}
	if ((orig_rwnd == 0) && (tcb->asoc.total_flight == 0) &&
	    (orig_flight <= net->mtu)) {
		/*
		 * If the LAST packet sent was not acked and our rwnd is 0
		 * then we are in a win-probe state.
		 */
		win_probes = 1;
		non_win_probes = 0;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
			printf("WIN_PROBE set via o_rwnd=0 tf=0 and all:%d fit in mtu:%d\n",
			       orig_flight, net->mtu);
		}
#endif /* SCTP_DEBUG */
	}
	if (audit_tf) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
			printf("Audit total flight due to negative value net:%x\n",
			       (u_int)net);
		}
#endif /* SCTP_DEBUG */
		tcb->asoc.total_flight = 0;
		/* Clear all networks flight size */
		TAILQ_FOREACH(lnets, &tcb->asoc.nets, sctp_next) {
			lnets->flight_size = 0;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER4) {
				printf("Net:%x c-f cwnd:%d ssthresh:%d\n",
				       (u_int)lnets, lnets->cwnd,
				       lnets->ssthresh);
			}
#endif /* SCTP_DEBUG */
		}
		TAILQ_FOREACH(chk, &tcb->asoc.sent_queue, sctp_next) {
			if (chk->sent < SCTP_DATAGRAM_RESEND) {
				tcb->asoc.total_flight += chk->send_size;
				chk->whoTo->flight_size += chk->send_size;
			}
		}
	}
	/* We return 1 if we only have a window probe outstanding */
	if (win_probes && (non_win_probes == 0))
		return (1);

	return (0);
}

static void
sctp_move_all_chunks_to_alt(struct sctp_tcb *tcb,
			    struct sctp_nets *net,
			    struct sctp_nets *alt)
{
	struct sctp_association *asoc;
	struct sctp_stream_out *outs;
	struct sctp_tmit_chunk *chk;

	if (net == alt)
		/* nothing to do */
		return;

	asoc = &tcb->asoc;

	/*
	 * now through all the streams checking for chunks sent to our
	 * bad network.
	 */
	TAILQ_FOREACH(outs, &asoc->out_wheel, next_spoke) {
		/* now clean up any chunks here */
		TAILQ_FOREACH(chk, &outs->outqueue, sctp_next) {
			if (chk->whoTo == net) {
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = alt;
				alt->ref_count++;
			}
		}
	}
	/* Now check the pending queue */
	TAILQ_FOREACH(chk, &asoc->send_queue, sctp_next) {
		if (chk->whoTo == net) {
			sctp_free_remote_addr(chk->whoTo);
			chk->whoTo = alt;
			alt->ref_count++;
		}
	}

}

void
sctp_t3rxt_timer(struct sctp_inpcb *ep,
		 struct sctp_tcb *tcb,
		 struct sctp_nets *net)
{
	struct sctp_nets *alt;
	int win_probe;

	/* Find an alternate and mark those for retransmission */
	alt = sctp_find_alternate_net(tcb, net);
	win_probe = sctp_mark_all_for_resend(tcb, net, alt);

	/* Loss recovery just ended. */
	tcb->asoc.fast_retran_loss_recovery = 0;

	/* Backoff the timer and cwnd */
	sctp_backoff_on_timeout(ep, net, win_probe);
	if (win_probe == 0) {
		/* We don't do normal threshold management on window probes */
		if (sctp_threshold_management(ep, tcb, net,
					      tcb->asoc.max_send_times)) {
			/* Association was destroyed */
			return;
		}
	} else {
		/*
		 * For a window probe we don't penalize the net's but only
		 * the association. This may fail it if SACKs are not coming
		 * back. If sack's are coming with rwnd locked at 0, we will
		 * continue to hold things waiting for rwnd to raise
		 */
		if (sctp_threshold_management(ep, tcb, NULL,
					      tcb->asoc.max_send_times)) {
			/* Association was destroyed */
			return;
		}
	}
	if (net->dest_state & SCTP_ADDR_NOT_REACHABLE) {
		/* Move all pending over too */
		sctp_move_all_chunks_to_alt(tcb, net, alt);
		/* Was it our primary? */
		if ((tcb->asoc.primary_destination == net) && (alt != net)) {
			/*
			 * Yes, note it as such and find an alternate
			 * note: this means HB code must use this to resent
			 * the primary if it goes active AND if someone does
			 * a change-primary then this flag must be cleared
			 * from any net structures.
			 */
			net->dest_state |= SCTP_ADDR_WAS_PRIMARY;
			tcb->asoc.primary_destination = alt;
		}
	}
	/*
	 * Special case for cookie-echo'ed case, we don't do output
	 * but must await the COOKIE-ACK before retransmission
	 */
	if ((tcb->asoc.state&SCTP_STATE_MASK) == SCTP_STATE_COOKIE_ECHOED) {
		/*
		 * Here we just reset the timer and start again since we
		 * have not established the asoc
		 */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
			printf("Special cookie case return\n");
		}
#endif /* SCTP_DEBUG */
		sctp_timer_start(SCTP_TIMER_TYPE_SEND, ep, tcb, net);
		return;
	}
	if (tcb->asoc.peer_supports_usctp) {
		sctp_try_advance_peer_ack_point(tcb, &tcb->asoc);
		/* C3. See if we need to send a Fwd-TSN */
		if (compare_with_wrap(tcb->asoc.advanced_peer_ack_point,
				      tcb->asoc.last_acked_seq, MAX_TSN)) {
			/*
			 * ISSUE with ECN, see FWD-TSN processing for notes
			 * on issues that will occur when the ECN NONCE stuff
			 * is put into SCTP for cross checking.
			 */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
				printf("Forward TSN time\n");
			}
#endif /* SCTP_DEBUG */
			send_forward_tsn(tcb, &tcb->asoc);
		}
	}
}

void
sctp_t1init_timer(struct sctp_inpcb *ep,
		  struct sctp_tcb *tcb,
		  struct sctp_nets *net)
{
	/* bump the thresholds */
	if (sctp_threshold_management(ep, tcb, net,
				      tcb->asoc.max_init_times)) {
		/* Association was destroyed */
		return;
	}
	sctp_backoff_on_timeout(ep, tcb->asoc.primary_destination, 0);
	/* Send out a new init */
	sctp_send_initiate(ep, tcb);
}

/*
 * For cookie and asconf we actually need to find and mark for resend,
 * then increment the resend counter (after all the threshold management
 * stuff of course).
 */
void sctp_cookie_timer(struct sctp_inpcb *ep,
		       struct sctp_tcb *tcb,
		       struct sctp_nets *net)
{
	struct sctp_nets *alt;
	struct sctp_tmit_chunk *cookie;
	/* first before all else we must find the cookie */
	TAILQ_FOREACH(cookie, &tcb->asoc.control_send_queue, sctp_next) {
		if (cookie->rec.chunk_id == SCTP_COOKIE_ECHO) {
			break;
		}
	}
	if (cookie == NULL) {
		if ((tcb->asoc.state&SCTP_STATE_MASK) ==
		    SCTP_STATE_COOKIE_ECHOED) {
			/* FOOBAR! */
			sctp_abort_an_association(ep, tcb,
						  SCTP_INTERNAL_ERROR, NULL);
		}
		return;
	}
	/* Ok we found the cookie, threshold management next */
	if (sctp_threshold_management(ep, tcb, cookie->whoTo,
				      tcb->asoc.max_init_times)) {
		/* Assoc is over */
		return;
	}
	/*
	 * cleared theshold management now lets backoff the address &
	 * select an alternate
	 */
	sctp_backoff_on_timeout(ep, cookie->whoTo, 0);
	alt = sctp_find_alternate_net(tcb, cookie->whoTo);
	sctp_free_remote_addr(cookie->whoTo);
	cookie->whoTo = alt;
	alt->ref_count++;

	/* Now mark the retran info */
	if (cookie->sent != SCTP_DATAGRAM_RESEND)
		tcb->asoc.sent_queue_retran_cnt++;
	cookie->sent = SCTP_DATAGRAM_RESEND;
	/*
	 * Now call the output routine to kick out the cookie again, Note we
	 * don't mark any chunks for retran so that FR will need to kick in
	 * to move these (or a send timer).
	 */
}

void sctp_asconf_timer(struct sctp_inpcb *ep,
		       struct sctp_tcb *tcb,
		       struct sctp_nets *net)
{
	struct sctp_nets *alt;
	struct sctp_tmit_chunk *asconf,*chk;

	/* is this the first send, or a retransmission? */
	if (tcb->asoc.asconf_sent == 0) {
		/* compose a new ASCONF chunk and send it */
		sctp_send_asconf(tcb, net);
	} else {
		/* Retransmission of the existing ASCONF needed... */

		/* find the existing ASCONF */
		TAILQ_FOREACH(asconf, &tcb->asoc.control_send_queue,
			      sctp_next) {
			if (asconf->rec.chunk_id == SCTP_ASCONF) {
				break;
			}
		}
		if (asconf == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
				printf("Strange, asconf timer fires, but I can't find an asconf?\n");
			}
#endif /* SCTP_DEBUG */
			return;
		}
		/* do threshold management */
		if (sctp_threshold_management(ep, tcb, asconf->whoTo,
					      tcb->asoc.max_send_times)) {
			/* Assoc is over */
			return;
		}
		if (asconf->snd_count > tcb->asoc.max_send_times) {
			/*
			 * Something is rotten, peer is not responding to
			 * ASCONFs but maybe is to data etc.  e.g. it is not
			 * properly handling the chunk type upper bits
			 * Mark this peer as ASCONF incapable and cleanup
			 */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_TIMER1) {
				printf("asconf_timer: Peer has not responded to our repeated ASCONFs\n");
			}
#endif /* SCTP_DEBUG */
			sctp_asconf_cleanup(tcb, net);
			return;
		}
		/*
		 * cleared theshold management
		 * now lets backoff the address & select an alternate
		 */
		sctp_backoff_on_timeout(ep, asconf->whoTo, 0);
		alt = sctp_find_alternate_net(tcb, asconf->whoTo);
		sctp_free_remote_addr(asconf->whoTo);
		asconf->whoTo = alt;
		alt->ref_count++;

		/* See if a ECN Echo is also stranded */
		TAILQ_FOREACH(chk, &tcb->asoc.control_send_queue, sctp_next) {
			if ((chk->whoTo == net) &&
			    (chk->rec.chunk_id == SCTP_ECN_ECHO)) {
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = alt;
				alt->ref_count++;

			}
		}
		if (net->dest_state & SCTP_ADDR_NOT_REACHABLE) {
			/*
			 * If the address went un-reachable, we need to move
			 * to alternates for ALL chk's in queue
			 */
			sctp_move_all_chunks_to_alt(tcb, net, alt);
		}
		/* mark the retran info */
		if (asconf->sent != SCTP_DATAGRAM_RESEND)
			tcb->asoc.sent_queue_retran_cnt++;
		asconf->sent = SCTP_DATAGRAM_RESEND;
	}
}

/*
 * For the shutdown and shutdown-ack, we do not keep one around on the
 * control queue. This means we must generate a new one and call the general
 * chunk output routine, AFTER having done threshold
 * management.
 */
void
sctp_shutdown_timer(struct sctp_inpcb *ep,
		    struct sctp_tcb *tcb,
		    struct sctp_nets *net)
{
	struct sctp_nets *alt;
	/* first threshold managment */
	if (sctp_threshold_management(ep, tcb, net,
				      tcb->asoc.max_send_times)) {
		/* Assoc is over */
		return;
	}
	/* second select an alternative */
	alt = sctp_find_alternate_net(tcb, net);

	/* third generate a shutdown into the queue for out net */
	if (alt) {
		sctp_send_shutdown(tcb, alt);
	} else {
		return;
	}
	/* fourth restart timer */
	sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN, ep, tcb, alt);
}

void sctp_shutdownack_timer(struct sctp_inpcb *ep,
			    struct sctp_tcb *tcb,
			    struct sctp_nets *net)
{
	struct sctp_nets *alt;
	/* first threshold managment */
	if (sctp_threshold_management(ep, tcb, net,
				      tcb->asoc.max_send_times)) {
		/* Assoc is over */
		return;
	}
	/* second select an alternative */
	alt = sctp_find_alternate_net(tcb, net);

	/* third generate a shutdown into the queue for out net */
	sctp_send_shutdown_ack(tcb, alt);

	/* fourth restart timer */
	sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNACK, ep, tcb, alt);
}


void
sctp_heartbeat_timer(struct sctp_inpcb *ep,
		     struct sctp_tcb *tcb,
		     struct sctp_nets *net)
{
	if (net) {
		if (net->hb_responded == 0) {
			/* Set winprobe flags since we reduce cwnd here */
			sctp_backoff_on_timeout(ep, net, 1);
		}
		/* Zero PBA, if it needs it */
		if (net->partial_bytes_acked)
			net->partial_bytes_acked = 0;
	}
	/* Send a new HB, this will do threshold managment, pick a new dest */
	sctp_send_hb(tcb, 0, NULL);
}

#define SCTP_NUMBER_OF_MTU_SIZES 18
static int mtu_sizes[]={
	68,
	296,
	508,
	512,
	544,
	576,
	1006,
	1492,
	1500,
	1536,
	2002,
	2048,
	4352,
	4464,
	8166,
	17914,
	32000,
	65535
};


static u_int32_t
sctp_getnext_mtu(struct sctp_inpcb *ep, u_int32_t cur_mtu)
{
	/* select another MTU that is just bigger than this one */
	int i;

	if (cur_mtu >= ep->sctp_ep.max_mtu) {
		/* never get bigger than the max of all our interface MTU's */
		return (ep->sctp_ep.max_mtu);
	}
	for (i = 0; i < SCTP_NUMBER_OF_MTU_SIZES; i++) {
		if (cur_mtu < mtu_sizes[i]) {
			if (ep->sctp_ep.max_mtu < mtu_sizes[i]) {
				/* is max_mtu smaller? if so return it */
				return (ep->sctp_ep.max_mtu);
			} else {
				/* no max_mtu is bigger than this one */
				return (mtu_sizes[i]);
			}
		}
	}
	/* here return the highest allowable */
	return (ep->sctp_ep.max_mtu);
}


void sctp_pathmtu_timer(struct sctp_inpcb *ep,
			struct sctp_tcb *tcb,
			struct sctp_nets *pnet)
{
	u_int32_t next_mtu;
	struct sctp_nets *net;
	struct sctp_association *asoc;

	asoc = &tcb->asoc;
	/* restart the timer in any case */
	if (asoc->smallest_mtu >= SCTP_DEFAULT_MAXSEGMENT)
		/* nothing to do */
		return;

	next_mtu = sctp_getnext_mtu(ep, asoc->smallest_mtu);
	/* fix the smallest one up */
	if (next_mtu <= asoc->smallest_mtu) {
		/* nothing to do now */
		return;
	}
	asoc->smallest_mtu = next_mtu;
	/* now adjust all networks to be at min this value */
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		if (net->mtu < next_mtu) {
			net->mtu = next_mtu;
		}
	}
	/* restart the timer */
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, ep, tcb, pnet);
}

void sctp_autoclose_timer(struct sctp_inpcb *ep,
			  struct sctp_tcb *tcb,
			  struct sctp_nets *net)
{
	struct timeval tn,*tim_touse;
	struct sctp_association *asoc;
	int ticks_gone_by;

	SCTP_GETTIME_TIMEVAL(&tn);
	if (tcb->asoc.sctp_autoclose_ticks &&
	    (ep->sctp_flags & SCTP_PCB_FLAGS_AUTOCLOSE)) {
		/* Auto close is on */
		asoc = &tcb->asoc;
		/* pick the time to use */
		if (asoc->time_last_rcvd.tv_sec >
		    asoc->time_last_sent.tv_sec) {
			tim_touse = &asoc->time_last_rcvd;
		} else {
			tim_touse = &asoc->time_last_sent;
		}
		/* Now has long enough transpired to autoclose? */
		ticks_gone_by = ((tn.tv_sec - tim_touse->tv_sec) * hz);
		if ((ticks_gone_by > 0) &&
		    (ticks_gone_by >= asoc->sctp_autoclose_ticks)) {
			/*
			 * autoclose time has hit, call the output routine,
			 * which should do nothing just to be SURE we don't
			 * have hanging data. We can then safely check the
			 * queues and know that we are clear to send shutdown
			 */
			sctp_chunk_output(ep, tcb, 9);
			/* Are we clean? */
			if (TAILQ_EMPTY(&asoc->send_queue) &&
			    TAILQ_EMPTY(&asoc->sent_queue)) {
				/*
				 * there is nothing queued to send,
				 * so I'm done...
				 */
				if ((asoc->state & SCTP_STATE_MASK) !=
				    SCTP_STATE_SHUTDOWN_SENT) {
					/* only send SHUTDOWN 1st time thru */
					sctp_send_shutdown(tcb, tcb->asoc.primary_destination);
					asoc->state = SCTP_STATE_SHUTDOWN_SENT;
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN,
							 tcb->sctp_ep, tcb,
							 asoc->primary_destination);
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD,
							 tcb->sctp_ep, tcb,
							 asoc->primary_destination);
				}
			} else {
				asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
			}
		} else {
			/*
			 * No auto close at this time, reset t-o to
			 * check later
			 */
			int tmp;
			/* fool the timer startup to use the time left */
			tmp = asoc->sctp_autoclose_ticks;
			asoc->sctp_autoclose_ticks -= ticks_gone_by;
			sctp_timer_start(SCTP_TIMER_TYPE_AUTOCLOSE, ep, tcb,
					 net);
			/* restore the real tick value */
			asoc->sctp_autoclose_ticks = tmp;
		}
	}
}
