/*	$KAME: sctp_indata.c,v 1.13 2003/01/21 06:33:03 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_indata.c,v 1.124 2002/04/04 18:48:39 randall Exp	*/

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
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <machine/limits.h>
#include <machine/cpu.h>

#if defined(__FreeBSD__)
#include <vm/vm_zone.h>
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/pool.h>
#endif


#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#ifdef INET6
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
#include <netinet/sctp_uio.h>
#include <netinet/sctp_timer.h>
#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif /*IPSEC*/

#ifdef SCTP_DEBUG
extern u_int32_t sctp_debug_on;
#endif


/* NOTES: On the outbound side of things
 * I need to check the sack timer to see
 * if I should generate a sack into the chunk
 * queue (if I have data to send that is  and
 * will be sending it .. for bundling.
 *
 * The callback in sctp_usrreq.c will get called
 * when the socket is read from. This will cause
 * sctp_service_queues() to get called on the
 * top entry in the list.
 *
 */
extern struct sctp_epinfo sctppcbinfo;

void
sctp_set_rwnd(struct sctp_tcb *stcb,
	      struct sctp_association *asoc)
{
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INDATA4) {
		printf("cc:%d hiwat:%d lowat:%d mbcnt:%d mbmax:%d\n",
		       (int)stcb->sctp_socket->so_rcv.sb_cc,
		       (int)stcb->sctp_socket->so_rcv.sb_hiwat,
		       (int)stcb->sctp_socket->so_rcv.sb_lowat,
		       (int)stcb->sctp_socket->so_rcv.sb_mbcnt,
		       (int)stcb->sctp_socket->so_rcv.sb_mbmax);
		printf("Setting rwnd to: sb:%d - (del:%d + reasm:%d str:%d)\n",
		       (int)sctp_sbspace(&stcb->sctp_socket->so_rcv),
		       asoc->size_on_delivery_queue,
		       asoc->size_on_reasm_queue,
		       asoc->size_on_all_streams);
	}
#endif
	asoc->my_rwnd = sctp_sbspace(&stcb->sctp_socket->so_rcv) -
		(asoc->size_on_delivery_queue +
		 asoc->size_on_reasm_queue +
		 asoc->size_on_all_streams);
	if (asoc->my_rwnd < 0)
		asoc->my_rwnd = 0;
	/* SWS threshold */
	if (asoc->my_rwnd &&
	   (asoc->my_rwnd < stcb->sctp_ep->sctp_ep.sctp_sws_receiver)) {
		/* SWS engaged, tell peer none left */
		asoc->my_rwnd = 1;
#ifdef SCTP_DBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA4) {
			printf(" - SWS zeros\n");
		}
	} else {
		if (sctp_debug_on & SCTP_DEBUG_INDATA4) {
			printf("\n");
		}
#endif
	}
}

static
struct mbuf *
sctp_build_ctl(struct sctp_tcb *stcb,
	       struct sctp_tmit_chunk *chk)
{
	/* Take a chk structure and build it into
	 * an mbuf. Hmm should we change things
	 * so that instead we store the data side
	 * in a chunk?
	 */
	struct sctp_sndrcvinfo *outinfo;
	struct cmsghdr *cmh;
	struct mbuf *ret;
	MGET(ret, M_DONTWAIT, MT_CONTROL);
	if (ret == NULL)
		/* No space */
		return (ret);

	/* We need a CMSG header followed by the struct  */
	cmh = mtod(ret, struct cmsghdr *);
	outinfo = (struct sctp_sndrcvinfo *)((caddr_t)cmh + CMSG_ALIGN(sizeof(struct cmsghdr)));
	cmh->cmsg_level = IPPROTO_SCTP;
	cmh->cmsg_type = SCTP_SNDRCV;
	cmh->cmsg_len = (sizeof(struct sctp_sndrcvinfo) +
			 CMSG_ALIGN(sizeof(struct cmsghdr)));
	outinfo->sinfo_stream = chk->rec.data.stream_number;
	outinfo->sinfo_ssn = chk->rec.data.stream_seq;
	if (chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED) {
		outinfo->sinfo_flags = MSG_UNORDERED;
	} else {
		outinfo->sinfo_flags = 0;
	}
	outinfo->sinfo_ppid = chk->rec.data.payloadtype;
	outinfo->sinfo_context = chk->rec.data.context;
	outinfo->sinfo_assoc_id = (caddr_t)stcb;
	outinfo->sinfo_tsn = chk->rec.data.TSN_seq;
	outinfo->sinfo_cumtsn = stcb->asoc.cumulative_tsn;
	ret->m_len = cmh->cmsg_len;
	return (ret);
}

#ifndef __FreeBSD__
/* Don't know why but without this I get an unknown
 * reference when compiling NetBSD... hmm
 */
extern void in6_sin_2_v4mapsin6 (struct sockaddr_in *sin,
				 struct sockaddr_in6 *sin6);
#endif

int
sctp_deliver_data(struct sctp_tcb *stcb,
		  struct sctp_association *asoc,
		  struct sctp_tmit_chunk *chk);


int
sctp_deliver_data(struct sctp_tcb *stcb,
		  struct sctp_association *asoc,
		  struct sctp_tmit_chunk *chk)
{
	struct mbuf *control, *m;
	int free_it;
	struct sockaddr_in6 sin6;
	struct sockaddr *to;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
		printf("I am now in Deliver data! (%x)\n",
		       (u_int)chk);
	}
#endif
	free_it = 0;
	/* We always add it to the queue */
	if (stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
		/* socket above is long gone */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("gone is gone!\n");
		}
#endif
		if (chk != NULL) {
			if (chk->data)
				m_freem(chk->data);
			chk->data = NULL;
			sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif

			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
		}
		TAILQ_FOREACH(chk, &asoc->delivery_queue, sctp_next) {
			asoc->size_on_delivery_queue -= chk->send_size;
			asoc->cnt_on_delivery_queue--;
			/* Lose the data pointer, since its in the socket buffer */
			if (chk->data)
				m_freem(chk->data);
			chk->data = NULL;
			/* Now free the address and data */
			sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif

			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
		}
		return (0);
	}
	if (chk != NULL) {
		TAILQ_INSERT_TAIL(&asoc->delivery_queue, chk, sctp_next);
		asoc->size_on_delivery_queue += chk->send_size;
		asoc->cnt_on_delivery_queue++;
	}
	if (asoc->fragmented_delivery_inprogress) {
		/* oh oh, fragmented delivery in progress
		 * return out of here.
		 */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Fragmented delivery in progress?\n");
		}
#endif
		return (0);
	}
	/* Now grab the first one  */
	chk = TAILQ_FIRST(&asoc->delivery_queue);
	if (chk == NULL) {
		/* Nothing in queue */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Nothing in queue?\n");
		}
#endif
		asoc->size_on_delivery_queue = 0;
		asoc->cnt_on_delivery_queue = 0;
		return (0);
	}

	if ((!stcb->on_toqueue) &&
	   (stcb->sctp_socket->so_rcv.sb_cc >=
	    (stcb->sctp_ep->sctp_ep.sctp_sws_receiver >> 1))) {
		/* no room for anything. */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Ok onto the usr_rcv queue\n");
		}
#endif
		TAILQ_INSERT_TAIL(&stcb->sctp_ep->sctp_queue_list, stcb, sctp_toqueue);
		stcb->on_toqueue = 1;
	}
	if (stcb->sctp_socket->so_rcv.sb_cc >= stcb->sctp_socket->so_rcv.sb_hiwat) {
		/* Boy, there really is NO room */
		return (0);
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
		printf("Now to the delivery with chk(%x)!\n",
		       (u_int)chk);
	}
#endif
	/* XXX need to append PKTHDR to the socket buffer first */
	if ((chk->data->m_flags & M_PKTHDR) == 0) {
		if ((chk->data->m_flags & M_EXT) == 0) {
			MGETHDR(m, M_DONTWAIT, MT_DATA);
			if (m == NULL) {
				/* no room! */
				return (0);
			}
			m->m_pkthdr.len = chk->send_size;
			m->m_len = 0;
			m->m_next = chk->data;
			chk->data = m;
		} else {
			/* With a M_EXT the data portion of
			 * the mbuf is unused so we can easily pilfer it
			 * for a PKTHDR. We expect most of the time the
			 * recv intf will get a M_EXT so this code
			 * should be the predominat executor.
			 */
			chk->data->m_flags |= M_PKTHDR;
			chk->data->m_pkthdr.rcvif = 0;
			chk->data->m_pkthdr.len = chk->send_size;
#ifdef __FreeBSD__
			chk->data->m_pkthdr.header = 0;
			chk->data->m_pkthdr.csum_flags = 0;
			chk->data->m_pkthdr.csum_data = 0;
#endif
			SLIST_INIT(&chk->data->m_pkthdr.tags);
		}
	}
	if (chk->rec.data.rcv_flags & SCTP_DATA_LAST_FRAG) {
		if (chk->data->m_next == NULL) {
			/* hopefully we hit here most of the time */
			chk->data->m_flags |= M_EOR;
		} else {
			/* Add the flag to the LAST mbuf in the chain */
			m = chk->data;
			while (m->m_next != NULL) {
				m = m->m_next;
			}
			m->m_flags |= M_EOR;
		}
	}

	if (chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) {
		struct sockaddr_in6 lsa6;

		control = sctp_build_ctl(stcb, chk);
		if (control == NULL) {
			/* No room to even get a mbuf to
			 * hold the control. We will just
			 * queue this chunk for later consumption.
			 */
			return (0);
		}
		to = (struct sockaddr *)&chk->whoTo->ra._l_addr;
		if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4) &&
		   (to->sa_family == AF_INET)) {
			in6_sin_2_v4mapsin6((struct sockaddr_in *)to, &sin6);
			to = (struct sockaddr *)&sin6;
		}
		/* check and strip embedded scope junk */
		to = (struct sockaddr *)sctp_recover_scope((struct sockaddr_in6 *)to,
							   &lsa6);

		if (sctp_sbspace(&stcb->sctp_socket->so_rcv) < chk->send_size) {
			/* Gak not enough room */
			if (control) {
				m_freem(control);
			}
			goto skip;
		}
		if (stcb->sctp_ep->sctp_vtag_last == 0) {
			stcb->sctp_ep->sctp_vtag_last = stcb->asoc.my_vtag;
		}

		if (!sbappendaddr_nocheck(&stcb->sctp_socket->so_rcv,
					  to, chk->data, 
					  control, stcb->asoc.my_vtag)) {
			/* Gak not enough room */
			if (control) {
				m_freem(control);
			}
		} else {
			free_it = 1;
		}
	} else {
		/* append to a already started message. */
		if (sctp_sbspace(&stcb->sctp_socket->so_rcv) >= chk->send_size) {
			sbappend(&stcb->sctp_socket->so_rcv, chk->data);
			free_it = 1;
		}
	}
 skip:
	/* free up the one we inserted */
	if (free_it) {
		/* Pull it off the queue */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
		printf("Free_it true, doing tickle wakeup\n");
	}
#endif
		sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
		TAILQ_REMOVE(&asoc->delivery_queue, chk, sctp_next);
		asoc->size_on_delivery_queue -= chk->send_size;
		asoc->cnt_on_delivery_queue--;
		/* Lose the data pointer, since its in the socket buffer */
		chk->data = NULL;
		/* Now free the address and data */
		sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif

		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
	}
	return (free_it);
}




static void
sctp_service_reassembly(struct sctp_tcb *stcb,
			struct sctp_association *asoc)
{
	/* We are delivering currently from the
	 * reassembly queue. We must continue to
	 * deliver until we either:
	 * 1) run out of space.
	 * 2) run out of sequential TSN's
	 * 3) hit the SCTP_DATA_LAST_FRAG flag.
	 */
	struct sockaddr *to;
	struct sockaddr_in6 sin6;
	struct sctp_tmit_chunk *chk, *at;
	struct mbuf *control, *m;
	u_int16_t nxt_todel;
	u_int16_t stream_no;
	int cntDel;
	cntDel = stream_no = 0;

	if (stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
		/* socket above is long gone */
		asoc->fragmented_delivery_inprogress = 0;
		TAILQ_FOREACH(chk, &asoc->reasmqueue, sctp_next) {
			asoc->size_on_delivery_queue -= chk->send_size;
			asoc->cnt_on_delivery_queue--;
			/* Lose the data pointer, since its in the socket buffer */
			if (chk->data)
				m_freem(chk->data);
			chk->data = NULL;
			/* Now free the address and data */
			sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif

			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
		}
		return;
	}
	do{
		if ((!stcb->on_toqueue) &&
		   (stcb->sctp_socket->so_rcv.sb_cc >=
		    (stcb->sctp_ep->sctp_ep.sctp_sws_receiver >> 1))) {
			TAILQ_INSERT_TAIL(&stcb->sctp_ep->sctp_queue_list, stcb, sctp_toqueue);
			stcb->on_toqueue = 1;
		}
		if (stcb->sctp_socket->so_rcv.sb_cc >= stcb->sctp_socket->so_rcv.sb_hiwat) {
			/* no room */
			if (cntDel) {
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			}
			return;
		}
		chk = TAILQ_FIRST(&asoc->reasmqueue);
		if (chk == NULL) {
			if (cntDel) {
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			}
			return;
		}
		if (chk->rec.data.TSN_seq != (asoc->tsn_last_delivered + 1)) {
			/* Can't deliver more :< */
			if (cntDel) {
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			}
			return;
		}
		stream_no = chk->rec.data.stream_number;
		nxt_todel = asoc->strmin[stream_no].last_sequence_delivered + 1;
		if ((nxt_todel != chk->rec.data.stream_seq) &&
		   ((chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED) == 0)) {
			/* Not the next sequence to deliver in its stream OR unordered*/
			if (cntDel) {
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			}
			return;
		}

		if ((chk->data->m_flags & M_PKTHDR) == 0) {
			if ((chk->data->m_flags & M_EXT) == 0) {
				MGETHDR(m, M_DONTWAIT, MT_DATA);
				if (m == NULL) {
					/* no room! */
					return;
				}
				m->m_pkthdr.len = chk->send_size;
				m->m_len = 0;
				m->m_next = chk->data;
				chk->data = m;
			} else {
				/* With a M_EXT the data portion of
				 * the mbuf is unused so we can easily pilfer it
				 * for a PKTHDR. We expect most of the time the
				 * recv intf will get a M_EXT so this code
				 * should be the predominat executor.
				 */
				chk->data->m_flags |= M_PKTHDR;
				chk->data->m_pkthdr.rcvif = 0;
				chk->data->m_pkthdr.len = chk->send_size;
#ifdef __FreeBSD__
				chk->data->m_pkthdr.header = 0;
				chk->data->m_pkthdr.csum_flags = 0;
				chk->data->m_pkthdr.csum_data = 0;
#endif
				SLIST_INIT(&chk->data->m_pkthdr.tags);
			}
		}
		if (chk->rec.data.rcv_flags & SCTP_DATA_LAST_FRAG) {
			if (chk->data->m_next == NULL) {
				/* hopefully we hit here most of the time */
				chk->data->m_flags |= M_EOR;
			} else {
				/* Add the flag to the LAST mbuf in the chain */
				m = chk->data;
				while (m->m_next != NULL) {
					m = m->m_next;
				}
				m->m_flags |= M_EOR;
			}
		}
		if (chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) {
			struct sockaddr_in6 lsa6;

			control = sctp_build_ctl(stcb, chk);
			if (control == NULL) {
				/* No room to even get a mbuf to hold the control.
				 * We will just leave this chunk on queue for later
				 * consumption.
				 */
				if (cntDel) {
					sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
				}
				return;
			}
			to = (struct sockaddr *)&chk->whoTo->ra._l_addr;
			if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_NEEDS_MAPPED_V4) &&
			   (to->sa_family == AF_INET)) {
				in6_sin_2_v4mapsin6((struct sockaddr_in *)to, &sin6);
				to = (struct sockaddr *)&sin6;
			}
			/* check and strip embedded scope junk */
			to = (struct sockaddr *)sctp_recover_scope((struct sockaddr_in6 *)to,
								   &lsa6);
			if (sctp_sbspace(&stcb->sctp_socket->so_rcv) < chk->send_size) {
				if (control) {
					m_freem(control);
				}
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
				return;
			}
			if (stcb->sctp_ep->sctp_vtag_last == 0) {
				stcb->sctp_ep->sctp_vtag_last = stcb->asoc.my_vtag;
			}
			if (!sbappendaddr_nocheck(&stcb->sctp_socket->so_rcv,
						  to, chk->data, 
						  control, stcb->asoc.my_vtag )) {
				/* Gak not enough room */
				if (control) {
					m_freem(control);
				}
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
				return;
			}
			cntDel++;
		} else {
			if (sctp_sbspace(&stcb->sctp_socket->so_rcv) >= chk->send_size) {
				sbappend(&stcb->sctp_socket->so_rcv, chk->data);
				cntDel++;
			} else {
				/* out of space in the sb */
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
				return;
			}
		}
		/* pull it we did it */
		TAILQ_REMOVE(&asoc->reasmqueue, chk, sctp_next);
		if (chk->rec.data.rcv_flags & SCTP_DATA_LAST_FRAG) {
			asoc->fragmented_delivery_inprogress = 0;
			if ((chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED) == 0) {
			  asoc->strmin[stream_no].last_sequence_delivered++;
			}
		}
		asoc->tsn_last_delivered = chk->rec.data.TSN_seq;
		asoc->size_on_reasm_queue -= chk->send_size;
		asoc->cnt_on_reasm_queue--;
		/* free up the chk */
		sctp_free_remote_addr(chk->whoTo);
		chk->data = NULL;
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		if (asoc->fragmented_delivery_inprogress == 0) {
			/* Now lets see if we can deliver the next one on the stream */
			u_int16_t nxt_todel;
			struct sctp_stream_in *strm;

			strm = &asoc->strmin[stream_no];
			nxt_todel = strm->last_sequence_delivered + 1;
			chk = TAILQ_FIRST(&strm->inqueue);
			if ((chk) &&
			   (nxt_todel == chk->rec.data.stream_seq)) {
				while (chk != NULL) {
					/* all delivered */
					if (nxt_todel == chk->rec.data.stream_seq) {
						at = TAILQ_NEXT(chk, sctp_next);
						TAILQ_REMOVE(&strm->inqueue, chk, sctp_next);
						asoc->size_on_all_streams -= chk->send_size;
						asoc->cnt_on_all_streams--;
						strm->last_sequence_delivered++;
						/* We ignore the return of deliver_data here
						 * since we always can hold the chunk on the
						 * d-queue. And we have a finite number that
						 * can be delivered from the strq.
						 */
						sctp_deliver_data(stcb, asoc, chk);
						chk = at;
					} else {
						break;
					}
					nxt_todel = strm->last_sequence_delivered + 1;
				}
			}
			if (!TAILQ_EMPTY(&asoc->delivery_queue)) {
				/* Here if deliver_data fails, we must break */
				if (sctp_deliver_data(stcb, asoc, NULL) == 0)
					break;
			}
			sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			return;
		}
		chk = TAILQ_FIRST(&asoc->reasmqueue);
	} while (chk);
	if (cntDel) {
		sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
	}
}



static void
sctp_queue_data_to_stream(struct sctp_tcb *stcb,
			  struct sctp_association *asoc,
			  struct sctp_tmit_chunk *chk,
			  int *abort_flag)
{
	/* Queue the chunk either right into the socket
	 * buffer if it is the next one to go OR put it
	 * in the correct place in the delivery queue.
	 * If we do append to the so_buf, keep doing so
	 * until we are out of order.
	 * One big question still remains, what do I do
	 * when the socket buffer is FULL??
	 */
	struct sctp_stream_in *strm;
	struct sctp_tmit_chunk *at;
	int queue_needed;
	u_int16_t nxt_todel;

/*** FIX FIX FIX
 * Need to add code to deal with 16 bit seq wrap
 * without a TSN wrap for ordered delivery.
 * FIX FIX FIX
 */
	queue_needed = 1;
	asoc->size_on_all_streams += chk->send_size;
	asoc->cnt_on_all_streams++;
	strm = &asoc->strmin[chk->rec.data.stream_number];
	nxt_todel = strm->last_sequence_delivered + 1;
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
		printf("queue to stream called for ssn:%d lastdel:%d nxt:%d\n",
		       (int)chk->rec.data.stream_seq,
		       (int)strm->last_sequence_delivered,
		       (int)nxt_todel);
	}
#endif
	if (compare_with_wrap(strm->last_sequence_delivered,
			     chk->rec.data.stream_seq, MAX_SEQ) ||
	   (strm->last_sequence_delivered == chk->rec.data.stream_seq)) {
		/* The incoming sseq is behind where we last delivered? */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Duplicate S-SEQ:%d delivered:%d from peer, Abort  association\n",
			       chk->rec.data.stream_seq,
			       strm->last_sequence_delivered);
		}
#endif
		/* throw it in the stream so it gets cleaned up in
		 * association destruction
		 */
		TAILQ_INSERT_HEAD(&strm->inqueue, chk, sctp_next);
		sctp_abort_an_association(stcb->sctp_ep,
					  stcb, SCTP_PEER_FAULTY,(struct mbuf *)NULL);

		*abort_flag = 1;
		return;

	}
	if (nxt_todel == chk->rec.data.stream_seq) {
		/* can be delivered right away */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("It's NEXT!\n");
		}
#endif
		queue_needed = 0;
		asoc->size_on_all_streams -= chk->send_size;
		asoc->cnt_on_all_streams--;
		strm->last_sequence_delivered++;
		sctp_deliver_data(stcb, asoc, chk);
		chk = TAILQ_FIRST(&strm->inqueue);
		while (chk != NULL) {
			/* all delivered */
			nxt_todel = strm->last_sequence_delivered + 1;
			if (nxt_todel == chk->rec.data.stream_seq) {
				at = TAILQ_NEXT(chk, sctp_next);
				TAILQ_REMOVE(&strm->inqueue, chk, sctp_next);
				asoc->size_on_all_streams -= chk->send_size;
				asoc->cnt_on_all_streams--;
				strm->last_sequence_delivered++;
				/* We ignore the return of deliver_data here
				 * since we always can hold the chunk on the
				 * d-queue. And we have a finite number that
				 * can be delivered from the strq.
				 */
				sctp_deliver_data(stcb, asoc, chk);
				chk = at;
				continue;
			}
			break;
		}
#ifdef SCTP_OLD_USCTP_COMPAT
		if (asoc->peer_supports_usctp &&
		   (TAILQ_EMPTY(&strm->inqueue)) &&
		   ((strm->next_spoke.tqe_next != NULL) ||
		    (strm->next_spoke.tqe_prev != NULL))
			) {
			TAILQ_REMOVE(&asoc->unrel_wheel, strm, next_spoke);
			strm->next_spoke.tqe_next = NULL;
			strm->next_spoke.tqe_prev = NULL;
		}
#endif
	}
	if (queue_needed) {
		/* Ok, we did not deliver this guy, find
		 * the correct place to put it on the queue.
		 */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Queue Needed!\n");
		}
#endif
		if (TAILQ_EMPTY(&strm->inqueue)) {
			/* Empty queue */
			TAILQ_INSERT_HEAD(&strm->inqueue, chk, sctp_next);
		} else {
			TAILQ_FOREACH(at, &strm->inqueue, sctp_next) {
				if (compare_with_wrap(at->rec.data.stream_seq, chk->rec.data.stream_seq, MAX_SEQ)) {
					/* one in queue is bigger than the new one, insert before this one */
					TAILQ_INSERT_BEFORE(at, chk, sctp_next);
					break;
				} else if (at->rec.data.stream_seq == chk->rec.data.stream_seq) {
					/* Gak, He sent me a duplicate str seq number */
					/* foo bar, I guess I will just free this new guy, should we
					 * abort too? FIX ME MAYBE? Or it COULD be that
					 * the SSN's have wrapped. Maybe I should compare to
					 * TSN somehow... sigh for now just blow away the chunk!
					 */
					if (chk->data)
						m_freem(chk->data);
					chk->data = NULL;
					sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
					zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
					pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
					sctppcbinfo.ipi_count_chunk--;
					if ((int)sctppcbinfo.ipi_count_chunk < 0) {
						panic("Chunk count is negative");
					}
					sctppcbinfo.ipi_gencnt_chunk++;
					return;
				} else {
					if (TAILQ_NEXT(at, sctp_next) == NULL) {
						/* We are at the end, insert it after this one */
						TAILQ_INSERT_AFTER(&strm->inqueue, at, chk, sctp_next);
						break;
					}
				}
			}
		}
#ifdef SCTP_OLD_USCTP_COMPAT
		if (asoc->peer_supports_usctp &&
		   (strm->next_spoke.tqe_next == NULL) &&
		   (strm->next_spoke.tqe_prev == NULL)) {
			/* Insert the pr-stream on the wheel of unrel streams with
			 * pending data
			 */
			TAILQ_INSERT_HEAD(&asoc->unrel_wheel, strm, next_spoke);
		}
#endif
	} else {
		/* We delivered some chunks, wake them up */

#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Doing WAKEUP!\n");
		}
#endif
		sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
	}
}



static int
sctp_is_all_msg_on_reasm(struct sctp_association *asoc,
			 int *t_size)

{
	/* Returns two things. You get the
	 * total size of the deliverable parts of the
	 * first fragmented message on the reassembly queue.
	 * And you get a 1 back if all of the message is ready
	 * or a 0 back if the message is still incomplete
	 */
	struct sctp_tmit_chunk *chk;
	u_int32_t tsn;
	*t_size = 0;
	chk = TAILQ_FIRST(&asoc->reasmqueue);
	if (chk == NULL) {
		/* nothing on the queue */
		return (0);
	}
	if ((chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) == 0) {
		/* Not a first on the queue */
		return (0);
	}
	tsn = chk->rec.data.TSN_seq;
	while (chk) {
		if (tsn != chk->rec.data.TSN_seq) {
			return (0);
		}
		*t_size += chk->send_size;
		if (chk->rec.data.rcv_flags & SCTP_DATA_LAST_FRAG) {
			return (1);
		}
		tsn++;
		chk = TAILQ_NEXT(chk, sctp_next);
	}
	return (0);
}



static void
sctp_queue_data_for_reasm(struct sctp_tcb *stcb,
			  struct sctp_association *asoc,
			  struct sctp_tmit_chunk *chk,
			  int *abort_flag)
{
	/* Dump onto the re-assembly queue, in its
	 * proper place. After dumping on the queue,
	 * see if anthing can be delivered. If so
	 * pull it off (or as much as we can. If we
	 * run out of space then we must dump what we
	 * can and set the appropriate flag to say
	 * we queued what we could.
	 */
	u_int16_t nxt_todel;
	u_int32_t cum_ackp1, last_tsn, prev_tsn, post_tsn;
	int tsize;
	u_char last_flags;
	struct sctp_tmit_chunk *at, *prev, *next;


	prev = next = NULL;
	cum_ackp1 = asoc->tsn_last_delivered + 1;

	if (TAILQ_EMPTY(&asoc->reasmqueue)) {
		/* This is the first one on the queue */
		TAILQ_INSERT_HEAD(&asoc->reasmqueue, chk, sctp_next);
		/* we do not check for delivery of anything when
		 * only one fragment is here */
		asoc->size_on_reasm_queue = chk->send_size;
		asoc->cnt_on_reasm_queue++;
		if (chk->rec.data.TSN_seq == cum_ackp1) {
			if ((asoc->fragmented_delivery_inprogress == 0)  &&
			   ((chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) != SCTP_DATA_FIRST_FRAG)) {
				/* An empty queue, no delivery inprogress, we hit the next one
				 * and it does NOT have a FIRST fragment mark.
				 */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
					printf("Gak, Evil plot, its not first, no fragmented delivery in progress\n");
				}
#endif
				sctp_abort_an_association(stcb->sctp_ep,
							  stcb, SCTP_PEER_FAULTY,(struct mbuf *)NULL);
				*abort_flag = 1;
			} else if ((asoc->fragmented_delivery_inprogress) &&
				 ((chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) == SCTP_DATA_FIRST_FRAG)) {
				/* We are doing a partial delivery and the NEXT chunk MUST be either
				 * the LAST or MIDDLE fragment NOT a FIRST
				 */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
					printf("Gak, Evil plot, it IS a first and fragmented delivery in progress\n");
				}
#endif
				sctp_abort_an_association(stcb->sctp_ep,
							  stcb, SCTP_PEER_FAULTY,(struct mbuf *)NULL);
				*abort_flag = 1;
			} else if (asoc->fragmented_delivery_inprogress) {
				/* Here we are ok with a MIDDLE or LAST piece */
				if (chk->rec.data.stream_number != asoc->str_of_pdapi) {
					/* Got to be the right STR No */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Gak, Evil plot, it IS not same stream number %d vs %d\n",
						       chk->rec.data.stream_number, asoc->str_of_pdapi);
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,(struct mbuf *)NULL);
					*abort_flag = 1;
				} else if (((asoc->fragment_flags & SCTP_DATA_UNORDERED) !=  SCTP_DATA_UNORDERED) &&
					 (chk->rec.data.stream_seq != asoc->ssn_of_pdapi)) {
					/* Got to be the right STR Seq */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Gak, Evil plot, it IS not same stream seq %d vs %d\n",
						       chk->rec.data.stream_seq, asoc->ssn_of_pdapi);
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,(struct mbuf *)NULL);
					*abort_flag = 1;
				}
			}
		}
		return;
	}
	/* Find its place */
	at = TAILQ_FIRST(&asoc->reasmqueue);

	/* Grab the top flags */
	TAILQ_FOREACH(at, &asoc->reasmqueue, sctp_next) {
		if (compare_with_wrap(at->rec.data.TSN_seq, chk->rec.data.TSN_seq, MAX_TSN)) {
			/* one in queue is bigger than the new one, insert before this one */
			/* A check */
			asoc->size_on_reasm_queue += chk->send_size;
			asoc->cnt_on_reasm_queue++;
			next = at;
			TAILQ_INSERT_BEFORE(at, chk, sctp_next);
			break;
		} else if (at->rec.data.TSN_seq == chk->rec.data.TSN_seq) {
			/* Gak, He sent me a duplicate str seq number */
			/* foo bar, I guess I will just free this new guy, should we
			 * abort too? FIX ME MAYBE? Or it COULD be that
			 * the SSN's have wrapped. Maybe I should compare to
			 * TSN somehow... sigh for now just blow away the chunk!
			 */
			if (chk->data)
				m_freem(chk->data);
			chk->data = NULL;
			sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			return;
		} else {
			last_flags = at->rec.data.rcv_flags;
			last_tsn = at->rec.data.TSN_seq;
			prev = at;
			if (TAILQ_NEXT(at, sctp_next) == NULL) {
				/* We are at the end, insert it after this one */
				/* check it first */
				asoc->size_on_reasm_queue += chk->send_size;
				asoc->cnt_on_reasm_queue++;
				TAILQ_INSERT_AFTER(&asoc->reasmqueue, at, chk, sctp_next);
				break;
			}
		}
	}
	/* Now the audits */
	if (prev) {
		prev_tsn = chk->rec.data.TSN_seq - 1;
		if (prev_tsn == prev->rec.data.TSN_seq) {
			/* Ok the one I am dropping onto the end
			 * is the NEXT. A bit of valdiation here.
			 */
			if (((prev->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_FIRST_FRAG) ||
			   ((prev->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_MIDDLE_FRAG)) {
				/* Insert chk MUST be a MIDDLE or LAST fragment */
				if ((chk->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_FIRST_FRAG) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Prev check - It can be a midlle or last but not a first\n");
						printf("Gak, Evil plot, it's a FIRST!\n");
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
				if (chk->rec.data.stream_number != prev->rec.data.stream_number) {
					/* Huh, need the correct STR here, they must
					 * be the same.
					 */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Prev check - Gak, Evil plot, ssn:%d not the same as at:%d\n",
						       chk->rec.data.stream_number, prev->rec.data.stream_number);
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
				if (((prev->rec.data.rcv_flags & SCTP_DATA_UNORDERED) == 0) &&
				   (chk->rec.data.stream_seq != prev->rec.data.stream_seq)) {
					/* Huh, need the correct STR here, they must
					 * be the same.
					 */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Prev check - Gak, Evil plot, sseq:%d not the same as at:%d\n",
						       chk->rec.data.stream_seq, prev->rec.data.stream_seq);
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
			} else if ((prev->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_LAST_FRAG) {
				/* Insert chk MUST be a FIRST */
				if ((chk->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) != SCTP_DATA_FIRST_FRAG) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Prev check - Gak, evil plot, its not FIRST and it must be!\n");
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
			}
		}
	}

	if (next) {
		post_tsn = chk->rec.data.TSN_seq + 1;
		if (post_tsn == next->rec.data.TSN_seq) {
			/* Ok the one I am inserting ahead of
			 * is my NEXT one. A bit of valdiation here.
			 */
			if (next->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) {
				/* Insert chk MUST be a last fragment */
				if ((chk->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK)
				   != SCTP_DATA_LAST_FRAG) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Next chk - Next is FIRST, we must be LAST\n");
						printf("Gak, Evil plot, its not a last!\n");
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
			} else if (((next->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_MIDDLE_FRAG) ||
				 ((next->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_LAST_FRAG)) {
				/* Insert chk CAN be MIDDLE or FIRST NOT LAST */
				if ((chk->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) == SCTP_DATA_LAST_FRAG) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Next chk - Next is a MIDDLE/LAST\n");
						printf("Gak, Evil plot, new prev chunk is a LAST\n");
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
				if (chk->rec.data.stream_number != next->rec.data.stream_number) {
					/* Huh, need the correct STR here, they must
					 * be the same.
					 */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Next chk - Gak, Evil plot, ssn:%d not the same as at:%d\n",
						       chk->rec.data.stream_number, next->rec.data.stream_number);
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;
				}
				if (((next->rec.data.rcv_flags & SCTP_DATA_UNORDERED) == 0) &&
				   (chk->rec.data.stream_seq != next->rec.data.stream_seq)) {
					/* Huh, need the correct STR here, they must
					 * be the same.
					 */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
						printf("Next chk - Gak, Evil plot, sseq:%d not the same as at:%d\n",
						       chk->rec.data.stream_seq, next->rec.data.stream_seq);
					}
#endif
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					return;

				}
			}
		}
	}
	/* now that we have all in there place we must check
	 * a number of things to see if we can send data
	 * to the ULP.
	 */
	/* we need to do some delivery, if we can */
	chk = TAILQ_FIRST(&asoc->reasmqueue);
	if (chk == NULL) {
		/* Huh? */
		asoc->size_on_reasm_queue = 0;
		asoc->cnt_on_reasm_queue = 0;
		return;
	}
	if (asoc->fragmented_delivery_inprogress == 0) {
		nxt_todel = asoc->strmin[chk->rec.data.stream_number].last_sequence_delivered + 1;
		if ((chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) &&
		   ((nxt_todel == chk->rec.data.stream_seq) ||
		    (chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED))) {
			/* Yep the first one is here and its
			 * ok to deliver but should we?
			 */
			if ((TAILQ_EMPTY(&asoc->delivery_queue)) &&
			   ((sctp_is_all_msg_on_reasm(asoc, &tsize)) ||
			    ((asoc->size_on_reasm_queue >= (stcb->sctp_socket->so_rcv.sb_hiwat >> 2)) &&
			     tsize))
				) {
				/* Yes, we setup to
				 * start reception, by backing down the TSN
				 * just in case we can't deliver. If we
				 */
				asoc->fragmented_delivery_inprogress = 1;
				asoc->tsn_last_delivered = chk->rec.data.TSN_seq-1;
				asoc->str_of_pdapi = chk->rec.data.stream_number;
				asoc->ssn_of_pdapi = chk->rec.data.stream_seq;
				asoc->fragment_flags = chk->rec.data.rcv_flags;
				sctp_service_reassembly(stcb, asoc);
			}
		}
	} else {
		sctp_service_reassembly(stcb, asoc);
	}
}



/* This is an unfortunate routine. It checks to make
 * sure a evil guy is not stuffing us full of bad
 * packet fragments. A broken peer could also do this
 * but this is doubtful. It is to bad I must worry
 * about evil crackers sigh :< more cycles.
 */
static int
sctp_does_chk_belong_to_reasm(struct sctp_association *asoc,
			      struct sctp_tmit_chunk *chk)
{
	struct sctp_tmit_chunk *at;
	u_int32_t tsn_est;
	TAILQ_FOREACH(at, &asoc->reasmqueue, sctp_next) {
		if (compare_with_wrap(chk->rec.data.TSN_seq, at->rec.data.TSN_seq, MAX_TSN)) {
			/* is it one bigger? */
			tsn_est = at->rec.data.TSN_seq + 1;
			if (tsn_est == chk->rec.data.TSN_seq) {
				/* yep. It better be a last then*/
				if ((at->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) != SCTP_DATA_LAST_FRAG) {
					/* Ok this guy belongs next to a guy
					 * that is NOT last, it should be a middle/last,
					 * not a complete chunk.
					 */
					return (1);
				} else {
					/* This guy is ok since its a LAST and the new
					 * chunk is a fully self-contained one.
					 */
					return (0);
				}
			}
		} else if (chk->rec.data.TSN_seq == at->rec.data.TSN_seq) {
			/* Software error since I have a dup? */
			return (1);
		} else {
			/* Ok, 'at' is larger than new chunk but does it
			 * need to be right before it.
			 */
			tsn_est = chk->rec.data.TSN_seq + 1;
			if (tsn_est == at->rec.data.TSN_seq) {
				/* Yep, It better be a first */
				if ((at->rec.data.rcv_flags&SCTP_DATA_FRAG_MASK) != SCTP_DATA_FIRST_FRAG) {
					return (1);
				} else {
					return (0);
				}
			}
		}
	}
	return (0);
}
static int
sctp_process_a_data_chunk(struct sctp_tcb *stcb,
			  struct sctp_association *asoc,
			  struct mbuf *m,
			  int offset,
			  struct sctp_data_chunk *ch,
			  int chk_length,
			  struct sctp_nets *net,
			  u_int32_t *high_tsn,
			  int *break_flag,
			  int *abort_flag)
{
	/* Process a data chunk */
	/*  struct sctp_tmit_chunk *chk;*/
	struct sctp_tmit_chunk *chk;
	u_int32_t tsn, gap;
	int full_queue_flag=0;
	u_int16_t strmno, strmseq;

	tsn = ntohl(ch->dp.tsn);
	if ((compare_with_wrap(asoc->cumulative_tsn, tsn, MAX_TSN)) ||
             (asoc->cumulative_tsn == tsn)) {
		/* It is a duplicate */
		sctp_pegs[SCTP_DUPTSN_RECVD]++;
		if (asoc->numduptsns < SCTP_MAX_DUP_TSNS) {
			/* Record a dup for the next outbound sack */
			asoc->dup_tsns[asoc->numduptsns] = tsn;
			asoc->numduptsns++;
		}
		return (0);
	}
	/* Calculate the number of TSN's between the base and this TSN */
	if (tsn >= asoc->mapping_array_base_tsn) {
		gap  = tsn - asoc->mapping_array_base_tsn;
	} else {
		gap = (MAX_TSN - asoc->mapping_array_base_tsn) + tsn + 1;
	}
	if (gap > (SCTP_MAPPING_ARRAY << 3)) {
		/* Can't hold the bit in the mapping array toss it */
		return (0);
	}
	if (compare_with_wrap(tsn, *high_tsn, MAX_TSN)) {
		*high_tsn = tsn;
	}
	/* See if we have received this one already */
	if (SCTP_IS_TSN_PRESENT(asoc->mapping_array, gap)) {
		sctp_pegs[SCTP_DUPTSN_RECVD]++;
		if (asoc->numduptsns < SCTP_MAX_DUP_TSNS) {
			/* Record a dup for the next outbound sack */
			asoc->dup_tsns[asoc->numduptsns] = tsn;
			asoc->numduptsns++;
		}
		if (!callout_pending(&asoc->dack_timer.timer)) {
			/* By starting the timer we assure that we
			 * WILL sack at the end of the packet
			 * when sctp_sack_check gets called.
			 */
			sctp_timer_start(SCTP_TIMER_TYPE_RECV,
					 stcb->sctp_ep,
					 stcb, NULL);
		}
		return (0);
	}
	/* Now before going further we see
	 * if there is room. If NOT then
	 * we MAY let one through only IF
	 * this TSN is the one we are
	 * waiting for on a partial
	 * delivery API.
	 */

	if (stcb->sctp_socket->so_rcv.sb_cc >= stcb->sctp_socket->so_rcv.sb_hiwat) {
		full_queue_flag = 1;
	}
	/* now do the tests */
	if ((asoc->my_rwnd <= 0) &&
	   (sctp_sbspace(&stcb->sctp_socket->so_rcv) >=
	    (chk_length - sizeof(struct sctp_data_chunk))) &&
	   (full_queue_flag == 0)
		) {
		/* When we have NO room in the rwnd but room
		 * in the socket buffer for more data we will
		 * only accept the NEXT sequence number above
		 * the cum-ack point. By definition this is deliverable
		 * in some fashion and COULD free up other sequences as well.
		 */
		if (tsn != (asoc->cumulative_tsn + 1)) {
			/* Nope not the next one I want. Dump it */
			if (stcb->sctp_socket->so_rcv.sb_cc) {
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			}
			sctp_pegs[SCTP_RWND_DROPS]++;
			*break_flag = 1;
			return (0);
		}
	} else if (asoc->my_rwnd <= 0) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("My rwnd is overrun! sbspace:%d delq:%d!\n",
			       (int)sctp_sbspace(&stcb->sctp_socket->so_rcv),
			       (int)stcb->asoc.cnt_on_delivery_queue
				);
		}
#endif
		sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
		*break_flag = 1;
		sctp_pegs[SCTP_RWND_DROPS]++;
		return (0);
	}
	if (ntohs(ch->dp.stream_id) >= asoc->streamincnt) {
		struct sctp_paramhdr *phdr;
		struct mbuf *mb;

		MGETHDR(mb, M_DONTWAIT, MT_DATA);
		if (mb != NULL) {
			/* add some space up front so prepend will work well */
			mb->m_data += sizeof(struct sctp_chunkhdr);
			phdr = mtod(mb, struct sctp_paramhdr *);
			/* Error causes are just param's and this one
			 * has two back to back phdr, one with the
			 * error type and size, the other with
			 * the streamid and a rsvd
			 */
			mb->m_pkthdr.len = mb->m_len = (sizeof(struct sctp_paramhdr) * 2);
			phdr->param_type = htons(SCTP_CAUSE_INV_STRM);
			phdr->param_length = htons((sizeof(struct sctp_paramhdr) * 2));
			phdr++;
			/* We insert the stream in the type field */
			phdr->param_type = ch->dp.stream_id;
			/* And set the length to 0 for the rsvd field */
			phdr->param_length = 0;
			sctp_queue_op_err(stcb, mb);
		}
		sctp_pegs[SCTP_BAD_STRMNO]++;
		return (0);
	}
	/* Before we continue lets validate that we are not
	 * being fooled by an evil attacker. We can only
	 * have 4k chunks based on our TSN spread allowed
	 * by the mapping array 512 * 8 bits, so there is
	 * no way our stream sequence numbers could have wrapped.
	 * We of course only validate the FIRST fragment so the
	 * bit must be set.
	 */
	strmno = ntohs(ch->dp.stream_id);
	strmseq = ntohs(ch->dp.stream_sequence);;
	if ((ch->ch.chunk_flags & SCTP_DATA_FIRST_FRAG) &&
	   ((ch->ch.chunk_flags & SCTP_DATA_UNORDERED) == 0) &&
	   (compare_with_wrap(asoc->strmin[strmno].last_sequence_delivered,
			      strmseq, MAX_SEQ) ||
	    (asoc->strmin[strmno].last_sequence_delivered == strmseq))
		) {
		/* The incoming sseq is behind where we last delivered? */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("EVIL/Broken-Dup S-SEQ:%d delivered:%d from peer, Abort!\n",
			       strmseq,
			       asoc->strmin[strmno].last_sequence_delivered);
		}
#endif
		/* throw it in the stream so it gets cleaned up in
		 * association destruction
		 */
		sctp_abort_an_association(stcb->sctp_ep,
					  stcb, SCTP_PEER_FAULTY,
					  (struct mbuf *)NULL);
		sctp_pegs[SCTP_BAD_SSN_WRAP]++;
		*abort_flag = 1;
		return (0);
	}
	/* If we reach here this is a new chunk */
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* No memory so we drop the chunk */
		sctp_pegs[SCTP_DROP_NOMEMORY]++;
		return (0);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;
	chk->rec.data.TSN_seq = tsn;
	chk->rec.data.stream_seq = strmseq;
	chk->rec.data.stream_number = strmno;
	chk->rec.data.payloadtype = ntohl(ch->dp.protocol_id);
	chk->rec.data.context = 0;
	chk->rec.data.doing_fast_retransmit = 0;
	chk->rec.data.rcv_flags = ch->ch.chunk_flags;
	chk->asoc = asoc;
	chk->send_size = chk_length - sizeof(struct sctp_data_chunk);
	chk->whoTo = net;
	net->ref_count++;
	chk->data = m_copym(m,(offset + sizeof(struct sctp_data_chunk)),
			    (chk_length-sizeof(struct sctp_data_chunk)),
			    M_DONTWAIT);
	if (chk->data == NULL) {
		/* No mbuf space */
		/* back off the reference count */
		net->ref_count--;
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		sctp_pegs[SCTP_DROP_NOMEMORY]++;
		return (0);
	}
	/* Mark it as received */
	/* Now queue it where it belongs */
	if (stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
		/* socket is GONE */
		/* Kill the reassembly queue */
		sctp_service_reassembly(stcb, asoc);
		/* Kill the delivery queue */
		sctp_deliver_data(stcb, asoc, NULL);
		/* Now kill this chunk */
		if (chk != NULL) {
			if (chk->data)
				m_freem(chk->data);
			chk->data = NULL;
			sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif

			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
		}
	} else {

		if ((chk->rec.data.rcv_flags & SCTP_DATA_NOT_FRAG) == SCTP_DATA_NOT_FRAG) {
			/* First a sanity check */
			if (asoc->fragmented_delivery_inprogress) {
				/* Ok, we have a fragmented delivery in progress
				 * if this chunk is next to deliver OR belongs in
				 * our view to the reassembly, the peer is evil
				 * or broken.
				 */
				u_int32_t estimate_tsn;
				estimate_tsn = asoc->tsn_last_delivered + 1;
				if (TAILQ_EMPTY(&asoc->reasmqueue) &&
				   (estimate_tsn == chk->rec.data.TSN_seq)) {
				/* Evil/Broke peer */
					sctp_abort_an_association(stcb->sctp_ep,
								  stcb, SCTP_PEER_FAULTY,
								  (struct mbuf *)NULL);
					*abort_flag = 1;
					sctp_pegs[SCTP_DROP_FRAG]++;
					return (0);
				} else {
					if (sctp_does_chk_belong_to_reasm(asoc, chk)) {
						sctp_abort_an_association(stcb->sctp_ep,
									  stcb, SCTP_PEER_FAULTY,
									  (struct mbuf *)NULL);
						*abort_flag = 1;
						sctp_pegs[SCTP_DROP_FRAG]++;
						return (0);
					}
				}
			} else {
				if (!TAILQ_EMPTY(&asoc->reasmqueue)) {
				/* Reassembly queue is NOT empty
				 * validate that this chk does not need to
				 * be in reasembly queue. If it does then
				 * our peer is broken or evil.
				 */
					if (sctp_does_chk_belong_to_reasm(asoc, chk)) {
						sctp_abort_an_association(stcb->sctp_ep,
									  stcb, SCTP_PEER_FAULTY,
									  (struct mbuf *)NULL);
						*abort_flag = 1;
						sctp_pegs[SCTP_DROP_FRAG]++;
						return (0);
					}
				}
			}
			if (chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED) {
				/* queue directly into socket buffer */
				sctp_deliver_data(stcb, asoc, chk);
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			} else {
				sctp_queue_data_to_stream(stcb, asoc, chk, abort_flag);
			}
		} else {
			/* Into the re-assembly queue */
			sctp_queue_data_for_reasm(stcb, asoc, chk, abort_flag);
			if (*abort_flag) {
				sctp_pegs[SCTP_DROP_FRAG]++;
				return (0);
			}
		}
	}
	/* Mark it as received */
	if (compare_with_wrap(tsn, asoc->highest_tsn_inside_map, MAX_TSN)) {
		/* we have a new high score */
		asoc->highest_tsn_inside_map = tsn;
	}
	sctp_pegs[SCTP_PEG_TSNS_RCVD]++;
	/* Set it present please */
	SCTP_SET_TSN_PRESENT(asoc->mapping_array, gap);
	return (1);
}


static void
sctp_sack_check(struct sctp_tcb *stcb, int ok_to_sack)
{
	/* Now we also need to check the mapping array
	 * in a couple of ways.
	 * 1) Did we move the cum-ack point?
	 */
	struct sctp_association *asoc;
	int i, at;
	asoc = &stcb->asoc;
	at = 0;
	/* We could probably improve this a
	 * small bit by calculating the offset of
	 * the current cum-ack as the starting
	 * point.
	 */
	for (i = 0; i < (SCTP_MAPPING_ARRAY << 3); i++) {
		if (!SCTP_IS_TSN_PRESENT(asoc->mapping_array, i)) {
			/* Ok we found the first place that we are
			 * missing a TSN.
			 */
			at = i;
			asoc->cumulative_tsn = asoc->mapping_array_base_tsn + (i-1);
			break;
		}
	}
	if (at >= 8) {
		/* we can slide the mapping array down */
		int slide_from, slide_end, lgap, distance;
		/* Calculate the new byte postion we can move down */
		slide_from = at >> 3;
		/* now calculate the ceiling of the move using our highest TSN value */
		if (asoc->highest_tsn_inside_map >= asoc->mapping_array_base_tsn) {
			lgap  = asoc->highest_tsn_inside_map - asoc->mapping_array_base_tsn;
		} else {
			lgap = (MAX_TSN - asoc->mapping_array_base_tsn) + asoc->highest_tsn_inside_map + 1;
		}
		slide_end = lgap >> 3;
		distance = (slide_end-slide_from) + 1;
		if (((distance+slide_from) >= SCTP_MAPPING_ARRAY) ||
		   (distance < 0)) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
				printf("Ugh bad addition.. you can't hrumpp!\n");
			}
#endif
			;
		} else {
			memcpy(asoc->mapping_array, &asoc->mapping_array[slide_from], distance);
			memset(&asoc->mapping_array[distance],0,(slide_end-distance+1));
		}
		asoc->mapping_array_base_tsn += (slide_from << 3);
	}
	/* Now we need to see if we need to
	 * queue a sack or just start the timer (if allowed).
	 */
	if (ok_to_sack) {
		if ((asoc->state&SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_SENT) {
			/* Ok special case, in SHUTDOWN-SENT case.
			 * here we maker sure SACK timer is off and
			 * instead send a SHUTDOWN and a SACK
			 */
			if (callout_pending(&stcb->asoc.dack_timer.timer)) {
				sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
						stcb->sctp_ep,
						stcb, NULL);
			}
			sctp_send_shutdown(stcb, stcb->asoc.primary_destination);
			sctp_send_sack(stcb);
		} else {
			if (callout_pending(&stcb->asoc.dack_timer.timer) ||
			   (stcb->asoc.first_ack_sent == 0) ||
			   (compare_with_wrap(stcb->asoc.highest_tsn_inside_map,
					      stcb->asoc.cumulative_tsn, MAX_TSN)) ||
			   (stcb->asoc.numduptsns)
				) {
				/* Ok we must build a SACK since the timer
				 * is pending, we got our first packet OR
				 * there are gaps or duplicates.
				 */
				stcb->asoc.first_ack_sent = 1;
				sctp_send_sack(stcb);
				/* The sending will stop the timer */
			} else {
				sctp_timer_start(SCTP_TIMER_TYPE_RECV,
						 stcb->sctp_ep,
						 stcb, NULL);
			}
		}
	}
}

void
sctp_service_queues(struct sctp_tcb *stcb,
		    struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk;
	int tsize, cntDel;
	u_int16_t nxt_todel;

	cntDel = 0;
	if (asoc->fragmented_delivery_inprogress) {
		sctp_service_reassembly(stcb, asoc);
	}
	/* Can we proceed further, i.e. the PD-API is complete */
	if (asoc->fragmented_delivery_inprogress)
		/* no */
		return;

	/* Yes, reassembly delivery no longer in progress see if we
	 * have some on the sb hold queue.
	 */
	do{
		if ((!stcb->on_toqueue) &&
		   (stcb->sctp_socket->so_rcv.sb_cc >=
		    (stcb->sctp_ep->sctp_ep.sctp_sws_receiver >> 1))) {
			/* no room */
			TAILQ_INSERT_TAIL(&stcb->sctp_ep->sctp_queue_list, stcb, sctp_toqueue);
			stcb->on_toqueue = 1;
		}
		if (stcb->sctp_socket->so_rcv.sb_cc >= stcb->sctp_socket->so_rcv.sb_hiwat) {
			if (cntDel == 0)
				sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
			break;
		}
		/* If deliver_data says no we must stop */
		if (sctp_deliver_data(stcb, asoc,(struct sctp_tmit_chunk *)NULL) == 0)
			break;
		cntDel++;
		chk = TAILQ_FIRST(&asoc->delivery_queue);
	} while (chk);
	if (cntDel) {
		sctp_sorwakeup(stcb->sctp_ep, stcb->sctp_socket);
	}
	/* Now is there some other chunk I can deliver
	 * from the reassembly queue.
	 */
	chk = TAILQ_FIRST(&asoc->reasmqueue);
	if (chk == NULL) {
		asoc->size_on_reasm_queue = 0;
		asoc->cnt_on_reasm_queue = 0;
		return;
	}
	nxt_todel = asoc->strmin[chk->rec.data.stream_number].last_sequence_delivered + 1;
	if ((chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG) &&
	   ((nxt_todel == chk->rec.data.stream_seq) ||
	    (chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED))) {
		/* Yep the first one is here. We setup to
		 * start reception, by backing down the TSN
		 * just in case we can't deliver.
		 */

		/* Before we start though either all of the
		 * message should be here or 1/4 the socket buffer
		 * max or nothing on the delivery queue and something
		 * can be delivered.
		 */
		if ((TAILQ_EMPTY(&asoc->delivery_queue)) &&
		   ((sctp_is_all_msg_on_reasm(asoc, &tsize)) ||
		    ((asoc->size_on_reasm_queue>= (stcb->sctp_socket->so_rcv.sb_hiwat >> 2)) &&
		     tsize))
			) {
			asoc->fragmented_delivery_inprogress = 1;
			asoc->tsn_last_delivered = chk->rec.data.TSN_seq-1;
			asoc->str_of_pdapi = chk->rec.data.stream_number;
			asoc->ssn_of_pdapi = chk->rec.data.stream_seq;
			asoc->fragment_flags = chk->rec.data.rcv_flags;
			sctp_service_reassembly(stcb, asoc);
		}
	}
}

int
sctp_process_data(struct mbuf **mm,
		  struct sctp_inpcb *inp,
		  struct sctp_tcb *stcb,
		  struct sctp_nets *netp,
		  int iphlen,
		  int *offset,
		  int *length,
		  u_int32_t *high_tsn)
{
	struct sctp_data_chunk *ch, chunk_buf;
	struct sctp_association *asoc;
	int num_chunks = 0;	/* number of control chunks processed */
	int chk_length, break_flag;
	int abort_flag=0;
	struct mbuf *m;

	m = *mm;
	asoc = &stcb->asoc;

	/* setup where we got the last DATA packet from for
	 * any SACK that may need to go out. Don't bump
	 * the netp. This is done ONLY when a chunk
	 * is assigned.
	 */
	asoc->last_data_chunk_from = netp;

	/* Now before we proceed we must figure out if this
	 * is a wasted cluster... i.e. it is a small packet
	 * sent in and yet the driver underneath allocated a
	 * full cluster for it. If so we must copy it to a
	 * smaller mbuf and free up the cluster mbuf. This
	 * will help with cluster starvation.
	 */
	if ((m->m_len < MHLEN) && (m->m_next == NULL)) {
		/* we only handle mbufs that are singletons.. not chains */
		MGET(m, M_DONTWAIT, MT_DATA);
		if (m) {
			/* ok lets see if we can copy the data up */
			caddr_t *from, *to;
			if ((*mm)->m_flags & M_PKTHDR) {
				/* got to copy the header first */
#ifdef __OpenBSD__
				M_MOVE_PKTHDR(m, (*mm));
#else
				M_COPY_PKTHDR(m, (*mm));
#endif
			}
			/* get the pointers and copy */
			to = mtod(m, caddr_t *);
			from = mtod((*mm), caddr_t *);
			memcpy(to, from, (*mm)->m_len);
			/* copy the length and free up the old */
			m->m_len = (*mm)->m_len;
			m_freem(*mm);
			/* sucess, back copy just in case */
			*mm = m;
		} else {
			/* We are in trouble in the mbuf world .. yikes */
			m = *mm;
		}
	}
	if (stcb && (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_GONE)) {
		/* wait a minute, this guy is gone, there is no
		 * longer a receiver. Send peer an ABORT!
		 */
		struct mbuf *op_err;
		op_err = sctp_generate_invmanparam(SCTP_CAUSE_OUT_OF_RESC);
		sctp_abort_association( inp, stcb, m, iphlen, op_err );
		return (1);
	}
	/* get pointer to the first chunk header */
	ch = (struct sctp_data_chunk *)sctp_m_getptr(m, *offset,
						     sizeof(chunk_buf),
						     (u_int8_t *)&chunk_buf);

	/*
	 * process all DATA chunks...
	 */

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_INPUT1) {
		printf("In process data off:%d length:%d iphlen:%d ch->type:%d\n",
		       *offset, *length, iphlen,
		       (int)ch->ch.chunk_type);
	}
#endif


	*high_tsn = asoc->cumulative_tsn;
	break_flag = 0;
	while (ch->ch.chunk_type == SCTP_DATA) {
		/* validate chunk length */
		chk_length = ntohs(ch->ch.chunk_length);
		if ((chk_length < (sizeof(struct sctp_data_chunk)+1))  ||
		    (*length < chk_length)) {
			/* Need to send an abort since we had a invalid
			 * data chunk.
			 */
			sctp_abort_association(inp, stcb, m, iphlen, NULL);
			return (1);
		}
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INPUT1) {
			printf("A chunk of len:%d to process (tot:%d)\n",
			       chk_length, *length);
		}
#endif

		if (sctp_process_a_data_chunk(stcb, asoc, m, *offset, ch, chk_length, netp,
					     high_tsn,
					     &break_flag,
					     &abort_flag)) {
			num_chunks++;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INPUT1) {
				printf("Now incr num_chunks to %d\n", num_chunks);
			}
#endif
		}
		if (abort_flag)
			return (1);

		if (break_flag)
			/* Set because of out of rwnd space, no more data please */
			break;

		*offset += SCTP_SIZE32(chk_length);
		*length -= SCTP_SIZE32(chk_length);
		if (*length <= 0) {
			/* no more data left in the mbuf chain */
			break;
		}
		ch = (struct sctp_data_chunk *)sctp_m_getptr(m, *offset,
							     sizeof(chunk_buf),
							     (u_int8_t *)&chunk_buf);
		if (ch == NULL) {
			*length = 0;
			break;
		}
	} /* while */
	if (num_chunks) {
		/* Did we get data, if so update the time for
		 * auto-close and give peer credit for being
		 * alive.
		 */
		sctp_pegs[SCTP_DATA_DG_RECV]++;
		stcb->asoc.overall_error_count = 0;
		SCTP_GETTIME_TIMEVAL(&stcb->asoc.time_last_rcvd);
	}
	/* now service all of the reassm queue and delivery queue */
	sctp_service_queues(stcb, asoc);
	if ((asoc->state&SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_SENT) {
		/* Assure that we ack right away by making
		 * sure that a d-ack timer is running. So the
		 * sack_check will send a sack.
		 */
		sctp_timer_start(SCTP_TIMER_TYPE_RECV,
				 stcb->sctp_ep,
				 stcb,
				 netp);
	}
	/* Start a sack timer or QUEUE a SACK for sending */
	sctp_sack_check(stcb,1);
	return (0);
}

static void
sctp_handle_segments(struct sctp_tcb *stcb,
		     struct sctp_association *asoc,
		     struct sctp_sack_chunk *ch,
		     u_long last_tsn,
		     u_long *biggest_tsn_acked,
		     int num_seg
		     )

{
	/************************************************/
	/* process fragments and update sendqueue        */
	/************************************************/
	struct sctp_sack *sack;
	struct sctp_gap_ack_block *frag;
	struct sctp_tmit_chunk *tp1;
	int i, j;
	u_short frag_strt, frag_end, primary_flag_set;
	u_long last_frag_high;


	if (asoc->primary_destination->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
		primary_flag_set = 1;
	} else {
		primary_flag_set = 0;
	}

	sack = &ch->sack;
	frag = (struct sctp_gap_ack_block *)((caddr_t)sack + sizeof(struct sctp_sack));
	tp1 = NULL;
	last_frag_high = 0;
	for (i = 0; i < num_seg; i++) {
		frag_strt = ntohs(frag->start);
		frag_end = ntohs(frag->end);
		/* some sanity checks on the fargment offsets */
		if (frag_strt > frag_end) {
			/* this one is malformed, skip */
			frag++;
			continue;
		}
		if (compare_with_wrap((frag_end+last_tsn), *biggest_tsn_acked, MAX_TSN))
			*biggest_tsn_acked = frag_end+last_tsn;

		/* mark acked dgs and find out the highestTSN being acked */
		if (tp1 == NULL) {
			tp1 = TAILQ_FIRST(&asoc->sent_queue);

			/* save the locations of the last frags */
			last_frag_high = frag_end + last_tsn;
		} else {
			/* now lets see if we need to reset the queue
			 * due to a out-of-order SACK fragment
			 */
			if (compare_with_wrap(frag_strt+last_tsn, last_frag_high, MAX_TSN)) {
				/* if the new frag starts after the last TSN frag covered, we are ok */
				/* and this one is beyond the last one */
				;
			} else {
				/* ok, they have reset us, so we need to reset the queue
				 * this will cause extra hunting but hey, they chose the performance
				 * hit when they failed to order there gaps..
				 */
				tp1 = TAILQ_FIRST(&asoc->sent_queue);
			}
			last_frag_high = frag_end + last_tsn;
		}
		for (j=frag_strt + last_tsn; j<=frag_end + last_tsn; j++) {
			while (tp1) {
				if (tp1->rec.data.TSN_seq == j) {
					if (tp1->sent != SCTP_DATAGRAM_UNSENT) {
						/* must be held until cum-ack passes */
						if (tp1->sent < SCTP_DATAGRAM_ACKED) {
							/* If it is less than ACKED, it is now no-longer in
							 * flight. Higher values may already be set via previous
							 * Gap Ack Blocks... i.e. ACKED or MARKED.
							 */
							tp1->whoTo->flight_size -= tp1->send_size;
							if (tp1->whoTo->flight_size < 0) {
								tp1->whoTo->flight_size = 0;
							}
							asoc->total_flight -= tp1->send_size;
							if (asoc->total_flight < 0) {
								asoc->total_flight = 0;
							}
							if (tp1->snd_count < 2) {
								/* True non-retransmited chunk */
								tp1->whoTo->net_ack2 += tp1->send_size;

								/* update RTO too? */
								if (tp1->sent_rcv_time.tv_sec || tp1->sent_rcv_time.tv_usec) {
									tp1->whoTo->RTO = sctp_calculate_rto(stcb, asoc,
													     tp1->whoTo,
													     &tp1->sent_rcv_time);
									tp1->whoTo->rto_pending = 0;
									tp1->sent_rcv_time.tv_sec = tp1->sent_rcv_time.tv_usec = 0;
								}
							}
						}
						if ((tp1->sent <= SCTP_DATAGRAM_RESEND) &&
						   (tp1->sent != SCTP_DATAGRAM_UNSENT) &&
						   (compare_with_wrap(tp1->rec.data.TSN_seq, asoc->this_sack_highest_gap, MAX_TSN))) {
							asoc->this_sack_highest_gap = tp1->rec.data.TSN_seq;
							if (primary_flag_set) {
								tp1->whoTo->cacc_saw_newack = 1;
							}
						}
						if (tp1->sent == SCTP_DATAGRAM_RESEND) {
#ifdef SCTP_DEBUG
							if (sctp_debug_on & SCTP_DEBUG_INDATA3) {
								printf("Hmm. one that is in RESEND that is now ACKED\n");
							}
#endif
							asoc->sent_queue_retran_cnt--;
						}
						tp1->sent = SCTP_DATAGRAM_MARKED;
					}
					break;
				} /* if (tp1->TSN_seq == j) */
				if (compare_with_wrap(tp1->rec.data.TSN_seq, j, MAX_TSN))
					break;
				tp1 = TAILQ_NEXT(tp1, sctp_next);
			}/* end while (tp1) */
		}  /* end for (j=fragStart */
		frag++; /* next one */
	}
}



static void
sctp_check_for_revoked(struct sctp_association *asoc,
		       u_long cum_ack)

{
	struct sctp_tmit_chunk *tp1;

	tp1 = TAILQ_FIRST(&asoc->sent_queue);
	while (tp1) {
		if (compare_with_wrap(tp1->rec.data.TSN_seq, cum_ack, MAX_TSN)) {
			/* ok this guy is either ACK or MARKED. If it is ACKED it
			 * has been previously acked but not this time i.e. revoked.
			 * If it is MARKED it was ACK'ed again.
			 */
			if (tp1->sent == SCTP_DATAGRAM_ACKED) {
				/* it has been revoked */
				/* We do NOT add back to flight size here since
				 * it is really NOT in flight. Resend (when/if it occurs
				 * will add to flight size
				 */
				tp1->sent = SCTP_DATAGRAM_SENT;
			} else if (tp1->sent == SCTP_DATAGRAM_MARKED) {
				/* it has been re-acked in this SACK */
				tp1->sent = SCTP_DATAGRAM_ACKED;
			}
		}
		if (tp1->sent == SCTP_DATAGRAM_UNSENT)
			break;
		tp1 = TAILQ_NEXT(tp1, sctp_next);
	}
}


static void
sctp_strike_gap_ack_chunks(struct sctp_tcb *tcb,
			   struct sctp_association *asoc,
			   u_long biggest_tsn_acked,
			   int strike_enabled)
{
	struct sctp_tmit_chunk *tp1;

	int primary_switch_active = 0;
	int double_switch_active = 0;
	if (asoc->primary_destination->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
		primary_switch_active = 1;
	}
	if (asoc->primary_destination->dest_state & SCTP_ADDR_DOUBLE_SWITCH) {
		double_switch_active = 1;
	}
	tp1 = TAILQ_FIRST(&asoc->sent_queue);
	while (tp1) {
		if ((compare_with_wrap(tp1->rec.data.TSN_seq, biggest_tsn_acked, MAX_TSN)) ||
		   (tp1->sent == SCTP_DATAGRAM_UNSENT)) {
			/* done */
			break;
		}
		if (tp1->sent >= SCTP_DATAGRAM_RESEND) {
			/* either a RESEND, ACKED, or MARKED */
			/* skip */
			tp1 = TAILQ_NEXT(tp1, sctp_next);
			continue;
		}
		if (compare_with_wrap(tp1->rec.data.TSN_seq, asoc->this_sack_highest_gap, MAX_TSN)) {
			tp1 = TAILQ_NEXT(tp1, sctp_next);
			continue;
		}
		if (primary_switch_active && (strike_enabled == 0)) {
			if (tp1->whoTo != asoc->primary_destination) {
				/* We can only strike things on the primary if
				 * the strike_enabled flag is clear
				 */
				continue;
			}
		} else if (primary_switch_active) {
			if (tp1->whoTo->cacc_saw_newack == 0) {
				/* Only one was received but it was NOT
				 * this one.
				 */
				continue;
			}
		}
		if (double_switch_active &&
		   (compare_with_wrap(asoc->primary_destination->next_tsn_at_change,
				      tp1->rec.data.TSN_seq,
				      MAX_TSN))) {
			/* With a double switch we do NOT mark unless we
			 * are beyond the switch point.
			 */
			continue;
		}
		/* Strike the TSN */
		tp1->sent++;

		if (tp1->sent == SCTP_DATAGRAM_RESEND) {
			/* Increment the count to resend */
			struct sctp_nets *alt;
			asoc->sent_queue_retran_cnt++;
			/* Mark it as a FR */
			tp1->rec.data.doing_fast_retransmit = 1;
			if (tp1->sent_rcv_time.tv_sec) {
				/*  this guy had a RTO calculation pending on it, cancel it */
				tp1->whoTo->rto_pending = 0;
				tp1->sent_rcv_time.tv_sec = tp1->sent_rcv_time.tv_usec = 0;
			}
			/* fix counts and things */
			tp1->whoTo->net_ack++;
			tp1->whoTo->flight_size -= tp1->send_size;
			asoc->total_flight -= tp1->send_size;
			if (asoc->total_flight < 0) {
				asoc->total_flight = 0;
			}
			/* Can we move it to an alternate net */
			alt = sctp_find_alternate_net(tcb, tp1->whoTo);
			if (alt != tp1->whoTo) {
				/* yes */
				sctp_free_remote_addr(tp1->whoTo);
				tp1->whoTo = alt;
				alt->ref_count++;
			}
		}
		tp1 = TAILQ_NEXT(tp1, sctp_next);
	} /* while (tp1) */
}


void
sctp_try_advance_peer_ack_point(struct sctp_tcb *stcb,
				struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *tp1, *tp2;
	struct timeval now;
	int audit_needed = 0;

	if (asoc->peer_supports_usctp == 0) {
		return;
	}
	SCTP_GETTIME_TIMEVAL(&now);
	tp1 = TAILQ_FIRST(&asoc->sent_queue);
	while (tp1) {
		if ((tp1->sent != SCTP_FORWARD_TSN_SKIP) &&
		   (tp1->sent != SCTP_DATAGRAM_RESEND)) {
			/* no chance to advance, out of here */
			break;
		}
		if ((tp1->flags & SCTP_PR_SCTP_ENABLED) == 0) {
			/* We can't fwd-tsn past any that are reliable
			 * aka retransmitted until the asoc fails.
			 */
			break;
		}
		tp2 = TAILQ_NEXT(tp1, sctp_next);
		/*
		 * now we got a chunk which is marked for another
		 * retransmission to a PR-stream but has run
		 * out its chances already maybe OR has been
		 * marked to skip now. Can we skip it if its a
		 * resend?
		 */
		if ((tp1->sent == SCTP_DATAGRAM_RESEND) &&
		   ((tp1->flags & SCTP_PR_SCTP_BUFFER) == 0)) {
			/* Now is this one marked for resend and its time
			 * is now up?
			 */
			if ((now.tv_sec > tp1->rec.data.timetodrop.tv_sec) ||
			   ((tp1->rec.data.timetodrop.tv_sec == now.tv_sec) &&
			    (now.tv_usec > tp1->rec.data.timetodrop.tv_usec))) {
				/* Yes so drop it */
				tp1->sent = SCTP_FORWARD_TSN_SKIP;
			} else {
				/* No, we are done when hit one for resend whos
				 * time as not expired.
				 */
				break;
			}
		}
		/* Ok now if this chunk is marked to drop it
		 * we can clean up the chunk, advance our peer ack point
		 * and we can check the next chunk.
		 */
		if (tp1->sent == SCTP_FORWARD_TSN_SKIP) {
			/* advance PeerAckPoint goes forward */
			asoc->advanced_peer_ack_point = tp1->rec.data.TSN_seq;
			/* we don't want to de-queue it here. Just wait for the next
			 * peer SACK to come with a new cumTSN and then the chunk will
			 * be droped in the normal fashion.
			 */
			if (tp1->data) {
				sctp_free_bufspace(stcb, asoc, tp1);
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
					printf("--total out:%d total_mbuf_out:%d\n",
					       (int)asoc->total_output_queue_size,
					       (int)asoc->total_output_mbuf_queue_size);
				}
#endif
				sctp_ulp_notify(SCTP_NOTIFY_DG_FAIL, stcb,
						/* Maybe there should be another notification type */
						(SCTP_RESPONSE_TO_USER_REQ|SCTP_NOTIFY_DATAGRAM_SENT),
						tp1);
				m_freem(tp1->data);
				tp1->data = NULL;
				sctp_sowwakeup(stcb->sctp_ep, stcb->sctp_socket);
			}
		} else {
			/* If it is still in RESEND we can advance no further */
			break;
		}
		/* If we hit here we just dumped tp1, move to next
		 * tsn on sent queue.
		 */
		tp1 = tp2;
	}
	if (audit_needed) {
		sctp_audit_retranmission_queue(asoc);
	}
}



void
sctp_handle_sack(struct sctp_sack_chunk *ch, struct sctp_tcb *stcb,
		 struct sctp_nets *net_from)
{
	struct sctp_association *asoc;
	struct sctp_sack *sack;
	struct sctp_tmit_chunk *tp1, *tp2;
	u_long cum_ack, last_tsn, biggest_tsn_acked;
	u_short num_seg;
	int some_on_streamwheel;
	long j;
	int strike_enabled, cnt_of_cacc = 0;
	int accum_moved = 0;
	int marking_allowed = 1;
	int a_rwnd;


	struct sctp_nets *net = NULL;
	asoc = &stcb->asoc;
	/* Handle the incoming sack on data I have
	 * been sending.
	 */

	/* we take any chance we can to service our queues
	 * since we cannot get awoken when the socket
	 * is read from :<
	 */
	asoc->overall_error_count = 0;

	if (asoc->sent_queue_retran_cnt) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Handling SACK for asoc:%x retran:%d\n",
			       (u_int)asoc, asoc->sent_queue_retran_cnt);
		}
#endif
	}

	sctp_service_queues(stcb, asoc);
	/* Now perform the actual SACK handling:
	 * 1) Verify that it is not an old sack, if so discard.
	 * 2) If there is nothing left in the send queue (cum-ack is
	 *    equal to last acked) then you have a duplicate too, update
	 *    any rwnd change and verify no timers are running. then return.
	 * 3) Process any new consequtive data i.e. cum-ack moved
	 *    process these first and note that it moved.
	 * 4) Process any sack blocks.
	 * 5) Drop any acked from the queue.
	 * 6) Check for any revoked blocks and mark.
	 * 7) Update the cwnd.
	 * 8) Nothing left, sync up flightsizes and things, stop all timers
	 *    and also check for shutdown_pending state. If so then
	 *    go ahead and send off the shutdown. If in shutdown recv, send
	 *    off the shutdown-ack and start that timer, Ret.
	 * 9) Strike any non-acked things and do FR procedure if
	 *    needed being sure to set the FR flag.
	 * 10) Do u-sctp procedures.
	 * 11) Apply any FR penalties.
	 * 12) Assure we will SACK if in shutdown_recv state.
	 */
	j = 0;


	if (ntohs(ch->ch.chunk_length) < sizeof(struct sctp_sack_chunk)) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Bad size on sack chunk .. to small\n");
		}
#endif
		return;
	}
	sack = &ch->sack;
	cum_ack = last_tsn = ntohl(sack->cum_tsn_ack);
	num_seg = ntohs(sack->num_gap_ack_blks);

	/* update the Rwnd of the peer */
	a_rwnd = ntohl(sack->a_rwnd);
	if (asoc->sent_queue_retran_cnt) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("cum_ack:%x num_seg:%d last_acked_seq:%x\n",
			       (u_int)cum_ack,
			       num_seg,
			       (u_int)asoc->last_acked_seq);
		}
#endif
	}
	if (compare_with_wrap(asoc->t3timeout_highest_marked, cum_ack, MAX_TSN)) {
		/* we are not allowed to mark for FR */
		marking_allowed = 0;
	}
	/**********************/
	/* 1) check the range */
	/**********************/
	if (compare_with_wrap(asoc->last_acked_seq, last_tsn, MAX_TSN)) {
		/* acking something behind */
		if (asoc->sent_queue_retran_cnt) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
				printf("The cum-ack is behind us\n");
			}
#endif
		}
		return;
	}

	if (TAILQ_EMPTY(&asoc->sent_queue)) {
		/* nothing left on sendqueue.. consider done */
		asoc->peers_rwnd = a_rwnd;
		if (asoc->sent_queue_retran_cnt) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
				printf("Huh? retran set but none on queue\n");
			}
#endif
			asoc->sent_queue_retran_cnt = 0;
		}
		if (asoc->peers_rwnd < stcb->sctp_ep->sctp_ep.sctp_sws_sender) {
			/* SWS sender side engages */
			asoc->peers_rwnd = 0;
		}
		/* stop any timers */
		TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
			sctp_timer_stop(SCTP_TIMER_TYPE_SEND,
					stcb->sctp_ep,
					stcb,
					net);
			net->partial_bytes_acked = 0;
			net->flight_size = 0;
		}
		asoc->total_flight = 0;
		return;
	}
	/* We init netAckSz and netAckSz2 to 0. These
	 * are used to track 2 things. The total byte
	 * count acked is tracked in netAckSz AND netAck2
	 * is used to track the total bytes acked that are un-amibguious
	 * and were never retransmitted. We track these on a
	 * per destination address basis.
	 */
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		net->net_ack = 0;
		net->net_ack2 = 0;
	}
	/* process the new consecutive TSN first */
	tp1 = TAILQ_FIRST(&asoc->sent_queue);
	while (tp1) {
		if ((compare_with_wrap(last_tsn, tp1->rec.data.TSN_seq, MAX_TSN))  ||
		    (last_tsn == tp1->rec.data.TSN_seq)) {
			if (tp1->sent != SCTP_DATAGRAM_UNSENT) {
				accum_moved = 1;
				asoc->nonce_sum_expect_base += tp1->rec.data.ect_nonce;
				if (tp1->sent < SCTP_DATAGRAM_ACKED) {
					/* If it is less than ACKED, it is now no-longer in
					 * flight. Higher values may occur during marking
					 */
					tp1->whoTo->flight_size -= tp1->send_size;
					if (tp1->whoTo->flight_size < 0) {
						tp1->whoTo->flight_size = 0;
					}
					asoc->total_flight -= tp1->send_size;
					if (asoc->total_flight < 0) {
						asoc->total_flight = 0;
					}
					tp1->whoTo->net_ack += tp1->send_size;
					if (tp1->snd_count < 2) {
						/* True non-retransmited chunk */
						tp1->whoTo->net_ack2 += tp1->send_size;
						/* update RTO too? */
						if (tp1->sent_rcv_time.tv_sec || tp1->sent_rcv_time.tv_usec) {
							tp1->whoTo->RTO = sctp_calculate_rto(stcb, asoc,
											     tp1->whoTo,
											     &tp1->sent_rcv_time);
							tp1->whoTo->rto_pending = 0;
							tp1->sent_rcv_time.tv_sec = tp1->sent_rcv_time.tv_usec = 0;
						}
					}
				}
				if (tp1->sent == SCTP_DATAGRAM_RESEND) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_INDATA3) {
						printf("Hmm. one that is in RESEND that is now ACKED\n");
					}
#endif
					asoc->sent_queue_retran_cnt--;
				}
				tp1->sent = SCTP_DATAGRAM_ACKED;
			}
		} else {
			break;
		}
		tp1 = TAILQ_NEXT(tp1, sctp_next);
	}
	/***************************************/
	/* cancel ALL T3-send timer if accum moved */
	/***************************************/
	if (accum_moved) {
		TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
			sctp_timer_stop(SCTP_TIMER_TYPE_SEND,
					stcb->sctp_ep,
					stcb,
					net);
		}
	}
	biggest_tsn_acked = last_tsn;
	/* always set this up to cum-ack */
	asoc->this_sack_highest_gap = last_tsn;

	if (num_seg > 0) {
		if (asoc->primary_destination->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
			/* clear the nets CACC flags */
			TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
				net->cacc_saw_newack = 0;
			}
		}
		/* thisSackHigestGap will increase while handling NEW segments */
		sctp_handle_segments(stcb, asoc, ch, last_tsn, &biggest_tsn_acked,
				     num_seg);
		if (asoc->primary_destination->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
			/* clear the nets CACC flags */
			TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
				if (net->cacc_saw_newack) {
					cnt_of_cacc++;
				}
			}
		}
	}
	if (cnt_of_cacc < 2) {
		strike_enabled = 1;
	} else {
		strike_enabled = 0;
	}

	/*******************************************/
	/* drop the acked chunks from the sendqueue */
	/*******************************************/
	asoc->last_acked_seq = cum_ack;
	if (asoc->fast_retran_loss_recovery && accum_moved) {
		if (compare_with_wrap(asoc->last_acked_seq, asoc->fast_recovery_tsn, MAX_TSN) ||
		    (asoc->last_acked_seq == asoc->fast_recovery_tsn)) {
			/* RFC2582 recovery has ended */
			asoc->fast_retran_loss_recovery = 0;
		}
	}
	if (asoc->primary_destination->dest_state & SCTP_ADDR_SWITCH_PRIMARY) {
		if ((cum_ack == asoc->primary_destination->next_tsn_at_change) ||
		    (compare_with_wrap(cum_ack,
				       asoc->primary_destination->next_tsn_at_change,
				       MAX_TSN))) {
			struct sctp_nets *lnet;
			/* Turn off the switch flag for ALL addresses */
			TAILQ_FOREACH(lnet, &asoc->nets, sctp_next) {
				asoc->primary_destination->dest_state &= ~(SCTP_ADDR_SWITCH_PRIMARY|SCTP_ADDR_DOUBLE_SWITCH);
			}
		}
	}
	/* Drag along the t3 timeout point so we don't have
	 * a problem at wrap
	 */
	if (marking_allowed) {
		asoc->t3timeout_highest_marked = cum_ack;
	}
	tp1 = TAILQ_FIRST(&asoc->sent_queue);
	do {
		if (compare_with_wrap(tp1->rec.data.TSN_seq, cum_ack, MAX_TSN)) {
			break;
		}
		if (tp1->sent == SCTP_DATAGRAM_UNSENT) {
			/* no more sent on list */
			break;
		}
		tp2 = TAILQ_NEXT(tp1, sctp_next);
		TAILQ_REMOVE(&asoc->sent_queue, tp1, sctp_next);
		if (tp1->data) {
			sctp_free_bufspace(stcb, asoc, tp1);
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
				printf("--total out:%d total_mbuf_out:%d\n",
				       (int)asoc->total_output_queue_size,
				       (int)asoc->total_output_mbuf_queue_size);
			}
#endif

			m_freem(tp1->data);
		}
		tp1->data = NULL;
		sctp_sowwakeup(stcb->sctp_ep, stcb->sctp_socket);
		asoc->sent_queue_cnt--;
		if (tp1->flags && SCTP_PR_SCTP_BUFFER) {
			asoc->sent_queue_cnt_removeable--;
		}
		sctp_free_remote_addr(tp1->whoTo);
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is going negative");
		}
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, tp1);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, tp1);
#endif
		sctppcbinfo.ipi_gencnt_chunk++;
		tp1 = tp2;
	} while (tp1 != NULL);

	/* Check revoke no matter whether this SACK has frag or not */
	sctp_check_for_revoked(asoc, cum_ack);

	/******************************/
	/* update cwnd                */
	/******************************/
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		/* if nothing was acked on this destination
		 * skip it.
		 */
		if (net->net_ack == 0)
			continue;

		if (net->net_ack2 > 0) {
			/* Karn's rule applies to clearing error count, this is optional. */
			net->error_count = 0;
			if ((net->dest_state&SCTP_ADDR_NOT_REACHABLE) == SCTP_ADDR_NOT_REACHABLE) {
				/* addr came good */
				net->dest_state &= ~SCTP_ADDR_NOT_REACHABLE;
				net->dest_state |= SCTP_ADDR_REACHABLE;
				sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_UP, stcb, SCTP_RECEIVED_SACK, (void *)net);
				/* now was it the primary? if so restore */
				if (net->dest_state & SCTP_ADDR_WAS_PRIMARY) {
					stcb->asoc.primary_destination = net;
					net->dest_state &= ~SCTP_ADDR_WAS_PRIMARY;
				}
			}
		}
		if (accum_moved) {
			/* If the cumulative ack moved we can proceed */
			if (net->cwnd <= net->ssthresh) {
				/* We are in slow start */
				if ((net->flight_size+net->net_ack) >= net->cwnd) {
					if (net->net_ack > net->mtu) {
						net->cwnd += net->mtu;
					} else {
						net->cwnd += net->net_ack;
					}
					sctp_pegs[SCTP_CWND_INCRS]++;
				}
			} else {
				/* We are in congestion avoidance */
				if ((net->flight_size+net->net_ack) >= net->cwnd) {
					/* add to pba only if we
					 * had a cwnd's worth (or so) in flight
					 */
					net->partial_bytes_acked += net->net_ack;
				}
				/* Do we need to increase (if pba is > cwnd)? */
				if ((net->partial_bytes_acked >= net->cwnd) &&
				    ((net->flight_size+net->net_ack ) >= net->cwnd)) {
					/* Yep, we had a full cwnd out */
					if (net->cwnd <= net->partial_bytes_acked) {
						net->partial_bytes_acked -= net->cwnd;
					} else {
						net->partial_bytes_acked = 0;
					}
					net->cwnd += net->mtu;
					sctp_pegs[SCTP_CWND_INCRS]++;
				}
			}
		}
		/* NOW, according to Karn's rule do we need to
		 * restore the RTO timer back? Check our
		 * net_ack2. If not set then we have a
		 * ambiguity.. i.e. all data ack'd was
		 * sent to more than one place.
		 */
		if (net->net_ack2) {
			/* restore any doubled timers */
			net->RTO = ((net->lastsa >> 2) + net->lastsv) >> 1;
			if (net->RTO < stcb->sctp_ep->sctp_ep.sctp_minrto) {
				net->RTO = stcb->sctp_ep->sctp_ep.sctp_minrto;
			}
			if (net->RTO > stcb->sctp_ep->sctp_ep.sctp_maxrto) {
				net->RTO = stcb->sctp_ep->sctp_ep.sctp_maxrto;
			}
		}
	}
	/**********************************/
	/* Now what about shutdown issues */
	/**********************************/
	some_on_streamwheel = 0;
	if (!TAILQ_EMPTY(&asoc->out_wheel)) {
		/* Check to see if some data queued */
		struct sctp_stream_out *outs;
		TAILQ_FOREACH(outs, &asoc->out_wheel, next_spoke) {
			if (!TAILQ_EMPTY(&outs->outqueue)) {
				some_on_streamwheel = 1;
				break;
			}
		}
	}
	if (TAILQ_EMPTY(&asoc->send_queue) && TAILQ_EMPTY(&asoc->sent_queue) &&
	    (some_on_streamwheel == 0)) {
		/* nothing left on sendqueue.. consider done */
		/* stop all timers */
		asoc->peers_rwnd = a_rwnd;
		if (asoc->peers_rwnd < stcb->sctp_ep->sctp_ep.sctp_sws_sender) {
			/* SWS sender side engages */
			asoc->peers_rwnd = 0;
		}
		/* stop any timers */
		TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
			sctp_timer_stop(SCTP_TIMER_TYPE_SEND,
					stcb->sctp_ep,
					stcb,
					net);
			net->flight_size = 0;
			net->partial_bytes_acked = 0;
		}
		asoc->total_flight = 0;
		/* clean up */
		if (asoc->state & SCTP_STATE_SHUTDOWN_PENDING) {
			asoc->state = SCTP_STATE_SHUTDOWN_SENT;
			sctp_send_shutdown(stcb, stcb->asoc.primary_destination);
			sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN,
					 stcb->sctp_ep,
					 stcb, asoc->primary_destination);
			sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD,
					 stcb->sctp_ep,
					 stcb, asoc->primary_destination);
		} else if ((asoc->state & SCTP_STATE_MASK) ==  SCTP_STATE_SHUTDOWN_RECEIVED) {
			asoc->state = SCTP_STATE_SHUTDOWN_ACK_SENT;

			sctp_send_shutdown_ack(stcb, stcb->asoc.primary_destination);

			sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNACK,
					 stcb->sctp_ep,
					 stcb, asoc->primary_destination);
		}
		return;
	}
	/* Now here we are going to recycle net_ack for a different
	 * use... HEADS UP.
	 */
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		net->net_ack = 0;
	}
	if ((num_seg > 0) && marking_allowed) {
		sctp_strike_gap_ack_chunks(stcb, asoc, biggest_tsn_acked, strike_enabled);
	}

	/*********************************************/
	/* Here we perform U-SCTP procedures 	       */
	/* (section 4.2)                             */
	/*********************************************/
	/* C1. update advancedPeerAckPoint */
	if (compare_with_wrap(cum_ack, asoc->advanced_peer_ack_point, MAX_TSN)) {
		asoc->advanced_peer_ack_point = cum_ack;
	}
	/* C2. try to further move advancedPeerAckPoint ahead */
	if (asoc->peer_supports_usctp) {
		sctp_try_advance_peer_ack_point(stcb, asoc);
		/* C3. See if we need to send a Fwd-TSN */
		if (compare_with_wrap(asoc->advanced_peer_ack_point, cum_ack, MAX_TSN)) {
			/* ISSUE with ECN, see FWD-TSN processing for notes on issues
			 * that will occur when the ECN NONCE stuff is put into
			 * SCTP for cross checking.
			 */
			send_forward_tsn(stcb, asoc);
		}
	}
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		if (asoc->fast_retran_loss_recovery == 0) {
			/* out of a RFC2582 Fast recovery window? */
			if (net->net_ack > 0) {
				/* per section 7.2.3, are there
				 * any destinations that had a fast
				 * retransmit to them. If so what we
				 * need to do is adjust ssthresh and
				 * cwnd.
				 */
				net->ssthresh = net->cwnd / 2;
				if (net->ssthresh < (net->mtu*2)) {
					net->ssthresh = 2 * net->mtu;
				}
				net->cwnd = net->ssthresh;
				net->partial_bytes_acked = 0;
				/* Turn on fast recovery window */
				asoc->fast_retran_loss_recovery = 1;
				/* Mark end of the window */
				asoc->fast_recovery_tsn = asoc->sending_seq;
			}
		} else if (net->net_ack > 0) {
			/* Mark a peg that we WOULD have done a cwnd reduction
			 * but RFC2582 prevented this action.
			 */
			sctp_pegs[SCTP_FR_INAWINDOW]++;
		}
		if (net->flight_size > 0) {
			sctp_timer_start(SCTP_TIMER_TYPE_SEND,
					 stcb->sctp_ep,
					 stcb,
					 net);
		}
	}

	/* Adjust and set the new rwnd value */
	asoc->peers_rwnd =  a_rwnd - asoc->total_flight;
	if (asoc->peers_rwnd < stcb->sctp_ep->sctp_ep.sctp_sws_sender) {
		/* SWS sender side engages */
		asoc->peers_rwnd = 0;
	}
	/* Now we must setup so we have a timer up
	 * for anyone with outstanding data.
	 */
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		struct sctp_tmit_chunk *chk;
		int flg;
		flg = 0;
		TAILQ_FOREACH(chk, &asoc->sent_queue, sctp_next) {
			if ((chk->whoTo == net) &&
			    (chk->sent < SCTP_DATAGRAM_ACKED)) {
				/* Not ack'ed and still outstanding to this
				 * destination.
				 */
				sctp_timer_start(SCTP_TIMER_TYPE_SEND,
						 stcb->sctp_ep,
						 stcb,
						 net);
				flg = 1;
				break;
			}
			if (flg)
				/* On to next network */
				continue;
		}
	}
}

void
sctp_update_acked(struct sctp_tcb *stcb,
		  struct sctp_shutdown_chunk *cp,
		  struct sctp_nets *netp)
{
	/* Mutate a shutdown into a SACK */
	struct sctp_sack_chunk sack;

	/* Copy cum-ack */
	sack.sack.cum_tsn_ack = cp->cumulative_tsn_ack;
	/* Arrange so a_rwnd does NOT change */
	sack.ch.chunk_type = SCTP_SELECTIVE_ACK;
	sack.ch.chunk_flags = 0;
	sack.ch.chunk_length = ntohs(sizeof(struct sctp_sack_chunk));
	sack.sack.a_rwnd = htonl(stcb->asoc.peers_rwnd + stcb->asoc.total_flight);
	/* no gaps in this one. This may cause a temporal
	 * view to reneging, but hopefully the second chunk
	 * is a true SACK in the packet and will correct this
	 * view. One will come soon after no matter what to fix
	 * this.
	 */
	sack.sack.num_gap_ack_blks = 0;
	sack.sack.num_dup_tsns = 0;
	/* Now call the SACK processor */
	sctp_handle_sack(&sack, stcb, netp);
}

static void 
sctp_kick_prsctp_reorder_queue(struct sctp_tcb *stcb,
			       struct sctp_stream_in *strmin)
{
	struct sctp_tmit_chunk *chk, *nchk;
	struct sctp_association *asoc;
	int tt;

	asoc = &stcb->asoc;
	tt = strmin->last_sequence_delivered + 1;
	chk = TAILQ_FIRST(&strmin->inqueue);
	while (chk) {
		nchk = TAILQ_NEXT(chk, sctp_next);
		if (compare_with_wrap(tt, chk->rec.data.stream_seq, MAX_SEQ) ||
		    (tt == chk->rec.data.stream_seq)) {
			/* this is deliverable now */
			TAILQ_REMOVE(&strmin->inqueue, chk, sctp_next);
			/* Do we need to advance tt? */
			if (chk->rec.data.stream_seq == tt)
				tt = chk->rec.data.stream_seq + 1;
			/* subtract pending on streams */
			asoc->size_on_all_streams -= chk->send_size;
			asoc->cnt_on_all_streams--;
			/* deliver it to at least the delivery-q */
			sctp_deliver_data(stcb, &stcb->asoc, chk);
		} else {
                       /* no more delivery now. */
 		        break;
		}
		chk = nchk;
	}
}

#ifdef SCTP_OLD_USCTP_COMPAT
static int
sctp_kick_unrel_reorder_queue(struct sctp_tcb *stcb,
			      struct sctp_stream_in *strmin)
{
	/* this subroutine tries to deliver any ready msgs
	 * from the inqueue of an PR-streams
	 */
	struct sctp_tmit_chunk *chk, *nchk;
	struct sctp_association *asoc;
	int tt, ret;
	ret = 0;
	asoc = &stcb->asoc;
	tt = strmin->last_sequence_delivered + 1;
	chk = TAILQ_FIRST(&strmin->inqueue);
	while (chk) {
		nchk = TAILQ_NEXT(chk, sctp_next);
		if (compare_with_wrap(asoc->cumulative_tsn,
				      chk->rec.data.TSN_seq, MAX_TSN) ||
		    (asoc->cumulative_tsn == chk->rec.data.TSN_seq) ||
		    (tt == chk->rec.data.stream_seq)) {
			/* this is deliverable now */
			TAILQ_REMOVE(&strmin->inqueue, chk, sctp_next);
			ret++;
			/* Do we need to advance tt? */
			if (chk->rec.data.stream_seq >= tt)
				tt = chk->rec.data.stream_seq + 1;
			/* subtract pending on streams */
			asoc->size_on_all_streams -= chk->send_size;
			asoc->cnt_on_all_streams--;
			/* deliver it to at least the delivery-q */
			sctp_deliver_data(stcb, &stcb->asoc, chk);
		}
		chk = nchk;
		/* See if we have come far enough */
		if (chk) {
			if (compare_with_wrap(chk->rec.data.TSN_seq,
					      asoc->cumulative_tsn, MAX_TSN))
				/* yep */
				break;
		}
	}
	if (ret) {
		/* Update the last sequence delivered */
		strmin->last_sequence_delivered = tt - 1;
		if (TAILQ_EMPTY(&strmin->inqueue) &&
		    ((strmin->next_spoke.tqe_next != NULL) |
		     (strmin->next_spoke.tqe_prev != NULL))) {
			/* Ok it was on the wheel and
			 * has nothing left, remove it.
			 */
			TAILQ_REMOVE(&asoc->unrel_wheel, strmin, next_spoke);
			strmin->next_spoke.tqe_next = NULL;
			strmin->next_spoke.tqe_prev = NULL;
		}
	}
	return (ret);
}
#endif

void
sctp_handle_forward_tsn(struct sctp_tcb *stcb,
			struct sctp_forward_tsn_chunk *fwd)
{
	/* ISSUES that MUST be fixed for ECN! When we are the
	 * sender of the forward TSN, when the SACK comes back
	 * that acknowledges the FWD-TSN we must reset the
	 * NONCE sum to match correctly. This will get quite
	 * tricky since we may have sent more data interveneing and
	 * must carefully account for what the SACK says on the
	 * nonce and any gaps that are reported. This work
	 * will NOT be done here, but I note it here since
	 * it is really related to PR-SCTP and FWD-TSN's
	 */

	/* The pr-sctp fwd tsn */
	/* here we will perform all the data receiver side steps for
	 * processing FwdTSN, as required in by pr-sctp draft:
	 *
	 * Assume we get FwdTSN(x):
	 *
	 * 1) update local cumTSN to x
	 * 2) try to further advance cumTSN to x + others we have
	 * 3) examine and update re-ordering queue on pr-in-streams
	 * 4) clean up re-assembly queue
	 */
	struct sctp_strseq *stseq;
	struct sctp_association *asoc;
	u_int32_t new_cum_tsn, gap;
	int i, cnt_gone, fwd_sz;
	struct sctp_stream_in *strm;
	struct sctp_tmit_chunk *chk, *at;

	asoc = &stcb->asoc;
	cnt_gone = 0;
	if ((fwd_sz = ntohs(fwd->ch.chunk_length)) < sizeof(struct sctp_forward_tsn_chunk)) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Bad size too small/big fwd-tsn\n");
		}
#endif
		return;
	}
	/*************************************************************/
	/* 1. Here we update local cumTSN and shift the bitmap array */
	/*************************************************************/
	new_cum_tsn = ntohl(fwd->new_cumulative_tsn);
	if ((compare_with_wrap(asoc->cumulative_tsn, new_cum_tsn, MAX_TSN)) ||
	    (asoc->cumulative_tsn == new_cum_tsn)) {
		/* Already got there ... */
		return;
	}
	if (compare_with_wrap(new_cum_tsn, asoc->highest_tsn_inside_map, MAX_TSN)) {
		asoc->highest_tsn_inside_map = new_cum_tsn;
	}
	/* now we know the new TSN is more advanced, let's find the actual gap */
	if (new_cum_tsn >= asoc->mapping_array_base_tsn)
		gap = new_cum_tsn - asoc->mapping_array_base_tsn;
	else
		/* try to prevent underflow here */
		gap = new_cum_tsn + (MAX_TSN - asoc->mapping_array_base_tsn) + 1;

	if (gap >(SCTP_MAPPING_ARRAY << 3)  || gap < 0) {
		/* out of range, too questionable. better to drop it silently */
		return;
	}
	for (i = 0; i <= gap; i++) {
		SCTP_SET_TSN_PRESENT(asoc->mapping_array, i);
	}
	/* Now after marking all, slide thing forward but no
	 * sack please.
	 */
	sctp_sack_check(stcb,0);
	/*************************************************************/
	/* 2. Clear up re-assembly queue                             */
	/*************************************************************/

	/* First service it if pd-api is up, just in case we can
	 * progress it forward
	 */
	if (asoc->fragmented_delivery_inprogress) {
		sctp_service_reassembly(stcb, asoc);
	}
	if (!TAILQ_EMPTY(&asoc->reasmqueue)) {
		/* For each one on here see if we need to toss it */
		chk = TAILQ_FIRST(&asoc->reasmqueue);
		while (chk) {
			at = TAILQ_NEXT(chk, sctp_next);
			if ((compare_with_wrap(asoc->cumulative_tsn,
					       chk->rec.data.TSN_seq, MAX_TSN)) ||
			    (asoc->cumulative_tsn == chk->rec.data.TSN_seq)) {
				/* It needs to be tossed */
				TAILQ_REMOVE(&asoc->reasmqueue, chk, sctp_next);
				if (compare_with_wrap(chk->rec.data.TSN_seq,
						      asoc->tsn_last_delivered,
						      MAX_TSN)) {
					/* advance stuff here, hmm we may have been
					 * in a partial delivery thats a problem.
					 */
					asoc->tsn_last_delivered = chk->rec.data.TSN_seq;
					asoc->str_of_pdapi = chk->rec.data.stream_number;
					asoc->ssn_of_pdapi = chk->rec.data.stream_seq;
					asoc->fragment_flags = chk->rec.data.rcv_flags;
				}
				asoc->size_on_reasm_queue -= chk->send_size;
				asoc->cnt_on_reasm_queue--;
				cnt_gone++;
				/* If we are delivering to the PD-API and the last chunk is
				 * being dumped, we can turn of the PD-API
				 */
				if ((asoc->fragmented_delivery_inprogress) &&
				    (chk->rec.data.rcv_flags & SCTP_DATA_LAST_FRAG)
					) {
					asoc->fragmented_delivery_inprogress = 0;
					sctp_ulp_notify(SCTP_NOTIFY_PARTIAL_DELVIERY_INDICATION,
							stcb, SCTP_PARTIAL_DELIVERY_ABORTED, (void *)NULL);

				}
				/* Clear up any stream problem */
				if (((chk->rec.data.rcv_flags & SCTP_DATA_UNORDERED) != SCTP_DATA_UNORDERED) &&
				    (compare_with_wrap(chk->rec.data.stream_seq,
						       asoc->strmin[chk->rec.data.stream_number].last_sequence_delivered,
						       MAX_SEQ))) {
					/* We must dump forward this streams
					 * sequence number if the chunk is not unordered
					 * that is being skipped. There is a chance that if
					 * the peer does not include the last fragment
					 * in its FWD-TSN we WILL have a problem
					 * here since you would have a partial chunk
					 * in queue that may not be deliverable.
					 * Also if a Partial delivery API as started
					 * the user may get a partial chunk. The next
					 * read returning a new chunk... really ugly
					 * but I see no way around it! Maybe a notify??
					 */

					asoc->strmin[chk->rec.data.stream_number].last_sequence_delivered = chk->rec.data.stream_seq;
				}
				if (chk->data) {
					m_freem(chk->data);
					chk->data = NULL;
				}
				sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
				zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
				pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
				sctppcbinfo.ipi_count_chunk--;
				if ((int)sctppcbinfo.ipi_count_chunk < 0) {
					panic("Chunk count is negative");
				}
				sctppcbinfo.ipi_gencnt_chunk++;
			} else {
				/* Ok we have gone beyond the end of the
				 * fwd-tsn's mark. Some checks...
				 */
				if ((asoc->fragmented_delivery_inprogress) &&
				    (chk->rec.data.rcv_flags & SCTP_DATA_FIRST_FRAG)) {
					/* Special case PD-API is up and what we fwd-tsn'
					 * over includes one that had the LAST_FRAG. We
					 * no longer need to do the PD-API.
					 */
					asoc->fragmented_delivery_inprogress = 0;
					sctp_ulp_notify(SCTP_NOTIFY_PARTIAL_DELVIERY_INDICATION,
							stcb, SCTP_PARTIAL_DELIVERY_ABORTED, (void *)NULL);

				}
				break;
			}
			chk = at;
		}
	}
	if ((asoc->fragmented_delivery_inprogress) &&
	    (cnt_gone)) {
		/* Ok we removed cnt_gone chunks in the PD-API queue that
		 * were being delivered. So now we must turn off the
		 * flag.
		 */
		asoc->fragmented_delivery_inprogress = 0;
	}
	/*************************************************************/
	/* 3. Update the PR-stream re-ordering queues                */
	/*************************************************************/
	stseq = (struct sctp_strseq *)((caddr_t *)fwd + sizeof(*fwd));
	fwd_sz -= sizeof(*fwd);
#ifdef SCTP_OLD_USCTP_COMPAT
	if (fwd_sz < sizeof(struct sctp_strseq)) {
		/* We do this the old way... for now we support
		 * those who don't put in a list of str/seq and
		 * those who do. When we disconntinue this then
		 * we can kill the code that adds things to the unrel_wheel and
		 * get rid of the unrel_wheel from the assoc structure.
		 */
		struct sctp_stream_in *nstrm;
#ifdef SCTP_DEBUG

		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Using OLD method, no strseq's reported in FWD-TSN\n");
		}
#endif
		strm = TAILQ_FIRST(&asoc->unrel_wheel);
		while (strm) {
			nstrm = TAILQ_NEXT(strm, next_spoke);
			/* this should always be true */
			sctp_kick_unrel_reorder_queue(stcb, strm);
			strm = nstrm;
		}
	} else
#endif
	{
		/* New method. */
		int num_str, i;
		num_str = fwd_sz/sizeof(struct sctp_strseq);
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
			printf("Using NEW method, %d strseq's reported in FWD-TSN\n", num_str);
		}
#endif
		for (i = 0; i < num_str; i++) {
			u_int16_t st;
			/* Convert */
			st = ntohs(stseq[i].stream);
			stseq[i].stream = st;
			st = ntohs(stseq[i].sequence);
			stseq[i].sequence = st;
			/* now process */
			if (stseq[i].stream > asoc->streamincnt) {
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_INDATA1) {
					printf("Bogus stream number %d streamincnt is %d\n",
					       stseq[i].stream, asoc->streamincnt);
				}
#endif
				/* It is arguable if we should continue. Since the peer
				 * sent bogus stream info we may be in deep trouble..
				 * a return may be a better choice?
				 */
				continue;
			}
			strm = &asoc->strmin[stseq[i].stream];
			if (compare_with_wrap(stseq[i].sequence, strm->last_sequence_delivered, MAX_SEQ)) {
				/* Update the sequence number */
				strm->last_sequence_delivered = stseq[i].sequence;
			}
			/* now kick the stream the new way */
			sctp_kick_prsctp_reorder_queue(stcb, strm);
		} 
	}
}




