/*	$KAME: sctp_structs.h,v 1.2 2002/05/01 06:31:11 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_structs.h,v 1.67 2002/04/03 21:10:19 lei Exp	*/

#ifndef __sctp_structs_h__
#define __sctp_structs_h__

/*
 * Copyright (c) 2001, 2002 Cisco Systems, Inc.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Cisco Systems, Inc.
 * 4. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CISCO SYSTEMS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CISCO SYSTEMS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/queue.h>

#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif

#include <netinet/sctp_header.h>
#include <netinet/sctp_uio.h>

struct sctp_timer {
	struct callout timer;
	int type;
	/*
	 * Depending on the timer type these will be setup and cast with
	 * the appropriate entity.
	 */
	void *ep;
	void *tcb;
	void *net;
};

/*
 * This is the information we track on each interface that we know about	* from the distant end.
 */
TAILQ_HEAD(sctpnetlisthead, sctp_nets);

struct sctp_nets {
	/* Ip address and port */
	TAILQ_ENTRY(sctp_nets) sctp_next;	/* next link */
	/*
	 * The following two in combination equate to a route entry for
	 * v6 or v4.
	 */
	struct sctp_route {
		struct rtentry *ro_rt;
		struct sockaddr_storage _l_addr;	/* remote peer addr */
	} ra;
	int ref_count;
	/* This is used for SHUTDOWN/SHUTDOWN-ACK/SEND or INIT timers */
	struct sctp_timer rxt_timer;

	/* smoothed average things for RTT and RTO itself */
	int lastsa;
	int lastsv;
	int RTO;

	/* Congestion stats per destination */
	/*
	 * flight size variables and such, sorry Vern, I could not avoid
	 * this if I wanted performance :>
	 */
	int flight_size;
	int cwnd; /* actual cwnd */
	int partial_bytes_acked; /* in CA tracks when to increment a MTU */
	int ssthresh;  

	/* mtu discovered so far */
	int mtu;

	/* last time in seconds I sent to it */
	struct timeval last_sent_time;

	/* tracking variables to avoid the aloc/free in sack processing */
	int net_ack;
	int net_ack2;
	/*
	 * These only are valid if the primary dest_sstate holds the
	 * SCTP_ADDR_SWITCH_PRIMARY flag
	 */
	u_int32_t next_tsn_at_change;
	/* if this guy is ok or not ... status */
	unsigned short dest_state;
	/* number of transmit failures to down this guy */
	unsigned short failure_threshold;
	/* error stats on destination */
	unsigned short error_count;

	/* Flags that probably can be combined into dest_state */
	u_int8_t rto_pending;		/* is segment marked for RTO update */
	u_int8_t fast_retran_ip;	/* fast retransmit in progress */
	u_int8_t hb_responded;
	u_int8_t cacc_saw_newack;	/* CACC algorithm flag */
};


struct sctp_data_chunkrec {
	u_int32_t TSN_seq;  /* the TSN of this transmit */
	u_int16_t stream_seq; /* the stream sequence number of this transmit */
	u_int16_t stream_number; /* the stream number of this guy */
	u_int32_t payloadtype;
	u_int32_t context;	/* from send */
	struct timeval timetodrop;	/* time we drop it from queue */
	u_char doing_fast_retransmit;
	u_char rcv_flags; /* flags pulled from data chunk on inbound
			   * for outbound holds sending flags.	
			   */
	u_char ect_nonce;
	u_char state_flags;
};

TAILQ_HEAD(sctpchunk_listhead, sctp_tmit_chunk);

#define CHUNK_FLAGS_FRAGMENT_OK	0x0001

struct sctp_tmit_chunk {
	union {
		struct sctp_data_chunkrec data;
		int chunk_id;
	} rec;
	int sent;		/* the send status */
	int snd_count;		/* number of times I sent */
	u_int32_t flags;	/* flags, such as FRAGMENT_OK */
	int send_size;
	int book_size;
	struct sctp_association *asoc;	/* bp to asoc this belongs to */
	struct timeval sent_rcv_time;	/* filled in if RTT being calculated */
	struct mbuf *data;		/* pointer to mbuf chain of data */
	struct sctp_nets *whoTo;
	TAILQ_ENTRY(sctp_tmit_chunk) sctp_next;	/* next link */
};


/*
 * this struct contains info that is used to track inbound stream data
 * and help with ordering.
 */
TAILQ_HEAD(sctpwheelunrel_listhead, sctp_stream_in);
struct sctp_stream_in {
	struct sctpchunk_listhead inqueue;
	u_short stream_no;
	u_short last_sequence_delivered;	/* used for re-order */
	TAILQ_ENTRY(sctp_stream_in) next_spoke;
};

/* This struct is used to track the traffic on outbound streams */
TAILQ_HEAD(sctpwheel_listhead, sctp_stream_out);
struct sctp_stream_out {
	struct sctpchunk_listhead outqueue;
	TAILQ_ENTRY(sctp_stream_out) next_spoke; /* next link in wheel */
	u_short stream_no;
	u_short next_sequence_sent; /* next one I expect to send out */
};

/* used to keep track of the addresses yet to try to add/delete */
TAILQ_HEAD(sctp_asconf_addrhead, sctp_asconf_addr);
struct sctp_asconf_addr {
	TAILQ_ENTRY(sctp_asconf_addr) next;
	struct sctp_asconf_addr_param ap;
	struct ifaddr *ifa;	/* save the ifa for add/del ip */
	uint8_t	sent;		/* has this been sent yet? */
};


/* 
 * Here we have information about each individual association that we
 * track. We probably in production would be more dynamic. But for ease
 * of implementation we will have a fixed array that we hunt for in a
 * linear fashion. 
 */
struct sctp_association {
	/* association state */
	int state;

	struct timeval time_entered;		/* time we entered state */
	struct timeval time_last_rcvd;
	struct timeval time_last_sent;
	struct sctp_sndrcvinfo def_send;	/* default send parameters */

	/* timers and such */
	struct sctp_timer pmtu;			/* p-mtu raise timer */
	struct sctp_timer hb_timer;		/* hb timer */
	struct sctp_timer dack_timer;		/* Delayed ack timer */
	struct sctp_timer asconf_timer;		/* Asconf */
	struct sctp_timer shut_guard_timer;	/* guard */
	struct sctp_timer autoclose_timer;	/* automatic close timer */
#ifdef SCTP_TCP_MODEL_SUPPORT
	struct sctp_timer delayed_event_timer;	/* timer for delayed events */
#endif /* SCTP_TCP_MODEL_SUPPORT */
	/* the cookie life I award for any cookie, in seconds */
	int cookie_life;

	uint32_t cookie_preserve_req;

	/* if subset bound, type of addresses we have bound (eg. valid) */
	uint32_t bound_types;

	/* list of local addresses when add/del in progress */
	struct sctpladdr sctp_local_addr_list;

	/*
	 * if Source Address Selection happening, this will rotate through
	 * the link list.
	 */
	struct sctp_laddr *last_used_address;

	/* amount of data (bytes) currently in flight (on all destinations) */
	int total_flight;

	/* count of destinaton nets and list of destination nets */ 
	int numnets;
	struct sctpnetlisthead nets;

	/* Total error count on this association */
	int overall_error_count;

	/* various verification tag information */
	uint32_t my_vtag;	/*
				 * The tag to be used. if assoc is
				 * re-initited by remote end, and
				 * I have unlocked this will be
				 * regenrated to a new random value.
				 */
	uint32_t peer_vtag;	/* The peers last tag */


	/* my maximum number of retrans of INIT and SEND */
	/* copied from SCTP but should be individually setable */
	u_short max_init_times;
	u_short max_send_times;
	u_short def_net_failure;

	/*
	 * window state information and smallest MTU that I use to bound
	 * segmentation
	 */
	long peers_rwnd;
	long my_rwnd;

	/* This is the SCTP fragmentation threshold */
	u_int32_t smallest_mtu;

	/* primary destination to use */
	struct sctp_nets *primary_destination;

	/* last place I got a data chunk from */
	struct sctp_nets *last_data_chunk_from;
	/* last place I got a control from */
	struct sctp_nets *last_control_chunk_from;

	/*
	 * Special hook for Fast retransmit, allows us to track the highest
	 * TSN that is NEW in this SACK if gap ack blocks are present.
	 */
	u_int32_t this_sack_highest_gap;

	/*
	 * The highest consecutive TSN that has been acked by peer on my
	 * sends
	 */
	u_int32_t last_acked_seq;

	/* The next TSN that I will use in sending. */
	u_int32_t sending_seq;

	/* Original seq number I used */
	u_int32_t init_seq_number;

	/*
	 * We use this value to know if FR's are allowed, i.e. did the
	 * cum-ack pass this point or equal it so FR's are now allowed.
	 */
	u_int32_t t3timeout_highest_marked;

	/* The Advanced Peer Ack Point, as required by the U-SCTP */
	/* (A1 in Section 4.2) */
	u_int32_t advanced_peer_ack_point;

	/*
	 * The highest consequetive TSN at the bottom of the mapping
	 * array (for his sends).
	 */
	u_int32_t cumulative_tsn;
	/*
	 * Used to track the mapping array and its offset bits. This
	 * MAY be lower then cumulative_tsn.
	 */
	u_int32_t mapping_array_base_tsn;
	/*
	 * used to track highest TSN we have received and is listed in
	 * the mapping array.
	 */
	u_int32_t highest_tsn_inside_map;

	/* 
	 * Control chunk queue
	 */
	struct sctpchunk_listhead control_send_queue;
	int ctrl_queue_cnt;

	/* 
	 * All outbound datagrams queue into this list from the
	 * individual stream queue. Here they get assigned a TSN
	 * and then await sending. The stream seq comes when it
	 * is first put in the individual str queue
	 */
	struct sctpchunk_listhead send_queue;

	/* Once a TSN hits the wire it is moved to the sent_queue. We 
	 * maintain two counts here (don't know if any but retran_cnt
	 * is needed). The idea is that the sent_queue_retran_cnt 
	 * reflects how many chunks have been marked for retranmission
	 * by either T3-rxt or FR.
	 */
	struct sctpchunk_listhead sent_queue;
	int sent_queue_cnt;
	/* 
	 * Number on sent queue that are marked for retran until this
	 * value is 0 we only send one packet of retran'ed data.
	 */
	int sent_queue_retran_cnt;

	/* re-assembly queue for fragmented chunks on the inbound path */
	struct sctpchunk_listhead reasmqueue;
	int size_on_reasm_queue;
	int cnt_on_reasm_queue;

	/* For the partial delivery API, if up, invoked
	 * this is what last TSN I delivered
	 */
	u_int32_t tsn_last_delivered;
	u_int16_t str_of_pdapi;
	u_int16_t ssn_of_pdapi;

	/*
	 * this queue is used when we reach a condition that we can NOT
	 * put data into the socket buffer. We track the size of this
	 * queue and set our rwnd to the space in the socket minus also
	 * the size_on_delivery_queue.
	 */
	struct sctpchunk_listhead delivery_queue;
	int size_on_delivery_queue;
	int cnt_on_delivery_queue;

	/* All stream count of chunks for delivery */
	int size_on_all_streams;
	int cnt_on_all_streams;

	/* Heart Beat delay in ticks */
	int heart_beat_delay;

	/* autoclose */
	int sctp_autoclose_ticks;

	/* how many preopen streams we have */
	int pre_open_streams;

	/* How many streams I support coming into me */
	int max_inbound_streams;

	/* counts of actual built streams. Allocation may be more however */
	/* could re-arrange to optimize space here. */
	u_short streamincnt;
	u_short streamoutcnt;
	/* circular looking for output selection */
	struct sctp_stream_out *last_out_stream;

	/* stream arrays */
	long total_output_queue_size;
	long total_output_mbuf_queue_size;
	struct sctpwheel_listhead out_wheel;
	struct sctpwheelunrel_listhead unrel_wheel;
	struct sctp_stream_in  *strmin;
	struct sctp_stream_out *strmout;


	/*
	 * ASCONF stuff
	 */
	/* next seq I am sending out, inits at init-tsn */
	uint32_t asconf_seq_out;
	/* last received ASCONF from peer, starts at peer's TSN-1 */
	uint32_t asconf_seq_in;
	/* destination address last sent to */
	struct sctp_nets *asconf_last_sent_to;
	/* save the last ASCONF-ACK so we can resend it if necessary */
	struct mbuf *last_asconf_ack_sent;
	/* queue of pending addrs to add/delete */
	struct sctp_asconf_addrhead asconf_queue;


	/* Being that we have no bag to collect stale cookies, and
	 * that we really would not want to anyway.. we will count
	 * them in this counter. We of course feed them to the
	 * pigeons right away (I have always thought of pigeons
	 * as flying rats).
	 */
	int stale_cookie_count;
	u_int32_t last_echo_tsn;
	u_int32_t last_cwr_tsn;

	int numduptsns;
	int dup_tsns[SCTP_MAX_DUP_TSNS];
	int initial_init_rto_max;	/* initial RTO for INIT's */
	int initial_rto;		/* initial send RTO */
	struct socketdesc *sb;

	/*
	 * lock flag: 0 is ok to send, 1+ (duals as a retran count) is
	 * awaiting ACK
	 */
	uint16_t asconf_sent;

	/*
	 * This flag indicates that we need to send the first SACK. If
	 * in place it says we have NOT yet sent a SACK and need to.
	 */
	u_int8_t first_ack_sent;

	/* max burst after fast retransmit comletes */
	u_int8_t max_burst;

	/* flag goes on when we are doing a partial delivery api */
	u_int8_t hb_random_values[4];
	u_int8_t fragmented_delivery_inprogress;
	u_int8_t fragment_flags;
	u_int8_t hb_ect_randombit;
	u_int8_t nonce_sum_in;
	/*
	 * This value, plus all other ack'd but above cum-ack is added
	 * together to cross check against the bit that we have yet to
	 * define (probably in the SACK).
	 * When the cum-ack is updated, this sum is updated as well.
	 */
	u_int8_t nonce_sum_expect_base;
	/* Flag to tell if ECN is allowed */
	u_int8_t ecn_allowed;

	/* flag to indicate if peer can do asconf */
	uint8_t peer_supports_asconf;
	uint8_t peer_supports_asconf_setprim;
	/* u-sctp support flag */
	uint8_t peer_supports_usctp;

	/* Do we allow V6/V4? */
	u_int8_t ipv4_addr_legal;
	u_int8_t ipv6_addr_legal;
	/* Address scoping flags */
	/* scope value for IPv4 */
	u_int8_t ipv4_local_scope;
	/* scope values for IPv6 */
	u_int8_t local_scope;
	u_int8_t site_scope;	
	/* loopback scope */
	u_int8_t loopback_scope;
	/* flags to handle send alternate net tracking */
	u_int8_t used_alt_onsack;
	u_int8_t used_alt_asconfack;
	/*
	 * The mapping array is used to track out of order sequences
	 * above last_acked_seq. 0 indicates packet missing 1 indicates
	 * packet rec'd. We slide it up every time we raise last_acked_seq
	 * and 0 trailing locactions out.  If I get a TSN above the
	 * array mappingArraySz, I discard the datagram and let retransmit
	 * happen.
	 */
	u_int8_t mapping_array[SCTP_MAPPING_ARRAY];
};

#endif
