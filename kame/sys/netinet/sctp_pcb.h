/*	$KAME: sctp_pcb.h,v 1.18 2004/08/17 04:06:19 itojun Exp $	*/

#ifndef __sctp_pcb_h__
#define __sctp_pcb_h__

/*
 * Copyright (c) 2001, 2002, 2003, 2004 Cisco Systems, Inc.
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

/*
 * We must have V6 so the size of the proto can be calculated. Otherwise
 * we would not allocate enough for Net/Open BSD :-<
 */
#if defined(__FreeBSD__) && __FreeBSD_version > 500000
#include <net/pfil.h>
#endif
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/in6_var.h>
#if defined(__OpenBSD__) 
#include <netinet/in_pcb.h>
#else
#include <netinet6/in6_pcb.h>
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#ifndef in6pcb
#define in6pcb		inpcb
#endif
#endif

#include <netinet/sctp.h>
#include <netinet/sctp_constants.h>

LIST_HEAD(sctppcbhead, sctp_inpcb);
LIST_HEAD(sctpasochead, sctp_tcb);
TAILQ_HEAD(sctpsocketq, sctp_socket_q_list);
LIST_HEAD(sctpladdr, sctp_laddr);
LIST_HEAD(sctpvtaghead, sctp_tagblock);

#include <netinet/sctp_structs.h>
#include <netinet/sctp_uio.h>

/*
 * PCB flags
 */
#define SCTP_PCB_FLAGS_UDPTYPE		0x00000001
#define SCTP_PCB_FLAGS_TCPTYPE		0x00000002
#define SCTP_PCB_FLAGS_BOUNDALL		0x00000004
#define SCTP_PCB_FLAGS_ACCEPTING	0x00000008
#define SCTP_PCB_FLAGS_UNBOUND		0x00000010
#define SCTP_PCB_FLAGS_DO_ASCONF	0x00000020
#define SCTP_PCB_FLAGS_AUTO_ASCONF	0x00000040
/* socket options */
#define SCTP_PCB_FLAGS_NODELAY		0x00000100
#define SCTP_PCB_FLAGS_AUTOCLOSE	0x00000200
#define SCTP_PCB_FLAGS_RECVDATAIOEVNT	0x00000400
#define SCTP_PCB_FLAGS_RECVASSOCEVNT	0x00000800
#define SCTP_PCB_FLAGS_RECVPADDREVNT	0x00001000
#define SCTP_PCB_FLAGS_RECVPEERERR	0x00002000
#define SCTP_PCB_FLAGS_RECVSENDFAILEVNT	0x00004000
#define SCTP_PCB_FLAGS_RECVSHUTDOWNEVNT	0x00008000
#define SCTP_PCB_FLAGS_ADAPTIONEVNT	0x00010000
#define SCTP_PCB_FLAGS_PDAPIEVNT	0x00020000
#define SCTP_PCB_FLAGS_STREAM_RESETEVNT 0x00040000
#define SCTP_PCB_FLAGS_NO_FRAGMENT	0x00080000
/* TCP model support */
#define SCTP_PCB_FLAGS_CONNECTED	0x00100000
#define SCTP_PCB_FLAGS_IN_TCPPOOL	0x00200000
#define SCTP_PCB_FLAGS_DONT_WAKE	0x00400000
#define SCTP_PCB_FLAGS_WAKEOUTPUT	0x00800000
#define SCTP_PCB_FLAGS_WAKEINPUT	0x01000000
#define SCTP_PCB_FLAGS_BOUND_V6		0x02000000
#define SCTP_PCB_FLAGS_NEEDS_MAPPED_V4	0x04000000
#define SCTP_PCB_FLAGS_BLOCKING_IO	0x08000000
#define SCTP_PCB_FLAGS_SOCKET_GONE	0x10000000
#define SCTP_PCB_FLAGS_SOCKET_ALLGONE	0x20000000

/* flags to copy to new PCB */
#define SCTP_PCB_COPY_FLAGS		0x0707ff64

#define SCTP_IS_FLAG_SET(var, flag)	((var & flag) == flag))

#define SCTP_PCBHASH_ALLADDR(port, mask) (port & mask)
#define SCTP_PCBHASH_ASOC(tag, mask) (tag & mask)

struct sctp_laddr {
	LIST_ENTRY(sctp_laddr) sctp_nxt_addr;	/* next in list */
	struct ifaddr *ifa;
};

struct sctp_timewait {
	uint32_t tv_sec_at_expire;	/* the seconds from boot to expire */
	uint32_t v_tag;		/* the vtag that can not be reused */
};

struct sctp_tagblock {
	LIST_ENTRY(sctp_tagblock) sctp_nxt_tagblock;
	struct sctp_timewait vtag_block[SCTP_NUMBER_IN_VTAG_BLOCK];
};

struct sctp_epinfo {
	struct sctpasochead *sctp_asochash;
	u_long hashasocmark;

	struct sctppcbhead *sctp_ephash;
	u_long hashmark;

#ifdef SCTP_TCP_MODEL_SUPPORT
	/*
	 * The TCP model represents a substantial overhead in that we get
	 * an additional hash table to keep explicit connections in. The
	 * listening TCP endpoint will exist in the usual ephash above and
	 * accept only INIT's. It will be incapable of sending off an INIT.
	 * When a dg arrives we must look in the normal ephash. If we find
	 * a TCP endpoint that will tell us to go to the specific endpoint
	 * hash and re-hash to find the right assoc/socket. If we find a
	 * UDP model socket we then must complete the lookup. If this fails,
	 * i.e. no association can be found then we must continue to see if
	 * a sctp_peeloff()'d socket is in the tcpephash (a spun off socket
	 * acts like a TCP model connected socket).
	 */
	struct sctppcbhead *sctp_tcpephash;
	u_long hashtcpmark;
#endif /* SCTP_TCP_MODEL_SUPPORT */
	uint32_t hashtblsize;

	struct sctppcbhead listhead;

	/* ep zone info */
#if defined(__FreeBSD__) || defined(__APPLE__)
#if __FreeBSD_version >= 500000
	struct uma_zone *ipi_zone_ep;
	struct uma_zone *ipi_zone_asoc;
	struct uma_zone *ipi_zone_laddr;
	struct uma_zone *ipi_zone_raddr;
	struct uma_zone *ipi_zone_chunk;
	struct uma_zone *ipi_zone_sockq;
#else
	struct vm_zone *ipi_zone_ep;
	struct vm_zone *ipi_zone_asoc;
	struct vm_zone *ipi_zone_laddr;
	struct vm_zone *ipi_zone_raddr;
	struct vm_zone *ipi_zone_chunk;
	struct vm_zone *ipi_zone_sockq;
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	struct pool ipi_zone_ep;
	struct pool ipi_zone_asoc;
	struct pool ipi_zone_laddr;
	struct pool ipi_zone_raddr;
	struct pool ipi_zone_chunk;
	struct pool ipi_zone_sockq;
#endif
	u_int ipi_count_ep;
	u_quad_t ipi_gencnt_ep;

	/* assoc/tcb zone info */
	u_int ipi_count_asoc;
	u_quad_t ipi_gencnt_asoc;

	/* local addrlist zone info */
	u_int ipi_count_laddr;
	u_quad_t ipi_gencnt_laddr;

	/* remote addrlist zone info */
	u_int ipi_count_raddr;
	u_quad_t ipi_gencnt_raddr;

	/* chunk structure list for output */
	u_int ipi_count_chunk;
	u_quad_t ipi_gencnt_chunk;

	/* socket queue zone info */
	u_int ipi_count_sockq;
	u_quad_t ipi_gencnt_sockq;


#ifdef SCTP_VTAG_TIMEWAIT_PER_STACK
	struct sctpvtaghead vtag_timewait[SCTP_STACK_VTAG_HASH_SIZE];
#endif /* SCTP_VTAG_TIMEWAIT_PER_STACK */

#ifdef _SCTP_NEEDS_CALLOUT_
	struct calloutlist callqueue;
#endif /* _SCTP_NEEDS_CALLOUT_ */

	uint32_t mbuf_track;

	/* for port allocations */
	uint16_t lastport;
	uint16_t lastlow;
	uint16_t lasthi;

};

extern uint32_t sctp_pegs[SCTP_NUMBER_OF_PEGS];
/*
 * Here we have all the relevant information for each SCTP entity created.
 * We will need to modify this as approprate. We also need to figure out
 * how to access /dev/random.
 */
struct sctp_pcb {
	int time_of_secret_change; /* number of seconds from timeval.tv_sec */
	uint32_t secret_key[SCTP_HOW_MANY_SECRETS][SCTP_NUMBER_OF_SECRETS];
	int size_of_a_cookie;

	int sctp_timeoutticks[SCTP_NUM_TMRS];
	int sctp_minrto;
	int sctp_maxrto;
	int initial_rto;

	int initial_init_rto_max;

	int32_t sctp_sws_sender;
	int32_t sctp_sws_receiver;

	/* various thresholds */
	/* Max times I will init at a guy */
	uint16_t max_init_times;

	/* Max times I will send before we consider someone dead */
	uint16_t max_send_times;

	uint16_t def_net_failure;

	/* number of streams to pre-open on a association */
	uint16_t pre_open_stream_count;
	uint16_t max_open_streams_intome;

	/* random number generator */
	uint32_t random_counter;
	uint8_t random_numbers[SCTP_SIGNATURE_ALOC_SIZE];
	uint8_t random_store[SCTP_SIGNATURE_ALOC_SIZE];

	/*
	 * This timer is kept running per endpoint.  When it fires it
	 * will change the secret key.  The default is once a hour
	 */
	struct sctp_timer signature_change;
	int def_cookie_life;
	/* defaults to 0 */
	int auto_close_time;
	uint32_t initial_sequence_debug;
	uint32_t adaption_layer_indicator;
	char store_at;
	uint8_t max_burst;
	char current_secret_number;
	char last_secret_number;
};

#ifndef SCTP_ALIGNMENT
#define SCTP_ALIGNMENT 32
#endif

#ifndef SCTP_ALIGNM1
#define SCTP_ALIGNM1 (SCTP_ALIGNMENT-1)
#endif

#define sctp_lport ip_inp.inp.inp_lport

struct sctp_inpcb {
	/*
	 * put an inpcb in front of it all, kind of a waste but we need
	 * to for compatability with all the other stuff.
	 */
	union {
		struct inpcb inp;
		char align[(sizeof(struct in6pcb) + SCTP_ALIGNM1) &
			  ~SCTP_ALIGNM1];
	} ip_inp;
	LIST_ENTRY(sctp_inpcb) sctp_list;	/* lists all endpoints */
	/* hash of all endpoints for model */
	LIST_ENTRY(sctp_inpcb) sctp_hash;

	/* count of local addresses bound, 0 if bound all */
	int laddr_count;
	/* list of addrs in use by the EP */
	struct sctpladdr sctp_addr_list;
	/* used for source address selection rotation */
	struct sctp_laddr *next_addr_touse;
	struct ifnet *next_ifn_touse;
	/* back pointer to our socket */
	struct socket *sctp_socket;
	uint32_t sctp_flags;			/* flag set */
	caddr_t lowest_tcb;			/* lowest/highest used to */
	caddr_t highest_tcb;			/* validate the asoc_id.  */
	struct sctp_pcb sctp_ep;		/* SCTP ep data */
	/* head of the hash of all associations */
	struct sctpasochead *sctp_tcbhash;
	u_long sctp_hashmark;
	/* head of the list of all associations */
	struct sctpasochead sctp_asoc_list;
	/* queue of TCB's waiting to stuff data up the socket */
	struct sctpsocketq sctp_queue_list;
	void *sctp_tcb_at_block;
	int  error_on_block;
	int32_t sctp_frag_point;
	uint32_t sctp_vtag_last;
	struct mbuf *pkt, *pkt_last, *sb_last_mpkt;
	struct mbuf *control;
#ifndef SCTP_VTAG_TIMEWAIT_PER_STACK
	struct sctpvtaghead vtag_timewait[SCTP_NUMBER_IN_VTAG_BLOCK];
#endif
#if !(defined(__FreeBSD__) || defined(__APPLE__))
#ifndef INP_IPV6
#define INP_IPV6	0x1
#endif
#ifndef INP_IPV4
#define INP_IPV4	0x2
#endif
	u_char inp_vflag;
	u_char inp_ip_ttl;
	u_char inp_ip_tos;
#endif
};

struct sctp_tcb {
	struct socket *sctp_socket;		/* back pointer to socket */
	struct sctp_inpcb *sctp_ep;		/* back pointer to ep */
	LIST_ENTRY(sctp_tcb) sctp_tcbhash;	/* next link in hash table */
	LIST_ENTRY(sctp_tcb) sctp_tcblist;	/* list of all of the TCB's */
	LIST_ENTRY(sctp_tcb) sctp_asocs;
	struct sctp_association asoc;
	uint16_t rport;			/* remote port in network format */
	uint16_t resv;
};


struct sctp_socket_q_list {
	struct sctp_tcb *tcb;
	TAILQ_ENTRY(sctp_socket_q_list) next_sq;
};



#if defined(_KERNEL) || (defined(__APPLE__) && defined(KERNEL))

extern struct sctp_epinfo sctppcbinfo;
extern int sctp_auto_asconf;

int SCTP6_ARE_ADDR_EQUAL(struct in6_addr *a, struct in6_addr *b);

void sctp_fill_pcbinfo(struct sctp_pcbinfo *);

struct sctp_nets *sctp_findnet(struct sctp_tcb *, struct sockaddr *);

struct sctp_inpcb *sctp_pcb_findep(struct sockaddr *, int);

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
int sctp_inpcb_bind(struct socket *, struct sockaddr *, struct thread *);
#else
int sctp_inpcb_bind(struct socket *, struct sockaddr *, struct proc *);
#endif

struct sctp_tcb *sctp_findassociation_addr(struct mbuf *, int, int,
    struct sctphdr *, struct sctp_chunkhdr *, struct sctp_inpcb **,
    struct sctp_nets **);

struct sctp_tcb *sctp_findassociation_addr_sa(struct sockaddr *,
	struct sockaddr *, struct sctp_inpcb **, struct sctp_nets **, int);

#ifdef SCTP_TCP_MODEL_SUPPORT
void sctp_move_pcb_and_assoc(struct sctp_inpcb *, struct sctp_inpcb *,
	struct sctp_tcb *);
#endif

/*
 * For this call ep_addr, the to is the destination endpoint address
 * of the peer (relative to outbound). The from field is only used if
 * the TCP model is enabled and helps distingush amongst the subset
 * bound (non-boundall). The TCP model MAY change the actual ep field,
 * this is why it is passed.
 */
struct sctp_tcb *sctp_findassociation_ep_addr(struct sctp_inpcb **,
	struct sockaddr *, struct sctp_nets **, struct sockaddr *);

struct sctp_tcb *sctp_findassociation_ep_asocid(struct sctp_inpcb *, caddr_t);

struct sctp_tcb *sctp_findassociation_ep_asconf(struct mbuf *, int, int,
    struct sctphdr *, struct sctp_inpcb **, struct sctp_nets **);
    
int sctp_inpcb_alloc(struct socket *);


int sctp_is_address_on_local_host(struct sockaddr *addr);

void sctp_inpcb_free(struct sctp_inpcb *, int);

struct sctp_tcb *sctp_aloc_assoc(struct sctp_inpcb *, struct sockaddr *,
	int, int *);

void sctp_free_assoc(struct sctp_inpcb *, struct sctp_tcb *);

int sctp_add_local_addr_ep(struct sctp_inpcb *, struct ifaddr *);

int sctp_insert_laddr(struct sctpladdr *, struct ifaddr *);

void sctp_remove_laddr(struct sctp_laddr *);

int sctp_del_local_addr_ep(struct sctp_inpcb *, struct ifaddr *);

int sctp_del_local_addr_ep_sa(struct sctp_inpcb *, struct sockaddr *);

int sctp_add_remote_addr(struct sctp_tcb *, struct sockaddr *, int, int);

int sctp_del_remote_addr(struct sctp_tcb *, struct sockaddr *);

void sctp_pcb_init(void);

void sctp_free_remote_addr(struct sctp_nets *);

struct sctp_tcb *sctp_findassociation_associd(caddr_t);

int sctp_add_local_addr_assoc(struct sctp_tcb *, struct ifaddr *);

int sctp_del_local_addr_assoc(struct sctp_tcb *, struct ifaddr *);

int sctp_del_local_addr_assoc_sa(struct sctp_tcb *, struct sockaddr *);

int sctp_load_addresses_from_init(struct sctp_tcb *, struct mbuf *, int, int,
    int, struct sctphdr *, struct sockaddr *);

int sctp_set_primary_addr(struct sctp_tcb *, struct sockaddr *, struct sctp_nets *);

int sctp_is_vtag_good(struct sctp_inpcb *, uint32_t, struct timeval *);

/*void sctp_drain(void);*/

int sctp_destination_is_reachable(struct sctp_tcb *, struct sockaddr *);

int sctp_add_to_socket_q(struct sctp_inpcb *, struct sctp_tcb *);

struct sctp_tcb *sctp_remove_from_socket_q(struct sctp_inpcb *);

#if defined(__APPLE__)
void	sctp_callout_alloc(struct sctp_timer *);
void	sctp_callout_free(struct callout *);
#endif

#endif /* _KERNEL */
#endif /* !__sctp_pcb_h__ */
