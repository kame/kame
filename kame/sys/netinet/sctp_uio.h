/*	$KAME: sctp_uio.h,v 1.8 2003/08/29 06:37:38 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_uio.h,v 1.40 2002/04/04 16:34:41 lei Exp	*/

#ifndef __sctp_uio_h__
#define __sctp_uio_h__

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
#include <sys/types.h>

typedef caddr_t sctp_assoc_t;

/* On/Off setup for subscription to events */
struct sctp_event_subscribe {
	u_int8_t sctp_data_io_event;
	u_int8_t sctp_association_event;
	u_int8_t sctp_address_event;
	u_int8_t sctp_send_failure_event;
	u_int8_t sctp_peer_error_event;
	u_int8_t sctp_shutdown_event;
	u_int8_t sctp_partial_delivery_event;
	u_int8_t sctp_adaption_layer_event;
};

/* ancillary data types */
#define SCTP_INIT	0x0001
#define SCTP_SNDRCV	0x0002

/*
 * ancillary data structures
 */
struct sctp_initmsg {
	u_int16_t sinit_num_ostreams;
	u_int16_t sinit_max_instreams;
	u_int16_t sinit_max_attempts;
	u_int16_t sinit_max_init_timeo;
};

struct sctp_sndrcvinfo {
	u_int16_t sinfo_stream;
	u_int16_t sinfo_ssn;
	u_int16_t sinfo_flags;
	u_int32_t sinfo_ppid;
	u_int32_t sinfo_context;
	u_int32_t sinfo_timetolive;
	u_int32_t sinfo_tsn;
	u_int32_t sinfo_cumtsn;
	sctp_assoc_t sinfo_assoc_id;
};


/* send/recv flags */
/* MSG_EOF (0x0100) is reused from sys/socket.h */
#define MSG_PR_SCTP_TTL	0x0400	/* Partial Reliable on this msg */
#define MSG_PR_SCTP_BUF	0x0800	/* Buffer based PR-SCTP */
#ifndef MSG_EOF
#define MSG_EOF 	0x1000	/* Start shutdown procedures */
#endif
#define MSG_UNORDERED 	0x2000	/* Message is un-ordered */
#define MSG_ADDR_OVER	0x4000	/* Override the primary-address */
#define MSG_ABORT	0x8000	/* Send an ABORT to peer */

/* Stat's */
struct sctp_pcbinfo {
	u_int32_t ep_count;
	u_int32_t asoc_count;
	u_int32_t laddr_count;
	u_int32_t raddr_count;
	u_int32_t chk_count;
	u_int32_t sockq_count;
	u_int32_t mbuf_track;
};


/*
 * notification event structures
 */
struct sctp_assoc_change {
	u_int16_t sac_type;
	u_int16_t sac_flags;
	u_int32_t sac_length;
	u_int16_t sac_state;
	u_int16_t sac_error;
	u_int16_t sac_outbound_streams;
	u_int16_t sac_inbound_streams;
	sctp_assoc_t sac_assoc_id;
};
struct sctp_sockstat {
	sctp_assoc_t ss_assoc_id;
	u_int32_t ss_total_sndbuf;
	u_int32_t ss_total_mbuf_sndbuf;
	u_int32_t ss_total_recv_buf;
};
/* sac_state values */
#define SCTP_COMM_UP		0x0001
#define SCTP_COMM_LOST		0x0002
#define SCTP_RESTART		0x0003
#define SCTP_SHUTDOWN_COMP	0x0004
#define SCTP_CANT_STR_ASSOC	0x0005


struct sctp_paddr_change {
	u_int16_t spc_type;
	u_int16_t spc_flags;
	u_int32_t spc_length;
	struct sockaddr_storage spc_aaddr;
	u_int32_t spc_state;
	u_int32_t spc_error;
	sctp_assoc_t spc_assoc_id;
};
/* paddr state values */
#define SCTP_ADDR_AVAILABLE	0x0001
#define SCTP_ADDR_UNREACHABLE	0x0002
#define SCTP_ADDR_REMOVED	0x0003
#define SCTP_ADDR_ADDED		0x0004
#define SCTP_ADDR_MADE_PRIM	0x0005
#define SCTP_ADDR_CONFIRMED	0x0006


struct sctp_remote_error {
	u_int16_t sre_type;
	u_int16_t sre_flags;
	u_int32_t sre_length;
	u_int16_t sre_error;
	sctp_assoc_t sre_assoc_id;
	u_int8_t  sre_data[4];
};

struct sctp_send_failed {
	u_int16_t ssf_type;
	u_int16_t ssf_flags;
	u_int32_t ssf_length;
	u_int32_t ssf_error;
	struct sctp_sndrcvinfo ssf_info;
	sctp_assoc_t ssf_assoc_id;
	u_int8_t ssf_data[4];
};
/* flag that indicates state of data */
#define SCTP_DATA_UNSENT	0x0001	/* inqueue never on wire */
#define SCTP_DATA_SENT		0x0002	/* on wire at failure */


struct sctp_shutdown_event {
	u_int16_t	sse_type;
	u_int16_t	sse_flags;
	u_int32_t	sse_length;
	sctp_assoc_t	sse_assoc_id;
};


struct sctp_adaption_event {
	u_int16_t	sai_type;
	u_int16_t	sai_flags;
	u_int32_t	sai_length;
	u_int32_t	sai_adaption_ind;
	sctp_assoc_t	sai_assoc_id;
};

struct sctp_setadaption {
	u_int32_t	ssb_adaption_ind;
};

struct sctp_pdapi_event {
	u_int16_t	pdapi_type;
	u_int16_t	pdapi_flags;
	u_int32_t	pdapi_length;
	u_int32_t	pdapi_indication;
	sctp_assoc_t	pdapi_assoc_id;
};

/* pdapi indications */
#define SCTP_PARTIAL_DELIVERY_ABORTED	0x0001


/* notification types */
#define SCTP_ASSOC_CHANGE		0x0001
#define SCTP_PEER_ADDR_CHANGE		0x0002
#define SCTP_REMOTE_ERROR		0x0003
#define SCTP_SEND_FAILED		0x0004
#define SCTP_SHUTDOWN_EVENT		0x0005
#define SCTP_ADAPTION_INDICATION	0x0006
#define SCTP_PARTIAL_DELIVERY_EVENT	0x0007

struct sctp_tlv {
	u_int16_t sn_type;
	u_int16_t sn_flags;
	u_int32_t sn_length;
};


/* notification event */
union sctp_notification {
	struct sctp_tlv sn_header;
	struct sctp_assoc_change sn_assoc_change;
	struct sctp_paddr_change sn_paddr_change;
	struct sctp_remote_error sn_remote_error;
	struct sctp_send_failed	sn_send_failed;
	struct sctp_shutdown_event sn_shutdown_event;
	struct sctp_adaption_event sn_adaption_event;
	struct sctp_pdapi_event sn_pdapi_event;
};

/*
 * socket option structs
 */
#define SCTP_ISSUE_HB 0xffffffff	/* get a on-demand hb */
#define SCTP_NO_HB    0x0		/* turn off hb's */

struct sctp_paddrparams {
	sctp_assoc_t spp_assoc_id;
	struct sockaddr_storage spp_address;
	u_int32_t spp_hbinterval;
	u_int16_t spp_pathmaxrxt;
};

struct sctp_paddrinfo {
	sctp_assoc_t spinfo_assoc_id;
	struct sockaddr_storage spinfo_address;
	int32_t spinfo_state;
	u_int32_t spinfo_cwnd;
	u_int32_t spinfo_srtt;
	u_int32_t spinfo_rto;
	u_int32_t spinfo_mtu;
};

struct sctp_rtoinfo {
	sctp_assoc_t srto_assoc_id;
	u_int32_t srto_initial;
	u_int32_t srto_max;
	u_int32_t srto_min;
};

struct sctp_assocparams {
	sctp_assoc_t sasoc_assoc_id;
	u_int16_t sasoc_asocmaxrxt;
        u_int16_t sasoc_number_peer_destinations;
        u_int32_t sasoc_peer_rwnd;
        u_int32_t sasoc_local_rwnd;
        u_int32_t sasoc_cookie_life;
};

struct sctp_setprim {
	sctp_assoc_t ssp_assoc_id;
	struct sockaddr_storage ssp_addr;
};

struct sctp_setpeerprim {
	sctp_assoc_t sspp_assoc_id;
	struct sockaddr_storage sspp_addr;
};

struct sctp_getaddresses {
	sctp_assoc_t sget_assoc_id;
	/* addr is filled in for N * sockaddr_storage */
	struct sockaddr addr[1];
};

struct sctp_setstrm_timeout {
	sctp_assoc_t ssto_assoc_id;
	u_int32_t ssto_timeout;
	u_int32_t ssto_streamid_start;
	u_int32_t ssto_streamid_end;
};

struct sctp_status {
	sctp_assoc_t sstat_assoc_id;
	int32_t sstat_state;
	u_int32_t sstat_rwnd;
	u_int16_t sstat_unackdata;
	u_int16_t sstat_penddata;
        u_int16_t sstat_instrms;
        u_int16_t sstat_outstrms;
        u_int32_t sstat_fragmentation_point;
	struct sctp_paddrinfo sstat_primary;
};


struct sctp_cwnd_log{
	struct sctp_nets *net;
	u_int32_t cwnd_new_value;
	int cwnd_augment;
	u_int8_t from;
	u_int8_t resv[3];
};

struct sctp_cwnd_log_req{
	int num_in_log;     /* Number in log */
	int num_ret;        /* Number returned */
	int start_at;       /* start at this one */
	int end_at;         /* end at this one */
	struct sctp_cwnd_log log[0];
};

/*
 * API system calls
 */
#ifndef _KERNEL

__BEGIN_DECLS
int	sctp_peeloff	__P((int, sctp_assoc_t *));
int	sctp_bindx	__P((int, struct sockaddr *, int, int));
int     sctp_connectx   __P((int, struct sockaddr *, int));
int	sctp_getpaddrs	__P((int, sctp_assoc_t, struct sockaddr **));
void	sctp_freepaddrs	__P((struct sockaddr *));
int	sctp_getladdrs	__P((int, sctp_assoc_t, struct sockaddr **));
void	sctp_freeladdrs	__P((struct sockaddr *));
int     sctp_opt_info   __P((int, sctp_assoc_t, int, void *, size_t *));
int     sctp_sendmsg    __P((int, void *, size_t, struct sockaddr *,
	socklen_t, uint32_t, uint32_t, uint16_t, uint32_t, uint32_t));
int     sctp_recvmsg	__P((int, void *, size_t *, struct sockaddr *,
	socklen_t *, struct sctp_sndrcvinfo *, int *));

__END_DECLS



#endif /* !_KERNEL */

#endif /* !__sctp_uio_h__ */
