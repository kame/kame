/*	$KAME: sctp.h,v 1.1 2000/12/27 05:55:06 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#ifndef _NETINET_SCTP_H_
#define _NETINET_SCTP_H_

/*
 * RFC2960 Stream Control Transmission Protocol (SCTP)
 */

/* SCTP common header */
struct sctp_hdr {
	u_int16_t sh_sport;		/* source port */
	u_int16_t sh_dport;		/* destination port */
	u_int32_t sh_vtag;		/* verification tag */
	u_int32_t sh_cksum;		/* checksum */
} __attribute__((__packed__));

/* SCTP chunk */
struct sctp_chunk {
	u_int8_t sc_type;
	u_int8_t sc_flags;
	u_int16_t sc_len;
} __attribute__((__packed__));

#define SCTP_DATA		0  /* Payload Data (DATA) */
#define SCTP_INIT		1  /* Initiation (INIT) */
#define SCTP_INIT_ACK		2  /* Initiation Ack (INIT ACK) */
#define SCTP_SACK		3  /* Selective Ack (SACK) */
#define SCTP_HEARTBEAT		4  /* Heartbeat Request (HEARTBEAT) */
#define SCTP_HEARTBEAT_ACK	5  /* Heartbeat Ack (HEARTBEAT ACK) */
#define SCTP_ABORT		6  /* Abort (ABORT) */
#define SCTP_SHUTDOWN		7  /* Shutdown (SHUTDOWN) */
#define SCTP_SHUTDOWN_ACK	8  /* Shutdown Ack (SHUTDOWN ACK) */
#define SCTP_ERROR		9  /* Operation Error (ERROR) */
#define SCTP_COOKIE_ECHO	10 /* State Cookie (COOKIE ECHO) */
#define SCTP_COOKIE_ACK		11 /* Cookie Ack (COOKIE ACK) */
#define SCTP_ECNE		12 /* rsvd: ECN Echo (ECNE) */
#define SCTP_CWR		13 /* rsvd: Congestion Window Reduced (CWR) */
#define SCTP_SHUTDOWN_FIN	14 /* Shutdown Complete (SHUTDOWN COMPLETE) */

#define SCTP_TYPE(o)		((o) & 0xc0)
#define SCTP_TYPE_DISCARD	0x00	/* drop packet */
#define SCTP_TYPE_ERROR		0x40	/* drop, Unrecognized Parameter Type */
#define SCTP_TYPE_SKIP		0x80	/* skip */
#define SCTP_TYPE_SKIPERR	0xc0	/* skip, Unrecognized Chunk Type */

/* SCTP optional/variable length parameter */
struct sctp_vl {
	u_int16_t sv_type;
	u_int16_t sv_len;
} __attribute__((__packed__));

#define SCTP_VL_TYPE(o)		((o) & 0xc000)
#define SCTP_VL_TYPE_DISCARD	0x0000	/* drop packet */
#define SCTP_VL_TYPE_ERROR	0x4000	/* drop, Unrecognized Parameter Type */
#define SCTP_VL_TYPE_SKIP	0x8000	/* skip */
#define SCTP_VL_TYPE_SKIPERR	0xc000	/* skip, Unrecognized Parameter Type */

/* SCTP_DATA */
struct sctp_chunk_data {
	struct sctp_chunk sc_data_chunk;
#define sc_data_flags	sc_data_chunk.sc_flags
#define SCTP_DATA_U	0x04		/* unordered */
#define SCTP_DATA_B	0x02		/* beginning fragment */
#define SCTP_DATA_E	0x01		/* ending fragment */
	u_int32_t sc_data_tsn;		/* TSN */
	u_int16_t sc_data_sid;		/* stream identifier */
	u_int16_t sc_data_sseq;		/* stream sequence number */
	u_int32_t sc_data_protoid;	/* payload protocol identifier */
} __attribute__((__packed__));

/* SCTP_INIT, SCTP_INIT_ACK */
struct sctp_chunk_init {
	struct sctp_chunk sc_init_chunk;
	u_int32_t sc_init_itag;		/* initiate tag */
	u_int32_t sc_init_arwnd;	/* advertised receiver window credit */
	u_int16_t sc_init_ostream;	/* # of outbound streams */
	u_int16_t sc_init_istream;	/* # of inbound streams */
	u_int32_t sc_init_tsn;		/* initial TSN */
} __attribute__((__packed__));

#define SCTPOPT_HEARTBEAT	1	/* Heartbeat Info */
#define SCTPOPT_IPV4ADDR	5	/* IPv4 Address */
#define SCTPOPT_IPV6ADDR	6	/* IPv6 Address */
#define SCTPOPT_STATECOOKIE	7	/* State Cookie */
#define SCTPOPT_COOKIE		9	/* Cookie Preservative */
#define SCTPOPT_ECN		0x8000	/* Reserved for ECN Capable */
#define SCTPOPT_HOSTNAME	11	/* Host Name Address */
#define SCTPOPT_ADDRTYPE	12	/* Supported Address Types */

/* SCTP_SACK */
struct sctp_chunk_sack {
	struct sctp_chunk sc_sack_chunk;
	u_int32_t sc_sack_tsn;		/* Cumulative TSN Ack */
	u_int32_t sc_sack_arwnd;	/* advertised receiver window credit */
	u_int16_t sc_sack_gap;		/* # of gap ack blocks */
	u_int16_t sc_sack_duptsn;	/* # of duplicated TSNs */
} __attribute__((__packed__));

/* SCTP_HEARTBEAT, SCTP_HEARTBEAT_ACK - use sctp_chunk */

/* SCTP_ABORT - use sctp_chunk */
#define SCTP_ABORT_T	0x01

/* SCTP_SHUTDOWN */
struct sctp_chunk_shutdown {
	struct sctp_chunk sc_shutdown_chunk;
	u_int32_t sc_chunk_tsn;		/* Cumulative TSN Ack */
} __attribute__((__packed__));

/* SCTP_SHUTDOWN_ACK - use sctp_chunk */

/* SCTP_ERROR - use sctp_chunk */

/* SCTP_COOKIE_ECHO - use sctp_chunk */

/* SCTP_COOKIE_ACK - use sctp_chunk */

/* SCTP_SHUTDOWN_FIN - use sctp_chunk */
#define SCTP_SHUTDOWN_FIN_T	0x01

#endif /* _NETINET_SCTP_H_ */
