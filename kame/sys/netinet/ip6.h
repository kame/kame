/*	$KAME: ip6.h,v 1.52 2003/12/05 01:35:16 keiichi Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_IP6_H_
#define _NETINET_IP6_H_

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			u_int32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			u_int16_t ip6_un1_plen;	/* payload length */
			u_int8_t  ip6_un1_nxt;	/* next header */
			u_int8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		u_int8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
} __attribute__((__packed__));

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0

#if BYTE_ORDER == BIG_ENDIAN
#define IPV6_FLOWINFO_MASK	0x0fffffff	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0x000fffff	/* flow label (20 bits) */
#else
#if BYTE_ORDER == LITTLE_ENDIAN
#define IPV6_FLOWINFO_MASK	0xffffff0f	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0xffff0f00	/* flow label (20 bits) */
#endif /* LITTLE_ENDIAN */
#endif
#if 1
/* ECN bits proposed by Sally Floyd */
#define IP6TOS_CE		0x01	/* congestion experienced */
#define IP6TOS_ECT		0x02	/* ECN-capable transport */
#endif

/*
 * Extension Headers
 */

struct	ip6_ext {
	u_int8_t ip6e_nxt;
	u_int8_t ip6e_len;
} __attribute__((__packed__));

/* Hop-by-Hop options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_hbh {
	u_int8_t ip6h_nxt;	/* next header */
	u_int8_t ip6h_len;	/* length in units of 8 octets */
	/* followed by options */
} __attribute__((__packed__));

/* Destination options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_dest {
	u_int8_t ip6d_nxt;	/* next header */
	u_int8_t ip6d_len;	/* length in units of 8 octets */
	/* followed by options */
} __attribute__((__packed__));

/* Option types and related macros */
#define IP6OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6OPT_PADN		0x01	/* 00 0 00001 */
#define IP6OPT_JUMBO		0xC2	/* 11 0 00010 = 194 */
#define IP6OPT_NSAP_ADDR	0xC3	/* 11 0 00011 */
#define IP6OPT_TUNNEL_LIMIT	0x04	/* 00 0 00100 */
#ifndef _KERNEL
#define IP6OPT_RTALERT		0x05	/* 00 0 00101 (KAME definition) */
#endif
#define IP6OPT_ROUTER_ALERT	0x05	/* 00 0 00101 (2292bis, recommended) */

#define IP6OPT_RTALERT_LEN	4
#define IP6OPT_RTALERT_MLD	0	/* Datagram contains an MLD message */
#define IP6OPT_RTALERT_RSVP	1	/* Datagram contains an RSVP message */
#define IP6OPT_RTALERT_ACTNET	2 	/* contains an Active Networks msg */
#define IP6OPT_MINLEN		2

#define IP6OPT_HOME_ADDRESS	0xc9	/* 11 0 01001 */
#define IP6OPT_EID		0x8a	/* 10 0 01010 */

#define IP6OPT_TYPE(o)		((o) & 0xC0)
#define IP6OPT_TYPE_SKIP	0x00
#define IP6OPT_TYPE_DISCARD	0x40
#define IP6OPT_TYPE_FORCEICMP	0x80
#define IP6OPT_TYPE_ICMP	0xC0

#define IP6OPT_MUTABLE		0x20

/* IPv6 options: common part */
struct ip6_opt {
	u_int8_t ip6o_type;
	u_int8_t ip6o_len;
} __attribute__((__packed__));

/* Jumbo Payload Option */
struct ip6_opt_jumbo {
	u_int8_t ip6oj_type;
	u_int8_t ip6oj_len;
	u_int8_t ip6oj_jumbo_len[4];
} __attribute__((__packed__));
#define IP6OPT_JUMBO_LEN 6

/* NSAP Address Option */
struct ip6_opt_nsap {
	u_int8_t ip6on_type;
	u_int8_t ip6on_len;
	u_int8_t ip6on_src_nsap_len;
	u_int8_t ip6on_dst_nsap_len;
	/* followed by source NSAP */
	/* followed by destination NSAP */
} __attribute__((__packed__));

/* Tunnel Limit Option */
struct ip6_opt_tunnel {
	u_int8_t ip6ot_type;
	u_int8_t ip6ot_len;
	u_int8_t ip6ot_encap_limit;
} __attribute__((__packed__));

/* Router Alert Option */
struct ip6_opt_router {
	u_int8_t ip6or_type;
	u_int8_t ip6or_len;
	u_int8_t ip6or_value[2];
} __attribute__((__packed__));
/* Router alert values (in network byte order) */
#if BYTE_ORDER == BIG_ENDIAN
#define IP6_ALERT_MLD	0x0000
#define IP6_ALERT_RSVP	0x0001
#define IP6_ALERT_AN	0x0002
#else
#if BYTE_ORDER == LITTLE_ENDIAN
#define IP6_ALERT_MLD	0x0000
#define IP6_ALERT_RSVP	0x0100
#define IP6_ALERT_AN	0x0200
#endif /* LITTLE_ENDIAN */
#endif

/* Home Address Option */
struct ip6_opt_home_address {
	u_int8_t ip6oh_type;
	u_int8_t ip6oh_len;
	u_int8_t ip6oh_addr[16];/* Home Address */
	/* followed by sub-options */
} __attribute__((__packed__));

/* Routing header */
struct ip6_rthdr {
	u_int8_t  ip6r_nxt;	/* next header */
	u_int8_t  ip6r_len;	/* length in units of 8 octets */
	u_int8_t  ip6r_type;	/* routing type */
	u_int8_t  ip6r_segleft;	/* segments left */
	/* followed by routing type specific data */
} __attribute__((__packed__));

/* Type 0 Routing header */
struct ip6_rthdr0 {
	u_int8_t  ip6r0_nxt;		/* next header */
	u_int8_t  ip6r0_len;		/* length in units of 8 octets */
	u_int8_t  ip6r0_type;		/* always zero */
	u_int8_t  ip6r0_segleft;	/* segments left */
	u_int32_t  ip6r0_reserved;	/* reserved field */
	/* followed by up to 127 struct in6_addr */
} __attribute__((__packed__));

/* Type 2 Routing header for Mobile IPv6 */
struct ip6_rthdr2 {
	u_int8_t  ip6r2_nxt;		/* next header */
	u_int8_t  ip6r2_len;		/* always 2 */
	u_int8_t  ip6r2_type;		/* always 2 */
	u_int8_t  ip6r2_segleft;	/* 0 or 1 */
	u_int32_t  ip6r2_reserved;	/* reserved field */
	/* followed by one struct in6_addr */
} __attribute__((__packed__));

/* Fragment header */
struct ip6_frag {
	u_int8_t  ip6f_nxt;		/* next header */
	u_int8_t  ip6f_reserved;	/* reserved field */
	u_int16_t ip6f_offlg;		/* offset, reserved, and flag */
	u_int32_t ip6f_ident;		/* identification */
} __attribute__((__packed__));

#if BYTE_ORDER == BIG_ENDIAN
#define IP6F_OFF_MASK		0xfff8	/* mask out offset from _offlg */
#define IP6F_RESERVED_MASK	0x0006	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0001	/* more-fragments flag */
#else /* BYTE_ORDER == LITTLE_ENDIAN */
#define IP6F_OFF_MASK		0xf8ff	/* mask out offset from _offlg */
#define IP6F_RESERVED_MASK	0x0600	/* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0100	/* more-fragments flag */
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

/* Mobility header */
struct ip6_mh {
	u_int8_t  ip6mh_proto;	  /* following payload protocol (for PG) */
	u_int8_t  ip6mh_len;	  /* length in units of 8 octets */
	u_int8_t  ip6mh_type;	  /* message type */
	u_int8_t  ip6mh_reserved;
	u_int16_t ip6mh_cksum;    /* sum of IPv6 pseudo-header and MH */
	/* followed by type specific data */
} __attribute__((__packed__));

/* Mobility Header min. */
#define IP6M_MINLEN	8

/* Mobility header message types */
#define IP6_MH_TYPE_BRR		0
#define IP6_MH_TYPE_HOTI	1
#define IP6_MH_TYPE_COTI	2
#define IP6_MH_TYPE_HOT		3
#define IP6_MH_TYPE_COT		4
#define IP6_MH_TYPE_BU		5
#define IP6_MH_TYPE_BACK	6
#define IP6_MH_TYPE_BERROR	7
#define IP6_MH_TYPE_MAX		7

/* Binding Refresh Request (BRR) message */
struct ip6_mh_binding_request {
	struct ip6_mh ip6mhbr_hdr;
	u_int16_t     ip6mhbr_reserved;
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhbr_proto ip6mhbr_hdr.ip6mh_proto
#define ip6mhbr_len ip6mhbr_hdr.ip6mh_len
#define ip6mhbr_type ip6mhbr_hdr.ip6mh_type
#define ip6mhbr_reserved0 ip6mhbr_hdr.ip6mh_reserved
#define ip6mhbr_cksum ip6mhbr_hdr.ip6mh_cksum
#endif /* _KERNEL */

/* Home Test Init (HoTI) message */
struct ip6_mh_home_test_init {
	struct ip6_mh ip6mhhti_hdr;
	u_int16_t     ip6mhhti_reserved;
	union {
		u_int8_t  __cookie8[8];
		u_int32_t __cookie32[2];
	} __ip6mhhti_cookie;
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhhti_proto ip6mhhti_hdr.ip6mh_proto
#define ip6mhhti_len ip6mhhti_hdr.ip6mh_len
#define ip6mhhti_type ip6mhhti_hdr.ip6mh_type
#define ip6mhhti_reserved0 ip6mhhti_hdr.ip6mh_reserved
#define ip6mhhti_cksum ip6mhhti_hdr.ip6mh_cksum
#define ip6mhhti_cookie8 __ip6mhhti_cookie.__cookie8
#endif /* _KERNEL */

/* Care-of Test Init (CoTI) message */
struct ip6_mh_careof_test_init {
	struct ip6_mh ip6mhcti_hdr;
	u_int16_t     ip6mhcti_reserved;
	union {
		u_int8_t  __cookie8[8];
		u_int32_t __cookie32[2];
	} __ip6mhcti_cookie;
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhcti_proto ip6mhcti_hdr.ip6mh_proto
#define ip6mhcti_len ip6mhcti_hdr.ip6mh_len
#define ip6mhcti_type ip6mhcti_hdr.ip6mh_type
#define ip6mhcti_reserved0 ip6mhcti_hdr.ip6mh_reserved
#define ip6mhcti_cksum ip6mhcti_hdr.ip6mh_cksum
#define ip6mhcti_cookie8 __ip6mhcti_cookie.__cookie8
#endif /* _KERNEL */

/* Home Test (HoT) message */
struct ip6_mh_home_test {
	struct ip6_mh ip6mhht_hdr;
	u_int16_t     ip6mhht_nonce_index; /* idx of the CN nonce list array */
	union {
		u_int8_t  __cookie8[8];
		u_int32_t __cookie32[2];
	} __ip6mhht_cookie;
	union {
		u_int8_t  __token8[8];
		u_int32_t __token32[2];
	} __ip6mhht_token;
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhht_proto ip6mhht_hdr.ip6mh_proto
#define ip6mhht_len ip6mhht_hdr.ip6mh_len
#define ip6mhht_type ip6mhht_hdr.ip6mh_type
#define ip6mhht_reserved0 ip6mhht_hdr.ip6mh_reserved
#define ip6mhht_cksum ip6mhht_hdr.ip6mh_cksum
#define ip6mhht_cookie8 __ip6mhht_cookie.__cookie8
#define ip6mhht_token8 __ip6mhht_token.__token8
#endif /* _KERNEL */

/* Care-of Test (CoT) message */
struct ip6_mh_careof_test {
	struct ip6_mh ip6mhct_hdr;
	u_int16_t     ip6mhct_nonce_index; /* idx of the CN nonce list array */
	union {
		u_int8_t  __cookie8[8];
		u_int32_t __cookie32[2];
	} __ip6mhct_cookie;
	union {
		u_int8_t  __token8[8];
		u_int32_t __token32[2];
	} __ip6mhct_token;
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhct_proto ip6mhct_hdr.ip6mh_proto
#define ip6mhct_len ip6mhct_hdr.ip6mh_len
#define ip6mhct_type ip6mhct_hdr.ip6mh_type
#define ip6mhct_reserved0 ip6mhct_hdr.ip6mh_reserved
#define ip6mhct_cksum ip6mhct_hdr.ip6mh_cksum
#define ip6mhct_cookie8 __ip6mhct_cookie.__cookie8
#define ip6mhct_token8 __ip6mhct_token.__token8
#endif /* _KERNEL */

/* Binding Update (BU) message */
struct ip6_mh_binding_update {
	struct ip6_mh ip6mhbu_hdr;
	u_int16_t     ip6mhbu_seqno;	/* sequence number */
	u_int16_t     ip6mhbu_flags;	/* IP6MU_* flags */
	u_int16_t     ip6mhbu_lifetime;	/* in units of 4 seconds */
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhbu_proto ip6mhbu_hdr.ip6mh_proto
#define ip6mhbu_len ip6mhbu_hdr.ip6mh_len
#define ip6mhbu_type ip6mhbu_hdr.ip6mh_type
#define ip6mhbu_reserved0 ip6mhbu_hdr.ip6mh_reserved
#define ip6mhbu_cksum ip6mhbu_hdr.ip6mh_cksum
#endif /* _KERNEL */

/* Binding Update flags */
#if BYTE_ORDER == BIG_ENDIAN
#define IP6MU_ACK	0x8000	/* request a binding ack */
#define IP6MU_HOME	0x4000	/* home registration */
#define IP6MU_LINK	0x2000	/* link-local address compatibility */
#define IP6MU_KEY	0x1000	/* key management mobility compatibility */
#define IP6MU_CLONED	0x0100
#endif /* BIG_ENDIAN */
#if BYTE_ORDER == LITTLE_ENDIAN
#define IP6MU_ACK	0x0080	/* request a binding ack */
#define IP6MU_HOME	0x0040	/* home registration */
#define IP6MU_LINK	0x0020	/* link-local address compatibility */
#define IP6MU_KEY	0x0010	/* key management mobility compatibility */
#define IP6MU_CLONED	0x0001
#endif /* LITTLE_ENDIAN */

/* Binding Acknowledgement (BA) message */
struct ip6_mh_binding_ack {
	struct ip6_mh ip6mhba_hdr;
	u_int8_t      ip6mhba_status;	/* status code */
	u_int8_t      ip6mhba_flags;
	u_int16_t     ip6mhba_seqno;	/* sequence number */
	u_int16_t     ip6mhba_lifetime;	/* in units of 4 seconds */
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhba_proto ip6mhba_hdr.ip6mh_proto
#define ip6mhba_len ip6mhba_hdr.ip6mh_len
#define ip6mhba_type ip6mhba_hdr.ip6mh_type
#define ip6mhba_reserved0 ip6mhba_hdr.ip6mh_reserved
#define ip6mhba_cksum ip6mhba_hdr.ip6mh_cksum
#endif /* _KERNEL */

/* Binding Ack status codes */
#define IP6_MH_BAS_ACCEPTED		0   /* Binding Update accepted */
#define IP6_MH_BAS_PRFX_DISCOV		1   /* Accepted, but prefix discovery required */
#define IP6_MH_BAS_ERRORBASE		128 /* ERROR BASE */
#define IP6_MH_BAS_UNSPECIFIED		128 /* Reason unspecified */
#define IP6_MH_BAS_PROHIBIT		129 /* Administratively prohibited */
#define IP6_MH_BAS_INSUFFICIENT		130 /* Insufficient resources */
#define IP6_MH_BAS_HA_NOT_SUPPORTED	131 /* Home registration not supported */
#define IP6_MH_BAS_NOT_HOME_SUBNET	132 /* Not home subnet */
#define IP6_MH_BAS_NOT_HA		133 /* Not home agent for this mobile node */
#define IP6_MH_BAS_DAD_FAILED		134 /* Duplicate Address Detection failed */
#define IP6_MH_BAS_SEQNO_BAD		135 /* Sequence number out of window */
#define IP6_MH_BAS_HOME_NI_EXPIRED	136 /* Expired Home Nonce Index */
#define IP6_MH_BAS_COA_NI_EXPIRED	137 /* Expired Care-of Nonce Index */
#define IP6_MH_BAS_NI_EXPIRED		138 /* Expired Nonces */
#define IP6_MH_BAS_REG_NOT_ALLOWED	139 /* Registration type change disallowed */

/* Binding Error (BE) message */
struct ip6_mh_binding_error {
	struct ip6_mh   ip6mhbe_hdr;
	u_int8_t        ip6mhbe_status;		/* status code */
	u_int8_t        ip6mhbe_reserved;
	struct in6_addr ip6mhbe_homeaddr;
	/* followed by mobility options */
} __attribute__((__packed__));
#ifdef _KERNEL
#define ip6mhbe_proto ip6mhbe_hdr.ip6mh_proto
#define ip6mhbe_len ip6mhbe_hdr.ip6mh_len
#define ip6mhbe_type ip6mhbe_hdr.ip6mh_type
#define ip6mhbe_reserved0 ip6mhbe_hdr.ip6mh_reserved
#define ip6mhbe_cksum ip6mhbe_hdr.ip6mh_cksum
#endif /* _KERNEL */

/* Binding Error status codes */
#define IP6_MH_BES_UNKNOWN_HAO		1
#define IP6_MH_BES_UNKNOWN_MH		2

/* Mobility options */
struct ip6_mh_opt {
	u_int8_t ip6mhopt_type;
	u_int8_t ip6mhopt_len;
	/* followed by option data */
} __attribute__((__packed__));

/* Mobility option type */
#define IP6_MHOPT_PAD1		0	/* Pad1 */
#define IP6_MHOPT_PADN		1	/* PadN */
#define IP6_MHOPT_BREFRESH	2	/* Binding Refresh Advice */
#define IP6_MHOPT_ALTCOA	3	/* Alternate Care-of Address */
#define IP6_MHOPT_NONCEID	4	/* Nonce Indices */
#define IP6_MHOPT_BAUTH		5	/* Binding Authorization Data */

/* Binding Refresh Advice */
struct ip6_mh_opt_refresh_advice {
	u_int8_t ip6mora_type;
	u_int8_t ip6mora_len;
	u_int8_t ip6mora_interval[2];	/* Refresh Interval (units of 4 sec) */
} __attribute__((__packed__));

/* Alternate Care-of Address */
struct ip6_mh_opt_altcoa {
	u_int8_t ip6moa_type;
	u_int8_t ip6moa_len;
	u_int8_t ip6moa_addr[16];	/* Alternate Care-of Address */
} __attribute__((__packed__));

/* Nonce Indices */
struct ip6_mh_opt_nonce_index {
	u_int8_t ip6moni_type;
	u_int8_t ip6moni_len;
	u_int8_t ip6moni_home_nonce[2];
	u_int8_t ip6moni_coa_nonce[2];
} __attribute__((__packed__));

/* Binding Authorization Data */
struct ip6_mh_opt_auth_data {
	u_int8_t ip6moad_type;
	u_int8_t ip6moad_len;
	/* followed by authenticator data */
} __attribute__((__packed__));
#define IP6MOPT_AUTHDATA_SIZE (sizeof(struct ip6_mh_opt_auth_data) + MIP6_AUTHENTICATOR_LEN)

/*
 * Internet implementation parameters.
 */
#define IPV6_MAXHLIM	255	/* maximun hoplimit */
#define IPV6_DEFHLIM	64	/* default hlim */
#define IPV6_FRAGTTL	120	/* ttl for fragment packets, in slowtimo tick */
#define IPV6_HLIMDEC	1	/* subtracted when forwaeding */

#define IPV6_MMTU	1280	/* minimal MTU and reassembly. 1024 + 256 */
#define IPV6_MAXPACKET	65535	/* ip6 max packet size without Jumbo payload*/

#ifdef _KERNEL
/*
 * IP6_EXTHDR_CHECK ensures that region between the IP6 header and the
 * target header (including IPv6 itself, extension headers and
 * TCP/UDP/ICMP6 headers) are continuous. KAME requires drivers
 * to store incoming data into one internal mbuf or one or more external
 * mbufs(never into two or more internal mbufs). Thus, the third case is
 * supposed to never be matched but is prepared just in case.
 */

#define IP6_EXTHDR_CHECK(m, off, hlen, ret)				\
do {									\
    if ((m)->m_next != NULL) {						\
	if ((m)->m_len < (off) + (hlen)) {				\
		ip6stat.ip6s_exthdrtoolong++;				\
		m_freem(m);						\
		return ret;						\
	}								\
    } else {								\
	if ((m)->m_len < (off) + (hlen)) {				\
		ip6stat.ip6s_tooshort++;				\
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);	\
		m_freem(m);						\
		return ret;						\
	}								\
    }									\
} while (/*CONSTCOND*/ 0)

#ifdef PULLDOWN_STAT
#define IP6_EXTHDR_STAT(x)	x
#else
#define IP6_EXTHDR_STAT(x)
#endif

/*
 * IP6_EXTHDR_GET ensures that intermediate protocol header (from "off" to
 * "len") is located in single mbuf, on contiguous memory region.
 * The pointer to the region will be returned to pointer variable "val",
 * with type "typ".
 * IP6_EXTHDR_GET0 does the same, except that it aligns the structure at the
 * very top of mbuf.  GET0 is likely to make memory copy than GET.
 *
 * XXX we're now testing this, needs m_pulldown()
 */
#define IP6_EXTHDR_GET(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	int tmp;							\
	IP6_EXTHDR_STAT(mbstat.m_exthdrget++);				\
	if ((m)->m_len >= (off) + (len))				\
		(val) = (typ)(mtod((m), caddr_t) + (off));		\
	else {								\
		t = m_pulldown((m), (off), (len), &tmp);		\
		if (t) {						\
			if (t->m_len < tmp + (len))			\
				panic("m_pulldown malfunction");	\
			(val) = (typ)(mtod(t, caddr_t) + tmp);		\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while (/*CONSTCOND*/ 0)

#define IP6_EXTHDR_GET0(val, typ, m, off, len) \
do {									\
	struct mbuf *t;							\
	IP6_EXTHDR_STAT(mbstat.m_exthdrget0++);				\
	if ((off) == 0 && (m)->m_len >= len)				\
		(val) = (typ)mtod((m), caddr_t);			\
	else {								\
		t = m_pulldown((m), (off), (len), NULL);		\
		if (t) {						\
			if (t->m_len < (len))				\
				panic("m_pulldown malfunction");	\
			(val) = (typ)mtod(t, caddr_t);			\
		} else {						\
			(val) = (typ)NULL;				\
			(m) = NULL;					\
		}							\
	}								\
} while (/*CONSTCOND*/ 0)
#endif /*_KERNEL*/

#endif /* not _NETINET_IP6_H_ */
