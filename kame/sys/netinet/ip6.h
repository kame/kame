/*	$KAME: ip6.h,v 1.38 2002/11/05 03:48:31 itojun Exp $	*/

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
#define IP6OPT_RTALERT		0x05	/* 00 0 00101 (KAME definition) */
#define IP6OPT_ROUTER_ALERT	0x05	/* (2292bis def, recommended) */

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
struct ip6_mobility {
	u_int8_t ip6m_pproto;	/* following payload protocol (for PG) */
	u_int8_t ip6m_len;	/* length in units of 8 octets */
	u_int8_t ip6m_type;	/* message type */
	u_int8_t ip6m_reserved;
	u_int16_t ip6m_cksum;	/* sum of IPv6 pseudo-header and MH */
	/* followed by type specific data */
} __attribute__((__packed__));

/* Mobility Header min. */
#define IP6M_MINLEN	8

/* Mobility header message types */
#define IP6M_BINDING_REQUEST	0
#define IP6M_HOME_TEST_INIT	1
#define IP6M_CAREOF_TEST_INIT	2
#define IP6M_HOME_TEST		3
#define IP6M_CAREOF_TEST	4
#define IP6M_BINDING_UPDATE	5
#define IP6M_BINDING_ACK	6
#define IP6M_BINDING_ERROR	7

/* Binding Refresh Request (BRR) message */
struct ip6m_binding_request {
	u_int8_t ip6mr_pproto;
	u_int8_t ip6mr_len;
	u_int16_t ip6mr_type;
	u_int16_t ip6mr_cksum;
	u_int16_t ip6mr_reserved;
	/* followed by mobility options */
} __attribute__((__packed__));

/* Home Test Init (HoTI) message */
struct ip6m_home_test_init {
	u_int8_t ip6mhi_pproto;
	u_int8_t ip6mhi_len;
	u_int16_t ip6mhi_type;
	u_int16_t ip6mhi_cksum;
	u_int16_t ip6mhi_reserved;
	u_int8_t ip6mhi_hot_cookie[8];
	/* followed by mobility options */
} __attribute__((__packed__));

/* Care-of Test Init (CoTI) message */
struct ip6m_careof_test_init {
	u_int8_t ip6mci_pproto;
	u_int8_t ip6mci_len;
	u_int16_t ip6mci_type;
	u_int16_t ip6mci_cksum;
	u_int16_t ip6mci_reserved;
	u_int8_t ip6mci_cot_cookie[8];
	/* followed by mobility options */
} __attribute__((__packed__));

/* Home Test (HoT) message */
struct ip6m_home_test {
	u_int8_t ip6mh_pproto;
	u_int8_t ip6mh_len;
	u_int16_t ip6mh_type;
	u_int16_t ip6mh_cksum;
	u_int16_t ip6mh_nonce_index;	/* idx of the CN nonce list array */
	u_int8_t ip6mh_hot_cookie[8];
	u_int8_t ip6mh_cookie[8];	/* K0 cookie */
	/* followed by mobility options */
} __attribute__((__packed__));

/* Care-of Test (CoT) message */
struct ip6m_careof_test {
	u_int8_t ip6mc_pproto;
	u_int8_t ip6mc_len;
	u_int16_t ip6mc_type;
	u_int16_t ip6mc_cksum;
	u_int16_t ip6mc_nonce_index;	/* idx of the CN nonce list array */
	u_int8_t ip6mc_cot_cookie[8];
	u_int8_t ip6mc_cookie[8];	/* K1 cookie */
	/* followed by mobility options */
} __attribute__((__packed__));

/* Binding Update (BU) message */
struct ip6m_binding_update {
	u_int8_t ip6mu_pproto;
	u_int8_t ip6mu_len;
	u_int16_t ip6mu_type;
	u_int16_t ip6mu_cksum;
	u_int16_t ip6mu_seqno;
	u_int8_t ip6mu_flags;
	u_int8_t ip6mu_reserved;
	u_int16_t ip6mu_lifetime;	/* a unit of 4 seconds */
	/* followed by mobility options */
} __attribute__((__packed__));

/* Binding Update flags */
#define IP6MU_ACK	0x80	/* Request a binding ack */
#define IP6MU_HOME	0x40	/* Home Registration */
#define IP6MU_SINGLE	0x20	/* Update the specified address only */
#define IP6MU_DAD	0x10	/* Perform Duplicate Address Detection */
#define IP6MU_LINK	0x08	/* Link-Local Address Compatibility */
#define IP6MU_CLONED	0x01

/* Binding Acknowledgement (BA) message */
struct ip6m_binding_ack {
	u_int8_t ip6ma_pproto;
	u_int8_t ip6ma_len;
	u_int16_t ip6ma_type;
	u_int16_t ip6ma_cksum;
	u_int8_t ip6ma_status;
	u_int8_t ip6ma_reserved;
	u_int16_t ip6ma_seqno;
	u_int16_t ip6ma_lifetime;	/* a unit of 4 seconds */
	/* followed by mobility options */
} __attribute__((__packed__));

/* Binding Error (BE) message */
struct ip6m_binding_error {
	u_int8_t ip6me_pproto;
	u_int8_t ip6me_len;
	u_int16_t ip6me_type;
	u_int16_t ip6me_cksum;
	u_int8_t ip6me_status;
	u_int8_t ip6me_reserved;
	struct in6_addr ip6me_addr;
	/* followed by mobility options */
} __attribute__((__packed__));

/* Binding Error status codes */
#define IP6ME_UNVERIFIED_HAO	1
#define IP6ME_UNKNOWN_TYPE	2

/* Mobility options */
struct ip6m_opt {
	u_int8_t ip6mo_type;
	u_int8_t ip6mo_len;
	/* followed by option data */
} __attribute__((__packed__));

/* Mobility option type */
#define IP6MOPT_PAD1		0	/* Pad1 */
#define IP6MOPT_PADN		1	/* PadN */
#define IP6MOPT_UID		2	/* Unique Identifier */
#define IP6MOPT_ALTCOA		3	/* Alternate Care-of Address */
#define IP6MOPT_NONCE		4	/* Nonce Indices */
#define IP6MOPT_AUTHDATA	5	/* Binding Authorization Data */
/* XXX MIPv6 Issue 97 */
/* #define IP6MOPT_REFRESH	6 */
#define IP6MOPT_REFRESH		7	/* Binding Refresh Advice */

/* Unique Identifier */
struct ip6m_opt_uid {
	u_int8_t ip6mou_type;
	u_int8_t ip6mou_len;
	u_int8_t ip6mou_id[2];		/* Unique Identifier */
} __attribute__((__packed__));

/* Alternate Care-of Address */
struct ip6m_opt_altcoa {
	u_int8_t ip6moa_type;
	u_int8_t ip6moa_len;
	u_int8_t addr[16];		/* Alternate Care-of Address */
} __attribute__((__packed__));

/* Nonce Indices */
struct ip6m_opt_nonce {
	u_int8_t ip6mon_type;
	u_int8_t ip6mon_len;
	u_int8_t ip6mon_home_nonce_index[2];
	u_int8_t ip6mon_careof_nonce_index[2];
} __attribute__((__packed__));

/* Binding Authorization Data */
struct ip6m_opt_authdata {
	u_int8_t ip6moau_type;
	u_int8_t ip6moau_len;
	/* followed by authenticator data */
} __attribute__((__packed__));

/* Binding Refresh Advice */
struct ip6m_opt_refresh {
	u_int8_t ip6mor_type;
	u_int8_t ip6mor_len;
	u_int8_t ip6mor_refresh[2];	/* Refresh Interval */
} __attribute__((__packed__));

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
	if ((m)->m_flags & M_EXT) {					\
		if ((m)->m_len < (off) + (hlen)) {			\
			ip6stat.ip6s_exthdrtoolong++;			\
			m_freem(m);					\
			return ret;					\
		}							\
	} else {							\
		if ((m)->m_len < (off) + (hlen)) {			\
			ip6stat.ip6s_exthdrtoolong++;			\
			m_freem(m);					\
			return ret;					\
		}							\
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
