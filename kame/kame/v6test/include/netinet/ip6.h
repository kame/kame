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

/* formed from <draft-stevens-advanced-api-04.txt>
 * 	by SUMIKAWA Munechika <sumikawa@ebina.hitachi.co.jp
 */

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 24 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, 4 bits priority */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
};

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

/* Hop-by-Hop options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_hbh {
	uint8_t  ip6h_nxt;        /* next header */
	uint8_t  ip6h_len;        /* length in units of 8 octets */
	/* followed by options */
};

/* Destination options header */
/* XXX should we pad it to force alignment on an 8-byte boundary? */
struct ip6_dest {
	uint8_t  ip6d_nxt;        /* next header */
	uint8_t  ip6d_len;        /* length in units of 8 octets */
	/* followed by options */
};

/* Routing header */
struct ip6_rthdr {
	uint8_t  ip6r_nxt;        /* next header */
	uint8_t  ip6r_len;        /* length in units of 8 octets */
	uint8_t  ip6r_type;       /* routing type */
	uint8_t  ip6r_segleft;    /* segments left */
	/* followed by routing type specific data */
};

/* Type 0 Routing header */
struct ip6_rthdr0 {
	uint8_t  ip6r0_nxt;       /* next header */
	uint8_t  ip6r0_len;       /* length in units of 8 octets */
	uint8_t  ip6r0_type;      /* always zero */
	uint8_t  ip6r0_segleft;   /* segments left */
	u_int32_t  ip6r0_reserved;	/* reserved field */
	/* followed by up to 127 struct in6_addr */

#ifdef COMPAT_RFC2292
	struct in6_addr  ip6r0_addr[1];	/* up to 127 addresses */
#endif 
};

/* Fragment header */
struct ip6_frag {
	uint8_t   ip6f_nxt;       /* next header */
	uint8_t   ip6f_reserved;  /* reserved field */
	uint16_t  ip6f_offlg;     /* offset, reserved, and flag */
	uint32_t  ip6f_ident;     /* identification */
};

#if BYTE_ORDER == BIG_ENDIAN
#define IP6F_OFF_MASK		0xfff8  /* mask out offset from _offlg */
#define IP6F_RESERVED_MASK	0x0006  /* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0001  /* more-fragments flag */
#else /* BYTE_ORDER == LITTLE_ENDIAN */
#define IP6F_OFF_MASK		0xf8ff  /* mask out offset from _offlg */
#define IP6F_RESERVED_MASK	0x0600  /* reserved bits in ip6f_offlg */
#define IP6F_MORE_FRAG		0x0100  /* more-fragments flag */
#endif
