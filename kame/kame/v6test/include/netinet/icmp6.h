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

struct icmp6_hdr {
	uint8_t  icmp6_type;	/* type field */
	uint8_t  icmp6_code;	/* code field */
	uint16_t icmp6_cksum;	/* checksum field */
	union {
		uint32_t icmp6_un_data32[1];	/* type-specific field */
		uint16_t icmp6_un_data16[2];	/* type-specific field */
		uint8_t  icmp6_un_data8[4];	/* type-specific field */
	} icmp6_dataun;
};

#define icmp6_data32	icmp6_dataun.icmp6_un_data32
#define icmp6_data16	icmp6_dataun.icmp6_un_data16
#define icmp6_data8	icmp6_dataun.icmp6_un_data8
#define icmp6_pptr	icmp6_data32[0]	/* parameter prob */
#define icmp6_mtu	icmp6_data32[0]	/* packet too big */
#define icmp6_id	icmp6_data16[0]	/* echo request/reply */
#define icmp6_seq	icmp6_data16[1]	/* echo request/reply */
#define icmp6_maxdelay	icmp6_data16[0]	/* mcast group membership */

#define ICMP6_DST_UNREACH		1
#define ICMP6_PACKET_TOO_BIG		2
#define ICMP6_TIME_EXCEEDED		3
#define ICMP6_PARAM_PROB		4

#define ICMP6_INFOMSG_MASK  0x80    /* all informational messages */

#define ICMP6_ECHO_REQUEST		128
#define ICMP6_ECHO_REPLY		129
#define ICMP6_MEMBERSHIP_QUERY		130
#define ICMP6_MEMBERSHIP_REPORT		131
#define ICMP6_MEMBERSHIP_REDUCTION	132

#define ICMP6_DST_UNREACH_NOROUTE	0 /* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN		1 /* communication with destination */
					  /* administratively prohibited */
#define ICMP6_DST_UNREACH_NOTNEIGHBOR	2 /* not a neighbor */
#define ICMP6_DST_UNREACH_ADDR		3 /* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT	4 /* bad port */

#define ICMP6_TIME_EXCEED_TRANSIT	0 /* Hop Limit == 0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY	1 /* Reassembly time out */

#define ICMP6_PARAMPROB_HEADER		0 /* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER	1 /* unrecognized Next Header */
#define ICMP6_PARAMPROB_OPTION		2 /* unrecognized IPv6 option */

#define ND_ROUTER_SOLICIT		133
#define ND_ROUTER_ADVERT		134
#define ND_NEIGHBOR_SOLICIT		135
#define ND_NEIGHBOR_ADVERT		136
#define ND_REDIRECT			137

struct nd_router_solicit {	/* router solicitation */
	struct icmp6_hdr  nd_rs_hdr;
	/* could be followed by options */
};

#define nd_rs_type		nd_rs_hdr.icmp6_type
#define nd_rs_code		nd_rs_hdr.icmp6_code
#define nd_rs_cksum		nd_rs_hdr.icmp6_cksum
#define nd_rs_reserved		nd_rs_hdr.icmp6_data32[0]

struct nd_router_advert {	/* router advertisement */
	struct   icmp6_hdr  nd_ra_hdr;
	uint32_t nd_ra_reachable;	/* reachable time */
	uint32_t nd_ra_retransmit;	/* retransmit timer */
	/* could be followed by options */
};

#define nd_ra_type		nd_ra_hdr.icmp6_type
#define nd_ra_code		nd_ra_hdr.icmp6_code
#define nd_ra_cksum		nd_ra_hdr.icmp6_cksum
#define nd_ra_curhoplimit	nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved	nd_ra_hdr.icmp6_data8[1]
#define ND_RA_FLAG_MANAGED	0x80
#define ND_RA_FLAG_OTHER	0x40
#define nd_ra_router_lifetime	nd_ra_hdr.icmp6_data16[1]

struct nd_neighbor_solicit {	/* neighbor solicitation */
	struct icmp6_hdr nd_ns_hdr;
	struct in6_addr  nd_ns_target; /* target address */
	/* could be followed by options */
};

#define nd_ns_type		nd_ns_hdr.icmp6_type
#define nd_ns_code		nd_ns_hdr.icmp6_code
#define nd_ns_cksum		nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved		nd_ns_hdr.icmp6_data32[0]

struct nd_neighbor_advert {	/* neighbor advertisement */
	struct icmp6_hdr nd_na_hdr;
	struct in6_addr  nd_na_target; /* target address */
	/* could be followed by options */
};

#define nd_na_type		nd_na_hdr.icmp6_type
#define nd_na_code		nd_na_hdr.icmp6_code
#define nd_na_cksum		nd_na_hdr.icmp6_cksum
#define nd_na_flags_reserved	nd_na_hdr.icmp6_data32[0]
#if     BYTE_ORDER == BIG_ENDIAN
#define ND_NA_FLAG_ROUTER	0x80000000
#define ND_NA_FLAG_SOLICITED	0x40000000
#define ND_NA_FLAG_OVERRIDE	0x20000000
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
#define ND_NA_FLAG_ROUTER	0x00000080
#define ND_NA_FLAG_SOLICITED	0x00000040
#define ND_NA_FLAG_OVERRIDE	0x00000020
#endif

struct nd_redirect {		/* redirect */
	struct icmp6_hdr nd_rd_hdr;
	struct in6_addr  nd_rd_target;	/* target address */
	struct in6_addr  nd_rd_dst;	/* destination address */
	/* could be followed by options */
};

#define nd_rd_type		nd_rd_hdr.icmp6_type
#define nd_rd_code		nd_rd_hdr.icmp6_code
#define nd_rd_cksum		nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved		nd_rd_hdr.icmp6_data32[0]

struct nd_opt_hdr {	/* Neighbor discovery option header */
	uint8_t  nd_opt_type;
	uint8_t  nd_opt_len;	/* in units of 8 octets */
	/* followed by option specific data */
};

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			5

struct nd_opt_prefix_info {	/* prefix information */
	uint8_t  nd_opt_pi_type;
	uint8_t  nd_opt_pi_len;
	uint8_t  nd_opt_pi_prefix_len;
	uint8_t  nd_opt_pi_flags_reserved;
	uint32_t nd_opt_pi_valid_time;
	uint32_t nd_opt_pi_preferred_time;
	uint32_t nd_opt_pi_reserved2;
	struct in6_addr nd_opt_pi_prefix;
};

#define ND_OPT_PI_FLAG_ONLINK	0x80
#define ND_OPT_PI_FLAG_AUTO	0x40

struct nd_opt_rd_hdr {		/* redirected header */
	uint8_t  nd_opt_rh_type;
	uint8_t  nd_opt_rh_len;
	uint16_t nd_opt_rh_reserved1;
	uint32_t nd_opt_rh_reserved2;
	/* followed by IP header and data */
};

struct nd_opt_mtu {	/* MTU option */
	uint8_t  nd_opt_mtu_type;
	uint8_t  nd_opt_mtu_len;
	uint16_t nd_opt_mtu_reserved;
	uint32_t nd_opt_mtu_mtu;
};

struct icmp6_filter {
	uint32_t  icmp6_filt[8];  /* 8*32 = 256 bits */
};

#define ICMP6_FILTER_WILLPASS(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) != 0)
#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) == 0)
#define ICMP6_FILTER_SETPASS(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) |=  (1 << ((type) & 31))))
#define ICMP6_FILTER_SETBLOCK(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31))))
#define ICMP6_FILTER_SETPASSALL(filterp) \
	memset((filterp), 0xFF, sizeof(struct icmp6_filter))
#define ICMP6_FILTER_SETBLOCKALL(filterp) \
	memset((filterp), 0, sizeof(struct icmp6_filter))
