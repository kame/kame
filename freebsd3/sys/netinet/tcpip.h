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
 *	@(#)tcpip.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/netinet/tcpip.h,v 1.7.2.1 1999/08/29 16:29:57 peter Exp $
 */

#ifndef _NETINET_TCPIP_H_
#define _NETINET_TCPIP_H_

/*
 * Tcp+ip header, after ip options removed.
 */
struct tcpiphdr {
	struct 	ipovly ti_i;		/* overlaid ip structure */
	struct	tcphdr ti_t;		/* tcp header */
};
#ifdef notyet
/*
 * Tcp+ip header, after ip options removed but including TCP options.
 */
struct full_tcpiphdr {
	struct 	ipovly ti_i;		/* overlaid ip structure */
	struct	tcphdr ti_t;		/* tcp header */
	char	ti_o[TCP_MAXOLEN];	/* space for tcp options */
};
#endif /* notyet */
#define	ti_x1		ti_i.ih_x1
#define	ti_pr		ti_i.ih_pr
#define	ti_len		ti_i.ih_len
#define	ti_src		ti_i.ih_src
#define	ti_dst		ti_i.ih_dst
#define	ti_sport	ti_t.th_sport
#define	ti_dport	ti_t.th_dport
#define	ti_seq		ti_t.th_seq
#define	ti_ack		ti_t.th_ack
#define	ti_x2		ti_t.th_x2
#define	ti_off		ti_t.th_off
#define	ti_flags	ti_t.th_flags
#define	ti_win		ti_t.th_win
#define	ti_sum		ti_t.th_sum
#define	ti_urp		ti_t.th_urp

#ifndef INET6
/*
 * Same for templates.
 */
struct tcptemp {
	struct 	ipovly tt_i;		/* overlaid ip structure */
	struct	tcphdr tt_t;		/* tcp header */
};
#define tt_x1		tt_i.ih_x1
#define	tt_pr		tt_i.ih_pr
#define	tt_len		tt_i.ih_len
#define	tt_src		tt_i.ih_src
#define	tt_dst		tt_i.ih_dst
#define	tt_sport	tt_t.th_sport
#define	tt_dport	tt_t.th_dport
#define	tt_off		tt_t.th_off
#define tt_seq		tt_t.th_seq
#define tt_ack		tt_t.th_ack
#define tt_x2		tt_t.th_x2
#define tt_flags	tt_t.th_flags
#define tt_win		tt_t.th_win
#define tt_sum		tt_t.th_sum
#define tt_urp		tt_t.th_urp
#else

#define ip6tcp		tcpip6hdr	/* for KAME src sync over BSD*'s */

/*
 * IPv6+TCP headers.
 */
struct tcpip6hdr {
	struct 	ip6_hdr ti6_i;		/* IPv6 header */
	struct	tcphdr ti6_t;		/* TCP header */
};
#define	ti6_vfc		ti6_i.ip6_vfc
#define	ti6_flow	ti6_i.ip6_vlow
#define	ti6_plen	ti6_i.ip6_plen
#define	ti6_nxt		ti6_i.ip6_nxt
#define	ti6_hlim	ti6_i.ip6_hlim
#define	ti6_src		ti6_i.ip6_src
#define	ti6_dst		ti6_i.ip6_dst
#define	ti6_sport	ti6_t.th_sport
#define	ti6_dport	ti6_t.th_dport
#define	ti6_seq		ti6_t.th_seq
#define	ti6_ack		ti6_t.th_ack
#define	ti6_x2		ti6_t.th_x2
#define	ti6_off		ti6_t.th_off
#define	ti6_flags	ti6_t.th_flags
#define	ti6_win		ti6_t.th_win
#define	ti6_sum		ti6_t.th_sum
#define	ti6_urp		ti6_t.th_urp

/*
 * Dual template for IPv4/IPv6 TCP.
 *
 * Optimized for IPv4
 */
struct tcptemp {
	struct	ipovly tt_i;		/* overlaid ip structure */
	struct	tcphdr tt_t;		/* tcp header */
	struct	ip6_hdr tt_i6;		/* IPv6 header */
};
#define tt_x1		tt_i.ih_x1
#define	tt_pr		tt_i.ih_pr
#define	tt_len		tt_i.ih_len
#define	tt_src		tt_i.ih_src
#define	tt_dst		tt_i.ih_dst
#define	tt_sport	tt_t.th_sport
#define	tt_dport	tt_t.th_dport
#define	tt_off		tt_t.th_off
#define tt_seq		tt_t.th_seq
#define tt_ack		tt_t.th_ack
#define tt_x2		tt_t.th_x2
#define tt_flags	tt_t.th_flags
#define tt_win		tt_t.th_win
#define tt_sum		tt_t.th_sum
#define tt_urp		tt_t.th_urp
#define	tt_vfc		tt_i6.ip6_vfc
#define	tt_flow		tt_i6.ip6_flow
#define	tt_pr6		tt_i6.ip6_nxt
#define	tt_len6		tt_i6.ip6_plen
#define tt_src6		tt_i6.ip6_src
#define tt_dst6		tt_i6.ip6_dst
#endif

#endif
