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
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET6_TCP6_H_
#define _NETINET6_TCP6_H_

typedef	u_long	tcp6_seq;

/*
 * TCP6 header.
 * Per RFC 793, September, 1981.
 */
struct tcp6hdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp6_seq th_seq;		/* sequence number */
	tcp6_seq th_ack;		/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

#define	TCP6OPT_EOL		0
#define	TCP6OPT_NOP		1
#define	TCP6OPT_MAXSEG		2
#define    TCP6OLEN_MAXSEG		4
#define TCP6OPT_WINDOW		3
#define    TCP6OLEN_WINDOW		3
#define TCP6OPT_SACK_PERMITTED	4		/* Experimental */
#define    TCP6OLEN_SACK_PERMITTED	2
#define TCP6OPT_SACK		5		/* Experimental */
#define TCP6OPT_TIMESTAMP	8
#define    TCP6OLEN_TIMESTAMP		10
#define    TCP6OLEN_TSTAMP_APPA		(TCP6OLEN_TIMESTAMP+2) /* appendix A */

#define TCP6OPT_TSTAMP_HDR	\
    (TCP6OPT_NOP<<24|TCP6OPT_NOP<<16|TCP6OPT_TIMESTAMP<<8|TCP6OLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP6.
 * With an IP6 MSS of 1280, this is 1220,
 * but 1024 is probably more convenient. (xxx kazu in doubt)
 * This should be defined as MIN(1024, IP6_MSS - sizeof (struct tcpip6hdr))
 */
#define	TCP6_MSS	1024

#define	TCP6_MAXWIN	65535	/* largest value for (unscaled) window */

#define TCP6_MAX_WINSHIFT	14	/* maximum window shift */

/*
 * User-settable options (used with setsockopt).
 */
#define	TCP6_NODELAY	0x01	/* don't delay send to coalesce packets */
#define	TCP6_MAXSEG	0x02	/* set maximum segment size */
#define	TCP6_STDURG	0x03	/* URGENT pointer is last byte of urgent data */

#ifdef _KERNEL
/* parameters that can be set with sysctl */
extern int pmtu_expire;
extern int pmtu_probe;
extern int tcp6_43maxseg;	/* Fill in MAXSEG per 4.2BSD rules */
extern int tcp6_conntimeo;	/* initial connection timeout */
extern int tcp6_do_rfc1323;
extern int tcp6_keepcnt;	/* max idle probes */
extern int tcp6_keepidle;	/* time before probing idle */
extern int tcp6_keepintvl;	/* interval betwn idle probes */
extern int tcp6_maxpersistidle;	/* max idle time in persist */
extern int tcp6_pmtu;		/* turn on path MTU discovery code */
extern int tcp6_sendspace;
extern int tcp6_recvspace;
extern int tcp6_mssdflt;
extern int tcp6_rttdflt;
extern int tcp6_syn_cache_limit; /* Maximum # entries allowed in SYN cache */
extern int tcp6_syn_cache_interval; /* Interval for SYN cache timer, in 1/2 secs */
extern int tcp6_syn_bucket_limit;
#endif

/*
 * Names for TCP6 sysctl objects
 */
#define	TCP6CTL_MSSDFLT		1	/* default seg size */
#define	TCP6CTL_DO_RFC1323	2	/* use RFC1323 options */
#define	TCP6CTL_KEEPIDLE	3	/* time before probing idle */
#define	TCP6CTL_KEEPINTVL	4	/* interval betwn idle probes */
#define	TCP6CTL_KEEPCNT		5	/* max idle probes */
#define	TCP6CTL_MAXPERSISTIDLE	6	/* max idle time in persist */
#define	TCP6CTL_SENDSPACE	7	/* default send buffer */
#define	TCP6CTL_RECVSPACE	8	/* default recv buffer */
#define	TCP6CTL_CONNTIMEO	9	/* default recv buffer */
#define	TCP6CTL_PMTU		10	/* Enable path MTU discovery */
#define	TCP6CTL_PMTU_EXPIRE	11	/* When to expire discovered MTU info */
#define	TCP6CTL_PMTU_PROBE	12	/* When probing for higher MTU */
#define	TCP6CTL_43MAXSEG	13	/* Fill in MAXSEG per 4.3BSD rules */
#define	TCP6CTL_STATS		14	/* statistics */
#define	TCP6CTL_SYN_CACHE_LIMIT	15	/* Max size of SYN cache */
#define	TCP6CTL_SYN_BUCKET_LIMIT	16	/* Max size of buckets in SYN cache */
#define	TCP6CTL_SYN_CACHE_INTER	17	/* Interval for SYN cache timer */
#define	TCP6CTL_MAXID		18

#define	TCP6CTL_NAMES { \
	{ 0, 0 }, \
	{ "mssdflt", CTLTYPE_INT }, \
	{ "do_rfc1323", CTLTYPE_INT }, \
	{ "keepidle", CTLTYPE_INT }, \
	{ "keepinterval", CTLTYPE_INT }, \
	{ "keepcount", CTLTYPE_INT }, \
	{ "maxpersistidle", CTLTYPE_INT }, \
	{ "sendspace", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "conntimeo", CTLTYPE_INT }, \
	{ "pmtu", CTLTYPE_INT }, \
	{ "pmtu_expire", CTLTYPE_INT }, \
	{ "pmtu_probe", CTLTYPE_INT }, \
	{ "43maxseg", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ "syn_cache_limit", CTLTYPE_INT }, \
	{ "syn_bucket_limit", CTLTYPE_INT }, \
	{ "syn_cache_interval", CTLTYPE_INT }, \
}

#define	TCP6CTL_VARS { \
	0, \
	&tcp6_mssdflt, \
	&tcp6_do_rfc1323, \
	&tcp6_keepidle, \
	&tcp6_keepintvl, \
	&tcp6_keepcnt, \
	&tcp6_maxpersistidle, \
	&tcp6_sendspace, \
	&tcp6_recvspace, \
	&tcp6_conntimeo, \
	&tcp6_pmtu, \
	&pmtu_expire, \
	&pmtu_probe, \
	&tcp6_43maxseg, \
	0, \
	&tcp6_syn_cache_limit, \
	&tcp6_syn_bucket_limit, \
	&tcp6_syn_cache_interval, \
}

#endif /* ! _NETINET6_TCP6_H_ */
