/*	$KAME: altq.h,v 1.2 2000/02/22 14:00:28 itojun Exp $	*/

/*
 * Copyright (C) 1998-1999
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: altq.h,v 1.2 2000/02/22 14:00:28 itojun Exp $
 */
#ifndef _ALTQ_ALTQ_H_
#define _ALTQ_ALTQ_H_

#include <netinet/in.h>

/* altq discipline type */
#define ALTQT_NONE	0	/* reserved */
#define ALTQT_CBQ	1	/* cbq */
#define ALTQT_WFQ	2	/* wfq */
#define ALTQT_AFMAP	3	/* afmap */
#define ALTQT_FIFOQ	4	/* fifoq */
#define ALTQT_RED	5	/* red */
#define ALTQT_RIO	6	/* rio */
#define ALTQT_LOCALQ	7	/* local use */
#define ALTQT_HFSC	8	/* hfsc */
#define ALTQT_CDNR	9	/* traffic conditioner */
#define ALTQT_BLUE	10	/* blue */
#define ALTQT_MAX	10

/*
 * common network flow info structure
 */
struct flowinfo {
	u_char		fi_len;		/* total length */
	u_char		fi_family;	/* address family */
	u_int8_t	fi_data[46];	/* actually longer; address family
					   specific flow info. */
};

/*
 * flow info structure for internet protocol family.
 * (currently this is the only protocol family supported)
 */

struct flowinfo_in {
	u_char		fi_len;		/* sizeof(struct flowinfo_in) */
	u_char		fi_family;	/* AF_INET */
	u_int8_t	fi_proto;	/* IPPROTO_XXX */
	u_int8_t	fi_tos;		/* type-of-service */
	struct in_addr	fi_dst;		/* dest address */
	struct in_addr	fi_src;		/* src address */
	u_int16_t	fi_dport;	/* dest port */
	u_int16_t	fi_sport;	/* src port */
	u_int32_t	fi_gpi;		/* generalized port id for ipsec */
	u_int8_t	_pad[28];	/* make the size equal to
					   flowinfo_in6 */
};

#ifdef SIN6_LEN
struct flowinfo_in6 {
	u_char		fi6_len;	/* sizeof(struct flowinfo_in6) */
	u_char		fi6_family;	/* AF_INET6 */
	u_int8_t	fi6_proto;	/* IPPROTO_XXX */
	u_int8_t	fi6_tclass;	/* traffic class */
	u_int32_t	fi6_flowlabel;	/* ipv6 flowlabel */
	u_int16_t	fi6_dport;	/* dest port */
	u_int16_t	fi6_sport;	/* src port */
	u_int32_t	fi6_gpi;	/* generalized port id */
	struct in6_addr fi6_dst;	/* dest address */
	struct in6_addr fi6_src;	/* src address */
};
#endif /* INET6 */

/*
 * flow filters for AF_INET and AF_INET6
 */
struct flow_filter {
	int			ff_ruleno;
	struct flowinfo_in	ff_flow;
	struct {
		struct in_addr	mask_dst;
		struct in_addr	mask_src;
		u_int8_t	mask_tos;
		u_int8_t	_pad[3];
	} ff_mask;
	u_int8_t _pad2[24];	/* make the size equal to flow_filter6 */
};

#ifdef SIN6_LEN
struct flow_filter6 {
	int			ff_ruleno;
	struct flowinfo_in6	ff_flow6;
	struct {
		struct in6_addr	mask6_dst;
		struct in6_addr	mask6_src;
		u_int8_t	mask6_tclass;
		u_int8_t	_pad[3];
	} ff_mask6;
};
#endif /* INET6 */

#if defined(KERNEL) || defined(_KERNEL)
#include <altq/altq_var.h>
#endif

/* queue macros only in FreeBSD */
#ifndef LIST_EMPTY
#define	LIST_EMPTY(head) ((head)->lh_first == NULL)
#endif
#ifndef LIST_FOREACH
#define LIST_FOREACH(var, head, field)					\
	for((var) = (head)->lh_first; (var); (var) = (var)->field.le_next)
#endif

#endif /* _ALTQ_ALTQ_H_ */
