/*	$KAME: radix_art.h,v 1.6 2007/06/14 12:09:42 itojun Exp $	*/
/*	$NetBSD: radix.h,v 1.10 2000/11/06 11:07:37 itojun Exp $	*/

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
 * THE AUTHORS DO NOT GUARANTEE THAT THIS SOFTWARE DOES NOT INFRINGE
 * ANY OTHERS' INTELLECTUAL PROPERTIES. IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY INFRINGEMENT OF ANY OTHERS' INTELLECTUAL
 * PROPERTIES.
 */

/*
 * Copyright (c) 1988, 1989, 1993
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
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 */

#ifndef _NET_RADIX_ART_H_
#define	_NET_RADIX_ART_H_

/*
 * ART: Allotment Routing Table, by Donald Knuth and Yoichi Hariguchi.
 */

#ifdef _KERNEL
#define ART_BITLEN	4	/* XXX pool allocator limit, don't increase */
/*#define ART_BITLEN_CONSTANT*/
#if 0 /*def ART_BITLEN_CONSTANT*/
#define art_bitlen(t)		ART_BITLEN
#else
#define art_bitlen(t)		((t)->art_bitlen)
#define art_bitoffset(t)	((t)->art_bitoffset)
#endif

struct art_table {
#if 1 /*ndef ART_BITLEN_CONSTANT*/
	int art_bitoffset;	/* bit offset on the left */
	int art_bitlen;		/* bit length suppored by the table */
#endif
	void *art_table[1 << (ART_BITLEN + 1)];
};

typedef	u_int16_t artidx_t;	/* must hold 2 ^ (ART_BITLEN + 1) */
#define ART_COUNTIDX	0	/* count live routes */
#define ART_BASEIDX	1	/* base index, the table default route */

#define ART_RADIX	0
#define ART_TABLE	1
#define art_get(t, v)	((t)->art_table[(v)])
#define art_type(t, v) \
	((((u_long)art_get((t), (v))) & 1) ? ART_TABLE : ART_RADIX)
#define art_asradix(t, v) \
	((struct radix_node *)art_get((t), (v)))
#define art_astable(t, v) \
	((struct art_table *)((u_long)art_get((t), (v)) & ~1))
#define art_count(t)	((u_long)art_get((t), ART_COUNTIDX))

#define art_setradix(t, v, n) \
	do { (t)->art_table[(v)] = (n); } while (/*CONSTCOND*/ 0)
#define art_settable(t, v, n) \
	do {								\
		(t)->art_table[(v)] = (void *)((u_long)(n) | 1);	\
	} while (/*CONSTCOND*/ 0)
#define art_inccount(t) \
	do {								\
		(t)->art_table[ART_COUNTIDX] = (void *)(art_count((t)) + 1); \
	} while (/*CONSTCOND*/ 0)
#define art_deccount(t) \
	do {								\
		(t)->art_table[ART_COUNTIDX] = (void *)(art_count((t)) - 1); \
	} while (/*CONSTCOND*/ 0)

#define art_maxindex(t)	(2 << art_bitlen((t)))
#define art_leaf(t, v)	((v) >= (1 << art_bitlen((t))) && v < art_maxindex((t)))

struct art_node_head {
	struct radix_node_head art_radix_head;	/* traditional radix table */
	struct art_table *art_top;		/* toplevel table */
	unsigned int art_limit;			/* max prefixlen */
};

void	 rn_art_init(void);
int	 rn_art_inithead(void **, int);
void	 rn_art_setlimit(struct radix_node_head *, unsigned int);
struct radix_node
	 *rn_art_addroute(void *, void *, struct radix_node_head *,
			struct radix_node [2]),
	 *rn_art_delete(void *, void *, struct radix_node_head *),
	 *rn_art_insert(void *, struct radix_node_head *, int *,
			struct radix_node [2]),
	 *rn_art_lookup(void *, void *, struct radix_node_head *),
	 *rn_art_match(void *, struct radix_node_head *);
#endif

#endif /* _NET_RADIX_ART_H_ */
