/*	$KAME: radix_art.c,v 1.16 2007/06/14 12:09:42 itojun Exp $	*/
/*	$NetBSD: radix.c,v 1.14 2000/03/30 09:45:38 augustss Exp $	*/

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
 */

/*
 * ART: Allotment Routing Table, by Donald Knuth and Yoichi Hariguchi
 *	<yoichi@yottanet.com>
 * The implementation is by Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * We have multiple ART tables which hold 2^(ART_BITLEN + 1) elements.
 * A table will serve 2^(ART_BITLEN) bits in the address bits.  For example,
 * if ART_BITLEN == 3, we will handle 2^3 = 8 bits.
 * We organize elements in a table as follows.  The number in the bracket
 * is the index of an element, in a table.  Each of the entry corresponds
 * to a particular route, noted as prefix/prefixlen under the bracket.
 *
 *                [1]
 *                0/0
 *	  [2]	             [3]
 *	  0/1		     4/1
 *   [4]      [5]       [6]       [7]
 *   0/2      2/2       4/2       6/2
 * [8] [9] [10] [11] [12] [13] [14] [15]
 * 0/3 1/3 2/3  3/3  4/3  5/3  6/3  7/3
 *
 * To lookup a particular route, we just need to look at the content of the
 * table element - for example, if we need the routing information for 3/4,
 * just look at [11].  To compute the index from the prefix/prefixlen,
 * the following formula should be used (NOTE: the bitwidth of prefix is
 * equal to ART_BITLEN):
 *	if (prefixlen < 2^ART_BITLEN)
 *		idx = (prefix >> (ART_BITLEN - prefixlen)) | (1 << prefixlen);
 *	else
 *		idx = prefix | 2^ART_BITLEN;
 * with the above case (ART_BITLEN == 3), it will be as follows:
 *	if (prefixlen < 8)
 *		idx = (prefix >> (3 - prefixlen)) | (1 << prefixlen);
 *	else
 *		idx = prefix + 8;
 *
 * The topmost entry ([1]) is a special "table default" entry, and we call
 * the index 1 "base index".  Whenever other entry is set to NULL, we look at
 * the value in [1].
 *
 * To add an entry to the table, we need to fill in the table entries under the
 * prefix we need to set.  For exapmle, if we need to configure route to 4/2,
 * we need to fill [6], [12] and [13] with the value we need.
 * To remove an entry, we need to undo it by overwriting it by parent;
 * to remove route to 4/2, copy value of [3] into [6], [12] and [13].
 *
 * When we need to concatenate tables (so that we can handle addresses longer
 * than ART_BITLEN), we do so by putting pointer to child table into
 * entries.  If we need to put a pointer to child table as well as a route,
 * into the same entry, we just need to update the base pointer in the child
 * table.  During lookup, we need to chase the pointers from parent tables to
 * child tables.  Special care must be taken about table default route -
 * if we hit NULL as a result of lookup, we need to return the closest
 * non-NULL table default route.
 *
 * We need a special "invalid" value to designate nonexistent routes
 * (we have already used NULL to mean "look at base index").
 * In the source code, we use &invalid_node for this.
 *
 * ART can handle continuous masks only.  Therefore, we reject non-continuous
 * masks.
 *
 * ART algorithm is memory-eater; well, we have plenty of memory to spare,
 * and we need a speedup.  However, we do need to worry about kernel VM
 * shortage.  Here are some test results with ART_BITLEN == 8:
 *	IPv4, 10000 random entries - around 1700 phys pages (6.8M)
 *	IPv4, 20000 random entries - around 2400 phys pages (9.6M)
 *
 * External interface is kept compatible with radix node, so that we do not
 * surprise existing code too much.  However, because of it, we have certain
 * penalty - we need to manage ART table as well as radix table.
 * The behavior is not 100% compatible with radix, since ART does not support
 * non-continuous masks.
 *
 * If you want to use the code, you'd need to change the following items:
 * - In struct domain, set dom_rtattach member to rn_art_inithead, instead of
 *   rn_inithead.
 * - Before any other route gets inserted, set rt_tables[af]->rnh_addrsize
 *   to the byte width of the address for this particular address family.
 *   For AF_INET, we'd need the following in ip_init():
 *	rt_tables[AF_INET]->rnh_addrsize = sizeof(struct in_addr);
 *   (the initialization should probably be integrated into struct domain)
 * - You need to be careful selecting ART_BITLEN.  If you make it smaller,
 *   you will have more number of subtables, but are smaller (= more memory
 *   accesses, less memory footprint).  If you make it larger, you will have
 *   less number of subtables, but are larger (= less memory accesses, more
 *   memory footprint).  You can use variable-length ART_BITLEN if you wish,
 *   but to do that, you need to change some calls to art_newtable().
 * - Due to limitation in kernel memory allocator, struct art_table must be
 *   smaller or equal to 2Kbytes on netbsd (and probably openbsd).
 *   You need to use ART_BITLEN <= 8.  if you set ART_BITLEN to 8, you also
 *   need to use ART_BITLEN_CONSTANT.
 *
 * TODO:
 * - Memory starvation situations
 * - Handle art_limit right
 * - Regression test
 * - Sometimes returns different result from radix.c - need investigation
 * - Non-continuous masks (sin6_scope_id...)
 */

/* resolve, and compare result with radix.c */
#undef RADIX_ART_TEST

/* HUGE amount of kernel printf! */
#undef RADIX_ART_TRACE

/* statistics - need entries in rtstat (netbsd only at this moment) */
#ifdef __NetBSD__
#define RADIX_ART_STAT
#endif

#ifdef __FreeBSD__
#include "opt_mpath.h"
#endif
#ifdef RADIX_MPATH
#error RADIX_ART cannot be used with RADIX_MPATH
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#define	M_DONTWAIT M_NOWAIT
#include <sys/domain.h>
#include <sys/syslog.h>
#include <net/radix.h>
#include <net/radix_art.h>
#ifdef __NetBSD__
#include <sys/pool.h>
#endif

/* peep radix.c */
extern int	max_keylen;

/*
 * invalid radix_node, put into ART table if we could not deploy ART table -
 * look at radix table if you see it.
 */
static struct radix_node invalid_node;

#ifdef __NetBSD__
static struct pool art_pool;
/*rtstat*/
#include <net/route.h>
#endif

#if defined(RADIX_ART_TRACE) || defined(RADIX_ART_TEST)
static void art_printaddr(u_int8_t *, size_t);
#endif
#ifdef RADIX_ART_TRACE
static void art_printidx(struct art_table *, artidx_t);
#endif
static struct art_table *art_newtable(struct art_table *);
static void art_deltable(struct art_table *);
static inline artidx_t art_getidx(u_int8_t *, int, int);
static artidx_t art_offset(u_int8_t *, int, int, struct art_table *);
static struct radix_node *art_lookup(u_int8_t *, int, struct art_table *);
static inline void art_changeleaf(struct art_table *, artidx_t, void *, void *);
static void art_change(struct art_table *, artidx_t, void *, void *);
static int art_insert(u_int8_t *, int, struct art_table *, void *);
static int art_gc(u_int8_t *, int, int, struct art_table *,
	struct art_table *, artidx_t);
static int art_delete(u_int8_t *, int, struct art_table *, void *);
static int art_prefixlen(void *, struct radix_node_head *);

#ifndef __NetBSD__
extern struct radix_node
	 *rn_delete(void *, void *, struct radix_node_head *),
	 *rn_insert(void *, struct radix_node_head *, int *,
			struct radix_node [2]),
	 *rn_lookup(void *, void *, struct radix_node_head *);
#endif

#if defined(RADIX_ART_TRACE) || defined(RADIX_ART_TEST)
static void
art_printaddr(u_int8_t p, size_t l)
{
	size_t i;

	for (i = 0; i < l; i++)
		printf("%02x", p[i]);
}
#endif

#ifdef RADIX_ART_TRACE
static void
art_printidx(struct art_table *t, artidx_t v)
{

#ifdef ART_BITLEN_CONSTANT
	printf("(t=%p t.base=%p t.count=%lu v=%d+%d)",
	    t, art_asradix(t, ART_BASEIDX), art_count(t),
	    v / (1 << art_bitlen(t)), v % (1 << art_bitlen(t)));
#else
	printf("(t=%p %d/%d t.base=%p t.count=%lu v=%d+%d)",
	    t, art_bitoffset(t), art_bitlen(t),
	    art_asradix(t, ART_BASEIDX), art_count(t),
	    v / (1 << art_bitlen(t)), v % (1 << art_bitlen(t)));
#endif
}
#endif

static struct art_table *
art_newtable(struct art_table *parent)
{
	struct art_table *t;

#ifdef __NetBSD__
	t = pool_get(&art_pool, PR_NOWAIT);
#else
	t = (struct art_table *)malloc(sizeof(*t), M_RTABLE, M_NOWAIT);
#endif
	if (t) {
		bzero(t, sizeof(*t));
#ifndef ART_BITLEN_CONSTANT
		t->art_bitlen = ART_BITLEN;
		if (parent) {
			t->art_bitoffset = art_bitoffset(parent) +
			    art_bitlen(parent);
		} else
			t->art_bitoffset = 0;
#endif
	}
#ifdef RADIX_ART_STAT
	rtstat.rts_art_alloc++;
	rtstat.rts_art_table++;
#endif
	return t;
}

static void
art_deltable(struct art_table *t)
{

#ifdef __NetBSD__
	pool_put(&art_pool, t);
#else
	free(t, M_RTABLE);
#endif
#ifdef RADIX_ART_STAT
	rtstat.rts_art_free++;
	rtstat.rts_art_table--;
#endif
}

static inline artidx_t
art_getidx(u_int8_t *p, int off, int l)
{
	u_int32_t v;

	if (l > 32)
		panic("ART: l is too big in art_getidx");
	p += (off / 8);
	off %= 8;
	v = (u_int32_t)p[0] << 24;
	if (off + l > 8)
		v |= (u_int32_t)p[1] << 16;
	if (off + l > 16)
		v |= (u_int32_t)p[2] << 8;
	if (off + l > 24)
		v |= (u_int32_t)p[3];
	v <<= off;
	v >>= (32 - l);

	return (artidx_t)v;
}

static artidx_t
art_offset(u_int8_t *p, int offset, int prefixlen, struct art_table *t)
{
	int l;
	artidx_t v;

#ifdef ART_BITLEN_CONSTANT
	l = prefixlen % art_bitlen(t);
#else
	l = offset + prefixlen - art_bitoffset(t);
#endif
#ifdef DIAGNOSTIC
	if (0 < l || l > art_bitlen(t))
		panic("out of range in art_offset");
#endif
	v = art_getidx(p, offset, art_bitlen(t));
	if (prefixlen == 0)
		v = ART_BASEIDX;	/* base pointer */
	else if (prefixlen < art_bitlen(t) && prefixlen > 0)
		v = (v >> (art_bitlen(t) - l)) | (1 << l);
	else {
		/* negative prefixlen means infinity! */
		v |= (1 << art_bitlen(t));
	}
#ifdef DIAGNOSTIC
	if (v >= art_maxindex(t))
		panic("ART: v too big to make sense");
#endif
	return v;
}

/*
 * if you specify -1 to prefixlen, you can dig the table until we hit the
 * leaf.  however, as there's no boundary given for the bit string "p",
 * we may overrun the parameter.  Also we may see infinite loop if the
 * table has a loop (should not happen).
 */
static struct radix_node *
art_lookup(u_int8_t *p, int prefixlen, struct art_table *t)
{
	artidx_t v;
	int forever;
	struct radix_node *top;
	int offset;

	forever = (prefixlen < 0) ? 1 : 0;
	top = NULL;
	offset = 0;

#ifdef RADIX_ART_TRACE
	printf("lookup start, %d: ", prefixlen);
#endif
again:
#ifdef DIAGNOSTIC
	if (art_type(t, ART_BASEIDX) != ART_RADIX)
		panic("base index is not ART_RADIX");
#endif
	if (art_asradix(t, ART_BASEIDX))
		top = art_asradix(t, ART_BASEIDX);
	v = art_offset(p, offset, forever ? -1 : prefixlen, t);

#ifdef RADIX_ART_TRACE
	art_printidx(t, v);
#endif
	switch (art_type(t, v)) {
	case ART_RADIX:
#ifdef RADIX_ART_TRACE
		printf("radix %p %p %p\n", art_asradix(t, v), art_asradix(t, ART_BASEIDX), top);
#endif
		if (art_asradix(t, v))
			return art_asradix(t, v);
		else if (art_asradix(t, ART_BASEIDX))
			return art_asradix(t, ART_BASEIDX);
		else
			return top;
	case ART_TABLE:
#ifdef DIAGNOSTIC
		if (!art_leaf(t, v))
			panic("non-leaf node has ART_TABLE");
#ifndef ART_BITLEN_CONSTANT
		if (art_bitoffset(t) + art_bitlen(t) != art_bitoffset(art_astable(t, v)))
			panic("art_bitoffset mismatch");
#endif
#endif
		offset += art_bitlen(t);
		prefixlen -= art_bitlen(t);
		t = art_astable(t, v);
		goto again;
#ifdef DIAGNOSTIC
	default:
		panic("leaf node has a illegal value");
		break;
#endif
	}

#ifdef RADIX_ART_TRACE
	printf("NULL\n");
#endif
	return NULL;
}

/*
 * v - starting point
 * o - old value
 * n - new value
 */
static inline void
art_changeleaf(struct art_table *t, artidx_t v, void *o, void *n)
{
	struct art_table *child;
	void *r;

#ifdef DIAGNOSTIC
	if (!art_leaf(t, v))
		panic("nonleaf passed to art_changeleaf");
#endif
	switch (art_type(t, v)) {
	case ART_TABLE:
		child = art_astable(t, v);
#ifdef DIAGNOSTIC
		if (art_type(child, ART_BASEIDX) != ART_RADIX)
			panic("base index is not ART_RADIX");
#endif
		r = art_asradix(child, ART_BASEIDX);
		if (r == o)
			art_setradix(child, ART_BASEIDX, n);
		break;
	case ART_RADIX:
		if (art_asradix(t, v) == o)
			art_setradix(t, v, n);
		break;
#ifdef DIAGNOSTIC
	default:
		panic("leaf node has a illegal value");
		break;
#endif
	}
}

/*
 * This ultra-complex logic basically does the following:
 * - go all the way down the binary tree, until we hit some entry that is not
 *   the old value
 * - update entries, backtracking one by one
 *
 * s - starting point
 * o - old value
 * n - new value
 */
static void
art_change(struct art_table *t, artidx_t s, void *o, void *n)
{
	artidx_t v = s;

#ifdef DIAGNOSTIC
	if (v == 0)
		panic("v == 0 in art_change");
#endif

	if (art_leaf(t, v)) {
		art_changeleaf(t, v, o, n);
		return;
	}

again:
	v <<= 1;
	if (art_leaf(t, v)) {
		/*
		 * leaf nodes need special consideration
		 */
		while (1) {
			art_changeleaf(t, v, o, n);
			if (v % 2)
				goto moveup;
			v++;
		}
	}
nonleaf:
#ifdef DIAGNOSTIC
	if (art_type(t, v) != ART_RADIX)
		panic("non-leaf index is not ART_RADIX");
#endif
	if (art_asradix(t, v) == o)
		goto again;
moveon:
	if (v % 2)
		goto moveup;
	v++;
	goto nonleaf;
moveup:
	v >>= 1;
	art_setradix(t, v, n);
	if (v != s)
		goto moveon;
}

/*
 * Note on reference counting.
 * - we count ART_BASEIDX element into parent table.
 * - we count table pointers as well as route pointers.
 * Therefore, if table t has a child table, and the child table has
 * art_table[ART_BASEIDX] set, t's reference count is increased by 2 (not 1).
 */
static int
art_insert(u_int8_t *p, int prefixlen, struct art_table *t, void *n)
{
	artidx_t v;
	struct art_table *child;
	int offset = 0;

again:
	v = art_offset(p, offset, prefixlen, t);
	if (prefixlen == 0) {
		/*
		 * special case for prefixlen == 0.
		 * update base pointer for the table.  done.
		 */
		art_setradix(t, ART_BASEIDX, n);
		art_inccount(t);	/*XXX*/
		return 0;
	} else if (prefixlen > art_bitlen(t)) {
		/*
		 * prefixlen is outside of this table.  visit child table,
		 * or deploy a new child table if we don't have one yet.
		 */
		switch (art_type(t, v)) {
		case ART_TABLE:
#ifdef DIAGNOSTIC
			if (!art_leaf(t, v))
				panic("non-leaf node has ART_TABLE");
#endif
			child = art_astable(t, v);
			break;
		case ART_RADIX:
			/*
			 * we already have a route here, expand the table
			 */
			child = art_newtable(t);
			if (child == NULL) {
				/*
				 * we exceeded the memory usage limit
				 */
				art_setradix(t, v, &invalid_node);
				return -1;
			}
			art_setradix(child, ART_BASEIDX, art_asradix(t, v));
			art_settable(t, v, child);
			/* increase parent count for child table pointer */
			art_inccount(t);
			break;
#ifdef DIAGNOSTIC
		default:
			panic("leaf node has a illegal value");
			break;
#endif
		}

		offset += art_bitlen(t);
		prefixlen -= art_bitlen(t);
#ifdef DIAGNOSTIC
#ifndef ART_BITLEN_CONSTANT
		if (art_bitoffset(t) + art_bitlen(t) != art_bitoffset(child))
			panic("art_bitoffset mismatch");
#endif
#endif
		t = child;
		goto again;
	}

	/*
	 * prefixlen is inside this table.  the real update happens.
	 */
	if (art_leaf(t, v)) {
		switch (art_type(t, v)) {
		case ART_TABLE:
			child = art_astable(t, v);
			art_setradix(child, ART_BASEIDX, n);
			/* increase refcnt in parent */
			art_inccount(t);
			break;
		case ART_RADIX:
			art_setradix(t, v, n);
			art_inccount(t);
			break;
#ifdef DIAGNOSTIC
		default:
			panic("leaf node has a illegal value");
			break;
#endif
		}
	} else {
#ifdef DIAGNOSTIC
		if (art_type(t, v) != ART_RADIX)
			panic("intermediate node has a illegal value");
#endif
		art_change(t, v, art_asradix(t, v), n);
		art_inccount(t);
	}
	return 0;
}

static int
art_gc(u_int8_t *p, int offset, int prefixlen, struct art_table *t,
	struct art_table *parent, artidx_t pv)
{
	artidx_t v;

	v = art_offset(p, offset, prefixlen, t);
	switch (art_type(t, v)) {
	case ART_TABLE:
		(void)art_gc(p, offset + art_bitlen(t),
		    prefixlen - art_bitlen(t), art_astable(t, v), t, v);
		/* FALLTHROUGH */
	case ART_RADIX:
		if (art_count(t) != 0)
			break;
		if (!parent)
			break;
		if (art_type(parent, pv) != ART_TABLE ||
		    art_astable(parent, pv) != t) {
			panic("table chain is not sane");
			break;
		}
		/* disconnect myself from parent */
		art_setradix(parent, pv, art_asradix(t, ART_BASEIDX));
		/* decrease parent count for child table pointer */
		art_deccount(parent);
		art_deltable(t);
		break;
#ifdef DIAGNOSTIC
	default:
		panic("leaf node has a illegal value");
		break;
#endif
	}
	return 0;
}

static int
art_delete(u_int8_t *p0, int prefixlen0, struct art_table *t0, void *o)
{
	artidx_t v;
	struct art_table *child;
	struct art_table *parent;
	u_int8_t *p;
	int prefixlen;
	struct art_table *t;
	int offset;

	p = p0;
	prefixlen = prefixlen0;
	t = t0;
	offset = 0;

	parent = NULL;

again:
	v = art_offset(p, offset, prefixlen, t);

	switch (art_type(t, v)) {
	case ART_RADIX:
		if (art_asradix(t, v) != o) {
#ifdef RADIX_ART_TRACE
			printf("delete %d: unexpected RADIX, %p %p\n",
			    __LINE__, art_asradix(t, v), o);
			art_printidx(t, v);
			printf("\n");
#endif
			return -1;
		}
		if (v == ART_BASEIDX) {
			/*
			 * remove the top-level default route entry.
			 * for base index (table default) for non-top-level,
			 * ART_TABLE case will handle it.
			 */
			art_setradix(t, v, &invalid_node);
			if (parent)
				art_deccount(parent);
		} else if (v >> 1 == 1) {
			/* 
			 * remove 0/1 or 1/1 - set it to NULL, refer table
			 * default at the base index
			 */
			art_setradix(t, v, NULL);
			art_deccount(t);
		} else if (art_type(t, v >> 1) == ART_RADIX) {
			/* 
			 * remove normal intermediate entries.
			 */
			art_change(t, v, o, art_asradix(t, v >> 1));
			art_deccount(t);
		} else {
#ifdef RADIX_ART_TRACE
			printf("delete %d: unexpected RADIX, ", __LINE__);
			art_printidx(t, v);
			printf("\n");
#endif
			return -1;
		}
		goto done;
	case ART_TABLE:
#ifdef DIAGNOSTIC
		if (!art_leaf(t, v))
			panic("non-leaf node has ART_TABLE");
#endif
		child = art_astable(t, v);
#ifdef DIAGNOSTIC
		if (art_type(child, ART_BASEIDX) != ART_RADIX)
			panic("base index is not ART_RADIX");
#endif
		/* if we did not find the entry yet, look at the child */
		if (art_asradix(child, ART_BASEIDX) != o) {
#ifdef DIAGNOSTIC
#ifndef ART_BITLEN_CONSTANT
			if (art_bitoffset(t) + art_bitlen(t) !=
			    art_bitoffset(child))
				panic("art_bitoffset mismatch");
#endif
#endif
			offset += art_bitlen(t);
			prefixlen -= art_bitlen(t);
			parent = t;
			t = child;
			goto again;
		}

		/* if we have hit the entry, remove it. */
		if (art_type(t, v >> 1) == ART_RADIX) {
			/*
			 * copy parent value from the edge of the parent table,
			 * into the base index of child table
			 */
			art_setradix(child, ART_BASEIDX,
			    art_asradix(t, v >> 1));
			/* decrease refcnt in parent */
			art_deccount(t);
		} else {
#ifdef RADIX_ART_TRACE
			printf("delete %d: unexpected RADIX 2, ", __LINE__);
			art_printidx(t, v >> 1);
			printf("\n");
#endif
			return -1;
		}
		goto done;
#ifdef DIAGNOSTIC
	default:
		panic("leaf node has a illegal value");
		break;
#endif
	}

#ifdef RADIX_ART_TRACE
	printf("delete %d: unexpected RADIX 3\n", __LINE__);
#endif
	return -1;

done:
	/*
	 * original algorithm combines GC part into deletion, however,
	 * it seemed overly complex and not very readable.
	 */
	art_gc(p0, 0, prefixlen0, t0, NULL, 0);
	return 0;
}

static int
art_prefixlen(void *m_arg, struct radix_node_head *head)
{
	u_int8_t *netmask = (u_int8_t *)m_arg;
	u_int8_t *sp, *cp, *ep;
	int mlen;
	int skip = head->rnh_treetop->rn_off;
	int prefixlen;

	mlen = *netmask;
	/* special case for default route */
	if (mlen == 0)
		return 0;
	if (mlen > max_keylen)
		mlen = max_keylen;
	if (skip == 0)
		skip = 1;
	sp = (u_int8_t *)netmask + skip;
	ep = (u_int8_t *)netmask + mlen;
	if (sp > ep)
		return -1;
	else if (sp == ep)
		return 0;
	prefixlen = 0;
	for (cp = sp; cp < ep; cp++) {
		if (*cp != 0xff)
			break;
		prefixlen += 8;
	}
	switch (*cp) {
	case 0x80: prefixlen += 1; cp++; break;
	case 0xc0: prefixlen += 2; cp++; break;
	case 0xe0: prefixlen += 3; cp++; break;
	case 0xf0: prefixlen += 4; cp++; break;
	case 0xf8: prefixlen += 5; cp++; break;
	case 0xfc: prefixlen += 6; cp++; break;
	case 0xfe: prefixlen += 7; cp++; break;
	case 0x00: break;
	default:
		return -1;
	}
	for (/*nothing*/; cp < ep; cp++) {
		if (*cp != 0x00)
			return -1;
	}

	return prefixlen;
}

struct radix_node *
rn_art_lookup(void *v_arg, void *m_arg, struct radix_node_head *head)
{
	u_int8_t *p;
	int prefixlen;
	struct radix_node *rn1, *rn2;

#ifdef RADIX_ART_TRACE
	printf("lookup ");
	art_printaddr((u_int8_t *)v_arg + head->rnh_treetop->rn_off,
	    head->rnh_addrsize);
#endif
	if (m_arg) {
		/* reject non-continuous netmask */
		prefixlen = art_prefixlen(m_arg, head);
		if (prefixlen < 0) {
#ifdef RADIX_ART_TRACE
			printf(" (invalid mask)\n");
#endif
			return NULL;
		}
	} else {
		/*
		 * go all the way until we hit the leaf.
		 * XXX if the ART table is broken, we may overrun "p"
		 */
		prefixlen = -1;
	}
#ifdef RADIX_ART_TRACE
	printf(", prefixlen=%d\n", prefixlen);
#endif

	p = (u_int8_t *)v_arg;
#ifdef RADIX_ART_STAT
	rtstat.rts_art_lookups++;
#endif
	rn1 = art_lookup(p + head->rnh_treetop->rn_off, prefixlen,
	    ((struct art_node_head *)head)->art_top);
#ifndef RADIX_ART_TEST
	if (rn1 != &invalid_node)
		return rn1;
#endif

	rn2 = rn_lookup(v_arg, m_arg, head);
#ifdef RADIX_ART_TEST
	if (rn1 == &invalid_node) {
#ifdef RADIX_ART_STAT
		rtstat.rts_art_invalid++;
#endif
		if (rn2) {
#ifdef RADIX_ART_STAT
			rtstat.rts_art_mismatch++;
#endif
			art_printaddr((u_int8_t *)v_arg + head->rnh_treetop->rn_off,
			    head->rnh_addrsize);
			printf(" prefixlen %d - mismatch, ", prefixlen);
			printf("art=invalid, radix=%p\n", rn2);
		}
	} else if (rn1 != rn2) {
#ifdef RADIX_ART_STAT
		rtstat.rts_art_mismatch++;
#endif
		art_printaddr((u_int8_t *)v_arg + head->rnh_treetop->rn_off,
		    head->rnh_addrsize);
		printf(" prefixlen %d - mismatch, ", prefixlen);
		printf("art=%p, radix=%p\n", rn1, rn2);
	}
#endif
	return rn2;
}

struct radix_node *
rn_art_match(void *v_arg, struct radix_node_head *head)
{

	return rn_art_lookup(v_arg, NULL, head);
}

struct radix_node *
rn_art_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
	struct radix_node treenodes[2])
{
	u_int8_t *p;
	int prefixlen;
	struct radix_node *rn;

	/* reject non-continuous netmask */
	if (n_arg && art_prefixlen(n_arg, head) < 0)
		return NULL;

	rn = rn_addroute(v_arg, n_arg, head, treenodes);
	if (!rn)
		return rn;

	if (rn->rn_b < 0) {
		v_arg = rn->rn_key;
		n_arg = rn->rn_mask;
	}
	if (n_arg)
		prefixlen = art_prefixlen(n_arg, head);
	else if (head->rnh_addrsize) {
		/* host route */
		prefixlen = head->rnh_addrsize * 8;
	} else
		return rn;

#ifdef RADIX_ART_TRACE
	printf("add ");
	art_printaddr((u_int8_t *)v_arg + head->rnh_treetop->rn_off,
	    head->rnh_addrsize);
	printf(" prefixlen %d\n", prefixlen);
#endif
	/* skip routes that has too large prefixlen */
#if 1
	if (1)
#else
	/* XXX rn_art_lookup() will get confused by incomplete table */
	if (((struct art_node_head *)head)->art_limit >= prefixlen)
#endif
	{
		p = (u_int8_t *)v_arg;
		if (art_insert(p + head->rnh_treetop->rn_off, prefixlen, 
		    ((struct art_node_head *)head)->art_top, treenodes) != 0) {
			printf("ART routing table reached limit\n");
		}
	}

	return rn;
}

struct radix_node *
rn_art_delete(void *v_arg, void *netmask_arg, struct radix_node_head *head,
	struct radix_node *rn)
{
	u_int8_t *p;
	int prefixlen;

	rn = rn_delete(v_arg, netmask_arg, head, rn);

	if (rn) {
		/*
		 * if we got the leaf, use it to find the prefix we've
		 * actually deleted.
		 */
		if (rn->rn_b < 0) {
			v_arg = rn->rn_key;
			netmask_arg = rn->rn_mask;
		}

		if (netmask_arg) {
			prefixlen = art_prefixlen(netmask_arg, head);
			if (prefixlen < 0)
				return rn;
		} else
			prefixlen = -1;

		p = (u_int8_t *)v_arg;
		if (art_delete(p + head->rnh_treetop->rn_off, prefixlen, 
		    ((struct art_node_head *)head)->art_top, rn) != 0) {
#ifndef RADIX_ART_TRACE
			printf("ART routing table deletion failed\n");
#else
			printf("ART routing table deletion failed, ");
			art_printaddr((u_int8_t *)v_arg + head->rnh_treetop->rn_off,
			    head->rnh_addrsize);
			printf(" prefixlen %d rn %p\n", prefixlen, rn);
#endif
		}
	}

	return rn;
}

/* XXX should be integrated into struct domain */
void
rn_art_setlimit(struct radix_node_head *head, unsigned int limit)
{

	((struct art_node_head *)head)->art_limit = limit;
}

int
rn_art_inithead(void **head, int off)
{
	struct art_node_head *rnh;
	int ret;

	if (*head)
		return (1);
	R_Malloc(rnh, struct art_node_head *, sizeof (*rnh));
	if (rnh == 0)
		return (0);
	Bzero(rnh, sizeof (*rnh));
	rnh->art_top = art_newtable(NULL);
	rnh->art_limit = ~0U;
	if (!rnh->art_top) {
		Free(rnh);
		return (0);
	}
	art_setradix(rnh->art_top, ART_BASEIDX, &invalid_node);
	*head = rnh;

	/* initialize radix table */
	ret = rn_inithead0(&rnh->art_radix_head, off);
	if (!ret)
		return ret;

	/* override */
	rnh->art_radix_head.rnh_addaddr = rn_art_addroute;
	rnh->art_radix_head.rnh_deladdr = rn_art_delete;
	rnh->art_radix_head.rnh_lookup = rn_art_lookup;
	rnh->art_radix_head.rnh_matchaddr = rn_art_match;

	return ret;
}

void
rn_art_init(void)
{

#ifdef DIAGNOSTIC
	/* make sure artidx_t makes sense */
	if (ART_BITLEN + 1 > sizeof(artidx_t) * 8) {
		log(LOG_ERR,
		    "rn_art_init: ART_BITLEN too big\n");
		return;
	}

	/*
	 * rn_art_init() must be called after rn_init().
	 * max_keylen set by rn_init().
	 */
	if (max_keylen == 0) {
		log(LOG_ERR,
		    "rn_art_init: radix functions require max_keylen be set\n");
		return;
	}
#endif

#ifdef __NetBSD__
	pool_init(&art_pool, sizeof(struct art_table), 0, 0, 0, "art_table",
	    0, NULL, NULL, M_RTABLE);
	/* XXX pool_sethardlimit? */
#endif
}
