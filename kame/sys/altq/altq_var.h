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
 * $Id: altq_var.h,v 1.1 2000/01/18 07:29:15 kjc Exp $
 */
#ifndef _ALTQ_ALTQ_VAR_H_
#define _ALTQ_ALTQ_VAR_H_

#if defined(KERNEL) || defined(_KERNEL)

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/queue.h>

/*
 * filter structure for altq common classifier
 */
struct acc_filter {
	LIST_ENTRY(acc_filter)	f_chain;
	void			*f_class;	/* pointer to the class */
	u_long			f_handle;	/* filter id */
	u_int32_t		f_fbmask;	/* filter bitmask */
	struct flow_filter	f_filter;	/* filter value */
};

/*
 * XXX ACC_FILTER_TABLESIZE can't be larger than 2048 unless we fix
 * the handle assignment.
 */
#define	ACC_FILTER_TABLESIZE	(256+1)
#define	ACC_FILTER_MASK		(ACC_FILTER_TABLESIZE - 2)
#define ACC_WILDCARD_INDEX	(ACC_FILTER_TABLESIZE - 1)
#ifdef __GNUC__
#define	ACC_GET_HASH_INDEX(addr) \
	({int x = (addr) + ((addr) >> 16); (x + (x >> 8)) & ACC_FILTER_MASK;})
#else
#define	ACC_GET_HASH_INDEX(addr) \
	(((addr) + ((addr) >> 8) + ((addr) >> 16) + ((addr) >> 24)) \
	& ACC_FILTER_MASK)
#endif
#define	ACC_GET_HINDEX(handle) ((handle) >> 20)

struct acc_classifier {
	u_int32_t			acc_fbmask;
	LIST_HEAD(filt, acc_filter)	acc_filters[ACC_FILTER_TABLESIZE];
};

/*
 * flowinfo mask bits used by classifier
 */
/* for ipv4 */
#define FIMB4_PROTO	0x0001
#define FIMB4_TOS	0x0002
#define FIMB4_DADDR	0x0004
#define FIMB4_SADDR	0x0008
#define FIMB4_DPORT	0x0010
#define FIMB4_SPORT	0x0020
#define FIMB4_GPI	0x0040
#define FIMB4_ALL	0x007f
/* for ipv6 */
#define FIMB6_PROTO	0x0100
#define FIMB6_TCLASS	0x0200
#define FIMB6_DADDR	0x0400
#define FIMB6_SADDR	0x0800
#define FIMB6_DPORT	0x1000
#define FIMB6_SPORT	0x2000
#define FIMB6_GPI	0x4000
#define FIMB6_FLABEL	0x8000
#define FIMB6_ALL	0xff00

#define FIMB_ALL	(FIMB4_ALL|FIMB6_ALL)

#define FIMB4_PORTS	(FIMB4_DPORT|FIMB4_SPORT|FIMB4_GPI)
#define FIMB6_PORTS	(FIMB6_DPORT|FIMB6_SPORT|FIMB6_GPI)

/*
 * machine dependent clock
 * a 64bit high resolution time counter.
 */
extern u_int32_t machclk_freq;
extern u_int32_t machclk_per_tick;
extern void init_machclk(void);
#if defined(__i386__)
/* for pentium tsc */
#define read_machclk()	rdtsc()
#ifndef __FreeBSD__
static __inline u_int64_t rdtsc(void)
{
	u_int64_t rv;

	__asm __volatile(".byte 0x0f, 0x31" : "=A" (rv));
	return (rv);
}
#endif /* !__FreeBSD__ */
#else /* !i386 */
/* emulate 256MHz using microtime() */
#define MACHCLK_SHIFT	8
static __inline u_int64_t read_machclk(void)
{
	struct timeval tv;
	
	microtime(&tv);
	return (((u_int64_t)(tv.tv_sec - boottime.tv_sec) * 1000000
		 + tv.tv_usec) << MACHCLK_SHIFT);
}
#endif /* !i386 */

/*
 * debug support
 */
#ifdef ALTQ_DEBUG
#ifdef __STDC__
#define	ASSERT(e)	((e) ? (void)0 : altq_assert(__FILE__, __LINE__, #e))
#else	/* PCC */
#define	ASSERT(e)	((e) ? (void)0 : altq_assert(__FILE__, __LINE__, "e"))
#endif
#else
#define	ASSERT(e)	((void)0)
#endif

/*
 * misc stuff for compatibility
 */
/* ioctl cmd type */
#if defined(__FreeBSD__) && (__FreeBSD__ < 3)
typedef int ioctlcmd_t;
#else
typedef u_long ioctlcmd_t;
#endif

/*
 * queue macros:
 * the interface of TAILQ_LAST macro changed after the introduction
 * of softupdate. redefine it here to make it work with pre-2.2.7.
 */
#undef TAILQ_LAST
#define	TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#ifndef TAILQ_EMPTY
#define	TAILQ_EMPTY(head) ((head)->tqh_first == NULL)
#endif
#ifndef TAILQ_FOREACH
#define TAILQ_FOREACH(var, head, field)					\
	for (var = TAILQ_FIRST(head); var; var = TAILQ_NEXT(var, field))
#endif

/* macro for timeout/untimeout */
#if (__FreeBSD_version > 300000)
#define CALLOUT_HANDLE_INIT(h)	callout_handle_init((h))
#define TIMEOUT(f,a,t,h)	{ (h) = timeout((f),(a),(t)); }
#define UNTIMEOUT(f,a,h)	untimeout((f),(a),(h))
#else
/* dummy callout_handle structure */
struct callout_handle {
	void *callout;
};
#define CALLOUT_HANDLE_INIT(h)	{ (h)->callout = NULL; }
#define TIMEOUT(f,a,t,h)	timeout((f),(a),(t))
#define UNTIMEOUT(f,a,h)	untimeout((f),(a))
#if !defined(__FreeBSD__)
typedef void (timeout_t)(void *);
#endif
#endif

#ifdef INET6
#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a, b) \
	(((a)->s6_addr32[0] == (b)->s6_addr32[0]) && \
	 ((a)->s6_addr32[1] == (b)->s6_addr32[1]) && \
	 ((a)->s6_addr32[2] == (b)->s6_addr32[2]) && \
	 ((a)->s6_addr32[3] == (b)->s6_addr32[3]))
#endif
#endif /* INET6 */

#define	m_pktlen(m)		((m)->m_pkthdr.len)

struct ifnet; struct mbuf; struct flowinfo;

int if_altqattach __P((struct ifnet *, void *,
		       int (*)(struct ifnet *, struct mbuf *, struct pr_hdr *, int),
		       struct mbuf *(*)(struct ifnet *, int), int));
int if_altqdetach __P((struct ifnet *));
int if_altqenable __P((struct ifnet *));
int if_altqdisable __P((struct ifnet *));
void *altq_lookup __P((char *, int));
int altq_extractflow __P((struct mbuf *, struct pr_hdr *,
			  struct flowinfo *, u_int32_t));
int altq_mkctlhdr __P((struct pr_hdr *));
int acc_add_filter __P((struct acc_classifier *, struct flow_filter *,
			   void *, u_long *));
int acc_delete_filter __P((struct acc_classifier *, u_long));
int acc_discard_filters __P((struct acc_classifier *, void *, int));
void *acc_classify __P((struct acc_classifier *, struct flowinfo *));
u_int8_t read_dsfield __P((struct pr_hdr *));
void write_dsfield __P((struct pr_hdr *, u_int8_t));
void altq_assert __P((const char *, int, const char *));

#endif /* KERNEL */
#endif /* _ALTQ_ALTQ_VAR_H_ */
