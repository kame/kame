/*	$NetBSD: cacheops.h,v 1.6 2003/03/13 13:44:17 scw Exp $	*/

/*
 * Copyright 2002 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Steve C. Woodford for Wasabi Systems, Inc.
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
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __SH5_CACHEOPS_H
#define __SH5_CACHEOPS_H

/*
 * The SH5 architecture manual specifies that the cacheops always operate
 * on a cacheline size of 32. I'm not sure if this will always be the
 * case, but for now let's believe the docs.
 */
#define	SH5_CACHELINE_SIZE	32

struct sh5_cache_info {
	u_int		size;
	u_char		type;
	u_char		write;
	u_short		line_size;
	u_short		nways;
	u_short		nsets;
};

#define	SH5_CACHE_INFO_TYPE_NONE	0
#define	SH5_CACHE_INFO_TYPE_VIVT	1
#define	SH5_CACHE_INFO_TYPE_VIPT	2
#define	SH5_CACHE_INFO_TYPE_PI		3

#define	SH5_CACHE_INFO_WRITE_NONE	0
#define	SH5_CACHE_INFO_WRITE_THRU	1
#define	SH5_CACHE_INFO_WRITE_BACK	2

struct sh5_cache_ops {
	void (*dpurge)(vaddr_t, paddr_t, vsize_t);
	void (*dpurge_iinv)(vaddr_t, paddr_t, vsize_t);
	void (*dinv)(vaddr_t, paddr_t, vsize_t);
	void (*dinv_iinv)(vaddr_t, paddr_t, vsize_t);
	void (*iinv)(vaddr_t, paddr_t, vsize_t);
	void (*iinv_all)(void);
	void (*purge_all)(void);
	struct sh5_cache_info dinfo;
	struct sh5_cache_info iinfo;
};

#define	cpu_cache_dpurge	sh5_cache_ops.dpurge
#define	cpu_cache_dpurge_iinv	sh5_cache_ops.dpurge_iinv
#define	cpu_cache_dinv		sh5_cache_ops.dinv
#define	cpu_cache_dinv_iinv	sh5_cache_ops.dinv_iinv
#define	cpu_cache_iinv		sh5_cache_ops.iinv
#define	cpu_cache_iinv_all	sh5_cache_ops.iinv_all
#define	cpu_cache_purge_all	sh5_cache_ops.purge_all
#define	cpu_cache_dinfo		sh5_cache_ops.dinfo
#define	cpu_cache_iinfo		sh5_cache_ops.iinfo

#ifdef _KERNEL
extern struct sh5_cache_ops sh5_cache_ops;
#endif

#endif /* __SH5_CACHEOPS_H */
