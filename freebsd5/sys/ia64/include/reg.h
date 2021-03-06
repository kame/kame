/*-
 * Copyright (c) 2000 Doug Rabson
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/sys/ia64/include/reg.h,v 1.11 2002/09/23 05:55:10 peter Exp $
 */

#ifndef _MACHINE_REG_H_
#define _MACHINE_REG_H_

#ifndef _IA64_FPREG_DEFINED

struct ia64_fpreg {
	uint64_t	fpr_bits[2];
} __aligned(16);

#define _IA64_FPREG_DEFINED

#endif

struct reg {
	uint64_t	r_gr[128];
	uint64_t	r_br[8];
	uint64_t	r_cfm;
	uint64_t	r_ip;		/* Bits 0-3 encode the slot number */
	uint64_t	r_pr;
	uint64_t	r_psr;		/* User mask */
	uint64_t	r_ar_rsc;
	uint64_t	r_ar_bsp;
	uint64_t	r_ar_bspstore;
	uint64_t	r_ar_rnat;
	uint64_t	r_ar_ccv;
	uint64_t	r_ar_unat;
	uint64_t	r_ar_fpsr;
	uint64_t	r_ar_pfs;
	uint64_t	r_ar_lc;
	uint64_t	r_ar_ec;
};

struct fpreg {
	struct ia64_fpreg fpr_regs[128];
};

struct dbreg {
	uint64_t	dbr_data[8];
	uint64_t	dbr_inst[8];
};

#ifdef _KERNEL

struct thread;

void	restorehighfp(struct ia64_fpreg *);
void	savehighfp(struct ia64_fpreg *);

/*
 * XXX these interfaces are MI, so they should be declared in a MI place.
 */
int	fill_regs(struct thread *, struct reg *);
int	set_regs(struct thread *, struct reg *);
int	fill_fpregs(struct thread *, struct fpreg *);
int	set_fpregs(struct thread *, struct fpreg *);
int	fill_dbregs(struct thread *, struct dbreg *);
int	set_dbregs(struct thread *, struct dbreg *);
#endif

#endif /* _MACHINE_REG_H_ */
