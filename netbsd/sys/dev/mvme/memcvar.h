/*	$NetBSD: memcvar.h,v 1.1 2002/02/12 20:38:46 scw Exp $	*/

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Steve C. Woodford.
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
 *	      This product includes software developed by the NetBSD
 *	      Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_MVME_MEMCVAR_H
#define	_MVME_MEMCVAR_H

struct memc_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_bust;
	bus_space_handle_t	sc_bush;
	struct evcnt		sc_evcnt;
};

#define MEMC_NDEVS	2

#define	memc_reg_read(sc, off) \
	    bus_space_read_1((sc)->sc_bust, (sc)->sc_bush, (off))
#define	memc_reg_write(sc, off, v) \
	    bus_space_write_1((sc)->sc_bust, (sc)->sc_bush, (off), (v))

/*
 * Some tweakable parameters. Mind you, I don't recommend changing
 * the ipl...
 * XXX: This should probably be ipl 7
 */
#ifdef MVME68K
#define MEMC_IRQ_LEVEL		6
#else
#error Define irq level for memory contoller
#endif

extern	void	memc_init(struct memc_softc *);

#endif	/* _MVME_MEMCREG_H */
