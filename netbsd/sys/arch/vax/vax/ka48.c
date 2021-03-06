/*
 * Copyright (c) 1998 Ludd, University of Lule}, Sweden.
 * All rights reserved.
 *
 * This code is derived from software contributed to Ludd by Bertram Barth.
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
 *	This product includes software developed at Ludd, University of 
 *	Lule}, Sweden and its contributors.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*** needs to be completed MK-990306 ***/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>

#include <machine/pte.h>
#include <machine/cpu.h>
#include <machine/mtpr.h>
#include <machine/sid.h>
#include <machine/pmap.h>
#include <machine/nexus.h>
#include <machine/uvax.h>
#include <machine/ka410.h>
#include <machine/ka420.h>
#include <machine/ka48.h>
#include <machine/clock.h>
#include <machine/vsbus.h>

static	void	ka48_conf __P((struct device*, struct device*, void*));
static	void	ka48_steal_pages __P((void));
static	void	ka48_memerr __P((void));
static	int	ka48_mchk __P((caddr_t));
static	void	ka48_halt __P((void));
static	void	ka48_reboot __P((int));
static	void	ka48_cache_enable __P((void));

struct	vs_cpu *ka48_cpu;
extern  short *clk_page;

/* 
 * Declaration of 48-specific calls.
 */
struct	cpu_dep ka48_calls = {
	ka48_steal_pages,
	generic_clock,
	ka48_mchk,
	ka48_memerr, 
	ka48_conf,
	chip_clkread,
	chip_clkwrite,
	6,      /* ~VUPS */
	2,	/* SCB pages */
	ka48_halt,
	ka48_reboot,
};


void
ka48_conf(parent, self, aux)
	struct	device *parent, *self;
	void	*aux;
{
        extern  int clk_adrshift, clk_tweak;

	printf(": KA48\n");
	ka48_cpu = (void *)vax_map_physmem(VS_REGS, 1);
	printf("%s: turning on floating point chip\n", self->dv_xname);
	mtpr(2, PR_ACCS); /* Enable floating points */
	/*
	 * Setup parameters necessary to read time from clock chip.
	 */
	clk_adrshift = 1;       /* Addressed at long's... */
	clk_tweak = 2;          /* ...and shift two */
	clk_page = (short *)vax_map_physmem(VS_CLOCK, 1);
}

void
ka48_cache_enable()
{
	int i, *tmp;
	return; /*** not yet MK-990306 ***/

	/* Disable caches */
	*(int *)KA48_CCR &= ~CCR_SPECIO;/* secondary */
	mtpr(PCSTS_FLUSH, PR_PCSTS);	/* primary */
	*(int *)KA48_BWF0 &= ~BWF0_FEN; /* invalidate filter */

	/* Clear caches */
	tmp = (void *)KA48_INVFLT;	/* inv filter */
	for (i = 0; i < 32768; i++)
		tmp[i] = 0;

	/* Write valid parity to all primary cache entries */
	for (i = 0; i < 256; i++) {
		mtpr(i << 3, PR_PCIDX);
		mtpr(PCTAG_PARITY, PR_PCTAG);
	}

	/* Secondary cache */
	tmp = (void *)KA48_TAGST;
	for (i = 0; i < KA48_TAGSZ*2; i+=2)
		tmp[i] = 0;

	/* Enable cache */
	*(int *)KA48_BWF0 |= BWF0_FEN; /* invalidate filter */
	mtpr(PCSTS_ENABLE, PR_PCSTS);
	*(int *)KA48_CCR = CCR_SPECIO | CCR_CENA;
}

void
ka48_memerr()
{
	printf("Memory err!\n");
}

int
ka48_mchk(addr)
	caddr_t addr;
{
	panic("Machine check");
	return 0;
}

extern caddr_t le_iomem;

void
ka48_steal_pages()
{
	extern	vm_offset_t avail_start, virtual_avail, avail_end;
	int	i;

	MAPPHYS(le_iomem, (NI_IOSIZE/VAX_NBPG), VM_PROT_READ|VM_PROT_WRITE);

	/* Turn on caches (to speed up execution a bit) */
	ka48_cache_enable();
	/*
	 * The I/O MMU maps all 16K device addressable memory to
	 * the low 16M of the physical memory. In this way the
	 * device operations emulate the VS3100 way.
	 * This area must be on a 128k boundary and that causes
	 * a slight waste of memory. We steal it from the end.
	 *
	 * This will be reworked the day NetBSD/vax changes to
	 * 4K pages. (No use before that).
	 */
	{	int *io_map, *lio_map;

		avail_end &= ~0x3ffff;
		lio_map = (int *)avail_end;
		*(int *)(VS_REGS + 8) = avail_end & 0x07fe0000;
		MAPVIRT(io_map, (0x20000 / VAX_NBPG));
		pmap_map((vm_offset_t)io_map, (vm_offset_t)avail_end,
		    (vm_offset_t)avail_end + 0x20000, VM_PROT_READ|VM_PROT_WRITE);
		for (i = 0; i < 0x8000; i++)
			lio_map[i] = 0x80000000|i;
	}
}

static void
ka48_halt()
{
	asm("halt");
}

static void
ka48_reboot(arg)
	int arg;
{
	asm("halt");
}
