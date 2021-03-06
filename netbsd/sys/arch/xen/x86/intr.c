/*	$NetBSD: intr.c,v 1.1.2.1 2004/05/22 15:59:31 he Exp $	*/
/*	NetBSD: intr.c,v 1.15 2004/04/10 14:49:55 kochi Exp 	*/

/*
 * Copyright 2002 (c) Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Frank van der Linden for Wasabi Systems, Inc.
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: intr.c,v 1.1.2.1 2004/05/22 15:59:31 he Exp $");

#include "opt_multiprocessor.h"

#include <sys/cdefs.h>
#include <sys/param.h> 
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/errno.h>

#include <machine/atomic.h>
#include <machine/i8259.h>
#include <machine/cpu.h>
#include <machine/pio.h>

#include "ioapic.h"
#include "lapic.h"
#include "pci.h"

#if NIOAPIC > 0
#include <machine/i82093var.h> 
#include <machine/mpbiosvar.h>
#endif

#if NLAPIC > 0
#include <machine/i82489var.h>
#endif

#if NPCI > 0
#include <dev/pci/ppbreg.h>
#endif

struct pic softintr_pic = {
	.pic_dev = {
		.dv_xname = "softintr_fakepic",
	},
	.pic_type = PIC_SOFT,
	.pic_lock = __SIMPLELOCK_UNLOCKED,
};

#if NIOAPIC > 0
static int intr_scan_bus(int, int, int *);
#if NPCI > 0
static int intr_find_pcibridge(int, pcitag_t *, pci_chipset_tag_t *);
#endif
#endif

#if 0
/*
 * Fill in default interrupt table (in case of spurious interrupt
 * during configuration of kernel), setup interrupt control unit
 */
void
intr_default_setup(void)
{
	int i;

	/* icu vectors */
	for (i = 0; i < NUM_LEGACY_IRQS; i++) {
		idt_allocmap[ICU_OFFSET + i] = 1;
		setgate(&idt[ICU_OFFSET + i],
		    i8259_stubs[i].ist_entry, 0, SDT_SYS386IGT,
		    SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	}

	/*
	 * Eventually might want to check if it's actually there.
	 */
	i8259_default_setup();
}
#endif

/*
 * Handle a NMI, possibly a machine check.
 * return true to panic system, false to ignore.
 */
int
x86_nmi(void)
{
	log(LOG_CRIT, "NMI port 61 %x, port 70 %x\n", inb(0x61), inb(0x70));
	return(0);
}

/*
 * Recalculate the interrupt masks from scratch.
 */
void
intr_calculatemasks(struct cpu_info *ci)
{
	int irq, level, unusedirqs, intrlevel[MAX_INTR_SOURCES];
	struct intrhand *q;

	/* First, figure out which levels each IRQ uses. */
	unusedirqs = 0xffffffff;
	for (irq = 0; irq < MAX_INTR_SOURCES; irq++) {
		int levels = 0;

		if (ci->ci_isources[irq] == NULL) {
			intrlevel[irq] = 0;
			continue;
		}
		for (q = ci->ci_isources[irq]->is_handlers; q; q = q->ih_next)
			levels |= 1 << q->ih_level;
		intrlevel[irq] = levels;
		if (levels)
			unusedirqs &= ~(1 << irq);
	}

	/* Then figure out which IRQs use each level. */
	for (level = 0; level < NIPL; level++) {
		int irqs = 0;
		for (irq = 0; irq < MAX_INTR_SOURCES; irq++)
			if (intrlevel[irq] & (1 << level))
				irqs |= 1 << irq;
		ci->ci_imask[level] = irqs | unusedirqs;
	}

	for (level = 0; level<(NIPL-1); level++)
		ci->ci_imask[level+1] |= ci->ci_imask[level];

	for (irq = 0; irq < MAX_INTR_SOURCES; irq++) {
		int maxlevel = IPL_NONE;
		int minlevel = IPL_HIGH;

		if (ci->ci_isources[irq] == NULL)
			continue;
		for (q = ci->ci_isources[irq]->is_handlers; q;
		     q = q->ih_next) {
			if (q->ih_level < minlevel)
				minlevel = q->ih_level;
			if (q->ih_level > maxlevel)
				maxlevel = q->ih_level;
		}
		ci->ci_isources[irq]->is_maxlevel = maxlevel;
		ci->ci_isources[irq]->is_minlevel = minlevel;
	}

	for (level = 0; level < NIPL; level++)
		ci->ci_iunmask[level] = ~ci->ci_imask[level];
}

/*
 * List to keep track of PCI buses that are probed but not known
 * to the firmware. Used to 
 *
 * XXX should maintain one list, not an array and a linked list.
 */
#if (NPCI > 0) && (NIOAPIC > 0)
struct intr_extra_bus {
	int bus;
	pcitag_t *pci_bridge_tag;
	pci_chipset_tag_t pci_chipset_tag;
	LIST_ENTRY(intr_extra_bus) list;
};

LIST_HEAD(, intr_extra_bus) intr_extra_buses =
    LIST_HEAD_INITIALIZER(intr_extra_buses);


void
intr_add_pcibus(struct pcibus_attach_args *pba)
{
	struct intr_extra_bus *iebp;

	iebp = malloc(sizeof(struct intr_extra_bus), M_TEMP, M_WAITOK);
	iebp->bus = pba->pba_bus;
	iebp->pci_chipset_tag = pba->pba_pc;
	iebp->pci_bridge_tag = pba->pba_bridgetag;
	LIST_INSERT_HEAD(&intr_extra_buses, iebp, list);
}

static int
intr_find_pcibridge(int bus, pcitag_t *pci_bridge_tag,
		    pci_chipset_tag_t *pci_chipset_tag)
{
	struct intr_extra_bus *iebp;
	struct mp_bus *mpb;

	if (bus < 0)
		return ENOENT;

	if (bus < mp_nbus) {
		mpb = &mp_busses[bus];
		if (mpb->mb_pci_bridge_tag == NULL)
			return ENOENT;
		*pci_bridge_tag = *mpb->mb_pci_bridge_tag;
		*pci_chipset_tag = mpb->mb_pci_chipset_tag;
		return 0;
	}

	LIST_FOREACH(iebp, &intr_extra_buses, list) {
		if (iebp->bus == bus) {
			if (iebp->pci_bridge_tag == NULL)
				return ENOENT;
			*pci_bridge_tag = *iebp->pci_bridge_tag;
			*pci_chipset_tag = iebp->pci_chipset_tag;
			return 0;
		}
	}
	return ENOENT;
}
#endif


/*
 * XXX if defined(MULTIPROCESSOR) && .. ?
 */
#if NIOAPIC > 0
int
intr_find_mpmapping(int bus, int pin, int *handle)
{
#if NPCI > 0
	int dev, func;
	pcitag_t pci_bridge_tag;
	pci_chipset_tag_t pci_chipset_tag;
#endif

#if NPCI > 0
	while (intr_scan_bus(bus, pin, handle) != 0) {
		if (intr_find_pcibridge(bus, &pci_bridge_tag,
		    &pci_chipset_tag) != 0)
			return ENOENT;
		dev = pin >> 2;
		pin = pin & 3;
		pin = PPB_INTERRUPT_SWIZZLE(pin, dev);
		pci_decompose_tag(pci_chipset_tag, pci_bridge_tag, &bus,
		    &dev, &func);
		pin |= (dev << 2);
	}
	return 0;
#else
	return intr_scan_bus(bus, pin, handle);
#endif
}

static int
intr_scan_bus(int bus, int pin, int *handle)
{
	struct mp_intr_map *mip, *intrs;

	if (bus < 0 || bus >= mp_nbus)
		return ENOENT;

	intrs = mp_busses[bus].mb_intrs;
	if (intrs == NULL)
		return ENOENT;

	for (mip = intrs; mip != NULL; mip = mip->next) {
		if (mip->bus_pin == pin) {
			*handle = mip->ioapic_ih;
			return 0;
		}
	}
	return ENOENT;
}
#endif

int
intr_allocate_slot_cpu(struct cpu_info *ci, struct pic *pic, int pin,
		       int *index)
{
	int start, slot, i;
	struct intrsource *isp;

	start = CPU_IS_PRIMARY(ci) ? NUM_LEGACY_IRQS : 0;
	slot = -1;

	simple_lock(&ci->ci_slock);
	for (i = start; i < MAX_INTR_SOURCES ; i++) {
		isp = ci->ci_isources[i];
		if (isp != NULL && isp->is_pic == pic && isp->is_pin == pin) {
			slot = i;
			break;
		}
		if (isp == NULL && slot == -1) {
			slot = i;
			continue;
		}
	}
	if (slot == -1) {
		simple_unlock(&ci->ci_slock);
		return EBUSY;
	}

	isp = ci->ci_isources[slot];
	if (isp == NULL) {
		MALLOC(isp, struct intrsource *, sizeof (struct intrsource),
		    M_DEVBUF, M_NOWAIT|M_ZERO);
		if (isp == NULL) {
			simple_unlock(&ci->ci_slock);
			return ENOMEM;
		}
		snprintf(isp->is_evname, sizeof (isp->is_evname),
		    "pin %d", pin);
		evcnt_attach_dynamic(&isp->is_evcnt, EVCNT_TYPE_INTR, NULL,
		    pic->pic_dev.dv_xname, isp->is_evname);
		ci->ci_isources[slot] = isp;
	}
	simple_unlock(&ci->ci_slock);

	*index = slot;
	return 0;
}

/*
 * A simple round-robin allocator to assign interrupts to CPUs.
 */
int
intr_allocate_slot(struct pic *pic, int legacy_irq, int pin, int level,
		   struct cpu_info **cip, int *index, int *idt_slot)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	struct intrsource *isp;
	int slot, idtvec, error;

	/*
	 * If a legacy IRQ is wanted, try to use a fixed slot pointing
	 * at the primary CPU. In the case of IO APICs, multiple pins
	 * may map to one legacy IRQ, but they should not be shared
	 * in that case, so the first one gets the legacy slot, but
	 * a subsequent allocation with a different pin will get
	 * a different slot.
	 */
	if (legacy_irq != -1) {
		ci = &cpu_info_primary;
		/* must check for duplicate pic + pin first */
		for (slot = 0 ; slot < MAX_INTR_SOURCES ; slot++) {
			isp = ci->ci_isources[slot];
			if (isp != NULL && isp->is_pic == pic &&
			    isp->is_pin == pin ) {
				goto duplicate;
			}
		}
		slot = legacy_irq;
		isp = ci->ci_isources[slot];
		if (isp == NULL) {
			MALLOC(isp, struct intrsource *,
			    sizeof (struct intrsource), M_DEVBUF,
			     M_NOWAIT|M_ZERO);
			if (isp == NULL)
				return ENOMEM;
			snprintf(isp->is_evname, sizeof (isp->is_evname),
			    "pin %d", pin);
			evcnt_attach_dynamic(&isp->is_evcnt, EVCNT_TYPE_INTR,
			    NULL, pic->pic_dev.dv_xname, isp->is_evname);
			simple_lock(&ci->ci_slock);
			ci->ci_isources[slot] = isp;
			simple_unlock(&ci->ci_slock);
		} else {
			if (isp->is_pin != pin) {
#if 0
				if (pic == &i8259_pic)
					return EINVAL;
#endif
				goto other;
			}
		}
duplicate:
#if 0
		if (pic == &i8259_pic)
			idtvec = ICU_OFFSET + legacy_irq;
		else
#endif
		{
#ifdef IOAPIC_HWMASK
			if (level > isp->is_maxlevel) {
#else
			if (isp->is_minlevel == 0 || level < isp->is_minlevel) {
#endif
				idtvec = idt_vec_alloc(APIC_LEVEL(level),
				    IDT_INTR_HIGH);
				if (idtvec == 0)
					return EBUSY;
			} else
				idtvec = isp->is_idtvec;
		}
	} else {
other:
		/*
		 * Otherwise, look for a free slot elsewhere. Do the primary
		 * CPU first.
		 */
		ci = &cpu_info_primary;
		error = intr_allocate_slot_cpu(ci, pic, pin, &slot);
		if (error == 0)
			goto found;

		/*
		 * ..now try the others.
		 */
		for (CPU_INFO_FOREACH(cii, ci)) {
			if (CPU_IS_PRIMARY(ci))
				continue;
			error = intr_allocate_slot_cpu(ci, pic, pin, &slot);
			if (error == 0)
				goto found;
		}
		return EBUSY;
found:
		idtvec = idt_vec_alloc(APIC_LEVEL(level), IDT_INTR_HIGH);
		if (idtvec == 0) {
			simple_lock(&ci->ci_slock);
			FREE(ci->ci_isources[slot], M_DEVBUF);
			ci->ci_isources[slot] = NULL;
			simple_unlock(&ci->ci_slock);
			return EBUSY;
		}
	}
	*idt_slot = idtvec;
	*index = slot;
	*cip = ci;
	return 0;
}

void *
intr_establish(int legacy_irq, struct pic *pic, int pin, int type, int level,
	       int (*handler)(void *), void *arg)
{
	struct intrhand **p, *q, *ih;
	struct cpu_info *ci;
	int slot, error, idt_vec;
	struct intrsource *source;
	struct intrstub *stubp;

#ifdef DIAGNOSTIC
	if (legacy_irq != -1 && (legacy_irq < 0 || legacy_irq > 15))
		panic("intr_establish: bad legacy IRQ value");

#if 0
	if (legacy_irq == -1 && pic == &i8259_pic)
		panic("intr_establish: non-legacy IRQ on i8259");
#endif
#endif

	error = intr_allocate_slot(pic, legacy_irq, pin, level, &ci, &slot,
	    &idt_vec);
	if (error != 0) {
		printf("failed to allocate interrupt slot for PIC %s pin %d\n",
		    pic->pic_dev.dv_xname, pin);
		return NULL;
	}

	/* no point in sleeping unless someone can free memory. */
	ih = malloc(sizeof *ih, M_DEVBUF, cold ? M_NOWAIT : M_WAITOK);
	if (ih == NULL) {
		printf("intr_establish: can't allocate malloc handler info\n");
		return NULL;
	}

	source = ci->ci_isources[slot];

	if (source->is_handlers != NULL &&
	    source->is_pic->pic_type != pic->pic_type) {
		free(ih, M_DEVBUF);
		printf("intr_establish: can't share intr source between "
		       "different PIC types (legacy_irq %d pin %d slot %d)\n",
		    legacy_irq, pin, slot);
		return NULL;
	}

	simple_lock(&ci->ci_slock);

	source->is_pin = pin;
	source->is_pic = pic;

	switch (source->is_type) {
	case IST_NONE:
		source->is_type = type;
		break;
	case IST_EDGE:
	case IST_LEVEL:
		if (source->is_type == type)
			break;
	case IST_PULSE:
		if (type != IST_NONE) {
			simple_unlock(&ci->ci_slock);
			printf("intr_establish: pic %s pin %d: can't share "
			       "type %d with %d\n", pic->pic_name, pin,
				source->is_type, type);
			free(ih, M_DEVBUF);
			return NULL;
		}
		break;
	default:
		simple_unlock(&ci->ci_slock);
		panic("intr_establish: bad intr type %d for pic %s pin %d\n",
		    source->is_type, pic->pic_dev.dv_xname, pin);
	}

	if (!cold)
		pic->pic_hwmask(pic, pin);

	/*
	 * Figure out where to put the handler.
	 * This is O(N^2), but we want to preserve the order, and N is
	 * generally small.
	 */
	for (p = &ci->ci_isources[slot]->is_handlers;
	     (q = *p) != NULL && q->ih_level > level;
	     p = &q->ih_next)
		;

	ih->ih_fun = handler;
	ih->ih_arg = arg;
	ih->ih_next = *p;
	ih->ih_level = level;
	ih->ih_pin = pin;
	ih->ih_cpu = ci;
	ih->ih_slot = slot;
	*p = ih;

	intr_calculatemasks(ci);

	simple_unlock(&ci->ci_slock);

	if (ci->ci_isources[slot]->is_resume == NULL ||
	    source->is_idtvec != idt_vec) {
		if (source->is_idtvec != 0 && source->is_idtvec != idt_vec)
			idt_vec_free(source->is_idtvec);
		source->is_idtvec = idt_vec;
		stubp = type == IST_LEVEL ?
		    &pic->pic_level_stubs[slot] : &pic->pic_edge_stubs[slot];
		ci->ci_isources[slot]->is_resume = stubp->ist_resume;
		ci->ci_isources[slot]->is_recurse = stubp->ist_recurse;
		setgate(&idt[idt_vec], stubp->ist_entry, 0, SDT_SYS386IGT,
		    SEL_KPL, GSEL(GCODE_SEL, SEL_KPL));
	}

	pic->pic_addroute(pic, ci, pin, idt_vec, type);

	if (!cold)
		pic->pic_hwunmask(pic, pin);

#ifdef INTRDEBUG
	printf("allocated pic %s type %s pin %d level %d to cpu%u slot %d idt entry %d\n",
	    pic->pic_name, type == IST_EDGE ? "edge" : "level", pin, level,
	    ci->ci_apicid, slot, idt_vec);
#endif

	return (ih);
}

/*
 * Deregister an interrupt handler.
 */
void
intr_disestablish(struct intrhand *ih)
{
	struct intrhand **p, *q;
	struct cpu_info *ci;
	struct pic *pic;
	struct intrsource *source;
	int idtvec;

	ci = ih->ih_cpu;
	pic = ci->ci_isources[ih->ih_slot]->is_pic;
	source = ci->ci_isources[ih->ih_slot];
	idtvec = source->is_idtvec;

	simple_lock(&ci->ci_slock);
	pic->pic_hwmask(pic, ih->ih_pin);	
	x86_atomic_clearbits_l(&ci->ci_ipending, (1 << ih->ih_slot));

	/*
	 * Remove the handler from the chain.
	 */
	for (p = &source->is_handlers; (q = *p) != NULL && q != ih;
	     p = &q->ih_next)
		;
	if (q == NULL) {
		simple_unlock(&ci->ci_slock);
		panic("intr_disestablish: handler not registered");
	}

	*p = q->ih_next;

	intr_calculatemasks(ci);
	pic->pic_delroute(pic, ci, ih->ih_pin, idtvec, source->is_type);
	pic->pic_hwunmask(pic, ih->ih_pin);

#ifdef INTRDEBUG
	printf("cpu%u: remove slot %d (pic %s pin %d vec %d)\n",
	    ci->ci_apicid, ih->ih_slot, pic->pic_dev.dv_xname, ih->ih_pin,
	    idtvec);
#endif

	if (source->is_handlers == NULL) {
		evcnt_detach(&source->is_evcnt);
		FREE(source, M_DEVBUF);
		ci->ci_isources[ih->ih_slot] = NULL;
#if 0
		if (pic != &i8259_pic)
			idt_vec_free(idtvec);
#endif
	}

	free(ih, M_DEVBUF);

	simple_unlock(&ci->ci_slock);
}

const char *
intr_string(int ih)
{
	static char irqstr[64];
#if NIOAPIC > 0
	struct pic *pic;
#endif

	if (ih == 0)
		panic("pci_intr_string: bogus handle 0x%x", ih);


#if NIOAPIC > 0
	if (ih & APIC_INT_VIA_APIC) {
		pic = (struct pic *)ioapic_find(APIC_IRQ_APIC(ih));
		if (pic != NULL) {
			sprintf(irqstr, "%s pin %d (irq %d)",
			    pic->pic_name, APIC_IRQ_PIN(ih), ih&0xff);
		} else {
			sprintf(irqstr, "apic %d int %d (irq %d)",
			    APIC_IRQ_APIC(ih),
			    APIC_IRQ_PIN(ih),
			    ih&0xff);
		}
	} else
		sprintf(irqstr, "irq %d", ih&0xff);
#else

	sprintf(irqstr, "irq %d", ih&0xff);
#endif
	return (irqstr);

}

#define CONCAT(x,y)	__CONCAT(x,y)

/*
 * Fake interrupt handler structures for the benefit of symmetry with
 * other interrupt sources, and the benefit of intr_calculatemasks()
 */
struct intrhand fake_softclock_intrhand;
struct intrhand fake_softnet_intrhand;
struct intrhand fake_softserial_intrhand;
struct intrhand fake_timer_intrhand;
struct intrhand fake_ipi_intrhand;

#if NLAPIC > 0 && defined(MULTIPROCESSOR)
static char *x86_ipi_names[X86_NIPI] = X86_IPI_NAMES;
#endif

/*
 * Initialize all handlers that aren't dynamically allocated, and exist
 * for each CPU.
 */
void
cpu_intr_init(struct cpu_info *ci)
{
	struct intrsource *isp;
#if NLAPIC > 0 && defined(MULTIPROCESSOR)
	int i;
#endif

	MALLOC(isp, struct intrsource *, sizeof (struct intrsource), M_DEVBUF,
	    M_WAITOK|M_ZERO);
	if (isp == NULL)
		panic("can't allocate fixed interrupt source");
	isp->is_recurse = Xsoftclock;
	isp->is_resume = Xsoftclock;
	fake_softclock_intrhand.ih_level = IPL_SOFTCLOCK;
	isp->is_handlers = &fake_softclock_intrhand;
	isp->is_pic = &softintr_pic;
	ci->ci_isources[SIR_CLOCK] = isp;
	evcnt_attach_dynamic(&isp->is_evcnt, EVCNT_TYPE_INTR, NULL,
	    ci->ci_dev->dv_xname, "softclock");

	MALLOC(isp, struct intrsource *, sizeof (struct intrsource), M_DEVBUF,
	    M_WAITOK|M_ZERO);
	if (isp == NULL)
		panic("can't allocate fixed interrupt source");
	isp->is_recurse = Xsoftnet;
	isp->is_resume = Xsoftnet;
	fake_softnet_intrhand.ih_level = IPL_SOFTNET;
	isp->is_handlers = &fake_softnet_intrhand;
	isp->is_pic = &softintr_pic;
	ci->ci_isources[SIR_NET] = isp;
	evcnt_attach_dynamic(&isp->is_evcnt, EVCNT_TYPE_INTR, NULL,
	    ci->ci_dev->dv_xname, "softnet");

	MALLOC(isp, struct intrsource *, sizeof (struct intrsource), M_DEVBUF,
	    M_WAITOK|M_ZERO);
	if (isp == NULL)
		panic("can't allocate fixed interrupt source");
	isp->is_recurse = Xsoftserial;
	isp->is_resume = Xsoftserial;
	fake_softserial_intrhand.ih_level = IPL_SOFTSERIAL;
	isp->is_handlers = &fake_softserial_intrhand;
	isp->is_pic = &softintr_pic;
	ci->ci_isources[SIR_SERIAL] = isp;
	evcnt_attach_dynamic(&isp->is_evcnt, EVCNT_TYPE_INTR, NULL,
	    ci->ci_dev->dv_xname, "softserial");

#if NLAPIC > 0
	MALLOC(isp, struct intrsource *, sizeof (struct intrsource), M_DEVBUF,
	    M_WAITOK|M_ZERO);
	if (isp == NULL)
		panic("can't allocate fixed interrupt source");
	isp->is_recurse = Xrecurse_lapic_ltimer;
	isp->is_resume = Xresume_lapic_ltimer;
	fake_timer_intrhand.ih_level = IPL_CLOCK;
	isp->is_handlers = &fake_timer_intrhand;
	isp->is_pic = &local_pic;
	ci->ci_isources[LIR_TIMER] = isp;
	evcnt_attach_dynamic(&isp->is_evcnt, EVCNT_TYPE_INTR, NULL,
	    ci->ci_dev->dv_xname, "timer");

#ifdef MULTIPROCESSOR
	MALLOC(isp, struct intrsource *, sizeof (struct intrsource), M_DEVBUF,
	    M_WAITOK|M_ZERO);
	if (isp == NULL)
		panic("can't allocate fixed interrupt source");
	isp->is_recurse = Xrecurse_lapic_ipi;
	isp->is_resume = Xresume_lapic_ipi;
	fake_ipi_intrhand.ih_level = IPL_IPI;
	isp->is_handlers = &fake_ipi_intrhand;
	isp->is_pic = &local_pic;
	ci->ci_isources[LIR_IPI] = isp;

	for (i = 0; i < X86_NIPI; i++)
		evcnt_attach_dynamic(&ci->ci_ipi_events[i], EVCNT_TYPE_INTR,
		    NULL, ci->ci_dev->dv_xname, x86_ipi_names[i]);
#endif
#endif

	intr_calculatemasks(ci);

}

#ifdef MULTIPROCESSOR
void
x86_intlock(struct intrframe *iframe)
{
	if (iframe->if_ppl < IPL_SCHED)
		spinlockmgr(&kernel_lock, LK_EXCLUSIVE|LK_CANRECURSE, 0);
}

void
x86_intunlock(struct intrframe *iframe)
{
	if (iframe->if_ppl < IPL_SCHED)
		spinlockmgr(&kernel_lock, LK_RELEASE, 0);
}

void
x86_softintlock(void)
{
	spinlockmgr(&kernel_lock, LK_EXCLUSIVE|LK_CANRECURSE, 0);
}

void
x86_softintunlock(void)
{
	spinlockmgr(&kernel_lock, LK_RELEASE, 0);
}
#endif

#ifdef INTRDEBUG
void
intr_printconfig(void)
{
	int i;
	struct intrhand *ih;
	struct intrsource *isp;
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;

	for (CPU_INFO_FOREACH(cii, ci)) {
		printf("cpu%d: interrupt masks:\n", ci->ci_apicid);
		for (i = 0; i < NIPL; i++)
			printf("IPL %d mask %lx unmask %lx\n", i,
			    (u_long)ci->ci_imask[i], (u_long)ci->ci_iunmask[i]);
		simple_lock(&ci->ci_slock);
		for (i = 0; i < MAX_INTR_SOURCES; i++) {
			isp = ci->ci_isources[i];
			if (isp == NULL)
				continue;
			printf("cpu%u source %d is pin %d from pic %s maxlevel %d\n",
			    ci->ci_apicid, i, isp->is_pin,
			    isp->is_pic->pic_name, isp->is_maxlevel);
			for (ih = isp->is_handlers; ih != NULL;
			     ih = ih->ih_next)
				printf("\thandler %p level %d\n",
				    ih->ih_fun, ih->ih_level);

		}
		simple_unlock(&ci->ci_slock);
	}
}
#endif
