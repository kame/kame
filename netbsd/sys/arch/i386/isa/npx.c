/*	$NetBSD: npx.c,v 1.69 1999/03/24 05:51:02 mrg Exp $	*/

#if 0
#define IPRINTF(x)	printf x
#else
#define	IPRINTF(x)
#endif

/*-
 * Copyright (c) 1994, 1995, 1998 Charles M. Hannum.  All rights reserved.
 * Copyright (c) 1990 William Jolitz.
 * Copyright (c) 1991 The Regents of the University of California.
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
 *	@(#)npx.c	7.2 (Berkeley) 5/12/91
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/device.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>

#include <uvm/uvm_extern.h>

#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/pio.h>
#include <machine/cpufunc.h>
#include <machine/pcb.h>
#include <machine/trap.h>
#include <machine/specialreg.h>

#include <dev/isa/isareg.h>
#include <dev/isa/isavar.h>
#include <i386/isa/icu.h>

/*
 * 387 and 287 Numeric Coprocessor Extension (NPX) Driver.
 *
 * We do lazy initialization and switching using the TS bit in cr0 and the
 * MDP_USEDFPU bit in mdproc.
 *
 * DNA exceptions are handled like this:
 *
 * 1) If there is no NPX, return and go to the emulator.
 * 2) If someone else has used the NPX, save its state into that process's PCB.
 * 3a) If MDP_USEDFPU is not set, set it and initialize the NPX.
 * 3b) Otherwise, reload the process's previous NPX state.
 *
 * When a process is created or exec()s, its saved cr0 image has the TS bit
 * set and the MDP_USEDFPU bit clear.  The MDP_USEDFPU bit is set when the
 * process first gets a DNA and the NPX is initialized.  The TS bit is turned
 * off when the NPX is used, and turned on again later when the process's NPX
 * state is saved.
 */

#define	fldcw(addr)		__asm("fldcw %0" : : "m" (*addr))
#define	fnclex()		__asm("fnclex")
#define	fninit()		__asm("fninit")
#define	fnsave(addr)		__asm("fnsave %0" : "=m" (*addr))
#define	fnstcw(addr)		__asm("fnstcw %0" : "=m" (*addr))
#define	fnstsw(addr)		__asm("fnstsw %0" : "=m" (*addr))
#define	fp_divide_by_0()	__asm("fldz; fld1; fdiv %st,%st(1); fwait")
#define	frstor(addr)		__asm("frstor %0" : : "m" (*addr))
#define	fwait()			__asm("fwait")
#define	read_eflags()		({register u_long ef; \
				  __asm("pushfl; popl %0" : "=r" (ef)); \
				  ef;})
#define	write_eflags(x)		({register u_long ef = (x); \
				  __asm("pushl %0; popfl" : : "r" (ef));})
#define	clts()			__asm("clts")
#define	stts()			lcr0(rcr0() | CR0_TS)

int npxdna __P((struct proc *));
void npxexit __P((void));
int npxintr __P((void *));
static int npxprobe1 __P((struct isa_attach_args *));
static void npxsave1 __P((void));

struct npx_softc {
	struct device sc_dev;
	void *sc_ih;
};

int npxprobe __P((struct device *, struct cfdata *, void *));
void npxattach __P((struct device *, struct device *, void *));

struct cfattach npx_ca = {
	sizeof(struct npx_softc), npxprobe, npxattach
};

enum npx_type {
	NPX_NONE = 0,
	NPX_INTERRUPT,
	NPX_EXCEPTION,
	NPX_BROKEN,
};

struct proc	*npxproc;

static	enum npx_type		npx_type;
static	int			npx_nointr;
volatile u_int			npx_intrs_while_probing;
volatile u_int			npx_traps_while_probing;

static inline int
npxprobe1(ia)
	struct isa_attach_args *ia;
{
	int control;
	int status;

	ia->ia_iosize = 16;
	ia->ia_msize = 0;

	/*
	 * Finish resetting the coprocessor, if any.  If there is an error
	 * pending, then we may get a bogus IRQ13, but probeintr() will handle
	 * it OK.  Bogus halts have never been observed, but we enabled
	 * IRQ13 and cleared the BUSY# latch early to handle them anyway.
	 */
	fninit();
	delay(1000);		/* wait for any IRQ13 (fwait might hang) */

	/*
	 * Check for a status of mostly zero.
	 */
	status = 0x5a5a;
	fnstsw(&status);
	if ((status & 0xb8ff) == 0) {
		/*
		 * Good, now check for a proper control word.
		 */
		control = 0x5a5a;	
		fnstcw(&control);
		if ((control & 0x1f3f) == 0x033f) {
			/*
			 * We have an npx, now divide by 0 to see if exception
			 * 16 works.
			 */
			control &= ~(1 << 2);	/* enable divide by 0 trap */
			fldcw(&control);
			npx_traps_while_probing = npx_intrs_while_probing = 0;
			fp_divide_by_0();
			if (npx_traps_while_probing != 0) {
				/*
				 * Good, exception 16 works.
				 */
				npx_type = NPX_EXCEPTION;
				ia->ia_irq = IRQUNK;	/* zap the interrupt */
			} else if (npx_intrs_while_probing != 0) {
				/*
				 * Bad, we are stuck with IRQ13.
				 */
				npx_type = NPX_INTERRUPT;
			} else {
				/*
				 * Worse, even IRQ13 is broken.  Use emulator.
				 */
				npx_type = NPX_BROKEN;
				ia->ia_irq = IRQUNK;
			}
			return 1;
		}
	}
	/*
	 * Probe failed.  There is no usable FPU.
	 */
	npx_type = NPX_NONE;
	return 0;
}

/*
 * Probe routine.  Initialize cr0 to give correct behaviour for [f]wait
 * whether the device exists or not (XXX should be elsewhere).  Set flags
 * to tell npxattach() what to do.  Modify device struct if npx doesn't
 * need to use interrupts.  Return 1 if device exists.
 */
int
npxprobe(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct	isa_attach_args *ia = aux;
	int	irq;
	int	result;
	u_long	save_eflags;
	unsigned save_imen;
	struct	gate_descriptor save_idt_npxintr;
	struct	gate_descriptor save_idt_npxtrap;

	/*
	 * This routine is now just a wrapper for npxprobe1(), to install
	 * special npx interrupt and trap handlers, to enable npx interrupts
	 * and to disable other interrupts.  Someday isa_configure() will
	 * install suitable handlers and run with interrupts enabled so we
	 * won't need to do so much here.
	 */
	irq = NRSVIDT + ia->ia_irq;
	save_eflags = read_eflags();
	disable_intr();
	save_idt_npxintr = idt[irq].gd;
	save_idt_npxtrap = idt[16].gd;
	setgate(&idt[irq].gd, probeintr, 0, SDT_SYS386IGT, SEL_KPL);
	setgate(&idt[16].gd, probetrap, 0, SDT_SYS386TGT, SEL_KPL);
	save_imen = imen;
	imen = ~((1 << IRQ_SLAVE) | (1 << ia->ia_irq));
	SET_ICUS();

	/*
	 * Partially reset the coprocessor, if any.  Some BIOS's don't reset
	 * it after a warm boot.
	 */
	outb(0xf1, 0);		/* full reset on some systems, NOP on others */
	delay(1000);
	outb(0xf0, 0);		/* clear BUSY# latch */

	/*
	 * We set CR0 in locore to trap all ESC and WAIT instructions.
	 * We have to turn off the CR0_EM bit temporarily while probing.
	 */
	lcr0(rcr0() & ~(CR0_EM|CR0_TS));
	enable_intr();
	result = npxprobe1(ia);
	disable_intr();
	lcr0(rcr0() | (CR0_EM|CR0_TS));

	imen = save_imen;
	SET_ICUS();
	idt[irq].gd = save_idt_npxintr;
	idt[16].gd = save_idt_npxtrap;
	write_eflags(save_eflags);
	return (result);
}


/*
 * Attach routine - announce which it is, and wire into system
 */
void
npxattach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	struct npx_softc *sc = (void *)self;
	struct isa_attach_args *ia = aux;

	switch (npx_type) {
	case NPX_INTERRUPT:
		printf("\n");
		lcr0(rcr0() & ~CR0_NE);
		sc->sc_ih = isa_intr_establish(ia->ia_ic, ia->ia_irq,
		    IST_EDGE, IPL_NONE, npxintr, 0);
		break;
	case NPX_EXCEPTION:
		printf(": using exception 16\n");
		break;
	case NPX_BROKEN:
		printf(": error reporting broken; not using\n");
		npx_type = NPX_NONE;
		return;
	case NPX_NONE:
		return;
	}

	lcr0(rcr0() & ~(CR0_EM|CR0_TS));
	fninit();
	if (npx586bug1(4195835, 3145727) != 0)
		printf("WARNING: Pentium FDIV bug detected!\n");
	lcr0(rcr0() | (CR0_TS));
}

/*
 * Record the FPU state and reinitialize it all except for the control word.
 * Then generate a SIGFPE.
 *
 * Reinitializing the state allows naive SIGFPE handlers to longjmp without
 * doing any fixups.
 *
 * XXX there is currently no way to pass the full error state to signal
 * handlers, and if this is a nested interrupt there is no way to pass even
 * a status code!  So there is no way to have a non-naive SIGFPE handler.  At
 * best a handler could do an fninit followed by an fldcw of a static value.
 * fnclex would be of little use because it would leave junk on the FPU stack.
 * Returning from the handler would be even less safe than usual because
 * IRQ13 exception handling makes exceptions even less precise than usual.
 */
int
npxintr(arg)
	void *arg;
{
	register struct proc *p = npxproc;
	register struct save87 *addr;
	struct intrframe *frame = arg;
	int code;

	uvmexp.traps++;
	IPRINTF(("Intr"));

	if (p == 0 || npx_type == NPX_NONE) {
		printf("npxintr: p = %p, curproc = %p, npx_type = %d\n",
		    p, curproc, npx_type);
		panic("npxintr: came from nowhere");
	}

	/*
	 * Clear the interrupt latch.
	 */
	outb(0xf0, 0);

	/*
	 * If we're saving, ignore the interrupt.  The FPU will generate
	 * another one when we restore the state later.
	 */
	if (npx_nointr != 0)
		return (1);

#ifdef DIAGNOSTIC
	/*
	 * At this point, npxproc should be curproc.  If it wasn't, the TS bit
	 * should be set, and we should have gotten a DNA exception.
	 */
	if (p != curproc)
		panic("npxintr: wrong process");
#endif

	/*
	 * Find the address of npxproc's saved FPU state.  (Given the invariant
	 * above, this is always the one in curpcb.)
	 */
	addr = &p->p_addr->u_pcb.pcb_savefpu;
	/*
	 * Save state.  This does an implied fninit.  It had better not halt
	 * the cpu or we'll hang.
	 */
	fnsave(addr);
	fwait();
	/*
	 * Restore control word (was clobbered by fnsave).
	 */
	fldcw(&addr->sv_env.en_cw);
	fwait();
	/*
	 * Remember the exception status word and tag word.  The current
	 * (almost fninit'ed) fpu state is in the fpu and the exception
	 * state just saved will soon be junk.  However, the implied fninit
	 * doesn't change the error pointers or register contents, and we
	 * preserved the control word and will copy the status and tag
	 * words, so the complete exception state can be recovered.
	 */
	addr->sv_ex_sw = addr->sv_env.en_sw;
	addr->sv_ex_tw = addr->sv_env.en_tw;

	/*
	 * Pass exception to process.
	 */
	if (USERMODE(frame->if_cs, frame->if_eflags)) {
		/*
		 * Interrupt is essentially a trap, so we can afford to call
		 * the SIGFPE handler (if any) as soon as the interrupt
		 * returns.
		 *
		 * XXX little or nothing is gained from this, and plenty is
		 * lost - the interrupt frame has to contain the trap frame
		 * (this is otherwise only necessary for the rescheduling trap
		 * in doreti, and the frame for that could easily be set up
		 * just before it is used).
		 */
		p->p_md.md_regs = (struct trapframe *)&frame->if_es;
#ifdef notyet
		/*
		 * Encode the appropriate code for detailed information on
		 * this exception.
		 */
		code = XXX_ENCODE(addr->sv_ex_sw);
#else
		code = 0;	/* XXX */
#endif
		trapsignal(p, SIGFPE, code);
	} else {
		/*
		 * This is a nested interrupt.  This should only happen when
		 * an IRQ13 occurs at the same time as a higher-priority
		 * interrupt.
		 *
		 * XXX
		 * Currently, we treat this like an asynchronous interrupt, but
		 * this has disadvantages.
		 */
		psignal(p, SIGFPE);
	}

	return (1);
}

/*
 * Wrapper for the fnsave instruction.  We set the TS bit in the saved CR0 for
 * this process, so that it will get a DNA exception on the FPU instruction and
 * force a reload.  This routine is always called with npx_nointr set, so that
 * any pending exception will be thrown away.  (It will be caught again if/when
 * the FPU state is restored.)
 *
 * This routine is always called at spl0.  If it might called with the NPX
 * interrupt masked, it would be necessary to forcibly unmask the NPX interrupt
 * so that it could succeed.
 */
static inline void
npxsave1()
{
	struct proc *p = npxproc;

	fnsave(&p->p_addr->u_pcb.pcb_savefpu);
	p->p_addr->u_pcb.pcb_cr0 |= CR0_TS;
	fwait();
}

/*
 * Implement device not available (DNA) exception
 *
 * If the we were the last process to use the FPU, we can simply return.
 * Otherwise, we save the previous state, if necessary, and restore our last
 * saved state.
 */
int
npxdna(p)
	struct proc *p;
{

	if (npx_type == NPX_NONE) {
		IPRINTF(("Emul"));
		return (0);
	}

#ifdef DIAGNOSTIC
	if (cpl != 0 || npx_nointr != 0)
		panic("npxdna: masked");
#endif

	p->p_addr->u_pcb.pcb_cr0 &= ~CR0_TS;
	clts();

	/*
	 * Initialize the FPU state to clear any exceptions.  If someone else
	 * was using the FPU, save their state (which does an implicit
	 * initialization).
	 */
	npx_nointr = 1;
	if (npxproc != 0 && npxproc != p) {
		IPRINTF(("Save"));
		npxsave1();
	} else {
		IPRINTF(("Init"));
		fninit();
		fwait();
	}
	npx_nointr = 0;
	npxproc = p;

	if ((p->p_md.md_flags & MDP_USEDFPU) == 0) {
		fldcw(&p->p_addr->u_pcb.pcb_savefpu.sv_env.en_cw);
		p->p_md.md_flags |= MDP_USEDFPU;
	} else {
		/*
		 * The following frstor may cause an IRQ13 when the state being
		 * restored has a pending error.  The error will appear to have
		 * been triggered by the current (npx) user instruction even
		 * when that instruction is a no-wait instruction that should
		 * not trigger an error (e.g., fnclex).  On at least one 486
		 * system all of the no-wait instructions are broken the same
		 * as frstor, so our treatment does not amplify the breakage.
		 * On at least one 386/Cyrix 387 system, fnclex works correctly
		 * while frstor and fnsave are broken, so our treatment breaks
		 * fnclex if it is the first FPU instruction after a context
		 * switch.
		 */
		frstor(&p->p_addr->u_pcb.pcb_savefpu);
	}

	return (1);
}

/*
 * Drop the current FPU state on the floor.
 */
void
npxdrop()
{
	struct proc *p = npxproc;

	npxproc = 0;
	stts();
	p->p_addr->u_pcb.pcb_cr0 |= CR0_TS;
}

/*
 * Save npxproc's FPU state.
 *
 * The FNSAVE instruction clears the FPU state.  Rather than reloading the FPU
 * immediately, we clear npxproc and turn on CR0_TS to force a DNA and a reload
 * of the FPU state the next time we try to use it.  This routine is only
 * called when forking or core dumping, so the lazy reload at worst forces us
 * to trap once per fork(), and at best saves us a reload once per fork().
 */
void
npxsave()
{

#ifdef DIAGNOSTIC
	if (cpl != 0 || npx_nointr != 0)
		panic("npxsave: masked");
#endif
	IPRINTF(("Fork"));
	clts();
	npx_nointr = 1;
	npxsave1();
	npx_nointr = 0;
	npxproc = 0;
	stts();
}
