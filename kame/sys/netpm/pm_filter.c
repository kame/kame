/*	$KAME: pm_filter.c,v 1.2 2000/02/22 14:07:11 itojun Exp $	*/

/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$SuMiRe: pm_filter.c,v 1.4 1998/09/14 19:49:40 shin Exp $
//#	$Id: pm_filter.c,v 1.2 2000/02/22 14:07:11 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <netpm/pm_include.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(sparc) || defined(mips) || defined(ibm032)
#define PM_ALIGN
#endif

#ifndef PM_ALIGN
#define EXTRACT_SHORT(p)	((u_short)ntohs(*(u_short *)p))
#define EXTRACT_LONG(p)		(ntohl(*(u_long *)p))
#else
#define EXTRACT_SHORT(p)\
	((u_short)\
		((u_short)*((u_char *)p+0)<<8|\
		 (u_short)*((u_char *)p+1)<<0))
#define EXTRACT_LONG(p)\
		((u_long)*((u_char *)p+0)<<24|\
		 (u_long)*((u_char *)p+1)<<16|\
		 (u_long)*((u_char *)p+2)<<8|\
		 (u_long)*((u_char *)p+3)<<0)
#endif

#ifdef KERNEL
#define MINDEX(m, k) \
{ \
	register int len = m->m_len; \
 \
	while (k >= len) { \
		k -= len; \
		m = m->m_next; \
		if (m == 0) \
			return 0; \
		len = m->m_len; \
	} \
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static int	m_xword		__P((struct mbuf *, int, int *));
static int	m_xhalf		__P((struct mbuf *, int, int *));
static u_int	_pm_filter	__P((struct pm_insn *, u_char *, u_int, u_int));

int		pm_validate	__P((struct pm_insn *, int));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static int
m_xword(m, k, err)
	register struct mbuf *m;
	register int k, *err;
{
	register int len;
	register u_char *cp, *np;
	register struct mbuf *m0;

	len = m->m_len;
	while (k >= len) {
		k -= len;
		m = m->m_next;
		if (m == 0)
			goto bad;
		len = m->m_len;
	}
	cp = mtod(m, u_char *) + k;
	if (len - k >= 4) {
		*err = 0;
		return EXTRACT_LONG(cp);
	}
	m0 = m->m_next;
	if (m0 == 0 || m0->m_len + len - k < 4)
		goto bad;
	*err = 0;
	np = mtod(m0, u_char *);
	switch (len - k) {

	case 1:
		return (cp[k] << 24) | (np[0] << 16) | (np[1] << 8) | np[2];

	case 2:
		return (cp[k] << 24) | (cp[k + 1] << 16) | (np[0] << 8) | 
			np[1];

	default:
		return (cp[k] << 24) | (cp[k + 1] << 16) | (cp[k + 2] << 8) |
			np[0];
	}
    bad:
	*err = 1;
	return 0;
}


static int
m_xhalf(m, k, err)
	register struct mbuf *m;
	register int k, *err;
{
	register int len;
	register u_char *cp;
	register struct mbuf *m0;

	len = m->m_len;
	while (k >= len) {
		k -= len;
		m = m->m_next;
		if (m == 0)
			goto bad;
		len = m->m_len;
	}
	cp = mtod(m, u_char *) + k;
	if (len - k >= 2) {
		*err = 0;
		return EXTRACT_SHORT(cp);
	}
	m0 = m->m_next;
	if (m0 == 0)
		goto bad;
	*err = 0;
	return (cp[k] << 8) | mtod(m0, u_char *)[0];
 bad:
	*err = 1;
	return 0;
}
#endif


/* ------------------------------------------------------------------------ */

/*
 * function table
 */

static u_long (*pm_funcs[PM_FUNCNUM])(u_char *, struct mbuf *, u_long);

int pm_setfunc(int funcid, u_long (*func)(u_char *, struct mbuf *, u_long))
{
	if (funcid < 0 || funcid >= PM_FUNCNUM) {
		return -1;
	}
	pm_funcs[funcid] = func;
	return 0;
}

/* ------------------------------------------------------------------------ */

u_long
pm_filter(Cell *rules, struct mbuf *mbuf)
{
    Cell		*p;
    struct pm_program	*prg;
    struct mbuf		*m0;
    u_int		 pktlen;
    u_long		 rv;

    pktlen = 0;
    for (m0 = mbuf; m0 != 0; m0 = m0->m_next)
	pktlen += m0->m_len;

    for (p = rules; p; p = CDR(p))
    {
	/* CAUTION: CAAR has pm_program, and CADR has compacted filter rule  */
	prg = (struct pm_program *)CAAR(p);
	rv = _pm_filter(prg->pm_insns, (u_char *)mbuf, pktlen, 0);
	if ((rv == PM_PASS) || (rv == PM_BLOCK))
	    return (rv);
    }

    return (PM_NOMATCH);
}


/*
 * Execute the filter program starting at pc on the packet p
 * wirelen is the length of the original packet
 * buflen is the amount of data present
 */
static	u_int
_pm_filter(pc, p, wirelen, buflen)
	register struct pm_insn *pc;
	register u_char *p;
	u_int wirelen;
	register u_int buflen;
{
	register u_long A, X;
	register int k;
	long mem[PM_MEMWORDS];

	if (pc == 0)
		/*
		 * No filter means accept all.
		 */
		return (u_int)-1;

	A = 0;
	X = 0;

	--pc;
	while (1) {
		++pc;
		switch (pc->code) {

		default:
#ifdef KERNEL
			return 0;
#else
			abort();
#endif			
		case PM_RET|PM_K:
			return (u_int)pc->k;

		case PM_RET|PM_A:
			return (u_int)A;

		case PM_LD|PM_W|PM_ABS:
			k = pc->k;
			if (k + sizeof(long) > buflen) {
#ifdef KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xword((struct mbuf *)p, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else
				return 0;
#endif
			}
#ifdef PM_ALIGN
			if (((int)(p + k) & 3) != 0)
				A = EXTRACT_LONG(&p[k]);
			else
#endif
				A = ntohl(*(long *)(p + k));
			continue;

		case PM_LD|PM_H|PM_ABS:
			k = pc->k;
			if (k + sizeof(short) > buflen) {
#ifdef KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xhalf((struct mbuf *)p, k, &merr);
				continue;
#else
				return 0;
#endif
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case PM_LD|PM_B|PM_ABS:
			k = pc->k;
			if (k >= buflen) {
#ifdef KERNEL
				register struct mbuf *m;

				if (buflen != 0)
					return 0;
				m = (struct mbuf *)p;
				MINDEX(m, k);
				A = mtod(m, u_char *)[k];
				continue;
#else
				return 0;
#endif
			}
			A = p[k];
			continue;

		case PM_LD|PM_W|PM_LEN:
			A = wirelen;
			continue;

		case PM_LDX|PM_W|PM_LEN:
			X = wirelen;
			continue;

		case PM_LD|PM_W|PM_IND:
			k = X + pc->k;
			if (k + sizeof(long) > buflen) {
#ifdef KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xword((struct mbuf *)p, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else
				return 0;
#endif
			}
#ifdef PM_ALIGN
			if (((int)(p + k) & 3) != 0)
				A = EXTRACT_LONG(&p[k]);
			else
#endif
				A = ntohl(*(long *)(p + k));
			continue;

		case PM_LD|PM_H|PM_IND:
			k = X + pc->k;
			if (k + sizeof(short) > buflen) {
#ifdef KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xhalf((struct mbuf *)p, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else
				return 0;
#endif
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case PM_LD|PM_B|PM_IND:
			k = X + pc->k;
			if (k >= buflen) {
#ifdef KERNEL
				register struct mbuf *m;

				if (buflen != 0)
					return 0;
				m = (struct mbuf *)p;
				MINDEX(m, k);
				A = mtod(m, u_char *)[k];
				continue;
#else
				return 0;
#endif
			}
			A = p[k];
			continue;

		case PM_LDX|PM_MSH|PM_B:
			k = pc->k;
			if (k >= buflen) {
#ifdef KERNEL
				register struct mbuf *m;

				if (buflen != 0)
					return 0;
				m = (struct mbuf *)p;
				MINDEX(m, k);
				X = (mtod(m, char *)[k] & 0xf) << 2;
				continue;
#else
				return 0;
#endif
			}
			X = (p[pc->k] & 0xf) << 2;
			continue;

		case PM_LD|PM_IMM:
			A = pc->k;
			continue;

		case PM_LDX|PM_IMM:
			X = pc->k;
			continue;

		case PM_LD|PM_MEM:
			A = mem[pc->k];
			continue;
			
		case PM_LDX|PM_MEM:
			X = mem[pc->k];
			continue;

		case PM_ST:
			mem[pc->k] = A;
			continue;

		case PM_STX:
			mem[pc->k] = X;
			continue;

		case PM_JMP|PM_JA:
			pc += pc->k;
			continue;

		case PM_JMP|PM_JGT|PM_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JGE|PM_K:
			pc += (A >= pc->k) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JEQ|PM_K:
			pc += (A == pc->k) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JSET|PM_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JGT|PM_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JGE|PM_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JEQ|PM_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case PM_JMP|PM_JSET|PM_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case PM_ALU|PM_ADD|PM_X:
			A += X;
			continue;
			
		case PM_ALU|PM_SUB|PM_X:
			A -= X;
			continue;
			
		case PM_ALU|PM_MUL|PM_X:
			A *= X;
			continue;
			
		case PM_ALU|PM_DIV|PM_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
			
		case PM_ALU|PM_AND|PM_X:
			A &= X;
			continue;
			
		case PM_ALU|PM_OR|PM_X:
			A |= X;
			continue;

		case PM_ALU|PM_LSH|PM_X:
			A <<= X;
			continue;

		case PM_ALU|PM_RSH|PM_X:
			A >>= X;
			continue;

		case PM_ALU|PM_ADD|PM_K:
			A += pc->k;
			continue;
			
		case PM_ALU|PM_SUB|PM_K:
			A -= pc->k;
			continue;
			
		case PM_ALU|PM_MUL|PM_K:
			A *= pc->k;
			continue;
			
		case PM_ALU|PM_DIV|PM_K:
			A /= pc->k;
			continue;
			
		case PM_ALU|PM_AND|PM_K:
			A &= pc->k;
			continue;
			
		case PM_ALU|PM_OR|PM_K:
			A |= pc->k;
			continue;

		case PM_ALU|PM_LSH|PM_K:
			A <<= pc->k;
			continue;

		case PM_ALU|PM_RSH|PM_K:
			A >>= pc->k;
			continue;

		case PM_ALU|PM_NEG:
			A = -A;
			continue;

		case PM_MISC|PM_TAX:
			X = A;
			continue;

		case PM_MISC|PM_TXA:
			A = X;
			continue;
		case PM_MISC|PM_FCALL:
		    {
			struct	ip	*ip;

			ip = mtod((struct mbuf *)p, struct ip *);
			A = (*pm_funcs[pc->jf])((u_char *)ip, (struct mbuf *)p, pc->k);
			continue;
		    }
		}
	}
}


/*
 * Return true if the 'fcode' is a valid filter program.
 * The constraints are that each jump be forward and to a valid
 * code.  The code must terminate with either an accept or reject. 
 * 'valid' is an array for use by the routine (it must be at least
 * 'len' bytes long).  
 *
 * The kernel needs to be able to verify an application's filter code.
 * Otherwise, a bogus program could easily crash the system.
 */
int
pm_validate(f, len)
	struct pm_insn *f;
	int len;
{
	register int i;
	register struct pm_insn *p;

	for (i = 0; i < len; ++i) {
		/*
		 * Check that that jumps are forward, and within 
		 * the code block.
		 */
		p = &f[i];
		if (PM_CLASS(p->code) == PM_JMP) {
			register int from = i + 1;

			if (PM_OP(p->code) == PM_JA) {
				if (from + p->k >= len)
					return 0;
			}
			else if (from + p->jt >= len || from + p->jf >= len)
				return 0;
		}
		/*
		 * Check that memory operations use valid addresses.
		 */
		if ((PM_CLASS(p->code) == PM_ST ||
		     (PM_CLASS(p->code) == PM_LD && 
		      (p->code & 0xe0) == PM_MEM)) &&
		    (p->k >= PM_MEMWORDS || p->k < 0))
			return 0;
		/*
		 * Check for constant division by 0.
		 */
		if (p->code == (PM_ALU|PM_DIV|PM_K) && p->k == 0)
			return 0;
	}
	return PM_CLASS(f[len - 1].code) == PM_RET;
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
init_filter()
{
#if defined(__bsdi__)
    u_long	 pm_ipopt	__P((u_char *, struct mbuf *, u_long));
    u_long	 pm_packetlog	__P((u_char *, struct mbuf *, u_long));
    u_long	 pm_icmp	__P((u_char *, struct mbuf *, u_long));
#endif

    pm_setfunc(PM_DOIPOPT, pm_ipopt);
    pm_setfunc(PM_DOLOG,   pm_packetlog);
    pm_setfunc(PM_DOICMP,  pm_icmp);
}
