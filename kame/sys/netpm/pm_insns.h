/*	$KAME: pm_insns.h,v 1.2 2000/02/22 14:07:12 itojun Exp $	*/

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
//#	$SuMiRe: pm_insns.h,v 1.2 1998/09/14 19:49:43 shin Exp $
//#	$Id: pm_insns.h,v 1.2 2000/02/22 14:07:12 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#ifndef _PM_INSNS_H
#define _PM_INSNS_H

/* NAT and Packet Filtering Language Machine Code Instruction */
 
/*
 * The instruction encodings.
 */

/* instruction cleasses */

#define PM_CLASS(code)	((code) & 0x07)		/* 00000111 */

#define PM_LD		0x00			/* _____000 */
#define PM_LDX		0x01			/* _____001 */
#define PM_ST		0x02			/* _____010 */
#define PM_STX		0x03			/* _____011 */
#define PM_ALU		0x04			/* _____100 */
#define PM_JMP		0x05			/* _____101 */
#define PM_RET		0x06			/* _____110 */
#define PM_MISC		0x07			/* _____111 */

/* ld/ldx fields */

#define PM_SIZE(code)	((code) & 0x18)		/* 00011000 */

#define PM_W		0x00			/* ___00___ */
#define PM_H		0x08			/* ___01___ */
#define PM_B		0x10			/* ___10___ */

#define PM_MODE(code)	((code) & 0xe0)		/* 11100000 */

#define PM_IMM		0x00			/* 000_____ */
#define PM_ABS		0x20			/* 001_____ */
#define PM_IND		0x40			/* 010_____ */
#define PM_MEM		0x60			/* 011_____ */
#define PM_LEN		0x80			/* 100_____ */
#define PM_MSH		0xa0			/* 101_____ */

/* alu/jmp fields */
#define PM_OP(code)	((code) & 0xf0)		/* 11110000 */

#define PM_ADD		0x00			/* 0000____ */
#define PM_SUB		0x10			/* 0001____ */
#define PM_MUL		0x20			/* 0010____ */
#define PM_DIV		0x30			/* 0011____ */
#define PM_OR		0x40			/* 0100____ */
#define PM_AND		0x50			/* 0101____ */
#define PM_LSH		0x60			/* 0110____ */
#define PM_RSH		0x70			/* 0111____ */
#define PM_NEG		0x80			/* 1000____ */

#define PM_JA		0x00			/* 0000____ */
#define PM_JEQ		0x10			/* 0001____ */
#define PM_JGT		0x20			/* 0010____ */
#define PM_JGE		0x30			/* 0011____ */
#define PM_JSET		0x40			/* 0100____ */

#define PM_SRC(code)	((code) & 0x08)		/* 00001000 */

#define PM_K		0x00			/* ____0___ */
#define PM_X		0x08			/* ____1___ */

/* ret - PM_K and PM_X also apply */
#define PM_RVAL(code)	((code) & 0x18)		/* 00011000 */
#define PM_A		0x10			/* ___10___ */

/* misc */
#define PM_MISCOP(code)	((code) & 0xf8)		/* 1111_1000 */
#define PM_TAX		0x00			/* 0000_0___ */
#define PM_TXA		0x80			/* 1000_0___ */
#define PM_FCALL	0x08			/* 0000_1___ */

/*	CAUTION!						*/
/*	In case function call, function number was encoded	*/
/*	into jf field.						*/

/*
 * The instruction data structure.
 */

struct pm_program
{
	u_int	pm_len;
	struct	pm_insn *pm_insns;
};

struct pm_insn
{
	u_short	code;
	u_char	jt;
	u_char	jf;
	long	k;
};

/*
 * Macros for insn array initializers.
 */

#define PM_STMT(code, k)		{ (u_short)(code), 0, 0, k }
#define PM_JUMP(code, k, jt, jf)	{ (u_short)(code), jt, jf, k }

/*
 * Number of scratch memory words (for PM_LD|PM_MEM and PM_ST).
 */

#define PM_MEMWORDS	16

/*
 * packet direction (inout)
 */

#define PM_INBOUND	0
#define PM_OUTBOUND	1

/* 
 * pm_filter() return value
 */

#define PM_ERROR	((u_int)-1)	/* internal error		*/
#define PM_PASS		((u_int)0)	/* allow -> through packet	*/
#define PM_BLOCK	((u_int)1)	/* deny -> drop packet		*/
#define PM_NEXTRULE	((u_int)2)	/* continue -> try next filter	*/
#define	PM_NOMATCH	((u_int)3)	/* no filer rule matched	*/

/*
 * function ID (funcid in pm_setfunc)
 */

#define PM_DONAT	0
#define PM_DOIPOPT	1
#define PM_DOLOG	2
#define	PM_DOICMP	3

#define PM_FUNCNUM	4

#define	PM_LOGHEAD	1
#define	PM_LOGBODY	2


#endif /* _PM_INSNS_H */
