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
//#	$SuMiRe: defs.h,v 1.6 1998/09/17 01:14:50 shin Exp $
//#	$Id: defs.h,v 1.1 1999/08/08 23:31:07 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#define	SAME			0

#if !defined(TRUE)
#define	FALSE			0
#define	TRUE			(~FALSE)
#endif

#if !defined(NIL)
#define	NIL			NULL
#endif

#define	ERROR			(-1)

#define	SZNCE	sizeof(natRuleEntry)
#define	SZAPT	sizeof(addrBlock)

#define	isDebug(d)		(_debug & (d))

/* Bit assign for _debug						*/
#define	D_LEXTOKEN		0x00000001
#define	D_YYDEBUG		0x00000010
#define	D_SHOWROUTE		0x00000100
#define	D_DUMPIOCTL		0x00010000


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

typedef	struct	pm_program	Progs;
typedef	struct	pm_insn		Insns;


#if !defined(_PM_DEFS_H)
typedef	struct	_cell
{
    struct  _cell   *car;
    struct  _cell   *cdr;
}   Cell;

#endif
