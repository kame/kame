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
//#	$SuMiRe: showvar.h,v 1.3 1998/09/17 01:15:08 shin Exp $
//#	$Id: showvar.h,v 1.1 1999/08/08 23:31:11 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if !defined(_NETPM_SHOWVAR_H_)
#define	_NETPM_SHOWVAR_H_

void		 doPmaShowInterface	__P((char *));
void		 doPmaShowSide		__P((void));
void		 doPmaShowGlobal	__P((char *));
void		 doPmaShowFilrule	__P((char *));
void		 doPmaShowNatRule	__P((char *, int, int));
void		 doPmaShowStat		__P((void));
void		 doPmaShowRoute		__P((void));
void		 doPmaShowRouteStatus	__P((void));
void		 doPmaShowSelfaddr	__P((void));
void		 doPmaXlate		__P((int));
void		 doPmaShowCells		__P((void));
void		 doPmaShowKmem		__P((int));

void		 showPmBox		__P((pmBox *, int));
struct _pmBox	*readPmBox		__P((void));

int		 openKvm		__P((void));
int		 readNL			__P((caddr_t, int, char *));
int		 readKvm		__P((caddr_t, int, int));
void		 closeKvm		__P((void));

#endif	/* _NETPM_SHOWVAR_H_	*/
