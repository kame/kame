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
//#	$SuMiRe: miscvar.h,v 1.3 1998/09/17 01:14:58 shin Exp $
//#	$Id: miscvar.h,v 1.1 1999/08/08 23:31:08 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if !defined(_NETPM_MISCVAR_H_)
#define	_NETPM_MISCVAR_H_	

extern	int		_fd;
extern	int		_debug;


void	 doPmaSetGlobal		__P((char *, Cell *, int));
void	 doPmaRemoveGlobal	__P((char *, Cell *));
void	 doPmaSetNatRule	__P((struct _msgBox *, int, Cell *, Cell *, int));
void	 doPmaRemoveNatRule	__P((char *, int, Cell *));

void	 doPmaSetRoute		__P((int, addrBlock *, addrBlock *, u_int));
void	 doPmaRemoveRoute	__P((Cell *));
int	 countNatRules		__P((char *, int));
int	 countRouteRules	__P((void));
void	 doPmaGetSelfaddr	__P((void));
void	 doPmaSetSelfaddrFlags	__P((u_long, int));

void	 doPmaShowBind		__P((void));
void	 doPmaShowReal		__P((void));
void	 doPmaShowVirtual	__P((void));
void	 doPmaImmShowStat	__P((void));
void	 doPmaImmShowLinkStat	__P((void));

Cell	*LST_cons		__P((void *, void *));
Cell	*LST_last		__P((Cell *));
int	 LST_length		__P((Cell *));
Cell	*LST_hookup		__P((Cell *, void *));
Cell	*LST_hookup_list	__P((Cell **, void *));

int	 _masktobits		__P((u_long));
void	 debugProbe		__P((char *));
void	 close_fd		__P((void));
void	 init_misc		__P((void));

#endif	/* _NETPM_MISCVAR_H_	*/
