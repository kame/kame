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
//#	$Id: natpt_var.h,v 1.1 1999/08/12 12:41:14 shin Exp $
//#
//#------------------------------------------------------------------------
*/

/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

extern	int	 ptr_initialized;
extern	int	 ip6_protocol_tr;

extern	struct ifnet	*ptr_ip6src;

struct _cSlot	*lookingForIncomingV4Rule	__P((struct _cv *));
struct _cSlot	*lookingForOutgoingV4Rule	__P((struct _cv *));
struct _cSlot	*lookingForIncomingV6Rule	__P((struct _cv *));
struct _cSlot	*lookingForOutgoingV6Rule	__P((struct _cv *));
int		 _ptrEnableTrans		__P((caddr_t));
int		 _ptrDisableTrans		__P((caddr_t));
int		 _ptrSetRule			__P((caddr_t));
int		 _ptrSetFaithRule		__P((caddr_t));
int		 _ptrFlushRule			__P((caddr_t));
int		 _ptrSetPrefix			__P((caddr_t));

int		 _ptrBreak			__P((void));


struct ifBox	*ptr_asIfBox			__P((char *));
struct ifBox	*ptr_setIfBox			__P((char *));

int		 ptr_log			__P((int, int, void *, size_t));
void		 ptr_debugProbe			__P((void));
void		 ptr_initialize			__P((void));

struct _tSlot	*lookingForOutgoingV4Hash	__P((struct _cv *));
struct _tSlot	*lookingForIncomingV4Hash	__P((struct _cv *));
struct _tSlot	*lookingForOutgoingV6Hash	__P((struct _cv *));
struct _tSlot	*lookingForIncomingV6Hash	__P((struct _cv *));
struct _tSlot	*internIncomingV4Hash		__P((int, struct _cSlot *, struct _cv *));
struct _tSlot	*internOutgoingV4Hash		__P((int, struct _cSlot *, struct _cv *));
struct _tSlot	*internIncomingV6Hash		__P((int, struct _cSlot *, struct _cv *));
struct _tSlot	*internOutgoingV6Hash		__P((int, struct _cSlot *, struct _cv *));

struct mbuf	*translatingIPv4		__P((struct _cv *, struct _pat *));
struct mbuf	*translatingICMPv4		__P((struct _cv *, struct ipaddr *, struct ipaddr *));
struct mbuf	*translatingTCPv4		__P((struct _cv *, struct ipaddr *, struct ipaddr *));

struct mbuf	*translatingIPv6		__P((struct _cv *, struct _pat *));
struct mbuf	*translatingICMPv6		__P((struct _cv *, struct ipaddr *, struct ipaddr *));
struct mbuf	*translatingTCPv6		__P((struct _cv *, struct ipaddr *, struct ipaddr *));
struct mbuf	*translatingUDPv6		__P((struct _cv *, struct ipaddr *, struct ipaddr *));
