/*	$KAME: pm_include.h,v 1.2 2000/02/22 14:07:12 itojun Exp $	*/

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
//#	$SuMiRe: pm_include.h,v 1.4 1998/09/14 19:49:42 shin Exp $
//#	$Id: pm_include.h,v 1.2 2000/02/22 14:07:12 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/kernel.h>
#endif
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>

#if defined(__bsdi__) || (__FreeBSD__)
#include <sys/socket.h>
#endif

#include <net/bpf.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>		/* n_long			*/
#include <netinet/ip.h>

#include <netpm/pm_insns.h>
#include <netpm/pm_defs.h>
#include <netpm/pm_ioctl.h>
#include <netpm/pm_list.h>
#include <netpm/pm_log.h>

#include <netpm/pm_extern.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	pm_DebugLookingHashEntry	0x00000001
#define	pm_DebugAsAttEntry		0x00000002
#define	pm_DebugGetAttEntry		0x00000004
#define	pm_DebugaddAttEntry		0x00000008
#define	pm_DebugNatFtp			0x00000010
#define	pm_DebugToUs			0x00000100

#if PMDEBUG
#if defined(__bsdi__)
#define	DebugOut	aprint_debug
#else
#define	DebugOut	printf
#endif
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

