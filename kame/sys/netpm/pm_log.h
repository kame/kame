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
//#	$SuMiRe: pm_log.h,v 1.4 1998/09/14 19:49:50 shin Exp $
//#	$Id: pm_log.h,v 1.1 1999/08/12 12:41:10 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#if !defined(_PM_LOG_H)
#define	_PM_LOG_H


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(PM_USE_SOCKET)
#define	LSIZE	(MHLEN - sizeof(struct l_hdr))	/* LBUF within MBUF	*/
#else
#define	LSIZE	128				/* LBUF alone		*/
#endif
#define	LLEN	(LSIZE - sizeof(struct l_hdr))	/* Normal data len	*/


/*  Header at beginning of each lbuf.					*/

struct	l_hdr
{
    struct lbuf	*lh_next;	/* Next lbuf				*/
    u_short	 lh_type;	/* Type of data in this lbuf		*/
#define	LOG_MSG		(0)
#define	LOG_IP		(1)
#define	LOG_ATT		(2)
#define	LOG_ROUTE	(3)
    u_short	 lh_pri;	/* Priorities of thie message		*/
    size_t	 lh_size;	/* Size of data in this lbuf		*/
    u_long	 lh_sec;	/* Timestamp in second			*/
    u_long	 lh_usec;	/* Timestamp in microsecond		*/
};


/*  Header at beginning of logged packet.				*/

struct	l_pkt
{
    char	ifName[IFNAMSIZ];
    char	__buf[4];
};


/*  Header at beginning of active Transration Table			*/

struct	l_att
{
    u_int		_stub;
#define	ATT_ALLOC	(0)
#define	ATT_REMOVE	(1)
#define	ATT_FASTEN	(2)
#define	ATT_UNFASTEN	(3)
#define	ATT_REGIST	(4)
    caddr_t		_addr;
    struct  _aTT	_att;
    struct  _tcpstate	_state;
};


/*  Definition of whole lbuf						*/

struct	lbuf
{
    struct	l_hdr	l_hdr;
    union
    {
	struct	l_pkt	l_pkt;
	struct	l_att	l_att;
	char		__buf[LLEN];
    }   l_dat;
};


#endif	/* !_PM_LOG_H	*/
