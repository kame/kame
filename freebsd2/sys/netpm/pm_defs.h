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
//#	$SuMiRe: pm_defs.h,v 1.12 1998/09/17 00:47:15 shin Exp $
//#	$Id: pm_defs.h,v 1.1 1999/08/05 14:33:18 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if !defined(_PM_DEFS_H)
#define	_PM_DEFS_H


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	SAME			0
#define	NIL			(NULL)

#if !defined(FALSE)
#define	FALSE			0
#define	TRUE			(~FALSE)
#endif

#define	MAXATTENTRY		(4096)

#define	NAT_STATIC		(1)
#define	NAT_DYNAMIC		(2)
#define	NAT_LDIR		(3)

#define	PAT_ADDRONLY		(6)
#define	PAT_PORTFIRST		(7)
#define	PAT_ADDRFIRST		(8)


#if !defined(PM_USE_SOCKET) && !defined(PM_USE_IOCTL)
#define	PM_USE_SOCKET		(1)
#endif

#if defined(PM_USE_SOCKET) && defined(PM_USE_IOCTL)
#undef	PM_USE_IOCTL
#endif

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static MALLOC_DEFINE(M_PM, "SuMiRe", "Packet Management by SuMiRe");
#endif

#if !defined(PMDEBUG) && !defined(KAME) && !defined(M_PM)
#define	M_PM			M_TEMP
#endif


/*
//##
//#------------------------------------------------------------------------
//#	Enum definitions.
//#------------------------------------------------------------------------
*/

typedef enum
{
    NoSide,
    InSide,
    OutSide,
}   Side;


typedef	enum
{
    UnBound,
    InBound,
    OutBound,
}   InOut;


/*
//##
//#------------------------------------------------------------------------
//#	Struct definitions.
//#------------------------------------------------------------------------
*/

typedef	struct	_cell
{
    struct  _cell   *car;
    struct  _cell   *cdr;
}   Cell;


typedef	struct	_resCtrl
{
    int		 _used;
    int		 _free;
    Cell	*used;
    Cell	*free;
}   resCtrl;


typedef	struct	_pmBox
{
    Side	     side;
    char	     ifName[IFNAMSIZ];
    struct ifnet    *ifnet;
    struct _natBox  *natBox;
    struct _filBox  *filBox;
}   pmBox;


typedef	struct	_natBox
{
    resCtrl	 global;		/* gAddr control box		*/
    Cell	*natStatic;		/* List of natRuleEnt		*/
    Cell	*natDynamic;		/* List of natRuleEnt		*/
    Cell	*immBind;
}   natBox;


typedef	struct	_filBoxHalf
{
    Cell	*filRuleMae;
    Cell	*filRuleAto;
}   filBoxHalf;


typedef struct	_filBox
{
    struct _filBoxHalf	i;
    struct _filBoxHalf	o;
}   filBox;


typedef	struct
{
    int		    addrflags;
#define	NAT_GLOBAL	0x00000001
#define	LD_VIRTUAL	0x00000002
#define	MAYBE_ALIAS	0x00000004
#define	RESETFLAG	0x80000000		/* for _pmSetAddrFlag()	     */
    struct in_addr  ifaddr;
    struct in_addr  braddr;
    struct in_addr  netmask;
}   SelfAddr;


typedef	struct
{
    u_char		inout;
    u_char		type;
    u_short		ip_p;
    u_short		th_sport;
    u_short		th_dport;
    struct in_addr	ip_src;
    struct in_addr	ip_dst;
}   IPAssoc;


typedef	struct	_aTT
{
    u_char		 pm_type;
/*	#define	ATT_STATIC		NAT_STATIC			*/
/*	#define	ATT_DYNAMIC		NAT_DYNAMIC			*/
/*	#define ATT_LDIR		NAT_LDIR			*/
    u_char		 ip_p;
    u_short		 th_lport;
    u_short		 th_fport;
    u_short		 th_rport;
    struct  in_addr	 ip_laddr;
    struct  in_addr	 ip_faddr;
    struct  in_addr	 ip_raddr;
    time_t		 tstamp;
    u_long		 inbound;
    u_long		 outbound;
    union
    {
	struct  _natRuleEnt *rule;	/* (or (pm_type eq NAT_STATIC)
					       (pm_type eq NAT_DYNAMIC))     */
	caddr_t		     imm[2];	/* (pm_type eq NAT_LDIR)	     */
					/* virtualAddr and realAddr	     */
    }	_u;

    union
    {
	struct _idseq
	{
	    n_short	  icd_id;
	    n_short	  icd_seq;
	}		  ih_idseq;
	struct _tcpstate *tcp;
    }			  suit;
}   aTT;


typedef	struct	_tcpstate
{
    short	_state;
    short	_session;
    u_long	_ip_id[2];	/* IP packet Identification			*/
				/*    [0]: current packet			*/
				/*    [1]: just before packet			*/
    u_short	_port[2];	/* [0]:outGoing srcPort, [1]:inComing dstPort	*/
/*  u_long	_iss;			initial send sequence number		*/
    u_long	_delta[3];	/* Sequence delta				*/
				/*    [0]: current     (cumulative)		*/
				/*    [1]: just before (cumulative)		*/
				/*    [2]: (this time)				*/
}   TCPstate;


/*									*/
/*	CAUTION								*/
/*									*/
/*  This table data (address and port) is stored in NetworkByteOrder.	*/

typedef	struct
{
    u_char	linkc;
    u_char	flags;
#define	ADDR_STATIC	(0x0001)
#define	ADDR_DYNAMIC	(0x0002)
#define	ADDR_ASSIGNED	(ADDR_STATIC|ADDR_DYNAMIC)
    u_short		port;
    struct in_addr	addr;
}   gAddr;


typedef	struct
{
    u_short		 ip_p;
    u_char		 type;
#define	IN_ADDR_ANY	 (0)
#define	IN_ADDR_SINGLE	 (1)
#define	IN_ADDR_MASK	 (2)
#define	IN_ADDR_RANGE	 (3)
    u_char		 policy;
/*	#define	NRC_PORTFIRST		PAT_PORTFIRST		default	*/
/*	#define	NRC_ADDRFIRST		PAT_ADDRFIRST			*/
    struct in_addr	 addr[2];
    struct in_addr	 ptrn;		/* ptrn ::= addr & mask		*/
    Cell		*gList;		/* List of gAddr		*/
    Cell		*gAddrCur;	/* Current gAddr		*/
    u_short		 port[2];
    u_short		 curport;
    u_short		 pspace;
}   addrBlock;


typedef	struct	_natRuleEnt	
{
    u_short		 type;
/*	#define	NRC_STATIC		NAT_STATIC		default	*/
/*	#define	NRC_DYNAMIC		NAT_DYNAMIC			*/
/*	#define	NRC_LDIR		NAT_LDIR			*/
    u_short		 policy;
/*	#define	NRC_PORTFIRST		PAT_PORTFIRST		default	*/
/*	#define	NRC_ADDRFIRST		PAT_ADDRFIRST			*/
    Cell		*local;		/* List of addrBlock		*/
    Cell		*foreign;	/* List of addrBlock		*/
    int			 gAddrLen;	/* Length of gAddrBlock		*/
    u_long		 inbound;
    u_long		 outbound;
}   natRuleEnt;


typedef	struct
{
    u_short		 pm_type;
/*	#define	AP_STATIC		NAT_STATIC			*/
/*	#define	AP_DYNAMIC		NAT_DYNAMIC			*/
/*	#define	AP_LDIR			NAT_LDIR			*/
    u_short		 ip_p;
    u_short		 th_lport;
    u_short		 th_fport;
    struct  in_addr	 ip_laddr;
    struct  in_addr	 ip_faddr;
    union
    {
	struct  _natRuleEnt *rule;
	caddr_t		     imm[2];	/* virtualAddr and realAddr	*/
    }	_u;
}   AliasPair;


/*									*/
/*	CAUTION								*/
/*									*/
/*  This table data (address and port) is stored in NetworkByteOrder.	*/

typedef	struct
{
    u_short		 va_flags;
#define	VIP_IN_SERVICE	0x0001
    u_short		 NumOfRrealaddr;
    struct	in_addr	 virtualAddr;
    Cell		*realAddrHead;
    Cell		*realAddrTail;
    u_long		 inbound;
    u_long		 outbound;
}   virtualAddr;


typedef	struct
{
    u_short		 ra_flags;
#define	RIP_IN_SERVICE	0x0001
#define	RIP_BINDED	0x0002
    u_short		 threshold;
    struct	in_addr	 realAddr;
    u_long		 selected;
    u_long		 inbound;
    u_long		 outbound;
}   realAddr;

#endif	/* !_PM_DEFS_H	*/
