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
//#	$SuMiRe: pm_ioctl.h,v 1.7 1998/09/14 19:49:44 shin Exp $
//#	$Id: pm_ioctl.h,v 1.1 1999/08/05 14:33:19 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if defined(PM_USE_SOCKET)
/* Options for use with [gs]etsockopt at the IPPROTO_PM level.	*/
#define	PM_SOCKOPT		(0x01)

#define	PMIOCCONF		(  9)
#define	PMIOCGETADDR		( 10)
#define	PMIOCSETADDRFLG		( 11)

#define	PMIOCSETGLOBAL		( 16)
#define	PMIOCREMGLOBAL		( 17)
#define	PMIOCFLGLOBAL		( 18)

#define	PMIOCSETNAT 		( 32)
#define	PMIOCREMNAT		( 33)
#define	PMIOCFLNAT		( 34)

#define	PMIOCSETFRULE		( 48)
#define	PMIOCADDFRULE		( 49)
#define	PMIOCFLFRULE		( 50)

#define	PMIOCSETIMM		(126)
#define	PMIOCREMIMM		(127)

#define	PMIOCADDROUTE		(160)
#define	PMIOCREMROUTE		(161)
#define	PMIOCFLROUTE		(162)

#define	PMIOCENBLNAT		(176)
#define	PMIOCDSBLNAT		(177)
#define	PMIOCENBLFIL		(178)
#define	PMIOCDSBLFIL		(179)
#define	PMIOCENBLROUTE		(180)
#define	PMIOCDSBLROUTE		(181)

#define	PMIOCPMENB		(192)
#define	PMIOCPMDSB		(193)

#define	PMIOCENROUTE		(194)
#define	PMIOCDSROUTE		(195)

#else	/* if !defined(PM_USE_SOCKET)	*/

#define	PMIOCDEBUG	_IO ('P' ,  0)

#define	PMIOCSETLOGLVL	_IOW('P',   8, int)

#define	PMIOCCONF	_IOW('P',   9, struct if_natfil)
#define	PMIOCGETADDR	_IO ('P',  10)
#define	PMIOCSETADDRFLG	_IOW('P',  11, struct _msgBox)	/* ...		     */

#define	PMIOCSETGLOBAL	_IOW('P',  16, struct ip_global) /* Set Global addr  */
#define	PMIOCREMGLOBAL	_IOW('P',  17, struct _msgBox)	/* Remove ...	     */
#define	PMIOCFLGLOBAL	_IOW('P',  18, struct _msgBox)	/* Flush ...	     */

#define	PMIOCSETNAT	_IOW('P',  32, struct _natRule)	/* Set NAT rule	     */
#define	PMIOCREMNAT	_IOW('P',  33, struct _msgBox)	/* Remove ...	     */
#define	PMIOCFLNAT	_IOW('P',  34, struct _natRule)	/* Flush ...	     */

#define	PMIOCSETFRULE	_IOW('P',  48, struct _filRule)	/* Set Filter rule   */
#define	PMIOCADDFRULE	_IOW('P',  49, struct _filRule)	/* Add Filter rule   */
#define	PMIOCFLFRULE	_IOW('P',  50, struct _filRule)	/* Flush ...	     */

#define	PMIOCSETIMM	_IOW('P', 126, struct imm_rule)	/* Set IMM rule	     */
#define	PMIOCREMIMM	_IOW('P', 127, struct imm_rule)	/* Remove IMM rule   */

#if	obsolete
#define	PMIOCAREM	_IOW('P', 128, struct _natRule)	/* Remove ATT entry  */
#endif

#define	PMIOCADDROUTE	_IOW('P', 160, struct _fwdRoute)/* Add forward route */
#define PMIOCREMROUTE	_IOW('P', 161, struct _msgBox)/* Remove ...	     */
#define PMIOCFLROUTE	_IO ('P', 162)			/* Flush  ...	     */

#define	PMIOCENBLNAT	_IO ('P', 176)		/* Enable  nat			*/
#define	PMIOCDSBLNAT	_IO ('P', 177)		/* Disable nat			*/
#define	PMIOCENBLFIL	_IO ('P', 178)		/* Enable  IP filter		*/
#define	PMIOCDSBLFIL	_IO ('P', 179)		/* Disable IP filter		*/
#define	PMIOCENBLROUTE	_IO ('P', 180)		/* Enable  routing		*/
#define	PMIOCDSBLROUTE	_IO ('P', 181)		/* Disable routing		*/

#define	PMIOCPMENB	_IO ('P', 192)		/* Enable  PacketManagement  */
#define	PMIOCPMDSB	_IO ('P', 193)		/* Disable PacketManagement  */

#define	PMIOCENROUTE	_IO ('P', 194)		/* Enable  routing	     */
#define	PMIOCDSROUTE	_IO ('P', 195)		/* Disable routing	     */

#endif	/* defined(PM_USE_SOCKET)	*/


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

typedef	struct	_natRuleEntry
{
    u_short		type;
/*	#define	NRE_STATIC		NAT_STATIC			*/
/*	#define	NRE_DYNAMIC		NAT_DYNAMIC			*/
    u_short		policy;
/*	#define	NRE_ADDRONLY		PAT_ADDRONLY			*/
/*	#define	NRE_PORTFIRST		PAT_PORTFIRST			*/
/*	#define	NRE_ADDRFIRST		PAT_ADDRFIRST			*/
    u_int		srcCnt;
    u_int		dstCnt;
    addrBlock		addr[1];
}   natRuleEntry;


typedef	struct	imm_entry
{
    struct	in_addr	virtual;
    struct	in_addr	real[1];
}   immEntry;


typedef	struct	_fwdRoute
{
    u_char		 type[2];	/* [0]: source address		*/
					/* [1]: destination address	*/
/*	#define	IN_ADDR_ANY	 (0)					*/
/*	#define	IN_ADDR_SINGLE	 (1)					*/
/*	#define	IN_ADDR_MASK	 (2)					*/
/*	#define	IN_ADDR_RANGE	 (3)					*/
    u_short		 ip_p;
    u_short		 th_sport[2];
    u_short		 th_dport[2];
    struct in_addr	 ip_src[3];	/* [0]: address			*/
					/* [1]: netmask or end address	*/
					/* [2]: masked address		*/
    struct in_addr	 ip_dst[3];
    struct in_addr	 ip_via;
    struct route	*_route;
}   fwdRoute;


typedef	struct	_msgBox
{
    int		 msgtype;		/* Valid when socket used	*/
    int		 flags;
#define	IF_EXTERNAL		(0x01)	/* In case msgtype == PMIOCCONF */
#define	IF_INTERNAL		(0x02)
#define	IMM_VIRTUAL		(0x01)	/* In case msgtype == PMIOCSETIMM */
#define	IMM_REAL		(0x02)
#define	IMM_BIND		(0x10)
#define	IMM_IN_SERVICE		(0x20)
#define	IMM_OUT_OF_SERVICE	(0x40)
#define	FILFLAGMASK		(0xff)	/* In case mstgype == PMIOCADDFRULE */
#define	FIL_BEFORE		(0x01)
#define	FIL_AFTER		(0x02)
#define	FIL_INPUT		(0x10)
#define	FIL_OUTPUT		(0x20)
    int		 nums;			/* Number of element		*/
    int		 size;			/* sizeof(element)		*/
    char	*freight;
    union
    {
	char			 M_ifName[IFNAMSIZ];
	char			 M_aux[32];
	struct _fwdRoute	 M_fwdRoute;
	char			*M_frRules;
    }	M_dat;
}   msgBox;

#define	m_ifName	M_dat.M_ifName
#define	m_aux		M_dat.M_aux
#define	m_fwdRoute	M_dat.M_fwdRoute
#define	m_frRules	M_dat.M_frRules
#define m_frInsns	freight


/*
//##
//#------------------------------------------------------------------------
//#	BPF related definitions
//#------------------------------------------------------------------------
*/

#define		BPF_NAT		0x10
#define		BPF_IPO		0x20


