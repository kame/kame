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
//#	$Id: natpt_soctl.h,v 1.1 1999/08/12 12:41:13 shin Exp $
//#
//#------------------------------------------------------------------------
*/

/* cmd for use with ioctl at the socket				*/
/*	_IO()		no parameters		*/
/*	_IOR()		copy out parameters	*/
/*	_IOW()		copy in	 parameters	*/
/*	_IOWR()		copy in/out parameters	*/

#define	SIOCSETIF	_IOW ('n',   0, struct msgBox)	/* Set interface side	*/
#define SIOCGETIF	_IOWR('n',   1, struct msgBox)	/* Get interface sidde	*/
#define	SIOCENBTRANS	_IOW ('n',   2, struct msgBox)	/* Enable  translation	*/
#define SIOCDSBTRANS	_IOW ('n',   3, struct msgBox)	/* Disable translation	*/
#define	SIOCSETRULE	_IOW ('n',   4, struct msgBox)	/* Set rule		*/
#define	SIOCGETRULE	_IOWR('n',   5, struct msgBox)	/* Get rule		*/
#define SIOCFLUSHRULE	_IOW ('n',   6, struct msgBox)	/* Flush rule		*/
#define	SIOCSETPREFIX	_IOW ('n',   8, struct msgBox)	/* Set prefix		*/
#define	SIOCGETPREFIX	_IOWR('n',   9, struct msgBox)	/* Get prefix		*/

#define SIOCBREAK	_IO  ('n', 255)			/* stop			*/


typedef	struct msgBox
{
    int		 flags;
#define	IF_EXTERNAL		(0x01)		/* SIOC(GET|SET)IF		*/
#define	IF_INTERNAL		(0x02)
#define	IF_MASK			(0x03)

#define	PTR_STATIC		(0x10)		/* SIOT(SET|GET)RULE		*/
#define	PTR_DYNAMIC		(0x20)
#define PTR_FAITH		(0x40)
#define	PTR_MASK		(0xf0)

#if	0
#define	TRANS_44		(0x00)
#define	TRANS_46		(0x10)
#define	TRANS_64		(0x20)
#define	TRANS_66		(0x30)
#define	TRANS_MASK		(0x30)
#endif

#define	PREFIX_FAITH		(0x100)		/* SIOC(SET|GET)PREFIX		*/
#define	PREFIX_NATPT		(0x200)
#define	PREFIX_MASK		(0x300)

    int		 size;			/* sizeof(*freight)		*/
    char	*freight;
    union
    {
	char	 M_ifName[IFNAMSIZ];
	char	 M_aux[32];
    }		 M_dat;
}   msgBox;

#define	m_ifName	M_dat.M_ifName
#define	m_aux		M_dat.M_aux
