/*	$KAME: natpt_soctl.h,v 1.22 2002/12/16 09:21:50 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * cmd for use with ioctl at the socket
 *	_IO()		no parameters
 *	_IOR()		copy out parameters
 *	_IOW()		copy in	 parameters
 *	_IOWR()		copy in/out parameters
 */

#define NATPT_SETIF	_IOW ('n', 0, struct natpt_msgBox) /* Set interface side */
#define NATPT_GETIF	_IOWR('n', 1, struct natpt_msgBox) /* Get interface side */
#define NATPT_ENBTRANS	_IOW ('n', 2, struct natpt_msgBox) /* Enable translation */
#define NATPT_DSBTRANS	_IOW ('n', 3, struct natpt_msgBox) /* Disable translation */
#define NATPT_SETRULES	_IOW ('n', 4, struct natpt_msgBox) /* Set rules */
#define NATPT_RMRULE	_IOW ('n', 5, struct natpt_msgBox) /* Get rule */
#define NATPT_RENUMRULE	_IOW ('n', 6, struct natpt_msgBox) /* Flush rule */
#define NATPT_FLUSHRULE	_IOW ('n', 7, struct natpt_msgBox) /* Renumber rule */
#define NATPT_SETPREFIX	_IOW ('n', 8, struct natpt_msgBox) /* Set prefix */
#define NATPT_GETPREFIX	_IOWR('n', 9, struct natpt_msgBox) /* Get prefix */
#define NATPT_SETVALUE	_IOW ('n', 10, struct natpt_msgBox) /* Set value */
#define NATPT_GETVALUE	_IOWR('n', 11, struct natpt_msgBox) /* Get value */
#define NATPT_TESTLOG	_IOW ('n', 12, struct natpt_msgBox) /* Test log */

#define NATPT_SESSIONS	_IOWR('n', 13, struct natpt_msgBox) /* show sessions */
#define NATPT_XLATE	_IOWR('n', 14, struct natpt_msgBox) /* show xlate */

#define NATPT_BREAK	_IO  ('n', 255)			/* stop */

/*
 *
 */
struct natpt_msgBox {
	int size;
	int flags;
#define NATPT_FLUSH	0
#define NATPT_FLUSHALL	1
#define NATPT_FLUSHPREFIX	2

/* for NATPT_XLATE */
#define	NATPT_originalXLate	(-1)
#define	NATPT_duplicateXLate	(1)
#define	NATPT_releaseXLate	(0)

#define NATPT_DEBUG	1
#define NATPT_DUMP	2
	caddr_t freight;
	union {
		u_int M_uint;
		int M_int[2];
		caddr_t M_caddr;
		struct in6_addr M_in6addr;
	} M_data;
};

#define m_uint	M_data.M_uint
#define m_int0	M_data.M_int[0]
#define m_int1	M_data.M_int[1]
#define m_in6addr	M_data.M_in6addr
#define	m_caddr M_data.M_caddr
