/*	$KAME: defs.h,v 1.9 2001/10/25 07:18:25 fujisawa Exp $	*/

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

#ifndef TRUE
#define	TRUE			1
#define FALSE			0
#endif

/*
 *
 */

#define	PROTO_ICMP		0x01
#define	PROTO_TCP		0x02
#define	PROTO_UDP		0x04

#define	NATPT_MAP64		1
#define	NATPT_MAP46		2
#define	NATPT_MAP44		3


#define	GETA			64

#define	ROUNDUP(x)		roundup(x, sizeof(void *))

#ifndef roundup						/* comes from <sys/param.h> */
#define	roundup(x, y)		((((x)+((y)-1))/(y))*(y))  /* to any y */
#define	roundup2(x, y)		(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

#define SIN6(s)			((struct sockaddr_in6 *)s)

#define	isDebug(d)		(u_debug & (d))

/* Bit assign for _debug						*/
#define	D_LEXTOKEN		0x00000001
#define	D_YYDEBUG		0x00000010
#define	D_SHOWROUTE		0x00000100
#define	D_SHOWCSLOT		0x00000200
#define	D_DUMPIOCTL		0x00010000

struct ruletab
{
	struct pAddr	*from;
	union inaddr	*fdaddr;
	struct pAddr	*to;
	union inaddr	*tdaddr;
	u_short		*sports;	/* u_short (*)[3] */
	u_short		*dports;	/* u_short (*)[2] */
	int		 proto;
	int		 bidir;
};


/*
 *
 */

extern int	 u_debug;
extern char	*yytext;


/* cfparse.y */
int		yyparse			__P((void));

/* cftoken.l */
void		 switchToBuffer		__P((char *));
void		 reassembleCommandLine	__P((int, char *[]));

/* main.c */
void		 printHelp		__P((int, char *));


/* End of defs.h */
