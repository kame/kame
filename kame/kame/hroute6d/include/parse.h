/* 
 * $Id: parse.h,v 1.1 1999/08/08 23:29:41 itojun Exp $
 */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * Copyright(C)1997 by Hitachi, Ltd.
 */

#define INVALID_KEY  30

/*
 * Constants for GLOBAL configuration parameters.
 */
#define GLOBAL		28

#define QUIET		0
#define PORT		1
#define POISON		2 
#define HORIZON		3
#define NOHORIZON	4
#define TRACE		5
#define DEFAULTMETRIC	6
#define HEADERLEN	7
#define NEXTHOP		8
#define ROUTETAG	9
#define AUTH		10
#define COMPATIBLE	11
#define STATIC		12
#define IGNORE		13

/*
 * Constants for INTERFACE configuration parameters.
 */

#define INTERFACE	14 /* this means both */
			   /* 'interface section' and 'interface command' */
#define IN		15
#define NOIN		16
#define OUT		17
#define NOOUT		18
#define AGGREGATE	19
#define SITE		20
#define NOSITE		21
#define GENDEFAULT	22
#define FILTER		23
#define METRICIN	24
#define METRICOUT	25
#define PROPAGATE	26
#define SRCADDR		27
