/*	$KAME: cftoken.l,v 1.5 2002/01/11 10:02:26 fujisawa Exp $	*/

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

%{
#include <sys/types.h>

#include <err.h>
#include <string.h>

#include "cfparse.h"
#include "defs.h"

#define	YY_DECL		int _yylex(void)
#define	YY_NO_UNPUT

int		getDecimal		__P((char *));
int		getHexadecimal		__P((char *));
int		getDQuoteString		__P((char *));
int		SNAMEorKeyword		__P((char *));


%}


letter			[a-zA-Z_]
digit			[0-9]
hexdigit		[0-9A-Fa-f]
letter_or_digit		[0-9a-zA-Z_]
dot			"."
colon			":"
ipv4addr		{digit}{1,3}({dot}{digit}{1,3}){0,3}
ipv6addr		{hexdigit}{0,4}({colon}{hexdigit}{0,4}){2,7}
ipv4enbeddedipv6addr	{hexdigit}{0,4}({colon}{hexdigit}{0,4}){2,5}{colon}{ipv4addr}

%%

#[^\n]*\n			/* ignore comment line */
^[ \t]*\n			/* ignore blank line */
[ \t]+				/* eat up whitespace */
[\n]				/* toss return */
{letter}{letter_or_digit}*	return (SNAMEorKeyword(yytext));
{digit}+			return (getDecimal(yytext));
0x{hexdigit}+			return (getHexadecimal(yytext));
{ipv4addr}			return (SIPV4ADDR);
{ipv6addr}			return (SIPV6ADDR);
{ipv4enbeddedipv6addr}		return (SIPV6ADDR);

"-"				return (SMINUS);
"/"				return (SSLASH);
":"				return (SCOLON);
"="				return (SEQUAL);
"?"				return (SQUESTION);

\"				return (getDQuoteString(yytext));
.				return (SOTHER);

%%


#include "cftokeninclude.c"
