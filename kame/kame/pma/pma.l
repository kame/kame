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
//#	$SuMiRe: pma.l,v 1.6 1998/09/17 01:15:01 shin Exp $
//#	$Id: pma.l,v 1.1 1999/08/08 23:31:10 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

%{

#include <string.h>

#include "defs.h"
#include "pma.y.h"

#define	YY_DECL		int _yylex(void)
#define	YY_NO_UNPUT


int	getDecimal		__P((char *));
int	getDQuoteString		__P((char *));
int	SNAMEorKeyword		__P((char *));

%}

letter			[a-zA-Z_]
digit			[0-9]
letter_or_digit		[a-zA-Z_0-9]


%%

#[^\n]*\n			{ return SCOMMENT; }
[ \t\n]+			/* eat up whitespace		*/
{letter}{letter_or_digit}*	return (SNAMEorKeyword(yytext));
{digit}+			return (getDecimal(yytext));

"-"				return (SMINUS);
"."				return (SPERIOD);
"/"				return (SSLASH);
"~"				return (STILDA);

\"				return (getDQuoteString(yytext));
.				return (SOTHER);


%%

void
switchToBuffer(char *Wow)
{
    YY_BUFFER_STATE	yyb;

    yyb = yy_scan_string(Wow);
    yy_switch_to_buffer(yyb);
}


void
reassembleCommandLine(int argc, char *argv[], char *Wow, int size)
{
    YY_BUFFER_STATE      yyb;
    char	*s, *d;

    bzero(Wow, size);

    for (d = Wow; argc; argc--, argv++)
    {
	s = *(argv);
	while (*s)	*d++ = *s++;
	*d++ = ' ';
    }

    yyb = yy_scan_string(Wow);
    yy_switch_to_buffer(yyb);
}


int
getDecimal(char *yytext)
{
    yylval.Int = strtol(yytext, NULL, 0);
    return (SDECIMAL);
}


int
getDQuoteString(char *yytext)
{
    register  int      ch;
    register  char    *p = yytext;

    for (;;)
    {
	switch (ch = input())
	{
	    case 0:	return (SDQUOTE);
	    case '\"':	*p = 0; return (SSTRING);
	    default:	*p++ = ch;
	}
    }
    return (SSTRING);
}


#if	0
void
initYYlex(char *base, int size)
{
}
#endif
