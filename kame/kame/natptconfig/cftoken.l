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
 *
 *	$Id: cftoken.l,v 1.3 2000/02/18 11:39:55 fujisawa Exp $
 */

%{
#include <string.h>
#include <sys/types.h>
#include "natptconfig.y.h"

#define	YY_DECL		int _yylex(void)
#define	YY_NO_UNPUT

int	getDecimal		__P((char *));
int	getHexdicimal		__P((char *));
int	getDQuoteString		__P((char *));
int	SNAMEorKeyword		__P((char *));

%}

letter			[a-zA-Z_]
digit			[0-9]
hexdigit		[0-9A-Fa-f]
letter_or_digit		[0-9a-zA-Z_]
dot			"."
colon			":"
ipv4addr		{digit}{1,3}({dot}{digit}{1,3}){0,3}
ipv6addr		{hexdigit}{0,4}({colon}{hexdigit}{0,4}){2,7}

%%

#[^\n]*\n			{ return SCOMMENT; }
^[ \t]*\n			{ return SCOMMENT; }
[ \t\n]+			/* eat up whitespace		*/
{letter}{letter_or_digit}*	return (SNAMEorKeyword(yytext));
{digit}+			return (getDecimal(yytext));
0x{hexdigit}+			return (getHexdicimal(yytext));
{ipv4addr}			return (IPV4ADDR);
{ipv6addr}			return (IPV6ADDR);

"-"				return (SMINUS);
"."				return (SPERIOD);
"/"				return (SSLASH);
":"				return (SCOLON);
"="				return (SEQUAL);
"?"				return (SQUESTION);
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
reassembleCommandLine(int argc, char *argv[], char *Wow)
{
    YY_BUFFER_STATE	 yyb;
    char	*spc;
    char	*s, *d;

    for (d = Wow; argc; argc--, argv++)
    {
	s = *(argv);
	spc = strchr(s, ' ');
	if (spc == NULL)
	    spc = strchr(s, '\t');

	if (spc)	*d++ = '"';
	while (*s)	*d++ = *s++;
	if (spc)	*d++ = '"';

	*d++ = ' ';
    }

    yyb = yy_scan_string(Wow);
    yy_switch_to_buffer(yyb);
}


int
getDecimal(char *yytext)
{
    yylval.UInt = strtol(yytext, NULL, 0);
    return (SDECIMAL);
}


int
getHexdicimal(char *yytext)
{
    yylval.UInt = strtoul(yytext, NULL, 0);
    return (SHEXDECIMAL);
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
