/*	$KAME: cftoken.l,v 1.4 2004/01/21 06:49:57 suz Exp $	*/

%{
/*
 * Copyright (C) 1999 WIDE Project.
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

#include "mfc.h"
#if defined(__FreeBSD__) || defined(__NetBSD__)
#include "cfparse.h"
#else
#include "y.tab.h"
#endif

int lineno = 1;
static int af;

extern int yylex __P((void));
%}

/* common seciton */
nl		\n
ws		[ \t]+
comment		\#.*
semi		\;
string		[a-zA-Z0-9\._][a-zA-Z0-9\._]*
v6addr		[a-fA-F0-9:\.]*:[a-fA-F0-9:\.]*
v4addr		[0-9\.]*
digit		[0-9]
integer 	{digit}+
number		{integer}|({digit}*\.{integer})
hexdigit	[0-9A-Fa-f]
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
ifname		[a-zA-Z]+[0-9]+
slash		\/

%s INTF

%%
<INTF>to {  return(TO); }
<INTF>{string} {
	yylval.string = strdup(yytext);
	switch (af) {
	case AF_INET:
		return(INTERFACE4);
	case AF_INET6:
		return(INTERFACE6);
	default:
		break;
	}
}

	/* misc */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ ; }
from   {  return(FROM); }
to     {  return(TO); }
@      {  BEGIN INTF; return('@'); }
{semi} {  af = AF_UNSPEC; BEGIN INITIAL; return(EOS); }
{v4addr} { af = AF_INET; yylval.string = strdup(yytext); return(V4ADDR); }
{v6addr} { af = AF_INET6; yylval.string = strdup(yytext); return(V6ADDR); }

%%
void
parse_conf(const char *conf)
{
	if ((yyin = fopen(conf, "r")) == NULL)
                errx(1, "fopen(%s)\n", conf);
	yyparse();
}
