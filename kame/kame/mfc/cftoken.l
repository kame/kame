/*	$KAME: cftoken.l,v 1.1 2001/07/11 08:36:59 suz Exp $	*/

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
#include "y.tab.h"

int lineno = 1;

extern int yylex __P((void));
%}

/* common seciton */
nl		\n
ws		[ \t]+
comment		\#.*
semi		\;
string		[a-zA-Z0-9\._][a-zA-Z0-9\._]*
v6addr		[a-fA-F0-9:\.][a-fA-F0-9:\.]*
digit		[0-9]
integer 	{digit}+
number		{integer}|({digit}*\.{integer})
hexdigit	[0-9A-Fa-f]
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
ifname		[a-zA-Z]+[0-9]+
slash		\/

%%
	/* misc */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ ; }
{semi} {  return(EOS); }
from   {  return(FROM); }
to     {  return(TO); }
@      {  return('@'); }

{v6addr} {
		yylval.string = strdup(yytext);
		return(V6ADDR);
	}
	/* last resort */
{string} {
		yylval.string = strdup(yytext);
		return(STRING);
	}
%%
void
parse_conf(const char *conf)
{
	if ((yyin = fopen(conf, "r")) == NULL)
                errx(1, "fopen(%s)\n", conf);
	yyparse();
}
