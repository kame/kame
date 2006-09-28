/*	$KAME: cftoken.l,v 1.12 2006/09/28 03:05:53 keiichi Exp $	*/

%{
/*
 * Copyright (C) 2005 WIDE Project.
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

#include <string.h>

#ifndef __OpenBSD__
#include "cfparse.h"
#else
#include "y.tab.h"
#endif

void cfdebug_print(char *, char *, int);

int yylex(void);

static int yy_first_time = 1;

#define YY_NO_UNPUT 1

#define DP(str) cfdebug_print(str, yytext, yyleng)
#define D cfdebug_print(NULL, yytext, yyleng)
%}

/* abbreviations */
nl		\n
ws		[ \t]+
bcl		\{
ecl		\}
semi		\;
slash		\/
comment		\#.*
digit		[0-9]
integer		{digit}+
addrstring	[a-zA-Z0-9:\.][a-zA-Z0-9:\.]*
ifname		[a-zA-Z]+[0-9]+
mipifname	mip[0-9]+
filename	[a-zA-Z0-9:\.\-\+]*

%s S_CONFIG
%s S_INTERFACE
%s S_PREFIXTABLE
%s S_STATICTUNNEL
%s S_IPV4DUMMYTUNNEL
%s S_AUTHDATABASE

%%
%{
	if (yy_first_time) {
		BEGIN S_CONFIG;
		yy_first_time = 0;
	}
%}
	/* config parameters */
<S_CONFIG>debug { D; return (DEBUG); }
<S_CONFIG>namelookup { D; return (NAMELOOKUP); }
<S_CONFIG>command-port { D; return (COMMANDPORT); }
<S_CONFIG>home-registration-lifetime { D; return (HOMEREGISTRATIONLIFETIME ); }
<S_CONFIG>preference { D; return (PREFERENCE); }
<S_CONFIG>interface { D; BEGIN S_INTERFACE; return (INTERFACE); }
<S_CONFIG>key-management { D; return (KEYMANAGEMENT); }
<S_CONFIG>ipv4-mnp-support { D; return (IPV4MNPSUPPORT); }
<S_CONFIG>homelink-dad {D; return (DAD); }
<S_CONFIG>pager {D; return (PAGER); }
<S_CONFIG>auth-database {D; BEGIN S_AUTHDATABASE; return (AUTHDATABASE); }
<S_AUTHDATABASE>{filename} {
	D;
	BEGIN S_CONFIG;
	yylval.string = strdup(yytext);
	return (FILENAME);
}	
<S_AUTHDATABASE>{semi} {
	D;
	return (EOS);
}	
<S_INTERFACE>{ifname} {
	D;
	BEGIN S_CONFIG;
	yylval.string = strdup(yytext);
	return (IFNAME);
}
<S_CONFIG>prefixtable { D; BEGIN S_PREFIXTABLE; return (PREFIXTABLE); }
<S_PREFIXTABLE>{bcl} { D; return (BCL); }
<S_PREFIXTABLE>explicit {
	D;
	yylval.string = strdup(yytext);
	return (EXPLICIT);
}
<S_PREFIXTABLE>implicit {
	D;
	yylval.string = strdup(yytext);
	return (IMPLICIT);
}
<S_PREFIXTABLE>{integer} {
	D;
	yylval.number = (int)strtol(yytext, NULL, 10);
	return (INTEGER);
}
<S_PREFIXTABLE>{addrstring} {
	D;
	yylval.string = strdup(yytext);
	return (ADDRSTRING);
}
<S_PREFIXTABLE>{slash} { D; return (SLASH); }
<S_PREFIXTABLE>{ecl} { D; BEGIN S_CONFIG; return (ECL); }
<S_CONFIG>static-tunnel { D; BEGIN S_STATICTUNNEL; return (STATICTUNNEL); }
<S_STATICTUNNEL>{ifname} {
	D;
	yylval.string = strdup(yytext);
	return (IFNAME);
}
<S_STATICTUNNEL>{integer} {
	D;
	yylval.number = (int)strtol(yytext, NULL, 10);
	return (INTEGER);
}
<S_STATICTUNNEL>{addrstring} {
	D;
	yylval.string = strdup(yytext);
	return (ADDRSTRING);
}
<S_STATICTUNNEL>{ecl} { D; BEGIN S_CONFIG; return (ECL); }
<S_CONFIG>ipv4-dummy-tunnel {
	D;
	BEGIN S_IPV4DUMMYTUNNEL;
	return (IPV4DUMMYTUNNEL);
}
<S_IPV4DUMMYTUNNEL>{ifname} {
	D;
	yylval.string = strdup(yytext);
	return (IFNAME);
}
<S_IPV4DUMMYTUNNEL>{addrstring} {
	D;
	yylval.string = strdup(yytext);
	return (ADDRSTRING);
}
<S_IPV4DUMMYTUNNEL>{ecl} { D; BEGIN S_CONFIG; return (ECL); }

	/* misc */
{ws} { ; }
{comment} { ; }
{integer} {
	D;
	yylval.number = (int)strtol(yytext, NULL, 10);
	return (INTEGER);
}
{bcl} { D; return (BCL); }
{ecl} { D; return (ECL); }
{semi} { D; return (EOS); }
{nl} { ; }

%%

void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
#if 0
	if (w) {
		fprintf(stderr, "<%d>%s [%s] (%d)\n", yy_start, w, t, l);
	} else {
		fprintf(stderr, "<%d>[%s] (%d)\n", yy_start, t, l);
	}
#endif
}
