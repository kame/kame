/*	$KAME: cftoken.l,v 1.1 2002/04/30 14:49:08 jinmei Exp $	*/

%{
/*
 * Copyright (C) 2002 WIDE Project.
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
#include <sys/types.h>

#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "cfparse.h"
#include "y.tab.h"

char *configfilename;
int lineno = 1;

static int yy_first_time = 1;
static int yyerrorcount = 0;
 
int cfdebug = 1;

static void cfdebug_print __P((char *, char *, int));
%}

/* abbreviations */
nl		\n
ws		[ \t]+
comment		\#.*
semi		\;
string		[a-zA-Z0-9:\._][a-zA-Z0-9:\._]*
digit		[0-9]
integer 	{digit}+
number		{integer}|({digit}*\.{integer})
hexdigit	[0-9A-Fa-f]
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
ifname		[a-zA-Z]+[0-9]+
slash		\/
bcl		\{
ecl		\}

%s S_CNF
%s S_IFACE

%%
%{
	if (yy_first_time) {
		BEGIN S_CNF;
		yy_first_time = 0;
	}
%}
	/* interface configuration */
<S_CNF>interface { DECHO; BEGIN S_IFACE; return(INTERFACE); }
<S_IFACE>{string} {
	DECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return(IFNAME);
}

	/* send */
<S_CNF>send { DECHO; return(SEND); }

	/* DHCP options */
<S_CNF>rapid-commit { DECHO; return(RAPID_COMMIT); }

	/* generic options */
<S_CNF>information-only { DECHO; return(INFO_ONLY); }

	/* misc */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ DP("comment"); }
{number} 	{ DECHO; yylval.num = atoi(yytext); return(NUMBER); }
{slash} { DECHO; return(SLASH); }
{semi} { DP("end sentence"); return(EOS); }
{bcl} { DP("begin closure"); return(BCL); }
{ecl} { DP("end closure"); return(ECL); }

	/* generic string */
{string} {
		DECHO;
		yylval.str = strdup(yytext);
		return(STRING);
	}

%%
static void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
	printf("<%d>%s [%s] (%d)\n", yy_start, w, t, l);
}

static void
yyerror0(char *s, va_list ap)
{
	fprintf(stderr, "%s %d: ", configfilename, lineno);
	vfprintf(stderr, s, ap);
	fprintf(stderr, "\n");
}

void
yyerror(char *s, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	yyerror0(s, ap);
	va_end(ap);
	yyerrorcount++;
}

void
yywarn(char *s, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	yyerror0(s, ap);
	va_end(ap);
}

int
cfparse(conf)
	char *conf;
{
	configfilename = conf;
	if ((yyin = fopen(configfilename, "r")) == NULL) {
		warn("cfparse: fopen(%s)", configfilename);
		return(-1);
	}

	if (yyparse() || yyerrorcount) {
		if (yyerrorcount) {
			yyerror("fatal parse failure: exiting (%d errors)",
				yyerrorcount);
		} else
			yyerror("fatal parse failure: exiting");
		return(-1);
	}

	return(cf_post_config());
}
