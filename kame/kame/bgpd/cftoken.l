%{
/*
 * Copyright (C) 2000 WIDE Project.
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
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "vmbuf.h"
#include "debug.h"
#include "cfparse.h"
#include "y.tab.h"

static int yyerrorcount = 0;
int lineno = 1;
int yy_first_time = 1;
char *configfilename;

static int blockcount;

#ifdef YIPS_DEBUG
static void cfdebug_print __P((char *, char *, int));
#endif

extern int yylex __P((void));
%}

/* common seciton */
nl		\n
ws		[ \t]+
comment		\#.*
semi		\;
bcl		\{
ecl		\}
string		[a-zA-Z0-9:\._@%-][a-zA-Z0-9:\._@%-]*
digit		[0-9]
integer 	{digit}+
number		{integer}|({digit}*\.{integer})
hexdigit	[0-9A-Fa-f]
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
ifname		[a-zA-Z]+[0-9]+
slash		\/

%s S_CNF
%s S_LOG
%s S_IFACE
%s S_DESCR
%s S_IGNORE

%%
%{
	if (yy_first_time) {
		BEGIN S_CNF;
		yy_first_time = 0;
	}
%}

	/* logging */
<S_CNF>log { DP("begin logging"); BEGIN S_LOG; return(LOG); }
<S_LOG>(no)?bgp {
	YYD_ECHO;
	yylval.num = LOG_BGP;
	if (strncmp("no", yytext, 2))
		return(LOGLEV);
	else
		return(NOLOGLEV);
}
<S_LOG>(no)?rip {
	YYD_ECHO;
	yylval.num = LOG_RIP;
	if (strncmp("no", yytext, 2))
		return(LOGLEV);
	else
		return(NOLOGLEV);
}
<S_LOG>all { YYD_ECHO; yylval.num = LOG_ALL; return(LOGLEV); }
<S_LOG>{semi} { DP("end logging"); BEGIN S_CNF; return(EOS); }
<S_LOG>{string} { yywarn("unknown log type: %s (ignored)", yytext); }

	/* yes-or-no */
[yY][eE][sS] { YYD_ECHO; return(YES); }
[nN][oO] { DP("begin NO"); blockcount = 0; BEGIN S_IGNORE; return(NO); }
<S_IGNORE>{bcl} {DP("BCL"); blockcount++; }
<S_IGNORE>{ecl} {
		DP("ECL");
		if (--blockcount == 0) {
			BEGIN S_CNF;
			return(IGNORE_END);
		}
	}
<S_IGNORE>[^\{\}]* {DP("ignored");}

	/* all */
[aA][lL][lL] { YYD_ECHO; return(ALL); }

	/* dumpfile */
description { DP("begin description"); BEGIN S_DESCR; return(DESCR); }
<S_DESCR>{string} {
		YYD_ECHO;
		yylval.val.l = strlen(yytext);
		yylval.val.v = strdup(yytext);
		BEGIN S_CNF;
		return(DESCSTRING);
	}

	/* autonomoussystem */
<S_CNF>autonomoussystem { YYD_ECHO; return(AUTONOMOUSSYSTEM); }

	/* routerid */
<S_CNF>routerid { YYD_ECHO; return(ROUTERID); }

	/* clusterid */
<S_CNF>clusterid { YYD_ECHO; return(CLUSTERID); }

	/* holdtime */
<S_CNF>holdtime { YYD_ECHO; return(HOLDTIME); }

	/* route reflector */
<S_CNF>IamRouteReflector { YYD_ECHO; return(ROUTEREFLECTOR);} 

	/* bgpsbsize */
<S_CNF>bgpsbsize { YYD_ECHO; return(BGPSBSIZE); }

	/* dumpfile */
<S_CNF>dumpfile { YYD_ECHO; return(DUMPFILE); }

	/* interface */
<S_CNF>interface { YYD_ECHO; BEGIN S_IFACE; return(INTERFACE); }
<S_IFACE>{string} {
	YYD_ECHO;
	yylval.val.l = strlen(yytext);
	yylval.val.v = strdup(yytext);
	BEGIN S_CNF;
	return(IFNAME);
}

	/* rip */
<S_CNF>static { YYD_ECHO; return(STATIC); }
<S_CNF>gateway { YYD_ECHO; return(GATEWAY); }

	/* rip */
<S_CNF>rip { YYD_ECHO; return(RIP); }
<S_CNF>default { YYD_ECHO; return(DEFAULT); }
<S_CNF>originate { YYD_ECHO; return(ORIGINATE); }
<S_CNF>noripin { YYD_ECHO; return(NORIPIN); }
<S_CNF>noripout { YYD_ECHO; return(NORIPOUT); }
<S_CNF>sitelocal { YYD_ECHO; return(SITELOCAL); }
<S_CNF>metricin { YYD_ECHO; return(METRICIN); }

	/* filters */
<S_CNF>filterin { YYD_ECHO; return(FILTERIN); }
<S_CNF>filterout { YYD_ECHO; return(FILTEROUT); }
<S_CNF>restrictin { YYD_ECHO; return(RESTRICTIN); }
<S_CNF>restrictout { YYD_ECHO;  return(RESTRICTOUT); }

	/* bgp */
<S_CNF>bgp {YYD_ECHO; return(BGP); }
<S_CNF>group {YYD_ECHO; return(GROUP); }
<S_CNF>type {YYD_ECHO; return(TYPE); }
<S_CNF>internal {YYD_ECHO; return(INTERNAL); }
<S_CNF>external {YYD_ECHO; return(EXTERNAL); }
<S_CNF>peer {YYD_ECHO; return(PEER); }
<S_CNF>client {YYD_ECHO; return(CLIENT); }
<S_CNF>peeras {YYD_ECHO; return(PEERAS); }
<S_CNF>as {YYD_ECHO; return(AS); }
<S_CNF>synchronization {YYD_ECHO; return(SYNCHRONIZATION); }
<S_CNF>preference {YYD_ECHO; return(PREFERENCE); }
<S_CNF>prepend {YYD_ECHO; return(PREPEND); }
<S_CNF>lcladdr {YYD_ECHO; return(LCLADDR); }
<S_CNF>nexthopself {YYD_ECHO; return(NEXTHOPSELF); }
<S_CNF>no{ws}synchronization {YYD_ECHO; return(NOSYNC); }

	/* export */
<S_CNF>export {YYD_ECHO; return(EXPORT); }

	/* export */
<S_CNF>aggregate {YYD_ECHO; return(AGGREGATE); }
<S_CNF>explicit {YYD_ECHO; return(EXPLICIT); }

	/* routing protocols */
	/* rip and bgp are already defined */
<S_CNF>proto {YYD_ECHO; return(PROTO); }
<S_CNF>direct {YYD_ECHO; return(DIRECT); }
<S_CNF>ibgp {YYD_ECHO; return(IBGP); }

	/* misc */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ DP("comment"); }
{number} 	{ YYD_ECHO; yylval.num = atof(yytext); return(NUMBER); }
{slash} { YYD_ECHO; return(SLASH); }
{semi} { DP("end cnf"); return(EOS); }
{bcl} { DP("begin closure"); return(BCL); }
{ecl} { DP("end closure"); return(ECL); }

	/* last resort */
{string} {
		YYD_ECHO;
		yylval.val.l = strlen(yytext);
		yylval.val.v = strdup(yytext);
		return(STRING);
	}
%%

#ifdef YIPS_DEBUG
static void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
	printf("<%d>%s [%s] (%d)\n", yy_start, w, t, l);
}
#endif 

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
cfparse(strict, conf)
	int strict;
	char *conf;
{
#ifdef YIPS_DEBUG
	debug |= DEBUG_CONF;
#endif 

	configfilename = conf;
	if ((yyin = fopen(configfilename, "r")) == NULL) {
		warn("cfparse: fopen(%s)", configfilename);
		return(-1);
	}

	cf_init();

	if ((yyparse() || yyerrorcount) && strict) {
		if (yyerrorcount) {
			yyerror("fatal parse failure: exiting (%d errors)",
				yyerrorcount);
		} else
			yyerror("fatal parse failure: exiting");
		return(-1);
	}

	YIPSDP(PLOG("parse successed.\n"));

	return(cf_post_config());
}
