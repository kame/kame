/*	$KAME: cfparse.y,v 1.13 2001/09/06 09:46:05 fujisawa Exp $	*/

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
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>

#include "defs.h"
#include "miscvar.h"
#include "showvar.h"


char		*yykeyword = NULL;
char		*yyfilename;
int		 yylineno;
struct ruletab	 ruletab;

int		 yylex		__P((void));

static void
yyerror(char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	fprintf(stderr, "%s:%d: ", yyfilename, yylineno);
	if (yykeyword)
		fprintf(stderr, "in parsing %s: ", yykeyword);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}
%}

%union
{
	int		 Int;
	u_int		 UInt;
	u_short		*UShrt;
	char		*Char;
	caddr_t		 caddr;
	struct pAddr	*pAddr;
	struct addrinfo	*Ainfo;
}


/* Token definitions */

/*
 * End of line mark.  This token is *NOT* used in YACC grammer.
 * It is convenience for lexical analyzer.
 * And this token must appear first in %token lists.
 */
%token		SEOS


/* Key words, list alphabetically order */
%token		SALL
%token		SANY6
%token		SBREAK
%token		SBIDIR
%token		SDISABLE
%token		SDPORT
%token		SENABLE
%token		SFLUSH
%token		SFROM
%token		SICMP
%token		SLOG
%token		SLONG
%token		SMAP
%token		SMAPPING
%token		SPORT
%token		SPREFIX
%token		SRULES
%token		SSET
%token		SSHOW
%token		SSYSLOG
%token		STCP
%token		STEST
%token		STO
%token		SUDP
%token		SVARIABLES
%token		SXLATE


/* End of reserved word mark.  Must not change this position. */
%token		SOTHER


/* ASCII characters, called by name */
%token		SMINUS
%token		SSLASH
%token		SCOLON
%token		SEQUAL
%token		SQUESTION


/* Conventional token */
%token		SNAME
%token		SSTRING
%token		SDQUOTE
%token	<UInt>	SDECIMAL
%token	<UInt>	SHEXADECIMAL
%token		SIPV4ADDR
%token		SIPV6ADDR


%type	<Int>	dport
%type	<pAddr>	ipv4addrs
%type	<pAddr>	ipv6addrs
%type	<Ainfo>	ipv4addr
%type	<Ainfo>	ipv6addr
%type	<Char>	name
%type	<UInt>	opt_all
%type	<UInt>	opt_decimal
%type	<UInt>	opt_long
%type	<UShrt>	opt_ports
%type	<UInt>	opt_proto
%type	<UInt>	proto
%type	<UInt>	protos

%start	statement

%%

/* Top level definitions */

statement
		: question
		| break
		| prefix
		| rules
		| switch
		| set
		| show
		| log
		| test
		| error
		;


/* question mark */

question
		: SQUESTION
		    { printHelp(SQUESTION, NULL); }
		;


/* stop at breakpoint (for debug) */

break
		: SBREAK
		    { debugBreak(); }
		;


/* set NAT-PT prefix */

prefix
		: SPREFIX SQUESTION
		    { printHelp(SPREFIX, NULL); }
		| SPREFIX ipv6addr
		    { setPrefix($2); }
		;


/* Translation rule */

/*
	[v6->v4] -- outbound
	map from any6		    to 202.249.11.250
	map from any6		    to 202.249.11.250 port 28672 - 32767
	map from 3ffe:501:4819::/48 to 202.249.11.250 port 28672 - 32767
	map from 3ffe:501:4819::/48 to 202.249.11.192/26 port 28672 - 32767

	[v4->v6] -- inbound
	map from 202.249.11.251		    to 3ffe:0501:041c::1
	map from 202.249.11.251 dport 65305 to 3ffe:0501:041c::1 dport 23

	map from any4 to 3ffe:0501:041c::2

	src:202.249.11.33
	dst:203.178.141.196

	[v4->v4] -- outbound
	map from 10.0.0.3	      to 202.249.11.252
	map from 10.0.0.3/8	      to 202.249.11.252 port 28672 - 32767

	[v4->v4] -- inbound
	map from 202.249.11.253		    to 10.0.0.4
	map from 202.249.11.253 dport 63307 to 202.24.11
	map from any4		dport 63305 to 202.249.11.253 dport 23
*/

rules
		: map SQUESTION
		    { printHelp(SMAP, NULL); }

		/* IPv6 -> IPv4 */
		| map SFROM SANY6 STO ipv4addr opt_ports opt_proto
		    {
			ruletab.from   = NULL;
			ruletab.to     = getAddrs(AF_INET, ADDR_SINGLE, $5, 0);
			ruletab.sports = $6;
			ruletab.proto  = $7;
			setRules(NATPT_MAP64, &ruletab);
		    }

		| map SFROM ipv6addrs STO ipv4addrs opt_ports opt_proto
		    {
			ruletab.from   = $3;
			ruletab.to     = $5;
			ruletab.sports = $6;
			ruletab.proto  = $7;
			setRules(NATPT_MAP64, &ruletab);
		    }

		/* IPv4 -> IPv6 */
		| map SFROM ipv4addrs STO ipv6addrs opt_proto
		    {
			ruletab.from  = $3;
			ruletab.to    = $5;
			ruletab.proto = $6;
			setRules(NATPT_MAP46, &ruletab);
		    }

		| map SFROM ipv4addr dport STO ipv6addr dport opt_proto
		    {
			u_short *us = (u_short *)malloc(sizeof(u_short[2]));

			us[0] = $4;
			us[1] = $7;
			ruletab.from = getAddrs(AF_INET,  ADDR_SINGLE, $3, 0);
			ruletab.to   = getAddrs(AF_INET6, ADDR_SINGLE, $6, 0);
			ruletab.dports = us;
			ruletab.proto = $8;
			setRules(NATPT_MAP46, &ruletab);
		    }

		/* IPv4 -> IPv4 (outbound) */
		| map SFROM ipv4addrs STO ipv4addrs opt_ports opt_proto opt_bidir
		    {
			ruletab.from   = $3;
			ruletab.to     = $5;
			ruletab.sports = $6;
			ruletab.proto  =  $7;
			setRules(NATPT_MAP44, &ruletab);
		    }


		/* IPv4 -> IPv4 (inbound) */
		| map SFROM ipv4addr dport STO ipv4addr dport opt_proto

		| map SFLUSH opt_all
		    { flushRules($3); }
		;

map
		: SMAP
		    { bzero(&ruletab, sizeof(struct ruletab)); }
		;


/* Translation of/off */

switch
		: SMAP SENABLE
		    { setOnOff(SENABLE); }
		| SMAP SDISABLE
		    { setOnOff(SDISABLE); }
		;


/* Set variable(s) */

set
		: SSET SQUESTION
		    { printHelp(SSET, NULL); }
		| SSET name SEQUAL SDECIMAL
		    { setValue($2, $4); }
		| SSET name SEQUAL SHEXADECIMAL
		    { setValue($2, $4); }
		;


/* Show rule/variables/... */

show
		: SSHOW SQUESTION
		    { printHelp(SSHOW, NULL); }
		| SSHOW SPREFIX
		    { showPrefix(); }
		| SSHOW SRULES opt_all
		    { showRules($3); }
		| SSHOW SXLATE opt_long opt_decimal
		    { showXlate($3, $4); }
		| SSHOW SVARIABLES
		    { showVariables(); }
		| SSHOW SMAPPING
		    { showMapping(); }
		;


/* Log */

log
		: SLOG SSTRING
		| SLOG SSYSLOG
		;

/* Test log system */
test
		: STEST SQUESTION
		    { printHelp(STEST, NULL); }
		| STEST SLOG
		    { testLog(NULL); }
		| STEST SLOG SNAME
		    { testLog(yytext); }
		| STEST SLOG SSTRING
		    { testLog(yytext); }
		;


/* conventional */

opt_ports
		:
		    { $$ = NULL; }
		| SPORT SDECIMAL SMINUS SDECIMAL
		    {
			u_short	*us = (u_short *)malloc(sizeof(u_short[3]));

			us[0] = PORT_MINUS;
			us[1] = htons((u_short)($2));
			us[2] = htons((u_short)($4));
			$$ = us;
		    }
		| SPORT SDECIMAL SCOLON SDECIMAL
		    {
			u_short	*us = (u_short *)malloc(sizeof(u_short[3]));

			us[0] = PORT_COLON;
			us[1] = htons((u_short)($2));
			us[2] = htons((u_short)($2 + $4));
			$$ = us;
		    }
		;

opt_proto
		:
		    { $$ = 0; }
		| protos
		    { $$ = $1; }
		;

opt_all
		:
		    { $$ = 0; }
		| SALL
		    { $$ = SALL; }
		;

opt_bidir
		:
		| SBIDIR
		;

opt_long
		:
		    { $$ = 0; }
		| SLONG
		    { $$ = 1; }
		;

opt_decimal
		:
		    { $$ = 0; }
		| SDECIMAL
		    { $$ = $1; }
		;

dport
		: SDPORT SDECIMAL
		    { $$ = htons((u_short)($2)); }
		;

protos
		: proto
		    { $$ = $1; }
		| protos SSLASH proto
		    { $$ = $1 | $3; }
		;

proto
		: SICMP
		    { $$ = PROTO_ICMP; }
		| STCP
		    { $$ = PROTO_TCP; }
		| SUDP
		    { $$ = PROTO_UDP; }
		;

ipv4addrs
		: ipv4addr
		    { $$ = getAddrs(AF_INET, ADDR_SINGLE, $1, NULL); }
		| ipv4addr SSLASH SDECIMAL
		    {
			    int	dec = $3;

			    $$ = getAddrs(AF_INET, ADDR_MASK, $1, &dec);
		    }
		| ipv4addr SMINUS ipv4addr
		    { $$ = getAddrs(AF_INET, ADDR_RANGE, $1, $3); }
		;

ipv4addr
		: SIPV4ADDR
		    { $$ = getAddrInfo(AF_INET, yytext); }
		;

ipv6addrs
		: ipv6addr
		    { $$ = getAddrs(AF_INET6, ADDR_SINGLE, $1, NULL); }
		| ipv6addr SSLASH SDECIMAL
		    {
			    int	dec = $3;

			    $$ = getAddrs(AF_INET6, ADDR_MASK, $1, &dec);
		    }
		;

ipv6addr
		: SIPV6ADDR
		    { $$ = getAddrInfo(AF_INET6, yytext); }
		;

name
		: SNAME
		    { $$ = strdup(yytext); }
		;

%%
