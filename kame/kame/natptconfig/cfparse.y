%{
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
 *	$Id: cfparse.y,v 1.5 2000/02/23 12:53:19 fujisawa Exp $
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include "defs.h"
#include "miscvar.h"
#include "showvar.h"

struct	natpt_msgBox	mBox;

char	*yykeyword = NULL;
char	*yyfilename;
int	 yylineno = 0;

extern	char	*yytext;

void		 printHelp	__P((int, char *));
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
    int			 Int;
    u_int		 UInt;
    u_short		*UShrt;	
    char		*Char;
    struct pAddr	*Aport;
    struct addrinfo	*Ainfo;
}


/*  End of line mark.  This token is *NOT* use in YACC parser.
    It is convinience for lexecal analyzer.
    And this token *must* comes first.					*/
%token		SEOS

/*  Keyword								*/
%token		SANY4
%token		SANY6
%token		SBREAK
%token		SDISABLE
%token		SDYNAMIC
%token		SENABLE
%token		SEXTERNAL
%token		SFAITH
%token		SFLUSH
%token		SFROM
%token		SINBOUND
%token		SINCOMING
%token		SINTERFACE
%token		SINTERNAL
%token		SLOG
%token		SMAP
%token		SMAPPING
%token		SNATPT
%token		SOUTBOUND
%token		SOUTGOING
%token		SPORT
%token		SPREFIX
%token		SSET
%token		SSHOW
%token		SSTATIC
%token		STCP
%token		STEST
%token		STO
%token		SUDP
%token		SVARIABLES
%token		SXLATE

/*  End of reserved word mark.	This marker position should not changed. */
%token		SOTHER

/*  special token							*/
%token		SCOMMENT

/*  ASCII characters, and is called by name.				*/
%token		SDQUOTE
%token		SMINUS
%token		SPERIOD
%token		SSLASH
%token		SCOLON
%token		SEQUAL
%token		SQUESTION
%token		STILDA

/*  Conventional token							*/
%token	<UInt>	SDECIMAL
%token	<UInt>	SHEXDECIMAL
%token		SNAME
%token		SSTRING
%token		IPV4ADDR
%token		IPV6ADDR

%type	<Int>	in_ex
%type	<UInt>	decimal
%type	<Int>	dir
%type	<UInt>	hexdecimal
%type	<Char>	name
%type	<Char>	netdevice
%type	<Char>	opt_netdevice
%type	<Aport>	ipaddrport
%type	<Aport>	ipv4addrs
%type	<Aport>	ipv6addrs
%type	<Ainfo>	ipv4addr
%type	<Ainfo>	ipv6addr
%type	<UShrt>	port
%type	<Int>	opt_proto
%type	<Int>	opt_type
%type	<Int>	opt_decimal


%start	statement

%%

/* Top level definitions						*/

statement
		: comment
		| question
		| break
		| interface
		| prefix
		| rule
		| switch
		| set
		| show
		| test
		| error
		;


/* Comment and misc definition						*/

comment		: SCOMMENT
		;


/* ???									*/

question
		: SQUESTION
		    { printHelp(SQUESTION, NULL); }
		;

/* Stop at breakpoint							*/

break
		: SBREAK
		    { debugBreak(); }
		;


/* Interface definition							*/

interface
		: SINTERFACE SQUESTION
		    { printHelp(SINTERFACE, NULL); }
		| SINTERFACE netdevice in_ex
		    { setInterface($2, $3); }
		;

in_ex
		: SINTERNAL
		    { $$ = IF_INTERNAL; }
		| SEXTERNAL
		    { $$ = IF_EXTERNAL; }
		;


/* Set faith/NATPT prefix to the kernel					*/

prefix
		: SPREFIX SQUESTION
		    { printHelp(SPREFIX, NULL); }
		| SPREFIX SFAITH ipv6addr
		    { setPrefix(PREFIX_FAITH, $3, 0); }
		| SPREFIX SFAITH ipv6addr SSLASH SDECIMAL
		    { setPrefix(PREFIX_FAITH, $3, $5); }
		| SPREFIX SNATPT ipv6addr
		    { setPrefix(PREFIX_NATPT, $3, 0); }
		| SPREFIX SNATPT ipv6addr SSLASH SDECIMAL
		    { setPrefix(PREFIX_NATPT, $3, $5); }
		;


/* Translation rule definition						*/

rule
		: SMAP SQUESTION
		    { printHelp(SMAP, NULL); }
		| SMAP dir opt_proto SFROM ipaddrport STO ipaddrport
		    { setRule($2, $3, $5, $7); }
		| SMAP dir opt_proto SFROM SANY4 port STO ipaddrport
		    { setFromAnyRule($2, $3, SANY4, $6, $8); }
		| SMAP dir opt_proto SFROM SANY6 port STO ipaddrport
		    { setFromAnyRule($2, $3, SANY6, $6, $8); }
		| SMAP SFROM SANY6 STO SFAITH
		    { setFaithRule(NULL); }
		| SMAP SFROM ipaddrport STO SFAITH
		    { setFaithRule($3); }
		| SMAP SFLUSH opt_type
		    { flushRule($3); }
		;

dir
		: SINBOUND
		    { $$ = NATPT_INBOUND; }
		| SINCOMING
		    { $$ = NATPT_INBOUND; }
		| SOUTBOUND
		    { $$ = NATPT_OUTBOUND; }
		| SOUTGOING
		    { $$ = NATPT_OUTBOUND; }
		;


/* Translator on/off							*/

switch
		: SMAP SENABLE
		    { enableTranslate(SENABLE); }
		| SMAP SDISABLE
		    { enableTranslate(SDISABLE); }
		;


/* Set something							*/

set
		: SSET SQUESTION
		    { printHelp(SSET, NULL); }
		| SSET name SEQUAL decimal
		    { setValue($2, $4); }
		| SSET name SEQUAL hexdecimal
		    { setValue($2, $4); }
		;


/* Show something							*/

show
		: SSHOW SQUESTION
		    { printHelp(SSHOW, NULL); }
		| SSHOW SINTERFACE opt_netdevice
		    { showInterface($3); }
		| SSHOW SPREFIX
		    { showPrefix(); }
		| SSHOW SSTATIC
		    { showRule(NATPT_STATIC); }
		| SSHOW SDYNAMIC
		    { showRule(NATPT_DYNAMIC); }
		| SSHOW SXLATE opt_decimal
		    { showXlate($3); }
		| SSHOW SVARIABLES
		    { showVariables(); }
		| SSHOW SMAPPING
		    { showMapping(); }
		;


/* Test something							*/

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


/* ...									*/

opt_netdevice
		:
		    { $$ = NULL; }
		| netdevice
		    { $$ = $1; }
		;

netdevice
		: SSTRING
		    {
			strcpy(mBox.m_ifName, yytext);
			$$ = mBox.m_ifName;
		    }
		| SNAME
		    {
			strcpy(mBox.m_ifName, yytext);
			$$ = mBox.m_ifName;
		    }
		;

ipaddrport
		: ipv4addrs
		    { $$ = $1; }
		| ipv4addrs port
		    { $$ = setAddrPort($1, $2); }
		| ipv6addrs
		    { $$ = $1; }
		| ipv6addrs port
		    { $$ = setAddrPort($1, $2); }
		;

ipv4addrs
		: ipv4addr
		    { $$ = getAddrPort(AF_INET, ADDR_SINGLE, $1, NULL); }
		| ipv4addr SSLASH decimal
		    {
			int	dec = $3;

			$$ = getAddrPort(AF_INET, ADDR_MASK, $1, (void *)&dec);
		    }
		| ipv4addr SMINUS ipv4addr
		    { $$ = getAddrPort(AF_INET, ADDR_RANGE, $1, $3); }
		;

ipv6addrs
		: ipv6addr
		    { $$ = getAddrPort(AF_INET6, ADDR_SINGLE, $1, NULL); }
		| ipv6addr SSLASH decimal
		    {
			int	dec = $3;

			$$ = getAddrPort(AF_INET6, ADDR_MASK, $1, (void *)&dec);
		    }
		;

ipv4addr
		: IPV4ADDR
		    { $$ = getAddrInfo(AF_INET, yytext); }
		;

ipv6addr
		: IPV6ADDR
		    { $$ = getAddrInfo(AF_INET6, yytext); }
		;

name
		: SNAME
		    {
			$$ = malloc(ROUNDUP(strlen(yytext)));
			strcpy($$, yytext);
		    }
		;

decimal
		: SDECIMAL
		;

hexdecimal
		: SHEXDECIMAL
		;


port
		: SPORT SDECIMAL
		    {
			u_short	*optPort;

			debugProbe("<port> ::= SPORT SDECIMAL\n");
			optPort = (u_short *)malloc(sizeof(u_short[2]));
			optPort[0] = htons((u_short)($2));
			optPort[1] = 0;
			$$ = optPort;
		    }
		| SPORT SDECIMAL SCOLON SDECIMAL
		    {
			u_short	*optPort;

			debugProbe("<port> ::= SPORT SDECIMAL SCOLON SDECIMAL\n");
			optPort = (u_short *)malloc(sizeof(u_short[2]));
			optPort[0] = htons((u_short)($2));
			optPort[1] = htons((u_short)($2 + $4));
			$$ = optPort;
		    }
		| SPORT SDECIMAL SMINUS SDECIMAL
		    {
			u_short	*optPort;

			debugProbe("<port> ::= SPORT SDECIMAL SMINUS SDECIMAL\n");
			optPort = (u_short *)malloc(sizeof(u_short[2]));
			optPort[0] = htons((u_short)($2));
			optPort[1] = htons((u_short)($4));
			$$ = optPort;
		    }
		;

/* optional ...								*/

opt_proto
		:
		    { $$ = 0; }
		| STCP
		    { $$ = IPPROTO_TCP; }
		| SUDP
		    { $$ = IPPROTO_UDP; }
		;

opt_type
		:
		    { $$ = 0; }
		| SSTATIC
		    { $$ = NATPT_STATIC; }
		| SDYNAMIC
		    { $$ = NATPT_DYNAMIC; }
		;

opt_decimal
		:
		    { $$ = 0; }
		| SDECIMAL
		    { $$ = $1; }
		;


%%

/*
 * Local Variables:
 * mode: fundamental
 * End:
 */
