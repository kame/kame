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
 *	$Id: cfparse.y,v 1.2 2000/01/07 14:33:33 fujisawa Exp $
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <netdb.h>

#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include "miscvar.h"
#include "showvar.h"
#include "extern.h"

#define	ROUNDUP(x)		roundup(x, sizeof(void *))

struct	msgBox		mBox;

char	*yykeyword = NULL;
char	*yyfilename;
int	 yylineno = 0;

extern	char	*yytext;

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
    u_long		 ULong;	
    int			*Intp;
    char		*Char;
    struct addrCouple	*Acpl;
    struct addrinfo	*Ainfo;
}


/*  End of line mark. This token is *NOT* use in YACC parser.
    It is convinience for lexecal analyzer.
    And this token *must* comes first.					*/
%token		SEOS

/*  Keyword								*/
%token		SBREAK
%token		SDISABLE
%token		SDYNAMIC
%token		SENABLE
%token		SSET
%token		SEXTERNAL
%token		SFAITH
%token		SFLUSH
%token		SFROM
%token		SINBOUND
%token		SINCOMING
%token		SINTERFACE
%token		SINTERNAL
%token		SMAP
%token		SMAPPING
%token		SNATPT
%token		SOUTBOUND
%token		SOUTGOING
%token		SPORT
%token		SPREFIX
%token		SSHOW
%token		SSTATIC
%token		STO
%token		SVARIABLES
%token		SXLATE

/*  End of reserved word mark.	And this marker position should not changed. */
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
%token	<Int>	SDECIMAL
%token	<Int>	SHEXDECIMAL
%token		SNAME
%token		SSTRING
%token		IPV4ADDR
%token		IPV6ADDR

%type	<Int>	in_ex
%type	<Int>	decimal
%type	<Int>	dir
%type	<Int>	hexdecimal
%type	<Char>	name
%type	<Char>	netdevice
%type	<Char>	opt_netdevice
%type	<Acpl>	ipv4addrs
%type	<Acpl>	ipv6addrs
%type	<Ainfo>	ipaddr
%type	<Ainfo>	ipv4addr
%type	<Ainfo>	ipv6addr
%type	<Intp>	opt_port
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
		| error
		;


/* Comment and misc definition						*/

comment		: SCOMMENT
		;


/* ???									*/
question
		: SQUESTION
		    { printHelp(NULL); }
		;

/* Stop at breakpoint							*/
break
		: SBREAK
		    { debugBreak(); }
		;


/* Interface definition							*/
interface
		: SINTERFACE SQUESTION
		    { printInterfaceHelp(); }
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
		    { printPrefixHelp(); }
		| SPREFIX SFAITH ipv6addr
		    { setFaithPrefix($3, 0); }
		| SPREFIX SFAITH ipv6addr SSLASH SDECIMAL
		    { setFaithPrefix($3, $5); }
		| SPREFIX SNATPT ipv6addr
		    { setNatptPrefix($3, 0); }
		| SPREFIX SNATPT ipv6addr SSLASH SDECIMAL
		    { setNatptPrefix($3, $5); }
		;


/* Translation rule definition						*/
rule
		: SMAP SQUESTION
		    { printRuleHelp(); }
		| SMAP SFROM ipv4addrs STO SFAITH
		    { setFaithRule($3); }
		| SMAP SFROM ipv4addrs STO ipaddr opt_port
		    { setRule(0, $3, $5, $6); }
		| SMAP dir SFROM ipv4addrs STO ipaddr opt_port
		    { setRule($2, $4, $6, $7); }
		| SMAP SFROM ipv6addrs STO ipaddr opt_port
		    { setRule(0, $3, $5, $6); }
		| SMAP dir SFROM ipv6addrs STO ipaddr opt_port
		    { setRule($2, $4, $6, $7); }
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
		    { printSetHelp(); }
		| SSET name SEQUAL decimal
		    { setValue($2, $4); }
		| SSET name SEQUAL hexdecimal
		    { setValue($2, $4); }
		;


/* Show something							*/
show
		: SSHOW SQUESTION
		    { printShowHelp(); }
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

ipaddr
		: ipv4addr
		| ipv6addr
		;

ipv4addrs
		: ipv4addr
		    { $$ = getAddrBlock(AF_INET, ADDR_SINGLE, $1, NULL); }
		| ipv4addr SSLASH SDECIMAL
		    { $$ = getAddrBlock(AF_INET, ADDR_MASK, $1, (struct addrinfo *)$3); }
		| ipv4addr SMINUS ipv4addr
		    { $$ = getAddrBlock(AF_INET, ADDR_RANGE, $1, $3); }
		;

ipv6addrs
		: ipv6addr
		    { $$ = getAddrBlock(AF_INET6, ADDR_SINGLE, $1, NULL); }
		| ipv6addr SSLASH SDECIMAL
		    { $$ = getAddrBlock(AF_INET6, ADDR_MASK, $1, (struct addrinfo *)$3); }
		| ipv6addr SMINUS ipv6addr
		    { $$ = getAddrBlock(AF_INET6, ADDR_RANGE, $1, $3); }
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


opt_port
		:
		    { $$ = NULL; }
		| SPORT SDECIMAL
		    {
			static	int	optPort[2];

			optPort[0] = $2;
			optPort[1] = 0;
			$$ = optPort;
		    }
		| SPORT SDECIMAL SCOLON SDECIMAL
		    {
			static	int	optPort[2];

			optPort[0] = $2;
			optPort[1] = $2 + $4;
			$$ = optPort;
		    }
		| SPORT SDECIMAL SMINUS SDECIMAL
		    {
			static	int	optPort[2];

			optPort[0] = $2;
			optPort[1] = $4;
			$$ = optPort;
		    }
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
