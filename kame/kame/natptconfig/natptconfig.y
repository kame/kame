%{
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
//#	$Id: natptconfig.y,v 1.1 1999/08/08 23:31:16 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_soctl.h>

#include "miscvar.h"
#include "showvar.h"

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
    char		*Char;
    struct sockaddr	*Addr;
}


/*  End of line mark. This token is *NOT* use in YACC parser.
    It is convinience for lexecal analyzer.
    And this token *must* comes first.					*/
%token  SEOS

/*  Keyword								*/
%token	SBREAK
%token	SCOMMENT
%token	SDISABLE
%token	SDYNAMIC
%token	SENABLE
%token	SEXTERNAL
%token	SFAITH
%token	SFLUSH
%token	SFROM
%token	SINTERFACE
%token	SINTERNAL
%token	SMAP
%token	SPREFIX
%token	SSHOW
%token	SSTATIC
%token	STO
%token	SXLATE

/*  End of reserved word mark.  And this marker position should not changed. */
%token	SOTHER

/*  ASCII characters, and is called by name.				*/
%token	SDQUOTE
%token	SMINUS
%token	SPERIOD
%token	SSLASH
%token	STILDA

/*  Conventional token							*/
%token	<Int>	SDECIMAL
%token		SNAME
%token		SSTRING
%token		IPV4ADDR
%token		IPV6ADDR

%type	<Int>	in_ex
%type	<Char>	netdevice
%type	<Int>	opt_decimal
%type	<Char>	opt_netdevice
%type	<Int>	opt_type
%type	<Addr>	ipaddr
%type	<Addr>	ipv4addr
%type	<Addr>	ipv6addr


%start	statement

%%

/* Top level definitions						*/
statement
		: comment
		| interface
		| prefix
		| rule
		| show
		| switch
		| break
		;


/* Comment definition							*/

comment		: SCOMMENT
		;


/* Interface definition							*/
interface
		: SINTERFACE netdevice in_ex
		    { ptr_setInterface($2, $3); }
		;

in_ex
		: SINTERNAL
		    { $$ = IF_INTERNAL; }
		| SEXTERNAL
		    { $$ = IF_EXTERNAL; }
		;


/* Set faith/NATPT prefix to the kernel					*/
prefix		: SPREFIX SFAITH ipv6addr
		    { doPtrSetFaithPrefix($3, 0); }
		| SPREFIX SFAITH ipv6addr SSLASH SDECIMAL
		    { doPtrSetFaithPrefix($3, $5); }
		;


/* Translation rule definition						*/
rule
		: SMAP SFROM ipaddr opt_port STO   ipaddr opt_port
		    { doPtrSetRule($3, $6); }
		| SMAP SFROM ipaddr STO SFAITH
		    { doPtrSetFaithRule($3, 32); }
		| SMAP SFROM ipaddr SSLASH SDECIMAL STO SFAITH
		    { doPtrSetFaithRule($3, $5); }
		| SMAP SFLUSH opt_type
		    { doPtrFlushRule($3); }
		;


/* Show something							*/
show
		: SSHOW SINTERFACE opt_netdevice
		    { doPtrShowInterface($3); }
		| SSHOW SSTATIC
		    { doPtrShowRule(PTR_STATIC); }
		| SSHOW SDYNAMIC
		    { doPtrShowRule(PTR_DYNAMIC); }
		| SSHOW SXLATE opt_decimal
		    { doPtrShowXlate($3); }
		;

/* Translator on/off							*/
switch
		: SMAP SENABLE
		    { doPtrEnbTrans(SENABLE); }
		| SMAP SDISABLE
		    { doPtrEnbTrans(SDISABLE); }
		;


/* Stop at breakpoint							*/
break
		: SBREAK
		    { doPtrBreak(); }
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

ipv4addr
		: IPV4ADDR
		    { $$ = getsockaddr(AF_INET, yytext); }
		;

ipv6addr
		: IPV6ADDR
		    { $$ = getsockaddr(AF_INET6, yytext); }
		;

opt_port
		:
		;

opt_type
		:
		    { $$ = 0; }
		| SSTATIC
		    { $$ = PTR_STATIC; }
		| SDYNAMIC
		    { $$ = PTR_DYNAMIC; }
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
