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
//#	$SuMiRe: pma.y,v 1.10 1998/09/17 01:15:02 shin Exp $
//#	$Id: pma.y,v 1.1.1.1 1999/08/08 23:31:10 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#if defined(KAME)
#include "pm_insns.h"
#include "pm_defs.h"
#include "pm_ioctl.h"
#include "pm_list.h"
#else
#include <netpm/pm_insns.h>
#include <netpm/pm_defs.h>
#include <netpm/pm_ioctl.h>
#include <netpm/pm_list.h>
#endif

#include "defs.h"
#include "miscvar.h"
#include "showvar.h"
#include "extern.h"


/*
//##
//#---------------------------------------------------------------------------
//#
//#---------------------------------------------------------------------------
*/

int		rv;
int		maybeStatic;

struct _msgBox	mBox;
addrBlock	apt;
immEntry	ie;

extern	char	*yytext;
extern	int	errno;

extern	int	yylex		__P((void));
extern	int	sendMsg		__P((struct _msgBox *, int, int));

char *yykeyword = NULL;
char *yyfilename;
int yylineno = 0;

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
    unsigned int	 UInt;
    char        *Char;
    Cell	*CELL;
    void	*Void;
}


/*  End of line mark. This token is *NOT* use in YACC parser.
    It is convinience for lexecal analyzer.
    And this token *must* comes first.					*/
%token  SEOS

/*  Keyword								*/
%token	SADDRFIRST
%token	SALIAS
%token	SANY
%token	SATT
%token	SBIND
%token	SCELLUSED
%token	SCHFLAGS
%token	SDISABLE
%token	SDYNAMIC
%token	SENABLE
%token	SEXTERNAL
%token	SFILRULE
%token	SFILTER
%token	SFLUSH
%token	SFORCE
%token	SFROM
%token	SFULL
%token	SGET
%token	SGLOBAL
%token	SICMP
%token	SINTERFACE
%token	SINTERNAL
%token	SIN_SERVICE
%token	SKMEMBUCKETS
%token	SKMEMSTATS
%token	SKMEMUSAGE
%token	SLINKSTAT
%token	SNAT
%token	SNATGLOBAL
%token	SNO
%token	SOUT_OF_SERVICE
%token	SPORT
%token	SPORTFIRST
%token	SREAL
%token	SREMOVE
%token	SROUTE
%token	SSELFADDR
%token	SSHOW
%token	SSIDE
%token	SSTAT
%token	SSTATIC
%token	SSTATUS
%token	STCP
%token	STO
%token	STSD
%token	SUDP
%token	SVIA
%token	SVIRTUAL
%token	SXLATE
%token	SCOMMENT

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

%type	<Int>	addrflag
%type	<CELL>	internal_natrange
%type	<CELL>	external_natrange
%type	<Int>	opt_nattype
%type	<Char>	netaddr
%type	<Char>	netdevice
%type	<Int>	nattype
%type	<Char>	opt_netaddr
%type	<Char>	opt_netdevice
%type	<Int>	opt_full
%type	<CELL>	address_range
%type	<Void>	range_term
%type	<UInt>	ipaddress
%type	<Int>	netmask
%type	<Int>	policy
%type	<Int>	port
%type	<CELL>	rulenums
%type	<Int>	rulenum
%type	<UInt>	r_ip
%type	<UInt>	v_ip
%type	<Int>	opt_protocol
%type	<Int>	protocol
%type	<Int>	opt_decimal


%start	statement

%%

/*  Top level definitions						*/
statement
		: interface
		| global
		| filter
		| nat
		| tsd
		| att
		| route
		| selfaddr
		| show
		| comment
		;


/*  Interface definition						*/
interface
		: SINTERFACE
		    { bzero(&mBox, sizeof(struct _msgBox)); }
		  opt_netid netdevice in_ex
		    {
			if ((sendMsg(&mBox, PMIOCCONF, FALSE) < 0)
			    && (errno == EALREADY))
			{
			    fprintf(stderr, "interface `%s\' already configured.\n",
					    mBox.m_ifName);
			    exit(errno);
			}
		    }
		;

in_ex
		: SINTERNAL
		    { mBox.flags = IF_INTERNAL; }
		| SEXTERNAL
		    { mBox.flags = IF_EXTERNAL; }
		;


/*  Global address definition						*/
global
		: set_global
		| remove_global
		| flush_global
		;

set_global
		: SGLOBAL netdevice address_range
		    { doPmaSetGlobal(mBox.m_ifName, $3, 0); }
		| SGLOBAL netdevice address_range SFORCE
		    { doPmaSetGlobal(mBox.m_ifName, $3, 1); }
		;

remove_global
		: SGLOBAL SREMOVE netdevice address_range
		    { doPmaRemoveGlobal(mBox.m_ifName, $4); }
		;

flush_global
		: SGLOBAL SFLUSH opt_netdevice
		    {
			bzero(&mBox, sizeof(struct _msgBox));
			if ($3 != NULL)
			    strcpy(mBox.m_aux, $3);
			sendMsg(&mBox, PMIOCFLGLOBAL, TRUE);	
		    }
		;

address_range
		: range_term
		    {
			$$ = LST_cons($1, NIL); }
		| address_range range_term
		    {
			$$ = LST_hookup($1, $2); }
		;

range_term
		: ipaddress
		    {
			struct  in_addr	*inaddr;

			inaddr = (struct in_addr *)malloc(sizeof(struct in_addr)*2);
			inaddr[0].s_addr = $1;
			inaddr[1].s_addr = 0;
			$$ = inaddr;
		    }
		| ipaddress SSLASH netmask
		    {
			struct  in_addr	*inaddr;

			inaddr = (struct in_addr *)malloc(sizeof(struct in_addr)*2);
			inaddr[0].s_addr = $1;
			inaddr[1].s_addr = $1 | ~$3;
			$$ = inaddr;
		    }
		| ipaddress SMINUS ipaddress
		    {
			struct  in_addr	*inaddr;

			inaddr = (struct in_addr *)malloc(sizeof(struct in_addr)*2);
			inaddr[0].s_addr = $1;
			inaddr[1].s_addr = $3;
			$$ = inaddr;
		    }
		;


/*  IP packet filter							*/
filter
		: flush_filter
		| toggle_filter
		;

flush_filter
		: SFILTER SFLUSH opt_netdevice
		    {
			sendMsg(&mBox, PMIOCFLFRULE, TRUE);
		    }
		;

toggle_filter
		: SFILTER SENABLE
		    {
			sendMsg(&mBox, PMIOCENBLFIL, TRUE);
		    }
		| SFILTER SDISABLE
		    {
			sendMsg(&mBox, PMIOCDSBLFIL, TRUE);
		    }
		;


/*  Network Address Translation						*/
nat
		: natrule
		| remove_nat
		| flush_nat
		| toggle_nat
		;

natrule
		: SNAT
		    {
			maybeStatic = TRUE;
			bzero(&apt, sizeof(apt));
			bzero(&mBox, sizeof(mBox));
		    }
		  opt_netdevice opt_nattype internal_natrange
		  STO
		    {   bzero(&apt, sizeof(apt)); }
		  external_natrange policy
		    {
			doPmaSetNatRule(&mBox, $4, $5, $8, $9);
		    }
		;

internal_natrange
		: netaddr
		    { $$ = LST_cons($1, NIL); }
		| internal_natrange netaddr
		    { $$ = LST_hookup($1, $2); }
		;

external_natrange
		: netaddr
		    { $$ = LST_cons($1, NIL); }
		| internal_natrange netaddr
		    { $$ = LST_hookup($1, $2); }
		;

remove_nat
		: SNAT SREMOVE netdevice nattype rulenums
		    { doPmaRemoveNatRule($3, $4, $5); }
		;

flush_nat
		: SNAT SFLUSH opt_netdevice
		    {
			struct _msgBox	mBox;

			bzero(&mBox, sizeof(struct _msgBox));
			sendMsg(&mBox, PMIOCFLNAT, TRUE);
		    }
		;

toggle_nat
		: SNAT SENABLE
		  {
		    sendMsg(&mBox, PMIOCENBLNAT, TRUE);
		  }
		| SNAT SDISABLE
		  {
		    sendMsg(&mBox, PMIOCDSBLNAT, TRUE);
		  }
		;

opt_nattype
		:
		    { $$ = 0; }
		| nattype
		    { $$ = $1; }
		;

nattype
		: SSTATIC
		    { $$ = NAT_STATIC; }
		| SDYNAMIC
		    { $$ = NAT_DYNAMIC; }
		;

netaddr
		: ipaddr_range
		    {
			char	*p;

			p = malloc(sizeof(apt));
			bcopy(&apt, p, sizeof(addrBlock));
			$$ = p;
		    }
		| ipaddr_range ports
		    {
			char	*p;

			p = malloc(sizeof(apt));
			bcopy(&apt, p, sizeof(addrBlock));
			$$ = p;
		    }
		;

ipaddr_range
		: SANY
		    {
			apt.type = IN_ADDR_ANY;
			apt.addr[0].s_addr = 0;
			apt.addr[0].s_addr = 0;
		    }
		| ipaddress
		    {
			apt.type = IN_ADDR_SINGLE;
			apt.addr[0].s_addr = $1;
			apt.addr[1].s_addr = 0xffffffff;
		    }
		| ipaddress SSLASH netmask
		    {
			apt.type = IN_ADDR_MASK;
			apt.addr[0].s_addr = $1;
			apt.addr[1].s_addr = $3;
		    }
		| ipaddress SMINUS ipaddress
		    {
			apt.type = IN_ADDR_RANGE;
			apt.addr[0].s_addr = $1;
			apt.addr[1].s_addr = $3;
		    }
		;


ports
		: SPORT port
		    {
			apt.port[0] = $2;
			apt.port[1] = 0;
		    }
		| SPORT port SMINUS port
		    {
			apt.port[0] = $2;
			apt.port[1] = $4;
		    }
		;


policy
		:		{ $$ = PAT_ADDRONLY; }
		| SPORTFIRST	{ $$ = PAT_PORTFIRST; }
		| SADDRFIRST	{ $$ = PAT_ADDRFIRST; }
		;


/*  TCP Session Distributor						*/
tsd
		: virtual
		| real
		| bind
		| in_service
		| out_of_service
		;

virtual
		: STSD opt_netdevice SVIRTUAL v_ip
		    {
			mBox.flags   = IMM_VIRTUAL;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($4);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		| STSD opt_netdevice SNO SVIRTUAL v_ip
		    {
			mBox.flags   = IMM_VIRTUAL;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($5);
			sendMsg(&mBox, PMIOCREMIMM, TRUE);
		    }
		;

real
		: STSD opt_netdevice SREAL r_ip
		    {
			mBox.flags   = IMM_REAL;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.real[0].s_addr = htonl($4);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		| STSD opt_netdevice SNO SREAL r_ip
		    {
			mBox.flags   = IMM_REAL;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.real[0].s_addr = htonl($5);
			sendMsg(&mBox, PMIOCREMIMM, TRUE);
		    }
		;

bind
		: STSD opt_netdevice SBIND v_ip r_ip
		    {
			mBox.flags   = IMM_BIND;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($4);
			ie.real[0].s_addr = htonl($5);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		| STSD opt_netdevice SNO SBIND v_ip r_ip
		    {
			mBox.flags   = IMM_BIND;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($5);
			ie.real[0].s_addr = htonl($6);
			sendMsg(&mBox, PMIOCREMIMM, TRUE);
		    }
		;

in_service
		: STSD SIN_SERVICE SVIRTUAL v_ip
		    {
			mBox.flags   = IMM_VIRTUAL | IMM_IN_SERVICE;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($4);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		| STSD SIN_SERVICE SREAL r_ip
		    {
			mBox.flags   = IMM_REAL | IMM_IN_SERVICE;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($4);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		;

out_of_service
		: STSD SOUT_OF_SERVICE SVIRTUAL v_ip
		    {
			mBox.flags   = IMM_VIRTUAL | IMM_OUT_OF_SERVICE;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($4);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		| STSD SOUT_OF_SERVICE SREAL r_ip
		    {
			mBox.flags   = IMM_REAL | IMM_OUT_OF_SERVICE;
			mBox.nums    = 2;
			mBox.freight = (char *)&ie;

			ie.virtual.s_addr = htonl($4);
			sendMsg(&mBox, PMIOCSETIMM, TRUE);
		    }
		;

v_ip
		: ipaddress
		;

r_ip
		: ipaddress
		;


/*  Active Translation Slot						*/
att
		: att_flush
		;

att_flush
		: SATT SFLUSH
		;


/*  Route source address/port						*/
route
		: config_route
		| remove_route
		| flush_route
		| toggle_route
		;

config_route
		: SROUTE opt_protocol
		    { bzero(&apt, sizeof(apt)); }
		  SFROM opt_netaddr
		    { bzero(&apt, sizeof(apt)); }
		  STO opt_netaddr  SVIA ipaddress
		    { doPmaSetRoute($2, (addrBlock *)$5, (addrBlock *)$8, $10); }
		;

opt_protocol
		:
		    { $$ = IPPROTO_IP; }
		| protocol
		    { $$ = $1;}
		;

protocol
		: SDECIMAL		{ $$ = $1; }
		| SICMP			{ $$ = IPPROTO_ICMP; }
		| SUDP			{ $$ = IPPROTO_UDP; }
		| STCP			{ $$ = IPPROTO_TCP; }
		;

opt_netaddr
		:
		    { $$ = NULL; }
		| netaddr
		    { $$ = $1; }
		;

remove_route
		: SROUTE SREMOVE rulenums
		    { doPmaRemoveRoute($3); }
		;

flush_route
		: SROUTE SFLUSH
		    {
			bzero(&mBox, sizeof(mBox));
			sendMsg(&mBox, PMIOCFLROUTE, TRUE);
		    }
		;

toggle_route
		: SROUTE SENABLE
		    {
			sendMsg(&mBox, PMIOCENROUTE, TRUE);
		    }
		| SROUTE SDISABLE
		    {
			sendMsg(&mBox, PMIOCDSROUTE, TRUE);
		    }
		;


/*  ...									*/
selfaddr
		: SSELFADDR SGET
		    { doPmaGetSelfaddr(); }
		| SSELFADDR SCHFLAGS ipaddress addrflag
		    { doPmaSetSelfaddrFlags($3, $4); }
		;

addrflag
		: SNATGLOBAL		{ $$ =  NAT_GLOBAL; }
		| STILDA SNATGLOBAL	{ $$ = ~NAT_GLOBAL; }
		| SALIAS		{ $$ =  MAYBE_ALIAS; }
		| STILDA SALIAS		{ $$ = ~MAYBE_ALIAS; }
		;


/*  Show something							*/
show
		: SSHOW SINTERFACE opt_netdevice
		    { doPmaShowInterface($3); }
		| SSHOW SSIDE
		    { doPmaShowSide(); }
		| SSHOW SGLOBAL opt_netdevice
		    { doPmaShowGlobal($3); }
		| SSHOW SFILRULE
		    { doPmaShowFilrule(NULL); }
		| SSHOW SSTATIC opt_netdevice
		    { doPmaShowNatRule($3, NAT_STATIC,   0); }
		| SSHOW SDYNAMIC opt_netdevice opt_full
		    { doPmaShowNatRule($3, NAT_DYNAMIC, $4); }
		| SSHOW SSTAT
		    { doPmaShowStat(); }
		| SSHOW SREAL
		    { doPmaShowReal(); }
		| SSHOW SVIRTUAL
		    { doPmaShowVirtual(); }
		| SSHOW SBIND
		    { doPmaShowBind(); }
		| SSHOW STSD SSTAT
		    { doPmaImmShowStat(); }
		| SSHOW STSD SLINKSTAT
		    { doPmaImmShowLinkStat(); }
		| SSHOW SROUTE
		    { doPmaShowRoute(); }
		| SSHOW SROUTE SSTATUS
		    { doPmaShowRouteStatus(); }
		| SSHOW SSELFADDR
		    { doPmaShowSelfaddr(); }
		| SSHOW SXLATE opt_decimal
		    { doPmaXlate($3); }
		| SSHOW SCELLUSED
		    { doPmaShowCells(); }
		| SSHOW SKMEMBUCKETS
		    { doPmaShowKmem(SKMEMBUCKETS); }
		| SSHOW SKMEMSTATS
		    { doPmaShowKmem(SKMEMSTATS); }
		| SSHOW SKMEMUSAGE
		    { doPmaShowKmem(SKMEMUSAGE); }
		;

comment		: SCOMMENT	/*ignore*/
		;

/*  ...									*/
opt_netid
		:
		| netid
		;

netid
		: SDECIMAL
		;

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

opt_full
		:
		    { $$ = 0; }
		| SFULL
		    { $$ = SFULL; }
		;

ipaddress
		: SDECIMAL SPERIOD SDECIMAL SPERIOD SDECIMAL SPERIOD SDECIMAL
		    { $$ = ((((($1 << 8) + $3) << 8) + $5) << 8) +$7; }
		;

netmask
		: SDECIMAL
		    {
			int	iter, mask;

			mask = 0;
			if ($1 != 0)
			{
			    mask = 0x80000000;
			    for (iter = 1; iter < $1; iter++)
				mask >>= 1;
			}

			$$ = mask;
		    }
		;

port
		: SDECIMAL
		;

opt_decimal
		:
		    { $$ = 0; }
		| SDECIMAL
		    { $$ = $1; }
		;


/*	Specify nat/route rule						*/
rulenums
		: rulenum
		    {
			char	*p;

			p = calloc(sizeof(Cell), 1);
			((short *)p)[0] = $1;
			$$ = (Cell *)p;
		    }
		| rulenum SMINUS rulenum
		    {
			char	*p;

			if ($1 > $3)
			{
			    CEerror("%d - %d: Invalid range.\n", $1, $3);
			    $$ = NULL;
			}
			else
			{
			    p = calloc(sizeof(Cell), 1);
			    if ($1 == $3)
				((short *)p)[0] = $1;
			    else
			    {
				((short *)p)[0] = $1;
				((short *)p)[1] = $3;
			    }
			    $$ = (Cell *)p;
			}
		    }
		| rulenums rulenum
		    {
			char	*p;

			p = calloc(sizeof(Cell), 1);
			((short *)p)[0] = $2;
			if ($1 != NULL)
			    CDR(LST_last($1)) = (Cell *)p;
			$$ = $1;
		    }
		;

rulenum
		: SDECIMAL
		;


%%

void
init_yyparse()
{
    bzero(&mBox, sizeof(struct _msgBox));
}


/*
 * Local Variables:
 * mode: fundamental
 * End:
 */
