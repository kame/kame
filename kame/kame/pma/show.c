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
//#	$SuMiRe: show.c,v 1.5 1998/09/17 01:15:06 shin Exp $
//#	$Id: show.c,v 1.1.1.1 1999/08/08 23:31:11 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <kvm.h>

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/socket.h>

#define	TCPSTATES	1
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp_fsm.h>
#include <arpa/inet.h>

#if defined(KAME)
#include "pm_defs.h"
#include "pm_ioctl.h"
#include "pm_insns.h"
#else
#include <netpm/pm_defs.h>
#include <netpm/pm_ioctl.h>
#include <netpm/pm_insns.h>
#endif

#include "defs.h"
#include "pma.y.h"
#include "miscvar.h"
#include "showvar.h"
#include "extern.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(__bsdi__)
#define	EXECFILE		"/bsd"
#else
#define	EXECFILE		"/kernel"
#endif

#define	SHOWSIDE	(0x01)
#define	SHOWALL		(SHOWSIDE)
#define	IFL_BEF		(0x01)
#define	IFL_AFT		(0x02)
#define	IFL_IN		(0x10)
#define	IFL_OUT		(0x20)


kvm_t	*kd;

static	struct	nlist	nl[] =
{
    { "_selfAddr" },
    { "_attEntryList" },
    { "_pmBoxList" },
    { "_immVirtualPool" },
    { "_immRealPool" },
    { "_routeConf" },
    { "_doRoute" },
    { "__cell_used" },
    { "__cell_free" },
    { "_bucket" },		/* struct kmembuckets bucket[MINBUCKET + 16] */
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
    { "_kmemstatistics" },
#else
    { "_kmemstats" },		/* struct kmemstats kmemstats[M_LAST]	     */
#endif
    { "_kmemusage" },		/* struct kmemusage *kmemusage		     */
    { NULL }
};


extern	int	_debug;		/*  defined in main.c			*/


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	void	_showPmBox		__P((pmBox *, int));
static	void	_showGlobals		__P((int));
static	void	_showGAddr		__P((gAddr *));
#if defined(PMC_FILTER)
static	void	_showFilRule		__P((char *, int, Cell *));
#endif
static	void	_showNatStatic		__P((pmBox *, int, natBox *));
static	void	_showNatDynamic		__P((pmBox *, int, natBox *, int));
static	void	_showNatRuleEnt		__P((char *, int, natRuleEnt *));
static	void	_showNatRuleEntFull	__P((char *, natRuleEnt *));
static	void	_showAddrBlock		__P((addrBlock *));
static	void	_showBindedGlobal	__P((int));
static	void	_showFwdRoute		__P((fwdRoute *));
static	void	_showSelfaddr		__P((SelfAddr *));
static	void	_showXlate		__P((int));
static	void	_showKmemBuckets	__P((void));
static	void	_showKmemStats		__P((void));
static	void	_showKmemMusage		__P((void));
#if defined(PMC_FILTER)
static	void	disasmBPF		__P((Progs *));
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
doPmaShowInterface(char *ifName)
{
    Cell    cons;
    int	    pos;
    int     rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No interface set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    pmBox	pmb;

	    readKvm((caddr_t)&pmb, sizeof(pmb), (int)cons.car);
	    if ((ifName == NULL) || (strcmp(pmb.ifName, ifName) == SAME))
		_showPmBox(&pmb, SHOWALL);
	}
	pos = (int)cons.cdr;
    }

    closeKvm();
}


void
doPmaShowSide()
{
    Cell    cons;
    int	    pos;
    int     rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No interface set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    pmBox	pmb;

	    readKvm((caddr_t)&pmb, sizeof(pmb), (int)cons.car);
	    _showPmBox(&pmb, SHOWSIDE);
	}
	pos = (int)cons.cdr;
    }

    closeKvm();
}


void
doPmaShowGlobal(char *ifName)
{
    Cell	cons;
    int		pos;
    int		rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No globals set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    pmBox	pmb;

	    readKvm((caddr_t)&pmb, sizeof(pmb), (int)cons.car);
	    if ((ifName == NULL) || (strcmp(pmb.ifName, ifName) == SAME))
	    {
		natBox		nBox;

		if (pmb.natBox == NULL)
		{
		    StandardOut("No globals set.\n");
		    return ;
		}

		readKvm((caddr_t)&nBox, sizeof(natBox), (int)pmb.natBox);
		if ((nBox.global.used == NULL) && (nBox.global.free == NULL))
		{
		    StandardOut("No globals set.\n");
		    return ;
		}
		
		StandardOut("%s: ", pmb.ifName);
		_showGlobals((int)nBox.global.used);
		_showGlobals((int)nBox.global.free);
	    }
	}
	pos = (int)cons.cdr;
    }
    
    closeKvm();
}


#if !defined(PMC_FILTER)
void
doPmaShowFilrule(char *ifName)
{
    StandardOut("sorry, 'show filrule' is not supported.\n");
}
#else
void
doPmaShowFilrule(char *ifName)
{
    Cell	 cons;
    int		 pos;
    int		 rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No filter rule set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    pmBox	pmb;

	    readKvm((caddr_t)&pmb, sizeof(pmb), (int)cons.car);
	    if ((ifName == NULL) || (strcmp(pmb.ifName, ifName) == SAME))
	    {
		filBox		fBox;

		if (pmb.filBox == NULL)
		{
		    StandardOut("%s: No filter rule set.\n", pmb.ifName);
		    return;
		}
		readKvm((caddr_t)&fBox, sizeof(filBox), (int)pmb.filBox);
		_showFilRule(pmb.ifName, IFL_IN  | IFL_BEF, fBox.i.filRuleBfr);
		_showFilRule(pmb.ifName, IFL_IN  | IFL_AFT, fBox.i.filRuleAft);
		_showFilRule(pmb.ifName, IFL_OUT | IFL_BEF, fBox.o.filRuleBfr);
		_showFilRule(pmb.ifName, IFL_OUT | IFL_AFT, fBox.o.filRuleAft);
	    }
	}
	pos = (int)cons.cdr;
    }

    closeKvm();
}
#endif


void
doPmaShowNatRule(char *ifName, int type, int full)
{
    Cell	 cons;
    int		 pos;
    int		 rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No nat rule set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    pmBox	pmb;

	    readKvm((caddr_t)&pmb, sizeof(pmb), (int)cons.car);
	    if ((ifName == NULL) || (strcmp(pmb.ifName, ifName) == SAME))
	    {
		natBox		nBox;

		if (pmb.natBox == NULL)
		{
		    StandardOut("No nat rule set.\n");
		    return;
		}
		readKvm((caddr_t)&nBox, sizeof(natBox), (int)pmb.natBox);
		if (type == NAT_STATIC)
		    _showNatStatic (&pmb, type, &nBox);
		else
		    _showNatDynamic(&pmb, type, &nBox, full);
	    }
	}
	pos = (int)cons.cdr;
    }

    closeKvm();
}


void
doPmaShowStat()
{
    Cell	 cons;
    int		 pos;
    int		 rv;
    char	 Wow[32];

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_natStatic")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No static entry.\n");
	return ;
    }
    
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    addrBlock	laddr, faddr;
	    natRuleEnt	nap;

	    readKvm((caddr_t)&nap, sizeof(nap), (int)cons.car);

	    if (nap.local)
	    {
		Cell	cons;

		readKvm((caddr_t)&cons, sizeof(Cell), (int)nap.local);
		if (cons.car)
		    readKvm((caddr_t)&laddr, sizeof(addrBlock), (int)cons.car);
	    }

	    if (nap.foreign)
	    {
		Cell	cons;

		readKvm((caddr_t)&cons, sizeof(Cell), (int)nap.foreign);
		if (cons.car)
		    readKvm((caddr_t)&faddr, sizeof(addrBlock), (int)cons.car);
	    }
	    
	    sprintf(Wow, "%s/%d",
		    inet_ntoa(laddr.addr[0]),
		    _masktobits(ntohl(laddr.addr[1].s_addr)));
	    StandardOut("%-19s", Wow);
	    if (laddr.port[0] != 0)
		StandardOut("port %d-%d ", laddr.port[0], laddr.port[1]);
	    StandardOut(" -> ");

	    sprintf(Wow, "%s/%d",
		    inet_ntoa(faddr.addr[0]),
		    _masktobits(ntohl(faddr.addr[1].s_addr)));
	    StandardOut("%-19s", Wow);
	    if (faddr.port[0] != 0)
		StandardOut("port %d-%d", faddr.port[0], faddr.port[1]);

	    StandardOut("%10d in ", nap.inbound);
	    StandardOut("%10d out", nap.outbound);

	    StandardOut("\n");

	}
	pos = (int)cons.cdr;
    }

    closeKvm();
}


void
doPmaShowRoute()
{
    Cell	cons;
    int		pos;
    int		num = 0;
    int		rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_routeConf")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No route entry.\n");
	return ;
    }
    
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    fwdRoute	fwd;

	    StandardOut("%3d route ", num++);
	    readKvm((caddr_t)&fwd, sizeof(fwdRoute), (int)cons.car);
	    _showFwdRoute(&fwd);
	}
	pos = (int)cons.cdr;
    }
    
    closeKvm();
}


void
doPmaShowRouteStatus()
{
    int		val;
    int		rv;

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&val, sizeof(val), "_doRoute")) <= 0)
	return ;

    if (val == 0)
	StandardOut("Routing disable.\n");
    else
	StandardOut("Routing enable.\n");
}


void
doPmaShowSelfaddr()
{
    Cell	cons;
    int		pos;
    int		rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_selfAddr")) <= 0)
	return ;

    if (pos == 0)
    {
	StandardOut("No selfaddr entry.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell),  pos);
	if (cons.car)
	{
	    SelfAddr	self;

	    StandardOut("  ");
	    readKvm((caddr_t)&self, sizeof(self), (int)cons.car);
	    _showSelfaddr(&self);
	}
	pos = (int)cons.cdr;
    }

    closeKvm();
}


void
doPmaXlate(int interval)
{
    int		 pos;
    int		 rv;

    if (interval <= 0)
    {
	if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_attEntryList")) <= 0)
	    return ;

	if (pos == 0)
	{
	    StandardOut("No active xlate\n");
	    return ;
	}

	_showXlate(pos);
    }
    else
    {
	for (;;sleep(interval))
	{
	    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_attEntryList")) <= 0)
		return ;

	    if (pos == 0)
	    {
		StandardOut("No active xlate\n");
		continue ;
	    }

	    _showXlate(pos);
	}
    }
    
    closeKvm();
}


void
doPmaShowCells()
{
    int		used, free;
    int		rv;
    
    if ((rv = readNL((caddr_t)&used, sizeof(used), "__cell_used")) <= 0)
	return ;
    
    if ((rv = readNL((caddr_t)&free, sizeof(free), "__cell_free")) <= 0)
	return ;

    StandardOut("_cell_used: %d, _cell_free: %d\n", used, free);
    
    closeKvm();
}


void
doPmaShowKmem(int type)
{
    switch (type)
    {
      case SKMEMBUCKETS:	_showKmemBuckets();	break;
      case SKMEMSTATS:		_showKmemStats();	break;
      case SKMEMUSAGE:		_showKmemMusage();	break;
    }
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	void
_showPmBox(pmBox *pmb, int flags)
{
    StandardOut("%s: ", pmb->ifName);
    if (flags & SHOWSIDE)
	StandardOut("    %s", pmb->side == InSide ? "inside" : "outside");
#if	0
    _readRule(&pmb, IpInput, 1, FALSE);
    _readRule(&pmb, IpInput, 2, FALSE);
    _readRule(&pmb, IpInput, 3, FALSE);
    _readRule(&pmb, IpOutput, 1, FALSE);
    _readRule(&pmb, IpOutput, 2, FALSE);
    _readRule(&pmb, IpOutput, 3, FALSE);
#endif
    StandardOut("\n");
}


static	void
_showGlobals(int pos)
{
    Cell	cons;
    gAddr	gaddr;

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    readKvm((caddr_t)&gaddr, sizeof(gAddr), (int)cons.car);
	    _showGAddr(&gaddr);
	}
	pos = (int)cons.cdr;
    }
}


static	void
_showGAddr(gAddr *gaddr)
{
    StandardOut("\t%s [%c%c] (%d)\n", inet_ntoa(gaddr->addr),
		(gaddr->flags & ADDR_STATIC)  ? 'S' : '-',
		(gaddr->flags & ADDR_DYNAMIC) ? 'D' : '-',
		(gaddr->linkc));
}


#if defined(PMC_FILTER)
static	void
_showFilRule(char *ifName, int flags, Cell *rule)
{
    int		num;
    int		pos;
    Cell	cons, guru;

    if (rule == NULL)
	return;

    StandardOut("%s: ", ifName);
    StandardOut("%s: ", (flags & IFL_IN)  ? "input" : "output");
    StandardOut("%s",  (flags & IFL_BEF) ? "before" : "after");
    StandardOut("\n");

    num = 0;
    pos = (int)rule;
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    readKvm((caddr_t)&guru, sizeof(Cell), (int)cons.car);
	    if (guru.car)
	    {
		struct pm_program	 pgm;
		struct pm_insn		*insns;

		StandardOut("%3d\n", num++);

		readKvm((caddr_t)&pgm, sizeof(struct pm_program), (int)guru.car);
		insns = (struct pm_insn *)malloc(pgm.pm_len << 3);
		readKvm((caddr_t)insns, pgm.pm_len << 3, (int)pgm.pm_insns);
		pgm.pm_insns = insns;
		disasmBPF(&pgm);
	    }
	    StandardOut("\n");
	}
	pos = (int)cons.cdr;
    }
}
#endif


static	void
_showNatStatic(pmBox *pmb, int type, natBox *nBox)
{
    Cell	cons;
    int		pos;
    int		num = 0;

    if (nBox->natStatic == NULL)
	return ;

    StandardOut("%s: \n", pmb->ifName);

    pos = (int)nBox->natStatic;
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), (int)pos);
	if (cons.car)
	{
	    natRuleEnt	nap;

	    StandardOut("%3d: ", num++);
	    readKvm((caddr_t)&nap, sizeof(natRuleEnt), (int)cons.car);
	    _showNatRuleEnt(pmb->ifName, type, &nap);
	}
	pos = (int)cons.cdr;
    }
}


static	void
_showNatDynamic(pmBox *pmb, int type, natBox *nBox, int full)
{
    Cell	cons;
    int		pos;
    int		num = 0;

    if (nBox->natDynamic == NULL)
	return ;

    StandardOut("%s: \n", pmb->ifName);

    pos = (int)nBox->natDynamic;
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), (int)pos);
	if (cons.car)
	{
	    natRuleEnt	nap;

	    readKvm((caddr_t)&nap, sizeof(natRuleEnt), (int)cons.car);
	    if (full == 0)
		StandardOut("%3d: ", num++),
		_showNatRuleEnt(pmb->ifName, type, &nap);
	    else
		_showNatRuleEntFull(pmb->ifName, &nap);
	}
	pos = (int)cons.cdr;
    }
}


static	void
_showNatRuleEnt(char *ifName, int type, natRuleEnt *nap)
{
    if (nap->local)
    {
	int		pos;
	Cell		cons;
	addrBlock	laddr;

	pos = (int)nap->local;
	while (pos)
	{
	    readKvm((caddr_t)&cons, sizeof(Cell), pos);
	    if (cons.car)
	    {
		readKvm((caddr_t)&laddr, sizeof(addrBlock), (int)cons.car);
		_showAddrBlock(&laddr);
	    }
	    pos = (int)cons.cdr;
	}
    }

    StandardOut("to ");

    if (nap->foreign)
    {
	int		cnt;
	int		pos;
	Cell		cons;
	addrBlock	faddr;

	for (cnt = nap->gAddrLen; cnt; cnt--)
	{
	    pos = (int)nap->foreign;
	    readKvm((caddr_t)&cons, sizeof(Cell), pos);
	    if (cons.car)
	    {
		readKvm((caddr_t)&faddr, sizeof(addrBlock), (int)cons.car);
		_showAddrBlock(&faddr);
	    }
	    pos = (int)cons.cdr;
	}
    }

    if (type == NAT_DYNAMIC)
	switch (nap->policy)
	{
	  case PAT_ADDRONLY:	StandardOut("addronly ");	break;
	  case PAT_PORTFIRST:	StandardOut("portfirst ");	break;
	  case PAT_ADDRFIRST:	StandardOut("addrfirst ");	break;
	  default:		StandardOut("Policy Unknown ");	break;
	}

    StandardOut("\n");
}


static	void
_showNatRuleEntFull(char *ifName, natRuleEnt *nap)
{
    if (nap->local)
    {
	int	pos;
	Cell	cons;
	addrBlock	laddr;

	pos = (int)nap->local;
	while (pos)
	{
	    readKvm((caddr_t)&cons, sizeof(Cell), pos);
	    if (cons.car)
	    {
		readKvm((caddr_t)&laddr, sizeof(addrBlock), (int)cons.car);
		_showAddrBlock(&laddr);
	    }
	    pos = (int)cons.cdr;
	}
    }

    StandardOut("to\n");

    if (nap->foreign)
    {
	int	cnt;
	int	pos;
	Cell	cons;
	addrBlock	faddr;

	for (cnt = nap->gAddrLen; cnt; cnt--)
	{
	    pos = (int)nap->foreign;
	    readKvm((caddr_t)&cons, sizeof(Cell), pos);
	    if (cons.car)
	    {
		readKvm((caddr_t)&faddr, sizeof(addrBlock), (int)cons.car);
		_showAddrBlock(&faddr);

		switch (nap->policy)
		{
		  case PAT_ADDRONLY:	StandardOut("addronly ");	break;
		  case PAT_PORTFIRST:	StandardOut("portfirst ");	break;
		  case PAT_ADDRFIRST:	StandardOut("addrfirst ");	break;
		  default:		StandardOut("Policy Unknown ");	break;
		}

		StandardOut("\n");

		if (faddr.gList)
		    _showBindedGlobal((int)faddr.gList);

	    }
	    pos = (int)cons.cdr;
	}
    }

    StandardOut("\n");
}


static	void
_showAddrBlock(addrBlock *ab)
{
    char	Wow[64];

    switch (ab->type)
    {
      case IN_ADDR_SINGLE:
      case IN_ADDR_MASK:
	sprintf(Wow, "%s/%d",
		inet_ntoa(ab->addr[0]),
		_masktobits(ntohl(ab->addr[1].s_addr)));
	StandardOut("%-19s", Wow);
	break;

      case IN_ADDR_RANGE:
	{
	    char	Dum[32], Dee[32];

	    strcpy(Dum, inet_ntoa(ab->addr[0]));
	    strcpy(Dee, inet_ntoa(ab->addr[1]));
	    StandardOut("%s - %s ", Dum, Dee);
	}
	break;
    }
    if (ab->port[0] != 0)
	StandardOut("port %d - %d ", ab->port[0], ab->port[1]);
}


static	void
_showBindedGlobal(int pos)
{
    Cell	cons;
    gAddr	gac;

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    readKvm((caddr_t)&gac, sizeof(gAddr), (int)cons.car);
	    StandardOut("\t%s [%c%c]", inet_ntoa(gac.addr),
			(gac.flags & ADDR_STATIC)  ? 'S' : '-',
			(gac.flags & ADDR_DYNAMIC) ? 'D' : '-');
	    StandardOut(" (%d)", gac.linkc);
	    StandardOut("\n");
	}
	pos = (int)cons.cdr;
    }
    StandardOut("\n");
}


static	void
_showFwdRoute(fwdRoute *fwd)
{
    switch (fwd->ip_p)
    {
      case IPPROTO_IP:						break;
      case IPPROTO_ICMP:	StandardOut("icmp ");		break;
      case IPPROTO_TCP:		StandardOut("tcp ");		break;
      case IPPROTO_UDP:		StandardOut("udp ");		break;
      default:			StandardOut("unknown ");	break;
    }

    StandardOut("from ");
    switch (fwd->type[0])
    {
      case IN_ADDR_ANY:
	StandardOut("any");
	break;

      case IN_ADDR_SINGLE:
	StandardOut("%s", inet_ntoa(fwd->ip_src[0]));
	break;

      case IN_ADDR_MASK:
	StandardOut("%s/%d",
		    inet_ntoa(fwd->ip_src[0]),
		    _masktobits(ntohl(fwd->ip_src[1].s_addr)));
	if (isDebug(D_SHOWROUTE))
	    StandardOut("/%s", inet_ntoa(fwd->ip_src[2]));
	break;

      case IN_ADDR_RANGE:
	StandardOut("%s-%s",
		    inet_ntoa(fwd->ip_src[0]),
		    inet_ntoa(fwd->ip_src[1]));
	break;

      default:
	StandardOut("Unknown");
    }
    StandardOut(" ");

    if (fwd->th_sport[0] != 0)
    {
	StandardOut("port %d", ntohs(fwd->th_sport[0]));
	if (fwd->th_sport[1] != 0)
	    StandardOut("-%d", ntohs(fwd->th_sport[1]));
	StandardOut(" ");
    }

    StandardOut("to ");

    switch (fwd->type[1])
    {
      case IN_ADDR_ANY:
	StandardOut("any");
	break;

      case IN_ADDR_SINGLE:
	StandardOut("%s", inet_ntoa(fwd->ip_dst[0]));
	break;

      case IN_ADDR_MASK:
	StandardOut("%s/%d",
		    inet_ntoa(fwd->ip_dst[0]),
		    _masktobits(ntohl(fwd->ip_dst[1].s_addr)));
	break;

      case IN_ADDR_RANGE:
	StandardOut("%s-%s",
		    inet_ntoa(fwd->ip_dst[0]),
		    inet_ntoa(fwd->ip_dst[1]));
	break;

      default:
	StandardOut("Unknown");
    }
    StandardOut(" ");

    if (fwd->th_dport[0] != 0)
    {
	StandardOut("port %d", ntohs(fwd->th_dport[0]));
	if (fwd->th_dport[1] != 0)
	    StandardOut("-%d", ntohs(fwd->th_dport[1]));
	StandardOut(" ");
    }

    StandardOut("via ");
    StandardOut("%s", inet_ntoa(fwd->ip_via));

    StandardOut("\n");
}


static	void
_showSelfaddr(SelfAddr *self)
{
    int		firsttime = 0;

    StandardOut(" inet %s", inet_ntoa(self->ifaddr));
    StandardOut(" broadcast %s", inet_ntoa(self->braddr));
    StandardOut(" netmask %s", inet_ntoa(self->netmask));
    if (self->addrflags)
    {
	StandardOut(" (");
	if (self->addrflags & NAT_GLOBAL)
	    StandardOut("%snatglobal", (firsttime++ ? ",": ""));
	if (self->addrflags & MAYBE_ALIAS)
	    StandardOut("%salias", (firsttime++ ? ",": ""));
	StandardOut(")");
    }
    StandardOut("\n");
}


#define	_writeXlateHeader()						\
		{							\
		    StandardOut("%-6s",  "Proto");			\
		    StandardOut("%-21s", "Local Address");		\
		    StandardOut("%-22s", "Foreign Address");		\
		    StandardOut("%-21s", "Remote Address");		\
		    StandardOut("%6s",  "Ipkts");			\
		    StandardOut("%6s",  "Opkts");			\
		    StandardOut(" ");					\
									\
		    StandardOut("%-8s",  "  Idle");			\
		    StandardOut("%-8s",  " (state)");			\
		    StandardOut("\n");					\
		}


static	void
_showXlate(int pos)
{
    Cell	 cons;
    int		rv;
    char	 Wow[BUFSIZ];

    _writeXlateHeader();

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    aTT		 	 att;
	    struct  timeval	 tp;
	    struct  timezone	 tzp;
	    int			 idle;
	    char		*p;

	    readKvm((caddr_t)&att, sizeof(aTT), (int)cons.car);

	    switch (att.ip_p)
	    {
	      case IPPROTO_ICMP: p = "icmp"; break;
	      case IPPROTO_UDP:  p = "udp" ; break;
	      case IPPROTO_TCP:  p = "tcp" ; break;
	      default:		 p = "unk" ; break;
	    }
	    StandardOut("%-6s", p);

	    sprintf(Wow, "%s.%d", inet_ntoa(att.ip_laddr), ntohs(att.th_lport));
	    StandardOut("%-21s", Wow);
	    sprintf(Wow, "%s.%d", inet_ntoa(att.ip_faddr), ntohs(att.th_fport));
	    StandardOut("%-22s", Wow);
	    sprintf(Wow, "%s.%d", inet_ntoa(att.ip_raddr), ntohs(att.th_rport));
	    StandardOut("%-21s", Wow);

	    StandardOut("%6d", att.inbound);
	    StandardOut("%6d", att.outbound);
	    StandardOut(" ");

	    rv = gettimeofday(&tp, &tzp);
	    idle = tp.tv_sec - att.tstamp;
	    StandardOut("%02d:%02d:%02d", idle / 3600, (idle % 3600)/60, idle % 60);

	    switch (att.ip_p)
	    {
	      case IPPROTO_ICMP:
		{
		    StandardOut(" %5d/%-5d",
				att.suit.ih_idseq.icd_id,
				att.suit.ih_idseq.icd_seq);
		}
		break;

	      case IPPROTO_TCP:
		{
		    TCPstate	ts;

		    readKvm((caddr_t)&ts, sizeof(TCPstate), (int)att.suit.tcp);

		    if ((ts._state >= 0) && (ts._state < TCP_NSTATES))
			StandardOut(" %s", tcpstates[ts._state]);
		    else
			StandardOut(" %d", ts._state);
		}
		break;
	    }

	    StandardOut("\n");
	}
	pos = (int)cons.cdr;
    }
}


static	void
_showKmemBuckets()
{
    struct kmembuckets bucket[MINBUCKET + 16];
    int		idx;
    int		rv;

    if ((rv = readNL((caddr_t)&bucket, sizeof(bucket), "_bucket")) <= 0)
	return ;

    StandardOut("\t\t");
    StandardOut( "%7s", "next");
    StandardOut( "%8s", "calls");
    StandardOut( "%8s", "total");
    StandardOut("%10s", "totalfree");
    StandardOut( "%9s", "elmpercl");
    StandardOut( "%8s", "highwat");
    StandardOut("%11s", "couldfree");
    StandardOut("\n");
    for (idx = 0; idx < MINBUCKET + 16; idx++)
    {
	struct kmembuckets	*kbp = &bucket[idx];

	StandardOut("buckets[%2d]:", idx);
	StandardOut(" 0x%08x", kbp->kb_next);
	StandardOut( "%8d", kbp->kb_calls);
	StandardOut( "%8d", kbp->kb_total);
	StandardOut("%10d", kbp->kb_totalfree);
	StandardOut( "%9d", kbp->kb_elmpercl);
	StandardOut( "%8d", kbp->kb_highwat);
	StandardOut(" 0x%08x", kbp->kb_next);
	StandardOut("\n");
    }
    
    closeKvm();
}

#if !defined(__FreeBSD__) || __FreeBSD__ < 3
static	void
_showKmemStats()
{
    struct kmemstats  kmemstats[M_LAST];
    char	     *memname[] = INITKMEMNAMES;
    int		idx;
    int		rv;
    
    if ((rv = readNL((caddr_t)&kmemstats, sizeof(kmemstats), "_kmemstats")) <= 0)
	return ;
    
    StandardOut("\t");
    StandardOut("%12s", "inuse");
    StandardOut( "%8s", "calls");
    StandardOut( "%8s", "memuse");
    StandardOut( "%8s", "limblks");
    StandardOut( "%8s", "mapblks");
    StandardOut( "%8s", "maxused");
    StandardOut( "%9s", "limit");
    StandardOut( "%8s", "size");
    StandardOut( "%6s", "spare");
    StandardOut("\n");
    for (idx = 0; idx < M_LAST; idx++)
    {
	struct kmemstats *ksp = &kmemstats[idx];

	StandardOut("kmemstats[%2d]:", idx);
	StandardOut( "%6d", ksp->ks_inuse);
	StandardOut( "%8d", ksp->ks_calls);
	StandardOut( "%8d", ksp->ks_memuse);
	StandardOut( "%8d", ksp->ks_limblocks);
	StandardOut( "%8d", ksp->ks_mapblocks);
	StandardOut( "%8d", ksp->ks_maxused);
	StandardOut( "%9d", ksp->ks_limit);
	StandardOut( "%8d", ksp->ks_size);
	StandardOut( "%6d", ksp->ks_spare);
	StandardOut( " %s", memname[idx]);
	StandardOut("\n");
    }
}
#else
static	void
_showKmemStats()
{
    struct malloc_type *kmemstatistics, *ksp, *ksp_nxt, tbuf;
    char short_desc[10];
    int		idx;
    int		rv;

    short_desc[9] = '0';

    if ((rv = readNL((caddr_t)&kmemstatistics, sizeof(struct malloc_type *),
		     "_kmemstatistics")) <= 0)
	return ;
    if ((rv = kvm_read(kd, (int)kmemstatistics, &tbuf,
		       sizeof(struct malloc_type))) <= 0)
	return ;
    ksp = &tbuf;
    
    StandardOut("\t");
    StandardOut("%12s", "inuse");
    StandardOut( "%8s", "calls");
    StandardOut( "%8s", "memuse");
    StandardOut( "%8s", "limblks");
    StandardOut( "%8s", "mapblks");
    StandardOut( "%8s", "maxused");
    StandardOut( "%9s", "limit");
    StandardOut( "%8s", "size");
    StandardOut( "%8s", "magic");
    StandardOut("\n");

    while (1) {
	int idx = 0;

	if ((rv = kvm_read(kd, (int)ksp->ks_shortdesc, short_desc,
			   sizeof(short_desc) - 1)) <= 0) {
	    perror("read failure on kvm_read");
	    break;
	}

	StandardOut("<%10s>:", short_desc);
	StandardOut( "%7d", ksp->ks_inuse);
	StandardOut( "%8d", ksp->ks_calls);
	StandardOut( "%8d", ksp->ks_memuse);
	StandardOut( "%8d", ksp->ks_limblocks);
	StandardOut( "%8d", ksp->ks_mapblocks);
	StandardOut( "%8d", ksp->ks_maxused);
	StandardOut( "%9d", ksp->ks_limit);
	StandardOut( "%8d", ksp->ks_size);
	StandardOut( "%10d", ksp->ks_magic);
	StandardOut("\n");

	ksp_nxt = ksp->ks_next;
	if (ksp_nxt == NULL)
	    break;

	if ((rv = kvm_read(kd, (int)ksp_nxt, &tbuf,
			   sizeof(struct malloc_type))) <= 0) {
	    perror("read failure on kvm_read");
	    break;
	}
	ksp = &tbuf;
    }

}
#endif

static	void
_showKmemMusage()
{
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

struct _pmBox *
readPmBox()
{
    int		pos;
    int		rv;

    static	Cell	_cons_;
    static	pmBox	_pmb_;

    if (_cons_.car != NULL)
	pos = (int)_cons_.cdr;
    else
    {
	if ((rv = openKvm()) <= 0)
	    return (NULL);

	if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	    return (NULL);

	if (pos == 0)
	    return (NULL);
    }

    readKvm((caddr_t)&_cons_, sizeof(Cell), pos);
    if (_cons_.car)
    {
	readKvm((caddr_t)&_pmb_, sizeof(pmBox), (int)_cons_.car);
	return (&_pmb_);
    }

    closeKvm();

    _cons_.car = NULL;
    _cons_.cdr = NULL;

    return (NULL);
}


#if defined(PMC_FILTER)
#include "../pmc/disasm.c"
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif


int
readNL(caddr_t buf, int nbytes, char *n_name)
{
    int		     rv;
    struct  nlist   *nlp;

    if ((kd == NULL) && ((rv = openKvm()) < 0))
	return (0);

    for (nlp = nl; nlp->n_name; nlp++)
    {
	if (strncmp(nlp->n_name, n_name, strlen(n_name)) == SAME)
	    return (readKvm(buf, nbytes, nlp->n_value));
    }

    return (0);
}


int
openKvm()
{
    int		rv;
    char	Wow[128];

#if defined(__bsdi__)
    bcopy(EXECFILE, Wow, strlen(EXECFILE));
#endif	/*  __bsdi__  */

#if defined(__FreeBSD__)
    {
	int	mib[2];
	size_t	len = sizeof(Wow);

	mib[0] = CTL_KERN;
	mib[1] = KERN_BOOTFILE;
	if (sysctl(mib, 2, Wow,  &len, NULL, 0) == ERROR)
	    strcpy(Wow, EXECFILE);
    }
#endif	/*  __FreeBSD__  */

    if ((kd = kvm_open(Wow, NULL, NULL, O_RDONLY, "kvm_open")) <= (kvm_t *)0)
    {
	perror("Open failure on kvm_open");
	return (-1);
    }

    if ((rv = kvm_nlist(kd, nl)) < 0)
    {
	perror("Read failure on kvm_nlist");
	return (-1);
    }

    return ((int)kd);
}


int
readKvm(caddr_t buf, int nbytes, int pos)
{
    int	rv;

    if (nbytes <= 0)
	return (-1);

    if (kd <= (kvm_t *)0)
	return (-1);

    if ((rv = kvm_read(kd, pos, buf, nbytes)) <= 0)
    {
	perror("Read failure on KMEM");
	return (-1);
    }
    return (rv);
}


void
closeKvm()
{
    kvm_close(kd);
}
