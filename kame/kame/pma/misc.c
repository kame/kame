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
//#	$SuMiRe: misc.c,v 1.11 1998/09/17 01:14:55 shin Exp $
//#	$Id: misc.c,v 1.1 1999/08/08 23:31:08 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <nlist.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <kvm.h>

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <arpa/inet.h>

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

#if defined(__bsdi__)
#include <ifaddrs.h>
#endif

#include "defs.h"
#include "pma.y.h"
#include "miscvar.h"
#include "showvar.h"
#include "extern.h"

#if defined(orphan)
#include "../pmmc/pmfil.h"
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int	_fd;
u_long	mtobits[33];

#if (_BSDI_VERSION < 199701)
int		 nip;
#endif
struct	ifaddrs	*ifaddrs;

#define	INADDR		struct in_addr

static	void	 _setGlobal	__P((struct ifaddrs *, Cell *, int));
static	void	 _setNatStatic	__P((struct _msgBox *, Cell *, Cell *));
static	void	 _setNatDynamic	__P((struct _msgBox *, Cell *, Cell *, int));
static	void	*_unfoldAddr	__P((char *, INADDR *, INADDR *));
static	void	*__unfoldAddr	__P((struct ifaddrs *, INADDR *, INADDR *));
static	int	 isNatGlobal	__P((u_long));
static	struct in_addr	*_unfoldRange	__P((struct ifaddrs *, Cell *, int *));
static	int	*arrangeRuleNums __P((Cell *, int, int *));
static	int	 compar		__P((const void *, const void *));

static	void	 _dumpIoctl		__P((int, caddr_t));
static	void	 _dumpSETNAT		__P((caddr_t));
static	void	 _dumpSETNATdynamic	__P((natRuleEntry *));
static	void	 _dumpAddrBlock		__P((addrBlock *));

int		sendMsg			__P((struct _msgBox *, int, int));


#if defined(__FreeBSD__)

#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

#define	ROUNDUP(x)	roundup(x, sizeof(void *))

	int	 getifaddrs	__P((struct ifaddrs **));

struct	ifaddrs
{
    struct  ifaddrs	*ifa_next;
    char		*ifa_name;
    u_int		 ifa_flags;
    struct  sockaddr	*ifa_addr;
    struct  sockaddr	*ifa_netmask;
    struct  sockaddr	*ifa_dstaddr;
    void		*ifa_data;
};

#ifndef ifa_broadaddr
#define	ifa_broadaddr	ifa_dstaddr
#endif

#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
doPmaSetGlobal(char *ifName, Cell *range, int force)
{
#if (_BSDI_VERSION >= 199701) || defined(__FreeBSD__)

    struct	ifaddrs	*ifap;

    for (ifap = ifaddrs; ifap; ifap = ifap->ifa_next)
    {
	if (strcmp(ifap->ifa_name, ifName) != 0)
	    continue;

	if ((ifap->ifa_addr == NULL)
	    || (ifap->ifa_addr->sa_family != PF_INET))
	    continue;

	_setGlobal(ifap, range, force);
	break;
    }
#else

    int			 iter;
    struct	ifaddrs	*ifap;

    for (ifap = ifaddrs, iter = 0; iter < nip; ifap++, iter++)
    {
	if (strcmp(ifap->ifa_name, ifName) != 0)
	    continue;

	if ((ifap->ifa_addr) && (ifap->ifa_addr->sa_family != PF_INET))
	    continue;

	_setGlobal(ifap, range, force);
	break;
    }
#endif
}


void
doPmaRemoveGlobal(char *ifName, Cell *range)
{
    struct _msgBox	mBox;

    bzero(&mBox, sizeof(struct _msgBox));
    if ((mBox.freight = (char *)_unfoldRange(NULL, range, &mBox.nums)) == NULL)
	StandardOut("No appropriate global address.\n"),
	exit(2);

    strcpy(mBox.m_aux, ifName);
    mBox.size = sizeof(struct in_addr);
    sendMsg(&mBox, PMIOCREMGLOBAL, TRUE);
}


void
doPmaSetNatRule(struct _msgBox *ncf, int type, Cell *inrange, Cell *exrange, int policy)
{
    int	srcc, dstc;

    srcc = LST_length(inrange);
    dstc = LST_length(exrange);

    if ((type == NAT_STATIC)
	|| ((type == 0)
	    && (srcc == 1)
	    && (dstc == 1)
	    && (((addrBlock *)CAR(inrange))->addr[1].s_addr == 0xffffffff)
	    && (((addrBlock *)CAR(exrange))->addr[1].s_addr == 0xffffffff)
	    && (((addrBlock *)CAR(exrange))->port[0] == 0)))
	_setNatStatic (ncf, inrange, exrange);
    else
	_setNatDynamic(ncf, inrange, exrange, policy);
}


void
doPmaRemoveNatRule(char *ifName, int type, Cell *rules)
{
    int			*m;
    int			 num0, num1;
    struct _msgBox	 mBox;

    if (rules == NULL)
	return ;

    num0 = countNatRules(ifName, type);
    if (num0 <= 0)
    {
	StandardOut("No nat rule entry.\n");
	return ;
    }

    if ((m = arrangeRuleNums(rules, num0, &num1)) == NULL)
	return ;

    bzero(&mBox, sizeof(struct _msgBox));
    strcpy(mBox.m_aux, ifName);
    mBox.flags   = type;
    mBox.nums    = num1 + 1;
    mBox.size    = sizeof(int);
    mBox.freight = (char *)m;
    sendMsg(&mBox, PMIOCREMNAT, TRUE);
}


#if defined(orphan)
void
doPmaSetFilRule(char *ifName, int filflags, char *fileName)
{
    filRule	fr;
    int         rv;

    bzero(&fr, sizeof(filRule));
    rv = _checkBpfFile(fileName, &fr);

    strcpy(fr.ifName, ifName);
    fr.flags = filflags;
    rv = ioctl(_fd, PMIOCFADD, &fr);
}


int
_checkBpfFile(char *fileName, filRule *fr)
{
    int     fd, rv;
    int	    magic;

    if ((fd = open(fileName, O_RDONLY)) == ERROR)
	perror("readBpfFile"),
	exit(errno);

    lseek(fd, 0, SEEK_SET);

    if ((rv =read(fd, &magic, sizeof(int))) == ERROR)
	perror("Failure on read"),
	exit(errno);

    switch (magic)
    {
      case PMI_MAGIC:
	rv = readPmiFile(fd, fr);
	break;

      case PMI_BPF_MAGIC:
	rv = readBpfFile(fd, fr);
	break;

      default:
	perror("Illegal Magic"),
	exit(1);
    }

    close(fd);
    return (rv);
}


int
readPmiFile(int fd, filRule *fr)
{
    pmiHeader	ph;
    int		rv;

    rv = lseek(fd, 0, SEEK_SET);

    rv = read(fd, &ph, sizeof(pmiHeader));
    if (ph.version != PMI_VERSION)
	perror("Illegal PMI version"),
	exit(2);

    fr->frinfo_len = ph.Pmr.size;
    fr->frinfo_entry = malloc(ph.Pmr.size);
    rv = lseek(fd, ph.Pmr.offset, SEEK_SET);
    rv = read (fd, fr->frinfo_entry, ph.Pmr.size);

    fr->fr_len = ph.Bpf.size/ sizeof(struct pm_insn);
    fr->fr_entry = malloc(ph.Bpf.size);
    rv = lseek(fd, ph.Bpf.size, SEEK_SET);
    rv = read (fd, fr->fr_entry, ph.Bpf.size);

    return (rv);
}


int
readBpfFile(int fd, filRule *fr)
{
    int	    version;

    read(fd, &version, sizeof(int));
    if (version != PMI_BPF_VERSION)
	perror("Illegal Version"),
	exit(2);

    {
	pmiElemHeader	ph;
	int		rv, elsize;

	read(fd, &ph, sizeof(ph));
	if (ph.elementID != PMI_RT_BPF)
	    perror("Illegal ElementID"),
	    exit(3);

	elsize = ph.elementSZ - sizeof(pmiElemHeader);
	fr->fr_entry = (Insns *)malloc(elsize);
	fr->fr_len   = elsize / sizeof(struct pm_insn);
	rv = read(fd, fr->fr_entry, elsize);
	close(fd);
	return (rv);
    }
}
#endif


void
doPmaSetRoute(int proto, addrBlock *src, addrBlock *dst, u_int gw)
{
    int			 rv;
    fwdRoute		*fwr;
    struct _msgBox	 mBox;

    bzero(&mBox, sizeof(struct _msgBox));
    fwr = &mBox.m_fwdRoute;

    if (proto)
	fwr->ip_p = proto;

    if (src)
    {
	fwr->type[0] = src->type;
	fwr->ip_src[0].s_addr = htonl(src->addr[0].s_addr);
	fwr->ip_src[1].s_addr = htonl(src->addr[1].s_addr);
	fwr->th_sport[0] = htons(src->port[0]);
	fwr->th_sport[1] = htons(src->port[1]);
	if (src->type == IN_ADDR_MASK)
	    fwr->ip_src[2].s_addr = 
		htonl(src->addr[0].s_addr & src->addr[1].s_addr);
    }

    if (dst)
    {
	fwr->type[1] = dst->type;
	fwr->ip_dst[0].s_addr = htonl(dst->addr[0].s_addr);
	fwr->ip_dst[1].s_addr = htonl(dst->addr[1].s_addr);
	fwr->th_dport[0] = htons(dst->port[0]);
	fwr->th_dport[1] = htons(dst->port[1]);
	if (dst->type == IN_ADDR_MASK)
	    fwr->ip_dst[2].s_addr = 
		htonl(dst->addr[0].s_addr & dst->addr[1].s_addr);
    }

    fwr->ip_via.s_addr = htonl(gw);
    
    if ((rv = sendMsg(&mBox, PMIOCADDROUTE, TRUE)) < 0)
	switch (errno)
	{
	  case EADDRINUSE:
	    ErrorOut("pma: ioctl: `protocol\' or `from\' or `to\' duplicated\n");
	    break;

	  default:
	    perror("pma: ioctl:");
	    break;
	}
}


void
doPmaRemoveRoute(Cell *rules)
{
    int			*m;
    int		 	 num0, num1;
    struct _msgBox	 mBox;

    if (rules == NULL)
	return ;

    num0 = countRouteRules();
    if (num0 <= 0)
    {
	StandardOut("No route entry.\n");
	return ;
    }

    if ((m = arrangeRuleNums(rules, num0, &num1)) == NULL)
	return ;

    bzero(&mBox, sizeof(struct _msgBox));
    mBox.nums    = num1 + 1;			/* including sentinel	*/
    mBox.size    = sizeof(int);
    mBox.freight = (char *)m;
    if (sendMsg(&mBox, PMIOCREMROUTE, TRUE) < 0)
	perror("pma: ioctl: DeleteRoute");
}


int
countNatRules(char *ifName, int type)
{
    Cell	cons0, cons1;
    int		pos;
    int		rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_pmBoxList")) <= 0)
	return (0);

    if (pos == 0)
	return (0);

    while (pos)
    {
	readKvm((caddr_t)&cons0, sizeof(Cell), pos);
	if (cons0.car)
	{
	    pmBox	pmb;

	    readKvm((caddr_t)&pmb, sizeof(pmb), (int)cons0.car);
	    if ((ifName == NULL) || (strcmp(pmb.ifName, ifName) == SAME))
	    {
		natBox		nBox;

		if (pmb.natBox != NULL)
		{
		    readKvm((caddr_t)&nBox, sizeof(natBox), (int)pmb.natBox);
		    if (type == NAT_STATIC)
			pos = (int)nBox.natStatic;
		    else
			pos = (int)nBox.natDynamic;

		    rv = 0;
		    while (pos)
		    {
			readKvm((caddr_t)&cons1, sizeof(Cell), pos);
			if (cons1.car)
			    rv++;
			pos = (int)cons1.cdr;
		    }
		    return (rv);
		}
	    }
	}
	pos = (int)cons0.cdr;
    }

    return (0);
}


int
countRouteRules()
{
    Cell	cons;
    int		pos;
    int		rv;

    if ((rv = openKvm()) <= 0)
	return (0);

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_routeConf")) <= 0)
	return (0);

    if (pos == 0)
	return (0);
    
    rv = 0;
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	    rv++;

	pos = (int)cons.cdr;
    }
    
    closeKvm();
    return (rv);
}


void
doPmaGetSelfaddr()
{
    struct _msgBox	mBox;

    if (sendMsg(&mBox, PMIOCGETADDR, TRUE) < 0)
	perror("pma: ioctl: PMIOCGETADDR");
}


void
doPmaSetSelfaddrFlags(u_long ipaddr, int flag)
{
    struct _msgBox	mBox;

    HTONL(ipaddr);

    bzero(&mBox, sizeof(mBox));
    bcopy(&ipaddr, &mBox.m_aux, sizeof(ipaddr));
    mBox.flags = flag;
    if (sendMsg(&mBox, PMIOCSETADDRFLG, TRUE) < 0)
	perror("pma: ioctl: PMIOCSETADDRFLG");
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if	0
int
_readRule(pmBox *pmb, Dirs inout, int which, int disas)
{
    Cell     cons;
    char    *name, *io;
    int      pos;

    switch (which)
    {
      case 1: name = " preNat"; pos = (int)pmb->rules[inout].preNat;	break;
      case 2: name = "    Nat"; pos = (int)pmb->rules[inout].Nat;	break;
      case 3: name = "postNat"; pos = (int)pmb->rules[inout].postNat;	break;
    }

    if (inout == IpInput)	io = "input";
    else			io = "output";

    while (pos)
    {
	struct _haw	haw;
	PmProgram	pp;
	char		Wow[BUFSIZ];
	int		size;

	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    readKvm((caddr_t)&haw, sizeof(haw), (int)cons.car);
	    if (haw.pmprg.pm_insns)
	    {
		pp = haw.pmprg;
		StandardOut("    %s(%s): %d\n", name, io, pp.pm_len);
		size = sizeof(PmInsn)*pp.pm_len;
		readKvm((caddr_t)&pp, sizeof(pp), (int)haw.pmprg.pm_insns);
/*		out_asm((PmInsn *)Wow, pp.pm_len);			*/
	    }
	}
	pos = (int)cons.cdr;
    }
    return ;
}
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
doPmaShowReal()
{
    Cell    cons;
    int	    firsttime = 0;
    int     pos;
    int     rv;

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_immRealPool")) <= 0)
	return ;

    if (pos == 0)
    {
	StandardOut("No real adddress available.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    realAddr	ra;

	    if (firsttime == 0)
	    {
		firsttime = 1;
		StandardOut("IP\n");
	    }

	    readKvm((caddr_t)&ra, sizeof(ra), (int)cons.car);
	    StandardOut("%s\n", inet_ntoa(ra.realAddr));
	}
	pos = (int)cons.cdr;
    }
}


void
doPmaShowVirtual()
{
    Cell    cons;
    int	    firsttime = 0;
    int     pos;
    int     rv;

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_immVirtualPool")) <= 0)
	return ;

    if (pos == 0)
    {
	StandardOut("No virtual adddress available.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    virtualAddr	va;

	    if (firsttime == 0)
	    {
		firsttime = 1;
		StandardOut("IP\n");
	    }

	    readKvm((caddr_t)&va, sizeof(va), (int)cons.car);
	    StandardOut("%s\n", inet_ntoa(va.virtualAddr));
	}
	pos = (int)cons.cdr;
    }
}


void
doPmaImmShowStat()
{
    Cell    cons;
    int     firsttime = 0;
    int     pos;
    int     rv;

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_immBind")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No bind set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    virtualAddr	va;

	    if (firsttime == 0)
	    {
		firsttime = 1;
		StandardOut("Virtual			Real\n");
	    }

	    readKvm((caddr_t)&va, sizeof(va), (int)cons.car);
	    StandardOut("%s", inet_ntoa(va.virtualAddr));
	    StandardOut("\t\t\t\t\t%8d\t%8d", va.inbound, va.outbound);
	    StandardOut("\n");

	    if (va.realAddrHead)
	    {
		Cell	 cons1;
		Cell	*pos1;

		cons1.car = NULL;
		cons1.cdr = NULL;

		for (pos1  = va.realAddrHead; ; pos1  = cons1.cdr)
		{
		    readKvm((caddr_t)&cons1, sizeof(Cell), (int)pos1);
		    if (cons1.car)
		    {
			realAddr	ra;

			readKvm((caddr_t)&ra, sizeof(ra), (int)cons1.car);
			StandardOut("\t\t\t%s", inet_ntoa(ra.realAddr));
			StandardOut("(%4d)", ra.selected);
			StandardOut("\t%8d\t%8d", ra.inbound, ra.outbound);
			StandardOut("\n");
		    }

		    if (pos1 == va.realAddrTail)
			break;

		}
	    }
	}
	pos = (int)cons.cdr;
    }
}


void
doPmaImmShowLinkStat()
{
    Cell    cons;
    int     pos;
    int     rv;

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_immBind")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No bind set.\n");
	return ;
    }

    StandardOut("(linkstat");
    StandardOut("\n");
    StandardOut("  (time %d)", time(NULL));
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    virtualAddr	va;

	    readKvm((caddr_t)&va, sizeof(va), (int)cons.car);
	    StandardOut("\n");
	    StandardOut("  (virtual %s ", inet_ntoa(va.virtualAddr));
	    StandardOut(" (in %d)", va.inbound);
	    StandardOut(" (out %d)", va.outbound);

	    if (va.realAddrHead)
	    {
		Cell	 cons1;
		Cell	*pos1;

		cons1.car = NULL;
		cons1.cdr = NULL;

		for (pos1  = va.realAddrHead; ; pos1  = cons1.cdr)
		{
		    readKvm((caddr_t)&cons1, sizeof(Cell), (int)pos1);
		    if (cons1.car)
		    {
			realAddr	ra;

			readKvm((caddr_t)&ra, sizeof(ra), (int)cons1.car);
			StandardOut("\n");
			StandardOut("    (real %s", inet_ntoa(ra.realAddr));
			StandardOut(" (hit %d)", ra.selected);
			StandardOut(" (in %d)" , ra.inbound);
			StandardOut(" (out %d)", ra.outbound);
			StandardOut(")");
		    }

		    if (pos1 == va.realAddrTail)
			break;
		}
	    }
	    StandardOut(")");
	}
	pos = (int)cons.cdr;
    }
    StandardOut(")");
    StandardOut("\n");
}


void
doPmaShowBind()
{
    Cell    cons;
    int     firsttime = 0;
    int     pos;
    int     rv;

    if ((rv = openKvm()) <= 0)
	return ;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_immBind")) <= 0)
	return;

    if (pos == 0)
    {
	StandardOut("No bind set.\n");
	return ;
    }

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    virtualAddr	va;

	    if (firsttime == 0)
	    {
		firsttime = 1;
		StandardOut("Virtual			Real\n");
	    }

	    readKvm((caddr_t)&va, sizeof(va), (int)cons.car);
	    StandardOut("%s\n", inet_ntoa(va.virtualAddr));
	    if (va.realAddrHead)
	    {
		Cell	 cons1;
		Cell	*pos1;

		cons1.car = NULL;
		cons1.cdr = NULL;

		for (pos1  = va.realAddrHead; ; pos1  = cons1.cdr)
		{
		    readKvm((caddr_t)&cons1, sizeof(Cell), (int)pos1);
		    if (cons1.car)
		    {
			realAddr	ra;

			readKvm((caddr_t)&ra, sizeof(ra), (int)cons1.car);
			StandardOut("\t\t\t%s\n", inet_ntoa(ra.realAddr));
		    }

		    if (pos1 == va.realAddrTail)
			break;

		}
	    }
	}
	pos = (int)cons.cdr;
    }
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	void
_setGlobal(struct ifaddrs *ifap, Cell *range, int force)
{
    int		     cnt;
    Cell	    *p;
    struct in_addr  *inaddr, *ina, *inap;
    
    for (p = range, cnt = 0; p; p = CDR(p))
    {
	inaddr = (struct in_addr *)CAR(p);
	if (inaddr[1].s_addr == 0)
	    cnt += 1;
	else
	    cnt += (inaddr[1].s_addr - inaddr[0].s_addr + 1);
    }

    ina = (struct in_addr *)malloc(sizeof(struct in_addr) * cnt);
    inap = ina;

    {
	u_long	selfaddr, subnetmask;
	u_long	ipa, ips, ipe;

	selfaddr = ((struct sockaddr_in *)ifap->ifa_addr)->sin_addr.s_addr;
	selfaddr = ntohl(selfaddr);
	subnetmask = ((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr.s_addr;
	subnetmask = ntohl(subnetmask);

	for (p = range; p; p = CDR(p))
	{
	    inaddr = (struct in_addr *)CAR(p);
	    if (inaddr[1].s_addr == 0)
	    {
		ipa = inaddr[0].s_addr;
		if (((ipa == selfaddr)
		     || ((ipa & ~subnetmask) == 0)
		     || (~((ipa & ~subnetmask) | subnetmask) == 0))
		    && (force == 0))
		    continue;

		inap->s_addr = htonl(ipa);
		inap++;
	    }
	    else
	    {
		ips = inaddr[0].s_addr;
		ipe = inaddr[1].s_addr;

		for (ipa = ips; ipa <= ipe; ipa++)
		{
		    if (((ipa == selfaddr)
			 || ((ipa & ~subnetmask) == 0)
			 || (~((ipa & ~subnetmask) | subnetmask) == 0))
			&& (force == 0))
			continue;

		    inap->s_addr = htonl(ipa);
		    inap++;
		}
	    }
	}
    }

    {
	struct _msgBox	mBox;

	if (ina == inap)
	    StandardOut("No appropriate global address.\n"),
	    exit(2);

	strcpy(mBox.m_ifName, ifap->ifa_name);
	mBox.nums = inap - ina;
	mBox.freight = (char *)ina;
	if (sendMsg(&mBox, PMIOCSETGLOBAL, TRUE) < 0)
	    perror("pma: ioctl: setglobal"), exit(errno);
    }    
}


static	struct in_addr *
_unfoldRange(struct ifaddrs *ifap, Cell *range, int *num)
{
    int			 cnt;
    Cell		*p;
    struct in_addr	*inaddr, *ina, *inap;

    for (p = range, cnt = 1; p; p = CDR(p))
    {
	inaddr = (struct in_addr *)CAR(p);
	if (inaddr[1].s_addr == 0)
	    cnt += 1;
	else
	    cnt += (inaddr[1].s_addr - inaddr[0].s_addr + 1);
    }

    ina  = (struct in_addr *)(malloc(sizeof(struct in_addr) * cnt));
    inap = ina;

    {
	u_long	selfaddr, subnetmask;
	u_long ipa, ips, ipe;
	
	selfaddr = subnetmask = 0;
	if (ifap)
	{
	    selfaddr = ((struct sockaddr_in *)ifap->ifa_addr)->sin_addr.s_addr;
	    selfaddr = ntohl(selfaddr);
	    subnetmask = ((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr.s_addr;
	    subnetmask = ntohl(subnetmask);
	}

	for (p = range; p; p = CDR(p))
	{
	    inaddr = (struct in_addr *)CAR(p);
	    if (inaddr[1].s_addr == 0)
	    {
		ipa = inaddr[0].s_addr;
		if ((selfaddr)
		    && ((ipa == selfaddr)
			|| ((ipa & subnetmask) == 0)
			|| (~((ipa & ~subnetmask) | subnetmask) == 0)))
		    continue;

		inap->s_addr = htonl(ipa);
		inap++;
	    }
	    else
	    {
		ips = inaddr[0].s_addr;
		ipe = inaddr[1].s_addr;

		for (ipa = ips; ipa <= ipe; ipa++)
		{
		    if ((selfaddr)
			&& ((ipa == selfaddr)
			    || ((ipa & subnetmask) == 0)
			    || (~((ipa & ~subnetmask) | subnetmask) == 0)))
			continue;

		    inap->s_addr = htonl(ipa);
		    inap++;
		}
	    }
	}
    }

    if (ina == inap)
    {
	free(ina);
	return (NULL);
    }

    *num = inap - ina + 1;
    inap->s_addr = (-1);
    return (ina);
}


static	void
_setNatStatic(struct _msgBox *ncf, Cell *inrange, Cell *exrange)
{
    int			 size, srcc, dstc;
    Cell		*p;
    addrBlock		*ap;
    natRuleEntry	*nre;

    srcc = LST_length(inrange);
    dstc = LST_length(exrange);

    size = SZNCE + (srcc + dstc - 1) * SZAPT;
    nre = (natRuleEntry *)malloc(size);

    nre->type = NAT_STATIC;
    nre->srcCnt = srcc;
    nre->dstCnt = dstc;

    ap = nre->addr;
    for (p = inrange; p; p = CDR(p), ap++)
    {
	bcopy(CAR(p), ap, sizeof(addrBlock));
	HTONL(ap->addr[0].s_addr);
	HTONL(ap->addr[1].s_addr);
    }

    for (p = exrange; p; p = CDR(p), ap++)
    {
	bcopy(CAR(p), ap, sizeof(addrBlock));
	HTONL(ap->addr[0].s_addr);
	HTONL(ap->addr[1].s_addr);
    }

    ncf->nums = 1;
    ncf->size = size;
    ncf->freight = (char *)nre;
    sendMsg(ncf, PMIOCSETNAT, TRUE);
}


static	void
_setNatDynamic(struct _msgBox *ncf, Cell *inrange, Cell *exrange, int policy)
{
    int			 cnt, size;
    Cell		*p, *exr;
    addrBlock		*ap;
    natRuleEntry	*nre;

    struct	cfg
    {
	addrBlock	*ap;
	struct	in_addr	*aq;
    }		*cfg;

    exr = NULL;
    for (p = exrange; p ; p = CDR(p))
    {
	cfg = malloc(sizeof(struct cfg));

	ap = (addrBlock *)CAR(p);
	cfg->ap = ap;
	cfg->aq = _unfoldAddr(ncf->m_ifName, &ap->addr[0], &ap->addr[1]);
	LST_hookup_list(&exr, cfg);

	if ((policy == PAT_ADDRONLY)
	    && (ap->port[0] != 0))
	{
	    policy = PAT_PORTFIRST;
	}
    }

    for (p = exr, cnt = 0; p; p = CDR(p))
    {
	cnt += sizeof(addrBlock);
	cnt += sizeof(int);
	cnt += ((struct cfg *)CAR(p))->aq->s_addr * sizeof(struct in_addr);
    }
    
    size = SZNCE + cnt;
    nre = (natRuleEntry *)malloc(size);

    bzero(nre, size);

    nre->type   = NAT_DYNAMIC;
    nre->policy = policy;
    nre->srcCnt = LST_length(inrange);
    nre->dstCnt = LST_length(exrange);

    {
	int	 sz;
	char	*apc;

	apc = (char *)nre->addr;
	for (p = inrange; p; p = CDR(p), apc += sizeof(addrBlock))
	{
	    bcopy(CAR(p), apc, sizeof(addrBlock));
	    HTONL(((addrBlock *)apc)->addr[0].s_addr);
	    HTONL(((addrBlock *)apc)->addr[1].s_addr);
	}

	for (p = exr; p; p = CDR(p))
	{
	    cfg = (struct cfg *)CAR(p);
	    sz  = sizeof(int);
	    sz += cfg->aq->s_addr * sizeof(struct in_addr);

	    bcopy(cfg->ap, apc, sizeof(addrBlock));
	    HTONL(((addrBlock *)apc)->addr[0].s_addr);
	    HTONL(((addrBlock *)apc)->addr[1].s_addr);
	    apc += sizeof(addrBlock);

	    bcopy(cfg->aq, apc, sz);
	    apc += sz;
	}
    }
    
    if (isDebug(D_DUMPIOCTL))
    {
	int cmd;

	cmd = PMIOCSETNAT;
	_dumpIoctl(cmd, (caddr_t)ncf);
    }

    ncf->nums = 1;
    ncf->size = size;
    ncf->freight = (char *)nre;
    sendMsg(ncf, PMIOCSETNAT, TRUE);
}


static	void	*
_unfoldAddr(char *ifname, struct in_addr *addr, struct in_addr *mask)
{
#if (_BSDI_VERSION >= 199701) || defined(__FreeBSD__)

    struct	ifaddrs	*ifap;

    for (ifap = ifaddrs; ifap; ifap = ifap->ifa_next)
    {
	if ((ifap->ifa_addr == NULL)
	    || (ifap->ifa_addr->sa_family != PF_INET))
	    continue;

	if (strcmp(ifap->ifa_name, ifname) != 0)
	    continue;

	return (__unfoldAddr(ifap, addr, mask));
    }
#else

    int			 iter;
    struct	ifaddrs	*ifap;

    for (ifap = ifaddrs, iter = 0; iter < nip; ifap++, iter++)
    {
	if ((ifap->ifa_addr) && (ifap->ifa_addr->sa_family != PF_INET))
	    continue;

	if (strcmp(ifap->ifa_name, ifname) != 0)
	    continue;

	return (__unfoldAddr(ifap, addr, mask));
    }
#endif

    return (NULL);
}


static	void	*
__unfoldAddr(struct ifaddrs *ifap, struct in_addr *addr, struct in_addr *mask)
{
    int		cnt;
    u_long	saddr, eaddr;
    struct  in_addr	*ina, *inp;

    saddr = addr->s_addr;
    eaddr = addr->s_addr | ~mask->s_addr;
    cnt = eaddr - saddr + 1;

    cnt++;
    ina = (struct in_addr *)malloc(sizeof(struct in_addr) * cnt);
    inp = ina + 1;
    
    {
	u_long	selfaddr, subnetmask;
	u_long	ipa;

	selfaddr = ((struct sockaddr_in *)ifap->ifa_addr)->sin_addr.s_addr;
	selfaddr = ntohl(selfaddr);
	subnetmask = ((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr.s_addr;
	subnetmask = ntohl(subnetmask);

	for (ipa = saddr; ipa <= eaddr; ipa++)
	{
	    if (((ipa == selfaddr)
		 && (isNatGlobal(ipa) == FALSE))
		|| ((ipa & ~subnetmask) == 0)
		|| (~((ipa & ~subnetmask) | subnetmask) == 0))
		continue;

	    inp->s_addr = htonl(ipa);
	    inp++;
	}
	ina->s_addr = inp - ina - 1;
    }
    return (ina);
}


static	int
isNatGlobal(u_long addr)
{
    Cell	cons;
    int		pos;
    int		rv;

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_selfAddr")) <= 0)
	return (FALSE);

    if (pos == 0)
	return (FALSE);

    HTONL(addr);
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell),  pos);
	if (cons.car)
	{
	    SelfAddr	self;

	    readKvm((caddr_t)&self, sizeof(self), (int)cons.car);
	    if ((self.ifaddr.s_addr == addr)
		&& (self.addrflags & NAT_GLOBAL))
		return (TRUE);
	}
	pos = (int)cons.cdr;
    }
    closeKvm();

    return (FALSE);
}


static	int *
arrangeRuleNums(Cell *rules, int num0, int *num1)
{
    Cell	*p;
    short	*q;
    int		*m;
    int		 n1;

    for (p = rules, n1 = 1; p; p = CDR(p))	/* 1 for sentinel	*/
    {
	q = (short *)p;
	if (q[1] == 0)			n1++;
	else				n1 += q[1] - q[0] + 1;
    }

    m = (int *)malloc(sizeof(int) * n1);
    for (p = rules, n1 = 0; p; p = CDR(p))
    {
	q = (short *)p;
	if (q[1] == 0)
	    m[n1++] = q[0];
	else
	{
	    int	idx;

	    for (idx = q[0]; idx <= q[1]; idx++)
	    {
		m[n1++] = idx;
	    }
	}
    }

    if (n1 == 1)
    {
	if (m[0] >= num0)				/* 0 origin	*/
	{
	    StandardOut("%d: Out of range.\n", m[0]);
	    free(m);
	    return (NULL);
	}
    }
    else
    {
	int	idx0, idx1, mm;

	qsort(m, n1, sizeof(int), &compar);
	mm = m[0];
	for (idx0 = 1, idx1 = 0; idx0 < n1; idx0++)
	{
	    if (m[idx0] == m[idx1])
		StandardOut("%d: duplicated.\n", m[idx1]);
	    else if (m[idx0] >= num0)
		StandardOut("%d:  Out of range.\n", m[idx0]);
	    else
	    {
		idx1++;
		m[idx1] = m[idx0];
	    }
	}
	n1 = idx1 + 1;
    }

    m[n1] = -1;				/* for sentinel		*/
    *num1 = n1;

    return (m);
}


static	int
compar(const void *first, const void *second)
{
    if (*(int *)first < *(int *)second)
	return (-1);
    else if (*(int *)first > *(int *)second)
	return ( 1);
    else
	return ( 0);
}


int
sendMsg(struct _msgBox *mBox, int type, int doPerror)
{
    int	rv;

#if defined(PM_USE_SOCKET)
    mBox->msgtype = type;
    rv = setsockopt(_fd, IPPROTO_PM, PM_SOCKOPT, mBox, sizeof(struct _msgBox));
#else
    rv = ioctl(_fd, mBox->msgtype, mBox);
#endif

    if ((rv < 0) && (doPerror != 0))
	perror("pma");

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	CELL_NUMS		64
#define	CELL_PAGE		(CELL_NUMS * sizeof(Cell))
#define	CELL_FREE_MARKER	((Cell *)0xdeadface)

static	int	 _cell_used;
static	int	 _cell_free;
static	Cell	*_cell_freeList;
static	Cell	*_cell_mallBlock;

static	Cell *_getCell		__P((void));
static	Cell *_getEmptyCell	__P((void));


Cell *
LST_cons(void *c_car, void *c_cdr)
{
    Cell    *ptr = NULL;

    ptr = _getCell();
    CAR(ptr) = c_car;
    CDR(ptr) = c_cdr;

    _cell_used++;
    _cell_free--;

    return (ptr);
}


Cell *
LST_last(Cell *list)
{
    register	Cell	*ptr = NULL;

    if (list == NULL)
	ptr = NULL;
    else
	for (ptr = list; CDR(ptr) != NULL; ptr = CDR(ptr)) ;

    return (ptr);
}


int
LST_length(Cell *list)
{
    register    int     retval = 0;

    if (list == NULL)
	retval = 0;
   else
   {
       register    Cell    *ptr;

       for (ptr = list; ptr; retval++, ptr = CDR(ptr)) ;
   }

    return (retval);
}


Cell *
LST_hookup(Cell *list, void *elem)
{
    register    Cell    *ptr = list;

    if (list == NULL)
	ptr = LST_cons(elem, NULL);
    else
	CDR(LST_last(list)) = LST_cons(elem, NULL);

    return (ptr);
}


Cell *
LST_hookup_list(Cell **list, void *elem)
{
    register    Cell    *ptr = NULL;

    if (*list == NULL)
	*list = LST_cons(elem, NULL);
    else
	CDR(LST_last(*list)) = LST_cons(elem, NULL);

    return (ptr);
}


static	Cell *
_getCell()
{
    Cell    *ptr = NULL;

    if (_cell_freeList == NULL)
	_cell_freeList = _getEmptyCell();

    ptr = _cell_freeList;
    _cell_freeList = CDR(_cell_freeList);

    return (ptr);
}


static	Cell *
_getEmptyCell()
{
    register	int	iter;
    register	Cell    *ptr = NULL;
    register	Cell	*p;

#if defined(_KERNEL)
    MALLOC(ptr, Cell *, CELL_PAGE, M_TEMP, M_WAITOK);
#else
    ptr = (Cell *)malloc(CELL_PAGE);
#endif
    if (ptr == NULL)
    {
	return (ptr);
    }

    CAR(ptr) = (Cell *)ptr;
    CDR(ptr) = NULL;

    if (_cell_mallBlock == NULL)
	_cell_mallBlock = ptr;
    else
	CDR(LST_last(_cell_mallBlock)) = ptr;

    ptr++;
    for (iter = CELL_NUMS - 2 , p = ptr; iter; iter-- , p++)
	CAR(p) = (Cell *)0xdeadbeaf, CDR(p) = p + 1;
    CAR(p) = (Cell *)0xdeadbeaf;
    CDR(p) = NULL;
    _cell_free += CELL_NUMS - 1;
    
    return (ptr);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
_masktobits(u_long mask)
{
    int     iter;

    for (iter = 0; iter <= 32; iter++)
    {
	if (mtobits[iter] == mask)
	    return (iter);
    }
    return (-1);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__) && defined(NET_RT_IFLIST)

int
getifaddrs(struct ifaddrs **pif)
{
    int			 mib[6];
    size_t		 needed;
    char		*buf, *lim, *next;
    struct rt_msghdr	*rtm;
    struct ifaddrs	*ifa, *ifc, *ift, *cif;

    ifa = ifc = ift = cif = NULL;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
	perror("sysctl"), exit(errno);

    if ((buf = malloc(needed)) == NULL)
	perror("malloc"), exit(errno);

    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
	perror("sysctl"), exit(errno);

    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen)
    {
	rtm = (struct rt_msghdr *)next;
	if (rtm->rtm_version != RTM_VERSION)
	    continue;

	switch (rtm->rtm_type)
	{
	  case RTM_IFINFO:
	    {
		struct if_msghdr	*ifm;
		struct sockaddr_dl	*dl;

		ifm =  (struct if_msghdr *)rtm;
		if (ifm->ifm_addrs & RTA_IFP)
		{
		    dl = (struct sockaddr_dl *)(ifm+1);

		    ifc = (struct ifaddrs *)calloc(1, sizeof(struct ifaddrs));
		    ifc->ifa_name = calloc(1, ROUNDUP(dl->sdl_nlen + 1));
		    bcopy(dl->sdl_data, ifc->ifa_name, dl->sdl_nlen);
		    ifc->ifa_flags = (int)ifm->ifm_flags;

		    if (ifa == NULL)	ifa = ifc;
		    if (ift == NULL)	ift = ifc;
		    else		ift->ifa_next = ifc, ift = ifc;
		    cif = ifc;
		}
	    }
	    break;

	  case RTM_NEWADDR:
	    {
		int			 bits;
		struct ifa_msghdr	*ifam;
		struct sockaddr		*sa;

		ifc = (struct ifaddrs *)calloc(1, sizeof(struct ifaddrs));
		ifc->ifa_name  = cif->ifa_name;
		ifc->ifa_flags = cif->ifa_flags;

		if (ifa == NULL)	ifa = ifc;
		if (ift == NULL)	ift = ifc;
		else		ift->ifa_next = ifc, ift = ifc;

		ifam = (struct ifa_msghdr *)rtm;
		sa = (struct sockaddr *)(ifam+1);

		for (bits = 1; bits <= 0x80; bits <<= 1)
		{
		    if ((ifam->ifam_addrs & bits) == 0)
			continue;
		    
		    switch (bits)
		    {
		      case RTA_NETMASK:
			ifc->ifa_netmask = sa;
			break;

		      case RTA_IFA:
			ifc->ifa_addr = sa;
			break;

		      case RTA_BRD:
			ifc->ifa_broadaddr = sa;
			break;
		    }
		    sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len));
		}
	    }
	    break;
	}
    }
    *pif = ifa;
    return (0);
}

#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
debugProbe(char *msg)
{
    char	Wow[BUFSIZ];

    sprintf(Wow, "%s\n", msg);
    DebugOut(Wow);
}


static	void
_dumpIoctl(int cmd, caddr_t addr)
{
    switch (cmd)
    {
      case PMIOCSETNAT:	_dumpSETNAT(addr);	break;
    }
}


static	void
_dumpSETNAT(caddr_t addr)
{
    struct _msgBox	*nrs;

    nrs = (struct _msgBox *)addr;

    DebugOut("PMIOCSETNAT\n");
    DebugOut("  ifName: %s\n",     nrs->m_ifName);
    DebugOut("  flags:  0x%08x\n", nrs->flags);
    DebugOut("  nrByte: %d\n",     nrs->size);

    switch (((natRuleEntry *)nrs->freight)->type)
    {
      case NAT_DYNAMIC:	_dumpSETNATdynamic((natRuleEntry *)nrs->freight);	break;
    }
}


static	void
_dumpSETNATdynamic(natRuleEntry *nre)
{
    int		 iter;
    char	*ptr;

    DebugOut("type: %d\n",   nre->type);
    DebugOut("policy: %d\n", nre->policy);
    DebugOut("srcCnt: %d\n", nre->srcCnt);
    DebugOut("dstCnt: %d\n", nre->dstCnt);

    ptr = (char *)nre->addr;
    for (iter = 0; iter < nre->srcCnt; iter++)
    {
	_dumpAddrBlock((addrBlock *)ptr);
	ptr += sizeof(addrBlock);
    }

    for (iter = 0; iter < nre->dstCnt; iter++)
    {
	int	cnt, ite;

	_dumpAddrBlock((addrBlock *)ptr);
	ptr += sizeof(addrBlock);

	cnt = *(int *)ptr;
	ptr += sizeof(int);
	for (ite = 0; ite < cnt; ite++)
	{
	    DebugOut("gaddr: %s\n", inet_ntoa(*(struct in_addr *)ptr));
	    ptr += sizeof(struct in_addr);
	}
    }
}


static	void
_dumpAddrBlock(addrBlock *adr)
{
    DebugOut("ip_p: %d\n", adr->ip_p);
    DebugOut("type: %d\n", adr->type);
    DebugOut("policy: %d\n", adr->policy);
    DebugOut("addr: %s", inet_ntoa(adr->addr[0]));
    DebugOut(" %s\n", inet_ntoa(adr->addr[1]));
    DebugOut("ptrn: %s\n", inet_ntoa(adr->ptrn));
    DebugOut("gList: 0x%08x\n", adr->gList);
    DebugOut("gAddrCur: 0x%08x\n", adr->gAddrCur);
    DebugOut("port: %d %d\n", adr->port[0], adr->port[1]);
    DebugOut("curport: %d\n", adr->curport);
    DebugOut("pspace: %d\n", adr->pspace);
}


void
close_fd()
{
    close(_fd);
}


void
init_misc()
{
    if (_fd != 0)
	return;

#if defined(PM_USE_SOCKET)
    if ((_fd = socket(PF_INET, SOCK_RAW, IPPROTO_PM)) < 0)
	perror("pma: socket"), exit(errno);
#else
    if ((_fd = open("/dev/pmd", O_RDONLY)) < 0)
	perror("pma: /dev/pmd"), exit(errno);
#endif

    {
	int	iter, mask;

	bzero(mtobits, sizeof(mtobits));
	mask = 0x80000000;
	for (iter = 1; iter <= 32; iter++)
	{
	    mtobits[iter] = (u_long)mask;
	    mask >>= 1;
	}
    }

#if (_BSDI_VERSION >= 199701) || defined(__FreeBSD__)
    if (getifaddrs(&ifaddrs) < 0)
	perror("getifaddrs");
#else
    if (getifaddrs(&ifaddrs, &nip) < 0)
	perror("getifaddrs");
#endif
}
