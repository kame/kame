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
 *	$Id: show.c,v 1.3 2000/02/06 09:51:47 itojun Exp $
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#define	TCPSTATES	1
#include <netinet/tcp_fsm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include <arpa/inet.h>

#include "defs.h"
#include "extern.h"
#include "miscvar.h"
#include "showvar.h"


/*
 *
 */

extern	int	_fd;

#ifdef __bsdi__
#define	EXECFILE	"/bsd"
#else
#define	EXECFILE	"/kernel"
#endif	/* ifdef __bsdi__	*/

#ifdef readKMEM

#include <kvm.h>

kvm_t	*kd;

static	struct nlist	nl[] =
{
    { "_ptrStatic" },
    { "_ptrDynamic" },
    { "_tSlotEntry" },
    { "_natpt_debug" },
    { "_natpt_prefix" },
    { "_natpt_prefixmask" },
    { "_ip6_protocol_tr" },
    { NULL }
};
#endif	/* ifdef readKMEM	*/


static void	_showRuleStatic		__P((int, struct _cSlot *));
static void	_showRuleDynamic	__P((int, struct _cSlot *));
static void	_showRuleFaith		__P((int, struct _cSlot *));

static void	_showIPaddrCouple	__P((int, int, union inaddr *));
static void	_showIPaddr		__P((int, union inaddr *));

static void	_showXlate		__P((int));
static void	_showXlateHeterogeneous	__P((struct _tSlot *));
static void	_showXlateHomogeneous	__P((struct _tSlot *));


/*
 *
 */

void
showInterface(char *ifName)
{
    struct msgBox	mBox;

    extern	int		_fd;

    bzero(&mBox, sizeof(struct msgBox));
    if (ifName)
	strcpy(mBox.m_aux, ifName);

    if (soctl(_fd, SIOCGETIF, &mBox) < 0)
	err(errno, "showInterface: soctl failre");
}


void
showPrefix()
{
    int			rv;
    struct in6_addr	prefix;
    struct in6_addr	prefixmask;

    if ((rv = readNL((caddr_t)&prefix, sizeof(prefix), "_natpt_prefix")) <= 0)
	return ;

    if (rv != sizeof(struct in6_addr))
	errx(1, "failure on read prefix");
    else
    {
	char	in6txt[INET6_ADDRSTRLEN];
    
	inet_ntop(AF_INET6, (char *)&prefix, in6txt, INET6_ADDRSTRLEN);
	printf("prefix: %s\n", in6txt);
    }

    if ((rv = readNL((caddr_t)&prefixmask, sizeof(prefixmask), "_natpt_prefixmask")) <= 0)
	return ;

    if (rv != sizeof(struct in6_addr))
	errx(1, "failure on read prefixmask");
    else
    {
	char	in6txt[INET6_ADDRSTRLEN];
    
	inet_ntop(AF_INET6, (char *)&prefixmask, in6txt, INET6_ADDRSTRLEN);
	printf("prefixmask: %s\n", in6txt);
    }
}


void
showRule(int type)
{
    struct _cell	 cons;
    char		*n_name = "_ptrStatic";
    int			 num = 0;
    int			 pos;
    int			 rv;

    if (type == NATPT_DYNAMIC)
	n_name = "_ptrDynamic";

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), n_name)) <= 0)
	return ;
    
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(struct _cell), pos);
	if (cons.car)
	{
	    struct _cSlot	acs;

	    readKvm((caddr_t)&acs, sizeof(struct _cSlot), (int)cons.car);
	    switch (acs.c.flags)
	    {
	      case NATPT_STATIC:	_showRuleStatic(num, &acs);	break;
	      case NATPT_DYNAMIC:	_showRuleDynamic(num, &acs);	break;
	      case NATPT_FAITH:		_showRuleFaith(num, &acs);	break;
	    }
	}
	pos = (int)cons.cdr;
    }
}


void
showVariables()
{
    int		rv;
    int		debug;

    if ((rv = readNL((caddr_t)&debug, sizeof(debug), "_natpt_debug")) <= 0)
	return ;

    printf("debug: 0x%08x (%d)\n", debug, debug);
}


void
showMapping()
{
    int		rv;
    int		map;

    if ((rv = readNL((caddr_t)&map, sizeof(map), "_ip6_protocol_tr")) <= 0)
	return ;

    if (rv != sizeof(int))
	errx(1, "failure on read ip6_protocol_tr");
    else
    {
	printf("mapping: %s\n", (map != 0) ? "enable" : "disable");
    }
}


static void
_showRuleStatic(int num, struct _cSlot *acs)
{
    printf("%3d: ", num++);

    printf("from ");
    _showIPaddr(acs->c.lfamily, &acs->local);
    printf(" to ");
    _showIPaddr(acs->c.rfamily, &acs->remote);

    printf("\n");
}


static void
_showRuleDynamic(int num, struct _cSlot *acs)
{
    printf("%3d: ", num++);

    switch (acs->c.dir)
    {
      case NATPT_UNSPEC:	printf("unspec");	break;
      case NATPT_INBOUND:	printf("inbound");	break;
      case NATPT_OUTBOUND:	printf("outbound");	break;
      default:			printf("unknown");	break;
	break;
    }

    printf(" from ");
    _showIPaddrCouple(acs->c.lfamily, acs->c.adrtype, &acs->local);
    printf(" to ");
    _showIPaddr(acs->c.rfamily, &acs->remote);

    if (acs->sport || acs->eport)
    {
	printf(" port %d - %d", acs->sport, acs->eport);
    }

    printf("\n");
}


static void
_showRuleFaith(int num, struct _cSlot *acs)
{
    printf("%3d: ", num++);

    printf("from ");
    _showIPaddrCouple(acs->c.lfamily, acs->c.adrtype, &acs->local);
    printf(" to ");
    _showIPaddr(acs->c.rfamily, &acs->remote);

    printf("\n");
}


void
showXlate(int interval)
{
    int		 pos;
    int		 rv;

    while (TRUE)
    {
	if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_tSlotEntry")) <= 0)
	    return ;

	if (pos == 0)
	    printf("No active xlate\n");
	else
	    _showXlate(pos);

	if (interval <= 0)
	    break ;

	sleep(interval);
    }

    closeKvm();
}


/*
 *
 */

static void
_showIPaddrCouple(int family, int type, union inaddr *addr)
{
    switch (type)
    {
      case ADDR_ANY:
	printf("any");
	break;

      case ADDR_SINGLE:
	_showIPaddr(family, addr);
	break;

      case ADDR_MASK:
	_showIPaddr(family, addr);
	printf("/%d", in6_prefix2len(&(addr+1)->in6));
	break;

      case ADDR_RANGE:
	_showIPaddr(family, &addr[0]);
	_showIPaddr(family, &addr[1]);
	break;
    }
}


static void
_showIPaddr(int family, union inaddr *addr)
{
    char	Wow[128];

    printf("%s", inet_ntop(family, addr, Wow, sizeof(Wow)));
}


#define	_writeXlateHeader()					\
		{						\
		    printf("%-6s",  "Proto");			\
		    printf("%-21s", "Local Address");		\
		    printf("%-22s", "Foreign Address");		\
		    printf("%-21s", "Remote Address");		\
		    printf("%6s",  "Ipkts");			\
		    printf("%6s",  "Opkts");			\
		    printf(" ");				\
								\
		    printf("%-8s",  "  Idle");			\
		    printf("%-8s",  " (state)");		\
		    printf("\n");				\
		}


static void
_showXlate(int pos)
{
    Cell	 cons;
    int		 rv;
#if	0
    char	 Wow[BUFSIZ];
#endif

    _writeXlateHeader();

    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    struct _tSlot	 tslot;
	    struct timeval	 tp;
	    struct timezone	 tzp;
	    int			 idle;
	    char		*p;

	    readKvm((caddr_t)&tslot, sizeof(struct _tSlot), (int)cons.car);

	    switch (tslot.ip_payload)
	    {
	      case IPPROTO_ICMP: p = "icmp"; break;
	      case IPPROTO_UDP:  p = "udp" ; break;
	      case IPPROTO_TCP:  p = "tcp" ; break;
	      default:		 p = "unk" ; break;
	    }
	    printf("%-6s", p);

	    if (tslot.local.ip_p != tslot.remote.ip_p)
		_showXlateHeterogeneous(&tslot);
	    else
		_showXlateHomogeneous(&tslot);

	    rv = gettimeofday(&tp, &tzp);
	    idle = tp.tv_sec - tslot.tstamp;
	    printf("%02d:%02d:%02d", idle / 3600, (idle % 3600)/60, idle % 60);

	    switch (tslot.ip_payload)
	    {
	      case IPPROTO_ICMP:
		{
		    printf(" %5d/%-5d",
				tslot.suit.ih_idseq.icd_id,
				tslot.suit.ih_idseq.icd_seq);
		}
		break;

	      case IPPROTO_TCP:
		{
		    struct _tcpstate	ts;

		    readKvm((caddr_t)&ts, sizeof(struct _tcpstate), (int)tslot.suit.tcp);

		    if ((ts._state >= 0) && (ts._state < TCP_NSTATES))
			printf(" %s ", tcpstates[ts._state]);
		    else
			printf(" %d ", ts._state);
		}
		break;
	      
	    }

	    printf("\n");
	}
	pos = (int)cons.cdr;
    }
}


static void
_showXlateHeterogeneous(struct _tSlot *tslot )
{
    char	ntop_buf[INET6_ADDRSTRLEN];
    
    printf("%s.%d ", inet_ntop(tslot->local.src.sa_family, &tslot->local.src.u.in6, ntop_buf, sizeof(ntop_buf)),
	   ntohs(tslot->local.sport));
    printf("%s.%d ", inet_ntop(tslot->local.dst.sa_family, &tslot->local.dst.u.in6, ntop_buf, sizeof(ntop_buf)),
	   ntohs(tslot->local.dport));

    printf("%s.%d ", inet_ntop(tslot->remote.src.sa_family, &tslot->remote.src.u.in6, ntop_buf, sizeof(ntop_buf)),
	   ntohs(tslot->remote.sport));
    printf("%s.%d ", inet_ntop(tslot->remote.dst.sa_family, &tslot->remote.dst.u.in6, ntop_buf, sizeof(ntop_buf)),
	   ntohs(tslot->remote.dport));
}


static void
_showXlateHomogeneous(struct _tSlot *tslot)
{
}


/*
 *
 */

#ifdef readKMEM
int
readNL(caddr_t buf, int nbytes, char *n_name)
{
    int			 rv;
    struct nlist	*nlp;

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

    bzero(Wow, sizeof(Wow));

#ifdef __bsdi__
    bcopy(EXECFILE, Wow, strlen(EXECFILE));
#endif	/*  __bsdi__  */

#ifdef __FreeBSD__
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
	err(errno, "Open failure on kvm_open");

    if ((rv = kvm_nlist(kd, nl)) < 0)
	err(errno, "Read failure on kvm_nlist");

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
	err(errno, "Read failure on kvm_read");

    return (rv);
}


void
closeKvm()
{
    kvm_close(kd);
}
#endif	/* ifdef readKMEM	*/
