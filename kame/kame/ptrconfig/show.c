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
//#	$Id: show.c,v 1.1 1999/08/08 23:31:16 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#define	TCPSTATES	1
#include <netinet/tcp_fsm.h>

#include <netinet6/in6.h>
#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_soctl.h>

#include <arpa/inet.h>

#include "defs.h"
#include "extern.h"
#include "showvar.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

extern	int	_fd;

#if defined(__bsdi__)
#define	EXECFILE	"/bsd"
#else
#define	EXECFILE	"/kernel"
#endif	/* defined(__bsdi__)	*/

#if defined(readKMEM)

#include <kvm.h>

kvm_t	*kd;

static	struct nlist	nl[] =
{
    { "_ptrStatic" },
    { "_ptrDynamic" },
    { "_tSlotEntry" },
    { NULL }
};
#endif	/* defined(readKMEM)	*/


static void	_showIPaddr		__P((struct ipaddr *));

static void	_showXlate		__P((int));
static void	_showXlateHeterogeneous	__P((struct _tSlot *));
static void	_showXlateHomogeneous	__P((struct _tSlot *));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
doPtrShowInterface(char *ifName)
{
    int			rv;
    struct msgBox	mBox;

    bzero(&mBox, sizeof(struct msgBox));
    if (ifName)
	strcpy(mBox.m_aux, ifName);

    rv = ioctl(_fd, SIOCGETIF, &mBox);
}


void
doPtrShowRule(int type)
{
    struct _cell	 cons;
    char		*n_name = "_ptrStatic";
    int			 num = 0;
    int			 pos;
    int			 rv;

    if (type == PTR_DYNAMIC)
	n_name = "_ptrDynamic";

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), n_name)) <= 0)
	return ;
    
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(struct _cell), pos);
	if (cons.car)
	{
	    struct _cSlot	acs;

	    StandardOut("%3d: ", num++);
	    readKvm((caddr_t)&acs, sizeof(struct _cSlot), (int)cons.car);
	    StandardOut("from ");
	    _showIPaddr(&acs.local);
	    StandardOut(" to ");
	    _showIPaddr(&acs.remote);

	    StandardOut("\n");
	}
	pos = (int)cons.cdr;
    }
}


void
doPtrShowXlate(int interval)
{
    int		 pos;
    int		 rv;

    while (TRUE)
    {
	if ((rv = readNL((caddr_t)&pos, sizeof(pos), "_tSlotEntry")) <= 0)
	    return ;

	if (pos == 0)
	    StandardOut("No active xlate\n");
	else
	    _showXlate(pos);

	if (interval <= 0)
	    break ;

	sleep(interval);
    }

    closeKvm();
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static void
_showIPaddr(struct ipaddr *adr)
{
    char	Wow[128];

    StandardOut("%s", inet_ntop(adr->sa_family, &adr->u.in4, Wow, sizeof(Wow)));
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


static void
_showXlate(int pos)
{
    Cell	 cons;
    int		 rv;
    char	 Wow[BUFSIZ];

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
	    StandardOut("%-6s", p);

	    if (tslot.local.ip_p != tslot.remote.ip_p)
		_showXlateHeterogeneous(&tslot);
	    else
		_showXlateHomogeneous(&tslot);

	    rv = gettimeofday(&tp, &tzp);
	    idle = tp.tv_sec - tslot.tstamp;
	    StandardOut("%02d:%02d:%02d", idle / 3600, (idle % 3600)/60, idle % 60);

	    switch (tslot.ip_payload)
	    {
	      case IPPROTO_ICMP:
		{
		    StandardOut(" %5d/%-5d",
				tslot.suit.ih_idseq.icd_id,
				tslot.suit.ih_idseq.icd_seq);
		}
		break;

	      case IPPROTO_TCP:
		{
		    struct _tcpstate	ts;

		    readKvm((caddr_t)&ts, sizeof(struct _tcpstate), (int)tslot.suit.tcp);

		    if ((ts._state >= 0) && (ts._state < TCP_NSTATES))
			StandardOut(" %s ", tcpstates[ts._state]);
		    else
			StandardOut(" %d ", ts._state);
		}
		break;
	      
	    }

	    StandardOut("\n");
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
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(readKMEM)
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
#endif	/* defined(readKMEM)	*/

