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
 *	$Id: show.c,v 1.14 2001/05/05 11:50:07 fujisawa Exp $
 */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <paths.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include <arpa/inet.h>

#include "defs.h"
#include "miscvar.h"
#include "showvar.h"
#include "showsubs.h"


/*
 *
 */

#ifdef readKMEM

#include <kvm.h>

kvm_t	*kd;

static	struct nlist	nl[] =
{
    { "__cell_used" },
    { "__cell_free" },
    { "_tSlotEntryUsed" },
    { "_tSlotEntryMax" },
    { "_natptStatic" },
    { "_natptDynamic" },
    { "_tSlotEntry" },
    { "_natpt_initialized" },
    { "_natpt_debug" },
    { "_natpt_dump" },
    { "_natpt_prefix" },
    { "_natpt_prefixmask" },
    { "_ip6_protocol_tr" },
    { NULL }
};
#endif	/* ifdef readKMEM	*/


static void	_showRuleStatic		__P((int, struct _cSlot *));
static void	_showRuleDynamic	__P((int, struct _cSlot *));
static void	_showXlate		__P((int, u_long));
static void	_writeXlateHeader	__P((void));

/*
 *
 */

void
showInterface(char *ifName)
{
    struct natpt_msgBox	mBox;

    extern	int		_fd;

    bzero(&mBox, sizeof(struct natpt_msgBox));
    if (ifName)
	strcpy(mBox.m_aux, ifName);

    if (soctl(_fd, SIOCGETIF, &mBox) < 0)
	err(errno, "showInterface: soctl failure");
}


void
showPrefix()
{
    int			rv;
    struct in6_addr	prefix;
    struct in6_addr	prefixmask;

    if ((rv = readNL((caddr_t)&prefix, sizeof(prefix), "_natpt_prefix")) > 0)
    {
	if (rv != sizeof(struct in6_addr))
	    errx(1, "failure on read prefix");
	else
	{
	    char	in6txt[INET6_ADDRSTRLEN];

	    inet_ntop(AF_INET6, (char *)&prefix, in6txt, INET6_ADDRSTRLEN);
	    printf("prefix: %s\n", in6txt);
	}
    }

    if ((rv = readNL((caddr_t)&prefixmask, sizeof(prefixmask), "_natpt_prefixmask")) > 0)
    {
	if (rv != sizeof(struct in6_addr))
	    errx(1, "failure on read prefixmask");
	else
	{
	    char	in6txt[INET6_ADDRSTRLEN];

	    inet_ntop(AF_INET6, (char *)&prefixmask, in6txt, INET6_ADDRSTRLEN);
	    printf("prefixmask: %s ", in6txt);
	    printf("prefixlen %d\n", in6_mask2len(&prefixmask));
	}
    }
}


void
showRule(int type)
{
    struct _cell	 cons;
    char		*n_name = "_natptStatic";
    int			 num = 0;
    u_long		 pos;
    int			 rv;

    if (type == NATPT_DYNAMIC)
	n_name = "_natptDynamic";

    if ((rv = readNL((caddr_t)&pos, sizeof(pos), n_name)) <= 0)
	return ;
    
    while (pos)
    {
	readKvm((caddr_t)&cons, sizeof(struct _cell), pos);
	if (cons.car)
	{
	    struct _cSlot	acs;

	    readKvm((void *)&acs, sizeof(struct _cSlot), (u_long)cons.car);
	    switch (acs.type)
	    {
	      case NATPT_STATIC:	_showRuleStatic(num, &acs);	break;
	      case NATPT_DYNAMIC:	_showRuleDynamic(num, &acs);	break;
	    }
	}
	num++;
	pos = (u_long)cons.cdr;
    }
}


void
showVariables()
{
    u_int	value;

    if (readNL((caddr_t)&value, sizeof(value), "_tSlotEntryUsed") > 0)
	printf("%12s: 0x%08x (%d)\n", "tSlotEntryUsed", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "_tSlotEntryMax") > 0)
	printf("%12s: 0x%08x (%d)\n", "tSlotEntryMax", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "__cell_used") > 0)
	printf("%12s: 0x%08x (%d)\n", "cell_used", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "__cell_free") > 0)
	printf("%12s: 0x%08x (%d)\n", "cell_free", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "_ip6_protocol_tr") > 0)
	printf("%12s: 0x%08x (%d)\n", "ipn6_protocol_tr", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "_natpt_initialized") > 0)
	printf("%12s: 0x%08x (%d)\n", "natpt_initialized", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "_natpt_debug") > 0)
	printf("%12s: 0x%08x (%d)\n", "natpt_debug", value, value);

    if (readNL((caddr_t)&value, sizeof(value), "_natpt_dump") > 0)
	printf("%12s: 0x%08x (%d)\n", "natpt_dump",  value, value);
}


void
showMapping()
{
    int		rv;
    int		map;

    if ((rv = readNL((caddr_t)&map, sizeof(map), "_ip6_protocol_tr")) > 0)
    {
	if (rv != sizeof(int))
	    errx(1, "failure on read ip6_protocol_tr");
	else
	{
	    printf("mapping: %s\n", (map != 0) ? "enable" : "disable");
	}
    }
}


void
showCSlotEntry(struct _cSlot *cslot)
{
    struct logmsg	*lmsg = composeCSlotEntry(cslot);

    printf("%s", (char *)&lmsg->lmsg_data[0]);
    free(lmsg);
}


void
showXlate(int type, int interval)
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
	    _showXlate(type, pos);

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
_showRuleStatic(int num, struct _cSlot *acs)
{
    printf("%3d: ", num);

    showCSlotEntry(acs);

    printf("\n");
}


static void
_showRuleDynamic(int num, struct _cSlot *acs)
{
    printf("%3d: ", num);

    showCSlotEntry(acs);

    printf("\n");
}


static void
_showXlate(int type, u_long pos)
{
    Cell	 cons;

    _writeXlateHeader();

    while (pos)
    {
	readKvm((void *)&cons, sizeof(Cell), pos);
	if (cons.car)
	{
	    struct logmsg	*lmsg;
	    struct _tSlot	 tslot;
	    struct _tcpstate	 ts;

	    readKvm((void *)&tslot, sizeof(struct _tSlot), (u_long)cons.car);
	    if (tslot.ip_payload == IPPROTO_TCP)
		readKvm((void *)&ts, sizeof(struct _tcpstate), (u_long)tslot.suit.tcp);

	    lmsg = composeTSlotEntry(&tslot, &ts, type);

	    printf("%s\n", (char *)&lmsg->lmsg_data[0]);
	    free(lmsg);
	}
	pos = (u_long)cons.cdr;
    }
}


static void
_writeXlateHeader()
{
    printf("%-6s",  "Proto");
    printf("%-22s", "Local Address (src)");
    printf("%-22s", "Local Address (dst)");
    printf("%-22s", "Remote Address (src)");
    printf("%-22s", "Remote Address (dst)");
    printf("%6s",  "Ipkts");
    printf("%6s",  "Opkts");
    printf(" ");

    printf("%-8s",  "  Idle");
    printf("%-8s",  " (state)");
    printf("\n");
}


/*
 *
 */

#ifdef readKMEM
int
readNL(void *buf, int nbytes, char *n_name)
{
    int			 rv;
    struct nlist	*nlp;

    if ((kd == NULL) && ((rv = openKvm()) < 0))
	return (0);

    for (nlp = nl; nlp->n_name; nlp++)
    {
	if ((strlen(nlp->n_name) == strlen(n_name))
	    && (strncmp(nlp->n_name, n_name, strlen(n_name)) == SAME))
	    return (readKvm(buf, nbytes, nlp->n_value));
    }

    return (0);
}


u_long
openKvm()
{
    int		rv;

    if ((kd = kvm_open(NULL, NULL, NULL, O_RDONLY, "kvm_open")) <= (kvm_t *)0)
	err(errno, "Open failure on kvm_open");

    if ((rv = kvm_nlist(kd, nl)) < 0)
	err(errno, "Read failure on kvm_nlist");

    return ((u_long)kd);
}


int
readKvm(void *buf, int nbytes, u_long pos)
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
