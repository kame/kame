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
 *	$Id: showsubs.c,v 1.3 2000/04/19 08:09:01 fujisawa Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#define	TCPSTATES	1
#include <netinet/tcp_fsm.h>

#include <netinet6/natpt_defs.h>

#include <arpa/inet.h>

#include "defs.h"
#include "showsubs.h"


/*
 *
 */

static void	_composeAddrPort	__P((struct logmsg *, struct pAddr *));
static void	_composeAddrPort4	__P((struct logmsg *, struct pAddr *));
static void	_composeAddrPort6	__P((struct logmsg *, struct pAddr *));
static void	_composeAddrPortXL	__P((struct logmsg *, struct pAddr *, int));
static void	_composeAddrPortXL4	__P((struct logmsg *, struct pAddr *, int));
static void	_composeAddrPortXL6	__P((struct logmsg *, struct pAddr *, int));
static void	_composeAddrPortXL6long	 __P((struct logmsg *, struct in6_addr *, u_short));
static void	_composeAddrPortXL6short __P((struct logmsg *, struct in6_addr *, u_short));

void		concat			__P((struct logmsg *, char *, ...));


#ifdef NATPTCONFIG
void		log			__P((int, char *, ...));

#endif


/*
 *
 */

struct logmsg *
composeCSlotEntry(struct _cSlot *slt)
{
    struct logmsg	*lmsg;

    lmsg = (struct logmsg *)malloc(BUFSIZ);
    bzero(lmsg, BUFSIZ);

    lmsg->lmsg_size = BUFSIZ;
    lmsg->lmsg_last = &lmsg->lmsg_data[0];

    switch (slt->dir)
    {
      case NATPT_UNSPEC:	concat(lmsg, "unspec");		break;
      case NATPT_INBOUND:	concat(lmsg, "inbound");	break;
      case NATPT_OUTBOUND:	concat(lmsg, "outbound");	break;
      case NATPT_BIDIRECTIONAL:	concat(lmsg, "bidir");		break;
      default:			concat(lmsg, "unknown");	break;
	break;
    }

    concat(lmsg, " from ");
    if (slt->dir != NATPT_INBOUND)
	_composeAddrPort(lmsg, &slt->local);
    else
	_composeAddrPort(lmsg, &slt->remote);

    concat(lmsg, " to " );
    if (slt->dir != NATPT_INBOUND)
	_composeAddrPort(lmsg, &slt->remote);
    else
	_composeAddrPort(lmsg, &slt->local);

    return (lmsg);
}


struct logmsg *
composeTSlotEntry(struct _tSlot *slot, struct _tcpstate *ts, int type)
{
    int			 rv;
    int			 idle;
    struct logmsg	*lmsg;
    struct timeval	 tp;
    struct timezone	 tzp;

    lmsg = (struct logmsg *)malloc(BUFSIZ);
    bzero(lmsg, BUFSIZ);

    lmsg->lmsg_size = BUFSIZ;
    lmsg->lmsg_last = &lmsg->lmsg_data[0];

    switch (slot->ip_payload)
    {
      case IPPROTO_ICMP:	concat(lmsg, "icmp  ");	break;
      case IPPROTO_TCP:		concat(lmsg, "tcp   ");	break;
      case IPPROTO_UDP:		concat(lmsg, "udp   ");	break;
      default:			concat(lmsg, "unk   ");	break;
    }

    _composeAddrPortXL(lmsg, &slot->local,  type);
    _composeAddrPortXL(lmsg, &slot->remote, type);

    concat(lmsg, "%6d%6d ", slot->inbound, slot->outbound);

    rv = gettimeofday(&tp, &tzp);
    idle = tp.tv_sec - slot->tstamp;
    concat(lmsg, "%02d:%02d:%02d ", idle/3600, (idle%3600)/60, idle%60);

    switch (slot->ip_payload)
    {
      case IPPROTO_ICMP:
	concat(lmsg, "%5d/%-5d ", slot->suit.ih_idseq.icd_id, slot->suit.ih_idseq.icd_seq);
	break;

      case IPPROTO_TCP:
	if ((ts->_state >= 0) && (ts->_state < TCP_NSTATES))
	    concat(lmsg, "%s ", tcpstates[ts->_state]);
	else
	    concat(lmsg, "%d ", ts->_state);
	break;
    }

    return (lmsg);
}


/*
 *
 */

static void
_composeAddrPort(struct logmsg *lmsg, struct pAddr *apt)
{
    if (apt->sa_family == AF_INET)
	_composeAddrPort4(lmsg, apt);
    else
	_composeAddrPort6(lmsg, apt);
}


static void
_composeAddrPort4(struct logmsg *lmsg, struct pAddr *apt)
{
    char	Wow[128];

    if (apt->ad.type == ADDR_ANY)
	concat(lmsg, "any4");
    else
	concat(lmsg, "%s", inet_ntop(AF_INET, &apt->in4Addr, Wow, sizeof(Wow)));

    if (apt->ad.prefix != 0)
	concat(lmsg, "/%d", apt->ad.prefix);
    else if (apt->in4RangeEnd.s_addr != 0)
	concat(lmsg, " - %s", inet_ntop(AF_INET, &apt->in4RangeEnd, Wow, sizeof(Wow)));

    if (apt->port[0] != 0)
    {
	concat(lmsg, " port %d", ntohs(apt->port[0]));
	if (apt->port[1] != 0)
	    concat(lmsg, " - %d", ntohs(apt->port[1]));
    }
}


static void
_composeAddrPort6(struct logmsg *lmsg, struct pAddr *apt)
{
    struct in6_addr	in6addr = IN6ADDR_ANY_INIT;
    char		Wow[128];

    if (IN6_ARE_ADDR_EQUAL(&apt->in6Addr, &in6addr))
	concat(lmsg, "any6");
    else
	concat(lmsg, "%s", inet_ntop(AF_INET6, &apt->in6Addr, Wow, sizeof(Wow)));

    if (apt->ad.prefix != 0)
	concat(lmsg, "/%d", apt->ad.prefix);

    if (apt->port[0] != 0)
    {
	concat(lmsg, " port %d", ntohs(apt->port[0]));
	if (apt->port[1] != 0)
	    concat(lmsg, " - %d", ntohs(apt->port[1]));
    }
}


static void
_composeAddrPortXL(struct logmsg *lmsg, struct pAddr *apt, int type)
{
    if (apt->sa_family == AF_INET)
	_composeAddrPortXL4(lmsg, apt, type);
    else
	_composeAddrPortXL6(lmsg, apt, type);
}


static void
_composeAddrPortXL4(struct logmsg *lmsg, struct pAddr *apt, int type)
{
    char	Bow[128];
    char	Wow[128];

    inet_ntop(AF_INET, &apt->in4src, Bow, sizeof(Bow));
    sprintf(Wow, "%s.%d", Bow, ntohs(apt->_sport));
    concat(lmsg, "%-22s", Wow);

    inet_ntop(AF_INET, &apt->in4dst, Bow, sizeof(Bow));
    sprintf(Wow, "%s.%d", Bow, ntohs(apt->_dport));
    concat(lmsg, "%-22s", Wow);
}


static void
_composeAddrPortXL6(struct logmsg *lmsg, struct pAddr *apt, int type)
{
    if (type == LONG)
    {
	_composeAddrPortXL6long(lmsg, &apt->in6src, apt->_sport);
	_composeAddrPortXL6long(lmsg, &apt->in6dst, apt->_dport);
	
    }
    else
    {
	_composeAddrPortXL6short(lmsg, &apt->in6src, apt->_sport);
	_composeAddrPortXL6short(lmsg, &apt->in6dst, apt->_dport);
    }
}


static void
_composeAddrPortXL6long(struct logmsg *lmsg, struct in6_addr *addr, u_short port)
{
    char	Bow[128];
    char	Wow[128];

    inet_ntop(AF_INET6, addr, Bow, sizeof(Bow));
    sprintf(Wow, "%s.%d", Bow, ntohs(port));
    concat(lmsg, "%-45s", Wow);
}


static void
_composeAddrPortXL6short(struct logmsg *lmsg, struct in6_addr *addr, u_short port)
{
    int		 iter;
    char	*s, *d;
    char	 Bow[128];
    char	 Wow[128];
    char	 miaow[128];

    bzero(miaow, sizeof(miaow));
    bzero(Bow,   sizeof(Bow));
    inet_ntop(AF_INET6, addr, miaow, sizeof(miaow));

    if (strlen(miaow) <= 15)
    {
	strcpy(Bow, miaow);
    }
    else
    {
	s = miaow;
	d = Bow;
	for (iter = 0; iter <= 3; iter++)	*d++ = *s++;
	*d++ = '=';
	while (*s++ != '\0')			;
	s -= 10;
	for (iter = 0; iter <= 9; iter++)	*d++ = *s++;
    }

    sprintf(Wow, "%s.%d", Bow, ntohs(port));
    concat(lmsg, "%-22s", Wow);
}


/*
 *
 */

void
concat(struct logmsg *lmsg, char *fmt, ...)
{
    va_list	 ap;
    char	*s, *d;
    char	 Wow[BUFSIZ];
    
    va_start(ap, fmt);
    vsprintf(Wow, fmt, ap);

    s = Wow;
    d = lmsg->lmsg_last;
    while (*s)	*d++ = *s++;
    lmsg->lmsg_last = d;

    va_end(ap);
}
