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
 *	$Id: showsubs.c,v 1.1 2000/02/19 00:02:05 fujisawa Exp $
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

#include <netinet6/natpt_defs.h>

#include <arpa/inet.h>

#include "showsubs.h"


/*
 *
 */

static void	_composeAddrPort	__P((struct logmsg *, struct pAddr *));
static void	_composeAddrPort4	__P((struct logmsg *, struct pAddr *));
static void	_composeAddrPort6	__P((struct logmsg *, struct pAddr *));

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


/*
 *
 */

#ifdef NATPTCONFIG

void
log(int priority, char *fmt, ...)
{
    va_list	ap;
    char	Wow[BUFSIZ];

    va_start(ap, fmt);
    vsprintf(Wow, fmt, ap);

    fprintf(stdout, "%s", Wow),
    fprintf(stdout, "\n");

    va_end(ap);
}

#endif
