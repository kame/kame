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
 *	$Id: misc.c,v 1.4 2000/02/03 10:10:16 fujisawa Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/in6.h>
#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include "defs.h"
#include "extern.h"
#include "natptconfig.y.h"
#include "miscvar.h"


/*
 *
 */


int	_fd;
u_long	mtobits[33];


/*
 *
 */

void
setInterface(char *ifname, int inex)
{
    struct msgBox	 mBox;

    bzero(&mBox, sizeof(msgBox));
    strcpy(mBox.m_ifName, ifname);
    mBox.flags = inex;

    if (soctl(_fd, SIOCSETIF, &mBox) < 0)
	err(errno, "setInterface: soctl failure");
}


void
getInterface()
{
}


void
setFaithPrefix(struct addrinfo *prefix, int masklen)
{
    struct msgBox	 mBox;
    struct addrCouple	*freight;

    bzero(&mBox, sizeof(struct msgBox));

    mBox.flags = PREFIX_FAITH;
    mBox.size = sizeof(struct addrCouple);
    mBox.freight
	= (caddr_t)(freight = (struct addrCouple *)malloc(mBox.size));
    bzero(freight, mBox.size);

    freight->addr[0].in6 = ((struct sockaddr_in6 *)prefix->ai_addr)->sin6_addr;

    if (masklen <= 0)
	masklen = in6_prefix2len(&((struct sockaddr_in6 *)prefix->ai_addr)->sin6_addr);
    freight->addr[1].in6 = *in6_len2mask(masklen);

    if(soctl(_fd, SIOCSETPREFIX, &mBox) < 0)
	err(errno, "setFaithPrefix: soctl failure");
}


void
setNatptPrefix(struct addrinfo *prefix, int masklen)
{
    struct msgBox	 mBox;
    struct addrCouple	*freight;

    bzero(&mBox, sizeof(struct msgBox));

    mBox.flags = PREFIX_NATPT;
    mBox.size = sizeof(struct addrCouple);
    mBox.freight
	= (caddr_t)(freight = (struct addrCouple *)malloc(mBox.size));
    bzero(freight, mBox.size);

    freight->addr[0].in6 = ((struct sockaddr_in6 *)prefix->ai_addr)->sin6_addr;

    if (masklen <= 0)
	masklen = in6_prefix2len(&((struct sockaddr_in6 *)prefix->ai_addr)->sin6_addr);
    freight->addr[1].in6 = *in6_len2mask(masklen);

    if (soctl(_fd, SIOCSETPREFIX, &mBox) < 0)
	err(errno, "setNatptPrefix: soctl failure");
}


void
setRule(int dir, struct addrCouple *from, struct addrinfo *to, int *port)
{
    int			 type;
    struct msgBox	 mBox;
    struct _cSlot	*freight;

    if ((from->type == ADDR_SINGLE)
	&& (port == NULL))
	type = NATPT_STATIC;
    else
	type = NATPT_DYNAMIC;

    bzero(&mBox, sizeof(struct msgBox));
    mBox.flags = type;
    mBox.size = sizeof(struct _cSlot);
    mBox.freight
	= (caddr_t)(freight = (struct _cSlot *)malloc(mBox.size));
    bzero(freight, mBox.size);

    freight->c.flags   = type;
    freight->c.adrtype = from->type;
    freight->c.dir     = dir;
    freight->c.lfamily	= from->family;
    freight->local = from->addr[0];
    freight->lmask = from->addr[1];

    freight->c.rfamily = to->ai_family;
    if (to->ai_family == AF_INET)
	freight->remote.in4 = ((struct sockaddr_in *)to->ai_addr)->sin_addr;
    else
	freight->remote.in6 = ((struct sockaddr_in6 *)to->ai_addr)->sin6_addr;

    if (port)
    {
	freight->sport = port[0];
	freight->eport = port[1];
    }

    if (soctl(_fd, SIOCSETRULE, &mBox) < 0)
	err(errno, "setRule: soctl failure");
}


void
setFaithRule(struct addrCouple *from)
{
    struct msgBox	 mBox;
    struct _cSlot	*freight;

    bzero(&mBox, sizeof(struct msgBox));
    mBox.flags = NATPT_FAITH;
    mBox.size  = sizeof(struct _cSlot);
    mBox.freight
	= (caddr_t)(freight = (struct _cSlot *)malloc(mBox.size));
    bzero(freight, mBox.size);
    
    freight->c.flags = NATPT_FAITH;
    freight->c.adrtype = from->type;

    freight->c.lfamily = from->family;
    freight->local = from->addr[0];
    freight->lmask = from->addr[1];

    if (soctl(_fd, SIOCSETRULE, &mBox) < 0)
	err(errno, "setFaithRule: soctl failure");
}


void
flushRule(int type)
{
    struct msgBox	 mBox;

    bzero(&mBox, sizeof(struct msgBox));

    switch (type)
    {
      case NATPT_STATIC:	mBox.flags = NATPT_STATIC;			break;
      case NATPT_DYNAMIC:	mBox.flags = NATPT_DYNAMIC;			break;
      default:			mBox.flags = (NATPT_STATIC | NATPT_DYNAMIC);	break;
    }
    
    if (soctl(_fd, SIOCFLUSHRULE, &mBox) < 0)
	err(errno, "flushRule: soctl failure");
}


void
enableTranslate(int flag)
{
    switch (flag)
    {
      case SENABLE:
	if (soctl(_fd, SIOCENBTRANS) < 0)
	    err(errno, "enableTranslate: soctl failure");
	break;

      case SDISABLE:
	if (soctl(_fd, SIOCDSBTRANS) < 0)
	    err(errno, "enableTranslate: soctl failure");
	break;
    }
}


void
setValue(char *name, int val)
{
    int			type = 0;
    struct msgBox	mBox;

    bzero(&mBox, sizeof(struct msgBox));

    if (strcmp(name, "debug") == 0)		type =NATPT_DEBUG;

    if (type == 0)
	errx(1, "%s: no such variable\n", name);

    mBox.flags = type;
    mBox.size = sizeof(int);
    *((u_int *)mBox.m_aux) = val;

    if (soctl(_fd, SIOCSETVALUE, &mBox) < 0)
	err(errno, "setValue: soctl failre");
}


void
debugBreak()
{
    if (soctl(_fd, SIOCBREAK) < 0)
	err(errno, "debugBreak: soctl failure");
}


int
soctl(int fd, u_long request, ...)
{
    int		rv = 0;
    va_list	ap;

    va_start(ap, request);

    if (!isDebug(D_NOSOCKET))
	rv = ioctl(fd, request, va_arg(ap, void *));

    va_end(ap);

    return (rv);
}


struct addrinfo *
getAddrInfo(int family, char *text)
{
    int			 rv;
    struct addrinfo	 hints;
    struct addrinfo	*res;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = family;

    if ((rv = getaddrinfo(text, NULL, &hints, &res)) != 0)
	errx(errno, "getAddrInfo: %s\n", gai_strerror(rv));

    if (res->ai_addr->sa_family != family)
	errx(1, "getAddrInfo: unexpected address family %d (%d)",
	     res->ai_addr->sa_family, family);
    
    return (res);
}


struct addrCouple *
getAddrBlock(int family, int type, struct addrinfo *one, void *two)
{
    struct sockaddr	*sin;
    struct addrCouple	*block;

    block = malloc(sizeof(struct addrCouple));
    bzero(block, sizeof(struct addrCouple));

    block->family = family;
    block->type	  = type;

    switch (family)
    {
      case AF_INET:
	block->addr[0].in4 = ((struct sockaddr_in *)one)->sin_addr;
	break;

      case AF_INET6:
	block->addr[0].in6 = ((struct sockaddr_in6 *)one)->sin6_addr;
	break;
    }

    switch (type)
    {
      case ADDR_SINGLE:
	break;

      case ADDR_MASK:
	switch (family)
	{
	  case AF_INET:
	    block->addr[1].in4 = *in4_len2mask(*(int *)two);
	    break;

	  case AF_INET6:
	    block->addr[1].in6 = *in6_len2mask(*(int *)two);
	    break;
	}
	break;

      case ADDR_RANGE:
	switch (family)
	{
	  case AF_INET:
	    sin = ((struct addrinfo *)two)->ai_addr;
	    block->addr[1].in4 = ((struct sockaddr_in *)sin)->sin_addr;
	    break;

	  case AF_INET6:
	    sin = ((struct addrinfo *)two)->ai_addr;
	    block->addr[1].in6 = ((struct sockaddr_in6 *)sin)->sin6_addr;
	    break;
	}
	break;
    }

    return (block);
}


int
in6_prefix2len(struct in6_addr *prefix)
{
    int		 plen, byte, bit;
    u_char	*addr;

    plen = sizeof(struct in6_addr) * NBBY;
    addr = (u_char *)prefix;
    for (byte = sizeof(struct in6_addr)-1; byte >= 0; byte--)
	for (bit = 0; bit < NBBY; bit++, plen--)
	    if (addr[byte] & (1 << bit))
		return (plen);

    return (0);
}


int
in4_mask2len(struct in_addr *mask)
{
    int x, y;
    u_char	*cmask = (u_char *)mask;

    for (x = 0; x < sizeof(struct in_addr); x++)
    {
	if (*(cmask+x) != 0xff)
	    break;
    }
    y = 0;
    if (x < sizeof(struct in_addr))
    {
	for (y = 0; y < 8; y++)
	{
	    if ((cmask[x] & (0x80 >> y)) == 0)
		break;
	}
    }
    return (x * 8 + y);
}


int
in6_mask2len(struct in6_addr *mask)
{
    int x, y;

    for (x = 0; x < sizeof(*mask); x++)
    {
	if (mask->s6_addr[x] != 0xff)
	    break;
    }
    y = 0;
    if (x < sizeof(*mask))
    {
	for (y = 0; y < 8; y++)
	{
	    if ((mask->s6_addr[x] & (0x80 >> y)) == 0)
		break;
	}
    }
    return (x * 8 + y);
}


struct in_addr *
in4_len2mask(int masklen)
{
    static	struct in_addr	in4mask;

    in4mask.s_addr = mtobits[masklen];
    return (&in4mask);
}


struct in6_addr *
in6_len2mask(int masklen)
{
    int i;
    static	struct in6_addr	mask;

    bzero(&mask, sizeof(mask));
    for (i = 0; i < masklen / 8; i++)
	mask.s6_addr[i] = 0xff;
    if (masklen % 8)
	mask.s6_addr[i] = (0xff00 >> (masklen % 8)) & 0xff;

    return (&mask);
}


/*
 *
 */

void
debugProbe(char *msg)
{
    warnx("%s", msg);
}


void
close_fd()
{
    close(_fd);
}


void
init_misc()
{
    int		iter, mask;

    if (_fd != 0)
	return ;

    if ((!isDebug(D_NOSOCKET)
	 && (_fd = socket(PF_INET, SOCK_RAW, IPPROTO_AHIP)) < 0))
	err(errno, "init_misc:");

    bzero(mtobits, sizeof(mtobits));
    mask = 0x80000000;
    for (iter = 1; iter <= 32; iter++)
    {
	mtobits[iter] = htonl((u_long)mask);
	mask >>= 1;
    }
}
