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
//#	$Id: misc.c,v 1.1 1999/08/08 23:31:15 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/in6.h>
#include <netinet6/ptr_defs.h>
#include <netinet6/ptr_soctl.h>

#include "extern.h"
#include "ptrconfig.y.h"
#include "miscvar.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int	_fd;
u_long	mtobits[33];


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
ptr_setInterface(char *ifname, int inex)
{
    int			 rv;
    struct msgBox	 mBox;

    bzero(&mBox, sizeof(msgBox));
    strcpy(mBox.m_ifName, ifname);
    mBox.flags = inex;

    rv = ioctl(_fd, SIOCSETIF, &mBox);
}


void
ptr_getInterface()
{
}


void
doPtrSetFaithPrefix(struct sockaddr *prefix, int masklen)
{
    int			rv;
    struct msgBox	 mBox;
    struct sockaddr_in6	*freight;

    bzero(&mBox, sizeof(struct msgBox));

    mBox.flags = PREFIX_FAITH;
    mBox.size = sizeof(struct sockaddr_in6) * 2;
    freight = (struct sockaddr_in6 *)malloc(mBox.size);
    bzero(freight, mBox.size);

    *(freight+0) = *(struct sockaddr_in6 *)prefix;

    if (masklen <= 0)
	masklen = in6_prefix2len(&((struct sockaddr_in6 *)prefix)->sin6_addr);
    (freight+1)->sin6_addr = *in6_len2mask(masklen);
    mBox.freight = (caddr_t)freight;
    rv = ioctl(_fd, SIOCSETPREFIX, &mBox);
}


void
doPtrSetRule(struct sockaddr *from, struct sockaddr *to)
{
    int			 rv;
    struct msgBox	 mBox;
    struct sockaddr_in6	*freight;

    bzero(&mBox, sizeof(struct msgBox));
    mBox.flags = PTR_STATIC;
    mBox.size = sizeof(struct sockaddr_in6) * 2;
    freight = (struct sockaddr_in6 *)malloc(mBox.size);
    bzero(freight, mBox.size);

    *(freight+0) = *(struct sockaddr_in6 *)from;
    *(freight+1) = *(struct sockaddr_in6 *)to;
    mBox.freight = (caddr_t)freight;

    rv = ioctl(_fd, SIOCSETRULE, &mBox);
}


void
doPtrSetFaithRule(struct sockaddr *from, int masklen)
{
    int			 rv;
    struct msgBox	 mBox;
    struct sockaddr_in	*freight;
    struct sockaddr_in	 mask;

    bzero(&mask, sizeof(struct sockaddr_in));	
    mask.sin_len = sizeof(struct sockaddr_in);
    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = mtobits[masklen];

    bzero(&mBox, sizeof(struct msgBox));
    mBox.flags = PTR_FAITH;
    mBox.size = sizeof(struct sockaddr_in) * 2;
    freight = (struct sockaddr_in *)malloc(mBox.size);
    bzero(freight, mBox.size);

    *(freight+0) = *(struct sockaddr_in *)from;
    *(freight+1) =  mask;
    mBox.freight = (caddr_t)freight;

    rv = ioctl(_fd, SIOCSETRULE, &mBox);
}
		  

void
doPtrFlushRule(int type)
{
    int			 rv;
    struct msgBox	 mBox;

    bzero(&mBox, sizeof(struct msgBox));

    switch (type)
    {
      case PTR_STATIC:	mBox.flags = PTR_STATIC;			break;
      case PTR_DYNAMIC:	mBox.flags = PTR_DYNAMIC;			break;
      default:		mBox.flags = (PTR_STATIC | PTR_DYNAMIC);	break;
    }
    
    rv = ioctl(_fd, SIOCFLUSHRULE, &mBox);
}


void
doPtrEnbTrans(int flag)
{
    int		rv;

    switch (flag)
    {
      case SENABLE:
	rv = ioctl(_fd, SIOCENBTRANS);
	break;

      case SDISABLE:
	rv = ioctl(_fd, SIOCDSBTRANS);
	break;
    }
}


void
doPtrBreak()
{
    int			 rv;

    rv = ioctl(_fd, SIOCBREAK);
}


struct sockaddr *
getsockaddr(int family, char *text)
{
    int			 rv;
    struct addrinfo	 hints;
    struct addrinfo	*res;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = family;

    if ((rv = getaddrinfo(text, NULL, &hints, &res)) != 0)
	FEerror("%s\n", gai_strerror(rv));

    if (res->ai_addr->sa_family != family)
	FEerror("ptrconfig: getsockaddr()\n");

    return (res->ai_addr);
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

#if	0
    int		size = sizeof(struct in6_addr);
    int		 byte, bit, plen = 0;
    u_char	*name = (u_char *)prefix;

    for (byte = 0; byte < size; byte++, plen += 8)
	if (name[byte] != 0xff)
	    break;

    if (byte == size)
	return (plen);

    for (bit = 7; bit != 0; bit--, plen++)
	if (!(name[byte] & (1 << bit)))
	    break;

    for (; bit != 0; bit--)
	if (name[byte] & (1 << bit))
	    return(0);

    byte++;

    for (; byte < size; byte++)
	if (name[byte])
	    return(0);

    return (plen);
#endif
}


int
in6_mask2len(struct in6_addr *mask)
{
    int x, y;

    for (x = 0; x < sizeof(*mask); x++)
    {
	if (mask->s6_addr8[x] != 0xff)
	    break;
    }
    y = 0;
    if (x < sizeof(*mask))
    {
	for (y = 0; y < 8; y++)
	{
	    if ((mask->s6_addr8[x] & (0x80 >> y)) == 0)
		break;
	}
    }
    return (x * 8 + y);
}


struct in6_addr *
in6_len2mask(int len)
{
    int i;
    static	struct in6_addr	mask;

    bzero(&mask, sizeof(mask));
    for (i = 0; i < len / 8; i++)
	mask.s6_addr8[i] = 0xff;
    if (len % 8)
	mask.s6_addr8[i] = (0xff00 >> (len % 8)) & 0xff;

    return (&mask);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
close_fd()
{
    close(_fd);
}


void
init_misc()
{
    if (_fd != 0)
	return ;

    if ((_fd = socket(PF_INET, SOCK_RAW, IPPROTO_PTR)) < 0)
	perror("ptrconfig: socket"), exit(errno);

    {
	int	iter, mask;

	bzero(mtobits, sizeof(mtobits));
	mask = 0x80000000;
	for (iter = 1; iter <= 32; iter++)
	{
	    mtobits[iter] = htonl((u_long)mask);
	    mask >>= 1;
	}
    }
}
