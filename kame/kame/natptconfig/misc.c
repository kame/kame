/*	$KAME: misc.c,v 1.19 2001/10/29 02:36:48 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include "cfparse.h"
#include "defs.h"
#include "miscvar.h"
#include "showvar.h"


#define	LOGTESTPATTERN	"The quick brown fox jumped over the lazy dog."


int		 sfd;
u_long		 mtobits[33];


/*
 *
 */

void
setPrefix(struct addrinfo *prefix)
{
	const char *fn = __FUNCTION__;

	struct natpt_msgBox	 mBox;

	bzero(&mBox, sizeof(struct natpt_msgBox));
	mBox.m_in6addr = SIN6(prefix->ai_addr)->sin6_addr;

	if (soctl(sfd, SIOCSETPREFIX, &mBox) < 0)
		soctlFailure(fn);

	freeaddrinfo(prefix);
}


void
setRules(int type, struct ruletab *ruletab)
{
	const char *fn = __FUNCTION__;

	struct natpt_msgBox	 mBox;
	struct cSlot		*f;

	bzero(&mBox, sizeof(struct natpt_msgBox));
	mBox.size = sizeof(struct cSlot);
	f = (struct cSlot *)malloc(sizeof(struct cSlot));
	bzero(f, sizeof(struct cSlot));
	mBox.freight = (caddr_t)f;

	switch (type) {
	case NATPT_MAP64:
		if (ruletab->from)
			f->Local = *(ruletab->from);
		else {
			f->Local.sa_family = AF_INET6;
			f->Local.aType = ADDR_ANY;
		}
		f->Remote = *ruletab->to;
		break;

	case NATPT_MAP46:
	case NATPT_MAP44:
		if (ruletab->from)
			f->Local = *ruletab->from;
		else {
			f->Local.sa_family = AF_INET;
			f->Local.aType = ADDR_ANY;
		}
		f->Remote = *ruletab->to;
		break;

	default:
		err(1, "%s(): illegal rule type: %d", fn, type);
		break;
	}

	if (ruletab->sports) {
		f->map = NATPT_REMAP_SPORT;
		f->Remote.pType = ruletab->sports[0];
		f->Remote.port[0] = ruletab->sports[1];
		f->Remote.port[1] = ruletab->sports[2];
	}

	if (ruletab->dports) {
		f->map = NATPT_REDIRECT_PORT;
		f->local.dport = ruletab->dports[0];
		f->remote.dport = ruletab->dports[1];
	}

	if (ruletab->proto) {
		f->proto = ruletab->proto;
	}

	if (ruletab->bidir) {
		f->map |= NATPT_BIDIR;
	}

	f->lifetime = CSLOT_INFINITE_LIFETIME;
	if (soctl(sfd, SIOCSETRULES, &mBox) < 0)
		soctlFailure(fn);
}


void
flushRules(int all)
{
	const char *fn = __FUNCTION__;

	struct natpt_msgBox	 mBox;

	bzero(&mBox, sizeof(struct natpt_msgBox));
	mBox.flags = NATPT_FLUSHALL;

	if (soctl(sfd, SIOCFLUSHRULE, &mBox) < 0)
		soctlFailure(fn);
}


void
setOnOff(int flag)
{
	const char *fn = __FUNCTION__;

	switch (flag) {
	case SENABLE:
		if (soctl(sfd, SIOCENBTRANS) < 0)
			soctlFailure(fn);
		break;

	case SDISABLE:
		if (soctl(sfd, SIOCDSBTRANS) < 0)
			soctlFailure(fn);
		break;
	}
}


void
setValue(char *name, int val)
{
	const char *fn = __FUNCTION__;

	int			type = 0;
	struct natpt_msgBox	mBox;

	bzero(&mBox, sizeof(struct natpt_msgBox));

	if (strcmp(name, "natpt_debug") == 0)		type = NATPT_DEBUG;
	else if (strcmp(name, "natpt_dump") == 0)	type = NATPT_DUMP;

	if (type == 0)
		errx(1, "%s(): %s: no such variable\n", fn, name);

	mBox.flags = type;
	mBox.m_uint = val;

	if (soctl(sfd, SIOCSETVALUE, &mBox) < 0)
		soctlFailure(fn);
}


void
testLog(char *str)
{
	const char *fn = __FUNCTION__;

	int			 slen;
	char			*freight;
	struct natpt_msgBox	 mBox;

	bzero(&mBox, sizeof(struct natpt_msgBox));

	if (str == NULL)
		str = LOGTESTPATTERN;

	slen = ROUNDUP(strlen(str)+1);
	if ((freight = malloc(slen)) == NULL)
		err(errno, "%s():", fn);

	bzero(freight, slen);
	strncpy(freight, str, strlen(str));
	mBox.size = slen;
	mBox.freight = freight;

	if (soctl(sfd, SIOCTESTLOG, &mBox) < 0)
		soctlFailure(fn);
}


void
debugBreak()
{
	const char *fn = __FUNCTION__;

	if (soctl(sfd, SIOCBREAK) < 0)
		soctlFailure(fn);
}


/*
 *
 */

int
soctl(int fd, u_long request, ...)
{
	int		 rv = 0;
	va_list		 ap;

	if (sfd == -1) {
		if ((sfd = socket(PF_INET, SOCK_RAW, IPPROTO_AHIP)) < 0)
			return (-1);
	}

	va_start(ap, request);
	rv = ioctl(sfd, request, va_arg(ap, void *))
		va_end(ap);

	return (rv);
}


void
soctlFailure(const char *fn)
{
	err(errno, "%s(): soctl failure", fn);
}


/*
 *
 */


int
in6_prefix2len(struct in6_addr *prefix)
{
	int	 plen, byte, bit;
	u_char	*addr;

	plen = sizeof(struct in6_addr) * NBBY;
	addr = (u_char *)prefix;
	for (byte = sizeof(struct in6_addr) - 1; byte >= 0; byte--)
		for (bit = 0; bit < NBBY; bit++, plen--)
			if (addr[byte] & (1 << bit))
				return (plen);

	return (0);
}


struct in6_addr *
in6_len2mask(int masklen)
{
	int			i;
	static struct in6_addr	mask;

	bzero(&mask, sizeof(struct in6_addr));
	for (i = 0; i < masklen / 8; i++) {
		mask.s6_addr[i] = 0xff;
	}
	if (masklen & 8)
		mask.s6_addr[i] = (0xff00 >> (masklen % 8)) & 0xff;

	return (&mask);
}


int
in6_mask2len(struct in6_addr *mask)
{
	int x, y;

	for (x = 0; x < sizeof(*mask); x++) {
		if (mask->s6_addr[x] != 0xff)
			break;
	}
	y = 0;
	if (x < sizeof(*mask)) {
		for (y = 0; y < 8; y++)	{
			if ((mask->s6_addr[x] & (0x80 >> y)) == 0)
				break;
		}
	}
	return (x * 8 + y);
}


struct pAddr *
getAddrs(int family, int type, struct addrinfo *addr, void *aux)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;
	struct pAddr		*block;

	block = (struct pAddr *)malloc(sizeof(struct pAddr));
	bzero(block, sizeof(struct pAddr));

	block->sa_family = family;
	switch (family) {
	case AF_INET:
		sin4 = (struct sockaddr_in *)addr->ai_addr;
		block->in4Addr = sin4->sin_addr;
		break;

	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)addr->ai_addr;
		block->in6Addr = sin6->sin6_addr;
		break;
	}

	block->aType = type;
	if (aux) {
		switch (type) {
		case ADDR_SINGLE:
			break;

		case ADDR_MASK:
			if ((family == AF_INET)
			    || (family == AF_INET6)) {
				block->prefix = *(int *)aux;
			}
			break;

		case ADDR_RANGE:
			if (family == AF_INET) {
				block->in4Mask = ((struct sockaddr_in *)aux)->sin_addr;
			}
		}
	}

	return (block);
}


struct addrinfo *
getAddrInfo(int family, char *text)
{
	const char *fn = __FUNCTION__;
	int		 rv;
	struct addrinfo	 hints;
	struct addrinfo *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = family;

	if ((rv = getaddrinfo(text, NULL, &hints, &res)) != 0)
		errx(errno, "%s(): %s", fn, gai_strerror(rv));

	if (res->ai_addr->sa_family != family)
		errx(1, "%s(): unexpected address family %d (%d)",
		     fn, res->ai_addr->sa_family, family);

	return (res);
}


void
clean_misc()
{
	if (sfd != -1)
		close(sfd);
}


void
init_misc()
{
	int	iter, mask;

	sfd = -1;
	bzero(mtobits, sizeof(mtobits));
	mask = 0x80000000;
	for (iter = 1; iter <= 32; iter++) {
		mtobits[iter] = htonl((u_long)mask);
		mask >>= 1;
	}
}
