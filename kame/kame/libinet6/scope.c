/*	$KAME: scope.c,v 1.11 2004/06/15 07:59:39 itojun Exp $ */

/*
 * Copyright (C) 2000 WIDE Project.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>

#ifdef INET6
#include <sys/queue.h>		/* XXX in6_var.h requires this */
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <netinet6/in6_var.h>
#endif

#include <string.h>
#include <unistd.h>
#include <errno.h>

int
addr2scopetype(sa)
	struct sockaddr *sa;
{
#ifdef INET6
	struct sockaddr_in6 *sa6;
#endif
	u_int8_t *addr4;

	switch(sa->sa_family) {
#ifdef INET6
	case AF_INET6:
		sa6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) {
			/* just use the scope field of the multicast address */
			return(sa6->sin6_addr.s6_addr[1] & 0x0f);
		}
		/*
		 * Unicast addresses: map scope type to corresponding scope
		 * value defined for multcast addresses.
		 * XXX: hardcoded scope type values are bad...
		 */
		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			return(2); /* a special type of link-local scope */
		if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr))
			return(2); /* link-local scope */
		if (IN6_IS_ADDR_SITELOCAL(&sa6->sin6_addr))
			return(5); /* site-local scope */
		return(14);	/* global scope */
		break;
#endif
	case AF_INET:
		/*
		 * IPv4 pseudo scoping according to RFC 3484.
		 */
		addr4 = (u_int8_t *)&((struct sockaddr_in *)sa)->sin_addr;
		/* IPv4 autoconfiguration addresses have link-local scope. */
		if (addr4[0] == 169 && addr4[1] == 254)
			return(2);
		/* Private addresses have site-local scope. */
		if (addr4[0] == 10 ||
		    (addr4[0] == 172 && (addr4[1] & 0xf0) == 16) ||
		    (addr4[0] == 192 &&  addr4[1] == 168)) {
			return(5);
		}
		/* Loopback addresses have link-local scope. */
		if (addr4[0] == 127)
			return(2);
		return(14);
		break;
	default:
		errno = EAFNOSUPPORT; /* is this a good error? */
		return(-1);
	}
}

int
inet_zoneid(family, type, ifname, identp)
	int family, type;
	char *ifname;
	u_int32_t *identp;
{
#ifdef INET6
	int s;
	struct in6_ifreq ifreq;
#endif

	switch(family) {
#ifdef INET6
	case AF_INET6:
		if (type < 0 || type > 0x0f) {
			errno = EINVAL;
			return(-1);
		}
		if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
			return(-1);
		memset(&ifreq, 0, sizeof(ifreq));
		strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));

		if (ioctl(s, SIOCGSCOPE6, (caddr_t)&ifreq) < 0) {
			close(s);
			return(-1);
		}
		close(s);
		*identp = ifreq.ifr_ifru.ifru_scope_id[type];
		break;
#endif
	default:
		return(0);	/* XXX */
	}

	return(0);
}
