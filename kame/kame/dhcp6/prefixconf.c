/*	$KAME: prefixconf.c,v 1.2 2002/05/17 07:26:32 jinmei Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
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
#include <sys/queue.h>
#include <sys/ioctl.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <netinet/in.h>

#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>

#include "dhcp6.h"
#include "common.h"
#include "config.h"

#ifdef notyet
struct dhcp6_prefix {
	struct sockaddr_in6 paddr;
	int plen;
	u_int32_t lease;
	time_t updated; /* timestamp of last update */
	struct duid server_id;	/* server ID advertising the prefix */
};
#endif

/* should be moved to a header file later */
struct dhcp6_ifprefix {
	struct sockaddr_in6 paddr;
	int plen;

	/* address assigned on the interface based on the prefix */
	struct sockaddr_in6 ifaddr;
};

static int ifaddrconf __P((struct dhcp6_ifprefix *, struct prefix_ifconf *));

int
add_ifprefix(prefix, pconf)
	struct dhcp6_prefix *prefix;
	struct prefix_ifconf *pconf;
{
	struct dhcp6_ifprefix *ifpfx = NULL;
	struct in6_addr *a;
	u_long sla_id;
	char *sp;
	int b, i;

	ifpfx = (struct dhcp6_ifprefix *)malloc(sizeof(*ifpfx));
	memset(ifpfx, 0, sizeof(*ifpfx));

	ifpfx->paddr.sin6_family = AF_INET6;
	ifpfx->paddr.sin6_len = sizeof(struct sockaddr_in6);
	ifpfx->paddr.sin6_addr = prefix->addr;
	ifpfx->plen = prefix->plen + pconf->sla_len;
	/*
	 * XXX: our current implementation assumes ifid len is a multiple of 8
	 */
	if ((pconf->ifid_len % 8) != 0) {
		dprintf(LOG_NOTICE, "add_ifprefix: "
			"assumption failure on the length of interface ID");
		goto bad;
	}
	if (ifpfx->plen + pconf->ifid_len < 0 ||
	    ifpfx->plen + pconf->ifid_len > 128) {
		dprintf(LOG_INFO, "add_ifprefix: "
			"invalid prefix length %d + %d + %d",
			prefix->plen, ifpfx->plen, pconf->ifid_len);
		goto bad;
	}

	/* copy prefix and SLA ID */
	a = &ifpfx->paddr.sin6_addr;
	b = prefix->plen;
	for (i = 0, b = prefix->plen; b > 0; b -= 8, i++)
		a->s6_addr[i] = prefix->addr.s6_addr[i];
	sla_id = htonl(pconf->sla_id);
	sp = ((char *)&sla_id + 3);
	i = (128 - pconf->ifid_len) / 8;
	for (b = pconf->sla_len; b > 7; b -= 8, sp--)
		a->s6_addr[--i] = *sp;
	if (b)
		a->s6_addr[--i] |= *sp;

	/* configure the corresponding address */
	ifpfx->ifaddr = ifpfx->paddr;
	for (i = 15; i >= pconf->ifid_len / 8; i--)
		ifpfx->ifaddr.sin6_addr.s6_addr[i] = pconf->ifid[i];
	if (ifaddrconf(ifpfx, pconf))
		goto bad;

	/* TODO: send a control message for other processes */

	/* TODO: link into chain */

	/* TODO: set up a timer for the entry */

	return(0);

  bad:
	if (ifpfx)
		free(ifpfx);
	return(-1);
}

static int
ifaddrconf(ifpfx, pconf)
	struct dhcp6_ifprefix *ifpfx;
	struct prefix_ifconf *pconf;
{
	struct in6_aliasreq req;
	int s;			/* XXX overhead */

	if ((s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		dprintf(LOG_ERR, "ifaddrconf: "
			"can't open a temporary socket: %s",
			strerror(errno));
		return(-1);
	}

	memset(&req, 0, sizeof(req));
	memcpy(req.ifra_name, pconf->ifname, sizeof(req.ifra_name));
	req.ifra_addr = ifpfx->ifaddr;
	(void)sa6_plen2mask(&req.ifra_prefixmask, ifpfx->plen);
	/* XXX: should lifetimes be calculated based on the lease duration? */
	req.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	req.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	if (ioctl(s, SIOCAIFADDR_IN6, &req)) {
		dprintf(LOG_NOTICE,
			"ifaddrconf: failed to add an address on %s: %s",
			pconf->ifname, strerror(errno));
		close(s);
		return(-1);
	}

	dprintf(LOG_DEBUG, "added an address %s on %s",
		addr2str((struct sockaddr *)&ifpfx->ifaddr), pconf->ifname);

	close(s);
	return(0);
}
