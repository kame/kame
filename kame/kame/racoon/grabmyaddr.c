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
 */
/* YIPS @(#)$Id: grabmyaddr.c,v 1.6 2000/02/07 12:01:41 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/route.h>
#include <netkey/key_var.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "localconf.h"
#include "grabmyaddr.h"
#include "sockmisc.h"
#include "isakmp_var.h"

static unsigned int if_maxindex __P((void));
static void clear_myaddr __P((struct myaddrs **));

static unsigned int
if_maxindex()
{
	struct if_nameindex *p, *p0;
	unsigned int max = 0;

	p0 = if_nameindex();
	for (p = p0; p && p->if_index && p->if_name; p++) {
		if (max < p->if_index)
			max = p->if_index;
	}
	if_freenameindex(p0);
	return max;
}

static void
clear_myaddr(db)
	struct myaddrs **db;
{
	struct myaddrs *p;

	while (*db) {
		p = (*db)->next;
		delmyaddr(*db);
		*db = p;
	}
}

void
grab_myaddrs()
{
	int s;
	unsigned int maxif;
	int len;
	struct ifreq *iflist;
	struct ifconf ifconf;
	struct ifreq *ifr, *ifr_end;
	struct myaddrs *p;
#ifdef INET6
#ifdef __KAME__
	struct sockaddr_in6 *sin6;
#endif
#endif

#if defined(YIPS_DEBUG)
	char _addr1_[NI_MAXHOST];
#endif

	maxif = if_maxindex() + 1;
	len = maxif * sizeof(*iflist) * 5;	/* guess guess */
	iflist = (struct ifreq *)malloc(len);
	if (!iflist) {
		plog(logp, LOCATION, NULL,
			"not enough core\n");
		exit(1);
		/*NOTREACHED*/
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		plog(logp, LOCATION, NULL,
			"socket(SOCK_DGRAM)\n");
		exit(1);
		/*NOTREACHED*/
	}
	memset(&ifconf, 0, sizeof(ifconf));
	ifconf.ifc_req = iflist;
	ifconf.ifc_len = len;
	if (ioctl(s, SIOCGIFCONF, &ifconf) < 0) {
		plog(logp, LOCATION, NULL,
			"ioctl(SIOCGIFCONF)\n");
		exit(1);
		/*NOTREACHED*/
	}
	close(s);

	clear_myaddr(&lcconf->myaddrs);

	/* Look for this interface in the list */
	ifr_end = (struct ifreq *) (ifconf.ifc_buf + ifconf.ifc_len);
	for (ifr = ifconf.ifc_req;
	     ifr < ifr_end;
	     ifr = (struct ifreq *) ((char *) &ifr->ifr_addr
				    + ifr->ifr_addr.sa_len)) {
		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
#ifdef INET6
		case AF_INET6:
#endif
			p = newmyaddr();
			if (p == NULL) {
				exit(1);
				/*NOTREACHED*/
			}
			p->addr = dupsaddr(&ifr->ifr_addr);
			if (p->addr == NULL) {
				exit(1);
				/*NOTREACHED*/
			}
#ifdef INET6
#ifdef __KAME__
			sin6 = (struct sockaddr_in6 *)p->addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)
			 || IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
				sin6->sin6_scope_id =
					ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
				sin6->sin6_addr.s6_addr[2] = 0;
				sin6->sin6_addr.s6_addr[3] = 0;
			}
#endif
#endif
			YIPSDEBUG(DEBUG_MISC,
				if (getnameinfo(p->addr, p->addr->sa_len,
						_addr1_, sizeof(_addr1_),
						NULL, 0,
						NI_NUMERICHOST | niflags))
					strcpy(_addr1_, "(invalid)");
				plog(logp, LOCATION, NULL,
					"my interface: %s (%s)\n",
					_addr1_, ifr->ifr_name));
			p->next = lcconf->myaddrs;
			lcconf->myaddrs = p;
			break;
		default:
			break;
		}
	}

	free(iflist);
}

int
update_myaddrs()
{
	char msg[BUFSIZ];
	int len;
	struct rt_msghdr *rtm;

	len = read(lcconf->rtsock, msg, sizeof(msg));
	if (len < 0) {
		plog(logp, LOCATION, NULL,
			"read(PF_ROUTE) failed\n");
		return 0;
	}
	if (len < sizeof(*rtm)) {
		plog(logp, LOCATION, NULL,
			"read(PF_ROUTE) short read\n");
		return 0;
	}
	rtm = (struct rt_msghdr *)msg;
	if (rtm->rtm_version != RTM_VERSION) {
		plog(logp, LOCATION, NULL,
			"routing socket version mismatch\n");
		close(lcconf->rtsock);
		lcconf->rtsock = 0;
		return 0;
	}
	switch (rtm->rtm_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_DELETE:
	case RTM_IFINFO:
		break;
	default:
		plog(logp, LOCATION, NULL,
			"msg %d not interesting\n", rtm->rtm_type);
		return 0;
	}
	/* XXX more filters here? */

	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL,
			"need update interface address list\n"));
	return 1;
}

/*
 * initialize default port for ISAKMP to send, if no "listen"
 * directive is specified in config file.
 *
 * DO NOT listen to wildcard addresses.  if you receive packets to
 * wildcard address, you'll be in trouble (DoS attack possible by
 * broadcast storm).
 */
int
autoconf_myaddrsport()
{
	struct myaddrs *p;
	struct sockaddr_in *sin;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif
	int n;

	YIPSDEBUG(DEBUG_INFO,
		plog(logp, LOCATION, NULL,
			"configuring default isakmp port.\n"));
	n = 0;
	for (p = lcconf->myaddrs; p; p = p->next) {
		switch (p->addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)p->addr;
			sin->sin_port = htons(lcconf->port_isakmp);
			break;
#ifdef INET6
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)p->addr;
			sin6->sin6_port = htons(lcconf->port_isakmp);
			break;
#endif
		default:
			plog(logp, LOCATION, NULL,
				"unsupported AF %d\n", p->addr->sa_family);
			goto err;
		}
		n++;
	}
	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL,
			"isakmp_autoconf success, %d addrs\n", n));

	return 0;
err:
	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL,
			"isakmp_autoconf fail\n"));
	return -1;
}

/*
 * get a port number to which racoon binded.
 * NOTE: network byte order returned.
 */
u_short
getmyaddrsport(local)
	struct sockaddr *local;
{
	struct myaddrs *p;

	/* get a relative port */
	for (p = lcconf->myaddrs; p; p = p->next) {
		if (!p->addr)
			continue;
		if (!cmpsaddrwop(local, p->addr))
			return _INPORTBYSA(p->addr);
			continue;
	}

	return htons(PORT_ISAKMP);
}

struct myaddrs *
newmyaddr()
{
	struct myaddrs *new;

	new = CALLOC(sizeof(*new), struct myaddrs *);
	if (new == NULL) {
		plog(logp, LOCATION, NULL,
			"%s\n", strerror(errno)); 
		return NULL;
	}

	new->next = NULL;
	new->addr = NULL;

	return new;
}

void
insmyaddr(new, head)
	struct myaddrs *new;
	struct myaddrs **head;
{
	new->next = *head;
	*head = new;
}

void
delmyaddr(myaddr)
	struct myaddrs *myaddr;
{
	free(myaddr);
}

int
initmyaddr()
{
	/* initialize routing socket */
	lcconf->rtsock = socket(PF_ROUTE, SOCK_RAW, PF_UNSPEC);
	if (lcconf->rtsock < 0) {
		plog(logp, LOCATION, NULL,
			"socket(PF_ROUTE): %s", strerror(errno));
		return -1;
	}

	if (lcconf->myaddrs == NULL && lcconf->autograbaddr == 1) {
		grab_myaddrs();

		if (autoconf_myaddrsport() < 0)
			return -1;
	}

	return 0;
}

