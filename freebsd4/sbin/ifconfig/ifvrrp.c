/*
 * Copyright (c) 1999
 *	Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/ifconfig/ifvlan.c,v 1.2 1999/08/28 00:13:09 peter Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>

#include <stdlib.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_vrrp_var.h>
#include <net/route.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "ifconfig.h"

#ifndef lint
static const char rcsid[] =
  "$FreeBSD: src/sbin/ifconfig/ifvlan.c,v 1.2 1999/08/28 00:13:09 peter Exp $";
#endif

void vrrp_status(s, info)
	int			s;
	struct rt_addrinfo *info __unused;
{
	char ifname[IF_NAMESIZE];
	unsigned int ifindex = 0;

	ifr.ifr_data = (caddr_t)&ifindex;

	if (ioctl(s, SIOCGETVRRP, (caddr_t)&ifr) == -1)
		return;

	printf("\tvrrp parent interface: %s\n",
	    ifindex ? if_indextoname(ifindex, ifname) : "<none>");

	return;
}

void setvrrpdev(val, d, s, afp)
	const char		*val;
	int			d, s;
	const struct afswtch	*afp;
{
	unsigned int ifindex = 0;
	
	ifr.ifr_data = (caddr_t)&ifindex;

#if 0
	if (ioctl(s, SIOCGETVRRP, (caddr_t)&ifr) == -1)
		err(1, "SIOCGETVRRP");
#endif

	if ((ifindex = if_nametoindex(val)) == 0)
		err(1, "if_nametoindex");
	
	if (ioctl(s, SIOCSETVRRP, (caddr_t)&ifr) == -1)
		err(1, "SIOCSETVRRP");

	return;
}

void unsetvrrpdev(val, d, s, afp)
	const char		*val;
	int			d, s;
	const struct afswtch	*afp;
{
	unsigned int ifindex = 0;

	ifr.ifr_data = (caddr_t)&ifindex;
#if 0
	if (ioctl(s, SIOCGETVRRP, (caddr_t)&ifr) == -1)
		err(1, "SIOCGETVRRP");
#endif

	if (ioctl(s, SIOCSETVRRP, (caddr_t)&ifr) == -1)
		err(1, "SIOCSETVRRP");

	return;
}
