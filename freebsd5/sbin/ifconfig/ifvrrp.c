/*	$KAME: ifvrrp.c,v 1.2 2003/03/28 08:00:29 ono Exp $ */

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
#include <net/if_dl.h>
#include <net/route.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "ifconfig.h"

void vrrp_link_getaddr(const char *addr, struct sockaddr *sa);

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

void vrrp_link_getaddr(addr, sa)
	const char *addr;
	struct sockaddr *sa;
{
	char *temp;
	struct sockaddr_dl sdl;

	if ((temp = malloc(strlen(addr) + 1)) == NULL)
		errx(1, "malloc failed");
	temp[0] = ':';
	strcpy(temp + 1, addr);
	sdl.sdl_len = sizeof(sdl);
	link_addr(temp, &sdl);
	free(temp);
	if (sdl.sdl_alen > sizeof(sa->sa_data))
		errx(1, "malformed link-level address");
	sa->sa_family = AF_LINK;
	sa->sa_len = sdl.sdl_alen;
	bcopy(LLADDR(&sdl), sa->sa_data, sdl.sdl_alen);
}

void setvrrpdev(val, lladdr, s, afp)
	const char     *val, *lladdr;
	int			   s;
	const struct afswtch	*afp;
{
	struct vrrpreq vr;

	memset(&vr, 0, sizeof(vr));
	ifr.ifr_data = (caddr_t)&vr;

	if ((vr.vr_parent_index = if_nametoindex(val)) == 0) {
		err(1, "if_nametoindex");
	}
	
	vrrp_link_getaddr(lladdr, &vr.vr_lladdr);
		
	if (ioctl(s, SIOCSETVRRP, (caddr_t)&ifr) == -1)
		err(1, "SIOCSETVRRP");

	return;
}

void unsetvrrpdev(val, d, s, afp)
	const char		*val;
	int			d, s;
	const struct afswtch	*afp;
{
	struct vrrpreq vr;

	memset(&vr, 0, sizeof(vr));

	ifr.ifr_data = (caddr_t)&vr;
	vr.vr_parent_index = 0;

	if (ioctl(s, SIOCSETVRRP, (caddr_t)&ifr) == -1)
		err(1, "SIOCSETVRRP");

	return;
}
