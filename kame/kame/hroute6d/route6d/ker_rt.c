/* 
 * $Id: ker_rt.c,v 1.1 1999/08/08 23:29:47 itojun Exp $
 */

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

/* 
 * Copyright(C)1997 by Hitachi, Ltd.
 * Hitachi Id: ker_rt.c,v 1.2 1997/12/22 09:56:47 sumikawa Exp $
 */

#include "defs.h"

/* 
 * Func : rt_ioctl
 * Desc : to add, delete and modify route in kernel's routing table.
 */
int
rt_ioctl(struct rt_plen *plen, u_char cmd)
{
	char *cp;
	int tmp;
#define vSX ROUNDUP(sizeof(struct sockaddr_in6))
#define vDX ROUNDUP(sizeof(struct sockaddr_dl))
	struct {
		struct rt_msghdr w_rtm;
		char w_space[vSX + vSX + vSX + vDX];
	} w;
#undef vDX
#undef vSX
	struct sockaddr_in6 *w_dst;
	struct sockaddr_in6 *w_gate;
	struct sockaddr_in6 *w_netmask;
	struct sockaddr_dl *w_sdl;

#ifdef NINSTALL
	return 0;
#endif

	if ((cmd == RTM_ADD) && (kernel_routes > MAX_KERNEL_ROUTES6)) {
		syslog(LOG_ERR, "rt_ioctl: too many routes");
		return 0;
	}
	if (IN6_IS_ADDR_V4MAPPED(&plen->rp_leaf->key) ||
	    IN6_IS_ADDR_V4COMPAT(&plen->rp_leaf->key))
		return 0;

	bzero((char *)&w, sizeof(w));

#define rtm w.w_rtm
	rtm.rtm_pid = rt6_pid;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = cmd;
	rtm.rtm_flags = plen->rp_flags;
	rtm.rtm_seq = ++seqno;	/* who cares ? */
	rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP;
#undef rtm

	cp = w.w_space;
	w_dst = (struct sockaddr_in6 *)cp;
	w_dst->sin6_family = AF_INET6;
	w_dst->sin6_len = sizeof(struct sockaddr_in6);
	w_dst->sin6_addr = plen->rp_leaf->key;
	ADVANCE(cp, (struct sockaddr *)w_dst);

	w_gate = (struct sockaddr_in6 *)cp;
	w_gate->sin6_family = AF_INET6;
	w_gate->sin6_len = sizeof(struct sockaddr_in6);
	w_gate->sin6_addr = plen->rp_gway->gw_addr;
	ADVANCE(cp, (struct sockaddr *)w_gate);

	w_netmask = (struct sockaddr_in6 *)cp;
	w_netmask->sin6_family = AF_INET6;
	if (IN6_IS_ADDR_UNSPECIFIED(&w_dst->sin6_addr) &&
	    plen->rp_len == MAX_PREFLEN) {
		w_netmask->sin6_len = 0;	/* 'default' */
	} else {
		w_netmask->sin6_len = sizeof(struct sockaddr_in6);
		get_mask(plen->rp_len, (char *)(w_netmask->sin6_addr.s6_addr));
	}
	ADVANCE(cp, (struct sockaddr *)w_netmask);

	w_sdl = (struct sockaddr_dl *)cp;
	*w_sdl = plen->rp_gway->gw_ifp->if_sdl;	/* struct copy */
	ADVANCE(cp, (struct sockaddr *)w_sdl);

	w.w_rtm.rtm_msglen = cp - (char *)&w;

	tmp = write(rt6_sock, (char *)&w, w.w_rtm.rtm_msglen);
	if (tmp > 0) {
		if (cmd == RTM_ADD)
			kernel_routes++;
		else
			kernel_routes--;
	}

	return tmp;
}
