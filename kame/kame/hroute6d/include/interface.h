/* 
 * $Id: interface.h,v 1.1.1.1 1999/08/08 23:29:40 itojun Exp $
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
 */

/*
 * Contol infomation for sending a packet through an interface.
 */
struct ctlinfo {
	char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
};
#define ci_cmsg(x) (*(struct cmsghdr *)(x).cbuf)
#define ci_info(x) (*(struct in6_pktinfo *)CMSG_DATA((struct cmsghdr *)(x).cbuf))

/*
 * For linked list of prefixes.
 */
struct preflist {
	struct preflist *pl_next;
	struct prefix    pl_pref;
	struct in6_addr  pl_dest;
	struct in6_addr  pl_mask;
	int		 pl_flag;
};
#define  PL_NEWADDR    1
#define  PL_OLDADDR    2
#define  PL_DELADDR    3

/*
 * This is structure for the interface information maintained by route6d
 */
struct interface {
	struct interface *if_next;
	struct sockaddr_dl if_sdl;	/* for ifpaddr */
	char if_name[IFNAMSIZ];
	struct preflist *if_ip6addr;	/* Address on this host */
	struct preflist *if_sladdr;	/* Site local address on this host */
	struct preflist *if_lladdr;	/* Link local address on this host */
	struct ctlinfo  if_cinfo;	/* Contorl information for interface */
#define if_index(x)   ci_info((x)->if_cinfo).ipi6_ifindex
					/* network byte order ifindex */
	int if_metrc;			/* from RTM_IFINFO */
	int if_flag;			/* Flags used by kernel */
	int if_lmtu;			/* MTU of the link */
	u_long if_badpkt;		/* bad packets counter */
	u_long if_badrte;		/* bad RTEs counter */
	u_long if_updates;		/* number of updates sent */
	struct int_config *if_config;	/* Interface configuration data */
};

#define IFF_JOINED IFF_DEBUG             /* borrow the flag space */
