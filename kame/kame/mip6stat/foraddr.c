/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 and 2000 WIDE Project.
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
 * Copyright (c) 1999 and 2000 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Magnus Braathen <magnus.braathen@era.ericsson.se>
 *
 * $Id: foraddr.c,v 1.2 2000/02/08 02:58:56 itojun Exp $
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <netdb.h>
#include <string.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include "mip6stat.h"

void pr_foraddrhdr __P((void));
void pr_foraddrentry __P((struct mip6_static_addr));

void
foraddrpr(u_long mip6conf_ptr)
{
	u_long foraddr_ptr;
	struct mip6_config mip6config;
	struct mip6_static_addr foraddrentry;

	if (mip6conf_ptr == 0) {
		printf("symbol not in namelist\n");
		return;
	}

	kget(mip6conf_ptr, mip6config);

	printf("Static address list:\n");

	foraddr_ptr = (u_long)mip6config.fna_list.lh_first;

	pr_foraddrhdr();

	for (/*empty*/; foraddr_ptr;
	     foraddr_ptr = (u_long)foraddrentry.addr_entry.le_next) {
		kget(foraddr_ptr, foraddrentry);
		pr_foraddrentry(foraddrentry);
	}
}

/*
 * Print header for the table columns.
 */
void
pr_foraddrhdr()
{
	printf("%-*.*s %6.6s\n", WID_IP6P, WID_IP6P, "Static address", "Netif");
}

void
pr_foraddrentry(struct mip6_static_addr foraddrentry)
{
	char *cp;
	char iface[IFNAMSIZ + 3] = { 0 };
#if !(defined(__OpenBSD__) || defined(__NetBSD__))
	char if_name[IFNAMSIZ] = { 0 };
#endif
	struct ifnet ifs;

	cp = ip6addr_print(&foraddrentry.ip6_addr, foraddrentry.prefix_len);

	if (nflag)
		printf("%-*s ", WID_IP6P, cp);
	else
		printf("%-*.*s ", WID_IP6P, WID_IP6P, cp);

	if (foraddrentry.ifp) {
#if defined(__OpenBSD__) || defined(__NetBSD__)
		strncpy(iface, ifs.if_xname, sizeof(iface));
		iface[sizeof(iface) - 1] = '\0';
#else
		kget(foraddrentry.ifp, ifs);
		if (ifs.if_name)
			kgetp(ifs.if_name, if_name);
		sprintf(iface, "%s%d", if_name, ifs.if_unit);
#endif
	}
	printf("%6.6s", iface);
	printf("\n");
}
