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
 * $Id: haddr.c,v 1.3 2000/02/19 13:42:45 itojun Exp $
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
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include "mip6stat.h"
#include <string.h>

void pr_hahdr __P((void));
void pr_haentry __P((struct mip6_esm));

void
haddrpr(u_long haddrlist)
{
	u_long          ha_ptr;
	struct mip6_esm haentry;

	if (haddrlist == 0) {
		printf("symbol not in namelist\n");
		return;
	}

	kget(haddrlist, ha_ptr);
	printf("Home address list:\n");
	pr_hahdr();

	for(; ha_ptr; ha_ptr = (u_long)haentry.next) {
		kget(ha_ptr, haentry);
		pr_haentry(haentry);
	}
}

/*
 * Print header for the table columns.
 */
void
pr_hahdr()
{
	if (lflag)
		printf("%-*.*s %-*.*s %-*.*s %6.6s %6.6s %6.6s %8.8s\n",
			WID_IP6P, WID_IP6P, "Home address",
			WID_IP6, WID_IP6, "Home Agent address",
			WID_IP6, WID_IP6, "Care-of address",
			"State", "Netif", "Tunlif", "Lifetime");
	else
		printf("%-*.*s %-*.*s %6.6s %6.6s\n",
			WID_IP6P, WID_IP6P, "Home address",
			WID_IP6, WID_IP6, "Home Agent address",
			"State", "Netif");
}

void
pr_haentry(struct mip6_esm haentry)
{
	char *cp;
	char iface[IFNAMSIZ + 3] = { 0 };
#if 0
	char giface[IFNAMSIZ + 3] = { 0 };
#endif

	cp = ip6addr_print(&haentry.home_addr, haentry.prefix_len);

	if (nflag)
		printf("%-*s ", WID_IP6P, cp);
	else
		printf("%-*.*s ", WID_IP6P, WID_IP6P, cp);

	cp = ip6addr_print(&haentry.ha_hn, -1);
	if (nflag)
		printf("%-*s ", WID_IP6, cp);
	else
		printf("%-*.*s ", WID_IP6, WID_IP6, cp);

	if (lflag) {
		cp = ip6addr_print(&haentry.coa, -1);
		if (nflag)
			printf("%-*s ", WID_IP6, cp);
		else
			printf("%-*.*s ", WID_IP6, WID_IP6, cp);
	}

	switch(haentry.state) {
	case MIP6_STATE_UNDEF:
		printf("%6.6s ", "Undef");
		break;
	case MIP6_STATE_HOME:
		printf("%6.6s ", "Home");
		break;
	case MIP6_STATE_DEREG:
		printf("%6.6s ", "Dereg");
		break;
	case MIP6_STATE_NOTREG:
		printf("%6.6s ", "Notrg");
		break;
	case MIP6_STATE_REG:
		printf("%6.6s ", "Reg'd");
		break;
	case MIP6_STATE_REREG:
		printf("%6.6s ", "Rereg");
		break;
	case MIP6_STATE_REGNEWCOA:
		printf("%6.6s ", "NewCO");
		break;
	default: 
		printf("%6.6s ", "Unkwn");
		break;
	}             

	if (haentry.ifp) {
#if !(defined(__OpenBSD__) || defined(__NetBSD__))
		char if_name[IFNAMSIZ] = { 0 };
#endif
		struct ifnet ifs;

		kget(haentry.ifp, ifs);
#if defined(__OpenBSD__) || defined(__NetBSD__)
		strncpy(iface, ifs.if_xname, sizeof(iface));
		iface[sizeof(iface) - 1] = '\0';
#else
		if (ifs.if_name)
			kgetp(ifs.if_name, if_name);
		sprintf(iface, "%s%d", if_name, ifs.if_unit);
#endif
	}
	printf("%6.6s ", iface);

	if(lflag) {
#if 0
#if !(defined(__OpenBSD__) || defined(__NetBSD__))
		char gif_name[IFNAMSIZ] = { 0 };
#endif
		struct ifnet gif_ifs;

		if(haentry.gif_ifp) {
			kget(haentry.gif_ifp, gif_ifs);
#if defined(__OpenBSD__) || defined(__NetBSD__)
			strncpy(giface, gif_ifs.if_xname, sizeof(giface));
			iface[sizeof(giface) - 1] = '\0';
#else
			if(gif_ifs.if_name)
				kgetp(gif_ifs.if_name, gif_name);
			sprintf(giface, "%s%d", gif_name, gif_ifs.if_unit);
#endif
		}
		printf("%6.6s ", giface);
#endif

		if (haentry.lifetime == 0xFFFF)
			printf("%8x", haentry.lifetime);
		else
			printf("%8u", haentry.lifetime);
	}
	printf("\n");
}
