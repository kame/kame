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
 * $Id: bcache.c,v 1.1 2000/02/07 17:27:09 itojun Exp $
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <net/if.h>
#if defined( __FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <netdb.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <string.h>
#include <netinet6/mip6.h>
#include "mip6stat.h"

void pr_bchdr(void);
void pr_bcentry(struct mip6_bc);

/*
 * Print binding cache.
 */
void
bcachepr(u_long bclist)
{
	u_long bc_ptr;
	struct mip6_bc bcentry;

	if (bclist == 0) {
		printf("symbol not in namelist\n");
		return;
	}

	/*printf("bclist %x\n", bclist);*/

	kget(bclist, bc_ptr);

	printf("Binding cache:\n");

	pr_bchdr();

	/*printf("bc_ptr %x\n", bc_ptr);*/

	for (; bc_ptr; bc_ptr = (u_long)bcentry.next) {
		kget(bc_ptr, bcentry);
		pr_bcentry(bcentry);
	}
}

/*
 * Print header for the table columns.
 */
void
pr_bchdr()
{
	if (lflag)
		printf("%-*.*s %-*.*s %6.6s %6.6s %6.6s %6.6s\n",
			WID_IP6, WID_IP6, "Home address",
			WID_IP6, WID_IP6, "Care-of address",
			"Flags", "Seqno", "Netif", "Expire");
	else
		printf("%-*.*s %-*.*s %6.6s\n",
			WID_IP6, WID_IP6, "Home address",
			WID_IP6, WID_IP6, "Care-of address",
			"Expire");
}

void
pr_bcentry(struct mip6_bc bcentry)
{
	char *cp;

	cp = ip6addr_print(&bcentry.home_addr, -1);

	if (nflag)
		printf("%-*s ", WID_IP6, cp);
	else
		printf("%-*.*s ", WID_IP6, WID_IP6, cp);

	cp = ip6addr_print(&bcentry.coa, bcentry.prefix_len);
	if (nflag)
		printf("%-*s ", WID_IP6, cp);
	else
		printf("%-*.*s ", WID_IP6, WID_IP6, cp);

	if (lflag) {
		char flags[5] = { 0 };
		char giface[IFNAMSIZ + 3] = { 0 };
#if !(defined(__OpenBSD__) || defined(__NetBSD__))
		char gif_name[IFNAMSIZ] = { 0 };
#endif
		struct ifnet gif_ifs;

		if(bcentry.hr_flag)
			strcat(flags, "H");
		if(bcentry.rtr_flag)
			strcat(flags, "R");

		printf("%6.6s %6d ", flags, bcentry.seqno);

		if (bcentry.gif_ifp) {
			kget(bcentry.gif_ifp, gif_ifs);
#if defined(__OpenBSD__) || defined(__NetBSD__)
			strncpy(giface, gif_ifs.if_xname, sizeof(giface));
			giface[sizeof(giface) - 1] = '\0';
#else
			if (gif_ifs.if_name)
				kgetp(gif_ifs.if_name, gif_name);
			sprintf(giface, "%s%d", gif_name, gif_ifs.if_unit);
#endif
		}
		printf("%6.6s ", giface);
	}

	printf("%6u ", bcentry.lifetime);

	printf("\n");
}
