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
 * $Id: bulist.c,v 1.1 2000/02/07 17:27:09 itojun Exp $
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
#include <netinet6/in6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <string.h>
#include <time.h>
#include <netinet6/mip6.h>
#include "mip6stat.h"

void pr_buhdr __P((void));
void pr_buentry __P((struct mip6_bul));

void
bulistpr(u_long bulist)
{
	u_long bu_ptr;
	struct mip6_bul buentry;

	if (bulist == 0) {
		printf("symbol not in namelist\n");
		return;
	}

	kget(bulist, bu_ptr);

	printf("Binding update list:\n");

	pr_buhdr();

	for (; bu_ptr; bu_ptr = (u_long)buentry.next) {
		kget(bu_ptr, buentry);
		pr_buentry(buentry);
	}
}

/*
 * Print header for the table columns.
 */
void
pr_buhdr()
{
	if (lflag)
		printf("%-*.*s %-*.*s %-*.*s %9.9s %6.6s %8.8s %6.6s %6.6s\n",
			WID_IP6, WID_IP6, "Dst address",
			WID_IP6, WID_IP6, "Home address",
			WID_IP6, WID_IP6, "Care-of address",
			"Life/Rfrh", "Seqno", "Lasttime", "Count", "Flags");
	else
		printf("%-*.*s %-*.*s %9.9s\n",
			WID_IP6, WID_IP6, "Dst address",
			WID_IP6, WID_IP6, "Care-of address",
			"Life/Ref");
}

void
pr_buentry(struct mip6_bul buentry)
{
	char *cp;
	char timebuf[64];
	struct tm *tm;

	cp = ip6addr_print(&buentry.dst_addr, -1);

	if (nflag)
		printf("%-*s ", WID_IP6, cp);
	else
		printf("%-*.*s ", WID_IP6, WID_IP6, cp);

	if (lflag) {
		cp = ip6addr_print(&buentry.bind_addr, -1);
		if (nflag)
			printf("%-*s ", WID_IP6, cp);
		else
			printf("%-*.*s ", WID_IP6, WID_IP6, cp);
	}

	cp = ip6addr_print(&buentry.coa, -1);
	if (nflag)
		printf("%-*s ", WID_IP6, cp);
	else
		printf("%-*.*s ", WID_IP6, WID_IP6, cp);

	printf("%4u/%-4u ", buentry.lifetime, buentry.refreshtime);

	if (lflag) {
		char flags[5] = { 0 };

		printf("%6d ", buentry.seqno);

		tm = localtime(&buentry.lasttime);
		strftime(timebuf, sizeof(timebuf), "%A", tm);

		printf("%8.8s ", timebuf);
		printf("%6d ", buentry.no_of_sent_bu);

		if (buentry.bu_flag)
			strcat(flags, "H");
		if (buentry.hr_flag)
			strcat(flags, "U");

		printf("%6.6s", flags);
	}

	printf("\n");
}
