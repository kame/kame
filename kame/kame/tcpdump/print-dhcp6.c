/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Format and print bootp packets.
 */
#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /cvsroot/kame/kame/kame/kame/tcpdump/print-dhcp6.c,v 1.1 1999/09/11 04:43:49 itojun Exp $ (LBL)";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "dhcp6.h"

static char tstr[] = " [|dhcp6]";

/*
 * Print dhcp6 requests
 */
void
dhcp6_print(register const u_char *cp, u_int length,
	    u_short sport, u_short dport)
{
	union dhcp6 *dh6;

	printf("dhcp6");

	dh6 = (union dhcp6 *)cp;
	TCHECK(dh6->dh6_msgtype);
	switch (dh6->dh6_msgtype) {
	case DH6_SOLICIT:
		if (vflag && TTEST(dh6->dh6_sol.dh6sol_relayaddr)) {
			printf(" solicit(");
			if ((dh6->dh6_sol.dh6sol_flags & DH6SOL_CLOSE) != 0)
				printf("C");
			if (dh6->dh6_sol.dh6sol_flags != 0)
				printf(" ");
			printf("cliaddr=%s",
				ip6addr_string(&dh6->dh6_sol.dh6sol_cliaddr));
			printf(" relayaddr=%s", 
				ip6addr_string(&dh6->dh6_sol.dh6sol_relayaddr));
			printf(")");
		} else
			printf(" solicit");
		break;
	case DH6_ADVERT:
		if (!(vflag && TTEST(dh6->dh6_adv.dh6adv_serveraddr))) {
			printf(" advert");
			break;
		}
		printf(" advert(");
		if ((dh6->dh6_adv.dh6adv_flags & DH6ADV_SERVPRESENT) != 0)
			printf("S");
		if (dh6->dh6_adv.dh6adv_flags != 0)
			printf(" ");
		printf("pref=%u", dh6->dh6_adv.dh6adv_pref);
		printf(" cliaddr=%s",
			ip6addr_string(&dh6->dh6_adv.dh6adv_cliaddr));
		printf(" relayaddr=%s", 
			ip6addr_string(&dh6->dh6_adv.dh6adv_relayaddr));
		printf(" servaddr=%s", 
			ip6addr_string(&dh6->dh6_adv.dh6adv_serveraddr));
		printf(")");
		break;
	case DH6_REQUEST:
		printf(" request");
		break;
	case DH6_REPLY:
		printf(" reply");
		break;
	case DH6_RELEASE:
		printf(" release");
		break;
	case DH6_RECONFIG:
		printf(" reconfig");
		break;
	}
	return;

trunc:
	printf("%s", tstr);
}
