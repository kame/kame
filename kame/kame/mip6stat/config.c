/*	$KAME: config.c,v 1.7 2001/03/29 05:34:29 itojun Exp $	*/

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
 * Copyright (c) 1999, 2000 and 2001 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Authors:  Magnus Braathen <magnus.braathen@era.ericsson.se>
 *           Mattias Pettersson <mattias.pettersson@era.ericsson.se>
 */

#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <netdb.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>
#include "mip6stat.h"

void pr_confighdr __P((void));
void pr_configentry __P((struct mip6_config, int, int));

void
configpr(u_long mip6conf_ptr, u_long mip6debug_ptr, u_long mip6module_ptr)
{
	struct mip6_config mip6config;
	int mip6debug, mip6module;

	if (mip6conf_ptr == 0 || mip6debug_ptr == 0 || mip6module_ptr == 0) {
		printf("symbol not in namelist\n");
		return;
	}

	kget(mip6conf_ptr, mip6config);
	kget(mip6debug_ptr, mip6debug);
	kget(mip6module_ptr, mip6module);

	pr_confighdr();

	pr_configentry(mip6config, mip6debug, mip6module);
}

/*
 * Print header for the table columns.
 */
void
pr_confighdr()
{
	printf("\n");
	printf("Mobile IPv6 Configuration:\n");
}

void
pr_configentry(struct mip6_config configentry, int mip6debug, int mip6module)
{
	char *enabled  = "Enabled ";
	char *disabled = "Disabled";

#define BOOLQ(x) ((x) ? enabled : disabled)
	
#if 0
	printf("%s  Home Agent functionality\n", BOOLQ(configentry.enable_ha));
#endif

	printf("%8u  Binding Update lifetime (s)\n", configentry.bu_lifetime);

	printf("%8d  Binding Request update time (s)\n", configentry.br_update);

	printf("%8d  Home Agent preference\n", configentry.ha_pref);

	printf("%8u  Home registration lifetime\n", configentry.hr_lifetime);

	printf("%s  Forwarding of site local unicast destination addresses\n",
	       BOOLQ(configentry.fwd_sl_unicast));

	printf("%s  Forwarding of site local multicast destination addresses\n",
	       BOOLQ(configentry.fwd_sl_multicast));

	printf("%s  Link layer promiscuous mode\n",
	       BOOLQ(configentry.enable_prom_mode));

	printf("%s  Route optimization\n", BOOLQ(configentry.enable_bu_to_cn));

	printf("%s  Reverse tunneling\n", BOOLQ(configentry.enable_rev_tunnel));

	printf("%s  Sending Binding Request\n", BOOLQ(configentry.enable_br));

	printf("%s  Autoconfiguration\n", BOOLQ(configentry.autoconfig));

	switch (configentry.eager_md) {
	case 0:
		printf("%s  ", disabled);
		break;
	case 1:
		printf("Level 1   ");
		break;
	case 2:
		printf("Level 2   ");
		break;
	}
	printf("Eager Movement Detection\n");

	printf("%s  Debugging output\n", BOOLQ(mip6debug));
	switch (mip6module) {
	case MIP6_HA_MODULE:
		printf("Home Agent activated\n");
		break;
	case MIP6_MN_MODULE:
		printf("Mobile Node activated\n");
		break;
	default:
		printf("Only Correspondent Node functionality activated\n");
		break;
	}

	printf("\n");
}
