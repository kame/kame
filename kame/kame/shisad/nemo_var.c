/*      $KAME: nemo_var.c,v 1.9 2005/06/20 08:37:30 ryuji Exp $  */

/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <syslog.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <net/mipsock.h>

#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include "callout.h"
#include "command.h"
#include "shisad.h"
#include "stat.h"
#include "fsm.h"
#include "config.h"

#ifdef MIP_NEMO 

extern struct config_entry *if_params;

#ifdef MIP_MN
struct nemo_mptable *
nemo_mpt_get(hoainfo, nemoprefix, prefixlen)
	struct mip6_hoainfo *hoainfo;
	struct in6_addr *nemoprefix;
	u_int8_t prefixlen;
{
	struct nemo_mptable *mpt, *mptn;

        for (mpt = LIST_FIRST(&hoainfo->hinfo_mpt_head); 
	     mpt; mpt = mptn) {
		mptn = LIST_NEXT(mpt, mpt_entry);
		
		if (prefixlen != mpt->mpt_prefixlen)
			continue;

		if (mip6_are_prefix_equal(nemoprefix, 
					  &mpt->mpt_prefix, mpt->mpt_prefixlen)) 
			return (mpt);
	}

	return (NULL);
}

struct nemo_mptable *
nemo_mpt_add(hoainfo, nemoprefix, prefixlen, mode)
	struct mip6_hoainfo *hoainfo;
	struct in6_addr *nemoprefix;
	u_int8_t prefixlen;
	int mode;
{
	struct nemo_mptable *newmpt = NULL;

	newmpt = (struct nemo_mptable *)malloc(sizeof(struct nemo_mptable)); 
	if (newmpt == NULL) {
		perror("malloc");
		return (NULL);
	}

	memset(newmpt, 0, sizeof(struct nemo_mptable));

	newmpt->mpt_prefix = *nemoprefix;
	newmpt->mpt_prefixlen = prefixlen;
	newmpt->mpt_hoainfo = hoainfo;
	if (mode == NEMO_ROUTING) {
		syslog(LOG_ERR,
		    "Routing mode is not supported yet\n");
		return (NULL);
	}
	newmpt->mpt_regmode = mode;

	LIST_INSERT_HEAD(&hoainfo->hinfo_mpt_head, newmpt, mpt_entry);

	if (debug)
		syslog(LOG_INFO, "add mobile network prefix %s into hoainfo\n", 
		       ip6_sprintf(&newmpt->mpt_prefix));

	return (newmpt);
}

void
command_show_pt(s, dummy)
	int s;
	char *dummy;
{
	struct nemo_mptable *mpt, *mptn;
        struct mip6_hoainfo *hoainfo = NULL;
	
        for (hoainfo = LIST_FIRST(&hoa_head); hoainfo;
             hoainfo = LIST_NEXT(hoainfo, hinfo_entry)) {
		
		for (mpt = LIST_FIRST(&hoainfo->hinfo_mpt_head); 
		     mpt; mpt = mptn) {
			mptn = LIST_NEXT(mpt, mpt_entry);
			
			command_printf(s, "%s ", ip6_sprintf(&hoainfo->hinfo_hoa));
			command_printf(s, "%s%%%d ", 
				ip6_sprintf(&mpt->mpt_prefix), mpt->mpt_prefixlen);
			command_printf(s, "%s\n", 
				(mpt->mpt_regmode == NEMO_IMPLICIT) ? 
				"implicit" : "explicit");
		}
	}
}

#endif /* MIP_MN */

#ifdef MIP_HA 
struct nemo_hptable *
nemo_hpt_get(prefix, prefixlen, prefered_coa) 
	struct in6_addr *prefix;
	u_int8_t prefixlen;
	struct in6_addr *prefered_coa;
{
	struct nemo_hptable *hpt;

	LIST_FOREACH(hpt, &hpt_head, hpt_entry) {
		if (prefixlen != hpt->hpt_prefixlen)
			continue;
		if (mip6_are_prefix_equal(&hpt->hpt_prefix, prefix, prefixlen)) {
			if ((prefered_coa != NULL) &&
				!IN6_ARE_ADDR_EQUAL(hoa, &hpt->hpt_hoa))
				continue;
			else 
				return (hpt);
		}
	}

	return (NULL);
}

struct nemo_hptable *
nemo_hpt_add(hoa, nemoprefix, prefixlen, mode)
	struct in6_addr *hoa;
	struct in6_addr *nemoprefix;
	u_int8_t prefixlen;
	int mode;
{
	struct nemo_hptable *newpt = NULL;

	newpt = (struct nemo_hptable *)malloc(sizeof(struct nemo_hptable)); 
	if (newpt == NULL) {
		perror("malloc");
		return (NULL);
	}

	memset(newpt, 0, sizeof(struct nemo_hptable));

	newpt->hpt_prefix = *nemoprefix;
	newpt->hpt_prefixlen = prefixlen;
	newpt->hpt_hoa = *hoa;
	if (mode == NEMO_ROUTING) {
		syslog(LOG_ERR,
		    "Routing mode is not supported yet\n");
		return (NULL);
	}
	newpt->hpt_regmode = mode;

	LIST_INSERT_HEAD(&hpt_head, newpt, hpt_entry);

	if (debug)
		syslog(LOG_INFO, "add mobile network prefix %s into PrefixTable\n", 
		       ip6_sprintf(&newpt->hpt_prefix));

	return (newpt);
}


#endif /* MIP_HA */

void
nemo_parse_conf()
{
	struct config_entry *cfe;
	struct config_prefixtable *cfpt;
#ifdef MIP_MN
	struct nemo_mptable *mpt;
	struct mip6_hoainfo *hoainfo = NULL;
#elif defined(MIP_HA)
	struct nemo_hptable *hpt;
#endif /* MIP_MN */
	int mode = NEMO_IMPLICIT;

	if (config_get_prefixtable(&cfe, if_params) != 0) {
		syslog(LOG_INFO,
		    "no prefix table is defined\n");
		return;
	}

	for (; cfe != NULL; cfe = cfe->cfe_next) {
		cfpt = (struct config_prefixtable *)cfe->cfe_ptr;

		switch (cfpt->cfpt_mode) {
		case CFPT_IMPLICIT:
			mode = NEMO_IMPLICIT;
			break;
		case CFPT_EXPLICIT:
			mode = NEMO_EXPLICIT;
			break;
		case CFPT_ROUTING:
			mode = NEMO_ROUTING;
			break;
		}

		/* Insert this mobile prefix information to prefixtable */
#ifdef MIP_MN
		hoainfo = hoainfo_find_withhoa(&cfpt->cfpt_homeaddress);
		if (hoainfo == NULL)
			continue;

		mpt = nemo_mpt_get(hoainfo, &cfpt->cfpt_prefix,
		    cfpt->cfpt_prefixlen);
		if (mpt) {
			/* XXX update entry */
		} else {
			mpt = nemo_mpt_add(hoainfo, &cfpt->cfpt_prefix,
			    cfpt->cfpt_prefixlen,
			    mode);
			if (mpt == NULL) 
				syslog(LOG_ERR,
				    "adding nemoprefix is failed\n");
		}
#endif /* MIP_MN */
#ifdef MIP_HA
		hpt = nemo_hpt_get(&cfpt->cfpt_prefix, cfpt->cfpt_prefixlen, &cfpt->cfpt_homeaddress);
		if (hpt) {
			/* XXX update entry */
		} else {
			if (nemo_hpt_add(&cfpt->cfpt_homeaddress,
				&cfpt->cfpt_prefix, cfpt->cfpt_prefixlen,
				mode ) == NULL)
				syslog(LOG_ERR,
				    "adding nemoprefix to Prefix Table is failed\n");
		}
#endif /* MIP_HA */
	}
}

#endif /* MIP_NEMO */
