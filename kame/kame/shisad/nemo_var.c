/*      $KAME: nemo_var.c,v 1.2 2004/12/21 02:21:16 keiichi Exp $  */
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
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif /* __FreeBSD__ >= 3 */
#include <net/route.h>
#include <net/mipsock.h>

#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include "callout.h"
#include "shisad.h"
#include "stat.h"
#include "fsm.h"

#ifdef MIP_NEMO 

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
	char *mode;
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

	if (strncmp(mode, "implicit", strlen("implicit")) == 0)
		newmpt->mpt_regmode = NEMO_IMPLICIT;
	else if (strncmp(mode, "explicit", strlen("explicit")) == 0)
		newmpt->mpt_regmode = NEMO_EXPLICIT;
	else
		newmpt->mpt_regmode = NEMO_ROUTING; /* XXX */

	LIST_INSERT_HEAD(&hoainfo->hinfo_mpt_head, newmpt, mpt_entry);

	if (debug)
		syslog(LOG_INFO, "add mobile network prefix %s into hoainfo\n", 
		       ip6_sprintf(&newmpt->mpt_prefix));

	return (newmpt);
}

void
command_show_pt(s)
	int s;
{
	char buff[2048];
	struct nemo_mptable *mpt, *mptn;
        struct mip6_hoainfo *hoainfo = NULL;
	
        for (hoainfo = LIST_FIRST(&hoa_head); hoainfo;
             hoainfo = LIST_NEXT(hoainfo, hinfo_entry)) {
		
		for (mpt = LIST_FIRST(&hoainfo->hinfo_mpt_head); 
		     mpt; mpt = mptn) {
			mptn = LIST_NEXT(mpt, mpt_entry);
			
			sprintf(buff, "%s ", ip6_sprintf(&hoainfo->hinfo_hoa));
			sprintf(buff + strlen(buff), "%s%%%d ", 
				ip6_sprintf(&mpt->mpt_prefix), mpt->mpt_prefixlen);
			sprintf(buff + strlen(buff), "%s\n", 
				(mpt->mpt_regmode == NEMO_IMPLICIT) ? 
				"implicit" : "explicit");
			
			write(s, buff, strlen(buff));
		}
	}
}

#endif /* MIP_MN */

#ifdef MIP_HA 
struct nemo_hptable *
nemo_hpt_get(prefix, prefixlen) 
	struct in6_addr *prefix;
	u_int8_t prefixlen;
{
	struct nemo_hptable *hpt;

	LIST_FOREACH(hpt, &hpt_head, hpt_entry) {
		if (prefixlen != hpt->hpt_prefixlen)
			continue;
		if (mip6_are_prefix_equal(&hpt->hpt_prefix, prefix, prefixlen))
			return (hpt);
	}

	return (NULL);
}

struct nemo_hptable *
nemo_hpt_add(hoa, nemoprefix, prefixlen, mode)
	struct in6_addr *hoa;
	struct in6_addr *nemoprefix;
	u_int8_t prefixlen;
	char *mode;
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

	if (strncmp(mode, "implicit", strlen("implicit")) == 0)
		newpt->hpt_regmode = NEMO_IMPLICIT;
	else if (strncmp(mode, "explicit", strlen("explicit")) == 0)
		newpt->hpt_regmode = NEMO_EXPLICIT;
	else {
		syslog(LOG_ERR, "Routing Update is not supported\n");
		free(newpt);
		return (NULL);
	}

	LIST_INSERT_HEAD(&hpt_head, newpt, hpt_entry);

	if (debug)
		syslog(LOG_INFO, "add mobile network prefix %s into PrefixTable\n", 
		       ip6_sprintf(&newpt->hpt_prefix));

	return (newpt);
}


#endif /* MIP_HA */

void
nemo_parse_conf(filename)
	char *filename;
{
        FILE *file;
        int i=0;
        char buf[256], *spacer, *head;
#ifdef MIP_MN
	struct nemo_mptable *mpt;
	struct mip6_hoainfo *hoainfo = NULL;
#elif defined(MIP_HA)
	struct nemo_hptable *hpt;
#endif /* MIP_MN */

	char *option[NEMO_OPTNUM];
        /*
         * option[0]: HoA 
         * option[1]: Mobile Network Prefix
         * option[2]: Mobile Network Prefix Length
         * option[3]: Registration mode
         * option[4]: Binding Unique Identifier (optional)
         * option[5]: Home Agent Address (optional)
         */
	struct nemoprefixinfo {
		struct in6_addr hoa;
		struct in6_addr nemopfx;
		int nemopfxlen;
		char *mode;
#ifdef MIP_MCOA
		u_int16_t bid;
#endif /* MIP_MCOA */
		struct in6_addr ha;
	} npinfo;

	file = fopen((filename) ? filename : NEMOPREFIXINFO, "r");
        if(file == NULL) {
                perror("fopen");
                exit(0);
        }

        memset(buf, 0, sizeof(buf));
        while((fgets(buf, sizeof(buf), file)) != NULL){

		/* ignore comments */
		if (strchr(buf, '#') != NULL) 
			continue;
		if (strchr(buf, ' ') == NULL) 
			continue;
		
		/* parsing all options */
		for (i = 0; i < NEMO_OPTNUM; i++)
			option[i] = '\0';
		head = buf;
		for (i = 0, head = buf; 
		     (head != NULL) && (i < NEMO_OPTNUM); 
		     head = ++spacer, i ++) {

			spacer = strchr(head, ' ');
			if (spacer) {
				*spacer = '\0';
				option[i] = head;
			} else {
				option[i] = head;
				break;
			}
		}

		if (debug) {
			syslog(LOG_INFO, "parsing nemoconfig file\n");
			for (i = 0; i < (NEMO_OPTNUM - 2); i ++)  
				syslog(LOG_INFO, "\t%d=%s\n", i, option[i]);
#ifdef MIP_MCOA
			if (option[NEMO_OPTNUM - 2]) /* because of optional one */
				syslog(LOG_INFO, "\t%d=%s\n", i, option[NEMO_OPTNUM - 1]);
#endif /* MIP_MCOA */
			if (option[NEMO_OPTNUM - 1]) /* because of optional one */
				syslog(LOG_INFO, "\t%d=%s\n", i, option[NEMO_OPTNUM - 1]);
		}

		memset(&npinfo, 0, sizeof(npinfo));
                if (inet_pton(AF_INET6, option[0], &npinfo.hoa) < 0) {
                        fprintf(stderr, "%s is not correct address\n", option[0]);
                        continue;
		}

                if (inet_pton(AF_INET6, option[1], &npinfo.nemopfx) < 0) {
                        fprintf(stderr, "%s is not correct address\n", option[1]);
                        continue;
		}
		npinfo.nemopfxlen = atoi(option[2]);
		npinfo.mode = option[3];


#ifdef MIP_MCOA
		if (option[4]) {
			npinfo.bid = atoi(option[4]);
		} else 
			npinfo.bid = 0;
#endif /* MIP_MCOA */

		if (option[5]) {
                	if (inet_pton(AF_INET6, option[5], &npinfo.ha) < 0) {
                       	 	fprintf(stderr, "%s is not correct address\n", option[5]);
				continue;
			 }
		}

		/* Insert this npinfo to prefixtable */
#ifdef MIP_MN
		hoainfo = hoainfo_find_withhoa(&npinfo.hoa);
		if (hoainfo == NULL)
			continue;

		mpt = nemo_mpt_get(hoainfo, &npinfo.nemopfx, npinfo.nemopfxlen);
		if (mpt) {
			/* XXX update entry */
		} else {
			mpt = nemo_mpt_add(hoainfo, &npinfo.nemopfx, 
					 npinfo.nemopfxlen, npinfo.mode);
			if (mpt == NULL) 
				syslog(LOG_ERR, "adding nemoprefix is failed\n");
			else {	
				if(option[5]) 
					mpt->mpt_ha = npinfo.ha;
			}
		}
#elif defined(MIP_HA)
		hpt = nemo_hpt_get(&npinfo.nemopfx, npinfo.nemopfxlen);
		if (hpt) {
			/* XXX update entry */
		} else {
			if (nemo_hpt_add(&npinfo.hoa, &npinfo.nemopfx, 
					 npinfo.nemopfxlen, npinfo.mode) == NULL) 
				syslog(LOG_ERR, "adding nemoprefix to Prefix Table is failed\n");
		}
#endif /* MIP_MN */
			
		memset(buf, 0, sizeof(buf));
	}

	fclose(file);
	return;
}


#endif /* MIP_NEMO */
