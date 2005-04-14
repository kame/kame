/*      $KAME: mdd_nemo.c,v 1.2 2005/04/14 06:22:36 suz Exp $  */
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

#ifdef MIP_NEMO

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <netdb.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <ifaddrs.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/if_types.h>
#if 0
#include <net/ethernet.h>
#endif
#include <net/route.h>
#include <net/mipsock.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/in_var.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/ip6mh.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6_var.h>
#include <arpa/inet.h>

#include "mdd.h"

#define NEMOPREFIXINFO "/usr/local/etc/nemoprefix.info"

extern int mip6_are_prefix_equal(struct in6_addr *, struct in6_addr *, int);
extern u_int16_t  get_ifindex_from_address(struct in6_addr *);
extern struct sockaddr_in6 *nemo_ar_get(struct in6_addr *coa, struct sockaddr_in6 *);


#define NEMO_OPTNUM 4


struct nemoprefixinfo *
npi_get(struct in6_addr *mnpfx, int pfxlen) {
        struct nemoprefixinfo *npi, *npin = NULL;

	for (npi = LIST_FIRST(&npi_head); npi; npi = npin) {
		npin = LIST_NEXT(npi, npi_entry);
		if (npi->nemopfxlen != pfxlen)
			continue;
		if (mip6_are_prefix_equal(mnpfx, &npi->nemopfx, npi->nemopfxlen))
			return npi;
	}

	return NULL;
};

struct nemoprefixinfo *
npi_add(struct nemoprefixinfo *new) {
	struct nemoprefixinfo *npi;

	npi = malloc(sizeof(struct nemoprefixinfo));
	if (npi == NULL)
		return NULL;
	memset(npi, 0, sizeof(*npi));
	memcpy(npi, new, sizeof(*npi));

	LIST_INSERT_HEAD(&npi_head, npi, npi_entry);

	return npi;
};

void
npi_delete(struct in6_addr *mnpfx, int pfxlen) {

	return;
};


void
mdd_nemo_parse_conf(filename)
	char *filename;
{
        FILE *file;
        int i=0;
        char buf[256], *spacer, *head;

	char *option[NEMO_OPTNUM];
        /*
	 * option[0]: HoA 
	 * option[1]: Mobile Network Prefix
	 * option[2]: Mobile Network Prefix Length
	 * option[3]: tunnel ifname
	 */
	struct nemoprefixinfo npinfo;

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
		head = buf;
		for (i = 0, head = buf; 
		     (head != NULL) && (i < NEMO_OPTNUM); 
		     head = ++spacer, i ++) {
			spacer = strchr(head, ' ');
			if (spacer)
				*spacer = '\0';
			option[i] = head;
		}

		/* configuring all options into mnd structures */
		printf("parsing nemoconfig file\n");
		for (i = 0; i < NEMO_OPTNUM; i ++)  
			printf("\t%d=%s\n", i, option[i]);

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
		strncpy(npinfo.tunnel, option[3], strlen(option[3]));
		printf("----->%s\n", npinfo.tunnel);

		/* Insert this npinfo to table */
		if (npi_get(&npinfo.nemopfx, npinfo.nemopfxlen)) {
			/* XXX update entry */
		} else {
			if (npi_add(&npinfo) == NULL)
				printf("adding nemoprefix is failed\n");
		}
			
		memset(buf, 0, sizeof(buf));
	}

        fclose(file);
	return;
}

int
nemo_gif_ar_set(char *tunnel, struct in6_addr *coa) {
        int arsock;
        struct in6_ifreq ifreq6;
        struct sockaddr_in6 *ar_sin6, ar_sin6_orig;

        ar_sin6 = nemo_ar_get(coa, &ar_sin6_orig);
        if (ar_sin6 == NULL) {
                printf("sorry no AR\n");
                return -1;
        }

        memset(&ifreq6, 0, sizeof(ifreq6));
        strncpy(ifreq6.ifr_name, tunnel, strlen(tunnel));
        memcpy(&ifreq6.ifr_ifru.ifru_addr, ar_sin6, sizeof(struct sockaddr_in6));

        arsock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (arsock < 0) {
                perror("socket");
                return errno;
        }

        if (ioctl(arsock, SIOCSIFPHYNEXTHOP_IN6, &ifreq6) < 0) {
                perror("ioctl");
                return errno;
        }

        return (0);
}

/* This is alos defined in common.c */
const char *
ip6_sprintf(addr) 
	const struct in6_addr *addr;
{
	static int ip6round = 0;
	static char ip6buf[8][NI_MAXHOST];
	struct sockaddr_in6 sin6;
	int flags = 0;

#if 0   /* This could be useful. Leave it */
	if (numerichost)
		flags |= NI_NUMERICHOST;
#endif

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *addr;
	/*     
	 * XXX: This is a special workaround for KAME kernels.
	 * sin6_scope_id field of SA should be set in the future.
	 */

	if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
		IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr) ||
		IN6_IS_ADDR_MC_NODELOCAL(&sin6.sin6_addr)) {
		/* XXX: override is ok? */

		sin6.sin6_scope_id = (u_int32_t)ntohs(*(u_short *)&sin6.sin6_addr.s6_addr[2]);
		*(u_short *)&sin6.sin6_addr.s6_addr[2] = 0;
	}

	ip6round = (ip6round + 1) & 7;
	if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6),
		ip6buf[ip6round], NI_MAXHOST, NULL, 0, flags) != 0)
			return "?"; 

		return ip6buf[ip6round];
}


#endif /* MIP_NEMO */
