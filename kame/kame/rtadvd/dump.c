/*
 * Copyright (C) 2000 WIDE Project.
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
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <netinet/in.h>

/* XXX: the following two are non-standard include files */
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <arpa/inet.h>

#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "rtadvd.h"

static FILE *fp;

extern struct rainfo *ralist;

static char *ether_str __P((struct sockaddr_dl *));
static void if_dump __P((void));

static char *
ether_str(sdl)
	struct sockaddr_dl *sdl;
{
	static char ebuf[32];
	u_char *cp;

	if (sdl->sdl_alen && sdl->sdl_alen > 5) {
		cp = (u_char *)LLADDR(sdl);
		sprintf(ebuf, "%x:%x:%x:%x:%x:%x",
			cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
	}
	else {
		sprintf(ebuf, "NONE");
	}

	return(ebuf);
}

static void
if_dump()
{
	struct rainfo *rai;
	struct prefix *pfx;
	char prefixbuf[INET6_ADDRSTRLEN];
	int first;
	time_t lastsent;

	for (rai = ralist; rai; rai = rai->next) {
		fprintf(fp, "%s:\n", rai->ifname);

		/* control information */
		lastsent = (time_t)rai->lastsent.tv_sec;
		if (lastsent) /* ctime() appends CR by itself */
			fprintf(fp, "  Last RA sent: %s", ctime(&lastsent));
		fprintf(fp, "  waits: %d, initcount: %d\n",
			rai->waiting, rai->initcounter);

		/* interface information */
		if (rai->advlinkopt)
			fprintf(fp, "  Link-layer address: %s\n",
				ether_str(rai->sdl));
		fprintf(fp, "  MTU: %d\n", rai->phymtu);

		/* Router configuration variables */
		fprintf(fp,
			"  DefaultLifetime: %d, MaxAdvInterval: %d, "
			"MinAdvInterval: %d\n",
			rai->lifetime, rai->maxinterval, rai->mininterval);
		fprintf(fp, "  Flags: %s%s%s MTU: %d\n",
			rai->managedflg ? "M" : "", rai->otherflg ? "O" : "",
#ifdef MIP6
			rai->haflg ? "H" :
#endif
			"", rai->linkmtu);
		fprintf(fp, "  ReachableTime: %d, RetransTimer: %d, "
			"CurHopLimit: %d\n", rai->reachabletime,
			rai->retranstimer, rai->hoplimit);
#ifdef MIP6
		fprintf(fp, "  HAPreference: %d, HALifetime: %d\n",
			rai->hapref, rai->hatime);
#endif 

		for (first = 1, pfx = rai->prefix.next; pfx != &rai->prefix;
		     pfx = pfx->next) {
			if (first) {
				fprintf(fp, "  Prefixes:\n");
				first = 0;
			}
			fprintf(fp, "    %s/%d(",
				inet_ntop(AF_INET6, &pfx->prefix,
					  prefixbuf, sizeof(prefixbuf)),
				pfx->prefixlen);
			if (pfx->validlifetime == ND6_INFINITE_LIFETIME)
				fprintf(fp, "vltime: infinity, ");
			else
				fprintf(fp, "vltime: %ld, ",
					(long)pfx->validlifetime);
			if (pfx->preflifetime ==  ND6_INFINITE_LIFETIME)
				fprintf(fp, "pltime: infinity, ");
			else
				fprintf(fp, "pltime: %ld, ",
					(long)pfx->preflifetime);
			fprintf(fp, "flags: %s%s%s)\n",
				pfx->onlinkflg ? "L" : "",
				pfx->autoconfflg ? "A" : "",
#ifdef MIP6
				pfx->routeraddr ? "R" :
#endif
				"");
		}
	}
}

void
rtadvd_dump_file(dumpfile)
	char *dumpfile;
{
	if ((fp = fopen(dumpfile, "w")) == NULL) {
		syslog(LOG_WARNING, "<%s> open a dump file(%s)",
		       __FUNCTION__, dumpfile, strerror(errno));
		return;
	}

	if_dump();

	fclose(fp);
}
