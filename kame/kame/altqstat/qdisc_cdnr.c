/*
 * Copyright (C) 1999
 *	Sony Computer Science Laboratories, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: qdisc_cdnr.c,v 1.1 2000/01/18 07:28:58 kjc Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <altq/altq.h>
#include <altq/altq_cdnr.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <err.h>

#include "quip_client.h"
#include "altqstat.h"

#define NELEMENTS	64
#define MAX_PROB	(128*1024)

struct tce_stats	elements[NELEMENTS], last[NELEMENTS];
static char cdnrnames[NELEMENTS][128];

char *element_names[] = { "none", "top", "element", "tbmeter", "trtcm", "tbrio" };
char *tbmprof_names[] = { "in:    ", "out:   " };
char *tcmprof_names[] = { "green: ", "yellow:", "red:   " };
char *tbrioprof_names[] = { "g(pass):", "g(drop):", 
			    "y(pass):", "y(drop):", 
			    "r(pass):", "r(drop):"  };

static const char *colornames[] = {"green: ", "yellow:", "red:   " };

static void
tbrio_print(struct tce_stats *tce, struct tce_stats *lp, double sec)
{
	int j, k;
	u_int pkts, drops;
	u_quad_t bytes, last_bytes;
	double droprate, mbps;

	/* XXX prob is passed through the drop count field for green */
	printf("  \t\t\t\t\t\tdrop prob[%.1f%%]\n",
	       (double)tce->tce_stats[1].packets / MAX_PROB * 100);
	tce->tce_stats[1].packets = 0;

	for (j = 0; j < 3; j++) {
		pkts = tce->tce_stats[j*2].packets
			- lp->tce_stats[j*2].packets;
		drops =	tce->tce_stats[j*2+1].packets
			- lp->tce_stats[j*2+1].packets;
		if (drops > 0)
			droprate = (double)drops / (pkts + drops) * 100;
		else
			droprate = 0.0;

		bytes = 0;
		last_bytes = 0;
		for (k = 0; k <= j; k++) {
			bytes += tce->tce_stats[k*2].bytes;
			last_bytes += lp->tce_stats[k*2].bytes;
		}
		mbps = (double)(bytes - last_bytes) * 8 / sec / 1000000.0;

		printf("  %s %10u pks %10u drops (%6.2f%%)  %8.3fMbps\n",
		       colornames[j], pkts, drops, droprate, mbps);

	}
	printf("  cumulative:\n");
	for (j = 0; j < 3; j++) {
		pkts = tce->tce_stats[j*2].packets;
		drops =	tce->tce_stats[j*2+1].packets;
		if (drops > 0)
			droprate = (double)drops / (pkts + drops) * 100;
		else
			droprate = 0.0;
		printf("    %s %10u pks %10u drops (%6.2f%%)\n",
		       colornames[j], pkts, drops, droprate);
	}
}

void
cdnr_stat_loop(int fd, const char *ifname, int count, int interval)
{
	struct cdnr_get_stats	get_stats;
	struct tce_stats	*tce, *lp;
	struct timeval		cur_time, last_time;
	double			sec, mbps;
	char			**profile_names, _ifname[32];
	int			i, j, nprofile;
	int cnt = count;

	if (ifname[0] == '_')
		ifname++;
	sprintf(_ifname, "_%s", ifname);

	strcpy(get_stats.iface.cdnr_ifname, ifname);
	get_stats.nskip = 0;
	get_stats.nelements = NELEMENTS;
	get_stats.tce_stats = elements;

	while (count == 0 || cnt-- > 0) {
	
		if (ioctl(fd, CDNR_GETSTATS, &get_stats) < 0)
			err(1, "ioctl CDNR_GETSTATS");

		gettimeofday(&cur_time, NULL);
		sec = (double)(cur_time.tv_sec - last_time.tv_sec) +
			(double)(cur_time.tv_usec - last_time.tv_usec)
				/ 1000000;

		printf("actions:\n");
		printf("  pass:%d drop:%d mark:%d next:%d return:%d none:%d\n",
		       get_stats.stats[TCACODE_PASS].packets,
		       get_stats.stats[TCACODE_DROP].packets,
		       get_stats.stats[TCACODE_MARK].packets,
		       get_stats.stats[TCACODE_NEXT].packets,
		       get_stats.stats[TCACODE_RETURN].packets,
		       get_stats.stats[TCACODE_NONE].packets);

		for (i = 0; i < get_stats.nelements; i++) {
			tce = &elements[i];
			lp = &last[i];

			if (tce->tce_handle != lp->tce_handle) {
				memset(lp, 0, sizeof(*lp));
				lp->tce_handle = tce->tce_handle;
				quip_chandle2name(_ifname, tce->tce_handle,
						  cdnrnames[i]);
				continue;
			}

			switch (tce->tce_type) {
			case TCETYPE_TBMETER:
				nprofile = 2;
				profile_names = tbmprof_names;
				break;
			case TCETYPE_TRTCM:
				nprofile = 3;
				profile_names = tcmprof_names;
				break;
			case TCETYPE_TBRIO:
				nprofile = 6;
				profile_names = tbrioprof_names;
				break;
			default:
				nprofile = 0;
			}

			if (nprofile == 0)
				continue;

			printf("[%s: %s] handle:%#lx\n",
			       element_names[tce->tce_type], cdnrnames[i],
			       tce->tce_handle);
#if 1
			if (tce->tce_type == TCETYPE_TBRIO)
				tbrio_print(tce, lp, sec);
			else
#endif
			for (j = 0; j < nprofile; j++) {
				mbps = (double)(tce->tce_stats[j].bytes -
						lp->tce_stats[j].bytes)
					* 8 / sec / 1000000.0; 
				printf("  %s %10u pkts %16qu bytes (%8.2fMbps)\n",
				       profile_names[j], 
				       tce->tce_stats[j].packets,
				       tce->tce_stats[j].bytes, mbps);
			}
			last_time = cur_time;
			*lp = *tce;
		}
		printf("\n");

		sleep(interval);
	}
}
