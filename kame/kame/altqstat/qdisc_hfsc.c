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
 * $Id: qdisc_hfsc.c,v 1.1 2000/01/18 07:29:01 kjc Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <altq/altq.h>
#include <altq/altq_hfsc.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <err.h>

#include "quip_client.h"
#include "altqstat.h"

#define NCLASSES	64

static int avg_scale = 4096;  /* default fixed-point scale for red */

static struct class_stats stats[NCLASSES], last[NCLASSES];
static char clnames[NCLASSES][128];

void
hfsc_stat_loop(int fd, const char *ifname, int count, int interval)
{
	struct hfsc_class_stats	get_stats;
	struct class_stats	*sp, *lp;
	struct timeval		cur_time, last_time;
	u_int			pkts, drops;
	u_int64_t		total, cumul;
	int			i;
	double			sec;
	int			cnt = count;
	
	/* invalidate class ids */
	for (i=0; i<NCLASSES; i++)
		last[i].class_id = 999999; /* XXX */
		
	strcpy(get_stats.iface.hfsc_ifname, ifname);
	get_stats.stats = &stats[0];

	while (count == 0 || cnt-- > 0) {
		get_stats.nskip = 0;
		get_stats.nclasses = NCLASSES;
	
		if (ioctl(fd, HFSC_GETSTATS, &get_stats) < 0)
			err(1, "ioctl HFSC_GETSTATS");

		printf("\ncur_time:%#qx %u classes %u packets in the tree\n",
		       get_stats.cur_time,
		       get_stats.hif_classes, get_stats.hif_packets);

		gettimeofday(&cur_time, NULL);
		sec = (double)(cur_time.tv_sec - last_time.tv_sec) +
			(double)(cur_time.tv_usec - last_time.tv_usec)
				/ 1000000;

		for (i=0; i<get_stats.nclasses; i++) {
			sp = &stats[i];
			lp = &last[i];

			if (sp->class_id != lp->class_id) {
				memset(lp, 0, sizeof(*lp));
				lp->class_id = sp->class_id;
				quip_chandle2name(ifname, sp->class_handle,
						  clnames[i]);
				continue;
			}

			pkts = sp->npackets - lp->npackets;
			drops = sp->drops - lp->drops;
			total = sp->total - lp->total;
			cumul = sp->cumul - lp->cumul;

			printf("[%2d %s] handle:%#x [rt %uK %ums %uK][ls %uK %ums %uK]\n",
			       sp->class_id, clnames[i], sp->class_handle,
			       sp->rsc.m1/1000, sp->rsc.d, sp->rsc.m2/1000,
			       sp->fsc.m1/1000, sp->fsc.d, sp->fsc.m2/1000);
			printf("  measured: %8.2fMbps [rt:%6.2fM ls:%6.2fM] qlen:%2d period:%u\n",
			       (double)total * 8.0 / sec / 1000000.0,
			       (double)cumul * 8.0 / sec / 1000000.0,
			       (double)(total - cumul) * 8.0 / sec / 1000000.0,
			       sp->qlength, sp->period);
			printf("     packets:%u (%qu bytes) drops:%u\n",
			       sp->npackets,
			       (sp->npackets > 0 ? sp->total : 0),
			       sp->drops);
			printf("     cumul:%#qx total:%#qx\n",
			       sp->cumul, sp->total);
			printf("     vt:%#qx d:%#qx e:%#qx\n",
			       sp->vt, sp->d, sp->e);
			if (sp->qtype == Q_RED) {
				printf("     RED q_avg:%.2f xmit: %u (forced: %u, early: %u marked: %u)\n",
				       ((double)sp->red[0].q_avg)/(double)avg_scale,
				       sp->red[0].xmit_packets, 
				       sp->red[0].drop_forced,
				       sp->red[0].drop_unforced,
				       sp->red[0].marked_packets);
			}
			else if (sp->qtype == Q_RIO) {
				int dp;

				for (dp = 0; dp < RIO_NDROPPREC; dp++)
					printf("     RIO[%d] q_avg:%.2f xmit: %u (forced: %u, early: %u marked: %u)\n",
					       dp,
					       ((double)sp->red[dp].q_avg)/(double)avg_scale,
					       sp->red[dp].xmit_packets, 
					       sp->red[dp].drop_forced,
					       sp->red[dp].drop_unforced,
					       sp->red[dp].marked_packets);
			}

			*lp = *sp;
		}

		last_time = cur_time;
		sleep(interval);
	}
}
