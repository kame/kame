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
 * $Id: qdisc_cbq.c,v 1.1 2000/01/18 07:28:58 kjc Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <altq/altq.h>
#include <altq/altq_cbq.h>

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

#ifndef RM_FILTER_GAIN
#define	RM_FILTER_GAIN	5	/* log2 of gain, e.g., 5 => 31/32 */
#endif
#ifndef RM_POWER
#define RM_POWER	(1 << RM_FILTER_GAIN)
#endif

static u_quad_t last_bytes[NCLASSES];
static char clnames[NCLASSES][128];
static u_long clhandles[NCLASSES];
static int avg_scale = 4096;  /* default fixed-point scale for red */

void
cbq_stat_loop(int fd, const char *ifname, int count, int interval)
{
	struct cbq_getstats	get_stats;
	class_stats_t		*sp, stats[NCLASSES];
	struct timeval		cur_time, last_time;
	int			i, msec;
	u_quad_t		xmit_bytes;
	double			flow_kbps, kbps;
	int cnt = count;

	for (i = 0; i < NCLASSES; i++)
	    clhandles[i] = NULL_CLASS_HANDLE;

	strcpy(get_stats.iface.cbq_ifacename, ifname);
	get_stats.iface.cbq_ifacelen = strlen(ifname);
	get_stats.stats = stats;

	while (count == 0 || cnt-- > 0) {
	
		get_stats.nclasses = NCLASSES;
	
		if (ioctl(fd, CBQ_GETSTATS, &get_stats) < 0)
			err(1, "ioctl CBQ_GETSTATS");

		gettimeofday(&cur_time, NULL);
		msec = (cur_time.tv_sec - last_time.tv_sec)*1000 +
			(cur_time.tv_usec - last_time.tv_usec)/1000;

		for (i=0; i<get_stats.nclasses; i++) {
			sp = &stats[i];

			if (sp->handle != clhandles[i]) {
				clhandles[i] = sp->handle;
				quip_chandle2name(ifname, sp->handle,
						  clnames[i]);
				last_bytes[i] = sp->nbytes;
				continue;
			}

			/*
			 * measure the throughput of this class
			 */
			xmit_bytes = sp->nbytes - last_bytes[i];
			kbps = (double)xmit_bytes * 8.0 / (double)msec
				* 1000.0 / 1000.0;
			last_bytes[i] = sp->nbytes;
	    
			switch (sp->handle) {
			case ROOT_CLASS_HANDLE:
				printf("Root Class for Interface %s: %s\n",
				       ifname, clnames[i]);
				break;
			case DEFAULT_CLASS_HANDLE:
				printf("Default Class for Interface %s: %s\n",
				       ifname, clnames[i]);
				break;
			case CTL_CLASS_HANDLE:
				printf("Ctl Class for Interface %s: %s\n",
				       ifname, clnames[i]);
				break;
			default:
				printf("Class %d on Interface %s: %s\n",
				       sp->handle, ifname, clnames[i]);
				break;
			}

			flow_kbps = 8.0 / (double)sp->ns_per_byte
				* 1000*1000*1000/1000;

			printf("\tpriority: %d depth: %d",
			       sp->priority, sp->depth);
			printf(" offtime: %d [us] wrr_allot: %d bytes\n",
			       sp->offtime, sp->wrr_allot);
			printf("\tnsPerByte: %d", sp->ns_per_byte);
			if (flow_kbps > 1000.0)
				printf("\t(%.2f Mbps),", flow_kbps/1000.0);
			else
				printf("\t(%.2f Kbps),", flow_kbps);

			if (kbps > 1000.0)
				printf("\tMeasured: %.2f [Mbps]\n",
				       kbps/1000.0);
			else
				printf("\tMeasured: %.2f [Kbps]\n", kbps);
	    
			printf("\tpkts: %u,\tbytes: %qu\n",
			       sp->npackets, sp->nbytes);
			printf("\tovers: %u,\toveractions: %u\n",
			       sp->over, sp->overactions);
			printf("\tborrows: %u,\tdelays: %u\n",
			       sp->borrows, sp->delays);
			printf("\tdrops: %u,\tdrop_bytes: %qu\n",
			       sp->drops, sp->drop_bytes);
			if (sp->qtype == Q_RED) {
				printf("    RED q_avg:%.2f xmit: %u (forced: %u, early: %u marked: %u)\n",
				       ((double)sp->red[0].q_avg)/(double)avg_scale,
				       sp->red[0].xmit_packets, 
				       sp->red[0].drop_forced,
				       sp->red[0].drop_unforced,
				       sp->red[0].marked_packets);
			}
			else if (sp->qtype == Q_RIO) {
				int dp;

				for (dp = 0; dp < RIO_NDROPPREC; dp++)
					printf("    RIO[%d] q_avg:%.2f xmit: %u (forced: %u, early: %u marked: %u)\n",
					       dp,
					       ((double)sp->red[dp].q_avg)/(double)avg_scale,
					       sp->red[dp].xmit_packets, 
					       sp->red[dp].drop_forced,
					       sp->red[dp].drop_unforced,
					       sp->red[dp].marked_packets);
			}
			printf("\tQCount: %d,\t(qmax: %d)\n",
			       sp->qcnt, sp->qmax);
			printf("\tAvgIdle: %d [us],\t(maxidle: %d minidle: %d [us])\n",
			       sp->avgidle >> RM_FILTER_GAIN,
			       sp->maxidle >> RM_FILTER_GAIN,
			       sp->minidle / RM_POWER);
		}

		last_time = cur_time;
		sleep(interval);
	}
}
