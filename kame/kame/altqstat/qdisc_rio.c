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
 * $Id: qdisc_rio.c,v 1.1 2000/01/18 07:29:02 kjc Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <altq/altq.h>
#include <altq/altq_red.h>
#include <altq/altq_rio.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <err.h>

#include "altqstat.h"

static int avg_scale = 4096;	/* default fixed-point scale */

void
rio_stat_loop(int fd, const char *ifname, int count, int interval)
{
	struct rio_stats rio_stats;
	struct timeval cur_time, last_time;
	u_quad_t xmit_bytes, lo_last_bytes, med_last_bytes, hi_last_bytes;
	int msec;
	double lo_kbps, med_kbps, hi_kbps;
	int cnt = count;
	
	bzero(&rio_stats, sizeof(rio_stats));
	strcpy(rio_stats.iface.rio_ifname, ifname);

	gettimeofday(&last_time, NULL);
	last_time.tv_sec -= interval;
	lo_last_bytes = med_last_bytes = hi_last_bytes = 0;

	while (count == 0 || cnt-- > 0) {
	
		if (ioctl(fd, RIO_GETSTATS, &rio_stats) < 0)
			err(1, "ioctl RIO_GETSTATS");

		gettimeofday(&cur_time, NULL);
		msec = (cur_time.tv_sec - last_time.tv_sec)*1000 +
			(cur_time.tv_usec - last_time.tv_usec)/1000;
		last_time = cur_time;

		/*
		 * measure the throughput
		 */
		xmit_bytes = rio_stats.q_stats[0].xmit_bytes - lo_last_bytes;
		lo_kbps = (double)xmit_bytes * 8.0 / (double)msec
			* 1000.0 / 1000.0;
		lo_last_bytes = rio_stats.q_stats[0].xmit_bytes;

		xmit_bytes = rio_stats.q_stats[1].xmit_bytes - med_last_bytes;
		med_kbps = (double)xmit_bytes * 8.0 / (double)msec
			* 1000.0 / 1000.0;
		med_last_bytes = rio_stats.q_stats[1].xmit_bytes;

		xmit_bytes = rio_stats.q_stats[2].xmit_bytes - hi_last_bytes;
		hi_kbps = (double)xmit_bytes * 8.0 / (double)msec
			* 1000.0 / 1000.0;
		hi_last_bytes = rio_stats.q_stats[2].xmit_bytes;

		printf("weight:%d q_limit:%d\n",
		       rio_stats.weight, rio_stats.q_limit);

		printf("\t\t\tLOW DP\t\tMEDIUM DP\t\tHIGH DP\n");

		printf("thresh (prob):\t\t[%d,%d](1/%d)\t[%d,%d](1/%d)\t\t[%d,%d](%d)\n",
		       rio_stats.q_params[0].th_min,
		       rio_stats.q_params[0].th_max,
		       rio_stats.q_params[0].inv_pmax,
		       rio_stats.q_params[1].th_min,
		       rio_stats.q_params[1].th_max,
		       rio_stats.q_params[1].inv_pmax,
		       rio_stats.q_params[2].th_min,
		       rio_stats.q_params[2].th_max,
		       rio_stats.q_params[2].inv_pmax);
		printf("qlen (avg):\t\t%d (%.2f)\t%d (%.2f)\t\t%d (%.2f)\n",
		       rio_stats.q_len[0],
		       ((double)rio_stats.q_stats[0].q_avg)/(double)avg_scale,
		       rio_stats.q_len[1],
		       ((double)rio_stats.q_stats[1].q_avg)/(double)avg_scale,
		       rio_stats.q_len[2],
		       ((double)rio_stats.q_stats[2].q_avg)/(double)avg_scale);
		printf("xmit (drop) pkts:\t%u (%u)\t\t%u (%u)\t\t\t%u (%u)\n",
		       rio_stats.q_stats[0].xmit_packets,
		       rio_stats.q_stats[0].drop_packets,
		       rio_stats.q_stats[1].xmit_packets,
		       rio_stats.q_stats[1].drop_packets,
		       rio_stats.q_stats[2].xmit_packets,
		       rio_stats.q_stats[2].drop_packets);
		printf("(forced:early):\t\t(%u:%u)\t\t(%u:%u)\t\t\t(%u:%u)\n",
		       rio_stats.q_stats[0].drop_forced,
		       rio_stats.q_stats[0].drop_unforced,
		       rio_stats.q_stats[1].drop_forced,
		       rio_stats.q_stats[1].drop_unforced,
		       rio_stats.q_stats[2].drop_forced,
		       rio_stats.q_stats[2].drop_unforced);
		if (rio_stats.q_stats[0].marked_packets != 0
		    || rio_stats.q_stats[1].marked_packets != 0
		    || rio_stats.q_stats[2].marked_packets != 0)
			printf("marked:\t\t\t%u\t\t%u\t\t\t%u\n",
			       rio_stats.q_stats[0].marked_packets,
			       rio_stats.q_stats[1].marked_packets,
			       rio_stats.q_stats[2].marked_packets);
		if (hi_kbps > 1000.0 || lo_kbps > 1000.0)
			printf("throughput:\t\t%.2f Mbps\t%.2f Mbps\t\t%.2f Mbps\n\n",
			       lo_kbps/1000.0, med_kbps/1000.0, hi_kbps/1000.0);
		else
			printf("throughput:\t\t%.2f Kbps\t%.2f Kbps\t\t%.2f Kbps\n\n",
			       lo_kbps, med_kbps, hi_kbps);

		sleep(interval);
	}
}
