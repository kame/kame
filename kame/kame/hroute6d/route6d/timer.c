/* 
 * $Id: timer.c,v 1.1 1999/08/08 23:29:48 itojun Exp $
 */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

/* Copyright (c) 1997, 1998. Hitachi,Ltd.  All rights reserved. */
/* Hitachi Id: timer.c,v 1.3 1998/01/12 12:39:08 sumikawa Exp $ */

#include  "defs.h"

/* 
 * To calculate time and call appropriate function.
 */
void
timer(void)
{
	int updateinterval;
	int update_time(void);

	if (scanning > 0) {
		scanning = 0;
		return;
	}
	(void)gettimeofday(&now_time, (struct timezone *)NULL);

	if (update_time())
		sendupdate = TRUE;

	if (nr_time.tv_sec <= now_time.tv_sec) {
		regular = 1;
	/* send_regular_update(); */

		updateinterval = TIMER_RATE + get_random_num(URANGE);
		nr_time.tv_sec = now_time.tv_sec + updateinterval;
		nr_time.tv_usec = now_time.tv_usec;
	/* next Triggered time need not be modified */
	} else {
		updateinterval = nr_time.tv_sec - now_time.tv_sec;
	}

	alarminterval = updateinterval;	/* to use in next update_time() */
	alarm(alarminterval);
	return;
}

/* 
 * Get a random number in the specified range.
 */
int
get_random_num(int range)
{
	return ((random() % range) + 1);
}

/* 
 * To maintain timer for triggered update.
 */
void
trigger_update(void)
{
	(void)gettimeofday(&now_time, (struct timezone *)NULL);
	send_triggered_update();

	nt_time.tv_sec = now_time.tv_sec + get_random_num(TRANGE);
	nt_time.tv_usec = now_time.tv_usec;

	return;
}

/* 
 * To update the timers for the route and keep their validity.
 */
int
update_time(void)
{
	struct rt_plen *rtp, *temp;
	struct gateway *gwp;
	int changed = 0;

	for (gwp = gway; gwp; gwp = gwp->gw_next) {
		for (rtp = gwp->gw_dest; rtp;) {
			temp = rtp;
			rtp = rtp->rp_ndst;
			if ((temp->rp_state & (RTS6_KERNEL |
					       RTS6_STATIC |
					       RTS6_INTERFACE)) != 0)
				continue;
			temp->rp_timer += alarminterval;
			if (temp->rp_timer > GARBAGE_TIME) {
				garbage = 1;
			/* delete_local_route( temp ); */
			} else if ((temp->rp_timer > EXPIRE_TIME) &&
				   (temp->rp_metric != HOPCOUNT_INFINITY)) {
				changed = 1;
				temp->rp_metric = HOPCOUNT_INFINITY;
				temp->rp_state |= RTS6_CHANGED;
				rt_ioctl(temp, RTM_DELETE);
			}
		}
	}

	return changed;
}

/* 
 * To add two timevals.
 */
void
timevaladd(struct timeval *t1, struct timeval *t2)
{
	t1->tv_sec += t2->tv_sec;
	if ((t1->tv_usec += t2->tv_usec) > 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

/* 
 * To subtract two timevals.
 */
void
timevalsub(struct timeval *t1, struct timeval *t2)
{
	t1->tv_sec -= t2->tv_sec;
	if ((t1->tv_usec -= t2->tv_usec) < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
}
