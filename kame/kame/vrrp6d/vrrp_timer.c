/*	$KAME: vrrp_timer.c,v 1.2 2003/02/25 09:29:25 ono Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.
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

#include <sys/time.h>

#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <search.h>
#endif

#include "vrrp_timer.h"

static TAILQ_HEAD(_vrrptimer, vrrp_timer) timer_head;
static struct timeval timer_min;

#define MILLION 1000000

static struct timeval tm_max = {0x7fffffff, 0x7fffffff};

void
vrrp_timer_init()
{
	TAILQ_INIT(&timer_head);
	timer_min = tm_max;
}

struct vrrp_timer *
vrrp_add_timer(struct vrrp_timer *(*timeout) __P((void *)),
    void (*update) __P((void *, struct timeval *)),
    void *timeodata, void *updatedata)
{
	struct vrrp_timer *newtimer;

	if ((newtimer = malloc(sizeof(*newtimer))) == NULL) {
		syslog(LOG_ERR,
		       "<%s> can't allocate memory", __func__);
		exit(1);
	}

	memset(newtimer, 0, sizeof(*newtimer));

	if (timeout == NULL) {
		syslog(LOG_ERR,
		       "<%s> timeout function unspecified", __func__);
		exit(1);
	}
	newtimer->expire = timeout;
	newtimer->update = update;
	newtimer->expire_data = timeodata;
	newtimer->update_data = updatedata;
	newtimer->tm = tm_max;

	/* link into chain */
	TAILQ_INSERT_HEAD(&timer_head, newtimer, timer_link);

	return(newtimer);
}

void
vrrp_remove_timer(struct vrrp_timer **timer)
{
	TAILQ_REMOVE(&timer_head, *timer, timer_link);
	free(*timer);
	*timer = NULL;
}

void
vrrp_set_timer(u_int interval, struct vrrp_timer *timer)
{
	struct timeval now;

	/* reset the timer */
	gettimeofday(&now, NULL);

	TIMEVAL_ADD_INT(&now, interval, &timer->tm);

	/* update the next expiration time */
	if (TIMEVAL_LT(&timer->tm, &timer_min))
		timer_min = timer->tm;

	return;
}

/*
 * Check expiration for each timer. If a timer expires,
 * call the expire function for the timer and update the timer.
 * Return the next interval for select() call.
 */
struct timeval *
vrrp_check_timer()
{
	static struct timeval returnval;
	struct timeval now;
	struct vrrp_timer *tm, *tm_next;

	gettimeofday(&now, NULL);

	timer_min = tm_max;

	for (tm = TAILQ_FIRST(&timer_head); tm; tm = tm_next)
	{
		tm_next = TAILQ_NEXT(tm, timer_link);

		if (TIMEVAL_LEQ(&tm->tm, &now)) {
			if (((*tm->expire)(tm->expire_data) == NULL))
				continue; /* the timer was removed */
			if (tm->update)
				(*tm->update)(tm->update_data, &tm->tm);
			TIMEVAL_ADD(&tm->tm, &now, &tm->tm);
		}

		if (TIMEVAL_LT(&tm->tm, &timer_min))
			timer_min = tm->tm;
	}

	if (TIMEVAL_EQUAL(&tm_max, &timer_min)) {
		/* no need to timeout */
		return(NULL);
	} else if (TIMEVAL_LT(&timer_min, &now)) {
		/* this may occur when the interval is too small */
		returnval.tv_sec = returnval.tv_usec = 0;
	} else
		TIMEVAL_SUB(&timer_min, &now, &returnval);
	return(&returnval);
}

struct timeval *
vrrp_timer_rest(struct vrrp_timer *timer)
{
	static struct timeval returnval, now;

	gettimeofday(&now, NULL);
	if (TIMEVAL_LEQ(&timer->tm, &now)) {
		syslog(LOG_DEBUG,
		       "<%s> a timer must be expired, but not yet",
		       __func__);
		returnval.tv_sec = returnval.tv_usec = 0;
	}
	else
		TIMEVAL_SUB(&timer->tm, &now, &returnval);

	return(&returnval);
}

/* result = a + b */
void
TIMEVAL_ADD(struct timeval *a, struct timeval *b, struct timeval *result)
{
	long l;

	if ((l = a->tv_usec + b->tv_usec) < MILLION) {
		result->tv_usec = l;
		result->tv_sec = a->tv_sec + b->tv_sec;
	}
	else {
		result->tv_usec = l - MILLION;
		result->tv_sec = a->tv_sec + b->tv_sec + 1;
	}
}

/* result = a + b */
void
TIMEVAL_ADD_INT(struct timeval *a, u_int interval, struct timeval *result)
{
	result->tv_usec = interval;
	result->tv_sec = a->tv_sec + interval;
}

/*
 * result = a - b
 * XXX: this function assumes that a >= b.
 */
void
TIMEVAL_SUB(struct timeval *a, struct timeval *b, struct timeval *result)
{
	long l;

	if ((l = a->tv_usec - b->tv_usec) >= 0) {
		result->tv_usec = l;
		result->tv_sec = a->tv_sec - b->tv_sec;
	}
	else {
		result->tv_usec = MILLION + l;
		result->tv_sec = a->tv_sec - b->tv_sec - 1;
	}
}
