/*	$KAME: callout.c,v 1.8 2006/09/28 03:05:53 keiichi Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>	/* for definition of INFTIM */
#include <syslog.h>
#include <time.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>

#include "command.h"
#include "callout.h"

#define timermilisec(tvp)	((tvp)->tv_usec / 1000 + (tvp)->tv_sec * 1000)
#ifndef INFTIM
#define INFTIM	(-1)
#endif

struct callout_queue_t_head callout_head;

static void insert_callout_queue(struct callout_queue_t *);

/* 
 * You have to include following header prior including "callout.h"
 *
 * #include <sys/queue.h>
 * #include <sys/time.h>
 */

/*
 *  The data structures in this libarary like a list of callout 
 *  table are assumed to use in synchronized sequence. Don't operate
 *  them in interrupted procedures. It might cause serious problems.
 *
 *  Entries are TAILQed in order of expiration time. With this 
 *  order, the system doesn't need the check the expiration in
 *  each second.
 *
 *  - Initialize
 *	callout_init();
 *	This function must be called when the process is started.
 *
 *  - Registration
 *  new_callout_entry(s, func, arg):
 *    A function 'func' will be called with an argument 'arg' after
 *    's' seconds. A returned value is a handle of this callout
 *    table which can be used to remove it.
 *
 *  - In the system loop
 *	This callout framework is supposed to use with poll(2) system call.
 *	Typical usage are as follows. Another framework 'fdlist' is used
 *	in this examle.
 *
 *	while (1) {
 *		clear_revents();
 *	    
 *		if ((pfds = poll(fdl_fds, fdl_nfds, get_next_timeout())) < 0) {
 *			perror("poll");
 *			continue;
 *		}
 *		
 *		if (pfds != 0) {
 *			dispatch_fdfunctions(fdl_fds, fdl_nfds);
 *		}
 *		callout_expire_check();
 *	}
 *
 *	get_next_timeout() function helps to know when the system should
 *	wake next time.
 *	callout_expire_check() must be called before the next event
 *	function would be called.
 *		
 */

void
callout_init()
{
	TAILQ_INIT(&callout_head);
}

void
callout_expire_check()
{
	struct callout_queue_t *cq;
	struct timeval current_time;

	gettimeofday(&current_time, NULL);
	while ((cq = TAILQ_FIRST(&callout_head))) {
		if (timercmp(&current_time, &cq->exptime, <))
			break;
		TAILQ_REMOVE(&callout_head, cq, callout_entry);
		(*cq->func)(cq->arg);
		free(cq);
	}
}

CALLOUT_HANDLE
new_callout_entry(exprelative, func, arg, funcname)
	int exprelative;	/* Relative time of expire (s) */
	void (*func)(void *);	/* Function to be called */
	void *arg;		/* An argument to pass the function */
	char *funcname;		/* Function name used for debugging */
{
	struct callout_queue_t *newcq;

	if (exprelative <= 0) {
		syslog(LOG_ERR, "new_callout_entry: invalid tick (%d)", exprelative);
		return (NULL);
	}
	newcq = (struct callout_queue_t *)malloc(sizeof(*newcq));
	if (!newcq) {
		syslog(LOG_ERR, "new_callout_entry: memory allocation failed");
		return (NULL);
	}

	gettimeofday(&newcq->exptime, NULL);
	newcq->exptime.tv_sec += exprelative;
	newcq->func = func;
	newcq->arg = arg;
	newcq->funcname = funcname;

	insert_callout_queue(newcq);

	return (newcq);
}

static void
insert_callout_queue(newcq)
	struct callout_queue_t *newcq;
{
	struct callout_queue_t *cq;

	/* Search appropriate position to insert a new entry */
	TAILQ_FOREACH(cq, &callout_head, callout_entry) {
		if (timercmp(&cq->exptime, &newcq->exptime, >)) {
			TAILQ_INSERT_BEFORE(cq, newcq, callout_entry);
			return;
		}
	}
	if (!cq)
		TAILQ_INSERT_TAIL(&callout_head, newcq, callout_entry);
}

void
remove_callout_entry(ch)
	CALLOUT_HANDLE ch;
{
	struct callout_queue_t *cq;

	if (ch == NULL)
		return;

	/* To check the validity of the given callout_handle, 
	   try to find the handle from the callout queue.
	   If the same handle was found, the handle would be valid.
	   'Valid' means the entry can be removed safely */
	TAILQ_FOREACH(cq, &callout_head, callout_entry) {
		if (cq == ch)
			break;
	}
	if (cq == NULL)
		return;

	/* ch validity has been guaranteed at this time */
	TAILQ_REMOVE(&callout_head, ch, callout_entry);
	free(ch);

	/* There are no necessary to reschedule the expiration. */
}

void
update_callout_entry(ch, sec)
	CALLOUT_HANDLE ch;
	int sec;
{
	/*struct timeval exptime;*/

	/* This is the very simplest way. there must be 
	   more efficient ways */
	TAILQ_REMOVE(&callout_head, ch, callout_entry);
	gettimeofday(&ch->exptime, NULL);
	ch->exptime.tv_sec += sec;
	insert_callout_queue(ch);
}

int
get_next_timeout()
{
	int timeout;
	struct timeval current_time, t;

	timeout = INFTIM;
	if (!TAILQ_EMPTY(&callout_head) &&
	    gettimeofday(&current_time, NULL) == 0) {
		if (timercmp(&TAILQ_FIRST(&callout_head)->exptime,
			     &current_time, <)) {
			syslog(LOG_INFO, "Schedule might be behind\n");
			timeout = 0;
		} else {
			timersub(&TAILQ_FIRST(&callout_head)->exptime,
				 &current_time, &t);
			timeout = timermilisec(&t);
		}
	}
	return (timeout);
}

void
show_callout_table(s, line)
	int s;
	char *line; /* dummy */
{
	struct timeval current_time, t;
	struct callout_queue_t *cq;
	
	gettimeofday(&current_time, NULL);
	TAILQ_FOREACH(cq, &callout_head, callout_entry) {
		struct tm *tm;
		
		tm = localtime((time_t *)&cq->exptime.tv_sec);
		
  		timersub(&cq->exptime, &current_time, &t);
		command_printf(s, "%02d:%02d:%02d(%ld.%06lds) %s() for %p\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec,
			t.tv_sec, t.tv_usec,
			cq->funcname, cq->arg);
	}
}
