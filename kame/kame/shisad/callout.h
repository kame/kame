/*	$KAME: callout.h,v 1.5 2006/09/28 03:05:53 keiichi Exp $	*/

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

#ifndef _SHISAD_CALLOUT_H_
#define _SHISAD_CALLOUT_H_

struct callout_queue_t {
	TAILQ_ENTRY(callout_queue_t) callout_entry;

	struct timeval exptime;
	char *funcname;
	void (*func)(void *);
	void *arg;
};

typedef struct callout_queue_t *CALLOUT_HANDLE;

TAILQ_HEAD(callout_queue_t_head, callout_queue_t);

/*extern struct callout_queue_t_head callout_head;*/

void callout_init(void);
void callout_expire_check(void);
CALLOUT_HANDLE new_callout_entry(int, void (*)(void *), void *, char *);
void remove_callout_entry(CALLOUT_HANDLE ch);
void update_callout_entry(CALLOUT_HANDLE ch, int);
int get_next_timeout(void);
void show_callout_table(int, char *);

#endif /* _SHISAD_CALLOUT_H_ */
