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
/* YIPS @(#)$Id: schedule.h,v 1.1.1.1 1999/08/08 23:31:25 itojun Exp $ */

typedef u_int32_t sched_index;

/* scheduling table */
struct sched {
	sched_index index;	/* index */
	int status;		/* status for scheduling */
	int tick;		/* tick counter */
	int (*f_try)();		/* pointer to the function when tick over */
	int try;		/* try counter */
	int (*f_over)();	/* pointer to the function when try over */
	caddr_t ptr1;		/* buffer 1 */
	caddr_t ptr2;		/* buffer 2 */
	struct sched *next;
	struct sched *prev;

	int identifier;		/* id for the entry */
#define SCHED_ID_PH1_RESEND	0
#define SCHED_ID_PH1_LIFETIME	1
#define SCHED_ID_PH2_RESEND	2
#define SCHED_ID_PST_ACQUIRE	3
#define SCHED_ID_PST_LIFETIME	4
};

struct schedtab {
	struct sched *head;
	struct sched *tail;
	int len;
};

/* Status for scheduling */
#define SCHED_OFF  0
#define SCHED_ON   1
#define SCHED_DEAD 2

extern int schedular __P((int));
extern struct sched *sched_add __P((u_int, int (*)(), u_int, int (*)(),
				caddr_t, caddr_t, int id));
extern void sched_kill __P((struct sched **sc));
extern vchar_t *sched_dump __P((void));
extern char *sched_pindex __P((sched_index *index));
extern int sched_init __P((void));
