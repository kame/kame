/*
 * Copyright (C) 1998 WIDE Project.
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

/*   requires "bgp.h"   */

typedef struct _task {
  struct _task    *tsk_next;
  struct _task    *tsk_prev;
  union {
    struct rpcb   *tsku_bgp;
    struct ripif  *tsku_rip;
  } tsk_tsku;
#define tsk_bgp  tsk_tsku.tsku_bgp
#define tsk_rip  tsk_tsku.tsku_rip

  byte             tsk_timename;
#define                 BGP_CONNECT_TIMER    1
#define                 BGP_HOLD_TIMER       2
#define                 BGP_KEEPALIVE_TIMER  3
#define                 RIP_DUMP_TIMER       4
#define                 RIP_LIFE_TIMER       5
#define                 RIP_GARBAGE_TIMER    6
#define                 OSPF_HELLO_TIMER     7

  struct timeval   tsk_timefull; 
  struct timeval   tsk_timeval; 
} task;



#define TIMEVAL_TO_TIMET(tv, tt) {     \
	*(tt)  = (tv)->tv_sec * 1000000;  \
	*(tt) += (tv)->tv_usec;        \
}

#define TIMET_TO_TIMEVAL(tt, tv) {     \
	(tv)->tv_sec  = *(tt) / 1000000;     \
	(tv)->tv_usec = *(tt) - ((tv)->tv_sec * 1000000);  \
}

#define HOLDTIME_ISCORRECT(t) ((t) == 0 || (t) >= 3)


/*
 *   var
 */
void   task_timer_update __P((task *));
task  *task_remove       __P((task *));
void   task_timer_sync   __P((void));

time_t sub_timeval       __P((struct timeval *, struct timeval *));
void   fatal             __P((char *));
void   fatalx            __P((char *));
void dperror             __P((char *));
void terminate           __P((void));

/*
 *   signal handler
 */
void alarm_handler       __P((void));
void pipe_handler        __P((void));
