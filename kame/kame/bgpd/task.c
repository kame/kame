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

#include "include.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "rt_table.h"
#include "aspath.h"
#include "bgp_var.h"

char *task_timerstr[] = {
  "",
  "BGP ConnectRetry timer",
  "BGP Hold timer",
  "BGP KeepAlive timer",
  "RIP Dump timer",
  "RIP Life timer",
  "RIP Garbage timer"
};


extern task *taskhead;
static void dump_timer();

#define TIMER_MINIMUM_USEC 100000 /* 100msec */

/*
 *  task_timer_update()
 */
void
task_timer_update(argtask)
     task *argtask;
{
  task *tsk;
  struct itimerval itimer;

  if (!taskhead)
    fatalx("<task_timer_update>: BUG : NULL taskhead");
  
  memset(&itimer, 0, sizeof(itimer));

  task_timer_sync();    /* Queue Order will not changed */

  /* charge timer  */
  argtask->tsk_timeval = argtask->tsk_timefull;


  /*  re-sort argtask  */
  if (taskhead->tsk_next != taskhead) { /* not solo ? */

    if (taskhead == argtask)
      taskhead = taskhead->tsk_next;

    tsk = taskhead;
    remque(argtask);
    while(1) {
      if (sub_timeval(&argtask->tsk_timeval,
		          &tsk->tsk_timeval)       > 0) {

	insque(argtask, tsk->tsk_prev);  /* found place to insque          */
	if (tsk == taskhead)
	  taskhead = argtask;             /* argtask into TOP of the queue  */
	break; /* while() */ 
      }

      if ((tsk = tsk->tsk_next) == taskhead) {
	insque(argtask, tsk->tsk_prev);  /* argtask into LAST of the queue */
	break; /* while() */ 
      }
    }
  }

  /* Re-call setitimer() */
  itimer.it_value = taskhead->tsk_timeval;

  if (itimer.it_value.tv_sec  == 0 &&
      itimer.it_value.tv_usec == 0) /* must be impossible, but.. */
    itimer.it_value.tv_usec = TIMER_MINIMUM_USEC;


  if (setitimer(ITIMER_REAL, &itimer, NULL) == 0) {
    IFLOG(LOG_TIMER)
      syslog(LOG_DEBUG, "<task_timer_update>: %s (%d.%d sec) set",
	     task_timerstr[taskhead->tsk_timename],
	     taskhead->tsk_timeval.tv_sec,
	     taskhead->tsk_timeval.tv_usec);
  } else {
    fatalx("<task_timer_update>: setitimer");
  }
}



/*
 *  task_remove()
 *    DESCRIPTION:  Remove and Free ONE.  Doesn't touch union "tsk_tsku".
 *
 *    NOTE: argtask SHOULD exist in the queue.
 */
task *
task_remove(argtask)
     task *argtask;
{
  struct itimerval itimer;

  if (!argtask ||
      !taskhead  )
    fatalx("<task_remove>: BUG: No task");

  memset(&itimer, 0, sizeof(itimer));

  task_timer_sync();    /* NOTE: queue order isn't changed */

  /* remove task */
  if (taskhead->tsk_next == taskhead) { /* solo ? */

    if (taskhead == argtask) {
      free(argtask);
      taskhead = NULL;    /*   itimer == 0, here.  */
    } else
      fatalx("<task_remove>: BUG !");

  } else {                              /*  Not solo  */

    if (taskhead == argtask)
      taskhead = taskhead->tsk_next;

    remque(argtask);
    free(argtask);
    itimer.it_value = taskhead->tsk_timeval;
  }    

  /* Re-call setitimer()   (might clear the timer, if NULL.)   */

  if (setitimer(ITIMER_REAL, &itimer, NULL) < 0)
    fatal("<task_remove>: setitimer");

  return taskhead;
}




/*
 *  task_timer_sync()
 */
void
task_timer_sync()
{
  struct  itimerval itimer;
  task   *tsk;
  time_t  tt_x, tt_y, tt_z;


  if (getitimer(ITIMER_REAL, &itimer) < 0)
    fatal("<task_timer_sync>: getitimer");

  if ((tt_z = sub_timeval(&itimer.it_value, &taskhead->tsk_timeval)) < 0 ) {
	  /* Negative tt_z ! */
	  tt_z = 0;
	  syslog(LOG_ERR,
		 "<task_timer_sync>: internal inconsistency "
		 "expire: %lu:%lu, tasktime: %lu:%lu",
		 itimer.it_value.tv_sec, itimer.it_value.tv_usec,
		 taskhead->tsk_timeval.tv_sec, taskhead->tsk_timeval.tv_usec);
	  IFLOG(LOG_TIMER)
	    dump_timer();
  }

  tsk = taskhead;

  while(1) {
    TIMEVAL_TO_TIMET(&tsk->tsk_timeval, &tt_y);

    tt_x = (tt_y - tt_z > TIMER_MINIMUM_USEC) ?  (tt_y-tt_z) : 100000 ;

    TIMET_TO_TIMEVAL(&tt_x, &tsk->tsk_timeval);

    if ((tsk = tsk->tsk_next) == taskhead)
      break;  /* while() */
  }
}


/*
 *     sub_timeval(tv2 - tv1)
 */
time_t
sub_timeval(tv1, tv2)
     struct timeval *tv1;
     struct timeval *tv2;
{
  time_t tt1, tt2;

  TIMEVAL_TO_TIMET(tv1, &tt1);
  TIMEVAL_TO_TIMET(tv2, &tt2);

  return (tt2 - tt1);
}

static void
dump_timer()
{
	char logbuf[4096], *s;
	task *t = taskhead;
	int i = 0;

	if (t == NULL)
		return;

	while(1) {
		switch(t->tsk_timename) {
		 case BGP_CONNECT_TIMER:
			 s = "bgpconnect";
			 break;
		 case BGP_HOLD_TIMER:
			 s = "bgphold";
			 break;
		 case BGP_KEEPALIVE_TIMER:
			 s = "bgpkeepalive";
			 break;
		 case RIP_DUMP_TIMER:
			 s = "ripdump";
			 break;
		 case RIP_LIFE_TIMER:
			 s = "riplife";
			 break;
		 case RIP_GARBAGE_TIMER:
			 s = "ripgarbage";
			 break;
		 case OSPF_HELLO_TIMER:
			 s = "ospfhello";
			 break;
		 default:
			 s = "???";
			 break;
		}
		i += sprintf(&logbuf[i], "%s=%d:%d,", s,
			     (int)t->tsk_timeval.tv_sec,
			     (int)t->tsk_timeval.tv_usec);

		if ((t = t->tsk_next) == taskhead)
			break;
	}

	logbuf[i - 1] = '\0';	/* i must be positive here */

	syslog(LOG_NOTICE, "<%s>: %s", __FUNCTION__, logbuf);
}
