/*	$Id: altq_jobs.c,v 1.1 2002/10/24 09:17:52 suz Exp $	*/
/*
 * Copyright (c) 2001-2002, by the Rector and Board of Visitors of the 
 * University of Virginia.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 *
 * Redistributions of source code must retain the above 
 * copyright notice, this list of conditions and the following 
 * disclaimer. 
 *
 * Redistributions in binary form must reproduce the above 
 * copyright notice, this list of conditions and the following 
 * disclaimer in the documentation and/or other materials provided 
 * with the distribution. 
 *
 * Neither the name of the University of Virginia nor the names 
 * of its contributors may be used to endorse or promote products 
 * derived from this software without specific prior written 
 * permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (C) 2000
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
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
 */

/*                                                                     
 * JoBS - altq prototype implementation                                
 *                                                                     
 * Author: Nicolas Christin <nicolas@cs.virginia.edu>
 *
 * JoBS algorithms originally devised and proposed by		       
 * Nicolas Christin and Jorg Liebeherr.
 * Grateful acknowledgments to Tarek Abdelzaher for his help and       
 * comments, and to Kenjiro Cho for some helpful advice.
 * Contributed by the Multimedia Networks Group at the University
 * of Virginia. 
 *
 * http://qosbox.cs.virginia.edu
 *                                                                      
 */ 							               

/*
 * JoBS queue
 */

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include "opt_altq.h"
#if (__FreeBSD__ != 2)
#include "opt_inet.h"
#ifdef __FreeBSD__
#include "opt_inet6.h"
#endif
#endif
#endif /* __FreeBSD__ || __NetBSD__ */

#ifdef ALTQ_JOBS  /* jobs is enabled by ALTQ_JOBS option in opt_altq.h */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/queue.h>

#include <machine/limits.h>

#include <net/if.h>
#include <net/if_types.h>

#include <altq/altq.h>
#include <altq/altq_conf.h>
#include <altq/altq_jobs.h>

/*
 * function prototypes
 */
static struct jobs_if *jobs_attach __P((struct ifaltq *, u_int, u_int, u_int));
static int jobs_detach __P((struct jobs_if *));
static int jobs_clear_interface __P((struct jobs_if *));
static int jobs_request __P((struct ifaltq *, int, void *));
static void jobs_purge __P((struct jobs_if *));
static struct jobs_class *jobs_class_create __P((struct jobs_if *,
						 int, 
						 int64_t, int64_t,
						 int64_t, int64_t, int64_t,
						 int));
static int jobs_class_destroy __P((struct jobs_class *));
static int jobs_enqueue __P((struct ifaltq *, struct mbuf *,
			     struct altq_pktattr *));
static struct mbuf *jobs_dequeue __P((struct ifaltq *, int));

static int jobs_addq __P((struct jobs_class *, struct mbuf *, struct jobs_if*));
static struct mbuf *jobs_getq __P((struct jobs_class *));
static struct mbuf *jobs_pollq __P((struct jobs_class *));
static void jobs_purgeq __P((struct jobs_class *));

int jobsopen __P((dev_t, int, int, struct proc *));
int jobsclose __P((dev_t, int, int, struct proc *));
int jobsioctl __P((dev_t, ioctlcmd_t, caddr_t, int, struct proc *));
static int jobscmd_if_attach __P((struct jobs_attach *));
static int jobscmd_if_detach __P((struct jobs_interface *));
static int jobscmd_add_class __P((struct jobs_add_class *));
static int jobscmd_delete_class __P((struct jobs_delete_class *));
static int jobscmd_modify_class __P((struct jobs_modify_class *));
static int jobscmd_add_filter __P((struct jobs_add_filter *));
static int jobscmd_delete_filter __P((struct jobs_delete_filter *));
static int jobscmd_class_stats __P((struct jobs_class_stats *));
static void get_class_stats __P((struct class_stats *, struct jobs_class *));
static struct jobs_class *clh_to_clp __P((struct jobs_if *, u_long));
static u_long clp_to_clh __P((struct jobs_class *));

static tslist_t *tslist_alloc __P((void));
static void tslist_destroy __P((struct jobs_class *));
static int tslist_enqueue __P((struct jobs_class *, u_int64_t));
static void tslist_dequeue __P((struct jobs_class *));
static void tslist_drop __P((struct jobs_class *));

static int enforce_wc __P((struct jobs_if *));
static int64_t* adjust_rates_rdc __P((struct jobs_if *));
static int64_t* assign_rate_drops_adc __P((struct jobs_if *));
static int64_t* update_error __P((struct jobs_if *));
static int min_rates_adc __P((struct jobs_if *));
static int64_t proj_delay __P((struct jobs_if *,int));
static int pick_dropped_rlc __P((struct jobs_if *));

/* jif_list keeps all jobs_if's allocated. */
static struct jobs_if *jif_list = NULL;

/* scaling/conversion macros */

#define secs2ticks(x) ((x) * machclk_freq)
#define ticks2secs(x) ((x) / machclk_freq)

#define invsecs2invticks(x) ticks2secs(x)
#define invticks2invsecs(x) secs2ticks(x)

#define bits2Bytes(x) ((x) >> 3)
#define Bytes2bits(x) ((x) << 3)

#define ScaleRate(x) ((x) << SCALE_RATE)
#define UnscaleRate(x) ((x) >> SCALE_RATE)

#define bps2internal(x) (invsecs2invticks(bits2Bytes(ScaleRate(x))))
#define internal2bps(x) (UnscaleRate(invticks2invsecs(Bytes2bits(x))))

/* this macro takes care of possible wraparound
 * effects in the computation of a delay
 */

#define DELAYDIFF(x,y) ((x >= y)?(x - y):((ULLONG_MAX-y)+x+1))

typedef unsigned long long ull;

/* setup functions */

static struct jobs_if *
jobs_attach(ifq, bandwidth, qlimit, separate)
     struct ifaltq *ifq;
     u_int bandwidth;
     u_int qlimit;
     u_int separate;
{
  struct jobs_if *jif;
  
  MALLOC(jif, struct jobs_if *, sizeof(struct jobs_if),
	 M_DEVBUF, M_WAITOK);
  if (jif == NULL)
    return (NULL);
  bzero(jif, sizeof(struct jobs_if));
  jif->jif_bandwidth = bandwidth;
  jif->jif_qlimit = qlimit;
  jif->jif_separate = separate;
  printf("JoBS bandwidth = %d bps\n",(int)bandwidth);
  printf("JoBS buffer size = %d pkts [%s]\n",(int)qlimit,separate?"separate buffers":"shared buffer");
  jif->jif_maxpri = -1;
  jif->jif_ifq = ifq;

  jif->wc_cycles_enqueue = 0;
  jif->avg_cycles_enqueue = 0;
  jif->avg_cycles2_enqueue = 0;
  jif->bc_cycles_enqueue = INFINITY;
  jif->wc_cycles_dequeue = 0;
  jif->avg_cycles_dequeue = 0;
  jif->avg_cycles2_dequeue = 0;
  jif->bc_cycles_dequeue = INFINITY;
  jif->total_enqueued = 0;
  jif->total_dequeued = 0;

  /* add this state to the jobs list */
  jif->jif_next = jif_list;
  jif_list = jif;
  
  return (jif);
}

static int
jobs_detach(jif)
     struct jobs_if *jif;
{
  (void)jobs_clear_interface(jif);
  
  /* remove this interface from the jif list */
  if (jif_list == jif)
    jif_list = jif->jif_next;
  else {
    struct jobs_if *p;
    
    for (p = jif_list; p != NULL; p = p->jif_next)
      if (p->jif_next == jif) {
	p->jif_next = jif->jif_next;
	break;
      }
    ASSERT(p != NULL);
  }
  FREE(jif, M_DEVBUF);
  return (0);
}

/*
 * bring the interface back to the initial state by discarding
 * all the filters and classes.
 */
static int
jobs_clear_interface(jif)
     struct jobs_if *jif;
{
  struct jobs_class	*cl;
  int pri;
  
  /* free the filters for this interface */
  acc_discard_filters(&jif->jif_classifier, NULL, 1);
  
  /* clear out the classes */
  for (pri = 0; pri <= jif->jif_maxpri; pri++)
    if ((cl = jif->jif_classes[pri]) != NULL)
      jobs_class_destroy(cl);
  
  return (0);
}

static int
jobs_request(ifq, req, arg)
     struct ifaltq *ifq;
     int req;
     void *arg;
{
  struct jobs_if	*jif = (struct jobs_if *)ifq->altq_disc;
  
  switch (req) {
  case ALTRQ_PURGE:
    jobs_purge(jif);
    break;
  }
  return (0);
}

/* discard all the queued packets on the interface */
static void
jobs_purge(jif)
     struct jobs_if *jif;
{
  struct jobs_class *cl;
  int pri;
  
  for (pri = 0; pri <= jif->jif_maxpri; pri++) {
    if ((cl = jif->jif_classes[pri]) != NULL && !qempty(cl->cl_q))
      jobs_purgeq(cl);
  }
  if (ALTQ_IS_ENABLED(jif->jif_ifq))
    jif->jif_ifq->ifq_len = 0;
}

static struct jobs_class *
jobs_class_create(jif, pri, adc, rdc, alc, rlc, arc, flags)
     struct jobs_if *jif;
     int pri;
     int64_t adc,rdc,alc,rlc, arc;
     int flags;
{
  struct jobs_class *cl,*scan1,*scan2;
  int s;
  int classExists1,classExists2;
  int i,j;
  int64_t tmp[JOBS_MAXPRI];
  u_int64_t now;

  if ((cl = jif->jif_classes[pri]) != NULL) {
    /* modify the class instead of creating a new one */
    s = splimp();
    if (!qempty(cl->cl_q))
      jobs_purgeq(cl);
    splx(s);
  } else {
    MALLOC(cl, struct jobs_class *, sizeof(struct jobs_class),
	   M_DEVBUF, M_WAITOK);
    if (cl == NULL)
      return (NULL);
    bzero(cl, sizeof(struct jobs_class));
    
    MALLOC(cl->cl_q, class_queue_t *, sizeof(class_queue_t),
	   M_DEVBUF, M_WAITOK);
    if (cl->cl_q == NULL)
      goto err_ret;
    bzero(cl->cl_q, sizeof(class_queue_t));

    cl->arv_tm = tslist_alloc();
    if (cl->arv_tm == NULL)
      goto err_ret;
  }
  
  jif->jif_classes[pri] = cl;
  
  if (flags & JOCF_DEFAULTCLASS)
    jif->jif_default = cl;
  qtype(cl->cl_q) = Q_DROPTAIL;
  qlen(cl->cl_q) = 0;

  cl->service_rate = 0;
  cl->min_rate_adc = 0;
  cl->current_loss = 0;	
  cl->cl_period = 0;
  PKTCNTR_RESET(&cl->cl_arrival);
  PKTCNTR_RESET(&cl->cl_rin);	
  PKTCNTR_RESET(&cl->cl_rout);
  PKTCNTR_RESET(&cl->cl_rout_th);
  PKTCNTR_RESET(&cl->cl_dropcnt);	
  PKTCNTR_RESET(&cl->st_arrival);
  PKTCNTR_RESET(&cl->st_rin);	
  PKTCNTR_RESET(&cl->st_rout);
  PKTCNTR_RESET(&cl->st_dropcnt);	
  cl->st_service_rate = 0;
  cl->cl_lastdel = 0;
  cl->cl_avgdel = 0;
  cl->adc_violations = 0;

  if (adc == -1) {
    cl->concerned_ADC = 0;
    adc = INFINITY;
  } else {
    cl->concerned_ADC = 1;
  }
  if (alc == -1) {
    cl->concerned_ALC = 0;
    alc = INFINITY;
  } else {
    cl->concerned_ALC = 1;
  }
  if (rdc == -1) {
    rdc = 0;
    cl->concerned_RDC = 0;
  } else {
    cl->concerned_RDC = 1;
  }
  if (rlc == -1) {
    rlc = 0;
    cl->concerned_RLC = 0;
  } else {
    cl->concerned_RLC = 1;
  }
  if (arc == -1) {
    arc = 0;
    cl->concerned_ARC = 0;
  } else {
    cl->concerned_ARC = 1;
  }

  cl->RDC=rdc;

  if (cl->concerned_ADC) {
    /* adc is given in us, convert it to clock ticks */
    cl->ADC = (u_int64_t)(adc*machclk_freq/GRANULARITY);
  } else {
    cl->ADC = adc;
  }
  if (cl->concerned_ARC) {
    /* arc is given in bps, convert it to internal unit */
    cl->ARC = (u_int64_t)(bps2internal(arc));
  } else {
    cl->ARC = arc;
  }

  cl->RLC=rlc;
  cl->ALC=alc;
  cl->delay_prod_others = 0;
  cl->loss_prod_others = 0; 
  cl->cl_flags = flags;
  cl->cl_pri = pri;
  if (pri > jif->jif_maxpri)
    jif->jif_maxpri = pri;
  cl->cl_jif = jif;
  cl->cl_handle = (u_long)cl;  /* XXX: just a pointer to this class */

  /* update delay_prod_others and loss_prod_others
   * in all classes if needed 
   */

  if (cl->concerned_RDC) { 
    for (i = 0; i <= jif->jif_maxpri; i++) {
      scan1 = jif->jif_classes[i];
      classExists1 = (scan1 != NULL);
      if (classExists1) {
	tmp[i] = 1;
	for (j = 0; j <= i-1; j++) {
	  scan2 = jif->jif_classes[j];
	  classExists2 = (scan2 != NULL);
	  if (classExists2 && scan2->concerned_RDC)
	    tmp[i] *= scan2->RDC;
	} 
      } else 
	tmp[i] = 0; 
    }

    for (i = 0; i <= jif->jif_maxpri; i++) {
      scan1 = jif->jif_classes[i];
      classExists1 = (scan1 != NULL);
      if (classExists1) {
	scan1->delay_prod_others = 1;
	for (j = 0; j <= jif->jif_maxpri; j++) {
	  scan2 = jif->jif_classes[j];
	  classExists2 = (scan2 != NULL);
	  if (classExists2 && j != i && scan2->concerned_RDC) {
	    scan1->delay_prod_others *= tmp[j];
	  }
	}
      }
    }
  }
  
  if (cl->concerned_RLC) {
    for (i = 0; i <= jif->jif_maxpri; i++) {
      scan1 = jif->jif_classes[i];
      classExists1 = (scan1 != NULL);
      if (classExists1) {
	tmp[i] = 1;
	for (j = 0; j <= i-1; j++) {
	  scan2 = jif->jif_classes[j];
	  classExists2 = (scan2 != NULL);
	  if (classExists2 && scan2->concerned_RLC)
	    tmp[i] *= scan2->RLC;
	} 
      } else 
	tmp[i] = 0; 
    }

    for (i = 0; i <= jif->jif_maxpri; i++) {
      scan1 = jif->jif_classes[i];
      classExists1 = (scan1 != NULL);
      if (classExists1) {
	scan1->loss_prod_others = 1;
	for (j = 0; j <= jif->jif_maxpri; j++) {
	  scan2 = jif->jif_classes[j];
	  classExists2 = (scan2 != NULL);
	  if (classExists2 && j != i && scan2->concerned_RLC) {
	    scan1->loss_prod_others *= tmp[j];
	  }
	}
      }
    }
  }

  now = read_machclk();
  cl->idletime = now;

  return (cl);
  
 err_ret:
  if (cl->cl_q != NULL)
    FREE(cl->cl_q, M_DEVBUF);
  if (cl->arv_tm != NULL)
    FREE(cl->arv_tm, M_DEVBUF);

  FREE(cl, M_DEVBUF);
  return (NULL);
}

static int
jobs_class_destroy(cl)
     struct jobs_class *cl;
{
  struct jobs_if *jif;
  int s, pri;
  
  s = splimp();
  
  /* delete filters referencing to this class */
  acc_discard_filters(&cl->cl_jif->jif_classifier, cl, 0);
  
  if (!qempty(cl->cl_q))
    jobs_purgeq(cl);
  
  jif = cl->cl_jif;
  jif->jif_classes[cl->cl_pri] = NULL;
  if (jif->jif_maxpri == cl->cl_pri) {
    for (pri = cl->cl_pri; pri >= 0; pri--)
      if (jif->jif_classes[pri] != NULL) {
	jif->jif_maxpri = pri;
	break;
      }
    if (pri < 0)
      jif->jif_maxpri = -1;
  }
  splx(s);

  tslist_destroy(cl);
  FREE(cl->cl_q, M_DEVBUF);
  FREE(cl, M_DEVBUF);
  return (0);
}

/*
 * jobs_enqueue is an enqueue function to be registered to
 * (*altq_enqueue) in struct ifaltq.
 */
static int 
jobs_enqueue(ifq, m, pktattr)
     struct ifaltq *ifq;
     struct mbuf *m;
     struct altq_pktattr *pktattr;
{
  struct jobs_if	*jif = (struct jobs_if *)ifq->altq_disc;
  struct jobs_class *cl,*scan;
  int len;
  int return_flag;
  int pri;
  u_int64_t now;
  u_int64_t old_arv;
  int64_t* DeltaR;

  u_int64_t tstamp1,tstamp2,cycles; /* used for benchmarking only */

  jif->total_enqueued++;
  now = read_machclk();
  tstamp1 = now;

  return_flag = 0;

  /* proceed with packet enqueuing */

  if (IFQ_IS_EMPTY(ifq)) {
    for (pri=0; pri <= jif->jif_maxpri; pri++) {
      scan = jif->jif_classes[pri];
      if (scan) {
	PKTCNTR_RESET(&scan->cl_rin);
	PKTCNTR_RESET(&scan->cl_rout);
	PKTCNTR_RESET(&scan->cl_rout_th);
	PKTCNTR_RESET(&scan->cl_arrival);
	PKTCNTR_RESET(&scan->cl_dropcnt);	
	scan->cl_lastdel = 0;
	scan->current_loss = 0;
	scan->service_rate = 0;
	scan->idletime = now; 
	scan->cl_last_rate_update = now;
	/* reset all quantities, EXCEPT: average delay, number of violations */
      }
    }
  }


  /* grab class set by classifier */
  if (pktattr == NULL || (cl = pktattr->pattr_class) == NULL)
    cl = jif->jif_default;
  
  len = m_pktlen(m);
  old_arv = cl->cl_arrival.bytes;
  PKTCNTR_ADD(&cl->cl_arrival, (int)len);
  PKTCNTR_ADD(&cl->cl_rin, (int)len);
  PKTCNTR_ADD(&cl->st_arrival, (int)len);
  PKTCNTR_ADD(&cl->st_rin, (int)len);

  if (cl->cl_arrival.bytes < old_arv) {
    /* deals w/ overflow */
    for (pri=0; pri <= jif->jif_maxpri; pri++) {
      scan = jif->jif_classes[pri];
      if (scan) {
	PKTCNTR_RESET(&scan->cl_rin);
	PKTCNTR_RESET(&scan->cl_rout);
	PKTCNTR_RESET(&scan->cl_rout_th);
	PKTCNTR_RESET(&scan->cl_arrival);
	PKTCNTR_RESET(&scan->cl_dropcnt);	
	scan->current_loss = 0;
	scan->service_rate = 0;
	scan->idletime = now; 
	scan->cl_last_rate_update = now;
	/* reset all quantities, EXCEPT: average delay, number of violations */
      }
    }
    PKTCNTR_ADD(&cl->cl_arrival, (int)len);
    PKTCNTR_ADD(&cl->cl_rin, (int)len);
  }

  if (cl->cl_arrival.bytes > cl->cl_rin.bytes)
    cl->current_loss = ((cl->cl_arrival.bytes - cl->cl_rin.bytes) << SCALE_LOSS)/cl->cl_arrival.bytes;
  else 
    cl->current_loss = 0;

  /* for MDRR: update theoretical value of the output curve */

  for (pri=0; pri <= jif->jif_maxpri; pri++) {
    scan = jif->jif_classes[pri];
    if (scan) {
      if (scan->cl_last_rate_update == scan->idletime || scan->cl_last_rate_update == 0) {
	scan->cl_last_rate_update = now; /* initial case */
      } else {
	scan->cl_rout_th.bytes += DELAYDIFF(now,scan->cl_last_rate_update)*(scan->service_rate); 
	/* we don't really care about packets here */
	/* WARNING: rout_th is SCALED (b/c of the service rate) 
	 * for precision, as opposed to rout. 
	 */
      }
      scan->cl_last_rate_update = now;
    }
  }

  if (jobs_addq(cl, m, jif) != 0) {
    return_flag = ENOBUFS; /* signals there's a buffer overflow */
  } else {
    IFQ_INC_LEN(ifq);
  }

  /* successfully queued. */

  enforce_wc(jif); 

  if (!min_rates_adc(jif)) {
    DeltaR = assign_rate_drops_adc(jif);        
    if (DeltaR != NULL) { 
      for (pri = 0; pri <= jif->jif_maxpri; pri++) {
	if ((cl = jif->jif_classes[pri]) != NULL &&
	    !qempty(cl->cl_q)) {
	  cl->service_rate += DeltaR[pri];
	}
      }
    }
    FREE(DeltaR, M_DEVBUF);
  }
  
  DeltaR = adjust_rates_rdc(jif);
  if (DeltaR != NULL) {
    for (pri = 0; pri <= jif->jif_maxpri; pri++) {
      if ((cl = jif->jif_classes[pri]) != NULL &&
	  !qempty(cl->cl_q)) {
	cl->service_rate += DeltaR[pri];
      }
    }
  }
  FREE(DeltaR, M_DEVBUF);      
  
  tstamp2 = read_machclk();
  cycles = DELAYDIFF(tstamp2,tstamp1);
  if (cycles > jif->wc_cycles_enqueue) jif->wc_cycles_enqueue=cycles;
  if (cycles < jif->bc_cycles_enqueue) jif->bc_cycles_enqueue=cycles;

  jif->avg_cycles_enqueue += cycles;
  jif->avg_cycles2_enqueue += cycles*cycles;

  return (return_flag);
}

/*
 * jobs_dequeue is a dequeue function to be registered to
 * (*altq_dequeue) in struct ifaltq.
 *
 * note: ALTDQ_POLL returns the next packet without removing the packet
 *	from the queue.  ALTDQ_REMOVE is a normal dequeue operation.
 *	ALTDQ_REMOVE must return the same packet if called immediately
 *	after ALTDQ_POLL.
 */


static struct mbuf *
jobs_dequeue(ifq, op)
     struct ifaltq	*ifq;
     int		op;
{
  struct jobs_if	*jif = (struct jobs_if *)ifq->altq_disc;
  struct jobs_class *cl;
  struct mbuf *m;
  int pri;
  int svc_class;
  int64_t maxError;
  int64_t error;
  u_int64_t now;

  u_int64_t tstamp1,tstamp2,cycles;

  jif->total_dequeued++;

  now = read_machclk();
  tstamp1 = now;

  if (IFQ_IS_EMPTY(ifq)) {
    /* no packet in the queue */
    for (pri=0; pri <= jif->jif_maxpri; pri++) {
      cl = jif->jif_classes[pri];
      if (cl) 
	cl->idletime = now; 
    }

    tstamp2 = read_machclk();
    cycles = DELAYDIFF(tstamp2,tstamp1);
    if (cycles > jif->wc_cycles_dequeue) jif->wc_cycles_dequeue=cycles;
    if (cycles < jif->bc_cycles_dequeue) jif->bc_cycles_dequeue=cycles;

    jif->avg_cycles_dequeue += cycles;
    jif->avg_cycles2_dequeue += cycles*cycles;

    return (NULL);    
  }
   
  /* 
   * select the class whose actual tranmissions are the furthest from 
   * the promised transmissions
   */

  maxError = -1;
  svc_class = -1;

  for (pri=0; pri <= jif->jif_maxpri; pri++) {
    if (((cl = jif->jif_classes[pri]) != NULL)&& !qempty(cl->cl_q)) {
      error = (int64_t)cl->cl_rout_th.bytes-(int64_t)ScaleRate(cl->cl_rout.bytes);
      if (maxError == -1) {
	maxError = error;
	svc_class = pri;
      } else if (error > maxError){
	maxError = error;
	svc_class = pri;
      }
    }
  }
  
  
  if (svc_class != -1) {
    cl = jif->jif_classes[svc_class];
  } else
    cl = NULL;
  
  if (op == ALTDQ_POLL) {

    tstamp2 = read_machclk();
    cycles = DELAYDIFF(tstamp2,tstamp1);
    if (cycles > jif->wc_cycles_dequeue) jif->wc_cycles_dequeue=cycles;
    if (cycles < jif->bc_cycles_dequeue) jif->bc_cycles_dequeue=cycles;

    jif->avg_cycles_dequeue += cycles;
    jif->avg_cycles2_dequeue += cycles*cycles;

    return (jobs_pollq(cl));
  }

  if (cl)
    m = jobs_getq(cl);
  else
    m = NULL;

  if (m != NULL) {
    IFQ_DEC_LEN(ifq);
    if (qempty(cl->cl_q)) 
      cl->cl_period++;
    
    cl->cl_lastdel = (u_int64_t)DELAYDIFF(now,tslist_first(cl->arv_tm)->timestamp);
    if (cl->concerned_ADC && (int64_t)cl->cl_lastdel > cl->ADC)
      cl->adc_violations++;
    cl->cl_avgdel  += ticks2secs(GRANULARITY*cl->cl_lastdel);

    PKTCNTR_ADD(&cl->cl_rout, m_pktlen(m));
    PKTCNTR_ADD(&cl->st_rout, m_pktlen(m));
  }
  if (cl) tslist_dequeue(cl);		/* dequeue the timestamp */


  tstamp2 = read_machclk();
  cycles = DELAYDIFF(tstamp2,tstamp1);
  if (cycles > jif->wc_cycles_dequeue) jif->wc_cycles_dequeue=cycles;
  if (cycles < jif->bc_cycles_dequeue) jif->bc_cycles_dequeue=cycles;

  jif->avg_cycles_dequeue += cycles;
  jif->avg_cycles2_dequeue += cycles*cycles;

  return (m);
}

static int
jobs_addq(cl, m, jif)
     struct jobs_class *cl;
     struct mbuf *m;
     struct jobs_if *jif;     
{
  int victim;
  u_int64_t len;
  u_int64_t now;
  struct jobs_class* victim_class;
  
  victim = -1;
  victim_class = NULL;
  len = 0;

  now = read_machclk();

  if (jif->jif_separate && qlen(cl->cl_q) >= jif->jif_qlimit) {
    /* separate buffers: no guarantees on packet drops can be offered
     * thus we drop the incoming packet
     */
    len = (u_int64_t)m_pktlen(m);
    PKTCNTR_ADD(&cl->cl_dropcnt, (int)len);
    PKTCNTR_SUB(&cl->cl_rin, (int)len);
    PKTCNTR_ADD(&cl->st_dropcnt, (int)len);
    PKTCNTR_SUB(&cl->st_rin, (int)len);
    cl->current_loss += (len << SCALE_LOSS)/cl->cl_arrival.bytes;
    m_freem(m);
    return (-1);

  } else if (!jif->jif_separate && jif->jif_ifq->ifq_len >= jif->jif_qlimit) {
    /* shared buffer: supports guarantees on losses */
    if (!cl->concerned_RLC) {
      if (!cl->concerned_ALC) {
	/* no ALC, no RLC on this class: drop the incoming packet */
	len = (u_int64_t)m_pktlen(m);
	PKTCNTR_ADD(&cl->cl_dropcnt, (int)len);
	PKTCNTR_SUB(&cl->cl_rin, (int)len);
	PKTCNTR_ADD(&cl->st_dropcnt, (int)len);
	PKTCNTR_SUB(&cl->st_rin, (int)len);
	cl->current_loss += (len << SCALE_LOSS)/cl->cl_arrival.bytes;
	m_freem(m);
	return (-1);
      } else {
	/* no RLC, but an ALC: drop the incoming packet if possible */
	len = (u_int64_t)m_pktlen(m);
	if (cl->current_loss+(len << SCALE_LOSS)/cl->cl_arrival.bytes <= cl->ALC) {
	  PKTCNTR_ADD(&cl->cl_dropcnt, (int)len);
	  PKTCNTR_SUB(&cl->cl_rin, (int)len);
	  PKTCNTR_ADD(&cl->st_dropcnt, (int)len);
	  PKTCNTR_SUB(&cl->st_rin, (int)len);
	  cl->current_loss += (len << SCALE_LOSS)/cl->cl_arrival.bytes;
	  m_freem(m);
	  return (-1);
	} else {
	  /* the ALC would be violated: pick another class */
	  _addq(cl->cl_q, m);
	  tslist_enqueue(cl,now);

	  victim = pick_dropped_rlc(jif);
	  	  
	  if (victim == -1) {
	    /* something went wrong 
	     * let us discard the incoming packet,
	     * regardless of what may happen...
	     */
	    victim_class = cl;
	  } else {
	    victim_class = jif->jif_classes[victim];
	  }
	  
	  if (victim_class) {
	    /* test for safety purposes... it must be true */
	    m = _getq_tail(victim_class->cl_q);
	    len = (u_int64_t)m_pktlen(m);
	    PKTCNTR_ADD(&victim_class->cl_dropcnt, (int)len);
	    PKTCNTR_SUB(&victim_class->cl_rin, (int)len);
	    PKTCNTR_ADD(&victim_class->st_dropcnt, (int)len);
	    PKTCNTR_SUB(&victim_class->st_rin, (int)len);
	    victim_class->current_loss += (len << SCALE_LOSS)/victim_class->cl_arrival.bytes;
	    m_freem(m); /* the packet is trashed here */
	    tslist_drop(victim_class); /* and its timestamp as well */
	  }
	  return (-1);
	}
      }
    } else {
      /* RLC on that class: pick class according to RLCs */
      _addq(cl->cl_q, m);
      tslist_enqueue(cl,now);

      victim = pick_dropped_rlc(jif);
      if (victim == -1) {
	/* something went wrong 
	 * let us discard the incoming packet,
	 * regardless of what may happen...
	 */
	victim_class = cl;
      } else {
	victim_class = jif->jif_classes[victim];
      }

      if (victim_class) {
	/* test for safety purposes... it must be true */      
	m = _getq_tail(victim_class->cl_q);
	len = (u_int64_t)m_pktlen(m);
	PKTCNTR_ADD(&victim_class->cl_dropcnt, (int)len);
	PKTCNTR_SUB(&victim_class->cl_rin, (int)len);
	PKTCNTR_ADD(&victim_class->st_dropcnt, (int)len);
	PKTCNTR_SUB(&victim_class->st_rin, (int)len);
	victim_class->current_loss += (len << SCALE_LOSS)/victim_class->cl_arrival.bytes;
	m_freem(m); /* the packet is trashed here */
	tslist_drop(victim_class); /* and its timestamp as well */
      }
      return (-1);
    }
  }
  /* else: no drop */
  
  _addq(cl->cl_q, m);
  tslist_enqueue(cl,now);  

  return (0);
}

static struct mbuf *
jobs_getq(cl)
     struct jobs_class *cl;
{
  return _getq(cl->cl_q);
}

static struct mbuf *
jobs_pollq(cl)
     struct jobs_class *cl;
{
  return qhead(cl->cl_q);
}

static void
jobs_purgeq(cl)
     struct jobs_class *cl;
{
  struct mbuf *m;
  
  if (qempty(cl->cl_q))
    return;
  
  while ((m = _getq(cl->cl_q)) != NULL) {
    PKTCNTR_ADD(&cl->cl_dropcnt, m_pktlen(m));
    PKTCNTR_ADD(&cl->st_dropcnt, m_pktlen(m));
    m_freem(m);
    tslist_drop(cl);
  }
  ASSERT(qlen(cl->cl_q) == 0);
}

/*
 * timestamp list support routines 
 */
/*
 * timestamp list holds class timestamps
 * there is one timestamp list per class.
 */
static tslist_t *
tslist_alloc()
{
  tslist_t *list_init;
  
  MALLOC(list_init, tslist_t *, sizeof(tslist_t), M_DEVBUF, M_WAITOK);
  
  if (!list_init) {
    FREE(list_init, M_DEVBUF);
    return (NULL);
  }
  
  list_init->nr_elts = 0;
  list_init->head = NULL;
  list_init->tail = NULL;
  return (list_init);
}
static void
tslist_destroy(cl)
     struct jobs_class *cl;
{
  while (tslist_first(cl->arv_tm) != NULL)
    tslist_dequeue(cl);

  FREE(cl->arv_tm, M_DEVBUF);
}

static int
tslist_enqueue(cl,arv)
     struct jobs_class *cl;
     u_int64_t arv;
{    
  tsentry_t *pushed;
  MALLOC(pushed, tsentry_t*, sizeof(tsentry_t), M_DEVBUF, M_WAITOK);  
  if (!pushed) {
    FREE(pushed, M_DEVBUF);
    return (0);
  }
  
  pushed->timestamp = arv;
  
  if (tslist_empty(cl->arv_tm)) {
    pushed->next = NULL;
    pushed->prev = NULL;
    tslist_first(cl->arv_tm) = pushed;
    tslist_last(cl->arv_tm) = pushed;
  } else {
    tslist_last(cl->arv_tm)->next = pushed;
    pushed->prev = tslist_last(cl->arv_tm);
    pushed->next = NULL;
    tslist_last(cl->arv_tm) = pushed; 
  }
  cl->arv_tm->nr_elts++;
  return (1);
}

static void 
tslist_dequeue(cl)
     struct jobs_class *cl;
{
  tsentry_t *popped;
  popped = tslist_first(cl->arv_tm);
  if (popped) {
    tslist_first(cl->arv_tm) = popped->next;
    if (popped->next) 
      popped->next->prev = NULL;
    else {
      tslist_last(cl->arv_tm) = NULL;
    }
    FREE(popped, M_DEVBUF);
    cl->arv_tm->nr_elts--;
  }
  return;
}

static void 
tslist_drop(cl)
     struct jobs_class *cl;
{
  tsentry_t *popped;
  popped = tslist_last(cl->arv_tm);
  if (popped) {
    tslist_last(cl->arv_tm) = popped->prev;
    if (popped->prev) 
      popped->prev->next = NULL;
    else {
      tslist_first(cl->arv_tm) = NULL;
    }
    FREE(popped, M_DEVBUF);
    cl->arv_tm->nr_elts--;
  }
  return;
}

/*
 * rate allocation support routines
 */
/*
 * enforce_wc: enforce that backlogged classes have non-zero
 * service rate, and that non-backlogged classes have zero
 * service rate.
 */

static int 
enforce_wc(jif) 
     struct jobs_if *jif;
{
  struct jobs_class *cl;

  int64_t activeClasses;
  int pri;
  int isBacklogged, classExists, updated;

  updated = 0;
  activeClasses = 0;
  
  for (pri = 0; pri <= jif->jif_maxpri; pri++) {
    cl = jif->jif_classes[pri];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));

    if (isBacklogged) 
      activeClasses++;
    if ((isBacklogged && cl->service_rate <= 0)
	||(classExists && !isBacklogged && cl->service_rate > 0))
      updated = 1;
  }

  if (updated) {
    for (pri = 0; pri <= jif->jif_maxpri; pri++) {
      cl = jif->jif_classes[pri];
      classExists = (cl != NULL);
      isBacklogged = (classExists && !qempty(cl->cl_q));

      if (classExists && !isBacklogged) {
	cl->service_rate = 0;
      } else if (isBacklogged) {
	cl->service_rate = (int64_t)(bps2internal((u_int64_t)jif->jif_bandwidth)/activeClasses);
      }
    }
  }
  
  return (updated);
}

/*
 * adjust_rates_rdc: compute the service rates adjustments 
 * needed to realize the desired proportional delay differentiation.
 * essentially, the rate adjustement DeltaR = Kp*error,
 * where error is the difference between the measured "weighted"
 * delay and the mean of the weighted delays. see paper for more 
 * information.
 * Kp is computed slightly differently from the paper - this 
 * condition seems to provide better results.
 */

static int64_t*
adjust_rates_rdc(jif)
     struct jobs_if *jif;
{
  int64_t* result;
  int64_t  credit,available,lower_bound,upper_bound;
  int64_t  bk;
  int i,j;
  int RDC_Classes,activeClasses;
  int classExists, isBacklogged;
  struct jobs_class *cl; 
  int64_t* error;
  int64_t Kp;
  u_int64_t max_prod;

  u_int64_t min_share;
  u_int64_t max_avg_pkt_size;

  /* min_share is scaled 
   * to avoid dealing with doubles
   */

  activeClasses = 0;
  RDC_Classes = 0;
  max_prod = 0;  
  max_avg_pkt_size = 0;

  upper_bound = (int64_t)jif->jif_bandwidth;

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged) {
      activeClasses++;
      if (cl->concerned_RDC) 
	RDC_Classes++;
      else 
	upper_bound -= internal2bps(cl->service_rate);
    }
  }

  MALLOC(result, int64_t*, jif->jif_maxpri*sizeof(int64_t), M_DEVBUF, M_WAITOK);
  
  if (!result) {
    FREE(result, M_DEVBUF);
    return NULL;
  }

  for (i = 0; i <= jif->jif_maxpri; i++) 
    result[i] = 0;

  if (upper_bound <= 0 || RDC_Classes == 0) return result;

  credit = 0;
  lower_bound = 0;
  min_share = ((u_int64_t)1 << SCALE_SHARE);
  bk = 0;

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged && cl->concerned_RDC)
      bk += cl->cl_rin.bytes;
  }

  if (bk == 0) return (result); 

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged && (cl->cl_rin.bytes << SCALE_SHARE)/bk < min_share)
      min_share = (cl->cl_rin.bytes << SCALE_SHARE)/bk;
    if (isBacklogged && cl->concerned_RDC && cl->delay_prod_others > max_prod)
      max_prod = cl->delay_prod_others;


    if (isBacklogged && cl->concerned_RDC && cl->cl_rin.bytes > max_avg_pkt_size*cl->cl_rin.packets)
      max_avg_pkt_size = (u_int64_t)((u_int)cl->cl_rin.bytes/(u_int)cl->cl_rin.packets);

  }

  error = update_error(jif);
  if (!error) return (NULL);

  Kp = (upper_bound*upper_bound*min_share)
    /(max_prod*(max_avg_pkt_size << 2));

  
  Kp = bps2internal(ticks2secs(Kp)); /* in BT-1 */

  credit = 0;
  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged && cl->concerned_RDC) {
      result[i] = -Kp*error[i]; /* in BT-1 */
      result[i] >>= (SCALE_SHARE); 
    }
  }    


  FREE(error,M_DEVBUF); /* we don't need these anymore */

  /* saturation */

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));

    if (isBacklogged && cl->concerned_RDC) 
      lower_bound += cl->min_rate_adc; /* note: if there's no ADC or ARC on cl, 
					* this is equal to zero, which is fine 
					*/
  }

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));

    if (isBacklogged && cl->concerned_RDC && result[i] + cl->service_rate > upper_bound) {
      for (j = 0; j <= jif->jif_maxpri; j++) {
	cl = jif->jif_classes[j];
	classExists = (cl != NULL);
	isBacklogged = (classExists && !qempty(cl->cl_q));
	if (isBacklogged && cl->concerned_RDC) {
	  if (j == i) 
	    result[j] = (upper_bound-cl->service_rate)  
	      + cl->min_rate_adc - lower_bound;
	  else
	    result[j] = -cl->service_rate+cl->min_rate_adc;
	}
      }
      return result;
    }

    cl = jif->jif_classes[i]; /* redo this since it may have been modified */
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));

    if (isBacklogged && cl->concerned_RDC && result[i] + cl->service_rate < cl->min_rate_adc) {
      credit    += cl->service_rate+result[i]-cl->min_rate_adc; 
      /* "credit" is in fact a negative number */
      result[i] = -cl->service_rate+cl->min_rate_adc;
    }
  }

  for (i = jif->jif_maxpri; (i >= 0 && credit < 0); i--) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
 
    if (isBacklogged && cl->concerned_RDC) {
      available = result[i] + cl->service_rate-cl->min_rate_adc;
      if (available >= -credit) {
	result[i] += credit;
	credit = 0;
      } else {
	result[i] -= available;
	credit += available;
      }      
    }
  }
  return result;
}

/*
 * assign_rate_drops_adc: returns the adjustment needed to 
 * the service rates to meet the absolute delay/rate constraints 
 * (delay/throughput bounds) and drops traffic if need be. 
 * see tech. report UVA/T.R. CS-2000-24/CS-2001-21 for more info.
 */

static int64_t*
assign_rate_drops_adc(jif)
     struct jobs_if* jif;
{
  int64_t* result;
  int classExists,isBacklogged;
  struct jobs_class *cl;
 
  int64_t *c, *n, *k;
  int64_t *available;

  int lowest, highest;
  int keep_going;
  int i;
  u_int64_t now,oldest_arv;

  struct mbuf* pkt;
  u_int64_t len;

  now = read_machclk();
  oldest_arv = now;

  MALLOC(result, int64_t*, jif->jif_maxpri*sizeof(int64_t), M_DEVBUF, M_WAITOK);  
  if (!result) {
    FREE(result, M_DEVBUF);
    return NULL;
  }  
  MALLOC(c, int64_t*, jif->jif_maxpri*sizeof(u_int64_t), M_DEVBUF, M_WAITOK);  
  if (!c) {
    FREE(c, M_DEVBUF);
    return NULL;
  }
  MALLOC(n, int64_t*, jif->jif_maxpri*sizeof(u_int64_t), M_DEVBUF, M_WAITOK);  
  if (!n) {
    FREE(n, M_DEVBUF);
    return NULL;
  }
  MALLOC(k, int64_t*, jif->jif_maxpri*sizeof(u_int64_t), M_DEVBUF, M_WAITOK);  
  if (!k) {
    FREE(k, M_DEVBUF);
    return NULL;
  }
  MALLOC(available, int64_t*, jif->jif_maxpri*sizeof(int64_t), M_DEVBUF, M_WAITOK);
  if (!available) {
    FREE(available, M_DEVBUF);
    return NULL;
  }
  
  for (i = 0;i <= jif->jif_maxpri; i++) 
    result[i] = 0;

  keep_going = 1;

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));

    if (isBacklogged) {
      if (cl->concerned_ADC) {
	/* get the arrival time of the oldest class-i packet */
	if (!tslist_first(cl->arv_tm)) 
	  oldest_arv = now; /* shouldn't be reached */
	else
	  oldest_arv = (tslist_first(cl->arv_tm))->timestamp; 

	n[i] = cl->service_rate;
	k[i] = ScaleRate((int64_t)(cl->cl_rin.bytes - cl->cl_rout.bytes));
	
	if (cl->ADC > (int64_t)DELAYDIFF(now,oldest_arv)) {
	  c[i] = cl->ADC - (int64_t)DELAYDIFF(now,oldest_arv);  	
	  /* this is the remaining time before 
	   * the deadline is violated (in ticks)
	   */	
	  available[i] = n[i]-k[i]/c[i];      
	} else {
	  /* deadline has passed... */
	  /* we allocate the whole link capacity to hopefully solve the problem */
	  c[i] = 0;	  
	  available[i] = -((int64_t)bps2internal((u_int64_t)jif->jif_bandwidth));
	}
	if (cl->concerned_ARC) {
	  /* there's an ARC in addition to the ADC */
	  if (n[i] - cl->ARC < available[i])
	    available[i] = n[i] - cl->ARC;
	}
      } else if (cl->concerned_ARC) {
	/* backlogged, concerned by ARC but not by ADC */
	n[i] = cl->service_rate;
	available[i] = n[i] - cl->ARC;
      } else {
	/* backlogged but not concerned by ADC or ARC -> can give everything */
	n[i] = cl->service_rate;
	available[i] = n[i];
      }
    } else {
      /* not backlogged */
      n[i] = 0;
      k[i] = 0;
      c[i] = 0;
      if (classExists)
	available[i] = cl->service_rate;
      else
	available[i] = 0;
    }
  }

  /* step 1: adjust rates (greedy algorithm) */

  highest = 0;
  lowest  = jif->jif_maxpri;

  while (highest < jif->jif_maxpri+1 && available[highest] >= 0)
    highest++; /* which is the highest class that needs more service? */
  while (lowest > 0 && available[lowest] <= 0)
    lowest--;  /* which is the lowest class that needs less service? */


  while (highest != jif->jif_maxpri+1 && lowest != -1) {
    /* give the excess service from lowest to highest */
    if (available[lowest]+available[highest] > 0) {
      /* still some "credit" left 
       * give all that is needed by "highest" 
       */
      n[lowest]  += available[highest];
      n[highest] -= available[highest];
      
      available[lowest]  += available[highest];
      available[highest] = 0;

      while (highest < jif->jif_maxpri+1 && available[highest] >= 0)
	highest++;  /* which is the highest class that needs more service? */
      
    } else if (available[lowest]+available[highest] == 0) {
      /* no more credit left but it's fine */
      n[lowest]  += available[highest];
      n[highest] -= available[highest];
      
      available[highest] = 0;
      available[lowest]  = 0;

      while (highest < jif->jif_maxpri+1 && available[highest] >= 0)
	highest++;  /* which is the highest class that needs more service? */
      while ((lowest >= 0)&&(available[lowest] <= 0))
	lowest--;   /* which is the lowest class that needs less service? */

    } else if (available[lowest]+available[highest] < 0) {
      /* no more credit left and we need to switch to another class */
      n[lowest]  -= available[lowest];
      n[highest] += available[lowest];

      available[highest] += available[lowest];
      available[lowest]  = 0;

      while ((lowest >= 0)&&(available[lowest] <= 0))
	lowest--;  /* which is the lowest class that needs less service? */
    }
  }

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged) {
      result[i] = n[i] - cl->service_rate;
    } else {
      if (classExists)
	result[i] = - cl->service_rate;
      else
	result[i] = 0;
    }
  }

  /* step 2: adjust drops (for ADC) */

  if (highest != jif->jif_maxpri+1) {
    /* some class(es) still need(s) additional service */
    for (i = 0; i <= jif->jif_maxpri; i++) {
      cl = jif->jif_classes[i];
      classExists = (cl != NULL);
      isBacklogged = (classExists && !qempty(cl->cl_q));
      if (isBacklogged && available[i] < 0) {
	if (cl->concerned_ADC) {
	  k[i] = c[i]*n[i];
	  while (keep_going && ScaleRate((int64_t)(cl->cl_rin.bytes-cl->cl_rout.bytes)) > k[i]) {
	    pkt = qtail(cl->cl_q);
	    if (pkt) {		/* "safeguard" test (a packet SHOULD be in there) */
	      len = (u_int64_t)m_pktlen(pkt);
	    /* access packet at the tail */
	      if (cl->concerned_ALC && cl->current_loss+(len << SCALE_LOSS)/cl->cl_arrival.bytes > cl->ALC) {	  
		keep_going = 0; /* relax ADC in favor of ALC */
	      } else {
		/* drop packet at the tail of the class-i queue, update values */
		pkt = _getq_tail(cl->cl_q);
		len = (u_int64_t)m_pktlen(pkt);
		PKTCNTR_ADD(&cl->cl_dropcnt, (int)len);
		PKTCNTR_SUB(&cl->cl_rin, (int)len);
		PKTCNTR_ADD(&cl->st_dropcnt, (int)len);
		PKTCNTR_SUB(&cl->st_rin, (int)len);
		cl->current_loss += (len << SCALE_LOSS)/cl->cl_arrival.bytes;
		m_freem(pkt); /* the packet is trashed here */
		tslist_drop(cl);
		IFQ_DEC_LEN(cl->cl_jif->jif_ifq);
	      }
	    } else keep_going = 0;
	  }
	  k[i] = ScaleRate((int64_t)(cl->cl_rin.bytes-cl->cl_rout.bytes));
	} 	
	/* n[i] is the max rate we can give. the above drops as much as possible
	 * to respect a delay bound.
	 * for throughput bounds, there's nothing that can be done after the greedy reallocation.
	 */
      }            
    }
  } 

  /* update the values of min_rate_adc */
  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged && cl->concerned_ADC) {
      if (c[i] != 0) {
	if (cl->concerned_ADC && !cl->concerned_ARC) {
	  cl->min_rate_adc = k[i]/c[i]; 
	} else cl->min_rate_adc = n[i]; 
      } else {
	cl->min_rate_adc = (int64_t)bps2internal((u_int64_t)jif->jif_bandwidth);
      }
    } else if (isBacklogged && cl->concerned_ARC) {
      cl->min_rate_adc = n[i]; /* that's the best we can give */
    } else {
      if (classExists)
	cl->min_rate_adc = 0;    
    }
  }

  FREE(c, M_DEVBUF);
  FREE(n, M_DEVBUF);
  FREE(k, M_DEVBUF);
  FREE(available, M_DEVBUF);

  return (result);
}

/*
 * update_error: returns the difference between the mean weighted
 * delay and the weighted delay for each class. if proportional 
 * delay differentiation is perfectly achieved, it should return 
 * zero for each class. 
 */
static int64_t*
update_error(jif)
     struct jobs_if* jif;
{
  int		i;
  int	activeClasses,backloggedClasses;
  u_int64_t	meanWeightedDelay;
  u_int64_t	delays[JOBS_MAXPRI];
  int64_t*	error;
  int classExists, isBacklogged;
  struct jobs_class *cl;

  MALLOC(error, int64_t*, sizeof(int64_t)*jif->jif_maxpri, M_DEVBUF, M_WAITOK);
  
  if (!error) {
    FREE(error, M_DEVBUF);
    return NULL;
  }

  bzero(error,sizeof(int64_t)*jif->jif_maxpri);

  meanWeightedDelay = 0;
  activeClasses = 0 ; 
  backloggedClasses = 0;
  
  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));

    if (isBacklogged) {
      backloggedClasses++;
      if (cl->concerned_RDC) {
	delays[i] = proj_delay(jif,i);
	meanWeightedDelay += cl->delay_prod_others*delays[i];
	activeClasses ++;
      }    
    }
  }
   

  if (activeClasses == 0) 
    return error;
  else  
    meanWeightedDelay /= activeClasses;

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
 
    if (isBacklogged && cl->concerned_RDC) 
      error[i] = ((int64_t)meanWeightedDelay)-((int64_t)cl->delay_prod_others*delays[i]);
    else 
      error[i] = 0; /* either the class isn't concerned, or it's not backlogged
		     * in any case, the rate shouldn't be adjusted. 
		     */    
  }
  return error;
}

/*
 * min_rates_adc: computes the minimum service rates needed in 
 * each class to meet the absolute delay bounds. if, for any 
 * class i, the current service rate of class i is less than 
 * the computed minimum service rate, this function returns 
 * false, true otherwise.
 */
static int
min_rates_adc(jif)
     struct jobs_if* jif;
{
  int result;
  int i;
  int classExists, isBacklogged;
  struct jobs_class *cl;
  result = 1;  

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged && cl->concerned_ADC) {            
      if (cl->ADC - proj_delay(jif,i) > 0 ) {
	/* min rate needed for ADC */	
	cl->min_rate_adc = (ScaleRate((int64_t)(cl->cl_rin.bytes-cl->cl_rout.bytes)))/(cl->ADC - proj_delay(jif,i));
	if (cl->concerned_ARC && cl->ARC > cl->min_rate_adc) {
	  /* min rate needed for ADC + ARC */
	  cl->min_rate_adc = cl->ARC;
	}
      } else {
	cl->min_rate_adc = (int64_t)bps2internal((u_int64_t)jif->jif_bandwidth);       
	/* the deadline has been exceeded: give the whole link capacity to hopefully fix the situation */
      }
      
    } else if (isBacklogged && cl->concerned_ARC) {
      /* no ADC, an ARC */
      cl->min_rate_adc = cl->ARC;
    } else if (classExists) {
      /* either the class is not backlogged or there is no ADC and no ARC */
      cl->min_rate_adc = 0;	
    }
    if (isBacklogged && cl->min_rate_adc > cl->service_rate) result = 0;
  }

  return result;
}

/*
 * proj_delay: computes the difference between the current time
 * and the time the oldest class-i packet still in the class-i
 * queue i arrived in the system.
 */
static int64_t
proj_delay(jif,i)
     struct jobs_if* jif;
     int i;
{
  u_int64_t now;
  int classExists,isBacklogged;
  struct jobs_class *cl;

  now = read_machclk();
  cl = jif->jif_classes[i];
  classExists = (cl != NULL);
  isBacklogged = (classExists && !qempty(cl->cl_q));

  if (isBacklogged) 
    return ((int64_t)DELAYDIFF(now,tslist_first(cl->arv_tm)->timestamp));

  return (0); /* this statement should *not* be reached */
}

/*
 * pick_dropped_rlc: returns the class index of the class to be 
 * dropped for meeting the relative loss constraints.
 */
static int
pick_dropped_rlc(jif)
     struct jobs_if* jif;
{
  int64_t Mean;
  int64_t* loss_error;
  int i,activeClasses,backloggedClasses;
  int classExists,isBacklogged;
  int class_dropped;
  int64_t maxError;
  int64_t maxALC;
  struct mbuf* pkt;
  struct jobs_class *cl;
  u_int64_t len;

  MALLOC(loss_error, int64_t *, sizeof(int64_t)*jif->jif_maxpri, M_DEVBUF, M_WAITOK);  
  
  if (!loss_error) {
    FREE(loss_error, M_DEVBUF);
    return -1;
  }
  
  class_dropped = -1;
  maxError = 0;
  Mean = 0;
  activeClasses = 0;
  backloggedClasses = 0;

  for (i = 0; i <= jif->jif_maxpri; i++) {
    cl = jif->jif_classes[i];
    classExists = (cl != NULL);
    isBacklogged = (classExists && !qempty(cl->cl_q));
    if (isBacklogged) {
      backloggedClasses ++;
      if (cl->concerned_RLC) {
	Mean += cl->loss_prod_others*cl->current_loss;
	activeClasses ++;
      }    
    }
  }

  if (activeClasses > 0) 
    Mean /= activeClasses;

  if (activeClasses == 0) 
    class_dropped = JOBS_MAXPRI+1; /* no classes are concerned by RLCs (JOBS_MAXPRI+1 means "ignore RLC" here) */
  else {
    for (i = 0; i <= jif->jif_maxpri; i++) {
      cl = jif->jif_classes[i];
      classExists = (cl != NULL);
      isBacklogged = (classExists && !qempty(cl->cl_q));
      
      if ((isBacklogged)&&(cl->RLC)) 
	loss_error[i]=cl->loss_prod_others*cl->current_loss-Mean;
      else loss_error[i] = INFINITY;
    }
    
    for (i = 0; i <= jif->jif_maxpri; i++) {
      cl = jif->jif_classes[i];
      classExists = (cl != NULL);
      isBacklogged = (classExists && !qempty(cl->cl_q));
      if (isBacklogged && loss_error[i] <= maxError) {
	maxError = loss_error[i]; /* Find out which class is the most below the mean */
	class_dropped = i;   /* It's the one that needs to be dropped 
			      * Ties are broken in favor of the higher 
			      * priority classes (i.e., if two classes 
			      * present the same deviation, the lower 
			      * priority class will get dropped).
			      */
      } 
    }
    
    if (class_dropped != -1) {
      cl = jif->jif_classes[class_dropped];
      pkt = qtail(cl->cl_q);
      if (pkt) {		/* "safeguard" test (a packet SHOULD be in there) */
	len = (u_int64_t)m_pktlen(pkt);
	/* access packet at the tail */
	if (cl->current_loss+(len << SCALE_LOSS)/cl->cl_arrival.bytes > cl->ALC) {	  
	  /* the class to drop for meeting the RLC will defeat the ALC: ignore RLC. */
	  class_dropped = JOBS_MAXPRI+1; 
	}
      } else class_dropped = JOBS_MAXPRI+1; /* this statement should not be reached */
    } else class_dropped = JOBS_MAXPRI+1;
  }

  /* the following segment of code has yet to be extensively tested
   * (it appears to work, though)
   */
  if (class_dropped == JOBS_MAXPRI+1) {
    maxALC = -((int64_t)1 << SCALE_LOSS);
    for (i = jif->jif_maxpri; i >= 0; i--) {
      cl = jif->jif_classes[i];
      classExists = (cl != NULL);
      isBacklogged = (classExists && !qempty(cl->cl_q));
      if (isBacklogged) {
	if (cl->concerned_ALC && cl->ALC - cl->current_loss > maxALC) {
	  maxALC = cl->ALC-cl->current_loss; /* pick the class which is the furthest from its ALC */
	  class_dropped = i;
	} else if (!cl->concerned_ALC && ((int64_t) 1 << SCALE_LOSS)-cl->current_loss > maxALC) {
	  maxALC = ((int64_t) 1 << SCALE_LOSS)-cl->current_loss; 
	  class_dropped = i;
	}
      }
    }
  }

  FREE(loss_error, M_DEVBUF);
  return (class_dropped);
}

/* 
 * ALTQ binding/setup functions (taken from Kenjiro's code)
 */
/*
 * jobs device interface
 */
int
jobsopen(dev, flag, fmt, p)
     dev_t dev;
     int flag, fmt;
     struct proc *p;
{
  if (machclk_freq == 0)
    init_machclk();

  if (machclk_freq == 0) {
    printf("jobs: no cpu clock available!\n");
    return (ENXIO);
  }
  /* everything will be done when the queueing scheme is attached. */
  return 0;
}

int
jobsclose(dev, flag, fmt, p)
     dev_t dev;
     int flag, fmt;
     struct proc *p;
{
  struct jobs_if *jif;
  int err, error = 0;
  
  while ((jif = jif_list) != NULL) {
    /* destroy all */
    if (ALTQ_IS_ENABLED(jif->jif_ifq))
      altq_disable(jif->jif_ifq);
    
    err = altq_detach(jif->jif_ifq);
    if (err == 0)
      err = jobs_detach(jif);
    if (err != 0 && error == 0)
      error = err;
  }
  
  return error;
}

int
jobsioctl(dev, cmd, addr, flag, p)
     dev_t dev;
     ioctlcmd_t cmd;
     caddr_t addr;
     int flag;
     struct proc *p;
{
  struct jobs_if *jif;
  struct jobs_interface *ifacep;
  int	error = 0;
  
  /* check super-user privilege */
  switch (cmd) {
  case JOBS_GETSTATS:
    break;
  default:
#if (__FreeBSD_version > 400000)
    if ((error = suser(p)) != 0)
      return (error);
#else
    if ((error = suser(p->p_ucred, &p->p_acflag)) != 0)
      return (error);
#endif
    break;
  }
  
  switch (cmd) {
    
  case JOBS_IF_ATTACH:
    error = jobscmd_if_attach((struct jobs_attach *)addr);
    break;
    
  case JOBS_IF_DETACH:
    error = jobscmd_if_detach((struct jobs_interface *)addr);
    break;
    
  case JOBS_ENABLE:
  case JOBS_DISABLE:
  case JOBS_CLEAR:
    ifacep = (struct jobs_interface *)addr;
    if ((jif = altq_lookup(ifacep->jobs_ifname,
			   ALTQT_JOBS)) == NULL) {
      error = EBADF;
      break;
    }
    
    switch (cmd) {
    case JOBS_ENABLE:
      if (jif->jif_default == NULL) {
#if 1
	printf("jobs: no default class\n");
#endif
	error = EINVAL;
	break;
      }
      error = altq_enable(jif->jif_ifq);
      break;
      
    case JOBS_DISABLE:
      error = altq_disable(jif->jif_ifq);
      break;
      
    case JOBS_CLEAR:
      jobs_clear_interface(jif);
      break;
    }
    break;
    
  case JOBS_ADD_CLASS:
    error = jobscmd_add_class((struct jobs_add_class *)addr);
    break;
    
  case JOBS_DEL_CLASS:
    error = jobscmd_delete_class((struct jobs_delete_class *)addr);
    break;
    
  case JOBS_MOD_CLASS:
    error = jobscmd_modify_class((struct jobs_modify_class *)addr);
    break;
    
  case JOBS_ADD_FILTER:
    error = jobscmd_add_filter((struct jobs_add_filter *)addr);
    break;
    
  case JOBS_DEL_FILTER:
    error = jobscmd_delete_filter((struct jobs_delete_filter *)addr);
    break;
    
  case JOBS_GETSTATS:
    error = jobscmd_class_stats((struct jobs_class_stats *)addr);
    break;
    
  default:
    error = EINVAL;
    break;
  }
  return error;
}

static int
jobscmd_if_attach(ap)
     struct jobs_attach *ap;
{
  struct jobs_if *jif;
  struct ifnet *ifp;
  int error;
  
  if ((ifp = ifunit(ap->iface.jobs_ifname)) == NULL)
    return (ENXIO);
  if ((jif = jobs_attach(&ifp->if_snd, ap->bandwidth, ap->qlimit, ap->separate)) == NULL)
    return (ENOMEM);
  
  /*
   * set JOBS to this ifnet structure.
   */
  if ((error = altq_attach(&ifp->if_snd, ALTQT_JOBS, jif,
			   jobs_enqueue, jobs_dequeue, jobs_request,
			   &jif->jif_classifier, acc_classify)) != 0)
    (void)jobs_detach(jif);
  
  return (error);
}

static int
jobscmd_if_detach(ap)
     struct jobs_interface *ap;
{
  struct jobs_if *jif;
  int error;
  
  if ((jif = altq_lookup(ap->jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);
  
  if (ALTQ_IS_ENABLED(jif->jif_ifq))
    altq_disable(jif->jif_ifq);
  
  if ((error = altq_detach(jif->jif_ifq)))
    return (error);
  
  return jobs_detach(jif);
}

static int
jobscmd_add_class(ap)
     struct jobs_add_class *ap;
{
  struct jobs_if *jif;
  struct jobs_class *cl;

  if ((jif = altq_lookup(ap->iface.jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);

  if (ap->pri < 0 || ap->pri >= JOBS_MAXPRI)
    return (EINVAL);

  if ((cl = jobs_class_create(jif, 
			      ap->pri, 
			      ap->ADC, ap->RDC, 
			      ap->ALC, ap->RLC, ap-> ARC,
			      ap->flags)) == NULL)
    return (ENOMEM);
  
  /* return a class handle to the user */
  ap->class_handle = clp_to_clh(cl);
  return (0);
}

static int
jobscmd_delete_class(ap)
     struct jobs_delete_class *ap;
{
  struct jobs_if *jif;
  struct jobs_class *cl;
  
  if ((jif = altq_lookup(ap->iface.jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);
  
  if ((cl = clh_to_clp(jif, ap->class_handle)) == NULL)
    return (EINVAL);

  return jobs_class_destroy(cl);
}

static int
jobscmd_modify_class(ap)
     struct jobs_modify_class *ap;
{
  struct jobs_if *jif;
  struct jobs_class *cl;

  if ((jif = altq_lookup(ap->iface.jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);
  
  if (ap->pri < 0 || ap->pri >= JOBS_MAXPRI)
    return (EINVAL);
  
  if ((cl = clh_to_clp(jif, ap->class_handle)) == NULL)
    return (EINVAL);
  
  /*
   * if priority is changed, move the class to the new priority
   */
  if (jif->jif_classes[ap->pri] != cl) {
    if (jif->jif_classes[ap->pri] != NULL)
      return (EEXIST);
    jif->jif_classes[cl->cl_pri] = NULL;
    jif->jif_classes[ap->pri] = cl;
    cl->cl_pri = ap->pri;
  }
  
  /* call jobs_class_create to change class parameters */
  if ((cl = jobs_class_create(jif, 
			      ap->pri, 
			      ap->ADC, ap->RDC, 
			      ap->ALC, ap->RLC, ap->ARC,
			      ap->flags)) == NULL)
    return (ENOMEM);
  return 0;
}

static int
jobscmd_add_filter(ap)
     struct jobs_add_filter *ap;
{
  struct jobs_if *jif;
  struct jobs_class *cl;
  
  if ((jif = altq_lookup(ap->iface.jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);
  
  if ((cl = clh_to_clp(jif, ap->class_handle)) == NULL)
    return (EINVAL);
  
  return acc_add_filter(&jif->jif_classifier, &ap->filter,
			cl, &ap->filter_handle);
}

static int
jobscmd_delete_filter(ap)
     struct jobs_delete_filter *ap;
{
  struct jobs_if *jif;
  
  if ((jif = altq_lookup(ap->iface.jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);
  
  return acc_delete_filter(&jif->jif_classifier,
			   ap->filter_handle);
}

static int
jobscmd_class_stats(ap)
     struct jobs_class_stats *ap;
{
  struct jobs_if *jif;
  struct jobs_class *cl;
  struct class_stats stats, *usp;
  int	pri, error;
  
  if ((jif = altq_lookup(ap->iface.jobs_ifname, ALTQT_JOBS)) == NULL)
    return (EBADF);
  
  ap->maxpri = jif->jif_maxpri;
  
  /* then, read the next N classes in the tree */
  usp = ap->stats;
  for (pri = 0; pri <= jif->jif_maxpri; pri++) {
    cl = jif->jif_classes[pri];
    if (cl != NULL)
      get_class_stats(&stats, cl);
    else
      bzero(&stats, sizeof(stats));
    if ((error = copyout((caddr_t)&stats, (caddr_t)usp++,
			 sizeof(stats))) != 0)
      return (error);
  }
  return (0);
}

static void get_class_stats(sp, cl)
     struct class_stats *sp;
     struct jobs_class *cl;
{
  u_int64_t now;
  now = read_machclk();

  sp->class_handle = clp_to_clh(cl);
  
  sp->qlength = qlen(cl->cl_q);
  if (cl->arv_tm) {
    sp->ts_elts = cl->arv_tm->nr_elts;
  } else 
    sp->ts_elts = 0;
  sp->period = cl->cl_period;
 
  sp->rin = cl->st_rin;
  sp->arrival = cl->st_arrival;
  sp->arrivalbusy = cl->cl_arrival;
  sp->rout = cl->st_rout; 
  sp->dropcnt = cl->cl_dropcnt; 

  /*  PKTCNTR_RESET(&cl->st_arrival);*/
  PKTCNTR_RESET(&cl->st_rin);
  PKTCNTR_RESET(&cl->st_rout);

  sp->qlensez = qlen(cl->cl_q);
  sp->totallength = cl->cl_jif->jif_ifq->ifq_len;
  sp->lastdel = ticks2secs(GRANULARITY*cl->cl_lastdel); 
  sp->avgdel = cl->cl_avgdel;

  cl->cl_avgdel = 0;

  sp->busylength = ticks2secs(1000*DELAYDIFF(now,cl->idletime));
  sp->adc_violations = cl->adc_violations;

  sp->wc_cycles_enqueue = cl->cl_jif->wc_cycles_enqueue;
  sp->wc_cycles_dequeue = cl->cl_jif->wc_cycles_dequeue;
  sp->bc_cycles_enqueue = cl->cl_jif->bc_cycles_enqueue;
  sp->bc_cycles_dequeue = cl->cl_jif->bc_cycles_dequeue;
  sp->avg_cycles_enqueue = cl->cl_jif->avg_cycles_enqueue;
  sp->avg_cycles_dequeue = cl->cl_jif->avg_cycles_dequeue;
  sp->avg_cycles2_enqueue = cl->cl_jif->avg_cycles2_enqueue;
  sp->avg_cycles2_dequeue = cl->cl_jif->avg_cycles2_dequeue;
  sp->total_enqueued = cl->cl_jif->total_enqueued;
  sp->total_dequeued = cl->cl_jif->total_dequeued;
}

/* convert a class handle to the corresponding class pointer */
static struct jobs_class *
clh_to_clp(jif, chandle)
     struct jobs_if *jif;
     u_long chandle;
{
  struct jobs_class *cl;
  
  cl = (struct jobs_class *)chandle;
  if (chandle != ALIGN(cl)) {
#if 1
    printf("clh_to_cl: unaligned pointer %p\n", cl);
#endif
    return (NULL);
  }
  
  if (cl == NULL || cl->cl_handle != chandle || cl->cl_jif != jif)
    return (NULL);
  return (cl);
}

/* convert a class pointer to the corresponding class handle */
static u_long
clp_to_clh(cl)
     struct jobs_class *cl;
{
  return (cl->cl_handle);
}

#ifdef KLD_MODULE

static struct altqsw jobs_sw =
{"jobs", jobsopen, jobsclose, jobsioctl};

ALTQ_MODULE(altq_jobs, ALTQT_JOBS, &jobs_sw);

#endif /* KLD_MODULE */

#endif /* ALTQ_JOBS */
