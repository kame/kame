/*	$Id: altq_jobs.h,v 1.1 2002/10/24 09:17:52 suz Exp $	*/
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
 * Grateful Acknowledgments to Tarek Abdelzaher for his help and       
 * comments, and to Kenjiro Cho for some helpful advice.
 * Contributed by the Multimedia Networks Group at the University
 * of Virginia. 
 *
 * http://qosbox.cs.virginia.edu
 *                                                                      
 */ 							               

#ifndef _ALTQ_ALTQ_JOBS_H_
#define	_ALTQ_ALTQ_JOBS_H_

#include <altq/altq.h>
#include <altq/altq_classq.h>

#ifdef __cplusplus
extern "C" {
#endif 

#define	JOBS_MAXPRI	16	/* upper limit on the number of priorities */
#define SCALE_RATE	32
#define SCALE_LOSS	32
#define SCALE_SHARE	16
#define GRANULARITY	1000000 /* microseconds */
#define INFINITY	LLONG_MAX

/* list of packet arrival times */
typedef struct _tsentry {
  uint64_t	timestamp;
  struct _tsentry *next;
  struct _tsentry *prev;
} tsentry_t;

typedef struct _tslist {
  tsentry_t	*head;
  tsentry_t	*tail;
  int		nr_elts;
} tslist_t;

#define tslist_first(s) (s->head)
#define tslist_last(s) (s->tail)
#define tslist_empty(s) (s->head == NULL)

/* additional macros (PKTCNTR_ADD can be found 
 * in the original distribution) 
 */

#define PKTCNTR_SUB(cntr, len)  \
        do { (cntr)->packets--; (cntr)->bytes -= len; } while (0)
#define PKTCNTR_RESET(cntr)  \
        do { (cntr)->packets = 0; (cntr)->bytes = 0; } while (0)

struct jobs_interface {
	char	jobs_ifname[IFNAMSIZ];	/* interface name (e.g., fxp0) */
	u_long	arg;			/* request-specific argument */
};
struct jobs_attach {
  struct	jobs_interface iface;
  u_int		bandwidth;  /* link bandwidth in bits/sec */
  u_int		qlimit; /* buffer size in packets */
  u_int		separate;
};

struct jobs_add_class {
	struct jobs_interface	iface;
	int			pri;	/* priority (0 is the lowest) */
	int			flags;	/* misc flags (see below) */
	
	int64_t			RDC;	/* RDC weight (-1 = NO RDC) 
					 * no unit
					 */
	int64_t			ADC;	/* Delay Bound (-1 = NO ADC) 
					 * is provided in us
					 * is converted to clock ticks
					 */
	int64_t			RLC;	/* RLC weight (-1 = NO RLC) 
					 * no unit
					 */
	int64_t			ALC;	/* Loss Rate Bound (-1 = NO ALC) 
					 * is provided in fraction of 1
					 * is converted to a fraction of 
					 * 2^(SCALE_LOSS)
					 */
	int64_t			ARC;	/* lower bound on throughput (-1 = no ARC)
					 * is provided in (string) and 
					 * is converted to internal format
					 */
	u_long			class_handle;  /* return value */
};

/* jobs class flags */
#define	JOCF_CLEARDSCP		0x0010  /* clear diffserv codepoint */
#define	JOCF_DEFAULTCLASS	0x1000	/* default class */

/* special class handles */
#define	JOBS_NULLCLASS_HANDLE	0

struct jobs_delete_class {
	struct jobs_interface	iface;
	u_long			class_handle;
};

struct jobs_modify_class {
	struct jobs_interface	iface;
	u_long			class_handle;
	int			pri;
	int64_t			RDC;	/* RDC weight (-1 = NO RDC) 
					 * no unit
					 */
	int64_t			ADC;	/* Delay Bound (-1 = NO ADC) 
					 * is provided in us
					 * is converted to clock ticks
					 */
	int64_t			RLC;	/* RLC weight (-1 = NO RLC) 
					 * no unit
					 */
	int64_t			ALC;	/* Loss Rate Bound (-1 = NO ALC) 
					 * is provided in fraction of 1
					 * is converted to a fraction of 
					 * 2^(SCALE_LOSS)
					 */
	int64_t			ARC;	/* lower bound on throughput (-1 = no ARC)
					 * is provided in (string) and 
					 * is converted to internal format
					 */

	int			flags;
};

struct jobs_add_filter {
	struct jobs_interface	iface;
	u_long			class_handle;
	struct flow_filter	filter;

	u_long			filter_handle;  /* return value */
};

struct jobs_delete_filter {
	struct jobs_interface	iface;
	u_long			filter_handle;
};

struct class_stats {
	u_long			class_handle;

	u_int			qlength;
	u_int 			period;
	struct pktcntr		arrival;  /* rin+dropped */
  struct pktcntr	arrivalbusy;
	struct pktcntr		rin;  /* dropped packet counter */
	struct pktcntr		rout;  /* transmitted packet counter */
	struct pktcntr		dropcnt;  /* dropped packet counter */
	int64_t		service_rate;	/* bps that should be out */
  
	u_int64_t		lastdel; /* in us */
	u_int64_t		avgdel;
	u_int64_t		busylength; /* in ms */
	int			ts_elts;
	u_int			adc_violations;

  u_int64_t bc_cycles_enqueue;
  u_int64_t wc_cycles_enqueue;
  u_int64_t avg_cycles_enqueue;
  u_int64_t avg_cycles2_enqueue;
  u_int64_t total_enqueued;

  u_int64_t bc_cycles_dequeue;
  u_int64_t wc_cycles_dequeue;
  u_int64_t avg_cycles_dequeue;
  u_int64_t avg_cycles2_dequeue;
  u_int64_t total_dequeued;
  u_int	totallength;
  u_int qlensez;

};

struct jobs_class_stats {
	struct jobs_interface	iface;
	int			maxpri;	  /* in/out */

	struct class_stats	*stats;   /* pointer to stats array */
};

#define	JOBS_IF_ATTACH		_IOW('Q', 1, struct jobs_attach)
#define	JOBS_IF_DETACH		_IOW('Q', 2, struct jobs_interface)
#define	JOBS_ENABLE		_IOW('Q', 3, struct jobs_interface)
#define	JOBS_DISABLE		_IOW('Q', 4, struct jobs_interface)
#define	JOBS_CLEAR		_IOW('Q', 5, struct jobs_interface)
#define	JOBS_ADD_CLASS		_IOWR('Q', 7, struct jobs_add_class)
#define	JOBS_DEL_CLASS		_IOW('Q', 8, struct jobs_delete_class)
#define	JOBS_MOD_CLASS		_IOW('Q', 9, struct jobs_modify_class)
#define	JOBS_ADD_FILTER		_IOWR('Q', 10, struct jobs_add_filter)
#define	JOBS_DEL_FILTER		_IOW('Q', 11, struct jobs_delete_filter)
#define	JOBS_GETSTATS		_IOWR('Q', 12, struct jobs_class_stats)

#ifdef _KERNEL

struct jobs_class {
	u_long		cl_handle;	/* class handle */
	class_queue_t	*cl_q;		/* class queue structure */
	int		cl_pri;		/* priority */
	int		cl_flags;	/* class flags */
	struct jobs_if	*cl_jif;	/* back pointer to jif */

        tslist_t	*arv_tm;	/* list of timestamps */

	/* control variables */
	int64_t	service_rate;	/* bps that should be out */
  
        /* internal representation: bytes/unit_time << 32 
         *                          = (bps /8 << 32)*1/machclk_freq 
         */

        int64_t	min_rate_adc;	/* bps that should be out for ADC/ARC */
        /* same internal rep as above */  
	u_int64_t	current_loss;	/* % of packets dropped */

	/* statistics */
	u_int		cl_period;	/* backlog period */
	struct pktcntr  cl_arrival;	/* arrived packet counter */
	struct pktcntr  cl_rin;		/* let in packet counter */
	struct pktcntr  cl_rout;	/* transmitted packet counter */

	struct pktcntr  cl_dropcnt;	/* dropped packet counter */
	u_int64_t	cl_lastdel;     /* in clock ticks */
	u_int64_t	cl_avgdel;
	
	/* modified deficit round-robin specific variables */
	u_int64_t	cl_last_rate_update; /* in clock ticks */
	struct pktcntr	cl_rout_th;	/* theoretical transmissions */
	/* WARNING: rout_th is SCALED for precision, as opposed to rout. */

	int64_t st_service_rate;
	struct pktcntr  st_arrival;  /* rin+dropped */
	struct pktcntr	st_rin;  /* dropped packet counter */
	struct pktcntr	st_rout;  /* transmitted packet counter */
	struct pktcntr	st_dropcnt;  /* dropped packet counter */

	/* service guarantees */
	int64_t			RDC;	/* RDC weight (-1 = NO RDC) 
					 * no unit
					 */
	int64_t			ADC;	/* Delay Bound (-1 = NO ADC) 
					 * is provided in milliseconds
					 * is converted to clock ticks
					 */
	int64_t			RLC;	/* RLC weight (-1 = NO RLC) 
					 * no unit
					 */
	int64_t			ALC;	/* Loss Rate Bound (-1 = NO ALC) 
					 * is provided in fraction of 1
					 * is converted to a fraction of
					 * 2^(SCALE_LOSS)
					 */
	int64_t			ARC;	/* lower bound on throughput (-1 = no ARC)
					 * is provided in (string) and 
					 * is converted to internal format
					 */

	int concerned_RDC;
	int concerned_ADC;
	int concerned_RLC;
	int concerned_ALC;
	int concerned_ARC;

	u_int		adc_violations;
	u_int64_t	delay_prod_others;
	u_int64_t	loss_prod_others;
	u_int64_t	idletime;
};

/*
 * jobs interface state
 */
struct jobs_if {
	struct jobs_if		*jif_next;	/* interface state list */
	struct ifaltq		*jif_ifq;	/* backpointer to ifaltq */
	u_int			jif_bandwidth;	/* link bandwidth in bps */
	int			jif_maxpri;	/* max priority in use */
	struct jobs_class	*jif_default;	/* default class */
	struct jobs_class	*jif_classes[JOBS_MAXPRI]; /* classes */
	struct acc_classifier	jif_classifier;	/* classifier */
  u_int jif_qlimit; /* buffer size in packets */
  u_int jif_separate; /* separate buffers or not */
  u_int64_t bc_cycles_enqueue;
  u_int64_t wc_cycles_enqueue;
  u_int64_t avg_cycles_enqueue;
  u_int64_t avg_cycles2_enqueue;
  u_int64_t total_enqueued;

  u_int64_t bc_cycles_dequeue;
  u_int64_t wc_cycles_dequeue;
  u_int64_t avg_cycles_dequeue;
  u_int64_t avg_cycles2_dequeue;
  u_int64_t total_dequeued;
};

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif 

#endif /* _ALTQ_ALTQ_JOBS_H_ */
