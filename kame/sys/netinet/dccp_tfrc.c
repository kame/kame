/*	$KAME: dccp_tfrc.c,v 1.9 2004/05/21 08:35:48 itojun Exp $	*/

/*
 * Copyright (c) 2003  Nils-Erik Mattsson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Id: dccp_tfrc.c,v 1.47 2003/05/28 17:36:15 nilmat-8 Exp
 */

/*
 * This implementation conforms to the drafts of DCCP dated Mars 2003.
 * The options used are window counter, elapsed time, loss event rate
 * and receive rate.  No support for history discounting or oscillation
 * prevention.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
#include <sys/sx.h>
#endif
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#ifdef __NetBSD__
#include <sys/callout.h>
#endif

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_var.h>

#include <netinet/dccp_tfrc.h>
#include <netinet/dccp.h>
#include <netinet/dccp_var.h>

/*#define TFRCDEBUG
  #define TFRCDEBUGTIMERS*/

#include <netinet/dccp_tfrc_lookup.h>

/*#define NOTFRCSENDER
#define NOTFRCRECV*/

#ifdef TFRCDEBUG
#define TFRC_DEBUG(args) log args
#else
#define TFRC_DEBUG(args)
#endif

#ifdef TFRCDEBUGTIMERS
#define TFRC_DEBUG_TIME(args) log args
#else
#define TFRC_DEBUG_TIME(args)
#endif

#if !defined(__FreeBSD__) || __FreeBSD_version < 500000
#define	INP_INFO_LOCK_INIT(x,y)
#define	INP_INFO_WLOCK(x)
#define INP_INFO_WUNLOCK(x)
#define	INP_INFO_RLOCK(x)
#define INP_INFO_RUNLOCK(x)
#define	INP_LOCK(x)
#define INP_UNLOCK(x)
#endif


#include <netinet/dccp_tfrc_print.h>

/* Timeval operations */
const struct timeval delta_half = {0, TFRC_OPSYS_TIME_GRAN / 2};

#ifdef __FreeBSD__
#define	timercmp(tvp, uvp, cmp)						\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define	timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#endif
/*
 * Half time value struct (accurate to +- 0.5us)
 * args:  tvp  -  pointer to timeval structure
 * Tested u:OK
 */
#define HALFTIMEVAL(tvp) \
        do { \
		if ((tvp)->tv_sec & 1)				\
			(tvp)->tv_usec += 1000000;		\
		(tvp)->tv_sec = (tvp)->tv_sec >> 1;		\
		(tvp)->tv_usec = (tvp)->tv_usec >> 1;		\
        } while (0)

/* Sender side */

/* Calculate new t_ipi (inter packet interval) by
 *    t_ipi = s/X_inst;
 * args:  ccbp - pointer to sender ccb block
 * Tested u:OK - Note: No check for x = 0 -> t_ipi = {0xFFF...,0xFFF}
 */
#define CALCNEWTIPI(ccbp) \
        do { \
		struct fixpoint x, y;					\
		fixpoint_div(&x, &(ccbp)->s, &(ccbp)->x);		\
		y->num = (ccbp)->t_ipi.tv_sec = fixpoint_getlong(&x);	\
		y->denom = 1;						\
		fixpoint_sub(&x, &x, &y);				\
		y->num = 1000000;					\
		y->denom = 1;						\
		fixpoint_mul(&x, &x, &y);				\
		(ccbp)->t_ipi.tv_usec = fixpoint_getlong(&x);		\
        } while (0)

/* Calculate new delta by
 *    delta = min(t_ipi/2, t_gran/2);
 * args: ccbp - pointer to sender ccb block
 * Tested u:OK
 */
#define CALCNEWDELTA(ccbp) \
         do { \
		(ccbp)->delta = delta_half;				\
		if ((ccbp)->t_ipi.tv_sec == 0 &&			\
		    (ccbp)->t_ipi.tv_usec < TFRC_OPSYS_TIME_GRAN) {	\
			(ccbp)->delta = (ccbp)->t_ipi;			\
			HALFTIMEVAL(&((ccbp)->delta));			\
		}							\
	 } while (0)

const struct fixpoint tfrc_smallest_p = { 4LL, 1000000LL };

/* External declarations */
extern int dccp_get_option(char *, int, int, char *, int);

/* Forward declarations */
void tfrc_time_no_feedback(void *);
void tfrc_time_send(void *);
void tfrc_set_send_timer(struct tfrc_send_ccb *, struct timeval);
void tfrc_updateX(struct tfrc_send_ccb *, struct timeval);
const struct fixpoint *tfrc_calcX(u_int16_t, u_int32_t,
	const struct fixpoint *);
void tfrc_send_term(void *);

static void normalize(long long *, long long *);
struct fixpoint *fixpoint_add(struct fixpoint *, const struct fixpoint *,
	const struct fixpoint *);
struct fixpoint *fixpoint_sub(struct fixpoint *, const struct fixpoint *,
	const struct fixpoint *);
int fixpoint_cmp(const struct fixpoint *, const struct fixpoint *);
struct fixpoint *fixpoint_mul(struct fixpoint *, const struct fixpoint *,
	const struct fixpoint *);
struct fixpoint *fixpoint_div(struct fixpoint *, const struct fixpoint *,
	const struct fixpoint *);
long fixpoint_getlong(const struct fixpoint *);

const struct fixpoint *flookup(const struct fixpoint *);
const struct fixpoint *tfrc_flookup_reverse(const struct fixpoint *);

/*
 * Calculate the send rate according to TCP throughput eq.
 * args: s - packet size (in bytes)
 *       R - Round trip time  (in micro seconds)
 *       p - loss event rate  (0<=p<=1)
 * returns:  calculated send rate (in bytes per second)
 * Tested u:OK
 */
__inline const struct fixpoint *
tfrc_calcX(u_int16_t s, u_int32_t r, const struct fixpoint *p)
{
	static struct fixpoint x;

	x.num = 1000000 * s;
	x.denom = 1 * r;
	fixpoint_div(&x, &x, p);
	return &x;
}

/*
 * Function called by the send timer (to send packet)
 * args: cb -  sender congestion control block
 */
void
tfrc_time_send(void *ccb)
{
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;
	int s;
	struct inpcb *inp;

	if (cb->state == TFRC_SSTATE_TERM) {
		TFRC_DEBUG((LOG_INFO,
		    "TFRC - Send timer is ordered to terminate. (tfrc_time_send)\n"));
		return;
	}
	if (callout_pending(cb->ch_stimer)) {
		TFRC_DEBUG((LOG_INFO,
		    "TFRC - Callout pending. (tfrc_time_send)\n"));
		return;
	}
	/* aquire locks for dccp_output */
	s = splnet();
	INP_INFO_RLOCK(&dccpbinfo);
	inp = cb->pcb->d_inpcb;
	INP_LOCK(inp);
	INP_INFO_RUNLOCK(&dccpbinfo);

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&cb->ch_stimer);
#else
	timeout_del(&cb->ch_stimer);
#endif
	dccp_output(cb->pcb, 1);
	/* make sure we schedule next send time */
	tfrc_send_packet_sent(cb, 0, -1);

	/* release locks */
	INP_UNLOCK(inp);
	splx(s);
}
/*
 * Calculate and set when the send timer should expire
 * args: cb -  sender congestion control block
 *       t_now - timeval struct containing actual time
 * Tested u:OK
 */
void
tfrc_set_send_timer(struct tfrc_send_ccb * cb, struct timeval t_now)
{
	struct timeval t_temp;
	long t_ticks;

	/* set send timer to fire in t_ipi - (t_now-t_nom_old) or in other
	 * words after t_nom - t_now */
	t_temp = cb->t_nom;
	timersub(&t_temp, &t_temp, &t_now);

#ifdef TFRCDEBUG
	if (t_temp.tv_sec < 0 || t_temp.tv_usec < 0)
		panic("TFRC - scheduled a negative time! (tfrc_set_send_timer)");
#endif

	t_ticks = (t_temp.tv_usec + 1000000 * t_temp.tv_sec) / (1000000 / hz);
	if (t_ticks == 0)
		t_ticks = 1;
	TFRC_DEBUG_TIME((LOG_INFO,
	    "TFRC scheduled send timer to expire in %ld ticks (hz=%lu)\n",
	     t_ticks, (unsigned long)hz));
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&cb->ch_stimer, t_ticks, tfrc_time_send, cb);
#else
	timeout_set(&cb->ch_stimer, tfrc_time_send, cb);
	timeout_add(&cb->ch_stimer, t_ticks);
#endif
}

/*
 * Update X by
 *    If (p > 0)
 *       x_calc = calcX(s,R,p);
 *       X = max(min(X_calc, 2*X_recv), s/t_mbi);
 *    Else
 *       If (t_now - tld >= R)
 *          X = max(min("2*X, 2*X_recv),s/R);
 *          tld = t_now;
 * args: cb -  sender congestion control block
 *       t_now - timeval struct containing actual time
 * Tested u:OK
 */
void
tfrc_updateX(struct tfrc_send_ccb * cb, struct timeval t_now)
{
	struct fixpoint temp, temp2;
	struct timeval t_temp, t_rtt = {0, 0};

	/* to avoid large error in calcX */
	if (fixpoint_cmp(&cb->p, &tfrc_smallest_p) >= 0) {
		cb->x_calc = *tfrc_calcX(cb->s, cb->rtt, &cb->p);
		temp = cb->x_recv;
		temp.num *= 2;
		if (fixpoint_cmp(&cb->x_calc, &temp) < 0)
			temp = cb->x_calc;
		cb->x = temp;
		temp2.num = cb->s;
		temp2.denom *= TFRC_MAX_BACK_OFF_TIME;
		if (fixpoint_cmp(&temp, &temp2) < 0)
			cb->x = temp2;
		normalize(&cb->x.num, &cb->x.denom);
		TFRC_DEBUG((LOG_INFO, "TFRC updated send rate to "));
		PRINTFLOAT(&cb->x);
		TFRC_DEBUG((LOG_INFO, " bytes/s (tfrc_updateX, p>0)\n"));
	} else {
		t_rtt.tv_usec = cb->rtt % 1000000;
		t_rtt.tv_sec = cb->rtt / 1000000;
		t_temp = t_now;
		timersub(&t_temp, &t_temp, &cb->t_ld);
		if (timercmp(&t_temp, &t_rtt, >=)) {
			temp = cb->x_recv;
			temp.num *= 2;
			temp2 = cb->x;
			temp2.num *= 2;
			if (fixpoint_cmp(&temp2, &temp) < 0)
				temp = temp2;
			cb->x.num = cb->s;
			cb->x.denom = 1;
			cb->x.num *= 1000000;
			cb->x.denom *= cb->rtt;
			if (fixpoint_cmp(&temp, &cb->x) > 0)
				cb->x = temp;
			normalize(&cb->x.num, &cb->x.denom);
			cb->t_ld = t_now;
			TFRC_DEBUG((LOG_INFO, "TFRC updated send rate to "));
			PRINTFLOAT(&cb->x);
			TFRC_DEBUG((LOG_INFO, " bytes/s (tfrc_updateX, p==0)\n"));
		} else
			TFRC_DEBUG((LOG_INFO, "TFRC didn't update send rate! (tfrc_updateX, p==0)\n"));
	}
}

/*
 * Function called by the no feedback timer
 * args:  cb -  sender congestion control block
 * Tested u:OK
 */
void
tfrc_time_no_feedback(void *ccb)
{
	struct fixpoint v, w;
	u_int32_t next_time_out = 1;	/* remove init! */
	struct timeval t_now;
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_lock(&(cb->mutex));
#endif

	if (cb->state == TFRC_SSTATE_TERM) {
		TFRC_DEBUG((LOG_INFO, "TFRC - No feedback timer is ordered to terminate\n"));
		goto nf_release;
	}
	if (cb->ch_nftimer.callout == NULL || callout_pending(cb->ch_nftimer.callout)) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Callout pending, exiting...(tfrc_time_no_feedback)\n"));
		goto nf_release;
	}
	cb->ch_nftimer = NULL;
	switch (cb->state) {
	case TFRC_SSTATE_NO_FBACK:
		TFRC_DEBUG((LOG_INFO, "TFRC - no feedback timer expired, state NO_FBACK\n"));
		/* half send rate */
		cb->x.denom *= 2;
		v = cb->s;
		v.denom *= TFRC_MAX_BACK_OFF_TIME;
		if (fixpoint_cmp(&cb->x, &v) < 0)
			cb->x = v;

		TFRC_DEBUG((LOG_INFO, "TFRC updated send rate to "));
		PRINTFLOAT(cb->x);
		TFRC_DEBUG((LOG_INFO, " bytes/s (tfrc_time_no_feedback\n"));

		/* reschedule next time out */

		v.num = 2;
		v.denom = 1;
		fixpoint_mul(&v, &v, &cb->s);
		fixpoint_div(&v, &v, &cb->x);
		v.num *= 1000000;
		normlaize(&v.num, &v.denom);
		next_time_out = v.num / v.denom;
		if (next_time_out < TFRC_INITIAL_TIMEOUT * 1000000)
			next_time_out = TFRC_INITIAL_TIMEOUT * 1000000;
		break;
	case TFRC_SSTATE_FBACK:
		/*
	 	 * Check if IDLE since last timeout and recv rate is less than
		 * 4 packets per RTT
		 */

		v = cb->s;
		v.num *= 4;
		v.denom *= cb->rtt;
		v.num *= 1000000;
		normlaize(&v.num, &v.denom);
		if (!cb->idle || fixpoint_cmp(&cb->x_recv, &v) >= 0)
			TFRC_DEBUG((LOG_INFO, "TFRC - no feedback timer expired, state FBACK, not idle\n"));
			/* Half sending rate */

			/*
			 * If (X_calc > 2* X_recv) X_recv = max(X_recv/2,
			 * s/(2*t_mbi)); Else X_recv = X_calc/4;
			 */
			v.num = TFRC_SMALLEST_P;
			v.denom = 1;
			if (fixpoint_cmp(&cb->p, &v) < 0 && cb->x_calc.num == 0)
				panic("TFRC - X_calc is zero! (tfrc_time_no_feedback)\n");

			/* check also if p i zero -> x_calc is infinity ?? */
			w = cb->x_recv;
			w.num *= 2;
			if (fixpoint_cmp(&cb->p, &v) || fixpoint_cmp(&cb->x_calc, &w) > 0) {
				cb->x_recv.denom *= 2;
				w = cb->s;
				w.denom *= (2 * TFRC_MAX_BACK_OFF_TIME);
				if (fixpoint_cmp(&cb->x_recv, &w) < 0)
					cb->x_recv = w;
			} else
				cb->x_recv.denom *= 4;
			normalize(&cb->x_recv.num, &cb->x_recv.denom);

			/* Update sending rate */
			microtime(&t_now);
			tfrc_updateX(cb, t_now);
		}
		/* Schedule no feedback timer to expire in max(4*R, 2*s/X) */
		v = cb->s;
		v.num *= 2;
		fixpoint_div(&v, &v, &cb->x);
		v.num *= 1000000;
		next_time_out = v.num / v.denom;
		if (next_time_out < cb->t_rto)
			next_time_out = cb->t_rto;
		break;
	default:
		panic("tfrc_no_feedback: Illegal state!");
		break;
	}

	/* Set timer */

	next_time_out = next_time_out / (1000000 / hz);
	if (next_time_out == 0)
		next_time_out = 1;

	TFRC_DEBUG_TIME((LOG_INFO, "TFRC scheduled no feedback timer to expire in %u ticks (hz=%u)\n", next_time_out, hz));

	cb->ch_nftimer = timeout(tfrc_time_no_feedback, (void *) cb, next_time_out);

	/* set idle flag */
	cb->idle = 1;
nf_release:
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
#endif
}

/*
 * Removes ccb from memory
 * args: ccb - ccb of sender
 */
void
tfrc_send_term(void *ccb)
{
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;

	if (ccb == 0)
		panic("TFRC - Sender ccb is null! (free)");

	/* free sender */

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_destroy(&(cb->mutex));
#endif

	free(cb, M_PCB);
	TFRC_DEBUG((LOG_INFO, "TFRC sender is destroyed\n"));
}

/* Functions declared in struct dccp_cc_sw */

/*
 * Initialises the sender side
 * args:  pcb - dccp protocol control block
 * returns: pointer to a tfrc_send_ccb struct on success, otherwise 0
 * Tested u:OK
 */
void *
tfrc_send_init(struct dccpcb * pcb)
{
	struct tfrc_send_ccb *ccb;

	ccb = malloc(sizeof(struct tfrc_send_ccb), M_PCB, M_DONTWAIT | M_ZERO);
	if (ccb == 0) {
		TFRC_DEBUG((LOG_INFO, "Unable to allocate memory for tfrc_send_ccb!\n"));
		return 0;
	}
	/* init sender */

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_init(&(ccb->mutex), "TFRC Sender mutex", NULL, MTX_DEF | MTX_RECURSE);
#endif

	ccb->pcb = pcb;
	if (ccb->pcb->avgpsize >= TFRC_MIN_PACKET_SIZE && ccb->pcb->avgpsize <= TFRC_MAX_PACKET_SIZE)
		ccb->s = (u_int16_t) ccb->pcb->avgpsize;
	else
		ccb->s = TFRC_STD_PACKET_SIZE;

	TFRC_DEBUG((LOG_INFO, "TFRC - Sender is using packet size %u\n", ccb->s));

	ccb->x.num = ccb->s;	/* set transmissionrate to 1 packet
	ccb->x.denom = 1;
					 * per second */
	ccb->t_ld.tv_sec = -1;
	ccb->t_ld.tv_usec = 0;

#ifdef TFRCDEBUG
	ccb->t_last_win_count.tv_sec = -1;
#endif

	/* init packet history */
	TAILQ_INIT(&(ccb->hist));

	ccb->state = TFRC_SSTATE_NO_SENT;

	TFRC_DEBUG((LOG_INFO, "TFRC sender initialised!\n"));
	dccpstat.tfrcs_send_conn++;
	return ccb;
}

/*
 * Free the sender side
 * args: ccb - ccb of sender
 * Tested u:OK
 */
void
tfrc_send_free(void *ccb)
{
	struct s_hist_entry *elm, *elm2;
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;

	TFRC_DEBUG((LOG_INFO, "TFRC send free called!\n"));

	if (ccb == 0)
		panic("TFRC - Sender ccb is null! (free)");

	/* uninit sender */

	/* get mutex */
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_lock(&(cb->mutex));
#endif
	cb->state = TFRC_SSTATE_TERM;
	/* unschedule timers */
	if (cb->ch_stimer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_stop(&cb->ch_stimer);
#else
		timeout_del(&cb->ch_stimer);
#endif
	}
	if (cb->ch_nftimer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_stop(&cb->ch_nftimer);
#else
		timeout_del(&cb->ch_nftimer);
#endif
	}

	/* Empty packet history */
	elm = TAILQ_FIRST(&(cb->hist));
	while (elm != NULL) {
		elm2 = TAILQ_NEXT(elm, linfo);
		free(elm, M_TEMP);	/* M_TEMP ?? */
		elm = elm2;
	}
	TAILQ_INIT(&(cb->hist));

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
#endif

	/* schedule the removal of ccb */
	timeout(tfrc_send_term, (void *) cb, TFRC_SEND_WAIT_TERM * hz);
}

/*
 * Ask TFRC whether one can send a packet or not
 * args: ccb  -  ccb block for current connection
 * returns: 1 if ok, else 0.
 * Tested u:OK
 */
int
tfrc_send_packet(void *ccb, long datasize)
{
	struct s_hist_entry *new_packet;
	u_int8_t answer = 0;
	u_int8_t win_count = 0;
	u_int32_t uw_win_count = 0;
	struct timeval t_now, t_temp;
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;
#ifdef NOTFRCSENDER
	return 1;
#endif

	/* check if pure ACK or Terminating */
	if (datasize == 0 || cb->state == TFRC_SSTATE_TERM) {
		return 1;
	} else if (cb->state == TFRC_SSTATE_TERM) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Asked to send packet when terminating!\n"));
		return 0;
	}
	/* we have data to send */
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_lock(&(cb->mutex));
#endif

	/* check to see if we already have allocated memory last time */
	new_packet = TAILQ_FIRST(&(cb->hist));

	if ((new_packet != NULL && new_packet->t_sent.tv_sec >= 0) || new_packet == NULL) {
		/* check to see if we have memory to add to packet history */
		new_packet = malloc(sizeof(struct s_hist_entry), M_TEMP, M_DONTWAIT);	/* M_TEMP?? */
		if (new_packet == NULL) {
			TFRC_DEBUG((LOG_INFO, "TFRC - Not enough memory to add packet to packet history (send refused)! (tfrc_send_packet)\n"));
			answer = 0;
			dccpstat.tfrcs_send_nomem++;
			goto sp_release;
		}
		new_packet->t_sent.tv_sec = -1;	/* mark as unsent */
		TAILQ_INSERT_HEAD(&(cb->hist), new_packet, linfo);
	}
	switch (cb->state) {
	case TFRC_SSTATE_NO_SENT:
		TFRC_DEBUG((LOG_INFO, "TFRC - DCCP ask permission to send first data packet (tfrc_send_packet)\n"));
		microtime(&(cb->t_nom));	/* set nominal send time for
						 * initial packet */
		t_now = cb->t_nom;


		/* init feedback timer */

		cb->ch_nftimer = timeout(tfrc_time_no_feedback, (void *) cb,
		    TFRC_INITIAL_TIMEOUT * hz);
		win_count = 0;
		cb->t_last_win_count = t_now;
		TFRC_DEBUG((LOG_INFO, "TFRC - Permission granted. Scheduled no feedback timer (initial) to expire in %u ticks (hz=%u) (tfrc_send_packet)\n", TFRC_INITIAL_TIMEOUT * hz, hz));
		/* start send timer */

		/* Calculate new t_ipi */
		CALCNEWTIPI(cb);
		timeradd(&cb->t_nom, &cb->t_nom, &cb->t_ipi);
		/* Calculate new delta */
		CALCNEWDELTA(cb);
		tfrc_set_send_timer(cb, t_now);	/* if so schedule sendtimer */
		cb->state = TFRC_SSTATE_NO_FBACK;
		answer = 1;
		break;
	case TFRC_SSTATE_NO_FBACK:
	case TFRC_SSTATE_FBACK:
		if (!(cb->ch_stimer)) {
			microtime(&t_now);

			t_temp = t_now;
			timeradd(&t_temp, &t_temp, &cb->delta);

			if ((timercmp(&(t_temp), &(cb->t_nom), >))) {
				/* Packet can be sent */

#ifdef TFRCDEBUG
				if (cb->t_last_win_count.tv_sec == -1)
					panic("TFRC - t_last_win_count unitialized (tfrc_send_packet)\n");
#endif
				t_temp = t_now;
				timersub(&t_temp, &t_temp, &(cb->t_last_win_count));

				/* calculate win_count option */
				if (cb->state == TFRC_SSTATE_NO_FBACK) {
					/* Assume RTT= t_rto(initial)/4 */
					uw_win_count = (((double) (t_temp.tv_sec)) + (((double) (t_temp.tv_usec)) / 1000000.0)) / (TFRC_INITIAL_TIMEOUT / (4.0 * TFRC_WIN_COUNT_PER_RTT));
				} else {
					uw_win_count = (((double) (t_temp.tv_sec)) + (((double) (t_temp.tv_usec)) / 1000000.0)) / (((double) (cb->rtt)) / (1000000.0 * TFRC_WIN_COUNT_PER_RTT));
				}
				uw_win_count += cb->last_win_count;
				win_count = uw_win_count % TFRC_WIN_COUNT_LIMIT;
				answer = 1;
			} else {
				answer = 0;
			}
		} else {
			answer = 0;
		}
		break;
	default:
		panic("tfrc_send_packet: Illegal state!");
		break;
	}

	/* can we send? if so add options and add to packet history */
	if (answer) {
		/* Add packet to history */

		new_packet->win_count = win_count;

		/* todo: remove old option */

		/* add option */
		if (dccp_add_option(cb->pcb, TFRC_OPT_WINDOW_COUNT, (char *) &win_count, 1)) {
			TFRC_DEBUG((LOG_INFO, "TFRC - Add window counter option failed, send refused! (tfrc_send_packet)!\n"));
			answer = 0;
			dccpstat.tfrcs_send_erropt++;
		}
	}
sp_release:
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
#endif
	return answer;
}
/* Notify sender that a packet has been sent
 * args: ccb - ccb block for current connection
 *	 moreToSend - if there exists more packets to send
 *       dataSize -   packet size
 */
void
tfrc_send_packet_sent(void *ccb, int moreToSend, long datasize)
{
	struct timeval t_now, t_temp;
	struct s_hist_entry *packet;
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;

#ifdef NOTFRCSENDER
	return;
#endif

	if (cb->state == TFRC_SSTATE_TERM) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Packet sent when terminating!\n"));
		return;
	}
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_lock(&(cb->mutex));
#endif
	microtime(&t_now);

	/* check if we have sent a data packet */
	if (datasize > 0) {
		/* add send time to history */
		packet = TAILQ_FIRST(&(cb->hist));
		if (packet == NULL)
			panic("TFRC - Packet does not exist in history! (tfrc_send_packet_sent)");
		else if (packet != NULL && packet->t_sent.tv_sec >= 0)
			panic("TFRC - No unsent packet in history! (tfrc_send_packet_sent)");
		packet->t_sent = t_now;
		packet->seq = cb->pcb->seq_snd;
		/* check if win_count have changed */
		if (packet->win_count != cb->last_win_count) {
			cb->t_last_win_count = t_now;
			cb->last_win_count = packet->win_count;
		}
		TFRC_DEBUG((LOG_INFO, "TFRC - Packet sent (%u,%u,(", packet->seq, packet->win_count));
		PRINTTIMEVALu(&(packet->t_sent));
		TFRC_DEBUG((LOG_INFO, ")) (tfrc_send_packet_sent)\n"));
		cb->idle = 0;
	}
	/* if timer is running, do nothing */
	if (cb->ch_stimer) {
		goto sps_release;
	}
	switch (cb->state) {
	case TFRC_SSTATE_NO_SENT:
		/* if first was pure ack */
		if (datasize == 0) {
			goto sps_release;
		} else
			panic("TFRC - First packet sent is noted as a data packet in tfrc_send_packet_sent\n");
		break;
	case TFRC_SSTATE_NO_FBACK:
	case TFRC_SSTATE_FBACK:
		if (datasize <= 0) {	/* we have ack (or simulate a sent
					 * packet which never can have
					 * moreToSend */
			moreToSend = 0;
		} else {
			/* Calculate new t_ipi */
			CALCNEWTIPI(cb);
			timeradd(&cb->t_nom, &cb->t_nom, &cb->t_ipi);
			/* Calculate new delta */
			CALCNEWDELTA(cb);
		}

		if (!moreToSend) {
			/* loop until we find a send time in the future */
			microtime(&t_now);
			t_temp = t_now;
			timeradd(&t_temp, &t_temp, &cb->delta);
			while ((timercmp(&(t_temp), &(cb->t_nom), >))) {
				/* Calculate new t_ipi */
				CALCNEWTIPI(cb);
				timeradd(&cb->t_nom, &cb->t_nom, &cb->t_ipi);
				/* Calculate new delta */
				CALCNEWDELTA(cb);

				microtime(&t_now);
				t_temp = t_now;
				timeradd(&t_temp, &t_temp, &cb->delta);
			}
			tfrc_set_send_timer(cb, t_now);
		} else {
			microtime(&t_now);
			t_temp = t_now;
			timeradd(&t_temp, &t_temp, &cb->delta);
			/* Check if next packet can not be sent immediately */
			if (!(timercmp(&(t_temp), &(cb->t_nom), >))) {
				tfrc_set_send_timer(cb, t_now);	/* if so schedule
								 * sendtimer */
			}
		}
		break;
	default:
		panic("tfrc_send_packet_sent: Illegal state!");
		break;
	}

sps_release:
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
#endif
}
/* Notify that a an ack package was received (i.e. a feedback packet)
 * args: ccb  -  ccb block for current connection
 */
void
tfrc_send_packet_recv(void *ccb, char *options, int optlen)
{
	u_int32_t next_time_out;
	struct timeval t_now;
	int res;
	u_int16_t t_elapsed;
	u_int32_t pinv;
	u_int32_t x_recv;

	u_int32_t r_sample;

	struct s_hist_entry *elm, *elm2;
	struct tfrc_send_ccb *cb = (struct tfrc_send_ccb *) ccb;

#ifdef NOTFRCSENDER
	return;
#endif

	if (cb->state == TFRC_SSTATE_TERM) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Sender received a packet when terminating!\n"));
		return;
	}
	/* we are only interested in ACKs */
	if (!(cb->pcb->type_rcv == DCCP_TYPE_ACK || cb->pcb->type_rcv == DCCP_TYPE_DATAACK))
		return;

	res = dccp_get_option(options, optlen, TFRC_OPT_LOSS_RATE, (char *) &pinv, 4);
	if (res == 0) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Missing Loss rate option! (tfrc_send_packet_recv)\n"));
		dccpstat.tfrcs_send_noopt++;
		return;
	}
	res = dccp_get_option(options, optlen, TFRC_OPT_ELAPSED_TIME, (char *) &t_elapsed, 2);

	if (res == 0) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Missing elapsed time option! (tfrc_send_packet_recv)\n"));
		dccpstat.tfrcs_send_noopt++;
		return;
	}
	res = dccp_get_option(options, optlen, TFRC_OPT_RECEIVE_RATE, (char *) &x_recv, 4);
	if (res == 0) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Missing x_recv option! (tfrc_send_packet_recv)\n"));
		dccpstat.tfrcs_send_noopt++;
		return;
	}
	dccpstat.tfrcs_send_fbacks++;
	/* change byte order */
	t_elapsed = ntohs(t_elapsed);
	x_recv = ntohl(x_recv);
	pinv = ntohl(pinv);

	TFRC_DEBUG((LOG_INFO, "TFRC - Receieved options on ack %u: pinv=%u, t_elapsed=%u, x_recv=%u ! (tfrc_send_packet_recv)\n", cb->pcb->ack_rcv, pinv, t_elapsed, x_recv));

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_lock(&(cb->mutex));
#endif

	switch (cb->state) {
	case TFRC_SSTATE_NO_FBACK:
	case TFRC_SSTATE_FBACK:
		/* Calculate new round trip sample by R_sample = (t_now -
		 * t_recvdata)-t_delay; */

		/* get t_recvdata from history */
		elm = TAILQ_FIRST(&(cb->hist));
		while (elm != NULL) {
			if (elm->seq == cb->pcb->ack_rcv)
				break;
			elm = TAILQ_NEXT(elm, linfo);
		}

		if (elm == NULL) {
			TFRC_DEBUG((LOG_INFO, "TFRC - Packet does not exist in history (seq=%u)! (tfrc_send_packet_recv)", cb->pcb->ack_rcv));
			goto sar_release;
		}
		/* Update RTT */
		microtime(&t_now);
		timersub(&t_now, &t_now, &(elm->t_sent));
		r_sample = t_now.tv_sec * 1000000 + t_now.tv_usec;
		r_sample = r_sample - ((u_int32_t) t_elapsed) * 1000;	/* t_elapsed in ms */

		/* Update RTT estimate by If (No feedback recv) R = R_sample;
		 * Else R = q*R+(1-q)*R_sample; */
		if (cb->state == TFRC_SSTATE_NO_FBACK) {
			cb->state = TFRC_SSTATE_FBACK;
			cb->rtt = r_sample;
		} else {
			cb->rtt = (u_int32_t) (TFRC_RTT_FILTER_CONST * ((double) (cb->rtt)) +
			    (1 - TFRC_RTT_FILTER_CONST) * ((double) (r_sample)));
		}

		TFRC_DEBUG((LOG_INFO, "TFRC - New RTT estimate %u (tfrc_send_packet_recv)\n", cb->rtt));

		/* Update timeout interval */
		cb->t_rto = 4 * cb->rtt;

		/* Update receive rate */
		cb->x_recv = ((double) x_recv) / 8.0;	/* x_recv in bits per
							 * second */

		/* Update loss event rate */
		if (pinv == 0)
			cb->p = 0;
		else {
			cb->p = 1.0 / ((double) pinv);

			if (cb->p < TFRC_SMALLEST_P) {
				cb->p = TFRC_SMALLEST_P;
				TFRC_DEBUG((LOG_INFO, "TFRC - Smallest p used!\n"));
			}
		}

		/* unschedule no feedback timer */
		if (cb->ch_nftimer.callout != NULL) {
			untimeout(tfrc_time_no_feedback, (void *) cb, cb->ch_nftimer);
		}
		/* Update sending rate */
		microtime(&t_now);
		tfrc_updateX(cb, t_now);

		/* Update next send time */
		timersub(&cb->t_nom, &cb->t_nom, &cb->t_ipi);

		/* Calculate new t_ipi */
		CALCNEWTIPI(cb);
		timeradd(&cb->t_nom, &cb->t_nom, &cb->t_ipi);
		/* Calculate new delta */
		CALCNEWDELTA(cb);

		if (cb->ch_stimer != NULL)
			untimeout(tfrc_time_send, (void *) cb, cb->ch_stimer);

		cb->ch_stimer = NULL;
		dccp_output(cb->pcb, 1);
		tfrc_send_packet_sent(cb, 0, -1);	/* make sure we schedule
							 * next send time */

		/* remove all packets older than the one acked from history */
		/* elm points to acked package! */

		elm2 = TAILQ_NEXT(elm, linfo);

		while (elm2 != NULL) {
			TAILQ_REMOVE(&(cb->hist), elm2, linfo);
			free(elm2, M_TEMP);
			elm2 = TAILQ_NEXT(elm, linfo);
		}

		/* Schedule no feedback timer to expire in max(4*R, 2*s/X) */
		next_time_out = (u_int32_t) (2 * ((double) (cb->s)) * 1000000 / cb->x);
		if (next_time_out < cb->t_rto)
			next_time_out = cb->t_rto;
		TFRC_DEBUG_TIME((LOG_INFO,
			"TFRC - Scheduled no feedback timer to expire in %u ticks (%u us) (hz=%u)(tfrc_send_packet_recv)\n",
			next_time_out / (1000000 / hz), next_time_out, hz));
		next_time_out = next_time_out / (1000000 / hz);
		if (next_time_out == 0)
			next_time_out = 1;

		cb->ch_nftimer = timeout(tfrc_time_no_feedback, (void *) cb, next_time_out);
		/* set idle flag */
		cb->idle = 1;
		break;
	default:
		panic("tfrc_send_packet_recv: Illegal state!");
		break;
	}
sar_release:
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
#endif
}
/* Receiver side */

/* Forward declarations */
double tfrc_calcImean(struct tfrc_recv_ccb *);
void tfrc_recv_send_feedback(struct tfrc_recv_ccb *);
int tfrc_recv_add_hist(struct tfrc_recv_ccb *, struct r_hist_entry *);
void tfrc_recv_detectLoss(struct tfrc_recv_ccb *);
u_int32_t tfrc_recv_calcFirstLI(struct tfrc_recv_ccb *);
void tfrc_recv_updateLI(struct tfrc_recv_ccb *, long, u_int8_t);

/* Weights used to calculate loss event rate */
const double tfrc_recv_w[] = {1, 1, 1, 1, 0.8, 0.6, 0.4, 0.2};
/* Find a data packet in history
 * args:  cb - ccb of receiver
 *        elm - pointer to element (variable)
 *        num - number in history (variable)
 * returns:  elm points to found packet, otherwise NULL
 * Tested u:OK
 */
#define TFRC_RECV_FINDDATAPACKET(cb,elm,num) \
  do { \
    elm = TAILQ_FIRST(&((cb)->hist)); \
      while ((elm) != NULL) { \
        if ((elm)->type == DCCP_TYPE_DATA || (elm)->type == DCCP_TYPE_DATAACK) \
          (num)--; \
        if (num == 0) \
          break; \
        elm = TAILQ_NEXT((elm), linfo); \
      } \
  } while (0)

/* Find next data packet in history
 * args:  cb - ccb of receiver
 *        elm - pointer to element (variable)
 * returns:  elm points to found packet, otherwise NULL
 * Tested u:OK
 */
#define TFRC_RECV_NEXTDATAPACKET(cb,elm) \
  do { \
    if (elm != NULL) { \
      elm = TAILQ_NEXT(elm, linfo); \
      while ((elm) != NULL && (elm)->type != DCCP_TYPE_DATA && (elm)->type != DCCP_TYPE_DATAACK) { \
        elm = TAILQ_NEXT((elm), linfo); \
      } \
    } \
  } while (0)

/*
 * Calculate avarage loss Interval I_mean
 * args: cb - ccb of receiver
 * returns: avarage loss interval
 * Tested u:OK
 */
double
tfrc_calcImean(struct tfrc_recv_ccb * cb)
{
	struct li_hist_entry *elm;
	double I_tot;
	double I_tot0 = 0.0;
	double I_tot1 = 0.0;
	double W_tot = 0.0;
	int i;
	elm = TAILQ_FIRST(&(cb->li_hist));

	for (i = 0; i < TFRC_RECV_IVAL_F_LENGTH; i++) {
#ifdef TFRCDEBUG
		if (elm == 0)
			goto I_panic;
#endif
		I_tot0 = I_tot0 + (elm->interval * tfrc_recv_w[i]);
		W_tot = W_tot + tfrc_recv_w[i];
		elm = TAILQ_NEXT(elm, linfo);
	}

	elm = TAILQ_FIRST(&(cb->li_hist));
	elm = TAILQ_NEXT(elm, linfo);

	for (i = 1; i <= TFRC_RECV_IVAL_F_LENGTH; i++) {
#ifdef TFRCDEBUG
		if (elm == 0)
			goto I_panic;
#endif
		I_tot1 = I_tot1 + (elm->interval * tfrc_recv_w[i - 1]);
		elm = TAILQ_NEXT(elm, linfo);
	}

	I_tot = I_tot0;		/* I_tot = max(I_tot0, I_tot1) */
	if (I_tot0 < I_tot1)
		I_tot = I_tot1;

	if (I_tot < W_tot)
		I_tot = W_tot;

	return (I_tot / W_tot);
#ifdef TFRCDEBUG
I_panic:if (elm == NULL)
		panic("TFRC - Missing entry in interval history! (tfrc_calcImean)");
#endif
}
/*
 * Send a feedback packet
 * args: cb - ccb for receiver
 * Tested u:OK
 */
void
tfrc_recv_send_feedback(struct tfrc_recv_ccb * cb)
{
	u_int32_t x_recv, pinv;
	u_int16_t t_elapsed;
	struct r_hist_entry *elm;
	struct timeval t_now, t_temp;
	int num;

	if (cb->p < 0.00000000025)	/* -> 1/p > 4 000 000 000 */
		pinv = 0;
	else
		pinv = (u_int32_t) ((double) 1.0 / cb->p);

	switch (cb->state) {
	case TFRC_RSTATE_NO_DATA:
		x_recv = 0;
		break;
	case TFRC_RSTATE_DATA:
		/* Calculate x_recv */
		microtime(&t_temp);
		timersub(&t_temp, &t_temp, &cb->t_last_feedback);

		x_recv = (u_int32_t) (((double) (cb->bytes_recv * 8)) /
		    (((double) t_temp.tv_sec) + ((double) t_temp.tv_usec) / 1000000.0));

		break;
	default:
		panic("tfrc_recv_send_feedback: Illegal state!");
		break;
	}

	/* Find largest win_count so far (data packet with highest seqnum so
	 * far) */
	num = 1;
	TFRC_RECV_FINDDATAPACKET(cb, elm, num);

	if (elm == NULL)
		panic("No data packet in history! (tfrc_recv_send_feedback)");


	microtime(&t_now);
	timersub(&t_now, &t_now, &elm->t_recv);
	t_elapsed = (u_int16_t) (t_now.tv_sec * 1000 + t_now.tv_usec / 1000);

	/* change byte order */
	t_elapsed = htons(t_elapsed);
	x_recv = htonl(x_recv);
	pinv = htonl(pinv);

	/* add options from variables above */
	if (dccp_add_option(cb->pcb, TFRC_OPT_LOSS_RATE, (char *) &pinv, 4)
	    || dccp_add_option(cb->pcb, TFRC_OPT_ELAPSED_TIME, (char *) &t_elapsed, 2)
	    || dccp_add_option(cb->pcb, TFRC_OPT_RECEIVE_RATE, (char *) &x_recv, 4)) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Can't add options, aborting send feedback (tfrc_send_feedback)"));
		/* todo: remove options */
		dccpstat.tfrcs_recv_erropt++;
		return;
	}
	cb->pcb->ack_snd = elm->seq;
	cb->last_counter = elm->win_count;
	cb->seq_last_counter = elm->seq;
	microtime(&(cb->t_last_feedback));
	cb->bytes_recv = 0;
	TFRC_DEBUG((LOG_INFO, "TFRC - Sending a feedback packet with (t_elapsed %u,pinv %u, x_recv %u, ack=%u) (tfrc_recv_send_feedback)\n", ntohs(t_elapsed), ntohl(pinv), ntohl(x_recv), elm->seq));
	dccpstat.tfrcs_recv_fbacks++;
	dccp_output(cb->pcb, 1);
}
/*
 * Calculate first loss interval
 * args: cb - ccb of the receiver
 * returns: loss interval
 * Tested u:OK
 */
u_int32_t
tfrc_recv_calcFirstLI(struct tfrc_recv_ccb * cb)
{
	struct r_hist_entry *elm, *elm2;
	struct li_hist_entry *li_elm;
	struct timeval t_temp;
	double t_rtt;
	int temp;
	double x_recv, fval;
	int win_count;

	temp = 1;
	TFRC_RECV_FINDDATAPACKET(cb, elm, temp);

	if (elm == NULL)
		panic("Packet history contains no data packets! (tfrc_recv_calcFirstLI)\n");
	t_temp = elm->t_recv;
	win_count = elm->win_count;
	elm2 = elm;
	TFRC_RECV_NEXTDATAPACKET(cb, elm2);
	while (elm2 != NULL) {
		temp = win_count - (int) (elm2->win_count);
		if (temp < 0)
			temp = temp + TFRC_WIN_COUNT_LIMIT;

		if (temp > 4)
			break;
		elm = elm2;
		TFRC_RECV_NEXTDATAPACKET(cb, elm2);
	}

	if (elm2 == NULL) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Could not find a win_count interval > 4 \n"));
		elm2 = elm;
		if (temp == 0) {
			TFRC_DEBUG((LOG_INFO, "TFRC - Could not find a win_count interval > 0. Defaulting to 1 (tfrc_recv_calcFirstLI)\n"));
			temp = 1;
		}
	}
	PRINTRCCB(cb, elm, li_elm);
	timersub(&t_temp, &t_temp, &elm2->t_recv);
	t_rtt = ((double) (t_temp.tv_sec)) + ((double) (t_temp.tv_usec)) / ((double) 1000000);

	if (t_rtt < 0) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Approximation of RTT is negative!\n"));
		t_rtt = -t_rtt;
	}
	t_rtt = t_rtt * 4 / ((double) (temp));

	TFRC_DEBUG((LOG_INFO, "TFRC - Approximated rtt to "));
	PRINTFLOAT(t_rtt);
	TFRC_DEBUG((LOG_INFO, " s (tfrc_recv_calcFirstLI)\n"));

	/* Calculate x_recv */
	microtime(&t_temp);
	timersub(&t_temp, &t_temp, &cb->t_last_feedback);
	x_recv = (((double) (cb->bytes_recv)) /
	    (((double) t_temp.tv_sec) + ((double) t_temp.tv_usec) / 1000000.0));

	TFRC_DEBUG((LOG_INFO, "TFRC - Receive rate "));
	PRINTFLOAT(x_recv);
	TFRC_DEBUG((LOG_INFO, " bytes/s (tfrc_recv_calcFirstLI)\n"));

	fval = ((double) (cb->s)) / (x_recv * t_rtt);
	TFRC_DEBUG((LOG_INFO, "TFRC - Fvalue to locate "));
	PRINTFLOAT(fval);
	TFRC_DEBUG((LOG_INFO, " (tfrc_recv_calcFirstLI)\n"));
	fval = tfrc_flookup_reverse(fval);
	TFRC_DEBUG((LOG_INFO, "TFRC - Lookup gives p= "));
	PRINTFLOAT(fval);
	TFRC_DEBUG((LOG_INFO, " (tfrc_recv_calcFirstLI)\n"));
	TFRC_DEBUG((LOG_INFO, "First interval length %u\n", (u_int32_t) (1.0 / fval)));
	if (fval == 0)
		return (u_int32_t) 0xFFFFFFFF;
	return (u_int32_t) (1.0 / fval);
}
/* Add packet to recv history (sorted on seqnum)
 * Do not add packets that are already lost
 * args: cb - ccb of receiver
 *       packet - packet to insert
 * returns:  1 if the packet was considered lost, 0 otherwise
 * Tested u:OK
 */
int
tfrc_recv_add_hist(struct tfrc_recv_ccb * cb, struct r_hist_entry * packet)
{
	struct r_hist_entry *elm, *elm2;
	u_int8_t num_later = 0, win_count;
	u_int32_t seq_num = packet->seq;
	int temp;

	TFRC_DEBUG((LOG_INFO, "TFRC - Adding packet (seq=%u,win_count=%u,type=%u,ndp=%u) to history! (tfrc_recv_add_hist)\n", packet->seq, packet->win_count, packet->type, packet->ndp));

	if (TAILQ_EMPTY(&(cb->hist))) {
		TAILQ_INSERT_HEAD(&(cb->hist), packet, linfo);
	} else {
		elm = TAILQ_FIRST(&(cb->hist));
		if ((seq_num > elm->seq
			&& seq_num - elm->seq < TFRC_RECV_NEW_SEQ_RANGE) ||
		    (seq_num < elm->seq
			&& elm->seq - seq_num > DCCP_SEQ_NUM_LIMIT - TFRC_RECV_NEW_SEQ_RANGE)) {
			TAILQ_INSERT_HEAD(&(cb->hist), packet, linfo);
		} else {
			if (elm->type == DCCP_TYPE_DATA || elm->type == DCCP_TYPE_DATAACK)
				num_later = 1;

			elm2 = TAILQ_NEXT(elm, linfo);
			while (elm2 != NULL) {
				if ((seq_num > elm2->seq
					&& seq_num - elm2->seq < TFRC_RECV_NEW_SEQ_RANGE) ||
				    (seq_num < elm2->seq
					&& elm2->seq - seq_num > DCCP_SEQ_NUM_LIMIT - TFRC_RECV_NEW_SEQ_RANGE)) {
					TAILQ_INSERT_AFTER(&(cb->hist), elm, packet, linfo);
					break;
				}
				elm = elm2;
				elm2 = TAILQ_NEXT(elm, linfo);

				if (elm->type == DCCP_TYPE_DATA || elm->type == DCCP_TYPE_DATAACK)
					num_later++;

				if (num_later == TFRC_RECV_NUM_LATE_LOSS) {
					free(packet, M_TEMP);
					TFRC_DEBUG((LOG_INFO, "TFRC - Packet already lost! (tfrc_recv_add_hist)\n"));
					return 1;
					break;
				}
			}

			if (elm2 == NULL && num_later < TFRC_RECV_NUM_LATE_LOSS) {
				TAILQ_INSERT_TAIL(&(cb->hist), packet, linfo);
			}
		}
	}

	/* trim history (remove all packets after the NUM_LATE_LOSS+1 data
	 * packets) */
	if (TAILQ_FIRST(&(cb->li_hist)) != NULL) {
		num_later = TFRC_RECV_NUM_LATE_LOSS + 1;
		TFRC_RECV_FINDDATAPACKET(cb, elm, num_later);
		if (elm != NULL) {
			elm2 = TAILQ_NEXT(elm, linfo);
			while (elm2 != NULL) {
				TAILQ_REMOVE(&(cb->hist), elm2, linfo);
				free(elm2, M_TEMP);
				elm2 = TAILQ_NEXT(elm, linfo);
			}
		}
	} else {
		/* we have no loss interval history so we need at least one
		 * rtt:s of data packets to approximate rtt */
		num_later = TFRC_RECV_NUM_LATE_LOSS + 1;
		TFRC_RECV_FINDDATAPACKET(cb, elm2, num_later);
		if (elm2 != NULL) {
			num_later = 1;
			TFRC_RECV_FINDDATAPACKET(cb, elm, num_later);
			win_count = elm->win_count;

			elm = elm2;
			TFRC_RECV_NEXTDATAPACKET(cb, elm2);
			while (elm2 != NULL) {
				temp = win_count - (int) (elm2->win_count);
				if (temp < 0)
					temp = temp + TFRC_WIN_COUNT_LIMIT;

				if (temp > TFRC_WIN_COUNT_PER_RTT + 1) {
					/* we have found a packet older than
					 * one rtt remove the rest */
					elm = TAILQ_NEXT(elm2, linfo);

					while (elm != NULL) {
						TAILQ_REMOVE(&(cb->hist), elm, linfo);
						free(elm, M_TEMP);
						elm = TAILQ_NEXT(elm2, linfo);
					}
					break;
				}
				elm = elm2;
				TFRC_RECV_NEXTDATAPACKET(cb, elm2);
			}
		}		/* end if (exist atleast 4 data packets) */
	}

	return 0;
}
/*
 * Detect loss events and update loss interval history
 * args: cb - ccb of the receiver
 * Tested u:OK
 */
void
tfrc_recv_detectLoss(struct tfrc_recv_ccb * cb)
{
	struct r_hist_entry *bLoss, *aLoss, *elm, *elm2;
	u_int8_t num_later = TFRC_RECV_NUM_LATE_LOSS;
	long seq_temp = 0;
	long seq_loss = -1;
	u_int8_t win_loss = 0;

	TFRC_RECV_FINDDATAPACKET(cb, bLoss, num_later);

	if (bLoss == NULL) {
		/* not enough packets yet to cause the first loss event */
	} else {		/* bloss != NULL */
		num_later = TFRC_RECV_NUM_LATE_LOSS + 1;
		TFRC_RECV_FINDDATAPACKET(cb, aLoss, num_later);
		if (aLoss == NULL) {
			if (TAILQ_EMPTY(&(cb->li_hist))) {
				/* no loss event have occured yet */

				/* todo: find a lost data packet by comparing
				 * to initial seq num */

			} else {
				panic("Less than 4 data packets in history (tfrc_recv_detecLossEvent)\n");
			}
		} else {	/* aLoss != NULL */
			/* locate a lost data packet */
			elm = bLoss;
			elm2 = TAILQ_NEXT(elm, linfo);
			do {
				seq_temp = ((long) (elm->seq)) - ((long) elm2->seq);

				if (seq_temp < 0)
					seq_temp = seq_temp + DCCP_SEQ_NUM_LIMIT;

				if (seq_temp != 1) {
					/* check no data packets */
					if (elm->type == DCCP_TYPE_DATA || elm->type == DCCP_TYPE_DATAACK)
						seq_temp = seq_temp - 1;
					if (seq_temp % DCCP_NDP_LIMIT != ((int) elm->ndp - (int) elm2->ndp + DCCP_NDP_LIMIT) % DCCP_NDP_LIMIT)
						seq_loss = (elm2->seq + 1) % DCCP_SEQ_NUM_LIMIT;
				}
				elm = elm2;
				elm2 = TAILQ_NEXT(elm2, linfo);
			} while (elm != aLoss);

			if (seq_loss != -1) {
				win_loss = aLoss->win_count;
			}
		}
	}			/* end if (bLoss == NULL) */
	tfrc_recv_updateLI(cb, seq_loss, win_loss);
}
/* Updates the loss interval history
 * cb   -  congestion control block
 * seq_loss  -  sequence number of lost packet (-1 for none)
 * win_loss  -  window counter for previous (from the lost packet view) packet
 * Tested u:OK
 */
void
tfrc_recv_updateLI(struct tfrc_recv_ccb * cb, long seq_loss, u_int8_t win_loss)
{
	struct r_hist_entry *elm, *elm_temp;
	struct li_hist_entry *li_elm, *li_elm2, *li_elm_temp;
	u_int8_t num_later = TFRC_RECV_NUM_LATE_LOSS;
	long seq_temp = 0;
	int i;
	u_int8_t win_start;
	int debug_info = 0;
	if (seq_loss != -1) {	/* we have found a packet loss! */
		dccpstat.tfrcs_recv_losts++;
		TFRC_DEBUG((LOG_INFO, "TFRC - seqloss=%i, winloss=%i\n", (int) seq_loss, (int) win_loss));
		if (TAILQ_EMPTY(&(cb->li_hist))) {
			debug_info = 1;
			/* first loss detected */
			TFRC_DEBUG((LOG_INFO, "TFRC - First loss event detected! (tfrc_recv_updateLI)\n"));
			/* create history */
			for (i = 0; i < TFRC_RECV_IVAL_F_LENGTH + 1; i++) {
				li_elm = malloc(sizeof(struct li_hist_entry),
				    M_TEMP, M_DONTWAIT | M_ZERO);	/* M_TEMP?? */
				if (li_elm == NULL) {
					TFRC_DEBUG((LOG_INFO, "TFRC - Not enough memory for loss interval history!\n"));
					/* Empty loss interval history */
					li_elm = TAILQ_FIRST(&(cb->li_hist));
					while (li_elm != NULL) {
						li_elm2 = TAILQ_NEXT(li_elm, linfo);
						free(li_elm, M_TEMP);	/* M_TEMP ?? */
						li_elm = li_elm2;
					}
					return;
				}
				TAILQ_INSERT_HEAD(&(cb->li_hist), li_elm, linfo);
			}

			li_elm->seq = seq_loss;
			li_elm->win_count = win_loss;

			li_elm = TAILQ_NEXT(li_elm, linfo);
			/* add approx interval */
			li_elm->interval = tfrc_recv_calcFirstLI(cb);

		} else {	/* we have a loss interval history */
			debug_info = 2;
			/* Check if the loss is in the same loss event as
			 * interval start */
			win_start = (TAILQ_FIRST(&(cb->li_hist)))->win_count;
			if ((win_loss > win_start
				&& win_loss - win_start > TFRC_WIN_COUNT_PER_RTT) ||
			    (win_loss < win_start
				&& win_start - win_loss < TFRC_WIN_COUNT_LIMIT - TFRC_WIN_COUNT_PER_RTT)) {
				/* new loss event detected */
				/* calculate last interval length */
				seq_temp = seq_loss - ((long) ((TAILQ_FIRST(&(cb->li_hist)))->seq));
				if (seq_temp < 0)
					seq_temp = seq_temp + DCCP_SEQ_NUM_LIMIT;

				(TAILQ_FIRST(&(cb->li_hist)))->interval = seq_temp;

				TFRC_DEBUG((LOG_INFO, "TFRC - New loss event detected!, interval %i (tfrc_recv_updateLI)\n", (int) seq_temp));
				/* Remove oldest interval */
				li_elm = TAILQ_LAST(&(cb->li_hist), li_hist_head);
				TAILQ_REMOVE(&(cb->li_hist), li_elm, linfo);

				/* Create the newest interval */
				li_elm->seq = seq_loss;
				li_elm->win_count = win_loss;

				/* insert it into history */
				TAILQ_INSERT_HEAD(&(cb->li_hist), li_elm, linfo);
			} else
				TFRC_DEBUG((LOG_INFO, "TFRC - Loss belongs to previous loss event (tfrc_recv_updateLI)!\n"));
		}
	}
	if (TAILQ_FIRST(&(cb->li_hist)) != NULL) {
		/* calculate interval to last loss event */
		num_later = 1;
		TFRC_RECV_FINDDATAPACKET(cb, elm, num_later);

		seq_temp = ((long) (elm->seq)) -
		    ((long) ((TAILQ_FIRST(&(cb->li_hist)))->seq));
		if (seq_temp < 0)
			seq_temp = seq_temp + DCCP_SEQ_NUM_LIMIT;

		(TAILQ_FIRST(&(cb->li_hist)))->interval = seq_temp;
		if (debug_info > 0) {
			TFRC_DEBUG((LOG_INFO, "TFRC - Highest data packet received %u (tfrc_recv_updateLI)\n", elm->seq));
			if (debug_info == 1)
				PRINTRCCB(cb, elm_temp, li_elm_temp);
			else if (debug_info == 2)
				PRINTLIHIST(cb, li_elm_temp);
		}
	}
}


/* Functions declared in struct dccp_cc_sw */
/* Initialises the receiver side
 * returns: pointer to a tfrc_recv_ccb struct on success, otherwise 0
 * Tested u:OK
 */
void *
tfrc_recv_init(struct dccpcb * pcb)
{
	struct tfrc_recv_ccb *ccb;

	ccb = malloc(sizeof(struct tfrc_recv_ccb), M_PCB, M_DONTWAIT | M_ZERO);
	if (ccb == 0) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Unable to allocate memory for tfrc_recv_ccb!\n"));
		return 0;
	}
	/* init recv here */

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_init(&(ccb->mutex), "TFRC Receiver mutex", NULL, MTX_DEF);
#endif

	ccb->pcb = pcb;

	if (ccb->pcb->avgpsize >= TFRC_MIN_PACKET_SIZE && ccb->pcb->avgpsize <= TFRC_MAX_PACKET_SIZE)
		ccb->s = (u_int16_t) ccb->pcb->avgpsize;
	else
		ccb->s = TFRC_STD_PACKET_SIZE;

	TFRC_DEBUG((LOG_INFO, "TFRC - Receiver is using packet size %u\n", ccb->s));

	/* init packet history */
	TAILQ_INIT(&(ccb->hist));

	/* init loss interval history */
	TAILQ_INIT(&(ccb->li_hist));

	ccb->state = TFRC_RSTATE_NO_DATA;
	TFRC_DEBUG((LOG_INFO, "TFRC receiver initialised!\n"));
	dccpstat.tfrcs_recv_conn++;
	return ccb;
}
/* Free the receiver side
 * args: ccb - ccb of recevier
 * Tested u:OK
 */
void
tfrc_recv_free(void *ccb)
{
	struct r_hist_entry *elm, *elm2;
	struct li_hist_entry *li_elm, *li_elm2;
	struct tfrc_recv_ccb *cb = (struct tfrc_recv_ccb *) ccb;

	if (ccb == 0)
		panic("TFRC - Receiver ccb is null! (free)");

	/* uninit recv here */

	cb->state = TFRC_RSTATE_TERM;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	/* get mutex */
	mtx_lock(&(cb->mutex));
#endif

	/* Empty packet history */
	elm = TAILQ_FIRST(&(cb->hist));
	while (elm != NULL) {
		elm2 = TAILQ_NEXT(elm, linfo);
		free(elm, M_TEMP);	/* M_TEMP ?? */
		elm = elm2;
	}
	TAILQ_INIT(&(cb->hist));

	/* Empty loss interval history */
	li_elm = TAILQ_FIRST(&(cb->li_hist));
	while (li_elm != NULL) {
		li_elm2 = TAILQ_NEXT(li_elm, linfo);
		free(li_elm, M_TEMP);	/* M_TEMP ?? */
		li_elm = li_elm2;
	}
	TAILQ_INIT(&(cb->li_hist));

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
	mtx_destroy(&(cb->mutex));
#endif

	free(ccb, M_PCB);

	TFRC_DEBUG((LOG_INFO, "TFRC receiver is destroyed\n"));
}


/*
 * Tell TFRC that a packet has been received
 * args: ccb  -  ccb block for current connection
 */
void
tfrc_recv_packet_recv(void *ccb, char *options, int optlen)
{
	struct r_hist_entry *packet;
	u_int8_t win_count = 0;
	double p_prev;
	int ins;
	struct tfrc_recv_ccb *cb = (struct tfrc_recv_ccb *) ccb;

#ifdef NOTFRCRECV
	return;
#endif

	if (!(cb->state == TFRC_RSTATE_NO_DATA || cb->state == TFRC_RSTATE_DATA)) {
		panic("TFRC - Illegal state! (tfrc_recv_packet_recv)\n");
		return;
	}
	/* Check which type */
	switch (cb->pcb->type_rcv) {
	case DCCP_TYPE_ACK:
		if (cb->state == TFRC_RSTATE_NO_DATA)
			return;
		break;
	case DCCP_TYPE_DATA:
	case DCCP_TYPE_DATAACK:
		break;
	default:
		TFRC_DEBUG((LOG_INFO, "TFRC - Received not data/dataack/ack packet! (tfrc_recv_packet_recv)"));
		return;
	}

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_lock(&(cb->mutex));
#endif

	/* Add packet to history */

	packet = malloc(sizeof(struct r_hist_entry), M_TEMP, M_DONTWAIT);	/* M_TEMP?? */
	if (packet == NULL) {
		TFRC_DEBUG((LOG_INFO, "TFRC - Not enough memory to add received packet to history (consider it lost)! (tfrc_recv_packet_recv)"));
		dccpstat.tfrcs_recv_nomem++;
		goto rp_release;
	}
	microtime(&(packet->t_recv));
	packet->seq = cb->pcb->seq_rcv;
	packet->type = cb->pcb->type_rcv;
	packet->ndp = cb->pcb->ndp_rcv;

	ins = dccp_get_option(options, optlen, TFRC_OPT_WINDOW_COUNT, (char *) &win_count, 1);

	if ((packet->type == DCCP_TYPE_DATA || packet->type == DCCP_TYPE_DATAACK) &&
	    (ins != 1)) {
		TFRC_DEBUG((LOG_INFO, "TFRC - No window counter (size %i) option on data packet! (consider it lost)! (tfrc_recv_packet_recv)", ins));
		free(packet, M_TEMP);
		dccpstat.tfrcs_recv_noopt++;
		goto rp_release;
	}
	packet->win_count = win_count;

	ins = tfrc_recv_add_hist(cb, packet);

	/* check if we got a data packet */
	if (cb->pcb->type_rcv != DCCP_TYPE_ACK) {

		switch (cb->state) {
		case TFRC_RSTATE_NO_DATA:
			TFRC_DEBUG((LOG_INFO, "TFRC - Send an inital feedback packet (tfrc_recv_packet_recv)\n"));
			tfrc_recv_send_feedback(cb);
			cb->state = TFRC_RSTATE_DATA;
			break;
		case TFRC_RSTATE_DATA:
			cb->bytes_recv = cb->bytes_recv + cb->pcb->len_rcv;
			if (!ins) {
				/* find loss event */
				tfrc_recv_detectLoss(cb);
				p_prev = cb->p;

				/* Calculate loss event rate */
				if (!TAILQ_EMPTY(&(cb->li_hist))) {
					cb->p = 1 / tfrc_calcImean(cb);
				}
				/* check send conditions then send */
				if (cb->p > p_prev) {
					TFRC_DEBUG((LOG_INFO, "TFRC - Send a feedback packet because p>p_prev (tfrc_recv_packet_recv)\n"));
					tfrc_recv_send_feedback(cb);
				} else {
					if ((cb->pcb->seq_rcv > cb->seq_last_counter
						&& cb->pcb->seq_rcv - cb->seq_last_counter < TFRC_RECV_NEW_SEQ_RANGE) ||
					    (cb->pcb->seq_rcv < cb->seq_last_counter
						&& cb->seq_last_counter - cb->pcb->seq_rcv > DCCP_SEQ_NUM_LIMIT - TFRC_RECV_NEW_SEQ_RANGE)) {

						/* the sequence number is
						 * newer than seq_last_count */
						if ((win_count > cb->last_counter
							&& win_count - cb->last_counter > TFRC_WIN_COUNT_PER_RTT) ||
						    (win_count < cb->last_counter
							&& cb->last_counter - win_count < TFRC_WIN_COUNT_LIMIT - TFRC_WIN_COUNT_PER_RTT)) {

							TFRC_DEBUG((LOG_INFO, "TFRC - Send a feedback packet (%i)(win_count larger) (tfrc_recv_packet_recv)\n", (win_count - cb->last_counter + TFRC_WIN_COUNT_LIMIT) % TFRC_WIN_COUNT_LIMIT));

							tfrc_recv_send_feedback(cb);
						}
					}	/* end newer seqnum */
				}	/* end p > p_prev */

			}
			break;
		default:
			panic("tfrc_recv_packet_recv: Illegal state!");
			break;
		}

	}			/* end if not pure ack */
rp_release:
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	mtx_unlock(&(cb->mutex));
#endif
}


/*
 * fixpoint routines
 */
static void
normalize(num, denom)
	long long *num, *denom;
{
	static const int prime[] = { 2, 3, 5, 7, 11, 13, 17, 19, 0 };
	int i;

	if (denom < 0) {
		*num *= (-1);
		*denom *= (-1);
	}

	if (*num % *denom == 0) {
		*num /= *denom;
		*denom = 1;
	}
	for (i = 0; prime[i]; i++)
		while (*num % prime[i] == 0 && *denom % prime[i] == 0) {
			*num /= prime[i];
			*denom /= prime[i];
		}
}

struct fixpoint *
fixpoint_add(x, a, b)
	struct fixpoint *x;
	const struct fixpoint *a, *b;
{
	long long num, denom;

	num = a->num * b->denom + a->denom * b->num;
	denom = a->denom * b->denom;
	normalize(&num, &denom);

	x->num = num;
	x->denom = denom;
	return (x);
}

struct fixpoint *
fixpoint_sub(x, a, b)
	struct fixpoint *x;
	const struct fixpoint *a, *b;
{
	long long num, denom;

	num = a->num * b->denom - a->denom * b->num;
	denom = a->denom * b->denom;
	normalize(&num, &denom);

	x->num = num;
	x->denom = denom;
	return (x);
}

int
fixpoint_cmp(a, b)
	const struct fixpoint *a, *b;
{
	struct fixpoint x;

	fixpoint_sub(&x, a, b);
	if (x.num > 0)
		return (1);
	else if (x.num < 0)
		return (-1);
	else
		return (0);
}

struct fixpoint *
fixpoint_mul(x, a, b)
	struct fixpoint *x;
	const struct fixpoint *a, *b;
{
	long long num, denom;

	num = a->num * b->num;
	denom = a->denom * b->denom;
	normalize(&num, &denom);

	x->num = num;
	x->denom = denom;
	return (x);
}

struct fixpoint *
fixpoint_div(x, a, b)
	struct fixpoint *x;
	const struct fixpoint *a, *b;
{
	long long num, denom;

	num = a->num * b->denom;
	denom = a->denom * b->num;
	normalize(&num, &denom);

	x->num = num;
	x->denom = denom;
	return (x);
}

long
fixpoint_getlong(x)
	const struct fixpoint *x;
{

	if (x->denom == 0)
		return (0);
	return (x->num / x->denom);
}

const struct fixpoint flargex = { 2LL, 1000LL };
const struct fixpoint fsmallx = { 1LL, 100000LL };
const struct fixpoint fsmallstep = { 4LL, 1000000LL };

/*
 * FLOOKUP macro. NOTE! 0<=(int x)<=1 
 * Tested u:OK
 */
const struct fixpoint *
flookup(x)
	const struct fixpoint *x;
{
	static const struct fixpoint y = { 250000, 1 };
	struct fixpoint z;
	int i;

	if (fixpoint_cmp(x, &flargex) >= 0) {
		if (x->num == 0)
			return NULL;
		i = x->denom / x->num;
#ifdef TFRCDEBUG
		if (i >= sizeof(flarge_table) / sizeof(flarge_table[0])
			panic("flarge_table lookup failed");
#endif

		return &flarge_table[i];
	} else {
		fixpoint_mul(&z, x, &y);
		if (z.num == 0)
			return NULL;
		i = fixpoint_getlong(&z);
#ifdef TFRCDEBUG
		if (i >= sizeof(fsmall_table) / sizeof(fsmall_table[0])
			panic("fsmall_table lookup failed");
#endif

		return &fsmall_table[i];
	}
}

/*
 * Inverse of the FLOOKUP above
 * args: fvalue - function value to match
 * returns:  p  closest to that value
 * Tested u:OK
 */
const struct fixpoint *
tfrc_flookup_reverse(const struct fixpoint *fvalue)
{
	static struct fixpoint x;
	int ctr;

	if (fixpoint_cmp(fvalue, &flarge_table[1]) >= 0) {
		/* 1.0 */
		x.num = 1;
		x.denom = 1;
		return &x;
	} else if (fixpoint_cmp(fvalue, &flarge_table[sizeof(flarge_table) /
	    sizeof(flarge_table[0]) - 1]) >= 0) {
		ctr = sizeof(flarge_table) / sizeof(flarge_table[0]) - 1;
		while (ctr > 1 && fixpoint_cmp(fvalue, &flarge_table[ctr]) >= 0)
			ctr--;

		/* round to smallest */
		ctr = ctr + 1;
    
		/* round to nearest */
		return &flarge_table[ctr];
	} else if (fixpoint_cmp(fvalue, &fsmall_table[0]) >= 0) {
		ctr = 0;
		while (ctr < sizeof(fsmall_table) / sizeof(fsmall_table[0]) &&
		    fixpoint_cmp(fvalue, &fsmall_table[ctr]) > 0)
			ctr++;
		x = fsmallstep;
		x.num *= ctr;
		return &x;
	}
	return &fsmallstep;
}
