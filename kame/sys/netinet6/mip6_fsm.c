/*	$KAME: mip6_fsm.c,v 1.28 2004/06/02 05:53:16 itojun Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.  All rights reserved.
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
#ifdef __FreeBSD__
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/scope6_var.h>

#include <netinet/ip6mh.h>
#include <net/if_hif.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#include <netinet6/mip6_mncore.h>

static int mip6_bu_pri_fsm(struct mip6_bu *, int, void *);
static int mip6_bu_pri_fsm_home_registration(struct mip6_bu *);
static int mip6_bu_sec_fsm(struct mip6_bu *, int, void *);
static void mip6_bu_stop_timers(struct mip6_bu *);

int
mip6_bu_fsm(mbu, event, data)
	struct mip6_bu *mbu;
	int event;
	void *data;
{
	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

	if (MIP6_BU_IS_PRI_FSM_EVENT(event))
		return (mip6_bu_pri_fsm(mbu, event, data));
	if (MIP6_BU_IS_SEC_FSM_EVENT(event))
		return (mip6_bu_sec_fsm(mbu, event, data));

	/* invalid event. */
	return (EINVAL);
}

int
mip6_bu_pri_fsm(mbu, event, data)
	struct mip6_bu *mbu;
	int event;
	void *data;
{
	u_int8_t *mbu_pri_fsm_state;
	int error;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif
	struct ip6_mh_binding_request *ip6mr;
	struct ip6_mh_binding_ack *ip6ma;
	struct ip6_mh_binding_error *ip6me;
	struct icmp6_hdr *icmp6;
	struct hif_softc *hif;

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

#ifdef __FreeBSD__
	mono_time.tv_sec = time_second;
#endif

	mbu_pri_fsm_state = &mbu->mbu_pri_fsm_state;

	/* set pointers. */
	ip6mr = (struct ip6_mh_binding_request *)data;
	ip6ma = (struct ip6_mh_binding_ack *)data;
	ip6me = (struct ip6_mh_binding_error *)data;
	icmp6 = (struct icmp6_hdr *)data;
	hif = (struct hif_softc *)data;

	error = 0;

	switch (*mbu_pri_fsm_state) {
	case MIP6_BU_PRI_FSM_STATE_IDLE:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Reset retransmission counter,
				 * Start retransmission timer,
				 * XXX Start failure timer.
				 */
				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * Start RR.
				 */
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "secondary fsm transition "
					    "failed.\n",
					    __FILE__, __LINE__, error));
					return (error);
				}
				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET:
			/*
			 * Start RR.
			 */
			if ((mbu->mbu_state & MIP6_BU_STATE_NEEDTUNNEL)
			    != 0) {
				/*
				 * if the peer doesn't support MIP6,
				 * keep IDLE state.
				 */
				break;
			}
			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_START_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "secondary fsm transition failed.\n",
				    __FILE__, __LINE__, error));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRINIT;

			break;

		case MIP6_BU_PRI_FSM_EVENT_ICMP_PARAMPROB:
			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;
		}
		break;

	case MIP6_BU_PRI_FSM_STATE_RRINIT:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_RR_DONE:
			if ((mbu->mbu_flags & IP6MU_ACK) != 0) {
				/*
				 * if A flag is set,
				 *   Send BU,
				 *   Reset retransmission counter,
				 *   Start retransmission timer,
				 *   Start failure timer.
				 */

				/* XXX no code yet. */

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * if A flag is not set,
				 *   Send BU,
				 *   Start refresh timer.
				 */
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					return (error);
				}

				mbu->mbu_retrans
				    = mono_time.tv_sec + mbu->mbu_lifetime;

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_BOUND;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;
			
		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			/*
			 * Stop timers,
			 * Stop RR,
			 * Start RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);

			if (error == 0) {
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
			}
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRINIT;

			break;

		case MIP6_BU_PRI_FSM_EVENT_RETURNING_HOME:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			/* free mbu */
			mbu->mbu_lifetime = 0;
			mbu->mbu_expire = mono_time.tv_sec + mbu->mbu_lifetime;

			break;

		case MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET:
			/*
			 * Start RR.
			 */
			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_START_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "secondary fsm transition failed.\n",
				    __FILE__, __LINE__, error));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRINIT;

			break;

		case MIP6_BU_PRI_FSM_EVENT_ICMP_PARAMPROB:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;
		}
		break;

	case MIP6_BU_PRI_FSM_STATE_RRREDO:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_RR_DONE:
			if ((mbu->mbu_flags & IP6MU_ACK) != 0) {
				/*
				 * if A flag is set,
				 *   Send BU,
				 *   Reset retransmission counter,
				 *   Start retransmission timer,
				 *   Start failure timer.
				 */

				/* XXX no code yet. */

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITAR;
			} else {
				/*
				 * if A flag is not set,
				 *   Send BU,
				 *   Start refresh timer.
				 */
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					return (error);
				}

				mbu->mbu_retrans
				    = mono_time.tv_sec + mbu->mbu_lifetime;

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_BOUND;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;
			
		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			/*
			 * Stop timers,
			 * Stop RR,
			 * Start RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);

			if (error == 0) {
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
			}
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRINIT;

			break;

		case MIP6_BU_PRI_FSM_EVENT_RETURNING_HOME:
			/*
			 * Stop timers,
			 * Stop RR,
			 * Start Home RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);

			if (error == 0) {
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_HOME_RR,
				    data);
			}
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRDEL;

			break;

		case MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET:
			/*
			 * Start RR.
			 */
			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_START_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "secondary fsm transition failed.\n",
				    __FILE__, __LINE__, error));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRREDO;

			break;

		case MIP6_BU_PRI_FSM_EVENT_ICMP_PARAMPROB:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;
		}
		break;

	case MIP6_BU_PRI_FSM_STATE_WAITA:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_BA:
			/* XXX */
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * (Process BA,)
				 * Stop timer,
				 * Reset retransmission counter,
				 * Start refresh timer.
				 */

				/* XXX home registration completed. */

				mip6_bu_stop_timers(mbu);
				
				mbu->mbu_retrans_count = 0;

				mbu->mbu_retrans
				    = mono_time.tv_sec
				    + mbu->mbu_refresh;

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_BOUND;
			} else {
				/* XXX no code yet. */
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_RETRANS_TIMER:
			/*
			 * Send BU,
			 * Start retransmittion timer.
			 */
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Start retransmittion timer.
				 */
				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					return (error);
				}

				if (mbu->mbu_retrans_count++
				    > MIP6_BU_MAX_BACKOFF)
					mbu->mbu_retrans_count
					    = MIP6_BU_MAX_BACKOFF;
				mbu->mbu_retrans
				    = mono_time.tv_sec
				    + (1 << mbu->mbu_retrans_count);

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/* XXX correct ? */
				break;
			}

			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;

		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Reset retrans counter,
				 * Start retransmittion timer,
				 * XXX Start failure timer.
				 */
				mbu->mbu_retrans_count = 0;
				
				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}
				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_RETURNING_HOME:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Reset retrans counter,
				 * Start retransmittion timer.
				 */
				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITD;
			} else {
				/*
				 * Stop timers,
				 * Start Home RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_HOME_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRDEL;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET:
			/*
			 * Start RR.
			 */
			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_START_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "secondary fsm transition failed.\n",
				    __FILE__, __LINE__, error));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRINIT;

			break;
		}
		break;

	case MIP6_BU_PRI_FSM_STATE_WAITAR:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_BA:
			/* XXX */
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * (Process BA,)
				 * Stop timer,
				 * Reset retrans count,
				 * Start refresh timer.
				 */

				/* XXX home registration completed. */

				mip6_bu_stop_timers(mbu);
				
				mbu->mbu_retrans_count = 0;

				mbu->mbu_retrans
				    = mono_time.tv_sec
				    + mbu->mbu_refresh;

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_BOUND;
			} else {
				/* XXX no code yet. */
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_RETRANS_TIMER:
			/* XXX */
			/*
			 * Send BU,
			 * Start retransmittion timer.
			 */
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Start retransmittion timer.
				 */
				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITAR;
			} else {
				/*
				 * Send BU,
				 * Start retransmission timer.
				 */
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					return (error);
				}

				if (mbu->mbu_retrans_count++
				    > MIP6_BU_MAX_BACKOFF)
					mbu->mbu_retrans_count
					    = MIP6_BU_MAX_BACKOFF;
				mbu->mbu_retrans
				    = mono_time.tv_sec
				    + (1 << mbu->mbu_retrans_count);

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITAR;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/* XXX correct ? */
				break;
			}

			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;

		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Reset retrans counter,
				 * Start retransmittion timer.
				 */
				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}
				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_RETURNING_HOME:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Reset retrans counter,
				 * Start retransmittion timer.
				 */
				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITD;
			} else {
				/*
				 * Stop timers,
				 * Start Home RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_HOME_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRDEL;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET:
			/*
			 * Start RR.
			 */
			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_START_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "secondary fsm transition failed.\n",
				    __FILE__, __LINE__, error));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRREDO;

			break;
		}
		break;

	case MIP6_BU_PRI_FSM_STATE_WAITD:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_BA:
			/* XXX */
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/* XXX home de-registration completed. */
			} else {
				/* XXX no code yet. */
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_RETRANS_TIMER:
			/* XXX */
			/*
			 * Send BU,
			 * Start retransmittion timer.
			 */
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Start retransmittion timer.
				 */
				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITD;
			} else {
				/*
				 * Send BU,
				 * Start retransmittion timer.
				 */
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					return (error);
				}

				if (mbu->mbu_retrans_count++
				    > MIP6_BU_MAX_BACKOFF)
					mbu->mbu_retrans_count
					    = MIP6_BU_MAX_BACKOFF;
				mbu->mbu_retrans
				    = mono_time.tv_sec
				    + (1 << mbu->mbu_retrans_count);

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITD;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/* XXX correct ? */
				break;
			}

			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;

		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * XXX
				 * Stop timers,
				 * Reset retrainsmission counter,
				 * Start retransmission timer,
				 * XXX Start failure timer.
				 */
				mip6_bu_stop_timers(mbu);

				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRINIT;
			}
			break;
		}
		break;

	case MIP6_BU_PRI_FSM_STATE_RRDEL:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_RR_DONE:
			if ((mbu->mbu_flags & IP6MU_ACK) != 0) {
				/*
				 * if A flag is set,
				 *   Send BU,
				 *   Stop timers,
				 *   Start retransmission timer,
				 *   Start failure timer.
				 */

				/* XXX no code yet. */

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITD;
			} else {
				/*
				 * if A flag is not set,
				 *   Stop timers,
				 *   Send BU.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_IDLE;

				/* free mbu */
				mbu->mbu_lifetime = 0;
				mbu->mbu_expire = mono_time.tv_sec + mbu->mbu_lifetime;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNKNOWN_MH_TYPE:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			/* free mbu */
			mbu->mbu_lifetime = 0;
			mbu->mbu_expire = mono_time.tv_sec + mbu->mbu_lifetime;

			break;
			
		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			/*
			 * Stop timers,
			 * Stop RR,
			 * Start RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);

			if (error == 0) {
				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
			}
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRINIT;

			break;

		case MIP6_BU_PRI_FSM_EVENT_ICMP_PARAMPROB:
			/*
			 * Stop timers,
			 * Stop RR.
			 */
			mip6_bu_stop_timers(mbu);

			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_STOP_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "second fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_IDLE;

			mbu->mbu_state |= MIP6_BU_STATE_DISABLE;

			break;
		}
		break;


	case MIP6_BU_PRI_FSM_STATE_BOUND:
		switch (event) {
		case MIP6_BU_PRI_FSM_EVENT_BRR:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Start retransmission timer.
				 */
				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITAR;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRREDO;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_MOVEMENT:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Stop timer,
				 * Send BU,
				 * Reset retransmission counter,
				 * Start retransmission timer,
				 * XXX Start failure timer.
				 */
				mip6_bu_stop_timers(mbu);

				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_RETURNING_HOME:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Stop timer,
				 * Send BU,
				 * Reset retransmission counter,
				 * Start retransmission timer,
				 * XXX Start failure timer.
				 */
				mip6_bu_stop_timers(mbu);

				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITD;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_HOME_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRDEL;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_REVERSE_PACKET:
			/*
			 * Start RR.
			 */
			error = mip6_bu_sec_fsm(mbu,
			    MIP6_BU_SEC_FSM_EVENT_START_RR,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "secondary fsm transition failed.\n",
				    __FILE__, __LINE__, error));
				return (error);
			}

			*mbu_pri_fsm_state = MIP6_BU_PRI_FSM_STATE_RRREDO;

			break;

		case MIP6_BU_PRI_FSM_EVENT_REFRESH_TIMER:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Send BU,
				 * Start retransmission timer.
				 */
				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITAR;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRREDO;
			}
			break;

		case MIP6_BU_PRI_FSM_EVENT_UNVERIFIED_HAO:
			if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
				/*
				 * Stop timer,
				 * Send BU,
				 * Reset retransmission counter,
				 * Start retransmission timer,
				 * XXX Start failure timer.
				 */
				mip6_bu_stop_timers(mbu);

				mbu->mbu_retrans_count = 0;

				error = mip6_bu_pri_fsm_home_registration(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "sending a home registration "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));
					/* continue and try again. */
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_WAITA;
			} else {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				mip6_bu_stop_timers(mbu);

				error = mip6_bu_sec_fsm(mbu,
				    MIP6_BU_SEC_FSM_EVENT_START_RR,
				    data);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: "
					    "second fsm state transition "
					    "failed.\n",
					    __FILE__, __LINE__));
					return (error);
				}

				*mbu_pri_fsm_state
				    = MIP6_BU_PRI_FSM_STATE_RRINIT;
			}
			break;
		}
		break;

	default:
		panic("the state of the primary fsm is unknown.");
	}

	return (0);
}

static int
mip6_bu_pri_fsm_home_registration(mbu)
	struct mip6_bu *mbu;
{
	struct mip6_ha *mha;
	int error;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

#ifdef __FreeBSD__
	microtime(&mono_time);
#endif

	error = mip6_home_registration2(mbu);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending a home registration failed. (%d)\n",
		    __FILE__, __LINE__, error));
		/* continue and try again. */
	}

	if (mbu->mbu_retrans_count++ > MIP6_BU_MAX_BACKOFF) {
		/*
		 * try another home agent.  if we have no alternative,
		 * set an unspecified address to trigger DHAAD
		 * procedure.
		 */
		mha = hif_find_next_preferable_ha(mbu->mbu_hif,
		    &mbu->mbu_paddr);
		if (mha != NULL)
			mbu->mbu_paddr = mha->mha_addr;
		else
			mbu->mbu_paddr = in6addr_any;
		mbu->mbu_retrans_count = 1;
	}
	mbu->mbu_retrans = mono_time.tv_sec + (1 << mbu->mbu_retrans_count);

	return (error);
}

int
mip6_bu_sec_fsm(mbu, event, data)
	struct mip6_bu *mbu;
	int event;
	void *data;
{
	u_int8_t *mbu_sec_fsm_state;
	int error;
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif
	struct ip6_mh_home_test *ip6mh;
	struct ip6_mh_careof_test *ip6mc;

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

	mbu_sec_fsm_state = &mbu->mbu_sec_fsm_state;
#ifdef __FreeBSD__
	mono_time.tv_sec = time_second;
#endif

	mbu_sec_fsm_state = &mbu->mbu_sec_fsm_state;

	/* set pointers. */
	ip6mh = (struct ip6_mh_home_test *)data;
	ip6mc = (struct ip6_mh_careof_test *)data;

	error = 0;

	switch (*mbu_sec_fsm_state) {
	case MIP6_BU_SEC_FSM_STATE_START:
		switch (event) {
		case MIP6_BU_SEC_FSM_EVENT_START_RR:
			/*
			 * Send HoTI,
			 * Send CoTI,
			 * Start retransmission timer,
			 * Steart failure timer
			 */
			if (mip6_bu_send_hoti(mbu) != 0)
				break;
			if (mip6_bu_send_coti(mbu) != 0)
				break;
			mbu->mbu_retrans
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT;
			mbu->mbu_failure
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT * 5; /* XXX */
			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITHC;

			break;
		
		case MIP6_BU_SEC_FSM_EVENT_START_HOME_RR:
			/*
			 * Send HoTI,
			 * Start retransmission timer,
			 * Steart failure timer
			 */
			if (mip6_bu_send_hoti(mbu) != 0)
				break;
			mbu->mbu_retrans
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT;
			mbu->mbu_failure
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT * 5; /* XXX */
			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITH;

			break;
		}
		break;

	case MIP6_BU_SEC_FSM_STATE_WAITHC:
		switch (event) {
		case MIP6_BU_SEC_FSM_EVENT_HOT:
			/*
			 * Store token, nonce index.
			 */
			/* XXX */
			mbu->mbu_home_nonce_index
			    = htons(ip6mh->ip6mhht_nonce_index);
			bcopy(ip6mh->ip6mhht_keygen8, mbu->mbu_home_token,
			    sizeof(ip6mh->ip6mhht_keygen8));

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITC;

			break;

		case MIP6_BU_SEC_FSM_EVENT_COT:
			/*
			 * Store token, nonce index.
			 */
			/* XXX */
			mbu->mbu_careof_nonce_index
			    = htons(ip6mc->ip6mhct_nonce_index);
			bcopy(ip6mc->ip6mhct_keygen8, mbu->mbu_careof_token,
			    sizeof(ip6mc->ip6mhct_keygen8));

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITH;
			break;

		case MIP6_BU_SEC_FSM_EVENT_STOP_RR:
			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_START;

			break;

		case MIP6_BU_SEC_FSM_EVENT_RETRANS_TIMER:
			/*
			 * Send HoTI,
			 * Send CoTI,
			 * Start retransmission timer.
			 */
			if (mip6_bu_send_hoti(mbu) != 0)
				break;
			if (mip6_bu_send_coti(mbu) != 0)
				break;
			mbu->mbu_retrans
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT;

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITHC;

			break;
		}
		break;

	case MIP6_BU_SEC_FSM_STATE_WAITH:
		switch (event) {
		case MIP6_BU_SEC_FSM_EVENT_HOT:
			/*
			 * Store token and nonce index,
			 * Stop timers,
			 * RR done.
			 */
			mbu->mbu_home_nonce_index
			    = htons(ip6mh->ip6mhht_nonce_index);
			bcopy(ip6mh->ip6mhht_keygen8, mbu->mbu_home_token,
			    sizeof(ip6mh->ip6mhht_keygen8));

			mip6_bu_stop_timers(mbu);

			error = mip6_bu_pri_fsm(mbu,
			    MIP6_BU_PRI_FSM_EVENT_RR_DONE,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "primary fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_START;

			break;

		case MIP6_BU_SEC_FSM_EVENT_STOP_RR:
			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_START;

			break;

		case MIP6_BU_SEC_FSM_EVENT_RETRANS_TIMER:
			/*
			 * Send HoTI,
			 * Start retransmission timer.
			 */
			if (mip6_bu_send_hoti(mbu) != 0)
				break;
			mbu->mbu_retrans
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT;

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITH;

			break;
		}
		break;

	case MIP6_BU_SEC_FSM_STATE_WAITC:
		switch (event) {
		case MIP6_BU_SEC_FSM_EVENT_COT:
			/*
			 * Store token and nonce index,
			 * Stop timers,
			 * RR done.
			 */
			mbu->mbu_careof_nonce_index
			    = htons(ip6mc->ip6mhct_nonce_index);
			bcopy(ip6mc->ip6mhct_keygen8, mbu->mbu_careof_token,
			    sizeof(ip6mc->ip6mhct_keygen8));

			mip6_bu_stop_timers(mbu);

			error = mip6_bu_pri_fsm(mbu,
			    MIP6_BU_PRI_FSM_EVENT_RR_DONE,
			    data);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: "
				    "primary fsm state transition failed.\n",
				    __FILE__, __LINE__));
				return (error);
			}

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_START;

			break;

		case MIP6_BU_SEC_FSM_EVENT_STOP_RR:
			/*
			 * Stop timers.
			 */
			mip6_bu_stop_timers(mbu);

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_START;

			break;

		case MIP6_BU_SEC_FSM_EVENT_RETRANS_TIMER:
			/*
			 * Send CoTI,
			 * Start retransmission timer.
			 */
			if (mip6_bu_send_coti(mbu) != 0)
				break;
			mbu->mbu_retrans
			    = mono_time.tv_sec + MIP6_HOT_TIMEOUT;

			*mbu_sec_fsm_state = MIP6_BU_SEC_FSM_STATE_WAITC;

			break;
		}
		break;

	default:
		panic("the state of the secondary fsm is unknown.");
	}
	return (0);
}

void
mip6_bu_stop_timers(mbu)
	struct mip6_bu *mbu;
{
	if (mbu == NULL)
		return;

	mbu->mbu_retrans = 0;
	mbu->mbu_failure = 0;
}
