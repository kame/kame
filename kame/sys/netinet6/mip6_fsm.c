/*	$KAME: mip6_fsm.c,v 1.7 2002/08/08 07:18:01 k-sugyou Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
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

#include <net/if_hif.h>

#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>

int
mip6_bu_fsm(mbu, event, data)
	struct mip6_bu *mbu;
	int event;
	void *data;
{
	u_int8_t *mbu_fsm_state;
	struct ip6m_binding_request *ip6mr;
	struct ip6m_home_test *ip6mh;
	struct ip6m_careof_test *ip6mc;
	struct ip6m_binding_ack *ip6ma;
	struct ip6m_binding_error *ip6me;
	struct icmp6_hdr *icmp6;
	int error;

	/* set pointers. */
	ip6mr = (struct ip6m_binding_request *)data;
	ip6mh = (struct ip6m_home_test *)data;
	ip6mc = (struct ip6m_careof_test *)data;
	ip6ma = (struct ip6m_binding_ack *)data;
	ip6me = (struct ip6m_binding_error *)data;
	icmp6 = (struct icmp6_hdr *)data;

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

	mbu_fsm_state = &mbu->mbu_fsm_state;

#ifdef MIP6_DEBUG
	mip6log((LOG_INFO, "st=%d:ev=%d =>", *mbu_fsm_state, event));
#endif

	switch (*mbu_fsm_state)
	{
	case MIP6_BU_FSM_STATE_IDLE:
		switch (event) {
		case MIP6_BU_FSM_EVENT_RO_DESIRED:
			/*
			 * send HoTI, CoTI, start retrans timer and
			 * failure timers.
			 */

			/* XXX error handling */
			mip6_bu_send_hoti(mbu);
			mip6_bu_send_coti(mbu);

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			break;
		}
		break;

	case MIP6_BU_FSM_STATE_WAITHC:
		switch (event) {
		case MIP6_BU_FSM_EVENT_HOT_RECEIVED:
			/*
			 * store cookie and nonce index.
			 */

			/* XXX */
			mbu->mbu_home_nonce_index
			    = htons(ip6mh->ip6mh_nonce_index);
			bcopy(ip6mh->ip6mh_cookie, mbu->mbu_home_cookie,
			    sizeof(ip6mh->ip6mh_cookie));

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITC;
			break;

		case MIP6_BU_FSM_EVENT_COT_RECEIVED:
			/*
			 * store cookie and nonce index.
			 */

			/* XXX */
			mbu->mbu_careof_nonce_index
			    = htons(ip6mc->ip6mc_nonce_index);
			bcopy(ip6mc->ip6mc_cookie, mbu->mbu_careof_cookie,
			    sizeof(ip6mc->ip6mc_cookie));

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITH;
			break;

		case MIP6_BU_FSM_EVENT_RETRANS:
			/*
			 * send HoTI, CoTI, start retrans timer.
			 */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_BE_2_RECEIVED:
			/*
			 * stop timers.
			 */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_MOVEMENT:
			/*
			 * send CoTI, restart retrans and failure timers.
			 */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_ICMP_PARAMPROB_RECEIVED:
			/*
			 * stop timers.
			 */

			/* XXX */

			break;
		}
		break;

	case MIP6_BU_FSM_STATE_WAITH:
		switch(event) {
		case MIP6_BU_FSM_EVENT_HOT_RECEIVED:
			/*
			 * store cookie and nonce index, send bu.
			 */

			mbu->mbu_home_nonce_index
			    = htons(ip6mh->ip6mh_nonce_index);
			bcopy(ip6mh->ip6mh_cookie, mbu->mbu_home_cookie,
			    sizeof(ip6mh->ip6mh_cookie));

			if (mbu->mbu_flags & IP6MU_ACK) {
				/*
				 * start retrans timer.
				 */
				
				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITA;
			} else {
				/*
				 * stop timers.
				 */

				/* XXX */

				/* XXX */ mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));

					/* restore state. */
					*mbu_fsm_state
					    = MIP6_BU_FSM_STATE_WAITH;
					return (error);
				}

				*mbu_fsm_state = MIP6_BU_FSM_STATE_BOUND;
			}
			break;

		case MIP6_BU_FSM_EVENT_RETRANS:
			/*
			 * send HoTI, start retrans timer.
			 */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_BE_2_RECEIVED:
			/*
			 * stop timers.
			 */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			break;

		case MIP6_BU_FSM_EVENT_MOVEMENT:
			/*
			 * send CoTI, restart retrans and failure timers.
			 */

			/* XXX */

			break;
		}
		break;

	case MIP6_BU_FSM_STATE_WAITC:
		switch (event) {
		case MIP6_BU_FSM_EVENT_COT_RECEIVED:
			/*
			 * store cookie and nonce index, send bu.
			 */

			mbu->mbu_careof_nonce_index
			    = htons(ip6mc->ip6mc_nonce_index);
			bcopy(ip6mc->ip6mc_cookie, mbu->mbu_careof_cookie,
			    sizeof(ip6mc->ip6mc_cookie));

			if (mbu->mbu_flags & IP6MU_ACK) {
				/*
				 * start retrans timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITA;
			} else {
				/*
				 * stop timers.
				 */

				/* XXX */

				/* XXX */ mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
				error = mip6_bu_send_cbu(mbu);
				if (error) {
					mip6log((LOG_ERR,
					    "%s:%d: sending a binding upate "
					    "failed. (%d)\n",
					    __FILE__, __LINE__, error));

					/* restore state. */
					*mbu_fsm_state
					    = MIP6_BU_FSM_STATE_WAITC;
					return (error);
				}

				*mbu_fsm_state = MIP6_BU_FSM_STATE_BOUND;
			}
			break;

		case MIP6_BU_FSM_EVENT_BE_2_RECEIVED:
			/*
			 * stop timers.
			 */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			break;

		case MIP6_BU_FSM_EVENT_RETRANS:
			/*
			 * send CoTI, restart retrans and failure timers.
			 */

			/* XXX */

			break;
		}
		break;

	case MIP6_BU_FSM_STATE_WAITA:
		switch (event) {
		case MIP6_BU_FSM_EVENT_BA_RECEIVED:
			if (ip6ma->ip6ma_status < IP6MA_STATUS_ERRORBASE) {
				/* stop timers. */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_BOUND;
			} else if (ip6ma->ip6ma_status
			    == IP6MA_STATUS_SEQNO_TOO_SMALL) {
				/*
				 * set seq#, send bu, restart retrans
				 * and failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITA;
			} else if ((ip6ma->ip6ma_status
			    == IP6MA_STATUS_HOME_NONCE_EXPIRED)
			    || (ip6ma->ip6ma_status
			    == IP6MA_STATUS_CAREOF_NONCE_EXPIRED)) {
				/*
				 * send HoTI, CoTI, restart
				 * retransmission and failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			} else {
				/* stop timers. */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			}
			break;

		case MIP6_BU_FSM_EVENT_RETRANS:
			/* send bu, start retrans timer. */

			/* XXX */
			break;

		case MIP6_BU_FSM_EVENT_BE_2_RECEIVED:
			/* stop timers. */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			break;

		case MIP6_BU_FSM_EVENT_MOVEMENT:
			/* send CoTI, restart retran and failure timers. */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITC;
			break;
		}
		break;

	case MIP6_BU_FSM_STATE_WAITD:
		switch (event) {
		case MIP6_BU_FSM_EVENT_BA_RECEIVED:
			if (ip6ma->ip6ma_status < IP6MA_STATUS_ERRORBASE) {
				/* stop timers. */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			} else if (ip6ma->ip6ma_status
			    == IP6MA_STATUS_SEQNO_TOO_SMALL) {
				/*
				 * set seq#, send bu, restart retrans
				 * and failure timers.
				 */

				/* XXX */
			} else if ((ip6ma->ip6ma_status
			    == IP6MA_STATUS_HOME_NONCE_EXPIRED)
			    || (ip6ma->ip6ma_status
			    == IP6MA_STATUS_CAREOF_NONCE_EXPIRED)) {
				/*
				 * send HoTI, restart retrans and
				 * failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITDH;
			} else {
				/* stop timers. */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			}
			break;

		case MIP6_BU_FSM_EVENT_RETRANS:
			/* send bu, start retrans timer. */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_BE_1_RECEIVED:
		case MIP6_BU_FSM_EVENT_BE_2_RECEIVED:
			/* stop timers. */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_RO_DESIRED:
			/*
			 * send HoTI, CoTI, restart retrans and
			 * failure timers.
			 */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			break;
		}
		break;

	case MIP6_BU_FSM_STATE_WAITDH:
		switch (event) {
		case MIP6_BU_FSM_EVENT_HOT_RECEIVED:
			if (mbu->mbu_flags & IP6MU_ACK) {
				/*
				 * send bu, restart retrans and
				 * failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITD;
			} else {
				/* send bu, stop timers. */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			}
			break;

		case MIP6_BU_FSM_EVENT_RETRANS:
			/* send HoTI, start retrans timer. */

			/* XXX */

			break;

		case MIP6_BU_FSM_EVENT_BE_1_RECEIVED:
		case MIP6_BU_FSM_EVENT_BE_2_RECEIVED:
			/* stop timers. */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			break;

		case MIP6_BU_FSM_EVENT_RO_DESIRED:
			/*
			 * send HoTI, CoTI, restart retrans and
			 * failure timers.
			 */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			break;
		}
		break;

	case MIP6_BU_FSM_STATE_BOUND:
		switch (event) {
		case MIP6_BU_FSM_EVENT_BRR_RECEIVED:
			/* send HoTI, CoTI, start retrans timers. */

			/* XXX */

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			break;

		case MIP6_BU_FSM_EVENT_RO_NOT_DESIRED:
			if ((mbu->mbu_flags & IP6MU_ACK)
			    && 1 /* home cookie not too old */) {
				/*
				 * send bu, start retrans and failure
				 * timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITD;
			} if (((mbu->mbu_flags & IP6MU_ACK) == 0)
			    && 1 /* home cookie not too old */) {
				/* send bu. */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;
			} else {
				/*
				 * send HoTI, start retrans and
				 * failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITDH;
			}
			break;

		case MIP6_BU_FSM_EVENT_MOVEMENT:
			if (1 /* home cookie not too old */) {
				/*
				 * send CoTI, start retrans and
				 * failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITC;
			} else {
				/*
				 * send HoTI, CoTI, start retrans nad
				 * failure timers.
				 */

				/* XXX */

				*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			}
			break;

		case MIP6_BU_FSM_EVENT_BE_1_RECEIVED:
			/*
			 * XXX if there is any reason to believe
			 * forward progress is begin made, do nothing.
			 */

			/* XXX reset state? */
			*mbu_fsm_state = MIP6_BU_FSM_STATE_IDLE;

			/*
			 * send HoTI, CoTI, start retrans and failure
			 * timers.
			 */

			/* XXX error handling */
			mip6_bu_send_hoti(mbu);
			mip6_bu_send_coti(mbu);

			*mbu_fsm_state = MIP6_BU_FSM_STATE_WAITHC;
			break;
		}
		break;
	}

#ifdef MIP6_DEBUG
	mip6log((LOG_INFO, "st=%d:ev=%d\n", *mbu_fsm_state, event));
#endif

	return(0);
}
