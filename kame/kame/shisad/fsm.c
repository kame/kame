/*	$KAME: fsm.c,v 1.8 2005/01/26 07:41:59 t-momose Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/syslog.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <net/if_dl.h>
#include <net/mipsock.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#define _KERNEL
#include <netinet/ip6mh.h>
#undef _KERNEL

#include "callout.h"
#include "shisad.h"
#include "stat.h"
#include "fsm.h"

int initial_bindack_timeout_first_reg = 2; /* the spec says more than 1.5 */

static int bul_reg_fsm(struct binding_update_list *, int,
    struct fsm_message *);
static int bul_rr_fsm(struct binding_update_list *, int, struct fsm_message *);

static int bul_fsm_save_hot_info(struct binding_update_list *,
    struct ip6_mh_home_test *);
static int bul_fsm_save_cot_info(struct binding_update_list *,
    struct ip6_mh_careof_test *);
static int bul_fsm_back_preprocess(struct binding_update_list *,
    struct fsm_message *);
static int bul_fsm_back_register(struct binding_update_list *,
    struct fsm_message *);
static int bul_fsm_back_deregister(struct binding_update_list *,
    struct fsm_message *);

/* for debuging. */
static void dump_ba(struct in6_addr *, struct in6_addr *, struct in6_addr *,
    u_int16_t, u_int16_t, u_int8_t);
static void bul_print_all(void);

static int bul_send_unsolicited_na(struct binding_update_list *);

static void bul_set_retrans_timer(struct binding_update_list *, int);
static void bul_stop_retrans_timer(struct binding_update_list *);
static void bul_set_expire_timer(struct binding_update_list *, int);
static void bul_stop_expire_timer(struct binding_update_list *);
static void bul_stop_timers(struct binding_update_list *);

/*
 * return value:
 *  -1 error
 *   0 success
 *   1 success and mbul was removed
 */
int
bul_kick_fsm_by_mh(src, dst, hoa, rtaddr, mh, mhlen)
	struct in6_addr *src, *dst, *hoa, *rtaddr;
	struct ip6_mh *mh;
	int mhlen;
{
	struct ip6_mh_careof_test *ip6mhct = NULL;
	struct ip6_mh_binding_error *ip6mhbe = NULL;
	struct mip6_hoainfo *hinfo = NULL;
	struct binding_update_list *bul = NULL;
	struct fsm_message fsmmsg;
	int error = 0;
#ifdef MIP_MCOA 
	u_int16_t bid = 0;
#endif /* MIP_MCOA */

	bzero(&fsmmsg, sizeof(struct fsm_message));
	fsmmsg.fsmm_src = src;
	fsmmsg.fsmm_dst = dst;
	fsmmsg.fsmm_hoa = hoa;
	fsmmsg.fsmm_rtaddr = rtaddr;
	fsmmsg.fsmm_data = mh;
	fsmmsg.fsmm_datalen = mhlen;

	switch(mh->ip6mh_type) {
	case IP6_MH_TYPE_BRR:
		hinfo = hoainfo_find_withhoa(dst);
		if (hinfo == NULL) {
			syslog(LOG_NOTICE,
			    "no related HoA found with this BRR.\n");
			return (-1);
		}
#ifndef MIP_MCOA
		bul = bul_get(dst, src);
#else
		/* bid must be stored in BRR request. retrieve that... XXX */ 
		bid = get_bid_option(mh, sizeof(struct ip6_mh_binding_request),
				     fsmmsg.fsmm_datalen);
		bul = bul_mcoa_get(dst, src, bid); 
#endif /* MIP_MCOA */
		if (bul == NULL) {
			syslog(LOG_NOTICE,
			    "no related binding update entry with "
			    "this BRR.\n");
			return (-1);
		}
		error = bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_BRR, &fsmmsg);
		if (error == -1) {
			syslog(LOG_NOTICE,
			    "BRR fsm state transition failed.\n");
			return (-1);
		}
		break;

	case IP6_MH_TYPE_HOT:
		if (hoa || rtaddr)
			break;
		hinfo = hoainfo_find_withhoa(dst);  
		if (hinfo == NULL) {
			syslog(LOG_NOTICE,
			    "no related HoA found with this HoT.\n");
			return (-1);
		}
#ifndef MIP_MCOA
		bul = bul_get(dst, src);
#else
		bid = get_bid_option(mh, sizeof(struct ip6_mh_home_test), 
				     fsmmsg.fsmm_datalen);
		bul = bul_mcoa_get(dst, src, bid);
#endif /* MIP_MCOA */
		if (bul == NULL) {
			syslog(LOG_NOTICE,
			    "no related binding update entry with "
			    "this HoT.\n");
			return (-1);
		}
		error = bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_HOT, &fsmmsg);
		if (error == -1) {
			syslog(LOG_NOTICE,
			    "HOT fsm state transition failed.\n");
			return (-1);
		}
		break;

	case IP6_MH_TYPE_COT:
		if (hoa || rtaddr)
			break;
		ip6mhct = (struct ip6_mh_careof_test *)mh;
		bul = bul_get_nohoa((char *)ip6mhct->ip6mhct_cookie, dst, src);
		if (bul == NULL) {
			syslog(LOG_NOTICE,
			    "no related binding update entry found with "
			    "this CoT.\n");
			return (-1);
		}
		error = bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_COT, &fsmmsg);
		if (error == -1) {
			syslog(LOG_ERR, "COT state transition failed.\n");
			return (-1);
		}
		break;

	case IP6_MH_TYPE_BACK:
		hinfo = hoainfo_find_withhoa(dst);  
		if (hinfo == NULL) {
			syslog(LOG_NOTICE,
			    "no related HoA found with this BACK.\n"); 
			return (-1);
		}
#ifndef MIP_MCOA
		bul = bul_get(dst, src);
#else
		bid = get_bid_option(mh, sizeof(struct ip6_mh_binding_ack), 
				     fsmmsg.fsmm_datalen);
		syslog(LOG_INFO, "received bid is %d\n", bid);
		bul = bul_mcoa_get(dst, src, bid);

#endif /* MIP_MCOA */
		if (bul == NULL) {
			syslog(LOG_NOTICE,
			    "no matching binding update entry found with "
			    "this BACK.\n");
			return (-1);
		}
		if (!IN6_ARE_ADDR_EQUAL(&bul->bul_coa, &hinfo->hinfo_hoa)
		    && rtaddr == NULL) {
			syslog(LOG_ERR,
			    "RTHDR2 must be exist when a mobile node is "
			    "foreign.\n");
			return (-1);
		}
		error = bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_BACK, &fsmmsg);
		if (error == -1) {
			syslog(LOG_ERR, "BACK state transition failed.\n");
			return (-1);
		}
		break;

	case IP6_MH_TYPE_BERROR:
		ip6mhbe = (struct ip6_mh_binding_error *)mh;

		if (IN6_IS_ADDR_UNSPECIFIED(&ip6mhbe->ip6mhbe_homeaddr))
			hinfo = hoainfo_find_withhoa(dst);
		else {
			hinfo = hoainfo_find_withhoa(&ip6mhbe->ip6mhbe_homeaddr);
		}
		if (hinfo == NULL) {
			syslog(LOG_NOTICE,
			    "no related HoA found with this BE.\n");
			return (-1);
		}

#ifndef MIP_MCOA 
		bul = bul_get(&hinfo->hinfo_hoa, src);
#else
		bid = get_bid_option(mh, sizeof(struct ip6_mh_binding_error), 
				     fsmmsg.fsmm_datalen);

		/* bid must be stored in BRR request. retrieve that... XXX */ 
		bul = bul_mcoa_get(&hinfo->hinfo_hoa, src, bid); /* XXX */
#endif /* MIP_MCOA */
		if (bul == NULL) {
			syslog(LOG_NOTICE,
			    "no related binding update entry found with "
			    "this BE.\n");
			return (-1);
		}

		mip6stat.mip6s_be_hist[ip6mhbe->ip6mhbe_status]++;
		switch (ip6mhbe->ip6mhbe_status) {
		case IP6_MH_BES_UNKNOWN_HAO:
			/*
			 * the CN doesn't have a binding cache entry.
			 * start RR.
			 */
			error =  bul_kick_fsm(bul,
			    MIP6_BUL_FSM_EVENT_UNKNOWN_HAO, &fsmmsg);
			break;

		case IP6_MH_BES_UNKNOWN_MH:
			/* XXX future extension? */
			error = bul_kick_fsm(bul,
			    MIP6_BUL_FSM_EVENT_UNKNOWN_MH, &fsmmsg);
			break;

		default:
			syslog(LOG_INFO,
			    "unknown BE status code (status = %u).\n",
			    ip6mhbe->ip6mhbe_status);
		}
		if (error == -1) {
			syslog(LOG_ERR, "BE state transition failed.\n");
			return (-1);
		}
		break;

	case IP6_MH_TYPE_HOTI:
	case IP6_MH_TYPE_COTI:
	case IP6_MH_TYPE_BU:
		/* MN just ignores */
		break;

	default:
		syslog(LOG_ERR,
		    "Unknown Mobility Header Message is received\n");

		/* 
		 * SECTION 9.2 if MH type has unknown value, issue BE
		 * with status set to 2.  
		 */
		if (IN6_IS_ADDR_LINKLOCAL(src)
		    || IN6_IS_ADDR_MULTICAST(src)
		    || IN6_IS_ADDR_LOOPBACK(src)
		    || IN6_IS_ADDR_V4MAPPED(src)
		    || IN6_IS_ADDR_UNSPECIFIED(src))
			break;

		send_be(src, dst, hoa, IP6_MH_BES_UNKNOWN_MH);
		break;
	}

	return (error);
}

/*
 * return value:
 *  -1 error
 *   0 success
 *   1 success and mbul was be removed
 */
int
bul_kick_fsm(bul, event, data)
	struct binding_update_list *bul;
	int event;
	struct fsm_message *data;
{
	if (bul == NULL)
		return (-1);

	if (debug) {
		syslog(LOG_INFO, "event = %d", event);
		bul_print_all();
	}

	if (event == MIP6_BUL_FSM_EVENT_RETRANS_TIMER) {
		if (MIP6_BUL_IS_RR_FSM_RUNNING(bul))
			return(bul_rr_fsm(bul, event, data));
		else
			return(bul_reg_fsm(bul, event, data));
	}
	if (MIP6_BUL_IS_REG_FSM_EVENT(event))
		return (bul_reg_fsm(bul, event, data));
	if (MIP6_BUL_IS_RR_FSM_EVENT(event))
		return (bul_rr_fsm(bul, event, data));

	/* unknown event is specified. */
	return (-1);
}

#define REGFSMS (bul->bul_reg_fsm_state)
static int
bul_reg_fsm(bul, event, data)
	struct binding_update_list *bul;
	int event;
	struct fsm_message *data;
{
	int error;
	struct home_agent_list *hal = NULL;
	struct binding_update_list *cnbul;

	error = 0;
	
	switch (bul->bul_reg_fsm_state) {
	case MIP6_BUL_REG_FSM_STATE_IDLE:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_IDLE */
			bul->bul_lifetime
			    = set_default_bu_lifetime(bul->bul_hoainfo);
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				if (IN6_IS_ADDR_UNSPECIFIED(&bul->bul_peeraddr)){
					/* 
					 * pick an address of one of
					 * our home agent from the
					 * home agent list.
					 */
					hal = mip6_find_hal(bul->bul_hoainfo);
					if (hal) {
						bul->bul_peeraddr = hal->hal_ip6addr;
						goto idle_send_bu;
					}
					
					/*
					 * keep idle state if we
					 * haven't been assigned a
					 * valid CoA
					 */
					if (IN6_IS_ADDR_UNSPECIFIED(&bul->bul_coa)) {
						return (0);
					}

					/* send a DHAAD request message. */
					if (send_haadreq(bul->bul_hoainfo, 64 /* XXX */, &bul->bul_coa) > 0)
						/* how handle this */;
					
					/* set retrans timer */
					bul->bul_retrans_time
					    = INITIAL_BINDACK_TIMEOUT;
					bul_set_retrans_timer(bul,
					    bul->bul_retrans_time);

					bul_set_expire_timer(bul,
					    bul->bul_lifetime << 2);

					REGFSMS = MIP6_BUL_REG_FSM_STATE_DHAAD;
					return (0);
				}

			idle_send_bu:
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed. (%d)\n", error);
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = initial_bindack_timeout_first_reg;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			} else {
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "secondary fsm transition "
					    "failed (%d).\n", error);
					return (error);
				}

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BUL_FSM_EVENT_REVERSE_PACKET:
			/* in MIP6_BUL_REG_FSM_STATE_IDLE */
			bul->bul_lifetime
			    = set_default_bu_lifetime(bul->bul_hoainfo); /* XXX should i set the maximun RR lifetime? */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
#if 0
				if ((bul->bul_state
				     & MIP6_BUL_STATE_NEEDTUNNEL) != 0) {
					/*
					 * if the peer doesn't support
					 * MIP6, keep IDLE state.
					 */
					break;
				}
#endif
				bul_stop_retrans_timer(bul);
				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "secondary fsm transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB:
			/* in MIP6_BUL_REG_FSM_STATE_IDLE */
			bul_stop_retrans_timer(bul);

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BUL_REG_FSM_STATE_IDLE */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				bul_remove(bul);
				bul = NULL;
			}
			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_RRINIT:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_RR_DONE:
			/* in MIP6_BUL_REG_FSM_STATE_RRINIT */
			if ((bul->bul_flags & IP6_MH_BU_ACK) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a binding update "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			} else {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a binding upate "
					    "failed. (%d)\n", error);
					return (error);
				}

				/*
				 * bul_fsm_back_register() will update
				 * the kernel bul, too.
				 */
				if (bul_fsm_back_register(bul, data)) {
					syslog(LOG_ERR,
					    "registering a binding update "
					    "entry failed.\n");
					return (-1);
				}

				bul_set_retrans_timer(bul,
				    bul->bul_refresh << 2);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_BOUND;
			}
			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BU_REG_FSM_STATE_RRINIT */
			bul_stop_timers(bul);

			bul_remove(bul);
			bul = NULL;

			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_MH:
			/* in MIP6_BUL_REG_FSM_STATE_RRINIT */
			bul_stop_retrans_timer(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;
			
		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_RRINIT */
			bul_stop_retrans_timer(bul);
			
			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);

			if (error == 0) {
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
			}
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;

			break;

		case MIP6_BUL_FSM_EVENT_RETURNING_HOME:
			/* in MIP6_BUL_REG_FSM_STATE_RRINIT */
			bul_stop_timers(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			/* free mbu */
			bul_remove(bul);
			bul = NULL;

			break;

		case MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB:
			/* in MIP6_BUL_REG_FSM_STATE_RRINIT */
			bul_stop_retrans_timer(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_RRREDO:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_RR_DONE:
			/* in MIP6_BUL_REG_FSM_STATE_RRREDO */
			if ((bul->bul_flags & IP6_MH_BU_ACK) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a binding upate "
					    "failed.\n");
					return (error);
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITAR;
			} else {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a binding upate "
					    "failed.\n");
					return (error);
				}

				/*
				 * bul_fsm_back_register() updates the
				 * kernel bul, too.
				 */
				if (bul_fsm_back_register(bul, data)) {
					syslog(LOG_ERR,
					    "registering a binding update "
					    "entry failed.\n");
					return (-1);
				}

				bul_set_retrans_timer(bul,
				    bul->bul_refresh << 2);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_BOUND;
			}
			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_MH:
			/* in MIP6_BUL_REG_FSM_STATE_RRREDO */
			bul_stop_retrans_timer(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;
			
		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_RRREDO */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);

			if (error == 0) {
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
			}
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;

			break;

		case MIP6_BUL_FSM_EVENT_RETURNING_HOME:
			/* in MIP6_BUL_REG_FSM_STATE_RRREDO */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);

			if (error == 0) {
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_HOME_RR, data);
			}
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			REGFSMS = MIP6_BUL_REG_FSM_STATE_RRDEL;

			break;

		case MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB:
			/* in MIP6_BUL_REG_FSM_STATE_RRREDO */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			bul_stop_retrans_timer(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_WAITA:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_BACK:
			/* in MIP6_BUL_REG_FSM_STATE_WAITA */
			error = bul_fsm_back_preprocess(bul, data);
			if (error) {
				syslog(LOG_ERR,
				    "processing a binding ack failed.\n");
				/*
				 * a binding update will be
				 * retransmitted.
				 */
				return (error);
			}
			/*
			 * bul_fsm_back_register() updates the kernel
			 * bul, too.
			 */
			if (bul_fsm_back_register(bul, data)) {
				syslog(LOG_ERR,
				    "registering a binding update entry "
				    "failed.\n");
				return (-1);
			}

			bul_set_retrans_timer(bul, bul->bul_refresh << 2);

			bul_set_expire_timer(bul, bul->bul_lifetime << 2);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_BOUND;

			/* process binding update lists for CN. */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				for (cnbul = LIST_FIRST(&bul->bul_hoainfo->hinfo_bul_head);
				     cnbul;
				     cnbul = LIST_NEXT(cnbul, bul_entry)) {
					if ((cnbul->bul_flags & IP6_MH_BU_HOME) != 0)
						continue;
					if (cnbul->bul_hoainfo != bul->bul_hoainfo)
						continue;
					bul_kick_fsm(cnbul,
					    MIP6_BUL_FSM_EVENT_REGISTERED,
					    NULL);
				}
			}

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_REG_FSM_STATE_WAITA */
			error = send_bu(bul);
			if (error) {
				syslog(LOG_ERR,
				    "sending a binding update failed.\n");
				/* continue and try again. */
			}

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_BINDACK_TIMEOUT) {
				/* XXX should find another home agent. */
				bul->bul_retrans_time = MAX_BINDACK_TIMEOUT;
			}
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;

			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BU_REG_FSM_STATE_WAITA */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {

				/* XXX remove the current HA entry. */
				/* mip6_remove_hal(bul->bul_peeraddr) */

				/* 
				 * pick an address of one of
				 * our home agent from the
				 * home agent list.
				 */
				hal = mip6_find_hal(bul->bul_hoainfo);
				if (hal) {
					bul->bul_peeraddr = hal->hal_ip6addr;
					goto waita_send_bu;
				}
					
				/* send a DHAAD request message. */
				if (send_haadreq(bul->bul_hoainfo, 64 /* XXX */, &bul->bul_coa) > 0)
					/* how handle this */;

				/* set retrans timer */
				bul->bul_retrans_time = INITIAL_DHAAD_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				/* set expire timer */
				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_DHAAD;
				return (0);

			waita_send_bu:
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed. (%d)\n", error);
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			} else {
				bul_stop_timers(bul);
				bul_remove(bul);
				bul = NULL;
			}
			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_MH:
			/* in MIP6_BUL_REG_FSM_STATE_WAITA */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				break;
			}

			bul_stop_retrans_timer(bul);

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;

		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_WAITA */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			} else {
				/* XXX no need? */
				bul_stop_timers(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BUL_FSM_EVENT_RETURNING_HOME:
			/* in MIP6_BUL_REG_FSM_STATE_WAITA */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITD;
			} else {
				/* XXX no need? */
				bul_stop_timers(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_HOME_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRDEL;
			}
			break;

		case MIP6_BUL_FSM_EVENT_REVERSE_PACKET:
			/* in MIP6_BUL_REG_FSM_STATE_WAITA */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				bul_stop_retrans_timer(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "secondary fsm transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}

			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_WAITAR:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_BACK:
			/* in MIP6_BUL_REG_FSM_STATE_WAITAR */
			error = bul_fsm_back_preprocess(bul, data);
			if (error) {
				syslog(LOG_ERR,
				    "processing a binding ack failed.\n");
				/*
				 * a binding update will be
				 * retransmitted.
				 */
				return (error);
			}
			/*
			 * bul_fsm_back_register() updates the kernel
			 * bul too.
			 */
			if (bul_fsm_back_register(bul, data)) {
				syslog(LOG_ERR,
				    "registering a binding update entry "
				    "failed.\n");
				return (-1);
			}

			bul_set_retrans_timer(bul,
			    bul->bul_refresh << 2);

			bul_set_expire_timer(bul,
			    bul->bul_lifetime << 2);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_BOUND;

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_REG_FSM_STATE_WAITAR */
			error = send_bu(bul);
			if (error) {
				syslog(LOG_ERR,
				    "sending a binding upate failed.\n");
				/*
				 * a binding update will be
				 * retransmitted.
				 */
				return (error);
			}

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_BINDACK_TIMEOUT) {
				/* XXX should find another home agent. */
				bul->bul_retrans_time = MAX_BINDACK_TIMEOUT;
			}
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITAR;

			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BU_REG_FSM_STATE_WAITAR */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {

				/* XXX remove the current HA entry. */
				/* mip6_remove_hal(bul->bul_peeraddr) */

				/* 
				 * pick an address of one of
				 * our home agent from the
				 * home agent list.
				 */
				hal = mip6_find_hal(bul->bul_hoainfo);
				if (hal) {
					bul->bul_peeraddr = hal->hal_ip6addr;
					goto waitar_send_bu;
				}
					
				/* send a DHAAD request message. */
				if (send_haadreq(bul->bul_hoainfo, 64 /* XXX */, &bul->bul_coa) > 0)
					/* how handle this */;

				/* set retrans timer */
				bul->bul_retrans_time
				    = INITIAL_DHAAD_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				/* set expire timer */
				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_DHAAD;
				return (0);

			waitar_send_bu:
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed. (%d)\n", error);
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			} else {
				bul_stop_timers(bul);
				bul_remove(bul);
				bul = NULL;
			}
			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_MH:
			/* in MIP6_BUL_REG_FSM_STATE_WAITAR */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				/* XXX correct ? */
				break;
			}

			bul_stop_retrans_timer(bul);

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			break;

		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_WAITAR */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			} else {
				/* XXX no need? */
				bul_stop_retrans_timer(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BUL_FSM_EVENT_RETURNING_HOME:
			/* in MIP6_BUL_REG_FSM_STATE_WAITAR */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
					return (error);
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITD;
			}
			break;

		case MIP6_BUL_FSM_EVENT_REVERSE_PACKET:
			/* in MIP6_BUL_REG_FSM_STATE_WAITAR */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				bul_stop_retrans_timer(bul);
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "secondary fsm transition "
					    "failed.\n");	
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRREDO;
			}
			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_WAITD:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_BACK:
			/* in MIP6_BUL_REG_FSM_STATE_WAITD */
			if (bul_fsm_back_preprocess(bul, data)) {
				syslog(LOG_ERR,
				    "processing a binding ack failed.\n");
				return (-1);
			}
#ifdef MIP_MCOA
			if (bul->bul_hoainfo && 
				IN6_ARE_ADDR_EQUAL(&bul->bul_hoainfo->hinfo_hoa, &bul->bul_coa)) { 
#endif /* MIP_MCOA */
			if (bul_fsm_back_deregister(bul, data)) {
				syslog(LOG_ERR,
				    "returning home failed.\n");
				return (-1);
			}
#ifdef MIP_MCOA
			}
#endif /* MIP_MCOA */
			bul_stop_timers(bul);

			/*
			 * remove a binding information registered in
			 * a kernel.
			 */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			/* keep a home registration entry for reuse. */
			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			/* process binding update lists for CN. */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				for (cnbul = LIST_FIRST(&bul->bul_hoainfo->hinfo_bul_head);
				     cnbul;
				     cnbul = LIST_NEXT(cnbul, bul_entry)) {
					if ((cnbul->bul_flags & IP6_MH_BU_HOME) != 0)
						continue;
					if (cnbul->bul_hoainfo != bul->bul_hoainfo)
						continue;
					bul_kick_fsm(cnbul,
					    MIP6_BUL_FSM_EVENT_DEREGISTERED,
					    NULL);
				}
			} else {
				bul_remove(bul);
				bul = NULL;
			}

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_REG_FSM_STATE_WAITD */
			error = send_bu(bul);
			if (error) {
				syslog(LOG_ERR,
				    "sending a binding upate failed.\n");
				return (error);
			}

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_BINDACK_TIMEOUT) {
				/* XXX how should we do?  remove bul? */
				bul->bul_retrans_time = MAX_BINDACK_TIMEOUT;
			}
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITD;

			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BU_REG_FSM_STATE_WAITD */
			bul_stop_timers(bul);

			/*
			 * remove a binding information registered in
			 * a kernel.
			 */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			/* keep a home registration entry for reuse. */
			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				bul_remove(bul);
				bul = NULL;
			}

			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_MH:
			/* in MIP6_BUL_REG_FSM_STATE_WAITD */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				break;
			}

			bul_stop_retrans_timer(bul);

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;

		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_WAITD */
			bul->bul_lifetime
			    = set_default_bu_lifetime(bul->bul_hoainfo);
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				bul_stop_timers(bul);

				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				bul_set_expire_timer(bul,
				    bul->bul_lifetime << 2);
				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			}
			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_RRDEL:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_RR_DONE:
			/* in MIP6_BUL_REG_FSM_STATE_RRDEL */
			if ((bul->bul_flags & IP6_MH_BU_ACK) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a binding update "
					    "failed.\n");
					/* continue */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITD;
			} else {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a binding upate "
					    "failed.\n");
					return (error);
				}

				if (bul_fsm_back_deregister(bul, data)) {
					syslog(LOG_ERR,
					    "deregistering a binding update "
					    "entry failed.\n");
					return (-1);
				}

				bul_stop_timers(bul);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

				/* free mbu */
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}
				bul_remove(bul);
				bul = NULL;
			}
			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_MH:
			/* in MIP6_BUL_REG_FSM_STATE_RRDEL */
			bul_stop_timers(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			/* free mbu */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}
			bul_remove(bul);
			bul = NULL;

			break;
			
		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_RRDEL */
			bul_stop_retrans_timer(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error == 0) {
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
			}
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;

			break;

		case MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB:
			/* in MIP6_BUL_REG_FSM_STATE_RRDEL */
			bul_stop_retrans_timer(bul);

			error = bul_rr_fsm(bul,
			    MIP6_BUL_FSM_EVENT_STOP_RR, data);
			if (error) {
				syslog(LOG_ERR,
				    "second fsm state transition failed.\n");
				return (error);
			}

			bul->bul_state |= MIP6_BUL_STATE_DISABLE;

			/* update binding update information in a kernel. */
			if (mipsock_bul_request(bul, MIPM_BUL_ADD)) {
				syslog(LOG_ERR,
				    "updating a binding update entry "
				    "in a kernel failed.\n");
				return (-1);
			}

			/* Add this host in No RO list */
			noro_add(&bul->bul_peeraddr);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;

			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BU_REG_FSM_STATE_RRDEL */
			bul_stop_timers(bul);

			/*
			 * remove a binding information registered in
			 * a kernel.
			 */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}

			/* remove a binding update entry for CN. */
			bul_remove(bul);
			bul = NULL;

			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_BOUND:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_BRR:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITAR;
			} else {
				bul_stop_retrans_timer(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRREDO;
			}
			break;

		case MIP6_BUL_FSM_EVENT_MOVEMENT:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
			}
			break;

		case MIP6_BUL_FSM_EVENT_REGISTERED:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}

				bul_stop_retrans_timer(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}
			break;

		case MIP6_BUL_FSM_EVENT_RETURNING_HOME:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}

				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITD;
			}
			break;

		case MIP6_BUL_FSM_EVENT_DEREGISTERED:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_HOME_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRDEL;
			}
			break;

		case MIP6_BUL_FSM_EVENT_REVERSE_PACKET:
#if 0
/* don't restart RR procedure if we already have a binding update entry. */
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				/*
				 * Stop timers,
				 * Start RR.
				 */
				bul_stop_timers(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "secondary fsm transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRREDO;
			}
#endif

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				error = send_bu(bul);
				if (error) {
					syslog(LOG_ERR,
					    "sending a home registration "
					    "failed.\n");
					/* continue and try again. */
				}

				bul->bul_retrans_time
				    = INITIAL_BINDACK_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITAR;
			} else {
				bul_stop_retrans_timer(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRREDO;
			}
			break;

		case MIP6_BUL_FSM_EVENT_EXPIRE_TIMER:
			/* in MIP6_BU_REG_FSM_STATE_BOUND */
			/*
			 * Stop timers,
			 * if (home)
			 *   Send DHAAD request,
			 *   Reset retrans counter,
			 *   Start retrans timer.
			 * else
			 *   Remove entry.
			 */
			bul_stop_timers(bul);

			/*
			 * remove a binding information registered in
			 * a kernel.
			 */
			if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
				syslog(LOG_ERR,
				    "removing bul entry from kernel "
				    "failed.\n");
			}
			if ((bul->bul_flags & IP6_MH_BU_HOME) != 0) {
				/* get another HA addr. */

				/* if found,
				 *   send bu,
				 *   reset retrans count,
				 *   start retrans timer,
				 *   start expire timer.
				 * break;
				 */

				/* XXX send DHAAD request. */

				bul->bul_retrans_time = INITIAL_DHAAD_TIMEOUT;
				bul_set_retrans_timer(bul,
				    bul->bul_retrans_time);

				REGFSMS = MIP6_BUL_REG_FSM_STATE_DHAAD;
			} else {
				/* remove a binding update entry for CN. */
				bul_remove(bul);
				bul = NULL;
			}

			break;

		case MIP6_BUL_FSM_EVENT_UNKNOWN_HAO:
			/* in MIP6_BUL_REG_FSM_STATE_BOUND */
			if ((bul->bul_flags & IP6_MH_BU_HOME) == 0) {
				if (mipsock_bul_request(bul, MIPM_BUL_REMOVE)) {
					syslog(LOG_ERR,
					    "removing bul entry from kernel "
					    "failed.\n");
				}

				bul_stop_retrans_timer(bul);

				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_STOP_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}
				error = bul_rr_fsm(bul,
				    MIP6_BUL_FSM_EVENT_START_RR, data);
				if (error) {
					syslog(LOG_ERR,
					    "second fsm state transition "
					    "failed.\n");
					return (error);
				}

				REGFSMS = MIP6_BUL_REG_FSM_STATE_RRINIT;
			}
			break;
		}
		break;

	case MIP6_BUL_REG_FSM_STATE_DHAAD:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_RETURNING_HOME:
			/* in MIP6_BUL_REG_FSM_STATE_DHAAD */
			/*
			 * Stop retransmission timer,
			 * Stop expire timer.
			 */
			bul_stop_timers(bul);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_IDLE;
			break;

		case MIP6_BUL_FSM_EVENT_DHAAD_REPLY:
			/* in MIP6_BUL_REG_FSM_STATE_DHAAD */
			/*
			 * Set home agent address,
			 * Send BU,
			 * Reset retransmission count,
			 * Start retransmission timer,
			 * Start expire timer.
			 */
			hal = mip6_find_hal(bul->bul_hoainfo);
			if (hal == NULL)
				break;

			memcpy(&bul->bul_peeraddr, &hal->hal_ip6addr, sizeof(struct in6_addr));
			syslog(LOG_INFO, "%s peer addd--------> add\n", ip6_sprintf(&bul->bul_peeraddr));
			error = send_bu(bul);
			if (error) {
				syslog(LOG_ERR,
				    "sending a home registration "
				    "failed. (%d)\n", error);
				/* continue and try again. */
			}

			bul->bul_retrans_time
			    = initial_bindack_timeout_first_reg;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			bul_set_expire_timer(bul, bul->bul_lifetime << 2);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_WAITA;
#ifdef MIP_MCOA 
			if (!LIST_EMPTY(&bul->bul_mcoa_head)) {
				struct binding_update_list *mbul;
				
				for (mbul = LIST_FIRST(&bul->bul_mcoa_head); mbul;
				     mbul = LIST_NEXT(bul, bul_entry)) {
		
					syslog(LOG_INFO, "found multiple BULISTS\n");
					memcpy(&mbul->bul_peeraddr, 
					       &hal->hal_ip6addr, sizeof(struct in6_addr));
					error = send_bu(mbul);
					if (error) {
						syslog(LOG_ERR,
						       "sending a home registration "
						       "failed. (%d)\n", error);
						/* continue and try again. */
					}
					
					mbul->bul_retrans_time
					    = INITIAL_BINDACK_TIMEOUT;
					bul_set_retrans_timer(mbul,
					    mbul->bul_retrans_time);
					
					bul_set_expire_timer(mbul,
					    mbul->bul_lifetime << 2);
					mbul->bul_reg_fsm_state
					    = MIP6_BUL_REG_FSM_STATE_WAITA;
				}
			}
#endif /* MIP_MCOA */

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_REG_FSM_STATE_DHAAD */
			/*
			 * Send DHAAD request,
			 * Start retrans timer with backoff.
			 */
			/* XXX send DHAAD */
			if (send_haadreq(bul->bul_hoainfo, 64 /* XXX */, &bul->bul_coa) > 0)
				/* how handle this */;

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_DHAAD_TIMEOUT) {
				/*
				 * we keep sending DHAAD request. this
				 * breaks the specification, however
				 * we believe it is better keep sending than
				 * stop Mobile IPv6 service.
				 */
				bul->bul_retrans_time = MAX_DHAAD_TIMEOUT;
			}
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			REGFSMS = MIP6_BUL_REG_FSM_STATE_DHAAD;

			break;
		}
		break;

	default:
		syslog(LOG_ERR, "the state of the primary fsm is unknown.");
	}

	return (bul == NULL ? 1 : 0);
	
}
#undef REGFSMS

#define RRFSMS (bul->bul_rr_fsm_state)
int
bul_rr_fsm(bul, event, fsmmsg)
	struct binding_update_list *bul;
	int event;
	struct fsm_message *fsmmsg;
{
	int error;

	/* sanity check. */
	if (bul == NULL)
		return (-1);

	error = 0;

	switch (bul->bul_rr_fsm_state) {
	case MIP6_BUL_RR_FSM_STATE_START:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_START_RR:
			/* in MIP6_BUL_RR_FSM_STATE_START */
			/*
			 * Send HoTI,
			 * Send CoTI,
			 * Start retransmission timer,
			 */
			if (send_hoti(bul) != 0)
				break;
			if (send_coti(bul) != 0)
				break;

			bul->bul_retrans_time = INITIAL_HOTI_COTI_TIMEOUT;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITHC;

			break;
		
		case MIP6_BUL_FSM_EVENT_START_HOME_RR:
			/*
			 * Send HoTI,
			 * Start retransmission timer,
			 */
			if (send_hoti(bul) != 0)
				break;

			bul->bul_retrans_time = INITIAL_HOTI_COTI_TIMEOUT;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITH;

			break;
		}
		break;

	case MIP6_BUL_RR_FSM_STATE_WAITHC:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_HOT:
			/* in MIP6_BUL_RR_FSM_STATE_WAITHC */
			/*
			 * Store keygen token, nonce index.
			 */
			if (bul_fsm_save_hot_info(bul,
			    (struct ip6_mh_home_test *)(fsmmsg->fsmm_data))) {
				syslog(LOG_ERR, "bul_rr_fsm: "
				    "saving hot failed.\n");
				/* keep current state. */
				break;
			}

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITC;

			break;

		case MIP6_BUL_FSM_EVENT_COT:
			/* in MIP6_BUL_RR_FSM_STATE_WAITHC */
			/*
			 * Store token, nonce index.
			 */
			if (bul_fsm_save_cot_info(bul,
			    (struct ip6_mh_careof_test *)(fsmmsg->fsmm_data))) {
				syslog(LOG_ERR, "bul_rr_fsm: "
				    "saving cot failed.\n");
				/* keep current state. */
				break;
			}

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITH;

			break;

		case MIP6_BUL_FSM_EVENT_STOP_RR:
			/* in MIP6_BUL_RR_FSM_STATE_WAITHC */
			/*
			 * Stop retrans timer.
			 */
			bul_stop_retrans_timer(bul);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_START;

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_RR_FSM_STATE_WAITHC */
			/*
			 * Send HoTI,
			 * Send CoTI,
			 * Start retransmission timer with backoff.
			 */
			if (send_hoti(bul) != 0)
				break;
			if (send_coti(bul) != 0)
				break;

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_HOTI_COTI_TIMEOUT)
				bul->bul_retrans_time = MAX_HOTI_COTI_TIMEOUT;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITHC;

			break;
		}
		break;

	case MIP6_BUL_RR_FSM_STATE_WAITH:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_HOT:
			/* in MIP6_BUL_RR_FSM_STATE_WAITH */
			/*
			 * Store token and nonce index,
			 * Stop retrans timer,
			 * RR done.
			 */
			if (bul_fsm_save_hot_info(bul,
			    (struct ip6_mh_home_test *)(fsmmsg->fsmm_data))) {
				syslog(LOG_ERR, "bul_rr_fsm: "
				    "saving hot failed.\n");
				/* keep current state. */
				break;
			}
			bul_stop_retrans_timer(bul);

			error = bul_reg_fsm(bul, MIP6_BUL_FSM_EVENT_RR_DONE,
			    fsmmsg);
			if (error) {
				syslog(LOG_ERR,
				    "primary fsm state transition failed.\n");
				return (error);
			}

			RRFSMS = MIP6_BUL_RR_FSM_STATE_START;

			break;

		case MIP6_BUL_FSM_EVENT_STOP_RR:
			/* in MIP6_BUL_RR_FSM_STATE_WAITH */
			/*
			 * Stop retransmission timer.
			 */
			bul_stop_retrans_timer(bul);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_START;

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/*
			 * Send HoTI,
			 * Start retransmission timer with backoff.
			 */
			if (send_hoti(bul) != 0)
				break;

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_HOTI_COTI_TIMEOUT)
				bul->bul_retrans_time = MAX_HOTI_COTI_TIMEOUT;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITH;

			break;
		}
		break;

	case MIP6_BUL_RR_FSM_STATE_WAITC:
		switch (event) {
		case MIP6_BUL_FSM_EVENT_COT:
			/* in MIP6_BUL_RR_FSM_STATE_WAITC */
			/*
			 * Store token and nonce index,
			 * Stop retransmission timer,
			 * RR done.
			 */
			if (bul_fsm_save_cot_info(bul,
			    (struct ip6_mh_careof_test *)(fsmmsg->fsmm_data))) {
				syslog(LOG_ERR, "bul_rr_fsm: "
				    "saving cot failed.\n");
				/* keep current state. */
				break;
			}
			bul_stop_retrans_timer(bul);

			error = bul_reg_fsm(bul, MIP6_BUL_FSM_EVENT_RR_DONE,
			    fsmmsg);
			if (error) {
				syslog(LOG_ERR,
				    "primary fsm state transition failed.\n");
				return (error);
			}

			RRFSMS = MIP6_BUL_RR_FSM_STATE_START;

			break;

		case MIP6_BUL_FSM_EVENT_STOP_RR:
			/* in MIP6_BUL_RR_FSM_STATE_WAITC */
			/*
			 * Stop retrans timer.
			 */
			bul_stop_retrans_timer(bul);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_START;

			break;

		case MIP6_BUL_FSM_EVENT_RETRANS_TIMER:
			/* in MIP6_BUL_RR_FSM_STATE_WAITC */
			/*
			 * Send CoTI,
			 * Start retransmission timer with backoff.
			 */
			if (send_coti(bul) != 0)
				break;

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_HOTI_COTI_TIMEOUT)
				bul->bul_retrans_time = MAX_HOTI_COTI_TIMEOUT;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			RRFSMS = MIP6_BUL_RR_FSM_STATE_WAITC;

			break;
		}
		break;

	default:
		syslog(LOG_ERR, "the state of the secondary fsm is unknown.");
	}
	return (0);
}
#undef RRFSMS

static int
bul_fsm_save_hot_info(bul, ip6mhht)
	struct binding_update_list *bul;
	struct ip6_mh_home_test *ip6mhht;
{
	if (bul == NULL || ip6mhht == NULL)
		return (-1);

	if (memcmp((void *)ip6mhht->ip6mhht_cookie,
	    (void *)bul->bul_home_cookie, sizeof(mip6_cookie_t)) != 0) {
		syslog(LOG_INFO, "bul_fsm_save_hot_info: "
		    "the cookie doesn't match.\n");
		return (-1);
	}
	bul->bul_home_nonce_index = htons(ip6mhht->ip6mhht_nonce_index);
	memcpy(bul->bul_home_token, ip6mhht->ip6mhht_keygen8,
	    sizeof(ip6mhht->ip6mhht_keygen8));

	return (0);
}

static int
bul_fsm_save_cot_info(bul, ip6mhct)
	struct binding_update_list *bul;
	struct ip6_mh_careof_test *ip6mhct;
{
	if (bul == NULL || ip6mhct == NULL)
		return (-1);

	if (memcmp((void *)ip6mhct->ip6mhct_cookie,
	    (void *)bul->bul_careof_cookie, sizeof(mip6_cookie_t)) != 0) {
		syslog(LOG_INFO, "bul_fsm_save_cot_info: "
		    "the cookie doesn't match.\n");
		return (-1);
	}
	bul->bul_careof_nonce_index = htons(ip6mhct->ip6mhct_nonce_index);
	memcpy(bul->bul_careof_token, ip6mhct->ip6mhct_keygen8,
	    sizeof(ip6mhct->ip6mhct_keygen8));

	return (0);
}

static int
bul_fsm_back_preprocess(bul, fsmmsg)
	struct binding_update_list *bul;
	struct fsm_message *fsmmsg;
{
	mip6_kbm_t kbm;
	u_int16_t cksum;
	mip6_authenticator_t authenticator;
	struct ip6_mh_binding_ack *ip6mhba;
	u_int16_t seqno;
	int ip6mhbalen;
	u_int16_t lifetime, refresh;
	time_t curtime;
	struct mip6_mobility_options mopt;

	ip6mhba = (struct ip6_mh_binding_ack *)(fsmmsg->fsmm_data);
	ip6mhbalen = fsmmsg->fsmm_datalen;

	mip6stat.mip6s_ba_hist[ip6mhba->ip6mhba_status]++;

	curtime = time(NULL);

	/* check Sequence Number */
	seqno = ntohs(ip6mhba->ip6mhba_seqno);
	if (0)
	dump_ba(fsmmsg->fsmm_src, fsmmsg->fsmm_dst, fsmmsg->fsmm_rtaddr, 
	    seqno, ntohs(ip6mhba->ip6mhba_lifetime), ip6mhba->ip6mhba_status);
	if (ip6mhba->ip6mhba_status == IP6_MH_BAS_SEQNO_BAD) {
                /*
                 * our home agent has a greater sequence number in its
                 * binging cache entriy of mine.  we should resent
                 * binding update with greater than the sequence
                 * number of the binding cache already exists in our
                 * home agent.  this binding ack is valid though the
                 * sequence number doesn't match.
                 */
		/* XXX should be in fsm? */
		syslog(LOG_ERR,
		    "sequence number is too small.\n");
		bul->bul_seqno = seqno + 1;
		if (send_bu(bul)) {
			syslog(LOG_ERR,
			    "sending a binding update failed.\n");
		}
		bul->bul_retrans_time = INITIAL_BINDACK_TIMEOUT;
		bul_set_retrans_timer(bul, bul->bul_retrans_time);
		/* keep current state. */
		
		return (-1); /* XXX */
	} else if (seqno != bul->bul_seqno) {
                syslog(LOG_NOTICE,
		    "unmached sequence no (%d recv, %d sent) from.\n",
		    seqno, bul->bul_seqno);
                /* silently ignore. */
		mip6stat.mip6s_seqno++;
                return (-1);
	}

	/* retrieve Mobility Options */
	if (get_mobility_options((struct ip6_mh *)ip6mhba, 
		 sizeof(*ip6mhba), ip6mhbalen, &mopt)) {
		mip6stat.mip6s_invalidopt++;
		syslog(LOG_ERR, "bad mobility option in BACK.\n");
		return (-1);
	}

	/* 
	 * Authenticator check if available. BA is protected by IPsec
	 * when it is from Home Agent (i.e. Home Flag set to
	 * BUL. Otherwise, all packets SHOULD have authenticator and
	 * nonce indice option. */
	if (mopt.opt_auth) {
		/* verify authenticator. */
		/*
		 * RFC3775 Section 6.2.7
		 */
		mip6_calculate_kbm(&bul->bul_home_token,
		    (fsmmsg->fsmm_rtaddr != NULL)
		    ? &bul->bul_careof_token : NULL, &kbm);
		/*
		 * clear the checksum field to calculate a correcet
		 * authenticator.
		 */
		cksum = ip6mhba->ip6mhba_hdr.ip6mh_cksum;
		ip6mhba->ip6mhba_hdr.ip6mh_cksum = 0;
		mip6_calculate_authenticator(&kbm,
		    (fsmmsg->fsmm_rtaddr != NULL)
		    ? fsmmsg->fsmm_rtaddr : fsmmsg->fsmm_dst,
		    fsmmsg->fsmm_src, (caddr_t)ip6mhba, ip6mhbalen,
		    ((caddr_t)mopt.opt_auth - (caddr_t)ip6mhba) + 2,
		    MIP6_AUTHENTICATOR_SIZE, &authenticator);
		ip6mhba->ip6mhba_hdr.ip6mh_cksum = cksum;
		if (memcmp((caddr_t)mopt.opt_auth + 2, &authenticator,
			MIP6_AUTHENTICATOR_SIZE) != 0) {
			syslog(LOG_ERR,
			    "BACK authenticator mismatch.\n");
			return (-1);
		}
	} else if (!(bul->bul_flags & IP6_MH_BU_HOME)) /* Not Home Registration */
		return (-1);

	/* update lifetime and refresh time. */
	lifetime = ntohs(ip6mhba->ip6mhba_lifetime);
/*	bul->bul_expire = curtime + (lifetime << 2); */
	if (bul->bul_flags & IP6_MH_BU_HOME) {
		if (mopt.opt_refresh != NULL) {
			refresh = ntohs(*(u_int16_t *)((struct ip6_mh_opt_refresh_advice *)(mopt.opt_refresh)->ip6mora_interval));
			if (refresh > lifetime || refresh == 0) {
				/*
				 * use default refresh interval for an
				 * invalid binding refresh interval
				 * option.
				 */
  				refresh = lifetime / 2;  /* XXX */
			}
		} else {
			/*
			 * set refresh interval even when a home agent
			 * doesn't specify refresh interval, so that a
			 * mobile node can re-register its binding
			 * before the binding update entry expires.
			 */
			/*
			 * XXX: the calculation algorithm of a default
			 * value must be discussed.
			 */
			refresh = lifetime / 2; /* XXX */
		}
	} else
		refresh = lifetime;
	bul->bul_refresh = refresh;

#ifdef MIP_NEMO
	/* 
	 * When HA returns BA without R flag, MR must trigger DHAAD to
	 * find right NEMO HAs. If such BA indicates successful
	 * registration, MR MUST de-register the binding from legacy
	 * HA.
	 */
	if (bul->bul_flags & (IP6_MH_BU_HOME | IP6_MH_BU_ROUTER)) {
		if (ip6mhba->ip6mhba_flags != IP6_MH_BA_ROUTER) {
			/* sending DHAAD again XXX */
			if (send_haadreq(bul->bul_hoainfo, 64 /* XXX */, &bul->bul_coa) > 0)
				/* how handle this */;

			bul->bul_retrans_time <<= 1;
			if (bul->bul_retrans_time > MAX_DHAAD_TIMEOUT)
				bul->bul_retrans_time = MAX_DHAAD_TIMEOUT;
			bul_set_retrans_timer(bul, bul->bul_retrans_time);

			bul->bul_reg_fsm_state = MIP6_BUL_REG_FSM_STATE_DHAAD;

			/* need deregistration XXX */
			return (-1);
		}
	}
#endif /* MIP_NEMO */

	if (ip6mhba->ip6mhba_status == IP6_MH_BAS_PRFX_DISCOV) {
#if TODO
		if (mip6_icmp6_mp_sol_output(&bul->bul_haddr,
			&bul->bul_paddr)) {
			syslog(LOG_ERR,
			    "sending a mobile prefix solicitation message "
			    "failed\n");
			/* proceed anyway... */
		}
#endif
	}

	return (0);
}

static void
dump_ba (src, dst, rtaddr, seq, lifetime, status) 
	struct in6_addr *src, *dst, *rtaddr;
	u_int16_t seq, lifetime;
	u_int8_t status;
{
        /* Dump Binding Acknowledge */
        syslog(LOG_INFO, "\tBA Src   %s\n", ip6_sprintf(src));
        syslog(LOG_INFO, "\tBA Dst   %s\n", ip6_sprintf(dst));
        syslog(LOG_INFO, "\tBA Rtopt %s\n", rtaddr ? ip6_sprintf(rtaddr) : "(null)");


        syslog(LOG_INFO, "\tBA Sequence No. %d\n", seq);
        syslog(LOG_INFO, "\tBA Lifetime     %d\n", lifetime);
		syslog(LOG_INFO, "\tBA Status: ");
        switch (status) {
        case IP6_MH_BAS_ACCEPTED:
                syslog(LOG_INFO, "\tBinding Update accepted\n");
                break;
        case IP6_MH_BAS_PRFX_DISCOV:
                syslog(LOG_INFO, "\tAccepted but prefix discovery necessary\n");
                break;
        case IP6_MH_BAS_UNSPECIFIED:
                syslog(LOG_INFO, "\tReason unspecified");
                break;
        case IP6_MH_BAS_PROHIBIT:
                syslog(LOG_INFO, "\tAdministratively prohibited\n");
                break;
        case IP6_MH_BAS_INSUFFICIENT:
                syslog(LOG_INFO, "\tInsufficient resources\n");
                break;
        case IP6_MH_BAS_HA_NOT_SUPPORTED:
                syslog(LOG_INFO, "\tHome registration not supported\n");
                break;
        case IP6_MH_BAS_NOT_HOME_SUBNET:
                syslog(LOG_INFO, "\tNot home subnet\n"); 
                break;
        case IP6_MH_BAS_NOT_HA:
                syslog(LOG_INFO, "\tNot home agent for this mobile node\n");
                break;
        case IP6_MH_BAS_DAD_FAILED:
                syslog(LOG_INFO, "\tDuplicate Address Detection failed\n");
                break;
        case IP6_MH_BAS_SEQNO_BAD:
                syslog(LOG_INFO, "\tSequence number out of window\n");
                break;
        case IP6_MH_BAS_HOME_NI_EXPIRED:
                syslog(LOG_INFO, "\tExpired home nonce index\n");
                break;
        case IP6_MH_BAS_COA_NI_EXPIRED:
                syslog(LOG_INFO, "\tExpired care-of nonce index\n");
                break;
        case IP6_MH_BAS_NI_EXPIRED:
                syslog(LOG_INFO, "\tExpired nonces\n");
                break;
        case IP6_MH_BAS_REG_NOT_ALLOWED:
                syslog(LOG_INFO, "\tRegistration type change disallowed\n");
                break;
        default:
                syslog(LOG_INFO, "\tUnknown\n");
                break;
        }
}

static int
bul_fsm_back_register(bul, data)
	struct binding_update_list *bul;
	struct fsm_message *data;
{
	
	if (bul->bul_lifetime == 0) {
		syslog(LOG_WARNING,
		    "lifetime is zero.\n");
		/* XXX ignored */
#ifdef TODO
		/* removed BUL from the kernel ?! */
#endif
	}

	/* inject binding information to kernel. */
	if (mipsock_bul_request(bul, MIPM_BUL_ADD)) {
		syslog(LOG_ERR, "updating a binding update entry in a kernel "
		    "failed.\n");
		return (-1);
	}

#if TODO
	/* notify all the CNs that we have a new coa. */
	error = mip6_bu_list_notify_binding_change(sc, 0);
	if (error) {
		syslog(LOG_ERR,
		    "updating the bining cache entries of all CNs failed.\n");
		return (error);
	}
#endif
	return (0);
}

static int
bul_fsm_back_deregister(bul, data)
	struct binding_update_list *bul;
	struct fsm_message *data;
{
	char homeifname[IFNAMSIZ];

	if (if_indextoname(bul->bul_home_ifindex, homeifname)) {
	}
	/* clear IFF_DEREGISTERING flag. */
	if (set_ip6addr(homeifname, &bul->bul_hoainfo->hinfo_hoa, 64,
		IN6_IFF_NODAD|IN6_IFF_HOME)) {
		syslog(LOG_ERR,
		    "removing IFF_DEREGISTERING flag failed.\n");
	}

	if (bul->bul_flags & IP6_MH_BU_HOME) {
		/* send an unsolicited neighbor advertisement message. */
		bul_send_unsolicited_na(bul);
	}

	return (0);
#if TODO
	struct sockaddr_in6 coa_sa;
	struct sockaddr_in6 daddr; /* XXX */
	struct sockaddr_in6 lladdr;
	struct ifaddr *ifa;

	if (bul->bul_flags & IP6_MH_BU_HOME) {
		/* 
		 * home unregsitration has completed.  send an
		 * unsolicited neighbor advertisement.
		 */
		bzero(&coa_sa, sizeof(coa_sa));
		coa_sa.sin6_len = sizeof(coa_sa);
		coa_sa.sin6_family = AF_INET6;
		coa_sa.sin6_addr = mbu->mbu_coa;
		/* XXX scope? how? */
		if ((ifa = ifa_ifwithaddr((struct sockaddr *)&coa_sa)) == NULL) {
			mip6log((LOG_ERR,
				    "%s:%d: can't find CoA interface\n",
				    __FILE__, __LINE__));
			m_freem(m);
			return (EINVAL);	/* XXX */
		}

		bzero(&daddr, sizeof(daddr));
		daddr.sin6_family = AF_INET6;
		daddr.sin6_len = sizeof(daddr);
		daddr.sin6_addr = in6addr_linklocal_allnodes;
		if (in6_addr2zoneid(ifa->ifa_ifp, &daddr.sin6_addr,
			&daddr.sin6_scope_id)) {
			/* XXX: should not happen */
			mip6log((LOG_ERR,
				    "%s:%d: in6_addr2zoneid failed\n",
				    __FILE__, __LINE__));
			m_freem(m);
			return (EIO);
		}
		if ((error = in6_embedscope(&daddr.sin6_addr, &daddr))) {
			/* XXX: should not happen */
			mip6log((LOG_ERR,
				    "%s:%d: in6_embedscope failed\n",
				    __FILE__, __LINE__));
			m_freem(m);
			return (error);
		}

		nd6_na_output(ifa->ifa_ifp, &daddr.sin6_addr,
		    &mbu->mbu_haddr, ND_NA_FLAG_OVERRIDE, 1, NULL);
		mip6log((LOG_INFO,
			    "%s:%d: send a unsolicited na for %s\n",
			    __FILE__, __LINE__,
			    ip6_sprintf(&mbu->mbu_haddr)));
	}

	/*
	 * if the binding update entry has the L flag on,
	 * send unsolicited neighbor advertisement to my
	 * link-local address.
	 */
	if (bul->bul_flags & IP6_MH_BU_LLOCAL) {
		bzero(&lladdr, sizeof(lladdr));
		lladdr.sin6_len = sizeof(lladdr);
		lladdr.sin6_family = AF_INET6;
		lladdr.sin6_addr.s6_addr16[0]
		    = IPV6_ADDR_INT16_ULL;
		lladdr.sin6_addr.s6_addr32[2]
		    = mbu->mbu_haddr.s6_addr32[2];
		lladdr.sin6_addr.s6_addr32[3]
		    = mbu->mbu_haddr.s6_addr32[3];
				
		if (in6_addr2zoneid(ifa->ifa_ifp,
			&lladdr.sin6_addr,
			&lladdr.sin6_scope_id)) {
			/* XXX: should not happen */
			mip6log((LOG_ERR,
				    "%s:%d: in6_addr2zoneid failed\n",
				    __FILE__, __LINE__));
			m_freem(m);
			return (EIO);
		}
		if ((error = in6_embedscope(&lladdr.sin6_addr,
			 &lladdr))) {
			/* XXX: should not happen */
			mip6log((LOG_ERR,
				    "%s:%d: in6_embedscope failed\n",
				    __FILE__, __LINE__));
			m_freem(m);
			return (error);
		}

		nd6_na_output(ifa->ifa_ifp, &daddr.sin6_addr,
		    &lladdr.sin6_addr, ND_NA_FLAG_OVERRIDE, 1,
		    NULL);

		mip6log((LOG_INFO,
			    "%s:%d: send a unsolicited na for %s\n",
			    __FILE__, __LINE__,
			    ip6_sprintf(&lladdr.sin6_addr)));
	}

	if (bul->bul_flags & IP6_MH_BU_HOME) {
		/* notify all the CNs that we are home. */
		error = mip6_bu_list_notify_binding_change(sc, 1);
		if (error) {
			mip6log((LOG_ERR,
				    "%s:%d: removing the bining cache entries of all CNs failed.\n",
				    __FILE__, __LINE__));
			m_freem(m);
			return (error);
		}
	}

	/* XXX call mipsock to remove internal entry. */


	/* XXX ? */
	error = mip6_bu_list_remove_all(&sc->hif_bu_list, 0);
	if (error) {
		mip6log((LOG_ERR,
			    "%s:%d: BU remove all failed.\n",
			    __FILE__, __LINE__));
		m_freem(m);
		return (error);
	}
	mbu = NULL; /* free in mip6_bu_list_remove_all() */
#endif
}

static int
bul_send_unsolicited_na(bul)
	struct binding_update_list *bul;
{
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_in6 to;
	struct mip6_hoainfo *hinfo;
	char adata[512]; /* for ip6_pktopts and hlim */
	char nabuf[1024]; /* for neighbor advertisement message */
	struct cmsghdr *cmsgptr;
	struct in6_pktinfo *pi;
	struct nd_neighbor_advert *na;
	size_t nalen;
	struct nd_opt_hdr *ndopt;
	struct ifaddrs *ifahead, *ifa;

	if (bul == NULL)
		return (-1);

	hinfo = bul->bul_hoainfo;

	bzero(&to, sizeof(to));
	to.sin6_len = sizeof(to);
	to.sin6_family = AF_INET6;
	to.sin6_addr = in6addr_linklocal_allnodes;
	to.sin6_scope_id = bul->bul_home_ifindex;

	msg.msg_name = (void *)&to;
	msg.msg_namelen = sizeof(to);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo))
	    + CMSG_SPACE(sizeof(int));

	/*
	 * set the source address of an unsolicited neighbor
	 * advertisement message to my link-local address.
	 */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	bzero(pi, sizeof(*pi));
	pi->ipi6_ifindex = bul->bul_home_ifindex;
	pi->ipi6_addr = hinfo->hinfo_hoa;
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(*pi));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	/* HopLimit Information (always 255) */
        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_HOPLIMIT;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)(CMSG_DATA(cmsgptr)) = 255;
        cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	bzero(nabuf, sizeof(nabuf));
	na = (struct nd_neighbor_advert *)nabuf;
	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	na->nd_na_cksum = 0;
	na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
	na->nd_na_target = hinfo->hinfo_hoa;
	nalen = sizeof(struct nd_neighbor_advert);

	/* target link-layer option. */
	if (getifaddrs(&ifahead) != 0) {
		syslog(LOG_ERR,
		    "retrieving my link-layer address failed.\n");
		return (-1);
	}
#define ROUNDUP8(a) (1 + (((a) - 1) | 7))
	for (ifa = ifahead; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_dl *sdl;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)(ifa->ifa_addr);
		if (sdl->sdl_index != bul->bul_home_ifindex)
			continue;
		ndopt = (struct nd_opt_hdr *) (nabuf + nalen);
		ndopt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		ndopt->nd_opt_len = (ROUNDUP8(sdl->sdl_alen + 2)) >> 3;
		memcpy((void *)(ndopt + 1), LLADDR(sdl), sdl->sdl_alen);
		nalen += ROUNDUP8(sdl->sdl_alen + 2);
		break;
	}
#undef ROUNDUP8
	freeifaddrs(ifahead);
	
	iov.iov_base = nabuf;
	iov.iov_len = nalen;
	
	if (sendmsg(icmp6sock, &msg, 0) == -1) {
		syslog(LOG_ERR,
		    "sending an unsolicited neighbor advertisement message "
		    "failed.\n");
		return (-1);
	}

	if (bul->bul_flags & IP6_MH_BU_LLOCAL) {
		/* send an unsolicited na to my link-layer address. */
	}

	return (0);
}

static void
bul_set_retrans_timer(bul, tick)
	struct binding_update_list *bul;
	int tick;
{
	remove_callout_entry(bul->bul_retrans);
	bul->bul_retrans = new_callout_entry(tick, bul_retrans_timer,
	    (void *)bul, "bul_retrans_timer");
}

static void
bul_stop_retrans_timer(bul)
	struct binding_update_list *bul;
{
	remove_callout_entry(bul->bul_retrans);
}

void
bul_retrans_timer(arg)
	void *arg;
{
	int error;
	struct binding_update_list *bul = (struct binding_update_list *)arg;

	error = bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_RETRANS_TIMER, NULL);
	if (error == 1)
		syslog(LOG_INFO, "a binding update entry is removed.\n");
}

static void
bul_set_expire_timer(bul, tick)
	struct binding_update_list *bul;
	int tick;
{
	remove_callout_entry(bul->bul_expire);
	bul->bul_expire = new_callout_entry(tick, bul_expire_timer,
	    (void *)bul, "bul_expire_timer");
}

static void
bul_stop_expire_timer(bul)
	struct binding_update_list *bul;
{
	remove_callout_entry(bul->bul_expire);
}

void
bul_expire_timer(arg)
	void *arg;
{
	int error = 0;
	struct binding_update_list *bul = (struct binding_update_list *)arg;

	bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_EXPIRE_TIMER, NULL);
	if (error == 1)
		syslog(LOG_INFO, "a binding update entry is removed.\n");
}

static void
bul_stop_timers(bul)
	struct binding_update_list *bul;
{
	/* sanity check. */
	if (bul == NULL)
		return;

	bul_stop_retrans_timer(bul);
	bul_stop_expire_timer(bul);
}

#define timesub(a,b) ((a)->tv_sec - (b)->tv_sec)
static void
bul_print_all(void)
{
	struct mip6_hoainfo *hoainfo;
	struct binding_update_list *bul;
	struct timeval now;

	gettimeofday(&now, NULL);

	syslog(LOG_INFO, "Binding update list\n");
	for (hoainfo = LIST_FIRST(&hoa_head); hoainfo;
	     hoainfo = LIST_NEXT(hoainfo, hinfo_entry)) {
		for (bul = LIST_FIRST(&hoainfo->hinfo_bul_head); bul;
		     bul = LIST_NEXT(bul, bul_entry)) {
			syslog(LOG_INFO,
#ifndef MIP_MCOA
			    "\tp=%s,c=%s,lt=%d,rf=%d,seq=%d,fl=0x%x,reg=%d,rr=%d,rt=%ld,et=%ld\n",
#else
			    "\tp=%s,c=%s,lt=%d,rf=%d,seq=%d,fl=0x%x,reg=%d,rr=%d,rt=%ld,et=%ld bid=%d\n",
#endif /* MIP_MCOA */
			       ip6_sprintf(&bul->bul_peeraddr),
			       ip6_sprintf(&bul->bul_coa),
			       bul->bul_lifetime,
			       bul->bul_refresh,
			       bul->bul_seqno,
			       bul->bul_flags,
			       bul->bul_reg_fsm_state,
			       bul->bul_rr_fsm_state,
			       (bul->bul_retrans) ? timesub(&bul->bul_retrans->exptime, &now) : -1,
			       (bul->bul_expire) ? timesub(&bul->bul_expire->exptime, &now) : -1
#ifndef MIP_MCOA
			       );
#else
			       ,bul->bul_bid);
#endif /* MIP_MCOA */
#ifdef MIP_MCOA 
			if (!LIST_EMPTY(&bul->bul_mcoa_head)) {
				struct binding_update_list *mbul;
				
				for (mbul = LIST_FIRST(&bul->bul_mcoa_head); mbul;
				     mbul = LIST_NEXT(mbul, bul_entry)) {
					syslog(LOG_INFO,
					       "\t\tp=%s,c=%s,lt=%d,rf=%d,seq=%d,fl=0x%x,reg=%d,rr=%d,rt=%ld,et=%ld bid=%d\n",
					       ip6_sprintf(&mbul->bul_peeraddr),
					       ip6_sprintf(&mbul->bul_coa),
					       mbul->bul_lifetime,
					       mbul->bul_refresh,
					       mbul->bul_seqno,
					       mbul->bul_flags,
					       mbul->bul_reg_fsm_state,
					       mbul->bul_rr_fsm_state,
					       (mbul->bul_retrans) ? timesub(&mbul->bul_retrans->exptime, &now) : -1,
					       (mbul->bul_expire) ? timesub(&mbul->bul_expire->exptime, &now) : -1,
					       mbul->bul_bid);
					
				}
			}
#endif /* MIP_MCOA */

		}
	}
}
