/*	$KAME: mld6_proto.c,v 1.38 2004/06/09 14:54:23 suz Exp $	*/

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
/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
/*
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/ip6_mroute.h>
#include <netinet/icmp6.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "defs.h"
#include "mld6.h"
#include "vif.h"
#include "mld6_proto.h"
#include "mld6v2.h"
#include "mld6v2_proto.h"
#include "debug.h"
#include "inet6.h"
#include "mrt.h"
#include "route.h"
#include "callout.h"
#include "timer.h"

#include "mld6_proto.h"

/*
 * Forward declarations.
 */
static int DeleteTimer __P((int id));
static void SendQuery __P((void *arg));
static int SetQueryTimer
__P((struct listaddr * g, int mifi, int to_expire,
     int q_time));

/*
 * Send group membership queries on that interface if I am querier.
 */
void
query_groups(v)
	register struct uvif *v;
{
	v->uv_gq_timer = MLD6_QUERY_INTERVAL;
	if (v->uv_flags & VIFF_QUERIER &&
	    (v->uv_flags & VIFF_NOLISTENER) == 0) {
		if (v->uv_stquery_cnt)
			v->uv_stquery_cnt--;
		if (v->uv_stquery_cnt)
			v->uv_gq_timer = MLD6_STARTUP_QUERY_INTERVAL;
		else
			v->uv_gq_timer = MLD6_QUERY_INTERVAL;
		send_mld6(MLD_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
			  NULL, (struct in6_addr *)&in6addr_any, v->uv_ifindex,
			  MLD6_QUERY_RESPONSE_INTERVAL, 0, 1);
		v->uv_out_mld_query++;
	}
}

/*
 * Process an incoming host membership query
 */
void
accept_listener_query(src, dst, group, tmo)
	struct sockaddr_in6 *src;
	struct in6_addr *dst, *group;
	int tmo;
{
	register int mifi;
	register struct uvif *v;
	struct sockaddr_in6 group_sa = {sizeof(group_sa), AF_INET6};

	/* Ignore my own listener query */
	if (local_address(src) != NO_VIF)
		return;

	if ((mifi = find_vif_direct(src)) == NO_VIF) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0,
			    "accept_listener_query: can't find a mif");
		return;
	}
	v = &uvifs[mifi];
	if ((v->uv_mld_version & MLDv1) == 0) {
		log_msg(LOG_WARNING,0,
		    "Mif %s configured in MLDv2 received MLDv1 query (src %s)!",
		    v->uv_name,sa6_fmt(src));
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_DEBUG, 0,
		    "accepting multicast listener query on %s: "
		    "src %s, dst %s, grp %s",
		    v->uv_name,
		    sa6_fmt(src), inet6_fmt(dst), inet6_fmt(group));
	v->uv_in_mld_query++;

	if (!inet6_equal(&v->uv_querier->al_addr, src)) {
		/*
		 * This might be:
		 * - A query from a new querier, with a lower source address
		 *   than the current querier (who might be me).
		 * - A query from a new router that just started up and
		 *   doesn't know who the querier is.
		 */
		if (inet6_lessthan(src,
				   (v->uv_querier ? &v->uv_querier->al_addr
				    : &v->uv_linklocal->pa_addr))) {
			IF_DEBUG(DEBUG_MLD)
				log_msg(LOG_DEBUG, 0, "new querier %s (was %s) "
				    "on mif %d",
				    sa6_fmt(src),
				    v->uv_querier ?
				    sa6_fmt(&v->uv_querier->al_addr) :
				    "me", mifi);

			v->uv_flags &= ~VIFF_QUERIER;
			v->uv_querier->al_addr = *src;
			time(&v->uv_querier->al_ctime);
		}
	}

	/*
	 * Ignore the query if we're (still) the querier.
	 */
	if ((v->uv_flags & VIFF_QUERIER) != 0)
		return;

	/*
	 * Reset the timer since we've received a query.
	 */
	if (v->uv_querier && inet6_equal(src, &v->uv_querier->al_addr))
		v->uv_querier->al_timer = MLD6_OTHER_QUERIER_PRESENT_INTERVAL;

	/*
	 * If this is a Group-Specific query, we must set our membership timer
	 * to [Last Member Query Count] * the [Max Response Time] in the
	 * packet.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(group)) {
		register struct listaddr *g;

		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "%s for %s from %s on mif %d, timer %d",
			    "Group-specific membership query",
			    inet6_fmt(group), sa6_fmt(src), mifi, tmo);

		group_sa.sin6_addr = *group;
		group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);
		for (g = v->uv_groups; g != NULL; g = g->al_next) {
			if (inet6_equal(&group_sa, &g->al_addr) &&
			    g->al_query == 0) {
				/*
				 * setup a timeout to remove the group
				 * membership.
				 */
				if (g->al_timerid)
					g->al_timerid =
						DeleteTimer(g->al_timerid);
				g->al_timer = MLD6_LAST_LISTENER_QUERY_COUNT *
					tmo / MLD6_TIMER_SCALE;
				/*
				 * use al_query to record our presence in
				 * last-member state.
				 */
				g->al_query = -1;
				g->al_timerid = SetTimer(mifi, g);
				IF_DEBUG(DEBUG_MLD)
					log_msg(LOG_DEBUG, 0,
					    "timer for grp %s on mif %d "
					    "set to %ld",
					    inet6_fmt(group),
					    mifi, g->al_timer);
				break;
			}
		}
	}
}

/*
 * Process an incoming group membership report.
 */
void
accept_listener_report(src, dst, group)
	struct sockaddr_in6 *src;
	struct in6_addr *dst, *group;
{
	mifi_t mifi;
	struct uvif *v = NULL;
	struct sockaddr_in6 group_sa;

	if (IN6_IS_ADDR_MC_LINKLOCAL(group)) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "accept_listener_report: group(%s) has the "
			    "link-local scope. discard", inet6_fmt(group));
		return;
	}

	if ((mifi = find_vif_direct_local(src)) == NO_VIF) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0,
			    "accept_listener_report: can't find a mif");
		return;
	}

	v = &uvifs[mifi];
	bzero(&group_sa, sizeof(group_sa));
	group_sa.sin6_family = AF_INET6;
	group_sa.sin6_len = sizeof(group_sa);
	group_sa.sin6_addr = *group;
	group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

	if ((v->uv_mld_version & MLDv1) == 0) {
		log_msg(LOG_DEBUG, 0,
		    "ignores MLDv1 report for %s on non-MLDv1 Mif %s",
		    inet6_fmt(group), v->uv_name);
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_DEBUG, 0,
		    "accepting multicast listener report: "
		    "src %s,dst %s, grp %s",
		    sa6_fmt(src),inet6_fmt(dst), inet6_fmt(group));

	v->uv_in_mld_report++;

#ifdef MLDV2_LISTENER_REPORT
	if (v->uv_mld_version & MLDv2) {
		log_msg(LOG_DEBUG, 0,
		    "shift to MLDv1 compat-mode for %s on Mif %s",
		    inet6_fmt(group), v->uv_name);
		mld_shift_to_v1mode(mifi, src, &group_sa);
		return;
	}
#endif
	recv_listener_report(mifi, src, &group_sa, MLDv1);
}

/* shared with MLDv1-compat mode in mld6v2_proto.c */
void
recv_listener_report(mifi, src, grp, mld_version)
	mifi_t mifi;
	struct sockaddr_in6 *src, *grp;
	int mld_version;
{
	struct uvif *v = &uvifs[mifi];
	register struct listaddr *g;

	/*
	 * Look for the group in our group list; if found, just reset its timer
	 */
	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (!inet6_equal(grp, &g->al_addr))
			continue;

		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG,0, "The group already exists");

		g->al_reporter = *src;

		/* delete old timers, set a timer for expiration */

		g->al_timer = MLD6_LISTENER_INTERVAL;
		if (g->al_query)
			g->al_query = DeleteTimer(g->al_query);
		if (g->al_timerid)
			g->al_timerid = DeleteTimer(g->al_timerid);
		g->al_timerid = SetTimer(mifi, g);
		add_leaf(mifi, NULL, grp);
		return;
	}

	if (g != NULL)
		/* impossible! */
		return;

	/* add it to the list and update kernel cache. */
	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_DEBUG,0,
		    "The group doesn't exist , trying to add it");

	g = (struct listaddr *) malloc(sizeof(struct listaddr));
	if (g == NULL)
		log_msg(LOG_ERR, 0, "ran out of memory");	/* fatal */

	g->al_addr = *grp;
	g->sources = NULL;

	/** set a timer for expiration **/
	g->al_query = 0;
	g->al_timer = MLD6_LISTENER_INTERVAL;
	g->al_reporter = *src;
	g->al_timerid = SetTimer(mifi, g);
	g->al_next = v->uv_groups;
	g->comp_mode = mld_version;
	if (g->comp_mode == MLDv2)
		g->filter_mode = MODE_IS_EXCLUDE;
	v->uv_groups = g;
	time(&g->al_ctime);

	add_leaf(mifi, NULL, grp);
}

/* TODO: send PIM prune message if the last member? */
void
accept_listener_done(src, dst, group)
	struct sockaddr_in6 *src;
	struct in6_addr *dst, *group;
{
	mifi_t mifi;
	struct uvif *v = NULL;
	struct sockaddr_in6 group_sa;

	/* Don't create routing entries for the LAN scoped addresses */
	/* sanity? */
	if (IN6_IS_ADDR_MC_NODELOCAL(group)) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "accept_listener_done: address multicast node "
			    " local(%s), ignore it...", inet6_fmt(group));
		return;
	}

	if (IN6_IS_ADDR_MC_LINKLOCAL(group)) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "accept_listener_done: address multicast "
			    "link local(%s), ignore it ...", inet6_fmt(group));
		return;
	}

	if ((mifi = find_vif_direct_local(src)) == NO_VIF) {
		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_INFO, 0,
			    "accept_listener_done: can't find a mif");
		return;
	}

	v = &uvifs[mifi];
	bzero(&group_sa, sizeof(group_sa));
	group_sa.sin6_family = AF_INET6;
	group_sa.sin6_len = sizeof(group_sa);
	group_sa.sin6_addr = *group;
	group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

	/*
	 * MLD done does not affeect mld-compatibility;
	 * draft-vida-mld-v2-05.txt section 7.3.2 says:
	 *  The Multicast Address Compatibility Mode variable is based 
	 *  on whether an older version report was heard in the last 
	 *  Older Version Host Present Timeout seconds.
	 */
	if ((v->uv_mld_version & MLDv1) == 0) {
		log_msg(LOG_DEBUG, 0,
		    "ignores MLDv1 done for %s on non-MLDv1 Mif %s",
		    inet6_fmt(group), v->uv_name);
		return;
	}

	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_INFO, 0,
		    "accepting listener done message: src %s, dst %s, grp %s",
		    sa6_fmt(src), inet6_fmt(dst), inet6_fmt(group));
	v->uv_in_mld_done++;

	recv_listener_done(mifi, src, &group_sa);
}


/* shared with MLDv1-compat mode in mld6v2_proto.c */
void
recv_listener_done(mifi, src, grp)
	mifi_t mifi;
	struct sockaddr_in6 *src, *grp;
{
	struct uvif *v = &uvifs[mifi];
	register struct listaddr *g;

	/*
	 * XXX: in MLDv1-compat mode, non-querier is allowed to ignore MLDv2
	 * report?
	 */
	if (!(v->uv_flags & (VIFF_QUERIER | VIFF_DR)))
		return;

	/*
	 * Look for the group in our group list in order to set up a
	 * short-timeout query.
	 */
	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (!inet6_equal(grp, &g->al_addr))
			continue;

		IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0, "[accept_done_message] %ld\n",
			    g->al_query);

		/* still waiting for a reply to a query, ignore the done */
		if (g->al_query)
			return;

		/* delete old timer set a timer for expiration */
		if (g->al_timerid)
			g->al_timerid = DeleteTimer(g->al_timerid);

		/* send a group specific query */
		g->al_timer = (MLD6_LAST_LISTENER_QUERY_INTERVAL /
			       MLD6_TIMER_SCALE) * 
			       (MLD6_LAST_LISTENER_QUERY_COUNT + 1);

		if ((v->uv_flags & VIFF_QUERIER) == 0 ||
		    (v->uv_flags & VIFF_NOLISTENER) != 0)
			goto set_timer;

		/*
		 * if an interface is configure in MLDv2, query is done 
		 * by MLDv2, regardless of compat-mode.
		 * (draft-vida-mld-v2-05.txt section 7.3.2 page 39)
		 *
		 * if an interface is configured only with MLDv1, query 
		 * is done by MLDv1.
		 */
#ifdef MLDV2_LISTENER_REPORT
		if (v->uv_mld_version & MLDv2) {
			send_mld6v2(MLD_LISTENER_QUERY, 0,
				    &v->uv_linklocal->pa_addr, NULL,
				    &g->al_addr,
				    v->uv_ifindex,
				    MLD6_QUERY_RESPONSE_INTERVAL,
				    0, TRUE, SFLAGNO, v->uv_mld_robustness,
				    v->uv_mld_query_interval, FALSE);
		} else if (v->uv_mld_version & MLDv1) 
#endif
		{
			send_mld6(MLD_LISTENER_QUERY, 0,
				  &v->uv_linklocal->pa_addr, NULL,
				  &g->al_addr.sin6_addr,
				  v->uv_ifindex,
				  MLD6_LAST_LISTENER_QUERY_INTERVAL, 0, 1);
		}
		v->uv_out_mld_query++;

	set_timer:
		g->al_query = SetQueryTimer(g, mifi,
					    MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE,
					    MLD6_LAST_LISTENER_QUERY_INTERVAL);
		g->al_timerid = SetTimer(mifi, g);
		break;
	}
}

/*
 * Time out record of a group membership on a vif
 */
void
DelVif(arg)
	void *arg;
{
	cbk_t *cbk = (cbk_t *) arg;
	mifi_t mifi = cbk->mifi;
	struct uvif *v = &uvifs[mifi];
	struct listaddr *a, **anp, *g = cbk->g;

	/*
	 * Group has expired delete all kernel cache entries with this group.
	 */
	if (g->al_query)
		DeleteTimer(g->al_query);

	delete_leaf(mifi, NULL, &g->al_addr);

	/* increment statistics */
	v->uv_listener_timo++;

	anp = &(v->uv_groups);
	while ((a = *anp) != NULL) {
		if (a == g) {
			*anp = a->al_next;
			free((char *) a);
		} else {
			anp = &a->al_next;
		}
	}

	free(cbk);
}

/*
 * Set a timer to delete the record of a group membership on a vif.
 */
int
SetTimer(mifi, g)
	mifi_t mifi;
	struct listaddr *g;
{
	cbk_t *cbk;

	cbk = (cbk_t *) malloc(sizeof(cbk_t));
	cbk->mifi = mifi;
	cbk->g = g;
	cbk->s = NULL;
	return timer_setTimer(g->al_timer, DelVif, cbk);
}

/*
 * Delete a timer that was set above.
 */
static int
DeleteTimer(id)
	int id;
{
	timer_clearTimer(id);
	return 0;
}

/*
 * Send a group-specific query.  This function shouldn't be called when 
 * the interface is configured with MLDv2, to prevent MLDv2 hosts from
 * shifting to MLDv1-compatible mode unnecessarily.
 * (now it's called only from SetQueryTimer() when the interface is 
 *  configured in MLDv1, so the above condition is satisfied)
 */
static void
SendQuery(arg)
	void *arg;
{
	cbk_t *cbk = (cbk_t *) arg;
	register struct uvif *v = &uvifs[cbk->mifi];

	/* sanity check */
	if (v->uv_mld_version & MLDv2) {
		log_msg(LOG_DEBUG, 0,
			"MLDv2-ready I/F %s cannot send MLDv1 Query",
			v->uv_name);
		return;
	}
	if (v->uv_flags & VIFF_QUERIER &&
	    (v->uv_flags & VIFF_NOLISTENER) == 0) {
		send_mld6(MLD_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
			  NULL, &cbk->g->al_addr.sin6_addr, v->uv_ifindex,
			  cbk->q_time, 0, 1);
		v->uv_out_mld_query++;
	}
	cbk->g->al_query = 0;
	free(cbk);
}

/*
 * Set a timer to send a group-specific query.
 * If an interface is configured only with MLDv1, query is done by MLDv1.
 * Otherwise (i.e. MLDv2 or any), query is done by MLDv2, regardless of
 * compat-mode (draft-vida-mld-v2-08.txt section 8.3.2 page 47).
 */
static int
SetQueryTimer(g, mifi, to_expire, q_time)
	struct listaddr *g;
	mifi_t mifi;
	int to_expire;
	int q_time;
{
	cbk_t *cbk;
	struct uvif *v = &uvifs[mifi];

	cbk = (cbk_t *) malloc(sizeof(cbk_t));
	cbk->g = g;
	cbk->s = NULL;
	cbk->q_time = q_time;
	cbk->mifi = mifi;

#ifdef MLDV2_LISTENER_REPORT
	if (v->uv_mld_version & MLDv2) {
		return timer_setTimer(to_expire, Send_GS_QueryV2, cbk);
	}
#endif
	/* either MLDv1-bit or MLDv2-bit is on in v->uv_mld_version */
	return timer_setTimer(to_expire, SendQuery, cbk);
}

/*
 * Checks for MLD listener: returns TRUE if there is a receiver for the group
 * on the given uvif, or returns FALSE otherwise.
 */
int
check_multicast_listener(v, group)
	struct uvif *v;
	struct sockaddr_in6 *group;
{
	register struct listaddr *g;

	/* Look for the group in our listener list. */
	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (inet6_equal(group, &g->al_addr))
			return TRUE;
	}
	return FALSE;
}
