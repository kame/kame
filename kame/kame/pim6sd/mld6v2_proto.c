/*
 * $KAME: mld6v2_proto.c,v 1.44 2004/06/14 08:16:03 suz Exp $
 */

/*
 * Copyright (C) 1999 LSIIT Laboratory.
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
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
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
#include <netdb.h>
#include "defs.h"
#include "vif.h"
#include "mld6.h"
#include "mld6_proto.h"
#include "mld6v2_proto.h"
#include "debug.h"
#include "timer.h"
#include "inet6.h"
#include "mld6v2.h"
#include "mrt.h"
#include "route.h"
#include "callout.h"
#include "pim6.h"

#ifdef MLDV2_LISTENER_REPORT

 /* MLDv2 implementation
  *   - MODE_IS_INCLUDE, ALLOW_NEW_SOURCES, BLOCK_OLD_SOURCES,
  *	    (S,G) is handled
  *   - MODE_IS_EXCLUDE, CHANGE_TO_EXCLUDE
  *	    just regarded as MLDv1 join
  *   - CHANGE_TO_INCLUDE:
  *	    regarded as (S,G)
  *
  * If the Multicast Interface is configured to 
  *	- any(both): goes to MLDv1-compat mode if MLDv1 is received.
  *	  (default)
  *	- MLDv1 only: ignores MLDv2 messages
  *	- MLDv2 only: ignores MLDv1 messages
  */  

/*
 * Forward declarations.
 */
static void Send_GSS_QueryV2 __P((void *arg));
static void DelVifV2 __P((void *arg));

static void accept_multicast_record(mifi_t, struct mld_group_record_hdr *,
				    struct sockaddr_in6 *,
				    struct sockaddr_in6 *);

/*
 * Send general group membership queries on that interface if I am querier.
 */
void
query_groupsV2(v)
    struct uvif *v;
{

    v->uv_gq_timer = v->uv_mld_query_interval;
    if ((v->uv_flags & VIFF_QUERIER) &&
    	(v->uv_flags & VIFF_NOLISTENER) == 0) {
	int ret;

	if (v->uv_stquery_cnt)
		v->uv_stquery_cnt--;
	if (v->uv_stquery_cnt)
		v->uv_gq_timer /= 4;	/* Startup Query Interval */

	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"sending multicast listener general query V2 on : %s ",
		v->uv_name);

	ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
			  NULL, (struct sockaddr_in6 *) NULL, v->uv_ifindex,
			  MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGNO,
			  v->uv_mld_robustness, v->uv_mld_query_interval,
			  FALSE);
	if (ret == TRUE)
		v->uv_out_mld_query++;
    }
}

/*
 * Send a group-source-specific v2 query.
 * Two specific queries are built and sent:
 *  1) one with S-flag ON with every source having a timer <= LLQI
 *  2) one with S-flag OFF with every source having a timer >LLQI
 * So we call send_mldv2() twice for different set of sources.
 */
static void
Send_GSS_QueryV2(arg)
    void           *arg;
{
    cbk_t          *cbk = (cbk_t *) arg;
    register struct uvif *v = &uvifs[cbk->mifi];
    int ret;

    if ((v->uv_flags & VIFF_QUERIER) == 0 || (v->uv_flags & VIFF_NOLISTENER)) {
	log_msg(LOG_DEBUG, 0,
		"don't send a GSS Query due to a lack of querying right");
	return;
    }

    ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
    		      NULL, &cbk->g->al_addr, v->uv_ifindex,
		      MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGNO,
		      v->uv_mld_robustness, v->uv_mld_query_interval, TRUE);
    if (ret == TRUE)
    	v->uv_out_mld_query++;

    ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
    		      NULL, &cbk->g->al_addr, v->uv_ifindex,
		      MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGYES,
		      v->uv_mld_robustness, v->uv_mld_query_interval, TRUE);
    if (ret == TRUE)
    	v->uv_out_mld_query++;

    cbk->g->al_rob--;

    /*
     * Schedule MLD6_ROBUSTNESS_VARIABLE specific queries.
     * is received or timer expired ( XXX: The timer granularity is 1s !!)
     */
    if (cbk->g->al_rob > 0) {
        timer_setTimer(MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE,
                       Send_GSS_QueryV2, cbk);
    } else
        free(cbk);
}

/*
 * Send a group-specific v2 query.
 */
void
Send_GS_QueryV2(arg)
    void           *arg;
{
    cbk_t          *cbk = (cbk_t *) arg;
    register struct uvif *v = &uvifs[cbk->mifi];
    int sflag = SFLAGNO;
    int ret;

    if ((v->uv_flags & VIFF_QUERIER) == 0 || (v->uv_flags & VIFF_NOLISTENER)) {
	log_msg(LOG_DEBUG, 0,
		"don't send a GS Query due to a lack of querying right");
	return;
    }

    if (cbk->g->al_timer > MLD6_LAST_LISTENER_QUERY_TIMER &&
        cbk->g->comp_mode == MLDv2)
    	sflag = SFLAGYES;

    ret = send_mld6v2(MLD_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
    		      NULL, &cbk->g->al_addr, v->uv_ifindex,
		      MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, sflag,
		      v->uv_mld_robustness, v->uv_mld_query_interval, FALSE);
    if (ret == TRUE)
	v->uv_out_mld_query++;
    cbk->g->al_rob--;

    /*
     * Schedule MLD6_ROBUSTNESS_VARIABLE specific queries.
     * is received or timer expired ( XXX: The timer granularity is 1s !!)
     */
    if (cbk->g->al_rob > 0) {
        timer_setTimer(MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE,
                       Send_GS_QueryV2, cbk);
    } else
        free(cbk);
}

/*
 * Process an incoming host membership v2 query according to the spec (rfc
 * 2710),the router can be in two states : QUERIER or NON QUERIER , and the
 * router start in the QUERIER state.
 * warn if the interface is in MLDv1 mode
 */

void
accept_listenerV2_query(src, dst, query_message, datalen)
    struct sockaddr_in6 *src;
    struct in6_addr *dst;
    register char  *query_message;
    int             datalen;
{
    register int    vifi;
    register struct uvif *v;
    struct sockaddr_in6 group_sa = { sizeof(group_sa), AF_INET6 };
    struct sockaddr_in6 source_sa = { sizeof(source_sa), AF_INET6 };
    struct listaddr *g, *s;
    struct in6_addr *group;
    struct mldv2_hdr *mldh;
    int             tmo;
    int             numsrc;
    int             i;
    u_int8_t        qqi;
    u_int8_t        qrv;
    u_int8_t        sflag;

    /*
     * Ignore my own listener v2 query 
     * since they are processed in the kernel 
     */

    if (local_address(src) != NO_VIF)
	return;

    if ((vifi = find_vif_direct(src)) == NO_VIF) {
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_INFO, 0, "accept_listenerv2_query: can't find a vif");
	return;
    }
    v = &uvifs[vifi];
    v->uv_in_mld_query++;

    if ((v->uv_mld_version & MLDv2) == 0) {
	log_msg(LOG_WARNING, 0,
	    "Mif %s configured in MLDv1 received MLDv2 query (src %s), ignored",
	    v->uv_name, sa6_fmt(src));
	return;
    }

    mldh = (struct mldv2_hdr *) query_message;
    group = &mldh->mld_addr;

    /*
     * XXX Hard Coding 
     */

    if ((tmo = ntohs(mldh->mld_maxdelay)) >= 32768)
	tmo = decodeafloat(ntohs(mldh->mld_maxdelay), 3, 12);
    numsrc = ntohs(mldh->mld_numsrc);
    if ((qqi = mldh->mld_qqi) >= 128)
	qqi = decodeafloat(mldh->mld_qqi, 3, 4);

    qrv = MLD_QRV(mldh->mld_rtval);
    sflag = MLD_SFLAG(mldh->mld_rtval);

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "accepting multicast listener query V2 on %s: "
	    "src %s, dst %s, grp %s\n"
	    "\t     sflag : %s,robustness : %d,qqi : %d maxrd :%d",
	    v->uv_name, sa6_fmt(src), inet6_fmt(dst), inet6_fmt(group),
	    sflag ? "YES" : "NO", qrv, qqi, tmo);

    /*
     * According to RFC2710 : when a query received from a router with a
     * lower IPv6 address than me  : 
     *   - start other Querier present. 
     *   - pass (or stay in the Non Querier state) .
     */

    if (inet6_lessthan(src, &v->uv_linklocal->pa_addr)) {
	IF_DEBUG(DEBUG_MLD)
	    if (!inet6_equal(src, &v->uv_querier->al_addr))
	    	log_msg(LOG_DEBUG, 0, "new querier %s (was %s) on vif %d",
			sa6_fmt(src), sa6_fmt(&v->uv_querier->al_addr), vifi);

	/* I'm not the querier anymore */
	v->uv_flags &= ~VIFF_QUERIER;
	v->uv_querier->al_addr = *src;
	SET_TIMER(v->uv_querier->al_timer, MLD6_OTHER_QUERIER_PRESENT_INTERVAL);
	time(&v->uv_querier->al_ctime);
    }
    /*
     * else nothing : the new router will receive a query one day... 
     */

    /*
     * Ignore the query if we're (still) the querier.
     */

    if ((v->uv_flags & VIFF_QUERIER) != 0)
	return;

    /*
     * routers adopt the most recent value of QRV and QQI unless 
     * this value is null
     */
    if (qrv != 0) {
	v->uv_mld_robustness = qrv;
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0, "New Qrv adopted : %d",
		v->uv_mld_robustness);
    }
    if (qqi != 0) {
	v->uv_mld_query_interval = qqi;
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0, "New Qqi adopted : %d",
		v->uv_mld_query_interval);
    }

    /*
     * When S-flag is set, only querier election has to be done.
     * (draft-vida-mld-v2-08.txt section 5.1.7)
     */
    if (sflag == TRUE) {
	log_msg(LOG_DEBUG, 0, "MLDv2 Query processing is suppressed");
    	return;
    }

    if (IN6_IS_ADDR_UNSPECIFIED(group)) {
	log_msg(LOG_DEBUG, 0,
		"nothing to do with general-query on router-side, "
		"except for querier-election");
    	return;
    }

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "%s for %s from %s on vif %d, timer %d",
	    "Group/Source-specific membership query V2",
	    inet6_fmt(group), sa6_fmt(src), vifi, tmo);

    group_sa.sin6_addr = *group;
    group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

    /* 
     * group-specific query:
     * Filter Timer should be lowered to [Last Listener Query Interval].
     */
    if (numsrc == 0) {
	IF_DEBUG(DEBUG_MLD)
		log_msg(LOG_DEBUG, 0, "Group-Specific-Query");

	for (g = v->uv_groups; g != NULL; g = g->al_next) {
		if (inet6_equal(&group_sa, &g->al_addr))
			break;
	}
	if (g == NULL) {
		log_msg(LOG_DEBUG, 0, "do nothing due to a lack of a "
			"correspoding group record");
		return;
	}

	/* setup a timeout to remove the multicast record */
	if (timer_leftTimer(g->al_timerid) >
            (int) (MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE)) {
	    timer_clearTimer(g->al_timerid);
	    SET_TIMER(g->al_timer,
	    	MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE);
	    g->al_timerid = SetTimer(vifi, g);
	}

	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"timer for grp %s on vif %d set to %ld",
		inet6_fmt(group), vifi, g->al_timer);
	return;
    }

    /* 
     * group-source-specific query:
     * for each sources in the Specific Query
     * message, lower our membership timer to [Last Listener Query Interval]
     */
    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0, "List of sources :");
    for (i = 0; i < numsrc; i++) {
	source_sa.sin6_addr = mldh->mld_src[i];
	source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

        log_msg(LOG_DEBUG, 0, "%s", sa6_fmt(&source_sa));

	/*
	 * Section 7.6.1 draft-vida-mld-v2-08.txt : When a router 
	 * receive a query with clear router Side Processing flag,
	 * it must update it's timer to reflect the correct
	 * timeout values : source timer for sources are lowered to LLQI
	 */

	s = check_multicastV2_listener(v, &group_sa, &g, &source_sa);
	if (s == NULL)
		continue;

	/* setup a timeout to remove the source/group membership */
	if (timer_leftTimer(s->al_timerid) >
            (int) (MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE)) {
	    timer_clearTimer(s->al_timerid);
	    SET_TIMER(s->al_timer,
	    	MLD6_LAST_LISTENER_QUERY_INTERVAL / MLD6_TIMER_SCALE);
	    s->al_timerid = SetTimerV2(vifi, g, s);
	}

	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_DEBUG, 0,
		"timer for grp %s src %s on vif %d set to %ld",
		inet6_fmt(group), sa6_fmt(&source_sa), vifi, s->al_timer);
    }
}

/*
 * Process an incoming group membership report. Note : this can be possible
 * only if The Router Alert Option have been set and I'm configured as a
 * router (net.inet6.ip6.forwarding=1) because report are sent to the
 * multicast group. processed in QUERIER and Non-QUERIER State
 * actually there is a timer per group/source pair. It's the easiest solution
 * but not really efficient...
 */
void
accept_listenerV2_report(src, dst, report_message, datalen)
    struct sockaddr_in6 *src;
    struct in6_addr *dst;
    register char  *report_message;
    int             datalen;
{

    register mifi_t vifi;
    register struct uvif *v;
    struct mld_report_hdr *report;
    struct mld_group_record_hdr *mard;
    int             i, nummard, numsrc, totsrc;
    struct sockaddr_in6 group_sa = { sizeof(group_sa), AF_INET6 };
    char *p;

    if ((vifi = find_vif_direct_local(src)) == NO_VIF) {
	IF_DEBUG(DEBUG_MLD)
	    log_msg(LOG_INFO, 0, "accept_listenerV2_report : can't find a vif");
	return;
    }

    v = &uvifs[vifi];

    if ((v->uv_mld_version & MLDv2) == 0) {
	log_msg(LOG_WARNING, 0,
	    "Mif %s configured in MLDv1 received MLDv2 report,ignored",
	    v->uv_name);
	return;
    }

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "accepting multicast listener V2 report: "
	    "src %s,dst %s", sa6_fmt(src), inet6_fmt(dst));

    report = (struct mld_report_hdr *) report_message;
    nummard = ntohs(report->mld_grpnum);

    v->uv_in_mld_report++;

    /*
     * loop through each multicast record 
     */

    totsrc = 0;
    for (i = 0; i < nummard; i++) {
	struct mld_group_record_hdr *mard0 = (struct mld_group_record_hdr *)(report + 1);
 	p = (char *)(mard0 + i) - sizeof(struct in6_addr) * i
		+ totsrc * sizeof(struct in6_addr);
        mard= (struct mld_group_record_hdr *) p;
	numsrc = ntohs(mard->numsrc);
	totsrc += numsrc;

	group_sa.sin6_addr = mard->group;
	group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

	if (IN6_IS_ADDR_MC_LINKLOCAL(&group_sa.sin6_addr)) {
	    /* too noisy */
	    IF_DEBUG(DEBUG_PKT)
		log_msg(LOG_DEBUG, 0,
		    "accept_listenerV2_report: group(%s) has the "
		    "link-local scope. discard",
		    sa6_fmt(&group_sa));
	    continue;
	}

	accept_multicast_record(vifi, mard, src, &group_sa);
    }
}


/* handles multicast record in normal MLDv2-mode */
static void
accept_multicast_record(vifi, mard, src, grp)
    mifi_t vifi;
    struct mld_group_record_hdr *mard;
    struct sockaddr_in6 *src;
    struct sockaddr_in6 *grp;
{
	struct uvif *v = &uvifs[vifi];
	int numsrc = ntohs(mard->numsrc);
	int j;
	struct sockaddr_in6 source_sa = { sizeof(source_sa), AF_INET6 };
    	struct listaddr *s = NULL;
    	struct listaddr *g = NULL;
	cbk_t *cbk;

	/* sanity check */
	if (v->uv_flags & VIFF_NOLISTENER)
	 	return;
	if (grp == NULL)
		return;

	/* just locate group */
	check_multicastV2_listener(v, grp, &g, NULL);

	switch (mard->record_type) {
	case CHANGE_TO_INCLUDE_MODE:
	    if (numsrc == 0) {
	        if (g == NULL) {
			log_msg(LOG_DEBUG, 0,
				"impossible to delete non-existent record");
			return;
		}
		g->filter_mode = MODE_IS_INCLUDE;
		recv_listener_done(vifi, src, grp);
	        break;
	    }
	    /* FALLTHOUGH */
	case MODE_IS_INCLUDE:
	case ALLOW_NEW_SOURCES:
	    for (j = 0; j < numsrc; j++) {
		/*
		 * Look for the src/group 
		 * in our src/group list; if found, reset its timer.
		 * (B)=MALI implementation
		 */
		source_sa.sin6_addr = mard->src[j];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);
		IF_DEBUG(DEBUG_MLD)
		    log_msg(LOG_DEBUG, 0, "processing source %s group %s",
			sa6_fmt(&source_sa), sa6_fmt(grp));

		s = check_multicastV2_listener(v, grp, &g, &source_sa);
		if (s != NULL) {
		    IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0, "The Source/group already exist");

		    /*
		     * delete old timers , set a timer for expiration 
		     * => start timer for this source/group
		     */

		    timer_clearTimer(s->al_timerid);
		    SET_TIMER(s->al_timer, MLD6_LISTENER_INTERVAL);
		    s->al_timerid = SetTimerV2(vifi, g, s);

		    /*
		     * If in the checking Listener : notify the timer is > LLQI
		     * for this source/group 
                     * If we have specific queries for this source/group
                     * pending they will be sent with the S flag set.
                     */

                    if (s->al_rob > 0)
                        s->al_checklist = MORETHANLLQI;
                    else
                        s->al_checklist = FALSE;
		} else {
		    /*
		     * If not found, add it to the list and update kernel cache.
		     */
		    IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "The source doesn't exist , trying to add it");

		    s = (struct listaddr *) malloc(sizeof(struct listaddr));
		    if (s == NULL)
			log_msg(LOG_ERR, 0, "ran out of memory"); /* fatal */
		    s->al_addr = source_sa;
		    s->sources = NULL;

		    /*
		     * if the group doesn't exist 
		     * link it to the chain of group 
		     */

		    if (g == NULL) {
			IF_DEBUG(DEBUG_MLD)
			    log_msg(LOG_DEBUG, 0,
				"The group too , trying to add it");

			g = (struct listaddr *)
			    malloc(sizeof(struct listaddr));
			if (g == NULL)
			    log_msg(LOG_ERR, 0, "ran out of memory"); /* fatal */
			g->al_addr = *grp;
			g->sources = NULL;
			g->comp_mode = MLDv2;
			g->filter_mode = MODE_IS_INCLUDE;

			g->al_next = v->uv_groups;
			v->uv_groups = g;
			time(&g->al_ctime);
		    }

		    /*
		     * start timer for this source/group 
		     */

		    s->al_checklist = FALSE;
		    SET_TIMER(s->al_timer, MLD6_LISTENER_INTERVAL);
		    s->al_timerid = SetTimerV2(vifi, g, s);

		    /*
		     * link it to the chain of sources 
		     */

		    s->al_next = g->sources;
		    g->sources = s;
		    time(&s->al_ctime);

		    /*
		     * this is protocol specific 
		     */
		    IF_DEBUG(DEBUG_MLD)
			log_msg(LOG_DEBUG, 0,
			    "*** notify routing daemon *** : "
			    "group(%s),source(%s) should be forwarded on %s",
			    sa6_fmt(&g->al_addr),
			    sa6_fmt(&s->al_addr), v->uv_name);

		}
		add_leaf(vifi, &source_sa, grp);

	    }
	    break;

	case BLOCK_OLD_SOURCES:
	    if (g == NULL) {
	    	log_msg(LOG_DEBUG, 0,
			"cannot accept BLOCK_OLD_SOURCE record"
			"for non-existent group");
	    	return;
	    }
	    if (g->comp_mode == MLDv1) {
	    	log_msg(LOG_DEBUG, 0, "ignores BLOCK msg in MLDv1-compat-mode");
		return;
	    }

	    /*
	     * Unlike RFC2710 section 4 p.7 (Routers in Non-Querier state 
	     * MUST ignore Done messages), MLDv2 non-querier should 
	     * accept BLOCK_OLD_SOURCES message to support fast-leave
	     * (although it's not explcitly mentioned).
	     */
	    for (j = 0; j < numsrc; j++) {
		/*
		 * Look for the src/group 
		 * in our src/group list; in order to set up a short-timeout
		 * group/source specific query.
		 */

		source_sa.sin6_addr = mard->src[j];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

		s = check_multicastV2_listener(v, grp, &g, &source_sa);
		if (s == NULL) {
			/* warning ? */
			break;
		}
		/*
		 * the source exist , so according to the spec, we will always 
		 * send a source specific query here : A*B is true here 
		 */
		/** => start timer **/
		/** timer updates are done in send_mldv2 **/
		if (s->al_checklist != LESSTHANLLQI) {
			s->al_checklist = LESSTHANLLQI;
			s->al_rob = MLD6_ROBUSTNESS_VARIABLE;
		} else {
                        s = NULL;
		}
	    }

	    /* scheduling MLD6_ROBUSTNESS_VAR specific queries to send */
            /* => send a m-a-s	*/
            /* start rxmt timer */
	    if (s) {
	    	cbk = (cbk_t *)malloc(sizeof(cbk_t));
		if (cbk == NULL)
			log_msg(LOG_ERR, 0, "ran out of memory"); /* fatal */
		g->al_rob = MLD6_ROBUSTNESS_VARIABLE;
	    	cbk->g = g;
	    	cbk->s = NULL;
	    	cbk->q_time = MLD6_LAST_LISTENER_QUERY_INTERVAL;
 	    	cbk->mifi = vifi;

	    	Send_GSS_QueryV2(cbk);
	    }
	    break;

	case MODE_IS_EXCLUDE:
	    /* just regard as (*,G) but not shift to mldv1-compat-mode */
	    recv_listener_report(vifi, src, grp, MLDv2);
	    break;

	case CHANGE_TO_EXCLUDE_MODE:
	    /* 
	     * RFC3810 8.3.2 says "MLDv2 BLOCK messages are ignored, as are 
	     * source-lists in TO_EX() messages".  But pim6sd does nothing,
	     * since it always ignores the source-list in a TO_EX message.
	     */
	    if (g->comp_mode == MLDv1) {
	    	log_msg(LOG_DEBUG, 0,
		    "ignores TO_EX source list in MLDv1-compat-mode");
	    }
	    /* just regard as (*,G) but not shift to mldv1-compat-mode */
	    recv_listener_report(vifi, src, grp, MLDv2);
	    break;

	default:
	    log_msg(LOG_NOTICE, 0,
		"wrong multicast report type : %d", mard->record_type);
	    break;
	}
}

/*
 * Time out record of a source(s)/group membership on a vif
 */

static void
DelVifV2(arg)
    void           *arg;
{
    cbk_t          *cbk = (cbk_t *) arg;
    mifi_t          vifi = cbk->mifi;
    struct uvif    *v = &uvifs[vifi];
    struct listaddr *a, **anp, *g = cbk->g;
    struct listaddr *b, **anq, *s = cbk->s;

    /*
     * Source(s)/Group has expired delete all kernel cache entries with this
     * group
     */

    /*
     * protocol specific 
     */

    IF_DEBUG(DEBUG_MLD)
	log_msg(LOG_DEBUG, 0,
	    "*** notify routing daemon ***: "
	    "group(%s),source(%s) has no more listeners on %s",
	    sa6_fmt(&g->al_addr), sa6_fmt(&s->al_addr), v->uv_name);

    delete_leaf(vifi, &s->al_addr, &g->al_addr);

    /*
     * increment statistics 
     */
    v->uv_listener_timo++;

    anp = &(v->uv_groups);

    /*
     * unlink it from the chain 
     * if there is no more source,delete the group 
     */

    while ((a = *anp) != NULL) {
	if (a != g) {
	    anp = &a->al_next;
	    continue;
	}

	/* We have found the group, now search the source to be deleted */
	anq = &(a->sources);
	while ((b = *anq) != NULL) {
		if (b != s) {
		    anq = &b->al_next;
		    continue;
		}
		*anq = b->al_next;
		free(b);
		break;
	}

	/*
 	 * no more sources, delete the group
	 * clear the checklist state for this group
	 */

	if (a->sources == NULL) {
		*anp = a->al_next;
		free(a);
	}
	break;
    }
    free(cbk);

}

/*
 * Set a timer to delete the record of a source/group membership on a vif.
 * typically used when report with record type 
 * -BLOCK_OLD_SOURCES,MODE_IS_INCLUDE,ALLOW_NEW_SOURCES  or  m-a-s source/group is received
 */

int
SetTimerV2(vifi, g, s)
    mifi_t          vifi;
    struct listaddr *g;
    struct listaddr *s;

{
    cbk_t          *cbk;

    cbk = (cbk_t *) malloc(sizeof(cbk_t));
    if (cbk == NULL)
 	log_msg(LOG_ERR, 0, "ran out of memory");	/*fatal */
    cbk->mifi = vifi;
    cbk->g = g;
    cbk->s = s;
    return timer_setTimer(s->al_timer, DelVifV2, cbk);
}

/*
 * Checks for MLDv2 listeners: returns a pointer on the source/group if there
 * is a receiver for the group on the given uvif, or returns NULL otherwise.
 *
 * *g points the group if it exists on the given uvif. if the group does not 
 * exist, *g is NULL.
 */
struct listaddr *
check_multicastV2_listener(v, group, g, source)
    struct uvif    *v;
    struct sockaddr_in6 *group;
    struct listaddr **g;
    struct sockaddr_in6 *source;
{
    struct listaddr *s;

    /*
     * Look for the source/group in our listener list;
     */
    for (*g = v->uv_groups; *g != NULL; *g = (*g)->al_next) {
	if (inet6_equal(group, &(*g)->al_addr) == 0)
	    continue;

	for (s = (*g)->sources; s != NULL; s = s->al_next) {
	    if (source && inet6_equal(source, &s->al_addr))
		return s;	/* group found, source found */
	}
	return NULL;	/* group found, source not found */
    }

    return NULL;	/* group not found, source not found */
}

void
mld_shift_to_v2mode(arg)
	void *arg;
{
	cbk_t *cbk = (cbk_t *) arg;
	
	struct sockaddr_in6 *grp = &cbk->g->al_addr;
	mifi_t mifi = cbk->mifi;
	struct uvif *v = &uvifs[mifi];
	struct listaddr *g;

	log_msg(LOG_DEBUG, 0,
	    "shift back mode from MLDv1-compat to MLDv2 for %s on Mif %s",
	    sa6_fmt(grp), v->uv_name);

	/* locate group info from this interface */
	for (g = v->uv_groups; g != NULL; g = g->al_next)
		if (inet6_equal(&g->al_addr, grp))
			break;
	if (g == NULL) {
		log_msg(LOG_ERR, 0,
		    "tried to shift back to MLDv2 mode for %s on Mif %s,"
		    "but there's no such group.",
		    sa6_fmt(grp), v->uv_name);
		return;	/* impossible */
	}

	g->comp_mode = MLDv2;
	g->al_comp = 0;
	free(cbk);

	/* won't continue this timer and just return */
	return;
}

int
SetTimerV1compat(mifi, g, interval)
	mifi_t mifi;
	struct listaddr *g;
{
	cbk_t *cbk;

	cbk = (cbk_t *) malloc(sizeof(cbk_t));
	cbk->mifi = mifi;
	cbk->g = g;
	cbk->s = NULL;
	return timer_setTimer(interval, mld_shift_to_v2mode, cbk);
}

int
DeleteTimerV1compat(id)
	int id;
{
	timer_clearTimer(id);
	return 0;
}
#endif
