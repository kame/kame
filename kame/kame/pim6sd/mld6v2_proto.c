/*
 * $KAME: mld6v2_proto.c,v 1.3 2001/08/09 08:46:57 suz Exp $
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


 /* MLDv2 implementation on SSM range i.e only MODE_IS_INCLUDE,
  * ALLOW_NEW_SOURCES,BLOCK_OLD_SOURCES Multicast address record
  * are processed
  * If the Multicast Interface is configured in version 1, none
  * of MLDv2 messages are processed
  * If the interface is configured in version 2 , and MLDv1 messages
  * arrives,process like the draft says
  */  

/*
 * Forward declarations.
 */
static void DelVifV2 __P((void *arg));
static int      SetTimerV2
__P((int vifi, struct listaddr * g, struct listaddr * s));
static void SendQueryV2spec __P((void *arg));

/*
 * Send general group membership queries on that interface if I am querier.
 */


void
query_groupsV2(v)
    register struct uvif *v;
{

    if ((v->uv_flags & VIFF_NOLISTENER) == 0)
    {
	IF_DEBUG(DEBUG_MLD)
	    log(LOG_DEBUG, 0,
		"sending multicast listener general query V2 on : %s ",
		v->uv_name);

	/*
	 * send gen. q. v2 
	 * S Flag not set.
	 */

	send_mld6v2(MLD6_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
		    NULL, (struct in6_addr *) &in6addr_any, v->uv_ifindex,
		    MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGNO,
		    v->uv_mld_robustness, v->uv_mld_query_interval, NULL);
	v->uv_out_mld_query++;
    }
    /*
     * (re)start initial gen. q. timer 
     */

    SET_TIMER(v->uv_gq_timer, v->uv_mld_query_interval);

}

/*
 * Send a group/source-specific v2 query : it only append if I am the querier
 * and interface isn't configured with nonlistener option if the source list
 * is null , it is a group-specifique query
 * according to the spec : Two specific query are built and sent : the first
 * one with the S flag set contain source who has timer <=LLQI, the second
 * with S flag cleared contain source who has timer >LLQI : not possible
 */

static void
SendQueryV2spec(arg)
    void           *arg;
{
    cbk_t          *cbk = (cbk_t *) arg;
    struct listaddr *sources = cbk->s;
    struct listaddr *logsrc = cbk->s;
    register struct uvif *v = &uvifs[cbk->mifi];

    /* we use the check list var for the group  to see */
    /* if we are in state checking listener for this group/source(s)*/
    
    if(cbk->g->al_checklist == FALSE)
    {
	while(logsrc)
	{
		sources=logsrc->al_next;
		log(LOG_DEBUG,0,"Freed %s",sa6_fmt(&logsrc->al_addr));
		free(logsrc);
		logsrc=sources;
	}	
	free(cbk);
	return;
    }

    IF_DEBUG(DEBUG_MLD)
	log(LOG_DEBUG, 0,
	    "sending multicast listener specific query V2 on : %s ,grp(%s)",
	    v->uv_name, inet6_fmt(&cbk->g->al_addr.sin6_addr));

    IF_DEBUG(DEBUG_MLD) if (sources)
    {
	log(LOG_DEBUG, 0, "list of sources :");
	while (logsrc)
	{
	    log(LOG_DEBUG, 0, "%s", sa6_fmt(&logsrc->al_addr));
	    logsrc = logsrc->al_next;
	}
    }
    send_mld6v2(MLD6_LISTENER_QUERY, 0, &v->uv_linklocal->pa_addr,
		NULL, &cbk->g->al_addr.sin6_addr, v->uv_ifindex,
		MLD6_QUERY_RESPONSE_INTERVAL, 0, TRUE, SFLAGNO,
		v->uv_mld_robustness, v->uv_mld_query_interval, sources);
    v->uv_out_mld_query++;

    /* Schedule another specific query until a INCLUDE state 
     * is received or timer expired ( XXX: not conform )
     */

    timer_setTimer(MLD6_LAST_LISTENER_QUERY_INTERVAL/MLD6_TIMER_SCALE,SendQueryV2spec,cbk);

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
    struct in6_addr *group;
    struct mld6v2_hdr *mldh;
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

    if ((vifi = find_vif_direct(src)) == NO_VIF)
    {
	IF_DEBUG(DEBUG_MLD)
	    log(LOG_INFO, 0, "accept_listenerv2_query: can't find a vif");
	return;
    }
    v = &uvifs[vifi];
    v->uv_in_mld_query++;

    if (v->uv_mld_version == MLDv1)
    {
	log(LOG_WARNING, 0,
	    "Mif %s configured in MLDv1 received MLDv2 query (src %s),ignored",
	    v->uv_name,sa6_fmt(src));
	return;
    }

    mldh = (struct mld6v2_hdr *) query_message;
    group = &mldh->mld6v2_addr;

    /*
     * XXX Hard Coding 
     */

    if ((tmo = ntohs(mldh->mld6v2_maxrc)) >= 32768)
	tmo = decodeafloat(ntohs(mldh->mld6v2_maxrc), 3, 12);
    numsrc = ntohs(mldh->mld6v2_numsrc);
    if ((qqi = mldh->mld6v2_qqi) >= 128)
	qqi = decodeafloat(mldh->mld6v2_qqi, 3, 4);

    qrv = MLD6_QRV(mldh);
    sflag = MLD6_SFLAG(mldh);

    IF_DEBUG(DEBUG_MLD)
	log(LOG_DEBUG, 0,
	    "accepting multicast listener query V2 on %s: "
	    "src %s, dst %s, grp %s\n\t     sflag : %s,robustness : %d,qqi : %d maxrd :%d",
	    v->uv_name, sa6_fmt(src), inet6_fmt(dst), inet6_fmt(group),
	    sflag ? "YES" : "NO", qrv, qqi, tmo);

    /*
     * According to rfc 2710 : when a query received from a router with a
     * lower IPv6 address than me  :   - start other Querier present. 
     *                       -pass (or stay in the Non Querier state .
     */

    if (inet6_lessthan(src, &v->uv_linklocal->pa_addr))
    {
	IF_DEBUG(DEBUG_MLD) if (!inet6_equal(src, &v->uv_querier->al_addr))
	    log(LOG_DEBUG, 0, "new querier %s (was %s) "
		"on vif %d",
		sa6_fmt(src), sa6_fmt(&v->uv_querier->al_addr), vifi);

	/*
	 * I'm not the querier anymore 
	 */
	v->uv_flags &= ~VIFF_QUERIER;
	v->uv_querier->al_addr = *src;
	SET_TIMER(v->uv_querier->al_timer,
		  MLD6_OTHER_QUERIER_PRESENT_INTERVAL);
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
    if (qrv != 0)
    {
	v->uv_mld_robustness = qrv;
	IF_DEBUG(DEBUG_MLD)
	    log(LOG_DEBUG, 0, "New Qrv adopted : %d",
		v->uv_mld_robustness);
    }
    if (qqi != 0)
    {
	v->uv_mld_query_interval = qqi;
	IF_DEBUG(DEBUG_MLD)
	    log(LOG_DEBUG, 0, "New Qqi adopted : %d", v->uv_mld_query_interval);
    }

    /*
     * if the S flag is set
     * I'm not the querier : for each sources in the Specific Query
     * message,lower our membership timer to (according draft-vida-mldv2)
     * - [Last Listener Query Interval] if this is a m-a-s source/group
     * query. (they are no group specific query : we are in SSM)
     */

    if (sflag == 0)
    {
	if (!IN6_IS_ADDR_UNSPECIFIED(group))
	{
	    struct listaddr *g;
	    struct listaddr *s;

	    IF_DEBUG(DEBUG_MLD)
		log(LOG_DEBUG, 0,
		    "%s for %s from %s on vif %d, timer %d",
		    "Group/Source-specific membership query V2",
		    inet6_fmt(group), sa6_fmt(src), vifi, tmo);

	    group_sa.sin6_addr = *group;
	    group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

	    IF_DEBUG(DEBUG_MLD)
		log(LOG_DEBUG,0,"List of sources :");
	    for (i = 0; i < numsrc; i++)
	    {
		source_sa.sin6_addr = mldh->mld6v2_sources[i];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

	        log(LOG_DEBUG, 0, "%s", sa6_fmt(&source_sa));

               /*
                * I'm not the querier but maybe I'm still in the state Checking listener
                * for this Group/Source we verify this with the al_checklist var
                */

		if ((s =
		     check_multicastV2_listener(v, &group_sa, &g,
						&source_sa)) != NULL
		    && s->al_checklist == FALSE)
		{
		    /*
		     * setup a timeout to remove the source/group
		     * membership
		     */
		    timer_clearTimer(s->al_timerid);
		    SET_TIMER(s->al_timer,
			      MLD6_LAST_LISTENER_QUERY_INTERVAL /
			      MLD6_TIMER_SCALE);

		    s->al_timerid = SetTimerV2(vifi, g, s);

		    /*
		     * use al_checklist to record our presence in
		     * last-member state
		     */

		    s->al_checklist = TRUE;
		    IF_DEBUG(DEBUG_MLD)
			log(LOG_DEBUG, 0,
			    "timer for grp %s src %s on vif %d "
			    "set to %ld",
			    inet6_fmt(group),
			    inet6_fmt(&source_sa.sin6_addr), vifi,
			    s->al_timer);

		}
	    }
	}
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
    struct mld6v2_report *report;
    struct mld6v2_maddr_rec *mard;
    int             i, j, nummard, numsrc;
    struct listaddr *g;
    struct listaddr *s;
    struct listaddr *spec;
    struct listaddr *tmp;
    struct sockaddr_in6 group_sa = { sizeof(group_sa), AF_INET6 };
    struct sockaddr_in6 source_sa = { sizeof(source_sa), AF_INET6 };
    cbk_t	*cbk;

    if ((vifi = find_vif_direct_local(src)) == NO_VIF)
    {
	IF_DEBUG(DEBUG_MLD)
	    log(LOG_INFO, 0, "accept_listenerV2_report : can't find a vif");
	return;
    }

    v = &uvifs[vifi];

    if (v->uv_mld_version == MLDv1)
    {
	log(LOG_WARNING, 0,
	    "Mif %s configured in MLDv1 received MLDv2 report,ignored",
	    v->uv_name);
	return;
    }

    IF_DEBUG(DEBUG_MLD)
	log(LOG_DEBUG, 0,
	    "accepting multicast listener V2 report: "
	    "src %s,dst %s", sa6_fmt(src), inet6_fmt(dst));

    report = (struct mld6v2_report *) report_message;
    nummard = ntohs(report->nmcastrcd);

    v->uv_in_mld_report++;

    /*
     * loop trough each multicast record 
     */

    for (i = 0; i < nummard; i++)
    {
	mard = &report->mr_maddr[i];
	numsrc = ntohs(mard->mmr_numsrc);

	group_sa.sin6_addr = mard->mmar_maddr;
	group_sa.sin6_scope_id = inet6_uvif2scopeid(&group_sa, v);

	if (IN6_IS_ADDR_MC_LINKLOCAL(&group_sa.sin6_addr))
	{
	    /*
	     * too noisy 
	     */

	    IF_DEBUG(DEBUG_PKT)
		log(LOG_DEBUG, 0,
		    "accept_listenerV2_report: group(%s) has the "
		    "link-local scope. discard",
		    inet6_fmt(&group_sa.sin6_addr));
	    continue;
	}

	switch (mard->mmr_type)
	{
	case MODE_IS_INCLUDE:
	case ALLOW_NEW_SOURCES:
	    for (j = 0; j < numsrc; j++)
	    {
		/*
		 * Look for the src/group 
		 * in our scr/group list; if found, reset its timer.
                 * (B)=MALI implementation
		 */

		source_sa.sin6_addr = mard->mmar_sources[j];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

		IF_DEBUG(DEBUG_MLD)
		    log(LOG_DEBUG, 0, "processing source %s group %s",
			inet6_fmt(&source_sa.sin6_addr),
			inet6_fmt(&group_sa.sin6_addr));

		if ((s =
		     check_multicastV2_listener(v, &group_sa, &g,
						&source_sa)) != NULL)
		{
		    IF_DEBUG(DEBUG_MLD)
			log(LOG_DEBUG, 0, "The Source/group already exist");

		    /*
		     * delete old timers , set a timer for expiration 
		     * => start timer for this source/group
		     */

		    timer_clearTimer(s->al_timerid);
		    SET_TIMER(s->al_timer, MLD6_LISTENER_INTERVAL);
		    s->al_timerid = SetTimerV2(vifi, g, s);

		    /*
		     * If in the checking Listener : clear rmxt timer 
		     * for this source/group 
		     */

		    if (s->al_checklist)
		    {
			timer_clearTimer(s->al_checklist);
			s->al_checklist = FALSE;
		    }

		}
		else
		    /*
		     * If not found, add it to the list and update kernel cache.
		     */
		{
		    IF_DEBUG(DEBUG_MLD)
			log(LOG_DEBUG, 0,
			    "The source doesn't exist , trying to add it");

		    s = (struct listaddr *) malloc(sizeof(struct listaddr));
		    if (s == NULL)
			log(LOG_ERR, 0, "ran out of memory");	/*fatal */
		    s->al_addr = source_sa;

		    /*
		     * if the group doesn't exist 
		     * link it to the chain of group 
		     */

		    if (g == NULL)
		    {
			IF_DEBUG(DEBUG_MLD)
			    log(LOG_DEBUG, 0,
				"The group too , trying to add it");

			g = (struct listaddr *)
			    malloc(sizeof(struct listaddr));
			if (g == NULL)
			    log(LOG_ERR, 0, "ran out of memory");	/*fatal */
			g->al_addr = group_sa;

			g->al_next = v->uv_groups;
			v->uv_groups = g;
			time(&g->al_ctime);
		    }

		     /** set a timer for expiration **/
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
			log(LOG_DEBUG, 0,
			    "*** notify routing daemon *** : group(%s),source(%s) should be forwarded on %s",
			    inet6_fmt(&g->al_addr.sin6_addr),
			    inet6_fmt(&s->al_addr.sin6_addr), v->uv_name);

		    add_leaf(vifi, &source_sa, &group_sa);
		}

	    }
	    break;

	case BLOCK_OLD_SOURCES:
	    /*
	     * Routers in Non-Querier state MUST ignore BLOCK_OLD_SOURCES message ? 
	     * like rfc 2710 ? 
	     */
	    if (!(v->uv_flags & (VIFF_QUERIER))
		|| v->uv_flags & VIFF_NOLISTENER)
		continue;

	    spec = NULL;

	    for (j = 0; j < numsrc; j++)
	    {
		/*
		 * Look for the src/group 
		 * in our scr/group list; in order to set up a short-timeout group/source specific query.
		 */

		source_sa.sin6_addr = mard->mmar_sources[j];
		source_sa.sin6_scope_id = inet6_uvif2scopeid(&source_sa, v);

		if ((s =
		     check_multicastV2_listener(v, &group_sa, &g,
						&source_sa)) != NULL)
		{
		    /*
		     * the source exist , so according to the spec, we will always 
		     * send a source specific query here : A*B is true here 
		     */

		    /*
		     * still waiting for a reply to a query, ignore the block source 
		     * - we are in state "checking listener"
		     * - we are the querier
		     * so ignore the block old source message for this group/source
                     * TODO :If g->al_checklist there is a pending query for the 
                     * same group, we have to merge it!
		     */

		    if (s->al_checklist)
			continue;

		    s->al_checklist = TRUE;

		    /** delete old timer set a timer for expiration **/
		    /** => start timer **/
		    /* XXX : not conform to the spec : we should send LLQC
                     * specific queries in LLQI.
		     */

		    timer_clearTimer(s->al_timerid);
		    SET_TIMER(s->al_timer,
			      MIN(s->al_timer,
				  MLD6_LAST_LISTENER_QUERY_INTERVAL /
				  MLD6_TIMER_SCALE) *
			      (MLD6_LAST_LISTENER_QUERY_COUNT));
		    s->al_timerid = SetTimerV2(vifi, g, s);

		    /** prepare the list for the source specific query **/

		    /*
		     * copy it 
		     */
		    tmp = (struct listaddr *) malloc(sizeof(struct listaddr));
		    if (tmp == NULL)
			log(LOG_ERR, 0, "ran out of memory");	/*fatal */
		    tmp->al_addr = s->al_addr;
		    tmp->al_checklist = TRUE;
		    /*
		     * link it 
		     */
		    tmp->al_next = spec;
		    spec = tmp;
		}
		/*
		 * else warning ? 
		 */

	    }

	    /* scheduling specific queries send */
            /* => send a m-a-s	*/
            /* start rxmt timer */

	    if(spec!=NULL)
	    {
		g->al_checklist=TRUE;
	    	cbk=(cbk_t *)malloc(sizeof(cbk_t));
	    	cbk->g=g;
	  	cbk->s=spec;
	    	cbk->q_time=MLD6_LAST_LISTENER_QUERY_INTERVAL;
 	    	cbk->mifi=vifi;

	    	SendQueryV2spec(cbk);
	    }

	    break;
	default:
	    log(LOG_NOTICE, 0,
		"Received a multicast report not supported : %d",
		mard->mmr_type);
	}

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
     * If coming from Checking Listener state clear rxmt timer.
     */

     g->al_checklist = FALSE;

    /*
     * protocol specific 
     */

    IF_DEBUG(DEBUG_MLD)
	log(LOG_DEBUG, 0,
	    "*** notify routing daemon ***: group(%s),source(%s) has no more listeners on %s",
	    inet6_fmt(&g->al_addr.sin6_addr),
	    inet6_fmt(&s->al_addr.sin6_addr), v->uv_name);

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

    while ((a = *anp) != NULL)
    {
	/*
	 * We have found the group,now search the source 
	 */

	if (a == g)
	{
	    anq = &(a->sources);
	    while ((b = *anq) != NULL)
	    {
		if (b == s)
		{
		    *anq = b->al_next;
		    free(b);
		    break;
		}
		else
		    anq = &b->al_next;
	    }

	    /*
	     * no more sources, delete the group 
             * clear the checklist state for this group
	     */

	    if (a->sources == NULL)
	    {
		*anp = a->al_next;
		free(a);
		timer_clearTimer(g->al_checklist);
		g->al_checklist=FALSE;
    		free(cbk);
	    }
	    break;
	}
	else
	    anp = &a->al_next;
    }

}

/*
 * Set a timer to delete the record of a source/group membership on a vif.
 * typically used when report with record type BLOCK_OLD_SOURCES or  m-a-s source/group is received
 */

static int
SetTimerV2(vifi, g, s)
    mifi_t          vifi;
    struct listaddr *g;
    struct listaddr *s;

{
    cbk_t          *cbk;

    cbk = (cbk_t *) malloc(sizeof(cbk_t));
    cbk->mifi = vifi;
    cbk->g = g;
    cbk->s = s;
    return timer_setTimer(s->al_timer, DelVifV2, cbk);
}

/*
 * Checks for MLDv2 listeners: returns a pointer on the source/group if there
 * is a receiver for the group on the given uvif, or returns NULL otherwise.
 * if the group exist but not the source, *g is updated
 * if the group does not exist *g is NULL else it point to the group int
 * the group list
 */

struct listaddr *
check_multicastV2_listener(v, group, g, source)
    struct uvif    *v;
    struct sockaddr_in6 *group;
    struct listaddr **g;
    struct sockaddr_in6 *source;
{
    register struct listaddr *s;

    /*
     * Look for the source/group in our listener list;
     */

    for (*g = v->uv_groups; *g != NULL; *g = (*g)->al_next)
    {
	if (inet6_equal(group, &(*g)->al_addr))
	{

	    for (s = (*g)->sources; s != NULL; s = s->al_next)
	    {
		if (inet6_equal(source, &s->al_addr))
		    return s;	/* case : group found,source found */
	    }
	    return NULL;	/* case : group found,source not found */
	}
    }
    return NULL;		/* case : group not found , source not found */
}
