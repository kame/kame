/*	$KAME: mld6_proto.h,v 1.11 2004/06/08 07:52:55 suz Exp $	*/

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


#ifndef MLD6_PROTO_H
#define MLD6_PROTO_H

/* structure used to send multicast group/source specific queries */
typedef struct
{
	mifi_t mifi;
	struct listaddr *g;
	struct listaddr *s;
	int q_time;
} cbk_t;

/*
 * Constans for Multicast Listener Discovery protocol for IPv6.
 */

#define	MLD6_DEFAULT_VERSION	MLDv1
#define MLD6_DEFAULT_ROBUSTNESS_VARIABLE        2
#define MLD6_DEFAULT_QUERY_INTERVAL 125 /* in seconds */
#define MLD6_DEFAULT_QUERY_RESPONSE_INTERVAL 10000 /* in milliseconds */
#define MLD6_DEFAULT_LAST_LISTENER_QUERY_INTERVAL 1000 /* in milliseconds */
#define MLD6_STARTUP_QUERY_INTERVAL 30	/* in seconds */
#define MLD6_STARTUP_QUERY_COUNT	MLD6_ROBUSTNESS_VARIABLE

#define MLD6_ROBUSTNESS_VARIABLE	v->uv_mld_robustness
#define MLD6_QUERY_INTERVAL		v->uv_mld_query_interval
#define MLD6_QUERY_RESPONSE_INTERVAL 	v->uv_mld_query_rsp_interval
#define MLD6_LAST_LISTENER_QUERY_INTERVAL	v->uv_mld_llqi
#ifndef MLD6_TIMER_SCALE
#define MLD6_TIMER_SCALE 1000
#endif

#define MLD6_LISTENER_INTERVAL (MLD6_ROBUSTNESS_VARIABLE * \
                MLD6_QUERY_INTERVAL + \
                MLD6_QUERY_RESPONSE_INTERVAL / MLD6_TIMER_SCALE)
#define MLD6_LAST_LISTENER_QUERY_COUNT      MLD6_ROBUSTNESS_VARIABLE

#define MLD6_OTHER_QUERIER_PRESENT_INTERVAL (MLD6_ROBUSTNESS_VARIABLE * \
		MLD6_QUERY_INTERVAL + \
		MLD6_QUERY_RESPONSE_INTERVAL / (2 * MLD6_TIMER_SCALE))
#define MLD6_OLDER_VERSION_HOST_PRESENT (MLD6_ROBUSTNESS_VARIABLE * \
		MLD6_QUERY_INTERVAL + \
		MLD6_QUERY_RESPONSE_INTERVAL / MLD6_TIMER_SCALE)

extern void     query_groups            __P((struct uvif *v));
extern int      check_grp_membership    __P((struct uvif *v, 
                                             struct sockaddr_in6 *group));
extern void     accept_listener_query   __P((struct sockaddr_in6 *src,
                                             struct in6_addr *dst,
                                             struct in6_addr *group,
                                             int tmo));
extern void     accept_listener_report  __P((struct sockaddr_in6 *src,
                                             struct in6_addr *dst,
                                             struct in6_addr *group));
extern void     accept_listener_done    __P((struct sockaddr_in6 *src,
                                             struct in6_addr *dst,
                                             struct in6_addr *group));
extern int      check_multicast_listener __P((struct uvif *v,
                                              struct sockaddr_in6 *group));

extern void     recv_listener_report	__P((mifi_t,
					     struct sockaddr_in6 *src,
                                             struct sockaddr_in6 *group));
extern void     recv_listener_done      __P((mifi_t,
					     struct sockaddr_in6 *src,
                                             struct sockaddr_in6 *group));
extern int	SetTimer __P((int mifi, struct listaddr * g));
extern void	DelVif __P((void *));

#endif
