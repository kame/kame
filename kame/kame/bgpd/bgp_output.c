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

#include "include.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "rt_table.h"
#include "aspath.h"
#include "bgp_var.h"
#include "in6.h"
#include "ripng.h"

#define BGP_LOG_SEND(type, len) IFLOG(LOG_BGPOUTPUT) \
          { syslog(LOG_DEBUG,\
		   "BGP+ SEND %s+%d -> %s+%d",\
		   ip6str2(&bnp->rp_myaddr),\
		   ntohs(bnp->rp_myaddr.sin6_port),\
		   bgp_peerstr(bnp),\
		   ntohs(bnp->rp_addr.sin6_port));\
	      syslog(LOG_DEBUG,\
		     "BGP+ SEND message type %d (%s) length %d",\
		     (type), bgp_msgstr[(type)], (len));\
	  }

/*
 *   bgp_send_open()
 */
int
bgp_send_open(struct rpcb *bnp)
{
  int i;
  u_int16_t      netasnum, nethldtim;
  struct bgphdr *bh;
  task          *tsk;

  extern byte       outpkt[];
  extern char      *bgp_msgstr[];
  extern u_int16_t  my_as_number, bgpHoldtime;
  extern u_int32_t  bgpIdentifier;
  extern fd_set     fdmask;
  extern task      *taskhead;


  memset(outpkt, 0, BGPMAXPACKETSIZE);

  bh = (struct bgphdr *)outpkt;
  /** fixed-size header **/
  /* Marker (16-octet to be all 1) */
  memset(bh->bh_marker, 0xff, BGP_HEADER_MARKER_LEN);

  /* Type   (1-octet) */
  bh->bh_type = BGP_OPEN;

  i = BGP_HEADER_LEN;
  /***  Open Message Format  ***/
  /* Version (1-octet)    */
  outpkt[i++] = BGP_VERSION_4;

  /* My Autonomous System (2-octet) */
  netasnum = htons(my_as_number);
  memcpy(&outpkt[i], &netasnum, 2);
  i += 2;

  /* Hold Time            (2-octet) */
  nethldtim = htons(bgpHoldtime);
  memcpy(&outpkt[i], &nethldtim, 2);
  i += 2;


  /* BGP Identifier       (4-octet) */
  memcpy(&outpkt[i], &bgpIdentifier, 4);  /* net-order (jinmei) */
  i += 4;

  /* Optional Parameters  (length is specified by "Opt Parm Len") */
  /* Opt Parm Len         (1-octet) */
  i++;
  /* NO authentification is supported. */

  /* again, total msg Length (2-octet) field in the header */
  bh->bh_length = htons(i);

  /****  send OPEN message  ****/
  if ((write(bnp->rp_socket, outpkt, i)) != i) {
    syslog(LOG_ERR, "<bgp_send_open>: write failed");
    bgp_cease(bnp);
    return NULL;
  }

  bgp_update_stat(bnp, BGPS_OPENSENT);
  BGP_LOG_SEND(BGP_OPEN, i);

  /***   OpenSent   ***/
  bnp->rp_state = BGPSTATE_OPENSENT;
  IFLOG(LOG_BGPSTATE)
    syslog(LOG_DEBUG, "<%s>: BGP state shift[%s] peer: %s", __FUNCTION__,
	   bgp_statestr[bnp->rp_state], bgp_peerstr(bnp));

  FD_SET(bnp->rp_socket, &fdmask);  /* open-sent Socket (to the global) */

  MALLOC(tsk, task);

  if (taskhead) {
    insque(tsk, taskhead);  /* will be sorted later by task_timer_update() */
  } else {
    tsk->tsk_next = tsk;
    tsk->tsk_prev = tsk;
    taskhead      = tsk;
  }

  tsk->tsk_bgp         = bnp;
  tsk->tsk_timename    = BGP_HOLD_TIMER;
  bnp->rp_hold_timer = tsk;

 /* was originally set to a large value */
  tsk->tsk_timefull.tv_sec  = bgpHoldtime;
  tsk->tsk_timefull.tv_usec = 0;

  /*  Hold timer ON. */ 
  task_timer_update(tsk);

  return NULL;
}

/*
 *   bgp_send_notification()
 */
int
bgp_send_notification(bnp, errcode, subcode, len, data)
     struct rpcb *bnp;
     byte errcode;
     byte subcode;
     int len;
     byte *data;
{
  int            i;     /* bytes to send */
  int            wlen;
  struct bgphdr *bh;

  extern byte      outpkt[];
  extern char *bgp_errstr[];
  extern char *bgp_hdrerrstr[];
  extern char *bgp_opnerrstr[];
  extern char *bgp_upderrstr[];
  extern char *bgp_msgstr[];
  memset(outpkt, 0, BGPMAXPACKETSIZE);

  bh = (struct bgphdr *)outpkt;
  /** fixed-size header **/
  /* Marker (16-octet to be all 1) */
  memset(bh->bh_marker, 0xff, BGP_HEADER_MARKER_LEN);

  /* Type   (1-octet) */
  bh->bh_type = BGP_NOTIFY;

  i = BGP_HEADER_LEN;
  /***  NOTIFICATION Message Format ***/

  /*   Error Code, Sub Code  */
  outpkt[i++] = errcode;
  outpkt[i++] = subcode;

  memcpy(&outpkt[i], data, len);
  i += len;

  /* again, total msg Length (2-octet) field in the header */
  bh->bh_length = htons(i);

  /****   send  NOTIFICATION  message   ****/ 
  if ((wlen = write(bnp->rp_socket, outpkt, i)) != i)
    syslog(LOG_ERR, "%s: write to %s (%s AS %d) failed: %s", __FUNCTION__,
	   bgp_peerstr(bnp),
	   ((bnp->rp_mode & BGPO_IGP) ? "Internal" : "External"),
	   (int)bnp->rp_as, strerror(errno));
  else
    syslog(LOG_NOTICE,
	   "NOTIFICATION sent to %s (%s AS %d): code %d (%s) data %s",
	   bgp_peerstr(bnp),
	   ((bnp->rp_mode & BGPO_IGP) ? "Internal" : "External"),
	   (int)bnp->rp_as,
	   errcode,
	   bgp_errstr[errcode],
	   bgp_errdatastr(data, len));


  switch (errcode) { /* code */
  case BGP_ERR_HEADER:
    if (subcode <= BGP_ERRHDR_TYPE)
      syslog(LOG_NOTICE, "\t subcode (%d) %s",
	     subcode, bgp_hdrerrstr[subcode]);
    break;
  case BGP_ERR_OPEN:
    if (subcode <= BGP_ERROPN_BADHOLDTIME)
      syslog(LOG_NOTICE, "\t subcode (%d) %s",
	     subcode, bgp_opnerrstr[subcode]);
    break;
  case BGP_ERR_UPDATE:
    if (subcode <= BGP_ERRUPD_ASPATH)
      syslog(LOG_NOTICE, "\t subcode (%d) %s",
	     subcode, bgp_upderrstr[subcode]);
    break;
  default:
    break;
  }

  bgp_update_stat(bnp, BGPS_NOTIFYSENT);
  BGP_LOG_SEND(BGP_NOTIFY, i);

  bnp->rp_state = BGPSTATE_IDLE;
  IFLOG(LOG_BGPSTATE)
    syslog(LOG_NOTICE, "<%s>: BGP state shift[%s] peer: %s", __FUNCTION__,
	   bgp_statestr[bnp->rp_state], bgp_peerstr(bnp));

  return NULL;    /* End of bgp_send_notification() */
}


/*
 *   bgp_send_keepalive()
 */
int
bgp_send_keepalive(struct rpcb *bnp)
{
  struct bgphdr *bh;

  extern byte       outpkt[];
  extern char      *bgp_msgstr[];

  memset(outpkt,   0, BGPMAXPACKETSIZE);

  bh = (struct bgphdr *)outpkt;  
  /** fixed-size header **/
  /* Marker (16-octet to be all 1) */
  memset(bh->bh_marker, 0xff, BGP_HEADER_MARKER_LEN);

  /* Type   (1-octet) */
  bh->bh_type = BGP_KEEPALIVE;

  /* again, total msg Length (2-octet) field in the header */
  bh->bh_length = htons(BGP_HEADER_LEN);

#if 0
  /*
   * XXX: we have to introduce a jitter here, but usleep
   * is not appropriate...
   */
  usleep(BGP_ADV_DELAY);   /* <---- important !! */
#endif 

  /****  send KEEPALIVE message  ****/
  if ((write(bnp->rp_socket, outpkt, BGP_HEADER_LEN)) != BGP_HEADER_LEN) {
    dperror("<bgp_send_keepalive>: write failed");
    syslog(LOG_ERR, "<bgp_send_keepalive>: write failed");
    bgp_cease(bnp);
    return NULL;
  }

  bgp_update_stat(bnp, BGPS_KEEPALIVESENT);
  BGP_LOG_SEND(BGP_KEEPALIVE, BGP_HEADER_LEN);


  /*  KeepAlive Timer ON. */
  task_timer_update(bnp->rp_keepalive_timer);

  return NULL;
}

#define BGP_LOG_ATTR  IFLOG(LOG_BGPOUTPUT) { syslog(LOG_DEBUG,\
			 "BGP+ SEND flags 0x%x code %s(%d):\\",\
			 outpkt[i-2],\
			 pa_typestr[outpkt[i-1]],\
			 outpkt[i-1]); }

/*
 *
 *   bgp_send_update()
 *       RETURN VALUES: last rte
 */
struct rt_entry *
bgp_send_update(bnp, rte, headrte)
     struct rpcb     *bnp;
     struct rt_entry *rte, *headrte;    /* is ring, and, have the same aspath. */
{
  struct bgphdr   *bh;
  int              i, topa_p, mp_p, lennh_p, nlri_p;       /* cursor */
  u_int8_t         origin;
  int              aspathlen;
  struct aspath   *asp;
  u_int16_t        netafi;
  u_int16_t        netmpnlrilen, nettpalen, netaspathlen;
  u_int32_t        netorigid = 0;
  u_int16_t        netnlrilen;
  struct rtproto  *rtp;    /* origin protocol of rte                 */
  struct rtproto   artp;
  struct rt_entry *rt;     /* return value. the last RTE which advd. */
  struct rt_entry *agg;    /* (1998/06/12) */
  struct optatr *optatr;

  extern byte       outpkt[];
  extern u_int16_t  my_as_number;
  extern byte       IamRR;
  extern u_int32_t  bgpIdentifier;
  extern char      *bgp_msgstr[], *bgp_statestr[];
  extern char      *pa_typestr[], *origin_str[];

  IFLOG(LOG_BGPOUTPUT)
    syslog(LOG_DEBUG,
	   "<%s>: invoked. AS=%u, ID=%s, state=%s",  /* iw97  */
	   __FUNCTION__,
	   bnp->rp_as, inet_ntoa(*(struct in_addr *)&bnp->rp_id),
	   bgp_statestr[bnp->rp_state]);

  if (bnp->rp_state != BGPSTATE_ESTABLISHED)
    fatalx("<bgp_send_update>: internal error: invalid state");


  if (rte == NULL) {                /* argument */
    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "<%s>: Nothing to be sent.", __FUNCTION__);
    return NULL;
  }

  memset(&artp, 0, sizeof(artp));
  artp.rtp_type = RTPROTO_BGP;
  artp.rtp_bgp   = bnp;

  memset(outpkt, 0, BGPMAXPACKETSIZE);
  rt = NULL;

  bh = (struct bgphdr *)outpkt;  
  /*** fixed-size header ***/
  /* Marker (16 octets to be all 1) */
  memset(bh->bh_marker, 0xff, BGP_HEADER_MARKER_LEN);

  /* Type   (1 octet) */
  bh->bh_type = BGP_UPDATE;

  i = BGP_HEADER_LEN;

  /***  Update Message Format  ***/

  /* Unfeasible Routes Length (2 octets)  */ 
  i += 2;
  /* IPv6 (BGP4+) doesn't send this.      */


  /*   Total Path Attribute Length (2 octets) (0...65535)    */
  i += 2;

  topa_p = i;


  rtp = &rte->rt_proto;              /* identical to each RTE */


  /*
   *   Path Attributes
   */
  /**  ORIGIN (Type Code 1)  **/
  outpkt[i++] |= PA_FLAG_TRANS;      /* well-known mandatory */
  outpkt[i++] =  PA4_TYPE_ORIGIN;    /* T */
  BGP_LOG_ATTR;
  outpkt[i++] =  PA4_LEN_ORIGIN;     /* L */  /* data len */
                                     /* V */
  switch (rtp->rtp_type) {
  case RTPROTO_IF: case RTPROTO_RIP: 
    origin = PATH_ORG_IGP;
    break;

  case RTPROTO_BGP:
    if (rtp->rtp_bgp->rp_mode & BGPO_IGP) {
      if (rte->rt_aspath)
	origin = rte->rt_aspath->asp_origin;
      else
	origin = PATH_ORG_IGP;  /* I originate. */
    } else {
      origin = PATH_ORG_EGP;
    }
    break;

  case RTPROTO_AGGR:
    origin = PATH_ORG_IGP;      /*   no case    */
    break;
  default:
    fatalx("BUG ! Invalid origin protocol");
    break;
  }


  switch (origin) {
  case PATH_ORG_IGP: case PATH_ORG_EGP: case PATH_ORG_XX:
    outpkt[i] = origin;
    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "BGP+ SEND\t\t%s", origin_str[origin]);
    break;
  default:
    fatalx("BUG ! Invalid ORIGIN attribute");
    break;
  }


  i += PA4_LEN_ORIGIN;

  
  /**  AS_PATH (Type Code 2)  **/    /* well-known mandatory */
  outpkt[i++] |= PA_FLAG_TRANS;      /* well-known mandatory */
  outpkt[i++] =  PA4_TYPE_ASPATH;    /* T */
  BGP_LOG_ATTR;

  i++;                               /* L */   /* later re-written */
                                     /* V */
  if (bnp->rp_mode & BGPO_IGP)
    asp = rte->rt_aspath;
  else {
    asp = prepend_aspath(my_as_number, rte->rt_aspath, 1);   /* mallocated */
    if (bnp->rp_ebgp_as_prepends) {
	    int i;
	    for (i = 0; i < bnp->rp_ebgp_as_prepends; i++)
		    asp = prepend_aspath(my_as_number, asp, 0);
    }
  }

  aspathlen = aspath2msg(asp ,i);    /* AS path is identical to the   */
                                     /* head of RTEs (i.e. argument)  */
                                     /* L */
  if (aspathlen <= 0xff) {
    outpkt[i-1] = aspathlen;
    i += aspathlen;
  } else {
    netaspathlen = htons(aspathlen);
    memcpy(&outpkt[i-1], &netaspathlen, sizeof(netaspathlen));
    outpkt[i-3] |= PA_FLAG_EXTLEN;
    i += 1;
    aspath2msg(asp ,i);  /* overwrite (...slow) */
  }
  if (!(bnp->rp_mode & BGPO_IGP)) {                      /* mallocated */
    free_aspath(asp);
    asp = NULL;
  }

  /**   NEXT_HOP   (Type Code 3)   **/
  /*     This is only allowed IPv4 address, so it's "no sense" for us.  */
  outpkt[i++] |= PA_FLAG_TRANS;          /* well-known mandatory */
  outpkt[i++] =  PA4_TYPE_NEXTHOP;       /* T */
  BGP_LOG_ATTR;
  outpkt[i++] =  sizeof(struct in_addr); /* L (IPv4 specific) */
                                         /* V */

  /* added by jinmei to interoperate with CISCO */  
  memcpy(&outpkt[i], (void *)&bgpIdentifier, PA_LEN_NEXTHOP); 

  i +=  PA_LEN_NEXTHOP;                  /* IPv4 address makes "no sense" */



  /** MULTI_EXIT_DISC (Type Code 4) optional non-transitive    **/
  /*   which received from a neighboring AS      [BGP4+ 5.1.4]  */
  /*        MUST NOT be propagated to other neighboring ASs     */

  if ((bnp->rp_mode & BGPO_IGP) &&
      rte->rt_aspath              &&
      rte->rt_aspath->asp_med != 0)          /* net-order */
    {
      outpkt[i++] |= PA_FLAG_OPT;
      outpkt[i++] =  PA4_TYPE_METRIC;        /* T */
      BGP_LOG_ATTR;
      outpkt[i++] =  PA4_LEN_METRIC;         /* L */
                                             /* V */
      memcpy(&outpkt[i], &rte->rt_aspath->asp_med, PA4_LEN_METRIC);
      i += PA4_LEN_METRIC;
    }

  /**   LOCAL_PREF (Type Code 5) well-known mandatory           **/
  /*     when it goes to external peer, It MUST NOT be included  */
  if (bnp->rp_mode & BGPO_IGP) {         /* IGP */
    u_int32_t netlocalpref;

    if (rte->rt_aspath)
      netlocalpref = rte->rt_aspath->asp_localpref;
    else
      netlocalpref = bnp->rp_prefer;

    outpkt[i++] |= PA_FLAG_TRANS;          /* well-known mandatory */
    outpkt[i++] =  PA4_TYPE_LOCALPREF;     /*  T  */
    outpkt[i++] =  PA4_LEN_LOCALPREF;      /*  L  */
                                           /*  V  */
    memcpy(&outpkt[i], &netlocalpref, PA4_LEN_LOCALPREF);
      
    i += PA4_LEN_LOCALPREF;
  }

  /**   ATOMIC_AGGREGATE (Type Code 6) well-known discretinary */
  if ( rte->rt_aspath &&
      (rte->rt_aspath->asp_atomagg & PATH_FLAG_ATOMIC_AGG)) {
    outpkt[i++] |= PA_FLAG_TRANS;          /* well-known discretinary */
    outpkt[i++] =  PA4_TYPE_ATOMICAGG;     /* T */
    outpkt[i++] =  PA4_LEN_ATOMICAGG;      /* L (IPv4 specific) */
    /* no data */
  }


  /**   ORIGINATOR_ID (Type Code 9) optional non-transitive */
  /*
     ORIGINATOR_ID is a new optional, non-transitive BGP attribute of Type
     code 9.  This attribute is 4 bytes long and it will be created by a
     RR. This attribute will carry the ROUTER_ID of the originator of the
     route in the local AS. A BGP speaker should not create an
     ORIGINATOR_ID attribute if one already exists.  A route reflector
     must never send routing information back to the router specified in
     ORIGINATOR_ID.  */
  if (IamRR &&
      (bnp->rp_mode & BGPO_IGP)) {

    /* ~fromEBGP and ~(ORIG_ID exists) */
    if (!(rtp->rtp_type == RTPROTO_BGP &&     /* excluding  EBGP */
	  (!(rtp->rtp_bgp->rp_mode & BGPO_IGP)))) {

      netorigid = (rte->rt_aspath && (rte->rt_aspath->asp_origid != 0)) ?
			rte->rt_aspath->asp_origid : rtp->rtp_bgp->rp_id;

      outpkt[i++] |= PA_FLAG_OPT;
      outpkt[i++] =  PA4_TYPE_ORIGINATOR;     /* T */
      BGP_LOG_ATTR;
      outpkt[i++] =  PA4_LEN_ORIGINATOR;      /* L */
      IFLOG(LOG_BGPOUTPUT)
	syslog(LOG_DEBUG, "BGP+ SEND\t\t%s",
	       inet_ntoa(*(struct in_addr *)&netorigid));
      memcpy(&outpkt[i], &netorigid, PA4_LEN_ORIGINATOR);
      i += PA4_LEN_ORIGINATOR;

    }
  }

  /**   CLUSTER_LIST (Type Code 10) optional non-transitive */
  /*
     When a RR reflects a route from its Clients to a Non-Client peer, it
     must append the local CLUSTER_ID to the CLUSTER_LIST. If the
     CLUSTER_LIST is empty, it must create a new one. Using this attribute
     an RR can identify if the routing information is looped back to the
     same cluster due to mis-configuration. If the local CLUSTER_ID is
     found in the cluster-list, the advertisement will be ignored.       */

  if (IamRR &&
      rtp->rtp_type == RTPROTO_BGP &&
      (rtp->rtp_bgp->rp_mode & BGPO_RRCLIENT) &&
      (bnp->rp_mode & BGPO_IGP) &&
      !(bnp->rp_mode & BGPO_RRCLIENT)) {

    struct clstrlist *cll;
    int               cllen;
    u_int16_t         netcllen;

    extern u_int32_t clusterId;

    outpkt[i++] |= PA_FLAG_OPT;
    outpkt[i++] =  PA4_TYPE_CLUSTERLIST;     /* T */
    BGP_LOG_ATTR;
    i++;                           /* L */   /* later re-written */
                                   /* V */  
    cll   = prepend_clstrlist(clusterId, rte->rt_aspath->asp_clstr);
    cllen = clstrlist2msg(cll, i);
                                     /* L */
    if (cllen <= 0xff) {
      outpkt[i-1] = cllen;
      i += cllen;
    } else {
      netcllen = htons(cllen);
      memcpy(&outpkt[i-1], &netcllen, sizeof(netcllen));
      outpkt[i-3] |= PA_FLAG_EXTLEN;
      i += 1;
      clstrlist2msg(cll ,i);  /* overwrite (...slow) */
    }

    free_clstrlist(cll);
  }
  


  /**                                                            **/
  /**   MP_REACH_NLRI (Type Code 14)   (optional non-transitive) **/
  /**                                                            **/
  outpkt[i]   |= PA_FLAG_OPT;      
  outpkt[i++] |= PA_FLAG_EXTLEN; /* tmp */
  outpkt[i++] =  PA4_TYPE_MPREACHNLRI;      /* T */
  BGP_LOG_ATTR;

  i += 2; /*   Extended length (temporaly) */ /* L */

  mp_p = i;
                                              /* V */
  /* Address Family Identifier (2 octets)        */
  netafi = htons(AFN_IP6);
  memcpy(&outpkt[i],  &netafi,  2);
  i += 2;
  /* Subsequent Address Family Identifier (1 octet) */
  outpkt[i++] = PA4_MP_UCAST;                /* implmntd for UNIcast only */

  /* Length of Next Hop Network Address (1 octet) */
  lennh_p = i++;

  /* Network Address of Next Hop (variable)       */
  IFLOG(LOG_BGPOUTPUT)
    syslog(LOG_DEBUG, "BGP+ SEND\t\tNextHop");

#define PUT_NEXTHOP(nexthop)  \
  { outpkt[lennh_p] += (byte)sizeof(struct in6_addr);  \
    memcpy(&outpkt[i], (nexthop),  \
	   sizeof(struct in6_addr));  \
    i +=  sizeof(struct in6_addr);  \
  }

  /*
   * The link-local address shall be included in the Next Hop field if and
   * only if the BGP speaker shares a common subnet with the entity
   * identified by the global IPv6 address carried in the Network Address
   * of Next Hop field and the peer the route is being advertised to.
   *
   * In all other cases a BGP speaker shall advertise to its peer in the
   * Network Address field only the global IPv6 address of the next hop
   * (the value of the Length of Network Address of Next Hop field shall
   * be set to 16).
   * [RFC 2545, Section 3]
   */
  if (bnp->rp_mode & BGPO_IGP) {   /* to IBGP */
    if (rte->rt_aspath &&
	!IN6_IS_ADDR_UNSPECIFIED(&rte->rt_aspath->asp_nexthop) &&
	(bnp->rp_mode & BGPO_NEXTHOPSELF) == 0) {
      PUT_NEXTHOP(&rte->rt_aspath->asp_nexthop); /* must be global */
    }
  } else {                        /* to EBGP */
    if (rte->rt_aspath &&
	!IN6_IS_ADDR_UNSPECIFIED(&rte->rt_aspath->asp_nexthop)) {
      struct rt_entry *irte;
      irte = bnp->rp_ife->ifi_rte;
      while (irte) {
        if (IN6_ARE_PRFX_EQUAL(&rte->rt_aspath->asp_nexthop,
                               &irte->rt_ripinfo.rip6_dest,
                                irte->rt_ripinfo.rip6_plen)) {
	  PUT_NEXTHOP(&rte->rt_aspath->asp_nexthop);
          break;
        }
        if ((irte = irte->rt_next) == bnp->rp_ife->ifi_rte)
          break;
      }
    }
  }
  /* If a global address to be included is not decided, choose one */
  if (IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)&outpkt[lennh_p + 1])) {
    /* put my global */
    if (!IN6_IS_ADDR_LINKLOCAL(&bnp->rp_myaddr.sin6_addr)) {
      PUT_NEXTHOP(&bnp->rp_myaddr.sin6_addr);
    } else {
      if (!IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_ife->ifi_gaddr))
	PUT_NEXTHOP(&bnp->rp_ife->ifi_gaddr);
    }
  }
  /*
   * Put my linklocal for an on-link peer
   * XXX: we suspect if it's really useful...see a comment in
   * bgp_process_update().
   */
  if (IN6_IS_ADDR_LINKLOCAL(&bnp->rp_ife->ifi_laddr) &&
      (bnp->rp_mode & BGPO_ONLINK)) {
    PUT_NEXTHOP(&bnp->rp_ife->ifi_laddr);
  }

  IFLOG(LOG_BGPOUTPUT) {
    if (outpkt[lennh_p] == 0)
      syslog(LOG_DEBUG, "BGP+ SEND\t\t(I have no Nexthop address)");
    if (outpkt[lennh_p] >= 16)
      syslog(LOG_DEBUG, "BGP+ SEND\t\t%s",
	     ip6str((struct in6_addr *)&outpkt[lennh_p + 1], 0));
    if (outpkt[lennh_p] >= 32)
      syslog(LOG_DEBUG, "BGP+ SEND\t\t%s",
	     ip6str((struct in6_addr *)&outpkt[lennh_p + 1 + 16], 0));
  }

  /* Number of SNPAs (1 octet) */
  outpkt[i++] = 0;                           /* NOT implmntd  */ 

#ifdef DRAFT_IETF_00
  /* Network Layer Reachability Information Length (2 Octets) */
  i += 2;
#endif

  nlri_p = i;

  /*** NLRI (4+) ***/
  IFLOG(LOG_BGPOUTPUT)
    syslog(LOG_DEBUG, "BGP+ SEND\t\tNLRI");

  rt = rte;          /* rte:argument */
  while(rt) {
    int poctets;     /* (minimum len in octet bound) */

    /* Generally, each AS has its own preferred default router. 
       Therefore, default routes should generally not leave the
       boundary of an AS. [rfc2080.txt] */
    if (!(bnp->rp_mode & BGPO_IGP) &&
	IN6_IS_ADDR_UNSPECIFIED(&rte->rt_ripinfo.rip6_dest))
      goto next_rte;

    /* generic filter */
    if (bgp_output_filter(bnp, rte))
      goto next_rte;

    agg = rt->rt_aggr.ag_agg;  /* (1998/06/12) */

    if (aggr_advable(agg, &artp)) {

      poctets = POCTETS(agg->rt_ripinfo.rip6_plen);

      if (i + 1 + poctets > BGPMAXPACKETSIZE ) {  /* 4096 octets */
	syslog(LOG_NOTICE, "<%s>: Max Size of BGP message", __FUNCTION__);
	rt = rt->rt_prev;
	break; /* while(rt) */
      }
      outpkt[i++] = agg->rt_ripinfo.rip6_plen;
      memcpy(&outpkt[i], agg->rt_ripinfo.rip6_dest.s6_addr, poctets);
      i +=  poctets;
      IFLOG(LOG_BGPOUTPUT)
	syslog(LOG_DEBUG, "BGP+ SENDING MP_REACH\t\t%s/%d to %s",
	       ip6str(&agg->rt_ripinfo.rip6_dest, 0),
	       agg->rt_ripinfo.rip6_plen,
	       bgp_peerstr(bnp));
      agg->rt_aggr.ag_flags |= AGGR_ADVDONE;
    }


    if (rt->rt_aggr.ag_flags & AGGR_NOADVD &&
	agg &&
	agg->rt_aggr.ag_flags & AGGR_ADVDONE)
      goto next_rte;

    if (rtp->rtp_type == RTPROTO_RIP &&
	(rt->rt_flags & RTF_IGP_EGP_SYNC || !(rt->rt_flags & RTF_UP)))
      goto next_rte;

    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "BGP+ SEND\t\t%s/%d",
	     ip6str(&rt->rt_ripinfo.rip6_dest, 0),
	     rt->rt_ripinfo.rip6_plen);	       

    if (rtp->rtp_type == RTPROTO_BGP) {
      if ((rt->rt_flags & (RTF_UP|RTF_INSTALLED)) != (RTF_UP|RTF_INSTALLED)) {
	IFLOG(LOG_BGPOUTPUT)
	  syslog(LOG_DEBUG, "BGP+ SEND\t\t\t(was skipped since unavaiable)");
	goto next_rte;
      }

      /* XXX: is there any case of INSTALLED but not SYNCHRONIZED? */
      if ((rtp->rtp_bgp->rp_mode & BGPO_IGP) &&
	  !(rtp->rtp_bgp->rp_mode & BGPO_NOSYNC) &&
	  (!(rt->rt_flags & RTF_IGP_EGP_SYNC))) {
	IFLOG(LOG_BGPOUTPUT)
	  syslog(LOG_DEBUG,
		 "BGP+ SEND\t\t\t(was skipped since not synchronized)");
	      goto next_rte;
	    }
    }

    poctets = POCTETS(rt->rt_ripinfo.rip6_plen);

    if (i + 1 + poctets > BGPMAXPACKETSIZE ) {  /* 4096 octets */
      syslog(LOG_NOTICE, "<%s>: Max Size of BGP message", __FUNCTION__);
      rt = rt->rt_prev;
      break; /* while(rt) */
    }
    outpkt[i++] = rt->rt_ripinfo.rip6_plen;
    memcpy(&outpkt[i], rt->rt_ripinfo.rip6_dest.s6_addr, poctets);
    i +=  poctets;
    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "BGP+ SEND\t\t%s/%d",
	     ip6str(&rt->rt_ripinfo.rip6_dest, 0),
	     rt->rt_ripinfo.rip6_plen);	       
  next_rte:

    if (rt->rt_next == headrte ||
	!equal_aspath(rt->rt_aspath, rt->rt_next->rt_aspath))
      break;

    if (rt->rt_next == rt)
      fatalx("BUG!");

    rt = rt->rt_next;

  } /* while(rt)... End of NLRI */

  /******************************/

  if (IamRR &&
      netorigid == bnp->rp_id) {
    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "<%s>: Don't re-send to originator.", __FUNCTION__);
    return rt;  /* pointer */
  }

  /* Network Layer Reachability Information Length (2 Octets) */
  if ((netnlrilen = htons(i - nlri_p)) == 0) {
    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "<%s>: Nothing to be sent for %s",
	     __FUNCTION__, bgp_peerstr(bnp));
    return rt;           /* (1998/06/16) */
  }
#ifdef DRAFT_IETF_00
  memcpy(&outpkt[nlri_p - 2], &netnlrilen, 2);
#endif


  /*  data length of MP_REACH_NLRI  */
  if (i - mp_p > 0xff) {
    netmpnlrilen = htons(i - mp_p);
    memcpy(&outpkt[mp_p - 2], &netmpnlrilen, 2);
  } else {
    outpkt[mp_p - 2] =  i - mp_p;
    outpkt[mp_p - 4] &= ~PA_FLAG_EXTLEN;  /* down */
    memmove(&outpkt[mp_p - 1], &outpkt[mp_p], i - mp_p);
    outpkt[i--] = 0;
  }

  /**********                          **********/ 
  /**********   End of MP_REACH_NLRI   **********/ 
  /**********                          **********/ 

  /* unrecognized but transitive path attributes */
  if (rtp->rtp_type == RTPROTO_BGP &&
      rte->rt_aspath) {		/* XXX: paranoid? */
    for (optatr = rte->rt_aspath->asp_optatr; optatr; optatr = optatr->next) {
      memcpy(&outpkt[i], optatr->data, optatr->len); /* XXX: boundary check */
      /* set partial bit since we don't recognize the attribute */
      outpkt[i] |= PA_FLAG_PARTIAL;
      i += optatr->len;
    }
  }

  /*** Total Path Attribute Length (2 octets) ***/
  nettpalen = htons(i - topa_p);
  memcpy(&outpkt[topa_p - 2], &nettpalen, 2);

  
  /* again, total msg Length (2-octet) field in the header */
  bh->bh_length = htons(i);

#if 0
  usleep(BGP_ADV_DELAY);
#endif
  
  /****  send UPDATE message  ****/
  if ((write(bnp->rp_socket, outpkt, i)) != i) {
    syslog(LOG_ERR, "<%s>: write to %s failed: %s",__FUNCTION__,
	   bgp_peerstr(bnp),strerror(errno));
#if 0
    /*
     * we don't have to(even MUST NOT) call bgp_cease() here, since
     * it will be called in the caller of the function, redistribute().
     * (jinmei@kame.net 19981127)
     */
    bgp_cease(bnp);
#endif 
    return NULL;
  }

  bgp_update_stat(bnp, BGPS_UPDATESENT);
  BGP_LOG_SEND(BGP_UPDATE, i);


  return rt;   /* the last RTE. */
}



/*
 *
 *   bgp_send_withdrawn()
 */
struct rt_entry *
bgp_send_withdrawn(bnp, rte, headrte)
     struct rpcb     *bnp;
     struct rt_entry *rte, *headrte;/* is ring, and, may have the same aspath. */
{
  struct bgphdr   *bh;
  int              i, topa_p, mp_p, nlri_p;            /* cursor */
  u_int16_t        netafi;
  u_int16_t        netmpnlrilen, nettpalen;
#ifdef DRAFT_IETF_00
  u_int16_t        netnlrilen;
#endif
  struct rt_entry *rt;

  extern byte       outpkt[];
  extern char      *bgp_msgstr[], *bgp_statestr[];
  extern char      *pa_typestr[];

  IFLOG(LOG_BGPOUTPUT)
    syslog(LOG_DEBUG, "<bgp_send_withdrawn>: invoked. AS=%u, ID=%s, state=%s",
	   bnp->rp_as, inet_ntoa(*(struct in_addr *)&bnp->rp_id),
	   bgp_statestr[bnp->rp_state]);

  if (bnp->rp_state != BGPSTATE_ESTABLISHED)
    fatalx("<bgp_send_withdrawn>: internal error: invalid state");

  memset(outpkt, 0, BGPMAXPACKETSIZE);
  rt = NULL;

  bh = (struct bgphdr *)outpkt;  
  /*** fixed-size header ***/
  /* Marker (16 octets) (to be all 1) */
  memset(bh->bh_marker, 0xff, BGP_HEADER_MARKER_LEN);


  bh->bh_type = BGP_UPDATE;  /* Type   (1 octet) */

  i = BGP_HEADER_LEN;
  /***  Update Message Format  ***/

  /* Unfeasible Routes Length (2 octets)  */ 
  i += 2;
  /* IPv6 (BGP4+) doesn't use this        */


  /*   Total Path Attribute Length (2 octets) (0...65535)    */
  i += 2;

  topa_p = i;

  /* exporting routes exist ? */
  if (rte == NULL) {                /* argument */
    fatalx("<bgp_send_withdrawn>: BUG !");
    return NULL;
  }

  /*
   *   Path Attributes
   */
  /**                                                            **/
  /**   MP_UNREACH_NLRI (Type Code 14)   (optional non-transitive) **/
  /**                                                            **/
  outpkt[i]   |= PA_FLAG_OPT;      
  outpkt[i++] |= PA_FLAG_EXTLEN;  /* tmp */
  outpkt[i++] =  PA4_TYPE_MPUNREACHNLRI;      /* T */
  BGP_LOG_ATTR;

  i += 2; /*   Extended length (temporary) */ /* L */

  mp_p = i;
                                              /* V */
  /* Address Family Identifier (2 octets)        */
  netafi = htons(AFN_IP6);
  memcpy(&outpkt[i],  &netafi,  2);
  i += 2;
  /* Subsequent Address Family Identifier (1 octet) */
  outpkt[i++] = PA4_MP_UCAST;                /* implmntd for UNIcast only */

#ifdef DRAFT_IETF_00
  /* Unfeasible Routes Length (2 Octets) */
  i += 2;
#endif

  nlri_p = i;

  /*** Withdrawn Routes, NLRI(+)format ***/
  {
    rt = rte;

    while(1) {
      int pbytes;     /* (minimum len in octet bound) */

      if (bgp_output_filter(bnp, rt))
	goto next_rte;

      outpkt[i++] = rt->rt_ripinfo.rip6_plen;
      IFLOG(LOG_BGPOUTPUT)
	syslog(LOG_DEBUG, "BGP+ SEND MP_UNREACH\t\t%s/%d to %s",
	       ip6str(&rt->rt_ripinfo.rip6_dest, 0),
	       rt->rt_ripinfo.rip6_plen,
	       bgp_peerstr(bnp));

      pbytes = POCTETS(rt->rt_ripinfo.rip6_plen);

      if (i + pbytes > BGPMAXPACKETSIZE ) {
	syslog(LOG_NOTICE, "<bgp_send_withdrawn>: Too Large NLRI");
	i--;
	break;
      }
      memcpy(&outpkt[i], rt->rt_ripinfo.rip6_dest.s6_addr, pbytes);
      i += pbytes;

    next_rte:

      if (rt->rt_next == headrte ||
	  !equal_aspath(rt->rt_aspath, rt->rt_next->rt_aspath))
	      break;

      rt = rt->rt_next;
    }
  }   /* End of NLRI */

#ifdef DRAFT_IETF_00
  /* Unfeasible Routes length (2 Octets) */
  netnlrilen = htons(i - nlri_p);
  memcpy(&outpkt[nlri_p - 2], &netnlrilen, 2);
#endif
    
  /* data length of MP_UNREACH_NLRI */
  if (i - mp_p > 0xff) {
    netmpnlrilen = htons(i - mp_p);
    memcpy(&outpkt[mp_p - 2], &netmpnlrilen, 2);
  } else {
    outpkt[mp_p - 2] =  i - mp_p;
    outpkt[mp_p - 4] &= ~PA_FLAG_EXTLEN;  /* down */
    memmove(&outpkt[mp_p - 1], &outpkt[mp_p], i - mp_p);
    outpkt[i--] = 0;
  }

  /**********                            **********/ 
  /**********   End of MP_UnReach_NLRI   **********/ 
  /**********                            **********/ 




  /* Total Path Attribute Length (2 octets) */
  nettpalen = htons(i - topa_p);
  memcpy(&outpkt[topa_p - 2], &nettpalen, 2);
  

  /* again, total msg Length (2-octet) field in the header */
  bh->bh_length = htons(i);

#if 0
  usleep(BGP_ADV_DELAY);
#endif

  /****  send UPDATE message  ****/ 
  if ((write(bnp->rp_socket, outpkt, i)) != i) {
    syslog(LOG_ERR, "<%s>: write %s failed: %s",
	   __FUNCTION__, bgp_peerstr(bnp), strerror(errno));

    return NULL;
  }

  bgp_update_stat(bnp, BGPS_WITHDRAWSENT);
  BGP_LOG_SEND(BGP_UPDATE, i);

  return rt;   /* the last RTE. */
}



void
bgp_dump(struct rpcb *bnp) {
    struct rtproto     *rtp;
    struct rt_entry    *rtehead, *rte;  /*  advertising  */
    struct rt_entry    *last;           /*  (1998/05/29) */
    extern char        *bgp_statestr[];

    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG,
	     "<bgp_dump>: invoked for %s (AS=%u, ID=%s, state=%s)",
	     bgp_peerstr(bnp), bnp->rp_as,
	     inet_ntoa(*(struct in_addr *)&bnp->rp_id),
	     bgp_statestr[bnp->rp_state]);

    aggr_flush();

    rtp = bnp->rp_adj_ribs_out;    /* we're gonna send DUMP */
    while (rtp) {

      rtehead = NULL;       /* (1998/06/10) */

      switch (rtp->rtp_type) {

      case RTPROTO_IF:
	/* In IBGP world, Split Holizon is commited. */
	if (!((bnp->rp_mode & BGPO_IGP) &&
	      bnp->rp_ife == rtp->rtp_if))
	  if (bgp_send_update(bnp, rtp->rtp_if->ifi_rte, rtp->rtp_if->ifi_rte)
	      == NULL){ /* a few */
	    bgp_cease(bnp); /* (1998/05/29) */
	    return;
	  }
	break;


      case RTPROTO_BGP:
      {
	      struct rpcb *ebnp = find_epeer_by_rpcb(rtp->rtp_bgp);
	      if (ebnp)
		      rtehead = ebnp->rp_adj_ribs_in;

	      rte = rtehead;
	      while(rte) { /* pointer maybe shifted */
		      if ((last = bgp_send_update(bnp, rte, rtehead)) == NULL) {
			      /* (1998/05/29) */
			      bgp_cease(bnp);
			      return;
		      }
		      if ((rte != rtehead) && (last == rtehead))
			      break;
		      if ((rte = last->rt_next) == rtehead)   /* head ? */
			      break;
	      }
	      break;
      }

      case RTPROTO_RIP:
	rtehead = rtp->rtp_rip->rip_adj_ribs_in;  /* (first redistribute) */
	rte = rtehead;
	while(rte) { /* pointer maybe shifted */
	  if ((last = bgp_send_update(bnp, rte, rtehead)) == NULL) { /* (1998/05/29) */
	    bgp_cease(bnp);
	    return;
	  }
	  if ((rte != rtehead) && (last == rtehead))
	    break;
	  if ((rte = last->rt_next) == rtehead)   /* head ? */
	    break;
	}
	break;

      default:
	fatalx("<bgp_dump>: BUG !");
	break;	
      }
      if ((rtp = rtp->rtp_next) == bnp->rp_adj_ribs_out)
	break;
    } /*  while(rtp) */

    IFLOG(LOG_BGPOUTPUT)
      syslog(LOG_DEBUG, "<bgp_dump>: done.");

    return;
}



#undef BGP_LOG_ATTR
#undef BGP_LOG_SEND
