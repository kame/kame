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
#include "ripng_var.h"

int          bgpsock;              /* socket for BGP tcp communication */

u_int16_t    my_as_number;         /* my AS number                     */
u_int32_t    bgpIdentifier;        /* BGP Identifier  (net-order)      */
u_int32_t    clusterId;            /* CLUSTER_ID                       */
u_int16_t    bgpHoldtime;          /* hold timer                       */
byte         IamRR;                /* I am Route Reflector             */

/* lists */
struct rpcb *bgb;

byte         outpkt[BGPMAXPACKETSIZE];

static int bgp_selectroute __P((struct rt_entry *, struct rpcb *));


/*
 *  bgp_connect_start()
 *    DESCRIPTION
 *       Initiate  connection-trying  to other BGP peer.
 *        It's first called by main(), after this, called by bgp_cease().
 */ 
void
bgp_connect_start(struct rpcb *bnp)
{
  task        *tsk;
  extern task *taskhead;

  if (bnp->rp_mode & BGPO_PASSIVE)
    fatalx("<bgp_connect_start>: BUG !");

  /*  "New" socket()  */ 
  if ((bnp->rp_socket = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
    fatal("<bgp_connect_start>: socket");

  bnp->rp_adj_ribs_in = NULL;           /*  <--- for safety.          */
  bnp->rp_stat.rps_connretry++;

  MALLOC(tsk, task);

  if (taskhead) {
    insque(tsk, taskhead);  /* will be sorted later by connect_try()    */
  } else {
    tsk->tsk_next = tsk->tsk_prev = tsk;
    taskhead      = tsk;
  }

  tsk->tsk_timename         = BGP_CONNECT_TIMER;
  tsk->tsk_bgp              = bnp;


#ifdef DEBUG
  tsk->tsk_timefull.tv_sec  = BGPCONN_SHORT;
#else
  tsk->tsk_timefull.tv_sec  = bnp->rp_stat.rps_connretry * BGPCONN_SHORT;
#endif
  tsk->tsk_timefull.tv_usec = 0;
  bnp->rp_connect_timer     = tsk;
  bnp->rp_state             = BGPSTATE_CONNECT;

  if (!(bnp->rp_mode & BGPO_IFSTATIC))  /* <--- need.   */
    bnp->rp_ife = NULL;

  /*  ConnectRetry timer ON. */
  task_timer_update(bnp->rp_connect_timer);

}



/*
 *   connect_try()
 *       Triggerd by SIGALRM (if and only-if).
 */ 
void
connect_try(struct rpcb *bnp)
{
#ifdef ADVANCEDAPI
  int                 on;
#endif
  int                 optval, optlen;
  char                in6txt[INET6_ADDRSTRLEN];/* length of my address  */
  int                 childpid;

  extern task   *taskhead;
  extern fd_set  fdmask;

  if (bnp->rp_mode & BGPO_PASSIVE ||
      bnp->rp_socket == -1)
    fatalx("<connect_try>: BUG !");

  /* CONNECT state - trying to connect */
  bnp->rp_state = BGPSTATE_CONNECT;

  /* If specfied, set source address */
  if (!IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_lcladdr.sin6_addr) &&
      bind(bnp->rp_socket, (struct sockaddr *)&bnp->rp_lcladdr,
	   sizeof(bnp->rp_lcladdr)) < 0) {
	  syslog(LOG_ERR, "<%s>: bind: %s", __FUNCTION__, strerror(errno));
	  fatalx("bind failed");
  }

  optval = 1; optlen = sizeof(optval);
  if (setsockopt(bnp->rp_socket, SOL_SOCKET, SO_REUSEADDR,
		 (int *)&optval, optlen) < 0) {
    fatal("<connect_try>: setsockopt: SO_REUSEADDR");
  }

#ifdef ADVANCEDAPI
  on = 1;
  if (setsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<connect_try>: setsockopt: IPV6_PKTINFO");

  if (bnp->rp_mode & BGPO_IFSTATIC) {
    struct in6_pktinfo *pktinfo;
    struct cmsghdr     *cmsgp;

    if ((cmsgp =
	 (struct cmsghdr *)malloc(CMSG_SPACE(sizeof(struct in6_pktinfo))))
	== 0)
      fatalx("<connect_try>: malloc");

    memset(cmsgp, 0, CMSG_SPACE(sizeof(struct in6_pktinfo)));

    cmsgp->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsgp->cmsg_level = IPPROTO_IPV6;
    cmsgp->cmsg_type  = IPV6_PKTINFO;
    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
    pktinfo->ipi6_ifindex = bnp->rp_ife->ifi_ifn->if_index;
    if (setsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTOPTIONS,
		   (void *)cmsgp,
		   CMSG_SPACE(sizeof(struct in6_pktinfo)))
	< 0)
      fatal("<connect_try>: setsockopt");
  }
#endif /* ADVANCEDAPI */

  childpid = 0;


  if (s_pipe(bnp->rp_sfd) < 0)
    terminate();

#if 0
  syslog(LOG_DEBUG, "<connect_try>: <s_pipe>: sfd[0]=%d, sfd[1]=%d ",
	 bnp->rp_sfd[0], bnp->rp_sfd[1]);
#endif


  if ((childpid = fork()) < 0) {
    dperror("<connect_try>: fork");
    terminate();
  }
  if (childpid == 0) {

    /*****  Child  *****/
/*    close(bnp->rp_sfd[0]); */

    if (connect(bnp->rp_socket, 
		(struct sockaddr *)&bnp->rp_addr, /* global or linklocal*/
		sizeof(bnp->rp_addr)) == 0)    {

      syslog(LOG_DEBUG,
	     "<connect_try>: <child>: connection succeed with %s (%s AS %d)",
	     inet_ntop(AF_INET6, &bnp->rp_addr.sin6_addr,
		       in6txt, INET6_ADDRSTRLEN),
	     ((bnp->rp_mode & BGPO_IGP) ? "Internal" : "External"),
	     bnp->rp_as);
    } else {
#ifdef DEBUG
      syslog(LOG_ERR, "<connect_try>: <child>: connect failed: %s",
	     strerror(errno));
      syslog(LOG_DEBUG, "\t\t\t by %s %s",
	     inet_ntop(AF_INET6, &bnp->rp_addr.sin6_addr,
		       in6txt, INET6_ADDRSTRLEN),
	     (bnp->rp_mode & BGPO_IFSTATIC) ?
	       bnp->rp_ife->ifi_ifn->if_name : "");
#endif
      close(bnp->rp_socket);
      bnp->rp_socket = -1;
    }

    if ((bgpd_sendfile(bnp->rp_sfd[1], bnp->rp_socket)) < 0) {
      exit(1);
    } else {
#if 0
      syslog(LOG_DEBUG, "<connect_try>: <child>: EXIT.");
#endif
      exit(0);
    }
  } /***  End of child  ***/

  /******  Parent  ******/
/*  close(bnp->rp_sfd[1]);*/

  FD_SET(bnp->rp_sfd[0] , &fdmask);
  /*  Clear ConnectRetry Timer  */
  taskhead = task_remove(bnp->rp_connect_timer);
  bnp->rp_connect_timer = NULL;

}



/*
 *   connect_process()
 */
#define CONNECT_RETRY(bnp) { close((bnp)->rp_socket);\
			     (bnp)->rp_socket = -1;\
			     bgp_connect_start((bnp));\
			     return; }
void
connect_process(struct rpcb *bnp)
{
  int   myaddrlen;
  int   cfd;

  extern fd_set  fdmask;

  cfd = recvfile(bnp->rp_sfd[0]);
  FD_CLR(bnp->rp_sfd[0], &fdmask);  /* no more use            */
  FD_CLR(bnp->rp_sfd[1], &fdmask);  /* <--- for safty (?) XXX */
  close(bnp->rp_sfd[0]);  bnp->rp_sfd[0] = -1;
  close(bnp->rp_sfd[1]);  bnp->rp_sfd[1] = -1;
  wait(NULL);

  if (cfd == bnp->rp_socket) {

    /**  connect succeed **/


    /* for Asynchronous connect */
    if (((bnp->rp_mode & BGPO_IGP) && find_epeer_by_rpcb(bnp)) ||
	(!(bnp->rp_mode & BGPO_IGP) && find_epeer_by_as(bnp->rp_as))) {
      close(bnp->rp_socket);
      bnp->rp_socket = -1;
      bnp->rp_state = BGPSTATE_IDLE;

      if (!(bnp->rp_mode & BGPO_IGP)) /* EBGP */
	bnp->rp_id = 0;
      return;
    }


    /*  my address  (insufficient information, for debug) */
    myaddrlen = sizeof(bnp->rp_myaddr);
    if (getsockname(bnp->rp_socket,
		    (struct sockaddr *)&bnp->rp_myaddr, &myaddrlen) != 0) {
	    syslog(LOG_INFO, "<%s>: failed to getsockname", __FUNCTION__);
	    CONNECT_RETRY(bnp);
    }

#ifdef ADVANCEDAPI
    {
      struct cmsghdr     *cmsgp;   /* Adv. API */
      struct in6_pktinfo *pktinfo; /* Adv. API */
      struct ifinfo      *ife;     /* ours     */ 
      int                 off, optlen;
      if ((cmsgp =
	   (struct cmsghdr *)malloc(CMSG_SPACE(sizeof(struct in6_pktinfo))))
	  == 0)
	fatalx("<connect_process>: malloc");

      memset(cmsgp, 0, CMSG_SPACE(sizeof(struct in6_pktinfo)));
      cmsgp->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
      cmsgp->cmsg_level = IPPROTO_IPV6;
      cmsgp->cmsg_type  = IPV6_PKTINFO;
      pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
      optlen  = CMSG_SPACE(sizeof(struct in6_pktinfo));
      if (getsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTOPTIONS,
		     (void *)cmsgp, &optlen)
	  < 0) {
	      syslog(LOG_INFO, "<%s>: failed to getsockopt(IPV6_PKTOPTIONS)", __FUNCTION__);
	      CONNECT_RETRY(bnp);
      }

      if (!(ife = find_if_by_index(pktinfo->ipi6_ifindex)))
	fatalx("<connect_process>: find_if_by_index: Unknown I/F");

      if (bnp->rp_mode & BGPO_IFSTATIC) {
	if (bnp->rp_ife != ife)
	  CONNECT_RETRY(bnp);
      } else {
	bnp->rp_ife = ife; /* overwrite */
      }

      off = 0;
      if (setsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTINFO,
		     &off, sizeof(off)) < 0) {
	      syslog(LOG_INFO, "<%s>: failed to setsockopt(IPV6_PKTINFO)",
		     __FUNCTION__);
	      CONNECT_RETRY(bnp);
      }
    }
#else  /* ! ADVANCEDAPI */
    {
      struct ifinfo *ife;

      if (!(ife = find_if_by_addr(&bnp->rp_myaddr.sin6_addr)))
	fatalx("<connect_process>: find_if_by_addr: Unknown Address");

      if (bnp->rp_mode & BGPO_IFSTATIC) {
	if (bnp->rp_ife != ife)
	  CONNECT_RETRY(bnp);
      } else {
	bnp->rp_ife = ife; /* overwrite */
      }
    }
#endif /* ADVANCEDAPI */


    bgp_send_open(bnp);
    return;

  } else { /**  connect() failed.  **/

    CONNECT_RETRY(bnp);

  }
}
#undef CONNECT_RETRY

/* Marker (16-octets to be all 1) */
#define BGP_MARKER_CHECK  for (i = 0; i < BGP_HEADER_MARKER_LEN; i++) { \
	   if (bh->bh_marker[i] != 0xff) {\
	    bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_UNSYNC, 0, NULL);\
	    return;\
	   };\
          }


/*
 *    bgp_process_open()
 *        DESCRIPTION: process received OPEN msg.
 */
void
bgp_process_open(struct rpcb *bnp) {
  int             i, k;       /*  tracer     */
  u_int16_t       rcvas, rcvht, negoht;
  u_int32_t       rcvid;      /*  net-order  */
  u_int8_t        optlen;
  struct rpcb    *ep = NULL;  /*    eBGP     */
  struct rpcb    *ip = NULL;  /*    iBGP     */
  struct rpcb    *p  = NULL;
  struct bgphdr  *bh;
  struct timeval  t;          /* calculation */
  task           *tsk;

  extern task *taskhead;
  
  bh = (struct bgphdr *)bnp->rp_inpkt;

  BGP_MARKER_CHECK;

  if (bnp->rp_state != BGPSTATE_OPENSENT) {
    bgp_notify(bnp, BGP_ERR_FSM, BGP_ERR_UNSPEC, 0, NULL);
    return;
  }

  /***  OPEN Message Format  ***/
  i = BGP_HEADER_LEN;
  /* Version (1-octet)    */
  /* If the version number contained in the Version field of the received
     OPEN message is not supported, then the Error Subcode is set to
     Unsupported Version Number.  The Data field is a 2-octet unsigned
     integer, which indicates the largest locally supported version number
     less than the version the remote BGP peer bid (as indicated in the
     received OPEN message). */
  if (bnp->rp_inpkt[i++] != BGP_VERSION_4) {
    u_int16_t version = BGP_VERSION_4;
    version = htons(version);
    bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_VERSION, 2, (byte *)&version);
    return;
  }

  /* My Autonomous System (2-octet) */
  rcvas = ntohs(*(u_short *)&bnp->rp_inpkt[i]);
  i += 2;
#ifdef DEBUG
  syslog(LOG_DEBUG,
	 "BGP+ RECV\t\tAutonomous System = %d", rcvas);
#endif
  /* Hold Time            (2-octet) */
  rcvht = ntohs(*(u_short *)&bnp->rp_inpkt[i]);
  if ( !HOLDTIME_ISCORRECT(rcvht) ) {
    bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_BADHOLDTIME, 0, NULL);
    return;
  };
  i += 2;

  /* BGP Identifier       (4-octet) */
  rcvid = *(u_long *)&bnp->rp_inpkt[i];
#ifdef DEBUG
  syslog(LOG_DEBUG,
	 "BGP+ RECV\t\tBGP Identifier = %s",
	 inet_ntoa(*(struct in_addr *)&rcvid));
#endif
  if (rcvid == 0) {
    bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_BGPID, 0, NULL);/* Bad BGPID */
    return;
  };
  i += 4;

  /* If the Autonomous System field of the OPEN message is unacceptable,
     then the Error Subcode is set to Bad Peer AS.  The determination of
     acceptable Autonomous System numbers is outside the scope of this
     protocol.                   (See section 6.2 of [I-D bgp4].)   */

  if (rcvas != my_as_number) { /* EGP ? */
    if (bnp->rp_mode & BGPO_PASSIVE) {
      if ((ep = find_peer_by_as(rcvas))) {  /* same AS */ 
	bnp->rp_as = rcvas; /* <<--- important !!! */
	bnp->rp_id = rcvid;
	bnp->rp_adj_ribs_out = ep->rp_adj_ribs_out;  /* fixedly */
	bnp->rp_ebgp_as_prepends = ep->rp_ebgp_as_prepends;
	bnp->rp_prefer = ep->rp_prefer;
	bnp->rp_mode |= (ep->rp_mode & BGPO_EBGPSTATIC); /* copy EBGP static */
      } else {
	bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_AS, 0, NULL);/*Bad Peer AS*/
	return;
      }
    }
    if (!(bnp->rp_mode & BGPO_PASSIVE)) {
      if (bnp->rp_as != rcvas) {
	bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_AS, 0, NULL);/*Bad Peer AS*/
	return;
      }
      if (bnp->rp_id == 0)
	bnp->rp_id = rcvid;
    }
  } /* end of EGP */

  if (rcvas == my_as_number) { /* IGP */
    if (bnp->rp_mode & BGPO_PASSIVE) {
      if ((ip = rpcblookup(bgb, rcvid)) ||              /* iw97         */
	  (ip = find_apeer_by_addr(&bnp->rp_gaddr)) ||   /* (1998/05/25) */
	  (ip = find_apeer_by_addr(&bnp->rp_laddr)))  {  /* (1998/05/25) */
	bnp->rp_as    = rcvas;
	bnp->rp_id    = rcvid;
	bnp->rp_mode |= BGPO_IGP;
	bnp->rp_mode |= (ip->rp_mode & BGPO_IBGPSTATIC); /* copy IBGP static */
	bnp->rp_adj_ribs_out = ip->rp_adj_ribs_out;    /* fixedly */
      } else {
	bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_BGPID, 0, NULL);/*Bad BGPID*/
	return;
      }
    }

    if (!(bnp->rp_mode & BGPO_PASSIVE)) {
      if ((bnp->rp_mode & BGPO_IDSTATIC) &&  /* BGP-ID wasn't configured */
	  (bnp->rp_id != rcvid)) {
	bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_BGPID, 0, NULL);/*Bad BGPID*/
	return;
      } else
	bnp->rp_id = rcvid;
    }

  } /* end of IGP */


  /* Opt Parm Len         (1-octet) */
  optlen = bnp->rp_inpkt[i++];
  k = i;

  /* Optional Parameters  (length is specified by "Opt Parm Len") */
  while (i < k + optlen) {
    struct bgpoptparm *bop;

    bop = (struct bgpoptparm *)&bnp->rp_inpkt[i];

    switch(bop->bop_type) {
    case BGP_OPTPARAM_AUTH:
      i += sizeof(struct bgpoptparm) + bop->bop_len;
      break;      /* NO authentification is checked. */
    case BGP_OPTPARAM_CAPA:
      i += sizeof(struct bgpoptparm) + bop->bop_len;
      break;
    default:
      /* If one of the Optional Parameters in the OPEN message is not
	 recognized, then the Error Subcode is set to Unsupported Optional
	 Parameters. [BGP-4] */
      bgp_notify(bnp, BGP_ERR_OPEN, BGP_ERROPN_OPTION, 0, NULL);
      return;
      break;
    }
  }


  if (i != ntohs(bh->bh_length)) {
    bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH, 0, NULL);
    return;
  }
  
  p = bnp; /*  "p" initial  */

  if (ep) {
    if (ep->rp_id == bnp->rp_id)
      switch (ep->rp_state) {
      case BGPSTATE_OPENCONFIRM: case BGPSTATE_OPENSENT:

	p = collision_resolv(bnp, ep);
	  
	if (p != bnp)  /* Local "p" is prefered to new "bnp".  And,       */
	  return;      /* current "bnp" was deleted by collision_resolv() */

	break;


      case BGPSTATE_ESTABLISHED:
	syslog(LOG_NOTICE,
	       "<bgp_process_open>: Already established peer exists");
	bgp_notify(bnp, BGP_CEASE, BGP_ERR_UNSPEC, 0, NULL);
	return;
      case BGPSTATE_IDLE: case BGPSTATE_CONNECT: case BGPSTATE_ACTIVE:
	/* collision cannot be detected in these states */
	p = bnp; /* Now "p" is ...      */
	break;
      default :
	fatalx("<bgp_process_open>: not implmntd.");
      };
  } else {
    if (ip) {
      switch (ip->rp_state) {
      case BGPSTATE_OPENCONFIRM: case BGPSTATE_OPENSENT:

	p = collision_resolv(bnp, ip);
	  
	if (p != bnp)  /* Local "p" is prefered to new "bnp".  And,       */
	  return;      /* current "bnp" was deleted by collision_resolv() */

	break;

      case BGPSTATE_ESTABLISHED:
	syslog(LOG_NOTICE,
	       "<bgp_process_open>: Already established peer exists");
	bgp_notify(bnp, BGP_CEASE, BGP_ERR_UNSPEC, 0, NULL);
	return;
      case BGPSTATE_IDLE: case BGPSTATE_CONNECT: case BGPSTATE_ACTIVE:
	/* collision cannot be detected in these states */
	p = bnp; /* Now "p" is ...      */
	break;
      default :
	fatalx("<bgp_process_open>: not implmntd.");
      };
    } else
      p = bnp;
  } /* End of if (ep) */


  /**  HoldTime negotiation        **/
  t.tv_sec  = rcvht;
  t.tv_usec = 0;

  /*   If the negotiated Hold Time value is zero,
       then the Hold Time timer and KeepAlive timers are not started.  */

  if (rcvht == 0) {
    taskhead = task_remove(p->rp_hold_timer);
    p->rp_hold_timer = NULL;    

  } else {

    if (sub_timeval(&t ,&p->rp_hold_timer->tsk_timefull) > 0) {
    
      p->rp_hold_timer->tsk_timefull.tv_sec  = rcvht;
      p->rp_hold_timer->tsk_timefull.tv_usec = 0;

      task_timer_update(p->rp_hold_timer);
    }
  }

  /* NOTE: If the negotiated Hold Time is 0,
            then system doesn't send/receive any KeepAlives  */

  if ((negoht = p->rp_hold_timer->tsk_timefull.tv_sec) == 0) {
    /* KeepAlive timer not started */
  } else {

    MALLOC(tsk, task);
    
    if (taskhead) {
      insque(tsk, taskhead);  /* will be sorted later by task_timer_update() */
    } else {
      tsk->tsk_next = tsk;
      tsk->tsk_prev = tsk;
      taskhead      = tsk;
    }

    tsk->tsk_bgp          = p;
    tsk->tsk_timename     = BGP_KEEPALIVE_TIMER;
    p->rp_keepalive_timer = tsk;

    /* A reasonable maximum time between KEEPALIVE messages
       would be one third of the Hold Time interval.  KEEPALIVE messages
       MUST NOT be sent more frequently than one per second. [Page.17]*/
    tsk->tsk_timefull.tv_sec  = (negoht/3 < 1) ? 1 : negoht/3;/* sec. */
    tsk->tsk_timefull.tv_usec = 0;
  }

  bgp_send_keepalive(p);

  /***  Finally, the state is changed to  OpenConfirm.   ***/
  p->rp_state = BGPSTATE_OPENCONFIRM;

}




/*
 *    bgp_process_update()
 *       process received UPDATE msg.
 */
void
bgp_process_update(struct rpcb *bnp)
{
  int               i,j,k;       /* tracer                                */
  struct bgphdr    *bh;
  u_int16_t         length;      /* Length                                */
  int               pa_p;        /* start point of Path Attributes        */
  u_int16_t         urlen;       /* Unfeasible Routes Length              */
  u_int16_t         tpalen;      /* Total Path Attributes Length          */
  u_int16_t         atrlen;      /* the length of the attribute           */
  u_int16_t         atrdatalen;  /* the length of the attribute data      */
  byte              origin;      /* ORIGIN                                */
  struct aspath    *asp;         /* AS_PATH                               */ 
  u_int32_t         med;         /* MULTI_EXIT_DISC    (net-order)        */ 
  u_int32_t         localpref;   /* LOCAL_PREF         (net-order)        */ 
  int               aggregated;  /* logical                               */
  u_int32_t         originatorid;/* [rfc1966]          (net-order)        */
  struct clstrlist *cll;         /* [rfc1966]                             */
  struct optatr *optatr = NULL;	 /* list of unrecognized attributes */
  u_int8_t          nhnalen;     /* Next Hop Network Addresses Length (+) */
  struct in6_addr   gnhaddr;     /* "nexthop" address                 (+) */
  struct in6_addr   lnhaddr;     /* "nexthop" address                 (+) */
  u_int8_t          snpanum;     /* Number of SNPAs                   (+) */
  u_int8_t          snpalen;     /* Length of a SNPA                  (+) */
#ifdef DRAFT_IETF_00
  u_int16_t         nlrilen;     /* NLRI Length                       (+) */
#endif
  u_int16_t         v4nlrilen;   /* "traditional" NLRI Length             */

  /* routes that may be installed and/or redistributed: */
  struct rt_entry  uprtehead = {&uprtehead, &uprtehead};
  /* routes that should be withdrawn: */
  struct rt_entry  wdrtehead  = {&wdrtehead, &wdrtehead};
  struct rt_entry  *uprte;
  struct rt_entry  *wdrte;
  char              in6txt[INET6_ADDRSTRLEN];

  extern struct ifinfo   *ifentry;
  extern struct rt_entry *aggregations; 
#ifdef DEBUG
  extern char   *pa_typestr[], *origin_str[];
#endif
 
  bitstr_t bit_decl(parsedflag, PA4_MAXTYPE);
  bit_nclear(parsedflag, 0, PA4_MAXTYPE);

  origin     = PATH_ORG_XX;    /* "incomplete" */
  med = aggregated = originatorid = v4nlrilen = 0;
  localpref  = bnp->rp_prefer; /* default      */
  asp        = NULL;
  cll        = NULL;

  memset(&gnhaddr, 0, sizeof(gnhaddr));
  memset(&lnhaddr, 0, sizeof(lnhaddr));
  memset(in6txt,   0, INET6_ADDRSTRLEN);

  bh = (struct bgphdr *)bnp->rp_inpkt;
  /* if the OPEN message carries no Authentication Information (as an
     Optional Parameter), then the Marker must be all ones. */
 
  BGP_MARKER_CHECK;

  /* Length (2-octet) */ /* was checked partially */
  length = ntohs(bh->bh_length);

  if (bnp->rp_state != BGPSTATE_ESTABLISHED) {
    bgp_notify(bnp, BGP_ERR_FSM, BGP_ERR_UNSPEC, 0, NULL); 
    return;
  }

  /* Update Hold Timer */
  task_timer_update(bnp->rp_hold_timer);

  i = BGP_HEADER_LEN;
  /***  UPDATE Message Format  ***/

  /* Unfeasible Routes Length (2 octets) */
  urlen = ntohs(*(u_short *)&bnp->rp_inpkt[i]);
  i += 2 ;
  /* Total Path Attribute Length (2 octets) */
  tpalen = ntohs(*(u_short *)&bnp->rp_inpkt[i + urlen]);

  if (urlen + tpalen + 23 > length ) {   /* Malformed Attribute List */
      bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_ATTRLIST, 0, NULL);
      return;
  }
    
  i += urlen;  /* IPv6 (BGP4+) ignores this. */

  i += 2;      /* Total Path Attribute Length (2 octet) */


  /*  Path Attributes (variable)  */
  pa_p = i;
  while (pa_p + tpalen > i) {    /* Malformation is detected ASAP */
	  int error;

#ifdef DEBUG
	  {
		  struct in_addr peerid;

		  peerid = *(struct in_addr *)&bnp->rp_id;
		  if (PA4_TYPE_VALID(bnp->rp_inpkt[i + 1]))
			  syslog(LOG_DEBUG,
				 "BGP+ RECV flags 0x%x code %s(%d) peerid %s:\\",
				 bnp->rp_inpkt[i],
				 pa_typestr[bnp->rp_inpkt[i + 1]],
				 bnp->rp_inpkt[i + 1], inet_ntoa(peerid));
	  }
#endif
    
#define PA4_TYPE_CODE_CHECK \
    { i++;\
      if (bit_test(parsedflag, bnp->rp_inpkt[i]))\
	{ bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_ATTRLIST, 0, NULL);\
	  goto done;\
	}\
      bit_set(parsedflag, bnp->rp_inpkt[i]);\
      i++;\
    }

#define PA4_LEN_PARSE \
    { if (bnp->rp_inpkt[k] & PA_FLAG_EXTLEN) {\
	atrdatalen = ntohs(*(u_int16_t *)&bnp->rp_inpkt[i]);\
	i += 2;\
      } else {\
	atrdatalen = bnp->rp_inpkt[i];\
	i += 1;\
      }\
      atrlen = i + atrdatalen - k;\
      if (i + atrdatalen > pa_p + tpalen) {\
	syslog(LOG_ERR, "<%s>: invalid attribute length(%d) from %s\n",\
		         __FUNCTION__, atrdatalen, bgp_peerstr(bnp));\
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,\
		   i - k, &bnp->rp_inpkt[k]);\
	goto done;\
      }\
    }

    k = i;
    switch(bnp->rp_inpkt[i + 1]) { 
    case  PA4_TYPE_ORIGIN:   
      /* ORIGIN (Type Code 1) well-known mandatory */   
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if ( (bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	  !(bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      if (atrdatalen != PA4_LEN_ORIGIN) {       /* Attribute Length Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      switch (bnp->rp_inpkt[i]) {
      case PATH_ORG_IGP: case PATH_ORG_EGP: case PATH_ORG_XX:
#ifdef DEBUG
	syslog(LOG_DEBUG, "BGP+ RECV\t\t%s", origin_str[bnp->rp_inpkt[i]]);
#endif
	origin = bnp->rp_inpkt[i++];
	break;
      default:
	/* If the ORIGIN attribute has an undefined value, then the Error
	   Subcode is set to Invalid Origin Attribute.  The Data field contains
	   the unrecognized attribute (type, length and value). */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_ORIGIN,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
	break;
      }
      break;



    case  PA4_TYPE_ASPATH:
      /* ASPATH (Type Code 2) well-known mandatory */   
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if ( (bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	  !(bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      /* construct AS_PATH */
      if ((asp = msg2aspath(bnp, i, atrdatalen, &error)) == NULL) {
	switch (error) {
	case EINVAL:
	  bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_ASPATH, 0, NULL);
	  goto done;
	default:   /* AS path loop detected. this msg is to be ignore. */
	  goto done;  /*  iw97                                            */
	}
      }
      i += atrdatalen;
      break;



    case PA4_TYPE_NEXTHOP:
      /* NEXT_HOP (Type Code 3) well-known mandatory */   
      /* check syntax only. */ 
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if ( (bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	  !(bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {       /* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS, atrlen,
		   &bnp->rp_inpkt[k]);
	goto done;
      }
      /* IPv4 specific */
      if (atrdatalen != PA_LEN_NEXTHOP) {         /* Attribute Length Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      i += sizeof(struct in_addr);
      break;


    case PA4_TYPE_METRIC:
      /* MULTI_EXIT_DISC (Type Code 4) optional non-transitive */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      /* optional non-transitive attributes the Partial bit must be
	 set to 0. */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	   (bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      if (atrdatalen != PA4_LEN_METRIC) {      /* Attribute Length Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
#ifdef DEBUG
      syslog(LOG_DEBUG, "BGP+ RECV\t\t%d",
	     ntohl(*(u_int32_t *)&bnp->rp_inpkt[i]));
#endif
      med = *(u_int32_t *)&bnp->rp_inpkt[i];     /* net-order */

      i += atrdatalen;
      break;


    case PA4_TYPE_LOCALPREF:
      /* LOCAL_PREF (Type Code 5) well-known mandatory      */
      /*  If it is received from an external peer,          */
      /* then this attribute MUST be ignored. [BGP4+ 5.1.5] */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      if (bnp->rp_mode & BGPO_IGP) {
	/* T */
	if ( (bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	    !(bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	     (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	  bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		     atrlen, &bnp->rp_inpkt[k]);
	  goto done;
	}
	if (atrdatalen != PA4_LEN_LOCALPREF) {  /* Attribute Length Error */
	  bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		     atrlen,&bnp->rp_inpkt[k]);
	  goto done;
	}
	/* V */
#ifdef DEBUG
	syslog(LOG_DEBUG, "BGP+ RECV\t\t%d",
	       ntohl(*(u_int32_t *)&bnp->rp_inpkt[i]));
#endif
	if (bnp->rp_mode & BGPO_IGP)
	  localpref = *(u_int32_t *)&bnp->rp_inpkt[i]; /* net-order */
      }
      i += atrdatalen;
      break;


    case PA4_TYPE_ATOMICAGG:
      /* ATOMIC_AGGREGATE (Type Code 6) well-known discretinary */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if ( (bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	  !(bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }

      if (atrdatalen != PA4_LEN_ATOMICAGG) {    /* Attribute Length Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      aggregated = PATH_FLAG_ATOMIC_AGG;
      i += PA4_LEN_ATOMICAGG; /* this has no data */
      break;


    case PA4_TYPE_AGGREGATOR:
      /* AGGREGATOR (Type Code 7) optional transitive            */
      /* this is used for debugging (furthermore, for IPv4 only) */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)    ||
	  !(bnp->rp_inpkt[k] & PA_FLAG_TRANS))    {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      if (atrdatalen != PA4_LEN_AGGREGATOR) {   /* Attribute Length Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      i += PA4_LEN_AGGREGATOR;  /* specific for IPv4, so ignored. */
      break;

#ifdef notyet
    case PA4_TYPE_COMMUNITY:
      /* COMMUNITY (Type Code 8) optional transitive       */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)    ||
	  !(bnp->rp_inpkt[k] & PA_FLAG_TRANS))    {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      if (atrdatalen != 0) {
	      if ((coml = msg2communitylist(bnp, i, atrdatalen)) == NULL)
		      goto done;
      }
      i += atrdatalen;
      break;
#endif /* notyet */

    case PA4_TYPE_ORIGINATOR:
      /* ORIGINATOR_ID (Type Code 9) optional non-transitive       */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      /* optional non-transitive attributes the Partial bit must be
	 set to 0. */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	   (bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      if (atrdatalen != PA4_LEN_ORIGINATOR) {   /* Attribute Length Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      /* This attribute is 4 bytes long and it will be created by a RR. 
	 [rfc1966] */
#ifdef DEBUG
      syslog(LOG_DEBUG, "BGP+ RECV\t\t%s", 
	     /*	     ntohl(*(u_int32_t *)&bnp->rp_inpkt[i])); */
	     inet_ntoa(*(struct in_addr *)&bnp->rp_inpkt[i]));
#endif
      if ( (bnp->rp_mode & BGPO_IGP) &&
	  !(bnp->rp_mode & BGPO_RRCLIENT))
	originatorid = *(u_int32_t *)&bnp->rp_inpkt[i];

      i += atrdatalen;
      break;

    case PA4_TYPE_CLUSTERLIST:
      /* CLUSTER_LIST (Type Code 10) optional non-transitive       */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      /* optional non-transitive attributes the Partial bit must be
	 set to 0. */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	   (bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* V */
      /* construct CLUSTER_LIST */
      /* If the local CLUSTER_ID is found in the cluster-list,
	 the advertisement will be ignored.        [rfc1966] */
      if (atrdatalen != 0             &&
	  (bnp->rp_mode & BGPO_IGP))  {
	if ((cll = msg2clstrlist(bnp, i, atrdatalen)) == NULL)
	  goto done;
      }
      i += atrdatalen;
      break;



    case PA4_TYPE_MPREACHNLRI:
      /* MP_REACH_NLRI (Type Code 14) optional non-transitive */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	   (bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }

      /* Address Family Identifier            (2 octets) */
      if (ntohs(*(u_int16_t *)&bnp->rp_inpkt[i]) != AFN_IP6) {
	syslog(LOG_NOTICE,
	       "<%s>: AFI is not AFN_IP6 (%d).", __FUNCTION__, AFN_IP6);
	i += atrdatalen;
	break;   /* Gently ignore :-) */
      }
      i += 2;

      /* SAFI */
      /* Subsequent Address Family Identifier (1 octet) */
      if (bnp->rp_inpkt[i++] != PA4_MP_UCAST) {      /* implmntd for UNIcast only */
	syslog(LOG_NOTICE,
	       "<%s>: SAFI isn't (%d). I only support unicast", __FUNCTION__,
	       PA4_MP_UCAST);
	i = k + atrlen;
	break;    /* Quietly ignore :-< */
      }
      /* Length of Next Hop Network Address   (1 octet) */
      nhnalen = bnp->rp_inpkt[i++];

      if (!((nhnalen == sizeof(struct in6_addr)) ||
	    (nhnalen == sizeof(struct in6_addr) * 2))) {
	syslog(LOG_NOTICE,
	       "<%s>: nexthop address length (%d) cannot accepted.",
	       __FUNCTION__, (int)nhnalen);
	i = k + atrlen;
	break; /* this attribute */
      }


      /* Network Address of Next Hop          (variable)  */
      gnhaddr = *(struct in6_addr *)&bnp->rp_inpkt[i]; /* (normally) */

#ifdef DEBUG
      syslog(LOG_DEBUG, "BGP+ RECV\t\tNextHop");
      syslog(LOG_DEBUG, "BGP+ RECV\t\t%s",
	     inet_ntop(AF_INET6, &gnhaddr, in6txt, INET6_ADDRSTRLEN));
#endif


      if (IN6_IS_ADDR_LINKLOCAL(&gnhaddr)) {                /* link-local */
	lnhaddr = gnhaddr;
	memset(&gnhaddr, 0, sizeof(gnhaddr));
#ifdef DEBUG
	if (!(IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_laddr)) &&
	    !(IN6_ARE_ADDR_EQUAL(&bnp->rp_laddr, &lnhaddr)))
	  syslog(LOG_DEBUG,
		 "<%s>: Third Party NextHop %s", __FUNCTION__,
		 inet_ntop(AF_INET6, &lnhaddr, in6txt, INET6_ADDRSTRLEN));

      } else {
	if (!(IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_gaddr)) &&   /* global */
	    !(IN6_ARE_ADDR_EQUAL(&bnp->rp_gaddr, &gnhaddr)))
	  syslog(LOG_DEBUG,
		 "<%s>: Third Party NextHop %s", __FUNCTION__,
		 inet_ntop(AF_INET6, &gnhaddr, in6txt, INET6_ADDRSTRLEN));
#endif
      }

      i += sizeof(struct in6_addr);


      /*    RFC 2283,2545  bellow  */
      if (nhnalen == sizeof(struct in6_addr) * 2) {
	if (IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)&bnp->rp_inpkt[i])) {
	  /*                              I prefer linklocal nexthop      */
	  lnhaddr = *(struct in6_addr *)&bnp->rp_inpkt[i];
#ifdef DEBUG
	  syslog(LOG_DEBUG, "BGP+ RECV\t\t%s",
		 inet_ntop(AF_INET6, &lnhaddr, in6txt, INET6_ADDRSTRLEN));

	  if (!(IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_laddr)) &&
	      !(IN6_ARE_ADDR_EQUAL(&bnp->rp_laddr, &lnhaddr)))
	    syslog(LOG_DEBUG,
		   "<%s>: Third Party NextHop %s", __FUNCTION__,
		   inet_ntop(AF_INET6, &lnhaddr, in6txt, INET6_ADDRSTRLEN));
#endif
	}
	i += sizeof(struct in6_addr);
      }


      /* Number of SNPAs (1 octet) */
      snpanum = bnp->rp_inpkt[i++];
      for (j = 0; j < snpanum; j++) {
	snpalen = bnp->rp_inpkt[i++];
	i += ((snpalen % 2) ? snpalen / 2 + 1 : snpalen / 2);
      }

#ifdef DRAFT_IETF_00
      /* Network Layer Reachability Information Length (2 Octets) */
      nlrilen = ntohs(*(u_short *)&bnp->rp_inpkt[i]);
      i += 2;
      if (i + nlrilen  !=  k + atrlen) {
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
#endif


      /***  NLRI (4+) ***/
#ifdef DEBUG
      syslog(LOG_DEBUG, "BGP+ RECV\t\tNLRI");
#endif
      while (i < k + atrlen) {      /* Malformation is detected ASAP */
	struct rt_entry *rte;       /* to be installed               */
	int              poctets;   /* (minimum len in octet bound)  */
	struct ifinfo   *ife;       /* search for                    */
	struct rt_entry *orte;      /* which I had                   */

	MALLOC(rte, struct rt_entry);

	orte = NULL;

	/*  Length (1 octet)  */
	if ((rte->rt_ripinfo.rip6_plen = bnp->rp_inpkt[i++]) > 128) {
	  syslog(LOG_NOTICE,
		 "<%s>: Bad prefix length (=%d) in NLRI", __FUNCTION__,
		 rte->rt_ripinfo.rip6_plen);
	  free(rte);
	  i = k + atrlen;
	  break;   /* ignore  rest of MP_REACH_NLRI */
	}

	poctets = POCTETS(rte->rt_ripinfo.rip6_plen);

	/*  Prefix (variable)  */
	memcpy( rte->rt_ripinfo.rip6_dest.s6_addr,
	       &bnp->rp_inpkt[i],
	       poctets);
	i += poctets;

#ifdef DEBUG
	syslog(LOG_DEBUG, "BGP+ RECV\t\t%s/%d",
	       inet_ntop(AF_INET6, &rte->rt_ripinfo.rip6_dest,
			 in6txt, INET6_ADDRSTRLEN),
	       rte->rt_ripinfo.rip6_plen);	       
#endif

	if (!IN6_IS_ADDR_ROUTABLE(&rte->rt_ripinfo.rip6_dest)) {
	  syslog(LOG_NOTICE,
		 "<%s>: Invalid prefix in NLRI (ignored)", __FUNCTION__);
	  free(rte);
	  continue;  /* to next rte */
	}


	
	if (rte->rt_ripinfo.rip6_plen == 128) {
	  ife = ifentry;
	  while(ife) {
	    /*  check global I/F addrs  */
	    if (IN6_ARE_ADDR_EQUAL(&rte->rt_ripinfo.rip6_dest,
				   &ife->ifi_gaddr)) {
	      ife = NULL;
	      break;
	    }
	    if ((ife = ife->ifi_next) == ifentry)
	      break;
	  }
	  if (ife == NULL) {
	    free(rte);
	    continue;  /* ignore */	
	  }
	}

	/* XXX */
	rte->rt_bgw = IN6_IS_ADDR_UNSPECIFIED(&lnhaddr) ? gnhaddr : lnhaddr;
	rte->rt_flags = RTF_UP|RTF_GATEWAY;
	if (rte->rt_ripinfo.rip6_plen == 128)
	  rte->rt_flags |= RTF_HOST;

	rte->rt_ripinfo.rip6_tag    = htons(aspath2tag(asp));
	rte->rt_ripinfo.rip6_metric = 0;   /* (ad-hoc) */
	rte->rt_proto.rtp_type      = RTPROTO_BGP;
	rte->rt_proto.rtp_bgp       = bnp; /* for each RTE, each RTP exists. */
	rte->rt_aspath = asp; /* AS path field will be filled in later */

	/*  check I/F routes  */
	ife = ifentry;
	while(ife) {
	  if ((orte = find_rte(rte, ife->ifi_rte)))
	    break;
	  if ((ife = ife->ifi_next) == ifentry)
	    break;
	}
	if (orte != NULL) {  /* I/F direct route (most preferable) */
#if 0
	  syslog(LOG_DEBUG,
		 "<%s>: I/F direct %s/%d not overwritten", __FUNCTION__,
		 inet_ntop(AF_INET6, &rte->rt_ripinfo.rip6_dest, in6txt,
			   INET6_ADDRSTRLEN),
		 rte->rt_ripinfo.rip6_plen);
#endif
	  free(rte);
	  continue;  /* to next rte */
	}

	/*  check aggregate routes  */
	if (find_rte(rte, aggregations)) {
#ifdef DEBUG
	  syslog(LOG_DEBUG,
		 "<%s>: aggregate route %s/%d cannot overwritten",
		 __FUNCTION__,
		 inet_ntop(AF_INET6, &rte->rt_ripinfo.rip6_dest, in6txt,
			   INET6_ADDRSTRLEN),
		 rte->rt_ripinfo.rip6_plen);
#endif
	  free(rte);
	  continue;  /* to next rte */
	}

	insque(rte, &uprtehead); /* Keep the RTE in the queue for later use */

      }  /* End of while (NLRI) */

      /* If an optional attribute is recognized, then the value of this
	 attribute is checked.  If an error is detected, the attribute is
	 discarded, and the Error Subcode is set to Optional Attribute Error.
	 The Data field contains the attribute (type, length and value). */

      if (i != k + atrlen) {
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_OPTATTR,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }

      break;



    case PA4_TYPE_MPUNREACHNLRI:
      /* MP_UNREACH_NLRI (Type Code 15) optional non-transitive */

      /* An UPDATE message that contains the MP_UNREACH_NLRI is not required
	 to carry any other path attributes.  */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)     ||
	   (bnp->rp_inpkt[k] & PA_FLAG_TRANS)   ||
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL))   {	/* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* Address Family Identifier            (2 octets) */
      if (ntohs(*(u_int16_t *)&bnp->rp_inpkt[i]) != AFN_IP6) {
	syslog(LOG_NOTICE,
	       "<%s>: AFI is not AFN_IP6(%d)", __FUNCTION__, AFN_IP6);
	i += atrdatalen;
	break;   /* Gently ignore :-) */
      }
      i += 2;

      /* SAFI */
      /* Subsequent Address Family Identifier (1 octet) */
      if (bnp->rp_inpkt[i++] != PA4_MP_UCAST) {      /* implmntd for UNIcast only */
	syslog(LOG_NOTICE,
	       "<%s>: SAFI isn't (%d). I only support unicast", __FUNCTION__,
	       PA4_MP_UCAST);
	i = k + atrlen;
	break;    /* Quietly ignore :-< */
      }

#ifdef DRAFT_IETF_00
      /* Unfeasible Routes Length (2 Octets) */
      nlrilen = ntohs(*(u_short *)&bnp->rp_inpkt[i]);
      i += 2;

      if (i + nlrilen  !=  k + atrlen) {
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_LENGTH,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
#endif

      /***  Withdrawn Routes  ( NLRI encoding )  ***/
      while (i < k + atrlen) {             /* Malform is detected ASAP */
	struct rt_entry *rte;
	int              poctets;   /* (minimum len in octet bound) */

	MALLOC(rte, struct rt_entry);

	/* Length in bits (1 octet) */
	if ((rte->rt_ripinfo.rip6_plen = bnp->rp_inpkt[i++]) > 128) {
	  syslog(LOG_NOTICE,
		 "<%s>: Bad prefix length (=%d) in NLRI", __FUNCTION__,
		 rte->rt_ripinfo.rip6_plen);
	  free(rte);
	  i = k + atrlen;
	  break;   /* ignore  rest of MP_UNREACH_NLRI */
	}

	poctets = POCTETS(rte->rt_ripinfo.rip6_plen);

	/* Dest. */
	memcpy(rte->rt_ripinfo.rip6_dest.s6_addr, &bnp->rp_inpkt[i], poctets);
	i += poctets;

#ifdef DEBUG
	syslog(LOG_DEBUG, "BGP+ RECV\t\t%s/%d",
	       inet_ntop(AF_INET6, &rte->rt_ripinfo.rip6_dest.s6_addr,
			 in6txt, INET6_ADDRSTRLEN),
	       rte->rt_ripinfo.rip6_plen);
#endif

	rte->rt_proto.rtp_type      = RTPROTO_BGP;
	rte->rt_proto.rtp_bgp       = bnp; /* for each RTE, each RTP exists. */
	rte->rt_aspath = asp; /* AS path field will be filled in later */

	insque(rte, &wdrtehead);/* Keep the RTE in the queue for later use */

      }  /* End of while(NLRI) */

      break;


    default:
      /* XXX: PA propagation not fully implemented. */
      PA4_TYPE_CODE_CHECK;
      PA4_LEN_PARSE;
      /* T */
      /* If any of the mandatory well-known attributes are not recognized,
	 then the Error Subcode is set to Unrecognized Well-known Attribute.
	 The Data field contains the unrecognized attribute (type, length and
	 value). */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_OPT)) {
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_UNKNOWN,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      
      /*
       * Optional transitive attributes should be passed to other peers
       * transparently.
       */
      if ((bnp->rp_inpkt[k] & PA_FLAG_OPT) &&
	  (bnp->rp_inpkt[k] & PA_FLAG_TRANS)) {
#ifdef DEBUG_BGP
	syslog(LOG_DEBUG,
	       "<%s>: BGP+ RECV\t\tUnrecognized Attribute: type=%d,len=%d",
	       __FUNCTION__, bnp->rp_inpkt[k + 1], atrdatalen);
#endif 
	optatr = add_optatr(optatr, &bnp->rp_inpkt[k], atrlen);
      }

      /* optional non-transitive attributes the Partial bit must be
	 set to 0. */
      if (!(bnp->rp_inpkt[k] & PA_FLAG_TRANS)  &&
	   (bnp->rp_inpkt[k] & PA_FLAG_PARTIAL)) {   /* Attribute Flags Error */
	bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_FLAGS,
		   atrlen, &bnp->rp_inpkt[k]);
	goto done;
      }
      /* Unrecognized non-transitive optional attributes must be quietly
	 ignored and not passed along to other BGP peers. [Page20]       */
      /* V */
      i += atrdatalen;      /* quietry ignore */
      break;

    }  /* <--  End of Switch path-attrs. */
  }

  if (pa_p + tpalen != i) {      /* Malformed Attribute List */
    bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_ATTRLIST, 0, NULL);
    goto done;
  }

  /* In IPv4 BGP4, here appears "traditional NLRI", 
      which can be quietry ignored in BGP4+ (for IPv6) */
  if ((v4nlrilen = length - i ) > 0)
    syslog(LOG_NOTICE,
	   "<bgp_process_update>: traditional NLRI appread (ignore)");

  { byte missin_attr = 0;
    /* If any of the mandatory well-known attributes are not present, then
       the Error Subcode is set to Missing Well-Known Attribute. The Data
       field contains the Attribute Type Code of the missing well-known
       attribute. */
    if (!(bit_test(parsedflag, PA4_TYPE_ORIGIN)))
      missin_attr = PA4_TYPE_ORIGIN;

    if (!(bit_test(parsedflag, PA4_TYPE_ASPATH)))
      missin_attr = PA4_TYPE_ASPATH;

    if (!(bit_test(parsedflag, PA4_TYPE_MPREACHNLRI)) &&     /* bgp4+ */
	!(bit_test(parsedflag, PA4_TYPE_NEXTHOP)))
      missin_attr = PA4_TYPE_NEXTHOP;

    if ((bnp->rp_mode & BGPO_IGP) &&
	!(bit_test(parsedflag, PA4_TYPE_LOCALPREF)))
      missin_attr = PA4_TYPE_LOCALPREF;


    /* An UPDATE message that contains the MP_UNREACH_NLRI is not required
       to carry any other path attributes. */
    if (missin_attr &&
	(v4nlrilen > 0 || !bit_test(parsedflag, PA4_TYPE_MPUNREACHNLRI))) {
      bgp_notify(bnp, BGP_ERR_UPDATE, BGP_ERRUPD_MISSING, 1, &missin_attr);
      goto done;
    }
  }  /* missin_atr */

  /*
   * At this point, the received message is confirmed to be valid.
   * Now install or redistribute routes according to the message.
   */

  if (asp) {
    asp->asp_origin    = origin;
    /* anyway, anymay:  */
    asp->asp_nexthop   = IN6_IS_ADDR_UNSPECIFIED(&lnhaddr) ? gnhaddr : lnhaddr;
    asp->asp_med       = med;            /* net  order      */
    asp->asp_localpref = localpref;      /* net  order      */
    asp->asp_atomagg   = aggregated;
    asp->asp_origid    = originatorid;   /* net  order      */
    asp->asp_clstr     = cll;
    asp->asp_optatr    = optatr;
  }

  /***                     ***/
  /***   Route Selection   ***/
  /***                     ***/	/* XXX: protocol preference ?? */
  for (uprte = uprtehead.rt_next; uprte != &uprtehead;
       uprte = uprte->rt_next) {
	  struct rt_entry *nrte = NULL;

	  if (bgp_selectroute(uprte, bnp))
		  goto done;

	  if (bgp_enable_rte(uprte) == 0) {
#ifdef DEBUG_BGP
		  syslog(LOG_NOTICE,
			 "<%s>: MP_REACH_NLRI %s/%d: from %s, not enabled",
			 __FUNCTION__,
			 ip6str(&uprte->rt_ripinfo.rip6_dest, 0),
			 uprte->rt_ripinfo.rip6_plen,
			 bgp_peerstr(bnp));
#endif
		  nrte = uprte->rt_prev; /* XXX */
		  remque(uprte);
		  free(uprte);
		  uprte = nrte;
		  continue;
	  } else {   /* (1998/06/30) */
		  /* Copy enable route into adj-ribs-in list */
		  struct rt_entry *irte;

#ifdef DEBUG_BGP
		  syslog(LOG_NOTICE,
			 "<%s>: MP_REACH_NLRI %s/%d: from %s, enabled(%s)",
			 __FUNCTION__,
			 ip6str(&uprte->rt_ripinfo.rip6_dest, 0),
			 uprte->rt_ripinfo.rip6_plen,
			 bgp_peerstr(bnp),
			 (uprte->rt_flags & RTF_UP) ? "installed" : "backup");
#endif 

		  MALLOC(irte, struct rt_entry);
		  memcpy(irte, uprte, sizeof(struct rt_entry));
		  irte->rt_aspath = aspathcpy(uprte->rt_aspath);
		  if (bnp->rp_adj_ribs_in) {
			  insque(irte, bnp->rp_adj_ribs_in);
		  } else {
			  irte->rt_next = irte->rt_prev = irte;
			  bnp->rp_adj_ribs_in = irte;
		  };
	  }

	  /* a BGP speaker advertise to its peers (other BGP speakers which it
	     communicates with) in neighboring ASs only those routes that it
	     itself uses [BGP4, Page2] */
	  if ((bnp->rp_mode  & BGPO_IGP && uprte->rt_flags & RTF_UP &&
	       ((uprte->rt_flags & RTF_IGP_EGP_SYNC) ||
		(bnp->rp_mode & BGPO_NOSYNC)))
	      ||
	      (!(bnp->rp_mode  & BGPO_IGP) && uprte->rt_flags & RTF_UP))
		  continue;	/* to next RTE */
	  else {
		  nrte = uprte->rt_prev; /* XXX */
		  remque(uprte);
		  free(uprte);
		  uprte = nrte;
	  }
  }

  /*
   * withdraw route
   */
  for (wdrte = wdrtehead.rt_next; wdrte != &wdrtehead;
       wdrte = wdrte->rt_next) {
	  struct rt_entry *drte;

	  if ((drte = find_rte(wdrte, bnp->rp_adj_ribs_in))) {
		  if (drte->rt_flags & RTF_UP) {
			  struct rt_entry rte;
#ifdef DEBUG_BGP
			  syslog(LOG_NOTICE,
				 "<%s>: MP_UNREACH_NLRI %s/%d: from %s (deleted)",
				 __FUNCTION__,
				 ip6str(&wdrte->rt_ripinfo.rip6_dest, 0),
				 wdrte->rt_ripinfo.rip6_plen,
				 bgp_peerstr(bnp));
#endif 
			  bgp_disable_rte(drte);

			  /* (also copy "back-pointer" ASpath pointer) */
			  memcpy(&rte, wdrte, sizeof(struct rt_entry));
			  rte.rt_next   = &rte;
			  rte.rt_prev   = &rte;

			  propagate(&rte);
			  if (!bgp_rpcb_isvalid(bnp)) {
				  syslog(LOG_NOTICE,
					 "<%s>: rpcb %p was invalidated during "
					 "a propagation",
					 __FUNCTION__, bnp);
				  goto done;
			  }

			  /* remove and free from the imported list */
			  bnp->rp_adj_ribs_in 
				  = rte_remove(drte, bnp->rp_adj_ribs_in);

			  /* try to recovery from backup routes */
			  bgp_recover_rte(&rte);
			  if (!bgp_rpcb_isvalid(bnp)) {
				  syslog(LOG_NOTICE,
					 "<%s>: rpcb %p was invalidated during "
					 "a route-recovery",
					 __FUNCTION__, bnp);
				  goto done;
			  }
		  }
		  else {
			  /*
			   * when a backup route is withdrawn,
			   * no update msg is advertized. just delete the entry.
			   */
#ifdef DEBUG_BGP
			  syslog(LOG_NOTICE,
				 "<%s>: MP_UNREACH_NLRI %s/%d: from %s (~UP)",
				 __FUNCTION__,
				 ip6str(&wdrte->rt_ripinfo.rip6_dest, 0),
				 wdrte->rt_ripinfo.rip6_plen,
				 bgp_peerstr(bnp));

#endif 
			  bnp->rp_adj_ribs_in 
				  = rte_remove(drte, bnp->rp_adj_ribs_in);
		  }
	  } else { /* RTE not found */
		  syslog(LOG_NOTICE,
			 "<%s>: MP_UNREACH_NLRI %s/%d: %s not origin (ignored): ",
			 __FUNCTION__,
			 ip6str(&wdrte->rt_ripinfo.rip6_dest, 0),
			 wdrte->rt_ripinfo.rip6_plen,
			 bgp_peerstr(bnp));
	  }
  }

  if (uprtehead.rt_next != &uprtehead) {
	  struct rt_entry *head = uprtehead.rt_next;
	  remque(&uprtehead); 	/* XXX: uprtehead would annoy redistribute() */
	  redistribute(head);
	  insque(&uprtehead, head); /* XXX: restore link */
	  if (!bgp_rpcb_isvalid(bnp)) {
		  syslog(LOG_NOTICE,
			 "<%s>: rpcb %p was invalidated during a redistribution",
			 __FUNCTION__, bnp);
		  goto done;
	  }
  } /* uprtehead */

  task_timer_update(bnp->rp_hold_timer);

  done:
    if (asp)
	    free_aspath(asp);
    {
	    struct rt_entry *drte;

	    for (drte = uprtehead.rt_next; drte != &uprtehead;) {
		    struct rt_entry *nrte = drte->rt_next;
		    remque(drte);
		    free(drte);	/* aspath has been already freed. */
		    drte = nrte;
	    }

	    for (drte = wdrtehead.rt_next; drte != &wdrtehead;) {
		    struct rt_entry *nrte = drte->rt_next;
		    remque(drte);
		    free(drte);	/* ditto. */
		    drte = nrte;
	    }
    }
  /* End of bgp_process_update() */
}

static int
bgp_selectroute(rte, bnp)
	struct rt_entry *rte;
	struct rpcb *bnp;
{
	struct rpcb     *obnp;      /* search for */
	struct rt_entry *orte;
	extern struct ripif    *ripifs;
	extern byte             ripyes; 

	/*
	 * At first, check our own routes since possible propagation
	 * might destory bnp...Ugh!
	 */
	if ((orte = find_rte(rte, bnp->rp_adj_ribs_in))) {
		struct rt_entry crte; /* local copy */
		/*
		 * i) If its Network Layer Reachability Information (NLRI)
		 * is identical to the one of a route currently stored
		 * in the Adj-RIB-In, then the new route shall replace the
		 * older route in the Adj-RIB-In, thus implicitly withdrawing
		 * the older route from service. The BGP speaker shall run
		 * its Decision Process since the older route is no longer
		 * available for use.
		 * [BGP4+   9. UPDATE Message Handling]
		 */
		if (orte->rt_flags & RTF_UP) {
#ifdef DEBUG_BGP
			syslog(LOG_NOTICE,
			       "<%s>: %s/%d from %s was overwritten",
			       __FUNCTION__,
			       ip6str(&orte->rt_ripinfo.rip6_dest, 0),
			       orte->rt_ripinfo.rip6_plen,
			       bgp_peerstr(bnp));
#endif 
			crte = *orte;
			crte.rt_next = crte.rt_prev = &crte;
			bgp_disable_rte(&crte);

			propagate(&crte);
			/* XXX: propagate might invalidate bnp */
			if (!bgp_rpcb_isvalid(bnp)) {
				syslog(LOG_NOTICE,
				       "<%s>: rpcb %p was invalidated during a "
				       "propagation", __FUNCTION__, bnp);
				return(-1);
			}
		}
		bnp->rp_adj_ribs_in = rte_remove(orte,
						 bnp->rp_adj_ribs_in);
	}

	obnp = bgb;
	while(obnp) {
		if (bnp != obnp && /* already done above */
		    (orte = find_rte(rte, obnp->rp_adj_ribs_in))) {
			/* same NLRI */
			/*
			 * Route Selection
			 * take care of route flapping !!
			 * comparison technique
			 * (like RIPng metric) (1998/05/13)
			 */
			if (orte->rt_flags & RTF_UP) {
				if (bgp_preferred_rte(rte, orte))
					/* a new RTE may prefer */
					bgp_disable_rte(orte);
				else {
					/*
					 * Don't activate Kernel table
					 */
					rte->rt_flags &= ~RTF_UP;
#ifdef DEBUG
					syslog(LOG_DEBUG,
					       "<%s>: to be backup.",
					       __FUNCTION__);
#endif
				}
			}
		}
		if ((obnp = obnp->rp_next) == bgb) 
			break;
	} /* End of while(obnp) */

	/**  check RIPng routes  **/
	if (ripyes) {
		struct ripif *oripif;

		oripif = ripifs;
		while(oripif) {
			/* iw97 */
			if ((orte = find_rte(rte, oripif->rip_adj_ribs_in)) &&
			    (orte->rt_flags & RTF_UP)) {
				/* fuckin' reversing BGP speker */

				/* route synchronization(1998/06/20) */
				if (orte->rt_ripinfo.rip6_tag == 0) {
					/* purely internal */
					/*
					 * Don't activate Kernel table
					 */
					rte->rt_flags &= ~RTF_UP;
					break; /* while(oripif) */
				}

				if (bnp->rp_mode & BGPO_IGP){
					/* IBGP */

					if (rte->rt_ripinfo.rip6_tag ==
					    orte->rt_ripinfo.rip6_tag){
						struct rt_entry *nrte;

						/*
						 * If "rte" is backup, don't
						 * install even if "rte"
						 * becomes syncronized
						 */
#ifdef DEBUG
						syslog(LOG_DEBUG, "<%s>: now synchronized.", __FUNCTION__);
#endif		  
						nrte = rip_disable_rte(orte);
						free(nrte);
						rte->rt_flags |=
							RTF_IGP_EGP_SYNC;
						orte->rt_flags |=
							RTF_IGP_EGP_SYNC;
					} else {  /* tag differ */
						if (orte->rt_flags & RTF_IGP_EGP_SYNC &&
						    rte->rt_flags & RTF_UP) {
#ifdef DEBUG
							syslog(LOG_DEBUG, "<%s>: a new iBGP RTE prefered.",
							       __FUNCTION__);
#endif
							rip_erase_rte(orte);
						}
					}
				} else {    /* eBGP */

					if (rte->rt_ripinfo.rip6_tag ==
					    orte->rt_ripinfo.rip6_tag) {
#ifdef DEBUG
						syslog(LOG_DEBUG, "<%s>: fear.", __FUNCTION__);
#endif
						rip_erase_rte(orte);
					} else {  /* tag differ */
						if (orte->rt_flags & RTF_IGP_EGP_SYNC &&
						    rte->rt_flags & RTF_UP) {
							syslog(LOG_NOTICE, "<%s>: a new eBGP RTE prefered.",
							       __FUNCTION__);
							rip_erase_rte(orte);
						} else {
#ifdef DEBUG
							syslog(LOG_DEBUG, "<%s>: to be Backup.", __FUNCTION__);
#endif		  
							rte->rt_flags &= ~RTF_UP;
						}
					}
				} /* End of eBGP */ 
			}
			/* still I may get poison-reverse via RIP */

			if ((oripif = oripif->rip_next) == ripifs)
				break;
		}  /* while(oripif) */
	} /* (ripyes) */

	return(0);		/* sucess */
}


/*
 *    bgp_process_notification()
 *       process received KEEPALIVE msg.
 */
void
bgp_process_notification (struct rpcb *bnp) {
  char         in6txt[INET6_ADDRSTRLEN];
  struct bgphdr *bh = (struct bgphdr *)bnp->rp_inpkt;

  extern char *bgp_errstr[];
  extern char *bgp_hdrerrstr[];
  extern char *bgp_opnerrstr[];
  extern char *bgp_upderrstr[];

  memset(in6txt, 0, INET6_ADDRSTRLEN);

  syslog(LOG_NOTICE,
	 "NOTIFICATION received from %s (%s AS %d): code %d (%s) data %s",
	 inet_ntop(AF_INET6, &bnp->rp_addr.sin6_addr,
		   in6txt, INET6_ADDRSTRLEN),
	 ((bnp->rp_mode & BGPO_IGP) ? "Internal" : "External"),
	 (int)bnp->rp_as,
	 (int)bnp->rp_inpkt[BGP_HEADER_LEN],   /* code */
	 bgp_errstr[(int)bnp->rp_inpkt[BGP_HEADER_LEN]],
	 bgp_errdatastr(&bnp->rp_inpkt[BGP_HEADER_LEN + 2],
			ntohs(bh->bh_length) - (BGP_HEADER_LEN + 2)));

  switch ((int)bnp->rp_inpkt[BGP_HEADER_LEN]) { /* code */
  case BGP_ERR_HEADER:
    if ((int)bnp->rp_inpkt[BGP_HEADER_LEN+1] <= BGP_ERRHDR_TYPE)
      syslog(LOG_NOTICE, "\t subcode (%d) %s",
	     (int)bnp->rp_inpkt[BGP_HEADER_LEN+1],
	     bgp_hdrerrstr[(int)bnp->rp_inpkt[BGP_HEADER_LEN+1]]);
    break;
  case BGP_ERR_OPEN:
    if ((int)bnp->rp_inpkt[BGP_HEADER_LEN+1] <= BGP_ERROPN_BADHOLDTIME)
      syslog(LOG_NOTICE, "\t subcode (%d) %s",
	     (int)bnp->rp_inpkt[BGP_HEADER_LEN+1],
	     bgp_opnerrstr[(int)bnp->rp_inpkt[BGP_HEADER_LEN+1]]);
    break;
  case BGP_ERR_UPDATE:
    if ((int)bnp->rp_inpkt[BGP_HEADER_LEN+1] <= BGP_ERRUPD_ASPATH)
      syslog(LOG_NOTICE, "\t subcode (%d) %s",
	     (int)bnp->rp_inpkt[BGP_HEADER_LEN+1],
	     bgp_upderrstr[(int)bnp->rp_inpkt[BGP_HEADER_LEN+1]]);
    break;
  default:
    break;
  }

  /* Update Hold Timer. XXX: connection will soon be released */
  if (bnp->rp_state == BGPSTATE_ESTABLISHED)
	  task_timer_update(bnp->rp_hold_timer);

  bgp_cease(bnp);

  /* no means of reporting error in NOTIFICATION msg */
}



/*
 *    bgp_process_keepalive()
 *       process received KEEPALIVE msg.
 */
void
bgp_process_keepalive (struct rpcb *bnp) {
  int                    i;               /*  tracer       */
  struct bgphdr          *bh;
  struct rt_entry        *rtehead, *rte;  /*  advertising  */

  rtehead = rte = NULL;

  bh = (struct bgphdr *)bnp->rp_inpkt;

  if (( bnp->rp_mode & BGPO_PASSIVE) && 
      !(bnp->rp_ife))
#ifdef ADVANCEDAPI
    {
      struct cmsghdr     *cmsgp;        /* Adv. API */
      struct in6_pktinfo *pktinfo;      /* Adv. API */
      int                 off, optlen;  /* Adv. API */
      struct in6_addr     llhackaddr;

      if ((cmsgp =
	   (struct cmsghdr *)malloc(CMSG_SPACE(sizeof(struct in6_pktinfo))))
	  == 0)
	fatalx("<bgp_process_keepalive>: malloc");

      memset(cmsgp, 0, CMSG_SPACE(sizeof(struct in6_pktinfo)));
      cmsgp->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
      cmsgp->cmsg_level = IPPROTO_IPV6;
      cmsgp->cmsg_type  = IPV6_PKTINFO;
      pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgp);
      optlen  = CMSG_SPACE(sizeof(struct in6_pktinfo));

      if (getsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTOPTIONS,
		     (void *)cmsgp, &optlen) == 0) {
	if ((bnp->rp_ife = find_if_by_index(pktinfo->ipi6_ifindex)) == NULL)
	  fatalx("<bgp_process_keepalive>: find_if_by_index: Unknown I/F");
      } else {
	dperror("<bgp_process_keepalive>: getsockopt: IPV6_PKTOPTIONS");
	if ((bnp->rp_ife = find_if_by_addr(&bnp->rp_myaddr.sin6_addr)) == NULL)
	  fatalx("<bgp_process_open>: find_if_by_addr");
      }

      off = 0;
      if (setsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTINFO,  /* off */
		     &off, sizeof(off)) < 0)
	fatal("<bgp_process_keepalive>: setsockopt: IPV6_PKTINFO");
      free(cmsgp);
      llhackaddr = bnp->rp_addr.sin6_addr;
      if (IN6_IS_ADDR_LINKLOCAL(&llhackaddr))
	SET_IN6_LINKLOCAL_IFINDEX(&llhackaddr,
				  bnp->rp_ife->ifi_ifn->if_index);
      if (find_apeer_by_addr(&llhackaddr) == NULL) {
	bgp_notify(bnp, BGP_CEASE, BGP_ERR_UNSPEC, 0, NULL);
	return;
      }
    }
#else  /* !ADVANCEDAPI */
    {
	if ((bnp->rp_ife = find_if_by_addr(&bnp->rp_myaddr.sin6_addr)) == NULL)
	    fatalx("<bgp_process_keepalive>: find_if_by_addr Unknown I/F");
    }  
#endif /* ADVANCEDAPI */

  BGP_MARKER_CHECK;

  switch (bnp->rp_state) {

  case BGPSTATE_OPENCONFIRM:
    bnp->rp_state = BGPSTATE_ESTABLISHED;
    bgp_dump(bnp);
    if (bnp && bnp->rp_hold_timer)
      task_timer_update(bnp->rp_hold_timer);
    break;
  case BGPSTATE_ESTABLISHED:
    task_timer_update(bnp->rp_hold_timer);
    break;

  default:
    bgp_notify(bnp, BGP_ERR_FSM, BGP_ERR_UNSPEC, 0, NULL);
    break;
  };
}


/*
 *    collision_resolv()
 */
struct rpcb *
collision_resolv(newconn, oldconn)
     struct rpcb *newconn;
     struct rpcb *oldconn;
{

#ifdef DEBUG
  syslog(LOG_DEBUG, "<collision_resolv>: invoked.");
#endif

  if (newconn->rp_id > bgpIdentifier) {

    bgp_notify(oldconn, BGP_CEASE, BGP_ERR_UNSPEC, 0, NULL); /* use newconn */
    return newconn;

  } else {

    bgp_notify(newconn, BGP_CEASE, BGP_ERR_UNSPEC, 0, NULL); /* use oldconn */ 
    return oldconn;  
  } 

#ifdef DEBUG
  syslog(LOG_DEBUG, "<collision_resolv>: end.");
#endif


}




/*
 *  bgp_holdtimer_expired()
 */
void
bgp_holdtimer_expired(task *t)
{
#ifdef DEBUG
  char in6txt[INET6_ADDRSTRLEN];

  syslog(LOG_DEBUG,
	 "<%s>: holdtime expired for %s (%s AS %d)",
	 __FUNCTION__,
	 inet_ntop(AF_INET6, &t->tsk_bgp->rp_addr.sin6_addr,
		   in6txt, INET6_ADDRSTRLEN),
	 ((t->tsk_bgp->rp_mode & BGPO_IGP) ? "Internal" : "External"),
	 (int)t->tsk_bgp->rp_as);
#endif

  bgp_notify(t->tsk_bgp, BGP_ERR_HOLDTIME, BGP_ERR_UNSPEC, 0, NULL);
}


/*
 *   bgp_notify()
 */
void
bgp_notify(struct rpcb *bnp, byte errcode, byte subcode, int len, byte *data)
{
  bgp_send_notification(bnp, errcode, subcode, len, data);
  bgp_cease(bnp);
}




/*
 *   bgp_cease()
 */
void
bgp_cease(struct rpcb *bnp)
{
  struct rpcb     *abnp = NULL;                 /* another entry */

  if (bnp == NULL)
    return;

  bgp_flush(bnp);

#if 0
  /* XXX: ad-hoc solution */
  abnp = bgb;
  while(abnp) {
    if (abnp != bnp &&
	abnp->rp_state == BGPSTATE_ESTABLISHED)
      bgp_dump(abnp);
    if ((abnp = abnp->rp_next) == bgb)
      break;
  }
#endif

  /***  PASSIVEly opened Entry ***/
  if (bnp->rp_mode & BGPO_PASSIVE) {   

    /*  Remove the Entry from global-list */

    if (bgb->rp_next != bgb) { /* check solo ? */
      if (bgb == bnp)
	bgb = bgb->rp_next;
      remque(bnp);

    } else {   /* solo */
      /* active entry should exist. */	    
      fatalx("bgp_cease: no active entry(BUG !!)"); 
    }

    /*
     * If there is an RPCB whose state is IDLE for the peer and
     * there is no active other peer, retry connecting to it
     * (after waiting for ConnectRetryTimer).
     * It must not be an already opened passive connection(should we check it?)
     */
    if (!find_active_peer(bnp) && (abnp = find_idle_peer(bnp)))
	    bgp_connect_start(abnp);

    free(bnp); /* (1998/06/26) */
  } else {
	  /***  ACTIVEly opened entry  ***/
	  bnp->rp_incc = 0;
	  bnp->rp_inputmode = BGP_READ_HEADER;

	  /*
	   * Reset router ID unless it had been manually configured
	   * (and note that it is allowed only for an IBGP peer).
	   */
	  if (!(bnp->rp_mode & BGPO_IGP) ||
	      !(bnp->rp_mode & BGPO_IDSTATIC)) {
		  bnp->rp_id = 0;
	  }

	  /*
	   * If there is no active other peer, retry connecting to it
	   * (after waiting for ConnectRetryTimer).
	   * BNP itself must not be found by find_active_peer()
	   * since its state is reset to IDLE in bgp_flush() above.
	   */
	  if (!find_active_peer(bnp))
		  bgp_connect_start(bnp);
  }

  /* End of bgp_cease() */
}


void
bgp_flush(struct rpcb *bnp)
{
  extern task   *taskhead;
  extern fd_set  fdmask;

  bnp->rp_state = BGPSTATE_IDLE;       /* (1998/7/15) */

  close(bnp->rp_socket);

  if (bnp->rp_socket != -1) {
    FD_CLR(bnp->rp_socket, &fdmask);   /*  (global)  */ /* no more use */
    bnp->rp_socket = -1;  
  }

  /* tasks */
  if (bnp->rp_connect_timer) {
    taskhead = task_remove(bnp->rp_connect_timer);
    bnp->rp_connect_timer   = NULL;
  }
  if (bnp->rp_hold_timer) {
    taskhead = task_remove(bnp->rp_hold_timer);
    bnp->rp_hold_timer      = NULL;
  }

  if (bnp->rp_keepalive_timer) {
    taskhead = task_remove(bnp->rp_keepalive_timer);
    bnp->rp_keepalive_timer = NULL;
  }

  while ( bnp->rp_adj_ribs_in ) {
    struct rt_entry crte;

    crte = *bnp->rp_adj_ribs_in;
    crte.rt_next = crte.rt_prev = &crte;
    crte.rt_ripinfo.rip6_metric = RIPNG_METRIC_UNREACHABLE;

    if (bnp->rp_adj_ribs_in->rt_flags & RTF_UP) {
	    /* If it is actually used, withdraw it by routing protocols */
	    bgp_disable_rte(bnp->rp_adj_ribs_in);
	    propagate(&crte);

	    bgp_recover_rte(&crte);
    }

    bnp->rp_adj_ribs_in 
      = rte_remove(bnp->rp_adj_ribs_in, bnp->rp_adj_ribs_in );
  }
  /* End of bgp_flush() */
}
