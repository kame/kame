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

int                  ripsock;              /* socket for RIPng UDP      */
int                  rip_use_sitelocal = 0;/* if we handle site-local addrs */
byte                 ripbuf[RIPNG_BUFSIZ];
byte                 rippkt[RIPNG_MAXPKT]; /* should discover path MTU  */
struct ripif        *ripifs; 
struct sockaddr_in6  ripsin;               /* ff02::9.RIPNG_PORT        */


/*
 * RIP message types
 */
char *rip_msgstr[] = {
  "",
  "Request",
  "Response"};


/*
 *   rip_init()
 */
void 
rip_init()
{
  struct ripif      *ripif;
#ifndef ADVANCEDAPI
  int hops;
#endif
  struct ifinfo     *ife;
  struct timeb      *ttt;              /* random seed   */

  extern struct ifinfo *ifentry;

  ripifs = NULL;

  /* random seed */
  MALLOC(ttt, struct timeb);
  ftime(ttt);
  srandom(ttt->millitm);

  ife = ifentry;
  while (ife) {   /*  for each available I/F  */
	  if (ife->ifi_flags & IFF_UP &&
	      ife->ifi_flags & IFF_MULTICAST) /* XXX */
	  {
		  MALLOC(ripif, struct ripif);
		  ripif->rip_ife   = ife;

		  /* (1998/05/21) */
		  if (IN6_IS_ADDR_UNSPECIFIED(&ife->ifi_laddr)) {
			  ripif->rip_mode |= IFS_NORIPIN;
			  ripif->rip_mode |= IFS_NORIPOUT;
		  }

		  if (ripifs) 
			  insque(ripif, ripifs);
		  else {
			  ripif->rip_next = ripif->rip_prev = ripif;
			  ripifs = ripif;
		  }
	  }

	  if ((ife = ife->ifi_next) == ifentry)
		  break;
  }

  /* End of rip_init() */
}

void
rip_sockinit()
{
  task              *tsk;
  struct ripif      *ripif;
  struct ipv6_mreq   mreq;
  int on;
  extern task          *taskhead;
  extern fd_set         fdmask;

  /* for RIPng */
  if ((ripsock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    fatal("<rip_init>: socket");

  memset(&ripsin,   0, sizeof(ripsin));  /* sockaddr_in6  */
  memset(&mreq,     0, sizeof(mreq));

  ripsin.sin6_len      = sizeof(struct sockaddr_in6);
  ripsin.sin6_family   = AF_INET6;
  ripsin.sin6_port     = htons(RIPNG_PORT);
  ripsin.sin6_flowinfo = 0;
  if (inet_pton(AF_INET6, RIPNG_DEST, (void *)&ripsin.sin6_addr) != 1)
    fatal("<rip_init>: inet_pton");
  mreq.ipv6mr_multiaddr = ripsin.sin6_addr;

  if (bind(ripsock, (struct sockaddr *)&ripsin, sizeof(ripsin)) < 0)
    fatal("<rip_init>: bind");

  for (ripif = ripifs; ripif; ) { /* XXX: odd loop */
    if ((ripif->rip_mode & IFS_NORIPIN) != 0)
      goto nextif;

    mreq.ipv6mr_interface = ripif->rip_ife->ifi_ifn->if_index;
    if (setsockopt(ripsock, IPPROTO_IPV6,
		   IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
	    fatal("<rip_init>: setsockopt: IPV6_JOIN_GROUP");

  nextif:
    if ((ripif = ripif->rip_next) == ripifs)
	    break;
  }

#ifndef ADVANCEDAPI
  hops = RIPNG_HOPLIMIT;
  if (setsockopt(ripsock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		 &hops, sizeof(int)) < 0)
    fatal("<rip_init>: setsockopt IPV6_MULTICAST_HOPS");
#endif /* ADVANCEDAPI */

  on = 0;
  if (setsockopt(ripsock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		 &on, sizeof(on)) < 0)
    fatal("<rip_init>: setsockopt IPV6_MULTICAST_LOOP");

#ifdef ADVANCEDAPI
  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(ripsock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<rip_init>: setsockopt(IPV6_RECVPKTINFO)");
#else  /* old adv. API */
  if (setsockopt(ripsock, IPPROTO_IPV6, IPV6_PKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<rip_init>: setsockopt(IPV6_PKTINFO)");
#endif 
  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(ripsock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<rip_init>: setsockopt(IPV6_RECVPKTINFO)");
#else  /* old adv. API */
  if (setsockopt(ripsock, IPPROTO_IPV6, IPV6_PKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<rip_init>: setsockopt(IPV6_PKTINFO)");
#endif 
#endif /* ADVANCEDAPI */

  FD_SET(ripsock,  &fdmask);

  MALLOC(tsk, task);

  if (taskhead) {
    insque(tsk, taskhead);
  } else {
    taskhead      = tsk;
    tsk->tsk_next = tsk;
    tsk->tsk_prev = tsk;
  }
  tsk->tsk_timename         = RIP_DUMP_TIMER;
  tsk->tsk_rip              = NULL;
  tsk->tsk_timefull.tv_sec  = 1; /* immediately */ 
  tsk->tsk_timefull.tv_usec = 0;


  task_timer_update(tsk);
}

/*
 * rip_inport_init: initilize Adj_Ribs_Out for RIPng
 */
void
rip_import_init()
{
  struct ripif      *ripif = ripifs;
  extern byte           bgpyes;
  extern struct ifinfo *ifentry;
  extern struct rpcb   *bgb;

  while (ripif) {

    struct ripif  *outripif;
    struct ifinfo *outife;
    struct rpcb   *outbnp;

    /*    Include ripif itself, for "specific request".    */
    outripif = ripifs;
    while(outripif) {
	    struct rtproto *rtp;
      
	    MALLOC(rtp, struct rtproto);
	    rtp->rtp_type = RTPROTO_RIP;
	    rtp->rtp_rip  = outripif;
	
	    if (ripif->rip_adj_ribs_out)
		    insque(rtp, ripif->rip_adj_ribs_out);
	    else {
		    rtp->rtp_next =  rtp->rtp_prev = rtp;
		    ripif->rip_adj_ribs_out        = rtp;
	    }
	    if ((outripif = outripif->rip_next) == ripifs)  /* global */
		    break;
    } /* while(outripif) */


    outife = ifentry;      /* Don't include ife itself */
    while (outife) {
	    struct rtproto *rtp;

	    if (ripif->rip_ife != outife) {
		    MALLOC(rtp, struct rtproto);
		    rtp->rtp_type = RTPROTO_IF;
		    rtp->rtp_if   = outife;
	
		    if (ripif->rip_adj_ribs_out)
			    insque(rtp, ripif->rip_adj_ribs_out);
		    else {
			    rtp->rtp_next =  rtp->rtp_prev = rtp;
			    ripif->rip_adj_ribs_out        = rtp;
		    }
	    }
	    if ((outife = outife->ifi_next) == ifentry)  /* global */
		    break;
    } /* while(outife) */


    if (bgpyes) {
	    outbnp = bgb;
	    while(outbnp) {/* Import All eBGP routes into RIP (1998/05/21) */
		    struct rtproto *rtp;
		    if (!(outbnp->rp_mode & BGPO_IGP)) {
			    MALLOC(rtp, struct rtproto);
			    rtp->rtp_type = RTPROTO_BGP;
			    rtp->rtp_bgp  = outbnp;
	
			    if (ripif->rip_adj_ribs_out)
				    insque(rtp, ripif->rip_adj_ribs_out);
			    else {
				    rtp->rtp_next =  rtp->rtp_prev = rtp;
				    ripif->rip_adj_ribs_out        = rtp;
			    }
		    }
      
		    if ((outbnp = outbnp->rp_next) == bgb)  /* global */
			    break;
	    } /* while (struct rpcb) */
    }
      
    if ((ripif = ripif->rip_next) == ripifs)
	    break;
  } /* while (global "ripifs") */ 
}

/*
 *   rip_query_dump()
 */
void
rip_query_dump()
{
  struct ripif        *ripif;
  struct in6_pktinfo   spktinfo;
  struct riphdr       *rp;
  struct ripinfo6     *np;         /* RIPng RTE              */


  memset(rippkt, 0, RIPNG_MAXPKT);

  rp = (struct riphdr *)rippkt;    /* outgoing RIPng header  */
  rp->riph_cmd   = RIPNGCMD_REQUEST;
  rp->riph_vers  = RIPNG_VERSION;
  rp->riph_zero2 = 0;

  np  = (struct ripinfo6 *)(rippkt + sizeof(struct riphdr));
  np->rip6_metric = RIPNG_METRIC_UNREACHABLE;

  ripif = ripifs; /* global */
  while(ripif) {
    if (!(ripif->rip_mode & IFS_NORIPOUT)) {

      spktinfo.ipi6_addr    = ripif->rip_ife->ifi_laddr;  /* copy */
      spktinfo.ipi6_ifindex = ripif->rip_ife->ifi_ifn->if_index;

      if (rip_sendmsg(&ripsin,      /* ff02::9.RIPNG_PORT  */
		      &spktinfo,    /* source address, I/F */
		      sizeof(struct riphdr) + sizeof(struct ripinfo6)))
	ripif->rip_reqsentfail++;
      ripif->rip_requestsent++;
    }
    if ((ripif = ripif->rip_next) == ripifs)
      break;
  }
}


struct sockaddr_in6 fsock;  /* sender's address */
/*
 *
 *   rip_input()
 *
 */
void 
rip_input()
{
  struct ripif       *ripif;
  int                 nn;     /* number of RTEs                  */
  int                 len;    /* recvmsg                         */
  int                 flen;   /* sizeof From addr (for Adv. API) */
  struct ifinfo      *ife;
  struct riphdr      *rp;     /* RIPng header                    */

  extern struct ifinfo *ifentry;


  struct msghdr       rmsghdr;            /* Adv. API */
  struct iovec        rmsgiov;            /* buffer for data (gather)  */
                                          /* buffer for ancillary data */
  char   cmsg[CMSG_SPACE(sizeof(struct in6_pktinfo)) + 
	      CMSG_SPACE(sizeof(int))];
  struct cmsghdr     *ch;                 /* Adv. API */
  struct in6_pktinfo *rpktinfo;           /* received I/F address */
  struct in6_pktinfo  spktinfo;           /* sending source I/F   */
  int                *rhoplimit;          /* Adv. API */

  char                ifname[IFNAMSIZ];

  memset(&fsock,    0, sizeof(struct sockaddr_in6)); /* sender's addr/port */
  memset(ripbuf,    0, RIPNG_BUFSIZ);
  memset(rippkt,    0, RIPNG_MAXPKT);
  memset(&rmsghdr,  0, sizeof(struct msghdr));
  memset(&rmsgiov,  0, sizeof(struct iovec));
  memset(cmsg,      0, CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	               CMSG_SPACE(sizeof(int)));
  memset(&spktinfo, 0, sizeof(struct in6_pktinfo));
  rpktinfo  = NULL;
  rhoplimit = NULL;

/***  Adv. API  ***/
  flen = sizeof(struct sockaddr_in6);
  rmsghdr.msg_name       = (caddr_t)&fsock; /* sender's addr/port          */
  rmsghdr.msg_namelen    = flen;            /* size of address             */
  rmsgiov.iov_base       = (void *)ripbuf;  /* buffer, base should be void */
  rmsgiov.iov_len        = sizeof(ripbuf);  /* 1500 (receiving buffer len) */
  rmsghdr.msg_iov        = &rmsgiov;
  rmsghdr.msg_iovlen     = 1; /* 1 iovec obj. */
#ifdef ADVANCEDAPI
  rmsghdr.msg_control    = (caddr_t)cmsg;   /* buffer for ancillary data   */
  rmsghdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                           CMSG_SPACE(sizeof(int));
#else
  rmsghdr.msg_control    = (caddr_t)0;
  rmsghdr.msg_controllen = 0;
#endif /* ADVANCEDAPI */
  rmsghdr.msg_flags      = 0; /* ? */

  len = 0;
  if ((len = recvmsg(ripsock, &rmsghdr, 0)) < 0)   /* Adv. API */
    fatal("<rip_input>: recvmsg");


  if (IN6_IS_ADDR_LINKLOCAL(&fsock.sin6_addr))
    CLEAR_IN6_LINKLOCAL_IFINDEX(&fsock.sin6_addr);  /* for safty */

#ifdef ADVANCEDAPI
  for (ch = CMSG_FIRSTHDR(&rmsghdr);ch; ch = CMSG_NXTHDR(&rmsghdr, ch)) {

    if (ch->cmsg_level == IPPROTO_IPV6 &&
	ch->cmsg_type  == IPV6_PKTINFO &&
	ch->cmsg_len   == CMSG_LEN(sizeof(struct in6_pktinfo))) {
      rpktinfo = (struct in6_pktinfo *)CMSG_DATA(ch);
    }

    if (ch->cmsg_level == IPPROTO_IPV6 &&
	ch->cmsg_type  == IPV6_HOPLIMIT &&
	ch->cmsg_len   == CMSG_LEN(sizeof(int))) {
      rhoplimit = (int *)CMSG_DATA(ch);
    }
  }

  if (rpktinfo == NULL) {
    fatalx("<rip_input>: Can't get received interface");
    return;
  }
#else  /* for older hydranger */
  {
      struct ifinfo *ife;
      static struct in6_pktinfo rrpktinfo;

      if ((ife = find_if_by_addr(&fsock.sin6_addr)) == NULL)
	  fatalx("<rip_input>: find_if_by_addr");
      rrpktinfo.ipi6_ifindex = ife->ifi_ifn->if_index;
      rpktinfo = &rrpktinfo;

  }
#endif /* ADVANCEDAPI */

  IFLOG(LOG_RIP)
	  syslog(LOG_DEBUG, "RIPng RECV from %s+%d (%s)",
		 ip6str2(&fsock), ntohs(fsock.sin6_port),
		 if_indextoname(rpktinfo->ipi6_ifindex, ifname));

  /* Received I/F */
  if ((ripif = find_rip_by_index((u_int)rpktinfo->ipi6_ifindex)) == NULL) {
    syslog(LOG_ERR,
	   "<rip_input>: RIP received at Unknown I/F %d (ignored)",
	   rpktinfo->ipi6_ifindex);
    return;
  }

  if (ripif->rip_mode & IFS_NORIPIN)
    return;             /* discard */
  
  nn = (len - sizeof(struct riphdr)) / sizeof(struct ripinfo6);

  if (nn == 0) return;             /* number of RTEs */

  rp = (struct riphdr *)ripbuf;    /* RIPng header   */


  if (rp->riph_vers !=  RIPNG_VERSION) {
    syslog(LOG_ERR, "<rip_input>: Unknown RIPng version %d",
	   rp->riph_vers);
    return;
  }

  rp->riph_zero2 = 0;             /* must be ignored, and must be zero */ 

  switch (rp->riph_cmd) {         /* received cmd */

  case RIPNGCMD_REQUEST:
    ripif->rip_requestrcvd++;
    IFLOG(LOG_RIP)
	    syslog(LOG_DEBUG, "RIPng RECV cmd=%s, length=%d, nn=%d",
		   rip_msgstr[rp->riph_cmd], len, nn);

    if (ripif->rip_mode & IFS_NORIPOUT)
      return;

    ife = ifentry;
    while(ife) {  /* from myself ? */
      if (ife->ifi_ifn->if_index == rpktinfo->ipi6_ifindex &&
	  IN6_ARE_ADDR_EQUAL(&ife->ifi_laddr, &fsock.sin6_addr) &&
	  ripsin.sin6_port == fsock.sin6_port) {
	return;
      }
      if ((ife = ife->ifi_next) == ifentry)
	break; /* while */
    }
    
    nn = rip_process_request(ripif, nn);  

    if (nn > 0) {
      int mm;  /* current */
      int done;
      done = 0;

      if (fsock.sin6_port != ripsin.sin6_port &&        /* RIPNG_PORT */
	  !IN6_ARE_ADDR_EQUAL(&rpktinfo->ipi6_addr, &ripsin.sin6_addr) &&
	  !IN6_IS_ADDR_UNSPECIFIED(&ripif->rip_ife->ifi_gaddr))

	spktinfo.ipi6_addr = ripif->rip_ife->ifi_gaddr; /* copy */
      else
	spktinfo.ipi6_addr = ripif->rip_ife->ifi_laddr; /* copy */

      spktinfo.ipi6_ifindex = rpktinfo->ipi6_ifindex;

      while(1) {
	mm = MIN(nn - done, RIPNG_MAXRTES);

	memcpy(&rippkt[sizeof(struct riphdr)],
	       &ripbuf[sizeof(struct riphdr) + done*sizeof(struct ripinfo6)],
	       mm * sizeof(struct ripinfo6));

	if (rip_sendmsg(&fsock,     /* sender's addr.port  */
			&spktinfo,  /* source address, I/F */
			sizeof(struct riphdr) + mm * sizeof(struct ripinfo6)))
	  ripif->rip_respfail++;
	ripif->rip_responsesent++;
	done += mm;
	if (done == nn) break;
      }
    }
    break;

  case RIPNGCMD_RESPONSE:

    ripif->rip_responsercvd++;
    if (ntohs(fsock.sin6_port) != RIPNG_PORT) {
      IFLOG(LOG_RIP)
	syslog(LOG_DEBUG,
	       "<rip_input>: Response from non RIPng port: %s+%d on %s",
	       ip6str2(&fsock), ntohs(fsock.sin6_port),
	       if_indextoname(rpktinfo->ipi6_ifindex, ifname));
      return; /* The Response must be ignored
		 if it is not from the RIPng port. [rfc2080] */
    }


    if (!IN6_IS_ADDR_LINKLOCAL(&fsock.sin6_addr)) {
      IFLOG(LOG_RIP)
	syslog(LOG_ERR,
	       "<rip_input>: Response from non-linklocal addr: %s on %s",
	       ip6str2(&fsock),
	       if_indextoname(rpktinfo->ipi6_ifindex, ifname));
      return;  /* Ignore response msg from non-link-local address [rfc2080] */
    }

    /* It is also worth checking to see whether the
       response is from one of the router's own addresses [rfc2080] */
    ife = ifentry;
    while(ife) {
      if (ife->ifi_ifn->if_index == rpktinfo->ipi6_ifindex &&
	  IN6_ARE_ADDR_EQUAL(&ife->ifi_laddr, &fsock.sin6_addr)) {
	return;
      }
      if ((ife = ife->ifi_next) == ifentry)
	break; /* while */
    }

#ifdef ADVANCEDAPI
    /* multicast packets sent from the RIPng port
       (i.e. periodic advertisement or triggered update packets) must be
       examined to ensure that the hop count is 255. [rfc2080] */

    if (rhoplimit != NULL && *rhoplimit != RIPNG_HOPLIMIT &&
	rpktinfo != NULL && IN6_IS_ADDR_MULTICAST(&rpktinfo->ipi6_addr)) {
      IFLOG(LOG_RIP)
	syslog(LOG_ERR,
	       "<%s>: Response from non-neighbor: %s on %s, hoplimit=%d",
	       __FUNCTION__,
	       ip6str2(&fsock), if_indextoname(rpktinfo->ipi6_ifindex, ifname),
	       *rhoplimit);
      return;
    }

#endif

    IFLOG(LOG_RIP)
      syslog(LOG_DEBUG,
	     "RIPng RECV cmd=%s, length=%d, nn=%d",
	     rip_msgstr[rp->riph_cmd], len, nn);

    nn = rip_process_response(ripif, nn);

    IFLOG(LOG_RIP)
      syslog(LOG_DEBUG,
	     "<rip_input>: rip_process_response() returned. (nn=%d)", nn);

    break;

  default:
    syslog(LOG_ERR,
	   "<rip_input>: Unknow RIPng command %d", rp->riph_cmd);
    break;
  }

  return; 
}

/*
 *  rip_process_request()
 */
int
rip_process_request(ripif, nn)
     struct ripif *ripif;
     int           nn;     /* the Number of ripinfo6 */
{
  int i;
  struct ripinfo6 *np;     /* RIPng RTE              */
  struct rt_entry  key;
  struct rt_entry *base, *rte;
  struct rtproto  *rtp;
  struct riphdr   *rp;

  rp = (struct riphdr *)rippkt;    /* outgoing RIPng header  */
  rp->riph_cmd   = RIPNGCMD_RESPONSE;
  rp->riph_vers  = RIPNG_VERSION;
  rp->riph_zero2 = 0;

  np  = (struct ripinfo6 *)(ripbuf + sizeof(struct riphdr));

  /* DUMP request */
  if (nn == 1 &&
      IN6_IS_ADDR_UNSPECIFIED(&np->rip6_dest) &&
      np->rip6_plen   == 0 &&
      np->rip6_metric == RIPNG_METRIC_UNREACHABLE) {
    nn = rip_make_dump(ripif);
    return nn;
  }

  /* If the request is for specific entries, they are looked up in the
     routing table and the information is returned as is;
     no Split Horizon processing is done.              [rfc2080  2.4.1] */
  for (i = 0 ; i < nn ; i++, np++ ) {
    rte = NULL;
    memset(&key, 0, sizeof(key));

    key.rt_ripinfo.rip6_dest = np->rip6_dest;
    key.rt_ripinfo.rip6_plen = np->rip6_plen;
  
    rtp = ripif->rip_adj_ribs_out;
    while(rtp) {
      switch(rtp->rtp_type) {
      case RTPROTO_IF:
	base = rtp->rtp_if->ifi_rte;
	break;
      case RTPROTO_BGP:
	base = rtp->rtp_bgp->rp_adj_ribs_in;
	break;
      case RTPROTO_RIP:
	base = rtp->rtp_rip->rip_adj_ribs_in;
	break;
      default:
	fatalx("<rip_process_request>: BUG !");
	break;			/* NOTREACHED */
      }
      rte = find_rte(&key, base);
      if (rte) break;  /* while */

      if ((rtp = rtp->rtp_next) ==  ripif->rip_adj_ribs_out)
	break;         /* while */
    }

    if (rte) {  /* advertizing via RIP */
      np->rip6_metric = MIN(rte->rt_ripinfo.rip6_metric + 1, 
			    RIPNG_METRIC_UNREACHABLE);
      np->rip6_tag    = rte->rt_ripinfo.rip6_tag; /* AS number (net byte) */
    } else {
      np->rip6_metric = RIPNG_METRIC_UNREACHABLE;
      np->rip6_tag    = 0;                        /* no info              */
    }
  } /* for */

  return nn;

  /* End of rip_process_request() */
}



/*
 *
 *  rip_process_response()
 *     DESCRIPTION:   install RTE. and redistribute, if needed.
 *     RETURN VALUES: the number of "triggered updated" RTEs. (ad-hoc)
 */
int
rip_process_response(ripif, nn)
     struct ripif *ripif;
     int           nn;     /* the Number of ripinfo6 */
{
  int i;
  int unn, dnn;                               /*  return. (no use)    */
  struct ripinfo6 *np;                        /*  nibbing             */
  struct in6_addr *nhaddr;                    /* "nexthop" address    */
  struct ripif    *oripif;

  struct rt_entry *uprtehead,  *uprte; /* copied object by igp_enable_rte()  */
  struct rt_entry              *dwnrte;/* copied object by rip_disable_rte() */

  task            *lifetime,  *garbage;       /*  may be registered          */
  byte             lifeyes,    garbageyes;
  char             in6txt[INET6_ADDRSTRLEN];
  char *ifname = ripif->rip_ife->ifi_ifn->if_name; /* for debugging use */

  extern struct ifinfo    *ifentry;
  extern task             *taskhead;
  extern byte              bgpyes;
  extern struct rt_entry  *aggregations;

  IFLOG(LOG_RIP)
    syslog(LOG_DEBUG, "<rip_process_response>: invoked, nn=%d", nn);

  memset(in6txt, 0, INET6_ADDRSTRLEN);

  uprtehead = NULL;
  unn = dnn = 0;

  MALLOC(lifetime, task);    lifeyes    = 0;
  MALLOC(garbage,  task);    garbageyes = 0;
  
  nhaddr = &fsock.sin6_addr;          /*  sender's address (normally) */


  np  = (struct ripinfo6 *)&(ripbuf[sizeof(struct riphdr)]);
  for (i = 0 ; i < nn ; i++, np++ ) {
    struct rt_entry *rte;           /* to be installed    */
    struct rt_entry *srte = NULL;   /* newly synchronized */
    struct ifinfo   *ife;           /* search for         */
    struct rt_entry *orte = NULL;   /* old RTE            */
    uprte = NULL;

    IFLOG(LOG_RIP)
      syslog(LOG_DEBUG, "RIPng RECV\t%d\t%s/%d (%d) on %s",
	     i, ip6str(&np->rip6_dest, 0),
	     np->rip6_plen, np->rip6_metric, ifname);

    if (np->rip6_metric == RIPNG_METRIC_NEXTHOP) { /* "nexthop" address */
      if (IN6_IS_ADDR_LINKLOCAL(&np->rip6_dest))
	nhaddr = &np->rip6_dest; 
      else
	nhaddr = &fsock.sin6_addr;   /* sender's */
      continue;
    }

    if (!IN6_IS_ADDR_ROUTABLE(&np->rip6_dest)) {
	    syslog(LOG_NOTICE,
		   "<%s>: non-routable address(%s/%d) on %s",
		   __FUNCTION__, ip6str(&np->rip6_dest, 0), np->rip6_plen,
		   ripif->rip_ife->ifi_ifn->if_name);
	    continue;  /* ignore */
    }
    /*
     * Check route filter and restriction.
     */
    if (input_filter_check(&ripif->rip_filterset, rip_use_sitelocal, np)) {
      IFLOG(LOG_RIP)
	syslog(LOG_DEBUG,
	       "<%s>: incoming route %s/%d on %s was filtered",
	       __FUNCTION__, ip6str(&np->rip6_dest, 0), np->rip6_plen,
	       ripif->rip_ife->ifi_ifn->if_name);
	
      continue;
    }

    if (np->rip6_metric == 0 ||
	np->rip6_metric > RIPNG_METRIC_UNREACHABLE) { 
	    syslog(LOG_NOTICE,
		   "<%s>: invaid metric(%d) for %s/%d on %s", __FUNCTION__,
		   np->rip6_metric, ip6str(&np->rip6_dest, 0), np->rip6_plen,
		   ripif->rip_ife->ifi_ifn->if_name);
	    continue;  /* ignore */
    }
    else {
	    /* incoming metric addition(if specified) */
	    if (ripif->rip_metricin) {
		    np->rip6_metric += ripif->rip_metricin;
		    if (np->rip6_metric > RIPNG_METRIC_UNREACHABLE)
			    np->rip6_metric = RIPNG_METRIC_UNREACHABLE;
		    IFLOG(LOG_RIP)
		      syslog(LOG_DEBUG,
			     "RIPng METRIC ADD\t%d\t%s/%d (%d) on %s",
			     i, ip6str(&np->rip6_dest, 0),
			     np->rip6_plen, np->rip6_metric, ifname);
	    }
    }

    if (np->rip6_plen > 128) {
      syslog(LOG_ERR, 
	     "<rip_process_response>: invaid plefix length(%d)", np->rip6_plen);
      continue;  /* ignore */
    }

    if (np->rip6_plen == 128) {
      ife = ifentry;
      while(ife) {
	/*  check I/F addrs  */
	if (IN6_ARE_ADDR_EQUAL(&np->rip6_dest, &ife->ifi_gaddr)) {
	  ife = NULL;
	  break;
	}
	if ((ife = ife->ifi_next) == ifentry)
	  break;
      }
      if (ife == NULL) {
	continue;  /* ignore */	
      }
    }


    MALLOC(rte, struct rt_entry);

    rte->rt_gw                  = *nhaddr;    /* copy                       */
    rte->rt_flags               = RTF_UP|RTF_GATEWAY;
    rte->rt_ripinfo             = *np;  /* tag must be preserved and readvd */
    mask_nclear(&rte->rt_ripinfo.rip6_dest, rte->rt_ripinfo.rip6_plen);

    if (rte->rt_ripinfo.rip6_plen == 128)
      rte->rt_flags |= RTF_HOST;

    rte->rt_proto.rtp_type      = RTPROTO_RIP;
    rte->rt_proto.rtp_rip       = ripif; /* for each RTE, each RTP exists.  */
    rte->rt_riptime             = NULL;
    rte->rt_aspath              = NULL;
/*  rte->rt_aggr                = 0;    */


    /**  check I/F routes **/
    ife = ifentry;
    while(ife) {
      if ((orte = find_rte(rte, ife->ifi_rte)))
	break;
      if ((ife = ife->ifi_next) == ifentry)
	break;
    }
    if (orte != NULL) {  /* I/F direct route (most preferable) */
      IFLOG(LOG_RIP)
	syslog(LOG_DEBUG,
	       "<%s>: I/F direct route(%s/%d on %s) cannot overwritten",
	       __FUNCTION__,
	       ip6str(&orte->rt_ripinfo.rip6_dest, 0),
	       orte->rt_ripinfo.rip6_plen, ifname);
      free(rte);
      continue;  /* to next rte */
    }


    /**  check aggregate routes  **/
    if (find_rte(rte, aggregations)) {
      IFLOG(LOG_RIP)
	syslog(LOG_DEBUG,
	       "<%s>: aggregate route %s/%d on %s cannot overwritten",
	       __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
	       rte->rt_ripinfo.rip6_plen, ifname);
      free(rte);
      continue;  /* to next rte */
    }



    /**  check BGP routes              **/
    /**    exclude Poisoned Reverse    **/
    if (bgpyes &&                       
	rte->rt_ripinfo.rip6_metric != RIPNG_METRIC_UNREACHABLE) {
      struct rpcb        *obnp;
      extern struct rpcb *bgb;

      obnp = bgb;
      while(obnp) {
	if (obnp->rp_mode & BGPO_IGP &&
	    (orte = find_rte(rte, obnp->rp_adj_ribs_in))) {

	  if (rte->rt_ripinfo.rip6_tag == 0) {   /* purely internal */
	    IFLOG(LOG_RIP)
	      syslog(LOG_DEBUG, "<%s>: %s/%d on %s is purely internal.",
		     __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		     rte->rt_ripinfo.rip6_plen, ifname);
	    bgp_disable_rte(orte); /* XXX: do not have to propagate? */
	  }
	  else {
	    /**   route synchronization  (1998/06/27)  **/

	    if (rte->rt_ripinfo.rip6_tag == orte->rt_ripinfo.rip6_tag) {
	      rte->rt_flags  |=   RTF_IGP_EGP_SYNC;
	      rte->rt_flags  &=  ~RTF_UP;

	      if (!(orte->rt_flags & RTF_IGP_EGP_SYNC)) {
		IFLOG(LOG_RIP)
		  syslog(LOG_DEBUG, "<%s>: synchronized...%s/%d on %s, tag=%d",
			 __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
			 rte->rt_ripinfo.rip6_plen, ifname,
			 ntohs(rte->rt_ripinfo.rip6_tag));
		orte->rt_flags |=   RTF_IGP_EGP_SYNC;
		/* don't touch RTF_UP, for backup-route */
		srte = orte;
	      }
	    }
	  }
	}
	if ((obnp = obnp->rp_next) == bgb)
	  break;
      } /* while(obnp) iBGP */

      obnp = bgb;
      while(obnp) {
	if (!(obnp->rp_mode & BGPO_IGP) &&                  /* eBGP */
	    (orte = find_rte(rte, obnp->rp_adj_ribs_in))) {

	  if (rte->rt_ripinfo.rip6_tag == 0) {   /* purely internal */
	    IFLOG(LOG_RIP)
	      syslog(LOG_DEBUG, "<%s>: %s/%d on %s is purely internal.",
		     __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		     rte->rt_ripinfo.rip6_plen, ifname,
		     ntohs(rte->rt_ripinfo.rip6_tag));
	    bgp_disable_rte(orte);
	  } else {

	    if (rte->rt_ripinfo.rip6_tag == orte->rt_ripinfo.rip6_tag) {
	      obnp = NULL;   /* I mean "continue to next rte" */
	      break;
	    } else
	      if (srte) { /* tag differ */
		if ((ntohl(srte->rt_aspath->asp_localpref) >
		     ntohl(orte->rt_aspath->asp_localpref))
		    ||
		    ((ntohl(srte->rt_aspath->asp_localpref) ==
		      ntohl(orte->rt_aspath->asp_localpref))    &&
		     ((aspath2cost(srte->rt_aspath) <
		       aspath2cost(orte->rt_aspath))     ||
		      (ntohl(srte->rt_aspath->asp_med) <
		       ntohl(orte->rt_aspath->asp_med))))) {
		  IFLOG(LOG_RIP)
		    syslog(LOG_DEBUG, "<%s>: tag differ.", __FUNCTION__);
		  bgp_disable_rte(orte); /* XXX: do not have to propagate? */
		} else {
		  /* don't touch srte's RTF_UP. No need. */
		  obnp = NULL;   /* I mean "continue to next rte" */
		  break;
		}
	      }
	  }
	}

	if (obnp == NULL ||
	    (obnp = obnp->rp_next) == bgb)
	  break;
      } /* while(obnp) eBGP */

      if (obnp == NULL) {
	free(rte);
	IFLOG(LOG_RIP)
	  syslog(LOG_DEBUG, "<%s>: skip", __FUNCTION__);
	continue;   /* to next rte */
      }
    }



    /**  check RIPng routes  **/
    oripif = ripifs;
    while(oripif) {
#define ALTER_RTE {  rte->rt_riptime = lifetime;   lifeyes = 1;\
		     rip_erase_rte(orte);\
		     uprte  = igp_enable_rte(rte);\
		     if (uprte) unn++; }
      if ((orte = find_rte(rte, oripif->rip_adj_ribs_in))) {
	/* If there is an existing route, compare the next hop address to the
	   address of the router from which the datagram came. [rfc2080] */
	if (ripif->rip_ife->ifi_ifn->if_index ==
	    oripif->rip_ife->ifi_ifn->if_index &&
	    IN6_ARE_ADDR_EQUAL(&orte->rt_gw, &fsock.sin6_addr)) {

	  if (rte->rt_ripinfo.rip6_metric == RIPNG_METRIC_UNREACHABLE) {
	    /* Note that the deletion process is started only when the metric
	       is first set to infinity.  If the metric was already infinity,
	       then a new deletion process is not started. [rfc2080] */
	    if (orte->rt_ripinfo.rip6_metric == RIPNG_METRIC_UNREACHABLE) {
	      oripif = NULL;  /* I mean "continue to next rte" */
	      break;
	    } else {
	      orte->rt_riptime = garbage;   garbageyes = 1;
	      orte->rt_ripinfo.rip6_metric = RIPNG_METRIC_UNREACHABLE;
	      dwnrte = rip_disable_rte(orte); /* copied */
	      if (dwnrte) {
		dnn++;
		dwnrte->rt_next = dwnrte->rt_prev = dwnrte;
		propagate(dwnrte);
		free(dwnrte);
		bgp_recover_rte(orte);
		oripif = NULL;
	      }
	      break;
	    }
	  }

	  /* 0 < rte < 16 */
	  if (orte->rt_ripinfo.rip6_metric == RIPNG_METRIC_UNREACHABLE) {


	    rte->rt_riptime = lifetime;  lifeyes = 1;

	    oripif->rip_adj_ribs_in
	      = rte_remove(orte, oripif->rip_adj_ribs_in);

	    uprte = igp_enable_rte(rte);   /* copied */
	    if (uprte) unn++;
	    break; /* while(oripif) */
	  }

	  /* 0 < orte < 16 */
	  if (rte->rt_ripinfo.rip6_metric == orte->rt_ripinfo.rip6_metric) {
	    /* If the new metric is the same as the old one, 
	       it is simplest to do nothing further
	       (beyond reinitializing the timeout...)   [rfc2080] */
	 
	    orte->rt_riptime = lifetime;  lifeyes = 1;
	    oripif = NULL;  /* I mean "continue to next rte" */
	    break; /* while(oripif) */
	  }

	  if (rte->rt_ripinfo.rip6_metric != orte->rt_ripinfo.rip6_metric) {
	    /**  Metric Change  **/
	    IFLOG(LOG_RIP)
	      syslog(LOG_DEBUG,
		     "<%s>: metric for %s/%d on %s changes from %d to %d",
		     __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		     rte->rt_ripinfo.rip6_plen, ifname,
		     orte->rt_ripinfo.rip6_metric,
		     rte->rt_ripinfo.rip6_metric);
	    ALTER_RTE;
	    break; /* while(oripif) */
	  }

	} else {  /* nexthop differ (maybe came from another router) */
#if 0
     /* there is a heuristic which could be applied.  Normally,
	it is senseless to replace a route if the new route has the same
	metric as the existing route; this would cause the route to bounce
	back and forth, which would generate an intolerable number of
	triggered updates.  However, if the existing route is showing signs
	of timing out, it may be better to switch to an equally-good
	alternative route immediately, rather than waiting for the timeout to
	happen.  Therefore, if the new metric is the same as the old one,
	examine the timeout for the existing route.  If it is at least
	halfway to the expiration point, switch to the new route.  This
	heuristic is optional, but highly recommended. [rfc2080.txt]
     */
#endif
	  if (rte->rt_ripinfo.rip6_metric == RIPNG_METRIC_UNREACHABLE ||
	      orte->rt_ripinfo.rip6_metric <= rte->rt_ripinfo.rip6_metric) {
	    oripif = NULL;  /* I mean "continue to next rte" */
	    break; /* while(oripif) */

	  } else {
	    IFLOG(LOG_RIP)
	      syslog(LOG_DEBUG, "<%s>: nexthop for %s/%d changes "
		     "from %s to %s on %d",
		     __FUNCTION__,
		     ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		     rte->rt_ripinfo.rip6_plen,
		     ip6str(&orte->rt_gw, oripif->rip_ife->ifi_ifn->if_index),
		     ip6str(&rte->rt_gw, ripif->rip_ife->ifi_ifn->if_index),
		     ifname);
	    ALTER_RTE;
	    break;
	  }
	} /*   (nexthop differ)   */
      } else {
	/* couldn't find the same RTE */
      }
      if ((oripif = oripif->rip_next) == ripifs)
	break;

#undef ALTER_RTE
    } /*  while(oripif)  */


    if (oripif == NULL) {
      free(rte);
      IFLOG(LOG_RIP)
	syslog(LOG_DEBUG, "<%s>: skip", __FUNCTION__);
      continue;   /* to next rte */
    }


    if (!(uprte)) {  /*  Nothing matched in rp_adj_ribs_in  */
      if (rte->rt_ripinfo.rip6_metric == RIPNG_METRIC_UNREACHABLE) {
	free(rte);
	continue;   /* to next rte */
      }
      rte->rt_riptime = lifetime;  lifeyes = 1;
      uprte = igp_enable_rte(rte);  /* copied */
      if (uprte) unn++;
    }

    if (srte) { 
      struct rt_entry crte;

      bgp_enable_rte(srte);

      crte = *srte;
      crte.rt_next = crte.rt_prev = &crte;
      redistribute(&crte);   /* newly synchronized iBGP rte */
    }


    if (uprte) {
      if (uprtehead) {
	insque(uprte, uprtehead);
      } else {
	uprte->rt_next = uprte;
	uprte->rt_prev = uprte;
	uprtehead = uprte;
      }
    }
  }   /* for (i<nn) */


  /* triggerd update Go. */

  if (uprtehead) {
    redistribute(uprtehead);
    while(uprtehead) {
      uprtehead
	= rte_remove(uprtehead, uprtehead);      
    }
  }


  if (lifeyes) {
    lifetime->tsk_rip             = ripif;
    lifetime->tsk_timename        = RIP_LIFE_TIMER;
    lifetime->tsk_timefull.tv_sec = RIP_T_LIFE;
    insque(lifetime, taskhead);        /* assume taskhead exists. */
    task_timer_update(lifetime);
  } else {
    free(lifetime);
  }

  if (garbageyes) {
    garbage->tsk_rip             = ripif;
    garbage->tsk_timename        = RIP_GARBAGE_TIMER;
    garbage->tsk_timefull.tv_sec = RIP_T_GARBAGE;
    insque(garbage, taskhead);         /* assume taskhead exists. */
    task_timer_update(garbage);
  } else {
    free(garbage);
  }

  IFLOG(LOG_RIP)
    syslog(LOG_DEBUG, "<rip_process_response>: done, i=%d", i);

  return (unn + dnn);
}


/*
 *  rip_sendmsg()
 *     Actually sendmsg.
 */
int
rip_sendmsg(sin, pktinfo, len)
     struct sockaddr_in6 *sin;      /* dst addr.port           */
     struct in6_pktinfo  *pktinfo;  /* src addr, outgoing I/F  */
     int                  len;      /* data                    */
{

  int                 tlen;   /* sizeof To addr (for Adv. API) */
  int                 slen;   /* sent data len                 */
  struct msghdr       smsghdr;            /* Adv. API */
  struct iovec        smsgiov;            /* Adv. API */
                                          /* buffer for ancillary data */
  char   cmsg[CMSG_SPACE(sizeof(struct in6_pktinfo)) + 
	      CMSG_SPACE(sizeof(int))];
  struct cmsghdr     *ch;                 /* Adv. API */
  int                 shoplimit;          /* Adv. API */
  char                ifname[IFNAMSIZ];
  struct riphdr      *rp;    /* RIPng header   */

  memset(  ifname, 0, IFNAMSIZ);

  memset(cmsg,  0,
	 CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	 CMSG_SPACE(sizeof(int)));

  shoplimit = RIPNG_HOPLIMIT;

/***  Adv. API  ***/
  tlen = sizeof(struct sockaddr_in6);
  smsghdr.msg_name       = (caddr_t)sin;    /* dest addr.port              */
  smsghdr.msg_namelen    = tlen;            /* size of address             */
  smsgiov.iov_base       = (void *)rippkt;  /* buffer, base should be void */
  smsgiov.iov_len        = len;             /* sending data len            */
  smsghdr.msg_iov        = &smsgiov;
  smsghdr.msg_iovlen     = 1; /* 1 iovec obj. */
#ifdef ADVANCEDAPI
  smsghdr.msg_control    = (caddr_t)cmsg;   /* buffer for ancillary data   */
  smsghdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                           CMSG_SPACE(sizeof(int));
#endif
  smsghdr.msg_flags      = 0; /* ? */


  ch = CMSG_FIRSTHDR(&smsghdr);

#ifdef ADVANCEDAPI
  ch->cmsg_level = IPPROTO_IPV6;
  ch->cmsg_type  = IPV6_PKTINFO;
  ch->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
  /* source address selection */
  memcpy(CMSG_DATA(ch), pktinfo, sizeof(struct in6_pktinfo));

  ch = CMSG_NXTHDR(&smsghdr, ch);
  ch->cmsg_level = IPPROTO_IPV6;
  ch->cmsg_type  = IPV6_HOPLIMIT;    /* may not be supported */
  ch->cmsg_len   = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(ch), &shoplimit, sizeof(int));
#else  /* for hydranger */
  if (IN6_IS_ADDR_MULTICAST(&sin->sin6_addr) &&
      setsockopt(ripsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		 &pktinfo->ipi6_ifindex, sizeof(u_int)) < 0) {
      fatal("<rip_sendmsg>: IPV6_MULTICAST_IF");
  }
#endif /* ADVANCEDAPI */


  if ((slen = sendmsg(ripsock, &smsghdr, 0)) != len) {
    syslog(LOG_ERR,                            /* spoofing or misconfig ? */
	   "<rip_sendmsg>: sendmsg on %s (src=%s): %s",
	   if_indextoname(pktinfo->ipi6_ifindex, ifname),
	   ip6str(&pktinfo->ipi6_addr, 0), strerror(errno));
    return(-1);
  }

  IFLOG(LOG_RIP) {
    rp = (struct riphdr *)rippkt;    /* RIPng header   */
    syslog(LOG_DEBUG,
	   "RIPng SEND cmd %s, length %d", rip_msgstr[rp->riph_cmd], len);
    syslog(LOG_DEBUG,
	   "RIPng SEND %s+%d -> %s+%d (%s)",
	   ip6str(&pktinfo->ipi6_addr, 0), RIPNG_PORT, ip6str2(sin),
	   ntohs(sin->sin6_port),
	   if_indextoname(pktinfo->ipi6_ifindex, ifname));
  }

  return(0);
  /* End of rip_sendmsg */
}


/*
 *  rip_make_dump() 
 *    DESCRIPTION: make a RIP dump msg.
 *                 Split horizon applied.
 *                 Don't send the same I/F's direct route (metric = 0)
 *
 *     RETURN VALUES:  the number of RTEs
 */
int
rip_make_dump(ripif)
        struct ripif *ripif;
{
  struct ripinfo6 *np;   /* RIPng RTE, nibbing to "ripbuf"  */
  struct rtproto  *rtp, artp;
  struct rt_entry *rte, *base, *agg;
  int nn = 0;
  np  = (struct ripinfo6 *)(ripbuf + sizeof(struct riphdr));

  if (ripif->rip_mode & IFS_DEFAULTORIGINATE) {
    memset(np, 0, sizeof(struct ripinfo6));
    np->rip6_metric = 1;
    np++;
    nn++;
    IFLOG(LOG_RIP)
      syslog(LOG_DEBUG, "RIPng DUMP\t%d\tdefault(originated) on %s",
	     nn,
	     ripif->rip_ife->ifi_ifn->if_name);
  }

  memset(&artp, 0, sizeof(artp));
  artp.rtp_type = RTPROTO_IF;
  artp.rtp_if   = ripif->rip_ife;


  aggr_flush();

  rtp = ripif->rip_adj_ribs_out;
  while(rtp) {

    base = NULL;
    switch(rtp->rtp_type) {
    case RTPROTO_IF:
      base = rtp->rtp_if->ifi_rte;
      break;
    case RTPROTO_BGP:
    {
	    struct rpcb *ebnp = find_epeer_by_rpcb(rtp->rtp_bgp);
	    if (ebnp)
		    base = ebnp->rp_adj_ribs_in;
	    break;
    }
    case RTPROTO_RIP:
      if (rtp->rtp_rip != ripif)                 /* split horizon */
	base = rtp->rtp_rip->rip_adj_ribs_in;
      break;
    default:
      fatalx("<rip_make_dump>: BUG !");
      break;
    }


    rte = base;
    while(rte) {
      if ((rte->rt_flags & RTF_UP ||   /* iw97: avoid doublebooking */
	   (rtp->rtp_type == RTPROTO_RIP &&
	    rte->rt_flags & RTF_IGP_EGP_SYNC))) {

	agg = rte->rt_aggr.ag_agg;

	if (aggr_advable(agg, &artp) &&
	    !rip_output_filter(ripif, &agg->rt_ripinfo)) {
	  if ((ripif->rip_mode & IFS_DEFAULTORIGINATE) &&
	      IN6_IS_ADDR_UNSPECIFIED(&agg->rt_ripinfo.rip6_dest) &&
	      agg->rt_ripinfo.rip6_plen == 0) {
	    IFLOG(LOG_RIP)
	      syslog(LOG_DEBUG,
		     "<%s>: ignore default route when originating",
		     __FUNCTION__);

		  goto nextroute;
	  }
	  memcpy(np, &agg->rt_ripinfo, sizeof(struct ripinfo6));
	  np->rip6_metric = MIN(np->rip6_metric+1, RIPNG_METRIC_UNREACHABLE);
	  np++;  /* nibbing */ 
	  nn++;  /* count   */	    
	  agg->rt_aggr.ag_flags |= AGGR_ADVDONE;
	}

	if (!((rte->rt_aggr.ag_flags & AGGR_NOADVD) &&
	      agg &&
	      agg->rt_aggr.ag_flags & AGGR_ADVDONE) &&
	    !rip_output_filter(ripif, &rte->rt_ripinfo)) {
	  if ((ripif->rip_mode & IFS_DEFAULTORIGINATE) &&
	      IN6_IS_ADDR_UNSPECIFIED(&rte->rt_ripinfo.rip6_dest) &&
	      rte->rt_ripinfo.rip6_plen == 0) {
	    IFLOG(LOG_RIP)
	      syslog(LOG_DEBUG,
		     "<%s>: ignore default route when originating",
		     __FUNCTION__);
		  goto nextroute;
	  }

	  memcpy(np, &rte->rt_ripinfo, sizeof(struct ripinfo6));
	  np->rip6_metric = MIN(np->rip6_metric+1, RIPNG_METRIC_UNREACHABLE);
	  IFLOG(LOG_RIP)
	    syslog(LOG_DEBUG, "RIPng DUMP\t%d\t%s/%d (%d) on %s",
		   nn, ip6str(&np->rip6_dest, 0),
		   np->rip6_plen, np->rip6_metric,
		   ripif->rip_ife->ifi_ifn->if_name);

	  np++;  /* nibbing */ 
	  nn++;  /* count   */
	}
      }

      nextroute:
      if ((rte = rte->rt_next) == base)
	break;
    } /* while(rte) */

    if ((rtp = rtp->rtp_next) == ripif->rip_adj_ribs_out)
      break;

  } /* while(rtp) */

  return nn;  /* End of rip_make_dump() */
}



/*
 *  rip_make_data() 
 *    DESCRIPTION: make a RIP data. (excluding RIP header)
 */
int
rip_make_data(rte, ripif, ripmode)
     struct rt_entry *rte;
     struct ripif    *ripif;  /* NULL case .... withdrawning. */
     byte	     ripmode;
{
  struct ripinfo6 *np;   /* RIPng RTE, nibbing "ripbuf" */
  struct rt_entry *r, *agg;
  struct rtproto   artp;

  int nn = 0;
  np  = (struct ripinfo6 *)(ripbuf + sizeof(struct riphdr));

  if (ripif) {
    memset(&artp, 0, sizeof(artp));
    artp.rtp_type = RTPROTO_IF;
    artp.rtp_if   = ripif->rip_ife;
  }

  r = rte;
  while(r) {

    agg = r->rt_aggr.ag_agg;

    if (ripif &&
	aggr_advable(agg, &artp) &&
	!rip_output_filter(ripif, &agg->rt_ripinfo)) {
      if ((ripmode & IFS_DEFAULTORIGINATE) &&
	  IN6_IS_ADDR_UNSPECIFIED(&agg->rt_ripinfo.rip6_dest) &&
	  agg->rt_ripinfo.rip6_plen) {
	IFLOG(LOG_RIP)
	  syslog(LOG_DEBUG,
		 "<%s>: ignore default route when originating",
		 __FUNCTION__);
	      goto nextroute;
      }

      memcpy(np, &agg->rt_ripinfo, sizeof(struct ripinfo6));
      np->rip6_metric = MIN(np->rip6_metric+1, RIPNG_METRIC_UNREACHABLE);
      np++;  /* nibbing */ 
      nn++;  /* count   */	    
      agg->rt_aggr.ag_flags |= AGGR_ADVDONE;
    }


    if (ripif == NULL ||  /* withdrawing or.. */
	(((r->rt_flags & RTF_UP ||
	  (r->rt_proto.rtp_type == RTPROTO_RIP &&
	   (r->rt_flags & RTF_IGP_EGP_SYNC)))       &&
	 !(r->rt_aggr.ag_flags & AGGR_NOADVD &&
	   agg                               &&
	   (agg->rt_aggr.ag_flags & AGGR_ADVDONE))) &&
	!rip_output_filter(ripif, &r->rt_ripinfo))) {
      if ((ripmode & IFS_DEFAULTORIGINATE) &&
	  IN6_IS_ADDR_UNSPECIFIED(&r->rt_ripinfo.rip6_dest) &&
	  r->rt_ripinfo.rip6_plen) {
	IFLOG(LOG_RIP)
	  syslog(LOG_DEBUG,
		 "<%s>: ignore default route when originating",
		 __FUNCTION__);

	      goto nextroute;
      }
      memcpy(np, &r->rt_ripinfo, sizeof(struct ripinfo6));
      np->rip6_metric = MIN(np->rip6_metric + 1, RIPNG_METRIC_UNREACHABLE);
      np++;  /* nibbing */ 
      nn++;  /* count   */ 
    }

    nextroute:
    if ((r = r->rt_next) == rte)
      break;
  }

  return nn;  /* End of rip_make_data() */
}





/*
 *    find_rip_by_index()
 */
struct ripif *
find_rip_by_index(u_int index)
{
  struct ripif *rip;

  extern struct ripif *ripifs;
  
  if ((rip = ripifs) == NULL)
    return NULL;

  while(rip) {
    if (rip->rip_ife == NULL ||
	rip->rip_ife->ifi_ifn == NULL)
      fatalx("<find_rip_by_index>: BUG !");
    
    if (rip->rip_ife->ifi_ifn->if_index == index)
      break;

    if ((rip = rip->rip_next) == ripifs)
      return NULL;
  }

  return rip;
}


/*
 *  rip_disable_rte()
 *    DESCRIPTION: called by rip_life_expired(), bgp_process_update(),
 *                            or, when received metric=16.
 */
struct rt_entry *
rip_disable_rte(rte)
     struct rt_entry *rte;
{
  struct rt_entry *crte;  /* to be copied */

  IFLOG(LOG_RIP)
    syslog(LOG_DEBUG, "<%s>: delroute()...", __FUNCTION__);

  if (delroute(rte, &rte->rt_gw) != 0) {
    syslog(LOG_ERR, "<%s>: route couldn't be deleted.", __FUNCTION__);
    return NULL;

    rte->rt_flags &= ~RTF_UP;
  }

  rte->rt_flags &= ~RTF_UP;          /* down */
  rte->rt_ripinfo.rip6_metric = RIPNG_METRIC_UNREACHABLE;

  /* also disable BGP routes that use this route to resolve the nexthop */
  bgp_disable_rte_by_igp(rte);

  MALLOC(crte, struct rt_entry);
  memcpy(crte, rte, sizeof(struct rt_entry));

  return crte;
}


/*
 *  rip_erase_rte()
 *     DESCRIPTION:  Kernel delroute().
 *                   rip_adj_ribs_in is shorten.
 */
void
rip_erase_rte(rte)
     struct rt_entry *rte;
{
  struct ripif    *ripif;

  if (rte->rt_proto.rtp_type != RTPROTO_RIP)
    fatalx("<rip_erase_rte>: BUG !");

  IFLOG(LOG_RIP)
    syslog(LOG_DEBUG, "<%s>: delroute()...", __FUNCTION__);

  if (delroute(rte, &rte->rt_gw) != 0)
    syslog(LOG_ERR, "<%s>: route couldn't be deleted.", __FUNCTION__);

  /* also disable BGP routes that use this route to resolve the nexthop */
  bgp_disable_rte_by_igp(rte);

  if ((ripif = rte->rt_proto.rtp_rip) == NULL)
    fatalx("<rip_erase_rte>: BUG !");

  ripif->rip_adj_ribs_in 
    = rte_remove(rte, ripif->rip_adj_ribs_in);
}


/*
 *  rip_change_rte()
 */
struct rt_entry *
rip_change_rte(rte)
     struct rt_entry *rte;
{
  struct rt_entry *crte;  /* to be copied */

  if (chroute(rte, &rte->rt_gw, rte->rt_proto.rtp_rip->rip_ife) != 0) {
    syslog(LOG_ERR, "<rip_change_rte>: route couldn't be changed.");
    return NULL;
  }

  MALLOC(crte, struct rt_entry);
  memcpy(crte, rte, sizeof(struct rt_entry));

  return crte;
}


/*
 *   rip_dump()
 *      triggered by SIGALRM.
 */
void
rip_dump() {
  struct ripif        *ripif;
  struct in6_pktinfo   spktinfo;      /* Adv. API */
  struct riphdr       *rp;
  int                  nn;

  extern task                *taskhead;

  memset(ripbuf, 0, RIPNG_BUFSIZ);
  memset(rippkt, 0, RIPNG_MAXPKT);

  rp = (struct riphdr *)rippkt;    /* outgoing RIPng header  */
  rp->riph_cmd   = RIPNGCMD_RESPONSE;
  rp->riph_vers  = RIPNG_VERSION;
  rp->riph_zero2 = 0;

  ripif = ripifs;  /* global */
  while(ripif) {
    if (!(ripif->rip_mode & IFS_NORIPOUT)) {
      nn = rip_make_dump(ripif);     /* periodic DUMP */
	
      spktinfo.ipi6_addr    = ripif->rip_ife->ifi_laddr;  /* copy */
      spktinfo.ipi6_ifindex = ripif->rip_ife->ifi_ifn->if_index;
      if (nn > 0) {
	int mm;  /* current */
	int done;
	done = 0;
	while(1) {
	  mm = MIN(nn - done, RIPNG_MAXRTES);
	  memcpy(&rippkt[sizeof(struct riphdr)],
		 &ripbuf[sizeof(struct riphdr) + done*sizeof(struct ripinfo6)],
		 mm * sizeof(struct ripinfo6));

	  if (rip_sendmsg(&ripsin,      /* ff02::9.RIPNG_PORT  */
			  &spktinfo,    /* source address, I/F */
			  sizeof(struct riphdr) +
			  mm * sizeof(struct ripinfo6)))
	    ripif->rip_respfail++;
	  ripif->rip_responsesent++;

	  done += mm;
	  if (done == nn) break;
	}
      }
    }
    if ((ripif = ripif->rip_next) == ripifs)
      break;
  }

  taskhead->tsk_timefull.tv_sec = RIP_T_DUMP +
    (random()%(RIP_T_DUMPRAND*2)) - RIP_T_DUMPRAND;
  taskhead->tsk_timefull.tv_usec = 0;


  task_timer_update(taskhead);

  /* End of rip_dump() */
}


/*
 *   rip_life_expired()
 */
void
rip_life_expired() {
  struct ripif    *ripif;
  task            *garbage;
  byte             garbageyes;
  struct rt_entry *rte;                         /* cursor */
  struct rt_entry *dwnrte;

  extern task     *taskhead;

  MALLOC(garbage, task);  garbageyes = 0;
  garbage->tsk_timename = RIP_GARBAGE_TIMER;

  ripif = taskhead->tsk_rip;

  rte = ripif->rip_adj_ribs_in;
  while(rte) {
    dwnrte = NULL;
    if (rte->rt_riptime->tsk_next == NULL)  /* safety check */
      fatalx("<rip_life_expired>: BUG !");

    if (rte->rt_riptime == taskhead) {

      rte->rt_riptime = garbage;   garbageyes = 1;
      rte->rt_ripinfo.rip6_metric = RIPNG_METRIC_UNREACHABLE;
      IFLOG(LOG_RIP)
	syslog(LOG_DEBUG, "<%s>: calling rip_disable_rte()...", __FUNCTION__);

      dwnrte = rip_disable_rte(rte); /* copied */
      if (dwnrte) {
	dwnrte->rt_next = dwnrte->rt_prev = dwnrte;
	propagate(dwnrte);      /* triggered update */
	free(dwnrte);
	
	bgp_recover_rte(rte);
      }
    }

    if ((rte = rte->rt_next) ==  ripif->rip_adj_ribs_in)
      break;
  } /* while(rte) */

  taskhead = task_remove(taskhead);   /* erase lifetime */

  if (garbageyes) {
    garbage->tsk_rip             = ripif;
    garbage->tsk_timename        = RIP_GARBAGE_TIMER;
    garbage->tsk_timefull.tv_sec = RIP_T_GARBAGE;
    insque(garbage, taskhead);         /* taskhead exists. */
    task_timer_update(garbage);
  } else {
    free(garbage);
  }

  return;
}


/*
 *   rip_garbage_expired()
 */
void
rip_garbage_expired() {
  struct ripif    *ripif;
  struct rt_entry *rte;                         /* cursor */

  extern task     *taskhead;

  IFLOG(LOG_RIP)
    syslog(LOG_DEBUG, "<rip_garbage_expired>: invoked.");

  ripif = taskhead->tsk_rip;

  rte = ripif->rip_adj_ribs_in;
  if (rte)
    while(rte) {
      if (rte->rt_riptime == taskhead) {

	ripif->rip_adj_ribs_in 
	  = rte_remove(rte, ripif->rip_adj_ribs_in);

	if ((rte = ripif->rip_adj_ribs_in))
	  continue;
	else
	  break;
      }
      if ((rte = rte->rt_next) == ripif->rip_adj_ribs_in)
	break;
    }

  taskhead = task_remove(taskhead);

  IFLOG(LOG_RIP)
    syslog(LOG_DEBUG, "<rip_garbage_expired>: done.");
}

/*
 * Detect if a specified outgoing RIPng route should be filtered on the given
 * interface.
 * 1. If we specify to restrict rotes to the default, all non default routes
 *    should be filtered.
 * 2. If we specify the restiction list, filter the route unless it
 *    matches at least one entry of the list.
 * 3. If we filter the default route on the interface, filter it.
 * 4. If we specify the filter list, the route that matches
 *    at least one entry of the list should be filtered.
 */
int
rip_output_filter(struct ripif *ripif, struct ripinfo6 *ripinfo)
{
	struct filterset *f = &ripif->rip_filterset;

	if (output_filter_check(f, rip_use_sitelocal, ripinfo)) {
		IFLOG(LOG_RIP)
			syslog(LOG_DEBUG,
			       "<%s>: output route %s/%d on %s was filtered"
			       __FUNCTION__,
			       ip6str(&ripinfo->rip6_dest, 0),
			       ripinfo->rip6_plen,
			       ripif->rip_ife->ifi_ifn->if_name);
		return(1);
	}
	return(0);
}
