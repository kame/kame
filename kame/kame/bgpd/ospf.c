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
#include "in6.h"
#include "ospf.h"


int                  ospfsock;              /* socket for OSPF           */
byte                 ospfbuf[OSPF_BUFSIZ];
byte                 ospfpkt[OSPF_MAXPKT];  /* should discover path MTU  */
struct ospfrtr      *ospfrtrs; 
struct sockaddr_in6  ospfsin;               /* AllSPFRouters ff02::5     */
struct area         *areas;
int32_t              ls_sequence;           /* LS sequence number        */


/*
 * OSPF message types
 */
char *ospf_msgstr[] = {
  "",
  "Hello",
  "Database Description",
  "Link State Request",
  "Link State Update",
  "Link State Acknowledgment"};


/*
 *   ospf_init()
 */
void
ospf_init()
{
  int on;
#ifndef ADVANCEDAPI
  int hops;
#endif
  struct ifinfo        *ife;
  struct ipv6_mreq      mreq;
  task                 *tsk;

  extern fd_set         fdmask;
  extern struct ifinfo *ifentry;
  extern task          *taskhead;

  memset(&ospfsin,   0, sizeof(ospfsin));  /* sockaddr_in6  */
  memset(&mreq,      0, sizeof(mreq));
  ls_sequence = InitialSequenceNumber;


  MALLOC(areas, struct area);
  areas->ar_next = areas->ar_prev = areas;
  areas->ar_id   = 0;           /* the backbone */

  ife = ifentry;

  while(ife) {
    struct ospflink *ol;

    if (ife->ifi_flags & IFF_UP) {
	    MALLOC(ol, struct ospflink);
	    ol->ol_area = areas; /* XXX: backbone only */

	    ife->ifi_rtpinfo[RTPROTO_OSPF] = (caddr_t)ol;
    }

    if ((ife = ife->ifi_next) == ifentry)
      break;
  }


  if ((ospfsock = socket(PF_INET6, SOCK_RAW, IPPROTO_OSPF)) < 0) {
    fatal("<ospf_init>: socket");
  }

  ospfsin.sin6_family = AF_INET6;
  ospfsin.sin6_len    = sizeof(struct sockaddr_in6);

  /* XXX */
  if (bind(ospfsock, (struct sockaddr *)&ospfsin, sizeof(ospfsin)) < 0)
    fatal("<ospf_init>: bind");

  if (inet_pton(AF_INET6, ALLSPFROUTERS, &ospfsin.sin6_addr) != 1)
    fatal("<ospf_init>: inet_pton");
  mreq.ipv6mr_multiaddr = ospfsin.sin6_addr;

  ife = ifentry;
  while (ife) {   /*  foreach I/F  */
    mreq.ipv6mr_interface = ife->ifi_ifn->if_index;
    if (setsockopt(ospfsock, IPPROTO_IPV6,
		   IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
      fatal("<ospf_init>: setsockopt: IPV6_JOIN_GROUP");

    if ((ife = ife->ifi_next) == ifentry)
      break;
  }

#ifndef ADVANCEDAPI
  hops = OSPF_HOPLIMIT;
  if (setsockopt(ospfsock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		 &hops, sizeof(int)) < 0)
    fatal("<ospf_init>: setsockopt IPV6_MULTICAST_HOPS");
#endif /* ADVANCEDAPI */

  on = 0;
  if (setsockopt(ospfsock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		 &on, sizeof(on)) < 0)
    fatal("<ospf_init>: setsockopt IPV6_MULTICAST_LOOP");

#ifdef ADVANCEDAPI
  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(ospfsock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<ospf_init>: setsockopt(IPV6_RECVPKTINFO)");
#else  /* old adv. API */
  if (setsockopt(ospfsock, IPPROTO_IPV6, IPV6_PKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<ospf_init>: setsockopt(IPV6_PKTINFO)");
#endif 
  on = 1;
#ifdef IPV6_RECVPKTINFO
  if (setsockopt(ospfsock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<ospf_init>: setsockopt(IPV6_RECVPKTINFO)");
#else  /* old adv. API */
  if (setsockopt(ospfsock, IPPROTO_IPV6, IPV6_PKTINFO,
		 &on, sizeof(on)) < 0)
    fatal("<ospf_init>: setsockopt(IPV6_PKTINFO)");
#endif 
#endif /* ADVANCEDAPI */

  FD_SET(ospfsock,  &fdmask);   /* initialize */

  MALLOC(tsk, task);

  if (taskhead) {
    insque(tsk, taskhead);
  } else {
    taskhead      = tsk;
    tsk->tsk_next = tsk;
    tsk->tsk_prev = tsk;
  }
  tsk->tsk_timename         = OSPF_HELLO_TIMER;
  tsk->tsk_rip              = NULL;  /* XXX */
  tsk->tsk_timefull.tv_sec  = 1; /* immediately */ 
  tsk->tsk_timefull.tv_usec = 0;


  task_timer_update(tsk);

  /* End of ospf_init() */
}


/*
 *   ospf_hello()
 */
void
ospf_hello() {

  struct ifinfo         *ife;
  struct in6_pktinfo     spktinfo;
  struct ospfhdr        *ospfh;
  struct ospf_hello_hdr *ospfhello;


  extern u_int32_t       bgpIdentifier;
  extern struct ifinfo  *ifentry;
  extern task           *taskhead;


  memset(&ospfpkt, 0, OSPF_MAXPKT);

  ospfh = (struct ospfhdr *)ospfpkt;   /* outgoing OSPF header */
  ospfh->ospfh_vers    = OSPF_VERSION_3;
  ospfh->ospfh_type    = OSPF_PKT_HELLO;
  ospfh->ospfh_rtr_id  = bgpIdentifier;

  ospfhello = &ospfh->ospfh_hello;
  ospfhello->oh_helloint = htons(OSPF_T_HELLOINTERVAL);
  ospfhello->oh_deadint  = htons(OSPF_T_HELLOINTERVAL * 4);  /* XXX: ad-hoc */

  ife = ifentry;  /* global */
  while(ife) {
    /*  On all OSPF interfaces except virtual links,
        OSPF packets are sent using the interface's associated link-
        local unicast address as source. */
    spktinfo.ipi6_addr    = ife->ifi_laddr;  /* copy */
    spktinfo.ipi6_ifindex = ife->ifi_ifn->if_index;

    ospfhello->oh_if_id    = GET_IN6_IF_ID_OSPF(&ife->ifi_laddr);

    ospfh->ospfh_length    = htons(sizeof(struct ospfhdr)
				   - sizeof(union ospf_types)
				   + sizeof(struct ospf_hello_hdr));
    ospf_sendmsg(&ospfsin,     /* ff02::5             */
		 &spktinfo,    /* source address, I/F */
		 ntohs(ospfh->ospfh_length));

    if ((ife = ife->ifi_next) == ifentry)
      break;
  }

  taskhead->tsk_timefull.tv_sec = OSPF_T_HELLOINTERVAL;
  task_timer_update(taskhead);

  /* End of ospf_hello() */
}


/*
 *
 *  ospf_sendmsg()
 *     1. fill checkksum,
 *     2. Actually sendmsg.
 *
 */
void
ospf_sendmsg(sin, pktinfo, len)
     struct sockaddr_in6 *sin;      /* dst addr.port           */
     struct in6_pktinfo  *pktinfo;  /* src addr, outgoing I/F  */
     int                  len;      /* sending data            */
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

  struct ip6_pseudohdr  phdr;
  struct ospfhdr       *oh;
  u_int16_t             cksum;

#ifdef DEBUG_OSPF
  char                in6txt[INET6_ADDRSTRLEN];
  char              myin6txt[INET6_ADDRSTRLEN];
  char                 rtrid[INET_ADDRSTRLEN];
  char                areaid[INET_ADDRSTRLEN];
  char                ifname[IFNAMSIZ];

  memset(  in6txt, 0, INET6_ADDRSTRLEN);
  memset(myin6txt, 0, INET6_ADDRSTRLEN);
  memset(   rtrid, 0, INET_ADDRSTRLEN);
  memset(  areaid, 0, INET_ADDRSTRLEN);
  memset(  ifname, 0, IFNAMSIZ);
#endif

  memset(cmsg,  0,
         CMSG_SPACE(sizeof(struct in6_pktinfo)) +
         CMSG_SPACE(sizeof(int)));

  shoplimit = OSPF_HOPLIMIT;

/***  Adv. API  ***/
  tlen = sizeof(struct sockaddr_in6);
  smsghdr.msg_name       = (caddr_t)sin;    /* dest addr.port              */
  smsghdr.msg_namelen    = tlen;            /* size of address             */
  smsgiov.iov_base       = (void *)ospfpkt; /* buffer, base should be void */
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
      setsockopt(ospfsock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		 &pktinfo->ipi6_ifindex, sizeof(u_int)) < 0) {
      fatal("<ospf_sendmsg>: IPV6_MULTICAST_IF");
  }
#endif /* ADVANCEDAPI */

  memset(&phdr, 0, sizeof(phdr));
  phdr.ph6_src   = pktinfo->ipi6_addr;
  phdr.ph6_dst   = sin->sin6_addr;
  phdr.ph6_uplen = len;
  phdr.ph6_nxt   = IPPROTO_OSPF;
  oh             = (struct ospfhdr *)ospfpkt;

  /* Before computing the checksum, the checksum field in the OSPF packet
     header is set to 0. [Page 56] */
  oh->ospfh_cksum = 0;

  cksum = ip6_cksum(&phdr, ospfpkt);
  oh->ospfh_cksum = htons(cksum);
/*
  syslog(LOG_ERR,
	 "<ospf_sendmsg>: checksum =%x, if=%d",
	 oh->ospfh_cksum, pktinfo->ipi6_ifindex);
*/
  if ((slen = sendmsg(ospfsock, &smsghdr, 0)) != len) {
    syslog(LOG_ERR,                            /* spoofing or misconfig ? */
	   "<ospf_sendmsg>: sendmsg: %s", strerror(errno));
    return;
  }

#ifdef DEBUG_OSPF
  syslog(LOG_DEBUG,
	 "OSPFv3 SENT %s(%s) -> %s ",
	 inet_ntop(AF_INET6, &pktinfo->ipi6_addr, myin6txt, INET6_ADDRSTRLEN),
	 if_indextoname(pktinfo->ipi6_ifindex, ifname),
	 inet_ntop(AF_INET6, &sin->sin6_addr, in6txt, INET6_ADDRSTRLEN));
  syslog(LOG_DEBUG,
	 "OSPFv3 SENT %s  Len: %d", ospf_msgstr[oh->ospfh_type], len);
  syslog(LOG_DEBUG,
	 "OSPFv3 SENT RouterID: %s  Area: %s  Checksum:0x%x",
	 inet_ntop(AF_INET, &oh->ospfh_rtr_id,  rtrid,  INET_ADDRSTRLEN),
	 inet_ntop(AF_INET, &oh->ospfh_area_id, areaid, INET_ADDRSTRLEN),
	 oh->ospfh_cksum);
#endif


  /* End of ospf_sendmsg */
}



struct sockaddr_in6 fsock;  /* sender's address */
/*
 *
 *   ospf_input()
 *
 */
void 
ospf_input()
{
  int                  len;    /* recvmsg                               */
  int                  flen;   /* sizeof From addr (for Adv. API)       */
  struct ifinfo       *ife;
  struct ospflink     *ol;
  struct ospfhdr      *oh;     /* OSPF header                           */
  struct msghdr        rmsghdr;            /* Adv. API                  */
  struct iovec         rmsgiov;            /* buffer for data (gather)  */
                                           /* buffer for ancillary data */
  char   cmsg[CMSG_SPACE(sizeof(struct in6_pktinfo)) + 
	      CMSG_SPACE(sizeof(int))];
  struct cmsghdr      *ch;                 /* Adv. API */
  struct in6_pktinfo  *rpktinfo;           /* received I/F address */
  struct in6_pktinfo   spktinfo;           /* sending source I/F   */
  int                 *rhoplimit;          /* Adv. API */

  struct ip6_pseudohdr phdr;
  u_int16_t            cksum;
  struct rpcb         *nbr;

  extern struct ifinfo *ifentry;

#ifdef DEBUG_OSPF
  char                in6txt[INET6_ADDRSTRLEN];
  char              myin6txt[INET6_ADDRSTRLEN];
  char                 rtrid[INET_ADDRSTRLEN];
  char                areaid[INET_ADDRSTRLEN];
  char                ifname[IFNAMSIZ];

  memset(in6txt,   0, INET6_ADDRSTRLEN);
  memset(myin6txt, 0, INET6_ADDRSTRLEN);
  memset(   rtrid, 0, INET_ADDRSTRLEN);
  memset(  areaid, 0, INET_ADDRSTRLEN);
  memset(  ifname, 0, IFNAMSIZ);
#endif

  memset(&fsock,    0, sizeof(struct sockaddr_in6)); /* sender's address   */
  memset(ospfbuf,   0, OSPF_BUFSIZ);
  memset(ospfpkt,   0, OSPF_MAXPKT);
  memset(&rmsghdr,  0, sizeof(struct msghdr));
  memset(&rmsgiov,  0, sizeof(struct iovec));
  memset(cmsg,      0, CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	               CMSG_SPACE(sizeof(int)));
  memset(&spktinfo, 0, sizeof(struct in6_pktinfo));
  rpktinfo  = NULL;
  rhoplimit = NULL;

/***  Adv. API  ***/
  flen = sizeof(struct sockaddr_in6);
  rmsghdr.msg_name       = (caddr_t)&fsock; /* sender's address            */
  rmsghdr.msg_namelen    = flen;            /* size of address             */
  rmsgiov.iov_base       = (void *)ospfbuf; /* buffer, base should be void */
  rmsgiov.iov_len        = sizeof(ospfbuf); /* 1500 (receiving buffer len) */
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
  if ((len = recvmsg(ospfsock, &rmsghdr, 0)) < 0)
    fatal("<ospf_input>: recvmsg");


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
	ch->cmsg_type  == IPV6_HOPLIMIT &&     /* may not be supported */
	ch->cmsg_len   == CMSG_LEN(sizeof(int))) {
      rhoplimit = (int *)CMSG_DATA(ch);
    }
  }

  if (rpktinfo == NULL) {
    fatalx("<ospf_input>: Can't get received interface");
    return;
  }
#else  /* for older hydranger */
  {
      struct ifinfo *ife;
      static struct in6_pktinfo rrpktinfo;

      if ((ife = find_if_by_addr(&fsock.sin6_addr)) == NULL)
	  fatalx("<ospf_input>: find_if_by_addr");
      rrpktinfo.ipi6_ifindex = ife->ifi_ifn->if_index;
      rpktinfo = &rrpktinfo;

  }
#endif /* ADVANCEDAPI */

#ifdef DEBUG_OSPF
  syslog(LOG_DEBUG, "OSPFv3 RECV %s -> %s(%s)",
	 inet_ntop(AF_INET6, &fsock.sin6_addr, in6txt, INET6_ADDRSTRLEN),
	 inet_ntop(AF_INET6, &rpktinfo->ipi6_addr, myin6txt, INET6_ADDRSTRLEN),
	 if_indextoname(rpktinfo->ipi6_ifindex, ifname));
#endif


  /* Locally originated packets should not be passed on to OSPF.
     That is, the source IPv6 adddress should be examined to make sure
     this is not a multicast packet that the router itself generated.  */
  ife = ifentry;
  while(ife) {
    if (IN6_ARE_ADDR_EQUAL(&ife->ifi_laddr, &fsock.sin6_addr)) {
      return;
    }
    if ((ife = ife->ifi_next) == ifentry)
      break; /* while */
  }


  /* the interface it was received on [OSPF-v2 pp.51] */
  if ((ife = find_if_by_index((u_int)rpktinfo->ipi6_ifindex)) == NULL) {
    syslog(LOG_ERR,
	   "<ospf_input>: OSPFv3 received at Unknown I/F %d (ignored)",
	   rpktinfo->ipi6_ifindex);
    return;
  }

  if (len < sizeof(struct ip6_hdr) + sizeof(struct ospfhdr))
    return;

  oh = (struct ospfhdr *)(ospfbuf + IPV6_HDRLEN);

#ifdef DEBUG_OSPF
  syslog(LOG_DEBUG, "OSPFv3 RECV RouterID: %s  Area: %s  Checksum:0x%x",
	 inet_ntop(AF_INET, &oh->ospfh_rtr_id,  rtrid,  INET_ADDRSTRLEN),
	 inet_ntop(AF_INET, &oh->ospfh_area_id, areaid, INET_ADDRSTRLEN),
	 oh->ospfh_cksum);
#endif

  memset(&phdr, 0, sizeof(phdr));
  phdr.ph6_src   = fsock.sin6_addr;
  phdr.ph6_dst   = rpktinfo->ipi6_addr;
  phdr.ph6_uplen = len - IPV6_HDRLEN;
  phdr.ph6_nxt   = IPPROTO_OSPF;

  cksum          = ntohs(oh->ospfh_cksum);
  /* Before computing the checksum, the checksum field in the OSPF packet
     header is set to 0. [Page 56] */
  oh->ospfh_cksum = 0;

  if (cksum != ip6_cksum(&phdr, (u_char *)oh)) {
    syslog(LOG_NOTICE, "OSPFv3 RECV invalid Checksum: rcvd=0x%x, calcd=0x%x",
	   cksum, ip6_cksum(&phdr, ospfbuf));
    return;
  }


  /*  The version number field must specify protocol version  3. */
  if (oh->ospfh_vers != OSPF_VERSION_3) {
    syslog(LOG_ERR, "<ospf_input>: Unknown OSPF version %d", oh->ospfh_vers);
    return;
  }

  /* The Area ID found in the OSPF header must be verified. */
  ol = (struct ospflink *)ife->ifi_rtpinfo[RTPROTO_OSPF];
  if (ol->ol_area->ar_id != oh->ospfh_area_id)
    return;


  if (ntohs(oh->ospfh_length) > len)
    return;


  switch (oh->ospfh_type) {         /* received type */

  case OSPF_PKT_HELLO:
#ifdef DEBUG_OSPF
    syslog(LOG_DEBUG, "OSPFv3 RECV %s  Len: %d",
	   ospf_msgstr[oh->ospfh_type], ntohs(oh->ospfh_length));
#endif
    ospf_process_hello(oh, ife);
    break;


    /* All other packet types are sent/received only on adjacencies.
       [OSPFv2 pp.53] */
  case OSPF_PKT_DD:
#ifdef DEBUG_OSPF
    syslog(LOG_DEBUG, "OSPFv3 RECV %s Len: %d",
	   ospf_msgstr[oh->ospfh_type], ntohs(oh->ospfh_length));
#endif
    if ((nbr = rpcblookup(ol->ol_nbrs, oh->ospfh_rtr_id)) == NULL)
      return;
    ospf_process_dd(oh, nbr);
    break;
  
  default:
    syslog(LOG_ERR,
	   "<ospf_input>: Unknow OSPF type %d", oh->ospfh_type);
    break;
  }

  return; 
}


/*
 *   ospf_process_hello()
 */
void
ospf_process_hello(oh, ife)
     struct ospfhdr *oh;
     struct ifinfo  *ife;
{
  struct rpcb        *nbr;
  struct ospflink    *ol;
  struct ospfhdr     *ospfh;
  struct ospf_db_hdr *ospfdd;
  struct in6_pktinfo  spktinfo;
  int len;  /* sending OSPF packet length */

  extern u_int32_t    bgpIdentifier;


  ol = (struct ospflink *)ife->ifi_rtpinfo[RTPROTO_OSPF];

  if ((nbr = rpcblookup(ol->ol_nbrs, oh->ospfh_rtr_id)) == NULL) {
    MALLOC(nbr, struct rpcb);
    nbr->rp_ife  = ife;
    nbr->rp_id   = oh->ospfh_rtr_id;

    if (ol->ol_nbrs)
      insque(nbr, ol->ol_nbrs);
    else {
      nbr->rp_next = nbr->rp_prev = nbr;
      ol->ol_nbrs  = nbr;
    }

    memset(&ospfpkt, 0, OSPF_MAXPKT);
    ospfh   = (struct ospfhdr *)ospfpkt;

    ospfh->ospfh_vers   = OSPF_VERSION_3;
    ospfh->ospfh_type   = OSPF_PKT_DD;
    ospfh->ospfh_rtr_id = bgpIdentifier;

    ospfdd = &ospfh->ospfh_database;
    ospfdd->od_ifmtu  = htons(MINMTU);
    ospfdd->od_i_m_ms |= bit_I;
    ospfdd->od_i_m_ms |= bit_MS;

    len = sizeof(struct ospfhdr) - sizeof(union ospf_types)
          + sizeof(struct ospf_db_hdr);

    len += ospf_make_dump((u_char *)(ospfdd + 1));  /* give buffer */

    ospfh->ospfh_length    = htons(len);

    spktinfo.ipi6_addr    = ife->ifi_laddr;  /* copy */
    spktinfo.ipi6_ifindex = ife->ifi_ifn->if_index;

    ospf_sendmsg(&fsock,       /* sender's address    */
		 &spktinfo,    /* source address, I/F */
		 ntohs(ospfh->ospfh_length));
  }
  /*  End of ospf_process_hello()  */
}


/*
 *   ospf_process_dd()
 *      The incoming Database Description Packet has already been associated 
 *      with a neighbor and receiving interface by the generic input packet
 *      processing.
 */
void
ospf_process_dd(oh, nbr)
     struct ospfhdr *oh;
     struct rpcb    *nbr;
{
  struct ospflink      *ol;
  struct ospf_db_hdr   *ospfdd;
  struct lsahdr        *lsahdr;
  struct ospf_prfx     *opx;

  struct rt_entry      *uprte;

  int                   len;   /* left       */

  extern struct ifinfo *ifentry;
#ifdef DEBUG_OSPF
  char                in6txt[INET6_ADDRSTRLEN];
  memset(in6txt, 0, INET_ADDRSTRLEN);
#endif

  len = htons(oh->ospfh_length) -
         (sizeof(struct ospfhdr) - sizeof(union ospf_types)
          + sizeof(struct ospf_db_hdr));  /* now len is of unread LSAs */
  
  ol = (struct ospflink *)(nbr->rp_ife->ifi_rtpinfo[RTPROTO_OSPF]);
  ospfdd = &oh->ospfh_database;

  if (len < sizeof(struct lsahdr))
    return;

  lsahdr = (struct lsahdr *)(ospfdd + 1);

  while(lsahdr) {  /* all LSAs */
    u_int16_t lstype;
    if (lsahdr->lsa_adv_rtr == nbr->rp_id) { /* off-link LSA not implemented */
      lstype = ntohs(lsahdr->lsa_lstype) & ~bit_U & ~bit_S2 & ~bit_S1; 
      switch(lstype) {
      case LS_PREFIX: {
	struct iap_lsa   *iap;
	int num;    /* # prefixes */

	if ((ntohs(lsahdr->lsa_length) <
	     sizeof(struct lsahdr) + sizeof(struct iap_lsa)) ||
	    (ntohs(lsahdr->lsa_length) > len))
	  return;   /* Bad Length */ 

	len -= sizeof(struct lsahdr) + sizeof(struct iap_lsa);
	iap = (struct iap_lsa *)(lsahdr + 1);
	opx = (struct ospf_prfx *)(iap + 1);

	for (num = ntohs(iap->iap_num) ; num > 0 ; num--) {
	  struct rt_entry *rte, *orte;
	  struct ripinfo6 *np;
	  struct ifinfo   *ife;
	  int              poctets = POCTETS(opx->opx_plen);
	  int              plen4w; /* 32-bit (4-byte) word boudary */

	  if (len < sizeof(struct ospf_prfx) + poctets)
	    return;

	  MALLOC(rte, struct rt_entry);

	  /*   XXX: NOT SPF at all.  */
	  rte->rt_gw    = fsock.sin6_addr; /* sender's */
	  rte->rt_flags = RTF_UP|RTF_GATEWAY;
	  np = &rte->rt_ripinfo;
	  memcpy(&np->rip6_dest, (u_char *)(opx+1), poctets);
	  np->rip6_plen   = opx->opx_plen;
	  np->rip6_metric = (u_char)ntohs(opx->opx_metric);
	  mask_nclear(&np->rip6_dest, np->rip6_plen);

	  rte->rt_proto.rtp_type = RTPROTO_OSPF;
	  rte->rt_proto.rtp_ospf = nbr;

#ifdef DEBUG_OSPF
	  syslog(LOG_DEBUG, "OSPFv3 RECV\t%s/%d (%d)",
		 inet_ntop(AF_INET6, &np->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 np->rip6_plen, np->rip6_metric);
#endif

	  /**  check I/F addrs  **/



	  /**  check I/F routes **/
	  ife = ifentry;
	  while(ife) {
	    if ((orte = find_rte(rte, ife->ifi_rte)))
	      break;
	    if ((ife = ife->ifi_next) == ifentry)
	      break;
	  }
	  if (orte != NULL) {  /* I/F direct route (most preferable) */
#ifdef DEBUG_OSPF
	    syslog(LOG_DEBUG,
		   "<ospf_process_dd>: I/F direct route cannot overwritten");
#endif
	    rte = NULL;
	  }

	  if (find_rte(rte, nbr->rp_adj_ribs_in))
	    rte = NULL;

	  if (rte) {
	    uprte = igp_enable_rte(rte);   /* copied */
	    free(uprte); /* XXX: ad-hoc */
	  }

	  plen4w = poctets%4  ? (poctets/4 + 1) * 4 :  poctets;

	  len -= (sizeof(struct ospf_prfx) + poctets);
	  opx = (struct ospf_prfx *)((u_char *)(opx + 1) + plen4w);
	}
      }
      default:
	break;
      }
    }
  }
  /*  End of ospf_process_dd()  */
}



/*
 *  ospf_make_dump()
 *      RETURN VALUES: length of buf
 */
int
ospf_make_dump(buf)
     u_char *buf;
{
  struct ifinfo    *ife;
  struct lsahdr    *lsahdr;
  struct iap_lsa   *iap;
  struct ospf_prfx *opx;
  int               len;     /* length of the LSA includes LSA header */
  int               num = 0;


  extern u_int32_t      bgpIdentifier;
  extern struct ifinfo *ifentry;

  lsahdr = (struct lsahdr *)buf;

  /*  Intra-Area-Prefix-LSAs:  LS type = 9  */
  /*         (for attached network)         */
  lsahdr->lsa_age     = 0;        /* [OSPFv6 page.24]; newly (re)originated */
  lsahdr->lsa_lstype  = htons(LS_PREFIX | bit_S1); /* area scope            */
  lsahdr->lsa_lsid    = htons(ls_sequence);        /* or something          */
  lsahdr->lsa_adv_rtr = bgpIdentifier;             /* Originated Router ID  */
  lsahdr->lsa_seq     = htons(ls_sequence);

  ls_sequence++;


  iap = (struct iap_lsa *)(lsahdr + 1);
  iap->iap_ref_lstype  = htons(LS_RTR | bit_S1);   /* router-LSA reference  */
  iap->iap_ref_lsid    = 0;
  iap->iap_ref_adv_rtr = bgpIdentifier;

  opx = (struct ospf_prfx *)(iap + 1);

  ife = ifentry;
  while(ife) {
    struct rt_entry  *rte;

    rte = ife->ifi_rte;  /* I/F direct RTEs */
    while(rte) {
      struct ripinfo6 *np      = &rte->rt_ripinfo;
      int              poctets = POCTETS(np->rip6_plen);
      int              plen4w; /* 32-bit (4-byte) word boudary */

      opx->opx_plen   = np->rip6_plen;
      opx->opx_opts   = 0;
      opx->opx_metric = htons(np->rip6_metric + 1);
      memcpy(opx + 1,  &np->rip6_dest, poctets);

      plen4w = poctets%4  ? (poctets/4 + 1) * 4 :  poctets;

      opx = (struct ospf_prfx *)((u_char *)(opx + 1)  +  plen4w);
      num++;

      if ((rte = rte->rt_next) == ife->ifi_rte)
	break;
    }/* (rte) */
    
    if ((ife = ife->ifi_next) == ifentry)
      break; /* (ife) */
  }

  iap->iap_num = htons(num);

  len =  (u_char *)opx - buf;
  lsahdr->lsa_length  = htons(len);

  /**  LS checksum  **/
  lsahdr->lsa_lscksum = htons(lsa_cksum(buf, len));

  return len;

  /* End of ospf_make_dump()  */
}


u_int16_t
lsa_cksum(lsa, len)
     u_char *lsa;
     int     len;
{
  u_int32_t sum = 0;

  while(len > 1) {
    sum += *((u_int16_t *) lsa)++;
    if (sum & 0x80000000)
      sum = (sum & 0xffff) + (sum >> 16);
    len -= 2;
  }

  if (len)
    sum += (u_int16_t)*(u_char *)lsa;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}
