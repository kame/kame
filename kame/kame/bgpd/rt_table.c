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
#include "aspath.h"
#include "rt_table.h"
#include "bgp_var.h"
#include "in6.h"
#include "ripng.h"

/* alignment constraint for routing socket messages */
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

void
krt_init()
{
  int    mib[6];
  size_t msize;
  char *buf, *p, *lim;
  struct rt_msghdr *rtm;

  extern int rtsock;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET6;      /* Address family */
  mib[4] = NET_RT_DUMP;   /* Dump the kernel routing table */
  mib[5] = 0;             /* No flags */
  if (sysctl(mib, 6, NULL, &msize, NULL, 0) < 0)
    fatal("<krt_init>: sysctl estimate");
  if ((buf = (char *)malloc(msize)) == NULL)
    fatalx("<krt_init>: malloc");
  if (sysctl(mib, 6, buf, &msize, NULL, 0) < 0)
    fatal("<krt_init>: sysctl NET_RT_DUMP");

  if ((rtsock = socket(PF_ROUTE, SOCK_RAW, AF_INET6)) < 0)
    fatal("<krt_init>: routing socket");

  /* force Routing socket write-only */

  if (shutdown(rtsock, 0) < 0)
    fatal("<krt_init>: shutdown");

  lim = buf + msize;
  for (p = buf; p < lim; p += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)p;
    krt_entry(rtm);
  }
  free(buf);
}


/*
 *   krt_entry()
 *      Flush dinamic-network-routes. 
 *      Construct the initial "rt_entry" list.
 */
void
krt_entry(rtm)
     struct rt_msghdr *rtm;
{
  struct  sockaddr_in6 *sin6_dst, *sin6_gw, *sin6_mask;
  struct  sockaddr_in6 *sin6_genmask, *sin6_ifp;
  char   *rtmp, *ifname;
  char    buf[BUFSIZ];
  struct  rt_entry *rrt;
  struct  ripinfo6 *np;
  struct  ifinfo   *ife;
  int               s;

  extern  int       rtsock;

  /*  Interface  */
  if ((s = rtm->rtm_index))
    ifname = if_indextoname(s, buf);
    else 
      fatalx("<krt_entry>: Unkown interface");

  sin6_dst = sin6_gw = sin6_mask = sin6_genmask = sin6_ifp = 0;
  if ((rtm->rtm_flags & RTF_UP) == 0 ||
#ifdef __FreeBSD__
      (rtm->rtm_flags & (RTF_XRESOLVE|RTF_BLACKHOLE|RTF_WASCLONED))
#endif /* __FreeBSD__ */
#ifdef __bsdi__
      (rtm->rtm_flags & (RTF_XRESOLVE|RTF_BLACKHOLE|RTF_CLONED))
#endif /*__bsdi__*/
#if defined(__NetBSD__) || defined(__OpenBSD__)
      (rtm->rtm_flags & (RTF_XRESOLVE|RTF_BLACKHOLE))
#endif /* __NetBSD__ || __OpenBSD__ */
      )
    return;             /* not interested in the link route */



  rtmp = (char *)(rtm + 1);
  /* Destination */
  if ((rtm->rtm_addrs & RTA_DST) == 0) /* ignore routes without destination */
    return;                            /*                           address */
  sin6_dst = (struct sockaddr_in6 *)rtmp;

  if (!IN6_IS_ADDR_ROUTABLE(&sin6_dst->sin6_addr))
    return;

  rtmp += sin6_dst->sin6_len;               /* char pointer */

  if (rtm->rtm_addrs & RTA_GATEWAY) {
    sin6_gw = (struct sockaddr_in6 *)rtmp;
    rtmp += ROUNDUP(sin6_gw->sin6_len);
  }
  if (rtm->rtm_addrs & RTA_NETMASK) {
    sin6_mask = (struct sockaddr_in6 *)rtmp;
    rtmp += ROUNDUP(sin6_mask->sin6_len);
  }
  if (rtm->rtm_addrs & RTA_GENMASK) {
    sin6_genmask = (struct sockaddr_in6 *)rtmp;
    rtmp += ROUNDUP(sin6_genmask->sin6_len);
  }
  if (rtm->rtm_addrs & RTA_IFP) {
    sin6_ifp = (struct sockaddr_in6 *)rtmp;
    rtmp += ROUNDUP(sin6_ifp->sin6_len);
  }

  /* checking previously added P-to-P self route (1998/04/24) */
  if (IN6_IS_ADDR_LOOPBACK(&sin6_gw->sin6_addr))
    return;

  /* flush */
  if (!(rtm->rtm_flags & RTF_STATIC)  &&
       (rtm->rtm_flags & RTF_GATEWAY)) {
    int len;

    rtm->rtm_type = RTM_DELETE;
    rtm->rtm_seq  = 0;          /*  ???  */
    len = write(rtsock, (char *)rtm, rtm->rtm_msglen);
    if (len < (int)rtm->rtm_msglen) {
      fatalx("<krt_entry>: write failed routing socket");
    }
    return;
  }


  MALLOC(rrt, struct rt_entry);  /* a new space */

  np = &rrt->rt_ripinfo;

  rrt->rt_aspath  = NULL;        /* because I/F direct RTE */
  rrt->rt_riptime = NULL;

  np->rip6_metric = rtm->rtm_rmx.rmx_hopcount;  /* direct RTE metric = 0 */

  rrt->rt_flags = rtm->rtm_flags;
  np->rip6_dest = sin6_dst->sin6_addr;

  /* Prefix length (from routing socket) */
  if (rtm->rtm_flags & RTF_HOST)                  /* host route */
    np->rip6_plen = 128;
  else if (sin6_mask)                             /*   other    */
    np->rip6_plen = mask2len(&sin6_mask->sin6_addr);
  else
    np->rip6_plen = 0;


  /* Gateway (i.e. next hop) */
  if (sin6_gw == NULL)
    memset(&rrt->rt_gw, 0, sizeof(struct in6_addr));
  else
    rrt->rt_gw = sin6_gw->sin6_addr;

  /* Check gateway */
  if (!IN6_IS_ADDR_LINKLOCAL(&rrt->rt_gw)) {
    rrt->rt_flags |= RTF_NH_NOT_LLADDR;
  }

  if ((ife = find_if_by_index(s)) == NULL)
    fatalx("<krt_entry>: I/F not found");

  if (find_rte(rrt, ife->ifi_rte)) {    /* Already found ? */
    free(rrt);
    return;
  }

  rrt->rt_proto.rtp_type = RTPROTO_IF;
  rrt->rt_proto.rtp_if   = ife;

  /* Put "rrt" into the I/F's RTE-list */
  if (ife->ifi_rte != NULL) {
    insque(rrt, ife->ifi_rte);
  } else {
    rrt->rt_next = rrt;
    rrt->rt_prev = rrt;
    ife->ifi_rte = rrt;
  };

  /*
   * Add a route for our own address on a point-to-point interface.
   */
  if ((sin6_gw->sin6_family == AF_INET6) &&
      IN6_IS_ADDR_ROUTABLE(&sin6_gw->sin6_addr) &&
      ife->ifi_flags & IFF_POINTOPOINT) {
    struct rt_entry *rte;

    MALLOC(rte, struct rt_entry);  /* a new space */

    np = &rte->rt_ripinfo;

    np->rip6_dest   = sin6_gw->sin6_addr;    /* in6_addr              */
    np->rip6_plen   = 128;
    np->rip6_metric = 0;                     /* direct RTE metric = 0 */

    rte->rt_gw      = in6addr_loopback;

    rte->rt_flags = RTF_UP|RTF_GATEWAY|RTF_HOST;  /* UGH */

    rte->rt_proto.rtp_type = RTPROTO_IF;
    rte->rt_proto.rtp_if   = ife;

    addroute(rte, &rte->rt_gw, ife);
    /* Put "rte" into the I/F's RTE-list */
    insque(rte, ife->ifi_rte);
    return;
  }



  /*  End of krt_entry()  */
}



/*
 *    find_rte()
 */
struct rt_entry *
find_rte(key, base)
     struct rt_entry *key;
     struct rt_entry *base;
{
  struct rt_entry *rte;

  if ((key == NULL) ||
      ((rte = base) == NULL))
    return NULL;

  while(rte) {

    if (key->rt_ripinfo.rip6_plen == rte->rt_ripinfo.rip6_plen &&
	IN6_ARE_PRFX_EQUAL(&rte->rt_ripinfo.rip6_dest,
			   &key->rt_ripinfo.rip6_dest,
			   key->rt_ripinfo.rip6_plen))
      break;

    if ((rte = rte->rt_next) == base)
      return NULL;

    if (rte == rte->rt_next)
      fatalx("<find_rte>: BUG");
  }
  return rte;
}

int
set_nexthop(dst, ret_rte)
     struct in6_addr *dst;
     struct rt_entry *ret_rte;
{
  struct ifinfo   *ife;
  struct rt_entry *rte;
  struct ripif    *ripif;

  extern byte           ripyes;
  extern struct ifinfo *ifentry;
  extern struct ripif  *ripifs;

  /* flush old nexthop */
  memset(&ret_rte->rt_gw, 0, sizeof(struct in6_addr));
  ret_rte->rt_gwif = NULL;
  ret_rte->rt_gwsrc_type = RTPROTO_NONE;
  ret_rte->rt_gwsrc_entry = NULL;

  ife = ifentry; /* global */
  while(ife) {
    rte = ife->ifi_rte;
    while(rte) {
      if (IN6_ARE_PRFX_EQUAL(dst,
			     &rte->rt_ripinfo.rip6_dest,
			     rte->rt_ripinfo.rip6_plen)  &&
	  (rte->rt_flags & RTF_UP)) {
	memcpy(&ret_rte->rt_gw, &rte->rt_gw, sizeof(struct in6_addr));
	ret_rte->rt_gwif = ife;
	ret_rte->rt_gwsrc_type = RTPROTO_IF;
	ret_rte->rt_gwsrc_entry = rte;
	return 1;
      }
      if ((rte = rte->rt_next) == ife->ifi_rte)
	break;
    }
    if ((ife = ife->ifi_next) == ifentry)
      break;
  }

  if (ripyes) {
    ripif = ripifs; /* global */
    while(ripif) {
      rte = ripif->rip_adj_ribs_in;
      while(rte) {
	if (IN6_ARE_PRFX_EQUAL(dst,
			       &rte->rt_ripinfo.rip6_dest,
			       rte->rt_ripinfo.rip6_plen)  &&
	    (rte->rt_flags & RTF_UP)) {
	  memcpy(&ret_rte->rt_gw, &rte->rt_gw, sizeof(struct in6_addr));
	  ret_rte->rt_gwif = ripif->rip_ife;
	  ret_rte->rt_gwsrc_type = RTPROTO_RIP;
	  ret_rte->rt_gwsrc_entry = rte;
	  return 1;
	}
	if ((rte = rte->rt_next) == ripif->rip_adj_ribs_in)
	  break;
      }
      if ((ripif = ripif->rip_next) == ripifs)
	break;
    }
  }

  return 0;  /* not found */
}

/*
 *    find_nexthop()
 *     RETURN VALUES:   1:   found
 *                      0: not found
 */
int
find_nexthop(dst, gw, i)
     struct in6_addr *dst;
     struct in6_addr *gw;
     struct ifinfo   *i;
{
  struct ifinfo   *ife;
  struct rt_entry *rte;
  struct ripif    *ripif;
  char             in6txt[INET6_ADDRSTRLEN];

  extern byte           ripyes;
  extern struct ifinfo *ifentry;
  extern struct ripif  *ripifs;

  ife = ifentry; /* global */
  while(ife) {
    rte = ife->ifi_rte;
    while(rte) {
      if (IN6_ARE_PRFX_EQUAL(dst,
			     &rte->rt_ripinfo.rip6_dest,
			     rte->rt_ripinfo.rip6_plen)  &&
	  (rte->rt_flags & RTF_UP)) {
	memcpy(gw, &rte->rt_gw, sizeof(struct in6_addr));
	memcpy(i, ife, sizeof(struct ifinfo));
	return 1;
      }
      if ((rte = rte->rt_next) == ife->ifi_rte)
	break;
    }
    if ((ife = ife->ifi_next) == ifentry)
      break;
  }

  if (ripyes) {
    ripif = ripifs; /* global */
    while(ripif) {
      rte = ripif->rip_adj_ribs_in;
      while(rte) {
	if (IN6_ARE_PRFX_EQUAL(dst,
			       &rte->rt_ripinfo.rip6_dest,
			       rte->rt_ripinfo.rip6_plen)  &&
	    (rte->rt_flags & RTF_UP)) {
	  memcpy(gw,    &rte->rt_gw, sizeof(struct in6_addr));
	  memcpy(i, ripif->rip_ife, sizeof(struct ifinfo)); /* XXX */
	  return 1;
	}
	if ((rte = rte->rt_next) == ripif->rip_adj_ribs_in)
	  break;
      }
      if ((ripif = ripif->rip_next) == ripifs)
	break;
    }
  }

#if 0
  /*
   * It is not a good idea to refer BGP routes in order to find the nexthop
   * gateway for a BGP route. It is not only meaningless but could be harmful.
   */
  if (bgpyes) {
    bnp = bgb; /* global */
    while(bnp) {
      rte = bnp->rp_adj_ribs_in;
      while(rte) {
        if (IN6_ARE_PRFX_EQUAL(dst,
                               &rte->rt_ripinfo.rip6_dest,
                               rte->rt_ripinfo.rip6_plen)  &&
            (rte->rt_flags & RTF_UP)) {
          memcpy(gw,    &rte->rt_gw, sizeof(struct in6_addr));
	  memcpy(i, bnp->rp_ife, sizeof(struct ifinfo)); /* XXX */
          return 1;
        }
        if ((rte = rte->rt_next) == bnp->rp_adj_ribs_in)
          break;
      }
      if ((bnp = bnp->rp_next) == bgb)
        break;
    }
  }
#endif

  syslog(LOG_NOTICE, "<find_nexthop>: not found: %s",
	 inet_ntop(AF_INET6, &dst->s6_addr, in6txt, INET6_ADDRSTRLEN));


  return 0;  /* not found */
}

/*
 * find_filter()
 * RETURN VALUES:  1: found
 *                 0: not found
 */
int
find_filter(head, filter)
	struct filtinfo *head, *filter;
{
	struct filtinfo *search = head;

	while (search) {
		if (IN6_ARE_ADDR_EQUAL(&head->filtinfo_addr,
				       &filter->filtinfo_addr) &&
		    head->filtinfo_plen == filter->filtinfo_plen)
			return(1);

		if ((search = search->filtinfo_next) == head)
			break;
	}

	return(0);
}

/*
 *    addroute()
 */
int
addroute(rte, gw, ife)
        struct rt_entry       *rte;
        const struct in6_addr *gw;
        struct ifinfo         *ife;
{
        struct  ripinfo6 *np;
        static  u_long  seq = 0;
        u_char  buf[BUFSIZ];
        struct  rt_msghdr       *rtm;
        struct  sockaddr_in6    *sin;
        int     len, wlen;
	char    in6txt[INET6_ADDRSTRLEN];
	char    gw6txt[INET6_ADDRSTRLEN];

	extern int rtsock;
	extern pid_t pid;

	if (rte == NULL || gw == NULL || ife == NULL) {
	  syslog(LOG_ERR, "<%s>: invalid argument", __FUNCTION__);
	  return -1;
	}

	memset(in6txt, 0, INET6_ADDRSTRLEN);
	memset(gw6txt, 0, INET6_ADDRSTRLEN);
	memset(buf,    0, BUFSIZ);

	np = &rte->rt_ripinfo;
        memset(buf, 0, sizeof(buf));
        rtm = (struct rt_msghdr *)buf;
        rtm->rtm_type = RTM_ADD;
        rtm->rtm_version = RTM_VERSION;
        rtm->rtm_seq = seq++;
        rtm->rtm_pid = pid;
        rtm->rtm_flags = rte->rt_flags & RTF_ROUTE_H;
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFA;
	switch (rte->rt_proto.rtp_type) {
	case RTPROTO_RIP: case RTPROTO_OSPF: case RTPROTO_IF:
	  rtm->rtm_rmx.rmx_hopcount = np->rip6_metric;
	  break;
	case RTPROTO_BGP:
	  if (rte->rt_aspath == NULL)
	    fatalx("NULL AS path");
	  rtm->rtm_rmx.rmx_hopcount = aspath2cost(rte->rt_aspath);
	  break;
	default:
	  fatalx("<addroute>: BUG !");
	  break;
	}
        rtm->rtm_inits = RTV_HOPCOUNT;
        sin = (struct sockaddr_in6 *)&buf[sizeof(struct rt_msghdr)];
        /* Destination */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = np->rip6_dest;
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Gateway */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = *gw;
	if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr))
	  SET_IN6_LINKLOCAL_IFINDEX(&sin->sin6_addr, ife->ifi_ifn->if_index);
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Netmask */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        mask_nset(&sin->sin6_addr, np->rip6_plen);
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Interface */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = ife->ifi_laddr;
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));

        len = (char *)sin - (char *)buf;
        rtm->rtm_msglen = len;

	errno = 0;
        if ((wlen = write(rtsock, buf, len)) == len) {
#ifdef DEBUG
	  syslog(LOG_DEBUG, "<%s>: %s/%d gw=%s tag=%d%s, succeed",
		 __FUNCTION__,
		 inet_ntop(AF_INET6, &np->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 np->rip6_plen,
		 inet_ntop(AF_INET6, gw,            gw6txt, INET6_ADDRSTRLEN),
 		 ntohs(np->rip6_tag),
 		 rte->rt_flags & RTF_IGP_EGP_SYNC ? "(sync)":"");
#endif
	  aggr_ckconf(rte);
	  return 0;
	} else {
	  int errorlevel;

	  if (errno == EEXIST) {  /* doubtful "File exists" */
	    aggr_ckconf(rte);
	    return 0;
	  }

	  /*
	   * If the specified next hop is not a link-local address
	   * and it is an IBGP route, it may have been specified in a
	   * next hop field of a BGP4+. In IBGP cases, it is usually a off-link
	   * gateway, so adding the route is tend to fail.
	   */
	  if (rte->rt_proto.rtp_type == RTPROTO_BGP &&
	      rte->rt_proto.rtp_bgp->rp_mode & BGPO_IGP &&
	      !IN6_IS_ADDR_LINKLOCAL(gw))
		  errorlevel = LOG_DEBUG; /* use a lower log level */
	  else
		  errorlevel = LOG_ERR;

	  syslog(errorlevel,
		 "<%s>: %s/%d gw=%s, failed: %s",
		 __FUNCTION__,
		 inet_ntop(AF_INET6, &np->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 np->rip6_plen,
		 inet_ntop(AF_INET6, gw,             gw6txt, INET6_ADDRSTRLEN),
		 strerror(errno));
	  return -1;
	}

}



/*
 *    delroute()
 */
#define AGGR_DECLEM(rte) { if (rte->rt_aggr.ag_agg) \
			     rte->rt_aggr.ag_agg->rt_aggr.ag_refcnt -- ; }
int
delroute(rte, gw)
        struct rt_entry *rte;
        struct in6_addr *gw;
{
        struct ripinfo6 *rp;
        static  u_long  seq = 0;
        u_char  buf[BUFSIZ];
        struct  rt_msghdr       *rtm;
        struct  sockaddr_in6    *sin;
        int     len;
	char    in6txt[INET6_ADDRSTRLEN];
	char    gw6txt[INET6_ADDRSTRLEN];

	extern int rtsock;
	extern pid_t pid;

	if (rte == NULL || gw == NULL) {
	  syslog(LOG_ERR, "<%s>: invalid argument", __FUNCTION__);
	  return -1;
	}

	memset(buf,    0, BUFSIZ);
	memset(in6txt, 0, INET6_ADDRSTRLEN);
	memset(gw6txt, 0, INET6_ADDRSTRLEN);

	rp = &rte->rt_ripinfo;
        bzero(buf, sizeof(buf));
        rtm = (struct rt_msghdr *)buf;
        rtm->rtm_type = RTM_DELETE;
        rtm->rtm_version = RTM_VERSION;
        rtm->rtm_seq = seq++;
        rtm->rtm_pid = pid;
	rtm->rtm_flags  = rte->rt_flags & RTF_ROUTE_H;
        rtm->rtm_flags |= RTF_UP | RTF_GATEWAY;
/*       rtm->rtm_flags = RTF_UP | RTF_GATEWAY; */
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        sin = (struct sockaddr_in6 *)&buf[sizeof(struct rt_msghdr)];
        /* Destination */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = rp->rip6_dest;
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Gateway */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = *gw;
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Netmask */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        mask_nset(&sin->sin6_addr, rp->rip6_plen);
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));

        len = (char *)sin - (char *)buf;
        rtm->rtm_msglen = len;

	errno = 0;
        if (write(rtsock, buf, len) == len) {
#ifdef DEBUG
	  syslog(LOG_DEBUG, "<%s>: %s/%d gw=%s tag=%d%s, succeed",
		 __FUNCTION__,
		 inet_ntop(AF_INET6, &rp->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 rp->rip6_plen,
		 inet_ntop(AF_INET6, gw,            gw6txt, INET6_ADDRSTRLEN),
 		 ntohs(rp->rip6_tag),
 		 rte->rt_flags & RTF_IGP_EGP_SYNC ? "(sync)":"");
#endif
	  AGGR_DECLEM(rte);
	  return 0;
	} else {
	  if (errno == ESRCH) {  /* doubtful "No such process" */
	    AGGR_DECLEM(rte);
	    return 0;
	  }
	  syslog(LOG_ERR,
		 "<%s>: %s/%d gw=%s, failed: %s",
		 __FUNCTION__,
		 inet_ntop(AF_INET6, &rp->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 rp->rip6_plen,
		 inet_ntop(AF_INET6, gw,             gw6txt, INET6_ADDRSTRLEN),
		 strerror(errno));
	  return -1;
	}

}


/*
 *   chroute()
 *      Change metric.
 */
int
chroute(rte, gw, ife)
        struct rt_entry       *rte;
        const struct in6_addr *gw;
        struct ifinfo *ife;
{
        struct  ripinfo6 *np;
        static  u_long  seq = 0;
        u_char  buf[BUFSIZ];
        struct  rt_msghdr       *rtm;
        struct  sockaddr_in6    *sin;
        int     len, wlen;
	char    in6txt[INET6_ADDRSTRLEN];
	char    gw6txt[INET6_ADDRSTRLEN];

	extern int rtsock;
	extern pid_t pid;

	if (rte == NULL || gw == NULL || ife == NULL) {
	  syslog(LOG_ERR, "<chroute>: invalid argument");
	  return -1;
	}

	memset(in6txt, 0, INET6_ADDRSTRLEN);
	memset(gw6txt, 0, INET6_ADDRSTRLEN);
	memset(buf,    0, BUFSIZ);

	np = &rte->rt_ripinfo;
        memset(buf, 0, sizeof(buf));
        rtm = (struct rt_msghdr *)buf;
        rtm->rtm_type = RTM_CHANGE;
        rtm->rtm_version = RTM_VERSION;
        rtm->rtm_seq = seq++;
        rtm->rtm_pid = pid;
        rtm->rtm_flags = rte->rt_flags & RTF_ROUTE_H;
        rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFA;
	switch (rte->rt_proto.rtp_type) {
	case RTPROTO_RIP:
	  rtm->rtm_rmx.rmx_hopcount = np->rip6_metric;
	  break;
	case RTPROTO_BGP:
	  if (rte->rt_aspath == NULL)
	    fatalx("<chroute>: BUG !");
	  rtm->rtm_rmx.rmx_hopcount = aspath2cost(rte->rt_aspath);
	  break;
	default:
	  fatalx("<chroute>: BUG !");
	  break;
	}
        rtm->rtm_inits = RTV_HOPCOUNT;
        sin = (struct sockaddr_in6 *)&buf[sizeof(struct rt_msghdr)];
        /* Destination */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = np->rip6_dest;
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Gateway */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = *gw;
	if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr))
	  SET_IN6_LINKLOCAL_IFINDEX(&sin->sin6_addr, ife->ifi_ifn->if_index);
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Netmask */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        mask_nset(&sin->sin6_addr, np->rip6_plen);
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));
        /* Interface */
        sin->sin6_len = sizeof(struct sockaddr_in6);
        sin->sin6_family = AF_INET6;
        sin->sin6_addr = ife->ifi_laddr;
	sin = (struct sockaddr_in6 *)((char *)sin + ROUNDUP(sin->sin6_len));

        len = (char *)sin - (char *)buf;
        rtm->rtm_msglen = len;

        if ((wlen = write(rtsock, buf, len)) == len) {
#ifdef DEBUG
	  syslog(LOG_DEBUG, "<chroute>: %s/%d gw=%s met=%d, succeed",
		 inet_ntop(AF_INET6, &np->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 np->rip6_plen,
		 inet_ntop(AF_INET6, gw,            gw6txt, INET6_ADDRSTRLEN),
		 rtm->rtm_rmx.rmx_hopcount);
#endif
	} else {
	  syslog(LOG_ERR,
		 "<chroute>: %s/%d gw=%s met=%lu, failed: %s",
		 inet_ntop(AF_INET6, &np->rip6_dest, in6txt, INET6_ADDRSTRLEN),
		 np->rip6_plen,
		 inet_ntop(AF_INET6, gw,             gw6txt, INET6_ADDRSTRLEN),
		 (u_long)rtm->rtm_rmx.rmx_hopcount,
		 strerror(errno));
	  return -1;
	}

        return 0;  /*  End of chroute() */
}



/*
 *  igp_enable_rte()
 *     DESCRIPTION:  Kernel addroute().
 *                   Insert a rte into ripif|rpcb adj_ribs_in.
 *                   NextHop must be specified.
 *
 *     RETURN VALUES:  copy of rte.
 */
struct rt_entry *
igp_enable_rte(rte)
     struct rt_entry *rte;
{
  struct ifinfo   *ife;
  struct rt_entry **adj_ribs_in;
  struct rt_entry *crte;  /* copied */

  switch(rte->rt_proto.rtp_type) {
  case RTPROTO_RIP:
    ife         = rte->rt_proto.rtp_rip->rip_ife;
    adj_ribs_in = &(rte->rt_proto.rtp_rip->rip_adj_ribs_in);
    break;
  case RTPROTO_OSPF:
    ife         = rte->rt_proto.rtp_ospf->rp_ife;
    adj_ribs_in = &(rte->rt_proto.rtp_ospf->rp_adj_ribs_in);
    break;
  default:
    fatalx("<igp_enable_rte>: Bad routing protocol");
    /*NOTRECHED*/
  }

  if (rte->rt_flags & RTF_UP)
    if (addroute(rte, &rte->rt_gw, ife) != 0) {
      syslog(LOG_ERR, "%s: route couldn't be added.", __FUNCTION__);
      return NULL;
    }

  /* check if some BGP routes can be enabled by this route */
  bgp_enable_rte_by_igp(rte);

  if (*adj_ribs_in)
    insque(rte, *adj_ribs_in);
  else {
    rte->rt_next = rte->rt_prev = rte;
    *adj_ribs_in = rte;
  }

  MALLOC(crte, struct rt_entry);
  memcpy(crte, rte, sizeof(struct rt_entry));

  return crte;
}


/*
 *  rte_remove()
 *     Remove and Free ONE.  Exact match.
 *       If Solo entry, Frees ASpath, too.
 */
struct rt_entry *
rte_remove(key, base)
     struct rt_entry *key;
     struct rt_entry *base;
{
  struct rt_entry *rte;

#ifdef DEBUG2
  char    in6txt[INET6_ADDRSTRLEN];
  char    gw6txt[INET6_ADDRSTRLEN];
  memset(in6txt, 0, INET6_ADDRSTRLEN);
  memset(gw6txt, 0, INET6_ADDRSTRLEN);
#define RTE_LOG_REMOVE \
  syslog(LOG_DEBUG, "<rte_remove>: %s/%d gw=%s, removed",\
	 inet_ntop(AF_INET6, &rte->rt_ripinfo.rip6_dest,\
		   in6txt, INET6_ADDRSTRLEN),\
	 rte->rt_ripinfo.rip6_plen,\
	 inet_ntop(AF_INET6, &rte->rt_gw, gw6txt, INET6_ADDRSTRLEN))
#else
#define RTE_LOG_REMOVE
#endif

  if (key == NULL)
    return base;

  if ((rte = base) == NULL)
    return NULL;


  while(rte) {
    if (rte->rt_proto.rtp_type > RTPROTO_MAX)    /* safety check */
      fatalx("<rte_remove>: rt_proto.rtp_type corrupt");

    if (key == rte) {
	    RTE_LOG_REMOVE;
	    free_aspath(rte->rt_aspath); /* argument validation will be in free_aspath */

	    if (rte == base) {
		    /* RTE is the first entry of the list. Treat it carefully */
		    if (rte->rt_next == rte) {
			    /*
			     * There is no other RTE in the list.
			     * just free the etnry.
			     */
#ifdef DEBUG2
			    syslog(LOG_DEBUG, "<%s>: solo", __FUNCTION__);
#endif
			    free(rte);
			    return(NULL);
		    }
		    else {
			  rte = base->rt_next; /* advance pointer */
			  remque(base);
			  free(base);
			  return(rte);
		    }
	    }

	    remque(rte);
	    free(rte);
	    return base;
    }
    if ((rte = rte->rt_next) == base) {
#ifdef DEBUG2
      syslog(LOG_DEBUG, "<%s>: Not found", __FUNCTION__);
#endif
      return base;
    }
  }
  /* NOT REACHED */
#undef RTE_LOG_REMOVE
  return NULL;
}

struct rt_entry *
aggregatable(struct rt_entry *rte) {
  struct rt_entry *agg;
  extern struct rt_entry *aggregations;

  agg = aggregations;
  while(agg) {
    if (agg->rt_ripinfo.rip6_plen < rte->rt_ripinfo.rip6_plen &&
	IN6_ARE_PRFX_EQUAL(&agg->rt_ripinfo.rip6_dest,
			   &rte->rt_ripinfo.rip6_dest,
			   agg->rt_ripinfo.rip6_plen))
      return agg;
    if ((agg = agg->rt_next) == aggregations)
      break;
  }
  return NULL;
}

struct filtinfo *
filter_check(head, addr, plen)
	struct filtinfo *head;	/* must not be NULL */
	struct in6_addr *addr;
	int plen;
{
	struct filtinfo *filter = head;

	while(filter) {
		if (filter->filtinfo_plen <= plen &&
		    IN6_ARE_PRFX_EQUAL(&filter->filtinfo_addr, addr,
				       filter->filtinfo_plen)) {
			filter->filtinfo_stat++;
			return(filter);
		}

		if ((filter = filter->filtinfo_next) == head)
			break;
	}

	return(NULL);
}

struct filtinfo *
restrict_check(head, addr, plen)
	struct filtinfo *head;	/* must not be NULL */
	struct in6_addr *addr;
	int plen;
{
	struct filtinfo *restriction = head;

	while(restriction) {
		if (restriction->filtinfo_plen <= plen &&
		    IN6_ARE_PRFX_EQUAL(&restriction->filtinfo_addr, addr,
				       restriction->filtinfo_plen)) {
			restriction->filtinfo_stat++;
			return(restriction);
		}

		if ((restriction = restriction->filtinfo_next) == head)
			break;
	}

	return(NULL);
}

void
aggr_ckconf(rte)
     struct rt_entry *rte;    /* some specific route */
{
  struct rt_entry *agg;

  if ((agg = aggregatable(rte))) {
    agg->rt_aggr.ag_refcnt++;
    rte->rt_aggr.ag_agg       = agg;
    rte->rt_aggr.ag_flags    |= AGGR_NOADVD;
    if (find_rte(rte, agg->rt_aggr.ag_explt))
      rte->rt_aggr.ag_flags &= ~AGGR_NOADVD;
  }
}


void 
aggr_ifinit() {
  struct ifinfo        *ife;
  extern struct ifinfo *ifentry;

  ife = ifentry;
  while(ife) {
    struct rt_entry *rte;
    
    rte = ife->ifi_rte;
    while(rte) {
      aggr_ckconf(rte);     /* I/F initially */
      if ((rte = rte->rt_next) == ife->ifi_rte)
	break;
    } /* (rte) */
    
    if ((ife = ife->ifi_next) == ifentry)
      break;
  } /* (ife) */
}

void
aggr_flush() {
  struct rt_entry *agg;
  extern struct rt_entry *aggregations;

  agg = aggregations;
  while(agg) {
    agg->rt_aggr.ag_flags &= ~AGGR_ADVDONE;
    
    if ((agg = agg->rt_next) == aggregations)
      return;
  }
}



/*
 *   aggr_advable()
 *       1 ... O.K.
 *       0 ... N.G.
 */
int
aggr_advable(agg, rtp)
     struct rt_entry *agg;
     struct rtproto  *rtp;
{
  if (!agg || !rtp)
    return 0;

  if (agg->rt_aggr.ag_refcnt == 0 ||
      agg->rt_aggr.ag_flags  &  AGGR_ADVDONE)
    return 0;

  if (find_rtp(rtp, agg->rt_aggr.ag_rtp))
    return 1;
  else
    return 0;
}
