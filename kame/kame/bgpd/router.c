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

/*
 *    rpcblookup()
 *      RETURN VALUES:   a Pointer:  found
 *                       NULL     : not found
 *
 *      DESCRIPTION:     find a router by ID.
 */
struct rpcb *
rpcblookup(head, id)
     struct rpcb *head;  /* list */
     u_int32_t    id;
{
  struct rpcb *rp;
  
  if (id == 0)
    return NULL;

  rp = head;
  while(rp) {
    if (rp->rp_id == id)
      return rp;

    if ((rp = rp->rp_next) == head)
      break;
  }
  return NULL;
}


/*
 *    find_rtp()
 */
struct rtproto *
find_rtp(key, base)
     struct rtproto *key;
     struct rtproto *base;
{ 
  struct rtproto *rtp;

  if ((key == NULL) ||
      ((rtp = base) == NULL))
    return NULL;

  while(rtp) {
    if (rtp->rtp_type == key->rtp_type)
      switch (key->rtp_type) {
      case RTPROTO_IF:
	if (key->rtp_if == rtp->rtp_if)
	  return rtp;	
	break;
      case RTPROTO_BGP:
	if (key->rtp_bgp->rp_mode & BGPO_IGP) { /* IBGP, compare BGP-ID */
		if ((key->rtp_bgp->rp_id &&
		     key->rtp_bgp->rp_id == rtp->rtp_bgp->rp_id) ||
		    sa6_equal(&key->rtp_bgp->rp_addr, &rtp->rtp_bgp->rp_addr))
			return(rtp);
	} else {                                  /* EBGP, compare AS num */
		if (key->rtp_bgp->rp_as == rtp->rtp_bgp->rp_as)
			return(rtp);
	}
	break;
      case RTPROTO_RIP:
	if (rtp->rtp_rip == key->rtp_rip)
	  return rtp;
	break;
      default:
	fatalx("<find_rtp>: BUG !");
	break;
      }

    if ((rtp = rtp->rtp_next) == base)
      return NULL;
  }

  return NULL; /* NOT REACHED */ 
}

/*
 *   propagate()
 */
void
propagate(rte)
     struct rt_entry *rte;       /* list               */
{
  struct rtproto  *srcrtp;    /* rtproto (struct rpcb), which RTEs got  */
  struct rt_entry *last;      /* (1998/05/29) */
  extern byte      bgpyes;
  extern byte      ripyes;

  if (rte == NULL) {
    IFLOG(LOG_BGPROUTE)
      syslog(LOG_DEBUG, "<%s>: Nothing to do.", __FUNCTION__);
    return;
  }

  srcrtp = &rte->rt_proto;

  if (bgpyes) {
    struct bgpcblist  *dist, *disthead;
    struct rpcb *bnp;

    disthead = make_bgpcb_list();
    for (dist = disthead; dist; dist = dist->next) {
	    bnp = dist->bnp;
	     /*
	      * XXX: bnp might be closed or even freed during the loop,
	      * so the validity check is necessary.
	      */
	    if (bgp_rpcb_isvalid(bnp) &&
		find_rtp(srcrtp, bnp->rp_adj_ribs_out)) {
		    struct rt_entry *irte;

		    irte = rte;  /* iw97 */
		    while (irte) { /* pointer maybe shifted (1998/05/29) */
			    if ((last = bgp_send_withdrawn(bnp, irte, rte)) ==
				NULL) {
				    bgp_cease(bnp);
				    break;
			    }

			    if ((irte != rte) && (last == rte)) {
				    break;
			    }
			    if ((irte = last->rt_next) == rte) {
				    break;
			    }
		    } /* while(irte) */
	    }
    }
    free_bgpcb_list(disthead);
  }

  if (ripyes) {
    struct ripif        *ripif;        /* Propagated to... */
    struct in6_pktinfo   spktinfo;
    struct riphdr       *rp;  
    int                  nn;

    extern struct sockaddr_in6  ripsin; /* ff02::9  */
    extern struct ripif        *ripifs;
    extern byte                 rippkt[], ripbuf[];

    rp = (struct riphdr *)rippkt;    /* outgoing RIPng header   */
    rp->riph_cmd   = RIPNGCMD_RESPONSE;
    rp->riph_vers  = RIPNG_VERSION;
    rp->riph_zero2 = 0;


    ripif = ripifs;
    while(ripif) {
      if ((ripif->rip_mode & IFS_NORIPOUT) == 0 &&
	  find_rtp(srcrtp, ripif->rip_adj_ribs_out) &&
	  ripif != srcrtp->rtp_rip) {  /* split holizon */
	int mm;  /* current */
	int done = 0;


	nn = rip_make_data(rte, NULL, ripif->rip_mode);  /* withdrawning: (1998/06/11) */


	spktinfo.ipi6_addr    = ripif->rip_ife->ifi_laddr;  /* copy */
	spktinfo.ipi6_ifindex = ripif->rip_ife->ifi_ifn->if_index;


	while(1) {
	  mm = MIN(nn - done, RIPNG_MAXRTES);
	  memcpy(&rippkt[sizeof(struct riphdr)],
		 &ripbuf[sizeof(struct riphdr) + done*sizeof(struct ripinfo6)],
		 mm * sizeof(struct ripinfo6));

	  if (rip_sendmsg(&ripsin,
			  &spktinfo,
			  sizeof(struct riphdr) +
			  mm * sizeof(struct ripinfo6)))
	    ripif->rip_respfail++;
	  ripif->rip_responsesent++;

	  done += mm;
	  if (done == nn) break;
	}
      }
      if ((ripif = ripif->rip_next) == ripifs)
	break;
    }
  }
}

/*
 *   redistribute()
 *     DESCRIPTION: Redistribute to IGP first,
 *                    then, Redistribute to iBGP. see [rfc1772]
 */
void
redistribute(rte)
     struct rt_entry *rte;   /* Redistribute RTEs                         */
{
  struct rtproto *srcrtp;    /* rtproto (struct rpcb), which new RTEs got */

  extern byte     bgpyes;
  extern byte     ripyes;
 
  if (rte)
    srcrtp = &rte->rt_proto;
  else {
    IFLOG(LOG_BGPROUTE)
      syslog(LOG_DEBUG, "<%s>: Nothing to do.", __FUNCTION__);
    return;
  }

  if (ripyes) {
    struct ripif        *ripif;   /* Redistributed to...  */
    struct in6_pktinfo   spktinfo;
    struct riphdr       *rp;  
    int                  nn;

    extern struct sockaddr_in6  ripsin; /* ff02::9  */
    extern struct ripif        *ripifs;
    extern byte                 rippkt[], ripbuf[];

    rp = (struct riphdr *)rippkt;    /* outgoing RIPng header   */
    rp->riph_cmd   = RIPNGCMD_RESPONSE;
    rp->riph_vers  = RIPNG_VERSION;
    rp->riph_zero2 = 0;


    ripif = ripifs;
    while(ripif) {

      if ((ripif->rip_mode & IFS_NORIPOUT) == 0 &&
	  find_rtp(srcrtp , ripif->rip_adj_ribs_out) &&
	  ripif != srcrtp->rtp_rip) {  /* split holizon */
	int mm;  /* current */
	int done = 0;

	aggr_flush();                     /* (1998/06/11) */
	nn = rip_make_data(rte, ripif, ripif->rip_mode);


	spktinfo.ipi6_addr    = ripif->rip_ife->ifi_laddr;  /* copy */
	spktinfo.ipi6_ifindex = ripif->rip_ife->ifi_ifn->if_index;

	while(1) {
	  mm = MIN(nn - done, RIPNG_MAXRTES);
	  memcpy(&rippkt[sizeof(struct riphdr)],
		 &ripbuf[sizeof(struct riphdr) + done*sizeof(struct ripinfo6)],
		 mm * sizeof(struct ripinfo6));

	  if (rip_sendmsg(&ripsin,
			  &spktinfo,
			  sizeof(struct riphdr) +
			  mm * sizeof(struct ripinfo6)))
	    ripif->rip_respfail++;
	  ripif->rip_responsesent++;

	  done += mm;
	  if (done == nn) break;
	}
      }
      if ((ripif = ripif->rip_next) == ripifs)
	break;
    }
  }

  if (bgpyes) {
    struct rpcb        *bnp;         /* Redistributed to...  */
    struct bgpcblist  *dist, *disthead;

    disthead = make_bgpcb_list();
    for (dist = disthead; dist; dist = dist->next) {
	    bnp = dist->bnp;
	     /*
	      * XXX: bnp might be closed or even freed during the loop,
	      * so the validity check is necessary.
	      */
	    if (bgp_rpcb_isvalid(bnp) &&
		find_rtp(srcrtp, bnp->rp_adj_ribs_out)) {
		    aggr_flush();
		    /* msg length short enough */
		    if (bgp_send_update(bnp, rte, rte) == NULL)
			    bgp_cease(bnp);
      }
    }
    free_bgpcb_list(disthead);
  }
}

