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

/*
 * BGP message types
 */
char *bgp_msgstr[] = {
  "",
  "Open",
  "Update",
  "Notify",
  "KeepAlive"};

char *bgp_errstr[] = {
  "",
        "Message Header Error",
          "Open Message Error",
        "Update Message Error",
    "Hold Timer Expired Error",
  "Finite State Machine Error",
  "Cease"
};

char *bgp_hdrerrstr[] = {
  "",
        "Connection Not Synchronized",
          "Bad Message Length",
          "Bad Message Type"
};

char *bgp_opnerrstr[] = {
  "",
        "Unsupported Version number",
          "Bad peer AS",
        "Bad BGP Identifier",
    "Unsupported Optional Parameter",
  "Authentication Failure",
  "Unacceptabel Hold Time"
};


char *bgp_upderrstr[] = {
  "",
  "Malformed Attribute List",
  "Unrecognized Well-known Attribute",
  "Missing Well-known Attribute",
  "Attribute Flags Error",
  "Attribute Length Error",
  "Invalid ORIGIN Attribute",
  "AS Routing Loop",
  "Invalid NEXT_HOP Attribute",
  "Optional Attribute Error",
  "Invalid Network Field",
  "Malformed AS_PATH"
};

char *bgp_statestr[] = {
  "",
  "Idle",
  "Connect",
  "Active",
  "OpenSent",
  "OpenConfirm",
  "Established"
};

char *
bgp_errdatastr(char *buf, int len)
{
#define MAXDATALEN 64
	int i = 0, n;
	static char errstr[(MAXDATALEN * 3) + 3];

	if (len == 0) {
		strcpy(errstr, "(NONE)");
		return(errstr);
	}

	/* traslate data buffer into a hex list */
	for (n = 0; n < len && n < MAXDATALEN; n++) {
		i += sprintf(&errstr[i], "%s%02x",
			     (i == 0) ? "" : " ", (unsigned char)buf[n]);
	}
	/* if there are remaining data, notify that */
	if (len > MAXDATALEN)
		i += sprintf(&errstr[i], "%s", "...");

	/* terminate the string buffer with NULL */
	errstr[i] = '\0';

	return(errstr);
}


/*
 * bgp_new_peer()
 *       DESCRIPTION
 *           Create & Initiate a peer
 *       RETURN VALUES
 *            pointer to new struct rpcb
 */
struct rpcb *
bgp_new_peer()
{
  struct rpcb *bnp;

  MALLOC(bnp, struct rpcb);

  bnp->rp_next   = bnp;
  bnp->rp_prev   = bnp;
  bnp->rp_state  = BGPSTATE_IDLE;
#ifdef DEBUG_BGPSTATE
  syslog(LOG_NOTICE, "<%s>: BGP state shift[%s] peer: %s", __FUNCTION__,
	 bgp_statestr[bnp->rp_state], bgp_peerstr(bnp));
#endif 
  bnp->rp_socket = -1;    /* none */
  bnp->rp_prefer = htonl(BGP_DEF_LOCALPREF);
  bnp->rp_sfd[0] = -1;    /* none */
  bnp->rp_sfd[1] = -1;    /* none */
  bnp->rp_inputmode = BGP_READ_HEADER;
  
  return bnp;
}


/*
 *  bgp_enable_rte()
 *     RETURN VALUES:   1: succeed
 *                      0: failed
 */
int
bgp_enable_rte(rte)
   struct rt_entry *rte;
{
  struct rpcb   *bnp;
  struct ifinfo *ifep = NULL;

  bnp = rte->rt_proto.rtp_bgp; /* come from */

  errno = 0;

  /* Add kernel table */
  if (rte->rt_flags & RTF_UP) {
      if (!(bnp->rp_mode & BGPO_IGP)) { /* eBGP */
	      if (!in6_is_addr_onlink(&rte->rt_bgw, &ifep)) {
		      /* currently we do not support multi-hop EBGP */
		      syslog(LOG_INFO, "<%s>: EBGP next hop %s is not on-link"
			     "(not activated)",
			     __FUNCTION__, ip6str(&rte->rt_bgw, 0));
		      rte->rt_flags &= ~RTF_UP;
		      return 0;	/* continue to next rte */
	      }
	      rte->rt_gw = rte->rt_bgw;
	      rte->rt_gwsrc_type = RTPROTO_BGP;
	      if (ifep == NULL)
		      ifep = bnp->rp_ife;

	      if (addroute(rte, &rte->rt_bgw, ifep) != 0) {
		      /* If the next hop is inaccessible, do not consider it. */
		      /*                                             [cisco]  */
		      return 0;
	      }
	      rte->rt_flags |= RTF_INSTALLED;
      } else {                          /* iBGP */
	      /*
	       * In IBGP cases, try to resolve an on-link gateway to the
	       * next-hop. It will succeed if an IGP(e.g. RIPng) works well.
	       * If a gateway is resolved, try to install it.
	       */
	      if (IN6_IS_ADDR_LINKLOCAL(&rte->rt_bgw)) {
		      /* we reject link-local next hop for IBGP */
		      rte->rt_flags &= ~RTF_UP;
		      return 0;
	      }
	      if (set_nexthop(&rte->rt_bgw, rte) == 1) {
		  if (addroute(rte, &rte->rt_gw, rte->rt_gwif) == 0) {
#ifdef DEBUG
			  syslog(LOG_DEBUG, "<%s>:succeed (maybe third-party)",
				 __FUNCTION__);
#endif
			  rte->rt_flags |= RTF_INSTALLED;
		  }
		  else {
			  syslog(LOG_ERR,
				 "<%s>: failed to add a route dst: %s/%d, "
				 "gw: %s if: %s", __FUNCTION__,
				 ip6str(&rte->rt_ripinfo.rip6_dest, 0),
				 rte->rt_ripinfo.rip6_plen,
				 ip6str(&rte->rt_gw,
					rte->rt_gwif->ifi_ifn->if_index),
				 rte->rt_gwif->ifi_ifn->if_name);
		  }
	      }
	      else {
		      syslog(LOG_ERR,
			     "<%s>: failed to set a gateway for nexthop %s",
			     __FUNCTION__, ip6str(&rte->rt_bgw, 0));
	      }
      }
  }

  if (!IN6_IS_ADDR_UNSPECIFIED(&rte->rt_gw) &&
      !IN6_IS_ADDR_LINKLOCAL(&rte->rt_gw))
    rte->rt_flags |= RTF_NH_NOT_LLADDR;

  return 1; /* succeed */
}

/*
 *  bgp_disable_rte()
 */
void
bgp_disable_rte(rte)
   struct rt_entry *rte;
{
  if (rte->rt_proto.rtp_type != RTPROTO_BGP)
    fatalx("<bgp_disable_rte>: BUG !");

  if (rte->rt_flags & RTF_INSTALLED) {
#ifdef DEBUG
    syslog(LOG_DEBUG, "<%s>: delroute()...", __FUNCTION__);
#endif
    if (delroute(rte, &rte->rt_gw) != 0)
	    syslog(LOG_ERR, "<%s>: route couldn't be deleted: dst=%s/%d, "
		   "gw=%s", __FUNCTION__,
		   ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		   rte->rt_ripinfo.rip6_plen,
		   ip6str(&rte->rt_gw, 0));

    rte->rt_flags &= ~RTF_INSTALLED;          /* down */
    rte->rt_ripinfo.rip6_metric = RIPNG_METRIC_UNREACHABLE;
  }
}

/*
 *  bgp_recover_rte()
 *    DESCRIPTION:   Find recoverable route.
 */
void
bgp_recover_rte(drte)
   struct rt_entry *drte;        /* already down */
{
  struct rpcb     *obnp;         /* other Peer   */
  struct rt_entry *orte, *rrte;  /* recover RTE  */

  extern struct rpcb *bgb;

  orte = rrte = NULL;
  obnp = bgb;
  while(obnp) {
    if ((drte->rt_proto.rtp_type != RTPROTO_BGP ||
	 obnp != drte->rt_proto.rtp_bgp) &&
	(orte = find_rte(drte, obnp->rp_adj_ribs_in))) {
      
      if (obnp->rp_mode & BGPO_IGP &&
	  drte->rt_ripinfo.rip6_tag == orte->rt_ripinfo.rip6_tag)
	  orte->rt_flags &= ~RTF_IGP_EGP_SYNC;  /* XXX: de-synchronize */


      if (!(obnp->rp_mode & BGPO_IGP) ||
	  obnp->rp_mode & BGPO_NOSYNC ||
	  orte->rt_flags & RTF_IGP_EGP_SYNC) {

	if (rrte == NULL)
	  rrte = orte;     /* the first candidate */
	else {
	  if (bgp_preferred_rte(orte, rrte))
	    rrte = orte;   /* More preferable candidate */
	}
      }
    }
    if ((obnp = obnp->rp_next) == bgb)
      break;
  }

  if (rrte) {
    struct rt_entry crte;

    rrte->rt_flags               |= RTF_UP;
    rrte->rt_ripinfo.rip6_metric  = 1;

    if (bgp_enable_rte(rrte) == 0) {
	    struct rpcb *obnp = rrte->rt_proto.rtp_bgp;

#ifdef DEBUG_BGP
	    syslog(LOG_NOTICE,
		   "<%s>: failed route recovery for %s/%d, origin: %s(deleted)",
		   __FUNCTION__,
		   ip6str(&drte->rt_ripinfo.rip6_dest, 0),
		   drte->rt_ripinfo.rip6_plen,
		   bgp_peerstr(rrte->rt_proto.rtp_bgp));
#endif
	    obnp->rp_adj_ribs_in = rte_remove(rrte, obnp->rp_adj_ribs_in);
    }
    else if (!(rrte->rt_flags & RTF_INSTALLED)) {
#ifdef DEBUG_BGP
	    syslog(LOG_NOTICE,
		   "<%s>: route recover for %s/%d, origin: %s (not installed)",
		   __FUNCTION__,
		   ip6str(&drte->rt_ripinfo.rip6_dest, 0),
		   drte->rt_ripinfo.rip6_plen,
		   bgp_peerstr(rrte->rt_proto.rtp_bgp));
#endif 
    }
    else {
#ifdef DEBUG_BGP
	    syslog(LOG_NOTICE, "<%s>: route recover for %s/%d, origin: %s",
		   __FUNCTION__,
		   ip6str(&drte->rt_ripinfo.rip6_dest, 0),
		   drte->rt_ripinfo.rip6_plen,
		   bgp_peerstr(rrte->rt_proto.rtp_bgp));
#endif
	    crte = *rrte;
	    crte.rt_next = crte.rt_prev = &crte;
	    redistribute(&crte); /* XXX: this might hevily modify the peer list */
    }
  } else {
#ifdef DEBUG_BGP
    syslog(LOG_NOTICE, "<%s>: no recover for %s/%d", __FUNCTION__,
	   ip6str(&drte->rt_ripinfo.rip6_dest, 0), drte->rt_ripinfo.rip6_plen);
#endif
  }
  return;
}

/*
 * Detect if RTE is preferred to ORTE.
 */
int
bgp_preferred_rte(rte, orte)
	struct rt_entry *rte, *orte;
{
	u_int32_t lp, olp, med, omed;

	lp = ntohl(rte->rt_aspath->asp_localpref);
	olp = ntohl(orte->rt_aspath->asp_localpref);
	if (lp > olp)
		return(1);
	if (lp < olp)
		return(0);

	/* then lp == olp */
	if (aspath2cost(rte->rt_aspath) < aspath2cost(orte->rt_aspath))
		return(1);
	if (aspath2cost(rte->rt_aspath) > aspath2cost(orte->rt_aspath))
		return(0);

	/*
	 * now lp == olp && pathlen(rte) == pathlen(orte)
	 * XXX: Cisco convention
	 */
	med = ntohl(rte->rt_aspath->asp_med);
	omed = ntohl(orte->rt_aspath->asp_med);
	if (med < omed)
		return(1);
	if (med > omed)
		return(0);

	return(0);
}

/*
 * If an IGP route (including an interface route) is being newly installed,
 * check each BGP routes that is up but does not have a proper gateway. 
 * If the IGP route can be used as a gateway for a BGP route, enable the
 * BGP route.
 */
void
bgp_enable_rte_by_igp(rte)
	struct rt_entry *rte;
{
	struct rpcb *bnp;
	struct rt_entry *brte;
	struct bgpcblist *bgpcb, *bgpcb_head;
	extern byte bgpyes;

	if (!bgpyes)
		return;

	switch(rte->rt_proto.rtp_type) {
	case RTPROTO_RIP:
	case RTPROTO_IF:
#ifdef notyet
	case RTPROTO_OSPF:
#endif 
		bgpcb_head = make_bgpcb_list();
		for (bgpcb = bgpcb_head; bgpcb; bgpcb = bgpcb->next) {
			bnp = bgpcb->bnp;
			/*
			 * XXX: bnp might be closed or even freed during the loop,
			 * so the validity check is necessary.
			 */
			if (!bgp_rpcb_isvalid(bnp))
				continue;

			brte = bnp->rp_adj_ribs_in;
			while(brte) {
				if ((brte->rt_flags & (RTF_UP|RTF_INSTALLED)) ==
				    RTF_UP) {
					/* try to enable */
					if (bgp_enable_rte(brte) == 1 &&
					    (brte->rt_flags & RTF_INSTALLED)) {
						struct rt_entry crte;
#ifdef DEBUG_BGP
						syslog(LOG_NOTICE,
						       "<%s>: BGP route(%s/%d) "
						       "was enabled",
						       __FUNCTION__,
						       ip6str(&brte->rt_ripinfo.rip6_dest,
							      0),
						       brte->rt_ripinfo.rip6_plen);
#endif 
						/* redistribute this route */
						crte = *brte;
						crte.rt_next = crte.rt_prev = &crte;
						redistribute(&crte);

						/*
						 * XXX: redistrib might
						 * invalidate bnp
						 */
						if (!bgp_rpcb_isvalid(bnp)) {
							syslog(LOG_NOTICE,
							       "<%s>: rpcb %p was "
							       "invalidated during a "
							       "redistribution",
							       __FUNCTION__, bnp);
							break;
						}
					}
				}
				if ((brte = brte->rt_next) == bnp->rp_adj_ribs_in)
					break;
			}
		}
		free_bgpcb_list(bgpcb_head);
		break;
	default:
		fatalx("<bgp_enable_rte_by_igp>: rt_proto.rtp_type corrupted");
		/* NOTREACHED */
	}
}

/*
 * If an IGP route (including an interface route) is being removed,
 * all BGP routes that refer to the IGP route should also be disabled.
 * XXX: The routes are withdrawn even when an alternative IGP route are
 *      soon avaiable...
 */
void
bgp_disable_rte_by_igp(rte)
	struct rt_entry *rte;
{
	struct rpcb *bnp;
	struct rt_entry *brte;
	struct bgpcblist *bgpcb, *bgpcb_head;
	extern byte bgpyes;

	if (!bgpyes)
		return;

	switch(rte->rt_proto.rtp_type) {
	case RTPROTO_RIP:
	case RTPROTO_IF:
#ifdef notyet
	case RTPROTO_OSPF:
#endif 
		bgpcb_head = make_bgpcb_list();
		for (bgpcb = bgpcb_head; bgpcb; bgpcb = bgpcb->next) {
			bnp = bgpcb->bnp;
			/*
			 * XXX: bnp might be closed or even freed during the loop,
			 * so the validity check is necessary.
			 */
			if (!bgp_rpcb_isvalid(bnp))
				continue;

			brte = bnp->rp_adj_ribs_in;
			while(brte) {
				if (brte->rt_gwsrc_type ==
				    rte->rt_proto.rtp_type && /* sanity? */
				    brte->rt_gwsrc_entry == rte &&
				    (brte->rt_flags & (RTF_UP|RTF_INSTALLED)) ==
				    (RTF_UP|RTF_INSTALLED)) {
					struct rt_entry crte;
#ifdef DEBUG_BGP
					syslog(LOG_NOTICE,
					       "<%s>: BGP route(%s/%d) was disabled",
					       __FUNCTION__,
					       ip6str(&brte->rt_ripinfo.rip6_dest,
						      0),
					       brte->rt_ripinfo.rip6_plen);
#endif 
					bgp_disable_rte(brte);

					/* flush gateway information */
					brte->rt_gwsrc_type = RTPROTO_NONE;
					brte->rt_gwsrc_entry = NULL;
					memset(&brte->rt_gw, 0,
					       sizeof(struct in6_addr));
					brte->rt_gwif = NULL;

					/* withdraw this route */
					crte = *brte;
					crte.rt_next = crte.rt_prev = &crte;
					propagate(&crte);

					/* XXX: propagate might invalidate bnp */
					if (!bgp_rpcb_isvalid(bnp)) {
						syslog(LOG_NOTICE,
						       "<%s>: rpcb %p was "
						       "invalidated during a "
						       "propagation",
						       __FUNCTION__, bnp);
						break;
					}
				}
				if ((brte = brte->rt_next) == bnp->rp_adj_ribs_in)
					break;
			}
		}
		free_bgpcb_list(bgpcb_head);
		break;
	default:
		fatalx("<bgp_disable_rte_by_igp>: rt_proto.rtp_type corrupted");
		/* NOTREACHED */
	}
}

struct rpcb *
find_epeer_by_rpcb(bnp)
	struct rpcb *bnp;
{
	struct rpcb *ebnp = NULL;

	if (bnp == NULL)
		return(NULL);

	if (bnp->rp_state == BGPSTATE_ESTABLISHED)
		return(bnp);

	if (bnp->rp_mode & BGPO_IGP) { /* IBGP */
		ebnp = find_epeer_by_id(bnp->rp_id);

		if (ebnp == NULL)
			ebnp = find_epeer_by_addr(&bnp->rp_gaddr);

		if (ebnp == NULL) /* last resort */
			ebnp = find_epeer_by_addr(&bnp->rp_laddr);
	}
	else {			/* EBGP */
		ebnp = find_epeer_by_as(bnp->rp_as);
	}

	return(ebnp);
}

struct rpcb *
find_epeer_by_addr(addr)
	struct in6_addr *addr;
{
	struct rpcb *bnp;
	struct in6_addr lladdr;

	extern struct rpcb *bgb;

	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		return(NULL);

	bnp = bgb;
	while(bnp) {
		lladdr = bnp->rp_laddr;
		if (bnp->rp_ife)
			SET_IN6_LINKLOCAL_IFINDEX(&lladdr,
						  bnp->rp_ife->ifi_ifn->if_index);
		if (bnp->rp_state == BGPSTATE_ESTABLISHED &&
		    (IN6_ARE_ADDR_EQUAL(&bnp->rp_gaddr, addr) ||
		     (!IN6_IS_ADDR_UNSPECIFIED(&lladdr) &&
		      IN6_ARE_ADDR_EQUAL(&lladdr, addr))))
			return(bnp);

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}

	return NULL;
}

/*
 *    find_peer_by_as()
 */
struct rpcb *
find_peer_by_as(u_int16_t asnum) {
  struct rpcb *bnp;
  
  extern struct rpcb *bgb;

  bnp = bgb;

  while(bnp) {
    if (bnp->rp_as == asnum)
      return bnp;

    if ((bnp = bnp->rp_next) == bgb)
      break;
  }
  return NULL;
}


/*
 *    find_epeer_by_as()
 *       DESCRIPTION: find ESTABLISHED peer by ASnumber
 */
struct rpcb *
find_epeer_by_as(u_int16_t asnum) {
  struct rpcb *bnp;
  
  extern struct rpcb *bgb;

  bnp = bgb;

  while(bnp) {
    if (bnp->rp_as    == asnum &&
	bnp->rp_state == BGPSTATE_ESTABLISHED)
      return bnp;

    if ((bnp = bnp->rp_next) == bgb)
      break;
  }
  return NULL;
}


/*
 *    find_ppeer_by_as()
 *       DESCRIPTION: find PASSIVEly connected peer by ASnumber
 */
struct rpcb *
find_ppeer_by_as(u_int16_t asnum) {
  struct rpcb *bnp;
  
  extern struct rpcb *bgb;

  bnp = bgb;

  while(bnp) {
    if ((bnp->rp_as == asnum) &&
	(bnp->rp_mode & BGPO_PASSIVE))
      return bnp;

    if ((bnp = bnp->rp_next) == bgb)
      break;
  }
  return NULL;
}


/*
 *    find_epeer_by_id()
 *      RETURN VALUES:   a Pointer:  found
 *                       NULL     : not found
 */
struct rpcb *
find_epeer_by_id(u_int32_t id) {
  struct rpcb *bnp;
  
  extern struct rpcb *bgb;

  if (id == 0)
    return NULL;

  bnp = bgb;
  while(bnp) {
    if (bnp->rp_id    == id &&
	bnp->rp_state == BGPSTATE_ESTABLISHED)
      return bnp;

    if ((bnp = bnp->rp_next) == bgb)
      break;
  }
  return NULL;
}

/*
 *    find_ppeer_by_id()
 */
struct rpcb *
find_ppeer_by_id(u_int32_t id) {
  struct rpcb *bnp;
  
  extern struct rpcb *bgb;

  bnp = bgb;
  while(bnp) {
    if (bnp->rp_id    == id &&
	(bnp->rp_mode & BGPO_PASSIVE))
      return bnp;

    if ((bnp = bnp->rp_next) == bgb)
      break;
  }
  return NULL;
}

struct rpcb *
find_active_peer(key)
	struct rpcb *key;
{
	struct rpcb *bnp;
	extern struct rpcb *bgb;

	/*
	 * If state of the KEY rpcb is unspecified(because of, for example,
	 * not fully connected yet), there is no rpcb that matches it.
	 */
	if (key->rp_id == 0 && key->rp_as == 0)
		return(NULL);

	bnp = bgb;
	while(bnp) {
		if ((key->rp_mode & BGPO_IGP) &&
		    (bnp->rp_mode & BGPO_IGP) &&
		    bnp->rp_state >= BGPSTATE_CONNECT &&
		    ((bnp->rp_id && bnp->rp_id == key->rp_id) ||
		     IN6_ARE_ADDR_EQUAL(&key->rp_gaddr, &bnp->rp_gaddr) ||
		     (!IN6_IS_ADDR_UNSPECIFIED(&key->rp_laddr) &&
		      IN6_ARE_ADDR_EQUAL(&key->rp_laddr, &bnp->rp_laddr))))
			return(bnp);

		if (!(key->rp_mode & BGPO_IGP) &&
		    !(bnp->rp_mode & BGPO_IGP) &&
		    bnp->rp_as == key->rp_as &&
		    bnp->rp_state >= BGPSTATE_CONNECT)
			return(bnp);

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}

	return(NULL);
}

struct rpcb *
find_idle_peer(key)
	struct rpcb *key;
{
	struct rpcb *bnp;
	extern struct rpcb *bgb;

	/*
	 * If state of the KEY rpcb is unspecified(because of, for example,
	 * not fully connected yet), there is no rpcb that matches it.
	 */
	if (key->rp_id == 0 && key->rp_as == 0)
		return(NULL);

	bnp = bgb;
	while(bnp) {
		if ((key->rp_mode & BGPO_IGP) &&
		    (bnp->rp_mode & BGPO_IGP) &&
		    bnp->rp_state == BGPSTATE_IDLE &&
		    ((bnp->rp_id && bnp->rp_id == key->rp_id) ||
		     IN6_ARE_ADDR_EQUAL(&key->rp_gaddr, &bnp->rp_gaddr) ||
		     (!IN6_IS_ADDR_UNSPECIFIED(&key->rp_laddr) &&
		      IN6_ARE_ADDR_EQUAL(&key->rp_laddr, &bnp->rp_laddr))))
			return(bnp);

		if (!(key->rp_mode & BGPO_IGP) &&
		    !(bnp->rp_mode & BGPO_IGP) &&
		    bnp->rp_as == key->rp_as &&
		    bnp->rp_state == BGPSTATE_IDLE)
			return(bnp);

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}

	return(NULL);
}

/*
 *    find_apeer_by_addr()
 *     DESCRIPTION: in the case of LinkLocal-address, 
 *                   we need I/F information. (e.g. LLADDRHACK)
 */
struct rpcb *
find_apeer_by_addr(struct in6_addr *addr) {
  struct rpcb        *bnp;
  struct in6_addr     llhackaddr;
  extern struct rpcb *bgb;

  if (IN6_IS_ADDR_UNSPECIFIED(addr))
    return NULL;

  bnp = bgb;

  while(bnp) {
    llhackaddr = bnp->rp_laddr;
    if (bnp->rp_ife)
      SET_IN6_LINKLOCAL_IFINDEX(&llhackaddr,
				bnp->rp_ife->ifi_ifn->if_index);
    if (!(bnp->rp_mode & BGPO_PASSIVE) &&
	(IN6_ARE_ADDR_EQUAL(&bnp->rp_gaddr, addr) ||
	 (!IN6_IS_ADDR_UNSPECIFIED(&llhackaddr) &&
	  IN6_ARE_ADDR_EQUAL(&llhackaddr,    addr))))
      return bnp;

    if ((bnp = bnp->rp_next) == bgb)
      break;
  }
  return NULL;
}

/*
 * Check if a given pointer is actually in the peer list and if
 * the connection to the peer is ESTABLISHUED.
 * We need this function since we sometimes encounter a situation where
 * the connection associated with the pointer is closed or even the pointer
 * is freed during some operations such as update or withdrawing.
 * This means that we must not the content of BNP, the argument.
 * We can only refer the address of the pointer.
 */
int
bgp_rpcb_isvalid(bnp)
	struct rpcb *bnp;
{
	extern struct rpcb *bgb;
	struct rpcb *b;

	b = bgb;
	while(b) {
		if (b == bnp &&	b->rp_state == BGPSTATE_ESTABLISHED)
			return(1);

		if ((b = b->rp_next) == bgb)
			break;
	}
	return(0);
}

/*
 *   ibgpconfig()
 *
 *       Route Reflector [rfc1966].
 */
void ibgpconfig()
{
  struct rpcb   *ibnp, *bnp;
#if 0
  struct ifinfo *ife;
  struct ripif  *ripif;
#endif

  extern byte             IamRR;
#if 0
  extern byte             ripyes;
#endif
  extern u_int32_t        clusterId, bgpIdentifier;
  extern struct rpcb     *bgb;
#if 0
  extern struct ifinfo   *ifentry;
  extern struct ripif    *ripifs;
#endif


  if (IamRR)
    if (clusterId == 0)
      clusterId = bgpIdentifier;  /* ad-hoc */

  /*
   *  1) A Route from a Non-Client peer
   *
   *     Reflect to all other Clients.
   */
  if (IamRR) {
    ibnp = bgb;
    while (ibnp) {
      if (ibnp->rp_mode & BGPO_RRCLIENT) {
	bnp = bgb;
	while (bnp) {
	  if ( (bnp->rp_mode & BGPO_IGP) &&
	      !(bnp->rp_mode & BGPO_RRCLIENT) &&
	      ibnp != bnp ) {

	    struct rtproto *rtp;
	  
	    MALLOC(rtp, struct rtproto);
	  
	    rtp->rtp_type = RTPROTO_BGP;
	    rtp->rtp_bgp  = bnp;

	    if (ibnp->rp_adj_ribs_out)
	      insque(rtp, ibnp->rp_adj_ribs_out);
	    else {
	      rtp->rtp_next = rtp;
	      rtp->rtp_prev = rtp;
	      ibnp->rp_adj_ribs_out = rtp;
	    }
	  }
	  if ((bnp = bnp->rp_next) == bgb)
	    break;
	}
      }
      if ((ibnp = ibnp->rp_next) == bgb)
	break;      
    }
  }


  /*
   *  2) A Route from a Client peer
   *
   *     Reflect to all the Non-Client peers and also to the
   *     Client peers other than the originator. (Hence the
   *     Client peers are not required to be fully meshed).
   */
  if (IamRR) {
    ibnp = bgb;
    while (ibnp) {
      if (ibnp->rp_mode & BGPO_IGP) {
	bnp = bgb;
	while (bnp) {
	  if ((bnp->rp_mode & BGPO_RRCLIENT) &&
	      ibnp != bnp ) {

	    struct rtproto *rtp;

	    MALLOC(rtp, struct rtproto);
	  
	    rtp->rtp_type = RTPROTO_BGP;
	    rtp->rtp_bgp  = bnp;

	    if (ibnp->rp_adj_ribs_out)
	      insque(rtp, ibnp->rp_adj_ribs_out);
	    else {
	      rtp->rtp_next = rtp;
	      rtp->rtp_prev = rtp;
	      ibnp->rp_adj_ribs_out = rtp;
	    }
	  }
	  if ((bnp = bnp->rp_next) == bgb)
	    break;
	}
      }
      if ((ibnp = ibnp->rp_next) == bgb)
	break;      
    }
  }


  /*  
   * Whether IamRR or NOT,
   *
   *  3) Route from an EBGP peer
   *
   *     Send to all the Client and Non-Client Peers.
   */
  ibnp = bgb;
  while(ibnp) {
    if (ibnp->rp_mode & BGPO_IGP) {
      bnp = bgb;
      while (bnp) {
	if (!(bnp->rp_mode & BGPO_IGP)) {
	  struct rtproto *rtp;

	  MALLOC(rtp, struct rtproto);

	  rtp->rtp_type = RTPROTO_BGP;
	  rtp->rtp_bgp  = bnp;

	  if (ibnp->rp_adj_ribs_out)
	    insque(rtp, ibnp->rp_adj_ribs_out);
	  else {
	    rtp->rtp_next = rtp;
	    rtp->rtp_prev = rtp;
	    ibnp->rp_adj_ribs_out = rtp;
	  }
	}
	if ((bnp = bnp->rp_next) == bgb)
	  break;
      }
    }
    if ((ibnp = ibnp->rp_next) == bgb)
      break;      
  }

#if 0
  /*
   *  Whether IamRR or not,
   *
   *  4) Route of direct Interface,
   *
   *     Send to all the Client and Non-Client Peers.
   */
  ibnp = bgb;
  while (ibnp) {
    if (ibnp->rp_mode & BGPO_IGP) {
      ife = ifentry;
      while (ife) {
	struct rtproto *rtp;

	if (ife != ibnp->rp_ife) {/* split holizon (ad-hoc) I/F not known */

	  MALLOC(rtp, struct rtproto);
	  
	  rtp->rtp_type = RTPROTO_IF;
	  rtp->rtp_if   = ife;

	  if (ibnp->rp_adj_ribs_out)
	    insque(rtp, ibnp->rp_adj_ribs_out);
	  else {
	    rtp->rtp_next = rtp;
	    rtp->rtp_prev = rtp;
	    ibnp->rp_adj_ribs_out = rtp;
	  }
	}
	if ((ife = ife->ifi_next) == ifentry)
	  break;
      }
    }
    if ((ibnp = ibnp->rp_next) == bgb)
      break;      
  } /* while */
#endif


  /*  commeted out !  */

#if 0
  /*
   *  whether IamRR or not,
   *
   *  5) Route from RIPng,
   *
   *     Send to all the Client and Non-Client Peers.
   */
  if (ripyes) {
    ibnp = bgb;
    while (ibnp) {
      if (ibnp->rp_mode & BGPO_IGP) {
	ripif = ripifs;
	while (ripif) {
	  struct rtproto *rtp;

	  MALLOC(rtp, struct rtproto);
	  
	  rtp->rtp_type = RTPROTO_RIP;
	  rtp->rtp_rip  = ripif;

	  if (ibnp->rp_adj_ribs_out)
	    insque(rtp, ibnp->rp_adj_ribs_out);
	  else {
	    rtp->rtp_next = rtp;
	    rtp->rtp_prev = rtp;
	    ibnp->rp_adj_ribs_out = rtp;
	  }
	  if ((ripif = ripif->rip_next) == ripifs)
	    break;
	}
      }
      if ((ibnp = ibnp->rp_next) == bgb)
	break;      
    } /* while */
  }
#endif
}


int
s_pipe(fd)
     int fd[2];
{
  return(socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
}


int
bgpd_sendfile(sockfd, fd)
     int sockfd;
     int fd;
{
  int    slen;
  u_char buf[sizeof(int)];
  u_int  netfd;
#if 0
  syslog(LOG_DEBUG, "<bgpd_sendfile>: Invoked. (sockfd=%d, fd=%d)", sockfd, fd);
#endif
  netfd = htonl(fd);
  memcpy(buf, (u_char *)&netfd, sizeof(int));

  if ((slen = write(sockfd, buf, sizeof(int))) < 0) {
    syslog(LOG_NOTICE, "<bgpd_sendfile>: write failed, sockfd=%d.", sockfd);
    dperror("<bgpd_sendfile>: write");
    return -1;
  }

#if 0
  syslog(LOG_DEBUG, "<bgpd_sendfile>: End.");
#endif
  return 0;
}

int
recvfile(sockfd)
     int sockfd;
{
  int    rlen;
  u_char buf[sizeof(int)];

#if 0
  syslog(LOG_DEBUG, "<recvfile>: Invoked. (sockfd=%d)", sockfd);
#endif
  memset(buf, 0, sizeof(int));

  if ((rlen = read(sockfd, buf, sizeof(int))) < 0) {
    dperror("<recvfile>: read");
    return -1;
  }
#if 0
  syslog(LOG_DEBUG, "<recvfile>: End.");
#endif
  return ntohl(*(int *)buf);/* <-- the FD !! */
}

char *
bgp_peerstr(bnp)
	struct rpcb *bnp;
{
	if (IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_addr.sin6_addr))
		return(ip6str(&bnp->rp_addr.sin6_addr,
			      bnp->rp_addr.sin6_scope_id));
	else if (!IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_gaddr))
		return(ip6str(&bnp->rp_gaddr, 0));
	else {
		unsigned int ifindex = 0;

		if (bnp->rp_ife && bnp->rp_ife->ifi_ifn)
			ifindex = bnp->rp_ife->ifi_ifn->if_index;

		return(ip6str(&bnp->rp_laddr, ifindex));
	}
}

struct bgpcblist *
make_bgpcb_list()
{
	struct bgpcblist *d = NULL, *new;
	struct rpcb *bnp;
	extern struct rpcb *bgb;
	
	bnp = bgb;
	while(bnp) {
		if (bnp->rp_state == BGPSTATE_ESTABLISHED) {
			MALLOC(new, struct bgpcblist);
			new->bnp = bnp;	/* set the pointer */

			/* make chain */
			new->next = d;
			d = new;
		}
		if ((bnp = bnp->rp_next) == bgb)
			break;
	}

	return(d);
}

void
free_bgpcb_list(head)
	struct bgpcblist *head;
{
	struct bgpcblist *d, *next;

	for(d = head; d;) {
		next = d->next;
		free(d);
		d = next;
	}
}

/*
 * Check an incoming BGP route to be filtered or not.
 * XXX: currently only site-local addresses are filtered.
 */
int
bgp_input_filter(bnp, rte)
	struct rpcb *bnp;	/* unused */
	struct rt_entry *rte;
{
	if (IN6_IS_ADDR_SITELOCAL(&rte->rt_ripinfo.rip6_dest)) {
		syslog(LOG_NOTICE,
		       "<%s>: site-local prefix(%s/%d) from %s was discarded",
		       __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		       rte->rt_ripinfo.rip6_plen, bgp_peerstr(bnp));
		return 1;	/* to be filtered */
	}

	return 0;		/* accept it */
}

/*
 * Check an outoging BGP route to be filtered or not.
 * XXX: currently only site-local addresses are filtered.
 */
int
bgp_output_filter(bnp, rte)
	struct rpcb *bnp;
	struct rt_entry *rte;
{
	if (IN6_IS_ADDR_SITELOCAL(&rte->rt_ripinfo.rip6_dest)) {
		syslog(LOG_NOTICE,
		       "<%s>: site-local prefix(%s/%d) to %s was filtered",
		       __FUNCTION__, ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		       rte->rt_ripinfo.rip6_plen, bgp_peerstr(bnp));
		return 1;	/* to be filtered */
	}

	return 0;		/* accept it */
}
