/* 
 * $Id: input.c,v 1.2 1999/08/17 14:23:31 itojun Exp $
 */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * Copyright(C)1997 by Hitachi, Ltd.
 * Hitachi Id: input.c,v 1.3 1998/02/06 01:14:48 sumikawa Exp $
 */

#include "defs.h"

/* forward references */
int validate_entry(struct route_entry *);
int validate_source(struct sockaddr_in6 *, struct interface *);
void calculate_metric(struct route_entry *, struct interface *);
int check_host_address(struct in6_addr *);
int check_in(struct sockaddr_in6 *, struct interface *);
struct interface *get_interface(struct msghdr *);
void log_badrte(struct route_entry *, struct interface *,
		struct sockaddr_in6 *);

/* 
 * Receives RIPng messages and does validity check for source address,
 * packet and the individual route entries. It updates the local cache
 * and the kernel routing table.
 */
void
process_rip6_msg(struct msghdr *mh, int nbytes)
{
	int n, nentries, state, changes, ientries;
	struct rip6 *pkt;
	struct sockaddr_in6 *src;
	struct route_entry *rp, nh, dnh;
	struct tree_node *node;
	struct rt_plen *lrt, *drt;
	struct ign_prefix *igp;
	struct aggregate *fp;
	struct interface *ifp;
	struct rte_stat *dfp;

	ientries = 0;

	/* initialized at compile time. never modified */
	if (mh->msg_flags & (MSG_TRUNC | MSG_CTRUNC))
		return;		/* sanity check */
	if ((nentries = nbytes - 4) < sizeof(struct route_entry))
		return;
	nentries /= sizeof(struct route_entry);

	if ((ifp = get_interface(mh)) == NULL)
		return;
	pkt = (struct rip6 *)mh->msg_iov->iov_base;
	if (pkt->rip6_ver < RIP6_VERSION) {
		/* RFC doesn't say anything about VERSION field. */
		/* so, same as RFC1058, ignore version 0 only.   */
		ifp->if_badpkt++;
		return;
	}
	src = (struct sockaddr_in6 *)mh->msg_name;
	rp = pkt->rip6_rte;

	switch (pkt->rip6_cmd) {
	case RIP6_REQUEST:
		gq_counter++;
		if (rt6_trace)
			trace_packet("Rx", ifp, mh, nentries, ientries);

		if ((nentries == 1) && CHECK_ETE(rp)) {
			if (src->sin6_port != htons(RIP6_PORT)) {
				/* cmsg_type is already PKTINFO */
				send_full_table(mh, ifp);
			} else if (IN6_IS_ADDR_LINKLOCAL(&(src->sin6_addr))) {
				struct control *ctlp;
				/* if quiet then not respond to neighbor */
				for (ctlp = ifp->if_config->int_ctlout; ctlp; ctlp = ctlp->ctl_next)
					if (ctlp->ctl_pass == CTL_NOSEND
					    || (!IN6_IS_ADDR_MULTICAST(&(ctlp->ctl_addr.sin6_addr))
						&& bcmp((void *)ctlp->ctl_addr.sin6_addr.s6_addr, (void *)src,
						  sizeof(struct in6_addr))))
						 continue;
				if (!ctlp)
					break;	/* switch */

				/* cmsg_type is already PKTINFO */
				send_update(ifp, mh, 0, 0);
				/* THIS IS DONE BY UNICAST */
				/* SHOULD NOT CLEAR CHANGE FLAG OR TRIGGERED UPDATE */
			}
		} else if (src->sin6_port != htons(RIP6_PORT)) {
			for (n = 0; n < nentries; n++, rp++) {
				if (rp->rip6_prflen == 0)	/* default route */
					lrt = locate_local_route(&default_rte, &node);
				else
					lrt = locate_local_route(rp, &node);

				if (lrt != NULL) {
					rp->rip6_metric = lrt->rp_metric;
					rp->rip6_rtag = lrt->rp_tag;
				} else {
					rp->rip6_metric = HOPCOUNT_INFINITY;
				}
			}
			pkt->rip6_cmd = RIP6_RESPONSE;
			/* cmsg_type is already PKTINFO */
			mh->msg_iov->iov_len = nbytes;	/* ? */
			send_message(mh, ifp, 0);
		}
		/* else entry-specific Request from another route6d ? ignore */
		break;

	case RIP6_RESPONSE:
		changes = FALSE;

		if (!validate_source(src, ifp)) {
			ifp->if_badpkt++;	/* include 'NOIN' neighbor */
			return;
		}
		/* make dummy nexthop entry */
		bzero((void *)&dnh, sizeof(struct route_entry));
		dnh.rip6_addr = src->sin6_addr;
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(&dnh.rip6_addr))
			*(u_int16_t *)&dnh.rip6_addr.s6_addr[2] =
				htons(if_index(ifp));
#endif
		dnh.rip6_metric = RIP6_NEXTHOP_METRIC;	/* no one cares. but */

		nh = dnh;	/* struct copy */

		for (n = 0; n < nentries; n++, rp++) {
			switch (validate_entry(rp)) {
			case -1:	/* just ignore */
				continue;

			case 0:
				log_badrte(rp, ifp, src);
				ifp->if_badrte++;
				ientries++;
				continue;
			}

			if (IN6_IS_ADDR_SITELOCAL(&(rp->rip6_addr))
			    && !(ifp->if_config->int_site))
				continue;

			/* Is it a valid default route entry ? */
			if (CHECK_RAE(rp)) {	/* check prefix length &
						 * metric (only) */
				if (rt6_igndefault)
					continue;	/* so, never be able
							 * to propagate */

				if ((dfp = ifp->if_config->int_dfilter) != NULL) {
					if (!(dfp->rts_metric) || (dfp->rts_tagval == rp->rip6_rtag))
						continue;
				}
				calculate_metric(rp, ifp);

				if ((drt = locate_local_route(&default_rte, &node)) != NULL) {
					/* exactly matched entry (i.e. default ) found */
					if (drt->rp_state & (RTS6_STATIC | RTS6_KERNEL))
						continue;
					/* never RTS6_INTERFACE */

					if (IN6_ARE_ADDR_EQUAL(&drt->rp_gway->gw_addr, &nh.rip6_addr)) {
							/* simple update */
						if (rp->rip6_metric == drt->rp_metric) {
							if (rp->rip6_metric < HOPCOUNT_INFINITY)
								drt->rp_timer = 0;
							continue;
						}
						modify_local_route(drt, rp, &nh, ifp);
						grc_counter++;
						if (rp->rip6_metric == HOPCOUNT_INFINITY) {
							drt->rp_timer = EXPIRE_TIME;
							rt_ioctl(drt, RTM_DELETE);
						}
						changes = TRUE;
					} else if ((rp->rip6_metric < drt->rp_metric)
						|| (HEURISTIC_UPDATE(drt, rp)
						    && rp->rip6_metric < HOPCOUNT_INFINITY)) {
						struct route_entry tmprt;
						/* if no entry, RTM_CHANGE will not work */
						if (drt->rp_metric == HOPCOUNT_INFINITY)
							rt_ioctl(drt, RTM_ADD);
						tmprt = default_rte;
						tmprt.rip6_metric = rp->rip6_metric;
						tmprt.rip6_rtag = rp->rip6_rtag;
						modify_local_route(drt, &tmprt, &nh, ifp);
						grc_counter++;
						changes = TRUE;
					}
				} else {
					/* perfectly new default route */
					struct route_entry tmprt;
					tmprt = default_rte;
					tmprt.rip6_metric = rp->rip6_metric;
					tmprt.rip6_rtag = rp->rip6_rtag;
					state = RTS6_DEFAULT | RTS6_CHANGED;
					add_local_route(&tmprt, &nh, ifp, state, node);
					grc_counter++;
					changes = TRUE;
				}
				continue;
			}	/* end of default entry (RAE) */
			if (CHECK_NHE(rp)) {	/* linklocal or 0::0, metric 0xFF */
				if (rt6_nhopnoin == FALSE) {
					if (IN6_IS_ADDR_LINKLOCAL(&rp->rip6_addr))
						nh = *rp;
					else	/* UNSPECIFIED */
						nh = dnh;
				}
				continue;
			}
			if (IN6_IS_ADDR_LINKLOCAL(&(rp->rip6_addr))) {
				log_badrte(rp, ifp, src);
				ifp->if_badrte++;
				ientries++;
				continue;
			}
			/* Check for ignore prefix */
			for (igp = ignprf; igp; igp = igp->igp_next) {
				if (address_match(&(rp->rip6_addr),
						  &(igp->igp_prefix.prf_addr), &(igp->igp_mask)))
					break;
			}
			if (igp)
				continue;

			/* Check for filter prefix */
			for (fp = ifp->if_config->int_filter; fp; fp = fp->agr_next) {
				if (address_match(&(rp->rip6_addr),
				&(fp->agr_pref.prf_addr), &(fp->agr_mask))) {
					if ((fp->agr_stat.rts_metric == FALSE)
					    || (fp->agr_stat.rts_tagval == rp->rip6_rtag))
						break;
				}
			}
			if (fp)
				continue;
			if (IS_METRIC_VALID(rp) == 0)
				continue;	/* <= INFINITY */

			calculate_metric(rp, ifp);
			if ((lrt = locate_local_route(rp, &node)) != NULL) {
				/* found exactly matching entry */
				if (lrt->rp_state & (RTS6_STATIC | RTS6_KERNEL | RTS6_INTERFACE))
					continue;

				if (IN6_ARE_ADDR_EQUAL(&lrt->rp_gway->gw_addr, &nh.rip6_addr)) {
					if (rp->rip6_metric == lrt->rp_metric) {
						if (rp->rip6_metric < HOPCOUNT_INFINITY)
							lrt->rp_timer = 0;
						continue;
					}
					modify_local_route(lrt, rp, &nh, ifp);
					grc_counter++;
					if (rp->rip6_metric == HOPCOUNT_INFINITY) {
						lrt->rp_timer = EXPIRE_TIME;
						rt_ioctl(lrt, RTM_DELETE);
					}
					changes = TRUE;
				} else if ((rp->rip6_metric < lrt->rp_metric)
					   || (HEURISTIC_UPDATE(lrt, rp) &&
					       rp->rip6_metric < HOPCOUNT_INFINITY)) {
					/* if no entry, RTM_CHANGE will not work */
					if (lrt->rp_metric == HOPCOUNT_INFINITY)
						rt_ioctl(lrt, RTM_ADD);
					lrt->rp_metric = rp->rip6_metric;
					modify_local_route(lrt, rp, &nh, ifp);
					grc_counter++;
					changes = TRUE;
				}
				/* else other gw and expensive. Ignore it */
			} else if (rp->rip6_metric != HOPCOUNT_INFINITY) {
				state = RTS6_CHANGED;
				add_local_route(rp, &nh, ifp, state, node);
				grc_counter++;
				changes = TRUE;
			}
		}

		if (rt6_trace)
			trace_packet("Rx", ifp, mh, nentries, ientries);

		(void)gettimeofday(&now_time, (struct timezone *)NULL);
		if (changes) {
			if (timercmp(&nt_time, &now_time, <))
				trigger_update();
			else
				sendupdate = TRUE;
		}
		break;

	default:
		/* unknow_timen message : ignore? *//* should ifp->badpkt++; ? */
		break;
	}
	return;
}

/* 
 * Processes rip6admin message and calls appropriate output function.
 */
void
process_admin_msg(char *buf, int nbytes)
{
	struct prefix prf;
	struct info_detail *idp;

	if (nbytes < sizeof(struct info_detail))
		 return;

	idp = (struct info_detail *)buf;

	if (idp->id_type == ADM_STAT) {
		send_admin_stat();
	} else if (idp->id_type == ADM_TABLE) {
		prf.prf_len = idp->id_prflen;
		prf.prf_addr = idp->id_addr;
		send_admin_table(&prf);
	} else
		syslog(LOG_ERR, "Wrong message type from admin");

	return;
}

/* 
 * Processes kernel messages received threough routing socket and
 * updates local cache and interface infomation.
 */
void
process_kernel_msg(char *buf, int nbytes)
{
	struct route_entry re, rg;
	struct sockaddr_in6 *nt, *gt, *dt;
	struct rt_msghdr *rtm;
	struct rt_plen *lrt;
	struct tree_node *node;
	struct interface *ifp = NULL;
	int state, index;
	int changed = 0;
	struct preflist *pl = NULL;

	/* No PID check is needed. SO_USELOOPBACK == 0 */
	rtm = (struct rt_msghdr *)buf;
	if (nbytes < sizeof(struct rt_msghdr))
		 return;

	bzero((char *)&re, sizeof(re));
	bzero((char *)&rg, sizeof(rg));

	switch (rtm->rtm_type) {
	case RTM_ADD:
	case RTM_CHANGE:
	case RTM_REDIRECT:
		xaddress(rtm->rtm_addrs, (char *)(rtm + 1), buf + rtm->rtm_msglen, &rtinfo);
		if (dest == NULL || gate == NULL)
			break;
		/* In case of host-route, netmask == NULL */
		/* netmask != NULL and len==0 then default */

		dt = (struct sockaddr_in6 *)dest;
		gt = (struct sockaddr_in6 *)gate;
		nt = (struct sockaddr_in6 *)netmask;	/* maybe length == 0 */

		if (IN6_IS_ADDR_LINKLOCAL(&dt->sin6_addr)
		    || IN6_IS_ADDR_LOOPBACK(&dt->sin6_addr)
		    || IN6_IS_ADDR_MULTICAST(&dt->sin6_addr))
			break;
		if (IN6_IS_ADDR_V4MAPPED(&dt->sin6_addr)
		    || IN6_IS_ADDR_V4COMPAT(&dt->sin6_addr))
			break;

#ifndef __NetBSD__
		if (rtm->rtm_flags & RTF_CLONED)
			break;	/* verbose host-route omitted */
		/* virtual network-address may be assigned to real interface */
		/* if((rtm->rtm_flags & RTF_GATEWAY)== 0) break; */
#endif

		if (!IN6_IS_ADDR_LINKLOCAL(&gt->sin6_addr))
			break;	/* ignore */

		if (rtm->rtm_type == RTM_ADD)
			kernel_routes++;

		if (ifpaddr) {
			for (ifp = ifnet; ifp; ifp = ifp->if_next) {
				if ((ifp->if_flag & IFF_UP) == 0)
					continue;
				if (!strncmp((void *)((struct sockaddr_dl *)ifpaddr)->sdl_data,
					     (void *)&(ifp->if_name),
					     ifp->if_sdl.sdl_nlen))
					break;
			}
		} else if (ifaaddr && ifaaddr->sa_family == AF_INET6) {
			for (ifp = ifnet; ifp; ifp = ifp->if_next) {
				if ((ifp->if_flag & IFF_UP) == 0)
					continue;
				for (pl = ifp->if_ip6addr; pl; pl = pl->pl_next) {
					if (!bcmp((void *)
						  ((struct sockaddr_in6 *)ifaaddr)->sin6_addr.s6_addr,
						  (void *)&(pl->pl_pref.prf_addr), sizeof(struct in6_addr)))
						break;
				}
				if (pl)
					break;
				for (pl = ifp->if_sladdr; pl; pl = pl->pl_next) {
					if (!bcmp((void *)
						  ((struct sockaddr_in6 *)ifaaddr)->sin6_addr.s6_addr,
						  (void *)&(pl->pl_pref.prf_addr), sizeof(struct in6_addr)))
						 break;
				}
				if (pl)
					break;
			}	/* ifp loop */
		} else if (rtm->rtm_index) {
			index = rtm->rtm_index;
			for (ifp = ifnet; ifp; ifp = ifp->if_next)
				if ((ifp->if_flag & IFF_UP) && (index == if_index(ifp)))
					break;
		}
		if (ifp == NULL)
			break;

		if (rtm->rtm_flags & RTF_GATEWAY) {
			state = 0;
			re.rip6_rtag = 0;
			re.rip6_metric = rt6_metric + ifp->if_config->int_metric_in;
			if (re.rip6_metric > HOPCOUNT_INFINITY)
				re.rip6_metric = HOPCOUNT_INFINITY - 1;
			/* anyway it exists */
		} else {
			state = RTS6_INTERFACE;
			re.rip6_rtag = rt6_tag;
			re.rip6_metric = rt6_metric;
		}

		if (nt) {
			if (nt->sin6_len == 0) {	/* default */
				re.rip6_prflen = 128;
				state |= RTS6_DEFAULT;
			} else {
				re.rip6_prflen = get_prefixlen(nt);
				re.rip6_addr = dt->sin6_addr;
			}
		} else {	/* host route */
			re.rip6_prflen = MAX_PREFLEN;	/* host route */
			re.rip6_addr = dt->sin6_addr;
		}

		rg.rip6_addr = gt->sin6_addr;
		lrt = locate_local_route(&re, &node);

		if (rtm->rtm_flags & RTF_STATIC) {
			state |= RTS6_KERNEL | RTS6_STATIC;
			if (lrt == NULL) {
				add_local_route(&re, &rg, ifp, state, node);
				changed = 1;
			} else {
				lrt->rp_state |= state;		/* mmm ? */
				modify_local_route(lrt, &re, &rg, ifp);
				changed = 1;
			}
		} else {	/* not static kernel route */
			state |= RTS6_KERNEL;	/* It may never be timed out. */
			/* One who created this route should take care */
			if (lrt == NULL) {
				add_local_route(&re, &rg, ifp, state, node);
				changed = 1;
			} else {
				if (rtm->rtm_type == RTM_REDIRECT) {
					lrt->rp_state = state;
					modify_local_route(lrt, &re, &rg, ifp);
					changed = 1;
				}
			/* else ... ? */
			}
		}
		break;

	case RTM_DELETE:
		xaddress(rtm->rtm_addrs, (char *)(rtm + 1), buf + rtm->rtm_msglen, &rtinfo);
		if (dest == NULL || gate == NULL)
			break;

		if (rtm->rtm_flags & RTF_GATEWAY)
			kernel_routes--;
		if (kernel_routes < 0)
			kernel_routes = 0;

		if (netmask) {
			if (netmask->sa_len == 0) {	/* default route */
				re.rip6_prflen = MAX_PREFLEN;
				bzero((void *)&re.rip6_addr, sizeof(struct in6_addr));
			} else {
				re.rip6_prflen = get_prefixlen((struct sockaddr_in6 *)netmask);
				re.rip6_addr = ((struct sockaddr_in6 *)dest)->sin6_addr;
			}
		} else {
			re.rip6_prflen = MAX_PREFLEN;	/* host route */
			re.rip6_addr = ((struct sockaddr_in6 *)dest)->sin6_addr;
		}

		if ((lrt = locate_local_route(&re, &node)) != NULL) {
			if (lrt->rp_timer < EXPIRE_TIME) {
				lrt->rp_state = RTS6_KERNEL;
				delete_local_route(lrt);
				changed = 1;
			}
		}
		break;

	case RTM_DELADDR:
	case RTM_IFINFO:
	case RTM_NEWADDR:
		scanning = 1;	/* to block update_timer */
		if (scan_interface()) {
			halted = 1;
			return;
		}
		if (scanning == 0)
			timer();
		else
			scanning = 0;
		break;

	default:
		break;
	}
	if (changed) {
		gettimeofday(&now_time, (struct timezone *)NULL);
		if (timercmp(&nt_time, &now_time, <))
			trigger_update();
		else
			sendupdate = TRUE;
	}
	return;
}

/* 
 * Does the validity check for a given RTE.
 */
int
validate_entry(struct route_entry *rp)
{
	if (IN6_IS_ADDR_LOOPBACK(&(rp->rip6_addr)) ||
	    IN6_IS_ADDR_MULTICAST(&(rp->rip6_addr)))
		return 0;

	if (!rt6_accept_compat &&
	    (IN6_IS_ADDR_V4COMPAT(&rp->rip6_addr) ||
	     IN6_IS_ADDR_V4MAPPED(&rp->rip6_addr)))
		return -1;
	/* just ignore ! */

	if (IS_PREFIX_VALID(rp) == 0)
		return 0;

	return 1;
}

/* 
 * Does the validity check for source address.
 */
int
validate_source(struct sockaddr_in6 *src, struct interface *ifp)
{
	if (!IN6_IS_ADDR_LINKLOCAL(&(src->sin6_addr)) ||
	    (src->sin6_port != htons(RIP6_PORT)) ||
	    check_host_address(&(src->sin6_addr)))	/* it's me ? */
		return 0;

	return check_in(src, ifp);
}

/* 
 * Calculates metric value from the received metric.
 */
void
calculate_metric(struct route_entry *rtp, struct interface *ifp)
{
	rtp->rip6_metric += ifp->if_config->int_metric_in;
	if (rtp->rip6_metric > HOPCOUNT_INFINITY)
		rtp->rip6_metric = HOPCOUNT_INFINITY;
	return;
}

/* 
 * Verifies if the address belongs to one of our interface.
 */
int
check_host_address(struct in6_addr *addr)
{
	struct interface *ifp;
	struct preflist *plp;

	for (ifp = ifnet; ifp; ifp = ifp->if_next)
		for (plp = ifp->if_lladdr; plp; plp = plp->pl_next)
			if (IN6_ARE_ADDR_EQUAL(addr, &plp->pl_pref.prf_addr))
				return 1;

	return 0;
}

/* 
 * Verifies if we can accept the packet from given address.
 */
int
check_in(struct sockaddr_in6 *src, struct interface *ifp)
{
	struct control *cp;

	if (ifp->if_config == NULL)
		return 1;	/* never the case */

	for (cp = ifp->if_config->int_ctlin; cp; cp = cp->ctl_next)
		if (IN6_ARE_ADDR_EQUAL(&src->sin6_addr,
				       &cp->ctl_addr.sin6_addr))
			return (cp->ctl_pass == CTL_LISTEN);

	return (ifp->if_config->int_inpass == CTL_LISTEN);
}

/* 
 * Get a pointer to interface from which the packet arrived.
 */
struct interface *
get_interface(struct msghdr *mh)
{
	struct cmsghdr *cp;
	struct in6_pktinfo *infop;
	struct interface *ifp;

	if (mh->msg_controllen <= 0)
		return (struct interface *)NULL;

	cp = CMSG_FIRSTHDR(mh);
	if (cp->cmsg_type != IPV6_PKTINFO)
		return (struct interface *)NULL;

	infop = (struct in6_pktinfo *)CMSG_DATA(cp);
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
		if (if_index(ifp) == infop->ipi6_ifindex)
			break;

	return (ifp);		/* maybe LOOPBACK(REQUEST) */
}

/* 
 * Verify if given address matches the prefix.
 */
int
address_match(struct in6_addr *addr1, struct in6_addr *addr2,
	      struct in6_addr *mask)
{
	int i;
	for (i = 0; i < sizeof(struct in6_addr); i++) {
		if (((addr1->s6_addr[i] ^ addr2->s6_addr[i]) & mask->s6_addr[i]) != 0)
			return 0;
	}

	return 1;
}

/* 
 * Log illegal RTE.
 */
void
log_badrte(struct route_entry *rp, struct interface *ifp,
	   struct sockaddr_in6 *src)
{
	time_t clock;
	char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];

	time(&clock);
	inet_ntop(AF_INET6, (void *)&src->sin6_addr, str1, sizeof(str1));
	inet_ntop(AF_INET6, (void *)&rp->rip6_addr, str2, sizeof(str2));
	syslog(LOG_INFO, "Illegal RTE: %s\t%s\t%s\t%s\t%d\t%d\t%d\n",
	       asctime(localtime(&clock)),
	       ifp->if_name, str1, str2,
	       rp->rip6_prflen, rp->rip6_rtag, rp->rip6_metric);
	return;
}

/* 
 * Log trace info into trace file.
 */
void
trace_packet(char *trx, struct interface *ifp, struct msghdr *mh,
	     int nrte, int irte)
{
	time_t clock;
	char str1[INET6_ADDRSTRLEN], str2[INET6_ADDRSTRLEN];
	struct in6_addr *a1 = NULL, *a2 = NULL;
	struct cmsghdr *cp;

	if (trace_file_ptr == NULL)
		return;
	time(&clock);
	if (!strcmp(trx, "Tx")) {
		a1 = &ci_info(ifp->if_cinfo).ipi6_addr;
		a2 = &(((struct sockaddr_in6 *)mh->msg_name)->sin6_addr);
	} else {		/* Rx */
		a1 = &(((struct sockaddr_in6 *)mh->msg_name)->sin6_addr);
		for (cp = CMSG_FIRSTHDR(mh); cp; cp = CMSG_NXTHDR(mh, cp))
			if (cp->cmsg_type == IPV6_PKTINFO) {
				a2 = &((struct in6_pktinfo *)CMSG_DATA(cp))->ipi6_addr;
				break;
			}
	}

	inet_ntop(AF_INET6, (void *)a1, str1, sizeof(str1));
	inet_ntop(AF_INET6, (void *)a2, str2, sizeof(str2));

	/* asctime includes '\n' */
	fprintf(trace_file_ptr, "Packet: %s%s %s %s->%s %dRTE BAD%d\n",
		asctime(localtime(&clock)), trx, ifp->if_name,
		str1, str2, nrte, irte);
	fflush(trace_file_ptr);
	return;
}
