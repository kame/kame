/* 
 * $Id: output.c,v 1.1.1.1 1999/08/08 23:29:47 itojun Exp $
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

/* Copyright (c) 1997, 1998. Hitachi,Ltd.  All rights reserved. */
/* Hitachi Id: output.c,v 1.3 1998/01/12 12:39:03 sumikawa Exp $ */

#include "defs.h"

/* 
 * ONCE_FOR_EACH_PACKET
 * packet data initialization.
 * affected variables: num_entries, pkt, rp, current_nhp, need_nhp, new_nhp
 */
#define ONCE_FOR_EACH_PACKET \
	do {\
		num_entries = 0;\
		bzero( snd_data, max_datasize );\
		/* mh->msg_iov->iov_len  = 0; */\
		pkt->rip6_cmd = RIP6_RESPONSE;\
		pkt->rip6_ver = RIP6_VERSION;\
		rp = pkt->rip6_rte;\
		current_nhp = &ci_info(ifp->if_cinfo).ipi6_addr; /* my src addr */\
		if(!need_nhp && rt6_nhopout) {\
			need_nhp = !nohopout;\
			new_nhp  = current_nhp;\
		}\
	} while(0)

/* 
 * WRITE_PAIR
 * send possibly one NextHop RTE + (real) RTE
 * IN: r_tmp, need_nhp, current_nhp, new_nhp, num_entries, rp ...
 */
#define WRITE_PAIR(r_tmp) \
	do {\
		/* maybe need_nhp is already 1. NEVER CLEAR */\
		if (memcmp((void *)current_nhp, \
			   (void*)new_nhp, sizeof(struct in6_addr)))\
			need_nhp = 1;\
		if (need_nhp) {\
			if (num_entries + 2 > max_entries) {\
				/* flush packet */\
				mh->msg_iov->iov_len = \
					((char *)rp - (char *)mh->msg_iov->iov_base);\
				send_message(mh, ifp, agronly);\
				ONCE_FOR_EACH_PACKET;\
			}\
			/* write nexthop RTE */\
			rp->rip6_addr = *new_nhp;\
			rp->rip6_metric = RIP6_NEXTHOP_METRIC; /* 0xFF */\
			num_entries++;\
			rp++;\
			current_nhp = new_nhp;\
			need_nhp = 0;\
		}\
		\
		if (num_entries + 1 > max_entries) {\
			/* flush packet */\
			mh->msg_iov->iov_len = ((char *)rp - (char *)mh->msg_iov->iov_base);\
			send_message(mh, ifp, agronly );\
			ONCE_FOR_EACH_PACKET;\
		}\
		\
		if (need_nhp) {\
			/* maybe set in previous ONCE_FOR_EACH_PACKET */\
			/* already packet flushed */\
			rp->rip6_addr = *new_nhp;\
			rp->rip6_metric = RIP6_NEXTHOP_METRIC; /* 0xFF */\
			num_entries++;\
			rp++;\
			current_nhp = new_nhp;\
			need_nhp = 0;\
		}\
		*rp = r_tmp;\
		num_entries++;\
		rp++;\
	} while(0)

/* 
 * CHECK_AGR(struct in6_addr *addrp)
 */
#define CHECK_AGR(addrp) \
	do {\
		for (agp = ifp->if_config->int_aggr; agp; agp = agp->agr_next) {\
			if(address_match((addrp), &agp->agr_pref.prf_addr, \
					 &agp->agr_mask)) {\
				if (agp->agr_sent != AGR_SENT) \
					agp->agr_sent = AGR_SENDING;\
				break;\
			}\
		}\
	} while(0)

/* 
 * CHECK_NHOP
 */
#define CHECK_NHOP(r_tmp) \
	do {\
		for(nhrp = ifp->if_config->int_nhop; nhrp; nhrp = nhrp->nh_next) {\
			if (address_match(&r_tmp.rip6_addr, \
					  &nhrp->nh_prf.prf_addr, &nhrp->nh_mask)) {\
				new_nhp = &(nhrp->nh_addr);\
				break;\
			}\
		}\
	} while(0)

/* forward references */
int get_max_rte(struct interface *);
void clear_changeF(void);

/* 
 * Send request on all interfaces for information from other routers
 * at startup time.
 */
void
send_request(void)
{
	struct interface *ifp;
	struct msghdr *mh;
	struct rip6 *pkt;
	struct route_entry *rp;
	struct sockaddr_in6 sdst;
	int n;

	if (snd_data == NULL)
		return;
	pkt = (struct rip6 *)snd_data;
	bzero((void *)pkt, sizeof(struct rip6));
	pkt->rip6_cmd = RIP6_REQUEST;
	pkt->rip6_ver = RIP6_VERSION;
	rp = pkt->rip6_rte;
	rp->rip6_metric = HOPCOUNT_INFINITY;

	mh = &smsgh;		/* used in send_request/send_update */
	(void)inet_pton(AF_INET6, ALL_RIP6_ROUTER, (void *)&sdst.sin6_addr);
	mh->msg_name = (char *)&(sdst);
	sdst.sin6_len = mh->msg_namelen = sizeof(struct sockaddr_in6);
	mh->msg_iov = &siov;
	mh->msg_iovlen = 1;

	siov.iov_base = snd_data;
	siov.iov_len = sizeof(struct rip6);

	sdst.sin6_family = AF_INET6;
	sdst.sin6_port = htons(RIP6_PORT);
	sdst.sin6_flowinfo = 0;

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if ((ifp->if_flag & IFF_UP) == 0 ||
		    (ifp->if_flag & IFF_LOOPBACK) ||
		    (ifp->if_flag & IFF_RUNNING) == 0)
			continue;

		if (ifp->if_config->int_inpass == CTL_NOLISTEN &&
		    ifp->if_config->int_ctlin == NULL)
			continue;

		mh->msg_control = (char *)&(ifp->if_cinfo);
		mh->msg_controllen = sizeof(struct ctlinfo);

		if (rt6_trace)
			trace_packet("Tx", ifp, mh, 1, 0);
		if ((n = sendmsg(rip6_sock, mh, 0)) < 0)
			syslog(LOG_ERR, "send_request: send_request: UDP socket: %m");
	}
	return;
}

/* 
 * To send unsolicited update on every interface.
 */
void
send_regular_update(void)
{
	struct interface *ifp;
	unsigned int agronly = 0;

	regular = 0;		/* flag reset */
	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if ((ifp->if_flag & IFF_UP) == 0 ||
		    (ifp->if_flag & IFF_LOOPBACK) ||
		    (ifp->if_flag & IFF_RUNNING) == 0)
			continue;

		if (ifp->if_config->int_outpass == CTL_NOSEND &&
		    ifp->if_config->int_ctlout == NULL)
			agronly = 1;	/* continue; */
		send_update(ifp, (struct msghdr *)NULL, 0, agronly);
		agronly = 0;
	}

	clear_changeF();

	return;
}

/* 
 * To send triggered update on every interface.
 */
void
send_triggered_update(void)
{
	struct interface *ifp;
	unsigned int agronly = 0;

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if ((ifp->if_flag & IFF_UP) == 0 ||
		    (ifp->if_flag & IFF_LOOPBACK) ||
		    (ifp->if_flag & IFF_RUNNING) == 0)
			continue;
		if (ifp->if_config->int_outpass == CTL_NOSEND &&
		    ifp->if_config->int_ctlout == NULL)
			agronly = 1;	/* continue; */
		send_update(ifp, (struct msghdr *)NULL, RTS6_CHANGED, agronly);
		agronly = 0;
	}

	clear_changeF();

	return;
}

/* 
 * Sends the full 'RAW' routing table to the requester.
 */
void
send_full_table(struct msghdr *mh, struct interface *ifp)
{
	int max_entries, num_entries;
	int need_nhp = 0;
	struct in6_addr *current_nhp, *new_nhp;
	struct rip6 *pkt;
	struct route_entry *rp;
	struct rt_plen *rtp;
	struct gateway *gp;
	struct route_entry r_tmp;
	const int nohopout = 1;
	unsigned int agronly = 0;

	if (snd_data == NULL)
		return;
	if (mh == NULL || mh->msg_name == NULL)
		return;

	/* mh->name, mh->namelen are already set */
	mh->msg_iov = &siov;
	mh->msg_iovlen = 1;
	mh->msg_flags = 0;	/* Clear received flag */
	mh->msg_iov->iov_base = snd_data;
	pkt = (struct rip6 *)snd_data;

	/* Path MTU not supported */
	max_entries = (DEFAULT_MTU - rt6_hdrlen -
		       sizeof(struct rip6)) / sizeof(struct route_entry) + 1;
	need_nhp = 0;
	ONCE_FOR_EACH_PACKET;
	for (gp = gway; gp; gp = gp->gw_next) {
		for (rtp = gp->gw_dest; rtp; rtp = rtp->rp_ndst) {
			r_tmp.rip6_prflen = rtp->rp_len;
			r_tmp.rip6_addr = rtp->rp_leaf->key;
			r_tmp.rip6_metric = rtp->rp_metric;
			r_tmp.rip6_rtag = htons(rtp->rp_tag);

			new_nhp = current_nhp;	/* always */
			WRITE_PAIR(r_tmp);
		}
	}

	/* last one */
	if (num_entries) {
		mh->msg_iov->iov_len = ((char *)rp - (char *)mh->msg_iov->iov_base);
		send_message(mh, ifp, 0);
	}

	return;
}

/* 
 * Writes the message on to UDP socket to appropriate destinations.
 */
void
send_message(struct msghdr *mh, struct interface *ifp, unsigned int force)
{
	int n, nentries, flag;
	struct control *ctlp;

	flag = 0;
	nentries = (mh->msg_iov->iov_len - sizeof(struct rip6))
	/ sizeof(struct route_entry) + 1;

	if (mh->msg_name != NULL) {	/* should respond by unicast */
		struct in6_pktinfo *pf;
		/* query(all), query(n), startup-query(all) */

		/* send back to the sender of request directly */
		/* Its src addr is response's dst addr         */
		/* mh->msg_name = mh->msg_name;                */

		pf = (struct in6_pktinfo *)CMSG_DATA(CMSG_FIRSTHDR(mh));
		if (IN6_IS_ADDR_MULTICAST(&pf->ipi6_addr)) {
			if (ifp->if_lladdr)
				pf->ipi6_addr = ifp->if_lladdr->pl_pref.prf_addr;
			else
				return;	/* cannot send without linklocal */
		}
		if (rt6_trace)
			trace_packet("Tx", ifp, mh, nentries, 0);

		if ((n = sendmsg(rip6_sock, mh, 0)) != mh->msg_iov->iov_len)
			syslog(LOG_ERR, "send_message: UDP socket: %m");

		return;
	}
	if (!(ifp->if_flag & IFF_RUNNING))
		return;		/* doesn't have any linklocal */

	mh->msg_control = (void *)&(ifp->if_cinfo);
	mh->msg_controllen = sizeof(struct ctlinfo);

	/* SPECIAL CASE */
	/* AGGREGATE overrides NOOUT */
	if (force) {
		struct sockaddr_in6 tmp6;
		bzero((void *)&tmp6, sizeof(tmp6));
		tmp6.sin6_port = htons(RIP6_PORT);
		tmp6.sin6_len = sizeof(tmp6);
		tmp6.sin6_family = AF_INET6;
		tmp6.sin6_flowinfo = 0;
		(void)inet_pton(AF_INET6, ALL_RIP6_ROUTER, &tmp6.sin6_addr);

		mh->msg_name = (char *)&tmp6;
		mh->msg_namelen = sizeof(tmp6);
		if (rt6_trace)
			trace_packet("Tx", ifp, mh, (nentries + 1), 0);
		if ((n = sendmsg(rip6_sock, mh, MSG_DONTROUTE)) != mh->msg_iov->iov_len)
			syslog(LOG_ERR, "send_message: UDP socket: %m");
		ifp->if_updates++;
		return;
	}

	/* 
	 * Loop through all the destinations listed in out list with
	 * CTL_SEND of this interface and send a copy to them each.
	 * Note: there should be a CTL_SEND to FF02::9 entry in
	 * default.
	 */
	for (ctlp = ifp->if_config->int_ctlout; ctlp; ctlp = ctlp->ctl_next) {
		if (ctlp->ctl_pass == CTL_NOSEND)
			continue;

		mh->msg_name = (char *)&(ctlp->ctl_addr);
		mh->msg_namelen = sizeof(struct sockaddr_in6);
		if (rt6_trace)
			trace_packet("Tx", ifp, mh, (nentries + 1), 0);

		n = sendmsg(rip6_sock, mh, MSG_DONTROUTE);
		if (n != mh->msg_iov->iov_len)
			syslog(LOG_ERR, "send_message: UDP socket: %m");
		ifp->if_updates++;
	}
	return;
}

/* 
 * Forms route6d statistics and sends to rip6admin.
 */
void
send_admin_stat(void)
{
	char buf[ADM_PKTSIZE];
	struct per_if_info *info;
	struct statistic *st;
	struct interface *ifp;
	int nbytes, adsize = sizeof(struct sockaddr_un);

	st = (struct statistic *)buf;
	st->st_grccount = grc_counter;
	st->st_gqcount = gq_counter;
	info = (struct per_if_info *)(buf + sizeof(struct statistic));

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if ((ifp->if_flag & IFF_UP) == 0)
			continue;

		bcopy(&(ifp->if_name), &(info->pi_ifname), IFNAMSIZ);
		info->pi_badpkt = ifp->if_badpkt;
		info->pi_badrte = ifp->if_badrte;
		info->pi_updates = ifp->if_updates;

		if ((char *)(++info + 1) >
		    (buf + ADM_PKTSIZE - sizeof(struct sockaddr_un))) {
			nbytes = ((char *)info - buf);
			if (sendto(admin_sock, buf, nbytes, 0,
			   (struct sockaddr *)&admin_dest, adsize) < nbytes)
				syslog(LOG_ERR, "send_admin_stat: UNIX socket: %m");
			info = (struct per_if_info *)buf;
		}
	}

	nbytes = ((char *)info - buf);
	if (sendto(admin_sock, buf, nbytes, 0, (struct sockaddr *)&admin_dest,
		   adsize) < nbytes)
		syslog(LOG_ERR, "send_admin_stat: UNIX socket: %m");

	buf[0] = ADM_EOF;
	sendto(admin_sock, buf, 1, 0, (struct sockaddr *)&admin_dest, adsize);
	return;
}

/* 
 * Calculates the maximum number of RTEs that can be put in a packet
 * when advertising on the interface.
 */
int
get_max_rte(struct interface *ifp)
{
	/* struct rip6 includes one RTE */
	return ((ifp->if_lmtu - rt6_hdrlen - sizeof(struct rip6)) /
		sizeof(struct route_entry) + 1);
}

#ifdef NDAEMON
/* 
 * print packet
 */
void
prt_packet(char *buf, int n, struct sockaddr_in6 *src)
{
	int i;
	char str[INET6_ADDRSTRLEN];
	struct rip6 *pkt;
	struct route_entry *rp;

	printf("Inside prt_packet ...\n");
	printf("nentries : %d\n", n);
	pkt = (struct rip6 *)buf;
	rp = pkt->rip6_rte;
	printf("pkt: %d  rp: %d\n", pkt, rp);
	for (i = 0; i < n; i++, rp++) {
		if (CHECK_NHE(rp))
			printf("Next Hop entry ...\n");
		else if (CHECK_RAE(rp))
			printf("default route ...\n");
		else
			printf("Route entry ...\n");
		inet_ntop(AF_INET6, (void *)&rp->rip6_addr, str, sizeof(str));
		printf("\taddr:  %s  tag: %d  prflen: %d  metric: %d\n",
		       str, rp->rip6_rtag, rp->rip6_prflen, rp->rip6_metric);
	}
	printf("... End of prt_packet!\n");
}

/* 
 * print route
 */
void
print_route(struct rt_plen *plen)
{
	char prefstr[INET6_ADDRSTRLEN];

	bzero(prefstr, INET6_ADDRSTRLEN);
	if (inet_ntop(AF_INET6, plen->rp_leaf->key.s6_addr, prefstr,
		      sizeof(prefstr)) == 0) {
		printf("utclcachemod : Incorrect data \n");
		flush_local_cache();
		exit(1);
	}
	printf("Destination : %s \n", prefstr);
	printf("Prefix len : %d \n", plen->rp_len);
	printf("Metric : %d \n", plen->rp_metric);
	printf("Route tag : %d \n", plen->rp_tag);
	bzero(prefstr, INET6_ADDRSTRLEN);
	if (inet_ntop(AF_INET6, plen->rp_gway->gw_addr.s6_addr,
		      prefstr, sizeof(prefstr)) == 0) {
		printf("utclcachemod : Incorrect data \n");
		flush_local_cache();
		exit(1);
	}
	printf("Gateway : %s \n", prefstr);
	printf("Interface Name: %s \n", plen->rp_gway->gw_ifp->if_name);
	return;
}
#endif				/* NDAEMON */

/* 
 * Forms the packet according to mode of operation.
 */
void
send_update(struct interface *ifp, struct msghdr *mh, int state, unsigned int agronly)
{
	int max_entries, num_entries;
	int metric_out, poisonf;
	int need_nhp = 0;
	struct in6_addr *addrp, *current_nhp, *new_nhp;
	struct rip6 *pkt;
	struct route_entry *rp;
	struct rt_plen *rtp, *drt;
	struct tree_node *node;
	struct rte_stat *stat;
	struct gateway *gp;
	struct nexthop_rte *nhrp;	/* nexthop list */
	struct aggregate *agp;
	struct route_entry r_tmp;
	const int nohopout = 0;

	if (snd_data == NULL)
		return;
	if (!(ifp->if_flag & IFF_RUNNING))
		return;		/* doesn't have any linklocal */

	if (mh == NULL) {	/* unsolicited */
		mh = &smsgh;
		bzero(mh, sizeof(smsgh));
	}
	mh->msg_iov = &siov;	/* overwrite does no harm */
	mh->msg_iovlen = 1;
	mh->msg_flags = 0;	/* clear */

	mh->msg_iov->iov_base = snd_data;
	pkt = (struct rip6 *)snd_data;

	max_entries = get_max_rte(ifp);
	need_nhp = 0;

	ONCE_FOR_EACH_PACKET;

	/* gendefault: if generate then no other RTE is needed */
	if ((stat = ifp->if_config->int_dstat) != NULL) {
		if (!state) {	/* regular update */
			/* default route cannot be aggregated further */

			bzero((void *)&r_tmp, sizeof(r_tmp));
			r_tmp.rip6_metric = stat->rts_metric +
				ifp->if_config->int_metric_out;
			if (r_tmp.rip6_metric > HOPCOUNT_INFINITY)
				r_tmp.rip6_metric = HOPCOUNT_INFINITY;
			r_tmp.rip6_rtag = htons(stat->rts_tagval);

			new_nhp = current_nhp;
			CHECK_NHOP(r_tmp);
			WRITE_PAIR(r_tmp);
		}
		goto lastone;	/* and return */
	}
	/* init aggregate list */
	for (agp = ifp->if_config->int_aggr; agp; agp = agp->agr_next)
		agp->agr_sent = AGR_NOTSENT;

	/* propagate default */
	if (ifp->if_config->int_propagate &&
	    (drt = locate_local_route(&default_rte, &node)) != NULL &&
	    (drt->rp_state & RTS6_STATIC) == 0 && /* learn from neighbour */
	    (!state || drt->rp_state & state) && !agronly) {
		/* sanity check omitted */
		if (drt->rp_gway->gw_ifp == ifp) {	/* same interface */
			switch (ifp->if_config->int_scheme) {
			case RT6_NOHORZN:	/* no intelligence */
				metric_out = drt->rp_metric +
					ifp->if_config->int_metric_out;
				break;
			case RT6_HORZN:
				goto loop;	/* no need to advertise */
			default:	/* case RT6_POISON: */
				metric_out = HOPCOUNT_INFINITY;
				break;
			}
		} else {	/* other interface */
			metric_out = drt->rp_metric +
				ifp->if_config->int_metric_out;
		}

		CHECK_AGR(&drt->rp_leaf->key);

		/* This is 1st. RTE, any aggregation has not been sent yet */
		if (agp) {
			r_tmp.rip6_prflen = agp->agr_pref.prf_len;
			r_tmp.rip6_addr = agp->agr_pref.prf_addr;
			r_tmp.rip6_metric = agp->agr_stat.rts_metric
				+ ifp->if_config->int_metric_out;
			r_tmp.rip6_rtag = htons(agp->agr_stat.rts_tagval);
			agp->agr_sent = AGR_SENT;
		} else {
			r_tmp.rip6_prflen = 0;	/* DEFAULT ROUTE drt->rp_len */
			r_tmp.rip6_addr = drt->rp_leaf->key;
			r_tmp.rip6_metric = metric_out;
			r_tmp.rip6_rtag = htons(drt->rp_tag);
		}
		if (r_tmp.rip6_metric > HOPCOUNT_INFINITY)
			r_tmp.rip6_metric = HOPCOUNT_INFINITY;
		new_nhp = &ci_info(ifp->if_cinfo).ipi6_addr;
		CHECK_NHOP(r_tmp);
		WRITE_PAIR(r_tmp);
	}	/* end propagate */
 loop:
	for (gp = gway; gp; gp = gp->gw_next) {
		if (!(gp->gw_ifp) || (gp->gw_ifp->if_flag & IFF_UP) == 0)
			continue;

		if (gp->gw_ifp == ifp) {
			switch (ifp->if_config->int_scheme) {
			case RT6_NOHORZN:	/* no intelligence */
				poisonf = 0;
				break;
			case RT6_HORZN:
				continue;
				/* never reached */
			default:	/* case RT6_POISON: */
				poisonf = 1;
				break;
			}
		} else
			poisonf = 0;

		for (rtp = gp->gw_dest; rtp; rtp = rtp->rp_ndst) {
			if (state && (rtp->rp_state & state) == 0)
				continue;

			addrp = &(rtp->rp_leaf->key);
			if (IN6_IS_ADDR_SITELOCAL(addrp) &&
			    !(ifp->if_config->int_site))
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(addrp) &&
			    rtp->rp_len == MAX_PREFLEN)
				continue;	/* already propagated */

			CHECK_AGR(addrp);
			if (agp) {
				if (agp->agr_sent == AGR_SENT)
					continue;	/* already sent */
				r_tmp.rip6_prflen = agp->agr_pref.prf_len;
				r_tmp.rip6_addr = agp->agr_pref.prf_addr;
				r_tmp.rip6_metric = agp->agr_stat.rts_metric +
					ifp->if_config->int_metric_out;
				r_tmp.rip6_rtag = htons(agp->agr_stat.rts_tagval);
				agp->agr_sent = AGR_SENT;
			} else {
				if (agronly)
					continue; /* send only aggregation */
				r_tmp.rip6_prflen = rtp->rp_len;
				r_tmp.rip6_addr = *addrp;
				r_tmp.rip6_metric = poisonf
					? HOPCOUNT_INFINITY
					: rtp->rp_metric + ifp->if_config->int_metric_out;
				r_tmp.rip6_rtag = htons(rtp->rp_tag);
			}
			if (r_tmp.rip6_metric > HOPCOUNT_INFINITY)
				r_tmp.rip6_metric = HOPCOUNT_INFINITY;

			new_nhp = &ci_info(ifp->if_cinfo).ipi6_addr;
			CHECK_NHOP(r_tmp);
			WRITE_PAIR(r_tmp);
		}		/* for each rtp */
	}			/* for each gateway */

 lastone:
	if (num_entries) {
		mh->msg_iov->iov_len = ((char *)rp - (char *)mh->msg_iov->iov_base);
		send_message(mh, ifp, agronly);
	}
	return;
}

/* 
 * Clear RTS6_CHANGED flags of all entries
 */
void
clear_changeF(void)
{
	struct gateway *gp;
	struct rt_plen *rtp;

	sendupdate = FALSE;	/* routes advertised. triggered or regular */

	for (gp = gway; gp; gp = gp->gw_next)
		for (rtp = gp->gw_dest; rtp; rtp = rtp->rp_ndst)
			rtp->rp_state &= ~RTS6_CHANGED;

	return;
}
