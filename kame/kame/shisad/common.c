/*      $KAME: common.c,v 1.11 2005/02/12 15:22:39 t-momose Exp $  */
/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <netdb.h>

#include <net/if.h>
#include <net/if_types.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#include <net/ethernet.h>
#endif /* __FreeBSD__ >= 3 */
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif /* __NetBSD__ */
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6mh.h>
#include <netinet/ip6.h>
#include <netinet6/mip6.h>
#include <netinet/icmp6.h>
#include <net/mipsock.h>
#include <arpa/inet.h>

#include "callout.h"
#include "command.h"
#include "stat.h"
#include "shisad.h"
#include "fsm.h"

extern struct mip6_mipif_list mipifhead;

static const struct in6_addr haanyaddr_ifid64 = {
        {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	   0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}
};
static const struct in6_addr haanyaddr_ifidnn = {
        {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}
};

#ifdef MIP_MN
//static struct sockaddr_dl *get_sockdl_from_ifindex(struct sockaddr_dl *, u_int16_t);
#endif

#ifndef MIP_CN
struct nd6options {
	struct nd_opt_prefix_info *ndpi;
	struct nd_opt_adv_interval *ndadvi;
	struct nd_opt_homeagent_info *ndhai;
} ndopts;

static int mip6_get_nd6options(struct nd6options *, char *, int);
extern struct mip6_hpfx_list hpfx_head; 
#endif /* MIP_CN */


void
mipsock_open()
{
        mipsock = socket(PF_MOBILITY, SOCK_RAW, 0);
	if (mipsock < 0) {
                perror("socket for MOBILITY");
                exit(-1);
        }

	syslog(LOG_INFO, "MIP socket is %d.", mipsock);

	return;
}

int
mipsock_input_common(fd)
	int fd;
{
	int n;
        char msg[1280];
	struct mip_msghdr *miphdr;

        n = read(mipsock, msg, sizeof(msg));
	if (n < 0) {
		return (errno);
	}
	
        miphdr = (struct mip_msghdr *)msg;
	if (miphdr->miph_version != MIP_VERSION) 
		return EOPNOTSUPP;

	return (mipsock_input(miphdr));
}	


void
icmp6sock_open()
{
	int on = 1;
	int error = 0;
	struct icmp6_filter filter;	

	icmp6sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmp6sock < 0) {
		perror("socket for ICMPv6");
		exit(-1);
	}
	error = setsockopt(icmp6sock, 
		IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
	if (error < 0) {
		perror("setsockopt IPV6_RECVPKTINFO for ICMPv6");
		exit(1);
	}

	error = setsockopt(icmp6sock, 
		IPPROTO_IPV6, IPV6_RECVDSTOPTS, &on, sizeof(on));
	if (error < 0) {
		perror("setsockopt IPV6_RECVDSTOPTS for ICMPv6");
		exit(1);
	}

	error = setsockopt(icmp6sock, 
		IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on));
	if (error < 0) {
		perror("setsockopt IPV6_RECVRTHDR for ICMPv6");
		exit(1);
	}

	/* configure filter to receive only RA and ICMPv6 related MIPv6 */
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
	ICMP6_FILTER_SETPASS(MIP6_HA_DISCOVERY_REQUEST, &filter);
	ICMP6_FILTER_SETPASS(MIP6_HA_DISCOVERY_REPLY, &filter);
	ICMP6_FILTER_SETPASS(MIP6_PREFIX_SOLICIT, &filter);
	ICMP6_FILTER_SETPASS(MIP6_PREFIX_ADVERT, &filter);
#ifdef MIP_CN
	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
#endif /* MIP_CN */
#ifdef MIP_MN
	ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &filter);
#endif /* MIP_MN */
	if (setsockopt(icmp6sock, IPPROTO_ICMPV6, 
		       ICMP6_FILTER, &filter, sizeof(filter)) < 0) {
		perror("setsockopt ICMP6_FILTER");
		exit(1);
	}

	syslog(LOG_INFO, "ICMP6 socket is %d.", icmp6sock);

	return;
}

#ifndef MIP_CN
static int
mip6_get_nd6options(ndoptions, options, total) 
	struct nd6options *ndoptions;
 	char *options;
	int total;
{
	int optlen = 0;
	struct nd_opt_hdr *hdr;
	
	for (;total > 0; total -= optlen) {
		options += optlen;
		
		hdr = (struct nd_opt_hdr *)options; 
		optlen = hdr->nd_opt_len << 3;
		
		switch (hdr->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR: 
		case ND_OPT_TARGET_LINKADDR:
		case ND_OPT_REDIRECTED_HEADER:
		case ND_OPT_MTU:
			/* we don't need these */
			break;
		case ND_OPT_PREFIX_INFORMATION:
			ndoptions->ndpi = (struct nd_opt_prefix_info *)hdr;
			if (IN6_IS_ADDR_MULTICAST(&ndoptions->ndpi->nd_opt_pi_prefix) ||
			    IN6_IS_ADDR_LINKLOCAL(&ndoptions->ndpi->nd_opt_pi_prefix))
				return (EINVAL);
			
                         /* aggregatable unicast address, rfc2374 XXX */
			if (ndoptions->ndpi->nd_opt_pi_prefix_len != 64)
				return (EINVAL);
			
			

			break;
		case ND_OPT_ADV_INTERVAL:
			ndoptions->ndadvi = (struct nd_opt_adv_interval *)hdr;
			break;
		case ND_OPT_HA_INFORMATION:
			ndoptions->ndhai = (struct nd_opt_homeagent_info *)hdr;
			break;
		default:
			break;
		}
	}

	return (0);
}
#endif /* MIP6_CN */ 


#ifdef MIP_MN
/* search the best HA for hoainfo */
struct home_agent_list *
mip6_find_hal(hoainfo)
	struct mip6_hoainfo *hoainfo;
{
        struct mip6_hpfxl *hpfx;
	struct mip6_mipif *mipif = NULL;

	mipif = mnd_get_mipif(hoainfo->hinfo_ifindex);
	if (mipif == NULL)
		return (NULL);

	LIST_FOREACH(hpfx, &mipif->mipif_hprefx_head, hpfx_entry) {
		if (mip6_are_prefix_equal(&hoainfo->hinfo_hoa, 
					  &hpfx->hpfx_prefix, hpfx->hpfx_prefixlen)) {
			return (LIST_FIRST(&hpfx->hpfx_hal_head));
		}
	}

	return (NULL);
}
#endif /* MIP_MN */

void
mip6_flush_hal(hpfx_entry, exception_flag)
	struct mip6_hpfxl *hpfx_entry;
	int exception_flag;
{
        struct home_agent_list *hal = NULL, *haln = NULL;

        for (hal = LIST_FIRST(&hpfx_entry->hpfx_hal_head); hal; hal = haln) {
                haln =  LIST_NEXT(hal, hal_entry);

		if (exception_flag & hal->hal_flag)
			continue;

		LIST_REMOVE(hal, hal_entry);
		hal_stop_expire_timer(hal);
		free(hal);
	}

	return;
}


void
mip6_delete_hal(hpfx_entry, gladdr) 
	struct mip6_hpfxl *hpfx_entry;
	struct in6_addr *gladdr;
{
	struct home_agent_list *hal;

	hal = mip6_get_hal(hpfx_entry, gladdr);
	if (hal == NULL)
		return;

	LIST_REMOVE(hal, hal_entry);
	hal_stop_expire_timer(hal);
	free(hal);
	hal = NULL;

	return;
}



struct home_agent_list *
mip6_get_hal(hpfx, global)
	struct mip6_hpfxl *hpfx;
	struct in6_addr *global;
{
        struct home_agent_list *hal = NULL, *haln = NULL;

        for (hal = LIST_FIRST(&hpfx->hpfx_hal_head); hal; hal = haln) {
                haln =  LIST_NEXT(hal, hal_entry);
		
		if (IN6_ARE_ADDR_EQUAL(&hal->hal_ip6addr, global))
			return (hal);
	}

	return (NULL);
}


void
hal_set_expire_timer(hal, tick)
        struct home_agent_list *hal;
        int tick;
{
        remove_callout_entry(hal->hal_expire);
        hal->hal_expire = new_callout_entry(tick, hal_expire_timer,
					    (void *)hal, "hal_expire_timer");
}


void
hal_stop_expire_timer(hal)
        struct home_agent_list *hal;
{
        remove_callout_entry(hal->hal_expire);
}

void
hal_expire_timer(arg)
        void *arg;
{
        struct home_agent_list *hal = (struct home_agent_list *)arg;

	hal_stop_expire_timer(hal);

	LIST_REMOVE(hal, hal_entry);
	free(hal);
	hal = NULL;
}

void
mip6_delete_hpfxlist(home_prefix, home_prefixlen, hpfxhead) 
	struct in6_addr *home_prefix;
	u_int16_t home_prefixlen;
	struct mip6_hpfx_list *hpfxhead;
{
	struct mip6_hpfxl *hpfx = NULL;
	struct home_agent_list *hal, *haln;

	hpfx = mip6_get_hpfxlist(home_prefix, home_prefixlen, hpfxhead);
	if (hpfx == NULL)
		return;

	for (hal = LIST_FIRST(&hpfx->hpfx_hal_head); hal;
	     hal = haln) {
		haln = LIST_NEXT(hal, hal_entry);

		LIST_REMOVE(hal, hal_entry);
		hal_stop_expire_timer(hal);
		free(hal);
		hal = NULL;
	}

	LIST_REMOVE(hpfx, hpfx_entry);
	free(hpfx);
	hpfx = NULL;
	
	return;
}


struct mip6_hpfxl *
mip6_get_hpfxlist(prefix, prefixlen, hpfxhead) 
	struct in6_addr *prefix;
	int prefixlen;
	struct mip6_hpfx_list *hpfxhead;
{
        struct mip6_hpfxl *hpl = NULL, *hpln = NULL;

        for (hpl = LIST_FIRST(hpfxhead); hpl; hpl = hpln) {
                hpln =  LIST_NEXT(hpl, hpfx_entry);
		
		if (prefixlen != hpl->hpfx_prefixlen) 
			continue;

		if (mip6_are_prefix_equal(prefix, &hpl->hpfx_prefix, prefixlen))
			return (hpl);
	}
	return (NULL);
}


int
icmp6_input_common(fd)
	int fd;
{
	register struct in6_addr *in6_lladdr = NULL, *in6_gladdr = NULL;
	int error = 0;
        struct sockaddr_in6 from;
        struct in6_addr dst;
	register struct icmp6_hdr *icp;
        int readlen, hoplimit;
        u_int receivedifindex = 0;
        struct msghdr msg;
        struct iovec iov;
        register struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pkt = NULL;
        char adata[512], buf[1024];
#ifdef MIP_MN
        struct mip6_hoainfo *hoainfo = NULL;
	struct binding_update_list *bul;
	struct mip6_prefix_advert *mpsadv;
	struct mip6_dhaad_rep *dhrep;
	struct in6_addr *dhrep_addr;
	struct mip6_mipif *mif = NULL;
#endif /* MIP_MN */

#ifndef MIP_CN
	struct mip6_hpfxl *hpfx = NULL;
	struct mip6_hpfx_list *hpfxhead = NULL; 
	struct home_agent_list *hal = NULL;

	struct nd_router_advert *ra;
        uint16_t       hai_preference = 0;
        uint16_t       hai_lifetime = 0;
        uint8_t        hai_pfxlen = 0;
#endif /* MIP_CN */

#ifdef MIP_HA
	struct mip6_dhaad_req *dhreq;
#endif /* MIP_HA */

	memset(&from, 0, sizeof(from));
        msg.msg_name = (void *)&from;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (void *) adata;
        msg.msg_controllen = sizeof(adata);

        bzero(buf, sizeof(buf));
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
	
        readlen = recvmsg(fd, &msg, 0);
        if (readlen < 0) {
                perror("recvmsg");
                return (-1);
        }

        for (cmsgptr = CMSG_FIRSTHDR(&msg); 
	     cmsgptr != NULL; 
	     cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {

                /* 
		 * getting a destination address and ifindex receiving
		 * this packet 
		 */
                if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
                    cmsgptr->cmsg_type == IPV6_PKTINFO) {
                        pkt = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
                        receivedifindex = pkt->ipi6_ifindex;
                        dst = pkt->ipi6_addr;
                }
                if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
                    cmsgptr->cmsg_type == IPV6_HOPLIMIT) {
			hoplimit = *(int *)(CMSG_DATA(cmsgptr));
		}

	}
#ifdef MIP_HA
#if 0
	/* 
	 * Check whether this ICMP packet is received at the managed
	 * interface 
	 */
	if (had_is_ha_if(receivedifindex) == 0)
		return (0);
	/* XXX This check must be done with destination address */
#endif
#endif /* MIP_HA */


	if (IN6_IS_ADDR_LINKLOCAL(&from.sin6_addr)) 
		in6_lladdr = &from.sin6_addr;
	else 
		in6_gladdr = &from.sin6_addr;

        icp = (struct icmp6_hdr *)msg.msg_iov[0].iov_base;

	switch(icp->icmp6_type) {
#ifdef MIP_CN
	case ICMP6_DST_UNREACH:
	{
		u_int8_t nh;
		struct ip6_hdr *iip6;
		struct binding_cache *bc;
		struct ip6_ext *ext;
		struct ip6_rthdr2 *rth2;

		iip6 = (struct ip6_hdr *)(icp + 1);
		for (ext = (struct ip6_ext *)(iip6 + 1), nh = iip6->ip6_nxt;
		     nh == IPPROTO_HOPOPTS ||
		     nh == IPPROTO_FRAGMENT ||
		     nh == IPPROTO_DSTOPTS;
                     /* sizeof *ext is 2 bytes. */
		     nh = ext->ip6e_nxt, ext += (ext->ip6e_len + 1) << 2);
		if (nh != IPPROTO_ROUTING)
			break;

		rth2 = (struct ip6_rthdr2 *)ext;
		if (rth2->ip6r2_type != 2)
			break;
		bc = mip6_bc_lookup((struct in6_addr *)(rth2 + 1), &iip6->ip6_src, 0);
		if (bc)  {
			mip6_bc_delete(bc);
			syslog(LOG_INFO, 
			       "binding for %s is deleted due to ICMP destunreach.\n",
				ip6_sprintf(&iip6->ip6_dst));
		}
		break;
		
	}
#endif /* MIP_CN */

#ifndef MIP_CN
        /* 
	 * When RA is received at HA, HA must update both Home Prefix
	 * List and Home Agent List according to the RA prefix option
	 * and home agent information option. On the other hand, MN
	 * update only Home Prefix List by receiving RA. Home Agent
	 * List is maintained by Dynamic Home Agent Address Discovery
	 * procedure.  
	 */
	case ND_ROUTER_ADVERT:
		ra = (struct nd_router_advert *)icp;
		
/*
		if (debug)
			syslog(LOG_INFO,
		       		"ra lifetime = %d\n", ntohs(ra->nd_ra_router_lifetime));
*/

		/* parse nd_options */ 
		memset(&ndopts, 0, sizeof(ndopts));
		error = mip6_get_nd6options(&ndopts, 
			    (char *)icp + sizeof(struct nd_router_advert), 
				    readlen - sizeof(struct nd_router_advert));
		if (error)
			break;

#if defined(MIP_HA)
		hpfxhead = &hpfx_head;
#elif defined(MIP_MN) /* MIP_MN */
		mif = mnd_get_mipif(receivedifindex);
		if (mif == NULL)
			break;
		hpfxhead = &mif->mipif_hprefx_head; 
#endif /* MIP_HA */
		if (hpfxhead == NULL)
			break;

		hai_lifetime = ntohs(ra->nd_ra_router_lifetime);
		if (ndopts.ndpi) {
			hai_pfxlen = ndopts.ndpi->nd_opt_pi_prefix_len;
			in6_gladdr = &ndopts.ndpi->nd_opt_pi_prefix;
			if (hai_lifetime == 0)
				hai_lifetime = ntohs(ndopts.ndpi->nd_opt_pi_valid_time);
			
/*
			if (debug)
				syslog(LOG_INFO, "prefix lifetime = %d\n", hai_lifetime);
*/

                        /* check H flag */
			if (!(ndopts.ndpi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ROUTER)) {
#if defined(MIP_HA)
				/* delete HAL */
				hpfx = mip6_get_hpfxlist(&ndopts.ndpi->nd_opt_pi_prefix, 
							 ndopts.ndpi->nd_opt_pi_prefix_len, 
							 hpfxhead);
				if (hpfx == NULL) 
					break;

				hal = mip6_get_hal(hpfx, in6_gladdr);
				if (hal == NULL) 
					break;
				
				mip6_delete_hal(hpfx, &ndopts.ndpi->nd_opt_pi_prefix);
				break;
#else /* MIP_MN */
				break; /* MN ignores RA which not having R flag */
#endif /* MIP_HA */
			} else {
				/* 
				 * when the prefix field does not
				 * have global address, it should
				 * be ignored 
				 */
			        if (IN6_IS_ADDR_LINKLOCAL(in6_gladdr)
            				|| IN6_IS_ADDR_MULTICAST(in6_gladdr)
            				|| IN6_IS_ADDR_LOOPBACK(in6_gladdr)
            				|| IN6_IS_ADDR_V4MAPPED(in6_gladdr)
            				|| IN6_IS_ADDR_UNSPECIFIED(in6_gladdr)) 
					break;

				/* 
				 * when the prefix field does not
				 * contain 128-bit address, it should
				 * be ignored 
				 */				
				if ((in6_gladdr->s6_addr[15] == 0) && 
				    (in6_gladdr->s6_addr[14] == 0) &&
				    (in6_gladdr->s6_addr[13] == 0) &&
				    (in6_gladdr->s6_addr[12] == 0) &&
				    (in6_gladdr->s6_addr[11] == 0) &&
				    (in6_gladdr->s6_addr[10] == 0))
					break;
			}
			if (debug)
				syslog(LOG_INFO, "RA received from HA (%s)\n", 
				       ip6_sprintf(&ndopts.ndpi->nd_opt_pi_prefix));
		}
		
		/* Home Agent Information Option */
		if (ndopts.ndhai) {
			hai_preference = ntohs(ndopts.ndhai->nd_opt_hai_preference);
			hai_lifetime = ntohs(ndopts.ndhai->nd_opt_hai_lifetime);

			if (debug)
				syslog(LOG_INFO, 
				       "hainfo option found in RA (pref=%d,life=%d)\n", 
				       hai_preference, hai_lifetime);
		}

		/* 
		 * if lifetime is zero, correspondent HA must be 
		 * removed from home agent list 
		 */
		if (hai_lifetime == 0 || 
		    !(ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT)) {
			/* if prefix is not specified, just ignore RA */
			if (ndopts.ndpi == NULL)
				break;
			hpfx = mip6_get_hpfxlist(&ndopts.ndpi->nd_opt_pi_prefix, 
						 ndopts.ndpi->nd_opt_pi_prefix_len, 
						 hpfxhead);
			if (hpfx == NULL) 
				break;

			hal = mip6_get_hal(hpfx, in6_gladdr);
			if (hal == NULL) 
				break;
			
			mip6_delete_hal(hpfx, &ndopts.ndpi->nd_opt_pi_prefix);
			break;
		}


		/* need both linklocal and global address to add home prefix info */
		if (in6_gladdr == NULL)
			break;

		hpfx = mip6_get_hpfxlist(in6_gladdr, hai_pfxlen, hpfxhead);
		if (hpfx == NULL) {
#if defined(MIP_HA)			
			break;
#else
			/* add_hpfx */
#endif /* MIP_HA */
		}
#ifdef MIP_HA
		/* add or update home agent list */
		hal = had_add_hal(hpfx, in6_gladdr, 
				  in6_lladdr, hai_lifetime, hai_preference, 0);
		if (hal == NULL) {
			error = EINVAL;
			break;
		}



#endif /* MIP_HA */
		break;
#endif /* MIP_CN */

#ifdef MIP_HA
	case MIP6_HA_DISCOVERY_REQUEST:
		mip6stat.mip6s_dhreq++;
		dhreq = (struct mip6_dhaad_req *)msg.msg_iov[0].iov_base;
		error = send_haadrep(&from.sin6_addr, &dst, dhreq, receivedifindex);
		break;
		
	case MIP6_PREFIX_SOLICIT: 
	{
		struct mip6_prefix_solicit *mps;

		mip6stat.mip6s_mps++;
		mps = (struct mip6_prefix_solicit *)msg.msg_iov[0].iov_base;
		error = send_mpa(&from.sin6_addr, mps->mip6_ps_id, receivedifindex);
		break;
	}
		
#endif /* MIP_HA */

#ifdef MIP_MN
	case MIP6_HA_DISCOVERY_REPLY:
	{
		struct mip6_hpfxl *hpfx;
		struct mip6_mipif *mipif = NULL;
		char *options;
		int optlen, total;

		mip6stat.mip6s_dhreply++;
		dhrep = (struct mip6_dhaad_rep *)msg.msg_iov[0].iov_base;

		/* Is this HAADREPLY mine? */
		hoainfo = hoainfo_get_withdhaadid(ntohs(dhrep->mip6_dhrep_id));
		if (hoainfo == NULL) {
			error = ENOENT;
			break;
		}

#ifdef MIP_NEMO
		if ((dhrep->mip6_dhrep_reserved & MIP6_DHREP_FLAG_MR) == 0) {
			/* XXX */
			syslog(LOG_INFO, "HA does not support the basic NEMO protocol\n");
			error = ENOENT;
			break;
		} 
#endif /* MIP_NEMO */

		/*
		 * When MN receives DHAAD reply, it flushes all home
		 * agent entries in the list except for static
		 * configured entries. After flush, new entries will
		 * be added according to the reply packet 
		 */

		mipif = mnd_get_mipif(hoainfo->hinfo_ifindex);
		if (mipif == NULL)
			return (0);

		LIST_FOREACH(hpfx, &mipif->mipif_hprefx_head, hpfx_entry) {
			if (mip6_are_prefix_equal(&hoainfo->hinfo_hoa, 
						  &hpfx->hpfx_prefix, hpfx->hpfx_prefixlen)) {
				break;
			}
		}
		if (hpfx == NULL) {
			error  = ENOENT;
			break;
		}
		mip6_flush_hal(hpfx, MIP6_HAL_STATIC);

                options = (char *)icp + sizeof(struct mip6_dhaad_rep);
                total = readlen - sizeof(struct mip6_dhaad_rep);
                for (optlen = 0; total > 0; total -= optlen) {
                        options += optlen;
			dhrep_addr = (struct in6_addr *)options; 
                        optlen = sizeof(struct in6_addr);
			if (mnd_add_hal(hpfx, dhrep_addr, 0) == NULL)
				continue;

			if (debug) 
				syslog(LOG_INFO, "%s is added into hal list\n",
					ip6_sprintf(dhrep_addr));
                }

		bul = bul_get_homeflag(&hoainfo->hinfo_hoa);
		if (bul) {
			bul->bul_reg_fsm_state = MIP6_BUL_REG_FSM_STATE_DHAAD;
			bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_DHAAD_REPLY, NULL);
			syslog(LOG_INFO, "DHAAD gets %s\n",
			       ip6_sprintf(&bul->bul_peeraddr));

#ifdef MIP_MCOA
			if (!LIST_EMPTY(&bul->bul_mcoa_head)) {
				struct binding_update_list *mbul;

				for (mbul = LIST_FIRST(&bul->bul_mcoa_head); mbul;
					mbul = LIST_NEXT(mbul, bul_entry)) {
					mbul->bul_reg_fsm_state = MIP6_BUL_REG_FSM_STATE_DHAAD;
					bul_kick_fsm(mbul, MIP6_BUL_FSM_EVENT_DHAAD_REPLY, NULL);
				}
			}
#endif /* MIP_MCOA */
		}
		break;
	}
	case ICMP6_PARAM_PROB:
		switch (icp->icmp6_code) {
		case ICMP6_PARAMPROB_NEXTHEADER:
			/* Check whether this ICMP is for MH */
			break;
		case ICMP6_PARAMPROB_HEADER:
		case ICMP6_PARAMPROB_OPTION:
			return (0);
		}

		/* when multiple coa is supported, MN/MR can not
                 * determin which BU is failed or not. so remove all
                 * BU entries anyway 
		 */
		bul = bul_get(&dst, &from.sin6_addr);
		if (bul) {
			if (bul_kick_fsm(bul,
				MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB,
				NULL) == -1) {
				syslog(LOG_ERR,
				    "state transision by "
				    "MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB "
				    "failed.\n");
			}
		}
		break;
	case MIP6_PREFIX_ADVERT:
	{
		char *options;
		struct mip6_mipif *mif;
		struct mip6_hpfx_mn_exclusive mnoption;
		struct nd_opt_hdr *hdr;
		struct nd_opt_prefix_info *ndpi;
		int optlen = 0, total = 0;

		mpsadv = (struct mip6_prefix_advert *)msg.msg_iov[0].iov_base;

		/* Check MPS ID */
		LIST_FOREACH(mif, &mipifhead, mipif_entry) {
			if (mif->mipif_mps_id == ntohl(mpsadv->mip6_pa_id))
				break;
		}
		if (mif == NULL)
			break;
		

		options = (char *)icp + sizeof(struct mip6_prefix_advert);
                total = readlen - sizeof(struct mip6_prefix_advert);

		for (;total > 0; total -= optlen) {
                        options += optlen;
                        hdr = (struct nd_opt_hdr *)options; 
                        optlen = hdr->nd_opt_len << 3;

			switch (hdr->nd_opt_type) {
                        case ND_OPT_PREFIX_INFORMATION:
                                ndpi = (struct nd_opt_prefix_info *)hdr;
                                
				if (IN6_IS_ADDR_MULTICAST(&ndpi->nd_opt_pi_prefix) ||
				    IN6_IS_ADDR_LINKLOCAL(&ndpi->nd_opt_pi_prefix))
                                        break;

				/* aggregatable unicast address, rfc2374 XXX */
				if (ndpi->nd_opt_pi_prefix_len != 64)
					return (EINVAL);

				memset(&mnoption, 0, sizeof(mnoption)); 
				mnoption.hpfxlist_vltime = 
					ntohl(ndpi->nd_opt_pi_valid_time);
				mnoption.hpfxlist_pltime = 
					ntohl(ndpi->nd_opt_pi_preferred_time);

				mnd_add_hpfxlist(&ndpi->nd_opt_pi_prefix,
						 ndpi->nd_opt_pi_prefix_len,
						 &mnoption,
						 mif);
                                break;
                        default:
                                break;
                        }
                }
		break;
	}
#endif /* MIP_MN */
	default:
		break;
	}

	return (error);
}


#ifdef MIP_MN
int
mip6_icmp6_create_haanyaddr(haanyaddr, mpfx, mpfx_len)
        struct in6_addr *haanyaddr;
        struct in6_addr *mpfx;
	int mpfx_len;
{
        if (mpfx == NULL)
                return (EINVAL);

        if (mpfx_len == 64)
                mip6_create_addr(haanyaddr, &haanyaddr_ifid64, mpfx, mpfx_len);
        else
                mip6_create_addr(haanyaddr, &haanyaddr_ifidnn, mpfx, mpfx_len);

        return (0);
}
#endif /* MIP_HA */

void
mip6_create_addr(addr, ifid, prefix, prefixlen)
	struct in6_addr *addr;
	const struct in6_addr *ifid;
	struct in6_addr *prefix;
	u_int8_t prefixlen;
{
	 int i, bytelen, bitlen;
	 u_int8_t mask;

#ifndef s6_addr8
#define s6_addr8  __u6_addr.__u6_addr8
#endif

	 bzero(addr, sizeof(*addr));

	 bytelen = prefixlen / 8;
	 bitlen = prefixlen % 8;
	 for (i = 0; i < bytelen; i++)
		 addr->s6_addr8[i] = prefix->s6_addr8[i];
	 if (bitlen) {
		 mask = 0;
		 for (i = 0; i < bitlen; i++)
			 mask |= (0x80 >> i);
		 addr->s6_addr8[bytelen] = (prefix->s6_addr8[bytelen] & mask)
			 | (ifid->s6_addr8[bytelen] & ~mask);
		 
		 for (i = bytelen + 1; i < 16; i++)
			 addr->s6_addr8[i] = ifid->s6_addr8[i];
	 } else {
		 for (i = bytelen; i < 16; i++)
			 addr->s6_addr8[i] = ifid->s6_addr8[i];
	 }
#undef s6_addr8
	 return;
}


int
in6_mask2len(mask, lim0)
        struct in6_addr *mask;
        u_char *lim0;
{
        int x = 0, y;
        u_char *lim = lim0, *p;

        /* ignore the scope_id part */
        if (lim0 == NULL || lim0 - (u_char *)mask > sizeof(*mask))
                lim = (u_char *)mask + sizeof(*mask);
        for (p = (u_char *)mask; p < lim; x++, p++) {
                if (*p != 0xff)
                        break;
        }
        y = 0;
        if (p < lim) {
                for (y = 0; y < 8; y++) {
                        if ((*p & (0x80 >> y)) == 0)
                                break;
                }
        }

        /*
         * when the limit pointer is given, do a stricter check on the
         * remaining bits.
         */
        if (p < lim) {
                if (y != 0 && (*p & (0x00ff >> y)) != 0)
                        return (-1);
                for (p = p + 1; p < lim; p++)
                        if (*p != 0)
                                return (-1);
        }

        return (x * 8 + y);
}


#if 0
#ifdef MIP_MN
int
send_na_home(hoa, ifindex)
	struct in6_addr *hoa;
	u_int16_t ifindex;
{
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pi = NULL;
        struct sockaddr_in6 to;
        char adata[512], buf[1024];
        struct nd_neighbor_advert *na;
	struct sockaddr_dl sockdl;
        size_t nalen = 0;
	struct nd_opt_hdr *opthdr;
	char *addr;

        memset(&to, 0, sizeof(to));
        if (inet_pton(AF_INET6, "ff02::1",&to.sin6_addr) != 1) 
                return (-1);
	to.sin6_family = AF_INET6;
	to.sin6_port = 0;
	to.sin6_scope_id = 0;
	to.sin6_len = sizeof (struct sockaddr_in6);

        msg.msg_name = (void *)&to;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (void *) adata;
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) 
		+ CMSG_SPACE(sizeof(int));

	/* Packet Information i.e. Source Address */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	memset(pi, 0, sizeof(*pi));
	pi->ipi6_ifindex = ifindex;

	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	/* HopLimit Information (always 255) */
        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_HOPLIMIT;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)(CMSG_DATA(cmsgptr)) = 255;
        cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
		
	bzero(buf, sizeof(buf));
	na = (struct nd_neighbor_advert *)buf;
        na->nd_na_type = ND_NEIGHBOR_ADVERT;
        na->nd_na_code = 0;
        na->nd_na_cksum = 0;
        na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
	na->nd_na_target = *hoa;
	nalen = sizeof(struct nd_neighbor_solicit);

	opthdr = (struct nd_opt_hdr *) (buf + nalen);
	opthdr->nd_opt_type = ND_OPT_TARGET_LINKADDR; 

	memset(&sockdl, 0, sizeof(sockdl));
	if  (get_sockdl_from_ifindex(&sockdl, ifindex) == NULL)
		return (-1);

	switch(sockdl.sdl_type) {
	case IFT_ETHER:
#ifdef IFT_IEEE80211
	case IFT_IEEE80211:
#endif

#define ROUNDUP8(a) (1 + (((a) - 1) | 7))
		opthdr->nd_opt_len = (ROUNDUP8(ETHER_ADDR_LEN + 2)) >> 3;
		addr = (char *)(opthdr + 1);
		memcpy(addr, LLADDR(&sockdl), ETHER_ADDR_LEN);
		nalen += ROUNDUP8(ETHER_ADDR_LEN + 2);
#undef ROUNDUP8
		break;
	default:
		return (-1);
	}

	iov.iov_base = buf;
	iov.iov_len = nalen;

	if (debug)
		syslog(LOG_INFO, "send NA to overwrite HoA ND cache at home\n");

	if (sendmsg(icmp6sock, &msg, 0) < 0)
		perror ("sendmsg icmp6");

	return (errno);
}


static struct sockaddr_dl *
get_sockdl_from_ifindex(sdl, ifindex) 
	struct sockaddr_dl *sdl;
	u_int16_t ifindex;
{
	size_t needed;
        char *buf, *next;
        struct if_msghdr *ifm;
        int mib[6];
        
        mib[0] = CTL_NET;
        mib[1] = PF_ROUTE;
        mib[2] = 0;
        mib[3] = AF_INET6;
        mib[4] = NET_RT_IFLIST;
        mib[5] = 0;
        
        if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
                perror("sysctl");
		return (NULL);
	}

        if ((buf = malloc(needed)) == NULL) {
                perror("malloc");
		return (NULL);
	}

        if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
                perror("sysctl");
		free(buf);
		return (NULL);
	}

        for (next = buf; next < buf + needed; 
	     next += ifm->ifm_msglen) {
                ifm = (struct if_msghdr *)next;

                if (ifm->ifm_type != RTM_IFINFO) 
			continue;

		if (ifm->ifm_index != ifindex)
			continue;
		memcpy(sdl, (struct sockaddr_dl *)(ifm + 1), sizeof(*sdl));
			
		free(buf);
		return (sdl);
	}

        free(buf); 
	
	return (NULL);
}
#endif /* MIP_MN */
#endif

#if defined(MIP_CN) || defined(MIP_HA)
int
mipsock_behint_input(miphdr)
	struct mip_msghdr *miphdr;
{
	struct mipm_be_hint *behint;
	struct sockaddr *sin;
	struct in6_addr *peeraddr, *coa, *hoa;
	u_int8_t status;

	behint = (struct mipm_be_hint *)miphdr;

	/* get the peer address. */
	sin = MIPMBEH_PEERADDR(behint);
	if (sin->sa_family != AF_INET6)
		return (0);
	peeraddr = &((struct sockaddr_in6 *)sin)->sin6_addr;

	/* get my care-of address. */
	sin = MIPMBEH_COA(behint);
	if (sin->sa_family != AF_INET6)
		return (0);
	coa = &((struct sockaddr_in6 *)sin)->sin6_addr;

	/* get my home address. */
	sin = MIPMBEH_HOA(behint);
	if (sin->sa_family != AF_INET6)
		return (0);
	hoa = &((struct sockaddr_in6 *)sin)->sin6_addr;

	status = behint->mipmbeh_status;

	return (send_be(peeraddr, coa, hoa, status));
}
#endif /* MIP_CN || MIP_HA */

int
mipsock_nodetype_request(nodetype, enable)
	u_int8_t nodetype;
	u_int8_t enable;
{
	struct mipm_nodetype_info msg;
	size_t written;
	
	memset(&msg, 0, sizeof(struct mipm_nodetype_info));
	msg.mipmni_msglen = sizeof(struct mipm_nodetype_info);
	msg.mipmni_version = MIP_VERSION;
	msg.mipmni_type = MIPM_NODETYPE_INFO;
	msg.mipmni_nodetype = nodetype;
	msg.mipmni_enable = enable;

	written = write(mipsock, &msg, sizeof(struct mipm_nodetype_info));

	return (0);
}


static const char *binding_ack_status_desc[] = {
	"binding update accepted",
	"#1",
	"#2",
	"#3",
	"#4",
	"#5",
	"#6",
	"#7",
	"#8",
	"#9",
	"#10",
	"#11",
	"#12",
	"#13",
	"#14",
	"#15",
	"#16",
	"#17",
	"#18",
	"#19",
	"#20",
	"#21",
	"#22",
	"#23",
	"#24",
	"#25",
	"#26",
	"#27",
	"#28",
	"#29",
	"#30",
	"#31",
	"#32",
	"#33",
	"#34",
	"#35",
	"#36",
	"#37",
	"#38",
	"#39",
	"#40",
	"#41",
	"#42",
	"#43",
	"#44",
	"#45",
	"#46",
	"#47",
	"#48",
	"#49",
	"#50",
	"#51",
	"#52",
	"#53",
	"#54",
	"#55",
	"#56",
	"#57",
	"#58",
	"#59",
	"#60",
	"#61",
	"#62",
	"#63",
	"#64",
	"#65",
	"#66",
	"#67",
	"#68",
	"#69",
	"#70",
	"#71",
	"#72",
	"#73",
	"#74",
	"#75",
	"#76",
	"#77",
	"#78",
	"#79",
	"#80",
	"#81",
	"#82",
	"#83",
	"#84",
	"#85",
	"#86",
	"#87",
	"#88",
	"#89",
	"#90",
	"#91",
	"#92",
	"#93",
	"#94",
	"#95",
	"#96",
	"#97",
	"#98",
	"#99",
	"#100",
	"#101",
	"#102",
	"#103",
	"#104",
	"#105",
	"#106",
	"#107",
	"#108",
	"#109",
	"#110",
	"#111",
	"#112",
	"#113",
	"#114",
	"#115",
	"#116",
	"#117",
	"#118",
	"#119",
	"#120",
	"#121",
	"#122",
	"#123",
	"#124",
	"#125",
	"#126",
	"#127",
	"reason unspecified",
	"administratively prohibited",
	"Insufficient resources",
	"home registration not supported",
	"not home subnet",
	"not home agent for this mobile node",
	"duplicate address detection failed",
	"sequence number out of window",
	"expired home nonce index",
	"expired care-of nonce index",
	"expired Nonces",
	"#139"
	"#140",
	"#141",
	"#142",
	"#143",
	"#144",
	"#145",
	"#146",
	"#147",
	"#148",
	"#149",
	"#150",
	"#151",
	"#152",
	"#153",
	"#154",
	"#155",
	"#156",
	"#157",
	"#158",
	"#159",
	"#160",
	"#161",
	"#162",
	"#163",
	"#164",
	"#165",
	"#166",
	"#167",
	"#168",
	"#169",
	"#170",
	"#171",
	"#172",
	"#173",
	"#174",
	"#175",
	"#176",
	"#177",
	"#178",
	"#179",
	"#180",
	"#181",
	"#182",
	"#183",
	"#184",
	"#185",
	"#186",
	"#187",
	"#188",
	"#189",
	"#190",
	"#191",
	"#192",
	"#193",
	"#194",
	"#195",
	"#196",
	"#197",
	"#198",
	"#199",
	"#200",
	"#201",
	"#202",
	"#203",
	"#204",
	"#205",
	"#206",
	"#207",
	"#208",
	"#209",
	"#210",
	"#211",
	"#212",
	"#213",
	"#214",
	"#215",
	"#216",
	"#217",
	"#218",
	"#219",
	"#220",
	"#221",
	"#222",
	"#223",
	"#224",
	"#225",
	"#226",
	"#227",
	"#228",
	"#229",
	"#230",
	"#231",
	"#232",
	"#233",
	"#234",
	"#235",
	"#236",
	"#237",
	"#238",
	"#239",
	"#240",
	"#241",
	"#242",
	"#243",
	"#244",
	"#245",
	"#246",
	"#247",
	"#248",
	"#249",
	"#250",
	"#251",
	"#252",
	"#253",
	"#254",
	"#255"
};

static const char *binding_error_status_desc[] = {
	"#0",
	"Home Address Option used without a binding",
	"received message had an unknown MH type",
	"#3",
	"#4",
	"#5",
	"#6",
	"#7",
	"#8",
	"#9",
	"#10",
	"#11",
	"#12",
	"#13",
	"#14",
	"#15",
	"#16",
	"#17",
	"#18",
	"#19",
	"#20",
	"#21",
	"#22",
	"#23",
	"#24",
	"#25",
	"#26",
	"#27",
	"#28",
	"#29",
	"#30",
	"#31",
	"#32",
	"#33",
	"#34",
	"#35",
	"#36",
	"#37",
	"#38",
	"#39",
	"#40",
	"#41",
	"#42",
	"#43",
	"#44",
	"#45",
	"#46",
	"#47",
	"#48",
	"#49",
	"#50",
	"#51",
	"#52",
	"#53",
	"#54",
	"#55",
	"#56",
	"#57",
	"#58",
	"#59",
	"#60",
	"#61",
	"#62",
	"#63",
	"#64",
	"#65",
	"#66",
	"#67",
	"#68",
	"#69",
	"#70",
	"#71",
	"#72",
	"#73",
	"#74",
	"#75",
	"#76",
	"#77",
	"#78",
	"#79",
	"#80",
	"#81",
	"#82",
	"#83",
	"#84",
	"#85",
	"#86",
	"#87",
	"#88",
	"#89",
	"#90",
	"#91",
	"#92",
	"#93",
	"#94",
	"#95",
	"#96",
	"#97",
	"#98",
	"#99",
	"#100",
	"#101",
	"#102",
	"#103",
	"#104",
	"#105",
	"#106",
	"#107",
	"#108",
	"#109",
	"#110",
	"#111",
	"#112",
	"#113",
	"#114",
	"#115",
	"#116",
	"#117",
	"#118",
	"#119",
	"#120",
	"#121",
	"#122",
	"#123",
	"#124",
	"#125",
	"#126",
	"#127",
	"#128",
	"#129",
	"#130",
	"#131",
	"#132",
	"#133",
	"#134",
	"#135",
	"#136",
	"#137",
	"#138",
	"#139",
	"#140",
	"#141",
	"#142",
	"#143",
	"#144",
	"#145",
	"#146",
	"#147",
	"#148",
	"#149",
	"#150",
	"#151",
	"#152",
	"#153",
	"#154",
	"#155",
	"#156",
	"#157",
	"#158",
	"#159",
	"#160",
	"#161",
	"#162",
	"#163",
	"#164",
	"#165",
	"#166",
	"#167",
	"#168",
	"#169",
	"#170",
	"#171",
	"#172",
	"#173",
	"#174",
	"#175",
	"#176",
	"#177",
	"#178",
	"#179",
	"#180",
	"#181",
	"#182",
	"#183",
	"#184",
	"#185",
	"#186",
	"#187",
	"#188",
	"#189",
	"#190",
	"#191",
	"#192",
	"#193",
	"#194",
	"#195",
	"#196",
	"#197",
	"#198",
	"#199",
	"#200",
	"#201",
	"#202",
	"#203",
	"#204",
	"#205",
	"#206",
	"#207",
	"#208",
	"#209",
	"#210",
	"#211",
	"#212",
	"#213",
	"#214",
	"#215",
	"#216",
	"#217",
	"#218",
	"#219",
	"#220",
	"#221",
	"#222",
	"#223",
	"#224",
	"#225",
	"#226",
	"#227",
	"#228",
	"#229",
	"#230",
	"#231",
	"#232",
	"#233",
	"#234",
	"#235",
	"#236",
	"#237",
	"#238",
	"#239",
	"#240",
	"#241",
	"#242",
	"#243",
	"#244",
	"#245",
	"#246",
	"#247",
	"#248",
	"#249",
	"#250",
	"#251",
	"#252",
	"#253",
	"#254",
	"#255"
};


void
command_show_stat(s, line)
	int s;
	char *line; /* dummy */
{
	int i;
	u_quad_t mip6s_mh;

#define PS(msg, value) do {\
         command_printf(s, "     %qu " msg "\n", value);\
	} while(/*CONSTCOND*/0)

	command_printf(s, "Input Statistic:\n");

	mip6s_mh = 0;
	for (i = 0; i < sizeof(mip6stat.mip6s_mobility) / sizeof(u_quad_t); i++)
		mip6s_mh += mip6stat.mip6s_mobility[i];
	
	PS("Mobility Headers", mip6s_mh);
	PS("HoTI messages", mip6stat.mip6s_hoti);
	PS("CoTI messages", mip6stat.mip6s_coti);
	PS("HoT messages", mip6stat.mip6s_hot);
	PS("CoT messages", mip6stat.mip6s_cot);
	PS("BU messages", mip6stat.mip6s_bu);
	PS("BA messages", mip6stat.mip6s_ba);
	for (i =0; i < 256; i++) {
		if ((&mip6stat)->mip6s_ba_hist[i] != 0) {
			command_printf(s, "\t\t%qu %s\n",
				       (&mip6stat)->mip6s_ba_hist[i],
				       binding_ack_status_desc[i]);
		}
	}
	PS("BR messages", mip6stat.mip6s_br);
	PS("BE messages", mip6stat.mip6s_be);
	for (i = 1; i <= 2; i++) { /* currently only 2 codes are available */
		if ((&mip6stat)->mip6s_be_hist[i] != 0) {
			command_printf(s, "\t\t%qu %s\n",
				       (&mip6stat)->mip6s_be_hist[i],
				       binding_error_status_desc[i]);
		}
	}
	PS("DHAAD request", mip6stat.mip6s_dhreq);
	PS("DHAAD reply", mip6stat.mip6s_dhreply);
	PS("Home Address Option", mip6stat.mip6s_hao);
	PS("unverified Home Address Option", mip6stat.mip6s_unverifiedhao);
	PS("Routing Header type 2", mip6stat.mip6s_rthdr2);
	PS("reverse tunneled input", mip6stat.mip6s_revtunnel);
	PS("bad MH checksum", mip6stat.mip6s_checksum);
	PS("bad payload protocol", mip6stat.mip6s_payloadproto);
	PS("unknown MH type", mip6stat.mip6s_unknowntype);
	PS("not my home address", mip6stat.mip6s_nohif);
	PS("no related binding update entry", mip6stat.mip6s_nobue);
	PS("home init cookie mismatch", mip6stat.mip6s_hinitcookie);
	PS("careof init cookie mismatch", mip6stat.mip6s_cinitcookie);
	PS("unprotected binding signaling packets", mip6stat.mip6s_unprotected);
	PS("BUs discarded due to bad HAO", mip6stat.mip6s_haopolicy);
	PS("RR authentication failed", mip6stat.mip6s_rrauthfail);
	PS("seqno mismatch", mip6stat.mip6s_seqno);
	PS("parameter problem for HAO", mip6stat.mip6s_paramprobhao);
	PS("parameter problem for MH", mip6stat.mip6s_paramprobmh);
	PS("Invalid Care-of address", mip6stat.mip6s_invalidcoa);
	PS("Invalid mobility options", mip6stat.mip6s_invalidopt);

	command_printf(s, "Output Statistic:\n");

	mip6s_mh = 0;
	for (i = 0; i < sizeof(mip6stat.mip6s_omobility) / sizeof(u_quad_t); i++)
		mip6s_mh += mip6stat.mip6s_omobility[i];
	PS("Mobility Headers", mip6s_mh);
	PS("HoTI messages", mip6stat.mip6s_ohoti);
	PS("CoTI messages", mip6stat.mip6s_ocoti);
	PS("HoT messages", mip6stat.mip6s_ohot);
	PS("CoT messages", mip6stat.mip6s_ocot);
	PS("BU messages", mip6stat.mip6s_obu);
	PS("BA messages", mip6stat.mip6s_oba);
	for (i =0; i < 256; i++) {
		if ((&mip6stat)->mip6s_oba_hist[i] != 0) {
			command_printf(s, "\t\t%qu %s\n",
				       (&mip6stat)->mip6s_oba_hist[i],
				       binding_ack_status_desc[i]);
		}
	}
	PS("BR messages", mip6stat.mip6s_obr);
	PS("BE messages", mip6stat.mip6s_obe);
	for (i = 1; i <= 2; i++) { /* currently only 2 codes are available */
		if ((&mip6stat)->mip6s_obe_hist[i] != 0) {
			command_printf(s, "\t\t%qu %s\n",
				       (&mip6stat)->mip6s_obe_hist[i],
				       binding_error_status_desc[i]);
		}
	}
	PS("DHAAD request", mip6stat.mip6s_odhreq);
	PS("DHAAD reply", mip6stat.mip6s_odhreply);
	PS("MPA", mip6stat.mip6s_ompa);
	PS("MPS", mip6stat.mip6s_omps);
	PS("Home Address Option", mip6stat.mip6s_ohao);
	PS("Routing Header type 2", mip6stat.mip6s_orthdr2);
	PS("reverse tunneled output", mip6stat.mip6s_orevtunnel);
}
