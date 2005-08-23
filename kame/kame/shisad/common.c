/*	$KAME: common.c,v 1.21 2005/08/23 08:24:52 t-momose Exp $	*/

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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <unistd.h>
#ifdef __OpenBSD__
#include <sys/uio.h>
#endif

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif /* __NetBSD__ */
#include <netinet/in.h>
#include <netinet/ip6mh.h>
#include <netinet/ip6.h>
#include <netinet6/mip6.h>
#include <netinet/icmp6.h>
#include <net/mipsock.h>

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
struct nd6options ndopts;

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
#if defined(MIP_CN) || defined(MIP_HA)
	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
#endif /* MIP_CN || MIP_HA */
#ifdef MIP_HA
	ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
#endif /* MIP_HA */
#if defined(MIP_MN) || defined(MIP_HA)
	ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &filter);
#endif /* MIP_MN || MIP_HA */
	if (setsockopt(icmp6sock, IPPROTO_ICMPV6, 
		       ICMP6_FILTER, &filter, sizeof(filter)) < 0) {
		perror("setsockopt ICMP6_FILTER");
		exit(1);
	}

	syslog(LOG_INFO, "ICMP6 socket is %d.", icmp6sock);

	return;
}

#ifndef MIP_CN
int
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
			if (ndoptions->ndpi_start == NULL)
				ndoptions->ndpi_start = (struct nd_opt_prefix_info *)hdr;
			ndoptions->ndpi_end = (struct nd_opt_prefix_info *)hdr;
			if (IN6_IS_ADDR_MULTICAST(&ndoptions->ndpi_end->nd_opt_pi_prefix) ||
			    IN6_IS_ADDR_LINKLOCAL(&ndoptions->ndpi_end->nd_opt_pi_prefix))
				return (EINVAL);
			
                         /* aggregatable unicast address, rfc2374 XXX */
			if (ndoptions->ndpi_end->nd_opt_pi_prefix_len != 64)
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
	struct binding_update_list *bul;
#endif /* MIP_MN */

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
                return (EINVAL);
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
		error = cn_receive_dst_unreach(icp);
		break;
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
		error = receive_ra((struct nd_router_advert *)icp, readlen,
				   receivedifindex, in6_lladdr, in6_gladdr);
		break;
#endif /* MIP_CN */

#ifdef MIP_HA
	case MIP6_HA_DISCOVERY_REQUEST:
		mip6stat.mip6s_dhreq++;
		error = send_haadrep(&from.sin6_addr, &dst,
				     (struct mip6_dhaad_req *)icp, receivedifindex);
		break;
		
	case MIP6_PREFIX_SOLICIT: 
	{
		struct mip6_prefix_solicit *mps;

		mip6stat.mip6s_mps++;
		mps = (struct mip6_prefix_solicit *)icp;
		error = send_mpa(&from.sin6_addr, mps->mip6_ps_id, receivedifindex);
		break;
	}

	case ICMP6_TIME_EXCEEDED:
	case ICMP6_PARAM_PROB:
	case ICMP6_PACKET_TOO_BIG:
		error = relay_icmp6_error(icp, readlen, receivedifindex);
		break;
#endif /* MIP_HA */

#ifdef MIP_MN
	case MIP6_HA_DISCOVERY_REPLY:
		mip6stat.mip6s_dhreply++;
		error = receive_hadisc_reply((struct mip6_dhaad_rep *)icp, readlen);
		break;

	case MIP6_PREFIX_ADVERT:
		error = receive_mpa((struct mip6_prefix_advert *)icp, readlen);
		break;

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
		if (bul == NULL)
			break;

		if (bul_kick_fsm(bul,
				 MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB,
				 NULL) == -1) {
			syslog(LOG_ERR,
			       "state transision by "
			       "MIP6_BUL_FSM_EVENT_ICMP6_PARAM_PROB "
			       "failed.\n");
		}
		break;

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

struct ip6_rthdr2*
find_rthdr2(ip6)
	struct ip6_hdr *ip6;
{
	u_int8_t nh;
	struct ip6_ext *ext;
	struct ip6_rthdr2 *rth2;

	for (ext = (struct ip6_ext *)(ip6 + 1), nh = ip6->ip6_nxt;
	     nh == IPPROTO_HOPOPTS ||
		     nh == IPPROTO_FRAGMENT ||
		     nh == IPPROTO_DSTOPTS;
	     /* sizeof *ext is 2 bytes. */
	     nh = ext->ip6e_nxt, ext += (ext->ip6e_len + 1) << 2)
		;
	if (nh != IPPROTO_ROUTING)
		return (NULL);

	rth2 = (struct ip6_rthdr2 *)ext;
	if (rth2->ip6r2_type != 2)
		return (NULL);

	return (rth2);
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
	"Accepted but prefix discovery necessary",
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
	"Registration type change disallowed",
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
