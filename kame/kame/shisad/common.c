/*	$KAME: common.c,v 1.33 2007/02/06 05:58:52 t-momose Exp $	*/

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
#include <sys/sysctl.h>
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
#include <arpa/inet.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "callout.h"
#include "command.h"
#include "stat.h"
#include "shisad.h"
#include "fsm.h"

extern struct mip6_mipif_list mipifhead;

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
		IPPROTO_IPV6, 
#ifdef IPV6_RECVPKTINFO
			   IPV6_RECVPKTINFO,
#else
			   IPV6_PKTINFO,
#endif
			   &on, sizeof(on));
	if (error < 0) {
		perror("setsockopt IPV6_RECVPKTINFO for ICMPv6");
		exit(1);
	}

	error = setsockopt(icmp6sock, 
		IPPROTO_IPV6,
#ifdef IPV6_RECVDSTOPTS
			   IPV6_RECVDSTOPTS,
#else
			   IPV6_DSTOPTS,
#endif
			   &on, sizeof(on));
	if (error < 0) {
		perror("setsockopt IPV6_RECVDSTOPTS for ICMPv6");
		exit(1);
	}

	error = setsockopt(icmp6sock, 
		IPPROTO_IPV6,
#ifdef IPV6_RECVRTHDR
			   IPV6_RECVRTHDR,
#else
			   IPV6_RTHDR,
#endif
			   &on, sizeof(on));
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
		syslog(LOG_ERR, "setsockopt ICMP6_FILTER was failed. but the system continues.");
	}

	syslog(LOG_INFO, "ICMP6 socket is %d.", icmp6sock);

	return;
}

#ifdef DSMIP
int
udp4_input_common(fd)
	int fd;
{
#ifdef MIP_HA
	struct msghdr msg;
	struct iovec iov;
	int n, mhlen;
	char buf[1024], adata[124];
	struct sockaddr_in from;
	struct ip6_hdr *ip6;
	struct ip6_dest *dest;
	struct ip6_opt_home_address *hoaopt;
	struct ip6_mh	*mh;
	char rthdr_on = 0;
	struct in6_addr hoa;
	struct in6_addr rtaddr;

	memset(&iov, 0, sizeof(iov));
	memset(&buf, 0, sizeof(buf));
	memset(&msg, 0, sizeof(msg));
	memset(&from, 0, sizeof(from));

	msg.msg_name = (caddr_t)&from;
	msg.msg_namelen = sizeof(from);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *) adata;
	msg.msg_controllen = sizeof(adata);

	n = recvmsg(udp4sock, &msg, 0);
	if (n < 0) {
		perror("recvmsg");
		return (errno);
	}

	/*
	 * - check whether it's containing IPv6 home address option
	 */
	ip6 = (struct ip6_hdr *)buf;

	dest = (struct ip6_dest *)(buf + sizeof(struct ip6_hdr));
	MIP6_FILL_PADDING((char *)(dest + 1), MIP6_HOAOPT_PADLEN);
	/* shall we check dest->ip6d_nxt, dest->ip6d_len?  */

	hoaopt = (struct ip6_opt_home_address *)
                        ((char *)(dest + 1) + MIP6_HOAOPT_PADLEN);
	/* shall we check hoaopt->ip6oh_type, hoaopt->ip6oh_len?  */

	mh = (struct ip6_mh *)((char *)(hoaopt + 1));
	mhlen = (mh->ip6mh_len + 1) << 3;

	if(memcmp(&from.sin_addr, &ip6->ip6_src.s6_addr[12],
	    sizeof(struct in_addr)) != 0) {
		syslog(LOG_ERR, "DSMIP NAT Traversal is not supported yet.");
		return(-1);
	}
	if(hoaopt) {
		mip6stat.mip6s_hao++;
		memcpy(&hoa, hoaopt->ip6oh_addr, sizeof(hoa));
	} else 
		mip6stat.mip6s_unverifiedhao++;

	if (debug) {
		syslog(LOG_INFO, "ipv4 src %s", inet_ntoa(from.sin_addr));
		syslog(LOG_INFO, "ipv6 src %s", ip6_sprintf(&ip6->ip6_src));
		syslog(LOG_INFO, "ipv6 dst %s", ip6_sprintf(&ip6->ip6_dst));
		syslog(LOG_INFO, "ipv6 hoa %s", ip6_sprintf(&hoa));
	}

	if (mh_input(&ip6->ip6_src, &ip6->ip6_dst, hoaopt ? &hoa : NULL,
			rthdr_on ? &rtaddr : NULL, mh, mhlen)) {
		return (-1);
	}
#endif /* MIPHA */

        return 0;
}

void
udp4sock_open()
{
	struct sockaddr_in server;

	memset(&server, 0, sizeof(server));
#define UDP4PORT 5555 
	server.sin_port = htons(UDP4PORT);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((udp4sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("socket SOCK_DGRAM");
		exit(1);
	}

	if(bind(udp4sock, (struct sockaddr *)&server, sizeof(server)))  {
		if (errno == EADDRINUSE)
			fprintf(stderr,"daemon already running\n");
		else
			perror("bind");
		exit(1);
	}

	syslog(LOG_INFO, "UDP4 socket is %d.", udp4sock);

	return;
	
}

#ifndef MIP_MN
void
raw4sock_open()
{
	struct sockaddr_in server;
	int bool = 1;

	memset(&server, 0, sizeof(server));
	server.sin_port = 0;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((raw4sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("socket SOCK_RAW");
		exit(1);
	}

	if (setsockopt(raw4sock, IPPROTO_IP, IP_HDRINCL,
		    (char *)&bool, sizeof(bool)) < 0) {
		perror("setsocketopt IP_HDRINCL");
		exit(1);
	}

	syslog(LOG_INFO, "RAW4 socket is %d.", raw4sock);

	return;
	
}
#endif /* !MIP_MN */
#endif /* DSMIP */

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
		bul = bul_get(&dst, &from.sin6_addr);
		if (bul == NULL)
			break;

		error = receive_mpa((struct mip6_prefix_advert *)icp, readlen, bul);
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

int
kernel_debug(mode)
	int mode;
{
	int value;
	size_t valsize = sizeof(value);
	int mib[] = {CTL_NET, PF_INET6, IPPROTO_MH, MIP6CTL_DEBUG};

	if (sysctl(mib, sizeof(mib) / sizeof(int), &value, &valsize, mode != -1 ? &mode : NULL , mode != -1 ? sizeof(mode) : 0) < 0) {
		perror("kernel_debug(): ");
		return (-1);
	}
	if (mode == -1)
		return (value);
	else
		return (mode);
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
	"ID of RFC4285 mismatched",
	"MIPV6-MESG-ID_REQD",
	"Authentication of RFC4285 was failed",
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

#define PS(msg, value) if (value != 0) {\
         command_printf(s, "     %qu " msg "\n", value);\
	} 

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
	PS("MPA", mip6stat.mip6s_mpa);
	PS("MPS", mip6stat.mip6s_mps);
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

#define DUMP 0

/*
 *   <------------------ datalen ------------------->
 *                  <-- exclude_data_len ---> 
 *   ---------------+-----------------------+--------
 *   ^              <--                   -->
 *   data     The area excluded from calculation Auth.
 *   - - - - - - - ->
 *     exclude_offset
 *
 *  If you don't need to exclude any area, you have to
 *  specify as follows:
 *    exclude_offset:   same as datalen
 *    exclude_data_len: 0
 */
void
calculate_authenticator(key, keylen, addr1, addr2, data, datalen,
			exclude_offset, exclude_data_len,
			authenticator, authenticator_len)
	u_int8_t *key;
	size_t keylen;
	struct in6_addr *addr1, *addr2;
	caddr_t data;
	size_t datalen;
	int exclude_offset;
	size_t exclude_data_len;
	u_int8_t *authenticator;
	size_t authenticator_len;
{
	int restlen;
	HMAC_CTX hmac_ctx;
	u_int8_t sha1result[20];

#if DUMP
	if (debug) {
		syslog(LOG_INFO, "key = %s\n",
		       hexdump(key, keylen));
		syslog(LOG_INFO, "addr1 = %s\n",
		       ip6_sprintf(addr1));
		syslog(LOG_INFO, "addr2 = %s\n",
		       ip6_sprintf(addr2));
		syslog(LOG_INFO, "datalen = %d\n", datalen);
		syslog(LOG_INFO, "exclude_offset = %d\n", exclude_offset);
		syslog(LOG_INFO, "exclude_data_len = %d\n", exclude_data_len);
	}
#endif

#ifndef __NetBSD__
	HMAC_CTX_init(&hmac_ctx);
#endif
	HMAC_Init(&hmac_ctx, (u_int8_t *)key, keylen, EVP_sha1());
	HMAC_Update(&hmac_ctx, (u_int8_t *)addr1, sizeof(*addr1));
#if DUMP
	syslog(LOG_INFO, "addr1: %s", hexdump((u_int8_t *)addr1, sizeof(*addr1)));
#endif
	HMAC_Update(&hmac_ctx, (u_int8_t *)addr2, sizeof(*addr2));
#if DUMP
	syslog(LOG_INFO, "addr2: %s", hexdump((u_int8_t *)addr2, sizeof(*addr2)));
#endif
	HMAC_Update(&hmac_ctx, (u_int8_t *)data, exclude_offset);
#if DUMP
	syslog(LOG_INFO, "data: %s", hexdump((u_int8_t *)data, exclude_offset));
#endif

	/* 
	 * Exclude authdata field in the mobility option to calculate
	 * authdata But it should be included padding area 
	 */

	restlen = datalen - (exclude_offset + exclude_data_len);
	if (restlen > 0) {
		HMAC_Update(&hmac_ctx, 
			    (u_int8_t *) data + exclude_offset + exclude_data_len,
			    restlen);
#if DUMP
	syslog(LOG_INFO, "restdata: %s", hexdump((u_int8_t *) data + exclude_offset + exclude_data_len, restlen));
#endif
	}

	HMAC_Final(&hmac_ctx, (u_int8_t *)sha1result, NULL);
	
	/* First96 */
	memcpy((void *)authenticator, (const void *)sha1result, 
	       authenticator_len);
#if DUMP
	if (debug)
		syslog(LOG_INFO, "authenticator = %s\n", 
		       hexdump(authenticator, authenticator_len));
#endif
}
