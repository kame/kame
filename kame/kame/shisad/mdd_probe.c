/*      $KAME: mdd_probe.c,v 1.4 2005/12/16 02:20:25 keiichi Exp $  */
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/route.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <arpa/inet.h>

#include "mdd.h"

#define LINKLOCAL_ALLROUTERS "ff02::2"

extern struct cifl     cifl_head;

static int send_rs(struct cif  *);
static void defrtrlists_flush(int);

#ifdef MIP_MCOA
static void send_dereg_link(struct cif  *);
extern struct bl       bl_head;
extern char ingressif[IFNAMSIZ];
extern void get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
extern int mipsock_deregforeign(struct sockaddr_in6 *, struct sockaddr_in6 *, 
                                struct sockaddr_in6 *, int, u_int16_t);
#endif


int
probe_ifstatus(s)
	int s;
{
	struct ifmediareq ifmr;
        struct cif *cifp;

        LIST_FOREACH(cifp, &cifl_head, cif_entries) {
		memset(&ifmr, 0, sizeof(ifmr));
                strncpy(ifmr.ifm_name, cifp->cif_name, IFNAMSIZ);
		
		if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) 
			continue;
		
		if (cifp->cif_linkstatus == ifmr.ifm_status)
			continue;
		
		if ((ifmr.ifm_status & IFM_AVALID) == 0) 
			continue;
		
		switch (IFM_TYPE(ifmr.ifm_active)) {
		case IFM_ETHER:
			if (ifmr.ifm_status & IFM_ACTIVE) {
				/*defrtrlists_flush(s);*/
				send_rs(cifp);
			} 
#ifdef MIP_MCOA
			else {
				send_dereg_link(cifp);
			}
#endif /* MIP_MCOA */
			break;
			
		case IFM_FDDI:
		case IFM_TOKEN:
			break;
		case IFM_IEEE80211:
			if (ifmr.ifm_status & IFM_ACTIVE) {
				defrtrlists_flush(s);
				send_rs(cifp);
			}
#ifdef MIP_MCOA
			else {
                                send_dereg_link(cifp);
			}
#endif /* MIP_MCOA */
			break;
		}
		
		cifp->cif_linkstatus = ifmr.ifm_status;
	}
	
	return (0);
};


static int
send_rs(cifp)
	struct cif *cifp;
{
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pi = NULL;
        struct sockaddr_in6 to;
        char adata[512], buf[1024];
        struct nd_router_solicit *rs;
        size_t rslen = 0;
/*
	struct nd_opt_hdr *opthdr;
	char *addr;
*/
	int icmpsock = -1, on = 1;

	icmpsock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmpsock < 0) {
		perror("socket for ICMPv6");
		return (0);
	}
	if (setsockopt(icmpsock, IPPROTO_IPV6, 
		       IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
		perror("setsockopt IPV6_RECVPKTINFO for ICMPv6");
		return (0);
	}


        memset(&to, 0, sizeof(to));
        if (inet_pton(AF_INET6, LINKLOCAL_ALLROUTERS, &to.sin6_addr) != 1) {
		close (icmpsock);
                return (-1);
	}
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
	pi->ipi6_ifindex = if_nametoindex(cifp->cif_name);
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_HOPLIMIT;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)(CMSG_DATA(cmsgptr)) = 255;
        cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
		
	bzero(buf, sizeof(buf));
	rs = (struct nd_router_solicit *)buf;
        rs->nd_rs_type = ND_ROUTER_SOLICIT;
        rs->nd_rs_code = 0;
        rs->nd_rs_cksum = 0;
        rs->nd_rs_reserved = 0;
	rslen = sizeof(struct nd_router_solicit);


#if 0
	opthdr = (struct nd_opt_hdr *) (buf + rslen);
	opthdr->nd_opt_type = ND_OPT_SOURCE_LINKADDR; 

	switch(mif->sockdl.sdl_type) {
	case IFT_ETHER:
#ifdef IFT_IEEE80211
	case IFT_IEEE80211:
#endif
		opthdr->nd_opt_len = (ROUNDUP8(ETHER_ADDR_LEN + 2)) >> 3;
		addr = (char *)(opthdr + 1);
		memcpy(addr, LLADDR(&mif->sockdl), ETHER_ADDR_LEN);
		rslen += ROUNDUP8(ETHER_ADDR_LEN + 2);
		break;
	default:
		return (-1);
	}
#endif

	iov.iov_base = buf;
	iov.iov_len = rslen;
	
	if (sendmsg(icmpsock, &msg, 0) < 0)
		perror ("sendmsg");

	printf("sending -- RS\n");

	close (icmpsock);
	return (errno);
}

static void
defrtrlists_flush(s)
	int s;
{
	char dummyif[IFNAMSIZ+8];

	strncpy(dummyif, "lo0", sizeof(dummyif));

	if (ioctl(s, SIOCSRTRFLUSH_IN6, (caddr_t)&dummyif) < 0)
		perror("ioctl(SIOCSRTRFLUSH_IN6)");

}

#ifdef MIP_MCOA
static void
send_dereg_link(cifp)
        struct cif *cifp;
{
        int detachindex;
        struct in6_ifreq ifr6;
        struct sockaddr_in6 *sin6;
        struct sockaddr *rti_info[RTAX_MAX];
        char *next, *limit;
        struct if_msghdr *ifm;
        struct ifa_msghdr *ifam;
        struct binding *bp;
        char buf[1024];

        detachindex = if_nametoindex(cifp->cif_name);
        if (detachindex <= 0)
                return;
        
        LIST_FOREACH(bp, &bl_head, binding_entries) 
                break;

        if (bp == NULL) 
                return;


        /* Detached address must be global */
        if (in6_addrscope(&bp->coa.sin6_addr) != 
		__IPV6_ADDR_SCOPE_GLOBAL) 
                return;

        syslog(LOG_INFO, "probe: Detached %s from LINK %s\n", 
                inet_ntop(AF_INET6, &bp->coa.sin6_addr, buf, sizeof(buf)), cifp->cif_name);

        /* 
	 * address is now detached from the link, send
         * dereg BU from foreign to mnd 
         */
        if (bp) {
                int mib[6];
                char *ifmsg = NULL;
                int len;

                mib[0] = CTL_NET;
                mib[1] = PF_ROUTE;
                mib[2] = 0;
                mib[3] = AF_INET6;
                mib[4] = NET_RT_IFLIST;
                mib[5] = 0;

                if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
                        syslog(LOG_ERR, "sysctl %s\n", strerror(errno));
                        return;
                }
                if ((ifmsg = malloc(len)) == NULL) {
                        syslog(LOG_ERR, "malloc %s\n", strerror(errno));
                        return;
                }
                if (sysctl(mib, 6, ifmsg, &len, NULL, 0) < 0) {
                        syslog(LOG_ERR, "sysctl %s\n", strerror(errno));
                        free(ifmsg);
                        return;
                }
        
                limit = ifmsg +  len;
                for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {

                        ifm = (struct if_msghdr *) next;

                        if (ifm->ifm_type == RTM_NEWADDR) {
                                ifam = (struct ifa_msghdr *) next;

                                get_rtaddrs(ifam->ifam_addrs,
                                            (struct sockaddr *) (ifam + 1), rti_info);
                                sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];
                                memset(&ifr6, 0, sizeof(ifr6));
                                ifr6.ifr_addr = *sin6;

                                /* unknown interface !? */
                                if (if_indextoname(ifm->ifm_index, 
					ifr6.ifr_name) == NULL) 
                                        continue;

                                if(strlen(ingressif) > 0 && 
					(strncmp(ifr6.ifr_name, ingressif, strlen(ingressif)) == 0)) {
                                        continue;
                                }

                                if (ifm->ifm_index == detachindex)
                                        continue;

                                /* MUST be global */
                                if (in6_addrscope(&sin6->sin6_addr) !=  
					__IPV6_ADDR_SCOPE_GLOBAL) 
                                        continue;
                                        
                                if (ioctl(sock_dg6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
                        		syslog(LOG_ERR, 
						"ioctl(SIOCGIFAFLAG_IN6) %s\n", 
						strerror(errno));
                                        continue;
                                }
                                if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_READONLY) 
                                        continue;

                                fprintf(stderr, "send dereg from address is %s\n", 
					inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))); 

                                mipsock_deregforeign(&bp->hoa, &bp->coa, sin6, 
					ifm->ifm_index, bp->bid);

                                /* send bu to msock */
                                free(ifmsg);
                                return;
                        }
                }
                if (ifmsg)
                        free(ifmsg);
        }

        /* send bu to msock */
        return;
}
#endif /* MCOA */

