/*      $KAME: network.c,v 1.11 2005/10/27 02:46:57 mitsuya Exp $  */

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
#include <unistd.h>
#include <errno.h>

#include <syslog.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <net/mipsock.h>

#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include "callout.h"
#include "shisad.h"
#include "stat.h"
#include "fsm.h"

#define SA2SIN6(ss) ((struct sockaddr_in6 *)(ss))
#define SA2SIN(ss) ((struct sockaddr_in *)(ss))

#ifdef MIP_NEMO
#ifdef MIP_IPV4MNPSUPPORT
extern int ipv4mnpsupport;
#endif /* MIP_IPV4MNPSUPPORT */
#endif /* MIP_NEMO */

#ifdef MIP_NEMO
static struct sockaddr_in6 sin6_default = {
	sizeof(struct sockaddr_in6), AF_INET6, 0, 0,
	IN6ADDR_ANY_INIT
}; 
#ifdef MIP_IPV4MNPSUPPORT
static struct sockaddr_in sin_default = {
	sizeof(struct sockaddr_in), AF_INET, 0,
	{INADDR_ANY}
}; 
#endif /* MIP_IPV4MNPSUPPORT */
#endif /* MIP_NEMO */

static struct in6_addrlifetime static_lifetime = 
	{0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME};
#ifdef MIP_NEMO
static int nemo_gif_init(char *);
static int inet_len2mask(int, int, struct sockaddr *);
static struct in6_nbrinfo *getnbrinfo __P((struct in6_addr *, int, int));
#endif

int
inet_are_prefix_equal(p1, p2, len)
        void *p1, *p2;
        int len;
{
        int bytelen, bitlen;
	u_int8_t *cp1, *cp2;

        /* sanity check */
        if (0 > len || len > 128) {
                syslog(LOG_ERR, "inet_are_prefix_equal:"
		       "invalid prefix length(%d)\n", len);
                return (0);
        }

        bytelen = len / 8;
        bitlen = len % 8;

        if (memcmp(p1, p2, bytelen))
                return (0);
	cp1 = p1;
	cp2 = p2;
        if (bitlen != 0 &&
            *(cp1 + bytelen) >> (8 - bitlen) !=
            *(cp2 + bytelen) >> (8 - bitlen))
                return (0);

        return (1);
}


int
set_ip6addr(ifname, ip6addr, prefixlen, flags) 
	char *ifname;
	struct in6_addr *ip6addr;
	int prefixlen;
	int flags;
{
	int s = 0;
	struct in6_aliasreq ifra;

	memset(&ifra, 0, sizeof(ifra));

	if ((s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	memcpy(ifra.ifra_name, ifname, strlen(ifname));

	ifra.ifra_prefixmask.sin6_family 
		= ifra.ifra_addr.sin6_family = AF_INET6; 
	ifra.ifra_prefixmask.sin6_len 
		= ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	memcpy(&ifra.ifra_addr.sin6_addr, ip6addr, sizeof(struct in6_addr));

	memset(&ifra.ifra_prefixmask.sin6_addr, 0xff, 
	       (prefixlen) ? prefixlen/8 : 16); 

	ifra.ifra_flags = flags;
	ifra.ifra_lifetime = static_lifetime;

	if (ioctl(s, SIOCAIFADDR_IN6, &ifra) < 0) {
		syslog(LOG_ERR, "%s ioctl(SIOCAIFADDR_IN6) %s",  
		       __FUNCTION__, strerror(errno));
		close (s);
		return (errno);
	}
	close (s);

	return (0);
}

int
delete_ip6addr(ifname, ip6addr, prefixlen) 
	char *ifname;
	struct in6_addr *ip6addr;
	int prefixlen;
{
	int s = 0;
	struct in6_aliasreq ifra;

	memset(&ifra, 0, sizeof(ifra));

	if ((s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		syslog(LOG_ERR, "socket open failed\n");
		return (-1);
	}

	memcpy(ifra.ifra_name, ifname, strlen(ifname));
	ifra.ifra_prefixmask.sin6_family 
		= ifra.ifra_addr.sin6_family = AF_INET6; 
	ifra.ifra_prefixmask.sin6_len 
		= ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);

	memcpy(&ifra.ifra_addr.sin6_addr, 
		ip6addr, sizeof(struct in6_addr));
	memset(&ifra.ifra_prefixmask.sin6_addr,
		0xff, (prefixlen) ? prefixlen/8 : 16); 

	ifra.ifra_flags |= IN6_IFF_NODAD;
	ifra.ifra_lifetime = static_lifetime;

	if (ioctl(s, SIOCDIFADDR_IN6, &ifra) < 0) {
		syslog(LOG_ERR, "%s ioctl(SIOCDIFADDR_IN6) %s",  
		       __FUNCTION__, strerror(errno));
		close (s);
		return (-1);
	}
	close (s);

	return (0);
}


#ifdef MIP_NEMO
int
nemo_tun_set(src, dst, gifindex, nxthop_enable)
	struct sockaddr *src;
	struct sockaddr *dst;
	u_int16_t gifindex;
	int nxthop_enable;
{
	int ioctls = 0;
	struct in6_aliasreq in6_addreq;
	struct in6_ifreq nexthopreq;
	struct sockaddr_in6 *src6, *dst6, ar;
	char if_name[IFNAMSIZ];

	if (src->sa_family != dst->sa_family) 
		return (EINVAL);

	if (src->sa_family != AF_INET6)
		return (0);

	if((ioctls = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		return (errno);
	}
	
	/* Check Gif tunnel */
	if (if_indextoname(gifindex, if_name) == NULL) {
		syslog(LOG_ERR, "%s if_indextoname() %s",  
		       __FUNCTION__, strerror(errno));
		close (ioctls);
		return (errno);
	}

	if (nemo_gif_init(if_name) > 0) {
		close (ioctls);
		return (EINVAL);
	}
	
	src6 = (struct sockaddr_in6 *)src;
	dst6 = (struct sockaddr_in6 *)dst;
	
	memset(&in6_addreq, 0, sizeof(in6_addreq)); 

	strncpy(in6_addreq.ifra_name, if_name, strlen(if_name));
	memcpy(&in6_addreq.ifra_addr, src6, src6->sin6_len);
	memcpy(&in6_addreq.ifra_dstaddr, dst6, dst6->sin6_len);

		syslog(LOG_INFO, "tun_setup: src %s\n", 
		       ip6_sprintf(&src6->sin6_addr));
		syslog(LOG_INFO, "tun_setup: dst %s\n", 
		       ip6_sprintf(&dst6->sin6_addr));
	
	if(ioctl(ioctls, SIOCSIFPHYADDR_IN6, &in6_addreq) < 0) {
		syslog(LOG_ERR, "%s ioctl(SIOCSIFPHYADDR_IN6) %s",  
		       __FUNCTION__, strerror(errno));
		close (ioctls);
		return (errno);
	}

	if (nxthop_enable) {
		/* get the access router address. */
		if (nemo_ar_get(&src6->sin6_addr, &ar)) {
			memset(&nexthopreq, 0, sizeof(struct in6_ifreq));
			strncpy(nexthopreq.ifr_name, if_name, strlen(if_name));
			memcpy(&nexthopreq.ifr_ifru.ifru_addr, &ar,
			    sizeof(struct sockaddr_in6));
			if (ioctl(ioctls, SIOCSIFPHYNEXTHOP_IN6, &nexthopreq) < 0) {
				perror("ioctl: failed to set next hop of nemo");
				/* XXX */
			}
		} else {
			syslog(LOG_ERR,
			    "cannot get AR's link-local address\n");
		}
	}
	    
	
	close(ioctls);

	return (0);
}


int
nemo_tun_del(gifname)
	char *gifname;
{
	int	ioctls = 0;
	struct ifreq ifr_del;

	if((ioctls = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		return (errno);
	}

	memset(&ifr_del, 0, sizeof(ifr_del));

	if (debug)
		syslog(LOG_INFO, "%s is tore down\n", gifname);
		
	strncpy(ifr_del.ifr_name, gifname, strlen(gifname));

	if(ioctl(ioctls, SIOCDIFPHYADDR, &ifr_del) < 0) {
		syslog(LOG_ERR, "%s ioctl(SIOCDIFPHYADDR) %s",  
		       __FUNCTION__, strerror(errno));
		close(ioctls);
		return (errno);
	}


	close(ioctls);
	return (errno);
}


static int
nemo_gif_init(gifname)
	char *gifname;
{
	int flags;

	flags = nemo_ifflag_get(gifname);

#if 0
	/* 
	 * If specified gif interface is not available, exit
	 * program. No way to create gif interface dynamically on
	 * KAME.  
	 */
	if (flags < 0) {
		syslog(LOG_ERR, "%s is not available %d 0x%x\n", gifname, flags, flags);
		exit(-1);
	}
#endif
		
	/* Set IFF_UP for the gif interface */
	if((flags & IFF_UP) == 0) 
		nemo_ifflag_set(gifname, (flags |= IFF_UP));
	
	return (0);
}

int
nemo_ifflag_get(ifname)
	char *ifname;
{
	int s;
	struct ifreq ifreq;

	if((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	memset(&ifreq, 0, sizeof(ifreq));
	(void)strncpy(ifreq.ifr_name, ifname, strlen(ifname));

	if(ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifreq) < 0) {
		perror("ioctl: SIOCGIFFLAGS");
		
		syslog(LOG_ERR, "%s is not available\n", ifname);
		return (-1);
	}

	close (s);

	return (ifreq.ifr_flags);
}

int
nemo_ifflag_set(ifname, flags)
	char *ifname;
	short flags;
{
	int s;
	struct ifreq ifreq;

	if((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		return (errno);
	}

	memset(&ifreq, 0, sizeof(ifreq));
	(void)strncpy(ifreq.ifr_name, ifname, strlen(ifname));
	ifreq.ifr_flags = flags;

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifreq) < 0 ) {
		perror("ioctl SIOCSIFFLAGS\n");
		close (s);
		return (errno);
	}

	close (s);

	return (0);
}

int
route_add(dest, gate, mask, pfxlen, gifindex)
	struct sockaddr *dest, *gate, *mask;
	int pfxlen;
	u_int16_t gifindex;
{
	int s;
	int rtm_addrs = RTA_DST|RTA_GATEWAY|RTA_NETMASK;
	struct{ 
		struct rt_msghdr m_rtm;
		char   m_space[512];
	} m_rtmsg;
	register char *cp = m_rtmsg.m_space;
	register int l;
	struct sockaddr_storage so_mask;
	struct sockaddr_dl so_dl;

	if ((dest == NULL) || (gate == NULL))
		return (-1);

	memset(&so_mask, 0, sizeof(struct sockaddr_storage));
	memset(&so_dl, 0, sizeof(struct sockaddr_dl));
	memset(&m_rtmsg, 0, sizeof(m_rtmsg));
  
	if((s = socket(PF_ROUTE,SOCK_RAW,0)) < 0){
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		return (-1);
	}
  
	if (mask) {
		memcpy(&so_mask, mask, mask->sa_len);
	} else {
		so_mask.ss_len = dest->sa_len;
		so_mask.ss_family = dest->sa_family;
		inet_len2mask(so_mask.ss_family, pfxlen,
		    (struct sockaddr *)&so_mask);
	}

	if ((dest->sa_family != gate->sa_family)
	    || (dest->sa_family != so_mask.ss_family))
		return (-1);
	if ((dest->sa_len != gate->sa_len)
	    || (dest->sa_len != so_mask.ss_len))
		return (-1);

#if 0
	if (debug)
		syslog(LOG_INFO, "route add dest %s\n", 
		       ip6_sprintf(dest));
#endif

	so_dl.sdl_family = AF_LINK;
	so_dl.sdl_len = sizeof(struct sockaddr_dl);
	so_dl.sdl_index = gifindex;
	
#if 0
	if (debug) {
		syslog(LOG_INFO, "route add gw %s\n", 
		       ip6_sprintf(gate));
		syslog(LOG_INFO, "ifindex %d\n", gifindex);
	}
#endif

	rtm_addrs |= RTA_IFP;

#define rtmsg m_rtmsg.m_rtm
	rtmsg.rtm_type = RTM_ADD;
	rtmsg.rtm_flags = RTF_STATIC | RTF_UP |RTF_GATEWAY;
	rtmsg.rtm_version = RTM_VERSION;
	rtmsg.rtm_seq = 0;
	rtmsg.rtm_addrs = rtm_addrs;
	bzero(&(rtmsg.rtm_rmx),sizeof(struct rt_metrics));
	rtmsg.rtm_inits = 0;
  
#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define NEXTADDR(u) \
    l = ROUNDUP((u)->sa_len); memcpy(cp, (char *)(u), (u)->sa_len); cp += l;


	NEXTADDR((struct sockaddr *)dest);
    	NEXTADDR((struct sockaddr *)gate);
	NEXTADDR((struct sockaddr *)&so_mask);
	NEXTADDR((struct sockaddr *)&so_dl);
	rtmsg.rtm_msglen = l = cp - (char *)&m_rtmsg;

	if (write(s, (char *)&m_rtmsg, l) < 0){
		perror("writing to routing socket");
		close (s);
		return (-1);
	}
	close(s);

	return (0);
}
#undef ROUNDUP
#undef NEXTADDR

/* when gifindex is zero, it indicates default route flush */
int
route_del(gifindex)
	u_int16_t gifindex;
{
	size_t needed;
	int s, mib[6], rlen, seqno;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;
	char *buf, *next, *lim;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = mib[5] = 0;
#if defined(MIP_NEMO) && defined(MIP_IPV4MNPSUPPORT)
	mib[3] = AF_UNSPEC;
#else
	mib[3] = AF_INET6;
#endif
	mib[4] = NET_RT_DUMP;
	
	if(sysctl(mib, 6, NULL, &needed, NULL, 0) < 0){
		perror("sysctl");
		return (-1);
	}
	if ((buf = malloc(needed)) == NULL){
		perror("malloc");
		return (-1);
	}
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0){
		perror("sysctl");
		free(buf);
		return (-1);
	}
	lim = buf + needed;
	seqno = 0;

	if((s = socket(PF_ROUTE, SOCK_RAW, 0)) < 0){
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		free(buf);
		return (-1);
	}
	shutdown(s,0);

	for (next = buf; next < lim; next += rtm->rtm_msglen) {

		rtm = (struct rt_msghdr *)next;
		sa = (struct sockaddr *)(rtm + 1);
    
		if ((sa->sa_family != AF_INET6)
		    && (sa->sa_family != AF_INET))
			continue;

		if(gifindex && rtm->rtm_index != gifindex)
			continue;

		if (gifindex == 0) {
			switch (sa->sa_family) {
			case AF_INET6:
				if (!IN6_ARE_ADDR_EQUAL(&SA2SIN6(sa)->sin6_addr,
					&sin6_default.sin6_addr))
					continue;
				break;
#ifdef MIP_NEMO
#ifdef MIP_IPV4MNPSUPPORT
			case AF_INET:
				if (ipv4mnpsupport
				    && (SA2SIN(sa)->sin_addr.s_addr
				    != sin_default.sin_addr.s_addr))
					continue;
				break;
#endif /* MIP_IPV4MNPSUPPORT */
#endif /* MIP_NEMO */
			default:
				continue;
			}
		}
#if 0
		if (debug)
			syslog(LOG_INFO, "route del addr %s\n", 
			       ip6_sprintf(&sin6->sin6_addr));
#endif
					
		rtm->rtm_type = RTM_DELETE;
		rtm->rtm_seq = seqno;
		rlen = write(s, next, rtm->rtm_msglen);
		if(rlen < (int)rtm->rtm_msglen){
			break;
		}
		seqno ++;
	}
	free(buf);
	close(s);

	return (0);
}

static int
inet_len2mask(af, plen, sa)
	int af, plen;
        struct sockaddr *sa;
{
        int pfxmsk, tmpnum, maxlen;
        char *tgtaddrp;

	switch (af) {
	case AF_INET6:
		maxlen = 128;
		tgtaddrp = (char *)&SA2SIN6(sa)->sin6_addr;
		break;
	case AF_INET:
		maxlen = 32;
		tgtaddrp = (char *)&SA2SIN(sa)->sin_addr;
		break;
	default:
		syslog(LOG_ERR, "unknown address family (%d).\n", af);
		return (-1);
	}
	if (plen > maxlen)
		return (-1);

        pfxmsk = plen >> 3;
        tmpnum = plen & 7;

        memset((void *)tgtaddrp, 0, (maxlen / 8));
        if(pfxmsk > 0)
                memset((void *)tgtaddrp, 0xff, pfxmsk);
        if(tmpnum > 0)
                *((u_char *)tgtaddrp + pfxmsk) = (0xff00 >> tmpnum) &  0xff;

	return (0);
}


struct sockaddr_in6 *
nemo_ar_get(coa, ret6)
	struct in6_addr *coa;
	struct sockaddr_in6 *ret6;
{
	struct in6_ifreq dstaddrreq;
	struct sockaddr_in6 sa6_coa;
	int s;
#if defined(ICMPV6CTL_ND6_PRLIST) && !defined(__NetBSD__)
	int mib[] = { CTL_NET, PF_INET6, IPPROTO_ICMPV6, ICMPV6CTL_ND6_PRLIST };
	char *buf;
	struct in6_prefix *p, *ep, *n;
	struct sockaddr_in6 *advrtr;
	size_t l;
	u_int16_t ifindex;
	struct sockaddr_in6 *sin6;

	ifindex = get_ifindex_from_address(coa);
	if (ifindex == 0)
		return (NULL);

	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &l, NULL, 0) < 0) {
		perror("sysctl(ICMPV6CTL_ND6_PRLIST)");
		/*NOTREACHED*/
	}
	buf = malloc(l);
	if (!buf) {
		perror("malloc");
		/*NOTREACHED*/
	}
	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &l, NULL, 0) < 0) {
		perror("sysctl(ICMPV6CTL_ND6_PRLIST)");
		/*NOTREACHED*/
	}

	ep = (struct in6_prefix *)(buf + l);
	for (p = (struct in6_prefix *)buf; p < ep; p = n) {
		advrtr = (struct sockaddr_in6 *)(p + 1);
		n = (struct in6_prefix *)&advrtr[p->advrtrs];
		
		if (ifindex != p->if_index)
			continue;

		if (inet_are_prefix_equal(&p->prefix.sin6_addr, 
					  coa, p->prefix.sin6_len) == 0)
			continue;
		
		/* XXX need to check lifetime and refcount? */ 

		/*
		 * "advertising router" list is meaningful only if the prefix
		 * information is from RA.
		 */
		if (p->advrtrs) {
			int j;
			sin6 = advrtr;

			for (j = 0; j < p->advrtrs; j++) {
				struct in6_nbrinfo *nbi;

				nbi = getnbrinfo(&sin6->sin6_addr,
				    p->if_index, 0);
				if (nbi) {
					switch (nbi->state) {
					case ND6_LLINFO_REACHABLE:
					case ND6_LLINFO_STALE:
					case ND6_LLINFO_DELAY:
					case ND6_LLINFO_PROBE:
						memset(ret6, 0, sizeof(*ret6));
						ret6->sin6_family = AF_INET6;
						ret6->sin6_len = sizeof(*sin6);
						ret6->sin6_scope_id = p->if_index;
						ret6->sin6_addr = sin6->sin6_addr;
						free(buf);
						return (ret6);
					default:
						break;
					}
				} 
				sin6++;
			}
		} else {
			break;
		}
	}
	free(buf);
#else
	/* XXX the following code seems buggy.  never expect to work. */
	struct in6_prlist pr;
	int i;
	struct timeval time;
	u_int16_t ifindex;

	ifindex = get_ifindex_from_address(coa);
	if (ifindex == 0)
		return (NULL);

	gettimeofday(&time, 0);

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));
		/* NOTREACHED */
	}
	bzero(&pr, sizeof(pr));
	strlcpy(pr.ifname, "lo0", sizeof(pr.ifname)); /* dummy */
	if (ioctl(s, SIOCGPRLST_IN6, (caddr_t)&pr) < 0) {
		perror("ioctl(SIOCGPRLST_IN6)");
		/* NOTREACHED */
	}
#define PR pr.prefix[i]
	for (i = 0; PR.if_index && i < PRLSTSIZ ; i++) {
		struct sockaddr_in6 p6;

		if (ifindex != PR.if_index)
			continue;

#if defined(NDPRF_ONLINK) && !defined(__NetBSD__)
		p6 = PR.prefix;
#else
		memset(&p6, 0, sizeof(p6));
		p6.sin6_family = AF_INET6;
		p6.sin6_len = sizeof(p6);
		p6.sin6_addr = PR.prefix;
#endif

		/*
		 * copy link index to sin6_scope_id field.
		 * XXX: KAME specific.
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&p6.sin6_addr)) {
			u_int16_t linkid;

			memcpy(&linkid, &p6.sin6_addr.s6_addr[2],
			    sizeof(linkid));
			linkid = ntohs(linkid);
			p6.sin6_scope_id = linkid;
			p6.sin6_addr.s6_addr[2] = 0;
			p6.sin6_addr.s6_addr[3] = 0;
		}

		if (inet_are_prefix_equal(&p6.sin6_addr, 
					  coa, PR.prefixlen) == 0)
			continue;
		

		/*
		 * "advertising router" list is meaningful only if the prefix
		 * information is from RA.
		 */
		if (0 &&	/* prefix origin is almost obsolted */
		    PR.origin != PR_ORIG_RA)
			;
		else if (PR.advrtrs) {
			int j;
			for (j = 0; j < PR.advrtrs; j++) {
				struct in6_nbrinfo *nbi;

				nbi = getnbrinfo(&PR.advrtr[j],
				    PR.if_index, 0);
				if (nbi) {
#if 0
					switch (nbi->state) {
					case ND6_LLINFO_REACHABLE:
					case ND6_LLINFO_STALE:
					case ND6_LLINFO_DELAY:
					case ND6_LLINFO_PROBE:
						memset(ret6, 0, sizeof(*ret6));
						ret6->sin6_family = AF_INET6;
						ret6->sin6_len = sizeof(*ret6);
						ret6->sin6_addr = PR.advrtr[j];
						ret6->sin6_scope_id = PR.if_index;

						close (s);
						return (ret6);
					default:
						break;
						;
					}
#else
					memset(ret6, 0, sizeof(*ret6));
					ret6->sin6_family = AF_INET6;
					ret6->sin6_len = sizeof(*ret6);
					ret6->sin6_addr = PR.advrtr[j];
					ret6->sin6_scope_id = PR.if_index;

					close (s);
					return (ret6);
#endif
				} 
			}
		} 
	}
#undef PR
	close(s);
#endif
	/*
	 * we couldn't find the address of the access router from
	 * prefix information.  try to get the destination address of
	 * the interface, if the interface is p2p interface.
	 */
	memset(&dstaddrreq, 0, sizeof(struct in6_ifreq));
	if_indextoname(ifindex, dstaddrreq.ifr_name);
	memset(&sa6_coa, 0, sizeof(struct sockaddr_in6));
	sa6_coa.sin6_len = sizeof(struct sockaddr_in6);
	sa6_coa.sin6_family = AF_INET6;
	sa6_coa.sin6_addr = *coa;
	sa6_coa.sin6_scope_id = ifindex;
	memcpy(&dstaddrreq.ifr_addr, &sa6_coa, sizeof(struct sockaddr_in6));
	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR,
		    "cannot create INET6 socket in nemo_ar_get()");
	}
	if (ioctl(s, SIOCGIFDSTADDR_IN6, &dstaddrreq) < 0) {
		syslog(LOG_ERR,
		    "SIOCGIFDSTADDR_IN6 failed in nemo_ar_get()");
	} else {
		close (s);
		*ret6 = dstaddrreq.ifr_dstaddr;
		ret6->sin6_scope_id = ifindex;
		return (ret6);
	}
	close (s);

	return (NULL);
}

int
nemo_gif_ar_set(tunnel, coa)
	char *tunnel;
	struct in6_addr *coa;
{
        int arsock;
        struct in6_ifreq ifreq6;
        struct sockaddr_in6 *ar_sin6, ar_sin6_orig;

        ar_sin6 = nemo_ar_get(coa, &ar_sin6_orig);
        if (ar_sin6 == NULL) {
                printf("sorry no AR\n");
                return (-1);
        }

        memset(&ifreq6, 0, sizeof(ifreq6));
        strncpy(ifreq6.ifr_name, tunnel, strlen(tunnel));
        memcpy(&ifreq6.ifr_ifru.ifru_addr, ar_sin6, sizeof(struct sockaddr_in6));

        arsock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (arsock < 0) {
                perror("socket");
                return (errno);
        }

        if (ioctl(arsock, SIOCSIFPHYNEXTHOP_IN6, &ifreq6) < 0) {
                perror("ioctl");
		close(arsock);
                return (errno);
        }

	close(arsock);
        return (0);
}


static struct in6_nbrinfo *
getnbrinfo(addr, ifindex, warning)
	struct in6_addr *addr;
	int ifindex;
	int warning;
{
	static struct in6_nbrinfo nbi;
	int s;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		syslog(LOG_ERR, "%s socket() %s",  
		       __FUNCTION__, strerror(errno));

	bzero(&nbi, sizeof(nbi));
	if_indextoname(ifindex, nbi.ifname);
	nbi.addr = *addr;
	if (ioctl(s, SIOCGNBRINFO_IN6, (caddr_t)&nbi) < 0) {
		if (warning)
			perror("ioctl(SIOCGNBRINFO_IN6)");
		close(s);
		return (NULL);
	}

	close(s);
	return (&nbi);
}


#endif /* MIP_NEMO */


/* get an ifindex of the address */
u_int16_t 
get_ifindex_from_address(address)
	struct in6_addr *address;
{
	struct ifaddrs *ifa, *ifap;
	u_int16_t index = -1;
	struct sockaddr *sa;

	if (getifaddrs(&ifap) != 0) {
		syslog(LOG_ERR, "%s\n", strerror(errno));
		return (0);
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		sa = ifa->ifa_addr;
                
		if (sa->sa_family != AF_INET6)
			continue;
		if (ifa->ifa_addr == NULL)
			continue;
		if (address == NULL)
			continue;
		
		if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, address)) {
			index = if_nametoindex(ifa->ifa_name);
			freeifaddrs(ifap);
			return (index);
		}
	}
	freeifaddrs(ifap);
	return (0);
}

int
send_unsolicited_na()
{
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_in6 to;
	struct mip6_hoainfo *hinfo;
	char adata[512]; /* for ip6_pktopts and hlim */
	char nabuf[1024]; /* for neighbor advertisement message */
	struct cmsghdr *cmsgptr;
	struct in6_pktinfo *pi;
	struct nd_neighbor_advert *na;
	size_t nalen;
	struct nd_opt_hdr *ndopt;
	struct ifaddrs *ifahead, *ifa;

#if 0
        if (bul == NULL)
                return (-1);

        hinfo = bul->bul_hoainfo;
#endif

	bzero(&to, sizeof(to));
	to.sin6_len = sizeof(to);
	to.sin6_family = AF_INET6;
	to.sin6_addr = in6addr_linklocal_allnodes;
#if 0
	to.sin6_scope_id = bul->bul_home_ifindex;
#endif

	msg.msg_name = (void *)&to;
	msg.msg_namelen = sizeof(to);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo))
				+ CMSG_SPACE(sizeof(int));

	/*
	 * set the source address of an unsolicited neighbor
	 * advertisement message
	 */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	bzero(pi, sizeof(*pi));
#if 0
        pi->ipi6_ifindex = bul->bul_home_ifindex;
        pi->ipi6_addr = hinfo->hinfo_hoa;
#endif
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(*pi));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	/* HopLimit Information (always 255) */
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_HOPLIMIT;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)(CMSG_DATA(cmsgptr)) = 255;
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	bzero(nabuf, sizeof(nabuf));
	na = (struct nd_neighbor_advert *)nabuf;
	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	na->nd_na_cksum = 0;
	na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
#if 0
	na->nd_na_target = hinfo->hinfo_hoa;
#endif
	nalen = sizeof(struct nd_neighbor_advert);

	/* target link-layer option. */
	if (getifaddrs(&ifahead) != 0) {
		syslog(LOG_ERR,
		    "retrieving my link-layer address failed.\n");
		return (-1);
	}
#define ROUNDUP8(a) (1 + (((a) - 1) | 7))
	for (ifa = ifahead; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_dl *sdl;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)(ifa->ifa_addr);
#if 0
		if (sdl->sdl_index != bul->bul_home_ifindex)
#endif
			continue;
		ndopt = (struct nd_opt_hdr *) (nabuf + nalen);
		ndopt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		ndopt->nd_opt_len = (ROUNDUP8(sdl->sdl_alen + 2)) >> 3;
		memcpy((void *)(ndopt + 1), LLADDR(sdl), sdl->sdl_alen);
		nalen += ROUNDUP8(sdl->sdl_alen + 2);
		break;
	}
#undef ROUNDUP8
	freeifaddrs(ifahead);
        
        iov.iov_base = nabuf;
        iov.iov_len = nalen;
        
        if (sendmsg(icmp6sock, &msg, 0) == -1) {
                syslog(LOG_ERR,
                    "sending an unsolicited neighbor advertisement message "
                    "failed.\n");
                return (-1);
        }

	return 0;
}


#if 0
int
send_na(dest, mif)
	struct in6_addr *dest;
	struct mobileip6_ifinfo *mif;
{
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pi = NULL;
        struct sockaddr_in6 to;
	struct in6_addr from;
        char adata[512], buf[1024];
        struct nd_neighbor_advert *na;
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
	pi->ipi6_ifindex = mif->ifindex;

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
	na->nd_na_target = *dest;
	nalen = sizeof(struct nd_neighbor_solicit);

	opthdr = (struct nd_opt_hdr *) (buf + nalen);
	opthdr->nd_opt_type = ND_OPT_TARGET_LINKADDR; 

	switch(mif->sockdl.sdl_type) {
	case IFT_ETHER:
#ifdef IFT_IEEE80211
	case IFT_IEEE80211:
#endif
		opthdr->nd_opt_len = (ROUNDUP8(ETHER_ADDR_LEN + 2)) >> 3;
		addr = (char *)(opthdr + 1);
		memcpy(addr, LLADDR(&mif->sockdl), ETHER_ADDR_LEN);
		nalen += ROUNDUP8(ETHER_ADDR_LEN + 2);
		break;
	default:
		return (-1);
	}

	iov.iov_base = buf;
	iov.iov_len = nalen;

	if (mobileip6var.var_debug > DEBUG_NORMAL)
		syslog(LOG_INFO, "%s sending NA\n", __FUNCTION__);

	if (sendmsg(icmpsock, &msg, 0) < 0)
		syslog(LOG_ERR, "%s sendmsg() %s",  
		       __FUNCTION__, strerror(errno));

	return (errno);
}

#endif

