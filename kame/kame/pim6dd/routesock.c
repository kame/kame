/*	$KAME: routesock.c,v 1.9 2003/09/02 09:57:05 itojun Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#include <sys/param.h>
#include <sys/file.h>
#include "defs.h"
#include <sys/socket.h>
#include <net/route.h>
#ifdef HAVE_ROUTING_SOCKETS
#include <net/if_dl.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>

#ifdef HAVE_ROUTING_SOCKETS
union sockunion {
    struct  sockaddr sa;
    struct  sockaddr_in6 sin6;
    struct  sockaddr_dl sdl;
} so_dst, so_ifp;
typedef union sockunion *sup;
int routing_socket;
int rtm_addrs, pid;
struct rt_metrics rt_metrics;
u_long rtm_inits;

/*
 * Local functions definitions.
 */
static int getmsg __P((register struct rt_msghdr *, int,
		       struct rpfctl *rpfinfo));

/*
 * TODO: check again!
 */
#ifdef IRIX
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(__uint64_t) - 1))) \
		    : sizeof(__uint64_t))
#else
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) \
		    : sizeof(long))
#endif /* IRIX */

#ifdef HAVE_SA_LEN
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#else
#define ADVANCE(x, n) (x += ROUNDUP(4))   /* TODO: a hack!! */
#endif

/* Open and initialize the routing socket */
int
init_routesock()
{
    pid = getpid();
    routing_socket = socket(PF_ROUTE, SOCK_RAW, AF_INET6);
    if (routing_socket < 0) {
	log_msg(LOG_ERR, 0, "\nRouting socket error");
	return -1;
    }
    if (fcntl(routing_socket, F_SETFL, O_NONBLOCK) == -1){
	log_msg(LOG_ERR, 0, "\n Routing socket error");
	return -1;
    }
#if 0
    {
    int off;
    
    off = 0;
    if (setsockopt(routing_socket, SOL_SOCKET,
		   SO_USELOOPBACK, (char *)&off,
		   sizeof(off)) < 0){
	log_msg(LOG_ERR, 0 , "\n setsockopt(SO_USELOOPBACK,0)");
	return -1;
    }
    }
#endif	
    return 0;
}


struct {
    struct  rt_msghdr m_rtm;
    char    m_space[512];
} m_rtmsg;


/* get the rpf neighbor info */
int
k_req_incoming(source, rpfp)
    struct sockaddr_in6 *source;
    struct rpfctl *rpfp;
{
    int flags = RTF_STATIC; 
    register sup su;
    static int seq;
    int rlen;
    register char *cp = m_rtmsg.m_space;
    register int l;
    struct rpfctl rpfinfo;
	
/* TODO: a hack!!!! */
#ifdef HAVE_SA_LEN
#define NEXTADDR(w, u) \
    if (rtm_addrs & (w)) { \
	l = ROUNDUP(u.sa.sa_len); bcopy((char *)&(u), cp, l); cp += l;\
    }
#else
#define NEXTADDR(w, u) \
    if (rtm_addrs & (w)) { \
	l = ROUNDUP(4); bcopy((char *)&(u), cp, l); cp += l;\
    }
#endif /* HAVE_SA_LEN */

    /* initialize */
    memset(&rpfinfo, 0, sizeof(rpfinfo));
    memset(&rpfp->rpfneighbor, 0, sizeof(rpfp->rpfneighbor));
    rpfp->source = *source;
    
    /* check if local address or directly connected before calling the
     * routing socket
     */

    if ((rpfp->iif = find_vif_direct_local(source)) != NO_VIF) {
	rpfp->rpfneighbor = *source;
	return(TRUE);
    }       

    /* prepare the routing socket params */
    rtm_addrs |= RTA_DST;
    rtm_addrs |= RTA_IFP;
    su = &so_dst;
    su->sin6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
    su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    su->sin6.sin6_addr = source->sin6_addr;
    su->sin6.sin6_scope_id = source->sin6_scope_id;
    so_ifp.sa.sa_family = AF_LINK;
#ifdef HAVE_SA_LEN
    so_ifp.sa.sa_len = sizeof(struct sockaddr_dl);
#endif
    flags |= RTF_UP;
    flags |= RTF_HOST;
    flags |= RTF_GATEWAY;
    errno = 0;
    bzero((char *)&m_rtmsg, sizeof(m_rtmsg));

#define rtm m_rtmsg.m_rtm
    rtm.rtm_type	= RTM_GET;
    rtm.rtm_flags	= flags;
    rtm.rtm_version	= RTM_VERSION;
    rtm.rtm_seq 	= ++seq;
    rtm.rtm_addrs	= rtm_addrs;
    rtm.rtm_rmx 	= rt_metrics;
    rtm.rtm_inits	= rtm_inits;

    NEXTADDR(RTA_DST, so_dst);
    NEXTADDR(RTA_IFP, so_ifp);
    rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
    
    if ((rlen = write(routing_socket, (char *)&m_rtmsg, l)) < 0) {
	IF_DEBUG(DEBUG_RPF | DEBUG_KERN) {
	    if (errno == ESRCH)
		log_msg(LOG_DEBUG, 0,
		    "Writing to routing socket: no such route\n");
	    else
		log_msg(LOG_DEBUG, 0, "Error writing to routing socket");
	}
	return(FALSE); 
    }
    
    do {
	l = read(routing_socket, (char *)&m_rtmsg, sizeof(m_rtmsg));
    } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
    
    if (l < 0) {
	IF_DEBUG(DEBUG_RPF | DEBUG_KERN)
	    log_msg(LOG_DEBUG, 0, "Read from routing socket failed: %s", strerror(errno));
	return(FALSE);
    }
    
    if (getmsg(&rtm, l, &rpfinfo)){
	rpfp->rpfneighbor = rpfinfo.rpfneighbor;
	rpfp->iif = rpfinfo.iif;
    }
#undef rtm
    return (TRUE);
}

/*
 * Returns TRUE on success, FALSE otherwise. rpfinfo contains the result.
 */
int 
getmsg(rtm, msglen, rpfinfop)
    register struct rt_msghdr *rtm;
    int msglen;
    struct rpfctl *rpfinfop;
{
    struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
    struct sockaddr_dl *ifp = NULL;
    register struct sockaddr *sa;
    register char *cp;
    register int i;
    struct sockaddr_in6 *sin6;
    vifi_t vifi;
    struct uvif *v;
    
    if (rpfinfop == (struct rpfctl *)NULL)
	return(FALSE);
    
    sin6 = (struct sockaddr_in6 *)&so_dst;
    IF_DEBUG(DEBUG_RPF)
	log_msg(LOG_DEBUG, 0, "route to: %s", inet6_fmt(&sin6->sin6_addr));
    cp = ((char *)(rtm + 1));
    if (rtm->rtm_addrs)
	for (i = 1; i; i <<= 1)
	    if (i & rtm->rtm_addrs) {
		sa = (struct sockaddr *)cp;
		switch (i) {
		case RTA_DST:
		    dst = sa;
		    break;
		case RTA_GATEWAY:
		    gate = sa;
		    break;
		case RTA_NETMASK:
		    mask = sa;
		    break;
		case RTA_IFP:
		    if (sa->sa_family == AF_LINK &&
			((struct sockaddr_dl *)sa)->sdl_nlen)
			ifp = (struct sockaddr_dl *)sa;
		    break;
		}
		ADVANCE(cp, sa);
	    }
    
    if (!ifp){ 	/* No incoming interface */
	IF_DEBUG(DEBUG_RPF)
	    log_msg(LOG_DEBUG, 0,
		"No incoming interface for destination %s",
		inet6_fmt(&sin6->sin6_addr));
	return(FALSE);
    }
    if (dst && mask)
	mask->sa_family = dst->sa_family;
    if (dst) {
	sin6 = (struct sockaddr_in6 *)dst;
	IF_DEBUG(DEBUG_RPF)
	    log_msg(LOG_DEBUG, 0, " destination is: %s",
		inet6_fmt(&sin6->sin6_addr));
    }
    if (gate && rtm->rtm_flags & RTF_GATEWAY) {
	sin6 = (struct sockaddr_in6 *)gate;
	IF_DEBUG(DEBUG_RPF)
	    log_msg(LOG_DEBUG, 0, " gateway is: %s", inet6_fmt(&sin6->sin6_addr));
	rpfinfop->rpfneighbor = *sin6;

	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
#if 0
		rpfinfop->rpfneighbor.sin6_scope_id =
			ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
#endif
		rpfinfop->rpfneighbor.sin6_scope_id = ifp->sdl_index;
		/*
		 * XXX: KAME kernel embeds the interface index to the address.
		 * Clear the index for safety.
		 */
		rpfinfop->rpfneighbor.sin6_addr.s6_addr[2] = 0;
		rpfinfop->rpfneighbor.sin6_addr.s6_addr[3] = 0;
	}
    }
    
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) 
	/* get the number of the interface by matching the name */
	if ((strlen(v->uv_name) == ifp->sdl_nlen) &&
	    !(strncmp(v->uv_name,ifp->sdl_data,ifp->sdl_nlen)))
	    break;
    
    IF_DEBUG(DEBUG_RPF)
	log_msg(LOG_DEBUG, 0, " iif is %d", vifi);
    
    rpfinfop->iif = vifi;
    
    if (vifi >= numvifs){
	IF_DEBUG(DEBUG_RPF)
	    log_msg(LOG_DEBUG, 0,
		"Invalid incoming interface for destination %s, because of invalid virtual interface",
		inet6_fmt(&sin6->sin6_addr));
	return(FALSE);/* invalid iif */
    }
    
    return(TRUE);
}


#else	/* HAVE_ROUTING_SOCKETS */


/*
 * Return in rpfcinfo the incoming interface and the next hop router
 * toward source.
 */
/* TODO: check whether next hop router address is in network or host order */
int
k_req_incoming(source, rpfcinfo)
    struct sockaddr_in6 *source;
    struct rpfctl *rpfcinfo;
{
    rpfcinfo->source = *source;
    rpfcinfo->iif = NO_VIF;     /* just initialized, will be */
    /* changed in kernel */
    memset(&rpfcinfo->rpfneighbor, 0, sizeof(rpfcinfo->rpfneighbor));  /* initialized */
    
    if (ioctl(udp_socket, SIOCGETRPF, (char *) rpfcinfo) < 0){
	log_msg(LOG_ERR, errno, "ioctl SIOCGETRPF k_req_incoming");
	return(FALSE);
    }
    return (TRUE);
}

#endif	/* HAVE_ROUTING_SOCKETS */

