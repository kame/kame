/*	$KAME: kern.c,v 1.4 2003/09/02 09:57:04 itojun Exp $	*/

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

#include "defs.h"

#ifdef RAW_OUTPUT_IS_RAW
int curttl = 0;
#endif


/*
 * Open/init the multicast routing in the kernel and sets the MRT_ASSERT
 * flag in the kernel.
 * 
 */
void
k_init_pim(socket)
  int socket;
{
    int v = 1;
    
    if (setsockopt(socket, IPPROTO_IPV6,
		   MRT6_INIT, (char *)&v, sizeof(int)) < 0)
	log_msg(LOG_ERR, errno, "cannot enable multicast routing in kernel");
    
    if(setsockopt(socket, IPPROTO_IPV6,
		  MRT6_PIM, (char *)&v, sizeof(int)) < 0)
	log_msg(LOG_ERR, errno, "cannot set ASSERT flag in kernel");
}


/*
 * Stops the multicast routing in the kernel and resets the MRT_ASSERT
 * flag in the kernel.
 */
void
k_stop_pim(socket)
    int socket;
{
    int v = 0;

    if(setsockopt(socket, IPPROTO_IPV6, MRT6_PIM,
		  (char *)&v, sizeof(int)) < 0)
	log_msg(LOG_ERR, errno, "cannot reset ASSERT flag in kernel");

    if (setsockopt(socket, IPPROTO_IPV6, MRT6_DONE, (char *)NULL, 0) < 0)
	log_msg(LOG_ERR, errno, "cannot disable multicast routing in kernel");
    
}


/*
 * Set the socket receiving buffer. `bufsize` is the preferred size,
 * `minsize` is the smallest acceptable size.
 */
void k_set_rcvbuf(socket, bufsize, minsize)
    int socket;
    int bufsize;
    int minsize;
{
    int delta = bufsize / 2;
    int iter = 0;
    
    /*
     * Set the socket buffer.  If we can't set it as large as we
     * want, search around to try to find the highest acceptable
     * value.  The highest acceptable value being smaller than
     * minsize is a fatal error.
     */
    if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF,
		   (char *)&bufsize, sizeof(bufsize)) < 0) {
	bufsize -= delta;
	while (1) {
	    iter++;
	    if (delta > 1)
	      delta /= 2;
	    
	    if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF,
			   (char *)&bufsize, sizeof(bufsize)) < 0) {
		bufsize -= delta;
	    } else {
		if (delta < 1024)
		    break;
		bufsize += delta;
	    }
	}
	if (bufsize < minsize) {
	    log_msg(LOG_ERR, 0, "OS-allowed buffer size %u < app min %u",
		bufsize, minsize);
	    /*NOTREACHED*/
	}
    }
    IF_DEBUG(DEBUG_KERN)
	log_msg(LOG_DEBUG, 0, "Got %d byte buffer size in %d iterations",
	    bufsize, iter);
}

#if 0				/* there is no HDRINCL option in IPv6 */
/*
 * Set/reset the IP_HDRINCL option. My guess is we don't need it for raw
 * sockets, but having it here won't hurt. Well, unless you are running
 * an older version of FreeBSD (older than 2.2.2). If the multicast
 * raw packet is bigger than 208 bytes, then IP_HDRINCL triggers a bug
 * in the kernel and "panic". The kernel patch for netinet/ip_raw.c
 * coming with this distribution fixes it.
 */
void k_hdr_include(socket, bool)
    int socket;
    int bool;
{
#ifdef IP_HDRINCL
    if (setsockopt(socket, IPPROTO_IP, IP_HDRINCL,
		   (char *)&bool, sizeof(bool)) < 0)
	log_msg(LOG_ERR, errno, "setsockopt IP_HDRINCL %u", bool);
#endif
}
#endif /* 0 */

/*
 * Set the default Hop Limit for the multicast packets outgoing from this
 * socket.
 */
void k_set_hlim(socket, h)
    int socket;
    int h;
{
#ifdef RAW_OUTPUT_IS_RAW
    curttl = h;
#else
    int hlim = h;
    
    if (setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		   (char *)&hlim, sizeof(hlim)) < 0)
	log_msg(LOG_ERR, errno, "setsockopt IPV6_MULTICAST_HOPS %u", hlim);
#endif
}


/*
 * Set/reset the IPV6_MULTICAST_LOOP. Set/reset is specified by "flag".
 */
void k_set_loop(socket, flag)
    int socket;
    int flag;
{
    u_int loop;

    loop = flag;
    if (setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		   (char *)&loop, sizeof(loop)) < 0)
	log_msg(LOG_ERR, errno, "setsockopt IPV6_MULTICAST_LOOP %u", loop);
}


/*
 * Set the IPV6_MULTICAST_IF option on local interface which has the
 * specified index.
 */
void k_set_if(socket, ifindex)
    int socket;
    u_int ifindex;
{
    if (setsockopt(socket, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		   (char *)&ifindex, sizeof(ifindex)) < 0)
	log_msg(LOG_ERR, errno, "setsockopt IPV6_MULTICAST_IF for %s",
	    ifindex2str(ifindex));
}


/*
 * Join a multicast grp group on local interface ifa.
 */
void k_join(socket, grp, ifindex)
    int socket;
    struct in6_addr *grp;
    u_int ifindex;
{
    struct ipv6_mreq mreq;
    
    mreq.ipv6mr_multiaddr = *grp;
    mreq.ipv6mr_interface = ifindex;

    if (setsockopt(socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		   (char *)&mreq, sizeof(mreq)) < 0)
	log_msg(LOG_WARNING, errno, "cannot join group %s on interface %s",
	    inet6_fmt(grp), ifindex2str(ifindex));
}


/*
 * Leave a multicats grp group on local interface ifa.
 */
void k_leave(socket, grp, ifindex)
    int socket;
    struct in6_addr *grp;
    u_int ifindex;
{
    struct ipv6_mreq mreq;

    mreq.ipv6mr_multiaddr = *grp;
    mreq.ipv6mr_interface = ifindex;
    
    if (setsockopt(socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
		   (char *)&mreq, sizeof(mreq)) < 0)
	log_msg(LOG_WARNING, errno, "cannot leave group %s on interface %s",
	    inet6_fmt(grp), ifindex2str(ifindex));
}


/*
 * Add a virtual interface in the kernel.
 */
void k_add_vif(socket, vifi, v)
    int socket;
    vifi_t vifi;
    struct uvif *v;
{
    struct mif6ctl mc;

    mc.mif6c_mifi            = vifi;
    /* TODO: only for DVMRP tunnels?
    mc.mif6c_flags           = v->uv_flags & VIFF_KERNEL_FLAGS;
    */
    mc.mif6c_flags           = v->uv_flags;
#ifdef notyet
    mc.mif6c_rate_limit	    = v->uv_rate_limit;
#endif
    mc.mif6c_pifi           = v->uv_ifindex;

    if (setsockopt(socket, IPPROTO_IPV6, MRT6_ADD_MIF,
		   (char *)&mc, sizeof(mc)) < 0)
	log_msg(LOG_ERR, errno, "setsockopt MRT6_ADD_MIF on mif %d", vifi);
}

/*
 * Delete a virtual interface in the kernel.
 */
void k_del_vif(socket, vifi)
    int socket;
    vifi_t vifi;
{
    if (setsockopt(socket, IPPROTO_IPV6, MRT6_DEL_MIF,
		   (char *)&vifi, sizeof(vifi)) < 0)
	log_msg(LOG_ERR, errno, "setsockopt MRT6_DEL_MIF on mif %d", vifi);
}


/*
 * Delete all MFC entries for particular routing entry from the kernel.
 */
int
k_del_mfc(socket, source, group)
    int socket;
    struct sockaddr_in6 *source;
    struct sockaddr_in6 *group;
{
    struct mf6cctl mc;

    mc.mf6cc_origin = *source;
    mc.mf6cc_mcastgrp = *group;
	
    if (setsockopt(socket, IPPROTO_IPV6, MRT6_DEL_MFC, (char *)&mc,
		   sizeof(mc)) < 0) {
	log_msg(LOG_WARNING, errno, "setsockopt MRT6_DEL_MFC");
	return FALSE;
    }
	
    IF_DEBUG(DEBUG_MFC)
	log_msg(LOG_DEBUG, 0, "Deleted MFC entry: src %s, grp %s",
	    inet6_fmt(&source->sin6_addr),
	    inet6_fmt(&group->sin6_addr));

    return(TRUE);
}


/*
 * Install/modify a MFC entry in the kernel
 */
int
k_chg_mfc(socket, source, group, iif, oifs)
    int socket;
    struct sockaddr_in6 *source;
    struct sockaddr_in6 *group;
    vifi_t iif;
    if_set *oifs;
{
    struct mf6cctl mc;
    vifi_t vifi;

    mc.mf6cc_origin = *source;
    mc.mf6cc_mcastgrp = *group;
    mc.mf6cc_parent = iif;

    IF_ZERO(&mc.mf6cc_ifset);
    for (vifi = 0; vifi < numvifs; vifi++) {
	if (IF_ISSET(vifi, oifs))
	    IF_SET(vifi, &mc.mf6cc_ifset);
	else
	    IF_CLR(vifi, &mc.mf6cc_ifset);
    }
    
    if (setsockopt(socket, IPPROTO_IPV6, MRT6_ADD_MFC, (char *)&mc,
                   sizeof(mc)) < 0) {
        log_msg(LOG_WARNING, errno,
	    "setsockopt MRT6_ADD_MFC for source %s and group %s",
	    inet6_fmt(&source->sin6_addr), inet6_fmt(&group->sin6_addr));
        return(FALSE);
    }
    return(TRUE);
}


/*
 * Get packet counters for particular interface
 */
/*
 * XXX: TODO: currently not used, but keep just in case we need it later.
 */
int k_get_vif_count(vifi, retval)
    vifi_t vifi;
    struct vif_count *retval;
{
    struct sioc_mif_req6 mreq;
    
    mreq.mifi = vifi;
    if (ioctl(udp_socket, SIOCGETMIFCNT_IN6, (char *)&mreq) < 0) {
	log_msg(LOG_WARNING, errno, "SIOCGETMIFCNT_IN6 on vif %d", vifi);
	retval->icount = retval->ocount = retval->ibytes =
	    retval->obytes = 0xffffffff;
	return (1);
    }
    retval->icount = mreq.icount;
    retval->ocount = mreq.ocount;
    retval->ibytes = mreq.ibytes;
    retval->obytes = mreq.obytes;
    return (0);
}


/*
 * Gets the number of packets, bytes, and number of packets arrived
 * on wrong if in the kernel for particular (S,G) entry.
 */
int
k_get_sg_cnt(socket, source, group, retval)
    int socket;    /* udp_socket */
    struct sockaddr_in6 *source;
    struct sockaddr_in6 *group;
    struct sg_count *retval;
{
    struct sioc_sg_req6 sgreq;
    
    sgreq.src = *source;
    sgreq.grp = *group;
    if (ioctl(socket, SIOCGETSGCNT_IN6, (char *)&sgreq) < 0) {
	log_msg(LOG_WARNING, errno, "SIOCGETSGCNT_IN6 on (%s %s)",
	    inet6_fmt(&source->sin6_addr), inet6_fmt(&group->sin6_addr));
	retval->pktcnt = retval->bytecnt = retval->wrong_if = ~0; /* XXX */
	return(1);
    }
    retval->pktcnt = sgreq.pktcnt;
    retval->bytecnt = sgreq.bytecnt;
    retval->wrong_if = sgreq.wrong_if;
    return(0);
}



