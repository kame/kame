/* 
 * $Id: defs.h,v 1.1.1.1 1999/08/08 23:29:40 itojun Exp $
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

/* Copyright (c) 1997, 1998. Hitachi,Ltd. All rights reserved. */
/* Hitachi Id: defs.h,v 1.2 1998/01/12 12:38:59 sumikawa Exp $ */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include <sys/un.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netdb.h>
#include <sys/sysctl.h>
#include <signal.h>

#define FALSE 0
#define TRUE  1

#ifdef __FreeBSD__
#define RTF_CLONED	RTF_WASCLONED	/* xxx */
#endif

#define IN6_IS_ADDR_GLOBAL(adr) \
	((!IN6_IS_ADDR_MULTICAST(adr)) && \
	 (!IN6_IS_ADDR_LINKLOCAL(adr)) && \
	 (!IN6_IS_ADDR_SITELOCAL(adr)))

typedef u_char boolean;

#include "route6d.h"
#include "config.h"
#include "tables.h"
#include "admin.h"
#include "interface.h"
#include "macros.h"
#include "proto.h"

#define ALL_RIP6_ROUTER "FF02::9"

extern char	*prog, *progname;
extern FILE	*trace_file_ptr;
extern char	*shm_ptr;	/* Shared memory pointer */
extern int	shm_id;		/* Shared memory id */
extern int	rip6_sock;	/* Socket to be used for RIPng messages */
extern int	rt6_sock;	/* Socket to be used for routing messages */
extern int	admin_sock;	/* Socket to be used for admin messages */
extern int	sendupdate;	/* true if we need update at nextbcast */
extern u_long	grc_counter;	/* Global route changes counter */
extern u_long	gq_counter;	/* Global queries counter */
extern int	seqno;		/* For identifying routing commands */
extern int	foundloopback;
extern int	scanning;
extern int	garbage;
extern int	regular;
extern int	sigusr2;

extern int	alarminterval;
extern struct timeval now_time;	/* current idea of time */
extern struct timeval nr_time;	/* time of next regular update */
extern struct timeval nt_time;	/* time of next triggered update */

extern int	rt6_opmode;
extern short	rt6_scheme;
extern int	rt6_trace;
extern short	rt6_metric;
extern int	rt6_hdrlen;
extern int	rt6_mtu; 
extern int	rt6_nhopout;
extern int	rt6_nhopnoin;
extern u_short	rt6_tag;
extern int	rt6_accept_compat;
extern int	rt6_igndefault;
extern pid_t	rt6_pid;

extern struct static_rt		*statrt;
extern struct ign_prefix	*ignprf;
extern struct interface		*ifnet;
extern struct gateway		*gway;
extern struct control		dctlout;
extern struct int_config	difconf;
extern struct int_config	*ifconf;
extern struct tree_head		*rnhead;
extern struct in6_addr		default_addr;
extern struct route_entry	default_rte;
extern struct sockaddr_un	admin_dest;
extern struct msghdr		rmsgh;
extern struct msghdr		smsgh;
extern struct iovec		riov;
extern struct iovec		siov;

extern struct rt_addrinfo rtinfo;
#define netmask	rtinfo.rti_info[RTAX_NETMASK]
#define ifaaddr	rtinfo.rti_info[RTAX_IFA]
#define brdaddr	rtinfo.rti_info[RTAX_BRD]
#define gate	rtinfo.rti_info[RTAX_GATEWAY]
#define dest	rtinfo.rti_info[RTAX_DST]
#define ifpaddr	rtinfo.rti_info[RTAX_IFP]

extern char	*snd_data;
extern char	*rcv_data;
extern int	max_datasize;
extern int	errno;

extern int halted;
#define MAX_KERNEL_ROUTES6 3000
extern int kernel_routes;
