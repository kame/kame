/* 
 * $Id: globals.h,v 1.1.1.1 1999/08/08 23:29:40 itojun Exp $
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
/* Hitachi Id: globals.h,v 1.2 1998/01/12 12:39:00 sumikawa Exp $ */

#ifndef _RIP6_GLOBALS_
#define _RIP6_GLOBALS_

/*
 * Initialise all global values.
 */
char	*progname, *prog;
FILE	*trace_file_ptr;

int	rip6_sock = -1;	/* Socket to be used for RIPng messages */
int	rt6_sock = -1;	/* Socket to be used for routing messages */
int	admin_sock = -1;/* Socket to be used for admin messages */
int	sendupdate; 	/* true if we need update at nextbcast */
u_long	grc_counter;	/* Global route changes counter */
u_long	gq_counter; 	/* Global queries counter */
int	seqno;		/* For identifying routing comands sent to kernel */
int	foundloopback;
int	scanning = 0;
int	garbage = 0;
int	regular = 0;
int	sigusr2 = 0;

int	alarminterval;
struct timeval now_time;/* current idea of time */
struct timeval nr_time;	/* time of next regular update */
struct timeval nt_time;	/* time of next triggered update */

int	rt6_opmode	= MODE_SUPPLY;
short	rt6_scheme	= RT6_POISON;
int	rt6_trace	= TRACE_OFF;
short	rt6_metric	= DEFAULT_METRIC;
int	rt6_hdrlen	= DEFAULT_HDRLEN;
int	rt6_mtu		= DEFAULT_MTU;
int	rt6_nhopout	= FALSE;	/* Do not put nexthop RTE */
int	rt6_nhopnoin	= FALSE;	/* Do not ignore the nexthop RTE */
u_short rt6_tag		= DEFAULT_RTTAG;
int	rt6_accept_compat = FALSE;
int	rt6_igndefault	= FALSE;
pid_t	rt6_pid;

struct static_rt   *statrt = NULL;
struct ign_prefix  *ignprf = NULL;/* Default is NULL,no prefix to be ignored */
struct interface   *ifnet  = NULL;
struct gateway     *gway   = NULL;

struct control dctlout;

struct int_config difconf = {
	NULL,
	"",
	RT6_POISON,
	CTL_LISTEN,
	NULL,
	CTL_SEND,
	&dctlout,
	NULL,
	FALSE,
	NULL,
	NULL,
	NULL,
	DEFAULT_METRIC,
	DEFAULT_METRIC_OUT,
	NULL,
	FALSE
};

struct int_config  *ifconf = NULL;
struct tree_head   *rnhead = NULL;
struct route_entry  default_rte = {
	IN6ADDR_ANY_INIT,
	0,    /* don't care */
	128,
	0     /* don't care */
};
struct sockaddr_un  admin_dest;
struct msghdr       rmsgh;
struct msghdr       smsgh;
struct iovec        riov;
struct iovec        siov;
struct rt_addrinfo  rtinfo;

char	*snd_data  = NULL;
char	*rcv_data  = NULL;
int	max_datasize;

int halted = 0; /* WAIT_FOR_SIGHUP */
int kernel_routes = 0;

int Cflag = 0;
int Nflag = 0;
int dflag = 0;

#endif /* _RIP6_GLOBALS_ */
