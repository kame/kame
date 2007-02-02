/*	$Id: babymdd.h,v 1.6 2007/02/02 05:34:27 t-momose Exp $	*/

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

#ifndef _SHISAD_BABYMDD_H_
#define _SHISAD_BABYMDD_H_

#define DEFAULT_CONFFILE "./mdd.conf"
#define DEFAULT_POLL 0
#define DEFAULT_DEBUG 0
#define DEFAULT_PRIORITY 0
#define DEFAULT_LINKWIFIHIGH 30
#define DEFAULT_LINKWIFILOW  15
#define DEFAULT_LINKCHECK 10 

#define DEBUG_NONE   0
#define DEBUG_NORMAL 1
#define DEBUG_HIGH   2

#define DEBUGHIGH (babyinfo.debug >= DEBUG_HIGH) 
#define DEBUGNORM (babyinfo.debug >= DEBUG_NORMAL)
#define DEBUGNONE (babyinfo.debug == DEBUG_NONE)

#define MDD_PIDFILE	"/var/run/babymdd.pid"

struct mdd_info {
	int debug;
	int linkpoll;
	int dns;
	int nondaemon;

	int rtsock;
	int mipsock;
	int linksock;

	int whereami;
#define IAMHOME    1
#define IAMFOREIGN 2

	struct if_info *coaif;
	LIST_HEAD(, if_info) ifinfo_head;

	u_int16_t hoa_index;
	LIST_HEAD(, hoa_info) hoainfo_head;

};

struct hoa_info {
	LIST_ENTRY(hoa_info) hoainfo_entry;

	struct sockaddr_storage hoa;/* HoA */
};


struct if_info {
	LIST_ENTRY(if_info) ifinfo_entry;
	char ifname[IFNAMSIZ];
	u_char iftype;
	u_int16_t ifindex;

	struct sockaddr_storage coa;/* Current CoA */
	struct sockaddr_storage pcoa;/* Previous CoA */

	time_t lastsent;

	int priority;
	int linkstatus;

	int bid;
};

#endif /* _SHISAD_BABYMDD_H_ */
