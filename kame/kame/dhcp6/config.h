/*	$KAME: config.h,v 1.3 2002/05/01 10:30:35 jinmei Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
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

/* per-interface information */
struct dhcp_if {
	struct dhcp_if *next;

	/* internal status */
	int state;
	u_int32_t xid;		/* current transaction ID */

	/* internal timer parameters */
	long retrans;
	long init_retrans;
	long max_retrans_cnt;
	long max_retrans_time;
	long max_retrans_dur;
	int timeouts;		/* number of timeouts */

	/* static parameters of the interface */
	char *ifname;
	unsigned int ifid;
	u_int32_t linkid;	/* to send link-local packets */

	/* configuration parameters */
	u_long send_flags;
	u_long allow_flags;

#define DHCIFF_INFO_ONLY 0x1
#define DHCIFF_RAPID_COMMIT 0x2

	struct dhcp_optconf *send_options;
};

/* client status code */
enum {DHCP6S_INIT, DHCP6S_SOLICIT, DHCP6S_INFOREQ, DHCP6S_IDLE};

struct dhcp_ifconf {
	struct dhcp_ifconf *next;

	char *ifname;

	/* configuration flags */
	u_long send_flags;
	u_long allow_flags;

	struct dhcp_optconf *send_options;
	struct dhcp_optconf *allow_options;
};

/* DHCP option information */
struct dhcp_optconf {
	struct dhcp_optconf *next;
	int type;
	int len;
	char *val;
};

/* structures and definitions used in the config file parser */
struct cf_ifconf {
	char *ifname;
	struct cf_declaration *decl;
	int line;
};

struct cf_iflist {
	struct cf_iflist *if_next;
	struct cf_ifconf *if_conf;
};

struct cf_declaration {
	struct cf_declaration *decl_next;
	int decl_type;
	void *decl_val;
};

struct cf_dhcpoption {
	struct cf_dhcpoption *dhcpopt_next; /* unused for now */
	int dhcpopt_type;
	void *dhcpopt_val;
};

enum {DECL_SEND, DECL_ALLOW, DECL_INFO_ONLY};
enum {DHCPOPT_RAPID_COMMIT};

extern struct dhcp_ifconf *dhcp_iflist;

extern void ifinit __P((char *));
extern int configure_interface __P((struct cf_iflist *));
extern void configure_cleanup __P((void));
extern void configure_commit __P((void));
extern int cfparse __P((char *));
extern struct dhcp_if *find_ifconf __P((char *));
