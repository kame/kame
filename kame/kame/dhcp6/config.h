/*	$KAME: config.h,v 1.9 2002/05/09 01:54:28 jinmei Exp $	*/

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
struct dhcp6_if {
	struct dhcp6_if *next;

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

	struct dhcp6_optconf *send_options;
	struct dhcp6_optconf *request_options;
};

/* client status code */
enum {DHCP6S_INIT, DHCP6S_SOLICIT, DHCP6S_INFOREQ, DHCP6S_IDLE};

struct dhcp6_ifconf {
	struct dhcp6_ifconf *next;

	char *ifname;

	/* configuration flags */
	u_long send_flags;
	u_long allow_flags;

	struct dhcp6_optconf *request_options;
	struct dhcp6_optconf *send_options;
	struct dhcp6_optconf *allow_options;
};

struct prefix_ifconf {
	struct prefix_ifconf *next;

	char *ifname;		/* interface name such as ne0 */
	int sla_len;		/* SLA ID length in bits */
	u_int32_t sla_id;	/* need more than 32bits? */
	int ifid_len;		/* interface ID length in bits */
	int ifid_type;		/* EUI-64 and manual (unused?) */
	char ifid[16];		/* Interface ID, up to 128bits */
};
#define IFID_LEN_DEFAULT 64

/* per-host configuration */
struct host_conf {
	struct host_conf *next;

	char *name;		/* host name to identify the host */
	struct duid duid;	/* DUID for the host */
	/* delegated prefixes for the host: */
	struct delegated_prefix_list prefix;
};

/* DHCP option information */
struct dhcp6_optconf {
	struct dhcp6_optconf *next;
	int type;
	int len;
	char *val;
};

/* structures and definitions used in the config file parser */
struct cf_namelist {
	struct cf_namelist *next;
	char *name;
	struct cf_list *params;
};

struct cf_list {
	struct cf_list *next;
	int type;

	/* type dependent values: */
	long long num;
	struct cf_list *list;
	void *ptr;
};

enum {DECL_SEND, DECL_ALLOW, DECL_INFO_ONLY, DECL_REQUEST, DECL_DUID,
      DECL_PREFIX,
      IFPARAM_SLA_ID,
      DHCPOPT_RAPID_COMMIT, DHCPOPT_PREFIX_DELEGATION};

extern struct dhcp6_ifconf *dhcp6_iflist;

extern void ifinit __P((char *));
extern int configure_interface __P((struct cf_namelist *));
extern int configure_prefix_interface __P((struct cf_namelist *));
extern int configure_host __P((struct cf_namelist *));
extern void configure_cleanup __P((void));
extern void configure_commit __P((void));
extern int cfparse __P((char *));
extern struct dhcp6_if *find_ifconf __P((char *));
extern struct prefix_ifconf *find_prefixifconf __P((char *));
extern struct host_conf *find_hostconf __P((struct duid *));
