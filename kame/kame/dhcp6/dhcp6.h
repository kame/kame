/*	$KAME: dhcp6.h,v 1.25 2002/05/16 05:55:48 jinmei Exp $	*/
/*
 * Copyright (C) 1998 and 1999 WIDE Project.
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
 * draft-ietf-dhc-dhcpv6-24
 */

#ifndef __DHCP6_H_DEFINED
#define __DHCP6_H_DEFINED

/* Error Values */
#define DH6ERR_FAILURE		16
#define DH6ERR_AUTHFAIL		17
#define DH6ERR_POORLYFORMED	18
#define DH6ERR_UNAVAIL		19
#define DH6ERR_OPTUNAVAIL	20

/* Message type */
#define DH6_SOLICIT	1
#define DH6_ADVERTISE	2
#define DH6_REQUEST	3
#define DH6_REPLY	7
#define DH6_INFORM_REQ	11

/* Predefined addresses */
#define DH6ADDR_ALLAGENT	"ff02::1:2"
#define DH6ADDR_ALLSERVER	"ff05::1:3"
#define DH6PORT_DOWNSTREAM	"546"
#define DH6PORT_UPSTREAM	"547"

/* Protocol constants */

/* timer parameters (msec, unless explicitly commented) */
#define MIN_SOL_DELAY	1000
#define MAX_SOL_DELAY	5000
#define SOL_TIMEOUT	500
#define SOL_MAX_RT	30000
#define INF_TIMEOUT	500
#define INF_MAX_RT	30000
#define REQ_TIMEOUT	250
#define REQ_MAX_RT	30000
#define REQ_MAX_RC	10	/* Max Request retry attempts */

#define DHCP6_DURATITION_INFINITE 0xffffffff

/* Internal data structure */

/* DUID: DHCP unique Identifier */
struct duid {
	int duid_len;		/* length */
	char *duid_id;		/* variable length ID value (must be opaque) */
};

/* option information */
struct dnslist {
	TAILQ_ENTRY(dnslist) link;
	struct in6_addr addr;
};
TAILQ_HEAD(dnsq, dnslist);

struct delegated_prefix_info {		/* delegated prefix information */
	struct in6_addr addr;
	int plen;
	u_int32_t duration;
};

struct delegated_prefix {
	TAILQ_ENTRY(delegated_prefix) link;
	struct delegated_prefix_info prefix;
};
TAILQ_HEAD(delegated_prefix_list, delegated_prefix);

struct dhcp6_optinfo {
	struct duid clientID;	/* DUID */
	struct duid serverID;	/* DUID */
	struct dhcp6_optconf *requests;	/* options in option request */
	int rapidcommit;	/* bool */
	struct dnsq dnslist;	/* DNS server list */
	struct delegated_prefix_list prefix; /* prefix list */
	int pref;		/* server preference */
};

/* DHCP6 base packet format */
struct dhcp6 {
	union {
		u_int8_t m;
		u_int32_t x;
	} dh6_msgtypexid;
	/* options follow */
} __attribute__ ((__packed__));
#define dh6_msgtype	dh6_msgtypexid.m
#define dh6_xid		dh6_msgtypexid.x
#define DH6_XIDMASK	0x00ffffff

/* options */
#define DH6OPT_CLIENTID	1
#define DH6OPT_SERVERID	2
#define DH6OPT_IA 3
#define DH6OPT_IA_TMP 4
#define DH6OPT_IADDR 5
#define DH6OPT_ORO 6
#define DH6OPT_PREFERENCE 7
#define DH6OPT_ELAPSED_TIME 8
#define DH6OPT_CLIENT_MSG 9
#define DH6OPT_SERVER_MSG 10
#define DH6OPT_AUTH 11
#define DH6OPT_UNICAST 12
#define DH6OPT_STATUS_CODE 13
#define DH6OPT_RAPID_COMMIT 14
#define DH6OPT_USER_CLASS 15
#define DH6OPT_VENDOR_CLASS 16
#define DH6OPT_VENDOR_OPTS 17
#define DH6OPT_INTERFACE_ID 18
#define DH6OPT_RECONF_MSG 19

#define DH6OPT_PREF_UNDEF -1
#define DH6OPT_PREF_MAX 255

/*
 * The option type has not been assigned for the following options.
 * We use type values from 256 temporarily. 
 */
#define DH6OPT_DNS 256
#define DH6OPT_PREFIX_DELEGATION 257
#define DH6OPT_PREFIX_INFORMATION 258
#define DH6OPT_PREFIX_REQUEST 259

struct dhcp6opt {
	u_int16_t dh6opt_type;
	u_int16_t dh6opt_len;
	/* type-dependent data follows */
} __attribute__ ((__packed__));

/* DUID type 1 */
struct dhcp6_duid_type1 {
	u_int16_t dh6duid1_type;
	u_int16_t dh6duid1_hwtype;
	u_int32_t dh6duid1_time;
	/* link-layer address follows */
} __attribute__ ((__packed__));

/* Prefix Information */
struct dhcp6_prefix_info {
	u_int16_t dh6_pi_type;
	u_int16_t dh6_pi_len;
	u_int32_t dh6_pi_duration;
	u_int8_t dh6_pi_plen;
	struct in6_addr dh6_pi_paddr;
} __attribute__ ((__packed__));

#endif /*__DHCP6_H_DEFINED*/
