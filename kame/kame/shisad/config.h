/*	$KAME: config.h,v 1.10 2007/01/13 18:46:21 keiichi Exp $	*/

/*
 * Copyright (C) 2005 WIDE Project.
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

#ifndef _SHISAD_CONFIG_H_
#define _SHISAD_CONFIG_H_

enum {
	CFM_CND, CFM_HAD, CFM_MND, CFM_MRD
};

enum {
	CFT_DEBUG, CFT_NAMELOOKUP, CFT_COMMANDPORT, CFT_DAD, CFT_PAGER,
	CFT_HOMEREGISTRATIONLIFETIME, CFT_MOBILENODEMODE,
	CFT_INTERFACE,
	CFT_PREFERENCE,
	CFT_KEYMANAGEMENT,
	CFT_IPV4MNPSUPPORT,
	CFT_PREFIXTABLELIST, CFT_PREFIXTABLE,
	CFT_STATICTUNNELLIST, CFT_STATICTUNNEL,
	CFT_IPV4DUMMYTUNNELLIST, CFT_IPV4DUMMYTUNNEL,
	CFT_AUTHDATABASE, 
};

enum {
	CFV_MOBILEHOST, CFV_MOBILEROUTER,
	CFV_IMPLICIT, CFV_EXPLICIT, CFV_ROUTING, CFV_MOBILEIPV6
};

struct config_entry {
	struct config_entry *cfe_next;
	struct config_entry *cfe_tail;
	int cfe_type;
	int cfe_number;
	void *cfe_ptr;
	struct config_entry *cfe_list;
};

struct config_prefixtable {
	struct in6_addr cfpt_homeaddress;
	struct sockaddr_storage cfpt_ss_prefix;
	int cfpt_prefixlen;
	int cfpt_mode;
	int cfpt_binding_id;
};

struct config_static_tunnel {
	char *cfst_ifname;
	struct in6_addr cfst_homeaddress;
	int cfst_binding_id;
};

struct config_ipv4_dummy_tunnel {
	char *cfdt_ifname;
	struct in_addr cfdt_mr_address;
	struct in_addr cfdt_ha_address;
};

extern struct config_entry *config_params;

extern int parse(int, const char *, struct config_entry **);

int parse_config(int, const char *);
int config_get_number(int, int *, struct config_entry *);
int config_get_string(int, char **, struct config_entry *);
int config_get_list(int, struct config_entry **, struct config_entry *);
int config_get_interface(const char *, struct config_entry **,
    struct config_entry *);
int config_get_prefixtable(struct config_entry **, struct config_entry *);
int config_get_static_tunnel(struct config_entry **, struct config_entry *);
int config_get_ipv4_dummy_tunnel(struct config_entry **,
    struct config_entry *);

#endif /* _SHISAD_CONFIG_H_ */
