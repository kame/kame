/*	$KAME: halist.h,v 1.7 2003/06/03 06:44:36 keiichi Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.
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
 * $Id: halist.h,v 1.7 2003/06/03 06:44:36 keiichi Exp $
 */

/*
 * Copyright (C) 2000 NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of NEC Corporation or any of its affiliates shall not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NEC CORPORATION ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL NEC CORPORATION BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <net/if.h>

/*
 * home agent liast structures
 */
/*
 * haifinfo_tab{}	home agent list for each interfaces
 * hagent_ifa_pair{}	global/ayncast addresses for interface
 *
 * hagent_entry{}	home agent (for ra)
 * hagent_gaddr{}	global addresses for a home agent
 *			 (home subnet prefix)
 *
 * halist_expire_head	home agent list
 *			 (sorted by remaining home agent lifetime)
 * gaddr_expire_head	global addresses list
 *			 (sorted by remaining valid lifetime)
 *
 *
 * haifinfo_tab{}
 * +---------------+
 * | +---------------+
 * | | +--------------+
 * | | | halist_pref  |
 * | | |  +------------------+   hagent_entry{}
 * | | |  | hagent_next_pref-|-->+------------------+   hagent_entry{}
 * | | |  | ...              |   | hagent_next_pref-|-->+------------------+
 * | | |  +------------------+<--|-hagent_prev_pref |   | hagent_next_pref-|--->NULL
 * | | | ifindex      |          | ...              |<--|-hagent_prev_pref |
 * +-| | *linklocal   |          +------------------+   | ...              |
 *   +-| haif_gavec   |               |                 +------------------+
 *     +---|----------+               |
 *         V hagent_ifa_pair{}        V hagent_gaddr{}
 *         +--------+                 +-------------------+
 *         |*global |-+               | hagent_next_gaddr-|-->NULL
 *         |*anycast| |               | ...               |
 *         +--------+ |               +-------------------+
 *          +---------+
 *
 * halist_expire_head
 *  +--------------------+    hagent_entry{}
 *  | hagent_next_expire-|-->+--------------------+
 *  | ...                |   | hagent_next_expire-|--> NULL
 *  +--------------------+<--|-hagent_prev_expire |
 *                           | ...                |
 *                           +--------------------+
 *
 * gaddr_expire_head
 *  +--------------------+    hagent_gaddr{}
 *  | hagent_next_expire |-->+-------------------+
 *  | ...                |   | hagent_next_gaddr-|-->NULL
 *  +--------------------+<--|-hagent_prev_gaddr |
 *                           | ...               |
 *                           +-------------------+
 */

/* global addresses for a home agent */
struct hagent_gaddr {
	struct hagent_gaddr	*hagent_next_gaddr, *hagent_prev_gaddr;
	struct hagent_gaddr	*hagent_next_expire, *hagent_prev_expire;
	struct in6_addr		hagent_gaddr;
	u_int8_t		hagent_prefixlen;
	struct hagent_flags {
		u_char		onlink : 1;
		u_char		autonomous : 1;
		u_char		router : 1;
	} hagent_flags;
	u_int32_t		hagent_vltime;
	u_int32_t		hagent_pltime;
	long			hagent_expire;
	long			hagent_preferred;
};

/* home agent entry */
struct hagent_entry {
	struct hagent_entry	*hagent_next_expire, *hagent_prev_expire,
				*hagent_next_pref, *hagent_prev_pref;
	struct in6_addr		hagent_addr;
	u_int16_t		hagent_pref;
	u_int16_t		hagent_lifetime;
	long			hagent_expire;
	struct hagent_gaddr	hagent_galist;
};

/*
 * interface information for home link(s)
 */
struct hagent_ifinfo {
	struct hagent_entry	halist_pref;
	int			ifindex;
	char			ifname[IF_NAMESIZE];
	struct ifaddrs		*linklocal;
	struct hagent_ifa_pair	*haif_gavec;
	int			gavec_used;
	int			gavec_size;
};

#define GAVEC_INIT_SIZE		(16)


struct hagent_ifa_pair {
	struct ifaddrs		*global;
	struct ifaddrs		*anycast;
};

struct hagent_entry *hal_update __P((int, struct in6_addr *, u_int16_t,
				     u_int16_t));
struct hagent_gaddr *hal_gaddr_add __P((struct hagent_entry *,
					struct hagent_gaddr *,
					struct nd_opt_prefix_info *));
void hal_gaddr_last __P((struct hagent_entry *, struct hagent_gaddr *));
void hal_check_expire __P((void));
void hal_clean __P((void));
int hal_delete __P((struct hagent_ifinfo *, struct in6_addr *));
int hal_pick __P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
		  struct hagent_ifinfo *, int));
void haif_prefix_add __P((struct hagent_ifinfo *, struct in6_addr *, u_int8_t));
struct hagent_ifinfo *haif_find __P((int));
struct hagent_ifinfo *haif_findwithanycast __P((struct in6_addr *, int *));
struct hagent_ifinfo *haif_findwithunicast __P((struct in6_addr *, int *));
struct hagent_ifinfo *haif_findwithhomeaddr __P((struct in6_addr *, int *));
struct hagent_entry *hal_find __P((struct hagent_ifinfo *, struct in6_addr *));
void haif_prefix_update __P((struct hagent_ifinfo *, struct in6_addr *,
			     u_int8_t, u_int32_t));
int haif_getifaddrs __P((void));
void haadisc_dump_file __P((char *dumpfile));
void haadisc_hup __P(());

int get_gaddr __P((struct hagent_gaddr *, struct in6_addr *,
                          struct hagent_gaddr *));
void create_mask __P((struct in6_addr *, u_int8_t));

#define IN6_ARE_ADDR_MASKEQUAL(x,y,z) (\
	(((x).__u6_addr.__u6_addr32[0] & (y).__u6_addr.__u6_addr32[0]) == ((z).__u6_addr.__u6_addr32[0] & (y).__u6_addr.__u6_addr32[0])) && \
	(((x).__u6_addr.__u6_addr32[1] & (y).__u6_addr.__u6_addr32[1]) == ((z).__u6_addr.__u6_addr32[1] & (y).__u6_addr.__u6_addr32[1])) && \
	(((x).__u6_addr.__u6_addr32[2] & (y).__u6_addr.__u6_addr32[2]) == ((z).__u6_addr.__u6_addr32[2] & (y).__u6_addr.__u6_addr32[2])) && \
	(((x).__u6_addr.__u6_addr32[3] & (y).__u6_addr.__u6_addr32[3]) == ((z).__u6_addr.__u6_addr32[3] & (y).__u6_addr.__u6_addr32[3])))

