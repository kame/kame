/*
 * Copyright (C) 1998 WIDE Project.
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

void             bgp_connect_start      __P((struct rpcb *));
void             connect_try            __P((struct rpcb *));
void             connect_process        __P((struct rpcb *));
void             bgp_notify         __P((struct rpcb *, byte, byte, int, byte *));
void             bgp_cease          __P((struct rpcb *));
void             bgp_flush          __P((struct rpcb *));

void             main_listen_accept   __P((void));
void             bgp_input            __P((struct rpcb *));

void             bgp_process_open         __P((struct rpcb *));
void             bgp_process_update       __P((struct rpcb *));
void             bgp_process_notification __P((struct rpcb *));
void             bgp_process_keepalive    __P((struct rpcb *));

char		*bgp_errdatastr __P((char *, int));

struct rpcb     *collision_resolv __P((struct rpcb *, struct rpcb *));

struct rpcb     *bgp_new_peer     __P((void));
void             ibgpconfig       __P((void));
int              s_pipe           __P((int[]));
int              bgpd_sendfile         __P((int, int));
int              recvfile         __P((int));

int		 bgp_preferred_rte __P((struct rt_entry *, struct rt_entry *));

/*
 *   output
 */
int              bgp_send_open          __P((struct rpcb *));
int              bgp_send_notification  __P((struct rpcb *, byte,byte, int, byte *));
int              bgp_send_keepalive     __P((struct rpcb *));
struct rt_entry *bgp_send_update      __P((struct rpcb *, struct rt_entry *,
					   struct rt_entry *));
struct rt_entry *bgp_send_withdrawn   __P((struct rpcb *, struct rt_entry *,
					   struct rt_entry *));
void             bgp_dump             __P((struct rpcb *));
void             redistribute         __P((struct rt_entry *));
void             propagate            __P((struct rt_entry *));


int              bgp_enable_rte       __P((struct rt_entry *));
void             bgp_disable_rte      __P((struct rt_entry *));
void             bgp_recover_rte      __P((struct rt_entry *));


/*
 *    aspath
 */
struct aspath   *prepend_aspath    __P((u_int16_t, struct aspath *, int));
int              aspath2msg        __P((struct aspath *, int i));
struct aspath   *msg2aspath        __P((struct rpcb *, int i, int len,
					int *errorp));
int              equal_asseg       __P((struct asseg  *, struct asseg  *)); 
int              equal_aspath      __P((struct aspath *, struct aspath *)); 
void             free_aspath       __P((struct aspath *));
void             free_asseg        __P((struct asseg *));
void             free_asnum        __P((struct asnum *));

struct aspath   *aspathcpy         __P((struct aspath *));
struct asseg    *assegcpy          __P((struct asseg *, int));
struct asnum    *asnumcpy          __P((struct asnum *, int));

struct asseg    *bgp_new_asseg     __P((u_int16_t));
struct asnum    *bgp_new_asnum     __P((u_int16_t));


void             ins_asnum         __P((struct asnum *, struct asseg *));
u_char           aspath2cost       __P((struct aspath *));
u_int16_t        aspath2tag        __P((struct aspath *));

/*
 *    cluster list
 */
struct clstrlist *prepend_clstrlist __P((u_int32_t, struct clstrlist *));
int               clstrlist2msg     __P((struct clstrlist *, int i));
struct clstrlist *clstrlistcpy      __P((struct clstrlist *));
struct clstrlist *msg2clstrlist     __P((struct rpcb *, int i, int len));
struct clstrlist *bgp_new_clstrlist __P((u_int32_t));
void              free_clstrlist    __P((struct clstrlist *));

/*
 *    search
 */
struct rpcb     *find_peer_by_as    __P((u_int16_t));
struct rpcb     *find_epeer_by_as   __P((u_int16_t));
struct rpcb     *find_ppeer_by_as   __P((u_int16_t));
struct rpcb     *find_epeer_by_id   __P((u_int32_t));
struct rpcb     *find_ppeer_by_id   __P((u_int32_t));
struct rpcb     *find_apeer_by_addr __P((struct in6_addr *));
struct rpcb	*find_active_peer   __P((struct rpcb *));
struct rpcb	*find_idle_peer     __P((struct rpcb *));
struct rpcb	*find_epeer_by_addr __P((struct in6_addr *));
struct rpcb	*find_epeer_by_rpcb __P((struct rpcb *));

int		 bgp_rpcb_isvalid __P((struct rpcb *));

void             bgp_holdtimer_expired __P((task *));
void             bgpdexit  __P((void));


/*
 *   route
 */
void             krt_init     __P((void));
void             krt_entry    __P((struct rt_msghdr *));
int              addroute     __P((struct rt_entry *, const struct in6_addr *,
				   struct ifinfo *));
int              delroute     __P((struct rt_entry *, struct in6_addr *));
int              chroute      __P((struct rt_entry *, const struct in6_addr *,
				   struct ifinfo *));
struct rt_entry *rte_remove   __P((struct rt_entry *, struct rt_entry *));


#define BGP_DEF_LOCALPREF       100   /* like cisco, gated, at least */
#define BGP_DEF_ASPREPEND	1 /* number of iteration of prepended AS(if enabled) */
