/* 
 * $Id: proto.h,v 1.1.1.1 1999/08/08 23:29:41 itojun Exp $
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

/*
 * Copyright(C)1997 by Hitachi, Ltd.
 */

/* main.c */
int scan_interface(void);
void quit_route6d(char *);

/* startup.c */
void initialize_signals(void);
void initialize_dctlout(void);
void initialize_pidfile(void);
void initialize_sockets(void);
void xaddress(const int, char *, char *, struct rt_addrinfo *);
int  initialize_interface(void);
void install_interface(void);
void install_routes(void);
int  join_multicast_group(struct interface *);
int  drop_multicast_group(struct interface *);
void if_freeaddresses(struct interface *);
int  get_prefixlen(struct sockaddr_in6 *);

/* timer.c */
void timer(void);
void trigger_update(void);
void timevaladd(struct timeval *, struct timeval *);
void timevalsub(struct timeval *, struct timeval *);
int  get_random_num(int);

/* input.c */
void process_rip6_msg(struct msghdr *, int);
void process_admin_msg(char *, int);
void process_kernel_msg(char *, int);
int  address_match(struct in6_addr *, struct in6_addr *, struct in6_addr *);
void trace_packet(char *, struct interface *, struct msghdr *, int, int);

/* output.c */
void send_request(void);
void send_regular_update(void);
void send_triggered_update(void);
void send_update(struct interface *, struct msghdr *, int, unsigned int);
void send_full_table(struct msghdr *, struct interface *);
void send_admin_stat(void);
void send_message(struct msghdr *, struct interface *, unsigned int);

/* tree.c */
void initialize_cache( void );
struct rt_plen *locate_local_route(struct route_entry *, struct tree_node **);
void add_local_route(struct route_entry *, struct route_entry *,
		     struct interface *, u_char, struct tree_node *);
void modify_local_route(struct rt_plen *, struct route_entry *,
			struct route_entry *, struct interface *);
void delete_local_route(struct rt_plen *);
void flush_local_cache(void);
void get_mask(u_char, char *);    
boolean prefcmp(struct in6_addr *, struct in6_addr *, u_char);

/* ker_rt.c */
int rt_ioctl(struct rt_plen *, u_char);

/* handler.c */
void sighup_handler(void);
void sigint_handler(void);
void sigusr1_handler(void);
void sigterm_handler(void);

/* send_admin.c */
void send_admin_table(struct prefix *);
void send_all_entries(struct tree_node *, char *, int *);
struct tree_node* get_start_ptr( void );

/* exit.c */
void exit_route6d(void);
void release_resources(void);

/* parse.c */
void parse_config(void);

#ifdef NDAEMON
void prt_entry(struct route_entry *, struct route_entry *, struct interface *);
void prt_packet(char *, int, struct sockaddr_in6 *);
void print_route(struct rt_plen *);
#endif /* NDAEMON */
