/*	$KAME: vrrp_functions.h,v 1.6 2003/05/13 07:06:29 ono Exp $	*/

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
/*
 * Copyright (c) 2001,2002 Sebastien Petit <spe@bsdfr.org>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <net/route.h>
#include <stdio.h>

/* vrrp_state.c functions */
int             vrrp_state_initialize(struct vrrp_vr *);
int             vrrp_state_initialize_all(void);
int             vrrp_state_set_master(struct vrrp_vr *);
int             vrrp_state_set_backup(struct vrrp_vr *);
int             vrrp_state_check_priority(struct vrrp_hdr *, struct vrrp_vr *, struct in6_addr *);
int             vrrp_state_master(struct vrrp_vr *);
int             vrrp_state_backup(struct vrrp_vr *);
void            vrrp_state_start(void);

/* vrrp_interface.c functions */
void            vrrp_interface_owner_verify(struct vrrp_vr *);
int             vrrp_interface_ethaddr_set(char *, struct ether_addr *);
int             vrrp_interface_ipaddr_set(char *, struct in6_addr *, struct in6_addr *netmask);
int             vrrp_interface_ipaddr_delete(char *, struct in6_addr *, int);
int             vrrp_interface_vripaddr_set(struct vrrp_vr *);
int             vrrp_interface_vripaddr_delete(struct vrrp_vr *);
int             vrrp_interface_down(char *);
int             vrrp_interface_up(char *);

/* vrrp_network.c functions */
int             vrrp_network_set_socket(struct vrrp_vr *);
int             vrrp_network_open_bpf(struct vrrp_vr *);
void            vrrp_network_close_bpf(struct vrrp_vr *);
void            vrrp_network_initialize(void);
int             vrrp_network_open_socket(struct vrrp_vr *);
size_t          vrrp_network_send_packet(char *, int, int);
u_int           vrrp_network_vrrphdr_len(struct vrrp_vr *);
void            vrrp_network_init_ethhdr(char *, struct vrrp_vr *);
void            vrrp_network_init_iphdr(char *, struct vrrp_vr *);
void            vrrp_network_init_vrrphdr(char *, struct vrrp_vr *);
int             vrrp_network_send_advertisement(struct vrrp_vr *);
int             vrrp_network_send_neighbor_advertisement(struct vrrp_vr *);
int             vrrp_network_delete_local_route(struct in6_addr *);
int             vrrp_network_flush_bpf(int);

/* vrrp_misc.c functions */
void            rt_xaddrs(caddr_t, caddr_t, struct rt_addrinfo *);
int             vrrp_misc_get_if_infos(char *, struct ether_addr *, struct in6_addr *, int *);
int             vrrp_misc_get_priority(struct vrrp_vr *);
u_int16_t       vrrp_misc_compute_checksum(struct ip6_pseudohdr *, u_char *);
int             vrrp_misc_calcul_tminterval(struct timeval *, u_int);
int             vrrp_misc_calcul_tmrelease(struct timeval *, struct timeval *);
int             vrrp_misc_check_vrrp_packet(struct vrrp_vr *, char *, struct ip6_pseudohdr *, int);
void            vrrp_misc_quit(int);
struct vrrp_if *vrrp_misc_search_if_entry(char *);
int		vrrp_misc_search_sdbpf_entry(char *);
void            vrrp_misc_log(int, const char *, ...);
#define         syslog vrrp_misc_log

/* vrrp_conf.c functions */
int             vrrp_conf_ident_option_arg(char *, char *, char *);
char          **vrrp_conf_split_args(char *, char);
void            vrrp_conf_freeargs(char **);
char            vrrp_conf_lecture_fichier(struct vrrp_vr *, FILE *);
FILE           *vrrp_conf_open_file(char *);

/* vrrp_multicast.c functions */
int            vrrp_multicast_join_group(int, u_char *, u_int);
int            vrrp_multicast_set_hops(int, int);
int            vrrp_multicast_set_if(int, u_int, char *);
int            vrrp_multicast_set_socket(struct vrrp_vr *);
int            vrrp_multicast_open_socket(struct vrrp_vr *);

/* vrrp_signal.c functions */
void            vrrp_signal_initialize(void);
void            vrrp_signal_quit(int);
void            vrrp_signal_shutdown(int);

/* vrrp_timer.c functions */
void vrrp_timer_init(void);
struct vrrp_timer *vrrp_add_timer(struct vrrp_timer *(*) (void *),
		void (*) (void *, struct timeval *), void *, void *);
void vrrp_set_timer(u_int, struct vrrp_timer *);
void vrrp_remove_timer(struct vrrp_timer **);
struct timeval * vrrp_check_timer(void);
struct timeval * vrrp_timer_rest(struct vrrp_timer *);

/* vrrp_main.c */
extern int optflag_f;
extern int optflag_d;

