/*	$KAME: pim6_proto.h,v 1.7 2001/08/09 08:46:58 suz Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
/*  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.        
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.        
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */


#ifndef PIM6_PROTO_H
#define PIM6_PROTO_H

extern build_jp_message_t *build_jp_message_pool;
extern int               build_jp_message_pool_counter;
extern struct sockaddr_in6 sockaddr6_any;
extern struct sockaddr_in6 sockaddr6_d;

extern int receive_pim6_hello         __P((struct sockaddr_in6 *src,
                       char *pim_message, int datalen));

extern int send_pim6_hello            __P((struct uvif *v, u_int16 holdtime));
extern void delete_pim6_nbr           __P((pim_nbr_entry_t *nbr_delete));

extern int  receive_pim6_register    __P((struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                         char *pim_message, int datalen));
extern int  send_pim6_null_register  __P((mrtentry_t *r));
extern int  receive_pim6_register_stop __P((struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                           char *pim_message,
                           int datalen));
extern int  send_pim6_register   __P((char *pkt));
extern int  receive_pim6_join_prune  __P((struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                         char *pim_message, int datalen));
extern int  join_or_prune       __P((mrtentry_t *mrtentry_ptr,  
                         pim_nbr_entry_t *upstream_router));
extern int  receive_pim6_assert  __P((struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                         char *pim_message, int datalen));
extern int  send_pim6_assert     __P((struct sockaddr_in6 *source, struct sockaddr_in6 *group,
                         mifi_t vifi,
                         mrtentry_t *mrtentry_ptr));
extern int  send_periodic_pim6_join_prune __P((mifi_t vifi, 
                          pim_nbr_entry_t *pim_nbr,
                          u_int16 holdtime));
extern int  add_jp_entry        __P((pim_nbr_entry_t *pim_nbr,
                         u_int16 holdtime, struct sockaddr_in6 *group,
                         u_int8 grp_msklen, struct sockaddr_in6 *source,  
                         u_int8 src_msklen,
                         u_int16 addr_flags,  
                         u_int8 join_prune));
extern void pack_and_send_jp6_message __P((pim_nbr_entry_t *pim_nbr));
extern int  receive_pim6_cand_rp_adv __P((struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                         char *pim_message, int datalen));
extern int  receive_pim6_bootstrap   __P((struct sockaddr_in6 *src, struct sockaddr_in6 *dst,
                         char *pim_message, int datalen));
extern int  send_pim6_cand_rp_adv    __P((void));
extern void send_pim6_bootstrap  __P((void));


#endif
