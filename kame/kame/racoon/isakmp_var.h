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
/* YIPS @(#)$Id: isakmp_var.h,v 1.5 2000/01/10 01:23:29 sakane Exp $ */

#define PORT_ISAKMP 500

typedef u_char cookie_t[8];
typedef u_char msgid_t[4];

typedef struct { /* i_cookie + r_cookie */
	cookie_t i_ck;
	cookie_t r_ck;
} isakmp_index;

struct isakmp_gen;
struct sched;

struct sockaddr;
struct ph1handle;
struct ph2handle;
struct remoteconf;
struct isakmp_gen;
struct ipsecdoi_pl_id;	/* XXX */
struct isakmp_pl_ke;	/* XXX */
struct isakmp_pl_nonce;	/* XXX */

extern int isakmp_handler __P((int so_isakmp));
extern int isakmp_main __P((vchar_t *msg, struct sockaddr *remote, struct sockaddr *local));
extern int isakmp_ph1begin_i __P((struct remoteconf *rmconf, struct sockaddr *remote));

extern vchar_t * isakmp_parsewoh __P((int np0, struct isakmp_gen *gen, int len));
extern vchar_t *isakmp_parse __P((vchar_t *buf));

extern int isakmp_init __P((void));
extern u_char *isakmp_pindex __P((isakmp_index *index, u_int32_t msgid));
extern int isakmp_open __P((void));
extern void isakmp_close __P((void));
extern int isakmp_send __P((struct ph1handle *iph1, vchar_t *buf));

extern void isakmp_ph1resend __P((struct ph1handle *iph1));
extern void isakmp_ph2resend __P((struct ph2handle *iph2));
extern void isakmp_ph1expire __P((struct ph1handle *iph1));
extern void isakmp_ph1restart __P((struct ph1handle *iph1));
extern void isakmp_ph2expire __P((struct ph2handle *iph2));

extern int isakmp_post_acquire __P((struct ph2handle *iph2));
extern int isakmp_post_getspi __P((struct ph2handle *iph2));
extern void isakmp_chkph1there __P((struct ph2handle *iph2));

extern caddr_t isakmp_set_attr_v
	__P((caddr_t buf, int type, caddr_t val, int len));
extern caddr_t isakmp_set_attr_l
	__P((caddr_t buf, int type, u_int32_t val));

extern int isakmp_newcookie
	__P((caddr_t place, struct sockaddr *remote, struct sockaddr *local));

extern int isakmp_p2ph __P((vchar_t **buf, struct isakmp_gen *gen));

extern void isakmp_check_vendorid __P((struct isakmp_gen *gen, struct sockaddr *from));

extern u_int32_t isakmp_newmsgid2 __P((struct ph1handle *iph1));
extern caddr_t set_isakmp_header __P((vchar_t *buf, struct ph1handle *iph1, int nptype));
extern caddr_t set_isakmp_header2 __P((vchar_t *buf, struct ph2handle *iph2, int nptype));
extern caddr_t set_isakmp_payload __P((caddr_t buf, vchar_t *src, int nptype));

#ifdef HAVE_PRINT_ISAKMP_C
extern void isakmp_printpacket __P((vchar_t *msg, struct sockaddr *from,
	struct sockaddr *my, int decoded));
#endif

extern int copy_ph1addresses __P(( struct ph1handle *iph1,
	struct remoteconf *rmconf, struct sockaddr *remote));
