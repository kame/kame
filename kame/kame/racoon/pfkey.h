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
/* YIPS @(#)$Id: pfkey.h,v 1.2 1999/09/01 05:39:40 sakane Exp $ */

#if !defined(_PFKEY_H_)
#define _PFKEY_H_

#include <sys/queue.h>

#define IPSEC_SA_STATUS_NONE		0
#define IPSEC_SA_STATUS_ACQUIRE		0x0001
#define IPSEC_SA_STATUS_GETSPI		0x0002
#define IPSEC_SA_STATUS_EXCHANGING	0x0004
#define IPSEC_SA_STATUS_UPDATE		0x0010
#define IPSEC_SA_STATUS_ADD		0x0020
#define IPSEC_SA_STATUS_ESTABLISHED	0x0040
#define IPSEC_SA_STATUS_EXPIRED		0x0080

/* status */
struct pfkey_st {
	int status;
	u_int32_t seq;			/* sequence number passed from kernel */
	int dir;

	struct sockaddr *src;		/* source address */
	struct sockaddr *dst;		/* desitnation address */
	u_int8_t ipsec_proto;		/* IPsec protocol, see ipsec_doi.h */
	u_int8_t prefs;			/* prefix for source */
	u_int8_t prefd;			/* prefix for destination */
	u_int8_t ul_proto;		/* upper protocol */
	u_int32_t spi;			/* SPI decided by me. i.e. ->me */
	u_int32_t spi_p;		/* SPI decided by peer. i.e. me-> */

	u_int8_t enctype;		/* cipher type and transform id */
	u_int8_t hashtype;		/* hash type */
	u_int8_t mode;			/* tunnel or transport */
	struct sockaddr *proxy;		/* proxy address */
	u_int32_t ld_time;		/* life time for seconds */
	u_int32_t ld_bytes;		/* life time for bytes */

	vchar_t *keymat;		/* KEYMAT */
	vchar_t *keymat_p;		/* peer's KEYMAT */

#if netyet
	struct sadb_prop *prop;		/* proposal buffer */
	struct sadb_ident *idents;	/* identity for source */
	struct sadb_ident *identd;	/* identity for destination */
	struct sadb_sens *sens;
#endif
	time_t created;			/* timestamp for created */

	struct isakmp_ph2 *ph2;  /* back pointer to isakmp status */
	struct sched *sc;

	LIST_ENTRY(pfkey_st) list;
};

#define IPSEC_INBOUND	0
#define IPSEC_OUTBOUND	1

extern int sock_pfkey;
extern u_int pfkey_acquire_lifetime;
extern u_int pfkey_acquire_try;
extern u_int pfkey_send_timer;
extern u_int pfkey_send_try;

extern int pfkey_handler __P((void));
extern vchar_t *pfkey_dump_sadb __P((int satype));
extern void pfkey_flush_sadb __P((u_int proto));
extern int pfkey_init __P((void));
extern void pfkey_set_acquire_time __P((u_int time));

extern struct pfkey_st *pfkey_new_pst __P((u_int ipsec_proto,
	struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd,
	u_int ul_proto, struct sockaddr *proxy,
	u_int32_t seq));
extern void pfkey_free_pst __P((struct pfkey_st *pst));
extern vchar_t *pfkey_dump_pst __P((int *error));
extern void pfkey_flush_pst __P((void));

extern struct pfkey_st *pfkey_get_pst __P((u_int ipsec_proto,
	struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd,
	u_int ul_proto, struct sockaddr *proxy,
	u_int32_t spi, int which_spi));

extern struct pfkey_st *pfkey_get_pst_wrap __P((caddr_t *mhp,
	int how_addrs, int how_spi));
extern int pfkey_send_getspi_wrap __P((int sock_pfkey, struct isakmp_ph2 *iph2));
extern int pfkey_resend_getspi __P((struct sched *));
extern int pfkey_send_update_wrap __P((int sock_pfkey, struct isakmp_ph2 *iph2));
extern int pfkey_send_add_wrap __P((int sock_pfkey, struct isakmp_ph2 *iph2));

extern u_int pfkey2ipsecdoi_proto __P((u_int proto));

extern int pfkey_convertfromipsecdoi __P((
	u_int proto_id, u_int t_id, u_int hashtype,
	u_int *e_type, u_int *e_keylen, u_int *a_type, u_int *a_keylen,
	u_int *flags));
#endif /* defined(_PFKEY_H_) */
