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
/* YIPS @(#)$Id: isakmp_var.h,v 1.1.1.1 1999/08/08 23:31:23 itojun Exp $ */

struct cipher_algorithm {
	char *name;
	vchar_t *(*encrypt) __P((vchar_t *data, vchar_t *key, caddr_t iv));
	vchar_t *(*decrypt) __P((vchar_t *data, vchar_t *key, caddr_t iv));
	int (*weakkey) __P((vchar_t *key));
};

/* for parsing ISAKMP header. */
struct isakmp_parse_t {
	u_char type;
	int len;
	struct isakmp_gen *ptr;
};

/* for IV management */
struct isakmp_ivm {
	vchar_t *iv;
	vchar_t *ive;
	vchar_t *ivd;
};

extern u_int isakmp_try;
extern u_int isakmp_timer;
extern int isakmp_random_padding;
extern u_int isakmp_random_padsize;
extern int isakmp_check_padding;
extern int isakmp_pad_exclone;

extern int isakmp_main __P((vchar_t *, struct sockaddr *, struct sockaddr *));
extern struct isakmp_ph1 *isakmp_begin_phase1 __P((struct isakmp_conf *,
					struct sockaddr *, struct sockaddr *));
extern struct isakmp_ivm *isakmp_new_iv __P((struct isakmp_ph1 *iph1));
extern struct isakmp_ivm *isakmp_new_iv2 __P((struct isakmp_ph1 *iph1, msgid_t *msgid));
extern void isakmp_free_ivm __P((struct isakmp_ivm *));
extern vchar_t *isakmp_compute_hash1 __P((struct isakmp_ph1 *iph1,
	msgid_t *msgid, vchar_t *body));
extern vchar_t *isakmp_compute_hash3 __P((struct isakmp_ph1 *iph1,
		msgid_t *msgid, vchar_t *body));
extern u_int32_t isakmp_get_msgid2 __P((struct isakmp_ph1 *));
extern int set_isakmp_header2 __P((vchar_t *buf, struct isakmp_ph2 *iph2, int nptype));
extern int set_isakmp_header __P((vchar_t *buf, struct isakmp_ph1 *iph1, int nptype));
extern int isakmp_quick_r2 __P((vchar_t *, struct sockaddr *, struct isakmp_ph2 *));
extern int isakmp_quick_i2 __P((vchar_t *, struct sockaddr *, struct isakmp_ph2 *));
extern int isakmp_begin_quick __P((struct isakmp_ph1 *, struct pfkey_st *));
extern vchar_t *isakmp_parse0 __P((int, struct isakmp_gen *, int));
extern vchar_t *isakmp_parse __P((vchar_t *, struct sockaddr *));

extern vchar_t *isakmp_do_encrypt __P((struct isakmp_ph1 *iph1,
	vchar_t *msg, vchar_t *ivep, vchar_t *ivp));
extern vchar_t *isakmp_do_decrypt __P((struct isakmp_ph1 *iph1,
	vchar_t *msg, vchar_t *ivep, vchar_t *ivp));

#ifdef HAVE_PRINT_ISAKMP_C
extern void isakmp_printpacket __P((vchar_t *msg, struct sockaddr *from,
	struct sockaddr *my, int decoded));
#endif
extern int isakmp_newgroup_r __P((vchar_t *, struct sockaddr *,
	struct isakmp_ph1 *));
extern int isakmp_set_cookie __P((char *, struct sockaddr *));
