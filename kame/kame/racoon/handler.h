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
/* @(#)$Id: handler.h,v 1.1.1.1 1999/08/08 23:31:21 itojun Exp $ */

#define MAXADDRS	16
extern u_int port_isakmp;

#define MAXDHGROUP	10
extern struct dh dhgroup[MAXDHGROUP];

extern vchar_t oakley_prime768;
extern vchar_t oakley_prime1024;
extern vchar_t oakley_prime1536;

struct myaddrs {
	struct myaddrs *next;
	struct sockaddr *addr;
	int sock;
};
extern struct myaddrs *myaddrs;

extern int autoaddr;
extern int rtsock;

extern int isakmp_handler __P((int));
extern void dh_init __P((void));
extern int isakmp_init __P((void));
extern u_char *isakmp_pindex __P((isakmp_index *, msgid_t *));

extern int isakmp_open __P((void));
extern void isakmp_close __P((void));
extern int isakmp_send __P((struct isakmp_ph1 *, vchar_t *));
extern int isakmp_resend_ph1 __P((struct sched *));
extern int isakmp_timeout_ph1 __P((struct sched *));
extern int isakmp_resend_ph2 __P((struct sched *));
extern int isakmp_timeout_ph2 __P((struct sched *));
extern int isakmp_expire __P((struct sched *));

extern struct isakmp_ph1 *isakmp_new_ph1 __P((isakmp_index *));
extern int isakmp_free_ph1 __P((struct isakmp_ph1 *));
extern struct isakmp_ph1 *isakmp_ph1byindex __P((isakmp_index *));
extern struct isakmp_ph1 *isakmp_ph1byindex0 __P((isakmp_index *));
extern struct isakmp_ph1 *isakmp_ph1byaddr __P((struct sockaddr *));
extern struct isakmp_ph2 *isakmp_new_ph2 __P((struct isakmp_ph1 *, msgid_t *));
extern int isakmp_free_ph2 __P((struct isakmp_ph2 *));
extern struct isakmp_ph2 *isakmp_ph2bymsgid __P((struct isakmp_ph1 *,
						msgid_t *));
extern int isakmp_post_getspi __P((struct pfkey_st *));
extern int isakmp_post_acquire __P((struct pfkey_st *));

extern int isakmp_new_queue __P((struct pfkey_st *pst,
	struct sockaddr *remote));
extern int isakmp_pfkey_over __P((struct sched *));
extern int isakmp_timeout_getspi __P((struct sched *));
extern struct isakmp_conf *isakmp_cfbypeer __P((struct sockaddr *));
extern vchar_t *isakmp_dump_ph1sa __P((u_int proto));
extern void isakmp_flush_ph1sa __P((u_int proto));

extern void isakmp_set_attr_v __P((char *buf, int type, caddr_t val, int len));
extern void isakmp_set_attr_l __P((char *buf, int type, u_int32_t val));

extern u_short isakmp_get_localport __P((struct sockaddr *local));

extern int isakmp_autoconf __P((void));
extern int update_myaddrs __P((void));
extern void grab_myaddrs __P((void));
