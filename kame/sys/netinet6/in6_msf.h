/* $KAME: in6_msf.h,v 1.8 2004/04/04 15:26:52 suz Exp $	*/

/*
 * Copyright (c) 2002 INRIA. All rights reserved.
 *
 * Implementation of Multicast Listener Discovery, Version 2.
 * Developed by Hitoshi Asaeda, INRIA, August 2002.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of INRIA nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

#ifndef _NETINET6_IN6MSF_H_
#define _NETINET6_IN6MSF_H_

#include <sys/queue.h>
#include <netinet/in_msf.h>
#include <netinet6/ip6_var.h>

/*
 * Multicast source filters list per group address.
 */
LIST_HEAD(i6as_head, in6_addr_source);

struct in6_addr_source {
	struct	sockaddr_in6 i6as_addr;	 /* source address		    */
	LIST_ENTRY(in6_addr_source) i6as_list; /* list of source addresses    */
	u_int	i6as_refcount;		 /* reference count of the source   */
};

struct in6_addr_slist {
	struct	i6as_head *head;	 /* head point of this list	    */
	u_int16_t numsrc;		 /* num of sources of this list	    */
};

struct in6_multi_source {
	u_int	i6ms_mode;		 /* current source filter mode	    */
	u_int	i6ms_grpjoin;		 /* (*,G) join request bit	    */
	struct	in6_addr_slist *i6ms_cur; /* current filtered source list  */
	struct	in6_addr_slist *i6ms_rec; /* recorded source address list  */
	struct	in6_addr_slist *i6ms_in; /* include source address list    */
	struct	in6_addr_slist *i6ms_ex; /* exclude source address list    */
	struct	in6_addr_slist *i6ms_alw;  /* pending ALLOW source address */
	struct	in6_addr_slist *i6ms_blk;  /* pending BLOCK source address */
	struct	in6_addr_slist *i6ms_toin; /* pending TO_IN source address */
	struct	in6_addr_slist *i6ms_toex; /* pending TO_EX source address */
	u_int	i6ms_timer;		 /* state-change report timer	    */
	u_int	i6ms_robvar;		 /* robustness var. of grp record  */
};

#ifdef _KERNEL
int	in6_addmultisrc(struct in6_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, int, struct i6as_head **,
		u_int *, u_int16_t *);
int	in6_delmultisrc(struct in6_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, int, struct i6as_head **,
		u_int *, u_int16_t *);
int	in6_modmultisrc(struct in6_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, u_int16_t,
		struct sockaddr_storage *, u_int, u_int, struct i6as_head **,
		u_int *, u_int16_t *);
void	in6_undomultisrc(struct in6_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, int);
int	in6_get_new_msf_state(struct in6_multi *, struct i6as_head **,
		u_int *, u_int16_t *);
int	in6_merge_msf_state(struct in6_multi *, struct i6as_head *, u_int, u_int16_t);
void	in6_free_all_msf_source_list(struct in6_multi *);
void	in6_free_msf_source_list(struct i6as_head *);
void	in6_free_msf_source_addr(struct in6_addr_slist *, struct sockaddr_in6 *);
void	in6_clear_all_pending_report(struct in6_multi *);
int	in6_merge_msf_source_addr(struct in6_addr_slist *, struct sockaddr_in6 *, int);
int	sock6_setmopt_srcfilter(struct socket *, struct group_filter **);
int	sock6_getmopt_srcfilter(struct socket *, struct group_filter **);
int	in6_getmopt_source_list(struct sock_msf *, u_int16_t *,
				struct sockaddr_storage **, u_int *);
int	in6_setmopt_source_addr(struct sockaddr_storage *,
				struct sock_msf *, int);
int	in6_setmopt_source_list(struct sock_msf *, u_int16_t,
				struct sockaddr_storage *, u_int, u_int16_t *,
				u_int16_t *, struct sockaddr_storage *);
void	in6_freemopt_source_list(struct sock_msf *, struct msf_head *, struct msf_head *);
void	in6_cleanmopt_source_addr(struct sock_msf *, int);
void	in6_undomopt_source_addr(struct sock_msf *, int);
void	in6_undomopt_source_list(struct sock_msf *, u_int);
int	match_msf6_per_if(struct in6_multi *, struct in6_addr *,
			  struct in6_addr *);

#ifdef HAVE_NRL_INPCB
int	match_msf6_per_socket(struct inpcb *, struct in6_addr *,
			      struct in6_addr *);
#else
int	match_msf6_per_socket(struct in6pcb *, struct in6_addr *,
			      struct in6_addr *);
#endif
#endif /* _KERNEL */
#endif /* _NETINET6_IN6MSF_H_ */
