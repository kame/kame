/*
 * Copyright (c) 2002 INRIA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by INRIA and its
 *	contributors.
 * 4. Neither the name of INRIA nor the names of its contributors may be
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
 * Implementation of Internet Group Management Protocol, Version 3.
 *
 * Developed by Hitoshi Asaeda, INRIA, February 2002.
 */
#ifndef _NETINET_INMSF_H_
#define _NETINET_INMSF_H_

#include <sys/queue.h>
#include <netinet/ip_var.h>

/*
 * Multicast source filters list per group address.
 */
LIST_HEAD(ias_head, in_addr_source);

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_MSFILTER);
MALLOC_DECLARE(M_IPMOPTS);
#endif /* MALLOC_DECLARE */
#endif


struct in_addr_source {
	struct	in_addr ias_addr;	 /* source address		    */
	LIST_ENTRY(in_addr_source) ias_list; /* list of source addresses    */
	u_int	ias_refcount;		 /* reference count of the source   */
};

struct in_addr_slist {
	struct	ias_head *head;		 /* head point of this list	    */
	u_int16_t numsrc;		 /* num of sources of this list	    */
};

struct in_multi_source {
	u_int	ims_mode;		 /* current source filter mode	    */
	u_int	ims_grpjoin;		 /* (*,G) join request bit	    */
	struct	in_addr_slist *ims_cur;	 /* current filtered source list    */
	struct	in_addr_slist *ims_rec;	 /* recorded source address list    */
	struct	in_addr_slist *ims_in;	 /* include source address list	    */
	struct	in_addr_slist *ims_ex;	 /* exclude source address list	    */
	u_int	ims_excnt;		 /* max source count of EX list	    */
	struct	in_addr_slist *ims_alw;  /* pending ALLOW source address    */
	struct	in_addr_slist *ims_blk;  /* pending BLOCK source address    */
	struct	in_addr_slist *ims_toin; /* pending TO_IN source address    */
	struct	in_addr_slist *ims_toex; /* pending TO_EX source address    */
	u_int	ims_timer;		 /* state-change report timer	    */
	u_int	ims_robvar;		 /* robusutness var. of grp record  */
};

#ifdef _KERNEL
#define	IMS_ADD_SOURCE		1	 /* request to add source to list   */
#define	IMS_DELETE_SOURCE	2	 /* request to delete source to list */

#define IGMP_JOINLEAVE_OPS(optname)				\
	(((optname) == IP_ADD_SOURCE_MEMBERSHIP) ||		\
	 ((optname) == IP_DROP_SOURCE_MEMBERSHIP) ||		\
	 ((optname) == MCAST_JOIN_SOURCE_GROUP) ||		\
	 ((optname) == MCAST_LEAVE_SOURCE_GROUP))

#define IGMP_BLOCK_OPS(optname)					\
	(((optname) == IP_BLOCK_SOURCE) ||			\
	 ((optname) == IP_UNBLOCK_SOURCE) ||			\
	 ((optname) == MCAST_BLOCK_SOURCE) ||			\
	 ((optname) == MCAST_UNBLOCK_SOURCE))

#define IGMP_MSFON_OPS(optname)					\
	(((optname) == IP_ADD_SOURCE_MEMBERSHIP) ||		\
	 ((optname) == IP_BLOCK_SOURCE) ||			\
	 ((optname) == MCAST_JOIN_SOURCE_GROUP) ||		\
	 ((optname) == MCAST_BLOCK_SOURCE))

#define IGMP_MSFOFF_OPS(optname)				\
	(((optname) == IP_DROP_SOURCE_MEMBERSHIP) ||		\
	 ((optname) == IP_UNBLOCK_SOURCE) ||			\
	 ((optname) == MCAST_LEAVE_SOURCE_GROUP) ||		\
	 ((optname) == MCAST_UNBLOCK_SOURCE))

#define	IMO_MSF_ALLOC(msf) do {					\
	(msf) = (struct sock_msf *)				\
			malloc(sizeof(struct sock_msf),		\
				M_IPMOPTS, M_NOWAIT);		\
	if ((msf) == NULL) {					\
		error = ENOBUFS;				\
		break;						\
	}							\
	(msf)->msf_head = (struct msf_head *)			\
			malloc(sizeof(struct msf_head),		\
				M_IPMOPTS, M_NOWAIT);		\
	if ((msf)->msf_head == NULL) {				\
		IMO_MSF_FREE((msf));				\
		error = ENOBUFS;				\
		break;						\
	}							\
	LIST_INIT((msf)->msf_head);				\
	(msf)->msf_numsrc = 0;					\
	(msf)->msf_blkhead = (struct msf_head *)		\
			malloc(sizeof(struct msf_head),		\
				M_IPMOPTS, M_NOWAIT);		\
	if ((msf)->msf_blkhead == NULL) {			\
		IMO_MSF_FREE((msf));				\
		error = ENOBUFS;				\
		break;						\
	}							\
	LIST_INIT((msf)->msf_blkhead);				\
	(msf)->msf_blknumsrc = 0;				\
	(msf)->msf_grpjoin = 0;					\
} while (0)

#define	IMO_MSF_FREE(msf) {					\
	if ((msf)->msf_head != NULL)				\
		FREE((msf)->msf_head, M_IPMOPTS);		\
	if ((msf)->msf_blkhead != NULL)				\
		FREE((msf)->msf_blkhead, M_IPMOPTS);		\
	if ((msf) != NULL)					\
		FREE((msf), M_IPMOPTS);				\
}

int	in_addmultisrc __P((struct in_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, int, struct ias_head **,
		u_int *, u_int16_t *));
int	in_delmultisrc __P((struct in_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, int, struct ias_head **,
		u_int *, u_int16_t *));
int	in_modmultisrc __P((struct in_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, u_int16_t,
		struct sockaddr_storage *, u_int, u_int, struct ias_head **,
		u_int *, u_int16_t *));
void	in_undomultisrc __P((struct in_multi *, u_int16_t,
		struct sockaddr_storage *, u_int, int));
int	in_get_new_msf_state __P((struct in_multi *, struct ias_head **,
		u_int *, u_int16_t *));
int	in_merge_msf_state __P((struct in_multi *, struct ias_head *,
		u_int, u_int16_t));
void	in_free_all_msf_source_list __P((struct in_multi *));
void	in_free_msf_source_list __P((struct ias_head *));
void	in_free_msf_source_addr __P((struct in_addr_slist *, u_int32_t));
void	in_clear_all_pending_report __P((struct in_multi *));
int	in_merge_msf_source_addr __P((struct in_addr_slist *, u_int32_t, int));
int	ip_setmopt_srcfilter __P((struct socket *, struct ip_msfilter **));
int	ip_getmopt_srcfilter __P((struct socket *, struct ip_msfilter **));
int	sock_setmopt_srcfilter __P((struct socket *, struct group_filter **));
int	sock_getmopt_srcfilter __P((struct socket *, struct group_filter **));
void	in_freemopt_source_list __P((struct sock_msf *, struct msf_head *,
		struct msf_head *));
void	in_cleanmopt_source_addr __P((struct sock_msf *, int));
void	in_undomopt_source_addr __P((struct sock_msf *, int));
void	in_undomopt_source_list __P((struct sock_msf *, u_int));
#endif /* _KERNEL */
#endif /* _NETINET_INMSF_H_ */
