/* 
 * $Id: tree.c,v 1.1 1999/08/08 23:29:48 itojun Exp $
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
 * Hitachi Id: tree.c,v 1.2 1997/12/22 09:56:51 sumikawa Exp $
 */

#include "defs.h"

u_char get_bposn(struct in6_addr *, struct tree_node *, boolean);
struct gateway *get_gateway(struct in6_addr *, struct interface *);

struct in6_addr all_zeros, all_ones;

/* 
 * to initialize local cache
 */
void
initialize_cache(void)
{
	bzero(&all_zeros, sizeof(all_zeros));
	memset(&all_ones, 0xFF, sizeof(all_ones));

	rnhead = (struct tree_head *)malloc(sizeof(struct tree_head));
	if (rnhead == NULL) {
		syslog(LOG_ERR, "local cache memory allocation failed: %m");
		exit_route6d();
	}
	bzero(rnhead, sizeof(struct tree_head));

	rnhead->th_node[TREE_LEFT].tn_backp = &(rnhead->th_node[TREE_HEAD]);
	rnhead->th_node[TREE_LEFT].tn_bposn = LEAF_BIT_POSN;
	rnhead->th_node[TREE_LEFT].key = all_zeros;
	rnhead->th_node[TREE_LEFT].dst = NULL;

	rnhead->th_node[TREE_RIGHT].tn_backp = &(rnhead->th_node[TREE_HEAD]);
	rnhead->th_node[TREE_RIGHT].tn_bposn = LEAF_BIT_POSN;
	rnhead->th_node[TREE_RIGHT].key = all_ones;
	rnhead->th_node[TREE_RIGHT].dst = NULL;

	rnhead->th_node[TREE_HEAD].tn_backp = NULL;
	rnhead->th_node[TREE_HEAD].tn_bposn = HEAD_BIT_POSN;
	rnhead->th_node[TREE_HEAD].tn_bmask = 0x80;
	rnhead->th_node[TREE_HEAD].boff = HEAD_BIT_OFFSET;
	rnhead->th_node[TREE_HEAD].lptr = &(rnhead->th_node[TREE_LEFT]);
	rnhead->th_node[TREE_HEAD].rptr = &(rnhead->th_node[TREE_RIGHT]);

	return;
}

/* 
 * to search the route in radix tree.
 */
struct rt_plen *
locate_local_route(struct route_entry *rt_ptr, struct tree_node **result_ptr)
{
	int i;
	struct tree_node *current_node, *short_pre_ptr = NULL;
	struct rt_plen *entry_ptr;
	u_char search_pre_len;
	struct in6_addr search_prefix;
	boolean short_pre_len;

	/* rip6_preflen > 0 (MUST) */
	if (rnhead == NULL) {
		*result_ptr = NULL;
		return NULL;
	}
	current_node = &(rnhead->th_node[TREE_HEAD]);
	search_prefix = rt_ptr->rip6_addr;
	search_pre_len = rt_ptr->rip6_prflen;
	short_pre_len = FALSE;

	/* Initialize search key */
	i = (search_pre_len - 1) / 8 + 1;
	search_prefix.s6_addr[i - 1] &=
		((signed char)0x80 >> ((search_pre_len - 1) % 8));
	for (; i < 16; i++)
		search_prefix.s6_addr[i] = 0;

	/* 
	 * Traverse the tree, while leaf is not encountered. If the
	 * node is encountered with the prefix length greater than
	 * search prefix length, move left. ( as if bit is 0 )
	 */
	while (current_node->tn_bposn != LEAF_BIT_POSN) {
		/*
		 * position is 0..127, length is 0..128 (but 0 is
		 * default route) so, position+1 == length
		 */
		if (current_node->tn_bposn >= search_pre_len) {
			short_pre_len = TRUE;
			short_pre_ptr = current_node;
			do {
				current_node = current_node->lptr;
			} while (current_node->tn_bposn != LEAF_BIT_POSN);
			break;
		}
		/* If bit to be compared is ON, move right, else, move left. */
		if (search_prefix.s6_addr[current_node->boff] &
		    current_node->tn_bmask)
			current_node = current_node->rptr;
		else
			current_node = current_node->lptr;
	}

	/* 
	 * If entry is found, return the entry. NO "longest match"
	 * is needed.
	 */
	if (bcmp((void *)&search_prefix,
		 (void *)&(current_node->key), 16) == 0) {
		for (entry_ptr = current_node->dst; entry_ptr;
		     entry_ptr = entry_ptr->rp_next) {
			if (entry_ptr->rp_len == search_pre_len)
				return (entry_ptr);
		}
		*result_ptr = current_node;
		return NULL;
	}

	/* 
	 * If prefix does not match and short prefix length entry is
	 * searched for, make result pointer equal to the entry; where
	 * the entry was found with short prefix length. if prefix
	 * does not match and entry searched for is not with short
	 * prefix length, make result pointer equal to back pointer of
	 * this leaf entry.
	 */
	if (short_pre_len)
		*result_ptr = short_pre_ptr;
	else
		*result_ptr = current_node->tn_backp;

	return NULL;
}

/* 
 * to add local route in radix tree.
 */
void
add_local_route(struct route_entry *rt_ptr, struct route_entry *nh_ptr,
		struct interface *if_ptr, u_char state,
		struct tree_node *add_here)
{
	int i;
	struct rt_plen *plen;
	struct in6_addr add_prefix, gw_addr;
	u_char add_pre_len, add_metric;
	u_short add_tag;
	struct tree_node *current, *next, *leaf, *intermediate;
	struct gateway *gw;
	boolean short_pre_len = FALSE;

	current = next = leaf = intermediate = NULL;

	/* 
	 * If entry in tree where route is to be added is leaf node,
	 * add rt_plen entry to the leaf node.
	 */
	add_prefix = rt_ptr->rip6_addr;
	add_pre_len = rt_ptr->rip6_prflen;

	i = (add_pre_len - 1) / 8 + 1;
	add_prefix.s6_addr[i - 1] &=
		((signed char)0x80 >> ((add_pre_len - 1) % 8));
	for (; i < 16; i++)
		add_prefix.s6_addr[i] = 0;

	add_tag = rt_ptr->rip6_rtag;
	add_metric = rt_ptr->rip6_metric;
	gw_addr = nh_ptr->rip6_addr;

	if (add_here->tn_bposn == LEAF_BIT_POSN) {
		leaf = add_here;
		goto ATTACH;
	}

	/* Entry is to be added between current and next. */

	current = add_here;
	if (add_pre_len <= add_here->tn_bposn) {
		short_pre_len = TRUE;	/* for get_bposn() */
		next = current->lptr;
	} else if (add_prefix.s6_addr[current->boff] & current->tn_bmask)
		next = current->rptr;
	else
		next = current->lptr;

	intermediate = (struct tree_node *)malloc(sizeof(struct tree_node));
	if (intermediate == NULL) {
		syslog(LOG_ERR, "local cache memory allocation failed: %m");
		return;
	}
	leaf = (struct tree_node *)malloc(sizeof(struct tree_node));
	if (leaf == NULL) {
		free(intermediate);
		syslog(LOG_ERR, "local cache memory allocation failed: %m");
		return;
	}
	bzero(intermediate, sizeof(*intermediate));
	bzero(leaf, sizeof(*leaf));

	intermediate->tn_bposn =
		get_bposn(&add_prefix, next, short_pre_len);
	intermediate->tn_bmask =
		((unsigned char)0x80 >> ((intermediate->tn_bposn % 8)));
	intermediate->boff = (intermediate->tn_bposn) / 8;

	while (intermediate->tn_bposn < current->tn_bposn) {
		next = current;
		current = current->tn_backp;
	}

	while (next->tn_bposn < intermediate->tn_bposn) {
		/* maybe all lptr */
		current = next;
		if (add_prefix.s6_addr[current->boff] &
		    current->tn_bmask)
			next = current->rptr;
		else
			next = current->lptr;
	}

	intermediate->tn_backp = current;

	if (add_prefix.s6_addr[intermediate->boff] & intermediate->tn_bmask) {
		intermediate->rptr = leaf;
		intermediate->lptr = next;
	} else {
		intermediate->rptr = next;
		intermediate->lptr = leaf;
	}

	leaf->tn_backp = intermediate;
	leaf->tn_bposn = LEAF_BIT_POSN;
	leaf->key = add_prefix;

	if (current->lptr == next)
		current->lptr = intermediate;
	else
		current->rptr = intermediate;

	next->tn_backp = intermediate;

 ATTACH:
	plen = (struct rt_plen *)malloc(sizeof(struct rt_plen));
	if (plen == NULL) {
		syslog(LOG_ERR, "local cache memory allocation failed: %m");
		return;
	}
	bzero(plen, sizeof(*plen));

	gw = get_gateway(&gw_addr, if_ptr);
	plen->rp_leaf = leaf;
	plen->rp_gway = gw;
	plen->rp_tag = add_tag;
	plen->rp_len = add_pre_len;
	plen->rp_metric = add_metric;
	plen->rp_timer = 0;
	plen->rp_state = state;

	if ((plen->rp_len == MAX_PREFLEN) && !(state & RTS6_DEFAULT))
		plen->rp_flags |= RTF_HOST;		/* hack */
	if (state & RTS6_STATIC)
		plen->rp_flags |= RTF_STATIC;
	if ((state & RTS6_INTERFACE) && !(state & RTS6_PTOP))
		plen->rp_flags |= RTF_CLONING;	/* but no one cares */
	if (!(state & RTS6_INTERFACE))
		plen->rp_flags |= RTF_GATEWAY;
	if (state & RTS6_BLACKHOLE)
		plen->rp_flags |= RTF_REJECT;

	plen->rp_flags |= RTF_UP;

	if (!(state & RTS6_KERNEL)) {
		if ((rt_ioctl(plen, RTM_ADD) < 0) && (errno != EEXIST)) {
			/* 
			 * If new prfeix was added, delete intermediate and
			 * leaf entry for prefix.
			 */
			if (intermediate) {
				(intermediate->tn_backp->lptr == intermediate) ?
					(intermediate->tn_backp->lptr = next) :
					(intermediate->tn_backp->rptr = next);
				next->tn_backp = intermediate->tn_backp;
				free(intermediate);
				free(leaf);
			}
			free(plen);
			return;
		}
	}

	/* Link to the link list of rt_plen for this leaf. */
	plen->rp_next = leaf->dst;
	plen->rp_prev = NULL;
	if (leaf->dst)
		leaf->dst->rp_prev = plen;
	leaf->dst = plen;

	/* Link to the link list of rt_plen through the same gateway. */
	plen->rp_ndst = gw->gw_dest;
	plen->rp_pdst = NULL;
	if (gw->gw_dest)
		gw->gw_dest->rp_pdst = plen;
	gw->gw_dest = plen;

	return;
}

/* 
 * to modify local route in radix tree.
 */
void
modify_local_route(struct rt_plen *plen, struct route_entry *rt_ptr,
		   struct route_entry *nh_ptr, struct interface *if_ptr)
{
	struct gateway *gw_ptr;

	plen->rp_tag = rt_ptr->rip6_rtag;
	plen->rp_len = rt_ptr->rip6_prflen;
	plen->rp_metric = rt_ptr->rip6_metric;
	plen->rp_timer = 0;
	gw_ptr = plen->rp_gway;

	/* If gateway is changed from previous, make the changes in link. */
	if (memcmp(plen->rp_gway->gw_addr.s6_addr,
		   nh_ptr->rip6_addr.s6_addr, 16)) {
		if (plen->rp_pdst)
			plen->rp_pdst->rp_ndst = plen->rp_ndst;
		else
			plen->rp_gway->gw_dest = plen->rp_ndst;

		if (plen->rp_ndst)
			plen->rp_ndst->rp_pdst = plen->rp_pdst;

		gw_ptr = get_gateway(&(nh_ptr->rip6_addr), if_ptr);
		plen->rp_gway = gw_ptr;
		plen->rp_ndst = gw_ptr->gw_dest;
		plen->rp_pdst = NULL;
		if (gw_ptr->gw_dest)
			gw_ptr->gw_dest->rp_pdst = plen;

		gw_ptr->gw_dest = plen;
	}
	plen->rp_state |= RTS6_CHANGED;

	gw_ptr->gw_ifp = if_ptr;
	if (!(plen->rp_state & RTS6_KERNEL))
		if ((rt_ioctl(plen, RTM_CHANGE) < 0) && (errno == ESRCH))
			rt_ioctl(plen, RTM_ADD);

	return;
}

/* 
 * to delete local route from radix tree.
 */
void
delete_local_route(struct rt_plen *plen)
{
	struct tree_node *next_ptr;
	if ((plen->rp_state & RTS6_KERNEL) == 0) {
		/* only STATIC route may be deleted. (for flushing) */
		if (rt_ioctl(plen, RTM_DELETE) < 0)
			if (errno != ESRCH)
				syslog(LOG_ERR, "RTM_DELETE failed: %m");
	}
	/* Unlink from the link list of rt_plen for this leaf. */
	if (plen->rp_prev)
		plen->rp_prev->rp_next = plen->rp_next;
	/* else... is done later ZXCV */
	if (plen->rp_next)
		plen->rp_next->rp_prev = plen->rp_prev;

	/* Unlink from the link list of rt_plen through the same gateway. */
	if (plen->rp_pdst)
		plen->rp_pdst->rp_ndst = plen->rp_ndst;
	else
		plen->rp_gway->gw_dest = plen->rp_ndst;

	if (plen->rp_ndst)
		plen->rp_ndst->rp_pdst = plen->rp_pdst;

	/* 
	 * If the rt_plen to be deleted is last entry for the leaf,
	 * delete the leaf also. ZXCV
	 */
#define leaf_ptr     plen->rp_leaf
#define internal_ptr leaf_ptr->tn_backp

	if ((leaf_ptr->dst == plen) &&
	    (plen->rp_next == NULL) &&
	    (memcmp(leaf_ptr->key.s6_addr, all_zeros.s6_addr, 16) != 0) &&
	    (memcmp(leaf_ptr->key.s6_addr, all_ones.s6_addr, 16) != 0)) {
		if (internal_ptr->lptr == leaf_ptr)
			next_ptr = internal_ptr->rptr;
		else
			next_ptr = internal_ptr->lptr;

		if (internal_ptr->tn_backp->lptr == internal_ptr)
			internal_ptr->tn_backp->lptr = next_ptr;
		else
			internal_ptr->tn_backp->rptr = next_ptr;

		next_ptr->tn_backp = internal_ptr->tn_backp;
		free(internal_ptr);
		free(leaf_ptr);
		leaf_ptr = NULL;
	}

	/* ZXCV */
	if ((leaf_ptr) && (leaf_ptr->dst == plen))
		leaf_ptr->dst = plen->rp_next;	/* not NULL */
#undef internal_ptr
#undef leaf_ptr

	free(plen);

	return;
}

/* 
 * to get the gateway entry, from the link list of gateways, with the
 * address passed.
 */
struct gateway *
get_gateway(struct in6_addr *gw_addr, struct interface *if_ptr)
{
	struct gateway *gw;

	for (gw = gway; gw; gw = gw->gw_next) {
		if (!memcmp(gw->gw_addr.s6_addr, gw_addr->s6_addr, 16) &&
		    (gw->gw_ifp == if_ptr))
			return (gw);
	}

	gw = (struct gateway *)malloc(sizeof(struct gateway));
	if (gw == NULL) {
		syslog(LOG_ERR, "local cache memory allocation failed: %m");
		exit_route6d();
	}
	bzero(gw, sizeof(*gw));
	gw->gw_next = gway;
	gway = gw;
	gw->gw_addr = *gw_addr;
	gw->gw_ifp = if_ptr;
#ifdef __KAME__
	if (IN6_IS_ADDR_LINKLOCAL(&gw->gw_addr))
		gw->gw_addr.s6_addr16[1] = htons(if_index(if_ptr));
#endif

	return (gw);
}

/* 
 * flush all the local routes in radix tree, gw list and if list.
 */
void
flush_local_cache(void)
{
	struct gateway *gw, *next_gw;
	struct rt_plen *plen, *next_plen;
	struct interface *if_ptr, *next_if;
	struct int_config *if_conf_ptr, *next_if_conf;

	for (gw = gway; gw;) {
		next_gw = gw->gw_next;
		gway = next_gw;
		for (plen = gw->gw_dest; plen;) {
			next_plen = plen->rp_ndst;
			delete_local_route(plen);
			/* link will be modified before free */
			plen = next_plen;
		}
		free(gw);
		gw = next_gw;
	}
	/* now gway is NULL */

	for (if_ptr = ifnet; if_ptr;) {
		next_if = if_ptr->if_next;
		ifnet = next_if;
		if_freeaddresses(if_ptr);
		free(if_ptr);
		if_ptr = next_if;
	}

	/* Freeing interface configurations. */
	for (if_conf_ptr = ifconf; if_conf_ptr;) {
		next_if_conf = if_conf_ptr->int_next;
		ifconf = next_if_conf;
		free(if_conf_ptr);
		if_conf_ptr = next_if_conf;
	}

	if (rnhead) {
		struct tree_head *tmphead;
		tmphead = rnhead;
		rnhead = NULL;
		free(tmphead);
	}
	return;
}

/* 
 * get_bposn 
 */
u_char
get_bposn(struct in6_addr *add_pref, struct tree_node *next_ptr,
	  boolean is_short)
{
	struct tree_node *tmp_next;
	register caddr_t add, next;
	register int cmp_res, bposn;

	tmp_next = next_ptr;
	if (is_short)
		while (tmp_next->tn_bposn != LEAF_BIT_POSN)
			tmp_next = tmp_next->lptr;

	add = (caddr_t)add_pref->s6_addr;
	next = (caddr_t)tmp_next->key.s6_addr;

	while (*add++ == *next++);
	cmp_res = (add[-1] ^ next[-1]) & 0xff;	/* because cmp_res is int */
	for (bposn = (add - (caddr_t)(add_pref->s6_addr)) * 8;
	     cmp_res; bposn--) {
		cmp_res >>= 1;
	}

	return (bposn);
}

/* 
 * to compare two prefixes.
 */
boolean
prefcmp(struct in6_addr *pref1, struct in6_addr *pref2, u_char len)
{
	char t_byte = 0xFF;

	if (bcmp(pref1->s6_addr, pref2->s6_addr, len / 8) != 0)
		return (FALSE);

	if (len % 8 != 0) {
		t_byte <<= (8 - len % 8);
		return ((pref1->s6_addr[len / 8]) & t_byte)
			== ((pref2->s6_addr[len / 8]) & t_byte);
	}
	return (TRUE);
}

/* 
 * to get mask from pref length.
 */
void
get_mask(u_char pref_len, char *mask)
{
	int i;

	if (!pref_len)
		return;

	i = 0;
	while (pref_len > 31) {
		*(unsigned long *)&mask[i] = 0xFFFFFFFFUL;
		i += 4;
		pref_len -= 32;
	}
	while (pref_len > 7) {
		mask[i++] = 0xFFU;
		pref_len -= 8;
	}
	if (i < 16)
		mask[i] = 0xFFU << (8 - pref_len);

	return;
}
