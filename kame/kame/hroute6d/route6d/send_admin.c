/* 
 * $Id: send_admin.c,v 1.1.1.1 1999/08/08 23:29:48 itojun Exp $
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
 * Hitachi Id: send_admin.c,v 1.2 1997/12/22 09:56:49 sumikawa Exp $
 */

#include "defs.h"

static struct prefix pref_val;

/* 
 * to send routing table information to admin.
 */
void
send_admin_table(struct prefix *send_pref)
{
	struct tree_node *start_ptr;
	char buffer[ADM_PKTSIZE];
	int buf_used;

	if (!rnhead)
		goto SEND_EOF;	/* now flushing */
	bzero(&pref_val, sizeof(pref_val));
	pref_val = *send_pref;

	/* If complete table is requested, start_ptr is head of tree */
	if (pref_val.prf_len == 0) {
		start_ptr = &(rnhead->th_node[TREE_HEAD]);
	} else {
		if ((start_ptr = get_start_ptr()) == NULL)
			goto SEND_EOF;
	}

	bzero(buffer, ADM_PKTSIZE);
	buf_used = 0;
	send_all_entries(start_ptr, buffer, &buf_used);

 SEND_EOF:
	bzero(buffer, ADM_PKTSIZE);
	buf_used = 1;
	buffer[0] = ADM_EOF;
	if (sendto(admin_sock, buffer, buf_used,
		   0, (struct sockaddr *)&admin_dest,
		   sizeof(admin_dest)) < 0) {
		syslog(LOG_ERR, "send_admin_table: %m");
		return;
	}
	return;
}

/* 
 * to get the start entry from where all entries are to be sent. 
 */
struct tree_node *
get_start_ptr(void)
{
	struct tree_node *start_here;
	struct route_entry rte;

	bzero((char *)&rte, sizeof(rte));
	rte.rip6_addr = pref_val.prf_addr;
	rte.rip6_prflen = pref_val.prf_len;

	start_here = &(rnhead->th_node[TREE_HEAD]);
	while ((start_here->tn_bposn != LEAF_BIT_POSN)
	       && (start_here->tn_bposn < pref_val.prf_len)) {
		if (pref_val.prf_addr.s6_addr[start_here->boff] &
		    start_here->tn_bmask) {
			start_here = start_here->rptr;
		} else {
			start_here = start_here->lptr;
		}
	}

	return (start_here);
}

int
print_node(struct tree_node *next, char *buffer, int *buf_used)
{
	struct rt_plen *plen;
	struct rt_table *tbl;

	if (!prefcmp(&next->key, &pref_val.prf_addr, pref_val.prf_len))
		return(1);
	for (plen = next->dst; plen; plen = plen->rp_next) {
		if (plen->rp_len < pref_val.prf_len)
			continue;
		if ((ADM_PKTSIZE - *buf_used) < sizeof(struct rt_table)) {
			if (sendto(admin_sock, buffer, *buf_used, 0,
				   (struct sockaddr *)&admin_dest,
				   sizeof(admin_dest)) < 0) {
				syslog(LOG_ERR, "print node: %m");
			}
			bzero(buffer, sizeof(ADM_PKTSIZE));
			*buf_used = 0;
		}
		tbl = (struct rt_table *)(buffer + *buf_used);
		tbl->rt_dest   = next->key;
		tbl->rt_prflen = plen->rp_len;
		tbl->rt_metric = plen->rp_metric;
		tbl->rt_flag   = plen->rp_state;
		tbl->rt_gway   = plen->rp_gway->gw_addr;
		strcpy(tbl->rt_ifname, plen->rp_gway->gw_ifp->if_name);
		*buf_used += sizeof(struct rt_table);
	}
	return(0);
}

/* 
 * to send entry
 */
void
send_all_entries(struct tree_node *start, char *buffer, int *buf_used)
{
	struct tree_node *next = start;

	if (next->tn_bposn == LEAF_BIT_POSN) {
		if (!print_node(next, buffer, buf_used))
			goto LASTONE;
	}

	while (1) {
		while (next->tn_bposn != LEAF_BIT_POSN) {
			next = next->lptr;
		}
		if (print_node(next, buffer, buf_used))
			break;
		while (next->tn_backp->rptr == next) {
			next = next->tn_backp;
			if (next == start)
				goto LASTONE;
		}
		next = next->tn_backp->rptr;
	}

 LASTONE:
	if (*buf_used) {
		if (sendto(admin_sock, buffer, *buf_used, 0,
			   (struct sockaddr *)&admin_dest,
			   sizeof(admin_dest)) < 0) {
			syslog(LOG_ERR, "send_all_entries: %m");
		}
	}
	return;
}
