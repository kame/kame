/*	$KAME: vrrp_state.c,v 1.9 2003/05/13 07:06:30 ono Exp $	*/

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

#include "vrrp_state.h"

struct vrrp_timer *vrrp_state_master_expire(void *data);
void vrrp_state_master_update(void *data, struct timeval *tm);
struct vrrp_timer *vrrp_state_backup_expire(void *data);

/* addresses table of all struct vrrp_vr */
struct vrrp_vr *vr_ptr[VRRP_PROTOCOL_MAX_VRID];
/* actual position on this table */
u_char vr_ptr_pos = 0;

int
vrrp_state_initialize(struct vrrp_vr * vr)
{
	if (vr->priority == 255) {
		if (vrrp_state_set_master(vr) == -1)
			return -1;
	} else if (vrrp_state_set_backup(vr) == -1)
		return -1;

	return 0;
}

int
vrrp_state_initialize_all(void)
{
	int i;
	
	for (i = 0; i < vr_ptr_pos; i++) {
		if (vrrp_state_initialize(vr_ptr[i]) != 0)
			return -1;
	}

	return 0;
}

int
vrrp_state_set_master(struct vrrp_vr * vr)
{
	if (vr->tm)
		vrrp_remove_timer(&vr->tm);
	if (vrrp_interface_vripaddr_set(vr) == -1)
		return -1;
	vrrp_interface_up(vr->vrrpif_name);
	vrrp_network_send_advertisement(vr);
	if (vrrp_network_send_neighbor_advertisement(vr) == -1)
	    return -1;
	vr->tm = vrrp_add_timer(vrrp_state_master_expire,
	    vrrp_state_master_update, vr, vr);
	vrrp_set_timer(vr->adv_int, vr->tm);

	vr->state = VRRP_STATE_MASTER;
	syslog(LOG_NOTICE, "server state vrid %d: master", vr->vr_id);

	return 0;
}

int
vrrp_state_set_backup(struct vrrp_vr * vr)
{
	if (vr->tm)
		vrrp_remove_timer(&vr->tm);

	vrrp_interface_vripaddr_delete(vr);
	vrrp_interface_down(vr->vrrpif_name);
	vr->skew_time = (256 - vr->priority) / 256;
	vr->master_down_int = (3 * vr->adv_int) + vr->skew_time;

	vr->tm = vrrp_add_timer(vrrp_state_backup_expire,
	    NULL, vr, NULL);
	vrrp_set_timer(vr->master_down_int, vr->tm);
	
	vr->state = VRRP_STATE_BACKUP;
	syslog(LOG_NOTICE, "server state vrid %d: backup", vr->vr_id);

	return 0;
}

int
vrrp_state_select(struct vrrp_vr * vr, struct timeval * interval)
{
	int             coderet;
	static int             fd_ok = 0;
	static fd_set          readfds;

//	if (fd_ok == 0) {
		FD_ZERO(&readfds);
		FD_SET(vr->sd, &readfds);
		fd_ok = 1;
//	}
	coderet = select(vr->sd + 1, &readfds, NULL, NULL, interval);

	return coderet;
}

int
vrrp_state_get_packet(struct vrrp_vr *vr,
		      u_char *packet, int buflen,
		      int *hlim, 
		      struct ip6_pseudohdr *phdr)
{
	struct msghdr msg;
	struct iovec iov[1];
	int rcvcmsglen;
	struct cmsghdr *cm;
	static u_char *rcvcmsgbuf = NULL;
	struct sockaddr_in6 src;
	struct in6_pktinfo *pi = NULL;
	int plen, hlim_data = -1;
	
	plen=0;
	iov[0].iov_base = (caddr_t) packet;
	iov[0].iov_len = buflen;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	rcvcmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	rcvcmsglen += CMSG_SPACE(sizeof(int));
	if (rcvcmsgbuf == NULL &&
	    (rcvcmsgbuf = (u_char *)malloc(rcvcmsglen)) == NULL) {
		syslog(LOG_ERR, "malloc failed");
		return -1;
	}
	msg.msg_control = (caddr_t ) rcvcmsgbuf;
	msg.msg_controllen = rcvcmsglen;
	
	if ((plen = recvmsg(vr->sd, &msg, 0)) == -1) {
		syslog(LOG_ERR, "can't read on vr->sd socket descriptor: %m");
		return -1;
	}
	
	/* extract vital information via Advanced API */
	for(cm = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
	    cm;
	    cm =(struct cmsghdr *)CMSG_NXTHDR(&msg , cm ))
	{
		
		if( cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
		{
			pi=(struct in6_pktinfo *)(CMSG_DATA(cm));
		}
		
		if( cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_HOPLIMIT &&
		    cm->cmsg_len == CMSG_LEN(sizeof(int)))
		{
			hlim_data = *(int *)(CMSG_DATA(cm));
		}
	}

	if (pi == NULL) {
		syslog(LOG_WARNING, "can't get IPV6_PKTINFO");
		return -1;
	}

	if (hlim_data < 0) {
		syslog(LOG_WARNING, "can't get IPV6_HOPLIMIT");
		return -1;
	}

	*hlim = hlim_data;
	phdr->ph6_dst=pi->ipi6_addr;
	phdr->ph6_src=src.sin6_addr;
	phdr->ph6_uplen = htonl(plen);
	phdr->ph6_nxt = IPPROTO_VRRP;
	return 0;
}

int
vrrp_state_check_priority(struct vrrp_hdr * vrrph, struct vrrp_vr * vr, struct in6_addr *addr)
{
	if (vrrph->priority > vr->priority)
		return 1;
	if ((vrrph->priority == vr->priority) && memcmp((char *)addr, (char *)&vr->vr_if->ip_addrs[0], sizeof(struct in6_addr)) > 0)
		return 1;

	return 0;
}

int
vrrp_state_proc_packet(struct vrrp_vr *vr)
{
	static u_char packet[4096];
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) packet;
	struct ip6_pseudohdr phdr;
	int hlim;

	bzero(&phdr, sizeof(phdr));
	if (vrrp_state_get_packet(vr,packet, sizeof(packet), &hlim, &phdr) != 0)
		return 0;
	if (vrrp_misc_check_vrrp_packet(vr, packet, &phdr, hlim) == -1)
		return 0;
	switch (vr->state)
	{
	case VRRP_STATE_MASTER:
		if (vrrph->priority == 0) {
			if (vr->sd_bpf == -1)
				return -1;
			vrrp_network_send_advertisement(vr);
			vrrp_set_timer(vr->adv_int, vr->tm);
			return 0;
		}
		if (vrrp_state_check_priority(vrrph, vr, &phdr.ph6_src)) {
			if (vrrp_state_set_backup(vr) == -1)
				return -1;
		}
		break;
	case VRRP_STATE_BACKUP:
		if (vrrph->priority == 0)
			vrrp_set_timer(vr->skew_time, vr->tm);
		else if (vr->preempt_mode == 0 || vrrph->priority >= vr->priority)
			vrrp_set_timer(vr->master_down_int, vr->tm);
		break;
	}
	return 0;
}

void
vrrp_state_start()
{
	struct timeval *timeout;
	fd_set rfds, readers;
	int i, nfds, n;

	FD_ZERO(&readers);
	nfds = 0;
	for (i = 0; i < vr_ptr_pos; i++){
		FD_SET(vr_ptr[i]->sd, &readers);
		nfds = vr_ptr[i]->sd + 1;
	}
	
	for (;;) {
		bcopy((char *) &readers, (char *) &rfds, sizeof(rfds));

		timeout = vrrp_check_timer();
		if ((n = select(nfds, &rfds, NULL, NULL, timeout)) < 0)
		{
			if (errno != EINTR)
				syslog(LOG_WARNING, "select failed %d", errno);
			continue;
		}
		
		if (n > 0) {
			for (i = 0; i < vr_ptr_pos; i++)
			{
				if (FD_ISSET(vr_ptr[i]->sd, &rfds))
				{
					vrrp_state_proc_packet(vr_ptr[i]);
				}
			}
		}
	}
}

struct vrrp_timer *
vrrp_state_master_expire(void *data)
{
	struct vrrp_vr *vr = (struct vrrp_vr *) data;
#ifdef VRRP_DEBUG
	printf("master expire %s\n", vr->vrrpif_name);
#endif
	vrrp_network_send_advertisement(vr);

	return vr->tm;
}

void
vrrp_state_master_update(void *data, struct timeval *tm)
{
	struct vrrp_vr *vr = (struct vrrp_vr *) data;
	tm->tv_usec = 0;
	tm->tv_sec = vr->adv_int;
}

struct vrrp_timer *
vrrp_state_backup_expire(void *data)
{
	struct vrrp_vr *vr = (struct vrrp_vr *) data;
#ifdef VRRP_DEBUG
	printf("backup expire %s\n", vr->vrrpif_name);
#endif
	vrrp_state_set_master(vr);

	return NULL;
}
