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
 *
 * $Id: vrrp_state.c,v 1.2 2002/07/09 07:29:00 ono Exp $
 */

#include "vrrp_state.h"

char 
vrrp_state_initialize(struct vrrp_vr * vr)
{
	syslog(LOG_NOTICE, "server state vrid %d: initialize", vr->vr_id);
	if (vr->priority == 255) {
		if (vrrp_state_set_master(vr) == -1)
			return -1;
	} else if (vrrp_state_set_backup(vr) == -1)
		return -1;

	return 0;
}

char 
vrrp_state_set_master(struct vrrp_vr * vr)
{
	vrrp_interface_up(vr->vrrpif_name);
	vrrp_network_send_advertisement(vr);
	vrrp_thread_mutex_lock();
	if (vrrp_interface_vripaddr_set(vr) == -1)
		return -1;
	vrrp_thread_mutex_unlock();
	if (vrrp_network_send_neighbor_advertisement(vr) == -1)
	    return -1;
	if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
		return -1;
	vr->state = VRRP_STATE_MASTER;
	syslog(LOG_NOTICE, "server state vrid %d: master", vr->vr_id);

	return 0;
}

char 
vrrp_state_set_backup(struct vrrp_vr * vr)
{
	vrrp_interface_down(vr->vrrpif_name);
	vrrp_thread_mutex_lock();
	vrrp_interface_vripaddr_delete(vr);
	vrrp_thread_mutex_unlock();
	vr->skew_time = (256 - vr->priority) / 256;
	vr->master_down_int = (3 * vr->adv_int) + vr->skew_time;
	if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->master_down_int) == -1)
		return -1;
	vr->state = VRRP_STATE_BACKUP;
	syslog(LOG_NOTICE, "server state vrid %d: backup", vr->vr_id);

	return 0;
}

char 
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

/* Operation a effectuer durant l'etat master */
char 
vrrp_state_master(struct vrrp_vr * vr)
{
	int             coderet;
	static u_char   packet[4096];
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) packet;
	struct timeval  interval;
	struct ip6_pseudohdr phdr;
	int hlim;

	for (;;) {
		if (vrrp_misc_calcul_tmrelease(&vr->tm.adv_tm, &interval) == -1)
			return -1;
		coderet = vrrp_state_select(vr, &interval);
		if (coderet > 0) {
			bzero(&phdr, sizeof(phdr));
			if (vrrp_state_get_packet(vr,packet, sizeof(packet), &hlim, &phdr) != 0)
				continue;
			if (vrrp_misc_check_vrrp_packet(vr, packet, &phdr, hlim) == -1)
				continue;
			if (vrrph->priority == 0) {
				if (vr->sd_bpf == -1)
					return -1;
				vrrp_network_send_advertisement(vr);
				if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
					return -1;
				continue;
			}
			if (vrrp_state_check_priority(vrrph, vr, &phdr.ph6_src)) {
				if (vrrp_state_set_backup(vr) == -1)
					return -1;
			}
			return 0;
		}
		if (coderet == 0) {
			vrrp_network_send_advertisement(vr);
			if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
				return -1;
			continue;
		}
		if (coderet == -1) {
			syslog(LOG_ERR, "select on readfds fd_set failed: %m");
			return -1;
		}
	}

	/* Normally never executed */
	return 0;
}

char 
vrrp_state_backup(struct vrrp_vr * vr)
{
	int             coderet;
	u_char          packet[4096];
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet;
	struct timeval  interval;
	struct ip6_pseudohdr phdr;
	int hlim;

	for (;;) {
		if (vrrp_misc_calcul_tmrelease(&vr->tm.master_down_tm, &interval) == -1)
			return -1;
		coderet = vrrp_state_select(vr, &interval);
		if (coderet > 0) {
			bzero(&phdr, sizeof(phdr));
			if (vrrp_state_get_packet(vr, packet, sizeof(packet), &hlim, &phdr) != 0)
				continue;
			if (vrrp_misc_check_vrrp_packet(vr, packet, &phdr, hlim) == -1)
				continue;
			if (vrrph->priority == 0) {
				if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->skew_time) == -1)
					return -1;
				continue;
			}
			if (vr->preempt_mode == 0 || vrrph->priority >= vr->priority)
				if (vrrp_misc_calcul_tminterval(&vr->tm.master_down_tm, vr->master_down_int) == -1)
					return -1;
			continue;
		}
		if (coderet == -1) {
			syslog(LOG_ERR, "select on readfds fd_set failed: %m");
			return -1;
		}
		if (coderet == 0) {
			if (vrrp_state_set_master(vr) == -1)
				return -1;
			else
				return 0;
		}
	}

	/* Normally never executed */
	return 0;
}

char 
vrrp_state_check_priority(struct vrrp_hdr * vrrph, struct vrrp_vr * vr, struct in6_addr *addr)
{
	if (vrrph->priority > vr->priority)
		return 1;
	if ((vrrph->priority == vr->priority) && memcmp((char *)addr, (char *)&vr->vr_if->ip_addrs[0], sizeof(struct in6_addr)) > 0)
		return 1;

	return 0;
}
