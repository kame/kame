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
 * $Id: vrrp_state.c,v 1.1 2002/07/09 07:19:20 ono Exp $
 */

#include "vrrp_state.h"

char 
vrrp_state_initialize(struct vrrp_vr * vr)
{
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
	vrrp_network_send_advertisement(vr);
	vrrp_thread_mutex_lock();
	if (vrrp_interface_vripaddr_set(vr) == -1)
		return -1;
	vrrp_thread_mutex_unlock();
	if (vrrp_network_send_gratuitous_arp_vripaddrs(vr, &vr->vr_if->ethaddr) == -1)
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
	struct ether_addr ethaddr;

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
	fd_set          readfds;

	FD_ZERO(&readfds);
	FD_SET(vr->sd, &readfds);
	coderet = select(vr->sd + 1, &readfds, NULL, NULL, interval);

	return coderet;
}

/* Operation a effectuer durant l'etat master */
char 
vrrp_state_master(struct vrrp_vr * vr)
{
	int             coderet;
	u_char          packet[4096];
	struct ip      *ipp = (struct ip *) packet;
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet[sizeof(struct ip)];
	struct timeval  interval;

	for (;;) {
		if (vrrp_misc_calcul_tmrelease(&vr->tm.adv_tm, &interval) == -1)
			return -1;
		coderet = vrrp_state_select(vr, &interval);
		if (coderet > 0) {
			if (read(vr->sd, packet, sizeof(packet)) == -1) {
				syslog(LOG_ERR, "can't read on vr->sd socket descriptor: %m");
				return -1;
			}
			if (vrrp_misc_check_vrrp_packet(vr, packet) == -1)
				continue;
			if (vrrph->priority == 0) {
				if (vr->sd_bpf == -1)
					return -1;
				vrrp_network_send_advertisement(vr);
				if (vrrp_misc_calcul_tminterval(&vr->tm.adv_tm, vr->adv_int) == -1)
					return -1;
				continue;
			}
			if (vrrp_state_check_priority(vrrph, vr, ipp->ip_src)) {
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
	struct vrrp_hdr *vrrph = (struct vrrp_hdr *) & packet[sizeof(struct ip)];
	struct timeval  interval;

	for (;;) {
		if (vrrp_misc_calcul_tmrelease(&vr->tm.master_down_tm, &interval) == -1)
			return -1;
		coderet = vrrp_state_select(vr, &interval);
		if (coderet > 0) {
			if (read(vr->sd, packet, sizeof(packet)) == -1) {
				syslog(LOG_ERR, "can't read on vr->sd socket descriptor: %m");
				return -1;
			}
			if (vrrp_misc_check_vrrp_packet(vr, packet) == -1)
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
vrrp_state_check_priority(struct vrrp_hdr * vrrph, struct vrrp_vr * vr, struct in_addr addr)
{
	if (vrrph->priority > vr->priority)
		return 1;
	if ((vrrph->priority == vr->priority) && (addr.s_addr > vr->vr_if->ip_addrs[0].s_addr))
		return 1;

	return 0;
}
