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
 * $Id: vrrp_signal.c,v 1.1.1.1 2002/07/09 07:19:21 ono Exp $
 */

#include "vrrp_signal.h"

/*
 * On detourne les signaux SIGHUP et SIGSTOP, ainsi que le signal SIGINT.
 */
void 
vrrp_signal_initialize(void)
{
	signal(SIGINT, vrrp_signal_quit);
	signal(SIGABRT, vrrp_signal_quit);
	signal(SIGTERM, vrrp_signal_quit);
	signal(SIGHUP, vrrp_signal_shutdown);
	signal(SIGSTOP, vrrp_signal_shutdown);

	return;
}

/*
 * On quitte gentiment
 */
void 
vrrp_signal_quit(int sig)
{
	int             cpt = 0;
	int             cpt2 = 0;
	struct ether_addr *ethaddr;

	while (vr_ptr[cpt]) {
		ethaddr = &vr_ptr[cpt]->vr_if->ethaddr;
		vrrp_interface_vripaddr_delete(vr_ptr[cpt]);
		while (vr_ptr[cpt]->vr_if->ip_addrs[cpt2].s_addr) {
			syslog(LOG_NOTICE, "update all ARP caches of the LAN for %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", ethaddr->octet[0], ethaddr->octet[1], ethaddr->octet[2], ethaddr->octet[3], ethaddr->octet[4], ethaddr->octet[5]);
			vrrp_network_send_gratuitous_arp(vr_ptr[cpt]->vr_if->if_name, ethaddr, vr_ptr[cpt]->vr_if->ip_addrs[cpt2], vr_ptr[cpt]);
			cpt2++;
		}
		close(vr_ptr[cpt]->sd);
		cpt++;
	}

	exit(0);
}

/*
 * Shutdown A REGARDER DE PLUS PRES PAR RAPPORT A LA RFC A QUOI CA SERT CE
 * TRUC ???
 */
void 
vrrp_signal_shutdown(int sig)
{
	int             cpt = 0;

	while (vr_ptr[cpt]) {
		switch (vr_ptr[cpt]->state) {
		case VRRP_STATE_MASTER:
			vr_ptr[cpt]->priority = 0;
			vrrp_network_send_advertisement(vr_ptr[cpt]);
		case VRRP_STATE_BACKUP:
			vrrp_state_initialize(vr_ptr[cpt]);
		}
		cpt++;
	}

	return;
}
