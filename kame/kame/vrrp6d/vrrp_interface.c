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
 * $Id: vrrp_interface.c,v 1.1 2002/07/09 07:19:21 ono Exp $
 */

#include "vrrp_interface.h"

void 
vrrp_interface_owner_verify(struct vrrp_vr * vr)
{
	int             cpt, cpt2;

	for (cpt = 0; cpt < vr->cnt_ip; cpt++)
		for (cpt2 = 0; cpt2 < vr->vr_if->nb_ip; cpt2++)
			if (vr->vr_ip[cpt].addr.s_addr == vr->vr_if->ip_addrs[cpt2].s_addr)
				vr->vr_ip[cpt].owner = VRRP_INTERFACE_IPADDR_OWNER;

	return;
}

char 
vrrp_interface_ethaddr_set(char *if_name, struct ether_addr * ethaddr)
{
	int             sd;
	struct ifreq    ifr;

#if defined(SIOCSIFLLADDR)
	bzero(&ifr, sizeof(ifr));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for changing ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	bcopy(ethaddr, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	if (ioctl(sd, SIOCSIFLLADDR, (caddr_t) & ifr) == -1) {
		syslog(LOG_ERR, "cannot set mac address for interface %s (ioctl): %m", if_name);
		close(sd);
		return -1;
	}
	close(sd);
#endif

	return 0;
}

in_addr_t 
vrrp_interface_compute_netmask(u_int nbbits)
{
	int             cpt = 0;
	in_addr_t       netmask = 0;

	if (nbbits > 32) {
		syslog(LOG_ERR, "specified netmask is invalid: /%u", nbbits);
		syslog(LOG_ERR, "netmask /32 or 255.255.255.255 is applied");
		return 0xFFFFFFFF;
	}
	while (cpt < nbbits) {
		netmask |= (in_addr_t) pow(2, 31 - cpt);
		cpt++;
	}

	return netmask;
}

char 
vrrp_interface_ipaddr_set(char *if_name, struct in_addr addr, in_addr_t netmask)
{
	int             sd;
	struct ifaliasreq ifra;

	bzero(&ifra, sizeof(ifra));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for adding ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifra.ifra_name, if_name, sizeof(ifra.ifra_name));
	ifra.ifra_addr.sa_len = sizeof(struct sockaddr_in);
	ifra.ifra_addr.sa_family = AF_INET;
	((struct sockaddr_in *) & ifra.ifra_addr)->sin_addr = addr;
	ifra.ifra_mask.sa_len = sizeof(struct sockaddr_in);
	ifra.ifra_mask.sa_family = AF_INET;
	((struct sockaddr_in *) & ifra.ifra_mask)->sin_addr.s_addr = htonl(netmask);
	if (ioctl(sd, SIOCAIFADDR, &ifra) == -1) {
		syslog(LOG_ERR, "cannot set ip addr %s for interface %s (ioctl SIOCAIFADDR): %m", inet_ntoa(addr), if_name);
		close(sd);
		return -1;
	}
	close(sd);

	return 0;
}

char 
vrrp_interface_ipaddr_delete(char *if_name, struct in_addr addr, int verbose)
{
	int             sd;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for deleting ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = sizeof(struct sockaddr_in);
	ifr.ifr_addr.sa_family = AF_INET;
	((struct sockaddr_in *) & ifr.ifr_addr)->sin_addr = addr;
	if ((ioctl(sd, SIOCDIFADDR, (char *)&ifr) == -1) && verbose) {
		syslog(LOG_ERR, "cannot delete ip addr %s for interface %s (ioctl SIOCDIFADDR): %m", inet_ntoa(addr), if_name);
		close(sd);
		return -1;
	}
	close(sd);

	return 0;
}

char 
vrrp_interface_vripaddr_set(struct vrrp_vr * vr)
{
	int             cpt;

	for (cpt = 0; cpt < vr->cnt_ip; cpt++) {
		if (!vr->vr_ip[cpt].owner) {
			if (vrrp_interface_ipaddr_set(vr->vr_if->if_name, vr->vr_ip[cpt].addr, vrrp_interface_compute_netmask(vr->vr_netmask[cpt])) == -1) {
				if (errno != EEXIST) {
					syslog(LOG_ERR, "an error occured during setting virtual router ip address %s", inet_ntoa(vr->vr_ip[cpt].addr));
					return -1;
				}
			}
		}
	}

	return 0;
}

char 
vrrp_interface_vripaddr_delete(struct vrrp_vr * vr)
{
	int             cpt;

	for (cpt = 0; cpt < vr->cnt_ip; cpt++) {
		if (vr->vr_ip[cpt].owner != VRRP_INTERFACE_IPADDR_OWNER) {
			if (vrrp_interface_ipaddr_delete(vr->vr_if->if_name, vr->vr_ip[cpt].addr, 0) == -1) {
				if (errno != EADDRNOTAVAIL) {
					syslog(LOG_ERR, "an error occured during deleting virtual router ip address %s", inet_ntoa(vr->vr_ip[cpt].addr));
					return -1;
				}
			}
			vrrp_network_delete_local_route(vr->vr_ip[cpt].addr);
		}
	}

	return 0;
}

char 
vrrp_interface_down(char *if_name)
{
	int             sd;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1)
		return -1;
	if (ioctl(sd, SIOCGIFFLAGS, &ifr) == -1) {
		close(sd);
		return -1;
	}
	if (ifr.ifr_flags & IFF_UP) {
		ifr.ifr_flags ^= IFF_UP;
		if (ioctl(sd, SIOCSIFFLAGS, &ifr) == -1) {
			close(sd);
			return -1;
		}
	}
	close(sd);

	return 0;
}

char 
vrrp_interface_up(char *if_name)
{
	int             sd;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1)
		return -1;
	if (ioctl(sd, SIOCGIFFLAGS, &ifr) == -1) {
		close(sd);
		return -1;
	}
	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sd, SIOCSIFFLAGS, &ifr) == -1) {
			close(sd);
			return -1;
		}
	}
	close(sd);

	return 0;
}
