/*	$KAME: vrrp_interface.c,v 1.4 2002/07/10 07:41:45 ono Exp $	*/

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

#include "vrrp_interface.h"

void 
vrrp_interface_owner_verify(struct vrrp_vr * vr)
{
	int             cpt, cpt2;

	for (cpt = 0; cpt < vr->cnt_ip; cpt++)
		for (cpt2 = 0; cpt2 < vr->vr_if->nb_ip; cpt2++)
		  if (memcmp(&vr->vr_ip[cpt].addr, &vr->vr_if->ip_addrs[cpt2], sizeof(struct in6_addr)) == 0)
				vr->vr_ip[cpt].owner = VRRP_INTERFACE_IPADDR_OWNER;

	return;
}

char 
vrrp_interface_ethaddr_set(char *if_name, struct ether_addr * ethaddr)
{
	int             sd;
	struct ifreq    ifr;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for changing mac address of interface %s: %m", if_name);
		return -1;
	}

	bzero(&ifr, sizeof(ifr));
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

	return 0;
}

char 
vrrp_interface_vrrif_set(char *if_name, u_int parent_index)
{
	int             sd;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for changing ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&parent_index;
	
	if (ioctl(sd, SIOCSETVRRP, (caddr_t) &ifr) == -1) {
		syslog(LOG_ERR, "cannot set vrrp parent interface %s (ioctl): %m", if_name);
		close(sd);
		return -1;
	}

	close(sd);

	return 0;
}

char 
vrrp_interface_vrrif_delete(char *if_name)
{
	int             sd;
	struct ifreq    ifr;
	u_int ifindex;

	bzero(&ifr, sizeof(ifr));
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for changing ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;

	ifr.ifr_data = (caddr_t)&ifindex;
	
	if (ioctl(sd, SIOCSETVRRP, (caddr_t) &ifr) == -1) {
		syslog(LOG_ERR, "cannot delete vrrp parent interface %s (ioctl): %m", if_name);
		close(sd);
		return -1;
	}

	close(sd);

	return 0;
}

struct in6_addr *
vrrp_interface_compute_netmask(u_int nbbits, struct in6_addr *mask)
{
	int i;
	
	if (nbbits > 128) {
		syslog(LOG_ERR, "specified netmask is invalid: /%u", nbbits);
		syslog(LOG_ERR, "netmask /128 is applied");
		nbbits = 128;
	}

	bzero(mask, sizeof(*mask));
	
	for (i = 0; i < nbbits / 8; i++)
		mask->s6_addr[i] = 0xff;
	
	if (nbbits % 8)
		mask->s6_addr[i] = (0xff00 >> (nbbits % 8)) & 0xff;

	return mask;
}

char 
vrrp_interface_ipaddr_set(char *if_name, struct in6_addr *addr, struct in6_addr *netmask)
{
	int             sd;
	struct in6_aliasreq ifra;
	char buf[NI_MAXHOST];

	bzero(&ifra, sizeof(struct in6_aliasreq));
	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for adding ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifra.ifra_name, if_name, sizeof(ifra.ifra_name));
	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_addr.sin6_addr = *addr;
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_addr = *netmask;

	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
        ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	
	if (ioctl(sd, SIOCAIFADDR_IN6, &ifra) == -1) {
		syslog(LOG_ERR, "cannot set ip addr %s for interface %s (ioctl SIOCAIFADDR_IN6): %m",
		       inet_ntop(AF_INET6, addr, buf, sizeof(buf)) ? buf :"", if_name);
		close(sd);
		return -1;
	}
	close(sd);

	return 0;
}

char 
vrrp_interface_ipaddr_delete(char *if_name, struct in6_addr *addr, int verbose)
{
	int             sd;
	struct in6_ifreq    ifr;
	char buf[NI_MAXHOST];

	bzero(&ifr, sizeof(ifr));
	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd == -1) {
		syslog(LOG_WARNING, "cannot open socket for deleting ip address of interface %s: %m", if_name);
		return -1;
	}
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifr.ifr_addr.sin6_family = AF_INET6;
	memcpy(&ifr.ifr_addr.sin6_addr, addr, sizeof(struct in6_addr));
	if ((ioctl(sd, SIOCDIFADDR_IN6, (char *)&ifr) == -1) && verbose) {
		syslog(LOG_ERR, "cannot delete ip addr %s for interface %s (ioctl SIOCDIFADDR): %m",
		       inet_ntop(AF_INET6, addr, buf, sizeof(buf)) ? buf :"", if_name);
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
	char buf[NI_MAXHOST];
	struct in6_addr mask;

	for (cpt = 0; cpt < vr->cnt_ip; cpt++) {
		if (!vr->vr_ip[cpt].owner) {
			vrrp_interface_vrrif_set(vr->vrrpif_name,vr->vr_if->if_index);
//			vrrp_interface_ethaddr_set(vr->vrrpif_name, &vr->ethaddr);
			vrrp_interface_compute_netmask(vr->vr_netmask[cpt],&mask);
			if (vrrp_interface_ipaddr_set(vr->vrrpif_name, &vr->vr_ip[cpt].addr, &mask) == -1) {
				if (errno != EEXIST) {
					syslog(LOG_ERR, "an error occured during setting virtual router ip address %s", 
					       inet_ntop(AF_INET6, &vr->vr_ip[cpt].addr, buf, sizeof(buf)) ? buf : "");
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
	char buf[NI_MAXHOST];

	for (cpt = 0; cpt < vr->cnt_ip; cpt++) {
		if (vr->vr_ip[cpt].owner != VRRP_INTERFACE_IPADDR_OWNER) {
			if (vrrp_interface_ipaddr_delete(vr->vrrpif_name, &vr->vr_ip[cpt].addr, 0) == -1) {
				if (errno != EADDRNOTAVAIL) {
					syslog(LOG_ERR, "an error occured during deleting virtual router ip address %s",
					       inet_ntop(AF_INET6, &vr->vr_ip[cpt].addr, buf, sizeof(buf)) ? buf : "");
					return -1;
				}
			}
			vrrp_network_delete_local_route(&vr->vr_ip[cpt].addr);
//			vrrp_interface_ethaddr_set(vr->vrrpif->if_name, &vr->vr_if->ethaddr);
			vrrp_interface_vrrif_delete(vr->vrrpif_name);
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
