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
 * $Id: vrrp_network.c,v 1.1 2002/07/09 07:19:20 ono Exp $
 */

#include "vrrp_network.h"

u_short         ip_id;

int 
vrrp_network_open_bpf(struct vrrp_vr * vr)
{
	struct ifreq    ifr;
	int             n = 0;
	char            device[16];
	int             sd_bpf = 0;
	int             yes = 1;

	vrrp_network_initialize();
	while (sd_bpf <= 0 && n < 100) {
		snprintf(device, sizeof(device), "/dev/bpf%d", n++);
		sd_bpf = open(device, O_WRONLY);
	}

	if (sd_bpf < 0) {
		syslog(LOG_ALERT, "%s: %m", device);
		return -1;
	}
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, vr->vr_if->if_name, sizeof(ifr.ifr_name));
	if (ioctl(sd_bpf, BIOCSETIF, (caddr_t) & ifr) < 0) {
		syslog(LOG_ERR, "interface %s doesn't seem to exist, ioctl: %m\n", ifr.ifr_name);
		syslog(LOG_ERR, "you must correct your configuration file with a good option for 'interface ='");
		return -1;
	}
	if (ioctl(sd_bpf, BIOCSHDRCMPLT, &yes) < 0) {
		syslog(LOG_ERR, "cannot do BIOCSHDRCMPLT: %m");
		syslog(LOG_ERR, "something is terribly wrong, I can't continue: exit -1");
		return -1;
	}
	return sd_bpf;
}

void 
vrrp_network_close_bpf(struct vrrp_vr * vr)
{
	close(vr->sd_bpf);
	vr->sd_bpf = 0;

	return;
}

int 
vrrp_network_flush_bpf(int sd_bpf)
{
	if (ioctl(sd_bpf, BIOCFLUSH) == -1) {
		syslog(LOG_WARNING, "ioctl failed for flushing bpf socket descriptor");
		return -1;
	}
	ioctl(sd_bpf, BIOCFLUSH);

	return 0;
}

/* Initialisation pour l'identification IP */
void 
vrrp_network_initialize(void)
{
	srand(time(NULL));
	ip_id = random() % 65535;

	return;
}

/* Open VRRP socket for reading */
char 
vrrp_network_open_socket(struct vrrp_vr * vr)
{
	vr->sd = socket(AF_INET, SOCK_RAW, IPPROTO_VRRP);
	if (vr->sd == -1) {
		syslog(LOG_ERR, "cannot open raw socket for VRRP protocol [ AF_INET, SOCK_RAW, IPPROTO_VRRP ]");
		return -1;
	}
	return 0;
}

size_t 
vrrp_network_send_packet(char *buffer, int sizebuf, int sd_bpf)
{
	/* struct sockaddr_in addr; */
	size_t          octets;

	vrrp_thread_mutex_lock_bpf();
	vrrp_network_flush_bpf(sd_bpf);
	octets = write(sd_bpf, buffer, sizebuf);
	vrrp_network_flush_bpf(sd_bpf);
	vrrp_thread_mutex_unlock_bpf();
	if (octets == -1) {
		syslog(LOG_ERR, "can't write to bpf socket descriptor (pseudo_device bpf not activated in kernel ?)");
		return -1;
	}
	return octets;
}

u_int 
vrrp_network_vrrphdr_len(struct vrrp_vr * vr)
{
	u_int           len = sizeof(struct vrrp_hdr);

	len += (vr->cnt_ip << 2) + VRRP_AUTH_DATA_LEN;

	return len;
}

void 
vrrp_network_init_ethhdr(char *buffer, struct vrrp_vr * vr)
{
	struct ether_header *ethhdr = (struct ether_header *) buffer;

	memcpy(&ethhdr->ether_shost, &vr->ethaddr, ETHER_ADDR_LEN);
	memset(ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
	ethhdr->ether_type = htons(ETHERTYPE_IP);

	return;
}

void 
vrrp_network_init_iphdr(char *buffer, struct vrrp_vr * vr)
{
	struct ip      *iph = (struct ip *) & buffer[sizeof(struct ether_header)];

	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = sizeof(struct ip) + vrrp_network_vrrphdr_len(vr);
	iph->ip_len = htons(iph->ip_len);
	iph->ip_id = ++ip_id;
	iph->ip_off = 0;
	iph->ip_ttl = VRRP_MULTICAST_TTL;
	iph->ip_p = IPPROTO_VRRP;
	iph->ip_src.s_addr = vr->vr_if->ip_addrs[0].s_addr;
	iph->ip_dst.s_addr = inet_addr(VRRP_MULTICAST_IP);
	iph->ip_sum = vrrp_misc_compute_checksum((u_short *) iph, iph->ip_hl << 2);

	return;
}

void 
vrrp_network_init_vrrphdr(char *buffer, struct vrrp_vr * vr)
{
	struct vrrp_hdr *vp;
	struct in_addr *addr;
	char           *password;
	int             cpt;

	vp = (struct vrrp_hdr *) & buffer[ETHER_HDR_LEN + sizeof(struct ip)];
	vp->vrrp_v = VRRP_PROTOCOL_VERSION;
	vp->vrrp_t = VRRP_PROTOCOL_ADVERTISEMENT;
	vp->vr_id = vr->vr_id;
	vp->priority = vr->priority;
	vp->cnt_ip = vr->cnt_ip;
	vp->auth_type = vr->auth_type;
	vp->adv_int = vr->adv_int;
	addr = (struct in_addr *) & buffer[ETHER_HDR_LEN + sizeof(struct ip) + sizeof(*vp)];
	for (cpt = 0; cpt < vr->cnt_ip; cpt++) {
		addr[cpt].s_addr = htonl(vr->vr_ip[cpt].addr.s_addr);
	}
	if (vr->auth_type == 1) {
		password = (char *)&addr[vr->cnt_ip];
		strncpy(password, vr->password, 8);
	}
	vp->csum = vrrp_misc_compute_checksum((u_short *) vp, vrrp_network_vrrphdr_len(vr));

	return;
}

char 
vrrp_network_send_advertisement(struct vrrp_vr * vr)
{
	u_char         *buffer;
	u_int           len = ETHER_HDR_LEN + sizeof(struct ip) + vrrp_network_vrrphdr_len(vr);

	buffer = (u_char *) malloc(len);
	bzero(buffer, len);
	vrrp_network_init_iphdr(buffer, vr);
	vrrp_network_init_ethhdr(buffer, vr);
	vrrp_network_init_vrrphdr(buffer, vr);
	if (vrrp_network_send_packet(buffer, len, vr->sd_bpf) != 0) {
		free(buffer);
		return -1;
	}
	free(buffer);

	return 0;
}

char 
vrrp_network_send_gratuitous_arp(char *if_name, struct ether_addr * ethaddr, struct in_addr addr, struct vrrp_vr * vr)
{
	char            buffer[ETHER_HDR_LEN + sizeof(struct arp_header)];
	struct ether_header *ethhdr = (struct ether_header *) buffer;
	struct arp_header *arph = (struct arp_header *) & buffer[ETHER_HDR_LEN];

	memset(ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
	bcopy(ethaddr, ethhdr->ether_shost, ETHER_ADDR_LEN);
	ethhdr->ether_type = htons(ETHERTYPE_ARP);
	bzero(arph, sizeof(*arph));
	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ETHER_ADDR_LEN;
	arph->ar_pln = 4;
	arph->ar_op = htons(ARPOP_REQUEST);
	memcpy(arph->ar_sha, ethhdr->ether_shost, ETHER_ADDR_LEN);
	if (vr->sd_bpf == -1)
		return -1;
	memcpy(arph->ar_spa, &addr, sizeof(struct in_addr));
	memcpy(arph->ar_tpa, &addr, sizeof(struct in_addr));
	vrrp_thread_mutex_lock_bpf();
	if (write(vr->sd_bpf, buffer, ETHER_HDR_LEN + sizeof(struct arp_header)) == -1) {
		vrrp_thread_mutex_unlock_bpf();
		syslog(LOG_ERR, "cannot write on socket descriptor vr->sd_bpf: %m");
		return -1;
	}
	vrrp_thread_mutex_unlock_bpf();

	return 0;
}

char 
vrrp_network_send_gratuitous_arp_vripaddrs(struct vrrp_vr * vr, struct ether_addr * ethaddr)
{
	int             cpt;
	char            coderet = 0;

	for (cpt = 0; cpt < vr->cnt_ip; cpt++)
		coderet = vrrp_network_send_gratuitous_arp(vr->vr_if->if_name, ethaddr, vr->vr_ip[cpt].addr, vr);

	return coderet;
}

/*
 * char vrrp_network_send_gratuitous_arp_ipaddrs(struct vrrp_vr *vr, struct
 * ether_addr *ethaddr) { int cpt; char coderet = 0;
 * 
 * for (cpt = 0; cpt < vr->vr_if->nb_ip; cpt++) coderet =
 * vrrp_network_send_gratuitous_arp(vr->vr_if->if_name, ethaddr,
 * vr->vr_if->ip_addrs[cpt]);
 * 
 * return coderet; }
 */

char 
vrrp_network_send_gratuitous_arp_ips(struct vrrp_vr * vr, struct ether_addr * ethaddr)
{
	int             cpt = 0;
	struct in_addr  addrs[MAX_IP_ALIAS];
	int             size = MAX_IP_ALIAS;
	char            coderet = 0;

	bzero(addrs, sizeof(addrs));
	vrrp_misc_get_if_infos(vr->vr_if->if_name, NULL, addrs, &size);
	while (addrs[cpt].s_addr) {
		coderet = vrrp_network_send_gratuitous_arp(vr->vr_if->if_name, ethaddr, addrs[cpt], vr);
		syslog(LOG_ERR, "send ip = %s, eth = %x:%x:%x:%x:%x:%x", inet_ntoa(addrs[cpt]), ethaddr->octet[0], ethaddr->octet[1], ethaddr->octet[2], ethaddr->octet[3], ethaddr->octet[4], ethaddr->octet[5]);
		cpt++;
	}

	return coderet;
}

#define rtm rtmsg.rthdr
char 
vrrp_network_delete_local_route(struct in_addr addr)
{
	struct routemsg rtmsg;
	int             sd;

	sd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (sd == -1) {
		close(sd);
		return -1;
	}
	bzero(&rtmsg, sizeof(rtmsg));
	rtm.rtm_type = RTM_DELETE;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_flags = RTF_UP | RTF_HOST | RTF_LOCAL | RTF_WASCLONED;
	rtm.rtm_addrs = RTA_DST;
	rtm.rtm_msglen = sizeof(rtmsg);
	rtmsg.addr.sin_len = sizeof(rtmsg.addr);
	rtmsg.addr.sin_family = AF_INET;
	rtmsg.addr.sin_addr = addr;
	if (write(sd, &rtmsg, sizeof(rtmsg)) == -1) {
		close(sd);
		return -1;
	}
	close(sd);

	return 0;
}
