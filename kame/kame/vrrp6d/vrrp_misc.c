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
 * $Id: vrrp_misc.c,v 1.1.1.1 2002/07/09 07:19:20 ono Exp $
 */

#include "vrrp_misc.h"

/* this code is based on ifconfig.c */
#define ROUNDUP(a) \
((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

void 
rt_xaddrs(caddr_t cp, caddr_t cplim, struct rt_addrinfo * rtinfo)
{
	struct sockaddr *sa;
	int             i;

	memset(rtinfo->rti_info, 0, sizeof(rtinfo->rti_info));
	for (i = 0; (i < RTAX_MAX) && (cp < cplim); i++) {
		if ((rtinfo->rti_addrs & (1 << i)) == 0)
			continue;
		rtinfo->rti_info[i] = sa = (struct sockaddr *) cp;
		ADVANCE(cp, sa);
	}
}

char 
vrrp_misc_get_if_infos(char *if_name, struct ether_addr * ethaddr, struct in_addr * ip_addrs, int *size)
{
	int             addrcount;
	struct if_msghdr *ifm, *nextifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_dl *sdl;
	struct sockaddr_in *sin;
	char           *buf, *lim, *next;
	char            name[32];
	struct rt_addrinfo info;
	size_t          needed;
	int             mib[6];
	int             sizes = *size;
	char            myinterface = 0;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		syslog(LOG_ERR, "iflist-sysctl-estimate: %m");
		return -1;
	}
	if ((buf = malloc(needed)) == NULL) {
		syslog(LOG_ERR, "malloc: %m");
		return -1;
	}
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		syslog(LOG_ERR, "actual retrieval of interface table: %m");
		return -1;
	}
	lim = buf + needed;

	next = buf;
	while (next < lim) {
		*size = sizes;
		ifm = (struct if_msghdr *) next;
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *) (ifm + 1);
			strncpy(name, sdl->sdl_data, sdl->sdl_nlen);
			name[sdl->sdl_nlen] = '\0';
		} else {
			syslog(LOG_ERR, "there is an error: ifm->ifm_type != RTM_INFO");
			return -1;
		}
		if (strlen(name) != sdl->sdl_nlen)
			continue;
		if (strncmp(name, sdl->sdl_data, sdl->sdl_nlen) != 0)
			continue;
		myinterface = !strncmp(if_name, sdl->sdl_data, sdl->sdl_nlen);
		if (ip_addrs != NULL && size != NULL && *size > 0) {
			next += ifm->ifm_msglen;
			ifam = NULL;
			addrcount = 0;
			while (next < lim) {
				nextifm = (struct if_msghdr *) next;
				if (nextifm->ifm_type != RTM_NEWADDR)
					break;
				ifam = (struct ifa_msghdr *) nextifm;
				info.rti_addrs = ifam->ifam_addrs;
				rt_xaddrs((char *)(ifam + 1), ifam->ifam_msglen + (char *)ifam, &info);
				sin = (struct sockaddr_in *) info.rti_info[RTAX_IFA];
				if (myinterface)
					ip_addrs[addrcount] = sin->sin_addr;
				addrcount++;
				if (*size <= addrcount)
					break;
				next += nextifm->ifm_msglen;
			}
			*size = addrcount;
		}
		if (ethaddr != NULL)
			if (myinterface)
				memcpy(ethaddr, LLADDR(sdl), sizeof(*ethaddr));
		if (myinterface)
			break;
	}
	free(buf);
	return 0;
}

int 
vrrp_misc_get_priority(struct vrrp_vr * vr)
{
	u_char          i = 0, j = 0;

	if (vr->cnt_ip == vr->vr_if->nb_ip) {
		while (j < vr->cnt_ip) {
			while (i < vr->vr_if->nb_ip) {
				if (vr->vr_if->ip_addrs[j].s_addr == vr->vr_ip[i].addr.s_addr)
					break;
				i++;
			}
			if (i >= vr->vr_if->nb_ip)
				return VRRP_PRIORITY_DEFAULT;
			j++;
		}
		return VRRP_PRIORITY_MASTER;
	} else
		return VRRP_PRIORITY_DEFAULT;
}

u_short 
vrrp_misc_compute_checksum(u_short * addr, register int len)
{
	int             nleft = len;
	const u_short * w = addr;
	u_short         answer;
	int             sum = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
		sum += htons(*(u_char *) w << 8);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

char 
vrrp_misc_calcul_tminterval(struct timeval * timer, u_int interval)
{
	struct timeval  tm;

	if (gettimeofday(&tm, NULL) == -1) {
		syslog(LOG_ERR, "cannot get time with gettimeofday: %m");
		return -1;
	}
	timer->tv_sec = tm.tv_sec + interval;
	timer->tv_usec = tm.tv_usec;

	return 0;
}

char 
vrrp_misc_calcul_tmrelease(struct timeval * timer, struct timeval * interval)
{
	struct timeval  tm;

	interval->tv_sec = 0;
	interval->tv_usec = 0;
	if (gettimeofday(&tm, NULL) == -1) {
		syslog(LOG_ERR, "cannot get time with gettimeofday: %m");
		return -1;
	}
	if (tm.tv_sec < timer->tv_sec || (tm.tv_sec == timer->tv_sec && tm.tv_usec < timer->tv_usec)) {
		interval->tv_sec = timer->tv_sec - tm.tv_sec;
		if (timer->tv_usec < tm.tv_usec) {
			interval->tv_sec--;
			interval->tv_usec = (timer->tv_usec + 1000000) - tm.tv_usec;
		} else
			interval->tv_usec = timer->tv_usec - tm.tv_usec;
	}
	return 0;
}

u_short 
vrrp_misc_vphdr_len(struct vrrp_hdr * vph)
{
	return (sizeof(struct vrrp_hdr) + (vph->cnt_ip << 2) + VRRP_AUTH_DATA_LEN);
}

char 
vrrp_misc_check_vrrp_packet(struct vrrp_vr * vr, char *packet)
{
	struct ip      *iph = (struct ip *) packet;
	struct vrrp_hdr *vph = (struct vrrp_hdr *) & packet[sizeof(struct ip)];
	struct in_addr *ip_addrs = (struct in_addr *) & packet[sizeof(struct ip) + sizeof(struct vrrp_hdr)];
	char           *password = NULL;
	int             error = 0;
	int             cpt, cpt2;
	char            detected;
	u_short         checksum_orig = vph->csum;
	/* VERIFIER TOUT CE QUI CONCERNE LE PACKET RECU */
	/* NON FAIT POUR LE MOMENT */

	if (iph->ip_ttl != VRRP_PRIORITY_MASTER) {
		syslog(LOG_ERR, "ip ttl of vrrp packet isn't set to 255. Packet is discarded !");
		return -1;
	}
	if (vph->vrrp_v != VRRP_PROTOCOL_VERSION) {
		syslog(LOG_ERR, "vrrp version of vrrp packet is not valid or compatible with this daemon. Packet is discarded !");
		return -1;
	}
	if (ntohs(iph->ip_len) < sizeof(struct ip) + vrrp_misc_vphdr_len(vph)) {
		syslog(LOG_ERR, "invalid vrrp packet received (invalid size). Packet is discarded !");
		return -1;
	}
	vph->csum = 0;
	if (vrrp_misc_compute_checksum((u_short *) vph, vrrp_misc_vphdr_len(vph)) != checksum_orig) {
		syslog(LOG_ERR, "checksum of vrrp packet is invalid. Packet is discarded !");
		return -1;
	}
	vph->csum = checksum_orig;
	if (vph->vr_id != vr->vr_id)
		return -1;
	if (vph->cnt_ip != vr->cnt_ip)
		error = 1;
	else {
		for (cpt = 0; cpt < vph->cnt_ip; cpt++) {
			detected = 0;
			for (cpt2 = 0; cpt2 < vr->cnt_ip; cpt2++) {
				if (ntohl(ip_addrs[cpt].s_addr) == vr->vr_ip[cpt2].addr.s_addr)
					detected = 1;
			}
			if (!detected) {
				error = 1;
				break;
			}
		}
	}
	if (error == 1) {
		syslog(LOG_ERR, "detection of misconfigured server on the network for vrid = %u and priority = %u", vph->vr_id, vph->priority);
		if (vph->priority != VRRP_PRIORITY_MASTER) {
			syslog(LOG_ERR, "this server is not a master virtual router. Packet is discarded !");
			return -1;
		}
	}
	if (vph->adv_int != vr->adv_int) {
		syslog(LOG_ERR, "the advertisement interval set on received vrrp packet isn't same localy. Packet is discarded !");
		return -1;
	}
	/* Verification of Authentification */
	password = (char *)&ip_addrs[vph->cnt_ip];
	if (vr->auth_type == 1 && strncmp(vr->password, password, 8)) {
		syslog(LOG_ERR, "authentification incorrect in a received vrrp packet. Packet is discarded !");
		return -1;
	}
	return 0;
}

void 
vrrp_misc_quit(int coderet)
{
	exit(coderet);
}

struct vrrp_if *
vrrp_misc_search_if_entry(char *name)
{
	int             cpt = 0;

	while (cpt < VRRP_PROTOCOL_MAX_VRID) {
		if (vr_ptr[cpt] == NULL)
			break;
		if (!strncmp(vr_ptr[cpt]->vr_if->if_name, name, strlen(name)))
			return vr_ptr[cpt]->vr_if;
		cpt++;
	}

	return NULL;
}

int
vrrp_misc_search_sdbpf_entry(char *name)
{
	int             cpt = 0;

	while (cpt < VRRP_PROTOCOL_MAX_VRID) {
		if (vr_ptr[cpt] == NULL)
			break;
		if (!strncmp(vr_ptr[cpt]->vr_if->if_name, name, strlen(name)))
			return vr_ptr[cpt]->sd_bpf;
		cpt++;
	}

	return -1;
}
