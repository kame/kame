/*	$KAME: vrrp_network.c,v 1.3 2002/07/10 04:54:16 itojun Exp $	*/

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
	int offset = 6;
	vr->sd = socket(AF_INET6, SOCK_RAW, IPPROTO_VRRP);
	if (vr->sd == -1) {
		syslog(LOG_ERR, "cannot open raw socket for VRRP protocol [ AF_INET6, SOCK_RAW, IPPROTO_VRRP ]");
		return -1;
	}
	if (setsockopt(vr->sd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0) {
		syslog(LOG_ERR, "setsockopt(IPV6_CHECKSUM):%m");
		return -1;
	}

	return 0;
}

char 
vrrp_network_set_socket(struct vrrp_vr * vr)
{
	int on;

	if (setsockopt(vr->sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
		syslog(LOG_ERR, "setsockopt(IPV6_RECVPKTINFO):%m");
		return -1;
	}
	if (setsockopt(vr->sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) {
		syslog(LOG_ERR, "setsockopt(IPV6_RECVHOPLIMIT):%m");
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

	len += sizeof(struct in6_addr) + VRRP_AUTH_DATA_LEN;

	return len;
}

void 
vrrp_network_init_ethhdr(char *buffer, struct vrrp_vr * vr)
{
	struct ether_header *ethhdr = (struct ether_header *) buffer;
	struct ip6_hdr      *ip = (struct ip6_hdr *) & buffer[sizeof(struct ether_header)];

	memcpy(&ethhdr->ether_shost, &vr->ethaddr, ETHER_ADDR_LEN);
	if (IN6_IS_ADDR_MULTICAST(&(ip->ip6_dst))) {
		ethhdr->ether_dhost[0] = 0x33;
		ethhdr->ether_dhost[1] = 0x33;
		ethhdr->ether_dhost[2] = ip->ip6_dst.s6_addr[12];
		ethhdr->ether_dhost[3] = ip->ip6_dst.s6_addr[13];
		ethhdr->ether_dhost[4] = ip->ip6_dst.s6_addr[14];
		ethhdr->ether_dhost[5] = ip->ip6_dst.s6_addr[15];
	} else {
		ethhdr->ether_dhost[0] = ip->ip6_dst.s6_addr[8] & 0xfd;
		ethhdr->ether_dhost[1] = ip->ip6_dst.s6_addr[9];
		ethhdr->ether_dhost[2] = ip->ip6_dst.s6_addr[10];
		ethhdr->ether_dhost[3] = ip->ip6_dst.s6_addr[13];
		ethhdr->ether_dhost[4] = ip->ip6_dst.s6_addr[14];
		ethhdr->ether_dhost[5] = ip->ip6_dst.s6_addr[15];
	}		
	ethhdr->ether_type = htons(ETHERTYPE_IPV6);

	return;
}

void 
vrrp_network_init_iphdr(char *buffer, struct vrrp_vr * vr)
{
	struct ip6_hdr      *ip = (struct ip6_hdr *) & buffer[sizeof(struct ether_header)];

	memset(ip, 0, sizeof(struct ip6_hdr));

	ip->ip6_vfc = IPV6_VERSION;
	ip->ip6_plen = htons(vrrp_network_vrrphdr_len(vr));
	ip->ip6_hlim = VRRP6_MULTICAST_HOPS;
	ip->ip6_nxt = IPPROTO_VRRP;
	ip->ip6_src = vr->vr_if->ip_addrs[0];

	inet_pton(AF_INET6, VRRP6_MULTICAST_IP, &ip->ip6_dst);
	/* XXX error */

	return;
}

void 
vrrp_network_init_vrrphdr(char *buffer, struct vrrp_vr * vr)
{
	struct vrrp_hdr *vp;
	struct in6_addr *addr;
	struct ip6_hdr      *ip = (struct ip6_hdr *) & buffer[sizeof(struct ether_header)];
	char           *password;
	struct ip6_pseudohdr phdr;

	vp = (struct vrrp_hdr *) & buffer[ETHER_HDR_LEN + sizeof(struct ip6_hdr)];

	memset(vp, 0, vrrp_network_vrrphdr_len(vr));

	vp->vrrp_v = VRRP_PROTOCOL_VERSION;
	vp->vrrp_t = VRRP_PROTOCOL_ADVERTISEMENT;
	vp->vr_id = vr->vr_id;
	vp->priority = vr->priority;
//	vp->cnt_ip = vr->cnt_ip;
	vp->auth_type = vr->auth_type;
	vp->adv_int = vr->adv_int;
	addr = (struct in6_addr *) & buffer[ETHER_HDR_LEN + sizeof(struct ip6_hdr) + sizeof(*vp)];
	*addr =  vr->vr_ip[0].addr;
	if (vr->auth_type == 1) {
		password = (char *)&addr[1];
		strncpy(password, vr->password, 8);
	}

	bzero(&phdr,sizeof(phdr));
	phdr.ph6_uplen = htonl(vrrp_network_vrrphdr_len(vr));
	phdr.ph6_src = ip->ip6_src;
	phdr.ph6_dst = ip->ip6_dst;
	phdr.ph6_nxt = IPPROTO_VRRP;
	
	vp->csum = vrrp_misc_compute_checksum(&phdr, (u_char *) vp);

	return;
}

char 
vrrp_network_send_advertisement(struct vrrp_vr * vr)
{
	u_char         *buffer;
	u_int           len = ETHER_HDR_LEN + sizeof(struct ip6_hdr) + vrrp_network_vrrphdr_len(vr);

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
vrrp_network_send_icmp_packet(char *p, int len, int ifindex)
{
    struct msghdr m;
    struct iovec iov[2];
    static struct sockaddr_in6 sin6_buf, *sin6 = 0;
    int sd;
    u_int hlim = 255;
    int ret;

    sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sd == -1) {
	syslog(LOG_ERR, "cannot open raw socket for ICMP protocol [ AF_INET6, SOCK_RAW, IPPROTO_ICMPV6 ]");
	return -1;
    }

    if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hlim, sizeof(hlim)) == -1) {
	syslog(LOG_ERR, "setsockopt(IPV6_MULTICAST_HOPS)");
	return -1;
    }
    if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) == 1) {
	syslog(LOG_ERR, "setsockopt(IPV6_MULTICAST_IF)");
	return -1;
    }

    if (sin6 == 0) {
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;

	error = getaddrinfo(ALLHOSTS_MULTICAST_IPV6, NULL, &hints, &res);
	if (error) {
	    /* XXX error */
	    syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(error));
	    exit(1);
	}
	sin6 = &sin6_buf;
	memcpy(sin6, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
    }

    m.msg_name = (caddr_t)sin6;
    m.msg_namelen = sin6->sin6_len;
    iov[0].iov_base = p;
    iov[0].iov_len = len;
    m.msg_iov = iov;
    m.msg_iovlen = 1;
    m.msg_control = NULL;
    m.msg_controllen = 0;

    ret = sendmsg(sd, &m, 0);
    close(sd);
    return len == ret ? 0 : -1;
}

      

char
vrrp_network_send_neighbor_advertisement(struct vrrp_vr *vr)
{
#define ROUNDUP8(a) (1 + (((a) - 1) | 7))
	struct nd_neighbor_advert *icp;
	struct nd_opt_hdr *ndopt;
	u_char outpack[sizeof(struct nd_neighbor_advert) + ROUNDUP8(ETHER_ADDR_LEN + 2)];
	
	memset(outpack, 0, sizeof outpack);
	icp = (struct nd_neighbor_advert *)outpack;
	
	icp->nd_na_type = ND_NEIGHBOR_ADVERT;
	icp->nd_na_code = 0;
	icp->nd_na_cksum = 0;
	icp->nd_na_flags_reserved = ND_NA_FLAG_ROUTER|ND_NA_FLAG_OVERRIDE;

	memcpy(&icp->nd_na_target, &vr->vr_ip->addr, sizeof(struct in6_addr));
	ndopt = (struct nd_opt_hdr *)(icp+1);
	
	ndopt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	ndopt->nd_opt_len = (ROUNDUP8(ETHER_ADDR_LEN + 2)) >> 3;
	memcpy(ndopt + 1, &vr->ethaddr, ETHER_ADDR_LEN);

	if (vrrp_network_send_icmp_packet(outpack, sizeof outpack, vr->vrrpif_index) != 0) {
	    return -1;
	}
	return 0;
}

#define rtm rtmsg.rthdr
char 
vrrp_network_delete_local_route(struct in6_addr *addr)
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
	rtmsg.addr.sin6_len = sizeof(rtmsg.addr);
	rtmsg.addr.sin6_family = AF_INET6;
	rtmsg.addr.sin6_addr = *addr;
	if (write(sd, &rtmsg, sizeof(rtmsg)) == -1) {
		close(sd);
		return -1;
	}
	close(sd);

	return 0;
}
