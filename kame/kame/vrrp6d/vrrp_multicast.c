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
 * $Id: vrrp_multicast.c,v 1.2 2002/07/09 07:29:00 ono Exp $
 */

#include "vrrp_multicast.h"

/* join multicast group with ip address */
char 
vrrp_multicast_join_group(int sd, u_char * multicast_ip, u_int interface_index)
{
	struct in6_addr ia6;
	struct ipv6_mreq imr;

	bzero(&ia6, sizeof(ia6));
	if (inet_pton(AF_INET6, multicast_ip, &ia6) == 0) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	bzero(&imr, sizeof(imr));
	imr.ipv6mr_multiaddr = ia6;
	imr.ipv6mr_interface = interface_index;
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &imr, sizeof(imr)) == -1) {
		syslog(LOG_ERR, "cannot join multicast group %s [ IPV6_JOIN_GROUP ]", multicast_ip);
		return -1;
	}
	return 0;
}

/* Set multicast ttl IP */
char 
vrrp_multicast_set_hops(int sd, int hops)
{
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) == -1) {
		syslog(LOG_ERR, "cannot set multicast HOPS [ IPV6_MULTICAST_HOPS ]");
		return -1;
	}
	return 0;
}

char 
vrrp_multicast_set_if(int sd, u_int ifindex, char *if_name)
{
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) == -1) {
		syslog(LOG_ERR, "cannot setsockopt IPV6_MULTICAST_IF on primary address of %s: %m", if_name);
		return -1;
	}
	return 0;
}

/* Open VRRP socket and join multicast group */
char 
vrrp_multicast_set_socket(struct vrrp_vr * vr)
{
    /*
     * join parent interface
     */
	if (vrrp_multicast_join_group(vr->sd, VRRP6_MULTICAST_IP, vr->vr_if->if_index) == -1) {
		close(vr->sd);
		return -1;
	}
	if (vrrp_multicast_set_hops(vr->sd, VRRP6_MULTICAST_HOPS) == -1) {
		close(vr->sd);
		return -1;
	}

	/*
	 * send to vrrp child interface
	 */
	if (vrrp_multicast_set_if(vr->sd, vr->vrrpif_index, vr->vrrpif_name) == -1) {
		close(vr->sd);
		return -1;
	}
	return 0;
}

char 
vrrp_multicast_open_socket(struct vrrp_vr * vr)
{
	if (vrrp_network_open_socket(vr) == -1)
		return -1;
	if (vrrp_multicast_set_socket(vr) == -1)
		return -1;
	if (vrrp_network_set_socket(vr) == -1)
		return -1;

	return 0;
}
