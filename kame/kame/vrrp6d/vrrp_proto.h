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
 * $Id: vrrp_proto.h,v 1.2 2002/07/09 07:29:00 ono Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include "vrrp_define.h"

/* RFC 2338 vrrp header */
struct vrrp_hdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int           vrrp_t:4, vrrp_v:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int           vrrp_v:4, vrrp_t:4;
#endif
	u_char          vr_id;
	u_char          priority;
	u_char          reserved;
	u_char          auth_type;
	u_char          adv_int;
	u_short         csum;
	/* Some IP adresses, number are not defined */
	/*
	 * After IP adresses, we can found Authentification Data 1 & 2 (total
	 * of 8 bytes)
	 */
};

struct vrrp_if {
	char            if_name[IFNAMSIZ];
	u_char          nb_ip;
	u_int           if_index;
	struct in6_addr  ip_addrs[MAX_IP_ALIAS];
	struct ether_addr ethaddr;
	/*
	 * For this time we don't change ethernet address of the real
	 * interface to the RFC Mac address because FreeBSD don't support
	 * multiple real device on one physical interface (and not
	 * pseudo-device like tap etc...). So we don't need the
	 * vrrp_ethaddr_list as far as we can't do that. freevrrpd is RFC
	 * compliant anyway because we broadcast VRRP packets with normalized
	 * MAC addresses 00:5E:00... struct vrrp_ethaddr_list *p, *d;
	 */
};

struct vrrp_vip {
	struct in6_addr  addr;
	u_char          owner;
};

/* Timers RFC2338-6.2 */
struct vrrp_timer {
	struct timeval  master_down_tm;
	struct timeval  adv_tm;
};

/*
 * Parameters per Virtual Router RFC2338-6.1.2 and
 * draft-ietf-vrrp-spec-v2-05.txt
 */
struct vrrp_vr {
	u_char          vr_id;
	u_char          priority;
	int             sd;
	int             sd_bpf;
	struct ether_addr ethaddr;
	u_char          cnt_ip;
	struct vrrp_vip *vr_ip;
	u_int          *vr_netmask;
	u_char          adv_int;
	u_int           master_down_int;
	u_int           skew_time;
	struct vrrp_timer tm;
	u_char          preempt_mode;	/* False = 0, True = 1 */
	u_char          state;	/* 0 = INITIALIZE, 1 = MASTER, 2 = BACKUP */
	u_char          auth_type;
	u_char          auth_data[VRRP_AUTH_DATA_LEN];
	struct vrrp_if *vr_if;
	char           *password;
	char            vrrpif_name[IFNAMSIZ];
	u_int           vrrpif_index;
};

/*
 * Same comments for the need of ethaddr list struct vrrp_ethaddr_list {
 * struct ether_addr ethaddr; struct vrrp_ethaddr_list *next; struct
 * vrrp_ethaddr_list *previous; };
 */

struct ip6_pseudohdr 
{
	struct in6_addr ph6_src;	/* Source      Address       */
	struct in6_addr ph6_dst;	/* Destination Address       */
	u_int32_t       ph6_uplen;	/* Upper-Layer Packet Length */
	u_int8_t        ph6_zero[3];	/* zero                      */
	u_int8_t        ph6_nxt;	/* Next Header               */
};

