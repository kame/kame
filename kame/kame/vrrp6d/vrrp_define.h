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
 * $Id: vrrp_define.h,v 1.1.1.1 2002/07/09 07:19:20 ono Exp $
 */

/*
 * The virtual router can have three different states set on vrrp_vr struct
 * RFC2338-6.4.1 to RFC2338-6.4.3
 */
#define VRRP_STATE_INITIALIZE 0
#define VRRP_STATE_MASTER 1
#define VRRP_STATE_BACKUP 2
#define VRRP_PRIORITY_DEFAULT 100
#define VRRP_PRIORITY_MASTER 255
#define VRRP_AUTH_DATA_LEN 8
#define VRRP_MULTICAST_IP "224.0.0.18"
#define VRRP_MULTICAST_TTL 255
#define VRRP_PROTOCOL_VERSION 2
#define VRRP_PROTOCOL_ADVERTISEMENT 1
#define VRRP_INTERFACE_IPADDR_OWNER 1
#define VRRP_USEC_COEFF 1000000
#define VRRP_CONF_MAX_ARGS 255
#define VRRP_DEFAULT_ADV_INT 1
#define VRRP_PROTOCOL_MAX_VRID 255
#define VRRP_CONF_FILE_NAME "/usr/local/etc/freevrrpd.conf"
#define IPPROTO_VRRP 112
#define MAX_IP_ALIAS 255

/* In FreeBSD < 4.3 in_addr_t doesn't exist */
#ifndef in_addr_t
#define in_addr_t u_int32_t
#endif
