/*	$KAME: vrrp_network.h,v 1.5 2003/02/19 10:10:01 ono Exp $	*/

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

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/bpf.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/ethernet.h>
#else
#include <net/if_ether.h>
#endif
#include <net/route.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <varargs.h>
#include "vrrp_define.h"
#include "vrrp_proto.h"
#include "vrrp_functions.h"

struct arp_header {
	u_short         ar_hrd;	/* format of hardware address */
#define ARPHRD_ETHER    1	/* ethernet hardware format */
#define ARPHRD_IEEE802  6	/* token-ring hardware format */
#define ARPHRD_FRELAY   15	/* frame relay hardware format */
	u_short         ar_pro;	/* format of protocol address */
	u_char          ar_hln;	/* length of hardware address */
	u_char          ar_pln;	/* length of protocol address */
	u_short         ar_op;	/* one of: */
#define ARPOP_REQUEST   1	/* request to resolve address */
#define ARPOP_REPLY     2	/* response to previous request */
#define ARPOP_REVREQUEST 3	/* request protocol address given hardware */
#define ARPOP_REVREPLY  4	/* response giving protocol address */
#define ARPOP_INVREQUEST 8	/* request to identify peer */
#define ARPOP_INVREPLY  9	/* response identifying peer */
	u_char          ar_sha[6];	/* sender hardware address */
	u_char          ar_spa[4];	/* sender protocol address */
	u_char          ar_tha[6];	/* target hardware address */
	u_char          ar_tpa[4];	/* target protocol address */
};

struct routemsg {
	struct rt_msghdr rthdr;
	struct sockaddr_in6 addr;
};
