/*
 * Copyright (C) 1998 and 1999 WIDE Project.
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
 * draft-ietf-dhc-v6exts-12
 */

#ifndef __DHCP6OPT_H_DEFINED
#define __DHCP6OPT_H_DEFINED

#define OL6_N	-1
#define OL6_16N	-2
#define OL6_Z	-3

#define OT6_NONE	0
#define OT6_V6		1
#define OT6_STR		2
#define OT6_NUM		3

/*
 * DHCPv6 extension code values:
 */
/* Releasable Resource Extension */
#define OC6_IPADDR 1
/* General Extension */
#define OC6_TIMEZONE 8193
#define OC6_DNS 8194
#define OC6_DOMAIN 8195
#define OC6_SLPAGENT 8196
#define OC6_SLPSCOPE 8197
/* Application and Service Parameters */
#define OC6_DIRAGENT 8196
#define OC6_SVCSCOPE 8197
#define OC6_NTPSERVER 8198
#define OC6_NISDOMAIN 8199
#define OC6_NISSERVER 8200
#define OC6_NISPLUSDOMAIN 8201
#define OC6_NISPLUSSERVER 8202
/* TCP Parameters */
#define OC6_TCPKEEPALIVEINT 8203
/* DHCPv6 Extensions */
#define OC6_MAXSIZE 8204
#define OC6_CONFPARAM 8205
#define OC6_ERE 8206
#define OC6_PREFIX 8207
#define OC6_PLATSPECIFIC 8208
#define OC6_PLATCLASSID 8209
#define OC6_CLASSID 8210
#define OC6_RECONFMADDR 8211
#define OC6_RENUMSERVERADDR 8212
#define OC6_CLISVRAUTH 8213
#define OC6_CLIKEYSELECT 8214
/* End Extension */
#define OC6_END 65536

struct dhcp6_opt {
	u_int code;
	int len;
	char *name;
	int type;
};

/* index to parameters */
#define DH6T_CLIENT_ADV_WAIT		1	/* milliseconds */
#define DH6T_DEFAULT_SOLICIT_HOPCOUNT	2	/* times */
#define DH6T_SERVER_MIN_ADV_DELAY	3	/* milliseconds */
#define DH6T_SERVER_MAX_ADV_DELAY	4	/* milliseconds */
#define DH6T_REQUEST_MSG_MIN_RETRANS	5	/* retransmissions */
#define DH6T_REPLY_MSG_TIMEOUT		6	/* milliseconds */
#define DH6T_REPLY_MSG_RETRANS_INTERVAL	7	/* milliseconds */
#define DH6T_RECONF_MSG_TIMEOUT		8	/* milliseconds */
#define DH6T_RECONF_MSG_MIN_RETRANS	9	/* retransmissions */
#define DH6T_RECONF_MSG_RETRANS_INTERVAL 10	/* milliseconds */
#define DH6T_RECONF_MMSG_MIN_RESP	11	/* milliseconds */
#define DH6T_RECONF_MMSG_MAX_RESP	12	/* milliseconds */
#define DH6T_MIN_SOLICIT_DELAY		13	/* milliseconds */
#define DH6T_MAX_SOLICIT_DELAY		14	/* milliseconds */
#define DH6T_XID_TIMEOUT		15	/* milliseconds */
#define DH6T_RECONF_MULTICAST_REQUEST_WAIT 16	/* milliseconds */

extern struct dhcp6_opt *dh6o_pad;
extern struct dhcp6_opt *dh6o_end;
extern int dhcp6_param[];
extern void dhcp6opttab_init __P((void));
extern struct dhcp6_opt *dhcp6opttab_byname __P((char *));
extern struct dhcp6_opt *dhcp6opttab_bycode __P((u_int));

#endif /*__DHCP6OPT_H_DEFINED*/
