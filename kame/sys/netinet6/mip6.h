/*	$KAME: mip6.h,v 1.55 2002/08/05 11:49:17 k-sugyou Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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

#ifndef _MIP6_H_
#define _MIP6_H_

#define SIOCSMIP6CFG _IOW('m', 120, int)
#define SIOCSMIP6CFG_ENABLEMN        0
#define SIOCSMIP6CFG_DISABLEMN       1
#define SIOCSMIP6CFG_ENABLEHA        2
#define SIOCSMIP6CFG_ENABLEIPSEC     3
#define SIOCSMIP6CFG_DISABLEIPSEC    4
#define SIOCSMIP6CFG_ENABLEAUTHDATA  5
#define SIOCSMIP6CFG_DISABLEAUTHDATA 6
#define SIOCSMIP6CFG_ENABLEDEBUG     128
#define SIOCSMIP6CFG_DISABLEDEBUG    129
#define SIOCGBC               _IOWR('m', 122, struct mip6_req)
#define SIOCSUNUSEHA          _IOW('m', 123, struct mip6_req)
#define SIOCGUNUSEHA          _IOWR('m', 124, struct mip6_req)
#define SIOCDUNUSEHA          _IOW('m', 125, struct mip6_req)
#define SIOCDBC               _IOW('m', 126, struct mip6_req)
#define SIOCSPREFERREDIFNAMES _IOW('m', 127, struct mip6_req)

struct mip6_preferred_ifnames {
	char mip6pi_ifname[3][IFNAMSIZ];
	/* is 3 enough? or should it be dynamic? */
};
struct mip6_req {
	u_int8_t mip6r_count;
	union {
		struct mip6_bc *mip6r_mbc;
		struct sockaddr_in6 mip6r_sin6;
		struct mip6_preferred_ifnames mip6r_ifnames;
	} mip6r_ru;
};

/* protocol constants */
#define MIP6_HA_DEFAULT_LIFETIME   1800
#define MIP6_MAX_UPDATE_RATE       5
#define MIP6_MAX_PFX_ADV_DELAY     1000
#define MIP6_DHAAD_INITIAL_TIMEOUT 2
#define MIP6_DHAAD_RETRIES         3
#define MIP6_BA_INITIAL_TIMEOUT    1
#define MIP6_BA_MAX_TIMEOUT        256

/* Binding Ack status code. */
#define IP6MA_STATUS_ACCEPTED              0	/* Binding Update accepted */
#define IP6MA_STATUS_ERRORBASE             128
#define IP6MA_STATUS_UNSPECIFIED           128	/* Reason unspecified */
#define IP6MA_STATUS_PROHIBIT              129	/* Administratively prohibited */
#define IP6MA_STATUS_RESOURCES             130	/* Insufficient resources */
#define IP6MA_STATUS_NOT_SUPPORTED         131	/* ome registration not supported */
#define IP6MA_STATUS_NOT_HOME_SUBNET       132	/* Not home subnet */
#define IP6MA_STATUS_NOT_HOME_AGENT        133	/* Not home agent for this mobile node */
#define IP6MA_STATUS_DAD_FAILED            134	/* Duplicate Address Detection failed */
#define IP6MA_STATUS_SEQNO_TOO_SMALL       135	/* Sequence number out of window */
#define IP6MA_STATUS_RO_NOT_DESIRED        136	/* Route optimization unnecessary due to low traffic */
#define IP6MA_STATUS_INVAL_AUTHENTICATOR   137	/* Invalid authenticator */
#define IP6MA_STATUS_HOME_NONCE_EXPIRED    138	/* Expired Home Nonce Index */
#define IP6MA_STATUS_CAREOF_NONCE_EXPIRED  139	/* Expired Care-of Nonce Index */

/* Binding Error status code. */
#define IP6ME_STATUS_NO_BINDING		1	/* Home Address destination
						   option used without a binding
						 */
#define IP6ME_STATUS_UNKNOWN_MH_TYPE	2	/* Received message had an
						   unknown value for the MH Type
						   field
						  */
#endif /* !_MIP6_H_ */
