/*	$KAME: mip6.h,v 1.49 2002/02/13 14:52:00 keiichi Exp $	*/

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
#define SIOCGBC      _IOWR('m', 122, struct mip6_req)
#define SIOCSUNUSEHA _IOW('m', 123, struct mip6_req)
#define SIOCGUNUSEHA _IOWR('m', 124, struct mip6_req)
#define SIOCDUNUSEHA _IOW('m', 125, struct mip6_req)

struct mip6_req {
	u_int8_t mip6r_count;
	union {
		struct mip6_bc *mip6r_mbc;
		struct sockaddr_in6 mip6r_sin6;
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

/* sub-option type. */
#define MIP6SUBOPT_PAD1     0x00
#define MIP6SUBOPT_PADN     0x01
#define MIP6SUBOPT_UNIQID   0x02
#ifdef MIP6_DRAFT13
#define MIP6SUBOPT_ALTCOA   0x04
#else
#define MIP6SUBOPT_ALTCOA   0x03
#define MIP6SUBOPT_AUTHDATA 0x04
#endif /* MIP6_DRAFT13 */

/* binding ack status code. */
#define MIP6_BA_STATUS_ACCEPTED              0
#define MIP6_BA_STATUS_ERRORBASE             128
#define MIP6_BA_STATUS_UNSPECIFIED           128
#define MIP6_BA_STATUS_PROHIBIT              130
#define MIP6_BA_STATUS_RESOURCES             131
#define MIP6_BA_STATUS_NOT_SUPPORTED         132
#define MIP6_BA_STATUS_NOT_HOME_SUBNET       133
#ifdef MIP6_DRAFT13
#define MIP6_BA_STATUS_INCORRECT_IFID_LENGTH 136
#endif
#define MIP6_BA_STATUS_NOT_HOME_AGENT        137
#define MIP6_BA_STATUS_DAD_FAILED            138
#define MIP6_BA_STATUS_NO_SA                 139
#define MIP6_BA_STATUS_SEQNO_TOO_SMALL       141

/* Unique Identifier sub-option format. */
struct mip6_subopt_uniqid {
	u_int8_t type; /* 0x02 */
	u_int8_t len;  /* == 2 */
	u_int16_t id;  /* uniqid */
} __attribute__ ((__packed__));

/* Alternate Care-of Address sub-option format. */
struct mip6_subopt_altcoa {
	u_int8_t type;    /* 0x04 for draft-13, 0x03 for newer drafts */
	u_int8_t len;     /* == 16 */
	u_int8_t coa[16]; /* Alternate COA */
} __attribute__ ((__packed__));

/* Autnentication Data sub-option format. */
struct mip6_subopt_authdata {
	u_int8_t type; /* 0x04 */
	u_int8_t len;
	u_int8_t spi[4]; /* security parameter index */
	/* followed by authentication data (variable length) */
} __attribute__ ((__packed__));

#endif /* !_MIP6_H_ */
