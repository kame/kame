/*	$KAME: mip6.h,v 1.59 2003/04/24 02:28:39 keiichi Exp $	*/

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

/* protocol constants. */
#define MIP6_HA_DEFAULT_LIFETIME   1800
#define MIP6_MAX_UPDATE_RATE       5
#define MIP6_MAX_PFX_ADV_DELAY     1000
#define MIP6_DHAAD_INITIAL_TIMEOUT 2
#define MIP6_DHAAD_RETRIES         3
#define MIP6_BA_INITIAL_TIMEOUT    1
#define MIP6_BA_MAX_TIMEOUT        256
#define MIP6_BU_MAX_BACKOFF        7
#define MIP6_MAX_MOB_PFX_ADV_INTERVAL	86400
#define MIP6_MIN_MOB_PFX_ADV_INTERVAL	  600

/* binding ack status code. */
#define IP6MA_STATUS_ACCEPTED              0	/* Binding Update accepted */
#define IP6MA_STATUS_ERRORBASE             128	/* ERROR BASE */
#define IP6MA_STATUS_UNSPECIFIED           128	/* Reason unspecified */
#define IP6MA_STATUS_PROHIBIT              129	/* Administratively prohibited */
#define IP6MA_STATUS_RESOURCES             130	/* Insufficient resources */
#define IP6MA_STATUS_NOT_SUPPORTED         131	/* Home registration not supported */
#define IP6MA_STATUS_NOT_HOME_SUBNET       132	/* Not home subnet */
#define IP6MA_STATUS_NOT_HOME_AGENT        133	/* Not home agent for this mobile node */
#define IP6MA_STATUS_DAD_FAILED            134	/* Duplicate Address Detection failed */
#define IP6MA_STATUS_SEQNO_TOO_SMALL       135	/* Sequence number out of window */
#define IP6MA_STATUS_HOME_NONCE_EXPIRED    136	/* Expired Home Nonce Index */
#define IP6MA_STATUS_CAREOF_NONCE_EXPIRED  137	/* Expired Care-of Nonce Index */
#define IP6MA_STATUS_NONCE_EXPIRED         138	/* Expired Nonces */

#endif /* !_MIP6_H_ */
