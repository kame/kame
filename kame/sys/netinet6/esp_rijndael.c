Return-Path: markus@openbsd.org
Delivery-Date: Wed Jul 16 00:17:26 2003
Return-Path: <markus@openbsd.org>
Delivered-To: itojun@itojun.org
Received: from sh1.iijlab.net (sh1.iijlab.net [202.232.15.98])
	by coconut.itojun.org (Postfix) with ESMTP id F033E13
	for <itojun@itojun.org>; Wed, 16 Jul 2003 00:17:25 +0900 (JST)
Received: by sh1.iijlab.net (Postfix)
	id 879DB7FB; Wed, 16 Jul 2003 00:17:25 +0900 (JST)
Delivered-To: itojun@iijlab.net
Received: from faui03.informatik.uni-erlangen.de (faui03.informatik.uni-erlangen.de [131.188.30.103])
	by sh1.iijlab.net (Postfix) with ESMTP id 1C9AE7F2
	for <itojun@iijlab.net>; Wed, 16 Jul 2003 00:17:24 +0900 (JST)
Received: from folly.informatik.uni-erlangen.de (localhost [127.0.0.1])
	by faui03.informatik.uni-erlangen.de (8.12.9/8.12.9) with ESMTP id h6FFDbOc007362
	for <itojun@iijlab.net>; Tue, 15 Jul 2003 17:13:38 +0200 (CEST)
Received: by folly.informatik.uni-erlangen.de (Postfix, from userid 31451)
	id 117E02D041; Tue, 15 Jul 2003 17:14:14 +0200 (CEST)
Date: Tue, 15 Jul 2003 17:14:14 +0200
From: Markus Friedl <markus@openbsd.org>
To: itojun@iijlab.net
Subject: Re: (KAME-snap 7892) IPsec interop problems between OpenBSD 3.2-stable and KAME
Message-ID: <20030715151414.GA21407@folly>
References: <20030714155152.GA22510@folly> <20030714160722.DFBAF13@coconut.itojun.org> <20030715103110.GA19324@folly> <20030715143018.GA1315@folly> <20030715145139.GA19968@folly> <20030715150901.GA31499@folly>
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Disposition: inline
In-Reply-To: <20030715150901.GA31499@folly>
User-Agent: Mutt/1.4.1i
X-Bogosity: No, tests=bogofilter, spamicity=0.000000, version=0.13.7.2
X-Filter: mailagent [version 3.0 PL73] for itojun@itojun.org

this works for me.

/*	$KAME: esp_rijndael.c,v 1.9 2003/07/15 15:20:25 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
#include <netinet6/esp_rijndael.h>

#include <crypto/rijndael/rijndael.h>

#include <net/net_osdep.h>

/* as rijndael uses assymetric scheduled keys, we need to do it twice. */

typedef struct {
	u_int32_t	r_ek[(RIJNDAEL_MAXNR+1)*4];
	u_int32_t	r_dk[(RIJNDAEL_MAXNR+1)*4];
	int		r_nr; /* key-length-dependent number of rounds */
} rijndael_ctx;

size_t
esp_rijndael_schedlen(algo)
	const struct esp_algorithm *algo;
{
	return sizeof(rijndael_ctx);
}

int
esp_rijndael_schedule(algo, sav)
	const struct esp_algorithm *algo;
	struct secasvar *sav;
{
	rijndael_ctx *ctx;

	ctx = (rijndael_ctx *)sav->sched;
	if ((ctx->r_nr = rijndaelKeySetupEnc(ctx->r_ek,
	    (char *)_KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc) * 8)) == 0)
		return -1;
	if (rijndaelKeySetupDec(ctx->r_dk, (char *)_KEYBUF(sav->key_enc),
	    _KEYLEN(sav->key_enc) * 8) == 0)
		return -1;
	return 0;
}

int
esp_rijndael_blockdecrypt(algo, sav, s, d)
	const struct esp_algorithm *algo;
	struct secasvar *sav;
	u_int8_t *s;
	u_int8_t *d;
{
	rijndael_ctx *ctx;

	ctx = (rijndael_ctx *)sav->sched;
	rijndaelDecrypt(ctx->r_dk, ctx->r_nr, s, d);
	return 0;
}

int
esp_rijndael_blockencrypt(algo, sav, s, d)
	const struct esp_algorithm *algo;
	struct secasvar *sav;
	u_int8_t *s;
	u_int8_t *d;
{
	rijndael_ctx *ctx;

	ctx = (rijndael_ctx *)sav->sched;
	rijndaelEncrypt(ctx->r_ek, ctx->r_nr, s, d);
	return 0;
}
