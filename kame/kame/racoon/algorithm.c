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
/* YIPS @(#)$Id: algorithm.c,v 1.1 2000/01/09 01:31:20 itojun Exp $ */

#include <sys/param.h>
#include <sys/types.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"

#include "algorithm.h"
#include "oakley.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "ipsec_doi.h"

static int ipsecenc2doi[] = {
	ALGTYPE_NOTHING,
	IPSECDOI_ESP_DES_IV64,
	IPSECDOI_ESP_DES,
	IPSECDOI_ESP_3DES,
	IPSECDOI_ESP_RC5,
	IPSECDOI_ESP_IDEA,
	IPSECDOI_ESP_CAST,
	IPSECDOI_ESP_BLOWFISH,
	IPSECDOI_ESP_3IDEA,
	IPSECDOI_ESP_DES_IV32,
	IPSECDOI_ESP_RC4,
	IPSECDOI_ESP_NULL,
};
static int ipsecauth2doi[] = {
	ALGTYPE_NOTHING,
	IPSECDOI_ATTR_AUTH_HMAC_MD5,
	IPSECDOI_ATTR_AUTH_HMAC_SHA1,
	IPSECDOI_ATTR_AUTH_DES_MAC,
	IPSECDOI_ATTR_AUTH_KPDK,
};
static int ipseccomp2doi[] = {
	ALGTYPE_NOTHING,
	IPSECDOI_IPCOMP_OUI,
	IPSECDOI_IPCOMP_DEFLATE,
	IPSECDOI_IPCOMP_LZS,
};
static int isakmpenc2doi[] = {
	ALGTYPE_NOTHING,
	-1,
	OAKLEY_ATTR_ENC_ALG_DES,
	OAKLEY_ATTR_ENC_ALG_3DES,
	OAKLEY_ATTR_ENC_ALG_RC5,
	OAKLEY_ATTR_ENC_ALG_IDEA,
	OAKLEY_ATTR_ENC_ALG_CAST,
	OAKLEY_ATTR_ENC_ALG_BLOWFISH,
};
static int isakmphash2doi[] = {
	ALGTYPE_NOTHING,
	OAKLEY_ATTR_HASH_ALG_MD5,
	OAKLEY_ATTR_HASH_ALG_SHA,
	OAKLEY_ATTR_HASH_ALG_TIGER,
};
static int isakmpameth2doi[] = {
	ALGTYPE_NOTHING,
	OAKLEY_ATTR_AUTH_METHOD_PSKEY,
	OAKLEY_ATTR_AUTH_METHOD_DSSSIG,
	OAKLEY_ATTR_AUTH_METHOD_RSASIG,
	OAKLEY_ATTR_AUTH_METHOD_RSAENC,
	OAKLEY_ATTR_AUTH_METHOD_RSAREV,
};
static int isakmpdh2doi[] = {
	ALGTYPE_NOTHING,
	OAKLEY_ATTR_GRP_DESC_MODP768,
	OAKLEY_ATTR_GRP_DESC_MODP1024,
	OAKLEY_ATTR_GRP_DESC_MODP1536,
	OAKLEY_ATTR_GRP_DESC_EC2N155,
	OAKLEY_ATTR_GRP_DESC_EC2N185,
};

/*
 * check key length
 * OUT: -1:	NG
 *       0:	OK
 */
int
check_keylen(class, type, len)
	int class, type, len;
{
	switch (class) {
	case algclass_isakmp_enc:
		switch (type) {
		case algtype_blowfish:
		case algtype_rc5:
		case algtype_cast128:
			if (len % 8 != 0) {
				plog(logp, LOCATION, NULL,
					"key length %d is not multiple of 8",
					len);
				return -1;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

/*
 * convert algorithm type to DOI value.
 * OUT	-1   : NG
 *	other: converted.
 */
int
algtype2doi(class, type)
	int class, type;
{
	switch (class) {
	case algclass_ipsec_enc:
		if (ARRAYLEN(ipsecenc2doi) > type)
			return ipsecenc2doi[type];
		break;
	case algclass_ipsec_auth:
		if (ARRAYLEN(ipsecauth2doi) > type)
			return ipsecauth2doi[type];
		break;
	case algclass_ipsec_comp:
		if (ARRAYLEN(ipseccomp2doi) > type)
			return ipseccomp2doi[type];
		break;
	case algclass_isakmp_enc:
		if (ARRAYLEN(isakmpenc2doi) > type)
			return isakmpenc2doi[type];
		break;
	case algclass_isakmp_hash:
		if (ARRAYLEN(isakmphash2doi) > type)
			return isakmphash2doi[type];
		break;
	case algclass_isakmp_dh:
		if (ARRAYLEN(isakmpdh2doi) > type)
			return isakmpdh2doi[type];
		break;
	case algclass_isakmp_ameth:
		if (ARRAYLEN(isakmpameth2doi) > type)
			return isakmpameth2doi[type];
		break;
	}
	return -1;
}

/*
 * convert algorithm class to DOI value.
 * OUT	-1   : NG
 *	other: converted.
 */
int
algclass2doi(class)
	int class;
{
	switch (class) {
	case algclass_ipsec_enc:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case algclass_ipsec_auth:
		return IPSECDOI_ATTR_AUTH;
	case algclass_ipsec_comp:
		return IPSECDOI_PROTO_IPCOMP;
	case algclass_isakmp_enc:
		return OAKLEY_ATTR_ENC_ALG;
	case algclass_isakmp_hash:
		return OAKLEY_ATTR_HASH_ALG;
	case algclass_isakmp_dh:
		return OAKLEY_ATTR_GRP_DESC;
	case algclass_isakmp_ameth:
		return OAKLEY_ATTR_AUTH_METHOD;
	default:
		return -1;
	}
	/*NOTREACHED*/
	return -1;
}

