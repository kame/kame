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
/* YIPS @(#)$Id: oakley.c,v 1.10 2000/01/31 13:39:13 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "str2val.h"
#include "plog.h"
#include "debug.h"

#include "isakmp_var.h"
#include "isakmp.h"
#include "oakley.h"
#include "localconf.h"
#include "remoteconf.h"
#include "policy.h"
#include "handler.h"
#include "ipsec_doi.h"
#include "algorithm.h"
#include "crypto_openssl.h"
#include "strnames.h"
#include "signing.h"

#define OUTBOUND_SA	0
#define INBOUND_SA	1

#define INITDHVAL(s, a, d, t)                                                  \
do {                                                                           \
	(a)->v = str2val((s), 16, &(a)->l);                                    \
	memset(&dhgroup[(d)], 0, sizeof(struct dhgroup));                      \
	dhgroup[(d)].type = (t);                                               \
	dhgroup[(d)].prime = vdup(a);                                          \
	dhgroup[(d)].gen1 = 2;                                                 \
	dhgroup[(d)].gen2 = 0;                                                 \
} while(0);

struct dhgroup dhgroup[MAXDHGROUP];

static vchar_t oakley_prime768;
static vchar_t oakley_prime1024;
static vchar_t oakley_prime1536;

static struct cipher_algorithm cipher[] = {
{ "NULL",	NULL,			NULL,			NULL, },
{ "des",	eay_des_encrypt,	eay_des_decrypt,	eay_des_weakkey, },
#ifdef HAVE_IDEA_H
{ "idea",	eay_idea_encrypt,	eay_idea_decrypt,	eay_idea_weakkey, },
#else
{ "*dummy*",	NULL,			NULL,			NULL, },
#endif
{ "blowfish",	eay_bf_encrypt,		eay_bf_decrypt,		eay_bf_weakkey, },
#ifdef HAVE_RC5_H
{ "rc5",	eay_rc5_encrypt,	eay_rc5_decrypt,	eay_rc5_weakkey, },
#else
{ "*dummy*",	NULL,			NULL,			NULL, },
#endif
{ "3des",	eay_3des_encrypt,	eay_3des_decrypt,	eay_3des_weakkey, },
{ "cast",	eay_cast_decrypt,	eay_cast_decrypt,	eay_cast_weakkey, },
};

static int oakley_compute_keymat_x __P((struct ph2handle *iph2, int side, int sa_dir));

int
oakley_get_defaultlifetime()
{
	return OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
}

void
oakley_dhinit()
{
	/* set DH MODP */
	INITDHVAL(OAKLEY_PRIME_MODP768, &oakley_prime768,
		OAKLEY_ATTR_GRP_DESC_MODP768, OAKLEY_ATTR_GRP_TYPE_MODP);
	INITDHVAL(OAKLEY_PRIME_MODP1024, &oakley_prime1024,
		OAKLEY_ATTR_GRP_DESC_MODP1024, OAKLEY_ATTR_GRP_TYPE_MODP);
	INITDHVAL(OAKLEY_PRIME_MODP1536, &oakley_prime1536,
		OAKLEY_ATTR_GRP_DESC_MODP1536, OAKLEY_ATTR_GRP_TYPE_MODP);
}

void
oakley_dhgrp_free(dhgrp)
	struct dhgroup *dhgrp;
{
	if (dhgrp->prime)
		vfree(dhgrp->prime);
	if (dhgrp->curve_a)
		vfree(dhgrp->curve_a);
	if (dhgrp->curve_b)
		vfree(dhgrp->curve_b);
	if (dhgrp->order)
		vfree(dhgrp->order);
	free(dhgrp);
}

/*
 * compute sharing secret of DH
 * IN:	*dh, *pub, *priv, *pub_p
 * OUT: **gxy
 */
int
oakley_dh_compute(dh, pub, priv, pub_p, gxy)
	const struct dhgroup *dh;
	vchar_t *pub, *priv, *pub_p, **gxy;
{
	if ((*gxy = vmalloc(dh->prime->l)) == 0) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		return -1;
	}

	switch (dh->type) {
	case OAKLEY_ATTR_GRP_TYPE_MODP:
		if (eay_dh_compute(dh->prime, dh->gen1, pub, priv, pub_p, gxy) < 0)
			return -1;
		break;
	case OAKLEY_ATTR_GRP_TYPE_ECP:
	case OAKLEY_ATTR_GRP_TYPE_EC2N:
		plog(logp, LOCATION, NULL,
			"dh type %d isn't supported.\n", dh->type);
		return -1;
	default:
		plog(logp, LOCATION, NULL,
			"invalid dh type %d.\n", dh->type);
		return -1;
	}

	YIPSDEBUG(DEBUG_KEY,
		plog(logp, LOCATION, NULL,
			"compute DH's shared.\n"));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(*gxy));

	return 0;
}

/*
 * generate values of DH
 * IN:	*dh
 * OUT: **pub, **priv
 */
int
oakley_dh_generate(dh, pub, priv)
	const struct dhgroup *dh;
	vchar_t **pub, **priv;
{
	switch (dh->type) {
	case OAKLEY_ATTR_GRP_TYPE_MODP:
		if (eay_dh_generate(dh->prime, dh->gen1, dh->gen2, pub, priv) < 0)
			return -1;
		break;

	case OAKLEY_ATTR_GRP_TYPE_ECP:
	case OAKLEY_ATTR_GRP_TYPE_EC2N:
		plog(logp, LOCATION, NULL,
			"dh type %d isn't supported.\n", dh->type);
		return -1;
	default:
		plog(logp, LOCATION, NULL,
			"invalid dh type %d.\n", dh->type);
		return -1;
	}

	YIPSDEBUG(DEBUG_KEY,
		plog(logp, LOCATION, NULL,
			"compute DH's private.\n"));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(*priv));

	YIPSDEBUG(DEBUG_KEY,
		plog(logp, LOCATION, NULL,
			"compute DH's public.\n"));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(*pub));

	return 0;
}

/*
 * copy pre-defined dhgroup values.
 */
int
oakley_setdhgroup(group, dhgrp)
	int group;
	struct dhgroup **dhgrp;
{
	*dhgrp = CALLOC(sizeof(struct dhgroup), struct dhgroup *);
	if (*dhgrp == NULL) {
		plog(logp, LOCATION, NULL,
			"calloc (%s)\n", strerror(errno));
		return NULL;
	}
	switch (group) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		if (group > ARRAYLEN(dhgroup)
		 || dhgroup[group].type == 0) {
			plog(logp, LOCATION, NULL,
				"invalid DH parameter grp=%d.\n", group);
			free(*dhgrp);
			*dhgrp = NULL;
			return -1;
		}
		/* set defined dh vlaues */
		memcpy(*dhgrp, &dhgroup[group], sizeof(dhgroup[group]));
		(*dhgrp)->prime = vdup(dhgroup[group].prime);
		break;
	default:
		if (!(*dhgrp)->type || !(*dhgrp)->prime || !(*dhgrp)->gen1) {
			/* XXX unsuported */
			plog(logp, LOCATION, NULL,
				"unsupported DH parameters grp=%d.\n", group);
			return -1;
		}
	}

	return 0;
}

/*
 * PRF
 *
 * NOTE: we do not support prf with different input/output bitwidth,
 * so we do not implement RFC2409 Appendix B (DOORAK-MAC example) in
 * oakley_compute_keymat().  If you add support for such prf function,
 * modify oakley_compute_keymat() accordingly.
 */
vchar_t *
oakley_prf(key, buf, iph1)
	vchar_t *key, *buf;
	struct ph1handle *iph1;
{
	vchar_t *res;

	if (iph1->approval == NULL) {
		/*
		 * it's before negotiating hash algorithm.
		 * We use md5 as default.
		 */
		goto defs;
	}

	switch (iph1->approval->dh_group) {
	default:
		switch (iph1->approval->hashtype) {
		case OAKLEY_ATTR_HASH_ALG_MD5:
defs:
			YIPSDEBUG(DEBUG_KEY,
				plog(logp, LOCATION, NULL, "hmac-md5 used.\n"));
			res = eay_hmacmd5_one(key, buf);
			break;
		case OAKLEY_ATTR_HASH_ALG_SHA:
			YIPSDEBUG(DEBUG_KEY,
				plog(logp, LOCATION, NULL, "hmac-sha1 used.\n"));
			res = eay_hmacsha1_one(key, buf);
			break;
		default:
			plog(logp, LOCATION, NULL,
				"hash type %d isn't supported.\n",
				iph1->approval->hashtype);
			return NULL;
			break;
		}
	}

	return res;
}

/*
 * hash
 */
vchar_t *
oakley_hash(buf, iph1)
	vchar_t *buf;
	struct ph1handle *iph1;
{
	vchar_t *res;

	if (iph1->approval == NULL) {
		/*
		 * it's before negotiating hash algorithm.
		 * We use md5 as default.
		 */
		goto defs;
	}

	switch (iph1->approval->dh_group) {
	default:
		switch (iph1->approval->hashtype) {
		case OAKLEY_ATTR_HASH_ALG_MD5:
defs:
			YIPSDEBUG(DEBUG_KEY,
				plog(logp, LOCATION, NULL,
					"use md5 to calculate phase 1.\n"));
			res = eay_md5_one(buf);
			break;
		case OAKLEY_ATTR_HASH_ALG_SHA:
			YIPSDEBUG(DEBUG_KEY,
				plog(logp, LOCATION, NULL,
					"use sha1 to calculate phase 1.\n"));
			res = eay_sha1_one(buf);
			break;
		default:
			plog(logp, LOCATION, NULL,
				"hash type %d isn't supported.\n",
				iph1->approval->hashtype);
			return NULL;
			break;
		}
	}

	return res;
}

/*
 * compute KEYMAT
 *   see seciton 5.5 Phase 2 - Quick Mode in isakmp-oakley-05.
 */
int
oakley_compute_keymat(iph2, side)
	struct ph2handle *iph2;
	int side;
{
	int error = -1;

	/* compute sharing secret of DH when PFS */
	if (iph2->spidx->policy->pfs_group && iph2->dhpub_p) {
		if (oakley_dh_compute(iph2->spidx->policy->pfsgrp, iph2->dhpub,
				iph2->dhpriv, iph2->dhpub_p, &iph2->dhgxy) < 0)
			goto end;
	}

	/* compute keymat */
	if (oakley_compute_keymat_x(iph2, side, INBOUND_SA) < 0
	 || oakley_compute_keymat_x(iph2, side, OUTBOUND_SA) < 0)
		goto end;

	YIPSDEBUG(DEBUG_KEY,
	    plog(logp, LOCATION, NULL, "compute KEYMAT.\n"));

	error = 0;

end:
	return error;
}

/*
 * compute KEYMAT.
 * KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b).
 * If PFS is desired and KE payloads were exchanged,
 *   KEYMAT = prf(SKEYID_d, g(qm)^xy | protocol | SPI | Ni_b | Nr_b)
 *
 * NOTE: we do not support prf with different input/output bitwidth,
 * so we do not implement RFC2409 Appendix B (DOORAK-MAC example).
 */
static int
oakley_compute_keymat_x(iph2, side, sa_dir)
	struct ph2handle *iph2;
	int side;
	int sa_dir;
{
	vchar_t *buf = NULL, *res = NULL, *bp;
	char *p;
	int len;
	int error = -1;
	int pfs = 0;
	int dupkeymat;	/* generate K[1-dupkeymat] */
	struct ipsecsakeys *k;

	pfs = ((iph2->spidx->policy->pfs_group && iph2->dhgxy) ? 1 : 0);
	
	len = pfs ? iph2->dhgxy->l : 0;
	len += (1
		+ sizeof(u_int32_t)	/* XXX SPI size */
		+ iph2->nonce->l
		+ iph2->nonce_p->l);
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	for (k = iph2->keys; k != NULL; k = k->next) {
		p = buf->v;

		/* if PFS */
		if (pfs) {
			memcpy(p, iph2->dhgxy->v, iph2->dhgxy->l);
			p += iph2->dhgxy->l;
		}

		p[0] = k->proto_id;
		p += 1;

		memcpy(p, (sa_dir == INBOUND_SA ? &k->spi : &k->spi_p),
			sizeof(k->spi));
		p += sizeof(k->spi);

		bp = (side == INITIATOR ? iph2->nonce : iph2->nonce_p);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (side == INITIATOR ? iph2->nonce_p : iph2->nonce);
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		/* compute IV */
		YIPSDEBUG(DEBUG_DKEY,
			plog(logp, LOCATION, NULL, "KEYMAT compute with\n"));
		YIPSDEBUG(DEBUG_DKEY, PVDUMP(buf));

		/* res = K1 */
		res = oakley_prf(iph2->ph1->skeyid_d, buf, iph2->ph1);
		if (res == NULL)
			goto end;

		/* a guess: ESP: 128bit minimum, AH: 160 bit minimum */
		dupkeymat = ((k->len ? k->len : 128) + 160) / 8 / res->l;
		dupkeymat += 2;	/* safety mergin */
		if (dupkeymat < 3)
			dupkeymat = 3;
		YIPSDEBUG(DEBUG_DKEY,
			plog(logp, LOCATION, NULL, "dupkeymat=%d\n", dupkeymat));
		if (0 < --dupkeymat) {
			vchar_t *prev = res;	/* K(n-1) */
			vchar_t *this = NULL;	/* Kn */
			vchar_t *seed = NULL;	/* seed for Kn */
			size_t l;

			/*
			 * generating long key (isakmp-oakley-08 5.5)
			 *	KEYMAT = K1 | K2 | K3 | ...
			 * where
			 *	src = [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b
			 *	K1 = prf(SKEYID_d, src)
			 *	K2 = prf(SKEYID_d, K1 | src)
			 *	K3 = prf(SKEYID_d, K2 | src)
			 *	Kn = prf(SKEYID_d, K(n-1) | src)
			 */
			YIPSDEBUG(DEBUG_DKEY,
				plog(logp, LOCATION, NULL,
					"generating K1...K%d for KEYMAT.\n",
					dupkeymat + 1));

			seed = vmalloc(prev->l + buf->l);
			if (seed == NULL) {
				plog(logp, LOCATION, NULL,
					"vmalloc (%s)\n", strerror(errno));
				goto end;
			}

			while (dupkeymat--) {
				memcpy(seed->v, prev->v, prev->l);
				memcpy(seed->v + prev->l, buf->v, buf->l);
				this = oakley_prf(iph2->ph1->skeyid_d, seed, iph2->ph1);
				if (!this) {
					plog(logp, LOCATION, NULL,
						"oakley_prf memory overflow\n");
					vfree(this);
					vfree(seed);
					goto end;
				}

				l = res->l;
				if (!VREALLOC(res, l + this->l)) {
					perror("vrealloc");
					vfree(this);
					vfree(seed);
					goto end;
				}
				memcpy(res->v + l, this->v, this->l);
				res->l = l + this->l;

				if (prev && prev != res)
					vfree(prev);
				prev = this;
				this = NULL;
			}

			if (prev && prev != res)
				vfree(prev);
			vfree(seed);
		}

		YIPSDEBUG(DEBUG_DKEY, PVDUMP(res));

		if (sa_dir == INBOUND_SA)
			k->keymat = res;
		else
			k->keymat_p = res;
	}

	error = 0;

end:
	if (error) {
		for (k = iph2->keys; k != NULL; k = k->next) {
			if (k->keymat) {
				vfree(k->keymat);
				k->keymat = NULL;
			}
			if (k->keymat_p) {
				vfree(res);
				k->keymat_p = NULL;
			}
		}
	}

	if (buf != NULL)
		vfree(buf);

	return error;
}

#if notyet
/*
 * NOTE: Must terminate by NULL.
 */
vchar_t *
oakley_compute_hashx(struct ph1handle *iph1, ...)
{
	vchar_t *buf, *res;
	vchar_t *s;
	caddr_t p;
	int len;

	va_list ap;

	/* get buffer length */
	va_start(ap, iph1);
	len = 0;
        while ((s = va_arg(ap, char *)) != NULL) {
		len += s->l
        }
	va_end(ap);

	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		return NULL;
	}

	/* set buffer */
	va_start(ap, iph1);
	p = buf->v;
        while ((s = va_arg(ap, char *)) != NULL) {
		memcpy(p, s->v, s->l);
		p += s->l;
	}
	va_end(ap);

	YIPSDEBUG(DEBUG_DKEY, plog(logp, LOCATION, NULL, "HASH with: \n");
		PVDUMP(buf));

	/* compute HASH */
	res = oakley_prf(iph1->skeyid_a, buf, iph1);
	vfree(buf);
	if (res == NULL)
		return NULL;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(res));

	return res;
}
#endif

/*
 * compute HASH(3) prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
 *   see seciton 5.5 Phase 2 - Quick Mode in isakmp-oakley-05.
 */
vchar_t *
oakley_compute_hash3(iph1, msgid, body)
	struct ph1handle *iph1;
	u_int32_t msgid;
	vchar_t *body;
{
	vchar_t *buf = 0, *res = 0;
	int len;
	int error = -1;

	/* create buffer */
	len = 1 + sizeof(u_int32_t) + body->l;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	buf->v[0] = 0;

	memcpy(buf->v + 1, (char *)&msgid, sizeof(msgid));

	memcpy(buf->v + 1 + sizeof(u_int32_t), body->v, body->l);

	YIPSDEBUG(DEBUG_DKEY, plog(logp, LOCATION, NULL, "HASH with: \n");
		PVDUMP(buf));

	/* compute HASH */
	res = oakley_prf(iph1->skeyid_a, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

/*
 * compute HASH type of prf(SKEYID_a, M-ID | buffer)
 *	e.g.
 *	for quick mode HASH(1):
 *		prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr ])
 *	for quick mode HASH(2):
 *		prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr ])
 *	for Informational exchange:
 *		prf(SKEYID_a, M-ID | N/D)
 */
vchar_t *
oakley_compute_hash1(iph1, msgid, body)
	struct ph1handle *iph1;
	u_int32_t msgid;
	vchar_t *body;
{
	vchar_t *buf = NULL, *res = NULL;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = sizeof(u_int32_t) + body->l;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	memcpy(buf->v, (char *)&msgid, sizeof(msgid));
	p += sizeof(u_int32_t);

	memcpy(p, body->v, body->l);

	YIPSDEBUG(DEBUG_DKEY, plog(logp, LOCATION, NULL, "HASH with:\n");
		PVDUMP(buf));

	/* compute HASH */
	res = oakley_prf(iph1->skeyid_a, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

/*
 * compute phase1 HASH
 * main/aggressive
 *   I-digest = prf(SKEYID, g^i | g^r | CKY-I | CKY-R | SAi_b | ID_i1_b)
 *   R-digest = prf(SKEYID, g^r | g^i | CKY-R | CKY-I | SAi_b | ID_r1_b)
 */
vchar_t *
oakley_ph1hash_common(iph1, sw)
	struct ph1handle *iph1;
	int sw;
{
	vchar_t *buf = NULL, *res = NULL, *bp;
	char *p, *bp2;
	int len, bl;
	int error = -1;

	/* create buffer */
	len = iph1->dhpub->l
		+ iph1->dhpub_p->l
		+ sizeof(cookie_t) * 2
		+ iph1->sa->l
		+ (sw == GENERATE ? iph1->id->l : iph1->id_p->l);
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	if (iph1->side == INITIATOR)
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.i_ck : (char *)&iph1->index.r_ck);
	else
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.r_ck : (char *)&iph1->index.i_ck);
	bl = sizeof(cookie_t);
	memcpy(p, bp2, bl);
	p += bl;

	if (iph1->side == INITIATOR)
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.r_ck : (char *)&iph1->index.i_ck);
	else
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.i_ck : (char *)&iph1->index.r_ck);
	bl = sizeof(cookie_t);
	memcpy(p, bp2, bl);
	p += bl;

	bp = iph1->sa;
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->id : iph1->id_p);
	memcpy(p, bp->v, bp->l);

	YIPSDEBUG(DEBUG_DKEY, plog(logp, LOCATION, NULL, "HASH with:\n");
		PVDUMP(buf));

	/* compute HASH */
	res = oakley_prf(iph1->skeyid, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

/*
 * compute HASH_I on base mode.
 * base:psk
 *   HASH_I = prf(SKEYID, g^xi | CKY-I | CKY-R | SAi_b | IDii_b)
 * base:sig
 *   HASH_I = prf(hash(Ni_b | Nr_b), g^xi | CKY-I | CKY-R | SAi_b | IDii_b)
 * base:rsa
 *   HASH_I = prf(SKEYID, g^xi | CKY-I | CKY-R | SAi_b | IDii_b)
 */
vchar_t *
oakley_ph1hash_base_i(iph1, sw)
	struct ph1handle *iph1;
	int sw;
{
	vchar_t *buf = NULL, *res = NULL, *bp;
	char *p;
	int len;
	int error = -1;

	/* sanity check */
	if (iph1->etype != ISAKMP_ETYPE_BASE) {
		YIPSDEBUG(DEBUG_KEY,
			plog(logp, LOCATION, NULL,
				"invalid etype for this hash function\n"));
		return NULL;
	}
	if (iph1->skeyid == NULL) {
		YIPSDEBUG(DEBUG_KEY,
			plog(logp, LOCATION, NULL,
				"no SKEYID found.\n"));
		return NULL;
	}

	/* XXX psk only */
	if (iph1->approval->authmethod != OAKLEY_ATTR_AUTH_METHOD_PSKEY) {
		plog(logp, LOCATION, NULL,
			"not supported authentication method %d\n",
			iph1->approval->authmethod);
		return NULL;
	}

	len = (sw == GENERATE ? iph1->dhpub->l : iph1->dhpub_p->l)
		+ sizeof(cookie_t) * 2
		+ iph1->sa->l
		+ (sw == GENERATE ? iph1->id->l : iph1->id_p->l);
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	memcpy(p, &iph1->index.i_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	memcpy(p, &iph1->index.r_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);

	memcpy(p, iph1->sa->v, iph1->sa->l);
	p += iph1->sa->l;

	bp = (sw == GENERATE ? iph1->id : iph1->id_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH_I with:\n"));
	YIPSDEBUG(DEBUG_KEY, PVDUMP(buf));

	/* compute HASH */
	res = oakley_prf(iph1->skeyid, buf, iph1);
	if (res == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH_I computed:"));
	YIPSDEBUG(DEBUG_KEY, PVDUMP(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

/*
 * compute HASH_R on base mode for signature method.
 * base:
 * HASH_R = prf(hash(Ni_b | Nr_b), g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
 */
vchar_t *
oakley_ph1hash_base_r(iph1, sw)
	struct ph1handle *iph1;
	int sw;
{
	vchar_t *buf = NULL, *res = NULL, *bp;
	vchar_t *hash;
	char *p;
	int len;
	int error = -1;

	/* sanity check */
	if (iph1->etype != ISAKMP_ETYPE_BASE) {
		YIPSDEBUG(DEBUG_KEY,
			plog(logp, LOCATION, NULL,
				"invalid etype for this hash function\n"));
			return NULL;
	}

	/* XXX psk only */
	if (iph1->approval->authmethod != OAKLEY_ATTR_AUTH_METHOD_PSKEY) {
		plog(logp, LOCATION, NULL,
			"not supported authentication method %d\n",
			iph1->approval->authmethod);
		return NULL;
	}

	/* make hash for seed */
	len = iph1->nonce->l + iph1->nonce_p->l;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	bp = (sw == GENERATE ? iph1->nonce_p : iph1->nonce);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->nonce : iph1->nonce_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	hash = oakley_hash(buf, iph1);
	if (hash == NULL)
		goto end;
	vfree(buf);
	buf = NULL;

	/* make really hash */
	len = (sw == GENERATE ? iph1->dhpub_p->l : iph1->dhpub->l)
		+ (sw == GENERATE ? iph1->dhpub->l : iph1->dhpub_p->l)
		+ sizeof(cookie_t) * 2
		+ iph1->sa->l
		+ (sw == GENERATE ? iph1->id_p->l : iph1->id->l);
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;


	bp = (sw == GENERATE ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	memcpy(p, &iph1->index.i_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	memcpy(p, &iph1->index.r_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);

	memcpy(p, iph1->sa->v, iph1->sa->l);
	p += iph1->sa->l;

	bp = (sw == GENERATE ? iph1->id_p : iph1->id);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH with:\n"));
	YIPSDEBUG(DEBUG_KEY, PVDUMP(buf));

	/* compute HASH */
	res = oakley_prf(hash, buf, iph1);
	vfree(hash);
	if (res == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH computed:"));
	YIPSDEBUG(DEBUG_KEY, PVDUMP(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

/*
 * compute each authentication method in phase 1.
 * OUT:
 *	0:	OK
 *	-1:	error
 *	other:	error to be reply with notification.
 *	        the value is notification type.
 */
int
oakley_validate_auth(iph1)
	struct ph1handle *iph1;
{
	switch (iph1->approval->authmethod) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
		/* validate HASH */
	    {
		char *r_hash;
		vchar_t *my_hash = NULL;
		int result;

		if (iph1->id_p == NULL || iph1->pl_hash == NULL) {
			plog(logp, LOCATION, iph1->remote,
				"few isakmp message received.\n");
			return -1;
		}

		r_hash = (caddr_t)(iph1->pl_hash + 1);

		YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "HASH received:"));
		YIPSDEBUG(DEBUG_DKEY,
			hexdump(r_hash,
				ntohs(iph1->pl_hash->h.len)
				- sizeof(*iph1->pl_hash)));

		switch (iph1->etype) {
		case ISAKMP_ETYPE_IDENT:
		case ISAKMP_ETYPE_AGG:
			my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			break;
		case ISAKMP_ETYPE_BASE:
			if (iph1->side == INITIATOR)
				my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			else
				my_hash = oakley_ph1hash_base_i(iph1, VALIDATE);
			break;
		default:
			plog(logp, LOCATION, NULL,
				"invalid etype %d\n", iph1->etype);
			return -1;
		}
		if (my_hash == NULL)
			return -1;

		result = memcmp(my_hash->v, r_hash, my_hash->l);
		vfree(my_hash);

		if (result) {
			plog(logp, LOCATION, NULL, "HASH mismatched\n");
			return ISAKMP_NTYPE_INVALID_HASH_INFORMATION;
		}

		plog(logp, LOCATION, NULL, "HASH for PSK validated.\n");
	    }
		break;
#ifdef HAVE_SIGNING_C
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
	    {
		vchar_t *my_hash = NULL;
		char *signer_name = NULL;
		void *certificate = NULL;
		void *signature = NULL;
		int signature_size = 0;
		int error;

		/* validate SIG & CERT */
		if (iph1->id_p == NULL || iph1->pl_sig == NULL) {
			plog(logp, LOCATION, iph1->remote,
				"few isakmp message received.\n");
			return -1;
		}

		/* MS&I: We validate CERT and SIG, calling cryptlib via
		 * check_certificate and check_signature calls Depending on
		 * the success of this section, the issue must reject the all
		 * packet (goto end;) or proceed.
		 * Possible error to notify:
		 * AKMP_NTYPE_INVALID_SIGNATURE
		 * AKMP_NTYPE_AUTHENTICATION_FAILED
		 * AKMP_NTYPE_INVALID_CERT_AUTHORITY
		 * AKMP_NTYPE_INVALID_CERTIFICATE
		 * AKMP_NTYPE_INVALID_CERT_ENCODING
		 */
		/* Getting back the signer identifier from id payload: */
		signer_name = malloc(iph1->id_p->l-sizeof(u_int32_t)+1);
		if (signer_name == NULL) {
			plog(logp, LOCATION, NULL,
				"malloc (%s)\n", strerror(errno));
			return -1;
		}
		memcpy(signer_name, iph1->id_p->v+(sizeof(u_int32_t)),
			iph1->id_p->l-sizeof(u_int32_t));
		*(signer_name + iph1->id_p->l - sizeof(u_int32_t)) = '\0';

		if (iph1->pl_cert) {
			int certificate_size;
			int error;

			certificate_size = ntohs(iph1->pl_cert->h.len)
				- sizeof(struct isakmp_gen)
				- sizeof(u_int8_t);

			certificate = (void *)
				((caddr_t)&(iph1->pl_cert->encode)
				+ sizeof(u_int8_t));

				error = check_certificate(signer_name,
						certificate,
						certificate_size);
			if (error) {
				plog(logp, LOCATION, NULL, "CERT mismatch.\n");
				return ISAKMP_NTYPE_INVALID_CERTIFICATE;
			}
			plog(logp, LOCATION, NULL,
				"Certificate Authenticated\n");
		}
		/*
		 * When no certificate is sent as a payload, there must be a
		 * local public key certificate to verify the signature, and
		 * this cerificate should be verified by the CA too. So we do.
		 */
		else {
			int size, res;

			if (get_certificate(signer_name, &size, (char **) &certificate)) {
				printf("No local user certificate grabbed "
					"to verify signature: Stop.\n");
				return -1;
			}
			res = check_certificate(signer_name, certificate, size);
			if (certificate) {
				printf("b\n");
				free(certificate);
			}
			if (res != 0) {
				printf("Local user certificate grabbed to "
					"verify signature is not valid! Stop.\n");
				return -1;
			}
		}

		signature = (char *)((void *)iph1->pl_sig + sizeof(struct isakmp_gen));
		signature_size = ntohs(iph1->pl_sig->h.len)
				- sizeof(struct isakmp_gen);
		
		switch (iph1->etype) {
		case ISAKMP_ETYPE_IDENT:
		case ISAKMP_ETYPE_AGG:
			my_hash = oakley_ph1hash_common(iph1, VALIDATE);
			break;
		case ISAKMP_ETYPE_BASE:
			if (iph1->side == INITIATOR)
				my_hash = oakley_ph1hash_base_r(iph1, VALIDATE);
			else
				my_hash = oakley_ph1hash_base_i(iph1, VALIDATE);
			break;
		default:
			plog(logp, LOCATION, NULL,
				"invalid etype %d\n", iph1->etype);
			return -1;
		}
		if (my_hash == NULL)
			return -1;

		error = check_signature((void *)(my_hash->v),
						(int)(my_hash->l),
						signer_name,
						signature,
						signature_size);
		vfree(my_hash);
		if (signer_name)
			free(signer_name);
		if (error) {
			plog(logp, LOCATION, NULL, "SIG mismatch.\n");
			return ISAKMP_NTYPE_INVALID_SIGNATURE;
		}
		plog(logp, LOCATION, NULL, "Signature authenticated\n");
	    }
		break;
#endif
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
		if (iph1->id_p == NULL || iph1->pl_hash == NULL) {
			plog(logp, LOCATION, iph1->remote,
				"few isakmp message received.\n");
			return -1;
		}
		plog(logp, LOCATION, iph1->remote,
			"not supported authmethod type %s\n",
			s_oakley_attr_method(iph1->approval->authmethod));
		return -1;
	default:
		plog(logp, LOCATION, iph1->remote,
			"invalid authmethod %d why ?\n",
			iph1->approval->authmethod);
		return -1;
	}

	return 0;
}

#ifdef HAVE_SIGNING_C
/* get certificate */
int
oakley_getcert(iph1)
	struct ph1handle *iph1;
{
	char *signer;
	char *sig = NULL;
	int signature_size = 0;
	char *certificate = NULL;
	int certificate_size = 0;

	/* signature */
	signer = malloc(iph1->id->l - sizeof(struct ipsecdoi_id_b) + 1);
	if (signer == NULL) {
		plog(logp, LOCATION, NULL, "malloc (%s)\n", strerror(errno));
		return -1;
	}
	memcpy(signer, iph1->id->v + sizeof(struct ipsecdoi_id_b),
		iph1->id->l - sizeof(struct ipsecdoi_id_b));
	signer[iph1->id->l - sizeof(struct ipsecdoi_id_b)] = '\0';

	if (sign((void *)iph1->hash->v,
			iph1->hash->l,
			signer,
			&sig,
			(int *)&signature_size) < 0) {
		printf("Signing error!!! Stop.\n");
		free(signer);
		return -1;
	}

	iph1->sig = vmalloc(signature_size);
	if (iph1->sig == NULL) {
		plog(logp, LOCATION, NULL, "vmalloc (%s)\n", strerror(errno));
		free(signer);
		return -1;
	}
	memcpy(iph1->sig->v, sig, iph1->sig->l);

	/* certificate */
	if (get_certificate(signer,
			(int *)&certificate_size, &certificate)) {
		printf("No local user certificate grabbed: going on "
			"still, no cert payload will be sent.\n");
		return 0;
	}

	/* XXX ???
	 * else there IS a local certificate: we could CA-validate it,
	 * but leave this to the receiver
	 */

	iph1->cert = vmalloc(certificate_size + 1);
	if (iph1->cert == NULL) {
		plog(logp, LOCATION, NULL, "vmalloc (%s)\n", strerror(errno));
		free(signer);
		return -1;
	}

	/* XXX to be configurable ! */
	iph1->cert->v[0] = ISAKMP_CERT_X509SIGN;
	memcpy(iph1->cert->v + 1, certificate, certificate_size);

	return 0;
}
#endif

/*
 * compute SKEYID
 * see seciton 5. Exchanges in RFC 2409
 * psk: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
 * sig: SKEYID = prf(Ni_b | Nr_b, g^ir)
 * enc: SKEYID = prf(H(Ni_b | Nr_b), CKY-I | CKY-R)
 */
int
oakley_skeyid(iph1)
	struct ph1handle *iph1;
{
	vchar_t *buf = NULL, *bp;
	char *p;
	int len;
	int error = -1;

	/* SKEYID */
	switch(iph1->approval->authmethod) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
		if (iph1->etype != ISAKMP_ETYPE_IDENT)
			iph1->authstr = getpsk(iph1->id_p);
		if (iph1->authstr == NULL) {
			/*
			 * If main mode or If failed to get psk by ID,
			 * we try to get it by remote IP address.
			 * It's may be nonsense.
			 */
			iph1->authstr = getpskbyaddr(iph1->remote);
			if (iph1->authstr == NULL) {
				plog(logp, LOCATION, iph1->remote,
					"couldn't find pskey.\n");
				goto end;
			}
		}
		YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "psk found: "));
		YIPSDEBUG(DEBUG_KEY, PVDUMP(iph1->authstr));

		len = iph1->nonce->l + iph1->nonce_p->l;
		buf = vmalloc(len);
		if (buf == NULL) {
			plog(logp, LOCATION, NULL,
				"vmalloc (%s)\n", strerror(errno));
			goto end;
		}
		p = buf->v;

		bp = (iph1->side == INITIATOR ? iph1->nonce : iph1->nonce_p);
		YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "nonce 1: "));
		YIPSDEBUG(DEBUG_KEY, PVDUMP(bp));
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (iph1->side == INITIATOR ? iph1->nonce_p : iph1->nonce);
		YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "nonce 2: "));
		YIPSDEBUG(DEBUG_KEY, PVDUMP(bp));
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		iph1->skeyid = oakley_prf(iph1->authstr, buf, iph1);
		if (iph1->skeyid == NULL)
			goto end;
		break;

	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
		len = iph1->nonce->l + iph1->nonce_p->l;
		buf = vmalloc(len);
		if (buf == NULL) {
			plog(logp, LOCATION, NULL,
				"vmalloc (%s)\n", strerror(errno));
			goto end;
		}
		p = buf->v;

		bp = (iph1->side == INITIATOR ? iph1->nonce : iph1->nonce_p);
		YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "nonce1: "));
		YIPSDEBUG(DEBUG_KEY, PVDUMP(bp));
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (iph1->side == INITIATOR ? iph1->nonce_p : iph1->nonce);
		YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "nonce2: "));
		YIPSDEBUG(DEBUG_KEY, PVDUMP(bp));
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		iph1->skeyid = oakley_prf(buf, iph1->dhgxy, iph1);
		if (iph1->skeyid == NULL)
			goto end;
		break;

		break;
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
		plog(logp, LOCATION, NULL,
			"not supported authentication method %s\n",
			s_oakley_attr_method(iph1->approval->authmethod));
		goto end;
	default:
		plog(logp, LOCATION, NULL,
			"invalid authentication method %d\n",
			iph1->approval->authmethod);
		goto end;
	}

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "SKEYID computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(iph1->skeyid));

	error = 0;

end:
	if (buf != NULL)
		vfree(buf);
	return error;
}

/*
 * compute SKEYID_[dae]
 * see seciton 5. Exchanges in RFC 2409
 * SKEYID_d = prf(SKEYID, g^ir | CKY-I | CKY-R | 0)
 * SKEYID_a = prf(SKEYID, SKEYID_d | g^ir | CKY-I | CKY-R | 1)
 * SKEYID_e = prf(SKEYID, SKEYID_a | g^ir | CKY-I | CKY-R | 2)
 */
int
oakley_skeyid_dae(iph1)
	struct ph1handle *iph1;
{
	vchar_t *buf = NULL;
	char *p;
	int len;
	int error = -1;

	if (iph1->skeyid == NULL) {
		YIPSDEBUG(DEBUG_KEY,
			plog(logp, LOCATION, NULL, "no SKEYID found.\n"));
		goto end;
	}

	/* compute sharing secret of DH */
	if (oakley_dh_compute(iph1->etype == ISAKMP_ETYPE_AGG
					? iph1->rmconf->dhgrp
					: iph1->approval->dhgrp,
				iph1->dhpub,
				iph1->dhpriv, iph1->dhpub_p, &iph1->dhgxy) < 0)
		goto end;

	/* SKEYID D */
	/* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
	len = iph1->dhgxy->l + sizeof(cookie_t) * 2 + 1;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	memcpy(p, iph1->dhgxy->v, iph1->dhgxy->l);
	p += iph1->dhgxy->l;
	memcpy(p, (caddr_t)&iph1->index.i_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	memcpy(p, (caddr_t)&iph1->index.r_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	*p = 0;
	iph1->skeyid_d = oakley_prf(iph1->skeyid, buf, iph1);
	if (iph1->skeyid_d == NULL)
		goto end;

	vfree(buf);
	buf = NULL;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "SKEYID_d computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(iph1->skeyid_d));

	/* SKEYID A */
	/* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
	len = iph1->skeyid_d->l + iph1->dhgxy->l + sizeof(cookie_t) * 2 + 1;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;
	memcpy(p, iph1->skeyid_d->v, iph1->skeyid_d->l);
	p += iph1->skeyid_d->l;
	memcpy(p, iph1->dhgxy->v, iph1->dhgxy->l);
	p += iph1->dhgxy->l;
	memcpy(p, (caddr_t)&iph1->index.i_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	memcpy(p, (caddr_t)&iph1->index.r_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	*p = 1;
	iph1->skeyid_a = oakley_prf(iph1->skeyid, buf, iph1);
	if (iph1->skeyid_a == NULL)
		goto end;

	vfree(buf);
	buf = NULL;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "SKEYID_a computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(iph1->skeyid_a));

	/* SKEYID E */
	/* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
	len = iph1->skeyid_a->l + iph1->dhgxy->l + sizeof(cookie_t) * 2 + 1;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;
	memcpy(p, iph1->skeyid_a->v, iph1->skeyid_a->l);
	p += iph1->skeyid_a->l;
	memcpy(p, iph1->dhgxy->v, iph1->dhgxy->l);
	p += iph1->dhgxy->l;
	memcpy(p, (caddr_t)&iph1->index.i_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	memcpy(p, (caddr_t)&iph1->index.r_ck, sizeof(cookie_t));
	p += sizeof(cookie_t);
	*p = 2;
	iph1->skeyid_e = oakley_prf(iph1->skeyid, buf, iph1);
	if (iph1->skeyid_e == NULL)
		goto end;

	vfree(buf);
	buf = NULL;

	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "SKEYID_e computed: "));
	YIPSDEBUG(DEBUG_DKEY, PVDUMP(iph1->skeyid_e));

	error = 0;

end:
	if (buf != NULL)
		vfree(buf);
	return error;
}

/*
 * compute final encryption key.
 * see Appendix B.
 */
int
oakley_compute_enckey(iph1)
	struct ph1handle *iph1;
{
	u_int keylen, prflen;
	int error = -1;

	/* RFC2409 p39 */
	switch (iph1->approval->enctype) {
	case OAKLEY_ATTR_ENC_ALG_DES:
		keylen = 8;
		break;
	case OAKLEY_ATTR_ENC_ALG_IDEA:
		keylen = 16;
		break;
	case OAKLEY_ATTR_ENC_ALG_BLOWFISH:	/* can negotiate keylen */
		keylen = iph1->approval->encklen
			? (iph1->approval->encklen + 7) / 8 : 56;
		break;
	case OAKLEY_ATTR_ENC_ALG_RC5:		/* can negotiate encklen */
	case OAKLEY_ATTR_ENC_ALG_CAST:		/* can negotiate encklen */
		keylen = iph1->approval->encklen
			? (iph1->approval->encklen + 7) / 8 : 16;
		break;
	case OAKLEY_ATTR_ENC_ALG_3DES:
		keylen = 24;
		break;
	default:
		plog(logp, LOCATION, NULL,
			"encryption algoritym %d isn't supported.\n",
			iph1->approval->enctype);
		goto end;
	}

	switch (iph1->approval->dh_group) {
	default:
		switch (iph1->approval->hashtype) {
		case OAKLEY_ATTR_HASH_ALG_MD5:
			prflen = 16;
			break;
		case OAKLEY_ATTR_HASH_ALG_SHA:
			prflen = 20;
			break;
		default:
			plog(logp, LOCATION, NULL,
				"hash type %d isn't supported.\n",
				iph1->approval->hashtype);
			return 0;
			break;
		}
	}

	iph1->key = vmalloc(keylen);
	if (iph1->key == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* see isakmp-oakley-08 5.3. */
	if (iph1->key->l <= iph1->skeyid_e->l) {
		/*
		 * if length(Ka) <= length(SKEYID_e)
		 *	Ka = first length(K) bit of SKEYID_e
		 */
		memcpy(iph1->key->v, iph1->skeyid_e->v, iph1->key->l);
	} else {
		vchar_t *buf = NULL, *res = NULL;
		u_char *p, *ep;
		int cplen;
		int subkey;

		/*
		 * otherwise,
		 *	Ka = K1 | K2 | K3
		 * where
		 *	K1 = prf(SKEYID_e, 0)
		 *	K2 = prf(SKEYID_e, K1)
		 *	K3 = prf(SKEYID_e, K2)
		 */
		YIPSDEBUG(DEBUG_CRYPT,
			plog(logp, LOCATION, NULL,
				"len(SKEYID_e) < len(Ka) (%d < %d), "
				"generating long key (Ka = K1 | K2 | ...)\n",
				iph1->skeyid_e->l, iph1->key->l));

		if ((buf = vmalloc(prflen)) == 0) {
			plog(logp, LOCATION, NULL,
				"vmalloc (%s)\n", strerror(errno));
			goto end;
		}
		p = (u_char *)iph1->key->v;
		ep = p + iph1->key->l;

		subkey = 1;
		while (p < ep) {
			if (p == (u_char *)iph1->key->v) {
				/* just for computing K1 */
				buf->v[0] = 0;
				buf->l = 1;
			}
			res = oakley_prf(iph1->skeyid_e, buf, iph1);
			if (res == NULL) {
				vfree(buf);
				goto end;
			}
			YIPSDEBUG(DEBUG_CRYPT,
				plog(logp, LOCATION, NULL,
					"compute intermediate cipher key K%d\n",
					subkey));
			YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(buf));
			YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(res));

			cplen = (res->l < ep - p) ? res->l : ep - p;
			memcpy(p, res->v, cplen);
			p += cplen;

			buf->l = prflen;	/* to cancel K1 speciality */
			if (res->l != buf->l) {
				plog(logp, LOCATION, NULL,
					"internal error: res->l=%d buf->l=%d\n",
					res->l, buf->l);
				vfree(res);
				vfree(buf);
				goto end;
			}
			memcpy(buf->v, res->v, res->l);
			vfree(res);
			subkey++;
		}

		vfree(buf);
	}

	/* weakkey check */
	if (iph1->approval->enctype > ARRAYLEN(cipher))
		goto end;
	if (cipher[iph1->approval->enctype].weakkey == NULL
	 && (cipher[iph1->approval->enctype].weakkey)(iph1->key)) {
		plog(logp, LOCATION, NULL,
			"weakkey was generated.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL, "final cipher key computed: "));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(iph1->key));

	error = 0;

end:
	return error;
}

/*
 * compute IV and set to ph1handle
 *	IV = hash(g^xi | g^xr)
 * see 4.1 Phase 1 state in draft-ietf-ipsec-ike.
 */
int
oakley_newiv(iph1)
	struct ph1handle *iph1;
{
	struct isakmp_ivm *newivm = NULL;
	vchar_t *buf = NULL, *bp;
	char *p;
	int len;

	/* create buffer */
	len = iph1->dhpub->l + iph1->dhpub_p->l;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		return -1;
	}

	p = buf->v;

	bp = (iph1->side == INITIATOR ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (iph1->side == INITIATOR ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	/* allocate IVm */
	newivm = CALLOC(sizeof(struct isakmp_ivm), struct isakmp_ivm *);
	if (newivm == NULL) {
		plog(logp, LOCATION, NULL,
			"calloc (%s)\n", strerror(errno)); 
		vfree(buf);
		return -1;
	}

	/* compute IV */
	newivm->iv = oakley_hash(buf, iph1);
	if (newivm->iv == NULL) {
		vfree(buf);
		oakley_delivm(newivm);
		return -1;
	}

	/* adjust length of iv */
	newivm->iv->l = CBC_BLOCKLEN;

	/* create buffer to save iv */
	if ((newivm->ive = vdup(newivm->iv)) == NULL
	 || (newivm->ivd = vdup(newivm->iv)) == NULL) {
		plog(logp, LOCATION, NULL,
			"vdup (%s)\n", strerror(errno));
		vfree(buf);
		oakley_delivm(newivm);
		return -1;
	}

	vfree(buf);

	YIPSDEBUG(DEBUG_CRYPT, plog(logp, LOCATION, NULL, "IV computed: "));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(newivm->iv));

	iph1->ivm = newivm;

	return 0;
}

/*
 * compute IV for the payload after phase 1.
 * It's not limited for phase 2.
 * if pahse 1 was encrypted.
 *	IV = hash(last CBC block of Phase 1 | M-ID)
 * if phase 1 was not encrypted.
 *	IV = hash(phase 1 IV | M-ID)
 * see 4.2 Phase 2 state in draft-ietf-ipsec-ike.
 */
struct isakmp_ivm *
oakley_newiv2(iph1, msgid)
	struct ph1handle *iph1;
	u_int32_t msgid;
{
	struct isakmp_ivm *newivm = NULL;
	vchar_t *buf = NULL;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = iph1->ivm->iv->l + sizeof(msgid_t);
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	memcpy(p, iph1->ivm->iv->v, iph1->ivm->iv->l);
	p += iph1->ivm->iv->l;

	memcpy(p, &msgid, sizeof(msgid));

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL, "compute IV for phase2\n"));
	YIPSDEBUG(DEBUG_CRYPT, plog(logp, LOCATION, NULL, "phase1 last IV: "));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(buf));

	/* allocate IVm */
	newivm = CALLOC(sizeof(struct isakmp_ivm), struct isakmp_ivm *);
	if (newivm == NULL) {
		plog(logp, LOCATION, NULL, "calloc (%s)\n", strerror(errno)); 
		goto end;
	}

	/* compute IV */
	if ((newivm->iv = oakley_hash(buf, iph1)) == NULL)
		goto end;

	/* create buffer to save new iv */
	if ((newivm->ive = vdup(newivm->iv)) == NULL
	 || (newivm->ivd = vdup(newivm->iv)) == NULL) {
		plog(logp, LOCATION, NULL, "vdup (%s)\n", strerror(errno));
		goto end;
	}

	error = 0;

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL, "phase2 IV computed: "));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(newivm->iv));

end:
	if (error && newivm != NULL)
		oakley_delivm(newivm);
	if (buf != NULL)
		vfree(buf);
	return newivm;
}

void
oakley_delivm(ivm)
	struct isakmp_ivm *ivm;
{
	if (ivm == NULL)
		return;

	if (ivm->iv != NULL)
		free(ivm->iv);
	if (ivm->ive != NULL)
		free(ivm->ive);
	if (ivm->ivd != NULL)
		free(ivm->ivd);
	free(ivm);

	return;
}

/*
 * decrypt packet.
 *   save new iv and old iv.
 */
vchar_t *
oakley_do_decrypt(iph1, msg, ivdp, ivep)
	struct ph1handle *iph1;
	vchar_t *msg, *ivdp, *ivep;
{
	vchar_t *buf = NULL, *new = NULL;
	char *pl;
	int len;
	u_int8_t padlen;
	int error = -1;

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"begin decryption.\n"));

	/* save IV for next, but not sync. */
	memset(ivep->v, 0, ivep->l);
	memcpy(ivep->v, (caddr_t)&msg->v[msg->l - CBC_BLOCKLEN], CBC_BLOCKLEN);

	YIPSDEBUG(DEBUG_CRYPT, plog(logp, LOCATION, NULL, "IV saved: "));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(ivep));
	YIPSDEBUG(DEBUG_CRYPT, plog(logp, LOCATION, NULL, "IV not sync yet\n"));

	pl = msg->v + sizeof(struct isakmp);

	len = msg->l - sizeof(struct isakmp);

	/* create buffer */
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, pl, len);

	/* do decrypt */
	if (iph1->approval->enctype > ARRAYLEN(cipher)
	 && cipher[iph1->approval->enctype].decrypt == NULL) {
		plog(logp, LOCATION, NULL,
			"invalid cipher algoriym was passed.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"decrypt(%s)\n",
			cipher[iph1->approval->enctype].name));
	YIPSDEBUG(DEBUG_DCRYPT,
		plog(logp, LOCATION, NULL,
			"with key: ");
		PVDUMP(iph1->key));

	new = (cipher[iph1->approval->enctype].decrypt)(buf, iph1->key, ivdp->v);
	vfree(buf);
	buf = NULL;
	if (new == NULL)
		goto end;

	YIPSDEBUG(DEBUG_DCRYPT,
		plog(logp, LOCATION, NULL,
			"decrypted payload by IV: ");
		PVDUMP(ivdp));

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"decrypted payload, but not trimed.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(new));

	/* get padding length */
	if (lcconf->pad_excltail)
		padlen = new->v[new->l - 1] + 1;
	else
		padlen = new->v[new->l - 1];
	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"padding len=%u\n", padlen));

	/* trim padding */
	if (lcconf->pad_restrict) {
		if (padlen > new->l) {
			plog(logp, LOCATION, NULL,
				"invalied padding len=%u, buflen=%u.\n",
				padlen, new->l);
			YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(new));
			goto end;
		}
		new->l -= padlen;
		YIPSDEBUG(DEBUG_CRYPT,
			plog(logp, LOCATION, NULL,
				"trimmed padding\n"));
	} else {
		YIPSDEBUG(DEBUG_CRYPT,
			plog(logp, LOCATION, NULL,
				"skip to trim padding.\n"));
		;
	}

	/* create new buffer */
	len = sizeof(struct isakmp) + new->l;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, msg->v, sizeof(struct isakmp));
	memcpy(buf->v + sizeof(struct isakmp), new->v, new->l);
	((struct isakmp *)buf->v)->len = htonl(buf->l);

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"decrypted.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(buf));

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->remote, iph1->local, 1);
#endif

	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}
	if (new != NULL)
		vfree(new);

	return buf;
}

/*
 * encrypt packet.
 */
vchar_t *
oakley_do_encrypt(iph1, msg, ivep, ivp)
	struct ph1handle *iph1;
	vchar_t *msg, *ivep, *ivp;
{
	vchar_t *buf = 0, *new = 0;
	char *pl;
	int len;
	u_int padlen;
	int error = -1;

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(logp, LOCATION, NULL, "begin encryption.\n"));

	pl = msg->v + sizeof(struct isakmp);
	len = msg->l - sizeof(struct isakmp);

	/* add padding */
	padlen = oakley_padlen(len);
	YIPSDEBUG(DEBUG_CRYPT,
	    plog(logp, LOCATION, NULL, "pad length = %u\n", padlen));

	/* create buffer */
	buf = vmalloc(len + padlen);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
        if (padlen) {
                int i;
		char *p = &buf->v[len];
                for (i = 0; i < padlen; i++)
                        *p++ = (char)random();
        }
        memcpy(buf->v, pl, len);

	/* make pad into tail */
	if (lcconf->pad_excltail)
		buf->v[len + padlen - 1] = padlen - 1;
	else
		buf->v[len + padlen - 1] = padlen;

	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(buf));

	/* do encrypt */
	if (iph1->approval->enctype > ARRAYLEN(cipher)
	 && cipher[iph1->approval->enctype].encrypt == NULL) {
		plog(logp, LOCATION, NULL,
			"invalid cipher algoriym was passed.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"encrypt(%s).\n",
			cipher[iph1->approval->enctype].name));
	YIPSDEBUG(DEBUG_DCRYPT,
		plog(logp, LOCATION, NULL,
			"with key: ");
		PVDUMP(iph1->key));

	new = (cipher[iph1->approval->enctype].encrypt)(buf, iph1->key, ivep->v);
	vfree(buf);
	buf = NULL;
	if (new == NULL)
		goto end;

	YIPSDEBUG(DEBUG_DCRYPT,
		plog(logp, LOCATION, NULL,
			"encrypted payload by IV: ");
		PVDUMP(ivep));

	/* save IV for next */
	memset(ivp->v, 0, ivp->l);
	memcpy(ivp->v, (caddr_t)&new->v[new->l - CBC_BLOCKLEN], CBC_BLOCKLEN);

	YIPSDEBUG(DEBUG_CRYPT, plog(logp, LOCATION, NULL, "save IV for next: "));
	YIPSDEBUG(DEBUG_DCRYPT, PVDUMP(ivp));

	/* create new buffer */
	len = sizeof(struct isakmp) + new->l;
	buf = vmalloc(len);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, msg->v, sizeof(struct isakmp));
	memcpy(buf->v + sizeof(struct isakmp), new->v, new->l);
	((struct isakmp *)buf->v)->len = htonl(buf->l);

	error = 0;

	YIPSDEBUG(DEBUG_CRYPT,
		plog(logp, LOCATION, NULL,
			"encrypted.\n"));

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}
	if (new != NULL)
		vfree(new);

	return buf;
}

/* culculate padding length */
int
oakley_padlen(len)
	int len;
{
	int padlen;
	int base = CBC_BLOCKLEN;

	padlen = 8 - len % 8;

	if (lcconf->pad_random)
		padlen += ((random() % (lcconf->pad_maxsize + 1) + 1) * base);

	return padlen;
}

