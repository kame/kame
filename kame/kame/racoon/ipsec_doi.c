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
/* YIPS @(#)$Id: ipsec_doi.c,v 1.4 1999/12/01 11:16:55 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netkey/keyv2.h>
#include <netkey/key_var.h>

#include <netinet/in.h>
#if INET6 && !defined(IPV6_INRIA_VERSION)
#include <netinet6/in6.h>
#endif

#ifdef IPV6_INRIA_VERSION
#include <netinet/ipsec.h>
#else
#include <netinet6/ipsec.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "var.h"
#include "vmbuf.h"
#include "cfparse.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "handler.h"
#include "misc.h"
#include "debug.h"
#include "isakmp_var.h"

struct prop_pair {
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct prop_pair *next;
};

#if 0
static int isakmp_port_type = 0;
#endif

#if 0
static int isakmp_max_sas = 3;
static int isakmp_max_proposals = 40;
static int isakmp_max_transforms = 40;
#endif

static vchar_t *get_newsabyprop __P((struct ipsecdoi_sa *, int));
static struct isakmp_pl_t *get_transform __P((struct isakmp_pl_p *));
static int check_doi __P((u_int32_t));
static int check_situation __P((u_int32_t));

static int check_prot_main __P((int));
static int check_prot_quick __P((int));
static int (*check_protocol[]) __P((int)) = {
	check_prot_main,	/* OAKLEY_MAIN_MODE */
	check_prot_quick,	/* OAKLEY_QUICK_MODE */
	check_prot_main,	/* OAKLEY_NEWGROUP_MODE */
};

static int check_spi_size __P((int, int));

static int check_trns_isakmp __P((int));
static int check_trns_ah __P((int));
static int check_trns_esp __P((int));
static int check_trns_ipcomp __P((int));
static int (*check_transform[]) __P((int)) = {
	0,
	check_trns_isakmp,	/* IPSECDOI_PROTO_ISAKMP */
	check_trns_ah,		/* IPSECDOI_PROTO_IPSEC_AH */
	check_trns_esp,		/* IPSECDOI_PROTO_IPSEC_ESP */
	check_trns_ipcomp,	/* IPSECDOI_PROTO_IPCOMP */
};

static int check_attr_isakmp __P((struct isakmp_pl_t *));
static int check_attr_ah __P((struct isakmp_pl_t *));
static int check_attr_esp __P((struct isakmp_pl_t *));
static int check_attr_ipsec __P((int, struct isakmp_pl_t *));
static int check_attr_ipcomp __P((struct isakmp_pl_t *));
static int (*check_attributes[]) __P((struct isakmp_pl_t *)) = {
	0,
	check_attr_isakmp,	/* IPSECDOI_PROTO_ISAKMP */
	check_attr_ah,		/* IPSECDOI_PROTO_IPSEC_AH */
	check_attr_esp,		/* IPSECDOI_PROTO_IPSEC_ESP */
	check_attr_ipcomp,	/* IPSECDOI_PROTO_IPCOMP */
};

static int get_attr_ipsec __P((caddr_t, struct ipsec_sa *, int));
static int get_attr_isakmp __P((caddr_t, struct oakley_sa *, int));
static u_int32_t ipsecdoi_set_ld __P((int type, vchar_t *));

/*
 * check SA payload.
 * and make new SA payload for use.
 * IN:	sap	: the pointer to SA payload. network byte order.
 *	mode	: OAKLEY_MAIN_MODE or OAKLEY_QUICK_MODE.
 * OUT:
 *	positive: the pointer to new buffer of SA payload.
 *		  network byte order.
 *	NULL	: error occurd.
 */
vchar_t *
ipsecdoi_get_proposal(sa, mode)
	struct ipsecdoi_sa *sa;
	int mode;
{
	vchar_t *newsa; /* new SA payload for use */
	int tlen;

	tlen = ntohs(sa->h.len);

	YIPSDEBUG(DEBUG_SA,
		plog(LOCATION, "total SA len=%d\n", tlen));
	YIPSDEBUG(DEBUG_DSA, pdump((caddr_t)sa, tlen, YDUMP_HEX));
#if 0
	YIPSDEBUG(DEBUG_DSA, ipsecdoi_debug_sa(sa));
#endif

	/* check DOI */
	if (check_doi(ntohl(sa->b.doi)) < 0)
		return NULL;

	/* check SITUATION */
	if (check_situation(ntohl(sa->b.sit)) < 0)
		return NULL;

	/* check and get proposal for use */
	if ((newsa = get_newsabyprop(sa, mode)) == NULL)
		return NULL;

	return newsa;
}

/*
 * check proposal payload and make new SA payload for use.
 */
static vchar_t *
get_newsabyprop(sa, mode)
	struct ipsecdoi_sa *sa;
	int mode;
{
	vchar_t *newsa = NULL; /* new SA payload for use */
	struct prop_pair *pair[256];
	int num_p = 0; /* number of proposal for use */
	int tlen;
	caddr_t bp;
	struct prop_pair *p, *q;
	int i;

	memset(pair, 0, sizeof(pair));

	bp = (caddr_t)sa + sizeof(struct ipsecdoi_sa);
	tlen = ntohs(sa->h.len) - sizeof(struct ipsecdoi_sa);

	if (tlen <= 0) {
		plog(LOCATION,
			"Invalid total SA len=%d.\n", tlen);
		goto err;
	}

    {
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	int proplen;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	pbuf = isakmp_parse0(ISAKMP_NPTYPE_P, (struct isakmp_gen *)bp, tlen);

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {
		/* check the value of next payload */
		if (pa->type != ISAKMP_NPTYPE_P) {
			plog(LOCATION, "Invalid payload type=%u\n", pa->type);
			goto err;
		}

		prop = (struct isakmp_pl_p *)pa->ptr;
		proplen = pa->len;

		YIPSDEBUG(DEBUG_SA,
			plog(LOCATION,
				"proposal #%u len=%d\n", prop->p_no, proplen));

		if (proplen == 0) {
			plog(LOCATION,
				"invalid proposal with length %d\n", proplen);
			goto err;
		}

		/* check Protocol ID */
		if (!check_protocol[mode]) {
			plog(LOCATION, "unsupported mode %d\n", mode);
			continue;
		}

		if (check_protocol[mode](prop->proto_id) < 0)
			continue;

		/* check SPI length when IKE. */
		if (check_spi_size(prop->proto_id, prop->spi_size) < 0)
			continue;

		/* check the number of transform */
		if (prop->num_t == 0) {
			plog(LOCATION,
				"Illegal the number of transform. num_t=%u\n",
				prop->num_t);
			continue;
		}

		/* get valid transform */
		trns = get_transform(prop);

		/* check for duplicated protocol id */
		for (p = pair[prop->p_no]; p; p = p->next) {
			if (p->prop->proto_id == prop->proto_id) {
				trns = NULL;
				break;
			}
		}

		if ((p = CALLOC(sizeof(*p), struct prop_pair *)) == NULL) {
			plog(LOCATION,
				"calloc (%s)\n", strerror(errno));
			goto err;
		}
		p->prop = prop;
		p->trns = trns;

		/* need to preserve the order */
		for (q = pair[prop->p_no]; q && q->next; q = q->next)
			;
		if (q)
			q->next = p;
		else {
			pair[prop->p_no] = p;
			num_p++;
		}
	}
	vfree(pbuf);
	pbuf = NULL;
    }

    {
	int notrans, nprop;
	struct prop_pair *q;

	/* check for proposals with no transforms */
	for (i = 0; i < sizeof(pair)/sizeof(pair[0]); i++) {
		if (!pair[i])
			continue;

		notrans = nprop = 0;
		for (p = pair[i]; p; p = p->next) {
			if (p->trns == NULL) {
				notrans++;
				break;
			}
			nprop++;
		}

		/*
		 * XXX at this moment, we cannot accept proposal group
		 * with multiple proposals.  this should be fixed.
		 */
		if (pair[i]->next) {
			plog(LOCATION,
				"proposal #%u ignored (multiple proposal not supported)\n",
				pair[i]->prop->p_no);
			notrans++;
		}

		if (notrans) {
			for (p = pair[i]; p; p = q) {
				q = p->next;
				free(p);
			}
			pair[i] = NULL;
			num_p--;
		} else {
			YIPSDEBUG(DEBUG_MISC,
				plog(LOCATION, "proposal #%u: %d proposals\n",
					pair[i]->prop->p_no, nprop));
		}
	}
    }

	/* bark if no proposal is found. */
	if (num_p <= 0) {
		plog(LOCATION, "no Proposal found.\n");
		goto err;
	}

    {
	int newtlen;
	u_int8_t *np_p = NULL;
	int prophlen, trnslen;

	/* XXX we blindly pick the first proposal group. */
	q = NULL;
	for (i = 0; i < sizeof(pair)/sizeof(pair[0]); i++) {
		if (pair[i]) {
			q = pair[i];
			break;
		}
	}
	if (!q) {
		YIPSDEBUG(DEBUG_MISC, plog(LOCATION, "no proposal found. why?\n")); 
		goto err;
	}

	newtlen = sizeof(struct isakmp_pl_sa);
	for (p = q; p; p = p->next) {
		newtlen += (sizeof(struct isakmp_pl_p) + p->prop->spi_size
				+ ntohs(p->trns->h.len));
	}

	if ((newsa = vmalloc(newtlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno)); 
		goto err;
	}
	bp = newsa->v;

	/* create SA payload */
	memcpy(bp, sa, sizeof(struct isakmp_pl_sa));
	((struct isakmp_gen *)bp)->len = htons(newtlen);
	bp += sizeof(struct isakmp_pl_sa);

	/* create proposal payloads */
	for (p = q; p; p = p->next) {
		prophlen = sizeof(struct isakmp_pl_p)
				+ p->prop->spi_size;
		trnslen = ntohs(p->trns->h.len);

		if (np_p)
			*np_p = ISAKMP_NPTYPE_P;

		/* create proposal */

		memcpy(bp, p->prop, prophlen);
		((struct isakmp_pl_p *)bp)->h.np = ISAKMP_NPTYPE_NONE;
		((struct isakmp_pl_p *)bp)->h.len = htons(prophlen + trnslen);
		((struct isakmp_pl_p *)bp)->num_t = 1;
		np_p = &((struct isakmp_pl_p *)bp)->h.np;
		bp += prophlen;

		/* create transform */
		memcpy(bp, p->trns, trnslen);
		((struct isakmp_pl_t *)bp)->h.np = ISAKMP_NPTYPE_NONE;
		((struct isakmp_pl_t *)bp)->h.len = htons(trnslen);
		bp += trnslen;
	}
    }

end:
	for (i = 0; i < sizeof(pair)/sizeof(pair[0]); i++) {
		for (p = pair[i]; p; p = q) {
			q = p->next;
			free(p);
		}
		pair[i] = NULL;
	}
	return newsa;

err:
	if (newsa != NULL)
		vfree(newsa);
	newsa = NULL;
	goto end;
}

/*
 * check transform payload.
 * OUT:
 *	positive: return the pointer to the payload of valid transform.
 *	0	: No valid transform found.
 */
static struct isakmp_pl_t *
get_transform(prop)
	struct isakmp_pl_p *prop;
{
	struct isakmp_pl_t *trns_ok = NULL; /* valid transform payload */
	int tlen; /* total length of all transform in a proposal */
	caddr_t bp;
	struct isakmp_pl_t *trns;
	int trnslen;
	vchar_t *pbuf;
	struct isakmp_parse_t *pa;

	bp = (caddr_t)prop + sizeof(struct isakmp_pl_p) + prop->spi_size;
	tlen = ntohs(prop->h.len)
		- (sizeof(struct isakmp_pl_p) + prop->spi_size);
	pbuf = isakmp_parse0(ISAKMP_NPTYPE_T, (struct isakmp_gen *)bp, tlen);

	/* check and get transform for use */
	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {
		/* check the value of next payload */
		if (pa->type != ISAKMP_NPTYPE_T) {
			plog(LOCATION, "Invalid payload type=%u\n", pa->type);
			break;
		}

		trns = (struct isakmp_pl_t *)pa->ptr;
		trnslen = pa->len;

		YIPSDEBUG(DEBUG_SA,
			plog(LOCATION,
				"transform #%u len=%u\n", trns->t_no, trnslen));

		/* check transform ID */
		if (prop->proto_id >= sizeof(check_transform)/sizeof(check_transform[0])) {
			plog(LOCATION,
				"unsupported proto_id %u\n", prop->proto_id);
			continue;
		}
		if (prop->proto_id >= sizeof(check_attributes)/sizeof(check_attributes[0])) {
			plog(LOCATION,
				"unsupported proto_id %u\n", prop->proto_id);
			continue;
		}

		if (!check_transform[prop->proto_id]
		 || !check_attributes[prop->proto_id]) {
			plog(LOCATION,
				"unsupported proto_id %u\n", prop->proto_id);
			continue;
		}
		if (check_transform[prop->proto_id](trns->t_id) < 0)
			continue;

		/* check data attributes */
		if (check_attributes[prop->proto_id](trns) == 0) {
			/* OK. Valid transform found. */
			trns_ok = trns;
			break;
		}
	}

	vfree(pbuf);
	if (trns_ok == NULL) {
		YIPSDEBUG(DEBUG_SA,
			plog(LOCATION,
				"no acceptable transform found.\n"));
	}
	return trns_ok;
}

/*
 * check DOI
 */
static int
check_doi(doi)
	u_int32_t doi;
{
	switch (doi) {
	case IPSEC_DOI:
		return 0;
	default:
		plog(LOCATION,
			"invalid value of DOI 0x%08x.\n", doi);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check situation
 */
static int
check_situation(sit)
	u_int32_t sit;
{
	switch (sit) {
	case IPSECDOI_SIT_IDENTITY_ONLY:
		return 0;

	case IPSECDOI_SIT_SECRECY:
	case IPSECDOI_SIT_INTEGRITY:
		plog(LOCATION,
			"situation 0x%08x unsupported yet.\n", sit);
		return -1;

	default:
		plog(LOCATION,
			"invalid situation 0x%08x.\n", sit);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check protocol id in main mode
 */
static int
check_prot_main(proto_id)
	int proto_id;
{
	switch (proto_id) {
	case IPSECDOI_PROTO_ISAKMP:
		return 0;

	default:
		plog(LOCATION,
			"Illegal protocol id=%u.\n", proto_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check protocol id in quick mode
 */
static int
check_prot_quick(proto_id)
	int proto_id;
{
	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_AH:
	case IPSECDOI_PROTO_IPSEC_ESP:
		return 0;

	case IPSECDOI_PROTO_IPCOMP:
		return 0;

	default:
		plog(LOCATION,
			"invalid protocol id %d.\n", proto_id);
		return -1;
	}
	/* NOT REACHED */
}

static int
check_spi_size(proto_id, size)
	int proto_id, size;
{
	switch (proto_id) {
	case IPSECDOI_PROTO_ISAKMP:
		if (size != 0) {
			/* WARNING */
			plog(LOCATION,
				"SPI size isn't zero, but IKE proposal.\n");
		}
		return 0;

	case IPSECDOI_PROTO_IPSEC_AH:
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (size != 4) {
			plog(LOCATION,
				"invalid SPI size=%d for IPSEC proposal.\n",
				size);
			return -1;
		}
		return 0;

	case IPSECDOI_PROTO_IPCOMP:
		if (size != 4) {
			plog(LOCATION,
				"invalid SPI size=%d for IPCOMP proposal.\n",
				size);
			return -1;
		}
		return 0;

	default:
		/* ??? */
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in ISAKMP.
 */
static int
check_trns_isakmp(t_id)
	int t_id;
{
	switch (t_id) {
	case IPSECDOI_KEY_IKE:
		return 0;
	default:
		plog(LOCATION,
			"invalid transform-id=%u in proto_id=%u.\n",
			t_id, IPSECDOI_KEY_IKE);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in AH.
 */
static int
check_trns_ah(t_id)
	int t_id;
{
	switch (t_id) {
	case IPSECDOI_AH_MD5:
	case IPSECDOI_AH_SHA:
		return 0;
	case IPSECDOI_AH_DES:
		plog(LOCATION,
			"not support transform-id=%u in AH.\n", t_id);
		return -1;
	default:
		plog(LOCATION,
			"invalid transform-id=%u in AH.\n", t_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in ESP.
 */
static int
check_trns_esp(t_id)
	int t_id;
{
	switch (t_id) {
	case IPSECDOI_ESP_DES:
	case IPSECDOI_ESP_3DES:
	case IPSECDOI_ESP_NULL:
		return 0;
	case IPSECDOI_ESP_DES_IV32:
	case IPSECDOI_ESP_DES_IV64:
	case IPSECDOI_ESP_RC5:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_CAST:
	case IPSECDOI_ESP_BLOWFISH:
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_RC4:
		plog(LOCATION,
			"not support transform-id=%u in ESP.\n", t_id);
		return -1;
	default:
		plog(LOCATION,
			"invalid transform-id=%u in ESP.\n", t_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check transform ID in IPCOMP.
 */
static int
check_trns_ipcomp(t_id)
	int t_id;
{
	switch (t_id) {
	case IPSECDOI_IPCOMP_OUI:
	case IPSECDOI_IPCOMP_DEFLATE:
	case IPSECDOI_IPCOMP_LZS:
		return 0;
	default:
		plog(LOCATION,
			"invalid transform-id=%u in IPCOMP.\n", t_id);
		return -1;
	}
	/* NOT REACHED */
}

/*
 * check data attributes in IKE.
 */
static int
check_attr_isakmp(trns)
	struct isakmp_pl_t *trns;
{
	struct isakmp_data *d;
	int tlen;
	int flag, type, lorv;

	tlen = ntohs(trns->h.len) - sizeof(struct isakmp_pl_t);
	d = (struct isakmp_data *)((caddr_t)trns + sizeof(struct isakmp_pl_t));

	while (tlen > 0) {
		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		YIPSDEBUG(DEBUG_DSA,
			plog(LOCATION,
				"type=%d, flag=0x%04x, lorv=0x%04x\n",
				type, flag, lorv));

		/*
		 * some of the attributes must be encoded in TV.
		 * see RFC2409 Appendix A "Attribute Classes".
		 */
		switch (type) {
		case OAKLEY_ATTR_ENC_ALG:
		case OAKLEY_ATTR_HASH_ALG:
		case OAKLEY_ATTR_AUTH_METHOD:
		case OAKLEY_ATTR_GRP_DESC:
		case OAKLEY_ATTR_GRP_TYPE:
		case OAKLEY_ATTR_SA_LD_TYPE:
		case OAKLEY_ATTR_PRF:
		case OAKLEY_ATTR_KEY_LEN:
		case OAKLEY_ATTR_FIELD_SIZE:
			if (!flag) {	/* TLV*/
				plog(LOCATION, "oakley attribute %d must be TV.\n",
					type);
				return -1;
			}
			break;
		}

		/* sanity check for TLV.  length must be specified. */
		if (!flag && lorv == 0) {	/*TLV*/
			plog(LOCATION,
				"invalid length %d for TLV attribute %d.\n",
				lorv, type);
			return -1;
		}

		switch (type) {
		case OAKLEY_ATTR_ENC_ALG:
			switch (lorv) {
			case OAKLEY_ATTR_ENC_ALG_DES:
			case OAKLEY_ATTR_ENC_ALG_3DES:
			case OAKLEY_ATTR_ENC_ALG_IDEA:
			case OAKLEY_ATTR_ENC_ALG_BLOWFISH:
			case OAKLEY_ATTR_ENC_ALG_RC5:
			case OAKLEY_ATTR_ENC_ALG_CAST:
				break;
			default:
				plog(LOCATION,
					"invalied enc algorithm=%d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_HASH_ALG:
			switch (lorv) {
			case OAKLEY_ATTR_HASH_ALG_MD5:
			case OAKLEY_ATTR_HASH_ALG_SHA:
				break;
			case OAKLEY_ATTR_HASH_ALG_TIGER:
				plog(LOCATION,
					"hash algorithm %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LOCATION,
					"invalid hash algorithm %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_AUTH_METHOD:
			switch (lorv) {
			case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
				break;
			case OAKLEY_ATTR_AUTH_METHOD_DSS:
			case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
			case OAKLEY_ATTR_AUTH_METHOD_RSA:
			case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
				plog(LOCATION,
					"auth method %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LOCATION,
					"invalid auth method %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_GRP_DESC:
			switch (lorv) {
			case OAKLEY_ATTR_GRP_DESC_MODP768:
			case OAKLEY_ATTR_GRP_DESC_MODP1024:
			case OAKLEY_ATTR_GRP_DESC_MODP1536:
				break;
			case OAKLEY_ATTR_GRP_DESC_EC2N155:
			case OAKLEY_ATTR_GRP_DESC_EC2N185:
				plog(LOCATION,
					"DH group %d isn't supported.\n",
					lorv);
				return -1;
			default:
				if (lorv >= 32768)	/*private group*/
					break;
				plog(LOCATION,
					"invalid DH group %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_GRP_TYPE:
			switch (lorv) {
			case OAKLEY_ATTR_GRP_TYPE_MODP:
				break;
			default:
				plog(LOCATION,
					"unsupported DH group type %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_GRP_PI:
		case OAKLEY_ATTR_GRP_GEN_ONE:
			/* sanity checks? */
			break;

		case OAKLEY_ATTR_GRP_GEN_TWO:
		case OAKLEY_ATTR_GRP_CURVE_A:
		case OAKLEY_ATTR_GRP_CURVE_B:
			plog(LOCATION,
				"attr type=%u isn't supported.\n", type);
			return -1;

		case OAKLEY_ATTR_SA_LD_TYPE:
			switch (lorv) {
			case OAKLEY_ATTR_SA_LD_TYPE_SEC:
			case OAKLEY_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(LOCATION,
					"invalid life type %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_SA_LD:
			/* should check the value */
			break;

		case OAKLEY_ATTR_PRF:
		case OAKLEY_ATTR_KEY_LEN:
			break;

		case OAKLEY_ATTR_FIELD_SIZE:
			plog(LOCATION,
				"attr type=%u isn't supported.\n", type);
			return -1;

		case OAKLEY_ATTR_GRP_ORDER:
			break;

		default:
			plog(LOCATION,
				"invalid attribute type %d.\n", type);
			return -1;
		}

		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d) + lorv);
		}
	}

	return 0;
}

/*
 * check data attributes in IPSEC AH/ESP.
 */
static int
check_attr_ah(trns)
	struct isakmp_pl_t *trns;
{
	return check_attr_ipsec(IPSECDOI_PROTO_IPSEC_AH, trns);
}

static int
check_attr_esp(trns)
	struct isakmp_pl_t *trns;
{
	return check_attr_ipsec(IPSECDOI_PROTO_IPSEC_ESP, trns);
}

static int
check_attr_ipsec(proto_id, trns)
	int proto_id;
	struct isakmp_pl_t *trns;
{
	struct isakmp_data *d;
	int tlen;
	int flag, type = 0, lorv;
	int attrseen[16];	/* XXX magic number */

	tlen = ntohs(trns->h.len) - sizeof(struct isakmp_pl_t);
	d = (struct isakmp_data *)((caddr_t)trns + sizeof(struct isakmp_pl_t));
	memset(attrseen, 0, sizeof(attrseen));

	while (tlen > 0) {
		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		YIPSDEBUG(DEBUG_DSA,
			plog(LOCATION,
				"type=%d, flag=0x%04x, lorv=0x%04x\n",
				type, flag, lorv));

		if (type < sizeof(attrseen)/sizeof(attrseen[0]))
			attrseen[type]++;

		switch (type) {
		case IPSECDOI_ATTR_ENC_MODE:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when ENC_MODE.\n");
			}

			switch (lorv) {
			case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
			case IPSECDOI_ATTR_ENC_MODE_TRNS:
				break;
			default:
				plog(LOCATION,
					"invalid encryption mode=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_AUTH:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when AUTH.\n");
			}

			switch (lorv) {
			case IPSECDOI_ATTR_AUTH_HMAC_MD5:
				if (proto_id == IPSECDOI_PROTO_IPSEC_AH
				 && trns->t_id != IPSECDOI_AH_MD5) {
ahmismatch:
					plog(LOCATION,
						"auth algorithm %u conflicts with transform %u.\n",
						lorv, trns->t_id);
					return -1;
				}
				break;
			case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
				if (proto_id == IPSECDOI_PROTO_IPSEC_AH) {
					if (trns->t_id != IPSECDOI_AH_SHA)
						goto ahmismatch;
				}
				break;
			case IPSECDOI_ATTR_AUTH_DES_MAC:
			case IPSECDOI_ATTR_AUTH_KPDK:
				plog(LOCATION,
					"auth algorithm %u isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LOCATION,
					"invalid auth algorithm=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD_TYPE:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when LD_TYPE.\n");
			}

			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(LOCATION,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				/* warning */
				plog(LOCATION,
					"should be TLV when LD.\n");
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if (lorv == 0) {
					plog(LOCATION,
						"invalid length of LD\n");
					return -1;
				}

				/* XXX to be checked the value of duration. */
				/* i.g. too short duration */
			}
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when GRP_DESC.\n");
			}

			switch (lorv) {
			case OAKLEY_ATTR_GRP_DESC_MODP768:
			case OAKLEY_ATTR_GRP_DESC_MODP1024:
			case OAKLEY_ATTR_GRP_DESC_MODP1536:
				break;
			case OAKLEY_ATTR_GRP_DESC_EC2N155:
			case OAKLEY_ATTR_GRP_DESC_EC2N185:
				plog(LOCATION,
					"DH group %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LOCATION,
					"invalid group description=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_KEY_LENGTH:
		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
			plog(LOCATION,
				"attr type=%u isn't supported.\n", type);
			return -1;

		default:
			plog(LOCATION,
				"invalid attribute type %d.\n", type);
			return -1;
		}

		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((caddr_t)d
				+ sizeof(*d) + lorv);
		}
	}

	if (proto_id == IPSECDOI_PROTO_IPSEC_AH
	 && !attrseen[IPSECDOI_ATTR_AUTH]) {
		plog(LOCATION,
			"attr AUTH must be present for AH.\n", type);
		return -1;
	}

	return 0;
}

static int
check_attr_ipcomp(trns)
	struct isakmp_pl_t *trns;
{
	struct isakmp_data *d;
	int tlen;
	int flag, type = 0, lorv;
	int attrseen[16];	/* XXX magic number */

	tlen = ntohs(trns->h.len) - sizeof(struct isakmp_pl_t);
	d = (struct isakmp_data *)((caddr_t)trns + sizeof(struct isakmp_pl_t));
	memset(attrseen, 0, sizeof(attrseen));

	while (tlen > 0) {
		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		YIPSDEBUG(DEBUG_DSA,
			plog(LOCATION,
				"type=%d, flag=0x%04x, lorv=0x%04x\n",
				type, flag, lorv));

		if (type < sizeof(attrseen)/sizeof(attrseen[0]))
			attrseen[type]++;

		switch (type) {
		case IPSECDOI_ATTR_ENC_MODE:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when ENC_MODE.\n");
			}

			switch (lorv) {
			case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
			case IPSECDOI_ATTR_ENC_MODE_TRNS:
				break;
			default:
				plog(LOCATION,
					"invalid encryption mode=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD_TYPE:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when LD_TYPE.\n");
			}

			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(LOCATION,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				/* warning */
				plog(LOCATION,
					"should be TLV when LD.\n");
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if (lorv == 0) {
					plog(LOCATION,
						"invalid length of LD\n");
					return -1;
				}

				/* XXX to be checked the value of duration. */
				/* i.g. too short duration */
			}
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			if (! flag) {
				/* warning */
				plog(LOCATION,
					"must be TV when GRP_DESC.\n");
			}

			switch (lorv) {
			case OAKLEY_ATTR_GRP_DESC_MODP768:
			case OAKLEY_ATTR_GRP_DESC_MODP1024:
			case OAKLEY_ATTR_GRP_DESC_MODP1536:
				break;
			case OAKLEY_ATTR_GRP_DESC_EC2N155:
			case OAKLEY_ATTR_GRP_DESC_EC2N185:
				plog(LOCATION,
					"DH group %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(LOCATION,
					"invalid group description=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_AUTH:
			plog(LOCATION, "invalid attr type=%u.\n", type);
			return -1;

		case IPSECDOI_ATTR_KEY_LENGTH:
		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
			plog(LOCATION,
				"attr type=%u isn't supported.\n", type);
			return -1;

		default:
			plog(LOCATION,
				"invalid attribute type %d.\n", type);
			return -1;
		}

		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d
				+ sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((caddr_t)d
				+ sizeof(*d) + lorv);
		}
	}

#if 0
	if (proto_id == IPSECDOI_PROTO_IPCOMP
	 && !attrseen[IPSECDOI_ATTR_AUTH]) {
		plog(LOCATION,
			"attr AUTH must be present for AH.\n", type);
		return -1;
	}
#endif

	return 0;
}

/* %%% */
static char *name_prot[] = {
	"",
	"ISAKMP",
	"AH",
	"ESP",
	"IPCOMP",
};

static char *name_trns_isakmp[] = {
	"",
	"IKE",
};

static char *name_trns_ah[] = {
	"",
	"",
	"MD5",
	"SHA",
	"DES",
};

static char *name_trns_esp[] = {
	"",
	"DES_IV64",
	"DES",
	"3DES",
	"RC5",
	"IDEA",
	"CAST",
	"BLOWFISH",
	"3IDEA",
	"DES_IV32",
	"RC4",
	"NULL",
};

static char *name_trns_ipcomp[] = {
	"",
	"OUI",
	"DEFLATE",
	"3IDEA",
	"DES_IV32",
	"RC4",
	"NULL",
};

static char **name_trns[] = {
	0,
	name_trns_isakmp,
	name_trns_ah,
	name_trns_esp,
	name_trns_ipcomp,
};

static char *name_attr_isakmp[] = {
	"",
	"Encryption Algorithm",
	"Hash Algorithm",
	"Authentication Method",
	"Group Description",
	"Group Type",
	"Group Prime/Irreducible Polynomial",
	"Group Generator One",
	"Group Generator Two",
	"Group Curve A",
	"Group Curve B",
	"Life Type",
	"Life Duration",
	"PRF",
	"Key Length",
	"Field Size",
	"Group Order",
};

static char *name_attr_isakmp_enc[] = {
	"",
	"DES-CBC",
	"IDEA-CBC",
	"Blowfish-CBC",
	"RC5-R16-B64-CBC",
	"3DES-CBC",
	"CAST-CBC",
};

static char *name_attr_isakmp_hash[] = {
	"",
	"MD5",
	"SHA",
	"Tiger",
};

static char *name_attr_isakmp_method[] = {
	"",
	"pre-shared key",
	"DSS signatures",
	"RSA signatures",
	"Encryption with RSA",
	"Revised encryption with RSA",
};

static char *name_attr_isakmp_desc[] = {
	"",
	"768-bit MODP group",
	"1024-bit MODP group",
	"EC2N group on GP[2^155]",
	"EC2N group on GP[2^185]",
	"1536-bit MODP group",
};

static char *name_attr_isakmp_group[] = {
	"",
	"MODP",
	"ECP",
	"EC2N",
};

static char *name_attr_isakmp_ltype[] = {
	"",
	"seconds",
	"kilobytes"
};

static char **name_attr_isakmp_v[] = {
	0,
	name_attr_isakmp_enc,
	name_attr_isakmp_hash,
	name_attr_isakmp_method,
	name_attr_isakmp_desc,
	name_attr_isakmp_group,
	0,
	0,
	0,
	0,
	0,
	name_attr_isakmp_ltype,
	0,
	0,
	0,
	0,
	0,
};

static char *name_attr_ipsec[] = {
	"",
	"SA Life Type",
	"SA Life Duration",
	"Group Description",
	"Encription Mode",
	"Authentication Algorithm",
	"Key Length",
	"Key Rounds",
	"Compression Dictionary Size",
	"Compression Private Algorithm"
};

static char *name_attr_ipsec_ltype[] = {
	"",
	"seconds",
	"kilobytes"
};

static char *name_attr_ipsec_enc_mode[] = {
	"",
	"Tunnel",
	"Transport"
};

static char *name_attr_ipsec_auth[] = {
	"",
	"hmac-md5",
	"hmac-sha",
	"des-mac",
	"kpdk",
};

static char **name_attr_ipsec_v[] = {
	0,
	name_attr_ipsec_ltype,
	0,
	0,
	name_attr_ipsec_enc_mode,
	name_attr_ipsec_auth,
	0,
	0,
	0,
	0,
};

/*
 * get IKE SA parameter.
 * MUST call after calling ipsecdoi_get_proposal().
 * IN:	pointer to the SA payload for use.
 * OUT:	
 *	positive: the pointer to new buffer of IPsec SA parameters.
 *	0	: error occurd.
 */
struct oakley_sa *
ipsecdoi_get_oakley(sap)
	vchar_t *sap;
{
	struct oakley_sa *newisa;

	/* allocate new buffer */
	if ((newisa = CALLOC(sizeof(struct oakley_sa),
				struct oakley_sa *)) == NULL) {
		plog(LOCATION,
			"calloc (%s)\n", strerror(errno));
		return 0;
	}

	newisa->doi = ntohl(((struct isakmp_pl_sa *)sap->v)->doi);
	newisa->sit = ntohl(((struct isakmp_pl_sa *)sap->v)->sit);

	YIPSDEBUG(DEBUG_SA,
		plog(LOCATION, "SA for use:\n");
		plog(LOCATION, "doi=0x%08x, sit=0x%08x\n",
			newisa->doi, newisa->sit));

    {
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	caddr_t bp;

	bp = sap->v + sizeof(struct isakmp_pl_sa);

	prop = (struct isakmp_pl_p *)bp;

	newisa->proto_id = prop->proto_id;
	newisa->spi = 0; /* MUST be check before. */

	YIPSDEBUG(DEBUG_SA,
		plog(LOCATION,
	       		"prop#=%d, prot-id=%s, spi-size=%d, #trns=%d\n",
			prop->p_no, name_prot[prop->proto_id],
			prop->spi_size, prop->num_t));

	bp += (sizeof(struct isakmp_pl_p)
		+ prop->spi_size); /* MUST zero */

	trns = (struct isakmp_pl_t *)bp;
	newisa->t_id = trns->t_id;

	YIPSDEBUG(DEBUG_SA,
	    plog(LOCATION,
	        "trns#=%d, trns-id=%s\n",
		trns->t_no, name_trns[prop->proto_id][trns->t_id]));

	bp += sizeof(struct isakmp_pl_t);

	/* get attributes */
	get_attr_isakmp(bp, newisa,
			ntohs(trns->h.len) - sizeof(struct isakmp_pl_t));
    }

	return newisa;
}

/*
 * get IPsec SA parameter.
 * IN:	pointer to the SA payload for use.
 * OUT:	
 *	positive: the pointer to new buffer of IPsec SA parameters.
 *	0	: error occurd.
 */
struct ipsec_sa *
ipsecdoi_get_ipsec(sap)
	vchar_t *sap;
{
	struct ipsec_sa *newisa, **isap;
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	int tlen, proplen;
	caddr_t bp;
	int np;

	bp = sap->v + sizeof(struct isakmp_pl_sa);
	prop = (struct isakmp_pl_p *)bp;
	tlen = ntohs(prop->h.len);

	isap = &newisa;
    
	while (1) {
		/* allocate new buffer */
		if ((*isap = CALLOC(sizeof(struct ipsec_sa),
					struct ipsec_sa *)) == NULL) {
			plog(LOCATION,
				"calloc (%s)\n", strerror(errno));
			goto err;
		}

		prop = (struct isakmp_pl_p *)bp;
		proplen = ntohs(prop->h.len);
		np = prop->h.np;

		(*isap)->proto_id = prop->proto_id;

		YIPSDEBUG(DEBUG_SA,
			plog(LOCATION,
				"prop#=%d, prot-id=%s, spi-size=%d, #trns=%d\n",
				prop->p_no, name_prot[prop->proto_id],
				prop->spi_size, prop->num_t));

		bp += sizeof(struct isakmp_pl_p);

		if (((*isap)->spi = vmalloc(prop->spi_size)) == 0) {
			plog(LOCATION,
				"vmalloc (%s)\n", strerror(errno));
			goto err;
		}
		memcpy((*isap)->spi->v, bp, prop->spi_size);

		YIPSDEBUG(DEBUG_SA,
			plog(LOCATION, "spi=");
				pvdump((*isap)->spi));

		bp += prop->spi_size;

		/* get transform */
		trns = (struct isakmp_pl_t *)bp;
		(*isap)->enctype = trns->t_id;

		YIPSDEBUG(DEBUG_SA,
			plog(LOCATION,
				"trns#=%d, trns-id=%s\n",
				trns->t_no,
				name_trns[prop->proto_id][trns->t_id]));

		bp += sizeof(struct isakmp_pl_t);

		/* get attributes */
		get_attr_ipsec(bp, *isap,
			ntohs(trns->h.len) - sizeof(struct isakmp_pl_t));

		tlen -= proplen;
		bp += proplen;

		if (np == ISAKMP_NPTYPE_NONE) break;

		isap = &(*isap)->next;
	}

	return newisa;
err:
    {
	struct ipsec_sa *isa;

	for (isa = newisa; isa; isa = isa->next) {
		if (isa) {
			if (isa->spi) vfree(isa->spi);
			if (isa->spi_p) vfree(isa->spi);
			free(isa);
		}
	}
    }
	return 0;
}

/*
 * get ISAKMP data attributes
 */
static int
get_attr_isakmp(bp, sa, tlen)
	caddr_t bp;
	struct oakley_sa *sa;
	int tlen;
{
	struct isakmp_data *d, *prev;
	int flag, type, lorv;
	int error = -1;
	int life_t;
	int keylen = 0;
	vchar_t *val = NULL;
	int len;
	u_char *p;

	prev = (struct isakmp_data *)NULL;
	d = (struct isakmp_data *)bp;

	/* default */
	sa->ld_bytes = 0;
	life_t = OAKLEY_ATTR_SA_LD_TYPE_DEFAULT;
	sa->ld_time = OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
	sa->dh = CALLOC(sizeof(struct dh), struct dh *);
	if (!sa->dh)
		goto end;

	while (tlen > 0) {

		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		YIPSDEBUG(DEBUG_DSA,
			plog(LOCATION,
				"type=%s, flag=0x%04x, lorv=%s\n",
				name_attr_isakmp[type], flag,
				name_attr_isakmp_v[type] ?
					name_attr_isakmp_v[type][lorv]:""));

		/* get variable-sized item */
		switch (type) {
		case OAKLEY_ATTR_GRP_PI:
		case OAKLEY_ATTR_GRP_GEN_ONE:
		case OAKLEY_ATTR_GRP_GEN_TWO:
		case OAKLEY_ATTR_GRP_CURVE_A:
		case OAKLEY_ATTR_GRP_CURVE_B:
		case OAKLEY_ATTR_SA_LD:
		case OAKLEY_ATTR_GRP_ORDER:
			if (flag) {	/*TV*/
				len = 2;
				p = (u_char *)&lorv;
			} else {	/*TLV*/
				len = lorv;
				p = (u_char *)(d + 1);
			}
			val = vmalloc(len);
			if (!val)
				return -1;
			memcpy(val->v, p, len);
			break;

		default:
			break;
		}

		switch (type) {
		case OAKLEY_ATTR_ENC_ALG:
			sa->enctype = (u_int8_t)lorv;
			break;

		case OAKLEY_ATTR_HASH_ALG:
			sa->hashtype = (u_int8_t)lorv;
			break;

		case OAKLEY_ATTR_AUTH_METHOD:
			sa->authtype = (u_int8_t)lorv;
			break;

		case OAKLEY_ATTR_GRP_DESC:
			sa->dhgrp = (u_int8_t)lorv;
			break;

		case OAKLEY_ATTR_GRP_TYPE:
			if (lorv == OAKLEY_ATTR_GRP_TYPE_MODP)
				sa->dh->type = lorv;
			else
				return -1;
			break;

		case OAKLEY_ATTR_GRP_PI:
			sa->dh->prime = val;
			break;

		case OAKLEY_ATTR_GRP_GEN_ONE:
			vfree(val);
			if (!flag)
				sa->dh->gen1 = ntohs(lorv);
			else {
				sa->dh->gen1 = 0;
				if (lorv > 4)
					return -1;
				memcpy(&sa->dh->gen1, d + 1, lorv);
				sa->dh->gen1 = ntohl(sa->dh->gen1);
			}
			break;

		case OAKLEY_ATTR_GRP_GEN_TWO:
			vfree(val);
			if (!flag)
				sa->dh->gen2 = ntohs(lorv);
			else {
				sa->dh->gen2 = 0;
				if (lorv > 4)
					return -1;
				memcpy(&sa->dh->gen2, d + 1, lorv);
				sa->dh->gen2 = ntohl(sa->dh->gen2);
			}
			break;

		case OAKLEY_ATTR_GRP_CURVE_A:
			sa->dh->curve_a = val;
			break;

		case OAKLEY_ATTR_GRP_CURVE_B:
			sa->dh->curve_b = val;
			break;

		case OAKLEY_ATTR_SA_LD_TYPE:
			switch (lorv) {
			case OAKLEY_ATTR_SA_LD_TYPE_SEC:
			case OAKLEY_ATTR_SA_LD_TYPE_KB:
				life_t = lorv;
				break;
			default:
				life_t = OAKLEY_ATTR_SA_LD_TYPE_DEFAULT;
				break;
			}
			break;

		case OAKLEY_ATTR_SA_LD:
		    {
			u_int32_t t;

			if (!life_t || !prev
			 || (ntohs(prev->type) & ~ISAKMP_GEN_MASK) !=
					OAKLEY_ATTR_SA_LD_TYPE) {
				plog(LOCATION,
				    "life duration must follow ltype\n");
				break;
			}

			switch (life_t) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
				t = ipsecdoi_set_ld(life_t, val);
				if (t == ~0)
					sa->ld_time = OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
				else
					sa->ld_time = ipsecdoi_set_ld(life_t, val);
				break;
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				t = ipsecdoi_set_ld(life_t, val);
				if (t == ~0)
					sa->ld_bytes = t;
				else
					sa->ld_bytes = 0;	/*XXX*/

				break;
			}
			vfree(val);
		    }
			break;

		case OAKLEY_ATTR_KEY_LEN:
			if (lorv % 8 != 0) {
				plog(LOCATION, "keylen %d: not multiple of 8\n",
					lorv);
				goto end;
			}
			sa->keylen = (u_int8_t)lorv / 8;
			keylen++;
			break;

		case OAKLEY_ATTR_PRF:
		case OAKLEY_ATTR_FIELD_SIZE:
			/* unsupported */
			break;

		case OAKLEY_ATTR_GRP_ORDER:
			sa->dh->order = val;
			break;

		default:
			break;
		}

		prev = d;
		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d + sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((char *)d + sizeof(*d) + lorv);
		}
	}

	/* check DH group settings */
	switch (sa->dhgrp) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		if (sa->dh->prime || sa->dh->gen1)
			goto end;
		if (sa->dhgrp > sizeof(dhgroup)/sizeof(dhgroup[0])
		 || dhgroup[sa->dhgrp].type == 0)
			goto end;
		memcpy(sa->dh, &dhgroup[sa->dhgrp], sizeof(dhgroup[sa->dhgrp]));
		sa->dh->prime = vdup(dhgroup[sa->dhgrp].prime);
		break;
	default:
		if (!sa->dh->type || !sa->dh->prime || !sa->dh->gen1) {
			goto end;
		}
	}

	/* key length must not be specified on some algorithms */
	if (keylen) {
		switch (sa->enctype) {
		case OAKLEY_ATTR_ENC_ALG_DES:
		case OAKLEY_ATTR_ENC_ALG_IDEA:
		case OAKLEY_ATTR_ENC_ALG_3DES:
			plog(LOCATION,
				"keylen must not be specified for encryption algorithm %d\n",
				sa->enctype);
			goto end;
		case OAKLEY_ATTR_ENC_ALG_BLOWFISH:
		case OAKLEY_ATTR_ENC_ALG_RC5:
		case OAKLEY_ATTR_ENC_ALG_CAST:
			break;
		default:
			plog(LOCATION,
				"unknown encryption algorithm %d\n",
				sa->enctype);
			goto end;
		}
	}

	return 0;
end:
	if (sa->dh) {
		if (sa->dh->prime)
			vfree(sa->dh->prime);
		free(sa->dh);
	}
	return error;
}

/*
 * get IPsec data attributes
 */
static int
get_attr_ipsec(bp, sa, tlen)
	caddr_t bp;
	struct ipsec_sa *sa;
	int tlen;
{
	struct isakmp_data *d, *prev;
	int flag, type, lorv;
	int error = -1;
	int life_t;
	struct dh *dh;

	prev = (struct isakmp_data *)NULL;
	d = (struct isakmp_data *)bp;

	/* default */
	sa->ld_bytes = 0;
	life_t = IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT;
	sa->ld_time = IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;
	sa->dh = CALLOC(sizeof(struct dh), struct dh *);
	if (!sa->dh)
		goto end;

	while (tlen > 0) {

		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		YIPSDEBUG(DEBUG_DSA,
			plog(LOCATION,
				"type=%s, flag=0x%04x, lorv=%s\n",
				name_attr_ipsec[type], flag,
				name_attr_ipsec_v[type] ?
					name_attr_ipsec_v[type][lorv]:""));

		switch (type) {
		case IPSECDOI_ATTR_SA_LD_TYPE:
			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				life_t = lorv;
				break;
			default:
				plog(LOCATION,
				    "Warning of invalid life duration type.\n");
				life_t = IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT;
				break;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (life_t == NULL
			 || prev == NULL
			 || (ntohs(prev->type) & ~ISAKMP_GEN_MASK) !=
					IPSECDOI_ATTR_SA_LD_TYPE) {
				plog(LOCATION,
				    "life duration must follow ltype\n");
				break;
			}

		    {
			vchar_t *ld_buf = NULL;
			u_int32_t t;
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				if ((ld_buf = vmalloc(sizeof(d->lorv))) == 0) {
					plog(LOCATION,
					    "vmalloc (%s)\n", strerror(errno));
					goto end;
				}
				memcpy(ld_buf->v, (caddr_t)&lorv,
					sizeof(d->lorv));
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if ((ld_buf = vmalloc(lorv)) == 0) {
					plog(LOCATION,
					    "vmalloc (%s)\n", strerror(errno));
					goto end;
				}
				memcpy(ld_buf->v, (caddr_t)d + sizeof(*d), lorv);
			}
			switch (life_t) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
				t = ipsecdoi_set_ld(life_t, ld_buf);
				if (t == ~0)
					sa->ld_time = IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;
				else
					sa->ld_time = t;
				break;
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				t = ipsecdoi_set_ld(life_t, ld_buf);
				if (t == ~0)
					sa->ld_bytes = 0;	/*XXX*/
				else
					sa->ld_bytes = t;
				break;
			}
			vfree(ld_buf);
		    }
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			sa->dhgrp = (u_int8_t)lorv;
			break;

		case IPSECDOI_ATTR_ENC_MODE:
			sa->mode = (u_int8_t)lorv;
			break;

		case IPSECDOI_ATTR_AUTH:
			sa->hashtype = (u_int8_t)lorv;
			break;

		case IPSECDOI_ATTR_KEY_LENGTH:
		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
		default:
			break;
		}

		prev = d;
		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d + sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((caddr_t)d + sizeof(*d) + lorv);
		}
	}

	/* check DH group settings */
	switch (sa->dhgrp) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		if (sa->dh->prime || sa->dh->gen1)
			goto end;
		if (sa->dhgrp > sizeof(dhgroup)/sizeof(dhgroup[0])
		 || dhgroup[sa->dhgrp].type == 0)
			goto end;
		dh = CALLOC(sizeof(struct dh), struct dh *);
		if (!dh)
			goto end;
		memcpy(dh, &dhgroup[sa->dhgrp], sizeof(dhgroup[sa->dhgrp]));
		dh->prime = vdup(dhgroup[sa->dhgrp].prime);
		free((void *)sa->dh);
		sa->dh = dh;
		break;
	default:
		if (!sa->dh->type || !sa->dh->prime || !sa->dh->gen1) {
			goto end;
		}
	}

	error = 0;
end:
	return error;
}

static u_int32_t
ipsecdoi_set_ld(type, buf)
	int type;
	vchar_t *buf;
{
	u_int32_t ld;

	if (type == 0 || buf == 0)
		return 0;

	switch (buf->l) {
	case 2:
		ld = ntohs(*(u_int16_t *)buf->v);
		break;
	case 4:
		ld = ntohl(*(u_int32_t *)buf->v);
		break;
	default:
		plog(LOCATION, "length %d of life duration isn't supported.\n", buf->l);
		return ~0;
	}

	return ld;
}

/*
 * create ID payload
 * get ID for phase 1, and set into iph1->id.
 */
vchar_t *
ipsecdoi_get_id1(iph1)
	struct isakmp_ph1 *iph1;
{
	vchar_t *ret;

	if (iph1->cfp->ph[0]->id_b) {
		/* from configuration, that may be string. */
		/* XXX to be check the included values */
		return vdup(iph1->cfp->ph[0]->id_b);
	} else {
		/* from iph1->local, that is IP[64] address. */
		int type;

		switch (iph1->local->sa_family) {
		case AF_INET:
			type = IPSECDOI_ID_IPV4_ADDR;
			break;
#ifdef INET6
		case AF_INET6:
			type = IPSECDOI_ID_IPV6_ADDR;
			break;
#endif
		default:
			plog(LOCATION, "invalid address family.\n");
			return NULL;
		}

		ret = vmalloc(4 + _INALENBYAF(iph1->local->sa_family));
		if (ret == NULL) {
			plog(LOCATION,
				"vmalloc (%s)\n", strerror(errno));
			return NULL;
		}

		memcpy(ret->v + 4, _INADDRBYSA(iph1->local),
			_INALENBYAF(iph1->local->sa_family));
		ret->v[0] = type;
		ret->v[1] = IPPROTO_UDP;
#if 0
		*(u_int16_t *)&ret->v[2] = htons(PORT_ISAKMP);
#else
		*(u_int16_t *)&ret->v[2] = _INPORTBYSA(iph1->local);
#endif
	}

	return ret;
}

/*
 * create ID payload from sockaddr.
 * see, RFC2407 4.6.2.1
 * XXX: create the address type.  This function can NOT create other type.
 * 	e.g. certificate type.
 */
int
ipsecdoi_sockaddr2id(buf0, addr, prefixlen, proto)
	vchar_t **buf0;
	struct sockaddr *addr;
	u_int prefixlen;
	u_int proto;
{
	int type, len, len2;

	/* get default ID length */
	len = sizeof(struct ipsecdoi_id_b) + _INALENBYAF(addr->sa_family);

	/*
	 * XXXX:
	 * Q. When type is SUBNET, is it allowed to be ::1/128.
	 */
	switch (addr->sa_family) {
	case AF_INET:
		if (prefixlen == (_INALENBYAF(addr->sa_family) << 3)) {
			type = IPSECDOI_ID_IPV4_ADDR;
			len2 = 0;
		} else {
			type = IPSECDOI_ID_IPV4_ADDR_SUBNET;
			len2 = _INALENBYAF(addr->sa_family); /* acutually 4 */
		}
		break;
#ifdef INET6
	case AF_INET6:
		if (prefixlen == (_INALENBYAF(addr->sa_family) << 3)) {
			type = IPSECDOI_ID_IPV6_ADDR;
			len2 = 0;
		} else {
			type = IPSECDOI_ID_IPV6_ADDR_SUBNET;
			len2 = _INALENBYAF(addr->sa_family); /* acutually 16 */
		}
		break;
#endif
	default:
		plog(LOCATION, "invalid address family.\n");
		return -1;
	}

	/* get ID buffer */
	if (((*buf0) = vmalloc(len + len2)) == NULL) {
		plog(LOCATION,
			"vmalloc (%s)\n", strerror(errno));
		return -1;
	}

	memset((*buf0)->v, 0, (*buf0)->l);

	/* set the part of header. */
	((struct ipsecdoi_id_b *)(*buf0)->v)->type = type;
	((struct ipsecdoi_id_b *)(*buf0)->v)->proto_id = proto;
	((struct ipsecdoi_id_b *)(*buf0)->v)->port = _INPORTBYSA(addr);

	/* set address */
	memcpy((*buf0)->v + sizeof(struct ipsecdoi_id_b),
		_INADDRBYSA(addr), _INALENBYAF(addr->sa_family));

	/* set prefix */
	if (len2 != 0) {
		u_char *p = (*buf0)->v + len;
		u_int bits = prefixlen;

		while (bits >= 8) {
			*p++ = 0xff;
			bits -= 8;
		}

		if (bits > 0)
			*p = ~((1 << (8 - bits)) - 1);
	}

	return 0;
}

/*
 * create sockaddr structure from ID payload.
 * see, RFC2407 4.6.2.1
 */
int ipsecdoi_id2sockaddr(
	vchar_t *buf,
	struct sockaddr **addr,
	u_int *prefixlen,
	u_int *ul_proto)
{
	struct ipsecdoi_id_b *id_b = (struct ipsecdoi_id_b *)buf->v;
	u_int family, plen = 0;

	switch (id_b->type) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
		family = AF_INET;
		break;
#ifdef INET6
	case IPSECDOI_ID_IPV6_ADDR:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
		family = AF_INET6;
		break;
#endif
	default:
		plog(LOCATION, "invalid ID type.\n");
		return -1;
	}

	/* get prefix length */
	switch (id_b->type) {
	case IPSECDOI_ID_IPV4_ADDR:
	case IPSECDOI_ID_IPV6_ADDR:
		plen = _INALENBYAF(family) << 3;
		break;
	case IPSECDOI_ID_IPV4_ADDR_SUBNET:
	case IPSECDOI_ID_IPV6_ADDR_SUBNET:
	    {
		u_char *p;
		u_int max;

		/* sanity check */
		if (buf->l < _INALENBYAF(family)) {
			plog(LOCATION, "invalid mask.\n");
			return -1;
		}

		/* get subnet mask length */
		plen = 0;
		max = (_INALENBYAF(family) << 3);

		p = buf->v
			+ sizeof(struct ipsecdoi_id_b)
			+ _INALENBYAF(family);

		for (; *p == 0xff; p++) {
			if (plen >= max)
				break;
			plen += 8;
		}

		if (plen < max) {
			u_int l = 0;
			u_char b = ~(*p);

			while (b) {
				b >>= 1;
				l++;
			}

			l = 8 - l;
			plen += l;
		}
	    }
		break;
	default:
		plog(LOCATION, "unsupported ID type.\n");
		return -1;
	}

	/* get buffer for sockaddr_in* */
	if ((*addr = CALLOC(_SALENBYAF(family), struct sockaddr *)) == NULL) {
		plog(LOCATION,
			"calloc (%s)\n", strerror(errno));
		return -1;
	}

	(*addr)->sa_len = _SALENBYAF(family);
	(*addr)->sa_family = family;
	_INPORTBYSA(*addr) = id_b->port;
	memcpy(_INADDRBYSA(*addr), buf->v + sizeof(struct ipsecdoi_id_b),
		_INALENBYAF(family));
	*prefixlen = plen;
	*ul_proto = id_b->proto_id;

	YIPSDEBUG(DEBUG_MISC,
		GETNAMEINFO(*addr, _addr1_, _addr2_);
		plog(LOCATION, "%s/%u[%s] %u.\n",
			_addr1_, *prefixlen, _addr2_, *ul_proto));

	return 0;
}

/*
 * The order of values is network byte order.
 */
vchar_t *
ipsecdoi_make_mysa(cf_sa, spi, proptype, mode)
	struct isakmp_cf_sa *cf_sa;
	u_int32_t spi;			/* == 0 i.e. phase 1 */
	int proptype;			/* proposal type, 0: any */
	u_int8_t mode;			/* mode of SA */
{
	vchar_t *mysa;
	u_int tlen;	/* total sa length */
	struct isakmp_cf_p *cf_p;
	struct isakmp_cf_p *group;
	struct isakmp_cf_t *cf_t;
	struct ipsecdoi_sa *sa;
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct isakmp_data *data;
	u_int8_t *np_p = 0, *np_t = 0;
	caddr_t p;
	int goodgroup = 0, nprop = 0;

	/* get total SA length */
	/* XXX: it is not right value. */
	tlen = cf_sa->len;
	if (spi) {
		/* for encryption mode */
		for (cf_p = cf_sa->p; cf_p; cf_p = cf_p->next) {
			for (cf_t = cf_p->t; cf_t; cf_t = cf_t->next) {
				tlen += sizeof(*data);
			}
		}
	}

	if ((mysa = vmalloc(tlen)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno)); 
		return 0;
	}
	p = mysa->v;

	/* create SA payload */
	sa = (struct ipsecdoi_sa *)p;
	sa->h.np = ISAKMP_NPTYPE_NONE;
	sa->h.len = htons(cf_sa->len);	/*will be adjusted later*/
	sa->b.doi = cf_sa->doi;
	sa->b.sit = cf_sa->sit;
	p += sizeof(*sa);

	group = NULL;
	for (cf_p = cf_sa->p; cf_p; cf_p = cf_p->next) {

		int proplen = 0;	/* for updating prop->h.len */

		if (!proptype)
			goto nopropfilt;

		if (cf_p == group)
			group = NULL;
		if (!group) {
			goodgroup = 0;
			nprop = 0;
			for (group = cf_p;
			     group && group->p_no == cf_p->p_no;
			     group = group->next) {
				nprop++;
				if (proptype == group->proto_id)
					goodgroup = 1;
			}
			/* XXX this restriction should be fixed */
			if (nprop != 1) {
				plog(LOCATION,
					"proposal group %d filtered due to multiple proposals (%d proposals, unsupported).\n",
					cf_p->p_no, nprop); 
				goodgroup = 0;
			} else if (!goodgroup) {
				plog(LOCATION,
					"proposal group %d filtered (proposal type mismatch with requested type %d).\n",
					cf_p->p_no, proptype); 
			} else {
				plog(LOCATION,
					"proposal group %d looks good.\n",
					cf_p->p_no); 
			}
		}
		if (!goodgroup)
			continue;

nopropfilt:
		if (np_p)
			*np_p = ISAKMP_NPTYPE_P;

		/* create proposal */
		prop = (struct isakmp_pl_p *)p;
		prop->h.np     = ISAKMP_NPTYPE_NONE;
		prop->h.len    = 0;	/* be updated leter. */
		prop->p_no     = cf_p->p_no;
		prop->proto_id  = cf_p->proto_id;
		prop->spi_size =
			(prop->proto_id == IPSECDOI_PROTO_ISAKMP) ? 0 : 4;
		prop->num_t    = cf_p->num_t;
		p += sizeof(*prop);

		if (prop->spi_size != 0) {
			if (spi) {
				memcpy(p, (caddr_t)&spi, prop->spi_size);
			} else
				memset(p, 0, prop->spi_size);

			p += prop->spi_size;
		}

		for (cf_t = cf_p->t; cf_t; cf_t = cf_t->next) {
			if (np_t)
				*np_t = ISAKMP_NPTYPE_T;

			/* create transform */
			trns = (struct isakmp_pl_t *)p;
			trns->h.np  = ISAKMP_NPTYPE_NONE;
			trns->h.len = htons(cf_t->len);
			trns->t_no  = cf_t->t_no;
			trns->t_id  = cf_t->t_id;
			p += sizeof(*trns);

			memcpy(p, cf_t->data->v, cf_t->data->l);
			p += cf_t->data->l;

			if (spi) {
				/* set encryption mode */
				isakmp_set_attr_l(p,
					IPSECDOI_ATTR_ENC_MODE,
					mode);
				p += sizeof(*data);

				/* fix length */
				trns->h.len = htons(cf_t->len + sizeof(*data));
			}

			/* count up proposal length */
			proplen += ntohs(trns->h.len);

			/* save buffer to pre-next payload */
			np_t = &trns->h.np;
		}

		/* update proposal length */
		prop->h.len = htons(sizeof(*prop) + prop->spi_size + proplen);

		/* save buffer to pre-next payload */
		np_p = &prop->h.np;
		np_t = 0;
	}

	/* no valid proposal found */
	if (p == (caddr_t)(sa + 1)) {
		vfree(mysa);
		return NULL;
	}

	mysa->l = p - mysa->v;	/* adjust length */
	sa->h.len = htons(mysa->l);
	return mysa;
}

#if 0
static caddr_t get_last_attr(caddr_t buf, u_int len)
{
	struct isakmp_data *d = (struct isakmp_data *)buf;
	int flag, lorv;

	while (len > 0) {
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = ntohs(d->lorv);

		if (flag) {
			len -= sizeof(*d);
			d = (struct isakmp_data *)((caddr_t)d + sizeof(*d));
		} else {
			len -= (sizeof(*d) + lorv);
			d = (struct isakmp_data *)((caddr_t)d + (sizeof(*d) + lorv));
		}
	}
}
#endif

