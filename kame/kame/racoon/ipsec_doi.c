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
/* YIPS @(#)$Id: ipsec_doi.c,v 1.51 2000/02/16 05:55:19 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netkey/key_var.h>
#include <netinet/in.h>

#ifdef IPV6_INRIA_VERSION
#include <netinet/ipsec.h>
#else
#include <netinet6/ipsec.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
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
#include "vmbuf.h"
#include "misc.h"
#include "plog.h"
#include "debug.h"

#include "cfparse.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "remoteconf.h"
#include "localconf.h"
#include "sockmisc.h"
#include "handler.h"
#include "policy.h"
#include "algorithm.h"
#include "strnames.h"

/*
 * prop_pair: (proposal number, transform number)
 *
 *	(SA (P1 (T1 T2)) (P1' (T1' T2')) (P2 (T1" T2")))
 *
 *              p[1]      p[2]
 *      top     (P1,T1)   (P2",T1")
 *		 |  |tnext     |tnext
 *		 |  v          v
 *		 | (P1, T2)   (P2", T2")
 *		 v next
 *		(P1', T1')
 *		    |tnext
 *		    v
 *		   (P1', T2')
 *
 * when we convert it to ipsecsa in prop2ipsecsa(), it should become like:
 *	{next	<bundle (P1 T1), (P1', T1')>
 *		<bundle (P1 T1), (P1', T2')>
 *		<bundle (P1 T2), (P1', T1')>
 *		<bundle (P1 T2), (P1', T2')>}
 *	{next	(P2" T1")
 *		(P2" T2")}}
 * what a hard job.
 */
struct prop_pair {
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct prop_pair *next;	/* next prop_pair with same proposal # */
				/* (bundle case) */
	struct prop_pair *tnext; /* next prop_pair in same proposal payload */
				/* (multiple tranform case) */
};
#define MAXPROPPAIRLEN	256	/* It's enough because field size is 1 octet. */

static vchar_t *get_ph1approval __P((struct ph1handle *iph1,
	struct prop_pair **pair));
static struct isakmpsa *get_ph1approvalx __P((struct prop_pair *p,
	struct isakmpsa *proposal));
static int t2isakmpsa __P((struct isakmp_pl_t *trns, struct isakmpsa *sa));
static vchar_t *get_ph2approval __P((struct ph2handle *iph2,
	struct prop_pair **pair));
static struct ipsecsa *prop2ipsecsa_emit1 __P((struct prop_pair *p));
static int prop2ipsecsa_emit __P((struct prop_pair **b, size_t max,
	struct ipsecsa **result));
static int prop2ipsecsa_recurse __P((struct prop_pair **b0,
	struct prop_pair **b, size_t l, size_t max, struct ipsecsa **result));
static struct ipsecsa *prop2ipsecsa __P((struct prop_pair *p));
static struct ipsecsa *prop2ipsecsa __P((struct prop_pair *));
static int get_ph2approvalx __P((struct ph2handle *, struct prop_pair *));
#if 0
static const struct ipsecsa *find_proposalmatch
	__P((const struct ipsecsa *p1, const struct ipsecsa *p2));
#endif
static int cmpproposal_bundles __P((const struct ipsecsa *p1,
	const struct ipsecsa *p2));
static int cmpproposal __P((const struct ipsecsa *p1,
	const struct ipsecsa *p2));

static int t2ipsecsa __P((struct isakmp_pl_t *trns, struct ipsecsa *sa));

static void free_proppair __P((struct prop_pair **));
static struct prop_pair **get_proppair
	__P((struct ipsecdoi_pl_sa *sa, int mode));
static int get_transform
	__P((struct isakmp_pl_p *prop, struct prop_pair **pair, int *num_p));
static vchar_t *get_sabyproppair __P((struct prop_pair *pair));
static u_int32_t ipsecdoi_set_ld __P((int type, vchar_t *buf));

static int check_doi __P((u_int32_t));
static int check_situation __P((u_int32_t));

static int check_prot_main __P((int));
static int check_prot_quick __P((int));
static int (*check_protocol[]) __P((int)) = {
	check_prot_main,	/* IPSECDOI_TYPE_PH1 */
	check_prot_quick,	/* IPSECDOI_TYPE_PH2 */
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

static int setph1prop __P((struct isakmpsa *props, caddr_t buf));
static int setph1trns __P((struct isakmpsa *props, caddr_t buf));
static int setph1attr __P((struct isakmpsa *props, caddr_t buf));
#if 0
static int getph2proplen __P((struct ipsecsa *proposal));
#endif
static caddr_t setph2attr __P((caddr_t buf, struct ipsecsa *sa, int *len));
static vchar_t *sockaddr2id __P((struct sockaddr *saddr,
	u_int prefixlen, u_int ul_proto));
static int mksakeys __P((struct ipsecsa *b, struct ipsecsakeys **keys,
	struct sockaddr *dst, struct sockaddr *src));

#ifdef YIPS_DEBUG
static void ipsecdoi_printsa_bundle __P((const struct ipsecsa *));
#endif
static void ipsecdoi_printsa_bundle0 __P((const struct ipsecsa *, int));
static void ipsecdoi_printsa_1 __P((const struct ipsecsa *));

#ifdef YIPS_DEBUG
static void print_proppair0 __P((struct prop_pair *, int));
static void print_proppair __P((struct prop_pair *));
#endif

/*%%%*/
/*
 * check phase 1 SA payload.
 * make new SA payload to be replyed not including general header.
 * the pointer to one of isakmpsa in proposal is set into iph1->approval.
 * OUT:
 *	positive: the pointer to new buffer of SA payload.
 *		  network byte order.
 *	NULL	: error occurd.
 */
int
ipsecdoi_checkph1proposal(sa, iph1)
	struct ipsecdoi_pl_sa *sa;
	struct ph1handle *iph1;
{
	vchar_t *newsa;		/* new SA payload approved. */
	struct prop_pair **pair;

	/* get proposal pair */
	pair = get_proppair(sa, IPSECDOI_TYPE_PH1);
	if (pair == NULL)
		return -1;

	/* check and get one SA for use */
	newsa = get_ph1approval(iph1, pair);
	
	free_proppair(pair);

	if (newsa == NULL)
		return -1;

	/* update some of values in SA header */
	((struct ipsecdoi_sa_b *)newsa->v)->doi = htonl(iph1->rmconf->doitype);
	((struct ipsecdoi_sa_b *)newsa->v)->sit = htonl(iph1->rmconf->sittype);

	iph1->sa_ret = newsa;

	return 0;
}

/*
 * acceptable check for remote configuration.
 * return a new SA payload to be reply to peer.
 */
static vchar_t *
get_ph1approval(iph1, pair)
	struct ph1handle *iph1;
	struct prop_pair **pair;
{
	vchar_t *newsa;
	struct isakmpsa *sa;
	struct prop_pair *s, *p;
	int prophlen;
	int i;

	iph1->approval = NULL;

	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (pair[i] == NULL)
			continue;
		for (s = pair[i]; s; s = s->next) {
			prophlen = sizeof(struct isakmp_pl_p)
					+ s->prop->spi_size;
			/* compare proposal and select one */
			for (p = s; p; p = p->tnext) {
				sa = get_ph1approvalx(p, iph1->rmconf->proposal);
				if (sa != NULL)
					goto found;
			}
		}
	}

	return NULL;

found:
	/* check DH group settings */
	if (sa->dhgrp) {
		if (sa->dhgrp->prime && sa->dhgrp->gen1) {
			/* it's ok */
			goto saok;
		}
		plog(logp, LOCATION, NULL,
			"invalid DH parameter found, use default.\n");
		oakley_dhgrp_free(sa->dhgrp);
	}

	sa->dhgrp = CALLOC(sizeof(struct dhgroup), struct dhgroup *);
	if (!sa->dhgrp) {
		plog(logp, LOCATION, NULL,
			"calloc (%s)\n", strerror(errno));
		return NULL;
	}
	switch (sa->dh_group) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		if (sa->dh_group > ARRAYLEN(dhgroup)
		 || dhgroup[sa->dh_group].type == 0) {
			plog(logp, LOCATION, NULL,
				"invalid DH parameter grp=%d.\n",
				sa->dh_group);
			free(sa->dhgrp);
			sa->dhgrp = NULL;
			return NULL;
			break;
		}
		/* set defined dh vlaues */
		memcpy(sa->dhgrp, &dhgroup[sa->dh_group],
			sizeof(dhgroup[sa->dh_group]));
		sa->dhgrp->prime = vdup(dhgroup[sa->dh_group].prime);
		break;
	default:
		if (!sa->dhgrp->type || !sa->dhgrp->prime || !sa->dhgrp->gen1) {
			break;
		}
	}

saok:
	iph1->approval = sa;

	newsa = get_sabyproppair(s);
	if (newsa == NULL)
		iph1->approval = NULL;

	return newsa;
}

/* compare proposal and select one */
static struct isakmpsa *
get_ph1approvalx(p, proposal)
	struct prop_pair *p;
	struct isakmpsa *proposal;
{
#ifdef YIPS_DEBUG
	struct isakmp_pl_p *prop = p->prop;
#endif
	struct isakmp_pl_t *trns = p->trns;
	struct isakmpsa sa, *s;

	YIPSDEBUG(DEBUG_SA,
		plog(logp, LOCATION, NULL,
	       		"prop#=%d, prot-id=%s, spi-size=%d, #trns=%d\n",
			prop->p_no, s_ipsecdoi_proto(prop->proto_id),
			prop->spi_size, prop->num_t));

	YIPSDEBUG(DEBUG_SA,
		plog(logp, LOCATION, NULL,
			"trns#=%d, trns-id=%s\n",
			trns->t_no,
			s_ipsecdoi_trns(prop->proto_id, trns->t_id)));

	/* XXX Is it good to compare directly ? */
	memset(&sa, 0, sizeof(sa));
	if (t2isakmpsa(trns, &sa) < 0)
		return NULL;
	for (s = proposal; s != NULL; s = s->next) {
		YIPSDEBUG(DEBUG_SA,
			plog(logp, LOCATION, NULL,
				"DB lifetime = %ld\n", s->lifetime);
			plog(logp, LOCATION, NULL,
				"DB lifebyte = %d\n", s->lifebyte);
			plog(logp, LOCATION, NULL,
				"DB enctype = %s\n",
				s_oakley_attr_v(OAKLEY_ATTR_ENC_ALG,
						s->enctype));
			plog(logp, LOCATION, NULL,
				"DB hashtype = %s\n",
				s_oakley_attr_v(OAKLEY_ATTR_HASH_ALG,
						s->authmethod));
			plog(logp, LOCATION, NULL,
				"DB authmethod = %s\n",
				s_oakley_attr_v(OAKLEY_ATTR_AUTH_METHOD,
						s->authmethod));
			plog(logp, LOCATION, NULL,
				"DB dh_group = %s\n",
				s_oakley_attr_v(OAKLEY_ATTR_GRP_DESC,
						s->authmethod));
		);
#if 0
		/* XXX to be considered */
		if (sa.lifetime > s->lifetime) ;
		if (sa.lifebyte > s->lifebyte) ;
		if (sa.encklen >= s->encklen) ;
#endif
		if (sa.enctype == s->enctype
		 && sa.authmethod == s->authmethod
		 && sa.hashtype == s->hashtype
		 && sa.dh_group == s->dh_group)
			break;
	}

	YIPSDEBUG(DEBUG_SA,
		if (s == NULL) {
			plog(logp, LOCATION, NULL,
				"unacceptable proposal.\n");
		} else {
			plog(logp, LOCATION, NULL,
				"acceptable proposal found.\n");
		});

	if (sa.dhgrp != NULL)
		oakley_dhgrp_free(sa.dhgrp);
	return s;
}

/*
 * get ISAKMP data attributes
 */
static int
t2isakmpsa(trns, sa)
	struct isakmp_pl_t *trns;
	struct isakmpsa *sa;
{
	struct isakmp_data *d, *prev;
	int flag, type, lorv;
	int error = -1;
	int life_t;
	int keylen = 0;
	vchar_t *val = NULL;
	int len, tlen;
	u_char *p;

	tlen = ntohs(trns->h.len) - sizeof(*trns);
	prev = (struct isakmp_data *)NULL;
	d = (struct isakmp_data *)(trns + 1);

	/* default */
	sa->lifebyte = 0;
	life_t = OAKLEY_ATTR_SA_LD_TYPE_DEFAULT;
	sa->lifetime = OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
	sa->dhgrp = CALLOC(sizeof(struct dhgroup), struct dhgroup *);
	if (!sa->dhgrp)
		goto err;

	while (tlen > 0) {

		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = d->lorv;

		YIPSDEBUG(DEBUG_DSA,
			plog(logp, LOCATION, NULL,
				"type=%s, flag=0x%04x, lorv=%s\n",
				s_oakley_attr(type), flag,
				s_oakley_attr_v(type, ntohs(lorv))));

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
				len = ntohs(lorv);
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
			sa->enctype = (u_int8_t)ntohs(lorv);
			break;

		case OAKLEY_ATTR_HASH_ALG:
			sa->hashtype = (u_int8_t)ntohs(lorv);
			break;

		case OAKLEY_ATTR_AUTH_METHOD:
			sa->authmethod = (u_int8_t)ntohs(lorv);
			break;

		case OAKLEY_ATTR_GRP_DESC:
			sa->dh_group = (u_int8_t)ntohs(lorv);
			break;

		case OAKLEY_ATTR_GRP_TYPE:
		{
			int type = (int)ntohs(lorv);
			if (type == OAKLEY_ATTR_GRP_TYPE_MODP)
				sa->dhgrp->type = type;
			else
				return -1;
			break;
		}
		case OAKLEY_ATTR_GRP_PI:
			sa->dhgrp->prime = val;
			break;

		case OAKLEY_ATTR_GRP_GEN_ONE:
			vfree(val);
			if (!flag)
				sa->dhgrp->gen1 = ntohs(lorv);
			else {
				int len = ntohs(lorv);
				sa->dhgrp->gen1 = 0;
				if (len > 4)
					return -1;
				memcpy(&sa->dhgrp->gen1, d + 1, len);
				sa->dhgrp->gen1 = ntohl(sa->dhgrp->gen1);
			}
			break;

		case OAKLEY_ATTR_GRP_GEN_TWO:
			vfree(val);
			if (!flag)
				sa->dhgrp->gen2 = ntohs(lorv);
			else {
				int len = ntohs(lorv);
				sa->dhgrp->gen2 = 0;
				if (len > 4)
					return -1;
				memcpy(&sa->dhgrp->gen2, d + 1, len);
				sa->dhgrp->gen2 = ntohl(sa->dhgrp->gen2);
			}
			break;

		case OAKLEY_ATTR_GRP_CURVE_A:
			sa->dhgrp->curve_a = val;
			break;

		case OAKLEY_ATTR_GRP_CURVE_B:
			sa->dhgrp->curve_b = val;
			break;

		case OAKLEY_ATTR_SA_LD_TYPE:
		{
			int type = (int)ntohs(lorv);
			switch (type) {
			case OAKLEY_ATTR_SA_LD_TYPE_SEC:
			case OAKLEY_ATTR_SA_LD_TYPE_KB:
				life_t = type;
				break;
			default:
				life_t = OAKLEY_ATTR_SA_LD_TYPE_DEFAULT;
				break;
			}
			break;
		}
		case OAKLEY_ATTR_SA_LD:
		    {
			u_int32_t t;

			if (!life_t || !prev
			 || (ntohs(prev->type) & ~ISAKMP_GEN_MASK) !=
					OAKLEY_ATTR_SA_LD_TYPE) {
				plog(logp, LOCATION, NULL,
				    "life duration must follow ltype\n");
				break;
			}

			switch (life_t) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
				t = ipsecdoi_set_ld(life_t, val);
				if (t == ~0)
					sa->lifetime = OAKLEY_ATTR_SA_LD_SEC_DEFAULT;
				else
					sa->lifetime = ipsecdoi_set_ld(life_t, val);
				break;
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				t = ipsecdoi_set_ld(life_t, val);
				if (t == ~0)
					sa->lifebyte = 0;	/*XXX*/
				else
					sa->lifebyte = t;

				break;
			}
			vfree(val);
		    }
			break;

		case OAKLEY_ATTR_KEY_LEN:
		{
			int len = ntohs(lorv);
			if (len % 8 != 0) {
				plog(logp, LOCATION, NULL,
					"keylen %d: not multiple of 8\n",
					len);
				goto err;
			}
			sa->encklen = (u_int8_t)len;
			keylen++;
			break;
		}
		case OAKLEY_ATTR_PRF:
		case OAKLEY_ATTR_FIELD_SIZE:
			/* unsupported */
			break;

		case OAKLEY_ATTR_GRP_ORDER:
			sa->dhgrp->order = val;
			break;

		default:
			break;
		}

		prev = d;
		if (flag) {
			tlen -= sizeof(*d);
			d = (struct isakmp_data *)((char *)d + sizeof(*d));
		} else {
			tlen -= (sizeof(*d) + ntohs(lorv));
			d = (struct isakmp_data *)((char *)d + sizeof(*d) + ntohs(lorv));
		}
	}

	/* key length must not be specified on some algorithms */
	if (keylen) {
		switch (sa->enctype) {
		case OAKLEY_ATTR_ENC_ALG_DES:
		case OAKLEY_ATTR_ENC_ALG_IDEA:
		case OAKLEY_ATTR_ENC_ALG_3DES:
			plog(logp, LOCATION, NULL,
				"keylen must not be specified for encryption algorithm %d\n",
				sa->enctype);
			goto err;
		case OAKLEY_ATTR_ENC_ALG_BLOWFISH:
		case OAKLEY_ATTR_ENC_ALG_RC5:
		case OAKLEY_ATTR_ENC_ALG_CAST:
			break;
		default:
			plog(logp, LOCATION, NULL,
				"unknown encryption algorithm %d\n",
				sa->enctype);
			goto err;
		}
	}

	return 0;
err:
	return error;
}

/*
 * check phase 2 SA payload.
 * make new SA payload to be replyed not including general header.
 * the pointer to one of ipsecsa in proposal is set into iph2->approval.
 * OUT:
 *	positive: the pointer to new buffer of SA payload.
 *		  network byte order.
 *	NULL	: error occurd.
 */
int
ipsecdoi_checkph2proposal(sa, iph2)
	struct ipsecdoi_pl_sa *sa;
	struct ph2handle *iph2;
{
	vchar_t *newsa;		/* new SA payload approved. */
	struct prop_pair **pair;

	/* get proposal pair */
	pair = get_proppair(sa, IPSECDOI_TYPE_PH2);
	if (pair == NULL)
		return -1;

	/* check and get one SA for use */
	newsa = get_ph2approval(iph2, pair);

	free_proppair(pair);

	if (newsa == NULL)
		return -1;

	/* update some of values in SA header */
	((struct ipsecdoi_sa_b *)newsa->v)->doi = htonl(iph2->ph1->rmconf->doitype);
	((struct ipsecdoi_sa_b *)newsa->v)->sit = htonl(iph2->ph1->rmconf->sittype);

	iph2->sa_ret = newsa;

	return 0;
}

/*
 * acceptable check for policy configuration.
 * return a new SA payload to be reply to peer.
 */
static vchar_t *
get_ph2approval(iph2, pair)
	struct ph2handle *iph2;
	struct prop_pair **pair;
{
	vchar_t *newsa;
	struct prop_pair *s;
	int prophlen;
	int i;

	/* sanity */
	if (iph2->spidx == NULL) {
		plog(logp, LOCATION, NULL, "no policy index found. why ?\n");
		return NULL;
	}

#if 0
	if (iph2->approval)
		delipsecsa(iph2->approval);
#endif
	iph2->approval = NULL;

	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (pair[i] == NULL)
			continue;
		YIPSDEBUG(DEBUG_SA, plog(logp, LOCATION, NULL, "pair[%d]: %p\n",
			i, pair[i]);
			print_proppair(pair[i]););

		s = pair[i];
		prophlen = sizeof(struct isakmp_pl_p)
				+ s->prop->spi_size;
		/* compare proposal and select one */
		if (get_ph2approvalx(iph2, s) == 0)
			goto found;
	}

	plog(logp, LOCATION, NULL, "no suitable policy found.\n");

	return NULL;

found:
	newsa = get_sabyproppair(s);
	if (newsa == NULL) {
#if 0
		if (iph2->approval)
			delipsecsa(iph2->approval);
#endif
		iph2->approval = NULL;
	}

	return newsa;
}

static struct ipsecsa *
prop2ipsecsa_emit1(p)
	struct prop_pair *p;
{
	struct ipsecsa *q;

#if 0
	YIPSDEBUG(DEBUG_SA, plog(logp, LOCATION, NULL, "param: %p\n", p);
		print_proppair(p););
#endif
	q = CALLOC(sizeof(struct ipsecsa), struct ipsecsa *);
	if (q == NULL)
		return NULL;

	/* XXX structure of ipsecsa may be strange. should be fix ? */
	q->proto_id = p->prop->proto_id;
	if (q->proto_id == IPSECDOI_PROTO_IPSEC_ESP)
		q->enctype = p->trns->t_id;
	if (q->proto_id == IPSECDOI_PROTO_IPCOMP)
		q->comptype = p->trns->t_id;

	/* XXX this should belong to elsewhere */
	if (sizeof(q->spi) >= p->prop->spi_size) {
		q->spisize = p->prop->spi_size;
		memcpy(&q->spi, p->prop + 1, p->prop->spi_size);
	} else {
		free(q);
		return NULL;
	}

	if (t2ipsecsa(p->trns, q) < 0) {
		free(q);
		return NULL;
	}

#if 0
	YIPSDEBUG(DEBUG_SA,
		plog(logp, LOCATION, NULL, "result: %p\n", q);
		ipsecdoi_printsa(q););
#endif

	return q;
}

static int
prop2ipsecsa_emit(b, max, result)
	struct prop_pair **b;
	size_t max;
	struct ipsecsa **result;
{
	size_t i;
	struct ipsecsa top, *q;

	memset(&top, 0, sizeof(top));
	q = &top;
	for (i = 0; i < max; i++) {
#if 0
		YIPSDEBUG(DEBUG_SA, plog(logp, LOCATION, NULL, "param[%d]: %p\n", i, b[i]);
			print_proppair(b[i]););
#endif
		q->bundles = prop2ipsecsa_emit1(b[i]);
#if 0
		YIPSDEBUG(DEBUG_SA, plog(logp, LOCATION, NULL, "got %p from %p\n", q->bundles, b[i]););
#endif
		if (q->bundles == NULL) {
			delipsecsa(top.next);
			return -1;
		}
		q = q->bundles;
	}
	top.bundles->next = *result;
	*result = top.bundles;

#if 0
	YIPSDEBUG(DEBUG_SA,
		plog(logp, LOCATION, NULL, "%p\n", *result);
		ipsecdoi_printsa_bundle(*result););
#endif

	return 0;
}

static int
prop2ipsecsa_recurse(b0, b, l, max, result)
	struct prop_pair **b0;
	struct prop_pair **b;
	size_t l;
	size_t max;
	struct ipsecsa **result;
{
	int ret = 0;
	size_t i;

	for (b[l] = b0[l]; b[l]; b[l] = b[l]->tnext) {
		if (l + 1 < max) {
			ret = prop2ipsecsa_recurse(b0, b, l + 1, max, result);
			if (ret)
				break;
		} else {
			for (i = 0; i < max; i++)
				printf(" %ld=%p", (long)i, b[i]);
			printf("\n");
			ret = prop2ipsecsa_emit(b, max, result);
#if 0
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL, "%p\n", result);
				ipsecdoi_printsa(*result););
#endif
			if (ret)
				break;
		}
	}

	return ret;
}

static struct ipsecsa *
prop2ipsecsa(p)
	struct prop_pair *p;
{
	struct prop_pair **b, **b0;
	struct prop_pair *q;
	size_t l, max;
	struct ipsecsa top;

	max = 0;
	for (q = p; q; q = q->next)
		max++;
	b0 = CALLOC(sizeof(struct prop_pair *) * max, struct prop_pair **);
	if (b0 == NULL)
		return NULL;
	b = CALLOC(sizeof(struct prop_pair *) * max, struct prop_pair **);
	if (b == NULL)
		return NULL;

	/* b[n] contains pointer to bundle proposal */
	l = 0;
	for (q = p; q; q = q->next)
		b0[l++] = q;

	memset(&top, 0, sizeof(top));
	if (prop2ipsecsa_recurse(b0, b, 0, max, &top.next)) {
		delipsecsa(top.next);
		return NULL;
	}
	return top.next;
}

/* compare my proposal and peers proposal. */
static int
get_ph2approvalx(iph2, p)
	struct ph2handle *iph2;
	struct prop_pair *p;
{
	const struct ipsecsa *proposal = iph2->spidx->policy->proposal;
	struct ipsecsa *sa;
	struct ipsecsa *r;

	YIPSDEBUG(DEBUG_SA, plog(logp, LOCATION, NULL, "begin.\n"));

	YIPSDEBUG(DEBUG_SA,
		plog(logp, LOCATION, NULL,
	       		"prop#=%d prot-id=%s spi-size=%d #trns=%d "
			"trns#=%d trns-id=%s\n",
			p->prop->p_no, s_ipsecdoi_proto(p->prop->proto_id),
			p->prop->spi_size, p->prop->num_t,
			p->trns->t_no,
			s_ipsecdoi_trns(p->prop->proto_id, p->trns->t_id)));

	sa = prop2ipsecsa(p);
	if (sa == NULL)
		return -1;

	YIPSDEBUG(DEBUG_DSA,
		plog(logp, LOCATION, NULL, "peer's full proposal:\n");
		ipsecdoi_printsa(sa););
	YIPSDEBUG(DEBUG_DSA,
		plog(logp, LOCATION, NULL, "my full proposal:\n");
		ipsecdoi_printsa(proposal););

    {
	const struct ipsecsa *q1;
	const struct ipsecsa *q2;

	for (q1 = sa; q1; q1 = q1->next) {
		for (q2 = proposal; q2; q2 = q2->next) {
			YIPSDEBUG(DEBUG_DSA,
				plog(logp, LOCATION, NULL,
					"peer's single bundle:\n");
				ipsecdoi_printsa_bundle(q1););
			YIPSDEBUG(DEBUG_DSA,
				plog(logp, LOCATION, NULL,
					"my single bundle:\n");
				ipsecdoi_printsa_bundle(q2););

			if (cmpproposal_bundles(q1, q2) == 0)
				goto found;

			YIPSDEBUG(DEBUG_DSA,
				plog(logp, LOCATION, NULL, "not matched\n"););
		}
	}
	delipsecsa(sa);
	return -1;

found:
	YIPSDEBUG(DEBUG_DSA, plog(logp, LOCATION, NULL, "matched\n"););
	if (q1 == NULL) {
		YIPSDEBUG(DEBUG_SA, plog(logp, LOCATION, NULL,
				"no acceptable proposal found.\n"));
		return -1;
	}

	/* duplicate the result for future modification */
	r = dupipsecsa(q1);
	r->ipsp = NULL;
	delipsecsa(r->next);
	r->next = NULL;

	delipsecsa(sa);
	sa = NULL;
    }

	if (iph2->side == RESPONDER) {
#if 0
		if (iph2->approval)
			delipsecsa(iph2->approval);
#endif
		iph2->approval = r;
		/* ipsecsa keys from approval */
		if (ipsecdoi_initsakeys(iph2) < 0) {
			plog(logp, LOCATION, NULL,
				"failed to get variable spece for phase2.\n");
			delipsecsa(sa);
			return -1;
		}
	}

    {
	/* set peer's spi from proposal payload */
	struct sockaddr *dst;
	struct ipsecsakeys *k;
	struct ipsecsa *q1;

	for (q1 = r; q1; q1 = q1->bundles) {
		dst = q1->dst ? q1->dst : iph2->dst; /* XXX cheat */
		for (k = iph2->keys; k != NULL; k = k->next) {
			if (q1->proto_id == k->proto_id
			 && q1->encmode == k->encmode
			 && (cmpsaddrwop(dst, k->dst) == 0))
				break;
		}
		if (k == NULL) {
			plog(logp, LOCATION, NULL,
				"no SPI found for %s/%s\n",
				s_ipsecdoi_proto(q1->proto_id),
				saddrwop2str(dst));
			delipsecsa(q1);
			return -1;
		}
		/* special case for IPComp CPI - accept two-byte CPI */
		if (q1->spisize == 2 && q1->proto_id == IPSECDOI_PROTO_IPCOMP) {
			u_int16_t t[2];
			memset(&t, 0, sizeof(t));
			memcpy(&t[1], &q1->spi, q1->spisize);
			memset(&q1->spi, 0, sizeof(q1->spi));
			memcpy(&q1->spi, &t, sizeof(t));
			q1->spisize = sizeof(t);
		} else if (q1->spisize != sizeof(k->spi_p)) {
			plog(logp, LOCATION, NULL,
				"spi size mismatch, %d/%d\n",
				q1->spisize, sizeof(k->spi_p));
			delipsecsa(q1);
			return -1;
		}
		memcpy(&k->spi_p, &q1->spi, q1->spisize);
	}
    }

#if 0
	if (iph2->approval)
		delipsecsa(iph2->approval);
#endif
	iph2->approval = r;

	return 0;
}

#if 0
/*
 * take a match against proposals (which is a linked list of bundles).
 * returns element from first argument only.
 */
static const struct ipsecsa *
find_proposalmatch(p1, p2)
	const struct ipsecsa *p1;
	const struct ipsecsa *p2;
{
	const struct ipsecsa *q1;
	const struct ipsecsa *q2;

	YIPSDEBUG(DEBUG_DSA,
		plog(logp, LOCATION, NULL, "peer's single bundle:\n");
		ipsecdoi_printsa_bundle(p1););
	YIPSDEBUG(DEBUG_DSA,
		plog(logp, LOCATION, NULL, "my single bundle:\n");
		ipsecdoi_printsa_bundle(p2););

	for (q1 = p1; q1; q1 = q1->next) {
		for (q2 = p2; q2; q2 = q2->next) {
			if (cmpproposal_bundles(q1, q2) == 0)
				goto found;
		}
	}
	YIPSDEBUG(DEBUG_DSA, plog(logp, LOCATION, NULL, "not matched\n"););
	return NULL;

found:
	YIPSDEBUG(DEBUG_DSA, plog(logp, LOCATION, NULL, "matched\n"););
	return q1;
}
#endif

/*
 * take a complete match against bundles.  the order must match as well.
 * 0 if equal.
 */
static int
cmpproposal_bundles(p1, p2)
	const struct ipsecsa *p1;
	const struct ipsecsa *p2;
{
	const struct ipsecsa *q1;
	const struct ipsecsa *q2;

	q1 = p1;
	q2 = p2;
	while (q1 && q2) {
		if (cmpproposal(q1, q2) != 0)
			goto fail;
		q1 = q1->bundles;
		q2 = q2->bundles;
	}

	/* if the length of bundles is different, they don't match */
	if (q1 || q2)
		goto fail;

	return 0;

fail:
	return 1;
}

/* take a single match betwee ipsecsa.  0 if equal. */
static int
cmpproposal(p1, p2)
	const struct ipsecsa *p1;
	const struct ipsecsa *p2;
{
	if (p1->proto_id != p2->proto_id)
		goto fail;
	if (p1->encmode != p2->encmode)
		goto fail;
#if 0
	/* XXX to be considered */
	if (p1->lifetime > p2->lifetime) ;
	if (p1->lifebyte > p2->lifebyte) ;
	if (p1->encklen >= p2->encklen) ;
#endif

	switch (p1->proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (p1->enctype != p2->enctype || p1->authtype != p2->authtype)
			goto fail;
		break;
	case IPSECDOI_PROTO_IPSEC_AH:
		if (p1->authtype != p2->authtype)
			goto fail;
		break;
	case IPSECDOI_PROTO_IPCOMP:
		if (p1->comptype != p2->comptype)
			goto fail;
		break;
	default:
		plog(logp, LOCATION, NULL,
			"invalid proto_id found %d\n", p1->proto_id);
		goto fail;
	}

	return 0;
fail:
	return 1;
}

/*
 * get IPsec data attributes
 */
static int
t2ipsecsa(trns, sa)
	struct isakmp_pl_t *trns;
	struct ipsecsa *sa;
{
	struct isakmp_data *d, *prev;
	int flag, type, lorv;
	int error = -1;
	int life_t;
	int tlen;

	tlen = ntohs(trns->h.len) - sizeof(*trns);
	prev = (struct isakmp_data *)NULL;
	d = (struct isakmp_data *)(trns + 1);

	/* default */
	sa->lifebyte = 0;
	life_t = IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT;
	sa->lifetime = IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;

	while (tlen > 0) {

		type = ntohs(d->type) & ~ISAKMP_GEN_MASK;
		flag = ntohs(d->type) & ISAKMP_GEN_MASK;
		lorv = d->lorv;

		YIPSDEBUG(DEBUG_DSA,
			plog(logp, LOCATION, NULL,
				"type=%s, flag=0x%04x, lorv=%s\n",
				s_ipsecdoi_attr(type), flag,
				s_ipsecdoi_attr_v(type, ntohs(lorv))));

		switch (type) {
		case IPSECDOI_ATTR_SA_LD_TYPE:
		{
			int type = ntohs(lorv);
			switch (type) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				life_t = type;
				break;
			default:
				plog(logp, LOCATION, NULL,
				    "Warning of invalid life duration type.\n");
				life_t = IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT;
				break;
			}
			break;
		}
		case IPSECDOI_ATTR_SA_LD:
			if (life_t == NULL
			 || prev == NULL
			 || (ntohs(prev->type) & ~ISAKMP_GEN_MASK) !=
					IPSECDOI_ATTR_SA_LD_TYPE) {
				plog(logp, LOCATION, NULL,
				    "life duration must follow ltype\n");
				break;
			}

		    {
			vchar_t *ld_buf = NULL;
			u_int32_t t;
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				ld_buf = vmalloc(sizeof(d->lorv));
				if (ld_buf == NULL) {
					plog(logp, LOCATION, NULL,
					    "vmalloc (%s)\n", strerror(errno));
					goto end;
				}
				memcpy(ld_buf->v, &lorv, sizeof(d->lorv));
			} else {
				int len = ntohs(lorv);
				/* i.e. ISAKMP_GEN_TLV */
				ld_buf = vmalloc(len);
				if (ld_buf == NULL) {
					plog(logp, LOCATION, NULL,
					    "vmalloc (%s)\n", strerror(errno));
					goto end;
				}
				memcpy(ld_buf->v, d + 1, len);
			}
			switch (life_t) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
				t = ipsecdoi_set_ld(life_t, ld_buf);
				if (t == ~0)
					sa->lifetime = IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;
				else
					sa->lifetime = t;
				break;
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				t = ipsecdoi_set_ld(life_t, ld_buf);
				if (t == ~0)
					sa->lifebyte = 0;	/*XXX*/
				else
					sa->lifebyte = t;
				break;
			}
			vfree(ld_buf);
		    }
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			/*
			 * RFC2407: 4.5 IPSEC Security Association Attributes
			 *   Specifies the Oakley Group to be used in a PFS QM
			 *   negotiation.  For a list of supported values, see
			 *   Appendix A of [IKE].
			 */
			sa->pfs_group = (u_int8_t)ntohs(lorv);
			break;

		case IPSECDOI_ATTR_ENC_MODE:
			sa->encmode = (u_int8_t)ntohs(lorv);
			break;

		case IPSECDOI_ATTR_AUTH:
			sa->authtype = (u_int8_t)ntohs(lorv);
			break;

		case IPSECDOI_ATTR_KEY_LENGTH:
			sa->encklen = ntohs(lorv);
			break;

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
			tlen -= (sizeof(*d) + ntohs(lorv));
			d = (struct isakmp_data *)((caddr_t)d + sizeof(*d) + ntohs(lorv));
		}
	}

	error = 0;
end:
	return error;
}

static void
free_proppair(pair)
	struct prop_pair **pair;
{
	struct prop_pair *p, *q;
	int i;

	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		for (p = pair[i]; p; p = q) {
			q = p->next;
			free(p);
		}
		pair[i] = NULL;
	}
	free(pair);
}

/*
 * get proposal pairs from SA payload.
 * tiny check for proposal payload.
 */
static struct prop_pair **
get_proppair(sa, mode)
	struct ipsecdoi_pl_sa *sa;
	int mode;
{
	struct prop_pair **pair;
	int num_p = 0;			/* number of proposal for use */
	int tlen;
	caddr_t bp;
	int i;

	YIPSDEBUG(DEBUG_SA,
		plog(logp, LOCATION, NULL,
			"total SA len=%d\n", ntohs(sa->h.len)));
	YIPSDEBUG(DEBUG_DSA, hexdump(sa, ntohs(sa->h.len)));

	/* check DOI */
	if (check_doi(ntohl(sa->b.doi)) < 0)
		return NULL;

	/* check SITUATION */
	if (check_situation(ntohl(sa->b.sit)) < 0)
		return NULL;

	pair = CALLOC(MAXPROPPAIRLEN * sizeof(*pair), struct prop_pair **);
	if (pair == NULL) {
		plog(logp, LOCATION, NULL,
			"calloc (%s)\n", strerror(errno));
		return NULL;
	}
	memset(pair, 0, sizeof(pair));

	bp = (caddr_t)(sa + 1);
	tlen = ntohs(sa->h.len) - sizeof(*sa);

	if (tlen <= 0) {
		plog(logp, LOCATION, NULL,
			"Invalid length of SA payload = %d.\n",
			tlen + sizeof(*sa));
		return NULL;
	}

    {
	struct isakmp_pl_p *prop;
	int proplen;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	pbuf = isakmp_parsewoh(ISAKMP_NPTYPE_P, (struct isakmp_gen *)bp, tlen);
	if (pbuf == NULL)
		return NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {
		/* check the value of next payload */
		if (pa->type != ISAKMP_NPTYPE_P) {
			plog(logp, LOCATION, NULL,
				"Invalid payload type=%u\n", pa->type);
			return NULL;
		}

		prop = (struct isakmp_pl_p *)pa->ptr;
		proplen = pa->len;

		YIPSDEBUG(DEBUG_SA,
			plog(logp, LOCATION, NULL,
				"proposal #%u len=%d\n", prop->p_no, proplen));

		if (proplen == 0) {
			plog(logp, LOCATION, NULL,
				"invalid proposal with length %d\n", proplen);
			return NULL;
		}

		/* check Protocol ID */
		if (!check_protocol[mode]) {
			plog(logp, LOCATION, NULL,
				"unsupported mode %d\n", mode);
			continue;
		}

		if (check_protocol[mode](prop->proto_id) < 0)
			continue;

		/* check SPI length when IKE. */
		if (check_spi_size(prop->proto_id, prop->spi_size) < 0)
			continue;

		/* check the number of transform */
		if (prop->num_t == 0) {
			plog(logp, LOCATION, NULL,
				"Illegal the number of transform. num_t=%u\n",
				prop->num_t);
			continue;
		}

		/* get transform */
		get_transform(prop, pair, &num_p);
	}
	vfree(pbuf);
	pbuf = NULL;
    }

    {
	int notrans, nprop;
	struct prop_pair *p, *q;

	/* check for proposals with no transforms */
	for (i = 0; i < MAXPROPPAIRLEN; i++) {
		if (!pair[i])
			continue;

		YIPSDEBUG(DEBUG_SA,
			printf("pair %d:\n", i);
			print_proppair(pair[i]););

		notrans = nprop = 0;
		for (p = pair[i]; p; p = p->next) {
			if (p->trns == NULL) {
				notrans++;
				break;
			}
			for (q = p; q; q = q->tnext)
				nprop++;
		}

#if 0
		/*
		 * XXX at this moment, we cannot accept proposal group
		 * with multiple proposals.  this should be fixed.
		 */
		if (pair[i]->next) {
			plog(logp, LOCATION, NULL,
				"proposal #%u ignored "
				"(multiple proposal not supported)\n",
				pair[i]->prop->p_no);
			notrans++;
		}
#endif

		if (notrans) {
			for (p = pair[i]; p; p = q) {
				q = p->next;
				free(p);
			}
			pair[i] = NULL;
			num_p--;
		} else {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"proposal #%u: %d transform\n",
					pair[i]->prop->p_no, nprop));
		}
	}
    }

	/* bark if no proposal is found. */
	if (num_p <= 0) {
		plog(logp, LOCATION, NULL,
			"no Proposal found.\n");
		return NULL;
	}

	return pair;
}

/*
 * check transform payload.
 * OUT:
 *	positive: return the pointer to the payload of valid transform.
 *	0	: No valid transform found.
 */
static int
get_transform(prop, pair, num_p)
	struct isakmp_pl_p *prop;
	struct prop_pair **pair;
	int *num_p;
{
	int tlen; /* total length of all transform in a proposal */
	caddr_t bp;
	struct isakmp_pl_t *trns;
	int trnslen;
	vchar_t *pbuf;
	struct isakmp_parse_t *pa;
	struct prop_pair *p = NULL, *q;

	bp = (caddr_t)prop + sizeof(struct isakmp_pl_p) + prop->spi_size;
	tlen = ntohs(prop->h.len)
		- (sizeof(struct isakmp_pl_p) + prop->spi_size);
	pbuf = isakmp_parsewoh(ISAKMP_NPTYPE_T, (struct isakmp_gen *)bp, tlen);
	if (pbuf == NULL)
		return -1;

	/* check and get transform for use */
	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {
		/* check the value of next payload */
		if (pa->type != ISAKMP_NPTYPE_T) {
			plog(logp, LOCATION, NULL,
				"Invalid payload type=%u\n", pa->type);
			break;
		}

		trns = (struct isakmp_pl_t *)pa->ptr;
		trnslen = pa->len;

		YIPSDEBUG(DEBUG_SA,
			plog(logp, LOCATION, NULL,
				"transform #%u len=%u\n", trns->t_no, trnslen));

		/* check transform ID */
		if (prop->proto_id >= ARRAYLEN(check_transform)) {
			plog(logp, LOCATION, NULL,
				"unsupported proto_id %u\n", prop->proto_id);
			continue;
		}
		if (prop->proto_id >= ARRAYLEN(check_attributes)) {
			plog(logp, LOCATION, NULL,
				"unsupported proto_id %u\n", prop->proto_id);
			continue;
		}

		if (!check_transform[prop->proto_id]
		 || !check_attributes[prop->proto_id]) {
			plog(logp, LOCATION, NULL,
				"unsupported proto_id %u\n", prop->proto_id);
			continue;
		}
		if (check_transform[prop->proto_id](trns->t_id) < 0)
			continue;

		/* check data attributes */
		if (check_attributes[prop->proto_id](trns) != 0)
			continue;

		p = CALLOC(sizeof(*p), struct prop_pair *);
		if (p == NULL) {
			plog(logp, LOCATION, NULL,
				"calloc (%s)\n", strerror(errno));
			return -1;
		}
		p->prop = prop;
		p->trns = trns;

		/* need to preserve the order */
		for (q = pair[prop->p_no]; q && q->next; q = q->next)
			;
		if (q && q->prop == p->prop) {
			for (/*nothing*/; q && q->tnext; q = q->tnext)
				;
			q->tnext = p;
		} else {
			if (q)
				q->next = p;
			else {
				pair[prop->p_no] = p;
				(*num_p)++;
			}
		}
	}

	vfree(pbuf);

	return 0;
}

/*
 * make a new SA payload from prop_pair.
 */
static vchar_t *
get_sabyproppair(pair)
	struct prop_pair *pair;
{
	vchar_t *newsa;
	int newtlen;
	u_int8_t *np_p = NULL;
	struct prop_pair *p;
	int prophlen, trnslen;
	caddr_t bp;

	newtlen = sizeof(struct ipsecdoi_sa_b);
	for (p = pair; p; p = p->next) {
		newtlen += (sizeof(struct isakmp_pl_p)
				+ p->prop->spi_size
				+ ntohs(p->trns->h.len));
	}

	newsa = vmalloc(newtlen);
	if (newsa == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno)); 
		return NULL;
	}
	bp = newsa->v;

	/* some of values of SA must be updated in the out of this function */
	((struct isakmp_gen *)bp)->len = htons(newtlen);
	bp += sizeof(struct ipsecdoi_sa_b);

	/* create proposal payloads */
	for (p = pair; p; p = p->next) {
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

	return newsa;
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
		plog(logp, LOCATION, NULL,
			"length %d of life duration "
			"isn't supported.\n", buf->l);
		return ~0;
	}

	return ld;
}

/*%%%*/
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
		plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
			"situation 0x%08x unsupported yet.\n", sit);
		return -1;

	default:
		plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
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
			plog(logp, LOCATION, NULL,
				"SPI size isn't zero, but IKE proposal.\n");
		}
		return 0;

	case IPSECDOI_PROTO_IPSEC_AH:
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (size != 4) {
			plog(logp, LOCATION, NULL,
				"invalid SPI size=%d for IPSEC proposal.\n",
				size);
			return -1;
		}
		return 0;

	case IPSECDOI_PROTO_IPCOMP:
		if (size != 2 && size != 4) {
			plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
			"not support transform-id=%u in AH.\n", t_id);
		return -1;
	default:
		plog(logp, LOCATION, NULL,
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
	case IPSECDOI_ESP_RC5:
	case IPSECDOI_ESP_CAST:
	case IPSECDOI_ESP_BLOWFISH:
		return 0;
	case IPSECDOI_ESP_DES_IV32:
	case IPSECDOI_ESP_DES_IV64:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_RC4:
		plog(logp, LOCATION, NULL,
			"not support transform-id=%u in ESP.\n", t_id);
		return -1;
	default:
		plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
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
			plog(logp, LOCATION, NULL,
				"type=%s, flag=0x%04x, lorv=%s\n",
				s_oakley_attr(type), flag,
				s_oakley_attr_v(type, lorv)));

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
				plog(logp, LOCATION, NULL,
					"oakley attribute %d must be TV.\n",
					type);
				return -1;
			}
			break;
		}

		/* sanity check for TLV.  length must be specified. */
		if (!flag && lorv == 0) {	/*TLV*/
			plog(logp, LOCATION, NULL,
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
				plog(logp, LOCATION, NULL,
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
				plog(logp, LOCATION, NULL,
					"hash algorithm %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(logp, LOCATION, NULL,
					"invalid hash algorithm %d.\n",
					lorv);
				return -1;
			}
			break;

		case OAKLEY_ATTR_AUTH_METHOD:
			switch (lorv) {
			case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
			case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
				break;
			case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
			case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
			case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
				plog(logp, LOCATION, NULL,
					"auth method %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(logp, LOCATION, NULL,
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
				plog(logp, LOCATION, NULL,
					"DH group %d isn't supported.\n",
					lorv);
				return -1;
			default:
				if (lorv >= 32768)	/*private group*/
					break;
				plog(logp, LOCATION, NULL,
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
				plog(logp, LOCATION, NULL,
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
			plog(logp, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		case OAKLEY_ATTR_SA_LD_TYPE:
			switch (lorv) {
			case OAKLEY_ATTR_SA_LD_TYPE_SEC:
			case OAKLEY_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(logp, LOCATION, NULL,
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
			plog(logp, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		case OAKLEY_ATTR_GRP_ORDER:
			break;

		default:
			plog(logp, LOCATION, NULL,
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
			plog(logp, LOCATION, NULL,
				"type=%s, flag=0x%04x, lorv=%s\n",
				s_ipsecdoi_attr(type), flag,
				s_ipsecdoi_attr_v(type, lorv)));

		if (type < sizeof(attrseen)/sizeof(attrseen[0]))
			attrseen[type]++;

		switch (type) {
		case IPSECDOI_ATTR_ENC_MODE:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when ENC_MODE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
			case IPSECDOI_ATTR_ENC_MODE_TRNS:
				break;
			default:
				plog(logp, LOCATION, NULL,
					"invalid encryption mode=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_AUTH:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when AUTH.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_AUTH_HMAC_MD5:
				if (proto_id == IPSECDOI_PROTO_IPSEC_AH
				 && trns->t_id != IPSECDOI_AH_MD5) {
ahmismatch:
					plog(logp, LOCATION, NULL,
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
				plog(logp, LOCATION, NULL,
					"auth algorithm %u isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(logp, LOCATION, NULL,
					"invalid auth algorithm=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD_TYPE:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when LD_TYPE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(logp, LOCATION, NULL,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				/* warning */
				plog(logp, LOCATION, NULL,
					"should be TLV when LD.\n");
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if (lorv == 0) {
					plog(logp, LOCATION, NULL,
						"invalid length of LD\n");
					return -1;
				}

				/* XXX to be checked the value of duration. */
				/* i.g. too short duration */
			}
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when GRP_DESC.\n");
				return -1;
			}

			switch (lorv) {
			case OAKLEY_ATTR_GRP_DESC_MODP768:
			case OAKLEY_ATTR_GRP_DESC_MODP1024:
			case OAKLEY_ATTR_GRP_DESC_MODP1536:
				break;
			case OAKLEY_ATTR_GRP_DESC_EC2N155:
			case OAKLEY_ATTR_GRP_DESC_EC2N185:
				plog(logp, LOCATION, NULL,
					"DH group %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(logp, LOCATION, NULL,
					"invalid group description=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_KEY_LENGTH:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when KEY_LENGTH.\n");
				return -1;
			}
			break;

		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
			plog(logp, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		default:
			plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
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
			plog(logp, LOCATION, NULL,
				"type=%d, flag=0x%04x, lorv=0x%04x\n",
				type, flag, lorv));

		if (type < sizeof(attrseen)/sizeof(attrseen[0]))
			attrseen[type]++;

		switch (type) {
		case IPSECDOI_ATTR_ENC_MODE:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when ENC_MODE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
			case IPSECDOI_ATTR_ENC_MODE_TRNS:
				break;
			default:
				plog(logp, LOCATION, NULL,
					"invalid encryption mode=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD_TYPE:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when LD_TYPE.\n");
				return -1;
			}

			switch (lorv) {
			case IPSECDOI_ATTR_SA_LD_TYPE_SEC:
			case IPSECDOI_ATTR_SA_LD_TYPE_KB:
				break;
			default:
				plog(logp, LOCATION, NULL,
					"invalid life type %d.\n", lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_SA_LD:
			if (flag) {
				/* i.e. ISAKMP_GEN_TV */
				/* warning */
				plog(logp, LOCATION, NULL,
					"should be TLV when LD.\n");
			} else {
				/* i.e. ISAKMP_GEN_TLV */
				if (lorv == 0) {
					plog(logp, LOCATION, NULL,
						"invalid length of LD\n");
					return -1;
				}

				/* XXX to be checked the value of duration. */
				/* i.g. too short duration */
			}
			break;

		case IPSECDOI_ATTR_GRP_DESC:
			if (! flag) {
				plog(logp, LOCATION, NULL,
					"must be TV when GRP_DESC.\n");
				return -1;
			}

			switch (lorv) {
			case OAKLEY_ATTR_GRP_DESC_MODP768:
			case OAKLEY_ATTR_GRP_DESC_MODP1024:
			case OAKLEY_ATTR_GRP_DESC_MODP1536:
				break;
			case OAKLEY_ATTR_GRP_DESC_EC2N155:
			case OAKLEY_ATTR_GRP_DESC_EC2N185:
				plog(logp, LOCATION, NULL,
					"DH group %d isn't supported.\n",
					lorv);
				return -1;
			default:
				plog(logp, LOCATION, NULL,
					"invalid group description=%u.\n",
					lorv);
				return -1;
			}
			break;

		case IPSECDOI_ATTR_AUTH:
			plog(logp, LOCATION, NULL, "invalid attr type=%u.\n", type);
			return -1;

		case IPSECDOI_ATTR_KEY_LENGTH:
		case IPSECDOI_ATTR_KEY_ROUNDS:
		case IPSECDOI_ATTR_COMP_DICT_SIZE:
		case IPSECDOI_ATTR_COMP_PRIVALG:
			plog(logp, LOCATION, NULL,
				"attr type=%u isn't supported.\n", type);
			return -1;

		default:
			plog(logp, LOCATION, NULL,
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
		plog(logp, LOCATION, NULL,
			"attr AUTH must be present for AH.\n", type);
		return -1;
	}
#endif

	return 0;
}

/* %%% */
/*
 * create phase1 proposal from remote configuration.
 * NOT INCLUDING isakmp general header of SA payload
 */
vchar_t *
ipsecdoi_setph1proposal(props)
	struct isakmpsa *props;
{
	vchar_t *mysa;
	int sablen;

	/* count total size of SA minus isakpm general header */
	/* not including isakmp general header of SA payload */
	sablen = sizeof(struct ipsecdoi_sa_b);
	sablen += setph1prop(props, NULL);

	mysa = vmalloc(sablen);
	if (mysa == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate my sa buffer (%s)\n",
			strerror(errno)); 
		return NULL;
	}

	/* create SA payload */
	/* not including isakmp general header */
	((struct ipsecdoi_sa_b *)mysa->v)->doi = htonl(props->rmconf->doitype);
	((struct ipsecdoi_sa_b *)mysa->v)->sit = htonl(props->rmconf->sittype);

	(void)setph1prop(props, mysa->v + sizeof(struct ipsecdoi_sa_b));

	return mysa;
}

static int
setph1prop(props, buf)
	struct isakmpsa *props;
	caddr_t buf;
{
	struct isakmp_pl_p *prop = NULL;
	struct isakmpsa *s = NULL;
	int proplen, trnslen;
	u_int8_t *np_t; /* pointer next trns type in previous header */
	int trns_num;
	caddr_t p = buf;

	proplen = sizeof(*prop);
	if (buf) {
		/* create proposal */
		prop = (struct isakmp_pl_p *)p;
		prop->h.np = ISAKMP_NPTYPE_NONE;
		prop->p_no = props->prop_no;
		prop->proto_id = IPSECDOI_PROTO_ISAKMP;
		prop->spi_size = 0;
		p += sizeof(*prop);
	}

	np_t = NULL;
	trns_num = 0;

	for (s = props; s != NULL; s = s->next) {
		if (np_t)
			*np_t = ISAKMP_NPTYPE_T;

		trnslen = setph1trns(s, p);
		proplen += trnslen;
		if (buf) {
			/* save buffer to pre-next payload */
			np_t = &((struct isakmp_pl_t *)p)->h.np;
			p += trnslen;

			/* count up transform length */
			trns_num++;
		}
	}

	/* update proposal length */
	if (buf) {
		prop->h.len = htons(proplen);
		prop->num_t = trns_num;
	}

	return proplen;
}

static int
setph1trns(sa, buf)
	struct isakmpsa *sa;
	caddr_t buf;
{
	struct isakmp_pl_t *trns = NULL;
	int trnslen, attrlen;
	caddr_t p = buf;

	trnslen = sizeof(*trns);
	if (buf) {
		/* create transform */
		trns = (struct isakmp_pl_t *)p;
		trns->h.np  = ISAKMP_NPTYPE_NONE;
		trns->t_no  = sa->trns_no;
		trns->t_id  = IPSECDOI_KEY_IKE;
		p += sizeof(*trns);
	}

	attrlen = setph1attr(sa, p);
	trnslen += attrlen;
	if (buf)
		p += attrlen;

	if (buf)
		trns->h.len = htons(trnslen);

	return trnslen;
}

static int
setph1attr(sa, buf)
	struct isakmpsa *sa;
	caddr_t buf;
{
	caddr_t p = buf;
	int attrlen = 0;

	if (sa->lifetime) {
		attrlen += sizeof(struct isakmp_data)
			+ sizeof(struct isakmp_data);
		if (sa->lifetime > 0xffff)
			attrlen += sizeof(sa->lifetime);
		if (buf) {
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_SA_LD_TYPE,
						OAKLEY_ATTR_SA_LD_TYPE_SEC);
			if (sa->lifetime > 0xffff) {
				u_int32_t v = htonl((u_int32_t)sa->lifetime);
				p = isakmp_set_attr_v(p, OAKLEY_ATTR_SA_LD,
						(caddr_t)&v, sizeof(v));
			} else {
				p = isakmp_set_attr_l(p, OAKLEY_ATTR_SA_LD,
							sa->lifetime);
			}
		}
	}

	if (sa->lifebyte) {
		attrlen += sizeof(struct isakmp_data)
			+ sizeof(struct isakmp_data);
		if (sa->lifebyte > 0xffff)
			attrlen += sizeof(sa->lifebyte);
		if (buf) {
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_SA_LD_TYPE,
						OAKLEY_ATTR_SA_LD_TYPE_KB);
			if (sa->lifebyte > 0xffff) {
				u_int32_t v = htonl((u_int32_t)sa->lifebyte);
				p = isakmp_set_attr_v(p, OAKLEY_ATTR_SA_LD,
							(caddr_t)&v, sizeof(v));
			} else {
				p = isakmp_set_attr_l(p, OAKLEY_ATTR_SA_LD,
							sa->lifebyte);
			}
		}
	}
	if (sa->enctype) {
		attrlen += sizeof(struct isakmp_data);
		if (buf)
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_ENC_ALG, sa->enctype);
	}
	if (sa->encklen) {
		attrlen += sizeof(struct isakmp_data);
		if (buf)
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_KEY_LEN, sa->encklen);
	}
	if (sa->authmethod) {
		attrlen += sizeof(struct isakmp_data);
		if (buf)
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_AUTH_METHOD, sa->authmethod);
	}
	if (sa->hashtype) {
		attrlen += sizeof(struct isakmp_data);
		if (buf)
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_HASH_ALG, sa->hashtype);
	}
	switch (sa->dh_group) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		/* don't attach group type for known groups */
		attrlen += sizeof(struct isakmp_data);
		if (buf) {
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_GRP_DESC,
				sa->dh_group);
		}
		break;
	case OAKLEY_ATTR_GRP_DESC_EC2N155:
	case OAKLEY_ATTR_GRP_DESC_EC2N185:
		/* don't attach group type for known groups */
		attrlen += sizeof(struct isakmp_data);
		if (buf) {
			p = isakmp_set_attr_l(p, OAKLEY_ATTR_GRP_TYPE,
				OAKLEY_ATTR_GRP_TYPE_EC2N);
		}
		break;
	case 0:
	default:
		break;
	}

	return attrlen;
}

#if 0
/*
 * create phase2 proposal from policy configuration.
 * INCLUDING isakmp general header of SA payload.
 *
 * XXX the routine disagrees with other code in terms of interpretation of
 * "bundle" pointer.  we'll need to have more appropriate structure for
 * ipsecsa.
 */
vchar_t *
ipsecdoi_setph2proposal(iph2, keys)
	struct ph2handle *iph2;
	struct ipsecsakeys *keys;
{
	struct ipsecsa *proposal;
	vchar_t *mysa;
	struct ipsecdoi_pl_sa *sa;
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	struct ipsecsa *n, *b;
	u_int tlen;	/* total sa length */
	u_int8_t *np_p; /* pointer next prop type in previous header */
	u_int8_t *np_t; /* pointer next trns type in previous header */
	int proplen, trns_num, attrlen;
	caddr_t p;

	proposal = iph2->side == INITIATOR
			? iph2->spidx->policy->proposal
			: iph2->approval;

	/* count total size of SA minus isakpm general header */
	/* INCLUDING isakmp general header of SA payload. */
	tlen = sizeof(struct ipsecdoi_pl_sa);
	tlen += getph2proplen(proposal);

	mysa = vmalloc(tlen);
	if (mysa == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate my sa buffer (%s)\n",
			strerror(errno)); 
		return NULL;
	}
	p = mysa->v;

	/* create SA payload */
	sa = (struct ipsecdoi_pl_sa *)p;
	sa->b.doi = htonl(IPSEC_DOI);
	sa->b.sit = htonl(IPSECDOI_SIT_IDENTITY_ONLY);	/* XXX configurable ? */
	p += sizeof(*sa);

	np_p = NULL;

	for (n = proposal; n != NULL; n = n->next) {

		if (np_p)
			*np_p = ISAKMP_NPTYPE_P;

		/* create proposal */
		prop = (struct isakmp_pl_p *)p;
		prop->h.np = ISAKMP_NPTYPE_NONE;
		prop->p_no = n->prop_no;
		prop->proto_id = n->proto_id;
	    {
		struct sockaddr *dst;
		struct ipsecsakeys *k;
		dst = n->dst ? n->dst : iph2->dst;
		for (k = keys; k != NULL; k = k->next) {
			if (n->proto_id == k->proto_id
			 && n->encmode == k->encmode
			 && cmpsaddrwop(dst, k->dst) == 0)
				break;
		}
		if (k == NULL) {
			plog(logp, LOCATION, NULL,
				"no SPI found for %s/%s\n",
				s_ipsecdoi_proto(n->proto_id),
				saddrwop2str(dst));
			vfree(mysa);
			return NULL;
		}
		prop->spi_size = sizeof(k->spi);
		p += sizeof(*prop);
		memcpy(p, &k->spi, sizeof(k->spi));
		p += sizeof(k->spi);
	    }

		np_t = NULL;
		trns_num = 0;
		proplen = 0;

		for (b = n; b != NULL; b = b->bundles) {
			attrlen = 0;

			if (np_t)
				*np_t = ISAKMP_NPTYPE_T;

			/* create transform */
			trns = (struct isakmp_pl_t *)p;
			trns->h.np  = ISAKMP_NPTYPE_NONE;
			trns->t_no  = b->trns_no;
			switch (b->proto_id) {
			case IPSECDOI_PROTO_IPSEC_ESP:
				trns->t_id  = b->enctype;
				break;
			case IPSECDOI_PROTO_IPSEC_AH:
				switch (b->authtype) {
				case IPSECDOI_ATTR_AUTH_HMAC_MD5:
					trns->t_id = IPSECDOI_AH_MD5;
					break;
				case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
					trns->t_id = IPSECDOI_AH_SHA;
					break;
				case IPSECDOI_ATTR_AUTH_DES_MAC:
					trns->t_id = IPSECDOI_AH_DES;
					break;
				case IPSECDOI_ATTR_AUTH_KPDK:
					trns->t_id = 0;
					break;
				default:
					plog(logp, LOCATION, NULL,
						"invalid authtype %d\n",
						b->authtype);
					vfree(mysa);
					return NULL;
				}
				break;
			case IPSECDOI_PROTO_IPCOMP:
				trns->t_id  = b->comptype;
				break;
			default:
				plog(logp, LOCATION, NULL,
					"invalid proto_id %d\n", b->proto_id);
				vfree(mysa);
				return NULL;
			}
			p += sizeof(*trns);
			p = setph2attr(p, b, &attrlen);

			trns->h.len = htons(sizeof(*trns) + attrlen);

			/* count up transform length */
			proplen += sizeof(*trns) + attrlen;
			trns_num++;

			/* save buffer to pre-next payload */
			np_t = &trns->h.np;
		}

		/* update proposal length */
		prop->h.len = htons(sizeof(*prop) + prop->spi_size + proplen);
		prop->num_t = trns_num;

		/* count up sa length */
		sa->h.len += sizeof(*prop) + prop->spi_size + proplen;

		/* save buffer to pre-next payload */
		np_p = &prop->h.np;
		np_t = NULL;
	}

	/* update sa length */
	sa->h.len = htons(sizeof(*sa) + sa->h.len);

	return mysa;
}

static int
getph2proplen(proposal)
	struct ipsecsa *proposal;
{
	struct ipsecsa *n, *b;
	int len = 0;

	for (n = proposal; n != NULL; n = n->next) {

		len += sizeof(struct isakmp_pl_p) + sizeof(u_int32_t);
						/* XXX spi size */

		for (b = n; b != NULL; b = b->bundles) {
			len += sizeof(struct isakmp_pl_t);

			/* encryption mode always exists. */
			len += sizeof(struct isakmp_data);

			if (b->lifetime) {
				len += sizeof(struct isakmp_data)
					+ sizeof(struct isakmp_data);
				if (b->lifetime > 0xffff)
					len += sizeof(u_int32_t);
			}
			if (b->lifebyte) {
				len += sizeof(struct isakmp_data)
					+ sizeof(struct isakmp_data);
				if (b->lifebyte > 0xffff)
					len += sizeof(u_int32_t);
			}
			if (b->encklen)
				len += sizeof(struct isakmp_data);
			if (b->authtype)
				len += sizeof(struct isakmp_data);
		}
	}

	return len;
}
#else
/*
 * XXX Assumes that there will be no ipsecsa struct with the same proto_id 
 * on "bundle" chain.  (i.e. single proposal payload will accompany single
 * transform payload only)
 */
vchar_t *
ipsecdoi_setph2proposal0(iph2, keys, b)
	const struct ph2handle *iph2;
	const struct ipsecsakeys *keys;
	const struct ipsecsa *b;
{
	vchar_t *p;
	const struct sockaddr *dst;
	const struct ipsecsakeys *k;
	struct isakmp_pl_p *prop;
	struct isakmp_pl_t *trns;
	int len;
	int attrlen;
	size_t trnsoff;

	dst = b->dst ? b->dst : iph2->dst;
	for (k = keys; k != NULL; k = k->next) {
		if (b->proto_id == k->proto_id && b->encmode == k->encmode
		 && cmpsaddrwop((struct sockaddr *)dst,
				 (struct sockaddr *)k->dst) == 0)
			break;
	}
	if (k == NULL) {
		plog(logp, LOCATION, NULL,
			"no SPI found for %s/%s\n",
			s_ipsecdoi_proto(b->proto_id),
			saddrwop2str((struct sockaddr *)dst));
		return NULL;
	}

	p = vmalloc(sizeof(*prop) + sizeof(k->spi) + sizeof(*trns));
	if (p == NULL)
		return NULL;

	/* create proposal */
	prop = (struct isakmp_pl_p *)p->v;
	prop->h.np = ISAKMP_NPTYPE_NONE;
	prop->p_no = b->prop_no;
	prop->proto_id = b->proto_id;
	prop->num_t = 1;

	prop->spi_size = sizeof(k->spi);
	memcpy(prop + 1, &k->spi, sizeof(k->spi));

	/* create transform */
	trnsoff = sizeof(*prop) + sizeof(k->spi);
	trns = (struct isakmp_pl_t *)(p->v + trnsoff);
	trns->h.np  = ISAKMP_NPTYPE_NONE;
	trns->t_no  = b->trns_no;
	switch (b->proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		trns->t_id  = b->enctype;
		break;
	case IPSECDOI_PROTO_IPSEC_AH:
		switch (b->authtype) {
		case IPSECDOI_ATTR_AUTH_HMAC_MD5:
			trns->t_id = IPSECDOI_AH_MD5;
			break;
		case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
			trns->t_id = IPSECDOI_AH_SHA;
			break;
		case IPSECDOI_ATTR_AUTH_DES_MAC:
			trns->t_id = IPSECDOI_AH_DES;
			break;
		case IPSECDOI_ATTR_AUTH_KPDK:
			trns->t_id = 0;
			break;
		default:
			plog(logp, LOCATION, NULL,
				"invalid authtype %d\n", b->authtype);
			vfree(p);
			return NULL;
		}
		break;
	case IPSECDOI_PROTO_IPCOMP:
		trns->t_id  = b->comptype;
		break;
	default:
		plog(logp, LOCATION, NULL,
			"invalid proto_id %d\n", b->proto_id);
		vfree(p);
		return NULL;
	}

	len = sizeof(struct isakmp_data);
	if (b->lifetime) {
		len += sizeof(struct isakmp_data) + sizeof(struct isakmp_data);
		if (b->lifetime > 0xffff)
			len += sizeof(u_int32_t);
	}
	if (b->lifebyte) {
		len += sizeof(struct isakmp_data) + sizeof(struct isakmp_data);
		if (b->lifebyte > 0xffff)
			len += sizeof(u_int32_t);
	}
	if (b->encklen)
		len += sizeof(struct isakmp_data);
	if (b->authtype)
		len += sizeof(struct isakmp_data);

	switch (b->ipsp->pfs_group) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		len += sizeof(struct isakmp_data);
		break;
	case 0:
	default:
		break;
	}

	p = vrealloc(p, p->l + len);
	if (p == NULL)
		return NULL;

	setph2attr(p->v + p->l - len, (struct ipsecsa *)b, &attrlen);

	trns = (struct isakmp_pl_t *)(p->v + trnsoff);
	trns->h.len = htons(sizeof(*trns) + attrlen);

	prop = (struct isakmp_pl_p *)p->v;
	prop->h.len = htons(p->l);

	return p;
}

/*
 * create phase2 proposal from policy configuration.
 * INCLUDING isakmp general header of SA payload.
 *
 * XXX the routine disagrees with other code in terms of interpretation of
 * "bundle" pointer.  we'll need to have more appropriate structure for
 * ipsecsa.
 */
vchar_t *
ipsecdoi_setph2proposal(iph2, keys)
	struct ph2handle *iph2;
	struct ipsecsakeys *keys;
{
	struct ipsecsa *proposal;
	vchar_t *mysa, *q;
	struct ipsecdoi_pl_sa *sa;
	struct isakmp_pl_p *prop;
	struct ipsecsa *n, *b;
	size_t propoff;

	proposal = iph2->side == INITIATOR
			? iph2->spidx->policy->proposal
			: iph2->approval;

	mysa = vmalloc(sizeof(*sa));
	if (mysa == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate my sa buffer (%s)\n",
			strerror(errno)); 
		return NULL;
	}

	/* create SA payload */
	sa = (struct ipsecdoi_pl_sa *)mysa->v;
	sa->b.doi = htonl(IPSEC_DOI);
	sa->b.sit = htonl(IPSECDOI_SIT_IDENTITY_ONLY);	/* XXX configurable ? */

	prop = NULL;
	propoff = -1;
	for (n = proposal; n; n = n->next) {
		for (b = n; b; b = b->bundles) {
			q = ipsecdoi_setph2proposal0(iph2, keys, b);
			if (q == NULL) {
				vfree(mysa);
				return NULL;
			}

			mysa = vrealloc(mysa, mysa->l + q->l);
			memcpy(mysa->v + mysa->l - q->l, q->v, q->l);
			if (propoff >= 0) {
				prop = (struct isakmp_pl_p *)(mysa->v +
					propoff);
				prop->h.np = ISAKMP_NPTYPE_P;
			}
			propoff = mysa->l - q->l;

			vfree(q);
		}
	}

	sa = (struct ipsecdoi_pl_sa *)mysa->v;
	sa->h.len = htons(mysa->l);

	return mysa;
}
#endif

static caddr_t
setph2attr(buf, sa, len)
	caddr_t buf;
	struct ipsecsa *sa;
	int *len;
{
	caddr_t p = buf;

	*len = 0;

	if (sa->lifetime) {
		p = isakmp_set_attr_l(p, IPSECDOI_ATTR_SA_LD_TYPE,
					IPSECDOI_ATTR_SA_LD_TYPE_SEC);
		if (sa->lifetime > 0xffff) {
			u_int32_t v = htonl((u_int32_t)sa->lifetime);
			p = isakmp_set_attr_v(p, IPSECDOI_ATTR_SA_LD,
						(caddr_t)&v, sizeof(v));
		} else {
			p = isakmp_set_attr_l(p, IPSECDOI_ATTR_SA_LD,
						sa->lifetime);
		}
	}

	if (sa->lifebyte) {
		p = isakmp_set_attr_l(p, IPSECDOI_ATTR_SA_LD_TYPE,
					IPSECDOI_ATTR_SA_LD_TYPE_KB);
		if (sa->lifebyte > 0xffff) {
			u_int32_t v = htonl((u_int32_t)sa->lifebyte);
			p = isakmp_set_attr_v(p, IPSECDOI_ATTR_SA_LD,
						(caddr_t)&v, sizeof(v));
		} else {
			p = isakmp_set_attr_l(p, IPSECDOI_ATTR_SA_LD,
						sa->lifebyte);
		}
	}

	p = isakmp_set_attr_l(p, IPSECDOI_ATTR_ENC_MODE, sa->encmode);

	if ((sa->proto_id == IPSECDOI_PROTO_IPSEC_ESP && sa->authtype)
	 || sa->proto_id == IPSECDOI_PROTO_IPSEC_AH)
		p = isakmp_set_attr_l(p, IPSECDOI_ATTR_AUTH, sa->authtype);

	if (sa->encklen)
		p = isakmp_set_attr_l(p, IPSECDOI_ATTR_KEY_LENGTH, sa->encklen);

	switch (sa->ipsp->pfs_group) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		p = isakmp_set_attr_l(p, IPSECDOI_ATTR_GRP_DESC,
			sa->ipsp->pfs_group);
		break;
	case 0:
	default:
		break;
	}

	*len = p - buf;

	return p;
}

int
ipsecdoi_get_defaultlifetime()
{
	return IPSECDOI_ATTR_SA_LD_SEC_DEFAULT;
}

int
ipsecdoi_checkalgtypes(proto_id, enc, auth, comp)
	int proto_id, enc, auth, comp;
{
#define TMPALGTYPE2STR(n) s_algtype(algclass_ipsec_##n, n)
	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (enc == 0 || comp != 0) {
			plog(logp, LOCATION, NULL,
				"illegal algorithm defined "
				"ESP enc=%s auth=%s comp=%s.\n",
				TMPALGTYPE2STR(enc),
				TMPALGTYPE2STR(auth),
				TMPALGTYPE2STR(comp));
			return -1;
		}
		break;
	case IPSECDOI_PROTO_IPSEC_AH:
		if (enc != 0 || auth == 0 || comp != 0) {
			plog(logp, LOCATION, NULL,
				"illegal algorithm defined "
				"AH enc=%s auth=%s comp=%s.\n",
				TMPALGTYPE2STR(enc),
				TMPALGTYPE2STR(auth),
				TMPALGTYPE2STR(comp));
			return -1;
		}
		break;
	case IPSECDOI_PROTO_IPCOMP:
		if (enc != 0 || auth != 0 || comp == 0) {
			plog(logp, LOCATION, NULL,
				"illegal algorithm defined "
				"IPcomp enc=%s auth=%s comp=%s.\n",
				TMPALGTYPE2STR(enc),
				TMPALGTYPE2STR(auth),
				TMPALGTYPE2STR(comp));
			return -1;
		}
		break;
	default:
		plog(logp, LOCATION, NULL,
			"invalid ipsec protocol %d\n", proto_id);
		return -1;
	}
#undef TMPALGTYPE2STR(n)
	return 0;
}

int
ipproto2doi(proto)
	int proto;
{
	switch (proto) {
	case IPPROTO_AH:
		return IPSECDOI_PROTO_IPSEC_AH;
	case IPPROTO_ESP:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case IPPROTO_IPCOMP:
		return IPSECDOI_PROTO_IPCOMP;
	}
	return -1;	/* XXX */
}

/*
 * check if phase 1 ID payload conforms RFC2407 4.6.2.
 * (proto, port) must be (0, 0) or (udp, 500).
 *
 * "ident" should be ID payload without general header, i.e.
 * value set to iph1->id_p after isakmp_p2ph().
 */
int
ipsecdoi_checkid1(iph1)
	struct ph1handle *iph1;
{
	struct ipsecdoi_id_b *id_b;

	if (iph1->id_p == NULL) {
		plog(logp, LOCATION, NULL,
			"invalid iph1 passed id_p == NULL\n");
		goto err;
	}
	if (iph1->id_p->l < sizeof(id_b)) {
		plog(logp, LOCATION, NULL,
			"invalid value passed as \"ident\" (len=%lu)\n",
			(u_long)iph1->id_p->l);
		goto err;
	}

	id_b = (struct ipsecdoi_id_b *)iph1->id_p->v;

	/*
	 * In main mode with pre-shared key, only type of specific address
	 * can be used.
	 */
	if (iph1->etype == ISAKMP_ETYPE_IDENT
	 && iph1->approval->authmethod == OAKLEY_ATTR_AUTH_METHOD_PSKEY) {
		 if (id_b->type != IPSECDOI_ID_IPV4_ADDR
		 && id_b->type != IPSECDOI_ID_IPV6_ADDR) {
			plog(logp, LOCATION, NULL,
				"Expecting IP address type in main mode, "
				"but %s.\n", s_ipsecdoi_ident(id_b->type));
			goto err;
		}

		if (id_b->proto_id == 0 && ntohs(id_b->port) == 0)
			return 0;
		if (id_b->proto_id == IPPROTO_UDP) {
			if (ntohs(id_b->port) == _INPORTBYSA(iph1->remote))
				return 0;
#if 1
			/* allow hardcoded "500" for now */
			if (ntohs(id_b->port) == 500)
				return 0;
#endif
		}

#if 0
		plog(logp, LOCATION, NULL,
			"wrong ID payload (proto, port) = (%u, %u).\n",
			id_b->proto_id, ntohs(id_b->port));
		return -1;
#else
		plog(logp, LOCATION, NULL,
			"wrong ID payload (proto, port) = (%u, %u), "
			"okay for now.\n",
			id_b->proto_id, ntohs(id_b->port));
		return 0;
#endif
	}
	return 0;
err:
	return -1;
}

/*
 * create ID payload for phase 1 and set into iph1->id.
 * NOT INCLUDING isakmp general header.
 * see, RFC2407 4.6.2.1
 */
int
ipsecdoi_setid1(iph1)
	struct ph1handle *iph1;
{
	vchar_t *ret = NULL;
	struct ipsecdoi_id_b id_b;
	int lctype;
	vchar_t *ident = NULL, idtmp;

	lctype = doi2idtype(iph1->rmconf->identtype);

	/* init */
	id_b.type = iph1->rmconf->identtype;
	id_b.proto_id = 0;
	id_b.port = 0;

	switch (iph1->rmconf->identtype) {
	case IPSECDOI_ID_FQDN:
		ident = lcconf->ident[lctype];
		break;
	case IPSECDOI_ID_USER_FQDN:
		ident = lcconf->ident[lctype];
		break;
	case IPSECDOI_ID_KEY_ID:
		ident = lcconf->ident[lctype];
		break;
	default:
		ident = NULL;
	}

	/* use local IP address as identifier */
	if (ident == NULL) {
		/* use IP address */
		switch (iph1->local->sa_family) {
		case AF_INET:
			id_b.type = IPSECDOI_ID_IPV4_ADDR;
			break;
#ifdef INET6
		case AF_INET6:
			id_b.type = IPSECDOI_ID_IPV6_ADDR;
			break;
#endif
		default:
			plog(logp, LOCATION, NULL,
				"invalid address family.\n");
			goto err;
		}

		id_b.proto_id = IPPROTO_UDP;
#if 0	/* XXX should be configurable ? */
		id_b.port = htons(PORT_ISAKMP);
#else
		id_b.port = _INPORTBYSA(iph1->local);
#endif
		idtmp.v = _INADDRBYSA(iph1->local);
		idtmp.l = _INALENBYAF(iph1->local->sa_family);
		ident = &idtmp;
	}

	ret = vmalloc(sizeof(id_b) + ident->l);
	if (ret == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto err;
	}

	memcpy(ret->v, &id_b, sizeof(id_b));
	memcpy(ret->v + sizeof(id_b), ident->v, ident->l);

	iph1->id = ret;

	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL,
			"use ID type of %s\n", s_ipsecdoi_ident(id_b.type)));
	return 0;

err:
	plog(logp, LOCATION, NULL,
		"failed get my ID\n");
	return -1;
}

/*
 * create ID payload for phase 2, and set into iph2->id and id_p.
 * this function is for initiator.  responder will get to copy from payload.
 * NOT INCLUDING isakmp general header.
 * see, RFC2407 4.6.2.1
 */
int
ipsecdoi_setid2(iph2)
	struct ph2handle *iph2;
{
	struct policyindex *spidx = iph2->spidx;

	/*
	 * XXX only make ID of address type.  should be supported other type.
	 * 	e.g. key_id.
	 */
	iph2->id = sockaddr2id((struct sockaddr *)&spidx->src,
				spidx->prefs, spidx->ul_proto);
	if (iph2->id == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to get ID for %s\n",
			saddr2str((struct sockaddr *)&spidx->src));
		return -1;
	}
	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL, "use local ID type %s\n",
			s_ipsecdoi_ident(((struct ipsecdoi_id_b *)iph2->id->v)->type)));

	iph2->id_p = sockaddr2id((struct sockaddr *)&spidx->dst,
				spidx->prefd, spidx->ul_proto);
	if (iph2->id_p == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to get ID for %s\n",
			saddr2str((struct sockaddr *)&spidx->dst));
		vfree(iph2->id);
		iph2->id = NULL;
		return -1;
	}
	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL,
			"use remote ID type %s\n",
			s_ipsecdoi_ident(((struct ipsecdoi_id_b *)iph2->id_p->v)->type)));

	return 0;
}

/*
 * set address type of ID.
 */
static vchar_t *
sockaddr2id(saddr, prefixlen, ul_proto)
	struct sockaddr *saddr;
	u_int prefixlen;
	u_int ul_proto;
{
	vchar_t *new;
	int type, len, len2;

	/* get default ID length */
	len = sizeof(struct ipsecdoi_id_b) + _INALENBYAF(saddr->sa_family);

	/*
	 * XXXX:
	 * Q. When type is SUBNET, is it allowed to be ::1/128.
	 */
	switch (saddr->sa_family) {
	case AF_INET:
		if (prefixlen == (_INALENBYAF(saddr->sa_family) << 3)) {
			type = IPSECDOI_ID_IPV4_ADDR;
			len2 = 0;
		} else {
			type = IPSECDOI_ID_IPV4_ADDR_SUBNET;
			len2 = _INALENBYAF(saddr->sa_family); /* acutually 4 */
		}
		break;
#ifdef INET6
	case AF_INET6:
		if (prefixlen == (_INALENBYAF(saddr->sa_family) << 3)) {
			type = IPSECDOI_ID_IPV6_ADDR;
			len2 = 0;
		} else {
			type = IPSECDOI_ID_IPV6_ADDR_SUBNET;
			len2 = _INALENBYAF(saddr->sa_family); /* acutually 16 */
		}
		break;
#endif
	default:
		plog(logp, LOCATION, NULL, "invalid address family.\n");
		return NULL;
	}

	/* get ID buffer */
	new = vmalloc(len + len2);
	if (new == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		return NULL;
	}

	memset(new->v, 0, new->l);

	/* set the part of header. */
	((struct ipsecdoi_id_b *)new->v)->type = type;

	/* set ul_proto and port */
	/*
	 * NOTE: we use both IPSEC_ULPROTO_ANY and IPSEC_PORT_ANY as wild card
	 * because 0 means port number of 0.  Instead of 0, we use IPSEC_*_ANY.
	 */
	((struct ipsecdoi_id_b *)new->v)->proto_id =
			ul_proto == IPSEC_ULPROTO_ANY
					? 0 : ul_proto;
	((struct ipsecdoi_id_b *)new->v)->port =
			_INPORTBYSA(saddr) == IPSEC_PORT_ANY
					? 0 : _INPORTBYSA(saddr);

	/* set address */
	memcpy(new->v + sizeof(struct ipsecdoi_id_b),
		_INADDRBYSA(saddr), _INALENBYAF(saddr->sa_family));

	/* set prefix */
	if (len2 != 0) {
		u_char *p = new->v + len;
		u_int bits = prefixlen;

		while (bits >= 8) {
			*p++ = 0xff;
			bits -= 8;
		}

		if (bits > 0)
			*p = ~((1 << (8 - bits)) - 1);
	}

	return new;
}

/*
 * create sockaddr structure from ID payload.
 * buffer must be allocated.
 * see, RFC2407 4.6.2.1
 */
int
ipsecdoi_id2sockaddr(
	vchar_t *buf,
	struct sockaddr *saddr,
	u_int8_t *prefixlen,
	u_int16_t *ul_proto)
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
		plog(logp, LOCATION, NULL,
			"unsupported ID type %d\n", id_b->type);
		return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
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
		if (buf->l < _INALENBYAF(family))
			return -1;

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
		plog(logp, LOCATION, NULL, "unsupported ID type.\n");
		return ISAKMP_NTYPE_INVALID_ID_INFORMATION;
	}

	saddr->sa_len = _SALENBYAF(family);
	saddr->sa_family = family;
	_INPORTBYSA(saddr) = id_b->port == 0
				? IPSEC_PORT_ANY
				: id_b->port;		/* see sockaddr2id() */
	memcpy(_INADDRBYSA(saddr), buf->v + sizeof(*id_b), _INALENBYAF(family));
	*prefixlen = plen;
	*ul_proto = id_b->proto_id == 0
				? IPSEC_ULPROTO_ANY
				: id_b->proto_id;	/* see sockaddr2id() */

	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, NULL,
			"make saddr from ID payload "
			"%s prefixlen=%u ul_proto=%u\n",
			saddr2str(saddr),
			*prefixlen, *ul_proto));

	return 0;
}

/*
 * fix sa keys to be use.  this function is for initiator.
 */
int
ipsecdoi_fixsakeys(iph2)
	struct ph2handle *iph2;
{
	struct ipsecsakeys *original;
	struct ipsecsa *b;
	struct ipsecsakeys *v, *o;
	struct sockaddr *dst, *src;

	/* initialize */
	original = iph2->keys;
	iph2->keys = NULL;
	dst = NULL;

	for (b = iph2->approval; b != NULL; b = b->bundles) {
		/* see ipsecdoi_initsakeys() */
		dst = b->dst != NULL ? b->dst : (dst != NULL ? dst : iph2->dst);
		src = iph2->src;		/* XXX cheat ! */

		if (mksakeys(b, &iph2->keys, dst, src) < 0) {
			plog(logp, LOCATION, NULL,
				"failed to create sa keys\n");
			return -1;
		}
	}

	/* set initiator's spi from original */
	for (v = iph2->keys; v != NULL; v = v->next) {
		for (o = original; o != NULL; o = o->next) {
			/* don't check source address */
			if (v->proto_id == o->proto_id
			 && v->encmode == o->encmode
			 && ((v->dst == NULL && o->dst == NULL)
			  || cmpsaddrwop(v->dst, o->dst) == 0)) {
				v->spi = o->spi;
				v->spi_p = o->spi_p;
				break;
			}
		}
	}

	return 0;
}

/*
 * create sa keys to be possible.
 */
int
ipsecdoi_initsakeys(iph2)
	struct ph2handle *iph2;
{
	struct ipsecsa *proposal;
	struct ipsecsa *p, *b;
	struct ipsecsakeys *v;
	struct sockaddr *dst, *src;

	/* initialize */
	if (iph2->keys != NULL) {
		while (iph2->keys != NULL) {
			v = iph2->keys->next;
			free(iph2->keys);
			iph2->keys = v;
		}
	}
	proposal = iph2->side == INITIATOR
			? iph2->spidx->policy->proposal
			: iph2->approval;

	for (p = proposal; p; p = p->next) {

		/* reset dst when next proposal */
		dst = NULL;

		for (b = p; b; b = b->bundles) {
			/* dst address */
			/* when transport, iph2->src is usually used.
			 * But when there is a tunnel mode, copy its dst
			 * address to next transport entries.  */
			dst = b->dst != NULL
				? b->dst		/* tunnel mode */
				: (dst != NULL
					? dst		/* transport mode */
					: iph2->dst);	/* first entry */

			src = iph2->src;		/* XXX cheat ! */

			if (mksakeys(b, &iph2->keys, dst, src) < 0)
				return -1;
		}

		/* don't walk other proposals if responder. */
		if (iph2->side == RESPONDER)
			break;
	}

	return 0;
}

/* create sa keys */
static int
mksakeys(b, keys, dst, src)
	struct ipsecsa *b;
	struct ipsecsakeys **keys;
	struct sockaddr *dst, *src;
{
	struct ipsecsakeys *v;

	/* skip if there are sa with same proto and dst. */
	/* don't check source address */
	for (v = *keys; v != NULL; v = v->next) {
		if (v->proto_id == b->proto_id
		 && v->encmode == b->encmode
		 && (b->dst == NULL
		  || cmpsaddrwop(v->dst, b->dst) == 0))
			break;
	}
	/* this sa has already recorded */
	if (v != NULL)
		return 0;

	v = CALLOC(sizeof(*v), struct ipsecsakeys *);
	if (v == NULL) {
		plog(logp, LOCATION, NULL,
			"calloc (%s)\n",
			strerror(errno));
		goto err;
	}
	v->proto_id = b->proto_id;
	v->encmode = b->encmode;
	v->dst = dst;
	v->src = src;
	v->next = *keys;
	v->len = b->encklen;
	*keys = v;

	YIPSDEBUG(DEBUG_MISC,
		char *xsrc = strdup(saddrwop2str(v->src));
		plog(logp, LOCATION, NULL,
			"create keys %s/%s/%s->%s\n",
			s_ipsecdoi_proto(v->proto_id),
			s_ipsecdoi_encmode(v->encmode),
			xsrc,
			saddrwop2str(v->dst));
		free(xsrc));
	return 0;

err:
	while (*keys != NULL) {
		v = (*keys)->next;
		free(*keys);
		*keys = v;
	}
	return -1;
}

void
ipsecdoi_printsa(s0)
	const struct ipsecsa *s0;
{
	const struct ipsecsa *s;
	int level, i;

	if (!s0) {
		printf("(null)");
		return;
	}

	level = 0;
	for (i = 0; i < level; i++)
		printf("\t");
	if (s0->next)
		printf("{next ");
	for (s = s0; s; s = s->next) {
		ipsecdoi_printsa_bundle0(s, level + 1);
		if (s->next)
			printf("\n");
	}
	if (s0->next)
		printf("}");
	printf("\n");
}

#ifdef YIPS_DEBUG
static void
ipsecdoi_printsa_bundle(s0)
	const struct ipsecsa *s0;
{
	ipsecdoi_printsa_bundle0(s0, 0);
	printf("\n");
}
#endif

static void
ipsecdoi_printsa_bundle0(s0, level)
	const struct ipsecsa *s0;
	int level;
{
	const struct ipsecsa *s;
	int i;

	if (!s0) {
		printf("(null)");
		return;
	}

	for (i = 0; i < level; i++)
		printf("\t");
	if (s0->bundles)
		printf("<bundle ");
	for (s = s0; s; s = s->bundles) {
		ipsecdoi_printsa_1(s);
		if (s->bundles) {
			printf("\n");
			for (i = 0; i < level + 1; i++)
				printf("\t");
		}
	}
	if (s0->bundles)
		printf(">");
}

static void
ipsecdoi_printsa_1(s)
	const struct ipsecsa *s;
{
	if (!s) {
		printf("(null)");
		return;
	}

	printf("(proto_id=%s encmode=%s enctype=%s authtype=%s comptype=%s)",
		s_ipsecdoi_proto(s->proto_id),
		s_ipsecdoi_trns(IPSECDOI_PROTO_IPSEC_ESP, s->enctype),
		s_ipsecdoi_attr_v(IPSECDOI_ATTR_ENC_MODE, s->encmode),
		s_ipsecdoi_attr_v(IPSECDOI_ATTR_AUTH, s->authtype),
		s_ipsecdoi_trns(IPSECDOI_PROTO_IPCOMP, s->comptype));
}

#ifdef YIPS_DEBUG
static void
print_proppair0(p, level)
	struct prop_pair *p;
	int level;
{
	int i;
	for (i = 0; i < level; i++)
		printf("\t");
	printf("%p: next=%p tnext=%p\n", p, p->next, p->tnext);
	if (p->next)
		print_proppair0(p->next, level + 1);
	if (p->tnext)
		print_proppair0(p->tnext, level + 1);
}

static void
print_proppair(p)
	struct prop_pair *p;
{
	print_proppair0(p, 1);
}
#endif
