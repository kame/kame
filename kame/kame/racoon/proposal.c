/*	$KAME: proposal.c,v 1.16 2000/09/19 02:08:09 itojun Exp $	*/

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
/* YIPS @(#)$Id: proposal.c,v 1.16 2000/09/19 02:08:09 itojun Exp $ */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <netkey/key_var.h>
#include <netinet/in.h>
#include <netinet6/ipsec.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "isakmp_var.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "algorithm.h"
#include "proposal.h"
#include "sainfo.h"
#include "localconf.h"
#include "remoteconf.h"
#include "oakley.h"
#include "handler.h"
#include "strnames.h"

/* %%%
 * modules for ipsec sa spec
 */
struct saprop *
newsaprop()
{
	struct saprop *new;

	new = CALLOC(sizeof(*new), struct saprop *);
	if (new == NULL)
		return NULL;

	return new;
}

struct saproto *
newsaproto()
{
	struct saproto *new;

	new = CALLOC(sizeof(*new), struct saproto *);
	if (new == NULL)
		return NULL;

	return new;
}

/* set saprop to last part of the prop tree */
void
inssaprop(head, new)
	struct saprop **head;
	struct saprop *new;
{
	struct saprop *p;

	if (*head == NULL) {
		*head = new;
		return;
	}

	for (p = *head; p->next; p = p->next)
		;
	p->next = new;

	return;
}

/* set saproto to last part of the proto tree in saprop */
void
inssaproto(pp, new)
	struct saprop *pp;
	struct saproto *new;
{
	struct saproto *p;

	for (p = pp->head; p && p->next; p = p->next)
		;
	if (p == NULL)
		pp->head = new;
	else
		p->next = new;

	return;
}

struct satrns *
newsatrns()
{
	struct satrns *new;

	new = CALLOC(sizeof(*new), struct satrns *);
	if (new == NULL)
		return NULL;

	return new;
}

/* set saproto to last part of the proto tree in saprop */
void
inssatrns(pr, new)
	struct saproto *pr;
	struct satrns *new;
{
	struct satrns *tr;

	for (tr = pr->head; tr && tr->next; tr = tr->next)
		;
	if (tr == NULL)
		pr->head = new;
	else
		tr->next = new;

	return;
}

/*
 * take a single match between saprop.  and new proposal allocated.
 *	pp1: peer's proposal.
 *	pp2: my proposal.
 * NOTE: In the case of initiator, must be ensured that there is no
 * modification of the proposal by calling cmp_aproppair_i() before
 * this function.
 */
struct saprop *
cmpsaprop_alloc(ph1, pp1, pp2)
	struct ph1handle *ph1;
	const struct saprop *pp1, *pp2;
{
	struct saprop *newpp = NULL;
	struct saproto *pr1, *pr2, *newpr = NULL;
	struct satrns *tr1, *tr2, *newtr;

	newpp = newsaprop();
	if (newpp == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate saprop.\n");
		return NULL;
	}
	newpp->prop_no = pp1->prop_no;

	/* see proposal.h about lifetime/key length and PFS selection. */

	/* check time/bytes lifetime and PFS */
	switch (ph1->rmconf->pcheck_level) {
	case PROP_CHECK_OBEY:
		newpp->lifetime = pp1->lifetime;
		newpp->lifebyte = pp1->lifebyte;
		newpp->pfs_group = pp1->pfs_group;
		break;
	case PROP_CHECK_STRICT:
		if (pp1->lifetime > pp2->lifetime) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"ERROR: long lifetime proposed: "
					"my:%d peer:%d\n",
					pp2->lifetime, pp1->lifetime));
			goto err;
		}
		if (pp1->lifebyte > pp2->lifebyte) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"ERROR: long lifebyte proposed: "
					"my:%d peer:%d\n",
					pp2->lifebyte, pp1->lifebyte));
			goto err;
		}
		newpp->lifetime = pp1->lifetime;
		newpp->lifebyte = pp1->lifebyte;

    prop_pfs_check:
		if (pp2->pfs_group != 0 && pp1->pfs_group != pp2->pfs_group) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"ERROR: pfs group mismatched: "
					"my:%d peer:%d\n",
					pp2->pfs_group, pp1->pfs_group));
			goto err;
		}
		newpp->pfs_group = pp1->pfs_group;
		break;
	case PROP_CHECK_CLAIM:
		/* lifetime */
		if (pp1->lifetime <= pp2->lifetime) {
			newpp->lifetime = pp1->lifetime;
		} else {
			newpp->lifetime = pp2->lifetime;
			newpp->claim |= IPSECDOI_ATTR_SA_LD_TYPE_SEC;
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"NOTICE: use own lifetime: "
					"my:%d peer:%d\n",
					pp2->lifetime, pp1->lifetime));
		}

		/* lifebyte */
		if (pp1->lifebyte <= pp2->lifebyte) {
			newpp->lifebyte = pp1->lifebyte;
			break;
		} else {
			newpp->lifebyte = pp2->lifebyte;
			newpp->claim |= IPSECDOI_ATTR_SA_LD_TYPE_SEC;
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"NOTICE: use own lifebyte: "
					"my:%d peer:%d\n",
					pp2->lifebyte, pp1->lifebyte));
		}

    		goto prop_pfs_check;
		break;
	case PROP_CHECK_EXACT:
		if (pp1->lifetime != pp2->lifetime) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"ERROR: lifetime mismatched: "
					"my:%d peer:%d\n",
					pp2->lifetime, pp1->lifetime));
			goto err;
		}
		if (pp1->lifebyte != pp2->lifebyte) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"ERROR: lifebyte mismatched: "
					"my:%d peer:%d\n",
					pp2->lifebyte, pp1->lifebyte));
			goto err;
		}
		if (pp1->pfs_group != pp2->pfs_group) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"ERROR: pfs group mismatched: "
					"my:%d peer:%d\n",
					pp2->pfs_group, pp1->pfs_group));
			goto err;
		}
		newpp->lifebyte = pp1->lifebyte;
		newpp->lifebyte = pp1->lifebyte;
		newpp->pfs_group = pp1->pfs_group;
		break;
	default:
		plog(logp, LOCATION, NULL,
			"FATAL: invalid pcheck_level why?.\n");
		goto err;
	}

	/* check protocol order */
	pr1 = pp1->head;
	pr2 = pp2->head;

	while (pr1 && pr2) {
		if (pr1->proto_id != pr2->proto_id) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"proto_id mismatched: "
					"my:%d peer:%d\n",
					pr2->proto_id, pr1->proto_id));
			goto err;
		}
		if (pr1->spisize != pr2->spisize) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"spisize mismatched: "
					"my:%d peer:%d\n",
					pr2->spisize, pr1->spisize));
			goto err;
		}
		if (pr1->encmode != pr2->encmode) {
			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"encmode mismatched: "
					"my:%d peer:%d\n",
					pr2->encmode, pr1->encmode));
			goto err;
		}

		for (tr1 = pr1->head; tr1; tr1 = tr1->next) {
			for (tr2 = pr2->head; tr2; tr2 = tr2->next) {
				if (cmpsatrns(tr1, tr2) == 0)
					goto found;
			}
		}

		goto err;

	    found:
		newpr = newsaproto();
		if (newpr == NULL) {
			plog(logp, LOCATION, NULL,
				"failed to allocate saproto.\n");
			goto err;
		}
		newpr->proto_id = pr1->proto_id;
		newpr->spisize = pr1->spisize;
		newpr->encmode = pr1->encmode;
		newpr->spi = pr2->spi;		/* copy my SPI */
		newpr->spi_p = pr1->spi;	/* copy peer's SPI */
		newpr->reqid_in = pr2->reqid_in;
		newpr->reqid_out = pr2->reqid_out;

		newtr = newsatrns();
		if (newtr == NULL) {
			plog(logp, LOCATION, NULL,
				"failed to allocate satrns.\n");
			goto err;
		}
		newtr->trns_no = tr1->trns_no;
		newtr->trns_id = tr1->trns_id;
		newtr->encklen = tr1->encklen;
		newtr->authtype = tr1->authtype;

		inssatrns(newpr, newtr);
		inssaproto(newpp, newpr);

		pr1 = pr1->next;
		pr2 = pr2->next;
	}

	/* should be matched all protocols in a proposal */
	if (pr1 != NULL || pr2 != NULL)
		goto err;

	return newpp;

err:
	flushsaprop(newpp);
	return NULL;
}

/* take a single match between saprop.  0 if equal. */
int
cmpsaprop(pp1, pp2)
	const struct saprop *pp1, *pp2;
{
	if (pp1->pfs_group != pp2->pfs_group) {
		plog(logp, LOCATION, NULL,
			"WARNING: pfs_group mismatch. mine:%d peer:%d\n",
			pp1->pfs_group, pp2->pfs_group);
		/* FALLTHRU */
	}

	if (pp1->lifetime > pp2->lifetime) {
		plog(logp, LOCATION, NULL,
			"WARNING: less lifetime proposed. mine:%d peer:%d\n",
			pp1->lifetime, pp2->lifetime);
		/* FALLTHRU */
	}
	if (pp1->lifebyte > pp2->lifebyte) {
		plog(logp, LOCATION, NULL,
			"WARNING: less lifebyte proposed. mine:%d peer:%d\n",
			pp1->lifebyte, pp2->lifebyte);
		/* FALLTHRU */
	}

	return 0;
}

/*
 * take a single match between satrns.  0 if equal.
 * tr1: peer's
 * tr2: my.
 */
int
cmpsatrns(tr1, tr2)
	const struct satrns *tr1, *tr2;
{
	if (tr1->trns_id != tr2->trns_id) {
		YIPSDEBUG(DEBUG_SA,
			plog(logp, LOCATION, NULL,
				"trns_id mismatched: "
				"my:%d peer:%d\n",
				tr1->trns_id, tr2->trns_id));
		return 1;
	}
	if (tr1->authtype != tr2->authtype) {
		YIPSDEBUG(DEBUG_SA,
			plog(logp, LOCATION, NULL,
				"authtype mismatched: "
				"my:%d peer:%d\n",
				tr1->authtype, tr2->authtype));
		return 1;
	}

	/* XXX
	 * At this moment for interoperability, the responder obey
	 * the initiator.  It should be defined a notify message.
	 */
	if (tr1->encklen > tr2->encklen) {
		plog(logp, LOCATION, NULL,
			"WARNING: less key length proposed, "
			"mine:%d peer:%d.  Use initiaotr's one.\n",
			tr1->encklen, tr2->encklen);
		/* FALLTHRU */
	}

	return 0;
}

int
set_satrnsbysainfo(pr, sainfo)
	struct saproto *pr;
	struct sainfo *sainfo;
{
	struct sainfoalg *a, *b;
	struct satrns *newtr;
	int t;

	switch (pr->proto_id) {
	case IPSECDOI_PROTO_IPSEC_AH:
		if (sainfo->algs[algclass_ipsec_auth] == NULL) {
			plog(logp, LOCATION, NULL,
				"no auth algorithm found\n");
			goto err;
		}
		t = 1;
		for (a = sainfo->algs[algclass_ipsec_auth]; a; a = a->next) {

			if (a->alg == IPSECDOI_ATTR_AUTH_NONE)
				continue;
				
			/* allocate satrns */
			newtr = newsatrns();
			if (newtr == NULL) {
				plog(logp, LOCATION, NULL,
					"failed to allocate satrns.\n");
				goto err;
			}

			newtr->trns_no = t++;
			newtr->trns_id = ipsecdoi_authalg2trnsid(a->alg);
			newtr->authtype = a->alg;

			inssatrns(pr, newtr);
		}
		break;
	case IPSECDOI_PROTO_IPSEC_ESP:
		if (sainfo->algs[algclass_ipsec_enc] == NULL) {
			plog(logp, LOCATION, NULL,
				"no auth algorithm found\n");
			goto err;
		}
		t = 1;
		for (a = sainfo->algs[algclass_ipsec_enc]; a; a = a->next) {
			for (b = sainfo->algs[algclass_ipsec_auth]; b; b = b->next) {
				/* allocate satrns */
				newtr = newsatrns();
				if (newtr == NULL) {
					plog(logp, LOCATION, NULL,
						"failed to allocate satrns.\n");
					goto err;
				}

				newtr->trns_no = t++;
				newtr->trns_id = a->alg;
				newtr->encklen = a->encklen;
				newtr->authtype = b->alg;

				inssatrns(pr, newtr);
			}
		}
		break;
	case IPSECDOI_PROTO_IPCOMP:
		if (sainfo->algs[algclass_ipsec_comp] == NULL) {
			plog(logp, LOCATION, NULL,
				"no ipcomp algorithm found\n");
			goto err;
		}
		t = 1;
		for (a = sainfo->algs[algclass_ipsec_comp]; a; a = a->next) {

			/* allocate satrns */
			newtr = newsatrns();
			if (newtr == NULL) {
				plog(logp, LOCATION, NULL,
					"failed to allocate satrns.\n");
				goto err;
			}

			newtr->trns_no = t++;
			newtr->trns_id = a->alg;

			inssatrns(pr, newtr);
		}
		break;
	default:
		plog(logp, LOCATION, NULL,
			"unknown proto_id (%d).\n", pr->proto_id);
		goto err;
	}

	/* no proposal found */
	if (pr->head == NULL) {
		plog(logp, LOCATION, NULL, "no algorithms found.\n");
		return -1;
	}

	return 0;

err:
	flushsatrns(pr->head);
	return -1;
}

struct saprop *
aproppair2saprop(p0)
	struct prop_pair *p0;
{
	struct prop_pair *p, *t;
	struct saprop *newpp;
	struct saproto *newpr;
	struct satrns *newtr;

	if (p0 == NULL)
		return NULL;

	/* allocate ipsec a sa proposal */
	newpp = newsaprop();
	if (newpp == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate saprop.\n");
		return NULL;
	}
	newpp->prop_no = p0->prop->p_no;
	/* lifetime & lifebyte must be updated later */

	for (p = p0; p; p = p->next) {

		/* allocate ipsec sa protocol */
		newpr = newsaproto();
		if (newpr == NULL) {
			plog(logp, LOCATION, NULL,
				"failed to allocate saproto.\n");
			goto err;
		}

		/* check spi size */
		/* XXX should be handled isakmp cookie */
		if (sizeof(newpr->spi) < p->prop->spi_size) {
			plog(logp, LOCATION, NULL,
				"invalid spi size %d.\n", p->prop->spi_size);
			goto err;
		}

		newpr->proto_id = p->prop->proto_id;
		newpr->spisize = p->prop->spi_size;
		memcpy(&newpr->spi, p->prop + 1, p->prop->spi_size);
		newpr->reqid_in = 0;
		newpr->reqid_out = 0;

		for (t = p; t; t = t->tnext) {

			YIPSDEBUG(DEBUG_SA,
				plog(logp, LOCATION, NULL,
					"prop#=%d prot-id=%s spi-size=%d "
					"#trns=%d trns#=%d trns-id=%s\n",
					t->prop->p_no,
					s_ipsecdoi_proto(t->prop->proto_id),
					t->prop->spi_size, t->prop->num_t,
					t->trns->t_no,
					s_ipsecdoi_trns(t->prop->proto_id,
					t->trns->t_id)));

			/* allocate ipsec sa transform */
			newtr = newsatrns();
			if (newtr == NULL) {
				plog(logp, LOCATION, NULL,
					"failed to allocate satrns.\n");
				goto err;
			}

			if (ipsecdoi_t2satrns(t->trns, newpp, newpr, newtr) < 0) {
				flushsaprop(newpp);
				return NULL;
			}

			inssatrns(newpr, newtr);
		}

		inssaproto(newpp, newpr);
	}

	return newpp;

err:
	flushsaprop(newpp);
	return NULL;
}

void
flushsaprop(head)
	struct saprop *head;
{
	struct saprop *p, *save;

	for (p = head; p != NULL; p = save) {
		save = p->next;
		flushsaproto(p->head);
		free(p);
	}

	return;
}

void
flushsaproto(head)
	struct saproto *head;
{
	struct saproto *p, *save;

	for (p = head; p != NULL; p = save) {
		save = p->next;
		flushsatrns(p->head);
		free(p);
	}

	return;
}

void
flushsatrns(head)
	struct satrns *head;
{
	struct satrns *p, *save;

	for (p = head; p != NULL; p = save) {
		save = p->next;
		free(p);
	}

	return;
}

/*
 * print multiple proposals
 */
void
printsaprop(pp)
	const struct saprop *pp;
{
	const struct saprop *p;

	if (pp == NULL) {
		plog(logp, LOCATION, NULL, "(null)");
		return;
	}

	for (p = pp; p; p = p->next) {
		printsaprop0(p);
		plognl();
	}

	return;
}

/*
 * print one proposal.
 */
void
printsaprop0(pp)
	const struct saprop *pp;
{
	const struct saproto *p;

	if (pp == NULL)
		return;

	for (p = pp->head; p; p = p->next) {
		printsaproto(p);
	}

	return;
}

void
printsaproto(pr)
	const struct saproto *pr;
{
	struct satrns *tr;

	if (pr == NULL)
		return;

	plog(logp, LOCATION, NULL,
		" (proto_id=%s spisize=%d spi=%08x spi_p=%08x "
		"encmode=%s reqid=%d:%d)\n",
		s_ipsecdoi_proto(pr->proto_id),
		pr->spisize,
		pr->spi,
		pr->spi_p,
		s_ipsecdoi_attr_v(IPSECDOI_ATTR_ENC_MODE, pr->encmode),
		pr->reqid_in, pr->reqid_out);

	for (tr = pr->head; tr; tr = tr->next) {
		printsatrns(pr->proto_id, tr);
	}

	return;
}

void
printsatrns(proto_id, tr)
	const int proto_id;
	const struct satrns *tr;
{
	if (tr == NULL)
		return;

	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_AH:
		plog(logp, LOCATION, NULL,
			"  (trns_id=%s authtype=%s)\n",
			s_ipsecdoi_trns(proto_id, tr->trns_id),
			s_ipsecdoi_attr_v(IPSECDOI_ATTR_AUTH, tr->authtype));
		break;
	case IPSECDOI_PROTO_IPSEC_ESP:
		plog(logp, LOCATION, NULL,
			"  (trns_id=%s encklen=%d authtype=%s)\n",
			s_ipsecdoi_trns(proto_id, tr->trns_id),
			tr->encklen,
			s_ipsecdoi_attr_v(IPSECDOI_ATTR_AUTH, tr->authtype));
		break;
	case IPSECDOI_PROTO_IPCOMP:
		plog(logp, LOCATION, NULL,
			"  (trns_id=%s)\n",
			s_ipsecdoi_trns(proto_id, tr->trns_id));
		break;
	default:
		plog(logp, LOCATION, NULL,
			"(unknown proto_id %d)\n", proto_id);
	}

	return;
}

void
print_proppair0(p, level)
	struct prop_pair *p;
	int level;
{
	char spc[21];

	memset(spc, ' ', sizeof(spc));
	spc[sizeof(spc) - 1] = '\0';
	if (level < 20) {
		spc[level] = '\0';
	}

	plog(logp, LOCATION, NULL,
		"%s%p: next=%p tnext=%p\n", spc, p, p->next, p->tnext);
	if (p->next)
		print_proppair0(p->next, level + 1);
	if (p->tnext)
		print_proppair0(p->tnext, level + 1);
}

void
print_proppair(p)
	struct prop_pair *p;
{
	print_proppair0(p, 1);
}

