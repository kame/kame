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
/* YIPS @(#)$Id: isakmp_agg.c,v 1.2 2000/01/09 22:59:35 sakane Exp $ */

/* Aggressive Exchange (Aggressive Mode) */

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
#include "plog.h"
#include "sockmisc.h"
#include "schedule.h"
#include "debug.h"

#include "localconf.h"
#include "remoteconf.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "handler.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "crypto_openssl.h"
#include "pfkey.h"
#include "isakmp_ident.h"
#include "isakmp_inf.h"

/*
 * begin Aggressive Mode as initiator.
 */
/*
 * send to responder
 * 	psk: HDR, SA, KE, Ni, IDi1
 * 	sig: HDR, SA, KE, Ni, IDi1
 * 	rsa: HDR, SA, [ HASH(1),] KE, <IDi1_b>Pubkey_r, <Ni_b>Pubkey_r
 * 	rev: HDR, SA, [ HASH(1),] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	     <IDii_b>Ke_i [, <Cert-I_b>Ke_i ]
 */
int
agg_i1send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg; /* must be null */
{
	struct isakmp_gen *gen;
	caddr_t p;
	int tlen;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_START) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* create isakmp index */
	memset(&iph1->index, 0, sizeof(iph1->index));
	isakmp_newcookie((caddr_t)&iph1->index, iph1->remote, iph1->local);

	/* make ID payload into isakmp status */
	if (ipsecdoi_setid1(iph1) < 0)
		goto end;

	/* create SA payload for my proposal */
	iph1->sa = ipsecdoi_setph1proposal(iph1->rmconf->proposal);
	if (iph1->sa == NULL)
		goto end;

	/* consistency check of proposals */
	if (iph1->rmconf->dhgrp == NULL) {
		plog(logp, LOCATION, NULL,
			"configuration failure about DH group.\n");
		goto end;
	}

	/* generate DH public value */
	if (oakley_dh_generate(iph1->rmconf->dhgrp,
				&iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	iph1->nonce = eay_set_random(iph1->rmconf->nonce_size);
	if (iph1->nonce == NULL)
		goto end;

	/* create buffer to send isakmp payload */
	tlen = sizeof(struct isakmp)
		+ sizeof(*gen) + iph1->sa->l
		+ sizeof(*gen) + iph1->dhpub->l
		+ sizeof(*gen) + iph1->nonce->l
		+ sizeof(*gen) + iph1->id->l;

	iph1->sendbuf = vmalloc(tlen);
	if (iph1->sendbuf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	p = set_isakmp_header(iph1->sendbuf, iph1, ISAKMP_NPTYPE_SA);
	if (p == NULL)
		goto end;

	/* set SA payload to propose */
	p = set_isakmp_payload(p, iph1->sa, ISAKMP_NPTYPE_KE);

	/* create isakmp KE payload */
	p = set_isakmp_payload(p, iph1->dhpub, ISAKMP_NPTYPE_NONCE);

	/* create isakmp NONCE payload */
	p = set_isakmp_payload(p, iph1->nonce, ISAKMP_NPTYPE_ID);

	/* create isakmp ID payload */
	p = set_isakmp_payload(p, iph1->id, ISAKMP_NPTYPE_NONE);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send to responder */
	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		goto end;

	iph1->status = PHASE1ST_MSG1SENT;

	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:
	return error;
}

/*
 * receive from responder
 * 	psk: HDR, SA, KE, Nr, IDr1, HASH_R
 * 	sig: HDR, SA, KE, Nr, IDr1, [ CERT, ] SIG_R
 * 	rsa: HDR, SA, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i, HASH_R
 * 	rev: HDR, SA, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDir_b>Ke_r, HASH_R
 */
int
agg_i2recv(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	struct ipsecdoi_pl_sa *sa_tmp = NULL;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG1SENT) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_AGG, INITIATOR
	 * ISAKMP_NPTYPE_SA,
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_ID,
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	iph1->pl_hash = NULL;

	/* SA paylad is fixed postion */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(logp, LOCATION, iph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
		vfree(pbuf);
		goto end;
	}
	sa_tmp = (struct ipsecdoi_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			if (isakmp_p2ph(iph1->dhpub_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_NONCE:
			if (isakmp_p2ph(iph1->nonce_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_ID:
			if (isakmp_p2ph(iph1->id_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_HASH:
			iph1->pl_hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog(logp, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

	/* payload existency check */
	if (iph1->dhpub_p == NULL || iph1->nonce_p == NULL
	 || iph1->id_p == NULL || iph1->pl_hash == NULL) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}

	/* check SA payload and set approval SA for use */
	if (ipsecdoi_checkph1proposal(sa_tmp, iph1) < 0) {
		plog(logp, LOCATION, iph1->remote,
			"failed to get valid proposal.\n");
		/* XXX send information */
		goto end;
	}
	if (iph1->sa_ret) {
		vfree(iph1->sa_ret);
		iph1->sa_ret = NULL;
	}

	/* fix isakmp index */
	memcpy(&iph1->index.r_ck, &((struct isakmp *)msg->v)->r_ck,
		sizeof(cookie_t));

	/* generate SKEYIDs & IV & final cipher key */
	if (oakley_compute_skeyids(iph1) < 0)
		goto end;
	if (oakley_compute_enckey(iph1) < 0)
		goto end;
	if (oakley_newiv(iph1) < 0)
		goto end;

	/* validate authentication value */
    {
	int type;
	type = oakley_validate_auth(iph1);
	if (type != 0) {
		if (type == -1) {
			/* message printed inner oakley_validate_auth() */
			goto end;
		}
		isakmp_info_send_n1(iph1, type, NULL);
		goto end;
	}
    }

	/* change status of isakmp status entry */
	iph1->status = PHASE1ST_MSG2RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	return error;
}

/*
 * send to responder
 * 	psk: HDR, HASH_I
 * 	sig: HDR, [ CERT, ] SIG_I
 * 	rsa: HDR, HASH_I
 * 	rev: HDR, HASH_I
 */
int
agg_i2send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	struct isakmp_gen *gen;
	char *p;
	int tlen;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2RECEIVED) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* generate HASH to send */
	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "generate HASH_I\n"));
	iph1->hash = oakley_compute_hash(iph1, GENERATE);
	if (iph1->hash == NULL)
		goto end;

	/* create buffer to send isakmp payload */
	tlen = sizeof(struct isakmp)
		+ sizeof(*gen) + iph1->hash->l;
	iph1->sendbuf = vmalloc(tlen);
	if (iph1->sendbuf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	p = set_isakmp_header(iph1->sendbuf, iph1, ISAKMP_NPTYPE_HASH);
	if (p == NULL)
		goto end;

	/* set HASH payload */
	p = set_isakmp_payload(p, iph1->hash, ISAKMP_NPTYPE_NONE);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send to responder */
	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		goto end;

	iph1->status = PHASE1ST_ESTABLISHED;

	/* save created date. */
	(void)time(&iph1->created);

#if 0 /* XXX: How resend ? */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);
#endif
	iph1->sce = sched_new(iph1->approval->lifetime, isakmp_ph1expire, iph1);

	plog(logp, LOCATION, iph1->remote,
		"established ISAKMP-SA, %s.\n",
		isakmp_pindex(&iph1->index, 0));
	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "===\n"));

	error = 0;

end:
	return error;
}

/*
 * receive from initiator
 * 	psk: HDR, SA, KE, Ni, IDi1
 * 	sig: HDR, SA, KE, Ni, IDi1
 * 	rsa: HDR, SA, [ HASH(1),] KE, <IDi1_b>Pubkey_r, <Ni_b>Pubkey_r
 * 	rev: HDR, SA, [ HASH(1),] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	     <IDii_b>Ke_i [, <Cert-I_b>Ke_i ]
 */
int
agg_r1recv(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	struct ipsecdoi_pl_sa *sa_tmp = NULL;
	int error = -1;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_START) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_AGG, RESPONDER, PHASE1ST_ESTABLISHED
	 * ISAKMP_NPTYPE_SA,
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_ID,
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* SA paylad is fixed postion */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(logp, LOCATION, iph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
		vfree(pbuf);
		goto end;
	}
	sa_tmp = (struct ipsecdoi_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			if (isakmp_p2ph(iph1->dhpub_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_NONCE:
			if (isakmp_p2ph(iph1->nonce_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_ID:
			if (isakmp_p2ph(iph1->id_p, pa->ptr) < 0)
				goto end;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog(logp, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}

	/* payload existency check */
	if (iph1->dhpub_p == NULL || iph1->nonce_p == NULL
	 || iph1->id_p == NULL) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}

	/* check SA payload and set approval SA for use */
	if (ipsecdoi_checkph1proposal(sa_tmp, iph1) < 0) {
		plog(logp, LOCATION, iph1->remote,
			"failed to get valid proposal.\n");
		/* XXX send information */
		goto end;
	}

	/* save SA payload minus genera header to calculate hash later */
	iph1->sa = vmalloc(ntohs(sa_tmp->h.len) - sizeof(struct isakmp_gen));
	if (iph1->sa == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		/* XXX send information */
		goto end;
	}
	memmove(iph1->sa->v, &sa_tmp->h + 1,
		ntohs(sa_tmp->h.len) - sizeof(struct isakmp_gen));

	iph1->status = PHASE1ST_MSG1RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);

	return error;
}

/*
 * send to initiator
 * 	psk: HDR, SA, KE, Nr, IDr1, HASH_R
 * 	sig: HDR, SA, KE, Nr, IDr1, [ CERT, ] SIG_R
 * 	rsa: HDR, SA, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i, HASH_R
 * 	rev: HDR, SA, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDir_b>Ke_r, HASH_R
 */
int
agg_r1send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	struct isakmp_gen *gen;
	char *p;
	int tlen;
	vchar_t *vidhash = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG1RECEIVED) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* set responder's cookie */
	isakmp_newcookie((caddr_t)&iph1->index.r_ck, iph1->remote, iph1->local);

	/* make ID payload into isakmp status */
	if (ipsecdoi_setid1(iph1) < 0)
		goto end;

	/* generate DH public value */
	if (oakley_dh_generate(iph1->rmconf->dhgrp,
				&iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	iph1->nonce = eay_set_random(iph1->rmconf->nonce_size);
	if (iph1->nonce == NULL)
		goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (oakley_compute_skeyids(iph1) < 0)
		goto end;
	if (oakley_compute_enckey(iph1) < 0)
		goto end;
	if (oakley_newiv(iph1) < 0)
		goto end;

	/* generate HASH to send */
	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "generate HASH_R\n"));
	iph1->hash = oakley_compute_hash(iph1, GENERATE);
	if (iph1->hash == NULL)
		goto end;

	/* create buffer to send isakmp payload */
	tlen = sizeof(struct isakmp)
		+ sizeof(*gen) + iph1->sa_ret->l
		+ sizeof(*gen) + iph1->dhpub->l
		+ sizeof(*gen) + iph1->nonce->l
		+ sizeof(*gen) + iph1->id->l
		+ sizeof(*gen) + iph1->hash->l;
	if (lcconf->vendorid) {
		vidhash = oakley_hash(lcconf->vendorid, iph1);
		tlen += sizeof(*gen) + vidhash->l;
	}

	iph1->sendbuf = vmalloc(tlen);
	if (iph1->sendbuf == NULL) { 
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	p = set_isakmp_header(iph1->sendbuf, iph1, ISAKMP_NPTYPE_SA);
	if (p == NULL)
		goto end;

	/* set SA payload to reply */
	p = set_isakmp_payload(p, iph1->sa_ret, ISAKMP_NPTYPE_KE);

	/* create isakmp KE payload */
	p = set_isakmp_payload(p, iph1->dhpub, ISAKMP_NPTYPE_NONCE);

	/* create isakmp NONCE payload */
	p = set_isakmp_payload(p, iph1->nonce, ISAKMP_NPTYPE_ID);

	/* create isakmp ID payload */
	p = set_isakmp_payload(p, iph1->id, ISAKMP_NPTYPE_HASH);

	/* create isakmp HASH payload */
	p = set_isakmp_payload(p, iph1->hash,
		vidhash ? ISAKMP_NPTYPE_VID : ISAKMP_NPTYPE_NONE);

	/* append vendor id, if needed */
	if (vidhash)
		p = set_isakmp_payload(p, vidhash, ISAKMP_NPTYPE_NONE);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 1);
#endif

	/* send HDR;SA to responder */
	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		goto end;

	iph1->status = PHASE1ST_MSG1SENT;

	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:
	if (iph1->sa_ret != NULL) {
		vfree(iph1->sa_ret);
		iph1->sa_ret = NULL;
	}
	if (vidhash != NULL)
		vfree(vidhash);

	return error;
}

/*
 * receive from initiator
 * 	psk: HDR, HASH_I
 * 	sig: HDR, [ CERT, ] SIG_I
 * 	rsa: HDR, HASH_I
 * 	rev: HDR, HASH_I
 */
int
agg_r2recv(iph1, msg0)
	struct ph1handle *iph1;
	vchar_t *msg0;
{
	vchar_t *msg = NULL;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG1SENT) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting if need. */
	/* XXX configurable ? */
	if (ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		msg = oakley_do_decrypt(iph1, msg0,
					iph1->ivm->iv, iph1->ivm->ive);
		if (msg == NULL)
			goto end;
	} else
		msg = vdup(msg0);

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_AGG, RESPONDER
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_hash = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_HASH:
			iph1->pl_hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog(logp, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}

	/* validate authentication value */
    {
	int type;
	type = oakley_validate_auth(iph1);
	if (type != 0) {
		if (type == -1) {
			/* message printed inner oakley_validate_auth() */
			goto end;
		}
		isakmp_info_send_n1(iph1, type, NULL);
		goto end;
	}
    }

	iph1->status = PHASE1ST_MSG2RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * status update and establish isakmp sa.
 */
int
agg_r2send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2RECEIVED) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* synchronization IV when packet encrypted. */
	if (ISSET(((struct isakmp *)msg->v)->flags, ISAKMP_FLAG_E)) {
		memcpy(iph1->ivm->ivd->v, iph1->ivm->ive->v, iph1->ivm->iv->l);
		memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->iv->l);
	}

	/* change status of isakmp status entry */
	iph1->status = PHASE1ST_ESTABLISHED;

	/* save created date. */
	iph1->created = time(NULL);

	iph1->sce = sched_new(iph1->approval->lifetime, isakmp_ph1expire, iph1);

	plog(logp, LOCATION, iph1->remote,
		"established ISAKMP-SA, %s.\n",
		isakmp_pindex(&iph1->index, 0));
	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "===\n"));

	error = 0;

end:
	return error;
}

