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
/* YIPS @(#)$Id: isakmp_ident.c,v 1.1 2000/01/09 01:31:25 itojun Exp $ */

/* Identity Protecion Exchange (Main Mode) */

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

static vchar_t *ident_ir2sendmx __P((struct ph1handle *));
static vchar_t *ident_ir3sendmx __P((struct ph1handle *));

/* %%%
 * begin Identity Protection Mode as initiator.
 */
/*
 * send to responder
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_i1send(iph1, msg)
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

	/* create SA payload for my proposal */
	iph1->sa = ipsecdoi_setph1proposal(iph1->rmconf->proposal);
	if (iph1->sa == NULL)
		goto end;

	/* create buffer to send isakmp payload */
	tlen = sizeof(struct isakmp)
		+ sizeof(*gen) + iph1->sa->l;

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
	p = set_isakmp_payload(p, iph1->sa, ISAKMP_NPTYPE_NONE);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send to responder */
	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		goto end;

	iph1->status = PHASE1ST_MSG1SENT;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:

	return error;
}

/*
 * receive from responder
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_i2recv(iph1, msg)
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
	 * ISAKMP_ETYPE_IDENT, INITIATOR
	 * ISAKMP_NPTYPE_SA,
	 * (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 *
	 * NOTE: RedCreek(as responder) attaches N[responder-lifetime] here,
	 *	if proposal-lifetime > lifetime-redcreek-wants.
	 *	(see doi-08 4.5.4)
	 *	=> According to the seciton 4.6.3 in RFC 2407, This is illegal.
	 * NOTE: we do not really care about ordering of VID and N.
	 *	does it matters?
	 * NOTE: even if there's multiple VID/N, we'll ignore them.
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
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/* don't send information, see ident_r1recv() */
			error = 0;
			plog(logp, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
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

	iph1->status = PHASE1ST_MSG2RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	return error;
}

/*
 * send to responder
 * 	psk: HDR, KE, Ni
 * 	sig: HDR, KE, Ni
 * 	rsa: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * 	rev: HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	          <IDi1_b>Ke_i, [<<Cert-I_b>Ke_i]
 */
int
ident_i2send(iph1, msg)
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

	/* fix isakmp index */
	memcpy(&iph1->index.r_ck, &((struct isakmp *)msg->v)->r_ck,
		sizeof(cookie_t));

	/* generate DH public value */
	if (oakley_dh_generate(iph1->approval->dhgrp,
				&iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	iph1->nonce = eay_set_random(iph1->rmconf->nonce_size);
	if (iph1->nonce == NULL)
		goto end;

	/* create buffer to send isakmp payload */
	iph1->sendbuf = ident_ir2sendmx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;

	iph1->status = PHASE1ST_MSG2SENT;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:
	return error;
}

/*
 * receive from responder
 * 	psk: HDR, KE, Nr
 * 	sig: HDR, KE, Nr
 * 	rsa: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * 	rev: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r,
 */
int
ident_i3recv(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2SENT) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, INITIATOR
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID)
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_ke = NULL;
	iph1->pl_nonce = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			iph1->pl_ke = (struct isakmp_pl_ke *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_NONCE:
			iph1->pl_nonce = (struct isakmp_pl_nonce *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/* don't send information, see ident_r1recv() */
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
	if (iph1->pl_ke == NULL || iph1->pl_nonce == NULL) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}

	iph1->status = PHASE1ST_MSG3RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	return error;
}

/*
 * send to responder
 * 	psk: HDR*, IDi1, HASH_I
 * 	sig: HDR*, IDi1, [ CERT, ] SIG_I
 * 	rsa: HDR*, HASH_I
 * 	rev: HDR*, HASH_I
 */
int
ident_i3send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG3RECEIVED) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* save responder's ke, nonce for use */
	if (isakmp_kn2isa(iph1, iph1->pl_ke, iph1->pl_nonce) < 0)
		goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (oakley_compute_skeyids(iph1) < 0)
		goto end;
	if (oakley_compute_enckey(iph1) < 0)
		goto end;
	if (oakley_newiv(iph1) < 0)
		goto end;

	/* make ID payload into isakmp status */
	if (ipsecdoi_setid1(iph1) < 0)
		goto end;

	/* generate HASH to send */
	iph1->hash = oakley_compute_hash(iph1, GENERATE);
	if (iph1->hash == NULL)
		goto end;

	/* set encryption flag */
	iph1->flags |= ISAKMP_FLAG_E;

	/* create HDR;ID;HASH payload */
	iph1->sendbuf = ident_ir3sendmx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;

	iph1->status = PHASE1ST_MSG3SENT;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:
	return error;
}

/*
 * receive from responder
 * 	psk: HDR*, IDr1, HASH_R
 * 	sig: HDR*, IDr1, [ CERT, ] SIG_R
 * 	rsa: HDR*, HASH_R
 * 	rev: HDR*, HASH_R
 */
int
ident_i4recv(iph1, msg0)
	struct ph1handle *iph1;
	vchar_t *msg0;
{
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	vchar_t *msg = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG3SENT) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		error = 0;
		plog(logp, LOCATION, iph1->remote,
			"ignore the packet, "
			"expecting the packet encrypted.\n");
		goto end;
	}
	msg = oakley_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive);
	if (msg == NULL)
		goto end;

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, INITIATOR
	 * ISAKMP_NPTYPE_ID, ISAKMP_NPTYPE_HASH, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID), (ISAKMP_NPTYPE_N)
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_id = NULL;
	iph1->pl_hash = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_ID:
			iph1->pl_id = (struct ipsecdoi_pl_id *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_HASH:
			iph1->pl_hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_CERT:
			iph1->pl_cert = (struct isakmp_pl_cert *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_SIG:
			iph1->pl_sig = (struct isakmp_pl_sig *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		case ISAKMP_NPTYPE_N:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph1);
			break;
		default:
			/* don't send information, see ident_r1recv() */
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
    {
	int ng = 0;

	switch (iph1->approval->authmethod) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
		if (iph1->pl_id == NULL || iph1->pl_hash == NULL)
			ng++;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
		if (iph1->pl_id == NULL || iph1->pl_sig == NULL)
			ng++;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
		if (iph1->pl_hash == NULL)
			ng++;
		break;
	default:
		plog(logp, LOCATION, iph1->remote,
			"invalid authmethod %d why ?\n",
			iph1->approval->authmethod);
		goto end;
	}
	if (ng) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}
    }

	/* save responder's id */
	if (isakmp_id2isa(iph1, iph1->pl_id) < 0)
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

	/*
	 * XXX: Should we do compare two addresses, ph1handle's and ID
	 * payload's.
	 */

	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, iph1->remote, "ID ");
		hexdump((caddr_t)(iph1->pl_id + 1),
			ntohs(iph1->pl_id->h.len) - sizeof(*iph1->pl_id)));

	iph1->status = PHASE1ST_MSG4RECEIVED;

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
ident_i4send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG4RECEIVED) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* synchronization IV */
	memcpy(iph1->ivm->ivd->v, iph1->ivm->ive->v, iph1->ivm->iv->l);
	memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->iv->l);

	iph1->status = PHASE1ST_ESTABLISHED;

	/* save created date. */
	iph1->created = time(NULL);

	/* add to the schedule to expire, and seve back pointer. */
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
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_r1recv(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	struct ipsecdoi_pl_sa *sa_tmp = NULL;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_START) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, RESPONDER, PHASE1_STATE_ESTABLISHED
	 * ISAKMP_NPTYPE_SA, (ISAKMP_NPTYPE_VID,) ISAKMP_NPTYPE_NONE
	 *
	 * NOTE: XXX even if multiple VID, we'll silently ignore those.
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* check the position of SA paylad */
	if (pa->type != ISAKMP_NPTYPE_SA) {
		plog(logp, LOCATION, iph1->remote,
			"received invalid next payload type %d, "
			"expecting %d.\n",
			pa->type, ISAKMP_NPTYPE_SA);
		goto end;
	}
	sa_tmp = (struct ipsecdoi_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/*
			 * We don't send information to the peer even
			 * if we received malformed packet.  Because we
			 * can't distinguish the malformed packet and
			 * the re-sent packet.  And we do same behavior
			 * when we expect encrypted packet.
			 */
			error = 0;
			plog(logp, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
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
 * 	psk: HDR, SA
 * 	sig: HDR, SA
 * 	rsa: HDR, SA
 * 	rev: HDR, SA
 */
int
ident_r1send(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
	struct isakmp_gen *gen;
	caddr_t p;
	int tlen;
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

	/* create buffer to send isakmp payload */
	tlen = sizeof(struct isakmp)
		+ sizeof(*gen) + iph1->sa_ret->l;

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
	p = set_isakmp_payload(p, iph1->sa_ret, ISAKMP_NPTYPE_NONE);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(iph1->sendbuf, iph1->local, iph1->remote, 0);
#endif

	/* send to responder */
	if (isakmp_send(iph1, iph1->sendbuf) < 0)
		goto end;

	iph1->status = PHASE1ST_MSG1SENT;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:
	if (iph1->sa_ret) {
		vfree(iph1->sa_ret);
		iph1->sa_ret = NULL;
	}

	return error;
}

/*
 * receive from initiator
 * 	psk: HDR, KE, Ni
 * 	sig: HDR, KE, Ni
 * 	rsa: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * 	rev: HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 * 	          <IDi1_b>Ke_i, [<<Cert-I_b>Ke_i]
 */
int
ident_r2recv(iph1, msg)
	struct ph1handle *iph1;
	vchar_t *msg;
{
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
	 * ISAKMP_ETYPE_IDENT, RESPONDER
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID)
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_ke = NULL;
	iph1->pl_nonce = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			iph1->pl_ke = (struct isakmp_pl_ke *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_NONCE:
			iph1->pl_nonce = (struct isakmp_pl_nonce *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		default:
			/* don't send information, see ident_r1recv() */
			error = 0;
			plog(logp, LOCATION, iph1->remote,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			goto end;
		}
	}

	/* payload existency check */
	if (iph1->pl_ke == NULL || iph1->pl_nonce == NULL) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}

	iph1->status = PHASE1ST_MSG2RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	return error;
}

/*
 * send to initiator
 * 	psk: HDR, KE, Nr
 * 	sig: HDR, KE, Nr
 * 	rsa: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * 	rev: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r,
 */
int
ident_r2send(iph1, msg)
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

	/* generate DH public value */
	if (oakley_dh_generate(iph1->approval->dhgrp,
				&iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	iph1->nonce = eay_set_random(iph1->rmconf->nonce_size);
	if (iph1->nonce == NULL)
		goto end;

	/* create HDR;KE;NONCE payload */
	iph1->sendbuf = ident_ir2sendmx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;

	/* save initiator's ke, nonce for use */
	if (isakmp_kn2isa(iph1, iph1->pl_ke, iph1->pl_nonce) < 0)
		goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (oakley_compute_skeyids(iph1) < 0)
		goto end;
	if (oakley_compute_enckey(iph1) < 0)
		goto end;
	if (oakley_newiv(iph1) < 0)
		goto end;

	iph1->status = PHASE1ST_MSG2SENT;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);

	error = 0;

end:
	return error;
}

/*
 * receive from initiator
 * 	psk: HDR*, IDi1, HASH_I
 * 	sig: HDR*, IDi1, [ CERT, ] SIG_I
 * 	rsa: HDR*, HASH_I
 * 	rev: HDR*, HASH_I
 */
int
ident_r3recv(iph1, msg0)
	struct ph1handle *iph1;
	vchar_t *msg0;
{
	vchar_t *msg = NULL;
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG2SENT) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		error = 0;
		plog(logp, LOCATION, iph1->remote,
			"ignore the packet, "
			"expecting the packet encrypted.\n");
		goto end;
	}
	msg = oakley_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive);
	if (msg == NULL)
		goto end;

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, RESPONDER
	 * ISAKMP_NPTYPE_ID, ISAKMP_NPTYPE_HASH, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID), (ISAKMP_NPTYPE_N)
	 */
	pbuf = isakmp_parse(msg);
	if (pbuf == NULL)
		goto end;

	iph1->pl_id = NULL;
	iph1->pl_hash = NULL;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_ID:
			iph1->pl_id = (struct ipsecdoi_pl_id *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_HASH:
			iph1->pl_hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_CERT:
			iph1->pl_cert = (struct isakmp_pl_cert *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_SIG:
			iph1->pl_sig = (struct isakmp_pl_sig *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1->remote);
			break;
		case ISAKMP_NPTYPE_N:
			plog(logp, LOCATION, iph1->remote,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph1);
			break;
		default:
			/* don't send information, see ident_r1recv() */
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
	if (iph1->pl_id == NULL || iph1->pl_hash == NULL) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}

	/* payload existency check */
	/* XXX same as ident_i4recv(), should be merged. */
    {
	int ng = 0;

	switch (iph1->approval->authmethod) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
		if (iph1->pl_id == NULL || iph1->pl_hash == NULL)
			ng++;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
		if (iph1->pl_id == NULL || iph1->pl_sig == NULL)
			ng++;
		break;
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
		if (iph1->pl_hash == NULL)
			ng++;
		break;
	default:
		plog(logp, LOCATION, iph1->remote,
			"invalid authmethod %d why ?\n",
			iph1->approval->authmethod);
		goto end;
	}
	if (ng) {
		plog(logp, LOCATION, iph1->remote,
			"short isakmp message received.\n");
		goto end;
	}
    }

	/* save initiator's id */
	if (isakmp_id2isa(iph1, iph1->pl_id) < 0)
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

	/*
	 * XXX: Should we do compare two addresses, ph1handle's and ID
	 * payload's.
	 */

	YIPSDEBUG(DEBUG_MISC,
		plog(logp, LOCATION, iph1->remote, "ID ");
		hexdump((caddr_t)(iph1->pl_id + 1),
			ntohs(iph1->pl_id->h.len) - sizeof(*iph1->pl_id)));

	iph1->status = PHASE1ST_MSG3RECEIVED;

	error = 0;

end:
	if (pbuf)
		vfree(pbuf);
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * send to initiator
 * 	psk: HDR*, IDr1, HASH_R
 * 	sig: HDR*, IDr1, [ CERT, ] SIG_R
 * 	rsa: HDR*, HASH_R
 * 	rev: HDR*, HASH_R
 */
int
ident_r3send(iph1, msg0)
	struct ph1handle *iph1;
	vchar_t *msg0;
{
	vchar_t *msg = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "begin.\n"));

	/* validity check */
	if (iph1->status != PHASE1ST_MSG3RECEIVED) {
		plog(logp, LOCATION, NULL,
			"status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* make ID payload into isakmp status */
	if (ipsecdoi_setid1(iph1) < 0)
		goto end;

	/* generate HASH to send */
	YIPSDEBUG(DEBUG_KEY, plog(logp, LOCATION, NULL, "generate HASH_R\n"));
	iph1->hash = oakley_compute_hash(iph1, GENERATE);
	if (iph1->hash == NULL)
		goto end;

	/* re-set encryption flag, for serurity. */
	iph1->flags |= ISAKMP_FLAG_E;

	/* create HDR;ID;HASH payload */
	iph1->sendbuf = ident_ir3sendmx(iph1);
	if (iph1->sendbuf == NULL)
		goto end;

	iph1->status = PHASE1ST_ESTABLISHED;

	/* save created date. */
	(void)time(&iph1->created);

#if 0 /* XXX: How resend ? */
	/* add to the schedule to resend, and seve back pointer. */
	iph1->retry_counter = iph1->rmconf->retry_counter;
	iph1->scr = sched_new(iph1->rmconf->retry_interval,
			isakmp_ph1resend, iph1);
#endif
	/* add to the schedule to expire, and seve back pointer. */
	iph1->sce = sched_new(iph1->approval->lifetime, isakmp_ph1expire, iph1);

	plog(logp, LOCATION, iph1->remote,
		"established ISAKMP-SA, %s.\n",
		isakmp_pindex(&iph1->index, 0));
	YIPSDEBUG(DEBUG_STAMP, plog(logp, LOCATION, NULL, "===\n"));

	error = 0;

end:
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * create KE, NONCE payload with isakmp header.
 * This is used in main mode for:
 *	initiator's 3rd exchange
 *	responders 2nd exchnage
 */
static vchar_t *
ident_ir2sendmx(iph1)
	struct ph1handle *iph1;
{
	vchar_t *buf = 0;
	struct isakmp_gen *gen;
	vchar_t *vidhash = NULL;
	char *p;
	int tlen;
	int error = -1;

	/* create buffer */
	tlen = sizeof(struct isakmp)
	     + sizeof(*gen) + iph1->dhpub->l
	     + sizeof(*gen) + iph1->nonce->l;
	if (lcconf->vendorid) {
		vidhash = oakley_hash(lcconf->vendorid, iph1);
		tlen += sizeof(*gen) + vidhash->l;
	}

	buf = vmalloc(tlen);
	if (buf == NULL) {
		plog(logp, LOCATION, NULL,
			"vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	p = set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_KE);
	if (p == NULL)
		goto end;

	/* create isakmp KE payload */
	p = set_isakmp_payload(p, iph1->dhpub, ISAKMP_NPTYPE_NONCE);

	/* create isakmp NONCE payload */
	p = set_isakmp_payload(p, iph1->nonce,
		vidhash ? ISAKMP_NPTYPE_VID : ISAKMP_NPTYPE_NONE);

	/* append vendor id, if needed */
	if (vidhash)
		p = set_isakmp_payload(p, vidhash, ISAKMP_NPTYPE_NONCE);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 0);
#endif

	/* send HDR;KE;NONCE to responder */
	if (isakmp_send(iph1, buf) < 0)
		goto end;

	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}

	if (vidhash != NULL)
		vfree(vidhash);

	return buf;
}

/*
 * This is used in main mode for:
 * initiator's 4th exchange
 * send to responder
 * 	psk: HDR*, IDi1, HASH_I
 * 	sig: HDR*, IDi1, [ CERT, ] SIG_I
 * 	rsa: HDR*, HASH_I
 * 	rev: HDR*, HASH_I
 * responders 3rd exchnage
 * send to initiator
 * 	psk: HDR*, IDr1, HASH_R
 * 	sig: HDR*, IDr1, [ CERT, ] SIG_R
 * 	rsa: HDR*, HASH_R
 * 	rev: HDR*, HASH_R
 */
static vchar_t *
ident_ir3sendmx(iph1)
	struct ph1handle *iph1;
{
	vchar_t *buf = NULL, *new = NULL;
	char *p;
	int tlen;
	struct isakmp_gen *gen;
	int error = -1;

	/* create buffer */
	tlen = sizeof(struct isakmp);

	switch (iph1->approval->authmethod) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
		tlen += sizeof(*gen) + iph1->id->l
			+ sizeof(*gen) + iph1->hash->l;

		buf = vmalloc(tlen);
		if (buf == NULL) {
			plog(logp, LOCATION, NULL,
				"vmalloc (%s)\n", strerror(errno));
			goto end;
		}

		/* set isakmp header */
		p = set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_ID);
		if (p == NULL)
			goto end;

		/* create isakmp ID payload */
		p = set_isakmp_payload(p, iph1->id, ISAKMP_NPTYPE_HASH);

		/* create isakmp HASH payload */
		p = set_isakmp_payload(p, iph1->hash, ISAKMP_NPTYPE_NONE);
		break;
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
	{
		if (oakley_getcert(iph1) < 0)
			goto end;

		tlen += sizeof(*gen) + iph1->id->l
			+ sizeof(*gen) + iph1->sig->l;
		if (iph1->cert != NULL)
			tlen += sizeof(*gen) + iph1->cert->l;

		buf = vmalloc(tlen);
		if (buf == NULL) {
			plog(logp, LOCATION, NULL,
				"vmalloc (%s)\n", strerror(errno));
			goto end;
		}

		/* set isakmp header */
		p = set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_ID);
		if (p == NULL)
			goto end;

		/* add ID payload */
		p = set_isakmp_payload(p, iph1->id, iph1->cert != NULL
							? ISAKMP_NPTYPE_CERT
							: ISAKMP_NPTYPE_SIG);

		/* add CERT payload if there */
		if (iph1->cert != NULL)
			p = set_isakmp_payload(p, iph1->cert, ISAKMP_NPTYPE_SIG);
		p = set_isakmp_payload(p, iph1->sig, ISAKMP_NPTYPE_NONE);
	}
		break;
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
		tlen += sizeof(*gen) + iph1->hash->l;
		break;
	}

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 1);
#endif

	/* encoding */
	new = oakley_do_encrypt(iph1, buf, iph1->ivm->ive, iph1->ivm->iv);
	if (new == NULL)
		goto end;

	vfree(buf);

	buf = new;

	/* send HDR;ID;HASH to responder */
	if (isakmp_send(iph1, buf) < 0)
		goto end;

	/* synchronization IV */
	memcpy(iph1->ivm->ive->v, iph1->ivm->iv->v, iph1->ivm->iv->l);
	memcpy(iph1->ivm->ivd->v, iph1->ivm->iv->v, iph1->ivm->iv->l);

	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}

	return buf;
}

