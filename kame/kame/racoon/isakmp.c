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
/* YIPS @(#)$Id: isakmp.c,v 1.1.1.1 1999/08/08 23:31:22 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <net/route.h>
#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key_var.h>

#include <netinet/in.h>

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
#include <netdb.h>

#include "var.h"
#include "vmbuf.h"
#include "schedule.h"
#include "cfparse.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_inf.h"
#include "handler.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "crypto.h"
#include "pfkey.h"
#include "admin.h"
#include "post_com.h"
#include "misc.h"
#include "debug.h"

#define PH1_CHECK_ORDER(p, t, n) \
  if (p->type != t) {\
    plog2(from, n, "received invalid next payload type %d, expecting %d.\n",\
	p->type, t);\
    vfree(pbuf);\
    goto end;\
  }

#define PH2_CHECK_ORDER(p, t, n) \
  if (p->type != t) {\
    plog2(from, n, "received invalid next payload type %d, expecting %d.\n",\
	p->type, t);\
    vfree(pbuf);\
    goto end;\
  }

static u_char r_ck0[] = { 0,0,0,0,0,0,0,0 }; /* used to verify the r_ck. */
static u_char msgid0[] = { 0,0,0,0 }; /* used to verify the msgid. */

u_int isakmp_try = ISAKMP_TRY_DEFAULT;
u_int isakmp_timer = ISAKMP_TIMER_DEFAULT;
static u_int isakmp_nonce_size = DEFAULTNONCESIZE;
static u_int local_secret_size = DEFAULTSECRETSIZE;
int isakmp_random_padding = 0;
u_int isakmp_random_padsize = MAXPADLWORD;
int isakmp_check_padding = 0;
int isakmp_pad_exclone = 0;

/* quick mode */
int isakmp_quick_r3 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph2 *));
int isakmp_quick_i3 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph2 *));
int isakmp_quick_r1 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph2 *));
int isakmp_quick_i1 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph2 *));
static vchar_t *isakmp_quick_ir1mx __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph2 *));
static int isakmp_compute_keymat(struct isakmp_ph2 *iph2, int dir);
static vchar_t *isakmp_compute_keymat_x(struct isakmp_ph2 *iph2, int dir, int sa_dir);

int isakmp_newgroup_r __P((vchar_t *msg, struct sockaddr *from, struct isakmp_ph1 *iph1));

/* main mode */
static int isakmp_ident_i4 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_ident_r3 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_ident_i3 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_ident_r2 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_ident_i2 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_ident_r1 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_ident_i1 __P((vchar_t *, struct sockaddr *,
				struct isakmp_ph1 *));
static vchar_t *isakmp_ident_ir3mx __P((struct sockaddr *,
				struct isakmp_ph1 *));
static vchar_t *isakmp_ident_ir2mx __P((struct sockaddr *,
				struct isakmp_ph1 *));
static int isakmp_aggressive_r2 __P((vchar_t *msg, struct sockaddr *from,
				struct isakmp_ph1 *));
static int isakmp_aggressive_i2 __P((vchar_t *msg, struct sockaddr *from,
				struct isakmp_ph1 *));
static int isakmp_aggressive_r1 __P((vchar_t *msg, struct sockaddr *from,
				struct isakmp_ph1 *));
static int isakmp_aggressive_i1 __P((vchar_t *msg, struct sockaddr *from,
				struct isakmp_ph1 *));
static int isakmp_compute_skeyids __P((struct isakmp_ph1 *));
static int isakmp_compute_enckey __P((struct isakmp_ph1 *));
static vchar_t *isakmp_compute_hash __P((struct isakmp_ph1 *, int));
static vchar_t *isakmp_prf __P((vchar_t *, vchar_t *, struct isakmp_ph1 *));
static vchar_t *isakmp_hash __P((vchar_t *, struct isakmp_ph1 *));
static int isakmp_dh_compute __P((const struct dh *, vchar_t *, vchar_t *,
				vchar_t *, vchar_t **));
static int isakmp_dh_generate __P((const struct dh *, vchar_t **, vchar_t **));
static int isakmp_padlen __P((int));
static int isakmp_id2isa __P((struct isakmp_ph1 *, struct isakmp_pl_id *));
static int isakmp_kn2isa __P((struct isakmp_ph1 *, struct isakmp_pl_ke *,
				struct isakmp_pl_nonce *));

static void isakmp_check_vendorid __P((struct isakmp_gen *, struct isakmp_ph1 *,
	struct sockaddr *));
static void isakmp_check_notify __P((struct isakmp_gen *, struct isakmp_ph1 *,
	struct sockaddr *));
static int etypesw __P((int etype));

int (*isakmp_exchange[][2][ISAKMP_STATE_MAX])() = {
{	/* reserved */
	{NULL,NULL,NULL,NULL,NULL},
	{NULL,NULL,NULL,NULL,NULL},
},
{	/* Identity Protection exchange */
    {	/* INITIATOR */
	NULL, isakmp_ident_i1, isakmp_ident_i2, isakmp_ident_i3, isakmp_ident_i4,
    },
    {	/* RESPONDER */
	NULL, isakmp_ident_r1, isakmp_ident_r2, isakmp_ident_r3, NULL,
    },
},
{	/* Aggressive exchange */
    {	/* INITIATOR */
	NULL, isakmp_aggressive_i1, isakmp_aggressive_i2, NULL, NULL,
    },
    {	/* RESPONDER */
	NULL, isakmp_aggressive_r1, isakmp_aggressive_r2, NULL, NULL,
    },
},
{	/* Quick mode for IKE*/
    {	/* INITIATOR */
	NULL, isakmp_quick_i1, isakmp_quick_i2, isakmp_quick_i3, NULL,
    },
    {	/* RESPONDER */
	NULL, isakmp_quick_r1, isakmp_quick_r2, isakmp_quick_r3, NULL,
    },
},
{	/* Newg roup mode for IKE*/
    {	/* INITIATOR */
	NULL, NULL, NULL, NULL, NULL,
    },
    {	/* RESPONDER */
	NULL, isakmp_newgroup_r, NULL, NULL, NULL
    },
},
};

struct cipher_algorithm cipher[] = {
{ "NULL",	NULL,			NULL,			NULL, },
{ "des",	eay_des_encrypt,	eay_des_decrypt,	eay_des_weakkey, },
{ "idea",	eay_idea_encrypt,	eay_idea_decrypt,	eay_idea_weakkey, },
{ "blowfish",	eay_bf_encrypt,		eay_bf_decrypt,		eay_bf_weakkey, },
{ "rc5",	eay_rc5_encrypt,	eay_rc5_decrypt,	eay_rc5_weakkey, },
{ "3des",	eay_3des_encrypt,	eay_3des_decrypt,	eay_3des_weakkey, },
{ "cast",	eay_cast_decrypt,	eay_cast_decrypt,	eay_cast_weakkey, },
};

/*
 * main processing to handle isakmp payload
 */
int
isakmp_main(msg, remote, local)
	vchar_t *msg;
	struct sockaddr *remote, *local;
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	isakmp_index *index = (isakmp_index *)isakmp;
	msgid_t *msgid = &isakmp->msgid;
	struct isakmp_conf *cfp = NULL;
	struct isakmp_ph1 *iph1;

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(msg, remote, local, 0);
#endif

	/* Check the Major and Minor Version fields. */
	/*
	 * XXX Is is right to check version here ?
	 * I think it may no be here because the version depends
	 * on exchange status.
	 */
	if (isakmp->v_number < ISAKMP_VERSION_NUMBER) {

		if (isakmp->v_major < ISAKMP_MAJOR_VERSION) {
			YIPSDEBUG(DEBUG_NOTIFY,
				plog2(remote, LOCATION,
					"invalid major version %d.\n",
					isakmp->v_major));
			return -1;
		}

#if ISAKMP_MINOR_VERSION > 0
		if (isakmp->v_minor < ISAKMP_MINOR_VERSION) {
			YIPSDEBUG(DEBUG_NOTIFY,
				plog2(remote, LOCATION,
					"invalid minor version %d.\n",
					isakmp->v_minor));
			return -1;
		}
#endif
	}

	/* check the Flags field. */
	/* XXX How is the exclusive check, E and A ? */
	if (isakmp->flags & ~(ISAKMP_FLAG_E | ISAKMP_FLAG_C | ISAKMP_FLAG_A)) {
		YIPSDEBUG(DEBUG_NOTIFY,
		    plog2(remote, LOCATION,
		        "invalid flag 0x%02x.\n", isakmp->flags));
		return -1;
	}

	/* ignore commit bit. */
	if (ISSET(isakmp->flags, ISAKMP_FLAG_C)) {
		YIPSDEBUG(DEBUG_NOTIFY,
		    plog2(remote, LOCATION,
		        "ISAKMP_FLAG_C unsupported (ignored).\n"));
	}

	/* look for my configuration */
	if ((cfp = isakmp_cfbypeer(remote)) == NULL) {
		plog2(remote, LOCATION,
			"couldn't find configuration.\n");
		return -1;
	}

	/* XXX acceptable check */

	iph1 = isakmp_ph1byindex(index);

	switch (isakmp->etype) {
	case ISAKMP_ETYPE_IDENT:
	case ISAKMP_ETYPE_AGG:
	    {
		/* search isakmp status record of phase 1 */
		if (iph1 == NULL) {
			/*
			 * This packet may be responder's 1st or initiator's
			 * 2nd exchange.
			 */

			/* search isakmp status table by index in which r_ck is zero */
			iph1 = isakmp_ph1byindex0(index);
			if (iph1 == NULL) {
				/* validity check */
				if (memcmp(&isakmp->r_ck, r_ck0, sizeof(cookie_t)) != 0) {
					YIPSDEBUG(DEBUG_NOTIFY,
						plog(LOCATION,
							"mulformed packet, "
							"responder's cookie was filled.\n"));
					return -1;
				}

				/* This packet is responder's 1st exchange. */
				YIPSDEBUG(DEBUG_NOTIFY,
					plog(LOCATION,
						"begin IDENTITY PROTECTION mode.\n"));

				/* add new entry to isakmp status table. */
				if ((iph1 = isakmp_new_ph1(index)) == NULL)
					return -1;

				iph1->status = ISAKMP_STATE_1;
				iph1->cfp = cfp;

				iph1->dir = RESPONDER;
				iph1->version = isakmp->v_number;
				iph1->etype = isakmp->etype;
				iph1->flags = 0;

				/* copy local address */
				GET_NEWBUF(iph1->local, struct sockaddr *, local, local->sa_len);
				if (iph1->local == NULL) {
					plog(LOCATION, "malloc (%s)\n", strerror(errno));
					(void)isakmp_free_ph1(iph1);
					return -1;
				}

				/* copy remote address */
				GET_NEWBUF(iph1->remote, struct sockaddr *, remote, remote->sa_len);
				if (iph1->remote == NULL) {
					plog(LOCATION, "malloc (%s)\n", strerror(errno));
					(void)isakmp_free_ph1(iph1);
					return -1;
				}
			}
		}

		/* turn off schedule */
		if (iph1->sc != NULL)
			sched_kill(&iph1->sc);
	
		if (iph1->status >= ISAKMP_STATE_MAX
		 || isakmp_exchange[etypesw(isakmp->etype)][iph1->dir][iph1->status] == NULL) {
			(void)isakmp_free_ph1(iph1);
			return -1;
		}

		YIPSDEBUG(DEBUG_MISC,
			plog(LOCATION,
				"call by etype=%d, dir=%d and status=%d\n",
				etypesw(isakmp->etype), iph1->dir, iph1->status));

		if ((isakmp_exchange[etypesw(isakmp->etype)][iph1->dir][iph1->status])(msg, remote, iph1) < 0) {
			(void)isakmp_free_ph1(iph1);
			return -1;
		}
	    }
		break;

	case ISAKMP_ETYPE_INFO:
		/*
		 * iph1 must be present for Inoformation message.
		 * if iph1 is null then trying to get the phase1 status
		 * as the packet from responder againt initiator's 1st
		 * exchange in phase 1.
		 * NOTE: We think such informational exchange should be ignored.
		 */
		if (iph1 == NULL
		 && (iph1 = isakmp_ph1byindex0(index)) == NULL) {
			YIPSDEBUG(DEBUG_NOTIFY,
				plog(LOCATION,
					"ignored, Unknown pakcet received.\n"));
			return -1;
		}

		if (isakmp_info_recv(iph1, msg, remote) < 0)
			return -1;
		break;

	case ISAKMP_ETYPE_BASE:
	case ISAKMP_ETYPE_AUTH:
		YIPSDEBUG(DEBUG_NOTIFY,
		    plog2(remote, LOCATION,
		        "invalid exchange type %d, not supported.\n", isakmp->etype));
		break;

	case ISAKMP_ETYPE_QUICK:
	    {
		struct isakmp_ph2 *iph2;

		if (iph1 == NULL) {
			isakmp_info_send_nx(isakmp, remote, local,
				ISAKMP_NTYPE_INVALID_COOKIE, NULL);
			YIPSDEBUG(DEBUG_NOTIFY,
			    plog2(remote, LOCATION,
				"Unknown packet, there is no ISAKMP-SA.\n"));
			return -1;
		}

		/* check status of phase 1 whether negotiated or not. */
		if (iph1->status != ISAKMP_STATE_ESTABLISHED) {
			YIPSDEBUG(DEBUG_NOTIFY,
			    plog2(remote, LOCATION,
				"Unknown packet, there is no valid ISAKMP-SA.\n"));
			return -1;
		}

		/* search isakmp phase 2 stauts record. */
		if ((iph2 = isakmp_ph2bymsgid(iph1, msgid)) == NULL) {

			/* It's new negotiation in phase 2 */
			if ((iph2 = isakmp_new_ph2(iph1, msgid)) == NULL)
				return -1;

			iph2->dir = RESPONDER;
			iph2->status = ISAKMP_STATE_1;

			if ((iph2->ivm = isakmp_new_iv2(iph2->ph1, &iph2->msgid)) == NULL) {
				isakmp_free_ph2(iph2);
				return -1;
			}
		}

		/* turn off schedule */
		if (iph2->sc != NULL)
			sched_kill(&iph2->sc);
		if (iph2->pst != NULL && iph2->pst->sc != NULL)
			sched_kill(&iph2->pst->sc);
	
		if (iph2->status >= ISAKMP_STATE_MAX
		 || isakmp_exchange[etypesw(isakmp->etype)][iph2->dir][iph2->status] == NULL) {
			(void)isakmp_free_ph2(iph2);
			return -1;
		}
		
		if ((isakmp_exchange[etypesw(isakmp->etype)][iph2->dir][iph2->status])(msg, remote, iph2) < 0) {
			(void)isakmp_free_ph2(iph2);
			return -1;
		}

		/*
		 * phase 2 status is deleted when last exchage.
		 */
	    }
		break;

	case ISAKMP_ETYPE_NEWGRP:
		if (iph1 == NULL) {
			YIPSDEBUG(DEBUG_NOTIFY,
				plog2(remote, LOCATION,
					"Unknown packet, there is no ISAKMP-SA.\n"));
			return -1;
		}
		isakmp_newgroup_r(msg, remote, iph1);
		break;

	case ISAKMP_ETYPE_NONE:
	default:
		YIPSDEBUG(DEBUG_NOTIFY,
		    plog2(remote, LOCATION,
		        "Invalid exchange type %d.\n", isakmp->etype));
		return -1;
	}

	return 0;
}

struct isakmp_ph1 *
isakmp_begin_phase1(cfp, local, remote)
	struct isakmp_conf *cfp;
	struct sockaddr *local;
	struct sockaddr *remote;
{
	struct isakmp_ph1 *iph1;
	isakmp_index index;
	int error = -1;

	/* create isakmp index */
	memset((char *)&index, 0, sizeof(index));
	isakmp_set_cookie((char *)&index, remote);

	/* add new entry to isakmp status table */
	if ((iph1 = isakmp_new_ph1(&index)) == NULL)
		goto end;

	iph1->cfp = cfp;
	iph1->status = ISAKMP_STATE_1;

	/* set local address */
	GET_NEWBUF(iph1->local, struct sockaddr *, local, local->sa_len);
	if (iph1->local == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set remote address */
	GET_NEWBUF(iph1->remote, struct sockaddr *, remote, remote->sa_len);
	if (iph1->remote == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto end;
	}

	/* begin ident mode */
	/* XXX: variable ? */
	switch (iph1->cfp->ph[0]->etype) {
	case ISAKMP_ETYPE_AGG:
		plog(LOCATION, "begin AGGRESSIVE mode.\n");
		if (isakmp_aggressive_i1((vchar_t *)NULL, remote, iph1) < 0)
			goto end;
		break;
	case ISAKMP_ETYPE_IDENT:
		plog(LOCATION, "begin IDENTITY PROTECTION mode.\n");
		if (isakmp_ident_i1((vchar_t *)NULL, remote, iph1) < 0)
			goto end;
		break;
	}

	error = 0;

end:
	if (error) {
		if (iph1 != NULL)
			(void)isakmp_free_ph1(iph1);
		iph1 = NULL;
	}
	return iph1;
}

int
isakmp_begin_quick(iph1, pst)
	struct isakmp_ph1 *iph1;
	struct pfkey_st *pst;
{
	struct isakmp_ph2 *iph2 = 0;
	u_int32_t msgid2;
	int error = -1;

	/* add new entry to isakmp status table */
	msgid2 = isakmp_get_msgid2(iph1);
	if ((iph2 = isakmp_new_ph2(iph1, (msgid_t *)&msgid2)) == NULL)
		goto end;

	/* save ph2 pointer */
	pst->ph2 = iph2;

	iph2->dir = INITIATOR;
	iph2->pst = pst;
	iph2->status = ISAKMP_STATE_1;

	if ((iph2->ivm = isakmp_new_iv2(iph2->ph1, &iph2->msgid)) == NULL) {
		isakmp_free_ph2(iph2);
		goto end;
	}

	/* begin quick mode */
	if (isakmp_quick_i1((vchar_t *)0, NULL, iph2) < 0) goto end;

	error = 0;
end:
	if (error) {
		if (iph2 != NULL)
			(void)isakmp_free_ph2(iph2);
		iph2 = NULL;
	}
	return error;
}

/*
 * parse ISAKMP payloads, without ISAKMP base header.
 */
vchar_t *
isakmp_parse0(np0, gen, len)
	int np0;
	struct isakmp_gen *gen;
	int len;
{
	u_char np = np0 & 0xff;
	int tlen, plen;
	vchar_t *result;
	struct isakmp_parse_t *p, *ep;
	static char *npstr[] = {
		"none", "sa", "p", "t", "ke", "id", "cert", "cr", "hash",
		"sig", "nonce", "n", "d", "vid"
	};

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/*
	 * 5 is a magic number, but any value larger than 2 should be fine
	 * as we VREALLOC() in the following loop.
	 */
	result = vmalloc(sizeof(struct isakmp_parse_t) * 5);
	if (result == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		return NULL;
	}
	p = (struct isakmp_parse_t *)result->v;
	ep = (struct isakmp_parse_t *)(result->v + result->l - sizeof(*ep));

	tlen = len;

	/* parse through general headers */
	while (0 < tlen && np != ISAKMP_NPTYPE_NONE) {
		if (tlen <= sizeof(struct isakmp_gen)) {
			/* don't send information, see isakmp_ident_r1() */
			YIPSDEBUG(DEBUG_NOTIFY,
			    plog(LOCATION, "invalid length of payload\n"));
			vfree(result);
			return NULL;
		}

		YIPSDEBUG(DEBUG_NOTIFY,
			plog(LOCATION, "seen nptype=%u(%s)\n", np,
				(np < sizeof(npstr)/sizeof(npstr[0]))
					? npstr[np]
					: "?"));

		p->type = np;
		p->len = ntohs(gen->len);
		p->ptr = gen;
		p++;
		if (ep <= p) {
			int off;

			off = p - (struct isakmp_parse_t *)result->v;
			if (!VREALLOC(result, result->l * 2)) {
				perror("vrealloc");
				vfree(result);
				return NULL;
			}
			result->l *= 2;
			ep = (struct isakmp_parse_t *)
				(result->v + result->l - sizeof(*ep));
			p = (struct isakmp_parse_t *)result->v;
			p += off;
		}

		np = gen->np;
		plen = ntohs(gen->len);
		gen = (struct isakmp_gen *)((caddr_t)gen + plen);
		tlen -= plen;
	}
	p->type = ISAKMP_NPTYPE_NONE;
	p->len = 0;
	p->ptr = NULL;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "succeed.\n"));

	return result;
}

/*
 * parse ISAKMP payloads, including ISAKMP base header.
 */
vchar_t *
isakmp_parse(buf, from)
	vchar_t *buf;
	struct sockaddr *from;
{
	struct isakmp *isakmp = (struct isakmp *)buf->v;
	struct isakmp_gen *gen;
	int tlen;
	vchar_t *result;
	u_char np;

	YIPSDEBUG(DEBUG_STAMP, plog2(from, LOCATION, "begin.\n"));

	np = isakmp->np;
	gen = (struct isakmp_gen *)(buf->v + sizeof(*isakmp));
	tlen = buf->l - sizeof(struct isakmp);

	result = isakmp_parse0(np, gen, tlen);
	YIPSDEBUG(DEBUG_STAMP, plog2(from, LOCATION, "end.\n"));
	return result;
}

/* %%%
 * Quick Mode
 */
/*
 * receive HDR*, HASH(3) from initiator, and set SA to kernel.
 */
int
isakmp_quick_r3(msg0, from, iph2)
	vchar_t *msg0;
	struct sockaddr *from;
	struct isakmp_ph2 *iph2;
{
	vchar_t *msg = NULL;
	struct isakmp_pl_hash *hash = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph2->status != ISAKMP_STATE_3) {
		plog(LOCATION, "status mismatched %d.\n", iph2->status);
		goto end;
	}

	/* decrypt packet */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		plog2(from, LOCATION, "Packet wasn't encrypted.\n");
		goto end;
	}
	if ((msg = isakmp_do_decrypt(iph2->ph1, msg0, iph2->ivm->iv, iph2->ivm->ive)) == NULL)
		goto end;

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_QUICK, RESPONDER, ISAKMP_STATE_1
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_N), ISAKMP_NPTYPE_NONE
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_HASH:
			hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_N:
			plog2(from, LOCATION,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph2->ph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (hash == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* validate HASH(3) */
	/* HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b) */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	vchar_t *tmp = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH(3)\n"));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	if ((tmp = vmalloc(iph2->nonce_p->l + iph2->nonce->l)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(tmp->v, iph2->nonce_p->v, iph2->nonce_p->l);
	memcpy(tmp->v + iph2->nonce_p->l, iph2->nonce->v, iph2->nonce->l);

	my_hash = isakmp_compute_hash3(iph2->ph1, &iph2->msgid, tmp);
	vfree(tmp);
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog2(from, LOCATION, "HASH(3) mismatch.\n");
		isakmp_info_send_n2(iph2, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL, iph2->ph1->flags);
		goto end;
	}
    }

	/* compute both of KEYMATs */
	if (isakmp_compute_keymat(iph2, RESPONDER) < 0) goto end;

	/* Do UPDATE for initiator */
	if (!f_local) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "call PFKEY UPDATE\n"));
		if (pfkey_send_update_wrap(sock_pfkey, iph2) < 0) {
			plog(LOCATION, "PFKEY UPDATE failed.\n");
			goto end;
		}
	}

	/* Do ADD for responder */
	if (!f_local) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "call PFKEY ADD\n"));
		if (pfkey_send_add_wrap(sock_pfkey, iph2) < 0) {
			plog(LOCATION, "PFKEY ADD failed.\n");
			goto end;
		}
	}

	/* change status of isakmp status entry */
	iph2->status = ISAKMP_STATE_ESTABLISHED;

	plog2(from, LOCATION,
	    "get SA values for IPsec, %s.\n",
	        isakmp_pindex(&iph2->ph1->index, &iph2->msgid));

	error = 0;

end:
	if (iph2 != NULL)
		(void)isakmp_free_ph2(iph2);
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * receive HDR*;HASH(2);SA;Nr;[KE];[IDci,IDcr] from responder,
 * and send HDR*;HASH(3)
 */
int
isakmp_quick_i3(msg0, from, iph2)
	vchar_t *msg0;
	struct sockaddr *from;
	struct isakmp_ph2 *iph2;
{
	vchar_t *msg = NULL;
	vchar_t *buf = NULL, *body = NULL;
	struct isakmp *isakmp = (struct isakmp *)msg0->v;
	struct isakmp_gen *gen;
	struct isakmp_pl_hash *hash = NULL;
	struct ipsecdoi_sa *sa_tak = NULL; /* SA payloads to parse. */
	vchar_t *sa_ret = NULL; /* SA payload for reply. */
	int f_id;
	char *p;
	int tlen;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph2->status != ISAKMP_STATE_3) {
		plog(LOCATION, "status mismatched %d.\n", iph2->status);
		goto end;
	}

	/* decrypt packet */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		plog2(from, LOCATION, "Packet wasn't encrypted.\n");
		goto end;
	}
	if ((msg = isakmp_do_decrypt(iph2->ph1, msg0, iph2->ivm->iv, iph2->ivm->ive)) == NULL)
		goto end;

	/* create buffer for validating HASH(2) */
	/*
	 * ISAKMP_ETYPE_QUICK, INITIATOR, ISAKMP_STATE_1
	 * ISAKMP_NPTYPE_HASH, ISAKMP_NPTYPE_SA
	 * ISAKMP_NPTYPE_NONCE,
	 * (ISAKMP_NPTYPE_KE), (ISAKMP_NPTYPE_ID, ISAKMP_NPTYPE_ID)
	 * (ISAKMP_NPTYPE_N)
	 *
	 * ordering rule:
	 *	1. the first one must be HASH
	 *	2. the second one must be SA (added in isakmp-oakley-05!)
	 *	3. two IDs must be considered as IDci, then IDcr
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* HASH paylad is fixed postion */
	PH2_CHECK_ORDER(pa, ISAKMP_NPTYPE_HASH, LOCATION);
	hash = (struct isakmp_pl_hash *)pa->ptr;
	pa++;

#if 0
	/*
	 * this restriction was introduced in isakmp-oakley-05.
	 * we do not check this for backward compatibility.
	 * TODO: command line/config file option to enable/disable this code
	 */
	/* HASH paylad is fixed postion */
	PH2_CHECK_ORDER(pa, ISAKMP_NPTYPE_SA, LOCATION);
#endif

	/* allocate buffer for computing HASH(2) */
	tlen = iph2->nonce->l
		+ ntohl(isakmp->len) - sizeof(*isakmp);
	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		vfree(pbuf);
		goto end;
	}
	p = buf->v + iph2->nonce->l;	/* retain the space for Ni_b */

	/*
	 * parse the payloads.
	 * copy non-HASH payloads into buf, so that we can validate HASH.
	 */
	sa_tak = NULL;	/* don't support multi SAs. */
	f_id = 0;	/* flag to use checking ID */
	tlen = 0;	/* count payload length except of HASH payload. */
	for (; pa->type; pa++) {

		/* copy to buffer for HASH */
		/* Don't modify the payload */
		memcpy(p, pa->ptr, pa->len);

		switch (pa->type) {
		case ISAKMP_NPTYPE_SA:
			if (sa_tak != NULL) {
				plog(LOCATION,
					"Ignored, multiple SA isn't supported.\n");
				break;
			}
			sa_tak = (struct ipsecdoi_sa *)pa->ptr;
			break;

		case ISAKMP_NPTYPE_NONCE:
			if ((iph2->nonce_p = vmalloc(pa->len - sizeof(struct isakmp_gen))) == NULL) {
				plog(LOCATION,
					"vmalloc (%s)\n", strerror(errno));
				vfree(pbuf);
				goto end;
			}
			memcpy(iph2->nonce_p->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen),
				iph2->nonce_p->l);
			break;

		case ISAKMP_NPTYPE_KE:
			if ((iph2->dhpub_p = vmalloc(pa->len - sizeof(struct isakmp_gen))) == NULL) {
				plog(LOCATION,
					"vmalloc (%s)\n", strerror(errno));
				vfree(pbuf);
				goto end;
			}
			memcpy(iph2->dhpub_p->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen),
				iph2->dhpub_p->l);
			break;

		case ISAKMP_NPTYPE_ID:
		    {
			vchar_t *vp;

			/* check ID value */
			if (f_id == 0) {
				/* for IDci */
				f_id = 1;
				vp = iph2->id;
			} else {
				/* for IDcr */
				vp = iph2->id_p;
			}

			if (memcmp(vp->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen), vp->l)) {

				isakmp_info_send_n2(iph2, ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED, NULL, 0);
				plog(LOCATION,
					"mismatched ID was returned.\n");
				vfree(pbuf);
				goto end;
			}
		    }
			break;

		case ISAKMP_NPTYPE_N:
			plog2(from, LOCATION,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph2->ph1, from);
			break;

		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}

		p += pa->len;

		/* compute true length of payload. */
		tlen += pa->len;
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (hash == NULL || sa_tak == NULL || iph2->nonce_p == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* Fixed buffer for calculating HASH */
	memcpy(buf->v, iph2->nonce->v, iph2->nonce->l);
	YIPSDEBUG(DEBUG_KEY,
		plog(LOCATION,
			"HASH allocated:buf->l=%d actual:tlen=%d\n",
			buf->l, tlen + iph2->nonce->l));
	/* adjust buffer length for HASH */
	buf->l = iph2->nonce->l + tlen;

	/* validate HASH(2) */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "received HASH(2)\n"));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	my_hash = isakmp_compute_hash1(iph2->ph1, &iph2->msgid, buf);
	vfree(buf);
	buf = NULL;
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog2(from, LOCATION, "HASH(2) mismatch.\n");
		isakmp_info_send_n2(iph2, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL, iph2->ph1->flags);
		goto end;
	}
    }

	/* XXX check SA returned. */

	/* check SA payload and get new one for use */
	if ((sa_ret = ipsecdoi_get_proposal(sa_tak, OAKLEY_QUICK_MODE)) == 0) {
		/* XXX ??? send information ? */
		goto end;
	}

	/* save sa parameters */
	if ((iph2->isa = ipsecdoi_get_ipsec(sa_ret)) == 0)
		goto end;

	/* XXX save ipsec_sa into pfkey_st */
	iph2->pst->spi_p = *(u_int32_t *)iph2->isa->spi->v;
	iph2->pst->mode_t = iph2->isa->mode_t;
	iph2->pst->cipher_t = iph2->isa->cipher_t;
	iph2->pst->hash_t = iph2->isa->hash_t;
	iph2->pst->ld_time = iph2->isa->ld_time;
	iph2->pst->ld_bytes = iph2->isa->ld_bytes;

	/* generate HASH(3) */
    {
	vchar_t *tmp = NULL;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "generate HASH(3)\n"));

	if ((tmp = vmalloc(iph2->nonce->l + iph2->nonce_p->l)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(tmp->v, iph2->nonce->v, iph2->nonce->l);
	memcpy(tmp->v + iph2->nonce->l, iph2->nonce_p->v, iph2->nonce_p->l);

	iph2->hash = isakmp_compute_hash3(iph2->ph1, &iph2->msgid, tmp);
	vfree(tmp);

	if (iph2->hash == NULL)
		goto end;
    }

	/* create buffer for isakmp payload */
	tlen = sizeof(*isakmp)
		+ sizeof(struct isakmp_gen) + iph2->hash->l;
	if ((buf = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* create isakmp header */
	memcpy(buf->v, (caddr_t)isakmp, sizeof(*isakmp));
	isakmp = (struct isakmp *)buf->v;
	isakmp->np = ISAKMP_NPTYPE_HASH;
	isakmp->len = htonl(tlen);
	memcpy((caddr_t)&isakmp->msgid, (caddr_t)&iph2->msgid,
		sizeof(isakmp->msgid));
	p = buf->v + sizeof(*isakmp);

	/* create HASH(3) payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;
	gen->len = htons(sizeof(*gen) + iph2->hash->l);
	p += sizeof(*gen);

	memcpy(p, iph2->hash->v, iph2->hash->l);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph2->ph1->local, iph2->ph1->remote, 1);
#endif

	/* encoding */
	if ((body = isakmp_do_encrypt(iph2->ph1, buf, iph2->ivm->ive, iph2->ivm->iv)) == 0)
		goto end;

	vfree(buf);

	buf = body;

	/* send HDR*;HASH(3) */
	if (isakmp_send(iph2->ph1, buf) < 0) goto end;

	/* XXX: How resend ? */

	/* compute both of KEYMATs */
	if (isakmp_compute_keymat(iph2, INITIATOR) < 0) goto end;

	/* Do UPDATE for initiator */
	if (!f_local) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "call PFKEY UPDATE\n"));
		if (pfkey_send_update_wrap(sock_pfkey, iph2) < 0) {
			plog(LOCATION, "PFKEY UPDATE failed.\n");
			goto end;
		}
	}

	/* Do ADD for responder */
	if (!f_local) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "call PFKEY ADD\n"));
		if (pfkey_send_add_wrap(sock_pfkey, iph2) < 0) {
			plog(LOCATION, "PFKEY ADD failed.\n");
			goto end;
		}
	}

	/* change status of isakmp status entry */
	iph2->status = ISAKMP_STATE_ESTABLISHED;

	plog2(from, LOCATION,
	    "get SA values for IPsec, %s.\n",
	        isakmp_pindex(&iph2->ph1->index, &iph2->msgid));

	error = 0;

end:
	if (iph2 != NULL)
		(void)isakmp_free_ph2(iph2);
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * receive SADB_GETSPI from kernel
 * and send HDR*;HASH(2);SA;Nr;[KE];[IDci,IDCr]
 */
int
isakmp_quick_r2(msg, from, iph2)
	vchar_t *msg;	/* to be zero */
	struct sockaddr *from;
	struct isakmp_ph2 *iph2;
{
	vchar_t *buf = NULL, *body = NULL;
	struct isakmp_gen *gen;
	char *p;
	int tlen;
	u_int8_t *npp;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph2->status != ISAKMP_STATE_2) {
		plog(LOCATION, "status mismatched %d.\n", iph2->status);
		goto end;
	}

	/* update SPI value to SA payload. */
	memcpy((caddr_t)(iph2->sa->v
			+ sizeof(struct ipsecdoi_sa)
			+ sizeof(struct isakmp_pl_p)),
		(caddr_t)&iph2->pst->spi, sizeof(iph2->pst->spi));

	/* generate NONCE value */
	if ((iph2->nonce = eay_set_random(isakmp_nonce_size)) == NULL)
		goto end;

	/* generate KE value if need */
	if (iph2->needpfs && iph2->isa->dhgrp) {
		plog(LOCATION, "attaching KE payload for PFS.\n");
		/* generate DH public value */
		if (isakmp_dh_generate(iph2->isa->dh,
				&iph2->dhpub, &iph2->dhpriv) < 0) {
			goto end;
		}
	}

	/* create SA;NONCE payload, and KE and ID if need */
	tlen = iph2->sa->l
		+ sizeof(*gen) + iph2->nonce->l;
	if (iph2->needpfs && iph2->isa->dhgrp)
		tlen += (sizeof(*gen) + iph2->dhpub->l);
	if (iph2->id_p != NULL)
		tlen += (sizeof(*gen) + iph2->id_p->l
			+ sizeof(*gen) + iph2->id->l);

	if ((body = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = body->v;

	/* make SA payload */ 
	memcpy(p, iph2->sa->v, iph2->sa->l);
	((struct isakmp_gen *)p)->np = ISAKMP_NPTYPE_NONCE;
	p += iph2->sa->l;

	gen = (struct isakmp_gen *)p;
	gen->np = ((iph2->needpfs && iph2->isa->dhgrp) ?
		ISAKMP_NPTYPE_KE : ISAKMP_NPTYPE_NONE);
	npp = &gen->np; /* save the pointer of next payload type */
	gen->len = htons(sizeof(struct isakmp_gen) + iph2->nonce->l);
	p += sizeof(struct isakmp_gen);
	memcpy(p, iph2->nonce->v, iph2->nonce->l);
	p += iph2->nonce->l;

	/* add KE payload if need. */
	if (iph2->needpfs && iph2->isa->dhgrp != NULL) {
		*npp = ISAKMP_NPTYPE_KE;
		gen = (struct isakmp_gen *)p;
		gen->np = ((iph2->id_p == NULL) ? ISAKMP_NPTYPE_NONE : ISAKMP_NPTYPE_ID);
		npp = &gen->np; /* save the pointer of next payload type */
		gen->len = htons(sizeof(*gen) + iph2->dhpub->l);
		p += sizeof(*gen);
		memcpy(p, iph2->dhpub->v, iph2->dhpub->l);
		p += iph2->dhpub->l;
	}

	/* add ID payloads received. */
	if (iph2->id_p != NULL) {
		/* IDci */
		*npp = ISAKMP_NPTYPE_ID;
		gen = (struct isakmp_gen *)p;
		gen->np = ISAKMP_NPTYPE_ID;
		npp = &gen->np; /* save the pointer of next payload type */
		gen->len = htons(sizeof(*gen) + iph2->id_p->l);
		p += sizeof(*gen);
		memcpy(p, iph2->id_p->v, iph2->id_p->l);
		p += iph2->id_p->l;

		/* IDcr */
		*npp = ISAKMP_NPTYPE_ID;
		gen = (struct isakmp_gen *)p;
		gen->np = ISAKMP_NPTYPE_NONE;
		npp = &gen->np; /* save the pointer of next payload type */
		gen->len = htons(sizeof(*gen) + iph2->id->l);
		p += sizeof(*gen);
		memcpy(p, iph2->id->v, iph2->id->l);
	}

	/* generate HASH(2) */
    {
	vchar_t *tmp;

	if ((tmp = vmalloc(iph2->nonce_p->l + body->l)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(tmp->v, iph2->nonce_p->v, iph2->nonce_p->l);
	memcpy(tmp->v + iph2->nonce_p->l, body->v, body->l);

	iph2->hash = isakmp_compute_hash1(iph2->ph1, &iph2->msgid, tmp);
	vfree(tmp);

	if (iph2->hash == NULL)
		goto end;
    }

	/* send isakmp payload */
	if ((buf = isakmp_quick_ir1mx(body, from, iph2)) == NULL)
		goto end;

	/* change status of isakmp status entry */
	iph2->status = ISAKMP_STATE_3;

	/* add to the schedule to resend, and seve back pointer. */
	iph2->sc = sched_add(isakmp_timer, isakmp_resend_ph2,
				isakmp_try, isakmp_timeout_ph2,
				(caddr_t)iph2, (caddr_t)buf,
				SCHED_ID_PH2_RESEND);

	/* add to the schedule to wait establish IPsec-SA */
	iph2->pst->sc = sched_add(pfkey_acquire_lifetime, 0,
				1, isakmp_pfkey_over,
				(caddr_t)iph2->pst, 0,
				SCHED_ID_PST_ACQUIRE);

	error = 0;

end:
	if (body != NULL)
		vfree(body);

	return error;
}

/*
 * receive SADB_GETSPI and send HDR*;HASH(1);SA;Ni;[KE];[IDci,IDCr]
 */
int
isakmp_quick_i2(msg, from, iph2)
	vchar_t *msg; /* must be null pointer */
	struct sockaddr *from;
	struct isakmp_ph2 *iph2;
{
	vchar_t *buf = NULL, *body = NULL;
	struct isakmp_gen *gen;
	char *p;
	int tlen;
	int error = -1;
	u_char pfsgroup;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph2->status != ISAKMP_STATE_2) {
		plog(LOCATION, "status mismatched %d.\n", iph2->status);
		goto end;
	}

	/* make my ipsec sa */
	if ((iph2->sa = ipsecdoi_make_mysa(&iph2->ph1->cfp->ph[1]->sa,
				iph2->pst->spi,
				iph2->pst->ipsec_proto,
				iph2->pst->proxy)) == NULL) {
		plog(LOCATION, "no matching proposal found.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_SA,
	    plog(LOCATION, "SA payload len=%d\n", iph2->sa->l));
	YIPSDEBUG(DEBUG_DSA, pdump(iph2->sa->v, iph2->sa->l, YDUMP_HEX));

	/* generate NONCE value */
	if ((iph2->nonce = eay_set_random(isakmp_nonce_size)) == NULL)
		goto end;

	/* generate KE value if need */
	pfsgroup = iph2->ph1->cfp->ph[1]->pfsgroup;
	if (pfsgroup) {
		/* generate DH public value */
		plog(LOCATION, "attaching KE payload for PFS.\n");
		if (isakmp_dh_generate(iph2->ph1->cfp->ph[1]->pfsdh,
				&iph2->dhpub, &iph2->dhpriv) < 0) {
			goto end;
		}
	}

	/* generate ID value */
	if (ipsecdoi_sockaddr2id(&iph2->id,
			iph2->pst->src,
			iph2->pst->prefs,
			iph2->pst->ul_proto) < 0)
		goto end;

	if (ipsecdoi_sockaddr2id(&iph2->id_p,
			iph2->pst->dst,
			iph2->pst->prefd,
			iph2->pst->ul_proto) < 0)
		goto end;

	/* create SA;NONCE payload, and KE if need, and IDii, IDir. */
	tlen = iph2->sa->l
		+ sizeof(*gen) + iph2->nonce->l
		+ sizeof(*gen) + iph2->id->l
		+ sizeof(*gen) + iph2->id_p->l;
	if (pfsgroup)
		tlen += (sizeof(*gen) + iph2->dhpub->l);

	if ((body = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = body->v;

	gen = (struct isakmp_gen *)p;
	memcpy(p, iph2->sa->v, iph2->sa->l);
	p += iph2->sa->l;

	gen->np = ISAKMP_NPTYPE_NONCE;
	gen = (struct isakmp_gen *)p;
	gen->len = htons(sizeof(*gen) + iph2->nonce->l);
	p += sizeof(*gen);
	memcpy(p, iph2->nonce->v, iph2->nonce->l);
	p += iph2->nonce->l;

	/* add KE payload if need. */
	if (pfsgroup) {
		gen->np = ISAKMP_NPTYPE_KE;
		gen = (struct isakmp_gen *)p;
		gen->len = htons(sizeof(*gen) + iph2->dhpub->l);
		p += sizeof(*gen);
		memcpy(p, iph2->dhpub->v, iph2->dhpub->l);
		p += iph2->dhpub->l;
	}

	/* IDci */
	gen->np = ISAKMP_NPTYPE_ID;
	gen = (struct isakmp_gen *)p;
	gen->len = htons(sizeof(*gen) + iph2->id->l);
	p += sizeof(*gen);
	memcpy(p, iph2->id->v, iph2->id->l);
	p += iph2->id->l;

	/* IDcr */
	gen->np = ISAKMP_NPTYPE_ID;
	gen = (struct isakmp_gen *)p;
	gen->len = htons(sizeof(*gen) + iph2->id_p->l);
	p += sizeof(*gen);
	memcpy(p, iph2->id_p->v, iph2->id_p->l);
	p += iph2->id_p->l;

	gen->np = ISAKMP_NPTYPE_NONE;

	/* generate HASH(1) */
	if ((iph2->hash = isakmp_compute_hash1(iph2->ph1, &iph2->msgid, body)) == NULL)
		goto end;

	/* send isakmp payload */
	if ((buf = isakmp_quick_ir1mx(body, from, iph2)) == NULL)
		goto end;

	/* change status of isakmp status entry */
	iph2->status = ISAKMP_STATE_3;

	/* add to the schedule to resend, and seve back pointer. */
	iph2->sc = sched_add(isakmp_timer, isakmp_resend_ph2,
				isakmp_try, isakmp_timeout_ph2,
				(caddr_t)iph2, (caddr_t)buf,
				SCHED_ID_PH2_RESEND);

	/* add to the schedule to wait establish IPsec-SA */
	iph2->pst->sc = sched_add(pfkey_acquire_lifetime, 0,
				1, isakmp_pfkey_over,
				(caddr_t)iph2->pst, 0,
				SCHED_ID_PST_ACQUIRE);

	error = 0;

end:
	if (body != NULL)
		vfree(body);

	return error;
}

/*
 * receive HDR*;HASH(1);SA;Ni;[KE];[IDci,IDCr] from initiator,
 * and call pfkey_getspi.
 */
int
isakmp_quick_r1(msg0, from, iph2)
	vchar_t *msg0;
	struct sockaddr *from;
	struct isakmp_ph2 *iph2;
{
	vchar_t *msg = NULL;
	vchar_t *buf = NULL, *body = NULL;
	struct isakmp *isakmp = (struct isakmp *)msg0->v;
	struct isakmp_pl_hash *hash = NULL;
	struct ipsecdoi_sa *sa_tak = NULL; /* SA payloads to parse. */
	char *p;
	int tlen;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph2->status != ISAKMP_STATE_1) {
		plog(LOCATION, "status mismatched %d.\n", iph2->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		plog2(from, LOCATION, "Packet wasn't encrypted.\n");
		goto end;
	}
	/* decrypt packet */
	if ((msg = isakmp_do_decrypt(iph2->ph1, msg0, iph2->ivm->iv, iph2->ivm->ive)) == NULL)
		goto end;

	/* create buffer for using to validate HASH(1) */
	/*
	 * ISAKMP_ETYPE_QUICK, INITIATOR
	 * ISAKMP_NPTYPE_HASH, ISAKMP_NPTYPE_SA
	 * ISAKMP_NPTYPE_NONCE,
	 * (ISAKMP_NPTYPE_KE), (ISAKMP_NPTYPE_ID, ISAKMP_NPTYPE_ID)
	 * (ISAKMP_NPTYPE_N)
	 *
	 * ordering rule:
	 *	1. the first one must be HASH
	 *	2. the second one must be SA (added in isakmp-oakley-05!)
	 *	3. two IDs must be considered as IDci, then IDcr
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;
	int f_id_order;	/* for ID payload detection */

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* HASH paylad is fixed postion */
	PH2_CHECK_ORDER(pa, ISAKMP_NPTYPE_HASH, LOCATION);
	hash = (struct isakmp_pl_hash *)pa->ptr;
	pa++;

#if 0
	/*
	 * this restriction was introduced in isakmp-oakley-05.
	 * we do not check this for backward compatibility.
	 * TODO: command line/config file option to enable/disable this code
	 */
	/* HASH paylad is fixed postion */
	PH2_CHECK_ORDER(pa, ISAKMP_NPTYPE_SA, LOCATION);
#endif

	/* allocate buffer for computing HASH(1) */
	tlen = ntohl(isakmp->len) - sizeof(*isakmp);
	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		vfree(pbuf);
		goto end;
	}
	p = buf->v;

	/*
	 * parse the payloads.
	 * copy non-HASH payloads into buf, so that we can validate HASH.
	 */
	sa_tak = NULL;	/* don't support multi SAs. */
	iph2->id_p = NULL;
	tlen = 0;	/* count payload length except of HASH payload. */

	/*
	 * IDi2 MUST be immediatelly followed by IDr2.  We allowed the
	 * illegal case, but logged.  First ID payload is to be IDi2.
	 * And next ID payload is to be IDr2.
	 */
	f_id_order = 0;

	for (; pa->type; pa++) {

		/* copy to buffer for HASH */
		/* Don't modify the payload */
		memcpy(p, pa->ptr, pa->len);

		if (pa->type != ISAKMP_NPTYPE_ID)
			f_id_order = 0;

		switch (pa->type) {
		case ISAKMP_NPTYPE_SA:
			if (sa_tak != NULL) {
				plog(LOCATION,
					"Multi SAs isn't supported.\n");
				vfree(pbuf);
				goto end;
			}
			sa_tak = (struct ipsecdoi_sa *)pa->ptr;
			break;

		case ISAKMP_NPTYPE_NONCE:
			if ((iph2->nonce_p = vmalloc(pa->len - sizeof(struct isakmp_gen))) == NULL) {
				plog(LOCATION,
					"vmalloc (%s)\n",
					strerror(errno));
				vfree(pbuf);
				goto end;
			}
			memcpy(iph2->nonce_p->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen),
				iph2->nonce_p->l);
			break;

		case ISAKMP_NPTYPE_KE:
			if ((iph2->dhpub_p = vmalloc(pa->len - sizeof(struct isakmp_gen))) == NULL) {
				plog(LOCATION,
					"vmalloc (%s)\n", strerror(errno));
				vfree(pbuf);
				goto end;
			}
			memcpy(iph2->dhpub_p->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen),
				iph2->dhpub_p->l);
			iph2->needpfs = 1;
			break;

		case ISAKMP_NPTYPE_ID:
			if (iph2->id_p == NULL) {
				/* for IDci */
				f_id_order++;

				if ((iph2->id_p = vmalloc(pa->len - sizeof(struct isakmp_gen))) == NULL) {
					plog(LOCATION,
						"vmalloc (%s)\n",
						strerror(errno));
					vfree(pbuf);
					goto end;
				}
				memcpy(iph2->id_p->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen),
					iph2->id_p->l);
				YIPSDEBUG(DEBUG_KEY,
					plog(LOCATION, "received IDci\n");
					pvdump(iph2->id_p));

			} else if (iph2->id == NULL) {
				/* for IDcr */
				if (f_id_order == 0) {
					plog(LOCATION,
						"IDr2 payload is not "
						"immediatelly followed by IDi2.\n");
					/* XXX we allowed in this case. */
				}

				if ((iph2->id = vmalloc(pa->len - sizeof(struct isakmp_gen))) == NULL) {
					plog(LOCATION,
						"vmalloc (%s)\n",
						strerror(errno));
					vfree(pbuf);
					goto end;
				}
				memcpy(iph2->id->v, (caddr_t)pa->ptr + sizeof(struct isakmp_gen),
					iph2->id->l);
				YIPSDEBUG(DEBUG_KEY,
					plog(LOCATION, "received IDci\n");
					pvdump(iph2->id));
			} else {
				YIPSDEBUG(DEBUG_KEY,
					plog(LOCATION, "received too many ID payloads.\n");
					pvdump(iph2->id));
					vfree(pbuf);
					goto end;
			}
			break;

		case ISAKMP_NPTYPE_N:
			plog2(from, LOCATION,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph2->ph1, from);
			break;

		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}

		p += pa->len;

		/* compute true length of payload. */
		tlen += pa->len;
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (hash == NULL || sa_tak == NULL || iph2->nonce_p == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* adjust buffer length for HASH */
	buf->l = tlen;

	/* validate HASH(1) */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH(1)\n"));

	r_hash = (caddr_t)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	my_hash = isakmp_compute_hash1(iph2->ph1, &iph2->msgid, buf);
	vfree(buf);
	buf = NULL;
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
#if 0	/* XXX can't get SA's values because before checking SA */
		isakmp_info_send_n2(iph2, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL, iph2->ph1->flags);
#endif
		plog2(from, LOCATION, "HASH(1) mismatch.\n");
		goto end;
	}
    }

	/* check SA payload and get new one for use */
	if ((iph2->sa = ipsecdoi_get_proposal(sa_tak, OAKLEY_QUICK_MODE)) == NULL) {
		/* XXX ??? send information ? */
		goto end;
	}

	/* save sa parameters */
	if ((iph2->isa = ipsecdoi_get_ipsec(iph2->sa)) == NULL)
		goto end;

	/* check the existence of ID payload */
	if ((iph2->id_p != NULL && iph2->id == NULL)
	 || (iph2->id_p == NULL && iph2->id != NULL)) {
		/* XXX send information */
		plog(LOCATION, "Both ID wasn't found in payload.\n");
		goto end;
	}

	/* create the entry for IPsec SA management */
    {
	struct sockaddr *ipsec_src = NULL, *ipsec_dst = NULL, *proxy;
	u_int prefs, prefd, ul_proto;

	/* make both src and dst address */
	if (iph2->id_p != NULL && iph2->id != NULL) {
		/* from ID payload */
		/* source address for use */
		if (ipsecdoi_id2sockaddr(iph2->id,
					&ipsec_src, &prefs, &ul_proto))
			goto end;
		/* destination address for use */
		if (ipsecdoi_id2sockaddr(iph2->id_p,
					&ipsec_dst, &prefd, &ul_proto))
			goto end;
	} else {
		/*
		 * from Phase 1's identity and mask these port number,
		 * if there are no ID payload
		 */
		/* source address for use */
		GET_NEWBUF(ipsec_src, struct sockaddr *,
			iph2->ph1->local, iph2->ph1->local->sa_len);
		if (ipsec_src == NULL)
			goto end;
		_INPORTBYSA(ipsec_src) = 0;
		prefs = (_INALENBYAF(iph2->ph1->local->sa_family) << 3);

		/* destination address for use */
		GET_NEWBUF(ipsec_dst, struct sockaddr *,
			iph2->ph1->remote, iph2->ph1->remote->sa_len);
		if (ipsec_dst == NULL)
			goto end;
		_INPORTBYSA(ipsec_dst) = 0;
		prefd = (_INALENBYAF(iph2->ph1->remote->sa_family) << 3);

		ul_proto = 0;
	}

	/* if mode_t == IPSECDOI_ATTR_ENC_MODE_TUNNEL */
	if (iph2->isa->mode_t == IPSECDOI_ATTR_ENC_MODE_TUNNEL)
		proxy = iph2->ph1->remote;
	else
		proxy = NULL;

	/* allocate buffer for status management of pfkey message */
	if ((iph2->pst = pfkey_new_pst(
			iph2->isa->proto_id,
			ipsec_src, prefs,
			ipsec_dst, prefd,
			ul_proto,
			proxy,
			0)) == NULL)
		return NULL;

	if (ipsec_src != NULL)
		free(ipsec_src);
	if (ipsec_dst != NULL)
		free(ipsec_dst);
    }

	/* XXX save ipsec_sa into pfkey_st */
	iph2->pst->dir = iph2->dir;
	iph2->pst->spi_p = *(u_int32_t *)iph2->isa->spi->v;
	iph2->pst->mode_t = iph2->isa->mode_t;
	iph2->pst->cipher_t = iph2->isa->cipher_t;
	iph2->pst->hash_t = iph2->isa->hash_t;
	iph2->pst->ld_time = iph2->isa->ld_time;
	iph2->pst->ld_bytes = iph2->isa->ld_bytes;

	/* save phase 2 pointer */
	iph2->pst->ph2 = iph2;

	/* Do GETSPI */
	/*
	 * It called as the source address is remote IKE address,
	 * the destination address is local IKE address,
	 * because SPI is decided by responder.
	 */
	YIPSDEBUG(DEBUG_STAMP,
		plog(LOCATION, "call PFKEY GETSPI.\n"));
	if (pfkey_send_getspi_wrap(sock_pfkey, iph2) < 0) {
		plog(LOCATION, "PFKEY GETSPI failed.\n");
		goto end;
	}

	/* change status of isakmp status entry */
	iph2->status = ISAKMP_STATE_2;

#ifdef PFKEY_RESEND
	/* add to the schedule to resend, and seve back pointer. */
	iph2->sc = sched_add(pfkey_send_timer, pfkey_resend_getspi,
				pfkey_send_try, isakmp_timeout_getspi,
				(caddr_t)sock_pfkey, (caddr_t)iph2,
				SCHED_ID_PH2_RESEND);
#endif

	/* add to the schedule to wait establish IPsec-SA */
	iph2->pst->sc = sched_add(pfkey_acquire_lifetime, 0,
				1, isakmp_pfkey_over,
				(caddr_t)iph2->pst, 0,
				SCHED_ID_PST_ACQUIRE);

	error = 0;

end:
	if (body != NULL)
		vfree(body);
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * begin Quick Mode as initiator , and send HDR*;HASH(1);SA;Ni;[KE];[IDci,IDCr]
 */
int
isakmp_quick_i1(msg, from, iph2)
	vchar_t *msg; /* must be null pointer */
	struct sockaddr *from; /* XXX NULL */
	struct isakmp_ph2 *iph2;
{
	vchar_t *body = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph2->status != ISAKMP_STATE_1) {
		plog(LOCATION, "status mismatched %d.\n", iph2->status);
		goto end;
	}

	/* allocate buffer to save SPI */
	if ((iph2->isa =
	        CALLOC(sizeof(struct ipsec_sa), struct ipsec_sa *)) == 0) {
		plog(LOCATION, "calloc (%s)\n", strerror(errno)); 
		goto end;
	}
	iph2->isa->proto_id = iph2->pst->ipsec_proto;

	/* Do GETSPI */
	/*
	 * It called as the source address is remote IKE address,
	 * the destination address is local IKE address,
	 * because SPI is decided by responder.
	 */
	if (!f_local) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "call PFKEY GETSPI.\n"));
		if (pfkey_send_getspi_wrap(sock_pfkey, iph2) < 0) {
			plog(LOCATION, "PFKEY GETSPI failed.\n");
			goto end;
		}
	}

	/* change status of isakmp status entry */
	iph2->status = ISAKMP_STATE_2;

#ifdef PFKEY_RESEND
	/* add to the schedule to resend, and seve back pointer. */
	iph2->sc = sched_add(pfkey_send_timer, pfkey_resend_getspi,
				pfkey_send_try, isakmp_timeout_getspi,
				(caddr_t)sock_pfkey, (caddr_t)iph2,
				SCHED_ID_PH2_RESEND);
#endif

	/* add to the schedule to wait establish IPsec-SA */
	iph2->pst->sc = sched_add(pfkey_acquire_lifetime, 0,
				1, isakmp_pfkey_over,
				(caddr_t)iph2->pst, 0,
				SCHED_ID_PST_ACQUIRE);

	error = 0;

end:
	if (body != NULL)
		vfree(body);

	return error;
}

/*
 * create HASH, body (SA, NONCE) payload with isakmp header.
 */
static vchar_t *
isakmp_quick_ir1mx(body, from, iph2)
	vchar_t *body;
	struct sockaddr *from;
	struct isakmp_ph2 *iph2;
{
	struct isakmp *isakmp;
	vchar_t *buf = NULL, *new = NULL;
	char *p;
	int tlen;
	struct isakmp_gen *gen;
	int error = -1;

	/* create buffer for isakmp payload */
	tlen = sizeof(*isakmp) + sizeof(*gen) + iph2->hash->l + body->l;
	if ((buf = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	/* re-set encryption flag, for serurity. */
	iph2->ph1->flags |= ISAKMP_FLAG_E;

	/* set isakmp header */
	if (set_isakmp_header2(buf, iph2, ISAKMP_NPTYPE_HASH) < 0)
		goto end;
	p += sizeof(*isakmp);

	/* create HASH payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_SA;
	gen->len = htons(sizeof(*gen) + iph2->hash->l);
	p += sizeof(*gen);

	memcpy(p, iph2->hash->v, iph2->hash->l);
	p += iph2->hash->l;

	/* create SA;NONCE payload */
	memcpy(p, body->v, body->l);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph2->ph1->local, iph2->ph1->remote, 1);
#endif

	/* encoding */
	if ((new = isakmp_do_encrypt(iph2->ph1, buf, iph2->ivm->ive, iph2->ivm->iv)) == NULL)
		goto end;

	vfree(buf);

	buf = new;

	/* send HDR*;HASH(1);SA;Nr to responder */
	if (isakmp_send(iph2->ph1, buf) < 0) goto end;

#if 0 /* emulation traffic congestion */
	if (isakmp_send(iph2->ph1, buf) < 0) goto end;
#endif

	/* XXX: synchronization IV */
	memcpy(iph2->ivm->ivd->v, iph2->ivm->iv->v, iph2->ivm->iv->l);

	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}

	return buf;
}

/*
 * compute KEYMAT
 *   see seciton 5.5 Phase 2 - Quick Mode in isakmp-oakley-05.
 */
static int
isakmp_compute_keymat(iph2, dir)
	struct isakmp_ph2 *iph2;
	int dir;
{
	int error = -1;

	/* compute sharing secret of DH when PFS */
	if (iph2->isa->dhgrp && iph2->dhpub_p) {
		if (isakmp_dh_compute(iph2->isa->dh, iph2->dhpub,
				iph2->dhpriv, iph2->dhpub_p, &iph2->dhgxy) < 0)
			goto end;
	}

	/* compute keymat */
	iph2->pst->keymat = isakmp_compute_keymat_x(iph2, dir, IPSEC_INBOUND);
	iph2->pst->keymat_p = isakmp_compute_keymat_x(iph2, dir, IPSEC_OUTBOUND);
	if (iph2->pst->keymat == NULL || iph2->pst->keymat_p == NULL)
		goto end;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute KEYMAT.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(iph2->pst->keymat));
	YIPSDEBUG(DEBUG_DKEY, pvdump(iph2->pst->keymat_p));

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
static vchar_t *
isakmp_compute_keymat_x(iph2, dir, sa_dir)
	struct isakmp_ph2 *iph2;
	int dir;
	int sa_dir;
{
	vchar_t *buf = NULL, *res = NULL, *bp;
	char *p;
	int len;
	int error = -1;
	int pfs = 0;
	int dupkeymat = 3;	/* generate K[1-dupkeymat] */

	pfs = ((iph2->isa->dhgrp && iph2->dhgxy) ? 1 : 0);
	
	len = pfs ? iph2->dhgxy->l : 0;
	len += (1
		+ sizeof(iph2->pst->spi)
		+ iph2->nonce->l
		+ iph2->nonce_p->l);
	if ((buf = vmalloc(len)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	/* if PFS */
	if (pfs) {
		memcpy(p, iph2->dhgxy->v, iph2->dhgxy->l);
		p += iph2->dhgxy->l;
	}

	p[0] = iph2->pst->ipsec_proto;
	p += 1;

	memcpy(p,
		(sa_dir == IPSEC_INBOUND ? &iph2->pst->spi : &iph2->pst->spi_p),
		sizeof(iph2->pst->spi));
	p += sizeof(iph2->pst->spi);

	bp = (dir == INITIATOR ? iph2->nonce : iph2->nonce_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (dir == INITIATOR ? iph2->nonce_p : iph2->nonce);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	/* compute IV */
	YIPSDEBUG(DEBUG_DKEY,
	    plog(LOCATION, "body for computing KEYMAT.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(buf));

	/* res = K1 */
	if ((res = isakmp_prf(iph2->ph1->skeyid_d, buf, iph2->ph1)) == NULL)
		goto end;

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
		    plog(LOCATION,
			    "generating K1...K%d for KEYMAT.\n",
			    dupkeymat + 1));

		if (!(seed = vmalloc(prev->l + buf->l))) {
			plog(LOCATION,
				"vmalloc (%s)\n", strerror(errno));
			goto end;
		}

		while (dupkeymat--) {
			memcpy(seed->v, prev->v, prev->l);
			memcpy(seed->v + prev->l, buf->v, buf->l);
			this = isakmp_prf(iph2->ph1->skeyid_d, seed, iph2->ph1);
			if (!this) {
				plog(LOCATION,
					"isakmp_prf memory overflow\n");
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

	error = 0;

end:
	if (error) {
		vfree(res);
	}

	if (buf != NULL)
		vfree(buf);

	return res;
}

#if notyet
/*
 * NOTE: Must terminate by NULL.
 */
vchar_t *
isakmp_compute_hashx(struct isakmp_ph1 *iph1, ...)
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

	if ((buf = vmalloc(len)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
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

	YIPSDEBUG(DEBUG_DKEY,
		plog(LOCATION, "compute HASH with:\n");
		pvdump(buf));

	/* compute HASH */
	res = isakmp_prf(iph1->skeyid_a, buf, iph1);
	vfree(buf);
	if (res == NULL)
		return NULL;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "compute HASH.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(res));

	return res;
}
#endif

/*
 * compute HASH(3) prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
 *   see seciton 5.5 Phase 2 - Quick Mode in isakmp-oakley-05.
 */
vchar_t *
isakmp_compute_hash3(iph1, msgid, body)
	struct isakmp_ph1 *iph1;
	msgid_t *msgid;
	vchar_t *body;
{
	vchar_t *buf = 0, *res = 0;
	int len;
	int error = -1;

	/* create buffer */
	len = 1 + sizeof(msgid_t) + body->l;
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	buf->v[0] = 0;

	memcpy(buf->v + 1, msgid, sizeof(msgid_t));

	memcpy(buf->v + 1 + sizeof(msgid_t), body->v, body->l);

	YIPSDEBUG(DEBUG_DKEY,
		plog(LOCATION, "compute HASH with:\n");
		pvdump(buf));

	/* compute HASH */
	if ((res = isakmp_prf(iph1->skeyid_a, buf, iph1)) == 0) goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "compute HASH.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(res));

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
isakmp_compute_hash1(iph1, msgid, body)
	struct isakmp_ph1 *iph1;
	msgid_t *msgid;
	vchar_t *body;
{
	vchar_t *buf = NULL, *res = NULL;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = sizeof(msgid_t) + body->l;
	if ((buf = vmalloc(len)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	memcpy(buf->v, msgid, sizeof(msgid_t));
	p += sizeof(msgid_t);

	memcpy(p, body->v, body->l);

	YIPSDEBUG(DEBUG_DKEY,
		plog(LOCATION, "compute HASH with:\n");
		pvdump(buf));

	/* compute HASH */
	if ((res = isakmp_prf(iph1->skeyid_a, buf, iph1)) == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "compute HASH.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

u_int32_t
isakmp_get_msgid2(iph1)
	struct isakmp_ph1 *iph1;
{
	u_int32_t msgid2;

	do {
		msgid2 = random();
	} while (isakmp_ph2bymsgid(iph1, (msgid_t *)&msgid2));

	return msgid2;
}

/*
 * set isakmp header for phase 2
 */
int
set_isakmp_header2(buf, iph2, nptype)
	vchar_t *buf;
	struct isakmp_ph2 *iph2;
	int nptype;
{
	struct isakmp *isakmp;

	if (buf->l < sizeof(*isakmp))
		return -1;

	isakmp = (struct isakmp *)buf->v;
	memcpy(&isakmp->i_ck, &iph2->ph1->index.i_ck, sizeof(cookie_t));
	memcpy(&isakmp->r_ck, &iph2->ph1->index.r_ck, sizeof(cookie_t));
	isakmp->np      = nptype;
	isakmp->v_number = ISAKMP_VERSION_NUMBER;
	isakmp->etype   = ISAKMP_ETYPE_QUICK;
	isakmp->flags   = iph2->ph1->flags;
	memcpy(&isakmp->msgid, &iph2->msgid, sizeof(isakmp->msgid));
	isakmp->len = htonl(buf->l);

	return 0;
}

/*
 * set isakmp header for phase 1
 */
int
set_isakmp_header(buf, iph1, nptype)
	vchar_t *buf;
	struct isakmp_ph1 *iph1;
	int nptype;
{
	struct isakmp *isakmp;

	if (buf->l < sizeof(*isakmp))
		return -1;

	isakmp = (struct isakmp *)buf->v;
	memcpy(&isakmp->i_ck, &iph1->index.i_ck, sizeof(cookie_t));
	memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(cookie_t));
	isakmp->np      = nptype;
	isakmp->v_number = ISAKMP_VERSION_NUMBER;
	isakmp->etype   = iph1->etype;
	isakmp->flags   = iph1->flags;
	memcpy(&isakmp->msgid, iph1->msgid, sizeof(isakmp->msgid));
	isakmp->len = htonl(buf->l);

	return 0;
}

/* %%%
 * Identity Protecion Exchange (Main Mode)
 */
/*
 * receive HDR*;ID;HASH from responder, and do QUICK mode.
 */
static int
isakmp_ident_i4(msg0, from, iph1)
	vchar_t *msg0;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *msg = NULL;
	struct isakmp_pl_id *id = NULL;
	struct isakmp_pl_hash *hash = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_4) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		error = 0;
		plog2(from, LOCATION,
			"ignore the packet, "
			"expecting the packet encrypted.\n");
		goto end;
	}
	if ((msg = isakmp_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive)) == NULL)
		goto end;

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, INITIATOR
	 * ISAKMP_NPTYPE_ID, ISAKMP_NPTYPE_HASH, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID), (ISAKMP_NPTYPE_N)
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_ID:
			id = (struct isakmp_pl_id *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_HASH:
			hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		case ISAKMP_NPTYPE_N:
			plog2(from, LOCATION,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (id == NULL || hash == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* save responder's id */
	if (isakmp_id2isa(iph1, id) < 0) goto end;

	/* validate HASH */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH\n"));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	my_hash = isakmp_compute_hash(iph1, VALIDATE);
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog(LOCATION, "HASH mismatch.\n");
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL);
		goto end;
	}
    }

	/* XXX: compare address in stauts structure and address in ID payload */

	YIPSDEBUG(DEBUG_MISC,
		GETNAMEINFO(iph1->remote, _addr1_, _addr2_);
		plog(LOCATION, "remote addr=%s.\n", _addr1_);
		plog(LOCATION, "ID ");
		pdump(((caddr_t)id + sizeof(*id)),
			ntohs(id->h.len) - sizeof(*id), YDUMP_HEX));

	/* XXX: synchronization IV */
	memcpy(iph1->ivm->ivd->v, iph1->ivm->ive->v, iph1->ivm->iv->l);
	memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->iv->l);

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_ESTABLISHED;

	/* save created date. */
	iph1->created = time(NULL);

	/* add to the schedule to expire, and seve back pointer. */
	iph1->sc = sched_add(iph1->isa->ld_time, 0,
				1, isakmp_expire,
				(caddr_t)iph1, (caddr_t)0,
				SCHED_ID_PH1_LIFETIME);

	plog2(from, LOCATION,
	    "established ISAKMP-SA, %s.\n", isakmp_pindex(&iph1->index, 0));

	/* XXX: do post-command */
	if (iph1->cfp->exec_command != NULL)
		post_command(iph1);

	error = 0;

end:
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * receive HDR*;ID;HASH from initiator, and retrun HDR*;ID;HASH
 */
static int
isakmp_ident_r3(msg0, from, iph1)
	vchar_t *msg0;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *msg = NULL;
	struct isakmp_pl_id *id = NULL;
	struct isakmp_pl_hash *hash = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_3) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting */
	if (!ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		error = 0;
		plog2(from, LOCATION,
			"ignore the packet, "
			"expecting the packet encrypted.\n");
		goto end;
	}
	if ((msg = isakmp_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive)) == NULL)
		goto end;

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, RESPONDER
	 * ISAKMP_NPTYPE_ID, ISAKMP_NPTYPE_HASH, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID), (ISAKMP_NPTYPE_N)
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_ID:
			id = (struct isakmp_pl_id *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_HASH:
			hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		case ISAKMP_NPTYPE_N:
			plog2(from, LOCATION,
				"peer transmitted Notify Message.\n");
			isakmp_check_notify(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (id == NULL || hash == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* save initiator's id */
	if (isakmp_id2isa(iph1, id) < 0) goto end;

	/* validate HASH */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH\n"));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	my_hash = isakmp_compute_hash(iph1, VALIDATE);
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog2(from, LOCATION, "HASH mismatch.\n");
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL);
		goto end;
	}
    }

	/* XXX: compare address in stauts structure and address in ID payload */
	YIPSDEBUG(DEBUG_MISC,
		GETNAMEINFO(iph1->remote, _addr1_, _addr2_);
		plog(LOCATION, "remote addr=%s.\n", _addr1_);
		plog(LOCATION, "ID ");
		pdump(((caddr_t)id + sizeof(*id)),
			ntohs(id->h.len) - sizeof(*id), YDUMP_HEX));

	/* generate HASH to send */
	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "generate HASH_I\n"));
	if ((iph1->hash = isakmp_compute_hash(iph1, GENERATE)) == NULL)
		goto end;

	/* re-set encryption flag, for serurity. */
	iph1->flags |= ISAKMP_FLAG_E;

	/* create HDR;ID;HASH payload */
    {
	vchar_t *ret;

	if ((ret = isakmp_ident_ir3mx(from, iph1)) == 0) goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_ESTABLISHED;

	/* save created date. */
	iph1->created = time(NULL);

#if 0 /* XXX: How resend ? */
	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)ret,
				SCHED_ID_PH1_RESEND);
#else
	/* add to the schedule to expire, and seve back pointer. */
	iph1->sc = sched_add(iph1->isa->ld_time, 0,
				1, isakmp_expire,
				(caddr_t)iph1, (caddr_t)0,
				SCHED_ID_PH1_LIFETIME);

	plog2(from, LOCATION,
	    "established ISAKMP-SA, %s.\n", isakmp_pindex(&iph1->index, 0));

#endif
    }

	/* XXX: do post-command */
	if (iph1->cfp->exec_command != NULL)
		post_command(iph1);

	error = 0;

end:
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * receive HDR;KE;NONCE from responder, and retrun HDR*;ID;HASH
 */
static int
isakmp_ident_i3(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = 0;
	struct isakmp_pl_ke *ke = NULL;
	struct isakmp_pl_nonce *nonce = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_3) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, INITIATOR
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID)
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			ke = (struct isakmp_pl_ke *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_NONCE:
			nonce = (struct isakmp_pl_nonce *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (ke == NULL || nonce == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* commit responder's ke, nonce for use */
	if (isakmp_kn2isa(iph1, ke, nonce) < 0) goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (isakmp_compute_skeyids(iph1) < 0) goto end;
	if (isakmp_compute_enckey(iph1) < 0) goto end;
	if ((iph1->ivm = isakmp_new_iv(iph1)) == NULL)
		goto end;

	/* generate HASH to send */
	if ((iph1->hash = isakmp_compute_hash(iph1, GENERATE)) == NULL)
		goto end;

	/* set encryption flag */
	iph1->flags |= ISAKMP_FLAG_E;

	/* create HDR;ID;HASH payload */
	if ((buf = isakmp_ident_ir3mx(from, iph1)) == NULL)
		goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_4;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)buf,
				SCHED_ID_PH1_RESEND);

	error = 0;

end:
	return error;
}

/*
 * receive HDR;KE;NONCE from initiator, and retrun HDR;KE;NONCE.
 */
static int
isakmp_ident_r2(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = 0;
	struct isakmp_pl_ke *ke = NULL;
	struct isakmp_pl_nonce *nonce = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_2) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, RESPONDER
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_NONE
	 * (ISAKMP_NPTYPE_VID)
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			ke = (struct isakmp_pl_ke *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_NONCE:
			nonce = (struct isakmp_pl_nonce *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (ke == NULL || nonce == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* commit initiator's ke, nonce for use */
	if (isakmp_kn2isa(iph1, ke, nonce) < 0)
		goto end;

	/* generate DH public value */
	if (isakmp_dh_generate(iph1->isa->dh, &iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	if ((iph1->nonce = eay_set_random(isakmp_nonce_size)) == NULL)
		goto end;

	/* create HDR;KE;NONCE payload */
	if ((buf = isakmp_ident_ir2mx(from, iph1)) == NULL)
		goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (isakmp_compute_skeyids(iph1) < 0) goto end;
	if (isakmp_compute_enckey(iph1) < 0) goto end;
	if ((iph1->ivm = isakmp_new_iv(iph1)) == NULL)
		goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_3;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)buf,
				SCHED_ID_PH1_RESEND);

	error = 0;

end:
	return error;
}

/*
 * receive HDR;SA from responder, and retrun HDR;KE;NONCE.
 */
static int
isakmp_ident_i2(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	struct isakmp_pl_sa *sa_tmp = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_2) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
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
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* SA paylad is fixed postion */
	PH1_CHECK_ORDER(pa, ISAKMP_NPTYPE_SA, LOCATION);
	sa_tmp = (struct isakmp_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* XXX check SA returned. */

	/* check SA payload and get new one for use */
    {
	vchar_t *sa_ret;

	if ((sa_ret = ipsecdoi_get_proposal((struct ipsecdoi_sa *)sa_tmp,
					OAKLEY_MAIN_MODE)) == 0) {
		/* XXX send information */
		goto end;
	}

	/* save sa parameters */
	iph1->isa = ipsecdoi_get_oakley(sa_ret);
	vfree(sa_ret);
	if (iph1->isa == NULL)
		goto end;
    }

	/* iph1->sa (SAi_b) is recorded in isamp_ident_i1 */

	/* modify index of the isakmp status record */
	memcpy(&iph1->index.r_ck, &((struct isakmp *)msg->v)->r_ck,
		sizeof(cookie_t));

	/* generate DH public value */
	if (isakmp_dh_generate(iph1->isa->dh, &iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	/* XXX: configurable */
	if ((iph1->nonce = eay_set_random(isakmp_nonce_size)) == NULL)
		goto end;

	/* create buffer to send isakmp payload */
    {
	vchar_t *buf;

	if ((buf = isakmp_ident_ir2mx(from, iph1)) == NULL)
		goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_3;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)buf,
				SCHED_ID_PH1_RESEND);
    }

	error = 0;

end:
	return error;
}

/*
 * receive HDR;SA from initiator, and retrun appropreate HDR;SA.
 */
static int
isakmp_ident_r1(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = 0;
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct isakmp_pl_sa *sa_tmp = NULL;
	vchar_t *sa_ret;
	int error = -1;
	vchar_t *vidhash = NULL;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_1) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_IDENT, RESPONDER, ISAKMP_STATE_ESTABLISHED
	 * ISAKMP_NPTYPE_SA, (ISAKMP_NPTYPE_VID,) ISAKMP_NPTYPE_NONE
	 *
	 * NOTE: even if multiple VID, we'll silently ignore those.
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* SA paylad is fixed postion */
	PH1_CHECK_ORDER(pa, ISAKMP_NPTYPE_SA, LOCATION);
	sa_tmp = (struct isakmp_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/*
			 * We don't send information to the peer even
			 * if we received mulformed packet.  Because we
			 * can't distinguish the mulformed pakcet and
			 * the re-sent packet.  And we do same behavior
			 * when we expect encrypted packet.
			 */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* check SA payload and get new one for use */
	if ((sa_ret = ipsecdoi_get_proposal((struct ipsecdoi_sa *)sa_tmp,
					OAKLEY_MAIN_MODE)) == NULL) {
		/* XXX send information */
		goto end;
	}

	/* save sa parameters */
	if ((iph1->isa = ipsecdoi_get_oakley(sa_ret)) == NULL)
		goto end;

	/* re-arrange and save SA payload minus general header. */
	iph1->sa = vmalloc(ntohs(sa_tmp->h.len) - sizeof(struct isakmp_gen));
	if (!iph1->sa) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		/* XXX send information */
		goto end;
	}
	memmove(iph1->sa->v, &sa_tmp->h + 1,
		ntohs(sa_tmp->h.len) - sizeof(struct isakmp_gen));

	/* set remote address */
	if ((iph1->remote =
	        (struct sockaddr *)malloc(from->sa_len)) == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy((caddr_t)iph1->remote, (caddr_t)from, from->sa_len);

	/* save values into isakmp status */
	iph1->etype = isakmp->etype;

	/* make ID payload into isakmp status */
	if ((iph1->id = ipsecdoi_get_id1(iph1)) == NULL)
		goto end;

	/* create buffer to send isakmp payload */
    {
	struct isakmp_gen *gen = NULL;
	char *p;
	int tlen;

	tlen = sizeof(struct isakmp)
		+ sa_ret->l;
	if (iph1->cfp->vendorid) {
		/* XXX should this be configurable? */
		vidhash = eay_md5_one(iph1->cfp->vendorid);
		tlen += sizeof(*gen) + vidhash->l;
	}
	if ((buf = vmalloc(tlen)) == 0) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* create isakmp header */
	memcpy(buf->v, (caddr_t)isakmp, sizeof(*isakmp));

	/* set responder's cookie */
	isakmp = (struct isakmp *)buf->v;
	isakmp_set_cookie((char *)&isakmp->r_ck, from);

	/* modify index of the isakmp status record */
	memcpy((caddr_t)&iph1->index.r_ck, (caddr_t)&isakmp->r_ck,
		sizeof(cookie_t));

	isakmp->len = htonl(tlen);
	p = buf->v + sizeof(struct isakmp);

	/* create ISAKMP-SA payload to reply */
	gen = (struct isakmp_gen *)p;
	memcpy(p, sa_ret->v, sa_ret->l);
	gen->reserved = 0;
	gen->len = htons(sa_ret->l);
	p += sa_ret->l;

	/* append vendor id, if needed */
	if (vidhash) {
		gen->np = ISAKMP_NPTYPE_VID;
		gen = (struct isakmp_gen *)p;
		gen->len = ntohs(sizeof(*gen) + vidhash->l);
		p += sizeof(*gen);
		memcpy(p, vidhash->v, vidhash->l);
		p += vidhash->l;
	}

	gen->np = ISAKMP_NPTYPE_NONE;
    }

	vfree(sa_ret);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 0);
#endif

	/* send HDR;SA to responder */
	if (isakmp_send(iph1, buf) < 0) goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_2;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)buf,
				SCHED_ID_PH1_RESEND);

	error = 0;

end:
	if (error) {
		if (buf != NULL)
			vfree(buf);
	}
	if (vidhash != NULL)
		vfree(vidhash);
	return error;
}

/*
 * begin Identity Protection Mode as initiator, and send HDR;SA to responder.
 */
static int
isakmp_ident_i1(msg, to, iph1)
	vchar_t *msg; /* must be null */
	struct sockaddr *to;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = NULL;
	vchar_t *mysa = NULL;
	int error = -1;
	vchar_t *vidhash = NULL;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_1) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* set isakmp header value */
	iph1->dir = INITIATOR;
	iph1->version = ISAKMP_VERSION_NUMBER;
	iph1->etype = iph1->cfp->ph[0]->etype;
	iph1->flags = 0;
	memcpy(&iph1->msgid, msgid0, sizeof(iph1->msgid));

	/* make ID payload into isakmp status */
	if ((iph1->id = ipsecdoi_get_id1(iph1)) == NULL)
		goto end;

	/* create SA payload */
	if ((mysa = ipsecdoi_make_mysa(&iph1->cfp->ph[0]->sa, 0, 0, NULL)) == NULL)
		goto end;

	/* create buffer to send isakmp payload */
    {
	struct isakmp_gen *gen;
	char *p;
	int tlen;

	tlen = sizeof(struct isakmp)
		+ mysa->l;
	if (iph1->cfp->vendorid) {
		/* XXX should it be configurable? */
		vidhash = eay_md5_one(iph1->cfp->vendorid);
		tlen += sizeof(*gen) + vidhash->l;
	}
	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	if (set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_SA) < 0)
		goto end;
	p = buf->v + sizeof(struct isakmp);

	/* set ISAKMP-SA payload to propose */
	gen = (struct isakmp_gen *)p;
	memcpy(p, mysa->v, mysa->l);
	p += mysa->l;

	/* append vendor id, if needed */
	if (vidhash) {
		gen->np = ISAKMP_NPTYPE_VID;
		gen = (struct isakmp_gen *)p;
		gen->len = ntohs(sizeof(*gen) + vidhash->l);
		p += sizeof(*gen);
		memcpy(p, vidhash->v, vidhash->l);
		p += vidhash->l;
	}

	gen->np = ISAKMP_NPTYPE_NONE;
    }

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 0);
#endif

	/* send HDR;SA to responder */
	if (isakmp_send(iph1, buf) < 0) goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_2;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)buf,
				SCHED_ID_PH1_RESEND);

	/* re-arrange and save SA payload minus general header. */
	memmove(mysa->v, mysa->v + sizeof(struct isakmp_gen),
		mysa->l - sizeof(struct isakmp_gen));
	mysa->l -= sizeof(struct isakmp_gen);
	iph1->sa = mysa;
	mysa = NULL;

	error = 0;

end:
	if (error) {
		if (buf != NULL)
			vfree(buf);
	}

	if (vidhash != NULL)
		vfree(vidhash);
	if (mysa != NULL)
		vfree(mysa);

	return error;
}

/*
 * create ID, HASH payload with isakmp header.
 */
static vchar_t *
isakmp_ident_ir3mx(from, iph1)
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = NULL, *new = NULL;
	char *p;
	int tlen;
	struct isakmp_gen *gen;
	int error = -1;

	/* create buffer */
	tlen = sizeof(struct isakmp)
	     + sizeof(*gen) + iph1->id->l
	     + sizeof(*gen) + iph1->hash->l;

	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	if (set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_ID) < 0)
		goto end;
	p = buf->v + sizeof(struct isakmp);

	/* create isakmp ID payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_HASH;
	gen->len = htons(sizeof(*gen) + iph1->id->l);
	p += sizeof(*gen);

	memcpy(p, iph1->id->v, iph1->id->l);
	p += iph1->id->l;

	/* create isakmp HASH payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;
	gen->len = htons(sizeof(*gen) + iph1->hash->l);
	p += sizeof(*gen);

	memcpy(p, iph1->hash->v, iph1->hash->l);
	p += iph1->hash->l;

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 1);
#endif

	/* encoding */
	if ((new = isakmp_do_encrypt(iph1, buf, iph1->ivm->ive, iph1->ivm->iv)) == 0)
		goto end;

	vfree(buf);

	buf = new;

	/* send HDR;ID;HASH to responder */
	if (isakmp_send(iph1, buf) < 0) goto end;

	/* XXX: synchronization IV */
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

/*
 * create KE, NONCE payload with isakmp header.
 */
static vchar_t *
isakmp_ident_ir2mx(from, iph1)
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = 0;
	struct isakmp_gen *gen;
	char *p;
	int tlen;
	int error = -1;

	/* create buffer */
	tlen = sizeof(struct isakmp)
	     + sizeof(*gen) + iph1->dhpub->l
	     + sizeof(*gen) + iph1->nonce->l;

	if ((buf = vmalloc(tlen)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	/* set isakmp header */
	if (set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_KE) < 0)
		goto end;
	p = buf->v + sizeof(struct isakmp);

	/* create isakmp KE payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONCE;
	gen->len = htons(sizeof(*gen) + iph1->dhpub->l);
	p += sizeof(*gen);

	memcpy(p, iph1->dhpub->v, iph1->dhpub->l);
	p += iph1->dhpub->l;

	/* create isakmp NONCE payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;
	gen->len = htons(sizeof(*gen) + iph1->nonce->l);
	p += sizeof(*gen);

	memcpy(p, iph1->nonce->v, iph1->nonce->l);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 0);
#endif

	/* send HDR;KE;NONCE to responder */
	if (isakmp_send(iph1, buf) < 0) goto end;

	error = 0;

end:
	if (error && buf != NULL) {
		vfree(buf);
		buf = NULL;
	}
	return buf;
}

/* %%%
 * Aggressive Exchange (Aggressive Mode)
 */
/*
 * receive HDR;HASH from initiator
 */
int
isakmp_aggressive_r2(msg0, from, iph1)
	vchar_t *msg0;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *msg = NULL;
	struct isakmp_pl_hash *hash = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_2) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* decrypting if need. */
	/* XXX configurable ? */
	if (ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		if ((msg = isakmp_do_decrypt(iph1, msg0, iph1->ivm->iv, iph1->ivm->ive)) == NULL)
			goto end;
	} else
		msg = vdup(msg0);

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_AGG, RESPONDER
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_HASH:
			hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (hash == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* validate HASH */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH\n"));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	my_hash = isakmp_compute_hash(iph1, VALIDATE);
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog2(from, LOCATION, "HASH mismatch.\n");
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL);
		goto end;
	}
    }

	/* XXX: synchronization IV */
	if (ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {
		memcpy(iph1->ivm->ivd->v, iph1->ivm->ive->v, iph1->ivm->iv->l);
		memcpy(iph1->ivm->iv->v, iph1->ivm->ive->v, iph1->ivm->iv->l);
	}

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_ESTABLISHED;

	/* add to the schedule to expire, and seve back pointer. */
	iph1->sc = sched_add(iph1->isa->ld_time, 0,
				1, isakmp_expire,
				(caddr_t)iph1, (caddr_t)0,
				SCHED_ID_PH1_RESEND);

	plog2(from, LOCATION,
	    "established ISAKMP-SA, %s.\n", isakmp_pindex(&iph1->index, 0));

	/* XXX: do post-command */
	if (iph1->cfp->exec_command != NULL)
		post_command(iph1);

	error = 0;

end:
	if (error) {
		if (iph1 != NULL)
			(void)isakmp_free_ph1(iph1);
	}
	if (msg != NULL)
		vfree(msg);

	return error;
}

/*
 * receive HDR;SA;KE;Nr;IDir;HASH_R from responder,
 * and retrun HDR;HASH_I
 */
int
isakmp_aggressive_i2(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = 0;
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct isakmp_pl_sa *sa = NULL;
	struct isakmp_pl_ke *ke = NULL;
	struct isakmp_pl_id *id = NULL;
	struct isakmp_pl_nonce *nonce = NULL;
	struct isakmp_pl_hash *hash = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_2) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_AGG, INITIATOR
	 * ISAKMP_NPTYPE_SA,
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_ID,
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* SA paylad is fixed postion */
	PH1_CHECK_ORDER(pa, ISAKMP_NPTYPE_SA, LOCATION);
	sa = (struct isakmp_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			ke = (struct isakmp_pl_ke *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_NONCE:
			nonce = (struct isakmp_pl_nonce *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_ID:
			id = (struct isakmp_pl_id *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_HASH:
			hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (ke == NULL || nonce == NULL || id == NULL || hash == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* XXX check SA returned. */

	/* check SA payload and get new one for use */
    {
	vchar_t *sa_ret;

	if ((sa_ret = ipsecdoi_get_proposal((struct ipsecdoi_sa *)sa,
					OAKLEY_MAIN_MODE)) == NULL) {
		/* XXX send information */
		goto end;
	}

	/* save sa parameters */
	iph1->isa = ipsecdoi_get_oakley(sa_ret);
	vfree(sa_ret);
	if (iph1->isa == NULL)
		goto end;
    }

	/* iph1->sa (SAi_b) is recorded in isamp_aggressive_i1 */

	/* modify index of the isakmp status record */
	memcpy(&iph1->index.r_ck, &isakmp->r_ck, sizeof(cookie_t));

	/* commit responder's ke, nonce for use */
	if (isakmp_kn2isa(iph1, ke, nonce) < 0) goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (isakmp_compute_skeyids(iph1) < 0) goto end;
	if (isakmp_compute_enckey(iph1) < 0) goto end;
	if ((iph1->ivm = isakmp_new_iv(iph1)) == NULL)
		goto end;

	/* save responder's id */
	if (isakmp_id2isa(iph1, id) < 0) goto end;

	/* validate HASH */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH\n"));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	my_hash = isakmp_compute_hash(iph1, VALIDATE);
	if (my_hash == NULL)
		goto end;

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog2(from, LOCATION, "HASH mismatch.\n");
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL);
		goto end;
	}
    }

	/* generate HASH to send */
	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "generate HASH_I\n"));
	if ((iph1->hash = isakmp_compute_hash(iph1, GENERATE)) == NULL)
		goto end;

	/* create buffer to send isakmp payload */
    {
	struct isakmp_gen *gen;
	char *p;
	int tlen;

	tlen = sizeof(struct isakmp)
		+ sizeof(*gen) + iph1->hash->l;
	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	/* set isakmp header */
	if (set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_HASH) < 0)
		goto end;
	p += sizeof(struct isakmp);

	/* create isakmp HASH payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;
	gen->len = htons(sizeof(*gen) + iph1->hash->l);
	p += sizeof(*gen);
	memcpy(p, iph1->hash->v, iph1->hash->l);
	p += iph1->hash->l;
    }

#if 0	/* XXX to be configurable */
	/* re-set encryption flag, for serurity. */
	iph1->flags |= ISAKMP_FLAG_E;
#endif

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 0);
#endif

	/* send HDR;ID;HASH to responder */
	if (isakmp_send(iph1, buf) < 0) goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_ESTABLISHED;

	/* add to the schedule to expire, and seve back pointer. */
	iph1->sc = sched_add(iph1->isa->ld_time, 0,
				1, isakmp_expire,
				(caddr_t)iph1, (caddr_t)0,
				SCHED_ID_PH1_LIFETIME);

	plog2(from, LOCATION,
	    "established ISAKMP-SA, %s.\n", isakmp_pindex(&iph1->index, 0));

	error = 0;

end:
	if (error) {
		if (iph1 != NULL)
			(void)isakmp_free_ph1(iph1);
	}
	return error;
}

/*
 * receive HDR;SA;KE;Ni;IDii from initiator,
 * and retrun appropreate HDR;SA;KE;Nr;IDir;HASH_R
 */
int
isakmp_aggressive_r1(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct isakmp_pl_sa *sa = NULL;
	struct isakmp_pl_ke *ke = NULL;
	struct isakmp_pl_nonce *nonce = NULL;
	struct isakmp_pl_id *id = NULL;
	vchar_t *sa_ret;
	int error = -1;
	vchar_t *vidhash = NULL;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_1) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_AGG, RESPONDER, ISAKMP_STATE_ESTABLISHED
	 * ISAKMP_NPTYPE_SA,
	 * ISAKMP_NPTYPE_KE, ISAKMP_NPTYPE_NONCE, ISAKMP_NPTYPE_ID,
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_NONE
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;
	pa = (struct isakmp_parse_t *)pbuf->v;

	/* SA paylad is fixed postion */
	PH1_CHECK_ORDER(pa, ISAKMP_NPTYPE_SA, LOCATION);
	sa = (struct isakmp_pl_sa *)pa->ptr;
	pa++;

	for (/*nothing*/;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_KE:
			ke = (struct isakmp_pl_ke *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_NONCE:
			nonce = (struct isakmp_pl_nonce *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_ID:
			id = (struct isakmp_pl_id *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			/* don't send information, see isakmp_ident_r1() */
			error = 0;
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);
    }

	/* payload existency check */
	if (ke == NULL || nonce == NULL || id == NULL) {
		plog2(from, LOCATION, "short isakmp message received.\n");
		goto end;
	}

	/* check SA payload and get new one for use */
	if ((sa_ret = ipsecdoi_get_proposal((struct ipsecdoi_sa *)sa,
					OAKLEY_MAIN_MODE)) == NULL) {
		/* XXX send information */
		goto end;
	}

	/* save sa parameters */
	if ((iph1->isa = ipsecdoi_get_oakley(sa_ret)) == NULL)
		goto end;

	/* re-arrange and save SA payload minus general header. */
	iph1->sa = vmalloc(ntohs(sa->h.len) - sizeof(struct isakmp_gen));
	if (!iph1->sa) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		/* XXX send information */
		goto end;
	}
	memmove(iph1->sa->v, &sa->h + 1,
		ntohs(sa->h.len) - sizeof(struct isakmp_gen));

	/* set remote address */
	if ((iph1->remote =
	        (struct sockaddr *)malloc(from->sa_len)) == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy((caddr_t)iph1->remote, (caddr_t)from, from->sa_len);

	/* save values into isakmp status */
	iph1->etype = isakmp->etype;

	/* save initiator's id */
	if (isakmp_id2isa(iph1, id) < 0)
		goto end;

	/* commit initiator's ke, nonce for use */
	if (isakmp_kn2isa(iph1, ke, nonce) < 0)
		goto end;

	/* set responder's cookie */
	isakmp_set_cookie((char *)&iph1->index.r_ck, from);

	/* modify index of the isakmp status record */
	memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(cookie_t));

	/* make ID payload into isakmp status */
	if ((iph1->id = ipsecdoi_get_id1(iph1)) == NULL)
		goto end;

	/* generate DH public value */
	if (isakmp_dh_generate(iph1->isa->dh,
		&iph1->dhpub, &iph1->dhpriv) < 0) goto end;

	/* generate NONCE value */
	/* XXX: configurable */
	if ((iph1->nonce = eay_set_random(isakmp_nonce_size)) == NULL) goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (isakmp_compute_skeyids(iph1) < 0) goto end;
	if (isakmp_compute_enckey(iph1) < 0) goto end;
	if ((iph1->ivm = isakmp_new_iv(iph1)) == NULL)
		goto end;

	/* generate HASH to send */
	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "generate HASH_R\n"));
	if ((iph1->hash = isakmp_compute_hash(iph1, GENERATE)) == NULL)
		goto end;

  {
	vchar_t *ret = NULL;

	/* create buffer to send isakmp payload */
    {
	struct isakmp_gen *gen = NULL;
	char *p;
	int tlen;

	tlen = sizeof(struct isakmp)
		+ sa_ret->l
		+ sizeof(*gen) + iph1->dhpub->l
		+ sizeof(*gen) + iph1->nonce->l
		+ sizeof(*gen) + iph1->id->l
		+ sizeof(*gen) + iph1->hash->l;
	if (iph1->cfp->vendorid) {
		/* XXX should this be configurable? */
		vidhash = eay_md5_one(iph1->cfp->vendorid);
		tlen += sizeof(*gen) + vidhash->l;
	}
	if ((ret = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	if (set_isakmp_header(ret, iph1, ISAKMP_NPTYPE_SA) < 0)
		goto end;
	p = ret->v + sizeof(*isakmp);

	/* create ISAKMP-SA payload to reply */
	gen = (struct isakmp_gen *)p;
	memcpy(p, sa_ret->v, sa_ret->l);
	gen->np = ISAKMP_NPTYPE_KE;
	gen->reserved = 0;
	gen->len = htons(sa_ret->l);
	p += sa_ret->l;

	/* create isakmp KE payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONCE;
	gen->len = htons(sizeof(*gen) + iph1->dhpub->l);
	p += sizeof(*gen);
	memcpy(p, iph1->dhpub->v, iph1->dhpub->l);
	p += iph1->dhpub->l;

	/* create isakmp NONCE payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_ID;
	gen->len = htons(sizeof(*gen) + iph1->nonce->l);
	p += sizeof(*gen);
	memcpy(p, iph1->nonce->v, iph1->nonce->l);
	p += iph1->nonce->l;

	/* create isakmp ID payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_HASH;
	gen->len = htons(sizeof(*gen) + iph1->id->l);
	p += sizeof(*gen);
	memcpy(p, iph1->id->v, iph1->id->l);
	p += iph1->id->l;

	/* create isakmp HASH payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;	/* updated later */
	gen->len = htons(sizeof(*gen) + iph1->hash->l);
	p += sizeof(*gen);
	memcpy(p, iph1->hash->v, iph1->hash->l);
	p += iph1->hash->l;

	/* append vendor id, if needed */
	if (vidhash) {
		gen->np = ISAKMP_NPTYPE_VID;	/* update np of previous gen */
		gen = (struct isakmp_gen *)p;
		gen->len = htons(sizeof(*gen) + vidhash->l);
		p += sizeof(*gen);
		memcpy(p, vidhash->v, vidhash->l);
		p += vidhash->l;
	}

	gen->np = ISAKMP_NPTYPE_NONE;
    }

	vfree(sa_ret);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(ret, iph1->local, iph1->remote, 1);
#endif

	/* send HDR;SA to responder */
	if (isakmp_send(iph1, ret) < 0) goto end;

	/* generate SKEYIDs & IV & final cipher key */
	if (isakmp_compute_skeyids(iph1) < 0) goto end;
	if (isakmp_compute_enckey(iph1) < 0) goto end;
	if ((iph1->ivm = isakmp_new_iv(iph1)) == NULL)
		goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_2;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)ret,
				SCHED_ID_PH1_RESEND);
  }

	error = 0;

end:
	if (error) {
		if (iph1 != NULL)
			(void)isakmp_free_ph1(iph1);
	}
	if (vidhash != NULL)
		vfree(vidhash);

	return error;
}

/*
 * begin Aggressive Mode as initiator, sending HDR;SA;KE;Ni;IDii to responder.
 */
int
isakmp_aggressive_i1(msg, to, iph1)
	vchar_t *msg; /* must be null */
	struct sockaddr *to;
	struct isakmp_ph1 *iph1;
{
	vchar_t *buf = NULL;
	struct isakmp *isakmp;
	vchar_t *mysa = NULL;
	int error = -1;
	vchar_t *vidhash = NULL;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validity check */
	if (iph1->status != ISAKMP_STATE_1) {
		plog(LOCATION, "status mismatched %d.\n", iph1->status);
		goto end;
	}

	/* set isakmp header value */
	iph1->dir = INITIATOR;
	iph1->version = ISAKMP_VERSION_NUMBER;
	iph1->etype = iph1->cfp->ph[0]->etype;
	iph1->flags = 0;
	memcpy(&iph1->msgid, msgid0, sizeof(iph1->msgid));

	/* make ID payload into isakmp status */
	if ((iph1->id = ipsecdoi_get_id1(iph1)) == NULL)
		goto end;

	/* create SA payload */
	if ((mysa = ipsecdoi_make_mysa(&iph1->cfp->ph[0]->sa, 0, 0, NULL)) == NULL) {
		plog(LOCATION, "no matching proposal found.\n");
		goto end;
	}

	if (!iph1->cfp->ph[0]->pfsgroup) {
		plog(LOCATION, "no pfs group found for aggressive mode.\n");
		goto end;
	}

	/* generate DH public value */
	if (isakmp_dh_generate(iph1->cfp->ph[0]->pfsdh,
				&iph1->dhpub, &iph1->dhpriv) < 0)
		goto end;

	/* generate NONCE value */
	/* XXX: configurable */
	if ((iph1->nonce = eay_set_random(isakmp_nonce_size)) == NULL)
		goto end;

	/* create buffer to send isakmp payload */
    {
	struct isakmp_gen *gen;
	char *p;
	int tlen;

	tlen = sizeof(*isakmp)
		+ mysa->l
		+ sizeof(*gen) + iph1->dhpub->l
		+ sizeof(*gen) + iph1->nonce->l
		+ sizeof(*gen) + iph1->id->l;
	if (iph1->cfp->vendorid) {
		/* XXX should this be configurable? */
		vidhash = eay_md5_one(iph1->cfp->vendorid);
		tlen += sizeof(*gen) + vidhash->l;
	}
	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/* set isakmp header */
	if (set_isakmp_header(buf, iph1, ISAKMP_NPTYPE_SA) < 0)
		goto end;
	p = buf->v + sizeof(*isakmp);

	/* create ISAKMP-SA payload to propose */
	gen = (struct isakmp_gen *)p;
	memcpy(p, mysa->v, mysa->l);
	gen->np = ISAKMP_NPTYPE_KE;
	p += mysa->l;

	/* create isakmp KE payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONCE;
	gen->len = htons(sizeof(*gen) + iph1->dhpub->l);
	p += sizeof(*gen);
	memcpy(p, iph1->dhpub->v, iph1->dhpub->l);
	p += iph1->dhpub->l;

	/* create isakmp NONCE payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_ID;
	gen->len = htons(sizeof(*gen) + iph1->nonce->l);
	p += sizeof(*gen);
	memcpy(p, iph1->nonce->v, iph1->nonce->l);
	p += iph1->nonce->l;

	/* create isakmp ID payload */
	gen = (struct isakmp_gen *)p;
	gen->np = ISAKMP_NPTYPE_NONE;	/* updated later */
	gen->len = htons(sizeof(*gen) + iph1->id->l);
	p += sizeof(*gen);
	memcpy(p, iph1->id->v, iph1->id->l);
	p += iph1->id->l;

	/* append vendor id, if needed */
	if (vidhash) {
		gen->np = ISAKMP_NPTYPE_VID;	/* update np of previous gen */
		gen = (struct isakmp_gen *)p;
		gen->len = htons(sizeof(*gen) + vidhash->l);
		p += sizeof(*gen);
		memcpy(p, vidhash->v, vidhash->l);
		p += vidhash->l;
	}

	gen->np = ISAKMP_NPTYPE_NONE;
    }

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 0);
#endif

	/* send HDR;SA;KE;Ni;IDii to responder */
	if (isakmp_send(iph1, buf) < 0) goto end;

	/* change status of isakmp status entry */
	iph1->status = ISAKMP_STATE_2;

	/* add to the schedule to resend, and seve back pointer. */
	iph1->sc = sched_add(isakmp_timer, isakmp_resend_ph1,
				isakmp_try, isakmp_timeout_ph1,
				(caddr_t)iph1, (caddr_t)buf,
				SCHED_ID_PH1_RESEND);

	/* re-arrange and save SA payload minus general header. */
	memmove(mysa->v, mysa->v + sizeof(struct isakmp_gen),
		mysa->l - sizeof(struct isakmp_gen));
	mysa->l -= sizeof(struct isakmp_gen);
	iph1->sa = mysa;
	mysa = NULL;

	error = 0;

end:
	if (error) {
		if (buf != NULL)
			vfree(buf);
	}

	if (vidhash != NULL)
		vfree(vidhash);
	if (mysa != NULL)
		vfree(mysa);

	return error;
}

/*
 * New group mode as responder
 */
int
isakmp_newgroup_r(msg, from, iph1)
	vchar_t *msg;
	struct sockaddr *from;
	struct isakmp_ph1 *iph1;
{
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct isakmp_pl_hash *hash = NULL;
	struct isakmp_pl_sa *sa = NULL;
	int error = -1;
	vchar_t *buf;
	struct oakley_sa *osa;
	int len;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validate the type of next payload */
	/*
	 * ISAKMP_ETYPE_NEWGRP,
	 * ISAKMP_NPTYPE_HASH, (ISAKMP_NPTYPE_VID), ISAKMP_NPTYPE_SA,
	 * ISAKMP_NPTYPE_NONE
	 */
    {
	vchar_t *pbuf = NULL;
	struct isakmp_parse_t *pa;

	if ((pbuf = isakmp_parse(msg, from)) == NULL)
		goto end;

	for (pa = (struct isakmp_parse_t *)pbuf->v;
	     pa->type != ISAKMP_NPTYPE_NONE;
	     pa++) {

		switch (pa->type) {
		case ISAKMP_NPTYPE_HASH:
			if (hash) {
				isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
				plog2(from, LOCATION,
				    "received multiple payload type %d.\n",
				    pa->type);
				vfree(pbuf);
				goto end;
			}
			hash = (struct isakmp_pl_hash *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_SA:
			if (sa) {
				isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
				plog2(from, LOCATION,
				    "received multiple payload type %d.\n",
				    pa->type);
				vfree(pbuf);
				goto end;
			}
			sa = (struct isakmp_pl_sa *)pa->ptr;
			break;
		case ISAKMP_NPTYPE_VID:
			plog2(from, LOCATION,
				"peer transmitted Vendor ID.\n");
			isakmp_check_vendorid(pa->ptr, iph1, from);
			break;
		default:
			isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pa->type);
			vfree(pbuf);
			goto end;
		}
	}
	vfree(pbuf);

	if (!hash || !sa) {
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
		plog2(from, LOCATION,
		    "no HASH, or no SA payload.\n");
		goto end;
	}
    }

	/* validate HASH */
    {
	char *r_hash;
	vchar_t *my_hash = NULL;
	int result;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "validate HASH\n"));

	len = sizeof(isakmp->msgid) + ntohs(sa->h.len);
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, &isakmp->msgid, sizeof(isakmp->msgid));
	memcpy(buf->v + sizeof(isakmp->msgid), sa, ntohs(sa->h.len));

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "hash source\n"));
	YIPSDEBUG(DEBUG_DKEY, pdump(buf->v, buf->l, YDUMP_HEX));

	my_hash = isakmp_prf(iph1->skeyid_a, buf, iph1);
	vfree(buf);
	if (my_hash == NULL)
		goto end;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "hash result\n"));
	YIPSDEBUG(DEBUG_DKEY, pdump(my_hash->v, my_hash->l, YDUMP_HEX));

	r_hash = (char *)hash + sizeof(*hash);

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "original hash\n"));
	YIPSDEBUG(DEBUG_DKEY,
	    pdump(r_hash, ntohs(hash->h.len) - sizeof(*hash), YDUMP_HEX));

	result = memcmp(my_hash->v, r_hash, my_hash->l);
	vfree(my_hash);

	if (result) {
		plog2(from, LOCATION, "HASH mismatch.\n");
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_HASH_INFORMATION, NULL);
		goto end;
	}
    }

	/* check SA payload and get new one for use */
	if ((buf = ipsecdoi_get_proposal((struct ipsecdoi_sa *)sa,
					OAKLEY_NEWGROUP_MODE)) == NULL) {
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED, NULL);
		goto end;
	}

	/* save sa parameters */
	if ((osa = ipsecdoi_get_oakley(buf)) == NULL) {
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED, NULL);
		goto end;
	}
	vfree(buf);

	switch (osa->dhgrp) {
	case OAKLEY_ATTR_GRP_DESC_MODP768:
	case OAKLEY_ATTR_GRP_DESC_MODP1024:
	case OAKLEY_ATTR_GRP_DESC_MODP1536:
		/*XXX*/
	default:
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED, NULL);
		plog(LOCATION,
		    "dh group %d isn't supported.\n", osa->dhgrp);
		goto end;
	}

	plog2(from, LOCATION,
	    "got new dh group %s.\n", isakmp_pindex(&iph1->index, 0));

	error = 0;

end:
	if (error) {
		if (iph1 != NULL)
			(void)isakmp_free_ph1(iph1);
	}
	return error;
}

/*
 * compute skeyids
 * see seciton 5. Exchanges in RFC 2409
 */
static int
isakmp_compute_skeyids(iph1)
	struct isakmp_ph1 *iph1;
{
	vchar_t *key, *buf = 0, *bp;
	char *p;
	int len;
	int error = -1;

	/* compute sharing secret of DH */
	if (isakmp_dh_compute(iph1->isa->dh, iph1->dhpub,
			iph1->dhpriv, iph1->dhpub_p, &iph1->dhgxy) < 0)
		goto end;

	/* SKEYID */
	switch(iph1->isa->auth_t) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:
		/* SKEYID = prf(pre-shared-key, Ni_b | Nr_b) */
		if ((key = iph1->cfp->ph[0]->pskey) == 0) {
			plog(LOCATION, "couldn't find pskey.\n");
			goto end;
		}
		YIPSDEBUG(DEBUG_MISC, plog(LOCATION, "get secret.\n"));
		YIPSDEBUG(DEBUG_DKEY, pvdump(key));

		len = iph1->nonce->l + iph1->nonce_p->l;
		if ((buf = vmalloc(len)) == 0) {
			plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
			goto end;
		}
		p = buf->v;

		bp = (iph1->dir == INITIATOR ? iph1->nonce : iph1->nonce_p);
		YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "nonce1.\n"));
		YIPSDEBUG(DEBUG_DKEY, pvdump(bp));
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		bp = (iph1->dir == INITIATOR ? iph1->nonce_p : iph1->nonce);
		YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "nonce2.\n"));
		YIPSDEBUG(DEBUG_DKEY, pvdump(bp));
		memcpy(p, bp->v, bp->l);
		p += bp->l;

		if ((iph1->skeyid = isakmp_prf(key, buf, iph1)) == 0) goto end;
		break;

	case OAKLEY_ATTR_AUTH_METHOD_DSS:
		/* SKEYID = prf(Ni_b | Nr_b, g^xy) */
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:
		/* SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R) */
	case OAKLEY_ATTR_AUTH_METHOD_RSA:
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:
		plog(LOCATION,
		    "authentication method %d isn't supported\n", iph1->isa->auth_t);
		break;
	default:
		break;
	}

	vfree(buf);
	buf = 0;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute SKEYID.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(iph1->skeyid));

	/* SKEYID D */
	/* SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0) */
	len = iph1->dhgxy->l + sizeof(cookie_t) * 2 + 1;
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
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
	if ((iph1->skeyid_d = isakmp_prf(iph1->skeyid, buf, iph1)) == 0) goto end;

	vfree(buf);
	buf = 0;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute SKEYID_d.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(iph1->skeyid_d));

	/* SKEYID A */
	/* SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1) */
	len = iph1->skeyid_d->l + iph1->dhgxy->l + sizeof(cookie_t) * 2 + 1;
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
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
	if ((iph1->skeyid_a = isakmp_prf(iph1->skeyid, buf, iph1)) == 0) goto end;

	vfree(buf);
	buf = 0;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute SKEYID_a.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(iph1->skeyid_a));

	/* SKEYID E */
	/* SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2) */
	len = iph1->skeyid_a->l + iph1->dhgxy->l + sizeof(cookie_t) * 2 + 1;
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
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
	if ((iph1->skeyid_e = isakmp_prf(iph1->skeyid, buf, iph1)) == 0) goto end;

	vfree(buf);
	buf = 0;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute SKEYID_e.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(iph1->skeyid_e));

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
static int
isakmp_compute_enckey(iph1)
	struct isakmp_ph1 *iph1;
{
	u_int keylen, prflen;
	int error = -1;

	/* RFC2409 p39 */
	switch (iph1->isa->enc_t) {
	case OAKLEY_ATTR_ENC_ALG_DES:
		keylen = 8;
		break;
	case OAKLEY_ATTR_ENC_ALG_IDEA:
		keylen = 16;
		break;
	case OAKLEY_ATTR_ENC_ALG_BLOWFISH:	/* can negotiate keylen */
		keylen = iph1->isa->keylen ? iph1->isa->keylen : 56;
		break;
	case OAKLEY_ATTR_ENC_ALG_RC5:		/* can negotiate keylen */
	case OAKLEY_ATTR_ENC_ALG_CAST:		/* can negotiate keylen */
		keylen = iph1->isa->keylen ? iph1->isa->keylen : 16;
		break;
	case OAKLEY_ATTR_ENC_ALG_3DES:
		keylen = 24;
		break;
	default:
		plog(LOCATION,
			"encryption algoritym %d isn't supported.\n",
			iph1->isa->enc_t);
		goto end;
	}

	switch (iph1->isa->prf_t) {
	default:
		switch (iph1->isa->hash_t) {
		case OAKLEY_ATTR_HASH_ALG_MD5:
			prflen = 16;
			break;
		case OAKLEY_ATTR_HASH_ALG_SHA:
			prflen = 20;
			break;
		default:
			plog(LOCATION,
				"hash type %d isn't supported.\n",
				iph1->isa->hash_t);
			return 0;
			break;
		}
	}

	if ((iph1->key = vmalloc(keylen)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
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
			plog(LOCATION,
			"len(SKEYID_e) < len(Ka) (%d < %d), generating long key (Ka = K1 | K2 | ...)\n",
			iph1->skeyid_e->l, iph1->key->l));

		if ((buf = vmalloc(prflen)) == 0) {
			plog(LOCATION,
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
			if (!(res = isakmp_prf(iph1->skeyid_e, buf, iph1))) {
				vfree(buf);
				goto end;
			}
			YIPSDEBUG(DEBUG_CRYPT,
				plog(LOCATION,
				"compute intermediate cipher key K%d.\n",
				subkey));
			YIPSDEBUG(DEBUG_DCRYPT, pvdump(buf));
			YIPSDEBUG(DEBUG_DCRYPT, pvdump(res));

			cplen = (res->l < ep - p) ? res->l : ep - p;
			memcpy(p, res->v, cplen);
			p += cplen;

			buf->l = prflen;	/* to cancel K1 speciality */
			if (res->l != buf->l) {
				plog(LOCATION,
					"internal error: res->l=%d, buf->l=%d\n",
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
	if (iph1->isa->enc_t > ARRAYSIZE(cipher))
		goto end;
	if (cipher[iph1->isa->enc_t].weakkey == NULL
	 && (cipher[iph1->isa->enc_t].weakkey)(iph1->key)) {
		plog(LOCATION, "weakkey was generated.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "compute final cipher key.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(iph1->key));

	error = 0;

end:
	return error;
}

/*
 * compute IV
 *	IV = hash(g^xi | g^xr)
 * see 4.1 Phase 1 state in draft-ietf-ipsec-ike.
 */
struct isakmp_ivm *
isakmp_new_iv(iph1)
	struct isakmp_ph1 *iph1;
{
	struct isakmp_ivm *newivm = NULL;
	vchar_t *buf = NULL, *bp;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = iph1->dhpub->l + iph1->dhpub_p->l;
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	bp = (iph1->dir == INITIATOR ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (iph1->dir == INITIATOR ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	/* allocate IVm */
	if ((newivm = CALLOC(sizeof(struct isakmp_ivm), struct isakmp_ivm *)) == NULL) {
		plog(LOCATION, "calloc (%s)\n", strerror(errno)); 
		goto end;
	}

	/* compute IV */
	if ((newivm->iv = isakmp_hash(buf, iph1)) == NULL)
		goto end;

	/* adjust length of iv */
	newivm->iv->l = CBC_BLOCKLEN;

	/* create buffer to save iv */
	if ((newivm->ive = vdup(newivm->iv)) == NULL
	 || (newivm->ivd = vdup(newivm->iv)) == NULL) {
		plog(LOCATION, "vdup (%s)\n", strerror(errno));
		goto end;
	}

	error = 0;

	YIPSDEBUG(DEBUG_CRYPT, plog(LOCATION, "compute IV.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(newivm->iv));

end:
	if (error && newivm != NULL)
		isakmp_free_ivm(newivm);
	if (buf != NULL)
		vfree(buf);
	return newivm;
}

/*
 * compute IV for Phase 2
 * if pahse 1 was encrypted.
 *	IV = hash(last CBC block of Phase 1 | M-ID)
 * if phase 1 was not encrypted.
 *	IV = hash(phase 1 IV | M-ID)
 * see 4.2 Phase 2 state in draft-ietf-ipsec-ike.
 */
struct isakmp_ivm *
isakmp_new_iv2(iph1, msgid)
	struct isakmp_ph1 *iph1;
	msgid_t *msgid;
{
	struct isakmp_ivm *newivm = NULL;
	vchar_t *buf = NULL;
	char *p;
	int len;
	int error = -1;

	/* create buffer */
	len = iph1->ivm->iv->l + sizeof(msgid_t);
	if ((buf = vmalloc(len)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	p = buf->v;

	memcpy(p, iph1->ivm->iv->v, iph1->ivm->iv->l);
	p += iph1->ivm->iv->l;

	memcpy(p, msgid, sizeof(msgid_t));

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "compute IV for Phase 2 - source.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(buf));

	/* allocate IVm */
	if ((newivm = CALLOC(sizeof(struct isakmp_ivm), struct isakmp_ivm *)) == NULL) {
		plog(LOCATION, "calloc (%s)\n", strerror(errno)); 
		goto end;
	}

	/* compute IV */
	if ((newivm->iv = isakmp_hash(buf, iph1)) == NULL)
		goto end;

	/* create buffer to save new iv */
	if ((newivm->ive = vdup(newivm->iv)) == NULL
	 || (newivm->ivd = vdup(newivm->iv)) == NULL) {
		plog(LOCATION, "vdup (%s)\n", strerror(errno));
		goto end;
	}

	error = 0;

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "compute IV for Phase 2 - result.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(newivm->iv));

end:
	if (error && newivm != NULL)
		isakmp_free_ivm(newivm);
	if (buf != NULL)
		vfree(buf);
	return newivm;
}

void
isakmp_free_ivm(ivm)
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
 * compute HASH
 *   see seciton 5. Exchanges in isakmp-oakley-05.
 */
static vchar_t *
isakmp_compute_hash(iph1, sw)
	struct isakmp_ph1 *iph1;
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
	if ((buf = vmalloc(len)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	/*
	 * HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
	 * HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
	 */
	p = buf->v;

	bp = (sw == GENERATE ? iph1->dhpub : iph1->dhpub_p);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	bp = (sw == GENERATE ? iph1->dhpub_p : iph1->dhpub);
	memcpy(p, bp->v, bp->l);
	p += bp->l;

	if (iph1->dir == INITIATOR)
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.i_ck : (char *)&iph1->index.r_ck);
	else
		bp2 = (sw == GENERATE ?
		      (char *)&iph1->index.r_ck : (char *)&iph1->index.i_ck);
	bl = sizeof(cookie_t);
	memcpy(p, bp2, bl);
	p += bl;

	if (iph1->dir == INITIATOR)
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

	YIPSDEBUG(DEBUG_DKEY,
		plog(LOCATION, "compute HASH with:\n");
		pvdump(buf));

	/* compute HASH */
	if ((res = isakmp_prf(iph1->skeyid, buf, iph1)) == NULL)
		goto end;

	error = 0;

	YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "compute HASH.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(res));

end:
	if (buf != NULL)
		vfree(buf);
	return res;
}

/*
 * PRF
 *
 * NOTE: we do not support prf with different input/output bitwidth,
 * so we do not implement RFC2409 Appendix B (DOORAK-MAC example) in
 * isakmp_compute_keymat().  If you add support for such prf function,
 * modify isakmp_compute_keymat() accordingly.
 */
static vchar_t *
isakmp_prf(key, buf, iph1)
	vchar_t *key, *buf;
	struct isakmp_ph1 *iph1;
{
	vchar_t *res;

	switch (iph1->isa->prf_t) {
	default:
		switch (iph1->isa->hash_t) {
		case OAKLEY_ATTR_HASH_ALG_MD5:
			YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "hmac-md5 used.\n"));
			res = eay_hmacmd5_one(key, buf);
			break;
		case OAKLEY_ATTR_HASH_ALG_SHA:
			YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "hmac-sha1 used.\n"));
			res = eay_hmacsha1_one(key, buf);
			break;
		default:
			plog(LOCATION,
			    "hash type %d isn't supported.\n", iph1->isa->hash_t);
			return NULL;
			break;
		}
	}

	return res;
}

/*
 * hash
 */
static vchar_t *
isakmp_hash(buf, iph1)
	vchar_t *buf;
	struct isakmp_ph1 *iph1;
{
	vchar_t *res;

	switch (iph1->isa->prf_t) {
	default:
		switch (iph1->isa->hash_t) {
		case OAKLEY_ATTR_HASH_ALG_MD5:
			YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "md5 used.\n"));
			res = eay_md5_one(buf);
			break;
		case OAKLEY_ATTR_HASH_ALG_SHA:
			YIPSDEBUG(DEBUG_KEY, plog(LOCATION, "sha1 used.\n"));
			res = eay_sha1_one(buf);
			break;
		default:
			plog(LOCATION,
			    "hash type %d isn't supported.\n", iph1->isa->hash_t);
			return NULL;
			break;
		}
	}

	return res;
}

/*
 * compute sharing secret of DH
 * IN:	*dh, *pub, *priv, *pub_p
 * OUT: **gxy
 */
static int
isakmp_dh_compute(dh, pub, priv, pub_p, gxy)
	const struct dh *dh;
	vchar_t *pub, *priv, *pub_p, **gxy;
{
	int error = -1;

	if ((*gxy = vmalloc(dh->prime->l)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	switch (dh->type) {
	case OAKLEY_ATTR_GRP_TYPE_MODP:
		if (eay_dh_compute(dh->prime, dh->gen1, pub, priv, pub_p, gxy) < 0) {
			goto end;
		}
		break;

	default:
		plog(LOCATION,
		    "dh type %d isn't supported.\n", dh->type);
		goto end;
	}

	error = 0;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute DH's shared.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(*gxy));

end:
	return error;
}

/*
 * generate values of DH
 * IN:	*dh
 * OUT: **pub, **priv
 */
static int
isakmp_dh_generate(dh, pub, priv)
	const struct dh *dh;
	vchar_t **pub, **priv;
{
	int error = -1;

	switch (dh->type) {
	case OAKLEY_ATTR_GRP_TYPE_MODP:
		if (eay_dh_generate(dh->prime, dh->gen1, dh->gen2, pub, priv) < 0)
			goto end;
		break;

	default:
		plog(LOCATION,
		    "dhgrp type %d isn't supported.\n", dh->type);
		goto end;
	}

	error = 0;

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute DH's private.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(*priv));

	YIPSDEBUG(DEBUG_KEY,
	    plog(LOCATION, "compute DH's public.\n"));
	YIPSDEBUG(DEBUG_DKEY, pvdump(*pub));

end:
	return error;
}

/*
 * decrypt packet.
 *   save new iv and old iv.
 */
vchar_t *
isakmp_do_decrypt(iph1, msg, ivdp, ivep)
	struct isakmp_ph1 *iph1;
	vchar_t *msg, *ivdp, *ivep;
{
	vchar_t *buf = NULL, *new = NULL;
	char *pl;
	int len;
	u_int8_t padlen;
	int error = -1;

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "begin decryption.\n"));

	/* save IV for next, but not sync. */
	memset(ivep->v, 0, ivep->l);
	memcpy(ivep->v, (caddr_t)&msg->v[msg->l - CBC_BLOCKLEN], CBC_BLOCKLEN);

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "save IV for next, but not sync.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(ivep));

	pl = msg->v + sizeof(struct isakmp);

	len = msg->l - sizeof(struct isakmp);

	/* create buffer */
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, pl, len);

	/* do decrypt */
	if (iph1->isa->enc_t > ARRAYSIZE(cipher)
	 && cipher[iph1->isa->enc_t].decrypt == NULL) {
		plog(LOCATION,
			"invalid cipher algoriym was passed.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_CRYPT,
		plog(LOCATION,
			"decrypt(%s) called.\n",
			cipher[iph1->isa->enc_t].name));
	YIPSDEBUG(DEBUG_DCRYPT,
		plog(LOCATION,
			"with key:\n");
		pvdump(iph1->key));

	new = (cipher[iph1->isa->enc_t].decrypt)(buf, iph1->key, ivdp->v);
	vfree(buf);
	buf = NULL;
	if (new == NULL)
		goto end;

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "decrypted payload, but not trimed.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(new));

	YIPSDEBUG(DEBUG_DCRYPT,
	    plog(LOCATION, "using IV,\n");
	    pvdump(ivdp));

	/* get padding length */
	if (isakmp_pad_exclone)
		padlen = new->v[new->l - 1] + 1;
	else
		padlen = new->v[new->l - 1];
	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "padding len=%u\n", padlen));

	/* trim padding */
	if (isakmp_check_padding) {
		if (padlen > new->l) {
			plog(LOCATION,
			    "invalied padding len=%u, buflen=%u.\n", padlen, new->l);
			YIPSDEBUG(DEBUG_DCRYPT, pvdump(new));
			goto end;
		}
		new->l -= padlen;
		YIPSDEBUG(DEBUG_CRYPT,
		    plog(LOCATION, "trimmed padding\n"));
	} else {
		YIPSDEBUG(DEBUG_CRYPT,
		    plog(LOCATION, "skip to trim padding.\n"));
		;
	}

	/* create new buffer */
	len = sizeof(struct isakmp) + new->l;
	if ((buf = vmalloc(len)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, msg->v, sizeof(struct isakmp));
	memcpy(buf->v + sizeof(struct isakmp), new->v, new->l);
	((struct isakmp *)buf->v)->len = htonl(buf->l);

	YIPSDEBUG(DEBUG_CRYPT, plog(LOCATION, "decrypted.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(buf));

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
isakmp_do_encrypt(iph1, msg, ivep, ivp)
	struct isakmp_ph1 *iph1;
	vchar_t *msg, *ivep, *ivp;
{
	vchar_t *buf = 0, *new = 0;
	char *pl;
	int len;
	u_int padlen;
	int error = -1;

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "begin encryption.\n"));

	pl = msg->v + sizeof(struct isakmp);
	len = msg->l - sizeof(struct isakmp);

	/* add padding */
	padlen = isakmp_padlen(len);
	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "pad length = %u\n", padlen));

	/* create buffer */
	if ((buf = vmalloc(len + padlen)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, pl, len);

	/* make pad into tail */
	if (isakmp_pad_exclone)
		buf->v[len + padlen - 1] = padlen - 1;
	else
		buf->v[len + padlen - 1] = padlen;

	YIPSDEBUG(DEBUG_DCRYPT, pvdump(buf));

	/* do encrypt */
	if (iph1->isa->enc_t > ARRAYSIZE(cipher)
	 && cipher[iph1->isa->enc_t].encrypt == NULL) {
		plog(LOCATION,
			"invalid cipher algoriym was passed.\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_CRYPT,
		plog(LOCATION,
			"encrypt(%s) called.\n",
			cipher[iph1->isa->enc_t].name));
	YIPSDEBUG(DEBUG_DCRYPT,
		plog(LOCATION,
			"with key:\n");
		pvdump(iph1->key));

	new = (cipher[iph1->isa->enc_t].encrypt)(buf, iph1->key, ivep->v);
	vfree(buf);
	buf = NULL;
	if (new == NULL)
		goto end;

	YIPSDEBUG(DEBUG_DCRYPT,
	    plog(LOCATION, "encrypted payload, using IV,\n");
	    pvdump(ivep));

	/* save IV for next */
	memset(ivp->v, 0, ivp->l);
	memcpy(ivp->v, (caddr_t)&new->v[new->l - CBC_BLOCKLEN], CBC_BLOCKLEN);

	YIPSDEBUG(DEBUG_CRYPT,
	    plog(LOCATION, "save IV for next.\n"));
	YIPSDEBUG(DEBUG_DCRYPT, pvdump(ivp));

	/* create new buffer */
	len = sizeof(struct isakmp) + new->l;
	if ((buf = vmalloc(len)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	memcpy(buf->v, msg->v, sizeof(struct isakmp));
	memcpy(buf->v + sizeof(struct isakmp), new->v, new->l);
	((struct isakmp *)buf->v)->len = htonl(buf->l);

	error = 0;

	YIPSDEBUG(DEBUG_CRYPT, plog(LOCATION, "encrypted.\n"));

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
static int
isakmp_padlen(len)
	int len;
{
	int padlen;
	int base = CBC_BLOCKLEN;

	padlen = 8 - len % 8;

	if (isakmp_random_padding)
		padlen += ((random() % (isakmp_random_padsize + 1) + 1) * base);

	return padlen;
}

/*
 * calculate cookie and set.
 */
int
isakmp_set_cookie(place, to)
	char *place;
	struct sockaddr *to;
{
	vchar_t *buf, *buf2;
	char *p;
	int blen;
	time_t t;
	int error = -1;
	u_short port;

	blen = _INALENBYAF(myaddrs->addr->sa_family) + sizeof(u_short)
		+ _INALENBYAF(to->sa_family) + sizeof(u_short)
		+ sizeof(time_t) + local_secret_size;
	if ((buf = vmalloc(blen)) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}
	p = buf->v;

	/* copy my address */
	memcpy(p, _INADDRBYSA(myaddrs->addr),
		_INALENBYAF(myaddrs->addr->sa_family));
	p += _INALENBYAF(myaddrs->addr->sa_family);
	port = _INPORTBYSA(myaddrs->addr);
	memcpy(p, &port, sizeof(u_short));
	p += sizeof(u_short);

	/* copy target address */
	memcpy(p, _INADDRBYSA(to), _INALENBYAF(to->sa_family));
	p += _INALENBYAF(to->sa_family);
	port = _INPORTBYSA(to);
	memcpy(p, &port, sizeof(u_short));
	p += sizeof(u_short);

	/* copy time */
	t = time(0);
	memcpy(p, (caddr_t)&t, sizeof(t));
	p += sizeof(t);

	/* copy random value */
	if ((buf2 = eay_set_random(local_secret_size)) == 0) {
		return -1;
	}
	memcpy(p, buf2->v, local_secret_size);
	p += local_secret_size;
	vfree(buf2);

	buf2 = eay_sha1_one(buf);
	memcpy(place, buf2->v, sizeof(cookie_t));
	vfree(buf2);

	error = 0;
end:
	return error;
}

/*
 * save partner's id into isakmp status.
 */
static int
isakmp_id2isa(iph1, id)
	struct isakmp_ph1 *iph1;
	struct isakmp_pl_id *id;
{
	/* save the body of the ID payload */
	if ((iph1->id_p = vmalloc(ntohs(id->h.len) - sizeof(struct isakmp_gen))) == 0) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto err;
	}
	memcpy(iph1->id_p->v, (caddr_t)id + sizeof(struct isakmp_gen),
		iph1->id_p->l);

	return 0;
err:
	return -1;
}

/*
 * save partner's ke and nonce into isakmp status.
 */
static int
isakmp_kn2isa(iph1, ke, nonce)
	struct isakmp_ph1 *iph1;
	struct isakmp_pl_ke *ke;
	struct isakmp_pl_nonce *nonce;
{
	/* save the body of the KE payload */
	if ((iph1->dhpub_p = vmalloc(ntohs(ke->h.len) - sizeof(*ke))) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto err;
	}
	memcpy(iph1->dhpub_p->v, (caddr_t)ke + sizeof(*ke),
		iph1->dhpub_p->l);

	/* save the body of the NONCE payload */
	if ((iph1->nonce_p = vmalloc(ntohs(nonce->h.len) - sizeof(*nonce))) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto err;
	}
	memcpy(iph1->nonce_p->v, (caddr_t)nonce + sizeof(*nonce),
		iph1->nonce_p->l);

	return 0;
err:
	return -1;
}

static void
isakmp_check_vendorid(gen, iph1, from)
	struct isakmp_gen *gen;		/* points to Vendor ID payload */
	struct isakmp_ph1 *iph1;	/* my vendor ID may be inside */
	struct sockaddr *from;
{
	vchar_t *vidhash;

	if (!gen)
		return;
	if (!iph1->cfp->vendorid) {
		plog2(from, LOCATION,
			"ignoring Vendor ID as I don't have one.\n");
		return;
	}

	/* XXX should this be configurable? */
	vidhash = eay_md5_one(iph1->cfp->vendorid);
	if (!vidhash) {
		plog2(from, LOCATION,
			"failed to hash my Vendor ID.\n");
		return;
	}
	if (vidhash->l == ntohs(gen->len) - sizeof(*gen)
	 && memcmp(vidhash->v, gen + 1, vidhash->l) == 0) {
		plog2(from, LOCATION,
			"Vendor ID matched <%s>.\n", iph1->cfp->vendorid->v);
	} else
		plog2(from, LOCATION, "Vendor ID mismatch.\n");
	vfree(vidhash);

	return;
}

static void
isakmp_check_notify(gen, iph1, from)
	struct isakmp_gen *gen;		/* points to Notify payload */
	struct isakmp_ph1 *iph1;
	struct sockaddr *from;
{
	struct isakmp_pl_n *notify = (struct isakmp_pl_n *)gen;

	switch (ntohs(notify->type)) {
	case IPSECDOI_NTYPE_RESPONDER_LIFETIME:
		plog2(from, LOCATION,
			"ignoring RESPONDER-LIFETIME notification.\n");
		break;
	case IPSECDOI_NTYPE_REPLAY_STATUS:
		plog2(from, LOCATION,
			"ignoring REPLAY-STATUS notification.\n");
		break;
	case IPSECDOI_NTYPE_INITIAL_CONTACT:
		plog2(from, LOCATION,
			"ignoring INITIAL-CONTACT notification.\n");
		break;
	default:
		isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
		plog2(from, LOCATION,
		    "received unknown notification type %u.\n",
		    ntohs(notify->type));
	}

	return;
}
#ifdef HAVE_PRINT_ISAKMP_C
/* for print-isakmp.c */
char *snapend;
extern void isakmp_print __P((const u_char *, u_int, const u_char *));

/*
 * Return a name for the IP address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
char *
getname(ap)
	const u_char *ap;
{
	struct sockaddr_in addr;
	static char ntop_buf[MAXHOSTNAMELEN];

	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(struct sockaddr_in);
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, ap, sizeof(addr.sin_addr));
	getnameinfo((struct sockaddr *)&addr, addr.sin_len,
		ntop_buf, sizeof(ntop_buf), NULL, 0, NI_NUMERICHOST);

	return ntop_buf;
}

#ifdef INET6
/*
 * Return a name for the IP6 address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
char *
getname6(ap)
	const u_char *ap;
{
	struct sockaddr_in6 addr;
	static char ntop_buf[MAXHOSTNAMELEN];

	memset(&addr, 0, sizeof(addr));
	addr.sin6_len = sizeof(struct sockaddr_in6);
	addr.sin6_family = AF_INET6;
	memcpy(&addr.sin6_addr, ap, sizeof(addr.sin6_addr));
	getnameinfo((struct sockaddr *)&addr, addr.sin6_len,
		ntop_buf, sizeof(ntop_buf), NULL, 0, NI_NUMERICHOST);

	return ntop_buf;
}
#endif /* INET6 */

void
isakmp_printpacket(msg, from, my, decoded)
	vchar_t *msg;
	struct sockaddr *from;
	struct sockaddr *my;
	int decoded;
{
	struct timeval tv;
	int s;
	char hostbuf[MAXHOSTNAMELEN];
	char portbuf[MAXHOSTNAMELEN];
	struct isakmp *isakmp;
	vchar_t *buf;

	YIPSDEBUG(DEBUG_DUMP, goto doit);
	return;

doit:
	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));


	gettimeofday(&tv, NULL);
	s = tv.tv_sec % 3600;
	printf("%02d:%02d.%06u ", s / 60, s % 60, (u_int32_t)tv.tv_usec);

	if (from) {
		getnameinfo(from, from->sa_len, hostbuf, sizeof(hostbuf),
			portbuf, sizeof(portbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);
		printf("%s:%s", hostbuf, portbuf);
	} else
		printf("?");
	printf(" -> ");
	if (my) {
		getnameinfo(my, my->sa_len, hostbuf, sizeof(hostbuf),
			portbuf, sizeof(portbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);
		printf("%s:%s", hostbuf, portbuf);
	} else
		printf("?");
	printf(": ");

	buf = vdup(msg);
	if (!buf) {
		printf("(malloc fail)\n");
		return;
	}
	if (decoded) {
		isakmp = (struct isakmp *)buf->v;
		if (isakmp->flags & ISAKMP_FLAG_E) {
#if 0
			int pad;
			pad = *(u_char *)(buf->v + buf->l - 1);
			if (buf->l < pad && 2 < vflag)
				printf("(wrong padding)");
#endif
			isakmp->flags &= ~ISAKMP_FLAG_E;
		}
	}

	snapend = buf->v + buf->l;
	isakmp_print(buf->v, buf->l, NULL);
	printf("\n");
	fflush(stdout);

	return;
}
#endif /*HAVE_PRINT_ISAKMP_C*/

static int
etypesw(etype)
	int etype;
{
	switch (etype) {
	case ISAKMP_ETYPE_IDENT:
		return 1;
	case ISAKMP_ETYPE_AGG:
		return 2;
	case ISAKMP_ETYPE_QUICK:
		return 3;
	case ISAKMP_ETYPE_NEWGRP:
		return 4;
	default:
		return 0;
	}
	/*NOTREACHED*/
}

