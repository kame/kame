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
/* YIPS @(#)$Id: isakmp_inf.c,v 1.5 1999/10/21 06:12:05 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <net/route.h>
#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key_var.h>
#include <netinet/in.h>
#ifdef IPV6_INRIA_VERSION
#include <sys/queue.h>
#include <netinet/ipsec.h>
#else
#include <netinet6/ipsec.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
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
#include "misc.h"
#include "debug.h"

LIST_HEAD(_info_ph1tab_, pfkey_st) pfkey_list;

/* information exchange */
static int isakmp_info_recv_n __P((vchar_t *, struct sockaddr *));
static int isakmp_info_recv_d __P((vchar_t *, struct sockaddr *));

static void purge_spi __P((int, u_int32_t *, size_t));

/* %%%
 * Information Exchange
 */
/*
 * receive Information
 */
int
isakmp_info_recv(iph1, msg0, from)
	struct isakmp_ph1 *iph1;
	vchar_t *msg0;
	struct sockaddr *from;
{
	vchar_t *msg = NULL;
	int error = -1;
	u_int8_t np;

	YIPSDEBUG(DEBUG_STAMP,
	    plog(LOCATION, "receive Information.\n"));

	/* decrypting */
	/* Use new IV to decrypt Informational message. */
	if (ISSET(((struct isakmp *)msg0->v)->flags, ISAKMP_FLAG_E)) {

		struct isakmp_ivm *ivm;

		/* compute IV */
		if ((ivm = isakmp_new_iv2(iph1, &((struct isakmp *)msg0->v)->msgid)) == NULL)
			goto end;

		msg = isakmp_do_decrypt(iph1, msg0, ivm->iv, ivm->ive);
		isakmp_free_ivm(ivm);
		if (msg == NULL)
			goto end;

	} else {

		/* validation */
		switch (iph1->etype) {
		case ISAKMP_ETYPE_IDENT:
			if ((iph1->dir == INITIATOR && iph1->status < ISAKMP_STATE_4)
			 || (iph1->dir == RESPONDER && iph1->status < ISAKMP_STATE_3)) {
				break;
			}
			/*FALLTHRU*/
		default:
			plog2(from, LOCATION,
				"ignore, the packet must be encrypted.\n");
			goto end;
		}

		msg = vdup(msg0);
	}

    {
	struct isakmp *isakmp = (struct isakmp *)msg->v;
	struct isakmp_gen *gen;

	gen = (struct isakmp_gen *)((caddr_t)isakmp + sizeof(struct isakmp));
	if (isakmp->np == ISAKMP_NPTYPE_HASH)
		np = gen->np;
	else
		np = isakmp->np;
		
	switch (np) {
	case ISAKMP_NPTYPE_N:
		if (isakmp_info_recv_n(msg, from) < 0)
			goto end;
		break;
	case ISAKMP_NPTYPE_D:
		if (isakmp_info_recv_d(msg, from) < 0)
			goto end;
		break;
	case ISAKMP_NPTYPE_NONCE:
		/* XXX to be 6.4.2 ike-01.txt */
		/* XXX IV is to be synchronized. */
		plog2(from, LOCATION,
			"ignore Acknowledged Informational\n");
		break;
	default:
		/* don't send information, see isakmp_ident_r1() */
		error = 0;
		plog2(from, LOCATION,
			"ignore the packet, "
			"received unexpecting payload type %d.\n",
			gen->np);
		goto end;
	}
    }

    end:
	if (msg != NULL)
		vfree(msg);

	return 0;
}

/*
 * send Delete payload (for IPsec SA) in Informational exchange, based on
 * pfkey msg.
 */
int isakmp_info_send_d2_pf(msg)
	struct sadb_msg *msg;
{
	struct isakmp_ph1 *iph1 = NULL;
	caddr_t mhp[SADB_EXT_MAX + 1];
	struct sadb_sa *sa;
	struct sadb_address *src, *dst, *proxy;
	vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	struct isakmp_pl_d *d;
	struct sockaddr *saddr;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	switch (msg->sadb_msg_type) {
	case SADB_DELETE:
		break;
	default:
		YIPSDEBUG(DEBUG_MISC,
			plog(LOCATION, "unsupported message type %d\n",
				msg->sadb_msg_type));
		return EINVAL;
	}

	if (pfkey_align(msg, mhp) || pfkey_check(mhp)) {
		plog(LOCATION, "pfkey_check (%s)\n", ipsec_strerror());
		return EINVAL;
	}
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	dst = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	proxy = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_PROXY];

	/* first try me -> other guy */
	if (proxy)
		iph1 = isakmp_ph1byaddr((struct sockaddr *)(proxy + 1));
	else if (dst) {
		saddr = (struct sockaddr *)(dst + 1);
		if (dst->sadb_address_prefixlen ==
				_INALENBYAF(saddr->sa_family) << 3) {
			iph1 = isakmp_ph1byaddr(saddr);
		}
	}
	/* other guy -> me */
	if (!iph1) {
		if (proxy)
			iph1 = isakmp_ph1byaddr((struct sockaddr *)(proxy + 1));
		else if (src) {
			saddr = (struct sockaddr *)(src + 1);
			if (src->sadb_address_prefixlen ==
					_INALENBYAF(saddr->sa_family) << 3) {
				iph1 = isakmp_ph1byaddr(saddr);
			}
		}
	}

	if (!iph1) {
		YIPSDEBUG(DEBUG_MISC, plog(LOCATION, "no ISAKMP SA found\n"));
		return EINVAL;
	}

	tlen = sizeof(*d) + sizeof(sa->sadb_sa_spi);
	if ((payload = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		return errno;
	}

	d = (struct isakmp_pl_d *)payload->v;
	d->h.np = ISAKMP_NPTYPE_NONE;
	d->h.len = htons(tlen);
	d->doi = htonl(IPSEC_DOI);		/* IPSEC DOI (1) */
	d->proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
						/* IPSEC AH/ESP/whatever */
	d->spi_size = sizeof(sa->sadb_sa_spi);
	d->num_spi = htons(1);
	memcpy(d + 1, &sa->sadb_sa_spi, sizeof(sa->sadb_sa_spi));

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_D, 0);
	vfree(payload);

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));
	return error;
}

/*
 * send Delete payload (for IPsec SA) in Informational exchange
 * XXX looks incomplete
 */
int isakmp_info_send_d2_pst(pst)
	struct pfkey_st *pst;
{
	struct isakmp_ph1 *iph1 = NULL;
	vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	struct isakmp_pl_d *d;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	YIPSDEBUG(DEBUG_DMISC,
		GETNAMEINFO(pst->src, _addr1_, _addr2_);
		plog(LOCATION, "src %s[%s]\n", _addr1_, _addr2_);
		GETNAMEINFO(pst->dst, _addr1_, _addr2_);
		plog(LOCATION, "dst %s[%s]\n", _addr1_, _addr2_);
		if (pst->proxy) {
			GETNAMEINFO(pst->proxy, _addr1_, _addr2_);
			plog(LOCATION, "proxy %s[%s]\n", _addr1_, _addr2_);
		}
		);
	if (pst->proxy)
		iph1 = isakmp_ph1byaddr(pst->proxy);
	else if (pst->dst) {
		if (pst->prefd != _INALENBYAF(pst->dst->sa_family) << 3)
			return EINVAL;
		iph1 = isakmp_ph1byaddr(pst->dst);
	}
	if (iph1 == NULL)
		return EINVAL;

	tlen = sizeof(*d) + sizeof(pst->spi);
	if ((payload = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		return errno;
	}

	d = (struct isakmp_pl_d *)payload->v;
	d->h.np = ISAKMP_NPTYPE_NONE;
	d->h.len = htons(tlen);
	d->doi = htonl(IPSEC_DOI);		/* IPSEC DOI (1) */
	d->proto_id = pst->ipsec_proto;	/* IPSEC AH/ESP/whatever */
	d->spi_size = sizeof(pst->spi);
	d->num_spi = htons(1);
	memcpy(d + 1, &pst->spi, sizeof(pst->spi));

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_D, 0);
	vfree(payload);

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));
	return error;
}

/*
 * send Notification payload (for without ISAKMP SA) in Informational exchange
 */
int
isakmp_info_send_nx(isakmp, remote, local, type, data)
	struct isakmp *isakmp;
	struct sockaddr *remote, *local;
	int type;
	vchar_t *data;
{
	struct isakmp_ph1 *iph1 = NULL;
	isakmp_index *index = (isakmp_index *)isakmp;
	vchar_t *payload = NULL;
	int tlen;
	int error = -1;
	struct isakmp_pl_n *n;
	int spisiz = 0;		/* see below */

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* add new entry to isakmp status table. */
	if ((iph1 = isakmp_new_ph1(index)) == NULL)
		return -1;

	memcpy(&iph1->index.i_ck, &isakmp->i_ck, sizeof(cookie_t));
	isakmp_set_cookie((char *)&iph1->index.r_ck, iph1->local, remote);
	iph1->status = ISAKMP_STATE_1;
	iph1->dir = INITIATOR;
	iph1->version = isakmp->v_number;
	iph1->etype = isakmp->etype;
	iph1->flags = 0;
	memcpy(&iph1->msgid, &isakmp->msgid, sizeof(iph1->msgid));

	/* copy local address */
	GET_NEWBUF(iph1->local, struct sockaddr *, local, local->sa_len);
	if (iph1->local == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto end;
	}

	/* copy remote address */
	GET_NEWBUF(iph1->remote, struct sockaddr *, remote, remote->sa_len);
	if (iph1->remote == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto end;
	}

	tlen = sizeof(*n) + spisiz;
	if (data)
		tlen += data->l;
	if ((payload = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		goto end;
	}

	n = (struct isakmp_pl_n *)payload->v;
	n->h.np = ISAKMP_NPTYPE_NONE;
	n->h.len = htons(tlen);
	n->doi = IPSEC_DOI;
	n->proto_id = IPSECDOI_KEY_IKE;
	n->spi_size = spisiz;
	n->type = htons(type);
	if (spisiz)
		memset(n + 1, 0, spisiz);	/*XXX*/
	if (data)
		memcpy((caddr_t)(n + 1) + spisiz, data->v, data->l);

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, 0);
	vfree(payload);

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));

    end:
	if (iph1 != NULL)
		(void)isakmp_free_ph1(iph1);

	return error;
}

/*
 * send Notification payload (for ISAKMP SA) in Informational exchange
 */
int
isakmp_info_send_n1(iph1, type, data)
	struct isakmp_ph1 *iph1;
	int type;
	vchar_t *data;
{
	vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	struct isakmp_pl_n *n;
	int spisiz = 0;		/* see below */

	/*
	 * note on SPI size: which description is correct?  I have chosen
	 * this to be 0.
	 *
	 * RFC2408 3.1, 2nd paragraph says: ISAKMP SA is identified by
	 * Initiator/Responder cookie and SPI has no meaning, SPI size = 0.
	 * RFC2408 3.1, first paragraph on page 40: ISAKMP SA is identified
	 * by cookie and SPI has no meaning, 0 <= SPI size <= 16.
	 */

#if 0
	return 0;
#endif

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	tlen = sizeof(*n) + spisiz;
	if (data)
		tlen += data->l;
	if ((payload = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		return errno;
	}

	n = (struct isakmp_pl_n *)payload->v;
	n->h.np = ISAKMP_NPTYPE_NONE;
	n->h.len = htons(tlen);
	n->doi = htonl(iph1->isa->doi);
	n->proto_id = iph1->isa->proto_id;
	n->spi_size = spisiz;
	n->type = htons(type);
	if (spisiz)
		memset(n + 1, 0, spisiz);	/*XXX*/
	if (data)
		memcpy((caddr_t)(n + 1) + spisiz, data->v, data->l);

	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, 0);
	vfree(payload);

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));
	return error;
}

/*
 * send Notification payload (for IPsec SA) in Informational exchange
 */
int
isakmp_info_send_n2(iph2, type, data, flags)
	struct isakmp_ph2 *iph2;
	int type;
	vchar_t *data;
	int flags;
{
	struct isakmp_ph1 *iph1 = iph2->ph1;
	vchar_t *payload = NULL;
	int tlen;
	int error = 0;
	struct isakmp_pl_n *n;

#if 0
	return 0;
#endif

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	tlen = sizeof(*n) + sizeof(iph2->pst->spi);
	if (data)
		tlen += data->l;
	if ((payload = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno));
		return errno;
	}

	n = (struct isakmp_pl_n *)payload->v;
	n->h.np = ISAKMP_NPTYPE_NONE;
	n->h.len = htons(tlen);
	n->doi = htonl(IPSEC_DOI);		/* IPSEC DOI (1) */
	n->proto_id = iph2->pst->ipsec_proto;	/* IPSEC AH/ESP/whatever */
	n->spi_size = sizeof(iph2->pst->spi);
	n->type = htons(type);
	*(u_int32_t *)(n + 1) = (u_int32_t)htonl(iph2->pst->spi);
	if (data) {
		memcpy((caddr_t)(n + 1) + sizeof(iph2->pst->spi),
			&iph2->pst->spi, sizeof(iph2->pst->spi));
	}

	flags |= ISAKMP_FLAG_E;	/* XXX Should we do FLAG_A ? */
	error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, flags);
	vfree(payload);

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));
	return error;
}

/*
 * send Information
 * When ph1->skeyid_a == NULL, send message without encoding.
 */
int
isakmp_info_send_common(iph1, payload, np, flags)
	struct isakmp_ph1 *iph1;
	vchar_t *payload;
	u_int32_t np;
	int flags;
{
	struct isakmp_ph2 *iph2 = NULL;
	vchar_t *buf = NULL;
	vchar_t *hash = NULL;
	struct isakmp *isakmp;
	struct isakmp_gen *gen;
	u_int32_t msgid;	/*XXX should be msgid_t*/
	char *p;
	int tlen;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* add new entry to isakmp status table */
	msgid = isakmp_get_msgid2(iph1);
	if ((iph2 = isakmp_new_ph2(iph1, (msgid_t *)&msgid)) == 0)
		goto end;

	iph2->dir = INITIATOR;

	/* get IV and HASH(1) if skeyid_a was generated. */
	if (iph1->skeyid_a != NULL) {
		if ((iph2->ivm = isakmp_new_iv2(iph1, (msgid_t *)&msgid)) == NULL) {
			isakmp_free_ph2(iph2);
			goto end;
		}

		/* generate HASH(1) */
		if ((hash = isakmp_compute_hash1(iph2->ph1, (msgid_t *)&msgid, payload)) == NULL)
			goto end;

		/* initialized total buffer length */
		tlen = hash->l;
		tlen += sizeof(*gen);
	} else {
		/* IKE-SA is not established */
		hash = NULL;

		/* initialized total buffer length */
		tlen = 0;
	}

	tlen += sizeof(*isakmp) + payload->l;

	/* create buffer for isakmp payload */
	if ((buf = vmalloc(tlen)) == NULL) { 
		plog(LOCATION, "vmalloc (%s)\n",
			strerror(errno));
		goto end;
	}

	/* create isakmp header */
	isakmp = (struct isakmp *)buf->v;
	memcpy(&isakmp->i_ck, &iph1->index.i_ck, sizeof(cookie_t));
	memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(cookie_t));
	isakmp->np       = hash == NULL ? (np & 0xff) : ISAKMP_NPTYPE_HASH;
	isakmp->v_number = iph1->version;
	isakmp->etype    = ISAKMP_ETYPE_INFO;
	if ((flags & ISAKMP_FLAG_A) == 0)
		isakmp->flags = (hash == NULL ? 0 : ISAKMP_FLAG_E);
	else
		isakmp->flags = (hash == NULL ? 0 : ISAKMP_FLAG_A);
	memcpy(&isakmp->msgid, &msgid, sizeof(isakmp->msgid));
	isakmp->len   = htonl(tlen);
	p = (char *)(isakmp + 1);

	/* create HASH payload */
	if (hash != NULL) {
		gen = (struct isakmp_gen *)p;
		gen->np = np & 0xff;
		gen->len = htons(sizeof(*gen) + hash->l);
		p += sizeof(*gen);
		memcpy(p, hash->v, hash->l);
		p += hash->l;
	}

	/* add payload */
	memcpy(p, payload->v, payload->l);
	p += payload->l;

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(buf, iph1->local, iph1->remote, 1);
#endif

	/* encoding */
	if ((flags & ISAKMP_FLAG_E) != 0) {
		vchar_t *tmp;

		if ((tmp = isakmp_do_encrypt(iph2->ph1, buf, iph2->ivm->ive,
				iph2->ivm->iv)) == 0) {
			goto end;
		}
		vfree(buf);
		buf = tmp;
	}

	/* HDR*, HASH(1), N */
	if (isakmp_send(iph2->ph1, buf) < 0) goto end;

	YIPSDEBUG(DEBUG_STAMP,
	    plog(LOCATION, "sendto Information (%d).\n", np));

	/* add to the schedule to resend, and seve back pointer. */
	/* XXX Should we send three packet per a time, alternately re-send ? */
	iph2->sc = sched_add(isakmp_timer, isakmp_resend_ph2,
				isakmp_try, isakmp_timeout_ph2,
				(caddr_t)iph2, (caddr_t)buf,
				SCHED_ID_PH2_RESEND);

	error = 0;

end:
	if (error) {
		if (buf)
			vfree(buf);
	}

	return(error);
}

static char *isakmp_notify_msg[] = {
0,
"INVALID-PAYLOAD-TYPE",
"DOI-NOT-SUPPORTED",
"SITUATION-NOT-SUPPORTED",
"INVALID-COOKIE",
"INVALID-MAJOR-VERSION",
"INVALID-MINOR-VERSION",
"INVALID-EXCHANGE-TYPE",
"INVALID-FLAGS",
"INVALID-MESSAGE-ID",
"INVALID-PROTOCOL-ID",
"INVALID-SPI",
"INVALID-TRANSFORM-ID",
"ATTRIBUTES-NOT-SUPPORTED",
"NO-PROPOSAL-CHOSEN",
"BAD-PROPOSAL-SYNTAX",
"PAYLOAD-MALFORMED",
"INVALID-KEY-INFORMATION",
"INVALID-ID-INFORMATION",
"INVALID-CERT-ENCODING",
"INVALID-CERTIFICATE",
"CERT-TYPE-UNSUPPORTED",
"INVALID-CERT-AUTHORITY",
"INVALID-HASH-INFORMATION",
"AUTHENTICATION-FAILED",
"INVALID-SIGNATURE",
"ADDRESS-NOTIFICATION",
"NOTIFY-SA-LIFETIME",
"CERTIFICATE-UNAVAILABLE",
"UNSUPPORTED-EXCHANGE-TYPE",
"UNEQUAL-PAYLOAD-LENGTHS",
0
};

/*
 * handling to receive Notification payload
 */
static int
isakmp_info_recv_n(msg, from)
	vchar_t *msg;
	struct sockaddr *from;
{
	struct isakmp_pl_n *n = NULL;
	u_int type;
	vchar_t *pbuf;
	struct isakmp_parse_t *pa, *pap;
	char *spi;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	if (!(pbuf = isakmp_parse(msg, from)))
		return -1;
	pa = (struct isakmp_parse_t *)pbuf->v;
	for (pap = pa; pap->type; pap++) {
		switch (pap->type) {
		case ISAKMP_NPTYPE_HASH:
			/* do something here */
			break;
		case ISAKMP_NPTYPE_N:
			n = (struct isakmp_pl_n *)pap->ptr;
			break;
		default:
			vfree(pbuf);
			return -1;
		}
	}
	vfree(pbuf);
	if (!n)
		return -1;

	type = ntohs(n->type);

	/* sanity check */
	if (type > sizeof(isakmp_notify_msg)/sizeof(isakmp_notify_msg[0])) {
		plog2(from, LOCATION,
		    "received unsupported message type %d.\n", type);
		return(-1);
	}

	switch (type) {
	default:
		/* do something */
		break;
	}

	/* get spi and allocate */
	if (ntohs(n->h.len) != sizeof(*n) + n->spi_size) {
		plog2(from, LOCATION,
		    "invalid spi_size in notification payload.\n");
	}
	spi = mem2str((u_char *)(n + 1), n->spi_size);

	plog2(from, LOCATION,
	    "notification message %d:%s, doi=%d proto_id=%d spi=%s(size=%d).\n",
	    type, isakmp_notify_msg[type], ntohl(n->doi), n->proto_id, spi,
	    n->spi_size);

	free(spi);

	return(0);
}

static void
purge_spi(proto, spi, n)
	int proto;
	u_int32_t *spi;	/*network byteorder*/
	size_t n;
{
	vchar_t *buf;
	struct sadb_msg *msg, *next, *end;
	struct sadb_sa *sa;
	struct sadb_address *src, *dst;
	size_t i;
	caddr_t mhp[SADB_EXT_MAX + 1];

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	buf = pfkey_dump_sadb(proto);
	if (buf == NULL) {
		YIPSDEBUG(DEBUG_MISC, plog(LOCATION,
			"pfkey_dump_sadb returned nothing.\n"));
		return;
	}

	msg = (struct sadb_msg *)buf->v;
	end = (struct sadb_msg *)(buf->v + buf->l);

	while (msg < end) {
		if ((msg->sadb_msg_len << 3) < sizeof(*msg))
			break;
		next = (struct sadb_msg *)((caddr_t)msg + (msg->sadb_msg_len << 3));
		if (msg->sadb_msg_type != SADB_DUMP) {
			msg = next;
			continue;
		}

		if (pfkey_align(msg, mhp) || pfkey_check(mhp)) {
			plog(LOCATION, "pfkey_check (%s)\n", ipsec_strerror());
			msg = next;
			continue;
		}

		sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
		src = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
		dst = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
		if (!sa || !src || !dst) {
			msg = next;
			continue;
		}

		/* XXX n^2 algorithm, inefficient */
		/* XXX should we remove SAs with opposite direction as well? */
		for (i = 0; i < n; i++) {
			YIPSDEBUG(DEBUG_DMISC,
				plog(LOCATION, "check spi: packet %u against SA %u.\n",
					ntohl(spi[i]), ntohl(sa->sadb_sa_spi)));
			if (spi[i] == sa->sadb_sa_spi) {
				YIPSDEBUG(DEBUG_DMISC,
					plog(LOCATION, "purging spi=%u.\n",
						ntohl(spi[i])));
				pfkey_send_delete(sock_pfkey,
					msg->sadb_msg_satype,
					msg->sadb_msg_mode,
					(struct sockaddr *)(src + 1),
					(struct sockaddr *)(dst + 1),
					sa->sadb_sa_spi);
			}
		}

		msg = next;
	}

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));
}

/*
 * handling to receive Deletion payload
 */
static int
isakmp_info_recv_d(msg, from)
	vchar_t *msg;
	struct sockaddr *from;
{
	struct isakmp_pl_d *d;
	u_int32_t *spi;
	int tlen, num_spi;
	vchar_t *pbuf;
	struct isakmp_parse_t *pa, *pap;
	int protected = 0;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* validate the type of next payload */
	if (!(pbuf = isakmp_parse(msg, from)))
		return -1;
	pa = (struct isakmp_parse_t *)pbuf->v;
	for (pap = pa; pap->type; pap++) {
		switch (pap->type) {
		case ISAKMP_NPTYPE_D:
			break;
		case ISAKMP_NPTYPE_HASH:
			if (pap == pa) {
				protected++;
				break;
			}
#if 0
			isakmp_info_send_n1(iph1, ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE, NULL);
#endif
			plog2(from, LOCATION,
			    "received next payload type %d in wrong place (must be the first payload).\n",
			    pap->type);
			vfree(pbuf);
			return -1;
		default:
			/* don't send information, see isakmp_ident_r1() */
			plog2(from, LOCATION,
				"ignore the packet, "
				"received unexpecting payload type %d.\n",
				pap->type);
			vfree(pbuf);
			return 0;
		}
	}

	for (pap = pa; pap->type; pap++) {
		if (pap->type != ISAKMP_NPTYPE_D)
			continue;

		d = (struct isakmp_pl_d *)pap->ptr;

		if (ntohl(d->doi) != IPSEC_DOI) {
			YIPSDEBUG(DEBUG_DMISC,
				plog2(from, LOCATION,
				    "deletion message received, "
				    "doi=%d proto_id=%d: unsupported DOI.\n",
				    ntohl(d->doi), d->proto_id));
			continue;
		}
		if (d->spi_size != sizeof(u_int32_t)) {
			YIPSDEBUG(DEBUG_DMISC,
				plog2(from, LOCATION,
				    "deletion message received, "
				    "doi=%d proto_id=%d: strange spi size %d.\n",
				    ntohl(d->doi), d->proto_id, d->spi_size));
			continue;
		}

		spi = (u_int32_t *)(d + 1);
		tlen = ntohs(d->h.len) - sizeof(struct isakmp_pl_d);
		num_spi = ntohs(d->num_spi);

		if (tlen != num_spi * d->spi_size) {
			plog2(from, LOCATION,
			    "deletion payload with invalid length.\n");
			vfree(pbuf);
			return(-1);
		}

		if (protected) {
			YIPSDEBUG(DEBUG_MISC, plog(LOCATION,
				"packet properly proteted, purge SPIs.\n"));
			purge_spi(d->proto_id, spi, num_spi);
		} else {
			YIPSDEBUG(DEBUG_MISC, plog(LOCATION,
				"packet is not proteted, ignored.\n"));
		}
	}

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));

	return(0);
}
