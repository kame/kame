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
/* YIPS @(#)$Id: pfkey.c,v 1.40 2000/05/31 16:04:04 sakane Exp $ */

#define _PFKEY_C_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/route.h>
#include <net/pfkeyv2.h>
#include <netkey/key_debug.h>

#include <netinet/in.h>
#ifdef IPV6_INRIA_VERSION
#include <netinet/ipsec.h>
#else
#include <netinet6/ipsec.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "isakmp_inf.h"
#include "ipsec_doi.h"
#include "pfkey.h"
#include "handler.h"
#include "policy.h"
#include "algorithm.h"
#include "sainfo.h"
#include "proposal.h"
#include "admin.h"
#include "strnames.h"

/* prototype */
static int pfkey_setspidxbymsg __P((caddr_t *mhp, struct policyindex *spidx));
static int pfkey_spidxinfo __P((struct sadb_ident *id, struct sockaddr *saddr,
	u_int8_t *pref, u_int16_t *ul_proto)); 
static u_int ipsecdoi2pfkey_aalg __P((u_int hashtype));
static u_int ipsecdoi2pfkey_ealg __P((u_int t_id));
static u_int ipsecdoi2pfkey_calg __P((u_int t_id));
static u_int keylen_aalg __P((u_int hashtype));
static u_int keylen_ealg __P((u_int t_id, int encklen));

static int pk_recvgetspi __P((caddr_t *mhp));
static int pk_recvupdate __P((caddr_t *mhp));
static int pk_recvadd __P((caddr_t *mhp));
static int pk_recvdelete __P((caddr_t *mhp));
static int pk_recvacquire __P((caddr_t *mhp));
static int pk_recvexpire __P((caddr_t *mhp));
static int pk_recvspdupdate __P((caddr_t *mhp));
static int pk_recvspdadd __P((caddr_t *mhp));
static int pk_recvspddelete __P((caddr_t *mhp));
static int pk_recvspdget __P((caddr_t *mhp));
static int pk_recvspddump __P((caddr_t *mhp));
static int pk_recvspdflush __P((caddr_t *mhp));
static struct sadb_msg *pk_recv __P((int so, int *lenp));

static int (*pkrecvf[]) __P((caddr_t *)) = {
NULL,
pk_recvgetspi,
pk_recvupdate,
pk_recvadd,
pk_recvdelete,
NULL,	/* SADB_GET */
pk_recvacquire,
NULL,	/* SADB_REGISTER */
pk_recvexpire,
NULL,	/* SADB_FLUSH */
NULL,	/* SADB_DUMP */
NULL,	/* SADB_X_PROMISC */
NULL,	/* SADB_X_PCHANGE */
pk_recvspdupdate,
pk_recvspdadd,
pk_recvspddelete,
pk_recvspdget,
NULL,	/* SADB_X_SPDACQUIRE */
pk_recvspddump,
pk_recvspdflush,
NULL,	/* SADB_X_SPDSETIDX */
NULL,	/* SADB_X_SPDEXPIRE */
NULL,	/* SADB_X_SPDDELETE2 */
};

static int addnewsp __P((caddr_t *mhp));

/*
 * PF_KEY packet handler
 *	0: success
 *	-1: fail
 */
int
pfkey_handler()
{
	struct sadb_msg *msg;
	int len;
	caddr_t mhp[SADB_EXT_MAX + 1];
	int error = -1;

	/* receive pfkey message. */
	len = 0;
	msg = (struct sadb_msg *)pk_recv(lcconf->sock_pfkey, &len);
	if (msg == NULL) {
		if (len < 0) {
			plog(logp, LOCATION, NULL,
				"failed to recv from pfkey (%s)\n",
				strerror(errno));
			goto end;
		} else {
			/* short message - msg not ready */
			return 0;
		}
	}

	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL, "get pfkey %s message\n",
			s_pfkey_type(msg->sadb_msg_type)));
	YIPSDEBUG(DEBUG_SVERB, kdebug_sadb(msg));

	/* is it mine ? */
	/* XXX should be handled all message in spite of mine */
	if ((msg->sadb_msg_type == SADB_DELETE && msg->sadb_msg_pid == getpid())
	 && (msg->sadb_msg_pid != 0 && msg->sadb_msg_pid != getpid())) {
		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"pfkey message pid %d not interesting.\n",
				msg->sadb_msg_pid));
		goto end;
	}

	/* validity check */
	if (msg->sadb_msg_errno) {
		plog(logp, LOCATION, NULL,
			"pfkey %s failed %s\n",
			s_pfkey_type(msg->sadb_msg_type),
			strerror(msg->sadb_msg_errno));
		goto end;
	}

	/* check pfkey message. */
	if (pfkey_align(msg, mhp)) {
		plog(logp, LOCATION, NULL,
			"libipsec failed pfkey align (%s)\n",
			ipsec_strerror());
		goto end;
	}
	if (pfkey_check(mhp)) {
		plog(logp, LOCATION, NULL,
			"libipsec failed pfkey check (%s)\n",
			ipsec_strerror());
		goto end;
	}
	msg = (struct sadb_msg *)mhp[0];

	if (pkrecvf[msg->sadb_msg_type] == NULL) {
		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"not supported command %s\n",
				s_pfkey_type(msg->sadb_msg_type)));
		goto end;
	}

	if ((pkrecvf[msg->sadb_msg_type])(mhp) < 0)
		goto end;

	error = 0;
end:
	if (msg)
		free(msg);
	return(error);
}

static int
pfkey_setspidxbymsg(mhp, spidx)
	caddr_t *mhp;
	struct policyindex *spidx;
{
	memset(spidx, 0, sizeof(*spidx));

	if (pfkey_spidxinfo((struct sadb_ident *)mhp[SADB_EXT_IDENTITY_SRC],
			(struct sockaddr *)&spidx->src,
			&spidx->prefs, &spidx->ul_proto) < 0)
		return -1;

	if (pfkey_spidxinfo((struct sadb_ident *)mhp[SADB_EXT_IDENTITY_DST],
			(struct sockaddr *)&spidx->dst,
			&spidx->prefd, &spidx->ul_proto) < 0)
		return -1;

	spidx->dir = IPSEC_DIR_OUTBOUND;

	return 0;
}

static int
pfkey_spidxinfo(id, saddr, pref, ul_proto)
	struct sadb_ident *id;
	struct sockaddr *saddr;
	u_int8_t *pref;
	u_int16_t *ul_proto;
{
	union sadb_x_ident_id *aid;

	if (id->sadb_ident_type != SADB_X_IDENTTYPE_ADDR) {
		plog(logp, LOCATION, NULL,
			"not supported id type %d\n",
				id->sadb_ident_type);
		return -1;
	}

	aid = (union sadb_x_ident_id *)&id->sadb_ident_id;

	*pref = aid->sadb_x_ident_id_addr.prefix;
	*ul_proto = aid->sadb_x_ident_id_addr.ul_proto;
	memcpy(saddr, id + 1, ((struct sockaddr *)(id + 1))->sa_len);

	return 0;
}

/*
 * dump SADB
 */
vchar_t *
pfkey_dump_sadb(satype)
	int satype;
{
	int s = -1;
	vchar_t *buf = NULL;
	pid_t pid = getpid();
	struct sadb_msg *msg = NULL;
	size_t bl, ml;
	int len;

	if ((s = pfkey_open()) < 0) {
		plog(logp, LOCATION, NULL,
			"libipsec failed pfkey open (%s)", ipsec_strerror());
		return NULL;
	}

	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL, "call pfkey_send_dump\n"););
	if (pfkey_send_dump(s, satype) < 0) {
		plog(logp, LOCATION, NULL,
			"libipsec failed dump (%s)\n", ipsec_strerror());
		goto fail;
	}

	while (1) {
		if (msg)
			free(msg);
		msg = pk_recv(s, &len);
		if (msg == NULL) {
			if (len < 0)
				goto done;
			else
				continue;
		}

		if (msg->sadb_msg_type != SADB_DUMP || msg->sadb_msg_pid != pid)
			continue;

		ml = msg->sadb_msg_len << 3;
		bl = buf ? buf->l : 0;
		buf = vrealloc(buf, bl + ml);
		if (buf == NULL) {
			plog(logp, LOCATION, NULL,
				"failed to reallocate buffer to dump.\n");
			goto fail;
		}
		memcpy(buf->v + bl, msg, ml);

		if (msg->sadb_msg_seq == 0)
			break;
	}
	goto done;

fail:
	if (buf)
		vfree(buf);
	buf = NULL;
done:
	if (msg)
		free(msg);
	if (s >= 0)
		close(s);
	return buf;
}

/*
 * flush SADB
 */
void
pfkey_flush_sadb(proto)
	u_int proto;
{
	int satype;

	/* convert to SADB_SATYPE */
	if ((satype = admin2pfkey_proto(proto)) < 0)
		return;

	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL, "call pfkey_send_flush\n"););
	if (pfkey_send_flush(lcconf->sock_pfkey, satype) < 0) {
		plog(logp, LOCATION, NULL,
			"libipsec failed send flush (%s)\n", ipsec_strerror());
		return;
	}

	return;
}

/*
 * PF_KEY initialization
 */
int
pfkey_init()
{
	int reg_fail = 0;

	if ((lcconf->sock_pfkey = pfkey_open()) < 0) {
		plog(logp, LOCATION, NULL,
			"libipsec failed pfkey open (%s)", ipsec_strerror());
		return -1;
	}

	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL, "call pfkey_send_register\n"););
	if (pfkey_send_register(lcconf->sock_pfkey, SADB_SATYPE_ESP) < 0) {
		plog(logp, LOCATION, NULL,
			"WARNING: failed to regist esp (%s)", ipsec_strerror());
		reg_fail++;
		/*FALLTHROUGH*/
	}

	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL, "call pfkey_send_register\n"););
	if (pfkey_send_register(lcconf->sock_pfkey, SADB_SATYPE_AH) < 0) {
		plog(logp, LOCATION, NULL,
			"WARNING: failed to regist ah (%s)", ipsec_strerror());
		reg_fail++;
		/*FALLTHROUGH*/
	}

	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL, "call pfkey_send_register\n"););
	if (pfkey_send_register(lcconf->sock_pfkey, SADB_X_SATYPE_IPCOMP) < 0) {
		plog(logp, LOCATION, NULL,
			"WARNING: failed to regist ipcomp (%s)", ipsec_strerror());
		reg_fail++;
		/*FALLTHROUGH*/
	}

	if (reg_fail == 3) {
		plog(logp, LOCATION, NULL,
			"failed to regist any protocol.");
		pfkey_close(lcconf->sock_pfkey);
		return -1;
	}

	initsp();

	if (pfkey_send_spddump(lcconf->sock_pfkey) < 0) {
		plog(logp, LOCATION, NULL,
			"libipsec failed regist ipcomp (%s)", ipsec_strerror());
		pfkey_close(lcconf->sock_pfkey);
		return -1;
	}
#if 0
	if (pfkey_promisc_toggle(1) < 0) {
		pfkey_close(lcconf->sock_pfkey);
		return -1;
	}
#endif
	return 0;
}

/* %%% for conversion */
/* IPSECDOI_ATTR_AUTH -> SADB_AALG */
static u_int
ipsecdoi2pfkey_aalg(hashtype)
	u_int hashtype;
{
	switch (hashtype) {
	case IPSECDOI_ATTR_AUTH_HMAC_MD5:
		return SADB_AALG_MD5HMAC;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
		return SADB_AALG_SHA1HMAC;
	case IPSECDOI_ATTR_AUTH_KPDK:		/* need special care */
		return SADB_AALG_NONE;

	/* not supported */
	case IPSECDOI_ATTR_AUTH_DES_MAC:
		plog(logp, LOCATION, NULL,
			"Not supported hash type: %u\n", hashtype);
		return ~0;

	case 0: /* reserved */
	default:
		return SADB_AALG_NONE;

		plog(logp, LOCATION, NULL,
			"Invalid hash type: %u\n", hashtype);
		return ~0;
	}
	/*NOTREACHED*/
}

/* IPSECDOI_ESP -> SADB_EALG */
static u_int
ipsecdoi2pfkey_ealg(t_id)
	u_int t_id;
{
	switch (t_id) {
	case IPSECDOI_ESP_DES_IV64:		/* sa_flags |= SADB_X_EXT_OLD */
		return SADB_EALG_DESCBC;
	case IPSECDOI_ESP_DES:
		return SADB_EALG_DESCBC;
	case IPSECDOI_ESP_3DES:
		return SADB_EALG_3DESCBC;
#ifdef SADB_EALG_RC5CBC
	case IPSECDOI_ESP_RC5:
		return SADB_EALG_RC5CBC;
#endif
	case IPSECDOI_ESP_CAST:
		return SADB_EALG_CAST128CBC;
	case IPSECDOI_ESP_BLOWFISH:
		return SADB_EALG_BLOWFISHCBC;
	case IPSECDOI_ESP_DES_IV32:	/* flags |= (SADB_X_EXT_OLD|
							SADB_X_EXT_IV4B)*/
		return SADB_EALG_DESCBC;
	case IPSECDOI_ESP_NULL:
		return SADB_EALG_NULL;

	/* not supported */
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		plog(logp, LOCATION, NULL,
			"Not supported transform: %u\n", t_id);
		return ~0;

	case 0: /* reserved */
	default:
		plog(logp, LOCATION, NULL,
			"Invalid transform id: %u\n", t_id);
		return ~0;
	}
	/*NOTREACHED*/
}

/* IPCOMP -> SADB_CALG */
static u_int
ipsecdoi2pfkey_calg(t_id)
	u_int t_id;
{
	switch (t_id) {
	case IPSECDOI_IPCOMP_OUI:
		return SADB_X_CALG_OUI;
	case IPSECDOI_IPCOMP_DEFLATE:
		return SADB_X_CALG_DEFLATE;
	case IPSECDOI_IPCOMP_LZS:
		return SADB_X_CALG_LZS;

	case 0: /* reserved */
	default:
		plog(logp, LOCATION, NULL,
			"Invalid transform id: %u\n", t_id);
		return ~0;
	}
	/*NOTREACHED*/
}

/* IPSECDOI_PROTO -> SADB_SATYPE */
u_int
ipsecdoi2pfkey_proto(proto)
	u_int proto;
{
	switch (proto) {
	case IPSECDOI_PROTO_IPSEC_AH:
		return SADB_SATYPE_AH;
	case IPSECDOI_PROTO_IPSEC_ESP:
		return SADB_SATYPE_ESP;
	case IPSECDOI_PROTO_IPCOMP:
		return SADB_X_SATYPE_IPCOMP;

	default:
		plog(logp, LOCATION, NULL,
			"Invalid ipsec_doi proto: %u\n", proto);
		return ~0;
	}
	/*NOTREACHED*/
}

/* SADB_SATYPE -> IPSECDOI_PROTO */
u_int
pfkey2ipsecdoi_proto(satype)
	u_int satype;
{
	switch (satype) {
	case SADB_SATYPE_AH:
		return IPSECDOI_PROTO_IPSEC_AH;
	case SADB_SATYPE_ESP:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case SADB_X_SATYPE_IPCOMP:
		return IPSECDOI_PROTO_IPCOMP;

	default:
		plog(logp, LOCATION, NULL,
			"Invalid pfkey proto: %u\n", satype);
		return ~0;
	}
	/*NOTREACHED*/
}

/* IPSECDOI_ATTR_ENC_MODE -> IPSEC_MODE */
u_int
ipsecdoi2pfkey_mode(mode)
	u_int mode;
{
	switch (mode) {
	case IPSECDOI_ATTR_ENC_MODE_TUNNEL:
		return IPSEC_MODE_TUNNEL;
	case IPSECDOI_ATTR_ENC_MODE_TRNS:
		return IPSEC_MODE_TRANSPORT;
	default:
		plog(logp, LOCATION, NULL, "Invalid mode type: %u\n", mode);
		return ~0;
	}
	/*NOTREACHED*/
}

/* IPSECDOI_ATTR_ENC_MODE -> IPSEC_MODE */
u_int
pfkey2ipsecdoi_mode(mode)
	u_int mode;
{
	switch (mode) {
	case IPSEC_MODE_TUNNEL:
		return IPSECDOI_ATTR_ENC_MODE_TUNNEL;
	case IPSEC_MODE_TRANSPORT:
		return IPSECDOI_ATTR_ENC_MODE_TRNS;
	default:
		plog(logp, LOCATION, NULL, "Invalid mode type: %u\n", mode);
		return ~0;
	}
	/*NOTREACHED*/
}

/* default key length for encryption algorithm */
static u_int
keylen_aalg(hashtype)
	u_int hashtype;
{
	switch (hashtype) {
	case IPSECDOI_ATTR_AUTH_HMAC_MD5:
		return 128;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
		return 160;
	case IPSECDOI_ATTR_AUTH_KPDK:		/* need special care */
		return 0;

	/* not supported */
	case IPSECDOI_ATTR_AUTH_DES_MAC:
		plog(logp, LOCATION, NULL,
			"Not supported hash type: %u\n", hashtype);
		return ~0;

	case 0: /* reserved */
	default:
		return SADB_AALG_NONE;

		plog(logp, LOCATION, NULL,
			"Invalid hash type: %u\n", hashtype);
		return ~0;
	}
	/*NOTREACHED*/
}

/* default key length for encryption algorithm */
static u_int
keylen_ealg(t_id, encklen)
	u_int t_id;
	int encklen;
{
	switch (t_id) {
	case IPSECDOI_ESP_DES_IV64:		/* sa_flags |= SADB_X_EXT_OLD */
		return 64;
	case IPSECDOI_ESP_DES:
		return 64;
	case IPSECDOI_ESP_3DES:
		return 192;
	case IPSECDOI_ESP_RC5:
		return encklen ? encklen : 128;
	case IPSECDOI_ESP_CAST:
		return encklen ? encklen : 128;
	case IPSECDOI_ESP_BLOWFISH:
		return encklen ? encklen : 128;
	case IPSECDOI_ESP_DES_IV32:	/* flags |= (SADB_X_EXT_OLD|
							SADB_X_EXT_IV4B)*/
		return 64;
	case IPSECDOI_ESP_NULL:
		return 0;

	/* not supported */
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		plog(logp, LOCATION, NULL,
			"Not supported transform: %u\n", t_id);
		return ~0;

	case 0: /* reserved */
	default:
		plog(logp, LOCATION, NULL,
			"Invalid transform id: %u\n", t_id);
		return ~0;
	}
	/*NOTREACHED*/
}

int
pfkey_convertfromipsecdoi(proto_id, t_id, hashtype,
		e_type, e_keylen, a_type, a_keylen, flags)
	u_int proto_id;
	u_int t_id;
	u_int hashtype;
	u_int *e_type;
	u_int *e_keylen;
	u_int *a_type;
	u_int *a_keylen;
	u_int *flags;
{
	*flags = 0;
	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		if ((*e_type = ipsecdoi2pfkey_ealg(t_id)) == ~0)
			goto bad;
		if ((*e_keylen = keylen_ealg(t_id, *e_keylen)) == ~0)
			goto bad;
		*e_keylen >>= 3;

		if ((*a_type = ipsecdoi2pfkey_aalg(hashtype)) == ~0)
			goto bad;
		if ((*a_keylen = keylen_aalg(hashtype)) == ~0)
			goto bad;
		*a_keylen >>= 3;

		if (*e_type == SADB_EALG_NONE) {
			plog(logp, LOCATION, NULL, "no ESP algorithm.\n");
			goto bad;
		}
		break;

	case IPSECDOI_PROTO_IPSEC_AH:
		if ((*a_type = ipsecdoi2pfkey_aalg(hashtype)) == ~0)
			goto bad;
		if ((*a_keylen = keylen_aalg(hashtype)) == ~0)
			goto bad;
		*a_keylen >>= 3;

		if (t_id == IPSECDOI_ATTR_AUTH_HMAC_MD5 
		 && hashtype == IPSECDOI_ATTR_AUTH_KPDK) {
			/* AH_MD5 + Auth(KPDK) = RFC1826 keyed-MD5 */
			*a_type = SADB_AALG_MD5;
			*flags |= SADB_X_EXT_OLD;
		}
		*e_type = SADB_EALG_NONE;
		*e_keylen = 0;
		if (*a_type == SADB_AALG_NONE) {
			plog(logp, LOCATION, NULL, "no AH algorithm.\n");
			goto bad;
		}
		break;

	case IPSECDOI_PROTO_IPCOMP:
		if ((*e_type = ipsecdoi2pfkey_calg(t_id)) == ~0)
			goto bad;
		*e_keylen = 0;

		*flags = SADB_X_EXT_RAWCPI;

		*a_type = SADB_AALG_NONE;
		*a_keylen = 0;
		if (*e_type == SADB_X_CALG_NONE) {
			plog(logp, LOCATION, NULL, "no IPCOMP algorithm.\n");
			goto bad;
		}
		break;

	default:
		plog(logp, LOCATION, NULL, "unknown IPsec protocol.\n");
		goto bad;
	}

	return 0;

    bad:
	errno = EINVAL;
	return -1;
}

/* called from scheduler */
void
pfkey_timeover(iph2)
	struct ph2handle *iph2;
{
	plog(logp, LOCATION, NULL,
		"%s give up to get IPsec-SA due to time up to wait.\n",
		saddrwop2str(iph2->dst));
	SCHED_INIT(iph2->sce);

	/* XXX do send error to kernel by SADB_ACQUIRE. */

	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);

	return;
}

/*%%%*/
/* send getspi message per ipsec protocol per remote address */
/*
 * the local address and remote address in ph1handle are dealed
 * with destination address and source address respectively.
 * Because SPI is decided by responder.
 */
int
pk_sendgetspi(iph2)
	struct ph2handle *iph2;
{
	u_int satype, mode;
	struct saprop *pp;
	struct saproto *pr;

	pp = iph2->side == INITIATOR
			? iph2->proposal
			: iph2->approval;

	for (pr = pp->head; pr != NULL; pr = pr->next) {

		/* validity check */
		satype = ipsecdoi2pfkey_proto(pr->proto_id);
		if (satype == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid encmode %d\n", pr->encmode);
			return -1;
		}

		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"call pfkey_send_getspi\n"););
		if (pfkey_send_getspi(
				lcconf->sock_pfkey,
				satype,
				mode,
				iph2->dst,		/* src of SA */
				iph2->src,		/* dst of SA */
				0, 0, 0, iph2->seq) < 0) {
			plog(logp, LOCATION, NULL,
				"ipseclib failed send getspi (%s)\n",
				ipsec_strerror());
			return -1;
		}
		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"send pfkey GETSPI for %s/%s/%s\n",
				s_ipsecdoi_proto(pr->proto_id),
				s_ipsecdoi_encmode(pr->encmode),
				saddrwop2str(iph2->dst)));
	}

	return 0;
}

/*
 * receive GETSPI from kernel.
 */
static int
pk_recvgetspi(mhp) 
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct ph2handle *iph2;
	struct sockaddr *dst;
	int proto_id;
	int allspiok, notfound;
	struct saprop *pp;
	struct saproto *pr;

	/* validity check */
	if (mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb getspi message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]); /* note SA dir */

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(logp, LOCATION, NULL,
			"seq %d of %s message not interesting.\n",
			msg->sadb_msg_seq,
			s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	if (iph2->status != PHASE2ST_GETSPISENT) {
		plog(logp, LOCATION, NULL,
			"status mismatch (db:%d msg:%d)\n",
			iph2->status, PHASE2ST_GETSPISENT);
		return -1;
	}

	/* set SPI, and check to get all spi whether or not */
	allspiok = 1;
	notfound = 1;
	proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
	pp = iph2->side == INITIATOR ? iph2->proposal : iph2->approval;

	for (pr = pp->head; pr != NULL; pr = pr->next) {
		if (pr->proto_id == proto_id && pr->spi == 0) {
			pr->spi = sa->sadb_sa_spi;
			notfound = 0;
			YIPSDEBUG(DEBUG_PFKEY,
				plog(logp, LOCATION, NULL,
					"get SPI %08x for %s %s\n",
					ntohl(sa->sadb_sa_spi),
					saddrwop2str(iph2->dst),
					s_ipsecdoi_proto(pr->proto_id)));
		}
		if (pr->spi == 0)
			allspiok = 0;	/* not get all spi */
	}

	if (notfound) {
		plog(logp, LOCATION, NULL,
			"get spi for unknown address %s\n",
			saddrwop2str(iph2->dst));
		return -1;
	}

	if (allspiok) {
		/* update status */
		iph2->status = PHASE2ST_GETSPIDONE;
		if (isakmp_post_getspi(iph2) < 0) {
			plog(logp, LOCATION, NULL,
				"failed to start post getspi.\n");
			unbindph12(iph2);
			remph2(iph2);
			delph2(iph2);
			iph2 = NULL;
			return -1;
		}
	}

	return 0;
}

int
pk_sendupdate(iph2)
	struct ph2handle *iph2;
{
	struct saproto *pr;
	int e_type, e_keylen, a_type, a_keylen, flags;
	u_int satype, mode;

	/* sanity check */
	if (iph2->approval == NULL) {
		plog(logp, LOCATION, NULL,
			"no approvaled SAs found.\n");
	}

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2pfkey_proto(pr->proto_id);
		if (satype == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid encmode %d\n", pr->encmode);
			return -1;
		}

		/* set algorithm type and key length */
		e_keylen = pr->head->encklen;
		if (pfkey_convertfromipsecdoi(
				pr->proto_id,
				pr->head->trns_id,
				pr->head->authtype,
				&e_type, &e_keylen,
				&a_type, &a_keylen, &flags) < 0)
			return -1;

		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"call pfkey_send_update\n"));

		if (pfkey_send_update(
				lcconf->sock_pfkey,
				satype,
				mode,
				iph2->dst,
				iph2->src,
				pr->spi,
				0,
				4,	/* XXX static size of window */
				pr->keymat->v,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, iph2->approval->lifebyte * 1024,
				iph2->approval->lifetime, 0,
				iph2->seq) < 0) {
			plog(logp, LOCATION, NULL,
				"libipsec failed send update (%s)\n",
				ipsec_strerror());
			return -1;
		}
	}

	return 0;
}

static int
pk_recvupdate(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2;
	u_int proto_id, encmode;
	int incomplete = 0;
	struct saproto *pr;

	/* ignore this message becauase of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb update message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(logp, LOCATION, NULL,
			"seq %d of %s message not interesting.\n",
			msg->sadb_msg_seq,
			s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	if (iph2->status != PHASE2ST_ADDSA) {
		plog(logp, LOCATION, NULL,
			"status mismatch (db:%d msg:%d)\n",
			iph2->status, PHASE2ST_ADDSA);
		return -1;
	}

	/* check to complete all keys ? */
	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
		if (proto_id == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid proto_id %d\n", msg->sadb_msg_satype);
			return -1;
		}
		encmode = pfkey2ipsecdoi_mode(msg->sadb_msg_mode);
		if (encmode == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid encmode %d\n", msg->sadb_msg_mode);
			return -1;
		}

		if (pr->proto_id == proto_id
		 && pr->spi == sa->sadb_sa_spi) {
			pr->ok = 1;
			YIPSDEBUG(DEBUG_MISC,
				char *xsrc = strdup(saddrwop2str(iph2->src));
				plog(logp, LOCATION, NULL,
					"pfkey %s success %s/%s/%s->%s\n",
					s_pfkey_type(msg->sadb_msg_type),
					s_ipsecdoi_proto(pr->proto_id),
					s_ipsecdoi_encmode(pr->encmode),
					xsrc,
					saddrwop2str(iph2->dst)));
		}

		if (pr->ok == 0)
			incomplete = 1;
	}

	if (incomplete)
		return 0;

	/* turn off schedule */
	if (iph2->sce == NULL) {
		plog(logp, LOCATION, NULL,
			"no buffer found as sendbuf\n"); 
		unbindph12(iph2);
		remph2(iph2);
		delph2(iph2);
		return -1;
	}
	SCHED_KILL(iph2->sce);
	
	/* update status */
	iph2->status = PHASE2ST_ESTABLISHED;

	iph2->sce = sched_new(iph2->approval->lifetime * 0.8,
				isakmp_ph2expire, iph2);

    {
	char *xsrc = strdup(saddrwop2str(iph2->src));
	plog(logp, LOCATION, NULL,
		"established IPsec-SAs for %s-%s\n",
		xsrc,
		saddrwop2str(iph2->dst));
	free(xsrc);
    }
	YIPSDEBUG(DEBUG_USEFUL, plog(logp, LOCATION, NULL, "===\n"));
	return 0;
}

int
pk_sendadd(iph2)
	struct ph2handle *iph2;
{
	struct saproto *pr;
	int e_type, e_keylen, a_type, a_keylen, flags;
	u_int satype, mode;

	/* sanity check */
	if (iph2->approval == NULL) {
		plog(logp, LOCATION, NULL,
			"no approvaled SAs found.\n");
	}

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2pfkey_proto(pr->proto_id);
		if (satype == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(logp, LOCATION, NULL,
				"invalid encmode %d\n", pr->encmode);
			return -1;
		}

		/* set algorithm type and key length */
		e_keylen = pr->head->encklen;
		if (pfkey_convertfromipsecdoi(
				pr->proto_id,
				pr->head->trns_id,
				pr->head->authtype,
				&e_type, &e_keylen,
				&a_type, &a_keylen, &flags) < 0)
			return -1;

		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"call pfkey_send_add(%u)\n"));

		if (pfkey_send_add(
				lcconf->sock_pfkey,
				satype,
				mode,
				iph2->src,
				iph2->dst,
				pr->spi_p,
				0,
				4,	/* XXX static size of window */
				pr->keymat_p->v,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, iph2->approval->lifebyte * 1024,
				iph2->approval->lifetime, 0,
				iph2->seq) < 0) {
			plog(logp, LOCATION, NULL,
				"libipsec failed send add (%s)\n", ipsec_strerror());
			return -1;
		}
	}

	return 0;
}

static int
pk_recvadd(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2;

	/* ignore this message becauase of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb add message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(logp, LOCATION, NULL,
			"seq %d of %s message not interesting.\n",
			msg->sadb_msg_seq,
			s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	/*
	 * NOTE don't update any status of phase2 handle
	 * because they must be updated by SADB_UPDATE message
	 */

    {
	char *xsrc = strdup(saddrwop2str(iph2->src));
	plog(logp, LOCATION, NULL,
		"pfkey %s success %s/%s/%s->%s\n",
		s_pfkey_type(msg->sadb_msg_type),
		s_pfkey_satype(msg->sadb_msg_satype),
		s_ipsecdoi_encmode(~msg->sadb_msg_mode & 3),
		xsrc,
		saddrwop2str(iph2->dst));
	free(xsrc);
    }
	YIPSDEBUG(DEBUG_USEFUL, plog(logp, LOCATION, NULL, "===\n"));
	return 0;
}

/* EXPIRE process will be done in isakmp_ph2expire(). */
static int
pk_recvexpire(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2;
	u_int proto_id;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || (mhp[SADB_EXT_LIFETIME_HARD] != NULL
	  && mhp[SADB_EXT_LIFETIME_SOFT] != NULL)) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb expire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
	if (proto_id == ~0) {
		plog(logp, LOCATION, NULL,
			"invalid proto_id %d\n", msg->sadb_msg_satype);
		return -1;
	}

	iph2 = getph2bysaidx(src, dst, proto_id, sa->sadb_sa_spi);
	if (iph2 == NULL) {
		char *xsrc = strdup(saddrwop2str(src));
		plog(logp, LOCATION, NULL,
			"no SA found %s/%s/%s->%s\n",
			s_pfkey_satype(msg->sadb_msg_satype),
			s_ipsecdoi_encmode(~msg->sadb_msg_mode & 3),
			xsrc,
			saddrwop2str(dst));
		free(xsrc);
		return -1;
	}

	/* iph2expire() checks it. */
	iph2->inuse = 2;

	return 0;
}

static int
pk_recvacquire(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_x_policy *xpl;
	struct policyindex spidxtmp;
	struct secpolicy *sp;
#ifdef YIPS_DEBUG
	char h1[NI_MAXHOST], h2[NI_MAXHOST];
	char s1[NI_MAXSERV], s2[NI_MAXSERV];
#ifdef NI_WITHSCOPEID
	const int niflags = NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID;
#else
	const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#endif
#endif
#define MAXNESTEDSA	5	/* XXX */
	struct ph2handle *iph2[MAXNESTEDSA];
	struct ipsecrequest *req;
	struct saprop *newpp = NULL;
	int n;	/* # of phase 2 handler */

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_EXT_IDENTITY_SRC] == NULL
	 || mhp[SADB_EXT_IDENTITY_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb acquire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	/* ignore if type is not IPSEC_POLICY_IPSEC */
	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"ignore SPDGET message. type is not IPsec.\n"));
		return 0;
	}

	/* check there is phase 2 handler ? */
	if (getph2byspid(xpl->sadb_x_policy_id) != NULL) {
		YIPSDEBUG(DEBUG_PFKEY,
			plog(logp, LOCATION, NULL,
				"ph2 found. ignore it.\n"));
		return -1;
	}

	/* set index of policyindex */
	if (pfkey_setspidxbymsg(mhp, &spidxtmp) < 0) {
		plog(logp, LOCATION, NULL,
			"failed to get policy index.\n");
		return -1;
	}

	/* search for proper policyindex */
	sp = getsp(&spidxtmp);
	if (sp == NULL) {
		plog(logp, LOCATION, NULL,
			"no policy found %s.\n", spidx2str(&spidxtmp));
		return -1;
	}
	YIPSDEBUG(DEBUG_PFKEY,
		plog(logp, LOCATION, NULL,
			"policy found: %s.\n", spidx2str(&spidxtmp)));

	memset(iph2, 0, MAXNESTEDSA);

	n = 0;

	/* allocate a phase 2 */
	iph2[n] = newph2();
	if (iph2[n] == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate phase2 entry.\n");
		return -1;
	}
	iph2[n]->spid = xpl->sadb_x_policy_id;
	iph2[n]->seq = msg->sadb_msg_seq;
	iph2[n]->status = PHASE2ST_STATUS2;

	/* set end addresses of SA */
	iph2[n]->dst = dupsaddr(PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]));
	if (iph2[n]->dst == NULL)
		return -1;
	iph2[n]->src = dupsaddr(PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]));
	if (iph2[n]->src == NULL)
		return -1;

	YIPSDEBUG(DEBUG_NOTIFY,
		h1[0] = s1[0] = h2[0] = s2[0] = '\0';
		getnameinfo(iph2[n]->src, iph2[n]->src->sa_len,
		    h1, sizeof(h1), s1, sizeof(s1), niflags);
		getnameinfo(iph2[n]->dst, iph2[n]->dst->sa_len,
		    h2, sizeof(h2), s2, sizeof(s2), niflags);
		plog(logp, LOCATION, NULL,
			"new acquire iph2 %p: src %s %s dst %s %s\n",
			iph2, h1, s1, h2, s2));

	/* get sainfo */
    {
	vchar_t *idsrc, *iddst;

	idsrc = ipsecdoi_sockaddr2id((struct sockaddr *)&sp->spidx.src,
				sp->spidx.prefs, sp->spidx.ul_proto);
	if (idsrc == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to get ID for %s\n",
			spidx2str(&sp->spidx));
		goto err;
	}
	iddst = ipsecdoi_sockaddr2id((struct sockaddr *)&sp->spidx.dst,
				sp->spidx.prefd, sp->spidx.ul_proto);
	if (iddst == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to get ID for %s\n",
			spidx2str(&sp->spidx));
		vfree(idsrc);
		goto err;
	}
	iph2[n]->sainfo = getsainfo(idsrc, iddst);
	vfree(idsrc);
	vfree(iddst);
	if (iph2[n]->sainfo == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to get sainfo.\n");
		goto err;
		/* XXX should use the algorithm list from register message */
	}
    }

	/* allocate first proposal */
	newpp = newsaprop();
	if (newpp == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate saprop.\n");
		goto err;
	}
	newpp->prop_no = 1;
	newpp->lifetime = iph2[n]->sainfo->lifetime;
	newpp->lifebyte = iph2[n]->sainfo->lifebyte;
	newpp->pfs_group = iph2[n]->sainfo->pfs_group;

	/* set new saprop */
	inssaprop(&iph2[n]->proposal, newpp);

	insph2(iph2[n]);

	for (req = sp->req; req; req = req->next) {
		struct saproto *newpr;
		struct sockaddr *psaddr = NULL;
		struct sockaddr *pdaddr = NULL;

		/* check if SA bundle ? */
		if (req->saidx.src.ss_len && req->saidx.dst.ss_len) {

			psaddr = (struct sockaddr *)&req->saidx.src;
			pdaddr = (struct sockaddr *)&req->saidx.dst;

			/* check end addresses of SA */
			if (memcmp(iph2[n]->src, psaddr, iph2[n]->src->sa_len)
			 || memcmp(iph2[n]->dst, pdaddr, iph2[n]->dst->sa_len)){
				/*
				 * XXX nested SAs with each destination
				 * address are different.
				 *       me +--- SA1 ---+ peer1
				 *       me +--- SA2 --------------+ peer2
				 */

				/* check first ph2's proposal */
				if (iph2[0]->proposal == NULL) {
					plog(logp, LOCATION, NULL,
						"SA addresses mismatch.\n");
					goto err;
				}

				/* XXX new ph2 should be alloated. */
				
				plog(logp, LOCATION, NULL,
					"not supported nested SA. Ignore.\n");
				break;
			}
		}

		/* allocate ipsec sa protocol */
		newpr = newsaproto();
		if (newpr == NULL) {
			plog(logp, LOCATION, NULL,
				"failed to allocate saproto.\n");
			goto err;
		}

		newpr->proto_id = ipproto2doi(req->saidx.proto);
		newpr->spisize = 4;
		newpr->encmode = pfkey2ipsecdoi_mode(req->saidx.mode);
		newpr->reqid = req->saidx.reqid;

		if (set_satrnsbysainfo(newpr, iph2[n]->sainfo) < 0)
			goto err;

		/* set new saproto */
		inssaproto(newpp, newpr);
	}

	/* start isakmp initiation by using ident exchange */
	/* XXX should be looped if there are multiple phase 2 handler. */
	if (isakmp_post_acquire(iph2[n]) < 0) {
		plog(logp, LOCATION, NULL,
			"failed to begin ipsec sa negotication.\n");
		unbindph12(iph2[n]);
		goto err;
	}

	return 0;

err:
	while (n >= 0) {
		remph2(iph2[n]);
		delph2(iph2[n]);
		iph2[n] = NULL;
		n--;
	}
	return -1;
}

static int
pk_recvdelete(mhp)
	caddr_t *mhp;
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb delete message passed.\n");
		return -1;
	}
	isakmp_info_send_d2_pf((struct sadb_msg *)mhp[0]);

	return 0;
}

static int
pk_recvspdupdate(mhp)
	caddr_t *mhp;
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spdupdate message passed.\n");
		return -1;
	}

	return 0;
}

static int
pk_recvspdadd(mhp)
	caddr_t *mhp;
{
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spdadd message passed.\n");
		return -1;
	}
	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			&spidx);

	sp = getsp(&spidx);
	if (sp != NULL) {
		plog(logp, LOCATION, NULL,
			"such policy already exists. "
			"anyway replace it: %s\n",
			spidx2str(&spidx));
		remsp(sp);
		delsp(sp);
	}

	if (addnewsp(mhp) < 0)
		return -1;

	return 0;
}

static int
pk_recvspddelete(mhp)
	caddr_t *mhp;
{
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spddelete message passed.\n");
		return -1;
	}
	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			&spidx);

	sp = getsp(&spidx);
	if (sp == NULL) {
		plog(logp, LOCATION, NULL,
			"no policy found: %s\n",
			spidx2str(&spidx));
		return -1;
	}

	remsp(sp);
	delsp(sp);

	return 0;
}

static int
pk_recvspdget(mhp)
	caddr_t *mhp;
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spdget message passed.\n");
		return -1;
	}

	return 0;
}

static int
pk_recvspddump(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;
	struct policyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp[0] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spddump message passed.\n");
		return -1;
	}

	for (msg = (struct sadb_msg *)mhp[0];
	     msg->sadb_msg_errno == 0;
	     msg = (struct sadb_msg *)((caddr_t)msg + PFKEY_EXTLEN(msg))) {

		saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
		daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
		xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

		KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
				saddr + 1,
				daddr + 1,
				saddr->sadb_address_prefixlen,
				daddr->sadb_address_prefixlen,
				saddr->sadb_address_proto,
				&spidx);

		sp = getsp(&spidx);
		if (sp != NULL) {
			plog(logp, LOCATION, NULL,
				"such policy already exists. "
				"anyway replace it: %s\n",
				spidx2str(&spidx));
			remsp(sp);
			delsp(sp);
		}

		if (addnewsp(mhp) < 0)
			return -1;

		/* last part ? */
		if (msg->sadb_msg_seq == 0)
			break;
	}

	return 0;
}

static int
pk_recvspdflush(mhp)
	caddr_t *mhp;
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spdflush message passed.\n");
		return -1;
	}

	flushsp();

	return 0;
}

/*
 * differences with pfkey_recv() in libipsec/pfkey.c:
 * - never performs busy wait loop.
 * - returns NULL and set *lenp to negative on fatal failures
 * - returns NULL and set *lenp to non-negative on non-fatal failures
 * - returns non-NULL on success
 */
static struct sadb_msg *
pk_recv(so, lenp)
	int so;
	int *lenp;
{
	struct sadb_msg buf, *newmsg;
	int reallen;

	*lenp = recv(so, (caddr_t)&buf, sizeof(buf), MSG_PEEK);
	if (*lenp < 0)
		return NULL;	/*fatal*/
	else if (*lenp < sizeof(buf))
		return NULL;

	reallen = PFKEY_UNUNIT64(buf.sadb_msg_len);
	if ((newmsg = CALLOC(reallen, struct sadb_msg *)) == NULL)
		return NULL;

	*lenp = recv(so, (caddr_t)newmsg, reallen, MSG_PEEK);
	if (*lenp < 0) {
		free(newmsg);
		return NULL;	/*fatal*/
	} else if (*lenp != reallen) {
		free(newmsg);
		return NULL;
	}

	*lenp = recv(so, (caddr_t)newmsg, reallen, 0);
	if (*lenp < 0) {
		free(newmsg);
		return NULL;	/*fatal*/
	} else if (*lenp != reallen) {
		free(newmsg);
		return NULL;
	}

	return newmsg;
}

/* see handler.h */
u_int32_t
pk_getseq()
{
	return (u_int32_t)random();
}

static int
addnewsp(mhp)
	caddr_t *mhp;
{
	struct secpolicy *new;
	struct sadb_address *saddr, *daddr;
	struct sadb_x_policy *xpl;

	/* sanity check */
	if (mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(logp, LOCATION, NULL,
			"inappropriate sadb spd management message passed.\n");
		return -1;
	}

	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	new = newsp();
	if (new == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate buffer\n");
		return -1;
	}

	new->spidx.dir = xpl->sadb_x_policy_dir;
	new->id = xpl->sadb_x_policy_id;
	new->policy = xpl->sadb_x_policy_type;

	/* check policy */
	switch (xpl->sadb_x_policy_type) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_NONE:
	case IPSEC_POLICY_ENTRUST:
	case IPSEC_POLICY_BYPASS:
		new->req = NULL;
		break;

	case IPSEC_POLICY_IPSEC:
	    {
		int tlen;
		struct sadb_x_ipsecrequest *xisr;
		struct ipsecrequest **p_isr = &new->req;

		/* validity check */
		if (PFKEY_EXTLEN(xpl) < sizeof(*xpl)) {
			plog(logp, LOCATION, NULL,
				"invalid msg length.\n");
			return -1;
		}

		tlen = PFKEY_EXTLEN(xpl) - sizeof(*xpl);
		xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);

		while (tlen > 0) {

			/* length check */
			if (xisr->sadb_x_ipsecrequest_len < sizeof(*xisr)) {
				plog(logp, LOCATION, NULL,
					"invalid msg length.\n");
				return -1;
			}

			/* allocate request buffer */
			*p_isr = newipsecreq();
			if (*p_isr == NULL) {
				plog(logp, LOCATION, NULL,
					"failed to get new ipsecreq.\n");
				return -1;
			}

			/* set values */
			(*p_isr)->next = NULL;

			switch (xisr->sadb_x_ipsecrequest_proto) {
			case IPPROTO_ESP:
			case IPPROTO_AH:
			case IPPROTO_IPCOMP:
				break;
			default:
				plog(logp, LOCATION, NULL,
					"invalid proto type: %u\n",
					xisr->sadb_x_ipsecrequest_proto);
				return -1;
			}
			(*p_isr)->saidx.proto = xisr->sadb_x_ipsecrequest_proto;

			switch (xisr->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
			case IPSEC_MODE_TUNNEL:
				break;
			case IPSEC_MODE_ANY:
			default:
				plog(logp, LOCATION, NULL,
					"invalid mode: %u\n",
					xisr->sadb_x_ipsecrequest_mode);
				return -1;
			}
			(*p_isr)->saidx.mode = xisr->sadb_x_ipsecrequest_mode;

			switch (xisr->sadb_x_ipsecrequest_level) {
			case IPSEC_LEVEL_DEFAULT:
			case IPSEC_LEVEL_USE:
			case IPSEC_LEVEL_REQUIRE:
				break;
			case IPSEC_LEVEL_UNIQUE:
				(*p_isr)->saidx.reqid =
					xisr->sadb_x_ipsecrequest_reqid;
				break;

			default:
				plog(logp, LOCATION, NULL,
					"invalid level: %u\n",
					xisr->sadb_x_ipsecrequest_level);
				return -1;
			}
			(*p_isr)->level = xisr->sadb_x_ipsecrequest_level;

			/* set IP addresses if there */
			if (xisr->sadb_x_ipsecrequest_len > sizeof(*xisr)) {
				struct sockaddr *paddr;

				paddr = (struct sockaddr *)(xisr + 1);
				bcopy(paddr, &(*p_isr)->saidx.src,
					paddr->sa_len);

				paddr = (struct sockaddr *)((caddr_t)paddr
							+ paddr->sa_len);
				bcopy(paddr, &(*p_isr)->saidx.dst,
					paddr->sa_len);
			}

			(*p_isr)->sp = new;

			/* initialization for the next. */
			p_isr = &(*p_isr)->next;
			tlen -= xisr->sadb_x_ipsecrequest_len;

			/* validity check */
			if (tlen < 0) {
				plog(logp, LOCATION, NULL,
					"becoming tlen < 0\n");
			}

			xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
			                 + xisr->sadb_x_ipsecrequest_len);
		}
	    }
		break;
	default:
		plog(logp, LOCATION, NULL,
			"invalid policy type.\n");
		return -1;
	}

	KEY_SETSECSPIDX(xpl->sadb_x_policy_dir,
			saddr + 1,
			daddr + 1,
			saddr->sadb_address_prefixlen,
			daddr->sadb_address_prefixlen,
			saddr->sadb_address_proto,
			&new->spidx);

	inssp(new);

	return 0;
}

