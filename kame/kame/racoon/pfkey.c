/*	$KAME: pfkey.c,v 1.107 2001/03/16 04:12:09 sakane Exp $	*/

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

#include "libpfkey.h"

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"
#include "remoteconf.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "isakmp_inf.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "pfkey.h"
#include "handler.h"
#include "policy.h"
#include "algorithm.h"
#include "sainfo.h"
#include "proposal.h"
#include "admin.h"
#include "strnames.h"
#include "backupsa.h"

/* prototype */
static u_int ipsecdoi2pfkey_aalg __P((u_int));
static u_int ipsecdoi2pfkey_ealg __P((u_int));
static u_int ipsecdoi2pfkey_calg __P((u_int));
static u_int ipsecdoi2pfkey_alg __P((u_int, u_int));
static u_int keylen_aalg __P((u_int));
static u_int keylen_ealg __P((u_int, int));

static int pk_recvgetspi __P((caddr_t *));
static int pk_recvupdate __P((caddr_t *));
static int pk_recvadd __P((caddr_t *));
static int pk_recvdelete __P((caddr_t *));
static int pk_recvacquire __P((caddr_t *));
static int pk_recvexpire __P((caddr_t *));
static int pk_recvflush __P((caddr_t *));
static int pk_recvspdupdate __P((caddr_t *));
static int pk_recvspdadd __P((caddr_t *));
static int pk_recvspddelete __P((caddr_t *));
static int pk_recvspdget __P((caddr_t *));
static int pk_recvspddump __P((caddr_t *));
static int pk_recvspdflush __P((caddr_t *));
static struct sadb_msg *pk_recv __P((int, int *));

static int (*pkrecvf[]) __P((caddr_t *)) = {
NULL,
pk_recvgetspi,
pk_recvupdate,
pk_recvadd,
pk_recvdelete,
NULL,	/* SADB_GET */
pk_recvacquire,
NULL,	/* SABD_REGISTER */
pk_recvexpire,
pk_recvflush,
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

static int addnewsp __P((caddr_t *));
static const char *sadbsecas2str __P((struct sockaddr *, struct sockaddr *,
	int, u_int32_t, int));

/* cope with old kame headers - ugly */
#ifndef SADB_X_AALG_MD5
#define SADB_X_AALG_MD5		SADB_AALG_MD5	
#endif
#ifndef SADB_X_AALG_SHA
#define SADB_X_AALG_SHA		SADB_AALG_SHA
#endif
#ifndef SADB_X_AALG_NULL
#define SADB_X_AALG_NULL	SADB_AALG_NULL
#endif

#ifndef SADB_X_EALG_BLOWFISHCBC
#define SADB_X_EALG_BLOWFISHCBC	SADB_EALG_BLOWFISHCBC
#endif
#ifndef SADB_X_EALG_CAST128CBC
#define SADB_X_EALG_CAST128CBC	SADB_EALG_CAST128CBC
#endif
#ifndef SADB_X_EALG_RC5CBC
#ifdef SADB_EALG_RC5CBC
#define SADB_X_EALG_RC5CBC	SADB_EALG_RC5CBC
#endif
#endif

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
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to recv from pfkey (%s)\n",
				strerror(errno));
			goto end;
		} else {
			/* short message - msg not ready */
			return 0;
		}
	}

	plog(LLV_DEBUG, LOCATION, NULL, "get pfkey %s message\n",
		s_pfkey_type(msg->sadb_msg_type));
	plogdump(LLV_DEBUG, msg, msg->sadb_msg_len << 3);

	/* is it mine ? */
	/* XXX should be handled all message in spite of mine */
	if ((msg->sadb_msg_type == SADB_DELETE && msg->sadb_msg_pid == getpid())
	 && (msg->sadb_msg_pid != 0 && msg->sadb_msg_pid != getpid())) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"pfkey message pid %d not interesting.\n",
			msg->sadb_msg_pid);
		goto end;
	}

	/* validity check */
	if (msg->sadb_msg_errno) {
		int pri;

		/* when SPD is empty, treat the state as no error. */
		if (msg->sadb_msg_type == SADB_X_SPDDUMP &&
		    msg->sadb_msg_errno == ENOENT)
			pri = LLV_DEBUG;
		else
			pri = LLV_ERROR;

		plog(pri, LOCATION, NULL,
			"pfkey %s failed: %s\n",
			s_pfkey_type(msg->sadb_msg_type),
			strerror(msg->sadb_msg_errno));

		goto end;
	}

	/* check pfkey message. */
	if (pfkey_align(msg, mhp)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec failed pfkey align (%s)\n",
			ipsec_strerror());
		goto end;
	}
	if (pfkey_check(mhp)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec failed pfkey check (%s)\n",
			ipsec_strerror());
		goto end;
	}
	msg = (struct sadb_msg *)mhp[0];

	if (pkrecvf[msg->sadb_msg_type] == NULL) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"not supported command %s\n",
			s_pfkey_type(msg->sadb_msg_type));
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
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec failed pfkey open: %s\n",
			ipsec_strerror());
		return NULL;
	}

	plog(LLV_DEBUG, LOCATION, NULL, "call pfkey_send_dump\n");
	if (pfkey_send_dump(s, satype) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec failed dump: %s\n", ipsec_strerror());
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
			plog(LLV_ERROR, LOCATION, NULL,
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

	plog(LLV_DEBUG, LOCATION, NULL, "call pfkey_send_flush\n");
	if (pfkey_send_flush(lcconf->sock_pfkey, satype) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec failed send flush (%s)\n", ipsec_strerror());
		return;
	}

	return;
}

/*
 * These are the SATYPEs that we manage.  We register to get
 * PF_KEY messages related to these SATYPEs, and we also use
 * this list to determine which SATYPEs to delete SAs for when
 * we receive an INITIAL-CONTACT.
 */
const struct pfkey_satype pfkey_satypes[] = {
	{ SADB_SATYPE_AH,	"AH" },
	{ SADB_SATYPE_ESP,	"ESP" },
	{ SADB_X_SATYPE_IPCOMP,	"IPCOMP" },
};
const int pfkey_nsatypes =
    sizeof(pfkey_satypes) / sizeof(pfkey_satypes[0]);

/*
 * PF_KEY initialization
 */
int
pfkey_init()
{
	int i, reg_fail;

	if ((lcconf->sock_pfkey = pfkey_open()) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec failed pfkey open (%s)", ipsec_strerror());
		return -1;
	}

	for (i = 0, reg_fail = 0; i < pfkey_nsatypes; i++) {
		plog(LLV_DEBUG, LOCATION, NULL,
		    "call pfkey_send_register for %s\n",
		    pfkey_satypes[i].ps_name);
		if (pfkey_send_register(lcconf->sock_pfkey,
					pfkey_satypes[i].ps_satype) < 0 ||
		    pfkey_recv_register(lcconf->sock_pfkey) < 0) {
			plog(LLV_WARNING, LOCATION, NULL,
			    "failed to register %s (%s)",
			    pfkey_satypes[i].ps_name,
			    ipsec_strerror());
			reg_fail++;
		}
	}

	if (reg_fail == pfkey_nsatypes) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to regist any protocol.");
		pfkey_close(lcconf->sock_pfkey);
		return -1;
	}

	initsp();

	if (pfkey_send_spddump(lcconf->sock_pfkey) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"libipsec sending spddump failed: %s",
			ipsec_strerror());
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
		plog(LLV_ERROR, LOCATION, NULL,
			"Not supported hash type: %u\n", hashtype);
		return ~0;

	case 0: /* reserved */
	default:
		return SADB_AALG_NONE;

		plog(LLV_ERROR, LOCATION, NULL,
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
#ifdef SADB_X_EALG_RC5CBC
	case IPSECDOI_ESP_RC5:
		return SADB_X_EALG_RC5CBC;
#endif
	case IPSECDOI_ESP_CAST:
		return SADB_X_EALG_CAST128CBC;
	case IPSECDOI_ESP_BLOWFISH:
		return SADB_X_EALG_BLOWFISHCBC;
	case IPSECDOI_ESP_DES_IV32:	/* flags |= (SADB_X_EXT_OLD|
							SADB_X_EXT_IV4B)*/
		return SADB_EALG_DESCBC;
	case IPSECDOI_ESP_NULL:
		return SADB_EALG_NULL;
#ifdef SADB_X_EALG_RIJNDAELCBC
	case IPSECDOI_ESP_RIJNDAEL:
		return SADB_X_EALG_RIJNDAELCBC;
#endif
#ifdef SADB_X_EALG_TWOFISHCBC
	case IPSECDOI_ESP_TWOFISH:
		return SADB_X_EALG_TWOFISHCBC;
#endif

	/* not supported */
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		plog(LLV_ERROR, LOCATION, NULL,
			"Not supported transform: %u\n", t_id);
		return ~0;

	case 0: /* reserved */
	default:
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
			"Invalid ipsec_doi proto: %u\n", proto);
		return ~0;
	}
	/*NOTREACHED*/
}

static u_int
ipsecdoi2pfkey_alg(algclass, type)
	u_int algclass, type;
{
	switch (algclass) {
	case IPSECDOI_ATTR_AUTH:
		return ipsecdoi2pfkey_aalg(type);
	case IPSECDOI_PROTO_IPSEC_ESP:
		return ipsecdoi2pfkey_ealg(type);
	case IPSECDOI_PROTO_IPCOMP:
		return ipsecdoi2pfkey_calg(type);
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"Invalid ipsec_doi algclass: %u\n", algclass);
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL, "Invalid mode type: %u\n", mode);
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
	case IPSEC_MODE_ANY:
		return IPSECDOI_ATTR_ENC_MODE_ANY;
	default:
		plog(LLV_ERROR, LOCATION, NULL, "Invalid mode type: %u\n", mode);
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
		plog(LLV_ERROR, LOCATION, NULL,
			"Not supported hash type: %u\n", hashtype);
		return ~0;

	case 0: /* reserved */
	default:
		return SADB_AALG_NONE;

		plog(LLV_ERROR, LOCATION, NULL,
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
	case IPSECDOI_ESP_RIJNDAEL:
		return encklen ? encklen : 128;
	case IPSECDOI_ESP_TWOFISH:
		return encklen ? encklen : 128;

	/* not supported */
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		plog(LLV_ERROR, LOCATION, NULL,
			"Not supported transform: %u\n", t_id);
		return ~0;

	case 0: /* reserved */
	default:
		plog(LLV_ERROR, LOCATION, NULL,
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
			plog(LLV_ERROR, LOCATION, NULL, "no ESP algorithm.\n");
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
			*a_type = SADB_X_AALG_MD5;
			*flags |= SADB_X_EXT_OLD;
		}
		*e_type = SADB_EALG_NONE;
		*e_keylen = 0;
		if (*a_type == SADB_AALG_NONE) {
			plog(LLV_ERROR, LOCATION, NULL, "no AH algorithm.\n");
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
			plog(LLV_ERROR, LOCATION, NULL, "no IPCOMP algorithm.\n");
			goto bad;
		}
		break;

	default:
		plog(LLV_ERROR, LOCATION, NULL, "unknown IPsec protocol.\n");
		goto bad;
	}

	return 0;

    bad:
	errno = EINVAL;
	return -1;
}

/* called from scheduler */
void
pfkey_timeover_stub(p)
	void *p;
{

	pfkey_timeover((struct ph2handle *)p);
}

void
pfkey_timeover(iph2)
	struct ph2handle *iph2;
{
	plog(LLV_ERROR, LOCATION, NULL,
		"%s give up to get IPsec-SA due to time up to wait.\n",
		saddrwop2str(iph2->dst));
	SCHED_INIT(iph2->sce);

	/* If initiator side, send error to kernel by SADB_ACQUIRE. */
	if (iph2->side == INITIATOR)
		pk_sendeacquire(iph2);

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
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid encmode %d\n", pr->encmode);
			return -1;
		}

		plog(LLV_DEBUG, LOCATION, NULL, "call pfkey_send_getspi\n");
		if (pfkey_send_getspi(
				lcconf->sock_pfkey,
				satype,
				mode,
				iph2->dst,		/* src of SA */
				iph2->src,		/* dst of SA */
				0, 0, pr->reqid_in, iph2->seq) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"ipseclib failed send getspi (%s)\n",
				ipsec_strerror());
			return -1;
		}
		plog(LLV_DEBUG, LOCATION, NULL,
			"pfkey GETSPI sent: %s\n",
			sadbsecas2str(iph2->dst, iph2->src, satype, 0, mode));
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
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb getspi message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]); /* note SA dir */

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"seq %d of %s message not interesting.\n",
			msg->sadb_msg_seq,
			s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	if (iph2->status != PHASE2ST_GETSPISENT) {
		plog(LLV_ERROR, LOCATION, NULL,
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
			plog(LLV_DEBUG, LOCATION, NULL,
				"pfkey GETSPI succeeded: %s\n",
				sadbsecas2str(iph2->dst, iph2->src,
				    msg->sadb_msg_satype,
				    sa->sadb_sa_spi,
				    ipsecdoi2pfkey_mode(pr->encmode)));
		}
		if (pr->spi == 0)
			allspiok = 0;	/* not get all spi */
	}

	if (notfound) {
		plog(LLV_ERROR, LOCATION, NULL,
			"get spi for unknown address %s\n",
			saddrwop2str(iph2->dst));
		return -1;
	}

	if (allspiok) {
		/* update status */
		iph2->status = PHASE2ST_GETSPIDONE;
		if (isakmp_post_getspi(iph2) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
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

/*
 * set inbound SA
 */
int
pk_sendupdate(iph2)
	struct ph2handle *iph2;
{
	struct saproto *pr;
	struct sockaddr *src = NULL, *dst = NULL;
	int e_type, e_keylen, a_type, a_keylen, flags;
	u_int satype, mode;

	/* sanity check */
	if (iph2->approval == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"no approvaled SAs found.\n");
	}

	/* for mobile IPv6 */
	if (iph2->ph1->rmconf->support_mip6 && iph2->src_id && iph2->dst_id) {
		src = iph2->src_id;
		dst = iph2->dst_id;
	} else {
		src = iph2->src;
		dst = iph2->dst;
	}

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2pfkey_proto(pr->proto_id);
		if (satype == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
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

		plog(LLV_DEBUG, LOCATION, NULL, "call pfkey_send_update\n");

		if (pfkey_send_update(
				lcconf->sock_pfkey,
				satype,
				mode,
				iph2->dst,
				iph2->src,
				pr->spi,
				pr->reqid_in,
				4,	/* XXX static size of window */
				pr->keymat->v,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, iph2->approval->lifebyte * 1024,
				iph2->approval->lifetime, 0,
				iph2->seq) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"libipsec failed send update (%s)\n",
				ipsec_strerror());
			return -1;
		}

		if (!lcconf->pathinfo[LC_PATHTYPE_BACKUPSA])
			continue;

		/*
		 * It maybe good idea to call backupsa_to_file() after
		 * racoon will receive the sadb_update messages.
		 * But it is impossible because there is not key in the
		 * information from the kernel.
		 */
		if (backupsa_to_file(satype, mode, iph2->dst, iph2->src,
				pr->spi, pr->reqid_in, 4,
				pr->keymat->v,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, iph2->approval->lifebyte * 1024,
				iph2->approval->lifetime, 0,
				iph2->seq) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"backuped SA failed: %s\n",
				sadbsecas2str(iph2->dst, iph2->src,
				satype, pr->spi, mode));
		}
		plog(LLV_DEBUG, LOCATION, NULL,
			"backuped SA: %s\n",
			sadbsecas2str(iph2->dst, iph2->src,
			satype, pr->spi, mode));
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
	u_int proto_id, encmode, sa_mode;
	int incomplete = 0;
	struct saproto *pr;

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb update message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];

	sa_mode = mhp[SADB_X_EXT_SA2] == NULL
		? IPSEC_MODE_ANY
		: ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"seq %d of %s message not interesting.\n",
			msg->sadb_msg_seq,
			s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	if (iph2->status != PHASE2ST_ADDSA) {
		plog(LLV_ERROR, LOCATION, NULL,
			"status mismatch (db:%d msg:%d)\n",
			iph2->status, PHASE2ST_ADDSA);
		return -1;
	}

	/* check to complete all keys ? */
	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
		if (proto_id == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid proto_id %d\n", msg->sadb_msg_satype);
			return -1;
		}
		encmode = pfkey2ipsecdoi_mode(sa_mode);
		if (encmode == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid encmode %d\n", sa_mode);
			return -1;
		}

		if (pr->proto_id == proto_id
		 && pr->spi == sa->sadb_sa_spi) {
			pr->ok = 1;
			plog(LLV_DEBUG, LOCATION, NULL,
				"pfkey UPDATE succeeded: %s\n",
				sadbsecas2str(iph2->dst, iph2->src,
				    msg->sadb_msg_satype,
				    sa->sadb_sa_spi,
				    sa_mode));

			plog(LLV_INFO, LOCATION, NULL,
				"IPsec-SA established: %s\n",
				sadbsecas2str(iph2->dst, iph2->src,
					msg->sadb_msg_satype, sa->sadb_sa_spi,
					sa_mode));
		}

		if (pr->ok == 0)
			incomplete = 1;
	}

	if (incomplete)
		return 0;

	/* turn off the timer for calling pfkey_timeover() */
	SCHED_KILL(iph2->sce);
	
	/* update status */
	iph2->status = PHASE2ST_ESTABLISHED;

	/* count up */
	iph2->ph1->ph2cnt++;

	/*
	 * since we are going to reuse the phase2 handler, we need to
	 * remain it and refresh all the references between ph1 and ph2 to use.
	 */
	unbindph12(iph2);

	iph2->sce = sched_new(iph2->approval->lifetime,
	    isakmp_ph2expire_stub, iph2);

	plog(LLV_DEBUG, LOCATION, NULL, "===\n");
	return 0;
}

/*
 * set outbound SA
 */
int
pk_sendadd(iph2)
	struct ph2handle *iph2;
{
	struct saproto *pr;
	struct sockaddr *src = NULL, *dst = NULL;
	int e_type, e_keylen, a_type, a_keylen, flags;
	u_int satype, mode;

	/* sanity check */
	if (iph2->approval == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"no approvaled SAs found.\n");
	}

	/* for mobile IPv6 */
	if (iph2->ph1->rmconf->support_mip6 && iph2->src_id && iph2->dst_id) {
		src = iph2->src_id;
		dst = iph2->dst_id;
	} else {
		src = iph2->src;
		dst = iph2->dst;
	}

	for (pr = iph2->approval->head; pr != NULL; pr = pr->next) {
		/* validity check */
		satype = ipsecdoi2pfkey_proto(pr->proto_id);
		if (satype == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid proto_id %d\n", pr->proto_id);
			return -1;
		}
		mode = ipsecdoi2pfkey_mode(pr->encmode);
		if (mode == ~0) {
			plog(LLV_ERROR, LOCATION, NULL,
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

		plog(LLV_DEBUG, LOCATION, NULL, "call pfkey_send_add\n");

		if (pfkey_send_add(
				lcconf->sock_pfkey,
				satype,
				mode,
				iph2->src,
				iph2->dst,
				pr->spi_p,
				pr->reqid_out,
				4,	/* XXX static size of window */
				pr->keymat_p->v,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, iph2->approval->lifebyte * 1024,
				iph2->approval->lifetime, 0,
				iph2->seq) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"libipsec failed send add (%s)\n",
				ipsec_strerror());
			return -1;
		}

		if (!lcconf->pathinfo[LC_PATHTYPE_BACKUPSA])
			continue;

		/*
		 * It maybe good idea to call backupsa_to_file() after
		 * racoon will receive the sadb_update messages.
		 * But it is impossible because there is not key in the
		 * information from the kernel.
		 */
		if (backupsa_to_file(satype, mode, iph2->src, iph2->dst,
				pr->spi_p, pr->reqid_out, 4,
				pr->keymat_p->v,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, iph2->approval->lifebyte * 1024,
				iph2->approval->lifetime, 0,
				iph2->seq) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"backuped SA failed: %s\n",
				sadbsecas2str(iph2->src, iph2->dst,
				satype, pr->spi_p, mode));
		}
		plog(LLV_DEBUG, LOCATION, NULL,
			"backuped SA: %s\n",
			sadbsecas2str(iph2->src, iph2->dst,
			satype, pr->spi_p, mode));
	}

	return 0;
}

static int
pk_recvadd(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2;
	u_int sa_mode;

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb add message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];

	sa_mode = mhp[SADB_X_EXT_SA2] == NULL
		? IPSEC_MODE_ANY
		: ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;

	iph2 = getph2byseq(msg->sadb_msg_seq);
	if (iph2 == NULL) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"seq %d of %s message not interesting.\n",
			msg->sadb_msg_seq,
			s_pfkey_type(msg->sadb_msg_type));
		return -1;
	}

	/*
	 * NOTE don't update any status of phase2 handle
	 * because they must be updated by SADB_UPDATE message
	 */

	plog(LLV_INFO, LOCATION, NULL,
		"IPsec-SA established: %s\n",
		sadbsecas2str(iph2->src, iph2->dst,
			msg->sadb_msg_satype, sa->sadb_sa_spi, sa_mode));

	plog(LLV_DEBUG, LOCATION, NULL, "===\n");
	return 0;
}

static int
pk_recvexpire(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2;
	u_int proto_id, sa_mode;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || (mhp[SADB_EXT_LIFETIME_HARD] != NULL
	  && mhp[SADB_EXT_LIFETIME_SOFT] != NULL)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb expire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	sa_mode = mhp[SADB_X_EXT_SA2] == NULL
		? IPSEC_MODE_ANY
		: ((struct sadb_x_sa2 *)mhp[SADB_X_EXT_SA2])->sadb_x_sa2_mode;


	proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
	if (proto_id == ~0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid proto_id %d\n", msg->sadb_msg_satype);
		return -1;
	}

	plog(LLV_INFO, LOCATION, NULL,
		"IPsec-SA expired: %s\n",
		sadbsecas2str(src, dst,
			msg->sadb_msg_satype, sa->sadb_sa_spi, sa_mode));

	iph2 = getph2bysaidx(src, dst, proto_id, sa->sadb_sa_spi);
	if (iph2 == NULL) {
		/*
		 * Ignore it because two expire messages are come up.
		 * phase2 handler has been deleted already when 2nd message
		 * is received.
		 */
		plog(LLV_DEBUG, LOCATION, NULL,
			"no such a SA found: %s\n",
			sadbsecas2str(src, dst,
			    msg->sadb_msg_satype, sa->sadb_sa_spi,
			    sa_mode));
		return 0;
	}
	if (iph2->status != PHASE2ST_ESTABLISHED) {
		/*
		 * If the status is not equal to PHASE2ST_ESTABLISHED,
		 * racoon ignores this expire message.  There are two reason.
		 * One is that the phase 2 probably starts becuase there is
		 * a potential that racoon receives the acquire message
		 * without receiving a expire message.  Another is that racoon
		 * may receive the multiple expire messages from the kernel.
		 */
		plog(LLV_WARNING, LOCATION, NULL,
			"the expire message is received "
			"but the handler has not been established.\n");
		return 0;
	}

	/* turn off the timer for calling isakmp_ph2expire() */ 
	SCHED_KILL(iph2->sce);

	iph2->status = PHASE2ST_EXPIRED;

	/* INITIATOR, begin phase 2 exchange. */
	/* allocate buffer for status management of pfkey message */
	if (iph2->side == INITIATOR) {

		initph2(iph2);

		/* update status for re-use */
		iph2->status = PHASE2ST_STATUS2;

		/* start isakmp initiation by using ident exchange */
		if (isakmp_post_acquire(iph2) < 0) {
			plog(LLV_ERROR, LOCATION, iph2->dst,
				"failed to begin ipsec sa "
				"re-negotication.\n");
			unbindph12(iph2);
			remph2(iph2);
			delph2(iph2);
			return -1;
		}

		return 0;
		/*NOTREACHED*/
	}

	/* If not received SADB_EXPIRE, INITIATOR delete ph2handle. */
	/* RESPONDER always delete ph2handle, keep silent.  RESPONDER doesn't
	 * manage IPsec SA, so delete the list */
	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);

	return 0;
}

static int
pk_recvacquire(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg;
	struct sadb_x_policy *xpl;
	struct secpolicy *sp_out = NULL, *sp_in = NULL;
#define MAXNESTEDSA	5	/* XXX */
	struct ph2handle *iph2[MAXNESTEDSA];
	int n;	/* # of phase 2 handler */

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb acquire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	/* ignore if type is not IPSEC_POLICY_IPSEC */
	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"ignore SPDGET message. type is not IPsec.\n");
		return 0;
	}

	/* ignore it if src is multicast address */
    {
	struct sockaddr *sa = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	if ((sa->sa_family == AF_INET
	  && IN_MULTICAST(ntohl(((struct sockaddr_in *)sa)->sin_addr.s_addr)))
#ifdef INET6
	 || (sa->sa_family == AF_INET6
	  && IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)sa)->sin6_addr))
#endif
	) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"ignore due to multicast address: %s.\n",
			saddrwop2str(sa));
		return 0;
	}
    }

	/*
	 * If there is a phase 2 handler against the policy identifier in
	 * the acquire message, and if
	 *    1. its state is less than PHASE2ST_ESTABLISHED, then racoon
	 *       should ignore such a acquire message becuase the phase 2
	 *       is just negotiating.
	 *    2. its state is equal to PHASE2ST_ESTABLISHED, then racoon
	 *       has to prcesss such a acquire message becuase racoon may
	 *       lost the expire message.
	 */
	iph2[0] = getph2byspid(xpl->sadb_x_policy_id);
	if (iph2[0] != NULL) {
		if (iph2[0]->status < PHASE2ST_ESTABLISHED) {
			plog(LLV_DEBUG, LOCATION, NULL,
				"ignore the acquire becuase ph2 found\n");
			return -1;
		}
		if (iph2[0]->status == PHASE2ST_EXPIRED)
			iph2[0] = NULL;
		/*FALLTHROUGH*/
	}

	/* search for proper policyindex */
	sp_out = getspbyspid(xpl->sadb_x_policy_id);
	if (sp_out == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "no policy found: id:%d.\n",
			xpl->sadb_x_policy_id);
		return -1;
	}

	/* get inbound policy */
    {
	struct policyindex spidx;

	spidx.dir = IPSEC_DIR_INBOUND;
	memcpy(&spidx.src, &sp_out->spidx.dst, sizeof(spidx.src));
	memcpy(&spidx.dst, &sp_out->spidx.src, sizeof(spidx.dst));
	spidx.prefs = sp_out->spidx.prefd;
	spidx.prefd = sp_out->spidx.prefs;
	spidx.ul_proto = sp_out->spidx.ul_proto;

	sp_in = getsp_r(&spidx);
	if (!sp_in) {
		plog(LLV_WARNING, LOCATION, NULL,
			"no in-bound policy found: %s\n",
			spidx2str(&spidx));
	}
    }

	plog(LLV_DEBUG, LOCATION, NULL,
		"suitable SP found: %s.\n", spidx2str(&sp_out->spidx));

	memset(iph2, 0, MAXNESTEDSA);

	n = 0;

	/* allocate a phase 2 */
	iph2[n] = newph2();
	if (iph2[n] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate phase2 entry.\n");
		return -1;
	}
	iph2[n]->side = INITIATOR;
	iph2[n]->spid = xpl->sadb_x_policy_id;
	iph2[n]->satype = msg->sadb_msg_satype;
	iph2[n]->seq = msg->sadb_msg_seq;
	iph2[n]->status = PHASE2ST_STATUS2;

	/* set end addresses of SA */
	iph2[n]->dst = dupsaddr(PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]));
	if (iph2[n]->dst == NULL) {
		delph2(iph2[n]);
		return -1;
	}
	iph2[n]->src = dupsaddr(PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]));
	if (iph2[n]->src == NULL) {
		delph2(iph2[n]);
		return -1;
	}

	plog(LLV_DEBUG, LOCATION, NULL,
		"new acquire %s\n", spidx2str(&sp_out->spidx));

	/* get sainfo */
    {
	vchar_t *idsrc, *iddst;

	idsrc = ipsecdoi_sockaddr2id((struct sockaddr *)&sp_out->spidx.src,
				sp_out->spidx.prefs, sp_out->spidx.ul_proto);
	if (idsrc == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get ID for %s\n",
			spidx2str(&sp_out->spidx));
		delph2(iph2[n]);
		return -1;
	}
	iddst = ipsecdoi_sockaddr2id((struct sockaddr *)&sp_out->spidx.dst,
				sp_out->spidx.prefd, sp_out->spidx.ul_proto);
	if (iddst == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get ID for %s\n",
			spidx2str(&sp_out->spidx));
		vfree(idsrc);
		delph2(iph2[n]);
		return -1;
	}
	iph2[n]->sainfo = getsainfo(idsrc, iddst);
	vfree(idsrc);
	vfree(iddst);
	if (iph2[n]->sainfo == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get sainfo.\n");
		delph2(iph2[n]);
		return -1;
		/* XXX should use the algorithm list from register message */
	}
    }

	if (set_proposal_from_policy(iph2[n], sp_in, sp_out) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to create saprop.\n");
		delph2(iph2[n]);
		return -1;
	}
	insph2(iph2[n]);

	/* start isakmp initiation by using ident exchange */
	/* XXX should be looped if there are multiple phase 2 handler. */
	if (isakmp_post_acquire(iph2[n]) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to begin ipsec sa negotication.\n");
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
	struct sadb_msg *msg;
	struct sadb_sa *sa;
	struct sockaddr *src, *dst;
	struct ph2handle *iph2 = NULL;
	u_int proto_id;

	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb acquire message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];
	sa = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
	dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);

	proto_id = pfkey2ipsecdoi_proto(msg->sadb_msg_satype);
	if (proto_id == ~0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid proto_id %d\n", msg->sadb_msg_satype);
		return -1;
	}

	iph2 = getph2bysaidx(src, dst, proto_id, sa->sadb_sa_spi);
	if (iph2 == NULL) {
		/* ignore */
		plog(LLV_ERROR, LOCATION, NULL,
			"no iph2 found: %s\n",
			sadbsecas2str(src, dst, msg->sadb_msg_satype,
				sa->sadb_sa_spi, IPSEC_MODE_ANY));
		return 0;
	}

	plog(LLV_ERROR, LOCATION, NULL,
		"pfkey DELETE received: %s\n",
		sadbsecas2str(iph2->src, iph2->dst,
			msg->sadb_msg_satype, sa->sadb_sa_spi, IPSEC_MODE_ANY));

	/* send delete information */
	if (iph2->status == PHASE2ST_ESTABLISHED)
		isakmp_info_send_d2(iph2);

	unbindph12(iph2);
	remph2(iph2);
	delph2(iph2);

	return 0;
}

static int
pk_recvflush(mhp)
	caddr_t *mhp;
{
	/* ignore this message because of local test mode. */
	if (f_local)
		return 0;

	/* sanity check */
	if (mhp[0] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb acquire message passed.\n");
		return -1;
	}

	flushph2();

	return 0;
}

static int
pk_recvspdupdate(mhp)
	caddr_t *mhp;
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
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
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb spddump message passed.\n");
		return -1;
	}
	msg = (struct sadb_msg *)mhp[0];

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
		plog(LLV_ERROR, LOCATION, NULL,
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
pk_recvspdflush(mhp)
	caddr_t *mhp;
{
	/* sanity check */
	if (mhp[0] == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb spdflush message passed.\n");
		return -1;
	}

	flushsp();

	return 0;
}

/*
 * send error against acquire message to kenrel.
 */
int
pk_sendeacquire(iph2)
	struct ph2handle *iph2;
{
	struct sadb_msg *newmsg;
	int len;

	len = sizeof(struct sadb_msg);
	newmsg = CALLOC(len, struct sadb_msg *);
	if (newmsg == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get buffer to send acquire.\n");
		return -1;
	}

	memset(newmsg, 0, len);
	newmsg->sadb_msg_version = PF_KEY_V2;
	newmsg->sadb_msg_type = SADB_ACQUIRE;
	newmsg->sadb_msg_errno = ENOENT;	/* XXX */
	newmsg->sadb_msg_satype = iph2->satype;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	newmsg->sadb_msg_reserved = 0;
	newmsg->sadb_msg_seq = iph2->seq;
	newmsg->sadb_msg_pid = (u_int32_t)getpid();

	/* send message */
	len = pfkey_send(lcconf->sock_pfkey, newmsg, len);

	free(newmsg);

	return 0;
}

/*
 * check if the algorithm is supported or not.
 * OUT	 0: ok
 *	-1: ng
 */
int
pk_checkalg(class, calg, keylen)
	int class, calg, keylen;
{
	int sup, error;
	u_int alg;
	struct sadb_alg alg0;

	switch (algclass2doi(class)) {
	case IPSECDOI_PROTO_IPSEC_ESP:
		sup = SADB_EXT_SUPPORTED_ENCRYPT;
		break;
	case IPSECDOI_ATTR_AUTH:
		sup = SADB_EXT_SUPPORTED_AUTH;
		break;
	case IPSECDOI_PROTO_IPCOMP:
		plog(LLV_WARNING, LOCATION, NULL,
			"compression algorithm can not be checked.\n");
		return 0;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid algorithm class.\n");
		return -1;
	}
	alg = ipsecdoi2pfkey_alg(algclass2doi(class), algtype2doi(class, calg));
	if (alg == ~0)
		return -1;

	if (keylen == 0) {
		if (ipsec_get_keylen(sup, alg, &alg0)) {
			plog(LLV_ERROR, LOCATION, NULL,
				"%s.\n", ipsec_strerror());
			return -1;
		}
		keylen = alg0.sadb_alg_minbits;
	}

	error = ipsec_check_keylen(sup, alg, keylen);
	if (error)
		plog(LLV_ERROR, LOCATION, NULL,
			"%s.\n", ipsec_strerror());

	return error;
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
		plog(LLV_ERROR, LOCATION, NULL,
			"inappropriate sadb spd management message passed.\n");
		return -1;
	}

	saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	new = newsp();
	if (new == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer\n");
		return -1;
	}

	new->spidx.dir = xpl->sadb_x_policy_dir;
	new->id = xpl->sadb_x_policy_id;
	new->policy = xpl->sadb_x_policy_type;
	new->req = NULL;

	/* check policy */
	switch (xpl->sadb_x_policy_type) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_NONE:
	case IPSEC_POLICY_ENTRUST:
	case IPSEC_POLICY_BYPASS:
		break;

	case IPSEC_POLICY_IPSEC:
	    {
		int tlen;
		struct sadb_x_ipsecrequest *xisr;
		struct ipsecrequest **p_isr = &new->req;

		/* validity check */
		if (PFKEY_EXTLEN(xpl) < sizeof(*xpl)) {
			plog(LLV_ERROR, LOCATION, NULL,
				"invalid msg length.\n");
			return -1;
		}

		tlen = PFKEY_EXTLEN(xpl) - sizeof(*xpl);
		xisr = (struct sadb_x_ipsecrequest *)(xpl + 1);

		while (tlen > 0) {

			/* length check */
			if (xisr->sadb_x_ipsecrequest_len < sizeof(*xisr)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"invalid msg length.\n");
				return -1;
			}

			/* allocate request buffer */
			*p_isr = newipsecreq();
			if (*p_isr == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
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
				plog(LLV_ERROR, LOCATION, NULL,
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
				plog(LLV_ERROR, LOCATION, NULL,
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
				plog(LLV_ERROR, LOCATION, NULL,
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
				plog(LLV_ERROR, LOCATION, NULL,
					"becoming tlen < 0\n");
			}

			xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
			                 + xisr->sadb_x_ipsecrequest_len);
		}
	    }
		break;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
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

/* proto/mode/src->dst spi */
static const char *
sadbsecas2str(src, dst, proto, spi, mode)
	struct sockaddr *src, *dst;
	int proto;
	u_int32_t spi;
	int mode;
{
	static char buf[256];
	u_int doi_proto, doi_mode;
	char *p;
	int blen, i;

	doi_proto = pfkey2ipsecdoi_proto(proto);
	if (doi_proto == ~0)
		return NULL;
	doi_mode = pfkey2ipsecdoi_mode(mode);
	if (doi_mode == ~0)
		return NULL;

	blen = sizeof(buf) - 1;
	p = buf;

	i = snprintf(p, blen, "%s/%s ",
		s_ipsecdoi_proto(doi_proto), s_ipsecdoi_encmode(doi_mode));
	p += i;
	blen -= i;

	i = snprintf(p, blen, "%s->", saddrwop2str(src));
	p += i;
	blen -= i;

	i = snprintf(p, blen, "%s ", saddrwop2str(dst));

	if (spi) {
		p += i;
		blen -= i;
		snprintf(p, blen, "spi=%lu(0x%lx)", (unsigned long)ntohl(spi),
		    (unsigned long)ntohl(spi));
	}

	return buf;
}
