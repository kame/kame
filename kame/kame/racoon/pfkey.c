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
/* YIPS @(#)$Id: pfkey.c,v 1.1 1999/08/08 23:31:24 itojun Exp $ */

#define _PFKEY_C_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/route.h>
#include <net/pfkeyv2.h>
#include <netkey/key_debug.h>

#include <netinet/in.h>
#include <netinet6/ipsec.h>

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
#include "vmbuf.h"
#include "schedule.h"
#include "isakmp.h"
#include "isakmp_inf.h"
#include "isakmp_var.h"
#include "ipsec_doi.h"
#include "pfkey.h"
#include "admin.h"
#include "misc.h"
#include "debug.h"
#include "handler.h"

#define WO_SPI	0	/* comparing without SPI */
#define W_SPI	1	/* comparing with my SPI */
#define W_SPI_P	2	/* comparing with peer SPI */
#define N_ADDRS	0	/* src and dst */
#define R_ADDRS	1	/* dst and src */

LIST_HEAD(_pfkey_list_, pfkey_st) pfkey_list;

int sock_pfkey;
u_int pfkey_acquire_lifetime = 30;
u_int pfkey_acquire_try = 30;
u_int pfkey_send_timer = 5;
u_int pfkey_send_try = 2;

/* prototype */
static struct pfkey_st *pfkey_new_pst_wrap __P((caddr_t *mhp));

static int admin2pfkey_proto __P((u_int proto));
static u_int ipsecdoi2pfkey_aalg __P((u_int hash_t));
static u_int ipsecdoi2pfkey_ealg __P((u_int t_id));
static u_int ipsecdoi2pfkey_calg __P((u_int t_id));
static u_int ipsecdoi2pfkey_proto __P((u_int proto));
static u_int keylen_aalg __P((u_int hash_t));
static u_int keylen_ealg __P((u_int t_id));

static struct sadb_msg *racoon_pfkey_recv __P((int, int *));

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
	struct pfkey_st *pst;
	int error = -1;

	/* receive pfkey message. */
	len = 0;
	msg = (struct sadb_msg *)racoon_pfkey_recv(sock_pfkey, &len);
	if (msg == NULL) {
		if (len < 0) {
			plog(LOCATION, "racoon_pfkey_recv (%s)\n", strerror(errno));
			goto end;
		} else {
			/* short message - msg not ready */
			return 0;
		}
	}

	YIPSDEBUG(DEBUG_PFKEY,
		fprintf(stderr, "pfkey_handler: get sadb_msg:\n");
		kdebug_sadb(msg));

	/* validity check */
	if (msg->sadb_msg_errno) {
		plog(LOCATION, "pfkey failed type:%u:%s\n",
			msg->sadb_msg_type,
			strerror(msg->sadb_msg_errno));
		goto end;
	}

	/* check pfkey message. */
	if (pfkey_check(msg, mhp)) {
		plog(LOCATION, "pfkey_check (%s)\n", ipsec_strerror());
		goto end;
	}

	switch (msg->sadb_msg_type) {
	case SADB_GETSPI:
		/* validity check */
		if (mhp[SADB_EXT_SA] == NULL) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"There is no SA extension "
					"for PFKEY GETSPI.\n"));
			goto end;
		}

		/* get pst entry */
		if ((pst = pfkey_get_pst_wrap(mhp, R_ADDRS, WO_SPI)) == NULL) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"no such a request "
					"against PFKEY GETSPI.\n"));
			goto end;
		}
		if (!ISSET(pst->status, IPSEC_SA_STATUS_GETSPI)) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"PFKEY GETSPI happens, "
					"status mismatched.\n"));
			goto end;
		}

		/* sanity check & update sequence */
		if (pst->dir == INITIATOR) {
			if (pst->seq != msg->sadb_msg_seq) {
				/* ignore, owner maybe other process. */
				goto end;
			}
		} else {
			/* RESPONDER */
			if (pst->seq != 0) {
				plog(LOCATION,
					"sequence mismatched, "
					"is kernel strange ?\n");
			}
			pst->seq = msg->sadb_msg_seq;
		}

		/* XXX to be considered the reason. */
		if (pst->sc != NULL)
			sched_kill(&pst->sc);

		/* set SPI */
		pst->spi = ((struct sadb_sa *)mhp[SADB_EXT_SA])->sadb_sa_spi;

		pst->status |= IPSEC_SA_STATUS_EXCHANGING;

		if (isakmp_post_getspi(pst) < 0) {
			plog(LOCATION,
				"pfkey_getspi failed in isakmp.\n");
			goto end;
		}

		break;

	case SADB_UPDATE:
		/* get pst entry */
		if ((pst = pfkey_get_pst_wrap(mhp, R_ADDRS, W_SPI)) == NULL) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"no such a request "
					"against PFKEY UPDATE.\n"));
			goto end;
		}

		/* sanity check */
		if (pst->seq != msg->sadb_msg_seq) {
			/* ignore, owner maybe other process. */
			goto end;
		}

		if (!ISSET(pst->status, IPSEC_SA_STATUS_UPDATE)) {
			/* ignore, owner maybe other process. */
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"PFKEY UPDATE happens, "
					"ignore, owner maybe other process.\n"));
			goto end;
		}

		/* XXX to be considered the reason. */
		if (pst->sc != NULL)
			sched_kill(&pst->sc);

		/* update status */
		pst->status |= IPSEC_SA_STATUS_ESTABLISHED;

		/* XXX When I can't get EXPIRE message in the future. */
		pst->sc = sched_add(pst->ld_time * 1.2, 0,
				1, isakmp_pfkey_over,
				(caddr_t)pst, (caddr_t)0,
				SCHED_ID_PST_LIFETIME);

		YIPSDEBUG(DEBUG_PFKEY,
			plog(LOCATION, "PFKEY UPDATE was success.\n"));
		break;

	case SADB_ADD:
		/* get pst entry */
		if ((pst = pfkey_get_pst_wrap(mhp, N_ADDRS, W_SPI_P)) == NULL) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"no such a request "
					"against PFKEY ADD.\n"));
			goto end;
		}

		/* sanity check */
		if (pst->seq != msg->sadb_msg_seq) {
			/* ignore, owner maybe other process. */
			goto end;
		}

		if (!ISSET(pst->status, IPSEC_SA_STATUS_ADD)) {
			/* ignore, owner maybe other process. */
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"PFKEY ADD happens, "
					"ignore, owner maybe other process.\n"));
			goto end;
		}

#if 0	/* XXX don't update because it's done by SADB_UPDATE */
		/* update status */
		/* It's redundant because of done in sadb_update. */
		pst->status |= IPSEC_SA_STATUS_ESTABLISHED;
#endif

		YIPSDEBUG(DEBUG_PFKEY,
			plog(LOCATION, "PFKEY ADD was success.\n"));
		break;

	case SADB_ACQUIRE:
		if (f_local) {
			/* ignore this message becauase of local test mode. */
			error = 0;
			goto end;
		}

		/* get pst entry to block ACQUIRE message. */
		pst = pfkey_get_pst_wrap(mhp, N_ADDRS, WO_SPI);

		if (pst != NULL
		 && !ISSET(pst->status, IPSEC_SA_STATUS_ESTABLISHED)
		 && !ISSET(pst->status, IPSEC_SA_STATUS_EXPIRED)) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"ignore, such PFKEY ACQUIRE request has "
					"been received.\n"));
			goto end;
		}
		if (pst != NULL
		 && ISSET(pst->status, IPSEC_SA_STATUS_ESTABLISHED)) {
			/*
			 * I couldn't get expire message from kernel,
			 * then I get the acquire message in the 1st.
			 * Delete old pst in order to keeping process.
			 */
			pfkey_free_pst(pst);
			pst = NULL;
		}

		if ((pst = pfkey_new_pst_wrap(mhp)) == NULL) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
				     "new pst creation failed.\n"));
			goto end;
		}

		pst->status |= IPSEC_SA_STATUS_ACQUIRE;
		pst->dir = INITIATOR;

		/* start isakmp initiation by using ident exchange */
		if (isakmp_post_acquire(pst) < 0) {
			plog(LOCATION,
				"IKE was failed against PFKEY ACQUIRE.\n");
			pfkey_free_pst(pst);
			goto end;
		}
		break;

	case SADB_REGISTER:
		/* XXX to be check to wait entry of register. */
		break;

	case SADB_EXPIRE:
		if (f_local) {
			/* ignore this message becauase of local test mode. */
			error = 0;
			goto end;
		}

		/* seconde check ph2 status to block EXPIRE message. */
		/* XXX What should I do ?  anyway I ignore it. */
		if (mhp[SADB_EXT_LIFETIME_HARD] != NULL) {
			/* ignore */
			break;
		}

		/* get pst entry */
		if ((pst = pfkey_get_pst_wrap(mhp, N_ADDRS, WO_SPI)) == NULL) {
			/* ignore */
			/* Maybe, it's key by pfkey_add. */
			break;
		}
		/* sanity check */
		if (pst->seq != msg->sadb_msg_seq) {
			/* ignore, owner maybe other process. */
			goto end;
		}
		if (ISSET(pst->status, IPSEC_SA_STATUS_EXPIRED)) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"PFKEY EXPIRE happens, but IPsec "
					"had been expired already.\n"));
			goto end;
		}
		if (!ISSET(pst->status, IPSEC_SA_STATUS_ESTABLISHED)) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"PFKEY EXPIRE happens, but IPsec "
					"SA hasn't established yet.\n"));
			goto end;
		}

		/* XXX re-set, see SADB_ACQUIRE handling in above. */
		if (pst->sc != NULL)
			sched_kill(&pst->sc);

		pst->status |= IPSEC_SA_STATUS_EXPIRED;

		/* check ph2 status to block EXPIRE message. */
		if (pst->ph2 != NULL) {
			YIPSDEBUG(DEBUG_PFKEY,
				plog(LOCATION,
					"ignore, such request is on processing.\n"));
			goto end;
		}

		/* INITIATOR, begin phase 2 exchange. */
		/* allocate buffer for status management of pfkey message */
		if (pst->dir == INITIATOR) {
			/* update status for re-use */
			pst->status |= IPSEC_SA_STATUS_ACQUIRE;

			/* start isakmp initiation by using ident exchange */
			if (isakmp_post_acquire(pst) < 0) {
				plog(LOCATION,
					"PFKEY ACQUIRE failed in isakmp.c\n");
				pfkey_free_pst(pst);
				goto end;
			}
		} else {
		/* RESPONDER delete the list, keep silent. */
			/* Receiver don't manage IPsec SA, so delete the list */
			pfkey_free_pst(pst);
		}
		break;

	case SADB_DUMP:
		/* ignore */
		break;

	case SADB_FLUSH:
		/* XXX should be flush ipsec-sa table */
		/* doing ignore, now. */
		break;

	case SADB_DELETE:
		isakmp_info_send_d2_pf(msg);
		break;

	default:
		YIPSDEBUG(DEBUG_PFKEY,
			plog(LOCATION,
				"command %d isn't supported.\n",
				msg->sadb_msg_type));
		goto end;
	}

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
		plog(LOCATION, "%s", ipsec_strerror());
		return NULL;
	}

	if (pfkey_send_dump(s, satype) < 0) {
		plog(LOCATION,
			"send dump failed (%s).\n", ipsec_strerror());
		goto fail;
	}

	while (1) {
		if (msg)
			free(msg);
		msg = racoon_pfkey_recv(s, &len);
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
			plog(LOCATION, "vrealloc(%s)\n", strerror(errno));
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

	if (pfkey_send_flush(sock_pfkey, satype) < 0) {
		plog(LOCATION,
			"send flush failed (%s).\n", ipsec_strerror());
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
	/* initialized PFKEY queue */
	LIST_INIT(&pfkey_list);

	if ((sock_pfkey = pfkey_open()) < 0) {
		plog(LOCATION, "%s", ipsec_strerror());
		return -1;
	}

	if (pfkey_send_register(sock_pfkey, SADB_SATYPE_ESP) < 0) {
		plog(LOCATION, "%s", ipsec_strerror());
		pfkey_close(sock_pfkey);
		return -1;
	}

	if (pfkey_send_register(sock_pfkey, SADB_SATYPE_AH) < 0) {
		plog(LOCATION, "%s", ipsec_strerror());
		pfkey_close(sock_pfkey);
		return -1;
	}

	if (pfkey_send_register(sock_pfkey, SADB_X_SATYPE_IPCOMP) < 0) {
		plog(LOCATION, "%s", ipsec_strerror());
		pfkey_close(sock_pfkey);
		return -1;
	}

#if 0
	if (pfkey_promisc_toggle(1) < 0) {
		pfkey_close(sock_pfkey);
		return -1;
	}
#endif
	return 0;
}

void
pfkey_set_acquire_time(time)
	u_int time;
{
	/* set time from isakmp's timer */
	pfkey_acquire_lifetime = time;
	pfkey_acquire_try = time;

	return;
}

/* %%% pfkey status management routines */
/*
 * create new status record of pfkey message
 */
struct pfkey_st *pfkey_new_pst(
	u_int ipsec_proto,
	struct sockaddr *src, u_int prefs,
	struct sockaddr *dst, u_int prefd,
	u_int ul_proto,
	struct sockaddr *proxy,
	u_int32_t seq)
{
	struct pfkey_st *pst;

	/* create new status */
	if ((pst = CALLOC(sizeof(*pst), struct pfkey_st *)) == 0) {
		plog(LOCATION,
			"malloc (%s)\n", strerror(errno)); 
		return NULL;
	}

	pst->status = IPSEC_SA_STATUS_NONE;
	pst->seq = seq;
	pst->ipsec_proto = ipsec_proto;
	pst->prefs = prefs;
	pst->prefd = prefd;
	pst->ul_proto = ul_proto;
	pst->spi = 0;
	pst->spi_p = 0;

	/* get src address */
	GET_NEWBUF(pst->src, struct sockaddr *, src, src->sa_len);
	if (pst->src == NULL)
		goto err;

	/* get dst address */
	GET_NEWBUF(pst->dst, struct sockaddr *, dst, dst->sa_len);
	if (pst->dst == NULL)
		goto err;

	/* get proxy address if present */
	if (proxy != NULL) {
		GET_NEWBUF(pst->proxy, struct sockaddr *, proxy, proxy->sa_len);
		if (pst->proxy == NULL)
			goto err;
	}

#if 0
	/* get proposal if present */
	if (mhp[SADB_EXT_PROPOSAL] != NULL) {
		GET_NEWBUF(pst->prop,
			struct sadb_prop *,
			mhp[SADB_EXT_PROPOSAL],
			PFKEY_EXTLEN(mhp[SADB_EXT_PROPOSAL]));
		if (pst->prop == NULL)
			goto err;
	}
#endif

	/* add to list */
	LIST_INSERT_HEAD(&pfkey_list, pst, list);

	return pst;

err:
	if (pst != NULL)
		pfkey_free_pst(pst);
	return NULL;
}

/*
 * free record from pfkey stauts table
 */
void
pfkey_free_pst(pst)
	struct pfkey_st *pst;
{
	/* remove from list */
	LIST_REMOVE(pst, list);

	if (pst->sc != NULL) sched_kill(&pst->sc);
	if (pst->src != NULL) free(pst->src);
	if (pst->dst != NULL) free(pst->dst);
	if (pst->proxy != NULL) free(pst->proxy);

#if notyet
	if (pst->prop != NULL) free(pst->prop);
	if (pst->idents != NULL) free(pst->idents);
	if (pst->identd != NULL) free(pst->identd);
	if (pst->sens != NULL) free(pst->sens);
#endif

	free(pst);

	return;
}

/*
 * dump pfkey stauts table
 */
vchar_t *
pfkey_dump_pst(error)
	int *error;
{
	struct pfkey_st *var;
	vchar_t *buf = NULL;
	caddr_t bufp;
	int tlen = 0;

#ifdef LIST_FOREACH
	LIST_FOREACH(var, &pfkey_list, list)
#else
	for (var = pfkey_list.lh_first; var; var = var->list.le_next)
#endif
	{
		tlen += sizeof(*var);
		tlen += var->src->sa_len;
		tlen += var->dst->sa_len;
		if (var->proxy != NULL)
			tlen += var->proxy->sa_len;
	}

	if (tlen == 0) {
		*error = ENOENT;
		return NULL;
	}

	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc(%s)\n", strerror(errno));
		*error = errno;
		return NULL;
	}
	bufp = buf->v;

#ifdef LIST_FOREACH
	LIST_FOREACH(var, &pfkey_list, list)
#else
	for (var = pfkey_list.lh_first; var; var = var->list.le_next)
#endif
	{
		memcpy(bufp, var, sizeof(*var));
		/* XXX to be defined the structure to communicate */
		/* XXX set lifetimer into the place of struct sched */
	    {
		struct pfkey_st *pst = (struct pfkey_st *)bufp;
		*(u_int *)pst->sc = pst->sc->tick * pst->sc->try;
	    }
		bufp += sizeof(*var);
		memcpy(bufp, var->src, var->src->sa_len);
		bufp += var->src->sa_len;
		memcpy(bufp, var->dst, var->dst->sa_len);
		bufp += var->dst->sa_len;

		if (var->proxy != NULL) {
			memcpy(bufp, var->proxy, var->proxy->sa_len);
			bufp += var->proxy->sa_len;
		}
	}

	return buf;
}

#if 1
/*
 * flush pfkey stauts table for DEBUGing.
 */
void
pfkey_flush_pst()
{
	struct pfkey_st *var;

#ifdef LIST_FOREACH
	LIST_FOREACH(var, &pfkey_list, list)
#else
	for (var = pfkey_list.lh_first; var; var = var->list.le_next)
#endif
	{
		pfkey_free_pst(var);
	}

	return;
}
#endif

/*
 * To get pfkey status record by src, dst and so on.
 * If spi == 0, ignore to check SPI.  If others, check SPI.
 * flag == 1, compare to spi_p.
 */
struct pfkey_st *
pfkey_get_pst(ipsec_proto, src, prefs, dst, prefd,
		ul_proto, proxy, spi, which_spi)
	u_int ipsec_proto;
	struct sockaddr *src;
	u_int prefs;
	struct sockaddr *dst;
	u_int prefd;
	u_int ul_proto;
	struct sockaddr *proxy;
	u_int32_t spi;
	int which_spi;
{
	struct pfkey_st *var;

	YIPSDEBUG(DEBUG_DMISC,
		char p1[20]; char p2[20];
		GETNAMEINFO(src, _addr1_, p1);
		GETNAMEINFO(dst, _addr2_, p2);
		plog(LOCATION,
			"obj:%2u %8x src:%s/%u[%s] dst:%s/%u[%s] "
			"ulp=%u proxy=%p\n",
			ipsec_proto, spi,
			_addr1_, prefs, p1,
			_addr2_, prefd, p2,
			ul_proto, proxy));

#ifdef LIST_FOREACH
	LIST_FOREACH(var, &pfkey_list, list)
#else
	for (var = pfkey_list.lh_first; var; var = var->list.le_next)
#endif
	{

		YIPSDEBUG(DEBUG_DMISC,
			char p1[20]; char p2[20];
			GETNAMEINFO(var->src, _addr1_, p1);
			GETNAMEINFO(var->dst, _addr2_, p2);
			plog(LOCATION,
				"lis:%2u %8x src:%s/%u[%s] dst:%s/%u[%s] "
				"ulp=%u proxy=%p\n",
				var->ipsec_proto, var->spi,
				_addr1_, var->prefs, p1,
				_addr2_, var->prefd, p2,
				var->ul_proto, proxy));

		if (var->ipsec_proto != ipsec_proto
		 || var->ul_proto != ul_proto
		 || var->prefs != prefs
		 || var->prefd != prefd)
			continue;
		if (spi != 0) {
			if (which_spi == 0) {
				if (var->spi != spi)
					continue;
			} else {
				if (var->spi_p != spi)
					continue;
			}
		}
		if (saddrcmp(var->src, src)
		 || saddrcmp(var->dst, dst))
			continue;
		if (proxy != NULL
		 && saddrcmp_woport(var->proxy, proxy))
			continue;

		/* found */
		return(var);
	}

	return NULL;
}

static struct pfkey_st *
pfkey_new_pst_wrap(mhp)
	caddr_t *mhp;
{
	struct pfkey_st *pst;
	struct sockaddr *proxy;
	u_int proto;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(LOCATION, "invalid pointer was passed.\n");
		return NULL;
	}

	/* get upper layer proto */
	if (PFKEY_ADDR_PROTO(mhp[SADB_EXT_ADDRESS_SRC])
	 != PFKEY_ADDR_PROTO(mhp[SADB_EXT_ADDRESS_DST])) {
		plog(LOCATION,
		     "mismatched protocol between src and dst.\n");
		return NULL;
	}

	/* validity check */
    {
	struct sadb_msg *msg = (struct sadb_msg *)mhp[0];
	if ((proto = pfkey2ipsecdoi_proto(msg->sadb_msg_satype)) == ~0)
		return NULL;
    }

	/* get proxy address if present */
	if (mhp[SADB_EXT_ADDRESS_PROXY] != NULL)
		proxy = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_PROXY]);
	else
		proxy = NULL;

	/* allocate buffer for status management of pfkey message */
	if ((pst = pfkey_new_pst(
			proto,
			PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]),
			PFKEY_ADDR_PREFIX(mhp[SADB_EXT_ADDRESS_SRC]),
			PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]),
			PFKEY_ADDR_PREFIX(mhp[SADB_EXT_ADDRESS_DST]),
			PFKEY_ADDR_PROTO(mhp[SADB_EXT_ADDRESS_SRC]),
			proxy,
			((struct sadb_msg *)mhp[0])->sadb_msg_seq)) == NULL)
		return NULL;

	return pst;
}

/*
 * how_addrs: the way to order of src and dst.
 *	N_ADDRS
 *	R_ADDRS
 * how_spi:	the way to compare w/o SPI.
 *	WO_SPI	without spi and with proxy address if present.
 *	W_SPI	with spi and without proxy address.
 *	W_SPI_P	with spi_p and without proxy address.
 */
struct pfkey_st *
pfkey_get_pst_wrap(mhp, how_addrs, how_spi)
	caddr_t *mhp;
	int how_addrs, how_spi;
{
	struct pfkey_st *pst;
	struct sockaddr *src, *dst, *proxy;
	u_int prefs, prefd, proto;
	u_int32_t spi;
	int which_spi;

	/* sanity check */
	if (mhp[0] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
		plog(LOCATION, "invalid pointer was passed.\n");
		return NULL;
	}

	if (how_addrs == N_ADDRS) {
		src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
		prefs = PFKEY_ADDR_PREFIX(mhp[SADB_EXT_ADDRESS_SRC]);
		dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
		prefd = PFKEY_ADDR_PREFIX(mhp[SADB_EXT_ADDRESS_DST]);
	} else {
		/* reverse ordering */
		src = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_DST]);
		prefs = PFKEY_ADDR_PREFIX(mhp[SADB_EXT_ADDRESS_DST]);
		dst = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_SRC]);
		prefd = PFKEY_ADDR_PREFIX(mhp[SADB_EXT_ADDRESS_SRC]);
	}

	/* get upper layer proto */
	if (PFKEY_ADDR_PROTO(mhp[SADB_EXT_ADDRESS_SRC])
	 != PFKEY_ADDR_PROTO(mhp[SADB_EXT_ADDRESS_DST])) {
		plog(LOCATION,
		     "mismatched protocol between src and dst.\n");
		return NULL;
	}

	which_spi = 0;

	switch (how_spi) {
	case W_SPI:
	case W_SPI_P:
		/* compare with SPI */
	 	if (mhp[SADB_EXT_SA] == NULL) {
			plog(LOCATION,
				"no SADB_SA msg exists.\n");
			return NULL;
		}
		spi = ((struct sadb_sa *)mhp[SADB_EXT_SA])->sadb_sa_spi;
		if (spi == 0) {
			plog(LOCATION,
				"Invalid SPI passed.\n");
			return NULL;
		}

		/* mask proxy */
		proxy = NULL;

		if (how_spi == W_SPI_P)
			which_spi = 1;
		break;

	case WO_SPI:
	default:
		/* compare without SPI */
		spi = 0;

		/* get proxy address if present */
		if (mhp[SADB_EXT_ADDRESS_PROXY] != NULL)
			proxy = PFKEY_ADDR_SADDR(mhp[SADB_EXT_ADDRESS_PROXY]);
		else
			proxy = NULL;
		break;
	}

	/* validity check */
    {
	struct sadb_msg *msg = (struct sadb_msg *)mhp[0];
	if ((proto = pfkey2ipsecdoi_proto(msg->sadb_msg_satype)) == ~0)
		return NULL;
    }

	if ((pst = pfkey_get_pst(
			proto,
			src, prefs,
			dst, prefd,
			PFKEY_ADDR_PROTO(mhp[SADB_EXT_ADDRESS_SRC]),
			proxy,
			spi, which_spi)) == NULL)
		return NULL;

	return pst;
}

/*
 * the wrapper for IPSEC_DOI to call pfkey_send_getspi().
 */
int
pfkey_send_getspi_wrap(sock_pfkey, iph2)
	int sock_pfkey;
	struct isakmp_ph2 *iph2;
{
	u_int proto;

	/* validity check */
	if ((proto = ipsecdoi2pfkey_proto(iph2->pst->ipsec_proto)) == ~0)
		return -1;

	/* if responder's request, MUST iph2->pst->seq == 0 */
	if (pfkey_send_getspi(
			sock_pfkey,
			proto,
			iph2->pst->dst,
			iph2->pst->prefd,
			iph2->pst->src,
			iph2->pst->prefs,
			iph2->pst->ul_proto,
			0, 0, iph2->pst->seq) < 0) {
		plog(LOCATION, "%s.\n", ipsec_strerror());
		return -1;
	}

	iph2->pst->status |= IPSEC_SA_STATUS_GETSPI;

	return 0;
}

/*
 * resend getspi for phase 2.
 */
int
pfkey_resend_getspi(sc)
	struct sched *sc;
{
	int s = (int)sc->ptr1;
	struct isakmp_ph2 *iph2 = (struct isakmp_ph2 *)sc->ptr2;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "resend packet.\n"));
	YIPSDEBUG(DEBUG_SCHED2, plog(LOCATION, "tick over #%s\n",
		sched_pindex(&sc->index)));

	if (pfkey_send_getspi_wrap(s, iph2) < 0) {
		plog(LOCATION, "getspi failed.\n");
		return -1;
	}

	sc->tick = pfkey_send_timer;

	return 0;
}

int
pfkey_send_update_wrap(sock_pfkey, iph2)
	int sock_pfkey;
	struct isakmp_ph2 *iph2;
{
	int e_type, e_keylen, a_type, a_keylen, flags;
	u_int proto;

	/* validity check */
	if ((proto = ipsecdoi2pfkey_proto(iph2->pst->ipsec_proto)) == ~0)
		return -1;

	/* set algorithm type and key length */
	if (pfkey_convertfromipsecdoi(
			iph2->isa->proto_id,
			iph2->isa->cipher_t,
			iph2->isa->hash_t,
			&e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0)
		return -1;

	/* I believe that proxy address is always equal to iph1->local. */
	if (pfkey_send_update(
			sock_pfkey,
			proto,
			iph2->pst->dst,
			iph2->pst->prefd,
			iph2->pst->src,
			iph2->pst->prefs,
			iph2->pst->ul_proto,
			iph2->pst->proxy == NULL ? 0 : iph2->ph1->local,
			iph2->pst->spi,
			iph2->pst->keymat->v,
			e_type, e_keylen, a_type, a_keylen, flags,
			0, iph2->pst->ld_bytes, iph2->pst->ld_time, 0,
			iph2->pst->seq) < 0) {
		plog(LOCATION, "%s.\n", ipsec_strerror());
		return -1;
	}

	iph2->pst->status |= IPSEC_SA_STATUS_UPDATE;

	return 0;
}

int
pfkey_send_add_wrap(sock_pfkey, iph2)
	int sock_pfkey;
	struct isakmp_ph2 *iph2;
{
	int e_type, e_keylen, a_type, a_keylen, flags;
	u_int proto;

	/* validity check */
	if ((proto = ipsecdoi2pfkey_proto(iph2->pst->ipsec_proto)) == ~0)
		return -1;

	/* set algorithm type and key length */
	if (pfkey_convertfromipsecdoi(
			iph2->isa->proto_id,
			iph2->isa->cipher_t,
			iph2->isa->hash_t,
			&e_type, &e_keylen, &a_type, &a_keylen, &flags) < 0)
		return -1;

	/* I believe that proxy address is always equal to iph1->remote. */
	if (pfkey_send_add(
			sock_pfkey,
			proto,
			iph2->pst->src,
			iph2->pst->prefs,
			iph2->pst->dst,
			iph2->pst->prefd,
			iph2->pst->ul_proto,
			iph2->pst->proxy == NULL ? 0 : iph2->ph1->remote,
			iph2->pst->spi_p,
			iph2->pst->keymat_p->v,
			e_type, e_keylen, a_type, a_keylen, flags,
			0, iph2->pst->ld_bytes, iph2->pst->ld_time, 0,
			iph2->pst->seq) < 0) {
		plog(LOCATION, "%s.\n", ipsec_strerror());
		return -1;
	}

	iph2->pst->status |= IPSEC_SA_STATUS_ADD;

	return 0;
}

/* %%% for conversion */
/* ADMIN_PROTO -> SADB_SATYPE */
static int
admin2pfkey_proto(proto)
	u_int proto;
{
	switch (proto) {
	case ADMIN_PROTO_IPSEC:
		return SADB_SATYPE_UNSPEC;
	case ADMIN_PROTO_AH:
		return SADB_SATYPE_AH;
	case ADMIN_PROTO_ESP:
		return SADB_SATYPE_ESP;
	default:
		plog(LOCATION, "unsupported proto %d\n", proto);
		return -1;
	}
	/*NOTREACHED*/
}

/* IPSECDOI_ATTR_AUTH -> SADB_AALG */
static u_int
ipsecdoi2pfkey_aalg(hash_t)
	u_int hash_t;
{
	switch (hash_t) {
	case IPSECDOI_ATTR_AUTH_HMAC_MD5:
		return SADB_AALG_MD5HMAC;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
		return SADB_AALG_SHA1HMAC;
	case IPSECDOI_ATTR_AUTH_KPDK:		/* need special care */
		return SADB_AALG_NONE;

	/* not supported */
	case IPSECDOI_ATTR_AUTH_DES_MAC:
		plog(LOCATION,
			"Not supported hash type: %u\n", hash_t);
		return ~0;

	case 0: /* reserved */
	default:
		return SADB_AALG_NONE;

		plog(LOCATION,
			"Invalid hash type: %u\n", hash_t);
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
	case IPSECDOI_ESP_RC5:
		return SADB_EALG_RC5CBC;
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
		plog(LOCATION,
			"Not supported transform: %u\n", t_id);
		return ~0;

	case 0: /* reserved */
	default:
		plog(LOCATION,
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
		plog(LOCATION,
			"Invalid transform id: %u\n", t_id);
		return ~0;
	}
	/*NOTREACHED*/
}

/* IPSECDOI_PROTO -> SADB_SATYPE */
static u_int
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
		plog(LOCATION,
			"Invalid ipsec_doi proto: %u\n", proto);
		return ~0;
	}
	/*NOTREACHED*/
};

/* SADB_SATYPE -> IPSECDOI_PROTO */
u_int
pfkey2ipsecdoi_proto(proto)
	u_int proto;
{
	switch (proto) {
	case SADB_SATYPE_AH:
		return IPSECDOI_PROTO_IPSEC_AH;
	case SADB_SATYPE_ESP:
		return IPSECDOI_PROTO_IPSEC_ESP;
	case SADB_X_SATYPE_IPCOMP:
		return IPSECDOI_PROTO_IPCOMP;

	default:
		plog(LOCATION,
			"Invalid pfkey proto: %u\n", proto);
		return ~0;
	}
	/*NOTREACHED*/
};

/* default key length for encryption algorithm */
static u_int
keylen_aalg(hash_t)
	u_int hash_t;
{
	switch (hash_t) {
	case IPSECDOI_ATTR_AUTH_HMAC_MD5:
		return 128;
	case IPSECDOI_ATTR_AUTH_HMAC_SHA1:
		return 160;
	case IPSECDOI_ATTR_AUTH_KPDK:		/* need special care */
		return 0;

	/* not supported */
	case IPSECDOI_ATTR_AUTH_DES_MAC:
		plog(LOCATION,
			"Not supported hash type: %u\n", hash_t);
		return ~0;

	case 0: /* reserved */
	default:
		return SADB_AALG_NONE;

		plog(LOCATION,
			"Invalid hash type: %u\n", hash_t);
		return ~0;
	}
	/*NOTREACHED*/
}

/* default key length for encryption algorithm */
static u_int
keylen_ealg(t_id)
	u_int t_id;
{
	switch (t_id) {
	case IPSECDOI_ESP_DES_IV64:		/* sa_flags |= SADB_X_EXT_OLD */
		return 64;
	case IPSECDOI_ESP_DES:
		return 64;
	case IPSECDOI_ESP_3DES:
		return 192;
	case IPSECDOI_ESP_RC5:
		return 40;
	case IPSECDOI_ESP_CAST:
		return 40;
	case IPSECDOI_ESP_BLOWFISH:
		return 64;
	case IPSECDOI_ESP_DES_IV32:	/* flags |= (SADB_X_EXT_OLD|
							SADB_X_EXT_IV4B)*/
		return 64;
	case IPSECDOI_ESP_NULL:
		return 0;

	/* not supported */
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_RC4:
		plog(LOCATION,
			"Not supported transform: %u\n", t_id);
		return ~0;

	case 0: /* reserved */
	default:
		plog(LOCATION,
			"Invalid transform id: %u\n", t_id);
		return ~0;
	}
	/*NOTREACHED*/
}
#include "isakmp.h"
#include "ipsec_doi.h"

int pfkey_convertfromipsecdoi(proto_id, t_id, hash_t,
		e_type, e_keylen, a_type, a_keylen, flags)
	u_int proto_id;
	u_int t_id;
	u_int hash_t;
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
		if ((*e_keylen = keylen_ealg(t_id)) == ~0)
			goto bad;
		*e_keylen >>= 3;

		if ((*a_type = ipsecdoi2pfkey_aalg(hash_t)) == ~0)
			goto bad;
		if ((*a_keylen = keylen_aalg(hash_t)) == ~0)
			goto bad;
		*a_keylen >>= 3;

		if (*e_type == SADB_EALG_NONE) {
			plog(LOCATION, "no ESP algorithm.\n");
			goto bad;
		}
		break;

	case IPSECDOI_PROTO_IPSEC_AH:
		if ((*a_type = ipsecdoi2pfkey_aalg(hash_t)) == ~0)
			goto bad;
		if ((*a_keylen = keylen_aalg(hash_t)) == ~0)
			goto bad;
		*a_keylen >>= 3;

		if (t_id == IPSECDOI_ATTR_AUTH_HMAC_MD5 
		 && hash_t == IPSECDOI_ATTR_AUTH_KPDK) {
			/* AH_MD5 + Auth(KPDK) = RFC1826 keyed-MD5 */
			*a_type = SADB_AALG_MD5;
			*flags |= SADB_X_EXT_OLD;
		}
		*e_type = SADB_EALG_NONE;
		*e_keylen = 0;
		if (*a_type == SADB_AALG_NONE) {
			plog(LOCATION, "no AH algorithm.\n");
			goto bad;
		}
		break;

	case IPSECDOI_PROTO_IPCOMP:
		if ((*e_type = ipsecdoi2pfkey_calg(t_id)) == ~0)
			goto bad;
		*e_keylen = 0;

		*a_type = SADB_AALG_NONE;
		*a_keylen = 0;
		if (*e_type == SADB_X_CALG_NONE) {
			plog(LOCATION, "no IPCOMP algorithm.\n");
			goto bad;
		}
		break;

	default:
		plog(LOCATION, "unknown IPsec protocol.\n");
		goto bad;
	}

	return 0;

    bad:
	errno = EINVAL;
	return -1;
}

/*
 * differences with pfkey_recv() in libipsec/pfkey.c:
 * - never performs busywait loop.
 * - returns NULL and set *lenp to negative on fatal failures
 * - returns NULL and set *lenp to non-negative on non-fatal failures
 * - returns non-NULL on success
 */
static struct sadb_msg *
racoon_pfkey_recv(so, lenp)
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
