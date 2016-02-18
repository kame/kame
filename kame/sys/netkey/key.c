/*	$NetBSD: key.c,v 1.121 2004/05/31 04:29:01 itojun Exp $	*/

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

/*
 * This code is referd to RFC 2367
 */

#ifdef __FreeBSD__
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#include "opt_ipsec.h"
#include "fs_kernfs.h"
#include "opt_mip6.h"
#else
#undef KERNFS
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#ifdef __NetBSD__
#include <sys/callout.h>
#endif
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/syslog.h>
#ifdef __NetBSD__
#include <sys/sysctl.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/raw_cb.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#endif /* INET6 */

#ifdef INET
#include <netinet/in_pcb.h>
#endif
#ifdef INET6
#include <netinet6/in6_pcb.h>
#endif /* INET6 */

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key.h>
#include <netkey/keysock.h>
#include <netkey/key_debug.h>

#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#ifdef IPSEC_ESP
#include <netinet6/esp.h>
#endif
#include <netinet6/ipcomp.h>

#ifdef KERNFS
#include <sys/mount.h>
#include <miscfs/kernfs/kernfs.h>
#endif

#include <machine/stdarg.h>

#if defined(__OpenBSD__) || defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ == 4)
#include "pf.h"
#endif
#if NPF > 0
#include <net/pfvar.h>
#else
#define NPF 0
#endif

/* randomness */
#ifdef __NetBSD__
#include "rnd.h"
#if NRND > 0
#include <sys/rnd.h>
#endif
#endif
#ifdef __FreeBSD__
#include <sys/random.h>
#endif

#ifdef MIP6
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include "mip.h"
#if NMIP > 0
#include <netinet/ip6mh.h>
#endif /* NMIP > 0*/
#endif /* MIP6 */

#include <net/net_osdep.h>

#ifndef offsetof
#define offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif
#ifndef satosin
#define satosin(s) ((struct sockaddr_in *)s)
#endif

#define FULLMASK	0xff

/*
 * Note on SA reference counting:
 * - SAs that are not in DEAD state will have (total external reference + 1)
 *   following value in reference count field.  they cannot be freed and are
 *   referenced from SA header.
 * - SAs that are in DEAD state will have (total external reference)
 *   in reference count field.  they are ready to be freed.  reference from
 *   SA header will be removed in keydb_delsecasvar(), when the reference count
 *   field hits 0 (= no external reference other than from SA header.
 */

u_int32_t key_debug_level = 0;
static u_int key_spi_trycnt = 1000;
static u_int32_t key_spi_minval = 0x100;
static u_int32_t key_spi_maxval = 0x0fffffff;	/* XXX */
static u_int key_larval_lifetime = 30;	/* interval to expire acquiring, 30(s)*/
static int key_blockacq_count = 10;	/* counter for blocking SADB_ACQUIRE.*/
static int key_blockacq_lifetime = 20;	/* lifetime for blocking SADB_ACQUIRE.*/
static int key_preferred_oldsa = 1;	/*preferred old sa rather than new sa.*/

static u_int32_t acq_seq = 0;

#ifdef PFKEYV2_SADB_X_EXT_PACKET
u_int32_t acq_maxpktlen = 512;
#endif

struct _satailq satailq;		/* list of all SAD entry */
struct _sptailq sptailq;		/* SPD table + pcb */
static LIST_HEAD(_sptree, secpolicy) sptree[IPSEC_DIR_MAX];	/* SPD table */
static LIST_HEAD(_sahtree, secashead) sahtree;			/* SAD */
static LIST_HEAD(_regtree, secreg) regtree[SADB_SATYPE_MAX + 1];
							/* registed list */

#define SPIHASHSIZE	128
#define	SPIHASH(x)	(((x) ^ ((x) >> 16)) % SPIHASHSIZE)
static LIST_HEAD(_spihash, secasvar) spihash[SPIHASHSIZE];

#ifndef IPSEC_NONBLOCK_ACQUIRE
static LIST_HEAD(_acqtree, secacq) acqtree;		/* acquiring list */
#endif
static LIST_HEAD(_spacqtree, secspacq) spacqtree;	/* SP acquiring list */

struct key_cb key_cb;

/* search order for SAs */
static const u_int saorder_state_valid_prefer_old[] = {
	SADB_SASTATE_DYING, SADB_SASTATE_MATURE,
};
static const u_int saorder_state_valid_prefer_new[] = {
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING,
};
static const u_int saorder_state_alive[] = {
	/* except DEAD */
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING, SADB_SASTATE_LARVAL
};
static const u_int saorder_state_any[] = {
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING,
	SADB_SASTATE_LARVAL, SADB_SASTATE_DEAD
};

static const int minsize[] = {
	sizeof(struct sadb_msg),	/* SADB_EXT_RESERVED */
	sizeof(struct sadb_sa),		/* SADB_EXT_SA */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_CURRENT */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_HARD */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_SOFT */
	sizeof(struct sadb_address),	/* SADB_EXT_ADDRESS_SRC */
	sizeof(struct sadb_address),	/* SADB_EXT_ADDRESS_DST */
	sizeof(struct sadb_address),	/* SADB_EXT_ADDRESS_PROXY */
	sizeof(struct sadb_key),	/* SADB_EXT_KEY_AUTH */
	sizeof(struct sadb_key),	/* SADB_EXT_KEY_ENCRYPT */
	sizeof(struct sadb_ident),	/* SADB_EXT_IDENTITY_SRC */
	sizeof(struct sadb_ident),	/* SADB_EXT_IDENTITY_DST */
	sizeof(struct sadb_sens),	/* SADB_EXT_SENSITIVITY */
	sizeof(struct sadb_prop),	/* SADB_EXT_PROPOSAL */
	sizeof(struct sadb_supported),	/* SADB_EXT_SUPPORTED_AUTH */
	sizeof(struct sadb_supported),	/* SADB_EXT_SUPPORTED_ENCRYPT */
	sizeof(struct sadb_spirange),	/* SADB_EXT_SPIRANGE */
	0,				/* SADB_X_EXT_KMPRIVATE */
	sizeof(struct sadb_x_policy),	/* SADB_X_EXT_POLICY */
	sizeof(struct sadb_x_sa2),	/* SADB_X_SA2 */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	sizeof(struct sadb_x_tag),	/* SADB_X_TAG */
	0 /*sizeof(struct sadb_x_sa3)*/, /* SADB_X_SA3 */
#ifdef PFKEYV2_SADB_X_EXT_PACKET
	sizeof(struct sadb_x_packet),	/* SADB_X_EXT_PACKET */
#else
	0,
#endif
};
static const int maxsize[] = {
	sizeof(struct sadb_msg),	/* SADB_EXT_RESERVED */
	sizeof(struct sadb_sa),		/* SADB_EXT_SA */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_CURRENT */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_HARD */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_SOFT */
	0,				/* SADB_EXT_ADDRESS_SRC */
	0,				/* SADB_EXT_ADDRESS_DST */
	0,				/* SADB_EXT_ADDRESS_PROXY */
	0,				/* SADB_EXT_KEY_AUTH */
	0,				/* SADB_EXT_KEY_ENCRYPT */
	0,				/* SADB_EXT_IDENTITY_SRC */
	0,				/* SADB_EXT_IDENTITY_DST */
	0,				/* SADB_EXT_SENSITIVITY */
	0,				/* SADB_EXT_PROPOSAL */
	0,				/* SADB_EXT_SUPPORTED_AUTH */
	0,				/* SADB_EXT_SUPPORTED_ENCRYPT */
	sizeof(struct sadb_spirange),	/* SADB_EXT_SPIRANGE */
	0,				/* SADB_X_EXT_KMPRIVATE */
	0,				/* SADB_X_EXT_POLICY */
	sizeof(struct sadb_x_sa2),	/* SADB_X_SA2 */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	0,				/* (used by NetBSD extension) */
	sizeof(struct sadb_x_tag),	/* SADB_X_TAG */
	0 /*sizeof(struct sadb_x_sa3)*/, /* SADB_X_SA3 */
#ifdef PFKEYV2_SADB_X_EXT_PACKET
	0,				/* SADB_X_EXT_PACKET */
#else
	0,
#endif
};

static int ipsec_esp_keymin = 256;
static int ipsec_esp_auth = 0;
static int ipsec_ah_keymin = 128;

#ifdef __FreeBSD__
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_key);
#endif

SYSCTL_INT(_net_key, KEYCTL_DEBUG_LEVEL,	debug,	CTLFLAG_RW, \
	&key_debug_level,	0,	"");

/* max count of trial for the decision of spi value */
SYSCTL_INT(_net_key, KEYCTL_SPI_TRY,		spi_trycnt,	CTLFLAG_RW, \
	&key_spi_trycnt,	0,	"");

/* minimum spi value to allocate automatically. */
SYSCTL_INT(_net_key, KEYCTL_SPI_MIN_VALUE,	spi_minval,	CTLFLAG_RW, \
	&key_spi_minval,	0,	"");

/* maximun spi value to allocate automatically. */
SYSCTL_INT(_net_key, KEYCTL_SPI_MAX_VALUE,	spi_maxval,	CTLFLAG_RW, \
	&key_spi_maxval,	0,	"");

/* lifetime for larval SA */
SYSCTL_INT(_net_key, KEYCTL_LARVAL_LIFETIME,	larval_lifetime, CTLFLAG_RW, \
	&key_larval_lifetime,	0,	"");

/* counter for blocking to send SADB_ACQUIRE to IKEd */
SYSCTL_INT(_net_key, KEYCTL_BLOCKACQ_COUNT,	blockacq_count,	CTLFLAG_RW, \
	&key_blockacq_count,	0,	"");

/* lifetime for blocking to send SADB_ACQUIRE to IKEd */
SYSCTL_INT(_net_key, KEYCTL_BLOCKACQ_LIFETIME,	blockacq_lifetime, CTLFLAG_RW, \
	&key_blockacq_lifetime,	0,	"");

/* minimum ESP key length */
SYSCTL_INT(_net_key, KEYCTL_ESP_KEYMIN,	esp_keymin, CTLFLAG_RW, \
	&ipsec_esp_keymin,	0,	"");

/* minimum AH key length */
SYSCTL_INT(_net_key, KEYCTL_AH_KEYMIN,	ah_keymin, CTLFLAG_RW, \
	&ipsec_ah_keymin,	0,	"");

/* perfered old SA rather than new SA */
SYSCTL_INT(_net_key, KEYCTL_PREFERED_OLDSA,	preferred_oldsa, CTLFLAG_RW,\
	&key_preferred_oldsa,	0,	"");
#endif /* __FreeBSD__ */

#ifndef LIST_FOREACH
#define LIST_FOREACH(elm, head, field)                                     \
	for (elm = LIST_FIRST(head); elm; elm = LIST_NEXT(elm, field))
#endif
#define __LIST_CHAINED(elm) \
	(!((elm)->chain.le_next == NULL && (elm)->chain.le_prev == NULL))
#define LIST_INSERT_TAIL(head, elm, type, field) \
do {\
	struct type *curelm = LIST_FIRST(head); \
	if (curelm == NULL) {\
		LIST_INSERT_HEAD(head, elm, field); \
	} else { \
		while (LIST_NEXT(curelm, field)) \
			curelm = LIST_NEXT(curelm, field);\
		LIST_INSERT_AFTER(curelm, elm, field);\
	}\
} while (/*CONSTCOND*/ 0)

#define KEY_CHKSASTATE(head, sav, name) \
do { \
	if ((head) != (sav)) {						\
		ipseclog((LOG_DEBUG, "%s: state mismatched (TREE=%u SA=%u)\n", \
			(name), (head), (sav)));			\
		continue;						\
	}								\
} while (/*CONSTCOND*/ 0)

#define KEY_CHKSPDIR(head, sp, name) \
do { \
	if ((head) != (sp)) {						\
		ipseclog((LOG_DEBUG, "%s: direction mismatched (TREE=%u SP=%u), " \
			"anyway continue.\n",				\
			(name), (head), (sp)));				\
	}								\
} while (/*CONSTCOND*/ 0)

#if 1
#define KMALLOC(p, t, n)                                                     \
	((p) = (t) malloc((unsigned long)(n), M_SECA, M_NOWAIT))
#define KFREE(p)                                                             \
	free((caddr_t)(p), M_SECA)
#else
#define KMALLOC(p, t, n) \
do { \
	((p) = (t)malloc((unsigned long)(n), M_SECA, M_NOWAIT));             \
	printf("%s %d: %p <- KMALLOC(%s, %d)\n",                             \
		__FILE__, __LINE__, (p), #t, n);                             \
} while (/*CONSTCOND*/ 0)

#define KFREE(p)                                                             \
	do {                                                                 \
		printf("%s %d: %p -> KFREE()\n", __FILE__, __LINE__, (p));   \
		free((caddr_t)(p), M_SECA);                                  \
	} while (/*CONSTCOND*/ 0)
#endif

/*
 * set parameters into secpolicyindex buffer.
 * Must allocate secpolicyindex buffer passed to this function.
 */
#define KEY_SETSECSPIDX(s, d, ps, pd, ulp, idx) \
do { \
	bzero((idx), sizeof(struct secpolicyindex));                             \
	(idx)->prefs = (ps);                                                 \
	(idx)->prefd = (pd);                                                 \
	(idx)->ul_proto = (ulp);                                             \
	bcopy((s), &(idx)->src, ((struct sockaddr *)(s))->sa_len);           \
	bcopy((d), &(idx)->dst, ((struct sockaddr *)(d))->sa_len);           \
} while (/*CONSTCOND*/ 0)

/*
 * set parameters into secasindex buffer.
 * Must allocate secasindex buffer before calling this function.
 */
#define KEY_SETSECASIDX(p, m, r, s, d, idx) \
do { \
	bzero((idx), sizeof(struct secasindex));                             \
	(idx)->proto = (p);                                                  \
	(idx)->mode = (m);                                                   \
	(idx)->reqid = (r);                                                  \
	bcopy((s), &(idx)->src, ((struct sockaddr *)(s))->sa_len);           \
	bcopy((d), &(idx)->dst, ((struct sockaddr *)(d))->sa_len);           \
} while (/*CONSTCOND*/ 0)

/* key statistics */
struct _keystat {
	u_long getspi_count; /* the avarage of count to try to get new SPI */
} keystat;

struct sadb_msghdr {
	struct sadb_msg *msg;
	struct sadb_ext *ext[SADB_EXT_MAX + 1];
	int extoff[SADB_EXT_MAX + 1];
	int extlen[SADB_EXT_MAX + 1];
};

static struct secasvar *key_allocsa_policy(struct secasindex *);
static struct secasvar *key_do_allocsa_policy(struct secashead *, u_int);
static void key_delsav(struct secasvar *);
static void key_delsp(struct secpolicy *);
static struct secpolicy *key_getsp(struct secpolicyindex *, int);
#if NPF > 0
static struct secpolicy *key_getspbytag(u_int16_t, int);
#endif
static u_int16_t key_newreqid(void);
static struct mbuf *key_gather_mbuf(struct mbuf *,
	const struct sadb_msghdr *, int, int, ...);
static int key_spdadd(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spddelete(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spddelete2(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spdget(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spdflush(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spddump(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
#if defined(__NetBSD__) || defined(__OpenBSD__)
static struct mbuf *key_setspddump(int *);
#endif
static u_int key_getspreqmsglen(struct secpolicy *);
static int key_spdexpire(struct secpolicy *);
static struct secashead *key_newsah(struct secasindex *);
static void key_delsah(struct secashead *);
static struct secasvar *key_newsav(struct mbuf *,
	const struct sadb_msghdr *, struct secashead *, int *);
static struct secashead *key_getsah(struct secasindex *);
static struct secasvar *key_checkspidup(struct secasindex *, u_int32_t);
static void key_setspi(struct secasvar *, u_int32_t);
static struct secasvar *key_getsavbyspi(struct secashead *, u_int32_t);
static int key_setsaval(struct secasvar *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_mature(struct secasvar *);
static struct mbuf *key_setdumpsa(struct secasvar *, u_int8_t,
	u_int8_t, u_int32_t, u_int32_t);
static struct mbuf *key_setsadbmsg(u_int8_t, u_int16_t, u_int8_t,
	u_int32_t, pid_t, u_int16_t);
static struct mbuf *key_setsadbsa(struct secasvar *);
static struct mbuf *key_setsadbaddr(u_int16_t,
	struct sockaddr *, u_int8_t, u_int16_t);
#if 0
static struct mbuf *key_setsadbident(u_int16_t, u_int16_t, caddr_t,
	int, u_int64_t);
#endif
static struct mbuf *key_setsadbxsa2(u_int8_t, u_int32_t, u_int16_t);
static struct mbuf *key_setsadbxtag(u_int16_t);
static struct mbuf *key_setsadblifetime(u_int16_t, u_int32_t,
	u_int64_t, u_int64_t, u_int64_t);
static struct mbuf *key_setsadbxpolicy(u_int16_t, u_int8_t,
	u_int32_t);
static void *key_newbuf(const void *, u_int);
static int key_ismyaddr(struct sockaddr *);
#ifdef INET6
static int key_ismyaddr6(struct sockaddr_in6 *);
#endif

/* flags for key_cmpsaidx() */
#define CMP_HEAD	1	/* protocol, addresses. */
#define CMP_MODE_REQID	2	/* additionally HEAD, reqid, mode. */
#define CMP_REQID	3	/* additionally HEAD, reqid. not used */
#define CMP_EXACTLY	4	/* all elements. */
static int key_cmpsaidx(struct secasindex *, struct secasindex *, int);

static int key_sockaddrcmp(struct sockaddr *, struct sockaddr *, int);
static int key_bbcmp(caddr_t, caddr_t, u_int);
static u_long key_random(void);
static u_int16_t key_satype2proto(u_int8_t);
static u_int8_t key_proto2satype(u_int16_t);

static int key_getspi(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static u_int32_t key_do_getnewspi(struct sadb_spirange *,
					struct secasindex *);
static int key_update(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
#ifdef IPSEC_DOSEQCHECK
static struct secasvar *key_getsavbyseq(struct secashead *, u_int32_t);
#endif
static int key_add(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_setident(struct secashead *, struct mbuf *,
	const struct sadb_msghdr *);
static struct mbuf *key_getmsgbuf_x1(struct mbuf *,
	const struct sadb_msghdr *);
static int key_delete(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_get(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);

static void key_getcomb_setlifetime(struct sadb_comb *);
#ifdef IPSEC_ESP
static struct mbuf *key_getcomb_esp(void);
#endif
static struct mbuf *key_getcomb_ah(void);
static struct mbuf *key_getcomb_ipcomp(void);
static struct mbuf *key_getprop(const struct secasindex *);

#ifdef PFKEYV2_SADB_X_EXT_PACKET
static int key_acquire(struct secasindex *, struct secpolicy *,
	struct mbuf *);
#else
static int key_acquire(struct secasindex *, struct secpolicy *);
#endif
#ifndef IPSEC_NONBLOCK_ACQUIRE
static struct secacq *key_newacq(struct secasindex *);
static struct secacq *key_getacq(struct secasindex *);
static struct secacq *key_getacqbyseq(u_int32_t);
#endif
static struct secspacq *key_newspacq(struct secpolicyindex *);
static struct secspacq *key_getspacq(struct secpolicyindex *);
static int key_acquire2(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_register(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_expire(struct secasvar *);
static int key_flush(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_dump(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
#if defined(__NetBSD__) || defined(__OpenBSD__)
static struct mbuf *key_setdump(u_int8_t, int *);
#endif
static int key_promisc(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_senderror(struct socket *, struct mbuf *, int);
static int key_validate_ext(/*const */struct sadb_ext *, int);
static int key_align(struct mbuf *, struct sadb_msghdr *);
#if 0
static const char *key_getfqdn(void);
static const char *key_getuserfqdn(void);
#endif
static void key_sa_chgstate(struct secasvar *, u_int8_t);
static void key_sp_dead(struct secpolicy *);
static void key_sp_unlink(struct secpolicy *);
static struct mbuf *key_alloc_mbuf(int);
#if defined(__NetBSD__) || defined(__FreeBSD__)
struct callout key_timehandler_ch;
#endif
#ifdef MIP6
static struct mbuf *key_setmigrate(struct secpolicy *, struct sockaddr *,
    struct sockaddr *, struct ipsecrequest *, u_int32_t, u_int32_t);
#endif /* MIP6 */


/* %%% IPsec policy management */
/*
 * allocating a SP for OUTBOUND or INBOUND packet.
 * Must call key_freesp() later.
 * OUT:	NULL:	not found
 *	others:	found and return the pointer.
 */
struct secpolicy *
key_allocsp(u_int16_t tag, struct secpolicyindex *spidx, u_int dir)
{
	struct secpolicy *sp;
	int s;

	/* check direction */
	switch (dir) {
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		panic("key_allocsp: Invalid direction is passed.");
	}

	/* get a SP entry */
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif
	if (spidx) {
		KEYDEBUG(KEYDEBUG_IPSEC_DATA,
			printf("*** objects\n");
			kdebug_secpolicyindex(spidx));
	}

	LIST_FOREACH(sp, &sptree[dir], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (!sp->spidx) {
			if (!tag)
				continue;
			if (sp->tag == tag)
				goto found;
		} else {
			if (!spidx)
				continue;

			KEYDEBUG(KEYDEBUG_IPSEC_DATA,
				printf("*** in SPD\n");
				kdebug_secpolicyindex(sp->spidx));

			if (key_cmpspidx_withmask(sp->spidx, spidx))
				goto found;
		}
	}

	splx(s);
	return NULL;

found:
	/* sanity check */
	KEY_CHKSPDIR(sp->dir, dir, "key_allocsp");

	/* found a SPD entry */
#ifdef __FreeBSD__
	sp->lastused = time_second;
#else
	sp->lastused = time.tv_sec;
#endif
	sp->refcnt++;
	splx(s);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP key_allocsp cause refcnt++:%d SP:%p\n",
			sp->refcnt, sp));

	return sp;
}

/*
 * return a policy that matches this particular inbound packet.
 * XXX slow
 */
struct secpolicy *
key_gettunnel(struct sockaddr *osrc, struct sockaddr *odst,
	struct sockaddr *isrc, struct sockaddr *idst)
{
	struct secpolicy *sp;
	const int dir = IPSEC_DIR_INBOUND;
	int s;
	struct ipsecrequest *r1, *r2, *p;
	struct sockaddr *os, *od, *is, *id;
	struct secpolicyindex spidx;

	if (isrc->sa_family != idst->sa_family) {
		ipseclog((LOG_ERR, "protocol family mismatched %u != %u\n",
			isrc->sa_family, idst->sa_family));
		return NULL;
	}

#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif
	LIST_FOREACH(sp, &sptree[dir], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;

		r1 = r2 = NULL;
		for (p = sp->req; p; p = p->next) {
			if (p->saidx.mode != IPSEC_MODE_TUNNEL)
				continue;

			r1 = r2;
			r2 = p;

			if (!r1) {
				if (sp->spidx) {
					/*
					 * here we look at address matches
					 * only
					 */
					spidx = *sp->spidx;
					if (isrc->sa_len > sizeof(spidx.src) ||
					    idst->sa_len > sizeof(spidx.dst))
						continue;
					bcopy(isrc, &spidx.src, isrc->sa_len);
					bcopy(idst, &spidx.dst, idst->sa_len);
					if (!key_cmpspidx_withmask(sp->spidx,
					    &spidx))
						continue;
				} else
					; /* can't check for tagged policy */
			} else {
				is = (struct sockaddr *)&r1->saidx.src;
				id = (struct sockaddr *)&r1->saidx.dst;
				if (key_sockaddrcmp(is, isrc, 0) ||
				    key_sockaddrcmp(id, idst, 0))
					continue;
			}

			os = (struct sockaddr *)&r2->saidx.src;
			od = (struct sockaddr *)&r2->saidx.dst;
			if (key_sockaddrcmp(os, osrc, 0) ||
			    key_sockaddrcmp(od, odst, 0))
				continue;

			goto found;
		}
	}
	splx(s);
	return NULL;

found:
#ifdef __FreeBSD__
	sp->lastused = time_second;
#else
	sp->lastused = time.tv_sec;
#endif
	sp->refcnt++;
	splx(s);
	return sp;
}

/*
 * allocating an SA entry for an *OUTBOUND* packet.
 * checking each request entries in SP, and acquire an SA if need.
 * OUT:	0: there are valid requests.
 *	ENOENT: policy may be valid, but SA with REQUIRE is on acquiring.
 */
#ifdef PFKEYV2_SADB_X_EXT_PACKET
int
key_checkrequest(struct ipsecrequest *isr, struct secasindex *saidx,
	struct mbuf *pkt)
#else
int
key_checkrequest(struct ipsecrequest *isr, struct secasindex *saidx)
#endif
{
	u_int level;
	int error;

	/* sanity check */
	if (isr == NULL || saidx == NULL)
		panic("key_checkrequest: NULL pointer is passed.");

	/* check mode */
	switch (saidx->mode) {
	case IPSEC_MODE_TRANSPORT:
	case IPSEC_MODE_TUNNEL:
		break;
	case IPSEC_MODE_ANY:
	default:
		panic("key_checkrequest: Invalid policy defined.");
	}

	/* get current level */
	level = ipsec_get_reqlevel(isr, saidx->src.ss_family);

#if 0
	/*
	 * We do allocate new SA only if the state of SA in the holder is
	 * SADB_SASTATE_DEAD.  The SA for outbound must be the oldest.
	 */
	if (isr->sav != NULL) {
		if (isr->sav->sah == NULL)
			panic("key_checkrequest: sah is null.");
		if (isr->sav ==
		    LIST_FIRST(&isr->sav->sah->savtree[SADB_SASTATE_DEAD])) {
			KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				printf("DP checkrequest calls free SA:%p\n",
					isr->sav));
			key_freesav(isr->sav);
			isr->sav = NULL;
		}
	}
#else
	/*
	 * we free any SA stashed in the IPsec request because a different
	 * SA may be involved each time this request is checked, either
	 * because new SAs are being configured, or this request is
	 * associated with an unconnected datagram socket, or this request
	 * is associated with a system default policy.
	 *
	 * The operation may have negative impact to performance.  We may
	 * want to check cached SA carefully, rather than picking new SA
	 * every time.
	 */
	if (isr->sav != NULL) {
		key_freesav(isr->sav);
		isr->sav = NULL;
	}
#endif

	/*
	 * new SA allocation if no SA found.
	 * key_allocsa_policy should allocate the oldest SA available.
	 * See key_do_allocsa_policy(), and draft-jenkins-ipsec-rekeying-03.txt.
	 */
	if (isr->sav == NULL)
		isr->sav = key_allocsa_policy(saidx);

	/* When there is SA. */
	if (isr->sav != NULL)
		return 0;

	/* there is no SA */
#ifdef PFKEYV2_SADB_X_EXT_PACKET
	if ((error = key_acquire(saidx, isr->sp, pkt)) != 0)
#else
	if ((error = key_acquire(saidx, isr->sp)) != 0)
#endif
	{
		/* XXX What should I do ? */
		ipseclog((LOG_DEBUG, "key_checkrequest: error %d returned "
			"from key_acquire.\n", error));
		return error;
	}

	return level == IPSEC_LEVEL_REQUIRE ? ENOENT : 0;
}

/*
 * allocating a SA for policy entry from SAD.
 * NOTE: searching SAD of aliving state.
 * OUT:	NULL:	not found.
 *	others:	found and return the pointer.
 */
static struct secasvar *
key_allocsa_policy(struct secasindex *saidx)
{
	struct secashead *sah;
	struct secasvar *sav;
	u_int stateidx, state;
	const u_int *saorder_state_valid;
	int arraysize;

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, saidx, CMP_MODE_REQID))
			goto found;
	}

	return NULL;

    found:

	/*
	 * search a valid state list for outbound packet.
	 * This search order is important.
	 */
	if (key_preferred_oldsa) {
		saorder_state_valid = saorder_state_valid_prefer_old;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_old);
	} else {
		saorder_state_valid = saorder_state_valid_prefer_new;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_new);
	}

	for (stateidx = 0; stateidx < arraysize; stateidx++) {

		state = saorder_state_valid[stateidx];

		sav = key_do_allocsa_policy(sah, state);
		if (sav != NULL)
			return sav;
	}

	return NULL;
}

/*
 * searching SAD with direction, protocol, mode and state.
 * called by key_allocsa_policy().
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secasvar *
key_do_allocsa_policy(struct secashead *sah, u_int state)
{
	struct secasvar *sav, *nextsav, *candidate, *d;

	/* initilize */
	candidate = NULL;

	for (sav = LIST_FIRST(&sah->savtree[state]);
	     sav != NULL;
	     sav = nextsav) {

		nextsav = LIST_NEXT(sav, chain);

		/* sanity check */
		KEY_CHKSASTATE(sav->state, state, "key_do_allocsa_policy");

		/* initialize */
		if (candidate == NULL) {
			candidate = sav;
			continue;
		}

		/* Which SA is the better ? */

		/* sanity check 2 */
		if (candidate->lft_c == NULL || sav->lft_c == NULL)
			panic("key_do_allocsa_policy: "
				"lifetime_current is NULL.\n");

		/* What the best method is to compare ? */
		if (key_preferred_oldsa) {
			if (candidate->lft_c->sadb_lifetime_addtime >
					sav->lft_c->sadb_lifetime_addtime) {
				candidate = sav;
			}
			continue;
			/*NOTREACHED*/
		}

		/* preferred new sa rather than old sa */
		if (candidate->lft_c->sadb_lifetime_addtime <
				sav->lft_c->sadb_lifetime_addtime) {
			d = candidate;
			candidate = sav;
		} else
			d = sav;

		/*
		 * prepared to delete the SA when there is more
		 * suitable candidate and the lifetime of the SA is not
		 * permanent.
		 */
		if (d->lft_h->sadb_lifetime_addtime != 0) {
			struct mbuf *m, *result = NULL;

			key_sa_chgstate(d, SADB_SASTATE_DEAD);

			m = key_setsadbmsg(SADB_DELETE, 0,
			    key_proto2satype(d->sah->saidx.proto),
			    0, 0, d->refcnt - 1);
			if (!m)
				goto msgfail;
			result = m;

			/* set sadb_address for saidx's. */
			m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
				(struct sockaddr *)&d->sah->saidx.src,
				FULLMASK, IPSEC_ULPROTO_ANY);
			if (!m)
				goto msgfail;
			m_cat(result, m);

			/* set sadb_address for saidx's. */
			m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
				(struct sockaddr *)&d->sah->saidx.dst,
				FULLMASK, IPSEC_ULPROTO_ANY);
			if (!m)
				goto msgfail;
			m_cat(result, m);

			/* create SA extension */
			m = key_setsadbsa(d);
			if (!m)
				goto msgfail;
			m_cat(result, m);

			if (result->m_len < sizeof(struct sadb_msg)) {
				result = m_pullup(result,
						sizeof(struct sadb_msg));
				if (result == NULL)
					goto msgfail;
			}

			result->m_pkthdr.len = 0;
			for (m = result; m; m = m->m_next)
				result->m_pkthdr.len += m->m_len;
			mtod(result, struct sadb_msg *)->sadb_msg_len =
				PFKEY_UNIT64(result->m_pkthdr.len);

			if (key_sendup_mbuf(NULL, result,
					KEY_SENDUP_REGISTERED))
				goto msgfail;

			result = NULL;

		 msgfail:
			if (result != NULL)
				m_freem(result);
			key_freesav(d);
		}
	}

	if (candidate) {
		candidate->refcnt++;
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP allocsa_policy cause "
				"refcnt++:%d SA:%p\n",
				candidate->refcnt, candidate));
	}
	return candidate;
}

/*
 * allocating a SA entry for a *INBOUND* packet.
 * Must call key_freesav() later.
 * OUT: positive:	pointer to a sav.
 *	NULL:		not found, or error occured.
 *
 * In the comparison, source address will be ignored for RFC2401 conformance.
 * To quote, from section 4.1:
 *	A security association is uniquely identified by a triple consisting
 *	of a Security Parameter Index (SPI), an IP Destination Address, and a
 *	security protocol (AH or ESP) identifier.
 * Note that, however, we do need to keep source address in IPsec SA.
 * IKE specification and PF_KEY specification do assume that we
 * keep source address in IPsec SA.  We see a tricky situation here.
 *
 * BEWARE: src and dst are in_addr * if family == AF_INET, and sockaddr_in6 *
 * if family == AF_INET6.
 */
struct secasvar *
key_allocsa(u_int family, caddr_t src, caddr_t dst, u_int proto, u_int32_t spi)
{
	struct secasvar *sav, *match;
	u_int stateidx, state, tmpidx, matchidx;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	int s;
	const u_int *saorder_state_valid;
	int arraysize;
#if 0
/* racoon2 guys want us to update ipsecdb. (2004.10.8 keiichi) */
#if defined(MIP6) && NMIP > 0
	struct mip6_bul_internal *bul = NULL;
#endif
#endif

	/* sanity check */
	if (src == NULL || dst == NULL)
		panic("key_allocsa: NULL pointer is passed.");

	/*
	 * when both systems employ similar strategy to use a SA.
	 * the search order is important even in the inbound case.
	 */
	if (key_preferred_oldsa) {
		saorder_state_valid = saorder_state_valid_prefer_old;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_old);
	} else {
		saorder_state_valid = saorder_state_valid_prefer_new;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_new);
	}

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);

	/*
	 * searching SAD.
	 * XXX: to be checked internal IP header somewhere.  Also when
	 * IPsec tunnel packet is received.  But ESP tunnel mode is
	 * encrypted so we can't check internal IP header.
	 */
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif
	/*
	 * search a valid state list for inbound packet.
	 * the search order is not important.
	 */
	match = NULL;
	matchidx = arraysize;
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		if (proto != sav->sah->saidx.proto)
			continue;
		if (family != sav->sah->saidx.src.ss_family ||
		    family != sav->sah->saidx.dst.ss_family)
			continue;
		tmpidx = arraysize;
		for (stateidx = 0; stateidx < matchidx; stateidx++) {
			state = saorder_state_valid[stateidx];
			if (sav->state == state) {
				tmpidx = stateidx;
				break;
			}
		}
		if (tmpidx >= matchidx)
			continue;

#if 0	/* don't check src */
		/* check src address */
		switch (family) {
		case AF_INET:
			bcopy(src, &sin.sin_addr, sizeof(sin.sin_addr));
			if (key_sockaddrcmp((struct sockaddr*)&sin,
			    (struct sockaddr *)&sav->sah->saidx.src, 0) != 0)
				continue;

			break;
		case AF_INET6:
			sin6.sin6_addr = *src;
			sin6.sin6_scope_id = 0;
			if (sa6_recoverscope(&sin6))
				continue;
			if (key_sockaddrcmp((struct sockaddr *)&sin6,
			    (struct sockaddr *)&sav->sah->saidx.src, 0) != 0)
				continue;
			break;
		default:
			ipseclog((LOG_DEBUG, "key_allocsa: "
			    "unknown address family=%d.\n",
			    family));
			continue;
		}

#endif
		/* check dst address */
		switch (family) {
		case AF_INET:
			bcopy(dst, &sin.sin_addr, sizeof(sin.sin_addr));
			if (key_sockaddrcmp((struct sockaddr*)&sin,
			    (struct sockaddr *)&sav->sah->saidx.dst, 0) != 0)
				continue;

			break;
		case AF_INET6:
			sin6.sin6_addr = *(struct in6_addr *)dst;
			sin6.sin6_scope_id = 0;
			if (sa6_recoverscope(&sin6))
				continue;
#if 0
/* racoon2 guys want us to update ipsecdb. (2004.10.8 keiichi) */
#if defined(MIP6) && NMIP > 0
			/* 
			 * If packet't proto is MH, need to fake the
			 * comparison of odst.
			 * 
			 * 1. search binding update list with the SA.
			 * 2. if found, compare odst with found CoA 
			 * 3. if it does match, use the SA
			 * 4. Otherwise, the SA is not for this packet.
			 */

			bul = mip6_bul_get_home_agent(&((struct sockaddr_in6 *)&sav->sah->saidx.dst)->sin6_addr);
			if (bul && 
			    IN6_ARE_ADDR_EQUAL(&bul->mbul_coa, 
					       (struct in6_addr *)dst)) { 
				printf("matched SA found\n");
				break;
			} else 
#endif
#endif
			if (key_sockaddrcmp((struct sockaddr *)&sin6,
					    (struct sockaddr *)&sav->sah->saidx.dst, 0) != 0) {
				printf("dst: %s\n", ip6_sprintf((struct in6_addr *)dst));
				printf("SA dst: %s\n", ip6_sprintf(&((struct sockaddr_in6 *)&sav->sah->saidx.dst)->sin6_addr));
				continue;
			}

			break;
		default:
			ipseclog((LOG_DEBUG, "key_allocsa: "
			    "unknown address family=%d.\n", family));
			continue;
		}

		match = sav;
		matchidx = tmpidx;
	}

	if (match)
		goto found;

	/* not found */
	splx(s);
	return NULL;

found:
	match->refcnt++;
	splx(s);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP allocsa cause refcnt++:%d SA:%p\n",
			match->refcnt, match));
	return match;
}

/*
 * Must be called after calling key_allocsp().
 * For both the packet without socket and key_freeso().
 */
void
key_freesp(struct secpolicy *sp)
{

	/* sanity check */
	if (sp == NULL)
		panic("key_freesp: NULL pointer is passed.");

	sp->refcnt--;
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP freesp cause refcnt--:%d SP:%p\n",
			sp->refcnt, sp));

	if (sp->refcnt == 0)
		key_delsp(sp);

	return;
}

/*
 * Must be called after calling key_allocsa().
 * This function is called by key_freesp() to free some SA allocated
 * for a policy.
 */
void
key_freesav(struct secasvar *sav)
{

	/* sanity check */
	if (sav == NULL)
		panic("key_freesav: NULL pointer is passed.");

	sav->refcnt--;
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP freesav cause refcnt--:%d SA:%p SPI %u\n",
			sav->refcnt, sav, (u_int32_t)ntohl(sav->spi)));

	if (sav->refcnt > 0)
		return;

	key_delsav(sav);
}

static void
key_delsav(struct secasvar *sav)
{
	int s;

	/* sanity check */
	if (sav == NULL)
		panic("key_delsav: NULL pointer is passed.");

	if (sav->refcnt > 0)
		panic("key_delsav: called with positive refcnt");

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif

#ifdef KERNFS
	kernfs_revoke_sa(sav);
#endif

	if (__LIST_CHAINED(sav))
		LIST_REMOVE(sav, chain);

	if (sav->spihash.le_prev || sav->spihash.le_next)
		LIST_REMOVE(sav, spihash);

	if (sav->key_auth != NULL) {
		bzero(_KEYBUF(sav->key_auth), _KEYLEN(sav->key_auth));
		KFREE(sav->key_auth);
		sav->key_auth = NULL;
	}
	if (sav->key_enc != NULL) {
		bzero(_KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc));
		KFREE(sav->key_enc);
		sav->key_enc = NULL;
	}
	if (sav->sched) {
		bzero(sav->sched, sav->schedlen);
		KFREE(sav->sched);
		sav->sched = NULL;
	}
	if (sav->replay != NULL) {
		keydb_delsecreplay(sav->replay);
		sav->replay = NULL;
	}
	if (sav->lft_c != NULL) {
		KFREE(sav->lft_c);
		sav->lft_c = NULL;
	}
	if (sav->lft_h != NULL) {
		KFREE(sav->lft_h);
		sav->lft_h = NULL;
	}
	if (sav->lft_s != NULL) {
		KFREE(sav->lft_s);
		sav->lft_s = NULL;
	}
	if (sav->iv != NULL) {
		KFREE(sav->iv);
		sav->iv = NULL;
	}

	keydb_delsecasvar(sav);

	splx(s);
}

/* %%% SPD management */
/*
 * free security policy entry.
 */
static void
key_delsp(struct secpolicy *sp)
{
	int s;

	/* sanity check */
	if (sp == NULL)
		panic("key_delsp: NULL pointer is passed.");

	if (sp->refcnt > 0)
		panic("key_delsp: called with positive refcnt");

#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

#ifdef KERNFS
	kernfs_revoke_sp(sp);
#endif

    {
	struct ipsecrequest *isr = sp->req, *nextisr;

	while (isr != NULL) {
		if (isr->sav != NULL) {
			KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				printf("DP delsp calls free SA:%p\n",
					isr->sav));
			key_freesav(isr->sav);
			isr->sav = NULL;
		}

		nextisr = isr->next;
		KFREE(isr);
		isr = nextisr;
	}
    }

	keydb_delsecpolicy(sp);

	splx(s);

	return;
}

/*
 * search SPD
 * OUT:	NULL	: not found
 *	others	: found, pointer to a SP.
 */
static struct secpolicy *
key_getsp(struct secpolicyindex *spidx, int dir)
{
	struct secpolicy *sp;

	/* sanity check */
	if (spidx == NULL)
		panic("key_getsp: NULL pointer is passed.");

	LIST_FOREACH(sp, &sptree[dir], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (!sp->spidx)
			continue;
		if (key_cmpspidx_exactly(spidx, sp->spidx)) {
			sp->refcnt++;
			return sp;
		}
	}

	return NULL;
}

#if NPF > 0
static struct secpolicy *
key_getspbytag(u_int16_t tag, int dir)
{
	struct secpolicy *sp;

	LIST_FOREACH(sp, &sptree[dir], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (sp->spidx)
			continue;
		if (sp->tag == tag) {
			sp->refcnt++;
			return sp;
		}
	}

	return NULL;
}
#endif

/*
 * get SP by index.
 * OUT:	NULL	: not found
 *	others	: found, pointer to a SP.
 */
struct secpolicy *
key_getspbyid(u_int32_t id)
{
	struct secpolicy *sp;

	TAILQ_FOREACH(sp, &sptailq, tailq) {
		if (sp->id == id) {
			sp->refcnt++;
			return sp;
		}
	}

	return NULL;
}

struct secpolicy *
key_newsp(u_int32_t id)
{
	struct secpolicy *newsp = NULL, *sp;
	u_int32_t newid;

	if (id > IPSEC_MANUAL_POLICYID_MAX) {
		ipseclog((LOG_DEBUG,
		    "key_newsp: policy_id=%u range "
		    "violation, updated by kernel.\n", id));
		id = 0;
	}

	if (id == 0) {
		if ((newid = keydb_newspid()) == 0) {
			ipseclog((LOG_DEBUG, 
			    "key_newsp: new policy_id allocation failed."));
			return NULL;
		}
	} else {
		sp = key_getspbyid(id);
		if (sp != NULL) {
			ipseclog((LOG_DEBUG,
			    "key_newsp: policy_id(%u) has been used.\n", id));
			key_freesp(sp);
			return NULL;
		}
		newid = id;
	}

	newsp = keydb_newsecpolicy();
	if (!newsp)
		return newsp;

	newsp->id = newid;
	newsp->refcnt = 1;
	newsp->req = NULL;

	return newsp;
}

/*
 * create secpolicy structure from sadb_x_policy structure.
 * NOTE: `state', `secpolicyindex' in secpolicy structure are not set,
 * so must be set properly later.
 */
struct secpolicy *
key_msg2sp(struct sadb_x_policy *xpl0, size_t len, int *error)
{
	struct secpolicy *newsp;

	/* sanity check */
	if (xpl0 == NULL)
		panic("key_msg2sp: NULL pointer was passed.");
	if (len < sizeof(*xpl0))
		panic("key_msg2sp: invalid length.");
	if (len != PFKEY_EXTLEN(xpl0)) {
		ipseclog((LOG_DEBUG, "key_msg2sp: Invalid msg length.\n"));
		*error = EINVAL;
		return NULL;
	}

	if ((newsp = key_newsp(xpl0->sadb_x_policy_id)) == NULL) {
		*error = ENOBUFS;
		return NULL;
	}

	newsp->dir = xpl0->sadb_x_policy_dir;
	newsp->policy = xpl0->sadb_x_policy_type;

	/* check policy */
	switch (xpl0->sadb_x_policy_type) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_NONE:
	case IPSEC_POLICY_ENTRUST:
	case IPSEC_POLICY_BYPASS:
		newsp->req = NULL;
		break;

	case IPSEC_POLICY_IPSEC:
	    {
		int tlen;
		struct sadb_x_ipsecrequest *xisr;
		struct ipsecrequest **p_isr = &newsp->req;

		/* validity check */
		if (PFKEY_EXTLEN(xpl0) < sizeof(*xpl0)) {
			ipseclog((LOG_DEBUG,
			    "key_msg2sp: Invalid msg length.\n"));
			key_freesp(newsp);
			*error = EINVAL;
			return NULL;
		}

		tlen = PFKEY_EXTLEN(xpl0) - sizeof(*xpl0);
		xisr = (struct sadb_x_ipsecrequest *)(xpl0 + 1);

		while (tlen > 0) {

			/* length check */
			if (xisr->sadb_x_ipsecrequest_len < sizeof(*xisr)) {
				ipseclog((LOG_DEBUG, "key_msg2sp: "
					"invalid ipsecrequest length.\n"));
				key_freesp(newsp);
				*error = EINVAL;
				return NULL;
			}

			/* allocate request buffer */
			KMALLOC(*p_isr, struct ipsecrequest *, sizeof(**p_isr));
			if ((*p_isr) == NULL) {
				ipseclog((LOG_DEBUG,
				    "key_msg2sp: No more memory.\n"));
				key_freesp(newsp);
				*error = ENOBUFS;
				return NULL;
			}
			bzero(*p_isr, sizeof(**p_isr));

			/* set values */
			(*p_isr)->next = NULL;

			switch (xisr->sadb_x_ipsecrequest_proto) {
			case IPPROTO_ESP:
			case IPPROTO_AH:
			case IPPROTO_IPCOMP:
				break;
			default:
				ipseclog((LOG_DEBUG,
				    "key_msg2sp: invalid proto type=%u\n",
				    xisr->sadb_x_ipsecrequest_proto));
				key_freesp(newsp);
				*error = EPROTONOSUPPORT;
				return NULL;
			}
			(*p_isr)->saidx.proto = xisr->sadb_x_ipsecrequest_proto;

			switch (xisr->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
			case IPSEC_MODE_TUNNEL:
				break;
			case IPSEC_MODE_ANY:
			default:
				ipseclog((LOG_DEBUG,
				    "key_msg2sp: invalid mode=%u\n",
				    xisr->sadb_x_ipsecrequest_mode));
				key_freesp(newsp);
				*error = EINVAL;
				return NULL;
			}
			(*p_isr)->saidx.mode = xisr->sadb_x_ipsecrequest_mode;

			switch (xisr->sadb_x_ipsecrequest_level) {
			case IPSEC_LEVEL_DEFAULT:
			case IPSEC_LEVEL_USE:
			case IPSEC_LEVEL_REQUIRE:
				break;
			case IPSEC_LEVEL_UNIQUE:
				/* validity check */
				/*
				 * If range violation of reqid, kernel will
				 * update it, don't refuse it.
				 */
				if (xisr->sadb_x_ipsecrequest_reqid
						> IPSEC_MANUAL_REQID_MAX) {
					ipseclog((LOG_DEBUG,
					    "key_msg2sp: reqid=%u range "
					    "violation, updated by kernel.\n",
					    xisr->sadb_x_ipsecrequest_reqid));
					xisr->sadb_x_ipsecrequest_reqid = 0;
				}

				/* allocate new reqid id if reqid is zero. */
				if (xisr->sadb_x_ipsecrequest_reqid == 0) {
					u_int16_t reqid;
					if ((reqid = key_newreqid()) == 0) {
						key_freesp(newsp);
						*error = ENOBUFS;
						return NULL;
					}
					(*p_isr)->saidx.reqid = reqid;
					xisr->sadb_x_ipsecrequest_reqid = reqid;
				} else {
				/* set it for manual keying. */
					(*p_isr)->saidx.reqid =
						xisr->sadb_x_ipsecrequest_reqid;
				}
				break;

			default:
				ipseclog((LOG_DEBUG, "key_msg2sp: invalid level=%u\n",
					xisr->sadb_x_ipsecrequest_level));
				key_freesp(newsp);
				*error = EINVAL;
				return NULL;
			}
			(*p_isr)->level = xisr->sadb_x_ipsecrequest_level;

			/* set IP addresses if there */
			if (xisr->sadb_x_ipsecrequest_len > sizeof(*xisr)) {
				struct sockaddr *paddr;

				paddr = (struct sockaddr *)(xisr + 1);

				/* validity check */
				if (paddr->sa_len
				    > sizeof((*p_isr)->saidx.src)) {
					ipseclog((LOG_DEBUG, "key_msg2sp: invalid request "
						"address length.\n"));
					key_freesp(newsp);
					*error = EINVAL;
					return NULL;
				}
				bcopy(paddr, &(*p_isr)->saidx.src,
					paddr->sa_len);

				paddr = (struct sockaddr *)((caddr_t)paddr
							+ paddr->sa_len);

				/* validity check */
				if (paddr->sa_len
				    > sizeof((*p_isr)->saidx.dst)) {
					ipseclog((LOG_DEBUG, "key_msg2sp: invalid request "
						"address length.\n"));
					key_freesp(newsp);
					*error = EINVAL;
					return NULL;
				}
				bcopy(paddr, &(*p_isr)->saidx.dst,
					paddr->sa_len);
			}

			(*p_isr)->sav = NULL;
			(*p_isr)->sp = newsp;

			/* initialization for the next. */
			p_isr = &(*p_isr)->next;
			tlen -= xisr->sadb_x_ipsecrequest_len;

			/* validity check */
			if (tlen < 0) {
				ipseclog((LOG_DEBUG, "key_msg2sp: becoming tlen < 0.\n"));
				key_freesp(newsp);
				*error = EINVAL;
				return NULL;
			}

			xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
			                 + xisr->sadb_x_ipsecrequest_len);
		}
	    }
		break;
	default:
		ipseclog((LOG_DEBUG, "key_msg2sp: invalid policy type.\n"));
		key_freesp(newsp);
		*error = EINVAL;
		return NULL;
	}

	*error = 0;
	return newsp;
}

static u_int16_t
key_newreqid(void)
{
	static u_int16_t auto_reqid = IPSEC_MANUAL_REQID_MAX + 1;

	auto_reqid = (auto_reqid == 0xffff
	    ? IPSEC_MANUAL_REQID_MAX + 1 : auto_reqid + 1);

	/* XXX should be unique check */

	return auto_reqid;
}

/*
 * copy secpolicy struct to sadb_x_policy structure indicated.
 */
struct mbuf *
key_sp2msg(struct secpolicy *sp)
{
	struct sadb_x_policy *xpl;
	int tlen;
	caddr_t p;
	struct mbuf *m;

	/* sanity check. */
	if (sp == NULL)
		panic("key_sp2msg: NULL pointer was passed.");

	tlen = key_getspreqmsglen(sp);

	m = key_alloc_mbuf(tlen);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	m->m_len = tlen;
	m->m_next = NULL;
	xpl = mtod(m, struct sadb_x_policy *);
	bzero(xpl, tlen);

	xpl->sadb_x_policy_len = PFKEY_UNIT64(tlen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = sp->policy;
	xpl->sadb_x_policy_dir = sp->dir;
	xpl->sadb_x_policy_id = sp->id;
	p = (caddr_t)xpl + sizeof(*xpl);

	/* if is the policy for ipsec ? */
	if (sp->policy == IPSEC_POLICY_IPSEC) {
		struct sadb_x_ipsecrequest *xisr;
		struct ipsecrequest *isr;

		for (isr = sp->req; isr != NULL; isr = isr->next) {

			xisr = (struct sadb_x_ipsecrequest *)p;

			xisr->sadb_x_ipsecrequest_proto = isr->saidx.proto;
			xisr->sadb_x_ipsecrequest_mode = isr->saidx.mode;
			xisr->sadb_x_ipsecrequest_level = isr->level;
			xisr->sadb_x_ipsecrequest_reqid = isr->saidx.reqid;

			p += sizeof(*xisr);
			bcopy(&isr->saidx.src, p, isr->saidx.src.ss_len);
			p += isr->saidx.src.ss_len;
			bcopy(&isr->saidx.dst, p, isr->saidx.dst.ss_len);
			p += isr->saidx.src.ss_len;

			xisr->sadb_x_ipsecrequest_len =
			    PFKEY_ALIGN8(sizeof(*xisr) +
			    isr->saidx.src.ss_len + isr->saidx.dst.ss_len);
		}
	}

	return m;
}

/* m will not be freed nor modified */
static struct mbuf *
#ifdef __STDC__
key_gather_mbuf(struct mbuf *m, const struct sadb_msghdr *mhp,
	int ndeep, int nitem, ...)
#else
key_gather_mbuf(struct mbuf *m, const struct sadb_msghdr *mhp, int ndeep,
	int nitem, va_alist)
#endif
{
	va_list ap;
	int idx;
	int i;
	struct mbuf *result = NULL, *n;
	int len;

	if (m == NULL || mhp == NULL)
		panic("null pointer passed to key_gather");

	va_start(ap, nitem);
	for (i = 0; i < nitem; i++) {
		idx = va_arg(ap, int);
		if (idx < 0 || idx > SADB_EXT_MAX)
			goto fail;
		/* don't attempt to pull empty extension */
		if (idx == SADB_EXT_RESERVED && mhp->msg == NULL)
			continue;
		if (idx != SADB_EXT_RESERVED  &&
		    (mhp->ext[idx] == NULL || mhp->extlen[idx] == 0))
			continue;

		if (idx == SADB_EXT_RESERVED) {
			len = PFKEY_ALIGN8(sizeof(struct sadb_msg));
#ifdef DIAGNOSTIC
			if (len > MHLEN)
				panic("assumption failed");
#endif
			MGETHDR(n, M_DONTWAIT, MT_DATA);
			if (!n)
				goto fail;
			n->m_len = len;
			n->m_next = NULL;
			m_copydata(m, 0, sizeof(struct sadb_msg),
			    mtod(n, caddr_t));
		} else if (i < ndeep) {
			len = mhp->extlen[idx];
			n = key_alloc_mbuf(len);
			if (!n || n->m_next) {	/*XXX*/
				if (n)
					m_freem(n);
				goto fail;
			}
			m_copydata(m, mhp->extoff[idx], mhp->extlen[idx],
			    mtod(n, caddr_t));
		} else {
			n = m_copym(m, mhp->extoff[idx], mhp->extlen[idx],
			    M_DONTWAIT);
		}
		if (n == NULL)
			goto fail;

		if (result)
			m_cat(result, n);
		else
			result = n;
	}
	va_end(ap);

	if ((result->m_flags & M_PKTHDR) != 0) {
		result->m_pkthdr.len = 0;
		for (n = result; n; n = n->m_next)
			result->m_pkthdr.len += n->m_len;
	}

	return result;

fail:
	va_end(ap);
	m_freem(result);
	return NULL;
}

/*
 * SADB_X_SPDADD, SADB_X_SPDSETIDX or SADB_X_SPDUPDATE processing
 * add an entry to SP database, when received
 *   <base, address(SD), (lifetime(H),) policy>
 * from the user(?).
 * Adding to SP database,
 * and send
 *   <base, address(SD), (lifetime(H),) policy>
 * to the socket which was send.
 *
 * SPDADD set a unique policy entry.
 * SPDSETIDX like SPDADD without a part of policy requests.
 * SPDUPDATE replace a unique policy entry.
 *
 * m will always be freed.
 */
static int
key_spdadd(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_address *src0 = NULL, *dst0 = NULL;
	struct sadb_x_policy *xpl0, *xpl;
	struct sadb_lifetime *lft = NULL;
	struct sadb_x_tag *tag = NULL;
	struct secpolicyindex spidx;
	struct secpolicy *newsp;
	struct ipsecrequest *isr;
	int error;
#if NPF > 0
	u_int16_t tagvalue = 0;
#endif
	int spidxmode;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spdadd: NULL pointer is passed.");

	if ((mhp->ext[SADB_EXT_ADDRESS_SRC] != NULL &&
	     mhp->ext[SADB_EXT_ADDRESS_DST] != NULL) ||
	    mhp->ext[SADB_X_EXT_TAG] != NULL) {
		;
	} else {
		ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
#if NPF == 0
	if (mhp->ext[SADB_X_EXT_TAG] != NULL) {
		ipseclog((LOG_DEBUG, "key_spdadd: tag not supported.\n"));
		return key_senderror(so, m, EOPNOTSUPP);
	}
#endif
	if (mhp->ext[SADB_X_EXT_POLICY] == NULL) {
		ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if ((mhp->extlen[SADB_EXT_ADDRESS_SRC] &&
	     mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address)) ||
	    (mhp->extlen[SADB_EXT_ADDRESS_DST] &&
	     mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) ||
	    (mhp->extlen[SADB_X_EXT_TAG] &&
	     mhp->extlen[SADB_X_EXT_TAG] < sizeof(struct sadb_x_tag)) ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_EXT_LIFETIME_HARD] != NULL) {
		if (mhp->extlen[SADB_EXT_LIFETIME_HARD]
			< sizeof(struct sadb_lifetime)) {
			ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
			return key_senderror(so, m, EINVAL);
		}
		lft = (struct sadb_lifetime *)mhp->ext[SADB_EXT_LIFETIME_HARD];
	}

	/* spidx mode, or tag mode */
	spidxmode = (mhp->ext[SADB_EXT_ADDRESS_SRC] != NULL);

	if (spidxmode) {
		src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
		dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];
		/* make secindex */
		/* XXX boundary check against sa_len */
		KEY_SETSECSPIDX(src0 + 1, dst0 + 1,
		    src0->sadb_address_prefixlen, dst0->sadb_address_prefixlen,
		    src0->sadb_address_proto, &spidx);
	} else
		tag = (struct sadb_x_tag *)mhp->ext[SADB_X_EXT_TAG];
	xpl0 = (struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY];

	/* checking the direciton. */
	switch (xpl0->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		ipseclog((LOG_DEBUG, "key_spdadd: Invalid SP direction.\n"));
		mhp->msg->sadb_msg_errno = EINVAL;
		return 0;
	}

	/* check policy */
	/* key_spdadd() accepts DISCARD, NONE and IPSEC. */
	if (xpl0->sadb_x_policy_type == IPSEC_POLICY_ENTRUST ||
	    xpl0->sadb_x_policy_type == IPSEC_POLICY_BYPASS) {
		ipseclog((LOG_DEBUG, "key_spdadd: Invalid policy type.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* policy requests are mandatory when action is ipsec. */
	if (mhp->msg->sadb_msg_type != SADB_X_SPDSETIDX &&
	    xpl0->sadb_x_policy_type == IPSEC_POLICY_IPSEC &&
	    mhp->extlen[SADB_X_EXT_POLICY] <= sizeof(*xpl0)) {
		ipseclog((LOG_DEBUG, "key_spdadd: some policy requests part required.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/*
	 * checking there is SP already or not.
	 * SPDUPDATE doesn't depend on whether there is a SP or not.
	 * If the type is either SPDADD or SPDSETIDX AND a SP is found,
	 * then error.
	 */
	if (xpl0->sadb_x_policy_id != 0)
		newsp = key_getspbyid(xpl0->sadb_x_policy_id);
	else if (spidxmode)
		newsp = key_getsp(&spidx, xpl0->sadb_x_policy_dir);
	else {
#if NPF > 0
		tagvalue = pf_tagname2tag(tag->sadb_x_tag_name);
		/* tag refcnt++ */
		newsp = key_getspbytag(tagvalue, xpl0->sadb_x_policy_dir);
#else
		panic("PF");
#endif
	}

	if (newsp && (newsp->readonly || newsp->persist)) {
		ipseclog((LOG_DEBUG,
		    "key_spdadd: tried to alter readonly/persistent SP.\n"));
		return key_senderror(so, m, EPERM);
	}

	if (mhp->msg->sadb_msg_type == SADB_X_SPDUPDATE) {
		if (newsp) {
			key_sp_dead(newsp);
			key_freesp(newsp);	/* ref gained by key_getsp */
			key_sp_unlink(newsp);
			newsp = NULL;
		}
	} else {
		if (newsp != NULL) {
			key_freesp(newsp);
			ipseclog((LOG_DEBUG, "key_spdadd: a SP entry exists already.\n"));
#if NPF > 0
			if (!mhp->ext[SADB_EXT_ADDRESS_SRC])
				pf_tag_unref(tagvalue);
#endif
			return key_senderror(so, m, EEXIST);
		}
	}

	/* allocation new SP entry */
	if ((newsp = key_msg2sp(xpl0, PFKEY_EXTLEN(xpl0), &error)) == NULL) {
#if NPF > 0
		if (!spidxmode)
			pf_tag_unref(tagvalue);
#endif
		return key_senderror(so, m, error);
	}

	if (spidxmode) {
		error = keydb_setsecpolicyindex(newsp, &spidx);
		if (error) {
			keydb_delsecpolicy(newsp);
			return key_senderror(so, m, error);
		}

		/* sanity check on addr pair */
		if (((struct sockaddr *)(src0 + 1))->sa_family !=
				((struct sockaddr *)(dst0 + 1))->sa_family) {
			keydb_delsecpolicy(newsp);
			return key_senderror(so, m, EINVAL);
		}
		if (((struct sockaddr *)(src0 + 1))->sa_len !=
				((struct sockaddr *)(dst0 + 1))->sa_len) {
			keydb_delsecpolicy(newsp);
			return key_senderror(so, m, EINVAL);
		}
	} else {
#if NPF > 0
		newsp->tag = tagvalue;
#else
		panic("PF");
#endif
	}

	for (isr = newsp->req; isr; isr = isr->next) {
		struct sockaddr *sa;

		/*
		 * port spec is not permitted for tunnel mode
		 */
		if (isr->saidx.mode == IPSEC_MODE_TUNNEL && src0 && dst0
#ifdef MIP6
		    && (src0->sadb_address_proto != IPPROTO_MH)
#endif
			) {
			sa = (struct sockaddr *)(src0 + 1);
			switch (sa->sa_family) {
			case AF_INET:
				if (((struct sockaddr_in *)sa)->sin_port) {
					keydb_delsecpolicy(newsp);
					return key_senderror(so, m, EINVAL);
				}
				break;
			case AF_INET6:
				if (((struct sockaddr_in6 *)sa)->sin6_port) {
					keydb_delsecpolicy(newsp);
					return key_senderror(so, m, EINVAL);
				}
				break;
			default:
				break;
			}
			sa = (struct sockaddr *)(dst0 + 1);
			switch (sa->sa_family) {
			case AF_INET:
				if (((struct sockaddr_in *)sa)->sin_port) {
					keydb_delsecpolicy(newsp);
					return key_senderror(so, m, EINVAL);
				}
				break;
			case AF_INET6:
				if (((struct sockaddr_in6 *)sa)->sin6_port) {
					keydb_delsecpolicy(newsp);
					return key_senderror(so, m, EINVAL);
				}
				break;
			default:
				break;
			}
		}
	}

	/*
	 * bark if we have different address family on tunnel address
	 * specification.  applies only if we decapsulate in RFC2401
	 * IPsec (implementation limitation).
	 */
	for (isr = newsp->req; isr; isr = isr->next) {
		struct sockaddr *sa;

		if (isr->saidx.src.ss_family && src0) {
			sa = (struct sockaddr *)(src0 + 1);
			if (sa->sa_family != isr->saidx.src.ss_family) {
				keydb_delsecpolicy(newsp);
				return key_senderror(so, m, EINVAL);
			}
		}
		if (isr->saidx.dst.ss_family && dst0) {
			sa = (struct sockaddr *)(dst0 + 1);
			if (sa->sa_family != isr->saidx.dst.ss_family) {
				keydb_delsecpolicy(newsp);
				return key_senderror(so, m, EINVAL);
			}
		}
	}

#ifdef __FreeBSD__
	newsp->created = time_second;
	newsp->lastused = time_second;
#else
	newsp->created = time.tv_sec;
	newsp->lastused = time.tv_sec;
#endif
	newsp->lifetime = lft ? lft->sadb_lifetime_addtime : 0;
	newsp->validtime = lft ? lft->sadb_lifetime_usetime : 0;

	newsp->state = IPSEC_SPSTATE_ALIVE;
	LIST_INSERT_TAIL(&sptree[newsp->dir], newsp, secpolicy, chain);
	/* refcnt == 1 for the link from sptree[] */

	/* delete the entry in spacqtree */
	if (mhp->msg->sadb_msg_type == SADB_X_SPDUPDATE &&
	    mhp->ext[SADB_EXT_ADDRESS_SRC]) {
		struct secspacq *spacq;
		if ((spacq = key_getspacq(&spidx)) != NULL) {
			/* reset counter in order to deletion by timehandler. */
#ifdef __FreeBSD__
			spacq->created = time_second;
#else
			spacq->created = time.tv_sec;
#endif
			spacq->count = 0;
		}
    	}

	/* invalidate all cached SPD pointers on pcb */
	ipsec_invalpcbcacheall();

    {
	struct mbuf *n, *mpolicy;
	struct sadb_msg *newmsg;
	int off;

	/* create new sadb_msg to reply. */
	if (lft) {
		n = key_gather_mbuf(m, mhp, 2, 5, SADB_EXT_RESERVED,
		    SADB_X_EXT_POLICY, SADB_EXT_LIFETIME_HARD,
		    SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST);
	} else {
		n = key_gather_mbuf(m, mhp, 2, 4, SADB_EXT_RESERVED,
		    SADB_X_EXT_POLICY,
		    SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST);
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	if (n->m_len < sizeof(*newmsg)) {
		n = m_pullup(n, sizeof(*newmsg));
		if (!n)
			return key_senderror(so, m, ENOBUFS);
	}
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	off = 0;
	mpolicy = m_pulldown(n, PFKEY_ALIGN8(sizeof(struct sadb_msg)),
	    sizeof(*xpl), &off);
	if (mpolicy == NULL) {
		/* n is already freed */
		return key_senderror(so, m, ENOBUFS);
	}
	xpl = (struct sadb_x_policy *)(mtod(mpolicy, caddr_t) + off);
	if (xpl->sadb_x_policy_exttype != SADB_X_EXT_POLICY) {
		m_freem(n);
		return key_senderror(so, m, EINVAL);
	}
	xpl->sadb_x_policy_id = newsp->id;

	newsp = NULL;
	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_SPDDELETE processing
 * receive
 *   <base, address(SD), policy(*)>
 * from the user(?), and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, address(SD), policy(*)>
 * to the ikmpd.
 * policy(*) including the direction of the policy.
 *
 * m will always be freed.
 */
static int
key_spddelete(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_address *src0, *dst0;
	struct sadb_x_policy *xpl0;
	struct secpolicyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spddelete: NULL pointer is passed.");

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    mhp->ext[SADB_X_EXT_POLICY] == NULL) {
		ipseclog((LOG_DEBUG, "key_spddelete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spddelete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];
	xpl0 = (struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY];

	/* make secindex */
	/* XXX boundary check against sa_len */
	KEY_SETSECSPIDX(src0 + 1,
	                dst0 + 1,
	                src0->sadb_address_prefixlen,
	                dst0->sadb_address_prefixlen,
	                src0->sadb_address_proto,
	                &spidx);

	/* checking the direciton. */
	switch (xpl0->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		ipseclog((LOG_DEBUG, "key_spddelete: Invalid SP direction.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* Is there SP in SPD ? */
	if ((sp = key_getsp(&spidx, xpl0->sadb_x_policy_dir)) == NULL) {
		ipseclog((LOG_DEBUG, "key_spddelete: no SP found.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (sp->persist) {
		ipseclog((LOG_DEBUG,
		    "key_spddelete: attempt to remove persistent SP:%u.\n",
		    sp->id));
		key_freesp(sp);	/* ref gained by key_getsp */
		return key_senderror(so, m, EPERM);
	}

	/* save policy id to be returned. */
	xpl0->sadb_x_policy_id = sp->id;

	key_sp_dead(sp);
	key_freesp(sp);	/* ref gained by key_getsp */
	key_sp_unlink(sp);
	sp = NULL;

	/* invalidate all cached SPD pointers on pcb */
	ipsec_invalpcbcacheall();

    {
	struct mbuf *n;
	struct sadb_msg *newmsg;

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, 4, SADB_EXT_RESERVED,
	    SADB_X_EXT_POLICY, SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_SPDDELETE2 processing
 * receive
 *   <base, policy(*)>
 * from the user(?), and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, policy(*)>
 * to the ikmpd.
 * policy(*) including the policy id.
 *
 * m will always be freed.
 */
static int
key_spddelete2(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	u_int32_t id;
	struct secpolicy *sp;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spddelete2: NULL pointer is passed.");

	if (mhp->ext[SADB_X_EXT_POLICY] == NULL ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spddelete2: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	id = ((struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY])->sadb_x_policy_id;

	/* Is there SP in SPD ? */
	if ((sp = key_getspbyid(id)) == NULL) {
		ipseclog((LOG_DEBUG, "key_spddelete2: no SP found id:%u.\n",
		    id));
		return key_senderror(so, m, EINVAL);
	}

	if (sp->persist) {
		ipseclog((LOG_DEBUG,
		    "key_spddelete2: attempt to remove persistent SP:%u.\n",
		    id));
		key_freesp(sp);	/* ref gained by key_getspbyid */
		return key_senderror(so, m, EPERM);
	}

	key_sp_dead(sp);
	key_freesp(sp);	/* ref gained by key_getspbyid */
	key_sp_unlink(sp);
	sp = NULL;

	/* invalidate all cached SPD pointers on pcb */
	ipsec_invalpcbcacheall();

    {
	struct mbuf *n, *nn;
	struct sadb_msg *newmsg;
	int off, len;

	/* create new sadb_msg to reply. */
	len = PFKEY_ALIGN8(sizeof(struct sadb_msg));

	if (len > MCLBYTES)
		return key_senderror(so, m, ENOBUFS);
	MGETHDR(n, M_DONTWAIT, MT_DATA);
	if (n && len > MHLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	n->m_len = len;
	n->m_next = NULL;
	off = 0;

	m_copydata(m, 0, sizeof(struct sadb_msg), mtod(n, caddr_t) + off);
	off += PFKEY_ALIGN8(sizeof(struct sadb_msg));

#ifdef DIAGNOSTIC
	if (off != len)
		panic("length inconsistency in key_spddelete2");
#endif

	n->m_next = m_copym(m, mhp->extoff[SADB_X_EXT_POLICY],
	    mhp->extlen[SADB_X_EXT_POLICY], M_DONTWAIT);
	if (!n->m_next) {
		m_freem(n);
		return key_senderror(so, m, ENOBUFS);
	}

	n->m_pkthdr.len = 0;
	for (nn = n; nn; nn = nn->m_next)
		n->m_pkthdr.len += nn->m_len;

	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_X_SPDGET processing
 * receive
 *   <base, policy(*)>
 * from the user(?),
 * and send,
 *   <base, address(SD), policy>
 * to the ikmpd.
 * policy(*) including direction of policy.
 *
 * m will always be freed.
 */
static int
key_spdget(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	u_int32_t id;
	struct secpolicy *sp;
	struct mbuf *n;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spdget: NULL pointer is passed.");

	if (mhp->ext[SADB_X_EXT_POLICY] == NULL ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spdget: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	id = ((struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY])->sadb_x_policy_id;

	/* Is there SP in SPD ? */
	if ((sp = key_getspbyid(id)) == NULL) {
		ipseclog((LOG_DEBUG, "key_spdget: no SP found id:%u.\n", id));
		return key_senderror(so, m, ENOENT);
	}

	n = key_setdumpsp(sp, SADB_X_SPDGET, 0, mhp->msg->sadb_msg_pid);
	key_freesp(sp);	/* ref gained by key_getspbyid */
	if (n != NULL) {
		m_freem(m);
		return key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
	} else
		return key_senderror(so, m, ENOBUFS);
}

/*
 * SADB_X_SPDACQUIRE processing.
 * Acquire policy and SA(s) for a *OUTBOUND* packet.
 * send
 *   <base, policy(*)>
 * to KMD, and expect to receive
 *   <base> with SADB_X_SPDACQUIRE if error occured,
 * or
 *   <base, policy>
 * with SADB_X_SPDUPDATE from KMD by PF_KEY.
 * policy(*) is without policy requests.
 *
 *    0     : succeed
 *    others: error number
 */
int
key_spdacquire(struct secpolicy *sp)
{
	struct mbuf *result = NULL, *m;
#ifndef IPSEC_NONBLOCK_ACQUIRE
	struct secspacq *newspacq;
#endif
	int error = -1;

	/* sanity check */
	if (sp == NULL)
		panic("key_spdacquire: NULL pointer is passed.");
	if (sp->req != NULL)
		panic("key_spdacquire: called but there is request.");
	if (sp->policy != IPSEC_POLICY_IPSEC)
		panic("key_spdacquire: policy mismathed. IPsec is expected.");
	if (!sp->spidx) {
		error = EOPNOTSUPP;
		goto fail;
	}

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* get an entry to check whether sent message or not. */
	if ((newspacq = key_getspacq(sp->spidx)) != NULL) {
		if (key_blockacq_count < newspacq->count) {
			/* reset counter and do send message. */
			newspacq->count = 0;
		} else {
			/* increment counter and do nothing. */
			newspacq->count++;
			return 0;
		}
	} else {
		/* make new entry for blocking to send SADB_ACQUIRE. */
		if ((newspacq = key_newspacq(sp->spidx)) == NULL)
			return ENOBUFS;

		/* add to acqtree */
		LIST_INSERT_HEAD(&spacqtree, newspacq, chain);
	}
#endif

	/* create new sadb_msg to reply. */
	m = key_setsadbmsg(SADB_X_SPDACQUIRE, 0, 0, 0, 0, 0);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* set sadb_x_policy */
	if (sp) {
		m = key_setsadbxpolicy(sp->policy, sp->dir, sp->id);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

fail:
	if (result)
		m_freem(result);
	return error;
}

/*
 * SADB_SPDFLUSH processing
 * receive
 *   <base>
 * from the user, and free all entries in secpctree.
 * and send,
 *   <base>
 * to the user.
 * NOTE: what to do is only marking SADB_SASTATE_DEAD.
 *
 * m will always be freed.
 */
static int
key_spdflush(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_msg *newmsg;
	struct secpolicy *sp, *nextsp;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spdflush: NULL pointer is passed.");

	if (m->m_len != PFKEY_ALIGN8(sizeof(struct sadb_msg)))
		return key_senderror(so, m, EINVAL);

	for (sp = TAILQ_FIRST(&sptailq); sp; sp = nextsp) {
		nextsp = TAILQ_NEXT(sp, tailq);
		if (sp->persist)
			continue;
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		key_sp_dead(sp);
		key_sp_unlink(sp);
		sp = NULL;
	}

	/* invalidate all cached SPD pointers on pcb */
	ipsec_invalpcbcacheall();

	if (sizeof(struct sadb_msg) > m->m_len + M_TRAILINGSPACE(m)) {
		ipseclog((LOG_DEBUG, "key_spdflush: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	if (m->m_next)
		m_freem(m->m_next);
	m->m_next = NULL;
	m->m_pkthdr.len = m->m_len = PFKEY_ALIGN8(sizeof(struct sadb_msg));
	newmsg = mtod(m, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(m->m_pkthdr.len);

	return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
}

/*
 * SADB_SPDDUMP processing
 * receive
 *   <base>
 * from the user, and dump all SP leaves
 * and send,
 *   <base> .....
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_spddump(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct secpolicy *sp;
	int cnt;
	u_int dir;
	struct mbuf *n;
	int error = 0, needwait = 0;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spddump: NULL pointer is passed.");

	/* search SPD entry and get buffer size. */
	cnt = 0;
	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			cnt++;
		}
	}

	if (cnt == 0)
		return key_senderror(so, m, ENOENT);

	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			--cnt;
			n = key_setdumpsp(sp, SADB_X_SPDDUMP, cnt,
			    mhp->msg->sadb_msg_pid);

			if (n) {
				error = key_sendup_mbuf(so, n,
				    KEY_SENDUP_ONE | KEY_SENDUP_CANWAIT);
				if (error == EAGAIN)
					needwait = 1;
			}
		}
	}

#if 0
	/* XXX: this can cause infinite loop. */
	kp = (struct keycb *)sotorawcb(so);
	while (needwait && kp->kp_queue)
		sbwait(&so->so_rcv);
#endif

	m_freem(m);
	return 0;
}

#if defined(__NetBSD__) || defined(__OpenBSD__)
static struct mbuf *
key_setspddump(int *errorp)
{
	struct secpolicy *sp;
	int cnt;
	u_int dir;
	struct mbuf *m, *n;

	/* search SPD entry and get buffer size. */
	cnt = 0;
	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			cnt++;
		}
	}

	if (cnt == 0) {
		*errorp = ENOENT;
		return (NULL);
	}

	m = NULL;
	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			--cnt;
			n = key_setdumpsp(sp, SADB_X_SPDDUMP, cnt, 0);

			if (!n) {
				*errorp = ENOBUFS;
				m_freem(m);
				return (NULL);
			}
			if (!m)
				m = n;
			else {
				m->m_pkthdr.len += n->m_pkthdr.len;
				m_cat(m, n);
			}
		}
	}

	*errorp = 0;
	return (m);
}
#endif

struct mbuf *
key_setdumpsp(struct secpolicy *sp, u_int8_t type, u_int32_t seq, u_int32_t pid)
{
	struct mbuf *result = NULL, *m;

	m = key_setsadbmsg(type, 0, SADB_SATYPE_UNSPEC, seq, pid, sp->refcnt);
	if (!m)
		goto fail;
	result = m;

	if (sp->spidx) {
		m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
		    (struct sockaddr *)&sp->spidx->src, sp->spidx->prefs,
		    sp->spidx->ul_proto);
		if (!m)
			goto fail;
		m_cat(result, m);

		m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
		    (struct sockaddr *)&sp->spidx->dst, sp->spidx->prefd,
		    sp->spidx->ul_proto);
		if (!m)
			goto fail;
		m_cat(result, m);
	} else if (sp->tag) {
		m = key_setsadbxtag(sp->tag);
		if (!m)
			goto fail;
		m_cat(result, m);
	}

	m = key_sp2msg(sp);
	if (!m)
		goto fail;
	m_cat(result, m);

	m = key_setsadblifetime(SADB_EXT_LIFETIME_CURRENT,
		0, 0, (u_int64_t)sp->created, (u_int64_t)sp->lastused);
	if (!m)
		goto fail;
	m_cat(result, m);

	m = key_setsadblifetime(SADB_EXT_LIFETIME_HARD,
		0, 0, (u_int64_t)sp->lifetime, (u_int64_t)sp->validtime);
	if (!m)
		goto fail;
	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0)
		goto fail;

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL)
			goto fail;
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return result;

fail:
	m_freem(result);
	return NULL;
}

/*
 * get PFKEY message length for security policy and request.
 */
static u_int
key_getspreqmsglen(struct secpolicy *sp)
{
	u_int tlen;

	tlen = sizeof(struct sadb_x_policy);

	/* if is the policy for ipsec ? */
	if (sp->policy != IPSEC_POLICY_IPSEC)
		return tlen;

	/* get length of ipsec requests */
    {
	struct ipsecrequest *isr;
	int len;

	for (isr = sp->req; isr != NULL; isr = isr->next) {
		len = sizeof(struct sadb_x_ipsecrequest)
			+ isr->saidx.src.ss_len
			+ isr->saidx.dst.ss_len;

		tlen += PFKEY_ALIGN8(len);
	}
    }

	return tlen;
}

/*
 * SADB_X_SPDEXPIRE processing
 * send
 *   <base, address(SD), lifetime(CH), policy>
 * to KMD by PF_KEY.
 *
 * OUT:	0	: succeed
 *	others	: error number
 */
static int
key_spdexpire(struct secpolicy *sp)
{
	int s;
	struct mbuf *result = NULL, *m;
	int len;
	int error = -1;
	struct sadb_lifetime *lt;

	/* XXX: Why do we lock ? */
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

	/* sanity check */
	if (sp == NULL)
		panic("key_spdexpire: NULL pointer is passed.");

	/* set msg header */
	m = key_setsadbmsg(SADB_X_SPDEXPIRE, 0, 0, 0, 0, 0);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* create lifetime extension (current and hard) */
	len = PFKEY_ALIGN8(sizeof(*lt)) * 2;
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		error = ENOBUFS;
		goto fail;
	}
	bzero(mtod(m, caddr_t), len);
	lt = mtod(m, struct sadb_lifetime *);
	lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = 0;
	lt->sadb_lifetime_addtime = sp->created;
	lt->sadb_lifetime_usetime = sp->lastused;
	lt = (struct sadb_lifetime *)(mtod(m, caddr_t) + len / 2);
	lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = 0;
	lt->sadb_lifetime_addtime = sp->lifetime;
	lt->sadb_lifetime_usetime = sp->validtime;
	m_cat(result, m);

	/* set sadb_address for source */
	if (sp->spidx) {
		m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
		    (struct sockaddr *)&sp->spidx->src,
		    sp->spidx->prefs, sp->spidx->ul_proto);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);

		/* set sadb_address for destination */
		m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
		    (struct sockaddr *)&sp->spidx->dst,
		    sp->spidx->prefd, sp->spidx->ul_proto);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);
	} else if (sp->tag) {
		m = key_setsadbxtag(sp->tag);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);
	}

	/* set secpolicy */
	m = key_sp2msg(sp);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0) {
		error = EINVAL;
		goto fail;
	}

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			error = ENOBUFS;
			goto fail;
		}
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	splx(s);
	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

 fail:
	if (result)
		m_freem(result);
	splx(s);
	return error;
}

/* %%% SAD management */
/*
 * allocating a memory for new SA head, and copy from the values of mhp.
 * OUT:	NULL	: failure due to the lack of memory.
 *	others	: pointer to new SA head.
 */
static struct secashead *
key_newsah(struct secasindex *saidx)
{
	struct secashead *newsah;

	/* sanity check */
	if (saidx == NULL)
		panic("key_newsaidx: NULL pointer is passed.");

	newsah = keydb_newsecashead();
	if (newsah == NULL)
		return NULL;

	bcopy(saidx, &newsah->saidx, sizeof(newsah->saidx));

	/* add to saidxtree */
	newsah->state = SADB_SASTATE_MATURE;
	LIST_INSERT_HEAD(&sahtree, newsah, chain);

	return (newsah);
}

/*
 * delete SA index and all SA registerd.
 */
static void
key_delsah(struct secashead *sah)
{
	struct secasvar *sav, *nextsav;
	u_int stateidx, state;
	int s;
	int zombie = 0;

	/* sanity check */
	if (sah == NULL)
		panic("key_delsah: NULL pointer is passed.");

#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

	/* searching all SA registerd in the secindex. */
	for (stateidx = 0;
	     stateidx < _ARRAYLEN(saorder_state_any);
	     stateidx++) {

		state = saorder_state_any[stateidx];
		for (sav = LIST_FIRST(&sah->savtree[state]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			if (sav->refcnt > 0) {
				/* give up to delete this sa */
				zombie++;
				continue;
			}

			/* sanity check */
			KEY_CHKSASTATE(state, sav->state, "key_delsah");

			/* remove back pointer */
			sav->sah = NULL;

			key_freesav(sav);

			sav = NULL;
		}
	}

	/* delete sah only if there's no sav. */
	if (zombie) {
		splx(s);
		return;
	}

	if (sah->sa_route.ro_rt) {
		RTFREE(sah->sa_route.ro_rt);
		sah->sa_route.ro_rt = (struct rtentry *)NULL;
	}

	/* remove from tree of SA index */
	if (__LIST_CHAINED(sah))
		LIST_REMOVE(sah, chain);

	KFREE(sah);

	splx(s);
	return;
}

/*
 * allocating a new SA with LARVAL state.  key_add() and key_getspi() call,
 * and copy the values of mhp into new buffer.
 * When SAD message type is GETSPI:
 *	to set sequence number from acq_seq++,
 *	to set zero to SPI.
 *	not to call key_setsava().
 * OUT:	NULL	: fail
 *	others	: pointer to new secasvar.
 *
 * does not modify mbuf.  does not free mbuf on error.
 */
static struct secasvar *
key_newsav(struct mbuf *m, const struct sadb_msghdr *mhp, struct secashead *sah,
	int *errp)
{
	struct secasvar *newsav;
	const struct sadb_sa *xsa;

	/* sanity check */
	if (m == NULL || mhp == NULL || mhp->msg == NULL || sah == NULL)
		panic("key_newsa: NULL pointer is passed.");

	newsav = keydb_newsecasvar();
	if (newsav == NULL) {
		ipseclog((LOG_DEBUG, "key_newsa: No more memory.\n"));
		*errp = ENOBUFS;
		return NULL;
	}

	switch (mhp->msg->sadb_msg_type) {
	case SADB_GETSPI:
		key_setspi(newsav, 0);

#ifdef IPSEC_DOSEQCHECK
		/* sync sequence number */
		if (mhp->msg->sadb_msg_seq == 0)
			newsav->seq =
				(acq_seq = (acq_seq == ~0 ? 1 : ++acq_seq));
		else
#endif
			newsav->seq = mhp->msg->sadb_msg_seq;
		break;

	case SADB_ADD:
		/* sanity check */
		if (mhp->ext[SADB_EXT_SA] == NULL) {
			KFREE(newsav);
			ipseclog((LOG_DEBUG, "key_newsa: invalid message is passed.\n"));
			*errp = EINVAL;
			return NULL;
		}
		xsa = (const struct sadb_sa *)mhp->ext[SADB_EXT_SA];
		key_setspi(newsav, xsa->sadb_sa_spi);
		newsav->seq = mhp->msg->sadb_msg_seq;
		break;
	default:
		KFREE(newsav);
		*errp = EINVAL;
		return NULL;
	}

	/* copy sav values */
	if (mhp->msg->sadb_msg_type != SADB_GETSPI) {
		*errp = key_setsaval(newsav, m, mhp);
		if (*errp) {
			if (newsav->spihash.le_prev || newsav->spihash.le_next)
				LIST_REMOVE(newsav, spihash);
			KFREE(newsav);
			return NULL;
		}
	}

	/* reset created */
#ifdef __FreeBSD__
	newsav->created = time_second;
#else
	newsav->created = time.tv_sec;
#endif

	newsav->pid = mhp->msg->sadb_msg_pid;

	/* add to satree */
	newsav->sah = sah;
	newsav->refcnt = 1;
	newsav->state = SADB_SASTATE_LARVAL;
	LIST_INSERT_TAIL(&sah->savtree[SADB_SASTATE_LARVAL], newsav,
			secasvar, chain);

	return newsav;
}

/*
 * search SAD.
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secashead *
key_getsah(struct secasindex *saidx)
{
	struct secashead *sah;

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, saidx, CMP_MODE_REQID))
			return sah;
	}

	return NULL;
}

/*
 * check not to be duplicated SPI.
 * NOTE: this function is too slow due to searching all SAD.
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secasvar *
key_checkspidup(struct secasindex *saidx, u_int32_t spi)
{
	struct secasvar *sav;
	u_int stateidx, state;

	/* check address family */
	if (saidx->src.ss_family != saidx->dst.ss_family) {
		ipseclog((LOG_DEBUG, "key_checkspidup: address family mismatched.\n"));
		return NULL;
	}

	/* check all SAD */
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_alive[stateidx];
			if (sav->state == state &&
			    key_ismyaddr((struct sockaddr *)&sav->sah->saidx.dst))
				return sav;
		}
	}

	return NULL;
}

static void
key_setspi(struct secasvar *sav, u_int32_t spi)
{
	int s;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	sav->spi = spi;
	if (sav->spihash.le_prev || sav->spihash.le_next)
		LIST_REMOVE(sav, spihash);
	LIST_INSERT_HEAD(&spihash[SPIHASH(spi)], sav, spihash);
	splx(s);
}

/*
 * search SAD litmited alive SA, protocol, SPI.
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secasvar *
key_getsavbyspi(struct secashead *sah, u_int32_t spi)
{
	struct secasvar *sav, *match;
	u_int stateidx, state, matchidx;

	match = NULL;
	matchidx = _ARRAYLEN(saorder_state_alive);
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		if (sav->sah != sah)
			continue;
		for (stateidx = 0; stateidx < matchidx; stateidx++) {
			state = saorder_state_alive[stateidx];
			if (sav->state == state) {
				match = sav;
				matchidx = stateidx;
				break;
			}
		}
	}

	return match;
}

/*
 * copy SA values from PF_KEY message except *SPI, SEQ, PID, STATE and TYPE*.
 * You must update these if need.
 * OUT:	0:	success.
 *	!0:	failure.
 *
 * does not modify mbuf.  does not free mbuf on error.
 */
static int
key_setsaval(struct secasvar *sav, struct mbuf *m,
	const struct sadb_msghdr *mhp)
{
#ifdef IPSEC_ESP
	const struct esp_algorithm *algo;
#endif
	int error = 0;

	/* sanity check */
	if (m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_setsaval: NULL pointer is passed.");

	/* initialization */
	sav->replay = NULL;
	sav->key_auth = NULL;
	sav->key_enc = NULL;
	sav->sched = NULL;
	sav->schedlen = 0;
	sav->iv = NULL;
	sav->lft_c = NULL;
	sav->lft_h = NULL;
	sav->lft_s = NULL;

	/* SA */
	if (mhp->ext[SADB_EXT_SA] != NULL) {
		const struct sadb_sa *sa0;

		sa0 = (const struct sadb_sa *)mhp->ext[SADB_EXT_SA];
		if (mhp->extlen[SADB_EXT_SA] < sizeof(*sa0)) {
			error = EINVAL;
			goto fail;
		}

		sav->alg_auth = sa0->sadb_sa_auth;
		sav->alg_enc = sa0->sadb_sa_encrypt;
		sav->flags = sa0->sadb_sa_flags;

		/* replay window */
		if ((sa0->sadb_sa_flags & SADB_X_EXT_OLD) == 0) {
			sav->replay = keydb_newsecreplay(sa0->sadb_sa_replay);
			if (sav->replay == NULL) {
				ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
				error = ENOBUFS;
				goto fail;
			}
		}
	}

	/* Authentication keys */
	if (mhp->ext[SADB_EXT_KEY_AUTH] != NULL) {
		const struct sadb_key *key0;
		int len;

		key0 = (const struct sadb_key *)mhp->ext[SADB_EXT_KEY_AUTH];
		len = mhp->extlen[SADB_EXT_KEY_AUTH];

		error = 0;
		if (len < sizeof(*key0)) {
			error = EINVAL;
			goto fail;
		}
		switch (mhp->msg->sadb_msg_satype) {
		case SADB_SATYPE_AH:
		case SADB_SATYPE_ESP:
#ifdef TCP_SIGNATURE
		case SADB_X_SATYPE_TCPSIGNATURE:
#endif
			if (len == PFKEY_ALIGN8(sizeof(struct sadb_key)) &&
			    sav->alg_auth != SADB_X_AALG_NULL)
				error = EINVAL;
			break;
		case SADB_X_SATYPE_IPCOMP:
		default:
			error = EINVAL;
			break;
		}
		if (error) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid key_auth values.\n"));
			goto fail;
		}

		sav->key_auth = (struct sadb_key *)key_newbuf(key0, len);
		if (sav->key_auth == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
	}

	/* Encryption key */
	if (mhp->ext[SADB_EXT_KEY_ENCRYPT] != NULL) {
		const struct sadb_key *key0;
		int len;

		key0 = (const struct sadb_key *)mhp->ext[SADB_EXT_KEY_ENCRYPT];
		len = mhp->extlen[SADB_EXT_KEY_ENCRYPT];

		error = 0;
		if (len < sizeof(*key0)) {
			error = EINVAL;
			goto fail;
		}
		switch (mhp->msg->sadb_msg_satype) {
		case SADB_SATYPE_ESP:
			if (len == PFKEY_ALIGN8(sizeof(struct sadb_key)) &&
			    sav->alg_enc != SADB_EALG_NULL) {
				error = EINVAL;
				break;
			}
			sav->key_enc = (struct sadb_key *)key_newbuf(key0, len);
			if (sav->key_enc == NULL) {
				ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
				error = ENOBUFS;
				goto fail;
			}
			break;
		case SADB_X_SATYPE_IPCOMP:
			if (len != PFKEY_ALIGN8(sizeof(struct sadb_key)))
				error = EINVAL;
			sav->key_enc = NULL;	/*just in case*/
			break;
		case SADB_SATYPE_AH:
#ifdef TCP_SIGNATURE
		case SADB_X_SATYPE_TCPSIGNATURE:
#endif
		default:
			error = EINVAL;
			break;
		}
		if (error) {
			ipseclog((LOG_DEBUG, "key_setsatval: invalid key_enc value.\n"));
			goto fail;
		}
	}

	/* set iv */
	sav->ivlen = 0;

	switch (mhp->msg->sadb_msg_satype) {
	case SADB_SATYPE_ESP:
#ifdef IPSEC_ESP
		algo = esp_algorithm_lookup(sav->alg_enc);
		if (algo && algo->ivlen)
			sav->ivlen = (*algo->ivlen)(algo, sav);
		if (sav->ivlen == 0)
			break;
		KMALLOC(sav->iv, caddr_t, sav->ivlen);
		if (sav->iv == 0) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}

		/* initialize */
		key_randomfill(sav->iv, sav->ivlen);
#endif
		break;
	case SADB_SATYPE_AH:
	case SADB_X_SATYPE_IPCOMP:
#ifdef TCP_SIGNATURE
	case SADB_X_SATYPE_TCPSIGNATURE:
#endif
		break;
	default:
		ipseclog((LOG_DEBUG, "key_setsaval: invalid SA type.\n"));
		error = EINVAL;
		goto fail;
	}

	/* reset created */
#ifdef __FreeBSD__
	sav->created = time_second;
#else
	sav->created = time.tv_sec;
#endif

	/* make lifetime for CURRENT */
	KMALLOC(sav->lft_c, struct sadb_lifetime *,
	    sizeof(struct sadb_lifetime));
	if (sav->lft_c == NULL) {
		ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
		error = ENOBUFS;
		goto fail;
	}

	sav->lft_c->sadb_lifetime_len =
	    PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	sav->lft_c->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	sav->lft_c->sadb_lifetime_allocations = 0;
	sav->lft_c->sadb_lifetime_bytes = 0;
#ifdef __FreeBSD__
	sav->lft_c->sadb_lifetime_addtime = time_second;
#else
	sav->lft_c->sadb_lifetime_addtime = time.tv_sec;
#endif
	sav->lft_c->sadb_lifetime_usetime = 0;

	/* lifetimes for HARD and SOFT */
    {
	const struct sadb_lifetime *lft0;

	lft0 = (struct sadb_lifetime *)mhp->ext[SADB_EXT_LIFETIME_HARD];
	if (lft0 != NULL) {
		if (mhp->extlen[SADB_EXT_LIFETIME_HARD] < sizeof(*lft0)) {
			error = EINVAL;
			goto fail;
		}
		sav->lft_h = (struct sadb_lifetime *)key_newbuf(lft0,
		    sizeof(*lft0));
		if (sav->lft_h == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
		/* we no longer support byte lifetime */
		if (sav->lft_h->sadb_lifetime_bytes) {
			error = EINVAL;
			goto fail;
		}
		/* initialize? */
	}

	lft0 = (struct sadb_lifetime *)mhp->ext[SADB_EXT_LIFETIME_SOFT];
	if (lft0 != NULL) {
		if (mhp->extlen[SADB_EXT_LIFETIME_SOFT] < sizeof(*lft0)) {
			error = EINVAL;
			goto fail;
		}
		sav->lft_s = (struct sadb_lifetime *)key_newbuf(lft0,
		    sizeof(*lft0));
		if (sav->lft_s == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
		/* we no longer support byte lifetime */
		if (sav->lft_s->sadb_lifetime_bytes) {
			error = EINVAL;
			goto fail;
		}
		/* initialize? */
	}
    }

	return 0;

 fail:
	/* initialization */
	if (sav->replay != NULL) {
		keydb_delsecreplay(sav->replay);
		sav->replay = NULL;
	}
	if (sav->key_auth != NULL) {
		bzero(_KEYBUF(sav->key_auth), _KEYLEN(sav->key_auth));
		KFREE(sav->key_auth);
		sav->key_auth = NULL;
	}
	if (sav->key_enc != NULL) {
		bzero(_KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc));
		KFREE(sav->key_enc);
		sav->key_enc = NULL;
	}
	if (sav->sched) {
		bzero(sav->sched, sav->schedlen);
		KFREE(sav->sched);
		sav->sched = NULL;
	}
	if (sav->iv != NULL) {
		KFREE(sav->iv);
		sav->iv = NULL;
	}
	if (sav->lft_c != NULL) {
		KFREE(sav->lft_c);
		sav->lft_c = NULL;
	}
	if (sav->lft_h != NULL) {
		KFREE(sav->lft_h);
		sav->lft_h = NULL;
	}
	if (sav->lft_s != NULL) {
		KFREE(sav->lft_s);
		sav->lft_s = NULL;
	}

	return error;
}

/*
 * validation with a secasvar entry, and set SADB_SATYPE_MATURE.
 * OUT:	0:	valid
 *	other:	errno
 */
static int
key_mature(struct secasvar *sav)
{
	int mature;
	int checkmask = 0;	/* 2^0: ealg  2^1: aalg  2^2: calg */
	int mustmask = 0;	/* 2^0: ealg  2^1: aalg  2^2: calg */

	mature = 0;

	/* check SPI value */
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
	case IPPROTO_AH:
		if (ntohl(sav->spi) >= 0 && ntohl(sav->spi) <= 255) {
			ipseclog((LOG_DEBUG,
			    "key_mature: illegal range of SPI %u.\n",
			    (u_int32_t)ntohl(sav->spi)));
			return EINVAL;
		}
		break;
	}

	/* check satype */
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
		/* check flags */
		if ((sav->flags & SADB_X_EXT_OLD) &&
		    (sav->flags & SADB_X_EXT_DERIV)) {
			ipseclog((LOG_DEBUG, "key_mature: "
			    "invalid flag (derived) given to old-esp.\n"));
			return EINVAL;
		}
		if (sav->alg_auth == SADB_AALG_NONE)
			checkmask = 1;
		else
			checkmask = 3;
		mustmask = 1;
		break;
	case IPPROTO_AH:
		/* check flags */
		if (sav->flags & SADB_X_EXT_DERIV) {
			ipseclog((LOG_DEBUG, "key_mature: "
			    "invalid flag (derived) given to AH SA.\n"));
			return EINVAL;
		}
		if (sav->alg_enc != SADB_EALG_NONE) {
			ipseclog((LOG_DEBUG, "key_mature: "
			    "protocol and algorithm mismated.\n"));
			return (EINVAL);
		}
		checkmask = 2;
		mustmask = 2;
		break;
	case IPPROTO_IPCOMP:
		if (sav->alg_auth != SADB_AALG_NONE) {
			ipseclog((LOG_DEBUG, "key_mature: "
				"protocol and algorithm mismated.\n"));
			return (EINVAL);
		}
		if ((sav->flags & SADB_X_EXT_RAWCPI) == 0 &&
		    ntohl(sav->spi) >= 0x10000) {
			ipseclog((LOG_DEBUG, "key_mature: invalid cpi for IPComp.\n"));
			return (EINVAL);
		}
		checkmask = 4;
		mustmask = 4;
		break;
#ifdef TCP_SIGNATURE
	case IPPROTO_TCP:
		if (sav->alg_auth != SADB_X_AALG_TCP_MD5) {
			ipseclog((LOG_DEBUG, "key_mature: unsupported authentication algorithm %u\n",
			    sav->alg_auth));
			return (EINVAL);
		}
		if (sav->alg_enc != SADB_EALG_NONE) {
			ipseclog((LOG_DEBUG, "%s : protocol and algorithm "
			    "mismated.\n", __func__));
			return(EINVAL);
		}
		if (sav->spi != htonl(0x1000)) {
			ipseclog((LOG_DEBUG, "key_mature: SPI must be TCP_SIG_SPI (0x1000)\n"));
			return (EINVAL);
		}
		checkmask = 2;
		mustmask = 2;
		break;
#endif
	default:
		ipseclog((LOG_DEBUG, "key_mature: Invalid satype.\n"));
		return EPROTONOSUPPORT;
	}

	/* check authentication algorithm */
	if ((checkmask & 2) != 0) {
		const struct ah_algorithm *algo;
		int keylen;

		algo = ah_algorithm_lookup(sav->alg_auth);
		if (!algo) {
			ipseclog((LOG_DEBUG,"key_mature: "
			    "unknown authentication algorithm.\n"));
			return EINVAL;
		}

		/* algorithm-dependent check */
		if (sav->key_auth)
			keylen = sav->key_auth->sadb_key_bits;
		else
			keylen = 0;
		if (keylen < algo->keymin || algo->keymax < keylen) {
			ipseclog((LOG_DEBUG,
			    "key_mature: invalid AH key length %d "
			    "(%d-%d allowed)\n",
			    keylen, algo->keymin, algo->keymax));
			return EINVAL;
		}

		if (algo->mature) {
			if ((*algo->mature)(sav)) {
				/* message generated in per-algorithm function*/
				return EINVAL;
			} else
				mature = SADB_SATYPE_AH;
		}

		if ((mustmask & 2) != 0 &&  mature != SADB_SATYPE_AH) {
			ipseclog((LOG_DEBUG, "key_mature: no satisfy algorithm for AH\n"));
			return EINVAL;
		}
	}

	/* check encryption algorithm */
	if ((checkmask & 1) != 0) {
#ifdef IPSEC_ESP
		const struct esp_algorithm *algo;
		int keylen;

		algo = esp_algorithm_lookup(sav->alg_enc);
		if (!algo) {
			ipseclog((LOG_DEBUG, "key_mature: unknown encryption algorithm.\n"));
			return EINVAL;
		}

		/* algorithm-dependent check */
		if (sav->key_enc)
			keylen = sav->key_enc->sadb_key_bits;
		else
			keylen = 0;
		if (keylen < algo->keymin || algo->keymax < keylen) {
			ipseclog((LOG_DEBUG,
			    "key_mature: invalid ESP key length %d "
			    "(%d-%d allowed)\n",
			    keylen, algo->keymin, algo->keymax));
			return EINVAL;
		}

		if (algo->mature) {
			if ((*algo->mature)(sav)) {
				/* message generated in per-algorithm function*/
				return EINVAL;
			} else
				mature = SADB_SATYPE_ESP;
		}

		if ((mustmask & 1) != 0 &&  mature != SADB_SATYPE_ESP) {
			ipseclog((LOG_DEBUG, "key_mature: no satisfy algorithm for ESP\n"));
			return EINVAL;
		}
#else /*IPSEC_ESP*/
		ipseclog((LOG_DEBUG, "key_mature: ESP not supported in this configuration\n"));
		return EINVAL;
#endif
	}

	/* check compression algorithm */
	if ((checkmask & 4) != 0) {
		const struct ipcomp_algorithm *algo;

		/* algorithm-dependent check */
		algo = ipcomp_algorithm_lookup(sav->alg_enc);
		if (!algo) {
			ipseclog((LOG_DEBUG, "key_mature: unknown compression algorithm.\n"));
			return EINVAL;
		}
	}

	key_sa_chgstate(sav, SADB_SASTATE_MATURE);

	return 0;
}

/*
 * subroutine for SADB_GET and SADB_DUMP.
 */
static struct mbuf *
key_setdumpsa(struct secasvar *sav, u_int8_t type, u_int8_t satype,
	u_int32_t seq, u_int32_t pid)
{
	struct mbuf *result = NULL, *tres = NULL, *m;
	int l = 0;
	int i;
	void *p;
	int dumporder[] = {
		SADB_EXT_SA, SADB_X_EXT_SA2,
		SADB_EXT_LIFETIME_HARD, SADB_EXT_LIFETIME_SOFT,
		SADB_EXT_LIFETIME_CURRENT, SADB_EXT_ADDRESS_SRC,
		SADB_EXT_ADDRESS_DST, SADB_EXT_ADDRESS_PROXY, SADB_EXT_KEY_AUTH,
		SADB_EXT_KEY_ENCRYPT, SADB_EXT_IDENTITY_SRC,
		SADB_EXT_IDENTITY_DST, SADB_EXT_SENSITIVITY,
	};

	m = key_setsadbmsg(type, 0, satype, seq, pid, sav->refcnt);
	if (m == NULL)
		goto fail;
	result = m;

	for (i = sizeof(dumporder)/sizeof(dumporder[0]) - 1; i >= 0; i--) {
		m = NULL;
		p = NULL;
		switch (dumporder[i]) {
		case SADB_EXT_SA:
			m = key_setsadbsa(sav);
			if (!m)
				goto fail;
			break;

		case SADB_X_EXT_SA2:
			m = key_setsadbxsa2(sav->sah->saidx.mode,
			    sav->replay ? (sav->replay->count & 0xffffffff) : 0,
			    sav->sah->saidx.reqid);
			if (!m)
				goto fail;
			break;

		case SADB_EXT_ADDRESS_SRC:
			m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
			    (struct sockaddr *)&sav->sah->saidx.src,
			    FULLMASK, IPSEC_ULPROTO_ANY);
			if (!m)
				goto fail;
			break;

		case SADB_EXT_ADDRESS_DST:
			m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
			    (struct sockaddr *)&sav->sah->saidx.dst,
			    FULLMASK, IPSEC_ULPROTO_ANY);
			if (!m)
				goto fail;
			break;

		case SADB_EXT_KEY_AUTH:
			if (!sav->key_auth)
				continue;
			l = PFKEY_UNUNIT64(sav->key_auth->sadb_key_len);
			p = sav->key_auth;
			break;

		case SADB_EXT_KEY_ENCRYPT:
			if (!sav->key_enc)
				continue;
			l = PFKEY_UNUNIT64(sav->key_enc->sadb_key_len);
			p = sav->key_enc;
			break;

		case SADB_EXT_LIFETIME_CURRENT:
			if (!sav->lft_c)
				continue;
			l = PFKEY_UNUNIT64(((struct sadb_ext *)sav->lft_c)->sadb_ext_len);
			p = sav->lft_c;
			break;

		case SADB_EXT_LIFETIME_HARD:
			if (!sav->lft_h)
				continue;
			l = PFKEY_UNUNIT64(((struct sadb_ext *)sav->lft_h)->sadb_ext_len);
			p = sav->lft_h;
			break;

		case SADB_EXT_LIFETIME_SOFT:
			if (!sav->lft_s)
				continue;
			l = PFKEY_UNUNIT64(((struct sadb_ext *)sav->lft_s)->sadb_ext_len);
			p = sav->lft_s;
			break;

		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
			/* XXX: should we brought from SPD ? */
		case SADB_EXT_SENSITIVITY:
		default:
			continue;
		}

		if ((!m && !p) || (m && p))
			goto fail;
		if (p && tres) {
			M_PREPEND(tres, l, M_DONTWAIT);
			if (!tres)
				goto fail;
			bcopy(p, mtod(tres, caddr_t), l);
			continue;
		}
		if (p) {
			m = key_alloc_mbuf(l);
			if (!m)
				goto fail;
			m_copyback(m, 0, l, p);
		}

		if (tres)
			m_cat(m, tres);
		tres = m;
	}

	m_cat(result, tres);

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL)
			goto fail;
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return result;

fail:
	m_freem(result);
	m_freem(tres);
	return NULL;
}

/*
 * set data into sadb_msg.
 */
static struct mbuf *
key_setsadbmsg(u_int8_t type, u_int16_t tlen, u_int8_t satype, u_int32_t seq,
	pid_t pid, u_int16_t reserved)
{
	struct mbuf *m;
	struct sadb_msg *p;
	int len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_msg));
	if (len > MCLBYTES)
		return NULL;
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m && len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (!m)
		return NULL;
	m->m_pkthdr.len = m->m_len = len;
	m->m_next = NULL;

	p = mtod(m, struct sadb_msg *);

	bzero(p, len);
	p->sadb_msg_version = PF_KEY_V2;
	p->sadb_msg_type = type;
	p->sadb_msg_errno = 0;
	p->sadb_msg_satype = satype;
	p->sadb_msg_len = PFKEY_UNIT64(tlen);
	p->sadb_msg_reserved = reserved;
	p->sadb_msg_seq = seq;
	p->sadb_msg_pid = (u_int32_t)pid;

	return m;
}

/*
 * copy secasvar data into sadb_address.
 */
static struct mbuf *
key_setsadbsa(struct secasvar *sav)
{
	struct mbuf *m;
	struct sadb_sa *p;
	int len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_sa));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_sa *);

	bzero(p, len);
	p->sadb_sa_len = PFKEY_UNIT64(len);
	p->sadb_sa_exttype = SADB_EXT_SA;
	p->sadb_sa_spi = sav->spi;
	p->sadb_sa_replay = (sav->replay != NULL ? sav->replay->wsize : 0);
	p->sadb_sa_state = sav->state;
	p->sadb_sa_auth = sav->alg_auth;
	p->sadb_sa_encrypt = sav->alg_enc;
	p->sadb_sa_flags = sav->flags;

	return m;
}

/*
 * set data into sadb_address.
 */
static struct mbuf *
key_setsadbaddr(u_int16_t exttype, struct sockaddr *saddr, u_int8_t prefixlen,
	u_int16_t ul_proto)
{
	struct mbuf *m;
	struct sadb_address *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_address)) +
	    PFKEY_ALIGN8(saddr->sa_len);
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_address *);

	bzero(p, len);
	p->sadb_address_len = PFKEY_UNIT64(len);
	p->sadb_address_exttype = exttype;
	p->sadb_address_proto = ul_proto;
	if (prefixlen == FULLMASK) {
		switch (saddr->sa_family) {
		case AF_INET:
			prefixlen = sizeof(struct in_addr) << 3;
			break;
		case AF_INET6:
			prefixlen = sizeof(struct in6_addr) << 3;
			break;
		default:
			; /*XXX*/
		}
	}
	p->sadb_address_prefixlen = prefixlen;
	p->sadb_address_reserved = 0;

	bcopy(saddr,
	    mtod(m, caddr_t) + PFKEY_ALIGN8(sizeof(struct sadb_address)),
	    saddr->sa_len);

	return m;
}

#if 0
/*
 * set data into sadb_ident.
 */
static struct mbuf *
key_setsadbident(u_int16_t exttype, u_int16_t idtype, caddr_t string, int stringlen, u_int64_t id)
{
	struct mbuf *m;
	struct sadb_ident *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_ident)) + PFKEY_ALIGN8(stringlen);
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_ident *);

	bzero(p, len);
	p->sadb_ident_len = PFKEY_UNIT64(len);
	p->sadb_ident_exttype = exttype;
	p->sadb_ident_type = idtype;
	p->sadb_ident_reserved = 0;
	p->sadb_ident_id = id;

	bcopy(string,
	    mtod(m, caddr_t) + PFKEY_ALIGN8(sizeof(struct sadb_ident)),
	    stringlen);

	return m;
}
#endif

/*
 * set data into sadb_x_sa2.
 */
static struct mbuf *
key_setsadbxsa2(u_int8_t mode, u_int32_t seq, u_int16_t reqid)
{
	struct mbuf *m;
	struct sadb_x_sa2 *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_x_sa2));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_x_sa2 *);

	bzero(p, len);
	p->sadb_x_sa2_len = PFKEY_UNIT64(len);
	p->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	p->sadb_x_sa2_mode = mode;
	p->sadb_x_sa2_reserved1 = 0;
	p->sadb_x_sa2_reserved2 = 0;
	p->sadb_x_sa2_sequence = seq;
	p->sadb_x_sa2_reqid = reqid;

	return m;
}

/*
 * set data into sadb_x_tag.
 */
static struct mbuf *
key_setsadbxtag(u_int16_t tag)
{
#if NPF > 0
	struct mbuf *m;
	struct sadb_x_tag *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_x_tag));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_x_tag *);

	bzero(p, len);
	p->sadb_x_tag_len = PFKEY_UNIT64(len);
	p->sadb_x_tag_exttype = SADB_X_EXT_TAG;
	pf_tag2tagname(tag, p->sadb_x_tag_name);

	return m;
#else
	return NULL;
#endif
}

/*
 * set data into sadb_lifetime
 */
static struct mbuf *
key_setsadblifetime(u_int16_t type, u_int32_t alloc, u_int64_t bytes,
	u_int64_t addtime, u_int64_t usetime)
{
	struct mbuf *m;
	struct sadb_lifetime *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_lifetime));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_lifetime *);

	bzero(p, len);
	p->sadb_lifetime_len = PFKEY_UNIT64(len);
	p->sadb_lifetime_exttype = type;
	p->sadb_lifetime_allocations = alloc;
	p->sadb_lifetime_bytes = bytes;
	p->sadb_lifetime_addtime = addtime;
	p->sadb_lifetime_usetime = usetime;

	return m;
}

/*
 * set data into sadb_x_policy
 */
static struct mbuf *
key_setsadbxpolicy(u_int16_t type, u_int8_t dir, u_int32_t id)
{
	struct mbuf *m;
	struct sadb_x_policy *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_x_policy));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_x_policy *);

	bzero(p, len);
	p->sadb_x_policy_len = PFKEY_UNIT64(len);
	p->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	p->sadb_x_policy_type = type;
	p->sadb_x_policy_dir = dir;
	p->sadb_x_policy_id = id;

	return m;
}

/* %%% utilities */
/*
 * copy a buffer into the new buffer allocated.
 */
static void *
key_newbuf(const void *src, u_int len)
{
	caddr_t new;

	KMALLOC(new, caddr_t, len);
	if (new == NULL) {
		ipseclog((LOG_DEBUG, "key_newbuf: No more memory.\n"));
		return NULL;
	}
	bcopy(src, new, len);

	return new;
}

/* compare my own address
 * OUT:	1: true, i.e. my address.
 *	0: false
 */
static int
key_ismyaddr(struct sockaddr *sa)
{
#ifdef INET
	struct sockaddr_in *sin;
	struct in_ifaddr *ia;
#endif

	/* sanity check */
	if (sa == NULL)
		panic("key_ismyaddr: NULL pointer is passed.");

	switch (sa->sa_family) {
#ifdef INET
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
#ifdef __NetBSD__
		TAILQ_FOREACH(ia, &in_ifaddrhead, ia_list)
#elif defined(__FreeBSD__)
		for (ia = in_ifaddrhead.tqh_first; ia;
		     ia = ia->ia_link.tqe_next)
#else
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
#endif
		{
			if (sin->sin_family == ia->ia_addr.sin_family &&
			    sin->sin_len == ia->ia_addr.sin_len &&
			    sin->sin_addr.s_addr == ia->ia_addr.sin_addr.s_addr)
			{
				return 1;
			}
		}
		break;
#endif
#ifdef INET6
	case AF_INET6:
		return key_ismyaddr6((struct sockaddr_in6 *)sa);
#endif
	}

	return 0;
}

#ifdef INET6
/*
 * compare my own address for IPv6.
 * 1: ours
 * 0: other
 * NOTE: derived ip6_input() in KAME. This is necessary to modify more.
 */
#include <netinet6/in6_var.h>

static int
key_ismyaddr6(struct sockaddr_in6 *sin6)
{
	struct in6_ifaddr *ia;
	struct in6_multi *in6m;

	if (sa6_embedscope(sin6, 0) != 0)
		return 0;

	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (key_sockaddrcmp((struct sockaddr *)&sin6,
		    (struct sockaddr *)&ia->ia_addr, 0) == 0)
			return 1;

		/*
		 * XXX Multicast
		 * XXX why do we care about multlicast here while we don't care
		 * about IPv4 multicast??
		 */
		in6m = NULL;
#ifdef __FreeBSD__
		IN6_LOOKUP_MULTI(sin6->sin6_addr, ia->ia_ifp, in6m);
#else
		for ((in6m) = ia->ia6_multiaddrs.lh_first;
		     (in6m) != NULL &&
		     !IN6_ARE_ADDR_EQUAL(&(in6m)->in6m_addr, &sin6->sin6_addr);
		     (in6m) = in6m->in6m_entry.le_next)
			continue;
#endif
		if (in6m)
			return 1;
	}

	/* loopback, just for safety */
	if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
		return 1;

	return 0;
}
#endif /*INET6*/

/*
 * compare two secasindex structure.
 * flag can specify to compare 2 saidxes.
 * compare two secasindex structure without both mode and reqid.
 * don't compare port.
 * IN:  
 *      saidx0: source, it can be in SAD.
 *      saidx1: object.
 * OUT: 
 *      1 : equal
 *      0 : not equal
 */
static int
key_cmpsaidx(struct secasindex *saidx0, struct secasindex *saidx1, int flag)
{

	/* sanity */
	if (saidx0 == NULL && saidx1 == NULL)
		return 1;

	if (saidx0 == NULL || saidx1 == NULL)
		return 0;

	if (saidx0->proto != saidx1->proto)
		return 0;

	if (flag == CMP_EXACTLY) {
		if (saidx0->mode != saidx1->mode)
			return 0;
		if (saidx0->reqid != saidx1->reqid)
			return 0;
		if (bcmp(&saidx0->src, &saidx1->src, saidx0->src.ss_len) != 0 ||
		    bcmp(&saidx0->dst, &saidx1->dst, saidx0->dst.ss_len) != 0)
			return 0;
	} else {

		/* CMP_MODE_REQID, CMP_HEAD */
		if (flag == CMP_MODE_REQID) {
			/*
			 * If reqid of SPD is non-zero, unique SA is required.
			 * The result must be of same reqid in this case.
			 */
			if (saidx1->reqid != 0 && saidx0->reqid != saidx1->reqid)
				return 0;
		}

		if (flag == CMP_MODE_REQID) {
			if (saidx0->mode != IPSEC_MODE_ANY &&
			    saidx0->mode != saidx1->mode)
				return 0;
		}

		if (key_sockaddrcmp((struct sockaddr *)&saidx0->src,
				(struct sockaddr *)&saidx1->src, 0) != 0) {
			return 0;
		}
		if (key_sockaddrcmp((struct sockaddr *)&saidx0->dst,
				(struct sockaddr *)&saidx1->dst, 0) != 0) {
			return 0;
		}
	}

	return 1;
}

/*
 * compare two secindex structure exactly.
 * IN:
 *	spidx0: source, it is often in SPD.
 *	spidx1: object, it is often from PFKEY message.
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
int
key_cmpspidx_exactly(struct secpolicyindex *spidx0,
	struct secpolicyindex *spidx1)
{

	/* sanity */
	if (spidx0 == NULL && spidx1 == NULL)
		return 1;

	if (spidx0 == NULL || spidx1 == NULL)
		return 0;

	if (spidx0->prefs != spidx1->prefs || spidx0->prefd != spidx1->prefd ||
	    spidx0->ul_proto != spidx1->ul_proto)
		return 0;

	if (key_sockaddrcmp((struct sockaddr *)&spidx0->src,
	    (struct sockaddr *)&spidx1->src, 1) != 0) {
		return 0;
	}
	if (key_sockaddrcmp((struct sockaddr *)&spidx0->dst,
	    (struct sockaddr *)&spidx1->dst, 1) != 0) {
		return 0;
	}

	return 1;
}

/*
 * compare two secindex structure with mask.
 * IN:
 *	spidx0: source, it is often in SPD.
 *	spidx1: object, it is often from IP header.
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
int
key_cmpspidx_withmask(struct secpolicyindex *spidx0,
	struct secpolicyindex *spidx1)
{

	/* sanity */
	if (spidx0 == NULL && spidx1 == NULL)
		return 1;

	if (spidx0 == NULL || spidx1 == NULL)
		return 0;

	if (spidx0->src.ss_family != spidx1->src.ss_family ||
	    spidx0->dst.ss_family != spidx1->dst.ss_family ||
	    spidx0->src.ss_len != spidx1->src.ss_len ||
	    spidx0->dst.ss_len != spidx1->dst.ss_len)
		return 0;

	/* if spidx.ul_proto == IPSEC_ULPROTO_ANY, ignore. */
	if (spidx0->ul_proto != (u_int16_t)IPSEC_ULPROTO_ANY &&
	    spidx0->ul_proto != spidx1->ul_proto)
		return 0;

	switch (spidx0->src.ss_family) {
	case AF_INET:
		if (satosin(&spidx0->src)->sin_port != IPSEC_PORT_ANY &&
		    satosin(&spidx0->src)->sin_port !=
		    satosin(&spidx1->src)->sin_port)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin(&spidx0->src)->sin_addr,
		    (caddr_t)&satosin(&spidx1->src)->sin_addr, spidx0->prefs))
			return 0;
		break;
	case AF_INET6:
		if (satosin6(&spidx0->src)->sin6_port != IPSEC_PORT_ANY &&
		    satosin6(&spidx0->src)->sin6_port !=
		    satosin6(&spidx1->src)->sin6_port)
			return 0;
		/*
		 * scope_id check. if sin6_scope_id is 0, we regard it
		 * as a wildcard scope, which matches any scope zone ID. 
		 */
		if (satosin6(&spidx0->src)->sin6_scope_id &&
		    satosin6(&spidx1->src)->sin6_scope_id &&
		    satosin6(&spidx0->src)->sin6_scope_id !=
		    satosin6(&spidx1->src)->sin6_scope_id)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin6(&spidx0->src)->sin6_addr,
		    (caddr_t)&satosin6(&spidx1->src)->sin6_addr, spidx0->prefs))
			return 0;
		break;
	default:
		/* XXX */
		if (bcmp(&spidx0->src, &spidx1->src, spidx0->src.ss_len) != 0)
			return 0;
		break;
	}

	switch (spidx0->dst.ss_family) {
	case AF_INET:
		if (satosin(&spidx0->dst)->sin_port != IPSEC_PORT_ANY &&
		    satosin(&spidx0->dst)->sin_port !=
		    satosin(&spidx1->dst)->sin_port)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin(&spidx0->dst)->sin_addr,
		    (caddr_t)&satosin(&spidx1->dst)->sin_addr, spidx0->prefd))
			return 0;
		break;
	case AF_INET6:
		if (satosin6(&spidx0->dst)->sin6_port != IPSEC_PORT_ANY &&
		    satosin6(&spidx0->dst)->sin6_port !=
		    satosin6(&spidx1->dst)->sin6_port)
			return 0;
		/*
		 * scope_id check. if sin6_scope_id is 0, we regard it
		 * as a wildcard scope, which matches any scope zone ID. 
		 */
		if (satosin6(&spidx0->src)->sin6_scope_id &&
		    satosin6(&spidx1->src)->sin6_scope_id &&
		    satosin6(&spidx0->dst)->sin6_scope_id !=
		    satosin6(&spidx1->dst)->sin6_scope_id)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin6(&spidx0->dst)->sin6_addr,
		    (caddr_t)&satosin6(&spidx1->dst)->sin6_addr, spidx0->prefd))
			return 0;
		break;
	default:
		/* XXX */
		if (bcmp(&spidx0->dst, &spidx1->dst, spidx0->dst.ss_len) != 0)
			return 0;
		break;
	}

	/* XXX Do we check other field ?  e.g. flowinfo */

	return 1;
}

/* returns 0 on match */
static int
key_sockaddrcmp(struct sockaddr *sa1, struct sockaddr *sa2, int port)
{

	if (sa1->sa_family != sa2->sa_family || sa1->sa_len != sa2->sa_len)
		return 1;

	switch (sa1->sa_family) {
	case AF_INET:
		if (sa1->sa_len != sizeof(struct sockaddr_in))
			return 1;
		if (satosin(sa1)->sin_addr.s_addr !=
		    satosin(sa2)->sin_addr.s_addr) {
			return 1;
		}
		if (port && satosin(sa1)->sin_port != satosin(sa2)->sin_port)
			return 1;
		break;
	case AF_INET6:
		if (sa1->sa_len != sizeof(struct sockaddr_in6))
			return 1;	/*EINVAL*/
		if (satosin6(sa1)->sin6_scope_id !=
		    satosin6(sa2)->sin6_scope_id) {
			return 1;
		}
		if (!IN6_ARE_ADDR_EQUAL(&satosin6(sa1)->sin6_addr,
		    &satosin6(sa2)->sin6_addr)) {
			return 1;
		}
		if (port &&
		    satosin6(sa1)->sin6_port != satosin6(sa2)->sin6_port) {
			return 1;
		}
		break;
	default:
		if (bcmp(sa1, sa2, sa1->sa_len) != 0)
			return 1;
		break;
	}

	return 0;
}

/*
 * compare two buffers with mask.
 * IN:
 *	addr1: source
 *	addr2: object
 *	bits:  Number of bits to compare
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
static int
key_bbcmp(caddr_t p1, caddr_t p2, u_int bits)
{
	u_int8_t mask;

	/* XXX: This could be considerably faster if we compare a word
	 * at a time, but it is complicated on LSB Endian machines */

	/* Handle null pointers */
	if (p1 == NULL || p2 == NULL)
		return (p1 == p2);

	while (bits >= 8) {
		if (*p1++ != *p2++)
			return 0;
		bits -= 8;
	}

	if (bits > 0) {
		mask = ~((1<<(8-bits))-1);
		if ((*p1 & mask) != (*p2 & mask))
			return 0;
	}
	return 1;	/* Match! */
}

/*
 * time handler.
 * scanning SPD and SAD to check status for each entries,
 * and do to remove or to expire.
 * XXX: year 2038 problem may remain.
 */
void
key_timehandler(void *arg)
{
	u_int dir;
	int s;
	struct timeval tv;

#ifdef __FreeBSD__
	microtime(&tv);
#else
	tv = time;
#endif

#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

	/* SPD */
    {
	struct secpolicy *sp, *nextsp;

	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		for (sp = LIST_FIRST(&sptree[dir]);
		     sp != NULL;
		     sp = nextsp) {
			nextsp = LIST_NEXT(sp, chain);

			if (sp->state == IPSEC_SPSTATE_DEAD) {
				key_sp_unlink(sp);	/*XXX*/
				sp = NULL;
				continue;
			}

			if (sp->lifetime == 0 && sp->validtime == 0)
				continue;

			/* the deletion will occur next time */
			if ((sp->lifetime &&
			     tv.tv_sec - sp->created > sp->lifetime) ||
			    (sp->validtime &&
			     tv.tv_sec - sp->lastused > sp->validtime)) {
				key_sp_dead(sp);
				key_spdexpire(sp);
				continue;
			}
		}
	}

	/* invalidate all cached SPD pointers on pcb */
	ipsec_invalpcbcacheall();
    }

	/* SAD */
    {
	struct secashead *sah, *nextsah;
	struct secasvar *sav, *nextsav;
	int havesav;
	u_int stateidx, state;

	for (sah = LIST_FIRST(&sahtree);
	     sah != NULL;
	     sah = nextsah) {

		nextsah = LIST_NEXT(sah, chain);

		/* if sah has been dead, then delete it and process next sah. */
		if (sah->state == SADB_SASTATE_DEAD) {
			key_delsah(sah);
			continue;
		}

		/* if LARVAL entry doesn't become MATURE, delete it. */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_LARVAL]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			if (tv.tv_sec - sav->created > key_larval_lifetime) {
				key_freesav(sav);
			}
		}

		/*
		 * check MATURE entry to start to send expire message
		 * whether or not.
		 */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_MATURE]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			/* we don't need to check. */
			if (sav->lft_s == NULL)
				continue;

			/* sanity check */
			if (sav->lft_c == NULL) {
				ipseclog((LOG_DEBUG, "key_timehandler: "
					"There is no CURRENT time, why?\n"));
				continue;
			}

			/* check SOFT lifetime */
			if (sav->lft_s->sadb_lifetime_addtime != 0 &&
			    tv.tv_sec - sav->created > sav->lft_s->sadb_lifetime_addtime) {
				/*
				 * check the SA if it has been used.
				 * when it hasn't been used, delete it.
				 * i don't think such SA will be used.
				 */
				if (sav->lft_c->sadb_lifetime_usetime == 0) {
					key_sa_chgstate(sav, SADB_SASTATE_DEAD);
					key_freesav(sav);
					sav = NULL;
				} else {
					key_sa_chgstate(sav, SADB_SASTATE_DYING);
					/*
					 * XXX If we keep to send expire
					 * message in the status of
					 * DYING. Do remove below code.
					 */
					key_expire(sav);
				}
			}

			/* check SOFT lifetime by bytes */
			/*
			 * XXX I don't know the way to delete this SA
			 * when new SA is installed.  Caution when it's
			 * installed too big lifetime by time.
			 */
			else if (sav->lft_s->sadb_lifetime_bytes != 0
			      && sav->lft_s->sadb_lifetime_bytes < sav->lft_c->sadb_lifetime_bytes) {

				key_sa_chgstate(sav, SADB_SASTATE_DYING);
				/*
				 * XXX If we keep to send expire
				 * message in the status of
				 * DYING. Do remove below code.
				 */
				key_expire(sav);
			}
		}

		/* check DYING entry to change status to DEAD. */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_DYING]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			/* we don't need to check. */
			if (sav->lft_h == NULL)
				continue;

			/* sanity check */
			if (sav->lft_c == NULL) {
				ipseclog((LOG_DEBUG,"key_timehandler: "
					"There is no CURRENT time, why?\n"));
				continue;
			}

			if (sav->lft_h->sadb_lifetime_addtime != 0 &&
			    tv.tv_sec - sav->created > sav->lft_h->sadb_lifetime_addtime) {
				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav);
				sav = NULL;
			}
#if 0	/* XXX Should we keep to send expire message until HARD lifetime ? */
			else if (sav->lft_s != NULL
			      && sav->lft_s->sadb_lifetime_addtime != 0
			      && tv.tv_sec - sav->created > sav->lft_s->sadb_lifetime_addtime) {
				/*
				 * XXX: should be checked to be
				 * installed the valid SA.
				 */

				/*
				 * If there is no SA then sending
				 * expire message.
				 */
				key_expire(sav);
			}
#endif
			/* check HARD lifetime by bytes */
			else if (sav->lft_h->sadb_lifetime_bytes != 0
			      && sav->lft_h->sadb_lifetime_bytes < sav->lft_c->sadb_lifetime_bytes) {
				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav);
				sav = NULL;
			}
		}

		/* delete entry in DEAD */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_DEAD]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			/* sanity check */
			if (sav->state != SADB_SASTATE_DEAD) {
				ipseclog((LOG_DEBUG, "key_timehandler: "
					"invalid sav->state "
					"(queue: %u SA: %u): "
					"kill it anyway\n",
					SADB_SASTATE_DEAD, sav->state));
			}

			/*
			 * do not call key_freesav() here.
			 * sav should already be freed, and sav->refcnt
			 * shows other references to sav
			 * (such as from SPD).
			 */
		}

		/* move SA header to DEAD if there's no SA */
		havesav = 0;
		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_alive[stateidx];
			if (LIST_FIRST(&sah->savtree[state])) {
				havesav++;
				break;
			}
		}
		if (havesav == 0) {
			ipseclog((LOG_DEBUG, "key_timehandler: "
			       "move sah %p to DEAD (no more SAs)\n", sah));
			sah->state = SADB_SASTATE_DEAD;
		}
	}
    }

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* ACQ tree */
    {
	struct secacq *acq, *nextacq;

	for (acq = LIST_FIRST(&acqtree);
	     acq != NULL;
	     acq = nextacq) {

		nextacq = LIST_NEXT(acq, chain);

		if (tv.tv_sec - acq->created > key_blockacq_lifetime &&
		    __LIST_CHAINED(acq)) {
			LIST_REMOVE(acq, chain);
			KFREE(acq);
		}
	}
    }
#endif

	/* SP ACQ tree */
    {
	struct secspacq *acq, *nextacq;

	for (acq = LIST_FIRST(&spacqtree);
	     acq != NULL;
	     acq = nextacq) {

		nextacq = LIST_NEXT(acq, chain);

		if (tv.tv_sec - acq->created > key_blockacq_lifetime &&
		    __LIST_CHAINED(acq)) {
			LIST_REMOVE(acq, chain);
			KFREE(acq);
		}
	}
    }

	/*
	 * should set timeout based on the most closest timer expiration.
	 * we don't bother to do that yet.
	 */
#if defined(__NetBSD__) || defined(__FreeBSD__)
	callout_reset(&key_timehandler_ch, hz, key_timehandler, (void *)0);
#else
	(void)timeout(key_timehandler, (void *)0, hz);
#endif

	splx(s);
	return;
}

/*
 * to initialize a seed for random()
 */
static u_long
key_random(void)
{
	u_long value;

	key_randomfill(&value, sizeof(value));
	return value;
}

void
key_randomfill(void *p, size_t l)
{
	size_t n;
	u_long v;
	static int warn = 1;

	n = 0;
#if defined(__NetBSD__) && NRND > 0
	n = rnd_extract_data(p, l, RND_EXTRACT_ANY);
#elif defined(__OpenBSD__)
	get_random_bytes(p, l);
	n = l;
#elif defined(__FreeBSD__)
	n = (size_t)read_random(p, (u_int)l);
#else
	*(u_int32_t *)p = arc4random();
	n = sizeof(u_int32_t);
#endif
	/* last resort */
	while (n < l) {
		v = random();
		bcopy(&v, (u_int8_t *)p + n,
		    l - n < sizeof(v) ? l - n : sizeof(v));
		n += sizeof(v);

		if (warn) {
			printf("WARNING: pseudo-random number generator "
			    "used for IPsec processing\n");
			warn = 0;
		}
	}
}

/*
 * map SADB_SATYPE_* to IPPROTO_*.
 * if satype == SADB_SATYPE then satype is mapped to ~0.
 * OUT:
 *	0: invalid satype.
 */
static u_int16_t
key_satype2proto(u_int8_t satype)
{

	switch (satype) {
	case SADB_SATYPE_UNSPEC:
		return IPSEC_PROTO_ANY;
	case SADB_SATYPE_AH:
		return IPPROTO_AH;
	case SADB_SATYPE_ESP:
		return IPPROTO_ESP;
	case SADB_X_SATYPE_IPCOMP:
		return IPPROTO_IPCOMP;
#ifdef TCP_SIGNATURE
	case SADB_X_SATYPE_TCPSIGNATURE:
		return IPPROTO_TCP;
#endif
	default:
		return 0;
	}
	/* NOTREACHED */
}

/*
 * map IPPROTO_* to SADB_SATYPE_*
 * OUT:
 *	0: invalid protocol type.
 */
static u_int8_t
key_proto2satype(u_int16_t proto)
{

	switch (proto) {
	case IPPROTO_AH:
		return SADB_SATYPE_AH;
	case IPPROTO_ESP:
		return SADB_SATYPE_ESP;
	case IPPROTO_IPCOMP:
		return SADB_X_SATYPE_IPCOMP;
#ifdef TCP_SIGNATURE
	case IPPROTO_TCP:
		return SADB_X_SATYPE_TCPSIGNATURE;
#endif
	default:
		return 0;
	}
	/* NOTREACHED */
}

/* %%% PF_KEY */
/*
 * SADB_GETSPI processing is to receive
 *	<base, (SA2), src address, dst address, (SPI range)>
 * from the IKMPd, to assign a unique spi value, to hang on the INBOUND
 * tree with the status of LARVAL, and send
 *	<base, SA(*), address(SD)>
 * to the IKMPd.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static int
key_getspi(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *newsah;
	struct secasvar *newsav;
	u_int8_t proto;
	u_int32_t spi;
	u_int8_t mode;
	u_int16_t reqid;
	int error;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_getspi: NULL pointer is passed.");

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_getspi: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_getspi: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_X_EXT_SA2] != NULL) {
		mode = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
		reqid = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_reqid;
	} else {
		mode = IPSEC_MODE_ANY;
		reqid = 0;
	}

	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_getspi: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* make sure if port number is zero. */
	switch (((struct sockaddr *)(src0 + 1))->sa_family) {
	case AF_INET:
		if (((struct sockaddr *)(src0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in *)(src0 + 1))->sin_port = 0;
		break;
	case AF_INET6:
		if (((struct sockaddr *)(src0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in6))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in6 *)(src0 + 1))->sin6_port = 0;
		break;
	default:
		; /*???*/
	}
	switch (((struct sockaddr *)(dst0 + 1))->sa_family) {
	case AF_INET:
		if (((struct sockaddr *)(dst0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in *)(dst0 + 1))->sin_port = 0;
		break;
	case AF_INET6:
		if (((struct sockaddr *)(dst0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in6))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in6 *)(dst0 + 1))->sin6_port = 0;
		break;
	default:
		; /*???*/
	}

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, mode, reqid, src0 + 1, dst0 + 1, &saidx);

	/* SPI allocation */
	spi = key_do_getnewspi((struct sadb_spirange *)mhp->ext[SADB_EXT_SPIRANGE],
	                       &saidx);
	if (spi == 0)
		return key_senderror(so, m, EINVAL);

	/* get a SA index */
	if ((newsah = key_getsah(&saidx)) == NULL) {
		/* create a new SA index */
		if ((newsah = key_newsah(&saidx)) == NULL) {
			ipseclog((LOG_DEBUG, "key_getspi: No more memory.\n"));
			return key_senderror(so, m, ENOBUFS);
		}
	}

	/* get a new SA */
	/* XXX rewrite */
	newsav = key_newsav(m, mhp, newsah, &error);
	if (newsav == NULL) {
		/* XXX don't free new SA index allocated in above. */
		return key_senderror(so, m, error);
	}

	/* set spi */
	key_setspi(newsav, htonl(spi));

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* delete the entry in acqtree */
	if (mhp->msg->sadb_msg_seq != 0) {
		struct secacq *acq;
		if ((acq = key_getacqbyseq(mhp->msg->sadb_msg_seq)) != NULL) {
			/* reset counter in order to deletion by timehandler. */
#ifdef __FreeBSD__
			acq->created = time_second;
#else
			acq->created = time.tv_sec;
#endif
			acq->count = 0;
		}
    	}
#endif

    {
	struct mbuf *n, *nn;
	struct sadb_sa *m_sa;
	struct sadb_msg *newmsg;
	int off, len;

	/* create new sadb_msg to reply. */
	len = PFKEY_ALIGN8(sizeof(struct sadb_msg)) +
	    PFKEY_ALIGN8(sizeof(struct sadb_sa));
	if (len > MCLBYTES)
		return key_senderror(so, m, ENOBUFS);

	MGETHDR(n, M_DONTWAIT, MT_DATA);
	if (len > MHLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	n->m_len = len;
	n->m_next = NULL;
	off = 0;

	m_copydata(m, 0, sizeof(struct sadb_msg), mtod(n, caddr_t) + off);
	off += PFKEY_ALIGN8(sizeof(struct sadb_msg));

	m_sa = (struct sadb_sa *)(mtod(n, caddr_t) + off);
	m_sa->sadb_sa_len = PFKEY_UNIT64(sizeof(struct sadb_sa));
	m_sa->sadb_sa_exttype = SADB_EXT_SA;
	m_sa->sadb_sa_spi = htonl(spi);
	off += PFKEY_ALIGN8(sizeof(struct sadb_sa));

#ifdef DIAGNOSTIC
	if (off != len)
		panic("length inconsistency in key_getspi");
#endif

	n->m_next = key_gather_mbuf(m, mhp, 0, 2, SADB_EXT_ADDRESS_SRC,
	    SADB_EXT_ADDRESS_DST);
	if (!n->m_next) {
		m_freem(n);
		return key_senderror(so, m, ENOBUFS);
	}

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return key_sendup_mbuf(so, m, KEY_SENDUP_ONE);
	}

	n->m_pkthdr.len = 0;
	for (nn = n; nn; nn = nn->m_next)
		n->m_pkthdr.len += nn->m_len;

	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_seq = newsav->seq;
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
    }
}

/*
 * allocating new SPI
 * called by key_getspi().
 * OUT:
 *	0:	failure.
 *	others: success.
 */
static u_int32_t
key_do_getnewspi(struct sadb_spirange *spirange, struct secasindex *saidx)
{
	u_int32_t newspi;
	u_int32_t min, max;
	int count = key_spi_trycnt;

	/* set spi range to allocate */
	if (spirange != NULL) {
		min = spirange->sadb_spirange_min;
		max = spirange->sadb_spirange_max;
	} else {
		min = key_spi_minval;
		max = key_spi_maxval;
	}
	/* IPCOMP needs 2-byte SPI */
	if (saidx->proto == IPPROTO_IPCOMP) {
		u_int32_t t;
		if (min >= 0x10000)
			min = 0xffff;
		if (max >= 0x10000)
			max = 0xffff;
		if (min > max) {
			t = min; min = max; max = t;
		}
	}

	if (min == max) {
		if (key_checkspidup(saidx, min) != NULL) {
			ipseclog((LOG_DEBUG, "key_do_getnewspi: SPI %u exists already.\n", min));
			return 0;
		}

		count--; /* taking one cost. */
		newspi = min;

	} else {

		/* init SPI */
		newspi = 0;

		/* when requesting to allocate spi ranged */
		while (count--) {
			/* generate pseudo-random SPI value ranged. */
			newspi = min + (key_random() % (max - min + 1));

			if (key_checkspidup(saidx, newspi) == NULL)
				break;
		}

		if (count == 0 || newspi == 0) {
			ipseclog((LOG_DEBUG, "key_do_getnewspi: to allocate spi is failed.\n"));
			return 0;
		}
	}

	/* statistics */
	keystat.getspi_count =
		(keystat.getspi_count + key_spi_trycnt - count) / 2;

	return newspi;
}

/*
 * SADB_UPDATE processing
 * receive
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       key(AE), (identity(SD),) (sensitivity)>
 * from the ikmpd, and update a secasvar entry whose status is SADB_SASTATE_LARVAL.
 * and send
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_update(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;
	u_int8_t mode;
	u_int16_t reqid;
	int error;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_update: NULL pointer is passed.");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_update: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_ESP &&
	     mhp->ext[SADB_EXT_KEY_ENCRYPT] == NULL) ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_AH &&
	     mhp->ext[SADB_EXT_KEY_AUTH] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] != NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] == NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] != NULL)) {
		ipseclog((LOG_DEBUG, "key_update: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa) ||
	    mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_update: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_X_EXT_SA2] != NULL) {
		mode = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
		reqid = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_reqid;
	} else {
		mode = IPSEC_MODE_ANY;
		reqid = 0;
	}
	/* XXX boundary checking for other extensions */

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, mode, reqid, src0 + 1, dst0 + 1, &saidx);

	/* get a SA header */
	if ((sah = key_getsah(&saidx)) == NULL) {
		ipseclog((LOG_DEBUG, "key_update: no SA index found.\n"));
		return key_senderror(so, m, ENOENT);
	}

	/* set spidx if there */
	/* XXX rewrite */
	error = key_setident(sah, m, mhp);
	if (error)
		return key_senderror(so, m, error);

	/* find a SA with sequence number. */
#ifdef IPSEC_DOSEQCHECK
	if (mhp->msg->sadb_msg_seq != 0 &&
	    (sav = key_getsavbyseq(sah, mhp->msg->sadb_msg_seq)) == NULL) {
		ipseclog((LOG_DEBUG,
		    "key_update: no larval SA with sequence %u exists.\n",
		    mhp->msg->sadb_msg_seq));
		return key_senderror(so, m, ENOENT);
	}
#else
	if ((sav = key_getsavbyspi(sah, sa0->sadb_sa_spi)) == NULL) {
		ipseclog((LOG_DEBUG,
		    "key_update: no such a SA found (spi:%u)\n",
		    (u_int32_t)ntohl(sa0->sadb_sa_spi)));
		return key_senderror(so, m, EINVAL);
	}
#endif

	/* validity check */
	if (sav->sah->saidx.proto != proto) {
		ipseclog((LOG_DEBUG,
		    "key_update: protocol mismatched (DB=%u param=%u)\n",
		    sav->sah->saidx.proto, proto));
		return key_senderror(so, m, EINVAL);
	}
#ifdef IPSEC_DOSEQCHECK
	if (sav->spi != sa0->sadb_sa_spi) {
		ipseclog((LOG_DEBUG,
		    "key_update: SPI mismatched (DB:%u param:%u)\n",
		    (u_int32_t)ntohl(sav->spi),
		    (u_int32_t)ntohl(sa0->sadb_sa_spi)));
		return key_senderror(so, m, EINVAL);
	}
#endif
	if (sav->pid != mhp->msg->sadb_msg_pid) {
		ipseclog((LOG_DEBUG,
		    "key_update: pid mismatched (DB:%u param:%u)\n",
		    sav->pid, mhp->msg->sadb_msg_pid));
		return key_senderror(so, m, EINVAL);
	}

	/* copy sav values */
	error = key_setsaval(sav, m, mhp);
	if (error) {
		key_freesav(sav);
		return key_senderror(so, m, error);
	}

	/* check SA values to be mature. */
	if ((error = key_mature(sav)) != 0) {
		key_freesav(sav);
		return key_senderror(so, m, error);
	}

    {
	struct mbuf *n;

	/* set msg buf from mhp */
	n = key_getmsgbuf_x1(m, mhp);
	if (n == NULL) {
		ipseclog((LOG_DEBUG, "key_update: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * search SAD with sequence for a SA which state is SADB_SASTATE_LARVAL.
 * only called by key_update().
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
#ifdef IPSEC_DOSEQCHECK
static struct secasvar *
key_getsavbyseq(struct secashead *sah, u_int32_t seq)
{
	struct secasvar *sav;
	u_int state;

	state = SADB_SASTATE_LARVAL;

	/* search SAD with sequence number ? */
	LIST_FOREACH(sav, &sah->savtree[state], chain) {

		KEY_CHKSASTATE(state, sav->state, "key_getsabyseq");

		if (sav->seq == seq)
			return sav;
	}

	return NULL;
}
#endif

/*
 * SADB_ADD processing
 * add an entry to SA database, when received
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       key(AE), (identity(SD),) (sensitivity)>
 * from the ikmpd,
 * and send
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * IGNORE identity and sensitivity messages.
 *
 * m will always be freed.
 */
static int
key_add(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *newsah;
	struct secasvar *newsav;
	u_int16_t proto;
	u_int8_t mode;
	u_int16_t reqid;
	int error;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_add: NULL pointer is passed.");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_add: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_ESP &&
	     mhp->ext[SADB_EXT_KEY_ENCRYPT] == NULL) ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_AH &&
	     mhp->ext[SADB_EXT_KEY_AUTH] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] != NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] == NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] != NULL)) {
		ipseclog((LOG_DEBUG, "key_add: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa) ||
	    mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		/* XXX need more */
		ipseclog((LOG_DEBUG, "key_add: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_X_EXT_SA2] != NULL) {
		mode = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
		reqid = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_reqid;
	} else {
		mode = IPSEC_MODE_ANY;
		reqid = 0;
	}

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, mode, reqid, src0 + 1, dst0 + 1, &saidx);

	/* get a SA header */
	if ((newsah = key_getsah(&saidx)) == NULL) {
		/* create a new SA header */
		if ((newsah = key_newsah(&saidx)) == NULL) {
			ipseclog((LOG_DEBUG, "key_add: No more memory.\n"));
			return key_senderror(so, m, ENOBUFS);
		}
	}

	/* set spidx if there */
	/* XXX rewrite */
	error = key_setident(newsah, m, mhp);
	if (error) {
		return key_senderror(so, m, error);
	}

	/* create new SA entry. */
	/* We can create new SA only if SPI is differenct. */
	if (key_getsavbyspi(newsah, sa0->sadb_sa_spi)) {
		ipseclog((LOG_DEBUG, "key_add: SA already exists.\n"));
		return key_senderror(so, m, EEXIST);
	}
	newsav = key_newsav(m, mhp, newsah, &error);
	if (newsav == NULL) {
		return key_senderror(so, m, error);
	}

	/* check SA values to be mature. */
	if ((error = key_mature(newsav)) != 0) {
		key_freesav(newsav);
		return key_senderror(so, m, error);
	}

	/*
	 * don't call key_freesav() here, as we would like to keep the SA
	 * in the database on success.
	 */

    {
	struct mbuf *n;

	/* set msg buf from mhp */
	n = key_getmsgbuf_x1(m, mhp);
	if (n == NULL) {
		ipseclog((LOG_DEBUG, "key_update: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/* m is retained */
static int
key_setident(struct secashead *sah, struct mbuf *m,
	const struct sadb_msghdr *mhp)
{
	const struct sadb_ident *idsrc, *iddst;
	int idsrclen, iddstlen;

	/* sanity check */
	if (sah == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_setident: NULL pointer is passed.");

	/* don't make buffer if not there */
	if (mhp->ext[SADB_EXT_IDENTITY_SRC] == NULL &&
	    mhp->ext[SADB_EXT_IDENTITY_DST] == NULL) {
		sah->idents = NULL;
		sah->identd = NULL;
		return 0;
	}
	
	if (mhp->ext[SADB_EXT_IDENTITY_SRC] == NULL ||
	    mhp->ext[SADB_EXT_IDENTITY_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_setident: invalid identity.\n"));
		return EINVAL;
	}

	idsrc = (const struct sadb_ident *)mhp->ext[SADB_EXT_IDENTITY_SRC];
	iddst = (const struct sadb_ident *)mhp->ext[SADB_EXT_IDENTITY_DST];
	idsrclen = mhp->extlen[SADB_EXT_IDENTITY_SRC];
	iddstlen = mhp->extlen[SADB_EXT_IDENTITY_DST];

	/* validity check */
	if (idsrc->sadb_ident_type != iddst->sadb_ident_type) {
		ipseclog((LOG_DEBUG, "key_setident: ident type mismatch.\n"));
		return EINVAL;
	}

	switch (idsrc->sadb_ident_type) {
	case SADB_IDENTTYPE_PREFIX:
	case SADB_IDENTTYPE_FQDN:
	case SADB_IDENTTYPE_USERFQDN:
	default:
		/* XXX do nothing */
		sah->idents = NULL;
		sah->identd = NULL;
	 	return 0;
	}

	/* make structure */
	KMALLOC(sah->idents, struct sadb_ident *, idsrclen);
	if (sah->idents == NULL) {
		ipseclog((LOG_DEBUG, "key_setident: No more memory.\n"));
		return ENOBUFS;
	}
	KMALLOC(sah->identd, struct sadb_ident *, iddstlen);
	if (sah->identd == NULL) {
		KFREE(sah->idents);
		sah->idents = NULL;
		ipseclog((LOG_DEBUG, "key_setident: No more memory.\n"));
		return ENOBUFS;
	}
	bcopy(idsrc, sah->idents, idsrclen);
	bcopy(iddst, sah->identd, iddstlen);

	return 0;
}

/*
 * m will not be freed on return.
 * it is caller's responsibility to free the result. 
 */
static struct mbuf *
key_getmsgbuf_x1(struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct mbuf *n;

	/* sanity check */
	if (m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_getmsgbuf_x1: NULL pointer is passed.");

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, 9, SADB_EXT_RESERVED,
	    SADB_EXT_SA, SADB_X_EXT_SA2,
	    SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST,
	    SADB_EXT_LIFETIME_HARD, SADB_EXT_LIFETIME_SOFT,
	    SADB_EXT_IDENTITY_SRC, SADB_EXT_IDENTITY_DST);
	if (!n)
		return NULL;

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return NULL;
	}
	mtod(n, struct sadb_msg *)->sadb_msg_errno = 0;
	mtod(n, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(n->m_pkthdr.len);

	return n;
}

static int key_delete_all(struct socket *, struct mbuf *,
	const struct sadb_msghdr *, u_int16_t);

/*
 * SADB_DELETE processing
 * receive
 *   <base, SA(*), address(SD)>
 * from the ikmpd, and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, SA(*), address(SD)>
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_delete(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav = NULL;
	u_int16_t proto;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_delete: NULL pointer is passed.");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_delete: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_delete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_delete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL) {
		/*
		 * Caller wants us to delete all non-LARVAL SAs
		 * that match the src/dst.  This is used during
		 * IKE INITIAL-CONTACT.
		 */
		ipseclog((LOG_DEBUG, "key_delete: doing delete all.\n"));
		return key_delete_all(so, m, mhp, proto);
	} else if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa)) {
		ipseclog((LOG_DEBUG, "key_delete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	/* get a SA header */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_HEAD) == 0)
			continue;

		/* get a SA with SPI. */
		sav = key_getsavbyspi(sah, sa0->sadb_sa_spi);
		if (sav)
			break;
	}
	if (sah == NULL) {
		ipseclog((LOG_DEBUG, "key_delete: no SA found.\n"));
		return key_senderror(so, m, ENOENT);
	}

	key_sa_chgstate(sav, SADB_SASTATE_DEAD);
	key_freesav(sav);
	sav = NULL;

    {
	struct mbuf *n;
	struct sadb_msg *newmsg;

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, 4, SADB_EXT_RESERVED,
	    SADB_EXT_SA, SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return key_senderror(so, m, ENOBUFS);
	}
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * delete all SAs for src/dst.  Called from key_delete().
 */
static int
key_delete_all(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp,
	u_int16_t proto)
{
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav, *nextsav;
	u_int stateidx, state;

	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_HEAD) == 0)
			continue;

		/* Delete all non-LARVAL SAs. */
		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_alive[stateidx];
			if (state == SADB_SASTATE_LARVAL)
				continue;
			for (sav = LIST_FIRST(&sah->savtree[state]);
			     sav != NULL; sav = nextsav) {
				nextsav = LIST_NEXT(sav, chain);
				/* sanity check */
				if (sav->state != state) {
					ipseclog((LOG_DEBUG, "key_delete_all: "
					       "invalid sav->state "
					       "(queue: %u SA: %u)\n",
					       state, sav->state));
					continue;
				}
				
				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav);
			}
		}
	}
    {
	struct mbuf *n;
	struct sadb_msg *newmsg;

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, 3, SADB_EXT_RESERVED,
	    SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return key_senderror(so, m, ENOBUFS);
	}
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_GET processing
 * receive
 *   <base, SA(*), address(SD)>
 * from the ikmpd, and get a SP and a SA to respond,
 * and send,
 *   <base, SA, (lifetime(HSC),) address(SD), (address(P),) key(AE),
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_get(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav = NULL;
	u_int16_t proto;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_get: NULL pointer is passed.");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_get: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_get: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa) ||
	    mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_get: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	/* get a SA header */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_HEAD) == 0)
			continue;

		/* get a SA with SPI. */
		sav = key_getsavbyspi(sah, sa0->sadb_sa_spi);
		if (sav)
			break;
	}
	if (sah == NULL) {
		ipseclog((LOG_DEBUG, "key_get: no SA found.\n"));
		return key_senderror(so, m, ENOENT);
	}

    {
	struct mbuf *n;
	u_int8_t satype;

	/* map proto to satype */
	if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
		ipseclog((LOG_DEBUG, "key_get: there was invalid proto in SAD.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* create new sadb_msg to reply. */
	n = key_setdumpsa(sav, SADB_GET, satype, mhp->msg->sadb_msg_seq,
	    mhp->msg->sadb_msg_pid);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
    }
}

/* XXX make it sysctl-configurable? */
static void
key_getcomb_setlifetime(struct sadb_comb *comb)
{

	comb->sadb_comb_soft_allocations = 1;
	comb->sadb_comb_hard_allocations = 1;
	comb->sadb_comb_soft_bytes = 0;
	comb->sadb_comb_hard_bytes = 0;
	comb->sadb_comb_hard_addtime = 86400;	/* 1 day */
	comb->sadb_comb_soft_addtime = comb->sadb_comb_hard_addtime * 80 / 100;
	comb->sadb_comb_hard_usetime = 28800;	/* 8 hours */
	comb->sadb_comb_soft_usetime = comb->sadb_comb_hard_usetime * 80 / 100;
}

#ifdef IPSEC_ESP
/*
 * XXX reorder combinations by preference
 * XXX no idea if the user wants ESP authentication or not
 */
static struct mbuf *
key_getcomb_esp(void)
{
	struct sadb_comb *comb;
	const struct esp_algorithm *algo;
	struct mbuf *result = NULL, *m, *n;
	int encmin;
	int i, off, o;
	int totlen;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_comb));

	m = NULL;
	for (i = 1; i <= SADB_EALG_MAX; i++) {
		algo = esp_algorithm_lookup(i);
		if (!algo)
			continue;

		if (algo->keymax < ipsec_esp_keymin)
			continue;
		if (algo->keymin < ipsec_esp_keymin)
			encmin = ipsec_esp_keymin;
		else
			encmin = algo->keymin;

		if (ipsec_esp_auth)
			m = key_getcomb_ah();
		else {
#ifdef DIAGNOSTIC
			if (l > MLEN)
				panic("assumption failed in key_getcomb_esp");
#endif
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m) {
				M_ALIGN(m, l);
				m->m_len = l;
				m->m_next = NULL;
				bzero(mtod(m, caddr_t), m->m_len);
			}
		}
		if (!m)
			goto fail;

		totlen = 0;
		for (n = m; n; n = n->m_next)
			totlen += n->m_len;
#ifdef DIAGNOSTIC
		if (totlen % l)
			panic("assumption failed in key_getcomb_esp");
#endif

		for (off = 0; off < totlen; off += l) {
			n = m_pulldown(m, off, l, &o);
			if (!n) {
				/* m is already freed */
				goto fail;
			}
			comb = (struct sadb_comb *)(mtod(n, caddr_t) + o);
			bzero(comb, sizeof(*comb));
			key_getcomb_setlifetime(comb);
			comb->sadb_comb_encrypt = i;
			comb->sadb_comb_encrypt_minbits = encmin;
			comb->sadb_comb_encrypt_maxbits = algo->keymax;
		}

		if (!result)
			result = m;
		else
			m_cat(result, m);
	}

	return result;

 fail:
	if (result)
		m_freem(result);
	return NULL;
}
#endif

/*
 * XXX reorder combinations by preference
 */
static struct mbuf *
key_getcomb_ah(void)
{
	struct sadb_comb *comb;
	const struct ah_algorithm *algo;
	struct mbuf *m;
	int min;
	int i;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_comb));

	m = NULL;
	for (i = 1; i <= SADB_AALG_MAX; i++) {
#if 1
		/* we prefer HMAC algorithms, not old algorithms */
		if (i != SADB_AALG_SHA1HMAC && i != SADB_AALG_MD5HMAC)
			continue;
#endif
		algo = ah_algorithm_lookup(i);
		if (!algo)
			continue;

		if (algo->keymax < ipsec_ah_keymin)
			continue;
		if (algo->keymin < ipsec_ah_keymin)
			min = ipsec_ah_keymin;
		else
			min = algo->keymin;

		if (!m) {
#ifdef DIAGNOSTIC
			if (l > MLEN)
				panic("assumption failed in key_getcomb_ah");
#endif
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m) {
				M_ALIGN(m, l);
				m->m_len = l;
				m->m_next = NULL;
			}
		} else
			M_PREPEND(m, l, M_DONTWAIT);
		if (!m)
			return NULL;

		comb = mtod(m, struct sadb_comb *);
		bzero(comb, sizeof(*comb));
		key_getcomb_setlifetime(comb);
		comb->sadb_comb_auth = i;
		comb->sadb_comb_auth_minbits = min;
		comb->sadb_comb_auth_maxbits = algo->keymax;
	}

	return m;
}

/*
 * not really an official behavior.  discussed in pf_key@inner.net in Sep2000.
 * XXX reorder combinations by preference
 */
static struct mbuf *
key_getcomb_ipcomp(void)
{
	struct sadb_comb *comb;
	const struct ipcomp_algorithm *algo;
	struct mbuf *m;
	int i;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_comb));

	m = NULL;
	for (i = 1; i <= SADB_X_CALG_MAX; i++) {
		algo = ipcomp_algorithm_lookup(i);
		if (!algo)
			continue;

		if (!m) {
#ifdef DIAGNOSTIC
			if (l > MLEN)
				panic("assumption failed in key_getcomb_ipcomp");
#endif
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m) {
				M_ALIGN(m, l);
				m->m_len = l;
				m->m_next = NULL;
			}
		} else
			M_PREPEND(m, l, M_DONTWAIT);
		if (!m)
			return NULL;

		comb = mtod(m, struct sadb_comb *);
		bzero(comb, sizeof(*comb));
		key_getcomb_setlifetime(comb);
		comb->sadb_comb_encrypt = i;
		/* what should we set into sadb_comb_*_{min,max}bits? */
	}

	return m;
}

/*
 * XXX no way to pass mode (transport/tunnel) to userland
 * XXX replay checking?
 * XXX sysctl interface to ipsec_{ah,esp}_keymin
 */
static struct mbuf *
key_getprop(const struct secasindex *saidx)
{
	struct sadb_prop *prop;
	struct mbuf *m, *n;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_prop));
	int totlen;

	switch (saidx->proto)  {
#ifdef IPSEC_ESP
	case IPPROTO_ESP:
		m = key_getcomb_esp();
		break;
#endif
	case IPPROTO_AH:
		m = key_getcomb_ah();
		break;
	case IPPROTO_IPCOMP:
		m = key_getcomb_ipcomp();
		break;
	default:
		return NULL;
	}

	if (!m)
		return NULL;
	M_PREPEND(m, l, M_DONTWAIT);
	if (!m)
		return NULL;

	totlen = 0;
	for (n = m; n; n = n->m_next)
		totlen += n->m_len;

	prop = mtod(m, struct sadb_prop *);
	bzero(prop, sizeof(*prop));
	prop->sadb_prop_len = PFKEY_UNIT64(totlen);
	prop->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	prop->sadb_prop_replay = 32;	/* XXX */

	return m;
}

/*
 * SADB_ACQUIRE processing called by key_checkrequest() and key_acquire2().
 * send
 *   <base, SA, address(SD), (address(P)), x_policy,
 *       (identity(SD),) (sensitivity,) proposal, (x_packet)>
 * to KMD, and expect to receive
 *   <base> with SADB_ACQUIRE if error occured,
 * or
 *   <base, src address, dst address, (SPI range)> with SADB_GETSPI
 * from KMD by PF_KEY.
 *
 * XXX x_policy is outside of RFC2367 (KAME extension).
 * XXX sensitivity is not supported.
 * XXX for ipcomp, RFC2367 does not define how to fill in proposal.
 * XXX x_packet is an IKEv2 extension.
 * see comment for key_getcomb_ipcomp().
 *
 * (note: x_packet exists only if PFKEYV2_SADB_X_EXT_PACKET is set)
 *
 * OUT:
 *    0     : succeed
 *    others: error number
 */
static int
#ifdef PFKEYV2_SADB_X_EXT_PACKET
key_acquire(struct secasindex *saidx, struct secpolicy *sp, struct mbuf *pkt)
#else
key_acquire(struct secasindex *saidx, struct secpolicy *sp)
#endif
{
	struct mbuf *result = NULL, *m;
#ifndef IPSEC_NONBLOCK_ACQUIRE
	struct secacq *newacq;
#endif
	u_int8_t satype;
	int error = -1;
	u_int32_t seq;

	/* sanity check */
	if (saidx == NULL)
		panic("key_acquire: NULL pointer is passed.");
	if ((satype = key_proto2satype(saidx->proto)) == 0)
		panic("key_acquire: invalid proto is passed.");

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/*
	 * We never do anything about acquirng SA.  There is anather
	 * solution that kernel blocks to send SADB_ACQUIRE message until
	 * getting something message from IKEd.  In later case, to be
	 * managed with ACQUIRING list.
	 */
	/* get an entry to check whether sending message or not. */
	if ((newacq = key_getacq(saidx)) != NULL) {
		if (key_blockacq_count < newacq->count) {
			/* reset counter and do send message. */
			newacq->count = 0;
		} else {
			/* increment counter and do nothing. */
			newacq->count++;
			return 0;
		}
	} else {
		/* make new entry for blocking to send SADB_ACQUIRE. */
		if ((newacq = key_newacq(saidx)) == NULL)
			return ENOBUFS;

		/* add to acqtree */
		LIST_INSERT_HEAD(&acqtree, newacq, chain);
	}
#endif


#ifndef IPSEC_NONBLOCK_ACQUIRE
	seq = newacq->seq;
#else
	seq = (acq_seq = (acq_seq == ~0 ? 1 : ++acq_seq));
#endif
	m = key_setsadbmsg(SADB_ACQUIRE, 0, satype, seq, 0, 0);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* set sadb_address for saidx's. */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
	    (struct sockaddr *)&saidx->src, FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
	    (struct sockaddr *)&saidx->dst, FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* XXX proxy address (optional) */

	/* set sadb_x_policy */
	if (sp) {
		m = key_setsadbxpolicy(sp->policy, sp->dir, sp->id);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);
	}

	/* set sadb_x_tag */
	if (sp && sp->tag) {
		m = key_setsadbxtag(sp->tag);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);
	}

	/* XXX identity (optional) */
#if 0
	if (idexttype && fqdn) {
		/* create identity extension (FQDN) */
		struct sadb_ident *id;
		int fqdnlen;

		fqdnlen = strlen(fqdn) + 1;	/* +1 for terminating-NUL */
		id = (struct sadb_ident *)p;
		bzero(id, sizeof(*id) + PFKEY_ALIGN8(fqdnlen));
		id->sadb_ident_len = PFKEY_UNIT64(sizeof(*id) + PFKEY_ALIGN8(fqdnlen));
		id->sadb_ident_exttype = idexttype;
		id->sadb_ident_type = SADB_IDENTTYPE_FQDN;
		bcopy(fqdn, id + 1, fqdnlen);
		p += sizeof(struct sadb_ident) + PFKEY_ALIGN8(fqdnlen);
	}

	if (idexttype) {
		/* create identity extension (USERFQDN) */
		struct sadb_ident *id;
		int userfqdnlen;

		if (userfqdn) {
			/* +1 for terminating-NUL */
			userfqdnlen = strlen(userfqdn) + 1;
		} else
			userfqdnlen = 0;
		id = (struct sadb_ident *)p;
		bzero(id, sizeof(*id) + PFKEY_ALIGN8(userfqdnlen));
		id->sadb_ident_len = PFKEY_UNIT64(sizeof(*id) + PFKEY_ALIGN8(userfqdnlen));
		id->sadb_ident_exttype = idexttype;
		id->sadb_ident_type = SADB_IDENTTYPE_USERFQDN;
		/* XXX is it correct? */
		if (curproc && curproc->p_cred)
			id->sadb_ident_id = curproc->p_cred->p_ruid;
		if (userfqdn && userfqdnlen)
			bcopy(userfqdn, id + 1, userfqdnlen);
		p += sizeof(struct sadb_ident) + PFKEY_ALIGN8(userfqdnlen);
	}
#endif

	/* XXX sensitivity (optional) */

	/* create proposal/combination extension */
	m = key_getprop(saidx);
#if 0
	/*
	 * spec conformant: always attach proposal/combination extension,
	 * the problem is that we have no way to attach it for ipcomp,
	 * due to the way sadb_comb is declared in RFC2367.
	 */
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);
#else
	/*
	 * outside of spec; make proposal/combination extension optional.
	 */
	if (m)
		m_cat(result, m);
#endif

#ifdef PFKEYV2_SADB_X_EXT_PACKET
	/*
	 * add the triggering packet.
	 */
	if (pkt) {
		int copy_len, len;
		struct sadb_x_packet *ext;

		copy_len = pkt->m_pkthdr.len;
		if (copy_len > acq_maxpktlen)
			copy_len = acq_maxpktlen;
		len = PFKEY_ALIGN8(sizeof(struct sadb_x_packet) + copy_len);

		m = key_alloc_mbuf(len);
		if (!m || m->m_next) {
			if (m)
				m_freem(m);
			error = ENOBUFS;
			goto fail;
		}

		bzero(mtod(m, caddr_t), len);
		ext = mtod(m, struct sadb_x_packet *);
		ext->sadb_x_packet_len = PFKEY_UNIT64(len);
		ext->sadb_x_packet_exttype = SADB_X_EXT_PACKET;
		ext->sadb_x_packet_copylen = copy_len;
		m_copydata(pkt, 0, copy_len, (caddr_t)(ext + 1));

		m_cat(result, m);
	}
#endif /* PFKEYV2_SADB_X_EXT_PACKET */

	if ((result->m_flags & M_PKTHDR) == 0) {
		error = EINVAL;
		goto fail;
	}

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			error = ENOBUFS;
			goto fail;
		}
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

 fail:
	if (result)
		m_freem(result);
	return error;
}

#ifndef IPSEC_NONBLOCK_ACQUIRE
static struct secacq *
key_newacq(struct secasindex *saidx)
{
	struct secacq *newacq;

	/* get new entry */
	KMALLOC(newacq, struct secacq *, sizeof(struct secacq));
	if (newacq == NULL) {
		ipseclog((LOG_DEBUG, "key_newacq: No more memory.\n"));
		return NULL;
	}
	bzero(newacq, sizeof(*newacq));

	/* copy secindex */
	bcopy(saidx, &newacq->saidx, sizeof(newacq->saidx));
	newacq->seq = (acq_seq == ~0 ? 1 : ++acq_seq);
#ifdef __FreeBSD__
	newacq->created = time_second;
#else
	newacq->created = time.tv_sec;
#endif
	newacq->count = 0;

	return newacq;
}

static struct secacq *
key_getacq(struct secasindex *saidx)
{
	struct secacq *acq;

	LIST_FOREACH(acq, &acqtree, chain) {
		if (key_cmpsaidx(saidx, &acq->saidx, CMP_EXACTLY))
			return acq;
	}

	return NULL;
}

static struct secacq *
key_getacqbyseq(u_int32_t seq)
{
	struct secacq *acq;

	LIST_FOREACH(acq, &acqtree, chain) {
		if (acq->seq == seq)
			return acq;
	}

	return NULL;
}
#endif

static struct secspacq *
key_newspacq(struct secpolicyindex *spidx)
{
	struct secspacq *acq;

	if (!spidx)
		return NULL;

	/* get new entry */
	KMALLOC(acq, struct secspacq *, sizeof(struct secspacq));
	if (acq == NULL) {
		ipseclog((LOG_DEBUG, "key_newspacq: No more memory.\n"));
		return NULL;
	}
	bzero(acq, sizeof(*acq));

	/* copy secindex */
	bcopy(spidx, &acq->spidx, sizeof(acq->spidx));
#ifdef __FreeBSD__
	acq->created = time_second;
#else
	acq->created = time.tv_sec;
#endif
	acq->count = 1;

	return acq;
}

static struct secspacq *
key_getspacq(struct secpolicyindex *spidx)
{
	struct secspacq *acq;

	if (!spidx)
		return NULL;

	LIST_FOREACH(acq, &spacqtree, chain) {
		if (key_cmpspidx_exactly(spidx, &acq->spidx))
			return acq;
	}

	return NULL;
}

/*
 * SADB_ACQUIRE processing,
 * in first situation, is receiving
 *   <base>
 * from the ikmpd, and clear sequence of its secasvar entry.
 *
 * In second situation, is receiving
 *   <base, address(SD), (address(P),) (identity(SD),) (sensitivity,) proposal>
 * from a user land process, and return
 *   <base, address(SD), (address(P),) (identity(SD),) (sensitivity,) proposal>
 * to the socket.
 *
 * m will always be freed.
 */
static int
key_acquire2(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
  	/*const */struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	u_int16_t proto;
	int error;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_acquire2: NULL pointer is passed.");

	/*
	 * Error message from KMd.
	 * We assume that if error was occured in IKEd, the length of PFKEY
	 * message is equal to the size of sadb_msg structure.
	 * We do not raise error even if error occured in this function.
	 */
	if (mhp->msg->sadb_msg_len == PFKEY_UNIT64(sizeof(struct sadb_msg))) {
#ifndef IPSEC_NONBLOCK_ACQUIRE
		struct secacq *acq;

		/* check sequence number */
		if (mhp->msg->sadb_msg_seq == 0) {
			ipseclog((LOG_DEBUG, "key_acquire2: must specify sequence number.\n"));
			m_freem(m);
			return 0;
		}

		if ((acq = key_getacqbyseq(mhp->msg->sadb_msg_seq)) == NULL) {
			/*
			 * the specified larval SA is already gone, or we got
			 * a bogus sequence number.  we can silently ignore it.
			 */
			m_freem(m);
			return 0;
		}

		/* reset acq counter in order to deletion by timehandler. */
#ifdef __FreeBSD__
		acq->created = time_second;
#else
		acq->created = time.tv_sec;
#endif
		acq->count = 0;
#endif
		m_freem(m);
		return 0;
	}

	/*
	 * This message is from user land.
	 */

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_acquire2: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    mhp->ext[SADB_EXT_PROPOSAL] == NULL) {
		/* error */
		ipseclog((LOG_DEBUG, "key_acquire2: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_PROPOSAL] < sizeof(struct sadb_prop)) {
		/* error */
		ipseclog((LOG_DEBUG, "key_acquire2: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	/* get a SA index */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_MODE_REQID))
			break;
	}
	if (sah != NULL) {
		ipseclog((LOG_DEBUG, "key_acquire2: a SA exists already.\n"));
		return key_senderror(so, m, EEXIST);
	}

#ifdef PFKEYV2_SADB_X_EXT_PACKET
	error = key_acquire(&saidx, NULL, NULL);
#else
	error = key_acquire(&saidx, NULL);
#endif
	if (error != 0) {
		ipseclog((LOG_DEBUG, "key_acquire2: error %d returned "
			"from key_acquire.\n", mhp->msg->sadb_msg_errno));
		return key_senderror(so, m, error);
	}

	return key_sendup_mbuf(so, m, KEY_SENDUP_REGISTERED);
}

/*
 * SADB_REGISTER processing.
 * If SATYPE_UNSPEC has been passed as satype, only return sabd_supported.
 * receive
 *   <base>
 * from the ikmpd, and register a socket to send PF_KEY messages,
 * and send
 *   <base, supported>
 * to KMD by PF_KEY.
 * If socket is detached, must free from regnode.
 *
 * m will always be freed.
 */
static int
key_register(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct secreg *reg, *newreg = 0;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_register: NULL pointer is passed.");

	/* check for invalid register message */
	if (mhp->msg->sadb_msg_satype >= sizeof(regtree)/sizeof(regtree[0]))
		return key_senderror(so, m, EINVAL);

	/* When SATYPE_UNSPEC is specified, only return sabd_supported. */
	if (mhp->msg->sadb_msg_satype == SADB_SATYPE_UNSPEC)
		goto setmsg;

	/* check whether existing or not */
	LIST_FOREACH(reg, &regtree[mhp->msg->sadb_msg_satype], chain) {
		if (reg->so == so) {
			ipseclog((LOG_DEBUG, "key_register: socket exists already.\n"));
			return key_senderror(so, m, EEXIST);
		}
	}

	/* create regnode */
	KMALLOC(newreg, struct secreg *, sizeof(*newreg));
	if (newreg == NULL) {
		ipseclog((LOG_DEBUG, "key_register: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}
	bzero((caddr_t)newreg, sizeof(*newreg));

	newreg->so = so;
	((struct keycb *)sotorawcb(so))->kp_registered++;

	/* add regnode to regtree. */
	LIST_INSERT_HEAD(&regtree[mhp->msg->sadb_msg_satype], newreg, chain);

  setmsg:
    {
	struct mbuf *n;
	struct sadb_msg *newmsg;
	struct sadb_supported *sup;
	u_int len, alen, elen;
	int off;
	int i;
	struct sadb_alg *alg;

	/* create new sadb_msg to reply. */
	alen = 0;
	for (i = 1; i <= SADB_AALG_MAX; i++) {
		if (ah_algorithm_lookup(i))
			alen += sizeof(struct sadb_alg);
	}
	if (alen)
		alen += sizeof(struct sadb_supported);
	elen = 0;
#ifdef IPSEC_ESP
	for (i = 1; i <= SADB_EALG_MAX; i++) {
		if (esp_algorithm_lookup(i))
			elen += sizeof(struct sadb_alg);
	}
	if (elen)
		elen += sizeof(struct sadb_supported);
#endif

	len = sizeof(struct sadb_msg) + alen + elen;

	if (len > MCLBYTES)
		return key_senderror(so, m, ENOBUFS);

	MGETHDR(n, M_DONTWAIT, MT_DATA);
	if (len > MHLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	n->m_pkthdr.len = n->m_len = len;
	n->m_next = NULL;
	off = 0;

	m_copydata(m, 0, sizeof(struct sadb_msg), mtod(n, caddr_t) + off);
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	off += PFKEY_ALIGN8(sizeof(struct sadb_msg));

	/* for authentication algorithm */
	if (alen) {
		sup = (struct sadb_supported *)(mtod(n, caddr_t) + off);
		sup->sadb_supported_len = PFKEY_UNIT64(alen);
		sup->sadb_supported_exttype = SADB_EXT_SUPPORTED_AUTH;
		off += PFKEY_ALIGN8(sizeof(*sup));

		for (i = 1; i <= SADB_AALG_MAX; i++) {
			const struct ah_algorithm *aalgo;

			aalgo = ah_algorithm_lookup(i);
			if (!aalgo)
				continue;
			alg = (struct sadb_alg *)(mtod(n, caddr_t) + off);
			alg->sadb_alg_id = i;
			alg->sadb_alg_ivlen = 0;
			alg->sadb_alg_minbits = aalgo->keymin;
			alg->sadb_alg_maxbits = aalgo->keymax;
			off += PFKEY_ALIGN8(sizeof(*alg));
		}
	}

#ifdef IPSEC_ESP
	/* for encryption algorithm */
	if (elen) {
		sup = (struct sadb_supported *)(mtod(n, caddr_t) + off);
		sup->sadb_supported_len = PFKEY_UNIT64(elen);
		sup->sadb_supported_exttype = SADB_EXT_SUPPORTED_ENCRYPT;
		off += PFKEY_ALIGN8(sizeof(*sup));

		for (i = 1; i <= SADB_EALG_MAX; i++) {
			const struct esp_algorithm *ealgo;

			ealgo = esp_algorithm_lookup(i);
			if (!ealgo)
				continue;
			alg = (struct sadb_alg *)(mtod(n, caddr_t) + off);
			alg->sadb_alg_id = i;
			if (ealgo && ealgo->ivlen) {
				/*
				 * give NULL to get the value preferred by
				 * algorithm XXX SADB_X_EXT_DERIV ?
				 */
				alg->sadb_alg_ivlen =
				    (*ealgo->ivlen)(ealgo, NULL);
			} else
				alg->sadb_alg_ivlen = 0;
			alg->sadb_alg_minbits = ealgo->keymin;
			alg->sadb_alg_maxbits = ealgo->keymax;
			off += PFKEY_ALIGN8(sizeof(struct sadb_alg));
		}
	}
#endif

#ifdef DIGAGNOSTIC
	if (off != len)
		panic("length assumption failed in key_register");
#endif

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_REGISTERED);
    }
}

/*
 * free secreg entry registered.
 * XXX: I want to do free a socket marked done SADB_RESIGER to socket.
 */
void
key_freereg(struct socket *so)
{
	struct secreg *reg;
	int i;

	/* sanity check */
	if (so == NULL)
		panic("key_freereg: NULL pointer is passed.");

	/*
	 * check whether existing or not.
	 * check all type of SA, because there is a potential that
	 * one socket is registered to multiple type of SA.
	 */
	for (i = 0; i <= SADB_SATYPE_MAX; i++) {
		LIST_FOREACH(reg, &regtree[i], chain) {
			if (reg->so == so && __LIST_CHAINED(reg)) {
				LIST_REMOVE(reg, chain);
				KFREE(reg);
				break;
			}
		}
	}
	
	return;
}

/*
 * SADB_EXPIRE processing
 * send
 *   <base, SA, SA2, lifetime(C and one of HS), address(SD)>
 * to KMD by PF_KEY.
 * NOTE: We send only soft lifetime extension.
 *
 * OUT:	0	: succeed
 *	others	: error number
 */
static int
key_expire(struct secasvar *sav)
{
	int s;
	int satype;
	struct mbuf *result = NULL, *m;
	int len;
	int error = -1;
	struct sadb_lifetime *lt;

	/* XXX: Why do we lock ? */
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

	/* sanity check */
	if (sav == NULL)
		panic("key_expire: NULL pointer is passed.");
	if (sav->sah == NULL)
		panic("key_expire: Why was SA index in SA NULL.");
	if ((satype = key_proto2satype(sav->sah->saidx.proto)) == 0)
		panic("key_expire: invalid proto is passed.");

	/* set msg header */
	m = key_setsadbmsg(SADB_EXPIRE, 0, satype, sav->seq, 0, sav->refcnt);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* create SA extension */
	m = key_setsadbsa(sav);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* create SA extension */
	m = key_setsadbxsa2(sav->sah->saidx.mode,
	    sav->replay ? (sav->replay->count & 0xffffffff) : 0,
	    sav->sah->saidx.reqid);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* create lifetime extension (current and soft) */
	len = PFKEY_ALIGN8(sizeof(*lt)) * 2;
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		error = ENOBUFS;
		goto fail;
	}
	bzero(mtod(m, caddr_t), len);
	lt = mtod(m, struct sadb_lifetime *);
	lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	lt->sadb_lifetime_allocations = sav->lft_c->sadb_lifetime_allocations;
	lt->sadb_lifetime_bytes = sav->lft_c->sadb_lifetime_bytes;
	lt->sadb_lifetime_addtime = sav->lft_c->sadb_lifetime_addtime;
	lt->sadb_lifetime_usetime = sav->lft_c->sadb_lifetime_usetime;
	lt = (struct sadb_lifetime *)(mtod(m, caddr_t) + len / 2);
	bcopy(sav->lft_s, lt, sizeof(*lt));
	m_cat(result, m);

	/* set sadb_address for source */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
	    (struct sockaddr *)&sav->sah->saidx.src,
	    FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* set sadb_address for destination */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
	    (struct sockaddr *)&sav->sah->saidx.dst,
	    FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0) {
		error = EINVAL;
		goto fail;
	}

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			error = ENOBUFS;
			goto fail;
		}
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	splx(s);
	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

 fail:
	if (result)
		m_freem(result);
	splx(s);
	return error;
}

/*
 * SADB_FLUSH processing
 * receive
 *   <base>
 * from the ikmpd, and free all entries in secastree.
 * and send,
 *   <base>
 * to the ikmpd.
 * NOTE: to do is only marking SADB_SASTATE_DEAD.
 *
 * m will always be freed.
 */
static int
key_flush(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct sadb_msg *newmsg;
	struct secashead *sah, *nextsah;
	struct secasvar *sav, *nextsav;
	u_int16_t proto;
	u_int8_t state;
	u_int stateidx;

	/* sanity check */
	if (so == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_flush: NULL pointer is passed.");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_flush: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* no SATYPE specified, i.e. flushing all SA. */
	for (sah = LIST_FIRST(&sahtree); sah != NULL; sah = nextsah) {
		nextsah = LIST_NEXT(sah, chain);

		if (mhp->msg->sadb_msg_satype != SADB_SATYPE_UNSPEC &&
		    proto != sah->saidx.proto)
			continue;

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			for (sav = LIST_FIRST(&sah->savtree[state]);
			     sav != NULL;
			     sav = nextsav) {

				nextsav = LIST_NEXT(sav, chain);

				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav);
			}
		}

		sah->state = SADB_SASTATE_DEAD;
	}

	if (m->m_len < sizeof(struct sadb_msg) ||
	    sizeof(struct sadb_msg) > m->m_len + M_TRAILINGSPACE(m)) {
		ipseclog((LOG_DEBUG, "key_flush: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	if (m->m_next)
		m_freem(m->m_next);
	m->m_next = NULL;
	m->m_pkthdr.len = m->m_len = sizeof(struct sadb_msg);
	newmsg = mtod(m, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(m->m_pkthdr.len);

	return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
}

/*
 * SADB_DUMP processing
 * dump all entries including status of DEAD in SAD.
 * receive
 *   <base>
 * from the ikmpd, and dump all secasvar leaves
 * and send,
 *   <base> .....
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_dump(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;
	u_int stateidx;
	u_int8_t satype;
	u_int8_t state;
	int cnt, error = 0, needwait = 0;
	struct mbuf *n;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_dump: NULL pointer is passed.");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_dump: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* count sav entries to be sent to the userland. */
	cnt = 0;
	LIST_FOREACH(sah, &sahtree, chain) {
		if (mhp->msg->sadb_msg_satype != SADB_SATYPE_UNSPEC &&
		    proto != sah->saidx.proto)
			continue;

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {
				cnt++;
			}
		}
	}

	if (cnt == 0)
		return key_senderror(so, m, ENOENT);

	/* send this to the userland, one at a time. */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (mhp->msg->sadb_msg_satype != SADB_SATYPE_UNSPEC &&
		    proto != sah->saidx.proto)
			continue;

		/* map proto to satype */
		if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
			ipseclog((LOG_DEBUG, "key_dump: there was invalid proto in SAD.\n"));
			return key_senderror(so, m, EINVAL);
		}

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {
				n = key_setdumpsa(sav, SADB_DUMP, satype,
				    --cnt, mhp->msg->sadb_msg_pid);
				if (!n)
					return key_senderror(so, m, ENOBUFS);

				error = key_sendup_mbuf(so, n,
				    KEY_SENDUP_ONE | KEY_SENDUP_CANWAIT);
				if (error == EAGAIN)
					needwait = 1;
			}
		}
	}

#if 0
	/* XXX: this can cause infinite loop. */
	kp = (struct keycb *)sotorawcb(so);
	while (needwait && kp->kp_queue)
		sbwait(&so->so_rcv);
#endif

	m_freem(m);
	return 0;
}

#if defined(__NetBSD__) || defined(__OpenBSD__)
static struct mbuf *
key_setdump(u_int8_t req_satype, int *errorp)
{
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;
	u_int stateidx;
	u_int8_t satype;
	u_int8_t state;
	int cnt;
	struct mbuf *m, *n;

	/* map satype to proto */
	if ((proto = key_satype2proto(req_satype)) == 0) {
		*errorp = EINVAL;
		return (NULL);
	}

	/* count sav entries to be sent to the userland. */
	cnt = 0;
	LIST_FOREACH(sah, &sahtree, chain) {
		if (req_satype != SADB_SATYPE_UNSPEC &&
		    proto != sah->saidx.proto)
			continue;

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {
				cnt++;
			}
		}
	}

	if (cnt == 0) {
		*errorp = ENOENT;
		return (NULL);
	}

	/* send this to the userland, one at a time. */
	m = NULL;
	LIST_FOREACH(sah, &sahtree, chain) {
		if (req_satype != SADB_SATYPE_UNSPEC &&
		    proto != sah->saidx.proto)
			continue;

		/* map proto to satype */
		if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
			m_freem(m);
			*errorp = EINVAL;
			return (NULL);
		}

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {
				n = key_setdumpsa(sav, SADB_DUMP, satype,
				    --cnt, 0);
				if (!n) {
					m_freem(m);
					*errorp = ENOBUFS;
					return (NULL);
				}

				if (!m)
					m = n;
				else
					m_cat(m, n);
			}
		}
	}

	if (!m) {
		*errorp = EINVAL;
		return (NULL);
	}

	if ((m->m_flags & M_PKTHDR) != 0) {
		m->m_pkthdr.len = 0;
		for (n = m; n; n = n->m_next)
			m->m_pkthdr.len += n->m_len;
	}

	*errorp = 0;
	return (m);
}
#endif

struct mbuf *
key_setdumpsa_spi(u_int32_t spi)
{
	struct mbuf *m, *n;
	struct secasvar *sav;
	u_int8_t satype;
	int cnt;

	cnt = 0;
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		cnt++;
	}

	if (cnt == 0)
		return NULL;

	m = NULL;
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		satype = key_proto2satype(sav->sah->saidx.proto);
		n = key_setdumpsa(sav, SADB_DUMP, satype, --cnt, 0);
		if (!m)
			m = n;
		else if (n)
			m_cat(m, n);
	}

	if (!m)
		return NULL;

	if ((m->m_flags & M_PKTHDR) != 0) {
		m->m_pkthdr.len = 0;
		for (n = m; n; n = n->m_next)
			m->m_pkthdr.len += n->m_len;
	}

	return m;
}

/*
 * SADB_X_PROMISC processing
 *
 * m will always be freed.
 */
static int
key_promisc(struct socket *so, struct mbuf *m, const struct sadb_msghdr *mhp)
{
	int olen;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_promisc: NULL pointer is passed.");

	olen = PFKEY_UNUNIT64(mhp->msg->sadb_msg_len);

	if (olen < sizeof(struct sadb_msg)) {
#if 1
		return key_senderror(so, m, EINVAL);
#else
		m_freem(m);
		return 0;
#endif
	} else if (olen == sizeof(struct sadb_msg)) {
		/* enable/disable promisc mode */
		struct keycb *kp;

		if ((kp = (struct keycb *)sotorawcb(so)) == NULL)
			return key_senderror(so, m, EINVAL);
		mhp->msg->sadb_msg_errno = 0;
		switch (mhp->msg->sadb_msg_satype) {
		case 0:
		case 1:
			kp->kp_promisc = mhp->msg->sadb_msg_satype;
			break;
		default:
			return key_senderror(so, m, EINVAL);
		}

		/* send the original message back to everyone */
		mhp->msg->sadb_msg_errno = 0;
		return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
	} else {
		/* send packet as is */

		m_adj(m, PFKEY_ALIGN8(sizeof(struct sadb_msg)));

		/* TODO: if sadb_msg_seq is specified, send to specific pid */
		return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
	}
}

static int (*key_typesw[])(struct socket *, struct mbuf *,
		const struct sadb_msghdr *) = {
	NULL,		/* SADB_RESERVED */
	key_getspi,	/* SADB_GETSPI */
	key_update,	/* SADB_UPDATE */
	key_add,	/* SADB_ADD */
	key_delete,	/* SADB_DELETE */
	key_get,	/* SADB_GET */
	key_acquire2,	/* SADB_ACQUIRE */
	key_register,	/* SADB_REGISTER */
	NULL,		/* SADB_EXPIRE */
	key_flush,	/* SADB_FLUSH */
	key_dump,	/* SADB_DUMP */
	key_promisc,	/* SADB_X_PROMISC */
	NULL,		/* SADB_X_PCHANGE */
	key_spdadd,	/* SADB_X_SPDUPDATE */
	key_spdadd,	/* SADB_X_SPDADD */
	key_spddelete,	/* SADB_X_SPDDELETE */
	key_spdget,	/* SADB_X_SPDGET */
	NULL,		/* SADB_X_SPDACQUIRE */
	key_spddump,	/* SADB_X_SPDDUMP */
	key_spdflush,	/* SADB_X_SPDFLUSH */
	key_spdadd,	/* SADB_X_SPDSETIDX */
	NULL,		/* SADB_X_SPDEXPIRE */
	key_spddelete2,	/* SADB_X_SPDDELETE2 */
#ifdef SADB_X_NAT_T_NEW_MAPPING
	NULL,		/* SADB_X_NAT_T_NEW_MAPPING */
#else
	NULL,
#endif
#ifdef SADB_X_MIGRATE
	/*TODO */ NULL,	/* SADB_X_MIGRATE */
#else
	NULL,
#endif
};

/*
 * parse sadb_msg buffer to process PFKEYv2,
 * and create a data to response if needed.
 * I think to be dealed with mbuf directly.
 * IN:
 *     msgp  : pointer to pointer to a received buffer pulluped.
 *             This is rewrited to response.
 *     so    : pointer to socket.
 * OUT:
 *    length for buffer to send to user process.
 */
int
key_parse(struct mbuf *m, struct socket *so)
{
	struct sadb_msg *msg;
	struct sadb_msghdr mh;
	u_int orglen;
	int error;
	int target;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif

	/* sanity check */
	if (m == NULL || so == NULL)
		panic("key_parse: NULL pointer is passed.");

#if 0	/*kdebug_sadb assumes msg in linear buffer*/
	KEYDEBUG(KEYDEBUG_KEY_DUMP,
		ipseclog((LOG_DEBUG, "key_parse: passed sadb_msg\n"));
		kdebug_sadb(msg));
#endif

	if (m->m_len < sizeof(struct sadb_msg)) {
		m = m_pullup(m, sizeof(struct sadb_msg));
		if (!m)
			return ENOBUFS;
	}
	msg = mtod(m, struct sadb_msg *);
	orglen = PFKEY_UNUNIT64(msg->sadb_msg_len);
	target = KEY_SENDUP_ONE;

	if ((m->m_flags & M_PKTHDR) == 0) {
		ipseclog((LOG_DEBUG, "key_parse: invalid message length.\n"));
		pfkeystat.out_invlen++;
		error = EINVAL;
		goto senderror;
	}

	if (msg->sadb_msg_version != PF_KEY_V2) {
		ipseclog((LOG_DEBUG,
		    "key_parse: PF_KEY version %u is mismatched.\n",
		    msg->sadb_msg_version));
		pfkeystat.out_invver++;
		error = EINVAL;
		goto senderror;
	}

	if (msg->sadb_msg_type > SADB_MAX) {
		ipseclog((LOG_DEBUG, "key_parse: invalid type %u is passed.\n",
		    msg->sadb_msg_type));
		pfkeystat.out_invmsgtype++;
		error = EINVAL;
		goto senderror;
	}

	/* for old-fashioned code - should be nuked */
	if (m->m_pkthdr.len > MCLBYTES) {
		m_freem(m);
		return ENOBUFS;
	}
	if (m->m_next) {
		struct mbuf *n;

		MGETHDR(n, M_DONTWAIT, MT_DATA);
		if (n && m->m_pkthdr.len > MHLEN) {
			MCLGET(n, M_DONTWAIT);
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				n = NULL;
			}
		}
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
		n->m_pkthdr.len = n->m_len = m->m_pkthdr.len;
		n->m_next = NULL;
		m_freem(m);
		m = n;
	}

	/* align the mbuf chain so that extensions are in contiguous region. */
	error = key_align(m, &mh);
	if (error)
		return error;

	msg = mh.msg;

	/* check SA type */
	switch (msg->sadb_msg_satype) {
	case SADB_SATYPE_UNSPEC:
		switch (msg->sadb_msg_type) {
		case SADB_GETSPI:
		case SADB_UPDATE:
		case SADB_ADD:
		case SADB_DELETE:
		case SADB_GET:
		case SADB_ACQUIRE:
		case SADB_EXPIRE:
			ipseclog((LOG_DEBUG, "key_parse: must specify satype "
			    "when msg type=%u.\n", msg->sadb_msg_type));
			pfkeystat.out_invsatype++;
			error = EINVAL;
			goto senderror;
		}
		break;
	case SADB_SATYPE_AH:
	case SADB_SATYPE_ESP:
	case SADB_X_SATYPE_IPCOMP:
#ifdef TCP_SIGNATURE
	case SADB_X_SATYPE_TCPSIGNATURE:
#endif
		switch (msg->sadb_msg_type) {
		case SADB_X_SPDADD:
		case SADB_X_SPDDELETE:
		case SADB_X_SPDGET:
		case SADB_X_SPDDUMP:
		case SADB_X_SPDFLUSH:
		case SADB_X_SPDSETIDX:
		case SADB_X_SPDUPDATE:
		case SADB_X_SPDDELETE2:
#ifdef SADB_X_MIGRATE
		case SADB_X_MIGRATE:
#endif
			ipseclog((LOG_DEBUG, "key_parse: illegal satype=%u\n",
			    msg->sadb_msg_type));
			pfkeystat.out_invsatype++;
			error = EINVAL;
			goto senderror;
		}
		break;
	case SADB_SATYPE_RSVP:
	case SADB_SATYPE_OSPFV2:
	case SADB_SATYPE_RIPV2:
	case SADB_SATYPE_MIP:
		ipseclog((LOG_DEBUG, "key_parse: type %u isn't supported.\n",
		    msg->sadb_msg_satype));
		pfkeystat.out_invsatype++;
		error = EOPNOTSUPP;
		goto senderror;
	case 1:	/* XXX: What does it do? */
		if (msg->sadb_msg_type == SADB_X_PROMISC)
			break;
		/*FALLTHROUGH*/
	default:
		ipseclog((LOG_DEBUG, "key_parse: invalid type %u is passed.\n",
		    msg->sadb_msg_satype));
		pfkeystat.out_invsatype++;
		error = EINVAL;
		goto senderror;
	}

	/* check field of upper layer protocol and address family */
	if (mh.ext[SADB_EXT_ADDRESS_SRC] != NULL &&
	    mh.ext[SADB_EXT_ADDRESS_DST] != NULL) {
		struct sadb_address *src0, *dst0;
		u_int plen;

		src0 = (struct sadb_address *)(mh.ext[SADB_EXT_ADDRESS_SRC]);
		dst0 = (struct sadb_address *)(mh.ext[SADB_EXT_ADDRESS_DST]);

		/* check upper layer protocol */
		if (src0->sadb_address_proto != dst0->sadb_address_proto) {
			ipseclog((LOG_DEBUG, "key_parse: upper layer protocol mismatched.\n"));
			pfkeystat.out_invaddr++;
			error = EINVAL;
			goto senderror;
		}

		/* check family */
		if (PFKEY_ADDR_SADDR(src0)->sa_family !=
		    PFKEY_ADDR_SADDR(dst0)->sa_family) {
			ipseclog((LOG_DEBUG, "key_parse: address family mismatched.\n"));
			pfkeystat.out_invaddr++;
			error = EINVAL;
			goto senderror;
		}
		if (PFKEY_ADDR_SADDR(src0)->sa_len !=
		    PFKEY_ADDR_SADDR(dst0)->sa_len) {
			ipseclog((LOG_DEBUG,
			    "key_parse: address struct size mismatched.\n"));
			pfkeystat.out_invaddr++;
			error = EINVAL;
			goto senderror;
		}

		switch (PFKEY_ADDR_SADDR(src0)->sa_family) {
		case AF_INET:
			if (PFKEY_ADDR_SADDR(src0)->sa_len !=
			    sizeof(struct sockaddr_in)) {
				pfkeystat.out_invaddr++;
				error = EINVAL;
				goto senderror;
			}
			break;
		case AF_INET6:
			if (PFKEY_ADDR_SADDR(src0)->sa_len !=
			    sizeof(struct sockaddr_in6)) {
				pfkeystat.out_invaddr++;
				error = EINVAL;
				goto senderror;
			}
#ifdef INET6
			/*
			 * Check validity of the scope zone ID of the
			 * addresses, and embed the zone ID into the address
			 * if necessary.
			 */
			sin6 = (struct sockaddr_in6 *)PFKEY_ADDR_SADDR(src0);
			if ((error = sa6_embedscope(sin6, 0)) != 0)
				goto senderror;
			sin6 = (struct sockaddr_in6 *)PFKEY_ADDR_SADDR(dst0);
			if ((error = sa6_embedscope(sin6, 0)) != 0)
				goto senderror;
#endif
			break;
		default:
			ipseclog((LOG_DEBUG,
			    "key_parse: unsupported address family.\n"));
			pfkeystat.out_invaddr++;
			error = EAFNOSUPPORT;
			goto senderror;
		}

		switch (PFKEY_ADDR_SADDR(src0)->sa_family) {
		case AF_INET:
			plen = sizeof(struct in_addr) << 3;
			break;
		case AF_INET6:
			plen = sizeof(struct in6_addr) << 3;
			break;
		default:
			plen = 0;	/*fool gcc*/
			break;
		}

		/* check max prefix length */
		if (src0->sadb_address_prefixlen > plen ||
		    dst0->sadb_address_prefixlen > plen) {
			ipseclog((LOG_DEBUG,
			    "key_parse: illegal prefixlen.\n"));
			pfkeystat.out_invaddr++;
			error = EINVAL;
			goto senderror;
		}

		/*
		 * prefixlen == 0 is valid because there can be a case when
		 * all addresses are matched.
		 */
	}

	if (msg->sadb_msg_type >= sizeof(key_typesw)/sizeof(key_typesw[0]) ||
	    key_typesw[msg->sadb_msg_type] == NULL) {
		pfkeystat.out_invmsgtype++;
		error = EINVAL;
		goto senderror;
	}

	return (*key_typesw[msg->sadb_msg_type])(so, m, &mh);

senderror:
	msg->sadb_msg_errno = error;
	return key_sendup_mbuf(so, m, target);
}

static int
key_senderror(struct socket *so, struct mbuf *m, int code)
{
	struct sadb_msg *msg;

	if (m->m_len < sizeof(struct sadb_msg))
		panic("invalid mbuf passed to key_senderror");

	msg = mtod(m, struct sadb_msg *);
	msg->sadb_msg_errno = code;
	return key_sendup_mbuf(so, m, KEY_SENDUP_ONE);
}

/*
 * set the pointer to each header into message buffer.
 * m will be freed on error.
 * XXX larger-than-MCLBYTES extension?
 */
static int
key_align(struct mbuf *m, struct sadb_msghdr *mhp)
{
	struct mbuf *n;
	struct sadb_ext *ext;
	size_t off, end;
	int extlen;
	int toff;

	/* sanity check */
	if (m == NULL || mhp == NULL)
		panic("key_align: NULL pointer is passed.");
	if (m->m_len < sizeof(struct sadb_msg))
		panic("invalid mbuf passed to key_align");

	/* initialize */
	bzero(mhp, sizeof(*mhp));

	mhp->msg = mtod(m, struct sadb_msg *);
	mhp->ext[0] = (struct sadb_ext *)mhp->msg;	/*XXX backward compat */

	end = PFKEY_UNUNIT64(mhp->msg->sadb_msg_len);
	extlen = end;	/*just in case extlen is not updated*/
	for (off = sizeof(struct sadb_msg); off < end; off += extlen) {
		n = m_pulldown(m, off, sizeof(struct sadb_ext), &toff);
		if (!n) {
			/* m is already freed */
			return ENOBUFS;
		}
		ext = (struct sadb_ext *)(mtod(n, caddr_t) + toff);

		/* set pointer */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_POLICY:
		case SADB_X_EXT_SA2:
		case SADB_X_EXT_TAG:
#ifdef PFKEYV2_SADB_X_EXT_PACKET
		case SADB_X_EXT_PACKET:
#endif
			/* duplicate check */
			/*
			 * XXX Are there duplication payloads of either
			 * KEY_AUTH or KEY_ENCRYPT ?
			 */
			if (mhp->ext[ext->sadb_ext_type] != NULL) {
				ipseclog((LOG_DEBUG,
				    "key_align: duplicate ext_type %u "
				    "is passed.\n", ext->sadb_ext_type));
				m_freem(m);
				pfkeystat.out_dupext++;
				return EINVAL;
			}
			break;
		default:
			ipseclog((LOG_DEBUG,
			    "key_align: invalid ext_type %u is passed.\n",
			    ext->sadb_ext_type));
			m_freem(m);
			pfkeystat.out_invexttype++;
			return EINVAL;
		}

		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);

		if (key_validate_ext(ext, extlen)) {
			m_freem(m);
			pfkeystat.out_invlen++;
			return EINVAL;
		}

		n = m_pulldown(m, off, extlen, &toff);
		if (!n) {
			/* m is already freed */
			return ENOBUFS;
		}
		ext = (struct sadb_ext *)(mtod(n, caddr_t) + toff);

		mhp->ext[ext->sadb_ext_type] = ext;
		mhp->extoff[ext->sadb_ext_type] = off;
		mhp->extlen[ext->sadb_ext_type] = extlen;
	}

	if (off != end) {
		m_freem(m);
		pfkeystat.out_invlen++;
		return EINVAL;
	}

	return 0;
}

static int
key_validate_ext(/*const*/ struct sadb_ext *ext, int len)
{
	struct sockaddr *sa;
	enum { NONE, ADDR } checktype = NONE;
	int baselen = 0;
	const int sal = offsetof(struct sockaddr, sa_len) + sizeof(sa->sa_len);

	if (len != PFKEY_UNUNIT64(ext->sadb_ext_len))
		return EINVAL;

	/* if it does not match minimum/maximum length, bail */
	if (ext->sadb_ext_type >= sizeof(minsize) / sizeof(minsize[0]) ||
	    ext->sadb_ext_type >= sizeof(maxsize) / sizeof(maxsize[0]))
		return EINVAL;
	if (!minsize[ext->sadb_ext_type] || len < minsize[ext->sadb_ext_type])
		return EINVAL;
	if (maxsize[ext->sadb_ext_type] && len > maxsize[ext->sadb_ext_type])
		return EINVAL;

	/* more checks based on sadb_ext_type XXX need more */
	switch (ext->sadb_ext_type) {
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_EXT_ADDRESS_PROXY:
		baselen = PFKEY_ALIGN8(sizeof(struct sadb_address));
		checktype = ADDR;
		break;
	case SADB_EXT_IDENTITY_SRC:
	case SADB_EXT_IDENTITY_DST:
		if (((struct sadb_ident *)ext)->sadb_ident_type ==
		    SADB_X_IDENTTYPE_ADDR) {
			baselen = PFKEY_ALIGN8(sizeof(struct sadb_ident));
			checktype = ADDR;
		} else
			checktype = NONE;
		break;
	default:
		checktype = NONE;
		break;
	}

	switch (checktype) {
	case NONE:
		break;
	case ADDR:
		sa = (struct sockaddr *)((caddr_t)ext + baselen);
		if (len < baselen + sal)
			return EINVAL;
		if (baselen + PFKEY_ALIGN8(sa->sa_len) != len)
			return EINVAL;
		break;
	}

	return 0;
}

void
key_init(void)
{
	int i;

	bzero((caddr_t)&key_cb, sizeof(key_cb));

#if defined(__NetBSD__)
	callout_init(&key_timehandler_ch);
#elif defined(__FreeBSD__)
	callout_init(&key_timehandler_ch, 0);
#endif

	for (i = 0; i < IPSEC_DIR_MAX; i++)
		LIST_INIT(&sptree[i]);

	LIST_INIT(&sahtree);

	for (i = 0; i <= SADB_SATYPE_MAX; i++)
		LIST_INIT(&regtree[i]);

	for (i = 0; i < SPIHASHSIZE; i++)
		LIST_INIT(&spihash[i]);

#ifndef IPSEC_NONBLOCK_ACQUIRE
	LIST_INIT(&acqtree);
#endif
	LIST_INIT(&spacqtree);

	TAILQ_INIT(&satailq);
	TAILQ_INIT(&sptailq);

	/* system default */
#ifdef INET
	ip4_def_policy = key_newsp(0);
	if (!ip4_def_policy)
		panic("could not initialize IPv4 default security policy");
	ip4_def_policy->state = IPSEC_SPSTATE_ALIVE;
	ip4_def_policy->policy = IPSEC_POLICY_NONE;
	ip4_def_policy->dir = IPSEC_DIR_ANY;
	ip4_def_policy->readonly = 1;
	ip4_def_policy->persist = 1;
#endif
#ifdef INET6
	ip6_def_policy = key_newsp(0);
	if (!ip6_def_policy)
		panic("could not initialize IPv6 default security policy");
	ip6_def_policy->state = IPSEC_SPSTATE_ALIVE;
	ip6_def_policy->policy = IPSEC_POLICY_NONE;
	ip6_def_policy->dir = IPSEC_DIR_ANY;
	ip6_def_policy->readonly = 1;
	ip6_def_policy->persist = 1;
#endif

#if defined(__NetBSD__) || defined(__FreeBSD__)
	callout_reset(&key_timehandler_ch, hz, key_timehandler, (void *)0);
#else
	timeout(key_timehandler, (void *)0, hz);
#endif

	/* initialize key statistics */
	keystat.getspi_count = 1;

	printf("IPsec: Initialized Security Association Processing.\n");

	return;
}

/*
 * XXX: maybe This function is called after INBOUND IPsec processing.
 *
 * Special check for tunnel-mode packets.
 * We must make some checks for consistency between inner and outer IP header.
 *
 * xxx more checks to be provided
 */
int
key_checktunnelsanity(struct secasvar *sav, u_int family, caddr_t src,
	caddr_t dst)
{

	/* sanity check */
	if (sav->sah == NULL)
		panic("sav->sah == NULL at key_checktunnelsanity");

	/* XXX: check inner IP header */

	return 1;
}

#if 0
#ifdef __FreeBSD__
#define hostnamelen	strlen(hostname)
#endif

/*
 * Get FQDN for the host.
 * If the administrator configured hostname (by hostname(1)) without
 * domain name, returns nothing.
 */
static const char *
key_getfqdn(void)
{
	int i;
	int hasdot;
	static char fqdn[MAXHOSTNAMELEN + 1];

	if (!hostnamelen)
		return NULL;

	/* check if it comes with domain name. */
	hasdot = 0;
	for (i = 0; i < hostnamelen; i++) {
		if (hostname[i] == '.')
			hasdot++;
	}
	if (!hasdot)
		return NULL;

	/* NOTE: hostname may not be NUL-terminated. */
	bzero(fqdn, sizeof(fqdn));
	bcopy(hostname, fqdn, hostnamelen);
	fqdn[hostnamelen] = '\0';
	return fqdn;
}

/*
 * get username@FQDN for the host/user.
 */
static const char *
key_getuserfqdn(void)
{
	const char *host;
	static char userfqdn[MAXHOSTNAMELEN + MAXLOGNAME + 2];
	struct proc *p = curproc;
	char *q;

	if (!p || !p->p_pgrp || !p->p_pgrp->pg_session)
		return NULL;
	if (!(host = key_getfqdn()))
		return NULL;

	/* NOTE: s_login may not be-NUL terminated. */
	bzero(userfqdn, sizeof(userfqdn));
	bcopy(p->p_pgrp->pg_session->s_login, userfqdn, MAXLOGNAME);
	userfqdn[MAXLOGNAME] = '\0';	/* safeguard */
	q = userfqdn + strlen(userfqdn);
	*q++ = '@';
	bcopy(host, q, strlen(host));
	q += strlen(host);
	*q++ = '\0';

	return userfqdn;
}
#endif

/* record data transfer on SA, and update timestamps */
void
key_sa_recordxfer(struct secasvar *sav, struct mbuf *m)
{

	if (!sav)
		panic("key_sa_recordxfer called with sav == NULL");
	if (!m)
		panic("key_sa_recordxfer called with m == NULL");
	if (!sav->lft_c)
		return;

	/*
	 * XXX Currently, there is a difference of bytes size
	 * between inbound and outbound processing.
	 */
	sav->lft_c->sadb_lifetime_bytes += m->m_pkthdr.len;
	/* to check bytes lifetime is done in key_timehandler(). */

	/*
	 * We use the number of packets as the unit of
	 * sadb_lifetime_allocations.  We increment the variable
	 * whenever {esp,ah}_{in,out}put is called.
	 */
	sav->lft_c->sadb_lifetime_allocations++;
	/* XXX check for expires? */

	/*
	 * NOTE: We record CURRENT sadb_lifetime_usetime by using wall clock,
	 * in seconds.  HARD and SOFT lifetime are measured by the time
	 * difference (again in seconds) from sadb_lifetime_usetime.
	 *
	 *	usetime
	 *	v     expire   expire
	 * -----+-----+--------+---> t
	 *	<--------------> HARD
	 *	<-----> SOFT
	 */
    {
#ifdef __FreeBSD__
	sav->lft_c->sadb_lifetime_usetime = time_second;
#else
	sav->lft_c->sadb_lifetime_usetime = time.tv_sec;
#endif
	/* XXX check for expires? */
    }

	return;
}

/* dumb version */
void
key_sa_routechange(struct sockaddr *dst)
{
	struct secashead *sah;
	struct route *ro;

	LIST_FOREACH(sah, &sahtree, chain) {
		ro = &sah->sa_route;
		if (ro->ro_rt && dst->sa_len == ro->ro_dst.sa_len &&
		    bcmp(dst, &ro->ro_dst, dst->sa_len) == 0) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)NULL;
		}
	}

	return;
}

static void
key_sa_chgstate(struct secasvar *sav, u_int8_t state)
{

	if (sav == NULL)
		panic("key_sa_chgstate called with sav == NULL");

	if (sav->state == state)
		return;

	if (__LIST_CHAINED(sav))
		LIST_REMOVE(sav, chain);

	sav->state = state;
	LIST_INSERT_HEAD(&sav->sah->savtree[state], sav, chain);
}

void
key_sa_stir_iv(struct secasvar *sav)
{

	if (!sav->iv)
		panic("key_sa_stir_iv called with sav == NULL");
	key_randomfill(sav->iv, sav->ivlen);
}

static void
key_sp_dead(struct secpolicy *sp)
{

	/* mark the SP dead */
	sp->state = IPSEC_SPSTATE_DEAD;
}

static void
key_sp_unlink(struct secpolicy *sp)
{

	/* remove from SP index */
	if (__LIST_CHAINED(sp)) {
		LIST_REMOVE(sp, chain);
		key_freesp(sp);
	}
}

/* XXX too much? */
static struct mbuf *
key_alloc_mbuf(int l)
{
	struct mbuf *m = NULL, *n;
	int len, t;

	len = l;
	while (len > 0) {
		MGET(n, M_DONTWAIT, MT_DATA);
		if (n && len > MLEN)
			MCLGET(n, M_DONTWAIT);
		if (!n) {
			m_freem(m);
			return NULL;
		}

		n->m_next = NULL;
		n->m_len = 0;
		n->m_len = M_TRAILINGSPACE(n);
		/* use the bottom of mbuf, hoping we can prepend afterwards */
		if (n->m_len > len) {
			t = (n->m_len - len) & ~(sizeof(long) - 1);
			n->m_data += t;
			n->m_len = len;
		}

		len -= n->m_len;

		if (m)
			m_cat(m, n);
		else
			m = n;
	}

	return m;
}

#ifdef __NetBSD__
static int
sysctl_net_key_dumpsa(SYSCTLFN_ARGS)
{
	struct mbuf *m, *n;
	int err2 = 0;
	char *p, *ep;
	size_t len;
	int s, error;

	if (newp)
		return (EPERM);
	if (namelen != 1)
		return (EINVAL);

	s = splsoftnet();
	m = key_setdump(name[0], &error);
	splx(s);
	if (!m)
		return (error);
	if (!oldp)
		*oldlenp = m->m_pkthdr.len;
	else {
		p = oldp;
		if (*oldlenp < m->m_pkthdr.len) {
			err2 = ENOMEM;
			ep = p + *oldlenp;
		} else {
			*oldlenp = m->m_pkthdr.len;
			ep = p + m->m_pkthdr.len;
		}
		for (n = m; n; n = n->m_next) {
			len =  (ep - p < n->m_len) ?
				ep - p : n->m_len;
			error = copyout(mtod(n, const void *), p, len);
			p += len;
			if (error)
				break;
		}
		if (error == 0)
			error = err2;
	}
	m_freem(m);

	return (error);
}

static int
sysctl_net_key_dumpsp(SYSCTLFN_ARGS)
{
	struct mbuf *m, *n;
	int err2 = 0;
	char *p, *ep;
	size_t len;
	int s, error;

	if (newp)
		return (EPERM);
	if (namelen != 0)
		return (EINVAL);

	s = splsoftnet();
	m = key_setspddump(&error);
	splx(s);
	if (!m)
		return (error);
	if (!oldp)
		*oldlenp = m->m_pkthdr.len;
	else {
		p = oldp;
		if (*oldlenp < m->m_pkthdr.len) {
			err2 = ENOMEM;
			ep = p + *oldlenp;
		} else {
			*oldlenp = m->m_pkthdr.len;
			ep = p + m->m_pkthdr.len;
		}
		for (n = m; n; n = n->m_next) {
			len =  (ep - p < n->m_len) ?
				ep - p : n->m_len;
			error = copyout(mtod(n, const void *), p, len);
			p += len;
			if (error)
				break;
		}
		if (error == 0)
			error = err2;
	}
	m_freem(m);

	return (error);
}

SYSCTL_SETUP(sysctl_net_key_setup, "sysctl net.key subtree setup")
{

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "net", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_NODE, "key", NULL,
		       NULL, 0, NULL, 0,
		       CTL_NET, PF_KEY, CTL_EOL);

	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "debug", NULL,
		       NULL, 0, &key_debug_level, 0,
		       CTL_NET, PF_KEY, KEYCTL_DEBUG_LEVEL, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "spi_try", NULL,
		       NULL, 0, &key_spi_trycnt, 0,
		       CTL_NET, PF_KEY, KEYCTL_SPI_TRY, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "spi_min_value", NULL,
		       NULL, 0, &key_spi_minval, 0,
		       CTL_NET, PF_KEY, KEYCTL_SPI_MIN_VALUE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "spi_max_value", NULL,
		       NULL, 0, &key_spi_maxval, 0,
		       CTL_NET, PF_KEY, KEYCTL_SPI_MAX_VALUE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "larval_lifetime", NULL,
		       NULL, 0, &key_larval_lifetime, 0,
		       CTL_NET, PF_KEY, KEYCTL_LARVAL_LIFETIME, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "blockacq_count", NULL,
		       NULL, 0, &key_blockacq_count, 0,
		       CTL_NET, PF_KEY, KEYCTL_BLOCKACQ_COUNT, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "blockacq_lifetime", NULL,
		       NULL, 0, &key_blockacq_lifetime, 0,
		       CTL_NET, PF_KEY, KEYCTL_BLOCKACQ_LIFETIME, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "esp_keymin", NULL,
		       NULL, 0, &ipsec_esp_keymin, 0,
		       CTL_NET, PF_KEY, KEYCTL_ESP_KEYMIN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "esp_auth", NULL,
		       NULL, 0, &ipsec_esp_auth, 0,
		       CTL_NET, PF_KEY, KEYCTL_ESP_AUTH, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
		       CTLTYPE_INT, "ah_keymin", NULL,
		       NULL, 0, &ipsec_ah_keymin, 0,
		       CTL_NET, PF_KEY, KEYCTL_AH_KEYMIN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "dumpsa", NULL,
		       sysctl_net_key_dumpsa, 0, NULL, 0,
		       CTL_NET, PF_KEY, KEYCTL_DUMPSA, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		       CTLFLAG_PERMANENT,
		       CTLTYPE_STRUCT, "dumpsp", NULL,
		       sysctl_net_key_dumpsp, 0, NULL, 0,
		       CTL_NET, PF_KEY, KEYCTL_DUMPSP, CTL_EOL);
}
#endif

#ifdef MIP6
#if NMIP > 0
void
key_mip6_update_mobile_node_ipsecdb(haddr, ocoa, ncoa, haaddr)
	struct sockaddr_in6 *haddr;
	struct sockaddr_in6 *ocoa;   /* not used.  may be NULL. */
	struct sockaddr_in6 *ncoa;
	struct sockaddr_in6 *haaddr;
{
	struct secpolicy *sp;
	struct secpolicyindex *spidx;
	struct ipsecrequest *isr;
	struct secashead *sa;
	struct secasindex *sahint;
	struct mbuf *m;
	struct sockaddr_in6 sin6;

	LIST_FOREACH(sp, &sptree[IPSEC_DIR_INBOUND], chain) {
		/* check if we have a valid spidx. */
		if ((spidx = sp->spidx) == NULL)
			continue;
		/* check addresses. */
		if (!IN6_ARE_ADDR_EQUAL(&sa6_any.sin6_addr,
			&((struct sockaddr_in6 *)&spidx->src)->sin6_addr))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&haddr->sin6_addr,
			&((struct sockaddr_in6 *)&spidx->dst)->sin6_addr))
			continue;
		/* check if the SP has a SA hint. */
		isr = sp->req;
		if (isr == NULL)
			continue;
		sahint = &isr->saidx;
		if (sahint == NULL)
			continue;

		/* update SA entries from a home agent to a mobile node. */
		LIST_FOREACH(sa, &sahtree, chain) {
			if (!IN6_ARE_ADDR_EQUAL(&haaddr->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.src)->sin6_addr))
				continue;
/* XXX don't check the old CoA.  instead, we use a uniqid.
			if (!IN6_ARE_ADDR_EQUAL(&ocoa->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.dst)->sin6_addr))
				continue;
*/
			if (sa->saidx.mode != IPSEC_MODE_TUNNEL)
				continue;
			if (sa->saidx.reqid == 0)
				continue;
			if (sa->saidx.reqid != sahint->reqid)
				continue;

			/* found. */
			*(struct sockaddr_in6 *)&(sa->saidx.dst) = *ncoa;

			/* free a cached route for the destination of
			   the SA to update. */
			if (sa->sa_route.ro_rt) {
				RTFREE(sa->sa_route.ro_rt);
				sa->sa_route.ro_rt = NULL;
			}
		}
		/* update the tunnel endpoint of a mobile node side. */
		sin6 = *(struct sockaddr_in6 *)(&sahint->dst);
		*(struct sockaddr_in6 *)(&sahint->dst) = *ncoa;

	if (mip6ctl_use_migrate) {
		m = key_setmigrate(sp, (struct sockaddr *)haaddr,
		    (struct sockaddr *)&sin6, isr, 0, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_mobile_node_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_MIGRATE in INBOUND processing.\n"));
			continue;
		}
	} else {
		/* announce the update. */
		m = key_setdumpsp(sp, SADB_X_SPDUPDATE, 0, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_mobile_node_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_SPDUPDATE in INBOUND processing.\n"));
			continue;
		}
	}
		key_sendup_mbuf(NULL, m, KEY_SENDUP_REGISTERED);
	}

	/* update outbound data. */
	LIST_FOREACH(sp, &sptree[IPSEC_DIR_OUTBOUND], chain) {
		/* check if we have a valid spidx. */
		if ((spidx = sp->spidx) == NULL)
			continue;
		/* check addresses. */
		if (!IN6_ARE_ADDR_EQUAL(&haddr->sin6_addr,
			&((struct sockaddr_in6 *)&spidx->src)->sin6_addr))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&sa6_any.sin6_addr,
			&((struct sockaddr_in6 *)&spidx->dst)->sin6_addr))
			continue;
		/* check if the SP has a SA hint. */
		isr = sp->req;
		if (isr == NULL)
			continue;
		sahint = &isr->saidx;
		if (sahint == NULL)
			continue;

		/* update SA entries from a mobile node to a home agent. */
		LIST_FOREACH(sa, &sahtree, chain) {
/* XXX don't check the old CoA.  instead, we use uniqid.
			if (!IN6_ARE_ADDR_EQUAL(&ocoa->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.src)->sin6_addr))
				continue;
*/
			if (!IN6_ARE_ADDR_EQUAL(&haaddr->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.dst)->sin6_addr))
				continue;
			if (sa->saidx.mode != IPSEC_MODE_TUNNEL)
				continue;
			if (sa->saidx.reqid == 0)
				continue;
			if (sa->saidx.reqid != sahint->reqid)
				continue;

			/* found. */
			*(struct sockaddr_in6 *)&(sa->saidx.src) = *ncoa;
		}
		/* update the tunnel endpoint of a mobile node side. */
		sin6 = *(struct sockaddr_in6 *)(&sahint->src);
		*(struct sockaddr_in6 *)(&sahint->src) = *ncoa;

	if (mip6ctl_use_migrate) {
		m = key_setmigrate(sp, (struct sockaddr *)&sin6,
		    (struct sockaddr *)haaddr, isr, 1, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_mobile_node_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_MIGRATE in OUTBOUND processing.\n"));
			continue;
		}
	} else {
		/* announce the update. */
		m = key_setdumpsp(sp, SADB_X_SPDUPDATE, 1, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_mobile_node_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_SPDUPDATE in OUTBOUND processing.\n"));
			continue;
		}
	}
		key_sendup_mbuf(NULL, m, KEY_SENDUP_REGISTERED);
	}
}
#endif /* NMIP > 0 */

void
key_mip6_update_home_agent_ipsecdb(struct sockaddr_in6 *haddr,
	struct sockaddr_in6 *ocoa, struct sockaddr_in6 *ncoa,
	struct sockaddr_in6 *haaddr)
{
	struct secpolicy *sp;
	struct secpolicyindex *spidx;
	struct ipsecrequest *isr;
	struct secashead *sa;
	struct secasindex *sahint;
	struct mbuf *m;
	struct sockaddr_in6 sin6;

	/* update outbound data. */
	LIST_FOREACH(sp, &sptree[IPSEC_DIR_INBOUND], chain) {
		/* check if we have a valid spidx. */
		if ((spidx = sp->spidx) == NULL)
			continue;
		/* check addresses. */
		if (!IN6_ARE_ADDR_EQUAL(&haddr->sin6_addr,
			&((struct sockaddr_in6 *)&spidx->src)->sin6_addr))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&sa6_any.sin6_addr,
			&((struct sockaddr_in6 *)&spidx->dst)->sin6_addr))
			continue;
		/* check if we have a SA hint. */
		isr = sp->req;
		if (isr == NULL)
			continue;
		sahint = &isr->saidx;
		if (sahint == NULL)
			continue;

		/* update SA entries from a mobile node to a home agent. */
		LIST_FOREACH(sa, &sahtree, chain) {
/* XXX don't check the old CoA.  instead we use a uniqid.
			if (!IN6_ARE_ADDR_EQUAL(&ocoa->sin6_addr,
			    &((struct sockaddr_in6 *)&sa->saidx.src)->sin6_addr))
				continue;
*/
			if (!IN6_ARE_ADDR_EQUAL(&haaddr->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.dst)->sin6_addr))
				continue;
			if (sa->saidx.mode != IPSEC_MODE_TUNNEL)
				continue;
			if (sa->saidx.reqid == 0)
				continue;
			if (sa->saidx.reqid != sahint->reqid)
				continue;

			/* found. */
			*(struct sockaddr_in6 *)&(sa->saidx.src) = *ncoa;
		}
		/* update a tunnel endpoint of a mobile node side. */
		sin6 = *(struct sockaddr_in6 *)(&sahint->src);
		*(struct sockaddr_in6 *)(&sahint->src) = *ncoa;

	if (mip6ctl_use_migrate) {
		m = key_setmigrate(sp, (struct sockaddr *)&sin6,
		    (struct sockaddr *)haaddr, isr, 0, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_home_agent_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_MIGRATE in INBOUND processing.\n"));
			continue;
		}
	} else {
		/* announce the update */
		m = key_setdumpsp(sp, SADB_X_SPDUPDATE, 0, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_home_agent_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_SPDUPDATE in INBOUND processing.\n"));
			continue;
		}
	}
		key_sendup_mbuf(NULL, m, KEY_SENDUP_REGISTERED);
	}

	/* update outbound data. */
	LIST_FOREACH(sp, &sptree[IPSEC_DIR_OUTBOUND], chain) {
		/* check if we have a valid spidx. */
		if ((spidx = sp->spidx) == NULL)
			continue;
		/* check addresses. */
		if (!IN6_ARE_ADDR_EQUAL(&sa6_any.sin6_addr,
			&((struct sockaddr_in6 *)&spidx->src)->sin6_addr))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&haddr->sin6_addr,
			&((struct sockaddr_in6 *)&spidx->dst)->sin6_addr))
			continue;
		/* check if we have a SA hint. */
		isr = sp->req;
		if (isr == NULL)
			continue;
		sahint = &isr->saidx;
		if (sahint == NULL)
			continue;

		/* update SA entries from a home agent to a mobile node. */
		LIST_FOREACH(sa, &sahtree, chain) {
			if (!IN6_ARE_ADDR_EQUAL(&haaddr->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.src)->sin6_addr))
				continue;
/* XXX don't check the old CoA.  instead, we use a uniqid.
			if (!IN6_ARE_ADDR_EQUAL(&ocoa->sin6_addr,
				&((struct sockaddr_in6 *)&sa->saidx.dst)->sin6_addr))
				continue;
*/
			if (sa->saidx.mode != IPSEC_MODE_TUNNEL)
				continue;
			if (sa->saidx.reqid == 0)
				continue;
			if (sa->saidx.reqid != sahint->reqid)
			continue;

			/* found. */
			*(struct sockaddr_in6 *)&(sa->saidx.dst) = *ncoa;
			/* free the cached route for the destination of
			   the SA to update. */
			if (sa->sa_route.ro_rt) {
				RTFREE(sa->sa_route.ro_rt);
				sa->sa_route.ro_rt = NULL;
			}
		}
		/* update a tunnel endpoint of a mobile node side. */
		sin6 = *(struct sockaddr_in6 *)(&sahint->dst);
		*(struct sockaddr_in6 *)(&sahint->dst) = *ncoa;
	
	if (mip6ctl_use_migrate) {
		m = key_setmigrate(sp, (struct sockaddr *)haaddr,
		    (struct sockaddr *)&sin6, isr, 1, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_home_agent_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_MIGRATE in INBOUND processing.\n"));
			continue;
		}
	} else {
		/* announce the update */
		m = key_setdumpsp(sp, SADB_X_SPDUPDATE, 1, 0);
		if (m == NULL) {
			mip6log((LOG_ERR,
			    "key_mip6_update_home_agent_ipsecdb: "
			    "failed to allocate a mbuf for "
			    "SADB_X_SPDUPDATE in OUTBOUND processing.\n"));
			continue;
		}
	}
		key_sendup_mbuf(NULL, m, KEY_SENDUP_REGISTERED);
	}
}

static struct mbuf *
key_setmigrate(struct secpolicy *sp, struct sockaddr *oldsrc,
	struct sockaddr *olddst, struct ipsecrequest *isr, u_int32_t seq,
	u_int32_t pid)
{
	struct mbuf *result = NULL, *m;
	struct sadb_x_policy *xpl;
	int xpllen;
	caddr_t p;
	struct sadb_x_ipsecrequest *xisr;

	m = key_setsadbmsg(SADB_X_MIGRATE, 0, SADB_SATYPE_UNSPEC, seq, pid,
	    sp->refcnt);
	if (m == NULL)
		goto fail;
	result = m;

	if (sp->spidx) {
		m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
		    (struct sockaddr *)&sp->spidx->src, sp->spidx->prefs,
		    sp->spidx->ul_proto);
		if (m == NULL)
			goto fail;
		m_cat(result, m);

		m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
		    (struct sockaddr *)&sp->spidx->dst, sp->spidx->prefd,
		    sp->spidx->ul_proto);
		if (m == NULL)
			goto fail;
		m_cat(result, m);
	} else
		goto fail;

	xpllen = sizeof(struct sadb_x_policy)
	    + PFKEY_ALIGN8(sizeof(struct sadb_x_ipsecrequest)
		+ oldsrc->sa_len * 2) * 2;

	m = key_alloc_mbuf(xpllen);
	if (m == NULL)
		goto fail;
	xpl = mtod(m, struct sadb_x_policy *);
	bzero(xpl, xpllen);
	xpl->sadb_x_policy_len = PFKEY_UNIT64(xpllen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = sp->policy;
	xpl->sadb_x_policy_dir = sp->dir;
	xpl->sadb_x_policy_id = sp->id;
	p = (caddr_t)xpl + sizeof(struct sadb_x_policy);

	xisr = (struct sadb_x_ipsecrequest *)p;
	xisr->sadb_x_ipsecrequest_proto = isr->saidx.proto;
	xisr->sadb_x_ipsecrequest_mode = isr->saidx.mode;
	xisr->sadb_x_ipsecrequest_level = isr->level;
	xisr->sadb_x_ipsecrequest_reqid = isr->saidx.reqid;
	p += sizeof(struct sadb_x_ipsecrequest);
	bcopy(oldsrc, p, oldsrc->sa_len);
	p += oldsrc->sa_len;
	bcopy(olddst, p, olddst->sa_len);
	p += olddst->sa_len;

	xisr->sadb_x_ipsecrequest_len = PFKEY_ALIGN8(
	    sizeof(struct sadb_x_ipsecrequest) + oldsrc->sa_len
	    + olddst->sa_len);

	xisr = (struct sadb_x_ipsecrequest *)p;
	xisr->sadb_x_ipsecrequest_proto = isr->saidx.proto;
	xisr->sadb_x_ipsecrequest_mode = isr->saidx.mode;
	xisr->sadb_x_ipsecrequest_level = isr->level;
	xisr->sadb_x_ipsecrequest_reqid = isr->saidx.reqid;
	p += sizeof(struct sadb_x_ipsecrequest);
	bcopy(&isr->saidx.src, p, isr->saidx.src.ss_len);
	p += isr->saidx.src.ss_len;
	bcopy(&isr->saidx.dst, p, isr->saidx.dst.ss_len);
	p += isr->saidx.dst.ss_len;

	xisr->sadb_x_ipsecrequest_len = PFKEY_ALIGN8(
	    sizeof(struct sadb_x_ipsecrequest) + isr->saidx.src.ss_len
	    + isr->saidx.dst.ss_len);

	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0)
		goto fail;

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL)
			goto fail;
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return(result);

 fail:
	m_freem(result);
	return (NULL);
}
#endif /* MIP6 */
