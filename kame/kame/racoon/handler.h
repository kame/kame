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
/* YIPS @(#)$Id: handler.h,v 1.6 2000/01/11 22:26:12 sakane Exp $ */

/* Phase 1 handler */
/*
 * main mode:
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   (---)                   1st valid msg received
 *  3   1st msg sent	        1st msg sent
 *  4   1st valid msg received  2st valid msg received
 *  5   2nd msg sent            2nd msg sent
 *  6   2nd valid msg received  3rd valid msg received
 *  7   3rd msg sent            3rd msg sent
 *  8   3rd valid msg received  (---)
 *  9   SA established          SA established
 *
 * aggressive mode:
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   (---)                   1st valid msg received
 *  3   1st msg sent	        1st msg sent
 *  4   1st valid msg received  2st valid msg received
 *  5   (---)                   (---)
 *  6   (---)                   (---)
 *  7   (---)                   (---)
 *  8   (---)                   (---)
 *  9   SA established          SA established
 *
 * base mode:
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   (---)                   1st valid msg received
 *  3   1st msg sent	        1st msg sent
 *  4   1st valid msg received  2st valid msg received
 *  5   2nd msg sent            (---)
 *  6   (---)                   (---)
 *  7   (---)                   (---)
 *  8   (---)                   (---)
 *  9   SA established          SA established
 */
#define PHASE1ST_SPAWN			0
#define PHASE1ST_START			1
#define PHASE1ST_MSG1RECEIVED		2
#define PHASE1ST_MSG1SENT		3
#define PHASE1ST_MSG2RECEIVED		4
#define PHASE1ST_MSG2SENT		5
#define PHASE1ST_MSG3RECEIVED		6
#define PHASE1ST_MSG3SENT		7
#define PHASE1ST_MSG4RECEIVED		8
#define PHASE1ST_ESTABLISHED		9
#define PHASE1ST_EXPIRED		10
#define PHASE1ST_MAX			11

/* About address semantics in each case.
 *			initiator(addr=I)	responder(addr=R)
 *			src	dst		src	dst
 *			(local)	(remote)	(local)	(remote)
 * phase 1 handler	I	R		R	I
 * phase 2 handler	I	R		R	I
 * getspi msg		R	I		I	R
 * aquire msg		I	R
 * ID payload		I	R		I	R
 */
struct ph1handle {
	isakmp_index index;

	int status;			/* status of this SA */
	int side;			/* INITIATOR or RESPONDER */

	struct sockaddr *remote;	/* remote address to negosiate ph1 */
	struct sockaddr *local;		/* local address to negosiate ph1 */
			/* XXX copy from rmconf due to anonymous configuration.
			 * If anonymous will be forbidden, we do delete them. */

	struct remoteconf *rmconf;	/* remote configuration */

	struct isakmpsa *approval;	/* SA(s) approved. */
	vchar_t *authstr;		/* place holder of string for auth. */
					/* for example pre-shared key */

	u_int8_t version;		/* ISAKMP version */
	u_int8_t etype;			/* Exchange type actually for use */
	u_int8_t flags;			/* Flags */
	u_int32_t msgid;		/* message id */

	int inuse;			/* received EXPIRE message */
					/* 0: init, 1: grace, 2: sa require */

	struct sched *sce;		/* schedule for expire */
	struct sched *scr;		/* schedule for resend */
	struct sched *scg;		/* schedule for release half connect */
	int retry_counter;		/* for resend. */
	vchar_t *sendbuf;		/* buffer for re-sending */
	time_t time_sent;		/* timestamp to sent packet */

	vchar_t *dhpriv;		/* DH; private value */
	vchar_t *dhpub;			/* DH; public value */
	vchar_t *dhpub_p;		/* DH; partner's public value */
	vchar_t *dhgxy;			/* DH; shared secret */
	vchar_t *nonce;			/* nonce value */
	vchar_t *nonce_p;		/* partner's nonce value */
	vchar_t *skeyid;		/* SKEYID */
	vchar_t *skeyid_d;		/* SKEYID_d */
	vchar_t *skeyid_a;		/* SKEYID_a, i.e. hash */
	vchar_t *skeyid_e;		/* SKEYID_e, i.e. encryption */
	vchar_t *key;			/* cipher key */
	vchar_t *hash;			/* HASH minus general header */
	vchar_t *sig;			/* SIG minus general header */
	vchar_t *cert;			/* CERT minus general header */
	vchar_t *id;			/* ID minus gen header */
	vchar_t *id_p;			/* partner's ID minus general header */
	struct isakmp_ivm *ivm;		/* IVs */

	vchar_t *sa;			/* whole SA payload to calculate HASH */
					/* NOT INCLUDING general header. */

	vchar_t *sa_ret;		/* SA payload to be reply */
					/* NOT INCLUDING general header. */
					/* NOTE: Should be release after use. */

	struct isakmp_pl_hash *pl_hash;	/* pointer to hash payload */
	struct isakmp_pl_cert *pl_cert;	/* pointer to cert payload */
	struct isakmp_pl_sig *pl_sig;	/* pointer to sig payload */
			/* XXX save these values into my buffer respectively.
			 * Need more cool method. */

	time_t created;			/* timestamp for establish */

	u_int32_t msgid2;		/* msgid counter for Phase 2 */
	LIST_HEAD(_ph2ofph1_, ph2handle) ph2tree;

	LIST_ENTRY(ph1handle) chain;
};

/* Phase 2 handler */
/*
 *      initiator               responder
 *  0   (---)                   (---)
 *  1   start                   start (1st msg received)
 *  2   acquire msg get         1st valid msg received
 *  3   getspi request sent     getspi request sent
 *  4   getspi done             getspi done
 *  5   1st msg sent            1st msg sent
 *  6   1st valid msg received  2nd valid msg received
 *  7   (commit bit)            (commit bit)
 *  8   SAs added               SAs added
 *  9   SAs established         SAs established
 * 10   SAs expired             SAs expired
 */
#define PHASE2ST_SPAWN		0
#define PHASE2ST_START		1
#define PHASE2ST_STATUS2	2
#define PHASE2ST_GETSPISENT	3
#define PHASE2ST_GETSPIDONE	4
#define PHASE2ST_MSG1SENT	5
#define PHASE2ST_STATUS6	6
#define PHASE2ST_COMMIT		7
#define PHASE2ST_ADDSA		8
#define PHASE2ST_ESTABLISHED	9
#define PHASE2ST_EXPIRED	10
#define PHASE2ST_MAX		11

struct ph2handle {
	struct policyindex *spidx;	/* pointer to policy */
			/* initiator set when get acquire msg.
			 * responder set after check 1st phase 2 msg. */

	int status;			/* ipsec sa status */
	u_int8_t side;			/* INITIATOR or RESPONDER */

	struct sched *sce;		/* schedule for expire */
	struct sched *scr;		/* schedule for resend */
	vchar_t *sendbuf;		/* buffer for re-sending */
	int retry_counter;
	time_t sent;			/* timestamp to sent packet */

	int retry_checkph1;		/* counter to wait phase 1 finished. */
					/* NOTE: actually it's timer. */

	u_int32_t seq;			/* sequence number used by PF_KEY */
			/*
			 * NOTE: In responder side, we can't identify each SAs
			 * with same destination address for example, when
			 * socket based SA is required.  So we set a identifier
			 * number to "seq", and sent kernel by pfkey.
			 */
	int inuse;			/* received EXPIRE message */
					/* 0: init, 1: grace, 2: sa require */

	u_int8_t flags;			/* Flags for phase 2 */
	u_int32_t msgid;		/* msgid for phase 2 */

	struct ipsecsa *approval;	/* SA(s) approved. */
			/* point to one of the proposals in policyindex. */
	struct ipsecsakeys *keys;

	struct sockaddr *src;		/* my address of SA. */
	struct sockaddr *dst;		/* peer's address of SA. */
		/* requested from kernel. */
		/* XXX it must be listed. */
		/* XXX it must be each addresses in approval. */

	vchar_t *dhpriv;		/* DH; private value */
	vchar_t *dhpub;			/* DH; public value */
	vchar_t *dhpub_p;		/* DH; partner's public value */
	vchar_t *dhgxy;			/* DH; shared secret */
	vchar_t *id;			/* ID minus gen header */
	vchar_t *id_p;			/* peer's ID minus general header */
	vchar_t *nonce;			/* nonce value in phase 2 */
	vchar_t *nonce_p;		/* partner's nonce value in phase 2 */
	vchar_t *hash;			/* HASH2 minus general header */

	vchar_t *sa_ret;		/* SA payload to be reply */
					/* NOT INCLUDING general header. */
					/* Should be release after use. */

	struct isakmp_ivm *ivm;		/* IVs */

	struct ph1handle *ph1;	/* back pointer to isakmp status */

	LIST_ENTRY(ph2handle) chain;
	LIST_ENTRY(ph2handle) ph1bind;	/* chain to ph1handle */
};

/* for parsing ISAKMP header. */
struct isakmp_parse_t {
	u_char type;		/* payload type of mine */
	int len;		/* ntohs(ptr->len) */
	struct isakmp_gen *ptr;
};

/* for IV management */
struct isakmp_ivm {
	vchar_t *iv;
	vchar_t *ive;
	vchar_t *ivd;
};

/* holder for the variable of SA */
struct ipsecsakeys {
	int proto_id;
	int encmode;
	struct sockaddr *src;
	struct sockaddr *dst;

	u_int32_t spi;			/* SPI defined by me. i.e. --SA-> me */
	u_int32_t spi_p;		/* SPI defined by peer. i.e. me -SA-> */
	vchar_t *keymat;		/* KEYMAT */
	vchar_t *keymat_p;		/* peer's KEYMAT */

	int ok;				/* if 1, success to set SA in kenrel */

	struct ipsecsakeys *next;
};

struct sockaddr;
struct ph1handle;
struct ph2handle;
struct policyindex;

extern struct ph1handle *getph1byindex __P((isakmp_index *index));
extern struct ph1handle *getph1byindex0 __P((isakmp_index *index));
extern struct ph1handle *getph1byaddr __P((struct sockaddr *remote));
extern vchar_t *dumpph1 __P((u_int proto));
extern struct ph1handle *newph1 __P((void));
extern void delph1 __P((struct ph1handle *iph1));
extern int insph1 __P((struct ph1handle *iph1));
extern void remph1 __P((struct ph1handle *iph1));
extern void flushph1 __P((u_int proto));
extern void initph1tree __P((void));

extern struct ph2handle *getph2byspidx __P((struct policyindex *spidx));
extern struct ph2handle *getph2byseq __P((u_int32_t seq));
extern struct ph2handle *getph2bymsgid __P((struct ph1handle *iph1, u_int32_t msgid));
extern struct ph2handle *getph2bysaidx __P((struct sockaddr *src, struct sockaddr *dst, u_int proto_id, u_int32_t spi));
extern struct ph2handle *newph2 __P((void));
extern void initph2 __P((struct ph2handle *iph2));
extern void delph2 __P((struct ph2handle *iph2));
extern int insph2 __P((struct ph2handle *iph2));
extern void remph2 __P((struct ph2handle *iph2));
extern void initph2tree __P((void));

extern void bindph12 __P((struct ph1handle *iph1, struct ph2handle *iph2));
extern void unbindph12 __P((struct ph2handle *iph2));
